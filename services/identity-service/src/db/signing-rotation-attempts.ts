import { signingTransitionEffects } from '../../../../packages/security-kernel/src/signing-transitions.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import type { PoolClient } from 'pg';
import { businessSigningTrustDigest } from '@openpc/security-kernel';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  businessProviderRequestDigest,
  type BusinessProviderDescriptor,
  type BusinessProviderRequest,
  type BusinessProviderObservation,
} from '../domain/business-signing-provider.js';
import { SigningRotationError, type SigningRotationState } from '../domain/signing-rotation.js';
import {
  rotationDigest,
  type RotationRow,
  type SigningRotationPartition,
} from './signing-rotation-store.js';
import { rotationPublicTrust } from './signing-rotation-trust.js';

export interface RotationAttempt {
  attemptId: string;
  createdAt?: Date;
  slot: string;
  request: BusinessProviderRequest;
  observation: BusinessProviderObservation | null;
  state:
    'READY' | 'DISPATCHING' | 'OBSERVED' | 'ACCEPTED' | 'REJECTED' | 'SUPERSEDED' | 'CANCELLED';
}
export async function rotationAttempts(
  client: PoolClient,
  scope: SigningRotationPartition,
  operationId: string,
) {
  return (
    await client.query<RotationAttempt>(
      `select attempt_id::text as "attemptId",created_at as "createdAt",slot,request,observation,state
    from control.signing_provider_attempt where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 order by slot`,
      [scope.participantId, scope.privacyDomainId, operationId],
    )
  ).rows;
}
export async function preparedRotationDescriptor(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
): Promise<BusinessProviderDescriptor> {
  const result = await client.query<{ observation: BusinessProviderObservation }>(
    `select observation from control.signing_provider_attempt
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and to_state='PREPARED' and state='ACCEPTED' and request->>'method'='PREPARE'`,
    [scope.participantId, scope.privacyDomainId, row.rotationId],
  );
  const descriptor = result.rows[0]?.observation.descriptor;
  if (result.rowCount !== 1 || descriptor === null || descriptor === undefined)
    throw new SigningRotationError('CONFLICT');
  return descriptor;
}
export async function planRotationAttempts(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
  operationId: string,
  toState: SigningRotationState,
  callerWorkloadCredentialId: string,
  lifecycleWorkloadCredentialId: string,
): Promise<RotationAttempt[]> {
  // Envelope attempts belong to the separately admitted Participant provider
  // queue. Never dispatch an envelope target through the receipt provider.
  if (row.request.signerRole === 'IDENTITY_ENVELOPE') throw new SigningRotationError('DENIED');
  const effects = signingTransitionEffects(signingRotationActions.advance, row.state, toState);
  if (
    !effects ||
    effects.kind !== 'ADVANCE' ||
    (effects.resumeFrom !== null && effects.resumeFrom !== row.recoveryFromState)
  )
    throw new SigningRotationError('CONFLICT');
  if (row.request.workloadCredentialId !== callerWorkloadCredentialId)
    throw new SigningRotationError('DENIED');
  let challenge = rotationDigest({
    rotationId: row.rotationId,
    candidateDigest: row.candidateDigest.toString('hex'),
    approvalRequestId: row.approvalRequestId,
    revision: row.revision,
    toState,
    newSignerId: row.newSignerId,
  }).toString('hex');
  if (effects.admitTrust)
    challenge = businessSigningTrustDigest(
      await rotationPublicTrust(
        client,
        scope,
        row,
        await preparedRotationDescriptor(client, scope, row),
      ),
    ).toString('hex');
  const base = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: row.request.environmentId,
    workloadCredentialId: row.request.workloadCredentialId,
    callerWorkloadCredentialId,
    secretClass: row.request.secretClass,
    purpose: row.request.purpose,
    operationId,
    rotationId: row.rotationId,
  };
  const planned: { slot: string; request: BusinessProviderRequest }[] = [];
  const add = (
    slot: string,
    method: 'PREPARE' | 'DISTRIBUTE' | 'PROVE' | 'REVOKE' | 'RETIRE',
    old = false,
  ) => {
    const reference = old ? row.request.oldReference : row.request.newReference;
    const common = {
      ...base,
      callerWorkloadCredentialId:
        method === 'PROVE' ? callerWorkloadCredentialId : lifecycleWorkloadCredentialId,
      attemptId: localOperationId(),
      reference,
      version: reference.slice(reference.lastIndexOf('#') + 1),
    };
    const fingerprint = old ? row.request.oldFingerprint : row.newSignerId;
    if (method === 'PREPARE')
      planned.push({
        slot,
        request: {
          ...common,
          method,
          ...(row.request.newFingerprint === undefined
            ? {}
            : { expectedFingerprint: row.request.newFingerprint }),
        },
      });
    else {
      if (fingerprint === null) throw new SigningRotationError('CONFLICT');
      planned.push({
        slot,
        request:
          method === 'PROVE'
            ? { ...common, method, expectedFingerprint: fingerprint, challengeHex: challenge }
            : { ...common, method, expectedFingerprint: fingerprint },
      });
    }
  };
  for (const [slot, method] of effects.providerSteps) add(slot, method, slot === 'old');
  for (const { slot, request } of planned)
    await client.query(
      `insert into control.signing_provider_attempt
    (participant_id,privacy_domain_id,rotation_id,attempt_id,operation_id,from_revision,from_state,to_state,slot,request,request_digest,state)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.rotationId,
        request.attemptId,
        operationId,
        row.revision,
        row.state,
        toState,
        slot,
        request,
        Buffer.from(businessProviderRequestDigest(request).slice(7), 'hex'),
        'READY',
      ],
    );
  return planned.map(({ slot, request }) => ({
    slot,
    request,
    attemptId: request.attemptId,
    observation: null,
    state: 'READY',
  }));
}
