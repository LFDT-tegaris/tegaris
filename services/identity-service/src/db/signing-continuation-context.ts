import type { PoolClient } from 'pg';
import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  businessProviderObservationSchema,
  businessProviderRequestDigest,
  businessProviderRequestSchema,
  validateBusinessProviderObservation,
} from '../domain/business-signing-provider.js';
import {
  SigningContinuationDenied,
  signingContinuationContextSchema,
  signingContinuationPurpose,
} from '../domain/signing-continuation.js';
import {
  lockSigningRotationKeys,
  rotationDigest,
  rotationRow,
  type SigningRotationPartition,
} from './signing-rotation-store.js';
import { getRotationCommand } from './signing-rotation-command.js';

/** Values obtained from an authenticated TLS peer and its exact active credential record. */
export interface SigningContinuationPeer extends SigningRotationPartition {
  readonly principalId: string;
  readonly credentialId: string;
  readonly credentialEpoch: string;
  readonly publicKeyDigest: Buffer;
}
const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');

/** Load and fence original authority and recorded provider truth; this never dispatches or impersonates a user. */
export async function loadSigningContinuationContext(
  client: PoolClient,
  peer: SigningContinuationPeer,
  rotationId: string,
  operationId: string,
  attemptId: string,
) {
  const discovered = await rotationRow(client, peer, rotationId);
  const original = await getRotationCommand(client, peer, operationId);
  if (
    original.rotationId !== rotationId ||
    original.actionIntentId !== 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' ||
    !['ACCEPTED', 'WRITE_AMBIGUITY'].includes(original.state) ||
    discovered.request.workloadCredentialId !== peer.credentialId ||
    discovered.approvalRequestId === null
  )
    throw new SigningContinuationDenied();
  const observed = await client.query<{
    request: unknown;
    requestDigest: Buffer;
    observation: unknown;
    observationDigest: Buffer;
    dispatchedAtNs: string;
    evidenceCbor: Buffer;
    fromRevision: string;
    fromState: string;
  }>(
    `select a.request,a.request_digest as "requestDigest",a.observation,a.observation_digest as "observationDigest",
    a.dispatched_at_ns::text as "dispatchedAtNs",a.from_revision::text as "fromRevision",a.from_state as "fromState",e.evidence_cbor as "evidenceCbor"
    from control.signing_provider_attempt a join control.signing_rotation_command c
    on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.operation_id=a.operation_id
    join control.mutation_evidence e on e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id
      and e.mutation_evidence_id=c.authorization_evidence_id and e.operation_id=c.operation_id
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.rotation_id=$3 and a.operation_id=$4 and a.attempt_id=$5
      and a.to_state=c.to_state and a.from_revision=c.from_revision and a.state='OBSERVED' and a.dispatched_at_ns is not null
      and a.request->>'method' in ('PREPARE','DISTRIBUTE','REVOKE','RETIRE')
      and not exists(select 1 from control.signing_rotation_command recovery where recovery.participant_id=c.participant_id
        and recovery.privacy_domain_id=c.privacy_domain_id and recovery.original_operation_id=c.operation_id and recovery.state='ACCEPTED')`,
    [peer.participantId, peer.privacyDomainId, rotationId, operationId, attemptId],
  );
  const attempt = observed.rows[0];
  if (observed.rowCount !== 1 || !attempt) throw new SigningContinuationDenied();
  const request = businessProviderRequestSchema.parse(attempt.request);
  const observation = businessProviderObservationSchema.parse(attempt.observation);
  validateBusinessProviderObservation(request, observation);
  if (
    request.attemptId !== attemptId ||
    request.operationId !== operationId ||
    !('rotationId' in request) ||
    request.rotationId !== rotationId ||
    request.participantId !== peer.participantId ||
    request.privacyDomainId !== peer.privacyDomainId ||
    businessProviderRequestDigest(request) !== tagged(attempt.requestDigest) ||
    !rotationDigest(observation).equals(attempt.observationDigest)
  )
    throw new SigningContinuationDenied();
  const authority = await client.query<{
    status: { unchangedLive: boolean; dependencies: unknown; approval: unknown };
    statusDigest: Buffer;
    makerDigest: Buffer;
    checkerDigest: Buffer;
  }>(
    `with current_status as materialized(select openpc.signing_attempt_authority_status($1) as value)
    select value as status,openpc.signing_continuation_authority_digest(value) as "statusDigest",
    sha256(convert_to(($2::jsonb->'authorities'->1)::text,'UTF8')) as "makerDigest",
    sha256(convert_to(($2::jsonb->'authorities'->2)::text,'UTF8')) as "checkerDigest" from current_status`,
    [attemptId, original.authorizationSnapshot.toString('utf8')],
  );
  if (authority.rowCount !== 1) throw new SigningContinuationDenied();
  // The retained fence includes the API credential and principal. Recheck the exact TLS key under that lock.
  const live = await client.query(
    `select 1 from control.credential c join control.principal p using(participant_id,principal_id)
    where c.participant_id=$1 and c.credential_id=$2 and c.principal_id=$3 and c.credential_epoch=$4
      and c.public_key_digest=$5 and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
      and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
    [
      peer.participantId,
      peer.credentialId,
      peer.principalId,
      peer.credentialEpoch,
      peer.publicKeyDigest,
    ],
  );
  if (live.rowCount !== 1) throw new SigningContinuationDenied();
  const row = await lockSigningRotationKeys(client, peer, discovered);
  if (
    row.revision !== discovered.revision ||
    row.approvalRequestId !== discovered.approvalRequestId ||
    !row.candidateDigest.equals(discovered.candidateDigest) ||
    !(
      (row.revision === attempt.fromRevision && row.state === attempt.fromState) ||
      (row.state === 'RECOVERING' &&
        row.recoveryFromRevision === attempt.fromRevision &&
        row.recoveryFromState === attempt.fromState)
    )
  )
    throw new SigningContinuationDenied();
  const stillPending = await client.query(
    `select 1 from control.signing_rotation_command c join control.signing_provider_attempt a
    on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.operation_id=c.operation_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.operation_id=$3 and a.attempt_id=$4
      and c.state in ('ACCEPTED','WRITE_AMBIGUITY') and a.state='OBSERVED' and a.observation_digest=$5
      and not exists(select 1 from control.signing_rotation_command r where r.participant_id=c.participant_id
        and r.privacy_domain_id=c.privacy_domain_id and r.original_operation_id=c.operation_id and r.state='ACCEPTED')
    for update of c,a`,
    [peer.participantId, peer.privacyDomainId, operationId, attemptId, attempt.observationDigest],
  );
  if (
    stillPending.rowCount !== 1 ||
    !rotationDigest(JSON.parse(original.authorizationSnapshot.toString('utf8'))).equals(
      original.authorizationSnapshotDigest,
    )
  )
    throw new SigningContinuationDenied();
  const status = authority.rows[0]!.status;
  return signingContinuationContextSchema.parse({
    version: 1,
    purpose: signingContinuationPurpose,
    effect: 'FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT',
    participantId: peer.participantId,
    privacyDomainId: peer.privacyDomainId,
    rotationId,
    rotationRevision: row.revision,
    operationId,
    actionIntentId: original.actionIntentId,
    targetState: original.toState,
    candidateDigest: tagged(original.approvalCandidateDigest),
    approvalRequestId: original.approvalRequestId,
    originalActorKeyDigest: tagged(
      decodeIdentityAuthContextAssertionPayload(attempt.evidenceCbor).actorKeyDigest,
    ),
    originalAuthoritySnapshotDigest: tagged(original.authorizationSnapshotDigest),
    originalMakerSnapshotDigest: tagged(authority.rows[0]!.makerDigest),
    originalCheckerSnapshotDigest: tagged(authority.rows[0]!.checkerDigest),
    providerAttemptId: attemptId,
    providerMethod: request.method,
    providerRequestDigest: tagged(attempt.requestDigest),
    providerObservationDigest: tagged(attempt.observationDigest),
    resultDisposition:
      observation.outcome === 'SUCCEEDED'
        ? 'APPLY_RESERVED_TARGET'
        : observation.reason === 'NOT_APPLIED'
          ? 'NO_EFFECT_RETRYABLE'
          : 'ENTER_FAILED_STATE',
    workloadPrincipalId: peer.principalId,
    workloadCredentialId: peer.credentialId,
    workloadCredentialEpoch: peer.credentialEpoch,
    workloadKeyDigest: tagged(peer.publicKeyDigest),
    currentAuthorityStatus: status.unchangedLive ? 'UNCHANGED_LIVE' : 'CHANGED',
    currentAuthorityDigest: tagged(authority.rows[0]!.statusDigest),
  });
}
