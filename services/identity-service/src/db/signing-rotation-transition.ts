import { signingTransitionEffects } from '../../../../packages/security-kernel/src/signing-transitions.js';
import type { PoolClient } from 'pg';
import { businessSigningTrustDigest } from '@openpc/security-kernel';
import { validateBusinessProviderObservation } from '../domain/business-signing-provider.js';
import { SigningRotationError } from '../domain/signing-rotation.js';
import {
  rotationDigest,
  type RotationRow,
  type SigningRotationPartition,
} from './signing-rotation-store.js';
import type { RotationCommand } from './signing-rotation-command.js';
import { rotationAttempts, preparedRotationDescriptor } from './signing-rotation-attempts.js';
import { admitRotationTrust, rotationPublicTrust } from './signing-rotation-trust.js';
import { consumeSigningGeneration } from './signing-generation-consumption.js';

/** Record a definitive provider rejection without changing any selected key or undoing cutover. */
export async function applySigningRotationFailure(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
  command: RotationCommand,
) {
  if (signingTransitionEffects(command.actionIntentId, row.state, 'FAILED')?.kind !== 'FAILURE')
    throw new SigningRotationError('CONFLICT');
  const attempts = (await rotationAttempts(client, scope, command.operationId)).filter(
    (attempt) => attempt.request.method !== 'SIGN_RECEIPT',
  );
  if (attempts.length === 0) throw new SigningRotationError('CONFLICT');
  let rejected = false;
  for (const attempt of attempts) {
    if (attempt.state !== 'OBSERVED' || attempt.observation === null)
      throw new SigningRotationError('AMBIGUOUS');
    validateBusinessProviderObservation(attempt.request, attempt.observation);
    rejected ||=
      attempt.observation.outcome === 'REJECTED' &&
      (attempt.request.method === 'PROVE' || attempt.observation.reason !== 'NOT_APPLIED');
  }
  if (!rejected) throw new SigningRotationError('CONFLICT');
  await client.query(
    `update control.signing_provider_attempt set state=case when request->>'method'='SIGN_RECEIPT' then 'ACCEPTED' else 'REJECTED' end
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='OBSERVED'`,
    [scope.participantId, scope.privacyDomainId, command.operationId],
  );
  await client.query(
    `update control.signing_key_rotation set state='FAILED',revision=revision+1,updated_at=clock_timestamp(),
     recovery_from_state=null,recovery_from_revision=null
     where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and revision=$4`,
    [scope.participantId, scope.privacyDomainId, row.rotationId, row.revision],
  );
  await client.query(
    `update control.signing_rotation_command set state='FAILED',result_kind='PROVIDER_REJECTED',result_revision=$4,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    [
      scope.participantId,
      scope.privacyDomainId,
      command.operationId,
      (BigInt(row.revision) + 1n).toString(),
    ],
  );
  await consumeSigningGeneration(client, scope, command, (BigInt(row.revision) + 1n).toString());
}

export async function applySigningRotationTransition(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
  command: RotationCommand,
  recordedAtNs: bigint,
) {
  const effects = signingTransitionEffects(command.actionIntentId, row.state, command.toState);
  if (
    !effects ||
    effects.kind !== 'ADVANCE' ||
    (effects.resumeFrom !== null && effects.resumeFrom !== row.recoveryFromState)
  )
    throw new SigningRotationError('CONFLICT');
  const attempts = (await rotationAttempts(client, scope, command.operationId)).filter(
    (a) => a.request.method !== 'SIGN_RECEIPT',
  );
  for (const attempt of attempts) {
    if (attempt.observation === null) throw new SigningRotationError('AMBIGUOUS');
    try {
      validateBusinessProviderObservation(attempt.request, attempt.observation);
    } catch {
      throw new SigningRotationError('PROVIDER_REJECTED');
    }
    if (attempt.observation.outcome !== 'SUCCEEDED')
      throw new SigningRotationError('PROVIDER_REJECTED');
  }
  let newSignerId = row.newSignerId;
  if (effects.prepare) {
    const descriptor = attempts[0]?.observation?.descriptor;
    if (
      descriptor === null ||
      descriptor === undefined ||
      descriptor.fingerprint === row.request.oldFingerprint ||
      (row.request.newFingerprint !== undefined &&
        descriptor.fingerprint !== row.request.newFingerprint)
    )
      throw new SigningRotationError('PROVIDER_REJECTED');
    newSignerId = descriptor.fingerprint;
  }
  if (effects.admitTrust) {
    const trust = await rotationPublicTrust(
      client,
      scope,
      row,
      await preparedRotationDescriptor(client, scope, row),
    );
    const digest = businessSigningTrustDigest(trust).toString('hex');
    if (
      attempts.length !== 2 ||
      !['old', 'new'].every((slot) =>
        attempts.some(
          (a) =>
            a.slot === slot && a.request.method === 'PROVE' && a.request.challengeHex === digest,
        ),
      )
    )
      throw new SigningRotationError('CONFLICT');
    await admitRotationTrust(client, trust);
  }
  if (effects.cutover) {
    const trust = await rotationPublicTrust(
      client,
      scope,
      row,
      await preparedRotationDescriptor(client, scope, row),
    );
    const active = await client.query(
      `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,
      changed_at_ns=floor(extract(epoch from clock_timestamp())*1000000)*1000,change_reference=$4,change_digest=$5
      where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='ADMITTED'`,
      [
        scope.participantId,
        scope.privacyDomainId,
        newSignerId,
        trust.admissionReference,
        rotationDigest({
          rotationId: row.rotationId,
          state: command.toState,
          revision: row.revision,
        }),
      ],
    );
    if (active.rowCount !== 1) throw new SigningRotationError('CONFLICT');
    const selected = await client.query(
      `update control.business_signing_selection set signer_id=$5,row_version=row_version+1,fenced_operation_id=null,
      changed_at_ns=floor(extract(epoch from clock_timestamp())*1000000)*1000,change_reference=$6,change_digest=$7
      where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and signer_id=$4
       and fenced_operation_id=$8 returning profile_digest`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.request.environmentId,
        row.request.oldFingerprint,
        newSignerId,
        trust.admissionReference,
        rotationDigest({
          rotationId: row.rotationId,
          state: command.toState,
          revision: row.revision,
        }),
        command.operationId,
      ],
    );
    if (
      selected.rowCount !== trust.grants.length ||
      !trust.grants.every((g) =>
        selected.rows.some((s) => g.profileDigest.equals(s.profile_digest as Buffer)),
      )
    )
      throw new SigningRotationError('CONFLICT');
    const fenced = await client.query(
      `update control.business_signing_key_state set state='RETIRED',row_version=row_version+1,
      changed_at_ns=floor(extract(epoch from clock_timestamp())*1000000)*1000,change_reference=$4,change_digest=$5
      where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='ACTIVE'`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.request.oldFingerprint,
        trust.admissionReference,
        rotationDigest({
          rotationId: row.rotationId,
          state: 'OLD_SIGNING_FENCED',
          revision: row.revision,
        }),
      ],
    );
    if (fenced.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  }
  if (effects.revoke) {
    const revoked = await client.query(
      `update control.business_signing_key_state set state='REVOKED',row_version=row_version+1,
      changed_at_ns=floor(extract(epoch from clock_timestamp())*1000000)*1000,change_reference=$4,change_digest=$5
      where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='RETIRED'`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.request.oldFingerprint,
        `urn:openpc:resource:${row.rotationId}`,
        rotationDigest({
          rotationId: row.rotationId,
          state: command.toState,
          revision: row.revision,
        }),
      ],
    );
    if (revoked.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  }
  await client.query(
    `update control.signing_provider_attempt set state='ACCEPTED' where participant_id=$1 and privacy_domain_id=$2
    and operation_id=$3 and state='OBSERVED'`,
    [scope.participantId, scope.privacyDomainId, command.operationId],
  );
  await client.query(
    `update control.signing_key_rotation set state=$4,new_signer_id=$5,revision=revision+1,updated_at=clock_timestamp(),recovery_from_state=null,recovery_from_revision=null,
    cutover_at_ns=case when $7::boolean then $6::bigint else cutover_at_ns end
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.rotationId,
      command.toState,
      newSignerId,
      recordedAtNs.toString(),
      effects.cutover,
    ],
  );
  await client.query(
    `update control.signing_rotation_command set state='SUCCEEDED',result_revision=$4,updated_at=clock_timestamp()
    where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    [
      scope.participantId,
      scope.privacyDomainId,
      command.operationId,
      (BigInt(row.revision) + 1n).toString(),
    ],
  );
  await consumeSigningGeneration(client, scope, command, (BigInt(row.revision) + 1n).toString());
}
