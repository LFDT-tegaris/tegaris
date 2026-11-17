import {
  assertHistoricalRecoveryRotationStep,
  recoveryRotationSubject,
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { identityEnvelopeSigningProfileDigest } from '@openpc/security-kernel';
import { selectIdentityEnvelopeRecoveryTrust } from '../../../participant-service/src/identity-envelope-rotation-selection.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationCutoverResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryRotationCutoverResult,
} from '../contracts/identity-envelope-recovery.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import {
  identityEnvelopeRecoveryEvidencePayload,
  signIdentityEnvelopeRecoveryEvidence,
} from '../domain/identity-envelope-recovery-evidence.js';
import {
  resolveIdentityEnvelopeRecoveryRotationPhase,
  commitIdentityEnvelopeRecoveryRotationPhase,
} from './identity-envelope-recovery-rotation-prepare.js';
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';

/** Cutover changes only the selected 371 key/version. Actual typed consumer
 * acceptance and predecessor private-key revocation remain later gates. */
export async function publishIdentityEnvelopeRecoveryCutover(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationCutoverResult | undefined> {
  return resolveIdentityEnvelopeRecoveryCutover(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    operationId,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryCutover(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationCutoverResult | undefined> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const selected = await client.query<{
    state: string;
    bound: boolean;
    current: boolean;
    result: unknown;
    cbor: Buffer | null;
    digest: Buffer | null;
    cose: Buffer | null;
  }>(
    `select s.state,openpc.identity_envelope_rotation_step_bound(s) as bound,case when s.state='COMMITTED' then false else openpc.identity_envelope_rotation_step_current(s) end as current,
 s.result,s.evidence_cbor as cbor,s.evidence_digest as digest,s.cose_sign1 as cose from control.identity_envelope_rotation_step s where s.operation_id=$1 and s.participant_id=$2 and s.privacy_domain_id=$3 and s.rotation_id=$4 and s.recovery_id=$5 and s.principal_id=$6 and s.from_revision=5 and s.from_state='VERIFIED' and s.to_state='CUTOVER_FENCED' for update of s`,
    [
      operationId,
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const step = selected.rows[0];
  assertHistoricalRecoveryRotationStep(context, step);
  if (selected.rowCount !== 1 || !step?.bound || actor.principalId !== lease.executorPrincipalId)
    throw new PlatformRecoveryError();
  const previous = await client.query<{
    operationId: string;
    expiresAtNs: string;
    attemptCount: number;
  }>(
    `select s.operation_id::text as "operationId",min((a.request->>'challengeExpiresAtNs')::numeric)::text as "expiresAtNs",count(a.attempt_id)::int as "attemptCount"
 from control.identity_envelope_rotation_step s join control.identity_envelope_rotation_attempt a using(participant_id,privacy_domain_id,rotation_id,operation_id)
 where s.participant_id=$1 and s.privacy_domain_id=$2 and s.rotation_id=$3 and s.recovery_id=$4 and s.principal_id=$5 and s.from_revision=4 and s.to_state='VERIFIED' and s.state='COMMITTED' and a.request->>'method'='PROVE' group by s.operation_id`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const prior = previous.rows[0];
  if (previous.rowCount !== 1 || !prior || prior.attemptCount !== 2)
    throw new PlatformRecoveryError();
  const verified = await resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    context,
    enrollment,
    lease,
    prior.operationId,
    localQaEnabled,
    signer,
  );
  if (!verified || verified.state !== 'VERIFIED' || verified.admissionState !== 'ADMITTED')
    throw new PlatformRecoveryError();
  const version = (BigInt(lease.selectionAdmissionVersion) + 1n).toString();
  const empty = await client.query<{ count: number }>(
    'select count(*)::int as count from control.identity_envelope_rotation_attempt where operation_id=$1',
    [operationId],
  );
  if (empty.rowCount !== 1 || empty.rows[0]?.count !== 0) throw new PlatformRecoveryError();
  if (step.state === 'COMMITTED') {
    const result = identityEnvelopeRecoveryRotationCutoverResult.parse(step.result);
    if (
      result.operationId !== operationId ||
      result.rotationId !== lease.rotationId ||
      result.recoveryId !== lease.recoveryId ||
      result.signerId !== verified.signerId ||
      result.trustDigest !== verified.trustDigest ||
      result.selectionAdmissionVersion !== version ||
      result.observationsDigest !== canonicalAuthorizationDigest([])
    )
      throw new PlatformRecoveryError();
    const payload = identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'rotation-phase',
      value: result,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: result.completedAt,
      expiresAt: lease.validUntil,
    });
    if (
      !step.cbor ||
      !step.digest ||
      !step.cose ||
      !step.cbor.equals(payload) ||
      !step.digest.equals(createHash('sha256').update(payload).digest()) ||
      !(await signer.verifyCanonicalAssertion(payload, step.cose))
    )
      throw new PlatformRecoveryError();
    const event = await client.query<{ matches: boolean }>(
      `select exists(select 1 from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation' and aggregate_id=$3 and event_id=$4 and event_type='openpc.identity.envelope-rotation.phase.v1' and payload_cbor=$5 and payload_digest=$6 and cose_sign1=$7) as matches`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        lease.rotationId,
        operationId,
        payload,
        step.digest,
        step.cose,
      ],
    );
    if (event.rowCount !== 1 || event.rows[0]?.matches !== true) throw new PlatformRecoveryError();
    return result;
  }
  if (step.state !== 'STARTED' || step.current !== true) return undefined;
  requireCurrentRecoveryRotationActor(context);
  const source = await captureIdentityEnvelopeRotationSource(
    client,
    enrollment,
    enrollment.request,
    signer,
  );
  // Authenticate current old selection and issuer without recapturing the lease.
  if (
    source.issuer.workloadParticipantEpoch !== lease.issuer.workloadParticipantEpoch ||
    canonicalAuthorizationDigest(source.issuer) !== canonicalAuthorizationDigest(lease.issuer) ||
    source.recordedAtNs >= BigInt(prior.expiresAtNs)
  )
    throw new PlatformRecoveryError();
  const successor = await client.query<{ matches: boolean }>(
    `select exists(select 1 from control.business_signing_key k join control.identity_envelope_signing_grant g using(participant_id,privacy_domain_id,signer_id)
 join control.business_signing_key_state life using(participant_id,privacy_domain_id,signer_id) where k.participant_id=$1 and k.privacy_domain_id=$2 and k.signer_id=$3 and k.trust_digest=$4 and k.signing_purpose_code=371 and g.signing_purpose_code=371 and g.profile_digest=$5 and life.state='ADMITTED' and life.row_version=1) as matches`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      verified.signerId,
      Buffer.from(verified.trustDigest.slice(7), 'hex'),
      Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex'),
    ],
  );
  if (successor.rowCount !== 1 || successor.rows[0]?.matches !== true)
    throw new PlatformRecoveryError();
  const result = identityEnvelopeRecoveryRotationCutoverResult.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: '5',
    revision: '6',
    state: 'CUTOVER_FENCED',
    selectionAdmissionVersion: version,
    permissionEffect: 'NONE',
    signerId: verified.signerId,
    trustDigest: verified.trustDigest,
    observationsDigest: canonicalAuthorizationDigest([]),
    completedAt: new Date(Number(source.recordedAtNs / 1000000n)).toISOString(),
  });
  requireCurrentRecoveryRotationActor(context);
  const signed = await signIdentityEnvelopeRecoveryEvidence(
    identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'rotation-phase',
      value: result,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: result.completedAt,
      expiresAt: lease.validUntil,
    }),
    signer,
  );
  await commitIdentityEnvelopeRecoveryRotationPhase(
    client,
    {
      actor: requireCurrentRecoveryRotationActor(context),
      enrollment,
      lease,
      result,
      signed,
      fromState: 'VERIFIED',
    },
    () => selectIdentityEnvelopeRecoveryTrust(client, result),
  );
  return result;
}
