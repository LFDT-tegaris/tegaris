import {
  assertHistoricalRecoveryRotationStep,
  recoveryRotationSubject,
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { revokeIdentityEnvelopeRecoveryTrust } from '../../../participant-service/src/identity-envelope-rotation-revocation.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationRevocationResult,
  identityEnvelopeRecoveryRotationRetirementResult,
  identityEnvelopeRecoveryRotationCompletionResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryRotationRevocationResult,
  type IdentityEnvelopeRecoveryRotationRetirementResult,
  type IdentityEnvelopeRecoveryRotationCompletionResult,
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
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  validateIdentityEnvelopeRotationObservation,
} from '../domain/identity-envelope-rotation-provider.js';
import { planIdentityEnvelopeRotationAttempts } from '../domain/identity-envelope-rotation-plan.js';
import {
  authenticatedIdentityEnvelopeSigningTrust,
  type IdentityEnvelopeSigningKeyRow,
} from './identity-envelope-signing-store.js';
import { captureIdentityEnvelopeRotationSuccessorSource } from './identity-envelope-rotation-successor-source.js';
import {
  commitIdentityEnvelopeRecoveryRotationPhase,
  resolveIdentityEnvelopeRecoveryRotationPhase,
  resolveIdentityEnvelopeRecoveryDistributedDescriptor,
} from './identity-envelope-recovery-rotation-prepare.js';
export type IdentityEnvelopeRecoveryRotationTerminalResult =
  | IdentityEnvelopeRecoveryRotationRevocationResult
  | IdentityEnvelopeRecoveryRotationRetirementResult
  | IdentityEnvelopeRecoveryRotationCompletionResult;

/** Original accepted consumer precedes irreversible private effects. Exact
 * journal lookup is the only reconciliation; no public revocation downgrade. */
export async function publishIdentityEnvelopeRecoveryRetirement(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationTerminalResult | undefined> {
  return resolveIdentityEnvelopeRecoveryRetirement(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    operationId,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryRetirement(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationTerminalResult | undefined> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const found = await client.query<{
    state: string;
    fromRevision: string;
    fromState: string;
    toState: string;
    consumerObservationId: string;
    bound: boolean;
    current: boolean;
    result: unknown;
    cbor: Buffer | null;
    digest: Buffer | null;
    cose: Buffer | null;
  }>(
    `select s.state,s.from_revision::text as "fromRevision",s.from_state as "fromState",s.to_state as "toState",s.consumer_observation_operation_id::text as "consumerObservationId",openpc.identity_envelope_rotation_step_bound(s) as bound,case when s.state='COMMITTED' then false else openpc.identity_envelope_rotation_step_current(s) end as current,s.result,s.evidence_cbor as cbor,s.evidence_digest as digest,s.cose_sign1 as cose from control.identity_envelope_rotation_step s where s.operation_id=$1 and s.participant_id=$2 and s.privacy_domain_id=$3 and s.rotation_id=$4 and s.recovery_id=$5 and s.principal_id=$6 for update of s`,
    [
      operationId,
      actor.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      actor.principalId,
    ],
  );
  const step = found.rows[0];
  assertHistoricalRecoveryRotationStep(context, step);
  const phase =
    step?.fromRevision === '7' && step.fromState === 'OBSERVING' && step.toState === 'OLD_REVOKED'
      ? 'revoke'
      : step?.fromRevision === '8' &&
          step.fromState === 'OLD_REVOKED' &&
          step.toState === 'OLD_RETIRED'
        ? 'retire'
        : step?.fromRevision === '9' &&
            step.fromState === 'OLD_RETIRED' &&
            step.toState === 'COMPLETE'
          ? 'complete'
          : undefined;
  if (
    found.rowCount !== 1 ||
    !step?.bound ||
    !phase ||
    !step.consumerObservationId ||
    actor.principalId !== lease.executorPrincipalId
  )
    throw new PlatformRecoveryError();
  const observed = await resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    context,
    enrollment,
    lease,
    step.consumerObservationId,
    localQaEnabled,
    signer,
  );
  if (
    !observed ||
    observed.state !== 'OBSERVING' ||
    observed.operationId !== step.consumerObservationId
  )
    throw new PlatformRecoveryError();
  let previous: IdentityEnvelopeRecoveryRotationTerminalResult | undefined;
  if (phase !== 'revoke') {
    const prior = await client.query<{ operationId: string }>(
      `select operation_id::text as "operationId" from control.identity_envelope_rotation_step where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and recovery_id=$4 and consumer_observation_operation_id=$5 and from_revision=$6 and state='COMMITTED'`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        lease.rotationId,
        lease.recoveryId,
        step.consumerObservationId,
        phase === 'retire' ? '7' : '8',
      ],
    );
    if (prior.rowCount !== 1 || !prior.rows[0]) throw new PlatformRecoveryError();
    previous = await resolveIdentityEnvelopeRecoveryRetirement(
      client,
      context,
      enrollment,
      lease,
      prior.rows[0].operationId,
      localQaEnabled,
      signer,
    );
    if (!previous || previous.state !== (phase === 'retire' ? 'OLD_REVOKED' : 'OLD_RETIRED'))
      throw new PlatformRecoveryError();
  }
  const attempts = await client.query<{
    slot: string;
    request: unknown;
    requestDigest: Buffer;
    state: string;
    first: unknown;
    firstDigest: Buffer | null;
    observation: unknown;
    digest: Buffer | null;
    startedAtNs: string | null;
  }>(
    `select slot,request,request_digest as "requestDigest",state,first_observation as first,first_observation_digest as "firstDigest",observation,observation_digest as digest,(floor(extract(epoch from started_at)*1000000)*1000)::text as "startedAtNs" from control.identity_envelope_rotation_attempt where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 and rotation_id=$4 for share`,
    [operationId, actor.participantId, enrollment.privacyDomainId, lease.rotationId],
  );
  if (attempts.rowCount !== (phase === 'complete' ? 0 : 1)) throw new PlatformRecoveryError();
  const attempt = attempts.rows[0];
  if (phase !== 'complete' && (!attempt || attempt.slot !== 'old'))
    throw new PlatformRecoveryError();
  if (attempt && attempt.state !== 'OBSERVED') return undefined;
  const schema =
    phase === 'revoke'
      ? identityEnvelopeRecoveryRotationRevocationResult
      : phase === 'retire'
        ? identityEnvelopeRecoveryRotationRetirementResult
        : identityEnvelopeRecoveryRotationCompletionResult;
  const historical = step.state === 'COMMITTED';
  const original = historical ? schema.parse(step.result) : undefined;
  if (!historical && (step.state !== 'STARTED' || !step.current)) return undefined;
  let source;
  if (historical) {
    const retained = await client.query<IdentityEnvelopeSigningKeyRow>(
      `select key.* from control.business_signing_key key where key.participant_id=$1 and key.privacy_domain_id=$2 and key.signer_id in($3,$4) and key.signing_purpose_code=371`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        enrollment.request.oldFingerprint,
        observed.signerId,
      ],
    );
    const old = retained.rows.find((k) => k.signer_id === enrollment.request.oldFingerprint),
      next = retained.rows.find((k) => k.signer_id === observed.signerId);
    if (retained.rowCount !== 2 || !old || !next) throw new PlatformRecoveryError();
    source = {
      trust: authenticatedIdentityEnvelopeSigningTrust(old),
      selectedTrust: authenticatedIdentityEnvelopeSigningTrust(next),
      issuer: lease.issuer,
      recordedAtNs: timestampNs(original!.completedAt),
    };
  } else {
    requireCurrentRecoveryRotationActor(context);
    source = await captureIdentityEnvelopeRotationSuccessorSource(client, enrollment, lease);
  }
  if (
    identityEnvelopeSigningTrustDigest(source.trust) !== lease.oldTrustDigest ||
    identityEnvelopeSigningTrustDigest(source.selectedTrust) !== observed.trustDigest ||
    source.recordedAtNs >= BigInt(Date.parse(lease.validUntil)) * 1000000n
  )
    throw new PlatformRecoveryError();
  const prepared = await resolveIdentityEnvelopeRecoveryDistributedDescriptor(
    client,
    context,
    enrollment,
    lease,
    localQaEnabled,
    signer,
  );
  const plan = planIdentityEnvelopeRotationAttempts(
    {
      request: enrollment.request,
      rotationId: lease.rotationId,
      operationId,
      state: step.fromState as 'OBSERVING' | 'OLD_REVOKED' | 'OLD_RETIRED',
      toState: step.toState as 'OLD_REVOKED' | 'OLD_RETIRED' | 'COMPLETE',
      oldTrust: source.trust,
      preparedIssuer: lease.issuer,
      currentIssuer: source.issuer,
      admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease },
      descriptor: prepared.descriptor,
      callerWorkloadCredentialId: lease.issuer.workloadCredentialId,
      nowNs: source.recordedAtNs,
      authorityValidUntilNs: BigInt(Date.parse(lease.validUntil)) * 1000000n,
    },
    () => (attempt ? identityEnvelopeRotationRequestSchema.parse(attempt.request).attemptId : ''),
  );
  let revokedAtNs = previous?.oldPrivateKeyRevokedAtNs,
    retiredAtNs = previous?.oldPrivateKeyRetiredAtNs ?? null;
  let observationsDigest = canonicalAuthorizationDigest([]);
  if (attempt) {
    const request = identityEnvelopeRotationRequestSchema.parse(attempt.request);
    if (
      request.method !== (phase === 'revoke' ? 'REVOKE' : 'RETIRE') ||
      canonicalAuthorizationJson(plan.attempts[0]?.request) !==
        canonicalAuthorizationJson(request) ||
      identityEnvelopeRotationRequestDigest(request) !==
        'sha256:' + attempt.requestDigest.toString('hex') ||
      !attempt.firstDigest ||
      !attempt.digest ||
      !attempt.startedAtNs ||
      canonicalAuthorizationDigest(attempt.first) !==
        'sha256:' + attempt.firstDigest.toString('hex') ||
      canonicalAuthorizationDigest(attempt.observation) !==
        'sha256:' + attempt.digest.toString('hex') ||
      !attempt.firstDigest.equals(attempt.digest)
    )
      throw new PlatformRecoveryError();
    const first = validateIdentityEnvelopeRotationObservation(request, attempt.first),
      observation = validateIdentityEnvelopeRotationObservation(request, attempt.observation);
    const d = observation.descriptor,
      t = source.trust;
    if (
      observation.outcome !== 'SUCCEEDED' ||
      !d ||
      canonicalAuthorizationJson(first) !== canonicalAuthorizationJson(observation) ||
      BigInt(observation.recordedAtNs) < BigInt(attempt.startedAtNs) ||
      BigInt(observation.recordedAtNs) > source.recordedAtNs ||
      d.fingerprint !== t.signerId ||
      d.publicKeySpkiHex !== t.publicKeySpkiDer.toString('hex') ||
      d.reference !== t.secretReference ||
      d.version !== t.secretVersion ||
      d.participantId !== t.participantId ||
      d.privacyDomainId !== t.privacyDomainId ||
      d.environmentId !== t.environmentId ||
      d.workloadCredentialId !== t.workloadCredentialId ||
      d.workloadCredentialEpoch !== t.workloadCredentialEpoch.toString() ||
      d.validFromNs !== t.validFromNs.toString() ||
      d.validUntilNs !== t.validUntilNs.toString() ||
      BigInt((phase === 'revoke' ? d.revokedAtNs : d.retiredAtNs)!) < BigInt(attempt.startedAtNs) ||
      (phase === 'retire' && d.revokedAtNs !== previous!.oldPrivateKeyRevokedAtNs)
    )
      throw new PlatformRecoveryError();
    revokedAtNs = d.revokedAtNs!;
    retiredAtNs = d.retiredAtNs;
    observationsDigest = canonicalAuthorizationDigest([{ slot: 'old', request, observation }]);
  }
  if (!revokedAtNs || (phase !== 'revoke' && !retiredAtNs)) throw new PlatformRecoveryError();
  const result = schema.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: step.fromRevision,
    revision: (BigInt(step.fromRevision) + 1n).toString(),
    state: step.toState,
    selectionAdmissionVersion: observed.selectionAdmissionVersion,
    permissionEffect: 'NONE',
    signerId: observed.signerId,
    trustDigest: observed.trustDigest,
    observationsDigest,
    consumerObservationOperationId: step.consumerObservationId,
    consumerActivationOperationId: observed.consumerActivationOperationId,
    consumerEnvelopeId: observed.consumerEnvelopeId,
    consumerPayloadDigest: observed.consumerPayloadDigest,
    consumerReceiptDigest: observed.consumerReceiptDigest,
    predecessorSignerId: enrollment.request.oldFingerprint,
    oldPrivateKeyState: phase === 'revoke' ? 'REVOKED' : 'RETIRED',
    oldPrivateKeyRevokedAtNs: revokedAtNs,
    oldPrivateKeyRetiredAtNs: retiredAtNs,
    ...(phase === 'complete' ? { postReviewRequired: true } : {}),
    completedAt: timestampIso(source.recordedAtNs),
  });
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
  if (historical) {
    if (
      canonicalAuthorizationDigest(original) !== canonicalAuthorizationDigest(result) ||
      !step.cbor ||
      !step.digest ||
      !step.cose ||
      !step.cbor.equals(payload) ||
      !step.digest.equals(createHash('sha256').update(payload).digest()) ||
      !(await signer.verifyCanonicalAssertion(payload, step.cose))
    )
      throw new PlatformRecoveryError();
    const retained = await client.query<{ matches: boolean }>(
      `select exists(select 1 from control.business_signing_key_state old_life where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state in('REVOKED','COMPROMISED')) and exists(select 1 from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation' and aggregate_id=$4 and event_id=$5 and event_type='openpc.identity.envelope-rotation.phase.v1' and payload_cbor=$6 and payload_digest=$7 and cose_sign1=$8) as matches`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        enrollment.request.oldFingerprint,
        lease.rotationId,
        operationId,
        payload,
        step.digest,
        step.cose,
      ],
    );
    if (retained.rowCount !== 1 || retained.rows[0]?.matches !== true)
      throw new PlatformRecoveryError();
    return result;
  }
  requireCurrentRecoveryRotationActor(context);
  const signed = await signIdentityEnvelopeRecoveryEvidence(payload, signer);
  await commitIdentityEnvelopeRecoveryRotationPhase(
    client,
    {
      actor: requireCurrentRecoveryRotationActor(context),
      enrollment,
      lease,
      result,
      signed,
      fromState: step.fromState,
    },
    phase === 'revoke' ? () => revokeIdentityEnvelopeRecoveryTrust(client, result) : undefined,
  );
  return result;
}
function timestampIso(ns: bigint) {
  return new Date(Number(ns / 1000000n))
    .toISOString()
    .replace('Z', `${(ns % 1000000n).toString().padStart(6, '0')}Z`);
}
function timestampNs(value: string) {
  const fraction = value.match(/\.([0-9]+)Z$/u)?.[1] ?? '';
  return BigInt(Date.parse(value)) * 1000000n + BigInt(fraction.padEnd(9, '0').slice(3, 9));
}
