import {
  assertHistoricalRecoveryRotationStep,
  recoveryRotationSubject,
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { authenticateIdentityEnvelopeRotationEffectiveProof } from '../../../participant-service/src/identity-envelope-rotation-proof.js';
import { readIdentityEnvelopeRotationConsumer } from '../../../participant-service/src/identity-envelope-rotation-consumer.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationObservationResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryRotationObservationResult,
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
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationRequestSchema,
} from '../domain/identity-envelope-rotation-provider.js';
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

/** Actual consumer and confirmed effective proof, under the original custody.
 * No predecessor revocation, permission grant or consumer fabrication. */
export async function publishIdentityEnvelopeRecoveryObservation(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationObservationResult | undefined> {
  return resolveIdentityEnvelopeRecoveryObservation(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    operationId,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryObservation(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationObservationResult | undefined> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const selected = await client.query<{
    state: string;
    bound: boolean;
    current: boolean;
    consumerId: string;
    result: unknown;
    cbor: Buffer | null;
    digest: Buffer | null;
    cose: Buffer | null;
  }>(
    `select s.state,openpc.identity_envelope_rotation_step_bound(s) as bound,case when s.state='COMMITTED' then false else openpc.identity_envelope_rotation_step_current(s) end as current,s.consumer_activation_operation_id::text as "consumerId",s.result,s.evidence_cbor as cbor,s.evidence_digest as digest,s.cose_sign1 as cose
 from control.identity_envelope_rotation_step s where s.operation_id=$1 and s.participant_id=$2 and s.privacy_domain_id=$3 and s.rotation_id=$4 and s.recovery_id=$5 and s.principal_id=$6 and s.from_revision=6 and s.from_state='CUTOVER_FENCED' and s.to_state='OBSERVING' for update of s`,
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
  if (
    selected.rowCount !== 1 ||
    !step?.bound ||
    !step.consumerId ||
    actor.principalId !== lease.executorPrincipalId
  )
    throw new PlatformRecoveryError();
  const attempts = await client.query<{
    slot: string;
    request: unknown;
    requestDigest: Buffer;
    state: string;
    firstObservation: unknown;
    firstDigest: Buffer | null;
    observation: unknown;
    digest: Buffer | null;
    startedAtNs: string | null;
  }>(
    `select slot,request,request_digest as "requestDigest",state,first_observation as "firstObservation",first_observation_digest as "firstDigest",observation,observation_digest as digest,(floor(extract(epoch from started_at)*1000000)*1000)::text as "startedAtNs" from control.identity_envelope_rotation_attempt where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 and rotation_id=$4 for share`,
    [operationId, actor.participantId, enrollment.privacyDomainId, lease.rotationId],
  );
  const attempt = attempts.rows[0];
  if (attempts.rowCount !== 1 || !attempt || attempt.slot !== 'effective')
    throw new PlatformRecoveryError();
  if (attempt.state !== 'OBSERVED') return undefined;
  const request = identityEnvelopeRotationRequestSchema.parse(attempt.request);
  if (
    request.method !== 'PROVE' ||
    !attempt.startedAtNs ||
    !attempt.firstDigest ||
    !attempt.digest ||
    identityEnvelopeRotationRequestDigest(request) !==
      'sha256:' + attempt.requestDigest.toString('hex') ||
    canonicalAuthorizationDigest(attempt.firstObservation) !==
      'sha256:' + attempt.firstDigest.toString('hex') ||
    canonicalAuthorizationDigest(attempt.observation) !==
      'sha256:' + attempt.digest.toString('hex') ||
    !attempt.firstDigest.equals(attempt.digest) ||
    typeof attempt.observation !== 'object' ||
    attempt.observation === null ||
    !('recordedAtNs' in attempt.observation) ||
    BigInt(String(attempt.observation.recordedAtNs)) < BigInt(attempt.startedAtNs)
  )
    throw new PlatformRecoveryError();
  const prior = await client.query<{ operationId: string }>(
    `select operation_id::text as "operationId" from control.identity_envelope_rotation_step where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and recovery_id=$4 and from_revision=5 and to_state='CUTOVER_FENCED' and state='COMMITTED'`,
    [actor.participantId, enrollment.privacyDomainId, lease.rotationId, lease.recoveryId],
  );
  if (prior.rowCount !== 1 || !prior.rows[0]) throw new PlatformRecoveryError();
  const cutover = await resolveIdentityEnvelopeRecoveryRotationPhase(
    client,
    context,
    enrollment,
    lease,
    prior.rows[0].operationId,
    localQaEnabled,
    signer,
  );
  if (!cutover || cutover.state !== 'CUTOVER_FENCED') throw new PlatformRecoveryError();
  const prepared = await resolveIdentityEnvelopeRecoveryDistributedDescriptor(
    client,
    context,
    enrollment,
    lease,
    localQaEnabled,
    signer,
  );
  const historical = step.state === 'COMMITTED';
  const original = historical
    ? identityEnvelopeRecoveryRotationObservationResult.parse(step.result)
    : undefined;
  if (!historical && (step.state !== 'STARTED' || !step.current)) return undefined;
  let source;
  if (historical) {
    // Retained immutable public metadata is sufficient to authenticate the
    // original signed result. Current activation/selection eligibility is not
    // recaptured, and no historical read may open a new phase or provider I/O.
    const retained = await client.query<IdentityEnvelopeSigningKeyRow>(
      `select key.* from control.business_signing_key key where key.participant_id=$1 and key.privacy_domain_id=$2 and key.signer_id in($3,$4) and key.signing_purpose_code=371`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        enrollment.request.oldFingerprint,
        cutover.signerId,
      ],
    );
    const old = retained.rows.find((row) => row.signer_id === enrollment.request.oldFingerprint);
    const next = retained.rows.find((row) => row.signer_id === cutover.signerId);
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
  const proof = authenticateIdentityEnvelopeRotationEffectiveProof(
    {
      request: enrollment.request,
      rotationId: lease.rotationId,
      operationId,
      descriptor: prepared.descriptor,
      oldTrust: source.trust,
      selectedTrust: source.selectedTrust,
      preparedIssuer: lease.issuer,
      currentIssuer: source.issuer,
      admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease },
      callerWorkloadCredentialId: lease.issuer.workloadCredentialId,
      nowNs: source.recordedAtNs,
      authorityValidUntilNs: BigInt(Date.parse(lease.validUntil)) * 1000000n,
    },
    attempt,
  );
  if (
    proof.trustDigest !== cutover.trustDigest ||
    proof.trustDigest !== prepared.result.trustDigest ||
    identityEnvelopeSigningTrustDigest(source.trust) !== lease.oldTrustDigest
  )
    throw new PlatformRecoveryError();
  const consumer = historical
    ? {
        operationId: original!.consumerActivationOperationId,
        envelopeId: original!.consumerEnvelopeId,
        payloadDigest: original!.consumerPayloadDigest,
        receiptDigest: original!.consumerReceiptDigest,
      }
    : await readIdentityEnvelopeRotationConsumer(
        client,
        {
          trust: source.selectedTrust,
          cutoverAtNs: 'cutoverAtNs' in source ? source.cutoverAtNs : 0n,
          observedAtNs: BigInt(request.challengeIssuedAtNs),
          operationId: step.consumerId,
        },
        signer,
      );
  if (!consumer || consumer.operationId !== step.consumerId) throw new PlatformRecoveryError();
  const result = identityEnvelopeRecoveryRotationObservationResult.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: '6',
    revision: '7',
    state: 'OBSERVING',
    selectionAdmissionVersion: cutover.selectionAdmissionVersion,
    permissionEffect: 'NONE',
    signerId: proof.trust.signerId,
    trustDigest: proof.trustDigest,
    observationsDigest: proof.observationsDigest,
    consumerActivationOperationId: consumer.operationId,
    consumerEnvelopeId: consumer.envelopeId,
    consumerPayloadDigest: consumer.payloadDigest,
    consumerReceiptDigest: consumer.receiptDigest,
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
      `select exists(select 1 from control.identity_envelope_activation a join control.mutation_evidence receipt on receipt.participant_id=a.participant_id and receipt.privacy_domain_id=a.privacy_domain_id and receipt.operation_id=a.operation_id and receipt.aggregate_id=a.envelope_id
 where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.envelope_id=$4 and a.state='COMMITTED' and a.row_version=4 and a.reserved_at_ns>=(select cutover_at_ns from control.signing_key_rotation where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$9 and recovery_case_id=$15) and floor(extract(epoch from a.committed_at)*1000000)*1000<=$14 and a.payload_digest=$5 and a.payload_digest=sha256(a.payload_cbor) and a.request->>'expectedFingerprint'=$6 and a.request->>'trustContextDigest'=$7 and receipt.evidence_digest=$8 and receipt.evidence_digest=sha256(receipt.evidence_cbor)
 and exists(select 1 from control.outbox_event event where event.participant_id=receipt.participant_id and event.privacy_domain_id=receipt.privacy_domain_id and event.aggregate_type='authority-envelope' and event.aggregate_id=a.envelope_id and event.event_type='openpc.authority-envelope.mutation.committed.v1' and event.payload_cbor=receipt.evidence_cbor and event.payload_digest=receipt.evidence_digest and event.cose_sign1=receipt.cose_sign1))
 and exists(select 1 from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation' and aggregate_id=$9 and event_id=$10 and event_type='openpc.identity.envelope-rotation.phase.v1' and payload_cbor=$11 and payload_digest=$12 and cose_sign1=$13) as matches`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        consumer.operationId,
        consumer.envelopeId,
        Buffer.from(consumer.payloadDigest.slice(7), 'hex'),
        result.signerId,
        result.trustDigest,
        Buffer.from(consumer.receiptDigest.slice(7), 'hex'),
        lease.rotationId,
        operationId,
        payload,
        step.digest,
        step.cose,
        request.challengeIssuedAtNs,
        lease.recoveryId,
      ],
    );
    if (retained.rowCount !== 1 || retained.rows[0]?.matches !== true)
      throw new PlatformRecoveryError();
    return result;
  }
  requireCurrentRecoveryRotationActor(context);
  const signed = await signIdentityEnvelopeRecoveryEvidence(payload, signer);
  await commitIdentityEnvelopeRecoveryRotationPhase(client, {
    actor: requireCurrentRecoveryRotationActor(context),
    enrollment,
    lease,
    result,
    signed,
    fromState: 'CUTOVER_FENCED',
  });
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
