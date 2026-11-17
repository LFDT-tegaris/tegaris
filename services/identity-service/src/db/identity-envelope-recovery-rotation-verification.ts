import {
  assertHistoricalRecoveryRotationStep,
  recoveryRotationSubject,
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import { createHash } from 'node:crypto';
import {
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import type { PoolClient } from 'pg';
import { authenticateIdentityEnvelopeRotationDualProof } from '../../../participant-service/src/identity-envelope-rotation-proof.js';
import { admitIdentityEnvelopeRecoveryTrust } from '../../../participant-service/src/identity-envelope-rotation-admission.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationVerificationResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryRotationVerificationResult,
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
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';
import { authenticateIdentityEnvelopeRecoveryRotationCreation } from './identity-envelope-recovery-rotation.js';
import {
  commitIdentityEnvelopeRecoveryRotationPhase,
  resolveIdentityEnvelopeRecoveryDistributedDescriptor,
} from './identity-envelope-recovery-rotation-prepare.js';

/** Only confirmed original dual proofs may admit public 371 trust. Admission
 * does not select the key, establish consumer use or retire the predecessor. */
export async function publishIdentityEnvelopeRecoveryVerification(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationVerificationResult | undefined> {
  return resolveIdentityEnvelopeRecoveryVerification(
    client,
    { kind: 'CURRENT', actor },
    enrollment,
    lease,
    operationId,
    localQaEnabled,
    signer,
  );
}

export async function resolveIdentityEnvelopeRecoveryVerification(
  client: PoolClient,
  context: RecoveryRotationContext,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
): Promise<IdentityEnvelopeRecoveryRotationVerificationResult | undefined> {
  const actor = recoveryRotationSubject(context, enrollment, lease);
  const selected = await client.query<{
    state: string;
    current: boolean;
    bound: boolean;
    result: unknown;
    cbor: Buffer | null;
    digest: Buffer | null;
    cose: Buffer | null;
  }>(
    `select s.state,case when s.state='COMMITTED' then false else openpc.identity_envelope_rotation_step_current(s) end as current,openpc.identity_envelope_rotation_step_bound(s) as bound,
 s.result,s.evidence_cbor as cbor,s.evidence_digest as digest,s.cose_sign1 as cose from control.identity_envelope_rotation_step s
 where s.operation_id=$1 and s.participant_id=$2 and s.privacy_domain_id=$3 and s.rotation_id=$4 and s.recovery_id=$5
 and s.principal_id=$6 and s.from_revision=4 and s.from_state='DISTRIBUTED' and s.to_state='VERIFIED' for update of s`,
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
    `select slot,request,request_digest as "requestDigest",state,first_observation as "firstObservation",first_observation_digest as "firstDigest",
 observation,observation_digest as digest,(floor(extract(epoch from started_at)*1000000)*1000)::text as "startedAtNs"
 from control.identity_envelope_rotation_attempt where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 and rotation_id=$4 for share`,
    [operationId, actor.participantId, enrollment.privacyDomainId, lease.rotationId],
  );
  if (attempts.rowCount !== 2) throw new PlatformRecoveryError();
  if (attempts.rows.some((a) => a.state !== 'OBSERVED')) return undefined;
  for (const a of attempts.rows) {
    const request = identityEnvelopeRotationRequestSchema.parse(a.request);
    if (
      identityEnvelopeRotationRequestDigest(request) !==
        `sha256:${a.requestDigest.toString('hex')}` ||
      !a.firstDigest ||
      !a.digest ||
      !a.startedAtNs ||
      a.firstObservation === null ||
      a.observation === null ||
      canonicalAuthorizationDigest(a.firstObservation) !==
        `sha256:${a.firstDigest.toString('hex')}` ||
      canonicalAuthorizationDigest(a.observation) !== `sha256:${a.digest.toString('hex')}` ||
      !a.firstDigest.equals(a.digest) ||
      typeof a.observation !== 'object' ||
      !('recordedAtNs' in a.observation) ||
      BigInt(String(a.observation.recordedAtNs)) < BigInt(a.startedAtNs)
    )
      throw new PlatformRecoveryError();
  }
  const previous = await resolveIdentityEnvelopeRecoveryDistributedDescriptor(
    client,
    context,
    enrollment,
    lease,
    localQaEnabled,
    signer,
  );
  const historical = step.state === 'COMMITTED';
  const original = historical
    ? identityEnvelopeRecoveryRotationVerificationResult.parse(step.result)
    : undefined;
  if (!historical && (step.state !== 'STARTED' || step.current !== true)) return undefined;
  let oldTrust;
  let currentIssuer;
  let nowNs: bigint;
  if (historical) {
    const old = await client.query<IdentityEnvelopeSigningKeyRow>(
      `select key.* from control.business_signing_key key join control.signing_key_rotation r
 on r.participant_id=key.participant_id and r.privacy_domain_id=key.privacy_domain_id and r.old_signer_id=key.signer_id
 where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3 and r.recovery_case_id=$4 and key.signing_purpose_code=371`,
      [actor.participantId, enrollment.privacyDomainId, lease.rotationId, lease.recoveryId],
    );
    if (old.rowCount !== 1 || !old.rows[0]) throw new PlatformRecoveryError();
    oldTrust = authenticatedIdentityEnvelopeSigningTrust(old.rows[0]);
    currentIssuer = lease.issuer;
    nowNs = timestampNs(original!.completedAt);
  } else {
    requireCurrentRecoveryRotationActor(context);
    await authenticateIdentityEnvelopeRecoveryRotationCreation(
      client,
      context,
      enrollment,
      lease,
      lease.creationOperationId,
      signer,
    );
    const source = await captureIdentityEnvelopeRotationSource(
      client,
      enrollment,
      enrollment.request,
      signer,
    );
    oldTrust = source.trust;
    currentIssuer = source.issuer;
    nowNs = source.recordedAtNs;
  }
  const proof = authenticateIdentityEnvelopeRotationDualProof(
    {
      request: enrollment.request,
      rotationId: lease.rotationId,
      operationId,
      oldTrust,
      preparedIssuer: lease.issuer,
      currentIssuer,
      admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease },
      descriptor: previous.descriptor,
      callerWorkloadCredentialId: lease.issuer.workloadCredentialId,
      nowNs,
      authorityValidUntilNs: BigInt(Date.parse(lease.validUntil)) * 1000000n,
    },
    attempts.rows,
  );
  if (proof.trustDigest !== previous.result.trustDigest) throw new PlatformRecoveryError();
  const result = identityEnvelopeRecoveryRotationVerificationResult.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: '4',
    revision: '5',
    state: 'VERIFIED',
    admissionState: 'ADMITTED',
    signerId: proof.trust.signerId,
    trustDigest: proof.trustDigest,
    observationsDigest: proof.observationsDigest,
    completedAt: timestampIso(nowNs),
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
      `select exists(select 1 from control.business_signing_key k
 join control.identity_envelope_signing_grant g using(participant_id,privacy_domain_id,signer_id)
 where k.participant_id=$1 and k.privacy_domain_id=$2 and k.signer_id=$3 and k.signing_purpose_code=371 and g.signing_purpose_code=371 and k.trust_digest=$4 and k.trust_preimage=$10 and g.profile_digest=$11
 and not exists(select 1 from control.business_signing_grant ordinary where ordinary.participant_id=k.participant_id and ordinary.privacy_domain_id=k.privacy_domain_id and ordinary.signer_id=k.signer_id))
 and exists(select 1 from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='signing-key-rotation' and aggregate_id=$5 and event_id=$6
 and event_type='openpc.identity.envelope-rotation.phase.v1' and payload_cbor=$7 and payload_digest=$8 and cose_sign1=$9) as matches`,
      [
        actor.participantId,
        enrollment.privacyDomainId,
        result.signerId,
        Buffer.from(result.trustDigest.slice(7), 'hex'),
        lease.rotationId,
        operationId,
        payload,
        step.digest,
        step.cose,
        identityEnvelopeSigningTrustPreimage(proof.trust),
        Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex'),
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
      fromState: 'DISTRIBUTED',
    },
    () => admitIdentityEnvelopeRecoveryTrust(client, proof.trust),
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
