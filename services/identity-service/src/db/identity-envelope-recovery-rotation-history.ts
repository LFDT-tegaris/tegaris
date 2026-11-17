import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryRotationCompletionResult,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import type {
  IdentityRuntimeAssertionVerifier,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { lockAuthorityFence } from './authority-fence.js';
import type { RecoveryRotationContext } from './identity-envelope-recovery-rotation-context.js';
import { resolveIdentityEnvelopeRecoveryRotationPhase } from './identity-envelope-recovery-rotation-prepare.js';

interface RotationRow {
  request: unknown;
  candidateDigest: Buffer;
  recoveryId: string;
  maker: string;
  approvalId: string | null;
  approvedOperationId: string;
  environmentId: string;
  workloadCredentialId: string;
  oldSignerId: string;
  oldTrustDigest: Buffer;
  newSignerId: string;
  state: string;
  revision: string;
  createdAt: Date;
}
interface StepRow {
  operationId: string;
  fromRevision: string;
  fromState: string;
  toState: string;
  state: string;
  bound: boolean;
  authorityBinding: unknown;
  authorityDigest: Buffer;
  result: unknown;
  completedAtNs: string | null;
}
const phases = [
  ['APPROVED', 'PREPARED'],
  ['PREPARED', 'DISTRIBUTED'],
  ['DISTRIBUTED', 'VERIFIED'],
  ['VERIFIED', 'CUTOVER_FENCED'],
  ['CUTOVER_FENCED', 'OBSERVING'],
  ['OBSERVING', 'OLD_REVOKED'],
  ['OLD_REVOKED', 'OLD_RETIRED'],
  ['OLD_RETIRED', 'COMPLETE'],
] as const;
const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');

/** Authenticate original completed phase history after the caller authenticates
 * custody and the activation lease. This takes row locks in the same fenced
 * transaction as its caller; it is not a PostgreSQL READ ONLY transaction.
 * It does not establish today's issuer/key/selection eligibility or authenticate
 * the typed consumer artifact; those are separate carry requirements. */
export async function readHistoricalIdentityEnvelopeRecoveryRotation(
  client: PoolClient,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
  completionOperationId: string,
  verifier: IdentityRuntimeAssertionVerifier,
) {
  const context = await client.query<{ serializable: boolean }>(
    "select openpc.assert_request_context(true),current_setting('transaction_isolation')='serializable' as serializable",
  );
  if (context.rowCount !== 1 || context.rows[0]?.serializable !== true)
    throw new PlatformRecoveryError();
  // Use the ordinary C04 fence without changing the caller's action. The live
  // recovery-specific enrollment lock requires Participants Update authority;
  // it cannot be borrowed by handover. Declare the same parent write lock
  // before any rotation/step locks to serialize against live recovery replay.
  await lockAuthorityFence(client, enrollment.participantId, {
    participant: [{ id: enrollment.participantId, write: true }],
  });
  const selected = await client.query<RotationRow>(
    `select r.request,r.candidate_digest as "candidateDigest",r.recovery_case_id::text as "recoveryId",
      r.maker_principal_id::text as maker,r.approval_request_id::text as "approvalId",
      r.approved_operation_id::text as "approvedOperationId",r.environment_id::text as "environmentId",
      r.workload_credential_id::text as "workloadCredentialId",r.old_signer_id as "oldSignerId",
      r.old_trust_digest as "oldTrustDigest",r.new_signer_id as "newSignerId",r.state,
      r.revision::text as revision,r.created_at as "createdAt"
    from control.signing_key_rotation r where r.participant_id=$1 and r.privacy_domain_id=$2
      and r.rotation_id=$3 and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    for update of r`,
    [enrollment.participantId, enrollment.privacyDomainId, lease.rotationId],
  );
  const rotation = selected.rows[0];
  const candidateDigest = canonicalAuthorizationDigest({ request: enrollment.request, lease });
  if (
    selected.rowCount !== 1 ||
    !rotation ||
    lease.enrollmentId !== enrollment.enrollmentId ||
    lease.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    lease.oldTrustDigest !== enrollment.oldTrustDigest ||
    lease.executorPrincipalId !== enrollment.recoveryPrincipal.principalId ||
    rotation.state !== 'COMPLETE' ||
    rotation.revision !== '10' ||
    rotation.recoveryId !== lease.recoveryId ||
    rotation.maker !== lease.executorPrincipalId ||
    rotation.approvalId !== null ||
    rotation.approvedOperationId !== lease.activationOperationId ||
    rotation.environmentId !== enrollment.request.environmentId ||
    rotation.workloadCredentialId !== enrollment.request.workloadCredentialId ||
    rotation.oldSignerId !== enrollment.request.oldFingerprint ||
    tagged(rotation.oldTrustDigest) !== lease.oldTrustDigest ||
    tagged(rotation.candidateDigest) !== candidateDigest ||
    canonicalAuthorizationDigest(rotation.request) !==
      canonicalAuthorizationDigest(enrollment.request)
  )
    throw new PlatformRecoveryError();
  const createdAt = rotation.createdAt.toISOString();
  if (
    Date.parse(createdAt) < Date.parse(lease.validFrom) ||
    Date.parse(createdAt) >= Date.parse(lease.validUntil)
  )
    throw new PlatformRecoveryError();
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment,
    operationId: lease.creationOperationId,
    actorPrincipalId: lease.executorPrincipalId,
    purpose: 'rotation-creation',
    value: {
      schema: 'pc.identity.identity-envelope-recovery-rotation-creation',
      schemaVersion: 1,
      operationId: lease.creationOperationId,
      recoveryId: lease.recoveryId,
      enrollmentId: enrollment.enrollmentId,
      rotationId: lease.rotationId,
      candidateDigest,
      revision: '2',
      state: 'APPROVED',
      createdAt,
    },
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: createdAt,
    expiresAt: lease.validUntil,
  });
  const events = await client.query<{ cbor: Buffer; digest: Buffer; cose: Buffer }>(
    `select e.payload_cbor as cbor,e.payload_digest as digest,e.cose_sign1 as cose
    from control.outbox_event e join control.outbox_aggregate_head h
      on h.participant_id=e.participant_id and h.aggregate_type=e.aggregate_type and h.aggregate_id=e.aggregate_id
    where e.participant_id=$1 and e.privacy_domain_id=$2 and e.aggregate_type='signing-key-rotation'
      and e.aggregate_id=$3 and e.aggregate_sequence=1 and e.event_id=$4
      and e.event_type='openpc.identity.envelope-rotation.created.v1' and e.occurred_at=$5
      and h.last_sequence=9`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.creationOperationId,
      createdAt,
    ],
  );
  const event = events.rows[0];
  if (
    events.rowCount !== 1 ||
    !event ||
    !event.cbor.equals(payload) ||
    !event.digest.equals(createHash('sha256').update(payload).digest()) ||
    !(await verifier.verifyCanonicalAssertion(payload, event.cose))
  )
    throw new PlatformRecoveryError();
  const steps = await client.query<StepRow>(
    `select s.operation_id::text as "operationId",s.from_revision::text as "fromRevision",
      s.from_state as "fromState",s.to_state as "toState",s.state,
      openpc.identity_envelope_rotation_step_bound(s) as bound,s.authority_binding as "authorityBinding",
      s.authority_digest as "authorityDigest",s.result,
      (floor(extract(epoch from s.completed_at)*1000000)*1000)::text as "completedAtNs"
    from control.identity_envelope_rotation_step s where s.participant_id=$1 and s.privacy_domain_id=$2
      and s.rotation_id=$3 and s.recovery_id=$4 and s.principal_id=$5
    order by s.from_revision for update of s`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      lease.executorPrincipalId,
    ],
  );
  if (
    steps.rowCount !== 8 ||
    steps.rows.length !== 8 ||
    new Set(steps.rows.map((s) => s.operationId)).size !== 8
  )
    throw new PlatformRecoveryError();
  const binding = canonicalAuthorizationDigest({
    kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY',
    enrollment,
    lease,
  });
  let lastCompletedNs = BigInt(Date.parse(createdAt)) * 1000000n;
  for (const [index, step] of steps.rows.entries()) {
    const result = step.result;
    if (
      !result ||
      typeof result !== 'object' ||
      !('completedAt' in result) ||
      typeof result.completedAt !== 'string'
    )
      throw new PlatformRecoveryError();
    const completedNs = timestampNs(result.completedAt);
    if (
      step.fromRevision !== String(index + 2) ||
      step.fromState !== phases[index]?.[0] ||
      step.toState !== phases[index]?.[1] ||
      step.state !== 'COMMITTED' ||
      !step.bound ||
      canonicalAuthorizationDigest(step.authorityBinding) !== binding ||
      tagged(step.authorityDigest) !== binding ||
      step.completedAtNs !== completedNs.toString() ||
      completedNs < lastCompletedNs ||
      completedNs >= BigInt(Date.parse(lease.validUntil)) * 1000000n
    )
      throw new PlatformRecoveryError();
    lastCompletedNs = completedNs;
  }
  if (steps.rows[7]?.operationId !== completionOperationId) throw new PlatformRecoveryError();
  const historicalContext: RecoveryRotationContext = Object.freeze({
    kind: 'HISTORICAL',
    subject: Object.freeze({
      participantId: enrollment.participantId,
      principalId: lease.executorPrincipalId,
    }),
  });
  const verifyOnly: IdentityRuntimeEvidenceSigner = {
    verifyCanonicalAssertion: (cbor, cose) => verifier.verifyCanonicalAssertion(cbor, cose),
    signCanonicalAssertion: async () => {
      throw new PlatformRecoveryError();
    },
  };
  const completion = identityEnvelopeRecoveryRotationCompletionResult.parse(
    await resolveIdentityEnvelopeRecoveryRotationPhase(
      client,
      historicalContext,
      enrollment,
      lease,
      completionOperationId,
      false,
      verifyOnly,
    ),
  );
  if (
    completion.rotationId !== lease.rotationId ||
    completion.recoveryId !== lease.recoveryId ||
    completion.operationId !== completionOperationId ||
    completion.signerId !== rotation.newSignerId ||
    completion.predecessorSignerId !== rotation.oldSignerId
  )
    throw new PlatformRecoveryError();
  return Object.freeze(completion);
}

function timestampNs(value: string) {
  z.iso.datetime({ offset: true }).parse(value);
  const millis = Date.parse(value);
  const fraction = value.match(/\.([0-9]+)(?:Z|[+-]\d\d:\d\d)$/u)?.[1] ?? '';
  if (!Number.isFinite(millis) || (fraction.length > 9 && /[1-9]/u.test(fraction.slice(9))))
    throw new PlatformRecoveryError();
  return BigInt(millis) * 1000000n + BigInt(fraction.padEnd(9, '0').slice(3, 9));
}
