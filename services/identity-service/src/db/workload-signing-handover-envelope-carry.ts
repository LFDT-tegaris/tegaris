import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { readHistoricalIdentityEnvelopeRotationConsumer } from '../../../participant-service/src/identity-envelope-rotation-consumer.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryRotationCutoverResult,
} from '../contracts/identity-envelope-recovery.js';
import { workloadSigningHandoverEnvelopeCarrySchema } from '../contracts/workload-signing-handover-v2.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryCustody } from '../domain/identity-envelope-recovery-custody.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryLease } from '../domain/identity-envelope-recovery-lease-history.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { lockAuthorityFence } from './authority-fence.js';
import { readHistoricalIdentityEnvelopeRecoveryRotation } from './identity-envelope-recovery-rotation-history.js';
import {
  assertIdentityEnvelopeRotationIssuerUnchanged,
  captureIdentityEnvelopeRotationIssuer,
} from './identity-envelope-rotation-issuer.js';
import { fenceIdentityEnvelopeSigningTrust } from './identity-envelope-signing-store.js';
import { readWorkloadSigningRepairClosure } from './workload-signing-handover-repair-closure.js';
import { readWorkloadSigningRepairProofs } from './workload-signing-handover-repair-proofs.js';
import { readWorkloadSigningRepairReview } from './workload-signing-handover-repair-review.js';

const scopeSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  environmentId: z.string().min(1).max(160),
  workloadCredentialId: z.uuidv7(),
  localQaEnabled: z.boolean(),
});
const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest();

interface HistoryRow {
  document: unknown;
  documentDigest: Buffer;
  signature: Buffer;
  pin: unknown;
  pinDigest: Buffer;
  intent: unknown;
  intentDigest: Buffer;
  enrollmentRevision: string;
  bindings: unknown;
  activationOperationId: string;
  activatedAt: Date;
  evidenceCbor: Buffer;
  evidenceDigest: Buffer;
  cose: Buffer;
}

export class WorkloadSigningEnvelopeCarryUnavailable extends Error {
  constructor() {
    super('Completed envelope repair cannot be carried into this handover');
  }
}
const deny = (): never => {
  throw new WorkloadSigningEnvelopeCarryUnavailable();
};

/** Capture under the source/admission owner's authorized SERIALIZABLE transaction.
 * Historical evidence establishes the completed repair only. Fresh issuer,
 * key, grant and selector checks establish eligibility to preserve that exact
 * current selection. No lease, session, key, grant or selector is created here.
 * The caller repeats this capture at admission after any provider I/O.
 */
export async function captureWorkloadSigningEnvelopeCarry(
  client: PoolClient,
  scopeInput: z.input<typeof scopeSchema>,
  carryInput: z.input<typeof workloadSigningHandoverEnvelopeCarrySchema>,
  verifier: IdentityRuntimeVerifier,
) {
  const scope = scopeSchema.parse(scopeInput);
  const carry = workloadSigningHandoverEnvelopeCarrySchema.parse(carryInput);
  const context = await client.query<{ serializable: boolean }>(
    "select openpc.assert_request_context(true),current_setting('transaction_isolation')='serializable' as serializable",
  );
  if (context.rowCount !== 1 || context.rows[0]?.serializable !== true) return deny();
  // This parent write fence precedes shared identity fences and rotation locks.
  // The handover must never upgrade an already held shared Participant fence.
  await lockAuthorityFence(client, scope.participantId, {
    participant: [{ id: scope.participantId, write: true }],
  });
  const current = await captureIdentityEnvelopeRotationIssuer(client, {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    workloadCredentialId: scope.workloadCredentialId,
  });
  const found = await client.query<HistoryRow>(
    `select e.document,e.document_digest as "documentDigest",e.signature,t.document as pin,t.document_digest as "pinDigest",
      c.intent,c.intent_digest as "intentDigest",c.enrollment_revision::text as "enrollmentRevision",
      c.lease_bindings as bindings,c.activation_operation_id::text as "activationOperationId",c.activated_at as "activatedAt",
      c.activation_evidence_cbor as "evidenceCbor",c.activation_evidence_digest as "evidenceDigest",c.activation_cose as cose
    from control.platform_recovery_case c
    join control.identity_envelope_recovery_enrollment e on e.enrollment_id=c.signer_repair_enrollment_id
      and e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id and e.document_digest=c.enrollment_digest
    join control.identity_envelope_recovery_custody_trust t on t.custody_trust_id=e.custody_trust_id
      and t.participant_id=e.participant_id and t.privacy_domain_id=e.privacy_domain_id and t.document_digest=e.custody_trust_digest
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.recovery_id=$3
      and c.state in('REVOKED','EXPIRED') and c.review_operation_id=$4
      and c.activated_at is not null and c.reviewed_at is not null
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 2`,
    [scope.participantId, scope.privacyDomainId, carry.recoveryId, carry.reviewOperationId],
  );
  const row = found.rows[0];
  if (found.rowCount !== 1 || !row) return deny();
  const enrollment = authenticateHistoricalIdentityEnvelopeRecoveryCustody(row.pin, {
    document: row.document,
    signature: row.signature.toString('base64url'),
  });
  const intent = identityEnvelopeRecoveryIntent.parse(row.intent);
  if (
    enrollment.participantId !== scope.participantId ||
    enrollment.privacyDomainId !== scope.privacyDomainId ||
    enrollment.request.environmentId !== scope.environmentId ||
    enrollment.request.workloadCredentialId !== scope.workloadCredentialId ||
    enrollment.issuerPrincipalId !== current.issuer.workloadPrincipalId ||
    (enrollment.profile === 'LOCAL_QA' && !scope.localQaEnabled) ||
    canonicalAuthorizationDigest(enrollment) !== tagged(row.documentDigest) ||
    canonicalAuthorizationDigest(row.pin) !== tagged(row.pinDigest) ||
    enrollment.custodyTrustDigest !== tagged(row.pinDigest) ||
    intent.recoveryId !== carry.recoveryId ||
    intent.enrollmentId !== enrollment.enrollmentId ||
    intent.rotationId !== carry.rotationId ||
    intent.enrollmentRevision !== row.enrollmentRevision ||
    canonicalAuthorizationDigest(intent) !== tagged(row.intentDigest)
  )
    return deny();
  const lease = await authenticateHistoricalIdentityEnvelopeRecoveryLease(
    {
      enrollment,
      intent,
      bindings: row.bindings,
      activationOperationId: row.activationOperationId,
      activatedAt: row.activatedAt,
      evidenceCbor: row.evidenceCbor,
      evidenceDigest: row.evidenceDigest,
      coseSign1: row.cose,
    },
    verifier,
  );
  assertIdentityEnvelopeRotationIssuerUnchanged(lease.issuer, current.issuer);
  const proofs = await readWorkloadSigningRepairProofs(client, enrollment, intent, lease);
  const completion = await readHistoricalIdentityEnvelopeRecoveryRotation(
    client,
    enrollment,
    lease,
    carry.completionOperationId,
    verifier,
  );
  const review = await readWorkloadSigningRepairReview(
    client,
    {
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      recoveryId: carry.recoveryId,
      reviewOperationId: carry.reviewOperationId,
    },
    verifier,
  );
  const closure = await readWorkloadSigningRepairClosure(
    client,
    { enrollment, lease, completion, review, closureOperationId: carry.leaseClosureOperationId },
    verifier,
  );
  const selected = await client.query<{
    signerId: string;
    admissionVersion: string;
    profileDigest: Buffer;
    cutover: unknown;
    cutoverOperationId: string;
    cutoverEvidenceDigest: Buffer;
    lifecycleState: string;
    lifecycleRevision: string;
    lifecycleChangeDigest: Buffer;
    grantCount: number;
    ordinaryGrantCount: number;
    renewalGrantCount: number;
  }>(
    `select selection.signer_id as "signerId",selection.admission_version::text as "admissionVersion",
      selection.profile_digest as "profileDigest",step.result as cutover,step.operation_id::text as "cutoverOperationId",
      step.evidence_digest as "cutoverEvidenceDigest",life.state as "lifecycleState",
      life.row_version::text as "lifecycleRevision",life.change_digest as "lifecycleChangeDigest",
      (select count(*)::integer from control.identity_envelope_signing_grant g
        where g.participant_id=selection.participant_id and g.privacy_domain_id=selection.privacy_domain_id
          and g.signer_id=selection.signer_id) as "grantCount",
      (select count(*)::integer from control.business_signing_grant g
        where g.participant_id=selection.participant_id and g.privacy_domain_id=selection.privacy_domain_id
          and g.signer_id=selection.signer_id) as "ordinaryGrantCount",
      (select count(*)::integer from control.workload_renewal_signing_grant g
        where g.participant_id=selection.participant_id and g.privacy_domain_id=selection.privacy_domain_id
          and g.signer_id=selection.signer_id) as "renewalGrantCount"
    from control.identity_envelope_signing_selection selection
    join control.identity_envelope_signing_grant grant_row on grant_row.participant_id=selection.participant_id
      and grant_row.privacy_domain_id=selection.privacy_domain_id and grant_row.signer_id=selection.signer_id
      and grant_row.profile_digest=selection.profile_digest and grant_row.signing_purpose_code=371
    join control.business_signing_key_state life on life.participant_id=selection.participant_id
      and life.privacy_domain_id=selection.privacy_domain_id and life.signer_id=selection.signer_id
    join control.identity_envelope_rotation_step step on step.participant_id=selection.participant_id
      and step.privacy_domain_id=selection.privacy_domain_id and step.rotation_id=$4 and step.recovery_id=$5
      and step.from_revision=5 and step.from_state='VERIFIED' and step.to_state='CUTOVER_FENCED' and step.state='COMMITTED'
      and step.principal_id=$6
    where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 2 for share of selection,life`,
    [
      scope.participantId,
      scope.privacyDomainId,
      scope.environmentId,
      carry.rotationId,
      carry.recoveryId,
      lease.executorPrincipalId,
    ],
  );
  const selection = selected.rows[0];
  if (selected.rowCount !== 1 || !selection) return deny();
  const cutover = identityEnvelopeRecoveryRotationCutoverResult.parse(selection.cutover);
  if (
    selection.signerId !== carry.signerId ||
    selection.admissionVersion !== carry.selectionAdmissionVersion ||
    tagged(selection.profileDigest) !== identityEnvelopeSigningProfileDigest ||
    carry.selectionAdmissionVersion !== (BigInt(lease.selectionAdmissionVersion) + 1n).toString() ||
    completion.operationId !== carry.completionOperationId ||
    completion.signerId !== carry.signerId ||
    completion.trustDigest !== carry.trustDigest ||
    completion.selectionAdmissionVersion !== carry.selectionAdmissionVersion ||
    selection.lifecycleState !== 'ACTIVE' ||
    selection.lifecycleRevision !== '2' ||
    selection.grantCount !== 1 ||
    selection.ordinaryGrantCount !== 0 ||
    selection.renewalGrantCount !== 0 ||
    selection.cutoverEvidenceDigest.length !== 32 ||
    !selection.lifecycleChangeDigest.equals(selection.cutoverEvidenceDigest) ||
    cutover.operationId !== selection.cutoverOperationId ||
    cutover.rotationId !== carry.rotationId ||
    cutover.recoveryId !== carry.recoveryId ||
    cutover.signerId !== carry.signerId ||
    cutover.trustDigest !== carry.trustDigest ||
    cutover.selectionAdmissionVersion !== carry.selectionAdmissionVersion
  )
    return deny();
  const key = await fenceIdentityEnvelopeSigningTrust(client, scope);
  const trust = key.trust;
  if (
    identityEnvelopeSigningTrustDigest(trust) !== carry.trustDigest ||
    trust.signerId !== carry.signerId ||
    trust.participantId !== scope.participantId ||
    trust.privacyDomainId !== scope.privacyDomainId ||
    trust.workloadCredentialId !== scope.workloadCredentialId ||
    trust.workloadCredentialEpoch.toString() !== current.issuer.workloadCredentialEpoch ||
    trust.workloadParticipantEpoch.toString() !== current.issuer.workloadParticipantEpoch ||
    trust.workloadPrincipalEpoch.toString() !== current.issuer.workloadPrincipalEpoch ||
    trust.environmentId !== scope.environmentId ||
    trust.admissionKind !== 'GOVERNED' ||
    trust.admissionReference !== `urn:openpc:resource:${carry.rotationId}` ||
    trust.validFromNs > key.recordedAtNs ||
    trust.validUntilNs <= key.recordedAtNs ||
    key.recordedAtNs < current.recordedAtNs
  )
    return deny();
  const consumer = await readHistoricalIdentityEnvelopeRotationConsumer(
    client,
    {
      trust,
      cutoverAtNs: timestampNs(cutover.completedAt),
      observedAtNs: timestampNs(completion.completedAt),
      operationId: completion.consumerActivationOperationId,
      envelopeId: completion.consumerEnvelopeId,
    },
    verifier,
  );
  if (
    consumer.operationId !== completion.consumerActivationOperationId ||
    consumer.envelopeId !== completion.consumerEnvelopeId ||
    consumer.payloadDigest !== completion.consumerPayloadDigest ||
    consumer.receiptDigest !== completion.consumerReceiptDigest
  )
    return deny();
  const clock = await client.query<{ nowNs: string }>(
    'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"',
  );
  if (
    clock.rowCount !== 1 ||
    !clock.rows[0] ||
    !/^(0|[1-9][0-9]{0,19})$/u.test(clock.rows[0].nowNs)
  )
    return deny();
  const nowNs = BigInt(clock.rows[0].nowNs);
  if (
    nowNs > 18446744073709551615n ||
    nowNs % 1000n !== 0n ||
    nowNs < key.recordedAtNs ||
    trust.validFromNs > nowNs ||
    trust.validUntilNs <= nowNs ||
    BigInt(current.issuer.credentialValidFromNs) > nowNs ||
    (current.issuer.credentialValidUntilNs !== null &&
      BigInt(current.issuer.credentialValidUntilNs) <= nowNs)
  )
    return deny();
  const preimage = identityEnvelopeSigningTrustPreimage(trust);
  return {
    trust,
    issuer: current.issuer,
    recordedAtNs: nowNs,
    document: Object.freeze({
      schema: 'pc.identity.workload-signing-handover.envelope-carry.v1' as const,
      ...carry,
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      environmentId: scope.environmentId,
      issuer: current.issuer,
      enrollmentId: enrollment.enrollmentId,
      enrollmentDigest: tagged(row.documentDigest),
      custodyTrustDigest: tagged(row.pinDigest),
      intentDigest: tagged(row.intentDigest),
      activationOperationId: lease.activationOperationId,
      activationEvidenceDigest: tagged(row.evidenceDigest),
      proofEvidenceDigest: proofs.proofEvidenceDigest,
      completionDigest: canonicalAuthorizationDigest(completion),
      cutoverEvidenceDigest: tagged(selection.cutoverEvidenceDigest),
      consumer: Object.freeze({ ...consumer }),
      closure,
      review,
      trustPreimageBase64: preimage.toString('base64'),
      trustPreimageDigest: tagged(hash(preimage)),
    }),
  };
}

function timestampNs(value: string) {
  z.iso.datetime({ offset: true }).parse(value);
  const fraction = value.match(/\.([0-9]+)(?:Z|[+-]\d\d:\d\d)$/u)?.[1] ?? '';
  if (fraction.length > 9 && /[1-9]/u.test(fraction.slice(9))) return deny();
  return BigInt(Date.parse(value)) * 1000000n + BigInt(fraction.padEnd(9, '0').slice(3, 9));
}
