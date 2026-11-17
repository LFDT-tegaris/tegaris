import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { verifyStoredStepUpEvidence } from './verified-step-up-evidence.js';

const inputSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  recoveryId: z.uuidv7(),
  reviewOperationId: z.uuidv7(),
});
const reviewRequestSchema = z.strictObject({
  recoveryId: z.uuidv7(),
  note: z
    .string()
    .min(10)
    .max(1024)
    .refine((value) => value.trim().length >= 10),
});
const reviewResultSchema = z.strictObject({
  recoveryId: z.uuidv7(),
  postReviewStatus: z.literal('REVIEWED'),
  reviewedAt: z.string().refine((value) => {
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
  }),
});
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const tagged = (value: Buffer) => 'sha256:' + value.toString('hex');
const hash = (value: Buffer | string) => createHash('sha256').update(value).digest();

export class WorkloadSigningRepairReviewUnavailable extends Error {
  constructor() {
    super('Completed signing repair review history is unavailable');
  }
}
const unavailable = (): never => {
  throw new WorkloadSigningRepairReviewUnavailable();
};

interface ReviewRow {
  participantId: string;
  privacyDomainId: string;
  recoveryId: string;
  reviewOperationId: string;
  enrollmentId: string;
  enrollmentDigest: Buffer;
  caseState: 'REVOKED' | 'EXPIRED';
  reviewerPrincipalId: string;
  checkerPrincipalId: string;
  reviewedAt: Date;
  noteDigest: Buffer;
  candidateId: string;
  candidate: unknown;
  candidateDigest: Buffer;
  closedCaseRevision: string;
  result: unknown;
  resultDigest: Buffer;
  resultRevision: string;
  approvalRequestId: string;
  approvalDecisionId: string;
  approvalDecisionDigest: Buffer;
  checkerCredentialId: string;
  checkerPublicKey: Buffer;
  checkerPublicKeyDigest: Buffer;
  evidenceCbor: Buffer;
  evidenceDigest: Buffer;
  coseSign1: Buffer;
}

/** Historical review provenance under the caller's existing scoped runtime role.
 * The original consumed candidate supplies the closed-case revision; today's
 * case revision/time is not closure evidence. No current grant or completed
 * key-repair claim follows from this review alone. The carry owner must also
 * authenticate custody, rotation, closure and current issuer/key/selection.
 */
export async function readWorkloadSigningRepairReview(
  client: PoolClient,
  input: z.input<typeof inputSchema>,
  verifier: IdentityRuntimeVerifier,
) {
  const value = inputSchema.parse(input);
  await client.query('select openpc.assert_request_context(true)');
  const found = await client.query<ReviewRow>(
    `select recovery.participant_id::text as "participantId",recovery.privacy_domain_id::text as "privacyDomainId",
      recovery.recovery_id::text as "recoveryId",recovery.review_operation_id::text as "reviewOperationId",
      enrollment.enrollment_id::text as "enrollmentId",enrollment.document_digest as "enrollmentDigest",
      recovery.state as "caseState",recovery.reviewed_by_principal_id::text as "reviewerPrincipalId",
      history.checker_principal_id::text as "checkerPrincipalId",recovery.reviewed_at as "reviewedAt",
      recovery.review_note_digest as "noteDigest",candidate.mutation_candidate_id::text as "candidateId",
      candidate.candidate_document as candidate,candidate.candidate_digest as "candidateDigest",
      candidate.expected_revision::text as "closedCaseRevision",committed.result_payload as result,
      committed.result_digest as "resultDigest",committed.result_aggregate_version::text as "resultRevision",
      approval.approval_request_id::text as "approvalRequestId",decision.approval_decision_id::text as "approvalDecisionId",
      decision.decision_digest as "approvalDecisionDigest",credential.credential_id::text as "checkerCredentialId",
      credential.public_key_spki_der as "checkerPublicKey",credential.public_key_digest as "checkerPublicKeyDigest",
      history.evidence_cbor as "evidenceCbor",history.evidence_digest as "evidenceDigest",history.cose_sign1 as "coseSign1"
    from control.platform_recovery_case recovery
    join control.identity_envelope_recovery_enrollment enrollment
      on enrollment.participant_id=recovery.participant_id and enrollment.privacy_domain_id=recovery.privacy_domain_id
      and enrollment.enrollment_id=recovery.signer_repair_enrollment_id and enrollment.document_digest=recovery.enrollment_digest
    join control.mutation_evidence history on history.participant_id=recovery.participant_id
      and history.privacy_domain_id=recovery.privacy_domain_id and history.operation_id=recovery.review_operation_id
      and history.aggregate_type='recovery' and history.aggregate_id=recovery.recovery_id
      and history.catalog_operation_id='ID-OP-RECOVERY-POST-REVIEW'
      and history.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      and history.principal_id=recovery.reviewed_by_principal_id
    join control.mutation_candidate candidate on candidate.participant_id=history.participant_id
      and candidate.privacy_domain_id=history.privacy_domain_id and candidate.maker_principal_id=history.principal_id
      and candidate.catalog_operation_id=history.catalog_operation_id and candidate.action_intent_id=history.action_intent_id
      and candidate.resource_id=recovery.recovery_id
      and candidate.candidate_digest=history.candidate_digest and candidate.expected_revision=history.aggregate_version
      and candidate.state='CONSUMED' and candidate.consumed_operation_id=history.operation_id
    join control.action_intent action on action.action_intent_id=candidate.action_intent_id
      and action.resource_type=candidate.resource_type and action.operation_class=candidate.operation_class
      and action.maker_checker_required and action.step_up_required and action.idempotency_required
    join control.approval_request approval on approval.participant_id=candidate.participant_id
      and approval.privacy_domain_id=candidate.privacy_domain_id and approval.approval_request_id=history.approval_request_id
      and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.subject_id=candidate.mutation_candidate_id
      and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
      and approval.action_intent_id=candidate.action_intent_id
    join control.approval_decision_record decision on decision.participant_id=approval.participant_id
      and decision.privacy_domain_id=approval.privacy_domain_id and decision.approval_request_id=approval.approval_request_id
      and decision.decision='APPROVE' and decision.candidate_digest=candidate.candidate_digest
      and decision.aggregate_version=candidate.expected_revision and decision.approver_principal_id=history.checker_principal_id
      and decision.evidence_cbor=history.evidence_cbor and decision.cose_sign1=history.cose_sign1
    join control.mfa_challenge challenge on challenge.participant_id=decision.participant_id
      and challenge.mfa_challenge_id=decision.mfa_challenge_id and challenge.principal_id=decision.approver_principal_id
      and challenge.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1' and challenge.resource_digest=decision.decision_digest
      and challenge.signer_credential_id=decision.signer_credential_id and challenge.signer_credential_epoch=decision.signer_credential_epoch
      and challenge.consumed_at is not null and challenge.consumed_at<=decision.decided_at and challenge.expires_at>decision.decided_at
    join control.credential credential on credential.participant_id=decision.participant_id
      and credential.principal_id=decision.approver_principal_id and credential.credential_id=decision.signer_credential_id
      and credential.kind='WEBAUTHN' and credential.valid_from<=decision.decided_at
      and (credential.valid_until is null or credential.valid_until>decision.decided_at)
    join control.idempotency_record committed on committed.participant_id=candidate.participant_id
      and committed.privacy_domain_id=candidate.privacy_domain_id and committed.principal_id=candidate.maker_principal_id
      and committed.operation_id=candidate.consumed_operation_id and committed.catalog_operation_id=candidate.catalog_operation_id
      and committed.action_intent_id=candidate.action_intent_id and committed.idempotency_key=candidate.idempotency_key
      and committed.input_digest=candidate.candidate_digest and committed.expected_aggregate_version=candidate.expected_revision
      and committed.terminal_state='COMMITTED' and committed.result_aggregate_version=candidate.expected_revision::numeric+1
      and committed.webauthn_assertion_binding_digest is not distinct from history.webauthn_assertion_binding_digest
    join control.outbox_event event on event.participant_id=history.participant_id and event.privacy_domain_id=history.privacy_domain_id
      and event.aggregate_type=history.aggregate_type and event.aggregate_id=history.aggregate_id
      and event.event_type='openpc.identity.recovery.mutation.committed.v1'
      and event.payload_cbor=history.evidence_cbor and event.payload_digest=history.evidence_digest and event.cose_sign1=history.cose_sign1
      and event.webauthn_assertion_binding_digest is not distinct from history.webauthn_assertion_binding_digest
      and decision.decided_at<=recovery.reviewed_at and history.occurred_at>=recovery.reviewed_at
      and event.occurred_at>=history.occurred_at
    where recovery.participant_id=$1 and recovery.privacy_domain_id=$2 and recovery.recovery_id=$3
      and recovery.review_operation_id=$4 and recovery.state in('REVOKED','EXPIRED')
      and recovery.activated_at is not null and recovery.reviewed_at is not null
      and recovery.intent->>'schema'='pc.identity.identity-envelope-recovery-intent'
      and recovery.intent->>'purpose'='IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY'
      and enrollment.document->>'schema'='pc.identity.identity-envelope-recovery-enrollment'
      and history.principal_id<>history.checker_principal_id
      and history.principal_id::text not in(enrollment.document->>'issuerPrincipalId',enrollment.document#>>'{recoveryPrincipal,principalId}')
      and history.checker_principal_id::text not in(enrollment.document->>'issuerPrincipalId',enrollment.document#>>'{recoveryPrincipal,principalId}')
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 2`,
    [value.participantId, value.privacyDomainId, value.recoveryId, value.reviewOperationId],
  );
  if (found.rowCount !== 1 || !found.rows[0]) return unavailable();
  const row = found.rows[0];
  let request: z.infer<typeof reviewRequestSchema>;
  let result: z.infer<typeof reviewResultSchema>;
  try {
    request = reviewRequestSchema.parse(row.candidate);
    result = reviewResultSchema.parse(row.result);
    revision.parse(row.closedCaseRevision);
    revision.parse(row.resultRevision);
    for (const bytes of [
      row.enrollmentDigest,
      row.noteDigest,
      row.candidateDigest,
      row.resultDigest,
      row.approvalDecisionDigest,
      row.checkerPublicKeyDigest,
      row.evidenceDigest,
    ])
      if (!Buffer.isBuffer(bytes) || bytes.length !== 32) return unavailable();
    if (
      row.participantId !== value.participantId ||
      row.privacyDomainId !== value.privacyDomainId ||
      row.recoveryId !== value.recoveryId ||
      row.reviewOperationId !== value.reviewOperationId ||
      !['REVOKED', 'EXPIRED'].includes(row.caseState) ||
      request.recoveryId !== value.recoveryId ||
      result.recoveryId !== value.recoveryId ||
      !Number.isFinite(new Date(row.reviewedAt).getTime()) ||
      result.reviewedAt !== new Date(row.reviewedAt).toISOString() ||
      canonicalAuthorizationDigest(request) !== tagged(row.candidateDigest) ||
      canonicalAuthorizationDigest(result) !== tagged(row.resultDigest) ||
      !hash(request.note).equals(row.noteDigest) ||
      !hash(row.evidenceCbor).equals(row.evidenceDigest) ||
      !hash(row.checkerPublicKey).equals(row.checkerPublicKeyDigest) ||
      BigInt(row.resultRevision) !== BigInt(row.closedCaseRevision) + 1n ||
      row.reviewerPrincipalId === row.checkerPrincipalId
    )
      return unavailable();
  } catch {
    return unavailable();
  }
  if (
    !(await verifyStoredStepUpEvidence(
      client,
      {
        participantId: value.participantId,
        privacyDomainId: value.privacyDomainId,
        principalId: row.checkerPrincipalId,
        credentialId: row.checkerCredentialId,
        approvalRequestId: row.approvalRequestId,
        credentialPublicKey: row.checkerPublicKey,
        evidenceCbor: row.evidenceCbor,
        coseSign1: row.coseSign1,
      },
      verifier,
    ))
  )
    return unavailable();
  return Object.freeze({
    schema: 'pc.identity.workload-signing-handover.repair-review.v1' as const,
    ...value,
    enrollmentId: row.enrollmentId,
    enrollmentDigest: tagged(row.enrollmentDigest),
    leaseClosureState: row.caseState,
    closedCaseRevision: row.closedCaseRevision,
    mutationCandidateId: row.candidateId,
    candidateDigest: tagged(row.candidateDigest),
    approvalRequestId: row.approvalRequestId,
    approvalDecisionId: row.approvalDecisionId,
    approvalDecisionDigest: tagged(row.approvalDecisionDigest),
    reviewerPrincipalId: row.reviewerPrincipalId,
    checkerPrincipalId: row.checkerPrincipalId,
    noteDigest: tagged(row.noteDigest),
    reviewedAt: result.reviewedAt,
    evidenceDigest: tagged(row.evidenceDigest),
    resultDigest: tagged(row.resultDigest),
  });
}
