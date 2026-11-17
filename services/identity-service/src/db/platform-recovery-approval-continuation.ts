import { createHash } from 'node:crypto';
import { authenticateHistoricalRuntimeStepUpEvidence } from './verified-step-up-evidence.js';
import type { PoolClient } from 'pg';
import {
  platformRecoveryApprovalContinuation,
  platformRecoveryIntent,
  type PendingExpiryPlatformRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { readClosedPlatformApprovalSource } from './platform-recovery-closed-approval.js';

/** An expired grant supplies historical intent only. The new case still needs
 * independent fresh custody, native no-effect checks and current source fences. */
export async function readPlatformRecoveryApprovalContinuation(
  client: PoolClient,
  enrollment: PendingExpiryPlatformRecoveryEnrollment,
  verifier: IdentityRuntimeAssertionVerifier | undefined,
) {
  if (enrollment.source.closedApproval)
    return readClosedPlatformApprovalSource(client, enrollment, verifier);
  const selected = await client.query<{
    witness: unknown;
    preparation: unknown;
    sourceCurrent: boolean;
  }>(
    `with originals as materialized (
      select c.*, m.mutation_candidate_id, m.candidate_digest, m.idempotency_key, m.attempt,
        a.approval_request_id
      from control.platform_recovery_case c
      join control.mutation_candidate m on m.participant_id=c.participant_id
        and m.privacy_domain_id=c.privacy_domain_id
        and m.candidate_document=c.intent->'preparation'
        and m.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(m.candidate_document),'UTF8'))
        and m.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' and m.expected_revision=0
        and m.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and m.resource_id::text=c.intent#>>'{preparation,replacementId}'
        and m.maker_principal_id::text=c.intent#>>'{preparation,administrators,0,principalId}'
        and m.consumed_operation_id is null
        and not exists(select 1 from control.mutation_candidate child
          where child.predecessor_candidate_id=m.mutation_candidate_id)
      join control.approval_request a on a.participant_id=m.participant_id
        and a.privacy_domain_id=m.privacy_domain_id and a.subject_type='CONFIGURATION_CANDIDATE'
        and a.subject_id=m.mutation_candidate_id and a.subject_digest=m.candidate_digest
        and a.subject_version=m.expected_revision and a.maker_principal_id=m.maker_principal_id
        and a.action_intent_id=m.action_intent_id
        and a.checker_principal_id::text=c.intent#>>'{preparation,administrators,1,principalId}'
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.enrollment_id=$3
        and c.state='EXPIRED' and c.valid_until<=clock_timestamp()
        and c.intent ? 'pendingExpiry'
        and c.activation_operation_id is not null and m.expires_at<=clock_timestamp()
        and m.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
        and a.state in ('OPEN','APPROVED','EXPIRED')
        and exists(select 1 from jsonb_array_elements(c.lease_bindings) b
          where b->>'envelopeId'=m.maker_authority_envelope_id::text
            and b->>'assignmentId'=m.maker_assignment_id::text
            and b->>'principalId'=m.maker_principal_id::text
            and b->>'principalEpoch'=m.maker_principal_epoch::text)
      limit 2
    ) select jsonb_build_object('schema','pc.identity.platform-prepare-approval-continuation',
        'schemaVersion',1,'recoveryId',recovery_id::text,
        'intentDigest','sha256:'||encode(intent_digest,'hex'),
        'activationOperationId',activation_operation_id::text,
        'activationReceiptDigest','sha256:'||encode(activation_evidence_digest,'hex'),
        'candidateId',mutation_candidate_id::text,'approvalId',approval_request_id::text,
        'candidateDigest','sha256:'||encode(candidate_digest,'hex'),
        'businessKey',idempotency_key,'attempt',attempt::text) as witness,
      intent->'preparation' as preparation,
      openpc.platform_recovery_pending_approval_history_current(participant_id,enrollment_id,recovery_id,mutation_candidate_id,approval_request_id,null::uuid) as "sourceCurrent"
    from originals`,
    [enrollment.participantId, enrollment.privacyDomainId, enrollment.enrollmentId],
  );
  if (selected.rowCount === 0) return undefined;
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || !row.sourceCurrent || !verifier)
    throw new PlatformRecoveryError();
  const witness = platformRecoveryApprovalContinuation.parse(row.witness);
  const seenCases = new Set<string>();
  const seenCandidates = new Set<string>();
  let current = witness;
  let authenticatedPreparation:
    ReturnType<typeof platformRecoveryIntent.parse>['preparation'] | undefined;
  for (let hop = 0; hop < 32; hop++) {
    if (seenCases.has(current.recoveryId) || seenCandidates.has(current.candidateId))
      throw new PlatformRecoveryError();
    seenCases.add(current.recoveryId);
    seenCandidates.add(current.candidateId);
    const original = await readStoredPlatformRecoveryReceipt(
      client,
      enrollment,
      enrollment.enrollmentId,
      current.recoveryId,
      verifier,
    );
    const intent = platformRecoveryIntent.parse(original.receipt.intent);
    if (
      original.enrollment.schemaVersion !== 4 ||
      canonicalAuthorizationDigest(original.enrollment) !==
        canonicalAuthorizationDigest(enrollment) ||
      original.receipt.state !== 'EXPIRED' ||
      original.receipt.authority !== 'NONE' ||
      !original.receipt.activation ||
      original.receipt.activation.operationId !== current.activationOperationId ||
      !original.activationEvidenceDigest ||
      `sha256:${original.activationEvidenceDigest.toString('hex')}` !==
        current.activationReceiptDigest ||
      original.receipt.intentDigest !== current.intentDigest ||
      canonicalAuthorizationDigest(intent.preparation) !== witness.candidateDigest ||
      original.receipt.proofs.length !== 4 ||
      new Set(original.receipt.proofs.map((p) => p.proofId)).size !== 4
    )
      throw new PlatformRecoveryError();
    authenticatedPreparation ??= structuredClone(intent.preparation);
    const parent = intent.approvalContinuation;
    if (!parent) {
      if (current.attempt !== '1') throw new PlatformRecoveryError();
      break;
    }
    if (
      parent.recoveryId === current.recoveryId ||
      parent.candidateId === current.candidateId ||
      parent.approvalId === current.approvalId ||
      parent.businessKey !== current.businessKey ||
      parent.candidateDigest !== current.candidateDigest ||
      BigInt(parent.attempt) + 1n !== BigInt(current.attempt)
    )
      throw new PlatformRecoveryError();
    // Generic PREPARE RESUME retains the canonical request rather than consuming
    // the receiving challenge. Bind its exact signed verification and committed
    // reservation. The retained producer validates the same signed assertion with
    // its live clock before effects; reservation is not that validation instant.
    // Its immutable commit, exact purpose and valid reservation interval are all
    // required. This read grants no present use of the historical assertion.
    const receiving = await client.query<{
      operationId: string;
      candidateDigest: Buffer;
      sessionId: string;
      reservedAt: Date;
      evidenceCbor: Buffer;
      evidenceDigest: Buffer;
      cose: Buffer;
    }>(
      `select verification.operation_id::text as "operationId",verification.evidence_cbor as "evidenceCbor",
        verification.evidence_digest as "evidenceDigest",verification.cose_sign1 as cose,
        verification.candidate_digest as "candidateDigest",challenge.session_id::text as "sessionId",
        admitted.created_at as "reservedAt"
       from control.mutation_candidate original
       join control.mfa_challenge challenge on challenge.participant_id=original.participant_id
        and ((challenge.used_at is null and challenge.used_operation_id is null)
          or (challenge.used_operation_id=original.resume_operation_id and challenge.used_at is not null))
        and challenge.principal_id=original.maker_principal_id and challenge.session_id=original.maker_session_id
        and challenge.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
        and challenge.resource_id=original.predecessor_approval_id::text
        and challenge.resource_digest=sha256(convert_to(openpc.signing_canonical_json(original.resume_request),'UTF8'))
       join control.mutation_evidence verification on verification.participant_id=challenge.participant_id
        and verification.privacy_domain_id=original.privacy_domain_id
        and verification.mfa_challenge_id=challenge.mfa_challenge_id
        and verification.principal_id=original.maker_principal_id
        and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
        and verification.bound_authority_envelope_id=original.maker_authority_envelope_id
        and verification.bound_assignment_id=original.maker_assignment_id
       join control.idempotency_record admitted on admitted.participant_id=verification.participant_id
        and admitted.privacy_domain_id=verification.privacy_domain_id and admitted.principal_id=verification.principal_id
        and admitted.operation_id=verification.operation_id and admitted.catalog_operation_id=verification.catalog_operation_id
        and admitted.action_intent_id=verification.action_intent_id and admitted.input_digest=verification.candidate_digest
        and admitted.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
        and admitted.terminal_state='COMMITTED'
        and admitted.created_at>=challenge.created_at and admitted.created_at<=challenge.consumed_at
       where original.participant_id=$1 and original.privacy_domain_id=$2 and original.mutation_candidate_id=$3`,
      [enrollment.participantId, enrollment.privacyDomainId, current.candidateId],
    );
    const evidence = receiving.rows[0];
    if (
      receiving.rowCount !== 1 ||
      !evidence ||
      !createHash('sha256')
        .update(evidence.evidenceCbor)
        .digest()
        .equals(evidence.evidenceDigest) ||
      !(await verifier.verifyCanonicalAssertion(evidence.evidenceCbor, evidence.cose))
    )
      throw new PlatformRecoveryError();
    const maker = intent.preparation.administrators[0];
    if (
      !maker ||
      !authenticateHistoricalRuntimeStepUpEvidence(
        {
          participantId: enrollment.participantId,
          principalId: maker.principalId,
          evidenceCbor: evidence.evidenceCbor,
        },
        {
          candidate_digest: evidence.candidateDigest,
          session_id: evidence.sessionId,
          occurred_at: evidence.reservedAt,
        },
      )
    )
      throw new PlatformRecoveryError();
    if (hop === 31) throw new PlatformRecoveryError();
    current = parent;
  }
  if (
    !authenticatedPreparation ||
    canonicalAuthorizationDigest(row.preparation) !== witness.candidateDigest
  )
    throw new PlatformRecoveryError();
  const preparation = authenticatedPreparation;
  return {
    approvalContinuation: witness,
    approvalContinuationPreparation: preparation,
    preparation,
    plannedRecordIds: [
      preparation.replacementId,
      ...preparation.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
    ],
  };
}
