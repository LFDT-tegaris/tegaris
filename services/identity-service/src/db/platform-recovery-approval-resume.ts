import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  platformRecoveryApprovalResumeReason,
  platformRecoveryApprovalResumePurpose,
} from '../contracts/platform-recovery.js';

/** Resolve the exact historical approval through a current schema3 lease.
 * The original candidate body, business key and consumed effects stay fixed. */
export async function readPlatformRecoveryApprovalResumePurpose(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly principalId: string;
    readonly authorityEnvelopeId: string;
    readonly approvalId: string;
    readonly requireLeaf?: boolean;
  },
) {
  const selected = await client.query<{
    approvalRevision: string;
    candidateId: string;
    attempt: string;
    candidateDigest: string;
    actionDigest: string;
    candidate: unknown;
    resourceId: string;
    expectedRevision: string;
  }>(
    `select a.row_version::text as "approvalRevision",c.mutation_candidate_id::text as "candidateId",
      c.attempt::text as attempt,'sha256:'||encode(c.candidate_digest,'hex') as "candidateDigest",
      'sha256:'||encode(i.semantic_digest,'hex') as "actionDigest",c.candidate_document as candidate,
      c.resource_id::text as "resourceId",c.expected_revision::text as "expectedRevision"
     from control.approval_request a join control.mutation_candidate c on c.participant_id=a.participant_id
      and c.privacy_domain_id=a.privacy_domain_id and c.mutation_candidate_id=a.subject_id
     join control.action_intent i on i.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$5
      and openpc.platform_recovery_approval_resume_subject_visible($1,$2,$3,$4,$5)
      ${
        input.requireLeaf === false
          ? ''
          : `and not exists(select 1 from control.mutation_candidate next
        where next.participant_id=c.participant_id and next.privacy_domain_id=c.privacy_domain_id
          and next.predecessor_candidate_id=c.mutation_candidate_id)`
      }`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.authorityEnvelopeId,
      input.approvalId,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    canonicalAuthorizationDigest(row.candidate) !== row.candidateDigest
  )
    return undefined;
  const request = platformRecoveryApprovalResumePurpose.parse({
    command: 'RESUME',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: row.actionDigest,
    expectedRevision: row.approvalRevision,
    predecessorCandidateId: row.candidateId,
    expectedAttempt: row.attempt,
    candidateDigest: row.candidateDigest,
    reason: platformRecoveryApprovalResumeReason,
    approvalRequestId: `urn:openpc:resource:${input.approvalId}`,
  });
  return { ...row, request, requestDigest: canonicalAuthorizationDigest(request) };
}
