import { sql, type SQLWrapper } from 'drizzle-orm';
import { pgPolicy } from 'drizzle-orm/pg-core';
import { controlOwnerRole } from './common.js';

// These selectors form an acyclic chain: candidate, approval, decision, then
// verification and its committed outputs. No selector confers current authority.
// Deliberately uncorrelated with the protected row: the current request's live
// signed custody scope is fixed for this statement, rather than recomputed for
// every historical approval/decision. The helper authenticates each enrollment
// and exact old-key/successor binding before returning any IDs.
const currentContinuationEnrollments = sql`select continuation_enrollment.enrollment_id
  from jsonb_to_recordset((select openpc.read_workload_credential_continuation_scope()))
    continuation_enrollment(enrollment_id uuid)`;

export const continuationCandidateIds = sql`select jsonb_array_elements_text(
  (select jsonb_object_agg(current_custody.enrollment_id::text,
    to_jsonb(openpc.read_workload_credential_continuation_ids(current_custody.enrollment_id,'CANDIDATE')))
   from (${currentContinuationEnrollments}) current_custody)->enrollment.enrollment_id::text)::uuid`;

export const continuationApprovalIds = sql`select jsonb_array_elements_text(
  (select jsonb_object_agg(current_custody.enrollment_id::text,
    to_jsonb(openpc.read_workload_credential_continuation_ids(current_custody.enrollment_id,'APPROVAL')))
   from (${currentContinuationEnrollments}) current_custody)->enrollment.enrollment_id::text)::uuid`;

export const continuationDecisions = sql`select decision.* from control.approval_decision_record decision
  where decision.participant_id=enrollment.participant_id
    and decision.privacy_domain_id=enrollment.privacy_domain_id
    and decision.decision='APPROVE' and decision.approval_request_id in (${continuationApprovalIds})`;

export const continuationHistory = sql`select * from jsonb_to_recordset(
  (select jsonb_object_agg(current_custody.enrollment_id::text,
    openpc.read_workload_credential_continuation_evidence(current_custody.enrollment_id))
   from (${currentContinuationEnrollments}) current_custody)->enrollment.enrollment_id::text)
  history(operation_id uuid,aggregate_type text,aggregate_id uuid,evidence_cbor text,evidence_digest text,cose_sign1 text)`;

/** Read the exact original normal workload rotation beneath a signed recovery
 * enrollment. The existing oracle still validates every joined commitment and
 * the caller authenticates the historical signature before accepting custody.
 * No application role or owner mutation receives an additional policy. */
export function workloadCredentialContinuationSourcePolicies(
  participantId: SQLWrapper,
  match: SQLWrapper,
  privacyDomainId?: SQLWrapper,
) {
  return [
    pgPolicy('workload_credential_continuation_read', {
      for: 'select',
      to: [controlOwnerRole],
      using: sql`openpc.matches_participant(${participantId})
        and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and exists(select 1 from jsonb_to_recordset((select openpc.read_workload_credential_continuation_scope()))
          enrollment(enrollment_id uuid,participant_id uuid,privacy_domain_id uuid,document jsonb,workload_credential_id uuid)
          cross join lateral (select enrollment.workload_credential_id) source_key
          where enrollment.participant_id=${participantId} and openpc.matches_privacy(enrollment.privacy_domain_id)
            ${privacyDomainId ? sql`and enrollment.privacy_domain_id=${privacyDomainId}` : sql``}
            and (${match}))`,
    }),
  ];
}
