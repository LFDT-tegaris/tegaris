import type { PoolClient } from 'pg';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';
import { platformEnvelopePolicyScope } from './platform-envelope-policy.js';

/** A closed Platform governance gate; the policy owner still requires an unambiguous direct grant. */
export async function platformBootstrapPolicyScope(
  client: PoolClient,
  participantId: string,
  principalId: string,
  sessionId: string,
  input: PolicyAuthorizationRequest,
): Promise<boolean> {
  const envelope = await platformEnvelopePolicyScope(client, participantId, principalId, input);
  if (envelope !== undefined) return envelope;
  // Explicit Platform grants still bound the target resource in the live policy query.
  // Lifecycle administration survives target suspension; source authority must remain live.
  if (
    input.actionIntentId === 'ACT-PARTICIPANTS_READ_COLLECTION-V1' &&
    input.resourceId === participantId
  )
    return true;
  if (
    input.actionIntentId === 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1' &&
    input.resourceId === participantId
  )
    return true;
  if (input.actionIntentId === 'ACT-PARTICIPANTS_READ_RESOURCE-V1') return true;
  if (
    input.resourceId !== participantId &&
    input.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    [
      'ID-OP-PARTICIPANT-TRANSFER',
      'ID-OP-PARTICIPANT-SHRINK',
      'ID-OP-PARTICIPANT-ARCHIVE',
      'ID-OP-PARTICIPANT-RESTORE',
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      'ID-OP-PLATFORM-SCOPE-COMMIT',
    ].includes(input.catalogOperationId ?? '')
  )
    return true;
  if (
    input.actionIntentId === 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1' &&
    input.catalogOperationId === 'ID-OP-PARTICIPANT-CREATE' &&
    input.resourceId !== participantId
  )
    return true;
  if (
    input.actionIntentId === 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' &&
    input.resourceId === principalId
  )
    return true;
  if (input.actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1' && input.resourceId === sessionId)
    return true;
  if (
    ![
      'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
      'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      'ACT-POLICY_APPROVE_REQUEST-V1',
    ].includes(input.actionIntentId)
  )
    return false;
  if (
    input.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    input.catalogOperationId !== undefined &&
    ![
      'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE',
      'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE',
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      'ID-OP-PLATFORM-SCOPE-COMMIT',
    ].includes(input.catalogOperationId)
  )
    return false;
  // Historical Root approval readback/resume is context admission only. Current
  // grants are selected independently; RESUME still proves no effect and fresh
  // Root custody before a successor can obtain new checker authority.
  const related = await client.query(
    `select 1 from control.mutation_candidate candidate
    left join control.approval_request approval on approval.participant_id=candidate.participant_id and approval.privacy_domain_id=candidate.privacy_domain_id
      and approval.subject_id=candidate.mutation_candidate_id and approval.subject_digest=candidate.candidate_digest
    where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.catalog_operation_id in ('ID-OP-PARTICIPANT-CREATE','ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE','ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE','ID-OP-PARTICIPANT-TRANSFER', 'ID-OP-PARTICIPANT-SHRINK', 'ID-OP-PARTICIPANT-ARCHIVE','ID-OP-PARTICIPANT-RESTORE','ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT')
      and (candidate.catalog_operation_id in ('ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT') or candidate.candidate_document ? 'firstAdministrator' or candidate.candidate_document ? 'mandateId' or (candidate.catalog_operation_id in ('ID-OP-PARTICIPANT-TRANSFER', 'ID-OP-PARTICIPANT-SHRINK', 'ID-OP-PARTICIPANT-ARCHIVE','ID-OP-PARTICIPANT-RESTORE') and candidate.candidate_document ? 'mutation')) and (candidate.expires_at>clock_timestamp() or (candidate.state='CONSUMED' and $5 in ('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'))
        or (candidate.catalog_operation_id in ('ID-OP-PLATFORM-SCOPE-PREPARE','ID-OP-PLATFORM-SCOPE-COMMIT')
          and approval.approval_request_id::text=$3
          and (($5='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1'
            and ($4=candidate.maker_principal_id::text or $4=approval.checker_principal_id::text))
            or ($5='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' and $4=candidate.maker_principal_id::text
              and candidate.consumed_operation_id is null and candidate.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')))))
      and candidate.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED','CONSUMED')
      and (candidate.resource_id::text=$3 or approval.approval_request_id::text=$3 or
        ($3=$4 and $5 in ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1')))
      and ($5<>'ACT-PARTICIPANTS_CREATE_RESOURCE-V1' or $6::bytea is null or candidate.candidate_digest=$6)
      and ($7::bytea is null or candidate.candidate_digest=$7) limit 1`,
    [
      participantId,
      input.privacyDomainId,
      input.resourceId,
      principalId,
      input.actionIntentId,
      input.stepUpCandidateDigest ? Buffer.from(input.stepUpCandidateDigest.slice(7), 'hex') : null,
      input.approvalCandidateDigest
        ? Buffer.from(input.approvalCandidateDigest.slice(7), 'hex')
        : null,
    ],
  );
  return related.rowCount === 1;
}
