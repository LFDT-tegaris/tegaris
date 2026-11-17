import type { PoolClient } from 'pg';
import {
  invitationAction,
  invitationCandidateSchema,
  invitationOperationIds,
} from '../contracts/invitation-operations.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { IdentityKernelError } from './identity-errors.js';
import type { RecoveryProposalBinding } from './recovery-proposal.js';

const operations = Object.values(invitationOperationIds);
function bound(binding: RecoveryProposalBinding) {
  return 'approvalRequestId' in binding
    ? { sql: 'approval.approval_request_id=$4', values: [binding.approvalRequestId] }
    : {
        sql: 'candidate.expected_revision=$4 and candidate.maker_principal_id=$5',
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}
export async function resolveInvitationProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  digest: string,
  binding: RecoveryProposalBinding,
) {
  const selection = bound(binding);
  const result = await client.query<{ resource_id: string }>(
    `select distinct candidate.resource_id from control.mutation_candidate candidate
    left join control.approval_request approval on approval.participant_id=candidate.participant_id and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
    where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.candidate_digest=$3 and ${selection.sql}
      and candidate.catalog_operation_id=any($${4 + selection.values.length}::text[]) limit 2`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(digest.slice(7), 'hex'),
      ...selection.values,
      operations,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}
export async function readInvitationProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  digest: string,
  binding: RecoveryProposalBinding,
) {
  const selection = bound(binding);
  const result = await client.query<{
    resource_id: string;
    maker_principal_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
    catalog_operation_id: string;
    action_intent_id: string;
    consumed_operation_id: string | null;
    approval_request_id: string | null;
    reason: string | null;
  }>(
    `select candidate.resource_id,candidate.maker_principal_id,candidate.expected_revision::text,candidate.state,candidate.expires_at,candidate.candidate_document,candidate.catalog_operation_id,candidate.action_intent_id,candidate.consumed_operation_id,approval.approval_request_id,approval.reason
    from control.mutation_candidate candidate left join control.approval_request approval on approval.participant_id=candidate.participant_id and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
    where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.candidate_digest=$3 and ${selection.sql}
      and candidate.resource_id=$${4 + selection.values.length} and candidate.catalog_operation_id=any($${5 + selection.values.length}::text[]) for share of candidate`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(digest.slice(7), 'hex'),
      ...selection.values,
      resourceId,
      operations,
    ],
  );
  const row = result.rows[0],
    candidate = invitationCandidateSchema.safeParse(row?.candidate_document);
  if (
    result.rowCount !== 1 ||
    !row ||
    !candidate.success ||
    candidate.data.change.invitationId !== resourceId ||
    candidate.data.expectedRevision !== row.expected_revision ||
    invitationOperationIds[candidate.data.change.mutation] !== row.catalog_operation_id ||
    invitationAction(candidate.data) !== row.action_intent_id ||
    canonicalAuthorizationDigest(candidate.data) !== digest
  )
    throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    candidateDigest: digest,
    resourceId,
    makerPrincipalId: row.maker_principal_id,
    expectedRevision: row.expected_revision,
    state: row.state,
    expiresAt: row.expires_at.toISOString(),
    candidate: candidate.data,
    catalogOperationId: row.catalog_operation_id,
    operationId: row.consumed_operation_id,
    ...(row.approval_request_id
      ? { approval: { approvalRequestId: row.approval_request_id, reason: row.reason } }
      : {}),
  };
}
