import type { PoolClient } from 'pg';
import {
  directoryCandidateSchema,
  directoryCandidateOperation,
  directoryOperations,
} from '../contracts/directory-operations.js';
import { IdentityKernelError } from './identity-errors.js';
import type { RecoveryProposalBinding } from './recovery-proposal.js';

function bindingSql(binding: RecoveryProposalBinding) {
  return 'approvalRequestId' in binding
    ? { sql: 'a.approval_request_id=$4', values: [binding.approvalRequestId] }
    : {
        sql: 'm.expected_revision=$4 and m.maker_principal_id=$5',
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}
export async function resolveDirectoryProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  digest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{ resource_id: string }>(
    `select distinct m.resource_id from control.mutation_candidate m
    left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
    where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3 and ${bound.sql}
      and m.catalog_operation_id=any($${4 + bound.values.length}::text[]) limit 2`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(digest.slice(7), 'hex'),
      ...bound.values,
      directoryOperations.map((operation) => operation.id),
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}
export async function readDirectoryProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  digest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{
    resource_id: string;
    maker_principal_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
    catalog_operation_id: string;
    consumed_operation_id: string | null;
    approval_request_id: string | null;
    reason: string | null;
  }>(
    `select m.resource_id,m.maker_principal_id,m.expected_revision::text,m.state,m.expires_at,m.candidate_document,m.catalog_operation_id,m.consumed_operation_id,a.approval_request_id,a.reason
     from control.mutation_candidate m left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
     where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3 and ${bound.sql}
       and m.resource_id=$${4 + bound.values.length} and m.catalog_operation_id=any($${5 + bound.values.length}::text[]) for share of m`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(digest.slice(7), 'hex'),
      ...bound.values,
      resourceId,
      directoryOperations.map((operation) => operation.id),
    ],
  );
  const row = result.rows[0],
    candidate = directoryCandidateSchema.safeParse(row?.candidate_document);
  if (
    result.rowCount !== 1 ||
    !row ||
    !candidate.success ||
    ('change' in candidate.data
      ? candidate.data.change.connectorId
      : candidate.data.connectorId) !== resourceId ||
    candidate.data.expectedRevision !== row.expected_revision ||
    directoryCandidateOperation(candidate.data) !== row.catalog_operation_id
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
