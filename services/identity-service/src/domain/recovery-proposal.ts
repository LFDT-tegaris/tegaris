import { z } from 'zod';
import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';
const uuid = z.uuid(),
  epoch = z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const candidates = {
  'ID-OP-RECOVERY-PRINCIPAL-QUALIFY': z.strictObject({
    principalId: uuid,
    credentialId: uuid,
    principalEpoch: epoch,
    credentialEpoch: epoch,
  }),
  'ID-OP-RECOVERY-PRINCIPAL-REVOKE': z.strictObject({
    principalId: uuid,
    state: z.literal('REVOKED'),
  }),
  'ID-OP-RECOVERY-BEGIN': z.strictObject({
    recoveryId: uuid,
    participantId: uuid,
    subjectId: uuid,
    recoveryPrincipalId: uuid,
    custodianPrincipalIds: z.tuple([uuid, uuid]),
    purposeDigest: digest,
    actionIntentId: z.literal('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'),
  }),
  'ID-OP-RECOVERY-APPROVE': z.strictObject({ recoveryId: uuid, purposeDigest: digest }),
  'ID-OP-RECOVERY-COMPLETE': z.strictObject({ recoveryId: uuid, state: z.literal('COMPLETED') }),
  'ID-OP-RECOVERY-POST-REVIEW': z.strictObject({
    recoveryId: uuid,
    note: z.string().min(10).max(1024),
  }),
};
export type RecoveryProposalBinding =
  { expectedRevision: string; makerPrincipalId: string } | { approvalRequestId: string };

function proposalBinding(binding: RecoveryProposalBinding, offset: number) {
  return 'approvalRequestId' in binding
    ? {
        sql: `mutation_candidate_id in (select subject_id from control.approval_request where participant_id=$1 and privacy_domain_id=$2 and approval_request_id=$${offset})`,
        values: [binding.approvalRequestId],
      }
    : {
        sql: `expected_revision=$${offset} and maker_principal_id=$${offset + 1}`,
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}
export async function resolveRecoveryProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = proposalBinding(binding, 5);
  const result = await client.query<{ resource_id: string }>(
    `select resource_id from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and candidate_digest=$3 and catalog_operation_id=any($4::text[]) and ${bound.sql} limit 2`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      Object.keys(candidates),
      ...bound.values,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}
/** Project only admitted recovery inputs after fencing read authority on their actual resource. */
export async function readRecoveryProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  candidateDigest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = proposalBinding(binding, 6);
  const result = await client.query<{
    mutation_candidate_id: string;
    maker_principal_id: string;
    catalog_operation_id: keyof typeof candidates;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
  }>(
    `select mutation_candidate_id,maker_principal_id,catalog_operation_id,expected_revision::text,state,expires_at,candidate_document from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3 and candidate_digest=$4 and catalog_operation_id=any($5::text[]) and ${bound.sql} for share`,
    [
      participantId,
      privacyDomainId,
      resourceId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      Object.keys(candidates),
      ...bound.values,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  const row = result.rows[0]!,
    document = candidates[row.catalog_operation_id].safeParse(row.candidate_document);
  if (!document.success) throw new IdentityKernelError('PC-IDENTITY-1008');
  let approval: { approvalRequestId: string; reason: string | null } | undefined;
  if ('approvalRequestId' in binding) {
    const requested = await client.query<{ reason: string | null }>(
      `select reason from control.approval_request where participant_id=$1 and privacy_domain_id=$2
         and subject_id=$3 and approval_request_id=$4 for share`,
      [participantId, privacyDomainId, row.mutation_candidate_id, binding.approvalRequestId],
    );
    const reason = z.string().min(1).max(1024).nullable().safeParse(requested.rows[0]?.reason);
    if (requested.rowCount !== 1 || !reason.success)
      throw new IdentityKernelError('PC-IDENTITY-1008');
    approval = { approvalRequestId: binding.approvalRequestId, reason: reason.data };
  }
  return {
    candidateDigest,
    resourceId,
    makerPrincipalId: row.maker_principal_id,
    catalogOperationId: row.catalog_operation_id,
    expectedRevision: row.expected_revision,
    state: row.state,
    expiresAt: row.expires_at.toISOString(),
    candidate: document.data,
    ...(approval ? { approval } : {}),
  };
}
