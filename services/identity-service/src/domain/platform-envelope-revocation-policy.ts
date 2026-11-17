import { platformScopeRowsSql } from '../db/current-platform-envelope.js';
import type { PoolClient } from 'pg';
import { z } from 'zod';

import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';

const catalog = 'ID-OP-ENVELOPE-REVOKE';
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const candidate = z.strictObject({
  envelopeId: z.uuid(),
  reason: z.string().trim().min(10).max(1024),
});

async function exactActivePlatformEnvelope(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  envelopeId: string,
  expectedRevision?: string,
) {
  const selected = await client.query(
    `select 1 from control.authority_envelope envelope
      join control.platform_context platform
        on platform.platform_context_id=envelope.platform_context_id
       and platform.authority_epoch=envelope.platform_authority_epoch and platform.state='ACTIVE'
      join ${platformScopeRowsSql} root
        on root.platform_context_id=platform.platform_context_id
       and root.platform_authority_epoch=platform.authority_epoch
       and root.owner_participant_id=envelope.participant_id
       and root.installation_privacy_domain_id=$2
     where envelope.participant_id=$1 and envelope.authority_envelope_id=$3
       and envelope.state='ACTIVE' and envelope.representation='TYPED_V1'
       and ($4::bigint is null or envelope.row_version=$4::bigint)`,
    [participantId, privacyDomainId, envelopeId, expectedRevision ?? null],
  );
  return selected.rowCount === 1;
}

/** Context eligibility only. The enclosing policy owner still resolves one
 * live direct grant for the action and exact target resource. */
export async function platformEnvelopeRevocationPolicyScope(
  client: PoolClient,
  participantId: string,
  principalId: string,
  input: PolicyAuthorizationRequest,
): Promise<boolean | undefined> {
  if (input.catalogOperationId === catalog)
    return (
      input.actionIntentId === action &&
      (await exactActivePlatformEnvelope(
        client,
        participantId,
        input.privacyDomainId,
        input.resourceId,
      ))
    );
  if (input.catalogOperationId !== undefined) return undefined;

  const requesting =
    input.actionIntentId === 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' &&
    input.approvalCandidateDigest !== undefined;
  const proving = input.actionIntentId === action && input.stepUpCandidateDigest !== undefined;
  const resuming = input.actionIntentId === 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
  const reviewing = [
    'ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  ].includes(input.actionIntentId);
  if (!requesting && !proving && !resuming && !reviewing) return undefined;
  if (requesting && input.resourceId !== principalId) return false;
  const candidateDigest = requesting
    ? input.approvalCandidateDigest
    : proving
      ? input.stepUpCandidateDigest
      : undefined;
  if (candidateDigest !== undefined && !/^sha256:[0-9a-f]{64}$/u.test(candidateDigest))
    return false;

  const selected = await client.query<{
    envelopeId: string;
    expectedRevision: string;
    document: unknown;
    live: boolean;
  }>(
    `select c.resource_id::text as "envelopeId",c.expected_revision::text as "expectedRevision",
      c.candidate_document as document,
      ($7='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' or
       ($7='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' and c.maker_principal_id=$4
        and ${currentMutationCandidateSql('c')} and c.state in ('APPROVAL_REQUESTED','APPROVED')
        and a.state in ('OPEN','APPROVED','EXPIRED')) or
       (c.expires_at>clock_timestamp() and c.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
        and ${currentMutationCandidateSql('c')}
        and (($5 and c.maker_principal_id=$4) or ($6 and c.maker_principal_id=$4)
          or (not $5 and not $6 and c.maker_principal_id<>$4 and a.state in ('OPEN','APPROVED')
            and a.expires_at>clock_timestamp() and (a.checker_principal_id is null or a.checker_principal_id=$4))))) live
     from control.mutation_candidate c left join control.approval_request a
       on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
       and a.subject_type='CONFIGURATION_CANDIDATE' and a.subject_id=c.mutation_candidate_id
       and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
       and a.action_intent_id=c.action_intent_id and a.maker_principal_id=c.maker_principal_id
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.catalog_operation_id='ID-OP-ENVELOPE-REVOKE'
       and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' and c.operation_class='UPDATE'
       and c.resource_type='participant'
       and (case when $5 then c.candidate_digest=$8 when $6 then c.resource_id::text=$3 and c.candidate_digest=$8
         else a.approval_request_id::text=$3 end)
       and (not ($5 or $6) or ${currentMutationCandidateSql('c')})`,
    [
      participantId,
      input.privacyDomainId,
      input.resourceId,
      principalId,
      requesting,
      proving,
      input.actionIntentId,
      candidateDigest === undefined ? null : Buffer.from(candidateDigest.slice(7), 'hex'),
    ],
  );
  if (selected.rowCount === 0) return undefined;
  const row = selected.rows[0];
  const parsed = candidate.safeParse(row?.document);
  if (
    selected.rowCount !== 1 ||
    !row?.live ||
    !parsed.success ||
    parsed.data.envelopeId !== row.envelopeId ||
    !(await exactActivePlatformEnvelope(
      client,
      participantId,
      input.privacyDomainId,
      row.envelopeId,
      row.expectedRevision,
    ))
  )
    return false;
  return true;
}
