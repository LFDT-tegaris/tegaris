import type { PoolClient } from 'pg';
import { decodeEnvelopeProposal } from '@openpc/security-kernel';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';
import { findEnvelopeProposal } from '../db/identity-envelope-proposal.js';
import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';

const activate = 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';
const catalog = 'ID-OP-ENVELOPE-ACTIVATE';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

/** Context eligibility is deliberately narrower than generic Platform policy.
 * It supplies no grant: the enclosing owner still resolves and fences the
 * actor's real direct action, assignment, root, role and fresh proof. */
export async function initialEnvelopeActivationEligible(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  envelopeId: string,
) {
  if (!uuid.test(envelopeId)) return false;
  const selected = await client.query<{ digest: Buffer }>(
    `select proposal_digest as digest from control.identity_envelope_proposal
     where participant_id=$1 and privacy_domain_id=$2 and target_participant_id=$1
       and envelope_id=$3 and state='APPROVED' and row_version=3`,
    [participantId, privacyDomainId, envelopeId],
  );
  if (selected.rowCount !== 1) return false;
  const proposal = await findEnvelopeProposal(
    client,
    { participantId, privacyDomainId },
    selected.rows[0]!.digest,
  );
  if (
    !proposal ||
    proposal.envelopeId !== envelopeId ||
    proposal.state !== 'APPROVED' ||
    proposal.version !== '3'
  )
    return false;
  const value = decodeEnvelopeProposal(proposal.bytes);
  return (
    value.issuance === 'PLATFORM_ROOT' &&
    value.participantId === participantId &&
    value.issuer.authority.participantId === participantId
  );
}

export async function platformEnvelopeActivationPolicyScope(
  client: PoolClient,
  participantId: string,
  principalId: string,
  input: PolicyAuthorizationRequest,
): Promise<boolean | undefined> {
  const eligible = (envelopeId: string) =>
    initialEnvelopeActivationEligible(client, participantId, input.privacyDomainId, envelopeId);
  if (input.catalogOperationId === catalog)
    return input.actionIntentId === activate && eligible(input.resourceId);
  if (input.catalogOperationId !== undefined) return undefined;
  const requesting =
    input.actionIntentId === 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' &&
    input.approvalCandidateDigest !== undefined;
  const proving = input.actionIntentId === activate && input.stepUpCandidateDigest !== undefined;
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
    document: unknown;
    digest: Buffer;
    live: boolean;
  }>(
    `select c.resource_id::text as "envelopeId",c.candidate_document as document,c.candidate_digest as digest,
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
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
       and c.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' and c.operation_class='ACTIVATE'
       and c.resource_type='participant' and c.expected_revision=3
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
  if (
    selected.rowCount !== 1 ||
    !row ||
    !row.live ||
    !(await eligible(row.envelopeId)) ||
    canonicalAuthorizationDigest(row.document) !==
      canonicalAuthorizationDigest({ envelopeId: row.envelopeId })
  )
    return false;
  if (requesting) {
    const count = await client.query<{ count: string }>(
      `select (
      (select count(*) from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and candidate_digest=$3)+
      (select count(*) from control.policy_version where participant_id=$1 and privacy_domain_id=$2 and semantic_digest=$3)+
      (select count(*) from control.identity_envelope_proposal where participant_id=$1 and privacy_domain_id=$2 and proposal_digest=$3))::text count`,
      [participantId, input.privacyDomainId, row.digest],
    );
    if (count.rows[0]?.count !== '1') return false;
  }
  return true;
}
