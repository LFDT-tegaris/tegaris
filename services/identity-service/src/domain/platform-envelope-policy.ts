import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';
import { platformScopeRowsSql } from '../db/current-platform-envelope.js';
import type { PoolClient } from 'pg';
import type { PolicyAuthorizationRequest } from './policy-authorization.js';
import { typedEnvelopeCreateCandidate } from '../../../participant-service/src/contracts/envelope.js';
import { findEnvelopeProposal } from '../db/identity-envelope-proposal.js';
import { platformEnvelopeActivationPolicyScope } from './platform-envelope-activation-policy.js';
import { platformEnvelopeRevocationPolicyScope } from './platform-envelope-revocation-policy.js';

async function initialPlatformEnvelopeStepUpEligible(
  client: PoolClient,
  participantId: string,
  principalId: string,
  input: PolicyAuthorizationRequest,
): Promise<boolean> {
  if (
    input.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
    !input.stepUpCandidateDigest ||
    !/^sha256:[0-9a-f]{64}$/u.test(input.stepUpCandidateDigest) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      input.resourceId,
    ) ||
    input.resourceId === participantId
  )
    return false;
  const result = await client.query(
    `select 1 from control.assignment assignment
      join control.authority_envelope envelope
        on envelope.participant_id=assignment.participant_id
       and envelope.authority_envelope_id=assignment.authority_envelope_id
      join control.platform_context platform
        on platform.platform_context_id=envelope.platform_context_id
       and platform.authority_epoch=envelope.platform_authority_epoch and platform.state='ACTIVE'
      join ${platformScopeRowsSql} root
        on root.platform_context_id=platform.platform_context_id
       and root.platform_authority_epoch=platform.authority_epoch
       and root.owner_participant_id=assignment.participant_id
       and root.installation_privacy_domain_id=$3
     where assignment.participant_id=$1 and assignment.principal_id=$2
       and assignment.state='ACTIVE' and assignment.valid_during @> clock_timestamp()
       and assignment.maker_checker_required and assignment.step_up_required
       and 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'=any(assignment.action_intent_ids)
       and $3::text=any(assignment.privacy_domain_ids)
       and ($4=any(assignment.resource_ids) or '*'=any(assignment.resource_ids))
       and (envelope.principal_id=$2 or (envelope.representation='TYPED_V1' and envelope.principal_id is null)) and envelope.state='ACTIVE'
       and envelope.valid_from<=clock_timestamp()
       and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
       and envelope.maker_checker_required and envelope.step_up_required
       and 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'=any(envelope.action_intent_ids)
       and $3::text=any(envelope.privacy_domain_ids)
       and ($4=any(envelope.resource_ids) or '*'=any(envelope.resource_ids))
     limit 1`,
    [participantId, principalId, input.privacyDomainId, input.resourceId],
  );
  return result.rowCount === 1;
}

/** Context eligibility only. The caller still requires a direct, unambiguous,
 * current Platform actor grant. Public owners re-resolve and fence the exact
 * business subject and fresh proof in the effect transaction. */
export async function platformEnvelopePolicyScope(
  client: PoolClient,
  participantId: string,
  principalId: string,
  input: PolicyAuthorizationRequest,
): Promise<boolean | undefined> {
  const revocation = await platformEnvelopeRevocationPolicyScope(
    client,
    participantId,
    principalId,
    input,
  );
  if (revocation !== undefined) return revocation;
  const activation = await platformEnvelopeActivationPolicyScope(
    client,
    participantId,
    principalId,
    input,
  );
  if (activation !== undefined) return activation;
  const create = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
  const submit = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
  if (input.catalogOperationId === 'ID-OP-ENVELOPE-CREATE')
    return (
      input.actionIntentId === create &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        input.resourceId,
      ) &&
      input.resourceId !== participantId
    );
  if (input.catalogOperationId !== undefined) return undefined;
  const scope = { participantId, privacyDomainId: input.privacyDomainId };
  if (input.actionIntentId === submit && input.approvalCandidateDigest !== undefined) {
    if (
      !/^sha256:[0-9a-f]{64}$/u.test(input.approvalCandidateDigest) ||
      input.resourceId !== principalId
    )
      return false;
    const digest = Buffer.from(input.approvalCandidateDigest.slice(7), 'hex');
    const selected = await client.query<{ document: unknown; live: boolean }>(
      `select candidate_document as document,
      (state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED') and expires_at>clock_timestamp()
       and maker_principal_id=$4 and expected_revision=0 and operation_class='UPDATE' and resource_type='participant') live
      from control.mutation_candidate c where participant_id=$1 and privacy_domain_id=$2 and candidate_digest=$3
      and catalog_operation_id='ID-OP-ENVELOPE-CREATE' and ${currentMutationCandidateSql('c')}`,
      [participantId, input.privacyDomainId, digest, principalId],
    );
    const proposal = await findEnvelopeProposal(client, scope, digest);
    if (selected.rowCount === 0 && !proposal) return undefined;
    // Include every public subject family: no ambiguous selector can grant context.
    const counts = await client.query<{ count: string }>(
      `select (
      (select count(*) from control.mutation_candidate c where participant_id=$1 and privacy_domain_id=$2 and candidate_digest=$3 and ${currentMutationCandidateSql('c')})+
      (select count(*) from control.policy_version where participant_id=$1 and privacy_domain_id=$2 and semantic_digest=$3)+
      (select count(*) from control.identity_envelope_proposal where participant_id=$1 and privacy_domain_id=$2 and proposal_digest=$3))::text count`,
      [participantId, input.privacyDomainId, digest],
    );
    if (counts.rows[0]?.count !== '1') return false;
    if (proposal)
      return (
        proposal.state === 'DRAFT' &&
        proposal.version === '1' &&
        proposal.makerPrincipalId === principalId
      );
    const row = selected.rows[0];
    const parsed = typedEnvelopeCreateCandidate.safeParse(row?.document);
    return (
      selected.rowCount === 1 &&
      row?.live === true &&
      parsed.success &&
      parsed.data.issuance === 'PLATFORM_ROOT'
    );
  }
  if (input.actionIntentId === create && input.stepUpCandidateDigest) {
    const selected = await client.query<{ document: unknown; digest: string; live: boolean }>(
      `select candidate_document as document,
      'sha256:'||encode(candidate_digest,'hex') digest,
      (state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED') and expires_at>clock_timestamp() and expected_revision=0) live
      from control.mutation_candidate c where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3
      and maker_principal_id=$4 and catalog_operation_id='ID-OP-ENVELOPE-CREATE' and ${currentMutationCandidateSql('c')}`,
      [participantId, input.privacyDomainId, input.resourceId, principalId],
    );
    if (selected.rowCount === 0) {
      if (/^sha256:[0-9a-f]{64}$/u.test(input.stepUpCandidateDigest)) {
        const custodyChange = await client.query(
          `select 1 from control.mutation_candidate c
           where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3
             and maker_principal_id=$4 and candidate_digest=$5
             and action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
             and operation_class='UPDATE' and resource_type='participant'
             and catalog_operation_id in ('ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE','ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE')
             and candidate_document ? 'mandateId' and expected_revision>0
             and state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
             and consumed_operation_id is null and expires_at>clock_timestamp()
             and ${currentMutationCandidateSql('c')}`,
          [
            participantId,
            input.privacyDomainId,
            input.resourceId,
            principalId,
            Buffer.from(input.stepUpCandidateDigest.slice(7), 'hex'),
          ],
        );
        // This is a different stored subject. Its bootstrap owner decides
        // context eligibility; this handler grants no permission for it.
        if (custodyChange.rowCount !== 0) return custodyChange.rowCount === 1 ? undefined : false;
      }
      return initialPlatformEnvelopeStepUpEligible(client, participantId, principalId, input);
    }
    const row = selected.rows[0];
    const parsed = typedEnvelopeCreateCandidate.safeParse(row?.document);
    return (
      selected.rowCount === 1 &&
      row?.live === true &&
      row.digest === input.stepUpCandidateDigest &&
      parsed.success &&
      parsed.data.issuance === 'PLATFORM_ROOT' &&
      parsed.data.envelopeId === input.resourceId
    );
  }
  if (input.actionIntentId === submit && input.stepUpCandidateDigest) {
    // The request digest is checked by the public submission owner; the exact
    // target is persisted by challenge/verification and must match consumption.
    const selected = await client.query<{ digest: Buffer }>(
      `select proposal_digest as digest from control.identity_envelope_proposal
      where participant_id=$1 and privacy_domain_id=$2 and envelope_id::text=$3`,
      [participantId, input.privacyDomainId, input.resourceId],
    );
    if (selected.rowCount === 0) return undefined;
    if (selected.rowCount !== 1) return false;
    const proposal = await findEnvelopeProposal(client, scope, selected.rows[0]!.digest);
    return (
      proposal?.state === 'DRAFT' &&
      proposal.version === '1' &&
      proposal.makerPrincipalId === principalId
    );
  }
  if (
    [
      'ACT-POLICY_APPROVE_REQUEST-V1',
      'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    ].includes(input.actionIntentId)
  ) {
    const candidate = await client.query<{ document: unknown; live: boolean }>(
      `select c.candidate_document as document,
      ($4='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' or
       ($4='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' and c.maker_principal_id=$5
        and ${currentMutationCandidateSql('c')} and c.consumed_operation_id is null
        and c.state in ('APPROVAL_REQUESTED','APPROVED') and r.state in ('OPEN','APPROVED','EXPIRED')
        and c.candidate_document->>'participantId'=$1::uuid::text
        and (c.candidate_document#>>'{usable,validUntilNs}')::numeric>extract(epoch from clock_timestamp())*1000000000
        and (c.candidate_document#>>'{grantable,validUntilNs}')::numeric>extract(epoch from clock_timestamp())*1000000000) or
       (c.state in ('APPROVAL_REQUESTED','APPROVED') and c.expires_at>clock_timestamp()
        and r.state in ('OPEN','APPROVED') and r.expires_at>clock_timestamp() and c.maker_principal_id<>$5
        and (r.checker_principal_id is null or r.checker_principal_id=$5)
        and ${currentMutationCandidateSql('c')})) live
      from control.mutation_candidate c join control.approval_request r
      on r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
      and r.subject_type='CONFIGURATION_CANDIDATE' and r.subject_id=c.mutation_candidate_id
      and r.subject_digest=c.candidate_digest and r.subject_version=c.expected_revision and r.maker_principal_id=c.maker_principal_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and r.approval_request_id::text=$3
      and c.catalog_operation_id='ID-OP-ENVELOPE-CREATE' and c.expected_revision=0
      and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' and r.action_intent_id=c.action_intent_id`,
      [participantId, input.privacyDomainId, input.resourceId, input.actionIntentId, principalId],
    );
    if (candidate.rowCount !== 0) {
      const row = candidate.rows[0];
      const parsed = typedEnvelopeCreateCandidate.safeParse(row?.document);
      return (
        candidate.rowCount === 1 &&
        row?.live === true &&
        parsed.success &&
        parsed.data.issuance === 'PLATFORM_ROOT'
      );
    }
    const selected = await client.query<{ digest: Buffer; id: string; state: string }>(
      `select p.proposal_digest as digest,p.envelope_id::text id,p.state
      from control.identity_envelope_proposal p join control.approval_request r
      on r.participant_id=p.participant_id and r.privacy_domain_id=p.privacy_domain_id
      and r.approval_request_id=p.submission_approval_id and r.subject_type='AUTHORITY_ENVELOPE'
      and r.subject_id=p.envelope_id and r.subject_digest=p.proposal_digest and r.subject_version=1
      and r.maker_principal_id=p.maker_principal_id and r.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      where p.participant_id=$1 and p.privacy_domain_id=$2 and r.approval_request_id::text=$3
      and ((p.state='SUBMITTED' and p.row_version=2) or (p.state='APPROVED' and p.row_version=3))
      and ($4='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' or
        (p.maker_principal_id<>$5 and (r.checker_principal_id is null or r.checker_principal_id=$5)
          and r.state in ('OPEN','APPROVED') and r.expires_at>clock_timestamp()))`,
      [participantId, input.privacyDomainId, input.resourceId, input.actionIntentId, principalId],
    );
    if (selected.rowCount === 0) return undefined;
    if (selected.rowCount !== 1) return false;
    const proposal = await findEnvelopeProposal(client, scope, selected.rows[0]!.digest);
    return proposal?.envelopeId === selected.rows[0]!.id;
  }
  return undefined;
}
