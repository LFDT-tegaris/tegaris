import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type { PoolClient } from 'pg';
import { decodeEnvelopeProposal } from '@openpc/security-kernel';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import { typedEnvelopeCreateCandidate } from '../../../participant-service/src/contracts/envelope.js';
import { AuthorityFenceError } from './authority-fence.js';
import {
  findEnvelopeProposal,
  type EnvelopeGovernanceScope,
  type StoredEnvelopeProposal,
} from './identity-envelope-proposal.js';

/** Scoped historical binding only. The caller must fence its current disclosure
 * grant. Neither consumed CREATE nor an old proof supplies present authority. */
export async function readEnvelopeCreation(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  envelopeId: string,
  lock: false | 'share' = false,
) {
  const selected = await client.query<{
    digest: Buffer;
    candidateId: string;
    candidateDigest: Buffer;
    document: unknown;
    operationId: string;
  }>(
    `select p.proposal_digest as digest,c.mutation_candidate_id::text as "candidateId",
      c.candidate_digest as "candidateDigest",c.candidate_document as document,p.create_operation_id::text as "operationId"
    from control.identity_envelope_proposal p
    join control.mutation_candidate c on c.participant_id=p.participant_id and c.privacy_domain_id=p.privacy_domain_id
      and c.mutation_candidate_id=p.create_candidate_id and c.consumed_operation_id=p.create_operation_id
      and c.state='CONSUMED' and c.catalog_operation_id='ID-OP-ENVELOPE-CREATE'
      and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' and c.expected_revision=0
      and c.resource_id=p.envelope_id and c.maker_principal_id=p.maker_principal_id
    join control.approval_request a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
      and a.approval_request_id=p.create_approval_id and a.subject_type='CONFIGURATION_CANDIDATE'
      and a.subject_id=c.mutation_candidate_id and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
      and a.action_intent_id=c.action_intent_id and a.maker_principal_id=p.maker_principal_id and a.state='APPROVED'
    join control.mutation_evidence e on e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id
      and e.operation_id=c.consumed_operation_id and e.candidate_digest=c.candidate_digest
      and e.principal_id=p.maker_principal_id and e.approval_request_id=p.create_approval_id
    join control.idempotency_record receipt on receipt.participant_id=c.participant_id and receipt.privacy_domain_id=c.privacy_domain_id
      and receipt.operation_id=c.consumed_operation_id and receipt.terminal_state='COMMITTED'
      and receipt.principal_id=p.maker_principal_id and receipt.action_intent_id=c.action_intent_id
      and receipt.result_payload->>'id'=p.envelope_id::text
      and receipt.result_payload->>'participantId'=p.target_participant_id::text
      and receipt.result_payload->>'semanticDigest'='sha256:'||encode(p.proposal_digest,'hex')
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.envelope_id=$3`,
    [scope.participantId, scope.privacyDomainId, envelopeId],
  );
  const original = selected.rows[0];
  if (selected.rowCount !== 1 || !original) throw new AuthorityFenceError();
  const stored = await findEnvelopeProposal(client, scope, original.digest, lock);
  const candidate = typedEnvelopeCreateCandidate.safeParse(original.document);
  if (!stored || !candidate.success) throw new AuthorityFenceError();
  const proposal = decodeEnvelopeProposal(stored.bytes);
  if (
    stored.envelopeId !== envelopeId ||
    candidate.data.envelopeId !== envelopeId ||
    candidate.data.participantId !== stored.targetParticipantId ||
    candidate.data.issuance !== proposal.issuance ||
    !isDeepStrictEqual(candidate.data.usable, proposal.usable) ||
    !isDeepStrictEqual(candidate.data.grantable, proposal.grantable) ||
    !createHash('sha256')
      .update(canonicalAuthorizationJson(original.document))
      .digest()
      .equals(original.candidateDigest)
  )
    throw new AuthorityFenceError();
  return { stored, original };
}

/** Resolve the operation that actually committed this preactivation state.
 * No attempt, current eligibility or new receipt is manufactured for a read. */
export async function readEnvelopeEffectReadback(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  creation: Awaited<ReturnType<typeof readEnvelopeCreation>>,
): Promise<{
  operationId: string;
  state: StoredEnvelopeProposal['state'] | 'ACTIVE';
  version: string;
}> {
  const { stored, original } = creation;
  if (stored.state === 'DRAFT' && stored.version === '1')
    return { operationId: original.operationId, state: stored.state, version: stored.version };
  if (stored.state === 'APPROVED' && stored.version === '3') {
    const activated = await client.query<{ id: string }>(
      `select activation.operation_id::text as id
         from control.identity_envelope_activation activation
         join control.mutation_candidate candidate
           on candidate.participant_id=activation.participant_id
          and candidate.privacy_domain_id=activation.privacy_domain_id
          and candidate.mutation_candidate_id=activation.candidate_id
          and candidate.candidate_digest=activation.candidate_digest
          and candidate.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
          and candidate.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
          and candidate.resource_id=activation.envelope_id
          and candidate.expected_revision=activation.expected_approved_version
          and candidate.state='CONSUMED'
          and candidate.consumed_operation_id=activation.operation_id
         join control.approval_request approval
           on approval.participant_id=activation.participant_id
          and approval.privacy_domain_id=activation.privacy_domain_id
          and approval.approval_request_id=activation.approval_request_id
          and approval.subject_type='CONFIGURATION_CANDIDATE'
          and approval.subject_id=activation.candidate_id
          and approval.subject_digest=activation.candidate_digest
          and approval.subject_version=activation.expected_approved_version
          and approval.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
          and approval.state='APPROVED'
         join control.idempotency_record receipt
           on receipt.participant_id=activation.participant_id
          and receipt.privacy_domain_id=activation.privacy_domain_id
          and receipt.idempotency_record_id=activation.idempotency_record_id
          and receipt.operation_id=activation.operation_id
          and receipt.principal_id=activation.principal_id
          and receipt.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
          and receipt.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
          and receipt.expected_aggregate_version=activation.expected_approved_version
          and receipt.result_aggregate_version=4
          and receipt.terminal_state='COMMITTED'
         join control.mutation_evidence evidence
           on evidence.participant_id=activation.participant_id
          and evidence.privacy_domain_id=activation.privacy_domain_id
          and evidence.operation_id=activation.operation_id
          and evidence.principal_id=activation.principal_id
          and evidence.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
          and evidence.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
          and evidence.aggregate_type='authority-envelope'
          and evidence.aggregate_id=activation.envelope_id
          and evidence.aggregate_version=activation.expected_approved_version
          and evidence.candidate_digest=activation.candidate_digest
          and evidence.approval_request_id=activation.approval_request_id
          and evidence.mfa_challenge_id=activation.maker_challenge_id
        where activation.participant_id=$1 and activation.privacy_domain_id=$2
          and activation.envelope_id=$3 and activation.proposal_digest=$4
          and activation.expected_approved_version=3
          and activation.state='COMMITTED' and activation.row_version=4`,
      [scope.participantId, scope.privacyDomainId, stored.envelopeId, stored.digest],
    );
    if (activated.rows.length > 1) throw new AuthorityFenceError();
    if (activated.rows.length === 1)
      return { operationId: activated.rows[0]!.id, state: 'ACTIVE', version: '4' };
  }
  const selected = await client.query<{ id: string }>(
    `select receipt.operation_id::text as id from control.identity_envelope_proposal p
      join control.approval_request a on a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id
        and a.approval_request_id=p.submission_approval_id and a.subject_type='AUTHORITY_ENVELOPE'
        and a.subject_id=p.envelope_id and a.subject_digest=p.proposal_digest and a.subject_version=1
        and a.maker_principal_id=p.maker_principal_id and a.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
      join control.idempotency_record receipt on receipt.participant_id=p.participant_id and receipt.privacy_domain_id=p.privacy_domain_id
        and receipt.terminal_state='COMMITTED' and receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||a.approval_request_id::text
      where p.participant_id=$1 and p.privacy_domain_id=$2 and p.envelope_id=$3 and p.state=$4 and p.row_version=$5
        and (
          (p.state='SUBMITTED' and p.row_version=2 and a.state='OPEN'
            and receipt.operation_id=p.submission_operation_id and receipt.input_digest=p.submission_intent_digest
            and receipt.principal_id=p.maker_principal_id and receipt.action_intent_id='ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1')
          or (p.state='APPROVED' and p.row_version=3 and a.state='APPROVED'
            and receipt.action_intent_id='ACT-POLICY_APPROVE_REQUEST-V1'
            and exists(select 1 from control.approval_decision_record d join control.mfa_challenge challenge
              on challenge.participant_id=d.participant_id and challenge.mfa_challenge_id=d.mfa_challenge_id
              and challenge.principal_id=d.approver_principal_id and challenge.used_operation_id=receipt.operation_id
              where d.participant_id=p.participant_id and d.privacy_domain_id=p.privacy_domain_id
                and d.approval_request_id=a.approval_request_id and d.decision='APPROVE'
                and d.candidate_digest=p.proposal_digest and d.aggregate_version=1
                and d.approver_principal_id=receipt.principal_id and d.decision_digest=receipt.input_digest
                and d.mfa_challenge_id::text=p.submission_checker->>'stepUpChallengeId'
                and d.approver_principal_id::text=p.submission_checker#>>'{authority,principalId}'))
        )`,
    [scope.participantId, scope.privacyDomainId, stored.envelopeId, stored.state, stored.version],
  );
  if (selected.rowCount !== 1) throw new AuthorityFenceError();
  return {
    operationId: selected.rows[0]!.id,
    state: stored.state,
    version: stored.version,
  };
}
