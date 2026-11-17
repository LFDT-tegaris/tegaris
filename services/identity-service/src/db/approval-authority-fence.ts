import type { PoolClient } from 'pg';

import {
  AuthorityFenceError,
  type AuthorityFence,
  type BoundAuthority,
} from './authority-fence.js';
import { currentMutationCandidateSql } from './mutation-candidate-fence.js';
import { findEnvelopeProposal } from './identity-envelope-proposal.js';
import { workloadSigningHandoverAdmissionOperation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import {
  handoverAdmissionCandidateSchema,
  type HandoverAdmissionCandidate,
} from '../domain/workload-signing-handover-admission-candidate.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { handoverAdmissionAuthorityDependencies } from './workload-signing-handover-admission-reader.js';

interface ApprovalAuthorityScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
}

/** Fence the candidate's actual grants as well as permission to record a decision. */
export async function approvalDecisionAuthorityDependencies(
  client: PoolClient,
  scope: ApprovalAuthorityScope,
  approvalRequestId: string,
  checker: BoundAuthority,
): Promise<{
  readonly authorities: readonly BoundAuthority[];
  readonly rows: AuthorityFence;
  readonly handoverAdmission?: {
    readonly candidate: HandoverAdmissionCandidate;
    readonly maker: BoundAuthority;
  };
}> {
  const approval = await approvalAuthorityDependencies(client, scope, approvalRequestId, false);
  const subject = await client.query<{
    subjectType: string;
    subjectDigest: Buffer;
    subjectId: string;
  }>(
    `select subject_type as "subjectType",subject_digest as "subjectDigest",subject_id::text as "subjectId" from control.approval_request
      where participant_id=$1 and privacy_domain_id=$2 and approval_request_id=$3`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId],
  );
  if (subject.rowCount !== 1) throw new AuthorityFenceError();
  if (subject.rows[0]!.subjectType === 'POLICY_VERSION') return approval;
  if (subject.rows[0]!.subjectType === 'AUTHORITY_ENVELOPE') {
    const proposal = await findEnvelopeProposal(client, scope, subject.rows[0]!.subjectDigest);
    if (
      !proposal ||
      !proposal.submissionMaker ||
      !(
        (proposal.state === 'SUBMITTED' && proposal.version === '2') ||
        (proposal.state === 'APPROVED' && proposal.version === '3')
      ) ||
      proposal.envelopeId !== subject.rows[0]!.subjectId ||
      proposal.submissionApprovalId !== approvalRequestId ||
      proposal.makerPrincipalId === checker.principalId
    )
      throw new AuthorityFenceError();
    const proof = proposal.submissionMaker;
    const credential = await client.query(
      `select 1 from control.credential where participant_id=$1 and principal_id=$2
      and credential_id=$3 and credential_epoch=$4 and kind='WEBAUTHN' and state='ACTIVE'
      and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())`,
      [
        scope.participantId,
        proposal.makerPrincipalId,
        proof.signerCredentialId,
        proof.signerCredentialEpoch,
      ],
    );
    if (credential.rowCount !== 1) throw new AuthorityFenceError();
    const binding = proposal.issuerAuthority.binding;
    return {
      authorities: [
        ...approval.authorities,
        {
          ...proposal.issuerAuthority.durable.grant,
          sessionId: binding.sessionId,
          sessionEpoch: binding.sessionEpoch,
        },
        {
          ...checker,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceId: proposal.envelopeId,
        },
      ],
      rows: {
        ...approval.rows,
        credential: [...(approval.rows.credential ?? []), { id: proof.signerCredentialId }],
      },
    };
  }
  if (subject.rows[0]!.subjectType !== 'CONFIGURATION_CANDIDATE') throw new AuthorityFenceError();

  const candidate = await client.query<BoundAuthority>(
    `select c.maker_principal_id::text as "principalId",
            c.maker_session_id::text as "sessionId",c.maker_session_epoch::text as "sessionEpoch",
            c.maker_participant_epoch::text as "participantEpoch",
            c.maker_principal_epoch::text as "principalEpoch",
            c.maker_assignment_id::text as "assignmentId",
            c.maker_assignment_row_version::text as "assignmentRowVersion",
            c.maker_authority_envelope_id::text as "authorityEnvelopeId",
            c.maker_authority_epoch::text as "authorityEpoch",
            c.maker_delegation_epoch::text as "delegationEpoch",
            c.privacy_domain_id::text as "privacyDomainId",
            c.action_intent_id as "actionIntentId",c.resource_id::text as "resourceId",
            c.catalog_operation_id as "catalogOperationId"
       from control.approval_request r
       join control.mutation_candidate c on c.participant_id=r.participant_id
        and c.privacy_domain_id=r.privacy_domain_id and c.mutation_candidate_id=r.subject_id
        and c.action_intent_id=r.action_intent_id and c.candidate_digest=r.subject_digest
        and c.expected_revision=r.subject_version and c.maker_principal_id=r.maker_principal_id
       join control.assignment maker_assignment on maker_assignment.participant_id=c.participant_id
        and maker_assignment.assignment_id=c.maker_assignment_id
        and maker_assignment.principal_id=c.maker_principal_id
        and maker_assignment.authority_envelope_id=c.maker_authority_envelope_id
        and maker_assignment.maker_checker_required=true
       join control.authority_envelope maker_envelope on maker_envelope.participant_id=c.participant_id
        and maker_envelope.authority_envelope_id=c.maker_authority_envelope_id
        and (maker_envelope.principal_id=c.maker_principal_id
          or (maker_envelope.representation='TYPED_V1' and maker_envelope.principal_id is null))
        and maker_envelope.maker_checker_required=true
       join control.assignment checker_assignment on checker_assignment.participant_id=c.participant_id
        and checker_assignment.assignment_id=$5 and checker_assignment.principal_id=$4
        and checker_assignment.authority_envelope_id=$6 and checker_assignment.maker_checker_required=true
       join control.authority_envelope checker_envelope on checker_envelope.participant_id=c.participant_id
        and checker_envelope.authority_envelope_id=$6
        and (checker_envelope.principal_id=$4
          or (checker_envelope.representation='TYPED_V1' and checker_envelope.principal_id is null))
        and checker_envelope.maker_checker_required=true
      where r.participant_id=$1 and r.privacy_domain_id=$2 and r.approval_request_id=$3
        and c.maker_principal_id<>$4 and (r.checker_principal_id is null or r.checker_principal_id=$4)
        and c.expires_at>clock_timestamp() and ${currentMutationCandidateSql('c')}
        and c.state in ('APPROVAL_REQUESTED','APPROVED','CONSUMED')`,
    [
      scope.participantId,
      scope.privacyDomainId,
      approvalRequestId,
      checker.principalId,
      checker.assignmentId,
      checker.authorityEnvelopeId,
    ],
  );
  const maker = candidate.rows[0];
  if (candidate.rowCount !== 1 || maker === undefined) throw new AuthorityFenceError();
  let handoverAdmission:
    { candidate: HandoverAdmissionCandidate; maker: BoundAuthority } | undefined;
  let handoverRows: AuthorityFence = {};
  if (
    maker.actionIntentId === workloadSigningHandoverAdmissionOperation.actionIntentId ||
    maker.catalogOperationId === workloadSigningHandoverAdmissionOperation.catalogOperationId
  ) {
    if (
      maker.actionIntentId !== workloadSigningHandoverAdmissionOperation.actionIntentId ||
      maker.catalogOperationId !== workloadSigningHandoverAdmissionOperation.catalogOperationId
    )
      throw new AuthorityFenceError();
    const body = await client.query<{ document: unknown }>(
      `select candidate_document as document from control.mutation_candidate
       where participant_id=$1 and privacy_domain_id=$2 and mutation_candidate_id=$3`,
      [scope.participantId, scope.privacyDomainId, subject.rows[0]!.subjectId],
    );
    const parsed = handoverAdmissionCandidateSchema.safeParse(body.rows[0]?.document);
    if (
      body.rowCount !== 1 ||
      !parsed.success ||
      parsed.data.handoverId !== maker.resourceId ||
      parsed.data.makerPrincipalId !== maker.principalId ||
      canonicalAuthorizationDigest(parsed.data) !==
        'sha256:' + subject.rows[0]!.subjectDigest.toString('hex')
    )
      throw new AuthorityFenceError();
    handoverAdmission = { candidate: parsed.data, maker };
    handoverRows = handoverAdmissionAuthorityDependencies(parsed.data);
  }
  // The ordinary shared fence owns role/group/delegation, action/scope, session
  // and epoch checks. The selected approval grant must also permit this exact
  // business action; selecting a different grant would not match its decision.
  return {
    authorities: [
      ...approval.authorities,
      maker,
      {
        ...checker,
        actionIntentId: maker.actionIntentId,
        resourceId: maker.resourceId,
        catalogOperationId: maker.catalogOperationId,
      },
    ],
    rows: handoverAdmission
      ? {
          ...approval.rows,
          principal: [...(approval.rows.principal ?? []), ...(handoverRows.principal ?? [])],
          credential: [...(approval.rows.credential ?? []), ...(handoverRows.credential ?? [])],
        }
      : approval.rows,
    ...(handoverAdmission ? { handoverAdmission } : {}),
  };
}

/** Historical approvals without an exact persisted authority binding require fresh approval. */
export async function approvalAuthorityDependencies(
  client: PoolClient,
  scope: ApprovalAuthorityScope,
  approvalRequestId: string,
  decisionRequired: boolean,
): Promise<{ readonly authorities: readonly BoundAuthority[]; readonly rows: AuthorityFence }> {
  const approval = await client.query<{
    makerPrincipalId: string;
    makerAuthority: BoundAuthority | null;
  }>(
    `select maker_principal_id::text as "makerPrincipalId",maker_authority as "makerAuthority"
       from control.approval_request
      where participant_id=$1 and privacy_domain_id=$2 and approval_request_id=$3
        and expires_at>clock_timestamp()
        and (($4 and state='APPROVED') or (not $4 and state in ('OPEN','APPROVED')))`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId, decisionRequired],
  );
  const maker = approval.rows[0];
  if (
    approval.rowCount !== 1 ||
    maker?.makerAuthority === null ||
    maker === undefined ||
    maker.makerAuthority.principalId !== maker.makerPrincipalId ||
    maker.makerAuthority.privacyDomainId !== scope.privacyDomainId
  ) {
    throw new AuthorityFenceError();
  }
  const authorities: BoundAuthority[] = [maker.makerAuthority];
  if (!decisionRequired) return { authorities, rows: {} };

  const decisions = await client.query<BoundAuthority & { signerCredentialId: string }>(
    `select d.approver_principal_id::text as "principalId",
            d.approver_session_id::text as "sessionId",d.approver_session_epoch::text as "sessionEpoch",
            d.approver_participant_epoch::text as "participantEpoch",
            d.approver_principal_epoch::text as "principalEpoch",
            d.approver_assignment_id::text as "assignmentId",
            d.approver_assignment_row_version::text as "assignmentRowVersion",
            d.approver_authority_envelope_id::text as "authorityEnvelopeId",
            d.approver_envelope_epoch::text as "authorityEpoch",
            d.approver_delegation_epoch::text as "delegationEpoch",
            d.privacy_domain_id::text as "privacyDomainId",
            'ACT-POLICY_APPROVE_REQUEST-V1' as "actionIntentId",
            d.approval_request_id::text as "resourceId",
            d.signer_credential_id::text as "signerCredentialId"
       from control.approval_decision_record d
       join control.approval_request r on r.participant_id=d.participant_id
        and r.privacy_domain_id=d.privacy_domain_id and r.approval_request_id=d.approval_request_id
        and r.subject_digest=d.candidate_digest and r.subject_version=d.aggregate_version
        and r.maker_principal_id<>d.approver_principal_id
        and (r.checker_principal_id is null or r.checker_principal_id=d.approver_principal_id)
       join control.credential c on c.participant_id=d.participant_id
        and c.credential_id=d.signer_credential_id and c.principal_id=d.approver_principal_id
        and c.credential_epoch=d.signer_credential_epoch and c.state='ACTIVE' and c.kind='WEBAUTHN'
        and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())
      where d.participant_id=$1 and d.privacy_domain_id=$2 and d.approval_request_id=$3
        and d.decision='APPROVE' and d.approver_session_id is not null
        and d.approver_session_epoch is not null`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId],
  );
  const checker = decisions.rows[0];
  if (decisions.rowCount !== 1 || checker === undefined) throw new AuthorityFenceError();
  authorities.push(checker);
  return { authorities, rows: { credential: [{ id: checker.signerCredentialId }] } };
}

export async function stepUpCredentialDependencies(
  client: PoolClient,
  scope: ApprovalAuthorityScope & { readonly principalId: string; readonly actionIntentId: string },
  sessionId: string,
  inputDigest: Buffer,
): Promise<AuthorityFence> {
  const selected = await client.query<{ credentialId: string }>(
    `select distinct evidence.signer_credential_id::text as "credentialId"
       from control.mfa_challenge challenge
       join control.session proof_session on proof_session.participant_id=challenge.participant_id
        and proof_session.session_id=challenge.session_id and proof_session.principal_id=challenge.principal_id
       join control.mutation_evidence evidence on evidence.participant_id=challenge.participant_id
        and evidence.privacy_domain_id=$2 and evidence.principal_id=challenge.principal_id
        and evidence.mfa_challenge_id=challenge.mfa_challenge_id
        and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and evidence.aggregate_type='webauthn-verification'
      where challenge.participant_id=$1 and challenge.principal_id=$3 and challenge.session_id=$4
        and challenge.action_intent_id=$5 and challenge.resource_digest=$6
        and case when proof_session.step_up_mfa_challenge_id is null
          then challenge.consumed_at>=clock_timestamp()-interval '5 minutes'
          else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
            and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
          end
        and challenge.expires_at>clock_timestamp()
      limit 2`,
    [
      scope.participantId,
      scope.privacyDomainId,
      scope.principalId,
      sessionId,
      scope.actionIntentId,
      inputDigest,
    ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new AuthorityFenceError();
  return { credential: [{ id: row.credentialId }] };
}
