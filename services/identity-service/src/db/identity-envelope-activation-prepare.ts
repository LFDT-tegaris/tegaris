import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { EnvelopeActorEvidence } from '@openpc/security-kernel';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { AuthorityFenceError, type BoundAuthority } from './authority-fence.js';
import {
  approvalAuthorityDependencies,
  stepUpCredentialDependencies,
} from './approval-authority-fence.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { fenceInitialEnvelopeActivation } from './identity-envelope-activation-authority.js';
import { reserveInitialEnvelopeActivation } from './identity-envelope-activation-store.js';
import { readEnvelopeCreation } from './identity-envelope-readback.js';
import { captureEnvelopeActorEvidence } from './identity-envelope-step-up.js';
import { fenceIdentityEnvelopeSigningTrust } from './identity-envelope-signing-store.js';
import { consumeLiveStepUpRecord } from './live-step-up.js';
import { fenceMutationIntent, currentMutationCandidateSql } from './mutation-candidate-fence.js';
import type { EnvelopeGovernanceScope } from './identity-envelope-proposal.js';
import { verifyStoredStepUpEvidence } from './verified-step-up-evidence.js';

interface ActivationApproval {
  candidateId: string;
  candidateDigest: Buffer;
  approvalDigest: Buffer;
  checkerChallengeId: string;
  checkerCredentialId: string;
  checkerCredentialEpoch: string;
  checkerEvidence: Buffer;
  checkerCose: Buffer;
  checkerPublicKey: Buffer;
  submissionOperationId: string;
  submissionApprovalDigest: Buffer;
}

/** Existing authenticated ACTIVATE ingress supplies only its actor and request
 * identity. This transaction resolves the actual approved candidate, current
 * grants, fresh original proof, historical submission and selected signing key.
 * It commits PREPARED only; no provider I/O or ACTIVE/assignment effect occurs.
 * Recovery selects the existing journal instead of invoking this function again. */
export async function prepareInitialEnvelopeActivation(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  input: {
    principalId: string;
    sessionId: string;
    envelopeId: string;
    approvalRequestId: string;
    idempotencyKey: string;
    environmentId: string;
    callerWorkloadCredentialId: string;
  },
  verifier: IdentityRuntimeVerifier | undefined,
) {
  if (scope.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1')
    throw new AuthorityFenceError();
  const creation = await readEnvelopeCreation(client, scope, input.envelopeId);
  const dependencies = await approvalAuthorityDependencies(
    client,
    scope,
    input.approvalRequestId,
    true,
  );
  const approvalMaker = dependencies.authorities[0];
  const approvedChecker = dependencies.authorities[1];
  // Approval creation has its own action/resource binding. ACTIVATE must use
  // the immutable candidate's independently selected business authority.
  const candidateMaker = await client.query<BoundAuthority>(
    `select c.maker_principal_id::text as "principalId",c.maker_session_id::text as "sessionId",
      c.maker_session_epoch::text as "sessionEpoch",c.maker_participant_epoch::text as "participantEpoch",
      c.maker_principal_epoch::text as "principalEpoch",c.maker_assignment_id::text as "assignmentId",
      c.maker_assignment_row_version::text as "assignmentRowVersion",
      c.maker_authority_envelope_id::text as "authorityEnvelopeId",c.maker_authority_epoch::text as "authorityEpoch",
      c.maker_delegation_epoch::text as "delegationEpoch",c.privacy_domain_id::text as "privacyDomainId",
      c.action_intent_id as "actionIntentId",c.resource_id::text as "resourceId",c.catalog_operation_id as "catalogOperationId"
     from control.mutation_candidate c join control.approval_request a on a.participant_id=c.participant_id
       and a.privacy_domain_id=c.privacy_domain_id and a.subject_type='CONFIGURATION_CANDIDATE'
       and a.subject_id=c.mutation_candidate_id and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
     where c.participant_id=$1 and c.privacy_domain_id=$2 and a.approval_request_id=$3
       and c.state='APPROVED' and c.expires_at>clock_timestamp() and ${currentMutationCandidateSql('c')}`,
    [scope.participantId, scope.privacyDomainId, input.approvalRequestId],
  );
  const maker = candidateMaker.rows[0];
  if (
    dependencies.authorities.length !== 2 ||
    candidateMaker.rowCount !== 1 ||
    !approvalMaker ||
    !maker ||
    !approvedChecker ||
    maker.principalId !== input.principalId ||
    approvalMaker.principalId !== input.principalId ||
    maker.sessionId !== input.sessionId ||
    maker.actionIntentId !== scope.actionIntentId ||
    maker.catalogOperationId !== 'ID-OP-ENVELOPE-ACTIVATE' ||
    maker.resourceId !== input.envelopeId
  )
    throw new AuthorityFenceError();
  const checker = {
    ...approvedChecker,
    actionIntentId: scope.actionIntentId,
    resourceId: input.envelopeId,
    catalogOperationId: undefined,
  };
  const workloads = await client.query<{ credentialId: string; principalId: string }>(
    `select credential.credential_id::text as "credentialId",credential.principal_id::text as "principalId"
     from control.credential credential join control.principal principal
       on principal.participant_id=credential.participant_id and principal.principal_id=credential.principal_id
     where credential.participant_id=$1 and credential.kind='WORKLOAD_MTLS' and credential.state='ACTIVE'
       and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp()
       and principal.kind='WORKLOAD' and principal.state='ACTIVE'
       and (credential.credential_id=$4 or credential.credential_id in (
         select key.workload_credential_id from control.identity_envelope_signing_selection selection
         join control.business_signing_key key on key.participant_id=selection.participant_id
           and key.privacy_domain_id=selection.privacy_domain_id and key.signer_id=selection.signer_id
         where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3))`,
    [
      scope.participantId,
      scope.privacyDomainId,
      input.environmentId,
      input.callerWorkloadCredentialId,
    ],
  );
  if (!workloads.rows.some((row) => row.credentialId === input.callerWorkloadCredentialId))
    throw new AuthorityFenceError();
  const completeDependencies = {
    authorities: dependencies.authorities,
    rows: {
      ...dependencies.rows,
      principal: workloads.rows.map((row) => ({ id: row.principalId })),
      credential: [
        ...(dependencies.rows.credential ?? []),
        ...((
          await stepUpCredentialDependencies(
            client,
            { ...scope, principalId: input.principalId },
            input.sessionId,
            Buffer.from(
              canonicalAuthorizationDigest({ envelopeId: input.envelopeId }).slice(7),
              'hex',
            ),
          )
        ).credential ?? []),
        ...workloads.rows.map((row) => ({ id: row.credentialId })),
      ],
    },
  };
  const authorities = await fenceInitialEnvelopeActivation(
    client,
    scope,
    creation.stored,
    maker,
    checker,
    completeDependencies,
  );
  const current = await readEnvelopeCreation(client, scope, input.envelopeId, 'share');
  if (
    !current.stored.bytes.equals(creation.stored.bytes) ||
    current.stored.version !== '3' ||
    current.stored.state !== 'APPROVED' ||
    !current.stored.submissionApprovalId
  )
    throw new AuthorityFenceError();
  const selected = await client.query<ActivationApproval>(
    `select c.mutation_candidate_id::text as "candidateId",c.candidate_digest as "candidateDigest",
      decision.decision_digest as "approvalDigest",decision.mfa_challenge_id::text as "checkerChallengeId",
      decision.signer_credential_id::text as "checkerCredentialId",decision.signer_credential_epoch::text as "checkerCredentialEpoch",
      decision.evidence_cbor as "checkerEvidence",decision.cose_sign1 as "checkerCose",credential.public_key_spki_der as "checkerPublicKey",
      proposal.submission_operation_id::text as "submissionOperationId",submission.decision_digest as "submissionApprovalDigest"
    from control.mutation_candidate c
    join control.approval_request approval on approval.participant_id=c.participant_id and approval.privacy_domain_id=c.privacy_domain_id
      and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.subject_id=c.mutation_candidate_id
      and approval.subject_digest=c.candidate_digest and approval.subject_version=3 and approval.state='APPROVED'
      and approval.expires_at>clock_timestamp() and approval.maker_principal_id=c.maker_principal_id
    join control.approval_decision_record decision on decision.participant_id=c.participant_id and decision.privacy_domain_id=c.privacy_domain_id
      and decision.approval_request_id=approval.approval_request_id and decision.decision='APPROVE'
      and decision.candidate_digest=c.candidate_digest and decision.aggregate_version=3
      and decision.approver_principal_id=$7
    join control.credential credential on credential.participant_id=decision.participant_id
      and credential.principal_id=decision.approver_principal_id and credential.credential_id=decision.signer_credential_id
      and credential.credential_epoch=decision.signer_credential_epoch and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
      and credential.valid_from<=clock_timestamp() and (credential.valid_until is null or credential.valid_until>clock_timestamp())
    join control.identity_envelope_proposal proposal on proposal.participant_id=c.participant_id
      and proposal.privacy_domain_id=c.privacy_domain_id and proposal.envelope_id=c.resource_id
      and proposal.state='APPROVED' and proposal.row_version=3
    join control.approval_decision_record submission on submission.participant_id=proposal.participant_id
      and submission.privacy_domain_id=proposal.privacy_domain_id and submission.approval_request_id=proposal.submission_approval_id
      and submission.candidate_digest=proposal.proposal_digest and submission.aggregate_version=1 and submission.decision='APPROVE'
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3 and approval.approval_request_id=$4
      and c.maker_principal_id=$5 and c.maker_session_id=$6 and c.state='APPROVED' and c.expected_revision=3
      and c.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' and c.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'
      and c.candidate_document=jsonb_build_object('envelopeId',$3::uuid::text)
      and c.expires_at>clock_timestamp() and ${currentMutationCandidateSql('c')}`,
    [
      scope.participantId,
      scope.privacyDomainId,
      input.envelopeId,
      input.approvalRequestId,
      input.principalId,
      input.sessionId,
      checker.principalId,
    ],
  );
  const approval = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !approval ||
    canonicalAuthorizationDigest({ envelopeId: input.envelopeId }) !==
      `sha256:${approval.candidateDigest.toString('hex')}` ||
    !(await verifyStoredStepUpEvidence(
      client,
      {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        principalId: checker.principalId,
        credentialId: approval.checkerCredentialId,
        approvalRequestId: input.approvalRequestId,
        credentialPublicKey: approval.checkerPublicKey,
        evidenceCbor: approval.checkerEvidence,
        coseSign1: approval.checkerCose,
      },
      verifier,
    ))
  )
    throw new AuthorityFenceError();
  const stepUpBinding = {
    ...scope,
    principalId: maker.principalId,
    sessionId: maker.sessionId,
    participantEpoch: maker.participantEpoch,
    principalEpoch: maker.principalEpoch,
    resourceDigest: approval.candidateDigest,
    resourceId: input.envelopeId,
  };
  const makerProof = await captureEnvelopeActorEvidence(
    client,
    stepUpBinding,
    authorities.maker.binding,
    verifier,
  );
  const checkerEvidence: EnvelopeActorEvidence = {
    authority: authorities.checker.binding,
    stepUpChallengeId: approval.checkerChallengeId,
    stepUpEvidenceDigest: `sha256:${createHash('sha256').update(approval.checkerEvidence).digest('hex')}`,
    signerCredentialId: approval.checkerCredentialId,
    signerCredentialEpoch: approval.checkerCredentialEpoch,
  };
  const signing = await fenceIdentityEnvelopeSigningTrust(client, {
    ...scope,
    environmentId: input.environmentId,
  });
  await fenceMutationIntent(client, {
    ...scope,
    principalId: input.principalId,
    catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
    idempotencyKey: input.idempotencyKey,
  });
  const receipt = await client.query<{ id: string }>(
    `insert into control.idempotency_record
      (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
       operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at)
      values($1,$2,$3,$4,'ID-OP-ENVELOPE-ACTIVATE',$5,$6,$7,$8,3,clock_timestamp()+interval '24 hours')
      returning idempotency_record_id::text as id`,
    [
      scope.participantId,
      scope.privacyDomainId,
      input.principalId,
      scope.actionIntentId,
      input.idempotencyKey,
      scope.operationId,
      approval.candidateDigest,
      makerProof.record.assertionBindingDigest,
    ],
  );
  if (receipt.rowCount !== 1) throw new AuthorityFenceError();
  await consumeLiveStepUpRecord(client, stepUpBinding, makerProof.record);
  return reserveInitialEnvelopeActivation(
    client,
    scope,
    {
      proposal: current.stored,
      submission: {
        operationId: approval.submissionOperationId,
        approvalRequestId: current.stored.submissionApprovalId,
        approvalDigest: `sha256:${approval.submissionApprovalDigest.toString('hex')}`,
      },
      activation: {
        operationId: scope.operationId,
        candidateId: approval.candidateId,
        candidateDigest: `sha256:${approval.candidateDigest.toString('hex')}`,
        approvalRequestId: input.approvalRequestId,
        approvalDigest: `sha256:${approval.approvalDigest.toString('hex')}`,
        expectedApprovedVersion: '3',
        maker: makerProof.evidence,
        checker: checkerEvidence,
      },
      idempotency: {
        recordId: receipt.rows[0]!.id,
        key: input.idempotencyKey,
        principalId: input.principalId,
        assertionBindingDigest: `sha256:${makerProof.record.assertionBindingDigest.toString('hex')}`,
      },
      attemptId: localOperationId(),
      callerWorkloadCredentialId: input.callerWorkloadCredentialId,
      trust: signing.trust,
      recordedAtNs: signing.recordedAtNs,
    },
    authorities,
  );
}
