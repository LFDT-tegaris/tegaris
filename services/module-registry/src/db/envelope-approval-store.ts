import type { PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
} from '../../../identity-service/src/db/authority-fence.js';
import { stepUpCredentialDependencies } from '../../../identity-service/src/db/approval-authority-fence.js';
import {
  findEnvelopeProposal,
  fenceInitialEnvelopeProposal,
  inEnvelopeParticipantScope,
} from '../../../identity-service/src/db/identity-envelope-proposal.js';
import { captureEnvelopeActorEvidence } from '../../../identity-service/src/db/identity-envelope-step-up.js';
import {
  consumeLiveStepUpRecord,
  type LiveStepUpBinding,
} from '../../../identity-service/src/db/live-step-up.js';
import { approvalCreateIntent } from '../public-approval-contract.js';
import type { ApprovalRow, PublicApprovalScope } from './public-approval-store.js';
import { approvalCandidateResponseSchema } from '../approval-candidate-contract.js';
import { projectEnvelopeApprovalCandidate } from '../envelope-candidate-contract.js';
import { ContractError } from '../domain/errors.js';

/** The enclosing public READ owner has already fenced the current reader.
 * Historical issuer/step-up expiry does not erase this scoped review record. */
export async function readEnvelopeApprovalCandidate(
  client: PoolClient,
  scope: PublicApprovalScope,
  approval: ApprovalRow,
) {
  const proposal = await findEnvelopeProposal(client, scope, approval.subjectDigest);
  if (
    !proposal ||
    approval.subjectType !== 'AUTHORITY_ENVELOPE' ||
    approval.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
    approval.subjectVersion !== '1' ||
    proposal.envelopeId !== approval.subjectId ||
    proposal.makerPrincipalId !== approval.makerPrincipalId ||
    proposal.submissionApprovalId !== approval.approvalRequestId ||
    !(
      (proposal.state === 'SUBMITTED' && proposal.version === '2' && approval.state === 'OPEN') ||
      (proposal.state === 'APPROVED' && proposal.version === '3' && approval.state === 'APPROVED')
    )
  )
    throw new ContractError('PC-POLICY-2001');
  const operation = await client.query<{ id: string }>(
    `select receipt.operation_id::text as id from control.identity_envelope_proposal p
      join control.idempotency_record receipt on receipt.participant_id=p.participant_id
      and receipt.privacy_domain_id=p.privacy_domain_id and receipt.operation_id=p.submission_operation_id
      and receipt.principal_id=p.maker_principal_id and receipt.input_digest=p.submission_intent_digest
      and receipt.action_intent_id='ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' and receipt.terminal_state='COMMITTED'
      and receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||p.submission_approval_id::text
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.envelope_id=$3 and p.submission_approval_id=$4`,
    [scope.participantId, scope.privacyDomainId, proposal.envelopeId, approval.approvalRequestId],
  );
  if (operation.rowCount !== 1) throw new ContractError('PC-POLICY-2001');
  const candidateDigest = `sha256:${proposal.digest.toString('hex')}`;
  return approvalCandidateResponseSchema.parse({
    approvalRequestId: `urn:openpc:resource:${approval.approvalRequestId}`,
    candidateDigest,
    actionIntentId: approval.actionIntentId,
    resourceRef: `urn:openpc:resource:${proposal.envelopeId}`,
    expectedRevision: approval.subjectVersion,
    state:
      proposal.state === 'APPROVED'
        ? 'APPROVED'
        : Date.parse(approval.expiresAt) <= Date.now()
          ? 'EXPIRED'
          : 'APPROVAL_REQUESTED',
    expiresAt: new Date(approval.expiresAt).toISOString(),
    operationRef: `urn:openpc:operation:${operation.rows[0]!.id}`,
    approvalUsable: false,
    canRequestResume: false,
    runtimePermission: 'NONE',
    deploymentIntent: null,
    candidate: projectEnvelopeApprovalCandidate(proposal.bytes, candidateDigest),
    redactedFields: [],
  });
}

/** Called only after the public owner resolved exactly one internal subject.
 * No caller-provided subject type or step-up object enters this path. */
export async function prepareEnvelopeSubmission(
  client: PoolClient,
  scope: PublicApprovalScope,
  request: unknown,
  verifier: IdentityRuntimeVerifier | undefined,
) {
  const intent = approvalCreateIntent(request);
  if (scope.actionIntentId !== intent.actionIntentId || scope.principalId !== intent.resourceId)
    throw new AuthorityFenceError();
  const proposal = await findEnvelopeProposal(
    client,
    scope,
    Buffer.from(intent.request.candidateDigest.slice(7), 'hex'),
  );
  if (
    !proposal ||
    proposal.state !== 'DRAFT' ||
    proposal.version !== '1' ||
    proposal.makerPrincipalId !== scope.principalId
  )
    throw new AuthorityFenceError();
  const business = {
    ...scope.authority,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceId: proposal.envelopeId,
    catalogOperationId: undefined,
  };
  const stepUpBinding = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    principalId: scope.principalId,
    operationId: scope.operationId,
    actionIntentId: scope.actionIntentId,
    sessionId: scope.authority.sessionId,
    participantEpoch: scope.authority.participantEpoch,
    principalEpoch: scope.authority.principalEpoch,
    resourceDigest: Buffer.from(intent.intentDigest.slice(7), 'hex'),
    resourceId: proposal.envelopeId,
  };
  const credentials = await stepUpCredentialDependencies(
    client,
    scope,
    scope.authority.sessionId,
    stepUpBinding.resourceDigest,
  );
  await fenceBoundAuthorities(
    client,
    scope.participantId,
    [scope.authority, business],
    credentials,
  );
  const current = await fenceInitialEnvelopeProposal(client, scope, proposal, business, true);
  const proof = await captureEnvelopeActorEvidence(
    client,
    stepUpBinding,
    current.binding,
    verifier,
  );
  const locked = await findEnvelopeProposal(client, scope, proposal.digest, true);
  if (
    !locked ||
    locked.state !== 'DRAFT' ||
    locked.version !== '1' ||
    !locked.bytes.equals(proposal.bytes)
  )
    throw new AuthorityFenceError();
  return { proposal: locked, proof, stepUpBinding };
}

export async function commitEnvelopeSubmission(
  client: PoolClient,
  scope: PublicApprovalScope,
  prepared: Awaited<ReturnType<typeof prepareEnvelopeSubmission>>,
  approvalRequestId: string,
) {
  const { proposal, proof, stepUpBinding } = prepared;
  const updated = await client.query(
    `update control.identity_envelope_proposal
    set state='SUBMITTED',row_version=2,submission_operation_id=$4,submission_intent_digest=$5,
      submission_approval_id=$6,submission_maker=$7
    where participant_id=$1 and privacy_domain_id=$2 and envelope_id=$3 and state='DRAFT' and row_version=1`,
    [
      scope.participantId,
      scope.privacyDomainId,
      proposal.envelopeId,
      scope.operationId,
      stepUpBinding.resourceDigest,
      approvalRequestId,
      proof.evidence,
    ],
  );
  if (updated.rowCount !== 1) throw new AuthorityFenceError();
  await inEnvelopeParticipantScope(client, scope, proposal.targetParticipantId, async () => {
    const target = await client.query(
      `update control.authority_envelope set state='SUBMITTED',row_version=2,
      last_mutation_operation_id=$5,updated_at=clock_timestamp()
      where participant_id=$1 and authority_envelope_id=$2 and issuer_participant_id=$3 and issuer_privacy_domain_id=$4
        and representation='TYPED_V1' and state='DRAFT' and row_version=1 and semantic_digest=$6`,
      [
        proposal.targetParticipantId,
        proposal.envelopeId,
        scope.participantId,
        scope.privacyDomainId,
        scope.operationId,
        proposal.digest,
      ],
    );
    if (target.rowCount !== 1) throw new AuthorityFenceError();
  });
  await consumeLiveStepUpRecord(client, stepUpBinding, proof.record);
  const sequence = await client.query<{ sequence: string }>(
    `insert into control.outbox_aggregate_head
    (participant_id,aggregate_type,aggregate_id,last_sequence) values($1,'authority-envelope',$2,1)
    on conflict(participant_id,aggregate_type,aggregate_id) do update
      set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
    returning last_sequence::text as sequence`,
    [scope.participantId, proposal.envelopeId],
  );
  if (sequence.rowCount !== 1) throw new AuthorityFenceError();
  await client.query(
    `insert into control.outbox_event
    (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,
     payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
    values($1,$2,uuidv7(),'openpc.identity.authority-envelope.submitted.v1','authority-envelope',$3,$4,$5,$6,$7,$8,clock_timestamp())`,
    [
      scope.participantId,
      scope.privacyDomainId,
      proposal.envelopeId,
      sequence.rows[0]!.sequence,
      proof.record.evidenceCbor,
      proof.record.evidenceDigest,
      proof.record.coseSign1,
      proof.record.assertionBindingDigest,
    ],
  );
}

export async function prepareEnvelopeDecision(
  client: PoolClient,
  scope: PublicApprovalScope,
  approvalRequestId: string,
  proposalDigest: Buffer,
  stepUpBinding: LiveStepUpBinding,
  verifier: IdentityRuntimeVerifier | undefined,
) {
  const proposal = await findEnvelopeProposal(client, scope, proposalDigest);
  if (
    !proposal ||
    !proposal.submissionMaker ||
    proposal.state !== 'SUBMITTED' ||
    proposal.version !== '2' ||
    proposal.submissionApprovalId !== approvalRequestId ||
    proposal.makerPrincipalId === scope.principalId
  )
    throw new AuthorityFenceError();
  const business = {
    ...scope.authority,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceId: proposal.envelopeId,
  };
  const current = await fenceInitialEnvelopeProposal(client, scope, proposal, business, false);
  const proof = await captureEnvelopeActorEvidence(
    client,
    stepUpBinding,
    current.binding,
    verifier,
  );
  if (proof.evidence.stepUpChallengeId === proposal.submissionMaker.stepUpChallengeId)
    throw new AuthorityFenceError();
  const locked = await findEnvelopeProposal(client, scope, proposalDigest, true);
  if (
    !locked ||
    locked.state !== 'SUBMITTED' ||
    locked.version !== '2' ||
    !locked.bytes.equals(proposal.bytes)
  )
    throw new AuthorityFenceError();
  return { proposal: locked, proof, checkerAuthority: current };
}

/** The public owner inserts the exact independent decision and consumes its
 * fresh step-up once in this same transaction. This owns the envelope effect. */
export async function commitEnvelopeDecision(
  client: PoolClient,
  scope: PublicApprovalScope,
  prepared: Awaited<ReturnType<typeof prepareEnvelopeDecision>>,
) {
  const { proposal, proof, checkerAuthority } = prepared;
  const changed = await client.query(
    `update control.identity_envelope_proposal
    set state='APPROVED',row_version=3,submission_checker=$4,submission_checker_authority=$5
    where participant_id=$1 and privacy_domain_id=$2 and envelope_id=$3 and state='SUBMITTED' and row_version=2`,
    [
      scope.participantId,
      scope.privacyDomainId,
      proposal.envelopeId,
      proof.evidence,
      checkerAuthority,
    ],
  );
  if (changed.rowCount !== 1) throw new AuthorityFenceError();
  await inEnvelopeParticipantScope(client, scope, proposal.targetParticipantId, async () => {
    const target = await client.query(
      `update control.authority_envelope set state='APPROVED',row_version=3,
      checker_principal_id=$5,last_mutation_operation_id=$6,updated_at=clock_timestamp()
      where participant_id=$1 and authority_envelope_id=$2 and issuer_participant_id=$3 and issuer_privacy_domain_id=$4
        and representation='TYPED_V1' and state='SUBMITTED' and row_version=2 and semantic_digest=$7`,
      [
        proposal.targetParticipantId,
        proposal.envelopeId,
        scope.participantId,
        scope.privacyDomainId,
        scope.principalId,
        scope.operationId,
        proposal.digest,
      ],
    );
    if (target.rowCount !== 1) throw new AuthorityFenceError();
  });
  const sequence = await client.query<{ sequence: string }>(
    `insert into control.outbox_aggregate_head
    (participant_id,aggregate_type,aggregate_id,last_sequence) values($1,'authority-envelope',$2,1)
    on conflict(participant_id,aggregate_type,aggregate_id) do update
      set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
    returning last_sequence::text as sequence`,
    [scope.participantId, proposal.envelopeId],
  );
  if (sequence.rowCount !== 1) throw new AuthorityFenceError();
  await client.query(
    `insert into control.outbox_event
    (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,
     payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
    values($1,$2,uuidv7(),'openpc.identity.authority-envelope.approved.v1','authority-envelope',$3,$4,$5,$6,$7,$8,clock_timestamp())`,
    [
      scope.participantId,
      scope.privacyDomainId,
      proposal.envelopeId,
      sequence.rows[0]!.sequence,
      proof.record.evidenceCbor,
      proof.record.evidenceDigest,
      proof.record.coseSign1,
      proof.record.assertionBindingDigest,
    ],
  );
}
