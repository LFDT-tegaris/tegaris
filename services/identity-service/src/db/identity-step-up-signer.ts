import type { PoolClient } from 'pg';
import { IdentityKernelError } from '../domain/identity-errors.js';
import { identityGovernanceOperations } from '../contracts/principal-operations.js';
import { currentMutationCandidateSql } from './mutation-candidate-fence.js';

export interface IdentityStepUpSignerInput {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly actionIntentId: string;
  readonly candidateDigest: Buffer;
  readonly assertionBindingDigest: Buffer | undefined;
}

/** An exact authenticated request tuple, never a caller-supplied replay grant. */
export interface CommittedIdentityStepUpInput extends IdentityStepUpSignerInput {
  readonly idempotencyKey: string;
  readonly catalogOperationId: string;
  readonly resourceId: string;
  readonly aggregateType?: string;
  readonly expectedRevision: string;
  readonly approvalRequestId: string;
  readonly checkerPrincipalId: string;
  readonly checkerCredentialId: string;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
  readonly operationId?: string;
}

export interface CommittedIdentityStepUp {
  readonly currentAssurance: {
    readonly sourceId: string | null;
    readonly verifiedAt: Date;
    readonly credentialId: string | null;
    readonly credentialEpoch: string | null;
  };
  readonly operationId: string;
  readonly result: unknown;
  readonly resultDigest: Buffer;
  readonly resultAggregateVersion: string;
  readonly expectedAggregateVersion: string;
  readonly mfaChallengeId: string;
  readonly assertionBindingDigest: Buffer;
  readonly credentialId: string;
  readonly credentialPublicKey: Buffer;
  readonly credentialPublicKeyDigest: Buffer;
  readonly verificationEvidenceCbor: Buffer;
  readonly verificationEvidenceDigest: Buffer;
  readonly verificationCoseSign1: Buffer;
  readonly verificationCandidateDigest: Buffer;
  readonly verificationOccurredAt: Date;
  readonly verificationSessionId: string;
  readonly boundParticipantEpoch: string;
  readonly boundPrincipalEpoch: string;
  readonly boundAuthorityEnvelopeId: string;
  readonly boundEnvelopeEpoch: string;
  readonly boundAssignmentId: string;
}

/** Readback admission only. The caller still fences current authority and
 * authenticates both signatures before returning the original result. */
export async function selectCommittedIdentityStepUp(
  client: PoolClient,
  input: CommittedIdentityStepUpInput,
  lock = false,
): Promise<CommittedIdentityStepUp | undefined> {
  const contract = identityGovernanceOperations.find(
    (entry) => entry.id === input.catalogOperationId,
  );
  if (
    !contract?.makerCheckerRequired ||
    !contract.webauthnStepUpRequired ||
    contract.actionIntentId !== input.actionIntentId
  )
    return undefined;
  const records = await client.query<{
    operation_id: string;
    input_digest: Buffer;
    expected_revision: string;
    assertion_digest: Buffer | null;
    result_digest: Buffer | null;
    result_payload: unknown;
    result_revision: string | null;
    terminal_state: string | null;
    unexpired: boolean;
  }>(
    `select record.operation_id,record.input_digest,record.expected_aggregate_version::text expected_revision,
       record.webauthn_assertion_binding_digest assertion_digest,record.result_digest,record.result_payload,
       record.result_aggregate_version::text result_revision,record.terminal_state,record.expires_at>clock_timestamp() unexpired
     from control.idempotency_record record
     join control.mutation_candidate consumed on consumed.participant_id=record.participant_id
       and consumed.privacy_domain_id=record.privacy_domain_id and consumed.maker_principal_id=record.principal_id
       and consumed.action_intent_id=record.action_intent_id and consumed.catalog_operation_id=record.catalog_operation_id
       and consumed.idempotency_key=record.idempotency_key and consumed.state='CONSUMED'
       and consumed.consumed_operation_id=record.operation_id and consumed.resource_id=$7
       and consumed.candidate_digest=$8 and consumed.expected_revision=$9::bigint
     join control.approval_request approved on approved.participant_id=consumed.participant_id
       and approved.privacy_domain_id=consumed.privacy_domain_id and approved.subject_id=consumed.mutation_candidate_id
       and approved.subject_type='CONFIGURATION_CANDIDATE' and approved.approval_request_id=$10
     where record.participant_id=$1 and record.privacy_domain_id=$2
       and record.principal_id=$3 and record.action_intent_id=$4 and record.catalog_operation_id=$5 and record.idempotency_key=$6
     ${lock ? 'for update of record' : ''}`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.actionIntentId,
      input.catalogOperationId,
      input.idempotencyKey,
      input.resourceId,
      input.candidateDigest,
      input.expectedRevision,
      input.approvalRequestId,
    ],
  );
  if (records.rowCount === 0) return undefined;
  const record = records.rows[0];
  if (
    records.rowCount !== 1 ||
    !record ||
    !record.unexpired ||
    !record.input_digest.equals(input.candidateDigest) ||
    record.expected_revision !== input.expectedRevision ||
    (input.operationId !== undefined && record.operation_id !== input.operationId) ||
    (input.assertionBindingDigest !== undefined &&
      !record.assertion_digest?.equals(input.assertionBindingDigest))
  )
    throw new IdentityKernelError('PC-IDENTITY-1009');
  if (record.terminal_state !== 'COMMITTED') return undefined;
  if (
    !record.assertion_digest ||
    record.assertion_digest.length !== 32 ||
    !record.result_digest ||
    record.result_revision === null
  )
    throw new IdentityKernelError('PC-IDENTITY-1009');
  const assurance = await client.query<{
    fresh: boolean | null;
    source_id: string | null;
    verified_at: Date | null;
    credential_id: string | null;
    credential_epoch: string | null;
  }>(
    `select session.step_up_mfa_challenge_id source_id,session.step_up_verified_at verified_at,
       credential.credential_id,credential.credential_epoch::text,
       case when session.step_up_mfa_challenge_id is null
       then session.step_up_verified_at>clock_timestamp()-interval '5 minutes'
       else openpc.session_step_up_valid_until(session.participant_id,session.session_id,session.principal_id)>clock_timestamp()
       end fresh from control.session session
       left join control.mfa_challenge source on source.participant_id=session.participant_id
         and source.principal_id=session.principal_id and source.session_id=session.session_id
         and source.mfa_challenge_id=session.step_up_mfa_challenge_id
         and source.consumed_at=session.step_up_verified_at
       left join control.credential credential on credential.participant_id=source.participant_id
         and credential.principal_id=source.principal_id and credential.credential_id=source.signer_credential_id
         and credential.credential_epoch=source.signer_credential_epoch and credential.kind='WEBAUTHN'
         and credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
         and (credential.valid_until is null or credential.valid_until>clock_timestamp())
       where session.participant_id=$1 and session.session_id=$2 and session.principal_id=$3
       and session.state='ACTIVE' and session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp()`,
    [input.participantId, input.sessionId, input.principalId],
  );
  const current = assurance.rows[0];
  if (
    assurance.rowCount !== 1 ||
    current?.fresh !== true ||
    !current.verified_at ||
    (current.source_id !== null && (!current.credential_id || !current.credential_epoch))
  )
    throw new IdentityKernelError('PC-AUTH-0005');
  const evidence = await client.query<
    Omit<
      CommittedIdentityStepUp,
      | 'currentAssurance'
      | 'operationId'
      | 'result'
      | 'resultDigest'
      | 'resultAggregateVersion'
      | 'expectedAggregateVersion'
    >
  >(
    `select challenge.mfa_challenge_id as "mfaChallengeId",
       verification.webauthn_assertion_binding_digest as "assertionBindingDigest",
       credential.credential_id as "credentialId",credential.public_key_spki_der as "credentialPublicKey",
       credential.public_key_digest as "credentialPublicKeyDigest",
       verification.evidence_cbor as "verificationEvidenceCbor",
       verification.evidence_digest as "verificationEvidenceDigest",
       verification.cose_sign1 as "verificationCoseSign1",
       verification.candidate_digest as "verificationCandidateDigest",
       verification.occurred_at as "verificationOccurredAt",challenge.session_id as "verificationSessionId",
       business.bound_participant_epoch::text as "boundParticipantEpoch",
       business.bound_principal_epoch::text as "boundPrincipalEpoch",
       business.bound_authority_envelope_id as "boundAuthorityEnvelopeId",
       business.bound_envelope_epoch::text as "boundEnvelopeEpoch",business.bound_assignment_id as "boundAssignmentId"
     from control.mutation_evidence business
     join control.approval_request approval on approval.participant_id=business.participant_id
       and approval.privacy_domain_id=business.privacy_domain_id
       and approval.approval_request_id=business.approval_request_id
       and approval.action_intent_id=business.action_intent_id and approval.subject_type='CONFIGURATION_CANDIDATE'
       and approval.subject_digest=business.candidate_digest and approval.subject_version=business.aggregate_version
       and approval.maker_principal_id=business.principal_id and approval.state='APPROVED'
       and approval.expires_at>clock_timestamp()
     join control.mutation_candidate candidate on candidate.participant_id=approval.participant_id
       and candidate.privacy_domain_id=approval.privacy_domain_id
       and candidate.mutation_candidate_id=approval.subject_id
       and candidate.action_intent_id=business.action_intent_id and candidate.catalog_operation_id=business.catalog_operation_id
       and candidate.resource_id=business.aggregate_id and candidate.candidate_digest=business.candidate_digest
       and candidate.expected_revision=business.aggregate_version and candidate.maker_principal_id=business.principal_id
       and candidate.idempotency_key=$16 and candidate.state='CONSUMED'
       and candidate.consumed_operation_id=business.operation_id and candidate.expires_at>clock_timestamp()
       and ${currentMutationCandidateSql('candidate')}
     join control.outbox_event business_event on business_event.participant_id=business.participant_id
       and business_event.privacy_domain_id=business.privacy_domain_id
       and business_event.aggregate_type=business.aggregate_type and business_event.aggregate_id=business.aggregate_id
       and business_event.event_type='openpc.identity.'||business.aggregate_type||'.mutation.committed.v1'
       and business_event.payload_cbor=business.evidence_cbor and business_event.payload_digest=business.evidence_digest
       and business_event.cose_sign1=business.cose_sign1
       and business_event.webauthn_assertion_binding_digest=business.webauthn_assertion_binding_digest
     join control.mfa_challenge challenge on challenge.participant_id=business.participant_id
       and challenge.principal_id=business.principal_id and challenge.mfa_challenge_id=business.mfa_challenge_id
       and challenge.session_id=$4 and challenge.action_intent_id=business.action_intent_id
       and challenge.resource_digest=business.candidate_digest and challenge.consumed_at is not null
       and challenge.used_at is not null and challenge.used_operation_id=business.operation_id
     join control.session assurance on assurance.participant_id=challenge.participant_id
       and assurance.principal_id=challenge.principal_id and assurance.session_id=challenge.session_id
       and case when assurance.step_up_mfa_challenge_id is null
         then assurance.step_up_verified_at>clock_timestamp()-interval '5 minutes'
         else openpc.session_step_up_valid_until(assurance.participant_id,assurance.session_id,assurance.principal_id)>clock_timestamp()
         end
     join control.mutation_evidence verification on verification.participant_id=challenge.participant_id
       and verification.privacy_domain_id=business.privacy_domain_id and verification.principal_id=challenge.principal_id
       and verification.mfa_challenge_id=challenge.mfa_challenge_id
       and verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
       and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
       and verification.aggregate_type='webauthn-verification' and verification.aggregate_id=challenge.session_id
       and verification.webauthn_assertion_binding_digest=business.webauthn_assertion_binding_digest
       and verification.evidence_digest=sha256(verification.evidence_cbor)
       and verification.occurred_at>=challenge.consumed_at and verification.occurred_at<challenge.expires_at
       and challenge.used_at>=verification.occurred_at and challenge.used_at<=business.occurred_at
       and verification.occurred_at<=business.occurred_at
     join control.idempotency_record verification_record on verification_record.participant_id=verification.participant_id
       and verification_record.privacy_domain_id=verification.privacy_domain_id
       and verification_record.principal_id=verification.principal_id and verification_record.operation_id=verification.operation_id
       and verification_record.action_intent_id=verification.action_intent_id
       and verification_record.catalog_operation_id=verification.catalog_operation_id
       and verification_record.input_digest=verification.candidate_digest
       and verification_record.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
       and verification_record.terminal_state='COMMITTED'
     join control.outbox_event verification_event on verification_event.participant_id=verification.participant_id
       and verification_event.privacy_domain_id=verification.privacy_domain_id
       and verification_event.aggregate_type=verification.aggregate_type and verification_event.aggregate_id=verification.aggregate_id
       and verification_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
       and verification_event.payload_cbor=verification.evidence_cbor and verification_event.payload_digest=verification.evidence_digest
       and verification_event.cose_sign1=verification.cose_sign1
       and verification_event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
     join control.credential credential on credential.participant_id=verification.participant_id
       and credential.principal_id=verification.principal_id and credential.credential_id=verification.signer_credential_id
       and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
       and credential.valid_from<=clock_timestamp() and (credential.valid_until is null or credential.valid_until>clock_timestamp())
       and challenge.signer_credential_id=credential.credential_id
       and challenge.signer_credential_epoch=credential.credential_epoch
     where business.participant_id=$1 and business.privacy_domain_id=$2 and business.principal_id=$3
       and business.action_intent_id=$5 and business.candidate_digest=$6
       and business.webauthn_assertion_binding_digest=$7 and business.catalog_operation_id=$8
       and business.aggregate_id=$9 and ($10::text is null or business.aggregate_type=$10)
       and business.aggregate_version=$11::bigint and business.operation_id=$12
       and business.approval_request_id=$13 and business.checker_principal_id=$14
       and business.signer_credential_id=$15 and business.evidence_cbor=$17
       and business.evidence_digest=$18 and business.cose_sign1=$19
       and business.evidence_digest=sha256(business.evidence_cbor)`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.sessionId,
      input.actionIntentId,
      input.candidateDigest,
      record.assertion_digest,
      input.catalogOperationId,
      input.resourceId,
      input.aggregateType ?? null,
      input.expectedRevision,
      record.operation_id,
      input.approvalRequestId,
      input.checkerPrincipalId,
      input.checkerCredentialId,
      input.idempotencyKey,
      input.evidenceCbor,
      input.evidenceDigest,
      input.coseSign1,
    ],
  );
  if (evidence.rowCount !== 1 || !evidence.rows[0])
    throw new IdentityKernelError('PC-IDENTITY-1005');
  return {
    ...evidence.rows[0],
    currentAssurance: {
      sourceId: current.source_id,
      verifiedAt: current.verified_at,
      credentialId: current.credential_id,
      credentialEpoch: current.credential_epoch,
    },
    operationId: record.operation_id,
    result: record.result_payload,
    resultDigest: record.result_digest,
    resultAggregateVersion: record.result_revision,
    expectedAggregateVersion: record.expected_revision,
  };
}

/** Resolve the maker's verified assertion independently of the checker's approval signature. */
export async function identityStepUpSigner(
  client: PoolClient,
  input: IdentityStepUpSignerInput & {
    readonly committedHistory?: CommittedIdentityStepUpInput & { readonly operationId: string };
  },
): Promise<string> {
  if (input.committedHistory !== undefined) {
    const history = input.committedHistory;
    if (
      history.participantId !== input.participantId ||
      history.privacyDomainId !== input.privacyDomainId ||
      history.principalId !== input.principalId ||
      history.sessionId !== input.sessionId ||
      history.actionIntentId !== input.actionIntentId ||
      !history.candidateDigest.equals(input.candidateDigest) ||
      !input.assertionBindingDigest ||
      !history.assertionBindingDigest?.equals(input.assertionBindingDigest)
    )
      throw new IdentityKernelError('PC-AUTH-0005');
    const original = await selectCommittedIdentityStepUp(client, history);
    if (!original || original.operationId !== history.operationId)
      throw new IdentityKernelError('PC-AUTH-0005');
    return original.credentialId;
  }
  const result = await client.query<{ credential_id: string }>(
    `select credential.credential_id from control.mfa_challenge challenge
     join control.session proof_session on proof_session.participant_id=challenge.participant_id
       and proof_session.session_id=challenge.session_id and proof_session.principal_id=challenge.principal_id
     join control.mutation_evidence verification on verification.participant_id=challenge.participant_id
       and verification.privacy_domain_id=$2 and verification.principal_id=challenge.principal_id
       and verification.mfa_challenge_id=challenge.mfa_challenge_id and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
       and verification.aggregate_type='webauthn-verification' and verification.aggregate_id=challenge.session_id
       and verification.webauthn_assertion_binding_digest=$7
     join control.credential credential on credential.participant_id=verification.participant_id
       and credential.principal_id=verification.principal_id and credential.credential_id=verification.signer_credential_id
       and credential.kind='WEBAUTHN' and credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
       and (credential.valid_until is null or credential.valid_until>clock_timestamp())
     where challenge.participant_id=$1 and challenge.principal_id=$3 and challenge.session_id=$4
       and challenge.action_intent_id=$5 and challenge.resource_digest=$6
       and case when proof_session.step_up_mfa_challenge_id is null
         then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
         else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
           and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
         end`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.sessionId,
      input.actionIntentId,
      input.candidateDigest,
      input.assertionBindingDigest ?? null,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-AUTH-0005');
  return result.rows[0]!.credential_id;
}
