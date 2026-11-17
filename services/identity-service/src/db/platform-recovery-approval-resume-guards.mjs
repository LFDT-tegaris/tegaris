/** Source3 permits fresh approval metadata for an unconsumed original activation.
 * It never renews the original recovery grant or changes the business intent. */
export const platformRecoveryApprovalResumeGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_platform_recovery_approval_resume(n control.mutation_candidate)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE old_attempt control.mutation_candidate; fresh control.platform_recovery_case;
 new_envelope control.authority_envelope; new_enrollment control.platform_recovery_enrollment;
 proof_count integer; proofs jsonb[]; proof_deadline timestamptz; expected_request jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'serializable'
  OR current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'
  OR openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
  OR jsonb_typeof(n.resume_request) IS DISTINCT FROM 'object'
  OR jsonb_typeof(n.resume_request->'platformReceivingProof') IS DISTINCT FROM 'object'
  OR n.resume_request->'platformReceivingProof' IS DISTINCT FROM jsonb_build_object(
   'mfaChallengeId',n.resume_request#>'{platformReceivingProof,mfaChallengeId}',
   'verificationOperationId',n.resume_request#>'{platformReceivingProof,verificationOperationId}',
   'evidenceDigest',n.resume_request#>'{platformReceivingProof,evidenceDigest}')
  OR jsonb_typeof(n.resume_request#>'{platformReceivingProof,mfaChallengeId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(n.resume_request#>'{platformReceivingProof,verificationOperationId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(n.resume_request#>'{platformReceivingProof,evidenceDigest}') IS DISTINCT FROM 'string'
  OR (n.resume_request#>>'{platformReceivingProof,mfaChallengeId}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR (n.resume_request#>>'{platformReceivingProof,verificationOperationId}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR (n.resume_request#>>'{platformReceivingProof,evidenceDigest}') !~ '^sha256:[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT * INTO STRICT old_attempt FROM control.mutation_candidate
  WHERE mutation_candidate_id=n.predecessor_candidate_id FOR UPDATE;
 SELECT * INTO STRICT new_envelope FROM control.authority_envelope
  WHERE participant_id=n.participant_id AND authority_envelope_id=n.maker_authority_envelope_id;
 SELECT * INTO STRICT fresh FROM control.platform_recovery_case
  WHERE participant_id=n.participant_id AND privacy_domain_id=n.privacy_domain_id
   AND recovery_id=new_envelope.recovery_case_id;
 SELECT * INTO STRICT new_enrollment FROM control.platform_recovery_enrollment
  WHERE enrollment_id=fresh.enrollment_id;
 IF new_enrollment.source_purpose IS DISTINCT FROM 'ROOT_EXPIRY_RECOVERY_CONTINUATION'
  OR new_enrollment.document->>'schemaVersion' IS DISTINCT FROM '3'
  OR new_enrollment.document->>'schema' IS DISTINCT FROM 'pc.identity.platform-recovery-enrollment'
  OR new_enrollment.document->>'assurance' IS DISTINCT FROM 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
  OR new_enrollment.document_digest IS DISTINCT FROM fresh.enrollment_digest
  OR new_enrollment.row_version IS DISTINCT FROM fresh.enrollment_revision
  OR fresh.state IS DISTINCT FROM 'ACTIVE' OR fresh.activated_at IS NULL
  OR fresh.intent->>'schema' IS DISTINCT FROM 'pc.identity.platform-recovery-intent'
  OR NOT fresh.intent ? 'continuation'
  OR fresh.intent ? 'completionSourceDigest'
  OR new_enrollment.document#>'{source}' ? 'activatedHandoff'
  OR openpc.platform_recovery_continuation_current(n.participant_id,fresh.enrollment_id,
    fresh.intent->'continuation',fresh.intent->'preparation') IS DISTINCT FROM true
  OR new_envelope.representation IS DISTINCT FROM 'RECOVERY_V1'
  OR new_envelope.principal_id IS DISTINCT FROM n.maker_principal_id
  OR new_envelope.authority_epoch IS DISTINCT FROM n.maker_authority_epoch
  OR new_envelope.delegation_epoch IS DISTINCT FROM n.maker_delegation_epoch
  OR openpc.platform_recovery_envelope_current(new_envelope.authority_envelope_id) IS DISTINCT FROM true
  OR openpc.platform_recovery_approval_resume_subject_visible(n.participant_id,n.privacy_domain_id,
    n.maker_principal_id,n.maker_authority_envelope_id,n.predecessor_approval_id) IS DISTINCT FROM true
  OR n.catalog_operation_id IS DISTINCT FROM 'ID-OP-ENVELOPE-ACTIVATE'
  OR n.action_intent_id IS DISTINCT FROM 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
  OR n.resource_type IS DISTINCT FROM 'participant' OR n.operation_class IS DISTINCT FROM 'ACTIVATE'
  OR n.expected_revision IS DISTINCT FROM 3 OR n.attempt IS DISTINCT FROM old_attempt.attempt+1
  OR n.state NOT IN ('PROPOSED','APPROVAL_REQUESTED') OR n.consumed_operation_id IS NOT NULL
  OR old_attempt.state NOT IN ('APPROVAL_REQUESTED','APPROVED') OR old_attempt.consumed_operation_id IS NOT NULL
  OR n.predecessor_approval_id IS NULL OR n.resume_operation_id IS NULL
  OR row(n.participant_id,n.privacy_domain_id,n.action_intent_id,n.catalog_operation_id,n.resource_type,
     n.operation_class,n.resource_id,n.candidate_digest,n.candidate_document,n.expected_revision,n.idempotency_key,n.maker_principal_id)
   IS DISTINCT FROM row(old_attempt.participant_id,old_attempt.privacy_domain_id,old_attempt.action_intent_id,
     old_attempt.catalog_operation_id,old_attempt.resource_type,old_attempt.operation_class,old_attempt.resource_id,
     old_attempt.candidate_digest,old_attempt.candidate_document,old_attempt.expected_revision,old_attempt.idempotency_key,old_attempt.maker_principal_id)
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 PERFORM openpc.assert_mutation_resume_no_effect(old_attempt.mutation_candidate_id);
 -- A receiving proof must be durably verified after this new case's activation.
 SELECT count(*),array_agg(jsonb_build_object('mfaChallengeId',m.mfa_challenge_id::text,
   'verificationOperationId',verification.operation_id::text,'evidenceDigest','sha256:'||encode(verification.evidence_digest,'hex'))),
   min(least(m.expires_at,
     case when proof_session.step_up_mfa_challenge_id is null then m.consumed_at+interval '5 minutes'
       else coalesce(openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id),'-infinity'::timestamptz) end,
     coalesce(credential.valid_until,'infinity'::timestamptz)))
  INTO proof_count,proofs,proof_deadline FROM control.mfa_challenge m
 JOIN control.session proof_session ON proof_session.participant_id=m.participant_id
  AND proof_session.session_id=m.session_id AND proof_session.principal_id=m.principal_id
 JOIN control.credential credential ON credential.participant_id=m.participant_id AND credential.credential_id=m.signer_credential_id
  AND credential.principal_id=m.principal_id AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
  AND credential.credential_epoch=m.signer_credential_epoch AND credential.valid_from<=clock_timestamp()
  AND (credential.valid_until IS NULL OR credential.valid_until>clock_timestamp())
  AND sha256(credential.public_key_spki_der)=credential.public_key_digest
 JOIN control.mutation_evidence verification ON verification.participant_id=m.participant_id
  AND verification.mfa_challenge_id=m.mfa_challenge_id AND verification.privacy_domain_id=n.privacy_domain_id
  AND verification.principal_id=n.maker_principal_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND verification.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
  AND verification.aggregate_type='webauthn-verification' AND verification.aggregate_id=n.maker_session_id
  AND verification.signer_credential_id=m.signer_credential_id AND verification.webauthn_assertion_binding_digest IS NOT NULL
  AND verification.evidence_digest=sha256(verification.evidence_cbor) AND verification.occurred_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND verification.occurred_at>=m.consumed_at AND verification.occurred_at<=clock_timestamp()
  AND verification.bound_participant_epoch=n.maker_participant_epoch AND verification.bound_principal_epoch=n.maker_principal_epoch
  AND verification.bound_authority_envelope_id=n.maker_authority_envelope_id AND verification.bound_envelope_epoch=n.maker_authority_epoch
  AND verification.bound_assignment_id=n.maker_assignment_id
 JOIN control.idempotency_record committed ON committed.participant_id=verification.participant_id
  AND committed.privacy_domain_id=verification.privacy_domain_id AND committed.operation_id=verification.operation_id
  AND committed.principal_id=verification.principal_id AND committed.action_intent_id=verification.action_intent_id
  AND committed.catalog_operation_id=verification.catalog_operation_id
  AND committed.input_digest=verification.candidate_digest AND committed.terminal_state='COMMITTED'
  AND committed.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
 JOIN control.outbox_event event ON event.participant_id=verification.participant_id AND event.privacy_domain_id=verification.privacy_domain_id
  AND event.aggregate_type=verification.aggregate_type AND event.aggregate_id=verification.aggregate_id
  AND event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
  AND event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
  AND event.payload_cbor=verification.evidence_cbor AND event.payload_digest=verification.evidence_digest AND event.cose_sign1=verification.cose_sign1
 WHERE m.participant_id=n.participant_id AND m.principal_id=n.maker_principal_id AND m.session_id=n.maker_session_id
  AND m.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' AND m.resource_digest=sha256(convert_to(openpc.signing_canonical_json(n.resume_request-'platformReceivingProof'),'UTF8')) AND m.resource_id=n.predecessor_approval_id::text
  AND m.created_at>=greatest(fresh.activated_at,new_envelope.valid_from) AND m.consumed_at>=greatest(fresh.activated_at,new_envelope.valid_from)
  AND (CASE WHEN proof_session.step_up_mfa_challenge_id IS NULL
    THEN m.consumed_at>clock_timestamp()-interval '5 minutes'
    ELSE proof_session.step_up_mfa_challenge_id=m.mfa_challenge_id
      AND openpc.session_step_up_valid_until(m.participant_id,m.session_id,m.principal_id)>clock_timestamp() END)
  AND m.consumed_at<=clock_timestamp()
  AND m.expires_at>clock_timestamp() AND ((m.used_at IS NULL AND m.used_operation_id IS NULL) OR (m.used_at IS NOT NULL AND m.used_operation_id=n.resume_operation_id));
 IF proof_count<>1 OR n.resume_request->'platformReceivingProof' IS DISTINCT FROM proofs[1]
  OR proof_deadline<=clock_timestamp()
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 SELECT jsonb_build_object('command','RESUME',
  'actionIntentId','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','actionIntentDigest','sha256:'||encode(action.semantic_digest,'hex'),
  'approvalRequestId','urn:openpc:resource:'||prior.approval_request_id::text,'expectedRevision',prior.row_version::text,
  'predecessorCandidateId',old_attempt.mutation_candidate_id::text,'expectedAttempt',old_attempt.attempt::text,
  'candidateDigest','sha256:'||encode(old_attempt.candidate_digest,'hex'),
  'reason','Resume the original unconsumed Platform administrator handoff under fresh independent recovery custody.',
  'platformReceivingProof',proofs[1]) INTO expected_request
 FROM control.approval_request prior JOIN control.action_intent action
  ON action.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
 WHERE prior.participant_id=n.participant_id AND prior.privacy_domain_id=n.privacy_domain_id
  AND prior.approval_request_id=n.predecessor_approval_id AND prior.subject_type='CONFIGURATION_CANDIDATE'
  AND prior.subject_id=old_attempt.mutation_candidate_id AND prior.subject_digest=n.candidate_digest
  AND prior.subject_version=n.expected_revision AND prior.action_intent_id=n.action_intent_id
  AND prior.maker_principal_id=n.maker_principal_id AND prior.checker_principal_id<>n.maker_principal_id
  AND prior.checker_principal_id::text=fresh.intent#>>'{preparation,administrators,1,principalId}'
  AND prior.state IN ('OPEN','APPROVED','EXPIRED');
 IF expected_request IS NULL OR n.resume_request IS DISTINCT FROM expected_request
  OR n.expires_at<=clock_timestamp()
  OR n.expires_at>least(clock_timestamp()+interval '30 minutes',fresh.valid_until,new_envelope.valid_until,proof_deadline,
    (SELECT least(s.idle_expires_at,s.absolute_expires_at) FROM control.session s
      WHERE s.participant_id=n.participant_id AND s.session_id=n.maker_session_id),
    (SELECT upper(a.valid_during) FROM control.assignment a
      WHERE a.participant_id=n.participant_id AND a.assignment_id=n.maker_assignment_id))
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
 -- Recheck live source and proof consumption at the actual commit/replay boundary.
 IF openpc.platform_recovery_approval_resume_subject_visible(n.participant_id,n.privacy_domain_id,
    n.maker_principal_id,n.maker_authority_envelope_id,n.predecessor_approval_id) IS DISTINCT FROM true
  OR NOT EXISTS(SELECT 1 FROM control.idempotency_record resume
   WHERE resume.participant_id=n.participant_id AND resume.privacy_domain_id=n.privacy_domain_id
    AND resume.operation_id=n.resume_operation_id AND resume.principal_id=n.maker_principal_id
    AND resume.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' AND resume.catalog_operation_id='LEGACY'
    AND resume.input_digest=sha256(convert_to(openpc.signing_canonical_json(n.resume_request-'platformReceivingProof'),'UTF8'))
    AND ((resume.terminal_state IS NULL AND EXISTS(SELECT 1 FROM control.mfa_challenge unused
      WHERE unused.participant_id=n.participant_id AND unused.mfa_challenge_id::text=proofs[1]->>'mfaChallengeId'
       AND unused.used_at IS NULL AND unused.used_operation_id IS NULL))
     OR (resume.terminal_state='COMMITTED' AND EXISTS(SELECT 1 FROM control.mfa_challenge used
      WHERE used.participant_id=n.participant_id AND used.mfa_challenge_id::text=proofs[1]->>'mfaChallengeId'
       AND used.used_at IS NOT NULL AND used.used_operation_id=n.resume_operation_id))))
  OR proof_deadline<=clock_timestamp() OR fresh.valid_until<=clock_timestamp() OR n.expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM control.session s JOIN control.principal p
    ON p.participant_id=s.participant_id AND p.principal_id=s.principal_id
   JOIN control.participant participant ON participant.participant_id=s.participant_id
   JOIN control.assignment a ON a.participant_id=s.participant_id AND a.assignment_id=n.maker_assignment_id
    AND a.principal_id=s.principal_id AND a.authority_envelope_id=n.maker_authority_envelope_id
   WHERE s.participant_id=n.participant_id AND s.session_id=n.maker_session_id AND s.principal_id=n.maker_principal_id
    AND s.state='ACTIVE' AND p.state='ACTIVE' AND participant.state='ACTIVE'
    AND p.authority_epoch=n.maker_principal_epoch AND participant.authority_epoch=n.maker_participant_epoch
    AND s.authority_epoch=n.maker_principal_epoch AND s.session_epoch=n.maker_session_epoch
    AND s.participant_epoch=n.maker_participant_epoch AND s.delegation_epoch=n.maker_delegation_epoch
    AND s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL
    AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
    AND a.state='ACTIVE' AND a.row_version=n.maker_assignment_row_version
    AND a.delegation_epoch=n.maker_delegation_epoch AND a.valid_during @> clock_timestamp())
 THEN RAISE EXCEPTION 'PC-POLICY-2004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_platform_recovery_approval_resume(control.mutation_candidate) FROM PUBLIC;
`;

export const platformRecoveryApprovalResumeGrantsSql = `
GRANT EXECUTE ON FUNCTION openpc.assert_platform_recovery_approval_resume(control.mutation_candidate)
 TO openpc_control_runtime,openpc_control_platform_runtime;
`;
