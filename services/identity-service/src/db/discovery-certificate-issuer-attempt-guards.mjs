/** Each issuer call is admitted separately by the shared identity mutation owner.
 * SQL closes the approved candidate, source, maker/checker and fresh step-up joins. */
export const discoveryCertificateIssuerAttemptGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_discovery_certificate_issuer_attempt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE issuance control.discovery_certificate_issuance;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 SELECT * INTO issuance FROM control.discovery_certificate_issuance i WHERE i.issuance_id=NEW.issuance_id
  and i.participant_id=NEW.participant_id and i.privacy_domain_id=NEW.privacy_domain_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ISSUING' or NEW.row_version<>1 or NEW.preparation_operation_id IS DISTINCT FROM openpc.current_operation_id()
   or NEW.sequence<>(select coalesce(max(a.sequence),0)+1 from control.discovery_certificate_issuer_attempt a
    where a.participant_id=NEW.participant_id and a.privacy_domain_id=NEW.privacy_domain_id and a.issuance_id=NEW.issuance_id)
   or NEW.sequence>10 or EXISTS(select 1 from control.discovery_certificate_issuer_attempt a
    where a.participant_id=NEW.participant_id and a.privacy_domain_id=NEW.privacy_domain_id and a.issuance_id=NEW.issuance_id and a.state='ISSUING')
   or NOT ((NEW.sequence=1 and issuance.state='PREPARED')
     or (NEW.sequence>1 and issuance.state='AMBIGUOUS' and issuance.replay_profile='IMMUTABLE_REQUEST_RESPONSE'
       and current_setting('openpc.local_qa_runtime',true)='1'))
   or NOT EXISTS(select 1 from control.mutation_candidate candidate
    join control.approval_request approval on approval.participant_id=candidate.participant_id
     and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
     and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
     and approval.maker_principal_id=candidate.maker_principal_id and approval.approval_request_id=issuance.approval_request_id
     and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.state='APPROVED' and approval.expires_at>clock_timestamp()
    join control.authority_envelope maker on maker.participant_id=candidate.participant_id
     and maker.authority_envelope_id=candidate.maker_authority_envelope_id and maker.representation='RECOVERY_V1'
     and maker.recovery_case_id=issuance.recovery_id and openpc.platform_recovery_envelope_current(maker.authority_envelope_id)
    join control.platform_recovery_case recovery on recovery.participant_id=maker.participant_id
     and recovery.recovery_id=maker.recovery_case_id and recovery.privacy_domain_id=candidate.privacy_domain_id and recovery.state='ACTIVE'
    join control.session session on session.participant_id=candidate.participant_id and session.session_id=candidate.maker_session_id
     and session.principal_id=candidate.maker_principal_id and session.session_epoch=candidate.maker_session_epoch
     and session.authority_epoch=candidate.maker_principal_epoch and session.participant_epoch=candidate.maker_participant_epoch
     and session.context_mode='PLATFORM' and session.privacy_domain_id is null and session.state='ACTIVE'
     and session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp()
    join control.approval_decision_record decision on decision.participant_id=approval.participant_id
     and decision.approval_request_id=approval.approval_request_id and decision.decision='APPROVE'
     and decision.approver_principal_id<>candidate.maker_principal_id and decision.candidate_digest=candidate.candidate_digest
     and decision.aggregate_version=candidate.expected_revision and decision.evidence_cbor=NEW.authorization_evidence_cbor
     and decision.cose_sign1=NEW.authorization_cose
    join control.authority_envelope checker on checker.participant_id=decision.participant_id
     and checker.authority_envelope_id=decision.approver_authority_envelope_id and checker.representation='RECOVERY_V1'
     and checker.recovery_case_id=recovery.recovery_id and openpc.platform_recovery_envelope_current(checker.authority_envelope_id)
    join control.mfa_challenge challenge on challenge.participant_id=candidate.participant_id
     and challenge.principal_id=candidate.maker_principal_id and challenge.session_id=candidate.maker_session_id
     and challenge.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' and challenge.resource_digest=candidate.candidate_digest
     and (case when session.step_up_mfa_challenge_id is null
       then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
       else session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
         and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
       end) and challenge.used_at is null
    join control.mutation_evidence verification on verification.participant_id=challenge.participant_id
     and verification.privacy_domain_id=candidate.privacy_domain_id and verification.principal_id=candidate.maker_principal_id
     and verification.mfa_challenge_id=challenge.mfa_challenge_id and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
     and verification.aggregate_type='webauthn-verification' and verification.aggregate_id=challenge.session_id
     and verification.webauthn_assertion_binding_digest=NEW.webauthn_assertion_binding_digest
    join control.idempotency_record verified on verified.participant_id=verification.participant_id
     and verified.privacy_domain_id=verification.privacy_domain_id and verified.operation_id=verification.operation_id
     and verified.catalog_operation_id=verification.catalog_operation_id and verified.input_digest=verification.candidate_digest
     and verified.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest and verified.terminal_state='COMMITTED'
    join control.outbox_event event on event.participant_id=verification.participant_id and event.privacy_domain_id=verification.privacy_domain_id
     and event.aggregate_type=verification.aggregate_type and event.aggregate_id=verification.aggregate_id
     and event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
     and event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
     and event.payload_cbor=verification.evidence_cbor and event.payload_digest=verification.evidence_digest and event.cose_sign1=verification.cose_sign1
    where candidate.participant_id=issuance.participant_id and candidate.privacy_domain_id=issuance.privacy_domain_id
     and candidate.mutation_candidate_id=issuance.mutation_candidate_id and candidate.state='APPROVED' and candidate.expires_at>clock_timestamp()
     and candidate.candidate_digest=issuance.candidate_digest and candidate.catalog_operation_id='ID-OP-WORKLOAD-ROTATE'
     and candidate.idempotency_key=NEW.idempotency_key and candidate.maker_principal_id=NEW.maker_principal_id
     and candidate.maker_session_id=NEW.maker_session_id and NEW.started_at<=clock_timestamp() and NEW.deadline>clock_timestamp()
     and NEW.deadline<=least(recovery.valid_until,approval.expires_at,candidate.expires_at,challenge.expires_at,
       session.idle_expires_at,session.absolute_expires_at,
       case when session.step_up_mfa_challenge_id is null then challenge.consumed_at+interval '5 minutes'
         else coalesce(openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id),'-infinity'::timestamptz) end)
     and (issuance.replay_profile<>'IMMUTABLE_REQUEST_RESPONSE' or (current_setting('openpc.local_qa_runtime',true)='1'
      and exists(select 1 from control.platform_recovery_enrollment enrollment where enrollment.enrollment_id=recovery.enrollment_id
       and enrollment.participant_id=recovery.participant_id and enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'))))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 ELSE
  IF OLD.state<>'ISSUING' or NEW.state NOT IN ('AMBIGUOUS','OBSERVED','REJECTED') or NEW.row_version<>OLD.row_version+1
   or (to_jsonb(NEW)-ARRAY['state','row_version','finished_at','certificate_fingerprint','failure_code']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','row_version','finished_at','certificate_fingerprint','failure_code'])
   or (NEW.failure_code='CLAIM_EXPIRED' and OLD.deadline>clock_timestamp())
   or NEW.finished_at>clock_timestamp() THEN RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS discovery_certificate_issuer_attempt_guard ON control.discovery_certificate_issuer_attempt;
CREATE TRIGGER discovery_certificate_issuer_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.discovery_certificate_issuer_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_certificate_issuer_attempt();

CREATE OR REPLACE FUNCTION openpc.guard_discovery_certificate_issuance_attempt_phase()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control AS $$
DECLARE attempt control.discovery_certificate_issuer_attempt;
BEGIN
 IF TG_OP='INSERT' THEN RETURN NEW; END IF;
 SELECT * INTO attempt FROM control.discovery_certificate_issuer_attempt a WHERE a.participant_id=NEW.participant_id
  and a.privacy_domain_id=NEW.privacy_domain_id and a.issuance_id=NEW.issuance_id ORDER BY a.sequence DESC LIMIT 1;
 IF NEW.state IN ('ISSUING','AMBIGUOUS','OBSERVED','COMMITTED') and NOT FOUND THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 IF NEW.state='ISSUING' and (attempt.state<>'ISSUING' or attempt.deadline<=clock_timestamp()
  or attempt.preparation_operation_id IS DISTINCT FROM openpc.current_operation_id()) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 IF NEW.state='AMBIGUOUS' and (attempt.state<>'AMBIGUOUS' or NEW.failure_code IS DISTINCT FROM attempt.failure_code) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 IF NEW.state IN ('OBSERVED','COMMITTED') and (attempt.state<>'OBSERVED'
  or NEW.certificate_fingerprint IS DISTINCT FROM attempt.certificate_fingerprint) THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 IF NEW.state='REJECTED' and OLD.state='ISSUING' and attempt.state<>'REJECTED' THEN
  RAISE EXCEPTION 'PC-AUTH-0005-DISCOVERY-ISSUER-ATTEMPT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS discovery_certificate_issuance_attempt_phase_guard ON control.discovery_certificate_issuance;
CREATE TRIGGER discovery_certificate_issuance_attempt_phase_guard BEFORE INSERT OR UPDATE ON control.discovery_certificate_issuance
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_discovery_certificate_issuance_attempt_phase();
`;
export const discoveryCertificateIssuerAttemptGrantsSql = `
GRANT SELECT,INSERT,UPDATE ON control.discovery_certificate_issuer_attempt TO openpc_control_runtime,openpc_control_platform_runtime;
`;
