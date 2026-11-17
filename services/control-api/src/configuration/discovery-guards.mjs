import { workloadCredentialSuccessorSql } from '../../../identity-service/src/db/workload-credential-successor.mjs';
/** Transport observations narrow eligibility; only actual activation establishes a generation. */
export const discoveryGuardsSql = `
ALTER TABLE control.runtime_target_connection FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_discovery_target_read ON control.runtime_target;
CREATE POLICY runtime_discovery_target_read ON control.runtime_target FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
${['participant', 'privacy_domain', 'principal', 'credential']
  .map(
    (table) => `
DROP POLICY IF EXISTS runtime_discovery_read_fence ON control.${table};
CREATE POLICY runtime_discovery_read_fence ON control.${table} FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1')
 WITH CHECK(false);`,
  )
  .join('\n')}
-- A transport owner can retain exact read locks without gaining Identity write rights.
CREATE OR REPLACE FUNCTION openpc.lock_runtime_discovery_authority(target uuid, certificate_digest text)
RETURNS TABLE(credential_id uuid, credential_epoch bigint, principal_epoch bigint, valid_until timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; selected_credential uuid; selected_principal uuid; candidates uuid[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
  OR certificate_digest !~ '^sha256:[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CONTEXT-INVALID'; END IF;
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 PERFORM 1 FROM control.participant p WHERE p.participant_id=pid AND p.state='ACTIVE' AND p.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PARTICIPANT-INVALID'; END IF;
 PERFORM 1 FROM control.privacy_domain p WHERE p.participant_id=pid AND p.privacy_domain_id=privacy AND p.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PRIVACY-INVALID'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
  AND t.runtime_target_id=target AND t.requires_authenticated_discovery)
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-TARGET-INVALID'; END IF;
 SELECT array_agg(c.credential_id ORDER BY c.credential_id) INTO candidates FROM control.credential c
  WHERE c.participant_id=pid AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE'
   AND c.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND c.audience='urn:openpc:workload:'||target::text
   AND c.secret_fingerprint=decode(substring(certificate_digest from 8),'hex');
 IF coalesce(cardinality(candidates),0)<>1 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-CARDINALITY'; END IF;
 selected_credential:=candidates[1];
 SELECT c.principal_id INTO selected_principal FROM control.credential c WHERE c.credential_id=selected_credential AND c.participant_id=pid;
 PERFORM 1 FROM control.principal p WHERE p.participant_id=pid AND p.principal_id=selected_principal
  AND p.kind='WORKLOAD' AND p.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-PRINCIPAL-INVALID'; END IF;
 PERFORM 1 FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=selected_credential FOR SHARE;
 RETURN QUERY SELECT c.credential_id,c.credential_epoch::bigint,p.authority_epoch::bigint,c.valid_until
  FROM control.credential c JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE c.participant_id=pid AND c.credential_id=selected_credential AND c.principal_id=selected_principal
   AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE' AND c.credential_epoch>0
   AND c.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND c.audience='urn:openpc:workload:'||target::text
   AND c.secret_fingerprint=decode(substring(certificate_digest from 8),'hex')
   AND c.certificate_der IS NOT NULL AND sha256(c.certificate_der)=c.secret_fingerprint
   AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
   AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND p.authority_epoch>0;
 IF NOT FOUND THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-INVALID'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.lock_runtime_discovery_authority(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_discovery_authority(uuid,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.runtime_target_discovery_current(pid uuid, privacy uuid, target uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT NOT t.requires_authenticated_discovery OR EXISTS(
  SELECT 1 FROM control.runtime_target_connection observation
  JOIN control.credential credential ON credential.participant_id=observation.participant_id
   AND credential.credential_id=observation.credential_id
  JOIN control.principal principal ON principal.participant_id=credential.participant_id
   AND principal.principal_id=credential.principal_id
  JOIN control.participant participant ON participant.participant_id=principal.participant_id
  JOIN control.privacy_domain privacy_domain ON privacy_domain.participant_id=observation.participant_id
   AND privacy_domain.privacy_domain_id=observation.privacy_domain_id
  WHERE observation.participant_id=pid AND observation.privacy_domain_id=privacy
   AND observation.runtime_target_id=target AND observation.connected
   AND observation.observed_at<=clock_timestamp() AND observation.valid_until>clock_timestamp()
   AND credential.kind='WORKLOAD_MTLS' AND credential.state='ACTIVE'
   AND credential.credential_epoch=observation.credential_epoch
   AND credential.valid_from<=clock_timestamp() AND credential.valid_until>clock_timestamp()
   AND credential.subject='urn:openpc:participant:'||pid::text||':workload:'||target::text
   AND credential.audience='urn:openpc:workload:'||target::text
   AND credential.secret_fingerprint=decode(substring(observation.certificate_digest from 8),'hex')
   AND credential.certificate_der IS NOT NULL AND sha256(credential.certificate_der)=credential.secret_fingerprint
   AND principal.kind='WORKLOAD' AND principal.state='ACTIVE' AND principal.authority_epoch=observation.principal_epoch
   AND participant.state='ACTIVE' AND participant.archived_at IS NULL AND privacy_domain.state='ACTIVE')
  FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
   AND t.runtime_target_id=target AND pid=openpc.current_participant_id() AND privacy=openpc.current_privacy_domain_id()),false)
$$;
REVOKE ALL ON FUNCTION openpc.runtime_target_discovery_current(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_target_discovery_current(uuid,uuid,uuid)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_target_connection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR
  NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR
  NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() OR
  (TG_OP='UPDATE' AND (NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id OR NEW.runtime_target_id<>OLD.runtime_target_id))
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-OWNER-INVALID'; END IF;
 IF NEW.connected AND (NEW.observed_at>clock_timestamp() OR NEW.valid_until<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM control.runtime_target t JOIN control.credential c
  ON c.participant_id=t.participant_id AND c.credential_id=NEW.credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE t.runtime_target_id=NEW.runtime_target_id AND t.participant_id=NEW.participant_id
   AND t.privacy_domain_id=NEW.privacy_domain_id AND t.requires_authenticated_discovery
   AND c.kind='WORKLOAD_MTLS' AND c.state='ACTIVE' AND c.credential_epoch=NEW.credential_epoch
   AND c.subject='urn:openpc:participant:'||t.participant_id::text||':workload:'||t.runtime_target_id::text
   AND c.audience='urn:openpc:workload:'||t.runtime_target_id::text
   AND c.certificate_der IS NOT NULL AND sha256(c.certificate_der)=c.secret_fingerprint
   AND c.secret_fingerprint=decode(substring(NEW.certificate_digest from 8),'hex')
   AND c.valid_from<=NEW.observed_at AND c.valid_until>=NEW.valid_until
   AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND p.authority_epoch=NEW.principal_epoch))
 THEN RAISE EXCEPTION 'DATA-6001-DISCOVERY-CREDENTIAL-INVALID'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_target_connection_fence ON control.runtime_target_connection;
CREATE TRIGGER runtime_target_connection_fence BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_target_connection
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS runtime_target_connection_owner ON control.runtime_target_connection;
CREATE TRIGGER runtime_target_connection_owner BEFORE INSERT OR UPDATE ON control.runtime_target_connection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_target_connection();

CREATE OR REPLACE FUNCTION openpc.guard_initial_target_discovery()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW.requires_authenticated_discovery IS DISTINCT FROM OLD.requires_authenticated_discovery
 THEN RAISE EXCEPTION 'DATA-6007-TARGET-ENROLLMENT-IMMUTABLE'; END IF;
 IF NEW.requires_authenticated_discovery AND NEW.state='DISCOVERED' AND
  (NOT pg_has_role(current_user,'openpc_control_worker','MEMBER') OR
   NOT openpc.runtime_target_discovery_current(NEW.participant_id,NEW.privacy_domain_id,NEW.runtime_target_id))
 THEN RAISE EXCEPTION 'DATA-6007-TARGET-DISCOVERY-REQUIRED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS initial_target_discovery ON control.runtime_target;
CREATE TRIGGER initial_target_discovery BEFORE INSERT OR UPDATE ON control.runtime_target
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_initial_target_discovery();

-- Historical transport succession is a separate read-only owner. Native
-- callers cannot read these authority histories directly or create effects.
${[
  'platform_recovery_enrollment',
  'platform_recovery_case',
  'discovery_certificate_issuance',
  'discovery_certificate_issuer_attempt',
  'mutation_candidate',
  'approval_request',
  'approval_decision_record',
  'mutation_evidence',
  'idempotency_record',
  'outbox_event',
]
  .map(
    (table) => `DROP POLICY IF EXISTS runtime_discovery_successor_history ON control.${table};
CREATE POLICY runtime_discovery_successor_history ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');`,
  )
  .join('\n')}
DROP POLICY IF EXISTS runtime_discovery_successor_challenge ON control.mfa_challenge;
CREATE POLICY runtime_discovery_successor_challenge ON control.mfa_challenge FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');

CREATE OR REPLACE FUNCTION openpc.runtime_discovery_credential_predecessor(target uuid,certificate text,source jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; authority record; current_credential control.credential; head jsonb;
 previous jsonb; predecessor_identity jsonb; matches integer;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,certificate);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT current_credential FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 SELECT a.binding->'target' INTO head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target ORDER BY a.revision DESC LIMIT 1;
 IF head IS NULL THEN RETURN NULL; END IF;
 matches:=0;
 FOR predecessor_identity IN SELECT jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
  'target_id',target::text,'credential_id',predecessor.credential_id::text,'principal_id',predecessor.principal_id::text,
  'credential_epoch',(recovery.intent#>>'{certificateRecovery,predecessorEpoch}')::numeric,
  'principal_epoch',(recovery.intent#>>'{certificateRecovery,workloadPrincipalEpoch}')::numeric,
  'certificate_digest',encode(predecessor.secret_fingerprint,'hex'))
 FROM control.discovery_certificate_issuance issuance
 JOIN control.platform_recovery_case recovery ON recovery.participant_id=issuance.participant_id
  AND recovery.privacy_domain_id=issuance.privacy_domain_id AND recovery.recovery_id=issuance.recovery_id
  AND recovery.state='COMPLETED' AND recovery.completion_operation_id=issuance.committed_operation_id
  AND recovery.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
 JOIN control.platform_recovery_enrollment enrollment ON enrollment.participant_id=recovery.participant_id
  AND enrollment.privacy_domain_id=recovery.privacy_domain_id AND enrollment.enrollment_id=recovery.enrollment_id
  AND enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
  AND enrollment.document->'certificateRecovery'=recovery.intent->'certificateRecovery'
  AND enrollment.document_digest=recovery.enrollment_digest
  AND enrollment.document_digest=sha256(convert_to(openpc.signing_canonical_json(enrollment.document),'UTF8'))
 JOIN control.credential predecessor ON predecessor.participant_id=issuance.participant_id
  AND predecessor.credential_id=issuance.predecessor_credential_id
  AND predecessor.credential_id=current_credential.rotated_from_credential_id
  AND predecessor.principal_id=current_credential.principal_id AND predecessor.audience=current_credential.audience
  -- The old source issuer stays immutable. The enrolled key's new certificate
  -- is verified by the current installed issuer/profile at claim and commit;
  -- an expired predecessor CA cannot become current through equality here.
  AND predecessor.issuer=recovery.intent#>>'{certificateRecovery,issuer}'
  AND predecessor.certificate_der IS NOT NULL AND sha256(predecessor.certificate_der)=predecessor.secret_fingerprint
  AND 'sha256:'||encode(predecessor.secret_fingerprint,'hex')=recovery.intent#>>'{certificateRecovery,predecessorFingerprint}'
  AND 'sha256:'||encode(predecessor.public_key_digest,'hex')=recovery.intent#>>'{certificateRecovery,predecessorPublicKeyDigest}'
 JOIN control.discovery_certificate_issuer_attempt attempt ON attempt.participant_id=issuance.participant_id
  AND attempt.privacy_domain_id=issuance.privacy_domain_id AND attempt.issuance_id=issuance.issuance_id
  AND attempt.state='OBSERVED' AND attempt.certificate_fingerprint=issuance.certificate_fingerprint
 JOIN control.mutation_candidate mutation ON mutation.participant_id=issuance.participant_id
  AND mutation.privacy_domain_id=issuance.privacy_domain_id AND mutation.mutation_candidate_id=issuance.mutation_candidate_id
  AND mutation.state='CONSUMED' AND mutation.consumed_operation_id=issuance.committed_operation_id
  AND mutation.candidate_digest=issuance.candidate_digest AND mutation.idempotency_key=attempt.idempotency_key
  AND mutation.maker_principal_id=attempt.maker_principal_id AND mutation.maker_session_id=attempt.maker_session_id
  AND mutation.maker_principal_id::text=recovery.intent#>>'{administrators,0,principalId}'
 JOIN control.approval_request approval ON approval.participant_id=mutation.participant_id
  AND approval.privacy_domain_id=mutation.privacy_domain_id AND approval.approval_request_id=issuance.approval_request_id
  AND approval.subject_id=mutation.mutation_candidate_id AND approval.subject_digest=mutation.candidate_digest
  AND approval.subject_version=mutation.expected_revision AND approval.state='APPROVED'
 JOIN control.approval_decision_record decision ON decision.participant_id=approval.participant_id
  AND decision.privacy_domain_id=approval.privacy_domain_id AND decision.approval_request_id=approval.approval_request_id
  AND decision.decision='APPROVE' AND decision.approver_principal_id::text=recovery.intent#>>'{administrators,1,principalId}'
  AND decision.approver_principal_id<>mutation.maker_principal_id AND decision.candidate_digest=mutation.candidate_digest
  AND decision.evidence_cbor=attempt.authorization_evidence_cbor AND decision.cose_sign1=attempt.authorization_cose
  AND sha256(attempt.authorization_evidence_cbor)=attempt.authorization_evidence_digest
 JOIN control.mfa_challenge challenge ON challenge.participant_id=mutation.participant_id
  AND challenge.principal_id=mutation.maker_principal_id AND challenge.session_id=mutation.maker_session_id
  AND challenge.resource_digest=mutation.candidate_digest AND challenge.action_intent_id=mutation.action_intent_id
  AND challenge.consumed_at IS NOT NULL AND challenge.used_operation_id=issuance.committed_operation_id
 JOIN control.mutation_evidence verification ON verification.participant_id=challenge.participant_id
  AND verification.privacy_domain_id=mutation.privacy_domain_id AND verification.principal_id=challenge.principal_id
  AND verification.mfa_challenge_id=challenge.mfa_challenge_id AND verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
  AND verification.aggregate_type='webauthn-verification' AND verification.aggregate_id=challenge.session_id
  AND verification.webauthn_assertion_binding_digest=attempt.webauthn_assertion_binding_digest
 JOIN control.idempotency_record verified ON verified.participant_id=verification.participant_id
  AND verified.privacy_domain_id=verification.privacy_domain_id AND verified.operation_id=verification.operation_id
  AND verified.input_digest=verification.candidate_digest AND verified.terminal_state='COMMITTED'
  AND verified.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
 JOIN control.outbox_event verified_event ON verified_event.participant_id=verification.participant_id
  AND verified_event.privacy_domain_id=verification.privacy_domain_id AND verified_event.aggregate_type=verification.aggregate_type
  AND verified_event.aggregate_id=verification.aggregate_id AND verified_event.payload_cbor=verification.evidence_cbor
  AND verified_event.payload_digest=verification.evidence_digest AND verified_event.cose_sign1=verification.cose_sign1
  AND verified_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
  AND verified_event.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest
 WHERE issuance.participant_id=pid AND issuance.privacy_domain_id=privacy AND issuance.state='COMMITTED'
  AND issuance.successor_credential_id=current_credential.credential_id AND issuance.certificate_der=current_credential.certificate_der
  AND issuance.certificate_fingerprint=current_credential.secret_fingerprint AND sha256(issuance.certificate_der)=issuance.certificate_fingerprint
  AND octet_length(issuance.issuer_profile_digest)=32 AND issuance.replay_profile IN ('READBACK_REQUIRED','IMMUTABLE_REQUEST_RESPONSE')
  AND (issuance.replay_profile<>'IMMUTABLE_REQUEST_RESPONSE' OR (current_setting('openpc.local_qa_runtime',true)='1'
    AND enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'))
  AND issuance.request_digest=sha256(convert_to(openpc.signing_canonical_json(issuance.request),'UTF8'))
  AND issuance.request=jsonb_build_object('credentialId',current_credential.credential_id::text,'participantId',pid::text,
   'principalId',current_credential.principal_id::text,'workloadId','urn:openpc:workload:'||target::text,
   'publicKeySpkiDer',replace(encode(current_credential.public_key_spki_der,'base64'),E'\n',''))
  AND recovery.intent#>>'{certificateRecovery,targetId}'=target::text
  AND recovery.intent#>>'{certificateRecovery,workloadPrincipalId}'=current_credential.principal_id::text
  AND (recovery.intent#>>'{certificateRecovery,workloadPrincipalEpoch}')::numeric=authority.principal_epoch
  AND recovery.completion_result=jsonb_build_object('issuanceId',issuance.issuance_id::text,'operationId',issuance.committed_operation_id::text,
   'predecessorCredentialId',predecessor.credential_id::text,'successorCredentialId',current_credential.credential_id::text,
   'certificateFingerprint','sha256:'||encode(current_credential.secret_fingerprint,'hex'))
  AND ${workloadCredentialSuccessorSql({
    participantId: 'pid',
    privacyDomainId: 'privacy',
    predecessorId: 'issuance.predecessor_credential_id',
    predecessorEpoch: "(recovery.intent#>>'{certificateRecovery,predecessorEpoch}')::numeric",
    successorId: 'issuance.successor_credential_id',
    successorEpoch: 'authority.credential_epoch',
    operationId: 'issuance.committed_operation_id',
  })}
  AND EXISTS(SELECT 1 FROM control.runtime_target_disposition_admission original
   JOIN control.runtime_target_disposition_delivery delivery ON delivery.participant_id=original.participant_id
    AND delivery.privacy_domain_id=original.privacy_domain_id AND delivery.runtime_target_id=original.runtime_target_id
    AND delivery.revision=original.revision
    AND delivery.claims=original.binding||jsonb_build_object('committed_admission_digest',substring(original.admission_digest from 8))
    AND delivery.delivery_digest='sha256:'||encode(sha256(delivery.signed_delivery),'hex')
   JOIN control.runtime_target_disposition_acknowledgement ack ON ack.participant_id=delivery.participant_id
    AND ack.privacy_domain_id=delivery.privacy_domain_id AND ack.runtime_target_id=delivery.runtime_target_id
    AND ack.delivery_digest=delivery.delivery_digest AND ack.claims->'target'=original.binding->'target'
    AND ack.acknowledgement_digest='sha256:'||encode(sha256(ack.signed_acknowledgement),'hex')
   WHERE original.participant_id=pid AND original.privacy_domain_id=privacy AND original.runtime_target_id=target
    AND original.binding->'source'=runtime_discovery_credential_predecessor.source
    AND original.binding->'target'=jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
     'target_id',target::text,'credential_id',predecessor.credential_id::text,'principal_id',predecessor.principal_id::text,
     'credential_epoch',(recovery.intent#>>'{certificateRecovery,predecessorEpoch}')::numeric,
     'principal_epoch',(recovery.intent#>>'{certificateRecovery,workloadPrincipalEpoch}')::numeric,
     'certificate_digest',encode(predecessor.secret_fingerprint,'hex')))
 LOOP
  matches:=matches+1; previous:=predecessor_identity;
 END LOOP;
 IF matches=1 THEN RETURN previous; END IF;
 IF matches<>0 OR head IS DISTINCT FROM jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
  'target_id',target::text,'credential_id',current_credential.credential_id::text,'principal_id',current_credential.principal_id::text,
  'credential_epoch',authority.credential_epoch,'principal_epoch',authority.principal_epoch,
  'certificate_digest',substring(certificate from 8))
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CREDENTIAL-SUCCESSOR'; END IF;
 RETURN NULL;
END $$;
ALTER FUNCTION openpc.runtime_discovery_credential_predecessor(uuid,text,jsonb) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.runtime_discovery_credential_predecessor(uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_discovery_credential_predecessor(uuid,text,jsonb) TO openpc_control_worker;
`;
