/** Evidence for provable no-effect failures, distinct from absence, timeout and write ambiguity. */
export const signingOperationEvidenceGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.signing_operation_failure_preimage(p_attempt uuid,p_kind text,p_assertion uuid)
RETURNS bytea LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.signing_provider_attempt%ROWTYPE; c control.signing_rotation_command%ROWTYPE;
 authority jsonb; assertion control.signing_continuation%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM control.signing_provider_attempt WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND attempt_id=p_attempt;
 SELECT * INTO STRICT c FROM control.signing_rotation_command WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id;
 IF c.operation_id IS DISTINCT FROM openpc.current_operation_id() OR c.action_intent_id<>'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
  OR openpc.current_action_intent_id()<>c.action_intent_id THEN RAISE EXCEPTION 'DATA-6021-NO-EFFECT-CONTEXT'; END IF;
 IF p_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH' THEN
  authority:=openpc.signing_attempt_authority_status(p_attempt);
  IF p_assertion IS NOT NULL OR (authority->>'unchangedLive')::boolean OR a.dispatched_at_ns IS NOT NULL
   OR EXISTS(SELECT 1 FROM control.signing_provider_attempt other WHERE other.participant_id=a.participant_id
    AND other.privacy_domain_id=a.privacy_domain_id AND other.operation_id=a.operation_id
    AND (other.state NOT IN ('READY','CANCELLED') OR other.dispatched_at_ns IS NOT NULL OR other.observation IS NOT NULL))
  THEN RAISE EXCEPTION 'DATA-6021-UNDISPATCHED-AUTHORITY-FAILURE'; END IF;
 ELSIF p_kind='NO_EFFECT_RETRYABLE' THEN
  SELECT * INTO STRICT assertion FROM control.signing_continuation WHERE participant_id=a.participant_id
   AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id AND provider_attempt_id=a.attempt_id
   AND assertion_id=p_assertion AND state IN ('ISSUED','CONSUMED');
  IF a.state NOT IN ('OBSERVED','REJECTED') OR a.dispatched_at_ns IS NULL OR a.observation->>'outcome' IS DISTINCT FROM 'REJECTED'
   OR a.observation->>'reason' IS DISTINCT FROM 'NOT_APPLIED'
   OR convert_from(assertion.context_preimage,'UTF8')::jsonb->>'resultDisposition' IS DISTINCT FROM 'NO_EFFECT_RETRYABLE'
  THEN RAISE EXCEPTION 'DATA-6021-PROVIDER-NO-EFFECT-GUARANTEE'; END IF;
 ELSE RAISE EXCEPTION 'DATA-6021-NO-EFFECT-KIND'; END IF;
 RETURN convert_to(jsonb_build_object('schema','pc.control.signing-rotation-operation-result.v1','participantId',a.participant_id,
  'privacyDomainId',a.privacy_domain_id,'rotationId',a.rotation_id,'operationId',c.operation_id,'kind',p_kind,
  'candidateDigest',encode(c.input_digest,'hex'),'revision',c.from_revision,'currentRevision',(SELECT r.revision FROM control.signing_key_rotation r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.rotation_id=c.rotation_id),'providerAttemptId',a.attempt_id,
  'providerRequestDigest',encode(a.request_digest,'hex'),'dispatchedAtNs',a.dispatched_at_ns,
  'providerObservationDigest',encode(a.observation_digest,'hex'),'originalAuthoritySnapshotDigest',encode(c.authorization_snapshot_digest,'hex'),
  'currentAuthority',authority,'continuationAssertionId',p_assertion,'continuationAssertionDigest',encode(assertion.assertion_digest,'hex'))::text,'UTF8');
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_signing_operation_evidence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-SIGNING-OPERATION-EVIDENCE'; END IF;
 IF NEW.preimage IS DISTINCT FROM openpc.signing_operation_failure_preimage(NEW.provider_attempt_id,NEW.kind,NEW.continuation_assertion_id)
  OR NOT EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.rotation_id=NEW.rotation_id AND a.operation_id=NEW.operation_id AND a.attempt_id=NEW.provider_attempt_id)
 THEN RAISE EXCEPTION 'DATA-6021-SIGNING-OPERATION-EVIDENCE'; END IF;
 NEW.recorded_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_operation_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_operation_evidence
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_operation_evidence();
CREATE OR REPLACE FUNCTION openpc.check_signing_no_effect_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.idempotency_record i USING(participant_id,privacy_domain_id,operation_id)
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id
   AND c.state='FAILED' AND c.result_kind=NEW.kind AND c.result_revision=(convert_from(NEW.preimage,'UTF8')::jsonb->>'currentRevision')::bigint AND i.terminal_state='COMMITTED'
   AND i.result_payload->>'state'='FAILED' AND i.result_payload->'signingResult'->>'kind'=NEW.kind)
  OR EXISTS(SELECT 1 FROM control.signing_rotation_history h WHERE h.participant_id=NEW.participant_id
   AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id)
  OR EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id)
  OR EXISTS(SELECT 1 FROM control.signing_provider_attempt a WHERE a.participant_id=NEW.participant_id
   AND a.privacy_domain_id=NEW.privacy_domain_id AND a.operation_id=NEW.operation_id
   AND ((NEW.kind='AUTHORITY_CHANGED_BEFORE_DISPATCH' AND a.state<>'CANCELLED') OR
    (NEW.kind='NO_EFFECT_RETRYABLE' AND a.state NOT IN ('REJECTED','SUPERSEDED'))))
 THEN RAISE EXCEPTION 'DATA-6021-NO-EFFECT-ATOMIC-COMPLETION'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER signing_no_effect_complete AFTER INSERT ON control.signing_rotation_operation_evidence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_signing_no_effect_completion();
`;
