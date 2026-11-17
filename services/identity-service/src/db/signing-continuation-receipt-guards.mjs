/** V2-only receipt binding for the closed, already-dispatched effect capability. */
export const signingContinuationReceiptGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_signing_continuation_snapshot(
 p_snapshot bytea,p_participant uuid,p_privacy uuid,p_operation uuid,p_receipt uuid,p_recorded_ns numeric,p_consumed boolean)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE snapshot jsonb; capability control.signing_continuation%ROWTYPE; expected jsonb;
BEGIN
 snapshot:=convert_from(p_snapshot,'UTF8')::jsonb;
 SELECT * INTO STRICT capability FROM control.signing_continuation WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
  AND operation_id=p_operation AND assertion_id=(snapshot->>'continuationAssertionId')::uuid
  AND state=CASE WHEN p_consumed THEN 'CONSUMED' ELSE 'ISSUED' END;
 expected:=jsonb_build_object('schema','pc.control.signing-rotation-continuation-snapshot.v1',
  'participantId',p_participant::text,'privacyDomainId',p_privacy::text,'operationId',p_operation::text,
  'recordedAtNs',snapshot->'recordedAtNs','decision','RECORD_DISPATCHED_TRUTH','continuationAssertionId',capability.assertion_id::text,
  'continuationAssertionDigest','sha256:'||encode(capability.assertion_digest,'hex'),'context',convert_from(capability.context_preimage,'UTF8')::jsonb);
 IF snapshot IS DISTINCT FROM expected OR jsonb_typeof(snapshot->'recordedAtNs') IS DISTINCT FROM 'string'
  OR NOT ((snapshot->>'recordedAtNs') ~ '^[0-9]{1,20}$') OR (snapshot->>'recordedAtNs')::numeric>p_recorded_ns
  OR p_recorded_ns<capability.issued_at_ns OR p_recorded_ns>=capability.expires_at_ns
  OR (p_consumed AND (capability.consumed_receipt_id IS DISTINCT FROM p_receipt OR capability.consumed_at_ns<p_recorded_ns))
  OR (NOT p_consumed AND capability.expires_at_ns<=floor(extract(epoch FROM clock_timestamp())*1000000)*1000)
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-RECEIPT-SNAPSHOT'; END IF;
 IF NOT p_consumed THEN PERFORM openpc.check_signing_continuation_context(snapshot->'context'); END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_consumed_signing_continuation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE context jsonb;
BEGIN
 IF NEW.state<>'CONSUMED' THEN RETURN NULL; END IF;
 context:=convert_from(NEW.context_preimage,'UTF8')::jsonb;
 IF context->>'resultDisposition'='NO_EFFECT_RETRYABLE' THEN
  IF NOT EXISTS(SELECT 1 FROM control.signing_rotation_operation_evidence e JOIN control.signing_rotation_command c USING(participant_id,privacy_domain_id,operation_id)
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
    AND e.continuation_assertion_id=NEW.assertion_id AND e.kind='NO_EFFECT_RETRYABLE' AND c.state='FAILED' AND c.result_kind=e.kind)
  THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ATOMIC-NO-EFFECT'; END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM control.signing_rotation_command c JOIN control.signing_provider_attempt p
  ON p.participant_id=c.participant_id AND p.privacy_domain_id=c.privacy_domain_id AND p.operation_id=c.operation_id
  JOIN control.audit_occurrence a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND a.operation_id=c.operation_id
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id
   AND c.state IN ('SUCCEEDED','FAILED') AND p.attempt_id=NEW.provider_attempt_id AND p.state IN ('ACCEPTED','REJECTED')
   AND a.receipt_id=NEW.consumed_receipt_id AND a.aggregate_type='signing-key-rotation' AND a.before_revision=(context->>'rotationRevision')::bigint
   AND convert_from(a.authority_snapshot,'UTF8')::jsonb->>'continuationAssertionId'=NEW.assertion_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-ATOMIC-EFFECT'; END IF;
 IF context->>'currentAuthorityStatus'='CHANGED' AND NOT EXISTS(SELECT 1 FROM control.signing_rotation_authority_hold h
  WHERE h.participant_id=NEW.participant_id AND h.privacy_domain_id=NEW.privacy_domain_id AND h.operation_id=NEW.operation_id
   AND h.continuation_assertion_id=NEW.assertion_id AND h.reason='AUTHORITY_CHANGED_AFTER_DISPATCH')
 THEN RAISE EXCEPTION 'DATA-6021-CONTINUATION-AUTHORITY-HOLD'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER signing_continuation_atomic AFTER UPDATE ON control.signing_continuation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_consumed_signing_continuation();
CREATE OR REPLACE FUNCTION openpc.guard_signing_authority_hold()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'CLEARED' OR NEW.cleared_by_operation_id IS DISTINCT FROM openpc.current_operation_id()
   OR openpc.current_action_intent_id()<>'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
   OR (to_jsonb(NEW)-ARRAY['state','cleared_by_operation_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','cleared_by_operation_id'])
   OR NOT EXISTS(SELECT 1 FROM control.signing_authorization_generation g JOIN control.signing_rotation_history h
    ON h.participant_id=g.participant_id AND h.privacy_domain_id=g.privacy_domain_id AND h.operation_id=g.consumed_operation_id
     AND h.revision=g.result_revision WHERE g.participant_id=NEW.participant_id AND g.privacy_domain_id=NEW.privacy_domain_id
      AND g.hold_id=NEW.hold_id AND g.state='CONSUMED' AND g.consumed_operation_id=NEW.cleared_by_operation_id
      AND h.receipt_id IS NOT NULL AND h.event_id IS NULL)
  THEN RAISE EXCEPTION 'DATA-6021-HOLD-GOVERNED-RECOVERY-REQUIRED'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-AUTHORITY-HOLD'; END IF;
 IF NEW.state<>'ACTIVE' OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR NOT EXISTS(SELECT 1 FROM control.signing_continuation c WHERE c.participant_id=NEW.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.operation_id=NEW.operation_id AND c.assertion_id=NEW.continuation_assertion_id
   AND c.state='CONSUMED' AND convert_from(c.context_preimage,'UTF8')::jsonb->>'currentAuthorityStatus'='CHANGED'
   AND convert_from(c.context_preimage,'UTF8')::jsonb->>'rotationId'=NEW.rotation_id::text)
 THEN RAISE EXCEPTION 'DATA-6021-AUTHORITY-HOLD-OWNER'; END IF;
 NEW.created_at_ns:=floor(extract(epoch FROM clock_timestamp())*1000000)*1000;
 RETURN NEW;
END $$;
CREATE TRIGGER signing_authority_hold_guard BEFORE INSERT OR UPDATE OR DELETE ON control.signing_rotation_authority_hold
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_signing_authority_hold();
`;
