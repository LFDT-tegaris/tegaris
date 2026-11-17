export const storeRetirementDeliveryGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.store_retirement_committed_digest(a control.store_retirement_admission)
RETURNS text LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt text;
BEGIN
 SELECT encode(receipt_digest,'hex') INTO STRICT receipt FROM control.audit_occurrence
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id
   AND aggregate_type='store-retirement' AND aggregate_id=a.attempt_id AND profile_id='pc.control.store-retirement.admit';
 RETURN encode(sha256(convert_to('["OPENPC_STORE_RETIREMENT_COMMITTED_V1",'||to_json(a.host_digest)::text||','||
  to_json(a.attempt_digest)::text||','||to_json(receipt)::text||','||to_json(substring(a.source_binding_digest from 8))::text||','||
  a.dispatch_not_after_ms::text||']','UTF8')),'hex');
END $$;
REVOKE ALL ON FUNCTION openpc.store_retirement_committed_digest(control.store_retirement_admission) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.store_retirement_committed_digest(control.store_retirement_admission) TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_store_retirement_cancellation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.store_retirement_admission; expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.store_retirement_admission WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id AND xmin<>pg_current_xact_id()::xid;
 PERFORM openpc.lock_store_retirement_workload(a.host_digest);
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||a.participant_id::text,0));
 IF EXISTS(SELECT 1 FROM control.store_retirement_outcome WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.lifecycle_revision:=openpc.store_retirement_lifecycle_revision(a.participant_id,a.privacy_domain_id);
 IF NEW.lifecycle_revision<>a.lifecycle_revision THEN
  expected:=jsonb_build_object('reason','LIFECYCLE_CHANGED','revision',NEW.lifecycle_revision::text);
 ELSIF a.dispatch_not_after_ms<=floor(extract(epoch from clock_timestamp())*1000) THEN
  expected:=jsonb_build_object('reason','AUTHORITY_EXPIRED','dispatchNotAfterMs',a.dispatch_not_after_ms::text);
 ELSIF EXISTS(SELECT 1 FROM control.store_retirement_delivery WHERE participant_id=a.participant_id
   AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id AND purpose='REQUEST') THEN
  expected:=jsonb_build_object('reason','RECONCILE_UNKNOWN');
 ELSE RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NEW.cause IS DISTINCT FROM expected OR NEW.lifecycle_revision<a.lifecycle_revision THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.committed_digest:=encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','OPENPC_STORE_RETIREMENT_CANCELLATION_V1','participantId',a.participant_id::text,'privacyDomainId',a.privacy_domain_id::text,
  'hostDigest',a.host_digest,'attemptDigest',a.attempt_digest,'cancellationId',NEW.cancellation_id::text,
  'lifecycleRevision',NEW.lifecycle_revision::text,'cause',expected)),'UTF8')),'hex');
 NEW.committed_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS store_retirement_cancellation_guard ON control.store_retirement_cancellation;
CREATE TRIGGER store_retirement_cancellation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.store_retirement_cancellation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_store_retirement_cancellation();

CREATE OR REPLACE FUNCTION openpc.guard_store_retirement_delivery()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.store_retirement_admission; c control.store_retirement_cancellation;
 claims jsonb; signed jsonb; host jsonb; receipt text; expected jsonb; now_ms numeric;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.store_retirement_admission WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id AND xmin<>pg_current_xact_id()::xid;
 -- Identity locks precede the lifecycle fence. Cancellation has no new execution
 -- authority and can resolve an expired or revoked original grant.
 IF NEW.purpose='REQUEST' THEN PERFORM openpc.lock_store_retirement_authority(a.attempt_id);
 ELSE PERFORM openpc.lock_store_retirement_workload(a.host_digest); END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||a.participant_id::text,0));
 PERFORM openpc.verify_store_retirement_commit(a.participant_id,a.privacy_domain_id,a.host_digest,'DELIVERY',
  sha256(sha256(a.attempt_wire)||sha256(NEW.signed_wire)),NEW.verification_nonce,NEW.verification_mac);
 IF EXISTS(SELECT 1 FROM control.store_retirement_outcome WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 signed:=convert_from(NEW.signed_wire,'UTF8')::jsonb; claims:=signed->'claims';
 SELECT convert_from(host_wire,'UTF8')::jsonb INTO STRICT host FROM control.store_retirement_host
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND host_digest=a.host_digest;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF NEW.issued_at_ms>now_ms OR NEW.expires_at_ms<=now_ms OR NEW.expires_at_ms-NEW.issued_at_ms NOT BETWEEN 1 AND 60000
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 expected:=jsonb_build_object('version',1,'host',host,'attempt',convert_from(a.attempt_wire,'UTF8')::jsonb,
  'issued_at_ms',NEW.issued_at_ms,'expires_at_ms',NEW.expires_at_ms);
 IF NEW.purpose='REQUEST' THEN
  IF signed->>'purpose' IS DISTINCT FROM 'openpc:store-retirement-request:v1'
   OR NEW.expires_at_ms>a.dispatch_not_after_ms
   OR openpc.store_retirement_source_binding(a.retention_policy_id,decode(a.source_binding->>'selectionWireHex','hex'),a.source_binding->'recordRefs')
     IS DISTINCT FROM a.source_binding
   OR EXISTS(SELECT 1 FROM control.store_retirement_cancellation WHERE participant_id=a.participant_id
     AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT encode(receipt_digest,'hex') INTO STRICT receipt FROM control.audit_occurrence
   WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id
    AND aggregate_type='store-retirement' AND aggregate_id=a.attempt_id AND profile_id='pc.control.store-retirement.admit';
  expected:=expected||jsonb_build_object('admission_receipt_digest',receipt,'committed_admission_digest',openpc.store_retirement_committed_digest(a));
 ELSIF NEW.purpose='CANCEL' THEN
  SELECT * INTO STRICT c FROM control.store_retirement_cancellation WHERE participant_id=a.participant_id
   AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id AND xmin<>pg_current_xact_id()::xid;
  IF signed->>'purpose' IS DISTINCT FROM 'openpc:store-retirement-cancel:v1' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  expected:=expected||jsonb_build_object('cancellation_id',c.cancellation_id::text,'lifecycle_revision',c.lifecycle_revision,
    'committed_cancellation_digest',c.committed_digest);
 ELSE RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF claims IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.committed_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS store_retirement_delivery_guard ON control.store_retirement_delivery;
CREATE TRIGGER store_retirement_delivery_guard BEFORE INSERT OR UPDATE OR DELETE ON control.store_retirement_delivery
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_store_retirement_delivery();

CREATE OR REPLACE FUNCTION openpc.guard_store_retirement_outcome()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.store_retirement_admission; signed jsonb; claims jsonb; effect jsonb; host jsonb; expected jsonb; selected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.store_retirement_admission WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id AND xmin<>pg_current_xact_id()::xid;
 PERFORM openpc.lock_store_retirement_workload(a.host_digest);
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||a.participant_id::text,0));
 PERFORM openpc.verify_store_retirement_commit(a.participant_id,a.privacy_domain_id,a.host_digest,'OUTCOME',
  sha256(sha256(a.attempt_wire)||sha256(NEW.signed_wire)),NEW.verification_nonce,NEW.verification_mac);
 signed:=convert_from(NEW.signed_wire,'UTF8')::jsonb; claims:=signed->'claims'; effect:=claims->'outcome'->'effect';
 SELECT convert_from(host_wire,'UTF8')::jsonb INTO STRICT host FROM control.store_retirement_host
  WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND host_digest=a.host_digest;
 expected:=jsonb_build_object('version',1,'host',host,'business_intent_id',a.retirement_id::text,'attempt_id',a.attempt_id::text,
  'outcome',jsonb_build_object('attempt_digest',a.attempt_digest,'effect',effect),'completed_at_ms',NEW.completed_at_ms);
 IF signed->>'purpose' IS DISTINCT FROM 'openpc:store-retirement-outcome:v1' OR claims IS DISTINCT FROM expected
  OR effect->>'state' IS DISTINCT FROM NEW.state THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NEW.state='APPLIED' THEN
  selected:=convert_from(a.attempt_wire,'UTF8')::jsonb->'selection'->'rows';
  IF effect IS DISTINCT FROM jsonb_build_object('state','APPLIED','retired_rows',jsonb_array_length(selected),
    'retired_payload_bytes',(SELECT sum((row->>'payload_bytes')::numeric) FROM jsonb_array_elements(selected) row),
    'retained_lineage_digest',effect->>'retained_lineage_digest','outbox_event_digest',effect->>'outbox_event_digest')
   OR coalesce(effect->>'retained_lineage_digest','')!~'^[0-9a-f]{64}$'
   OR coalesce(effect->>'outbox_event_digest','')!~'^[0-9a-f]{64}$'
   OR NOT EXISTS(SELECT 1 FROM control.store_retirement_delivery WHERE participant_id=a.participant_id
    AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id AND purpose='REQUEST') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSIF NEW.state='CANCELLED_NO_EFFECT' THEN
  IF effect IS DISTINCT FROM jsonb_build_object('state','CANCELLED_NO_EFFECT')
   OR NOT EXISTS(SELECT 1 FROM control.store_retirement_cancellation WHERE participant_id=a.participant_id
    AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSIF NEW.state='REJECTED_NO_EFFECT' THEN
  IF effect IS DISTINCT FROM jsonb_build_object('state','REJECTED_NO_EFFECT','rejection',effect->>'rejection')
   OR coalesce(effect->>'rejection','') NOT IN ('SOURCE_CHANGED','GENERATION_CHANGED','REORG_FENCED','CHECKPOINT_INCOMPLETE',
    'READINESS_PROTECTED','PUBLICATION_PROTECTED','REFERENCES_PROTECTED','RETENTION_NOT_ELAPSED','ARCHIVE_MISMATCH','GOVERNANCE_CHANGED')
   OR NOT EXISTS(SELECT 1 FROM control.store_retirement_delivery WHERE participant_id=a.participant_id
    AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id AND purpose='REQUEST') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.recorded_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS store_retirement_outcome_guard ON control.store_retirement_outcome;
CREATE TRIGGER store_retirement_outcome_guard BEFORE INSERT OR UPDATE OR DELETE ON control.store_retirement_outcome
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_store_retirement_outcome();
`;
