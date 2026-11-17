export const storeRetirementAdmissionGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','STORE_RETIREMENT_ADMISSION'),
 ('ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1','evidence-deletions','UPDATE','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','STORE_RETIREMENT_RECONCILIATION')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','STORE_RETIREMENT_ADMISSION'),
  ('ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1','evidence-deletions','UPDATE','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','STORE_RETIREMENT_RECONCILIATION')))<>2
 THEN RAISE EXCEPTION 'PC-AUTH-0002-STORE-RETIREMENT-ACTION'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_store_retirement_host()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE host jsonb:=convert_from(NEW.host_wire,'UTF8')::jsonb;
BEGIN
 IF host IS DISTINCT FROM jsonb_build_object('environment_id',host->>'environment_id','target_id',host->>'target_id',
   'scope',jsonb_build_object('participant_id',NEW.participant_id::text,'privacy_domain_id',NEW.privacy_domain_id::text),'store',host->>'store')
  OR coalesce(host->>'environment_id','')!~'^[!-~]{1,160}$' OR coalesce(host->>'target_id','')!~'^[!-~]{1,160}$'
  OR coalesce(host->>'store','') NOT IN ('openpc_facts','openpc_candidate_index')
  OR encode(substring(NEW.control_spki from 1 for 27),'hex')<>'3059301306072a8648ce3d020106082a8648ce3d03010703420004'
  OR encode(substring(NEW.target_spki from 1 for 27),'hex')<>'3059301306072a8648ce3d020106082a8648ce3d03010703420004'
  OR NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=NEW.database_role AND r.rolcanlogin
   AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND pg_has_role(r.oid,'openpc_control_worker','USAGE')
   AND NOT pg_has_role(r.oid,'openpc_control_owner','MEMBER') AND NOT pg_has_role(r.oid,'openpc_control_key_governor','MEMBER'))
  OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
   WHERE c.participant_id=NEW.participant_id AND c.credential_id=NEW.workload_credential_id
    AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC') AND c.state='ACTIVE' AND c.credential_epoch=NEW.workload_credential_epoch
    AND w.kind='WORKLOAD' AND w.state='ACTIVE' AND c.valid_from<=clock_timestamp()
    AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
    AND c.public_key_digest IS DISTINCT FROM sha256(NEW.control_spki) AND c.public_key_digest IS DISTINCT FROM sha256(NEW.target_spki))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS store_retirement_host_binding ON control.store_retirement_host;
CREATE TRIGGER store_retirement_host_binding BEFORE INSERT ON control.store_retirement_host FOR EACH ROW EXECUTE FUNCTION openpc.guard_store_retirement_host();

CREATE OR REPLACE FUNCTION openpc.guard_store_retirement_admission()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE attempt jsonb; host jsonb; actual_binding jsonb; policy control.retention_policy;
 previous control.store_retirement_admission; decision_digest bytea; count_decisions integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR current_setting('openpc.operation_id')::uuid IS DISTINCT FROM NEW.operation_id
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1'
  OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 NEW.admitted_at:=clock_timestamp();
 IF NEW.dispatch_not_after_ms<=floor(extract(epoch from NEW.admitted_at)*1000)
  OR NEW.dispatch_not_after_ms>floor(extract(epoch from NEW.admitted_at)*1000)+60000
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.verify_store_retirement_commit(NEW.participant_id,NEW.privacy_domain_id,NEW.host_digest,'SOURCE',
  sha256(NEW.attempt_wire||convert_to(NEW.source_binding_digest,'UTF8')||uuid_send(NEW.operation_id)
   ||uuid_send(NEW.approval_request_id)||int8send(NEW.dispatch_not_after_ms::bigint)),NEW.verification_nonce,NEW.verification_mac);
 attempt:=convert_from(NEW.attempt_wire,'UTF8')::jsonb;
 SELECT convert_from(host_wire,'UTF8')::jsonb INTO STRICT host FROM control.store_retirement_host
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND host_digest=NEW.host_digest
   AND valid_from_ms<=floor(extract(epoch from NEW.admitted_at)*1000) AND valid_until_ms>=NEW.dispatch_not_after_ms;
 SELECT * INTO STRICT policy FROM control.retention_policy WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND retention_policy_id=NEW.retention_policy_id AND active_until IS NULL;
 actual_binding:=openpc.store_retirement_source_binding(NEW.retention_policy_id,
  decode(NEW.source_binding->>'selectionWireHex','hex'),NEW.source_binding->'recordRefs');
 IF NEW.source_binding IS DISTINCT FROM actual_binding
  OR NEW.source_binding_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(actual_binding),'UTF8')),'hex')
  OR attempt->'selection' IS DISTINCT FROM convert_from(decode(actual_binding->>'selectionWireHex','hex'),'UTF8')::jsonb
  OR attempt->'scope' IS DISTINCT FROM host->'scope' OR attempt->>'store' IS DISTINCT FROM host->>'store'
  OR attempt->>'business_intent_id' IS DISTINCT FROM NEW.retirement_id::text OR attempt->>'attempt_id' IS DISTINCT FROM NEW.attempt_id::text
  OR attempt->>'selection_digest' IS DISTINCT FROM NEW.selection_digest
  OR NEW.attempt_digest IS DISTINCT FROM encode(sha256(convert_to('["OPENPC_STORE_RETIREMENT_ATTEMPT_V1",','UTF8')||NEW.attempt_wire||convert_to(']','UTF8')),'hex')
  OR NEW.lifecycle_revision::text IS DISTINCT FROM actual_binding->>'lifecycleRevision'
  OR attempt#>>'{governance,lifecycle_revision}' IS DISTINCT FROM NEW.lifecycle_revision::text
  OR attempt#>>'{governance,retention_policy_digest}' IS DISTINCT FROM substring(policy.policy_digest from 8)
  OR attempt#>>'{governance,archive_manifest_digest}' IS DISTINCT FROM actual_binding->>'archiveManifestDigest'
  OR attempt#>>'{governance,archive_acknowledgement_digest}' IS DISTINCT FROM actual_binding->>'archiveAcknowledgementDigest'
  OR attempt#>>'{governance,retention_not_before_ms}' IS DISTINCT FROM actual_binding->>'retentionNotBeforeMs'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT count(*),decode(min(encode(d.decision_digest,'hex')),'hex') INTO count_decisions,decision_digest
  FROM control.approval_decision_record d JOIN control.approval_request a USING(participant_id,privacy_domain_id,approval_request_id)
  WHERE d.participant_id=NEW.participant_id AND d.privacy_domain_id=NEW.privacy_domain_id AND d.approval_request_id=NEW.approval_request_id
   AND d.decision='APPROVE' AND a.state='APPROVED' AND a.expires_at>NEW.admitted_at
   AND a.maker_principal_id<>d.approver_principal_id AND a.subject_digest=d.candidate_digest
   AND a.subject_version=d.aggregate_version;
 IF count_decisions<>1 OR attempt#>>'{governance,approval_digest}' IS DISTINCT FROM encode(decision_digest,'hex')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NEW.previous_attempt_id IS NULL THEN
  IF NEW.retirement_id<>NEW.attempt_id THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  SELECT a.* INTO STRICT previous FROM control.store_retirement_admission a JOIN control.store_retirement_outcome o
    USING(participant_id,privacy_domain_id,attempt_id)
   WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.attempt_id=NEW.previous_attempt_id
    AND o.state IN ('REJECTED_NO_EFFECT','CANCELLED_NO_EFFECT');
  IF previous.retirement_id<>NEW.retirement_id OR previous.host_digest<>NEW.host_digest OR previous.selection_digest<>NEW.selection_digest
   OR previous.approval_request_id=NEW.approval_request_id THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END IF;
 -- A fresh idempotency key cannot disguise another unresolved business intent.
 IF EXISTS(SELECT 1 FROM control.store_retirement_admission a LEFT JOIN control.store_retirement_outcome o
   USING(participant_id,privacy_domain_id,attempt_id)
   WHERE a.participant_id=NEW.participant_id AND a.privacy_domain_id=NEW.privacy_domain_id AND a.host_digest=NEW.host_digest
    AND (o.state IS NULL OR o.state='APPLIED') AND EXISTS(SELECT 1
      FROM jsonb_array_elements(convert_from(a.attempt_wire,'UTF8')::jsonb->'selection'->'rows') old_row,
       jsonb_array_elements(attempt->'selection'->'rows') new_row WHERE old_row->>'candidate_id'=new_row->>'candidate_id'))
 THEN RAISE EXCEPTION 'PC-DATA-6007-UNRESOLVED-OR-APPLIED'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS store_retirement_admission_guard ON control.store_retirement_admission;
CREATE TRIGGER store_retirement_admission_guard BEFORE INSERT OR UPDATE OR DELETE ON control.store_retirement_admission
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_store_retirement_admission();
`;
