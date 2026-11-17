/** Cross-store authority is an immutable governed admission. These guards never
 * interpret an absent outcome, a lease, or a transport ACK as a physical effect. */
export const storeRetirementGuardsSql = `
ALTER TABLE control.store_retirement_host FORCE ROW LEVEL SECURITY;
ALTER TABLE control.store_retirement_admission FORCE ROW LEVEL SECURITY;
ALTER TABLE control.store_retirement_cancellation FORCE ROW LEVEL SECURITY;
ALTER TABLE control.store_retirement_delivery FORCE ROW LEVEL SECURITY;
ALTER TABLE control.store_retirement_outcome FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.store_retirement_host,control.store_retirement_admission,
 control.store_retirement_cancellation,control.store_retirement_delivery,control.store_retirement_outcome,
 control.store_retirement_verifier_key FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.store_retirement_host,control.store_retirement_admission,
 control.store_retirement_cancellation,control.store_retirement_delivery,control.store_retirement_outcome
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.store_retirement_admission TO openpc_control_runtime;
GRANT INSERT ON control.store_retirement_cancellation,control.store_retirement_delivery,control.store_retirement_outcome TO openpc_control_worker;

${['admission', 'cancellation', 'delivery', 'outcome']
  .map(
    (name) => `
GRANT SELECT ON control.store_retirement_${name} TO openpc_control_owner;
DROP POLICY IF EXISTS retirement_owner_read ON control.store_retirement_${name};
CREATE POLICY retirement_owner_read ON control.store_retirement_${name} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));`,
  )
  .join('\n')}

${['host', 'verifier_key']
  .map(
    (name) => `
ALTER TABLE control.store_retirement_${name} FORCE ROW LEVEL SECURITY;
GRANT SELECT,INSERT ON control.store_retirement_${name} TO openpc_control_owner,openpc_control_key_governor;
DROP POLICY IF EXISTS retirement_installation ON control.store_retirement_${name};
CREATE POLICY retirement_installation ON control.store_retirement_${name} TO openpc_control_owner,openpc_control_key_governor USING(true) WITH CHECK(true);
DROP TRIGGER IF EXISTS retirement_installation ON control.store_retirement_${name};
CREATE TRIGGER retirement_installation BEFORE INSERT OR UPDATE OR DELETE ON control.store_retirement_${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_installation();`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.lock_store_retirement_workload(host text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE t control.store_retirement_host; now_ms numeric:=floor(extract(epoch from clock_timestamp())*1000);
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT t FROM control.store_retirement_host WHERE host_digest=host
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 IF session_user<>t.database_role OR now_ms<t.valid_from_ms OR now_ms>=t.valid_until_ms THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.participant p WHERE p.participant_id=t.participant_id AND p.state='ACTIVE' AND p.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.privacy_domain p WHERE p.participant_id=t.participant_id AND p.privacy_domain_id=t.privacy_domain_id AND p.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
  WHERE c.participant_id=t.participant_id AND c.credential_id=t.workload_credential_id
   AND c.credential_epoch=t.workload_credential_epoch AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC')
   AND c.state='ACTIVE' AND w.kind='WORKLOAD' AND w.state='ACTIVE'
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND c.public_key_digest IS DISTINCT FROM sha256(t.control_spki) AND c.public_key_digest IS DISTINCT FROM sha256(t.target_spki)
  FOR SHARE OF c,w;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
END $$;
ALTER FUNCTION openpc.lock_store_retirement_workload(text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_store_retirement_workload(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_store_retirement_workload(text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.verify_store_retirement_commit(p uuid,d uuid,host text,
 domain text,binding bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; different integer:=0;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF p IS DISTINCT FROM current_setting('openpc.participant_id')::uuid
  OR d IS DISTINCT FROM current_setting('openpc.privacy_domain_id')::uuid
  OR domain NOT IN ('SOURCE','DELIVERY','OUTCOME') OR domain IS NULL
  OR octet_length(nonce) IS DISTINCT FROM 32 OR octet_length(mac) IS DISTINCT FROM 32
  OR octet_length(binding) IS DISTINCT FROM 32 OR host!~'^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF domain='SOURCE' THEN
  IF NOT pg_has_role(session_user,'openpc_control_runtime','USAGE')
   OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 ELSE PERFORM openpc.lock_store_retirement_workload(host); END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.store_retirement_verifier_key
  WHERE participant_id=p AND privacy_domain_id=d AND host_digest=host;
 expected:=public.hmac(convert_to('OPENPC_STORE_RETIREMENT_'||domain||'_COMMIT_V1','UTF8')
  ||uuid_send(p)||uuid_send(d)||decode(host,'hex')||binding||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different | (get_byte(expected,n) # get_byte(mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
END $$;
ALTER FUNCTION openpc.verify_store_retirement_commit(uuid,uuid,text,text,bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.verify_store_retirement_commit(uuid,uuid,text,text,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.verify_store_retirement_commit(uuid,uuid,text,text,bytea,bytea,bytea) TO openpc_control_runtime,openpc_control_worker;

-- Both existing mutable owners take the same participant lifecycle fence. Their
-- immutable versions/revisions form a monotonic scoped generation; deleted or
-- caller-supplied epoch rows cannot reset it. Root Participant holds remain visible.
CREATE OR REPLACE FUNCTION openpc.store_retirement_lifecycle_revision(p uuid,d uuid)
RETURNS numeric LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 1+coalesce((SELECT sum(revision) FROM control.retention_hold
  WHERE participant_id=p AND (selector_type='PARTICIPANT' OR privacy_domain_id=d)),0)
  +coalesce((SELECT sum(revision) FROM control.retention_policy WHERE participant_id=p AND privacy_domain_id=d),0)
$$;
REVOKE ALL ON FUNCTION openpc.store_retirement_lifecycle_revision(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.store_retirement_lifecycle_revision(uuid,uuid) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.store_retirement_state_projection(a control.store_retirement_admission)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_bytes(decode((a).host_digest,'hex')),
  '1',openpc.business_bytes(decode((a).attempt_digest,'hex')),
  '2',openpc.business_bytes(decode((a).selection_digest,'hex')),
  '3',openpc.business_bytes(decode(substring((a).source_binding_digest from 8),'hex')),
  '4',openpc.business_uuid((a).retention_policy_id),'5',openpc.business_uuid((a).approval_request_id),
  '6',openpc.business_uuid((a).operation_id),'7',openpc.business_uuid((a).retirement_id),
  '8',CASE WHEN (a).previous_attempt_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((a).previous_attempt_id) END,
  '9',(a).lifecycle_revision,'10',floor(extract(epoch from (a).admitted_at)*1000000)*1000,
  '11',(a).dispatch_not_after_ms)
$$;
REVOKE ALL ON FUNCTION openpc.store_retirement_state_projection(control.store_retirement_admission) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.store_retirement_state_projection(control.store_retirement_admission) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.assert_store_retirement_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF receipt.profile_id<>'pc.control.store-retirement.admit' OR receipt.catalog_operation_id<>'CFG-OP-ADMIT-STORE-RETIREMENT'
  OR receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_existence<>1 OR receipt.after_revision<>1
  OR openpc.business_cbor(receipt.before_state_preimage)->8 IS DISTINCT FROM '{}'::jsonb
  OR NOT EXISTS(SELECT 1 FROM control.store_retirement_admission a WHERE a.participant_id=receipt.participant_id
    AND a.privacy_domain_id=receipt.privacy_domain_id AND a.attempt_id=receipt.aggregate_id AND a.operation_id=receipt.operation_id
    AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.store_retirement_state_projection(a))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-STORE-ADMISSION'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_store_retirement_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_store_retirement_receipt(control.audit_occurrence) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.require_store_retirement_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE matched integer;
BEGIN
 SELECT count(*) INTO matched FROM control.mutation_evidence e JOIN control.mutation_candidate c
  ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.resource_id=e.aggregate_id AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.audit_occurrence receipt ON receipt.participant_id=e.participant_id AND receipt.privacy_domain_id=e.privacy_domain_id
   AND receipt.operation_id=e.operation_id AND receipt.aggregate_id=e.aggregate_id AND receipt.aggregate_type='store-retirement'
  JOIN control.idempotency_record i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   AND i.operation_id=e.operation_id AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
 WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id AND e.operation_id=NEW.operation_id
  AND e.approval_request_id=NEW.approval_request_id AND e.aggregate_type='store-retirement' AND e.aggregate_id=NEW.attempt_id
  AND e.catalog_operation_id='CFG-OP-ADMIT-STORE-RETIREMENT' AND e.action_intent_id='ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1'
  AND c.catalog_operation_id=e.catalog_operation_id AND c.action_intent_id=e.action_intent_id AND c.state='CONSUMED' AND c.expected_revision=0
  AND c.candidate_document->'sourceBinding'=NEW.source_binding AND c.candidate_document->>'hostDigest'=NEW.host_digest
  AND c.candidate_document->>'retentionPolicyId'='urn:openpc:resource:'||NEW.retention_policy_id::text
  AND c.candidate_document->'previousAttemptId'=coalesce(to_jsonb('urn:openpc:resource:'||NEW.previous_attempt_id::text),'null'::jsonb)
  AND i.terminal_state='COMMITTED' AND i.expected_aggregate_version=0
  AND receipt.profile_id='pc.control.store-retirement.admit' AND receipt.catalog_operation_id=e.catalog_operation_id
  AND receipt.action_intent_id=e.action_intent_id AND receipt.before_existence=0 AND receipt.before_revision=0
  AND receipt.after_existence=1 AND receipt.after_revision=1
  AND openpc.business_cbor(receipt.before_state_preimage)->8='{}'::jsonb
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.store_retirement_state_projection(NEW)
  AND (SELECT count(*) FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
    AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
    AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor))=1;
 IF matched<>1 THEN RAISE EXCEPTION 'PC-AUTH-0002-STORE-RETIREMENT-SIGNED-ADMISSION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS store_retirement_command_required ON control.store_retirement_admission;
CREATE CONSTRAINT TRIGGER store_retirement_command_required AFTER INSERT ON control.store_retirement_admission
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_store_retirement_command();
`;
