/** Denial-only settlement of an authenticated, expired local effect. The
 * confirmed active pointer, original signatures and no-effect retry contract
 * remain distinct from the installed predecessor projection. */
export const expiredActivationGuardsSql = `
ALTER TABLE control.runtime_expired_activation_denial FORCE ROW LEVEL SECURITY;
ALTER TABLE control.runtime_denied_predecessor FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.runtime_expired_activation_denial,control.runtime_denied_predecessor
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.runtime_expired_activation_denial TO openpc_control_worker;
GRANT SELECT ON control.runtime_denied_predecessor TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;
GRANT INSERT ON control.runtime_denied_predecessor TO openpc_control_worker;
DROP POLICY IF EXISTS runtime_expired_denial_owner_select ON control.runtime_expired_activation_denial;
CREATE POLICY runtime_expired_denial_owner_select ON control.runtime_expired_activation_denial
 FOR SELECT TO openpc_control_owner USING(participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id()
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
DROP POLICY IF EXISTS runtime_expired_denial_owner_insert ON control.runtime_expired_activation_denial;
CREATE POLICY runtime_expired_denial_owner_insert ON control.runtime_expired_activation_denial
 FOR INSERT TO openpc_control_owner WITH CHECK(participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id()
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
DROP POLICY IF EXISTS runtime_denied_predecessor_owner_select ON control.runtime_denied_predecessor;
CREATE POLICY runtime_denied_predecessor_owner_select ON control.runtime_denied_predecessor
 FOR SELECT TO openpc_control_owner USING(participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id()
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');

CREATE OR REPLACE FUNCTION openpc.expired_activation_state_digest(wanted uuid)
RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'work',to_jsonb(w),'target',to_jsonb(t),'generation',to_jsonb(g),'observation',to_jsonb(o),
  'head',to_jsonb(a),'delivery',to_jsonb(d),'acknowledgement',to_jsonb(k))),'UTF8')),'hex')
 FROM control.configuration_work w
 JOIN control.runtime_target t USING(participant_id,privacy_domain_id,runtime_target_id)
 JOIN control.runtime_configuration_generation g ON g.participant_id=w.participant_id
  AND g.privacy_domain_id=w.privacy_domain_id AND g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
 JOIN control.runtime_activation_observation o ON o.configuration_work_id=w.configuration_work_id
  AND o.participant_id=w.participant_id AND o.privacy_domain_id=w.privacy_domain_id
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=w.participant_id
  AND a.privacy_domain_id=w.privacy_domain_id AND a.runtime_target_id=w.runtime_target_id
  AND a.revision=(SELECT max(h.revision) FROM control.runtime_target_disposition_admission h
   WHERE h.participant_id=w.participant_id AND h.privacy_domain_id=w.privacy_domain_id AND h.runtime_target_id=w.runtime_target_id)
 JOIN control.runtime_target_disposition_delivery d ON d.participant_id=a.participant_id
  AND d.privacy_domain_id=a.privacy_domain_id AND d.runtime_target_id=a.runtime_target_id AND d.revision=a.revision
 JOIN control.runtime_target_disposition_acknowledgement k ON k.participant_id=d.participant_id
  AND k.privacy_domain_id=d.privacy_domain_id AND k.runtime_target_id=d.runtime_target_id AND k.delivery_digest=d.delivery_digest
 WHERE w.configuration_work_id=wanted AND w.participant_id=openpc.current_participant_id()
  AND w.privacy_domain_id=openpc.current_privacy_domain_id()
$$;
REVOKE ALL ON FUNCTION openpc.expired_activation_state_digest(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_activation_state_digest(uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.begin_expired_activation_denial(proof_wire bytea,nonce bytea,mac bytea)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0;
 pid uuid; privacy uuid; target uuid; w control.configuration_work; t control.runtime_target;
 o control.runtime_activation_observation; g control.runtime_configuration_generation;
 input control.runtime_configuration_input; head control.runtime_target_disposition_admission;
 delivery control.runtime_target_disposition_delivery; acknowledgement control.runtime_target_disposition_acknowledgement;
 authority record; principal uuid; source jsonb; identity jsonb; material jsonb; digest text; inputs uuid[];
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed'
  OR proof_wire IS NULL OR octet_length(proof_wire) NOT BETWEEN 2 AND 131072
  OR nonce IS NULL OR octet_length(nonce)<>32 OR mac IS NULL OR octet_length(mac)<>32
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_EXPIRED_ACTIVATION_DENIAL_V1','UTF8')||sha256(proof_wire)||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different|(get_byte(expected,n)#get_byte(mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 proof:=convert_from(proof_wire,'UTF8')::jsonb;
 IF proof IS DISTINCT FROM jsonb_build_object('version',1,'transactionId',pg_current_xact_id()::text,
  'intent',proof->'intent','intentBytesHex',proof->'intentBytesHex','intentDigest',proof->'intentDigest',
  'source',proof->'source','target',proof->'target','capsuleGeneration',proof->'capsuleGeneration',
  'capsuleNotBeforeNs',proof->'capsuleNotBeforeNs','capsuleExpiresAtNs',proof->'capsuleExpiresAtNs',
  'observedAtNs',proof->'observedAtNs','receiptWireDigest',proof->'receiptWireDigest','tokenDigest',proof->'tokenDigest')
  OR proof->'intent'->>'purpose' IS DISTINCT FROM 'EXPIRED_OBSERVED_DENIAL_V1'
  OR coalesce(proof->'intent'->>'requestId','') !~ '^[0-9a-f-]{36}$'
  OR coalesce(proof->'intent'->>'issuedAtMs','') !~ '^[0-9]{1,16}$'
  OR coalesce(proof->'intent'->>'expiresAtMs','') !~ '^[0-9]{1,16}$'
  OR (proof->'intent'->>'issuedAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric-(proof->'intent'->>'issuedAtMs')::numeric NOT BETWEEN 1 AND 120000
  OR proof->'intent'->'custody'->>'databaseRole' IS DISTINCT FROM session_user::text
  OR proof->'intent'->'custody'->>'workerRole' IS DISTINCT FROM 'openpc_control_worker'
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR pg_has_role(session_user,'openpc_control_owner','USAGE')
  OR coalesce(proof->>'intentBytesHex','') !~ '^[0-9a-f]+$'
  OR length(proof->>'intentBytesHex') NOT BETWEEN 4 AND 32768
  OR length(proof->>'intentBytesHex')%2<>0
  OR convert_from(decode(proof->>'intentBytesHex','hex'),'UTF8')::jsonb IS DISTINCT FROM proof->'intent'
  OR proof->>'intentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(proof->>'intentBytesHex','hex')),'hex')
  OR coalesce(proof->>'capsuleGeneration','') !~ '^[1-9][0-9]{0,17}$'
  OR EXISTS(SELECT 1 FROM (VALUES('capsuleNotBeforeNs'),('capsuleExpiresAtNs'),('observedAtNs')) n(k)
   WHERE coalesce(proof->>n.k,'') !~ '^[1-9][0-9]{0,19}$' OR (proof->>n.k)::numeric>18446744073709551615)
  OR (proof->>'capsuleNotBeforeNs')::numeric>(proof->>'observedAtNs')::numeric
  OR (proof->>'observedAtNs')::numeric>=(proof->>'capsuleExpiresAtNs')::numeric
  OR (proof->>'capsuleExpiresAtNs')::numeric>extract(epoch from clock_timestamp())*1000000000
 THEN RAISE EXCEPTION 'EXPIRED-ACTIVATION-PROOF'; END IF;
 pid:=openpc.current_participant_id();privacy:=openpc.current_privacy_domain_id();
 target:=(proof->'target'->>'target_id')::uuid;
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,
  'sha256:'||(proof->'target'->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c
  WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 identity:=jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,'target_id',target::text,
  'credential_id',authority.credential_id::text,'principal_id',principal::text,
  'credential_epoch',authority.credential_epoch,'principal_epoch',authority.principal_epoch,
  'certificate_digest',proof->'target'->>'certificate_digest');
 IF identity IS DISTINCT FROM proof->'target' THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT t FROM control.runtime_target WHERE runtime_target_id=target
  AND participant_id=pid AND privacy_domain_id=privacy FOR UPDATE NOWAIT;
 SELECT * INTO STRICT w FROM control.configuration_work
  WHERE configuration_work_id=(proof->'intent'->'custody'->>'workId')::uuid
   AND participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target FOR UPDATE NOWAIT;
 SELECT * INTO STRICT g FROM control.runtime_configuration_generation
  WHERE runtime_configuration_generation_id=w.runtime_configuration_generation_id
   AND participant_id=pid AND privacy_domain_id=privacy FOR UPDATE NOWAIT;
 SELECT * INTO STRICT o FROM control.runtime_activation_observation
  WHERE configuration_work_id=w.configuration_work_id AND participant_id=pid AND privacy_domain_id=privacy;
 IF w.state<>'RECONCILING' OR w.reconcile_after IS DISTINCT FROM 'infinity'::timestamptz
  OR w.lease_owner IS NOT NULL OR w.lease_until IS NOT NULL OR w.result_event_id IS NOT NULL OR w.completed_at IS NOT NULL
  OR w.execution_attempt_id IS NULL OR w.execution_started_at IS NULL OR w.predecessor_digest IS NULL
  OR w.work_kind<>'RUNTIME_ACTIVATION' OR g.state<>'ACTIVATING' OR g.activated_at IS NOT NULL
  OR t.state<>'STAGING' OR t.active_generation_digest IS DISTINCT FROM w.predecessor_digest
  OR t.desired_generation_digest IS DISTINCT FROM w.generation_digest
  OR o.operation_id<>w.operation_id OR o.execution_attempt_id<>w.execution_attempt_id
  OR o.runtime_configuration_generation_id<>w.runtime_configuration_generation_id
  OR o.runtime_target_id<>target OR o.generation_digest<>w.generation_digest OR o.xds_version_digest<>w.xds_version_digest
  OR (o.activation_receipt->>'capsuleGeneration')::bigint<>(proof->>'capsuleGeneration')::bigint
  OR proof->>'receiptWireDigest' IS DISTINCT FROM encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')
  OR EXISTS(SELECT 1 FROM control.policy_activation_occurrence_target c WHERE c.configuration_work_id=w.configuration_work_id)
  OR NOT EXISTS(SELECT 1 FROM control.mutation_evidence a JOIN control.idempotency_record i
    ON i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id AND i.operation_id=a.operation_id
   WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.operation_id=w.operation_id
    AND a.aggregate_id=target AND a.catalog_operation_id='CFG-OP-UPDATE-RUNTIME-TARGET'
    AND a.action_intent_id='ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1' AND octet_length(a.cose_sign1)>0
    AND i.terminal_state='COMMITTED' AND i.input_digest=a.candidate_digest)
 THEN RAISE EXCEPTION 'EXPIRED-ACTIVATION-ORIGINAL'; END IF;
 SELECT * INTO STRICT head FROM control.runtime_target_disposition_admission
  WHERE participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target ORDER BY revision DESC LIMIT 1;
 SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery
  WHERE participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target AND revision=head.revision;
 SELECT * INTO STRICT acknowledgement FROM control.runtime_target_disposition_acknowledgement
  WHERE participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target AND delivery_digest=delivery.delivery_digest;
 IF head.revision<>(proof->'intent'->'custody'->>'dispositionRevision')::bigint
  OR head.binding->>'action'<>'Withdraw'
  OR head.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',NULL)
  OR head.binding->'source'->>'capsule_digest' IS DISTINCT FROM substring(w.predecessor_digest from 8)
  OR acknowledgement.claims->>'installed_state'<>'NewUseDenied'
  OR proof->'intent'->'custody'->>'deliveryDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(delivery.signed_delivery),'hex')
  OR proof->'intent'->'custody'->>'acknowledgementDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(acknowledgement.signed_acknowledgement),'hex')
  OR openpc.expired_activation_state_digest(w.configuration_work_id)
    IS DISTINCT FROM proof->'intent'->'custody'->>'originalStateDigest'
 THEN RAISE EXCEPTION 'EXPIRED-ACTIVATION-HEAD'; END IF;
 SELECT array_agg(runtime_configuration_input_id) INTO inputs FROM control.runtime_configuration_input
  WHERE participant_id=pid AND privacy_domain_id=privacy AND configuration_digest=decode(substring(w.configuration_digest from 8),'hex');
 IF cardinality(inputs) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-INPUT-CARDINALITY'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE runtime_configuration_input_id=inputs[1];
 source:=jsonb_build_object('runtime_configuration_input_id',input.runtime_configuration_input_id::text,
  'configuration_digest',encode(input.configuration_digest,'hex'),'module_installation_id',input.module_installation_id::text,
  'module_configuration_generation_id',input.module_configuration_generation_id::text,
  'runtime_configuration_generation_id',w.runtime_configuration_generation_id::text,
  'capsule_digest',substring(o.capsule_digest from 8),'xds_version_digest',substring(w.xds_version_digest from 8),
  'predecessor_capsule_digest',substring(w.predecessor_digest from 8),'original_work_id',w.configuration_work_id::text,
  'original_operation_id',w.operation_id::text,'original_execution_attempt_id',w.execution_attempt_id::text);
 IF source IS DISTINCT FROM proof->'source' OR proof->'intent'->'custody'->>'capsuleDigest' IS DISTINCT FROM o.capsule_digest
  OR proof->'intent'->'custody'->>'receiptDigest' IS DISTINCT FROM o.activation_receipt_digest
  OR proof->'intent'->'custody'->>'schemaVersion' IS DISTINCT FROM '1'
  OR proof->'intent'->'custody'->>'participantId' IS DISTINCT FROM pid::text
  OR proof->'intent'->'custody'->>'privacyDomainId' IS DISTINCT FROM privacy::text
  OR proof->'intent'->'custody'->>'runtimeTargetId' IS DISTINCT FROM target::text
  OR proof->'intent'->'custody'->>'generationId' IS DISTINCT FROM w.runtime_configuration_generation_id::text
  OR proof->'intent'->'custody'->>'generationDigest' IS DISTINCT FROM w.generation_digest
  OR proof->'intent'->'custody'->>'configurationDigest' IS DISTINCT FROM w.configuration_digest
  OR proof->'intent'->'custody'->>'xdsVersionDigest' IS DISTINCT FROM w.xds_version_digest
  OR proof->'intent'->'custody'->>'occurrenceId' IS DISTINCT FROM w.configuration_work_id::text

  OR proof->'intent'->'custody'->>'executionAttemptId' IS DISTINCT FROM w.execution_attempt_id::text
  OR proof->'intent'->'custody'->>'operationId' IS DISTINCT FROM w.operation_id::text
  OR (proof->'intent'->'custody'->>'claimCount')::bigint IS DISTINCT FROM w.attempt_count
 THEN RAISE EXCEPTION 'EXPIRED-ACTIVATION-BINDING'; END IF;
 material:=jsonb_build_object('version',1,'action','Withdraw','revision',head.revision+1,
  'previous_revision',head.revision,'previous_delivery_digest',substring(delivery.delivery_digest from 8),
  'target',identity,'source',source,'cause',jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',w.execution_attempt_id::text));
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(material),'UTF8')),'hex');
 -- Locks and custody checks may consume the short operator window.
 IF (proof->'intent'->>'issuedAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
 THEN RAISE EXCEPTION 'EXPIRED-ACTIVATION-OPERATOR-WINDOW'; END IF;
 INSERT INTO control.runtime_expired_activation_denial(configuration_work_id,request_id,participant_id,privacy_domain_id,runtime_target_id,
  execution_attempt_id,admission_revision,admission_digest,capsule_digest,capsule_generation,proof,intent_bytes,intent_digest)
 VALUES(w.configuration_work_id,(proof->'intent'->>'requestId')::uuid,pid,privacy,target,w.execution_attempt_id,head.revision+1,digest,o.capsule_digest,
  (proof->>'capsuleGeneration')::bigint,proof,decode(proof->>'intentBytesHex','hex'),proof->>'intentDigest');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,admission_digest)
 VALUES(pid,privacy,target,head.revision+1,material,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_expired_activation_denial(bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_expired_activation_denial(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_expired_activation_denial(bytea,bytea,bytea) TO openpc_control_worker;

-- This exception admits signing only the exact new negative delivery. It cannot
-- construct a permit, repeat a signature, or authorize CONFIRM/RESTORE.
CREATE OR REPLACE FUNCTION openpc.expired_denial_issuance_matches(target uuid,revision bigint,digest text,worker text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.runtime_expired_activation_denial e
 JOIN control.configuration_work w USING(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,execution_attempt_id)
 JOIN control.runtime_activation_observation o USING(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,execution_attempt_id)
 JOIN control.runtime_target t USING(participant_id,privacy_domain_id,runtime_target_id)
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=e.participant_id
  AND a.privacy_domain_id=e.privacy_domain_id AND a.runtime_target_id=e.runtime_target_id AND a.revision=e.admission_revision
 WHERE e.participant_id=openpc.current_participant_id() AND e.privacy_domain_id=openpc.current_privacy_domain_id()
  AND e.runtime_target_id=$1 AND e.admission_revision=$2 AND e.admission_digest=$3
  AND e.proof->'intent'->'custody'->>'workerId'=$4
  AND (e.proof->'intent'->>'issuedAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
  AND (e.proof->'intent'->>'expiresAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  AND e.capsule_digest=o.capsule_digest AND e.execution_attempt_id=w.execution_attempt_id
  AND w.state='RECONCILING' AND w.reconcile_after='infinity'::timestamptz AND w.lease_owner IS NULL AND w.lease_until IS NULL
  AND w.result_event_id IS NULL AND w.completed_at IS NULL AND t.state='STAGING'
  AND t.active_generation_digest=w.predecessor_digest AND t.desired_generation_digest=w.generation_digest
  AND a.binding->>'action'='Withdraw' AND a.binding->'source'->>'original_work_id'=w.configuration_work_id::text
  AND a.binding->'source'->>'capsule_digest'=substring(e.capsule_digest from 8)
  AND a.binding->'cause'=jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',w.execution_attempt_id::text)
  AND a.revision=(SELECT max(h.revision) FROM control.runtime_target_disposition_admission h
   WHERE h.participant_id=e.participant_id AND h.privacy_domain_id=e.privacy_domain_id AND h.runtime_target_id=e.runtime_target_id))
$$;
REVOKE ALL ON FUNCTION openpc.expired_denial_issuance_matches(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_denial_issuance_matches(uuid,bigint,text,text) TO openpc_control_owner,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_denied_predecessor()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-IMMUTABLE'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_user<>session_user OR current_setting('role')<>'none'
  OR NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR pg_has_role(current_user,'openpc_control_owner','USAGE')
  OR current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
  OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
  OR NOT EXISTS(SELECT 1 FROM control.runtime_expired_activation_denial e
   LEFT JOIN control.runtime_expired_denial_handover h ON h.configuration_work_id=e.configuration_work_id
    AND h.participant_id=e.participant_id AND h.privacy_domain_id=e.privacy_domain_id AND h.runtime_target_id=e.runtime_target_id
   JOIN control.configuration_work w ON w.configuration_work_id=e.configuration_work_id AND w.participant_id=e.participant_id
    AND w.privacy_domain_id=e.privacy_domain_id AND w.runtime_target_id=e.runtime_target_id AND w.execution_attempt_id=e.execution_attempt_id
   JOIN control.runtime_activation_observation o ON o.configuration_work_id=w.configuration_work_id AND o.participant_id=w.participant_id
    AND o.privacy_domain_id=w.privacy_domain_id AND o.runtime_target_id=w.runtime_target_id AND o.execution_attempt_id=w.execution_attempt_id
   JOIN control.runtime_configuration_generation g ON g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
    AND g.participant_id=w.participant_id AND g.privacy_domain_id=w.privacy_domain_id
   JOIN control.runtime_target t ON t.participant_id=w.participant_id AND t.privacy_domain_id=w.privacy_domain_id
    AND t.runtime_target_id=w.runtime_target_id
   JOIN control.runtime_target_disposition_admission a ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
    AND a.runtime_target_id=e.runtime_target_id AND a.revision=coalesce(h.admission_revision,e.admission_revision)
   JOIN control.runtime_target_disposition_delivery d ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
    AND d.runtime_target_id=a.runtime_target_id AND d.revision=a.revision
   JOIN control.runtime_target_disposition_acknowledgement k ON k.participant_id=d.participant_id AND k.privacy_domain_id=d.privacy_domain_id
    AND k.runtime_target_id=d.runtime_target_id AND k.delivery_digest=d.delivery_digest
   JOIN control.outbox_event event ON event.event_id=w.result_event_id AND event.participant_id=w.participant_id
    AND event.privacy_domain_id=w.privacy_domain_id AND event.aggregate_id=w.runtime_target_id
   JOIN control.mutation_evidence approval ON approval.participant_id=w.participant_id
    AND approval.privacy_domain_id=w.privacy_domain_id AND approval.operation_id=w.operation_id
   WHERE e.configuration_work_id=NEW.configuration_work_id AND e.participant_id=NEW.participant_id
    AND e.privacy_domain_id=NEW.privacy_domain_id AND e.runtime_target_id=NEW.runtime_target_id
    AND e.proof->'intent'->'custody'->>'databaseRole'=current_user::text
    AND e.capsule_digest=NEW.capsule_digest AND e.capsule_generation=NEW.capsule_generation
    AND w.predecessor_digest=NEW.last_confirmed_capsule_digest AND w.xds_version_digest=NEW.xds_version_digest
    AND w.state='FAILED' AND w.xmin=pg_current_xact_id()::xid AND w.completed_at IS NOT NULL
    AND w.reconcile_after IS NULL AND w.lease_owner IS NULL AND w.lease_until IS NULL
    AND w.result_event_id=NEW.result_event_id AND g.state='FAILED' AND g.activated_at IS NULL
    AND t.state='FAILED' AND t.active_generation_digest=NEW.last_confirmed_capsule_digest AND t.desired_generation_digest IS NULL
    AND w.result_receipt=jsonb_build_object('outcome','EXPIRED_OBSERVED_DENIED','errorCode','PC-RUNTIME-3002',
     'observedEffect',true,'runtimeNewUse','DENIED','capsuleDigest',e.capsule_digest,
     'originalReceiptDigest',o.activation_receipt_digest,'denialDeliveryDigest',d.delivery_digest,
     'denialAcknowledgementDigest','sha256:'||encode(sha256(k.signed_acknowledgement),'hex'),
     'terminal',true,'resourceId',w.runtime_target_id::text,'workKind','RUNTIME_ACTIVATION')
    AND w.result_receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(w.result_receipt),'UTF8')),'hex')
    AND event.event_type='runtime-target.activation-expired-denied.v1' AND event.aggregate_type='runtime-targets'
    AND event.payload_cbor=convert_to(openpc.signing_canonical_json(w.result_receipt),'UTF8')
    AND event.payload_digest=sha256(event.payload_cbor) AND event.cose_sign1=approval.cose_sign1
    AND octet_length(approval.cose_sign1)>0
    AND a.revision=NEW.denial_revision AND a.admission_digest=coalesce(h.admission_digest,e.admission_digest) AND a.binding->>'action'='Withdraw'
    AND a.binding->'source'->>'original_work_id'=w.configuration_work_id::text
    AND a.binding->'source'->>'capsule_digest'=substring(e.capsule_digest from 8)
    AND ((h.configuration_work_id IS NULL AND a.binding->'cause'=jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
     'operation_id',w.operation_id::text,'execution_attempt_id',w.execution_attempt_id::text))
     OR (h.configuration_work_id IS NOT NULL AND h.abandoned_revision=e.admission_revision
      AND h.abandoned_admission_digest=e.admission_digest AND h.admission_revision=h.abandoned_revision+1
      AND (a.binding->'cause'->>'kind'='ExpiredObservedDenialHandover'
       OR (a.binding->'cause'->>'kind'='ExpiredObservedCredentialDenialHandover'
        AND h.proof->'intent'->>'purpose'='EXPIRED_OBSERVED_CREDENTIAL_DENIAL_HANDOVER_V1'
        AND a.binding->'target'=h.proof->'target'
        AND a.binding->'cause'->'abandoned_target'=e.proof->'target'
        AND a.binding->'cause'->>'credential_rotation_operation_id'=h.proof->'intent'->'credentialTransition'->>'rotationOperationId'))
      AND a.binding->'cause'->>'abandoned_admission_digest'=substring(e.admission_digest from 8)
      AND a.binding->'cause'->>'original_receipt_wire_digest'=e.proof->>'receiptWireDigest'))
    AND a.revision=(SELECT max(h.revision) FROM control.runtime_target_disposition_admission h
     WHERE h.participant_id=e.participant_id AND h.privacy_domain_id=e.privacy_domain_id AND h.runtime_target_id=e.runtime_target_id)
    AND d.delivery_digest=NEW.delivery_digest AND k.claims->>'installed_state'='NewUseDenied'
    AND NEW.acknowledgement_digest='sha256:'||encode(sha256(k.signed_acknowledgement),'hex'))
 THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-ORIGINAL'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_denied_predecessor() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_runtime_denied_predecessor() TO openpc_control_worker;
DROP TRIGGER IF EXISTS runtime_denied_predecessor_guard ON control.runtime_denied_predecessor;
CREATE TRIGGER runtime_denied_predecessor_guard BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_denied_predecessor
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_denied_predecessor();
DROP TRIGGER IF EXISTS runtime_denied_predecessor_truncate ON control.runtime_denied_predecessor;
CREATE TRIGGER runtime_denied_predecessor_truncate BEFORE TRUNCATE ON control.runtime_denied_predecessor
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_runtime_denied_predecessor();
DROP TRIGGER IF EXISTS runtime_expired_activation_denial_immutable ON control.runtime_expired_activation_denial;
CREATE TRIGGER runtime_expired_activation_denial_immutable BEFORE UPDATE OR DELETE ON control.runtime_expired_activation_denial
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS runtime_expired_activation_denial_truncate ON control.runtime_expired_activation_denial;
CREATE TRIGGER runtime_expired_activation_denial_truncate BEFORE TRUNCATE ON control.runtime_expired_activation_denial
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

-- Returns one exact, acknowledged physical cursor only while it is still the
-- installed predecessor. No latest-observation fallback or serving authority.
CREATE OR REPLACE FUNCTION openpc.runtime_denied_predecessor(target uuid)
RETURNS SETOF control.runtime_denied_predecessor LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE result control.runtime_denied_predecessor; found_count integer:=0;
BEGIN
 PERFORM openpc.assert_request_context(false);
 FOR result IN SELECT c.* FROM control.runtime_denied_predecessor c
 JOIN control.runtime_target t USING(participant_id,privacy_domain_id,runtime_target_id)
 JOIN control.configuration_work w ON w.configuration_work_id=c.configuration_work_id
  AND w.participant_id=c.participant_id AND w.privacy_domain_id=c.privacy_domain_id
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
  AND a.runtime_target_id=c.runtime_target_id AND a.revision=(SELECT max(h.revision)
   FROM control.runtime_target_disposition_admission h WHERE h.participant_id=c.participant_id
    AND h.privacy_domain_id=c.privacy_domain_id AND h.runtime_target_id=c.runtime_target_id)
 WHERE c.participant_id=openpc.current_participant_id() AND c.privacy_domain_id=openpc.current_privacy_domain_id()
  AND c.runtime_target_id=target AND t.active_generation_digest=c.last_confirmed_capsule_digest AND w.state='FAILED'
  AND w.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
  AND a.binding->>'action'='Withdraw' AND a.binding->'source'->>'capsule_digest'=substring(c.capsule_digest from 8)
  AND a.binding->'source'->>'original_work_id'=w.configuration_work_id::text
  AND NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation newer
   WHERE newer.participant_id=c.participant_id AND newer.privacy_domain_id=c.privacy_domain_id
    AND newer.runtime_target_id=c.runtime_target_id AND newer.configuration_work_id<>c.configuration_work_id
    AND newer.observed_at>c.created_at)
 LOOP
  found_count:=found_count+1;
  IF found_count>1 THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-CARDINALITY'; END IF;
  RETURN NEXT result;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_denied_predecessor(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_denied_predecessor(uuid) TO openpc_control_runtime,openpc_control_reader,openpc_control_worker,openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.runtime_installed_predecessor(target uuid)
RETURNS text LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installed text; confirmed text;
BEGIN
 SELECT c.capsule_digest INTO installed FROM openpc.runtime_denied_predecessor(target) c;
 IF FOUND THEN RETURN installed; END IF;
 SELECT t.active_generation_digest INTO STRICT confirmed FROM control.runtime_target t
  WHERE t.participant_id=openpc.current_participant_id() AND t.privacy_domain_id=openpc.current_privacy_domain_id()
   AND t.runtime_target_id=target;
 -- A missing current cursor is not proof the old confirmed capsule is installed.
 -- Only a genuinely completed later effect can supersede the physical denial.
 IF EXISTS(SELECT 1 FROM control.runtime_denied_predecessor c
  WHERE c.participant_id=openpc.current_participant_id() AND c.privacy_domain_id=openpc.current_privacy_domain_id()
   AND c.runtime_target_id=target AND NOT EXISTS(
    SELECT 1 FROM control.configuration_work w JOIN control.runtime_activation_observation o
     USING(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,execution_attempt_id)
    WHERE w.participant_id=c.participant_id AND w.privacy_domain_id=c.privacy_domain_id AND w.runtime_target_id=c.runtime_target_id
     AND w.state='COMPLETED' AND w.completed_at>c.created_at AND o.observed_at>c.created_at
     AND o.capsule_digest=confirmed AND w.result_event_id IS NOT NULL))
 THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-UNAVAILABLE'; END IF;
 RETURN confirmed;
END $$;
REVOKE ALL ON FUNCTION openpc.runtime_installed_predecessor(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_installed_predecessor(uuid) TO openpc_control_runtime,openpc_control_reader,openpc_control_worker,openpc_control_owner;

-- A queued replacement keeps its exact cursor link through its own Withdraw
-- and Confirm transitions. A newer unrelated effect or head invalidates it.
CREATE OR REPLACE FUNCTION openpc.runtime_work_predecessor_matches(wanted uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN w.denied_predecessor_work_id IS NULL THEN t.active_generation_digest IS NOT DISTINCT FROM w.predecessor_digest
 ELSE EXISTS(SELECT 1 FROM control.runtime_denied_predecessor c
  JOIN control.configuration_work original ON original.configuration_work_id=c.configuration_work_id
   AND original.participant_id=c.participant_id AND original.privacy_domain_id=c.privacy_domain_id
  WHERE c.configuration_work_id=w.denied_predecessor_work_id AND c.participant_id=w.participant_id
   AND c.privacy_domain_id=w.privacy_domain_id AND c.runtime_target_id=w.runtime_target_id
   AND c.capsule_digest=w.predecessor_digest AND c.last_confirmed_capsule_digest=t.active_generation_digest
   AND w.created_at>=c.created_at AND original.state='FAILED'
   AND original.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
   AND NOT EXISTS(SELECT 1 FROM control.runtime_activation_observation newer
    WHERE newer.participant_id=c.participant_id AND newer.privacy_domain_id=c.privacy_domain_id
     AND newer.runtime_target_id=c.runtime_target_id AND newer.observed_at>c.created_at
     AND newer.configuration_work_id<>w.configuration_work_id)
   AND EXISTS(SELECT 1 FROM control.runtime_target_disposition_admission a
    WHERE a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id AND a.runtime_target_id=c.runtime_target_id
     AND a.revision=(SELECT max(h.revision) FROM control.runtime_target_disposition_admission h
      WHERE h.participant_id=c.participant_id AND h.privacy_domain_id=c.privacy_domain_id AND h.runtime_target_id=c.runtime_target_id)
     AND ((a.binding->>'action'='Withdraw' AND a.binding->'source'->>'capsule_digest'=substring(c.capsule_digest from 8)
       AND a.binding->'source'->>'original_work_id'=c.configuration_work_id::text
       AND (a.revision=c.denial_revision OR a.binding->'cause'->>'work_id'=w.configuration_work_id::text))
      OR(a.binding->>'action'='ConfirmActivation' AND a.binding->'source'->>'original_work_id'=w.configuration_work_id::text
       AND a.binding->'cause'->>'execution_attempt_id'=w.execution_attempt_id::text)))) END
 FROM control.configuration_work w JOIN control.runtime_target t USING(participant_id,privacy_domain_id,runtime_target_id)
 WHERE w.configuration_work_id=wanted AND w.participant_id=openpc.current_participant_id()
  AND w.privacy_domain_id=openpc.current_privacy_domain_id()
$$;
REVOKE ALL ON FUNCTION openpc.runtime_work_predecessor_matches(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_work_predecessor_matches(uuid) TO openpc_control_worker,openpc_control_runtime,openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.guard_denied_predecessor_work_link()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE cursor_row control.runtime_denied_predecessor;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.denied_predecessor_work_id IS DISTINCT FROM OLD.denied_predecessor_work_id
   THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-LINK-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.work_kind<>'RUNTIME_ACTIVATION' THEN
  IF NEW.denied_predecessor_work_id IS NOT NULL THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-KIND'; END IF;
  RETURN NEW;
 END IF;
 -- Direct queue inserts must not bypass the candidate's unresolved-cursor fence.
 IF EXISTS(SELECT 1 FROM control.runtime_denied_predecessor c
  WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.runtime_target_id=NEW.runtime_target_id)
 THEN PERFORM openpc.runtime_installed_predecessor(NEW.runtime_target_id); END IF;
 SELECT * INTO cursor_row FROM openpc.runtime_denied_predecessor(NEW.runtime_target_id);
 IF NEW.denied_predecessor_work_id IS NULL THEN
  IF FOUND THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-LINK-REQUIRED'; END IF;
 ELSE
  IF NOT FOUND OR NEW.denied_predecessor_work_id IS DISTINCT FROM cursor_row.configuration_work_id
   OR NEW.participant_id IS DISTINCT FROM cursor_row.participant_id
   OR NEW.privacy_domain_id IS DISTINCT FROM cursor_row.privacy_domain_id
   OR NEW.predecessor_digest IS DISTINCT FROM cursor_row.capsule_digest
   OR NEW.created_at<cursor_row.created_at OR NEW.state<>'PENDING'
   OR NEW.execution_attempt_id IS NOT NULL OR NEW.execution_started_at IS NOT NULL
   OR openpc.current_action_intent_id()<>'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1'
   OR current_setting('transaction_isolation')<>'serializable'
  THEN RAISE EXCEPTION 'DENIED-PREDECESSOR-LINK'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_denied_predecessor_work_link() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_denied_predecessor_work_link() TO openpc_control_runtime,openpc_control_worker;
DROP TRIGGER IF EXISTS configuration_work_denied_predecessor_link ON control.configuration_work;
CREATE TRIGGER configuration_work_denied_predecessor_link BEFORE INSERT OR UPDATE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_denied_predecessor_work_link();
`;
