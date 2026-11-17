/** One negative handover preserves the original unsigned admission and never
 * recreates its permit. Ordinary no-effect recovery remains a separate owner. */
export const expiredDenialHandoverGuardsSql = `
ALTER TABLE control.runtime_expired_denial_handover FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.runtime_expired_denial_handover FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.runtime_expired_denial_handover TO openpc_control_worker;
DROP POLICY IF EXISTS runtime_expired_handover_owner_select ON control.runtime_expired_denial_handover;
CREATE POLICY runtime_expired_handover_owner_select ON control.runtime_expired_denial_handover
 FOR SELECT TO openpc_control_owner USING(participant_id=openpc.current_participant_id()
 AND privacy_domain_id=openpc.current_privacy_domain_id()
 AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
DROP POLICY IF EXISTS runtime_expired_handover_owner_insert ON control.runtime_expired_denial_handover;
CREATE POLICY runtime_expired_handover_owner_insert ON control.runtime_expired_denial_handover
 FOR INSERT TO openpc_control_owner WITH CHECK(participant_id=openpc.current_participant_id()
 AND privacy_domain_id=openpc.current_privacy_domain_id()
 AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
DROP TRIGGER IF EXISTS runtime_expired_handover_immutable ON control.runtime_expired_denial_handover;
CREATE TRIGGER runtime_expired_handover_immutable BEFORE UPDATE OR DELETE ON control.runtime_expired_denial_handover
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS runtime_expired_handover_truncate ON control.runtime_expired_denial_handover;
CREATE TRIGGER runtime_expired_handover_truncate BEFORE TRUNCATE ON control.runtime_expired_denial_handover
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_mutation();

CREATE OR REPLACE FUNCTION openpc.expired_denial_handover_state_digest(wanted uuid)
RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
 'originalDenial',to_jsonb(e),'work',to_jsonb(w),'target',to_jsonb(t),'generation',to_jsonb(g),
 'observation',to_jsonb(o),'abandoned',to_jsonb(a),'previous',to_jsonb(p),
 'previousDelivery',to_jsonb(d),'previousAcknowledgement',to_jsonb(k))),'UTF8')),'hex')
 FROM control.runtime_expired_activation_denial e
 JOIN control.configuration_work w USING(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,execution_attempt_id)
 JOIN control.runtime_target t USING(participant_id,privacy_domain_id,runtime_target_id)
 JOIN control.runtime_configuration_generation g ON g.participant_id=w.participant_id AND g.privacy_domain_id=w.privacy_domain_id
  AND g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
 JOIN control.runtime_activation_observation o ON o.configuration_work_id=w.configuration_work_id
  AND o.participant_id=w.participant_id AND o.privacy_domain_id=w.privacy_domain_id
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
  AND a.runtime_target_id=e.runtime_target_id AND a.revision=e.admission_revision AND a.admission_digest=e.admission_digest
 JOIN control.runtime_target_disposition_admission p ON p.participant_id=a.participant_id AND p.privacy_domain_id=a.privacy_domain_id
  AND p.runtime_target_id=a.runtime_target_id AND p.revision=a.revision-1
 JOIN control.runtime_target_disposition_delivery d ON d.participant_id=p.participant_id AND d.privacy_domain_id=p.privacy_domain_id
  AND d.runtime_target_id=p.runtime_target_id AND d.revision=p.revision
 JOIN control.runtime_target_disposition_acknowledgement k ON k.participant_id=d.participant_id AND k.privacy_domain_id=d.privacy_domain_id
  AND k.runtime_target_id=d.runtime_target_id AND k.delivery_digest=d.delivery_digest
 WHERE e.configuration_work_id=wanted AND e.participant_id=openpc.current_participant_id()
  AND e.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.revision=(SELECT max(h.revision)FROM control.runtime_target_disposition_admission h
   WHERE h.participant_id=a.participant_id AND h.privacy_domain_id=a.privacy_domain_id AND h.runtime_target_id=a.runtime_target_id)
  AND NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery x WHERE x.participant_id=a.participant_id
   AND x.privacy_domain_id=a.privacy_domain_id AND x.runtime_target_id=a.runtime_target_id AND x.revision=a.revision)
  AND NOT EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h WHERE h.configuration_work_id=e.configuration_work_id)
$$;
REVOKE ALL ON FUNCTION openpc.expired_denial_handover_state_digest(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_denial_handover_state_digest(uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.begin_expired_denial_handover(proof_wire bytea,nonce bytea,mac bytea)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0;
 pid uuid; privacy uuid; target uuid; w control.configuration_work; t control.runtime_target;
 e control.runtime_expired_activation_denial; o control.runtime_activation_observation; g control.runtime_configuration_generation;
 abandoned control.runtime_target_disposition_admission; previous control.runtime_target_disposition_admission;
 delivery control.runtime_target_disposition_delivery; acknowledgement control.runtime_target_disposition_acknowledgement;
 authority record; principal uuid; identity jsonb; material jsonb; digest text; h jsonb; floor jsonb;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR current_setting('transaction_isolation')<>'read committed' OR proof_wire IS NULL
  OR octet_length(proof_wire) NOT BETWEEN 2 AND 131072 OR nonce IS NULL OR octet_length(nonce)<>32
  OR mac IS NULL OR octet_length(mac)<>32 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_EXPIRED_UNSIGNED_DENIAL_HANDOVER_V1','UTF8')||sha256(proof_wire)||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different|(get_byte(expected,n)#get_byte(mac,n));END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005';END IF;
 proof:=convert_from(proof_wire,'UTF8')::jsonb;
 IF proof IS DISTINCT FROM jsonb_build_object('version',1,'transactionId',pg_current_xact_id()::text,
  'intent',proof->'intent','intentBytesHex',proof->'intentBytesHex','intentDigest',proof->'intentDigest',
  'source',proof->'source','target',proof->'target','capsuleGeneration',proof->'capsuleGeneration',
  'capsuleNotBeforeNs',proof->'capsuleNotBeforeNs','capsuleExpiresAtNs',proof->'capsuleExpiresAtNs',
  'observedAtNs',proof->'observedAtNs','receiptWireDigest',proof->'receiptWireDigest','tokenDigest',proof->'tokenDigest')
  OR proof->'intent' IS DISTINCT FROM jsonb_build_object('purpose','EXPIRED_OBSERVED_UNSIGNED_DENIAL_HANDOVER_V1',
   'requestId',proof->'intent'->'requestId','issuedAtMs',proof->'intent'->'issuedAtMs',
   'expiresAtMs',proof->'intent'->'expiresAtMs','custody',proof->'intent'->'custody','handover',proof->'intent'->'handover')
  OR coalesce(proof->'intent'->>'requestId','') !~ '^[0-9a-f-]{36}$'
  OR coalesce(proof->'intent'->>'issuedAtMs','') !~ '^[0-9]{1,16}$'
  OR coalesce(proof->'intent'->>'expiresAtMs','') !~ '^[0-9]{1,16}$'
  OR (proof->'intent'->>'issuedAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
  OR (proof->'intent'->>'expiresAtMs')::numeric-(proof->'intent'->>'issuedAtMs')::numeric NOT BETWEEN 1 AND 120000
  OR proof->'intent'->'custody'->>'databaseRole' IS DISTINCT FROM session_user::text
  OR proof->'intent'->'custody'->>'workerRole' IS DISTINCT FROM 'openpc_control_worker'
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE') OR pg_has_role(session_user,'openpc_control_owner','USAGE')
  OR coalesce(proof->>'intentBytesHex','') !~ '^[0-9a-f]+$' OR length(proof->>'intentBytesHex') NOT BETWEEN 4 AND 32768
  OR length(proof->>'intentBytesHex')%2<>0
  OR convert_from(decode(proof->>'intentBytesHex','hex'),'UTF8')::jsonb IS DISTINCT FROM proof->'intent'
  OR proof->>'intentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(proof->>'intentBytesHex','hex')),'hex')
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-PROOF';END IF;
 h:=proof->'intent'->'handover';floor:=h->'floor';
 IF h IS DISTINCT FROM jsonb_build_object('abandonedRevision',h->'abandonedRevision',
  'abandonedAdmissionDigest',h->'abandonedAdmissionDigest','floor',floor)
  OR floor IS DISTINCT FROM jsonb_build_object('installedRevision',floor->'installedRevision',
   'installedDeliveryDigest',floor->'installedDeliveryDigest','observedRevision',floor->'observedRevision',
   'observedAdmissionDigest',floor->'observedAdmissionDigest','originalReceiptWireDigest',floor->'originalReceiptWireDigest')
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-FLOOR';END IF;
 pid:=openpc.current_participant_id();privacy:=openpc.current_privacy_domain_id();target:=(proof->'target'->>'target_id')::uuid;
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,'sha256:'||(proof->'target'->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 identity:=jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,'target_id',target::text,
  'credential_id',authority.credential_id::text,'principal_id',principal::text,'credential_epoch',authority.credential_epoch,
  'principal_epoch',authority.principal_epoch,'certificate_digest',proof->'target'->>'certificate_digest');
 IF identity IS DISTINCT FROM proof->'target' THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY';END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007';END IF;
 SELECT * INTO STRICT e FROM control.runtime_expired_activation_denial WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_target_id=target AND configuration_work_id=(proof->'intent'->'custody'->>'workId')::uuid FOR SHARE NOWAIT;
 SELECT * INTO STRICT w FROM control.configuration_work WHERE configuration_work_id=e.configuration_work_id
  AND participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target FOR UPDATE NOWAIT;
 SELECT * INTO STRICT t FROM control.runtime_target WHERE participant_id=pid AND privacy_domain_id=privacy AND runtime_target_id=target FOR UPDATE NOWAIT;
 SELECT * INTO STRICT g FROM control.runtime_configuration_generation WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_configuration_generation_id=w.runtime_configuration_generation_id FOR SHARE NOWAIT;
 SELECT * INTO STRICT o FROM control.runtime_activation_observation WHERE configuration_work_id=w.configuration_work_id
  AND participant_id=pid AND privacy_domain_id=privacy;
 IF w.state IS DISTINCT FROM 'RECONCILING' OR w.reconcile_after IS DISTINCT FROM 'infinity'::timestamptz
  OR w.execution_attempt_id IS DISTINCT FROM e.execution_attempt_id OR w.execution_started_at IS NULL
  OR w.lease_owner IS NOT NULL OR w.lease_until IS NOT NULL OR w.result_event_id IS NOT NULL OR w.completed_at IS NOT NULL
  OR w.work_kind IS DISTINCT FROM 'RUNTIME_ACTIVATION' OR g.state IS DISTINCT FROM 'ACTIVATING' OR g.activated_at IS NOT NULL
  OR t.state IS DISTINCT FROM 'STAGING' OR t.active_generation_digest IS DISTINCT FROM w.predecessor_digest
  OR t.desired_generation_digest IS DISTINCT FROM w.generation_digest
  OR o.execution_attempt_id IS DISTINCT FROM w.execution_attempt_id OR o.capsule_digest IS DISTINCT FROM e.capsule_digest
  OR proof->>'receiptWireDigest' IS DISTINCT FROM e.proof->>'receiptWireDigest'
  OR proof->>'receiptWireDigest' IS DISTINCT FROM encode(sha256(decode(o.activation_receipt->>'activationReceiptCoseHex','hex')),'hex')
  OR proof->>'tokenDigest' IS DISTINCT FROM e.proof->>'tokenDigest'
  OR EXISTS(SELECT 1 FROM (VALUES('capsuleGeneration'),('capsuleNotBeforeNs'),('capsuleExpiresAtNs'),('observedAtNs'))n(k)
   WHERE proof->>n.k IS DISTINCT FROM e.proof->>n.k)
  OR (proof->>'capsuleExpiresAtNs')::numeric>extract(epoch from clock_timestamp())*1000000000
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-ORIGINAL';END IF;
 SELECT * INTO STRICT abandoned FROM control.runtime_target_disposition_admission WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_target_id=target ORDER BY revision DESC LIMIT 1 FOR UPDATE NOWAIT;
 SELECT * INTO STRICT previous FROM control.runtime_target_disposition_admission WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_target_id=target AND revision=e.admission_revision-1 FOR SHARE NOWAIT;
 SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_target_id=target AND revision=previous.revision;
 SELECT * INTO STRICT acknowledgement FROM control.runtime_target_disposition_acknowledgement WHERE participant_id=pid AND privacy_domain_id=privacy
  AND runtime_target_id=target AND delivery_digest=delivery.delivery_digest;
 IF abandoned.revision IS DISTINCT FROM e.admission_revision::numeric OR abandoned.admission_digest IS DISTINCT FROM e.admission_digest
  OR h->'abandonedRevision' IS DISTINCT FROM to_jsonb(e.admission_revision)
  OR h->>'abandonedAdmissionDigest' IS DISTINCT FROM substring(e.admission_digest from 8)
  OR abandoned.binding->>'action' IS DISTINCT FROM 'Withdraw' OR previous.binding->>'action' IS DISTINCT FROM 'Withdraw'
  OR abandoned.binding->'target' IS DISTINCT FROM identity OR previous.binding->'target' IS DISTINCT FROM identity
  OR abandoned.binding->'source' IS DISTINCT FROM proof->'source'
  OR abandoned.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',w.execution_attempt_id::text)
  OR previous.binding->'cause' IS DISTINCT FROM jsonb_build_object('kind','Activation','work_id',w.configuration_work_id::text,
   'operation_id',w.operation_id::text,'execution_attempt_id',NULL)
  OR abandoned.binding->'previous_revision' IS DISTINCT FROM to_jsonb(previous.revision)
  OR abandoned.binding->>'previous_delivery_digest' IS DISTINCT FROM substring(delivery.delivery_digest from 8)
  OR previous.binding->'source'->>'capsule_digest' IS DISTINCT FROM substring(w.predecessor_digest from 8)
  OR acknowledgement.claims->>'installed_state' IS DISTINCT FROM 'NewUseDenied'
  OR floor->'installedRevision' IS DISTINCT FROM to_jsonb(previous.revision)
  OR floor->>'installedDeliveryDigest' IS DISTINCT FROM substring(delivery.delivery_digest from 8)
  OR floor->'observedRevision' IS DISTINCT FROM to_jsonb(abandoned.revision)
  OR floor->>'observedAdmissionDigest' IS DISTINCT FROM substring(abandoned.admission_digest from 8)
  OR floor->>'originalReceiptWireDigest' IS DISTINCT FROM proof->>'receiptWireDigest'
  OR EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery x WHERE x.participant_id=pid AND x.privacy_domain_id=privacy
   AND x.runtime_target_id=target AND x.revision=e.admission_revision)
  OR EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover x WHERE x.configuration_work_id=w.configuration_work_id)
  OR proof->'intent'->'custody'->>'originalStateDigest' IS DISTINCT FROM openpc.expired_denial_handover_state_digest(w.configuration_work_id)
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-HEAD';END IF;
 IF EXISTS(SELECT 1 FROM (VALUES('workId',w.configuration_work_id::text),('operationId',w.operation_id::text),
  ('executionAttemptId',w.execution_attempt_id::text),('participantId',pid::text),('privacyDomainId',privacy::text),
  ('runtimeTargetId',target::text),('generationId',w.runtime_configuration_generation_id::text),('generationDigest',w.generation_digest),
  ('configurationDigest',w.configuration_digest),('xdsVersionDigest',w.xds_version_digest),('capsuleDigest',o.capsule_digest),
  ('receiptDigest',o.activation_receipt_digest),('occurrenceId',w.configuration_work_id::text),('schemaVersion','1'),
  ('deliveryDigest',delivery.delivery_digest),('acknowledgementDigest','sha256:'||encode(sha256(acknowledgement.signed_acknowledgement),'hex'))
 )n(k,v)WHERE proof->'intent'->'custody'->>n.k IS DISTINCT FROM n.v)
  OR (proof->'intent'->'custody'->>'claimCount')::bigint IS DISTINCT FROM w.attempt_count
  OR (proof->'intent'->'custody'->>'dispositionRevision')::numeric IS DISTINCT FROM previous.revision
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-BINDING';END IF;
 material:=jsonb_build_object('version',1,'action','Withdraw','revision',abandoned.revision+1,
  'previous_revision',previous.revision,'previous_delivery_digest',substring(delivery.delivery_digest from 8),
  'target',abandoned.binding->'target','source',abandoned.binding->'source','cause',jsonb_build_object(
   'kind','ExpiredObservedDenialHandover','work_id',w.configuration_work_id::text,'operation_id',w.operation_id::text,
   'execution_attempt_id',w.execution_attempt_id::text,'abandoned_revision',abandoned.revision,
   'abandoned_admission_digest',substring(abandoned.admission_digest from 8),'original_receipt_wire_digest',proof->>'receiptWireDigest',
   'installed_revision',previous.revision,'installed_delivery_digest',substring(delivery.delivery_digest from 8),
   'observed_revision',floor->'observedRevision','observed_admission_digest',floor->>'observedAdmissionDigest'));
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(material),'UTF8')),'hex');
 IF (proof->'intent'->>'expiresAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
 THEN RAISE EXCEPTION 'EXPIRED-HANDOVER-OPERATOR-WINDOW';END IF;
 INSERT INTO control.runtime_expired_denial_handover(configuration_work_id,request_id,participant_id,privacy_domain_id,runtime_target_id,
  abandoned_revision,abandoned_admission_digest,admission_revision,admission_digest,proof,intent_bytes,intent_digest)
 VALUES(w.configuration_work_id,(proof->'intent'->>'requestId')::uuid,pid,privacy,target,e.admission_revision,e.admission_digest,
  e.admission_revision+1,digest,proof,decode(proof->>'intentBytesHex','hex'),proof->>'intentDigest');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,admission_digest)
 VALUES(pid,privacy,target,e.admission_revision+1,material,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_expired_denial_handover(bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_expired_denial_handover(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_expired_denial_handover(bytea,bytea,bytea) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_handover_issuance_matches(target uuid,revision bigint,digest text,worker text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h
 JOIN control.runtime_expired_activation_denial e USING(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id)
 JOIN control.configuration_work w ON w.configuration_work_id=e.configuration_work_id AND w.participant_id=e.participant_id
  AND w.privacy_domain_id=e.privacy_domain_id AND w.runtime_target_id=e.runtime_target_id
 JOIN control.runtime_target t ON t.participant_id=w.participant_id AND t.privacy_domain_id=w.privacy_domain_id AND t.runtime_target_id=w.runtime_target_id
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=h.participant_id AND a.privacy_domain_id=h.privacy_domain_id
  AND a.runtime_target_id=h.runtime_target_id AND a.revision=h.admission_revision
 JOIN control.runtime_target_disposition_admission abandoned ON abandoned.participant_id=e.participant_id AND abandoned.privacy_domain_id=e.privacy_domain_id
  AND abandoned.runtime_target_id=e.runtime_target_id AND abandoned.revision=e.admission_revision
 WHERE h.participant_id=openpc.current_participant_id() AND h.privacy_domain_id=openpc.current_privacy_domain_id()
  AND h.runtime_target_id=$1 AND h.admission_revision=$2 AND h.admission_digest=$3
  AND h.proof->'intent'->'custody'->>'workerId'=$4
  AND (h.proof->'intent'->>'issuedAtMs')::numeric<=extract(epoch from clock_timestamp())*1000
  AND (h.proof->'intent'->>'expiresAtMs')::numeric>extract(epoch from clock_timestamp())*1000
  AND h.abandoned_revision=e.admission_revision AND h.abandoned_admission_digest=e.admission_digest
  AND h.admission_revision=h.abandoned_revision+1 AND abandoned.admission_digest=e.admission_digest
  AND a.binding->'source'=abandoned.binding->'source' AND a.binding->'target'=abandoned.binding->'target'
  AND a.binding->>'action'='Withdraw' AND a.binding->'cause'->>'kind'='ExpiredObservedDenialHandover'
  AND a.binding->'cause'->>'original_receipt_wire_digest'=e.proof->>'receiptWireDigest'
  AND a.admission_digest=h.admission_digest AND w.execution_attempt_id=e.execution_attempt_id
  AND w.state='RECONCILING' AND w.reconcile_after='infinity'::timestamptz AND w.lease_owner IS NULL AND w.lease_until IS NULL
  AND w.result_event_id IS NULL AND w.completed_at IS NULL AND t.state='STAGING'
  AND t.active_generation_digest=w.predecessor_digest AND t.desired_generation_digest=w.generation_digest
  AND NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_delivery d WHERE d.participant_id=e.participant_id
   AND d.privacy_domain_id=e.privacy_domain_id AND d.runtime_target_id=e.runtime_target_id AND d.revision=e.admission_revision)
  AND a.revision=(SELECT max(x.revision)FROM control.runtime_target_disposition_admission x WHERE x.participant_id=a.participant_id
   AND x.privacy_domain_id=a.privacy_domain_id AND x.runtime_target_id=a.runtime_target_id))
$$;
REVOKE ALL ON FUNCTION openpc.expired_handover_issuance_matches(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_handover_issuance_matches(uuid,bigint,text,text) TO openpc_control_owner,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_operator_issuance_window_matches(target uuid,revision bigint,digest text,worker text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM control.runtime_expired_activation_denial e
  WHERE e.participant_id=openpc.current_participant_id() AND e.privacy_domain_id=openpc.current_privacy_domain_id()
   AND e.runtime_target_id=$1 AND e.admission_revision=$2)
 THEN openpc.expired_denial_issuance_matches($1,$2,$3,$4)
 WHEN EXISTS(SELECT 1 FROM control.runtime_expired_denial_handover h
  WHERE h.participant_id=openpc.current_participant_id() AND h.privacy_domain_id=openpc.current_privacy_domain_id()
   AND h.runtime_target_id=$1 AND h.admission_revision=$2)
 THEN openpc.expired_handover_issuance_matches($1,$2,$3,$4) ELSE false END
$$;
REVOKE ALL ON FUNCTION openpc.expired_operator_issuance_window_matches(uuid,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_operator_issuance_window_matches(uuid,bigint,text,text) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.expired_denial_terminal_replay(wanted uuid,intent_digest text,intent_bytes bytea)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.runtime_expired_activation_denial e
 LEFT JOIN control.runtime_expired_denial_handover h ON h.configuration_work_id=e.configuration_work_id
  AND h.participant_id=e.participant_id AND h.privacy_domain_id=e.privacy_domain_id AND h.runtime_target_id=e.runtime_target_id
 JOIN control.runtime_denied_predecessor c ON c.configuration_work_id=e.configuration_work_id AND c.participant_id=e.participant_id
  AND c.privacy_domain_id=e.privacy_domain_id AND c.runtime_target_id=e.runtime_target_id
 JOIN control.configuration_work w ON w.configuration_work_id=e.configuration_work_id AND w.participant_id=e.participant_id
  AND w.privacy_domain_id=e.privacy_domain_id AND w.runtime_target_id=e.runtime_target_id AND w.execution_attempt_id=e.execution_attempt_id
 JOIN control.runtime_activation_observation o ON o.configuration_work_id=w.configuration_work_id AND o.participant_id=w.participant_id
  AND o.privacy_domain_id=w.privacy_domain_id AND o.execution_attempt_id=w.execution_attempt_id
 JOIN control.runtime_target_disposition_admission a ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id
  AND a.runtime_target_id=e.runtime_target_id AND a.revision=coalesce(h.admission_revision,e.admission_revision)
 JOIN control.runtime_target_disposition_delivery d ON d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
  AND d.runtime_target_id=a.runtime_target_id AND d.revision=a.revision
 JOIN control.runtime_target_disposition_acknowledgement k ON k.participant_id=d.participant_id AND k.privacy_domain_id=d.privacy_domain_id
  AND k.runtime_target_id=d.runtime_target_id AND k.delivery_digest=d.delivery_digest
 JOIN control.outbox_event event ON event.event_id=w.result_event_id AND event.participant_id=w.participant_id
  AND event.privacy_domain_id=w.privacy_domain_id AND event.aggregate_id=w.runtime_target_id
 WHERE e.configuration_work_id=$1 AND e.participant_id=openpc.current_participant_id() AND e.privacy_domain_id=openpc.current_privacy_domain_id()
  AND coalesce(h.intent_digest,e.intent_digest)=$2 AND coalesce(h.intent_bytes,e.intent_bytes)=$3
  AND w.state='FAILED' AND w.completed_at IS NOT NULL AND w.result_event_id=c.result_event_id
  AND w.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
  AND w.result_receipt->>'capsuleDigest'=c.capsule_digest AND c.capsule_digest=e.capsule_digest
  AND w.result_receipt->>'originalReceiptDigest'=o.activation_receipt_digest
  AND w.result_receipt->>'denialDeliveryDigest'=d.delivery_digest
  AND w.result_receipt->>'denialAcknowledgementDigest'='sha256:'||encode(sha256(k.signed_acknowledgement),'hex')
  AND w.result_receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(w.result_receipt),'UTF8')),'hex')
  AND event.event_type='runtime-target.activation-expired-denied.v1'
  AND event.payload_cbor=convert_to(openpc.signing_canonical_json(w.result_receipt),'UTF8') AND event.payload_digest=sha256(event.payload_cbor)
  AND a.admission_digest=coalesce(h.admission_digest,e.admission_digest) AND a.binding->>'action'='Withdraw'
  AND c.denial_revision=a.revision AND c.delivery_digest=d.delivery_digest
  AND c.acknowledgement_digest='sha256:'||encode(sha256(k.signed_acknowledgement),'hex')
  AND d.delivery_digest='sha256:'||encode(sha256(d.signed_delivery),'hex')
  AND k.claims->>'installed_state'='NewUseDenied')
$$;
REVOKE ALL ON FUNCTION openpc.expired_denial_terminal_replay(uuid,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.expired_denial_terminal_replay(uuid,text,bytea) TO openpc_control_worker;
`;
