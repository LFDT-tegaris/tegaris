/** Only the native current-source owner can attest restoration, and only in the
 * SAME transaction which holds those source locks. The attestation is not a
 * portable receipt: replay in another transaction is rejected before insertion.
 * This first owner admits terminal, provably unstarted successors only. */
export const targetDispositionRestoreSql = `
CREATE OR REPLACE FUNCTION openpc.begin_runtime_target_unstarted_restore(
 proof_wire bytea,nonce bytea,mac bytea)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0; pid uuid; privacy uuid; target uuid;
 head control.runtime_target_disposition_admission; delivery control.runtime_target_disposition_delivery;
 cause control.configuration_work; original control.configuration_work; current_target control.runtime_target;
 material jsonb; digest text; identity record; principal uuid;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR proof_wire IS NULL OR octet_length(proof_wire) NOT BETWEEN 1 AND 8192
  OR nonce IS NULL OR octet_length(nonce)<>32 OR mac IS NULL OR octet_length(mac)<>32
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_TARGET_DISPOSITION_RESTORE_ADMISSION_V1','UTF8')||sha256(proof_wire)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 proof:=convert_from(proof_wire,'UTF8')::jsonb;
 IF proof IS DISTINCT FROM (jsonb_build_object('version',1,'transactionId',pg_current_xact_id()::text,
  'targetId',proof->'targetId','withdrawalDigest',proof->'withdrawalDigest',
  'capsuleDigest',proof->'capsuleDigest','capsuleValidUntilNs',proof->'capsuleValidUntilNs',
  'policyGenerationDigest',proof->'policyGenerationDigest','workloadId',proof->'workloadId',
  'identityManifestDigest',proof->'identityManifestDigest','sourceMode',proof->'sourceMode',
  'originalReceiptDigest',proof->'originalReceiptDigest','originalTokenDigest',proof->'originalTokenDigest') || CASE WHEN proof->>'sourceMode'='FACT_BOUND'
   THEN jsonb_build_object('factCustody',proof->'factCustody') ELSE '{}'::jsonb END)
  OR jsonb_typeof(proof->'targetId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(proof->'workloadId') IS DISTINCT FROM 'string'
  OR coalesce(proof->>'workloadId','') !~ '^urn:openpc:workload:[A-Za-z0-9:._-]{1,140}$'
  OR jsonb_typeof(proof->'capsuleValidUntilNs') IS DISTINCT FROM 'string'
  OR coalesce(proof->>'capsuleValidUntilNs','') !~ '^[1-9][0-9]{0,19}$'
  OR (proof->>'capsuleValidUntilNs')::numeric>18446744073709551615
  OR (proof->>'capsuleValidUntilNs')::numeric<=extract(epoch from clock_timestamp())*1000000000
  OR EXISTS(SELECT 1 FROM (VALUES('withdrawalDigest'),('capsuleDigest'),('policyGenerationDigest'),
    ('identityManifestDigest'),('originalReceiptDigest'),('originalTokenDigest')) f(name)
    WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[0-9a-f]{64}$')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RESTORE-PROOF'; END IF;
 PERFORM openpc.check_runtime_target_fact_proof(proof);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id(); target:=(proof->>'targetId')::uuid;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target ORDER BY a.revision DESC LIMIT 1;
 IF head.binding->>'action'<>'Withdraw' OR head.binding->'cause'->>'kind'<>'Activation'
  OR head.binding->'source'->>'capsule_digest' IS DISTINCT FROM proof->>'capsuleDigest'
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RESTORE-HEAD'; END IF;
 SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery d
  WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target
   AND d.revision=head.revision AND d.delivery_digest='sha256:'||(proof->>'withdrawalDigest');
 IF NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_acknowledgement a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
   AND a.delivery_digest=delivery.delivery_digest AND a.claims->>'installed_state'='NewUseDenied')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACK-PENDING'; END IF;
 SELECT * INTO STRICT identity FROM openpc.lock_runtime_discovery_authority(target,
  'sha256:'||(head.binding->'target'->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=identity.credential_id;
 IF head.binding->'target' IS DISTINCT FROM jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
  'target_id',target::text,'credential_id',identity.credential_id::text,'principal_id',principal::text,
  'credential_epoch',identity.credential_epoch,'principal_epoch',identity.principal_epoch,
  'certificate_digest',head.binding->'target'->>'certificate_digest')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY'; END IF;
 SELECT * INTO STRICT cause FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.configuration_work_id=(head.binding->'cause'->>'work_id')::uuid AND w.runtime_target_id=target FOR SHARE;
 SELECT * INTO STRICT original FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.configuration_work_id=(head.binding->'source'->>'original_work_id')::uuid AND w.runtime_target_id=target FOR SHARE;
 SELECT * INTO STRICT current_target FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
  AND t.runtime_target_id=target FOR SHARE;
 IF cause.state<>'FAILED' OR cause.execution_started_at IS NOT NULL OR cause.execution_attempt_id IS NOT NULL
  OR cause.work_kind<>'RUNTIME_ACTIVATION' OR cause.completed_at IS NULL
  OR cause.operation_id::text IS DISTINCT FROM head.binding->'cause'->>'operation_id'
  OR head.binding->'cause'->'execution_attempt_id' IS DISTINCT FROM 'null'::jsonb
  OR original.state<>'COMPLETED' OR original.work_kind<>'RUNTIME_ACTIVATION'
  OR original.policy_generation_digest IS DISTINCT FROM 'sha256:'||(proof->>'policyGenerationDigest')
  OR original.result_receipt->>'activationReceiptCoseHex' IS NULL
  OR encode(sha256(decode(original.result_receipt->>'activationReceiptCoseHex','hex')),'hex') IS DISTINCT FROM proof->>'originalReceiptDigest'
  OR current_target.active_generation_digest IS DISTINCT FROM 'sha256:'||(proof->>'capsuleDigest')
  OR current_target.desired_generation_digest IS DISTINCT FROM cause.generation_digest OR current_target.state<>'FAILED'
  OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
   AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION' AND w.state IN ('PENDING','LEASED','RECONCILING'))
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RESTORE-CAUSE'; END IF;
 PERFORM openpc.lock_runtime_target_restore_sources(target,head.binding->'source',proof);
 material:=head.binding||jsonb_build_object('action','Restore','revision',head.revision+1,
  'previous_revision',head.revision,'previous_delivery_digest',substring(delivery.delivery_digest from 8));
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
  jsonb_build_object('binding',material,'restorationProof',proof)),'UTF8')),'hex');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,restoration_proof,admission_digest)
 VALUES(pid,privacy,target,head.revision+1,material,proof,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_runtime_target_unstarted_restore(bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_runtime_target_unstarted_restore(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_runtime_target_unstarted_restore(bytea,bytea,bytea) TO openpc_control_worker;
`;
