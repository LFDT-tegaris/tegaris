/** Confirms an already observed native effect. It cannot execute activation or
 * turn an absent/failed effect into a success. Native custody and current sources
 * are attested under a separate MAC domain in this exact transaction. */
export const targetDispositionActivationSql = `
CREATE OR REPLACE FUNCTION openpc.begin_runtime_target_activation_confirmation(
 proof_wire bytea,nonce bytea,mac bytea)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0; pid uuid; privacy uuid; target uuid;
 head control.runtime_target_disposition_admission; delivery control.runtime_target_disposition_delivery;
 original control.configuration_work; input control.runtime_configuration_input;
 current_target control.runtime_target; source jsonb; identity jsonb; authority record; principal uuid;
 material jsonb; digest text; next_revision bigint; previous_digest text; occurrence uuid;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR proof_wire IS NULL OR octet_length(proof_wire) NOT BETWEEN 1 AND 8192
  OR nonce IS NULL OR octet_length(nonce)<>32 OR mac IS NULL OR octet_length(mac)<>32
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_TARGET_DISPOSITION_ACTIVATION_ADMISSION_V1','UTF8')||sha256(proof_wire)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 proof:=convert_from(proof_wire,'UTF8')::jsonb;
 IF proof IS DISTINCT FROM (jsonb_build_object('version',1,'transactionId',pg_current_xact_id()::text,
  'targetId',proof->'targetId','source',proof->'source','target',proof->'target',
  'capsuleDigest',proof->'capsuleDigest','capsuleValidUntilNs',proof->'capsuleValidUntilNs',
  'policyGenerationDigest',proof->'policyGenerationDigest','workloadId',proof->'workloadId',
  'identityManifestDigest',proof->'identityManifestDigest','sourceMode',proof->'sourceMode',
  'originalReceiptDigest',proof->'originalReceiptDigest','originalTokenDigest',proof->'originalTokenDigest',
  'occurrenceId',proof->'occurrenceId') || CASE WHEN proof->>'sourceMode'='FACT_BOUND'
   THEN jsonb_build_object('factCustody',proof->'factCustody') ELSE '{}'::jsonb END)
  OR jsonb_typeof(proof->'source') IS DISTINCT FROM 'object'
  OR jsonb_typeof(proof->'target') IS DISTINCT FROM 'object'
  OR coalesce(proof->>'workloadId','') !~ '^urn:openpc:workload:[A-Za-z0-9:._-]{1,140}$'
  OR coalesce(proof->>'capsuleValidUntilNs','') !~ '^[1-9][0-9]{0,19}$'
  OR (proof->>'capsuleValidUntilNs')::numeric>18446744073709551615
  OR (proof->>'capsuleValidUntilNs')::numeric<=extract(epoch from clock_timestamp())*1000000000
  OR EXISTS(SELECT 1 FROM (VALUES('capsuleDigest'),('policyGenerationDigest'),('identityManifestDigest'),
   ('originalReceiptDigest'),('originalTokenDigest')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[0-9a-f]{64}$')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-PROOF'; END IF;
 PERFORM openpc.check_runtime_target_fact_proof(proof);
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id(); target:=(proof->>'targetId')::uuid;
 source:=proof->'source'; identity:=proof->'target';
 PERFORM openpc.lock_runtime_target_current_sources(target,source,proof,'CONFIRM');
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,'sha256:'||(identity->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 IF identity IS DISTINCT FROM jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,
  'target_id',target::text,'credential_id',authority.credential_id::text,'principal_id',principal::text,
  'credential_epoch',authority.credential_epoch,'principal_epoch',authority.principal_epoch,
  'certificate_digest',identity->>'certificate_digest')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY'; END IF;
 SELECT * INTO STRICT original FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.configuration_work_id=(source->>'original_work_id')::uuid AND w.runtime_target_id=target FOR SHARE NOWAIT;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input i WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
  AND i.runtime_configuration_input_id=(source->>'runtime_configuration_input_id')::uuid FOR SHARE NOWAIT;
 IF source IS DISTINCT FROM jsonb_build_object('runtime_configuration_input_id',input.runtime_configuration_input_id::text,
  'configuration_digest',encode(input.configuration_digest,'hex'),'module_installation_id',input.module_installation_id::text,
  'module_configuration_generation_id',input.module_configuration_generation_id::text,
  'runtime_configuration_generation_id',original.runtime_configuration_generation_id::text,
  'capsule_digest',proof->>'capsuleDigest','xds_version_digest',substring(original.xds_version_digest from 8),
  'predecessor_capsule_digest',substring(original.predecessor_digest from 8),'original_work_id',original.configuration_work_id::text,
  'original_operation_id',original.operation_id::text,'original_execution_attempt_id',original.execution_attempt_id::text)
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-SOURCE'; END IF;
 SELECT ot.activation_occurrence_id INTO occurrence FROM control.policy_activation_occurrence_target ot
  WHERE ot.participant_id=pid AND ot.privacy_domain_id=privacy AND ot.configuration_work_id=original.configuration_work_id;
 IF proof->>'occurrenceId' IS DISTINCT FROM coalesce(occurrence,original.configuration_work_id)::text
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-OCCURRENCE'; END IF;
 SELECT * INTO STRICT current_target FROM control.runtime_target t WHERE t.participant_id=pid AND t.privacy_domain_id=privacy
  AND t.runtime_target_id=target FOR SHARE NOWAIT;
 IF NOT coalesce(((original.state='COMPLETED' AND current_target.active_generation_digest='sha256:'||(proof->>'capsuleDigest'))
  OR (original.state IN ('LEASED','RECONCILING') AND openpc.runtime_work_predecessor_matches(original.configuration_work_id)
   AND current_target.desired_generation_digest=original.generation_digest)),false)
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-TARGET'; END IF;
 SELECT * INTO head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target ORDER BY a.revision DESC LIMIT 1;
 IF NOT FOUND THEN
  IF original.predecessor_digest IS NOT NULL THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-PREDECESSOR'; END IF;
  next_revision:=1; previous_digest:=NULL;
 ELSE
  IF head.binding->>'action' IS DISTINCT FROM 'Withdraw'
   OR (head.binding->'cause'->>'kind' IN ('Activation','UnsignedWithdrawalRecovery')) IS NOT TRUE
   OR head.binding->'cause'->>'work_id' IS DISTINCT FROM original.configuration_work_id::text
   OR head.binding->'cause'->>'operation_id' IS DISTINCT FROM original.operation_id::text
   OR (head.binding->'cause'->>'execution_attempt_id' IS NOT NULL
    AND head.binding->'cause'->>'execution_attempt_id' IS DISTINCT FROM original.execution_attempt_id::text)
   OR original.predecessor_digest IS DISTINCT FROM 'sha256:'||(head.binding->'source'->>'capsule_digest')
   OR head.binding->'source'->>'capsule_digest' IS NOT DISTINCT FROM proof->>'capsuleDigest'
   OR head.binding->'source'->>'original_work_id' IS NOT DISTINCT FROM original.configuration_work_id::text
   OR head.binding->'target' IS DISTINCT FROM identity
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACTIVATION-PREDECESSOR'; END IF;
  SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery d
   WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target AND d.revision=head.revision;
  IF NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_acknowledgement a
   WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
    AND a.delivery_digest=delivery.delivery_digest AND a.claims->>'installed_state'='NewUseDenied')
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACK-PENDING'; END IF;
  next_revision:=head.revision+1; previous_digest:=substring(delivery.delivery_digest from 8);
 END IF;
 material:=jsonb_build_object('version',1,'target',identity,'source',source,'action','ConfirmActivation',
  'cause',jsonb_build_object('kind','Activation','work_id',original.configuration_work_id::text,
   'operation_id',original.operation_id::text,'execution_attempt_id',original.execution_attempt_id::text),
  'revision',next_revision,'previous_revision',next_revision-1,'previous_delivery_digest',previous_digest);
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(
  jsonb_build_object('binding',material,'activationProof',proof)),'UTF8')),'hex');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,activation_proof,admission_digest)
 VALUES(pid,privacy,target,next_revision,material,proof,digest);
 RETURN QUERY SELECT material,digest;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;
ALTER FUNCTION openpc.begin_runtime_target_activation_confirmation(bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_runtime_target_activation_confirmation(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_runtime_target_activation_confirmation(bytea,bytea,bytea) TO openpc_control_worker;
`;
