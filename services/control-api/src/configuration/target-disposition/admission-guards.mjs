/** Activation handoff admission. The database constructs the binding from real
 * original effects and the live leased successor; no caller supplies claims.
 * Restore/dependency/retirement admissions have distinct owners and are not
 * admitted by this function. Pending denial is committed before native I/O. */
export const targetDispositionAdmissionSql = `
CREATE OR REPLACE FUNCTION openpc.begin_runtime_target_withdrawal(
 target uuid,cause_work uuid,worker text,certificate text,wanted_previous bigint)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; principal uuid; identity record; current_target control.runtime_target;
 cause control.configuration_work; original control.configuration_work;
 observation control.runtime_activation_observation; input control.runtime_configuration_input;
 head control.runtime_target_disposition_admission; delivery control.runtime_target_disposition_delivery;
 original_inputs uuid[]; material jsonb; digest text; next_revision bigint; recovery boolean:=false;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR target IS NULL OR cause_work IS NULL OR coalesce(worker,'')='' OR wanted_previous IS NULL OR wanted_previous<0
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT identity FROM openpc.lock_runtime_discovery_authority(target,certificate);
 -- lock_runtime_discovery_authority holds this exact credential and its actual
 -- principal through commit. Bind the association, not merely equal epochs.
 SELECT c.principal_id INTO STRICT principal FROM control.credential c
  WHERE c.participant_id=pid AND c.credential_id=identity.credential_id;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT current_target FROM control.runtime_target t
  WHERE t.participant_id=pid AND t.privacy_domain_id=privacy AND t.runtime_target_id=target FOR SHARE;
 SELECT * INTO STRICT cause FROM control.configuration_work w
  WHERE w.participant_id=pid AND w.privacy_domain_id=privacy AND w.configuration_work_id=cause_work
   AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION' FOR SHARE;
 -- This owner performs no provider effect and never fabricates a new attempt.
 IF cause.state<>'LEASED' OR cause.lease_owner IS DISTINCT FROM worker OR cause.lease_until<=clock_timestamp()
  OR cause.execution_started_at IS NOT NULL OR cause.execution_attempt_id IS NOT NULL
  OR cause.predecessor_digest IS NULL OR NOT openpc.runtime_work_predecessor_matches(cause.configuration_work_id)
  OR current_target.desired_generation_digest IS DISTINCT FROM cause.generation_digest
  OR current_target.state<>'STAGING'
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAUSE-UNAVAILABLE'; END IF;
 SELECT * INTO head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
  ORDER BY a.revision DESC LIMIT 1;
 IF FOUND AND head.binding->>'action'='Withdraw'
  AND (head.binding->'cause'=jsonb_build_object('kind','Activation','work_id',cause.configuration_work_id::text,
   'operation_id',cause.operation_id::text,'execution_attempt_id',NULL)
   OR (head.binding->'cause'->>'kind'='UnsignedWithdrawalRecovery'
    AND head.binding->'cause'->>'work_id'=cause.configuration_work_id::text
    AND head.binding->'cause'->>'operation_id'=cause.operation_id::text
    AND openpc.runtime_unsigned_withdrawal_recoverable(target,(head.revision-1)::bigint,
     'sha256:'||(head.binding->'cause'->>'abandoned_admission_digest'))))
 THEN
  -- Retry returns the original admission; it does not rotate identity/epochs or
  -- replace a pending delivery after a lost commit response.
  IF wanted_previous<>head.revision-1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAS'; END IF;
  RETURN QUERY SELECT head.binding,head.admission_digest;
  RETURN;
 END IF;
 IF coalesce(head.revision,0)<>wanted_previous THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAS'; END IF;
 IF head.revision IS NOT NULL THEN
  recovery:=openpc.runtime_unsigned_withdrawal_recoverable(target,head.revision::bigint,head.admission_digest);
  SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery d
   WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target
    AND d.revision=head.revision-CASE WHEN recovery THEN 1 ELSE 0 END;
  IF NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_acknowledgement a
   WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
    AND a.delivery_digest=delivery.delivery_digest)
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACK-PENDING'; END IF;
 END IF;
 SELECT * INTO STRICT observation FROM control.runtime_activation_observation o
  WHERE o.participant_id=pid AND o.privacy_domain_id=privacy AND o.runtime_target_id=target
   AND o.capsule_digest=cause.predecessor_digest;
 SELECT * INTO STRICT original FROM control.configuration_work w
  WHERE w.participant_id=pid AND w.privacy_domain_id=privacy AND w.configuration_work_id=observation.configuration_work_id
   AND w.runtime_target_id=target AND w.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
   AND w.operation_id=observation.operation_id AND w.execution_attempt_id=observation.execution_attempt_id
   AND w.execution_started_at IS NOT NULL AND w.work_kind='RUNTIME_ACTIVATION'
   AND w.generation_digest=observation.generation_digest AND w.xds_version_digest=observation.xds_version_digest
   AND ((w.state='COMPLETED' AND w.result_receipt_digest=observation.activation_receipt_digest)
    OR(w.state='FAILED' AND w.configuration_work_id=cause.denied_predecessor_work_id
     AND w.result_receipt->>'outcome'='EXPIRED_OBSERVED_DENIED'
     AND w.result_receipt->>'originalReceiptDigest'=observation.activation_receipt_digest
     AND EXISTS(SELECT 1 FROM control.runtime_denied_predecessor c WHERE c.configuration_work_id=w.configuration_work_id
      AND c.participant_id=pid AND c.privacy_domain_id=privacy AND c.runtime_target_id=target
      AND c.capsule_digest=observation.capsule_digest))) FOR SHARE;
 SELECT array_agg(i.runtime_configuration_input_id) INTO original_inputs FROM control.runtime_configuration_input i
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
   AND i.configuration_digest=decode(substring(original.configuration_digest from 8),'hex');
 IF coalesce(cardinality(original_inputs),0)<>1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-INPUT-CARDINALITY'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input i
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy AND i.runtime_configuration_input_id=original_inputs[1] FOR SHARE;
 next_revision:=wanted_previous+1;
 material:=jsonb_build_object('version',1,'action','Withdraw','revision',next_revision,
  'previous_revision',wanted_previous-CASE WHEN recovery THEN 1 ELSE 0 END,
  'previous_delivery_digest',substring(delivery.delivery_digest from 8),
  'target',jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,'target_id',target::text,
   'credential_id',identity.credential_id::text,'principal_id',principal::text,'credential_epoch',identity.credential_epoch,
   'principal_epoch',identity.principal_epoch,'certificate_digest',substring(certificate from 8)),
  'source',jsonb_build_object('runtime_configuration_input_id',input.runtime_configuration_input_id::text,
   'configuration_digest',encode(input.configuration_digest,'hex'),'module_installation_id',input.module_installation_id::text,
   'module_configuration_generation_id',input.module_configuration_generation_id::text,
   'runtime_configuration_generation_id',original.runtime_configuration_generation_id::text,
   'capsule_digest',substring(observation.capsule_digest from 8),'xds_version_digest',substring(observation.xds_version_digest from 8),
   'predecessor_capsule_digest',substring(original.predecessor_digest from 8),
   'original_work_id',original.configuration_work_id::text,'original_operation_id',original.operation_id::text,
   'original_execution_attempt_id',original.execution_attempt_id::text),
  'cause',CASE WHEN recovery THEN jsonb_build_object('kind','UnsignedWithdrawalRecovery',
   'work_id',cause.configuration_work_id::text,'operation_id',cause.operation_id::text,
   'abandoned_revision',head.revision,'abandoned_admission_digest',substring(head.admission_digest from 8))
   ELSE jsonb_build_object('kind','Activation','work_id',cause.configuration_work_id::text,
   'operation_id',cause.operation_id::text,'execution_attempt_id',NULL) END);
 IF recovery AND (material->'source' IS DISTINCT FROM head.binding->'source'
  OR material->'target' IS DISTINCT FROM head.binding->'target'
  OR cause.configuration_work_id::text=head.binding->'cause'->>'work_id')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-RECOVERY-BINDING'; END IF;
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(material),'UTF8')),'hex');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,admission_digest)
 VALUES(pid,privacy,target,next_revision,material,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_runtime_target_withdrawal(uuid,uuid,text,text,bigint) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_runtime_target_withdrawal(uuid,uuid,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_runtime_target_withdrawal(uuid,uuid,text,text,bigint) TO openpc_control_worker;
`;
