import { platformScopeReplacementSourcePoliciesSql } from '../../../../identity-service/src/db/platform-scope-replacement-guards.mjs';

export const platformScopeWithdrawalAdmissionSql = `
CREATE OR REPLACE FUNCTION openpc.begin_platform_scope_target_withdrawal(
 target uuid,replacement uuid,worker text,certificate text,wanted_previous bigint)
RETURNS TABLE(binding jsonb,admission_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE pid uuid; privacy uuid; principal uuid; identity record; current_target control.runtime_target;
 intent control.platform_scope_replacement; queued control.platform_scope_target_withdrawal;
 original control.configuration_work; observation control.runtime_activation_observation;
 input control.runtime_configuration_input; head control.runtime_target_disposition_admission;
 delivery control.runtime_target_disposition_delivery; original_inputs uuid[]; material jsonb; digest text;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner(); PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
   OR target IS NULL OR replacement IS NULL OR coalesce(worker,'')='' OR wanted_previous IS NULL OR wanted_previous<0
   OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ISSUANCE-CONTEXT'; END IF;
 pid:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT identity FROM openpc.lock_runtime_discovery_authority(target,certificate);
 SELECT c.principal_id INTO STRICT principal FROM control.credential c
  WHERE c.participant_id=pid AND c.credential_id=identity.credential_id;
 SELECT * INTO STRICT intent FROM control.platform_scope_replacement r WHERE r.replacement_id=replacement
   AND r.participant_id=pid AND r.privacy_domain_id=privacy AND r.state='WITHDRAWING' AND r.row_version=1;
 PERFORM 1 FROM control.platform_context p WHERE p.platform_context_id=intent.platform_context_id
  AND p.owner_participant_id=pid AND p.state='ACTIVE' AND p.authority_epoch=intent.predecessor_epoch
  AND p.row_version=intent.expected_root_revision FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAUSE-UNAVAILABLE'; END IF;
 SELECT * INTO STRICT queued FROM control.platform_scope_target_withdrawal q
  WHERE q.replacement_id=replacement AND q.participant_id=pid AND q.privacy_domain_id=privacy AND q.runtime_target_id=target;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||pid::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT current_target FROM control.runtime_target t
  WHERE t.participant_id=pid AND t.privacy_domain_id=privacy AND t.runtime_target_id=target FOR SHARE;
 IF current_target.active_generation_digest IS DISTINCT FROM queued.source->>'capsuleDigest'
  OR EXISTS(SELECT 1 FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
    AND w.runtime_target_id=target AND w.work_kind='RUNTIME_ACTIVATION' AND w.state IN('PENDING','LEASED','RECONCILING'))
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAUSE-UNAVAILABLE'; END IF;
 SELECT * INTO head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target ORDER BY a.revision DESC LIMIT 1;
 IF FOUND AND head.binding->>'action'='Withdraw' AND head.binding->'cause'=jsonb_build_object('kind','Dependency',
   'owner','Platform','resource_id',intent.replacement_id::text,'operation_id',intent.prepare_operation_id::text,'revision',1)
 THEN
  IF wanted_previous<>head.revision-1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAS'; END IF;
  RETURN QUERY SELECT head.binding,head.admission_digest; RETURN;
 END IF;
 IF coalesce(head.revision,0)<>wanted_previous THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAS'; END IF;
 IF head.revision IS NOT NULL THEN
  SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery d WHERE d.participant_id=pid
   AND d.privacy_domain_id=privacy AND d.runtime_target_id=target AND d.revision=head.revision;
  IF NOT EXISTS(SELECT 1 FROM control.runtime_target_disposition_acknowledgement a WHERE a.participant_id=pid
    AND a.privacy_domain_id=privacy AND a.runtime_target_id=target AND a.delivery_digest=delivery.delivery_digest)
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACK-PENDING'; END IF;
 END IF;
 SELECT * INTO STRICT observation FROM control.runtime_activation_observation o WHERE o.participant_id=pid
  AND o.privacy_domain_id=privacy AND o.runtime_target_id=target AND o.capsule_digest=current_target.active_generation_digest
  AND o.configuration_work_id=(queued.source->>'originalWorkId')::uuid
  AND o.execution_attempt_id=(queued.source->>'originalAttemptId')::uuid
  AND o.activation_receipt_digest=queued.source->>'activationReceiptDigest';
 SELECT * INTO STRICT original FROM control.configuration_work w WHERE w.participant_id=pid AND w.privacy_domain_id=privacy
  AND w.configuration_work_id=observation.configuration_work_id AND w.runtime_target_id=target
  AND w.operation_id=observation.operation_id AND w.execution_attempt_id=observation.execution_attempt_id
  AND w.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
  AND w.generation_digest=observation.generation_digest AND w.xds_version_digest=observation.xds_version_digest
  AND w.state='COMPLETED' AND w.work_kind='RUNTIME_ACTIVATION' AND w.execution_started_at IS NOT NULL
  AND w.result_receipt_digest=observation.activation_receipt_digest FOR SHARE;
 SELECT array_agg(i.runtime_configuration_input_id) INTO original_inputs FROM control.runtime_configuration_input i
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy AND i.configuration_digest=decode(substring(original.configuration_digest from 8),'hex');
 IF coalesce(cardinality(original_inputs),0)<>1 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-INPUT-CARDINALITY'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input i WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
  AND i.runtime_configuration_input_id=original_inputs[1] FOR SHARE;
 material:=jsonb_build_object('version',1,'action','Withdraw','revision',wanted_previous+1,
  'previous_revision',wanted_previous,'previous_delivery_digest',substring(delivery.delivery_digest from 8),
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
  'cause',jsonb_build_object('kind','Dependency','owner','Platform','resource_id',intent.replacement_id::text,
    'operation_id',intent.prepare_operation_id::text,'revision',1));
 IF head.revision IS NOT NULL AND head.binding->'target' IS DISTINCT FROM material->'target' THEN
  IF openpc.runtime_discovery_credential_predecessor(target,certificate,material->'source') IS DISTINCT FROM head.binding->'target'
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CREDENTIAL-SUCCESSOR'; END IF;
 END IF;
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(material),'UTF8')),'hex');
 INSERT INTO control.runtime_target_disposition_admission(participant_id,privacy_domain_id,runtime_target_id,revision,binding,admission_digest)
 VALUES(pid,privacy,target,wanted_previous+1,material,digest);
 RETURN QUERY SELECT material,digest;
END $$;
ALTER FUNCTION openpc.begin_platform_scope_target_withdrawal(uuid,uuid,text,text,bigint) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.begin_platform_scope_target_withdrawal(uuid,uuid,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.begin_platform_scope_target_withdrawal(uuid,uuid,text,text,bigint) TO openpc_control_worker;
`;

export const platformScopeWithdrawalRegistrationSql = `
${platformScopeReplacementSourcePoliciesSql}
ALTER TABLE control.platform_scope_target_withdrawal FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.platform_scope_target_withdrawal FROM PUBLIC,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.platform_scope_target_withdrawal TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.platform_scope_target_withdrawal TO openpc_control_owner;
CREATE OR REPLACE FUNCTION openpc.guard_platform_scope_target_withdrawal()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' OR current_user<>'openpc_control_owner' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-HISTORY'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.replacement_id=NEW.replacement_id
  AND r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id AND r.state='WITHDRAWING'
  AND r.prepare_operation_id=openpc.current_operation_id() AND r.row_version=1
  AND r.candidate->'affectedTargets' @> jsonb_build_array(NEW.source))
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-COHORT'; END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION openpc.guard_platform_scope_target_withdrawal() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_platform_scope_target_withdrawal() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_scope_target_history ON control.platform_scope_target_withdrawal;
CREATE TRIGGER platform_scope_target_history BEFORE INSERT OR UPDATE OR DELETE ON control.platform_scope_target_withdrawal
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_scope_target_withdrawal();
DROP TRIGGER IF EXISTS platform_scope_target_truncate ON control.platform_scope_target_withdrawal;
CREATE TRIGGER platform_scope_target_truncate BEFORE TRUNCATE ON control.platform_scope_target_withdrawal
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_platform_scope_target_withdrawal();

CREATE OR REPLACE FUNCTION openpc.guard_platform_pending_runtime_effect()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.platform_scope_replacement r WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.state='WITHDRAWING') THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='configuration_work' THEN
  IF NEW.work_kind='RUNTIME_ACTIVATION' THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-WITHDRAWING'; END IF;
 ELSIF TG_TABLE_NAME='runtime_target' THEN
 IF TG_OP='UPDATE' AND (
   NEW.active_generation_digest IS DISTINCT FROM OLD.active_generation_digest
   OR NEW.desired_generation_digest IS DISTINCT FROM OLD.desired_generation_digest)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-WITHDRAWING'; END IF;
 IF TG_OP='INSERT' AND (
   NEW.active_generation_digest IS NOT NULL OR NEW.desired_generation_digest IS NOT NULL)
 THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-WITHDRAWING'; END IF;
 ELSE RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-CONTEXT'; END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION openpc.guard_platform_pending_runtime_effect() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_platform_pending_runtime_effect() FROM PUBLIC;
DROP TRIGGER IF EXISTS platform_pending_runtime_effect ON control.configuration_work;
CREATE TRIGGER platform_pending_runtime_effect BEFORE INSERT OR UPDATE ON control.configuration_work
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_pending_runtime_effect();
DROP TRIGGER IF EXISTS platform_pending_runtime_effect ON control.runtime_target;
CREATE TRIGGER platform_pending_runtime_effect BEFORE INSERT OR UPDATE ON control.runtime_target
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_pending_runtime_effect();
`;
