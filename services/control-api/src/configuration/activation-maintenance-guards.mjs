/** Append-only operator audit, deliberately separate from original signed
 * business receipts. Only the existing worker may append, in the completion tx. */
export const activationMaintenanceGuardsSql = `
ALTER TABLE control.runtime_activation_maintenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.runtime_activation_maintenance FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.runtime_activation_maintenance FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.runtime_activation_maintenance TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_runtime_activation_maintenance()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'ACTIVATION-MAINTENANCE-IMMUTABLE'; END IF;
 IF current_user<>session_user OR current_setting('role')<>'none'
 OR NEW.intent->>'databaseRole' IS DISTINCT FROM current_user::text
 OR NEW.intent->>'workerRole' IS DISTINCT FROM 'openpc_control_worker'
 OR NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
 OR pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR has_schema_privilege(current_user,'control','CREATE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN(current_user,session_user) AND (rolsuper OR rolbypassrls))
 OR current_setting('session_replication_role')<>'origin' 
 OR current_setting('row_security')<>'on'
 OR NOT EXISTS (
  SELECT 1 FROM control.configuration_work w
  JOIN control.runtime_activation_observation o USING(configuration_work_id,participant_id,privacy_domain_id,operation_id,execution_attempt_id,runtime_target_id,runtime_configuration_generation_id,generation_digest,xds_version_digest)
  JOIN control.policy_activation_occurrence_target c ON c.participant_id=w.participant_id
   AND c.privacy_domain_id=w.privacy_domain_id AND c.configuration_work_id=w.configuration_work_id
   AND c.phase='FORWARD' AND c.state='ACTIVE_MATCHED'
  JOIN control.runtime_target_disposition_admission a ON a.participant_id=w.participant_id
   AND a.privacy_domain_id=w.privacy_domain_id AND a.runtime_target_id=w.runtime_target_id
   AND a.revision=(NEW.intent->>'dispositionRevision')::bigint
  JOIN control.runtime_target_disposition_delivery d ON d.participant_id=a.participant_id
   AND d.privacy_domain_id=a.privacy_domain_id AND d.runtime_target_id=a.runtime_target_id AND d.revision=a.revision
  JOIN control.runtime_target_disposition_acknowledgement k ON k.participant_id=d.participant_id
   AND k.privacy_domain_id=d.privacy_domain_id AND k.runtime_target_id=d.runtime_target_id AND k.delivery_digest=d.delivery_digest
  WHERE w.configuration_work_id=NEW.configuration_work_id AND w.participant_id=NEW.participant_id
   AND w.privacy_domain_id=NEW.privacy_domain_id AND w.operation_id=NEW.operation_id
   AND w.execution_attempt_id=NEW.execution_attempt_id AND w.result_event_id=NEW.result_event_id
   AND w.state='COMPLETED' AND w.work_kind='RUNTIME_ACTIVATION' AND w.predecessor_digest IS NULL
   AND w.attempt_count=NEW.claim_count AND w.lease_owner IS NULL AND w.lease_until IS NULL
   AND w.xmin=pg_current_xact_id()::xid
   AND NEW.intent->>'schemaVersion'='1'
   AND NEW.intent->>'occurrenceId'=c.activation_occurrence_id::text
   AND a.binding->>'action'='ConfirmActivation'
   AND a.binding->'source'->>'original_work_id'=w.configuration_work_id::text
   AND a.activation_proof->>'occurrenceId'=c.activation_occurrence_id::text
   AND NEW.intent->>'deliveryDigest'='sha256:'||encode(sha256(d.signed_delivery),'hex')
   AND NEW.intent->>'acknowledgementDigest'='sha256:'||encode(sha256(k.signed_acknowledgement),'hex')
   AND NEW.intent->>'participantId'=w.participant_id::text
   AND NEW.intent->>'privacyDomainId'=w.privacy_domain_id::text
   AND NEW.intent->>'workId'=w.configuration_work_id::text
   AND NEW.intent->>'operationId'=w.operation_id::text
   AND NEW.intent->>'executionAttemptId'=w.execution_attempt_id::text
   AND NEW.intent->>'runtimeTargetId'=w.runtime_target_id::text
   AND NEW.intent->>'generationId'=w.runtime_configuration_generation_id::text
   AND NEW.intent->>'generationDigest'=w.generation_digest
   AND NEW.intent->>'configurationDigest'=w.configuration_digest
   AND NEW.intent->>'xdsVersionDigest'=w.xds_version_digest
   AND NEW.intent->>'capsuleDigest'=o.capsule_digest
   AND NEW.intent->>'receiptDigest'=o.activation_receipt_digest
   AND NEW.intent->>'receiptDigest'=w.result_receipt_digest
   AND (NEW.intent->>'claimCount')::bigint=NEW.claim_count
 ) THEN RAISE EXCEPTION 'ACTIVATION-MAINTENANCE-ORIGINAL-REJECTED'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_activation_maintenance() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_runtime_activation_maintenance() TO openpc_control_worker;
DROP TRIGGER IF EXISTS runtime_activation_maintenance_original ON control.runtime_activation_maintenance;
CREATE TRIGGER runtime_activation_maintenance_original BEFORE INSERT OR UPDATE OR DELETE
 ON control.runtime_activation_maintenance FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_activation_maintenance();
DROP TRIGGER IF EXISTS runtime_activation_maintenance_truncate ON control.runtime_activation_maintenance;
CREATE TRIGGER runtime_activation_maintenance_truncate BEFORE TRUNCATE
 ON control.runtime_activation_maintenance FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_runtime_activation_maintenance();
`;
