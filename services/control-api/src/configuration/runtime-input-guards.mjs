export const runtimeInputGuardsSql = `
-- Acquire before row locks, including deselection and INSERT ... ON CONFLICT.
-- The Fleet writer already holds module-admission; direct SQL must obey it too.
-- Never wait while a caller may hold another scope/row fence in a different order.
CREATE OR REPLACE FUNCTION openpc.guard_runtime_input_reference_fence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_participant_id() IS NULL OR openpc.current_privacy_domain_id() IS NULL THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6001';
 END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||
   openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS runtime_input_reference_fence ON control.runtime_configuration_input;
CREATE TRIGGER runtime_input_reference_fence BEFORE INSERT OR UPDATE OR DELETE
 ON control.runtime_configuration_input FOR EACH STATEMENT
 EXECUTE FUNCTION openpc.guard_runtime_input_reference_fence();

CREATE OR REPLACE FUNCTION openpc.runtime_configuration_bindings_current(
  p_participant uuid,p_privacy uuid,p_bindings jsonb
) RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,control,openpc AS $$
 SELECT openpc.matches_participant(p_participant) AND openpc.matches_privacy(p_privacy)
   AND jsonb_typeof(p_bindings)='array' AND jsonb_array_length(p_bindings)>0
   AND NOT EXISTS (
     SELECT 1 FROM jsonb_array_elements(p_bindings) binding
     WHERE CASE binding->>'kind'
       WHEN 'ProviderProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.provider_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.provider_profile_id::text=binding->>'id'
           AND p.behavior_fingerprint=binding->>'digest' AND p.chain_id=binding->>'chainId' AND p.state<>'RETIRED')
       WHEN 'ClientIndexerProfile' THEN NOT EXISTS (
         SELECT 1 FROM control.indexer_profile p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.indexer_profile_id::text=binding->>'id'
           AND p.method_profile_digest=binding->>'digest' AND p.engine_version=binding->>'engineVersion' AND p.state<>'RETIRED')
       WHEN 'ProjectionPlan' THEN NOT EXISTS (
         SELECT 1 FROM control.projection_plan p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.projection_plan_id::text=binding->>'id'
           AND p.plan_digest=binding->>'digest' AND p.state<>'RETIRED')
       WHEN 'CiglSettings' THEN NOT EXISTS (
         SELECT 1 FROM control.cigl_settings p WHERE p.participant_id=p_participant
           AND p.privacy_domain_id=p_privacy AND p.cigl_settings_id::text=binding->>'id')
       ELSE true END
   )
$$;
REVOKE ALL ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_configuration_bindings_current(uuid,uuid,jsonb)
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_configuration_input()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control,openpc AS $$
BEGIN
 IF TG_OP='INSERT' THEN PERFORM openpc.assert_runtime_artifact_source_import(NEW); END IF;
 IF TG_OP='DELETE' THEN
  -- The earlier authentic BEFORE DELETE capture must already exist. Only this
  -- transaction's exact governed job can release its original input row.
  IF pg_trigger_depth()<>1 OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1'
   OR NOT EXISTS(SELECT 1 FROM control.runtime_artifact_retirement r JOIN control.deletion_job j
    USING(participant_id,privacy_domain_id,deletion_job_id) WHERE r.participant_id=OLD.participant_id
     AND r.privacy_domain_id=OLD.privacy_domain_id AND r.runtime_configuration_input_id=OLD.runtime_configuration_input_id
     AND r.configuration_digest='sha256:'||encode(OLD.configuration_digest,'hex')
     AND r.configuration_bytes=octet_length(OLD.configuration_cbor) AND j.operation_id=openpc.current_operation_id()
     AND j.state='EXECUTING' AND j.revision=0)
  THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6004'; END IF;
  RETURN OLD;
 END IF;
 IF (TG_OP='UPDATE' AND
   (to_jsonb(NEW)-'selected') IS DISTINCT FROM (to_jsonb(OLD)-'selected')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6004';
 END IF;
 -- A new row is new use even when it starts unselected. Matching bytes under
 -- another module installation/generation cannot bypass an original retirement.
 IF (TG_OP='INSERT' OR NEW.selected) AND
  openpc.runtime_artifact_new_use_allowed(NEW.participant_id,NEW.privacy_domain_id,NEW.configuration_digest) IS DISTINCT FROM true
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007'; END IF;
 IF NEW.selected AND (
   NOT openpc.runtime_configuration_bindings_current(NEW.participant_id,NEW.privacy_domain_id,NEW.resource_bindings)
   OR NOT EXISTS (
     SELECT 1 FROM control.module_configuration_generation c
       JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
       JOIN control.module_version v ON v.module_version_id=i.module_version_id
      WHERE c.generation_id=NEW.module_configuration_generation_id
        AND c.module_installation_id=NEW.module_installation_id
        AND c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id
        AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
        AND c.active AND i.state='ENABLED' AND i.lifecycle_operation_id IS NOT NULL
        AND v.module_id='pc.config.assets'
   )) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6007';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_configuration_input_guard ON control.runtime_configuration_input;
CREATE TRIGGER runtime_configuration_input_guard BEFORE INSERT OR UPDATE OR DELETE
 ON control.runtime_configuration_input FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_configuration_input();

-- A selected source is data only. Every consumer still needs its own approved
-- qualification/activation and this exact enabled module generation.
CREATE OR REPLACE VIEW control.runtime_configuration_input_current_metadata
 WITH (security_invoker=true) AS
 SELECT input.runtime_configuration_input_id,input.participant_id,input.privacy_domain_id,
  input.module_installation_id,input.module_configuration_generation_id,input.configuration_digest,
  input.resource_bindings,input.selected,input.created_at,true AS active
 FROM control.runtime_configuration_input input
 JOIN control.module_configuration_generation c
   ON c.generation_id=input.module_configuration_generation_id
  AND c.module_installation_id=input.module_installation_id
  AND c.participant_id=input.participant_id AND c.privacy_domain_id=input.privacy_domain_id
 JOIN control.module_installation i ON i.module_installation_id=c.module_installation_id
  AND i.participant_id=c.participant_id AND i.privacy_domain_id=c.privacy_domain_id
 JOIN control.module_version v ON v.module_version_id=i.module_version_id
 WHERE openpc.runtime_artifact_new_use_allowed(input.participant_id,input.privacy_domain_id,input.configuration_digest)
   AND input.selected AND c.active AND i.state='ENABLED'
   AND i.lifecycle_operation_id IS NOT NULL AND v.module_id='pc.config.assets'
   AND openpc.runtime_configuration_bindings_current(input.participant_id,input.privacy_domain_id,input.resource_bindings);
REVOKE ALL ON control.runtime_configuration_input_current_metadata FROM PUBLIC;
GRANT SELECT ON control.runtime_configuration_input_current_metadata
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
CREATE OR REPLACE VIEW control.runtime_configuration_input_current
 WITH (security_invoker=true) AS
 SELECT input.runtime_configuration_input_id,input.participant_id,input.privacy_domain_id,
  input.module_installation_id,input.module_configuration_generation_id,
  openpc.runtime_artifact_input_payload(input.runtime_configuration_input_id) AS configuration_cbor,
  input.configuration_digest,input.resource_bindings,input.selected,input.created_at,input.active
 FROM control.runtime_configuration_input_current_metadata input;
REVOKE ALL ON control.runtime_configuration_input_current FROM PUBLIC;
GRANT SELECT ON control.runtime_configuration_input_current
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
