/** Reference mutations must serialize with evidence retention and disposition.
 * This grants no reference clearance, deletion or runtime authority. In
 * particular, completed work and disconnected targets retain their references.
 */
export const runtimeArtifactRuntimeProducers = Object.freeze([
  'runtime_configuration_input',
  'configuration_work',
  'runtime_configuration_generation',
  'runtime_target',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'runtime_activation_observation',
  'runtime_target_connection',
  'runtime_route_publication',
  'provider_probe_observation',
  'runtime_target_disposition_admission',
  'runtime_target_disposition_delivery',
  'runtime_target_disposition_acknowledgement',
]);
// These rows participate in the exact artifact reference graph too. Their
// ordinary module/policy locks are independent admissions, not a substitute
// for serializing the full observation with disposition and new use.
export const runtimeArtifactDependencyProducers = Object.freeze([
  'module_configuration_generation',
  'module_installation',
  'policy_activation',
  'policy_activation_prerequisite',
  'policy_generation',
  'provider_profile',
  'indexer_profile',
  'cigl_settings',
  'projection_plan',
]);
export const runtimeArtifactFenceSql = `
CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_lifecycle_fence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_participant_id() IS NULL OR openpc.current_privacy_domain_id() IS NULL
   OR TG_OP='TRUNCATE' OR current_setting('session_replication_role')<>'origin'
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='PC-DATA-6004'; END IF;
 -- Producers can already own module, policy, target or occurrence locks.
 -- Never wait in the reverse order. Use the exclusive lock also used by
 -- evidence publication, avoiding shared-to-exclusive upgrade deadlocks.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||
   openpc.current_participant_id()::text,0))
 -- This is a definite statement/transaction abort, not an unknown effect.
 -- Serializable public owners may retry their same operation after rollback.
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_runtime_artifact_lifecycle_fence() FROM PUBLIC;
${[...runtimeArtifactRuntimeProducers, ...runtimeArtifactDependencyProducers]
  .map(
    (table) => `
DROP TRIGGER IF EXISTS artifact_lifecycle_fence ON control.${table};
CREATE TRIGGER artifact_lifecycle_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
 ON control.${table} FOR EACH STATEMENT
 EXECUTE FUNCTION openpc.guard_runtime_artifact_lifecycle_fence();`,
  )
  .join('\n')}
`;
