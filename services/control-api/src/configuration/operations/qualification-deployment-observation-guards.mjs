/** Register after the existing qualification roles and Identity source grants.
 * Protected native owners only. No SQL currentness/capability function exists. */
export const qualificationDeploymentObservationGuardsSql = String.raw`
SET ROLE openpc_control_owner;
CREATE OR REPLACE FUNCTION openpc.guard_qualification_deployment_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,control,openpc AS $$
DECLARE pins control.qualification_deployment_installation%ROWTYPE;
 attempt control.qualification_deployment_attempt%ROWTYPE;
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_IMMUTABLE'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_CONTEXT'; END IF;
 IF TG_TABLE_NAME='qualification_deployment_installation' THEN
  IF current_user<>'openpc_operations_qualification_bootstrap' THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_INSTALLER'; END IF;
  IF TG_OP='UPDATE' THEN
   IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') OR NEW.state<>'REVOKED' THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_IMMUTABLE'; END IF;
  ELSE
   IF NEW.state<>'ACTIVE' OR NEW.pins->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR (SELECT count(*) FROM jsonb_object_keys(NEW.pins))<>25
    OR NOT NEW.pins ?& ARRAY['schemaVersion','installationId','participantId','privacyDomainId','environmentId','operationsInstallationDigest','peer','daemonId','engineEndpoint','containerId','imageId','containerStartedAt','installedProcess','expectedUid','executable','argv','networkId','address','memoryBytes','nanoCpus','pidsLimit','mounts','tmpfsTargets','artifacts','separatedFrom']
    OR convert_from(NEW.pins_bytes,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(NEW.pins)
    OR NEW.pins->>'installationId' IS DISTINCT FROM NEW.installation_id::text
    OR NEW.pins->>'participantId' IS DISTINCT FROM NEW.participant_id::text
    OR NEW.pins->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
    OR NEW.pins->>'environmentId' IS DISTINCT FROM NEW.environment_id
    OR NEW.pins->>'engineEndpoint' IS DISTINCT FROM 'unix:///var/run/docker.sock'
    OR NOT EXISTS(SELECT 1 FROM control.operations_installation i WHERE i.environment_id=NEW.environment_id AND i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.state='ACTIVE' AND i.installation_digest=NEW.pins->>'operationsInstallationDigest')
   THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_PINS'; END IF;
  END IF;
 ELSE
  IF TG_OP<>'INSERT' OR current_user NOT IN ('openpc_control_owner','openpc_operations_qualification_owner') THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_NATIVE_OWNER'; END IF;
  IF TG_TABLE_NAME='qualification_deployment_attempt' THEN
   SELECT * INTO pins FROM control.qualification_deployment_installation WHERE installation_id=NEW.installation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
   IF NOT FOUND OR pins.state<>'ACTIVE' OR NEW.request->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR (SELECT count(*) FROM jsonb_object_keys(NEW.request))<>8
    OR NOT NEW.request ?& ARRAY['schemaVersion','observationId','operationId','installationDigest','pins','separatedPins','issuedAtMs','deadlineAtMs']
    OR NEW.request->'pins' IS DISTINCT FROM pins.pins OR NEW.request->>'installationDigest' IS DISTINCT FROM pins.pins_digest
    OR NEW.request->>'observationId' IS DISTINCT FROM NEW.observation_id::text OR NEW.request->>'operationId' IS DISTINCT FROM NEW.operation_id::text
    OR convert_from(NEW.request_bytes,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(NEW.request)
    OR jsonb_typeof(NEW.request->'issuedAtMs') IS DISTINCT FROM 'number' OR jsonb_typeof(NEW.request->'deadlineAtMs') IS DISTINCT FROM 'number'
    OR (NEW.request->>'issuedAtMs')::numeric>floor(extract(epoch from clock_timestamp())*1000)
    OR (NEW.request->>'deadlineAtMs')::numeric<=floor(extract(epoch from clock_timestamp())*1000)
    OR (NEW.request->>'deadlineAtMs')::numeric-(NEW.request->>'issuedAtMs')::numeric NOT BETWEEN 1 AND 30000
    OR NOT EXISTS(SELECT 1 FROM control.operations_installation i WHERE i.environment_id=pins.environment_id AND i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.state='ACTIVE' AND i.installation_digest=pins.pins->>'operationsInstallationDigest')
   THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_REQUEST'; END IF;
   IF jsonb_typeof(NEW.request->'separatedPins') IS DISTINCT FROM 'array'
    OR jsonb_array_length(NEW.request->'separatedPins')>8
    OR (SELECT coalesce(jsonb_agg(v->>'installationId' ORDER BY v->>'installationId'),'[]'::jsonb) FROM jsonb_array_elements(NEW.request->'separatedPins') v)
       IS DISTINCT FROM (SELECT coalesce(jsonb_agg(v ORDER BY v),'[]'::jsonb) FROM jsonb_array_elements(pins.pins->'separatedFrom') v)
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.request->'separatedPins') p WHERE NOT EXISTS(
     SELECT 1 FROM control.qualification_deployment_installation i WHERE i.installation_id=(p->>'installationId')::uuid AND i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.environment_id=pins.environment_id AND i.state='ACTIVE' AND i.pins=p))
   THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_SEPARATION'; END IF;
  ELSE
   SELECT * INTO attempt FROM control.qualification_deployment_attempt WHERE observation_id=NEW.observation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
   IF NOT FOUND OR NEW.observation->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR (SELECT count(*) FROM jsonb_object_keys(NEW.observation))<>7
    OR NOT NEW.observation ?& ARRAY['schemaVersion','observationId','requestDigest','state','measurement','identityRecheckedAtMs','retainedAtMs']
    OR NEW.observation->>'observationId' IS DISTINCT FROM NEW.observation_id::text OR NEW.observation->>'requestDigest' IS DISTINCT FROM attempt.request_digest
    OR NEW.observation->>'state' IS NULL OR NEW.observation->>'state' NOT IN ('OBSERVED','HISTORICAL','UNKNOWN')
    OR convert_from(NEW.observation_bytes,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(NEW.observation)
    OR jsonb_typeof(NEW.observation->'retainedAtMs') IS DISTINCT FROM 'number'
    OR (NEW.observation->>'retainedAtMs')::numeric>floor(extract(epoch from clock_timestamp())*1000)
   THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_RESULT'; END IF;
   IF NEW.observation->>'state'='UNKNOWN' THEN
    IF NEW.observation->'measurement' IS DISTINCT FROM 'null'::jsonb OR NEW.observation->'identityRecheckedAtMs' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_UNKNOWN'; END IF;
   ELSE
    IF jsonb_typeof(NEW.observation->'measurement') IS DISTINCT FROM 'object'
     OR NEW.observation->'measurement'->'schemaVersion' IS DISTINCT FROM '1'::jsonb
     OR NEW.observation->'measurement'->>'scope' IS DISTINCT FROM 'CONTAINER_WORKLOAD'
     OR (SELECT count(*) FROM jsonb_object_keys(NEW.observation->'measurement'))<>15
     OR jsonb_typeof(NEW.observation->'measurement'->'startedAtMs') IS DISTINCT FROM 'number'
     OR jsonb_typeof(NEW.observation->'measurement'->'completedAtMs') IS DISTINCT FROM 'number'
     OR (NEW.observation->'measurement'->>'startedAtMs')::numeric<(attempt.request->>'issuedAtMs')::numeric
     OR (NEW.observation->'measurement'->>'completedAtMs')::numeric<(NEW.observation->'measurement'->>'startedAtMs')::numeric
     OR (NEW.observation->'measurement'->>'completedAtMs')::numeric>=(attempt.request->>'deadlineAtMs')::numeric
     OR (NEW.observation->'measurement'->>'completedAtMs')::numeric>(NEW.observation->>'retainedAtMs')::numeric
     OR NEW.observation->'measurement'->>'installationDigest' IS DISTINCT FROM attempt.request->>'installationDigest'
     OR NEW.observation->'measurement'->>'observationId' IS DISTINCT FROM NEW.observation_id::text
     OR NEW.observation->'measurement'->>'requestDigest' IS DISTINCT FROM attempt.request_digest
     OR EXISTS(SELECT 1 FROM unnest(ARRAY['sourceBuildLink','changeAuthorship','exactSocketProcess','qualification']) k WHERE NEW.observation->'measurement'->>k IS DISTINCT FROM 'UNESTABLISHED')
    THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_CLAIM'; END IF;
    IF NEW.observation->>'state'='OBSERVED' THEN
     IF jsonb_typeof(NEW.observation->'identityRecheckedAtMs') IS DISTINCT FROM 'number'
      OR (NEW.observation->>'identityRecheckedAtMs')::numeric<(NEW.observation->'measurement'->>'completedAtMs')::numeric
      OR (NEW.observation->>'identityRecheckedAtMs')::numeric>(NEW.observation->>'retainedAtMs')::numeric
     THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_RECHECK'; END IF;
    ELSIF NEW.observation->'identityRecheckedAtMs' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'QUALIFICATION_DEPLOYMENT_HISTORY'; END IF;
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_qualification_deployment_observation() FROM PUBLIC;
${[
  'qualification_deployment_installation',
  'qualification_deployment_attempt',
  'qualification_deployment_observation',
]
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='openpc_identity_runtime') THEN
  REVOKE ALL ON control.${table} FROM openpc_identity_runtime;
 END IF;
END $$;
GRANT SELECT ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
GRANT UPDATE ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner;
${table === 'qualification_deployment_installation' ? 'GRANT INSERT,UPDATE ON control.qualification_deployment_installation TO openpc_operations_qualification_bootstrap;' : `GRANT INSERT ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner;`}
DROP POLICY IF EXISTS qualification_deployment_read ON control.${table};
CREATE POLICY qualification_deployment_read ON control.${table} FOR SELECT TO openpc_control_owner,openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS qualification_deployment_write ON control.${table};
CREATE POLICY qualification_deployment_write ON control.${table} FOR ALL TO ${table === 'qualification_deployment_installation' ? 'openpc_operations_qualification_bootstrap' : 'openpc_control_owner,openpc_operations_qualification_owner'} USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS qualification_deployment_lock ON control.${table};
CREATE POLICY qualification_deployment_lock ON control.${table} FOR UPDATE TO openpc_control_owner,openpc_operations_qualification_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(false);
DROP TRIGGER IF EXISTS qualification_deployment_guard ON control.${table};
CREATE TRIGGER qualification_deployment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_qualification_deployment_observation();
DROP TRIGGER IF EXISTS qualification_deployment_truncate_guard ON control.${table};
CREATE TRIGGER qualification_deployment_truncate_guard BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_qualification_deployment_observation();`,
  )
  .join('\n')}
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_operations_qualification_bootstrap;
`;
