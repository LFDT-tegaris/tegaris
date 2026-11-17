import { operationsConfigurationCoseProfiles } from '../../../../../packages/security-kernel/src/operations-configuration/generated.ts';
const siteProfile = operationsConfigurationCoseProfiles.OperationsSiteDocumentV1;
const tables = [
  'operations_installation',
  'operations_generation',
  'operations_generation_binding',
  'operations_generation_commit',
];
export const operationsGenerationGuardsSql = String.raw`
${tables
  .map(
    (name) => `ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader,openpc_control_owner;
GRANT SELECT,TRIGGER ON control.${name} TO openpc_control_owner;
DROP POLICY IF EXISTS operations_installer ON control.${name};
CREATE POLICY operations_installer ON control.${name} TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));`,
  )
  .join('\n')}
GRANT INSERT,UPDATE ON control.operations_installation,control.operations_generation TO openpc_control_owner;
GRANT INSERT ON control.operations_generation_commit TO openpc_control_owner;
-- Deliberately no writer for binding attestations until each real qualification,
-- secret-resolution and workload-observation admission owner is connected. An
-- installer or SQL fixture must not fabricate intermediate verification state.

CREATE OR REPLACE FUNCTION openpc.operations_generation_requirements(p_schema jsonb,p_configuration jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_agg(requirement ORDER BY requirement) FROM (
 SELECT 'SOURCE:C17_AUTHENTICATION' requirement
 UNION SELECT 'QUALIFICATION:'||key FROM jsonb_object_keys(p_configuration->'qualificationInputBindings') key
 UNION SELECT 'SECRET:'||section.key||'.'||field.key
 FROM jsonb_each(p_schema->'properties') section CROSS JOIN LATERAL jsonb_each(section.value->'properties') field
 WHERE field.value->>'$ref'='#/$defs/SecretRef'
 UNION SELECT phase||':'||component
 FROM jsonb_array_elements(p_schema->'x-openpc-settingCatalog') setting
 CROSS JOIN LATERAL jsonb_array_elements_text(setting->'componentRefs') component
 CROSS JOIN (VALUES('CONSUMER_STAGED'),('CONSUMER_EFFECTIVE')) phases(phase)
 UNION SELECT phase||':'||unit FROM (VALUES
 ('DU-PC-WORKBENCH'),('DU-PC-CONTROL'),('DU-PC-COMPILER'),('DU-PC-FLEET-CONTROL'),
 ('DU-PC-RUNTIME'),('DU-PC-FACT-BRIDGE'),('DU-ENVOY'),('DU-OTEL-COLLECTOR')) units(unit)
 CROSS JOIN (VALUES('UNIT_STAGED'),('UNIT_EFFECTIVE')) phases(phase)
 ) required;
$$;

CREATE OR REPLACE FUNCTION openpc.operations_generation_missing(p_environment text,p_generation uuid)
-- Native qualification reads acquire source fences and check the live clock.
-- Do not cache this readiness result under a statement-stable snapshot.
RETURNS jsonb LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM control.operations_generation
 WHERE environment_id=p_environment AND generation_id=p_generation)
 THEN '["GENERATION:MISSING"]'::jsonb
 ELSE coalesce(jsonb_agg(requirement ORDER BY requirement),'[]'::jsonb) END
 FROM control.operations_generation g CROSS JOIN LATERAL jsonb_array_elements_text(g.requirements) requirement
 WHERE g.environment_id=p_environment AND g.generation_id=p_generation
 AND CASE WHEN requirement='SOURCE:C17_AUTHENTICATION'
 THEN NOT openpc.operations_generation_source_authenticated(p_environment,p_generation)
 WHEN requirement='QUALIFICATION:provider.read_retry_limit'
 THEN NOT coalesce(openpc.operations_provider_retry_qualification_bound(p_environment,p_generation),false)
 ELSE NOT EXISTS(SELECT 1 FROM control.operations_generation_binding b
 WHERE b.environment_id=g.environment_id AND b.generation_id=g.generation_id AND b.requirement_id=requirement
 AND b.participant_id=g.participant_id AND b.privacy_domain_id=g.privacy_domain_id AND b.state='CURRENT'
 AND b.valid_until_ms>floor(extract(epoch from clock_timestamp())*1000)
 AND b.effective_digest=g.candidate->'configuration'->'generation'->>'contentDigest') END;
$$;

CREATE OR REPLACE FUNCTION openpc.guard_operations_configuration() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installation control.operations_installation%ROWTYPE; candidate control.operations_generation%ROWTYPE;
 prior control.operations_generation_commit%ROWTYPE; environment text; requirement jsonb; payload bytea; signature bytea; m jsonb; pins jsonb; site jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'OPS_CONFIG_IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 environment:=NEW.environment_id;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('operations-generation:'||environment,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_TABLE_NAME='operations_installation' THEN
  IF TG_OP='UPDATE' THEN
   IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
   THEN RAISE EXCEPTION 'OPS_CONFIG_IMMUTABLE'; END IF;
  ELSIF NEW.state<>'ACTIVE' OR NEW.installation IS DISTINCT FROM convert_from(NEW.installation_bytes,'UTF8')::jsonb
   OR NEW.installation->'pins'->>'environmentId' IS DISTINCT FROM environment
   OR NEW.installation-ARRAY['pins','schema','namedProfile','initialBaseGenerationId','sourceAuthentication']<>'{}'::jsonb
   OR NOT NEW.installation ?& ARRAY['pins','schema','namedProfile','initialBaseGenerationId']
   OR (NEW.installation ? 'sourceAuthentication' AND NOT openpc.operations_source_authentication_valid(NEW.installation))
  THEN RAISE EXCEPTION 'OPS_CONFIG_INVALID'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT installation FROM control.operations_installation WHERE environment_id=environment FOR SHARE;
 IF installation.state<>'ACTIVE' THEN RAISE EXCEPTION 'OPS_CONFIG_INSTALLATION_REVOKED'; END IF;
 SELECT * INTO prior FROM control.operations_generation_commit WHERE environment_id=environment ORDER BY sequence DESC LIMIT 1;
 IF TG_TABLE_NAME='operations_generation' THEN
  IF TG_OP='UPDATE' THEN
   IF OLD.state<>'STAGED' OR NEW.state<>'FENCED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
    OR EXISTS(SELECT 1 FROM control.operations_generation_commit c WHERE c.environment_id=environment AND c.generation_id=NEW.generation_id)
   THEN RAISE EXCEPTION 'OPS_CONFIG_IMMUTABLE'; END IF;
   RETURN NEW;
  END IF;
  IF NEW.state<>'STAGED' OR NEW.candidate IS DISTINCT FROM convert_from(NEW.candidate_bytes,'UTF8')::jsonb
   OR NEW.candidate_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.candidate),'UTF8')
   OR NEW.candidate->'configuration'->>'environmentId' IS DISTINCT FROM environment
   OR NEW.candidate->'configuration'->'generation'->>'generationId' IS DISTINCT FROM 'urn:openpc:generation:'||NEW.generation_id::text
   OR NEW.candidate->'configuration'->'generation'->>'baseGenerationId' IS DISTINCT FROM 'urn:openpc:generation:'||NEW.base_generation_id::text
   OR NEW.requirements IS DISTINCT FROM openpc.operations_generation_requirements(installation.installation->'schema',NEW.candidate->'configuration')
   OR jsonb_array_length(NEW.requirements)<20
  THEN RAISE EXCEPTION 'OPS_CONFIG_INVALID'; END IF;
  pins:=installation.installation->'pins';
  payload:=decode(NEW.candidate->'source'->>'payloadHex','hex');
  signature:=decode(NEW.candidate->'source'->>'coseHex','hex');
  site:=convert_from(decode(NEW.candidate->'source'->>'siteHex','hex'),'UTF8')::jsonb;
  PERFORM openpc.archive_cose_binding(payload,signature,'sha256:'||encode(sha256(decode(pins->>'issuerSpkiHex','hex')),'hex'),${siteProfile.schemaId},${siteProfile.purposeCode});
  m:=openpc.business_cbor(payload);
  IF (SELECT count(*) FROM jsonb_object_keys(m))<>${siteProfile.fields.length}
   OR NOT m ?& ARRAY[${siteProfile.fields.map((f) => `'${f.key}'`).join(',')}]
   OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${siteProfile.definitionDigest.slice(7)}')
   OR m->>'1' IS DISTINCT FROM environment
   OR m->>'2' IS DISTINCT FROM (CASE pins->>'profile' WHEN 'local' THEN '1' WHEN 'development' THEN '2' WHEN 'test' THEN '3' WHEN 'staging' THEN '4' WHEN 'production' THEN '5' END)
   OR m->>'3' IS DISTINCT FROM 'urn:openpc:generation:'||NEW.generation_id::text
   OR m->>'4' IS DISTINCT FROM 'urn:openpc:generation:'||NEW.base_generation_id::text
   OR m->'5' IS DISTINCT FROM jsonb_build_object('bytes',encode(sha256(convert_to(openpc.signing_canonical_json(site),'UTF8')),'hex'))
   OR m->'6' IS DISTINCT FROM jsonb_build_object('bytes',substring(pins->>'configurationSchemaDigest' from 8))
   OR m->'7' IS DISTINCT FROM jsonb_build_object('bytes',substring(pins->>'namedProfileDigest' from 8))
   OR m->'8' IS DISTINCT FROM jsonb_build_object('bytes',substring(NEW.candidate->'configuration'->'generation'->>'contentDigest' from 8))
   OR m->'9' IS DISTINCT FROM jsonb_build_object('bytes',encode(sha256(decode(pins->>'issuerSpkiHex','hex')),'hex'))
   OR m->>'10' IS DISTINCT FROM pins->>'issuerEpoch'
   OR (m->>'11')::numeric < (pins->>'issuerValidFromMs')::numeric
   OR (m->>'12')::numeric > (pins->>'issuerValidUntilMs')::numeric
   OR (m->>'11')::numeric > floor(extract(epoch from clock_timestamp())*1000)
   OR (m->>'12')::numeric <= floor(extract(epoch from clock_timestamp())*1000)
  THEN RAISE EXCEPTION 'OPS_CONFIG_SITE_BINDING'; END IF;
  IF NEW.base_generation_id::text IS DISTINCT FROM coalesce(prior.generation_id::text,installation.installation->>'initialBaseGenerationId')
  THEN RAISE EXCEPTION 'OPS_CONFIG_GENERATION_MISMATCH'; END IF;
  IF EXISTS(SELECT 1 FROM control.operations_generation g WHERE g.environment_id=environment AND g.state='STAGED'
   AND NOT EXISTS(SELECT 1 FROM control.operations_generation_commit c WHERE c.environment_id=environment AND c.generation_id=g.generation_id))
  THEN RAISE EXCEPTION 'OPS_CONFIG_COHORT_PENDING'; END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='operations_generation_commit' THEN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'OPS_CONFIG_IMMUTABLE'; END IF;
  SELECT * INTO STRICT candidate FROM control.operations_generation WHERE environment_id=environment AND generation_id=NEW.generation_id FOR SHARE;
  IF candidate.state<>'STAGED' OR candidate.base_generation_id::text IS DISTINCT FROM coalesce(prior.generation_id::text,installation.installation->>'initialBaseGenerationId')
   OR NEW.sequence<>coalesce(prior.sequence,0)+1
   OR NEW.effective_digest IS DISTINCT FROM candidate.candidate->'configuration'->'generation'->>'contentDigest'
  THEN RAISE EXCEPTION 'OPS_CONFIG_GENERATION_MISMATCH'; END IF;
  requirement:=openpc.operations_generation_missing(environment,NEW.generation_id);
  IF requirement<>'[]'::jsonb THEN RAISE EXCEPTION 'OPS_CONFIG_BINDINGS_UNAVAILABLE'; END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'OPS_CONFIG_BINDING_ADMISSION_UNAVAILABLE';
END $$;
${tables
  .map(
    (name) => `DROP TRIGGER IF EXISTS operations_configuration_guard ON control.${name};
CREATE TRIGGER operations_configuration_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_operations_configuration();
DROP TRIGGER IF EXISTS operations_configuration_truncate_guard ON control.${name};
CREATE TRIGGER operations_configuration_truncate_guard BEFORE TRUNCATE ON control.${name}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_operations_configuration();
REVOKE TRIGGER ON control.${name} FROM openpc_control_owner;`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION openpc.guard_operations_configuration(),openpc.operations_generation_requirements(jsonb,jsonb),openpc.operations_generation_missing(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_generation_requirements(jsonb,jsonb),openpc.operations_generation_missing(text,uuid) TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.current_notification_delivery_limit(p_environment text)
RETURNS TABLE(generation_id uuid,effective_digest text,configured_limit integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE installed control.operations_installation%ROWTYPE; accepted control.operations_generation_commit%ROWTYPE;
 candidate control.operations_generation%ROWTYPE;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('operations-generation:'||p_environment,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO installed FROM control.operations_installation i WHERE i.environment_id=p_environment FOR SHARE;
 IF installed.environment_id IS NULL OR installed.state<>'ACTIVE' THEN RAISE EXCEPTION 'OPS_CONFIG_UNREADY'; END IF;
 SELECT * INTO accepted FROM control.operations_generation_commit c WHERE c.environment_id=p_environment ORDER BY c.sequence DESC LIMIT 1;
 IF accepted.generation_id IS NULL THEN RAISE EXCEPTION 'OPS_CONFIG_UNREADY'; END IF;
 SELECT * INTO STRICT candidate FROM control.operations_generation g WHERE g.environment_id=p_environment AND g.generation_id=accepted.generation_id FOR SHARE;
 IF candidate.state<>'STAGED' OR openpc.operations_generation_missing(p_environment,accepted.generation_id)<>'[]'::jsonb
 THEN RAISE EXCEPTION 'OPS_CONFIG_UNREADY'; END IF;
 generation_id:=accepted.generation_id; effective_digest:=accepted.effective_digest;
 configured_limit:=(candidate.candidate->'configuration'->'settings'->>'operations.notification_delivery_limit')::integer;
 IF configured_limit IS NULL OR configured_limit<0 OR configured_limit>100 THEN RAISE EXCEPTION 'OPS_CONFIG_INVALID'; END IF;
 RETURN NEXT;
END $$;
REVOKE ALL ON FUNCTION openpc.current_notification_delivery_limit(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.current_notification_delivery_limit(text) TO openpc_control_runtime;
`;
