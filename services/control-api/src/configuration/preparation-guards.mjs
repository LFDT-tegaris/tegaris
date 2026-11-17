import { policyGenerationFenceSql } from '../../../module-registry/src/db/policy-generation-fence.mjs';

/** Preparation provenance is absence, never a fabricated policy or serving grant. */
export const preparationGuardsSql = `
${policyGenerationFenceSql}
CREATE OR REPLACE FUNCTION openpc.configuration_policy_provenance(pid uuid, privacy uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE selected text; cardinality bigint;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'DATA-6001-CONTEXT-INVALID'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||pid::text||':'||privacy::text,0));
 SELECT count(*),min('sha256:'||encode(generation_digest,'hex')) INTO cardinality,selected
 FROM control.policy_generation WHERE participant_id=pid AND privacy_domain_id=privacy AND active AND state='ACTIVE';
 IF cardinality=1 THEN RETURN selected; END IF;
 IF cardinality<>0 THEN RAISE EXCEPTION 'DATA-6007-CONFIGURATION-POLICY-UNAVAILABLE'; END IF;
 -- A published generation can require fresh provider preparation before its
 -- first activation. Bind that preparation to the sole approved generation,
 -- never to an arbitrary or failed generation.
 SELECT count(*),min('sha256:'||encode(g.generation_digest,'hex')) INTO cardinality,selected
 FROM control.policy_generation g
 JOIN control.policy_release_bundle r ON r.participant_id=g.participant_id
  AND r.privacy_domain_id=g.privacy_domain_id
  AND r.policy_version_id=g.policy_version_id
  AND r.approval_request_id=g.approval_request_id
  AND r.manifest_digest=g.generation_digest
  AND r.state IN ('PUBLISHED','STAGED')
 WHERE g.participant_id=pid AND g.privacy_domain_id=privacy
  AND g.state='PREPARED' AND NOT g.active;
 IF cardinality=1 THEN RETURN selected; END IF;
 IF cardinality<>0 OR EXISTS(SELECT 1 FROM control.policy_generation WHERE participant_id=pid AND privacy_domain_id=privacy)
 THEN RAISE EXCEPTION 'DATA-6007-CONFIGURATION-POLICY-UNAVAILABLE'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.configuration_policy_provenance(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.configuration_policy_provenance(uuid,uuid) TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_configuration_preparation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'DATA-6001-CONTEXT-INVALID'; END IF;
 IF TG_OP='UPDATE' AND (NEW.participant_id IS DISTINCT FROM OLD.participant_id OR NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id)
 THEN RAISE EXCEPTION 'DATA-6007-PREPARATION-SCOPE-IMMUTABLE'; END IF;
 IF NEW.policy_generation_digest IS NULL THEN
  IF TG_TABLE_NAME='configuration_work' THEN
   IF NEW.work_kind NOT IN ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION')
   THEN RAISE EXCEPTION 'DATA-6007-SERVING-POLICY-REQUIRED'; END IF;
  END IF;
  IF TG_OP='INSERT' OR OLD.policy_generation_digest IS NOT NULL THEN
   IF openpc.configuration_policy_provenance(NEW.participant_id,NEW.privacy_domain_id) IS NOT NULL
   THEN RAISE EXCEPTION 'DATA-6007-PREPARATION-PROVENANCE-REQUIRED'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
${['provider_profile', 'indexer_profile', 'projection_plan', 'runtime_target', 'configuration_work']
  .map(
    (table) => `
DROP TRIGGER IF EXISTS configuration_preparation_fence ON control.${table};
CREATE TRIGGER configuration_preparation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS configuration_preparation_provenance ON control.${table};
CREATE TRIGGER configuration_preparation_provenance BEFORE INSERT OR UPDATE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_configuration_preparation();`,
  )
  .join('\n')}

-- Reference fences only: these owners retain their own row provenance and
-- immutable-publication checks, not configuration preparation semantics.
${[
  ['runtime_configuration_generation', 'TRY_CIGL_INSERT'],
  ['cigl_settings', 'TRY'],
]
  .map(
    ([table, mode]) => `
DROP TRIGGER IF EXISTS ${table}_reference_fence ON control.${table};
CREATE TRIGGER ${table}_reference_fence BEFORE INSERT OR UPDATE OR DELETE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence('${mode}');`,
  )
  .join('\n')}
`;

/** Contract registration provenance is immutable history, never a serving lease. */
export const contractRegistrationGuardsSql = `
GRANT EXECUTE ON FUNCTION openpc.configuration_policy_provenance(uuid,uuid) TO openpc_control_platform_runtime;
${[
  'abi_artifact',
  'logical_contract_asset',
  'contract_runtime_binding',
  'typed_argument_rule_version',
  'contract_method_policy',
]
  .map(
    (table) => `
CREATE OR REPLACE FUNCTION openpc.guard_${table}_registration()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected text;
BEGIN
 IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'${table}' OR TG_OP NOT IN ('INSERT','UPDATE')
 THEN RAISE EXCEPTION 'DATA-6004-CONTRACT-REGISTRATION-OWNER'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'DATA-6001-CONTEXT-INVALID'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.participant_id IS DISTINCT FROM OLD.participant_id OR NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id
    OR NEW.policy_generation_digest IS DISTINCT FROM OLD.policy_generation_digest
  THEN RAISE EXCEPTION 'DATA-6007-CONTRACT-REGISTRATION-IMMUTABLE'; END IF;
 ELSE
  expected:=openpc.configuration_policy_provenance(NEW.participant_id,NEW.privacy_domain_id);
  IF NEW.policy_generation_digest IS DISTINCT FROM expected
  THEN RAISE EXCEPTION 'DATA-6007-CONTRACT-REGISTRATION-PROVENANCE'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS contract_registration_fence ON control.${table};
CREATE TRIGGER contract_registration_fence BEFORE INSERT OR UPDATE OR DELETE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();
DROP TRIGGER IF EXISTS contract_registration_provenance ON control.${table};
CREATE TRIGGER contract_registration_provenance BEFORE INSERT OR UPDATE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_${table}_registration();
`,
  )
  .join('\n')}
`;
