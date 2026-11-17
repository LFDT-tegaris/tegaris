/** Statement-level acquisition precedes row locks, including the first active generation. */
export const policyGenerationFenceSql = `
CREATE OR REPLACE FUNCTION openpc.guard_policy_generation_fence()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE mode text; scope_key bigint;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_NARGS=0 THEN mode:='BLOCKING';
 ELSIF TG_NARGS=1 AND TG_ARGV[0] IN ('TRY','TRY_CIGL_INSERT') THEN mode:=TG_ARGV[0];
 ELSE RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PC-DATA-6004'; END IF;
 IF mode='TRY_CIGL_INSERT' THEN
  IF TG_TABLE_SCHEMA<>'control' OR TG_TABLE_NAME<>'runtime_configuration_generation'
  THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PC-DATA-6004'; END IF;
  -- Its INSERT row guard takes the grant fence. Acquire it without waiting
  -- before policy, even for an empty INSERT or a caller already holding rows.
  IF TG_OP='INSERT' THEN PERFORM openpc.lock_cigl_grant_sources(true); END IF;
 END IF;
 scope_key:=hashtextextended('openpc-policy-generations:'||
  current_setting('openpc.participant_id')||':'||current_setting('openpc.privacy_domain_id'),0);
 IF mode='BLOCKING' THEN PERFORM pg_advisory_xact_lock(scope_key);
 ELSIF NOT pg_try_advisory_xact_lock(scope_key)
 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS policy_generation_mutation_fence ON control.policy_generation;
CREATE TRIGGER policy_generation_mutation_fence BEFORE INSERT OR UPDATE OR DELETE ON control.policy_generation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence();

-- Public activation and Fleet use different entrypoints. Cover every statement
-- without waiting behind a caller's earlier occurrence/target row locks.
${['policy_activation_occurrence', 'policy_activation_occurrence_target']
  .map(
    (table) => `
DROP TRIGGER IF EXISTS ${table}_reference_fence ON control.${table};
CREATE TRIGGER ${table}_reference_fence BEFORE INSERT OR UPDATE OR DELETE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_policy_generation_fence('TRY');`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.guard_policy_generation_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6007-POLICY-HISTORY-IMMUTABLE'; END IF;
 IF TG_OP='UPDATE' AND (NEW.participant_id IS DISTINCT FROM OLD.participant_id OR
   NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id OR NEW.policy_generation_id IS DISTINCT FROM OLD.policy_generation_id)
 THEN RAISE EXCEPTION 'DATA-6007-POLICY-HISTORY-IMMUTABLE'; END IF;
 IF TG_OP='INSERT' AND to_regclass('control.configuration_work') IS NOT NULL THEN
  IF EXISTS(SELECT 1 FROM control.configuration_work WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND policy_generation_digest IS NULL
    AND state IN ('PENDING','LEASED','RECONCILING'))
  THEN RAISE EXCEPTION 'DATA-6007-INITIAL-PREPARATION-INCOMPLETE'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS policy_generation_history ON control.policy_generation;
CREATE TRIGGER policy_generation_history BEFORE INSERT OR UPDATE OR DELETE ON control.policy_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_policy_generation_history();

-- Public policy-set readback derives its active digest from these generations.
-- Advance the parent revision in the same transaction, including retirement and
-- rollback, so an unchanged ETag can never hide a changed active version.
CREATE OR REPLACE FUNCTION openpc.advance_policy_set_generation_revision()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT (NEW.active AND NEW.state='ACTIVE') THEN RETURN NEW; END IF;
 ELSIF (NEW.active AND NEW.state='ACTIVE') IS NOT DISTINCT FROM
       (OLD.active AND OLD.state='ACTIVE') AND NEW.policy_version_id=OLD.policy_version_id THEN
  RETURN NEW;
 END IF;
 UPDATE control.policy SET row_version=row_version+1,updated_at=clock_timestamp()
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
    AND policy_id IN (SELECT policy_id FROM control.policy_version
      WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
        AND (policy_version_id=NEW.policy_version_id OR
             (TG_OP='UPDATE' AND policy_version_id=OLD.policy_version_id)));
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS policy_set_generation_revision ON control.policy_generation;
CREATE TRIGGER policy_set_generation_revision AFTER INSERT OR UPDATE ON control.policy_generation
 FOR EACH ROW EXECUTE FUNCTION openpc.advance_policy_set_generation_revision();
`;
