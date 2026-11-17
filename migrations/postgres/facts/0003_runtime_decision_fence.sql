-- SQLx-owned decision fence. A runtime reader holds the shared context lock
-- until evidence commit. Every supported lifecycle mutation takes its exclusive
-- counterpart before changing any eligibility, finality or checkpoint state.
CREATE FUNCTION facts.policy_fence_key(requested_participant text, requested_privacy_domain text)
RETURNS bigint LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path = pg_catalog
AS $$ SELECT hashtextextended('openpc:fact-runtime-fence:v1:' ||
  jsonb_build_array(requested_participant, requested_privacy_domain)::text, 0) $$;

CREATE OR REPLACE FUNCTION facts.assert_lifecycle_context(
  requested_participant text, requested_privacy_domain text
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'openpc_fact_bridge_writer', 'MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACT_LIFECYCLE_CALLER_REJECTED';
  END IF;
  IF pg_catalog.current_setting('openpc.participant_id', true) IS DISTINCT FROM requested_participant
     OR pg_catalog.current_setting('openpc.privacy_domain_id', true) IS DISTINCT FROM requested_privacy_domain THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACT_LIFECYCLE_CONTEXT_REJECTED';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(facts.policy_fence_key(requested_participant, requested_privacy_domain));
END $$;

CREATE FUNCTION facts.acquire_policy_read_fence(requested_participant text, requested_privacy_domain text)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF requested_participant IS NULL OR requested_participant = ''
     OR requested_privacy_domain IS NULL OR requested_privacy_domain = ''
     OR pg_catalog.current_setting('openpc.participant_id', true) IS DISTINCT FROM requested_participant
     OR pg_catalog.current_setting('openpc.privacy_domain_id', true) IS DISTINCT FROM requested_privacy_domain THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACT_POLICY_CONTEXT_REJECTED';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock_shared(facts.policy_fence_key(requested_participant, requested_privacy_domain));
END $$;
ALTER FUNCTION facts.policy_fence_key(text,text) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.acquire_policy_read_fence(text,text) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.policy_fence_key(text,text), facts.acquire_policy_read_fence(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.policy_fence_key(text,text) TO openpc_policy_fact_reader;
GRANT EXECUTE ON FUNCTION facts.acquire_policy_read_fence(text,text) TO openpc_policy_fact_reader;
