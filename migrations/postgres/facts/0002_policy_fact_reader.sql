-- SQLx-owned read capability for owner-resolved policy simulation. This role
-- cannot sign, admit, finalize, invalidate, or inspect mutation capabilities.
DO $roles$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='openpc_policy_fact_reader') THEN
    CREATE ROLE openpc_policy_fact_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END $roles$;
GRANT USAGE ON SCHEMA facts TO openpc_policy_fact_reader;
GRANT EXECUTE ON FUNCTION facts.matches_context(text,text) TO openpc_policy_fact_reader;
GRANT SELECT ON facts.canonical_fact, facts.admission_inbox, facts.fact_lineage,
  facts.source_checkpoint, facts.readiness_gate TO openpc_policy_fact_reader;
CREATE POLICY policy_reader_context ON facts.canonical_fact FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY policy_reader_context ON facts.admission_inbox FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY policy_reader_context ON facts.fact_lineage FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY policy_reader_context ON facts.source_checkpoint FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY policy_reader_context ON facts.readiness_gate FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
