-- SQLx-owned candidate retirement observation; existing shared eligibility predicate.
-- No Control authority, host key or verifier secret is provisioned here.
\set ON_ERROR_STOP on
\if :{?openpc_migration_checksum}
\else
  \quit 3
\endif
\if :{?openpc_migration_profile}
\else
  \quit 3
\endif
\connect openpc_candidate_index
SET ROLE openpc_candidate_index_owner;
BEGIN;

-- The reader can invoke only the shared observation predicate. Its definer
-- takes the established locks, then returns a blocker without any business DML.
-- Direct lock/execute/cancel/capability grants remain exclusive to the writer.
CREATE OR REPLACE FUNCTION candidate.lock_store_retirement(p uuid,d uuid,g uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF session_user='openpc_candidate_index_reader' THEN
    IF pg_has_role(session_user,'openpc_indexer_writer','MEMBER')
      OR pg_has_role(session_user,'openpc_candidate_index_owner','MEMBER')
      OR has_table_privilege(session_user,'candidate.candidate_event','INSERT,UPDATE,DELETE,TRUNCATE')
      OR has_table_privilege(session_user,'candidate.retirement_capability_secret','SELECT') THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_CANDIDATE_OBSERVATION_ROLE';
    END IF;
  ELSIF session_user<>'openpc_indexer_writer' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_ROLE';
  END IF;
  PERFORM openpc.assert_request_context(true);
  IF p IS DISTINCT FROM openpc.current_participant_id() OR d IS DISTINCT FROM openpc.current_privacy_domain_id() THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_SCOPE';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('candidate-retirement:'||p::text||':'||d::text,0));
  PERFORM 1 FROM candidate.projection_generation
    WHERE participant_id=p AND privacy_domain_id=d AND projection_generation_id=g FOR UPDATE;
END $$;
REVOKE ALL ON FUNCTION candidate.lock_store_retirement(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.lock_store_retirement(uuid,uuid,uuid) TO openpc_indexer_writer;

GRANT EXECUTE ON FUNCTION candidate.check_store_retirement(jsonb) TO openpc_candidate_index_reader;

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES('OPENPC-MIG-CANDIDATE-0009',decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
 :'openpc_migration_profile'::candidate.migration_profile,'M1_ADDITIVE_INACTIVE');
COMMIT;
RESET ROLE;
