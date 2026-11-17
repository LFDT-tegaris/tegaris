-- Candidate readers and writers need the transitive SECURITY INVOKER context
-- functions used by assert_request_context and forced row-level security.
-- Keep schema/table ownership and all business DML privileges unchanged.
\set ON_ERROR_STOP on
\if :{?openpc_migration_checksum}
\else
  \echo 'openpc_migration_checksum is required'
  \quit 3
\endif
\if :{?openpc_migration_profile}
\else
  \echo 'openpc_migration_profile is required'
  \quit 3
\endif
\connect openpc_candidate_index
SET ROLE openpc_candidate_index_owner;
BEGIN;

GRANT EXECUTE ON FUNCTION
  openpc.require_uuid_setting(text),
  openpc.current_participant_id(),
  openpc.current_privacy_domain_id(),
  openpc.current_operation_id(),
  openpc.current_action_intent_id(),
  openpc.matches_participant(uuid),
  openpc.matches_privacy(uuid)
TO openpc_indexer_writer, openpc_fact_bridge_reader, openpc_candidate_index_reader,
   openpc_candidate_index_maintenance, openpc_backup_operator;

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES ('OPENPC-MIG-CANDIDATE-0004',
        decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
        :'openpc_migration_profile'::candidate.migration_profile,
        'M1_ADDITIVE_INACTIVE');

COMMIT;
RESET ROLE;
