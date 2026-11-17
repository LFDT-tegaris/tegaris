-- OPENPC-MIG-CANDIDATE-0002 / EXPAND_MIGRATE_CONTRACT M2-M5 evidence structures
-- trace-packs: TP-MIGRATION, TP-CANDIDATE, TP-DATA-RLS

\set ON_ERROR_STOP on
\if :{?openpc_migration_checksum}
\else
  \echo 'openpc_migration_checksum is required and must match migration-manifest.json'
  \quit 3
\endif
\if :{?openpc_migration_profile}
\else
  \echo 'openpc_migration_profile is required: MIG-GREENFIELD-V1 or MIG-PREDECESSOR-V1'
  \quit 3
\endif
\connect openpc_candidate_index
SET ROLE openpc_candidate_index_owner;
BEGIN;

CREATE TABLE candidate.migration_differential_sample (
  migration_run_id openpc.uuid_v7 NOT NULL,
  sample_id openpc.uuid_v7 NOT NULL DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  partition_key text NOT NULL CHECK (length(partition_key) BETWEEN 1 AND 256),
  source_candidate_digest openpc.sha256_bytes NOT NULL,
  successor_candidate_digest openpc.sha256_bytes NOT NULL,
  comparison_state text NOT NULL CHECK (comparison_state IN ('EQUAL', 'MISMATCH', 'SOURCE_ONLY', 'SUCCESSOR_ONLY')),
  sampled_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  PRIMARY KEY (migration_run_id, sample_id),
  CHECK (authority_eligible = false),
  UNIQUE (migration_run_id, partition_key, source_candidate_digest, successor_candidate_digest)
);

CREATE TABLE candidate.generation_activation_receipt (
  activation_receipt_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  migration_run_id openpc.uuid_v7,
  exact_cohort_digest openpc.sha256_bytes NOT NULL,
  checkpoint_digest openpc.sha256_bytes NOT NULL,
  differential_proof_digest openpc.sha256_bytes NOT NULL,
  receipt_cbor openpc.cbor_payload NOT NULL,
  receipt_digest openpc.sha256_bytes NOT NULL,
  activated_at timestamptz(6) NOT NULL,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  FOREIGN KEY (participant_id, privacy_domain_id, projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id, privacy_domain_id, projection_generation_id) ON DELETE RESTRICT,
  CHECK (sha256(receipt_cbor) = receipt_digest),
  CHECK (authority_eligible = false),
  UNIQUE (projection_generation_id, exact_cohort_digest),
  UNIQUE (receipt_digest)
);

CREATE INDEX candidate_migration_differential_mismatch_idx ON candidate.migration_differential_sample (participant_id, privacy_domain_id, migration_run_id, partition_key) WHERE comparison_state <> 'EQUAL';
CREATE INDEX candidate_activation_receipt_idx ON candidate.generation_activation_receipt (participant_id, privacy_domain_id, projection_generation_id, activated_at DESC);

ALTER TABLE candidate.migration_differential_sample ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.migration_differential_sample FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_isolation ON candidate.migration_differential_sample
  USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
  WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
ALTER TABLE candidate.generation_activation_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.generation_activation_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_isolation ON candidate.generation_activation_receipt
  USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
  WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
CREATE TRIGGER candidate_activation_receipt_immutable BEFORE UPDATE ON candidate.generation_activation_receipt FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

REVOKE ALL ON candidate.migration_differential_sample, candidate.generation_activation_receipt FROM PUBLIC;
GRANT SELECT, INSERT ON candidate.migration_differential_sample, candidate.generation_activation_receipt TO openpc_indexer_writer;
GRANT SELECT ON candidate.generation_activation_receipt TO openpc_fact_bridge_reader, openpc_candidate_index_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON candidate.migration_differential_sample, candidate.generation_activation_receipt TO openpc_candidate_index_maintenance;

INSERT INTO candidate.schema_migration(migration_id, migration_checksum, profile, phase)
SELECT 'OPENPC-MIG-CANDIDATE-0002', decode(substring(:'openpc_migration_checksum' from 8), 'hex')::openpc.sha256_bytes,
       :'openpc_migration_profile'::candidate.migration_profile, 'M3_SHADOW_DIFFERENTIAL_PROOF'
FROM candidate.schema_migration WHERE migration_id = 'OPENPC-MIG-CANDIDATE-0001';

COMMIT;
RESET ROLE;
