-- Publish immutable governed source/projection lineage separately from the
-- untrusted candidate writer. Publication never makes a candidate authoritative.
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

-- A governed UPDATE keeps the public projection identity and creates new
-- immutable mapping bytes. Retain its older mapping rows and generations.
DO $mapping_identity$
DECLARE constraint_name name;
BEGIN
  SELECT c.conname INTO STRICT constraint_name
    FROM pg_constraint c
    JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attname='projection_plan_id'
   WHERE c.conrelid='candidate.projection_profile'::regclass
     AND c.contype='u' AND a.attnum=ANY(c.conkey);
  EXECUTE format('ALTER TABLE candidate.projection_profile DROP CONSTRAINT %I', constraint_name);
END
$mapping_identity$;
DROP INDEX candidate.projection_profile_qualified_identity_uq;
CREATE UNIQUE INDEX projection_profile_mapping_identity_uq
  ON candidate.projection_profile
  (participant_id,privacy_domain_id,source_profile_id,projection_plan_id,
   mapping_digest,fact_type,source_event_type,source_contract_address)
  NULLS NOT DISTINCT;

CREATE TABLE candidate.source_publication (
  projection_generation_id openpc.uuid_v7 PRIMARY KEY,
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  qualification_operation_id openpc.uuid_v7 NOT NULL,
  projection_revision bigint NOT NULL CHECK (projection_revision > 0),
  validation_operation_id openpc.uuid_v7 NOT NULL,
  configuration_digest openpc.sha256_bytes NOT NULL,
  finality_rule_cbor openpc.cbor_payload NOT NULL,
  finality_rule_digest openpc.sha256_bytes NOT NULL,
  acquisition_configuration_cbor openpc.cbor_payload NOT NULL,
  acquisition_configuration_digest openpc.sha256_bytes NOT NULL,
  publication_cbor openpc.cbor_payload NOT NULL,
  publication_digest openpc.sha256_bytes NOT NULL,
  state text NOT NULL DEFAULT 'PUBLISHED' CHECK (state IN ('PUBLISHED','FENCED','RETIRED')),
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id,privacy_domain_id,projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id,privacy_domain_id,projection_generation_id)
    ON DELETE RESTRICT,
  CHECK (sha256(finality_rule_cbor)=finality_rule_digest),
  CHECK (sha256(acquisition_configuration_cbor)=acquisition_configuration_digest),
  CHECK (sha256(publication_cbor)=publication_digest),
  CHECK (authority_eligible=false),
  UNIQUE (participant_id,privacy_domain_id,publication_digest)
);

CREATE FUNCTION candidate.protect_source_publication()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  IF (to_jsonb(OLD)-'state'-'authority_eligible') IS DISTINCT FROM (to_jsonb(NEW)-'state'-'authority_eligible')
     OR (OLD.state='FENCED' AND NEW.state NOT IN ('FENCED','RETIRED'))
     OR (OLD.state='RETIRED' AND NEW.state<>'RETIRED') THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER source_publication_immutable
  BEFORE UPDATE OR DELETE ON candidate.source_publication
  FOR EACH ROW EXECUTE FUNCTION candidate.protect_source_publication();

ALTER TABLE candidate.source_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.source_publication FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_isolation ON candidate.source_publication
  USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
  WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));

REVOKE ALL ON candidate.source_publication FROM PUBLIC;
REVOKE ALL ON FUNCTION candidate.protect_source_publication() FROM PUBLIC;
GRANT USAGE ON SCHEMA openpc,candidate TO openpc_indexer_manager;
GRANT EXECUTE ON FUNCTION
  openpc.set_request_context(openpc.context_mode,uuid,uuid,openpc.uuid_v7,openpc.action_intent_id,boolean),
  openpc.assert_request_context(boolean),
  openpc.require_uuid_setting(text),
  openpc.current_participant_id(),
  openpc.current_privacy_domain_id(),
  openpc.current_operation_id(),
  openpc.current_action_intent_id(),
  openpc.matches_participant(uuid),
  openpc.matches_privacy(uuid)
TO openpc_indexer_manager;
GRANT SELECT,INSERT ON candidate.source_profile,candidate.projection_profile,
  candidate.projection_generation,candidate.source_publication,candidate.candidate_partition
  TO openpc_indexer_manager;
GRANT UPDATE (state) ON candidate.projection_generation,candidate.source_publication
  TO openpc_indexer_manager;
GRANT SELECT ON candidate.source_publication
  TO openpc_indexer_writer,openpc_fact_bridge_reader,openpc_candidate_index_reader;
GRANT SELECT ON candidate.source_publication TO openpc_backup_operator;

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES ('OPENPC-MIG-CANDIDATE-0005',
        decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
        :'openpc_migration_profile'::candidate.migration_profile,
        'M1_ADDITIVE_INACTIVE');

COMMIT;
RESET ROLE;
