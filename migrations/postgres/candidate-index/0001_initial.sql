-- OPENPC-MIG-CANDIDATE-0001 / MIG-GREENFIELD-V1 and MIG-PREDECESSOR-V1 M1
-- trace-packs: TP-DATA-SCALARS, TP-DATA-OWNERSHIP, TP-DATA-RLS, TP-CANDIDATE,
-- TP-DATA-ASYNC-WORK, TP-MIGRATION

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

\ir ../../postgres/common-primitives.sql

CREATE SCHEMA candidate;
REVOKE ALL ON SCHEMA candidate FROM PUBLIC;

CREATE TYPE candidate.generation_state AS ENUM ('CREATED', 'BACKFILLING', 'SHADOW', 'READY', 'ACTIVE', 'STALE', 'REORG', 'RETIRED', 'FAILED');
CREATE TYPE candidate.candidate_state AS ENUM ('OBSERVED', 'VALIDATED_CANDIDATE', 'REMOVED', 'SUPERSEDED', 'QUARANTINED');
CREATE TYPE candidate.checkpoint_state AS ENUM ('OBSERVED', 'COMPLETE', 'STALE', 'REORG', 'FAILED');
CREATE TYPE candidate.qualification_state AS ENUM ('UNQUALIFIED', 'OBSERVING', 'QUALIFIED', 'DRIFTED', 'REVOKED');
CREATE TYPE candidate.migration_profile AS ENUM ('MIG-GREENFIELD-V1', 'MIG-PREDECESSOR-V1');
CREATE TYPE candidate.migration_phase AS ENUM ('M0_TRACE_FREEZE', 'M1_ADDITIVE_INACTIVE', 'M2_CHECKSUMMED_BACKFILL', 'M3_SHADOW_DIFFERENTIAL_PROOF', 'M4_EXACT_COHORT_ACTIVATION', 'M5_PREDECESSOR_RETIREMENT');

CREATE TABLE candidate.schema_migration (
  migration_id text PRIMARY KEY CHECK (migration_id ~ '^OPENPC-MIG-CANDIDATE-[0-9]{4}$'),
  migration_checksum openpc.sha256_bytes NOT NULL UNIQUE,
  profile candidate.migration_profile NOT NULL,
  phase candidate.migration_phase NOT NULL,
  applied_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  applied_by name NOT NULL DEFAULT current_user
);

CREATE TABLE candidate.migration_checkpoint (
  migration_run_id openpc.uuid_v7 NOT NULL,
  phase candidate.migration_phase NOT NULL,
  partition_key text NOT NULL CHECK (length(partition_key) BETWEEN 1 AND 256),
  source_cursor text NOT NULL CHECK (length(source_cursor) BETWEEN 1 AND 2048),
  source_count openpc.uint64 NOT NULL,
  source_digest openpc.sha256_bytes NOT NULL,
  successor_count openpc.uint64 NOT NULL,
  successor_digest openpc.sha256_bytes NOT NULL,
  verified_at timestamptz(6),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (migration_run_id, phase, partition_key),
  CHECK (verified_at IS NULL OR (source_count = successor_count AND source_digest = successor_digest))
);

CREATE TABLE candidate.source_profile (
  source_profile_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  indexer_profile_id openpc.uuid_v7 NOT NULL,
  chain_namespace text NOT NULL CHECK (length(chain_namespace) BETWEEN 1 AND 96),
  source_contract_urn openpc.openpc_urn NOT NULL,
  source_profile_cbor openpc.cbor_payload NOT NULL,
  source_profile_digest openpc.sha256_bytes NOT NULL,
  reorg_profile_digest openpc.sha256_bytes NOT NULL,
  finality_mode text NOT NULL CHECK (finality_mode IN ('CONFIRMATIONS', 'SAFE_TAG', 'FINALIZED_TAG')),
  confirmation_count integer,
  state candidate.qualification_state NOT NULL DEFAULT 'UNQUALIFIED',
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  CHECK (sha256(source_profile_cbor) = source_profile_digest),
  CHECK ((finality_mode = 'CONFIRMATIONS') = (confirmation_count IS NOT NULL)),
  CHECK (confirmation_count IS NULL OR confirmation_count > 0),
  UNIQUE (participant_id, privacy_domain_id, source_profile_digest),
  UNIQUE (participant_id, privacy_domain_id, source_profile_id)
);

CREATE TABLE candidate.projection_profile (
  projection_profile_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  source_profile_id openpc.uuid_v7 NOT NULL,
  projection_plan_id openpc.uuid_v7 NOT NULL,
  fact_type text NOT NULL CHECK (fact_type ~ '^[a-z][a-z0-9.]{1,127}$'),
  source_event_type text NOT NULL CHECK (source_event_type ~ '^[A-Za-z][A-Za-z0-9_]{0,127}$'),
  source_contract_address openpc.evm_address NOT NULL,
  schema_digest openpc.sha256_bytes NOT NULL,
  mapping_cbor openpc.cbor_payload NOT NULL,
  mapping_digest openpc.sha256_bytes NOT NULL,
  state candidate.qualification_state NOT NULL DEFAULT 'UNQUALIFIED',
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id, privacy_domain_id, source_profile_id)
    REFERENCES candidate.source_profile(participant_id, privacy_domain_id, source_profile_id) ON DELETE RESTRICT,
  CHECK (sha256(mapping_cbor) = mapping_digest),
  UNIQUE (participant_id, privacy_domain_id, projection_plan_id, fact_type, source_event_type, source_contract_address),
  UNIQUE (participant_id, privacy_domain_id, projection_profile_id)
);

CREATE TABLE candidate.projection_generation (
  projection_generation_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_profile_id openpc.uuid_v7 NOT NULL,
  generation_digest openpc.sha256_bytes NOT NULL,
  source_profile_digest openpc.sha256_bytes NOT NULL,
  projection_schema_digest openpc.sha256_bytes NOT NULL,
  state candidate.generation_state NOT NULL DEFAULT 'CREATED',
  effective_during tstzrange,
  predecessor_generation_digest openpc.sha256_bytes,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id, privacy_domain_id, projection_profile_id)
    REFERENCES candidate.projection_profile(participant_id, privacy_domain_id, projection_profile_id) ON DELETE RESTRICT,
  CHECK (effective_during IS NULL OR NOT isempty(effective_during)),
  CHECK (authority_eligible = false),
  EXCLUDE USING gist (participant_id WITH =, privacy_domain_id WITH =, projection_profile_id WITH =, effective_during WITH &&) WHERE (state = 'ACTIVE'),
  UNIQUE (participant_id, privacy_domain_id, generation_digest),
  UNIQUE (participant_id, privacy_domain_id, projection_generation_id)
);

CREATE TABLE candidate.candidate_block (
  candidate_block_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  chain_namespace text NOT NULL CHECK (length(chain_namespace) BETWEEN 1 AND 96),
  block_hash openpc.bytes32 NOT NULL,
  parent_hash openpc.bytes32 NOT NULL,
  block_number openpc.uint64 NOT NULL,
  block_timestamp timestamptz(6) NOT NULL,
  finality_state text NOT NULL CHECK (finality_state IN ('UNFINALIZED', 'SAFE', 'FINALIZED', 'REMOVED')),
  observed_at timestamptz(6) NOT NULL,
  source_payload_digest openpc.sha256_bytes NOT NULL,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  FOREIGN KEY (participant_id, privacy_domain_id, projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id, privacy_domain_id, projection_generation_id) ON DELETE RESTRICT,
  CHECK (authority_eligible = false),
  UNIQUE (projection_generation_id, block_hash),
  UNIQUE (projection_generation_id, block_number, block_hash),
  UNIQUE (participant_id, privacy_domain_id, candidate_block_id)
);

CREATE TABLE candidate.candidate_event (
  candidate_event_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  candidate_block_id openpc.uuid_v7 NOT NULL,
  transaction_hash openpc.bytes32 NOT NULL,
  transaction_index openpc.uint64 NOT NULL,
  log_index openpc.uint64 NOT NULL,
  contract_address openpc.evm_address NOT NULL,
  event_signature openpc.bytes32 NOT NULL,
  candidate_key_digest openpc.sha256_bytes NOT NULL,
  payload_cbor openpc.cbor_payload NOT NULL,
  payload_digest openpc.sha256_bytes NOT NULL,
  state candidate.candidate_state NOT NULL DEFAULT 'OBSERVED',
  removed_at timestamptz(6),
  observed_at timestamptz(6) NOT NULL,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  FOREIGN KEY (participant_id, privacy_domain_id, projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id, privacy_domain_id, projection_generation_id) ON DELETE RESTRICT,
  FOREIGN KEY (participant_id, privacy_domain_id, candidate_block_id)
    REFERENCES candidate.candidate_block(participant_id, privacy_domain_id, candidate_block_id) ON DELETE RESTRICT,
  CHECK (sha256(payload_cbor) = payload_digest),
  CHECK (authority_eligible = false),
  CHECK ((state = 'REMOVED') = (removed_at IS NOT NULL)),
  UNIQUE (projection_generation_id, transaction_hash, log_index),
  UNIQUE (participant_id, privacy_domain_id, candidate_event_id)
);

CREATE TABLE candidate.candidate_relation (
  candidate_relation_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  source_candidate_event_id openpc.uuid_v7 NOT NULL,
  relationship_type text NOT NULL CHECK (relationship_type ~ '^[a-z][a-z0-9.]{1,127}$'),
  target_candidate_event_id openpc.uuid_v7 NOT NULL,
  relation_digest openpc.sha256_bytes NOT NULL,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id, privacy_domain_id, projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id, privacy_domain_id, projection_generation_id) ON DELETE RESTRICT,
  FOREIGN KEY (participant_id, privacy_domain_id, source_candidate_event_id)
    REFERENCES candidate.candidate_event(participant_id, privacy_domain_id, candidate_event_id) ON DELETE RESTRICT,
  FOREIGN KEY (participant_id, privacy_domain_id, target_candidate_event_id)
    REFERENCES candidate.candidate_event(participant_id, privacy_domain_id, candidate_event_id) ON DELETE RESTRICT,
  CHECK (source_candidate_event_id <> target_candidate_event_id),
  CHECK (authority_eligible = false),
  UNIQUE (projection_generation_id, source_candidate_event_id, relationship_type, target_candidate_event_id)
);

CREATE TABLE candidate.checkpoint (
  checkpoint_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  checkpoint_kind text NOT NULL CHECK (checkpoint_kind IN ('BLOCK', 'SEQUENCE', 'BACKFILL_CURSOR')),
  position_cbor openpc.cbor_payload NOT NULL,
  position_digest openpc.sha256_bytes NOT NULL,
  state candidate.checkpoint_state NOT NULL,
  observed_at timestamptz(6) NOT NULL,
  completed_at timestamptz(6),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id, privacy_domain_id, projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id, privacy_domain_id, projection_generation_id) ON DELETE RESTRICT,
  CHECK (sha256(position_cbor) = position_digest),
  CHECK ((state = 'COMPLETE') = (completed_at IS NOT NULL)),
  UNIQUE (projection_generation_id, checkpoint_kind, position_digest),
  UNIQUE (participant_id, privacy_domain_id, checkpoint_id)
);

CREATE TABLE candidate.qualification_observation (
  qualification_observation_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_profile_id openpc.uuid_v7 NOT NULL,
  observation_type text NOT NULL CHECK (observation_type IN ('SCHEMA', 'FINALITY', 'REORG', 'DRIFT', 'DIFFERENTIAL')),
  input_digest openpc.sha256_bytes NOT NULL,
  result_digest openpc.sha256_bytes NOT NULL,
  outcome openpc.truth_state NOT NULL,
  observed_at timestamptz(6) NOT NULL,
  FOREIGN KEY (participant_id, privacy_domain_id, projection_profile_id)
    REFERENCES candidate.projection_profile(participant_id, privacy_domain_id, projection_profile_id) ON DELETE RESTRICT,
  UNIQUE (projection_profile_id, observation_type, input_digest, observed_at)
);

CREATE TABLE candidate.outbox_aggregate_head (
  participant_id openpc.uuid_v7 NOT NULL,
  aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9-]{0,62}$'),
  aggregate_id openpc.uuid_v7 NOT NULL,
  last_sequence openpc.uint64 NOT NULL DEFAULT 0,
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (participant_id, aggregate_type, aggregate_id)
);

CREATE TABLE candidate.outbox_event (
  event_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9-]{0,62}$'),
  aggregate_id openpc.uuid_v7 NOT NULL,
  aggregate_sequence openpc.uint64 NOT NULL,
  source openpc.openpc_urn NOT NULL,
  subject openpc.openpc_urn NOT NULL,
  event_type openpc.event_type NOT NULL,
  schema_uri openpc.schema_uri NOT NULL,
  correlation_id openpc.uuid_v7 NOT NULL,
  causation_id openpc.uuid_v7,
  payload_cbor openpc.cbor_payload NOT NULL,
  payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
  payload_digest openpc.sha256_bytes NOT NULL,
  occurred_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  state openpc.delivery_state NOT NULL DEFAULT 'PENDING',
  attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 10),
  available_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  lease_owner openpc.uuid_v7,
  lease_expires_at timestamptz(6),
  published_at timestamptz(6),
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  FOREIGN KEY (participant_id, aggregate_type, aggregate_id)
    REFERENCES candidate.outbox_aggregate_head(participant_id, aggregate_type, aggregate_id) ON DELETE RESTRICT,
  CHECK (sha256(payload_cbor) = payload_digest),
  CHECK (authority_eligible = false),
  CHECK ((state = 'LEASED') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK ((state = 'DELIVERED') = (published_at IS NOT NULL)),
  UNIQUE (participant_id, aggregate_type, aggregate_id, aggregate_sequence),
  UNIQUE (participant_id, event_id)
);

CREATE TABLE candidate.outbox_delivery_attempt (
  delivery_attempt_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  event_id openpc.uuid_v7 NOT NULL,
  attempt_number smallint NOT NULL CHECK (attempt_number BETWEEN 1 AND 10),
  worker_id openpc.uuid_v7 NOT NULL,
  state openpc.external_attempt_state NOT NULL DEFAULT 'NOT_STARTED',
  started_at timestamptz(6) NOT NULL,
  finished_at timestamptz(6),
  transport_receipt_digest openpc.sha256_bytes,
  error_code text CHECK (error_code IS NULL OR error_code ~ '^DATA-6[0-9]{3}-[A-Z0-9-]+$'),
  FOREIGN KEY (participant_id, event_id) REFERENCES candidate.outbox_event(participant_id, event_id) ON DELETE RESTRICT,
  CHECK (finished_at IS NULL OR finished_at >= started_at),
  UNIQUE (event_id, attempt_number)
);

CREATE TABLE candidate.inbox_consumer_head (
  consumer_id text NOT NULL CHECK (consumer_id = 'LS-INDEXER'),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  source openpc.openpc_urn NOT NULL,
  aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9-]{0,62}$'),
  aggregate_id openpc.uuid_v7 NOT NULL,
  last_sequence openpc.uint64 NOT NULL DEFAULT 0,
  last_event_id openpc.uuid_v7,
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (consumer_id, participant_id, source, aggregate_type, aggregate_id)
);

CREATE TABLE candidate.inbox_record (
  consumer_id text NOT NULL CHECK (consumer_id = 'LS-INDEXER'),
  event_id openpc.uuid_v7 NOT NULL,
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  source openpc.openpc_urn NOT NULL,
  aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9-]{0,62}$'),
  aggregate_id openpc.uuid_v7 NOT NULL,
  aggregate_sequence openpc.uint64 NOT NULL,
  payload_digest openpc.sha256_bytes NOT NULL,
  state openpc.inbox_state NOT NULL DEFAULT 'RECEIVED',
  effect_digest openpc.sha256_bytes,
  received_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  processed_at timestamptz(6),
  CHECK ((state = 'APPLIED') = (effect_digest IS NOT NULL AND processed_at IS NOT NULL)),
  PRIMARY KEY (consumer_id, event_id),
  UNIQUE (consumer_id, participant_id, source, aggregate_type, aggregate_id, aggregate_sequence)
);

CREATE TABLE candidate.quarantine_record (
  quarantine_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  object_type text NOT NULL CHECK (object_type IN ('SOURCE_PAYLOAD', 'CANDIDATE_EVENT', 'OUTBOX_EVENT', 'INBOX_EVENT')),
  object_id openpc.uuid_v7 NOT NULL,
  reason_code text NOT NULL CHECK (reason_code ~ '^DATA-6[0-9]{3}-[A-Z0-9-]+$'),
  payload_digest openpc.sha256_bytes NOT NULL,
  retry_exhausted_at timestamptz(6) NOT NULL,
  recovery_state openpc.truth_state NOT NULL DEFAULT 'FAILED',
  recovery_cursor_digest openpc.sha256_bytes,
  recovered_at timestamptz(6),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (object_type, object_id, payload_digest)
);

CREATE FUNCTION candidate.protect_candidate_event()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.candidate_event_id, OLD.participant_id, OLD.privacy_domain_id, OLD.projection_generation_id,
         OLD.candidate_block_id, OLD.transaction_hash, OLD.transaction_index, OLD.log_index, OLD.contract_address,
         OLD.event_signature, OLD.candidate_key_digest, OLD.payload_cbor, OLD.payload_digest, OLD.observed_at)
     IS DISTINCT FROM
     ROW(NEW.candidate_event_id, NEW.participant_id, NEW.privacy_domain_id, NEW.projection_generation_id,
         NEW.candidate_block_id, NEW.transaction_hash, NEW.transaction_index, NEW.log_index, NEW.contract_address,
         NEW.event_signature, NEW.candidate_key_digest, NEW.payload_cbor, NEW.payload_digest, NEW.observed_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.candidate_event';
  END IF;
  IF OLD.state <> NEW.state AND NOT (
    (OLD.state IN ('OBSERVED','VALIDATED_CANDIDATE') AND NEW.state IN ('REMOVED','SUPERSEDED','QUARANTINED'))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6200-CANDIDATE-STATE-TRANSITION-INVALID';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION candidate.protect_candidate_block()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.candidate_block_id, OLD.participant_id, OLD.privacy_domain_id, OLD.projection_generation_id,
         OLD.chain_namespace, OLD.block_hash, OLD.parent_hash, OLD.block_number, OLD.block_timestamp,
         OLD.observed_at, OLD.source_payload_digest)
     IS DISTINCT FROM
     ROW(NEW.candidate_block_id, NEW.participant_id, NEW.privacy_domain_id, NEW.projection_generation_id,
         NEW.chain_namespace, NEW.block_hash, NEW.parent_hash, NEW.block_number, NEW.block_timestamp,
         NEW.observed_at, NEW.source_payload_digest) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.candidate_block';
  END IF;
  IF OLD.finality_state <> NEW.finality_state AND NOT (
    (OLD.finality_state = 'UNFINALIZED' AND NEW.finality_state IN ('SAFE','FINALIZED','REMOVED'))
    OR (OLD.finality_state = 'SAFE' AND NEW.finality_state IN ('FINALIZED','REMOVED'))
    OR (OLD.finality_state = 'FINALIZED' AND NEW.finality_state = 'REMOVED')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6201-BLOCK-FINALITY-TRANSITION-INVALID';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER candidate_event_protect BEFORE UPDATE ON candidate.candidate_event FOR EACH ROW EXECUTE FUNCTION candidate.protect_candidate_event();
CREATE TRIGGER candidate_block_protect BEFORE UPDATE ON candidate.candidate_block FOR EACH ROW EXECUTE FUNCTION candidate.protect_candidate_block();
CREATE TRIGGER source_profile_touch BEFORE UPDATE ON candidate.source_profile FOR EACH ROW EXECUTE FUNCTION openpc.touch_versioned_row();
CREATE TRIGGER projection_profile_touch BEFORE UPDATE ON candidate.projection_profile FOR EACH ROW EXECUTE FUNCTION openpc.touch_versioned_row();
CREATE TRIGGER checkpoint_touch BEFORE UPDATE ON candidate.checkpoint FOR EACH ROW EXECUTE FUNCTION openpc.touch_versioned_row();
CREATE TRIGGER candidate_relation_immutable BEFORE UPDATE ON candidate.candidate_relation FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE TRIGGER qualification_observation_immutable BEFORE UPDATE ON candidate.qualification_observation FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

CREATE FUNCTION candidate.protect_outbox_event()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.event_id, OLD.participant_id, OLD.privacy_domain_id, OLD.aggregate_type, OLD.aggregate_id, OLD.aggregate_sequence,
         OLD.source, OLD.subject, OLD.event_type, OLD.schema_uri, OLD.correlation_id, OLD.causation_id,
         OLD.payload_cbor, OLD.payload_json, OLD.payload_digest, OLD.occurred_at)
     IS DISTINCT FROM
     ROW(NEW.event_id, NEW.participant_id, NEW.privacy_domain_id, NEW.aggregate_type, NEW.aggregate_id, NEW.aggregate_sequence,
         NEW.source, NEW.subject, NEW.event_type, NEW.schema_uri, NEW.correlation_id, NEW.causation_id,
         NEW.payload_cbor, NEW.payload_json, NEW.payload_digest, NEW.occurred_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.outbox_event';
  END IF;
  IF NEW.attempt_count < OLD.attempt_count THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-NONMONOTONIC-ATTEMPT';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER outbox_payload_immutable BEFORE UPDATE ON candidate.outbox_event FOR EACH ROW EXECUTE FUNCTION candidate.protect_outbox_event();
CREATE TRIGGER outbox_payload_digest_guard BEFORE INSERT ON candidate.outbox_event FOR EACH ROW EXECUTE FUNCTION openpc.verify_cbor_digest();

CREATE FUNCTION candidate.emit_outbox_event(
  p_participant_id openpc.uuid_v7,
  p_privacy_domain_id openpc.uuid_v7,
  p_aggregate_type text,
  p_aggregate_id openpc.uuid_v7,
  p_source openpc.openpc_urn,
  p_subject openpc.openpc_urn,
  p_event_type openpc.event_type,
  p_schema_uri openpc.schema_uri,
  p_correlation_id openpc.uuid_v7,
  p_causation_id openpc.uuid_v7,
  p_payload_cbor openpc.cbor_payload,
  p_payload_json jsonb,
  p_payload_digest openpc.sha256_bytes
)
RETURNS openpc.uuid_v7
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, candidate, openpc
AS $$
DECLARE v_sequence openpc.uint64; v_event_id openpc.uuid_v7 := uuidv7();
BEGIN
  IF sha256(p_payload_cbor) <> p_payload_digest THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6040-PAYLOAD-DIGEST-MISMATCH';
  END IF;
  INSERT INTO candidate.outbox_aggregate_head(participant_id, aggregate_type, aggregate_id, last_sequence)
  VALUES (p_participant_id, p_aggregate_type, p_aggregate_id, 0)
  ON CONFLICT (participant_id, aggregate_type, aggregate_id) DO NOTHING;
  SELECT last_sequence INTO v_sequence FROM candidate.outbox_aggregate_head
  WHERE participant_id = p_participant_id AND aggregate_type = p_aggregate_type AND aggregate_id = p_aggregate_id FOR UPDATE;
  IF v_sequence = 18446744073709551615::numeric THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6041-AGGREGATE-SEQUENCE-EXHAUSTED';
  END IF;
  v_sequence := v_sequence + 1;
  UPDATE candidate.outbox_aggregate_head SET last_sequence = v_sequence, updated_at = clock_timestamp()
  WHERE participant_id = p_participant_id AND aggregate_type = p_aggregate_type AND aggregate_id = p_aggregate_id;
  INSERT INTO candidate.outbox_event(event_id, participant_id, privacy_domain_id, aggregate_type, aggregate_id, aggregate_sequence,
    source, subject, event_type, schema_uri, correlation_id, causation_id, payload_cbor, payload_json, payload_digest)
  VALUES (v_event_id, p_participant_id, p_privacy_domain_id, p_aggregate_type, p_aggregate_id, v_sequence,
    p_source, p_subject, p_event_type, p_schema_uri, p_correlation_id, p_causation_id, p_payload_cbor, p_payload_json, p_payload_digest);
  RETURN v_event_id;
END
$$;

CREATE FUNCTION candidate.claim_outbox_batch(p_worker_id openpc.uuid_v7, p_batch_size integer, p_lease_ms openpc.duration_ms)
RETURNS SETOF candidate.outbox_event
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, candidate
AS $$
BEGIN
  IF p_batch_size NOT BETWEEN 1 AND 500 OR p_lease_ms NOT BETWEEN 1000 AND 300000 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6050-LEASE-BOUND-INVALID';
  END IF;
  RETURN QUERY WITH claimable AS (
    SELECT event_id FROM candidate.outbox_event
    WHERE attempt_count < 10 AND available_at <= clock_timestamp()
      AND (state IN ('PENDING','RETRY_WAIT') OR (state = 'LEASED' AND lease_expires_at <= clock_timestamp()))
    ORDER BY available_at, event_id FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  ) UPDATE candidate.outbox_event e
    SET state = 'LEASED', lease_owner = p_worker_id,
        lease_expires_at = clock_timestamp() + (p_lease_ms::text || ' milliseconds')::interval,
        attempt_count = e.attempt_count + 1
    FROM claimable WHERE e.event_id = claimable.event_id RETURNING e.*;
END
$$;

CREATE FUNCTION candidate.begin_inbox_event(
  p_event_id openpc.uuid_v7,
  p_participant_id openpc.uuid_v7,
  p_privacy_domain_id openpc.uuid_v7,
  p_source openpc.openpc_urn,
  p_aggregate_type text,
  p_aggregate_id openpc.uuid_v7,
  p_aggregate_sequence openpc.uint64,
  p_payload_digest openpc.sha256_bytes
)
RETURNS openpc.inbox_state
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, candidate
AS $$
DECLARE prior candidate.inbox_record%ROWTYPE; head_sequence openpc.uint64;
BEGIN
  INSERT INTO candidate.inbox_consumer_head(consumer_id,participant_id,privacy_domain_id,source,aggregate_type,aggregate_id)
  VALUES ('LS-INDEXER',p_participant_id,p_privacy_domain_id,p_source,p_aggregate_type,p_aggregate_id)
  ON CONFLICT (consumer_id,participant_id,source,aggregate_type,aggregate_id) DO NOTHING;
  SELECT last_sequence INTO head_sequence FROM candidate.inbox_consumer_head
  WHERE consumer_id='LS-INDEXER' AND participant_id=p_participant_id AND source=p_source AND aggregate_type=p_aggregate_type AND aggregate_id=p_aggregate_id FOR UPDATE;
  SELECT * INTO prior FROM candidate.inbox_record WHERE consumer_id='LS-INDEXER' AND event_id=p_event_id;
  IF FOUND THEN
    IF prior.payload_digest <> p_payload_digest THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6042-INBOX-DIGEST-CONFLICT'; END IF;
    RETURN 'DUPLICATE_SAME_DIGEST';
  END IF;
  IF p_aggregate_sequence <> head_sequence + 1 THEN
    INSERT INTO candidate.inbox_record(consumer_id,event_id,participant_id,privacy_domain_id,source,aggregate_type,aggregate_id,aggregate_sequence,payload_digest,state)
    VALUES ('LS-INDEXER',p_event_id,p_participant_id,p_privacy_domain_id,p_source,p_aggregate_type,p_aggregate_id,p_aggregate_sequence,p_payload_digest,'BLOCKED_SEQUENCE_GAP');
    INSERT INTO candidate.quarantine_record(participant_id,privacy_domain_id,object_type,object_id,reason_code,payload_digest,retry_exhausted_at,recovery_state)
    VALUES (p_participant_id,p_privacy_domain_id,'INBOX_EVENT',p_event_id,'DATA-6043-INBOX-SEQUENCE-GAP',p_payload_digest,clock_timestamp(),'RECOVERY');
    RETURN 'BLOCKED_SEQUENCE_GAP';
  END IF;
  INSERT INTO candidate.inbox_record(consumer_id,event_id,participant_id,privacy_domain_id,source,aggregate_type,aggregate_id,aggregate_sequence,payload_digest,state)
  VALUES ('LS-INDEXER',p_event_id,p_participant_id,p_privacy_domain_id,p_source,p_aggregate_type,p_aggregate_id,p_aggregate_sequence,p_payload_digest,'RECEIVED');
  RETURN 'RECEIVED';
END
$$;

CREATE FUNCTION candidate.complete_inbox_event(p_event_id openpc.uuid_v7, p_effect_digest openpc.sha256_bytes)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, candidate
AS $$
DECLARE r candidate.inbox_record%ROWTYPE; current_sequence openpc.uint64;
BEGIN
  SELECT * INTO STRICT r FROM candidate.inbox_record WHERE consumer_id='LS-INDEXER' AND event_id=p_event_id FOR UPDATE;
  IF r.state <> 'RECEIVED' THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6044-INBOX-NOT-RECEIVED'; END IF;
  SELECT last_sequence INTO current_sequence FROM candidate.inbox_consumer_head
  WHERE consumer_id=r.consumer_id AND participant_id=r.participant_id AND source=r.source AND aggregate_type=r.aggregate_type AND aggregate_id=r.aggregate_id FOR UPDATE;
  IF r.aggregate_sequence <> current_sequence + 1 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6043-INBOX-SEQUENCE-GAP'; END IF;
  UPDATE candidate.inbox_record SET state='APPLIED',effect_digest=p_effect_digest,processed_at=clock_timestamp()
  WHERE consumer_id='LS-INDEXER' AND event_id=p_event_id;
  UPDATE candidate.inbox_consumer_head SET last_sequence=r.aggregate_sequence,last_event_id=r.event_id,updated_at=clock_timestamp()
  WHERE consumer_id=r.consumer_id AND participant_id=r.participant_id AND source=r.source AND aggregate_type=r.aggregate_type AND aggregate_id=r.aggregate_id;
END
$$;

CREATE VIEW candidate.fact_bridge_feed_v1
WITH (security_invoker = true, security_barrier = true)
AS
SELECT e.candidate_event_id, e.participant_id, e.privacy_domain_id, e.projection_generation_id,
       g.generation_digest, g.source_profile_digest, p.projection_plan_id, p.fact_type, p.schema_digest,
       e.candidate_key_digest, e.payload_cbor, e.payload_digest, e.transaction_hash, e.log_index,
       b.block_hash, b.block_number, b.finality_state, e.state, e.observed_at,
       false AS authority_eligible
FROM candidate.candidate_event e
JOIN candidate.candidate_block b ON b.candidate_block_id = e.candidate_block_id
JOIN candidate.projection_generation g ON g.projection_generation_id = e.projection_generation_id
JOIN candidate.projection_profile p ON p.projection_profile_id = g.projection_profile_id
WHERE e.state = 'VALIDATED_CANDIDATE' AND g.state IN ('READY','ACTIVE') AND b.finality_state IN ('SAFE','FINALIZED');

CREATE VIEW candidate.outbox_ready_v1
WITH (security_invoker = true, security_barrier = true)
AS SELECT event_id, participant_id, privacy_domain_id, aggregate_type, aggregate_id, aggregate_sequence,
          event_type, payload_digest, available_at, attempt_count, false AS authority_eligible
FROM candidate.outbox_event
WHERE attempt_count < 10 AND available_at <= clock_timestamp()
  AND (state IN ('PENDING','RETRY_WAIT') OR (state='LEASED' AND lease_expires_at <= clock_timestamp()));

CREATE INDEX source_profile_state_idx ON candidate.source_profile (participant_id, privacy_domain_id, state, source_profile_id);
CREATE INDEX projection_profile_state_idx ON candidate.projection_profile (participant_id, privacy_domain_id, state, projection_profile_id);
CREATE INDEX projection_generation_state_idx ON candidate.projection_generation (participant_id, privacy_domain_id, state, projection_generation_id);
CREATE INDEX candidate_block_number_idx ON candidate.candidate_block (participant_id, privacy_domain_id, chain_namespace, block_number, block_hash);
CREATE INDEX candidate_event_feed_idx ON candidate.candidate_event (participant_id, privacy_domain_id, projection_generation_id, state, observed_at, candidate_event_id);
CREATE INDEX candidate_event_key_idx ON candidate.candidate_event (participant_id, privacy_domain_id, candidate_key_digest, observed_at DESC);
CREATE INDEX candidate_relation_source_idx ON candidate.candidate_relation (participant_id, privacy_domain_id, relationship_type, source_candidate_event_id, target_candidate_event_id);
CREATE INDEX checkpoint_latest_idx ON candidate.checkpoint (participant_id, privacy_domain_id, projection_generation_id, checkpoint_kind, observed_at DESC);
CREATE INDEX qualification_observation_idx ON candidate.qualification_observation (participant_id, privacy_domain_id, projection_profile_id, observation_type, observed_at DESC);
CREATE INDEX outbox_ready_idx ON candidate.outbox_event (available_at, event_id) WHERE state IN ('PENDING','RETRY_WAIT','LEASED');
CREATE INDEX inbox_blocked_idx ON candidate.inbox_record (participant_id, privacy_domain_id, received_at, event_id) WHERE state IN ('BLOCKED_SEQUENCE_GAP','QUARANTINED');
CREATE INDEX quarantine_recovery_idx ON candidate.quarantine_record (participant_id, privacy_domain_id, recovery_state, created_at, quarantine_id);

DO $rls$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'source_profile','projection_profile','projection_generation','candidate_block','candidate_event','candidate_relation',
    'checkpoint','qualification_observation','outbox_event','inbox_consumer_head','inbox_record','quarantine_record'
  ] LOOP
    EXECUTE format('ALTER TABLE candidate.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE candidate.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY privacy_isolation ON candidate.%I USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))', table_name);
  END LOOP;
END
$rls$;

ALTER TABLE candidate.outbox_aggregate_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.outbox_aggregate_head FORCE ROW LEVEL SECURITY;
CREATE POLICY participant_isolation ON candidate.outbox_aggregate_head
  USING (openpc.matches_participant(participant_id)) WITH CHECK (openpc.matches_participant(participant_id));
ALTER TABLE candidate.outbox_delivery_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.outbox_delivery_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY participant_isolation ON candidate.outbox_delivery_attempt
  USING (openpc.matches_participant(participant_id)) WITH CHECK (openpc.matches_participant(participant_id));

REVOKE ALL ON ALL TABLES IN SCHEMA candidate FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, candidate FROM PUBLIC;
GRANT USAGE ON SCHEMA openpc, candidate TO openpc_indexer_writer, openpc_fact_bridge_reader, openpc_candidate_index_reader, openpc_candidate_index_maintenance, openpc_backup_operator;
GRANT EXECUTE ON FUNCTION openpc.set_request_context(openpc.context_mode,uuid,uuid,openpc.uuid_v7,openpc.action_intent_id,boolean), openpc.assert_request_context(boolean), openpc.uuid_to_urn(text,openpc.uuid_v7), openpc.digest_to_text(openpc.sha256_bytes)
  TO openpc_indexer_writer, openpc_fact_bridge_reader, openpc_candidate_index_reader;
GRANT EXECUTE ON FUNCTION candidate.emit_outbox_event(openpc.uuid_v7,openpc.uuid_v7,text,openpc.uuid_v7,openpc.openpc_urn,openpc.openpc_urn,openpc.event_type,openpc.schema_uri,openpc.uuid_v7,openpc.uuid_v7,openpc.cbor_payload,jsonb,openpc.sha256_bytes),
  candidate.claim_outbox_batch(openpc.uuid_v7,integer,openpc.duration_ms),
  candidate.begin_inbox_event(openpc.uuid_v7,openpc.uuid_v7,openpc.uuid_v7,openpc.openpc_urn,text,openpc.uuid_v7,openpc.uint64,openpc.sha256_bytes),
  candidate.complete_inbox_event(openpc.uuid_v7,openpc.sha256_bytes)
  TO openpc_indexer_writer;

GRANT SELECT, INSERT, UPDATE ON candidate.source_profile, candidate.projection_profile, candidate.projection_generation,
  candidate.candidate_block, candidate.candidate_event, candidate.checkpoint, candidate.outbox_aggregate_head,
  candidate.outbox_event, candidate.inbox_consumer_head, candidate.inbox_record, candidate.quarantine_record
  TO openpc_indexer_writer;
GRANT SELECT, INSERT ON candidate.candidate_relation, candidate.qualification_observation, candidate.outbox_delivery_attempt
  TO openpc_indexer_writer;
GRANT SELECT ON candidate.fact_bridge_feed_v1, candidate.projection_profile, candidate.projection_generation,
  candidate.candidate_block, candidate.candidate_event, candidate.outbox_event, candidate.checkpoint, candidate.qualification_observation
  TO openpc_fact_bridge_reader;
GRANT SELECT ON candidate.source_profile, candidate.projection_profile, candidate.projection_generation, candidate.candidate_block,
  candidate.candidate_event, candidate.candidate_relation, candidate.checkpoint, candidate.qualification_observation,
  candidate.outbox_event, candidate.inbox_record, candidate.quarantine_record, candidate.fact_bridge_feed_v1, candidate.outbox_ready_v1
  TO openpc_candidate_index_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA candidate TO openpc_candidate_index_maintenance;
GRANT SELECT ON ALL TABLES IN SCHEMA candidate TO openpc_backup_operator;

ALTER DEFAULT PRIVILEGES FOR ROLE openpc_candidate_index_owner IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE openpc_candidate_index_owner IN SCHEMA candidate REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE openpc_candidate_index_owner IN SCHEMA candidate REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

INSERT INTO candidate.schema_migration(migration_id, migration_checksum, profile, phase)
VALUES ('OPENPC-MIG-CANDIDATE-0001', decode(substring(:'openpc_migration_checksum' from 8), 'hex')::openpc.sha256_bytes,
        :'openpc_migration_profile'::candidate.migration_profile, 'M1_ADDITIVE_INACTIVE');

COMMIT;
RESET ROLE;
