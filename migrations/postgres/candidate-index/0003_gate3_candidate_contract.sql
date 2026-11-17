-- OPENPC-MIG-CANDIDATE-0003 / I06 Gate3 typed candidate ownership closure
-- trace-packs: TP-CANDIDATE, TP-DATA-OWNERSHIP, TP-DATA-RLS, TP-MIGRATION

\set ON_ERROR_STOP on
\if :{?openpc_migration_checksum}
\else
  \echo 'openpc_migration_checksum is required and must match the changed-file manifest'
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

CREATE DOMAIN candidate.schema_reference AS text
  CHECK (
    VALUE ~ '^https://schemas\.openpc\.local/[A-Za-z0-9._~!$&''()*+,;=:@%/-]+$'
    OR VALUE ~ '^https://schemas\.openpc\.local/[A-Za-z0-9._~!$&''()*+,;=:@%/-]+#/\$defs/[A-Za-z][A-Za-z0-9]*$'
  );

ALTER TABLE candidate.outbox_event
  ALTER COLUMN schema_uri TYPE candidate.schema_reference
  USING schema_uri::text::candidate.schema_reference;

DROP FUNCTION candidate.emit_outbox_event(
  openpc.uuid_v7,openpc.uuid_v7,text,openpc.uuid_v7,openpc.openpc_urn,openpc.openpc_urn,
  openpc.event_type,openpc.schema_uri,openpc.uuid_v7,openpc.uuid_v7,openpc.cbor_payload,jsonb,openpc.sha256_bytes
);

CREATE FUNCTION candidate.emit_outbox_event(
  p_participant_id openpc.uuid_v7,
  p_privacy_domain_id openpc.uuid_v7,
  p_aggregate_type text,
  p_aggregate_id openpc.uuid_v7,
  p_source openpc.openpc_urn,
  p_subject openpc.openpc_urn,
  p_event_type openpc.event_type,
  p_schema_uri candidate.schema_reference,
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

ALTER TABLE candidate.projection_profile
  ADD COLUMN data_class text,
  ALTER COLUMN source_event_type DROP NOT NULL,
  ALTER COLUMN source_contract_address DROP NOT NULL,
  ADD CONSTRAINT projection_profile_data_class_required CHECK (
    data_class IS NOT NULL
    AND data_class IN ('EVENT_LOG','STATE_CALL','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
  ) NOT VALID,
  ADD CONSTRAINT projection_profile_identity_closed CHECK (
    (data_class = 'EVENT_LOG' AND source_event_type IS NOT NULL AND source_contract_address IS NOT NULL)
    OR (data_class IN ('STATE_CALL','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
      AND source_event_type IS NULL AND source_contract_address IS NULL)
  ) NOT VALID;

CREATE UNIQUE INDEX projection_profile_qualified_identity_uq
  ON candidate.projection_profile
  (participant_id,privacy_domain_id,projection_plan_id,fact_type,source_event_type,source_contract_address)
  NULLS NOT DISTINCT;

CREATE TABLE candidate.candidate_partition (
  candidate_partition_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  source_profile_id openpc.uuid_v7 NOT NULL,
  plan_digest openpc.sha256_bytes NOT NULL,
  source_id text NOT NULL CHECK (length(source_id) BETWEEN 1 AND 256),
  partition_id text NOT NULL CHECK (length(partition_id) BETWEEN 1 AND 256),
  range_start openpc.uint64 NOT NULL,
  range_end openpc.uint64,
  range_end_open boolean NOT NULL,
  binding_cbor openpc.cbor_payload NOT NULL,
  binding_digest openpc.sha256_bytes NOT NULL,
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (participant_id,privacy_domain_id,projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id,privacy_domain_id,projection_generation_id) ON DELETE RESTRICT,
  FOREIGN KEY (participant_id,privacy_domain_id,source_profile_id)
    REFERENCES candidate.source_profile(participant_id,privacy_domain_id,source_profile_id) ON DELETE RESTRICT,
  CHECK ((range_end_open AND range_end IS NULL)
    OR (NOT range_end_open AND range_end IS NOT NULL AND range_start <= range_end)),
  CHECK (sha256(binding_cbor) = binding_digest),
  CHECK (authority_eligible = false),
  UNIQUE (participant_id,privacy_domain_id,projection_generation_id,source_id,partition_id),
  UNIQUE (participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
);

ALTER TABLE candidate.candidate_block
  ADD COLUMN candidate_partition_id openpc.uuid_v7,
  ADD COLUMN finality_kind text,
  ADD COLUMN finality_evidence_digest openpc.sha256_bytes,
  ADD COLUMN finality_head_number openpc.uint64,
  ADD COLUMN finality_head_hash openpc.bytes32,
  ADD CONSTRAINT candidate_block_gate3_fields_required CHECK (
    candidate_partition_id IS NOT NULL AND finality_kind IS NOT NULL AND finality_evidence_digest IS NOT NULL
    AND finality_kind IN ('UNFINALIZED','SAFE_TAG','FINALIZED_TAG','CONFIRMATIONS')
  ) NOT VALID,
  ADD CONSTRAINT candidate_block_partition_fk FOREIGN KEY
    (participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    REFERENCES candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    ON DELETE RESTRICT NOT VALID,
  ADD CONSTRAINT candidate_block_finality_closed CHECK (
    (finality_kind = 'UNFINALIZED' AND finality_state = 'UNFINALIZED'
      AND finality_head_number IS NULL AND finality_head_hash IS NULL)
    OR (finality_kind = 'SAFE_TAG' AND finality_state IN ('SAFE','REMOVED')
      AND finality_head_number IS NULL AND finality_head_hash IS NULL)
    OR (finality_kind = 'FINALIZED_TAG' AND finality_state IN ('FINALIZED','REMOVED')
      AND finality_head_number IS NULL AND finality_head_hash IS NULL)
    OR (finality_kind = 'CONFIRMATIONS' AND finality_state IN ('FINALIZED','REMOVED')
      AND finality_head_number IS NOT NULL AND finality_head_hash IS NOT NULL)
  ) NOT VALID;

ALTER TABLE candidate.candidate_event
  ALTER COLUMN transaction_hash DROP NOT NULL,
  ALTER COLUMN transaction_index DROP NOT NULL,
  ALTER COLUMN log_index DROP NOT NULL,
  ALTER COLUMN contract_address DROP NOT NULL,
  ALTER COLUMN event_signature DROP NOT NULL,
  ADD COLUMN candidate_partition_id openpc.uuid_v7,
  ADD COLUMN record_kind text,
  ADD COLUMN record_sequence openpc.uint64,
  ADD COLUMN record_id text,
  ADD COLUMN schema_digest openpc.sha256_bytes,
  ADD COLUMN normalized_digest openpc.sha256_bytes,
  ADD COLUMN evidence_digest openpc.sha256_bytes,
  ADD COLUMN target_address openpc.evm_address,
  ADD COLUMN call_parameter_digest openpc.sha256_bytes,
  ADD CONSTRAINT candidate_event_gate3_fields_required CHECK (
    candidate_partition_id IS NOT NULL AND record_kind IS NOT NULL AND record_sequence IS NOT NULL
    AND record_id IS NOT NULL AND length(record_id) BETWEEN 1 AND 512
    AND schema_digest IS NOT NULL AND normalized_digest IS NOT NULL AND evidence_digest IS NOT NULL
    AND record_kind IN ('EVENT_LOG','STATE_CALL','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
  ) NOT VALID,
  ADD CONSTRAINT candidate_event_partition_fk FOREIGN KEY
    (participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    REFERENCES candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    ON DELETE RESTRICT NOT VALID,
  ADD CONSTRAINT candidate_event_record_identity_closed CHECK (
    (record_kind = 'EVENT_LOG'
      AND transaction_hash IS NOT NULL AND transaction_index IS NOT NULL AND log_index IS NOT NULL
      AND contract_address IS NOT NULL AND event_signature IS NOT NULL
      AND target_address IS NULL AND call_parameter_digest IS NULL)
    OR (record_kind = 'STATE_CALL'
      AND transaction_hash IS NULL AND transaction_index IS NULL AND log_index IS NULL
      AND contract_address IS NULL AND event_signature IS NULL
      AND target_address IS NOT NULL AND call_parameter_digest IS NOT NULL)
    OR (record_kind = 'TRANSACTION_RECEIPT'
      AND transaction_hash IS NOT NULL AND transaction_index IS NULL AND log_index IS NULL
      AND contract_address IS NULL AND event_signature IS NULL
      AND target_address IS NULL AND call_parameter_digest IS NULL)
    OR (record_kind IN ('BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
      AND transaction_hash IS NULL AND transaction_index IS NULL AND log_index IS NULL
      AND contract_address IS NULL AND event_signature IS NULL
      AND target_address IS NULL AND call_parameter_digest IS NULL)
  ) NOT VALID,
  ADD CONSTRAINT candidate_event_content_bound CHECK (
    sha256(payload_cbor) = payload_digest AND payload_digest = normalized_digest
  ) NOT VALID;

ALTER TABLE candidate.checkpoint
  ADD COLUMN candidate_partition_id openpc.uuid_v7,
  ADD COLUMN batch_id text,
  ADD COLUMN batch_sequence openpc.uint64,
  ADD COLUMN batch_digest openpc.sha256_bytes,
  ADD COLUMN predecessor_batch_digest openpc.sha256_bytes,
  ADD COLUMN range_start openpc.uint64,
  ADD COLUMN range_end openpc.uint64,
  ADD COLUMN authoritative_empty boolean,
  ADD CONSTRAINT checkpoint_gate3_fields_required CHECK (
    candidate_partition_id IS NOT NULL AND batch_id IS NOT NULL AND batch_sequence IS NOT NULL
    AND batch_digest IS NOT NULL AND range_start IS NOT NULL AND range_end IS NOT NULL
    AND authoritative_empty IS NOT NULL
  ) NOT VALID,
  ADD CONSTRAINT checkpoint_gate3_values_closed CHECK (
    length(batch_id) BETWEEN 1 AND 512 AND batch_sequence > 0 AND range_start <= range_end
    AND ((batch_sequence = 1 AND predecessor_batch_digest IS NULL)
      OR (batch_sequence > 1 AND predecessor_batch_digest IS NOT NULL))
  ) NOT VALID,
  ADD CONSTRAINT checkpoint_partition_fk FOREIGN KEY
    (participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    REFERENCES candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    ON DELETE RESTRICT NOT VALID;

CREATE UNIQUE INDEX checkpoint_partition_batch_id_uq
  ON candidate.checkpoint (candidate_partition_id,batch_id)
  WHERE candidate_partition_id IS NOT NULL;
CREATE UNIQUE INDEX checkpoint_partition_batch_sequence_uq
  ON candidate.checkpoint (candidate_partition_id,batch_sequence)
  WHERE candidate_partition_id IS NOT NULL;

CREATE TABLE candidate.candidate_invalidation (
  candidate_invalidation_id openpc.uuid_v7 PRIMARY KEY DEFAULT uuidv7(),
  participant_id openpc.uuid_v7 NOT NULL,
  privacy_domain_id openpc.uuid_v7 NOT NULL,
  projection_generation_id openpc.uuid_v7 NOT NULL,
  candidate_partition_id openpc.uuid_v7 NOT NULL,
  affected_start openpc.uint64 NOT NULL,
  affected_end openpc.uint64 NOT NULL,
  old_chain_id text NOT NULL CHECK (length(old_chain_id) BETWEEN 1 AND 96),
  old_genesis_hash openpc.bytes32 NOT NULL,
  old_network_id text NOT NULL CHECK (length(old_network_id) BETWEEN 1 AND 96),
  old_selector_kind text NOT NULL CHECK (old_selector_kind = 'PINNED'),
  old_block_number openpc.uint64 NOT NULL,
  old_block_hash openpc.bytes32 NOT NULL,
  old_pending_authorized boolean NOT NULL CHECK (old_pending_authorized = false),
  new_chain_id text NOT NULL CHECK (length(new_chain_id) BETWEEN 1 AND 96),
  new_genesis_hash openpc.bytes32 NOT NULL,
  new_network_id text NOT NULL CHECK (length(new_network_id) BETWEEN 1 AND 96),
  new_selector_kind text NOT NULL CHECK (new_selector_kind = 'PINNED'),
  new_block_number openpc.uint64 NOT NULL,
  new_block_hash openpc.bytes32 NOT NULL,
  new_pending_authorized boolean NOT NULL CHECK (new_pending_authorized = false),
  evidence_digest openpc.sha256_bytes NOT NULL,
  occurred_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  authority_eligible boolean GENERATED ALWAYS AS (false) STORED,
  FOREIGN KEY (participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    REFERENCES candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    ON DELETE RESTRICT,
  CHECK (affected_start <= affected_end),
  CHECK (old_block_number = affected_start),
  CHECK (old_chain_id = new_chain_id AND old_genesis_hash = new_genesis_hash
    AND old_network_id = new_network_id AND old_block_number = new_block_number
    AND old_block_hash <> new_block_hash),
  CHECK (authority_eligible = false),
  UNIQUE (candidate_partition_id,evidence_digest)
);

CREATE UNIQUE INDEX candidate_event_record_id_uq
  ON candidate.candidate_event (projection_generation_id, record_id);
CREATE UNIQUE INDEX candidate_event_state_call_uq
  ON candidate.candidate_event (projection_generation_id, candidate_block_id, target_address, call_parameter_digest)
  WHERE record_kind = 'STATE_CALL';
CREATE UNIQUE INDEX candidate_event_receipt_uq
  ON candidate.candidate_event (projection_generation_id, transaction_hash)
  WHERE record_kind = 'TRANSACTION_RECEIPT';
CREATE UNIQUE INDEX candidate_event_block_kind_uq
  ON candidate.candidate_event (projection_generation_id, candidate_block_id, record_kind)
  WHERE record_kind IN ('BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS');

CREATE OR REPLACE FUNCTION candidate.protect_candidate_block()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.candidate_block_id,OLD.participant_id,OLD.privacy_domain_id,OLD.projection_generation_id,
         OLD.candidate_partition_id,OLD.chain_namespace,OLD.block_hash,OLD.parent_hash,OLD.block_number,
         OLD.block_timestamp,OLD.observed_at,OLD.source_payload_digest,OLD.finality_kind,
         OLD.finality_evidence_digest,OLD.finality_head_number,OLD.finality_head_hash)
     IS DISTINCT FROM
     ROW(NEW.candidate_block_id,NEW.participant_id,NEW.privacy_domain_id,NEW.projection_generation_id,
         NEW.candidate_partition_id,NEW.chain_namespace,NEW.block_hash,NEW.parent_hash,NEW.block_number,
         NEW.block_timestamp,NEW.observed_at,NEW.source_payload_digest,NEW.finality_kind,
         NEW.finality_evidence_digest,NEW.finality_head_number,NEW.finality_head_hash) THEN
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

CREATE OR REPLACE FUNCTION candidate.protect_candidate_event()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.candidate_event_id,OLD.participant_id,OLD.privacy_domain_id,OLD.projection_generation_id,
         OLD.candidate_partition_id,OLD.candidate_block_id,OLD.record_kind,OLD.record_sequence,OLD.record_id,
         OLD.schema_digest,OLD.normalized_digest,OLD.evidence_digest,OLD.transaction_hash,OLD.transaction_index,
         OLD.log_index,OLD.contract_address,OLD.event_signature,OLD.target_address,OLD.call_parameter_digest,
         OLD.candidate_key_digest,OLD.payload_cbor,OLD.payload_digest,OLD.observed_at)
     IS DISTINCT FROM
     ROW(NEW.candidate_event_id,NEW.participant_id,NEW.privacy_domain_id,NEW.projection_generation_id,
         NEW.candidate_partition_id,NEW.candidate_block_id,NEW.record_kind,NEW.record_sequence,NEW.record_id,
         NEW.schema_digest,NEW.normalized_digest,NEW.evidence_digest,NEW.transaction_hash,NEW.transaction_index,
         NEW.log_index,NEW.contract_address,NEW.event_signature,NEW.target_address,NEW.call_parameter_digest,
         NEW.candidate_key_digest,NEW.payload_cbor,NEW.payload_digest,NEW.observed_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.candidate_event';
  END IF;
  IF OLD.state <> NEW.state AND NOT (
    OLD.state IN ('OBSERVED','VALIDATED_CANDIDATE') AND NEW.state IN ('REMOVED','SUPERSEDED','QUARANTINED')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6200-CANDIDATE-STATE-TRANSITION-INVALID';
  END IF;
  IF OLD.state = NEW.state AND OLD.removed_at IS DISTINCT FROM NEW.removed_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.candidate_event.removed_at';
  END IF;
  IF OLD.state <> NEW.state AND NEW.state = 'REMOVED' THEN
    NEW.removed_at := clock_timestamp();
  ELSIF OLD.state <> NEW.state AND NEW.removed_at IS DISTINCT FROM OLD.removed_at THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.candidate_event.removed_at';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION candidate.protect_checkpoint_gate3()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF ROW(OLD.checkpoint_id,OLD.participant_id,OLD.privacy_domain_id,OLD.projection_generation_id,
         OLD.candidate_partition_id,OLD.checkpoint_kind,OLD.position_cbor,OLD.position_digest,
         OLD.batch_id,OLD.batch_sequence,OLD.batch_digest,OLD.predecessor_batch_digest,
         OLD.range_start,OLD.range_end,OLD.authoritative_empty,OLD.observed_at)
     IS DISTINCT FROM
     ROW(NEW.checkpoint_id,NEW.participant_id,NEW.privacy_domain_id,NEW.projection_generation_id,
         NEW.candidate_partition_id,NEW.checkpoint_kind,NEW.position_cbor,NEW.position_digest,
         NEW.batch_id,NEW.batch_sequence,NEW.batch_digest,NEW.predecessor_batch_digest,
         NEW.range_start,NEW.range_end,NEW.authoritative_empty,NEW.observed_at)
     OR OLD.state <> 'COMPLETE' OR NEW.state <> 'REORG'
     OR OLD.completed_at IS NULL OR NEW.completed_at IS NOT NULL
     OR NEW.row_version <> OLD.row_version + 1 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6206-CHECKPOINT-TRANSITION-INVALID';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;

CREATE FUNCTION candidate.protect_source_profile_gate3()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.source_profile';
  END IF;
  IF ROW(OLD.source_profile_id,OLD.participant_id,OLD.privacy_domain_id,OLD.indexer_profile_id,
            OLD.chain_namespace,OLD.source_contract_urn,OLD.source_profile_cbor,
            OLD.source_profile_digest,OLD.reorg_profile_digest,OLD.finality_mode,
            OLD.confirmation_count,OLD.created_at)
        IS DISTINCT FROM
        ROW(NEW.source_profile_id,NEW.participant_id,NEW.privacy_domain_id,NEW.indexer_profile_id,
            NEW.chain_namespace,NEW.source_contract_urn,NEW.source_profile_cbor,
            NEW.source_profile_digest,NEW.reorg_profile_digest,NEW.finality_mode,
            NEW.confirmation_count,NEW.created_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.source_profile';
  END IF;
  NEW.row_version := OLD.row_version + 1;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;

CREATE FUNCTION candidate.protect_projection_profile_gate3()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.projection_profile';
  END IF;
  IF ROW(OLD.projection_profile_id,OLD.participant_id,OLD.privacy_domain_id,OLD.source_profile_id,
            OLD.projection_plan_id,OLD.fact_type,OLD.data_class,OLD.source_event_type,
            OLD.source_contract_address,OLD.schema_digest,OLD.mapping_cbor,OLD.mapping_digest,OLD.created_at)
        IS DISTINCT FROM
        ROW(NEW.projection_profile_id,NEW.participant_id,NEW.privacy_domain_id,NEW.source_profile_id,
            NEW.projection_plan_id,NEW.fact_type,NEW.data_class,NEW.source_event_type,
            NEW.source_contract_address,NEW.schema_digest,NEW.mapping_cbor,NEW.mapping_digest,NEW.created_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.projection_profile';
  END IF;
  NEW.row_version := OLD.row_version + 1;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END
$$;

CREATE FUNCTION candidate.protect_projection_generation_gate3()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.projection_generation';
  END IF;
  IF current_user = 'openpc_indexer_writer'
     OR ROW(OLD.projection_generation_id,OLD.participant_id,OLD.privacy_domain_id,
            OLD.projection_profile_id,OLD.generation_digest,OLD.source_profile_digest,
            OLD.projection_schema_digest,OLD.predecessor_generation_digest,OLD.created_at)
        IS DISTINCT FROM
        ROW(NEW.projection_generation_id,NEW.participant_id,NEW.privacy_domain_id,
            NEW.projection_profile_id,NEW.generation_digest,NEW.source_profile_digest,
            NEW.projection_schema_digest,NEW.predecessor_generation_digest,NEW.created_at) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'candidate.projection_generation';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER source_profile_touch ON candidate.source_profile;
CREATE TRIGGER source_profile_immutable BEFORE UPDATE OR DELETE ON candidate.source_profile
  FOR EACH ROW EXECUTE FUNCTION candidate.protect_source_profile_gate3();
DROP TRIGGER projection_profile_touch ON candidate.projection_profile;
CREATE TRIGGER projection_profile_immutable BEFORE UPDATE OR DELETE ON candidate.projection_profile
  FOR EACH ROW EXECUTE FUNCTION candidate.protect_projection_profile_gate3();
CREATE TRIGGER projection_generation_immutable BEFORE UPDATE OR DELETE ON candidate.projection_generation
  FOR EACH ROW EXECUTE FUNCTION candidate.protect_projection_generation_gate3();
DROP TRIGGER checkpoint_touch ON candidate.checkpoint;
CREATE TRIGGER checkpoint_touch BEFORE UPDATE ON candidate.checkpoint
  FOR EACH ROW EXECUTE FUNCTION candidate.protect_checkpoint_gate3();
CREATE TRIGGER candidate_partition_immutable BEFORE UPDATE OR DELETE ON candidate.candidate_partition
  FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE TRIGGER candidate_invalidation_immutable BEFORE UPDATE OR DELETE ON candidate.candidate_invalidation
  FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();

ALTER TABLE candidate.candidate_partition ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.candidate_partition FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_isolation ON candidate.candidate_partition
  USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
  WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
ALTER TABLE candidate.candidate_invalidation ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidate.candidate_invalidation FORCE ROW LEVEL SECURITY;
CREATE POLICY privacy_isolation ON candidate.candidate_invalidation
  USING (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
  WITH CHECK (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));

CREATE INDEX candidate_partition_lookup_idx
  ON candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,source_id,partition_id);
CREATE INDEX candidate_invalidation_partition_idx
  ON candidate.candidate_invalidation(participant_id,privacy_domain_id,candidate_partition_id,occurred_at);

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA candidate FROM PUBLIC;
REVOKE ALL ON candidate.candidate_partition,candidate.candidate_invalidation FROM PUBLIC;
GRANT SELECT ON candidate.candidate_partition TO openpc_indexer_writer,openpc_candidate_index_reader,openpc_fact_bridge_reader;
GRANT SELECT,INSERT ON candidate.candidate_invalidation TO openpc_indexer_writer;
GRANT SELECT ON candidate.candidate_invalidation TO openpc_candidate_index_reader,openpc_fact_bridge_reader;
GRANT EXECUTE ON FUNCTION candidate.emit_outbox_event(
  openpc.uuid_v7,openpc.uuid_v7,text,openpc.uuid_v7,openpc.openpc_urn,openpc.openpc_urn,
  openpc.event_type,candidate.schema_reference,openpc.uuid_v7,openpc.uuid_v7,openpc.cbor_payload,jsonb,openpc.sha256_bytes
) TO openpc_indexer_writer;
REVOKE INSERT,UPDATE,DELETE ON candidate.source_profile,candidate.projection_profile FROM openpc_indexer_writer;
REVOKE INSERT,DELETE ON candidate.projection_generation FROM openpc_indexer_writer;
GRANT SELECT ON candidate.source_profile,candidate.projection_profile TO openpc_indexer_writer;
GRANT SELECT,UPDATE ON candidate.projection_generation TO openpc_indexer_writer;
GRANT SELECT,INSERT,UPDATE ON candidate.candidate_block,candidate.candidate_event,candidate.checkpoint TO openpc_indexer_writer;

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
SELECT 'OPENPC-MIG-CANDIDATE-0003',
       decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
       :'openpc_migration_profile'::candidate.migration_profile,
       'M3_SHADOW_DIFFERENTIAL_PROOF'
FROM candidate.schema_migration
WHERE migration_id = 'OPENPC-MIG-CANDIDATE-0002';

COMMIT;
RESET ROLE;
