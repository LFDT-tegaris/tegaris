-- A source fence is a durable removal occurrence, not a reorg observation and
-- never Fact authority. FactBridge independently verifies the Control loss.
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

CREATE FUNCTION candidate.emit_source_fence(
  p_participant uuid,p_privacy uuid,p_partition uuid,p_generation uuid,
  p_operation uuid,p_payload_cbor bytea,p_payload_json jsonb
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE publication bytea; prior uuid; expected jsonb;
BEGIN
  IF NOT pg_has_role(session_user,'openpc_indexer_manager','MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='SOURCE_FENCE_MANAGER_REQUIRED';
  END IF;
  PERFORM openpc.assert_request_context(true);
  SELECT pub.publication_digest INTO publication FROM candidate.source_publication pub
    JOIN candidate.candidate_partition part USING(participant_id,privacy_domain_id,projection_generation_id)
    JOIN candidate.projection_generation generation USING(participant_id,privacy_domain_id,projection_generation_id)
    WHERE pub.participant_id=p_participant AND pub.privacy_domain_id=p_privacy
      AND pub.projection_generation_id=p_generation AND part.candidate_partition_id=p_partition
      AND pub.state IN ('FENCED','RETIRED') FOR UPDATE OF generation;
  IF publication IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SOURCE_FENCE_NOT_COMMITTED';
  END IF;
  expected:=jsonb_build_object('candidatePartitionId','urn:openpc:candidate-partition:'||p_partition,
    'projectionGenerationId','urn:openpc:projection-generation:'||p_generation,
    'publicationDigest','sha256:'||encode(publication,'hex'),
    'reasonCode','GOVERNED_SOURCE_NOT_CURRENT','authority','CANDIDATE_ONLY');
  IF p_payload_json IS DISTINCT FROM expected OR p_payload_cbor IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SOURCE_FENCE_BINDING_REJECTED';
  END IF;
  SELECT event_id INTO prior FROM candidate.outbox_event WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND aggregate_type='candidate-partition' AND aggregate_id=p_partition
    AND event_type='io.openpc.indexer.projection.source.fenced.v1';
  IF prior IS NOT NULL THEN RETURN prior; END IF;
  RETURN candidate.emit_outbox_event(p_participant,p_privacy,'candidate-partition',p_partition,
    ('urn:openpc:projection-generation:'||p_generation)::openpc.openpc_urn,
    ('urn:openpc:candidate-partition:'||p_partition)::openpc.openpc_urn,
    'io.openpc.indexer.projection.source.fenced.v1',
    'https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionSourceFenced',
    p_operation,p_operation,p_payload_cbor,p_payload_json,sha256(p_payload_cbor));
END $$;
REVOKE ALL ON FUNCTION candidate.emit_source_fence(uuid,uuid,uuid,uuid,uuid,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.emit_source_fence(uuid,uuid,uuid,uuid,uuid,bytea,jsonb) TO openpc_indexer_manager;
GRANT SELECT ON candidate.outbox_event TO openpc_indexer_manager;

-- Same scoped read-only boundary, including observed blocks with no candidate
-- rows. The checkpoint is data, never independently verified completeness.
CREATE VIEW candidate.fact_bridge_checkpoint_blocks_v1 WITH (security_barrier=true) AS
SELECT c.participant_id,c.privacy_domain_id,c.candidate_partition_id,c.checkpoint_id,
  b.block_number,b.block_hash,b.parent_hash,b.finality_state,b.finality_head_number,b.finality_head_hash
FROM candidate.checkpoint c JOIN candidate.candidate_block b
  ON b.participant_id=c.participant_id AND b.privacy_domain_id=c.privacy_domain_id
  AND b.projection_generation_id=c.projection_generation_id
  AND b.candidate_partition_id=c.candidate_partition_id
  AND b.block_number BETWEEN c.range_start AND c.range_end
WHERE c.state='COMPLETE' AND b.finality_state<>'REMOVED';
REVOKE ALL ON candidate.fact_bridge_checkpoint_blocks_v1 FROM PUBLIC;
GRANT SELECT ON candidate.fact_bridge_checkpoint_blocks_v1 TO openpc_fact_bridge_reader;

-- Registered schema names retain their frozen spelling at the shared candidate owner.
ALTER TABLE candidate.projection_profile DROP CONSTRAINT projection_profile_fact_type_check,
  ADD CONSTRAINT projection_profile_fact_type_check CHECK (
    fact_type ~ '^[a-z][a-z0-9.]{1,127}$'
    OR (fact_type='FactAdmissionCandidateV1' AND data_class='EXTERNAL_OBSERVATION'
      AND schema_digest=decode('50acd13677c30e1f0386804dc38d2daa8ef98bac3dfa3c005c4f75f056ec845c','hex'))
    OR (fact_type='RelationshipCandidateV1' AND data_class='EVENT_LOG'
      AND schema_digest=decode('1565b4180bdb05e6b3c8766965b51d1f4f5c473bb35d622e992ae11650be5ba0','hex'))
  );

-- External observations share the candidate owner and require explicit source class permission.
ALTER TABLE candidate.projection_profile DROP CONSTRAINT projection_profile_data_class_required,
  ADD CONSTRAINT projection_profile_data_class_required CHECK (
    data_class IS NOT NULL
    AND data_class IN ('EVENT_LOG','EXTERNAL_OBSERVATION','STATE_CALL','EXTERNAL_OBSERVATION','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
  ) NOT VALID;
ALTER TABLE candidate.projection_profile DROP CONSTRAINT projection_profile_identity_closed,
  ADD CONSTRAINT projection_profile_identity_closed CHECK (
    (data_class = 'EVENT_LOG' AND source_event_type IS NOT NULL AND source_contract_address IS NOT NULL)
    OR (data_class IN ('STATE_CALL','EXTERNAL_OBSERVATION','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
      AND source_event_type IS NULL AND source_contract_address IS NULL)
  ) NOT VALID;
ALTER TABLE candidate.candidate_event DROP CONSTRAINT candidate_event_gate3_fields_required,
  ADD CONSTRAINT candidate_event_gate3_fields_required CHECK (
    candidate_partition_id IS NOT NULL AND record_kind IS NOT NULL AND record_sequence IS NOT NULL
    AND record_id IS NOT NULL AND length(record_id) BETWEEN 1 AND 512
    AND schema_digest IS NOT NULL AND normalized_digest IS NOT NULL AND evidence_digest IS NOT NULL
    AND record_kind IN ('EVENT_LOG','EXTERNAL_OBSERVATION','STATE_CALL','EXTERNAL_OBSERVATION','TRANSACTION_RECEIPT','BLOCK_HEADER','FULL_BLOCK_TRANSACTIONS')
  ) NOT VALID;
ALTER TABLE candidate.candidate_event DROP CONSTRAINT candidate_event_record_identity_closed,
  ADD CONSTRAINT candidate_event_record_identity_closed CHECK (
    (record_kind = 'EVENT_LOG'
      AND transaction_hash IS NOT NULL AND transaction_index IS NOT NULL AND log_index IS NOT NULL
      AND contract_address IS NOT NULL AND event_signature IS NOT NULL
      AND target_address IS NULL AND call_parameter_digest IS NULL)
    OR (record_kind IN ('STATE_CALL','EXTERNAL_OBSERVATION')
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
  ) NOT VALID;
CREATE UNIQUE INDEX candidate_external_observation_identity ON candidate.candidate_event
  (projection_generation_id,candidate_block_id,target_address,call_parameter_digest) WHERE record_kind='EXTERNAL_OBSERVATION';

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES('OPENPC-MIG-CANDIDATE-0007',decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
  :'openpc_migration_profile'::candidate.migration_profile,'M1_ADDITIVE_INACTIVE');
COMMIT;
RESET ROLE;
