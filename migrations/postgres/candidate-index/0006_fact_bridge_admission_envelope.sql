-- One read-only admission envelope. None of these untrusted observations is a
-- FactBridge trust decision; retain non-current states so consumers can fence.
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

-- The non-login, non-bypass owner has FORCE RLS on every underlying table.
-- Owner-rights view access avoids granting the reader the source-profile table;
-- request-context RLS still applies, and the security barrier precedes caller
-- predicates. No SECURITY DEFINER function or mutating privilege is introduced.
CREATE VIEW candidate.fact_bridge_admission_v1
WITH (security_barrier = true)
AS
SELECT
  o.event_id, o.participant_id, o.privacy_domain_id,
  o.aggregate_sequence AS outbox_sequence, o.event_type, o.schema_uri,
  o.source AS event_source, o.subject AS event_subject,
  o.payload_cbor AS event_payload_cbor, o.payload_digest AS event_payload_digest,
  o.occurred_at AS event_occurred_at, o.correlation_id, o.causation_id,
  cp.candidate_partition_id, cp.source_id, cp.partition_id,
  cp.range_start AS partition_range_start, cp.range_end AS partition_range_end,
  cp.range_end_open AS partition_range_end_open,
  cp.binding_cbor AS partition_binding_cbor, cp.binding_digest AS partition_binding_digest,
  g.projection_generation_id, g.generation_digest, g.state AS generation_state,
  g.predecessor_generation_digest, g.projection_schema_digest,
  sp.source_profile_id, sp.indexer_profile_id, sp.source_contract_urn,
  sp.source_profile_cbor, sp.source_profile_digest, sp.reorg_profile_digest,
  sp.state AS source_state, sp.chain_namespace, sp.finality_mode, sp.confirmation_count,
  pp.projection_plan_id, pp.mapping_cbor, pp.mapping_digest,
  pp.state AS projection_state, pp.fact_type, pp.data_class,
  pp.source_event_type, pp.source_contract_address,
  pub.state AS publication_state, pub.publication_cbor, pub.publication_digest,
  pub.source_revision, pub.qualification_operation_id, pub.projection_revision,
  pub.validation_operation_id, pub.configuration_digest,
  pub.acquisition_configuration_cbor, pub.acquisition_configuration_digest,
  pub.finality_rule_cbor, pub.finality_rule_digest,
  e.candidate_event_id, e.state AS candidate_state, e.record_kind, e.record_id,
  e.record_sequence, e.schema_digest AS candidate_schema_digest,
  e.normalized_digest, e.candidate_key_digest, e.payload_cbor AS candidate_payload_cbor,
  e.payload_digest AS candidate_payload_digest, e.evidence_digest AS candidate_evidence_digest,
  e.observed_at AS candidate_observed_at, e.removed_at AS candidate_removed_at,
  e.transaction_hash, e.transaction_index, e.log_index, e.contract_address,
  e.event_signature, e.target_address, e.call_parameter_digest,
  b.block_number, b.block_hash, b.parent_hash, b.block_timestamp,
  b.source_payload_digest AS block_evidence_digest,
  b.finality_state AS block_finality_state, b.finality_kind,
  b.finality_evidence_digest, b.finality_head_number, b.finality_head_hash,
  c.checkpoint_id, c.state AS checkpoint_state, c.batch_id, c.batch_sequence,
  c.batch_digest, c.predecessor_batch_digest,
  c.range_start AS batch_range_start, c.range_end AS batch_range_end,
  c.authoritative_empty, c.position_cbor AS checkpoint_cbor,
  c.position_digest AS checkpoint_digest, c.completed_at AS checkpoint_completed_at,
  i.candidate_invalidation_id AS invalidation_id, i.affected_start, i.affected_end,
  i.old_chain_id, i.old_genesis_hash, i.old_network_id,
  i.old_block_number, i.old_block_hash, i.new_block_number, i.new_block_hash,
  i.evidence_digest AS invalidation_evidence_digest,
  i.occurred_at AS invalidation_occurred_at,
  false AS authority_eligible
FROM candidate.outbox_event o
JOIN candidate.candidate_partition cp
  ON cp.participant_id=o.participant_id AND cp.privacy_domain_id=o.privacy_domain_id
  AND cp.candidate_partition_id=o.aggregate_id AND o.aggregate_type='candidate-partition'
JOIN candidate.projection_generation g
  ON g.participant_id=cp.participant_id AND g.privacy_domain_id=cp.privacy_domain_id
  AND g.projection_generation_id=cp.projection_generation_id
JOIN candidate.projection_profile pp
  ON pp.participant_id=g.participant_id AND pp.privacy_domain_id=g.privacy_domain_id
  AND pp.projection_profile_id=g.projection_profile_id
JOIN candidate.source_profile sp
  ON sp.participant_id=pp.participant_id AND sp.privacy_domain_id=pp.privacy_domain_id
  AND sp.source_profile_id=pp.source_profile_id AND sp.source_profile_id=cp.source_profile_id
LEFT JOIN candidate.source_publication pub
  ON pub.participant_id=g.participant_id AND pub.privacy_domain_id=g.privacy_domain_id
  AND pub.projection_generation_id=g.projection_generation_id
LEFT JOIN candidate.candidate_event e
  ON e.participant_id=cp.participant_id AND e.privacy_domain_id=cp.privacy_domain_id
  AND e.projection_generation_id=g.projection_generation_id
  AND e.candidate_partition_id=cp.candidate_partition_id
  AND 'urn:openpc:candidate:'||e.candidate_event_id::text=o.payload_json->>'candidateId'
LEFT JOIN candidate.candidate_block b
  ON b.participant_id=e.participant_id AND b.privacy_domain_id=e.privacy_domain_id
  AND b.candidate_block_id=e.candidate_block_id
  AND b.projection_generation_id=g.projection_generation_id
  AND b.candidate_partition_id=cp.candidate_partition_id
LEFT JOIN candidate.checkpoint c
  ON c.participant_id=cp.participant_id AND c.privacy_domain_id=cp.privacy_domain_id
  AND c.projection_generation_id=g.projection_generation_id
  AND c.candidate_partition_id=cp.candidate_partition_id
  AND 'sha256:'||encode(c.position_digest,'hex')=
    coalesce(o.payload_json->>'sourceCursorDigest',o.payload_json->>'checkpointDigest')
LEFT JOIN candidate.candidate_invalidation i
  ON i.participant_id=cp.participant_id AND i.privacy_domain_id=cp.privacy_domain_id
  AND i.projection_generation_id=g.projection_generation_id
  AND i.candidate_partition_id=cp.candidate_partition_id
  AND i.candidate_invalidation_id::text=o.payload_json->>'invalidationId';

REVOKE ALL ON candidate.fact_bridge_admission_v1 FROM PUBLIC;
GRANT SELECT ON candidate.fact_bridge_admission_v1 TO openpc_fact_bridge_reader;

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES ('OPENPC-MIG-CANDIDATE-0006',
        decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
        :'openpc_migration_profile'::candidate.migration_profile,
        'M1_ADDITIVE_INACTIVE');

COMMIT;
RESET ROLE;
