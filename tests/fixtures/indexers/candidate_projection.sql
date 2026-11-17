\set ON_ERROR_STOP on

SET ROLE openpc_candidate_index_owner;
BEGIN;
SELECT openpc.set_request_context(
  'PARTICIPANT',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-dddddddddddd',
  'ACT-CANDIDATE_WRITE-V1', false
);
SELECT openpc.assert_request_context(true);

INSERT INTO candidate.source_profile(
  source_profile_id, participant_id, privacy_domain_id, indexer_profile_id,
  chain_namespace, source_contract_urn, source_profile_cbor, source_profile_digest,
  reorg_profile_digest, finality_mode, confirmation_count, state
) VALUES (
  '018f47a5-4a58-7b21-8f3a-333333333333',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-888888888888',
  'eip155:1',
  'urn:openpc:source-profile:018f47a5-4a58-7b21-8f3a-333333333333',
  decode('a0', 'hex'), sha256(decode('a0', 'hex')), decode(repeat('11', 32), 'hex'),
  'CONFIRMATIONS', 12, 'QUALIFIED'
);

INSERT INTO candidate.projection_profile(
  projection_profile_id, participant_id, privacy_domain_id, source_profile_id,
  projection_plan_id, fact_type, source_event_type, source_contract_address,
  schema_digest, mapping_cbor, mapping_digest, state
) VALUES (
  '018f47a5-4a58-7b21-8f3a-444444444444',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-333333333333',
  '018f47a5-4a58-7b21-8f3a-999999999999',
  'test.fact', 'TestEvent', decode(repeat('22', 20), 'hex'),
  decode(repeat('33', 32), 'hex'), decode('a0', 'hex'), sha256(decode('a0', 'hex')),
  'QUALIFIED'
);

INSERT INTO candidate.projection_generation(
  projection_generation_id, participant_id, privacy_domain_id, projection_profile_id,
  generation_digest, source_profile_digest, projection_schema_digest, state
) VALUES (
  '018f47a5-4a58-7b21-8f3a-555555555555',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-444444444444',
  decode(repeat('44', 32), 'hex'), decode(repeat('55', 32), 'hex'),
  decode(repeat('66', 32), 'hex'), 'READY'
);

INSERT INTO candidate.candidate_block(
  candidate_block_id, participant_id, privacy_domain_id, projection_generation_id,
  chain_namespace, block_hash, parent_hash, block_number, block_timestamp,
  finality_state, observed_at, source_payload_digest
) VALUES (
  '018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-555555555555',
  'eip155:1', decode(repeat('77', 32), 'hex'), decode(repeat('76', 32), 'hex'),
  10, timestamptz '2026-09-02 00:00:00+00', 'FINALIZED',
  timestamptz '2026-09-02 00:00:01+00', decode(repeat('78', 32), 'hex')
);

INSERT INTO candidate.candidate_event(
  candidate_event_id, participant_id, privacy_domain_id, projection_generation_id,
  candidate_block_id, transaction_hash, transaction_index, log_index,
  contract_address, event_signature, candidate_key_digest, payload_cbor,
  payload_digest, state, observed_at
) VALUES (
  '018f47a5-4a58-7b21-8f3a-bbbbbbbbbbbb',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-555555555555',
  '018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa',
  decode(repeat('79', 32), 'hex'), 0, 0, decode(repeat('22', 20), 'hex'),
  decode(repeat('7a', 32), 'hex'), decode(repeat('7b', 32), 'hex'),
  decode('a0', 'hex'), sha256(decode('a0', 'hex')), 'OBSERVED',
  timestamptz '2026-09-02 00:00:02+00'
);

INSERT INTO candidate.checkpoint(
  checkpoint_id, participant_id, privacy_domain_id, projection_generation_id,
  checkpoint_kind, position_cbor, position_digest, state, observed_at, completed_at
) VALUES (
  '018f47a5-4a58-7b21-8f3a-cccccccccccc',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-555555555555',
  'BLOCK', decode('a0', 'hex'), sha256(decode('a0', 'hex')), 'COMPLETE',
  timestamptz '2026-09-02 00:00:03+00', timestamptz '2026-09-02 00:00:04+00'
);

COMMIT;
RESET ROLE;
