\set ON_ERROR_STOP on
\pset format unaligned
\pset tuples_only on
SET client_min_messages = warning;

DO $identity$
BEGIN
  IF current_database() <> 'openpc_candidate_index' OR current_user <> 'openpc_indexer_writer' THEN
    RAISE EXCEPTION 'I06_GATE3_RUNTIME_DATABASE_OR_ROLE_IDENTITY';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('control','facts')) THEN
    RAISE EXCEPTION 'I06_GATE3_CANDIDATE_DATABASE_CONTAINS_FORBIDDEN_SCHEMA';
  END IF;
  IF to_regprocedure('candidate.register_partition(openpc.uuid_v7,openpc.uuid_v7,openpc.uuid_v7,openpc.uuid_v7,openpc.sha256_bytes,text,text,openpc.uint64,openpc.uint64,boolean,openpc.cbor_payload,openpc.sha256_bytes)') IS NOT NULL
     OR to_regprocedure('candidate.lock_partition(openpc.uuid_v7,openpc.uuid_v7,openpc.uuid_v7,text,text)') IS NOT NULL
     OR EXISTS (
       SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
     ) THEN
    RAISE EXCEPTION 'I06_GATE3_INVOKER_ONLY_PARTITION_AUTHORITY_VIOLATION';
  END IF;
  IF has_table_privilege(current_user,'candidate.source_profile','INSERT')
     OR has_table_privilege(current_user,'candidate.source_profile','UPDATE')
     OR has_table_privilege(current_user,'candidate.source_profile','DELETE')
     OR has_table_privilege(current_user,'candidate.projection_profile','INSERT')
     OR has_table_privilege(current_user,'candidate.projection_profile','UPDATE')
     OR has_table_privilege(current_user,'candidate.projection_profile','DELETE')
     OR has_table_privilege(current_user,'candidate.projection_generation','INSERT')
     OR NOT has_table_privilege(current_user,'candidate.projection_generation','UPDATE')
     OR has_table_privilege(current_user,'candidate.projection_generation','DELETE') THEN
    RAISE EXCEPTION 'I06_GATE3_QUALIFICATION_REFERENT_PRIVILEGE_VIOLATION';
  END IF;
END
$identity$;

CREATE TEMP TABLE i06_gate3_assertion (
  assertion_id text PRIMARY KEY,
  passed boolean NOT NULL CHECK (passed)
) ON COMMIT PRESERVE ROWS;

CREATE FUNCTION pg_temp.i06_assert(p_assertion_id text, p_passed boolean)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_assertion_id !~ '^I06-G3-M(12|13|14|15)-I[0-9]{2}-(P|N-)[A-Z0-9-]*$'
     OR p_assertion_id LIKE '%...%' OR NOT COALESCE(p_passed,false) THEN
    RAISE EXCEPTION 'I06_GATE3_ASSERTION_FAILED|%', p_assertion_id;
  END IF;
  INSERT INTO pg_temp.i06_gate3_assertion(assertion_id,passed)
  VALUES (p_assertion_id,true);
END
$$;

CREATE FUNCTION pg_temp.i06_reject(
  p_assertion_id text,
  p_statement text,
  p_expected_sqlstate text,
  p_expected_message text,
  p_expected_detail text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  rejected boolean := false;
  actual_sqlstate text;
  actual_message text;
  actual_detail text;
BEGIN
  BEGIN
    EXECUTE p_statement;
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
    GET STACKED DIAGNOSTICS
      actual_sqlstate = RETURNED_SQLSTATE,
      actual_message = MESSAGE_TEXT,
      actual_detail = PG_EXCEPTION_DETAIL;
    IF actual_sqlstate IS DISTINCT FROM p_expected_sqlstate
       OR actual_message IS DISTINCT FROM p_expected_message
       OR NULLIF(actual_detail,'') IS DISTINCT FROM NULLIF(p_expected_detail,'') THEN
      RAISE EXCEPTION USING
        MESSAGE = 'I06_GATE3_DATABASE_RESULT_MISMATCH|' || p_assertion_id,
        DETAIL = format(
          'expected=%s/%s/%s actual=%s/%s/%s',
          p_expected_sqlstate,p_expected_message,p_expected_detail,
          actual_sqlstate,actual_message,actual_detail
        );
    END IF;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I06_GATE3_DATABASE_RESULT_MISMATCH|%|expected rejection|actual=success',
      p_assertion_id;
  END IF;
  PERFORM pg_temp.i06_assert(p_assertion_id,rejected);
END
$$;

CREATE FUNCTION pg_temp.i06_require_exact_rejection(
  p_owner text,
  p_statement text,
  p_expected_sqlstate text,
  p_expected_message text,
  p_expected_detail text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  rejected boolean := false;
  actual_sqlstate text;
  actual_message text;
  actual_detail text;
BEGIN
  BEGIN
    EXECUTE p_statement;
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
    GET STACKED DIAGNOSTICS
      actual_sqlstate = RETURNED_SQLSTATE,
      actual_message = MESSAGE_TEXT,
      actual_detail = PG_EXCEPTION_DETAIL;
    IF actual_sqlstate IS DISTINCT FROM p_expected_sqlstate
       OR actual_message IS DISTINCT FROM p_expected_message
       OR NULLIF(actual_detail,'') IS DISTINCT FROM NULLIF(p_expected_detail,'') THEN
      RAISE EXCEPTION USING
        MESSAGE = 'I06_GATE3_PREREQUISITE_RESULT_MISMATCH|' || p_owner,
        DETAIL = format(
          'expected=%s/%s/%s actual=%s/%s/%s',
          p_expected_sqlstate,p_expected_message,p_expected_detail,
          actual_sqlstate,actual_message,actual_detail
        );
    END IF;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I06_GATE3_PREREQUISITE_RESULT_MISMATCH|%|expected rejection|actual=success',
      p_owner;
  END IF;
END
$$;


BEGIN;
SELECT openpc.set_request_context(
  'PARTICIPANT',
  '018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa',
  'ACT-CANDIDATE_WRITE-V1', false
);
SELECT openpc.assert_request_context(true);

DO $positive$
DECLARE
  partition_uuid uuid;
  candidate_one_uuid uuid;
  candidate_two_uuid uuid;
  invalidation_uuid uuid;
  invalidation_evidence_digest bytea;
  partition_match_count bigint;
BEGIN
  SELECT count(*) INTO partition_match_count
    FROM candidate.candidate_partition
   WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
     AND source_id='source' AND partition_id='partition';
  IF partition_match_count <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_PRIMARY_PARTITION_IDENTITY_COUNT|%', partition_match_count;
  END IF;
  SELECT candidate_partition_id INTO STRICT partition_uuid
    FROM candidate.candidate_partition
   WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
     AND source_id='source' AND partition_id='partition';
  SELECT candidate_event_id INTO STRICT candidate_one_uuid
    FROM candidate.candidate_event
   WHERE candidate_partition_id=partition_uuid
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND record_id='record-1-1';
  SELECT candidate_event_id INTO STRICT candidate_two_uuid
    FROM candidate.candidate_event
   WHERE candidate_partition_id=partition_uuid
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND record_id='record-1-2';
  SELECT ci.candidate_invalidation_id,ci.evidence_digest
    INTO STRICT invalidation_uuid,invalidation_evidence_digest
    FROM candidate.candidate_invalidation ci
    JOIN candidate.candidate_partition cp
      ON cp.candidate_partition_id=ci.candidate_partition_id
    JOIN candidate.outbox_event oe
      ON oe.aggregate_type='candidate-partition'
     AND oe.aggregate_id=ci.candidate_partition_id
     AND oe.aggregate_sequence=5
     AND oe.event_type='io.openpc.indexer.projection.candidate.invalidated.v1'
     AND oe.payload_json->>'invalidationId'=ci.candidate_invalidation_id::text
   WHERE cp.participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND cp.privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND cp.projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND cp.source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
     AND cp.source_id='source' AND cp.partition_id='partition'
     AND ci.projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND ci.affected_start=8 AND ci.affected_end=20
     AND ci.old_chain_id='1' AND ci.new_chain_id='1'
     AND ci.old_genesis_hash=decode(repeat('01',32),'hex')
     AND ci.new_genesis_hash=decode(repeat('01',32),'hex')
     AND ci.old_network_id='openpc-local' AND ci.new_network_id='openpc-local'
     AND ci.old_selector_kind='PINNED' AND ci.new_selector_kind='PINNED'
     AND ci.old_block_number=8 AND ci.new_block_number=8
     AND ci.old_block_hash=decode(repeat('08',32),'hex')
     AND ci.new_block_hash=decode(repeat('fe',32),'hex')
     AND NOT ci.old_pending_authorized AND NOT ci.new_pending_authorized;
  IF partition_uuid::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR invalidation_uuid::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'I06_GATE3_DATABASE_UUIDV7_IDENTITY';
  END IF;
  IF (SELECT count(*) FROM candidate.candidate_partition
       WHERE candidate_partition_id=partition_uuid
         AND participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
         AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
         AND source_id='source' AND partition_id='partition'
         AND range_start=1 AND range_end=30 AND NOT range_end_open
         AND sha256(binding_cbor)=binding_digest AND authority_eligible=false) <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_PARTITION_BINDING';
  END IF;
  IF (SELECT count(*) FROM candidate.candidate_block
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555') <> 3
     OR (SELECT count(*) FROM candidate.candidate_event
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555') <> 2
     OR (SELECT count(*) FROM candidate.checkpoint
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555') <> 2 THEN
    RAISE EXCEPTION 'I06_GATE3_PARTITION_FOREIGN_KEY_COUNTS';
  END IF;
  IF (SELECT count(*) FROM candidate.candidate_block
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND block_number BETWEEN 8 AND 20 AND finality_state='REMOVED'
         AND authority_eligible=false) <> 3
     OR (SELECT count(*) FROM candidate.candidate_event
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND state='REMOVED' AND removed_at IS NOT NULL
         AND authority_eligible=false) <> 2
     OR (SELECT count(*) FROM candidate.checkpoint
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND batch_id='batch-1' AND batch_sequence=1 AND state='REORG'
         AND completed_at IS NULL AND row_version=2) <> 1
     OR (SELECT count(*) FROM candidate.checkpoint
       WHERE candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND batch_id='batch-2' AND batch_sequence=2 AND state='REORG'
         AND completed_at IS NULL AND row_version=2 AND authoritative_empty) <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_REORG_AND_CHECKPOINT_STATE';
  END IF;
  IF (SELECT count(*) FROM candidate.candidate_invalidation
       WHERE candidate_invalidation_id=invalidation_uuid
         AND candidate_partition_id=partition_uuid
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         AND affected_start=8 AND affected_end=20
         AND old_block_hash=decode(repeat('08',32),'hex')
         AND new_block_hash=decode(repeat('fe',32),'hex')
         AND old_chain_id='1' AND new_chain_id='1'
         AND old_genesis_hash=decode(repeat('01',32),'hex')
         AND new_genesis_hash=decode(repeat('01',32),'hex')
         AND old_selector_kind='PINNED' AND new_selector_kind='PINNED'
         AND old_block_number=8 AND new_block_number=8
         AND NOT old_pending_authorized AND NOT new_pending_authorized
         AND octet_length(evidence_digest)=32
         AND authority_eligible=false) <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_INVALIDATION_OCCURRENCE';
  END IF;
  IF (SELECT count(*) FROM candidate.quarantine_record
       WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
         AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
         AND reason_code IN ('DATA-6042-INBOX-DIGEST-CONFLICT','DATA-6043-INBOX-SEQUENCE-GAP','DATA-6044-FBC-011-PC-RUNTIME-3009')) <> 4 THEN
    RAISE EXCEPTION 'I06_GATE3_QUARANTINE_COUNT';
  END IF;

  IF (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND source='urn:openpc:source-profile:018f47a5-4a58-7b21-8f3a-333333333333'
         AND subject=('urn:openpc:candidate-partition:'||partition_uuid)::openpc.openpc_urn
         AND sha256(payload_cbor)=payload_digest AND authority_eligible=false) <> 5 THEN
    RAISE EXCEPTION 'I06_GATE3_OUTBOX_PARTITION_IDENTITY_COUNT';
  END IF;
  IF (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND aggregate_sequence=1
         AND event_type='io.openpc.indexer.projection.candidate.observed.v1'
         AND schema_uri='https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateObserved'
         AND payload_json->>'candidateId'='urn:openpc:candidate:'||candidate_one_uuid
         AND payload_json->>'indexerProfileId'='urn:openpc:indexer-profile:018f47a5-4a58-7b21-8f3a-888888888888'
         AND payload_json->>'candidateDigest'='sha256:'||encode((SELECT normalized_digest FROM candidate.candidate_event WHERE candidate_event_id=candidate_one_uuid AND candidate_partition_id=partition_uuid AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'),'hex')
         AND payload_json->>'sourceCursorDigest'='sha256:'||encode((SELECT position_digest FROM candidate.checkpoint WHERE candidate_partition_id=partition_uuid AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-1' AND batch_sequence=1),'hex')
         AND payload_json->>'authority'='CANDIDATE_ONLY') <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_OBSERVED_EVENT_EXACT';
  END IF;
  IF (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND aggregate_sequence=2
         AND event_type='io.openpc.indexer.projection.candidate.observed.v1'
         AND schema_uri='https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateObserved'
         AND payload_json->>'candidateId'='urn:openpc:candidate:'||candidate_two_uuid
         AND payload_json->>'candidateDigest'='sha256:'||encode((SELECT normalized_digest FROM candidate.candidate_event WHERE candidate_event_id=candidate_two_uuid AND candidate_partition_id=partition_uuid AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'),'hex')
         AND payload_json->>'sourceCursorDigest'='sha256:'||encode((SELECT position_digest FROM candidate.checkpoint WHERE candidate_partition_id=partition_uuid AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-1' AND batch_sequence=1),'hex')
         AND payload_json->>'authority'='CANDIDATE_ONLY') <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_SECOND_OBSERVED_EVENT_EXACT';
  END IF;
  IF (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND aggregate_sequence=3
         AND event_type='io.openpc.indexer.projection.checkpoint.completed.v1'
         AND schema_uri='https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCheckpointCompleted'
         AND payload_json->>'batchId'='batch-1' AND payload_json->>'recordCount'='2'
         AND payload_json->>'authoritativeEmpty'='false'
         AND payload_json->'predecessorBatchDigest'='null'::jsonb
         AND payload_json->'decodeFailures'='[]'::jsonb
         AND payload_json->'missingIntervals'='[]'::jsonb
         AND payload_json->>'authority'='CANDIDATE_ONLY') <> 1
     OR (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND aggregate_sequence=4
         AND event_type='io.openpc.indexer.projection.checkpoint.completed.v1'
         AND payload_json->>'batchId'='batch-2' AND payload_json->>'recordCount'='0'
         AND payload_json->>'authoritativeEmpty'='true'
         AND payload_json->'decodeFailures'='[]'::jsonb
         AND payload_json->'missingIntervals'='[]'::jsonb
         AND payload_json->>'predecessorBatchDigest' IS NOT NULL
         AND payload_json->>'authority'='CANDIDATE_ONLY') <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_CHECKPOINT_EVENTS_EXACT';
  END IF;
  IF (SELECT count(*) FROM candidate.outbox_event
       WHERE aggregate_type='candidate-partition' AND aggregate_id=partition_uuid
         AND aggregate_sequence=5
         AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'
         AND schema_uri='https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateInvalidated'
         AND payload_json->>'candidatePartitionId'='urn:openpc:candidate-partition:'||partition_uuid
         AND payload_json->>'invalidationId'=invalidation_uuid::text
         AND payload_json->'affectedRange'='{"start":"8","end":"20"}'::jsonb
         AND payload_json->'affectedCandidateIds'=(
           SELECT jsonb_agg('urn:openpc:candidate:'||candidate_event_id::text ORDER BY record_sequence,candidate_event_id)
             FROM candidate.candidate_event
            WHERE candidate_partition_id=partition_uuid
              AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
         )
         AND payload_json->>'reorgEvidenceDigest'='sha256:'||encode(invalidation_evidence_digest,'hex')
         AND payload_json->>'authority'='CANDIDATE_ONLY') <> 1 THEN
    RAISE EXCEPTION 'I06_GATE3_INVALIDATION_EVENT_EXACT';
  END IF;
END
$positive$;

DO $negative$
DECLARE
  mutation text;
  partition_uuid uuid;
  block_uuid uuid;
  invalidation_uuid uuid;
  source_profile_before candidate.source_profile%ROWTYPE;
  source_profile_after candidate.source_profile%ROWTYPE;
  projection_profile_before candidate.projection_profile%ROWTYPE;
  projection_profile_after candidate.projection_profile%ROWTYPE;
  projection_generation_before candidate.projection_generation%ROWTYPE;
  projection_generation_after candidate.projection_generation%ROWTYPE;
BEGIN
  SELECT candidate_partition_id INTO STRICT partition_uuid
    FROM candidate.candidate_partition
   WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
     AND source_id='source' AND partition_id='partition';
  SELECT candidate_block_id INTO STRICT block_uuid
    FROM candidate.candidate_block
   WHERE candidate_partition_id=partition_uuid
     AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND block_number=8 AND block_hash=decode(repeat('08',32),'hex');
  SELECT ci.candidate_invalidation_id INTO STRICT invalidation_uuid
    FROM candidate.candidate_invalidation ci
    JOIN candidate.outbox_event oe
      ON oe.aggregate_type='candidate-partition'
     AND oe.aggregate_id=ci.candidate_partition_id
     AND oe.aggregate_sequence=5
     AND oe.event_type='io.openpc.indexer.projection.candidate.invalidated.v1'
     AND oe.payload_json->>'invalidationId'=ci.candidate_invalidation_id::text
   WHERE ci.candidate_partition_id=partition_uuid
     AND ci.projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND ci.affected_start=8 AND ci.affected_end=20
     AND ci.old_block_number=8 AND ci.new_block_number=8
     AND ci.old_block_hash=decode(repeat('08',32),'hex')
     AND ci.new_block_hash=decode(repeat('fe',32),'hex');
  SELECT * INTO STRICT source_profile_before
    FROM candidate.source_profile
   WHERE source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
     AND participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222';
  SELECT * INTO STRICT projection_profile_before
    FROM candidate.projection_profile
   WHERE projection_profile_id='018f47a5-4a58-7b21-8f3a-444444444444'
     AND participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333';
  SELECT * INTO STRICT projection_generation_before
    FROM candidate.projection_generation
   WHERE projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND participant_id='018f47a5-4a58-7b21-8f3a-111111111111'
     AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
     AND projection_profile_id='018f47a5-4a58-7b21-8f3a-444444444444';
  FOREACH mutation IN ARRAY ARRAY[
    'candidate_partition_id=''018f47a5-4a58-7b21-8f3a-d10000000001''::uuid',
    'chain_namespace=''eip155:2''',
    'block_hash=decode(repeat(''ff'',32),''hex'')',
    'parent_hash=decode(repeat(''fe'',32),''hex'')',
    'block_number=11',
    'block_timestamp=block_timestamp+interval ''1 second''',
    'observed_at=observed_at+interval ''1 second''',
    'source_payload_digest=decode(repeat(''fd'',32),''hex'')',
    'finality_kind=''SAFE_TAG''',
    'finality_evidence_digest=decode(repeat(''fc'',32),''hex'')',
    'finality_head_number=32',
    'finality_head_hash=decode(repeat(''fb'',32),''hex'')'
  ] LOOP
    PERFORM pg_temp.i06_require_exact_rejection(
      'candidate.candidate_block.'||mutation,
      format(
        'UPDATE candidate.candidate_block SET %s WHERE candidate_block_id=%L::uuid AND candidate_partition_id=%L::uuid AND projection_generation_id=%L::uuid',
        mutation,block_uuid,partition_uuid,'018f47a5-4a58-7b21-8f3a-555555555555'
      ),
      'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_block'
    );
  END LOOP;

  FOREACH mutation IN ARRAY ARRAY[
    'candidate_partition_id=''018f47a5-4a58-7b21-8f3a-d20000000001''::uuid','candidate_block_id=''018f47a5-4a58-7b21-8f3a-d20000000002''::uuid',
    'record_kind=''STATE_CALL''','record_sequence=2','record_id=''drift''',
    'schema_digest=decode(repeat(''fa'',32),''hex'')','normalized_digest=decode(repeat(''f9'',32),''hex'')',
    'evidence_digest=decode(repeat(''f8'',32),''hex'')','transaction_hash=decode(repeat(''f7'',32),''hex'')',
    'transaction_index=1','log_index=1','contract_address=decode(repeat(''f6'',20),''hex'')',
    'event_signature=decode(repeat(''f5'',32),''hex'')','target_address=decode(repeat(''f4'',20),''hex'')',
    'call_parameter_digest=decode(repeat(''f3'',32),''hex'')','candidate_key_digest=decode(repeat(''f2'',32),''hex'')',
    'payload_cbor=decode(''a2'',''hex'')','payload_digest=sha256(decode(''a2'',''hex''))',
    'observed_at=observed_at+interval ''1 second'''
  ] LOOP
    PERFORM pg_temp.i06_require_exact_rejection(
      'candidate.candidate_event.'||mutation,
      format(
        'UPDATE candidate.candidate_event SET %s WHERE candidate_partition_id=%L::uuid AND projection_generation_id=%L::uuid AND record_kind=''EVENT_LOG'' AND record_id=''record-1-1''',
        mutation,partition_uuid,'018f47a5-4a58-7b21-8f3a-555555555555'
      ),
      'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_event'
    );
  END LOOP;

  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.candidate_event.removed_at',
    format(
      'UPDATE candidate.candidate_event SET removed_at=clock_timestamp() WHERE candidate_partition_id=%L::uuid AND projection_generation_id=%L::uuid AND record_kind=''EVENT_LOG'' AND record_id=''record-1-1''',
      partition_uuid,'018f47a5-4a58-7b21-8f3a-555555555555'
    ),
    'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_event.removed_at'
  );

  FOREACH mutation IN ARRAY ARRAY[
    'candidate_partition_id=''018f47a5-4a58-7b21-8f3a-d30000000001''::uuid','checkpoint_kind=''SEQUENCE''',
    'position_cbor=decode(''a2'',''hex'')','position_digest=sha256(decode(''a2'',''hex''))',
    'batch_id=''drift''','batch_sequence=9','batch_digest=decode(repeat(''f1'',32),''hex'')',
    'predecessor_batch_digest=decode(repeat(''f0'',32),''hex'')','range_start=2','range_end=29',
    'authoritative_empty=NOT authoritative_empty','observed_at=observed_at+interval ''1 second'''
  ] LOOP
    PERFORM pg_temp.i06_require_exact_rejection(
      'candidate.checkpoint.'||mutation,
      format(
        'UPDATE candidate.checkpoint SET %s WHERE candidate_partition_id=%L::uuid AND projection_generation_id=%L::uuid AND batch_id=''batch-2'' AND batch_sequence=2',
        mutation,partition_uuid,'018f47a5-4a58-7b21-8f3a-555555555555'
      ),
      'P0001','DATA-6206-CHECKPOINT-TRANSITION-INVALID',''
    );
  END LOOP;

  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.projection_profile.data_class',
    'UPDATE candidate.projection_profile SET data_class=''STATE_CALL'' WHERE projection_profile_id=''018f47a5-4a58-7b21-8f3a-444444444444''::uuid AND participant_id=''018f47a5-4a58-7b21-8f3a-111111111111''::uuid AND privacy_domain_id=''018f47a5-4a58-7b21-8f3a-222222222222''::uuid AND source_profile_id=''018f47a5-4a58-7b21-8f3a-333333333333''::uuid',
    '42501','permission denied for table projection_profile',''
  );
  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.source_profile.qualified-referent-runtime-mutation',
    'UPDATE candidate.source_profile SET source_profile_cbor=decode(''a1'',''hex''), source_profile_digest=sha256(decode(''a1'',''hex'')), reorg_profile_digest=decode(repeat(''ef'',32),''hex''), finality_mode=''SAFE_TAG'', confirmation_count=NULL WHERE source_profile_id=''018f47a5-4a58-7b21-8f3a-333333333333''::uuid AND participant_id=''018f47a5-4a58-7b21-8f3a-111111111111''::uuid AND privacy_domain_id=''018f47a5-4a58-7b21-8f3a-222222222222''::uuid',
    '42501','permission denied for table source_profile',''
  );
  SELECT * INTO STRICT source_profile_after
    FROM candidate.source_profile
   WHERE source_profile_id=source_profile_before.source_profile_id
     AND participant_id=source_profile_before.participant_id
     AND privacy_domain_id=source_profile_before.privacy_domain_id;
  IF source_profile_after IS DISTINCT FROM source_profile_before THEN
    RAISE EXCEPTION 'I06_GATE3_SOURCE_PROFILE_RUNTIME_MUTATION_EFFECT';
  END IF;
  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.projection_generation.lock-only-update',
    'UPDATE candidate.projection_generation SET generation_digest=generation_digest WHERE projection_generation_id=''018f47a5-4a58-7b21-8f3a-555555555555''::uuid',
    'P0001','DATA-6020-IMMUTABLE-ROW','candidate.projection_generation'
  );
  SELECT * INTO STRICT projection_profile_after
    FROM candidate.projection_profile
   WHERE projection_profile_id=projection_profile_before.projection_profile_id
     AND participant_id=projection_profile_before.participant_id
     AND privacy_domain_id=projection_profile_before.privacy_domain_id
     AND source_profile_id=projection_profile_before.source_profile_id;
  SELECT * INTO STRICT projection_generation_after
    FROM candidate.projection_generation
   WHERE projection_generation_id=projection_generation_before.projection_generation_id
     AND participant_id=projection_generation_before.participant_id
     AND privacy_domain_id=projection_generation_before.privacy_domain_id
     AND projection_profile_id=projection_generation_before.projection_profile_id;
  IF projection_profile_after IS DISTINCT FROM projection_profile_before
     OR projection_generation_after IS DISTINCT FROM projection_generation_before THEN
    RAISE EXCEPTION 'I06_GATE3_QUALIFICATION_REFERENT_RUNTIME_MUTATION_EFFECT';
  END IF;
  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.outbox_event.subject',
    format('UPDATE candidate.outbox_event SET subject=''urn:openpc:candidate-partition:018f47a5-4a58-7b21-8f3a-d40000000001''::openpc.openpc_urn WHERE aggregate_type=''candidate-partition'' AND aggregate_id=%L::uuid AND aggregate_sequence=1',partition_uuid),
    'P0001','DATA-6020-IMMUTABLE-ROW','candidate.outbox_event'
  );
  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.outbox_event.payload_json',
    format('UPDATE candidate.outbox_event SET payload_json=''{}''::jsonb WHERE aggregate_type=''candidate-partition'' AND aggregate_id=%L::uuid AND aggregate_sequence=5',partition_uuid),
    'P0001','DATA-6020-IMMUTABLE-ROW','candidate.outbox_event'
  );
  PERFORM pg_temp.i06_require_exact_rejection(
    'candidate.candidate_invalidation.evidence_digest',
    format('UPDATE candidate.candidate_invalidation SET evidence_digest=decode(repeat(''ef'',32),''hex'') WHERE candidate_invalidation_id=%L::uuid AND candidate_partition_id=%L::uuid AND projection_generation_id=%L::uuid',invalidation_uuid,partition_uuid,'018f47a5-4a58-7b21-8f3a-555555555555'),
    '42501','permission denied for table candidate_invalidation',''
  );

  IF has_table_privilege(current_user,'candidate.candidate_partition','INSERT')
     OR has_table_privilege(current_user,'candidate.candidate_partition','UPDATE')
     OR has_table_privilege(current_user,'candidate.candidate_partition','DELETE') THEN
    RAISE EXCEPTION 'I06_GATE3_DIRECT_PARTITION_DML_GRANTED';
  END IF;
END
$negative$;
ROLLBACK;

BEGIN;
SELECT openpc.set_request_context(
  'PARTICIPANT','018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-222222222222',
  '018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa','ACT-CANDIDATE_WRITE-V1',false
);
SELECT openpc.assert_request_context(true);

SELECT pg_temp.i06_assert('I06-G3-M12-I01-N-CROSS-TENANT', NOT EXISTS (
  SELECT 1 FROM candidate.candidate_partition
   WHERE participant_id <> '018f47a5-4a58-7b21-8f3a-111111111111'
      OR privacy_domain_id <> '018f47a5-4a58-7b21-8f3a-222222222222'
));






SELECT pg_temp.i06_assert('I06-G3-M12-I07-N-CALLER-UUID', NOT has_table_privilege(current_user,'candidate.candidate_partition','INSERT'));
SELECT pg_temp.i06_assert('I06-G3-M12-I07-N-CROSS-TENANT', NOT EXISTS (
  SELECT 1 FROM candidate.candidate_partition cp JOIN candidate.outbox_event oe
    ON oe.aggregate_type='candidate-partition'
   AND oe.aggregate_id=cp.candidate_partition_id
   WHERE cp.participant_id <> oe.participant_id OR cp.privacy_domain_id <> oe.privacy_domain_id
));

SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-PARTICIPANT',
  $sql$UPDATE candidate.candidate_partition SET participant_id='018f47a5-4a58-7b21-8f3a-333333333333'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-PRIVACY',
  $sql$UPDATE candidate.candidate_partition SET privacy_domain_id='018f47a5-4a58-7b21-8f3a-333333333333'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-GENERATION',
  $sql$UPDATE candidate.candidate_partition SET projection_generation_id='018f47a5-4a58-7b21-8f3a-333333333333'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-SOURCE-PROFILE',
  $sql$UPDATE candidate.candidate_partition SET source_profile_id='018f47a5-4a58-7b21-8f3a-888888888888'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-PLAN-DIGEST',
  $sql$UPDATE candidate.candidate_partition SET plan_digest=decode(repeat('ff',32),'hex')$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-SOURCE-ID',
  $sql$UPDATE candidate.candidate_partition SET source_id='wrong'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-PARTITION-ID',
  $sql$UPDATE candidate.candidate_partition SET partition_id='wrong'$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-RANGE',
  $sql$UPDATE candidate.candidate_partition SET range_start=2$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-CBOR',
  $sql$UPDATE candidate.candidate_partition SET binding_cbor=decode('a0','hex')$sql$,
  '42501','permission denied for table candidate_partition','');
SELECT pg_temp.i06_reject('I06-G3-M12-I08-N-BINDING-DIGEST',
  $sql$UPDATE candidate.candidate_partition SET binding_digest=decode(repeat('ff',32),'hex')$sql$,
  '42501','permission denied for table candidate_partition','');


SELECT pg_temp.i06_reject('I06-G3-M14-I11-N-BLOCK-ID',
  $sql$UPDATE candidate.candidate_block SET candidate_block_id='018f47a5-4a58-7b21-8f3a-930000000001'
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
      AND block_number=8 AND block_hash=decode(repeat('08',32),'hex')$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_block');
SELECT pg_temp.i06_reject('I06-G3-M14-I11-N-BLOCK-HASH',
  $sql$UPDATE candidate.candidate_block SET block_hash=decode(repeat('ff',32),'hex')
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
      AND block_number=8 AND block_hash=decode(repeat('08',32),'hex')$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_block');
SELECT pg_temp.i06_reject('I06-G3-M14-I11-N-PARENT-HASH',
  $sql$UPDATE candidate.candidate_block SET parent_hash=decode(repeat('fe',32),'hex')
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
      AND block_number=8 AND block_hash=decode(repeat('08',32),'hex')$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_block');


SELECT pg_temp.i06_reject('I06-G3-M14-I13-N-EVENT-ID',
  $sql$UPDATE candidate.candidate_event SET candidate_event_id='018f47a5-4a58-7b21-8f3a-930000000002'
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND record_kind='EVENT_LOG' AND record_id='record-1-1'$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_event');
SELECT pg_temp.i06_assert('I06-G3-M14-I13-N-CROSS-PARTITION', NOT EXISTS (
  SELECT 1 FROM candidate.candidate_event ce JOIN candidate.candidate_block cb USING (candidate_block_id)
   WHERE ce.candidate_partition_id <> cb.candidate_partition_id
));

SELECT pg_temp.i06_reject('I06-G3-M14-I14-N-IMMUTABILITY',
  $sql$UPDATE candidate.candidate_event SET record_id='mutated'
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND record_kind='EVENT_LOG' AND record_id='record-1-1'$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.candidate_event');

SELECT pg_temp.i06_reject('I06-G3-M14-I15-N-CHECKPOINT-ID',
  $sql$UPDATE candidate.checkpoint SET checkpoint_id='018f47a5-4a58-7b21-8f3a-930000000003'
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-2' AND batch_sequence=2$sql$,
  'P0001','DATA-6206-CHECKPOINT-TRANSITION-INVALID','');
SELECT pg_temp.i06_reject('I06-G3-M14-I15-N-POSITION-CBOR',
  $sql$UPDATE candidate.checkpoint SET position_cbor=decode('a0','hex')
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-2' AND batch_sequence=2$sql$,
  'P0001','DATA-6206-CHECKPOINT-TRANSITION-INVALID','');
SELECT pg_temp.i06_reject('I06-G3-M14-I15-N-POSITION-DIGEST',
  $sql$UPDATE candidate.checkpoint SET position_digest=decode(repeat('f7',32),'hex')
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-2' AND batch_sequence=2$sql$,
  'P0001','DATA-6206-CHECKPOINT-TRANSITION-INVALID','');
SELECT pg_temp.i06_reject('I06-G3-M14-I15-N-IMMUTABILITY',
  $sql$UPDATE candidate.checkpoint SET batch_id='mutated'
    WHERE candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
      WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
        AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
        AND source_id='source' AND partition_id='partition')
      AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND batch_id='batch-2' AND batch_sequence=2$sql$,
  'P0001','DATA-6206-CHECKPOINT-TRANSITION-INVALID','');



SELECT pg_temp.i06_reject('I06-G3-M14-I18-N-EVENT-ID',
  $sql$UPDATE candidate.outbox_event SET event_id='018f47a5-4a58-7b21-8f3a-930000000004'
    WHERE aggregate_type='candidate-partition'
      AND aggregate_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
        WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
          AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
          AND source_id='source' AND partition_id='partition')
      AND aggregate_sequence=5 AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.outbox_event');
SELECT pg_temp.i06_reject('I06-G3-M14-I18-N-PAYLOAD-CBOR',
  $sql$UPDATE candidate.outbox_event SET payload_cbor=decode('a0','hex')
    WHERE aggregate_type='candidate-partition'
      AND aggregate_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
        WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
          AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
          AND source_id='source' AND partition_id='partition')
      AND aggregate_sequence=5 AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.outbox_event');
SELECT pg_temp.i06_reject('I06-G3-M14-I18-N-PAYLOAD-DIGEST',
  $sql$UPDATE candidate.outbox_event SET payload_digest=decode(repeat('f4',32),'hex')
    WHERE aggregate_type='candidate-partition'
      AND aggregate_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
        WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
          AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
          AND source_id='source' AND partition_id='partition')
      AND aggregate_sequence=5 AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'$sql$,
  'P0001','DATA-6020-IMMUTABLE-ROW','candidate.outbox_event');



SAVEPOINT i06_cross_privacy;
SELECT openpc.set_request_context(
  'PARTICIPANT','018f47a5-4a58-7b21-8f3a-111111111111',
  '018f47a5-4a58-7b21-8f3a-bbbbbbbbbbbb',
  '018f47a5-4a58-7b21-8f3a-cccccccccccc','ACT-CANDIDATE_WRITE-V1',false
);
DO $privacy$
BEGIN
  IF (SELECT count(*) FROM candidate.candidate_partition) <> 0
     OR (SELECT count(*) FROM candidate.candidate_block) <> 0
     OR (SELECT count(*) FROM candidate.candidate_event) <> 0
     OR (SELECT count(*) FROM candidate.checkpoint) <> 0
     OR (SELECT count(*) FROM candidate.candidate_invalidation) <> 0
     OR (SELECT count(*) FROM candidate.outbox_event) <> 0 THEN
    RAISE EXCEPTION 'I06_GATE3_CROSS_PRIVACY_RLS_VISIBLE';
  END IF;
END
$privacy$;
ROLLBACK TO SAVEPOINT i06_cross_privacy;

SELECT pg_temp.i06_assert('I06-G3-M15-I20-N-MALFORMED-UUID', NOT EXISTS (
  SELECT 1 FROM candidate.outbox_event
   WHERE aggregate_type='candidate-partition'
     AND aggregate_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
       WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
         AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
         AND source_id='source' AND partition_id='partition')
     AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'
     AND payload_json ? 'invalidationId'
   AND payload_json->>'invalidationId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
));
SELECT pg_temp.i06_assert('I06-G3-M15-I20-N-CALLER-UUID', (
  SELECT pg_get_expr(def.adbin,def.adrelid)='uuidv7()'
    FROM pg_attribute attribute
    JOIN pg_attrdef def ON def.adrelid=attribute.attrelid AND def.adnum=attribute.attnum
   WHERE attribute.attrelid='candidate.candidate_invalidation'::regclass
     AND attribute.attname='candidate_invalidation_id'
));

SELECT pg_temp.i06_assert('I06-G3-M15-I21-N-INVALIDATION-ID', (
  SELECT count(*)=1
    FROM candidate.candidate_invalidation ci
    JOIN candidate.outbox_event oe
      ON oe.aggregate_type='candidate-partition'
     AND oe.aggregate_id=ci.candidate_partition_id
     AND oe.aggregate_sequence=5
     AND oe.event_type='io.openpc.indexer.projection.candidate.invalidated.v1'
     AND oe.payload_json->>'invalidationId'=ci.candidate_invalidation_id::text
   WHERE ci.candidate_partition_id=(SELECT candidate_partition_id FROM candidate.candidate_partition
     WHERE participant_id='018f47a5-4a58-7b21-8f3a-111111111111' AND privacy_domain_id='018f47a5-4a58-7b21-8f3a-222222222222'
       AND projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555' AND source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
       AND source_id='source' AND partition_id='partition')
     AND ci.projection_generation_id='018f47a5-4a58-7b21-8f3a-555555555555'
     AND ci.affected_start=8 AND ci.affected_end=20
     AND ci.old_block_number=8 AND ci.new_block_number=8
     AND ci.old_block_hash=decode(repeat('08',32),'hex')
     AND ci.new_block_hash=decode(repeat('fe',32),'hex')
     AND oe.payload_json->>'reorgEvidenceDigest'='sha256:'||encode(ci.evidence_digest,'hex')
));




DO $assertion_count$
BEGIN
  IF (SELECT count(*) FROM pg_temp.i06_gate3_assertion WHERE passed) <> 29 THEN
    RAISE EXCEPTION 'I06_GATE3_ASSERTION_COUNT_MISMATCH|%',
      (SELECT count(*) FROM pg_temp.i06_gate3_assertion WHERE passed);
  END IF;
END
$assertion_count$;
SELECT 'I06_GATE3_ASSERTION_COUNT|SQL_DATABASE|'||count(*)||'|PASS'
FROM pg_temp.i06_gate3_assertion;
SELECT 'I06_GATE3_ASSERTION|SQL_DATABASE|'||assertion_id||'|PASS'
FROM pg_temp.i06_gate3_assertion
ORDER BY assertion_id;
ROLLBACK;

\echo I06_GATE3_POSTGRES18_PARTITION_TYPED_CHECKPOINT_OUTBOX_REORG_TAMPER|PASS
