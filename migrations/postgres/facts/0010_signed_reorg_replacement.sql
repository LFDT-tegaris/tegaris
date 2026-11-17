ALTER TABLE facts.candidate_feed_receipt DROP CONSTRAINT candidate_feed_receipt_check1,
 ADD CONSTRAINT candidate_feed_receipt_payload_kind CHECK (
  (event_kind='CANDIDATE' AND candidate_id IS NOT NULL AND fact_digest IS NOT NULL AND canonical_provenance IS NOT NULL AND record_ordinal<=record_count)
  OR (event_kind='CHECKPOINT' AND candidate_id IS NULL AND fact_digest IS NULL AND record_ordinal=record_count+1
      AND ((record_count=0 AND canonical_provenance IS NOT NULL) OR (record_count>0 AND canonical_provenance IS NULL))));
-- Complete empty source checkpoints consume sequence without fabricating facts.
ALTER TABLE facts.candidate_feed_receipt DROP CONSTRAINT candidate_feed_receipt_record_count_check,
  ADD CONSTRAINT candidate_feed_receipt_record_count_check CHECK(record_count >= 0);
-- Registered RGRA specialization shares the canonical fact owner. Historical
-- base records retain their exact tuple; no other schema family is admitted.
ALTER TABLE facts.canonical_fact DROP CONSTRAINT canonical_fact_schema_id_check,
  DROP CONSTRAINT canonical_fact_schema_digest_check,
  ADD CONSTRAINT canonical_fact_registered_schema CHECK (
    (schema_id=21006 AND schema_digest=decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525','hex')) OR
    (schema_id=21103 AND schema_digest=decode('b86eeaf46d4d23b047eab61e5e8e7a5dfd8e74525882005b316a93fb77125d38','hex'))
  );
-- SQLx-owned short-reorg recovery preserves the signed predecessor, consumes
-- the intervening invalidation, and separates admission from verified readiness.
ALTER TABLE facts.source_checkpoint ADD COLUMN recovery_candidate_id text,
  ADD COLUMN recovery_generation_id text,
  ADD COLUMN recovery_cursor_cbor bytea,
  ADD COLUMN recovery_checkpoint_cose bytea,
  ADD CONSTRAINT recovery_cursor_complete CHECK (
    (recovery_candidate_id IS NULL AND recovery_generation_id IS NULL AND recovery_cursor_cbor IS NULL AND recovery_checkpoint_cose IS NULL)
    OR (recovery_candidate_id IS NOT NULL AND recovery_generation_id IS NOT NULL AND octet_length(recovery_cursor_cbor) BETWEEN 1 AND 131072
      AND octet_length(recovery_checkpoint_cose) BETWEEN 65 AND 131072));
CREATE UNIQUE INDEX source_checkpoint_recovery_generation ON facts.source_checkpoint(participant_id,privacy_domain_id,recovery_generation_id)
  WHERE recovery_generation_id IS NOT NULL;
ALTER TABLE facts.lineage_outbox ADD COLUMN recovery_cursor_cbor bytea;
ALTER TABLE facts.lineage_outbox DROP CONSTRAINT lineage_outbox_event_type_check,
  ADD CONSTRAINT lineage_outbox_event_type_check CHECK(event_type IN
    ('io.openpc.fact.fact.retired.v1','io.openpc.fact.fact.invalidated.v1','io.openpc.fact.fact.superseded.v1','io.openpc.fact.gap.resolved.v1'));
DO $$ DECLARE item record; BEGIN
  FOR item IN SELECT conname FROM pg_constraint WHERE conrelid='facts.lineage_outbox'::regclass AND contype='u' LOOP
    EXECUTE format('ALTER TABLE facts.lineage_outbox DROP CONSTRAINT %I',item.conname);
  END LOOP;
END $$;
ALTER TABLE facts.lineage_outbox ADD CONSTRAINT lineage_event_action UNIQUE(participant_id,privacy_domain_id,source_event_id,candidate_id,event_type),
  ADD CONSTRAINT lineage_sequence_action UNIQUE(participant_id,privacy_domain_id,partition_id,source_sequence,candidate_id,event_type);
ALTER TABLE facts.canonical_fact DROP CONSTRAINT canonical_fact_finalization_state,
  ADD CONSTRAINT canonical_fact_finalization_state CHECK(state IN ('ADMITTED','RETIRED','REORG_TOMBSTONED','SUPERSEDED') OR finalized_at IS NOT NULL);
-- Complete signed replacements link while ADMITTED. Verified COM-019 publication
-- remains the only owner that can finalize them, supersede history and lift fences.
CREATE OR REPLACE FUNCTION facts.enforce_replacement_lifecycle()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, facts
AS $$
DECLARE
  predecessor facts.canonical_fact%ROWTYPE;
  replacement facts.canonical_fact%ROWTYPE;
  now_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
BEGIN
  SELECT * INTO predecessor FROM facts.canonical_fact
   WHERE candidate_id = NEW.candidate_id
     AND participant_id = NEW.participant_id
     AND privacy_domain_id = NEW.privacy_domain_id
   FOR UPDATE;
  -- Retirement records its invalidation first, then changes the fact in the
  -- same capability-authenticated transaction. It cannot install a replacement.
  IF TG_OP='INSERT' AND NEW.reason='RETIREMENT'
     AND predecessor.state IN ('ADMITTED','FINALIZED')
     AND predecessor.generation_id=NEW.predecessor_generation_id
     AND NEW.replacement_candidate_id IS NULL AND NEW.replacement_generation_id IS NULL
     AND NEW.linked_at IS NULL THEN
    RETURN NEW;
  END IF;
  IF predecessor.candidate_id IS NULL
     OR predecessor.state <> 'REORG_TOMBSTONED'
     OR predecessor.generation_id <> NEW.predecessor_generation_id THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_PREDECESSOR_REJECTED';
  END IF;
  IF NEW.replacement_generation_id IS NOT NULL THEN
    SELECT * INTO replacement FROM facts.canonical_fact
     WHERE candidate_id = NEW.replacement_candidate_id
       AND participant_id = NEW.participant_id
       AND privacy_domain_id = NEW.privacy_domain_id
     FOR UPDATE;
    IF replacement.candidate_id IS NULL
       OR NOT (replacement.state = 'FINALIZED' OR (
         replacement.state = 'ADMITTED' AND NEW.reason = 'REORG'
         AND EXISTS(SELECT 1 FROM facts.canonical_identity_allocation next
           JOIN facts.canonical_identity_allocation predecessor_allocation USING(participant_id,privacy_domain_id,fact_profile_id)
           JOIN facts.canonical_generation ng ON ng.participant_id=next.participant_id
             AND ng.privacy_domain_id=next.privacy_domain_id AND ng.fact_profile_id=next.fact_profile_id
             AND ng.generation_id=next.generation_id
           JOIN facts.canonical_generation og ON og.participant_id=predecessor_allocation.participant_id
             AND og.privacy_domain_id=predecessor_allocation.privacy_domain_id AND og.fact_profile_id=predecessor_allocation.fact_profile_id
             AND og.generation_id=predecessor_allocation.generation_id
           JOIN facts.lineage_outbox l ON l.candidate_id=predecessor_allocation.candidate_id
             AND l.participant_id=predecessor_allocation.participant_id AND l.privacy_domain_id=predecessor_allocation.privacy_domain_id
           WHERE next.candidate_id=replacement.candidate_id AND predecessor_allocation.candidate_id=predecessor.candidate_id
             AND next.participant_id=NEW.participant_id AND next.privacy_domain_id=NEW.privacy_domain_id
             AND ng.canonical_generation>og.canonical_generation
             AND l.event_type='io.openpc.fact.fact.invalidated.v1')))
       OR NOT replacement.complete
       OR NOT replacement.finality_verified
       OR replacement.fresh_until_ms < now_ms
       OR replacement.generation_id <> NEW.replacement_generation_id
       OR replacement.generation_id = NEW.predecessor_generation_id THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_REPLACEMENT_REJECTED';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION facts.verify_replacement_capability(
  requested_predecessor_candidate_id text,
  requested_candidate_id text,
  requested_participant text,
  requested_privacy_domain text,
  requested_source_profile text,
  requested_generation text,
  requested_source_sequence bigint,
  requested_payload_digest bytea,
  requested_schema_id bigint,
  requested_schema_version text,
  requested_schema_digest bytea,
  requested_canonical_payload bytea,
  requested_fact_digest bytea,
  requested_finality_anchor bytea,
  requested_observed_at_ms bigint,
  requested_fresh_until_ms bigint,
  requested_cose_sign1 bytea,
  requested_signed_fact_digest bytea,
  requested_signer_key_id bytea,
  requested_provenance_digest bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  preimage bytea;
BEGIN
  preimage := facts.mutation_capability_preimage(
    'ADMIT_REPLACEMENT', requested_participant, requested_privacy_domain,
    requested_candidate_id, requested_predecessor_candidate_id,
    requested_source_profile, requested_generation, requested_source_sequence,
    requested_payload_digest, requested_schema_id, requested_schema_version,
    requested_schema_digest, requested_canonical_payload, requested_fact_digest,
    requested_finality_anchor, requested_observed_at_ms, requested_fresh_until_ms,
    requested_cose_sign1, requested_signed_fact_digest, requested_signer_key_id,
    'openpc:fact-record:v1', requested_provenance_digest, NULL, NULL, NULL,
    'REORG', 'ADMIT_REORG_REPLACEMENT',
    requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'ADMIT_REPLACEMENT', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE OR REPLACE FUNCTION facts.admit_fact(
  requested_candidate_id text,
  requested_participant text,
  requested_privacy_domain text,
  requested_source_profile text,
  requested_generation text,
  requested_source_sequence bigint,
  requested_payload_digest bytea,
  requested_schema_id bigint,
  requested_schema_version text,
  requested_schema_digest bytea,
  requested_canonical_payload bytea,
  requested_fact_digest bytea,
  requested_finality_anchor bytea,
  requested_observed_at_ms bigint,
  requested_fresh_until_ms bigint,
  requested_cose_sign1 bytea,
  requested_signed_fact_digest bytea,
  requested_signer_key_id bytea,
  requested_provenance_digest bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM facts.assert_lifecycle_context(requested_participant, requested_privacy_domain);
  PERFORM facts.verify_admit_capability(
    requested_candidate_id, requested_participant, requested_privacy_domain,
    requested_source_profile, requested_generation, requested_source_sequence,
    requested_payload_digest, requested_schema_id, requested_schema_version,
    requested_schema_digest, requested_canonical_payload, requested_fact_digest,
    requested_finality_anchor, requested_observed_at_ms, requested_fresh_until_ms,
    requested_cose_sign1, requested_signed_fact_digest, requested_signer_key_id,
    requested_provenance_digest, requested_capability_nonce, requested_capability_mac
  );
  IF EXISTS(SELECT 1 FROM facts.source_checkpoint WHERE participant_id=requested_participant
    AND privacy_domain_id=requested_privacy_domain AND source_profile_id=requested_source_profile
    AND state='REORG_FENCED') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_SIGNED_REPLACEMENT_REQUIRED';
  END IF;
  RETURN facts.insert_validated_fact(
    requested_candidate_id, requested_participant, requested_privacy_domain,
    requested_source_profile, requested_generation, requested_source_sequence,
    requested_payload_digest, requested_schema_id, requested_schema_version,
    requested_schema_digest, requested_canonical_payload, requested_fact_digest,
    requested_finality_anchor, requested_observed_at_ms, requested_fresh_until_ms,
    requested_cose_sign1, requested_signed_fact_digest, requested_signer_key_id,
    requested_provenance_digest, 'ADMITTED'
  );
END
$$;

CREATE OR REPLACE FUNCTION facts.admit_replacement(
  requested_predecessor_candidate_id text,
  requested_candidate_id text,
  requested_participant text,
  requested_privacy_domain text,
  requested_source_profile text,
  requested_generation text,
  requested_source_sequence bigint,
  requested_payload_digest bytea,
  requested_schema_id bigint,
  requested_schema_version text,
  requested_schema_digest bytea,
  requested_canonical_payload bytea,
  requested_fact_digest bytea,
  requested_finality_anchor bytea,
  requested_observed_at_ms bigint,
  requested_fresh_until_ms bigint,
  requested_cose_sign1 bytea,
  requested_signed_fact_digest bytea,
  requested_signer_key_id bytea,
  requested_provenance_digest bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  predecessor_generation text;
  predecessor_state facts.fact_state;
  outcome text;
  changed bigint;
  canonical boolean;
BEGIN
  PERFORM facts.assert_lifecycle_context(requested_participant, requested_privacy_domain);
  PERFORM facts.verify_replacement_capability(
    requested_predecessor_candidate_id, requested_candidate_id,
    requested_participant, requested_privacy_domain, requested_source_profile,
    requested_generation, requested_source_sequence, requested_payload_digest,
    requested_schema_id, requested_schema_version, requested_schema_digest,
    requested_canonical_payload, requested_fact_digest, requested_finality_anchor,
    requested_observed_at_ms, requested_fresh_until_ms, requested_cose_sign1,
    requested_signed_fact_digest, requested_signer_key_id,
    requested_provenance_digest, requested_capability_nonce, requested_capability_mac
  );
  SELECT generation_id, state
    INTO predecessor_generation, predecessor_state
    FROM facts.canonical_fact
   WHERE candidate_id = requested_predecessor_candidate_id
     AND participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
   FOR UPDATE;
  IF predecessor_generation IS NULL
     OR predecessor_state <> 'REORG_TOMBSTONED'
     OR predecessor_generation = requested_generation THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_PREDECESSOR_REJECTED';
  END IF;
  PERFORM 1
    FROM facts.fact_invalidation
   WHERE candidate_id = requested_predecessor_candidate_id
     AND predecessor_generation_id = predecessor_generation
     AND reason = 'REORG'
     AND replacement_candidate_id IS NULL
     AND replacement_generation_id IS NULL
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_INVALIDATION_REQUIRED';
  END IF;
  canonical := EXISTS(SELECT 1 FROM facts.canonical_identity_allocation
    WHERE candidate_id=requested_predecessor_candidate_id AND participant_id=requested_participant
      AND privacy_domain_id=requested_privacy_domain);
  IF canonical THEN
    IF NOT EXISTS(SELECT 1 FROM facts.canonical_identity_allocation next
       JOIN facts.canonical_identity_allocation old USING(participant_id,privacy_domain_id,fact_profile_id)
       JOIN facts.canonical_generation next_generation ON next_generation.participant_id=next.participant_id
         AND next_generation.privacy_domain_id=next.privacy_domain_id AND next_generation.fact_profile_id=next.fact_profile_id
         AND next_generation.generation_id=next.generation_id
       JOIN facts.canonical_generation old_generation ON old_generation.participant_id=old.participant_id
         AND old_generation.privacy_domain_id=old.privacy_domain_id AND old_generation.fact_profile_id=old.fact_profile_id
         AND old_generation.generation_id=old.generation_id
       JOIN facts.lineage_outbox l ON l.candidate_id=old.candidate_id AND l.participant_id=old.participant_id AND l.privacy_domain_id=old.privacy_domain_id
       JOIN facts.admission_inbox i ON i.candidate_id=old.candidate_id
       WHERE old.candidate_id=requested_predecessor_candidate_id AND next.candidate_id=requested_candidate_id
         AND next.participant_id=requested_participant AND next.privacy_domain_id=requested_privacy_domain
         AND next.generation_id=requested_generation AND next_generation.canonical_generation>old_generation.canonical_generation
         AND (i.source_profile_id=requested_source_profile OR EXISTS(SELECT 1 FROM facts.source_checkpoint c
           WHERE c.participant_id=requested_participant AND c.privacy_domain_id=requested_privacy_domain
             AND c.source_profile_id=i.source_profile_id AND c.recovery_generation_id=requested_generation))
         AND l.event_type='io.openpc.fact.fact.invalidated.v1') THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_SIGNED_REPLACEMENT_REQUIRED';
    END IF;
  ELSIF EXISTS(SELECT 1 FROM facts.canonical_identity_allocation WHERE candidate_id=requested_candidate_id) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_SIGNED_REPLACEMENT_REQUIRED';
  END IF;
  outcome := facts.insert_validated_fact(
    requested_candidate_id, requested_participant, requested_privacy_domain,
    requested_source_profile, requested_generation, requested_source_sequence,
    requested_payload_digest, requested_schema_id, requested_schema_version,
    requested_schema_digest, requested_canonical_payload, requested_fact_digest,
    requested_finality_anchor, requested_observed_at_ms, requested_fresh_until_ms,
    requested_cose_sign1, requested_signed_fact_digest, requested_signer_key_id,
    requested_provenance_digest, CASE WHEN canonical THEN 'ADMITTED'::facts.fact_state ELSE 'FINALIZED'::facts.fact_state END
  );
  IF outcome = 'IDEMPOTENT_REPLAY' THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_REPLAY_REJECTED';
  END IF;
  UPDATE facts.fact_invalidation
     SET replacement_candidate_id = requested_candidate_id,
         replacement_generation_id = requested_generation,
         linked_at = pg_catalog.clock_timestamp()
   WHERE candidate_id = requested_predecessor_candidate_id
     AND predecessor_generation_id = predecessor_generation
     AND replacement_candidate_id IS NULL;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_LINK_REJECTED';
  END IF;
  IF canonical THEN
    UPDATE facts.source_checkpoint SET state='REORG_FENCED' WHERE participant_id=requested_participant
      AND privacy_domain_id=requested_privacy_domain AND source_profile_id=requested_source_profile;
    RETURN outcome;
  END IF;
  UPDATE facts.canonical_fact
     SET state = 'SUPERSEDED'
   WHERE candidate_id = requested_predecessor_candidate_id
     AND participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND state = 'REORG_TOMBSTONED';
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FTR010_SUPERSEDE_REJECTED';
  END IF;
  RETURN outcome;
END
$$;

CREATE OR REPLACE FUNCTION facts.consume_candidate_feed_event(
  p_participant text, p_privacy text, p_partition uuid, p_sequence bigint, p_event uuid,
  p_source_profile text, p_source_generation text, p_fact_generation text, p_kind text,
  p_checkpoint uuid, p_batch_sequence bigint, p_batch_digest bytea, p_predecessor bytea,
  p_range_start numeric, p_range_end numeric, p_ordinal bigint, p_count bigint,
  p_checkpoint_digest bytea, p_event_cbor bytea, p_candidate text, p_fact_digest bytea,
  p_provenance bytea, p_nonce bytea, p_mac bytea
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  receipt bytea;
  prior facts.candidate_feed_receipt%ROWTYPE;
  existing bytea;
  recovery boolean := false;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF NOT coalesce(p_partition IS NOT NULL AND p_event IS NOT NULL AND p_checkpoint IS NOT NULL
    AND uuid_extract_version(p_partition)=7 AND uuid_extract_version(p_event)=7
    AND uuid_extract_version(p_checkpoint)=7
    AND p_sequence>0 AND p_batch_sequence>0 AND p_ordinal>0 AND p_count>=0
    AND p_range_start=trunc(p_range_start) AND p_range_end=trunc(p_range_end)
    AND p_range_start>=0 AND p_range_end>=p_range_start AND p_range_end<=18446744073709551615
    AND octet_length(p_event_cbor) BETWEEN 1 AND 131072
    AND (p_provenance IS NULL OR octet_length(p_provenance) BETWEEN 1 AND 131072),false) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_MATERIAL';
  END IF;
  receipt := sha256(
    facts.capability_field(1,convert_to(p_participant,'UTF8')) ||
    facts.capability_field(2,convert_to(p_privacy,'UTF8')) ||
    facts.capability_field(3,convert_to(p_partition::text,'UTF8')) ||
    facts.capability_field(4,int8send(p_sequence)) ||
    facts.capability_field(5,convert_to(p_event::text,'UTF8')) ||
    facts.capability_field(6,convert_to(p_source_profile,'UTF8')) ||
    facts.capability_field(7,convert_to(p_source_generation,'UTF8')) ||
    facts.capability_field(8,convert_to(p_fact_generation,'UTF8')) ||
    facts.capability_field(9,convert_to(p_kind,'UTF8')) ||
    facts.capability_field(10,convert_to(p_checkpoint::text,'UTF8')) ||
    facts.capability_field(11,int8send(p_batch_sequence)) ||
    facts.capability_field(12,p_batch_digest) ||
    facts.capability_field(13,p_predecessor) ||
    facts.capability_field(14,convert_to(p_range_start::text,'UTF8')) ||
    facts.capability_field(15,convert_to(p_range_end::text,'UTF8')) ||
    facts.capability_field(16,int8send(p_ordinal)) ||
    facts.capability_field(17,int8send(p_count)) ||
    facts.capability_field(18,p_checkpoint_digest) ||
    facts.capability_field(19,sha256(p_event_cbor)) ||
    facts.capability_field(20,convert_to(p_candidate,'UTF8')) ||
    facts.capability_field(21,p_fact_digest) ||
    facts.capability_field(22,sha256(p_provenance)));
  PERFORM facts.verify_candidate_feed_capability(receipt,p_nonce,p_mac);
  SELECT receipt_digest INTO existing FROM facts.candidate_feed_receipt
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
      AND partition_id=p_partition AND candidate_sequence=p_sequence;
  IF existing IS NOT NULL THEN
    IF existing=receipt THEN RETURN 'IDEMPOTENT_REPLAY'; END IF;
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_REPLAY_CONFLICT';
  END IF;
  IF EXISTS (SELECT 1 FROM facts.candidate_feed_receipt WHERE participant_id=p_participant
       AND privacy_domain_id=p_privacy AND (event_id=p_event OR candidate_id=p_candidate)) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_REPLAY_CONFLICT';
  END IF;
  SELECT * INTO prior FROM facts.candidate_feed_receipt
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND partition_id=p_partition
    ORDER BY candidate_sequence DESC LIMIT 1;
  recovery := prior.event_kind='CHECKPOINT' AND p_kind='CANDIDATE' AND EXISTS(
    SELECT 1 FROM facts.lineage_outbox l JOIN facts.fact_invalidation i USING(candidate_id,participant_id,privacy_domain_id)
    WHERE l.participant_id=p_participant AND l.privacy_domain_id=p_privacy AND l.partition_id=p_partition
      AND l.source_generation_id=p_source_generation AND l.source_sequence=prior.candidate_sequence+1
      AND l.source_sequence=p_sequence-1 AND l.event_type='io.openpc.fact.fact.invalidated.v1'
      AND l.affected_start=p_range_start AND l.affected_end=p_range_end AND i.reason='REORG'
      AND i.replacement_candidate_id=p_candidate AND i.replacement_generation_id=p_fact_generation);
  IF prior.candidate_sequence IS NULL THEN
    IF p_sequence<>1 OR p_batch_sequence<>1 OR p_ordinal<>1
       OR NOT (p_kind='CANDIDATE' OR (p_kind='CHECKPOINT' AND p_count=0)) OR p_predecessor IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_GAP';
    END IF;
  ELSE
    IF p_sequence<>prior.candidate_sequence+1+(CASE WHEN recovery THEN 1 ELSE 0 END) OR p_source_profile<>prior.source_profile_id
       OR p_source_generation<>prior.source_generation_id THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_GAP';
    END IF;
    IF prior.event_kind='CHECKPOINT' THEN
      IF NOT (p_kind='CANDIDATE' OR (p_kind='CHECKPOINT' AND p_count=0)) OR p_ordinal<>1 OR p_batch_sequence<>prior.batch_sequence+1
         OR p_predecessor IS DISTINCT FROM prior.batch_digest
         OR (NOT recovery AND p_range_start<>prior.range_end+1) OR p_checkpoint=prior.checkpoint_id
         OR p_fact_generation=prior.fact_generation_id THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_BATCH_GAP';
      END IF;
    ELSE
      IF p_checkpoint<>prior.checkpoint_id OR p_batch_sequence<>prior.batch_sequence
         OR p_batch_digest<>prior.batch_digest OR p_predecessor IS DISTINCT FROM prior.predecessor_batch_digest
         OR p_fact_generation<>prior.fact_generation_id
         OR p_range_start<>prior.range_start OR p_range_end<>prior.range_end
         OR p_count<>prior.record_count OR p_checkpoint_digest<>prior.checkpoint_digest
         OR p_ordinal<>prior.record_ordinal+1 THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_BATCH_CONFLICT';
      END IF;
    END IF;
  END IF;
  IF p_kind='CANDIDATE' THEN
    IF NOT EXISTS (SELECT 1 FROM facts.canonical_fact f
        JOIN facts.admission_inbox i USING(candidate_id)
        JOIN facts.fact_lineage l USING(candidate_id)
        WHERE f.candidate_id=p_candidate AND f.participant_id=p_participant
          AND f.privacy_domain_id=p_privacy AND f.generation_id=p_fact_generation
          AND i.source_profile_id=p_source_profile AND f.fact_digest=p_fact_digest
          AND l.provenance_digest=sha256(p_provenance) AND f.state='ADMITTED')
       OR EXISTS (SELECT 1 FROM facts.readiness_gate WHERE participant_id=p_participant
          AND privacy_domain_id=p_privacy AND generation_id=p_fact_generation AND state='READY') THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_FACT_BINDING';
    END IF;
  ELSIF p_kind='CHECKPOINT' THEN
    IF (SELECT count(*) FROM facts.candidate_feed_receipt WHERE participant_id=p_participant
          AND privacy_domain_id=p_privacy AND partition_id=p_partition AND checkpoint_id=p_checkpoint
          AND event_kind='CANDIDATE')<>p_count THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_INCOMPLETE';
    END IF;
  ELSE
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_KIND';
  END IF;
  INSERT INTO facts.candidate_feed_receipt (
    participant_id,privacy_domain_id,partition_id,candidate_sequence,event_id,
    source_profile_id,source_generation_id,fact_generation_id,event_kind,checkpoint_id,
    batch_sequence,batch_digest,predecessor_batch_digest,range_start,range_end,record_ordinal,
    record_count,checkpoint_digest,event_payload_cbor,candidate_id,fact_digest,canonical_provenance,receipt_digest)
  VALUES (p_participant,p_privacy,p_partition,p_sequence,p_event,p_source_profile,p_source_generation,
    p_fact_generation,p_kind,p_checkpoint,p_batch_sequence,p_batch_digest,p_predecessor,
    p_range_start,p_range_end,p_ordinal,p_count,p_checkpoint_digest,p_event_cbor,
    p_candidate,p_fact_digest,p_provenance,receipt);
  RETURN 'APPLIED';
END $$;

CREATE OR REPLACE FUNCTION facts.tombstone_for_source_reorg(
  p_participant text,p_privacy text,p_candidate text,p_partition uuid,p_source_generation text,
  p_event uuid,p_sequence bigint,p_payload_digest bytea,p_action uuid,p_authority bytea,p_cose bytea,
  p_start numeric,p_end numeric,p_nonce bytea,p_mac bytea
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding bytea; prior facts.lineage_outbox%ROWTYPE; fact facts.canonical_fact%ROWTYPE;
  receipt facts.candidate_feed_receipt%ROWTYPE; last_sequence bigint;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  binding:=sha256(facts.capability_field(1,convert_to(p_participant,'UTF8'))||facts.capability_field(2,convert_to(p_privacy,'UTF8'))||
    facts.capability_field(3,convert_to(p_candidate,'UTF8'))||facts.capability_field(4,convert_to(p_partition::text,'UTF8'))||
    facts.capability_field(5,convert_to(p_source_generation,'UTF8'))||facts.capability_field(6,convert_to(p_event::text,'UTF8'))||
    facts.capability_field(7,convert_to(p_sequence::text,'UTF8'))||facts.capability_field(8,p_payload_digest)||
    facts.capability_field(9,convert_to(p_action::text,'UTF8'))||facts.capability_field(10,p_authority)||facts.capability_field(11,sha256(p_cose))||
    facts.capability_field(12,convert_to(p_start::text,'UTF8'))||facts.capability_field(13,convert_to(p_end::text,'UTF8'))||
    facts.capability_field(14,convert_to('REORG','UTF8')));
  PERFORM facts.verify_lineage_capability(binding,p_nonce,p_mac);
  SELECT * INTO prior FROM facts.lineage_outbox WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
    AND source_event_id=p_event AND candidate_id=p_candidate AND event_type='io.openpc.fact.fact.invalidated.v1';
  IF FOUND THEN
    IF prior.partition_id<>p_partition OR prior.source_sequence<>p_sequence OR prior.source_generation_id<>p_source_generation
      OR prior.source_payload_digest<>p_payload_digest OR prior.affected_start<>p_start OR prior.affected_end<>p_end
      OR prior.event_type<>'io.openpc.fact.fact.invalidated.v1' THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_LINEAGE_REPLAY_MISMATCH';
    END IF;
    RETURN false;
  END IF;
  SELECT * INTO STRICT fact FROM facts.canonical_fact WHERE candidate_id=p_candidate
    AND participant_id=p_participant AND privacy_domain_id=p_privacy AND state IN ('ADMITTED','FINALIZED') FOR UPDATE;
  SELECT * INTO STRICT receipt FROM facts.candidate_feed_receipt WHERE candidate_id=p_candidate
    AND participant_id=p_participant AND privacy_domain_id=p_privacy AND partition_id=p_partition
    AND source_generation_id=p_source_generation;
  SELECT max(candidate_sequence) INTO last_sequence FROM facts.candidate_feed_receipt
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND partition_id=p_partition;
  IF p_sequence<>last_sequence+1 OR p_payload_digest IS NULL OR octet_length(p_payload_digest)<>32
    OR uuid_extract_version(p_event)<>7 OR uuid_extract_version(p_action)<>7
    OR p_start IS NULL OR p_end IS NULL OR p_start<1 OR p_end<p_start OR p_end>18446744073709551615
    OR trunc(p_start)<>p_start OR trunc(p_end)<>p_end OR receipt.range_start>p_end OR receipt.range_end<p_start THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_LINEAGE_SEQUENCE_REJECTED';
  END IF;
  INSERT INTO facts.lineage_outbox(lineage_action_id,candidate_id,participant_id,privacy_domain_id,generation_id,
    partition_id,source_generation_id,source_event_id,source_sequence,source_payload_digest,affected_start,affected_end,
    authority_digest,cose_sign1,lineage_digest,event_type)
  VALUES(p_action,p_candidate,p_participant,p_privacy,fact.generation_id,p_partition,p_source_generation,p_event,p_sequence,
    p_payload_digest,p_start,p_end,p_authority,p_cose,sha256(p_cose),'io.openpc.fact.fact.invalidated.v1');
  UPDATE facts.canonical_fact SET state='REORG_TOMBSTONED' WHERE candidate_id=p_candidate;
  INSERT INTO facts.fact_invalidation(candidate_id,participant_id,privacy_domain_id,predecessor_generation_id,reason)
    VALUES(p_candidate,p_participant,p_privacy,fact.generation_id,'REORG');
  UPDATE facts.readiness_gate SET state='REORG',shard_verified=false WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND generation_id=fact.generation_id;
  UPDATE facts.source_checkpoint SET state='REORG_FENCED' WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND source_profile_id=receipt.source_profile_id;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION facts.enforce_fact_state_transition()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
     AND NOT (OLD.state = 'ADMITTED' AND NEW.state = 'FINALIZED'
              AND OLD.finalized_at IS NULL AND NEW.finalized_at IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_FINALIZATION_IMMUTABLE';
  END IF;
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    RETURN NEW;
  END IF;
  IF OLD.state = 'ADMITTED' AND NEW.state = 'FINALIZED' AND NEW.finalized_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF OLD.state IN ('ADMITTED','FINALIZED') AND NEW.state='RETIRED'
     AND NEW.finalized_at IS NOT DISTINCT FROM OLD.finalized_at
     AND EXISTS (SELECT 1 FROM facts.fact_invalidation WHERE candidate_id=OLD.candidate_id
       AND participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
       AND predecessor_generation_id=OLD.generation_id AND reason='RETIREMENT') THEN
    RETURN NEW;
  END IF;
  IF OLD.state='ADMITTED' AND NEW.state='REORG_TOMBSTONED'
     AND NEW.finalized_at IS NOT DISTINCT FROM OLD.finalized_at
     AND EXISTS(SELECT 1 FROM facts.lineage_outbox WHERE candidate_id=OLD.candidate_id
       AND participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
       AND generation_id=OLD.generation_id AND event_type='io.openpc.fact.fact.invalidated.v1') THEN
    RETURN NEW;
  END IF;
  IF OLD.state = 'FINALIZED' AND NEW.state = 'REORG_TOMBSTONED'
     AND NEW.finalized_at IS NOT DISTINCT FROM OLD.finalized_at THEN
    RETURN NEW;
  END IF;
  IF OLD.state = 'REORG_TOMBSTONED' AND NEW.state = 'SUPERSEDED'
     AND NEW.finalized_at IS NOT DISTINCT FROM OLD.finalized_at
     AND EXISTS (
       SELECT 1
         FROM facts.fact_invalidation AS invalidation
         JOIN facts.canonical_fact AS replacement
           ON replacement.candidate_id = invalidation.replacement_candidate_id
          AND replacement.participant_id = invalidation.participant_id
          AND replacement.privacy_domain_id = invalidation.privacy_domain_id
        WHERE invalidation.candidate_id = OLD.candidate_id
          AND invalidation.predecessor_generation_id = OLD.generation_id
          AND invalidation.replacement_candidate_id IS NOT NULL
          AND invalidation.replacement_generation_id = replacement.generation_id
          AND replacement.state = 'FINALIZED'
          AND replacement.complete
          AND replacement.finality_verified
          AND (NOT EXISTS(SELECT 1 FROM facts.canonical_identity_allocation WHERE candidate_id=OLD.candidate_id)
            OR (EXISTS(SELECT 1 FROM facts.readiness_gate WHERE participant_id=OLD.participant_id
              AND privacy_domain_id=OLD.privacy_domain_id AND generation_id=replacement.generation_id
              AND state='READY' AND shard_verified AND shard_cose_sign1 IS NOT NULL)
            AND EXISTS(SELECT 1 FROM facts.lineage_outbox WHERE candidate_id=OLD.candidate_id
              AND participant_id=OLD.participant_id AND privacy_domain_id=OLD.privacy_domain_id
              AND event_type='io.openpc.fact.fact.superseded.v1')))
     ) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_STATE_TRANSITION_REJECTED';
END
$$;

CREATE FUNCTION facts.supersede_verified_reorg_replacement(
  p_participant text,p_privacy text,p_predecessor text,p_replacement text,p_action uuid,
  p_authority bytea,p_cose bytea,p_nonce bytea,p_mac bytea,p_recovery_checkpoint bytea
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  binding bytea;
  prior facts.lineage_outbox%ROWTYPE;
  old_state facts.fact_state;
  recovery bytea;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  binding := sha256(facts.capability_field(1,convert_to(p_participant,'UTF8'))
    || facts.capability_field(2,convert_to(p_privacy,'UTF8'))
    || facts.capability_field(3,convert_to(p_predecessor,'UTF8'))
    || facts.capability_field(4,convert_to(p_replacement,'UTF8'))
    || facts.capability_field(5,convert_to(p_action::text,'UTF8'))
    || facts.capability_field(6,p_authority) || facts.capability_field(7,sha256(p_cose))
    || facts.capability_field(8,convert_to('SUPERSEDE','UTF8'))
    || facts.capability_field(9,sha256(coalesce(p_recovery_checkpoint,''::bytea))));
  PERFORM facts.verify_lineage_capability(binding,p_nonce,p_mac);
  IF uuid_extract_version(p_action)<>7 OR octet_length(p_authority)<>32 OR octet_length(p_cose)<=64
    OR p_predecessor=p_replacement THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_REPLACEMENT_SUPERSESSION_REJECTED';
  END IF;
  SELECT f.state INTO STRICT old_state FROM facts.canonical_fact f
    JOIN facts.fact_invalidation i USING(candidate_id,participant_id,privacy_domain_id)
    JOIN facts.canonical_fact replacement ON replacement.candidate_id=i.replacement_candidate_id
      AND replacement.participant_id=i.participant_id AND replacement.privacy_domain_id=i.privacy_domain_id
    JOIN facts.readiness_gate gate ON gate.participant_id=replacement.participant_id
      AND gate.privacy_domain_id=replacement.privacy_domain_id AND gate.generation_id=replacement.generation_id
    WHERE f.participant_id=p_participant AND f.privacy_domain_id=p_privacy AND f.candidate_id=p_predecessor
      AND i.reason='REORG' AND replacement.candidate_id=p_replacement
      AND i.predecessor_generation_id=f.generation_id AND i.replacement_generation_id=replacement.generation_id
      AND replacement.state='FINALIZED' AND replacement.complete AND replacement.finality_verified
      AND gate.state='READY' AND gate.shard_verified AND gate.shard_cose_sign1 IS NOT NULL
    FOR UPDATE OF f;
  SELECT recovery_cursor_cbor INTO recovery FROM facts.source_checkpoint WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND recovery_generation_id=(SELECT generation_id FROM facts.canonical_fact
      WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND candidate_id=p_replacement);
  IF (recovery IS NULL AND p_recovery_checkpoint IS NOT NULL)
    OR (recovery IS NOT NULL AND ((p_recovery_checkpoint IS NOT NULL) IS DISTINCT FROM
      (SELECT a.delta_sequence=(SELECT count(*) FROM facts.canonical_identity_allocation sibling
        WHERE sibling.participant_id=a.participant_id AND sibling.privacy_domain_id=a.privacy_domain_id AND sibling.generation_id=a.generation_id)
       FROM facts.canonical_identity_allocation a WHERE a.candidate_id=p_replacement AND a.participant_id=p_participant AND a.privacy_domain_id=p_privacy))) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_RECOVERY_CHECKPOINT_REQUIRED';
  END IF;
  IF old_state='SUPERSEDED' AND EXISTS(SELECT 1 FROM facts.lineage_outbox WHERE candidate_id=p_predecessor
    AND participant_id=p_participant AND privacy_domain_id=p_privacy AND event_type='io.openpc.fact.fact.superseded.v1'
    AND lineage_action_id=p_action AND authority_digest=p_authority AND lineage_digest=sha256(p_cose)) THEN
    IF p_recovery_checkpoint IS NOT NULL AND NOT EXISTS(SELECT 1 FROM facts.lineage_outbox WHERE participant_id=p_participant
      AND privacy_domain_id=p_privacy AND candidate_id=p_predecessor AND event_type='io.openpc.fact.gap.resolved.v1'
      AND recovery_cursor_cbor=recovery AND lineage_digest=sha256(p_recovery_checkpoint)) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_RECOVERY_REPLAY_CONFLICT';
    END IF;
    RETURN false;
  END IF;
  IF old_state<>'REORG_TOMBSTONED' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_REPLACEMENT_SUPERSESSION_REJECTED';
  END IF;
  SELECT * INTO STRICT prior FROM facts.lineage_outbox WHERE candidate_id=p_predecessor
    AND participant_id=p_participant AND privacy_domain_id=p_privacy AND event_type='io.openpc.fact.fact.invalidated.v1';
  INSERT INTO facts.lineage_outbox(lineage_action_id,candidate_id,participant_id,privacy_domain_id,generation_id,
    partition_id,source_generation_id,source_event_id,source_sequence,source_payload_digest,affected_start,affected_end,
    authority_digest,cose_sign1,lineage_digest,event_type)
  VALUES(p_action,p_predecessor,p_participant,p_privacy,prior.generation_id,prior.partition_id,prior.source_generation_id,
    prior.source_event_id,prior.source_sequence,prior.source_payload_digest,prior.affected_start,prior.affected_end,
    p_authority,p_cose,sha256(p_cose),'io.openpc.fact.fact.superseded.v1');
  IF p_recovery_checkpoint IS NOT NULL THEN
    INSERT INTO facts.lineage_outbox(lineage_action_id,candidate_id,participant_id,privacy_domain_id,generation_id,
      partition_id,source_generation_id,source_event_id,source_sequence,source_payload_digest,affected_start,affected_end,
      authority_digest,cose_sign1,lineage_digest,event_type,recovery_cursor_cbor)
    VALUES(uuidv7(),p_predecessor,p_participant,p_privacy,prior.generation_id,prior.partition_id,prior.source_generation_id,
      prior.source_event_id,prior.source_sequence,prior.source_payload_digest,prior.affected_start,prior.affected_end,
      p_authority,p_recovery_checkpoint,sha256(p_recovery_checkpoint),'io.openpc.fact.gap.resolved.v1',recovery);
  END IF;
  UPDATE facts.canonical_fact SET state='SUPERSEDED' WHERE candidate_id=p_predecessor
    AND participant_id=p_participant AND privacy_domain_id=p_privacy;
  RETURN true;
END $$;
ALTER FUNCTION facts.supersede_verified_reorg_replacement(text,text,text,text,uuid,bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.supersede_verified_reorg_replacement(text,text,text,text,uuid,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
-- Supersession is invoked only by the atomic verified-publication owner.
REVOKE ALL ON FUNCTION facts.supersede_verified_reorg_replacement(text,text,text,text,uuid,bytea,bytea,bytea,bytea,bytea) FROM openpc_fact_bridge_writer;

-- Legacy callers cannot manufacture complete-record readiness. COM-019 uses
-- the private primitive only inside the complete publication transaction.
ALTER FUNCTION facts.mark_signed_shard_ready(text,text,text,bytea,bytea,bytea,bytea) RENAME TO mark_verified_shard_ready_internal;
REVOKE ALL ON FUNCTION facts.mark_verified_shard_ready_internal(text,text,text,bytea,bytea,bytea,bytea) FROM PUBLIC,openpc_fact_bridge_writer;
CREATE FUNCTION facts.mark_signed_shard_ready(p_participant text,p_privacy text,p_generation text,
  p_digest bytea,p_cose bytea,p_nonce bytea,p_mac bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF EXISTS(SELECT 1 FROM facts.canonical_identity_allocation WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND generation_id=p_generation) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_COM019_REQUIRED';
  END IF;
  RETURN facts.mark_verified_shard_ready_internal(p_participant,p_privacy,p_generation,p_digest,p_cose,p_nonce,p_mac);
END $$;
ALTER FUNCTION facts.mark_signed_shard_ready(text,text,text,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.mark_signed_shard_ready(text,text,text,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.mark_signed_shard_ready(text,text,text,bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;

CREATE FUNCTION facts.commit_verified_publication(p_participant text,p_privacy text,p_generation text,
  p_digest bytea,p_cose bytea,p_nonce bytea,p_mac bytea,p_candidates text[],
  p_predecessors text[],p_actions uuid[],p_authorities bytea[],p_lineages bytea[],p_lineage_nonces bytea[],p_lineage_macs bytea[],p_recovery_checkpoints bytea[])
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE profile text; replacement text; applied boolean; position integer; linked integer;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF cardinality(p_candidates)=0 OR cardinality(p_candidates)<>(SELECT count(DISTINCT id) FROM unnest(p_candidates) id)
    OR cardinality(p_candidates)<>(SELECT count(*) FROM facts.canonical_fact f
      JOIN facts.canonical_identity_allocation a USING(candidate_id,participant_id,privacy_domain_id,generation_id)
      WHERE f.participant_id=p_participant AND f.privacy_domain_id=p_privacy AND f.generation_id=p_generation
        AND f.candidate_id=ANY(p_candidates) AND f.state='FINALIZED' AND f.complete AND f.finality_verified)
    OR cardinality(p_candidates)<>(SELECT count(*) FROM facts.canonical_fact
      WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND generation_id=p_generation)
    OR cardinality(p_predecessors)<>cardinality(p_actions) OR cardinality(p_predecessors)<>cardinality(p_authorities)
    OR cardinality(p_predecessors)<>cardinality(p_lineages) OR cardinality(p_predecessors)<>cardinality(p_lineage_nonces)
    OR cardinality(p_predecessors)<>cardinality(p_lineage_macs) OR cardinality(p_predecessors)<>cardinality(p_recovery_checkpoints)
    OR cardinality(p_predecessors)<>(SELECT count(DISTINCT id) FROM unnest(p_predecessors) id) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_COMPLETE_PUBLICATION_REQUIRED';
  END IF;
  SELECT DISTINCT source_profile_id INTO STRICT profile FROM facts.admission_inbox
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND generation_id=p_generation;
  SELECT count(*) INTO linked FROM facts.fact_invalidation WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND replacement_generation_id=p_generation;
  IF linked<>cardinality(p_predecessors) OR linked<>(SELECT count(*) FROM facts.fact_invalidation
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND replacement_generation_id=p_generation
      AND candidate_id=ANY(p_predecessors) AND replacement_candidate_id=ANY(p_candidates)) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_REPLACEMENT_PUBLICATION_BINDING';
  END IF;
  IF linked>0 THEN
    UPDATE facts.source_checkpoint SET state='COMPLETE' WHERE participant_id=p_participant
      AND privacy_domain_id=p_privacy AND source_profile_id=profile AND state IN ('REORG_FENCED','COMPLETE');
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_RECOVERY_CHECKPOINT_REQUIRED'; END IF;
  ELSIF EXISTS(SELECT 1 FROM facts.source_checkpoint WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
    AND source_profile_id=profile AND state<>'COMPLETE') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_RECOVERY_CHECKPOINT_REQUIRED';
  END IF;
  applied := facts.mark_verified_shard_ready_internal(p_participant,p_privacy,p_generation,p_digest,p_cose,p_nonce,p_mac);
  IF NOT applied THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_VERIFIED_PUBLICATION_REQUIRED'; END IF;
  FOR position IN 1..linked LOOP
    SELECT replacement_candidate_id INTO STRICT replacement FROM facts.fact_invalidation
      WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND candidate_id=p_predecessors[position]
        AND replacement_generation_id=p_generation;
    PERFORM facts.supersede_verified_reorg_replacement(p_participant,p_privacy,p_predecessors[position],replacement,
      p_actions[position],p_authorities[position],p_lineages[position],p_lineage_nonces[position],p_lineage_macs[position],p_recovery_checkpoints[position]);
  END LOOP;
  UPDATE facts.source_checkpoint SET state='COMPLETE' WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND recovery_candidate_id=ANY(p_candidates) AND state='REORG_FENCED';
  RETURN true;
END $$;
ALTER FUNCTION facts.commit_verified_publication(text,text,text,bytea,bytea,bytea,bytea,text[],text[],uuid[],bytea[],bytea[],bytea[],bytea[],bytea[]) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.commit_verified_publication(text,text,text,bytea,bytea,bytea,bytea,text[],text[],uuid[],bytea[],bytea[],bytea[],bytea[],bytea[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.commit_verified_publication(text,text,text,bytea,bytea,bytea,bytea,text[],text[],uuid[],bytea[],bytea[],bytea[],bytea[],bytea[]) TO openpc_fact_bridge_writer;

CREATE FUNCTION facts.authorize_gap_rebootstrap(p_participant text,p_privacy text,p_source text,
  p_predecessor text,p_candidate text,p_cursor bytea,p_checkpoint bytea,p_nonce bytea,p_mac bytea,p_generation text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding bytea; current facts.source_checkpoint%ROWTYPE;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  binding:=sha256(facts.capability_field(1,convert_to(p_participant,'UTF8'))||facts.capability_field(2,convert_to(p_privacy,'UTF8'))
    ||facts.capability_field(3,convert_to(p_source,'UTF8'))||facts.capability_field(4,convert_to(p_predecessor,'UTF8'))
    ||facts.capability_field(5,convert_to(p_candidate,'UTF8'))||facts.capability_field(6,sha256(p_cursor))
    ||facts.capability_field(7,sha256(p_checkpoint))||facts.capability_field(8,convert_to('RECOVER_GAP','UTF8'))
    ||facts.capability_field(9,convert_to(p_generation,'UTF8')));
  PERFORM facts.verify_lineage_capability(binding,p_nonce,p_mac);
  SELECT * INTO STRICT current FROM facts.source_checkpoint WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND source_profile_id=p_source FOR UPDATE;
  IF current.recovery_candidate_id=p_candidate THEN
    IF current.recovery_cursor_cbor<>p_cursor OR current.recovery_checkpoint_cose<>p_checkpoint OR current.recovery_generation_id<>p_generation THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_RECOVERY_REPLAY_CONFLICT';
    END IF;
    RETURN false;
  END IF;
  IF current.state<>'REORG_FENCED' OR current.recovery_candidate_id IS NOT NULL
    OR p_candidate=p_predecessor OR octet_length(p_cursor) NOT BETWEEN 1 AND 131072
    OR octet_length(p_checkpoint) NOT BETWEEN 65 AND 131072
    OR NOT EXISTS(SELECT 1 FROM facts.canonical_fact f JOIN facts.admission_inbox i USING(candidate_id,participant_id,privacy_domain_id)
       JOIN facts.lineage_outbox l USING(candidate_id,participant_id,privacy_domain_id)
       WHERE f.participant_id=p_participant AND f.privacy_domain_id=p_privacy AND f.candidate_id=p_predecessor
         AND f.state='REORG_TOMBSTONED' AND i.source_profile_id=p_source AND l.event_type='io.openpc.fact.fact.invalidated.v1') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_RECOVERY_FENCE_REQUIRED';
  END IF;
  UPDATE facts.source_checkpoint SET recovery_candidate_id=p_candidate,recovery_generation_id=p_generation,recovery_cursor_cbor=p_cursor,recovery_checkpoint_cose=p_checkpoint
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy AND source_profile_id=p_source;
  RETURN true;
END $$;
ALTER FUNCTION facts.authorize_gap_rebootstrap(text,text,text,text,text,bytea,bytea,bytea,bytea,text) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.authorize_gap_rebootstrap(text,text,text,text,text,bytea,bytea,bytea,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.authorize_gap_rebootstrap(text,text,text,text,text,bytea,bytea,bytea,bytea,text) TO openpc_fact_bridge_writer;

-- Public admission operations bind the existing immutable feed effect. No
-- parallel operation/fact table and no readiness assertion is introduced.
ALTER TABLE facts.candidate_feed_receipt
  ADD COLUMN operation_binding jsonb,
  ADD COLUMN operation_outcome text CHECK (operation_outcome IN ('ADMITTED','CONFLICTING')),
  ADD COLUMN operation_bound_at timestamptz(6),
  ADD CONSTRAINT admission_operation_complete CHECK (
    (operation_binding IS NULL AND operation_outcome IS NULL AND operation_bound_at IS NULL)
    OR (operation_binding IS NOT NULL AND operation_outcome IS NOT NULL AND operation_bound_at IS NOT NULL
      AND event_kind='CANDIDATE' AND record_ordinal=1));
CREATE UNIQUE INDEX admission_operation_id ON facts.candidate_feed_receipt
  ((operation_binding->>'operationId')) WHERE operation_binding IS NOT NULL;
CREATE UNIQUE INDEX admission_operation_replay ON facts.candidate_feed_receipt
  (participant_id,privacy_domain_id,(operation_binding->>'principalId'),(operation_binding->>'idempotencyKey'))
  WHERE operation_binding IS NOT NULL;
CREATE FUNCTION facts.guard_feed_operation_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.operation_binding IS NOT NULL OR NEW.operation_binding IS NULL
    OR (to_jsonb(OLD)-ARRAY['operation_binding','operation_outcome','operation_bound_at'])
       IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['operation_binding','operation_outcome','operation_bound_at']) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_FEED_IMMUTABLE';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION facts.guard_feed_operation_binding() FROM PUBLIC;
DROP TRIGGER candidate_feed_receipt_immutable ON facts.candidate_feed_receipt;
CREATE TRIGGER candidate_feed_receipt_immutable BEFORE UPDATE OR DELETE ON facts.candidate_feed_receipt
  FOR EACH ROW EXECUTE FUNCTION facts.guard_feed_operation_binding();
GRANT UPDATE(operation_binding,operation_outcome,operation_bound_at) ON facts.candidate_feed_receipt TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.bind_admission_operation(p_participant text,p_privacy text,p_document text,
  p_outcome text,p_nonce bytea,p_mac bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding jsonb; prior facts.candidate_feed_receipt%ROWTYPE; digest bytea;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  binding:=p_document::jsonb;
  IF NOT coalesce(octet_length(p_document)<=4096 AND jsonb_typeof(binding)='object',false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_OPERATION_INVALID';
  END IF;
  IF NOT coalesce((SELECT count(*) FROM jsonb_object_keys(binding))=6
    AND binding ?& ARRAY['operationId','principalId','candidateId','idempotencyKey','inputDigest','expectedRevision']
    AND (SELECT bool_and(jsonb_typeof(value)='string') FROM jsonb_each(binding))
    AND uuid_extract_version((binding->>'operationId')::uuid)=7
    AND uuid_extract_version((binding->>'principalId')::uuid)=7
    AND uuid_extract_version((binding->>'candidateId')::uuid)=7
    AND binding->>'idempotencyKey' ~ '^[A-Za-z0-9._~-]{16,128}$'
    AND binding->>'inputDigest' ~ '^sha256:[0-9a-f]{64}$'
    AND binding->>'expectedRevision' ~ '^[1-9][0-9]{0,19}$'
    AND (binding->>'expectedRevision')::numeric<=18446744073709551615
    AND p_outcome IN ('ADMITTED','CONFLICTING'),false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_OPERATION_INVALID';
  END IF;
  digest:=sha256(facts.capability_field(1,convert_to(p_participant,'UTF8'))
    ||facts.capability_field(2,convert_to(p_privacy,'UTF8'))
    ||facts.capability_field(3,convert_to(p_document,'UTF8'))
    ||facts.capability_field(4,convert_to(p_outcome,'UTF8'))
    ||facts.capability_field(5,convert_to('FACT_ARTIFACT_OPERATION','UTF8')));
  PERFORM facts.verify_lineage_capability(digest,p_nonce,p_mac);
  PERFORM pg_advisory_xact_lock(hashtextextended('fact-operation:'||p_participant||':'||p_privacy||':'
    ||(binding->>'principalId')||':'||(binding->>'idempotencyKey'),0));
  SELECT * INTO prior FROM facts.candidate_feed_receipt
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
      AND operation_binding->>'principalId'=binding->>'principalId'
      AND operation_binding->>'idempotencyKey'=binding->>'idempotencyKey';
  IF FOUND THEN
    IF (prior.operation_binding-'operationId') IS DISTINCT FROM (binding-'operationId') THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_REPLAY_CONFLICT';
    END IF;
    RETURN (prior.operation_binding->>'operationId')::uuid;
  END IF;
  SELECT * INTO STRICT prior FROM facts.candidate_feed_receipt
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
      AND candidate_id=binding->>'candidateId' AND event_kind='CANDIDATE' AND record_ordinal=1 FOR UPDATE;
  IF prior.candidate_sequence::text<>binding->>'expectedRevision' THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_REPLAY_CONFLICT';
  END IF;
  IF (p_outcome='CONFLICTING') IS DISTINCT FROM EXISTS(
    SELECT 1 FROM facts.semantic_occurrence s JOIN facts.occurrence_conflict c
      USING(participant_id,privacy_domain_id,occurrence_digest)
    WHERE s.participant_id=p_participant AND s.privacy_domain_id=p_privacy
      AND s.candidate_id=binding->>'candidateId') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_OPERATION_INVALID';
  END IF;
  IF prior.operation_binding IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_FEED_REPLAY_CONFLICT';
  END IF;
  UPDATE facts.candidate_feed_receipt SET operation_binding=binding,operation_outcome=p_outcome,
    operation_bound_at=clock_timestamp()
    WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
      AND partition_id=prior.partition_id AND candidate_sequence=prior.candidate_sequence;
  RETURN (binding->>'operationId')::uuid;
END $$;
ALTER FUNCTION facts.bind_admission_operation(text,text,text,text,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.bind_admission_operation(text,text,text,text,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.bind_admission_operation(text,text,text,text,bytea,bytea) TO openpc_fact_bridge_writer;

-- Policy publication reads only scoped signed empty-checkpoint evidence. These
-- receipts extend coverage without creating a membership or modifying history.
CREATE POLICY reader_empty_checkpoint ON facts.candidate_feed_receipt
  FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id) AND record_count=0);
GRANT SELECT (participant_id,privacy_domain_id,partition_id,range_start,record_count,canonical_provenance)
  ON facts.candidate_feed_receipt TO openpc_policy_fact_reader;
