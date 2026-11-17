-- SQLx-owned additive delivery receipts. Candidate outbox order includes
-- checkpoint events and is deliberately distinct from signed fact sequence.
CREATE TABLE facts.candidate_feed_receipt (
  participant_id text NOT NULL CHECK (length(participant_id) BETWEEN 1 AND 256),
  privacy_domain_id text NOT NULL CHECK (length(privacy_domain_id) BETWEEN 1 AND 256),
  partition_id uuid NOT NULL,
  candidate_sequence bigint NOT NULL CHECK (candidate_sequence > 0),
  event_id uuid NOT NULL,
  source_profile_id text NOT NULL CHECK (length(source_profile_id) BETWEEN 1 AND 256),
  source_generation_id text NOT NULL CHECK (length(source_generation_id) BETWEEN 1 AND 256),
  fact_generation_id text NOT NULL CHECK (length(fact_generation_id) BETWEEN 1 AND 256),
  event_kind text NOT NULL CHECK (event_kind IN ('CANDIDATE','CHECKPOINT')),
  checkpoint_id uuid NOT NULL,
  batch_sequence bigint NOT NULL CHECK (batch_sequence > 0),
  batch_digest bytea NOT NULL CHECK (octet_length(batch_digest)=32),
  predecessor_batch_digest bytea CHECK (octet_length(predecessor_batch_digest)=32),
  range_start numeric(20,0) NOT NULL CHECK (range_start BETWEEN 0 AND 18446744073709551615),
  range_end numeric(20,0) NOT NULL CHECK (range_end BETWEEN range_start AND 18446744073709551615),
  record_ordinal bigint NOT NULL CHECK (record_ordinal > 0),
  record_count bigint NOT NULL CHECK (record_count > 0),
  checkpoint_digest bytea NOT NULL CHECK (octet_length(checkpoint_digest)=32),
  event_payload_cbor bytea NOT NULL CHECK (octet_length(event_payload_cbor) BETWEEN 1 AND 131072),
  candidate_id text REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  fact_digest bytea CHECK (octet_length(fact_digest)=32),
  canonical_provenance bytea CHECK (octet_length(canonical_provenance) BETWEEN 1 AND 131072),
  receipt_digest bytea NOT NULL CHECK (octet_length(receipt_digest)=32),
  committed_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (participant_id,privacy_domain_id,partition_id,candidate_sequence),
  UNIQUE (participant_id,privacy_domain_id,event_id),
  UNIQUE (candidate_id),
  CHECK ((event_kind='CANDIDATE' AND candidate_id IS NOT NULL AND fact_digest IS NOT NULL
          AND canonical_provenance IS NOT NULL AND record_ordinal<=record_count)
      OR (event_kind='CHECKPOINT' AND candidate_id IS NULL AND fact_digest IS NULL
          AND canonical_provenance IS NULL AND record_ordinal=record_count+1))
);
CREATE INDEX candidate_feed_generation ON facts.candidate_feed_receipt
  (participant_id,privacy_domain_id,fact_generation_id,partition_id,candidate_sequence);
CREATE TRIGGER candidate_feed_receipt_immutable BEFORE UPDATE OR DELETE
  ON facts.candidate_feed_receipt FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
ALTER TABLE facts.candidate_feed_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.candidate_feed_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.candidate_feed_receipt TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id))
  WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY writer_read_context ON facts.candidate_feed_receipt FOR SELECT TO openpc_fact_bridge_writer
  USING (facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.candidate_feed_receipt FROM PUBLIC;
GRANT SELECT,INSERT ON facts.candidate_feed_receipt TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.candidate_feed_receipt TO openpc_fact_bridge_writer;

ALTER TABLE facts.mutation_capability_replay
  DROP CONSTRAINT mutation_capability_replay_operation_check,
  ADD CONSTRAINT mutation_capability_replay_operation_check CHECK (operation IN (
    'ADMIT_FACT','FINALIZE_FACT','MARK_SIGNED_SHARD_READY','INVALIDATE_FACT_FOR_REORG',
    'ADMIT_REPLACEMENT','CONSUME_CANDIDATE_FEED'));

CREATE OR REPLACE FUNCTION facts.verify_and_consume_mutation_capability(
  requested_operation text,
  requested_preimage bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  verifier_secret bytea;
  expected_mac bytea;
  mismatch integer := 0;
  byte_index integer;
BEGIN
  IF requested_operation NOT IN (
       'ADMIT_FACT',
       'FINALIZE_FACT',
       'MARK_SIGNED_SHARD_READY',
       'INVALIDATE_FACT_FOR_REORG',
       'ADMIT_REPLACEMENT',
       'CONSUME_CANDIDATE_FEED'
     )
     OR requested_preimage IS NULL
     OR requested_capability_nonce IS NULL
     OR requested_capability_mac IS NULL
     OR pg_catalog.octet_length(requested_capability_nonce) <> 32
     OR pg_catalog.octet_length(requested_capability_mac) <> 32 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  SELECT secret.verifier_secret INTO verifier_secret
    FROM facts.mutation_capability_secret AS secret
   WHERE secret.secret_version = 1;
  IF verifier_secret IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACTSTORE_CAPABILITY_SECRET_UNAVAILABLE';
  END IF;
  expected_mac := public.hmac(requested_preimage, verifier_secret, 'sha256');
  FOR byte_index IN 0..31 LOOP
    mismatch := mismatch | (
      pg_catalog.get_byte(expected_mac, byte_index)
      # pg_catalog.get_byte(requested_capability_mac, byte_index)
    );
  END LOOP;
  IF mismatch <> 0 THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  BEGIN
    INSERT INTO facts.mutation_capability_replay
      (capability_nonce, operation, capability_mac)
    VALUES
      (requested_capability_nonce, requested_operation, requested_capability_mac);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACTSTORE_CAPABILITY_REPLAY';
  END;
END
$$;


CREATE FUNCTION facts.verify_candidate_feed_capability(receipt_digest bytea, nonce bytea, mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF receipt_digest IS NULL OR octet_length(receipt_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  PERFORM facts.verify_and_consume_mutation_capability('CONSUME_CANDIDATE_FEED',
    convert_to('OPENPC_FACTSTORE_CANDIDATE_FEED_RECEIPT_V1','UTF8') || receipt_digest || nonce,
    nonce,mac);
END $$;
ALTER FUNCTION facts.verify_candidate_feed_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_candidate_feed_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_candidate_feed_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.consume_candidate_feed_event(
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
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF NOT coalesce(p_partition IS NOT NULL AND p_event IS NOT NULL AND p_checkpoint IS NOT NULL
    AND uuid_extract_version(p_partition)=7 AND uuid_extract_version(p_event)=7
    AND uuid_extract_version(p_checkpoint)=7
    AND p_sequence>0 AND p_batch_sequence>0 AND p_ordinal>0 AND p_count>0
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
  IF prior.candidate_sequence IS NULL THEN
    IF p_sequence<>1 OR p_batch_sequence<>1 OR p_ordinal<>1
       OR p_kind<>'CANDIDATE' OR p_predecessor IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_GAP';
    END IF;
  ELSE
    IF p_sequence<>prior.candidate_sequence+1 OR p_source_profile<>prior.source_profile_id
       OR p_source_generation<>prior.source_generation_id THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_GAP';
    END IF;
    IF prior.event_kind='CHECKPOINT' THEN
      IF p_kind<>'CANDIDATE' OR p_ordinal<>1 OR p_batch_sequence<>prior.batch_sequence+1
         OR p_predecessor IS DISTINCT FROM prior.batch_digest
         OR p_range_start<>prior.range_end+1 OR p_checkpoint=prior.checkpoint_id
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
ALTER FUNCTION facts.consume_candidate_feed_event(text,text,uuid,bigint,uuid,text,text,text,text,uuid,
  bigint,bytea,bytea,numeric,numeric,bigint,bigint,bytea,bytea,text,bytea,bytea,bytea,bytea)
  OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.consume_candidate_feed_event(text,text,uuid,bigint,uuid,text,text,text,text,uuid,
  bigint,bytea,bytea,numeric,numeric,bigint,bigint,bytea,bytea,text,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.consume_candidate_feed_event(text,text,uuid,bigint,uuid,text,text,text,text,uuid,
  bigint,bytea,bytea,numeric,numeric,bigint,bigint,bytea,bytea,text,bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.capability_field(integer,bytea) TO openpc_facts_lifecycle_owner;

-- Existing legacy facts remain readable after an additive upgrade. A generation
-- consuming real feed receipts additionally requires every closing checkpoint.
CREATE FUNCTION facts.enforce_candidate_feed_readiness()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.state='READY' AND EXISTS (SELECT 1 FROM facts.candidate_feed_receipt
       WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
         AND fact_generation_id=NEW.generation_id) THEN
    IF EXISTS (SELECT 1 FROM facts.candidate_feed_receipt r
         WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
           AND r.fact_generation_id=NEW.generation_id AND r.event_kind='CANDIDATE'
           AND NOT EXISTS (SELECT 1 FROM facts.candidate_feed_receipt c
             WHERE c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
               AND c.partition_id=r.partition_id AND c.checkpoint_id=r.checkpoint_id
               AND c.event_kind='CHECKPOINT'))
       OR EXISTS (SELECT 1 FROM facts.canonical_fact f
         WHERE f.participant_id=NEW.participant_id AND f.privacy_domain_id=NEW.privacy_domain_id
           AND f.generation_id=NEW.generation_id AND NOT EXISTS (
             SELECT 1 FROM facts.candidate_feed_receipt r WHERE r.candidate_id=f.candidate_id)) THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_FEED_INCOMPLETE';
    END IF;
  END IF;
  RETURN NEW;
END $$;
ALTER FUNCTION facts.enforce_candidate_feed_readiness() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.enforce_candidate_feed_readiness() FROM PUBLIC;
CREATE TRIGGER candidate_feed_readiness BEFORE INSERT OR UPDATE ON facts.readiness_gate
  FOR EACH ROW EXECUTE FUNCTION facts.enforce_candidate_feed_readiness();
