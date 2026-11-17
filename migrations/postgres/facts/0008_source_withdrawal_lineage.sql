-- SQLx-owned durable source withdrawal: signed lineage, readiness and
-- delivery fencing commit before replacement admission can continue.
ALTER TABLE facts.mutation_capability_replay DROP CONSTRAINT mutation_capability_replay_operation_check,
  ADD CONSTRAINT mutation_capability_replay_operation_check CHECK (operation IN (
    'ADMIT_FACT','FINALIZE_FACT','MARK_SIGNED_SHARD_READY','INVALIDATE_FACT_FOR_REORG',
    'ADMIT_REPLACEMENT','CONSUME_CANDIDATE_FEED','BIND_FACT_OCCURRENCE','ALLOCATE_FACT_IDENTITY','APPLY_FACT_LINEAGE'));

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
       'CONSUME_CANDIDATE_FEED',
       'BIND_FACT_OCCURRENCE','ALLOCATE_FACT_IDENTITY','APPLY_FACT_LINEAGE'
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

CREATE TABLE facts.lineage_outbox (
  lineage_action_id uuid PRIMARY KEY,
  candidate_id text NOT NULL REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  partition_id uuid NOT NULL,
  source_generation_id text NOT NULL,
  source_event_id uuid NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence>0),
  source_payload_digest bytea NOT NULL CHECK (octet_length(source_payload_digest)=32),
  affected_start numeric(20,0) NOT NULL,
  affected_end numeric(20,0) NOT NULL CHECK (affected_end>=affected_start),
  authority_digest bytea NOT NULL CHECK (octet_length(authority_digest)=32),
  cose_sign1 bytea NOT NULL CHECK (octet_length(cose_sign1)>64),
  lineage_digest bytea NOT NULL CHECK (lineage_digest=sha256(cose_sign1)),
  event_type text NOT NULL DEFAULT 'io.openpc.fact.fact.retired.v1'
    CHECK (event_type='io.openpc.fact.fact.retired.v1'),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(participant_id,privacy_domain_id,source_event_id,candidate_id),
  UNIQUE(participant_id,privacy_domain_id,partition_id,source_sequence,candidate_id)
);
ALTER TABLE facts.lineage_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.lineage_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.lineage_outbox TO openpc_facts_lifecycle_owner
  USING(facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK(facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.lineage_outbox FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING(facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.lineage_outbox FROM PUBLIC;
GRANT SELECT,INSERT ON facts.lineage_outbox TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.lineage_outbox TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
CREATE TRIGGER lineage_outbox_immutable BEFORE UPDATE OR DELETE ON facts.lineage_outbox
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();

-- Retirement may happen between admission and publication. It must not invent
-- a finalization time just to satisfy the original terminal-state constraint.
DO $$ DECLARE target name; BEGIN
  SELECT conname INTO STRICT target FROM pg_constraint WHERE conrelid='facts.canonical_fact'::regclass
    AND contype='c' AND pg_get_constraintdef(oid) LIKE '%finalized_at%' AND pg_get_constraintdef(oid) LIKE '%ADMITTED%';
  EXECUTE format('ALTER TABLE facts.canonical_fact DROP CONSTRAINT %I',target);
END $$;
ALTER TABLE facts.canonical_fact ADD CONSTRAINT canonical_fact_finalization_state
  CHECK (state IN ('ADMITTED','RETIRED') OR finalized_at IS NOT NULL);

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
     ) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_STATE_TRANSITION_REJECTED';
END
$$;

CREATE FUNCTION facts.verify_lineage_capability(binding_digest bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF binding_digest IS NULL OR octet_length(binding_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  PERFORM facts.verify_and_consume_mutation_capability('APPLY_FACT_LINEAGE',
    convert_to('OPENPC_FACTSTORE_SIGNED_LINEAGE_V1','UTF8')||binding_digest||nonce,nonce,mac);
END $$;
ALTER FUNCTION facts.verify_lineage_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_lineage_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_lineage_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.retire_for_source_withdrawal(
  p_participant text,p_privacy text,p_candidate text,p_partition uuid,p_source_generation text,
  p_event uuid,p_sequence bigint,p_payload_digest bytea,p_action uuid,p_authority bytea,p_cose bytea,p_nonce bytea,p_mac bytea
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding bytea; prior facts.lineage_outbox%ROWTYPE; fact facts.canonical_fact%ROWTYPE;
  receipt facts.candidate_feed_receipt%ROWTYPE; last_sequence bigint;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  binding:=sha256(facts.capability_field(1,convert_to(p_participant,'UTF8'))||facts.capability_field(2,convert_to(p_privacy,'UTF8'))||
    facts.capability_field(3,convert_to(p_candidate,'UTF8'))||facts.capability_field(4,convert_to(p_partition::text,'UTF8'))||
    facts.capability_field(5,convert_to(p_source_generation,'UTF8'))||facts.capability_field(6,convert_to(p_event::text,'UTF8'))||
    facts.capability_field(7,convert_to(p_sequence::text,'UTF8'))||facts.capability_field(8,p_payload_digest)||
    facts.capability_field(9,convert_to(p_action::text,'UTF8'))||facts.capability_field(10,p_authority)||facts.capability_field(11,sha256(p_cose)));
  PERFORM facts.verify_lineage_capability(binding,p_nonce,p_mac);
  SELECT * INTO prior FROM facts.lineage_outbox WHERE participant_id=p_participant AND privacy_domain_id=p_privacy
    AND source_event_id=p_event AND candidate_id=p_candidate;
  IF FOUND THEN
    IF prior.partition_id<>p_partition OR prior.source_sequence<>p_sequence OR prior.source_generation_id<>p_source_generation
      OR prior.source_payload_digest<>p_payload_digest THEN
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
    OR uuid_extract_version(p_event)<>7 OR uuid_extract_version(p_action)<>7 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_LINEAGE_SEQUENCE_REJECTED';
  END IF;
  INSERT INTO facts.fact_invalidation(candidate_id,participant_id,privacy_domain_id,predecessor_generation_id,reason)
    VALUES(p_candidate,p_participant,p_privacy,fact.generation_id,'RETIREMENT');
  UPDATE facts.canonical_fact SET state='RETIRED' WHERE candidate_id=p_candidate;
  UPDATE facts.readiness_gate SET state='STALE',shard_verified=false WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND generation_id=fact.generation_id;
  UPDATE facts.source_checkpoint SET state='GAP_BLOCKED' WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND source_profile_id=receipt.source_profile_id;
  INSERT INTO facts.lineage_outbox(lineage_action_id,candidate_id,participant_id,privacy_domain_id,generation_id,
    partition_id,source_generation_id,source_event_id,source_sequence,source_payload_digest,affected_start,affected_end,
    authority_digest,cose_sign1,lineage_digest)
  VALUES(p_action,p_candidate,p_participant,p_privacy,fact.generation_id,p_partition,p_source_generation,p_event,p_sequence,
    p_payload_digest,receipt.range_start,receipt.range_end,p_authority,p_cose,sha256(p_cose));
  RETURN true;
END $$;
ALTER FUNCTION facts.retire_for_source_withdrawal(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.retire_for_source_withdrawal(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.retire_for_source_withdrawal(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;

-- SQLx-owned correction: retirement is distinct from reorg replacement.
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
       OR replacement.state <> 'FINALIZED'
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

