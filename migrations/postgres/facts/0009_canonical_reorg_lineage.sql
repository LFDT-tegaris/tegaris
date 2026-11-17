-- SQLx-owned verified reorg tombstones. Signed history and admission receipts
-- remain immutable; replacement is a later, separately authorized operation.
ALTER TABLE facts.lineage_outbox DROP CONSTRAINT lineage_outbox_event_type_check,
  ADD CONSTRAINT lineage_outbox_event_type_check CHECK(event_type IN
    ('io.openpc.fact.fact.retired.v1','io.openpc.fact.fact.invalidated.v1'));
ALTER TABLE facts.canonical_fact DROP CONSTRAINT canonical_fact_finalization_state,
  ADD CONSTRAINT canonical_fact_finalization_state
    CHECK(state IN ('ADMITTED','RETIRED','REORG_TOMBSTONED') OR finalized_at IS NOT NULL);

CREATE FUNCTION facts.tombstone_for_source_reorg(
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
    AND source_event_id=p_event AND candidate_id=p_candidate;
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
ALTER FUNCTION facts.tombstone_for_source_reorg(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,numeric,numeric,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.tombstone_for_source_reorg(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,numeric,numeric,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.tombstone_for_source_reorg(text,text,text,uuid,text,uuid,bigint,bytea,uuid,bytea,bytea,numeric,numeric,bytea,bytea) TO openpc_fact_bridge_writer;

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
     ) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_STATE_TRANSITION_REJECTED';
END
$$;

CREATE OR REPLACE FUNCTION facts.invalidate_fact_for_reorg(
  requested_participant text,
  requested_privacy_domain text,
  requested_candidate_id text,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  predecessor_generation text;
BEGIN
  PERFORM facts.assert_lifecycle_context(requested_participant, requested_privacy_domain);
  PERFORM facts.verify_invalidate_capability(
    requested_participant, requested_privacy_domain, requested_candidate_id,
    requested_capability_nonce, requested_capability_mac
  );
  -- The legacy tuple helper cannot bypass complete signed source lineage.
  IF EXISTS(SELECT 1 FROM facts.canonical_identity_allocation WHERE candidate_id=requested_candidate_id
    AND participant_id=requested_participant AND privacy_domain_id=requested_privacy_domain) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='OPENPC_FACT_SIGNED_INVALIDATION_REQUIRED';
  END IF;
  UPDATE facts.canonical_fact
     SET state = 'REORG_TOMBSTONED'
   WHERE candidate_id = requested_candidate_id
     AND participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND state = 'FINALIZED'
  RETURNING generation_id INTO predecessor_generation;
  IF predecessor_generation IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_INVALIDATION_TRANSITION_REJECTED';
  END IF;
  INSERT INTO facts.fact_invalidation
    (candidate_id, participant_id, privacy_domain_id, predecessor_generation_id, reason)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     predecessor_generation, 'REORG');
  UPDATE facts.readiness_gate
     SET state = 'REORG'
   WHERE participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND generation_id = predecessor_generation;
  RETURN predecessor_generation;
END
$$;
