-- SQLx-owned occurrence/conflict custody. Signed historical fact bytes are
-- immutable; conflict is an independent, terminal eligibility fence.
CREATE TABLE facts.semantic_occurrence (
  candidate_id text PRIMARY KEY REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  occurrence_cbor bytea NOT NULL CHECK (octet_length(occurrence_cbor) BETWEEN 1 AND 131072),
  occurrence_digest bytea NOT NULL CHECK (octet_length(occurrence_digest)=32 AND occurrence_digest=sha256(occurrence_cbor)),
  value_digest bytea NOT NULL CHECK (octet_length(value_digest)=32),
  fact_digest bytea NOT NULL CHECK (octet_length(fact_digest)=32),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX semantic_occurrence_lookup ON facts.semantic_occurrence
  (participant_id,privacy_domain_id,occurrence_digest);
CREATE TABLE facts.occurrence_conflict (
  conflict_id uuid PRIMARY KEY DEFAULT uuidv7(),
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  occurrence_digest bytea NOT NULL CHECK (octet_length(occurrence_digest)=32),
  first_candidate_id text NOT NULL REFERENCES facts.semantic_occurrence(candidate_id) ON DELETE RESTRICT,
  conflicting_candidate_id text NOT NULL REFERENCES facts.semantic_occurrence(candidate_id) ON DELETE RESTRICT,
  evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest)=32),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (participant_id,privacy_domain_id,occurrence_digest),
  CHECK (first_candidate_id<>conflicting_candidate_id)
);
CREATE TABLE facts.occurrence_conflict_outbox (
  conflict_id uuid PRIMARY KEY REFERENCES facts.occurrence_conflict(conflict_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest)=32),
  delivery_state text NOT NULL DEFAULT 'PENDING' CHECK (delivery_state IN ('PENDING','DELIVERED','QUARANTINED')),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER semantic_occurrence_immutable BEFORE UPDATE OR DELETE ON facts.semantic_occurrence
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
CREATE TRIGGER occurrence_conflict_immutable BEFORE UPDATE OR DELETE ON facts.occurrence_conflict
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
ALTER TABLE facts.semantic_occurrence ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.semantic_occurrence FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.occurrence_conflict ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.occurrence_conflict FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.occurrence_conflict_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.occurrence_conflict_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.semantic_occurrence TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.occurrence_conflict TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.occurrence_conflict_outbox TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.semantic_occurrence FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.occurrence_conflict FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.occurrence_conflict_outbox FOR SELECT TO openpc_fact_bridge_writer
  USING (facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.semantic_occurrence,facts.occurrence_conflict,facts.occurrence_conflict_outbox FROM PUBLIC;
GRANT SELECT,INSERT ON facts.semantic_occurrence,facts.occurrence_conflict,facts.occurrence_conflict_outbox TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.semantic_occurrence,facts.occurrence_conflict TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
GRANT SELECT ON facts.occurrence_conflict_outbox TO openpc_fact_bridge_writer;
GRANT SELECT ON facts.candidate_feed_receipt TO openpc_policy_fact_reader;
CREATE POLICY policy_read_context ON facts.candidate_feed_receipt FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));

ALTER TABLE facts.mutation_capability_replay DROP CONSTRAINT mutation_capability_replay_operation_check,
  ADD CONSTRAINT mutation_capability_replay_operation_check CHECK (operation IN (
    'ADMIT_FACT','FINALIZE_FACT','MARK_SIGNED_SHARD_READY','INVALIDATE_FACT_FOR_REORG',
    'ADMIT_REPLACEMENT','CONSUME_CANDIDATE_FEED','BIND_FACT_OCCURRENCE'));

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
       'BIND_FACT_OCCURRENCE'
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

CREATE FUNCTION facts.verify_fact_occurrence_capability(binding_digest bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF binding_digest IS NULL OR octet_length(binding_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  PERFORM facts.verify_and_consume_mutation_capability('BIND_FACT_OCCURRENCE',
    convert_to('OPENPC_FACTSTORE_FACT_OCCURRENCE_V1','UTF8') || binding_digest || nonce,nonce,mac);
END $$;
ALTER FUNCTION facts.verify_fact_occurrence_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_fact_occurrence_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_fact_occurrence_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.bind_fact_occurrence(p_participant text,p_privacy text,p_candidate text,
  p_fact_digest bytea,p_occurrence_cbor bytea,p_value_digest bytea,p_nonce bytea,p_mac bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  occurrence bytea := sha256(p_occurrence_cbor);
  binding bytea;
  fact facts.canonical_fact%ROWTYPE;
  prior facts.semantic_occurrence%ROWTYPE;
  witness facts.semantic_occurrence%ROWTYPE;
  conflict facts.occurrence_conflict%ROWTYPE;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF NOT coalesce(octet_length(p_occurrence_cbor) BETWEEN 1 AND 131072
       AND octet_length(p_value_digest)=32 AND octet_length(p_fact_digest)=32,false) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_OCCURRENCE_BINDING';
  END IF;
  binding := sha256(facts.capability_field(1,convert_to(p_participant,'UTF8')) ||
    facts.capability_field(2,convert_to(p_privacy,'UTF8')) ||
    facts.capability_field(3,convert_to(p_candidate,'UTF8')) ||
    facts.capability_field(4,p_fact_digest) || facts.capability_field(5,occurrence) ||
    facts.capability_field(6,p_value_digest));
  PERFORM facts.verify_fact_occurrence_capability(binding,p_nonce,p_mac);
  SELECT f.* INTO fact FROM facts.canonical_fact f
    JOIN facts.candidate_feed_receipt r ON r.candidate_id=f.candidate_id
      AND r.participant_id=f.participant_id AND r.privacy_domain_id=f.privacy_domain_id
    WHERE f.candidate_id=p_candidate AND f.participant_id=p_participant AND f.privacy_domain_id=p_privacy
      AND f.fact_digest=p_fact_digest AND r.fact_digest=p_fact_digest;
  IF fact.candidate_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_OCCURRENCE_BINDING';
  END IF;
  SELECT * INTO prior FROM facts.semantic_occurrence WHERE candidate_id=p_candidate;
  IF prior.candidate_id IS NOT NULL THEN
    IF prior.occurrence_cbor<>p_occurrence_cbor OR prior.value_digest<>p_value_digest
        OR prior.fact_digest<>p_fact_digest THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_OCCURRENCE_REPLAY';
    END IF;
  ELSE
    INSERT INTO facts.semantic_occurrence(candidate_id,participant_id,privacy_domain_id,generation_id,
      occurrence_cbor,occurrence_digest,value_digest,fact_digest)
    VALUES(p_candidate,p_participant,p_privacy,fact.generation_id,p_occurrence_cbor,occurrence,p_value_digest,p_fact_digest);
  END IF;
  SELECT * INTO conflict FROM facts.occurrence_conflict WHERE participant_id=p_participant
    AND privacy_domain_id=p_privacy AND occurrence_digest=occurrence;
  IF conflict.conflict_id IS NULL THEN
    SELECT * INTO witness FROM facts.semantic_occurrence WHERE participant_id=p_participant
      AND privacy_domain_id=p_privacy AND occurrence_digest=occurrence AND value_digest<>p_value_digest
      ORDER BY candidate_id LIMIT 1;
    IF witness.candidate_id IS NOT NULL THEN
      INSERT INTO facts.occurrence_conflict(participant_id,privacy_domain_id,occurrence_digest,
        first_candidate_id,conflicting_candidate_id,evidence_digest)
      VALUES(p_participant,p_privacy,occurrence,witness.candidate_id,p_candidate,
        sha256(convert_to('OPENPC_FACT_OCCURRENCE_CONFLICT_V1','UTF8') || occurrence || witness.fact_digest || p_fact_digest))
      RETURNING * INTO conflict;
      INSERT INTO facts.occurrence_conflict_outbox(conflict_id,participant_id,privacy_domain_id,evidence_digest)
      VALUES(conflict.conflict_id,p_participant,p_privacy,conflict.evidence_digest);
    END IF;
  END IF;
  IF conflict.conflict_id IS NOT NULL THEN
    UPDATE facts.readiness_gate gate SET state='FAILED',shard_verified=false
      WHERE gate.participant_id=p_participant AND gate.privacy_domain_id=p_privacy
        AND EXISTS (SELECT 1 FROM facts.semantic_occurrence s WHERE s.participant_id=p_participant
          AND s.privacy_domain_id=p_privacy AND s.occurrence_digest=occurrence AND s.generation_id=gate.generation_id);
    RETURN true;
  END IF;
  RETURN false;
END $$;
ALTER FUNCTION facts.bind_fact_occurrence(text,text,text,bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.bind_fact_occurrence(text,text,text,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.bind_fact_occurrence(text,text,text,bytea,bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;

-- The terminal fence covers every generation sharing the occurrence. A new
-- delivery or a previously signed shard cannot restore contradictory authority.
CREATE FUNCTION facts.enforce_occurrence_readiness()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.state='READY' AND (
    EXISTS (SELECT 1 FROM facts.semantic_occurrence s JOIN facts.occurrence_conflict c
      ON c.participant_id=s.participant_id AND c.privacy_domain_id=s.privacy_domain_id
        AND c.occurrence_digest=s.occurrence_digest
      WHERE s.participant_id=NEW.participant_id AND s.privacy_domain_id=NEW.privacy_domain_id AND s.generation_id=NEW.generation_id)
    OR EXISTS (SELECT 1 FROM facts.candidate_feed_receipt r WHERE r.participant_id=NEW.participant_id
      AND r.privacy_domain_id=NEW.privacy_domain_id AND r.fact_generation_id=NEW.generation_id
      AND r.event_kind='CANDIDATE' AND NOT EXISTS (SELECT 1 FROM facts.semantic_occurrence s WHERE s.candidate_id=r.candidate_id))) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_OCCURRENCE_NOT_READY';
  END IF;
  RETURN NEW;
END $$;
ALTER FUNCTION facts.enforce_occurrence_readiness() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.enforce_occurrence_readiness() FROM PUBLIC;
CREATE TRIGGER occurrence_readiness BEFORE INSERT OR UPDATE ON facts.readiness_gate
  FOR EACH ROW EXECUTE FUNCTION facts.enforce_occurrence_readiness();

-- An upgrade cannot invent missing independent occurrence proofs. Preserve
-- existing receipts and signatures, but fence previously ready feed generations.
UPDATE facts.readiness_gate gate SET state='BLOCKED',shard_verified=false
WHERE gate.state='READY' AND EXISTS (SELECT 1 FROM facts.candidate_feed_receipt r
  WHERE r.participant_id=gate.participant_id AND r.privacy_domain_id=gate.privacy_domain_id
    AND r.fact_generation_id=gate.generation_id);
