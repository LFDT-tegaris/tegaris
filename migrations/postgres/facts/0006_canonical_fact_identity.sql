-- SQLx-owned canonical IDs and generations. Allocation and admission share one
-- transaction and the existing exclusive policy fence. An allocation cannot
-- commit without its exact admitted fact; old records are never backfilled.
CREATE TABLE facts.canonical_generation (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_profile_id text NOT NULL CHECK (fact_profile_id ~ '^urn:openpc:fact-profile:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  generation_id text NOT NULL,
  canonical_generation numeric(20,0) NOT NULL CHECK (canonical_generation BETWEEN 1 AND 18446744073709551615),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (participant_id,privacy_domain_id,fact_profile_id,generation_id),
  UNIQUE (participant_id,privacy_domain_id,fact_profile_id,canonical_generation)
);
CREATE UNIQUE INDEX canonical_fact_allocation_scope ON facts.canonical_fact
  (candidate_id,participant_id,privacy_domain_id,generation_id);
CREATE TABLE facts.canonical_identity_allocation (
  candidate_id text PRIMARY KEY,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_profile_id text NOT NULL,
  generation_id text NOT NULL,
  fact_id uuid NOT NULL UNIQUE DEFAULT uuidv7(),
  delta_sequence numeric(20,0) NOT NULL CHECK (delta_sequence BETWEEN 1 AND 18446744073709551615),
  admitted_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (participant_id,privacy_domain_id,fact_profile_id,generation_id,delta_sequence),
  FOREIGN KEY (participant_id,privacy_domain_id,fact_profile_id,generation_id)
    REFERENCES facts.canonical_generation(participant_id,privacy_domain_id,fact_profile_id,generation_id) ON DELETE RESTRICT,
  FOREIGN KEY (candidate_id,participant_id,privacy_domain_id,generation_id)
    REFERENCES facts.canonical_fact(candidate_id,participant_id,privacy_domain_id,generation_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER canonical_generation_immutable BEFORE UPDATE OR DELETE ON facts.canonical_generation
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
CREATE TRIGGER canonical_identity_allocation_immutable BEFORE UPDATE OR DELETE ON facts.canonical_identity_allocation
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
ALTER TABLE facts.canonical_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.canonical_generation FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.canonical_identity_allocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.canonical_identity_allocation FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.canonical_generation TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.canonical_identity_allocation TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.canonical_generation FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.canonical_identity_allocation FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.canonical_generation,facts.canonical_identity_allocation FROM PUBLIC;
GRANT SELECT,INSERT ON facts.canonical_generation,facts.canonical_identity_allocation TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.canonical_generation,facts.canonical_identity_allocation TO openpc_fact_bridge_writer,openpc_policy_fact_reader;

ALTER TABLE facts.mutation_capability_replay DROP CONSTRAINT mutation_capability_replay_operation_check,
  ADD CONSTRAINT mutation_capability_replay_operation_check CHECK (operation IN (
    'ADMIT_FACT','FINALIZE_FACT','MARK_SIGNED_SHARD_READY','INVALIDATE_FACT_FOR_REORG',
    'ADMIT_REPLACEMENT','CONSUME_CANDIDATE_FEED','BIND_FACT_OCCURRENCE','ALLOCATE_FACT_IDENTITY'));

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
       'BIND_FACT_OCCURRENCE','ALLOCATE_FACT_IDENTITY'
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

CREATE FUNCTION facts.verify_identity_allocation_capability(binding_digest bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF binding_digest IS NULL OR octet_length(binding_digest)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='OPENPC_FACTSTORE_CAPABILITY_INVALID';
  END IF;
  PERFORM facts.verify_and_consume_mutation_capability('ALLOCATE_FACT_IDENTITY',
    convert_to('OPENPC_FACTSTORE_CANONICAL_IDENTITY_ALLOCATION_V1','UTF8') || binding_digest || nonce,nonce,mac);
END $$;
ALTER FUNCTION facts.verify_identity_allocation_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_identity_allocation_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_identity_allocation_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.allocate_canonical_fact_identity(p_participant text,p_privacy text,p_candidate text,
  p_fact_profile text,p_generation text,p_nonce bytea,p_mac bytea)
RETURNS TABLE(fact_id uuid,canonical_generation text,delta_sequence text,admitted_at text,predecessor_digest bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding bytea; next_generation numeric(20,0); allocated facts.canonical_identity_allocation%ROWTYPE;
BEGIN
  PERFORM facts.assert_lifecycle_context(p_participant,p_privacy);
  IF NOT coalesce(p_candidate ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND p_generation ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND p_fact_profile ~ '^urn:openpc:fact-profile:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',false) THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_IDENTITY_BINDING';
  END IF;
  binding:=sha256(facts.capability_field(1,convert_to(p_participant,'UTF8')) ||
    facts.capability_field(2,convert_to(p_privacy,'UTF8')) || facts.capability_field(3,convert_to(p_candidate,'UTF8')) ||
    facts.capability_field(4,convert_to(p_fact_profile,'UTF8')) || facts.capability_field(5,convert_to(p_generation,'UTF8')));
  PERFORM facts.verify_identity_allocation_capability(binding,p_nonce,p_mac);
  SELECT * INTO allocated FROM facts.canonical_identity_allocation allocation WHERE allocation.candidate_id=p_candidate;
  IF allocated.candidate_id IS NOT NULL THEN
    IF allocated.participant_id<>p_participant OR allocated.privacy_domain_id<>p_privacy
        OR allocated.fact_profile_id<>p_fact_profile OR allocated.generation_id<>p_generation THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_IDENTITY_REPLAY';
    END IF;
  ELSE
    IF EXISTS(SELECT 1 FROM facts.canonical_fact fact WHERE fact.candidate_id=p_candidate) THEN
      RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OPENPC_FACT_IDENTITY_NO_BACKFILL';
    END IF;
    SELECT generation.canonical_generation INTO next_generation FROM facts.canonical_generation generation
      WHERE generation.participant_id=p_participant AND generation.privacy_domain_id=p_privacy
        AND generation.fact_profile_id=p_fact_profile AND generation.generation_id=p_generation;
    IF next_generation IS NULL THEN
      SELECT coalesce(max(generation.canonical_generation),0)+1 INTO next_generation FROM facts.canonical_generation generation
        WHERE generation.participant_id=p_participant AND generation.privacy_domain_id=p_privacy
          AND generation.fact_profile_id=p_fact_profile;
      INSERT INTO facts.canonical_generation(participant_id,privacy_domain_id,fact_profile_id,generation_id,canonical_generation)
        VALUES(p_participant,p_privacy,p_fact_profile,p_generation,next_generation);
    END IF;
    INSERT INTO facts.canonical_identity_allocation(candidate_id,participant_id,privacy_domain_id,fact_profile_id,generation_id,delta_sequence)
      SELECT p_candidate,p_participant,p_privacy,p_fact_profile,p_generation,coalesce(max(allocation.delta_sequence),0)+1
      FROM facts.canonical_identity_allocation allocation WHERE allocation.participant_id=p_participant
        AND allocation.privacy_domain_id=p_privacy AND allocation.fact_profile_id=p_fact_profile AND allocation.generation_id=p_generation
      RETURNING * INTO allocated;
  END IF;
  RETURN QUERY SELECT allocated.fact_id,generation.canonical_generation::text,allocated.delta_sequence::text,
    to_char(allocated.admitted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    (SELECT fact.fact_digest FROM facts.canonical_identity_allocation previous
      JOIN facts.canonical_fact fact ON fact.candidate_id=previous.candidate_id
      WHERE previous.participant_id=p_participant AND previous.privacy_domain_id=p_privacy
        AND previous.fact_profile_id=p_fact_profile AND previous.generation_id=p_generation
        AND previous.delta_sequence=allocated.delta_sequence-1)
    FROM facts.canonical_generation generation
    WHERE generation.participant_id=p_participant AND generation.privacy_domain_id=p_privacy
      AND generation.fact_profile_id=p_fact_profile AND generation.generation_id=p_generation;
END $$;
ALTER FUNCTION facts.allocate_canonical_fact_identity(text,text,text,text,text,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.allocate_canonical_fact_identity(text,text,text,text,text,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.allocate_canonical_fact_identity(text,text,text,text,text,bytea,bytea) TO openpc_fact_bridge_writer;
