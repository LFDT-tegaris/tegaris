-- OPENPC I05 Gate3 SQLx-owned, SQL-first Fact Bridge integrity schema.
-- Local PostgreSQL 18.6 proof only; production migration/activation remains separately gated.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
CREATE SCHEMA facts;
REVOKE ALL ON SCHEMA facts FROM PUBLIC;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openpc_facts_lifecycle_owner') THEN
    CREATE ROLE openpc_facts_lifecycle_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openpc_facts_capability_owner') THEN
    CREATE ROLE openpc_facts_capability_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openpc_fact_bridge_writer') THEN
    CREATE ROLE openpc_fact_bridge_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openpc_candidate_index_reader') THEN
    CREATE ROLE openpc_candidate_index_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE TYPE facts.inbox_state AS ENUM ('APPLIED', 'GAP_BLOCKED', 'QUARANTINED');
CREATE TYPE facts.fact_state AS ENUM ('ADMITTED', 'FINALIZED', 'REORG_TOMBSTONED', 'SUPERSEDED', 'RETIRED');
CREATE TYPE facts.checkpoint_state AS ENUM ('COMPLETE', 'GAP_BLOCKED', 'REORG_FENCED', 'QUARANTINED');
CREATE TYPE facts.readiness_state AS ENUM ('BLOCKED', 'PARTIAL', 'READY', 'STALE', 'REORG', 'FAILED');

CREATE TABLE facts.admission_inbox (
  candidate_id text PRIMARY KEY CHECK (length(candidate_id) BETWEEN 1 AND 256),
  participant_id text NOT NULL CHECK (length(participant_id) BETWEEN 1 AND 256),
  privacy_domain_id text NOT NULL CHECK (length(privacy_domain_id) BETWEEN 1 AND 256),
  source_profile_id text NOT NULL CHECK (length(source_profile_id) BETWEEN 1 AND 256),
  generation_id text NOT NULL CHECK (length(generation_id) BETWEEN 1 AND 256),
  source_sequence bigint NOT NULL CHECK (source_sequence > 0),
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
  state facts.inbox_state NOT NULL,
  admitted_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (participant_id, privacy_domain_id, source_profile_id, source_sequence)
);

CREATE TABLE facts.canonical_fact (
  candidate_id text PRIMARY KEY REFERENCES facts.admission_inbox(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  schema_id bigint NOT NULL CHECK (schema_id = 21006),
  schema_version text NOT NULL CHECK (schema_version = '1.0.0'),
  schema_digest bytea NOT NULL CHECK (
    schema_digest = decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525', 'hex')
  ),
  canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) BETWEEN 1 AND 1048576),
  fact_digest bytea NOT NULL CHECK (octet_length(fact_digest) = 32),
  finality_anchor bytea NOT NULL CHECK (octet_length(finality_anchor) = 32),
  finality_verified boolean NOT NULL CHECK (finality_verified),
  complete boolean NOT NULL CHECK (complete),
  observed_at_ms bigint NOT NULL CHECK (observed_at_ms >= 0),
  fresh_until_ms bigint NOT NULL CHECK (fresh_until_ms >= observed_at_ms),
  cose_sign1 bytea NOT NULL CHECK (octet_length(cose_sign1) > 64),
  signed_fact_digest bytea NOT NULL CHECK (octet_length(signed_fact_digest) = 32),
  signer_key_id bytea NOT NULL CHECK (octet_length(signer_key_id) BETWEEN 1 AND 64),
  state facts.fact_state NOT NULL,
  admitted_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  finalized_at timestamptz(6),
  CHECK (state = 'ADMITTED' OR finalized_at IS NOT NULL),
  CHECK (sha256(cose_sign1) = signed_fact_digest),
  UNIQUE (participant_id, privacy_domain_id, generation_id, fact_digest)
);

CREATE TABLE facts.fact_lineage (
  candidate_id text PRIMARY KEY REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  provenance_digest bytea NOT NULL CHECK (octet_length(provenance_digest) = 32),
  admitted_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE facts.source_checkpoint (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  source_profile_id text NOT NULL,
  last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
  state facts.checkpoint_state NOT NULL,
  updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (participant_id, privacy_domain_id, source_profile_id)
);

CREATE TABLE facts.readiness_gate (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  state facts.readiness_state NOT NULL,
  shard_verified boolean NOT NULL DEFAULT false,
  shard_digest bytea CHECK (shard_digest IS NULL OR octet_length(shard_digest) = 32),
  shard_cose_sign1 bytea,
  PRIMARY KEY (participant_id, privacy_domain_id, generation_id),
  CHECK (state <> 'READY' OR (shard_verified AND shard_digest IS NOT NULL AND octet_length(shard_cose_sign1) > 64))
);

CREATE TABLE facts.fact_invalidation (
  invalidation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  candidate_id text NOT NULL REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  predecessor_generation_id text NOT NULL,
  replacement_candidate_id text REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  replacement_generation_id text,
  reason text NOT NULL CHECK (reason IN ('REORG', 'CORRECTION', 'RETIREMENT')),
  invalidated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  linked_at timestamptz(6),
  CHECK (replacement_generation_id IS NULL OR replacement_generation_id <> predecessor_generation_id),
  CHECK ((replacement_candidate_id IS NULL) = (replacement_generation_id IS NULL)),
  CHECK ((replacement_generation_id IS NULL) = (linked_at IS NULL)),
  UNIQUE (candidate_id, predecessor_generation_id)
);

CREATE TABLE facts.evidence_occurrence (
  candidate_id text PRIMARY KEY REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_digest bytea NOT NULL CHECK (octet_length(fact_digest) = 32),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE facts.outbox (
  candidate_id text PRIMARY KEY REFERENCES facts.canonical_fact(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_digest bytea NOT NULL CHECK (octet_length(fact_digest) = 32),
  delivery_state text NOT NULL DEFAULT 'PENDING' CHECK (delivery_state IN ('PENDING', 'DELIVERED', 'QUARANTINED')),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE facts.mutation_capability_secret (
  secret_version smallint PRIMARY KEY CHECK (secret_version = 1),
  verifier_secret bytea NOT NULL CHECK (octet_length(verifier_secret) = 32),
  installed_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE facts.mutation_capability_replay (
  capability_nonce bytea PRIMARY KEY CHECK (octet_length(capability_nonce) = 32),
  operation text NOT NULL CHECK (operation IN (
    'ADMIT_FACT',
    'FINALIZE_FACT',
    'MARK_SIGNED_SHARD_READY',
    'INVALIDATE_FACT_FOR_REORG',
    'ADMIT_REPLACEMENT'
  )),
  capability_mac bytea NOT NULL CHECK (octet_length(capability_mac) = 32),
  consumed_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION facts.matches_context(row_participant text, row_privacy text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog
AS $$
  SELECT current_setting('openpc.participant_id', true) = row_participant
     AND current_setting('openpc.privacy_domain_id', true) = row_privacy
$$;

CREATE FUNCTION facts.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_IMMUTABLE';
END
$$;

CREATE FUNCTION facts.enforce_replacement_lifecycle()
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

CREATE FUNCTION facts.enforce_signed_fact_row()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, facts
AS $$
DECLARE
  inbox_digest bytea;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT payload_digest INTO inbox_digest FROM facts.admission_inbox
     WHERE candidate_id = NEW.candidate_id
       AND participant_id = NEW.participant_id
       AND privacy_domain_id = NEW.privacy_domain_id;
    IF inbox_digest IS NULL OR sha256(NEW.canonical_payload) <> inbox_digest THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_SIGNED_FACT_PAYLOAD_DIGEST_REJECTED';
    END IF;
  ELSIF NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
     OR NEW.participant_id IS DISTINCT FROM OLD.participant_id
     OR NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id
     OR NEW.generation_id IS DISTINCT FROM OLD.generation_id
     OR NEW.schema_id IS DISTINCT FROM OLD.schema_id
     OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
     OR NEW.schema_digest IS DISTINCT FROM OLD.schema_digest
     OR NEW.canonical_payload IS DISTINCT FROM OLD.canonical_payload
     OR NEW.fact_digest IS DISTINCT FROM OLD.fact_digest
     OR NEW.finality_anchor IS DISTINCT FROM OLD.finality_anchor
     OR NEW.finality_verified IS DISTINCT FROM OLD.finality_verified
     OR NEW.complete IS DISTINCT FROM OLD.complete
     OR NEW.observed_at_ms IS DISTINCT FROM OLD.observed_at_ms
     OR NEW.fresh_until_ms IS DISTINCT FROM OLD.fresh_until_ms
     OR NEW.cose_sign1 IS DISTINCT FROM OLD.cose_sign1
     OR NEW.signed_fact_digest IS DISTINCT FROM OLD.signed_fact_digest
     OR NEW.signer_key_id IS DISTINCT FROM OLD.signer_key_id THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_SIGNED_FACT_IDENTITY_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION facts.enforce_fact_state_transition()
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

CREATE FUNCTION facts.enforce_invalidation_immutability()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_INVALIDATION_IMMUTABLE';
  END IF;
  IF NEW.invalidation_id IS DISTINCT FROM OLD.invalidation_id
     OR NEW.candidate_id IS DISTINCT FROM OLD.candidate_id
     OR NEW.participant_id IS DISTINCT FROM OLD.participant_id
     OR NEW.privacy_domain_id IS DISTINCT FROM OLD.privacy_domain_id
     OR NEW.predecessor_generation_id IS DISTINCT FROM OLD.predecessor_generation_id
     OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.invalidated_at IS DISTINCT FROM OLD.invalidated_at THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FACT_INVALIDATION_IDENTITY_IMMUTABLE';
  END IF;
  IF OLD.replacement_candidate_id IS NOT NULL
     AND (NEW.replacement_candidate_id IS DISTINCT FROM OLD.replacement_candidate_id
          OR NEW.replacement_generation_id IS DISTINCT FROM OLD.replacement_generation_id
          OR NEW.linked_at IS DISTINCT FROM OLD.linked_at) THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'OPENPC_FTR010_REPLACEMENT_LINK_IMMUTABLE';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER fact_lineage_immutable BEFORE UPDATE OR DELETE ON facts.fact_lineage
FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
CREATE TRIGGER evidence_occurrence_immutable BEFORE UPDATE OR DELETE ON facts.evidence_occurrence
FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();
CREATE TRIGGER replacement_lifecycle_guard BEFORE INSERT OR UPDATE ON facts.fact_invalidation
FOR EACH ROW EXECUTE FUNCTION facts.enforce_replacement_lifecycle();
CREATE TRIGGER signed_fact_row_guard BEFORE INSERT OR UPDATE ON facts.canonical_fact
FOR EACH ROW EXECUTE FUNCTION facts.enforce_signed_fact_row();
CREATE TRIGGER fact_state_transition_guard BEFORE UPDATE ON facts.canonical_fact
FOR EACH ROW EXECUTE FUNCTION facts.enforce_fact_state_transition();
CREATE TRIGGER invalidation_immutability_guard BEFORE UPDATE OR DELETE ON facts.fact_invalidation
FOR EACH ROW EXECUTE FUNCTION facts.enforce_invalidation_immutability();

CREATE FUNCTION facts.assert_lifecycle_context(
  requested_participant text,
  requested_privacy_domain text
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'openpc_fact_bridge_writer', 'MEMBER') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACT_LIFECYCLE_CALLER_REJECTED';
  END IF;
  IF pg_catalog.current_setting('openpc.participant_id', true) IS DISTINCT FROM requested_participant
     OR pg_catalog.current_setting('openpc.privacy_domain_id', true) IS DISTINCT FROM requested_privacy_domain THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'OPENPC_FACT_LIFECYCLE_CONTEXT_REJECTED';
  END IF;
END
$$;

CREATE FUNCTION facts.capability_field(field_id integer, field_value bytea)
RETURNS bytea LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.int2send(field_id::smallint)
      || CASE WHEN field_value IS NULL
           THEN pg_catalog.decode('00', 'hex') || pg_catalog.int8send(0::bigint)
           ELSE pg_catalog.decode('01', 'hex')
             || pg_catalog.int8send(pg_catalog.octet_length(field_value)::bigint)
             || field_value
         END
$$;

CREATE FUNCTION facts.mutation_capability_preimage(
  requested_operation text,
  requested_participant text,
  requested_privacy_domain text,
  requested_candidate_id text,
  requested_predecessor_candidate_id text,
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
  requested_fact_cose_sign1 bytea,
  requested_signed_fact_digest bytea,
  requested_signer_key_id bytea,
  requested_signed_fact_purpose text,
  requested_provenance_digest bytea,
  requested_shard_digest bytea,
  requested_shard_cose_sign1 bytea,
  requested_shard_purpose text,
  requested_invalidation_reason text,
  requested_lifecycle_intent text,
  requested_capability_nonce bytea
) RETURNS bytea LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path = pg_catalog
AS $$
  SELECT facts.capability_field(1, pg_catalog.convert_to('OPENPC_FACTSTORE_DATABASE_MUTATION_CAPABILITY_V1', 'UTF8'))
      || facts.capability_field(2, pg_catalog.int2send(1::smallint))
      || facts.capability_field(3, pg_catalog.convert_to(requested_operation, 'UTF8'))
      || facts.capability_field(4, pg_catalog.convert_to(requested_participant, 'UTF8'))
      || facts.capability_field(5, pg_catalog.convert_to(requested_privacy_domain, 'UTF8'))
      || facts.capability_field(6, pg_catalog.convert_to(requested_candidate_id, 'UTF8'))
      || facts.capability_field(7, pg_catalog.convert_to(requested_predecessor_candidate_id, 'UTF8'))
      || facts.capability_field(8, pg_catalog.convert_to(requested_source_profile, 'UTF8'))
      || facts.capability_field(9, pg_catalog.convert_to(requested_generation, 'UTF8'))
      || facts.capability_field(10, pg_catalog.int8send(requested_source_sequence))
      || facts.capability_field(11, requested_payload_digest)
      || facts.capability_field(12, pg_catalog.int8send(requested_schema_id))
      || facts.capability_field(13, pg_catalog.convert_to(requested_schema_version, 'UTF8'))
      || facts.capability_field(14, requested_schema_digest)
      || facts.capability_field(15, requested_canonical_payload)
      || facts.capability_field(16, requested_fact_digest)
      || facts.capability_field(17, requested_finality_anchor)
      || facts.capability_field(18, pg_catalog.int8send(requested_observed_at_ms))
      || facts.capability_field(19, pg_catalog.int8send(requested_fresh_until_ms))
      || facts.capability_field(20, requested_fact_cose_sign1)
      || facts.capability_field(21, requested_signed_fact_digest)
      || facts.capability_field(22, requested_signer_key_id)
      || facts.capability_field(23, pg_catalog.convert_to(requested_signed_fact_purpose, 'UTF8'))
      || facts.capability_field(24, requested_provenance_digest)
      || facts.capability_field(25, requested_shard_digest)
      || facts.capability_field(26, requested_shard_cose_sign1)
      || facts.capability_field(27, pg_catalog.convert_to(requested_shard_purpose, 'UTF8'))
      || facts.capability_field(28, pg_catalog.convert_to(requested_invalidation_reason, 'UTF8'))
      || facts.capability_field(29, pg_catalog.convert_to(requested_lifecycle_intent, 'UTF8'))
      || facts.capability_field(30, requested_capability_nonce)
$$;

CREATE FUNCTION facts.verify_and_consume_mutation_capability(
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
       'ADMIT_REPLACEMENT'
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

CREATE FUNCTION facts.verify_admit_capability(
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
    'ADMIT_FACT', requested_participant, requested_privacy_domain,
    requested_candidate_id, NULL, requested_source_profile, requested_generation,
    requested_source_sequence, requested_payload_digest, requested_schema_id,
    requested_schema_version, requested_schema_digest, requested_canonical_payload,
    requested_fact_digest, requested_finality_anchor, requested_observed_at_ms,
    requested_fresh_until_ms, requested_cose_sign1, requested_signed_fact_digest,
    requested_signer_key_id, 'openpc:fact-record:v1', requested_provenance_digest,
    NULL, NULL, NULL, NULL, 'ADMIT_NOT_READY', requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'ADMIT_FACT', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE FUNCTION facts.verify_finalize_capability(
  requested_participant text,
  requested_privacy_domain text,
  requested_candidate_id text,
  requested_finality_anchor bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  preimage bytea;
BEGIN
  preimage := facts.mutation_capability_preimage(
    'FINALIZE_FACT', requested_participant, requested_privacy_domain,
    requested_candidate_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, requested_finality_anchor, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, 'ADMITTED_TO_FINALIZED', requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'FINALIZE_FACT', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE FUNCTION facts.verify_signed_shard_ready_capability(
  requested_participant text,
  requested_privacy_domain text,
  requested_generation text,
  requested_shard_digest bytea,
  requested_shard_cose_sign1 bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  preimage bytea;
BEGIN
  preimage := facts.mutation_capability_preimage(
    'MARK_SIGNED_SHARD_READY', requested_participant, requested_privacy_domain,
    NULL, NULL, NULL, requested_generation, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, requested_shard_digest,
    requested_shard_cose_sign1, 'openpc:fact-shard-manifest:v1', NULL,
    'FINALIZED_GENERATION_TO_SIGNED_SHARD_READY', requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'MARK_SIGNED_SHARD_READY', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE FUNCTION facts.verify_invalidate_capability(
  requested_participant text,
  requested_privacy_domain text,
  requested_candidate_id text,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  preimage bytea;
BEGIN
  preimage := facts.mutation_capability_preimage(
    'INVALIDATE_FACT_FOR_REORG', requested_participant, requested_privacy_domain,
    requested_candidate_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, 'REORG', 'FINALIZED_TO_REORG_TOMBSTONED', requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'INVALIDATE_FACT_FOR_REORG', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE FUNCTION facts.verify_replacement_capability(
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
    'REORG', 'REORG_TOMBSTONED_TO_SUPERSEDED_WITH_FINALIZED_REPLACEMENT',
    requested_capability_nonce
  );
  PERFORM facts.verify_and_consume_mutation_capability(
    'ADMIT_REPLACEMENT', preimage, requested_capability_nonce, requested_capability_mac
  );
END
$$;

CREATE FUNCTION facts.insert_validated_fact(
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
  requested_state facts.fact_state
) RETURNS text LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
DECLARE
  prior_digest bytea;
  durable_sequence bigint;
BEGIN
  IF requested_state NOT IN ('ADMITTED', 'FINALIZED') THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FACT_INSERT_STATE_REJECTED';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      requested_participant || ':' || requested_privacy_domain || ':' || requested_source_profile,
      0
    )
  );
  SELECT payload_digest INTO prior_digest
    FROM facts.admission_inbox
   WHERE candidate_id = requested_candidate_id;
  IF prior_digest IS NOT NULL THEN
    IF prior_digest = requested_payload_digest THEN
      RETURN 'IDEMPOTENT_REPLAY';
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'OPENPC_FACT_REPLAY_DIGEST_MISMATCH';
  END IF;
  SELECT last_sequence INTO durable_sequence
    FROM facts.source_checkpoint
   WHERE participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND source_profile_id = requested_source_profile
   FOR UPDATE;
  durable_sequence := COALESCE(durable_sequence, 0);
  IF requested_source_sequence <> durable_sequence + 1 THEN
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'OPENPC_FACT_SEQUENCE_RACE';
  END IF;

  INSERT INTO facts.admission_inbox
    (candidate_id, participant_id, privacy_domain_id, source_profile_id, generation_id,
     source_sequence, payload_digest, state)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     requested_source_profile, requested_generation, requested_source_sequence,
     requested_payload_digest, 'APPLIED');
  INSERT INTO facts.canonical_fact
    (candidate_id, participant_id, privacy_domain_id, generation_id, schema_id,
     schema_version, schema_digest, canonical_payload, fact_digest, finality_anchor,
     finality_verified, complete, observed_at_ms, fresh_until_ms, cose_sign1,
     signed_fact_digest, signer_key_id, state, finalized_at)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     requested_generation, requested_schema_id, requested_schema_version,
     requested_schema_digest, requested_canonical_payload, requested_fact_digest,
     requested_finality_anchor, true, true, requested_observed_at_ms,
     requested_fresh_until_ms, requested_cose_sign1, requested_signed_fact_digest,
     requested_signer_key_id, requested_state,
     CASE WHEN requested_state = 'FINALIZED' THEN pg_catalog.clock_timestamp() ELSE NULL END);
  INSERT INTO facts.fact_lineage
    (candidate_id, participant_id, privacy_domain_id, provenance_digest)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     requested_provenance_digest);
  INSERT INTO facts.source_checkpoint
    (participant_id, privacy_domain_id, source_profile_id, last_sequence, state)
  VALUES
    (requested_participant, requested_privacy_domain, requested_source_profile,
     requested_source_sequence, 'COMPLETE')
  ON CONFLICT (participant_id, privacy_domain_id, source_profile_id)
  DO UPDATE SET last_sequence = EXCLUDED.last_sequence, state = EXCLUDED.state;
  INSERT INTO facts.readiness_gate
    (participant_id, privacy_domain_id, generation_id, state, shard_verified)
  VALUES
    (requested_participant, requested_privacy_domain, requested_generation, 'BLOCKED', false)
  ON CONFLICT (participant_id, privacy_domain_id, generation_id) DO NOTHING;
  INSERT INTO facts.evidence_occurrence
    (candidate_id, participant_id, privacy_domain_id, fact_digest)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     requested_fact_digest);
  INSERT INTO facts.outbox
    (candidate_id, participant_id, privacy_domain_id, fact_digest)
  VALUES
    (requested_candidate_id, requested_participant, requested_privacy_domain,
     requested_fact_digest);
  IF requested_state = 'FINALIZED' THEN
    RETURN 'REPLACEMENT_FINALIZED';
  END IF;
  RETURN 'ADMITTED_NOT_READY';
END
$$;

CREATE FUNCTION facts.admit_fact(
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

CREATE FUNCTION facts.finalize_fact(
  requested_participant text,
  requested_privacy_domain text,
  requested_candidate_id text,
  requested_finality_anchor bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  changed bigint;
BEGIN
  PERFORM facts.assert_lifecycle_context(requested_participant, requested_privacy_domain);
  PERFORM facts.verify_finalize_capability(
    requested_participant, requested_privacy_domain, requested_candidate_id,
    requested_finality_anchor, requested_capability_nonce, requested_capability_mac
  );
  UPDATE facts.canonical_fact
     SET state = 'FINALIZED', finalized_at = pg_catalog.clock_timestamp()
   WHERE candidate_id = requested_candidate_id
     AND participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND state = 'ADMITTED'
     AND finality_anchor = requested_finality_anchor
     AND finality_verified;
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END
$$;

CREATE FUNCTION facts.mark_signed_shard_ready(
  requested_participant text,
  requested_privacy_domain text,
  requested_generation text,
  requested_shard_digest bytea,
  requested_shard_cose_sign1 bytea,
  requested_capability_nonce bytea,
  requested_capability_mac bytea
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
DECLARE
  changed bigint;
BEGIN
  PERFORM facts.assert_lifecycle_context(requested_participant, requested_privacy_domain);
  PERFORM facts.verify_signed_shard_ready_capability(
    requested_participant, requested_privacy_domain, requested_generation,
    requested_shard_digest, requested_shard_cose_sign1,
    requested_capability_nonce, requested_capability_mac
  );
  UPDATE facts.readiness_gate
     SET state = 'READY', shard_verified = true,
         shard_digest = requested_shard_digest,
         shard_cose_sign1 = requested_shard_cose_sign1
   WHERE participant_id = requested_participant
     AND privacy_domain_id = requested_privacy_domain
     AND generation_id = requested_generation
     AND NOT EXISTS (
       SELECT 1 FROM facts.canonical_fact AS fact
        WHERE fact.participant_id = requested_participant
          AND fact.privacy_domain_id = requested_privacy_domain
          AND fact.generation_id = requested_generation
          AND fact.state <> 'FINALIZED'
     )
     AND EXISTS (
       SELECT 1 FROM facts.canonical_fact AS fact
        WHERE fact.participant_id = requested_participant
          AND fact.privacy_domain_id = requested_privacy_domain
          AND fact.generation_id = requested_generation
          AND fact.state = 'FINALIZED'
     );
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END
$$;

CREATE FUNCTION facts.invalidate_fact_for_reorg(
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

CREATE FUNCTION facts.admit_replacement(
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
  outcome := facts.insert_validated_fact(
    requested_candidate_id, requested_participant, requested_privacy_domain,
    requested_source_profile, requested_generation, requested_source_sequence,
    requested_payload_digest, requested_schema_id, requested_schema_version,
    requested_schema_digest, requested_canonical_payload, requested_fact_digest,
    requested_finality_anchor, requested_observed_at_ms, requested_fresh_until_ms,
    requested_cose_sign1, requested_signed_fact_digest, requested_signer_key_id,
    requested_provenance_digest, 'FINALIZED'
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

ALTER TABLE facts.mutation_capability_secret OWNER TO openpc_facts_capability_owner;
ALTER TABLE facts.mutation_capability_replay OWNER TO openpc_facts_capability_owner;

ALTER FUNCTION facts.capability_field(integer, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.mutation_capability_preimage(text, text, text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, text, bytea, bytea, bytea, text, text, text, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_and_consume_mutation_capability(text, bytea, bytea, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_admit_capability(text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_finalize_capability(text, text, text, bytea, bytea, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_signed_shard_ready_capability(text, text, text, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_invalidate_capability(text, text, text, bytea, bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_replacement_capability(text, text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_capability_owner;

ALTER FUNCTION facts.assert_lifecycle_context(text, text) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.insert_validated_fact(text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, facts.fact_state) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.admit_fact(text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.finalize_fact(text, text, text, bytea, bytea, bytea) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.mark_signed_shard_ready(text, text, text, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.invalidate_fact_for_reorg(text, text, text, bytea, bytea) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.admit_replacement(text, text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) OWNER TO openpc_facts_lifecycle_owner;

ALTER TABLE facts.admission_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.admission_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.canonical_fact ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.canonical_fact FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.fact_lineage ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.fact_lineage FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.source_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.source_checkpoint FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.readiness_gate ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.readiness_gate FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.fact_invalidation ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.fact_invalidation FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.evidence_occurrence ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.evidence_occurrence FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.mutation_capability_secret ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.mutation_capability_secret FORCE ROW LEVEL SECURITY;
ALTER TABLE facts.mutation_capability_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.mutation_capability_replay FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_context ON facts.admission_inbox FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.canonical_fact FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.fact_lineage FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.source_checkpoint FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.readiness_gate FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.fact_invalidation FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.evidence_occurrence FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY writer_context ON facts.outbox FOR ALL TO openpc_fact_bridge_writer USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.admission_inbox FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.canonical_fact FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.fact_lineage FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.source_checkpoint FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.readiness_gate FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.fact_invalidation FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.evidence_occurrence FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY lifecycle_context ON facts.outbox FOR ALL TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id, privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id, privacy_domain_id));
CREATE POLICY capability_owner_only ON facts.mutation_capability_secret FOR ALL TO openpc_facts_capability_owner USING (true) WITH CHECK (true);
CREATE POLICY capability_owner_only ON facts.mutation_capability_replay FOR ALL TO openpc_facts_capability_owner USING (true) WITH CHECK (true);

REVOKE ALL ON ALL TABLES IN SCHEMA facts FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA facts FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA facts FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) FROM PUBLIC, openpc_facts_lifecycle_owner, openpc_fact_bridge_writer, openpc_candidate_index_reader;
REVOKE EXECUTE ON FUNCTION public.hmac(text, text, text) FROM PUBLIC, openpc_facts_lifecycle_owner, openpc_fact_bridge_writer, openpc_candidate_index_reader;
GRANT USAGE ON SCHEMA facts TO openpc_facts_capability_owner, openpc_facts_lifecycle_owner, openpc_fact_bridge_writer, openpc_candidate_index_reader;
GRANT USAGE ON SCHEMA public TO openpc_facts_capability_owner;
GRANT EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) TO openpc_facts_capability_owner;
GRANT EXECUTE ON FUNCTION public.hmac(text, text, text) TO openpc_facts_capability_owner;
GRANT SELECT, INSERT, UPDATE ON
  facts.admission_inbox,
  facts.canonical_fact,
  facts.fact_lineage,
  facts.source_checkpoint,
  facts.readiness_gate,
  facts.fact_invalidation,
  facts.evidence_occurrence,
  facts.outbox
TO openpc_facts_lifecycle_owner;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA facts TO openpc_facts_lifecycle_owner;
GRANT SELECT ON
  facts.admission_inbox,
  facts.canonical_fact,
  facts.fact_lineage,
  facts.source_checkpoint,
  facts.readiness_gate,
  facts.fact_invalidation,
  facts.evidence_occurrence,
  facts.outbox
TO openpc_fact_bridge_writer;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA facts FROM openpc_fact_bridge_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA facts FROM openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.verify_admit_capability(text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) TO openpc_facts_lifecycle_owner;
GRANT EXECUTE ON FUNCTION facts.verify_finalize_capability(text, text, text, bytea, bytea, bytea) TO openpc_facts_lifecycle_owner;
GRANT EXECUTE ON FUNCTION facts.verify_signed_shard_ready_capability(text, text, text, bytea, bytea, bytea, bytea) TO openpc_facts_lifecycle_owner;
GRANT EXECUTE ON FUNCTION facts.verify_invalidate_capability(text, text, text, bytea, bytea) TO openpc_facts_lifecycle_owner;
GRANT EXECUTE ON FUNCTION facts.verify_replacement_capability(text, text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) TO openpc_facts_lifecycle_owner;
GRANT EXECUTE ON FUNCTION facts.matches_context(text, text) TO openpc_facts_lifecycle_owner, openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.admit_fact(text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) TO openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.finalize_fact(text, text, text, bytea, bytea, bytea) TO openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.mark_signed_shard_ready(text, text, text, bytea, bytea, bytea, bytea) TO openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.invalidate_fact_for_reorg(text, text, text, bytea, bytea) TO openpc_fact_bridge_writer;
GRANT EXECUTE ON FUNCTION facts.admit_replacement(text, text, text, text, text, text, bigint, bytea, bigint, text, bytea, bytea, bytea, bytea, bigint, bigint, bytea, bytea, bytea, bytea, bytea, bytea) TO openpc_fact_bridge_writer;
GRANT SELECT ON facts.source_checkpoint, facts.readiness_gate TO openpc_candidate_index_reader;
