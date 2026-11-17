-- SQLx-owned physical Fact payload retirement. The immutable identity and the
-- original signed evidence have separate custody from the deletable projection.
-- No request, signing key, endpoint or host trust is installed by this migration.

LOCK TABLE facts.canonical_fact IN ACCESS EXCLUSIVE MODE;
SET LOCAL search_path=pg_catalog;

CREATE TABLE facts.retained_fact_identity (
  candidate_id text PRIMARY KEY REFERENCES facts.admission_inbox(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
  payload_bytes bigint NOT NULL CHECK(payload_bytes>0),
  fact_digest bytea NOT NULL CHECK(octet_length(fact_digest)=32),
  signed_fact_digest bytea NOT NULL CHECK(octet_length(signed_fact_digest)=32),
  observed_at_ms bigint NOT NULL,
  fresh_until_ms bigint NOT NULL,
  admitted_at timestamptz(6) NOT NULL,
  UNIQUE(candidate_id,participant_id,privacy_domain_id,generation_id),
  UNIQUE(participant_id,privacy_domain_id,generation_id,fact_digest)
);
CREATE TABLE facts.signed_fact_custody (
  candidate_id text PRIMARY KEY REFERENCES facts.retained_fact_identity(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  cose_sign1 bytea NOT NULL CHECK(octet_length(cose_sign1)>64),
  signed_fact_digest bytea NOT NULL CHECK(signed_fact_digest=sha256(cose_sign1))
);

-- Populated upgrade preserves exact bytes. It does not manufacture a replacement
-- canonical payload or change any Fact UUID, generation or sequence allocation.
INSERT INTO facts.retained_fact_identity
  SELECT candidate_id,participant_id,privacy_domain_id,generation_id,
    sha256(canonical_payload),octet_length(canonical_payload),fact_digest,signed_fact_digest,
    observed_at_ms,fresh_until_ms,admitted_at
  FROM facts.canonical_fact;
INSERT INTO facts.signed_fact_custody
  SELECT candidate_id,participant_id,privacy_domain_id,cose_sign1,signed_fact_digest
  FROM facts.canonical_fact;

-- Existing references now point to the identity that survives physical effect.
-- Preserve each constraint's columns, deferrability and RESTRICT semantics.
DO $$ DECLARE c record; definition text; BEGIN
  IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f'
    AND confrelid='facts.canonical_fact'::regclass AND connamespace<>'facts'::regnamespace) THEN
    RAISE EXCEPTION 'OPENPC_RETIREMENT_EXTERNAL_REFERENCE_REQUIRES_OWNER';
  END IF;
  FOR c IN SELECT conrelid,conname,pg_get_constraintdef(oid) definition
    FROM pg_constraint WHERE contype='f' AND confrelid='facts.canonical_fact'::regclass
  LOOP
    definition:=replace(c.definition,'REFERENCES facts.canonical_fact(',
      'REFERENCES facts.retained_fact_identity(');
    IF definition=c.definition THEN
      RAISE EXCEPTION 'OPENPC_RETIREMENT_FOREIGN_KEY_UNRECOGNIZED';
    END IF;
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.conrelid::regclass,c.conname);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.conrelid::regclass,c.conname,definition);
  END LOOP;
END $$;
ALTER TABLE facts.canonical_fact ADD CONSTRAINT canonical_fact_retained_identity
  FOREIGN KEY(candidate_id,participant_id,privacy_domain_id,generation_id)
  REFERENCES facts.retained_fact_identity(candidate_id,participant_id,privacy_domain_id,generation_id)
  ON DELETE RESTRICT;

CREATE TABLE facts.store_retirement_attempt (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  attempt_id text NOT NULL CHECK(length(attempt_id) BETWEEN 1 AND 256),
  business_intent_id text NOT NULL CHECK(length(business_intent_id) BETWEEN 1 AND 256),
  attempt_digest bytea NOT NULL CHECK(octet_length(attempt_digest)=32),
  selection_digest bytea NOT NULL CHECK(octet_length(selection_digest)=32),
  lifecycle_revision bigint NOT NULL CHECK(lifecycle_revision>0),
  attempt_document jsonb NOT NULL,
  authority_bytes bytea NOT NULL CHECK(octet_length(authority_bytes) BETWEEN 1 AND 1048576),
  authority_digest bytea NOT NULL CHECK(authority_digest=sha256(authority_bytes)),
  state text NOT NULL CHECK(state IN ('APPLIED','REJECTED_NO_EFFECT','CANCELLED_NO_EFFECT')),
  signed_outcome bytea NOT NULL CHECK(octet_length(signed_outcome) BETWEEN 1 AND 1048576),
  outcome_digest bytea NOT NULL CHECK(outcome_digest=sha256(signed_outcome)),
  completed_at_ms bigint NOT NULL CHECK(completed_at_ms>0),
  PRIMARY KEY(participant_id,privacy_domain_id,attempt_id),
  UNIQUE(participant_id,privacy_domain_id,attempt_id,outcome_digest)
);
CREATE TABLE facts.retired_fact_payload (
  candidate_id text PRIMARY KEY REFERENCES facts.retained_fact_identity(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  attempt_id text NOT NULL,
  outcome_digest bytea NOT NULL,
  retained_selection jsonb NOT NULL,
  finalized_at timestamptz(6) NOT NULL,
  FOREIGN KEY(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    REFERENCES facts.store_retirement_attempt(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    ON DELETE RESTRICT
);
CREATE INDEX store_retirement_business_intent ON facts.store_retirement_attempt
  (participant_id,privacy_domain_id,business_intent_id);
CREATE TABLE facts.store_retirement_outbox (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  attempt_id text NOT NULL,
  outcome_digest bytea NOT NULL,
  event_payload bytea NOT NULL CHECK(octet_length(event_payload) BETWEEN 1 AND 1048576),
  event_digest bytea NOT NULL CHECK(event_digest=sha256(event_payload)),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(participant_id,privacy_domain_id,attempt_id),
  FOREIGN KEY(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    REFERENCES facts.store_retirement_attempt(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    ON DELETE RESTRICT
);
CREATE INDEX canonical_fact_retirement_reference_scan ON facts.canonical_fact
  (participant_id,privacy_domain_id,candidate_id COLLATE "C")
  WHERE state NOT IN ('RETIRED','SUPERSEDED');

DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['retained_fact_identity','signed_fact_custody',
    'store_retirement_attempt','retired_fact_payload','store_retirement_outbox'] LOOP
    EXECUTE format('ALTER TABLE facts.%I OWNER TO openpc_facts_lifecycle_owner',target);
    EXECUTE format('ALTER TABLE facts.%I ENABLE ROW LEVEL SECURITY',target);
    EXECUTE format('ALTER TABLE facts.%I FORCE ROW LEVEL SECURITY',target);
    EXECUTE format('CREATE POLICY lifecycle_context ON facts.%I TO openpc_facts_lifecycle_owner
      USING(facts.matches_context(participant_id,privacy_domain_id))
      WITH CHECK(facts.matches_context(participant_id,privacy_domain_id))',target);
    EXECUTE format('CREATE POLICY read_context ON facts.%I FOR SELECT TO openpc_fact_bridge_writer
      USING(facts.matches_context(participant_id,privacy_domain_id))',target);
    EXECUTE format('REVOKE ALL ON facts.%I FROM PUBLIC',target);
    EXECUTE format('GRANT SELECT ON facts.%I TO openpc_fact_bridge_writer',target);
    EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON facts.%I
      FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation()',target);
  END LOOP;
END $$;

-- The old payload row is never re-created once its immutable identity exists.
CREATE FUNCTION facts.retain_original_fact_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  INSERT INTO facts.retained_fact_identity VALUES(NEW.candidate_id,NEW.participant_id,
    NEW.privacy_domain_id,NEW.generation_id,sha256(NEW.canonical_payload),
    octet_length(NEW.canonical_payload),NEW.fact_digest,NEW.signed_fact_digest,
    NEW.observed_at_ms,NEW.fresh_until_ms,NEW.admitted_at);
  INSERT INTO facts.signed_fact_custody VALUES(NEW.candidate_id,NEW.participant_id,
    NEW.privacy_domain_id,NEW.cose_sign1,NEW.signed_fact_digest);
  RETURN NEW;
END $$;
ALTER FUNCTION facts.retain_original_fact_identity() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.retain_original_fact_identity() FROM PUBLIC;
CREATE TRIGGER retain_original_identity BEFORE INSERT ON facts.canonical_fact
  FOR EACH ROW EXECUTE FUNCTION facts.retain_original_fact_identity();

CREATE FUNCTION facts.reject_retired_generation_readiness() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF NEW.state='READY' AND EXISTS(SELECT 1 FROM facts.retired_fact_payload r
    JOIN facts.retained_fact_identity i USING(candidate_id,participant_id,privacy_domain_id)
    WHERE i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id
      AND i.generation_id=NEW.generation_id) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIRED_GENERATION_READINESS_REJECTED';
  END IF;
  RETURN NEW;
END $$;
ALTER FUNCTION facts.reject_retired_generation_readiness() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.reject_retired_generation_readiness() FROM PUBLIC;
CREATE TRIGGER retired_generation_readiness BEFORE INSERT OR UPDATE ON facts.readiness_gate
  FOR EACH ROW EXECUTE FUNCTION facts.reject_retired_generation_readiness();

-- Separate nonce custody does not widen the existing mutation operation list.
CREATE TABLE facts.retirement_capability_replay (
  nonce bytea PRIMARY KEY CHECK(octet_length(nonce)=32),
  domain text NOT NULL CHECK(domain IN ('OPENPC_FACTSTORE_RETIREMENT_EXECUTION_V1',
    'OPENPC_FACTSTORE_RETIREMENT_CANCELLATION_V1')),
  binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
  mac bytea NOT NULL CHECK(octet_length(mac)=32),
  consumed_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE facts.retirement_capability_replay OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON facts.retirement_capability_replay FROM PUBLIC;

CREATE FUNCTION facts.consume_retirement_capability(p_domain text,p_attempt bytea,
  p_authority bytea,p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE secret bytea; binding bytea; expected bytea; mismatch integer:=0; n integer;
BEGIN
  IF p_domain NOT IN ('OPENPC_FACTSTORE_RETIREMENT_EXECUTION_V1','OPENPC_FACTSTORE_RETIREMENT_CANCELLATION_V1')
    OR p_domain IS NULL OR p_attempt IS NULL OR octet_length(p_attempt)<>32
    OR p_authority IS NULL OR octet_length(p_authority) NOT BETWEEN 1 AND 1048576
    OR p_outcome IS NULL OR octet_length(p_outcome) NOT BETWEEN 1 AND 1048576
    OR p_nonce IS NULL OR octet_length(p_nonce)<>32 OR p_mac IS NULL OR octet_length(p_mac)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CAPABILITY_INVALID';
  END IF;
  binding:=sha256(convert_to('OPENPC_FACTSTORE_RETIREMENT_BINDING_V1','UTF8')||
    p_attempt||sha256(p_authority)||sha256(p_outcome));
  SELECT verifier_secret INTO STRICT secret FROM facts.mutation_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to(p_domain,'UTF8')||binding||p_nonce,secret,'sha256');
  FOR n IN 0..31 LOOP mismatch:=mismatch|(get_byte(expected,n)#get_byte(p_mac,n)); END LOOP;
  IF mismatch<>0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CAPABILITY_INVALID';
  END IF;
  INSERT INTO facts.retirement_capability_replay VALUES(p_nonce,p_domain,binding,p_mac,clock_timestamp());
END $$;
ALTER FUNCTION facts.consume_retirement_capability(text,bytea,bytea,bytea,bytea,bytea)
  OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.consume_retirement_capability(text,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION facts.verify_retirement_execution(p_attempt bytea,p_authority bytea,
  p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT facts.consume_retirement_capability('OPENPC_FACTSTORE_RETIREMENT_EXECUTION_V1',
    p_attempt,p_authority,p_outcome,p_nonce,p_mac)
$$;
CREATE FUNCTION facts.verify_retirement_cancellation(p_attempt bytea,p_authority bytea,
  p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT facts.consume_retirement_capability('OPENPC_FACTSTORE_RETIREMENT_CANCELLATION_V1',
    p_attempt,p_authority,p_outcome,p_nonce,p_mac)
$$;
ALTER FUNCTION facts.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
ALTER FUNCTION facts.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea),
  facts.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea),
  facts.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

-- No durable STARTED row is committed alone. This scope fence closes the absent
-- row race; the terminal attempt row is then locked and compared by both paths.
-- A process lost before commit therefore remains UNKNOWN, never NO_EFFECT.
CREATE FUNCTION facts.lock_store_retirement(p_participant text,p_privacy text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT facts.assert_lifecycle_context(p_participant,p_privacy)
$$;
ALTER FUNCTION facts.lock_store_retirement(text,text) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.lock_store_retirement(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.lock_store_retirement(text,text) TO openpc_fact_bridge_writer;

-- Read-only preflight and final SQL check share the same actual row predicates.
-- Signature/provenance and incoming signed-record references are additionally
-- checked by the Rust owner while it holds this same exclusive scope fence.
CREATE FUNCTION facts.check_store_retirement(p_attempt jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p text:=p_attempt#>>'{scope,participant_id}'; d text:=p_attempt#>>'{scope,privacy_domain_id}';
  selection jsonb:=p_attempt->'selection'; source jsonb:=selection->'source';
  selected jsonb; actual record; previous_sequence bigint:=0;
BEGIN
  PERFORM facts.assert_lifecycle_context(p,d);
  IF p_attempt->>'store' IS DISTINCT FROM 'openpc_facts'
    OR selection->>'class' IS DISTINCT FROM 'ADMITTED_FACT'
    OR jsonb_typeof(selection->'rows') IS DISTINCT FROM 'array'
    OR jsonb_array_length(selection->'rows') NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SELECTION_REJECTED';
  END IF;
  IF (p_attempt#>>'{governance,retention_not_before_ms}')::bigint
    >floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN RETURN 'RETENTION_NOT_ELAPSED'; END IF;
  FOR selected IN SELECT value FROM jsonb_array_elements(selection->'rows') LOOP
    IF (selected->>'candidate_feed_sequence')::bigint<=previous_sequence THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SELECTION_REJECTED';
    END IF;
    previous_sequence:=(selected->>'candidate_feed_sequence')::bigint;
    SELECT f.*,a.fact_id,a.delta_sequence,g.canonical_generation,r.candidate_sequence,
      r.source_profile_id,r.source_generation_id,r.partition_id,r.checkpoint_digest,
      r.fact_generation_id,l.provenance_digest,i.state inbox_state,i.source_sequence,
      c.state checkpoint_state,c.last_sequence,ready.state readiness_state,ready.shard_verified,
      custody.signed_fact_digest custody_digest,retained.payload_digest retained_digest
    INTO actual FROM facts.canonical_fact f
    JOIN facts.canonical_identity_allocation a ON a.candidate_id=f.candidate_id AND a.participant_id=f.participant_id
      AND a.privacy_domain_id=f.privacy_domain_id AND a.generation_id=f.generation_id
    JOIN facts.canonical_generation g ON g.participant_id=a.participant_id AND g.privacy_domain_id=a.privacy_domain_id
      AND g.fact_profile_id=a.fact_profile_id AND g.generation_id=a.generation_id
    JOIN facts.candidate_feed_receipt r ON r.candidate_id=f.candidate_id AND r.participant_id=f.participant_id
      AND r.privacy_domain_id=f.privacy_domain_id
    JOIN facts.fact_lineage l ON l.candidate_id=f.candidate_id AND l.participant_id=f.participant_id
      AND l.privacy_domain_id=f.privacy_domain_id
    JOIN facts.admission_inbox i ON i.candidate_id=f.candidate_id AND i.participant_id=f.participant_id
      AND i.privacy_domain_id=f.privacy_domain_id
    JOIN facts.source_checkpoint c ON c.participant_id=f.participant_id AND c.privacy_domain_id=f.privacy_domain_id
      AND c.source_profile_id=i.source_profile_id
    JOIN facts.readiness_gate ready ON ready.participant_id=f.participant_id AND ready.privacy_domain_id=f.privacy_domain_id
      AND ready.generation_id=f.generation_id
    JOIN facts.signed_fact_custody custody ON custody.candidate_id=f.candidate_id AND custody.participant_id=f.participant_id
      AND custody.privacy_domain_id=f.privacy_domain_id
    JOIN facts.retained_fact_identity retained ON retained.candidate_id=f.candidate_id AND retained.participant_id=f.participant_id
      AND retained.privacy_domain_id=f.privacy_domain_id AND retained.generation_id=f.generation_id
    WHERE f.participant_id=p AND f.privacy_domain_id=d AND f.candidate_id=selected->>'candidate_id';
    IF NOT FOUND THEN RETURN 'SOURCE_CHANGED'; END IF;
    IF actual.source_profile_id IS DISTINCT FROM source->>'profile_id'
      OR actual.source_generation_id IS DISTINCT FROM source->>'generation_id'
      OR actual.partition_id::text IS DISTINCT FROM source->>'partition_id'
      OR actual.fact_generation_id IS DISTINCT FROM selection->>'fact_generation_id'
      OR actual.generation_id IS DISTINCT FROM selection->>'fact_generation_id'
      OR actual.canonical_generation::text IS DISTINCT FROM selection->>'canonical_generation'
    THEN RETURN 'GENERATION_CHANGED'; END IF;
    IF actual.fact_id::text IS DISTINCT FROM selected->>'fact_id'
      OR actual.delta_sequence::text IS DISTINCT FROM selected->>'fact_delta_sequence'
      OR actual.candidate_sequence::text IS DISTINCT FROM selected->>'candidate_feed_sequence'
      OR encode(sha256(actual.canonical_payload),'hex') IS DISTINCT FROM selected->>'payload_digest'
      OR octet_length(actual.canonical_payload)::text IS DISTINCT FROM selected->>'payload_bytes'
      OR encode(actual.signed_fact_digest,'hex') IS DISTINCT FROM selected->>'signed_fact_digest'
      OR encode(actual.provenance_digest,'hex') IS DISTINCT FROM selected->>'lineage_digest'
      OR encode(actual.checkpoint_digest,'hex') IS DISTINCT FROM selected->>'checkpoint_digest'
      OR actual.custody_digest<>actual.signed_fact_digest OR actual.retained_digest<>sha256(actual.canonical_payload)
    THEN RETURN 'SOURCE_CHANGED'; END IF;
    IF actual.state='REORG_TOMBSTONED' OR actual.checkpoint_state='REORG_FENCED'
      OR actual.readiness_state='REORG' THEN RETURN 'REORG_FENCED'; END IF;
    IF actual.inbox_state<>'APPLIED' OR actual.checkpoint_state<>'COMPLETE'
      OR actual.last_sequence<actual.source_sequence OR NOT actual.complete OR NOT actual.finality_verified
      OR actual.finalized_at IS NULL THEN RETURN 'CHECKPOINT_INCOMPLETE'; END IF;
    IF actual.state NOT IN ('RETIRED','SUPERSEDED') OR actual.readiness_state='READY'
      OR actual.shard_verified THEN RETURN 'READINESS_PROTECTED'; END IF;
    IF EXISTS(SELECT 1 FROM facts.shard_publication pub WHERE pub.participant_id=p
      AND pub.privacy_domain_id=d AND pub.generation_id=actual.generation_id
      AND pub.delivery_state<>'DELIVERED') THEN RETURN 'PUBLICATION_PROTECTED'; END IF;
    IF EXISTS(SELECT 1 FROM facts.outbox o WHERE o.participant_id=p AND o.privacy_domain_id=d
      AND o.candidate_id=actual.candidate_id AND o.delivery_state<>'DELIVERED')
      OR EXISTS(SELECT 1 FROM facts.fact_invalidation inv
        JOIN facts.canonical_fact dependent ON dependent.candidate_id=inv.candidate_id
          AND dependent.participant_id=inv.participant_id AND dependent.privacy_domain_id=inv.privacy_domain_id
        WHERE inv.participant_id=p AND inv.privacy_domain_id=d
          AND inv.replacement_candidate_id=actual.candidate_id AND dependent.state NOT IN ('RETIRED','SUPERSEDED'))
    THEN RETURN 'REFERENCES_PROTECTED'; END IF;
  END LOOP;
  RETURN NULL;
END $$;
ALTER FUNCTION facts.check_store_retirement(jsonb) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.check_store_retirement(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.check_store_retirement(jsonb) TO openpc_fact_bridge_writer;

-- Private common effect owner. Only the two fixed-purpose wrappers below can
-- call it. No caller-supplied "verified" or "eligible" field reaches this owner.
CREATE FUNCTION facts.commit_store_retirement(p_authority bytea,p_outcome bytea,p_event bytea,
  p_lineage bytea,p_nonce bytea,p_mac bytea,p_cancel boolean) RETURNS bytea
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE authority jsonb:=convert_from(p_authority,'UTF8')::jsonb->'claims';
  outcome jsonb:=convert_from(p_outcome,'UTF8')::jsonb->'claims';
  attempt jsonb:=authority->'attempt'; effect jsonb:=outcome#>'{outcome,effect}';
  p text:=attempt#>>'{scope,participant_id}'; d text:=attempt#>>'{scope,privacy_domain_id}';
  id text:=attempt->>'attempt_id'; digest bytea:=decode(outcome#>>'{outcome,attempt_digest}','hex');
  previous facts.store_retirement_attempt%ROWTYPE; blocker text; selected jsonb;
  count_rows bigint; count_bytes bigint; removed bigint; now_ms bigint;
BEGIN
  PERFORM facts.assert_lifecycle_context(p,d);
  IF p_cancel THEN
    PERFORM facts.verify_retirement_cancellation(digest,p_authority,p_outcome,p_nonce,p_mac);
  ELSE
    PERFORM facts.verify_retirement_execution(digest,p_authority,p_outcome,p_nonce,p_mac);
  END IF;
  IF authority->'host' IS DISTINCT FROM outcome->'host'
    OR outcome->>'attempt_id' IS DISTINCT FROM id
    OR outcome->>'business_intent_id' IS DISTINCT FROM attempt->>'business_intent_id'
    OR attempt->>'store' IS DISTINCT FROM 'openpc_facts' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_BINDING_REJECTED';
  END IF;
  SELECT * INTO previous FROM facts.store_retirement_attempt
    WHERE participant_id=p AND privacy_domain_id=d AND attempt_id=id FOR UPDATE;
  IF FOUND THEN
    IF previous.attempt_digest<>digest OR previous.attempt_document IS DISTINCT FROM attempt THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_ALTERED_REPLAY';
    END IF;
    RETURN previous.signed_outcome;
  END IF;
  IF EXISTS(SELECT 1 FROM facts.store_retirement_attempt prior
    WHERE prior.participant_id=p AND prior.privacy_domain_id=d
      AND prior.business_intent_id=attempt->>'business_intent_id'
      AND (prior.selection_digest<>decode(attempt->>'selection_digest','hex') OR prior.state='APPLIED')) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_BUSINESS_INTENT_REPLAY';
  END IF;
  now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF now_ms<(authority->>'issued_at_ms')::bigint OR now_ms>=(authority->>'expires_at_ms')::bigint
    OR (outcome->>'completed_at_ms')::bigint>now_ms THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_AUTHORITY_EXPIRED';
  END IF;
  IF p_cancel THEN
    IF effect->>'state' IS DISTINCT FROM 'CANCELLED_NO_EFFECT' THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CANCELLATION_REJECTED';
    END IF;
  ELSE
    IF effect->>'state' NOT IN ('APPLIED','REJECTED_NO_EFFECT') OR effect->>'state' IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_EXECUTION_REJECTED';
    END IF;
    blocker:=facts.check_store_retirement(attempt);
    IF effect->>'state'='APPLIED' THEN
      IF blocker IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_SOURCE_CHANGED';
      END IF;
      SELECT count(*),sum((value->>'payload_bytes')::bigint) INTO count_rows,count_bytes
        FROM jsonb_array_elements(attempt#>'{selection,rows}');
      IF (effect->>'retired_rows')::bigint IS DISTINCT FROM count_rows
        OR (effect->>'retired_payload_bytes')::bigint IS DISTINCT FROM count_bytes
        OR p_lineage IS NULL OR convert_from(p_lineage,'UTF8')::jsonb IS DISTINCT FROM attempt#>'{selection,rows}'
        OR encode(sha256(p_lineage),'hex') IS DISTINCT FROM effect->>'retained_lineage_digest'
        OR p_event IS NULL OR encode(sha256(p_event),'hex') IS DISTINCT FROM effect->>'outbox_event_digest'
      THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_EFFECT_BINDING_REJECTED'; END IF;
    ELSIF blocker IS NOT NULL AND effect->>'rejection' IS DISTINCT FROM blocker THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_REJECTION_CHANGED';
    END IF;
  END IF;
  INSERT INTO facts.store_retirement_attempt VALUES(p,d,id,attempt->>'business_intent_id',digest,
    decode(attempt->>'selection_digest','hex'),(attempt#>>'{governance,lifecycle_revision}')::bigint,
    attempt,p_authority,sha256(p_authority),effect->>'state',p_outcome,sha256(p_outcome),
    (outcome->>'completed_at_ms')::bigint);
  IF effect->>'state'='APPLIED' THEN
    FOR selected IN SELECT value FROM jsonb_array_elements(attempt#>'{selection,rows}') LOOP
      INSERT INTO facts.retired_fact_payload
        SELECT selected->>'candidate_id',p,d,id,sha256(p_outcome),selected,f.finalized_at
        FROM facts.canonical_fact f WHERE f.candidate_id=selected->>'candidate_id'
          AND f.participant_id=p AND f.privacy_domain_id=d;
      DELETE FROM facts.canonical_fact WHERE candidate_id=selected->>'candidate_id'
        AND participant_id=p AND privacy_domain_id=d;
      GET DIAGNOSTICS removed=ROW_COUNT;
      IF removed<>1 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_EFFECT_COUNT'; END IF;
    END LOOP;
  ELSE
    -- Non-effect outcomes still have their original signed result in the outbox.
    p_event:=p_outcome;
  END IF;
  INSERT INTO facts.store_retirement_outbox(participant_id,privacy_domain_id,attempt_id,
    outcome_digest,event_payload,event_digest) VALUES(p,d,id,sha256(p_outcome),p_event,sha256(p_event));
  IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=(authority->>'expires_at_ms')::bigint THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_AUTHORITY_EXPIRED';
  END IF;
  RETURN p_outcome;
END $$;
ALTER FUNCTION facts.commit_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea,boolean)
  OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.commit_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea,boolean) FROM PUBLIC;

CREATE FUNCTION facts.execute_store_retirement(p_authority bytea,p_outcome bytea,
  p_event bytea,p_lineage bytea,p_nonce bytea,p_mac bytea) RETURNS bytea
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT facts.commit_store_retirement(p_authority,p_outcome,p_event,p_lineage,p_nonce,p_mac,false)
$$;
CREATE FUNCTION facts.cancel_store_retirement(p_authority bytea,p_outcome bytea,
  p_nonce bytea,p_mac bytea) RETURNS bytea
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT facts.commit_store_retirement(p_authority,p_outcome,NULL,NULL,p_nonce,p_mac,true)
$$;
ALTER FUNCTION facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
ALTER FUNCTION facts.cancel_store_retirement(bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea),
  facts.cancel_store_retirement(bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea),
  facts.cancel_store_retirement(bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;
GRANT DELETE ON facts.canonical_fact TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.guard_physical_fact_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM facts.retired_fact_payload r
    JOIN facts.store_retirement_attempt a USING(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    WHERE r.candidate_id=OLD.candidate_id AND r.participant_id=OLD.participant_id
      AND r.privacy_domain_id=OLD.privacy_domain_id AND a.state='APPLIED'
      AND r.retained_selection->>'payload_digest'=encode(sha256(OLD.canonical_payload),'hex')
      AND (r.retained_selection->>'payload_bytes')::bigint=octet_length(OLD.canonical_payload)) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_PHYSICAL_FACT_RETIREMENT_REJECTED';
  END IF;
  RETURN OLD;
END $$;
ALTER FUNCTION facts.guard_physical_fact_retirement() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.guard_physical_fact_retirement() FROM PUBLIC;
CREATE TRIGGER physical_fact_retirement BEFORE DELETE ON facts.canonical_fact
  FOR EACH ROW EXECUTE FUNCTION facts.guard_physical_fact_retirement();
