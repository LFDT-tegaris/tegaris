-- SQLx-owned candidate projection retirement; psql envelope matches 0001-0007.
-- No Control authority, host key or verifier secret is provisioned here.
\set ON_ERROR_STOP on
\if :{?openpc_migration_checksum}
\else
  \quit 3
\endif
\if :{?openpc_migration_profile}
\else
  \quit 3
\endif
\connect openpc_candidate_index
SET ROLE openpc_candidate_index_owner;
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
LOCK TABLE candidate.candidate_event IN ACCESS EXCLUSIVE MODE;
SET LOCAL search_path=pg_catalog;
-- FORCE RLS normally protects the non-bypass owner. This transactional migration
-- alone must copy every tenant; the source's FORCE flag is restored before commit.
ALTER TABLE candidate.candidate_event NO FORCE ROW LEVEL SECURITY;
CREATE TABLE candidate.retained_candidate_identity (
  candidate_event_id uuid PRIMARY KEY,
  participant_id uuid NOT NULL,
  privacy_domain_id uuid NOT NULL,
  projection_generation_id uuid NOT NULL,
  record_id text,
  payload_digest bytea NOT NULL CHECK(octet_length(payload_digest)=32),
  payload_bytes bigint NOT NULL CHECK(payload_bytes>0),
  original_identity jsonb NOT NULL CHECK(NOT original_identity ? 'payload_cbor'),
  UNIQUE(participant_id,privacy_domain_id,candidate_event_id),
  UNIQUE(projection_generation_id,record_id),
  FOREIGN KEY(participant_id,privacy_domain_id,projection_generation_id)
    REFERENCES candidate.projection_generation(participant_id,privacy_domain_id,projection_generation_id)
);
INSERT INTO candidate.retained_candidate_identity
  SELECT candidate_event_id,participant_id,privacy_domain_id,projection_generation_id,
    record_id,payload_digest,octet_length(payload_cbor),to_jsonb(e)-'payload_cbor'
  FROM candidate.candidate_event e;
-- Relations keep their original candidate identity after the projection is gone.
DO $$ DECLARE c record; definition text; BEGIN
  IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f'
    AND confrelid='candidate.candidate_event'::regclass AND connamespace<>'candidate'::regnamespace) THEN
    RAISE EXCEPTION 'OPENPC_CANDIDATE_RETIREMENT_EXTERNAL_REFERENCE_REQUIRES_OWNER';
  END IF;
  FOR c IN SELECT con.conrelid,con.conname,pg_get_constraintdef(con.oid) definition,rel.relforcerowsecurity
    FROM pg_constraint con JOIN pg_class rel ON rel.oid=con.conrelid
    WHERE con.contype='f' AND con.confrelid='candidate.candidate_event'::regclass
  LOOP
    definition:=replace(c.definition,'REFERENCES candidate.candidate_event(',
      'REFERENCES candidate.retained_candidate_identity(');
    IF definition=c.definition THEN RAISE EXCEPTION 'OPENPC_CANDIDATE_RETIREMENT_FOREIGN_KEY_UNRECOGNIZED'; END IF;
    IF c.relforcerowsecurity THEN
      EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY',c.conrelid::regclass);
    END IF;
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.conrelid::regclass,c.conname);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.conrelid::regclass,c.conname,definition);
    IF c.relforcerowsecurity THEN
      EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',c.conrelid::regclass);
    END IF;
  END LOOP;
END $$;
ALTER TABLE candidate.candidate_event ADD CONSTRAINT candidate_retained_identity
  FOREIGN KEY(participant_id,privacy_domain_id,candidate_event_id)
  REFERENCES candidate.retained_candidate_identity(participant_id,privacy_domain_id,candidate_event_id);
ALTER TABLE candidate.candidate_event FORCE ROW LEVEL SECURITY;
CREATE TABLE candidate.store_retirement_attempt (
  participant_id uuid NOT NULL,
  privacy_domain_id uuid NOT NULL,
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
CREATE TABLE candidate.retired_candidate_payload (
  candidate_id uuid PRIMARY KEY REFERENCES candidate.retained_candidate_identity(candidate_event_id) ON DELETE RESTRICT,
  participant_id uuid NOT NULL,
  privacy_domain_id uuid NOT NULL,
  attempt_id text NOT NULL,
  outcome_digest bytea NOT NULL,
  retained_selection jsonb NOT NULL,
  retired_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    REFERENCES candidate.store_retirement_attempt(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    ON DELETE RESTRICT
);
CREATE INDEX store_retirement_business_intent ON candidate.store_retirement_attempt
  (participant_id,privacy_domain_id,business_intent_id);
CREATE TABLE candidate.store_retirement_outbox (
  participant_id uuid NOT NULL,
  privacy_domain_id uuid NOT NULL,
  attempt_id text NOT NULL,
  outcome_digest bytea NOT NULL,
  event_payload bytea NOT NULL CHECK(octet_length(event_payload) BETWEEN 1 AND 1048576),
  event_digest bytea NOT NULL CHECK(event_digest=sha256(event_payload)),
  created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(participant_id,privacy_domain_id,attempt_id),
  FOREIGN KEY(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    REFERENCES candidate.store_retirement_attempt(participant_id,privacy_domain_id,attempt_id,outcome_digest)
    ON DELETE RESTRICT
);

DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['retained_candidate_identity','store_retirement_attempt',
    'retired_candidate_payload','store_retirement_outbox'] LOOP
    EXECUTE format('ALTER TABLE candidate.%I ENABLE ROW LEVEL SECURITY',target);
    EXECUTE format('ALTER TABLE candidate.%I FORCE ROW LEVEL SECURITY',target);
    EXECUTE format('CREATE POLICY privacy_isolation ON candidate.%I USING
      (openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
      WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))',target);
    EXECUTE format('REVOKE ALL ON candidate.%I FROM PUBLIC',target);
    EXECUTE format('GRANT SELECT ON candidate.%I TO openpc_indexer_writer,openpc_candidate_index_reader,openpc_backup_operator',target);
    EXECUTE format('CREATE TRIGGER retirement_immutable BEFORE UPDATE OR DELETE ON candidate.%I
      FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation()',target);
  END LOOP;
END $$;
-- Separate host-installed secret and fixed-domain nonce custody. Neither is
-- readable or writable by any runtime/manager/reader role.
CREATE TABLE candidate.retirement_capability_secret (
  secret_version integer PRIMARY KEY CHECK(secret_version=1),
  verifier_secret bytea NOT NULL CHECK(octet_length(verifier_secret)=32)
);
REVOKE ALL ON candidate.retirement_capability_secret FROM PUBLIC;
CREATE TRIGGER retirement_secret_immutable BEFORE UPDATE OR DELETE ON candidate.retirement_capability_secret
  FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE TABLE candidate.retirement_capability_replay (
  nonce bytea PRIMARY KEY CHECK(octet_length(nonce)=32),
  domain text NOT NULL CHECK(domain IN ('OPENPC_CANDIDATE_INDEX_RETIREMENT_EXECUTION_V1',
    'OPENPC_CANDIDATE_INDEX_RETIREMENT_CANCELLATION_V1')),
  binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
  mac bytea NOT NULL CHECK(octet_length(mac)=32),
  consumed_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE candidate.retirement_capability_replay OWNER TO openpc_candidate_index_owner;
REVOKE ALL ON candidate.retirement_capability_replay FROM PUBLIC;

CREATE FUNCTION candidate.consume_retirement_capability(p_domain text,p_attempt bytea,
  p_authority bytea,p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE secret bytea; binding bytea; expected bytea; mismatch integer:=0; n integer;
BEGIN
  IF p_domain NOT IN ('OPENPC_CANDIDATE_INDEX_RETIREMENT_EXECUTION_V1','OPENPC_CANDIDATE_INDEX_RETIREMENT_CANCELLATION_V1')
    OR p_domain IS NULL OR p_attempt IS NULL OR octet_length(p_attempt)<>32
    OR p_authority IS NULL OR octet_length(p_authority) NOT BETWEEN 1 AND 1048576
    OR p_outcome IS NULL OR octet_length(p_outcome) NOT BETWEEN 1 AND 1048576
    OR p_nonce IS NULL OR octet_length(p_nonce)<>32 OR p_mac IS NULL OR octet_length(p_mac)<>32 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CAPABILITY_INVALID';
  END IF;
  binding:=sha256(convert_to('OPENPC_CANDIDATE_INDEX_RETIREMENT_BINDING_V1','UTF8')||
    p_attempt||sha256(p_authority)||sha256(p_outcome));
  SELECT verifier_secret INTO STRICT secret FROM candidate.retirement_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to(p_domain,'UTF8')||binding||p_nonce,secret,'sha256');
  FOR n IN 0..31 LOOP mismatch:=mismatch|(get_byte(expected,n)#get_byte(p_mac,n)); END LOOP;
  IF mismatch<>0 THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_CAPABILITY_INVALID';
  END IF;
  INSERT INTO candidate.retirement_capability_replay VALUES(p_nonce,p_domain,binding,p_mac,clock_timestamp());
END $$;
ALTER FUNCTION candidate.consume_retirement_capability(text,bytea,bytea,bytea,bytea,bytea)
  OWNER TO openpc_candidate_index_owner;
REVOKE ALL ON FUNCTION candidate.consume_retirement_capability(text,bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION candidate.verify_retirement_execution(p_attempt bytea,p_authority bytea,
  p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT candidate.consume_retirement_capability('OPENPC_CANDIDATE_INDEX_RETIREMENT_EXECUTION_V1',
    p_attempt,p_authority,p_outcome,p_nonce,p_mac)
$$;
CREATE FUNCTION candidate.verify_retirement_cancellation(p_attempt bytea,p_authority bytea,
  p_outcome bytea,p_nonce bytea,p_mac bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT candidate.consume_retirement_capability('OPENPC_CANDIDATE_INDEX_RETIREMENT_CANCELLATION_V1',
    p_attempt,p_authority,p_outcome,p_nonce,p_mac)
$$;
ALTER FUNCTION candidate.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_candidate_index_owner;
ALTER FUNCTION candidate.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_candidate_index_owner;
REVOKE ALL ON FUNCTION candidate.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea),
  candidate.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea),
  candidate.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea) TO openpc_candidate_index_owner;

-- No durable STARTED row is committed alone. This scope fence closes the absent
-- row race; the terminal attempt row is then locked and compared by both paths.
-- A process lost before commit therefore remains UNKNOWN, never NO_EFFECT.

-- Absent attempts serialize too. The generation lock is the existing writer,
-- reorg and publication boundary; partition sequences/checkpoints remain intact.
CREATE FUNCTION candidate.lock_store_retirement(p uuid,d uuid,g uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
  IF session_user<>'openpc_indexer_writer' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_ROLE';
  END IF;
  PERFORM openpc.assert_request_context(true);
  IF p IS DISTINCT FROM openpc.current_participant_id() OR d IS DISTINCT FROM openpc.current_privacy_domain_id() THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_SCOPE';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('candidate-retirement:'||p::text||':'||d::text,0));
  PERFORM 1 FROM candidate.projection_generation
    WHERE participant_id=p AND privacy_domain_id=d AND projection_generation_id=g FOR UPDATE;
END $$;
REVOKE ALL ON FUNCTION candidate.lock_store_retirement(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.lock_store_retirement(uuid,uuid,uuid) TO openpc_indexer_writer;

CREATE FUNCTION candidate.check_store_retirement(attempt jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p uuid:=(attempt#>>'{scope,participant_id}')::uuid;
 d uuid:=(attempt#>>'{scope,privacy_domain_id}')::uuid;
 selection jsonb:=attempt->'selection'; source jsonb:=selection->'source'; selected jsonb;
 actual record; previous_sequence numeric:=0; g uuid:=(source->>'generation_id')::uuid;
BEGIN
 PERFORM candidate.lock_store_retirement(p,d,g);
 IF attempt->>'store' IS DISTINCT FROM 'openpc_candidate_index'
   OR selection->>'class' IS DISTINCT FROM 'CANDIDATE_PROJECTION'
   OR jsonb_typeof(selection->'rows') IS DISTINCT FROM 'array'
   OR jsonb_array_length(selection->'rows') NOT BETWEEN 1 AND 256 THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_SELECTION';
 END IF;
 IF floor(extract(epoch FROM clock_timestamp())*1000)::numeric <
   (attempt#>>'{governance,retention_not_before_ms}')::numeric THEN RETURN 'RETENTION_NOT_ELAPSED'; END IF;
 FOR selected IN SELECT value FROM jsonb_array_elements(selection->'rows') LOOP
   IF (selected->>'candidate_feed_sequence')::numeric<=previous_sequence THEN
     RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_CANDIDATE_RETIREMENT_ORDER'; END IF;
   previous_sequence:=(selected->>'candidate_feed_sequence')::numeric;
   BEGIN
   SELECT e.*,b.finality_state,b.finality_kind,b.finality_evidence_digest,b.block_number,
     b.finality_head_number,b.finality_head_hash,sp.finality_mode,sp.confirmation_count,
     gen.state generation_state,part.source_profile_id,pub.state publication_state,pub.publication_digest,
     o.aggregate_sequence,o.state delivery_state,c.position_digest checkpoint_digest,
     c.state checkpoint_state,c.completed_at,c.range_start,c.range_end,
     i.payload_digest retained_digest,i.payload_bytes retained_bytes
   INTO STRICT actual FROM candidate.candidate_event e
   JOIN candidate.projection_generation gen USING(participant_id,privacy_domain_id,projection_generation_id)
   JOIN candidate.candidate_partition part ON part.participant_id=e.participant_id
     AND part.privacy_domain_id=e.privacy_domain_id AND part.projection_generation_id=e.projection_generation_id
     AND part.candidate_partition_id=e.candidate_partition_id
   JOIN candidate.source_profile sp ON sp.participant_id=e.participant_id
     AND sp.privacy_domain_id=e.privacy_domain_id AND sp.source_profile_id=part.source_profile_id
   JOIN candidate.source_publication pub ON pub.participant_id=e.participant_id
     AND pub.privacy_domain_id=e.privacy_domain_id AND pub.projection_generation_id=e.projection_generation_id
   JOIN candidate.candidate_block b ON b.participant_id=e.participant_id AND b.privacy_domain_id=e.privacy_domain_id
     AND b.projection_generation_id=e.projection_generation_id AND b.candidate_block_id=e.candidate_block_id
     AND b.candidate_partition_id=e.candidate_partition_id
   JOIN candidate.outbox_event o ON o.participant_id=e.participant_id AND o.privacy_domain_id=e.privacy_domain_id
     AND o.aggregate_type='candidate-partition' AND o.aggregate_id=e.candidate_partition_id
     AND o.event_type='io.openpc.indexer.projection.candidate.observed.v1'
     AND o.payload_json->>'candidateId'='urn:openpc:candidate:'||e.candidate_event_id::text
   JOIN candidate.checkpoint c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
     AND c.projection_generation_id=e.projection_generation_id AND c.candidate_partition_id=e.candidate_partition_id
     AND o.payload_json->>'sourceCursorDigest'='sha256:'||encode(c.position_digest,'hex')
   JOIN candidate.retained_candidate_identity i ON i.candidate_event_id=e.candidate_event_id
     AND i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
   WHERE e.participant_id=p AND e.privacy_domain_id=d AND e.candidate_event_id=(selected->>'candidate_id')::uuid
   FOR UPDATE OF e,gen,part,sp,pub,b,o,c,i;
   EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RETURN 'SOURCE_CHANGED'; END;
   IF actual.projection_generation_id<>g OR actual.candidate_partition_id<>(source->>'partition_id')::uuid
     OR actual.source_profile_id<>(source->>'profile_id')::uuid THEN RETURN 'GENERATION_CHANGED'; END IF;
   IF encode(actual.publication_digest,'hex') IS DISTINCT FROM source->>'identity_digest'
     OR encode(sha256(actual.payload_cbor),'hex') IS DISTINCT FROM selected->>'payload_digest'
     OR octet_length(actual.payload_cbor)::text IS DISTINCT FROM selected->>'payload_bytes'
     OR actual.aggregate_sequence::text IS DISTINCT FROM selected->>'candidate_feed_sequence'
     OR encode(actual.checkpoint_digest,'hex') IS DISTINCT FROM selected->>'checkpoint_digest'
     OR actual.retained_digest<>actual.payload_digest OR actual.retained_bytes<>octet_length(actual.payload_cbor)
     THEN RETURN 'SOURCE_CHANGED'; END IF;
   IF actual.generation_state='REORG' OR actual.checkpoint_state='REORG' OR actual.finality_state='REMOVED'
     OR EXISTS(SELECT 1 FROM candidate.candidate_invalidation inv WHERE inv.participant_id=p
       AND inv.privacy_domain_id=d AND inv.projection_generation_id=g
       AND inv.candidate_partition_id=actual.candidate_partition_id
       AND actual.block_number BETWEEN inv.affected_start AND inv.affected_end) THEN RETURN 'REORG_FENCED'; END IF;
   IF actual.checkpoint_state<>'COMPLETE' OR actual.completed_at IS NULL
     OR actual.block_number NOT BETWEEN actual.range_start AND actual.range_end
     OR actual.finality_state NOT IN ('SAFE','FINALIZED') OR actual.finality_kind='UNFINALIZED'
     OR actual.finality_evidence_digest IS NULL
     OR actual.finality_mode IS DISTINCT FROM actual.finality_kind
     OR (actual.finality_mode='CONFIRMATIONS' AND (actual.finality_head_number IS NULL
       OR actual.finality_head_hash IS NULL OR actual.confirmation_count IS NULL
       OR actual.finality_head_number<actual.block_number+actual.confirmation_count-1))
     THEN RETURN 'CHECKPOINT_INCOMPLETE'; END IF;
   -- The existing reconciler durably fences lost source authority as STALE/FENCED.
   -- FENCED cannot return to PUBLISHED; no fabricated terminal transition is needed.
   IF actual.generation_state NOT IN ('STALE','RETIRED') OR actual.publication_state NOT IN ('FENCED','RETIRED')
     OR actual.state NOT IN ('VALIDATED_CANDIDATE','SUPERSEDED') THEN RETURN 'READINESS_PROTECTED'; END IF;
   IF EXISTS(SELECT 1 FROM candidate.outbox_event o WHERE o.participant_id=p AND o.privacy_domain_id=d
     AND o.aggregate_type='candidate-partition' AND o.aggregate_id=actual.candidate_partition_id
     AND o.state<>'DELIVERED') THEN RETURN 'PUBLICATION_PROTECTED'; END IF;
   -- A referencing generation cannot become serving between this check and
   -- deletion. Inserts of new relations also lock the selected generation.
   PERFORM 1 FROM candidate.projection_generation gen
     WHERE gen.participant_id=p AND gen.privacy_domain_id=d AND gen.projection_generation_id IN
       (SELECT rel.projection_generation_id FROM candidate.candidate_relation rel
        WHERE rel.participant_id=p AND rel.privacy_domain_id=d
          AND (rel.source_candidate_event_id=actual.candidate_event_id OR rel.target_candidate_event_id=actual.candidate_event_id))
     ORDER BY gen.projection_generation_id FOR UPDATE;
   IF EXISTS(SELECT 1 FROM candidate.candidate_relation rel JOIN candidate.projection_generation gen
     USING(participant_id,privacy_domain_id,projection_generation_id)
     WHERE rel.participant_id=p AND rel.privacy_domain_id=d AND gen.state<>'RETIRED'
       AND (rel.source_candidate_event_id=actual.candidate_event_id OR rel.target_candidate_event_id=actual.candidate_event_id))
     THEN RETURN 'REFERENCES_PROTECTED'; END IF;
 END LOOP;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION candidate.check_store_retirement(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.check_store_retirement(jsonb) TO openpc_indexer_writer;
-- The host verifier authenticates the committed Control admission and its hold/
-- policy/approval revision; SQL rechecks local predicates and original bindings.
-- A caller-supplied eligibility/hold flag is never a substitute for that receipt.
-- Private common effect owner. Only the two fixed-purpose wrappers below can
-- call it. No caller-supplied "verified" or "eligible" field reaches this owner.
CREATE FUNCTION candidate.commit_store_retirement(p_authority bytea,p_outcome bytea,p_event bytea,
  p_lineage bytea,p_nonce bytea,p_mac bytea,p_cancel boolean) RETURNS bytea
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE authority jsonb:=convert_from(p_authority,'UTF8')::jsonb->'claims';
  outcome jsonb:=convert_from(p_outcome,'UTF8')::jsonb->'claims';
  attempt jsonb:=authority->'attempt'; effect jsonb:=outcome#>'{outcome,effect}';
  p uuid:=(attempt#>>'{scope,participant_id}')::uuid; d uuid:=(attempt#>>'{scope,privacy_domain_id}')::uuid;
  id text:=attempt->>'attempt_id'; digest bytea:=decode(outcome#>>'{outcome,attempt_digest}','hex');
  previous candidate.store_retirement_attempt%ROWTYPE; blocker text; selected jsonb;
  count_rows bigint; count_bytes bigint; removed bigint; now_ms bigint;
BEGIN
  PERFORM candidate.lock_store_retirement(p,d,(attempt#>>'{selection,source,generation_id}')::uuid);
  IF p_cancel THEN
    PERFORM candidate.verify_retirement_cancellation(digest,p_authority,p_outcome,p_nonce,p_mac);
  ELSE
    PERFORM candidate.verify_retirement_execution(digest,p_authority,p_outcome,p_nonce,p_mac);
  END IF;
  IF authority->'host' IS DISTINCT FROM outcome->'host'
    OR outcome->>'attempt_id' IS DISTINCT FROM id
    OR outcome->>'business_intent_id' IS DISTINCT FROM attempt->>'business_intent_id'
    OR attempt->>'store' IS DISTINCT FROM 'openpc_candidate_index' THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_BINDING_REJECTED';
  END IF;
  SELECT * INTO previous FROM candidate.store_retirement_attempt
    WHERE participant_id=p AND privacy_domain_id=d AND attempt_id=id FOR UPDATE;
  IF FOUND THEN
    IF previous.attempt_digest<>digest OR previous.attempt_document IS DISTINCT FROM attempt THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_ALTERED_REPLAY';
    END IF;
    RETURN previous.signed_outcome;
  END IF;
  IF EXISTS(SELECT 1 FROM candidate.store_retirement_attempt prior
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
    blocker:=candidate.check_store_retirement(attempt);
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
  INSERT INTO candidate.store_retirement_attempt VALUES(p,d,id,attempt->>'business_intent_id',digest,
    decode(attempt->>'selection_digest','hex'),(attempt#>>'{governance,lifecycle_revision}')::bigint,
    attempt,p_authority,sha256(p_authority),effect->>'state',p_outcome,sha256(p_outcome),
    (outcome->>'completed_at_ms')::bigint);
  IF effect->>'state'='APPLIED' THEN
    FOR selected IN SELECT value FROM jsonb_array_elements(attempt#>'{selection,rows}') LOOP
      INSERT INTO candidate.retired_candidate_payload
        SELECT (selected->>'candidate_id')::uuid,p,d,id,sha256(p_outcome),selected,clock_timestamp()
        FROM candidate.candidate_event f WHERE f.candidate_event_id=(selected->>'candidate_id')::uuid
          AND f.participant_id=p AND f.privacy_domain_id=d;
      DELETE FROM candidate.candidate_event WHERE candidate_event_id=(selected->>'candidate_id')::uuid
        AND participant_id=p AND privacy_domain_id=d;
      GET DIAGNOSTICS removed=ROW_COUNT;
      IF removed<>1 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIREMENT_EFFECT_COUNT'; END IF;
    END LOOP;
  ELSE
    -- Non-effect outcomes still have their original signed result in the outbox.
    p_event:=p_outcome;
  END IF;
  INSERT INTO candidate.store_retirement_outbox(participant_id,privacy_domain_id,attempt_id,
    outcome_digest,event_payload,event_digest) VALUES(p,d,id,sha256(p_outcome),p_event,sha256(p_event));
  IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=(authority->>'expires_at_ms')::bigint THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_RETIREMENT_AUTHORITY_EXPIRED';
  END IF;
  RETURN p_outcome;
END $$;
ALTER FUNCTION candidate.commit_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea,boolean)
  OWNER TO openpc_candidate_index_owner;
REVOKE ALL ON FUNCTION candidate.commit_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea,boolean) FROM PUBLIC;

CREATE FUNCTION candidate.execute_store_retirement(p_authority bytea,p_outcome bytea,
  p_event bytea,p_lineage bytea,p_nonce bytea,p_mac bytea) RETURNS bytea
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT candidate.commit_store_retirement(p_authority,p_outcome,p_event,p_lineage,p_nonce,p_mac,false)
$$;
CREATE FUNCTION candidate.cancel_store_retirement(p_authority bytea,p_outcome bytea,
  p_nonce bytea,p_mac bytea) RETURNS bytea
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT candidate.commit_store_retirement(p_authority,p_outcome,NULL,NULL,p_nonce,p_mac,true)
$$;
ALTER FUNCTION candidate.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea) OWNER TO openpc_candidate_index_owner;
ALTER FUNCTION candidate.cancel_store_retirement(bytea,bytea,bytea,bytea) OWNER TO openpc_candidate_index_owner;
REVOKE ALL ON FUNCTION candidate.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea),
  candidate.cancel_store_retirement(bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candidate.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea),
  candidate.cancel_store_retirement(bytea,bytea,bytea,bytea) TO openpc_indexer_writer;



-- Permanent identity insert rejects both original-ID and natural-key rebuilds.
CREATE FUNCTION candidate.retain_candidate_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 PERFORM 1 FROM candidate.projection_generation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND projection_generation_id=NEW.projection_generation_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM candidate.retired_candidate_payload retired JOIN candidate.retained_candidate_identity i
   ON i.candidate_event_id=retired.candidate_id WHERE i.projection_generation_id=NEW.projection_generation_id) THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIRED_CANDIDATE_GENERATION'; END IF;
 INSERT INTO candidate.retained_candidate_identity VALUES(NEW.candidate_event_id,NEW.participant_id,
   NEW.privacy_domain_id,NEW.projection_generation_id,NEW.record_id,NEW.payload_digest,
   octet_length(NEW.payload_cbor),to_jsonb(NEW)-'payload_cbor');
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION candidate.retain_candidate_identity() FROM PUBLIC;
CREATE TRIGGER retain_candidate_identity BEFORE INSERT ON candidate.candidate_event
 FOR EACH ROW EXECUTE FUNCTION candidate.retain_candidate_identity();

CREATE FUNCTION candidate.guard_physical_candidate_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM candidate.retired_candidate_payload r
   JOIN candidate.store_retirement_attempt a USING(participant_id,privacy_domain_id,attempt_id,outcome_digest)
   WHERE r.candidate_id=OLD.candidate_event_id AND r.participant_id=OLD.participant_id
     AND r.privacy_domain_id=OLD.privacy_domain_id AND a.state='APPLIED'
     AND r.retained_selection->>'payload_digest'=encode(sha256(OLD.payload_cbor),'hex')
     AND (r.retained_selection->>'payload_bytes')::bigint=octet_length(OLD.payload_cbor)) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_PHYSICAL_CANDIDATE_RETIREMENT_REJECTED'; END IF;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION candidate.guard_physical_candidate_retirement() FROM PUBLIC;
CREATE TRIGGER physical_candidate_retirement BEFORE DELETE ON candidate.candidate_event
 FOR EACH ROW EXECUTE FUNCTION candidate.guard_physical_candidate_retirement();

CREATE FUNCTION candidate.guard_retired_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF ((TG_TABLE_NAME='projection_generation' AND NEW.state::text NOT IN ('STALE','RETIRED'))
     OR (TG_TABLE_NAME='source_publication' AND NEW.state::text NOT IN ('FENCED','RETIRED')))
   AND (EXISTS(SELECT 1 FROM candidate.retired_candidate_payload r JOIN candidate.retained_candidate_identity i
     ON i.candidate_event_id=r.candidate_id WHERE i.projection_generation_id=NEW.projection_generation_id)
     OR EXISTS(SELECT 1 FROM candidate.candidate_relation rel JOIN candidate.retired_candidate_payload r
       ON r.candidate_id IN (rel.source_candidate_event_id,rel.target_candidate_event_id)
       WHERE rel.projection_generation_id=NEW.projection_generation_id)) THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIRED_CANDIDATE_READINESS'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION candidate.guard_retired_generation() FROM PUBLIC;
CREATE TRIGGER retired_generation_guard BEFORE UPDATE ON candidate.projection_generation
 FOR EACH ROW EXECUTE FUNCTION candidate.guard_retired_generation();
CREATE TRIGGER retired_publication_guard BEFORE UPDATE ON candidate.source_publication
 FOR EACH ROW EXECUTE FUNCTION candidate.guard_retired_generation();


-- Direct runtime DML must take the same generation fence as supported writers.
-- Incoming references cannot appear between the retirement check and commit.
CREATE FUNCTION candidate.guard_retirement_reference() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF TG_TABLE_NAME='candidate_relation' THEN
   PERFORM 1 FROM candidate.projection_generation g
     WHERE g.projection_generation_id IN (SELECT i.projection_generation_id
       FROM candidate.retained_candidate_identity i WHERE i.candidate_event_id IN
         (NEW.source_candidate_event_id,NEW.target_candidate_event_id))
     ORDER BY g.projection_generation_id FOR UPDATE;
   IF EXISTS(SELECT 1 FROM candidate.retired_candidate_payload r WHERE r.candidate_id IN
     (NEW.source_candidate_event_id,NEW.target_candidate_event_id)) THEN
     RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIRED_CANDIDATE_REFERENCE'; END IF;
 ELSIF NEW.aggregate_type='candidate-partition' THEN
   PERFORM 1 FROM candidate.projection_generation g JOIN candidate.candidate_partition part
     USING(participant_id,privacy_domain_id,projection_generation_id)
     WHERE part.candidate_partition_id=NEW.aggregate_id ORDER BY g.projection_generation_id FOR UPDATE OF g;
   IF NEW.state<>'DELIVERED' AND EXISTS(SELECT 1 FROM candidate.retired_candidate_payload r
     JOIN candidate.retained_candidate_identity i ON i.candidate_event_id=r.candidate_id
     JOIN candidate.candidate_partition part ON part.projection_generation_id=i.projection_generation_id
     WHERE part.candidate_partition_id=NEW.aggregate_id) THEN
     RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_RETIRED_CANDIDATE_PUBLICATION'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION candidate.guard_retirement_reference() FROM PUBLIC;
CREATE TRIGGER retired_relation_guard BEFORE INSERT ON candidate.candidate_relation
 FOR EACH ROW EXECUTE FUNCTION candidate.guard_retirement_reference();
CREATE TRIGGER retired_outbox_guard BEFORE INSERT OR UPDATE OF state ON candidate.outbox_event
 FOR EACH ROW EXECUTE FUNCTION candidate.guard_retirement_reference();

INSERT INTO candidate.schema_migration(migration_id,migration_checksum,profile,phase)
VALUES('OPENPC-MIG-CANDIDATE-0008',decode(substring(:'openpc_migration_checksum' from 8),'hex')::openpc.sha256_bytes,
 :'openpc_migration_profile'::candidate.migration_profile,'M1_ADDITIVE_INACTIVE');
COMMIT;
RESET ROLE;
