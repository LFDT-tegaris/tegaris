-- A removed source is not positive readiness. Close only its exact terminal
-- candidate prefix after independent admission, finality and signed retirement.
-- The immutable checkpoint explains closure without changing any original COSE.
CREATE TABLE facts.withdrawal_checkpoint (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  source_profile_id text NOT NULL,
  partition_id uuid NOT NULL,
  source_generation_id text NOT NULL,
  source_event_id uuid NOT NULL,
  source_sequence bigint NOT NULL CHECK(source_sequence>1),
  prefix_digest bytea NOT NULL CHECK(octet_length(prefix_digest)=32),
  material bytea NOT NULL CHECK(octet_length(material) BETWEEN 1 AND 4096),
  material_digest bytea NOT NULL CHECK(material_digest=sha256(material)),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(participant_id,privacy_domain_id,partition_id),
  UNIQUE(participant_id,privacy_domain_id,source_event_id),
  FOREIGN KEY(participant_id,privacy_domain_id,source_profile_id)
    REFERENCES facts.source_checkpoint(participant_id,privacy_domain_id,source_profile_id)
);
ALTER TABLE facts.withdrawal_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.withdrawal_checkpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.withdrawal_checkpoint TO openpc_facts_lifecycle_owner
  USING(facts.matches_context(participant_id,privacy_domain_id))
  WITH CHECK(facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.withdrawal_checkpoint FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING(facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.withdrawal_checkpoint FROM PUBLIC;
GRANT SELECT,INSERT ON facts.withdrawal_checkpoint TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.withdrawal_checkpoint TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
CREATE TRIGGER withdrawal_checkpoint_immutable BEFORE UPDATE OR DELETE ON facts.withdrawal_checkpoint
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();

CREATE FUNCTION facts.verify_withdrawal_checkpoint_capability(binding bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; mismatch integer:=0; i integer; BEGIN
  IF NOT coalesce(octet_length(binding)=32 AND octet_length(nonce)=32 AND octet_length(mac)=32,false) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_WITHDRAWAL_CAPABILITY';
  END IF;
  SELECT verifier_secret INTO STRICT secret FROM facts.mutation_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to('OPENPC_FACTSTORE_WITHDRAWAL_CHECKPOINT_V1','UTF8')||binding||nonce,secret,'sha256');
  FOR i IN 0..31 LOOP mismatch:=mismatch | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
  IF mismatch<>0 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_WITHDRAWAL_CAPABILITY'; END IF;
  INSERT INTO facts.admission_delivery_capability VALUES(nonce,binding,mac);
END $$;
ALTER FUNCTION facts.verify_withdrawal_checkpoint_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_withdrawal_checkpoint_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_withdrawal_checkpoint_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.close_source_withdrawal(material bytea,nonce bytea,mac bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE m jsonb; p text; d text; profile text; partition uuid; generation text; sequence bigint;
  prefix bytea; records bigint; first_sequence bigint; last_sequence bigint;
  prior facts.withdrawal_checkpoint%ROWTYPE; checkpoint facts.source_checkpoint%ROWTYPE;
BEGIN
  IF NOT coalesce(octet_length(material) BETWEEN 1 AND 4096,false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_WITHDRAWAL_MATERIAL';
  END IF;
  m:=convert_from(material,'UTF8')::jsonb;
  IF jsonb_typeof(m) IS DISTINCT FROM 'object'
    OR m-ARRAY['participantId','privacyDomainId','sourceProfileId','partitionId','sourceGenerationId',
      'sourceEventId','sourceSequence','sourcePayloadDigest','publicationDigest','prefixDigest','authorityDigest']<>'{}'
    OR (SELECT count(*) FROM jsonb_object_keys(m))<>11
    OR EXISTS(SELECT 1 FROM jsonb_each(m) f WHERE jsonb_typeof(f.value) IS DISTINCT FROM 'string')
    OR EXISTS(SELECT 1 FROM jsonb_each_text(m) f WHERE f.key LIKE '%Digest' AND f.value !~ '^sha256:[0-9a-f]{64}$') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_WITHDRAWAL_MATERIAL';
  END IF;
  p:=m->>'participantId'; d:=m->>'privacyDomainId'; profile:=m->>'sourceProfileId';
  partition:=(m->>'partitionId')::uuid; generation:=m->>'sourceGenerationId'; sequence:=(m->>'sourceSequence')::bigint;
  IF sequence<2 OR m->>'sourceSequence'<>sequence::text OR uuid_extract_version(partition)<>7
    OR uuid_extract_version((m->>'sourceEventId')::uuid)<>7 THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_WITHDRAWAL_MATERIAL';
  END IF;
  PERFORM facts.assert_lifecycle_context(p,d);
  PERFORM facts.verify_withdrawal_checkpoint_capability(sha256(material),nonce,mac);
  SELECT * INTO STRICT checkpoint FROM facts.source_checkpoint c
    WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.source_profile_id=profile FOR UPDATE;
  IF checkpoint.state NOT IN ('GAP_BLOCKED','COMPLETE') OR checkpoint.recovery_cursor_cbor IS NOT NULL THEN
    RETURN false;
  END IF;
  SELECT count(*),min(r.candidate_sequence),max(r.candidate_sequence),
    sha256(convert_to(string_agg(r.candidate_sequence::text||':'||r.event_id::text||':'||
      encode(sha256(r.event_payload_cbor),'hex'),E'\n' order by r.candidate_sequence),'UTF8'))
    INTO records,first_sequence,last_sequence,prefix FROM facts.candidate_feed_receipt r
    WHERE r.participant_id=p AND r.privacy_domain_id=d AND r.partition_id=partition;
  IF records<>sequence-1 OR first_sequence IS DISTINCT FROM 1 OR last_sequence IS DISTINCT FROM sequence-1
    OR m->>'prefixDigest' IS DISTINCT FROM 'sha256:'||encode(prefix,'hex')
    OR NOT EXISTS(SELECT 1 FROM facts.candidate_feed_receipt r
      WHERE r.participant_id=p AND r.privacy_domain_id=d AND r.partition_id=partition
        AND r.candidate_sequence=sequence-1 AND r.event_kind='CHECKPOINT' AND r.record_ordinal=r.record_count+1)
    OR EXISTS(SELECT 1 FROM facts.candidate_feed_receipt r
      WHERE r.participant_id=p AND r.privacy_domain_id=d AND r.partition_id=partition
        AND (r.source_profile_id<>profile OR r.source_generation_id<>generation)) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_WITHDRAWAL_PREFIX';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM facts.candidate_feed_receipt r
      WHERE r.participant_id=p AND r.privacy_domain_id=d AND r.partition_id=partition AND r.candidate_id IS NOT NULL)
    OR EXISTS(SELECT 1 FROM facts.candidate_feed_receipt r
      LEFT JOIN facts.canonical_fact f USING(candidate_id,participant_id,privacy_domain_id)
      LEFT JOIN facts.admission_inbox i USING(candidate_id,participant_id,privacy_domain_id)
      LEFT JOIN facts.readiness_gate g ON g.participant_id=f.participant_id AND g.privacy_domain_id=f.privacy_domain_id AND g.generation_id=f.generation_id
      LEFT JOIN facts.lineage_outbox l ON l.participant_id=r.participant_id AND l.privacy_domain_id=r.privacy_domain_id
        AND l.candidate_id=r.candidate_id AND l.source_event_id=(m->>'sourceEventId')::uuid
        AND l.event_type='io.openpc.fact.fact.retired.v1'
      WHERE r.participant_id=p AND r.privacy_domain_id=d AND r.partition_id=partition AND r.candidate_id IS NOT NULL
        AND (f.state IS DISTINCT FROM 'RETIRED' OR f.complete IS DISTINCT FROM true
          OR f.finality_verified IS DISTINCT FROM true OR f.finalized_at IS NULL
          OR i.state IS DISTINCT FROM 'APPLIED' OR i.source_profile_id IS DISTINCT FROM profile
          OR i.source_sequence>checkpoint.last_sequence OR g.state IS DISTINCT FROM 'STALE' OR g.shard_verified IS DISTINCT FROM false
          OR l.partition_id IS DISTINCT FROM partition OR l.source_sequence IS DISTINCT FROM sequence
          OR l.source_generation_id IS DISTINCT FROM generation
          OR 'sha256:'||encode(l.source_payload_digest,'hex') IS DISTINCT FROM m->>'sourcePayloadDigest'
          OR EXISTS(SELECT 1 FROM facts.fact_invalidation bad WHERE bad.candidate_id=r.candidate_id
            AND bad.participant_id=p AND bad.privacy_domain_id=d AND bad.reason<>'RETIREMENT'))) THEN
    RETURN false;
  END IF;
  SELECT * INTO prior FROM facts.withdrawal_checkpoint c
    WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.partition_id=partition;
  IF FOUND THEN
    IF convert_from(prior.material,'UTF8')::jsonb-'authorityDigest' IS DISTINCT FROM m-'authorityDigest' THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_WITHDRAWAL_REPLAY';
    END IF;
  ELSE
    INSERT INTO facts.withdrawal_checkpoint(participant_id,privacy_domain_id,source_profile_id,partition_id,
      source_generation_id,source_event_id,source_sequence,prefix_digest,material,material_digest)
      VALUES(p,d,profile,partition,generation,(m->>'sourceEventId')::uuid,sequence,prefix,material,sha256(material));
  END IF;
  -- A source-profile checkpoint may span partitions. Closing one cannot hide
  -- another partition's active, missing, incomplete or reorg-affected facts.
  IF EXISTS(SELECT 1 FROM facts.admission_inbox i
    LEFT JOIN facts.canonical_fact f USING(candidate_id,participant_id,privacy_domain_id)
    LEFT JOIN facts.candidate_feed_receipt r USING(candidate_id,participant_id,privacy_domain_id)
    LEFT JOIN facts.withdrawal_checkpoint c ON c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
      AND c.partition_id=r.partition_id AND c.source_profile_id=r.source_profile_id AND c.source_generation_id=r.source_generation_id
    WHERE i.participant_id=p AND i.privacy_domain_id=d AND i.source_profile_id=profile
      AND (f.state IS DISTINCT FROM 'RETIRED' OR i.state IS DISTINCT FROM 'APPLIED' OR c.partition_id IS NULL)) THEN
    RETURN false;
  END IF;
  IF checkpoint.state='COMPLETE' THEN RETURN false; END IF;
  UPDATE facts.source_checkpoint c SET state='COMPLETE',updated_at=clock_timestamp()
    WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.source_profile_id=profile;
  RETURN true;
END $$;
ALTER FUNCTION facts.close_source_withdrawal(bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.close_source_withdrawal(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.close_source_withdrawal(bytea,bytea,bytea) TO openpc_fact_bridge_writer;
