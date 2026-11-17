-- Historical delivery completion is separate from current readiness and from
-- governed retention. Runtime callers cannot write either outbox directly.
CREATE FUNCTION facts.verify_producer_delivery_capability(binding bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; mismatch integer:=0; i integer; BEGIN
  IF NOT coalesce(octet_length(binding)=32 AND octet_length(nonce)=32 AND octet_length(mac)=32,false) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_CAPABILITY';
  END IF;
  SELECT verifier_secret INTO STRICT secret FROM facts.mutation_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to('OPENPC_FACTSTORE_PRODUCER_DELIVERY_V1','UTF8')||binding||nonce,secret,'sha256');
  FOR i IN 0..31 LOOP mismatch:=mismatch | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
  IF mismatch<>0 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_CAPABILITY'; END IF;
  INSERT INTO facts.admission_delivery_capability VALUES(nonce,binding,mac);
END $$;
ALTER FUNCTION facts.verify_producer_delivery_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_producer_delivery_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_producer_delivery_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.guard_producer_delivery_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
  IF TG_OP<>'UPDATE' OR current_user<>'openpc_facts_lifecycle_owner'
    OR (to_jsonb(NEW)-'delivery_state') IS DISTINCT FROM (to_jsonb(OLD)-'delivery_state')
    OR OLD.delivery_state<>'PENDING' OR NEW.delivery_state<>'DELIVERED' THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_IMMUTABLE';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION facts.guard_producer_delivery_state() FROM PUBLIC;
DROP TRIGGER shard_publication_immutable ON facts.shard_publication;
CREATE TRIGGER shard_publication_immutable BEFORE UPDATE OR DELETE ON facts.shard_publication
  FOR EACH ROW EXECUTE FUNCTION facts.guard_producer_delivery_state();
CREATE TRIGGER producer_outbox_immutable BEFORE UPDATE OR DELETE ON facts.outbox
  FOR EACH ROW EXECUTE FUNCTION facts.guard_producer_delivery_state();
GRANT UPDATE(delivery_state) ON facts.shard_publication TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.complete_producer_delivery(material bytea,nonce bytea,mac bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE m jsonb; publication facts.shard_publication%ROWTYPE; original_manifest bytea; records bigint; BEGIN
  IF NOT coalesce(octet_length(material) BETWEEN 1 AND 2048,false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_MATERIAL';
  END IF;
  m:=convert_from(material,'UTF8')::jsonb;
  IF jsonb_typeof(m) IS DISTINCT FROM 'object'
    OR m-ARRAY['participantId','privacyDomainId','generationId','contentDigest','manifestDigest']<>'{}'
    OR (SELECT count(*) FROM jsonb_object_keys(m))<>5
    OR EXISTS(SELECT 1 FROM jsonb_each(m) field WHERE jsonb_typeof(field.value) IS DISTINCT FROM 'string') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_MATERIAL';
  END IF;
  PERFORM facts.assert_lifecycle_context(m->>'participantId',m->>'privacyDomainId');
  PERFORM facts.verify_producer_delivery_capability(sha256(material),nonce,mac);
  SELECT * INTO STRICT publication FROM facts.shard_publication p
    WHERE p.participant_id=m->>'participantId' AND p.privacy_domain_id=m->>'privacyDomainId'
      AND p.generation_id=m->>'generationId' FOR UPDATE;
  SELECT g.shard_cose_sign1 INTO STRICT original_manifest FROM facts.readiness_gate g
    WHERE g.participant_id=publication.participant_id AND g.privacy_domain_id=publication.privacy_domain_id
      AND g.generation_id=publication.generation_id AND g.shard_digest=publication.content_digest;
  IF m->>'contentDigest' IS DISTINCT FROM 'sha256:'||encode(publication.content_digest,'hex')
    OR m->>'manifestDigest' IS DISTINCT FROM 'sha256:'||encode(publication.manifest_digest,'hex')
    OR publication.manifest_digest IS DISTINCT FROM sha256(original_manifest)
    OR publication.descriptor IS DISTINCT FROM jsonb_build_object(
      'mediaType','application/vnd.openpc.fact-shard-manifest.v1+cbor',
      'digest','sha256:'||encode(publication.manifest_digest,'hex'),'size',octet_length(original_manifest))
    OR publication.delivery_state NOT IN ('PENDING','DELIVERED') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_PUBLICATION';
  END IF;
  SELECT count(*) INTO records FROM facts.canonical_identity_allocation a
    WHERE a.participant_id=publication.participant_id AND a.privacy_domain_id=publication.privacy_domain_id
      AND a.generation_id=publication.generation_id;
  IF records=0 OR records<>(SELECT count(*) FROM facts.canonical_fact f
      WHERE f.participant_id=publication.participant_id AND f.privacy_domain_id=publication.privacy_domain_id
        AND f.generation_id=publication.generation_id)
    OR EXISTS(SELECT 1 FROM facts.canonical_fact f
      LEFT JOIN facts.outbox o USING(candidate_id,participant_id,privacy_domain_id)
      LEFT JOIN facts.admission_delivery_event e USING(candidate_id,participant_id,privacy_domain_id)
      LEFT JOIN facts.control_admission_custody_ack c USING(candidate_id,participant_id,privacy_domain_id)
      LEFT JOIN facts.fleet_admission_ack a USING(candidate_id,participant_id,privacy_domain_id)
      WHERE f.participant_id=publication.participant_id AND f.privacy_domain_id=publication.privacy_domain_id
        AND f.generation_id=publication.generation_id AND (
          o.candidate_id IS NULL OR e.candidate_id IS NULL OR c.candidate_id IS NULL OR a.candidate_id IS NULL
          OR o.fact_digest IS DISTINCT FROM f.fact_digest OR e.generation_id IS DISTINCT FROM f.generation_id
          OR c.event_id IS DISTINCT FROM e.event_id OR a.event_id IS DISTINCT FROM e.event_id
          OR c.material_digest IS DISTINCT FROM sha256(c.material) OR a.material_digest IS DISTINCT FROM sha256(a.material)
          OR o.delivery_state NOT IN ('PENDING','DELIVERED')
          OR (publication.delivery_state='DELIVERED' AND o.delivery_state<>'DELIVERED'))) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_PRODUCER_DELIVERY_ACK_PENDING';
  END IF;
  IF publication.delivery_state='DELIVERED' THEN RETURN false; END IF;
  UPDATE facts.outbox o SET delivery_state='DELIVERED' FROM facts.canonical_fact f
    WHERE o.candidate_id=f.candidate_id AND o.participant_id=f.participant_id AND o.privacy_domain_id=f.privacy_domain_id
      AND f.participant_id=publication.participant_id AND f.privacy_domain_id=publication.privacy_domain_id
      AND f.generation_id=publication.generation_id AND o.delivery_state='PENDING';
  UPDATE facts.shard_publication p SET delivery_state='DELIVERED'
    WHERE p.participant_id=publication.participant_id AND p.privacy_domain_id=publication.privacy_domain_id
      AND p.generation_id=publication.generation_id;
  RETURN true;
END $$;
ALTER FUNCTION facts.complete_producer_delivery(bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.complete_producer_delivery(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.complete_producer_delivery(bytea,bytea,bytea) TO openpc_fact_bridge_writer;
