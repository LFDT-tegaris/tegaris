-- SQLx-owned delivery identity for the existing admission outbox. Original
-- candidates, Fact UUIDs, signed bytes and lifecycle/readiness remain unchanged.
-- Materialization does not acknowledge any consumer or permit retirement.
CREATE TABLE facts.admission_delivery_head (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_type text NOT NULL CHECK(fact_type IN ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION')),
  sequence bigint NOT NULL CHECK(sequence>0),
  PRIMARY KEY(participant_id,privacy_domain_id,fact_type)
);
CREATE TABLE facts.admission_delivery_event (
  candidate_id text PRIMARY KEY REFERENCES facts.outbox(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  fact_type text NOT NULL,
  sequence bigint NOT NULL CHECK(sequence>0),
  event_id uuid NOT NULL UNIQUE CHECK(uuid_extract_version(event_id)=7),
  generation_id text NOT NULL,
  source_material bytea NOT NULL CHECK(octet_length(source_material) BETWEEN 1 AND 16384),
  source_material_digest bytea NOT NULL CHECK(source_material_digest=sha256(source_material)),
  data_bytes bytea NOT NULL CHECK(octet_length(data_bytes) BETWEEN 1 AND 4096),
  envelope jsonb NOT NULL,
  materialized_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(participant_id,privacy_domain_id,fact_type,sequence),
  FOREIGN KEY(participant_id,privacy_domain_id,fact_type)
    REFERENCES facts.admission_delivery_head(participant_id,privacy_domain_id,fact_type) ON DELETE RESTRICT
);
CREATE TABLE facts.admission_delivery_capability (
  nonce bytea PRIMARY KEY CHECK(octet_length(nonce)=32),
  binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
  mac bytea NOT NULL CHECK(octet_length(mac)=32)
);
ALTER TABLE facts.admission_delivery_capability OWNER TO openpc_facts_capability_owner;
ALTER TABLE facts.admission_delivery_capability ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.admission_delivery_capability FORCE ROW LEVEL SECURITY;
CREATE POLICY capability_owner ON facts.admission_delivery_capability TO openpc_facts_capability_owner USING(true) WITH CHECK(true);
REVOKE ALL ON facts.admission_delivery_capability FROM PUBLIC;

DO $$ DECLARE name text; BEGIN
  FOREACH name IN ARRAY ARRAY['admission_delivery_head','admission_delivery_event'] LOOP
    EXECUTE format('ALTER TABLE facts.%I OWNER TO openpc_facts_lifecycle_owner',name);
    EXECUTE format('ALTER TABLE facts.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE facts.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('REVOKE ALL ON facts.%I FROM PUBLIC',name);
    EXECUTE format('CREATE POLICY lifecycle_context ON facts.%I TO openpc_facts_lifecycle_owner USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id))',name);
    EXECUTE format('CREATE POLICY read_context ON facts.%I FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader USING (facts.matches_context(participant_id,privacy_domain_id))',name);
    EXECUTE format('GRANT SELECT ON facts.%I TO openpc_fact_bridge_writer,openpc_policy_fact_reader',name);
  END LOOP;
END $$;
CREATE TRIGGER admission_delivery_immutable BEFORE UPDATE OR DELETE ON facts.admission_delivery_event
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();

CREATE FUNCTION facts.verify_admission_delivery_capability(binding bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; mismatch integer:=0; i integer; BEGIN
  IF NOT coalesce(octet_length(binding)=32 AND octet_length(nonce)=32 AND octet_length(mac)=32,false) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_DELIVERY_CAPABILITY';
  END IF;
  SELECT verifier_secret INTO STRICT secret FROM facts.mutation_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to('OPENPC_FACTSTORE_ADMISSION_DELIVERY_V1','UTF8')||binding||nonce,secret,'sha256');
  FOR i IN 0..31 LOOP mismatch:=mismatch | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
  IF mismatch<>0 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_DELIVERY_CAPABILITY'; END IF;
  INSERT INTO facts.admission_delivery_capability VALUES(nonce,binding,mac);
END $$;
ALTER FUNCTION facts.verify_admission_delivery_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_admission_delivery_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_admission_delivery_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.materialize_admission_delivery(material bytea,data bytea,nonce bytea,mac bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE m jsonb; d jsonb; original record; prior facts.admission_delivery_event%ROWTYPE;
  next_sequence bigint; event jsonb; binding bytea; BEGIN
  IF NOT coalesce(octet_length(material) BETWEEN 1 AND 16384 AND octet_length(data) BETWEEN 1 AND 4096,false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_DELIVERY_MATERIAL';
  END IF;
  m:=convert_from(material,'UTF8')::jsonb; d:=convert_from(data,'UTF8')::jsonb;
  IF jsonb_typeof(m) IS DISTINCT FROM 'object' OR jsonb_typeof(d) IS DISTINCT FROM 'object'
    OR m-ARRAY['participantId','privacyDomainId','candidateId','generationId','factType','eventId','signedFactDigest','sourceProfileDigest','sourcePayloadDigest','authorityGeneration','occurredAt','correlationId']<>'{}'
    OR (SELECT count(*) FROM jsonb_object_keys(m))<>12
    OR EXISTS(SELECT 1 FROM jsonb_each(m) field WHERE jsonb_typeof(field.value) IS DISTINCT FROM 'string')
    OR m->>'factType' NOT IN ('CONTRACT_STATE_CALL','RELATIONSHIP','EXTERNAL_DECISION') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_DELIVERY_MATERIAL';
  END IF;
  PERFORM facts.assert_lifecycle_context(m->>'participantId',m->>'privacyDomainId');
  -- assert_lifecycle_context holds the existing exclusive policy/source fence.
  binding:=sha256(facts.capability_field(1,material)||facts.capability_field(2,data));
  PERFORM facts.verify_admission_delivery_capability(binding,nonce,mac);
  SELECT f.generation_id,a.fact_id,f.signed_fact_digest,
    to_char(f.admitted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') occurred_at INTO STRICT original
    FROM facts.retained_fact_identity f JOIN facts.canonical_identity_allocation a
      USING(candidate_id,participant_id,privacy_domain_id,generation_id)
    JOIN facts.outbox o USING(candidate_id,participant_id,privacy_domain_id)
    WHERE f.participant_id=m->>'participantId' AND f.privacy_domain_id=m->>'privacyDomainId'
      AND f.candidate_id=m->>'candidateId' AND o.fact_digest=f.fact_digest;
  IF m->>'generationId' IS DISTINCT FROM original.generation_id
    OR m->>'eventId' IS DISTINCT FROM original.fact_id::text
    OR m->>'signedFactDigest' IS DISTINCT FROM 'sha256:'||encode(original.signed_fact_digest,'hex')
    OR m->>'correlationId' IS DISTINCT FROM m->>'candidateId'
    OR m->>'occurredAt' IS DISTINCT FROM original.occurred_at
    OR coalesce(m->>'sourceProfileDigest','')!~'^sha256:[0-9a-f]{64}$'
    OR coalesce(m->>'sourcePayloadDigest','')!~'^sha256:[0-9a-f]{64}$'
    OR coalesce(m->>'authorityGeneration','')!~'^sha256:[0-9a-f]{64}$'
    OR coalesce(m->>'occurredAt','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$'
    OR d IS DISTINCT FROM jsonb_build_object('candidateId','urn:openpc:resource:'||(m->>'candidateId'),
      'factArtifactId','urn:openpc:resource:'||(m->>'candidateId'),'artifactDigest',m->>'sourcePayloadDigest',
      'sourceProfileDigest',m->>'sourceProfileDigest','sourceNeutral',true) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_DELIVERY_BINDING';
  END IF;
  SELECT * INTO prior FROM facts.admission_delivery_event WHERE candidate_id=m->>'candidateId';
  IF FOUND THEN
    IF prior.source_material<>material OR prior.data_bytes<>data THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_DELIVERY_REPLAY_CONFLICT';
    END IF;
    RETURN prior.envelope;
  END IF;
  INSERT INTO facts.admission_delivery_head VALUES(m->>'participantId',m->>'privacyDomainId',m->>'factType',1)
    ON CONFLICT(participant_id,privacy_domain_id,fact_type) DO UPDATE SET sequence=facts.admission_delivery_head.sequence+1
    RETURNING sequence INTO next_sequence;
  event:=jsonb_build_object('specversion','1.0','id',m->>'eventId','source','urn:openpc:service:LS-FACT-BRIDGE',
    'type','io.openpc.fact.candidate.admitted.v1','subject','urn:openpc:resource:'||(m->>'candidateId'),
    'time',m->>'occurredAt','datacontenttype','application/json',
    'dataschema','https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
    'participantid','urn:openpc:participant:'||(m->>'participantId'),
    'privacydomainid','urn:openpc:privacy-domain:'||(m->>'privacyDomainId'),
    'correlationid',m->>'correlationId','authoritygeneration',m->>'authorityGeneration',
    'sequence',next_sequence::text,'datadigest','sha256:'||encode(sha256(data),'hex'),'data',d);
  INSERT INTO facts.admission_delivery_event(candidate_id,participant_id,privacy_domain_id,fact_type,sequence,
    event_id,generation_id,source_material,source_material_digest,data_bytes,envelope)
    VALUES(m->>'candidateId',m->>'participantId',m->>'privacyDomainId',m->>'factType',next_sequence,
      (m->>'eventId')::uuid,m->>'generationId',material,sha256(material),data,event);
  RETURN event;
END $$;
ALTER FUNCTION facts.materialize_admission_delivery(bytea,bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.materialize_admission_delivery(bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.materialize_admission_delivery(bytea,bytea,bytea,bytea) TO openpc_fact_bridge_writer;
