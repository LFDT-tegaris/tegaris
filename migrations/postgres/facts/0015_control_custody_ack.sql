-- Acknowledges only the real Control custody consumer. Fleet acknowledgement
-- and shard publication remain separate; no outbox or readiness state changes.
CREATE TABLE facts.control_admission_custody_ack (
  candidate_id text PRIMARY KEY REFERENCES facts.admission_delivery_event(candidate_id) ON DELETE RESTRICT,
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  event_id uuid NOT NULL UNIQUE,
  material bytea NOT NULL CHECK(octet_length(material) BETWEEN 1 AND 16384),
  material_digest bytea NOT NULL CHECK(material_digest=sha256(material)),
  acknowledged_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE facts.control_admission_custody_ack OWNER TO openpc_facts_lifecycle_owner;
ALTER TABLE facts.control_admission_custody_ack ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.control_admission_custody_ack FORCE ROW LEVEL SECURITY;
REVOKE ALL ON facts.control_admission_custody_ack FROM PUBLIC;
CREATE POLICY lifecycle_context ON facts.control_admission_custody_ack TO openpc_facts_lifecycle_owner
  USING(facts.matches_context(participant_id,privacy_domain_id))
  WITH CHECK(facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.control_admission_custody_ack FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING(facts.matches_context(participant_id,privacy_domain_id));
GRANT SELECT ON facts.control_admission_custody_ack TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
CREATE TRIGGER control_admission_ack_immutable BEFORE UPDATE OR DELETE ON facts.control_admission_custody_ack
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();

CREATE FUNCTION facts.verify_control_custody_capability(binding bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; mismatch integer:=0; i integer; BEGIN
  IF NOT coalesce(octet_length(binding)=32 AND octet_length(nonce)=32 AND octet_length(mac)=32,false) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_CAPABILITY';
  END IF;
  SELECT verifier_secret INTO STRICT secret FROM facts.mutation_capability_secret WHERE secret_version=1;
  expected:=public.hmac(convert_to('OPENPC_FACTSTORE_CONTROL_CUSTODY_ACK_V1','UTF8')||binding||nonce,secret,'sha256');
  FOR i IN 0..31 LOOP mismatch:=mismatch | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
  IF mismatch<>0 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_CAPABILITY'; END IF;
  INSERT INTO facts.admission_delivery_capability VALUES(nonce,binding,mac);
END $$;
ALTER FUNCTION facts.verify_control_custody_capability(bytea,bytea,bytea) OWNER TO openpc_facts_capability_owner;
REVOKE ALL ON FUNCTION facts.verify_control_custody_capability(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.verify_control_custody_capability(bytea,bytea,bytea) TO openpc_facts_lifecycle_owner;

CREATE FUNCTION facts.acknowledge_control_custody(material bytea,nonce bytea,mac bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE m jsonb; original facts.admission_delivery_event%ROWTYPE; prior bytea; BEGIN
  IF NOT coalesce(octet_length(material) BETWEEN 1 AND 16384,false) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_MATERIAL';
  END IF;
  m:=convert_from(material,'UTF8')::jsonb;
  IF jsonb_typeof(m) IS DISTINCT FROM 'object'
    OR m-ARRAY['participantId','privacyDomainId','candidateId','generationId','factType','sequence','eventId','consumerId','streamId','recordId','sourceReceiptDigest','envelope']<>'{}'
    OR (SELECT count(*) FROM jsonb_object_keys(m))<>12
    OR EXISTS(SELECT 1 FROM jsonb_each(m-'envelope') field WHERE jsonb_typeof(field.value) IS DISTINCT FROM 'string')
    OR m->>'consumerId' IS DISTINCT FROM 'LS-CONTROL-WORK'
    OR length(m->>'streamId') NOT BETWEEN 1 AND 256 OR length(m->>'recordId') NOT BETWEEN 1 AND 256
    OR jsonb_typeof(m->'envelope') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_MATERIAL';
  END IF;
  PERFORM facts.assert_lifecycle_context(m->>'participantId',m->>'privacyDomainId');
  PERFORM facts.verify_control_custody_capability(sha256(material),nonce,mac);
  SELECT * INTO STRICT original FROM facts.admission_delivery_event
    WHERE candidate_id=m->>'candidateId' AND participant_id=m->>'participantId' AND privacy_domain_id=m->>'privacyDomainId';
  IF m->>'generationId' IS DISTINCT FROM original.generation_id
    OR m->>'eventId' IS DISTINCT FROM original.event_id::text
    OR m->>'factType' IS DISTINCT FROM original.fact_type
    OR m->>'sequence' IS DISTINCT FROM original.sequence::text
    OR m->'envelope' IS DISTINCT FROM original.envelope
    OR m->>'sourceReceiptDigest' IS DISTINCT FROM (convert_from(original.source_material,'UTF8')::jsonb->>'signedFactDigest') THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_BINDING';
  END IF;
  SELECT a.material INTO prior FROM facts.control_admission_custody_ack a WHERE a.candidate_id=original.candidate_id;
  IF FOUND THEN
    IF prior<>material THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACT_CONTROL_CUSTODY_REPLAY_CONFLICT'; END IF;
    RETURN false;
  END IF;
  INSERT INTO facts.control_admission_custody_ack(candidate_id,participant_id,privacy_domain_id,event_id,material,material_digest)
    VALUES(original.candidate_id,original.participant_id,original.privacy_domain_id,original.event_id,material,sha256(material));
  RETURN true;
END $$;
ALTER FUNCTION facts.acknowledge_control_custody(bytea,bytea,bytea) OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.acknowledge_control_custody(bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION facts.acknowledge_control_custody(bytea,bytea,bytea) TO openpc_fact_bridge_writer;
