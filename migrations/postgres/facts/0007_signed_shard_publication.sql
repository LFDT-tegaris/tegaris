-- COM-019 publication occurrence/outbox is committed with READY. The service
-- verifies immutable artifact bytes first under the existing mutation fence.
CREATE TABLE facts.shard_publication (
  participant_id text NOT NULL,
  privacy_domain_id text NOT NULL,
  generation_id text NOT NULL,
  event_type text NOT NULL DEFAULT 'io.openpc.fact.shard.published.v1'
    CHECK (event_type='io.openpc.fact.shard.published.v1'),
  content_digest bytea NOT NULL CHECK (octet_length(content_digest)=32),
  manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
  descriptor jsonb NOT NULL,
  published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  delivery_state text NOT NULL DEFAULT 'PENDING' CHECK (delivery_state IN ('PENDING','DELIVERED','QUARANTINED')),
  PRIMARY KEY (participant_id,privacy_domain_id,generation_id),
  FOREIGN KEY (participant_id,privacy_domain_id,generation_id)
    REFERENCES facts.readiness_gate(participant_id,privacy_domain_id,generation_id) ON DELETE RESTRICT
);
ALTER TABLE facts.shard_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE facts.shard_publication FORCE ROW LEVEL SECURITY;
CREATE POLICY lifecycle_context ON facts.shard_publication TO openpc_facts_lifecycle_owner
  USING (facts.matches_context(participant_id,privacy_domain_id)) WITH CHECK (facts.matches_context(participant_id,privacy_domain_id));
CREATE POLICY read_context ON facts.shard_publication FOR SELECT TO openpc_fact_bridge_writer,openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
REVOKE ALL ON facts.shard_publication FROM PUBLIC;
GRANT SELECT,INSERT ON facts.shard_publication TO openpc_facts_lifecycle_owner;
GRANT SELECT ON facts.shard_publication TO openpc_fact_bridge_writer,openpc_policy_fact_reader;
CREATE TRIGGER shard_publication_immutable BEFORE UPDATE OR DELETE ON facts.shard_publication
  FOR EACH ROW EXECUTE FUNCTION facts.reject_immutable_mutation();

CREATE FUNCTION facts.record_signed_shard_publication()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $$
DECLARE
  manifest_digest bytea;
  prior facts.shard_publication%ROWTYPE;
BEGIN
  IF NEW.state<>'READY' OR NOT EXISTS (
    SELECT 1 FROM facts.canonical_identity_allocation a WHERE a.participant_id=NEW.participant_id
      AND a.privacy_domain_id=NEW.privacy_domain_id AND a.generation_id=NEW.generation_id
  ) THEN RETURN NEW; END IF;
  IF EXISTS (SELECT 1 FROM facts.canonical_fact f WHERE f.participant_id=NEW.participant_id
    AND f.privacy_domain_id=NEW.privacy_domain_id AND f.generation_id=NEW.generation_id
    AND (f.fresh_until_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      OR f.observed_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint)) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACTSTORE_SHARD_FRESHNESS_REJECTED';
  END IF;
  manifest_digest := sha256(NEW.shard_cose_sign1);
  SELECT * INTO prior FROM facts.shard_publication p WHERE p.participant_id=NEW.participant_id
    AND p.privacy_domain_id=NEW.privacy_domain_id AND p.generation_id=NEW.generation_id;
  IF FOUND THEN
    IF prior.manifest_digest<>manifest_digest OR prior.content_digest<>NEW.shard_digest THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OPENPC_FACTSTORE_SHARD_IMMUTABLE';
    END IF;
    RETURN NEW;
  END IF;
  INSERT INTO facts.shard_publication(participant_id,privacy_domain_id,generation_id,content_digest,manifest_digest,descriptor)
  VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.generation_id,NEW.shard_digest,manifest_digest,
    jsonb_build_object('mediaType','application/vnd.openpc.fact-shard-manifest.v1+cbor',
      'digest','sha256:'||encode(manifest_digest,'hex'),'size',octet_length(NEW.shard_cose_sign1)));
  RETURN NEW;
END
$$;
ALTER FUNCTION facts.record_signed_shard_publication() OWNER TO openpc_facts_lifecycle_owner;
REVOKE ALL ON FUNCTION facts.record_signed_shard_publication() FROM PUBLIC;
CREATE TRIGGER signed_shard_publication AFTER UPDATE ON facts.readiness_gate
  FOR EACH ROW EXECUTE FUNCTION facts.record_signed_shard_publication();
