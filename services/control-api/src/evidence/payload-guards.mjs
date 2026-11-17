/** Expand before contracting the old column. The owning generated migration
 * copies exact bytes and aborts on any mismatch before a later migration drops it.
 */
export const evidencePayloadGuardsSql = `
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='control'
  AND table_name='evidence_segment' AND column_name='encrypted_segment') THEN
  ALTER TABLE control.evidence_segment NO FORCE ROW LEVEL SECURITY;
  EXECUTE 'INSERT INTO control.evidence_segment_payload(participant_id,privacy_domain_id,stream_id,segment_id,encrypted_segment)
   SELECT participant_id,privacy_domain_id,stream_id,segment_id,encrypted_segment FROM control.evidence_segment
   ON CONFLICT DO NOTHING';
  IF EXISTS(SELECT 1 FROM control.evidence_segment s LEFT JOIN control.evidence_segment_payload p
   USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE p.segment_id IS NULL OR s.encrypted_segment IS DISTINCT FROM p.encrypted_segment OR s.object_digest<>'sha256:'||encode(sha256(p.encrypted_segment),'hex')) THEN
   RAISE EXCEPTION 'PC-DATA-6004-PAYLOAD-MIGRATION';
  END IF;
  ALTER TABLE control.evidence_segment FORCE ROW LEVEL SECURITY;
 END IF;
END $$;
ALTER TABLE control.evidence_segment_payload FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_segment_payload FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.evidence_segment_payload TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_evidence_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE segment control.evidence_segment%ROWTYPE; envelope jsonb; expected jsonb; head numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN
  PERFORM openpc.record_evidence_payload_deletion(OLD);
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT segment FROM control.evidence_segment s WHERE s.participant_id=NEW.participant_id
  AND s.privacy_domain_id=NEW.privacy_domain_id AND s.stream_id=NEW.stream_id AND s.segment_id=NEW.segment_id;
 SELECT last_sequence INTO STRICT head FROM control.evidence_stream WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF segment.first_sequence<=head THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF segment.object_digest<>'sha256:'||encode(sha256(NEW.encrypted_segment),'hex') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 envelope:=convert_from(NEW.encrypted_segment,'UTF8')::jsonb;
 expected:=jsonb_build_object('version','OPENPC_EVIDENCE_SEGMENT_V1','participantId',segment.participant_id::text,
  'privacyDomainId',segment.privacy_domain_id::text,'streamId',segment.stream_id,'segmentId',segment.segment_id::text,
  'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,'previousSegmentDigest',segment.previous_segment_digest,
  'keyId',segment.key_id,'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 IF envelope->'header' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_payload_guard ON control.evidence_segment_payload;
CREATE TRIGGER evidence_payload_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_segment_payload
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_payload();

DROP TRIGGER IF EXISTS evidence_payload_mirror ON control.evidence_segment;
DROP FUNCTION IF EXISTS openpc.mirror_legacy_evidence_payload();
CREATE OR REPLACE FUNCTION openpc.require_evidence_payload()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=NEW.participant_id
  AND p.privacy_domain_id=NEW.privacy_domain_id AND p.stream_id=NEW.stream_id AND p.segment_id=NEW.segment_id
  AND NEW.object_digest='sha256:'||encode(sha256(p.encrypted_segment),'hex')) THEN
  RAISE EXCEPTION 'PC-DATA-6004-EVIDENCE-PAYLOAD';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_payload_required ON control.evidence_segment;
CREATE CONSTRAINT TRIGGER evidence_payload_required AFTER INSERT ON control.evidence_segment
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_payload();
`;
