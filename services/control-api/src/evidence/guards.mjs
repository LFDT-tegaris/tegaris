import { evidenceExportGuardsSql } from './export-guards.mjs';

export const evidenceCustodyGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS'),
 ('ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1','evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE action_intent_id IN
 ('ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1')
 AND (resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
 = ('evidence-records','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_RECORDS'))<>2 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-ACTION'; END IF;
END $$;
ALTER TABLE control.evidence_stream FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_segment FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_catalogue FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_stream,control.evidence_segment,control.evidence_catalogue,control.evidence_checkpoint FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_stream,control.evidence_catalogue,control.evidence_checkpoint TO openpc_control_runtime,openpc_control_reader;
GRANT SELECT,INSERT ON control.evidence_stream,control.evidence_segment,control.evidence_catalogue,control.evidence_checkpoint TO openpc_control_worker;
GRANT UPDATE ON control.evidence_stream TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_custody()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE head control.evidence_stream%ROWTYPE; segment control.evidence_segment%ROWTYPE;
 prior control.evidence_checkpoint%ROWTYPE; expected jsonb; payload_size integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' AND TG_TABLE_NAME='evidence_catalogue' THEN
  PERFORM openpc.record_projection_deletion(OLD,'SEARCH_PROJECTION',openpc.evidence_catalogue_projection(OLD));
  RETURN OLD;
 END IF;
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND TG_TABLE_NAME<>'evidence_stream') THEN
  RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW';
 END IF;
 IF TG_TABLE_NAME='evidence_stream' AND TG_OP='UPDATE'
  AND current_setting('openpc.action_intent_id') IN ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1') THEN
  PERFORM openpc.assert_evidence_deletion_accounting(OLD,NEW);
  RETURN NEW;
 END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN
  RAISE EXCEPTION 'PC-AUTH-0005';
 END IF;
 IF TG_TABLE_NAME='evidence_stream' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
  IF TG_OP='INSERT' THEN
   IF NEW.last_sequence<>0 OR NEW.last_segment_digest IS NOT NULL OR NEW.used_bytes<>0 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['last_sequence','last_segment_digest','used_bytes']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['last_sequence','last_segment_digest','used_bytes']) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND first_sequence=OLD.last_sequence+1;
   IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   SELECT octet_length(p.encrypted_segment) INTO payload_size FROM control.evidence_segment_payload p
    WHERE p.participant_id=segment.participant_id AND p.privacy_domain_id=segment.privacy_domain_id
     AND p.stream_id=segment.stream_id AND p.segment_id=segment.segment_id;
   IF NOT FOUND OR NEW.last_sequence<>segment.through_sequence OR NEW.last_segment_digest<>segment.object_digest
    OR NEW.used_bytes<>OLD.used_bytes+payload_size THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO head FROM control.evidence_stream WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_TABLE_NAME='evidence_segment' THEN
  IF NEW.first_sequence<>head.last_sequence+1 OR NEW.previous_segment_digest IS DISTINCT FROM head.last_segment_digest
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.admitted_at:=clock_timestamp();
 ELSIF TG_TABLE_NAME='evidence_catalogue' THEN
  IF EXISTS(SELECT 1 FROM control.evidence_projection_retirement r WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
   AND r.data_class='SEARCH_PROJECTION' AND r.stream_id=NEW.stream_id AND r.record_id=NEW.record_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
  IF NOT FOUND OR NEW.sequence NOT BETWEEN segment.first_sequence AND segment.through_sequence THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 ELSE
  SELECT * INTO segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
  IF NOT FOUND OR NEW.through_sequence<>segment.through_sequence OR NEW.object_digest<>segment.object_digest THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO prior FROM control.evidence_checkpoint WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND sink_id=NEW.sink_id ORDER BY through_sequence DESC LIMIT 1;
  IF segment.first_sequence<>coalesce(prior.through_sequence,0)+1 OR NEW.previous_checkpoint_digest IS DISTINCT FROM prior.checkpoint_digest THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF NEW.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1' THEN
   PERFORM openpc.assert_remote_archive_checkpoint(NEW);
  ELSE
  IF EXISTS(SELECT 1 FROM control.evidence_archive_trust t WHERE t.participant_id=NEW.participant_id
   AND t.privacy_domain_id=NEW.privacy_domain_id AND t.sink_id=NEW.sink_id)
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  expected:=jsonb_build_object('object',jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'streamId',NEW.stream_id,'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'objectDigest',NEW.object_digest,
   'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,'previousSegmentDigest',segment.previous_segment_digest,
   'keyId',segment.key_id,'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
   'versionId',NEW.object_digest,'assurance','LOCAL_FSYNC_READBACK');
  IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
   OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  END IF;
  expected:=jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'streamId',NEW.stream_id,'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'throughSequence',NEW.through_sequence::text,
   'objectDigest',NEW.object_digest,'previousCheckpointDigest',NEW.previous_checkpoint_digest,'receiptDigest',NEW.receipt_digest);
  IF NEW.checkpoint_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.acknowledged_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_stream_guard ON control.evidence_stream;
CREATE TRIGGER evidence_stream_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_stream FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_segment_guard ON control.evidence_segment;
CREATE TRIGGER evidence_segment_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_segment FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_catalogue_guard ON control.evidence_catalogue;
CREATE TRIGGER evidence_catalogue_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_catalogue FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
DROP TRIGGER IF EXISTS evidence_checkpoint_guard ON control.evidence_checkpoint;
CREATE TRIGGER evidence_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_checkpoint FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_custody();
${evidenceExportGuardsSql}
`;
