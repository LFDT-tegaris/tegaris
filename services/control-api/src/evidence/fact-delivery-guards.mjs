/** Native Fact cryptography precedes these calls. SQL independently binds the
 * same event to an actual local custody effect and prevents cursor gap skipping. */
export const factDeliveryGuardsSql = `
ALTER TABLE control.evidence_fact_admission_inbox FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_fact_admission_cursor FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_fact_admission_inbox,control.evidence_fact_admission_cursor
 FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_fact_admission_inbox,control.evidence_fact_admission_cursor
 TO openpc_control_worker,openpc_control_reader;
GRANT INSERT ON control.evidence_fact_admission_inbox TO openpc_control_worker;
GRANT INSERT,UPDATE ON control.evidence_fact_admission_cursor TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.guard_fact_admission_inbox()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE e jsonb:=NEW.envelope; d jsonb:=e->'data'; p jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT f.projection INTO p FROM control.evidence_fact_provenance f
  JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
  JOIN control.evidence_segment_payload b USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE f.participant_id=NEW.participant_id AND f.privacy_domain_id=NEW.privacy_domain_id
   AND f.stream_id=NEW.stream_id AND f.record_id=NEW.record_id
   AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.receipt_digest=NEW.source_receipt_digest;
 IF p IS NULL THEN
  p:=nullif(current_setting('openpc.fact_delivery_source_projection',true),'')::jsonb;
  IF p IS NULL OR octet_length(p::text)>4096 OR NOT EXISTS(
   SELECT 1 FROM control.evidence_projection_retirement r
    JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
    JOIN control.evidence_catalogue c ON c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
      AND c.stream_id=r.stream_id AND c.record_id=r.record_id AND c.segment_id=r.segment_id
    JOIN control.evidence_segment_payload b ON b.participant_id=c.participant_id AND b.privacy_domain_id=c.privacy_domain_id
      AND b.stream_id=c.stream_id AND b.segment_id=c.segment_id
   WHERE r.participant_id=NEW.participant_id AND r.privacy_domain_id=NEW.privacy_domain_id
    AND r.stream_id=NEW.stream_id AND r.record_id=NEW.record_id
    AND r.data_class='NORMALIZED_JSON_PROJECTION' AND j.state='SUCCEEDED'
    AND j.selection->>'sourceKind'='FACT_PROVENANCE'
    AND r.retirement_digest=openpc.projection_retirement_digest(r)
    AND r.projection_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
    AND r.source_receipt_digest=NEW.source_receipt_digest
    AND r.preservation_metadata=jsonb_build_object('factLineage',p->'lineage')
    AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.receipt_digest=NEW.source_receipt_digest
    AND c.sequence::text=p->>'sourceSequence' AND c.occurred_at=(p->>'admittedAt')::timestamptz
  ) THEN RAISE EXCEPTION 'DATA-6021-FACT-INBOX-CUSTODY-BINDING'; END IF;
 END IF;
 IF p->>'candidateId' IS DISTINCT FROM NEW.candidate_id::text
  OR p->>'receiptDigest' IS DISTINCT FROM NEW.source_receipt_digest
  OR p->'lineage'->>'factId' IS DISTINCT FROM 'urn:openpc:fact:'||NEW.event_id::text
  OR p->'lineage'->>'factType' IS DISTINCT FROM NEW.fact_type
  OR e IS DISTINCT FROM jsonb_build_object(
   'specversion','1.0','id',NEW.event_id::text,'source','urn:openpc:service:LS-FACT-BRIDGE',
   'type','io.openpc.fact.candidate.admitted.v1','subject','urn:openpc:resource:'||NEW.candidate_id::text,
   'time',e->>'time','datacontenttype','application/json',
   'dataschema','https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
   'participantid','urn:openpc:participant:'||NEW.participant_id::text,
   'privacydomainid','urn:openpc:privacy-domain:'||NEW.privacy_domain_id::text,
   'correlationid',NEW.candidate_id::text,'authoritygeneration',e->>'authoritygeneration',
   'sequence',NEW.sequence::text,'datadigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(d),'UTF8')),'hex'),
   'data',d)
  OR d IS DISTINCT FROM jsonb_build_object('candidateId','urn:openpc:resource:'||NEW.candidate_id::text,
   'factArtifactId','urn:openpc:resource:'||NEW.candidate_id::text,'artifactDigest',d->>'artifactDigest',
   'sourceProfileDigest',d->>'sourceProfileDigest','sourceNeutral',true)
  OR coalesce(d->>'artifactDigest','')!~'^sha256:[0-9a-f]{64}$'
  OR coalesce(d->>'sourceProfileDigest','')!~'^sha256:[0-9a-f]{64}$'
  OR coalesce(e->>'authoritygeneration','')!~'^sha256:[0-9a-f]{64}$'
  OR coalesce(e->>'time','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$'
  OR NEW.envelope_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(e),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'DATA-6021-FACT-INBOX-CUSTODY-BINDING'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS fact_admission_inbox_guard ON control.evidence_fact_admission_inbox;
CREATE TRIGGER fact_admission_inbox_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_fact_admission_inbox
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_fact_admission_inbox();
CREATE OR REPLACE FUNCTION openpc.guard_fact_admission_cursor()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE amount bigint;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.sequence<>0 THEN RAISE EXCEPTION 'DATA-6021-FACT-INBOX-CURSOR'; END IF;
 ELSE
  IF row(NEW.participant_id,NEW.privacy_domain_id,NEW.fact_type) IS DISTINCT FROM row(OLD.participant_id,OLD.privacy_domain_id,OLD.fact_type)
   OR NEW.sequence<=OLD.sequence OR NEW.sequence>OLD.sequence+256 THEN RAISE EXCEPTION 'DATA-6021-FACT-INBOX-CURSOR'; END IF;
  SELECT count(*) INTO amount FROM control.evidence_fact_admission_inbox i WHERE i.participant_id=NEW.participant_id
   AND i.privacy_domain_id=NEW.privacy_domain_id AND i.fact_type=NEW.fact_type AND i.sequence>OLD.sequence AND i.sequence<=NEW.sequence;
  IF amount<>NEW.sequence-OLD.sequence THEN RAISE EXCEPTION 'DATA-6021-FACT-INBOX-GAP'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS fact_admission_cursor_guard ON control.evidence_fact_admission_cursor;
CREATE TRIGGER fact_admission_cursor_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_fact_admission_cursor
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_fact_admission_cursor();
REVOKE ALL ON FUNCTION openpc.guard_fact_admission_inbox(),openpc.guard_fact_admission_cursor() FROM PUBLIC;
`;
