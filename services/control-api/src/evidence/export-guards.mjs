export const evidenceExportGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1','evidence-exports','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1','evidence-exports','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORT_RECORDS-V1','evidence-export','EXPORT','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','EXPORT_EVIDENCE_EXPORT')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1','evidence-exports','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1','evidence-exports','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1','evidence-exports','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_EVIDENCE_EXPORTS'),
 ('ACT-EVIDENCE_EXPORT_RECORDS-V1','evidence-export','EXPORT','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','EXPORT_EVIDENCE_EXPORT')))<>5
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-EXPORT-ACTION'; END IF;
END $$;
ALTER TABLE control.evidence_export_selection FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_export_request FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_export_output FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_export_selection,control.evidence_export_request,control.evidence_export_output
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_export_selection,control.evidence_export_request,control.evidence_export_output
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_export_selection,control.evidence_export_request TO openpc_control_runtime;
GRANT UPDATE ON control.evidence_export_request TO openpc_control_runtime,openpc_control_worker;
GRANT INSERT ON control.evidence_export_output TO openpc_control_worker;
GRANT SELECT(participant_id,privacy_domain_id,stream_id,segment_id,object_digest)
 ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_selection()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE actual jsonb; v_first_sequence numeric; v_last_sequence numeric;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 v_first_sequence:=(NEW.selection->'range'->>'fromSequence')::numeric;
 v_last_sequence:=(NEW.selection->'range'->>'throughSequence')::numeric;
 IF v_first_sequence IS NULL OR v_last_sequence IS NULL OR v_first_sequence<1 OR v_last_sequence<v_first_sequence
  OR v_last_sequence>18446744073709551615 OR v_last_sequence-v_first_sequence>=128
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 SELECT jsonb_agg(jsonb_build_object('evidenceId','urn:openpc:resource:'||c.evidence_id::text,
  'sourceRecordId',c.record_id,'segmentId',c.segment_id::text,'objectDigest',s.object_digest,
  'sequence',c.sequence::text,'evidenceClass',c.evidence_class,'recordDigest',c.receipt_digest,
  'occurredAt',to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY c.sequence)
 INTO actual FROM control.evidence_catalogue c JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
 WHERE c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id
  AND c.sequence BETWEEN v_first_sequence AND v_last_sequence;
 IF actual IS NULL OR jsonb_array_length(actual)<>v_last_sequence-v_first_sequence+1 OR
  NEW.selection IS DISTINCT FROM jsonb_build_object('version','OPENPC_EVIDENCE_EXPORT_SELECTION_V1',
   'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
   'range',jsonb_build_object('streamId',NEW.stream_id,'fromSequence',v_first_sequence::text,
    'throughSequence',v_last_sequence::text,'redactionProfileId','pc.evidence.minimized-audit.v1'),'records',actual)
  OR NEW.request_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.selection),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_selection_guard ON control.evidence_export_selection;
CREATE TRIGGER evidence_export_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_selection
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_selection();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_request()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE action text; operation uuid; v_through_sequence numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 action:=current_setting('openpc.action_intent_id'); operation:=current_setting('openpc.operation_id')::uuid;
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF action<>'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1' OR NEW.creation_operation_id<>operation
   OR NEW.last_operation_id<>operation OR NEW.state<>'REQUESTED' OR NEW.start_operation_id IS NOT NULL
   OR NEW.revision<>1 OR NEW.checkpoint<>0 OR NEW.output_digest IS NOT NULL OR NEW.last_error_code IS NOT NULL
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
 ELSE
  IF NEW.revision<>OLD.revision+1 OR NEW.participant_id<>OLD.participant_id OR NEW.privacy_domain_id<>OLD.privacy_domain_id
   OR NEW.evidence_export_id<>OLD.evidence_export_id OR NEW.created_at<>OLD.created_at OR NEW.creation_operation_id<>OLD.creation_operation_id
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  IF action='ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1' THEN
   IF OLD.state<>'REQUESTED' OR NEW.state<>'REQUESTED' OR NEW.request_digest=OLD.request_digest
    OR NEW.last_operation_id<>operation OR NEW.last_error_code IS NOT NULL
    OR (to_jsonb(NEW)-ARRAY['request_digest','stream_id','revision','updated_at','last_operation_id']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['request_digest','stream_id','revision','updated_at','last_operation_id'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSIF action='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND OLD.state='REQUESTED' THEN
   IF NEW.state<>'RUNNING' OR NEW.last_operation_id<>operation OR NEW.start_operation_id<>operation
    OR (to_jsonb(NEW)-ARRAY['state','revision','updated_at','last_operation_id','start_operation_id']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['state','revision','updated_at','last_operation_id','start_operation_id'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSIF action='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND pg_has_role(current_user,'openpc_control_worker','USAGE') THEN
   IF OLD.state NOT IN ('RUNNING','BACKLOGGED') OR NEW.state NOT IN ('SUCCEEDED','FAILED','BACKLOGGED')
    OR operation<>OLD.start_operation_id OR
    (to_jsonb(NEW)-ARRAY['state','revision','updated_at','checkpoint','output_digest','last_error_code']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','revision','updated_at','checkpoint','output_digest','last_error_code'])
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   IF NEW.state='SUCCEEDED' THEN
    SELECT (selection->'range'->>'throughSequence')::numeric INTO v_through_sequence FROM control.evidence_export_selection
     WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND request_digest=NEW.request_digest;
    IF NEW.checkpoint IS DISTINCT FROM v_through_sequence OR NEW.last_error_code IS NOT NULL OR NOT EXISTS
     (SELECT 1 FROM control.evidence_export_output WHERE evidence_export_id=NEW.evidence_export_id
       AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND output_digest=NEW.output_digest)
    THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
   ELSIF NEW.last_error_code IS DISTINCT FROM 'PC-OPS-9002' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  ELSE RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.updated_at:=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_request_guard ON control.evidence_export_request;
CREATE TRIGGER evidence_export_request_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_request
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_request();

CREATE OR REPLACE FUNCTION openpc.require_evidence_export_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE action text; catalog text; expected numeric;
BEGIN
 IF TG_OP='UPDATE' AND OLD.state<>'REQUESTED' THEN RETURN NULL; END IF;
 IF TG_OP='INSERT' THEN action:='ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1';catalog:='CFG-OP-CREATE-EVIDENCE-EXPORT';expected:=0;
 ELSIF NEW.state='REQUESTED' THEN action:='ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1';catalog:='CFG-OP-UPDATE-EVIDENCE-EXPORT';expected:=OLD.revision;
 ELSE action:='ACT-EVIDENCE_EXPORT_RECORDS-V1';catalog:='CFG-OP-START-EVIDENCE-EXPORT';expected:=OLD.revision; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.idempotency_record i
  ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id AND i.operation_id=e.operation_id
   AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.operation_id=NEW.last_operation_id AND e.aggregate_type='evidence-export' AND e.aggregate_id=NEW.evidence_export_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action AND i.terminal_state='COMMITTED'
   AND i.expected_aggregate_version=expected AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.evidence_export_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=e.participant_id
    AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_type=e.aggregate_type AND event.aggregate_id=e.aggregate_id
    AND event.event_type=CASE catalog WHEN 'CFG-OP-CREATE-EVIDENCE-EXPORT' THEN 'openpc.evidence.export.requested.v1'
      WHEN 'CFG-OP-UPDATE-EVIDENCE-EXPORT' THEN 'openpc.evidence.export.updated.v1' ELSE 'openpc.evidence.export.started.v1' END
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(e.candidate_digest,'hex')
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'revision'=NEW.revision::text
    AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex')
    AND event.payload_digest=sha256(event.payload_cbor))
   AND (NEW.state<>'RUNNING' OR EXISTS(SELECT 1 FROM control.mutation_candidate c
    WHERE c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
     AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
     AND c.action_intent_id=action AND c.catalog_operation_id=catalog AND c.operation_class='EXPORT'
     AND c.state='CONSUMED' AND c.candidate_document->>'inputDigest'=NEW.request_digest)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-EXPORT-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_export_command_required ON control.evidence_export_request;
CREATE CONSTRAINT TRIGGER evidence_export_command_required AFTER INSERT OR UPDATE ON control.evidence_export_request
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_export_command();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_output()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE request control.evidence_export_request%ROWTYPE; v_selection jsonb; records jsonb; artifact jsonb; assurance text;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT request FROM control.evidence_export_request WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND evidence_export_id=NEW.evidence_export_id FOR UPDATE;
 IF request.state NOT IN ('RUNNING','BACKLOGGED') OR request.start_operation_id<>current_setting('openpc.operation_id')::uuid
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT s.selection INTO STRICT v_selection FROM control.evidence_export_selection s WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND request_digest=request.request_digest;
 assurance:=CASE WHEN EXISTS(SELECT 1 FROM control.evidence_archive_trust t WHERE t.participant_id=NEW.participant_id
   AND t.privacy_domain_id=NEW.privacy_domain_id AND t.sink_id=NEW.sink_id)
   THEN 'REMOTE_INTERFACE_VERIFIED' ELSE 'LOCAL_FSYNC_READBACK' END;
 IF assurance='REMOTE_INTERFACE_VERIFIED' THEN
  PERFORM openpc.require_archive_profile(current_setting('openpc.archive_profile_digest',true),NEW.stream_id);
 END IF;
 SELECT jsonb_agg(jsonb_build_object('evidenceId',r->>'evidenceId','sequence',r->>'sequence',
   'evidenceClass',r->>'evidenceClass','recordDigest',r->>'recordDigest','occurredAt',r->>'occurredAt',
   'segmentDigest',r->>'objectDigest','checkpointDigest',c.checkpoint_digest) ORDER BY (r->>'sequence')::numeric)
 INTO records FROM jsonb_array_elements(v_selection->'records') r JOIN control.evidence_checkpoint c
   ON c.participant_id=NEW.participant_id AND c.privacy_domain_id=NEW.privacy_domain_id AND c.stream_id=NEW.stream_id
    AND c.segment_id=(r->>'segmentId')::uuid AND c.object_digest=r->>'objectDigest' AND c.sink_id=NEW.sink_id
    AND c.receipt->>'assurance'=assurance
    AND (assurance='LOCAL_FSYNC_READBACK' OR (c.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1'
      AND openpc.remote_archive_covers(c.participant_id,c.privacy_domain_id,c.stream_id,c.segment_id,c.sink_id)
      AND EXISTS(SELECT 1 FROM control.evidence_archive_receipt ar JOIN control.evidence_archive_outbox ao
       USING(participant_id,privacy_domain_id,receipt_id) WHERE ar.participant_id=c.participant_id
        AND ar.privacy_domain_id=c.privacy_domain_id AND ar.receipt_digest=c.receipt_digest
        AND ar.receipt_id::text=c.receipt->>'receiptId' AND ar.profile_digest=c.receipt->>'profileDigest')));
 IF records IS NULL OR jsonb_array_length(records)<>jsonb_array_length(v_selection->'records')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 artifact:=jsonb_build_object('version','OPENPC_EVIDENCE_REDACTED_EXPORT_V1',
  'evidenceExportId','urn:openpc:resource:'||NEW.evidence_export_id::text,
  'participantId','urn:openpc:participant:'||NEW.participant_id::text,
  'privacyDomainId','urn:openpc:privacy-domain:'||NEW.privacy_domain_id::text,
  'requestDigest',request.request_digest,'range',v_selection->'range','sinkId',NEW.sink_id,
  'assurance',assurance,'records',records);
 IF assurance='REMOTE_INTERFACE_VERIFIED' THEN artifact:=artifact||jsonb_build_object('providerQualification','NOT_ESTABLISHED'); END IF;
 IF NEW.artifact<>convert_to(openpc.signing_canonical_json(artifact),'UTF8')
  OR NEW.output_digest<>'sha256:'||encode(sha256(NEW.artifact),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_output_guard ON control.evidence_export_output;
CREATE TRIGGER evidence_export_output_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_export_output
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_output();

CREATE OR REPLACE FUNCTION openpc.require_evidence_export_completion()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_export_request r WHERE r.participant_id=NEW.participant_id
  AND r.privacy_domain_id=NEW.privacy_domain_id AND r.stream_id=NEW.stream_id AND r.evidence_export_id=NEW.evidence_export_id
  AND r.state='SUCCEEDED' AND r.output_digest=NEW.output_digest)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_export_completion_required ON control.evidence_export_output;
CREATE CONSTRAINT TRIGGER evidence_export_completion_required AFTER INSERT ON control.evidence_export_output
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_export_completion();

-- Read the real producer boundary, including the exact original governed start
-- and immutable output. No caller-supplied success, digest or event can replace
-- this join. Historical start evidence is an input, not a new LEGACY event.
CREATE OR REPLACE FUNCTION openpc.evidence_export_completion_source(export_id uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source jsonb;
BEGIN
 PERFORM openpc.assert_request_context(false);
 SELECT jsonb_build_object('participantId',r.participant_id::text,'privacyDomainId',r.privacy_domain_id::text,
  'streamId',r.stream_id,'evidenceExportId',r.evidence_export_id::text,'startOperationId',r.start_operation_id::text,
  'causationId',event.event_id::text,'requestDigest',r.request_digest,'checkpoint',r.checkpoint::text,
  'outputDigest',o.output_digest,'recordCount',jsonb_array_length(s.selection->'records')::text)
 INTO STRICT source
 FROM control.evidence_export_request r
 JOIN control.evidence_export_output o USING(participant_id,privacy_domain_id,stream_id,evidence_export_id)
 JOIN control.evidence_export_selection s USING(participant_id,privacy_domain_id,stream_id,request_digest)
 JOIN control.mutation_evidence e ON e.participant_id=r.participant_id AND e.privacy_domain_id=r.privacy_domain_id
  AND e.operation_id=r.start_operation_id AND e.aggregate_id=r.evidence_export_id AND e.aggregate_type='evidence-export'
  AND e.action_intent_id='ACT-EVIDENCE_EXPORT_RECORDS-V1' AND e.catalog_operation_id='CFG-OP-START-EVIDENCE-EXPORT'
 JOIN control.idempotency_record i ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id
  AND i.operation_id=e.operation_id AND i.catalog_operation_id=e.catalog_operation_id AND i.action_intent_id=e.action_intent_id
  AND i.input_digest=e.candidate_digest AND i.terminal_state='COMMITTED'
 JOIN control.mutation_candidate c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
  AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  AND c.action_intent_id=e.action_intent_id AND c.catalog_operation_id=e.catalog_operation_id
  AND c.operation_class='EXPORT' AND c.state='CONSUMED' AND c.candidate_document->>'inputDigest'=r.request_digest
 JOIN control.outbox_event event ON event.participant_id=e.participant_id AND event.privacy_domain_id=e.privacy_domain_id
  AND event.aggregate_type=e.aggregate_type AND event.aggregate_id=e.aggregate_id
  AND event.event_type='openpc.evidence.export.started.v1'
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(e.candidate_digest,'hex')
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'revision'=(i.expected_aggregate_version+1)::text
  AND convert_from(event.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex')
  AND event.payload_digest=sha256(event.payload_cbor)
 WHERE r.participant_id=current_setting('openpc.participant_id')::uuid
  AND r.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND r.evidence_export_id=export_id
  AND r.state='SUCCEEDED' AND r.output_digest=o.output_digest
  AND r.checkpoint=(s.selection->'range'->>'throughSequence')::numeric
  AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||r.evidence_export_id::text
  AND r.request_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(s.selection),'UTF8')),'hex')
  AND o.output_digest='sha256:'||encode(sha256(o.artifact),'hex')
  AND jsonb_array_length(convert_from(o.artifact,'UTF8')::jsonb->'records')=jsonb_array_length(s.selection->'records');
 RETURN source;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'PC-DATA-6007-EVIDENCE-EXPORT-COMPLETION-SOURCE';
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_export_completion_source(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_export_completion_source(uuid) TO openpc_control_worker,openpc_control_reader;
`;
