import { evidenceHoldSourcesSql } from './hold-sources.mjs';
import { evidenceHoldSelectorsSql } from './hold-selectors.mjs';

export const evidenceHoldGuardsSql = `${evidenceHoldSelectorsSql}
${evidenceHoldSourcesSql}

INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ'),
 ('ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
 (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
 idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
 ('ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1','evidence-holds','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_CREATION'),
 ('ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1','evidence-holds','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_HOLD_RELEASE'),
 ('ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ'),
 ('ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1','evidence-holds','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_HOLD_READ')))<>6
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-ACTION'; END IF;
END $$;
ALTER TABLE control.retention_hold FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_hold_coverage FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.retention_hold,control.evidence_hold_coverage
 FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.retention_hold,control.evidence_hold_coverage
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT,UPDATE ON control.retention_hold TO openpc_control_runtime;
GRANT INSERT ON control.evidence_hold_coverage TO openpc_control_worker;
GRANT SELECT(admitted_at) ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_hold_state_projection(rule control.retention_hold)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',(rule).hold_kind,
  '1',openpc.business_bytes(decode(substring((rule).selector_digest from 8),'hex')),'2',(rule).state,
  '3',openpc.business_uuid((rule).approval_request_id),'4',openpc.business_uuid((rule).creation_operation_id),
  '5',CASE WHEN (rule).release_approval_request_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).release_approval_request_id) END,
  '6',CASE WHEN (rule).release_operation_id IS NULL THEN openpc.business_bytes(''::bytea) ELSE openpc.business_uuid((rule).release_operation_id) END,
  '7',floor(extract(epoch from (rule).effective_at)*1000000)*1000,
  '8',floor(extract(epoch from (rule).updated_at)*1000000)*1000)
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_state_projection(control.retention_hold) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_state_projection(control.retention_hold)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.assert_evidence_hold_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=receipt.participant_id
  AND h.privacy_domain_id=receipt.privacy_domain_id AND h.retention_hold_id=receipt.aggregate_id
  AND h.revision=receipt.after_revision AND receipt.after_existence=1
  AND coalesce(h.release_operation_id,h.creation_operation_id)=receipt.operation_id
  AND receipt.catalog_operation_id=CASE WHEN h.selector_type='PARTICIPANT' THEN CASE WHEN h.state='ACTIVE' THEN 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD' END ELSE CASE WHEN h.state='ACTIVE' THEN 'CFG-OP-CREATE-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-EVIDENCE-HOLD' END END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_hold_state_projection(h))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-HOLD-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_hold_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_hold_receipt(control.audit_occurrence) TO openpc_control_runtime;

-- Matching any record preserves its complete immutable encrypted object version.
CREATE OR REPLACE FUNCTION openpc.evidence_hold_matches(selector jsonb,participant uuid,privacy uuid,stream text,segment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT openpc.evidence_hold_match_state(selector,participant,privacy,stream,segment)<>'NON_MATCH'
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_matches(jsonb,uuid,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_matches(jsonb,uuid,uuid,text,uuid)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

-- The lifecycle fence orders admission against release. A terminal release keeps
-- historical acknowledgements, but creates no preservation duty for later objects.
CREATE OR REPLACE FUNCTION openpc.evidence_hold_requires_coverage(rule control.retention_hold,stream text,segment uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.evidence_segment s WHERE s.participant_id=(rule).participant_id
  AND ((rule).selector_type='PARTICIPANT' OR s.privacy_domain_id=(rule).privacy_domain_id)
  AND s.stream_id=stream AND s.segment_id=segment
  AND openpc.evidence_hold_matches((rule).selector,s.participant_id,s.privacy_domain_id,stream,segment)
  AND ((rule).state='ACTIVE' OR s.admitted_at<=(rule).updated_at))
$$;
REVOKE ALL ON FUNCTION openpc.evidence_hold_requires_coverage(control.retention_hold,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_hold_requires_coverage(control.retention_hold,text,uuid)
 TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_hold()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE encoded jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 encoded:=openpc.evidence_hold_selector_encoding(NEW.selector,NEW.participant_id,NEW.privacy_domain_id);
 IF NEW.selector_type IS DISTINCT FROM NEW.selector->>'type'
  OR openpc.business_cbor(NEW.selector_cbor) IS DISTINCT FROM encoded THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF NEW.selector_type='PARTICIPANT' AND NOT EXISTS(SELECT 1 FROM control.participant p
  WHERE p.participant_id=NEW.participant_id AND p.root_privacy_domain_id=NEW.privacy_domain_id)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'ACTIVE' OR NEW.revision<>1 OR NEW.creation_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>(CASE WHEN NEW.selector_type='PARTICIPANT' THEN 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  NEW.created_at:=clock_timestamp(); NEW.effective_at:=NEW.created_at;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['state','revision','release_operation_id','release_approval_request_id','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['state','revision','release_operation_id','release_approval_request_id','updated_at'])
   OR OLD.state<>'ACTIVE' OR NEW.state<>'RELEASED' OR NEW.revision<>2
   OR NEW.release_operation_id<>current_setting('openpc.operation_id')::uuid
   OR current_setting('openpc.action_intent_id')<>(CASE WHEN NEW.selector_type='PARTICIPANT' THEN 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1' END)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 END IF;
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_guard ON control.retention_hold;
CREATE TRIGGER evidence_hold_guard BEFORE INSERT OR UPDATE OR DELETE ON control.retention_hold
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_hold();

CREATE OR REPLACE FUNCTION openpc.require_evidence_hold_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid; approval uuid; catalog text; action text; expected numeric;
BEGIN
 IF TG_OP='INSERT' THEN
  operation:=NEW.creation_operation_id;approval:=NEW.approval_request_id;catalog:='CFG-OP-CREATE-EVIDENCE-HOLD';
  action:='ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1';expected:=0;
 ELSE
  operation:=NEW.release_operation_id;approval:=NEW.release_approval_request_id;catalog:='CFG-OP-RELEASE-EVIDENCE-HOLD';
  action:='ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1';expected:=1;
 END IF;
 IF NEW.selector_type='PARTICIPANT' THEN
  catalog:=CASE WHEN TG_OP='INSERT' THEN 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' ELSE 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD' END;
  action:=CASE WHEN TG_OP='INSERT' THEN 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1' ELSE 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1' END;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence e JOIN control.idempotency_record i
  ON i.participant_id=e.participant_id AND i.privacy_domain_id=e.privacy_domain_id AND i.operation_id=e.operation_id
   AND i.catalog_operation_id=e.catalog_operation_id AND i.input_digest=e.candidate_digest
  JOIN control.mutation_candidate c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.approval_request a ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
   AND a.subject_id=c.mutation_candidate_id AND a.approval_request_id=approval
  WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.operation_id=operation AND e.aggregate_type='evidence-hold' AND e.aggregate_id=NEW.retention_hold_id
   AND e.catalog_operation_id=catalog AND e.action_intent_id=action AND i.terminal_state='COMMITTED'
   AND i.expected_aggregate_version=expected AND i.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.retention_hold_id::text
   AND c.catalog_operation_id=catalog AND c.action_intent_id=action AND c.resource_id=NEW.retention_hold_id
   AND c.state='CONSUMED' AND c.expected_revision=expected
   AND (TG_OP<>'INSERT' OR (c.candidate_document->'selector'=NEW.selector AND c.candidate_document->>'holdKind'=NEW.hold_kind))
   AND EXISTS(SELECT 1 FROM control.outbox_event event JOIN control.audit_occurrence receipt
    ON receipt.participant_id=event.participant_id AND receipt.privacy_domain_id=event.privacy_domain_id
    AND receipt.receipt_id=event.receipt_id WHERE event.participant_id=e.participant_id
    AND event.privacy_domain_id=e.privacy_domain_id AND event.aggregate_id=e.aggregate_id AND event.aggregate_type=e.aggregate_type
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND receipt.operation_id=operation
    AND event.payload_digest=sha256(event.payload_cbor))) THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-PROVENANCE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM control.audit_occurrence receipt WHERE receipt.participant_id=NEW.participant_id
  AND receipt.privacy_domain_id=NEW.privacy_domain_id AND receipt.operation_id=operation
  AND receipt.aggregate_type='evidence-hold' AND receipt.aggregate_id=NEW.retention_hold_id
  AND receipt.catalog_operation_id=catalog AND receipt.action_intent_id=action
  AND receipt.before_existence=CASE WHEN TG_OP='INSERT' THEN 0 ELSE 1 END
  AND receipt.before_revision=expected AND receipt.after_existence=1 AND receipt.after_revision=NEW.revision
  AND openpc.business_cbor(receipt.before_state_preimage)->8=CASE WHEN TG_OP='INSERT' THEN '{}'::jsonb ELSE openpc.evidence_hold_state_projection(OLD) END
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_hold_state_projection(NEW))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-EVIDENCE-HOLD-SIGNED-TRANSITION'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_command_required ON control.retention_hold;
CREATE CONSTRAINT TRIGGER evidence_hold_command_required AFTER INSERT OR UPDATE ON control.retention_hold
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_hold_command();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_hold_coverage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE hold control.retention_hold%ROWTYPE; segment control.evidence_segment%ROWTYPE; expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT hold FROM control.retention_hold WHERE participant_id=NEW.participant_id
  AND (selector_type='PARTICIPANT' OR privacy_domain_id=NEW.privacy_domain_id) AND retention_hold_id=NEW.retention_hold_id;
 SELECT * INTO STRICT segment FROM control.evidence_segment WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id AND segment_id=NEW.segment_id;
 IF hold.revision<>NEW.hold_revision OR segment.object_digest<>NEW.object_digest
  OR NOT openpc.evidence_hold_requires_coverage(hold,NEW.stream_id,NEW.segment_id)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 expected:=jsonb_build_object('version','OPENPC_EVIDENCE_HOLD_ACK_V1','object',jsonb_build_object(
  'participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'streamId',NEW.stream_id,
  'sinkId',NEW.sink_id,'segmentId',NEW.segment_id::text,'objectDigest',NEW.object_digest,
  'firstSequence',segment.first_sequence::text,'throughSequence',segment.through_sequence::text,
  'previousSegmentDigest',segment.previous_segment_digest,'keyId',segment.key_id,
  'retentionUntil',to_char(segment.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
  'holdId',hold.retention_hold_id::text,'selectorDigest',hold.selector_digest,'revision',hold.revision::text,
  'state',hold.state,'operationId',coalesce(hold.release_operation_id,hold.creation_operation_id)::text,
  'assurance','LOCAL_FSYNC_READBACK');
 IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
  OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.acknowledged_at:=clock_timestamp(); RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_hold_coverage_guard ON control.evidence_hold_coverage;
CREATE TRIGGER evidence_hold_coverage_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_hold_coverage
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_hold_coverage();

CREATE OR REPLACE FUNCTION openpc.require_evidence_checkpoint_hold_coverage()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF NEW.receipt->>'kind'='SIGNED_REMOTE_ARCHIVE_V1' THEN
  PERFORM openpc.assert_remote_archive_checkpoint(NEW);
  RETURN NEW;
 END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=NEW.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=NEW.privacy_domain_id)
  AND openpc.evidence_hold_requires_coverage(h,NEW.stream_id,NEW.segment_id)
  AND NOT EXISTS(SELECT 1 FROM control.evidence_hold_coverage c WHERE c.participant_id=h.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.retention_hold_id=h.retention_hold_id AND c.hold_revision=h.revision
   AND c.segment_id=NEW.segment_id AND c.sink_id=NEW.sink_id AND c.object_digest=NEW.object_digest))
 THEN RAISE EXCEPTION 'PC-DATA-6007-EVIDENCE-HOLD-COVERAGE'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_checkpoint_hold_coverage ON control.evidence_checkpoint;
CREATE TRIGGER evidence_checkpoint_hold_coverage BEFORE INSERT ON control.evidence_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_checkpoint_hold_coverage();
`;
