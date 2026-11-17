import { evidenceDeletionContinuationSql } from './deletion-continuation.mjs';
import { evidenceDeletionEligibilitySql } from './deletion-eligibility.mjs';
import { evidenceDeletionSourcesSql } from './deletion-sources.mjs';

const actions = ` ('ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PROJECTION_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RUNTIME_ARTIFACT_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RAW_PROOF_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','evidence-deletions','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','EVIDENCE_LOCAL_DELETION'),
 ('ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ'),
 ('ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1','evidence-deletions','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','EVIDENCE_DELETION_READ')`;

export const evidenceDeletionGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
${actions}
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (${actions}))<>7
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DELETION-ACTION'; END IF;
END $$;
ALTER TABLE control.deletion_job FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_deletion_item FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.deletion_job,control.evidence_deletion_item FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.deletion_job,control.evidence_deletion_item TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT,UPDATE ON control.deletion_job TO openpc_control_runtime;
GRANT INSERT ON control.evidence_deletion_item TO openpc_control_runtime;
GRANT SELECT(participant_id,privacy_domain_id,stream_id,segment_id,ciphertext_bytes) ON control.evidence_segment_payload TO openpc_control_runtime,openpc_control_reader;
GRANT SELECT(first_sequence,through_sequence,retention_until) ON control.evidence_segment TO openpc_control_runtime,openpc_control_reader;
GRANT DELETE ON control.evidence_segment_payload TO openpc_control_runtime;
GRANT UPDATE(used_bytes) ON control.evidence_stream TO openpc_control_runtime;
${evidenceDeletionSourcesSql}
${evidenceDeletionEligibilitySql}
${evidenceDeletionContinuationSql}

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_operation(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE selection->>'version' WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN 'CFG-OP-DELETE-LOCAL-EVIDENCE'
 WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH'
 WHEN 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-RAW-PROOF-BATCH'
 WHEN 'OPENPC_PROJECTION_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-PROJECTION-BATCH'
 WHEN 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' THEN 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH' END
$$;
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_profile_version(selection jsonb)
RETURNS integer LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN selection->>'version'='OPENPC_PROJECTION_DELETION_BATCH_V1' THEN
  CASE selection->>'sourceKind' WHEN 'RPC_RETIRED_CATALOGUE' THEN 3 WHEN 'RETENTION_POLICY_CATALOGUE' THEN 2 ELSE 1 END
 WHEN selection->>'version' IN ('OPENPC_LOCAL_EVIDENCE_DELETION_V1','OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1') AND selection ? 'sourceRpcRetirements' THEN 2 ELSE 1 END
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_profile_version(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_profile_version(jsonb) TO openpc_control_runtime;
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_action(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE selection->>'version' WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1'
 WHEN 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1'
 WHEN 'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
 WHEN 'OPENPC_PROJECTION_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1'
 WHEN 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' THEN 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1' END
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_operation(jsonb),openpc.evidence_deletion_action(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_operation(jsonb),openpc.evidence_deletion_action(jsonb) TO openpc_control_runtime;


CREATE OR REPLACE FUNCTION openpc.evidence_deletion_selector_digest(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.local-payload-selector.v1','participantId',selection->'participantId',
  'privacyDomainId',selection->'privacyDomainId','streamId',selection->'streamId','segmentId',selection->'segmentId',
  'firstSequence',selection->'firstSequence','throughSequence',selection->'throughSequence')),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_after_digest(selector_digest text)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.local-payload-after.v1','selectorDigest',selector_digest,'payloads','[]'::jsonb)),'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_selector_digest(jsonb),openpc.evidence_deletion_after_digest(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_selector_digest(jsonb),openpc.evidence_deletion_after_digest(text) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deletion_job()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; item control.evidence_deletion_item%ROWTYPE; current_bytes bigint;
BEGIN
 IF TG_OP<>'DELETE' AND NEW.selection->>'version'='OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' THEN
  RETURN openpc.guard_runtime_artifact_deletion_job(TG_OP,OLD,NEW);
 END IF;
 IF TG_OP<>'DELETE' AND NEW.selection->>'version'='OPENPC_PROJECTION_DELETION_BATCH_V1' THEN
  RETURN openpc.guard_projection_deletion_job(TG_OP,OLD,NEW);
 END IF;
 IF TG_OP<>'DELETE' AND NEW.selection->>'version'='OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN
  RETURN openpc.guard_raw_proof_deletion_job(TG_OP,OLD,NEW);
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id') IS DISTINCT FROM openpc.evidence_deletion_action(NEW.selection)
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.operation_id<>current_setting('openpc.operation_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT used_bytes INTO STRICT current_bytes FROM control.evidence_stream
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND stream_id=NEW.stream_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  NEW.previous_deletion_job_id:=right(NEW.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  IF NEW.previous_deletion_job_id IS NOT NULL THEN
   PERFORM 1 FROM control.deletion_job WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
    AND deletion_job_id=NEW.previous_deletion_job_id FOR UPDATE;
  END IF;
  plan:=openpc.evidence_deletion_selection_plan(NEW.selection);
  IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM NEW.selection
   OR plan->>'beforeDigest' IS DISTINCT FROM NEW.before_digest OR NEW.state<>'EXECUTING' OR NEW.revision<>0
   OR NEW.retention_policy_id<>right(NEW.selection->>'retentionPolicyId',36)::uuid
   OR NEW.stream_id<>NEW.selection->>'streamId' OR NEW.segment_id<>(NEW.selection->>'segmentId')::uuid
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.target_selector_digest:=openpc.evidence_deletion_selector_digest(NEW.selection);
  NEW.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.selection),'UTF8')),'hex');
  NEW.before_used_bytes:=current_bytes;NEW.after_used_bytes:=NULL;
  NEW.started_at:=clock_timestamp();NEW.created_at:=NEW.started_at;
 ELSE
  IF OLD.state<>'EXECUTING' OR NEW.state<>'SUCCEEDED' OR OLD.revision<>0 OR NEW.revision<>1
   OR (to_jsonb(NEW)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.evidence_deletion_item WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND deletion_job_id=NEW.deletion_job_id;
  IF item.segment_id<>NEW.segment_id OR item.object_digest<>NEW.selection->>'objectDigest'
   OR current_bytes<>NEW.before_used_bytes-item.ciphertext_bytes
   OR EXISTS(SELECT 1 FROM control.evidence_segment_payload WHERE participant_id=NEW.participant_id
    AND privacy_domain_id=NEW.privacy_domain_id AND segment_id=NEW.segment_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  NEW.deleted_count:=1;NEW.deleted_bytes:=item.ciphertext_bytes;NEW.after_used_bytes:=current_bytes;
  NEW.after_digest:=openpc.evidence_deletion_after_digest(NEW.target_selector_digest);
  NEW.completed_at:=clock_timestamp();
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_job_guard ON control.deletion_job;
CREATE TRIGGER evidence_deletion_job_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deletion_job
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deletion_job();

CREATE OR REPLACE FUNCTION openpc.record_evidence_payload_deletion(payload control.evidence_segment_payload)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job%ROWTYPE; plan jsonb;
BEGIN
 -- Only the actual payload BEFORE DELETE trigger can attest this local effect.
 IF pg_trigger_depth()<>1 OR current_setting('openpc.action_intent_id') NOT IN ('ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1')
  OR payload.participant_id<>current_setting('openpc.participant_id')::uuid
  OR payload.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||payload.participant_id::text,0));
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=payload.participant_id
  AND privacy_domain_id=payload.privacy_domain_id AND operation_id=current_setting('openpc.operation_id')::uuid
  AND state='EXECUTING' AND revision=0 AND segment_id=payload.segment_id AND stream_id=payload.stream_id FOR UPDATE;
 plan:=openpc.evidence_deletion_selection_plan(job.selection);
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR plan->>'beforeDigest' IS DISTINCT FROM job.before_digest
  OR payload.ciphertext_bytes<>(job.selection->>'ciphertextBytes')::integer
  OR 'sha256:'||encode(sha256(payload.encrypted_segment),'hex')<>job.selection->>'objectDigest'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 INSERT INTO control.evidence_deletion_item(participant_id,privacy_domain_id,deletion_job_id,segment_id,object_digest,ciphertext_bytes)
 VALUES(payload.participant_id,payload.privacy_domain_id,job.deletion_job_id,payload.segment_id,job.selection->>'objectDigest',payload.ciphertext_bytes);
END $$;
REVOKE ALL ON FUNCTION openpc.record_evidence_payload_deletion(control.evidence_segment_payload) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.record_evidence_payload_deletion(control.evidence_segment_payload) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_deletion_item()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' AND pg_trigger_depth()=2 AND NEW.protected_object_id IS NOT NULL
  AND openpc.raw_proof_deletion_item_matches(NEW) THEN RETURN NEW; END IF;
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2
  OR NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_segment_payload p
   ON p.participant_id=j.participant_id AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id
   WHERE j.participant_id=NEW.participant_id AND j.privacy_domain_id=NEW.privacy_domain_id
    AND j.deletion_job_id=NEW.deletion_job_id AND j.operation_id=current_setting('openpc.operation_id')::uuid
    AND j.state='EXECUTING' AND j.segment_id=NEW.segment_id AND j.selection->>'objectDigest'=NEW.object_digest
    AND p.ciphertext_bytes=NEW.ciphertext_bytes)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_item_guard ON control.evidence_deletion_item;
CREATE TRIGGER evidence_deletion_item_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_deletion_item
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_deletion_item();

CREATE OR REPLACE FUNCTION openpc.assert_evidence_deletion_accounting(old_stream control.evidence_stream,new_stream control.evidence_stream)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF old_stream.participant_id<>current_setting('openpc.participant_id')::uuid
  OR old_stream.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR (to_jsonb(old_stream)-'used_bytes') IS DISTINCT FROM (to_jsonb(new_stream)-'used_bytes')
  OR NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id)
   WHERE j.participant_id=old_stream.participant_id AND j.privacy_domain_id=old_stream.privacy_domain_id
    AND j.stream_id=old_stream.stream_id AND j.operation_id=current_setting('openpc.operation_id')::uuid
    AND j.state='EXECUTING' AND old_stream.used_bytes=j.before_used_bytes
    AND new_stream.used_bytes=old_stream.used_bytes-i.ciphertext_bytes
    AND NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=j.participant_id
     AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_deletion_accounting(control.evidence_stream,control.evidence_stream) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_deletion_accounting(control.evidence_stream,control.evidence_stream) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_state_projection(job control.deletion_job)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('0',openpc.business_uuid((job).retention_policy_id),
  '1',openpc.business_bytes(decode(substring((job).target_selector_digest from 8),'hex')),
  '2',openpc.business_bytes(decode(substring((job).eligibility_digest from 8),'hex')),
  '3',openpc.business_bytes(decode(substring((job).before_digest from 8),'hex')),
  '4',openpc.business_bytes(decode(substring((job).after_digest from 8),'hex')),
  '5',openpc.business_uuid((job).attempt_id),'6',openpc.business_uuid((job).operation_id),
  '7',openpc.business_uuid((job).approval_request_id),'8',(job).deleted_count,'9',(job).deleted_bytes,
  '10',(job).retained_alias_count,'11',floor(extract(epoch from (job).started_at)*1000000)*1000,
  '12',floor(extract(epoch from (job).completed_at)*1000000)*1000,'13',(job).before_used_bytes,'14',(job).after_used_bytes)
$$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_state_projection(control.deletion_job) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_state_projection(control.deletion_job) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.assert_evidence_deletion_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.deletion_job j WHERE j.participant_id=receipt.participant_id
  AND j.privacy_domain_id=receipt.privacy_domain_id AND j.deletion_job_id=receipt.aggregate_id
  AND j.operation_id=receipt.operation_id AND j.state='SUCCEEDED' AND j.revision=1
  AND receipt.catalog_operation_id=openpc.evidence_deletion_operation(j.selection) AND receipt.before_existence=0 AND receipt.before_revision=0
  AND receipt.profile_version=openpc.evidence_deletion_profile_version(j.selection)
  AND receipt.after_existence=1 AND receipt.after_revision=1
  AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_deletion_state_projection(j))
 THEN RAISE EXCEPTION 'DATA-6021-RECEIPT-ACTUAL-DELETION-STATE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_evidence_deletion_receipt(control.audit_occurrence) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_evidence_deletion_receipt(control.audit_occurrence) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.require_evidence_deletion_command()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.deletion_job j LEFT JOIN control.evidence_deletion_item item
  USING(participant_id,privacy_domain_id,deletion_job_id)
  LEFT JOIN control.evidence_projection_retirement retired USING(participant_id,privacy_domain_id,deletion_job_id)
  JOIN control.mutation_evidence e ON e.participant_id=j.participant_id AND e.privacy_domain_id=j.privacy_domain_id
   AND e.aggregate_id=j.deletion_job_id AND e.operation_id=j.operation_id AND e.aggregate_type='evidence-deletion'
  JOIN control.mutation_candidate c ON c.participant_id=e.participant_id AND c.privacy_domain_id=e.privacy_domain_id
   AND c.resource_id=e.aggregate_id AND c.consumed_operation_id=e.operation_id AND c.candidate_digest=e.candidate_digest
  JOIN control.audit_occurrence receipt ON receipt.participant_id=e.participant_id AND receipt.privacy_domain_id=e.privacy_domain_id
   AND receipt.operation_id=e.operation_id AND receipt.aggregate_id=e.aggregate_id AND receipt.aggregate_type='evidence-deletion'
  WHERE j.participant_id=NEW.participant_id AND j.privacy_domain_id=NEW.privacy_domain_id AND j.deletion_job_id=NEW.deletion_job_id
   AND j.state='SUCCEEDED' AND j.revision=1 AND j.deleted_count=1
   AND CASE WHEN j.target_data_class IN ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') THEN
    item.deletion_job_id IS NULL AND retired.deletion_job_id IS NOT NULL AND openpc.projection_deletion_effect_matches(j,retired)
   ELSE retired.deletion_job_id IS NULL AND j.deleted_bytes=item.ciphertext_bytes
    AND j.after_digest=openpc.evidence_deletion_after_digest(j.target_selector_digest)
    AND CASE WHEN j.target_data_class='RAW_SOURCE_BODY' THEN openpc.raw_proof_deletion_effect_matches(j,item)
    ELSE j.target_data_class='AUDIT_EVIDENCE' AND j.segment_id=item.segment_id AND j.selection->>'objectDigest'=item.object_digest
     AND NOT EXISTS(SELECT 1 FROM control.evidence_segment_payload p WHERE p.participant_id=j.participant_id
      AND p.privacy_domain_id=j.privacy_domain_id AND p.segment_id=j.segment_id)
     AND EXISTS(SELECT 1 FROM control.evidence_stream s WHERE s.participant_id=j.participant_id
      AND s.privacy_domain_id=j.privacy_domain_id AND s.stream_id=j.stream_id AND s.used_bytes=j.after_used_bytes) END END
   AND e.approval_request_id=j.approval_request_id AND e.catalog_operation_id=openpc.evidence_deletion_operation(j.selection)
   AND e.action_intent_id=openpc.evidence_deletion_action(j.selection) AND c.catalog_operation_id=e.catalog_operation_id
   AND c.action_intent_id=e.action_intent_id AND c.state='CONSUMED' AND c.expected_revision=0
   AND c.candidate_document->'selection'=j.selection AND c.candidate_document->>'beforeDigest'=j.before_digest
   AND receipt.catalog_operation_id=e.catalog_operation_id AND receipt.action_intent_id=e.action_intent_id
   AND receipt.profile_version=openpc.evidence_deletion_profile_version(j.selection)
   AND receipt.before_existence=0 AND receipt.before_revision=0 AND receipt.after_existence=1 AND receipt.after_revision=1
   AND openpc.business_cbor(receipt.before_state_preimage)->8='{}'::jsonb
   AND openpc.business_cbor(receipt.after_state_preimage)->8=openpc.evidence_deletion_state_projection(j)
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=receipt.participant_id
    AND event.privacy_domain_id=receipt.privacy_domain_id AND event.receipt_id=receipt.receipt_id
    AND event.aggregate_type=receipt.aggregate_type AND event.aggregate_id=receipt.aggregate_id
    AND event.event_type='io.openpc.control.command.committed.v1' AND event.proof_kind='BUSINESS_RECEIPT_REFERENCE'
    AND event.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' AND event.payload_digest=sha256(event.payload_cbor)))
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DELETION-SIGNED-EFFECT'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS evidence_deletion_command_required ON control.deletion_job;
CREATE CONSTRAINT TRIGGER evidence_deletion_command_required AFTER INSERT OR UPDATE ON control.deletion_job
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_evidence_deletion_command();
`;
