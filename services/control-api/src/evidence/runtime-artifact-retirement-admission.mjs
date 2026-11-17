import { runtimeArtifactRetirementSelectionSql } from './runtime-artifact-retirement-selection.mjs';

/** Installed after source/archive/receipt owners. All physical authority stays
 * with the existing deletion transaction and its authentic OLD row trigger. */
export const runtimeArtifactRetirementAdmissionSql = `
${runtimeArtifactRetirementSelectionSql}
CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_eligible(job control.deletion_job,input control.runtime_configuration_input)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE selected jsonb;
BEGIN
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF (job).participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR (job).privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR (input).participant_id IS DISTINCT FROM (job).participant_id OR (input).privacy_domain_id IS DISTINCT FROM (job).privacy_domain_id
  OR (job).operation_id IS DISTINCT FROM openpc.current_operation_id()
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1'
  OR (job).state<>'EXECUTING' OR (job).revision<>0 OR (job).target_database<>'openpc_control'
  OR (job).target_data_class<>'RUNTIME_ARTIFACT' OR (job).external_attempt_state<>'NOT_STARTED'
  OR (input).selected OR (input).configuration_digest IS DISTINCT FROM sha256((input).configuration_cbor)
  OR octet_length((input).configuration_cbor) NOT BETWEEN 1 AND 4194304
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-SOURCE'; END IF;
 selected:=openpc.runtime_artifact_retirement_selection((job).retention_policy_id,(job).previous_deletion_job_id);
 IF selected IS DISTINCT FROM (job).selection
  OR selected->'source'->>'runtimeConfigurationInputId' IS DISTINCT FROM (input).runtime_configuration_input_id::text
  OR selected->'source'->>'configurationDigest' IS DISTINCT FROM 'sha256:'||encode((input).configuration_digest,'hex')
  OR (job).before_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_before(selected->'source')
 THEN RAISE EXCEPTION 'RUNTIME-RETIREMENT-STALE_SELECTION'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_effect(job control.deletion_job,r control.runtime_artifact_retirement)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE admission control.runtime_artifact_source_disposition; denied control.runtime_artifact_source_denial; receipt control.audit_occurrence;
BEGIN
 PERFORM openpc.assert_runtime_artifact_retirement_context();
 IF (job).participant_id IS DISTINCT FROM (r).participant_id OR (job).privacy_domain_id IS DISTINCT FROM (r).privacy_domain_id
  OR (job).deletion_job_id IS DISTINCT FROM (r).deletion_job_id OR (job).state<>'SUCCEEDED' OR (job).revision<>1
  OR (job).target_database<>'openpc_control' OR (job).target_data_class<>'RUNTIME_ARTIFACT'
  OR (job).external_attempt_state<>'NOT_STARTED' OR (job).deleted_count<>1 OR (job).retained_alias_count<>0
  OR (job).before_used_bytes IS DISTINCT FROM (r).configuration_bytes OR (job).deleted_bytes IS DISTINCT FROM (r).configuration_bytes
  OR (job).after_used_bytes IS DISTINCT FROM 0 OR (job).selection->'source' IS DISTINCT FROM openpc.runtime_artifact_retirement_source(r)
  OR (job).before_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_before((job).selection->'source')
  OR (job).after_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_after_digest(r)
  OR (r).retirement_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_digest(r)
  OR EXISTS(SELECT 1 FROM control.runtime_configuration_input WHERE participant_id=(r).participant_id
   AND privacy_domain_id=(r).privacy_domain_id AND (runtime_configuration_input_id=(r).runtime_configuration_input_id
    OR configuration_digest=decode(substring((r).configuration_digest from 8),'hex')))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-EFFECT'; END IF;
 -- Historical verification binds retained originals, never today's policy,
 -- selected generation, expiry or reference graph.
 SELECT * INTO STRICT admission FROM control.runtime_artifact_source_disposition WHERE participant_id=(r).participant_id
  AND privacy_domain_id=(r).privacy_domain_id AND disposition_id=((job).selection->'disposition'->>'dispositionId')::uuid
  AND runtime_configuration_input_id=(r).runtime_configuration_input_id
  AND configuration_digest=decode(substring((r).configuration_digest from 8),'hex');
 PERFORM openpc.assert_runtime_artifact_source_disposition_committed(admission);
 SELECT * INTO STRICT denied FROM control.runtime_artifact_source_denial WHERE participant_id=admission.participant_id
  AND privacy_domain_id=admission.privacy_domain_id AND disposition_id=admission.disposition_id AND source_owner_id=admission.source_owner_id;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=admission.participant_id
  AND privacy_domain_id=admission.privacy_domain_id AND operation_id=admission.operation_id
  AND aggregate_id=admission.disposition_id AND aggregate_type='runtime-artifact-disposition';
 IF (job).selection->'disposition' IS DISTINCT FROM jsonb_build_object('dispositionId',admission.disposition_id::text,
  'operationId',admission.operation_id::text,'receiptDigest','sha256:'||encode(receipt.receipt_digest,'hex'),
  'nativeDenialDigest','sha256:'||encode(denied.denial_digest,'hex'),'sourceOwnerId',admission.source_owner_id::text,
  'sourceRootDigest',admission.selection->>'sourceRootDigest') OR denied.denial_digest IS DISTINCT FROM sha256(denied.signed_denial)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-RETIREMENT-EFFECT'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_deletion_job(operation text,old_job control.deletion_job,new_job control.deletion_job)
RETURNS control.deletion_job LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE selected jsonb; item control.runtime_artifact_retirement;
BEGIN
 PERFORM openpc.lock_runtime_artifact_disposition();
 IF operation NOT IN ('INSERT','UPDATE') OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1'
  OR new_job.participant_id IS DISTINCT FROM openpc.current_participant_id() OR new_job.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR new_job.operation_id IS DISTINCT FROM openpc.current_operation_id() OR new_job.target_database<>'openpc_control'
  OR new_job.target_data_class<>'RUNTIME_ARTIFACT' OR new_job.external_attempt_state<>'NOT_STARTED'
  OR new_job.selection->>'version' IS DISTINCT FROM 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1'
  OR new_job.stream_id IS DISTINCT FROM new_job.selection->>'streamId' OR new_job.segment_id IS NOT NULL
  OR new_job.protected_object_id IS NOT NULL
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF operation='INSERT' THEN
  new_job.previous_deletion_job_id:=right(new_job.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  selected:=openpc.runtime_artifact_retirement_selection(new_job.retention_policy_id,new_job.previous_deletion_job_id);
  IF selected IS DISTINCT FROM new_job.selection OR new_job.state<>'EXECUTING' OR new_job.revision<>0
   OR new_job.before_digest IS DISTINCT FROM openpc.runtime_artifact_retirement_before(selected->'source')
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.target_selector_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'domain','pc.evidence.runtime-artifact-selector.v1','source',selected->'source')),'UTF8')),'hex');
  new_job.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(selected),'UTF8')),'hex');
  new_job.before_used_bytes:=(selected->'source'->>'configurationBytes')::integer;new_job.after_used_bytes:=NULL;
  new_job.started_at:=clock_timestamp();new_job.created_at:=new_job.started_at;
 ELSE
  IF old_job.state<>'EXECUTING' OR new_job.state<>'SUCCEEDED' OR old_job.revision<>0 OR new_job.revision<>1
   OR (to_jsonb(new_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
    (to_jsonb(old_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.runtime_artifact_retirement WHERE participant_id=new_job.participant_id
   AND privacy_domain_id=new_job.privacy_domain_id AND deletion_job_id=new_job.deletion_job_id;
  new_job.deleted_count:=1;new_job.deleted_bytes:=item.configuration_bytes;new_job.after_used_bytes:=0;
  new_job.after_digest:=openpc.runtime_artifact_retirement_after_digest(item);
  PERFORM openpc.assert_runtime_artifact_retirement_effect(new_job,item);
  new_job.completed_at:=clock_timestamp();
 END IF;
 new_job.updated_at:=clock_timestamp();RETURN new_job;
END $$;

GRANT DELETE ON control.runtime_configuration_input TO openpc_control_runtime;
GRANT INSERT ON control.runtime_artifact_retirement TO openpc_control_runtime;
DROP TRIGGER IF EXISTS runtime_artifact_retirement_capture ON control.runtime_configuration_input;
CREATE TRIGGER runtime_artifact_retirement_capture BEFORE DELETE ON control.runtime_configuration_input
 FOR EACH ROW EXECUTE FUNCTION openpc.capture_runtime_artifact_retirement();
REVOKE ALL ON FUNCTION openpc.assert_runtime_artifact_retirement_eligible(control.deletion_job,control.runtime_configuration_input),
 openpc.assert_runtime_artifact_retirement_effect(control.deletion_job,control.runtime_artifact_retirement),
 openpc.guard_runtime_artifact_deletion_job(text,control.deletion_job,control.deletion_job) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_retirement_eligible(control.deletion_job,control.runtime_configuration_input),
 openpc.assert_runtime_artifact_retirement_effect(control.deletion_job,control.runtime_artifact_retirement),
 openpc.guard_runtime_artifact_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.runtime_artifact_retirement_source(control.runtime_artifact_retirement) TO openpc_control_runtime;
-- The installed source role verifies historical tombstones. It never receives
-- physical mutation, current-plan or raw source-byte grants.
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_retirement_effect(control.deletion_job,control.runtime_artifact_retirement),
 openpc.runtime_artifact_retirement_source(control.runtime_artifact_retirement),openpc.runtime_artifact_retirement_before(jsonb),
 openpc.runtime_artifact_retirement_digest(control.runtime_artifact_retirement),
 openpc.runtime_artifact_retirement_after_digest(control.runtime_artifact_retirement),
 openpc.assert_runtime_artifact_retirement_owner(text),openpc.assert_runtime_artifact_retirement_committed(control.runtime_artifact_retirement),
 openpc.evidence_deletion_operation(jsonb),openpc.evidence_deletion_profile_version(jsonb),
 openpc.evidence_deletion_state_projection(control.deletion_job),
 openpc.assert_evidence_deletion_receipt(control.audit_occurrence) TO openpc_control_worker;
`;
