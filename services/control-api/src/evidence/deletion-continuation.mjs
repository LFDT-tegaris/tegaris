/** Fixed primary-key keyset, signed predecessor and live per-object eligibility.
 * The mutation owner holds the shared lifecycle fence while using this oracle.
 */
export const evidenceDeletionContinuationSql = `
CREATE OR REPLACE FUNCTION openpc.evidence_deletion_target(plan jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('evidenceId',plan->'selection'->'evidenceId',
  'segmentId',plan->'selection'->'segmentId','firstSequence',plan->'selection'->'firstSequence',
  'throughSequence',plan->'selection'->'throughSequence','objectDigest',plan->'selection'->'objectDigest',
  'ciphertextBytes',plan->'selection'->'ciphertextBytes','recordCount',plan->'selection'->'recordCount',
  'beforeDigest',plan->'beforeDigest')
$$;
CREATE OR REPLACE FUNCTION openpc.local_evidence_deletion_batch_plan(record uuid,previous uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; selected jsonb; targets jsonb:='[]'::jsonb; target jsonb; candidate record;
 prior control.deletion_job%ROWTYPE; receipt_digest text; next_job uuid; position integer:=0;
 cursor jsonb:='null'::jsonb; anchor jsonb; prior_policy jsonb; blockers jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (record IS NULL)=(previous IS NULL) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF previous IS NOT NULL THEN
  SELECT * INTO prior FROM control.deletion_job j
   WHERE j.participant_id=current_setting('openpc.participant_id')::uuid
    AND j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND j.deletion_job_id=previous;
  IF NOT FOUND OR prior.state<>'SUCCEEDED'
   OR prior.selection->>'version'<>'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN RETURN NULL; END IF;
  SELECT 'sha256:'||encode(a.receipt_digest,'hex') INTO receipt_digest FROM control.audit_occurrence a
   WHERE a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id
    AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=prior.deletion_job_id
    AND a.operation_id=prior.operation_id AND a.profile_id='pc.control.evidence-deletion.batch'
    AND a.catalog_operation_id='CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH';
  IF receipt_digest IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  targets:=prior.selection->'targets'; position:=(prior.selection->>'batchIndex')::integer+1;
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous::text,'receiptDigest',receipt_digest);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job j
   WHERE j.participant_id=prior.participant_id AND j.privacy_domain_id=prior.privacy_domain_id
    AND j.previous_deletion_job_id=previous AND j.state='SUCCEEDED';
  IF next_job IS NOT NULL OR position=jsonb_array_length(targets) THEN
   RETURN jsonb_build_object('evidenceId',prior.selection->'evidenceId','localPayload','DELETED',
    'eligible',false,'blockers','[]'::jsonb,'selection',null,'beforeDigest',null,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END);
  END IF;
  target:=targets->position;
  prior_policy:=jsonb_build_array(prior.selection->'retentionPolicyId',prior.selection->'policyDigest');
  plan:=openpc.local_evidence_deletion_plan(right(target->>'evidenceId',36)::uuid);
 ELSE
  anchor:=openpc.local_evidence_deletion_plan(record);
  IF anchor IS NULL THEN RETURN NULL; END IF;
  IF anchor->'selection'='null'::jsonb THEN
   RETURN anchor||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
  END IF;
  FOR candidate IN
   SELECT first_record.evidence_id FROM control.evidence_segment s
    JOIN control.evidence_segment_payload p USING(participant_id,privacy_domain_id,stream_id,segment_id)
    CROSS JOIN LATERAL (SELECT c.evidence_id FROM control.evidence_catalogue c
     WHERE c.participant_id=s.participant_id AND c.privacy_domain_id=s.privacy_domain_id
      AND c.stream_id=s.stream_id AND c.segment_id=s.segment_id ORDER BY c.sequence LIMIT 1) first_record
    WHERE s.participant_id=current_setting('openpc.participant_id')::uuid
     AND s.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
     AND s.stream_id=anchor->'selection'->>'streamId'
     AND s.segment_id>=(anchor->'selection'->>'segmentId')::uuid
    ORDER BY s.segment_id LIMIT 16
  LOOP
   selected:=openpc.local_evidence_deletion_plan(candidate.evidence_id);
   IF selected->'selection'='null'::jsonb THEN
    RETURN selected||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
   END IF;
   targets:=targets||jsonb_build_array(openpc.evidence_deletion_target(selected));
   IF plan IS NULL THEN plan:=selected; END IF;
  END LOOP;
  target:=targets->0;
 END IF;
 IF plan IS NULL OR target IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 blockers:=plan->'blockers';
 IF plan->'selection'='null'::jsonb THEN
  RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null);
 END IF;
 IF openpc.evidence_deletion_target(plan) IS DISTINCT FROM target OR
  (prior_policy IS NOT NULL AND prior_policy IS DISTINCT FROM
   jsonb_build_array(plan->'selection'->'retentionPolicyId',plan->'selection'->'policyDigest')) THEN
  blockers:=blockers||jsonb_build_array('STALE_SELECTION');
 END IF;
 selected:=(plan->'selection')||jsonb_build_object('version','OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1',
  'targets',targets,'batchIndex',position,'priorCursor',cursor);
 RETURN plan||jsonb_build_object('eligible',jsonb_array_length(blockers)=0,'blockers',blockers,
  'selection',CASE WHEN blockers ? 'STALE_SELECTION' THEN NULL ELSE selected END,
  'continuationState',CASE WHEN jsonb_array_length(blockers)=0 THEN 'READY' ELSE 'BLOCKED' END,
  'nextDeletionJobId',null);
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_target(jsonb),openpc.local_evidence_deletion_batch_plan(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_target(jsonb),openpc.local_evidence_deletion_batch_plan(uuid,uuid)
 TO openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.evidence_deletion_selection_plan(selection jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF selection->>'version'='OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1' THEN
  RETURN openpc.runtime_artifact_retirement_plan(right(selection->>'retentionPolicyId',36)::uuid,
   right(selection->'priorCursor'->>'deletionJobId',36)::uuid);
 ELSIF selection->>'version'='OPENPC_PROJECTION_DELETION_BATCH_V1' THEN
  IF selection->'priorCursor'='null'::jsonb THEN
   RETURN openpc.projection_deletion_batch_plan(right(selection->>'evidenceId',36)::uuid,NULL,selection->>'dataClass');
  END IF;
  RETURN openpc.projection_deletion_batch_plan(NULL,right(selection->'priorCursor'->>'deletionJobId',36)::uuid,selection->>'dataClass');
 ELSIF selection->>'version'='OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN
  IF selection->'priorCursor'='null'::jsonb THEN
   RETURN openpc.raw_proof_deletion_batch_plan(right(selection->>'objectRef',36)::uuid,NULL);
  END IF;
  RETURN openpc.raw_proof_deletion_batch_plan(NULL,right(selection->'priorCursor'->>'deletionJobId',36)::uuid);
 ELSIF selection->>'version'='OPENPC_LOCAL_EVIDENCE_DELETION_V1' THEN
  RETURN openpc.local_evidence_deletion_plan(right(selection->>'evidenceId',36)::uuid);
 ELSIF selection->>'version'='OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1' THEN
  IF selection->'priorCursor'='null'::jsonb THEN
   RETURN openpc.local_evidence_deletion_batch_plan(right(selection->>'evidenceId',36)::uuid,NULL);
  END IF;
  RETURN openpc.local_evidence_deletion_batch_plan(NULL,right(selection->'priorCursor'->>'deletionJobId',36)::uuid);
 END IF;
 RAISE EXCEPTION 'PC-DATA-6004';
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_deletion_selection_plan(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_deletion_selection_plan(jsonb) TO openpc_control_runtime;
`;
