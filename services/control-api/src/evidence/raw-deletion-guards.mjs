import { rawProofDeletionEligibilitySql } from './raw-deletion-eligibility.mjs';

export const rawProofDeletionGuardsSql = `
${rawProofDeletionEligibilitySql}
GRANT DELETE ON control.protected_proof_payload TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_selector_digest(selection jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.raw-proof-selector.v1','participantId',selection->'participantId',
  'privacyDomainId',selection->'privacyDomainId','objectRef',selection->'objectRef','objectVersion',selection->'objectVersion')),'UTF8')),'hex')
$$;

CREATE OR REPLACE FUNCTION openpc.guard_raw_proof_deletion_job(operation text,old_job control.deletion_job,new_job control.deletion_job)
RETURNS control.deletion_job LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; item control.evidence_deletion_item; current_bytes integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF operation NOT IN ('INSERT','UPDATE') OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
  OR new_job.participant_id<>current_setting('openpc.participant_id')::uuid
  OR new_job.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR new_job.operation_id<>current_setting('openpc.operation_id')::uuid
  OR new_job.target_data_class<>'RAW_SOURCE_BODY' OR new_job.target_database<>'openpc_control'
  OR new_job.selection->>'version'<>'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
  OR new_job.stream_id IS NOT NULL OR new_job.segment_id IS NOT NULL
  OR new_job.protected_object_id IS DISTINCT FROM right(new_job.selection->>'objectRef',36)::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||new_job.participant_id::text,0));
 SELECT coalesce(sum(octet_length(ciphertext)),0)::integer INTO current_bytes FROM control.protected_proof_payload
  WHERE participant_id=new_job.participant_id AND privacy_domain_id=new_job.privacy_domain_id;
 IF operation='INSERT' THEN
  new_job.previous_deletion_job_id:=right(new_job.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  IF new_job.previous_deletion_job_id IS NOT NULL THEN
   PERFORM 1 FROM control.deletion_job WHERE participant_id=new_job.participant_id AND privacy_domain_id=new_job.privacy_domain_id
    AND deletion_job_id=new_job.previous_deletion_job_id FOR UPDATE;
  END IF;
  plan:=openpc.evidence_deletion_selection_plan(new_job.selection);
  IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM new_job.selection
   OR plan->>'beforeDigest' IS DISTINCT FROM new_job.before_digest OR new_job.state<>'EXECUTING' OR new_job.revision<>0
   OR new_job.retention_policy_id IS DISTINCT FROM right(new_job.selection->>'retentionPolicyId',36)::uuid
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.target_selector_digest:=openpc.raw_proof_deletion_selector_digest(new_job.selection);
  new_job.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(new_job.selection),'UTF8')),'hex');
  new_job.before_used_bytes:=current_bytes;new_job.after_used_bytes:=NULL;
  new_job.started_at:=clock_timestamp();new_job.created_at:=new_job.started_at;
 ELSE
  IF old_job.target_data_class<>'RAW_SOURCE_BODY' OR old_job.state<>'EXECUTING' OR new_job.state<>'SUCCEEDED'
   OR old_job.revision<>0 OR new_job.revision<>1
   OR (to_jsonb(new_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
      (to_jsonb(old_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.evidence_deletion_item WHERE participant_id=new_job.participant_id
   AND privacy_domain_id=new_job.privacy_domain_id AND deletion_job_id=new_job.deletion_job_id;
  IF item.protected_object_id IS DISTINCT FROM new_job.protected_object_id OR item.object_digest<>new_job.selection->>'payloadDigest'
   OR current_bytes<>new_job.before_used_bytes-item.ciphertext_bytes
   OR EXISTS(SELECT 1 FROM control.protected_proof_payload WHERE participant_id=new_job.participant_id
    AND privacy_domain_id=new_job.privacy_domain_id AND object_id=new_job.protected_object_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.deleted_count:=1;new_job.deleted_bytes:=item.ciphertext_bytes;new_job.after_used_bytes:=current_bytes;
  new_job.after_digest:=openpc.evidence_deletion_after_digest(new_job.target_selector_digest);
  new_job.completed_at:=clock_timestamp();
 END IF;
 new_job.updated_at:=clock_timestamp();RETURN new_job;
END $$;

CREATE OR REPLACE FUNCTION openpc.record_raw_proof_payload_deletion(payload control.protected_proof_payload)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job; plan jsonb;
BEGIN
 IF pg_trigger_depth()<>1 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
  OR payload.participant_id<>current_setting('openpc.participant_id')::uuid
  OR payload.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||payload.participant_id::text,0));
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=payload.participant_id
  AND privacy_domain_id=payload.privacy_domain_id AND operation_id=current_setting('openpc.operation_id')::uuid
  AND target_data_class='RAW_SOURCE_BODY' AND state='EXECUTING' AND revision=0 AND protected_object_id=payload.object_id FOR UPDATE;
 plan:=openpc.evidence_deletion_selection_plan(job.selection);
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR plan->>'beforeDigest' IS DISTINCT FROM job.before_digest
  OR octet_length(payload.ciphertext)<>(job.selection->>'ciphertextBytes')::integer
  OR openpc.protected_proof_payload_digest(payload)<>job.selection->>'payloadDigest' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 INSERT INTO control.evidence_deletion_item(participant_id,privacy_domain_id,deletion_job_id,protected_object_id,object_digest,ciphertext_bytes)
 VALUES(payload.participant_id,payload.privacy_domain_id,job.deletion_job_id,payload.object_id,job.selection->>'payloadDigest',octet_length(payload.ciphertext));
END $$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_item_matches(item control.evidence_deletion_item)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.protected_proof_payload p
  ON p.participant_id=j.participant_id AND p.privacy_domain_id=j.privacy_domain_id AND p.object_id=j.protected_object_id
  WHERE j.participant_id=(item).participant_id AND j.privacy_domain_id=(item).privacy_domain_id AND j.deletion_job_id=(item).deletion_job_id
   AND j.operation_id=current_setting('openpc.operation_id')::uuid AND j.state='EXECUTING' AND j.target_data_class='RAW_SOURCE_BODY'
   AND j.protected_object_id=(item).protected_object_id AND (item).segment_id IS NULL
   AND j.selection->>'payloadDigest'=(item).object_digest AND openpc.protected_proof_payload_digest(p)=(item).object_digest
   AND octet_length(p.ciphertext)=(item).ciphertext_bytes)
$$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_effect_matches(job control.deletion_job,item control.evidence_deletion_item)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT (job).target_data_class='RAW_SOURCE_BODY' AND (job).protected_object_id=(item).protected_object_id
  AND (job).selection->>'payloadDigest'=(item).object_digest AND (job).segment_id IS NULL AND (item).segment_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM control.protected_proof_payload p WHERE p.participant_id=(job).participant_id
   AND p.privacy_domain_id=(job).privacy_domain_id AND p.object_id=(job).protected_object_id)
  AND (SELECT coalesce(sum(octet_length(p.ciphertext)),0) FROM control.protected_proof_payload p
   WHERE p.participant_id=(job).participant_id AND p.privacy_domain_id=(job).privacy_domain_id)=(job).after_used_bytes
$$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_selector_digest(jsonb),
 openpc.guard_raw_proof_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_raw_proof_payload_deletion(control.protected_proof_payload),
 openpc.raw_proof_deletion_item_matches(control.evidence_deletion_item),
 openpc.raw_proof_deletion_effect_matches(control.deletion_job,control.evidence_deletion_item) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_selector_digest(jsonb),
 openpc.guard_raw_proof_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_raw_proof_payload_deletion(control.protected_proof_payload),
 openpc.raw_proof_deletion_item_matches(control.evidence_deletion_item),
 openpc.raw_proof_deletion_effect_matches(control.deletion_job,control.evidence_deletion_item) TO openpc_control_runtime;
`;
