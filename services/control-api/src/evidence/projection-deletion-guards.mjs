import { projectionDeletionEligibilitySql } from './projection-deletion-eligibility.mjs';

export const projectionRetirementCoreSql = `
ALTER TABLE control.evidence_projection_retirement FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_projection_retirement FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_projection_retirement TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.evidence_projection_retirement TO openpc_control_runtime;
CREATE OR REPLACE FUNCTION openpc.projection_retirement_digest(r control.evidence_projection_retirement)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(to_jsonb(r)-'retirement_digest'),'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION openpc.projection_retirement_digest(control.evidence_projection_retirement) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.projection_retirement_digest(control.evidence_projection_retirement) TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
`;

export const projectionDeletionGuardsSql = `
${projectionDeletionEligibilitySql}
-- Apply after the source owners reset their grants. Their immutable-row guards
-- remain the only admission path for the narrowly governed physical deletion.
GRANT DELETE ON control.evidence_catalogue,control.evidence_rpc_provenance,control.evidence_fact_provenance,control.evidence_deployment_provenance TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.projection_preservation_metadata(c control.evidence_catalogue)
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT CASE WHEN (c).source_format='OPENPC_CANONICAL_FACT_V1' THEN
  (SELECT jsonb_build_object('factLineage',p.projection->'lineage') FROM control.evidence_fact_provenance p
   WHERE p.participant_id=(c).participant_id AND p.privacy_domain_id=(c).privacy_domain_id AND p.stream_id=(c).stream_id AND p.record_id=(c).record_id)
 ELSE openpc.evidence_hold_record_metadata(c) END
$$;
REVOKE ALL ON FUNCTION openpc.projection_preservation_metadata(control.evidence_catalogue) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.projection_preservation_metadata(control.evidence_catalogue) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.projection_deletion_after_digest(r control.evidence_projection_retirement)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'domain','pc.evidence.projection-after.v1','projectionState','RETIRED','retirementDigest',openpc.projection_retirement_digest(r))),'UTF8')),'hex')
$$;
CREATE OR REPLACE FUNCTION openpc.projection_deletion_effect_matches(j control.deletion_job,r control.evidence_projection_retirement)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT (j).target_data_class=(r).data_class AND (j).selection->>'projectionDigest'=(r).projection_digest
  AND (j).selection->>'recordId'=(r).record_id AND (j).selection->>'evidenceId'='urn:openpc:resource:'||(r).evidence_id::text
  AND (j).deleted_bytes=(r).projection_bytes AND (j).before_used_bytes=(r).projection_bytes AND (j).after_used_bytes=0
  AND (r).retirement_digest=openpc.projection_retirement_digest(r) AND (j).after_digest=openpc.projection_deletion_after_digest(r)
  AND CASE (r).data_class WHEN 'SEARCH_PROJECTION' THEN NOT EXISTS(SELECT 1 FROM control.evidence_catalogue c
   WHERE c.participant_id=(r).participant_id AND c.privacy_domain_id=(r).privacy_domain_id AND c.stream_id=(r).stream_id AND c.record_id=(r).record_id)
  WHEN 'NORMALIZED_JSON_PROJECTION' THEN CASE (j).selection->>'sourceKind'
   WHEN 'DEPLOYMENT_PROVENANCE' THEN NOT EXISTS(SELECT 1 FROM control.evidence_deployment_provenance p
    WHERE p.participant_id=(r).participant_id AND p.privacy_domain_id=(r).privacy_domain_id AND p.stream_id=(r).stream_id AND p.record_id=(r).record_id)
   WHEN 'FACT_PROVENANCE' THEN NOT EXISTS(SELECT 1 FROM control.evidence_fact_provenance p
    WHERE p.participant_id=(r).participant_id AND p.privacy_domain_id=(r).privacy_domain_id AND p.stream_id=(r).stream_id AND p.record_id=(r).record_id)
   WHEN 'RPC_PRE_ADMISSION_DENIAL' THEN NOT EXISTS(SELECT 1 FROM control.evidence_rpc_provenance p
    WHERE p.participant_id=(r).participant_id AND p.privacy_domain_id=(r).privacy_domain_id AND p.stream_id=(r).stream_id AND p.record_id=(r).record_id)
   WHEN 'RPC_CLOSED_TRANSITION' THEN NOT EXISTS(SELECT 1 FROM control.evidence_rpc_provenance p
    WHERE p.participant_id=(r).participant_id AND p.privacy_domain_id=(r).privacy_domain_id AND p.stream_id=(r).stream_id AND p.record_id=(r).record_id)
   ELSE false END
  ELSE false END
$$;

CREATE OR REPLACE FUNCTION openpc.guard_projection_deletion_job(operation text,old_job control.deletion_job,new_job control.deletion_job)
RETURNS control.deletion_job LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; item control.evidence_projection_retirement;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF operation NOT IN ('INSERT','UPDATE') OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1'
  OR new_job.participant_id<>current_setting('openpc.participant_id')::uuid OR new_job.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR new_job.operation_id<>current_setting('openpc.operation_id')::uuid
  OR new_job.target_data_class NOT IN ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') OR new_job.target_database<>'openpc_control'
  OR new_job.selection->>'version'<>'OPENPC_PROJECTION_DELETION_BATCH_V1' OR new_job.selection->>'dataClass'<>new_job.target_data_class
  OR new_job.stream_id IS DISTINCT FROM new_job.selection->>'streamId' OR new_job.segment_id IS DISTINCT FROM (new_job.selection->>'segmentId')::uuid
  OR new_job.protected_object_id IS NOT NULL THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||new_job.participant_id::text,0));
 IF operation='INSERT' THEN
  new_job.previous_deletion_job_id:=right(new_job.selection->'priorCursor'->>'deletionJobId',36)::uuid;
  IF new_job.previous_deletion_job_id IS NOT NULL THEN
   PERFORM 1 FROM control.deletion_job WHERE participant_id=new_job.participant_id AND privacy_domain_id=new_job.privacy_domain_id
    AND deletion_job_id=new_job.previous_deletion_job_id FOR UPDATE;
  END IF;
  plan:=openpc.evidence_deletion_selection_plan(new_job.selection);
  IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM new_job.selection
   OR plan->>'beforeDigest' IS DISTINCT FROM new_job.before_digest OR new_job.state<>'EXECUTING' OR new_job.revision<>0
   OR new_job.retention_policy_id IS DISTINCT FROM right(new_job.selection->>'retentionPolicyId',36)::uuid THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.target_selector_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'domain','pc.evidence.projection-selector.v1','participantId',new_job.participant_id::text,'privacyDomainId',new_job.privacy_domain_id::text,
   'dataClass',new_job.target_data_class,'streamId',new_job.stream_id,'recordId',new_job.selection->>'recordId')),'UTF8')),'hex');
  new_job.eligibility_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(new_job.selection),'UTF8')),'hex');
  new_job.before_used_bytes:=(new_job.selection->>'projectionBytes')::integer; new_job.after_used_bytes:=NULL;
  new_job.started_at:=clock_timestamp();new_job.created_at:=new_job.started_at;
 ELSE
  IF old_job.state<>'EXECUTING' OR new_job.state<>'SUCCEEDED' OR old_job.revision<>0 OR new_job.revision<>1
   OR (to_jsonb(new_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at']) IS DISTINCT FROM
    (to_jsonb(old_job)-ARRAY['state','revision','deleted_count','deleted_bytes','after_used_bytes','after_digest','completed_at','updated_at'])
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT * INTO STRICT item FROM control.evidence_projection_retirement WHERE participant_id=new_job.participant_id
   AND privacy_domain_id=new_job.privacy_domain_id AND deletion_job_id=new_job.deletion_job_id;
  new_job.deleted_count:=1;new_job.deleted_bytes:=item.projection_bytes;new_job.after_used_bytes:=0;
  new_job.after_digest:=openpc.projection_deletion_after_digest(item);
  IF NOT coalesce(openpc.projection_deletion_effect_matches(new_job,item),false) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  new_job.completed_at:=clock_timestamp();
 END IF;
 new_job.updated_at:=clock_timestamp();RETURN new_job;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_projection_retirement()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.evidence_catalogue; job control.deletion_job; plan jsonb; metadata jsonb;
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2 THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT c FROM control.evidence_catalogue WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND stream_id=NEW.stream_id AND record_id=NEW.record_id;
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND deletion_job_id=NEW.deletion_job_id AND operation_id=current_setting('openpc.operation_id')::uuid AND state='EXECUTING';
 plan:=openpc.evidence_deletion_selection_plan(job.selection); metadata:=openpc.projection_preservation_metadata(c);
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR metadata IS NULL OR NEW.preservation_metadata IS DISTINCT FROM metadata OR NEW.evidence_id<>c.evidence_id OR NEW.segment_id<>c.segment_id
  OR NEW.sequence<>c.sequence OR NEW.source_receipt_digest<>c.receipt_digest OR NEW.data_class<>job.target_data_class
  OR NEW.projection_digest<>job.selection->>'projectionDigest' OR NEW.projection_bytes<>(job.selection->>'projectionBytes')::integer
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.retirement_digest:=openpc.projection_retirement_digest(NEW);RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_projection_retirement_guard ON control.evidence_projection_retirement;
CREATE TRIGGER evidence_projection_retirement_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_projection_retirement
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_projection_retirement();

CREATE OR REPLACE FUNCTION openpc.record_projection_deletion(c control.evidence_catalogue,data_class text,projection jsonb)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE job control.deletion_job; plan jsonb; bytes integer; digest text;
BEGIN
 IF pg_trigger_depth()<>1 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1'
  OR c.participant_id<>current_setting('openpc.participant_id')::uuid OR c.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR data_class NOT IN ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||c.participant_id::text,0));
 SELECT * INTO STRICT job FROM control.deletion_job WHERE participant_id=c.participant_id AND privacy_domain_id=c.privacy_domain_id
  AND operation_id=current_setting('openpc.operation_id')::uuid AND state='EXECUTING' AND revision=0
  AND target_data_class=data_class AND selection->>'evidenceId'='urn:openpc:resource:'||c.evidence_id::text FOR UPDATE;
 plan:=openpc.evidence_deletion_selection_plan(job.selection);
 bytes:=octet_length(convert_to(openpc.signing_canonical_json(projection),'UTF8'));
 digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(projection),'UTF8')),'hex');
 IF plan IS NULL OR NOT (plan->>'eligible')::boolean OR plan->'selection' IS DISTINCT FROM job.selection
  OR plan->>'beforeDigest' IS DISTINCT FROM job.before_digest OR bytes<>(job.selection->>'projectionBytes')::integer
  OR digest<>job.selection->>'projectionDigest' THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 INSERT INTO control.evidence_projection_retirement(deletion_job_id,participant_id,privacy_domain_id,data_class,evidence_id,
  stream_id,segment_id,record_id,sequence,source_receipt_digest,projection_digest,projection_bytes,preservation_metadata,retirement_digest)
 VALUES(job.deletion_job_id,c.participant_id,c.privacy_domain_id,data_class,c.evidence_id,c.stream_id,c.segment_id,c.record_id,c.sequence,
  c.receipt_digest,digest,bytes,openpc.projection_preservation_metadata(c),'');
END $$;
REVOKE ALL ON FUNCTION openpc.projection_retirement_digest(control.evidence_projection_retirement),
 openpc.projection_deletion_after_digest(control.evidence_projection_retirement),
 openpc.projection_deletion_effect_matches(control.deletion_job,control.evidence_projection_retirement),
 openpc.guard_projection_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_projection_deletion(control.evidence_catalogue,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.projection_retirement_digest(control.evidence_projection_retirement),
 openpc.projection_deletion_after_digest(control.evidence_projection_retirement),
 openpc.projection_deletion_effect_matches(control.deletion_job,control.evidence_projection_retirement),
 openpc.guard_projection_deletion_job(text,control.deletion_job,control.deletion_job),
 openpc.record_projection_deletion(control.evidence_catalogue,text,jsonb) TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.projection_retirement_digest(control.evidence_projection_retirement) TO openpc_control_worker,openpc_control_reader;
`;
