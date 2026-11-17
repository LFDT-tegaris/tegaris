import { rpcRetirementSql } from './rpc-retirement.mjs';
import { rpcSearchRetirementSql } from './rpc-search-retirement.mjs';

/** Independent projection retention, exact original custody and producer-owned
 * completion. Projection retirement never retires a serving/recovery owner. */
export const projectionDeletionEligibilitySql = `
${rpcRetirementSql}
${rpcSearchRetirementSql}
CREATE OR REPLACE FUNCTION openpc.evidence_catalogue_projection(c control.evidence_catalogue)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('evidenceId',(c).evidence_id::text,'participantId',(c).participant_id::text,
  'privacyDomainId',(c).privacy_domain_id::text,'streamId',(c).stream_id,'recordId',(c).record_id,
  'segmentId',(c).segment_id::text,'sequence',(c).sequence::text,'evidenceClass',(c).evidence_class,
  'sourceFormat',(c).source_format,'receiptDigest',(c).receipt_digest,
  'occurredAt',to_char((c).occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'createdAt',to_char((c).created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
$$;

CREATE OR REPLACE FUNCTION openpc.projection_deletion_object_plan(record uuid,data_class text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.evidence_catalogue; s record; rule control.retention_policy;
 p jsonb; projection_digest text; projection_bytes integer; metadata jsonb; source_kind text;
 selection jsonb; before_digest text; receipts jsonb; quorum_micros numeric; eligible_micros numeric;
 blockers text[]:=ARRAY[]::text[]; closure jsonb; retired_rpc jsonb; terminal control.evidence_catalogue;
 terminal_segment record; terminal_receipts jsonb; terminal_quorum numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF data_class NOT IN ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 SELECT * INTO c FROM control.evidence_catalogue WHERE evidence_id=record
  AND participant_id=current_setting('openpc.participant_id')::uuid AND privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid;
 IF EXISTS(SELECT 1 FROM control.evidence_projection_retirement r JOIN control.deletion_job j USING(participant_id,privacy_domain_id,deletion_job_id)
  WHERE r.participant_id=current_setting('openpc.participant_id')::uuid AND r.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
   AND r.evidence_id=record AND r.data_class=projection_deletion_object_plan.data_class AND j.state='SUCCEEDED') THEN
  RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'dataClass',data_class,
   'projectionState','RETIRED','eligible',false,'blockers',jsonb_build_array('ALREADY_DELETED'),'selection',null,'beforeDigest',null);
 END IF;
 IF c.evidence_id IS NULL THEN RETURN NULL; END IF;
 SELECT first_sequence,through_sequence,object_digest,admitted_at INTO STRICT s FROM control.evidence_segment WHERE participant_id=c.participant_id AND privacy_domain_id=c.privacy_domain_id
  AND stream_id=c.stream_id AND segment_id=c.segment_id;
 metadata:=openpc.evidence_hold_record_metadata(c);
 IF data_class='SEARCH_PROJECTION' THEN
  p:=openpc.evidence_catalogue_projection(c); source_kind:='AUTHENTICATION_CATALOGUE';
  IF c.evidence_class='BUSINESS_TRANSITION' AND openpc.retention_policy_receipt_hold_metadata(c) IS NOT NULL THEN
   source_kind:='RETENTION_POLICY_CATALOGUE';
  ELSIF c.evidence_class='EFFECT' AND c.source_format='OPENPC_RPC_DECISION_TRANSITION_V1' THEN
   source_kind:='RPC_RETIRED_CATALOGUE'; retired_rpc:=openpc.rpc_retired_catalogue_proof(c);
   IF retired_rpc IS NULL OR metadata IS NULL THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
   ELSIF openpc.rpc_retired_catalogue_has_references(c)
   THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
  ELSIF c.evidence_class<>'AUTHENTICATION' OR c.source_format<>'OPENPC_AUTHENTICATION_OCCURRENCE_V1' OR metadata IS NULL THEN
   blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
  END IF;
  -- The catalogue is still a recovery/reference dependency of local ciphertext.
  -- Its period is never borrowed from AUDIT_EVIDENCE; this is reference clearance.
  IF EXISTS(SELECT 1 FROM control.evidence_segment_payload e WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
    AND e.stream_id=c.stream_id AND e.segment_id=c.segment_id)
   OR NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.audit_occurrence a
    ON a.participant_id=j.participant_id AND a.privacy_domain_id=j.privacy_domain_id AND a.operation_id=j.operation_id
     AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=j.deletion_job_id
    WHERE j.participant_id=c.participant_id AND j.privacy_domain_id=c.privacy_domain_id AND j.stream_id=c.stream_id
     AND j.segment_id=c.segment_id AND j.target_data_class='AUDIT_EVIDENCE' AND j.state='SUCCEEDED')
   OR EXISTS(SELECT 1 FROM control.protected_proof_object o WHERE o.participant_id=c.participant_id AND o.privacy_domain_id=c.privacy_domain_id
    AND o.source->>'evidenceId'='urn:openpc:resource:'||c.evidence_id::text)
   OR EXISTS(SELECT 1 FROM control.evidence_export_selection e WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
    AND EXISTS(SELECT 1 FROM jsonb_array_elements(e.selection->'records') r WHERE r->>'evidenceId'='urn:openpc:resource:'||c.evidence_id::text))
   OR EXISTS(SELECT 1 FROM control.evidence_rpc_provenance r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_fact_provenance r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_deployment_lineage r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_deployment_provenance r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_candidate_archive r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_candidate_archive_part r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_runtime_artifact_archive r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM control.evidence_runtime_artifact_archive_part r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id)
   OR EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_catalogue'::regclass
    AND conname NOT IN ('evidence_rpc_provenance_source_fk','evidence_fact_provenance_source_fk','evidence_deployment_lineage_source_fk','evidence_deployment_provenance_source_fk')
    AND NOT (conname='candidate_archive_manifest_fk' AND conrelid='control.evidence_candidate_archive'::regclass)
    AND NOT (conname='candidate_archive_part_catalogue_fk' AND conrelid='control.evidence_candidate_archive_part'::regclass)
    AND NOT (conname='runtime_artifact_archive_manifest_fk' AND conrelid='control.evidence_runtime_artifact_archive'::regclass)
    AND NOT (conname='runtime_artifact_archive_part_catalogue_fk' AND conrelid='control.evidence_runtime_artifact_archive_part'::regclass))
  THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 ELSIF c.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' THEN
  source_kind:='DEPLOYMENT_PROVENANCE';
  SELECT r.projection,r.projection_digest INTO p,projection_digest FROM control.evidence_deployment_provenance r
   WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id;
  IF p IS NULL OR c.evidence_class<>'EFFECT' OR metadata IS NULL
   OR p IS DISTINCT FROM openpc.evidence_deployment_projection(c)
   OR projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
  ELSE blockers:=blockers||openpc.deployment_projection_retirement_blockers(c,p); END IF;
  IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_deployment_provenance'::regclass)
  THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 ELSIF c.source_format='OPENPC_CANONICAL_FACT_V1' THEN
  source_kind:='FACT_PROVENANCE';
  SELECT r.projection,r.projection_digest INTO p,projection_digest FROM control.evidence_fact_provenance r
   WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id;
  IF p IS NULL OR c.evidence_class<>'EFFECT' OR p->>'receiptDigest'<>c.receipt_digest
   OR p->>'sourceSequence'<>c.sequence::text OR (p->>'admittedAt')::timestamptz<>c.occurred_at OR metadata IS NULL
   OR projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE'); END IF;
  IF metadata->'unresolvedReferences' IS DISTINCT FROM 'false'::jsonb
   OR EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_fact_provenance'::regclass)
  THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 ELSE
  source_kind:='RPC_PRE_ADMISSION_DENIAL';
  SELECT r.projection,r.projection_digest INTO p,projection_digest FROM control.evidence_rpc_provenance r
   WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id;
  IF p IS NULL OR c.evidence_class<>'EFFECT' OR c.source_format<>'OPENPC_RPC_DECISION_TRANSITION_V1'
   OR p->>'sourceDigest'<>c.receipt_digest
   OR p->>'sourceSequence'<>c.sequence::text OR metadata IS NULL
   OR projection_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex')
  THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE'); END IF;
  IF p->'transition'->>'phase'<>'PRE_ADMISSION_DENIAL' THEN
   source_kind:='RPC_CLOSED_TRANSITION'; closure:=openpc.rpc_projection_retirement_witness(c,p);
   IF closure IS NULL THEN
    blockers:=array_append(blockers,CASE WHEN p->'transition'->>'phase'='OPERATION_STATUS_RELEASED' THEN 'UNRESOLVED_OPERATION'
     WHEN p->'transition'->>'decisionEffect'='WRITE_AMBIGUITY' THEN 'WRITE_AMBIGUITY' ELSE 'UNRESOLVED_TRANSITION' END);
   ELSE
    SELECT * INTO terminal FROM control.evidence_catalogue t WHERE t.participant_id=c.participant_id AND t.privacy_domain_id=c.privacy_domain_id
     AND t.stream_id=c.stream_id AND t.evidence_id=right(closure->>'terminalEvidenceId',36)::uuid
     AND t.record_id=closure->>'terminalRecordId' AND t.receipt_digest=closure->>'terminalSourceDigest'
     AND t.sequence::text=closure->>'terminalSequence';
    IF NOT FOUND THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
    SELECT first_sequence,through_sequence,object_digest,admitted_at INTO STRICT terminal_segment FROM control.evidence_segment t
     WHERE t.participant_id=c.participant_id AND t.privacy_domain_id=c.privacy_domain_id AND t.stream_id=c.stream_id AND t.segment_id=terminal.segment_id;
    IF terminal.sequence NOT BETWEEN terminal_segment.first_sequence AND terminal_segment.through_sequence
     OR NOT EXISTS(SELECT 1 FROM control.evidence_stream h WHERE h.participant_id=c.participant_id AND h.privacy_domain_id=c.privacy_domain_id
      AND h.stream_id=c.stream_id AND h.last_sequence>=terminal_segment.through_sequence) THEN blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT'); END IF;
    IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=c.participant_id
     AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=c.privacy_domain_id) AND h.state='ACTIVE'
     AND openpc.evidence_hold_matches(h.selector,c.participant_id,c.privacy_domain_id,c.stream_id,terminal.segment_id))
    THEN blockers:=array_append(blockers,'ACTIVE_HOLD'); END IF;
   END IF;
  ELSIF p->'transition'->'requestDigest'<>'null'::jsonb OR p->'transition'->'responseDigest'<>'null'::jsonb THEN
   blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
  END IF;
  IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_rpc_provenance'::regclass)
  THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 END IF;
 IF c.sequence NOT BETWEEN s.first_sequence AND s.through_sequence
  OR NOT EXISTS(SELECT 1 FROM control.evidence_stream h WHERE h.participant_id=c.participant_id AND h.privacy_domain_id=c.privacy_domain_id
   AND h.stream_id=c.stream_id AND h.last_sequence>=s.through_sequence)
  OR NOT EXISTS(SELECT 1 FROM control.evidence_checkpoint e WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id
   AND e.stream_id=c.stream_id AND e.segment_id=c.segment_id AND e.object_digest=s.object_digest AND e.through_sequence=s.through_sequence)
 THEN blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT'); END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=c.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=c.privacy_domain_id) AND h.state='ACTIVE'
  AND openpc.evidence_hold_matches(h.selector,c.participant_id,c.privacy_domain_id,c.stream_id,c.segment_id))
 THEN blockers:=array_append(blockers,'ACTIVE_HOLD'); END IF;
 SELECT * INTO rule FROM control.retention_policy r WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id
  AND r.data_class=projection_deletion_object_plan.data_class AND r.active_until IS NULL;
 IF NOT FOUND THEN blockers:=array_append(blockers,'NO_ACTIVE_POLICY');
 ELSE
  IF rule.deletion_mode<>'PROJECTION_DELETE' THEN blockers:=array_append(blockers,'UNSUPPORTED_MODE'); END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',q.sink_id,'checkpointDigest',q.checkpoint_digest,
   'receiptDigest',q.receipt_digest,'acknowledgedAtMicros',q.ack_micros::text) ORDER BY q.ack_micros,q.sink_id),'[]'::jsonb),max(q.ack_micros)
   INTO receipts,quorum_micros FROM (
    SELECT e.sink_id,e.checkpoint_digest,e.receipt_digest,floor(extract(epoch from e.acknowledged_at)*1000000) ack_micros
    FROM control.evidence_checkpoint e WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id AND e.stream_id=c.stream_id
     AND e.segment_id=c.segment_id AND e.object_digest=s.object_digest AND e.through_sequence=s.through_sequence
     AND e.receipt->>'receiptDigest'=e.receipt_digest AND e.receipt->'object'->>'objectDigest'=s.object_digest
    ORDER BY e.acknowledged_at,e.sink_id LIMIT rule.sink_quorum) q;
  IF jsonb_array_length(receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
  eligible_micros:=greatest(floor(extract(epoch from c.occurred_at)*1000000)+rule.retention_period_ms*1000,
   coalesce(quorum_micros,floor(extract(epoch from s.admitted_at)*1000000))+rule.local_grace_ms*1000);
  IF closure IS NOT NULL THEN
   SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',q.sink_id,'checkpointDigest',q.checkpoint_digest,
    'receiptDigest',q.receipt_digest,'acknowledgedAtMicros',q.ack_micros::text) ORDER BY q.ack_micros,q.sink_id),'[]'::jsonb),max(q.ack_micros)
    INTO terminal_receipts,terminal_quorum FROM (
     SELECT e.sink_id,e.checkpoint_digest,e.receipt_digest,floor(extract(epoch from e.acknowledged_at)*1000000) ack_micros
     FROM control.evidence_checkpoint e WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id AND e.stream_id=c.stream_id
      AND e.segment_id=terminal.segment_id AND e.object_digest=terminal_segment.object_digest AND e.through_sequence=terminal_segment.through_sequence
      AND e.receipt->>'receiptDigest'=e.receipt_digest AND e.receipt->'object'->>'objectDigest'=terminal_segment.object_digest
     ORDER BY e.acknowledged_at,e.sink_id LIMIT rule.sink_quorum) q;
   IF jsonb_array_length(terminal_receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
   eligible_micros:=greatest(eligible_micros,floor(extract(epoch from terminal.occurred_at)*1000000)+rule.retention_period_ms*1000,
    coalesce(terminal_quorum,floor(extract(epoch from terminal_segment.admitted_at)*1000000))+rule.local_grace_ms*1000);
   closure:=closure||jsonb_build_object('archive',jsonb_build_object('segmentId',terminal.segment_id::text,
    'objectDigest',terminal_segment.object_digest,'sinkReceipts',terminal_receipts));
  END IF;
  IF eligible_micros>floor(extract(epoch from clock_timestamp())*1000000) THEN blockers:=array_append(blockers,'RETENTION_NOT_ELAPSED'); END IF;
  IF p IS NOT NULL THEN
   projection_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(p),'UTF8')),'hex');
   projection_bytes:=octet_length(convert_to(openpc.signing_canonical_json(p),'UTF8'));
   selection:=jsonb_build_object('version','OPENPC_PROJECTION_DELETION_BATCH_V1','participantId','urn:openpc:participant:'||c.participant_id::text,
    'privacyDomainId',c.privacy_domain_id::text,'retentionPolicyId','urn:openpc:resource:'||rule.retention_policy_id::text,'policyDigest',rule.policy_digest,
    'targetDatabase','openpc_control','dataClass',data_class,'deletionMode','PROJECTION_DELETE','sourceKind',source_kind,
    'streamId',c.stream_id,'segmentId',c.segment_id::text,'sequence',c.sequence::text,'evidenceId','urn:openpc:resource:'||c.evidence_id::text,
    'recordId',c.record_id,'projectionDigest',projection_digest,'projectionBytes',projection_bytes,'sourceReceiptDigest',c.receipt_digest,
    'archiveObjectDigest',s.object_digest,'eligibleAfterMicros',eligible_micros::text,'sinkReceipts',receipts);
   IF closure IS NOT NULL THEN selection:=selection||jsonb_build_object('rpcClosure',closure); END IF;
   before_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'domain','pc.evidence.projection-before.v1','participantId',c.participant_id::text,'privacyDomainId',c.privacy_domain_id::text,
    'dataClass',data_class,'evidenceId',c.evidence_id::text,'projectionDigest',projection_digest,'projectionBytes',projection_bytes,
    'sourceReceiptDigest',c.receipt_digest)),'UTF8')),'hex');
  END IF;
 END IF;
 -- Unsupported producers have no executable selection. In particular, their
 -- record must never be replaced by a later supported keyset member.
 IF blockers && ARRAY['UNSUPPORTED_SOURCE','UNRESOLVED_TRANSITION','UNRESOLVED_OPERATION','WRITE_AMBIGUITY','REORG_FENCED'] THEN selection:=NULL; before_digest:=NULL; END IF;
 -- The selected transition and its terminal witness may share a segment.
 -- Report each failed obligation once even when both anchors fail it.
 blockers:=ARRAY(SELECT DISTINCT b FROM unnest(blockers) b ORDER BY b);
 RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'dataClass',data_class,
  'projectionState',CASE WHEN p IS NULL THEN 'UNAVAILABLE' ELSE 'RETAINED' END,'eligible',cardinality(blockers)=0,
  'blockers',to_jsonb(blockers),'selection',selection,'beforeDigest',before_digest);
END $$;

CREATE OR REPLACE FUNCTION openpc.projection_deletion_target(plan jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('evidenceId',plan->'selection'->'evidenceId','recordId',plan->'selection'->'recordId',
  'projectionDigest',plan->'selection'->'projectionDigest','projectionBytes',plan->'selection'->'projectionBytes',
  'sourceReceiptDigest',plan->'selection'->'sourceReceiptDigest','beforeDigest',plan->'beforeDigest')
$$;

CREATE OR REPLACE FUNCTION openpc.projection_deletion_batch_plan(record uuid,previous uuid,data_class text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; selected jsonb; targets jsonb:='[]'::jsonb; target jsonb; candidate record;
 prior control.deletion_job; receipt_digest text; next_job uuid; position integer:=0;
 cursor jsonb:='null'::jsonb; prior_policy jsonb; blockers jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (record IS NULL)=(previous IS NULL) OR data_class NOT IN ('NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION') THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF previous IS NOT NULL THEN
  SELECT * INTO prior FROM control.deletion_job j WHERE j.participant_id=current_setting('openpc.participant_id')::uuid
   AND j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND j.deletion_job_id=previous;
  IF NOT FOUND OR prior.state<>'SUCCEEDED' OR prior.selection->>'version'<>'OPENPC_PROJECTION_DELETION_BATCH_V1'
   OR prior.target_data_class<>data_class THEN RETURN NULL; END IF;
  SELECT 'sha256:'||encode(a.receipt_digest,'hex') INTO receipt_digest FROM control.audit_occurrence a
   WHERE a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id AND a.operation_id=prior.operation_id
    AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=prior.deletion_job_id AND a.profile_id='pc.control.evidence-deletion.projection'
    AND a.catalog_operation_id='CFG-OP-DELETE-PROJECTION-BATCH';
  IF receipt_digest IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  targets:=prior.selection->'targets'; position:=(prior.selection->>'batchIndex')::integer+1;
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous::text,'receiptDigest',receipt_digest);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job j WHERE j.participant_id=prior.participant_id
   AND j.privacy_domain_id=prior.privacy_domain_id AND j.previous_deletion_job_id=previous AND j.state='SUCCEEDED';
  IF next_job IS NOT NULL OR position=jsonb_array_length(targets) THEN
   RETURN jsonb_build_object('evidenceId',prior.selection->'evidenceId','dataClass',data_class,'projectionState','RETIRED',
    'eligible',false,'blockers','[]'::jsonb,'selection',null,'beforeDigest',null,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END);
  END IF;
  target:=targets->position; prior_policy:=jsonb_build_array(prior.selection->'retentionPolicyId',prior.selection->'policyDigest');
  plan:=openpc.projection_deletion_object_plan(right(target->>'evidenceId',36)::uuid,data_class);
 ELSE
  plan:=openpc.projection_deletion_object_plan(record,data_class);
  IF plan IS NULL THEN RETURN NULL; END IF;
  IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
  -- Indexed primary-key keyset within the exact stream and producer. A blocked
  -- member remains in the selection; the next batch must clear its own gates.
  FOR candidate IN SELECT c.evidence_id FROM control.evidence_catalogue c
   WHERE c.participant_id=current_setting('openpc.participant_id')::uuid AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    AND c.stream_id=plan->'selection'->>'streamId' AND c.record_id>=plan->'selection'->>'recordId'
    AND ((data_class='SEARCH_PROJECTION' AND plan->'selection'->>'sourceKind'='AUTHENTICATION_CATALOGUE'
      AND c.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1' AND c.evidence_class='AUTHENTICATION')
     OR (data_class='SEARCH_PROJECTION' AND plan->'selection'->>'sourceKind'='RETENTION_POLICY_CATALOGUE'
      AND c.evidence_class='BUSINESS_TRANSITION' AND EXISTS(SELECT 1 FROM control.evidence_record e
       JOIN control.audit_occurrence a ON a.participant_id=e.participant_id AND a.privacy_domain_id=e.privacy_domain_id AND a.receipt_id=e.receipt_id
       WHERE e.participant_id=c.participant_id AND e.privacy_domain_id=c.privacy_domain_id AND e.evidence_record_id::text=c.record_id
        AND a.aggregate_type='retention-policy' AND a.profile_id IN ('pc.control.retention-policy.activate','pc.control.retention-policy.retire')))
     OR (data_class='SEARCH_PROJECTION' AND plan->'selection'->>'sourceKind'='RPC_RETIRED_CATALOGUE'
      AND c.evidence_class='EFFECT' AND c.source_format='OPENPC_RPC_DECISION_TRANSITION_V1'
      AND openpc.rpc_retired_catalogue_proof(c) IS NOT NULL)
     OR (data_class='NORMALIZED_JSON_PROJECTION' AND plan->'selection'->>'sourceKind'='DEPLOYMENT_PROVENANCE'
      AND c.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' AND EXISTS(SELECT 1 FROM control.evidence_deployment_provenance d
       WHERE d.participant_id=c.participant_id AND d.privacy_domain_id=c.privacy_domain_id AND d.stream_id=c.stream_id AND d.record_id=c.record_id
        AND cardinality(openpc.deployment_projection_retirement_blockers(c,d.projection))=0))
     OR (data_class='NORMALIZED_JSON_PROJECTION' AND plan->'selection'->>'sourceKind'='FACT_PROVENANCE'
      AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND EXISTS(SELECT 1 FROM control.evidence_fact_provenance f
       WHERE f.participant_id=c.participant_id AND f.privacy_domain_id=c.privacy_domain_id AND f.stream_id=c.stream_id AND f.record_id=c.record_id))
     OR (data_class='NORMALIZED_JSON_PROJECTION' AND plan->'selection'->>'sourceKind' IN ('RPC_PRE_ADMISSION_DENIAL','RPC_CLOSED_TRANSITION')
      AND EXISTS(SELECT 1 FROM control.evidence_rpc_provenance r
      WHERE r.participant_id=c.participant_id AND r.privacy_domain_id=c.privacy_domain_id AND r.stream_id=c.stream_id AND r.record_id=c.record_id
       AND CASE WHEN plan->'selection'->>'sourceKind'='RPC_PRE_ADMISSION_DENIAL'
        THEN r.projection->'transition'->>'phase'='PRE_ADMISSION_DENIAL'
        ELSE r.projection->'transition'->>'phase'<>'PRE_ADMISSION_DENIAL'
         AND openpc.rpc_projection_retirement_witness(c,r.projection) IS NOT NULL END)))
   ORDER BY c.record_id LIMIT 16 LOOP
   selected:=openpc.projection_deletion_object_plan(candidate.evidence_id,data_class);
   IF selected->'selection'='null'::jsonb THEN RETURN selected||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
   targets:=targets||jsonb_build_array(openpc.projection_deletion_target(selected));
  END LOOP;
  target:=targets->0;
 END IF;
 IF plan IS NULL OR target IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 blockers:=plan->'blockers';
 IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
 IF openpc.projection_deletion_target(plan) IS DISTINCT FROM target OR
  (prior_policy IS NOT NULL AND prior_policy IS DISTINCT FROM jsonb_build_array(plan->'selection'->'retentionPolicyId',plan->'selection'->'policyDigest'))
 THEN blockers:=blockers||jsonb_build_array('STALE_SELECTION'); END IF;
 RETURN plan||jsonb_build_object('selection',plan->'selection'||jsonb_build_object('priorCursor',cursor,'targets',targets,'batchIndex',position),
  'blockers',blockers,'eligible',jsonb_array_length(blockers)=0,'continuationState',CASE WHEN jsonb_array_length(blockers)=0 THEN 'READY' ELSE 'BLOCKED' END,'nextDeletionJobId',null);
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_catalogue_projection(control.evidence_catalogue),openpc.projection_deletion_object_plan(uuid,text),
 openpc.projection_deletion_target(jsonb),openpc.projection_deletion_batch_plan(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_catalogue_projection(control.evidence_catalogue),openpc.projection_deletion_object_plan(uuid,text),
 openpc.projection_deletion_target(jsonb),openpc.projection_deletion_batch_plan(uuid,uuid,text) TO openpc_control_runtime,openpc_control_reader;
`;
