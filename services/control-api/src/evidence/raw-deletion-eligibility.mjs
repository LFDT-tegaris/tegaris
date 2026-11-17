/** RAW_SOURCE_BODY is the exact encrypted protected-proof copy, not its
 * authentication receipt, archive, catalogue or original Identity assertion. */
export const rawProofDeletionEligibilitySql = `
CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_object_plan(object_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE object control.protected_proof_object; payload control.protected_proof_payload;
 source control.evidence_catalogue; rule control.retention_policy; receipts jsonb; selection jsonb;
 blockers text[]:=ARRAY[]::text[]; expected_payload_digest text; before_digest text; eligible_micros numeric;
 quorum_micros numeric; source_micros numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO object FROM control.protected_proof_object o
  WHERE o.participant_id=current_setting('openpc.participant_id')::uuid
   AND o.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND o.object_id=raw_proof_deletion_object_plan.object_id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO payload FROM control.protected_proof_payload p WHERE p.participant_id=object.participant_id
  AND p.privacy_domain_id=object.privacy_domain_id AND p.object_id=object.object_id;
 IF NOT FOUND THEN
  IF NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id) WHERE j.participant_id=object.participant_id
    AND j.privacy_domain_id=object.privacy_domain_id AND j.protected_object_id=object.object_id
    AND i.protected_object_id=object.object_id AND j.target_data_class='RAW_SOURCE_BODY' AND j.state='SUCCEEDED')
   THEN RAISE EXCEPTION 'PC-DATA-6004-RAW-PAYLOAD'; END IF;
  RETURN jsonb_build_object('objectRef','urn:openpc:resource:'||object.object_id::text,
   'localPayload','DELETED','eligible',false,'blockers',jsonb_build_array('ALREADY_DELETED'),'selection',null,'beforeDigest',null);
 END IF;
 expected_payload_digest:=openpc.protected_proof_payload_digest(payload);
 SELECT c.* INTO source FROM control.evidence_catalogue c JOIN control.authentication_occurrence a
  ON a.participant_id=c.participant_id AND a.privacy_domain_id=c.privacy_domain_id
   AND a.occurrence_id::text=c.record_id AND c.receipt_digest='sha256:'||encode(a.receipt_digest,'hex')
   AND a.receipt_digest=sha256(a.receipt) AND a.occurred_at=c.occurred_at AND a.method='WEBAUTHN_ASSERTION'
  WHERE c.participant_id=object.participant_id AND c.privacy_domain_id=object.privacy_domain_id
   AND 'urn:openpc:resource:'||c.evidence_id::text=object.source->>'evidenceId'
   AND c.record_id=object.source->>'occurrenceId' AND c.receipt_digest=object.source->>'sourceReceiptDigest'
   AND c.evidence_class='AUTHENTICATION' AND c.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
   AND object.source->>'materialType'='IDENTITY_SIGNED_AUTHORIZATION_ASSERTION'
   AND object.source->>'finality'='NOT_APPLICABLE' AND object.source->>'authorityEffect'='NONE';
 IF NOT FOUND THEN blockers:=array_append(blockers,'UNSUPPORTED_SOURCE'); END IF;
 -- These immutable local authentication sources have no chain finality/reorg
 -- dimension. Missing source lineage is a blocker, never a no-gap assertion.
 IF source.evidence_id IS NULL OR NOT EXISTS(SELECT 1 FROM control.protected_proof_checkpoint c
  WHERE c.participant_id=object.participant_id AND c.privacy_domain_id=object.privacy_domain_id
   AND c.object_id=object.object_id AND c.payload_digest=expected_payload_digest
   AND c.ciphertext_bytes=octet_length(payload.ciphertext)
   AND ((c.receipt->'object'->>'objectDigest'=object.object_digest
   AND c.receipt->'object'->>'objectVersion'=object.object_version::text
   AND c.receipt->'object'->'source'=object.source
   AND c.receipt->>'versionId'=expected_payload_digest AND c.receipt->>'receiptDigest'=c.receipt_digest) OR (openpc.protected_remote_checkpoint_valid(c)
    AND openpc.protected_remote_archive_covers(object.participant_id,object.privacy_domain_id,object.object_id,c.sink_id)))) THEN
  blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT');
 END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=object.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=object.privacy_domain_id) AND h.state='ACTIVE'
  AND (CASE h.selector_type
   WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
   WHEN 'DIGEST' THEN (h.selector->>'recordDigest' IN (object.object_digest,expected_payload_digest,source.receipt_digest))
   WHEN 'SEQUENCE_RANGE' THEN h.selector->>'streamId'=source.stream_id
    AND source.sequence>=(h.selector->>'fromSequence')::numeric
    AND (h.selector->'throughSequence'='null'::jsonb OR source.sequence<=(h.selector->>'throughSequence')::numeric)
   ELSE openpc.evidence_hold_source_match(h.selector,openpc.evidence_hold_record_metadata(source))
  END) IS DISTINCT FROM false) THEN blockers:=array_append(blockers,'ACTIVE_HOLD'); END IF;
 -- References to immutable object metadata remain valid; a live disclosure
 -- depends on the payload and must finish/expire. Unknown future physical FKs
 -- require their owning clearance protocol before this adapter can resume.
 IF EXISTS(SELECT 1 FROM control.protected_proof_access a WHERE a.participant_id=object.participant_id
  AND a.privacy_domain_id=object.privacy_domain_id AND a.object_id=object.object_id
  AND a.consumed_at IS NULL AND a.expires_at>clock_timestamp())
  OR EXISTS(SELECT 1 FROM control.evidence_remote_archive_intent i WHERE i.participant_id=object.participant_id
   AND i.privacy_domain_id=object.privacy_domain_id AND i.protected_object_id=object.object_id AND i.source_kind='PROTECTED_PROOF'
   AND (NOT openpc.protected_remote_archive_covers(object.participant_id,object.privacy_domain_id,object.object_id,i.sink_id)
    OR NOT EXISTS(SELECT 1 FROM control.protected_proof_checkpoint c WHERE c.participant_id=object.participant_id
     AND c.privacy_domain_id=object.privacy_domain_id AND c.object_id=object.object_id AND c.sink_id=i.sink_id
     AND openpc.protected_remote_checkpoint_valid(c))))
  OR EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.protected_proof_payload'::regclass)
 THEN blockers:=array_append(blockers,'REFERENCES'); END IF;
 SELECT * INTO rule FROM control.retention_policy p WHERE p.participant_id=object.participant_id
  AND p.privacy_domain_id=object.privacy_domain_id AND p.data_class='RAW_SOURCE_BODY' AND p.active_until IS NULL;
 IF NOT FOUND THEN blockers:=array_append(blockers,'NO_ACTIVE_POLICY');
 ELSE
  IF rule.deletion_mode<>'ROW_DELETE' THEN blockers:=array_append(blockers,'UNSUPPORTED_MODE'); END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',chosen.sink_id,'checkpointDigest',chosen.checkpoint_digest,
   'receiptDigest',chosen.receipt_digest,'acknowledgedAtMicros',chosen.ack_micros::text)
   ORDER BY chosen.ack_micros,chosen.sink_id),'[]'::jsonb),max(chosen.ack_micros)
   INTO receipts,quorum_micros FROM (
    SELECT c.sink_id,c.checkpoint_digest,c.receipt_digest,floor(extract(epoch from c.acknowledged_at)*1000000) ack_micros
    FROM control.protected_proof_checkpoint c WHERE c.participant_id=object.participant_id
     AND c.privacy_domain_id=object.privacy_domain_id AND c.object_id=object.object_id
     AND c.payload_digest=expected_payload_digest AND c.ciphertext_bytes=octet_length(payload.ciphertext)
     AND ((c.receipt->'object'->>'objectDigest'=object.object_digest AND c.receipt->'object'->'source'=object.source
     AND c.receipt->>'versionId'=expected_payload_digest AND c.receipt->>'receiptDigest'=c.receipt_digest) OR (openpc.protected_remote_checkpoint_valid(c)
      AND openpc.protected_remote_archive_covers(object.participant_id,object.privacy_domain_id,object.object_id,c.sink_id)))
    ORDER BY c.acknowledged_at,c.sink_id LIMIT rule.sink_quorum) chosen;
  IF jsonb_array_length(receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
  source_micros:=floor(extract(epoch from source.occurred_at)*1000000);
  eligible_micros:=greatest(source_micros+rule.retention_period_ms*1000,
   coalesce(quorum_micros,floor(extract(epoch from object.created_at)*1000000))+rule.local_grace_ms*1000,
   floor(extract(epoch from object.retain_until)*1000000));
  IF eligible_micros>floor(extract(epoch from clock_timestamp())*1000000) THEN blockers:=array_append(blockers,'RETENTION_NOT_ELAPSED'); END IF;
  selection:=jsonb_build_object('version','OPENPC_RAW_PROOF_DELETION_BATCH_V1',
   'participantId','urn:openpc:participant:'||object.participant_id::text,'privacyDomainId',object.privacy_domain_id::text,
   'retentionPolicyId','urn:openpc:resource:'||rule.retention_policy_id::text,'policyDigest',rule.policy_digest,
   'targetDatabase','openpc_control','dataClass','RAW_SOURCE_BODY','deletionMode','ROW_DELETE',
   'objectRef','urn:openpc:resource:'||object.object_id::text,'objectVersion',object.object_version::text,
   'objectDigest',object.object_digest,'payloadDigest',expected_payload_digest,'ciphertextBytes',octet_length(payload.ciphertext),
   'source',object.source,'eligibleAfterMicros',eligible_micros::text,'sinkReceipts',receipts);
  before_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
   'domain','pc.evidence.raw-proof-before.v1','participantId',object.participant_id::text,'privacyDomainId',object.privacy_domain_id::text,
   'objectRef',selection->'objectRef','objectVersion',selection->'objectVersion','objectDigest',object.object_digest,
   'payloadDigest',expected_payload_digest,'ciphertextBytes',octet_length(payload.ciphertext))),'UTF8')),'hex');
 END IF;
 RETURN jsonb_build_object('objectRef','urn:openpc:resource:'||object.object_id::text,'localPayload','RETAINED',
  'eligible',cardinality(blockers)=0,'blockers',to_jsonb(blockers),'selection',selection,'beforeDigest',before_digest);
END $$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_object_plan(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_object_plan(uuid) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_target(plan jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('objectRef',plan->'selection'->'objectRef','objectVersion',plan->'selection'->'objectVersion',
  'objectDigest',plan->'selection'->'objectDigest','payloadDigest',plan->'selection'->'payloadDigest',
  'ciphertextBytes',plan->'selection'->'ciphertextBytes','beforeDigest',plan->'beforeDigest')
$$;

CREATE OR REPLACE FUNCTION openpc.raw_proof_deletion_batch_plan(anchor uuid,previous uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE plan jsonb; selected jsonb; targets jsonb:='[]'::jsonb; target jsonb; candidate record;
 prior control.deletion_job; receipt_digest text; next_job uuid; position integer:=0;
 cursor jsonb:='null'::jsonb; prior_policy jsonb; blockers jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF (anchor IS NULL)=(previous IS NULL) THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF previous IS NOT NULL THEN
  SELECT * INTO prior FROM control.deletion_job j WHERE j.participant_id=current_setting('openpc.participant_id')::uuid
   AND j.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND j.deletion_job_id=previous;
  IF NOT FOUND OR prior.state<>'SUCCEEDED' OR prior.selection->>'version'<>'OPENPC_RAW_PROOF_DELETION_BATCH_V1' THEN RETURN NULL; END IF;
  SELECT 'sha256:'||encode(a.receipt_digest,'hex') INTO receipt_digest FROM control.audit_occurrence a
   WHERE a.participant_id=prior.participant_id AND a.privacy_domain_id=prior.privacy_domain_id
    AND a.aggregate_type='evidence-deletion' AND a.aggregate_id=prior.deletion_job_id AND a.operation_id=prior.operation_id
    AND a.profile_id='pc.control.evidence-deletion.raw-proof' AND a.catalog_operation_id='CFG-OP-DELETE-RAW-PROOF-BATCH';
  IF receipt_digest IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  targets:=prior.selection->'targets';position:=(prior.selection->>'batchIndex')::integer+1;
  cursor:=jsonb_build_object('deletionJobId','urn:openpc:resource:'||previous::text,'receiptDigest',receipt_digest);
  SELECT deletion_job_id INTO next_job FROM control.deletion_job j WHERE j.participant_id=prior.participant_id
   AND j.privacy_domain_id=prior.privacy_domain_id AND j.previous_deletion_job_id=previous AND j.state='SUCCEEDED';
  IF next_job IS NOT NULL OR position=jsonb_array_length(targets) THEN
   RETURN jsonb_build_object('objectRef',prior.selection->'objectRef','localPayload','DELETED','eligible',false,
    'blockers','[]'::jsonb,'selection',null,'beforeDigest',null,
    'continuationState',CASE WHEN next_job IS NULL THEN 'COMPLETE' ELSE 'ADVANCED' END,
    'nextDeletionJobId',CASE WHEN next_job IS NULL THEN NULL ELSE 'urn:openpc:resource:'||next_job::text END);
  END IF;
  target:=targets->position;
  prior_policy:=jsonb_build_array(prior.selection->'retentionPolicyId',prior.selection->'policyDigest');
  plan:=openpc.raw_proof_deletion_object_plan(right(target->>'objectRef',36)::uuid);
 ELSE
  plan:=openpc.raw_proof_deletion_object_plan(anchor);
  IF plan IS NULL THEN RETURN NULL; END IF;
  IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
  FOR candidate IN SELECT o.object_id FROM control.protected_proof_object o
   JOIN control.protected_proof_payload p USING(participant_id,privacy_domain_id,object_id)
   WHERE o.participant_id=current_setting('openpc.participant_id')::uuid AND o.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    AND o.object_id>=anchor ORDER BY o.object_id LIMIT 16 LOOP
   selected:=openpc.raw_proof_deletion_object_plan(candidate.object_id);
   IF selected->'selection'='null'::jsonb THEN RETURN selected||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
   targets:=targets||jsonb_build_array(openpc.raw_proof_deletion_target(selected));
  END LOOP;
  target:=targets->0;
 END IF;
 IF plan IS NULL OR target IS NULL THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 blockers:=plan->'blockers';
 IF plan->'selection'='null'::jsonb THEN RETURN plan||jsonb_build_object('continuationState','BLOCKED','nextDeletionJobId',null); END IF;
 IF openpc.raw_proof_deletion_target(plan) IS DISTINCT FROM target OR
  (prior_policy IS NOT NULL AND prior_policy IS DISTINCT FROM jsonb_build_array(plan->'selection'->'retentionPolicyId',plan->'selection'->'policyDigest'))
 THEN blockers:=blockers||jsonb_build_array('STALE_SELECTION'); END IF;
 selected:=(plan->'selection')||jsonb_build_object('targets',targets,'batchIndex',position,'priorCursor',cursor);
 RETURN plan||jsonb_build_object('eligible',jsonb_array_length(blockers)=0,'blockers',blockers,
  'selection',CASE WHEN blockers ? 'STALE_SELECTION' THEN NULL ELSE selected END,
  'continuationState',CASE WHEN jsonb_array_length(blockers)=0 THEN 'READY' ELSE 'BLOCKED' END,'nextDeletionJobId',null);
END $$;
REVOKE ALL ON FUNCTION openpc.raw_proof_deletion_target(jsonb),openpc.raw_proof_deletion_batch_plan(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.raw_proof_deletion_target(jsonb),openpc.raw_proof_deletion_batch_plan(uuid,uuid) TO openpc_control_runtime;
`;
