/** A shared read/mutation oracle derives eligibility from real scoped owners.
 * No caller can provide hold, sink, time, reference or recovery readiness.
 */
export const evidenceDeletionEligibilitySql = `
CREATE OR REPLACE FUNCTION openpc.local_evidence_deletion_plan(record uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s record; rule control.retention_policy%ROWTYPE;
 payload_bytes integer; record_count integer; first_seq numeric; last_seq numeric;
 local_sources boolean; source_micros numeric; quorum_micros numeric; eligible_micros numeric; rejections jsonb; rpc_retirements jsonb;
 sink_receipts jsonb; selection jsonb; before_digest text; blockers text[]:=ARRAY[]::text[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT segment.participant_id,segment.privacy_domain_id,segment.stream_id,segment.segment_id,
  segment.first_sequence,segment.through_sequence,segment.object_digest,segment.retention_until,segment.admitted_at
  INTO s FROM control.evidence_catalogue c JOIN control.evidence_segment segment
  USING(participant_id,privacy_domain_id,stream_id,segment_id)
  WHERE c.participant_id=current_setting('openpc.participant_id')::uuid
   AND c.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid AND c.evidence_id=record;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT ciphertext_bytes INTO payload_bytes FROM control.evidence_segment_payload p
  WHERE p.participant_id=s.participant_id AND p.privacy_domain_id=s.privacy_domain_id
   AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id;
 IF NOT FOUND THEN
  IF NOT EXISTS(SELECT 1 FROM control.deletion_job j JOIN control.evidence_deletion_item i
   USING(participant_id,privacy_domain_id,deletion_job_id) WHERE j.participant_id=s.participant_id
    AND j.privacy_domain_id=s.privacy_domain_id AND j.segment_id=s.segment_id AND i.segment_id=s.segment_id
    AND j.state='SUCCEEDED') THEN RAISE EXCEPTION 'PC-DATA-6004-EVIDENCE-PAYLOAD'; END IF;
  RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'localPayload','DELETED',
   'eligible',false,'blockers',jsonb_build_array('ALREADY_DELETED'),'selection',null,'beforeDigest',null);
 END IF;
 SELECT count(*)::integer,min(sequence),max(sequence),floor(extract(epoch from max(occurred_at))*1000000),
  bool_and(evidence_class IN ('AUTHENTICATION','BUSINESS_TRANSITION'))
  INTO record_count,first_seq,last_seq,source_micros,local_sources FROM control.evidence_catalogue c
  WHERE c.participant_id=s.participant_id AND c.privacy_domain_id=s.privacy_domain_id
   AND c.stream_id=s.stream_id AND c.segment_id=s.segment_id;
 IF record_count NOT BETWEEN 1 AND 128 OR record_count<>s.through_sequence-s.first_sequence+1 OR first_seq<>s.first_sequence OR last_seq<>s.through_sequence
  OR NOT EXISTS(SELECT 1 FROM control.evidence_stream h WHERE h.participant_id=s.participant_id
   AND h.privacy_domain_id=s.privacy_domain_id AND h.stream_id=s.stream_id AND h.last_sequence>=s.through_sequence)
  OR NOT EXISTS(SELECT 1 FROM control.evidence_checkpoint p WHERE p.participant_id=s.participant_id
   AND p.privacy_domain_id=s.privacy_domain_id AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id
   AND p.object_digest=s.object_digest AND p.through_sequence=s.through_sequence) THEN
  blockers:=array_append(blockers,'INCOMPLETE_CHECKPOINT');
 END IF;
 -- Distinct source proofs: actual pre-handoff rejection, or an already signed
 -- physical retirement of a closed RPC projection. Neither substitutes for the other.
 -- Submitted/ambiguous/unretired RPC observations remain blocked.
 IF NOT coalesce(local_sources,false) THEN
  -- Catalogue-only readers do not gain raw prepared-command privileges.
  IF pg_has_role(current_user,'openpc_control_runtime','USAGE') THEN
   rejections:=openpc.evidence_deletion_rejections(s.stream_id,s.segment_id);
   rpc_retirements:=openpc.rpc_local_payload_retirements(s.stream_id,s.segment_id);
  END IF;
  IF rejections IS NULL OR rpc_retirements IS NULL OR jsonb_array_length(rejections)+jsonb_array_length(rpc_retirements)=0 THEN
   blockers:=array_append(blockers,'UNSUPPORTED_SOURCE');
  END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM control.retention_hold h WHERE h.participant_id=s.participant_id
  AND (h.selector_type='PARTICIPANT' OR h.privacy_domain_id=s.privacy_domain_id) AND h.state='ACTIVE'
  AND openpc.evidence_hold_matches(h.selector,s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id)) THEN
  blockers:=array_append(blockers,'ACTIVE_HOLD');
 END IF;
 -- This target table deliberately has no incoming references. A future owner
 -- adding one must supply a real clearing/alias protocol before deletion resumes.
 IF EXISTS(SELECT 1 FROM pg_constraint WHERE contype='f' AND confrelid='control.evidence_segment_payload'::regclass) THEN
  blockers:=array_append(blockers,'REFERENCES');
 END IF;
 SELECT * INTO rule FROM control.retention_policy p WHERE p.participant_id=s.participant_id
  AND p.privacy_domain_id=s.privacy_domain_id AND p.data_class='AUDIT_EVIDENCE' AND p.active_until IS NULL;
 IF NOT FOUND THEN blockers:=array_append(blockers,'NO_ACTIVE_POLICY');
 ELSE
  IF rule.deletion_mode<>'ROW_DELETE' THEN blockers:=array_append(blockers,'UNSUPPORTED_MODE'); END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',chosen.sink_id,'checkpointDigest',chosen.checkpoint_digest,
   'receiptDigest',chosen.receipt_digest,'acknowledgedAtMicros',chosen.ack_micros::text)
    ORDER BY chosen.ack_micros,chosen.sink_id),'[]'::jsonb),max(chosen.ack_micros)
   INTO sink_receipts,quorum_micros FROM (
    SELECT p.sink_id,p.checkpoint_digest,p.receipt_digest,floor(extract(epoch from p.acknowledged_at)*1000000) ack_micros
    FROM control.evidence_checkpoint p WHERE p.participant_id=s.participant_id AND p.privacy_domain_id=s.privacy_domain_id
     AND p.stream_id=s.stream_id AND p.segment_id=s.segment_id AND p.object_digest=s.object_digest
     AND p.through_sequence=s.through_sequence AND p.receipt->>'receiptDigest'=p.receipt_digest
     AND p.receipt->'object'->>'objectDigest'=s.object_digest
    ORDER BY p.acknowledged_at,p.sink_id LIMIT rule.sink_quorum
   ) chosen;
  IF jsonb_array_length(sink_receipts)<>rule.sink_quorum THEN blockers:=array_append(blockers,'SINK_QUORUM'); END IF;
  eligible_micros:=greatest(source_micros+rule.retention_period_ms*1000,
   coalesce(quorum_micros,floor(extract(epoch from s.admitted_at)*1000000))+rule.local_grace_ms*1000,
   floor(extract(epoch from s.retention_until)*1000000));
  IF eligible_micros>floor(extract(epoch from clock_timestamp())*1000000) THEN
   blockers:=array_append(blockers,'RETENTION_NOT_ELAPSED');
  END IF;
  IF record_count BETWEEN 1 AND 128 THEN
   selection:=jsonb_build_object('version','OPENPC_LOCAL_EVIDENCE_DELETION_V1',
    'evidenceId','urn:openpc:resource:'||record::text,'participantId','urn:openpc:participant:'||s.participant_id::text,
    'privacyDomainId',s.privacy_domain_id::text,'retentionPolicyId','urn:openpc:resource:'||rule.retention_policy_id::text,
    'policyDigest',rule.policy_digest,'targetDatabase','openpc_control','dataClass','AUDIT_EVIDENCE','deletionMode','ROW_DELETE',
    'streamId',s.stream_id,'segmentId',s.segment_id::text,'firstSequence',s.first_sequence::text,
    'throughSequence',s.through_sequence::text,'objectDigest',s.object_digest,'ciphertextBytes',payload_bytes,
    'recordCount',record_count,'eligibleAfterMicros',eligible_micros::text,'sinkReceipts',sink_receipts,'priorCursor',null);
   IF rejections IS NOT NULL AND jsonb_array_length(rejections)>0 THEN
    selection:=selection||jsonb_build_object('sourceRejections',rejections);
   END IF;
   IF rpc_retirements IS NOT NULL AND jsonb_array_length(rpc_retirements)>0 THEN
    selection:=selection||jsonb_build_object('sourceRpcRetirements',rpc_retirements);
   END IF;
   before_digest:='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
    'domain','pc.evidence.local-payload-before.v1','participantId',s.participant_id::text,'privacyDomainId',s.privacy_domain_id::text,
    'streamId',s.stream_id,'segmentId',s.segment_id::text,'objectDigest',s.object_digest,
    'ciphertextBytes',payload_bytes,'recordCount',record_count)),'UTF8')),'hex');
  END IF;
 END IF;
 RETURN jsonb_build_object('evidenceId','urn:openpc:resource:'||record::text,'localPayload','RETAINED',
  'eligible',cardinality(blockers)=0,'blockers',to_jsonb(blockers),'selection',selection,'beforeDigest',before_digest);
END $$;
REVOKE ALL ON FUNCTION openpc.local_evidence_deletion_plan(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.local_evidence_deletion_plan(uuid) TO openpc_control_runtime,openpc_control_reader;
`;
