import { candidateRetirementSourceGuardsSql } from './candidate-archive/retirement-guards.mjs';

/** Control custody is checked independently of the live native source owner.
 * The source verifier must still prove the selected real target payloads and
 * target eligibility; archived history alone never establishes those facts. */
export const storeRetirementSourceGuardsSql = `${candidateRetirementSourceGuardsSql}
CREATE OR REPLACE FUNCTION openpc.store_retirement_source_binding(policy_id uuid,selection_wire bytea,record_refs jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p uuid:=openpc.current_participant_id(); d uuid:=openpc.current_privacy_domain_id();
 rule control.retention_policy; selection jsonb; refs jsonb:='[]'::jsonb; manifest jsonb:='[]'::jsonb;
 acknowledgements jsonb:='[]'::jsonb; selected jsonb; ref jsonb; actual record; sinks jsonb;
 ack_ms numeric; eligible_ms numeric:=0; row_index integer:=0; latest numeric;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF octet_length(selection_wire) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 selection:=convert_from(selection_wire,'UTF8')::jsonb;
 IF selection->>'class'='CANDIDATE_PROJECTION' THEN
  RETURN openpc.candidate_retirement_source_binding(policy_id,selection_wire,record_refs);
 END IF;
 IF selection->>'class' IS DISTINCT FROM 'ADMITTED_FACT' THEN RAISE EXCEPTION 'PC-DATA-6007-UNSUPPORTED-SOURCE'; END IF;
 IF jsonb_typeof(selection->'rows') IS DISTINCT FROM 'array'
  OR jsonb_array_length(selection->'rows') NOT BETWEEN 1 AND 256
  OR jsonb_typeof(record_refs) IS DISTINCT FROM 'array'
  OR jsonb_array_length(record_refs)<>jsonb_array_length(selection->'rows') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT rule FROM control.retention_policy WHERE participant_id=p AND privacy_domain_id=d
  AND retention_policy_id=policy_id AND data_class='ADMITTED_FACT' AND deletion_mode='ROW_DELETE' AND active_until IS NULL;
 FOR selected IN SELECT value FROM jsonb_array_elements(selection->'rows') LOOP
  ref:=record_refs->row_index;
  IF ref IS DISTINCT FROM jsonb_build_object('candidateId',selected->>'candidate_id','evidenceId',ref->>'evidenceId')
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT c.evidence_id,c.stream_id,c.record_id,c.sequence,c.receipt_digest,c.occurred_at,
   s.segment_id,s.object_digest,s.first_sequence,s.through_sequence,s.admitted_at
  INTO STRICT actual FROM control.evidence_catalogue c JOIN control.evidence_segment s
   USING(participant_id,privacy_domain_id,stream_id,segment_id)
   JOIN control.evidence_stream h USING(participant_id,privacy_domain_id,stream_id)
  WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.evidence_id=(ref->>'evidenceId')::uuid
   AND c.source_format='OPENPC_CANONICAL_FACT_V1' AND c.evidence_class='EFFECT'
   AND c.receipt_digest='sha256:'||(selected->>'signed_fact_digest')
   AND c.sequence BETWEEN s.first_sequence AND s.through_sequence AND h.last_sequence>=s.through_sequence;
  IF EXISTS(SELECT 1 FROM control.retention_hold hold WHERE hold.participant_id=p
   AND (hold.selector_type='PARTICIPANT' OR hold.privacy_domain_id=d) AND hold.state='ACTIVE'
   AND openpc.evidence_hold_matches(hold.selector,p,d,actual.stream_id,actual.segment_id))
   THEN RAISE EXCEPTION 'PC-DATA-6007-ACTIVE-HOLD'; END IF;
  -- A complete original checkpoint remains required even for a zero-quorum
  -- policy. This never changes the independent archive's retention deadline.
  IF NOT EXISTS(SELECT 1 FROM control.evidence_checkpoint c WHERE c.participant_id=p AND c.privacy_domain_id=d
   AND c.stream_id=actual.stream_id AND c.segment_id=actual.segment_id AND c.object_digest=actual.object_digest
   AND c.through_sequence=actual.through_sequence) THEN RAISE EXCEPTION 'PC-DATA-6007-CHECKPOINT'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('sinkId',s.sink_id,'checkpointDigest',s.checkpoint_digest,
   'receiptDigest',s.receipt_digest,'acknowledgedAtMicros',s.ack_micros::text) ORDER BY s.ack_micros,s.sink_id),'[]'::jsonb),
   max(ceil(s.ack_micros/1000)) INTO sinks,ack_ms FROM (
    SELECT c.sink_id,c.checkpoint_digest,c.receipt_digest,floor(extract(epoch from c.acknowledged_at)*1000000) ack_micros
     FROM control.evidence_checkpoint c WHERE c.participant_id=p AND c.privacy_domain_id=d
      AND c.stream_id=actual.stream_id AND c.segment_id=actual.segment_id AND c.object_digest=actual.object_digest
      AND c.through_sequence=actual.through_sequence AND c.receipt->>'receiptDigest'=c.receipt_digest
      AND c.receipt->'object'->>'objectDigest'=actual.object_digest
     ORDER BY c.acknowledged_at,c.sink_id LIMIT rule.sink_quorum
   ) s;
  IF jsonb_array_length(sinks)<>rule.sink_quorum THEN RAISE EXCEPTION 'PC-DATA-6007-SINK-QUORUM'; END IF;
  latest:=greatest(ceil(extract(epoch from actual.occurred_at)*1000)+rule.retention_period_ms,
    coalesce(ack_ms,ceil(extract(epoch from actual.admitted_at)*1000))+rule.local_grace_ms);
  eligible_ms:=greatest(eligible_ms,latest);
  refs:=refs||jsonb_build_array(ref);
  manifest:=manifest||jsonb_build_array(jsonb_build_object('candidateId',selected->>'candidate_id',
    'evidenceId',actual.evidence_id::text,'streamId',actual.stream_id,'recordId',actual.record_id,
    'sequence',actual.sequence::text,'recordDigest',actual.receipt_digest,'segmentId',actual.segment_id::text,
    'objectDigest',actual.object_digest));
  acknowledgements:=acknowledgements||jsonb_build_array(jsonb_build_object('candidateId',selected->>'candidate_id','sinkReceipts',sinks));
  row_index:=row_index+1;
 END LOOP;
 IF eligible_ms>floor(extract(epoch from clock_timestamp())*1000) OR eligible_ms>9223372036854775807
  THEN RAISE EXCEPTION 'PC-DATA-6007-RETENTION'; END IF;
 RETURN jsonb_build_object('version','OPENPC_STORE_RETIREMENT_SOURCE_V1','selectionWireHex',encode(selection_wire,'hex'),
  'recordRefs',refs,'manifest',manifest,'acknowledgements',acknowledgements,
  'archiveManifestDigest',encode(sha256(convert_to(openpc.signing_canonical_json(manifest),'UTF8')),'hex'),
  'archiveAcknowledgementDigest',encode(sha256(convert_to(openpc.signing_canonical_json(acknowledgements),'UTF8')),'hex'),
  'retentionNotBeforeMs',eligible_ms::text,'lifecycleRevision',openpc.store_retirement_lifecycle_revision(p,d)::text);
END $$;
REVOKE ALL ON FUNCTION openpc.store_retirement_source_binding(uuid,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.store_retirement_source_binding(uuid,bytea,jsonb) TO openpc_control_runtime,openpc_control_worker;
`;
