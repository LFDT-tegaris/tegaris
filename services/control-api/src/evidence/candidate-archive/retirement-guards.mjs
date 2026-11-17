/** The final manifest binds every original chunk. Its checkpoint binds the
 * complete preceding sink chain; every selected sink must cover every part.
 * This is Control custody only. The native owner independently checks live
 * payload, publication, finality, delivery and reference eligibility. */
export const candidateRetirementSourceGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.candidate_retirement_source_binding(policy_id uuid,selection_wire bytea,record_refs jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p uuid:=openpc.current_participant_id(); d uuid:=openpc.current_privacy_domain_id();
 rule control.retention_policy; selection jsonb; selected jsonb; ref jsonb; a control.evidence_candidate_archive;
 actual record; archived record; checkpoint record; identity jsonb; sinks jsonb; chosen text[];
 refs jsonb:='[]'; manifest jsonb:='[]'; acknowledgements jsonb:='[]';
 row_index integer:=0; eligible_ms numeric:=0; ack_ms numeric; latest numeric;
BEGIN
 PERFORM openpc.assert_request_context(false);
 IF octet_length(selection_wire) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 selection:=convert_from(selection_wire,'UTF8')::jsonb;
 IF selection->>'class' IS DISTINCT FROM 'CANDIDATE_PROJECTION'
  OR jsonb_typeof(selection->'rows') IS DISTINCT FROM 'array'
  OR jsonb_array_length(selection->'rows') NOT BETWEEN 1 AND 256
  OR jsonb_typeof(record_refs) IS DISTINCT FROM 'array'
  OR jsonb_array_length(record_refs)<>jsonb_array_length(selection->'rows') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT rule FROM control.retention_policy WHERE participant_id=p AND privacy_domain_id=d
  AND retention_policy_id=policy_id AND data_class='CANDIDATE_PROJECTION' AND deletion_mode='PROJECTION_DELETE' AND active_until IS NULL;
 FOR selected IN SELECT value FROM jsonb_array_elements(selection->'rows') LOOP
  ref:=record_refs->row_index;
  IF ref IS DISTINCT FROM jsonb_build_object('candidateId',selected->>'candidate_id','evidenceId',ref->>'evidenceId')
   THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  SELECT c.evidence_id,c.stream_id,c.record_id,c.sequence,c.receipt_digest,c.occurred_at,
   s.segment_id,s.object_digest,s.first_sequence,s.through_sequence,s.admitted_at INTO STRICT actual
   FROM control.evidence_catalogue c JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
   JOIN control.evidence_stream h USING(participant_id,privacy_domain_id,stream_id)
   WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.evidence_id=(ref->>'evidenceId')::uuid
    AND c.source_format='OPENPC_CANDIDATE_PROJECTION_MANIFEST_V1' AND c.evidence_class='EFFECT'
    AND c.sequence BETWEEN s.first_sequence AND s.through_sequence AND h.last_sequence>=s.through_sequence;
  SELECT * INTO STRICT a FROM control.evidence_candidate_archive WHERE participant_id=p AND privacy_domain_id=d
   AND stream_id=actual.stream_id AND record_id=actual.record_id AND candidate_id=(selected->>'candidate_id')::uuid;
  identity:=a.manifest->'identity';
  IF actual.receipt_digest IS DISTINCT FROM a.manifest_digest
   OR a.manifest_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(a.manifest),'UTF8')),'hex')
   OR identity->>'participantId' IS DISTINCT FROM p::text OR identity->>'privacyDomainId' IS DISTINCT FROM d::text
   OR identity->>'candidateId' IS DISTINCT FROM selected->>'candidate_id'
   OR identity->>'sourceProfileId' IS DISTINCT FROM selection#>>'{source,profile_id}'
   OR identity->>'generationId' IS DISTINCT FROM selection#>>'{source,generation_id}'
   OR identity->>'partitionId' IS DISTINCT FROM selection#>>'{source,partition_id}'
   OR identity->>'publicationDigest' IS DISTINCT FROM 'sha256:'||(selection#>>'{source,identity_digest}')
   OR identity->>'candidateFeedSequence' IS DISTINCT FROM selected->>'candidate_feed_sequence'
   OR identity->>'payloadDigest' IS DISTINCT FROM 'sha256:'||(selected->>'payload_digest')
   OR identity->>'payloadBytes' IS DISTINCT FROM selected->>'payload_bytes'
   OR identity->>'checkpointDigest' IS DISTINCT FROM 'sha256:'||(selected->>'checkpoint_digest')
  THEN RAISE EXCEPTION 'PC-DATA-6007-SOURCE'; END IF;
  -- Zero remote quorum still requires a complete original archive checkpoint
  -- chain, just as the Fact owner requires its original checkpoint. No storage
  -- retention deadline is shortened by retiring the native projection.
  chosen:=ARRAY[]::text[]; sinks:='[]';
  FOR checkpoint IN SELECT c.* FROM control.evidence_checkpoint c WHERE c.participant_id=p AND c.privacy_domain_id=d
   AND c.stream_id=actual.stream_id AND c.segment_id=actual.segment_id AND c.object_digest=actual.object_digest
   AND c.through_sequence=actual.through_sequence ORDER BY c.acknowledged_at,c.sink_id LOOP
   IF openpc.candidate_archive_coverage(p,d,actual.stream_id,actual.record_id,ARRAY[checkpoint.sink_id])->>'state'='COMPLETE' THEN
    chosen:=array_append(chosen,checkpoint.sink_id);
    sinks:=sinks||jsonb_build_array(jsonb_build_object('sinkId',checkpoint.sink_id,'checkpointDigest',checkpoint.checkpoint_digest,
     'receiptDigest',checkpoint.receipt_digest,'acknowledgedAtMicros',floor(extract(epoch from checkpoint.acknowledged_at)*1000000)::text));
    EXIT WHEN cardinality(chosen)=greatest(1,rule.sink_quorum);
   END IF;
  END LOOP;
  IF cardinality(chosen)<>greatest(1,rule.sink_quorum) THEN RAISE EXCEPTION 'PC-DATA-6007-SINK-QUORUM'; END IF;
  FOR archived IN SELECT DISTINCT c.occurred_at,s.segment_id,s.object_digest,s.through_sequence,s.admitted_at
   FROM control.evidence_candidate_archive_part part JOIN control.evidence_catalogue c USING(participant_id,privacy_domain_id,stream_id,record_id)
   JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE part.participant_id=p AND part.privacy_domain_id=d AND part.stream_id=actual.stream_id AND part.manifest_record_id=actual.record_id LOOP
   IF EXISTS(SELECT 1 FROM control.retention_hold hold WHERE hold.participant_id=p
    AND (hold.selector_type='PARTICIPANT' OR hold.privacy_domain_id=d) AND hold.state='ACTIVE'
    AND openpc.evidence_hold_matches(hold.selector,p,d,actual.stream_id,archived.segment_id))
    THEN RAISE EXCEPTION 'PC-DATA-6007-ACTIVE-HOLD'; END IF;
   SELECT max(ceil(extract(epoch from c.acknowledged_at)*1000)) INTO ack_ms FROM control.evidence_checkpoint c
    WHERE c.participant_id=p AND c.privacy_domain_id=d AND c.stream_id=actual.stream_id
     AND c.segment_id=archived.segment_id AND c.object_digest=archived.object_digest AND c.through_sequence=archived.through_sequence
     AND c.sink_id=ANY(chosen);
   latest:=greatest(ceil(extract(epoch from archived.occurred_at)*1000)+rule.retention_period_ms,
    greatest(ack_ms,ceil(extract(epoch from archived.admitted_at)*1000))+rule.local_grace_ms);
   eligible_ms:=greatest(eligible_ms,latest);
  END LOOP;
  refs:=refs||jsonb_build_array(ref);
  manifest:=manifest||jsonb_build_array(jsonb_build_object('candidateId',selected->>'candidate_id',
   'evidenceId',actual.evidence_id::text,'streamId',actual.stream_id,'recordId',actual.record_id,
   'sequence',actual.sequence::text,'recordDigest',actual.receipt_digest,'segmentId',actual.segment_id::text,'objectDigest',actual.object_digest));
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
REVOKE ALL ON FUNCTION openpc.candidate_retirement_source_binding(uuid,bytea,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.candidate_retirement_source_binding(uuid,bytea,jsonb) TO openpc_control_runtime,openpc_control_worker;
`;
