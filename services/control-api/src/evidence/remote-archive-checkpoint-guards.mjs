/** Remote coverage is a signed exact-version chain, not a local fsync receipt.
 * Historical profile expiry does not erase custody; changed hold state requires
 * a new signed observation before coverage can become current again. */
export const remoteArchiveCheckpointGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.remote_archive_covers(pid uuid,privacy uuid,stream text,segment uuid,sink text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.evidence_remote_archive_intent i
  JOIN control.evidence_remote_archive_attempt a USING(participant_id,privacy_domain_id,intent_id)
  JOIN control.evidence_archive_receipt r USING(participant_id,privacy_domain_id,attempt_id)
  JOIN control.evidence_archive_outbox o USING(participant_id,privacy_domain_id,receipt_id)
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy
   AND i.stream_id=stream AND i.segment_id=segment AND i.sink_id=sink
   AND a.state='OBSERVED' AND a.binding->'protection'->'rules'=openpc.remote_archive_rules(pid,privacy,stream,segment)
   AND NOT EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt newer
    WHERE newer.participant_id=i.participant_id AND newer.privacy_domain_id=i.privacy_domain_id
     AND newer.intent_id=i.intent_id AND (newer.binding->'protection'->>'revision')::numeric>(a.binding->'protection'->>'revision')::numeric))
$$;
REVOKE ALL ON FUNCTION openpc.remote_archive_covers(uuid,uuid,text,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.remote_archive_covers(uuid,uuid,text,uuid,text)
 TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.assert_remote_archive_checkpoint(v control.evidence_checkpoint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r control.evidence_archive_receipt; a control.evidence_remote_archive_attempt;
 i control.evidence_remote_archive_intent; p control.evidence_archive_profile; s control.evidence_segment; expected jsonb;
BEGIN
 p:=openpc.require_archive_profile(current_setting('openpc.archive_profile_digest',true),(v).stream_id);
 SELECT * INTO STRICT r FROM control.evidence_archive_receipt WHERE participant_id=(v).participant_id
  AND privacy_domain_id=(v).privacy_domain_id AND receipt_digest=(v).receipt_digest;
 SELECT * INTO STRICT a FROM control.evidence_remote_archive_attempt WHERE participant_id=r.participant_id
  AND privacy_domain_id=r.privacy_domain_id AND attempt_id=r.attempt_id AND intent_id=r.intent_id AND state='OBSERVED';
 SELECT * INTO STRICT i FROM control.evidence_remote_archive_intent WHERE participant_id=r.participant_id
  AND privacy_domain_id=r.privacy_domain_id AND intent_id=r.intent_id;
 SELECT * INTO STRICT s FROM control.evidence_segment WHERE participant_id=i.participant_id
  AND privacy_domain_id=i.privacy_domain_id AND stream_id=i.stream_id AND segment_id=i.segment_id;
 expected:=jsonb_build_object('kind','SIGNED_REMOTE_ARCHIVE_V1','receiptId',r.receipt_id::text,
  'receiptDigest',r.receipt_digest,'profileDigest',r.profile_digest,'assurance','REMOTE_INTERFACE_VERIFIED',
  'providerQualification','NOT_ESTABLISHED');
 IF (v).receipt IS DISTINCT FROM expected OR (v).sink_id<>i.sink_id OR (v).stream_id<>i.stream_id
  OR (v).segment_id<>i.segment_id OR (v).object_digest<>s.object_digest OR (v).through_sequence<>s.through_sequence
  OR i.profile_digest<>p.transport_digest OR i.profile IS DISTINCT FROM p.transport OR i.sink_id<>p.sink_id
  OR a.binding->'protection'->'rules' IS DISTINCT FROM openpc.remote_archive_rules(s)
  OR NOT openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,i.sink_id)
  OR EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt newer WHERE newer.participant_id=i.participant_id
   AND newer.privacy_domain_id=i.privacy_domain_id AND newer.intent_id=i.intent_id
   AND (newer.binding->'protection'->>'revision')::numeric>(a.binding->'protection'->>'revision')::numeric)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.require_archive_commit_nonce(r);
END $$;
REVOKE ALL ON FUNCTION openpc.assert_remote_archive_checkpoint(control.evidence_checkpoint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_remote_archive_checkpoint(control.evidence_checkpoint) TO openpc_control_worker;
`;
