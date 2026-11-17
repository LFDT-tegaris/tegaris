/** Exact protected-object custody. These predicates authenticate immutable
 * journal/receipt bindings; they never reconstruct missing local ciphertext. */
export const protectedRemoteCustodyGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.protected_remote_archive_rules(pid uuid,privacy uuid,proof uuid,sink text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i control.evidence_remote_archive_intent; c control.evidence_catalogue; created timestamptz;
 h control.retention_hold; metadata jsonb; matched boolean; rules jsonb:='[]'::jsonb;
BEGIN
 SELECT * INTO i FROM control.evidence_remote_archive_intent candidate WHERE candidate.participant_id=pid
  AND candidate.privacy_domain_id=privacy AND candidate.protected_object_id=proof AND candidate.sink_id=sink
  AND candidate.source_kind='PROTECTED_PROOF';
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT o.created_at INTO created FROM control.protected_proof_object o WHERE o.participant_id=pid
  AND o.privacy_domain_id=privacy AND o.object_id=proof AND o.object_version=i.protected_object_version
  AND o.object_digest=i.protected_object_digest;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO c FROM control.evidence_catalogue candidate WHERE candidate.participant_id=pid
  AND candidate.privacy_domain_id=privacy AND candidate.stream_id=i.stream_id
  AND 'urn:openpc:resource:'||candidate.evidence_id::text=i.intent->'source'->'object'->'source'->>'evidenceId'
  AND candidate.receipt_digest=i.intent->'source'->'object'->'source'->>'sourceReceiptDigest';
 IF NOT FOUND THEN RETURN NULL; END IF;
 metadata:=openpc.evidence_hold_record_metadata(c);
 IF metadata IS NULL THEN RETURN NULL; END IF;
 FOR h IN SELECT candidate.* FROM control.retention_hold candidate WHERE candidate.participant_id=pid
  AND (candidate.selector_type='PARTICIPANT' OR candidate.privacy_domain_id=privacy)
  AND (candidate.state='ACTIVE' OR created<=candidate.updated_at) ORDER BY candidate.retention_hold_id LOOP
  matched:=CASE h.selector_type
   WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
   WHEN 'DIGEST' THEN h.selector->>'recordDigest' IN (i.protected_object_digest,i.intent->>'payloadDigest',c.receipt_digest)
   WHEN 'SEQUENCE_RANGE' THEN h.selector->>'streamId'=c.stream_id AND c.sequence>=(h.selector->>'fromSequence')::numeric
    AND (h.selector->'throughSequence'='null'::jsonb OR c.sequence<=(h.selector->>'throughSequence')::numeric)
   ELSE openpc.evidence_hold_source_match(h.selector,metadata) END;
  IF matched IS NULL THEN RETURN NULL; END IF;
  IF matched THEN
   IF jsonb_array_length(rules)=1024 THEN RETURN NULL; END IF;
   rules:=rules||jsonb_build_array(jsonb_build_object('holdId',h.retention_hold_id::text,
    'selectorDigest',h.selector_digest,'creationOperationId',h.creation_operation_id::text,
    'releaseOperationId',h.release_operation_id::text,'state',h.state,'revision',h.revision::text));
  END IF;
 END LOOP;
 RETURN rules;
END $$;
REVOKE ALL ON FUNCTION openpc.protected_remote_archive_rules(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_remote_archive_rules(uuid,uuid,uuid,text)
 TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.protected_remote_archive_covers(pid uuid,privacy uuid,proof uuid,sink text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.evidence_remote_archive_intent i
  JOIN control.evidence_remote_archive_attempt a USING(participant_id,privacy_domain_id,intent_id)
  JOIN control.evidence_archive_receipt r USING(participant_id,privacy_domain_id,attempt_id)
  JOIN control.evidence_archive_outbox o USING(participant_id,privacy_domain_id,receipt_id)
  WHERE i.participant_id=pid AND i.privacy_domain_id=privacy AND i.protected_object_id=proof
   AND i.sink_id=sink AND i.source_kind='PROTECTED_PROOF' AND a.state='OBSERVED'
   AND a.binding->'protection'->'rules'=openpc.protected_remote_archive_rules(pid,privacy,proof,sink)
   AND NOT EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt newer WHERE newer.participant_id=pid
    AND newer.privacy_domain_id=privacy AND newer.intent_id=i.intent_id
    AND (newer.binding->'protection'->>'revision')::numeric>(a.binding->'protection'->>'revision')::numeric))
$$;
REVOKE ALL ON FUNCTION openpc.protected_remote_archive_covers(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_remote_archive_covers(uuid,uuid,uuid,text)
 TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.protected_remote_checkpoint_valid(v control.protected_proof_checkpoint)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM control.evidence_remote_archive_intent i
  JOIN control.evidence_remote_archive_attempt a USING(participant_id,privacy_domain_id,intent_id)
  JOIN control.evidence_archive_receipt r USING(participant_id,privacy_domain_id,attempt_id)
  JOIN control.evidence_archive_outbox o USING(participant_id,privacy_domain_id,receipt_id)
  WHERE i.participant_id=(v).participant_id AND i.privacy_domain_id=(v).privacy_domain_id
   AND i.protected_object_id=(v).object_id AND i.sink_id=(v).sink_id AND i.source_kind='PROTECTED_PROOF'
   AND i.intent->>'payloadDigest'=(v).payload_digest AND (i.intent->'source'->'object'->>'ciphertextBytes')::integer=(v).ciphertext_bytes
   AND r.receipt_digest=(v).receipt_digest AND a.state='OBSERVED'
   AND (v).receipt=jsonb_build_object('kind','SIGNED_REMOTE_PROTECTED_ARCHIVE_V1','receiptId',r.receipt_id::text,
    'receiptDigest',r.receipt_digest,'profileDigest',r.profile_digest,'assurance','REMOTE_INTERFACE_VERIFIED',
    'providerQualification','NOT_ESTABLISHED'))
$$;
REVOKE ALL ON FUNCTION openpc.protected_remote_checkpoint_valid(control.protected_proof_checkpoint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_remote_checkpoint_valid(control.protected_proof_checkpoint)
 TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;

CREATE OR REPLACE FUNCTION openpc.assert_protected_remote_checkpoint(v control.protected_proof_checkpoint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i control.evidence_remote_archive_intent; p control.evidence_archive_profile; r control.evidence_archive_receipt;
BEGIN
 SELECT * INTO STRICT i FROM control.evidence_remote_archive_intent WHERE participant_id=(v).participant_id
  AND privacy_domain_id=(v).privacy_domain_id AND protected_object_id=(v).object_id AND sink_id=(v).sink_id AND source_kind='PROTECTED_PROOF';
 p:=openpc.require_archive_profile(current_setting('openpc.archive_profile_digest',true),i.stream_id);
 IF p.claims->>'sourceKind' IS DISTINCT FROM 'PROTECTED_PROOF' OR p.transport IS DISTINCT FROM i.profile
  OR p.transport_digest IS DISTINCT FROM i.profile_digest OR p.sink_id IS DISTINCT FROM i.sink_id
  OR NOT openpc.protected_remote_checkpoint_valid(v)
  OR NOT openpc.protected_remote_archive_covers(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT r FROM control.evidence_archive_receipt WHERE participant_id=(v).participant_id
  AND privacy_domain_id=(v).privacy_domain_id AND receipt_digest=(v).receipt_digest;
 IF EXISTS(SELECT 1 FROM control.evidence_remote_archive_attempt newer WHERE newer.participant_id=i.participant_id
  AND newer.privacy_domain_id=i.privacy_domain_id AND newer.intent_id=i.intent_id
  AND (newer.binding->'protection'->>'revision')::numeric>(openpc.business_cbor(r.payload)->>'13')::numeric)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.require_archive_commit_nonce(r);
END $$;
REVOKE ALL ON FUNCTION openpc.assert_protected_remote_checkpoint(control.protected_proof_checkpoint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_protected_remote_checkpoint(control.protected_proof_checkpoint) TO openpc_control_worker;
`;
