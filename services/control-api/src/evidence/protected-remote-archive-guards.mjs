/** Source predicates only. The integrator installs this after the protected
 * object/payload and hold source owners. No table, attempt journal, signature,
 * checkpoint, transport permission or deletion eligibility is created here. */
export const protectedRemoteArchiveSourceSql = `
CREATE OR REPLACE FUNCTION openpc.protected_remote_archive_source(
 participant uuid,privacy uuid,proof uuid,sink text,original_intent uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.protected_proof_object; p control.protected_proof_payload;
 c control.evidence_catalogue; h control.retention_hold; metadata jsonb;
 packet jsonb; object jsonb; packet_digest text; observed timestamptz;
 matched boolean; rules jsonb:='[]'::jsonb; retained control.evidence_remote_archive_intent; payload_size integer; cipher_size integer;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id',true) IS DISTINCT FROM 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR participant IS DISTINCT FROM current_setting('openpc.participant_id',true)::uuid
  OR privacy IS DISTINCT FROM current_setting('openpc.privacy_domain_id',true)::uuid
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF proof IS NULL OR proof::text!~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR sink IS NULL OR sink!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 -- The common caller owns its lifecycle fence across this read, STARTED commit
 -- and I/O. No lock or transaction is manufactured by these source predicates.
 SELECT * INTO o FROM control.protected_proof_object candidate
  WHERE candidate.participant_id=participant AND candidate.privacy_domain_id=privacy AND candidate.object_id=proof;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','UNKNOWN','reason','OBJECT_UNAVAILABLE'); END IF;
 SELECT * INTO p FROM control.protected_proof_payload payload
  WHERE payload.participant_id=participant AND payload.privacy_domain_id=privacy AND payload.object_id=proof;
 IF NOT FOUND THEN
  -- A missing local packet is usable only for reconciliation of its original
  -- admitted journal identity, never as authority to recreate or resend bytes.
  SELECT * INTO retained FROM control.evidence_remote_archive_intent i
   WHERE i.participant_id=participant AND i.privacy_domain_id=privacy AND i.intent_id=original_intent
    AND i.source_kind='PROTECTED_PROOF' AND i.protected_object_id=proof
    AND i.protected_object_version=o.object_version AND i.protected_object_digest=o.object_digest AND i.sink_id=sink;
  IF NOT FOUND THEN RETURN jsonb_build_object('state','UNKNOWN','reason','PAYLOAD_UNAVAILABLE'); END IF;
 END IF;
 -- Only the already-governed immutable Identity proof copy qualifies. Catalogue
 -- identity alone cannot substitute for its authenticated occurrence lineage.
 SELECT catalogue.* INTO c FROM control.evidence_catalogue catalogue
  JOIN control.authentication_occurrence a ON a.participant_id=catalogue.participant_id
   AND a.privacy_domain_id=catalogue.privacy_domain_id AND a.occurrence_id::text=catalogue.record_id
   AND a.receipt_digest=sha256(a.receipt) AND a.occurred_at=catalogue.occurred_at
   AND catalogue.receipt_digest='sha256:'||encode(a.receipt_digest,'hex')
  WHERE catalogue.participant_id=participant AND catalogue.privacy_domain_id=privacy
   AND 'urn:openpc:resource:'||catalogue.evidence_id::text=o.source->>'evidenceId'
   AND catalogue.record_id=o.source->>'occurrenceId'
   AND catalogue.receipt_digest=o.source->>'sourceReceiptDigest'
   AND catalogue.evidence_class='AUTHENTICATION' AND catalogue.source_format='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
   AND a.method='WEBAUTHN_ASSERTION' AND a.operation_id::text=o.source->>'operationId'
   AND 'sha256:'||encode(a.proof_digest,'hex')=o.source->>'proofDigest'
   AND to_char(a.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')=o.source->>'occurredAt'
   AND o.source->>'materialType'='IDENTITY_SIGNED_AUTHORIZATION_ASSERTION'
   AND o.source->>'evidenceClass'='AUTHENTICATION'
   AND o.source->>'sourceFormat'='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
   AND o.source->>'occurrenceIntegrity'='CONTROL_DATABASE_IMMUTABLE'
   AND o.source->>'proofIntegrity'='IDENTITY_COSE_ED25519'
   AND o.source->>'finality'='NOT_APPLICABLE' AND o.source->>'authorityEffect'='NONE';
 IF NOT FOUND THEN RETURN jsonb_build_object('state','UNKNOWN','reason','LINEAGE_UNAVAILABLE'); END IF;
 metadata:=openpc.evidence_hold_record_metadata(c);
 IF metadata IS NULL THEN RETURN jsonb_build_object('state','UNKNOWN','reason','HOLD_LINEAGE_UNAVAILABLE'); END IF;
 IF p.object_id IS NOT NULL THEN
  packet:=jsonb_build_object('keyId',p.key_id,
   'nonceBase64',replace(encode(p.nonce,'base64'),chr(10),''),
   'ciphertextBase64',replace(encode(p.ciphertext,'base64'),chr(10),''));
  packet_digest:=openpc.protected_proof_payload_digest(p);
  payload_size:=octet_length(convert_to(openpc.signing_canonical_json(packet),'UTF8'));
  cipher_size:=octet_length(p.ciphertext);
 ELSE
  packet_digest:=retained.intent->>'payloadDigest';
  payload_size:=(retained.intent->>'payloadBytes')::integer;
  cipher_size:=(retained.intent->'source'->'object'->>'ciphertextBytes')::integer;
 END IF;
 object:=openpc.protected_proof_binding(o)||jsonb_build_object('dataClass','RAW_SOURCE_BODY',
  'participantId',participant::text,'privacyDomainId',privacy::text,'sinkId',sink,
  'payloadDigest',packet_digest,'ciphertextBytes',cipher_size,
  'retainUntil',to_char(o.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 IF retained.intent_id IS NOT NULL AND (retained.intent->'source'->'object' IS DISTINCT FROM object
  OR retained.stream_id IS DISTINCT FROM c.stream_id) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOR h IN SELECT candidate.* FROM control.retention_hold candidate
  WHERE candidate.participant_id=participant AND (candidate.selector_type='PARTICIPANT' OR candidate.privacy_domain_id=privacy)
   AND (candidate.state='ACTIVE' OR o.created_at<=candidate.updated_at)
  ORDER BY candidate.retention_hold_id LOOP
  -- A proof created after terminal release did not exist during that rule's
  -- lifetime, even if its original authentication segment is much older.
  matched:=CASE h.selector_type
   WHEN 'PARTICIPANT' THEN true WHEN 'PRIVACY_DOMAIN' THEN true
   WHEN 'DIGEST' THEN h.selector->>'recordDigest' IN (o.object_digest,packet_digest,c.receipt_digest)
   WHEN 'SEQUENCE_RANGE' THEN h.selector->>'streamId'=c.stream_id
    AND c.sequence>=(h.selector->>'fromSequence')::numeric
    AND (h.selector->'throughSequence'='null'::jsonb OR c.sequence<=(h.selector->>'throughSequence')::numeric)
   ELSE openpc.evidence_hold_source_match(h.selector,metadata) END;
  IF matched IS NULL THEN
   RETURN jsonb_build_object('state','UNKNOWN','reason','HOLD_LINEAGE_UNAVAILABLE');
  END IF;
  IF matched THEN
   IF jsonb_array_length(rules)=1024 THEN
    RETURN jsonb_build_object('state','UNKNOWN','reason','TOO_MANY_HOLDS');
   END IF;
   rules:=rules||jsonb_build_array(jsonb_build_object('holdId',h.retention_hold_id::text,
    'selectorDigest',h.selector_digest,'creationOperationId',h.creation_operation_id::text,
    'releaseOperationId',h.release_operation_id::text,'state',h.state,'revision',h.revision::text));
  END IF;
 END LOOP;
 observed:=clock_timestamp();
 RETURN jsonb_build_object('state','BOUND','object',object,'packet',packet,
  'payloadBytes',payload_size,
  'proofCreatedAt',to_char(o.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'observedAt',to_char(observed at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'lineage',jsonb_build_object('evidenceId','urn:openpc:resource:'||c.evidence_id::text,
   'streamId',c.stream_id,'sequence',c.sequence::text,'sourceReceiptDigest',c.receipt_digest),
  'retention',jsonb_build_object('state','UNKNOWN','reason',CASE WHEN o.retain_until<=observed
   THEN 'PROOF_DEADLINE_ELAPSED' ELSE 'PROFILE_NOT_ADMITTED' END),'rules',rules);
END $$;
REVOKE ALL ON FUNCTION openpc.protected_remote_archive_source(uuid,uuid,uuid,text,uuid) FROM PUBLIC,
 openpc_control_runtime,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.protected_remote_archive_source(uuid,uuid,uuid,text,uuid) TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.protected_remote_archive_source(participant uuid,privacy uuid,proof uuid,sink text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT openpc.protected_remote_archive_source(participant,privacy,proof,sink,NULL::uuid)
$$;
REVOKE ALL ON FUNCTION openpc.protected_remote_archive_source(uuid,uuid,uuid,text) FROM PUBLIC,
 openpc_control_runtime,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.protected_remote_archive_source(uuid,uuid,uuid,text) TO openpc_control_worker;
`;
