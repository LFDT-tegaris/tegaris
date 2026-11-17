export const protectedProofCustodyGuardsSql = `
ALTER TABLE control.protected_proof_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.protected_proof_checkpoint FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.protected_proof_checkpoint TO openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT INSERT ON control.protected_proof_checkpoint TO openpc_control_worker;
GRANT SELECT ON control.protected_proof_object,control.protected_proof_payload TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.protected_proof_payload_digest(payload control.protected_proof_payload)
RETURNS text LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'keyId',(payload).key_id,'nonceBase64',replace(encode((payload).nonce,'base64'),chr(10),''),
  'ciphertextBase64',replace(encode((payload).ciphertext,'base64'),chr(10),''))),'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION openpc.protected_proof_payload_digest(control.protected_proof_payload) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.protected_proof_payload_digest(control.protected_proof_payload) TO openpc_control_runtime,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_protected_proof_checkpoint()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE object control.protected_proof_object; payload control.protected_proof_payload; expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT object FROM control.protected_proof_object
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 SELECT * INTO STRICT payload FROM control.protected_proof_payload
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND object_id=NEW.object_id;
 IF NEW.payload_digest IS DISTINCT FROM openpc.protected_proof_payload_digest(payload)
  OR NEW.ciphertext_bytes<>octet_length(payload.ciphertext) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF NEW.receipt->>'kind'='SIGNED_REMOTE_PROTECTED_ARCHIVE_V1' THEN
  PERFORM openpc.assert_protected_remote_checkpoint(NEW);
 ELSE
 expected:=jsonb_build_object('object',openpc.protected_proof_binding(object)||jsonb_build_object(
  'dataClass','RAW_SOURCE_BODY','participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,
  'sinkId',NEW.sink_id,'payloadDigest',NEW.payload_digest,'ciphertextBytes',NEW.ciphertext_bytes,
  'retainUntil',to_char(object.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
  'versionId',NEW.payload_digest,'assurance','LOCAL_FSYNC_READBACK');
 IF NEW.receipt-'receiptDigest' IS DISTINCT FROM expected OR NEW.receipt->>'receiptDigest' IS DISTINCT FROM NEW.receipt_digest
  OR NEW.receipt_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 END IF;
 expected:=jsonb_build_object('domain','pc.evidence.protected-checkpoint.v1','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'objectRef','urn:openpc:resource:'||NEW.object_id::text,
  'objectVersion',object.object_version::text,'sinkId',NEW.sink_id,'payloadDigest',NEW.payload_digest,'receiptDigest',NEW.receipt_digest);
 IF NEW.checkpoint_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.acknowledged_at:=clock_timestamp();
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_protected_proof_checkpoint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.guard_protected_proof_checkpoint() TO openpc_control_worker;
DROP TRIGGER IF EXISTS protected_proof_checkpoint_guard ON control.protected_proof_checkpoint;
CREATE TRIGGER protected_proof_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON control.protected_proof_checkpoint
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_protected_proof_checkpoint();
GRANT EXECUTE ON FUNCTION openpc.protected_proof_binding(control.protected_proof_object) TO openpc_control_worker;
`;
