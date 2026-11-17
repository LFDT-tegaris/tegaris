/** The native owner verifies the closed PurposeSigner profile and actual TLS
 * peer before attesting these original bytes. Separate operation domains and a
 * private per-login bridge key prevent ordinary SQL roles fabricating proof. */
export const targetDispositionReceiptSql = `
CREATE OR REPLACE FUNCTION openpc.commit_runtime_target_disposition(
 kind text,wire bytea,nonce bytea,mac bytea)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE envelope jsonb; receipt_claims jsonb; identity jsonb; pid uuid; privacy uuid; target uuid; principal uuid;
 secret bytea; expected bytea; different integer:=0; wire_digest text; prior bytea; wanted_revision bigint;
 head control.runtime_target_disposition_admission; delivery control.runtime_target_disposition_delivery;
 authority record; previous_sequence numeric;
BEGIN
 PERFORM openpc.assert_runtime_target_disposition_owner();
 PERFORM openpc.assert_request_context(true);
 IF openpc.current_action_intent_id()<>'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
  OR kind IS NULL OR kind NOT IN ('DELIVERY','ACK') OR wire IS NULL OR octet_length(wire) NOT BETWEEN 1 AND 16384
  OR nonce IS NULL OR octet_length(nonce)<>32 OR mac IS NULL OR octet_length(mac)<>32
  OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_target_disposition_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_TARGET_DISPOSITION_'||kind||'_V1','UTF8')||sha256(wire)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 envelope:=convert_from(wire,'UTF8')::jsonb; receipt_claims:=envelope->'claims'; identity:=receipt_claims->'target';
 IF envelope->>'purpose' IS DISTINCT FROM (CASE kind WHEN 'DELIVERY' THEN 'openpc:target-disposition-delivery:v1'
   ELSE 'openpc:target-disposition-acknowledgement:v1' END)
  OR envelope IS DISTINCT FROM jsonb_build_object('purpose',envelope->'purpose','claims',receipt_claims,
   'claims_digest',envelope->'claims_digest','signature_p1363_hex',envelope->'signature_p1363_hex')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 pid:=(identity->>'participant_id')::uuid; privacy:=(identity->>'privacy_domain_id')::uuid; target:=(identity->>'target_id')::uuid;
 IF pid IS DISTINCT FROM openpc.current_participant_id() OR privacy IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR target IS NULL THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT authority FROM openpc.lock_runtime_discovery_authority(target,'sha256:'||(identity->>'certificate_digest'));
 SELECT c.principal_id INTO STRICT principal FROM control.credential c
  WHERE c.participant_id=pid AND c.credential_id=authority.credential_id;
 IF identity IS DISTINCT FROM jsonb_build_object('participant_id',pid::text,'privacy_domain_id',privacy::text,'target_id',target::text,
  'credential_id',authority.credential_id::text,'principal_id',principal::text,'credential_epoch',authority.credential_epoch,
  'principal_epoch',authority.principal_epoch,'certificate_digest',identity->>'certificate_digest')
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-IDENTITY'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||pid::text||':'||privacy::text||':'||target::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 wire_digest:='sha256:'||encode(sha256(wire),'hex');
 SELECT * INTO STRICT head FROM control.runtime_target_disposition_admission a
  WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target ORDER BY a.revision DESC LIMIT 1;
 IF kind='DELIVERY' THEN
  wanted_revision:=(receipt_claims->>'revision')::bigint;
  SELECT d.signed_delivery INTO prior FROM control.runtime_target_disposition_delivery d
   WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target AND d.revision=wanted_revision;
  IF FOUND THEN
   IF prior IS DISTINCT FROM wire THEN RAISE EXCEPTION 'TARGET-DISPOSITION-REPLAY-CONFLICT'; END IF;
   RETURN false;
  END IF;
  IF wanted_revision<>head.revision OR receipt_claims IS DISTINCT FROM
   head.binding||jsonb_build_object('committed_admission_digest',substring(head.admission_digest from 8))
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ADMISSION'; END IF;
  INSERT INTO control.runtime_target_disposition_delivery(participant_id,privacy_domain_id,runtime_target_id,revision,
   predecessor_digest,claims,signed_delivery,delivery_digest)
  VALUES(pid,privacy,target,wanted_revision,CASE WHEN receipt_claims->>'previous_delivery_digest' IS NULL THEN NULL
   ELSE 'sha256:'||(receipt_claims->>'previous_delivery_digest') END,receipt_claims,wire,wire_digest);
 ELSE
  wanted_revision:=(receipt_claims->>'disposition_revision')::bigint;
  SELECT * INTO STRICT delivery FROM control.runtime_target_disposition_delivery d
   WHERE d.participant_id=pid AND d.privacy_domain_id=privacy AND d.runtime_target_id=target
    AND d.delivery_digest='sha256:'||(receipt_claims->>'delivery_digest') AND d.revision=wanted_revision;
  IF receipt_claims IS DISTINCT FROM jsonb_build_object('version',1,'target',delivery.claims->'target',
   'delivery_digest',substring(delivery.delivery_digest from 8),'disposition_revision',delivery.revision,
   'journal_sequence',receipt_claims->'journal_sequence','installed_state',(CASE delivery.claims->>'action'
    WHEN 'Withdraw' THEN 'NewUseDenied' WHEN 'Restore' THEN 'SuspensionCleared' WHEN 'ConfirmActivation' THEN 'ActivationConfirmed' END))
   OR jsonb_typeof(receipt_claims->'journal_sequence') IS DISTINCT FROM 'number'
   OR (receipt_claims->>'journal_sequence')::numeric NOT BETWEEN 1 AND 9223372036854775807
   OR (receipt_claims->>'journal_sequence')::numeric<>trunc((receipt_claims->>'journal_sequence')::numeric)
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-ACK-BINDING'; END IF;
  SELECT a.signed_acknowledgement INTO prior FROM control.runtime_target_disposition_acknowledgement a
   WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target
    AND a.delivery_digest=delivery.delivery_digest;
  IF FOUND THEN
   IF prior IS DISTINCT FROM wire THEN RAISE EXCEPTION 'TARGET-DISPOSITION-REPLAY-CONFLICT'; END IF;
   RETURN false;
  END IF;
  IF wanted_revision<>head.revision THEN RAISE EXCEPTION 'TARGET-DISPOSITION-CAS'; END IF;
  SELECT max((a.claims->>'journal_sequence')::numeric) INTO previous_sequence
   FROM control.runtime_target_disposition_acknowledgement a
   WHERE a.participant_id=pid AND a.privacy_domain_id=privacy AND a.runtime_target_id=target;
  IF (receipt_claims->>'journal_sequence')::numeric<=coalesce(previous_sequence,0)
  THEN RAISE EXCEPTION 'TARGET-DISPOSITION-JOURNAL-ROLLBACK'; END IF;
  INSERT INTO control.runtime_target_disposition_acknowledgement(participant_id,privacy_domain_id,runtime_target_id,
   delivery_digest,claims,signed_acknowledgement,acknowledgement_digest)
  VALUES(pid,privacy,target,delivery.delivery_digest,receipt_claims,wire,wire_digest);
 END IF;
 RETURN true;
END $$;
ALTER FUNCTION openpc.commit_runtime_target_disposition(text,bytea,bytea,bytea) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.commit_runtime_target_disposition(text,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.commit_runtime_target_disposition(text,bytea,bytea,bytea) TO openpc_control_worker;
`;
