import { evidenceArchiveProfiles } from '../../../../packages/security-kernel/src/evidence-archive/generated.ts';
import { remoteArchiveProfileGuardsSql } from './remote-archive-profile-guards.mjs';
import { remoteArchiveCheckpointGuardsSql } from './remote-archive-checkpoint-guards.mjs';

const r = evidenceArchiveProfiles.EvidenceSinkReceiptV1;
const protectedReceipt = evidenceArchiveProfiles.EvidenceProtectedSinkReceiptV1;
export const remoteArchiveCustodyGuardsSql = `
${remoteArchiveProfileGuardsSql}
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
ALTER TABLE control.evidence_archive_commit_nonce FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_archive_commit_nonce FROM PUBLIC,openpc_control_worker,openpc_control_runtime,openpc_control_reader;
GRANT SELECT,INSERT ON control.evidence_archive_commit_nonce TO openpc_control_owner,openpc_control_key_governor;
DROP POLICY IF EXISTS archive_nonce_verifier ON control.evidence_archive_commit_nonce;
CREATE POLICY archive_nonce_verifier ON control.evidence_archive_commit_nonce TO openpc_control_owner,openpc_control_key_governor USING(true) WITH CHECK(true);
ALTER TABLE control.evidence_archive_commit_nonce ALTER CONSTRAINT evidence_archive_commit_nonce_receipt_fk DEFERRABLE INITIALLY DEFERRED;
GRANT USAGE ON SCHEMA openpc,control,public TO openpc_control_key_governor;

/** The worker login cannot read the verifier secret or write the nonce table.
 * The MAC binds the actual signed bytes. A deferred FK and receipt completion
 * check prevent consuming it without committing the exact receipt and outbox. */
CREATE OR REPLACE FUNCTION openpc.consume_archive_commit(p control.evidence_archive_profile,a control.evidence_remote_archive_attempt,v control.evidence_archive_receipt)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE secret bytea; expected bytea; different integer:=0;
BEGIN
 IF session_user IS DISTINCT FROM p.claims->>'databaseRole'
  OR v.participant_id<>p.participant_id OR v.privacy_domain_id<>p.privacy_domain_id
  OR a.participant_id<>v.participant_id OR a.privacy_domain_id<>v.privacy_domain_id
  OR a.attempt_id<>v.attempt_id OR v.profile_digest<>p.profile_digest
  OR v.receipt_digest<>'sha256:'||encode(sha256(v.cose),'hex')
  OR octet_length(v.commit_nonce)<>32 OR octet_length(v.commit_mac)<>32
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.evidence_archive_commit_key
  WHERE participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id
   AND environment_id=p.environment_id AND sink_id=p.sink_id;
 expected:=public.hmac(convert_to('OPENPC_REMOTE_ARCHIVE_CUSTODY_COMMIT_V1','UTF8')
  ||uuid_send(v.participant_id)||uuid_send(v.privacy_domain_id)||sha256(v.cose)||sha256(v.payload)
  ||decode(substring(p.profile_digest from 8),'hex')||decode(substring(a.binding_digest from 8),'hex')||v.commit_nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different | (get_byte(expected,n) # get_byte(v.commit_mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 INSERT INTO control.evidence_archive_commit_nonce(participant_id,privacy_domain_id,nonce,receipt_id,receipt_digest)
  VALUES(v.participant_id,v.privacy_domain_id,v.commit_nonce,v.receipt_id,v.receipt_digest);
END $$;
ALTER FUNCTION openpc.consume_archive_commit(control.evidence_archive_profile,control.evidence_remote_archive_attempt,control.evidence_archive_receipt) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.consume_archive_commit(control.evidence_archive_profile,control.evidence_remote_archive_attempt,control.evidence_archive_receipt) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.consume_archive_commit(control.evidence_archive_profile,control.evidence_remote_archive_attempt,control.evidence_archive_receipt) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_archive_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p control.evidence_archive_profile; a control.evidence_remote_archive_attempt; i control.evidence_remote_archive_intent;
 s control.evidence_segment; previous control.evidence_archive_receipt; actual jsonb; expected jsonb; recorded numeric; signer text; facts jsonb; object jsonb; protected_source boolean;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT a FROM control.evidence_remote_archive_attempt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id AND intent_id=NEW.intent_id AND state='OBSERVED';
 SELECT * INTO STRICT i FROM control.evidence_remote_archive_intent WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND intent_id=a.intent_id;
 p:=openpc.require_archive_profile(NEW.profile_digest,i.stream_id);
 protected_source:=i.source_kind='PROTECTED_PROOF';
 IF coalesce(p.claims->>'sourceKind','SEGMENT') IS DISTINCT FROM i.source_kind THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF protected_source THEN
  facts:=openpc.protected_remote_archive_source(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id,i.intent_id);
  IF facts->>'state' IS DISTINCT FROM 'BOUND' OR facts->'object' IS DISTINCT FROM i.intent->'source'->'object'
   OR facts->'lineage'->>'streamId' IS DISTINCT FROM i.stream_id
   OR (a.observation->'observedRetention'->>'retainUntil')::timestamptz IS DISTINCT FROM (facts->'object'->>'retainUntil')::timestamptz
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
  object:=facts->'object';
 ELSE
  SELECT * INTO STRICT s FROM control.evidence_segment WHERE participant_id=i.participant_id
   AND privacy_domain_id=i.privacy_domain_id AND stream_id=i.stream_id AND segment_id=i.segment_id;
 END IF;
 recorded:=floor(extract(epoch FROM NEW.recorded_at)*1000000);
 signer:='sha256:'||encode(sha256(decode(p.claims->>'receiptSignerSpki','hex')),'hex');
 IF i.profile_digest<>p.transport_digest OR i.profile IS DISTINCT FROM p.transport OR i.sink_id<>p.sink_id
  OR p.participant_id<>NEW.participant_id OR p.privacy_domain_id<>NEW.privacy_domain_id
  OR recorded<(p.claims->>'validFromMs')::numeric*1000 OR recorded>=(p.claims->>'validUntilMs')::numeric*1000
  OR NEW.recorded_at<a.updated_at
  OR NEW.recorded_at>clock_timestamp() OR NEW.recorded_at<clock_timestamp()-interval '30 seconds'
  OR NEW.receipt_id::text!~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO previous FROM control.evidence_archive_receipt prior WHERE prior.participant_id=i.participant_id
  AND prior.privacy_domain_id=i.privacy_domain_id AND prior.intent_id=i.intent_id
  ORDER BY (openpc.business_cbor(prior.payload)->>'13')::numeric DESC LIMIT 1;
 IF (a.action='PUT' AND (previous.receipt_id IS NOT NULL OR NEW.previous_receipt_digest IS NOT NULL))
  OR (a.action='PROTECTION' AND (previous.receipt_id IS NULL OR NEW.previous_receipt_digest IS DISTINCT FROM previous.receipt_digest
   OR (openpc.business_cbor(previous.payload)->>'13')::numeric>=(a.binding->'protection'->>'revision')::numeric))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 actual:=openpc.business_cbor(NEW.payload);
 expected:=jsonb_build_object('0',openpc.business_bytes(decode(CASE WHEN protected_source THEN '${protectedReceipt.definitionDigest.slice(7)}' ELSE '${r.definitionDigest.slice(7)}' END,'hex')),
  '1',p.environment_id,'2',openpc.business_uuid(i.participant_id),'3',openpc.business_uuid(i.privacy_domain_id),
  '4',openpc.business_uuid(NEW.receipt_id),'5',openpc.business_uuid(i.intent_id),'6',openpc.business_uuid(a.attempt_id),
  '7',openpc.business_bytes(decode(substring(p.profile_digest from 8),'hex')),
  '8',openpc.business_bytes(decode(substring(a.observation_digest from 8),'hex')),
  '9',openpc.business_bytes(decode(substring(a.binding_digest from 8),'hex')),
  '10',openpc.business_bytes(decode(substring(CASE WHEN protected_source THEN object->>'objectDigest' ELSE s.object_digest END from 8),'hex')),
  '11',openpc.business_bytes(sha256(convert_to(openpc.signing_canonical_json(a.observation->'locator'),'UTF8'))),
  '12',openpc.business_bytes(decode(substring(a.protection_digest from 8),'hex')),
  '13',(a.binding->'protection'->>'revision')::numeric,
  '14',floor(extract(epoch FROM (a.observation->'observedRetention'->>'retainUntil')::timestamptz)*1000000),
  '15',recorded,'16',openpc.business_bytes(coalesce(decode(substring(NEW.previous_receipt_digest from 8),'hex'),''::bytea)),
  '17',CASE a.action WHEN 'PUT' THEN 1 ELSE 2 END,'18',openpc.business_bytes(decode(substring(signer from 8),'hex')),
  '19',i.stream_id,'22',1,'23',0);
 IF protected_source THEN
  expected:=expected||jsonb_build_object('20',openpc.business_uuid(i.protected_object_id),'21',i.protected_object_version,
   '24',openpc.business_bytes(decode(substring(object->>'payloadDigest' from 8),'hex')),
   '25',openpc.business_bytes(sha256(convert_to(openpc.signing_canonical_json(object->'source'),'UTF8'))),
   '26',floor(extract(epoch FROM (object->>'retainUntil')::timestamptz)*1000000));
 ELSE expected:=expected||jsonb_build_object('20',openpc.business_uuid(i.segment_id),'21',s.through_sequence); END IF;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.archive_cose_binding(NEW.payload,NEW.cose,signer,CASE WHEN protected_source THEN ${protectedReceipt.schemaId} ELSE ${r.schemaId} END,CASE WHEN protected_source THEN ${protectedReceipt.purposeCode} ELSE ${r.purposeCode} END);
 PERFORM openpc.consume_archive_commit(p,a,NEW);
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_archive_outbox()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.evidence_archive_receipt; actual jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 SELECT * INTO STRICT receipt FROM control.evidence_archive_receipt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 actual:=openpc.business_cbor(NEW.event);
 IF actual IS DISTINCT FROM jsonb_build_object('0','pc.evidence.remote-custody.v1',
  '1',openpc.business_uuid(receipt.participant_id),'2',openpc.business_uuid(receipt.privacy_domain_id),
  '3',openpc.business_uuid(receipt.receipt_id),'4',openpc.business_bytes(decode(substring(receipt.receipt_digest from 8),'hex')),
  '5',openpc.business_bytes(decode(substring(receipt.profile_digest from 8),'hex')),'6',openpc.business_uuid(receipt.attempt_id))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_archive_commit_nonce(receipt control.evidence_archive_receipt)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_archive_commit_nonce n WHERE n.participant_id=receipt.participant_id
   AND n.privacy_domain_id=receipt.privacy_domain_id AND n.receipt_id=receipt.receipt_id
   AND n.receipt_digest=receipt.receipt_digest AND n.nonce=receipt.commit_nonce)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
END $$;
ALTER FUNCTION openpc.require_archive_commit_nonce(control.evidence_archive_receipt) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.require_archive_commit_nonce(control.evidence_archive_receipt) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.require_archive_commit_nonce(control.evidence_archive_receipt) TO openpc_control_worker;
CREATE OR REPLACE FUNCTION openpc.complete_archive_receipt()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE receipt control.evidence_archive_receipt;
BEGIN
 SELECT * INTO STRICT receipt FROM control.evidence_archive_receipt WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.receipt_id;
 PERFORM openpc.require_archive_profile(receipt.profile_digest,openpc.business_cbor(receipt.payload)->>'19');
 PERFORM openpc.require_archive_commit_nonce(receipt);
 IF NOT EXISTS(SELECT 1 FROM control.evidence_archive_outbox o WHERE o.participant_id=receipt.participant_id
  AND o.privacy_domain_id=receipt.privacy_domain_id AND o.receipt_id=receipt.receipt_id)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION openpc.complete_archive_receipt() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.complete_archive_nonce()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.evidence_archive_receipt r JOIN control.evidence_archive_outbox o
  USING(participant_id,privacy_domain_id,receipt_id) WHERE r.participant_id=NEW.participant_id
   AND r.privacy_domain_id=NEW.privacy_domain_id AND r.receipt_id=NEW.receipt_id
   AND r.commit_nonce=NEW.nonce AND r.receipt_digest=NEW.receipt_digest)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 RETURN NULL;
END $$;
ALTER FUNCTION openpc.complete_archive_nonce() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.complete_archive_nonce() FROM PUBLIC;
${['receipt', 'outbox']
  .map(
    (name) => `
ALTER TABLE control.evidence_archive_${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_archive_${name} FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT ON control.evidence_archive_${name} TO openpc_control_runtime,openpc_control_reader,openpc_control_owner,openpc_control_key_governor;
GRANT SELECT,INSERT ON control.evidence_archive_${name} TO openpc_control_worker;
DROP POLICY IF EXISTS archive_completion ON control.evidence_archive_${name};
CREATE POLICY archive_completion ON control.evidence_archive_${name} FOR SELECT TO openpc_control_owner,openpc_control_key_governor USING(true);
DROP TRIGGER IF EXISTS archive_${name} ON control.evidence_archive_${name};
CREATE TRIGGER archive_${name} BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_archive_${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_${name}();`,
  )
  .join('\n')}
DROP TRIGGER IF EXISTS archive_receipt_complete ON control.evidence_archive_receipt;
CREATE CONSTRAINT TRIGGER archive_receipt_complete AFTER INSERT ON control.evidence_archive_receipt
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.complete_archive_receipt();
DROP TRIGGER IF EXISTS archive_nonce_complete ON control.evidence_archive_commit_nonce;
CREATE CONSTRAINT TRIGGER archive_nonce_complete AFTER INSERT ON control.evidence_archive_commit_nonce
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.complete_archive_nonce();
${remoteArchiveCheckpointGuardsSql}
`;
