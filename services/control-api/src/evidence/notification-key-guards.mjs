import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';

const policyField = notificationCoseProfiles.NotificationRoutingProfileV1.fields.find(
  (field) => field.name === 'payloadKeyPolicyDigest',
).key;

/** Existing Drizzle/security-tail owner installs this beside the two declarations.
 * These append-only references protect original source/key identities. No delete,
 * key-destruction or consumer-closure capability is introduced. */
export const notificationKeyCustodyGuardsSql = String.raw`
ALTER TABLE control.notification_key_preparation FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_key_ciphertext FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification_key_preparation,control.notification_key_ciphertext FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.notification_key_preparation,control.notification_key_ciphertext TO openpc_control_runtime;
CREATE OR REPLACE FUNCTION openpc.guard_notification_key_custody() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb; i jsonb; o jsonb; source control.evidence_export_completion%ROWTYPE;
 route control.installed_notification_routing%ROWTYPE; kms control.evidence_kms_installation%ROWTYPE;
 prep control.notification_key_preparation%ROWTYPE; attempt control.evidence_kms_attempt%ROWTYPE;
 exchange control.evidence_kms_exchange%ROWTYPE; allowed text[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'NOTIFICATION-KEY-IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 IF TG_TABLE_NAME='notification_key_preparation' THEN
  p:=NEW.preparation; i:=p->'input'; o:=p->'objectIntent';
  allowed:=ARRAY['purpose','preparationId','occurrenceId','input','sourceEventId','sourceDataDigest',
    'sourceReceiptDigest','routingInstallationDigest','kms','objectIntent'];
  IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR p-allowed IS DISTINCT FROM '{}'::jsonb OR NOT p ?& allowed
  OR jsonb_typeof(i) IS DISTINCT FROM 'object'
  OR i-ARRAY['scope','evidenceExportId','producerTrustDigest','kmsInstallationDigest','routing'] IS DISTINCT FROM '{}'::jsonb
  OR NOT i ?& ARRAY['scope','evidenceExportId','producerTrustDigest','kmsInstallationDigest','routing']
  OR jsonb_typeof(i->'scope') IS DISTINCT FROM 'object'
  OR (i->'scope')-ARRAY['participantId','privacyDomainId','streamId'] IS DISTINCT FROM '{}'::jsonb
  OR NOT (i->'scope') ?& ARRAY['participantId','privacyDomainId','streamId']
  OR jsonb_typeof(i->'routing') IS DISTINCT FROM 'object'
  OR (i->'routing')-ARRAY['profileId','revision','signedProfileDigest'] IS DISTINCT FROM '{}'::jsonb
  OR NOT (i->'routing') ?& ARRAY['profileId','revision','signedProfileDigest']
  OR jsonb_typeof(o) IS DISTINCT FROM 'object'
  OR o-ARRAY['environmentId','participantId','privacyDomainId','payloadObjectId','objectVersion',
    'notificationOccurrenceRef','routingProfileDigest','templateDigest','recipientSetDigest',
    'redactionProfileDigest','preferenceGeneration','payloadDigest'] IS DISTINCT FROM '{}'::jsonb
  OR NOT o ?& ARRAY['environmentId','participantId','privacyDomainId','payloadObjectId','objectVersion',
    'notificationOccurrenceRef','routingProfileDigest','templateDigest','recipientSetDigest',
    'redactionProfileDigest','preferenceGeneration','payloadDigest']
  OR p->>'purpose' IS DISTINCT FROM 'NOTIFICATION_PAYLOAD'
  OR p->>'preparationId' IS DISTINCT FROM NEW.preparation_id::text
  OR p->>'occurrenceId' IS DISTINCT FROM NEW.occurrence_id::text
  OR p->>'sourceEventId' IS DISTINCT FROM NEW.source_event_id::text
  OR i->'scope'->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR i->'scope'->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR i->'routing'->>'profileId' IS DISTINCT FROM NEW.routing_profile_id::text
  OR i->>'kmsInstallationDigest' IS DISTINCT FROM NEW.kms_installation_digest
  OR o->>'payloadObjectId' IS DISTINCT FROM NEW.payload_object_id::text
  OR o->>'objectVersion' IS DISTINCT FROM '1'
  OR o->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR o->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR o->>'notificationOccurrenceRef' IS DISTINCT FROM 'urn:openpc:notification-occurrence:'||NEW.occurrence_id::text
  OR o->>'routingProfileDigest' IS DISTINCT FROM i->'routing'->>'signedProfileDigest'
  OR NEW.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8')
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-BINDING'; END IF;
  SELECT * INTO source FROM control.evidence_export_completion WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.source_event_id;
  IF NOT FOUND OR source.evidence_export_id::text IS DISTINCT FROM i->>'evidenceExportId'
   OR source.stream_id IS DISTINCT FROM i->'scope'->>'streamId'
   OR source.trust_digest IS DISTINCT FROM i->>'producerTrustDigest'
   OR source.receipt_payload_digest IS DISTINCT FROM p->>'sourceReceiptDigest'
   OR source.claims->>'dataDigest' IS DISTINCT FROM p->>'sourceDataDigest'
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-SOURCE'; END IF;
  SELECT * INTO kms FROM control.evidence_kms_installation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND installation_digest=NEW.kms_installation_digest;
  IF NOT FOUND OR kms.state<>'ACTIVE' OR kms.pins IS DISTINCT FROM p->'kms'
   OR kms.producer_trust_digest IS DISTINCT FROM i->>'producerTrustDigest'
   OR kms.pins->>'environmentId' IS DISTINCT FROM o->>'environmentId'
   OR NOT kms.pins->'permissions' ? 'ENCRYPT'
   OR floor(extract(epoch from clock_timestamp())*1000) NOT BETWEEN (kms.pins->>'validFromMs')::numeric AND (kms.pins->>'validUntilMs')::numeric-1
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-KMS'; END IF;
  SELECT * INTO route FROM control.installed_notification_routing WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND profile_id=NEW.routing_profile_id;
  IF NOT FOUND OR route.state<>'ACTIVE' OR route.installation_digest IS DISTINCT FROM p->>'routingInstallationDigest'
   OR route.signed_profile_digest IS DISTINCT FROM i->'routing'->>'signedProfileDigest'
   OR route.revision::text IS DISTINCT FROM i->'routing'->>'revision'
   OR route.producer_trust_digest IS DISTINCT FROM i->>'producerTrustDigest'
   OR openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->'${policyField}'
      IS DISTINCT FROM jsonb_build_object('bytes',substring(kms.pins->>'policyDigest' from 8))
   OR route.installation->'trust'->>'environmentId' IS DISTINCT FROM o->>'environmentId'
   OR o->>'templateDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(route.installation->'template'),'UTF8')),'hex')
   OR o->>'recipientSetDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(route.installation->'recipientSet'),'UTF8')),'hex')
   OR o->>'redactionProfileDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(route.installation->'redaction'),'UTF8')),'hex')
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-ROUTING'; END IF;
 ELSE
  SELECT * INTO prep FROM control.notification_key_preparation WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND preparation_id=NEW.preparation_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-KEY-PREPARATION'; END IF;
  SELECT * INTO attempt FROM control.evidence_kms_attempt WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.preparation_id;
  IF NOT FOUND OR attempt.state<>'PROVED' OR attempt.installation_digest<>prep.kms_installation_digest
   OR attempt.request->'objectIntent' IS DISTINCT FROM prep.preparation->'objectIntent'
   OR NOT EXISTS(SELECT 1 FROM control.evidence_wrapped_key k WHERE k.participant_id=NEW.participant_id
    AND k.privacy_domain_id=NEW.privacy_domain_id AND k.attempt_id=NEW.preparation_id AND k.key_id=NEW.key_id)
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-ORIGINAL'; END IF;
  SELECT * INTO exchange FROM control.evidence_kms_exchange WHERE participant_id=NEW.participant_id
   AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.preparation_id AND exchange_id=NEW.encryption_exchange_id;
  IF NOT FOUND OR exchange.kind<>'UNWRAP'
   OR convert_from(exchange.request_bytes,'UTF8')::jsonb->>'keyUse'<>'ENCRYPT'
   OR convert_from(exchange.request_bytes,'UTF8')::jsonb->>'keyId'<>NEW.key_id
   OR NOT ((exchange.state='PROVED' AND openpc.evidence_kms_stored_outcome(exchange.receipt_bytes)='1') OR
    EXISTS(SELECT 1 FROM control.evidence_kms_exchange r WHERE r.participant_id=NEW.participant_id
     AND r.privacy_domain_id=NEW.privacy_domain_id AND r.attempt_id=NEW.preparation_id AND r.kind='READ_ATTEMPT'
     AND r.state='PROVED' AND openpc.evidence_kms_stored_outcome(r.receipt_bytes)='1'
     AND convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=exchange.exchange_id::text
     AND convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=exchange.request_digest))
  THEN RAISE EXCEPTION 'NOTIFICATION-KEY-UNKNOWN'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_key_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-KEY-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_key_preparation_guard ON control.notification_key_preparation;
CREATE TRIGGER notification_key_preparation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_key_preparation FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_key_custody();
DROP TRIGGER IF EXISTS notification_key_ciphertext_guard ON control.notification_key_ciphertext;
CREATE TRIGGER notification_key_ciphertext_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_key_ciphertext FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_key_custody();
DROP TRIGGER IF EXISTS notification_key_preparation_truncate ON control.notification_key_preparation;
CREATE TRIGGER notification_key_preparation_truncate BEFORE TRUNCATE ON control.notification_key_preparation FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_key_truncate();
DROP TRIGGER IF EXISTS notification_key_ciphertext_truncate ON control.notification_key_ciphertext;
CREATE TRIGGER notification_key_ciphertext_truncate BEFORE TRUNCATE ON control.notification_key_ciphertext FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_key_truncate();
REVOKE ALL ON FUNCTION openpc.guard_notification_key_custody(),openpc.guard_notification_key_truncate() FROM PUBLIC;
`;
