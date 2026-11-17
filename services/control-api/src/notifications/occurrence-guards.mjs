import { notificationCoseProfiles as profiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const worker = profiles.NotificationWorkerProfileV1;
const occurrence = profiles.NotificationOccurrenceReceiptV1;
const delivery = profiles.NotificationDeliveryRequestedReceiptV1;
const key = (profile, name) => profile.fields.find((field) => field.name === name).key;
const c = (name) => `m->'${key(occurrence, name)}'`;
const pairBindings = [
  'environmentId',
  'participantId',
  'privacyDomainId',
  'notificationId',
  'notificationOccurrenceId',
  'payloadObjectId',
  'keyPreparationId',
  'sourceEventId',
  'sourceDataDigest',
  'sourceReceiptDigest',
  'routingProfileDigest',
  'custodyDigest',
  'endpointId',
  'endpointRevision',
  'templateDigest',
  'payloadDigest',
  'encryptedObjectDigest',
  'keyId',
]
  .map((name) => `OR m->'${key(occurrence, name)}' IS DISTINCT FROM o->'${key(occurrence, name)}'`)
  .join('\n ');
const bytes = (expression) => `jsonb_build_object('bytes',${expression})`;
function wire(field, root) {
  const text = `${root}->>'${field.name}'`;
  if (field.type === 'H32') return bytes(`substring(${text} from 8)`);
  if (field.type === 'uuidv7') return bytes(`replace(${text},'-','')`);
  if (field.type === 'P256_SPKI_DER') return bytes(text);
  if (field.type.startsWith('enum '))
    return `to_jsonb(CASE ${text} ${field.type
      .slice(5)
      .split(' ')
      .map((v) => {
        const [name, n] = v.split('=');
        return `WHEN '${name}' THEN ${n}`;
      })
      .join(' ')} ELSE NULL END)`;
  if (field.type === 'u64p' || field.type === 'safe_uint') return `to_jsonb((${text})::numeric)`;
  return `${root}->'${field.name}'`;
}
const workerMap = `jsonb_build_object('0',${bytes(`'${worker.definitionDigest.slice(7)}'`)},${worker.fields
  .slice(1)
  .map((f) => `'${f.key}',${wire(f, "p->'workerProfile'")}`)
  .join(',')})`;
const commonTypes = occurrence.fields
  .filter((f) => f.type === 'uuidv7' || f.type === 'H32')
  .map(
    (f) =>
      `OR (jsonb_typeof(m->'${f.key}')='object' AND (m->'${f.key}')-ARRAY['bytes']='{}'::jsonb AND m->'${f.key}'->>'bytes' ~ '${f.type === 'H32' ? '^[0-9a-f]{64}$' : '^[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$'}') IS DISTINCT FROM true`,
  )
  .join('\n ');
/** Canonical owns registration/migrations. These guards cover only immutable
 * preparation/observation; they do not bypass metadata or outbox admission. */
export const notificationOccurrenceGuardsSql = String.raw`
ALTER TABLE control.notification_occurrence_preparation FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_occurrence_observation FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification_occurrence_preparation,control.notification_occurrence_observation FROM PUBLIC,openpc_control_worker,openpc_control_reader,openpc_control_runtime;
GRANT SELECT,INSERT ON control.notification_occurrence_preparation,control.notification_occurrence_observation TO openpc_control_runtime;
GRANT UPDATE(state) ON control.notification_occurrence_preparation TO openpc_control_runtime;
CREATE OR REPLACE FUNCTION openpc.check_notification_occurrence_preparation(prep control.notification_occurrence_preparation)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=prep.preparation; m jsonb; w control.installed_notification_worker%ROWTYPE;
 k control.notification_key_preparation%ROWTYPE; cipher control.notification_key_ciphertext%ROWTYPE;
 source control.evidence_export_completion%ROWTYPE; event control.outbox_event%ROWTYPE;
 route control.installed_notification_routing%ROWTYPE; original control.notification_occurrence_observation%ROWTYPE;
 is_occurrence boolean:=prep.family='NotificationOccurrenceReceiptV1';
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR current_setting('row_security')<>'on'
 OR prep.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR prep.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR p-ARRAY['schema','preparationId','family','input','workerProfile','workerProfileDigest','workerAuthorityDigest','payloadHex'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(p))<>8
 OR jsonb_typeof(p->'input') IS DISTINCT FROM 'object'
 OR (p->'input')-ARRAY['worker','source','keyPreparationId'] IS DISTINCT FROM '{}'::jsonb
 OR (p->'input'->'worker')-ARRAY['participantId','privacyDomainId','installationDigest'] IS DISTINCT FROM '{}'::jsonb
 OR (p->'input'->'source')-ARRAY['scope','evidenceExportId','eventId'] IS DISTINCT FROM '{}'::jsonb
 OR (p->'input'->'source'->'scope')-ARRAY['participantId','privacyDomainId','streamId'] IS DISTINCT FROM '{}'::jsonb
 OR p->'input'->'source'->'scope'->>'participantId' IS DISTINCT FROM prep.participant_id::text
 OR p->'input'->'source'->'scope'->>'privacyDomainId' IS DISTINCT FROM prep.privacy_domain_id::text
 OR jsonb_typeof(p->'workerProfile') IS DISTINCT FROM 'object'
 OR (SELECT count(*) FROM jsonb_object_keys(p->'workerProfile'))<>${worker.fields.length - 1}
 OR (p->>'workerAuthorityDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
 OR p->>'schema' IS DISTINCT FROM 'pc.notification.occurrence-preparation.v1'
 OR p->>'preparationId' IS DISTINCT FROM prep.preparation_id::text OR p->>'family' IS DISTINCT FROM prep.family
 OR p->'input'->'worker'->>'participantId' IS DISTINCT FROM prep.participant_id::text
 OR p->'input'->'worker'->>'privacyDomainId' IS DISTINCT FROM prep.privacy_domain_id::text
 OR p->'input'->'worker'->>'installationDigest' IS DISTINCT FROM prep.worker_installation_digest
 OR p->'input'->>'keyPreparationId' IS DISTINCT FROM prep.key_preparation_id::text
 OR p->'input'->'source'->>'eventId' IS DISTINCT FROM prep.source_event_id::text
 OR prep.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8')
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PREPARATION'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=prep.participant_id
 AND privacy_domain_id=prep.privacy_domain_id AND installation_digest=prep.worker_installation_digest;
 IF w.state<>'ACTIVE' OR w.signed_profile_digest IS DISTINCT FROM p->>'workerProfileDigest'
 OR w.service_id IS DISTINCT FROM (CASE WHEN is_occurrence THEN 'LS-NOTIFICATION' ELSE 'LS-CONTROL-WORK' END)
 OR w.subscription_id IS DISTINCT FROM (CASE WHEN is_occurrence THEN 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1' ELSE 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1' END)
 OR openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex')) IS DISTINCT FROM ${workerMap}
 OR floor(extract(epoch from clock_timestamp())*1000)<(p->'workerProfile'->>'validFromMs')::numeric
 OR floor(extract(epoch from clock_timestamp())*1000)>=(p->'workerProfile'->>'validUntilMs')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-WORKER'; END IF;
 m:=openpc.business_cbor(decode(p->>'payloadHex','hex'));
 IF jsonb_typeof(m) IS DISTINCT FROM 'object'
 OR (SELECT count(*) FROM jsonb_object_keys(m))<>(CASE WHEN is_occurrence THEN ${occurrence.fields.length} ELSE ${delivery.fields.length} END)
 OR NOT m ?& ARRAY[${occurrence.fields.map((f) => `'${f.key}'`).join(',')}]
 OR m->'0' IS DISTINCT FROM ${bytes(`CASE WHEN is_occurrence THEN '${occurrence.definitionDigest.slice(7)}' ELSE '${delivery.definitionDigest.slice(7)}' END`)}
 ${commonTypes}
 OR jsonb_typeof(m->'23') IS DISTINCT FROM 'number' OR (m->>'23')::numeric<0 OR (m->>'23')::numeric>9007199254740991
 OR trunc((m->>'23')::numeric) IS DISTINCT FROM (m->>'23')::numeric
 OR jsonb_typeof(m->'18') IS DISTINCT FROM 'number' OR (m->>'18')::numeric<1 OR (m->>'18')::numeric>18446744073709551615
 OR ${c('participantId')} IS DISTINCT FROM openpc.business_uuid(prep.participant_id)
 OR ${c('privacyDomainId')} IS DISTINCT FROM openpc.business_uuid(prep.privacy_domain_id)
 OR ${c('sourceEventId')} IS DISTINCT FROM openpc.business_uuid(prep.source_event_id)
 OR ${c('keyPreparationId')} IS DISTINCT FROM openpc.business_uuid(prep.key_preparation_id)
 OR ${c('environmentId')} IS DISTINCT FROM p->'workerProfile'->'environmentId'
 OR ${c('workerProfileDigest')} IS DISTINCT FROM ${bytes("substring(p->>'workerProfileDigest' from 8)")}
 OR ${c('authoritySnapshotDigest')} IS DISTINCT FROM ${bytes("substring(p->>'workerAuthorityDigest' from 8)")}
 OR ${c('routingProfileDigest')} IS DISTINCT FROM ${bytes('substring(w.routing_profile_digest from 8)')}
 OR ${c('signerKeyId')} IS DISTINCT FROM ${bytes("encode(sha256(decode(p->'workerProfile'->>'receiptSignerSpki','hex')),'hex')")}
 OR (m->>'${key(occurrence, 'recordedAtMs')}')::numeric NOT BETWEEN (p->'workerProfile'->>'validFromMs')::numeric AND (p->'workerProfile'->>'validUntilMs')::numeric-1
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-CLAIMS'; END IF;
 SELECT * INTO STRICT k FROM control.notification_key_preparation WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND preparation_id=prep.key_preparation_id;
 SELECT * INTO STRICT cipher FROM control.notification_key_ciphertext WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND preparation_id=prep.key_preparation_id;
 SELECT * INTO STRICT source FROM control.evidence_export_completion WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND event_id=prep.source_event_id;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND event_id=prep.source_event_id;
 PERFORM openpc.check_evidence_export_completion_event(event);
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND profile_id=k.routing_profile_id;
 IF source.state<>'PUBLISHED' OR source.stream_id IS DISTINCT FROM p->'input'->'source'->'scope'->>'streamId'
 OR source.evidence_export_id::text IS DISTINCT FROM p->'input'->'source'->>'evidenceExportId'
 OR source.trust_digest IS DISTINCT FROM p->'workerProfile'->>'producerTrustDigest'
 OR k.source_event_id<>prep.source_event_id OR k.kms_installation_digest IS DISTINCT FROM p->'workerProfile'->>'kmsInstallationDigest'
 OR route.state<>'ACTIVE' OR route.installation_digest IS DISTINCT FROM k.preparation->>'routingInstallationDigest'
 OR route.signed_profile_digest IS DISTINCT FROM w.routing_profile_digest
 OR ${c('notificationOccurrenceId')} IS DISTINCT FROM openpc.business_uuid(k.occurrence_id)
 OR ${c('payloadObjectId')} IS DISTINCT FROM openpc.business_uuid(k.payload_object_id)
 OR ${c('sourceDataDigest')} IS DISTINCT FROM ${bytes("substring(source.claims->>'dataDigest' from 8)")}
 OR ${c('sourceReceiptDigest')} IS DISTINCT FROM ${bytes('substring(source.receipt_payload_digest from 8)')}
 OR ${c('endpointId')} IS DISTINCT FROM openpc.business_uuid(route.endpoint_id)
 OR ${c('endpointRevision')} IS DISTINCT FROM openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->'${key(profiles.NotificationRoutingProfileV1, 'endpointRevision')}'
 OR ${c('templateDigest')} IS DISTINCT FROM ${bytes("substring(k.preparation->'objectIntent'->>'templateDigest' from 8)")}
 OR ${c('payloadDigest')} IS DISTINCT FROM ${bytes("substring(k.preparation->'objectIntent'->>'payloadDigest' from 8)")}
 OR ${c('encryptedObjectDigest')} IS DISTINCT FROM ${bytes('substring(cipher.encrypted_object_digest from 8)')}
 OR ${c('keyId')} IS DISTINCT FROM ${bytes('substring(cipher.key_id from 8)')}
 OR ${c('custodyDigest')} IS DISTINCT FROM ${bytes("encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object('preparationDigest',k.preparation_digest,'keyId',cipher.key_id,'encryptionExchangeId',cipher.encryption_exchange_id::text,'encryptedObjectDigest',cipher.encrypted_object_digest,'encryptionContextDigest',cipher.encryption_context_digest)),'UTF8')),'hex')")}
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-CUSTODY'; END IF;
 IF NOT is_occurrence THEN
  SELECT o.* INTO STRICT original FROM control.notification_occurrence_preparation op
  JOIN control.notification_occurrence_observation o USING(participant_id,privacy_domain_id,preparation_id)
  WHERE op.participant_id=prep.participant_id AND op.privacy_domain_id=prep.privacy_domain_id
  AND op.key_preparation_id=prep.key_preparation_id AND op.family='NotificationOccurrenceReceiptV1' AND op.state='OBSERVED';
  IF (jsonb_typeof(m->'26')='object' AND (m->'26')-ARRAY['bytes']='{}'::jsonb AND m->'26'->>'bytes' ~ '^[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$') IS DISTINCT FROM true
  OR (jsonb_typeof(m->'29')='object' AND (m->'29')-ARRAY['bytes']='{}'::jsonb AND m->'29'->>'bytes' ~ '^[0-9a-f]{64}$') IS DISTINCT FROM true
  OR NOT m ?& ARRAY['25','26','27','28','29'] OR m->'25' IS DISTINCT FROM ${bytes("encode(sha256(original.receipt_payload),'hex')")}
  OR m->'27' IS DISTINCT FROM ${bytes("replace(p->'workerProfile'->>'sourceId','-','')")} OR m->'28' IS DISTINCT FROM '1'::jsonb
  OR ${c('notificationId')} IS DISTINCT FROM openpc.business_cbor(original.receipt_payload)->'${key(occurrence, 'notificationId')}'
  OR ${c('operationId')} IS NOT DISTINCT FROM openpc.business_cbor(original.receipt_payload)->'${key(occurrence, 'operationId')}'
  OR ${c('receiptId')} IS NOT DISTINCT FROM openpc.business_cbor(original.receipt_payload)->'${key(occurrence, 'receiptId')}'
  OR (m->>'${key(occurrence, 'recordedAtMs')}')::numeric<(openpc.business_cbor(original.receipt_payload)->>'${key(occurrence, 'recordedAtMs')}')::numeric
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-ORIGINAL'; END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_occurrence_signing()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prep control.notification_occurrence_preparation%ROWTYPE; m jsonb; profile_schema integer; profile_purpose integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-IMMUTABLE'; END IF;
 IF TG_TABLE_NAME='notification_occurrence_preparation' THEN
  prep:=NEW;
  IF TG_OP='INSERT' AND NEW.state<>'PREPARED' THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-STATE'; END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
   OR NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED') OR (OLD.state='DISPATCHED' AND NEW.state IN ('UNKNOWN','OBSERVED')) OR (OLD.state='UNKNOWN' AND NEW.state='OBSERVED')))
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-STATE'; END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-IMMUTABLE'; END IF;
  SELECT * INTO STRICT prep FROM control.notification_occurrence_preparation WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND preparation_id=NEW.preparation_id;
  IF prep.state NOT IN ('DISPATCHED','UNKNOWN') OR NEW.receipt_payload IS DISTINCT FROM decode(prep.preparation->>'payloadHex','hex')
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-OBSERVATION'; END IF;
  m:=openpc.business_cbor(NEW.receipt_payload);
  IF m->'5' IS DISTINCT FROM openpc.business_uuid(NEW.operation_id) OR m->'4' IS DISTINCT FROM openpc.business_uuid(NEW.receipt_id) THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-OBSERVATION'; END IF;
  profile_schema:=CASE WHEN prep.family='NotificationOccurrenceReceiptV1' THEN ${occurrence.schemaId} ELSE ${delivery.schemaId} END;
  profile_purpose:=CASE WHEN prep.family='NotificationOccurrenceReceiptV1' THEN ${occurrence.purposeCode} ELSE ${delivery.purposeCode} END;
  PERFORM openpc.archive_cose_binding(NEW.receipt_payload,NEW.cose_sign1,'sha256:'||(m->'${key(occurrence, 'signerKeyId')}'->>'bytes'),profile_schema,profile_purpose);
 END IF;
 PERFORM openpc.check_notification_occurrence_preparation(prep);
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_occurrence_observation_pair()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prep control.notification_occurrence_preparation%ROWTYPE; observation control.notification_occurrence_observation%ROWTYPE;
BEGIN
 SELECT * INTO STRICT prep FROM control.notification_occurrence_preparation WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND preparation_id=NEW.preparation_id;
 SELECT * INTO STRICT observation FROM control.notification_occurrence_observation WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND preparation_id=NEW.preparation_id;
 IF prep.state<>'OBSERVED' OR observation.receipt_payload IS DISTINCT FROM decode(prep.preparation->>'payloadHex','hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PAIR'; END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_occurrence_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-IMMUTABLE'; END $$;
${['notification_occurrence_preparation', 'notification_occurrence_observation']
  .map(
    (table) => `
DROP TRIGGER IF EXISTS ${table}_guard ON control.${table};
CREATE TRIGGER ${table}_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_occurrence_signing();
DROP TRIGGER IF EXISTS ${table}_truncate ON control.${table};
CREATE TRIGGER ${table}_truncate BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_occurrence_truncate();`,
  )
  .join('\n')}
DROP TRIGGER IF EXISTS notification_occurrence_observation_pair ON control.notification_occurrence_observation;
CREATE CONSTRAINT TRIGGER notification_occurrence_observation_pair AFTER INSERT ON control.notification_occurrence_observation DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_notification_occurrence_observation_pair();
DROP TRIGGER IF EXISTS notification_occurrence_preparation_pair ON control.notification_occurrence_preparation;
CREATE CONSTRAINT TRIGGER notification_occurrence_preparation_pair AFTER UPDATE ON control.notification_occurrence_preparation DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.state='OBSERVED') EXECUTE FUNCTION openpc.check_notification_occurrence_observation_pair();
REVOKE ALL ON FUNCTION openpc.check_notification_occurrence_preparation(control.notification_occurrence_preparation),openpc.guard_notification_occurrence_signing(),openpc.check_notification_occurrence_observation_pair(),openpc.guard_notification_occurrence_truncate() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_notification_occurrence_preparation(control.notification_occurrence_preparation) TO openpc_control_runtime;
`;

/** Canonical outbox dispatch must explicitly register this exact family, keeping
 * all older proof families intact. The retained-proof checker uses scoped runtime
 * access and is safe after the worker owner restores its action at commit; effect
 * INSERT guards enforce the export action before each write. No validation call
 * grants current worker/key authority or performs a write. */
export const notificationOccurrencePublicationGuardsSql = String.raw`
-- Immutable receipt-family resolver. Used before metadata creation and again
-- unconditionally for its deferred effect; request action cannot choose a proof.
CREATE OR REPLACE FUNCTION openpc.notification_occurrence_metadata_preparation(item control.notification)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE op control.notification_occurrence_preparation%ROWTYPE; dp control.notification_occurrence_preparation%ROWTYPE;
 original control.notification_occurrence_observation%ROWTYPE; proof control.notification_occurrence_observation%ROWTYPE;
 source control.evidence_export_completion%ROWTYPE; m jsonb; o jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR item.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT p.* INTO STRICT op FROM control.notification_occurrence_preparation p
 JOIN control.notification_occurrence_observation r USING(participant_id,privacy_domain_id,preparation_id)
 WHERE p.participant_id=item.participant_id AND p.privacy_domain_id=item.privacy_domain_id
 AND p.family='NotificationOccurrenceReceiptV1' AND p.state='OBSERVED'
 AND openpc.business_cbor(r.receipt_payload)->'6'=openpc.business_uuid(item.notification_id);
 SELECT * INTO STRICT original FROM control.notification_occurrence_observation
 WHERE participant_id=op.participant_id AND privacy_domain_id=op.privacy_domain_id AND preparation_id=op.preparation_id;
 SELECT * INTO STRICT dp FROM control.notification_occurrence_preparation
 WHERE participant_id=op.participant_id AND privacy_domain_id=op.privacy_domain_id
 AND key_preparation_id=op.key_preparation_id AND family='NotificationDeliveryRequestedReceiptV1' AND state='OBSERVED';
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation
 WHERE participant_id=dp.participant_id AND privacy_domain_id=dp.privacy_domain_id AND preparation_id=dp.preparation_id;
 m:=openpc.business_cbor(proof.receipt_payload);o:=openpc.business_cbor(original.receipt_payload);
 PERFORM openpc.archive_cose_binding(proof.receipt_payload,proof.cose_sign1,'sha256:'||(m->'24'->>'bytes'),${delivery.schemaId},${delivery.purposeCode});
 PERFORM openpc.archive_cose_binding(original.receipt_payload,original.cose_sign1,'sha256:'||(o->'24'->>'bytes'),${occurrence.schemaId},${occurrence.purposeCode});
 IF original.receipt_payload IS DISTINCT FROM decode(op.preparation->>'payloadHex','hex')
 OR proof.receipt_payload IS DISTINCT FROM decode(dp.preparation->>'payloadHex','hex')
 OR original.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(original.receipt_payload),'hex')
 OR m->'25' IS DISTINCT FROM ${bytes("encode(sha256(original.receipt_payload),'hex')")}
 ${pairBindings}
 OR m->'4' IS NOT DISTINCT FROM o->'4' OR m->'5' IS NOT DISTINCT FROM o->'5'
 OR (m->>'23')::numeric<(o->>'23')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-METADATA-PAIR'; END IF;
 SELECT * INTO STRICT source FROM control.evidence_export_completion
 WHERE participant_id=op.participant_id AND privacy_domain_id=op.privacy_domain_id AND event_id=op.source_event_id;
 IF item.severity IS DISTINCT FROM 'INFO' OR item.state IS DISTINCT FROM 'UNREAD' OR item.revision IS DISTINCT FROM 1::numeric
 OR item.message_key IS DISTINCT FROM 'evidence.export.completed'
 OR item.resource_ref IS DISTINCT FROM 'urn:openpc:resource:'||source.evidence_export_id::text
 OR item.candidate_digest IS DISTINCT FROM original.receipt_digest
 OR source.state IS DISTINCT FROM 'PUBLISHED'
 OR source.receipt_payload_digest IS DISTINCT FROM 'sha256:'||(o->'12'->>'bytes')
 OR o->'10' IS DISTINCT FROM openpc.business_uuid(source.event_id)
 OR o->'2' IS DISTINCT FROM openpc.business_uuid(item.participant_id)
 OR o->'3' IS DISTINCT FROM openpc.business_uuid(item.privacy_domain_id)
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-METADATA'; END IF;
 RETURN dp.preparation_id;
END $$;
CREATE OR REPLACE FUNCTION openpc.admit_notification_occurrence_metadata(item control.notification)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE bound_preparation_id uuid; dp control.notification_occurrence_preparation%ROWTYPE; op control.notification_occurrence_preparation%ROWTYPE;
BEGIN
 IF openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 bound_preparation_id:=openpc.notification_occurrence_metadata_preparation(item);
 SELECT p.* INTO STRICT dp FROM control.notification_occurrence_preparation p
 WHERE p.participant_id=item.participant_id AND p.privacy_domain_id=item.privacy_domain_id AND p.preparation_id=bound_preparation_id;
 SELECT p.* INTO STRICT op FROM control.notification_occurrence_preparation p
 WHERE p.participant_id=dp.participant_id AND p.privacy_domain_id=dp.privacy_domain_id AND p.key_preparation_id=dp.key_preparation_id AND p.family='NotificationOccurrenceReceiptV1';
 -- Fresh preparation checks bind ACTIVE installed profiles, roles, genuine source,
 -- route, original key/ciphertext/AAD digests and both immutable signed inputs.
 -- Actual peer and current key STATUS admission is held by the application owner
 -- on this same client; this SQL function grants no transferable capability.
 PERFORM openpc.check_notification_occurrence_preparation(op);
 PERFORM openpc.check_notification_occurrence_preparation(dp);
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_occurrence_metadata_effect(item control.notification)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE bound_preparation_id uuid; proof control.notification_occurrence_observation%ROWTYPE; event control.outbox_event%ROWTYPE;
BEGIN
 bound_preparation_id:=openpc.notification_occurrence_metadata_preparation(item);
 SELECT r.* INTO STRICT proof FROM control.notification_occurrence_observation r
 WHERE r.participant_id=item.participant_id AND r.privacy_domain_id=item.privacy_domain_id AND r.preparation_id=bound_preparation_id;
 SELECT e.* INTO STRICT event FROM control.outbox_event e WHERE e.participant_id=item.participant_id
 AND e.privacy_domain_id=item.privacy_domain_id AND e.event_id=(openpc.business_cbor(proof.receipt_payload)->'26'->>'bytes')::uuid;
 PERFORM openpc.check_notification_delivery_requested_event(event);
END $$;
REVOKE ALL ON FUNCTION openpc.notification_occurrence_metadata_preparation(control.notification),openpc.admit_notification_occurrence_metadata(control.notification),openpc.check_notification_occurrence_metadata_effect(control.notification) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.notification_occurrence_metadata_preparation(control.notification),openpc.admit_notification_occurrence_metadata(control.notification),openpc.check_notification_occurrence_metadata_effect(control.notification) TO openpc_control_runtime;

CREATE UNIQUE INDEX IF NOT EXISTS notification_delivery_request_occurrence_uq
 ON control.outbox_event(participant_id,privacy_domain_id,aggregate_id)
 WHERE proof_kind='NOTIFICATION_DELIVERY_REQUEST_REFERENCE';
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_requested_event(event control.outbox_event)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE prep control.notification_occurrence_preparation%ROWTYPE;
 proof control.notification_occurrence_observation%ROWTYPE;
 original control.notification_occurrence_observation%ROWTYPE;
 occurrence control.notification_occurrence%ROWTYPE; metadata control.notification%ROWTYPE;
 payload control.notification_payload_object%ROWTYPE;
 reference control.notification_payload%ROWTYPE;
 source control.evidence_export_completion%ROWTYPE;
 key_prep control.notification_key_preparation%ROWTYPE; cipher control.notification_key_ciphertext%ROWTYPE; route control.installed_notification_routing%ROWTYPE;
 m jsonb; o jsonb; occurrence_id uuid; payload_id uuid; source_id uuid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR event.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR event.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()

 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT p.* INTO STRICT prep FROM control.notification_occurrence_preparation p
 JOIN control.notification_occurrence_observation r USING(participant_id,privacy_domain_id,preparation_id)
 WHERE p.participant_id=event.participant_id AND p.privacy_domain_id=event.privacy_domain_id
 AND p.family='NotificationDeliveryRequestedReceiptV1' AND p.state='OBSERVED'
 AND openpc.business_cbor(r.receipt_payload)->'26'=openpc.business_uuid(event.event_id);
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation
 WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND preparation_id=prep.preparation_id;
 SELECT r.* INTO STRICT original FROM control.notification_occurrence_preparation p
 JOIN control.notification_occurrence_observation r USING(participant_id,privacy_domain_id,preparation_id)
 WHERE p.participant_id=prep.participant_id AND p.privacy_domain_id=prep.privacy_domain_id
 AND p.key_preparation_id=prep.key_preparation_id AND p.family='NotificationOccurrenceReceiptV1' AND p.state='OBSERVED';
 m:=openpc.business_cbor(proof.receipt_payload);o:=openpc.business_cbor(original.receipt_payload);
 PERFORM openpc.archive_cose_binding(proof.receipt_payload,proof.cose_sign1,'sha256:'||(m->'24'->>'bytes'),${delivery.schemaId},${delivery.purposeCode});
 PERFORM openpc.archive_cose_binding(original.receipt_payload,original.cose_sign1,'sha256:'||(o->'24'->>'bytes'),${occurrence.schemaId},${occurrence.purposeCode});
 IF m->'25' IS DISTINCT FROM ${bytes("encode(sha256(original.receipt_payload),'hex')")}
 ${pairBindings}
 OR m->'4' IS NOT DISTINCT FROM o->'4' OR m->'5' IS NOT DISTINCT FROM o->'5'
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PUBLICATION-PAIR'; END IF;
 occurrence_id:=(m->'7'->>'bytes')::uuid;payload_id:=(m->'8'->>'bytes')::uuid;source_id:=(m->'10'->>'bytes')::uuid;
 SELECT * INTO STRICT occurrence FROM control.notification_occurrence WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND notification_occurrence_id=occurrence_id;
 SELECT * INTO STRICT metadata FROM control.notification WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND notification_id=occurrence.notification_id;
 SELECT * INTO STRICT payload FROM control.notification_payload_object WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND payload_object_id=payload_id;
 SELECT * INTO STRICT reference FROM control.notification_payload WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND payload_object_id=payload_id;
 SELECT * INTO STRICT source FROM control.evidence_export_completion WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND event_id=source_id;
 SELECT * INTO STRICT key_prep FROM control.notification_key_preparation WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND preparation_id=prep.key_preparation_id;
 SELECT * INTO STRICT cipher FROM control.notification_key_ciphertext WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND preparation_id=prep.key_preparation_id;
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=prep.participant_id AND privacy_domain_id=prep.privacy_domain_id AND profile_id=key_prep.routing_profile_id;
 IF metadata.severity IS DISTINCT FROM 'INFO' OR metadata.message_key IS DISTINCT FROM 'evidence.export.completed'
 OR metadata.resource_ref IS DISTINCT FROM 'urn:openpc:resource:'||source.evidence_export_id::text
 OR metadata.candidate_digest IS DISTINCT FROM 'sha256:'||encode(sha256(original.receipt_payload),'hex')
 OR occurrence.notification_id IS DISTINCT FROM (m->'6'->>'bytes')::uuid
 OR occurrence.payload_object_id IS DISTINCT FROM payload_id
 OR occurrence.endpoint_id IS DISTINCT FROM (m->'17'->>'bytes')::uuid
 OR occurrence.endpoint_revision IS DISTINCT FROM (m->>'18')::numeric
 OR occurrence.source_event_id IS DISTINCT FROM source_id
 OR occurrence.source_data_digest IS DISTINCT FROM 'sha256:'||(m->'11'->>'bytes')
 OR occurrence.creation_operation_id IS DISTINCT FROM original.operation_id
 OR occurrence.subscription_id<>'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
 OR occurrence.template_digest IS DISTINCT FROM 'sha256:'||(m->'19'->>'bytes')
 OR occurrence.payload_digest IS DISTINCT FROM 'sha256:'||(m->'20'->>'bytes')
 OR payload.template_digest IS DISTINCT FROM occurrence.template_digest
 OR payload.payload_digest IS DISTINCT FROM occurrence.payload_digest
 OR payload.encrypted_object_digest IS DISTINCT FROM 'sha256:'||(m->'21'->>'bytes')
 OR payload.key_id IS DISTINCT FROM 'sha256:'||(m->'22'->>'bytes')
 OR payload.object_version<>1 OR payload.key_id IS DISTINCT FROM cipher.key_id
 OR payload.encrypted_object_digest IS DISTINCT FROM cipher.encrypted_object_digest
 OR payload.encryption_context_digest IS DISTINCT FROM cipher.encryption_context_digest
 OR payload.encryption_profile_digest IS DISTINCT FROM 'sha256:'||(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->'${key(profiles.NotificationRoutingProfileV1, 'encryptionProfileDigest')}'->>'bytes')
 OR payload.creation_operation_id IS DISTINCT FROM original.operation_id
 OR reference.encrypted_object_digest IS DISTINCT FROM payload.encrypted_object_digest
 OR reference.key_preparation_id IS DISTINCT FROM prep.key_preparation_id
 OR source.state<>'PUBLISHED' OR source.receipt_payload_digest IS DISTINCT FROM 'sha256:'||(m->'12'->>'bytes')
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PUBLICATION-EFFECT'; END IF;
 IF event.proof_kind<>'NOTIFICATION_DELIVERY_REQUEST_REFERENCE'
 OR event.sequence_namespace<>'NOTIFICATION_DELIVERY_REQUESTED_V1'
 OR event.aggregate_type<>'notification-occurrence' OR event.aggregate_id IS DISTINCT FROM occurrence_id
 OR event.aggregate_sequence IS NOT NULL OR event.business_sequence IS DISTINCT FROM 1::numeric
 OR event.receipt_id IS NOT NULL OR event.cose_sign1 IS NOT NULL OR event.authority_generation IS NOT NULL
 OR event.webauthn_assertion_binding_digest IS NOT NULL
 OR event.event_type<>'io.openpc.notification.delivery.requested.v1'
 OR event.data_schema_uri IS DISTINCT FROM 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/NotificationDeliveryRequested'
 OR event.source IS DISTINCT FROM 'urn:openpc:service:'||(m->'27'->>'bytes')::uuid::text
 OR event.subject IS DISTINCT FROM 'urn:openpc:notification-occurrence:'||occurrence_id::text
 OR event.correlation_id IS DISTINCT FROM proof.operation_id OR event.causation_id IS DISTINCT FROM source_id
 OR floor(extract(epoch from event.occurred_at)*1000) IS DISTINCT FROM (m->>'23')::numeric
 OR event.payload_digest IS DISTINCT FROM sha256(event.payload_cbor)
 OR m->'29' IS DISTINCT FROM ${bytes("encode(sha256(event.payload_cbor),'hex')")}
 OR openpc.business_cbor(event.payload_cbor) IS DISTINCT FROM jsonb_build_object('0','urn:openpc:notification-occurrence:'||occurrence_id::text,'1','urn:openpc:resource:'||occurrence.endpoint_id::text,'2',m->'19','3',m->'20')
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PUBLICATION-OUTBOX'; END IF;
 IF (SELECT count(*) FROM control.notification_source_inbox i
 JOIN control.notification_source_cursor cur USING(participant_id,privacy_domain_id,subscription_id,source,partition)
 WHERE i.participant_id=prep.participant_id AND i.privacy_domain_id=prep.privacy_domain_id AND i.event_id=source_id
 AND i.subscription_id IN ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
 AND i.state='ADMITTED' AND i.source_sequence=1 AND cur.last_sequence=1 AND cur.last_event_id=i.event_id
 AND cur.last_data_digest=i.data_digest AND i.data_digest='sha256:'||(m->'11'->>'bytes')
 AND i.source='urn:openpc:service:'||(source.claims->>'sourceId')
 AND i.partition='urn:openpc:resource:'||source.evidence_export_id::text
 AND i.envelope=source.event_payload AND i.envelope_digest=source.event_payload_digest
 AND i.admission_operation_id=CASE WHEN i.subscription_id='SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1' THEN original.operation_id ELSE proof.operation_id END) <> 2
 THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-PUBLICATION-CURSOR'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_occurrence_effect()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE completion boolean:=false;
BEGIN
 -- Completion uses a distinct signed owner. Route both OLD and NEW so changing
 -- subscription cannot escape its immutable identity or fall into legacy code.
 IF TG_TABLE_NAME IN ('notification_source_inbox','notification_source_cursor') THEN
  IF TG_OP='DELETE' THEN
   completion:=OLD.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
  ELSE
   completion:=NEW.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
   IF TG_OP='UPDATE' THEN completion:=completion OR OLD.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'; END IF;
  END IF;
  IF completion THEN
   IF TG_OP='DELETE' THEN RAISE EXCEPTION 'COMPLETION-SHARED-EFFECT-IMMUTABLE'; END IF;
   IF TG_TABLE_NAME='notification_source_inbox' THEN
    IF TG_OP='UPDATE' THEN PERFORM openpc.check_notification_completion_inbox_effect(NEW,OLD);
    ELSE PERFORM openpc.check_notification_completion_inbox_effect(NEW,NULL); END IF;
   ELSE
    IF TG_OP='UPDATE' THEN PERFORM openpc.check_notification_completion_cursor_effect(NEW,OLD);
    ELSE PERFORM openpc.check_notification_completion_cursor_effect(NEW,NULL); END IF;
   END IF;
   RETURN NEW;
  END IF;
 END IF;
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_TABLE_NAME='notification_source_inbox' THEN
  IF NEW.state<>'ADMITTED' OR NEW.source_sequence<>1 OR NEW.safe_problem_code IS NOT NULL
   OR NEW.subscription_id NOT IN ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-INBOX'; END IF;
 ELSIF TG_TABLE_NAME='notification_source_cursor' THEN
  IF NEW.last_sequence<>1 OR NEW.revision<>1
   OR NEW.subscription_id NOT IN ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-CURSOR'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_occurrence_effect_pair()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE signing_operation uuid; key_preparation uuid; event control.outbox_event%ROWTYPE; request_payload bytea; bound_claims jsonb;
BEGIN
 IF TG_TABLE_NAME IN ('notification_source_inbox','notification_source_cursor') THEN
  IF NEW.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' THEN
   IF TG_TABLE_NAME='notification_source_inbox' THEN
    PERFORM openpc.check_notification_completion_disposition_original(NEW.event_id);
   ELSE
    PERFORM openpc.check_notification_completion_disposition_original(NEW.last_event_id);
   END IF;
   RETURN NULL;
  END IF;
 END IF;
 IF TG_TABLE_NAME IN ('notification_payload_object','notification_occurrence') THEN
  signing_operation:=NEW.creation_operation_id;
 ELSIF TG_TABLE_NAME='notification_payload' THEN
  key_preparation:=NEW.key_preparation_id;
 ELSIF TG_TABLE_NAME='notification_source_inbox' THEN
  signing_operation:=NEW.admission_operation_id;
 ELSIF TG_TABLE_NAME='notification_source_cursor' THEN
  SELECT admission_operation_id INTO STRICT signing_operation FROM control.notification_source_inbox
  WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
  AND subscription_id=NEW.subscription_id AND event_id=NEW.last_event_id
  AND source=NEW.source AND partition=NEW.partition AND source_sequence=NEW.last_sequence AND data_digest=NEW.last_data_digest;
 ELSE RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-EFFECT'; END IF;
 IF key_preparation IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM control.notification_key_preparation k WHERE k.participant_id=NEW.participant_id
   AND k.privacy_domain_id=NEW.privacy_domain_id AND k.preparation_id=key_preparation AND k.payload_object_id=NEW.payload_object_id)
  THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-EFFECT-IDENTITY'; END IF;
 END IF;
 IF key_preparation IS NULL THEN
  SELECT openpc.business_cbor(o.receipt_payload) INTO STRICT bound_claims FROM control.notification_occurrence_observation o
  WHERE o.participant_id=NEW.participant_id AND o.privacy_domain_id=NEW.privacy_domain_id AND o.operation_id=signing_operation;
  IF TG_TABLE_NAME='notification_payload_object' THEN
   IF bound_claims->'8' IS DISTINCT FROM openpc.business_uuid(NEW.payload_object_id) THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-EFFECT-IDENTITY'; END IF;
  ELSIF TG_TABLE_NAME='notification_occurrence' THEN
   IF bound_claims->'7' IS DISTINCT FROM openpc.business_uuid(NEW.notification_occurrence_id) THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-EFFECT-IDENTITY'; END IF;
  ELSIF TG_TABLE_NAME='notification_source_inbox' THEN
   IF bound_claims->'10' IS DISTINCT FROM openpc.business_uuid(NEW.event_id) THEN RAISE EXCEPTION 'NOTIFICATION-OCCURRENCE-EFFECT-IDENTITY'; END IF;
  END IF;
  SELECT p.key_preparation_id INTO STRICT key_preparation FROM control.notification_occurrence_preparation p
  JOIN control.notification_occurrence_observation o USING(participant_id,privacy_domain_id,preparation_id)
  WHERE p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id AND o.operation_id=signing_operation;
 END IF;
 SELECT o.receipt_payload INTO STRICT request_payload FROM control.notification_occurrence_preparation p
 JOIN control.notification_occurrence_observation o USING(participant_id,privacy_domain_id,preparation_id)
 WHERE p.participant_id=NEW.participant_id AND p.privacy_domain_id=NEW.privacy_domain_id
 AND p.key_preparation_id=key_preparation AND p.family='NotificationDeliveryRequestedReceiptV1' AND p.state='OBSERVED';
 SELECT * INTO STRICT event FROM control.outbox_event
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
 AND event_id=(openpc.business_cbor(request_payload)->'26'->>'bytes')::uuid;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 RETURN NULL;
END $$;
${[
  'notification_payload_object',
  'notification_payload',
  'notification_source_inbox',
  'notification_occurrence',
  'notification_source_cursor',
]
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.${table} TO openpc_control_runtime;
DROP TRIGGER IF EXISTS ${table}_effect_guard ON control.${table};
CREATE TRIGGER ${table}_effect_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_occurrence_effect();
DROP TRIGGER IF EXISTS ${table}_effect_pair ON control.${table};
CREATE CONSTRAINT TRIGGER ${table}_effect_pair AFTER INSERT${['notification_source_inbox', 'notification_source_cursor'].includes(table) ? ' OR UPDATE' : ''} ON control.${table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.check_notification_occurrence_effect_pair();
DROP TRIGGER IF EXISTS ${table}_truncate_guard ON control.${table};
CREATE TRIGGER ${table}_truncate_guard BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_occurrence_truncate();`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION openpc.guard_notification_occurrence_effect(),openpc.check_notification_occurrence_effect_pair() FROM PUBLIC;
REVOKE ALL ON FUNCTION openpc.check_notification_delivery_requested_event(control.outbox_event) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.check_notification_delivery_requested_event(control.outbox_event) TO openpc_control_runtime;
`;
