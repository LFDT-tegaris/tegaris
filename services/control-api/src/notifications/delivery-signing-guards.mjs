import { notificationCoseProfiles as profiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const started = profiles.NotificationDeliveryStartedReceiptV1,
  source = profiles.NotificationDeliveryRequestedReceiptV1,
  worker = profiles.NotificationWorkerProfileV1,
  channel = profiles.NotificationChannelProfileV1,
  route = profiles.NotificationRoutingProfileV1;
const key = (p, name) => {
  const f = p.fields.find((f) => f.name === name);
  if (!f) throw new Error('Missing notification native field');
  return f.key;
};
const h = (x) =>
  `'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${x}),'UTF8')),'hex')`;
const bytes = (x) => `jsonb_build_object('bytes',substring(${x} from 8))`;
const uuid = (x) => `openpc.business_uuid((${x})::uuid)`;
const claims = (p, m) =>
  `jsonb_build_object(${p.fields
    .filter((f) => f.name !== 'schemaDefinitionDigest')
    .flatMap((f) => [
      `'${f.name}'`,
      f.type === 'uuidv7'
        ? `(${m}->'${f.key}'->>'bytes')::uuid::text`
        : f.type === 'H32'
          ? `'sha256:'||(${m}->'${f.key}'->>'bytes')`
          : f.type === 'safe_uint'
            ? `(${m}->>'${f.key}')::numeric`
            : f.type === 'u64p'
              ? `${m}->>'${f.key}'`
              : f.type === 'P256_SPKI_DER'
                ? `${m}->'${f.key}'->>'bytes'`
                : `${m}->'${f.key}'`,
    ])
    .join(',')})`;
const receiptValue = (f) => {
  const fromSource = [
    'environmentId',
    'participantId',
    'privacyDomainId',
    'notificationOccurrenceId',
    'payloadObjectId',
    'keyPreparationId',
    'routingProfileDigest',
    'endpointId',
    'endpointRevision',
    'templateDigest',
    'payloadDigest',
    'encryptedObjectDigest',
    'keyId',
  ];
  if (f.name === 'schemaDefinitionDigest')
    return `jsonb_build_object('bytes','${started.definitionDigest.slice(7)}')`;
  if (fromSource.includes(f.name)) return `sm->'${key(source, f.name)}'`;
  const raw = {
    receiptId: 'item.signing_attempt_id::text',
    operationId: 'item.operation_id::text',
    attemptId: "d.preparation->'attempt'->>'attemptId'",
    sourceEventId: 'd.source_event_id::text',
    sourceDataDigest: `'sha256:'||(sm->'${key(source, 'dataDigest')}'->>'bytes')`,
    sourceReceiptDigest: 'proof.receipt_digest',
    workerProfileDigest: 'w.signed_profile_digest',
    authoritySnapshotDigest: "d.preparation->>'authorityDigest'",
    signedChannelProfileDigest: "d.preparation->'channel'->>'signedProfileDigest'",
    attemptDigest: "d.preparation->>'attemptDigest'",
    contextDigest: "d.preparation->>'contextDigest'",
    attemptNumber: 'd.attempt_number',
    startedAtMs: "d.preparation->'attempt'->>'startedAtMs'",
    deadlineAtMs: "d.preparation->'attempt'->>'deadlineAtMs'",
    deliveryRevision: 'd.delivery_revision',
    beforeStateDigest: "d.preparation->>'beforeStateDigest'",
    afterStateDigest: "d.preparation->>'plannedAfterStateDigest'",
    signerKeyId: 's.signer_id',
  }[f.name];
  if (!raw) throw new Error('Unbound native STARTED field');
  return f.type === 'uuidv7'
    ? uuid(raw)
    : f.type === 'H32'
      ? bytes(raw)
      : `to_jsonb((${raw})::numeric)`;
};
const receiptMap = `jsonb_build_object(${started.fields.flatMap((f) => [`'${f.key}'`, receiptValue(f)]).join(',')})`;
const requestFields = {
  schemaVersion: '1',
  method: "'SIGN_NOTIFICATION_DELIVERY_STARTED'",
  signerInstallationDigest: 's.trust_digest',
  providerId: "s.trust->>'providerId'",
  purpose: "s.trust->>'purpose'",
  secretClass: "s.trust->>'secretClass'",
  reference: "s.trust->>'secretReference'",
  version: "s.trust->>'secretVersion'",
  keyEpoch: "s.trust->>'keyEpoch'",
  signerKeyId: 's.signer_id',
  environmentId: "s.trust->>'environmentId'",
  participantId: 'item.participant_id::text',
  privacyDomainId: 'item.privacy_domain_id::text',
  workloadCredentialId: "s.trust->>'workloadCredentialId'",
  workloadEpoch: "s.trust->>'workloadEpoch'",
  workerInstallationDigest: 'w.installation_digest',
  workerProfileDigest: 'w.signed_profile_digest',
  signingAttemptId: 'item.signing_attempt_id::text',
  operationId: 'item.operation_id::text',
  deliveryAttemptId: 'd.attempt_id::text',
  deliveryPreparationDigest: 'd.preparation_digest',
  payloadHex: "r->>'payloadHex'",
};
const expectedRequest = `jsonb_build_object(${Object.entries(requestFields)
  .flatMap(([k, v]) => [`'${k}'`, v])
  .join(',')})`;
/** Canonical registry/permissions own adoption. No shared budget/attempt guard
 * is replaced here; current payload STATUS/vault admission stays in its existing
 * application owner in the same actual Identity transaction. */
export const notificationDeliverySigningGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_signing_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_preparation_owner();
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_delivery_signing'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_signing'::regclass AND tgname='notification_delivery_signing_guard' AND tgtype=23 AND tgenabled IN ('O','A') AND tgfoid='openpc.guard_notification_delivery_signing()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_signing'::regclass AND tgname='notification_delivery_signing_immutable' AND tgtype=42 AND tgenabled IN ('O','A') AND tgfoid='openpc.deny_notification_delivery_signing_mutation()'::regprocedure)
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_signing_original(item control.notification_delivery_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=item.preparation;r jsonb:=p->'request';m jsonb;sm jsonb;expected jsonb;
 d control.notification_delivery_preparation%ROWTYPE;s control.notification_receipt_signer_installation%ROWTYPE;
 w control.installed_notification_worker%ROWTYPE;event control.outbox_event%ROWTYPE;proof control.notification_occurrence_observation%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_signing_owner();
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-SCOPE'; END IF;
 SELECT * INTO STRICT d FROM control.notification_delivery_preparation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.operation_id;
 SELECT * INTO STRICT s FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=d.worker_installation_digest;
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=d.source_operation_id;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND event_id=d.source_event_id;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 sm:=openpc.business_cbor(proof.receipt_payload);
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR p-ARRAY['schema','deliveryPreparation','sourceClaims','trust','request','requestDigest'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(p))<>6 OR p->>'schema' IS DISTINCT FROM 'pc.notification.delivery-signing.v1'
 OR item.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8') OR item.preparation_digest IS DISTINCT FROM ${h('p')}
 OR p->'deliveryPreparation' IS DISTINCT FROM d.preparation OR p->'sourceClaims' IS DISTINCT FROM ${claims(source, 'sm')}
 OR p->'trust' IS DISTINCT FROM jsonb_build_object('signer',s.trust-ARRAY['schema','schemaDefinitionDigest','signerKeyId'],'worker',w.installation)
 OR s.worker_installation_digest IS DISTINCT FROM d.worker_installation_digest OR s.trust->>'workerProfileDigest' IS DISTINCT FROM w.signed_profile_digest
 OR s.trust->>'workerIssuerSpkiHex' IS DISTINCT FROM w.installation->'pins'->>'issuerSpkiHex'
 OR s.trust->>'purpose' IS DISTINCT FROM 'pc.cose.notification-delivery-started-receipt.v1' OR s.trust->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
 OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR item.signing_attempt_id IN (d.operation_id,d.attempt_id,d.source_operation_id,(sm->'${key(source, 'receiptId')}'->>'bytes')::uuid)
 OR item.signing_attempt_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 OR (r->>'payloadHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true OR length(r->>'payloadHex') NOT BETWEEN 2 AND 131072
 OR r IS DISTINCT FROM ${expectedRequest}
 OR item.request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.notification.receipt-provider-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(r),'UTF8')),'hex')
 OR p->>'requestDigest' IS DISTINCT FROM item.request_digest
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-ORIGINAL'; END IF;
 m:=openpc.business_cbor(decode(r->>'payloadHex','hex'));
 IF m IS DISTINCT FROM ${receiptMap}
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-NATIVE-PAYLOAD'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_signing_current(item control.notification_delivery_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=item.preparation->'deliveryPreparation';d control.notification_delivery%ROWTYPE;
 w control.installed_notification_worker%ROWTYPE;s control.notification_receipt_signer_installation%ROWTYPE;
 i control.installed_notification_channel%ROWTYPE;ep control.notification_endpoint%ROWTYPE;o control.notification_occurrence%ROWTYPE;
 rt control.installed_notification_routing%ROWTYPE;wm jsonb;cm jsonb;actual record;now_ms numeric;lock_name text;before jsonb;
BEGIN
 PERFORM openpc.check_notification_delivery_signing_original(item);
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=p->'source'->'worker'->>'installationDigest';
 SELECT * INTO STRICT s FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest;
 SELECT * INTO STRICT o FROM control.notification_occurrence WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=(p->'source'->>'notificationOccurrenceId')::uuid;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND endpoint_id=o.endpoint_id FOR SHARE;
 SELECT * INTO STRICT i FROM control.installed_notification_channel WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND credential_ref=o.credential_ref;
 SELECT * INTO STRICT rt FROM control.installed_notification_routing WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND signed_profile_digest=w.routing_profile_digest;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||item.participant_id::text,'notification-worker:'||item.participant_id::text||':'||item.privacy_domain_id::text,
  'notification-receipt-signer:'||item.participant_id::text||':'||item.privacy_domain_id::text,'notification-installation:'||item.participant_id::text||':'||item.privacy_domain_id::text,
  'notification-routing:'||item.participant_id::text||':'||item.privacy_domain_id::text||':'||rt.profile_id::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
   AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-FENCE'; END IF;
 END LOOP;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));cm:=openpc.business_cbor(decode(i.channel_signed->>'payloadHex','hex'));
 IF w.state<>'ACTIVE' OR s.state<>'ACTIVE' OR i.state<>'ACTIVE' OR ep.state<>'ACTIVE' OR rt.state<>'ACTIVE'
 OR now_ms<(p->'attempt'->>'startedAtMs')::numeric OR now_ms>=(p->'attempt'->>'deadlineAtMs')::numeric OR now_ms>=(p->>'authorityValidUntilMs')::numeric
 OR now_ms<(wm->>'${key(worker, 'validFromMs')}')::numeric OR now_ms>=(wm->>'${key(worker, 'validUntilMs')}')::numeric
 OR now_ms*1000000<(s.trust->>'validFromNs')::numeric OR now_ms*1000000>=(s.trust->>'validUntilNs')::numeric
 OR now_ms<(cm->>'${key(channel, 'validFromMs')}')::numeric OR now_ms>=(cm->>'${key(channel, 'validUntilMs')}')::numeric
 OR now_ms<(openpc.business_cbor(decode(rt.installation->'signed'->>'payloadHex','hex'))->>'${key(route, 'validFromMs')}')::numeric
 OR now_ms>=(openpc.business_cbor(decode(rt.installation->'signed'->>'payloadHex','hex'))->>'${key(route, 'validUntilMs')}')::numeric
 OR i.credential->>'state'<>'ACTIVE' OR now_ms<(i.credential->>'validFromMs')::numeric OR now_ms>=(i.credential->>'validUntilMs')::numeric
 OR ep.revision IS DISTINCT FROM o.endpoint_revision OR ep.verification_id IS DISTINCT FROM o.verification_id OR ep.credential_ref IS DISTINCT FROM o.credential_ref
 OR ep.channel IS DISTINCT FROM o.channel OR ep.destination_ref IS DISTINCT FROM o.destination_ref OR ep.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR i.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest OR i.channel IS DISTINCT FROM o.channel OR i.destination_ref IS DISTINCT FROM o.destination_ref
 OR rt.endpoint_id IS DISTINCT FROM o.endpoint_id OR p->'channel' IS DISTINCT FROM jsonb_build_object('claims',${claims(channel, 'cm')},'transport',i.channel_signed->'transport','signedProfileDigest',i.channel_profile_digest)
 OR NOT EXISTS(SELECT 1 FROM control.notification_endpoint_verification v WHERE v.participant_id=ep.participant_id AND v.privacy_domain_id=ep.privacy_domain_id AND v.verification_id=ep.verification_id
  AND v.endpoint_id=ep.endpoint_id AND v.endpoint_revision=ep.revision AND v.channel=ep.channel AND v.destination_ref=ep.destination_ref AND v.channel_profile_digest=ep.channel_profile_digest AND v.credential_ref=ep.credential_ref)
 OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal a USING(participant_id,principal_id) JOIN control.participant t USING(participant_id) JOIN control.privacy_domain v USING(participant_id)
  WHERE c.participant_id=item.participant_id AND c.credential_id=w.workload_credential_id AND a.principal_id=w.principal_id AND v.privacy_domain_id=item.privacy_domain_id
  AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch::text=p->>'workerEpoch' AND c.audience=w.installation->'pins'->>'workloadId'
  AND 'sha256:'||encode(c.public_key_digest,'hex')=w.installation->'pins'->>'workloadKeyDigest' AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp()
  AND a.state='ACTIVE' AND a.kind='WORKLOAD' AND t.state='ACTIVE' AND v.state='ACTIVE')
 OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal a USING(participant_id,principal_id) WHERE c.participant_id=item.participant_id AND c.credential_id=i.workload_credential_id
  AND a.principal_id=i.principal_id AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch=i.workload_epoch AND c.audience=i.workload_id
  AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp() AND a.state='ACTIVE' AND a.kind='WORKLOAD')
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-CURRENT'; END IF;
 SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit(item.preparation->'sourceClaims'->>'environmentId');
 IF actual.generation_id::text IS DISTINCT FROM p->>'generationId' OR actual.effective_digest IS DISTINCT FROM p->>'effectiveDigest' OR to_jsonb(actual.configured_limit) IS DISTINCT FROM p->'configuredLimit' OR actual.configured_limit<=0
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-GENERATION'; END IF;
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=o.notification_occurrence_id FOR UPDATE;
 before:=jsonb_build_object('participantId',d.participant_id::text,'privacyDomainId',d.privacy_domain_id::text,'notificationOccurrenceId',d.notification_occurrence_id::text,'payloadDigest',d.payload_digest,'state',d.state,
 'attemptCount',d.attempt_count,'attemptLimit',d.attempt_limit,'nextAttemptAtMs',d.next_attempt_at_ms,'lastStartedAtMs',d.last_started_at_ms,'cancelRequested',d.cancel_requested,'revision',d.revision::text,
 'deliveryRequestEventId',d.delivery_request_event_id::text,'deliveryRequestOperationId',d.delivery_request_operation_id::text,'budgetEnvironmentId',d.budget_environment_id,'budgetGenerationId',d.budget_generation_id::text,
 'budgetEffectiveDigest',d.budget_effective_digest,'budgetConfiguredLimit',d.budget_configured_limit,'budgetWorkerInstallationDigest',d.budget_worker_installation_digest);
 IF p->'before' IS DISTINCT FROM before OR d.cancel_requested OR d.state NOT IN ('PENDING','RETRY_WAIT') OR d.attempt_count>=least(d.attempt_limit,actual.configured_limit,6)
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-STATE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_signing() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o jsonb;payload bytea;cose bytea;
BEGIN
 PERFORM openpc.check_notification_delivery_signing_original(NEW);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-PREPARED'; END IF;
  PERFORM openpc.check_notification_delivery_signing_current(NEW);RETURN NEW;
 END IF;
 IF to_jsonb(NEW)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest']
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-IMMUTABLE'; END IF;
 IF OLD.state='PREPARED' AND NEW.state='DISPATCHED' THEN
  IF NEW.dispatch_token IS NULL OR NEW.dispatched_at_ms<floor(extract(epoch from transaction_timestamp())*1000) OR NEW.dispatched_at_ms>floor(extract(epoch from clock_timestamp())*1000)
  THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-DISPATCH'; END IF;
  PERFORM openpc.check_notification_delivery_signing_current(NEW);RETURN NEW;
 END IF;
 IF OLD.state<>'DISPATCHED' OR NEW.state<>'OBSERVED' OR NEW.dispatch_token IS DISTINCT FROM OLD.dispatch_token OR NEW.dispatched_at_ms IS DISTINCT FROM OLD.dispatched_at_ms
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-ONCE'; END IF;
 o:=NEW.observation;
 IF jsonb_typeof(o) IS DISTINCT FROM 'object' OR o-ARRAY['schemaVersion','providerId','signingAttemptId','requestDigest','recordedAtMs','outcome','reason','coseHex'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(o))<>8 OR o->'schemaVersion' IS DISTINCT FROM '1'::jsonb
 OR o->>'providerId' IS DISTINCT FROM NEW.preparation->'request'->>'providerId' OR o->>'signingAttemptId' IS DISTINCT FROM NEW.signing_attempt_id::text OR o->>'requestDigest' IS DISTINCT FROM NEW.request_digest
 OR NEW.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(o),'UTF8') OR NEW.observation_digest IS DISTINCT FROM ${h('o')}
 OR jsonb_typeof(o->'recordedAtMs') IS DISTINCT FROM 'number' OR (o->>'recordedAtMs')::numeric NOT BETWEEN 0 AND 9007199254740991 OR trunc((o->>'recordedAtMs')::numeric)<>(o->>'recordedAtMs')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-OBSERVATION'; END IF;
 IF o->>'outcome'='REJECTED' THEN
  IF o->'coseHex' IS DISTINCT FROM 'null'::jsonb OR (o->>'reason' IN ('REVOKED','EXPIRED','WRONG_SCOPE','INVALID_REQUEST','ATTEMPT_CONFLICT','KEY_UNAVAILABLE')) IS DISTINCT FROM true THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-REJECTION'; END IF;
 ELSE
  IF o->>'outcome' IS DISTINCT FROM 'SIGNED' OR o->'reason' IS DISTINCT FROM 'null'::jsonb OR (o->>'coseHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true
  OR length(o->>'coseHex') NOT BETWEEN 130 AND 133120 OR (o->>'recordedAtMs')::numeric<(NEW.preparation->'deliveryPreparation'->'attempt'->>'startedAtMs')::numeric
  OR (o->>'recordedAtMs')::numeric>=(NEW.preparation->'deliveryPreparation'->'attempt'->>'deadlineAtMs')::numeric
  THEN RAISE EXCEPTION 'NOTIFICATION-SIGNING-SIGNATURE'; END IF;
  payload:=decode(NEW.preparation->'request'->>'payloadHex','hex');cose:=decode(o->>'coseHex','hex');
  PERFORM openpc.archive_cose_binding(payload,cose,NEW.preparation->'request'->>'signerKeyId',${started.schemaId},${started.purposeCode});
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_signing_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-SIGNING-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_delivery_signing_guard ON control.notification_delivery_signing;
CREATE TRIGGER notification_delivery_signing_guard BEFORE INSERT OR UPDATE ON control.notification_delivery_signing FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_signing();
DROP TRIGGER IF EXISTS notification_delivery_signing_immutable ON control.notification_delivery_signing;
CREATE TRIGGER notification_delivery_signing_immutable BEFORE DELETE OR TRUNCATE ON control.notification_delivery_signing FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_signing_mutation();
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_signing_owner(),openpc.check_notification_delivery_signing_original(control.notification_delivery_signing),openpc.check_notification_delivery_signing_current(control.notification_delivery_signing),openpc.guard_notification_delivery_signing(),openpc.deny_notification_delivery_signing_mutation() FROM PUBLIC;
`;
