import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const key = (profile, name) => {
  const f = notificationCoseProfiles[profile].fields.find((p) => p.name === name);
  if (!f) throw new Error('Notification preparation claim missing');
  return f.key;
};
const wm = (name) => `wm->>'${key('NotificationWorkerProfileV1', name)}'`;
const cm = (name) => `cm->>'${key('NotificationChannelProfileV1', name)}'`;
const hash = (expr) =>
  `'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${expr}),'UTF8')),'hex')`;

const channelClaims = `jsonb_build_object(${notificationCoseProfiles.NotificationChannelProfileV1.fields
  .filter((f) => f.name !== 'schemaDefinitionDigest')
  .flatMap((f) => {
    const value =
      f.type === 'uuidv7'
        ? `(cm->'${f.key}'->>'bytes')::uuid::text`
        : f.type === 'H32'
          ? `'sha256:'||(cm->'${f.key}'->>'bytes')`
          : f.type === 'P256_SPKI_DER'
            ? `cm->'${f.key}'->>'bytes'`
            : f.type === 'safe_uint'
              ? `(cm->>'${f.key}')::numeric`
              : `cm->>'${f.key}'`;
    return [`'${f.name}'`, value];
  })
  .join(',')})`;

/** Registration/grants stay canonical. These functions admit only immutable
 * preparation INSERTs; STARTED, attempts, delivery and outbox are untouched. */
export const notificationDeliveryPreparationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_preparation_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_budget_owner();
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_delivery_preparation'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_preparation'::regclass
   AND tgname='notification_delivery_preparation_guard' AND tgenabled IN ('O','A')
   AND tgfoid='openpc.guard_notification_delivery_preparation()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_preparation'::regclass
   AND tgname='notification_delivery_preparation_immutable' AND tgenabled IN ('O','A')
   AND tgfoid='openpc.deny_notification_delivery_preparation_mutation()'::regprocedure)
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_preparation_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-IMMUTABLE'; END $$;
CREATE OR REPLACE FUNCTION openpc.read_notification_delivery_payload_size(source_event uuid,worker_installation text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE pid uuid:=openpc.current_participant_id();privacy uuid:=openpc.current_privacy_domain_id();
 event control.outbox_event%ROWTYPE;proof control.notification_occurrence_observation%ROWTYPE;
 o control.notification_occurrence%ROWTYPE;w control.installed_notification_worker%ROWTYPE;
 installed control.installed_notification_channel%ROWTYPE;ep control.notification_endpoint%ROWTYPE;
 route control.installed_notification_routing%ROWTYPE;source control.evidence_export_completion%ROWTYPE;
 wm jsonb;cm jsonb;now_ms numeric;lock_name text;source_data jsonb;subject text;body text;rendered bytea;
BEGIN
 PERFORM openpc.assert_notification_delivery_preparation_owner();
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||pid::text,'notification-worker:'||pid::text||':'||privacy::text,
  'notification-installation:'||pid::text||':'||privacy::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
   AND l.mode=(CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END))
  THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-FENCE'; END IF;
 END LOOP;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=pid AND privacy_domain_id=privacy AND event_id=source_event;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation WHERE participant_id=pid AND privacy_domain_id=privacy AND operation_id=event.correlation_id;
 SELECT * INTO STRICT o FROM control.notification_occurrence WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=event.aggregate_id;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=pid
  AND privacy_domain_id=privacy AND installation_digest=worker_installation;
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF w.state<>'ACTIVE' OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR w.installation->'pins'->>'processRole' IS DISTINCT FROM 'ROLE-NOTIFICATION-WORKER'
 OR w.routing_profile_digest IS DISTINCT FROM 'sha256:'||(openpc.business_cbor(proof.receipt_payload)->'${key('NotificationDeliveryRequestedReceiptV1', 'routingProfileDigest')}'->>'bytes')
 OR (w.installation->'pins'->>'workloadEpoch')::numeric NOT BETWEEN 1 AND 9007199254740991
 OR now_ms<(${wm('validFromMs')})::numeric OR now_ms>=(${wm('validUntilMs')})::numeric
 OR NOT EXISTS(SELECT 1 FROM control.credential x JOIN control.principal q USING(participant_id,principal_id)
  JOIN control.participant t USING(participant_id) JOIN control.privacy_domain v USING(participant_id)
  WHERE x.participant_id=pid AND v.privacy_domain_id=privacy
   AND x.credential_id=w.workload_credential_id AND q.principal_id=w.principal_id
   AND x.state='ACTIVE' AND x.kind='WORKLOAD_MTLS' AND q.state='ACTIVE' AND q.kind='WORKLOAD' AND t.state='ACTIVE' AND v.state='ACTIVE'
   AND x.credential_epoch::text=w.installation->'pins'->>'workloadEpoch' AND x.audience=w.installation->'pins'->>'workloadId'
   AND 'sha256:'||encode(x.public_key_digest,'hex')=w.installation->'pins'->>'workloadKeyDigest'
   AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-WORKER'; END IF;
 SELECT * INTO STRICT installed FROM control.installed_notification_channel WHERE participant_id=pid
  AND privacy_domain_id=privacy AND credential_ref=o.credential_ref;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=pid
  AND privacy_domain_id=privacy AND endpoint_id=o.endpoint_id FOR SHARE;
 cm:=openpc.business_cbor(decode(installed.channel_signed->>'payloadHex','hex'));
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=pid
  AND privacy_domain_id=privacy AND signed_profile_digest=w.routing_profile_digest;
 IF route.state<>'ACTIVE' OR route.endpoint_id IS DISTINCT FROM o.endpoint_id
 OR now_ms<(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${key('NotificationRoutingProfileV1', 'validFromMs')}')::numeric
 OR now_ms>=(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${key('NotificationRoutingProfileV1', 'validUntilMs')}')::numeric
 OR ep.state<>'ACTIVE' OR ep.revision IS DISTINCT FROM o.endpoint_revision OR ep.verification_id IS DISTINCT FROM o.verification_id
 OR ep.credential_ref IS DISTINCT FROM o.credential_ref OR ep.channel IS DISTINCT FROM o.channel
 OR ep.destination_ref IS DISTINCT FROM o.destination_ref OR ep.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR installed.state<>'ACTIVE' OR installed.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR installed.channel IS DISTINCT FROM ep.channel OR installed.destination_ref IS DISTINCT FROM ep.destination_ref
 OR installed.credential->>'state' IS DISTINCT FROM 'ACTIVE'
 OR (installed.credential->>'validFromMs')::numeric>now_ms OR (installed.credential->>'validUntilMs')::numeric<=now_ms
 OR now_ms<(${cm('validFromMs')})::numeric OR now_ms>=(${cm('validUntilMs')})::numeric
 OR ${cm('environmentId')} IS DISTINCT FROM ${wm('environmentId')}
 OR NOT EXISTS(SELECT 1 FROM control.notification_endpoint_verification v WHERE v.participant_id=ep.participant_id
  AND v.privacy_domain_id=ep.privacy_domain_id AND v.verification_id=ep.verification_id AND v.endpoint_id=ep.endpoint_id
  AND v.endpoint_revision=ep.revision AND v.channel=ep.channel AND v.destination_ref=ep.destination_ref
  AND v.channel_profile_digest=ep.channel_profile_digest AND v.credential_ref=ep.credential_ref)
 OR NOT EXISTS(SELECT 1 FROM control.credential x JOIN control.principal q USING(participant_id,principal_id)
  WHERE x.participant_id=pid AND x.credential_id=installed.workload_credential_id AND q.principal_id=installed.principal_id
  AND x.state='ACTIVE' AND x.kind='WORKLOAD_MTLS' AND q.state='ACTIVE' AND q.kind='WORKLOAD'
  AND x.credential_epoch=installed.workload_epoch AND x.audience=installed.workload_id
  AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-ENDPOINT'; END IF;
 lock_name:='notification-routing:'||pid::text||':'||privacy::text||':'||route.profile_id::text;
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ShareLock'
  AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
  AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-FENCE'; END IF;
 SELECT * INTO STRICT source FROM control.evidence_export_completion WHERE participant_id=pid
  AND privacy_domain_id=privacy AND event_id=o.source_event_id AND state='PUBLISHED';
 source_data:=convert_from(source.event_payload,'UTF8')::jsonb->'data';
 SELECT string_agg(CASE WHEN x->>'kind'='TEXT' THEN x->>'value' ELSE source_data->>(x->>'field') END,'' ORDER BY n)
 INTO subject FROM jsonb_array_elements(route.installation->'template'->'subject') WITH ORDINALITY AS parts(x,n);
 SELECT string_agg(CASE WHEN x->>'kind'='TEXT' THEN x->>'value' ELSE source_data->>(x->>'field') END,'' ORDER BY n)
 INTO body FROM jsonb_array_elements(route.installation->'template'->'body') WITH ORDINALITY AS parts(x,n);
 rendered:=convert_to(openpc.signing_canonical_json(jsonb_build_object('body',coalesce(body,''),'subject',coalesce(subject,''))),'UTF8');
 IF 'sha256:'||encode(sha256(rendered),'hex') IS DISTINCT FROM o.payload_digest
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-PAYLOAD'; END IF;

 IF octet_length(rendered)>(installed.channel_signed->'transport'->>'maxPayloadBytes')::integer
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-PAYLOAD-LIMIT'; END IF;
 RETURN octet_length(rendered);
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_preparation() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb; a jsonb; c jsonb; b jsonb; planned jsonb; snapshot jsonb; expected jsonb;
 d control.notification_delivery%ROWTYPE; o control.notification_occurrence%ROWTYPE;
 event control.outbox_event%ROWTYPE; proof control.notification_occurrence_observation%ROWTYPE;
 w control.installed_notification_worker%ROWTYPE; installed control.installed_notification_channel%ROWTYPE;
 ep control.notification_endpoint%ROWTYPE; route control.installed_notification_routing%ROWTYPE;
 source control.evidence_export_completion%ROWTYPE; actual record; wm jsonb; cm jsonb;
 now_ms numeric; started numeric; deadline numeric; valid_until numeric; lock_name text;
 payload_size integer;
BEGIN
 PERFORM openpc.assert_notification_delivery_preparation_owner();
 IF TG_OP<>'INSERT' OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-SCOPE'; END IF;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||NEW.participant_id::text,
   'notification-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,
   'notification-installation:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted
    AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
    AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
    AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
    AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-FENCE'; END IF;
 END LOOP;
 p:=NEW.preparation;a:=p->'attempt';c:=p->'context';
 IF jsonb_typeof(p) IS DISTINCT FROM 'object'
 OR p-ARRAY['schema','operationId','source','sourceOperationId','sourceReceiptDigest','workerCredentialId','workerEpoch',
  'authorityDigest','authorityValidUntilMs','generationId','effectiveDigest','configuredLimit','before','plannedAfter',
  'beforeStateDigest','plannedAfterStateDigest','channel','attempt','context','attemptDigest','contextDigest'] IS DISTINCT FROM '{}'::jsonb
 OR p->>'schema' IS DISTINCT FROM 'pc.notification.delivery-preparation.v1'
 OR NEW.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8')
 OR NEW.preparation_digest IS DISTINCT FROM ${hash('p')}
 OR p->>'operationId' IS DISTINCT FROM NEW.operation_id::text
 OR p->>'sourceOperationId' IS DISTINCT FROM NEW.source_operation_id::text
 OR p->'source' IS DISTINCT FROM jsonb_build_object('worker',jsonb_build_object('participantId',NEW.participant_id::text,
   'privacyDomainId',NEW.privacy_domain_id::text,'installationDigest',NEW.worker_installation_digest),
   'notificationOccurrenceId',NEW.notification_occurrence_id::text,'eventId',NEW.source_event_id::text)
 OR NEW.operation_id IN (NEW.source_operation_id,NEW.attempt_id) OR NEW.attempt_id=NEW.source_operation_id
 OR NEW.operation_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 OR NEW.attempt_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-IDENTITY'; END IF;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.source_event_id;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.source_operation_id;
 SELECT * INTO STRICT o FROM control.notification_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND notification_occurrence_id=NEW.notification_occurrence_id;
 IF event.aggregate_id IS DISTINCT FROM NEW.notification_occurrence_id OR event.correlation_id IS DISTINCT FROM NEW.source_operation_id
 OR p->>'sourceReceiptDigest' IS DISTINCT FROM proof.receipt_digest
 OR openpc.business_cbor(proof.receipt_payload)->'${key('NotificationDeliveryRequestedReceiptV1', 'eventId')}' IS DISTINCT FROM openpc.business_uuid(NEW.source_event_id)
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-SOURCE'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND installation_digest=NEW.worker_installation_digest;
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF w.state<>'ACTIVE' OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR w.installation->'pins'->>'processRole' IS DISTINCT FROM 'ROLE-NOTIFICATION-WORKER'
 OR w.routing_profile_digest IS DISTINCT FROM 'sha256:'||(openpc.business_cbor(proof.receipt_payload)->'${key('NotificationDeliveryRequestedReceiptV1', 'routingProfileDigest')}'->>'bytes')
 OR p->>'workerCredentialId' IS DISTINCT FROM w.workload_credential_id::text
 OR p->>'workerEpoch' IS DISTINCT FROM w.installation->'pins'->>'workloadEpoch'
 OR (p->>'workerEpoch')::numeric NOT BETWEEN 1 AND 9007199254740991
 OR now_ms<(${wm('validFromMs')})::numeric OR now_ms>=(${wm('validUntilMs')})::numeric
 OR p->>'authorityDigest' IS NULL OR p->>'authorityDigest' !~ '^sha256:[0-9a-f]{64}$'
 OR NOT EXISTS(SELECT 1 FROM control.credential x JOIN control.principal q USING(participant_id,principal_id)
  JOIN control.participant t USING(participant_id) JOIN control.privacy_domain v USING(participant_id)
  WHERE x.participant_id=NEW.participant_id AND v.privacy_domain_id=NEW.privacy_domain_id
   AND x.credential_id=w.workload_credential_id AND q.principal_id=w.principal_id
   AND x.state='ACTIVE' AND x.kind='WORKLOAD_MTLS' AND q.state='ACTIVE' AND q.kind='WORKLOAD' AND t.state='ACTIVE' AND v.state='ACTIVE'
   AND x.credential_epoch::text=p->>'workerEpoch' AND x.audience=w.installation->'pins'->>'workloadId'
   AND 'sha256:'||encode(x.public_key_digest,'hex')=w.installation->'pins'->>'workloadKeyDigest'
   AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-WORKER'; END IF;
 SELECT * INTO STRICT installed FROM control.installed_notification_channel WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND credential_ref=o.credential_ref;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND endpoint_id=o.endpoint_id FOR SHARE;
 cm:=openpc.business_cbor(decode(installed.channel_signed->>'payloadHex','hex'));
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND signed_profile_digest=w.routing_profile_digest;
 IF route.state<>'ACTIVE' OR route.endpoint_id IS DISTINCT FROM o.endpoint_id
 OR now_ms<(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${key('NotificationRoutingProfileV1', 'validFromMs')}')::numeric
 OR now_ms>=(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${key('NotificationRoutingProfileV1', 'validUntilMs')}')::numeric
 OR ep.state<>'ACTIVE' OR ep.revision IS DISTINCT FROM o.endpoint_revision OR ep.verification_id IS DISTINCT FROM o.verification_id
 OR ep.credential_ref IS DISTINCT FROM o.credential_ref OR ep.channel IS DISTINCT FROM o.channel
 OR ep.destination_ref IS DISTINCT FROM o.destination_ref OR ep.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR installed.state<>'ACTIVE' OR installed.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR installed.channel IS DISTINCT FROM ep.channel OR installed.destination_ref IS DISTINCT FROM ep.destination_ref
 OR installed.credential->>'state' IS DISTINCT FROM 'ACTIVE'
 OR (installed.credential->>'validFromMs')::numeric>now_ms OR (installed.credential->>'validUntilMs')::numeric<=now_ms
 OR now_ms<(${cm('validFromMs')})::numeric OR now_ms>=(${cm('validUntilMs')})::numeric
 OR ${cm('environmentId')} IS DISTINCT FROM ${wm('environmentId')}
 OR NOT EXISTS(SELECT 1 FROM control.notification_endpoint_verification v WHERE v.participant_id=ep.participant_id
  AND v.privacy_domain_id=ep.privacy_domain_id AND v.verification_id=ep.verification_id AND v.endpoint_id=ep.endpoint_id
  AND v.endpoint_revision=ep.revision AND v.channel=ep.channel AND v.destination_ref=ep.destination_ref
  AND v.channel_profile_digest=ep.channel_profile_digest AND v.credential_ref=ep.credential_ref)
 OR NOT EXISTS(SELECT 1 FROM control.credential x JOIN control.principal q USING(participant_id,principal_id)
  WHERE x.participant_id=NEW.participant_id AND x.credential_id=installed.workload_credential_id AND q.principal_id=installed.principal_id
  AND x.state='ACTIVE' AND x.kind='WORKLOAD_MTLS' AND q.state='ACTIVE' AND q.kind='WORKLOAD'
  AND x.credential_epoch=installed.workload_epoch AND x.audience=installed.workload_id
  AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-ENDPOINT'; END IF;
 lock_name:='notification-routing:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||route.profile_id::text;
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ShareLock'
  AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
  AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-FENCE'; END IF;
 SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit(${wm('environmentId')});
 IF p->>'generationId' IS DISTINCT FROM actual.generation_id::text OR p->>'effectiveDigest' IS DISTINCT FROM actual.effective_digest
 OR p->'configuredLimit' IS DISTINCT FROM to_jsonb(actual.configured_limit)
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-GENERATION'; END IF;
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND notification_occurrence_id=NEW.notification_occurrence_id FOR UPDATE;
 started:=(a->>'startedAtMs')::numeric;deadline:=(a->>'deadlineAtMs')::numeric;
 IF d.revision IS DISTINCT FROM NEW.delivery_revision OR d.payload_digest IS DISTINCT FROM o.payload_digest
 OR d.delivery_request_event_id IS DISTINCT FROM NEW.source_event_id OR d.delivery_request_operation_id IS DISTINCT FROM NEW.source_operation_id
 OR d.budget_environment_id IS DISTINCT FROM ${wm('environmentId')}
 OR d.state NOT IN ('PENDING','RETRY_WAIT') OR d.cancel_requested OR d.attempt_count>=d.attempt_limit
 OR d.attempt_limit>least(actual.configured_limit,6) OR d.next_attempt_at_ms>started
 OR NEW.attempt_number<>d.attempt_count+1 OR d.last_started_at_ms>started
 OR started<floor(extract(epoch from transaction_timestamp())*1000) OR started>now_ms
 OR started<>trunc(started) OR deadline<>trunc(deadline) OR deadline<=now_ms
 OR deadline>9007199254740991 OR deadline<=started
 OR EXISTS(SELECT 1 FROM control.notification_delivery_preparation x WHERE x.participant_id=NEW.participant_id
   AND x.privacy_domain_id=NEW.privacy_domain_id AND x.notification_occurrence_id=NEW.notification_occurrence_id
   AND (x.attempt_number>=NEW.attempt_number OR x.delivery_revision>=NEW.delivery_revision))
 OR (d.attempt_count>0 AND NOT EXISTS(SELECT 1 FROM control.notification_delivery_preparation x WHERE x.participant_id=NEW.participant_id
   AND x.privacy_domain_id=NEW.privacy_domain_id AND x.notification_occurrence_id=NEW.notification_occurrence_id
   AND x.attempt_number=d.attempt_count AND (x.preparation->'attempt'->>'startedAtMs')::numeric=d.last_started_at_ms))
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-ELIGIBILITY'; END IF;
 snapshot:=jsonb_build_object('participantId',d.participant_id::text,'privacyDomainId',d.privacy_domain_id::text,
  'notificationOccurrenceId',d.notification_occurrence_id::text,'payloadDigest',d.payload_digest,'state',d.state,
  'attemptCount',d.attempt_count,'attemptLimit',d.attempt_limit,'nextAttemptAtMs',d.next_attempt_at_ms,
  'lastStartedAtMs',d.last_started_at_ms,'cancelRequested',d.cancel_requested);
 b:=snapshot||jsonb_build_object('revision',d.revision::text,'deliveryRequestEventId',d.delivery_request_event_id::text,
  'deliveryRequestOperationId',d.delivery_request_operation_id::text,'budgetEnvironmentId',d.budget_environment_id,
  'budgetGenerationId',d.budget_generation_id::text,'budgetEffectiveDigest',d.budget_effective_digest,
  'budgetConfiguredLimit',d.budget_configured_limit,'budgetWorkerInstallationDigest',d.budget_worker_installation_digest);
 planned:=snapshot||jsonb_build_object('state','STARTED','attemptCount',NEW.attempt_number,'nextAttemptAtMs',null,'lastStartedAtMs',started);
 IF p->'before' IS DISTINCT FROM b OR p->'plannedAfter' IS DISTINCT FROM planned
 OR p->>'beforeStateDigest' IS DISTINCT FROM ${hash("jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',d.revision::text,'projection',snapshot)")}
 OR p->>'plannedAfterStateDigest' IS DISTINCT FROM ${hash("jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',(d.revision+1)::text,'projection',planned)")}
 OR p->'channel'->'transport' IS DISTINCT FROM installed.channel_signed->'transport'
 OR p->'channel'->>'signedProfileDigest' IS DISTINCT FROM installed.channel_profile_digest
 OR p->'channel'->'claims' IS DISTINCT FROM ${channelClaims}
 OR p->'channel'-ARRAY['claims','transport','signedProfileDigest'] IS DISTINCT FROM '{}'::jsonb
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-PROJECTION'; END IF;
 payload_size:=openpc.read_notification_delivery_payload_size(NEW.source_event_id,NEW.worker_installation_digest);
 expected:=jsonb_build_object('version','NotificationDeliveryAttemptV1','participantId',NEW.participant_id::text,
  'privacyDomainId',NEW.privacy_domain_id::text,'notificationOccurrenceId','urn:openpc:resource:'||NEW.notification_occurrence_id::text,
  'endpointId','urn:openpc:resource:'||o.endpoint_id::text,'endpointRevision',o.endpoint_revision::text,
  'channel',o.channel,'destinationRef',o.destination_ref,'credentialRef',o.credential_ref,'channelProfileDigest',o.channel_profile_digest,
  'templateDigest',o.template_digest,'payloadDigest',o.payload_digest,'payloadBytes',payload_size,
  'attemptId',NEW.attempt_id::text,'attemptNumber',NEW.attempt_number,'startedAtMs',started,'deadlineAtMs',deadline);
 SELECT least(floor(extract(epoch from min(valid_until))*1000),(${wm('validUntilMs')})::numeric,
  (${cm('validUntilMs')})::numeric,(installed.credential->>'validUntilMs')::numeric,
  (openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${key('NotificationRoutingProfileV1', 'validUntilMs')}')::numeric)
 INTO valid_until FROM control.credential WHERE participant_id=NEW.participant_id
  AND credential_id IN (w.workload_credential_id,installed.workload_credential_id);
 IF a IS DISTINCT FROM expected OR p->>'attemptDigest' IS DISTINCT FROM ${hash('a')}
 OR p->'authorityValidUntilMs' IS DISTINCT FROM to_jsonb(valid_until)
 OR deadline IS DISTINCT FROM least(started+(installed.channel_signed->'transport'->>'requestTimeoutMs')::numeric,valid_until)
 OR payload_size>(installed.channel_signed->'transport'->>'maxPayloadBytes')::integer
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-ATTEMPT'; END IF;
 expected:=jsonb_build_object('authorizationDigest',p->>'authorityDigest','authorizationContextId',w.workload_credential_id::text,
  'authorizationContextEpoch',(p->>'workerEpoch')::numeric,'accessClassIds',jsonb_build_array('ACCESS-NOTIFICATION'),
  'profileDigest',installed.channel_profile_digest,
  'scopeDigest',${hash("jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text)")},
  'idempotencyDigest',${hash("jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'notificationOccurrenceId','urn:openpc:resource:'||NEW.notification_occurrence_id::text,'payloadDigest',o.payload_digest)")},
  'deadlineAt',to_char(to_timestamp(deadline::double precision/1000) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'occurrenceId',NEW.notification_occurrence_id::text,'auditCorrelationId',NEW.operation_id::text,
  'cancellation',jsonb_build_object('mode','NO_NEW_EFFECT_AFTER_CANCELLATION','occurrenceId',NEW.notification_occurrence_id::text),
  'reconciliation',jsonb_build_object('mode','EXACT_OCCURRENCE','occurrenceId',NEW.notification_occurrence_id::text));
 IF c IS DISTINCT FROM expected OR p->>'contextDigest' IS DISTINCT FROM ${hash('c')}
 THEN RAISE EXCEPTION 'NOTIFICATION-PREPARATION-CONTEXT'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_delivery_preparation_guard ON control.notification_delivery_preparation;
CREATE TRIGGER notification_delivery_preparation_guard BEFORE INSERT ON control.notification_delivery_preparation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_preparation();
DROP TRIGGER IF EXISTS notification_delivery_preparation_immutable ON control.notification_delivery_preparation;
CREATE TRIGGER notification_delivery_preparation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_preparation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_preparation_mutation();
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_preparation_owner(),openpc.guard_notification_delivery_preparation(),openpc.deny_notification_delivery_preparation_mutation(),openpc.read_notification_delivery_payload_size(uuid,text) FROM PUBLIC;
`;
