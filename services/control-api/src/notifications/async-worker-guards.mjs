import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const field = (profile, name) => {
  const entry = notificationCoseProfiles[profile].fields.find((f) => f.name === name);
  if (!entry) throw new Error('Notification claim missing');
  return entry.key;
};
/** Canonical registration owns grants/migration order and these two native
 * joins. They are required future bindings, NOT existing authority or optional
 * readiness flags. Until bound, every scheduling mutation fails closed. The
 * native current owner must derive actual input/capacity/process custody; the
 * proof owner selects immutable transition rows and atomically emits its
 * registered protected operational event. Neither accepts caller documents. */
export const notificationAsyncWorkerRequiredOwners = Object.freeze({
  current: 'openpc.assert_notification_async_work_current(control.notification_async_work)',
  proof: 'openpc.publish_notification_async_work_proof(uuid,numeric)',
  historical: 'openpc.check_notification_async_work_proof(uuid,numeric)',
});

export const notificationAsyncWorkerGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_async_worker_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin'
 OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_async_work'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_async_work_transition'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR EXISTS(SELECT 1 FROM (VALUES
 ('control.notification_async_work'::regclass,'notification_async_work_guard','openpc.guard_notification_async_work()',31),
 ('control.notification_async_work'::regclass,'notification_async_work_retain','openpc.retain_notification_async_work_transition()',21),
 ('control.notification_async_work'::regclass,'notification_async_work_no_truncate','openpc.deny_notification_async_truncate()',34),
 ('control.notification_async_work_transition'::regclass,'notification_async_transition_guard','openpc.guard_notification_async_transition()',31),
 ('control.notification_async_work_transition'::regclass,'notification_async_transition_no_truncate','openpc.deny_notification_async_truncate()',34)) required(rel,name,fn,kind)
 WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=required.rel AND t.tgname=required.name
 AND t.tgfoid=to_regprocedure(required.fn) AND t.tgtype=required.kind AND t.tgenabled='O' AND NOT t.tgisinternal))
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-OWNER'; END IF;
 IF to_regprocedure('${notificationAsyncWorkerRequiredOwners.current}') IS NULL
 OR to_regprocedure('${notificationAsyncWorkerRequiredOwners.proof}') IS NULL
 OR to_regprocedure('${notificationAsyncWorkerRequiredOwners.historical}') IS NULL
 THEN RAISE EXCEPTION 'OPS_NOTIFICATION_ASYNC_PROOF_OWNER_UNBOUND'; END IF;
END $$;

-- This is a fenced inspection of existing durable owners, not an external
-- no-effect receipt. A DISPATCHED signer request remains unknown forever unless
-- its own observation owner resolves it; provider absence/timeout is not used.
CREATE OR REPLACE FUNCTION openpc.notification_async_pre_effect_phase(source_event uuid) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE w control.notification_async_work%ROWTYPE;p control.notification_delivery_preparation%ROWTYPE;
 d control.notification_delivery%ROWTYPE;s control.notification_delivery_signing%ROWTYPE;
 event control.outbox_event%ROWTYPE;lock_name text;now_ms numeric;has_delivery boolean;has_signing boolean;
BEGIN
 PERFORM openpc.assert_notification_async_worker_owner();
 SELECT * INTO STRICT w FROM control.notification_async_work WHERE participant_id=openpc.current_participant_id()
 AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=source_event;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||w.participant_id::text,
  'notification-work-effect:'||w.participant_id::text||':'||w.privacy_domain_id::text||':'||w.event_id::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock'
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
   AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PRE-EFFECT-FENCE'; END IF;
 END LOOP;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id AND event_id=w.event_id;
 -- Includes both actual source inboxes and their original cursor/effect binding.
 PERFORM openpc.check_notification_delivery_requested_event(event);
 PERFORM openpc.assert_notification_delivery_signing_owner();
 SELECT * INTO d FROM control.notification_delivery WHERE participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id
 AND notification_occurrence_id=w.notification_occurrence_id FOR UPDATE;
 has_delivery:=FOUND;
 IF EXISTS(SELECT 1 FROM control.notification_cancellation_signing WHERE participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id
  AND notification_occurrence_id=w.notification_occurrence_id) OR (has_delivery AND d.cancel_requested)
 THEN RETURN 'HANDED_OFF'; END IF;
 SELECT * INTO p FROM control.notification_delivery_preparation WHERE participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id
 AND notification_occurrence_id=w.notification_occurrence_id ORDER BY attempt_number DESC LIMIT 1;
 IF NOT FOUND THEN
  IF has_delivery AND (d.state<>'PENDING' OR d.attempt_count<>0 OR d.last_started_at_ms IS NOT NULL)
  THEN RETURN 'HANDED_OFF'; END IF;
  IF EXISTS(SELECT 1 FROM control.notification_delivery_start WHERE participant_id=w.participant_id AND privacy_domain_id=w.privacy_domain_id AND notification_occurrence_id=w.notification_occurrence_id)
  THEN RETURN 'HANDED_OFF'; END IF;
  IF w.deadline_at_ms<=floor(extract(epoch from clock_timestamp())*1000) THEN RETURN 'STALE_PREPARED'; END IF;
  RETURN 'UNPREPARED';
 END IF;
 IF NOT has_delivery OR p.source_event_id<>w.event_id OR p.worker_installation_digest<>w.worker_installation_digest
 OR p.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p.preparation),'UTF8')
 OR p.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(p.preparation_bytes),'hex')
 OR p.preparation->>'operationId' IS DISTINCT FROM p.operation_id::text
 OR p.preparation->'attempt'->>'attemptId' IS DISTINCT FROM p.attempt_id::text
 OR p.preparation->'attempt'->'attemptNumber' IS DISTINCT FROM to_jsonb(p.attempt_number)
 OR p.preparation->'source'->>'eventId' IS DISTINCT FROM w.event_id::text
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PRE-EFFECT-ORIGINAL'; END IF;
 IF d.attempt_count<>p.attempt_number-1 OR d.state NOT IN ('PENDING','RETRY_WAIT')
 OR EXISTS(SELECT 1 FROM control.notification_delivery_start WHERE participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id AND operation_id=p.operation_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_dispatch_intent WHERE participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id AND operation_id=p.operation_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_outcome_signing WHERE participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id AND start_operation_id=p.operation_id)
 THEN RETURN 'HANDED_OFF'; END IF;
 SELECT * INTO s FROM control.notification_delivery_signing WHERE participant_id=p.participant_id AND privacy_domain_id=p.privacy_domain_id AND operation_id=p.operation_id FOR UPDATE;
 has_signing:=FOUND;
 IF has_signing THEN
  PERFORM openpc.check_notification_delivery_signing_original(s);
  IF s.state<>'PREPARED' OR s.dispatch_token IS NOT NULL OR s.dispatched_at_ms IS NOT NULL
   OR s.observation IS NOT NULL OR s.observation_bytes IS NOT NULL
  THEN RETURN 'HANDED_OFF'; END IF;
 END IF;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF least((p.preparation->'attempt'->>'deadlineAtMs')::numeric,(p.preparation->>'authorityValidUntilMs')::numeric,w.deadline_at_ms)<=now_ms
 OR d.attempt_limit<p.attempt_number OR p.preparation->>'generationId' IS DISTINCT FROM w.generation_id::text
 OR (p.preparation->'before'->>'revision')::numeric<>d.revision
 THEN RETURN 'STALE_PREPARED'; END IF;
 RETURN CASE WHEN has_signing THEN 'SIGNING_PREPARED' ELSE 'PREPARED' END;
END $$;

-- This selector-only inspector does not admit INSERT or authorize dispatch.
-- The mandatory native assertion in guard_notification_async_work and protected
-- proof publication independently rederives qualified deadline/input/capacity.
-- Its bookkeeping branch MUST retain actual EFFECTIVE process, role, scope,
-- generation, reviewer and artifact custody; only live payload/route eligibility
-- is inapplicable to a proven initial terminal disposition. No native stub here.
CREATE OR REPLACE FUNCTION openpc.notification_async_initial_disposition(source_event uuid,worker_installation text,qualified_deadline numeric) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE pid uuid:=openpc.current_participant_id();privacy uuid:=openpc.current_privacy_domain_id();
 event control.outbox_event%ROWTYPE;o control.notification_occurrence%ROWTYPE;
 prep control.notification_occurrence_preparation%ROWTYPE;w control.installed_notification_worker%ROWTYPE;
 ep control.notification_endpoint%ROWTYPE;route control.installed_notification_routing%ROWTYPE;
 channel control.installed_notification_channel%ROWTYPE;wm jsonb;lock_name text;why text;now_ms numeric;
BEGIN
 PERFORM openpc.assert_notification_async_worker_owner();
 lock_name:='evidence-lifecycle:'||pid::text;
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock'
  AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
  AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-FENCE'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-work-effect:'||pid::text||':'||privacy::text||':'||source_event::text,0))
 OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-worker:'||pid::text||':'||privacy::text,0))
 OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-installation:'||pid::text||':'||privacy::text,0))
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-BUSY'; END IF;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=pid AND privacy_domain_id=privacy AND event_id=source_event;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 SELECT * INTO STRICT o FROM control.notification_occurrence WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=event.aggregate_id;
 SELECT p.* INTO STRICT prep FROM control.notification_occurrence_preparation p
 JOIN control.notification_occurrence_observation r USING(participant_id,privacy_domain_id,preparation_id)
 WHERE p.participant_id=pid AND p.privacy_domain_id=privacy AND r.operation_id=event.correlation_id;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=pid AND privacy_domain_id=privacy AND installation_digest=worker_installation;
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF prep.family<>'NotificationDeliveryRequestedReceiptV1' OR prep.state<>'OBSERVED'
 OR prep.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(prep.preparation),'UTF8')
 OR prep.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(prep.preparation_bytes),'hex')
 OR prep.preparation->'workerProfile'->>'environmentId' IS DISTINCT FROM wm->>'${field('NotificationWorkerProfileV1', 'environmentId')}'
 OR prep.preparation->'workerProfile'->>'routingProfileDigest' IS DISTINCT FROM w.routing_profile_digest
 OR w.state<>'ACTIVE' OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR qualified_deadline IS NULL OR qualified_deadline<=floor(extract(epoch from event.occurred_at)*1000)
 OR qualified_deadline>9007199254740991
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-SOURCE'; END IF;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=pid AND privacy_domain_id=privacy AND endpoint_id=o.endpoint_id FOR SHARE;
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=pid AND privacy_domain_id=privacy AND signed_profile_digest=w.routing_profile_digest;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-routing:'||pid::text||':'||privacy::text||':'||route.profile_id::text,0))
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-BUSY'; END IF;
 -- Re-read after the owner's route fence, never treat missing rows as withdrawal.
 SELECT * INTO STRICT route FROM control.installed_notification_routing WHERE participant_id=pid AND privacy_domain_id=privacy AND signed_profile_digest=w.routing_profile_digest;
 SELECT * INTO STRICT channel FROM control.installed_notification_channel WHERE participant_id=pid AND privacy_domain_id=privacy AND credential_ref=o.credential_ref;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF qualified_deadline<=now_ms THEN why:='INITIAL_DOMAIN_DEADLINE';
 ELSIF ep.state<>'ACTIVE' OR ep.revision IS DISTINCT FROM o.endpoint_revision OR ep.verification_id IS DISTINCT FROM o.verification_id
 OR ep.credential_ref IS DISTINCT FROM o.credential_ref OR ep.channel IS DISTINCT FROM o.channel
 OR ep.destination_ref IS DISTINCT FROM o.destination_ref OR ep.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR route.state<>'ACTIVE' OR route.endpoint_id IS DISTINCT FROM o.endpoint_id
 OR prep.preparation->'workerProfile'->>'producerTrustDigest' IS DISTINCT FROM 'sha256:'||(wm->'${field('NotificationWorkerProfileV1', 'producerTrustDigest')}'->>'bytes')
 OR prep.preparation->'workerProfile'->>'kmsInstallationDigest' IS DISTINCT FROM 'sha256:'||(wm->'${field('NotificationWorkerProfileV1', 'kmsInstallationDigest')}'->>'bytes')
 OR now_ms>=(openpc.business_cbor(decode(route.installation->'signed'->>'payloadHex','hex'))->>'${field('NotificationRoutingProfileV1', 'validUntilMs')}')::numeric
 OR channel.state<>'ACTIVE' OR channel.channel_profile_digest IS DISTINCT FROM o.channel_profile_digest
 OR channel.credential->>'state' IS DISTINCT FROM 'ACTIVE'
 OR (channel.credential->>'validUntilMs')::numeric<=now_ms
 OR now_ms>=(openpc.business_cbor(decode(channel.channel_signed->>'payloadHex','hex'))->>'${field('NotificationChannelProfileV1', 'validUntilMs')}')::numeric
 THEN why:='INITIAL_SOURCE_WITHDRAWN';
 ELSE RETURN NULL;
 END IF;
 -- A prior budget, signer request or any delivery intent is not an unqueued
 -- no-effect original. Preserve all such uncertainty for its existing owner.
 IF EXISTS(SELECT 1 FROM control.notification_delivery WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_preparation WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_signing s JOIN control.notification_delivery_preparation p USING(participant_id,privacy_domain_id,operation_id) WHERE p.participant_id=pid AND p.privacy_domain_id=privacy AND p.notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_start WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_dispatch_intent WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_outcome WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_outcome_signing WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 OR EXISTS(SELECT 1 FROM control.notification_cancellation_signing WHERE participant_id=pid AND privacy_domain_id=privacy AND notification_occurrence_id=o.notification_occurrence_id)
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-ORIGINAL-UNRESOLVED'; END IF;
 RETURN why;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_async_work() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE source control.outbox_event%ROWTYPE;now_ms numeric;lock_name text;pre_effect text;initial_reason text;
BEGIN
 PERFORM openpc.assert_notification_async_worker_owner();
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-SCOPE'; END IF;
 SELECT * INTO STRICT source FROM control.outbox_event WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 PERFORM openpc.check_notification_delivery_requested_event(source);
 IF source.aggregate_type<>'notification-occurrence' OR source.aggregate_id<>NEW.notification_occurrence_id
 OR source.sequence_namespace<>'NOTIFICATION_DELIVERY_REQUESTED_V1' OR source.business_sequence<>NEW.sequence
 OR NEW.partition<>source.aggregate_type||':'||source.aggregate_id::text
 OR NEW.payload_bytes IS DISTINCT FROM octet_length(source.payload_cbor)
 OR NEW.source_digest IS DISTINCT FROM 'sha256:'||encode(source.payload_digest,'hex')
 OR NEW.published_at_ms IS DISTINCT FROM floor(extract(epoch from source.occurred_at)*1000)
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-SOURCE'; END IF;
 -- The canonical native SQL owner verifies limits, original artifact custody,
 -- actual mounted process and issuer/reviewer/current source fences itself.
 -- payload_bytes is receipt-envelope queue occupancy, NOT delivered body size.
 -- For live PENDING only, native maximumPayloadBytes MUST compare the body from
 -- read_notification_delivery_payload_size(event_id,worker_installation_digest)
 -- at INSERT, and verified immutable preparation attempt.payloadBytes at effects.
 EXECUTE 'select openpc.assert_notification_async_work_current($1)' USING NEW;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF TG_OP='INSERT' THEN
  initial_reason:=openpc.notification_async_initial_disposition(NEW.event_id,NEW.worker_installation_digest,NEW.deadline_at_ms);
  IF NEW.revision<>1 OR NEW.lease_epoch<>0 OR NEW.lease_owner IS NOT NULL OR NEW.lease_until_ms IS NOT NULL
  OR NEW.charged OR NEW.effect_uncertain OR NEW.original IS NOT NULL OR NEW.next_at_ms IS NOT NULL
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-INITIAL'; END IF;
  IF initial_reason IS NOT NULL THEN
   IF NEW.state<>'QUARANTINED' OR NEW.reason IS DISTINCT FROM initial_reason
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION'; END IF;
  ELSE
   PERFORM openpc.read_notification_delivery_payload_size(NEW.event_id,NEW.worker_installation_digest);
   IF NEW.state<>'PENDING' OR NEW.reason IS NOT NULL OR NEW.deadline_at_ms<=now_ms
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-INITIAL'; END IF;
  END IF;
 ELSE
  IF NEW.reason IN ('INITIAL_DOMAIN_DEADLINE','INITIAL_SOURCE_WITHDRAWN')
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-INITIAL-ONLY'; END IF;
  IF OLD.state='QUARANTINED' AND OLD.revision=1 AND OLD.lease_epoch=0 AND NOT OLD.charged AND NOT OLD.effect_uncertain
   AND OLD.reason IN ('INITIAL_DOMAIN_DEADLINE','INITIAL_SOURCE_WITHDRAWN')
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-DISPOSITION-TERMINAL'; END IF;
  IF to_jsonb(NEW)-ARRAY['state','lease_owner','lease_epoch','lease_until_ms','charged','effect_uncertain','next_at_ms','original','reason','revision','transition_event_id']
   IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','lease_owner','lease_epoch','lease_until_ms','charged','effect_uncertain','next_at_ms','original','reason','revision','transition_event_id']
  OR NEW.revision<>OLD.revision+1 OR NEW.lease_epoch<OLD.lease_epoch OR NEW.lease_epoch>OLD.lease_epoch+1
  OR OLD.state IN ('DONE','CANCELLED') OR NEW.transition_event_id=OLD.transition_event_id
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-IMMUTABLE'; END IF;
  IF NEW.lease_epoch>OLD.lease_epoch THEN
   lock_name:='notification-work-effect:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.event_id::text;
   IF NOT pg_try_advisory_xact_lock(hashtextextended(lock_name,0)) THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-EFFECT-HELD'; END IF;
   pre_effect:=openpc.notification_async_pre_effect_phase(NEW.event_id);
   IF OLD.state NOT IN ('PENDING','RETRY_WAIT','LEASED','RECONCILING','QUARANTINED')
   OR (OLD.state='RETRY_WAIT' AND OLD.next_at_ms>now_ms) OR OLD.deadline_at_ms<=now_ms
   OR NEW.state IS DISTINCT FROM (CASE WHEN OLD.effect_uncertain AND pre_effect NOT IN ('UNPREPARED','PREPARED','SIGNING_PREPARED') THEN 'RECONCILING' ELSE 'LEASED' END)
   OR NOT NEW.charged OR NOT NEW.effect_uncertain OR NEW.next_at_ms IS NOT NULL
   OR OLD.lease_until_ms>now_ms OR NEW.lease_owner IS NULL OR NEW.lease_until_ms<=now_ms
   OR (OLD.effect_uncertain AND pre_effect NOT IN ('UNPREPARED','PREPARED','SIGNING_PREPARED') AND (NEW.state<>'RECONCILING' OR NOT NEW.charged OR NOT NEW.effect_uncertain))
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-TAKEOVER'; END IF;
  ELSIF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND NEW.lease_owner IS NOT NULL
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-EPOCH';
  ELSIF NEW.lease_owner IS NOT NULL THEN
   -- Same-epoch heartbeat changes no business/effect/source custody.
   IF OLD.lease_until_ms<=now_ms OR NEW.lease_until_ms<OLD.lease_until_ms
   OR to_jsonb(NEW)-ARRAY['lease_until_ms','revision','transition_event_id'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['lease_until_ms','revision','transition_event_id']
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-HEARTBEAT'; END IF;
  ELSE
   IF NOT ((OLD.state IN ('LEASED','RECONCILING') AND OLD.lease_owner IS NOT NULL
     AND NEW.state IN ('RETRY_WAIT','DONE','CANCELLED','QUARANTINED'))
    OR (OLD.state IN ('PENDING','RETRY_WAIT','LEASED','RECONCILING','QUARANTINED') AND (OLD.lease_until_ms IS NULL OR OLD.lease_until_ms<=now_ms)
     AND NEW.state='QUARANTINED' AND NOT NEW.charged AND NOT NEW.effect_uncertain AND NEW.reason='PRE_EFFECT_STALE'
     AND openpc.notification_async_pre_effect_phase(NEW.event_id)='STALE_PREPARED')
    OR (OLD.state IN ('PENDING','RETRY_WAIT') AND OLD.deadline_at_ms<=now_ms AND NEW.state='QUARANTINED'
     AND NEW.charged=OLD.charged AND NEW.effect_uncertain=OLD.effect_uncertain AND NEW.reason='DOMAIN_DEADLINE'))
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-SETTLEMENT'; END IF;
   lock_name:='notification-work-effect:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.event_id::text;
   IF NOT pg_try_advisory_xact_lock(hashtextextended(lock_name,0)) THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-EFFECT-HELD'; END IF;
  END IF;
  IF NEW.reason='PRE_EFFECT_STALE' AND (NEW.state<>'QUARANTINED' OR NEW.charged OR NEW.effect_uncertain
   OR openpc.notification_async_pre_effect_phase(NEW.event_id)<>'STALE_PREPARED')
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PRE-EFFECT-STALE'; END IF;
  IF OLD.effect_uncertain AND NOT NEW.effect_uncertain THEN
   -- This is not a caller boolean. Native proof derives whether the original
   -- effect has actually resolved, and rejects unknown/absent observations.
   IF NEW.state NOT IN ('RETRY_WAIT','DONE','CANCELLED','QUARANTINED')
   THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-UNCERTAINTY'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.retain_notification_async_work_transition() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE record jsonb;payload bytea;operation uuid;
BEGIN
 PERFORM openpc.assert_notification_async_worker_owner();
 operation:=openpc.current_operation_id();
 record:=jsonb_build_object('schema','pc.notification.async-work-transition.v1','operationId',operation,
 'proofEventId',NEW.transition_event_id,
 'before',CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,'after',to_jsonb(NEW));
 payload:=convert_to(openpc.signing_canonical_json(record),'UTF8');
 INSERT INTO control.notification_async_work_transition(participant_id,privacy_domain_id,event_id,revision,operation_id,proof_event_id,transition,transition_bytes,transition_digest,recorded_at_ms)
 VALUES(NEW.participant_id,NEW.privacy_domain_id,NEW.event_id,NEW.revision,operation,NEW.transition_event_id,record,payload,'sha256:'||encode(sha256(payload),'hex'),floor(extract(epoch from clock_timestamp())*1000));
 -- Selector-only call: the proof owner must read back this exact row and join
 -- native authority, source and result custody on this transaction.
 EXECUTE 'select openpc.publish_notification_async_work_proof($1,$2)' USING NEW.event_id,NEW.revision;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_async_transition() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE work control.notification_async_work%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_async_worker_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-TRANSITION-IMMUTABLE'; END IF;
 SELECT * INTO STRICT work FROM control.notification_async_work WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR NEW.operation_id IS DISTINCT FROM openpc.current_operation_id() OR NEW.revision<>work.revision
 OR NEW.proof_event_id IS DISTINCT FROM work.transition_event_id
 OR NEW.transition->>'proofEventId' IS DISTINCT FROM NEW.proof_event_id::text
 OR NEW.transition->'after' IS DISTINCT FROM to_jsonb(work)
 OR NEW.transition IS DISTINCT FROM convert_from(NEW.transition_bytes,'UTF8')::jsonb
 OR convert_to(openpc.signing_canonical_json(NEW.transition),'UTF8') IS DISTINCT FROM NEW.transition_bytes
 OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-TRANSITION'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.deny_notification_async_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-ASYNC-IMMUTABLE'; END $$;
ALTER TABLE control.notification_async_work FORCE ROW LEVEL SECURITY;
ALTER TABLE control.notification_async_work_transition FORCE ROW LEVEL SECURITY;
DROP TRIGGER IF EXISTS notification_async_work_guard ON control.notification_async_work;
CREATE TRIGGER notification_async_work_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_async_work FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_async_work();
DROP TRIGGER IF EXISTS notification_async_work_retain ON control.notification_async_work;
CREATE TRIGGER notification_async_work_retain AFTER INSERT OR UPDATE ON control.notification_async_work FOR EACH ROW EXECUTE FUNCTION openpc.retain_notification_async_work_transition();
DROP TRIGGER IF EXISTS notification_async_transition_guard ON control.notification_async_work_transition;
CREATE TRIGGER notification_async_transition_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_async_work_transition FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_async_transition();
DROP TRIGGER IF EXISTS notification_async_work_no_truncate ON control.notification_async_work;
CREATE TRIGGER notification_async_work_no_truncate BEFORE TRUNCATE ON control.notification_async_work FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_async_truncate();
DROP TRIGGER IF EXISTS notification_async_transition_no_truncate ON control.notification_async_work_transition;
CREATE TRIGGER notification_async_transition_no_truncate BEFORE TRUNCATE ON control.notification_async_work_transition FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_async_truncate();
REVOKE ALL ON control.notification_async_work,control.notification_async_work_transition FROM PUBLIC;
REVOKE ALL ON FUNCTION openpc.assert_notification_async_worker_owner(),openpc.guard_notification_async_work(),openpc.retain_notification_async_work_transition(),openpc.guard_notification_async_transition(),openpc.deny_notification_async_truncate(),openpc.notification_async_pre_effect_phase(uuid),openpc.notification_async_initial_disposition(uuid,text,numeric) FROM PUBLIC;
`;
