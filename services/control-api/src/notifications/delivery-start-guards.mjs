import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const key = (profile, name) => {
  const field = profile.fields.find((p) => p.name === name);
  if (!field) throw new Error('Notification budget profile field missing');
  return field.key;
};
const request = notificationCoseProfiles.NotificationDeliveryRequestedReceiptV1;
const worker = notificationCoseProfiles.NotificationWorkerProfileV1;
const channel = notificationCoseProfiles.NotificationChannelProfileV1;
const claim = (object, profile, name) => `${object}->'${key(profile, name)}'`;
const number = (object, profile, name) => `(${object}->>'${key(profile, name)}')::numeric`;
const budgetColumns = [
  'attempt_limit',
  'revision',
  'budget_generation_id',
  'budget_effective_digest',
  'budget_configured_limit',
  'budget_worker_installation_digest',
];

/** Canonical registration must install this substantive guard after its source,
 * installation and operations owners. It grants no role privileges and registers
 * no new event/signature family. STARTED additionally requires the atomic owner. */
export const notificationDeliveryBudgetGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_budget_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin'
 OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_delivery'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery'::regclass
   AND tgname='notification_delivery_budget_guard' AND tgenabled IN ('O','A')
   AND tgfoid='openpc.guard_notification_delivery_budget()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery'::regclass
   AND tgname='notification_delivery_budget_truncate_guard' AND tgenabled IN ('O','A')
   AND tgfoid='openpc.deny_notification_delivery_effect()'::regprocedure)
 THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-UNAVAILABLE'; END IF;
 -- Installation-only checks avoid atomic -> signing -> preparation -> budget recursion.
 PERFORM openpc.assert_notification_delivery_start_atomic_guards();
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_budget() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE occurrence control.notification_occurrence%ROWTYPE; event control.outbox_event%ROWTYPE;
 proof control.notification_occurrence_observation%ROWTYPE; w control.installed_notification_worker%ROWTYPE;
 installed control.installed_notification_channel%ROWTYPE; ep control.notification_endpoint%ROWTYPE;
 actual record; m jsonb; wm jsonb; cm jsonb; now_ms numeric; lock_name text;
BEGIN
 PERFORM openpc.assert_notification_delivery_budget_owner();
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-EFFECT-CLOSED'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- Restricting an existing request uses its signed historical endpoint cause,
 -- not a still-enabled endpoint or a currently effective send budget.
 IF TG_OP='UPDATE' AND NOT OLD.cancel_requested AND NEW.cancel_requested THEN
  PERFORM openpc.check_notification_delivery_cancellation_projection(OLD,NEW);
  RETURN NEW;
 END IF;
 -- Presence selects the immutable outcome family only. Its full checker binds
 -- the actual OLD/NEW rows and current publication authority.
 IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM control.notification_delivery_outcome o
  WHERE o.participant_id=OLD.participant_id AND o.privacy_domain_id=OLD.privacy_domain_id
   AND o.notification_occurrence_id=OLD.notification_occurrence_id AND o.delivery_revision=OLD.revision) THEN
  PERFORM openpc.check_notification_delivery_outcome_projection(OLD,NEW);
  RETURN NEW;
 END IF;
 -- SQL admission requires the transaction-owned fences held by the real worker
 -- composition. Lock presence is a prerequisite, never a replacement TLS proof.
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||NEW.participant_id::text,
   'notification-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,
   'notification-installation:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted
    AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
    AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid
    AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
    AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-FENCE'; END IF;
 END LOOP;
 SELECT * INTO STRICT occurrence FROM control.notification_occurrence WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND notification_occurrence_id=NEW.notification_occurrence_id;
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.delivery_request_event_id;
 PERFORM openpc.check_notification_delivery_requested_event(event);
 SELECT * INTO STRICT proof FROM control.notification_occurrence_observation WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.delivery_request_operation_id;
 m:=openpc.business_cbor(proof.receipt_payload);
 IF event.aggregate_id IS DISTINCT FROM NEW.notification_occurrence_id
 OR event.correlation_id IS DISTINCT FROM NEW.delivery_request_operation_id
 OR event.event_id IS DISTINCT FROM NEW.delivery_request_event_id
 OR occurrence.payload_digest IS DISTINCT FROM NEW.payload_digest
 OR ${claim('m', request, 'notificationOccurrenceId')} IS DISTINCT FROM openpc.business_uuid(NEW.notification_occurrence_id)
 OR ${claim('m', request, 'eventId')} IS DISTINCT FROM openpc.business_uuid(NEW.delivery_request_event_id)
 OR ${claim('m', request, 'operationId')} IS DISTINCT FROM openpc.business_uuid(NEW.delivery_request_operation_id)
 OR m->>'${key(request, 'environmentId')}' IS DISTINCT FROM NEW.budget_environment_id
 THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-SOURCE'; END IF;
 SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit(m->>'${key(request, 'environmentId')}');
 IF NEW.budget_generation_id IS DISTINCT FROM actual.generation_id
 OR NEW.budget_effective_digest IS DISTINCT FROM actual.effective_digest
 OR NEW.budget_configured_limit IS DISTINCT FROM actual.configured_limit
 THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-CONFIGURATION'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND installation_digest=NEW.budget_worker_installation_digest;
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF w.state<>'ACTIVE' OR w.service_id<>'LS-NOTIFICATION'
 OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR w.installation->'pins'->>'processRole' IS DISTINCT FROM 'ROLE-NOTIFICATION-WORKER'
 OR w.installation->'pins'->>'environmentId' IS DISTINCT FROM NEW.budget_environment_id
 OR ${claim('wm', worker, 'routingProfileDigest')} IS DISTINCT FROM ${claim('m', request, 'routingProfileDigest')}
 OR now_ms<${number('wm', worker, 'validFromMs')} OR now_ms>=${number('wm', worker, 'validUntilMs')}
 OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p USING(participant_id,principal_id)
  JOIN control.participant t USING(participant_id) JOIN control.privacy_domain d USING(participant_id)
  WHERE c.participant_id=NEW.participant_id AND d.privacy_domain_id=NEW.privacy_domain_id
   AND c.credential_id=w.workload_credential_id AND p.principal_id=w.principal_id
   AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND p.kind='WORKLOAD' AND p.state='ACTIVE' AND t.state='ACTIVE' AND d.state='ACTIVE'
   AND c.credential_epoch::text=w.installation->'pins'->>'workloadEpoch'
   AND c.audience=w.installation->'pins'->>'workloadId'
   AND 'sha256:'||encode(c.public_key_digest,'hex')=w.installation->'pins'->>'workloadKeyDigest'
   AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-WORKER'; END IF;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND endpoint_id=occurrence.endpoint_id FOR SHARE;
 SELECT * INTO STRICT installed FROM control.installed_notification_channel WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND credential_ref=occurrence.credential_ref;
 cm:=openpc.business_cbor(decode(installed.channel_signed->>'payloadHex','hex'));
 IF ep.state<>'ACTIVE' OR ep.revision IS DISTINCT FROM occurrence.endpoint_revision
 OR ep.verification_id IS DISTINCT FROM occurrence.verification_id
 OR ep.credential_ref IS DISTINCT FROM occurrence.credential_ref
 OR ep.channel IS DISTINCT FROM occurrence.channel OR ep.destination_ref IS DISTINCT FROM occurrence.destination_ref
 OR ep.channel_profile_digest IS DISTINCT FROM occurrence.channel_profile_digest
 OR installed.state<>'ACTIVE' OR installed.channel_profile_digest IS DISTINCT FROM occurrence.channel_profile_digest
 OR installed.channel IS DISTINCT FROM ep.channel OR installed.destination_ref IS DISTINCT FROM ep.destination_ref
 OR installed.credential->>'state' IS DISTINCT FROM 'ACTIVE'
 OR (installed.credential->>'validFromMs')::numeric>now_ms OR (installed.credential->>'validUntilMs')::numeric<=now_ms
 OR cm->>'${key(channel, 'environmentId')}' IS DISTINCT FROM NEW.budget_environment_id
 OR now_ms<${number('cm', channel, 'validFromMs')} OR now_ms>=${number('cm', channel, 'validUntilMs')}
 OR NOT EXISTS(SELECT 1 FROM control.notification_endpoint_verification v WHERE v.participant_id=ep.participant_id
   AND v.privacy_domain_id=ep.privacy_domain_id AND v.verification_id=ep.verification_id
   AND v.endpoint_id=ep.endpoint_id AND v.endpoint_revision=ep.revision AND v.channel=ep.channel
   AND v.destination_ref=ep.destination_ref AND v.channel_profile_digest=ep.channel_profile_digest AND v.credential_ref=ep.credential_ref)
 OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal p USING(participant_id,principal_id)
   WHERE c.participant_id=NEW.participant_id AND c.credential_id=installed.workload_credential_id
   AND p.principal_id=installed.principal_id AND p.kind='WORKLOAD' AND p.state='ACTIVE'
   AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch=installed.workload_epoch
   AND c.audience=installed.workload_id AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-ENDPOINT'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PENDING' OR NEW.attempt_count<>0 OR NEW.attempt_limit<>least(actual.configured_limit,6)
   OR NEW.revision<>1 OR NEW.cancel_requested OR NEW.last_started_at_ms IS NOT NULL
   OR NEW.next_attempt_at_ms IS DISTINCT FROM floor(extract(epoch from statement_timestamp())*1000)
  THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-INITIAL'; END IF;
 ELSIF NEW.state='STARTED' AND OLD.state IN ('PENDING','RETRY_WAIT') THEN
  PERFORM openpc.check_notification_delivery_start_projection(OLD,NEW);
 ELSE
  IF NEW.attempt_limit IS DISTINCT FROM least(OLD.attempt_limit,actual.configured_limit,6)
   OR NEW.attempt_limit>=OLD.attempt_limit OR NEW.revision<>OLD.revision+1
   OR to_jsonb(NEW)-ARRAY[${budgetColumns.map((p) => `'${p}'`).join(',')}] IS DISTINCT FROM
      to_jsonb(OLD)-ARRAY[${budgetColumns.map((p) => `'${p}'`).join(',')}]
  THEN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-BUDGET-ONLY'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_effect() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-DELIVERY-EFFECT-CLOSED'; END $$;
DROP TRIGGER IF EXISTS notification_delivery_budget_guard ON control.notification_delivery;
CREATE TRIGGER notification_delivery_budget_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_delivery
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_budget();
DROP TRIGGER IF EXISTS notification_delivery_budget_truncate_guard ON control.notification_delivery;
CREATE TRIGGER notification_delivery_budget_truncate_guard BEFORE TRUNCATE ON control.notification_delivery
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_effect();
-- The attempt declaration may be registered with the future STARTED receipt. If
-- already present it must remain closed, including statement-level empty writes.
DO $$ BEGIN
 IF to_regclass('control.notification_delivery_attempt') IS NOT NULL THEN
  EXECUTE 'DROP TRIGGER IF EXISTS notification_delivery_attempt_closed ON control.notification_delivery_attempt';
  EXECUTE 'CREATE TRIGGER notification_delivery_attempt_closed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_attempt FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_effect()';
 END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_budget_owner(),openpc.guard_notification_delivery_budget(),openpc.deny_notification_delivery_effect() FROM PUBLIC;
`;
