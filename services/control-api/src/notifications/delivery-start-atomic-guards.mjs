import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const profile = notificationCoseProfiles.NotificationDeliveryStartedReceiptV1;
const claims = `jsonb_build_object(${profile.fields
  .filter((f) => f.name !== 'schemaDefinitionDigest')
  .flatMap((f) => [
    `'${f.name}'`,
    f.type === 'uuidv7'
      ? `(m->'${f.key}'->>'bytes')::uuid::text`
      : f.type === 'H32'
        ? `'sha256:'||(m->'${f.key}'->>'bytes')`
        : f.type === 'safe_uint'
          ? `(m->>'${f.key}')::numeric`
          : f.type === 'u64p'
            ? `m->>'${f.key}'`
            : `m->'${f.key}'`,
  ])
  .join(',')})`;
const hash = (x) =>
  `'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${x}),'UTF8')),'hex')`;
const budgetKeys =
  "ARRAY['revision','deliveryRequestEventId','deliveryRequestOperationId','budgetEnvironmentId','budgetGenerationId','budgetEffectiveDigest','budgetConfiguredLimit','budgetWorkerInstallationDigest']";
const projection = (r) =>
  `jsonb_build_object('participantId',${r}.participant_id::text,'privacyDomainId',${r}.privacy_domain_id::text,'notificationOccurrenceId',${r}.notification_occurrence_id::text,'payloadDigest',${r}.payload_digest,'state',${r}.state,'attemptCount',${r}.attempt_count,'attemptLimit',${r}.attempt_limit,'nextAttemptAtMs',${r}.next_attempt_at_ms,'lastStartedAtMs',${r}.last_started_at_ms,'cancelRequested',${r}.cancel_requested)`;
/** Additive declarations only. Canonical must compose the projection hook into
 * the budget guard and replace its closed-attempt requirement atomically with
 * these installed guard checks. No claim/send/consumer entrypoint is opened. */
export const notificationDeliveryStartAtomicGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_start_atomic_guards() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE table_name text; trigger_name text; function_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['notification_delivery_start','notification_delivery_attempt','notification_delivery_dispatch_intent'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=('control.'||table_name)::regclass AND relrowsecurity AND relforcerowsecurity)
  THEN RAISE EXCEPTION 'NOTIFICATION-START-OWNER'; END IF;
  trigger_name:=table_name||'_atomic_guard'; function_name:='openpc.guard_'||table_name||'_atomic()';
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=('control.'||table_name)::regclass AND tgname=trigger_name AND tgtype=7 AND tgenabled IN ('O','A') AND tgfoid=function_name::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=('control.'||table_name)::regclass AND tgname=table_name||'_atomic_immutable' AND tgtype=CASE WHEN table_name='notification_delivery_dispatch_intent' THEN 42 ELSE 58 END AND tgenabled IN ('O','A') AND tgfoid='openpc.deny_notification_delivery_start_atomic_mutation()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=('control.'||table_name)::regclass AND tgname=table_name||'_complete' AND tgtype=CASE WHEN table_name='notification_delivery_dispatch_intent' THEN 21 ELSE 5 END AND tgenabled IN ('O','A') AND tgdeferrable AND tginitdeferred AND tgfoid='openpc.guard_notification_delivery_start_complete()'::regprocedure)
  THEN RAISE EXCEPTION 'NOTIFICATION-START-OWNER'; END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_dispatch_intent'::regclass AND tgname='notification_delivery_dispatch_claim_guard' AND tgtype=19 AND tgenabled IN ('O','A') AND tgfoid='openpc.guard_notification_delivery_dispatch_claim()'::regprocedure) THEN RAISE EXCEPTION 'NOTIFICATION-START-OWNER'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery'::regclass AND tgname='notification_delivery_start_complete' AND tgtype=17 AND tgenabled IN ('O','A') AND tgdeferrable AND tginitdeferred AND tgfoid='openpc.guard_notification_delivery_start_complete()'::regprocedure)
 THEN RAISE EXCEPTION 'NOTIFICATION-START-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_start_atomic_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_signing_owner();
 PERFORM openpc.assert_notification_delivery_start_atomic_guards();
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_start_original(item control.notification_delivery_start) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE signing control.notification_delivery_signing%ROWTYPE;p jsonb;t jsonb:=item.transition;m jsonb;expected jsonb;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-START-SCOPE'; END IF;
 SELECT * INTO STRICT signing FROM control.notification_delivery_signing WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.operation_id;
 p:=signing.preparation->'deliveryPreparation';m:=openpc.business_cbor(item.receipt_payload);
 IF signing.state<>'OBSERVED' OR signing.observation->>'outcome' IS DISTINCT FROM 'SIGNED'
 OR item.receipt_id IS DISTINCT FROM signing.signing_attempt_id OR item.attempt_id::text IS DISTINCT FROM p->'attempt'->>'attemptId'
 OR item.notification_occurrence_id::text IS DISTINCT FROM p->'source'->>'notificationOccurrenceId' OR item.payload_digest IS DISTINCT FROM p->'attempt'->>'payloadDigest'
 OR item.delivery_revision::text IS DISTINCT FROM p->'before'->>'revision' OR item.source_operation_id::text IS DISTINCT FROM p->>'sourceOperationId'
 OR item.worker_installation_digest IS DISTINCT FROM p->'source'->'worker'->>'installationDigest'
 OR item.receipt_payload IS DISTINCT FROM decode(signing.preparation->'request'->>'payloadHex','hex')
 OR item.cose_sign1 IS DISTINCT FROM decode(signing.observation->>'coseHex','hex')
 OR item.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(item.receipt_payload),'hex')
 OR item.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(t),'UTF8') OR item.transition_digest IS DISTINCT FROM ${hash('t')}
 THEN RAISE EXCEPTION 'NOTIFICATION-START-ORIGINAL'; END IF;
 expected:=jsonb_build_object('schema','pc.notification.delivery-start-transition.v1','sourceOperationId',p->'sourceOperationId',
 'workerInstallation',signing.preparation->'trust'->'worker','workerInstallationDigest',p->'source'->'worker'->'installationDigest','workerAuthorityDigest',p->'authorityDigest',
 'receipt',${claims},'source',signing.preparation->'sourceClaims','channel',p->'channel','attempt',p->'attempt','context',p->'context',
 'before',(p->'before')-${budgetKeys},'after',p->'plannedAfter','configuredLimit',p->'configuredLimit','payloadHex',encode(item.receipt_payload,'hex'),'coseHex',encode(item.cose_sign1,'hex'));
 IF t IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NOTIFICATION-START-TRANSITION'; END IF;
 PERFORM openpc.archive_cose_binding(item.receipt_payload,item.cose_sign1,signing.preparation->'request'->>'signerKeyId',${profile.schemaId},${profile.purposeCode});
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_start_atomic() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE signing control.notification_delivery_signing%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_start_atomic_owner();
 PERFORM openpc.check_notification_delivery_start_original(NEW);
 SELECT * INTO STRICT signing FROM control.notification_delivery_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id FOR UPDATE;
 PERFORM openpc.check_notification_delivery_signing_current(signing);
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_attempt_atomic() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE start control.notification_delivery_start%ROWTYPE;p jsonb;
BEGIN
 PERFORM openpc.assert_notification_delivery_start_atomic_owner();
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.start_operation_id;
 PERFORM openpc.check_notification_delivery_start_original(start);p:=start.transition;
 IF NEW.attempt_id IS DISTINCT FROM start.attempt_id OR NEW.notification_occurrence_id IS DISTINCT FROM start.notification_occurrence_id OR NEW.payload_digest IS DISTINCT FROM start.payload_digest
 OR to_jsonb(NEW.attempt_number) IS DISTINCT FROM p->'attempt'->'attemptNumber' OR to_jsonb(NEW.started_at_ms) IS DISTINCT FROM p->'attempt'->'startedAtMs'
 OR NEW.worker_credential_id::text IS DISTINCT FROM p->'context'->>'authorizationContextId' OR NEW.worker_credential_epoch::numeric IS DISTINCT FROM (p->'context'->>'authorizationContextEpoch')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-START-ATTEMPT'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_dispatch_intent_original(item control.notification_delivery_dispatch_intent) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE start control.notification_delivery_start%ROWTYPE;
BEGIN
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.operation_id;
 PERFORM openpc.check_notification_delivery_start_original(start);
 IF item.attempt_id IS DISTINCT FROM start.attempt_id OR item.notification_occurrence_id IS DISTINCT FROM start.notification_occurrence_id OR item.payload_digest IS DISTINCT FROM start.payload_digest
 OR item.delivery_revision IS DISTINCT FROM start.delivery_revision+1 OR item.receipt_digest IS DISTINCT FROM start.receipt_digest
 OR ((item.state='PENDING' AND item.claim_token IS NULL AND item.claimed_at_ms IS NULL)
  OR (item.state='CLAIMED' AND item.claim_token IS NOT NULL AND item.claim_token ~ '^[0-9a-f]{64}$' AND item.claimed_at_ms IS NOT NULL AND item.claimed_at_ms BETWEEN 0 AND 9007199254740991
   AND item.claimed_at_ms >= (start.transition->'attempt'->>'startedAtMs')::numeric AND item.claimed_at_ms < (start.transition->'attempt'->>'deadlineAtMs')::numeric)) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'NOTIFICATION-START-INTENT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_dispatch_intent_atomic() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_start_atomic_owner();
 PERFORM openpc.check_notification_delivery_dispatch_intent_original(NEW);
 IF NEW.state<>'PENDING' THEN RAISE EXCEPTION 'NOTIFICATION-START-INTENT'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_start_projection(before_row control.notification_delivery,after_row control.notification_delivery) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE start control.notification_delivery_start%ROWTYPE;signing control.notification_delivery_signing%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_start_atomic_owner();
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=before_row.participant_id AND privacy_domain_id=before_row.privacy_domain_id AND notification_occurrence_id=before_row.notification_occurrence_id AND delivery_revision=before_row.revision;
 PERFORM openpc.check_notification_delivery_start_original(start);
 SELECT * INTO STRICT signing FROM control.notification_delivery_signing WHERE participant_id=start.participant_id AND privacy_domain_id=start.privacy_domain_id AND operation_id=start.operation_id;
 PERFORM openpc.check_notification_delivery_signing_current(signing);
 IF ${projection('before_row')} IS DISTINCT FROM start.transition->'before' OR ${projection('after_row')} IS DISTINCT FROM start.transition->'after'
 OR after_row.revision IS DISTINCT FROM before_row.revision+1
 OR to_jsonb(after_row)-ARRAY['state','attempt_count','last_started_at_ms','next_attempt_at_ms','revision'] IS DISTINCT FROM to_jsonb(before_row)-ARRAY['state','attempt_count','last_started_at_ms','next_attempt_at_ms','revision']
 THEN RAISE EXCEPTION 'NOTIFICATION-START-PROJECTION'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_start_complete(operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE start control.notification_delivery_start%ROWTYPE;a control.notification_delivery_attempt%ROWTYPE;d control.notification_delivery%ROWTYPE;i control.notification_delivery_dispatch_intent%ROWTYPE;
BEGIN
 -- Deferred checks run after the application restores its original action. All
 -- live admissions ran before mutation; this check grants no fresh authority.
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 PERFORM openpc.check_notification_delivery_start_original(start);
 SELECT * INTO STRICT a FROM control.notification_delivery_attempt WHERE participant_id=start.participant_id AND privacy_domain_id=start.privacy_domain_id AND start_operation_id=start.operation_id;
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=start.participant_id AND privacy_domain_id=start.privacy_domain_id AND notification_occurrence_id=start.notification_occurrence_id;
 SELECT * INTO STRICT i FROM control.notification_delivery_dispatch_intent WHERE participant_id=start.participant_id AND privacy_domain_id=start.privacy_domain_id AND operation_id=start.operation_id;
 IF a.attempt_id IS DISTINCT FROM start.attempt_id OR a.notification_occurrence_id IS DISTINCT FROM start.notification_occurrence_id OR a.payload_digest IS DISTINCT FROM start.payload_digest
 OR to_jsonb(a.attempt_number) IS DISTINCT FROM start.transition->'attempt'->'attemptNumber' OR to_jsonb(a.started_at_ms) IS DISTINCT FROM start.transition->'attempt'->'startedAtMs'
 OR a.worker_credential_id::text IS DISTINCT FROM start.transition->'context'->>'authorizationContextId' OR a.worker_credential_epoch::numeric IS DISTINCT FROM (start.transition->'context'->>'authorizationContextEpoch')::numeric
 OR d.revision IS DISTINCT FROM start.delivery_revision+1 OR ${projection('d')} IS DISTINCT FROM start.transition->'after'
 OR i.attempt_id IS DISTINCT FROM start.attempt_id OR i.notification_occurrence_id IS DISTINCT FROM start.notification_occurrence_id OR i.payload_digest IS DISTINCT FROM start.payload_digest
 OR i.delivery_revision IS DISTINCT FROM d.revision OR i.receipt_digest IS DISTINCT FROM start.receipt_digest
 THEN RAISE EXCEPTION 'NOTIFICATION-START-INCOMPLETE'; END IF;
 PERFORM openpc.check_notification_delivery_dispatch_intent_original(i);
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_start_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE operation uuid;
BEGIN
 IF TG_TABLE_NAME='notification_delivery' THEN
  IF NEW.state<>'STARTED' OR OLD.state='STARTED' THEN RETURN NULL; END IF;
  SELECT operation_id INTO STRICT operation FROM control.notification_delivery_start WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND notification_occurrence_id=NEW.notification_occurrence_id AND delivery_revision=OLD.revision;
 ELSIF TG_TABLE_NAME='notification_delivery_attempt' THEN operation:=NEW.start_operation_id;
 ELSE operation:=NEW.operation_id;
 END IF;
 PERFORM openpc.check_notification_delivery_start_complete(operation);RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_start_atomic_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-START-IMMUTABLE'; END $$;
${[
  'notification_delivery_start',
  'notification_delivery_attempt',
  'notification_delivery_dispatch_intent',
]
  .map(
    (t) => `
DROP TRIGGER IF EXISTS ${t}_atomic_guard ON control.${t};
CREATE TRIGGER ${t}_atomic_guard BEFORE INSERT ON control.${t} FOR EACH ROW EXECUTE FUNCTION openpc.guard_${t}_atomic();
DROP TRIGGER IF EXISTS ${t}_atomic_immutable ON control.${t};
CREATE TRIGGER ${t}_atomic_immutable BEFORE ${t === 'notification_delivery_dispatch_intent' ? '' : 'UPDATE OR '}DELETE OR TRUNCATE ON control.${t} FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_start_atomic_mutation();
DROP TRIGGER IF EXISTS ${t}_complete ON control.${t};
CREATE CONSTRAINT TRIGGER ${t}_complete AFTER INSERT${t === 'notification_delivery_dispatch_intent' ? ' OR UPDATE' : ''} ON control.${t} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_start_complete();`,
  )
  .join('\n')}
DROP TRIGGER IF EXISTS notification_delivery_start_complete ON control.notification_delivery;
CREATE CONSTRAINT TRIGGER notification_delivery_start_complete AFTER UPDATE ON control.notification_delivery DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_start_complete();
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_start_atomic_guards(),openpc.assert_notification_delivery_start_atomic_owner(),openpc.check_notification_delivery_start_original(control.notification_delivery_start),openpc.guard_notification_delivery_start_atomic(),openpc.guard_notification_delivery_attempt_atomic(),openpc.guard_notification_delivery_dispatch_intent_atomic(),openpc.check_notification_delivery_dispatch_intent_original(control.notification_delivery_dispatch_intent),openpc.check_notification_delivery_start_projection(control.notification_delivery,control.notification_delivery),openpc.check_notification_delivery_start_complete(uuid),openpc.guard_notification_delivery_start_complete(),openpc.deny_notification_delivery_start_atomic_mutation() FROM PUBLIC;
`;
