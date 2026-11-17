import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const profile = notificationCoseProfiles.NotificationDeliveryOutcomeReceiptV1;
const fields = profile.fields
  .filter((f) => f.name !== 'schemaDefinitionDigest')
  .flatMap((f) => {
    let value;
    if (f.type === 'H32') value = `'sha256:'||(m->'${f.key}'->>'bytes')`;
    else if (f.type === 'uuidv7') value = `(m->'${f.key}'->>'bytes')::uuid::text`;
    else if (f.type === 'safe_uint') value = `(m->>'${f.key}')::numeric`;
    else if (f.type === 'u64p') value = `m->>'${f.key}'`;
    else if (f.type.startsWith('enum '))
      value = `CASE m->>'${f.key}' ${f.type
        .slice(5)
        .split(' ')
        .map((x) => {
          const [n, v] = x.split('=');
          return `WHEN '${v}' THEN '${n}'`;
        })
        .join(' ')} ELSE NULL END`;
    else value = `m->'${f.key}'`;
    return [`'${f.name}'`, value];
  })
  .join(',');
const hash = (x) => `'sha256:'||encode(sha256(${x}),'hex')`;
const jsonHash = (x) => hash(`convert_to(openpc.signing_canonical_json(${x}),'UTF8')`);
const projection = (x) =>
  `jsonb_build_object('participantId',${x}.participant_id::text,'privacyDomainId',${x}.privacy_domain_id::text,'notificationOccurrenceId',${x}.notification_occurrence_id::text,'payloadDigest',${x}.payload_digest,'state',${x}.state,'attemptCount',${x}.attempt_count,'attemptLimit',${x}.attempt_limit,'nextAttemptAtMs',${x}.next_attempt_at_ms,'lastStartedAtMs',${x}.last_started_at_ms,'cancelRequested',${x}.cancel_requested)`;
/** No grants or shared dispatch edits. Canonical installs the explicit shared
 * owner assertion only after outbox, WorkItem source and projection branches,
 * proof constraint/index and these deferred/immutable guards are all enforced.
 * An absent function or failed admission propagates; no registry fallback exists. */
export const notificationOutcomePublicationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_outcome_publication_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_outcome_signing_owner();
 PERFORM openpc.assert_notification_outcome_publication_shared_owners();
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_outcome'::regclass AND tgname='notification_outcome_publication_complete' AND tgfoid='openpc.guard_notification_outcome_publication_complete()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=5 AND tgdeferrable AND tginitdeferred)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_outcome'::regclass AND tgname='notification_outcome_publication_insert' AND tgfoid='openpc.guard_notification_outcome_publication_insert()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=7)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_observation'::regclass AND tgname='notification_outcome_observation_insert' AND tgfoid='openpc.guard_notification_outcome_observation_insert()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=7)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_outcome_publication_receipt(item control.notification_delivery_outcome) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_delivery_outcome_signing%ROWTYPE;m jsonb;r jsonb;t jsonb:=item.transition;o jsonb;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-SCOPE'; END IF;
 SELECT * INTO STRICT s FROM control.notification_delivery_outcome_signing WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.operation_id;
 PERFORM openpc.check_notification_outcome_signing_original(s);
 o:=convert_from(s.observation_bytes,'UTF8')::jsonb;m:=openpc.business_cbor(item.receipt_payload);r:=jsonb_build_object(${fields});
 IF s.state IS DISTINCT FROM 'OBSERVED' OR o->>'outcome' IS DISTINCT FROM 'SIGNED'
 OR item.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(t),'UTF8') OR item.transition_digest IS DISTINCT FROM ${jsonHash('t')}
 OR t IS DISTINCT FROM (s.preparation->'preparation')||jsonb_build_object('schema','pc.notification.delivery-outcome-transition.v1','receipt',r,'payloadHex',s.preparation->'request'->>'payloadHex','coseHex',o->>'coseHex')
 OR item.receipt_payload IS DISTINCT FROM decode(s.preparation->'request'->>'payloadHex','hex') OR item.receipt_digest IS DISTINCT FROM ${hash('item.receipt_payload')}
 OR item.cose_sign1 IS DISTINCT FROM decode(o->>'coseHex','hex') OR item.receipt_id<>s.signing_attempt_id OR item.attempt_id<>s.attempt_id OR item.start_operation_id<>s.start_operation_id
 OR item.notification_occurrence_id<>s.notification_occurrence_id OR item.payload_digest<>s.payload_digest OR item.delivery_revision<>s.delivery_revision
 OR item.signer_installation_digest<>s.signer_installation_digest OR item.worker_installation_digest IS DISTINCT FROM s.preparation->'request'->>'workerInstallationDigest'
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-RECEIPT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_completed_event(e control.outbox_event) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;r jsonb;data jsonb;
BEGIN
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=e.participant_id AND privacy_domain_id=e.privacy_domain_id AND operation_id=e.correlation_id;
 PERFORM openpc.check_notification_outcome_publication_receipt(o);r:=o.transition->'receipt';
 data:=jsonb_build_object('0','urn:openpc:resource:'||o.notification_occurrence_id::text,'1',r->>'afterDeliveryState','2',(r->>'attemptCount')::numeric,'3',openpc.business_bytes(decode(substr(r->>'gatewayCoseDigest',8),'hex')));
 IF (r->>'afterDeliveryState' IN ('DELIVERED','FAILED')) IS DISTINCT FROM true
 OR e.event_id<>o.receipt_id OR e.event_type<>'io.openpc.notification.delivery.completed.v1' OR e.aggregate_type<>'notification-occurrence' OR e.aggregate_id<>o.notification_occurrence_id
 OR e.proof_kind<>'NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' OR e.sequence_namespace<>'NOTIFICATION_DELIVERY_COMPLETED_V1' OR e.business_sequence IS DISTINCT FROM 1
 OR e.aggregate_sequence IS NOT NULL OR e.receipt_id IS NOT NULL OR e.cose_sign1 IS NOT NULL OR e.authority_generation IS NOT NULL OR e.webauthn_assertion_binding_digest IS NOT NULL
 OR e.source IS DISTINCT FROM 'urn:openpc:service:LS-NOTIFICATION' OR e.subject IS DISTINCT FROM 'urn:openpc:resource:'||o.notification_occurrence_id::text
 OR e.data_schema_uri IS DISTINCT FROM 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/NotificationDeliveryCompleted'
 OR e.causation_id::text IS DISTINCT FROM o.transition->'input'->'observation'->'original'->'source'->>'eventId'
 OR extract(epoch from e.occurred_at)*1000 IS DISTINCT FROM (r->>'recordedAtMs')::numeric
 OR e.payload_digest IS DISTINCT FROM sha256(e.payload_cbor) OR openpc.business_cbor(e.payload_cbor) IS DISTINCT FROM data
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-EVENT'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.notification_failure_initial_projection(o control.notification_delivery_outcome) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE w control.installed_notification_worker%ROWTYPE;
BEGIN
 PERFORM openpc.check_notification_outcome_publication_receipt(o);
 IF o.transition->'receipt'->>'afterDeliveryState' IS DISTINCT FROM 'FAILED' THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-NOT-FAILED'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND installation_digest=o.worker_installation_digest;
 RETURN jsonb_build_object('0','DELIVERY_FAILURE','1','OPEN','2','urn:openpc:resource:'||o.notification_occurrence_id::text,'3',openpc.business_bytes(decode(substr(o.receipt_digest,8),'hex')),
 '4',openpc.business_bytes(sha256(convert_to('Notification delivery failed.','UTF8'))),'5',openpc.business_uuid(w.principal_id),'6',0,'8',0,'10',0);
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_failure_work(item control.work_item) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_outcome_publication_owner();
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND receipt_id=item.work_item_id;
 IF item.row_version<>1 OR openpc.work_item_business_projection(item) IS DISTINCT FROM openpc.notification_failure_initial_projection(o)
 OR (SELECT count(*) FROM control.work_item WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND work_item_id=item.work_item_id)<>0
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-FAILURE-WORK'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_outcome_publication_original(operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;first control.notification_delivery_observation%ROWTYPE;e control.outbox_event%ROWTYPE;w control.work_item%ROWTYPE;a control.audit_occurrence%ROWTYPE;native jsonb;expected jsonb;
BEGIN
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 PERFORM openpc.check_notification_outcome_publication_receipt(o);
 SELECT * INTO STRICT first FROM control.notification_delivery_observation WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND attempt_id=o.attempt_id;
 PERFORM openpc.check_notification_delivery_observation_original(first);native:=o.transition->'input'->'observation'->'observation';
 IF first.operation_id<>o.operation_id OR first.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(native),'UTF8') OR first.observation_digest IS DISTINCT FROM ${jsonHash('native')}
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-FIRST'; END IF;
 IF o.transition->'receipt'->>'afterDeliveryState' IN ('DELIVERED','FAILED') THEN
  SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND sequence_namespace='NOTIFICATION_DELIVERY_COMPLETED_V1' AND aggregate_type='notification-occurrence' AND aggregate_id=o.notification_occurrence_id;
  PERFORM openpc.check_notification_delivery_completed_event(e);
  IF e.correlation_id<>o.operation_id THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-EVENT'; END IF;
 ELSIF EXISTS(SELECT 1 FROM control.outbox_event WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND (event_id=o.receipt_id OR (sequence_namespace='NOTIFICATION_DELIVERY_COMPLETED_V1' AND correlation_id=o.operation_id)))
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-UNEXPECTED-EVENT'; END IF;
 IF o.transition->'receipt'->>'afterDeliveryState'='FAILED' THEN
  SELECT * INTO STRICT w FROM control.work_item WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND work_item_id=o.receipt_id;
  IF w.work_item_id<>o.receipt_id THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-WORK-ID'; END IF;
  expected:=openpc.notification_failure_initial_projection(o);
  IF w.row_version=1 THEN
   IF openpc.work_item_business_projection(w) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-WORK-PROJECTION'; END IF;
  ELSE
   -- Later public WorkItem updates retain their first independently admitted
   -- before-state. Do not demand that the current human-owned row stays OPEN.
   SELECT * INTO STRICT a FROM control.audit_occurrence WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND aggregate_type='work-item' AND aggregate_id=w.work_item_id AND before_revision=1;
   IF a.before_existence<>1 OR a.before_state_digest<>sha256(a.before_state_preimage) OR a.receipt_digest<>sha256(a.receipt_cbor)
    OR openpc.business_cbor(a.receipt_cbor)->'18' IS DISTINCT FROM jsonb_build_object('0',1,'1',1,'2',openpc.business_bytes(a.before_state_digest))
    OR openpc.business_cbor(a.before_state_preimage)->8 IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-WORK-PROVENANCE'; END IF;
  END IF;
 ELSIF EXISTS(SELECT 1 FROM control.work_item WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND work_item_id=o.receipt_id)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-UNEXPECTED-WORK'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_outcome_projection(before_row control.notification_delivery,after_row control.notification_delivery) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;r jsonb;expected jsonb;digest text;
BEGIN
 PERFORM openpc.assert_notification_outcome_publication_owner();
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=before_row.participant_id AND privacy_domain_id=before_row.privacy_domain_id AND notification_occurrence_id=before_row.notification_occurrence_id AND delivery_revision=before_row.revision;
 PERFORM openpc.check_notification_outcome_publication_receipt(o);r:=o.transition->'receipt';
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',before_row.revision::text,'projection',${projection('before_row')});digest:=${jsonHash('expected')};
 IF digest IS DISTINCT FROM r->>'beforeStateDigest' OR after_row.revision<>before_row.revision+1
 OR to_jsonb(after_row)-ARRAY['state','attempt_limit','next_attempt_at_ms','revision'] IS DISTINCT FROM to_jsonb(before_row)-ARRAY['state','attempt_limit','next_attempt_at_ms','revision']
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PROJECTION-BEFORE'; END IF;
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',after_row.revision::text,'projection',${projection('after_row')});
 IF ${jsonHash('expected')} IS DISTINCT FROM r->>'afterStateDigest' THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PROJECTION-AFTER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_outcome_publication_complete(operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;d control.notification_delivery%ROWTYPE;expected jsonb;
BEGIN
 PERFORM openpc.check_notification_outcome_publication_original(operation);
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=o.participant_id AND privacy_domain_id=o.privacy_domain_id AND notification_occurrence_id=o.notification_occurrence_id;
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',d.revision::text,'projection',${projection('d')});
 IF d.revision<>o.delivery_revision+1 OR ${jsonHash('expected')} IS DISTINCT FROM o.transition->'receipt'->>'afterStateDigest' THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-INCOMPLETE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_outcome_publication_insert() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_delivery_outcome_signing%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_outcome_publication_owner();PERFORM openpc.check_notification_outcome_publication_receipt(NEW);
 SELECT * INTO STRICT s FROM control.notification_delivery_outcome_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id;
 PERFORM openpc.check_notification_outcome_signing_current(s);
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_outcome_observation_insert() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o control.notification_delivery_outcome%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_outcome_publication_owner();PERFORM openpc.check_notification_delivery_observation_original(NEW);
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=NEW.operation_id;
 PERFORM openpc.check_notification_outcome_publication_receipt(o);
 IF NEW.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(o.transition->'input'->'observation'->'observation'),'UTF8') THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-PUBLICATION-FIRST'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_outcome_publication_complete() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN PERFORM openpc.check_notification_outcome_publication_complete(NEW.operation_id);RETURN NEW;END $$;
DROP TRIGGER IF EXISTS notification_outcome_publication_insert ON control.notification_delivery_outcome;
CREATE TRIGGER notification_outcome_publication_insert BEFORE INSERT ON control.notification_delivery_outcome FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_outcome_publication_insert();
DROP TRIGGER IF EXISTS notification_outcome_observation_insert ON control.notification_delivery_observation;
CREATE TRIGGER notification_outcome_observation_insert BEFORE INSERT ON control.notification_delivery_observation FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_outcome_observation_insert();
DROP TRIGGER IF EXISTS notification_outcome_publication_complete ON control.notification_delivery_outcome;
CREATE CONSTRAINT TRIGGER notification_outcome_publication_complete AFTER INSERT ON control.notification_delivery_outcome DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_outcome_publication_complete();
REVOKE ALL ON FUNCTION openpc.assert_notification_outcome_publication_owner(),openpc.check_notification_outcome_publication_receipt(control.notification_delivery_outcome),openpc.check_notification_delivery_completed_event(control.outbox_event),openpc.notification_failure_initial_projection(control.notification_delivery_outcome),openpc.check_notification_delivery_failure_work(control.work_item),openpc.check_notification_outcome_publication_original(uuid),openpc.check_notification_delivery_outcome_projection(control.notification_delivery,control.notification_delivery),openpc.check_notification_outcome_publication_complete(uuid),openpc.guard_notification_outcome_publication_insert(),openpc.guard_notification_outcome_observation_insert(),openpc.guard_notification_outcome_publication_complete() FROM PUBLIC;
`;
