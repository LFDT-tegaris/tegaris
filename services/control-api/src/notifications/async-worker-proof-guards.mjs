/** Prepared registration only. Install with the frozen feature guards and real
 * native custody owner; this module grants no worker/table access and supplies
 * no replacement for assert_notification_async_work_current. Operational events
 * reference immutable transitions, never claim a signed business/delivery result.
 * This distinct internal schema uses canonical UTF-8 JSON in the shared payload
 * byte column, as configuration events do; it does not use a receipt CBOR profile.
 */
export const notificationAsyncWorkProof = Object.freeze({
  kind: 'NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE',
  namespace: 'NOTIFICATION_ASYNC_WORK_TRANSITION_V1',
  eventType: 'io.openpc.notification.async-work.transitioned.v1',
  schema: 'urn:openpc:internal:notification-async-work-transition:v1',
});
const proof = notificationAsyncWorkProof;
/** PREPARED insert dispatch. Compose into the shared outbox owner only together
 * with the frozen feature guards, proof schema and real native current owner.
 * Merely importing this declaration never changes the installed/default guard. */
export const notificationAsyncWorkOutboxAdmissionSql = `
 -- Operational scheduling transitions have their own protected source and
 -- current native admission. Historical proof checks never open this insert.
 IF NEW.proof_kind='NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE' THEN
  PERFORM openpc.admit_notification_async_work_event(NEW);
  RETURN NEW;
 END IF;
`;
/** Historical shape only: current time, endpoint state and native execution
 * authority belong to live INSERT admission. Export the exact predicate for the
 * existing real SQL regression; it is not a second proof or admission owner. */
export const notificationAsyncInitialProofInvalidSql = `
 item.transition->'before' IS DISTINCT FROM 'null'::jsonb
 OR after_row.revision IS DISTINCT FROM 1 OR after_row.lease_epoch IS DISTINCT FROM 0
 OR after_row.lease_owner IS NOT NULL OR after_row.lease_until_ms IS NOT NULL
 OR after_row.charged IS DISTINCT FROM false OR after_row.effect_uncertain IS DISTINCT FROM false
 OR after_row.original IS NOT NULL OR after_row.next_at_ms IS NOT NULL
 OR ((after_row.state='PENDING' AND after_row.reason IS NULL)
  OR (after_row.state='QUARANTINED' AND after_row.reason IN ('INITIAL_DOMAIN_DEADLINE','INITIAL_SOURCE_WITHDRAWN'))) IS NOT TRUE
`;
export const notificationAsyncWorkProofGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.read_notification_async_work_transition(source_event uuid,source_revision numeric)
RETURNS control.notification_async_work_transition
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_async_work_transition%ROWTYPE;prior control.notification_async_work_transition%ROWTYPE;
 after_row control.notification_async_work%ROWTYPE;source control.outbox_event%ROWTYPE;expected jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR source_event IS NULL OR source_revision IS NULL OR source_revision<>trunc(source_revision)
 OR source_revision NOT BETWEEN 1 AND 18446744073709551615
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-CONTEXT'; END IF;
 SELECT * INTO STRICT item FROM control.notification_async_work_transition
 WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id()
 AND event_id=source_event AND revision=source_revision;
 SELECT * INTO STRICT after_row FROM jsonb_populate_record(NULL::control.notification_async_work,item.transition->'after');
 expected:=jsonb_build_object('schema','pc.notification.async-work-transition.v1','operationId',item.operation_id,
 'proofEventId',item.proof_event_id,'before',item.transition->'before','after',to_jsonb(after_row));
 IF item.transition IS DISTINCT FROM expected
 OR item.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(expected),'UTF8')
 OR item.transition_digest IS DISTINCT FROM 'sha256:'||encode(sha256(item.transition_bytes),'hex')
 OR after_row.participant_id IS DISTINCT FROM item.participant_id OR after_row.privacy_domain_id IS DISTINCT FROM item.privacy_domain_id
 OR after_row.event_id IS DISTINCT FROM item.event_id OR after_row.revision IS DISTINCT FROM item.revision
 OR after_row.transition_event_id IS DISTINCT FROM item.proof_event_id
 OR item.proof_event_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 OR item.operation_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-TRANSITION'; END IF;
 IF item.revision=1 THEN
  IF ${notificationAsyncInitialProofInvalidSql}
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-INITIAL'; END IF;
 ELSE
  SELECT * INTO STRICT prior FROM control.notification_async_work_transition
  WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id
  AND event_id=item.event_id AND revision=item.revision-1;
  IF prior.transition->'after' IS DISTINCT FROM item.transition->'before'
  OR prior.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(prior.transition),'UTF8')
  OR prior.transition_digest IS DISTINCT FROM 'sha256:'||encode(sha256(prior.transition_bytes),'hex')
  OR NOT EXISTS(SELECT 1 FROM control.outbox_event WHERE participant_id=prior.participant_id AND privacy_domain_id=prior.privacy_domain_id
   AND event_id=prior.proof_event_id AND aggregate_id=prior.event_id AND business_sequence=prior.revision
   AND proof_kind='${proof.kind}' AND sequence_namespace='${proof.namespace}')
  THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-PREDECESSOR'; END IF;
 END IF;
 SELECT * INTO STRICT source FROM control.outbox_event WHERE participant_id=item.participant_id
 AND privacy_domain_id=item.privacy_domain_id AND event_id=item.event_id;
 -- This existing checker verifies ORIGINAL receipt/source/custody. It does not
 -- renew authority or require today's async execution/process qualification.
 PERFORM openpc.check_notification_delivery_requested_event(source);
 IF source.aggregate_id IS DISTINCT FROM after_row.notification_occurrence_id
 OR source.aggregate_type IS DISTINCT FROM 'notification-occurrence'
 OR source.business_sequence IS DISTINCT FROM after_row.sequence
 OR after_row.partition IS DISTINCT FROM source.aggregate_type||':'||source.aggregate_id::text
 OR after_row.source_digest IS DISTINCT FROM 'sha256:'||encode(source.payload_digest,'hex')
 OR after_row.published_at_ms IS DISTINCT FROM floor(extract(epoch from source.occurred_at)*1000)
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-SOURCE'; END IF;
 RETURN item;
END $$;

CREATE OR REPLACE FUNCTION openpc.notification_async_work_event_bytes(item control.notification_async_work_transition)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT convert_to(openpc.signing_canonical_json(jsonb_build_object(
  'schema','${proof.schema}','participantId',item.participant_id,'privacyDomainId',item.privacy_domain_id,
  'sourceEventId',item.event_id,'proofEventId',item.proof_event_id,'operationId',item.operation_id,
  'revision',item.revision::text,'transitionDigest',item.transition_digest,
  'notificationOccurrenceId',item.transition->'after'->>'notification_occurrence_id',
  'beforeState',item.transition->'before'->'state','afterState',item.transition->'after'->'state')),'UTF8')
$$;

CREATE OR REPLACE FUNCTION openpc.check_notification_async_work_event(event control.outbox_event)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_async_work_transition%ROWTYPE;payload bytea;
BEGIN
 IF event.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR event.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-SCOPE'; END IF;
 item:=openpc.read_notification_async_work_transition(event.aggregate_id,event.business_sequence);
 payload:=openpc.notification_async_work_event_bytes(item);
 IF event.event_id IS DISTINCT FROM item.proof_event_id OR event.event_type IS DISTINCT FROM '${proof.eventType}'
 OR event.aggregate_type IS DISTINCT FROM 'notification-async-work'
 OR event.proof_kind IS DISTINCT FROM '${proof.kind}' OR event.sequence_namespace IS DISTINCT FROM '${proof.namespace}'
 OR event.aggregate_sequence IS NOT NULL OR event.receipt_id IS NOT NULL OR event.cose_sign1 IS NOT NULL
 OR event.authority_generation IS NOT NULL OR event.webauthn_assertion_binding_digest IS NOT NULL
 OR event.source IS DISTINCT FROM 'urn:openpc:service:LS-NOTIFICATION'
 OR event.subject IS DISTINCT FROM 'urn:openpc:resource:'||item.event_id::text
 OR event.data_schema_uri IS DISTINCT FROM '${proof.schema}'
 OR event.correlation_id IS DISTINCT FROM item.operation_id OR event.causation_id IS DISTINCT FROM item.event_id
 OR event.payload_cbor IS DISTINCT FROM payload OR event.payload_digest IS DISTINCT FROM sha256(payload)
 OR extract(epoch from event.occurred_at)*1000 IS DISTINCT FROM item.recorded_at_ms
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-EVENT'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.check_notification_async_work_proof(source_event uuid,source_revision numeric)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_async_work_transition%ROWTYPE;event control.outbox_event%ROWTYPE;
BEGIN
 item:=openpc.read_notification_async_work_transition(source_event,source_revision);
 SELECT * INTO STRICT event FROM control.outbox_event WHERE participant_id=item.participant_id
 AND privacy_domain_id=item.privacy_domain_id AND event_id=item.proof_event_id;
 PERFORM openpc.check_notification_async_work_event(event);
 IF (SELECT count(*) FROM control.outbox_event WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id
  AND aggregate_id=item.event_id AND business_sequence=item.revision AND sequence_namespace='${proof.namespace}')<>1
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-CARDINALITY'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.admit_notification_async_work_event(event control.outbox_event)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_async_work_transition%ROWTYPE;work control.notification_async_work%ROWTYPE;
BEGIN
 PERFORM openpc.check_notification_async_work_event(event);
 item:=openpc.read_notification_async_work_transition(event.aggregate_id,event.business_sequence);
 PERFORM openpc.assert_notification_async_worker_owner();
 SELECT * INTO STRICT work FROM control.notification_async_work WHERE participant_id=item.participant_id
 AND privacy_domain_id=item.privacy_domain_id AND event_id=item.event_id FOR UPDATE;
 IF item.operation_id IS DISTINCT FROM openpc.current_operation_id()
 OR item.transition->'after' IS DISTINCT FROM to_jsonb(work)
 OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-LIVE'; END IF;
 -- A signature/STAGED configuration check is not this native admission.
 -- Missing actual execution/capacity/reviewer/process custody stays fatal.
 PERFORM openpc.assert_notification_async_work_current(work);
END $$;

CREATE OR REPLACE FUNCTION openpc.publish_notification_async_work_proof(source_event uuid,source_revision numeric)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_async_work_transition%ROWTYPE;event control.outbox_event%ROWTYPE;payload bytea;
BEGIN
 item:=openpc.read_notification_async_work_transition(source_event,source_revision);
 payload:=openpc.notification_async_work_event_bytes(item);
 event.participant_id:=item.participant_id;event.privacy_domain_id:=item.privacy_domain_id;
 event.event_id:=item.proof_event_id;event.event_type:='${proof.eventType}';
 event.aggregate_type:='notification-async-work';event.aggregate_id:=item.event_id;event.business_sequence:=item.revision;
 event.proof_kind:='${proof.kind}';event.sequence_namespace:='${proof.namespace}';
 event.data_schema_uri:='${proof.schema}';event.source:='urn:openpc:service:LS-NOTIFICATION';
 event.subject:='urn:openpc:resource:'||item.event_id::text;event.correlation_id:=item.operation_id;event.causation_id:=item.event_id;
 event.payload_cbor:=payload;event.payload_digest:=sha256(payload);
 event.occurred_at:=to_timestamp((item.recorded_at_ms/1000)::double precision);
 PERFORM openpc.admit_notification_async_work_event(event);
 IF NOT EXISTS(SELECT 1 FROM control.outbox_event WHERE participant_id=item.participant_id AND event_id=item.proof_event_id) THEN
  INSERT INTO control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,business_sequence,
   proof_kind,sequence_namespace,data_schema_uri,source,subject,correlation_id,causation_id,payload_cbor,payload_digest,occurred_at)
  VALUES(event.participant_id,event.privacy_domain_id,event.event_id,event.event_type,event.aggregate_type,event.aggregate_id,event.business_sequence,
   event.proof_kind,event.sequence_namespace,event.data_schema_uri,event.source,event.subject,event.correlation_id,event.causation_id,event.payload_cbor,event.payload_digest,event.occurred_at);
 END IF;
 PERFORM openpc.check_notification_async_work_proof(source_event,source_revision);
 PERFORM openpc.admit_notification_async_work_event(event);
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_notification_async_work_proof_complete()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='outbox_event' THEN
  PERFORM openpc.check_notification_async_work_proof(NEW.aggregate_id,NEW.business_sequence);
 ELSE
  PERFORM openpc.check_notification_async_work_proof(NEW.event_id,NEW.revision);
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER notification_async_work_proof_complete AFTER INSERT OR UPDATE ON control.notification_async_work
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_async_work_proof_complete();
CREATE CONSTRAINT TRIGGER notification_async_transition_proof_complete AFTER INSERT ON control.notification_async_work_transition
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_async_work_proof_complete();
CREATE CONSTRAINT TRIGGER notification_async_outbox_proof_complete AFTER INSERT ON control.outbox_event
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.proof_kind='${proof.kind}')
 EXECUTE FUNCTION openpc.guard_notification_async_work_proof_complete();
CREATE OR REPLACE FUNCTION openpc.deny_notification_async_outbox_truncate()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-ASYNC-PROOF-IMMUTABLE'; END $$;
CREATE TRIGGER notification_async_outbox_no_truncate BEFORE TRUNCATE ON control.outbox_event
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_async_outbox_truncate();
REVOKE ALL ON FUNCTION openpc.read_notification_async_work_transition(uuid,numeric),
 openpc.notification_async_work_event_bytes(control.notification_async_work_transition),openpc.check_notification_async_work_event(control.outbox_event),
 openpc.check_notification_async_work_proof(uuid,numeric),openpc.admit_notification_async_work_event(control.outbox_event),
 openpc.publish_notification_async_work_proof(uuid,numeric),openpc.guard_notification_async_work_proof_complete(),
 openpc.deny_notification_async_outbox_truncate() FROM PUBLIC;
`;
