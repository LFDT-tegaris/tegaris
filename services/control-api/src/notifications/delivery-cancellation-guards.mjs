import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.ts';

const profile = notificationCoseProfiles.NotificationDeliveryCancellationReceiptV1;
const causeProfile = businessTransitionProfiles.find(
  (p) => p.catalogOperationId === 'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
);
if (!profile || !causeProfile) throw new Error('Missing canonical cancellation profile');
const hash = (x) =>
  `'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${x}),'UTF8')),'hex')`;
const fields = profile.fields
  .map((f) => {
    const v = `r->>'${f.name}'`;
    if (f.name === 'schemaDefinitionDigest')
      return `'${f.key}',openpc.business_bytes(decode('${profile.definitionDigest.slice(7)}','hex'))`;
    if (f.type === 'H32') return `'${f.key}',openpc.business_bytes(decode(substr(${v},8),'hex'))`;
    if (f.type === 'uuidv7') return `'${f.key}',openpc.business_uuid((${v})::uuid)`;
    if (f.type === 'safe_uint' || f.type === 'u64p') return `'${f.key}',(${v})::numeric`;
    if (f.type.startsWith('enum ')) {
      const branches = f.type
        .slice(5)
        .split(' ')
        .map((entry) => {
          const [name, value] = entry.split('=');
          return `WHEN '${name}' THEN ${value}`;
        })
        .join(' ');
      return `'${f.key}',CASE ${v} ${branches} ELSE NULL END`;
    }
    return `'${f.key}',${v}`;
  })
  .join(',');
const budgetKeys =
  "ARRAY['revision','deliveryRequestEventId','deliveryRequestOperationId','budgetEnvironmentId','budgetGenerationId','budgetEffectiveDigest','budgetConfiguredLimit','budgetWorkerInstallationDigest']";
const rowProjection = (r) =>
  `jsonb_build_object('participantId',${r}.participant_id::text,'privacyDomainId',${r}.privacy_domain_id::text,'notificationOccurrenceId',${r}.notification_occurrence_id::text,'payloadDigest',${r}.payload_digest,'state',${r}.state,'attemptCount',${r}.attempt_count,'attemptLimit',${r}.attempt_limit,'nextAttemptAtMs',${r}.next_attempt_at_ms,'lastStartedAtMs',${r}.last_started_at_ms,'cancelRequested',${r}.cancel_requested,'revision',${r}.revision::text,'deliveryRequestEventId',${r}.delivery_request_event_id::text,'deliveryRequestOperationId',${r}.delivery_request_operation_id::text,'budgetEnvironmentId',${r}.budget_environment_id,'budgetGenerationId',${r}.budget_generation_id::text,'budgetEffectiveDigest',${r}.budget_effective_digest,'budgetConfiguredLimit',${r}.budget_configured_limit,'budgetWorkerInstallationDigest',${r}.budget_worker_installation_digest)`;

const workerProfile = notificationCoseProfiles.NotificationWorkerProfileV1;
const sourceProfile = notificationCoseProfiles.NotificationDeliveryRequestedReceiptV1;
const key = (p, name) => {
  const field = p.fields.find((f) => f.name === name);
  if (!field) throw new Error('Missing canonical notification field');
  return field.key;
};
const sourceClaims = `jsonb_build_object(${sourceProfile.fields
  .filter((f) => f.name !== 'schemaDefinitionDigest')
  .flatMap((f) => [
    `'${f.name}'`,
    f.type === 'uuidv7'
      ? `(sm->'${f.key}'->>'bytes')::uuid::text`
      : f.type === 'H32'
        ? `'sha256:'||(sm->'${f.key}'->>'bytes')`
        : f.type === 'safe_uint'
          ? `(sm->>'${f.key}')::numeric`
          : f.type === 'u64p'
            ? `sm->>'${f.key}'`
            : `sm->'${f.key}'`,
  ])
  .join(',')})`;
const causeAuthorizationSql = `
 SELECT * INTO STRICT authorization_row FROM control.mutation_evidence e WHERE e.participant_id=a.participant_id AND e.privacy_domain_id=a.privacy_domain_id
  AND e.operation_id=a.operation_id AND e.action_intent_id=a.action_intent_id AND e.catalog_operation_id=a.catalog_operation_id AND e.aggregate_id=a.aggregate_id
  AND e.candidate_digest=a.candidate_digest AND e.evidence_digest=sha256(e.evidence_cbor)
  AND e.evidence_role='AUTHORIZATION_INPUT' AND e.evidence_format='IDENTITY_RUNTIME_ASSERTION_3002_2_13';
 IF openpc.business_cbor(a.receipt_cbor)->'20' IS DISTINCT FROM jsonb_build_array(
  jsonb_build_object('0',2,'1',authorization_row.mutation_evidence_id::text,'2',openpc.business_bytes(authorization_row.evidence_digest)),
  openpc.configuration_step_up_receipt_input(a,authorization_row))
 OR t->'cause' IS DISTINCT FROM jsonb_build_object('participantId',a.participant_id::text,'privacyDomainId',a.privacy_domain_id::text,'environmentId',a.environment_id,
  'operationId',a.operation_id::text,'receiptId',a.receipt_id::text,'endpointId',a.aggregate_id::text,'endpointRevision',a.before_revision::text,'successorRevision',a.after_revision::text,
  'profileDigest','sha256:'||encode(a.profile_digest,'hex'),'receiptDigest','sha256:'||encode(a.receipt_digest,'hex'),
  'beforeStateDigest','sha256:'||encode(a.before_state_digest,'hex'),'afterStateDigest','sha256:'||encode(a.after_state_digest,'hex'),'recordedAtMs',floor(a.recorded_at_ns/1000000))
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-CAUSE-AUTHORITY'; END IF;
`;
const inputStateSql = ` IF (b->>'state' IN ('PENDING','RETRY_WAIT','STARTED','AMBIGUOUS')) IS DISTINCT FROM true OR b->'cancelRequested' IS DISTINCT FROM 'false'::jsonb
 OR b->>'revision' IS DISTINCT FROM (r->>'deliveryRevision')::numeric::text OR n->>'revision' IS DISTINCT FROM ((r->>'deliveryRevision')::numeric+1)::text
 OR b->>'deliveryRequestOperationId' IS DISTINCT FROM (t->>'sourceOperationId')::uuid::text OR b->>'payloadDigest' IS DISTINCT FROM (r->>'payloadDigest')
 OR b->>'participantId' IS DISTINCT FROM item.participant_id::text OR b->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR b->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text
 OR n-ARRAY['revision','state','cancelRequested','nextAttemptAtMs'] IS DISTINCT FROM b-ARRAY['revision','state','cancelRequested','nextAttemptAtMs']
 OR n->'cancelRequested' IS DISTINCT FROM 'true'::jsonb OR n->'nextAttemptAtMs' IS DISTINCT FROM 'null'::jsonb
 OR n->>'state' IS DISTINCT FROM (CASE WHEN b->>'state' IN ('PENDING','RETRY_WAIT') THEN 'CANCELLED' ELSE b->>'state' END)
 OR r->>'beforeDeliveryState' IS DISTINCT FROM b->>'state' OR r->>'afterDeliveryState' IS DISTINCT FROM n->>'state' OR r->'attemptCount' IS DISTINCT FROM b->'attemptCount'
 OR r->>'disposition' IS DISTINCT FROM (CASE WHEN b->>'state'='PENDING' THEN 'CANCELLED_BEFORE_START' WHEN b->>'state'='RETRY_WAIT' THEN 'PREVENT_LATER_ATTEMPTS' ELSE 'RECONCILE_ORIGINAL' END)
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-TRANSITION'; END IF;
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',b->>'revision','projection',b-${budgetKeys});
 IF r->>'beforeStateDigest' IS DISTINCT FROM ${hash('expected')} THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-STATE'; END IF;
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',n->>'revision','projection',n-${budgetKeys});
 IF r->>'afterStateDigest' IS DISTINCT FROM ${hash('expected')} THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-STATE'; END IF;
 IF b->>'state'='PENDING' THEN
  IF b->'attemptCount' IS DISTINCT FROM '0'::jsonb OR t->'originalStart' IS DISTINCT FROM 'null'::jsonb OR t->'originalClaim' IS DISTINCT FROM 'null'::jsonb
   OR EXISTS(SELECT 1 FROM control.notification_delivery_attempt WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=item.notification_occurrence_id)
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-LINEAGE'; END IF;
 ELSE
  SELECT * INTO STRICT s FROM control.notification_delivery_start WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=(t->'originalStart'->'receipt'->>'operationId')::uuid;
  PERFORM openpc.check_notification_delivery_start_original(s);
  SELECT * INTO STRICT claim FROM control.notification_delivery_dispatch_intent WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND operation_id=s.operation_id;
  PERFORM openpc.check_notification_delivery_dispatch_intent_original(claim);
  IF t->'originalStart' IS DISTINCT FROM s.transition OR s.notification_occurrence_id<>item.notification_occurrence_id OR s.payload_digest<>(r->>'payloadDigest')
   OR t->'originalClaim' IS DISTINCT FROM jsonb_build_object('state',claim.state,'claimToken',claim.claim_token,'claimedAtMs',claim.claimed_at_ms)
   OR s.transition->'attempt'->'attemptNumber' IS DISTINCT FROM b->'attemptCount' OR s.transition->'attempt'->'startedAtMs' IS DISTINCT FROM b->'lastStartedAtMs'
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-LINEAGE'; END IF;
 END IF;
 IF b->>'state'='RETRY_WAIT' THEN
  SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id
   AND notification_occurrence_id=item.notification_occurrence_id AND start_operation_id=s.operation_id AND attempt_id=s.attempt_id;
  PERFORM openpc.check_notification_outcome_publication_original(o.operation_id);
  IF t->'originalOutcome' IS DISTINCT FROM o.transition OR o.transition->'receipt'->>'outcome' IS DISTINCT FROM 'RETRYABLE_NO_EFFECT'
   OR o.transition->'receipt'->>'afterDeliveryState' IS DISTINCT FROM 'RETRY_WAIT' OR claim.state<>'CLAIMED'
   OR (b->>'revision')::numeric<o.delivery_revision+1 OR (b->>'attemptLimit')::numeric>(o.transition->'receipt'->>'attemptLimit')::numeric
   OR (r->>'recordedAtMs')::numeric<(o.transition->'receipt'->>'recordedAtMs')::numeric
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-RETRY-LINEAGE'; END IF;
  expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',(o.delivery_revision+1)::text,
   'projection',(b-${budgetKeys})||jsonb_build_object('attemptLimit',o.transition->'receipt'->'attemptLimit'));
  IF ${hash('expected')} IS DISTINCT FROM o.transition->'receipt'->>'afterStateDigest'
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-RETRY-STATE'; END IF;
 ELSIF t ? 'originalOutcome' THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-UNEXPECTED-OUTCOME'; END IF;`;

/** Register through the canonical generated migration/security owner. No grants
 * or signer admission are manufactured here. The existing delivery-budget guard
 * must explicitly dispatch cancellation to the projection hook BEFORE positive
 * send-readiness checks. SQL framing supplements TS native crypto verification;
 * the distinct canonical signer admission remains mandatory and fail-closed. */
const cancellationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_cancellation_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE lock_name text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin' OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id',true) IS DISTINCT FROM 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_delivery_cancellation'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_cancellation_signing'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_cancellation_signing'::regclass AND tgname='notification_cancel_signing_guard' AND tgenabled IN ('O','A') AND tgtype=23 AND tgfoid='openpc.guard_notification_cancellation_signing()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_cancellation_signing'::regclass AND tgname='notification_cancel_signing_immutable' AND tgenabled IN ('O','A') AND tgtype=42 AND tgfoid='openpc.deny_notification_delivery_cancellation_mutation()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_cancellation'::regclass AND tgname='notification_cancellation_insert' AND tgenabled IN ('O','A') AND tgtype=7 AND tgfoid='openpc.guard_notification_delivery_cancellation()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_cancellation'::regclass AND tgname='notification_cancellation_immutable' AND tgenabled IN ('O','A') AND tgtype=58 AND tgfoid='openpc.deny_notification_delivery_cancellation_mutation()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_cancellation'::regclass AND tgname='notification_cancellation_complete' AND tgenabled IN ('O','A') AND tgtype=5 AND tgdeferrable AND tginitdeferred)
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-OWNER'; END IF;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||openpc.current_participant_id()::text,
 'notification-worker:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
   AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-FENCE'; END IF;
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_cancellation_original(item control.notification_delivery_cancellation) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE t jsonb:=item.transition;r jsonb:=t->'receipt';b jsonb:=t->'before';n jsonb:=t->'after';c jsonb:=t->'cause';
 a control.audit_occurrence%ROWTYPE;authorization_row control.mutation_evidence%ROWTYPE;i control.idempotency_record%ROWTYPE;e control.outbox_event%ROWTYPE;w control.installed_notification_worker%ROWTYPE;
 s control.notification_delivery_start%ROWTYPE;claim control.notification_delivery_dispatch_intent%ROWTYPE;o control.notification_delivery_outcome%ROWTYPE;before_projection jsonb;after_projection jsonb;expected jsonb;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR t->>'schema' IS DISTINCT FROM 'pc.notification.delivery-cancellation-transition.v1'
 OR item.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(t),'UTF8') OR item.transition_digest IS DISTINCT FROM ${hash('t')}
 OR item.receipt_payload IS DISTINCT FROM decode(t->>'payloadHex','hex') OR item.cose_sign1 IS DISTINCT FROM decode(t->>'coseHex','hex')
 OR item.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(item.receipt_payload),'hex')
 OR r->>'operationId' IS DISTINCT FROM item.operation_id::text OR r->>'receiptId' IS DISTINCT FROM item.receipt_id::text
 OR r->>'participantId' IS DISTINCT FROM item.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR r->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text OR r->>'payloadDigest' IS DISTINCT FROM item.payload_digest
 OR r->>'deliveryRevision' IS DISTINCT FROM item.delivery_revision::text OR r->>'causeOperationId' IS DISTINCT FROM item.cause_operation_id::text
 OR t->>'sourceOperationId' IS DISTINCT FROM item.source_operation_id::text OR c->>'receiptId' IS DISTINCT FROM item.cause_receipt_id::text
 OR t->'selector'->>'causeOperationId' IS DISTINCT FROM item.cause_operation_id::text
 OR t->'selector'->>'expectedRevision' IS DISTINCT FROM item.delivery_revision::text
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-ORIGINAL'; END IF;
 IF openpc.business_cbor(item.receipt_payload) IS DISTINCT FROM jsonb_build_object(${fields})
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-WIRE'; END IF;
 PERFORM openpc.archive_cose_binding(item.receipt_payload,item.cose_sign1,r->>'signerKeyId',${profile.schemaId},${profile.purposeCode});
 SELECT * INTO STRICT a FROM control.audit_occurrence WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id
 AND receipt_id=item.cause_receipt_id AND operation_id=item.cause_operation_id;
 SELECT * INTO STRICT i FROM control.idempotency_record WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id AND idempotency_record_id=a.idempotency_record_id;
 before_projection:=openpc.business_cbor(a.before_state_preimage)->8;after_projection:=openpc.business_cbor(a.after_state_preimage)->8;
 IF a.catalog_operation_id<>'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT' OR a.action_intent_id<>'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1'
 OR a.aggregate_type<>'notification-endpoint' OR a.profile_digest<>decode('${causeProfile.profileDigest.slice(7)}','hex')
 OR a.before_existence<>1 OR a.after_existence<>1 OR a.after_revision<>a.before_revision+1
 OR a.aggregate_id::text IS DISTINCT FROM r->>'endpointId' OR a.before_revision::text IS DISTINCT FROM r->>'endpointRevision'
 OR a.after_revision::text IS DISTINCT FROM r->>'causeEndpointRevision' OR a.environment_id IS DISTINCT FROM r->>'environmentId'
 OR before_projection->>'1'='RETIRED' OR after_projection->>'1' IS DISTINCT FROM (CASE WHEN before_projection->>'1'='QUARANTINED' THEN 'QUARANTINED' ELSE 'DISABLED' END)
 OR after_projection->'7' IS DISTINCT FROM '0'::jsonb OR after_projection ? '8'
 OR i.terminal_state<>'COMMITTED' OR i.action_intent_id<>a.action_intent_id OR i.catalog_operation_id<>a.catalog_operation_id OR i.input_digest<>a.candidate_digest
 OR i.result_payload->>'state' IS DISTINCT FROM 'SUCCEEDED' OR i.result_payload->>'truthState' IS DISTINCT FROM 'SUCCESS' OR i.result_payload->>'operationId' IS DISTINCT FROM a.operation_id::text
 OR a.before_state_digest<>sha256(a.before_state_preimage) OR a.after_state_digest<>sha256(a.after_state_preimage) OR a.pre_commit_authority_digest<>sha256(a.authority_snapshot)
 OR r->>'causeProfileDigest' IS DISTINCT FROM 'sha256:'||encode(a.profile_digest,'hex') OR a.after_revision::text IS DISTINCT FROM r->>'causeEndpointRevision' OR r->>'causeProfileDigest' IS DISTINCT FROM 'sha256:'||encode(a.profile_digest,'hex')
 OR a.before_state_digest<>sha256(a.before_state_preimage) OR a.after_state_digest<>sha256(a.after_state_preimage) OR a.pre_commit_authority_digest<>sha256(a.authority_snapshot)
 OR openpc.business_cbor(a.before_state_preimage)->8->>'1'='RETIRED'
 OR openpc.business_cbor(a.after_state_preimage)->8->>'1' IS DISTINCT FROM (CASE WHEN openpc.business_cbor(a.before_state_preimage)->8->>'1'='QUARANTINED' THEN 'QUARANTINED' ELSE 'DISABLED' END)
 OR openpc.business_cbor(a.after_state_preimage)->8->'7' IS DISTINCT FROM '0'::jsonb OR (openpc.business_cbor(a.after_state_preimage)->8) ? '8'
 OR r->>'causeReceiptDigest' IS DISTINCT FROM 'sha256:'||encode(a.receipt_digest,'hex')
 OR r->>'causeBeforeStateDigest' IS DISTINCT FROM 'sha256:'||encode(a.before_state_digest,'hex') OR r->>'causeAfterStateDigest' IS DISTINCT FROM 'sha256:'||encode(a.after_state_digest,'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-CAUSE'; END IF;
${causeAuthorizationSql}
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id
 AND event_id=(r->>'sourceEventId')::uuid AND correlation_id=item.source_operation_id AND aggregate_id=item.notification_occurrence_id;
 PERFORM openpc.check_notification_delivery_requested_event(e);
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=item.worker_installation_digest;
 IF w.installation IS DISTINCT FROM t->'workerInstallation' OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR t->'selector'->'source'->'worker' IS DISTINCT FROM jsonb_build_object('participantId',item.participant_id::text,'privacyDomainId',item.privacy_domain_id::text,'installationDigest',item.worker_installation_digest)
 OR t->'selector'->'source'->>'eventId' IS DISTINCT FROM r->>'sourceEventId'
 OR t->'selector'->'source'->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-WORKER'; END IF;
 ${inputStateSql}
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_cancellation() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_delivery%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_cancellation_owner();
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND notification_occurrence_id=NEW.notification_occurrence_id FOR UPDATE;
 IF ${rowProjection('d')} IS DISTINCT FROM NEW.transition->'before' THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-STALE'; END IF;
 PERFORM openpc.check_notification_delivery_cancellation_original(NEW);
 IF to_regprocedure('openpc.check_notification_delivery_cancellation_signer(uuid,text)') IS NULL THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNER-UNBOUND'; END IF;
 EXECUTE 'select openpc.check_notification_delivery_cancellation_signer($1,$2)' USING NEW.operation_id,NEW.transition_digest;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_cancellation_projection(before_row control.notification_delivery,after_row control.notification_delivery) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.notification_delivery_cancellation%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_cancellation_owner();
 SELECT * INTO STRICT c FROM control.notification_delivery_cancellation WHERE participant_id=before_row.participant_id AND privacy_domain_id=before_row.privacy_domain_id AND notification_occurrence_id=before_row.notification_occurrence_id AND delivery_revision=before_row.revision;
 PERFORM openpc.check_notification_delivery_cancellation_original(c);
 IF ${rowProjection('before_row')} IS DISTINCT FROM c.transition->'before' OR ${rowProjection('after_row')} IS DISTINCT FROM c.transition->'after'
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-PROJECTION'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_cancellation_complete(operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c control.notification_delivery_cancellation%ROWTYPE;d control.notification_delivery%ROWTYPE;
BEGIN
 SELECT * INTO STRICT c FROM control.notification_delivery_cancellation WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 PERFORM openpc.check_notification_delivery_cancellation_original(c);
 PERFORM openpc.check_notification_delivery_cancellation_signer(c.operation_id,c.transition_digest);
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=c.participant_id AND privacy_domain_id=c.privacy_domain_id AND notification_occurrence_id=c.notification_occurrence_id;
 IF d.revision<c.delivery_revision+1 OR NOT d.cancel_requested OR d.payload_digest<>c.payload_digest
 OR (d.revision=c.delivery_revision+1 AND ${rowProjection('d')} IS DISTINCT FROM c.transition->'after')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-INCOMPLETE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_cancellation_complete() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN PERFORM openpc.check_notification_delivery_cancellation_complete(NEW.operation_id);RETURN NEW;END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_cancellation_mutation() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-IMMUTABLE';END $$;
DROP TRIGGER IF EXISTS notification_cancellation_insert ON control.notification_delivery_cancellation;
CREATE TRIGGER notification_cancellation_insert BEFORE INSERT ON control.notification_delivery_cancellation FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_cancellation();
DROP TRIGGER IF EXISTS notification_cancellation_immutable ON control.notification_delivery_cancellation;
CREATE TRIGGER notification_cancellation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_cancellation FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_cancellation_mutation();
DROP TRIGGER IF EXISTS notification_cancellation_complete ON control.notification_delivery_cancellation;
CREATE CONSTRAINT TRIGGER notification_cancellation_complete AFTER INSERT ON control.notification_delivery_cancellation DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_cancellation_complete();
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_cancellation_owner(),openpc.check_notification_delivery_cancellation_original(control.notification_delivery_cancellation),openpc.guard_notification_delivery_cancellation(),openpc.check_notification_delivery_cancellation_projection(control.notification_delivery,control.notification_delivery),openpc.check_notification_delivery_cancellation_complete(uuid),openpc.guard_notification_delivery_cancellation_complete(),openpc.deny_notification_delivery_cancellation_mutation() FROM PUBLIC;
`;

const signingGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_notification_cancellation_signing_original(item control.notification_cancellation_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=item.preparation;x jsonb:=p->'input';q jsonb:=p->'request';r jsonb:=x->'receipt';trust jsonb:=p->'trust';
 signer control.notification_receipt_signer_installation%ROWTYPE;w control.installed_notification_worker%ROWTYPE;a control.audit_occurrence%ROWTYPE;
 authorization_row control.mutation_evidence%ROWTYPE;source control.notification_occurrence_observation%ROWTYPE;t jsonb:=x;sm jsonb;wm jsonb;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR item.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8') OR item.preparation_digest IS DISTINCT FROM ${hash('p')}
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-ORIGINAL'; END IF;
 IF p IS DISTINCT FROM jsonb_build_object('input',x,'trust',trust,'request',q)
 OR q-ARRAY['schemaVersion','method','purpose','signerInstallationDigest','providerId','secretClass','reference','version','keyEpoch','signerKeyId','environmentId','participantId','privacyDomainId','workerInstallationDigest','workerProfileDigest','workloadCredentialId','workloadEpoch','signingAttemptId','operationId','causeOperationId','cancellationPreparationDigest','payloadHex'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(q))<>22
 OR x->>'schema' IS DISTINCT FROM 'pc.notification.delivery-cancellation-transition.v1'
 OR q->>'method' IS DISTINCT FROM 'SIGN_NOTIFICATION_DELIVERY_CANCELLATION' OR q->>'purpose' IS DISTINCT FROM 'pc.cose.notification-delivery-cancellation-receipt.v1'
 OR q->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR q->>'operationId' IS DISTINCT FROM item.operation_id::text OR q->>'signingAttemptId' IS DISTINCT FROM item.signing_attempt_id::text
 OR q->>'participantId' IS DISTINCT FROM item.participant_id::text OR q->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR q->>'causeOperationId' IS DISTINCT FROM item.cause_operation_id::text OR q->>'signerInstallationDigest' IS DISTINCT FROM item.signer_installation_digest
 OR x->'selector'->'source'->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text
 OR q->>'payloadHex' IS DISTINCT FROM x->>'payloadHex' OR q->>'cancellationPreparationDigest' IS DISTINCT FROM ${hash('x')}
 OR r->>'operationId' IS DISTINCT FROM item.operation_id::text OR r->>'receiptId' IS DISTINCT FROM item.signing_attempt_id::text
 OR r->>'causeOperationId' IS DISTINCT FROM item.cause_operation_id::text OR r->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text
 OR openpc.business_cbor(decode(q->>'payloadHex','hex')) IS DISTINCT FROM jsonb_build_object(${fields})
 OR item.request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.notification.cancellation-receipt-provider-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(q),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-BINDING'; END IF;
 SELECT * INTO STRICT signer FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 IF trust->'worker' IS DISTINCT FROM w.installation OR x->'workerInstallation' IS DISTINCT FROM w.installation
 OR trust IS DISTINCT FROM jsonb_build_object('worker',w.installation,'signer',signer.trust-ARRAY['schema','schemaDefinitionDigest','signerKeyId'])
 OR trust->'signer' IS DISTINCT FROM signer.trust-ARRAY['schema','schemaDefinitionDigest','signerKeyId']
 OR signer.trust->>'purpose' IS DISTINCT FROM 'pc.cose.notification-delivery-cancellation-receipt.v1'
 OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR r->>'workerProfileDigest' IS DISTINCT FROM signer.trust->>'workerProfileDigest'
 OR r->>'signerKeyId' IS DISTINCT FROM signer.signer_id OR q->>'signerKeyId' IS DISTINCT FROM signer.signer_id
 OR q->>'reference' IS DISTINCT FROM signer.trust->>'secretReference' OR q->>'version' IS DISTINCT FROM signer.trust->>'secretVersion'
 OR q->>'providerId' IS DISTINCT FROM signer.trust->>'providerId' OR q->>'keyEpoch' IS DISTINCT FROM signer.trust->>'keyEpoch'
 OR q->>'workloadCredentialId' IS DISTINCT FROM signer.trust->>'workloadCredentialId' OR q->>'workloadEpoch' IS DISTINCT FROM signer.trust->>'workloadEpoch'
 OR q->>'workerInstallationDigest' IS DISTINCT FROM signer.worker_installation_digest OR q->>'workerProfileDigest' IS DISTINCT FROM signer.trust->>'workerProfileDigest'
 OR q->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY' OR q->>'environmentId' IS DISTINCT FROM signer.trust->>'environmentId'
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-TRUST'; END IF;
 SELECT * INTO STRICT a FROM control.audit_occurrence WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.cause_operation_id;
 IF a.catalog_operation_id<>'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT' OR a.action_intent_id<>'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1'
 OR a.aggregate_type<>'notification-endpoint' OR a.environment_id IS DISTINCT FROM r->>'environmentId'
 OR a.profile_digest<>decode('${causeProfile.profileDigest.slice(7)}','hex') OR a.before_existence<>1 OR a.after_existence<>1 OR a.after_revision<>a.before_revision+1
 OR a.aggregate_id::text IS DISTINCT FROM r->>'endpointId' OR a.before_revision::text IS DISTINCT FROM r->>'endpointRevision'
 OR a.after_revision::text IS DISTINCT FROM r->>'causeEndpointRevision' OR r->>'causeProfileDigest' IS DISTINCT FROM 'sha256:'||encode(a.profile_digest,'hex')
 OR a.before_state_digest<>sha256(a.before_state_preimage) OR a.after_state_digest<>sha256(a.after_state_preimage) OR a.pre_commit_authority_digest<>sha256(a.authority_snapshot)
 OR openpc.business_cbor(a.before_state_preimage)->8->>'1'='RETIRED'
 OR openpc.business_cbor(a.after_state_preimage)->8->>'1' IS DISTINCT FROM (CASE WHEN openpc.business_cbor(a.before_state_preimage)->8->>'1'='QUARANTINED' THEN 'QUARANTINED' ELSE 'DISABLED' END)
 OR openpc.business_cbor(a.after_state_preimage)->8->'7' IS DISTINCT FROM '0'::jsonb OR (openpc.business_cbor(a.after_state_preimage)->8) ? '8'
 OR r->>'causeReceiptDigest' IS DISTINCT FROM 'sha256:'||encode(a.receipt_digest,'hex')
 OR r->>'causeBeforeStateDigest' IS DISTINCT FROM 'sha256:'||encode(a.before_state_digest,'hex') OR r->>'causeAfterStateDigest' IS DISTINCT FROM 'sha256:'||encode(a.after_state_digest,'hex')
 OR NOT EXISTS(SELECT 1 FROM control.idempotency_record i WHERE i.participant_id=a.participant_id AND i.privacy_domain_id=a.privacy_domain_id AND i.operation_id=a.operation_id
  AND i.idempotency_record_id=a.idempotency_record_id AND i.action_intent_id=a.action_intent_id AND i.catalog_operation_id=a.catalog_operation_id AND i.input_digest=a.candidate_digest
  AND i.result_aggregate_version=a.after_revision AND i.result_digest=sha256(convert_to(openpc.signing_canonical_json(i.result_payload),'UTF8'))
  AND i.result_payload->>'operationId'=a.operation_id::text AND i.terminal_state='COMMITTED' AND i.result_payload->>'state'='SUCCEEDED' AND i.result_payload->>'truthState'='SUCCESS')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-CAUSE'; END IF;
${causeAuthorizationSql}
 SELECT * INTO STRICT source FROM control.notification_occurrence_observation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=(x->>'sourceOperationId')::uuid;
 sm:=openpc.business_cbor(source.receipt_payload);wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF x->'sourceClaims' IS DISTINCT FROM ${sourceClaims}
 OR r->>'sourceEventId' IS DISTINCT FROM x->'sourceClaims'->>'eventId' OR r->>'routingProfileDigest' IS DISTINCT FROM x->'sourceClaims'->>'routingProfileDigest'
 OR r->>'endpointId' IS DISTINCT FROM x->'sourceClaims'->>'endpointId' OR r->>'endpointRevision' IS DISTINCT FROM x->'sourceClaims'->>'endpointRevision'
 OR r->>'payloadDigest' IS DISTINCT FROM x->'sourceClaims'->>'payloadDigest' OR r->>'authoritySnapshotDigest' IS DISTINCT FROM x->>'workerAuthorityDigest'
 OR r->>'participantId' IS DISTINCT FROM item.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR r->>'environmentId' IS DISTINCT FROM q->>'environmentId' OR x->'sourceClaims'->>'operationId' IS DISTINCT FROM source.operation_id::text
 OR x->'selector'->>'causeOperationId' IS DISTINCT FROM item.cause_operation_id::text OR x->'selector'->>'expectedRevision' IS DISTINCT FROM r->>'deliveryRevision'
 OR (r->>'recordedAtMs')::numeric<(wm->>'${key(workerProfile, 'validFromMs')}')::numeric OR (r->>'recordedAtMs')::numeric>=(wm->>'${key(workerProfile, 'validUntilMs')}')::numeric
 OR x->>'sourceReceiptDigest' IS DISTINCT FROM source.receipt_digest OR r->>'sourceReceiptDigest' IS DISTINCT FROM source.receipt_digest
 OR (r->>'recordedAtMs')::numeric*1000000<a.recorded_at_ns OR (r->>'recordedAtMs')::numeric*1000000<(signer.trust->>'validFromNs')::numeric
 OR (r->>'recordedAtMs')::numeric*1000000>=(signer.trust->>'validUntilNs')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-SOURCE'; END IF;
 IF item.state<>'PREPARED' AND (item.dispatched_at_ms<(r->>'recordedAtMs')::numeric OR item.dispatched_at_ms*1000000>=(signer.trust->>'validUntilNs')::numeric OR item.dispatched_at_ms>=(wm->>'${key(workerProfile, 'validUntilMs')}')::numeric)
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-TIME'; END IF;
 IF item.state='OBSERVED' THEN
  IF item.observation-ARRAY['schemaVersion','providerId','signingAttemptId','requestDigest','recordedAtMs','outcome','reason','coseHex'] IS DISTINCT FROM '{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(item.observation))<>8 OR jsonb_typeof(item.observation->'recordedAtMs') IS DISTINCT FROM 'number'
  OR (item.observation->>'recordedAtMs')::numeric NOT BETWEEN 0 AND 9007199254740991 OR trunc((item.observation->>'recordedAtMs')::numeric)<>(item.observation->>'recordedAtMs')::numeric
  OR item.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(item.observation),'UTF8') OR item.observation_digest IS DISTINCT FROM ${hash('item.observation')}
  OR item.observation->>'providerId' IS DISTINCT FROM q->>'providerId' OR item.observation->>'signingAttemptId' IS DISTINCT FROM item.signing_attempt_id::text
  OR item.observation->>'requestDigest' IS DISTINCT FROM item.request_digest OR item.observation->'schemaVersion' IS DISTINCT FROM '1'::jsonb
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-OBSERVATION'; END IF;
  IF item.observation->>'outcome'='SIGNED' THEN
   IF item.observation->'reason' IS DISTINCT FROM 'null'::jsonb OR item.observation->>'coseHex' IS NULL
   OR (item.observation->>'recordedAtMs')::numeric>=(wm->>'${key(workerProfile, 'validUntilMs')}')::numeric
   OR (item.observation->>'recordedAtMs')::numeric<item.dispatched_at_ms OR (item.observation->>'recordedAtMs')::numeric*1000000>=(signer.trust->>'validUntilNs')::numeric
   THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-OBSERVATION'; END IF;
   PERFORM openpc.archive_cose_binding(decode(q->>'payloadHex','hex'),decode(item.observation->>'coseHex','hex'),signer.signer_id,${profile.schemaId},${profile.purposeCode});
  ELSIF item.observation->>'outcome' IS DISTINCT FROM 'REJECTED' OR item.observation->'coseHex' IS DISTINCT FROM 'null'::jsonb
   OR (item.observation->>'reason' IN ('REVOKED','EXPIRED','WRONG_SCOPE','INVALID_REQUEST','ATTEMPT_CONFLICT','KEY_UNAVAILABLE')) IS DISTINCT FROM true
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-OBSERVATION'; END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_cancellation_signing_current(item control.notification_cancellation_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_delivery%ROWTYPE;signer control.notification_receipt_signer_installation%ROWTYPE;now_ms numeric;lock_name text;wm jsonb;
 t jsonb:=item.preparation->'input';r jsonb:=t->'receipt';b jsonb:=t->'before';n jsonb:=t->'after';expected jsonb;
 s control.notification_delivery_start%ROWTYPE;claim control.notification_delivery_dispatch_intent%ROWTYPE;o control.notification_delivery_outcome%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_delivery_cancellation_owner();
 PERFORM openpc.check_notification_cancellation_signing_original(item);
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=item.notification_occurrence_id FOR UPDATE;
 IF ${rowProjection('d')} IS DISTINCT FROM item.preparation->'input'->'before' OR d.cancel_requested OR d.state NOT IN ('PENDING','RETRY_WAIT','STARTED','AMBIGUOUS')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-STALE'; END IF;
 ${inputStateSql}
 IF r->>'recordedAtMs' IS NULL OR r->>'workerProfileDigest' IS NULL THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-BINDING'; END IF;
 lock_name:='notification-receipt-signer:'||item.participant_id::text||':'||item.privacy_domain_id::text;
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ShareLock'
 AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-FENCE'; END IF;
 SELECT * INTO STRICT signer FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest AND state='ACTIVE';
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 SELECT openpc.business_cbor(decode(installation->'signed'->>'payloadHex','hex')) INTO STRICT wm FROM control.installed_notification_worker
 WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 IF now_ms<(wm->>'${key(workerProfile, 'validFromMs')}')::numeric OR now_ms>=(wm->>'${key(workerProfile, 'validUntilMs')}')::numeric OR now_ms*1000000<(signer.trust->>'validFromNs')::numeric OR now_ms*1000000>=(signer.trust->>'validUntilNs')::numeric
 OR NOT EXISTS(SELECT 1 FROM control.installed_notification_worker w JOIN control.credential c ON c.participant_id=w.participant_id AND c.credential_id=w.workload_credential_id
   JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
   WHERE w.participant_id=item.participant_id AND w.privacy_domain_id=item.privacy_domain_id AND w.installation_digest=signer.worker_installation_digest AND w.state='ACTIVE'
    AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch::text=signer.trust->>'workloadEpoch'
    AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp() AND p.state='ACTIVE' AND p.kind='WORKLOAD')
 THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-AUTHORITY'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_cancellation_signing() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_cancellation_owner();
 PERFORM openpc.check_notification_cancellation_signing_original(NEW);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-INITIAL'; END IF;
  PERFORM openpc.check_notification_cancellation_signing_current(NEW);
 ELSE
  IF to_jsonb(NEW)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest']
  THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-IMMUTABLE'; END IF;
  IF OLD.state='PREPARED' AND NEW.state='DISPATCHED' THEN
   PERFORM openpc.check_notification_cancellation_signing_current(NEW);
   IF NEW.dispatched_at_ms IS DISTINCT FROM floor(extract(epoch from statement_timestamp())*1000)
   THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-TIME'; END IF;
  ELSIF OLD.state='DISPATCHED' AND NEW.state='OBSERVED' THEN
   IF NEW.dispatch_token IS DISTINCT FROM OLD.dispatch_token OR NEW.dispatched_at_ms IS DISTINCT FROM OLD.dispatched_at_ms THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-CLAIM'; END IF;
  ELSE RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNING-ONE-SHOT'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_cancellation_signer(operation uuid,transition_digest text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_cancellation_signing%ROWTYPE;actual jsonb;
BEGIN
 SELECT * INTO STRICT s FROM control.notification_cancellation_signing WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 PERFORM openpc.check_notification_cancellation_signing_original(s);
 IF s.state<>'OBSERVED' OR s.observation->>'outcome' IS DISTINCT FROM 'SIGNED' THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNER-UNBOUND'; END IF;
 actual:=(s.preparation->'input')||jsonb_build_object('coseHex',s.observation->'coseHex');
 IF transition_digest IS DISTINCT FROM ${hash('actual')} THEN RAISE EXCEPTION 'NOTIFICATION-CANCELLATION-SIGNER-ORIGINAL'; END IF;
END $$;
DROP TRIGGER IF EXISTS notification_cancel_signing_guard ON control.notification_cancellation_signing;
CREATE TRIGGER notification_cancel_signing_guard BEFORE INSERT OR UPDATE ON control.notification_cancellation_signing FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_cancellation_signing();
DROP TRIGGER IF EXISTS notification_cancel_signing_immutable ON control.notification_cancellation_signing;
CREATE TRIGGER notification_cancel_signing_immutable BEFORE DELETE OR TRUNCATE ON control.notification_cancellation_signing FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_cancellation_mutation();
REVOKE ALL ON FUNCTION openpc.check_notification_cancellation_signing_original(control.notification_cancellation_signing),openpc.check_notification_cancellation_signing_current(control.notification_cancellation_signing),openpc.guard_notification_cancellation_signing(),openpc.check_notification_delivery_cancellation_signer(uuid,text) FROM PUBLIC;
`;
export const notificationDeliveryCancellationGuardsSql = cancellationGuardsSql + signingGuardsSql;
