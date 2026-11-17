import {
  notificationCompletionDispositionPhaseGuardsSql,
  notificationCompletionDispositionStructureGuardsSql,
} from './completion-disposition-effect-guards.mjs';
import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const worker = notificationCoseProfiles.NotificationCompletionWorkerProfileV1;
const field = (name) => worker.fields.find((f) => f.name === name).key;
const family = notificationCoseProfiles.NotificationCompletionDispositionReceiptV1;
const producerTrustField = notificationCoseProfiles.NotificationWorkerProfileV1.fields.find(
  (f) => f.name === 'producerTrustDigest',
).key;
if (!family) throw new Error('Canonical completion disposition registration unavailable');
const fields = [
  'schema',
  'schemaDefinitionDigest',
  'owner',
  'purpose',
  'environmentId',
  'participantId',
  'privacyDomainId',
  'installationId',
  'workerInstallationDigest',
  'workerProfileDigest',
  'workerIssuerSpkiHex',
  'principalId',
  'workloadCredentialId',
  'workloadEpoch',
  'workloadId',
  'secretClass',
  'secretReference',
  'secretVersion',
  'publicKeySpkiHex',
  'keyEpoch',
  'providerId',
  'providerOrigin',
  'providerTlsSpkiDigest',
  'validFromNs',
  'validUntilNs',
  'installationReference',
  'signerKeyId',
];
/** Initial-trust immutability and scoped current-worker binding. Signature
 * verification and actual Identity/mTLS remain application owners. No signer
 * attempt, dispatch, delivery state, public event or provider I/O is admitted. */
export const notificationCompletionDispositionSignerGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_disposition_signer_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE t jsonb; w control.installed_notification_completion_worker%ROWTYPE; m jsonb; c control.credential%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- Direct UPDATE already holds a row lock: fail instead of reversing the fence order.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-completion-disposition-signer:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
  THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 t:=NEW.trust;
 IF NEW.state<>'ACTIVE' OR jsonb_typeof(t) IS DISTINCT FROM 'object'
 OR t-ARRAY[${fields.map((f) => `'${f}'`).join(',')}] IS DISTINCT FROM '{}'::jsonb
 OR NOT t ?& ARRAY[${fields.map((f) => `'${f}'`).join(',')}]
 OR EXISTS(SELECT 1 FROM jsonb_each(t) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'<>btrim(e.value#>>'{}'))
 OR t->>'schema' IS DISTINCT FROM 'pc.notification.completion-disposition-signer-trust.v1'
 OR t->>'purpose' IS DISTINCT FROM 'pc.cose.notification-completion-disposition-receipt.v1' OR t->>'schemaDefinitionDigest' IS DISTINCT FROM '${family.definitionDigest}'
 OR t->>'owner' IS DISTINCT FROM 'LS-CONTROL-WORK'

 OR t->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
 OR t->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR t->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
 OR t->>'installationId' IS DISTINCT FROM NEW.installation_id::text
 OR t->>'workerInstallationDigest' IS DISTINCT FROM NEW.worker_installation_digest
 OR t->>'signerKeyId' IS DISTINCT FROM NEW.signer_id
 OR NEW.trust_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(t),'UTF8')
 OR NEW.trust_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.trust_bytes),'hex')
 OR NOT coalesce(t->>'secretReference' ~ '^secret://[a-z][a-z0-9-]{1,31}/[A-Za-z0-9._/-]{1,192}#[A-Za-z0-9._-]{1,96}$',false)
 OR split_part(t->>'secretReference','#',2) IS DISTINCT FROM t->>'secretVersion' OR lower(t->>'secretVersion') IN ('latest','current')
 OR NOT coalesce(t->>'providerId' ~ '^[a-z][a-z0-9.-]{0,127}$',false)
 OR length(t->>'providerOrigin')>2048 OR NOT coalesce(t->>'providerOrigin' ~ '^https://([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])(:[1-9][0-9]{0,4})?$',false)
 OR NOT coalesce(t->>'providerTlsSpkiDigest' ~ '^sha256:[0-9a-f]{64}$',false)
 OR NOT coalesce(t->>'workerProfileDigest' ~ '^sha256:[0-9a-f]{64}$',false)
 OR NOT coalesce(t->>'publicKeySpkiHex' ~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$',false)
 OR NOT coalesce(t->>'workerIssuerSpkiHex' ~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$',false)
 OR NEW.signer_id IS DISTINCT FROM 'sha256:'||encode(sha256(decode(t->>'publicKeySpkiHex','hex')),'hex')
 OR NOT coalesce(t->>'keyEpoch' ~ '^[1-9][0-9]{0,19}$',false)
 OR NOT coalesce(t->>'validFromNs' ~ '^(0|[1-9][0-9]{0,19})$',false)
 OR NOT coalesce(t->>'validUntilNs' ~ '^[1-9][0-9]{0,19}$',false)
 OR length(t->>'installationReference') NOT BETWEEN 1 AND 256
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-TRUST'; END IF;
 IF (t->>'keyEpoch')::numeric>18446744073709551615 OR (t->>'validUntilNs')::numeric>18446744073709551615
 OR (t->>'validFromNs')::numeric>=(t->>'validUntilNs')::numeric
 OR mod((t->>'validFromNs')::numeric,1000000)<>0 OR mod((t->>'validUntilNs')::numeric,1000000)<>0
 OR floor(extract(epoch from clock_timestamp())*1000)*1000000 NOT BETWEEN (t->>'validFromNs')::numeric AND (t->>'validUntilNs')::numeric-1
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-TIME'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_completion_worker WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
 AND installation_digest=NEW.worker_installation_digest AND state='ACTIVE';
 m:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF w.service_id<>'LS-CONTROL-WORK' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'
 OR w.signed_profile_digest IS DISTINCT FROM t->>'workerProfileDigest'
 OR w.installation->'pins'->>'issuerSpkiHex' IS DISTINCT FROM t->>'workerIssuerSpkiHex'
 ${['environmentId', 'principalId', 'workloadCredentialId', 'workloadEpoch', 'workloadId'].map((f) => `OR w.installation->'pins'->>'${f}' IS DISTINCT FROM t->>'${f}'`).join('\n ')}
 OR floor(extract(epoch from clock_timestamp())*1000) NOT BETWEEN (m->>'${field('validFromMs')}')::numeric AND (m->>'${field('validUntilMs')}')::numeric-1
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-WORKER'; END IF;
 SELECT * INTO STRICT c FROM control.credential WHERE participant_id=NEW.participant_id AND credential_id=w.workload_credential_id AND principal_id=w.principal_id;
 IF c.kind<>'WORKLOAD_MTLS' OR c.state<>'ACTIVE' OR c.credential_epoch::text IS DISTINCT FROM t->>'workloadEpoch'
 OR c.audience IS DISTINCT FROM t->>'workloadId' OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp() OR c.valid_until IS NULL
 OR NEW.signer_id=t->>'providerTlsSpkiDigest' OR t->>'providerTlsSpkiDigest'='sha256:'||encode(sha256(decode(t->>'workerIssuerSpkiHex','hex')),'hex')
 OR c.public_key_digest=decode(substring(t->>'providerTlsSpkiDigest' from 8),'hex')
 OR c.public_key_digest=decode(substring(NEW.signer_id from 8),'hex')
 OR NEW.signer_id='sha256:'||encode(sha256(decode(t->>'workerIssuerSpkiHex','hex')),'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-IDENTITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_completion_disposition_signer_installation_guard ON control.notification_completion_disposition_signer_installation;
CREATE TRIGGER notification_completion_disposition_signer_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_completion_disposition_signer_installation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_completion_disposition_signer_installation();
REVOKE ALL ON FUNCTION openpc.guard_notification_completion_disposition_signer_installation() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_disposition_signer_truncate() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_completion_disposition_signer_truncate_guard ON control.notification_completion_disposition_signer_installation;
CREATE TRIGGER notification_completion_disposition_signer_truncate_guard BEFORE TRUNCATE ON control.notification_completion_disposition_signer_installation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_completion_disposition_signer_truncate();
REVOKE ALL ON FUNCTION openpc.guard_notification_completion_disposition_signer_truncate() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_disposition_signer_owner() RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF current_setting('session_replication_role')<>'origin' OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_completion_disposition_signer_installation'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_completion_disposition_signer_installation'::regclass AND tgname='notification_completion_disposition_signer_installation_guard' AND tgenabled IN ('O','A') AND NOT tgisinternal)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_completion_disposition_signer_installation'::regclass AND tgname='notification_completion_disposition_signer_truncate_guard' AND tgenabled IN ('O','A') AND NOT tgisinternal)
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-OWNER'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_completion_disposition_signer_owner() FROM PUBLIC;
`;

const hash = (x) => `'sha256:'||encode(sha256(${x}),'hex')`;
const jsonHash = (x) => hash(`convert_to(openpc.signing_canonical_json(${x}),'UTF8')`);
const receiptFields = family.fields
  .filter((f) => f.name !== 'schemaDefinitionDigest')
  .flatMap((f) => {
    let value;
    if (f.type === 'H32') value = `'sha256:'||(m->'${f.key}'->>'bytes')`;
    else if (f.type === 'uuidv7') value = `(m->'${f.key}'->>'bytes')::uuid::text`;
    else if (f.type === 'safe_uint') value = `(m->>'${f.key}')::numeric`;
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
/** Feature-owned native proof, with source provenance checked before event
 * semantics. Shared authority/terminal effect dispatch stays canonical. */
const nativeProofSql =
  `
CREATE OR REPLACE FUNCTION openpc.notification_completion_source_envelope(e control.outbox_event) RETURNS jsonb
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('participantId',e.participant_id,'privacyDomainId',e.privacy_domain_id,'eventId',e.event_id,'eventType',e.event_type,'aggregateType',e.aggregate_type,'aggregateId',e.aggregate_id,
 'sequence',e.business_sequence::text,'aggregateSequence',e.aggregate_sequence::text,'proofKind',e.proof_kind,'namespace',e.sequence_namespace,'source',e.source,'subject',e.subject,
 'correlationId',e.correlation_id,'causationId',e.causation_id,'dataSchema',e.data_schema_uri,'payloadHex',encode(e.payload_cbor,'hex'),
 'payloadDigest',encode(e.payload_digest,'hex'),'occurredAtUs',floor(extract(epoch from e.occurred_at)*1000000)::text,
 'receiptId',e.receipt_id,'coseHex',encode(e.cose_sign1,'hex'),'authorityGenerationHex',encode(e.authority_generation,'hex'),'webauthnAssertionBindingDigest',encode(e.webauthn_assertion_binding_digest,'hex'));
$$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_source_origin(event uuid,receipt_digest text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE e control.outbox_event%ROWTYPE;o control.notification_delivery_outcome%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=e.participant_id AND privacy_domain_id=e.privacy_domain_id AND operation_id=e.correlation_id AND receipt_id=e.event_id;
 PERFORM openpc.check_notification_outcome_publication_receipt(o);
 IF e.proof_kind IS DISTINCT FROM 'NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' OR e.sequence_namespace IS DISTINCT FROM 'NOTIFICATION_DELIVERY_COMPLETED_V1'
 OR e.source IS DISTINCT FROM 'urn:openpc:service:LS-NOTIFICATION' OR e.event_type IS DISTINCT FROM 'io.openpc.notification.delivery.completed.v1'
 OR o.receipt_digest IS DISTINCT FROM receipt_digest OR (o.transition->'receipt'->>'afterDeliveryState' IN ('DELIVERED','FAILED')) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'COMPLETION-SOURCE-ORIGIN'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_validated_source(event uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE e control.outbox_event%ROWTYPE;
BEGIN
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 PERFORM openpc.check_notification_outcome_publication_original(e.correlation_id);
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_signing_preparation(event uuid,preparation jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_completion_source%ROWTYPE;signer control.notification_completion_disposition_signer_installation%ROWTYPE;w control.installed_notification_completion_worker%ROWTYPE;
 t jsonb:=preparation->'preparation';q jsonb:=preparation->'request';j jsonb;attempts jsonb;last_attempt jsonb;initial_profile jsonb;current_profile jsonb;m jsonb;r jsonb;before_state jsonb;after_state jsonb;expected_work text;expected_work_id text;expected_outcome text;counted integer;n numeric;
BEGIN
 SELECT * INTO STRICT s FROM control.notification_completion_source WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 PERFORM openpc.check_notification_completion_source_origin(event,s.source->'reference'->>'receiptDigest');
 SELECT jsonb_agg(attempt ORDER BY number),count(*) INTO attempts,counted FROM control.notification_completion_attempt WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND event_id=event;
 j:=jsonb_build_object('source',s.source->'reference','initialWorker',s.initial_worker,'effectiveLimit',s.effective_limit,'attempts',attempts);
 last_attempt:=attempts->(counted-1);initial_profile:=openpc.business_cbor(decode(s.initial_worker->'signed'->>'payloadHex','hex'));
 m:=openpc.business_cbor(decode(q->>'payloadHex','hex'));r:=jsonb_build_object(${receiptFields});
 SELECT * INTO STRICT signer FROM control.notification_completion_disposition_signer_installation WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND trust_digest=q->>'signerInstallationDigest';
 SELECT * INTO STRICT w FROM control.installed_notification_completion_worker WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 current_profile:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF preparation-ARRAY['schema','preparation','request','requestDigest'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(preparation))<>4 OR preparation->>'schema' IS DISTINCT FROM 'pc.notification.completion-disposition-signing.v1'
 OR t-ARRAY['journal','workerInstallation','signerInstallation','metadata','disposition','producerOutcome','producerWorkItemId'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(t))<>7
 OR t->'journal' IS DISTINCT FROM j OR counted<1 OR counted>(initial_profile->>'${field('maximumAttempts')}')::integer
 OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${family.definitionDigest.slice(7)}') OR (SELECT count(*) FROM jsonb_object_keys(m))<>${family.fields.length}
 OR r->>'sourceEventId' IS DISTINCT FROM event::text OR r->>'participantId' IS DISTINCT FROM s.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM s.privacy_domain_id::text
 OR r->>'initialWorkerInstallationDigest' IS DISTINCT FROM s.initial_worker_installation_digest OR r->>'initialWorkerProfileDigest' IS DISTINCT FROM s.initial_worker->'pins'->>'signedProfileDigest'
 OR r->>'attemptChainDigest' IS DISTINCT FROM ${jsonHash("j||jsonb_build_object('schema','pc.notification.completion-attempt-chain.v1')")}
 OR r->'attemptCount' IS DISTINCT FROM to_jsonb(counted) OR r->'attemptLimit' IS DISTINCT FROM to_jsonb(s.effective_limit)
 OR s.effective_limit>(initial_profile->>'${field('maximumAttempts')}')::numeric OR s.effective_limit>(current_profile->>'${field('maximumAttempts')}')::numeric
 OR r->'initialAttemptLimit' IS DISTINCT FROM initial_profile->'${field('maximumAttempts')}' OR r->'initialBackoffMs' IS DISTINCT FROM initial_profile->'${field('initialBackoffMs')}' OR r->'maximumBackoffMs' IS DISTINCT FROM initial_profile->'${field('maximumBackoffMs')}'
 ${[
   ['sourceEnvelopeDigest', 'envelopeDigest'],
   ['sourceDataDigest', 'dataDigest'],
   ['sourcePartitionDigest', 'partitionDigest'],
   ['producerTrustDigest', 'producerTrustDigest'],
   ['sourceReceiptDigest', 'receiptDigest'],
 ]
   .map(([a, b]) => `OR r->>'${a}' IS DISTINCT FROM s.source->'reference'->>'${b}'`)
   .join('\n ')}
 OR r->>'receiptId' IS DISTINCT FROM q->>'signingAttemptId' OR r->>'operationId' IS DISTINCT FROM q->>'operationId' OR r->>'receiptId'=r->>'operationId' OR event::text IN (r->>'receiptId',r->>'operationId')
 OR t->'metadata' IS DISTINCT FROM jsonb_build_object('receiptId',r->'receiptId','operationId',r->'operationId','authoritySnapshotDigest',r->'authoritySnapshotDigest','recordedAtMs',r->'recordedAtMs','beforeStateDigest',r->'beforeStateDigest','afterStateDigest',r->'afterStateDigest')
 OR t->>'disposition' IS DISTINCT FROM r->>'disposition' OR (r->>'recordedAtMs')::numeric<(last_attempt->>'finishedAtMs')::numeric
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-JOURNAL'; END IF;
 IF r->>'disposition'='ADMITTED' THEN
  IF last_attempt->>'state' IS DISTINCT FROM 'VALIDATED' OR r->>'safeProblem' IS DISTINCT FROM 'NONE' OR r->>'cursorMode' IS DISTINCT FROM 'ADVANCE' THEN RAISE EXCEPTION 'COMPLETION-SIGNING-ADMITTED'; END IF;
  PERFORM openpc.check_notification_completion_validated_source(event);
  SELECT transition->'receipt'->>'afterDeliveryState' INTO STRICT expected_outcome FROM control.notification_delivery_outcome WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND receipt_id=event;
  expected_work:=CASE expected_outcome WHEN 'FAILED' THEN 'DELIVERY_FAILURE' ELSE 'NONE' END;
  expected_work_id:=CASE expected_outcome WHEN 'FAILED' THEN event::text ELSE r->>'receiptId' END;
  IF t->>'producerOutcome' IS DISTINCT FROM expected_outcome OR t->'producerWorkItemId' IS DISTINCT FROM (CASE expected_outcome WHEN 'FAILED' THEN to_jsonb(event::text) ELSE 'null'::jsonb END) THEN RAISE EXCEPTION 'COMPLETION-SIGNING-PRODUCER'; END IF;
 ELSIF r->>'disposition'='QUARANTINED' THEN
  IF last_attempt->>'state' IS DISTINCT FROM 'FAILED' OR counted<s.effective_limit OR r->>'safeProblem' IS DISTINCT FROM 'PC-OPS-9001' OR r->>'cursorMode' IS DISTINCT FROM 'HOLD' OR t->'producerOutcome' IS DISTINCT FROM 'null'::jsonb OR t->'producerWorkItemId' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'COMPLETION-SIGNING-QUARANTINE'; END IF;
  expected_work:='REMEDIATION';expected_work_id:=r->>'receiptId';
 ELSE RAISE EXCEPTION 'COMPLETION-SIGNING-DISPOSITION';END IF;
 before_state:=jsonb_build_object('schema','pc.notification.completion-disposition-state.v1','journal',j,'disposition',NULL);
 after_state:=before_state||jsonb_build_object('disposition',r->'disposition','receiptId',r->'receiptId','operationId',r->'operationId','workItemKind',expected_work,'workItemId',expected_work_id,'cursorMode',r->'cursorMode');
 IF r->>'workItemKind' IS DISTINCT FROM expected_work OR r->>'workItemId' IS DISTINCT FROM expected_work_id OR r->>'beforeStateDigest' IS DISTINCT FROM ${jsonHash('before_state')} OR r->>'afterStateDigest' IS DISTINCT FROM ${jsonHash('after_state')}
 OR q-ARRAY['schemaVersion','method','purpose','signerInstallationDigest','providerId','secretClass','reference','version','keyEpoch','signerKeyId','environmentId','participantId','privacyDomainId','workloadCredentialId','workloadEpoch','workerInstallationDigest','workerProfileDigest','signingAttemptId','operationId','sourceEventId','attemptChainDigest','dispositionPreparationDigest','payloadHex'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(q))<>23
 OR q->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR q->>'method' IS DISTINCT FROM 'SIGN_NOTIFICATION_COMPLETION_DISPOSITION' OR q->>'purpose' IS DISTINCT FROM 'pc.cose.notification-completion-disposition-receipt.v1'
 OR q->>'dispositionPreparationDigest' IS DISTINCT FROM ${jsonHash('t')} OR preparation->>'requestDigest' IS DISTINCT FROM ${hash("convert_to('pc.notification.completion-disposition-provider-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(q),'UTF8')")}
 OR t->'workerInstallation' IS DISTINCT FROM w.installation OR t->'signerInstallation' IS DISTINCT FROM signer.trust-ARRAY['schema','schemaDefinitionDigest','signerKeyId']
 OR signer.trust->>'purpose' IS DISTINCT FROM 'pc.cose.notification-completion-disposition-receipt.v1' OR signer.trust->>'owner' IS DISTINCT FROM 'LS-CONTROL-WORK'
 ${['environmentId', 'participantId', 'privacyDomainId', 'workerInstallationDigest', 'workerProfileDigest', 'signerKeyId', 'providerId', 'secretClass', 'keyEpoch', 'workloadCredentialId', 'workloadEpoch'].map((k) => `OR q->>'${k}' IS DISTINCT FROM signer.trust->>'${k}'`).join('\n ')}
 OR q->>'reference' IS DISTINCT FROM signer.trust->>'secretReference' OR q->>'version' IS DISTINCT FROM signer.trust->>'secretVersion'
 ${['environmentId', 'participantId', 'privacyDomainId', 'workerInstallationDigest', 'workerProfileDigest', 'signerKeyId', 'signerInstallationDigest', 'sourceEventId', 'attemptChainDigest'].map((k) => `OR r->>'${k}' IS DISTINCT FROM q->>'${k}'`).join('\n ')}
 OR w.producer_trust_digest IS DISTINCT FROM r->>'producerTrustDigest'
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-BINDING'; END IF;
 n:=(r->>'recordedAtMs')::numeric;
 IF n<(current_profile->>'${field('validFromMs')}')::numeric OR n>=(current_profile->>'${field('validUntilMs')}')::numeric OR n*1000000<(signer.trust->>'validFromNs')::numeric OR n*1000000>=(signer.trust->>'validUntilNs')::numeric THEN RAISE EXCEPTION 'COMPLETION-SIGNING-TIME'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_signing_current(event uuid,preparation jsonb,phase text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_completion_disposition_signer_installation%ROWTYPE;w control.installed_notification_completion_worker%ROWTYPE;c control.credential%ROWTYPE;m jsonb;n numeric;
BEGIN
 IF phase IS NULL OR phase NOT IN ('PREPARE','SIGN_CLAIM') THEN RAISE EXCEPTION 'COMPLETION-SIGNING-PHASE'; END IF;
 PERFORM openpc.check_notification_completion_signing_preparation(event,preparation);
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-disposition-signer:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT s FROM control.notification_completion_disposition_signer_installation WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND trust_digest=preparation->'request'->>'signerInstallationDigest' AND state='ACTIVE';
 SELECT * INTO STRICT w FROM control.installed_notification_completion_worker WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND installation_digest=s.worker_installation_digest AND state='ACTIVE';
 SELECT * INTO STRICT c FROM control.credential WHERE participant_id=w.participant_id AND credential_id=w.workload_credential_id AND principal_id=w.principal_id;
 m:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));n:=floor(extract(epoch from clock_timestamp())*1000);
 IF c.state<>'ACTIVE' OR c.kind<>'WORKLOAD_MTLS' OR c.credential_epoch::text IS DISTINCT FROM w.installation->'pins'->>'workloadEpoch' OR c.valid_until IS NULL OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp()
 OR n<(m->>'${field('validFromMs')}')::numeric OR n>=(m->>'${field('validUntilMs')}')::numeric OR n*1000000<(s.trust->>'validFromNs')::numeric OR n*1000000>=(s.trust->>'validUntilNs')::numeric
 OR n<(preparation->'preparation'->'metadata'->>'recordedAtMs')::numeric
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-CURRENT'; END IF;
 PERFORM openpc.check_notification_completion_effect_binding(event,phase,w.installation_digest,preparation->'preparation'->'metadata'->>'authoritySnapshotDigest');
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_signing_observation(event uuid,ob jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_completion_disposition_signing%ROWTYPE;q jsonb;signer control.notification_completion_disposition_signer_installation%ROWTYPE;w jsonb;
BEGIN
 SELECT * INTO STRICT s FROM control.notification_completion_disposition_signing WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 q:=s.preparation->'request';PERFORM openpc.check_notification_completion_signing_preparation(event,s.preparation);
 SELECT * INTO STRICT signer FROM control.notification_completion_disposition_signer_installation WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND trust_digest=s.signer_installation_digest;
 SELECT openpc.business_cbor(decode(installation->'signed'->>'payloadHex','hex')) INTO STRICT w FROM control.installed_notification_completion_worker WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 IF s.state NOT IN ('DISPATCHED','OBSERVED') OR s.dispatched_at_ms IS NULL
 OR ob-ARRAY['schemaVersion','providerId','signingAttemptId','requestDigest','recordedAtMs','outcome','reason','coseHex'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(ob))<>8
 OR ob->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR ob->>'providerId' IS DISTINCT FROM q->>'providerId' OR ob->>'signingAttemptId' IS DISTINCT FROM s.signing_attempt_id::text OR ob->>'requestDigest' IS DISTINCT FROM s.request_digest
 OR (jsonb_typeof(ob->'recordedAtMs')='number' AND (ob->>'recordedAtMs') ~ '^(0|[1-9][0-9]*)$' AND (ob->>'recordedAtMs')::numeric<=9007199254740991) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-OBSERVATION'; END IF;
 IF ob->>'outcome'='SIGNED' THEN
  IF ob->'reason' IS DISTINCT FROM 'null'::jsonb OR (ob->>'recordedAtMs')::numeric<s.dispatched_at_ms OR (ob->>'recordedAtMs')::numeric>=(w->>'${field('validUntilMs')}')::numeric OR (ob->>'recordedAtMs')::numeric*1000000>=(signer.trust->>'validUntilNs')::numeric
  THEN RAISE EXCEPTION 'COMPLETION-SIGNING-OBSERVATION-TIME'; END IF;
  PERFORM openpc.archive_cose_binding(decode(q->>'payloadHex','hex'),decode(ob->>'coseHex','hex'),signer.signer_id,${family.schemaId},${family.purposeCode});
 ELSIF ob->>'outcome' IS DISTINCT FROM 'REJECTED' OR ob->'coseHex' IS DISTINCT FROM 'null'::jsonb OR (ob->>'reason' IN ('REVOKED','EXPIRED','WRONG_SCOPE','INVALID_REQUEST','ATTEMPT_CONFLICT','KEY_UNAVAILABLE')) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-OBSERVATION-REJECTION'; END IF;
 IF s.state='OBSERVED' AND s.observation IS DISTINCT FROM ob THEN RAISE EXCEPTION 'COMPLETION-SIGNING-FIRST'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_disposition_signed(event uuid,t jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.notification_completion_disposition_signing%ROWTYPE;m jsonb;r jsonb;
BEGIN
 SELECT * INTO STRICT s FROM control.notification_completion_disposition_signing WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 PERFORM openpc.check_notification_completion_signing_preparation(event,s.preparation);
 PERFORM openpc.check_notification_completion_signing_observation(event,s.observation);
 m:=openpc.business_cbor(decode(s.preparation->'request'->>'payloadHex','hex'));r:=jsonb_build_object(${receiptFields});
 IF s.state IS DISTINCT FROM 'OBSERVED' OR s.observation->>'outcome' IS DISTINCT FROM 'SIGNED'
 OR t IS DISTINCT FROM jsonb_build_object('schema','pc.notification.completion-disposition.v1','input',s.preparation->'preparation','receipt',r,'payloadHex',s.preparation->'request'->>'payloadHex','coseHex',s.observation->>'coseHex')
 THEN RAISE EXCEPTION 'COMPLETION-DISPOSITION-SIGNED'; END IF;
END $$;
` +
  [
    'notification_completion_source_envelope(control.outbox_event)',
    'check_notification_completion_source_origin(uuid,text)',
    'check_notification_completion_validated_source(uuid)',
    'check_notification_completion_signing_preparation(uuid,jsonb)',
    'check_notification_completion_signing_current(uuid,jsonb,text)',
    'check_notification_completion_signing_observation(uuid,jsonb)',
    'check_notification_completion_disposition_signed(uuid,jsonb)',
  ]
    .map((fn) => `REVOKE ALL ON FUNCTION openpc.${fn} FROM PUBLIC;`)
    .join('\n');

/** Shared owner must provide exact native per-phase admission and deferred
 * atomic proof; no GUC, runtime role membership or JS object grants effects. */
export const notificationCompletionDispositionGuardsSql =
  notificationCompletionDispositionSignerGuardsSql +
  nativeProofSql +
  notificationCompletionDispositionPhaseGuardsSql +
  notificationCompletionDispositionStructureGuardsSql +
  String.raw`
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_source() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb; m jsonb;e control.outbox_event%ROWTYPE;o control.notification_delivery_outcome%ROWTYPE;start_signer text;expected_selector jsonb;current_limit numeric;binding record;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'COMPLETION-SOURCE-IMMUTABLE'; END IF;
 PERFORM openpc.require_notification_completion_disposition_authority(NEW.event_id,CASE WHEN TG_OP='INSERT' THEN 'CLAIM' ELSE 'LIMIT' END);
 PERFORM openpc.check_notification_completion_phase_source(NEW.event_id,CASE WHEN TG_OP='INSERT' THEN 'CLAIM' ELSE 'LIMIT' END);
 SELECT * INTO STRICT binding FROM openpc.notification_completion_phase_binding(NEW.event_id,CASE WHEN TG_OP='INSERT' THEN 'CLAIM' ELSE 'LIMIT' END);
 IF TG_OP='INSERT' AND NEW.initial_worker_installation_digest IS DISTINCT FROM binding.installation_digest THEN RAISE EXCEPTION 'COMPLETION-SOURCE-WORKER'; END IF;
 IF TG_OP='UPDATE' THEN
  SELECT (openpc.business_cbor(decode(installation->'signed'->>'payloadHex','hex'))->>'${field('maximumAttempts')}')::numeric INTO STRICT current_limit FROM control.installed_notification_completion_worker WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND state='ACTIVE' AND installation_digest=binding.installation_digest;
  IF to_jsonb(OLD)-'effective_limit' IS DISTINCT FROM to_jsonb(NEW)-'effective_limit' OR NEW.effective_limit IS DISTINCT FROM least(OLD.effective_limit,current_limit) OR NEW.effective_limit<1
   OR EXISTS(SELECT 1 FROM control.notification_completion_disposition_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id)
  THEN RAISE EXCEPTION 'COMPLETION-BUDGET-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-completion-source:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.event_id::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 p:=NEW.source->'reference';
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 SELECT * INTO STRICT o FROM control.notification_delivery_outcome WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.event_id AND operation_id=e.correlation_id;
 SELECT signer_installation_digest INTO STRICT start_signer FROM control.notification_delivery_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND operation_id=o.start_operation_id;
 expected_selector:=jsonb_build_object('operationId',o.operation_id::text,'signerInstallationDigest',o.signer_installation_digest,
  'worker',jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'installationDigest',o.worker_installation_digest),
  'original',jsonb_build_object('operationId',o.start_operation_id::text,'signerInstallationDigest',start_signer,
   'source',jsonb_build_object('notificationOccurrenceId',o.notification_occurrence_id::text,'eventId',o.transition->'input'->'observation'->'original'->'source'->>'eventId',
    'worker',jsonb_build_object('participantId',NEW.participant_id::text,'privacyDomainId',NEW.privacy_domain_id::text,'installationDigest',o.transition->'input'->'observation'->'original'->>'workerInstallationDigest'))));
 IF NEW.source->'envelope' IS DISTINCT FROM openpc.notification_completion_source_envelope(e) OR NEW.original_selector IS DISTINCT FROM expected_selector
 OR p->>'dataDigest' IS DISTINCT FROM 'sha256:'||encode(e.payload_digest,'hex') OR p->>'receiptDigest' IS DISTINCT FROM o.receipt_digest
 OR p->>'partitionDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object('source','urn:openpc:service:LS-NOTIFICATION','notificationOccurrenceId',o.notification_occurrence_id::text)),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'COMPLETION-SOURCE-ORIGINAL'; END IF;
 IF NEW.source_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.source),'UTF8')
 OR NEW.source_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.source_bytes),'hex')
 OR p->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR p->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR p->>'eventId' IS DISTINCT FROM NEW.event_id::text
 OR NEW.source->'originalSelector' IS DISTINCT FROM NEW.original_selector
 OR p->>'envelopeDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.source->'envelope'),'UTF8')),'hex')
 OR NOT EXISTS(SELECT 1 FROM control.installed_notification_completion_worker w WHERE w.participant_id=NEW.participant_id AND w.privacy_domain_id=NEW.privacy_domain_id AND w.installation_digest=NEW.initial_worker_installation_digest AND w.installation=NEW.initial_worker AND w.state='ACTIVE')
 THEN RAISE EXCEPTION 'COMPLETION-SOURCE-BINDING'; END IF;
 m:=openpc.business_cbor(decode(NEW.initial_worker->'signed'->>'payloadHex','hex'));
 IF NEW.effective_limit IS DISTINCT FROM (m->>'${field('maximumAttempts')}')::numeric
 OR p->>'producerTrustDigest' IS DISTINCT FROM NEW.initial_worker->'pins'->>'producerTrustDigest'
 OR NOT EXISTS(SELECT 1 FROM control.installed_notification_worker producer WHERE producer.participant_id=o.participant_id AND producer.privacy_domain_id=o.privacy_domain_id AND producer.installation_digest=o.worker_installation_digest AND openpc.business_cbor(decode(producer.installation->'signed'->>'payloadHex','hex'))->'${producerTrustField}' IS NOT DISTINCT FROM openpc.business_bytes(decode(substr(p->>'producerTrustDigest',8),'hex')))
 THEN RAISE EXCEPTION 'COMPLETION-SOURCE-PROFILE'; END IF;
 PERFORM openpc.check_notification_completion_source_origin(NEW.event_id,p->>'receiptDigest');
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_attempt() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a jsonb;p jsonb;s control.notification_completion_source%ROWTYPE;previous control.notification_completion_attempt%ROWTYPE;n numeric;delay numeric;counted numeric;source_valid boolean;failure text;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-IMMUTABLE'; END IF;
 PERFORM openpc.require_notification_completion_disposition_authority(NEW.event_id,CASE WHEN TG_OP='INSERT' THEN 'CLAIM' ELSE 'FINISH' END);
 PERFORM openpc.check_notification_completion_phase_source(NEW.event_id,CASE WHEN TG_OP='INSERT' THEN 'CLAIM' ELSE 'FINISH' END);
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-completion-source:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.event_id::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF EXISTS(SELECT 1 FROM control.notification_completion_disposition_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id) THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-SEALED'; END IF;
 a:=NEW.attempt;n:=floor(extract(epoch from clock_timestamp())*1000);
 IF a-ARRAY['attemptId','number','workerInstallationDigest','authorityDigest','claimedAtMs','leaseUntilMs','state','finishedAtMs','nextAttemptAtMs'] IS DISTINCT FROM '{}'::jsonb
 OR NOT a ?& ARRAY['attemptId','number','workerInstallationDigest','authorityDigest','claimedAtMs','leaseUntilMs','state','finishedAtMs','nextAttemptAtMs']
 OR a->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR a->'number' IS DISTINCT FROM to_jsonb(NEW.number)
 OR NEW.attempt_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(a),'UTF8') OR NEW.attempt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.attempt_bytes),'hex')
 OR (a->>'authorityDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
 OR (a->>'workerInstallationDigest' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
 OR (jsonb_typeof(a->'claimedAtMs')='number' AND (a->>'claimedAtMs') ~ '^(0|[1-9][0-9]*)$') IS DISTINCT FROM true
 OR (jsonb_typeof(a->'leaseUntilMs')='number' AND (a->>'leaseUntilMs') ~ '^(0|[1-9][0-9]*)$') IS DISTINCT FROM true
 OR (a->>'leaseUntilMs')::numeric<=(a->>'claimedAtMs')::numeric OR (a->>'leaseUntilMs')::numeric>(a->>'claimedAtMs')::numeric+30000
 THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-BINDING'; END IF;
 SELECT * INTO STRICT s FROM control.notification_completion_source WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 p:=openpc.business_cbor(decode(s.initial_worker->'signed'->>'payloadHex','hex'));
 IF TG_OP='INSERT' THEN
  PERFORM openpc.check_notification_completion_effect_binding(NEW.event_id,'CLAIM',a->>'workerInstallationDigest',a->>'authorityDigest');
  SELECT count(*) INTO counted FROM control.notification_completion_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
  IF NEW.number<>counted+1 OR NEW.number>s.effective_limit OR a->>'state' IS DISTINCT FROM 'LEASED' OR a->'finishedAtMs' IS DISTINCT FROM 'null'::jsonb OR a->'nextAttemptAtMs' IS DISTINCT FROM 'null'::jsonb
   OR (a->>'claimedAtMs')::numeric>n OR (a->>'leaseUntilMs')::numeric<=n
  THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-ADMISSION'; END IF;
  IF NEW.number=1 THEN
   IF a->>'workerInstallationDigest' IS DISTINCT FROM s.initial_worker_installation_digest THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-FIRST'; END IF;
  ELSE
   SELECT * INTO STRICT previous FROM control.notification_completion_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id AND number=NEW.number-1;
   IF previous.attempt->>'state' NOT IN ('FAILED','RELEASED') OR (a->>'claimedAtMs')::numeric<(previous.attempt->>'nextAttemptAtMs')::numeric THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-BACKOFF'; END IF;
  END IF;
 ELSE
  IF to_jsonb(OLD)-ARRAY['attempt','attempt_bytes','attempt_digest'] IS DISTINCT FROM to_jsonb(NEW)-ARRAY['attempt','attempt_bytes','attempt_digest']
   OR OLD.attempt-ARRAY['state','finishedAtMs','nextAttemptAtMs'] IS DISTINCT FROM a-ARRAY['state','finishedAtMs','nextAttemptAtMs'] OR OLD.attempt->>'state' IS DISTINCT FROM 'LEASED'
   OR a->>'state' NOT IN ('VALIDATED','FAILED','RELEASED') OR (jsonb_typeof(a->'finishedAtMs')='number' AND (a->>'finishedAtMs') ~ '^(0|[1-9][0-9]*)$') IS DISTINCT FROM true
   OR (a->>'finishedAtMs')::numeric<(a->>'claimedAtMs')::numeric OR (a->>'finishedAtMs')::numeric>n
  THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-TRANSITION'; END IF;
  IF n<(OLD.attempt->>'leaseUntilMs')::numeric THEN
   PERFORM openpc.check_notification_completion_effect_binding(NEW.event_id,'FINISH',OLD.attempt->>'workerInstallationDigest',OLD.attempt->>'authorityDigest');
  END IF;
  IF a->>'state'='VALIDATED' THEN
   IF a->'nextAttemptAtMs' IS DISTINCT FROM 'null'::jsonb OR n>=(a->>'leaseUntilMs')::numeric OR (a->>'finishedAtMs')::numeric>=(a->>'leaseUntilMs')::numeric THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-EXPIRED'; END IF;
   PERFORM openpc.check_notification_completion_validated_source(NEW.event_id);
  ELSE
   IF a->>'state'='FAILED' AND (a->>'finishedAtMs')::numeric<(a->>'leaseUntilMs')::numeric THEN
    source_valid:=true;
    BEGIN
     PERFORM openpc.check_notification_completion_validated_source(NEW.event_id);
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
     GET STACKED DIAGNOSTICS failure=MESSAGE_TEXT;
     IF failure NOT LIKE 'NOTIFICATION-OUTCOME-PUBLICATION-%' THEN RAISE; END IF;
     source_valid:=false;
    END;
    IF source_valid THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-FALSE-FAILURE'; END IF;
   END IF;
   delay:=least((p->>'${field('maximumBackoffMs')}')::numeric,(p->>'${field('initialBackoffMs')}')::numeric*power(2,least(NEW.number-1,52)));
   IF a->'nextAttemptAtMs' IS DISTINCT FROM to_jsonb((a->>'finishedAtMs')::numeric+delay) THEN RAISE EXCEPTION 'COMPLETION-ATTEMPT-RETRY'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_signing() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE phase text;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'COMPLETION-SIGNING-IMMUTABLE'; END IF;
 phase:=CASE WHEN TG_OP='INSERT' THEN 'PREPARE' WHEN NEW.state='DISPATCHED' THEN 'SIGN_CLAIM' ELSE 'OBSERVE' END;
 PERFORM openpc.require_notification_completion_disposition_authority(NEW.event_id,phase);
 PERFORM openpc.check_notification_completion_phase_source(NEW.event_id,phase);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' THEN RAISE EXCEPTION 'COMPLETION-SIGNING-INITIAL'; END IF;
  PERFORM openpc.check_notification_completion_signing_current(NEW.event_id,NEW.preparation,phase);
 ELSE
  IF to_jsonb(OLD)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest'] IS DISTINCT FROM to_jsonb(NEW)-ARRAY['state','dispatch_token','dispatched_at_ms','observation','observation_bytes','observation_digest']
   OR NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED') OR (OLD.state='DISPATCHED' AND NEW.state='OBSERVED' AND NEW.dispatch_token=OLD.dispatch_token AND NEW.dispatched_at_ms=OLD.dispatched_at_ms))
  THEN RAISE EXCEPTION 'COMPLETION-SIGNING-TRANSITION'; END IF;
  IF NEW.state='DISPATCHED' THEN
   PERFORM openpc.check_notification_completion_signing_current(NEW.event_id,NEW.preparation,phase);
   IF NEW.dispatched_at_ms IS DISTINCT FROM floor(extract(epoch from clock_timestamp())*1000) AND (NEW.dispatched_at_ms>(extract(epoch from clock_timestamp())*1000) OR NEW.dispatched_at_ms<(NEW.preparation->'preparation'->'metadata'->>'recordedAtMs')::numeric) THEN RAISE EXCEPTION 'COMPLETION-SIGNING-DISPATCH-TIME'; END IF;
  END IF;
  IF NEW.state='OBSERVED' THEN
   IF NEW.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.observation),'UTF8')
    OR NEW.observation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.observation_bytes),'hex') THEN RAISE EXCEPTION 'COMPLETION-SIGNING-OBSERVATION'; END IF;
   PERFORM openpc.check_notification_completion_signing_observation(NEW.event_id,NEW.observation);
   IF NEW.observation->>'outcome'='SIGNED' THEN
    PERFORM openpc.check_notification_completion_receipt_admission(NEW.event_id,'OBSERVE',NEW.observation);
   END IF;
  END IF;
 END IF;
 IF NEW.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.preparation),'UTF8') OR NEW.request_digest IS DISTINCT FROM NEW.preparation->>'requestDigest'
 OR NEW.operation_id::text IS DISTINCT FROM NEW.preparation->'request'->>'operationId' OR NEW.signing_attempt_id::text IS DISTINCT FROM NEW.preparation->'request'->>'signingAttemptId'
 OR NEW.signer_installation_digest IS DISTINCT FROM NEW.preparation->'request'->>'signerInstallationDigest' OR NEW.event_id::text IS DISTINCT FROM NEW.preparation->'request'->>'sourceEventId'
 THEN RAISE EXCEPTION 'COMPLETION-SIGNING-BINDING'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_disposition() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'COMPLETION-DISPOSITION-IMMUTABLE'; END IF;
 PERFORM openpc.require_notification_completion_disposition_authority(NEW.event_id,'PUBLISH');
 PERFORM openpc.check_notification_completion_phase_source(NEW.event_id,'PUBLISH');
 IF NEW.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.transition),'UTF8')
 OR NEW.transition->'receipt'->>'sourceEventId' IS DISTINCT FROM NEW.event_id::text
 OR NEW.transition->'receipt'->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR NEW.transition->'receipt'->>'receiptId' IS DISTINCT FROM NEW.receipt_id::text
 OR NEW.transition->'receipt'->>'disposition' IS DISTINCT FROM NEW.disposition
 OR NEW.receipt_payload IS DISTINCT FROM decode(NEW.transition->>'payloadHex','hex') OR NEW.cose_sign1 IS DISTINCT FROM decode(NEW.transition->>'coseHex','hex')
 THEN RAISE EXCEPTION 'COMPLETION-DISPOSITION-BINDING'; END IF;
 PERFORM openpc.check_notification_completion_disposition_signed(NEW.event_id,NEW.transition);
 PERFORM openpc.check_notification_completion_receipt_admission(NEW.event_id,'PUBLISH',
  (SELECT observation FROM control.notification_completion_disposition_signing WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id));
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.complete_notification_completion_disposition() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN PERFORM openpc.check_notification_completion_disposition_original(NEW.event_id);RETURN NEW;END $$;
CREATE OR REPLACE FUNCTION openpc.complete_notification_completion_source() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE c integer;first_attempt jsonb;
BEGIN
 SELECT count(*) INTO c FROM control.notification_completion_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id;
 SELECT attempt INTO STRICT first_attempt FROM control.notification_completion_attempt WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND event_id=NEW.event_id AND number=1;
 IF c<1 OR first_attempt->>'workerInstallationDigest' IS DISTINCT FROM NEW.initial_worker_installation_digest THEN RAISE EXCEPTION 'COMPLETION-SOURCE-FIRST-ATTEMPT'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.reject_notification_completion_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'COMPLETION-DISPOSITION-IMMUTABLE';END $$;
` +
  [
    ['notification_completion_source', 'guard_notification_completion_source'],
    ['notification_completion_attempt', 'guard_notification_completion_attempt'],
    ['notification_completion_disposition_signing', 'guard_notification_completion_signing'],
    ['notification_completion_disposition', 'guard_notification_completion_disposition'],
  ]
    .map(
      ([table, fn]) => `
DROP TRIGGER IF EXISTS ${table}_guard ON control.${table};
CREATE TRIGGER ${table}_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.${fn}();
DROP TRIGGER IF EXISTS ${table}_truncate ON control.${table};
CREATE TRIGGER ${table}_truncate BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.reject_notification_completion_truncate();
REVOKE ALL ON FUNCTION openpc.${fn}() FROM PUBLIC;
`,
    )
    .join('') +
  `
DROP TRIGGER IF EXISTS notification_completion_source_first ON control.notification_completion_source;
CREATE CONSTRAINT TRIGGER notification_completion_source_first AFTER INSERT ON control.notification_completion_source DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.complete_notification_completion_source();
REVOKE ALL ON FUNCTION openpc.complete_notification_completion_source() FROM PUBLIC;
DROP TRIGGER IF EXISTS notification_completion_disposition_complete ON control.notification_completion_disposition;
CREATE CONSTRAINT TRIGGER notification_completion_disposition_complete AFTER INSERT ON control.notification_completion_disposition DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.complete_notification_completion_disposition();
REVOKE ALL ON FUNCTION openpc.complete_notification_completion_disposition() FROM PUBLIC;
REVOKE ALL ON FUNCTION openpc.reject_notification_completion_truncate() FROM PUBLIC;
`;
