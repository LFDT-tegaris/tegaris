import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const profile = notificationCoseProfiles.NotificationDeliveryReceiptV1;
const key = (name) => {
  const field = profile.fields.find((item) => item.name === name);
  if (!field) throw new Error('Missing native gateway receipt field');
  return field.key;
};
const hash = (value) => `'sha256:'||encode(sha256(${value}),'hex')`;
const jsonHash = (value) => hash(`convert_to(openpc.signing_canonical_json(${value}),'UTF8')`);
/** Native original/shape checks, not signature-verification or write admission.
 * The existing TS provider owner verifies ES256. Canonical must bind its exact
 * first receipt to the distinct signed Control result and deferred completeness.
 * These declarations grant nothing and deliberately install no INSERT owner.
 * The existing observation schema must first receive its canonical splice. */
export const notificationDeliveryOutcomeObservationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_observation_original(item control.notification_delivery_observation) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE start control.notification_delivery_start%ROWTYPE; intent control.notification_delivery_dispatch_intent%ROWTYPE;
 native jsonb; payload bytea; cose bytea; m jsonb; expected jsonb; signer text;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SCOPE'; END IF;
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.start_operation_id;
 SELECT * INTO STRICT intent FROM control.notification_delivery_dispatch_intent WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.start_operation_id;
 PERFORM openpc.check_notification_delivery_start_original(start);
 PERFORM openpc.check_notification_delivery_dispatch_intent_original(intent);
 IF start.attempt_id IS DISTINCT FROM item.attempt_id OR intent.state IS DISTINCT FROM 'CLAIMED'
 OR intent.claim_token IS DISTINCT FROM item.dispatch_claim_token OR item.operation_id IN (item.start_operation_id,start.source_operation_id,start.attempt_id)
 OR item.observed_at_ms<intent.claimed_at_ms OR item.observed_at_ms NOT BETWEEN 0 AND 9007199254740991
 OR octet_length(item.observation_bytes) NOT BETWEEN 1 AND 262144 OR item.observation_digest IS DISTINCT FROM ${hash('item.observation_bytes')}
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-ORIGINAL'; END IF;
 native:=convert_from(item.observation_bytes,'UTF8')::jsonb;
 IF item.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(native),'UTF8')
 OR jsonb_typeof(native) IS DISTINCT FROM 'object' OR jsonb_typeof(native->'signed') IS DISTINCT FROM 'object'
 OR (native->'signed'->>'payloadHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true
 OR length(native->'signed'->>'payloadHex') NOT BETWEEN 2 AND 131072
 OR (native->'signed'->>'coseHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true
 OR length(native->'signed'->>'coseHex') NOT BETWEEN 130 AND 262144
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-WIRE'; END IF;
 payload:=decode(native->'signed'->>'payloadHex','hex'); cose:=decode(native->'signed'->>'coseHex','hex');
 m:=openpc.business_cbor(payload);
 signer:=${hash("decode(start.transition->'channel'->'claims'->>'receiptSignerSpki','hex')")};
 expected:=jsonb_build_object(
 '${key('schemaDefinitionDigest')}',openpc.business_bytes(decode('${profile.definitionDigest.slice(7)}','hex')),
 '${key('environmentId')}',start.transition->'receipt'->'environmentId',
 '${key('participantId')}',openpc.business_bytes(uuid_send(item.participant_id)),
 '${key('privacyDomainId')}',openpc.business_bytes(uuid_send(item.privacy_domain_id)),
 '${key('receiptId')}',openpc.business_bytes(uuid_send(item.observation_id)),
 '${key('signedProfileDigest')}',openpc.business_bytes(decode(substr(start.transition->'channel'->>'signedProfileDigest',8),'hex')),
 '${key('attemptDigest')}',openpc.business_bytes(decode(substr(${jsonHash("start.transition->'attempt'")},8),'hex')),
 '${key('contextDigest')}',openpc.business_bytes(decode(substr(${jsonHash("start.transition->'context'")},8),'hex')),
 '${key('outcome')}',CASE item.outcome WHEN 'DELIVERED' THEN 1 WHEN 'RETRYABLE_NO_EFFECT' THEN 2 WHEN 'PERMANENT_FAILURE' THEN 3 WHEN 'AMBIGUOUS' THEN 4 END,
 '${key('observedAtMs')}',item.observed_at_ms,
 '${key('signerKeyId')}',openpc.business_bytes(decode(substr(signer,8),'hex')));
 IF m IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-NATIVE'; END IF;
 expected:=jsonb_build_object('signed',jsonb_build_object('payloadHex',encode(payload,'hex'),'coseHex',encode(cose,'hex')),
 'claims',jsonb_build_object('environmentId',start.transition->'receipt'->'environmentId','participantId',item.participant_id::text,'privacyDomainId',item.privacy_domain_id::text,
 'receiptId',item.observation_id::text,'signedProfileDigest',start.transition->'channel'->>'signedProfileDigest','attemptDigest',${jsonHash("start.transition->'attempt'")},
 'contextDigest',${jsonHash("start.transition->'context'")},'outcome',item.outcome,'observedAtMs',item.observed_at_ms,'signerKeyId',signer),
 'receiptDigest',${hash('cose')});
 IF native IS DISTINCT FROM expected THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-CLAIMS'; END IF;
 PERFORM openpc.archive_cose_binding(payload,cose,signer,${profile.schemaId},${profile.purposeCode});
END $$;
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_observation_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-FIRST-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_delivery_observation_immutable ON control.notification_delivery_observation;
CREATE TRIGGER notification_delivery_observation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_observation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_observation_mutation();
REVOKE ALL ON FUNCTION openpc.check_notification_delivery_observation_original(control.notification_delivery_observation),openpc.deny_notification_delivery_observation_mutation() FROM PUBLIC;
`;

/** Install only with the distinct outcome table. INSERT remains closed until
 * canonical supplies native signer admission and the full atomic result owner. */
export const notificationDeliveryOutcomeImmutabilityGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.deny_notification_delivery_outcome_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-RESULT-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_delivery_outcome_immutable ON control.notification_delivery_outcome;
CREATE TRIGGER notification_delivery_outcome_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_outcome
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_outcome_mutation();
REVOKE ALL ON FUNCTION openpc.deny_notification_delivery_outcome_mutation() FROM PUBLIC;
`;

const outcome = notificationCoseProfiles.NotificationDeliveryOutcomeReceiptV1;
const worker = notificationCoseProfiles.NotificationWorkerProfileV1;
const workerKey = (name) => {
  const field = worker.fields.find((f) => f.name === name);
  if (!field) throw new Error('Missing outcome worker field');
  return field.key;
};
const claimFields = outcome.fields.filter((f) => f.name !== 'schemaDefinitionDigest');
const decodedClaims = claimFields
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
        .map((part) => {
          const [name, number] = part.split('=');
          return `WHEN '${number}' THEN '${name}'`;
        })
        .join(' ')} ELSE NULL END`;
    else value = `m->'${f.key}'`;
    return [`'${f.name}'`, value];
  })
  .join(',');
const encodedClaims = outcome.fields
  .flatMap((f) => {
    const v = `r->>'${f.name}'`;
    let value;
    if (f.name === 'schemaDefinitionDigest')
      value = `openpc.business_bytes(decode('${outcome.definitionDigest.slice(7)}','hex'))`;
    else if (f.type === 'H32') value = `openpc.business_bytes(decode(substr(${v},8),'hex'))`;
    else if (f.type === 'uuidv7') value = `openpc.business_uuid((${v})::uuid)`;
    else if (f.type === 'safe_uint' || f.type === 'u64p') value = `(${v})::numeric`;
    else if (f.type.startsWith('enum '))
      value = `CASE ${v} ${f.type
        .slice(5)
        .split(' ')
        .map((part) => {
          const [name, number] = part.split('=');
          return `WHEN '${name}' THEN ${number}`;
        })
        .join(' ')} ELSE NULL END`;
    else value = v;
    return [`'${f.key}'`, value];
  })
  .join(',');
const projection = (row) =>
  `jsonb_build_object('participantId',${row}.participant_id::text,'privacyDomainId',${row}.privacy_domain_id::text,'notificationOccurrenceId',${row}.notification_occurrence_id::text,'payloadDigest',${row}.payload_digest,'state',${row}.state,'attemptCount',${row}.attempt_count,'attemptLimit',${row}.attempt_limit,'nextAttemptAtMs',${row}.next_attempt_at_ms,'lastStartedAtMs',${row}.last_started_at_ms,'cancelRequested',${row}.cancel_requested)`;
/** Feature-owned durable signing guards. Canonical registers these and grants
 * narrowly through its existing migration/security owner. Native crypto stays in
 * the real TS owner; framing is additional SQL defence, not signature admission.
 * No final projection, event/evidence/outbox or WorkItem write is allowed here. */
export const notificationDeliveryOutcomeSigningGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_outcome_signing_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE lock_name text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin' OR NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id',true) IS DISTINCT FROM 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_delivery_outcome_signing'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_outcome_signing'::regclass AND tgname='notification_outcome_signing_guard' AND tgenabled IN ('O','A') AND tgtype=23 AND tgfoid='openpc.guard_notification_outcome_signing()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_delivery_outcome_signing'::regclass AND tgname='notification_outcome_signing_immutable' AND tgenabled IN ('O','A') AND tgtype=42 AND tgfoid='openpc.deny_notification_delivery_outcome_mutation()'::regprocedure)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-OWNER'; END IF;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||openpc.current_participant_id()::text,
 'notification-worker:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
   AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-FENCE'; END IF;
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_outcome_signing_original(item control.notification_delivery_outcome_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb:=item.preparation;t jsonb:=p->'preparation';q jsonb:=p->'request';x jsonb:=t->'input';b jsonb:=x->'current'->'snapshot';
 r jsonb;m jsonb;n jsonb;ob jsonb;expected jsonb;wm jsonb;limit_count integer;after_state text;next_ms numeric;
 s control.notification_delivery_start%ROWTYPE;c control.notification_delivery_dispatch_intent%ROWTYPE;
 native control.notification_delivery_observation%ROWTYPE;signer control.notification_receipt_signer_installation%ROWTYPE;w control.installed_notification_worker%ROWTYPE;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR p IS DISTINCT FROM jsonb_build_object('schema','pc.notification.delivery-outcome-signing.v1','preparation',t,'request',q,'requestDigest',item.request_digest)
 OR item.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8') OR item.preparation_digest IS DISTINCT FROM ${jsonHash('p')}
 OR t IS DISTINCT FROM jsonb_build_object('input',x,'workerInstallation',t->'workerInstallation','signerInstallation',t->'signerInstallation','metadata',t->'metadata')
 OR q-ARRAY['schemaVersion','method','purpose','signerInstallationDigest','providerId','secretClass','reference','version','keyEpoch','signerKeyId','environmentId','participantId','privacyDomainId','workerInstallationDigest','workerProfileDigest','workloadCredentialId','workloadEpoch','signingAttemptId','operationId','startOperationId','attemptId','outcomePreparationDigest','payloadHex'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(q))<>23 OR q->'schemaVersion' IS DISTINCT FROM '1'::jsonb
 OR q->>'method' IS DISTINCT FROM 'SIGN_NOTIFICATION_DELIVERY_OUTCOME' OR q->>'purpose' IS DISTINCT FROM 'pc.cose.notification-delivery-outcome-receipt.v1'
 OR q->>'operationId' IS DISTINCT FROM item.operation_id::text OR q->>'signingAttemptId' IS DISTINCT FROM item.signing_attempt_id::text
 OR q->>'participantId' IS DISTINCT FROM item.participant_id::text OR q->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR q->>'startOperationId' IS DISTINCT FROM item.start_operation_id::text OR q->>'attemptId' IS DISTINCT FROM item.attempt_id::text
 OR q->>'signerInstallationDigest' IS DISTINCT FROM item.signer_installation_digest OR q->>'outcomePreparationDigest' IS DISTINCT FROM ${jsonHash('t')}
 OR item.request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.notification.outcome-receipt-provider-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(q),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-ORIGINAL'; END IF;
 m:=openpc.business_cbor(decode(q->>'payloadHex','hex'));r:=jsonb_build_object(${decodedClaims});
 IF EXISTS(SELECT 1 FROM jsonb_each(r) e WHERE e.value='null'::jsonb)
 OR m IS DISTINCT FROM jsonb_build_object(${encodedClaims})
 OR r->>'operationId' IS DISTINCT FROM item.operation_id::text OR r->>'receiptId' IS DISTINCT FROM item.signing_attempt_id::text
 OR r->>'participantId' IS DISTINCT FROM item.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR r->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text OR r->>'payloadDigest' IS DISTINCT FROM item.payload_digest
 OR r->>'deliveryRevision' IS DISTINCT FROM item.delivery_revision::text OR r->>'startOperationId' IS DISTINCT FROM item.start_operation_id::text OR r->>'attemptId' IS DISTINCT FROM item.attempt_id::text
 OR t->'metadata' IS DISTINCT FROM jsonb_build_object('operationId',item.operation_id::text,'receiptId',item.signing_attempt_id::text,'recordedAtMs',r->'recordedAtMs','authoritySnapshotDigest',r->'authoritySnapshotDigest')
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-PAYLOAD'; END IF;
 SELECT * INTO STRICT s FROM control.notification_delivery_start WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.start_operation_id;
 SELECT * INTO STRICT c FROM control.notification_delivery_dispatch_intent WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.start_operation_id;
 PERFORM openpc.check_notification_delivery_start_original(s);PERFORM openpc.check_notification_delivery_dispatch_intent_original(c);
 ob:=x->'observation'->'observation';
 IF x IS DISTINCT FROM jsonb_build_object('observation',jsonb_build_object('original',s.transition,'claim',jsonb_build_object('state',c.state,'claimToken',c.claim_token,'claimedAtMs',c.claimed_at_ms),'observation',ob),'current',jsonb_build_object('snapshot',b,'revision',item.delivery_revision::text),'configuredLimit',x->'configuredLimit')
 OR c.state IS DISTINCT FROM 'CLAIMED' OR s.attempt_id<>item.attempt_id OR s.notification_occurrence_id<>item.notification_occurrence_id OR s.payload_digest<>item.payload_digest
 OR r->>'startReceiptDigest' IS DISTINCT FROM s.receipt_digest OR r->>'dispatchClaimDigest' IS DISTINCT FROM ${jsonHash("x->'observation'->'claim'")}
 OR r->>'sourceReceiptDigest' IS DISTINCT FROM s.transition->'receipt'->>'sourceReceiptDigest'
 OR r->>'environmentId' IS DISTINCT FROM s.transition->'receipt'->>'environmentId' OR r->>'routingProfileDigest' IS DISTINCT FROM s.transition->'receipt'->>'routingProfileDigest'
 OR r->>'endpointId' IS DISTINCT FROM s.transition->'receipt'->>'endpointId' OR r->>'endpointRevision' IS DISTINCT FROM s.transition->'receipt'->>'endpointRevision'
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-LINEAGE'; END IF;
 native.participant_id:=item.participant_id;native.privacy_domain_id:=item.privacy_domain_id;native.operation_id:=item.operation_id;
 native.start_operation_id:=item.start_operation_id;native.attempt_id:=item.attempt_id;native.dispatch_claim_token:=c.claim_token;
 native.observation_id:=(ob->'claims'->>'receiptId')::uuid;native.outcome:=ob->'claims'->>'outcome';native.observed_at_ms:=(ob->'claims'->>'observedAtMs')::numeric;
 native.observation_bytes:=convert_to(openpc.signing_canonical_json(ob),'UTF8');native.observation_digest:=${jsonHash('ob')};
 PERFORM openpc.check_notification_delivery_observation_original(native);
 IF r->>'gatewayReceiptId' IS DISTINCT FROM native.observation_id::text OR r->>'gatewayReceiptDigest' IS DISTINCT FROM ${hash("decode(ob->'signed'->>'payloadHex','hex')")}
 OR r->>'gatewayCoseDigest' IS DISTINCT FROM ob->>'receiptDigest' OR r->>'observationDigest' IS DISTINCT FROM native.observation_digest
 OR r->>'outcome' IS DISTINCT FROM native.outcome OR (r->>'observedAtMs')::numeric IS DISTINCT FROM native.observed_at_ms
 OR (r->>'recordedAtMs')::numeric<native.observed_at_ms OR (r->>'recordedAtMs')::numeric NOT BETWEEN 0 AND 9007199254740991
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-NATIVE'; END IF;
 limit_count:=least((b->>'attemptLimit')::integer,(x->>'configuredLimit')::integer,6);
 IF b-ARRAY['participantId','privacyDomainId','notificationOccurrenceId','payloadDigest','state','attemptCount','attemptLimit','nextAttemptAtMs','lastStartedAtMs','cancelRequested'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(b))<>10 OR jsonb_typeof(b->'cancelRequested') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(b->'attemptLimit') IS DISTINCT FROM 'number' OR trunc((b->>'attemptLimit')::numeric)<>(b->>'attemptLimit')::numeric
 OR jsonb_typeof(x->'configuredLimit') IS DISTINCT FROM 'number' OR (x->>'configuredLimit')::numeric NOT BETWEEN 0 AND 100
 OR trunc((x->>'configuredLimit')::numeric)<>(x->>'configuredLimit')::numeric
 OR (b->>'state' IN ('STARTED','AMBIGUOUS')) IS DISTINCT FROM true OR (b->>'attemptCount')::integer NOT BETWEEN 1 AND 6
 OR (b->>'attemptLimit')::integer NOT BETWEEN 0 AND 6 OR b->'nextAttemptAtMs' IS DISTINCT FROM 'null'::jsonb
 OR b->>'participantId' IS DISTINCT FROM item.participant_id::text OR b->>'privacyDomainId' IS DISTINCT FROM item.privacy_domain_id::text
 OR b->>'notificationOccurrenceId' IS DISTINCT FROM item.notification_occurrence_id::text OR b->>'payloadDigest' IS DISTINCT FROM item.payload_digest
 OR b->'attemptCount' IS DISTINCT FROM s.transition->'after'->'attemptCount' OR b->'lastStartedAtMs' IS DISTINCT FROM s.transition->'after'->'lastStartedAtMs'
 OR (b->>'attemptLimit')::integer>(s.transition->'after'->>'attemptLimit')::integer OR item.delivery_revision<=s.delivery_revision
 OR (item.delivery_revision=s.delivery_revision+1 AND b IS DISTINCT FROM s.transition->'after')
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-STATE'; END IF;
 next_ms:=NULL;
 after_state:=CASE native.outcome WHEN 'DELIVERED' THEN 'DELIVERED' WHEN 'AMBIGUOUS' THEN 'AMBIGUOUS' WHEN 'PERMANENT_FAILURE' THEN 'FAILED'
 ELSE CASE WHEN (b->>'cancelRequested')::boolean THEN 'CANCELLED' WHEN (b->>'attemptCount')::integer>=limit_count THEN 'FAILED' ELSE 'RETRY_WAIT' END END;
 IF after_state='RETRY_WAIT' THEN next_ms:=native.observed_at_ms+(ARRAY[5000,30000,120000,600000,1800000])[(b->>'attemptCount')::integer]; END IF;
 n:=b||jsonb_build_object('state',after_state,'attemptLimit',limit_count,'nextAttemptAtMs',next_ms);
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',item.delivery_revision::text,'projection',b);
 IF r->>'beforeStateDigest' IS DISTINCT FROM ${jsonHash('expected')} THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-BEFORE'; END IF;
 expected:=jsonb_build_object('schema','pc.notification-delivery.state.v1','revision',(item.delivery_revision+1)::text,'projection',n);
 IF r->>'afterStateDigest' IS DISTINCT FROM ${jsonHash('expected')} OR r->>'beforeDeliveryState' IS DISTINCT FROM b->>'state' OR r->>'afterDeliveryState' IS DISTINCT FROM after_state
 OR r->'attemptCount' IS DISTINCT FROM b->'attemptCount' OR (r->>'attemptLimit')::integer IS DISTINCT FROM limit_count
 OR (r->>'nextAttemptAtMs')::numeric IS DISTINCT FROM coalesce(next_ms,0) OR coalesce(next_ms,0)>9007199254740991
 OR r->>'cancelRequested' IS DISTINCT FROM (CASE WHEN (b->>'cancelRequested')::boolean THEN 'YES' ELSE 'NO' END)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-AFTER'; END IF;
 SELECT * INTO STRICT signer FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF t->'workerInstallation' IS DISTINCT FROM w.installation OR t->'signerInstallation' IS DISTINCT FROM signer.trust-ARRAY['schema','schemaDefinitionDigest','signerKeyId']
 OR signer.trust->>'purpose' IS DISTINCT FROM 'pc.cose.notification-delivery-outcome-receipt.v1'
 OR w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR r->>'workerProfileDigest' IS DISTINCT FROM signer.trust->>'workerProfileDigest' OR r->>'routingProfileDigest' IS DISTINCT FROM 'sha256:'||(wm->'${workerKey('routingProfileDigest')}'->>'bytes')
 OR r->>'signerKeyId' IS DISTINCT FROM signer.signer_id OR q->>'signerKeyId' IS DISTINCT FROM signer.signer_id
 OR q->>'reference' IS DISTINCT FROM signer.trust->>'secretReference' OR q->>'version' IS DISTINCT FROM signer.trust->>'secretVersion'
 OR q->>'providerId' IS DISTINCT FROM signer.trust->>'providerId' OR q->>'keyEpoch' IS DISTINCT FROM signer.trust->>'keyEpoch'
 OR q->>'workloadCredentialId' IS DISTINCT FROM signer.trust->>'workloadCredentialId' OR q->>'workloadEpoch' IS DISTINCT FROM signer.trust->>'workloadEpoch'
 OR q->>'workerInstallationDigest' IS DISTINCT FROM signer.worker_installation_digest OR q->>'workerProfileDigest' IS DISTINCT FROM signer.trust->>'workerProfileDigest'
 OR q->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY' OR q->>'environmentId' IS DISTINCT FROM signer.trust->>'environmentId'
 OR r->>'environmentId' IS DISTINCT FROM q->>'environmentId'
 OR (r->>'recordedAtMs')::numeric<(wm->>'${workerKey('validFromMs')}')::numeric OR (r->>'recordedAtMs')::numeric>=(wm->>'${workerKey('validUntilMs')}')::numeric
 OR (r->>'recordedAtMs')::numeric*1000000<(signer.trust->>'validFromNs')::numeric OR (r->>'recordedAtMs')::numeric*1000000>=(signer.trust->>'validUntilNs')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-TRUST'; END IF;
 IF item.state<>'PREPARED' AND (item.dispatched_at_ms<(r->>'recordedAtMs')::numeric OR item.dispatched_at_ms*1000000>=(signer.trust->>'validUntilNs')::numeric OR item.dispatched_at_ms>=(wm->>'${workerKey('validUntilMs')}')::numeric)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-TIME'; END IF;
 IF item.state='OBSERVED' THEN
  ob:=convert_from(item.observation_bytes,'UTF8')::jsonb;
  IF item.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(ob),'UTF8') OR item.observation_digest IS DISTINCT FROM ${jsonHash('ob')}
  OR ob-ARRAY['schemaVersion','providerId','signingAttemptId','requestDigest','recordedAtMs','outcome','reason','coseHex'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(ob))<>8
  OR ob->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR ob->>'providerId' IS DISTINCT FROM q->>'providerId' OR ob->>'signingAttemptId' IS DISTINCT FROM item.signing_attempt_id::text OR ob->>'requestDigest' IS DISTINCT FROM item.request_digest
  OR jsonb_typeof(ob->'recordedAtMs') IS DISTINCT FROM 'number' OR (ob->>'recordedAtMs')::numeric NOT BETWEEN 0 AND 9007199254740991 OR trunc((ob->>'recordedAtMs')::numeric)<>(ob->>'recordedAtMs')::numeric
  THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-OBSERVATION'; END IF;
  IF ob->>'outcome'='SIGNED' THEN
   IF ob->'reason' IS DISTINCT FROM 'null'::jsonb OR ob->>'coseHex' IS NULL OR (ob->>'recordedAtMs')::numeric<item.dispatched_at_ms
    OR (ob->>'recordedAtMs')::numeric>=(wm->>'${workerKey('validUntilMs')}')::numeric OR (ob->>'recordedAtMs')::numeric*1000000>=(signer.trust->>'validUntilNs')::numeric
   THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-OBSERVATION'; END IF;
   PERFORM openpc.archive_cose_binding(decode(q->>'payloadHex','hex'),decode(ob->>'coseHex','hex'),signer.signer_id,${outcome.schemaId},${outcome.purposeCode});
  ELSIF ob->>'outcome' IS DISTINCT FROM 'REJECTED' OR ob->'coseHex' IS DISTINCT FROM 'null'::jsonb
   OR (ob->>'reason' IN ('REVOKED','EXPIRED','WRONG_SCOPE','INVALID_REQUEST','ATTEMPT_CONFLICT','KEY_UNAVAILABLE')) IS DISTINCT FROM true
  THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-OBSERVATION'; END IF;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_outcome_signing_current(item control.notification_delivery_outcome_signing) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_delivery%ROWTYPE;signer control.notification_receipt_signer_installation%ROWTYPE;wm jsonb;now_ms numeric;lock_name text;
BEGIN
 PERFORM openpc.assert_notification_outcome_signing_owner();PERFORM openpc.check_notification_outcome_signing_original(item);
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=item.notification_occurrence_id FOR UPDATE;
 IF d.revision<>item.delivery_revision OR ${projection('d')} IS DISTINCT FROM item.preparation->'preparation'->'input'->'current'->'snapshot'
 OR EXISTS(SELECT 1 FROM control.notification_delivery_observation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND attempt_id=item.attempt_id)
 OR EXISTS(SELECT 1 FROM control.notification_delivery_outcome_signing WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND attempt_id=item.attempt_id AND operation_id<>item.operation_id)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-STALE'; END IF;
 PERFORM 1 FROM control.notification_delivery_dispatch_intent WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND operation_id=item.start_operation_id FOR UPDATE;
 lock_name:='notification-receipt-signer:'||item.participant_id::text||':'||item.privacy_domain_id::text;
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ShareLock'
 AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-FENCE'; END IF;
 SELECT * INTO STRICT signer FROM control.notification_receipt_signer_installation WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND trust_digest=item.signer_installation_digest AND state='ACTIVE';
 SELECT openpc.business_cbor(decode(installation->'signed'->>'payloadHex','hex')) INTO STRICT wm FROM control.installed_notification_worker
 WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF now_ms<(wm->>'${workerKey('validFromMs')}')::numeric OR now_ms>=(wm->>'${workerKey('validUntilMs')}')::numeric OR now_ms*1000000<(signer.trust->>'validFromNs')::numeric OR now_ms*1000000>=(signer.trust->>'validUntilNs')::numeric
 OR now_ms<(item.preparation->'preparation'->'metadata'->>'recordedAtMs')::numeric
 OR NOT EXISTS(SELECT 1 FROM control.installed_notification_worker w JOIN control.credential c ON c.participant_id=w.participant_id AND c.credential_id=w.workload_credential_id
  JOIN control.principal p ON p.participant_id=c.participant_id AND p.principal_id=c.principal_id
  WHERE w.participant_id=item.participant_id AND w.privacy_domain_id=item.privacy_domain_id AND w.installation_digest=signer.worker_installation_digest AND w.state='ACTIVE'
  AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch::text=signer.trust->>'workloadEpoch'
  AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp() AND p.state='ACTIVE' AND p.kind='WORKLOAD')
 THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-AUTHORITY'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_outcome_signing() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_outcome_signing_owner();PERFORM openpc.check_notification_outcome_signing_original(NEW);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-INITIAL'; END IF;
  PERFORM openpc.check_notification_outcome_signing_current(NEW);
 ELSE
  IF to_jsonb(NEW)-ARRAY['state','dispatch_token','dispatched_at_ms','observation_bytes','observation_digest'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','dispatch_token','dispatched_at_ms','observation_bytes','observation_digest']
  THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-IMMUTABLE'; END IF;
  IF OLD.state='PREPARED' AND NEW.state='DISPATCHED' THEN
   PERFORM openpc.check_notification_outcome_signing_current(NEW);
   IF NEW.dispatched_at_ms IS DISTINCT FROM floor(extract(epoch from statement_timestamp())*1000) THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-TIME'; END IF;
  ELSIF OLD.state='DISPATCHED' AND NEW.state='OBSERVED' THEN
   IF NEW.dispatch_token IS DISTINCT FROM OLD.dispatch_token OR NEW.dispatched_at_ms IS DISTINCT FROM OLD.dispatched_at_ms THEN RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-CLAIM'; END IF;
  ELSE RAISE EXCEPTION 'NOTIFICATION-OUTCOME-SIGNING-ONE-SHOT'; END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_outcome_signing_guard ON control.notification_delivery_outcome_signing;
CREATE TRIGGER notification_outcome_signing_guard BEFORE INSERT OR UPDATE ON control.notification_delivery_outcome_signing FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_outcome_signing();
DROP TRIGGER IF EXISTS notification_outcome_signing_immutable ON control.notification_delivery_outcome_signing;
CREATE TRIGGER notification_outcome_signing_immutable BEFORE DELETE OR TRUNCATE ON control.notification_delivery_outcome_signing FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_outcome_mutation();
REVOKE ALL ON FUNCTION openpc.assert_notification_outcome_signing_owner(),openpc.check_notification_outcome_signing_original(control.notification_delivery_outcome_signing),openpc.check_notification_outcome_signing_current(control.notification_delivery_outcome_signing),openpc.guard_notification_outcome_signing() FROM PUBLIC;
`;
