import { evidenceKmsCoseProfiles } from '../../../../packages/security-kernel/src/evidence-kms/generated.ts';
import { notificationCoseProfiles as profiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const worker = profiles.NotificationWorkerProfileV1,
  channel = profiles.NotificationChannelProfileV1,
  route = profiles.NotificationRoutingProfileV1;
const key = (p, name) => {
  const f = p.fields.find((f) => f.name === name);
  if (!f) throw new Error('Missing notification native field');
  return f.key;
};
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
const kmsKey = (name) => key(evidenceKmsCoseProfiles.EvidenceKmsReceiptV1, name);

/** Feature declarations only. Canonical owns registration/grants/generated migrations.
 * SQL current checks supplement the genuine TLS/custody/vault callback, not replace it. */
export const notificationDeliveryDispatchGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_dispatch_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_start_atomic_owner();
 IF current_setting('openpc.action_intent_id',true) IS DISTINCT FROM 'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.check_notification_delivery_dispatch_current(operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE item control.notification_delivery_signing%ROWTYPE;start control.notification_delivery_start%ROWTYPE;p jsonb;d control.notification_delivery%ROWTYPE;
 w control.installed_notification_worker%ROWTYPE;
 i control.installed_notification_channel%ROWTYPE;ep control.notification_endpoint%ROWTYPE;o control.notification_occurrence%ROWTYPE;
 rt control.installed_notification_routing%ROWTYPE;wm jsonb;cm jsonb;actual record;now_ms numeric;lock_name text;after_state jsonb;k control.evidence_kms_attempt%ROWTYPE;ki control.evidence_kms_installation%ROWTYPE;status control.evidence_kms_exchange%ROWTYPE;km jsonb;
BEGIN
 PERFORM openpc.assert_notification_delivery_dispatch_owner();
 SELECT * INTO STRICT start FROM control.notification_delivery_start WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND operation_id=operation;
 PERFORM openpc.check_notification_delivery_start_original(start);
 SELECT * INTO STRICT item FROM control.notification_delivery_signing WHERE participant_id=start.participant_id AND privacy_domain_id=start.privacy_domain_id AND operation_id=operation;
 PERFORM openpc.check_notification_delivery_signing_original(item);p:=item.preparation->'deliveryPreparation';
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=p->'source'->'worker'->>'installationDigest';
 SELECT * INTO STRICT o FROM control.notification_occurrence WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=(p->'source'->>'notificationOccurrenceId')::uuid;
 SELECT * INTO STRICT ep FROM control.notification_endpoint WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND endpoint_id=o.endpoint_id FOR SHARE;
 SELECT * INTO STRICT i FROM control.installed_notification_channel WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND credential_ref=o.credential_ref;
 SELECT * INTO STRICT rt FROM control.installed_notification_routing WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND signed_profile_digest=w.routing_profile_digest;
 FOREACH lock_name IN ARRAY ARRAY['evidence-lifecycle:'||item.participant_id::text,'notification-worker:'||item.participant_id::text||':'||item.privacy_domain_id::text,
  'notification-installation:'||item.participant_id::text||':'||item.privacy_domain_id::text,
  'notification-routing:'||item.participant_id::text||':'||item.privacy_domain_id::text||':'||rt.profile_id::text] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1
   AND l.mode=CASE WHEN lock_name LIKE 'evidence-lifecycle:%' THEN 'ExclusiveLock' ELSE 'ShareLock' END)
  THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-FENCE'; END IF;
 END LOOP;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 wm:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));cm:=openpc.business_cbor(decode(i.channel_signed->>'payloadHex','hex'));
 IF w.state<>'ACTIVE' OR i.state<>'ACTIVE' OR ep.state<>'ACTIVE' OR rt.state<>'ACTIVE'
 OR now_ms<(p->'attempt'->>'startedAtMs')::numeric OR now_ms>=(p->'attempt'->>'deadlineAtMs')::numeric OR now_ms>=(p->>'authorityValidUntilMs')::numeric
 OR now_ms<(wm->>'${key(worker, 'validFromMs')}')::numeric OR now_ms>=(wm->>'${key(worker, 'validUntilMs')}')::numeric
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
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-CURRENT'; END IF;
 SELECT * INTO STRICT k FROM control.evidence_kms_attempt WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND attempt_id=(item.preparation->'sourceClaims'->>'keyPreparationId')::uuid FOR UPDATE;
 SELECT * INTO STRICT ki FROM control.evidence_kms_installation WHERE participant_id=k.participant_id AND privacy_domain_id=k.privacy_domain_id AND installation_digest=k.installation_digest;
 lock_name:='evidence-kms-installation:'||item.participant_id::text||':'||item.privacy_domain_id::text||':'||(ki.pins->>'installationId');
 IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode='ShareLock' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND l.classid=((hashtextextended(lock_name,0)>>32)&4294967295)::oid AND l.objid=(hashtextextended(lock_name,0)&4294967295)::oid AND l.objsubid=1)
 OR k.state<>'PROVED' OR ki.state<>'ACTIVE' OR now_ms<(ki.pins->>'validFromMs')::numeric OR now_ms>=(ki.pins->>'validUntilMs')::numeric
 OR ki.installation_digest IS DISTINCT FROM 'sha256:'||(wm->'${key(worker, 'kmsInstallationDigest')}'->>'bytes')
 OR NOT EXISTS(SELECT 1 FROM control.notification_key_preparation kp JOIN control.notification_key_ciphertext kc USING(participant_id,privacy_domain_id,preparation_id)
  WHERE kp.participant_id=k.participant_id AND kp.privacy_domain_id=k.privacy_domain_id AND kp.preparation_id=k.attempt_id
  AND kc.key_id=item.preparation->'sourceClaims'->>'keyId' AND kc.encrypted_object_digest=item.preparation->'sourceClaims'->>'encryptedObjectDigest')
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-CUSTODY'; END IF;
 IF EXISTS(SELECT 1 FROM control.evidence_kms_exchange e WHERE e.participant_id=k.participant_id AND e.privacy_domain_id=k.privacy_domain_id AND e.attempt_id=k.attempt_id AND (
  (e.state IN ('PREPARED','DISPATCHED','UNKNOWN') AND NOT EXISTS(SELECT 1 FROM control.evidence_kms_exchange r WHERE r.participant_id=e.participant_id AND r.privacy_domain_id=e.privacy_domain_id AND r.attempt_id=e.attempt_id AND r.kind='READ_ATTEMPT' AND r.state='PROVED'
   AND openpc.evidence_kms_stored_outcome(r.receipt_bytes) IN ('1','2') AND convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text AND convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest))
  OR (e.receipt_bytes IS NOT NULL AND openpc.business_cbor(decode(convert_from(e.receipt_bytes,'UTF8')::jsonb->'receipt'->>'payloadHex','hex'))->>'${kmsKey('keyState')}' IN ('3','4'))))
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-KMS-UNKNOWN'; END IF;
 SELECT * INTO STRICT status FROM control.evidence_kms_exchange WHERE participant_id=k.participant_id AND privacy_domain_id=k.privacy_domain_id AND attempt_id=k.attempt_id AND kind='STATUS' AND state='PROVED' ORDER BY provider_sequence DESC,exchange_id DESC LIMIT 1;
 km:=openpc.business_cbor(decode(convert_from(status.receipt_bytes,'UTF8')::jsonb->'receipt'->>'payloadHex','hex'));
 IF km->>'${kmsKey('keyState')}' IS DISTINCT FROM '1' OR now_ms<(km->>'${kmsKey('observedAtMs')}')::numeric OR now_ms>=(km->>'${kmsKey('validUntilMs')}')::numeric OR now_ms-(km->>'${kmsKey('observedAtMs')}')::numeric>5000
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-KMS-STALE'; END IF;
 SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit(item.preparation->'sourceClaims'->>'environmentId');
 IF actual.generation_id::text IS DISTINCT FROM p->>'generationId' OR actual.effective_digest IS DISTINCT FROM p->>'effectiveDigest' OR to_jsonb(actual.configured_limit) IS DISTINCT FROM p->'configuredLimit' OR actual.configured_limit<=0
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-GENERATION'; END IF;
 SELECT * INTO STRICT d FROM control.notification_delivery WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND notification_occurrence_id=o.notification_occurrence_id FOR UPDATE;
 after_state:=jsonb_build_object('participantId',d.participant_id::text,'privacyDomainId',d.privacy_domain_id::text,'notificationOccurrenceId',d.notification_occurrence_id::text,'payloadDigest',d.payload_digest,'state',d.state,
 'attemptCount',d.attempt_count,'attemptLimit',d.attempt_limit,'nextAttemptAtMs',d.next_attempt_at_ms,'lastStartedAtMs',d.last_started_at_ms,'cancelRequested',d.cancel_requested);
 IF start.transition->'after' IS DISTINCT FROM after_state OR d.revision IS DISTINCT FROM start.delivery_revision+1
 OR d.cancel_requested OR d.state<>'STARTED' OR d.attempt_count>least(d.attempt_limit,actual.configured_limit,6)
 OR d.delivery_request_event_id::text IS DISTINCT FROM p->'before'->>'deliveryRequestEventId'
 OR d.delivery_request_operation_id IS DISTINCT FROM start.source_operation_id
 OR d.budget_environment_id IS DISTINCT FROM p->'before'->>'budgetEnvironmentId'
 OR d.budget_generation_id::text IS DISTINCT FROM p->'before'->>'budgetGenerationId'
 OR d.budget_effective_digest IS DISTINCT FROM p->'before'->>'budgetEffectiveDigest'
 OR to_jsonb(d.budget_configured_limit) IS DISTINCT FROM p->'before'->'budgetConfiguredLimit'
 OR d.budget_worker_installation_digest IS DISTINCT FROM start.worker_installation_digest
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-STATE'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_dispatch_claim() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_delivery_dispatch_owner();
 PERFORM openpc.check_notification_delivery_dispatch_intent_original(OLD);
 PERFORM openpc.check_notification_delivery_dispatch_intent_original(NEW);
 IF TG_OP<>'UPDATE' OR OLD.state<>'PENDING' OR NEW.state<>'CLAIMED'
 OR to_jsonb(NEW)-ARRAY['state','claim_token','claimed_at_ms'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','claim_token','claimed_at_ms']
 OR NEW.claim_token IS NULL OR NEW.claimed_at_ms IS NULL
 OR NEW.claimed_at_ms<floor(extract(epoch from transaction_timestamp())*1000) OR NEW.claimed_at_ms>floor(extract(epoch from clock_timestamp())*1000)
 THEN RAISE EXCEPTION 'NOTIFICATION-DISPATCH-ONCE'; END IF;
 PERFORM openpc.check_notification_delivery_dispatch_current(NEW.operation_id);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_delivery_dispatch_claim_guard ON control.notification_delivery_dispatch_intent;
CREATE TRIGGER notification_delivery_dispatch_claim_guard BEFORE UPDATE ON control.notification_delivery_dispatch_intent FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_delivery_dispatch_claim();
REVOKE ALL ON FUNCTION openpc.assert_notification_delivery_dispatch_owner(),openpc.check_notification_delivery_dispatch_current(uuid),openpc.guard_notification_delivery_dispatch_claim() FROM PUBLIC;
`;
