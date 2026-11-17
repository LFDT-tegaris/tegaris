import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const worker = notificationCoseProfiles.NotificationWorkerProfileV1;
const field = (name) => worker.fields.find((f) => f.name === name).key;
const family = notificationCoseProfiles.NotificationDeliveryStartedReceiptV1;
const cancellation = notificationCoseProfiles.NotificationDeliveryCancellationReceiptV1;
const outcome = notificationCoseProfiles.NotificationDeliveryOutcomeReceiptV1;
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
export const notificationReceiptSignerGuardsSql = String.raw`
ALTER TABLE control.notification_receipt_signer_installation FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification_receipt_signer_installation FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.notification_receipt_signer_installation TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.notification_receipt_signer_installation TO openpc_control_owner;
DROP POLICY IF EXISTS notification_receipt_signer_installer ON control.notification_receipt_signer_installation;
CREATE POLICY notification_receipt_signer_installer ON control.notification_receipt_signer_installation TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
CREATE OR REPLACE FUNCTION openpc.guard_notification_receipt_signer_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE t jsonb; w control.installed_notification_worker%ROWTYPE; m jsonb; c control.credential%ROWTYPE;
BEGIN
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
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-receipt-signer:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
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
 OR t->>'schema' IS DISTINCT FROM 'pc.notification.receipt-signer-trust.v1'
 OR NOT ((t->>'purpose'='pc.cose.notification-delivery-started-receipt.v1' AND t->>'schemaDefinitionDigest'='${family.definitionDigest}')
  OR (t->>'purpose'='pc.cose.notification-delivery-cancellation-receipt.v1' AND t->>'schemaDefinitionDigest'='${cancellation.definitionDigest}')
  OR (t->>'purpose'='pc.cose.notification-delivery-outcome-receipt.v1' AND t->>'schemaDefinitionDigest'='${outcome.definitionDigest}'))
 OR t->>'owner' IS DISTINCT FROM 'LS-NOTIFICATION'

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
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_worker WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
 AND installation_digest=NEW.worker_installation_digest AND state='ACTIVE';
 m:=openpc.business_cbor(decode(w.installation->'signed'->>'payloadHex','hex'));
 IF w.service_id<>'LS-NOTIFICATION' OR w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
 OR w.signed_profile_digest IS DISTINCT FROM t->>'workerProfileDigest'
 OR w.installation->'pins'->>'issuerSpkiHex' IS DISTINCT FROM t->>'workerIssuerSpkiHex'
 ${['environmentId', 'principalId', 'workloadCredentialId', 'workloadEpoch', 'workloadId'].map((f) => `OR w.installation->'pins'->>'${f}' IS DISTINCT FROM t->>'${f}'`).join('\n ')}
 OR m->'${field('receiptSignerSpki')}' IS DISTINCT FROM jsonb_build_object('bytes',t->>'publicKeySpkiHex')
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
DROP TRIGGER IF EXISTS notification_receipt_signer_installation_guard ON control.notification_receipt_signer_installation;
CREATE TRIGGER notification_receipt_signer_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.notification_receipt_signer_installation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_receipt_signer_installation();
REVOKE ALL ON FUNCTION openpc.guard_notification_receipt_signer_installation() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.guard_notification_receipt_signer_truncate() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_receipt_signer_truncate_guard ON control.notification_receipt_signer_installation;
CREATE TRIGGER notification_receipt_signer_truncate_guard BEFORE TRUNCATE ON control.notification_receipt_signer_installation
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_receipt_signer_truncate();
REVOKE ALL ON FUNCTION openpc.guard_notification_receipt_signer_truncate() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.assert_notification_receipt_signer_owner() RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF current_setting('session_replication_role')<>'origin' OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_receipt_signer_installation'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_receipt_signer_installation'::regclass AND tgname='notification_receipt_signer_installation_guard' AND tgenabled IN ('O','A') AND NOT tgisinternal)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.notification_receipt_signer_installation'::regclass AND tgname='notification_receipt_signer_truncate_guard' AND tgenabled IN ('O','A') AND NOT tgisinternal)
 THEN RAISE EXCEPTION 'NOTIFICATION-RECEIPT-SIGNER-OWNER'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_receipt_signer_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_receipt_signer_owner() TO openpc_control_runtime,openpc_control_owner;
`;
