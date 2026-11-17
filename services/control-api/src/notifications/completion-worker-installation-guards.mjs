import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const profile = notificationCoseProfiles.NotificationCompletionWorkerProfileV1;
if (!profile || profile.schemaId !== 24030 || profile.purposeCode !== 367)
  throw new Error('Canonical completion-worker profile registration unavailable');
const field = (name) => {
  const f = profile.fields.find((f) => f.name === name);
  if (!f) throw new Error('Completion worker field missing');
  return f.key;
};
const claim = (name) => `m->'${field(name)}'`;
/** Shared migration, role grants and installer RLS are canonical owners. This
 * feature never grants inbox/cursor, WorkItem, quarantine or signing authority. */
export const notificationCompletionWorkerInstallationGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_worker_installation_owner() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_notification_completion_worker_shared_owner();
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.installed_notification_completion_worker'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.installed_notification_completion_worker'::regclass AND tgname='notification_completion_worker_installation_guard' AND tgfoid='openpc.guard_notification_completion_worker_installation()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=31)
 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='control.installed_notification_completion_worker'::regclass AND tgname='notification_completion_worker_truncate_guard' AND tgfoid='openpc.guard_notification_completion_worker_truncate()'::regprocedure AND tgenabled IN ('O','A') AND tgtype=34)
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-OWNER'; END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_worker_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i jsonb;p jsonb;m jsonb;c control.credential%ROWTYPE;payload bytea;signature bytea;now_ms numeric;
BEGIN
 PERFORM openpc.assert_notification_completion_worker_shared_owner();
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR current_setting('row_security')<>'on' OR current_setting('transaction_isolation')<>'read committed'
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-completion-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state' THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 i:=NEW.installation;p:=i->'pins';now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF NEW.state<>'ACTIVE' OR jsonb_typeof(i) IS DISTINCT FROM 'object' OR i-ARRAY['pins','signed','installationReference'] IS DISTINCT FROM '{}'::jsonb OR NOT i ?& ARRAY['pins','signed','installationReference']
 OR jsonb_typeof(p) IS DISTINCT FROM 'object' OR p-ARRAY['issuerSpkiHex','signedProfileDigest','environmentId','participantId','privacyDomainId','profileId','revision','serviceId','processRole','subscriptionId','principalId','workloadCredentialId','workloadEpoch','workloadId','workloadKeyDigest','producerTrustDigest'] IS DISTINCT FROM '{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(p))<>16 OR EXISTS(SELECT 1 FROM jsonb_each(p) AS pair WHERE jsonb_typeof(pair.value)<>'string')
 OR jsonb_typeof(i->'signed') IS DISTINCT FROM 'object' OR (i->'signed')-ARRAY['payloadHex','coseHex'] IS DISTINCT FROM '{}'::jsonb OR NOT (i->'signed') ?& ARRAY['payloadHex','coseHex'] OR jsonb_typeof(i->'signed'->'payloadHex') IS DISTINCT FROM 'string' OR jsonb_typeof(i->'signed'->'coseHex') IS DISTINCT FROM 'string'
 OR jsonb_typeof(i->'installationReference') IS DISTINCT FROM 'string' OR length(i->>'installationReference') NOT BETWEEN 1 AND 256 OR btrim(i->>'installationReference')<>i->>'installationReference'
 OR (p->>'issuerSpkiHex' ~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$') IS DISTINCT FROM true
 OR (i->'signed'->>'payloadHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true OR length(i->'signed'->>'payloadHex') NOT BETWEEN 2 AND 131072
 OR (i->'signed'->>'coseHex' ~ '^(?:[0-9a-f]{2})+$') IS DISTINCT FROM true OR length(i->'signed'->>'coseHex') NOT BETWEEN 2 AND 262144
 OR NEW.installation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(i),'UTF8') OR NEW.installation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.installation_bytes),'hex')
 ${['participantId', 'privacyDomainId', 'profileId', 'principalId', 'workloadCredentialId'].map((name) => `OR p->>'${name}' IS DISTINCT FROM NEW.${{ participantId: 'participant_id', privacyDomainId: 'privacy_domain_id', profileId: 'profile_id', principalId: 'principal_id', workloadCredentialId: 'workload_credential_id' }[name]}::text`).join('\n ')}
 OR p->>'signedProfileDigest' IS DISTINCT FROM NEW.signed_profile_digest OR p->>'producerTrustDigest' IS DISTINCT FROM NEW.producer_trust_digest
 OR p->>'serviceId' IS DISTINCT FROM 'LS-CONTROL-WORK' OR NEW.service_id<>'LS-CONTROL-WORK' OR p->>'processRole' IS DISTINCT FROM 'ROLE-CONTROL-WORKER'
 OR p->>'subscriptionId' IS DISTINCT FROM 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' OR NEW.subscription_id<>'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-BINDING'; END IF;
 payload:=decode(i->'signed'->>'payloadHex','hex');signature:=decode(i->'signed'->>'coseHex','hex');
 IF NEW.signed_profile_digest IS DISTINCT FROM 'sha256:'||encode(sha256(signature),'hex') THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-SIGNATURE'; END IF;
 PERFORM openpc.archive_cose_binding(payload,signature,'sha256:'||encode(sha256(decode(p->>'issuerSpkiHex','hex')),'hex'),${profile.schemaId},${profile.purposeCode});
 m:=openpc.business_cbor(payload);
 IF jsonb_typeof(m) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(m))<>${profile.fields.length} OR NOT m ?& ARRAY[${profile.fields.map((f) => `'${f.key}'`).join(',')}]
 OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${profile.definitionDigest.slice(7)}')
 ${profile.fields
   .filter((f) => f.type === 'H32' || f.type === 'uuidv7')
   .map(
     (f) =>
       `OR (jsonb_typeof(m->'${f.key}')='object' AND (m->'${f.key}')-ARRAY['bytes']='{}'::jsonb AND (m->'${f.key}'->>'bytes') ~ '${f.type === 'H32' ? '^[0-9a-f]{64}$' : '^[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$'}') IS DISTINCT FROM true`,
   )
   .join('\n ')}
 ${['participantId', 'privacyDomainId', 'profileId', 'principalId', 'workloadCredentialId'].map((n) => `OR ${claim(n)} IS DISTINCT FROM openpc.business_uuid((p->>'${n}')::uuid)`).join('\n ')}
 ${['environmentId', 'workloadId'].map((n) => `OR (${claim(n)} #>> '{}') !~ '^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$' OR ${claim(n)} IS DISTINCT FROM p->'${n}'`).join('\n ')}
 ${['revision', 'workloadEpoch'].map((n) => `OR (p->>'${n}' ~ '^[1-9][0-9]{0,19}$') IS DISTINCT FROM true OR (p->>'${n}')::numeric>18446744073709551615 OR ${claim(n)} IS DISTINCT FROM to_jsonb((p->>'${n}')::numeric)`).join('\n ')}
 ${['workloadKeyDigest', 'producerTrustDigest'].map((n) => `OR (p->>'${n}' ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true OR ${claim(n)} IS DISTINCT FROM openpc.business_bytes(decode(substr(p->>'${n}',8),'hex'))`).join('\n ')}
 ${['serviceId', 'processRole', 'subscriptionId'].map((n) => `OR ${claim(n)} IS DISTINCT FROM '1'::jsonb`).join('\n ')}
 ${['validFromMs', 'validUntilMs', 'maximumAttempts', 'initialBackoffMs', 'maximumBackoffMs'].map((n) => `OR (jsonb_typeof(${claim(n)})='number' AND (${claim(n)} #>> '{}') ~ '^(0|[1-9][0-9]*)$' AND (${claim(n)} #>> '{}')::numeric<=9007199254740991) IS DISTINCT FROM true`).join('\n ')}
 OR (m->>'${field('validUntilMs')}')::numeric<=(m->>'${field('validFromMs')}')::numeric OR now_ms<(m->>'${field('validFromMs')}')::numeric OR now_ms>=(m->>'${field('validUntilMs')}')::numeric
 OR (m->>'${field('maximumAttempts')}')::numeric NOT BETWEEN 1 AND 1000 OR (m->>'${field('initialBackoffMs')}')::numeric<1 OR (m->>'${field('maximumBackoffMs')}')::numeric<(m->>'${field('initialBackoffMs')}')::numeric OR (m->>'${field('maximumBackoffMs')}')::numeric>3600000
 OR ${claim('issuerKeyId')} IS DISTINCT FROM openpc.business_bytes(sha256(decode(p->>'issuerSpkiHex','hex'))) OR ${claim('issuerKeyId')} IS NOT DISTINCT FROM ${claim('workloadKeyDigest')}
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-PROFILE'; END IF;
 SELECT * INTO STRICT c FROM control.credential WHERE participant_id=NEW.participant_id AND credential_id=NEW.workload_credential_id AND principal_id=NEW.principal_id;
 IF c.kind<>'WORKLOAD_MTLS' OR c.state<>'ACTIVE' OR c.credential_epoch::text IS DISTINCT FROM p->>'workloadEpoch' OR c.audience IS DISTINCT FROM p->>'workloadId'
 OR p->>'workloadKeyDigest' IS DISTINCT FROM 'sha256:'||encode(c.public_key_digest,'hex') OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp() OR c.valid_until IS NULL
 OR NOT EXISTS(SELECT 1 FROM control.principal WHERE participant_id=c.participant_id AND principal_id=c.principal_id AND state='ACTIVE' AND kind='WORKLOAD')
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-IDENTITY'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION openpc.guard_notification_completion_worker_truncate() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-IMMUTABLE';END $$;
DROP TRIGGER IF EXISTS notification_completion_worker_installation_guard ON control.installed_notification_completion_worker;
CREATE TRIGGER notification_completion_worker_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_notification_completion_worker FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_completion_worker_installation();
DROP TRIGGER IF EXISTS notification_completion_worker_truncate_guard ON control.installed_notification_completion_worker;
CREATE TRIGGER notification_completion_worker_truncate_guard BEFORE TRUNCATE ON control.installed_notification_completion_worker FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_completion_worker_truncate();
REVOKE ALL ON FUNCTION openpc.assert_notification_completion_worker_installation_owner(),openpc.guard_notification_completion_worker_installation(),openpc.guard_notification_completion_worker_truncate() FROM PUBLIC;
`;
