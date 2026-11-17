import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const profile = notificationCoseProfiles.NotificationWorkerProfileV1;
const field = (name) => profile.fields.find((f) => f.name === name).key;
const claim = (name) => `m->'${field(name)}'`;
/** Immutable privileged trust plus live runtime selection. ECDSA and actual TLS
 * authentication remain mandatory application owners, never inferred by SQL. */
export const notificationWorkerInstallationGuardsSql = String.raw`
ALTER TABLE control.installed_notification_worker FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.installed_notification_worker FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.installed_notification_worker TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.installed_notification_worker TO openpc_control_owner;
DROP POLICY IF EXISTS notification_worker_installer ON control.installed_notification_worker;
CREATE POLICY notification_worker_installer ON control.installed_notification_worker TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS notification_worker_installation_identity ON control.credential;
CREATE POLICY notification_worker_installation_identity ON control.credential FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
CREATE OR REPLACE FUNCTION openpc.guard_notification_worker_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i jsonb; p jsonb; m jsonb; c control.credential%ROWTYPE; payload bytea; signature bytea;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
  OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
  OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-IMMUTABLE'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-worker:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
  THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 i:=NEW.installation;p:=i->'pins';
 IF NEW.state<>'ACTIVE' OR jsonb_typeof(i) IS DISTINCT FROM 'object'
 OR i-ARRAY['pins','signed','installationReference'] IS DISTINCT FROM '{}'::jsonb
 OR NOT i ?& ARRAY['pins','signed','installationReference']
 OR jsonb_typeof(p) IS DISTINCT FROM 'object'
 OR p-ARRAY['issuerSpkiHex','signedProfileDigest','environmentId','participantId','privacyDomainId','profileId','revision',
   'serviceId','processRole','subscriptionId','principalId','workloadCredentialId','workloadEpoch','workloadId','workloadKeyDigest'] IS DISTINCT FROM '{}'::jsonb
 OR (SELECT count(*) FROM jsonb_object_keys(p))<>15
 OR jsonb_typeof(i->'signed') IS DISTINCT FROM 'object'
 OR (i->'signed')-ARRAY['payloadHex','coseHex'] IS DISTINCT FROM '{}'::jsonb
 OR NOT (i->'signed') ?& ARRAY['payloadHex','coseHex']
 OR NEW.installation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(i),'UTF8')
 OR p->>'participantId' IS DISTINCT FROM NEW.participant_id::text
 OR p->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
 OR p->>'profileId' IS DISTINCT FROM NEW.profile_id::text
 OR p->>'principalId' IS DISTINCT FROM NEW.principal_id::text
 OR p->>'workloadCredentialId' IS DISTINCT FROM NEW.workload_credential_id::text
 OR p->>'serviceId' IS DISTINCT FROM NEW.service_id
 OR p->>'subscriptionId' IS DISTINCT FROM NEW.subscription_id
 OR p->>'signedProfileDigest' IS DISTINCT FROM NEW.signed_profile_digest
 THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-BINDING'; END IF;
 payload:=decode(i->'signed'->>'payloadHex','hex');signature:=decode(i->'signed'->>'coseHex','hex');
 IF NEW.signed_profile_digest IS DISTINCT FROM 'sha256:'||encode(sha256(signature),'hex')
 THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-PROFILE'; END IF;
 PERFORM openpc.archive_cose_binding(payload,signature,'sha256:'||encode(sha256(decode(p->>'issuerSpkiHex','hex')),'hex'),${profile.schemaId},${profile.purposeCode});
 m:=openpc.business_cbor(payload);
 IF jsonb_typeof(m) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(m))<>${profile.fields.length}
 OR NOT m ?& ARRAY[${profile.fields.map((f) => `'${f.key}'`).join(',')}]
 ${profile.fields
   .filter((f) => f.type === 'H32' || f.type === 'uuidv7' || f.type === 'P256_SPKI_DER')
   .map(
     (f) =>
       `OR (jsonb_typeof(m->'${f.key}')='object' AND (m->'${f.key}')-ARRAY['bytes']='{}'::jsonb AND (m->'${f.key}'->>'bytes') ~ '${f.type === 'H32' ? '^[0-9a-f]{64}$' : f.type === 'uuidv7' ? '^[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$' : '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'}') IS DISTINCT FROM true`,
   )
   .join('\n ')}
 OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${profile.definitionDigest.slice(7)}')
 ${['participantId', 'privacyDomainId', 'profileId', 'principalId', 'workloadCredentialId'].map((name) => `OR ${claim(name)} IS DISTINCT FROM jsonb_build_object('bytes',replace(p->>'${name}','-',''))`).join('\n ')}
 ${['environmentId', 'workloadId'].map((name) => `OR ${claim(name)} IS DISTINCT FROM p->'${name}'`).join('\n ')}
 ${['revision', 'workloadEpoch'].map((name) => `OR ${claim(name)} IS DISTINCT FROM to_jsonb((p->>'${name}')::numeric)`).join('\n ')}
 OR ${claim('routingProfileDigest')} IS DISTINCT FROM jsonb_build_object('bytes',substring(NEW.routing_profile_digest from 8))
 OR ${claim('issuerKeyId')} IS DISTINCT FROM jsonb_build_object('bytes',encode(sha256(decode(p->>'issuerSpkiHex','hex')),'hex'))
 OR ((NEW.service_id='LS-CONTROL-WORK' AND p->>'processRole'='ROLE-CONTROL-WORKER'
  AND NEW.subscription_id='SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1' AND ${claim('serviceId')}='1'::jsonb
  AND ${claim('processRole')}='1'::jsonb AND ${claim('subscriptionId')}='1'::jsonb)
 OR (NEW.service_id='LS-NOTIFICATION' AND p->>'processRole'='ROLE-NOTIFICATION-WORKER'
  AND ${claim('serviceId')}='2'::jsonb AND ${claim('processRole')}='2'::jsonb
  AND ((NEW.subscription_id='SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1' AND ${claim('subscriptionId')}='2'::jsonb)
   OR (NEW.subscription_id='SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' AND ${claim('subscriptionId')}='3'::jsonb)))) IS DISTINCT FROM true
 OR (m->>'${field('validFromMs')}') IS NULL OR (m->>'${field('validUntilMs')}') IS NULL
 OR (m->>'${field('validFromMs')}')::numeric<0 OR (m->>'${field('validUntilMs')}')::numeric>9007199254740991
 OR floor(extract(epoch from clock_timestamp())*1000)<(m->>'${field('validFromMs')}')::numeric
 OR floor(extract(epoch from clock_timestamp())*1000)>=(m->>'${field('validUntilMs')}')::numeric
 THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-PROFILE'; END IF;
 SELECT * INTO STRICT c FROM control.credential WHERE participant_id=NEW.participant_id
 AND credential_id=NEW.workload_credential_id AND principal_id=NEW.principal_id;
 IF c.kind<>'WORKLOAD_MTLS' OR c.state<>'ACTIVE' OR c.credential_epoch::text IS DISTINCT FROM p->>'workloadEpoch'
 OR c.audience IS DISTINCT FROM p->>'workloadId' OR p->>'workloadKeyDigest' IS DISTINCT FROM 'sha256:'||encode(c.public_key_digest,'hex')
 OR c.valid_from>clock_timestamp() OR c.valid_until<=clock_timestamp() OR c.valid_until IS NULL
 OR c.public_key_digest=sha256(decode(p->>'issuerSpkiHex','hex'))
 OR c.public_key_digest=sha256(decode(${claim('receiptSignerSpki')}->>'bytes','hex'))
 OR sha256(decode(${claim('receiptSignerSpki')}->>'bytes','hex'))=sha256(decode(p->>'issuerSpkiHex','hex'))
 THEN RAISE EXCEPTION 'NOTIFICATION-WORKER-IDENTITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_worker_installation_guard ON control.installed_notification_worker;
CREATE TRIGGER notification_worker_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_notification_worker
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_worker_installation();
REVOKE ALL ON FUNCTION openpc.guard_notification_worker_installation() FROM PUBLIC;
CREATE OR REPLACE FUNCTION openpc.guard_notification_worker_truncate() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
 BEGIN RAISE EXCEPTION 'NOTIFICATION-WORKER-IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS notification_worker_truncate_guard ON control.installed_notification_worker;
CREATE TRIGGER notification_worker_truncate_guard BEFORE TRUNCATE ON control.installed_notification_worker
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_notification_worker_truncate();
REVOKE ALL ON FUNCTION openpc.guard_notification_worker_truncate() FROM PUBLIC;
`;
