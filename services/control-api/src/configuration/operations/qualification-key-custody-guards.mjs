/** Native custody roles only. A row is an observation, never qualification. */
export const qualificationKeyCustodyGuardsSql = String.raw`
SET ROLE openpc_control_owner;
CREATE OR REPLACE FUNCTION openpc.guard_qualification_key_custody() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,control,openpc AS $$
DECLARE pins control.qualification_key_installation%ROWTYPE;
 attempt control.qualification_key_attempt%ROWTYPE;
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'QUALIFICATION_KEY_IMMUTABLE'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 OR NEW.participant_id<>openpc.current_participant_id() OR NEW.privacy_domain_id<>openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'QUALIFICATION_KEY_CONTEXT'; END IF;
 IF TG_TABLE_NAME='qualification_key_installation' THEN
  IF current_user<>'openpc_operations_qualification_bootstrap' THEN RAISE EXCEPTION 'QUALIFICATION_KEY_INSTALLER'; END IF;
  IF TG_OP='UPDATE' THEN
   IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
     OR OLD.state NOT IN ('ACTIVE','REVOKED') OR NEW.state<>'REVOKED' THEN RAISE EXCEPTION 'QUALIFICATION_KEY_IMMUTABLE'; END IF;
  ELSE
   IF NEW.state<>'ACTIVE' OR NEW.pins->'schemaVersion' IS DISTINCT FROM '1'::jsonb
     OR NOT NEW.pins ?& ARRAY['schemaVersion','installationId','participantId','privacyDomainId','environmentId','authorityId','rootEpoch','keyId','keyEpoch','purpose','publicKeySpkiHex','reference','version','providerId','providerOrigin','providerTlsSpkiDigest','peer','validFromMs','validUntilMs'] OR convert_from(NEW.pins_bytes,'UTF8')<>openpc.signing_canonical_json(NEW.pins)
     OR NEW.pins->>'installationId' IS DISTINCT FROM NEW.installation_id::text OR NEW.pins->>'participantId' IS DISTINCT FROM NEW.participant_id::text
     OR NEW.pins->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text OR NEW.pins->>'environmentId' IS DISTINCT FROM NEW.environment_id
     OR NOT EXISTS(SELECT 1 FROM control.operations_installation i WHERE i.environment_id=NEW.environment_id AND i.participant_id=NEW.participant_id AND i.privacy_domain_id=NEW.privacy_domain_id AND i.state='ACTIVE')
   THEN RAISE EXCEPTION 'QUALIFICATION_KEY_INSTALLATION'; END IF;
  END IF;
 ELSE
  IF current_user NOT IN ('openpc_control_owner','openpc_operations_qualification_owner') THEN RAISE EXCEPTION 'QUALIFICATION_KEY_NATIVE_OWNER'; END IF;
  IF TG_TABLE_NAME='qualification_key_attempt' THEN
   SELECT * INTO pins FROM control.qualification_key_installation WHERE installation_id=NEW.installation_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
   IF NOT FOUND OR pins.state<>'ACTIVE' THEN RAISE EXCEPTION 'QUALIFICATION_KEY_UNINSTALLED'; END IF;
   IF TG_OP='UPDATE' THEN
    IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') OR OLD.state<>'PREPARED' OR NEW.state<>'DISPATCHED' THEN RAISE EXCEPTION 'QUALIFICATION_KEY_IMMUTABLE'; END IF;
   ELSE
    IF NEW.state<>'PREPARED' OR NEW.request->'schemaVersion' IS DISTINCT FROM '1'::jsonb
     OR NOT NEW.request ?& ARRAY['schemaVersion','installationDigest','participantId','privacyDomainId','environmentId','authorityId','rootEpoch','keysetDigest','revocationsDigest','keyId','keyEpoch','purpose','providerId','reference','version','peer','operationId','attemptId','issuedAtMs','deadlineAtMs','method'] OR convert_from(NEW.request_bytes,'UTF8')<>openpc.signing_canonical_json(NEW.request)
     OR NEW.request->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR NEW.request->>'operationId' IS DISTINCT FROM NEW.operation_id::text
     OR NEW.request->>'installationDigest' IS DISTINCT FROM pins.pins_digest OR NEW.request->'peer' IS DISTINCT FROM pins.pins->'peer'
     OR NEW.request->>'method' NOT IN ('INSPECT','PROVE')
     OR (NEW.request->>'issuedAtMs')::numeric>floor(extract(epoch from clock_timestamp())*1000)
     OR (NEW.request->>'deadlineAtMs')::numeric<=floor(extract(epoch from clock_timestamp())*1000)
     OR EXISTS(SELECT 1 FROM unnest(ARRAY['participantId','privacyDomainId','environmentId','authorityId','rootEpoch','keyId','keyEpoch','purpose','providerId','reference','version']) k WHERE NEW.request->k IS DISTINCT FROM pins.pins->k)
    THEN RAISE EXCEPTION 'QUALIFICATION_KEY_REQUEST'; END IF;
   END IF;
  ELSE
   IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'QUALIFICATION_KEY_IMMUTABLE'; END IF;
   SELECT * INTO attempt FROM control.qualification_key_attempt WHERE attempt_id=NEW.attempt_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
   IF NOT FOUND OR attempt.state<>'DISPATCHED' OR NEW.observation->'schemaVersion' IS DISTINCT FROM '1'::jsonb
    OR NOT NEW.observation ?& ARRAY['schemaVersion','attemptId','requestDigest','observedAtMs','outcome','reason','descriptor','proofHex'] OR convert_from(NEW.observation_bytes,'UTF8')<>openpc.signing_canonical_json(NEW.observation)
    OR NEW.observation->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR NEW.observation->>'requestDigest' IS DISTINCT FROM attempt.request_digest
    OR NEW.observation->>'outcome' NOT IN ('OBSERVED','REJECTED')
   THEN RAISE EXCEPTION 'QUALIFICATION_KEY_OBSERVATION'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.guard_qualification_key_custody() FROM PUBLIC;
${['qualification_key_installation', 'qualification_key_attempt', 'qualification_key_observation']
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='openpc_identity_runtime') THEN
  REVOKE ALL ON control.${table} FROM openpc_identity_runtime;
 END IF;
END $$;
GRANT SELECT ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
GRANT UPDATE ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner;
${table === 'qualification_key_installation' ? 'GRANT INSERT,UPDATE ON control.qualification_key_installation TO openpc_operations_qualification_bootstrap;' : `GRANT INSERT ON control.${table} TO openpc_control_owner,openpc_operations_qualification_owner;`}
DROP POLICY IF EXISTS qualification_key_native_read ON control.${table};
CREATE POLICY qualification_key_native_read ON control.${table} FOR SELECT TO openpc_control_owner,openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS qualification_key_native_write ON control.${table};
CREATE POLICY qualification_key_native_write ON control.${table} FOR ALL TO ${table === 'qualification_key_installation' ? 'openpc_operations_qualification_bootstrap' : 'openpc_control_owner,openpc_operations_qualification_owner'}
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS qualification_key_native_lock ON control.${table};
CREATE POLICY qualification_key_native_lock ON control.${table} FOR UPDATE TO openpc_control_owner,openpc_operations_qualification_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)) WITH CHECK(false);
DROP TRIGGER IF EXISTS qualification_key_guard ON control.${table};
CREATE TRIGGER qualification_key_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.guard_qualification_key_custody();
DROP TRIGGER IF EXISTS qualification_key_truncate_guard ON control.${table};
CREATE TRIGGER qualification_key_truncate_guard BEFORE TRUNCATE ON control.${table} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_qualification_key_custody();`,
  )
  .join('\n')}
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_operations_qualification_bootstrap;
`;

/** Canonical shared grant splice: native Identity owner reads/locks only.
 * Runtime application roles receive no custody DML or new memberships. */
export const qualificationKeyPeerGrantsSql = String.raw`
SET ROLE openpc_control_owner;
${['participant', 'privacy_domain', 'principal', 'credential']
  .map(
    (table) => `
GRANT SELECT,UPDATE ON control.${table} TO openpc_operations_qualification_owner;
DROP POLICY IF EXISTS qualification_key_peer_read ON control.${table};
CREATE POLICY qualification_key_peer_read ON control.${table} FOR SELECT TO openpc_operations_qualification_owner
 USING(openpc.matches_participant(participant_id)${table === 'privacy_domain' ? ' AND openpc.matches_privacy(privacy_domain_id)' : ''});
DROP POLICY IF EXISTS qualification_key_peer_lock ON control.${table};
CREATE POLICY qualification_key_peer_lock ON control.${table} FOR UPDATE TO openpc_operations_qualification_owner
 USING(openpc.matches_participant(participant_id)${table === 'privacy_domain' ? ' AND openpc.matches_privacy(privacy_domain_id)' : ''}) WITH CHECK(false);`,
  )
  .join('\n')}
`;
