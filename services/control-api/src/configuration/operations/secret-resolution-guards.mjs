import { operationsConfigurationCoseProfiles } from '../../../../../packages/security-kernel/src/operations-configuration/generated.ts';

/** Canonical generator calls only after assigning/registering the real profile.
 * No empty SQL, dummy purpose or permissive fallback is emitted while pending. */
export function buildOperationsSecretResolutionGuardsSql() {
  const profile = operationsConfigurationCoseProfiles.OperationsSecretResolutionV1;
  if (
    !profile ||
    !Number.isSafeInteger(profile.schemaId) ||
    !Number.isSafeInteger(profile.purposeCode)
  )
    throw new Error('OPS_SECRET_OBSERVATION_PROFILE_UNREGISTERED');
  const fields = profile.fields
    .filter((field) => field.key !== 0)
    .map((field) => {
      const expected =
        field.type === 'H32'
          ? `jsonb_build_object('bytes',substring(NEW.claims->>'${field.name}' from 8))`
          : field.type === 'uuidv7'
            ? `jsonb_build_object('bytes',replace(NEW.claims->>'${field.name}','-',''))`
            : `NEW.claims->'${field.name}'`;
      return field.type === 'u64' || field.type === 'u64p'
        ? `m->>'${field.key}' IS DISTINCT FROM NEW.claims->>'${field.name}'`
        : `m->'${field.key}' IS DISTINCT FROM ${expected}`;
    });
  return String.raw`
-- Privileged migration bootstrap owns this zero-argument, self-only accessor.
-- SET ROLE hides a login backend's statistics even from the same connection.
-- Keep the operations owner unprivileged: never grant it pg_read_all_stats.
RESET ROLE;
CREATE OR REPLACE FUNCTION openpc.operations_observer_backend_start()
RETURNS text LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT backend_start::text FROM pg_catalog.pg_stat_activity
 WHERE pid=pg_catalog.pg_backend_pid() AND usesysid=session_user::regrole
$$;
REVOKE ALL ON FUNCTION openpc.operations_observer_backend_start() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_observer_backend_start() TO openpc_control_owner;
SET ROLE openpc_control_owner;
${['operations_secret_association', 'operations_secret_observation']
  .map(
    (name) => `
ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader,openpc_control_owner;
GRANT SELECT,INSERT,UPDATE,TRIGGER ON control.${name} TO openpc_control_owner;
DROP POLICY IF EXISTS operations_secret_installer ON control.${name};
CREATE POLICY operations_secret_installer ON control.${name} TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));`,
  )
  .join('\n')}

-- FOR SHARE needs both SELECT and UPDATE visibility. This grants scoped
-- identity reads/locks only; new row versions and deletion remain forbidden.
${['participant', 'privacy_domain', 'principal', 'credential']
  .map((table) => {
    const scope = `openpc.matches_participant(participant_id)${table === 'privacy_domain' ? ' AND openpc.matches_privacy(privacy_domain_id)' : ''}
      AND openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'`;
    return `
DROP POLICY IF EXISTS operations_secret_identity_read ON control.${table};
CREATE POLICY operations_secret_identity_read ON control.${table} FOR SELECT TO openpc_control_owner USING(${scope});
DROP POLICY IF EXISTS operations_secret_identity_lock ON control.${table};
CREATE POLICY operations_secret_identity_lock ON control.${table} FOR UPDATE TO openpc_control_owner USING(${scope}) WITH CHECK(false);`;
  })
  .join('\n')}

-- Historical cryptographic/source binding ONLY. The real observer's
-- withCurrent() must also hold/recheck the actual external DB proof and process
-- identity while canonical consumes it; this is not a stand-alone current grant.
CREATE OR REPLACE FUNCTION openpc.operations_secret_association_bound(p_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.operations_secret_association%ROWTYPE; r jsonb; now_ms numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' THEN RETURN false; END IF;
 SELECT * INTO a FROM control.operations_secret_association WHERE association_id=p_id FOR SHARE;
 IF a.association_id IS NULL OR a.state<>'ACTIVE' OR NOT openpc.matches_participant(a.participant_id)
  OR NOT openpc.matches_privacy(a.privacy_domain_id) THEN RETURN false; END IF;
 r:=a.association; now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('operations-generation:'||a.environment_id,0))
  THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF now_ms<(r->>'issuerValidFromMs')::numeric OR now_ms>=(r->>'issuerValidUntilMs')::numeric THEN RETURN false; END IF;
 PERFORM 1 FROM control.participant p JOIN control.privacy_domain d ON d.participant_id=p.participant_id
 JOIN control.principal principal ON principal.participant_id=p.participant_id
 JOIN control.credential c ON c.participant_id=p.participant_id AND c.principal_id=principal.principal_id
 WHERE p.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id
 AND principal.principal_id=(r->>'principalId')::uuid AND c.credential_id=(r->>'workloadCredentialId')::uuid
 AND p.state='ACTIVE' AND d.state='ACTIVE' AND principal.state='ACTIVE' AND principal.kind='WORKLOAD'
 AND c.state='ACTIVE' AND c.kind='WORKLOAD_MTLS' AND c.credential_epoch=(r->>'workloadCredentialEpoch')::numeric
 AND c.valid_from<=clock_timestamp() AND c.valid_until>clock_timestamp() FOR SHARE OF p,d,principal,c;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('secret-recipient:'||a.participant_id::text||':'||a.privacy_domain_id::text,0));
 PERFORM 1 FROM control.operations_installation i JOIN control.operations_generation g USING(environment_id)
 JOIN control.installed_secret_recipient s ON s.participant_id=a.participant_id AND s.privacy_domain_id=a.privacy_domain_id
 WHERE i.environment_id=a.environment_id AND g.generation_id=a.generation_id
 AND i.state='ACTIVE' AND g.state='STAGED' AND i.installation_digest=r->>'operationsInstallationDigest'
 AND g.candidate_digest=r->>'candidateDigest' AND i.installation->'pins'->>'profile'='test'
 AND g.candidate->'configuration'->'postgres'->>'candidateIndexDsnSecretRef'=r->>'reference'
 AND s.state='ACTIVE' AND s.consumer_id='LS-FACT-BRIDGE' AND s.store_id='STORE-CANDIDATE-INDEX-PG'
 AND s.binding_digest=r->>'recipientBindingDigest' AND s.installation_digest=r->>'recipientInstallationDigest'
 AND s.generation=(r->>'recipientGeneration')::numeric AND s.payload=decode(r->>'recipientPayloadHex','hex')
 AND s.cose=decode(r->>'recipientCoseHex','hex') AND s.issuer_spki=decode(r->>'recipientIssuerSpkiHex','hex')
 AND s.workload_credential_id=(r->>'workloadCredentialId')::uuid
 AND s.workload_credential_epoch=(r->>'workloadCredentialEpoch')::numeric FOR SHARE OF i,g,s;
 RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_operations_secret_resolution() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.operations_secret_association%ROWTYPE; r jsonb; m jsonb; now_ms numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'OPS_SECRET_OBSERVATION_IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.state='REVOKED' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
   THEN RAISE EXCEPTION 'OPS_SECRET_OBSERVATION_IMMUTABLE'; END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='operations_secret_association' THEN
  r:=NEW.association;
  IF NEW.state<>'ACTIVE' OR NEW.association IS DISTINCT FROM convert_from(NEW.association_bytes,'UTF8')::jsonb
   OR NEW.association_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(r),'UTF8')
   OR r->>'profile'<>'test' OR r->>'associationId' IS DISTINCT FROM NEW.association_id::text
   OR r->>'participantId' IS DISTINCT FROM NEW.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR r->>'environmentId' IS DISTINCT FROM NEW.environment_id OR r->>'generationId' IS DISTINCT FROM NEW.generation_id::text
   OR r->>'field' IS DISTINCT FROM 'postgres.candidateIndexDsnSecretRef'
   OR r->>'consumerId' IS DISTINCT FROM 'LS-FACT-BRIDGE' OR r->>'storeId' IS DISTINCT FROM 'STORE-CANDIDATE-INDEX-PG'
   OR r->>'observerBackendPid' IS DISTINCT FROM pg_backend_pid()::text
   OR r->>'observerBackendStart' IS DISTINCT FROM openpc.operations_observer_backend_start()
  THEN RAISE EXCEPTION 'OPS_SECRET_ASSOCIATION_REJECTED'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM control.operations_secret_association WHERE association_id=NEW.association_id;
 IF NEW.state<>'OBSERVED' OR NEW.observation_id::text IS DISTINCT FROM NEW.claims->>'challengeId'
  OR a.participant_id<>NEW.participant_id OR a.privacy_domain_id<>NEW.privacy_domain_id
  OR NOT openpc.operations_secret_association_bound(a.association_id)
 THEN RAISE EXCEPTION 'OPS_SECRET_OBSERVATION_REJECTED'; END IF;
 r:=a.association; now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF (SELECT count(*) FROM jsonb_object_keys(NEW.claims))<>${profile.fields.length - 1}
  OR r->>'observerBackendPid' IS DISTINCT FROM pg_backend_pid()::text
  OR r->>'observerBackendStart' IS DISTINCT FROM openpc.operations_observer_backend_start()
  OR EXISTS(SELECT 1 FROM jsonb_each(NEW.claims) c WHERE c.key NOT IN ('challengeId','probeDigest','observedAtMs','validUntilMs')
   AND c.value IS DISTINCT FROM r->c.key)
  OR (NEW.claims->>'observedAtMs')::numeric>now_ms OR (NEW.claims->>'validUntilMs')::numeric<=now_ms
  OR (NEW.claims->>'validUntilMs')::numeric-(NEW.claims->>'observedAtMs')::numeric NOT BETWEEN 1 AND 30000
  OR (NEW.claims->>'validUntilMs')::numeric>(r->>'issuerValidUntilMs')::numeric
  OR NEW.claims->>'probeDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.probe),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'OPS_SECRET_OBSERVATION_REJECTED'; END IF;
 -- This checks framing/binding, NOT ES256 cryptography. The producer AND live
 -- consumer verifyOperationsSecretResolution against installed SPKI; no SQL
 -- row or source digest alone can satisfy generation admission.
 PERFORM openpc.archive_cose_binding(NEW.payload,NEW.cose,r->>'issuerKeyId',${profile.schemaId},${profile.purposeCode});
 m:=openpc.business_cbor(NEW.payload);
 IF (SELECT count(*) FROM jsonb_object_keys(m))<>${profile.fields.length}
  OR NOT m ?& ARRAY[${profile.fields.map((field) => `'${field.key}'`).join(',')}]
  OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${profile.definitionDigest.slice(7)}')
  OR ${fields.join('\n  OR ')}
 THEN RAISE EXCEPTION 'OPS_SECRET_OBSERVATION_REJECTED'; END IF;
 RETURN NEW;
END $$;
${['operations_secret_association', 'operations_secret_observation']
  .map(
    (name) => `
DROP TRIGGER IF EXISTS operations_secret_guard ON control.${name};
CREATE TRIGGER operations_secret_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_operations_secret_resolution();
DROP TRIGGER IF EXISTS operations_secret_truncate_guard ON control.${name};
CREATE TRIGGER operations_secret_truncate_guard BEFORE TRUNCATE ON control.${name}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_operations_secret_resolution();
REVOKE TRIGGER ON control.${name} FROM openpc_control_owner;`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION openpc.operations_secret_association_bound(uuid),openpc.guard_operations_secret_resolution() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_secret_association_bound(uuid) TO openpc_control_owner;
`;
}
