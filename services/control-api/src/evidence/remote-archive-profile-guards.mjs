import { evidenceArchiveProfiles } from '../../../../packages/security-kernel/src/evidence-archive/generated.ts';

const p = evidenceArchiveProfiles.EvidenceSinkProfileV1;
const protectedProfile = evidenceArchiveProfiles.EvidenceProtectedSinkProfileV1;

/** Installation is an operational trust action. Runtime membership never grants
 * profile installation. Signature verification against the pinned host root is
 * additionally mandatory in RemoteArchiveAuthority before any network effect. */
export const remoteArchiveProfileGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.archive_cose_binding(payload bytea,cose bytea,key_id text,schema_id integer,purpose integer)
RETURNS void LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE parsed jsonb; header jsonb;
BEGIN
 IF octet_length(payload) NOT BETWEEN 1 AND 65536 OR octet_length(cose) NOT BETWEEN 65 AND 66560
  OR get_byte(cose,0)<>210 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 parsed:=openpc.business_cbor_item(cose,1,0);
 IF (parsed->>'next')::integer IS DISTINCT FROM octet_length(cose) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 parsed:=parsed->'value';
 IF jsonb_typeof(parsed) IS DISTINCT FROM 'array' OR jsonb_array_length(parsed)<>4
  OR parsed->1 IS DISTINCT FROM '{}'::jsonb OR parsed->2 IS DISTINCT FROM openpc.business_bytes(payload)
  OR parsed->3 IS DISTINCT FROM jsonb_build_object('bytes',parsed->3->>'bytes')
  OR coalesce(parsed->3->>'bytes','')!~'^[0-9a-f]{128}$'
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 header:=openpc.business_cbor(decode(parsed->0->>'bytes','hex'));
 IF header IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),
  '3','application/pc+cbor','4',openpc.business_bytes(convert_to(key_id,'UTF8')),
  '100',schema_id,'101',1,'102',purpose,'103',2) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.archive_cose_binding(bytea,bytea,text,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.archive_cose_binding(bytea,bytea,text,integer,integer)
 TO openpc_control_owner,openpc_control_key_governor,openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_archive_installation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_owner','MEMBER')
  AND NOT pg_has_role(current_user,'openpc_control_key_governor','MEMBER')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_archive_trust()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.environment_id!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
  OR NEW.sink_id!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
  OR EXISTS(SELECT 1 FROM control.evidence_checkpoint c WHERE c.participant_id=NEW.participant_id
   AND c.privacy_domain_id=NEW.privacy_domain_id AND c.sink_id=NEW.sink_id)
  OR encode(substring(NEW.issuer_spki from 1 for 27),'hex')<>'3059301306072a8648ce3d020106082a8648ce3d03010703420004'
  OR NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=NEW.database_role AND r.rolcanlogin
   AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole
   AND pg_has_role(r.oid,'openpc_control_worker','USAGE')
   AND NOT pg_has_role(r.oid,'openpc_control_owner','MEMBER')
   AND NOT pg_has_role(r.oid,'openpc_control_key_governor','MEMBER'))
  OR NOT EXISTS(SELECT 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
   WHERE c.participant_id=NEW.participant_id AND c.credential_id=NEW.workload_credential_id
    AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC') AND w.kind='WORKLOAD'
    AND c.state='ACTIVE' AND w.state='ACTIVE' AND c.credential_epoch=NEW.workload_credential_epoch
    AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
    AND c.public_key_digest IS DISTINCT FROM sha256(NEW.issuer_spki))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_archive_profile()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE t control.evidence_archive_trust; c jsonb; expected jsonb; actual jsonb; streams jsonb; protected_profile boolean;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||NEW.participant_id::text,0));
 SELECT * INTO STRICT t FROM control.evidence_archive_trust WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND environment_id=NEW.environment_id AND sink_id=NEW.sink_id
  AND issuer_key_id=NEW.issuer_key_id;
 c:=NEW.claims; protected_profile:=c ? 'sourceKind';
 expected:=jsonb_build_object('environmentId',t.environment_id,'participantId',t.participant_id::text,
  'privacyDomainId',t.privacy_domain_id::text,'profileId',NEW.profile_id,'sinkId',t.sink_id,'revision',NEW.revision::text,
  'validFromMs',c->'validFromMs','validUntilMs',c->'validUntilMs','transportProfileDigest',NEW.transport_digest,
  'receiptSignerSpki',c->'receiptSignerSpki','streamIds',c->'streamIds','issuerKeyId',t.issuer_key_id,
  'workloadCredentialId',t.workload_credential_id::text,'workloadCredentialEpoch',t.workload_credential_epoch::text,
  'databaseRole',t.database_role);
 IF protected_profile THEN expected:=expected||jsonb_build_object('sourceKind','PROTECTED_PROOF','retentionPolicy','SOURCE_DEADLINE_EXACT','heldExpiredPolicy','PRESERVE_EXISTING_ONLY'); END IF;
 IF c IS DISTINCT FROM expected OR jsonb_typeof(c->'streamIds') IS DISTINCT FROM 'array'
  OR jsonb_array_length(c->'streamIds') NOT BETWEEN 1 AND 256
  OR jsonb_typeof(c->'validFromMs') IS DISTINCT FROM 'number'
  OR jsonb_typeof(c->'validUntilMs') IS DISTINCT FROM 'number'
  OR coalesce(c->>'validFromMs','')!~'^[0-9]+$' OR coalesce(c->>'validUntilMs','')!~'^[0-9]+$'
  OR (c->>'validFromMs')::numeric<t.valid_from_ms OR (c->>'validUntilMs')::numeric>t.valid_until_ms
  OR (c->>'validFromMs')::numeric>=(c->>'validUntilMs')::numeric
  OR coalesce(c->>'receiptSignerSpki','')!~'^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'
  OR sha256(decode(c->>'receiptSignerSpki','hex'))=sha256(t.issuer_spki)
  OR NEW.transport_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.transport),'UTF8')),'hex')
  OR NEW.transport->>'sinkId' IS DISTINCT FROM t.sink_id OR NEW.transport->>'profileId' IS DISTINCT FROM NEW.profile_id
  OR NEW.revision IS DISTINCT FROM (SELECT coalesce(max(revision),0)+1 FROM control.evidence_archive_profile
   WHERE participant_id=t.participant_id AND privacy_domain_id=t.privacy_domain_id AND environment_id=t.environment_id AND sink_id=t.sink_id)
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT jsonb_agg(v ORDER BY convert_to(v#>>'{}','UTF8')) INTO streams
  FROM (SELECT DISTINCT value v FROM jsonb_array_elements(c->'streamIds')) items;
 IF streams IS DISTINCT FROM c->'streamIds' OR EXISTS(SELECT 1 FROM jsonb_array_elements(streams) v
  WHERE jsonb_typeof(v)<>'string' OR (v#>>'{}')!~'^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$')
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 actual:=openpc.business_cbor(NEW.payload);
 expected:=jsonb_build_object('0',openpc.business_bytes(decode(CASE WHEN protected_profile THEN '${protectedProfile.definitionDigest.slice(7)}' ELSE '${p.definitionDigest.slice(7)}' END,'hex')),
  '1',t.environment_id,'2',openpc.business_uuid(t.participant_id),'3',openpc.business_uuid(t.privacy_domain_id),
  '4',NEW.profile_id,'5',t.sink_id,'6',NEW.revision,'7',(c->>'validFromMs')::numeric,'8',(c->>'validUntilMs')::numeric,
  '9',openpc.business_bytes(decode(substring(NEW.transport_digest from 8),'hex')),
  '10',openpc.business_bytes(decode(c->>'receiptSignerSpki','hex')),'11',streams,
  '12',openpc.business_bytes(decode(substring(t.issuer_key_id from 8),'hex')),
  '13',openpc.business_uuid(t.workload_credential_id),'14',t.workload_credential_epoch,'15',t.database_role);
 IF protected_profile THEN expected:=expected||jsonb_build_object('16',1,'17',1,'18',1); END IF;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.archive_cose_binding(NEW.payload,NEW.cose,t.issuer_key_id,CASE WHEN protected_profile THEN ${protectedProfile.schemaId} ELSE ${p.schemaId} END,CASE WHEN protected_profile THEN ${protectedProfile.purposeCode} ELSE ${p.purposeCode} END);
 NEW.admitted_at:=clock_timestamp(); RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_archive_profile(wanted text,stream text)
RETURNS control.evidence_archive_profile LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p control.evidence_archive_profile; t control.evidence_archive_trust; now_ms numeric;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_worker','USAGE')
  OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT p FROM control.evidence_archive_profile WHERE profile_digest=wanted
  AND participant_id=current_setting('openpc.participant_id')::uuid
  AND privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid;
 SELECT * INTO STRICT t FROM control.evidence_archive_trust WHERE participant_id=p.participant_id
  AND privacy_domain_id=p.privacy_domain_id AND environment_id=p.environment_id AND sink_id=p.sink_id;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000);
 IF current_user<>t.database_role OR session_user<>t.database_role
  OR NOT (p.claims->'streamIds' ? stream) OR now_ms<(p.claims->>'validFromMs')::numeric
  OR now_ms>=(p.claims->>'validUntilMs')::numeric OR now_ms<t.valid_from_ms OR now_ms>=t.valid_until_ms
  OR EXISTS(SELECT 1 FROM control.evidence_archive_profile newer WHERE newer.participant_id=p.participant_id
   AND newer.privacy_domain_id=p.privacy_domain_id AND newer.environment_id=p.environment_id
   AND newer.sink_id=p.sink_id AND newer.revision>p.revision)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.lock_archive_workload(p.profile_digest);
 RETURN p;
END $$;
REVOKE ALL ON FUNCTION openpc.require_archive_profile(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.require_archive_profile(text,text) TO openpc_control_worker;

${['participant', 'privacy_domain', 'principal', 'credential']
  .map(
    (table) => `
DROP POLICY IF EXISTS archive_workload_read_fence ON control.${table};
CREATE POLICY archive_workload_read_fence ON control.${table} FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1')
 WITH CHECK(false);`,
  )
  .join('\n')}
-- Existing Identity columns remain read-only to the archive login. This narrow
-- owner function takes the row locks needed to fence revocation at commit.
CREATE OR REPLACE FUNCTION openpc.lock_archive_workload(wanted text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE p control.evidence_archive_profile; t control.evidence_archive_trust;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT p FROM control.evidence_archive_profile WHERE profile_digest=wanted
  AND participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id();
 SELECT * INTO STRICT t FROM control.evidence_archive_trust WHERE participant_id=p.participant_id
  AND privacy_domain_id=p.privacy_domain_id AND environment_id=p.environment_id AND sink_id=p.sink_id;
 IF session_user<>t.database_role THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.participant v WHERE v.participant_id=p.participant_id AND v.state='ACTIVE'
  AND v.archived_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.privacy_domain v WHERE v.participant_id=p.participant_id
  AND v.privacy_domain_id=p.privacy_domain_id AND v.state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM 1 FROM control.credential c JOIN control.principal w USING(participant_id,principal_id)
  WHERE c.participant_id=t.participant_id AND c.credential_id=t.workload_credential_id
   AND c.credential_epoch=t.workload_credential_epoch AND c.kind IN ('WORKLOAD_MTLS','WORKLOAD_OIDC')
   AND c.state='ACTIVE' AND w.kind='WORKLOAD' AND w.state='ACTIVE'
   AND c.valid_from<=clock_timestamp() AND (c.valid_until IS NULL OR c.valid_until>clock_timestamp())
   AND c.public_key_digest IS DISTINCT FROM sha256(decode(p.claims->>'receiptSignerSpki','hex'))
  FOR SHARE OF c,w;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
END $$;
ALTER FUNCTION openpc.lock_archive_workload(text) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.lock_archive_workload(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_archive_workload(text) TO openpc_control_worker;

${['trust', 'profile', 'commit_key']
  .map(
    (name) => `
ALTER TABLE control.evidence_archive_${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_archive_${name} FROM PUBLIC,openpc_control_runtime,openpc_control_reader,openpc_control_worker;
GRANT SELECT,INSERT ON control.evidence_archive_${name} TO openpc_control_owner,openpc_control_key_governor;
DROP POLICY IF EXISTS archive_installation ON control.evidence_archive_${name};
CREATE POLICY archive_installation ON control.evidence_archive_${name} TO openpc_control_owner,openpc_control_key_governor
 USING(true) WITH CHECK(true);
DROP TRIGGER IF EXISTS archive_installation ON control.evidence_archive_${name};
CREATE TRIGGER archive_installation BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_archive_${name}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_installation();`,
  )
  .join('\n')}
GRANT SELECT ON control.evidence_archive_trust,control.evidence_archive_profile TO openpc_control_worker,openpc_control_runtime,openpc_control_reader;
DROP TRIGGER IF EXISTS archive_trust ON control.evidence_archive_trust;
CREATE TRIGGER archive_trust BEFORE INSERT ON control.evidence_archive_trust FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_trust();
DROP TRIGGER IF EXISTS archive_profile ON control.evidence_archive_profile;
CREATE TRIGGER archive_profile BEFORE INSERT ON control.evidence_archive_profile FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_profile();
`;
