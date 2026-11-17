import { runtimeArtifactSourceImportGuardsSql } from './runtime-artifact-source-import-guards.mjs';
import { runtimeArtifactSourceNonUseSql } from './runtime-artifact-source-non-use.mjs';
import { runtimeArtifactSourceWireSql } from './runtime-artifact-source-wire.mjs';

// Native custody is independent of the Control backup. These owners authenticate
// installation and committed intent; they do not turn a denial into deletion.
const installed = (row) => `jsonb_build_object('participant_id',${row}.participant_id::text,
 'privacy_domain_id',${row}.privacy_domain_id::text,'source_owner_id',${row}.source_owner_id::text,
 'source_file_binding',encode(${row}.source_file_binding,'hex'))`;

export const runtimeArtifactSourceGuardsSql = `
${['source', 'source_verifier_key', 'source_disposition', 'source_denial']
  .map(
    (suffix) => `
ALTER TABLE control.runtime_artifact_${suffix} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.runtime_artifact_${suffix} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;`,
  )
  .join('\n')}
GRANT SELECT ON control.runtime_artifact_source,control.runtime_artifact_source_disposition,
 control.runtime_artifact_source_denial TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
${['source', 'source_verifier_key']
  .map(
    (suffix) => `
GRANT SELECT,INSERT ON control.runtime_artifact_${suffix} TO openpc_control_owner,openpc_control_key_governor;
DROP POLICY IF EXISTS runtime_artifact_source_installation ON control.runtime_artifact_${suffix};
CREATE POLICY runtime_artifact_source_installation ON control.runtime_artifact_${suffix}
 TO openpc_control_owner,openpc_control_key_governor USING(true) WITH CHECK(true);
DROP TRIGGER IF EXISTS runtime_artifact_source_installation ON control.runtime_artifact_${suffix};
CREATE TRIGGER runtime_artifact_source_installation BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_artifact_${suffix}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_archive_installation();`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_source_installation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.archive_custody IS NOT NULL AND (
  NEW.custody_root->>'consumer_profile' IS DISTINCT FROM 'openpc:local-runtime-source-consumers:v2'
  OR jsonb_typeof(NEW.archive_custody) IS DISTINCT FROM 'object'
  OR NEW.archive_custody IS DISTINCT FROM jsonb_build_object('database_role',NEW.archive_custody->'database_role','stream_id',NEW.archive_custody->'stream_id','keys',NEW.archive_custody->'keys')
  OR jsonb_typeof(NEW.archive_custody->'keys') IS DISTINCT FROM 'object'
  OR coalesce(NEW.archive_custody->>'stream_id','') !~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'
  OR NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=NEW.archive_custody->>'database_role' AND r.rolcanlogin
   AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication
   AND pg_has_role(r.oid,'openpc_control_worker','USAGE')
   AND shobj_description(r.oid,'pg_authid')::jsonb=jsonb_build_object('installation',${installed('NEW')},'root',NEW.custody_root,'archive',NEW.archive_custody)))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-INSTALLATION-UNAVAILABLE'; END IF;
 IF NEW.custody_root IS NOT NULL AND (
  NEW.custody_root IS DISTINCT FROM jsonb_build_object(
   'generation_id',NEW.custody_root->>'generation_id',
   'journal_binding',NEW.custody_root->>'journal_binding',
   'retained_root_binding',NEW.custody_root->>'retained_root_binding',
   'consumer_profile',NEW.custody_root->>'consumer_profile') ||
   CASE WHEN NEW.custody_root->>'consumer_profile'='openpc:local-runtime-source-consumers:v2'
    THEN jsonb_build_object('database',openpc.runtime_artifact_database_identity()) ELSE '{}'::jsonb END
  OR coalesce(NEW.custody_root->>'consumer_profile','') NOT IN ('openpc:local-runtime-source-consumers:v1','openpc:local-runtime-source-consumers:v2')
  OR coalesce(NEW.custody_root->>'generation_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR coalesce(NEW.custody_root->>'journal_binding','') !~ '^[0-9a-f]{64}$'
  OR coalesce(NEW.custody_root->>'retained_root_binding','') !~ '^[0-9a-f]{64}$'
  OR NEW.custody_root->>'journal_binding'=NEW.custody_root->>'retained_root_binding')
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- Rooted custody is installed with actual first trust. Existing scopes keep
 -- legacy custody; neither this birth pin nor an empty scope proves non-use.
 IF NEW.custody_root IS NOT NULL AND (
  NOT EXISTS(SELECT 1 FROM control.participant p WHERE p.participant_id=NEW.participant_id
    AND p.root_privacy_domain_id=NEW.privacy_domain_id AND p.xmin=pg_current_xact_id()::xid)
  OR NOT EXISTS(SELECT 1 FROM control.privacy_domain p WHERE p.participant_id=NEW.participant_id
    AND p.privacy_domain_id=NEW.privacy_domain_id AND p.xmin=pg_current_xact_id()::xid)
  OR EXISTS(SELECT 1 FROM control.runtime_artifact_source s WHERE s.participant_id=NEW.participant_id
    AND s.privacy_domain_id=NEW.privacy_domain_id))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-GENESIS-REQUIRED'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=NEW.database_role AND r.rolcanlogin
  AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb
  AND pg_has_role(r.oid,'openpc_control_worker','USAGE')
  AND NOT pg_has_role(r.oid,'openpc_control_runtime','MEMBER')
  AND NOT pg_has_role(r.oid,'openpc_control_owner','MEMBER')
  AND NOT pg_has_role(r.oid,'openpc_control_key_governor','MEMBER'))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_source_binding ON control.runtime_artifact_source;
CREATE TRIGGER runtime_artifact_source_binding BEFORE INSERT ON control.runtime_artifact_source
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_source_installation();

CREATE OR REPLACE FUNCTION openpc.lock_runtime_artifact_source_custody()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
  OR current_setting('session_replication_role')<>'origin'
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND NOT rolsuper AND NOT rolbypassrls)
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('module-release-catalog',0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))
  OR NOT pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.runtime_artifact_source_admission(a control.runtime_artifact_source_disposition)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.runtime_artifact_source; receipt control.audit_occurrence;
BEGIN
 -- This assertion belongs to the governed mutation owner. Missing registration,
 -- grants or admission validation is an error, never an empty custody inventory.
 PERFORM openpc.assert_runtime_artifact_source_disposition_committed(a);
 SELECT * INTO STRICT s FROM control.runtime_artifact_source WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND source_owner_id=a.source_owner_id;
 SELECT * INTO STRICT receipt FROM control.audit_occurrence WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND operation_id=a.operation_id AND aggregate_id=a.disposition_id
  AND aggregate_type='runtime-artifact-disposition' AND profile_id='pc.control.runtime-artifact.disposition'
  AND catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE';
 RETURN jsonb_build_object('installation',${installed('s')},'disposition_id',a.disposition_id::text,
  'operation_id',a.operation_id::text,'input_id',a.runtime_configuration_input_id::text,
  'configuration_digest',encode(a.configuration_digest,'hex'),
  'admission_receipt_digest',encode(receipt.receipt_digest,'hex'),'selection_digest',encode(a.selection_digest,'hex'));
END $$;

CREATE OR REPLACE FUNCTION openpc.read_runtime_artifact_source_admissions(installation jsonb,public_key bytea)
RETURNS TABLE(admission jsonb,signed_denial bytea)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE s control.runtime_artifact_source; a control.runtime_artifact_source_disposition;
BEGIN
 PERFORM openpc.lock_runtime_artifact_source_custody();
 SELECT * INTO STRICT s FROM control.runtime_artifact_source
  WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id()
   AND source_owner_id=(installation->>'source_owner_id')::uuid;
 IF installation IS DISTINCT FROM ${installed('s')} OR public_key IS DISTINCT FROM s.source_public_key
  OR session_user<>s.database_role OR NOT openpc.runtime_artifact_source_key_installed(s.source_owner_id)
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF (SELECT count(*) FROM control.runtime_artifact_source_disposition WHERE participant_id=s.participant_id
  AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id)>4096
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 FOR a IN SELECT d.* FROM control.runtime_artifact_source_disposition d WHERE d.participant_id=s.participant_id
  AND d.privacy_domain_id=s.privacy_domain_id AND d.source_owner_id=s.source_owner_id
  ORDER BY d.admitted_at,d.disposition_id LOOP
  IF EXISTS(SELECT 1 FROM control.runtime_artifact_source_disposition d WHERE d.disposition_id=a.disposition_id
    AND d.xmin=pg_current_xact_id()::xid)
  THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  admission:=openpc.runtime_artifact_source_admission(a);
  SELECT d.signed_denial INTO signed_denial FROM control.runtime_artifact_source_denial d
   WHERE d.participant_id=a.participant_id AND d.privacy_domain_id=a.privacy_domain_id AND d.disposition_id=a.disposition_id;
  RETURN NEXT;
 END LOOP;
END $$;

-- Installation key existence is visible through a scoped boolean only. The
-- secret never leaves the definer that verifies the native transaction MAC.
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_source_key_installed(source_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM control.runtime_artifact_source_verifier_key k JOIN control.runtime_artifact_source s
  USING(participant_id,privacy_domain_id,source_owner_id) WHERE k.participant_id=openpc.current_participant_id()
  AND k.privacy_domain_id=openpc.current_privacy_domain_id() AND k.source_owner_id=source_id AND s.database_role=session_user)
$$;
ALTER FUNCTION openpc.runtime_artifact_source_key_installed(uuid) OWNER TO openpc_control_owner;

CREATE OR REPLACE FUNCTION openpc.verify_runtime_artifact_source_commit(source_id uuid,wire bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE secret bytea; expected bytea; different integer:=0;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF octet_length(nonce) IS DISTINCT FROM 32 OR octet_length(mac) IS DISTINCT FROM 32
  OR octet_length(wire) NOT BETWEEN 1 AND 8192 OR wire IS NULL
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1'
  OR NOT pg_has_role(session_user,'openpc_control_worker','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT k.verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key k
  JOIN control.runtime_artifact_source s USING(participant_id,privacy_domain_id,source_owner_id)
  WHERE k.participant_id=openpc.current_participant_id() AND k.privacy_domain_id=openpc.current_privacy_domain_id()
   AND k.source_owner_id=source_id AND s.database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_SOURCE_DENIAL_COMMIT_V1'||pg_current_xact_id()::text
  ||encode(sha256(wire),'hex'),'UTF8')||nonce,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different | (get_byte(expected,n) # get_byte(mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
END $$;
ALTER FUNCTION openpc.verify_runtime_artifact_source_commit(uuid,bytea,bytea,bytea) OWNER TO openpc_control_owner;

${runtimeArtifactSourceNonUseSql}
${runtimeArtifactSourceWireSql}

CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_source_denial()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.runtime_artifact_source_disposition; wire jsonb; claims jsonb; original jsonb;
 previous control.runtime_artifact_source_denial;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 PERFORM openpc.lock_runtime_artifact_source_custody();
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.runtime_artifact_source_disposition WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND disposition_id=NEW.disposition_id AND source_owner_id=NEW.source_owner_id
  AND xmin<>pg_current_xact_id()::xid;
 original:=openpc.runtime_artifact_source_admission(a);
 PERFORM openpc.verify_runtime_artifact_source_commit(NEW.source_owner_id,NEW.signed_denial,NEW.verification_nonce,NEW.verification_mac);
 wire:=convert_from(NEW.signed_denial,'UTF8')::jsonb;
 claims:=wire->'claims';
 SELECT * INTO previous FROM control.runtime_artifact_source_denial WHERE participant_id=NEW.participant_id
  AND privacy_domain_id=NEW.privacy_domain_id AND source_owner_id=NEW.source_owner_id ORDER BY sequence DESC LIMIT 1;
 IF NEW.sequence IS DISTINCT FROM coalesce(previous.sequence,0)+1
  OR NEW.previous_denial_digest IS DISTINCT FROM previous.denial_digest
  OR NEW.denial_digest IS DISTINCT FROM sha256(NEW.signed_denial)
  OR NEW.signed_denial IS DISTINCT FROM openpc.runtime_artifact_source_denial_envelope_bytes(wire)
  OR claims IS DISTINCT FROM jsonb_build_object('version',2,'admission',original,'sequence',NEW.sequence,
    'previous_denial_digest',encode(NEW.previous_denial_digest,'hex'),'recovery','ForwardOnly','custody',claims->'custody')
  OR wire IS DISTINCT FROM jsonb_build_object('purpose','openpc:runtime-artifact-source-denial:v1','claims',claims,
   'claims_digest',encode(sha256(openpc.runtime_artifact_source_denial_claims_bytes(claims)),'hex'),
   'signature_p1363_hex',wire->>'signature_p1363_hex')
  OR coalesce(wire->>'signature_p1363_hex','')!~'^[0-9a-f]{128}$'
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-CUSTODY'; END IF;
 PERFORM openpc.assert_runtime_artifact_source_non_use(a,claims->'custody');
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_source_denial_guard ON control.runtime_artifact_source_denial;
CREATE TRIGGER runtime_artifact_source_denial_guard BEFORE INSERT OR UPDATE OR DELETE ON control.runtime_artifact_source_denial
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_artifact_source_denial();

CREATE OR REPLACE FUNCTION openpc.commit_runtime_artifact_source_denial(wanted uuid,wire bytea,nonce bytea,mac bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.runtime_artifact_source_disposition; retained bytea; claims jsonb;
BEGIN
 PERFORM openpc.lock_runtime_artifact_source_custody();
 SELECT * INTO STRICT a FROM control.runtime_artifact_source_disposition WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND disposition_id=wanted AND xmin<>pg_current_xact_id()::xid;
 PERFORM openpc.runtime_artifact_source_admission(a);
 PERFORM openpc.verify_runtime_artifact_source_commit(a.source_owner_id,wire,nonce,mac);
 SELECT signed_denial INTO retained FROM control.runtime_artifact_source_denial WHERE participant_id=a.participant_id
  AND privacy_domain_id=a.privacy_domain_id AND disposition_id=a.disposition_id;
 IF FOUND THEN
  IF retained IS DISTINCT FROM wire THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-CUSTODY'; END IF;
  RETURN;
 END IF;
 claims:=convert_from(wire,'UTF8')::jsonb->'claims';
 INSERT INTO control.runtime_artifact_source_denial(participant_id,privacy_domain_id,source_owner_id,disposition_id,
  sequence,previous_denial_digest,signed_denial,denial_digest,verification_nonce,verification_mac)
 VALUES(a.participant_id,a.privacy_domain_id,a.source_owner_id,a.disposition_id,(claims->>'sequence')::numeric,
  decode(claims->>'previous_denial_digest','hex'),wire,sha256(wire),nonce,mac);
END $$;

-- Admission grants and its exact receipt/eligibility owner arrive together.
-- Native readback cannot fabricate an admission in their absence.
CREATE OR REPLACE FUNCTION openpc.guard_runtime_artifact_source_disposition_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-IMMUTABLE-ROW'; END IF;
 RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-ADMISSION-UNAVAILABLE';
END $$;
DROP TRIGGER IF EXISTS runtime_artifact_source_disposition_guard ON control.runtime_artifact_source_disposition;
CREATE TRIGGER runtime_artifact_source_disposition_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
 ON control.runtime_artifact_source_disposition FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_runtime_artifact_source_disposition_immutable();

REVOKE ALL ON FUNCTION openpc.guard_runtime_artifact_source_installation(),openpc.lock_runtime_artifact_source_custody(),
 openpc.runtime_artifact_source_admission(control.runtime_artifact_source_disposition),
 openpc.read_runtime_artifact_source_admissions(jsonb,bytea),openpc.runtime_artifact_source_key_installed(uuid),
 openpc.verify_runtime_artifact_source_commit(uuid,bytea,bytea,bytea),openpc.guard_runtime_artifact_source_denial(),
 openpc.commit_runtime_artifact_source_denial(uuid,bytea,bytea,bytea),openpc.guard_runtime_artifact_source_disposition_immutable() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_runtime_artifact_source_custody(),
 openpc.runtime_artifact_source_admission(control.runtime_artifact_source_disposition),
 openpc.read_runtime_artifact_source_admissions(jsonb,bytea),openpc.runtime_artifact_source_key_installed(uuid),
 openpc.verify_runtime_artifact_source_commit(uuid,bytea,bytea,bytea),
 openpc.commit_runtime_artifact_source_denial(uuid,bytea,bytea,bytea) TO openpc_control_worker;
GRANT INSERT ON control.runtime_artifact_source_denial TO openpc_control_worker;
${runtimeArtifactSourceImportGuardsSql}
`;
