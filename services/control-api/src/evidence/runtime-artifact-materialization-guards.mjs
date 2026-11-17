/** The native source, not a SQL flag or read result, records possible use before
 * plaintext leaves the database. These declarations are installed by the owning
 * generated migration. V1 remains compatible but can never prove non-use. */
const profile = 'openpc:local-runtime-source-consumers:v2';
// Built-in NOLOGIN roles such as pg_read_all_data are not consumers when no
// application login can use or SET them. Count every actual reachable role,
// including NOINHERIT memberships and the installed product group roles.
const reachableRole = `(r.rolcanlogin OR r.rolname IN ('openpc_control_runtime','openpc_control_worker','openpc_control_reader')
 OR EXISTS(SELECT 1 FROM pg_roles login WHERE login.rolcanlogin AND NOT login.rolsuper
  AND NOT pg_has_role(login.oid,'openpc_control_owner','MEMBER') AND pg_has_role(login.oid,r.oid,'SET')))`;
const roleCheck = `EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user
 AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
 AND NOT pg_has_role(oid,'openpc_control_owner','MEMBER')
 AND NOT pg_has_role(oid,'openpc_control_key_governor','MEMBER'))
 AND (pg_has_role(session_user,'openpc_control_worker','USAGE')
  OR pg_has_role(session_user,'openpc_control_runtime','USAGE')
  OR pg_has_role(session_user,'openpc_control_reader','USAGE'))`;
// A restricted SECURITY DEFINER cannot see another role's backend_start in
// pg_stat_activity. The actual backend PID plus the cluster start and the full
// transaction ID bind the same live session without a statistics-reader grant.
const backend = `pg_backend_pid()::text||':'||extract(epoch FROM pg_postmaster_start_time())::text`;
const installation = (s) => `jsonb_build_object('participant_id',${s}.participant_id::text,
 'privacy_domain_id',${s}.privacy_domain_id::text,'source_owner_id',${s}.source_owner_id::text,
 'source_file_binding',encode(${s}.source_file_binding,'hex'))`;
const identity = (i) => `jsonb_build_object('input_id',${i}.runtime_configuration_input_id::text,
 'module_installation_id',${i}.module_installation_id::text,
 'module_configuration_generation_id',${i}.module_configuration_generation_id::text,
 'configuration_digest',encode(${i}.configuration_digest,'hex'))`;

const functions = [
  {
    name: 'runtime_artifact_database_identity',
    args: '',
    signature: '',
    result: 'jsonb',
    body: `
BEGIN
 RETURN (SELECT jsonb_build_object('system_identifier',s.system_identifier::text,'database_oid',d.oid::text)
  FROM pg_control_system() s,pg_database d WHERE d.datname=current_database());
END `,
  },
  {
    name: 'runtime_artifact_materialization_source',
    args: '',
    signature: '',
    result: 'control.runtime_artifact_source',
    body: `
DECLARE s control.runtime_artifact_source; marker text; pin jsonb; installed_role oid;
BEGIN
 PERFORM openpc.assert_request_context(true);
 marker:='openpc_rs_scope_'||rtrim(translate(encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_array(
  'openpc:runtime-source-scope:v1',openpc.current_participant_id()::text,openpc.current_privacy_domain_id()::text)),'UTF8')),
  'base64'),'+/','-_'),'=');
 SELECT oid INTO installed_role FROM pg_roles WHERE rolname=marker;
 IF (SELECT count(*) FROM control.runtime_artifact_source WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id())>1 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 SELECT * INTO s FROM control.runtime_artifact_source WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id();
 IF installed_role IS NULL THEN
  IF s.custody_root IS NOT NULL THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
  RETURN s;
 END IF;
 pin:=shobj_description(installed_role,'pg_authid')::jsonb;
 IF s.source_owner_id IS NULL OR s.custody_root IS NULL
  OR pin->'version' IS DISTINCT FROM '1'::jsonb OR pin->'installation' IS DISTINCT FROM ${installation('s')}
  OR pin->'root' IS DISTINCT FROM s.custody_root OR pin->>'database_role' IS DISTINCT FROM s.database_role
  OR pin->'archive_custody' IS DISTINCT FROM s.archive_custody
  OR NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.oid=installed_role AND NOT r.rolcanlogin AND NOT r.rolsuper
   AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication)
  OR (SELECT count(*) FROM pg_auth_members WHERE roleid=installed_role)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor
   WHERE m.roleid=installed_role AND member.rolname=s.database_role AND grantor.rolsuper
    AND NOT m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 RETURN s;
END `,
  },
  {
    name: 'runtime_artifact_input_information',
    args: 'input_id uuid',
    signature: 'uuid',
    result: 'jsonb',
    body: `
DECLARE input control.runtime_configuration_input;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT (${roleCheck}) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND runtime_configuration_input_id=input_id;
 RETURN jsonb_build_object('bytesMatch',input.configuration_digest=sha256(input.configuration_cbor),
  'byteLength',octet_length(input.configuration_cbor)::text);
END `,
  },
  {
    name: 'runtime_artifact_materialization_challenge',
    args: 'input_id uuid',
    signature: 'uuid',
    result: 'jsonb',
    body: `
DECLARE input control.runtime_configuration_input; s control.runtime_artifact_source; wire bytea; secret bytea;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT (${roleCheck}) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND runtime_configuration_input_id=input_id;
 s:=openpc.runtime_artifact_materialization_source();
 IF s.custody_root IS NULL OR s.custody_root->>'consumer_profile'='openpc:local-runtime-source-consumers:v1'
 THEN RETURN NULL; END IF;
 IF NOT openpc.runtime_artifact_new_use_allowed(input.participant_id,input.privacy_domain_id,input.configuration_digest)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-DENIED'; END IF;
 PERFORM openpc.assert_runtime_artifact_materialization_boundary();
 IF s.custody_root->>'consumer_profile' IS DISTINCT FROM '${profile}'
  OR s.custody_root->'database' IS DISTINCT FROM openpc.runtime_artifact_database_identity()
  OR input.configuration_digest IS DISTINCT FROM sha256(input.configuration_cbor)
  OR (SELECT count(*) FROM control.runtime_artifact_source WHERE participant_id=input.participant_id
    AND privacy_domain_id=input.privacy_domain_id)<>1
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 wire:=convert_to(jsonb_build_object('version',2,'installation',${installation('s')},'binding',s.custody_root,
  'materialization',jsonb_build_object('input',${identity('input')},'reader_role',session_user::text,
   'transaction_id',pg_current_xact_id()::text,'backend_id',${backend},'request_id',uuidv7()::text))::text,'UTF8');
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key WHERE participant_id=s.participant_id
  AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id;
 RETURN jsonb_build_object('wire',(SELECT jsonb_agg(get_byte(wire,n) ORDER BY n) FROM generate_series(0,octet_length(wire)-1) n),
  'mac',(SELECT jsonb_agg(get_byte(mac,n) ORDER BY n) FROM
   (SELECT public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_MATERIALIZATION_REQUEST_V2','UTF8')||wire,secret,'sha256') mac) m,
   generate_series(0,31) n));
END `,
  },
  {
    name: 'runtime_artifact_input_payload',
    args: 'input_id uuid',
    signature: 'uuid',
    result: 'bytea',
    body: `
DECLARE input control.runtime_configuration_input; s control.runtime_artifact_source; secret bytea;
 permits jsonb; permit jsonb; wire bytea; mac bytea; expected bytea; different integer:=0;
 document jsonb; challenge jsonb; materialization jsonb; observation jsonb; root jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT (${roleCheck}) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND runtime_configuration_input_id=input_id;
 s:=openpc.runtime_artifact_materialization_source();
 IF s.custody_root IS NULL OR s.custody_root->>'consumer_profile'='openpc:local-runtime-source-consumers:v1'
 THEN RETURN input.configuration_cbor; END IF;
 IF NOT openpc.runtime_artifact_new_use_allowed(input.participant_id,input.privacy_domain_id,input.configuration_digest)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-DENIED'; END IF;
 PERFORM openpc.assert_runtime_artifact_materialization_boundary();
 IF s.custody_root->>'consumer_profile' IS DISTINCT FROM '${profile}'
  OR s.custody_root->'database' IS DISTINCT FROM openpc.runtime_artifact_database_identity()
  OR input.configuration_digest IS DISTINCT FROM sha256(input.configuration_cbor)
  OR (SELECT count(*) FROM control.runtime_artifact_source WHERE participant_id=input.participant_id
    AND privacy_domain_id=input.privacy_domain_id)<>1
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 IF coalesce(octet_length(current_setting('openpc.runtime_source_read_permits',true)),0) NOT BETWEEN 2 AND 1048576
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 permits:=current_setting('openpc.runtime_source_read_permits',true)::jsonb;
 permit:=permits->input_id::text;
 IF permit IS DISTINCT FROM jsonb_build_object('wire',permit->'wire','mac',permit->'mac')
  OR coalesce(length(permit->>'wire'),0) NOT BETWEEN 2 AND 32768
  OR coalesce(permit->>'wire','') !~ '^[0-9a-f]+$' OR length(permit->>'wire')%2<>0
  OR coalesce(permit->>'mac','') !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 wire:=decode(permit->>'wire','hex'); mac:=decode(permit->>'mac','hex');
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key WHERE participant_id=s.participant_id
  AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id;
 expected:=public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_MATERIALIZATION_RESPONSE_V2','UTF8')||wire,secret,'sha256');
 FOR n IN 0..31 LOOP different:=different | (get_byte(expected,n) # get_byte(mac,n)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 document:=convert_from(wire,'UTF8')::jsonb; challenge:=document->'challenge';
 materialization:=challenge->'materialization'; observation:=document->'observation'->'claims'; root:=document->'root'->'claims';
 IF document IS DISTINCT FROM jsonb_build_object('challenge',challenge,'observation',document->'observation','root',document->'root')
  OR challenge IS DISTINCT FROM jsonb_build_object('version',2,'installation',${installation('s')},'binding',s.custody_root,
   'materialization',jsonb_build_object('input',${identity('input')},'reader_role',session_user::text,
    'transaction_id',pg_current_xact_id()::text,'backend_id',${backend},'request_id',materialization->>'request_id'))
  OR coalesce(materialization->>'request_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR document->'observation'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-history:v1'
  OR observation->'version' IS DISTINCT FROM '1'::jsonb
  OR observation->'installation' IS DISTINCT FROM ${installation('s')}
  OR observation->'observation' IS DISTINCT FROM jsonb_build_object('MaterializedOrUnknown',observation->'observation'->'MaterializedOrUnknown')
  OR observation->'observation'->'MaterializedOrUnknown'->'input' IS DISTINCT FROM ${identity('input')}
  OR document->'root'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-root:v1'
  OR root->'version' IS DISTINCT FROM '1'::jsonb OR root->'installation' IS DISTINCT FROM ${installation('s')}
  OR root->'binding' IS DISTINCT FROM s.custody_root
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-UNPROVEN'; END IF;
 RETURN input.configuration_cbor;
END `,
  },
  {
    name: 'runtime_artifact_archive_owner',
    args: 'stream text',
    signature: 'text',
    result: 'control.runtime_artifact_source',
    body: `
DECLARE s control.runtime_artifact_source; owner oid; pin jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 s:=openpc.runtime_artifact_materialization_source();
 IF NOT (${roleCheck}) OR current_user=session_user
  OR openpc.current_action_intent_id()<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
  OR current_setting('transaction_isolation')<>'read committed' OR current_setting('session_replication_role')<>'origin'
  OR s.custody_root->>'consumer_profile' IS DISTINCT FROM '${profile}'
  OR s.custody_root->'database' IS DISTINCT FROM openpc.runtime_artifact_database_identity()
  OR s.archive_custody->>'stream_id' IS DISTINCT FROM stream
  OR s.archive_custody->>'database_role' IS DISTINCT FROM session_user
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-OWNER-UNAVAILABLE'; END IF;
 SELECT oid INTO STRICT owner FROM pg_roles WHERE rolname=session_user AND rolcanlogin;
 pin:=shobj_description(owner,'pg_authid')::jsonb;
 IF pin IS DISTINCT FROM jsonb_build_object('installation',${installation('s')},'root',s.custody_root,'archive',s.archive_custody)
  OR EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=owner)
  OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles grantor ON grantor.oid=m.grantor
   WHERE m.member=owner AND (parent.rolname<>'openpc_control_worker' OR m.admin_option OR NOT grantor.rolsuper))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-OWNER-UNAVAILABLE'; END IF;
 PERFORM openpc.assert_runtime_artifact_materialization_boundary();
 RETURN s;
END `,
  },
  {
    name: 'runtime_artifact_archive_challenge',
    args: 'input_id uuid,stream text',
    signature: 'uuid,text',
    result: 'jsonb',
    body: `
DECLARE s control.runtime_artifact_source; input control.runtime_configuration_input; wire bytea; secret bytea;
BEGIN
 s:=openpc.runtime_artifact_archive_owner(stream);
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id
  AND runtime_configuration_input_id=input_id;
 IF NOT openpc.runtime_artifact_new_use_allowed(input.participant_id,input.privacy_domain_id,input.configuration_digest)
  OR input.configuration_digest IS DISTINCT FROM sha256(input.configuration_cbor)
  OR EXISTS(SELECT 1 FROM control.evidence_runtime_artifact_archive WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND runtime_configuration_input_id=input_id)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-DENIED'; END IF;
 wire:=convert_to(jsonb_build_object('version',1,'installation',${installation('s')},'binding',s.custody_root,
  'archive',jsonb_build_object('stream_id',stream,'materialization',jsonb_build_object('input',${identity('input')},'reader_role',session_user::text,
   'transaction_id',pg_current_xact_id()::text,'backend_id',${backend},'request_id',uuidv7()::text)))::text,'UTF8');
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id;
 RETURN jsonb_build_object('wire',(SELECT jsonb_agg(get_byte(wire,n) ORDER BY n) FROM generate_series(0,octet_length(wire)-1) n),
  'mac',(SELECT jsonb_agg(get_byte(mac,n) ORDER BY n) FROM (SELECT public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_ARCHIVE_REQUEST_V1','UTF8')||wire,secret,'sha256') mac) m,generate_series(0,31) n));
END `,
  },
  {
    name: 'runtime_artifact_archive_permit',
    args: 'input_id uuid,stream text',
    signature: 'uuid,text',
    result: 'jsonb',
    body: `
DECLARE s control.runtime_artifact_source; input control.runtime_configuration_input; permit jsonb; wire bytea; mac bytea; expected bytea; secret bytea;
 document jsonb; challenge jsonb; pending jsonb; observation jsonb; root jsonb; difference integer:=0;
BEGIN
 s:=openpc.runtime_artifact_archive_owner(stream);
 SELECT * INTO STRICT input FROM control.runtime_configuration_input WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND runtime_configuration_input_id=input_id;
 IF NOT openpc.runtime_artifact_new_use_allowed(input.participant_id,input.privacy_domain_id,input.configuration_digest)
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-DENIED'; END IF;
 IF coalesce(octet_length(current_setting('openpc.runtime_source_archive_permit',true)),0) NOT BETWEEN 2 AND 65536
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 permit:=current_setting('openpc.runtime_source_archive_permit',true)::jsonb;
 IF permit IS DISTINCT FROM jsonb_build_object('wire',permit->'wire','mac',permit->'mac')
  OR coalesce(permit->>'wire','') !~ '^[0-9a-f]+$' OR length(permit->>'wire')%2<>0
  OR coalesce(permit->>'mac','') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 wire:=decode(permit->>'wire','hex'); mac:=decode(permit->>'mac','hex');
 SELECT verifier_secret INTO STRICT secret FROM control.runtime_artifact_source_verifier_key WHERE participant_id=s.participant_id AND privacy_domain_id=s.privacy_domain_id AND source_owner_id=s.source_owner_id;
 expected:=public.hmac(convert_to('OPENPC_RUNTIME_ARTIFACT_ARCHIVE_RESPONSE_V1','UTF8')||wire,secret,'sha256');
 FOR n IN 0..31 LOOP difference:=difference | (get_byte(expected,n) # get_byte(mac,n)); END LOOP;
 IF difference<>0 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 document:=convert_from(wire,'UTF8')::jsonb; challenge:=document->'challenge'; pending:=challenge->'archive';
 observation:=document->'observation'->'claims'; root:=document->'root'->'claims';
 IF document IS DISTINCT FROM jsonb_build_object('challenge',challenge,'observation',document->'observation','root',document->'root','original',document->'original')
  OR challenge IS DISTINCT FROM jsonb_build_object('version',1,'installation',${installation('s')},'binding',s.custody_root,
   'archive',jsonb_build_object('stream_id',stream,'materialization',jsonb_build_object('input',${identity('input')},'reader_role',session_user::text,
    'transaction_id',pg_current_xact_id()::text,'backend_id',${backend},'request_id',pending->'materialization'->>'request_id')))
  OR coalesce(pending->'materialization'->>'request_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  OR document->'observation'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-history:v1'
  OR observation->'version' IS DISTINCT FROM '1'::jsonb OR observation->'installation' IS DISTINCT FROM ${installation('s')}
  OR observation->'observation' IS DISTINCT FROM jsonb_build_object('ArchiveMaterializedOrUnknown',pending)
  OR document->'root'->>'purpose' IS DISTINCT FROM 'openpc:runtime-artifact-source-root:v1'
  OR root->'version' IS DISTINCT FROM '1'::jsonb OR root->'installation' IS DISTINCT FROM ${installation('s')}
  OR root->'binding' IS DISTINCT FROM s.custody_root THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 IF coalesce(document->>'original','') !~ '^[0-9a-f]+$' OR length(document->>'original') NOT BETWEEN 2 AND 16384 OR length(document->>'original')%2<>0
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 IF convert_from(decode(document->>'original','hex'),'UTF8')::jsonb IS DISTINCT FROM document->'observation'
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-ARCHIVE-READ-UNPROVEN'; END IF;
 RETURN jsonb_build_object('original',document->'original','observation',document->'observation');
END `,
  },
  {
    name: 'runtime_artifact_archive_payload',
    args: 'input_id uuid,stream text',
    signature: 'uuid,text',
    result: 'bytea',
    body: `
DECLARE payload bytea;
BEGIN
 PERFORM openpc.runtime_artifact_archive_permit(input_id,stream);
 SELECT configuration_cbor INTO STRICT payload FROM control.runtime_configuration_input WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND runtime_configuration_input_id=input_id;
 RETURN payload;
END `,
  },
];

const literal = (value) => `'${value.replaceAll("'", "''")}'`;
export const runtimeArtifactMaterializationGuardsSql = `
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO openpc_control_owner;
${functions
  .map(
    (f) => `CREATE OR REPLACE FUNCTION openpc.${f.name}(${f.args}) RETURNS ${f.result}
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$${f.body}$$;
ALTER FUNCTION openpc.${f.name}(${f.signature}) OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.${f.name}(${f.signature}) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.${f.name}(${f.signature}) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_materialization_boundary()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 -- Traverse actual membership rather than superuser's implicit pg_has_role
 -- answer. A product login becoming an owner is a bypass, not an installer to
 -- exclude from the ordinary grant audit below.
 IF EXISTS(WITH RECURSIVE product_role(oid) AS (
  SELECT oid FROM pg_roles WHERE rolname IN ('openpc_control_runtime','openpc_control_worker','openpc_control_reader')
  UNION SELECT m.member FROM pg_auth_members m JOIN product_role p ON p.oid=m.roleid)
  SELECT 1 FROM product_role p JOIN pg_roles r ON r.oid=p.oid WHERE r.rolcanlogin AND (
   r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
   OR pg_has_role(r.oid,'openpc_control_owner','MEMBER')
   OR pg_has_role(r.oid,'openpc_control_key_governor','MEMBER')))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-ROLE-UNAVAILABLE'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles r WHERE NOT r.rolsuper
  AND NOT pg_has_role(r.oid,'openpc_control_owner','MEMBER')
  AND ${reachableRole} AND has_column_privilege(r.oid,'control.runtime_configuration_input','configuration_cbor','SELECT'))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-GRANT-UNAVAILABLE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  WHERE c.oid='control.runtime_configuration_input'::regclass AND c.relkind='r' AND c.relrowsecurity
   AND NOT c.relispartition AND r.rolname='openpc_control_owner')
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-OWNER-UNAVAILABLE'; END IF;
 IF EXISTS(SELECT 1 FROM pg_depend d JOIN pg_rewrite rule ON rule.oid=d.objid
  JOIN pg_class view ON view.oid=rule.ev_class
  WHERE d.classid='pg_rewrite'::regclass AND d.refclassid='pg_class'::regclass
   AND d.refobjid='control.runtime_configuration_input'::regclass
   AND (view.oid<>'control.runtime_configuration_input_current_metadata'::regclass
    OR d.refobjsubid=(SELECT attnum FROM pg_attribute
     WHERE attrelid='control.runtime_configuration_input'::regclass AND attname='configuration_cbor')
    OR rule.ev_action::text LIKE '%:varattno 0 %'
    OR NOT coalesce(view.reloptions @> ARRAY['security_invoker=true']::text[],false))
   AND view.relkind IN ('v','m') AND EXISTS(SELECT 1 FROM pg_roles r WHERE NOT r.rolsuper
    AND NOT pg_has_role(r.oid,'openpc_control_owner','MEMBER')
    AND ${reachableRole} AND has_any_column_privilege(r.oid,view.oid,'SELECT')))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-PROJECTION-UNAVAILABLE'; END IF;
 IF EXISTS(SELECT 1 FROM (VALUES ${functions.map((f) => `(${literal(`openpc.${f.name}(${f.signature})`)},${literal(f.body)})`).join(',')}) expected(signature,body)
  WHERE NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
   WHERE p.oid=to_regprocedure(expected.signature) AND r.rolname='openpc_control_owner'
    AND p.prosecdef AND p.provolatile='v' AND p.prokind='f' AND NOT p.proisstrict
    AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on']::text[] AND p.prosrc=expected.body))
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-SOURCE-READ-FUNCTION-UNAVAILABLE'; END IF;
END $$;
ALTER FUNCTION openpc.assert_runtime_artifact_materialization_boundary() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.assert_runtime_artifact_materialization_boundary() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_materialization_boundary()
 TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;

// Applied after generic table grants. INSERT RETURNING, COPY and whole-row
// projections also require this withheld column privilege.
export const runtimeArtifactPayloadGrantsSql = `
REVOKE SELECT ON control.runtime_configuration_input FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
REVOKE SELECT(configuration_cbor) ON control.runtime_configuration_input FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT(runtime_configuration_input_id,participant_id,privacy_domain_id,module_installation_id,
 module_configuration_generation_id,configuration_digest,resource_bindings,selected,created_at)
 ON control.runtime_configuration_input TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
`;
