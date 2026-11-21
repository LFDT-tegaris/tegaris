-- Only the authenticated initdb bootstrap identity (OID 10) is portable.
-- Other role names, privilege bits, grant options and grantors stay exact.
CREATE OR REPLACE FUNCTION pg_temp.tegaris_role(role_oid oid)
RETURNS text LANGUAGE sql STABLE AS $role$
 SELECT CASE role_oid WHEN 0 THEN 'PUBLIC' WHEN 10 THEN '@bootstrap' ELSE pg_get_userbyid(role_oid)::text END
$role$;
CREATE OR REPLACE FUNCTION pg_temp.tegaris_acl(value aclitem[])
RETURNS jsonb LANGUAGE sql STABLE AS $acl$
 SELECT coalesce(jsonb_agg(jsonb_build_array(pg_temp.tegaris_role(grantee),privilege_type,is_grantable,pg_temp.tegaris_role(grantor))
  ORDER BY pg_temp.tegaris_role(grantee),privilege_type,is_grantable,pg_temp.tegaris_role(grantor)),'[]'::jsonb)
 FROM aclexplode(value)
$acl$;

-- Runtime custody roles are installed after the frozen schema. Validate their
-- privilege envelope before removing them from the static fingerprint. This
-- does not authenticate custody files, attest source non-use or enroll a role.
CREATE OR REPLACE FUNCTION pg_temp.tegaris_runtime_binding(scope_name text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $binding$
DECLARE binding jsonb; installation jsonb; root jsonb; suffix text; value text; database_identity jsonb;
 uuid_pattern constant text:='^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
BEGIN
 BEGIN
  SELECT shobj_description(oid,'pg_authid')::jsonb INTO binding FROM pg_roles WHERE rolname=scope_name;
 EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: malformed scope binding';
 END;
 installation:=binding->'installation'; root:=binding->'root';
 IF binding IS NULL OR jsonb_typeof(binding)<>'object'
 OR NOT binding ?& ARRAY['version','installation','root','database_role','source_public_key','commit_key_digest']
 OR binding-ARRAY['version','installation','root','database_role','source_public_key','commit_key_digest','archive_custody']<>'{}'::jsonb
 OR binding->'version'<>'1'::jsonb OR jsonb_typeof(installation)<>'object' OR jsonb_typeof(root)<>'object'
 OR NOT installation ?& ARRAY['participant_id','privacy_domain_id','source_owner_id','source_file_binding']
 OR installation-ARRAY['participant_id','privacy_domain_id','source_owner_id','source_file_binding']<>'{}'::jsonb
 OR NOT root ?& ARRAY['generation_id','journal_binding','retained_root_binding','consumer_profile']
 OR root-ARRAY['generation_id','journal_binding','retained_root_binding','consumer_profile','database']<>'{}'::jsonb
 THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid scope binding'; END IF;
 FOREACH value IN ARRAY ARRAY[installation->>'participant_id',installation->>'privacy_domain_id',installation->>'source_owner_id',root->>'generation_id'] LOOP
  IF value IS NULL OR value !~ uuid_pattern THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid scope identity'; END IF;
 END LOOP;
 FOREACH value IN ARRAY ARRAY[installation->>'source_file_binding',root->>'journal_binding',root->>'retained_root_binding',binding->>'commit_key_digest'] LOOP
  IF value IS NULL OR value !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid binding digest'; END IF;
 END LOOP;
 IF root->>'journal_binding'=root->>'retained_root_binding'
 OR root->>'consumer_profile' NOT IN ('openpc:local-runtime-source-consumers:v1','openpc:local-runtime-source-consumers:v2')
 OR jsonb_typeof(binding->'source_public_key')<>'array'
 THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid root or public key'; END IF;
 IF jsonb_array_length(binding->'source_public_key')<>33 OR binding#>>'{source_public_key,0}' NOT IN ('2','3') OR EXISTS(
  SELECT FROM jsonb_array_elements(binding->'source_public_key') a(v)
  WHERE jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]{1,3}$' OR v::text::int>255)
 THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid public key'; END IF;
 IF root->>'consumer_profile'='openpc:local-runtime-source-consumers:v1' THEN
  IF root ? 'database' AND root->'database'<>'null'::jsonb THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: unexpected database binding'; END IF;
 ELSE
  IF jsonb_typeof(root->'database') IS DISTINCT FROM 'object'
  OR NOT (root->'database') ?& ARRAY['system_identifier','database_oid']
  OR (root->'database')-ARRAY['system_identifier','database_oid']<>'{}'::jsonb
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: missing database binding'; END IF;
  FOREACH value IN ARRAY ARRAY[root#>>'{database,system_identifier}',root#>>'{database,database_oid}'] LOOP
   IF value IS NULL OR value !~ '^[0-9]{1,20}$' THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid database binding'; END IF;
   IF value::numeric NOT BETWEEN 1 AND 18446744073709551615 THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid database binding'; END IF;
  END LOOP;
  SELECT jsonb_build_object('system_identifier',s.system_identifier::text,'database_oid',d.oid::text)
   INTO database_identity FROM pg_control_system() s,pg_database d WHERE d.datname=current_database();
  IF root->'database' IS DISTINCT FROM database_identity
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: materialization database identity differs'; END IF;
 END IF;
 -- Matches the public Rust/JCS scope-name vector, not jsonb's spaced rendering.
 suffix:=rtrim(translate(encode(sha256(convert_to(format('["openpc:runtime-source-scope:v1","%s","%s"]',installation->>'participant_id',installation->>'privacy_domain_id'),'UTF8')),'base64'),'+/','-_'),'=');
 IF scope_name<>'openpc_rs_scope_'||suffix OR binding->>'database_role' IS DISTINCT FROM 'openpc_rs_login_'||suffix
 THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: scope/login identity differs'; END IF;
 IF binding ? 'archive_custody' THEN
  IF jsonb_typeof(binding->'archive_custody')<>'object'
  OR NOT (binding->'archive_custody') ?& ARRAY['database_role','stream_id','keys']
  OR (binding->'archive_custody')-ARRAY['database_role','stream_id','keys']<>'{}'::jsonb
  OR binding#>>'{archive_custody,database_role}' IS DISTINCT FROM 'openpc_ra_login_'||suffix
  OR coalesce(binding#>>'{archive_custody,stream_id}','') !~ '^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$'
  OR jsonb_typeof(binding#>'{archive_custody,keys}') IS DISTINCT FROM 'object'
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid archive binding'; END IF;
  IF (SELECT count(*) NOT BETWEEN 1 AND 64 FROM jsonb_each(binding#>'{archive_custody,keys}'))
  OR EXISTS(SELECT FROM jsonb_each(binding#>'{archive_custody,keys}') a(k,v)
   WHERE k !~ '^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$' OR jsonb_typeof(v)<>'string' OR v#>>'{}' !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: invalid archive keys'; END IF;
 END IF;
 RETURN binding;
END $binding$;

CREATE OR REPLACE FUNCTION pg_temp.tegaris_static_catalog(catalog jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $runtime$
DECLARE r record; scope_name text; login_name text; suffix text; kind text;
 binding jsonb; archive_profile jsonb; missing_role boolean; dynamic_names text[]:=ARRAY[]::text[];
BEGIN
 -- A per-database dump does not contain roles. Never accept a source-bearing
 -- restore merely because its independent cluster bindings are absent.
 IF to_regclass('control.runtime_artifact_source') IS NOT NULL THEN
  EXECUTE 'SELECT EXISTS(SELECT FROM control.runtime_artifact_source s WHERE
   (starts_with(s.database_role,''openpc_rs_login_'') AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=s.database_role))
   OR (s.archive_custody IS NOT NULL AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=s.archive_custody->>''database_role'')))'
   INTO missing_role;
  IF missing_role THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: source binding roles are missing'; END IF;
 END IF;
 FOR r IN SELECT * FROM pg_roles WHERE starts_with(rolname,'openpc_rs_scope_')
  OR starts_with(rolname,'openpc_rs_login_') OR starts_with(rolname,'openpc_ra_login_') LOOP
  IF r.rolname !~ '^openpc_(rs_scope|rs_login|ra_login)_[A-Za-z0-9_-]{43}$'
  OR r.rolsuper OR NOT r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
  OR r.rolconnlimit<>-1 OR r.rolvaliduntil IS NOT NULL OR r.rolconfig IS NOT NULL
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: role attributes'; END IF;
  suffix:=right(r.rolname,43); scope_name:='openpc_rs_scope_'||suffix; login_name:='openpc_rs_login_'||suffix;
  kind:=CASE WHEN r.rolname=scope_name THEN 'scope' WHEN r.rolname=login_name THEN 'source' ELSE 'archive' END;
  IF r.rolcanlogin<>(kind<>'scope')
  OR NOT EXISTS(SELECT FROM pg_roles WHERE rolname=scope_name)
  OR NOT EXISTS(SELECT FROM pg_roles WHERE rolname=login_name)
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: missing scope or login'; END IF;
  binding:=pg_temp.tegaris_runtime_binding(scope_name);
  IF kind='source' AND shobj_description(r.oid,'pg_authid') IS NOT NULL
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: unexpected login comment'; END IF;
  IF binding ? 'archive_custody' AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname='openpc_ra_login_'||suffix)
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: missing archive login'; END IF;
  IF kind='archive' THEN
   BEGIN
    archive_profile:=shobj_description(r.oid,'pg_authid')::jsonb;
   EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: malformed archive binding';
   END;
   IF NOT binding ? 'archive_custody' OR archive_profile IS DISTINCT FROM jsonb_build_object(
    'installation',binding->'installation','root',binding->'root','archive',binding->'archive_custody')
   THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: archive profile differs'; END IF;
  END IF;
  -- No direct ownership, ACL, RLS-policy dependency or initial privilege grant,
  -- including objects outside the three schemas in the static fingerprint.
  IF EXISTS(SELECT FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=r.oid AND deptype IN ('a','o','r','i'))
  OR EXISTS(SELECT FROM pg_db_role_setting WHERE setrole=r.oid)
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: direct privileges or settings'; END IF;
  IF (SELECT count(*) FROM pg_auth_members WHERE roleid=r.oid OR member=r.oid OR grantor=r.oid)
   <>(CASE kind WHEN 'source' THEN 2 ELSE 1 END)
  OR EXISTS(SELECT FROM pg_auth_members a JOIN pg_roles parent ON parent.oid=a.roleid
   JOIN pg_roles member ON member.oid=a.member JOIN pg_roles grantor ON grantor.oid=a.grantor
   WHERE (a.roleid=r.oid OR a.member=r.oid OR a.grantor=r.oid) AND NOT (
    grantor.rolsuper AND NOT a.admin_option AND (
     (kind='scope' AND parent.rolname=scope_name AND member.rolname=login_name AND NOT a.inherit_option AND NOT a.set_option)
     OR (kind<>'scope' AND member.oid=r.oid AND parent.rolname='openpc_control_worker' AND a.inherit_option AND a.set_option)
     OR (kind='source' AND member.oid=r.oid AND parent.rolname=scope_name AND NOT a.inherit_option AND NOT a.set_option))))
  THEN RAISE EXCEPTION 'BASELINE-RUNTIME-ROLE-MISMATCH: memberships'; END IF;
  dynamic_names:=array_append(dynamic_names,r.rolname::text);
 END LOOP;
 IF cardinality(dynamic_names)=0 THEN RETURN catalog; END IF;
 -- Keep every static grant and every other catalogue field byte-significant.
 RETURN catalog || jsonb_build_object(
  'roles',(SELECT jsonb_agg(v ORDER BY ord) FROM jsonb_array_elements(catalog->'roles') WITH ORDINALITY a(v,ord) WHERE NOT (v->>0=ANY(dynamic_names))),
  'memberships',(SELECT jsonb_agg(v ORDER BY ord) FROM jsonb_array_elements(catalog->'memberships') WITH ORDINALITY a(v,ord) WHERE NOT (v->>0=ANY(dynamic_names) OR v->>1=ANY(dynamic_names))));
END $runtime$;
