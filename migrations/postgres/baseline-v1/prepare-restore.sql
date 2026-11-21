\set ON_ERROR_STOP on
BEGIN;
\ir catalog-helpers.sql
SET LOCAL lock_timeout='5s';
DO $lock$ BEGIN
 IF current_setting('server_version_num')<>'180006' THEN RAISE EXCEPTION 'PostgreSQL 18.6 required'; END IF;
 IF current_database()<>'openpc_control' THEN RAISE EXCEPTION 'This baseline requires database openpc_control'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('tegaris-control-baseline-v1',0)) THEN RAISE EXCEPTION 'Another baseline migrator is active'; END IF;
END $lock$;
DO $empty$ BEGIN
 IF EXISTS(SELECT FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_')
 OR EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
 OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
 THEN RAISE EXCEPTION 'Baseline requires an empty database; use verified legacy upgrade/handoff'; END IF;
END $empty$;
DO $roles$ DECLARE actual jsonb; BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE oid<>10 AND starts_with(rolname,'openpc_')) THEN
 SELECT jsonb_build_object('roles',j->'roles','memberships',j->'memberships') INTO actual FROM (SELECT jsonb_build_object(
 'bootstrap',(SELECT jsonb_build_array(rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig) FROM pg_roles WHERE oid=10),
 'database_acl',(SELECT jsonb_build_array(datname,pg_temp.tegaris_role(datdba),pg_temp.tegaris_acl(coalesce(datacl,acldefault('d'::"char",datdba)))) FROM pg_database WHERE datname=current_database()),
 'schemas',(SELECT jsonb_agg(jsonb_build_array(n.nspname,pg_temp.tegaris_role(n.nspowner),pg_temp.tegaris_acl(coalesce(n.nspacl,acldefault('n'::"char",n.nspowner)))) ORDER BY n.nspname)
   FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname IN ('control','openpc','public')),
 'relations',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relkind,pg_temp.tegaris_role(c.relowner),c.relrowsecurity,c.relforcerowsecurity,pg_temp.tegaris_acl(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))),c.reloptions) ORDER BY n.nspname,c.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
   WHERE n.nspname IN ('control','openpc','public') AND c.relkind IN ('r','p','v','m','S','f')),
 'columns',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid),pg_temp.tegaris_acl(a.attacl),co.collname) ORDER BY n.nspname,c.relname,a.attnum)
   FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   LEFT JOIN pg_collation co ON co.oid=a.attcollation
   WHERE n.nspname IN ('control','openpc','public') AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f')),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,k.contype,k.convalidated,k.conenforced,k.condeferrable,k.condeferred,pg_get_expr(k.conbin,k.conrelid),pg_get_constraintdef(k.oid,true)) ORDER BY n.nspname,c.relname,k.conname)
   FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('control','openpc','public')),
 'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_temp.tegaris_role(p.proowner),pg_temp.tegaris_acl(coalesce(p.proacl,acldefault('f'::"char",p.proowner))),pg_get_functiondef(p.oid)) ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid))
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
   WHERE n.nspname IN ('control','openpc','public') AND p.prokind IN ('f','p')),
 'policies',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,p.polname,p.polcmd,p.polpermissive,
   (SELECT array_agg(CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END ORDER BY CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END) FROM unnest(p.polroles) u),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY n.nspname,c.relname,p.polname)
   FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public')),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY n.nspname,c.relname,t.tgname)
   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('control','openpc','public') AND NOT t.tgisinternal),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,pg_get_indexdef(c.oid)) ORDER BY n.nspname,c.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public') AND c.relkind='i'),
 'enums',(SELECT jsonb_agg(jsonb_build_array(n.nspname,t.typname,e.enumlabel) ORDER BY n.nspname,t.typname,e.enumsortorder)
   FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN ('control','openpc','public')),
 'defaults',(SELECT jsonb_agg(jsonb_build_array(pg_temp.tegaris_role(r.oid),n.nspname,d.defaclobjtype,pg_temp.tegaris_acl(d.defaclacl)) ORDER BY pg_temp.tegaris_role(r.oid),n.nspname,d.defaclobjtype)
   FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE r.rolname LIKE 'openpc\_%' ESCAPE '\'),
 'system_function_acls',(SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_temp.tegaris_role(p.proowner),pg_temp.tegaris_acl(p.proacl)) ORDER BY p.oid::regprocedure::text)
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='pg_catalog' AND (p.proowner<>10 OR EXISTS(
    SELECT FROM aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee WHERE r.oid<>10 AND starts_with(r.rolname,'openpc_')))),
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig,shobj_description(oid,'pg_authid')) ORDER BY rolname)
   FROM pg_roles WHERE oid<>10 AND rolname LIKE 'openpc\_%' ESCAPE '\'),
 'views',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,pg_get_viewdef(c.oid,true)) ORDER BY n.nspname,c.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public') AND c.relkind IN ('v','m')),
 'sequences',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,format_type(s.seqtypid,NULL),s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle) ORDER BY n.nspname,c.relname)
   FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public')),
 'extensions',(SELECT jsonb_agg(jsonb_build_array(e.extname,e.extversion,n.nspname,pg_temp.tegaris_role(e.extowner)) ORDER BY e.extname)
   FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace),
 'memberships',(SELECT jsonb_agg(jsonb_build_array(pg_temp.tegaris_role(r.oid),pg_temp.tegaris_role(m.oid),pg_temp.tegaris_role(g.oid),a.admin_option,a.inherit_option,a.set_option) ORDER BY pg_temp.tegaris_role(r.oid),pg_temp.tegaris_role(m.oid),pg_temp.tegaris_role(g.oid))
   FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor
   WHERE r.rolname LIKE 'openpc\_%' ESCAPE '\' OR m.rolname LIKE 'openpc\_%' ESCAPE '\')
)) x(j);
 IF actual IS DISTINCT FROM '{"roles": [["openpc_backup_operator", false, false, false, false, false, false, true, -1, null, null, null], ["openpc_configuration_runtime", false, true, false, false, true, false, false, -1, null, null, null], ["openpc_control_key_governor", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_control_maintenance", false, false, false, false, false, false, true, -1, null, null, null], ["openpc_control_migrator", false, false, false, false, false, false, true, -1, null, null, null], ["openpc_control_owner", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_control_platform_runtime", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_control_reader", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_control_runtime", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_control_worker", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_identity_binding_owner", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_identity_binding_resolver", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_identity_runtime", false, true, false, false, true, false, false, -1, null, null, null], ["openpc_local_control_worker", false, true, false, false, true, false, false, -1, null, null, null], ["openpc_operations_qualification_bootstrap", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_operations_qualification_owner", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_participant_runtime", false, true, false, false, true, false, false, -1, null, null, null], ["openpc_policy_runtime", false, true, false, false, true, false, false, -1, null, null, null], ["openpc_runtime_source_legacy", false, true, false, false, false, false, false, -1, null, null, "openpc:runtime-artifact-source:legacy-unproven:v1"], ["openpc_signing_authority_locker", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_signing_continuation_issuer", false, false, false, false, false, false, false, -1, null, null, null], ["openpc_source_control_reader", false, true, false, false, true, false, false, -1, null, null, null]], "memberships": [["openpc_control_owner", "openpc_control_migrator", "@bootstrap", false, false, true], ["openpc_control_platform_runtime", "openpc_participant_runtime", "@bootstrap", false, true, true], ["openpc_control_reader", "openpc_source_control_reader", "@bootstrap", false, true, true], ["openpc_control_runtime", "openpc_configuration_runtime", "@bootstrap", false, true, true], ["openpc_control_runtime", "openpc_identity_runtime", "@bootstrap", false, true, true], ["openpc_control_runtime", "openpc_participant_runtime", "@bootstrap", false, true, true], ["openpc_control_runtime", "openpc_policy_runtime", "@bootstrap", false, true, true], ["openpc_control_worker", "openpc_local_control_worker", "@bootstrap", false, true, true], ["openpc_identity_binding_resolver", "openpc_identity_runtime", "@bootstrap", false, false, true], ["openpc_runtime_source_legacy", "openpc_local_control_worker", "@bootstrap", false, false, false], ["openpc_signing_continuation_issuer", "openpc_identity_runtime", "@bootstrap", false, true, true]]}'::jsonb THEN RAISE EXCEPTION 'Existing cluster roles differ from validated baseline'; END IF;
 END IF; END $roles$;

\ir roles.sql
ALTER DATABASE openpc_control OWNER TO openpc_control_owner;
SET ROLE openpc_control_owner;
CREATE EXTENSION pgcrypto WITH SCHEMA public VERSION '1.4';
RESET ROLE;
\ir database-acls.sql
COMMIT;
