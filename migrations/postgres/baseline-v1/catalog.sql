SET search_path=pg_catalog;
SELECT pg_temp.tegaris_static_catalog(jsonb_build_object(
 'bootstrap',(SELECT jsonb_build_array(rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig) FROM pg_roles WHERE oid=10),
 'database_acl',(SELECT jsonb_build_array(datname,pg_temp.tegaris_role(datdba),pg_temp.tegaris_acl(coalesce(datacl,acldefault('d'::"char",datdba)))) FROM pg_database WHERE datname=current_database()),
 'schemas',(SELECT jsonb_agg(jsonb_build_array(n.nspname,pg_temp.tegaris_role(n.nspowner),pg_temp.tegaris_acl(coalesce(n.nspacl,acldefault('n'::"char",n.nspowner)))) ORDER BY n.nspname COLLATE "C")
   FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname IN ('control','openpc','public')),
 'relations',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relkind,pg_temp.tegaris_role(c.relowner),c.relrowsecurity,c.relforcerowsecurity,pg_temp.tegaris_acl(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))),c.reloptions) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C")
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
   WHERE n.nspname IN ('control','openpc','public') AND c.relkind IN ('r','p','v','m','S','f')),
 'columns',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid),pg_temp.tegaris_acl(a.attacl),co.collname) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C",a.attnum)
   FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   LEFT JOIN pg_collation co ON co.oid=a.attcollation
   WHERE n.nspname IN ('control','openpc','public') AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f')),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,k.contype,k.convalidated,k.conenforced,k.condeferrable,k.condeferred,pg_get_expr(k.conbin,k.conrelid),pg_get_constraintdef(k.oid,true)) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C",k.conname COLLATE "C")
   FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('control','openpc','public')),
 'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_temp.tegaris_role(p.proowner),pg_temp.tegaris_acl(coalesce(p.proacl,acldefault('f'::"char",p.proowner))),pg_get_functiondef(p.oid)) ORDER BY n.nspname COLLATE "C",p.proname COLLATE "C",pg_get_function_identity_arguments(p.oid) COLLATE "C")
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
   WHERE n.nspname IN ('control','openpc','public') AND p.prokind IN ('f','p')),
 'policies',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,p.polname,p.polcmd,p.polpermissive,
   (SELECT array_agg(CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END ORDER BY (CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END) COLLATE "C") FROM unnest(p.polroles) u),pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C",p.polname COLLATE "C")
   FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public')),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C",t.tgname COLLATE "C")
   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname IN ('control','openpc','public') AND NOT t.tgisinternal),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,pg_get_indexdef(c.oid)) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C")
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public') AND c.relkind='i'),
 'enums',(SELECT jsonb_agg(jsonb_build_array(n.nspname,t.typname,e.enumlabel) ORDER BY n.nspname COLLATE "C",t.typname COLLATE "C",e.enumsortorder)
   FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN ('control','openpc','public')),
 'defaults',(SELECT jsonb_agg(jsonb_build_array(pg_temp.tegaris_role(r.oid),n.nspname,d.defaclobjtype,pg_temp.tegaris_acl(d.defaclacl)) ORDER BY pg_temp.tegaris_role(r.oid) COLLATE "C",n.nspname COLLATE "C",d.defaclobjtype)
   FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE r.rolname LIKE 'openpc\_%' ESCAPE '\'),
 'system_function_acls',(SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_temp.tegaris_role(p.proowner),pg_temp.tegaris_acl(p.proacl)) ORDER BY p.oid::regprocedure::text COLLATE "C")
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='pg_catalog' AND (p.proowner<>10 OR EXISTS(
    SELECT FROM aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee WHERE r.oid<>10 AND starts_with(r.rolname,'openpc_')))),
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig,shobj_description(oid,'pg_authid')) ORDER BY rolname COLLATE "C")
   FROM pg_roles WHERE oid<>10 AND rolname LIKE 'openpc\_%' ESCAPE '\'),
 'views',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,pg_get_viewdef(c.oid,true)) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C")
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public') AND c.relkind IN ('v','m')),
 'sequences',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,format_type(s.seqtypid,NULL),s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C")
   FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('control','openpc','public')),
 'extensions',(SELECT jsonb_agg(jsonb_build_array(e.extname,e.extversion,n.nspname,pg_temp.tegaris_role(e.extowner)) ORDER BY e.extname COLLATE "C")
   FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace),
 'memberships',(SELECT jsonb_agg(jsonb_build_array(pg_temp.tegaris_role(r.oid),pg_temp.tegaris_role(m.oid),pg_temp.tegaris_role(g.oid),a.admin_option,a.inherit_option,a.set_option) ORDER BY pg_temp.tegaris_role(r.oid) COLLATE "C",pg_temp.tegaris_role(m.oid) COLLATE "C",pg_temp.tegaris_role(g.oid) COLLATE "C")
   FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor
   WHERE r.rolname LIKE 'openpc\_%' ESCAPE '\' OR m.rolname LIKE 'openpc\_%' ESCAPE '\')
));
