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
