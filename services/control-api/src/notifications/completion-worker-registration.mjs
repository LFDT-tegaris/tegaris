import { notificationCompletionWorkerInstallationGuardsSql as guards } from './completion-worker-installation-guards.mjs';

const quote = (text) => `'${text.replaceAll("'", "''")}'`;
const bodies = [
  'guard_notification_completion_worker_installation',
  'guard_notification_completion_worker_truncate',
].map((name) => {
  const start = guards.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}()`);
  const begin = guards.indexOf('AS $$', start),
    end = guards.indexOf('$$;', begin);
  if (start < 0 || begin < start || end < begin)
    throw new Error('Missing completion installation guard');
  return `NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
   JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='openpc.${name}()'::regprocedure
   AND r.rolname='openpc_control_owner' AND l.lanname='plpgsql' AND NOT p.prosecdef
   AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog']
   AND p.prosrc=${quote(guards.slice(begin + 5, end))})`;
});

/** Privileged initial trust and read-only current admission. No consumer effect
 * is granted by this registration or its installation metadata. */
export const notificationCompletionWorkerRegistrationSql = `
ALTER TABLE control.installed_notification_completion_worker FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.installed_notification_completion_worker FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.installed_notification_completion_worker TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.installed_notification_completion_worker TO openpc_control_owner;
DROP POLICY IF EXISTS notification_completion_worker_installer ON control.installed_notification_completion_worker;
CREATE POLICY notification_completion_worker_installer ON control.installed_notification_completion_worker TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
${guards}
CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_worker_shared_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF ${bodies.join('\n OR ')}
 OR NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  WHERE c.oid='control.installed_notification_completion_worker'::regclass AND c.relkind='r'
  AND r.rolname='openpc_control_owner' AND c.relrowsecurity AND c.relforcerowsecurity AND NOT c.relispartition
  AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
 OR current_setting('session_replication_role')<>'origin'
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['openpc_control_runtime','openpc_control_worker','openpc_control_reader']) role(name)
  WHERE has_table_privilege(role.name,'control.installed_notification_completion_worker','INSERT,UPDATE,DELETE,TRUNCATE'))
 OR EXISTS(SELECT 1 FROM pg_class c,aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid='control.installed_notification_completion_worker'::regclass AND a.grantee=0)
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-WORKER-SHARED-OWNER'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_completion_worker_shared_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_completion_worker_shared_owner(),
 openpc.assert_notification_completion_worker_installation_owner() TO openpc_control_runtime;
SELECT openpc.assert_notification_completion_worker_installation_owner();
`;
