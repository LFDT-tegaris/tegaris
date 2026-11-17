import { targetDispositionActivationSql } from './activation-guards.mjs';
import { targetDispositionFactProofSql } from './fact-proof-guards.mjs';
import { targetDispositionAdmissionSql } from './admission-guards.mjs';
import { unsignedWithdrawalRecoverySql } from './unsigned-withdrawal-guards.mjs';
import { targetDispositionIssuanceSql } from './issuance-guards.mjs';
import { targetDispositionReceiptSql } from './receipt-guards.mjs';
import { targetDispositionRestoreSql } from './restore-guards.mjs';
import {
  platformScopeWithdrawalAdmissionSql,
  platformScopeWithdrawalRegistrationSql,
} from './platform-scope-guards.mjs';
import {
  targetDispositionCurrentSourcesSql,
  targetDispositionRestoreSourcesSql,
} from './restore-source-guards.mjs';

const tables = ['admission', 'delivery', 'acknowledgement'].map(
  (suffix) => `runtime_target_disposition_${suffix}`,
);
const quote = (value) => `'${value.replaceAll("'", "''")}'`;
const immutable = `
CREATE OR REPLACE FUNCTION openpc.guard_runtime_target_disposition_immutable()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'TARGET-DISPOSITION-IMMUTABLE';
END $$;
`;
const checks = [
  [
    unsignedWithdrawalRecoverySql,
    'runtime_unsigned_withdrawal_recoverable',
    'uuid,bigint,text',
    true,
  ],
  [
    platformScopeWithdrawalAdmissionSql,
    'begin_platform_scope_target_withdrawal',
    'uuid,uuid,text,text,bigint',
    true,
  ],
  [
    targetDispositionIssuanceSql,
    'lock_runtime_target_disposition_issuance',
    'uuid,bigint,text,text',
    true,
  ],
  [targetDispositionFactProofSql, 'check_runtime_target_fact_proof', 'jsonb', false],
  [
    targetDispositionActivationSql,
    'begin_runtime_target_activation_confirmation',
    'bytea,bytea,bytea',
    true,
  ],
  [
    targetDispositionCurrentSourcesSql,
    'lock_runtime_target_current_sources',
    'uuid,jsonb,jsonb,text',
    true,
  ],
  [
    targetDispositionAdmissionSql,
    'begin_runtime_target_withdrawal',
    'uuid,uuid,text,text,bigint',
    true,
  ],
  [
    targetDispositionReceiptSql,
    'commit_runtime_target_disposition',
    'text,bytea,bytea,bytea',
    true,
  ],
  [
    targetDispositionRestoreSql,
    'begin_runtime_target_unstarted_restore',
    'bytea,bytea,bytea',
    true,
  ],
  [
    targetDispositionRestoreSourcesSql,
    'lock_runtime_target_restore_sources',
    'uuid,jsonb,jsonb',
    true,
  ],
  [immutable, 'guard_runtime_target_disposition_immutable', '', false],
].map(([source, name, args, definer]) => {
  const start = source.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}(`);
  const begin = source.indexOf('AS $$', start),
    end = source.indexOf('$$;', begin);
  if (start < 0 || begin < start || end < begin) throw new Error('Disposition owner body missing');
  return `NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
   JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('openpc.${name}(${args})')
   AND r.rolname='openpc_control_owner' AND l.lanname='plpgsql' AND p.prosecdef=${definer}
   AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog'${definer ? ",'row_security=on'" : ''}]
   AND p.prosrc=${quote(source.slice(begin + 5, end))})`;
});

export const targetDispositionRegistrationSql = `
REVOKE ALL ON control.runtime_target_disposition_key FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.runtime_target_disposition_key TO openpc_control_owner;
${tables
  .map(
    (table) => `
ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.${table} TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.${table} TO openpc_control_owner;
DROP POLICY IF EXISTS runtime_target_disposition_owner ON control.${table};
CREATE POLICY runtime_target_disposition_owner ON control.${table} TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
`,
  )
  .join('\n')}
${[
  'runtime_target',
  'configuration_work',
  'runtime_configuration_input',
  'runtime_activation_observation',
  'provider_profile',
  'indexer_profile',
  'projection_plan',
  'policy_generation',
  'policy_version',
  'policy_artifact',
  'policy_activation',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'module_configuration_generation',
  'module_installation',
  'identity_runtime_snapshot_head',
  'identity_runtime_snapshot',
]
  .map(
    (table) => `
DROP POLICY IF EXISTS runtime_target_disposition_read ON control.${table};
CREATE POLICY runtime_target_disposition_read ON control.${table} FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1');
DROP POLICY IF EXISTS runtime_target_disposition_lock ON control.${table};
CREATE POLICY runtime_target_disposition_lock ON control.${table} FOR UPDATE TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1') WITH CHECK(false);
`,
  )
  .join('\n')}
${immutable}
${unsignedWithdrawalRecoverySql}
${tables
  .map(
    (table) => `
DROP TRIGGER IF EXISTS runtime_target_disposition_immutable ON control.${table};
CREATE TRIGGER runtime_target_disposition_immutable BEFORE UPDATE OR DELETE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_runtime_target_disposition_immutable();
DROP TRIGGER IF EXISTS runtime_target_disposition_truncate ON control.${table};
CREATE TRIGGER runtime_target_disposition_truncate BEFORE TRUNCATE ON control.${table}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_runtime_target_disposition_immutable();
`,
  )
  .join('\n')}
${targetDispositionFactProofSql}
${platformScopeWithdrawalRegistrationSql}
${platformScopeWithdrawalAdmissionSql}
${targetDispositionAdmissionSql}
${targetDispositionReceiptSql}
${targetDispositionCurrentSourcesSql}
${targetDispositionRestoreSourcesSql}
${targetDispositionActivationSql}
${targetDispositionRestoreSql}
${targetDispositionIssuanceSql}
CREATE OR REPLACE FUNCTION openpc.assert_runtime_target_disposition_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF current_setting('session_replication_role')<>'origin' OR current_setting('row_security')<>'on'
 OR ${checks.join('\n OR ')}
 OR EXISTS(SELECT 1 FROM unnest(ARRAY[${tables.map(quote).join(',')}]) table_name(name)
  WHERE NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
   WHERE c.oid=to_regclass('control.'||table_name.name) AND c.relkind='r' AND NOT c.relispartition
    AND c.relrowsecurity AND c.relforcerowsecurity AND r.rolname='openpc_control_owner'
    AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['openpc_control_runtime','openpc_control_worker','openpc_control_reader']) role(name)
   WHERE has_table_privilege(role.name,'control.'||table_name.name,'INSERT,UPDATE,DELETE,TRUNCATE')
    OR has_any_column_privilege(role.name,'control.'||table_name.name,'INSERT,UPDATE'))
  OR EXISTS(SELECT 1 FROM pg_class c,aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=to_regclass('control.'||table_name.name) AND a.grantee=0)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('control.'||table_name.name)
   AND t.tgname='artifact_lifecycle_fence' AND t.tgtype=62 AND t.tgenabled='O' AND NOT t.tgisinternal
   AND t.tgfoid='openpc.guard_runtime_artifact_lifecycle_fence()'::regprocedure
   AND t.tgnargs=0 AND t.tgqual IS NULL AND NOT t.tgdeferrable)
  OR EXISTS(SELECT 1 FROM (VALUES('runtime_target_disposition_immutable',27),('runtime_target_disposition_truncate',34)) required(name,kind)
   WHERE NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('control.'||table_name.name)
    AND t.tgname=required.name AND t.tgtype=required.kind AND t.tgenabled='O' AND NOT t.tgisinternal
    AND t.tgfoid='openpc.guard_runtime_target_disposition_immutable()'::regprocedure
    AND t.tgnargs=0 AND t.tgqual IS NULL AND NOT t.tgdeferrable)))
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['openpc_control_runtime','openpc_control_worker','openpc_control_reader']) role(name)
  WHERE has_table_privilege(role.name,'control.runtime_target_disposition_key','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
   OR has_any_column_privilege(role.name,'control.runtime_target_disposition_key','SELECT,INSERT,UPDATE'))
 OR NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
  WHERE c.oid='control.runtime_target_disposition_key'::regclass AND c.relkind='r' AND NOT c.relispartition
   AND r.rolname='openpc_control_owner' AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid)
   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0))
 THEN RAISE EXCEPTION 'TARGET-DISPOSITION-OWNER-UNAVAILABLE'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_runtime_target_disposition_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_target_disposition_owner() TO openpc_control_worker,openpc_control_reader;
SELECT openpc.assert_runtime_target_disposition_owner();
`;
