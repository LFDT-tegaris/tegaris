import { it, expect } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./completion-worker-installation-guards.mjs', import.meta.url).href
);
const sql = module.notificationCompletionWorkerInstallationGuardsSql;
if (typeof sql !== 'string') throw new Error('Missing completion installation guards');
it('passes the shared generated SQL conditional preflight', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('binds real credential epoch/key, exact subscription and finite signed limits without business grants', () => {
  for (const text of [
    '24030,367',
    'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
    'credential_epoch',
    'public_key_digest',
    "state='ACTIVE' AND kind='WORKLOAD'",
    'NOTIFICATION-COMPLETION-WORKER-IDENTITY',
    'NOT BETWEEN 1 AND 1000',
    '3600000',
    'relforcerowsecurity',
    'pg_try_advisory_xact_lock',
    'to_jsonb(OLD)',
    'REVOKE ALL',
    'BEFORE TRUNCATE',
  ])
    expect(sql).toContain(text);
  expect(sql).not.toMatch(
    /GRANT\s|SECURITY DEFINER|insert into control\.(work_item|notification_source_inbox|notification_source_cursor)/iu,
  );
});
it('cannot reactivate or replace a revoked original through updates', () => {
  expect(sql).toContain("OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'");
  expect(sql).toContain("to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'");
  expect(sql).toContain("IF TG_OP='DELETE'");
});
