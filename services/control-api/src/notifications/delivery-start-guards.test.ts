import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const owner: Record<string, unknown> = await import(
  new URL('./delivery-start-guards.mjs', import.meta.url).href
);
if (typeof owner.notificationDeliveryBudgetGuardsSql !== 'string')
  throw new Error('Missing notification budget guard owner');
const sql = owner.notificationDeliveryBudgetGuardsSql;

// Generator/dispatch contract checks only. The connected PostgreSQL cases own
// actual SQL permissions, row locking, rollback and source/Identity admission.
it('derives the cap from the actual environment-bound owner and checks source publication first', () => {
  expect(sql).toContain('openpc.check_notification_delivery_requested_event(event)');
  expect(sql.indexOf('openpc.check_notification_delivery_requested_event(event)')).toBeLessThan(
    sql.indexOf('SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit'),
  );
  for (const field of [
    'budget_generation_id',
    'budget_effective_digest',
    'budget_configured_limit',
  ])
    expect(sql).toContain(`NEW.${field} IS DISTINCT FROM actual.`);
  expect(sql).toContain("w.subscription_id<>'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'");
  expect(sql).toContain("'notification-installation:'");
  expect(sql).toContain('control.notification_endpoint_verification');
  expect(sql).toContain("c.kind='WORKLOAD_MTLS'");
  expect(sql).not.toMatch(/GRANT\s|SECURITY DEFINER|SET\s+row_security\s*=\s*off/iu);
});

it('keeps cap-only updates closed over every other column and refuses empty attempt statements', () => {
  const allowed = [
    'attempt_limit',
    'revision',
    'budget_generation_id',
    'budget_effective_digest',
    'budget_configured_limit',
    'budget_worker_installation_digest',
  ];
  expect(sql).toContain(`to_jsonb(NEW)-ARRAY[${allowed.map((p) => `'${p}'`).join(',')}]`);
  expect(sql).toContain('NEW.attempt_limit>=OLD.attempt_limit');
  expect(sql).toContain('NEW.revision<>OLD.revision+1');
  expect(sql).toContain("NEW.state<>'PENDING' OR NEW.attempt_count<>0");
  expect(sql).toContain('statement_timestamp()');
  expect(sql).toContain(
    'BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_attempt FOR EACH STATEMENT',
  );
  expect(sql).toContain("RAISE EXCEPTION 'NOTIFICATION-DELIVERY-EFFECT-CLOSED'");
  expect(sql).not.toMatch(/INSERT INTO control\.outbox_event|NEW\.state\s*:=/iu);
});

it('runtime requires the executable guard and uses the canonical callback before any mutation', () => {
  const source = readFileSync(new URL('./delivery-start-state.ts', import.meta.url), 'utf8');
  expect(source).toMatch(
    /withNotificationDeliveryConfiguration\(\s*pool,\s*kernel,\s*socket,\s*input,/u,
  );
  expect(source.indexOf('select openpc.assert_notification_delivery_budget_owner()')).toBeLessThan(
    source.indexOf('insert into control.notification_delivery'),
  );
  expect(source).not.toMatch(
    /planNotificationDelivery\s*\(|createNotificationGatewayAdapter\s*\(|signNotificationClaim\s*\(/u,
  );
  expect(sql).toContain('relrowsecurity AND relforcerowsecurity');
  expect(sql).toContain("tgenabled IN ('O','A')");
  expect(sql).toContain("current_setting('session_replication_role')<>'origin'");
});

it('passes the existing generated SQL conditional preflight', () => {
  expect(() => verifyConditionCases(sql)).not.toThrow();
});

it('routes only a restricting cancellation through its exact native owner before send readiness', () => {
  const branch = sql.indexOf(
    "IF TG_OP='UPDATE' AND NOT OLD.cancel_requested AND NEW.cancel_requested THEN",
  );
  const limit = sql.indexOf(
    'SELECT * INTO STRICT actual FROM openpc.current_notification_delivery_limit',
  );
  expect(branch).toBeGreaterThan(sql.indexOf("THEN RAISE EXCEPTION 'PC-AUTH-0005'"));
  expect(branch).toBeLessThan(limit);
  expect(sql.slice(branch, sql.indexOf('END IF;', branch))).toContain(
    'PERFORM openpc.check_notification_delivery_cancellation_projection(OLD,NEW);\n  RETURN NEW;',
  );
});

it('uses the existing lifecycle exclusion without widening immutable source UPDATE privileges', () => {
  const source = readFileSync(new URL('./delivery-start-state.ts', import.meta.url), 'utf8');
  expect(source).not.toMatch(/from control\.notification_occurrence[^`]*for (?:update|share)/iu);
  expect(sql).toContain("'evidence-lifecycle:'||NEW.participant_id::text");
  expect(sql).toContain("THEN 'ExclusiveLock' ELSE 'ShareLock' END");
  expect(sql).not.toMatch(/FROM control\.notification_occurrence[^;]*FOR (?:UPDATE|SHARE)/iu);
  expect(source).toMatch(/from control\.notification_delivery[^`]*for update/iu);
});

it('joins STARTED to the atomic projection without recursive owner admission', () => {
  const admission = sql.slice(
    sql.indexOf('CREATE OR REPLACE FUNCTION openpc.assert_notification_delivery_budget_owner'),
    sql.indexOf('CREATE OR REPLACE FUNCTION openpc.guard_notification_delivery_budget'),
  );
  expect(admission).toContain('openpc.assert_notification_delivery_start_atomic_guards()');
  expect(admission).not.toContain('openpc.assert_notification_delivery_start_atomic_owner()');
  expect(sql).toContain("ELSIF NEW.state='STARTED' AND OLD.state IN ('PENDING','RETRY_WAIT')");
  expect(sql).toContain('openpc.check_notification_delivery_start_projection(OLD,NEW)');
  const registration = readFileSync(
    new URL('../configuration/generate-security-tail.mjs', import.meta.url),
    'utf8',
  );
  expect(registration.indexOf('${notificationDeliveryStartAtomicGuardsSql}')).toBeLessThan(
    registration.indexOf('DROP TRIGGER IF EXISTS notification_delivery_attempt_closed'),
  );
});
