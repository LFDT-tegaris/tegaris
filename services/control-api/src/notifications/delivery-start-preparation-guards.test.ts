import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-start-preparation-guards.mjs', import.meta.url).href
);
if (typeof module.notificationDeliveryPreparationGuardsSql !== 'string')
  throw new Error('Missing preparation SQL');
const sql = module.notificationDeliveryPreparationGuardsSql;
it('passes the ordinary SQL conditional preflight', () => {
  expect(() => verifyConditionCases(sql)).not.toThrow();
});
it('requires installed guards/RLS and closes even empty mutation statements', () => {
  for (const text of [
    'relrowsecurity AND relforcerowsecurity',
    "tgenabled IN ('O','A')",
    'openpc.assert_notification_delivery_budget_owner()',
    'BEFORE UPDATE OR DELETE OR TRUNCATE',
    'FOR EACH STATEMENT',
    'NOTIFICATION-PREPARATION-IMMUTABLE',
    "THEN 'ExclusiveLock' ELSE 'ShareLock' END",
  ])
    expect(sql).toContain(text);
  expect(sql).not.toMatch(/GRANT\s|SECURITY DEFINER|SET\s+row_security\s*=\s*off/iu);
});
it('binds real source, current generation, exact before/planned/context, original IDs and no effects', () => {
  for (const text of [
    'openpc.check_notification_delivery_requested_event(event)',
    'openpc.current_notification_delivery_limit',
    'notification_endpoint_verification',
    'NEW.attempt_number<>d.attempt_count+1',
    "p->'before' IS DISTINCT FROM b",
    "p->'plannedAfter' IS DISTINCT FROM planned",
    'c IS DISTINCT FROM expected',
    'NEW.operation_id IN (NEW.source_operation_id,NEW.attempt_id)',
    "d.state NOT IN ('PENDING','RETRY_WAIT')",
    'd.next_attempt_at_ms>started',
    'deadline<=now_ms',
    'notification_delivery_preparation_ordinal_uq',
  ])
    expect(
      text.endsWith('_uq')
        ? readFileSync(new URL('./delivery-start-schema.ts', import.meta.url), 'utf8')
        : sql,
    ).toContain(text);
  expect(sql).not.toMatch(
    /(?:INSERT INTO|UPDATE|DELETE FROM) control\.(?:outbox_event|notification_delivery_start|notification_delivery_attempt)\b/iu,
  );
});
it('the source entrypoint accepts selectors and calls the committed Identity owner inside real configuration admission', () => {
  const src = readFileSync(new URL('./delivery-start-preparation.ts', import.meta.url), 'utf8');
  for (const text of [
    'withNotificationDeliveryConfiguration',
    'assertNotificationDeliveryWorkerAdmission',
    'readPublishedNotificationDeliveryRequest',
    'withCurrentNotificationRouting',
    'for update',
    'rendered.bytes.fill(0)',
  ])
    expect(src).toContain(text);
  expect(src).toMatch(
    /notificationDeliveryWorkerContextIdentity\(\s*admission,\s*client,\s*input.worker/u,
  );
  expect(src.indexOf('const original = await prior')).toBeLessThan(
    src.indexOf('const operationId = localOperationId()'),
  );
  expect(src).not.toMatch(
    /signNotificationClaim\(|createNotificationGatewayAdapter\(|\.deliver\(|\.decrypt\(/u,
  );
});
