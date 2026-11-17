import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-start-atomic-guards.mjs', import.meta.url).href
);
if (typeof module.notificationDeliveryStartAtomicGuardsSql !== 'string')
  throw new Error('Missing atomic SQL');
const sql = module.notificationDeliveryStartAtomicGuardsSql;
it('passes ordinary shared SQL conditional validation', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('requires the exact signed original and current admission before start/projection', () => {
  for (const token of [
    'check_notification_delivery_start_original',
    'check_notification_delivery_signing_current(signing)',
    "signing.observation->>'outcome' IS DISTINCT FROM 'SIGNED'",
    'item.receipt_id IS DISTINCT FROM signing.signing_attempt_id',
    'NOTIFICATION-START-TRANSITION',
    'NOTIFICATION-START-PROJECTION',
    'before_row.revision+1',
    'archive_cose_binding',
  ])
    expect(sql).toContain(token);
  expect(sql).not.toMatch(
    /GRANT\s|SECURITY DEFINER|DROP TRIGGER[^;]*notification_delivery_attempt_closed|CREATE OR REPLACE FUNCTION openpc\.guard_notification_delivery_budget/iu,
  );
});
it('requires all four owners at commit and keeps original members immutable while allowing only guarded intent claims', () => {
  for (const token of [
    'notification_delivery_start_complete',
    'notification_delivery_attempt_complete',
    'notification_delivery_dispatch_intent_complete',
    'DEFERRABLE INITIALLY DEFERRED',
    'BEFORE UPDATE OR DELETE OR TRUNCATE',
    'NOTIFICATION-START-INCOMPLETE',
    'tgdeferrable AND tginitdeferred',
    'tgtype=7',
    'THEN 42 ELSE 58 END',
    'THEN 21 ELSE 5 END',
    'tgtype=19',
    'notification_delivery_dispatch_claim_guard',
    'check_notification_delivery_dispatch_intent_original(i)',
    'tgtype=17',
  ])
    expect(sql).toContain(token);
  const schema = readFileSync(
    new URL('./delivery-start-atomic-schema.ts', import.meta.url),
    'utf8',
  );
  for (const token of [
    'notification_dispatch_revision_uq',
    'notification_dispatch_attempt_uq',
    'notification_dispatch_start_fk',
    "'PENDING'",
    "'CLAIMED'",
    'notification_dispatch_claim_token_uq',
    'claimed_at_ms',
  ])
    expect(schema).toContain(token);
});
