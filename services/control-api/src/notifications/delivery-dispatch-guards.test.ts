import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-dispatch-guards.mjs', import.meta.url).href
);
if (typeof module.notificationDeliveryDispatchGuardsSql !== 'string')
  throw new Error('Missing dispatch SQL');
const sql = module.notificationDeliveryDispatchGuardsSql;
it('validates shared SQL conditional structure', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('requires post-STARTED originals, current scopes/fences, native key state and configuration without pre-STARTED signer admission', () => {
  for (const text of [
    'check_notification_delivery_start_original(start)',
    'check_notification_delivery_signing_original(item)',
    "d.state<>'STARTED'",
    'd.cancel_requested',
    'start.delivery_revision+1',
    "start.transition->'after' IS DISTINCT FROM after_state",
    'current_notification_delivery_limit',
    'l.mode=CASE',
    'FOR UPDATE',
    'NOTIFICATION-DISPATCH-CUSTODY',
    'NOTIFICATION-DISPATCH-KMS-UNKNOWN',
    'NOTIFICATION-DISPATCH-KMS-STALE',
    "w.state<>'ACTIVE'",
    'c.valid_until>clock_timestamp()',
  ])
    expect(sql).toContain(text);
  expect(sql).not.toContain('check_notification_delivery_signing_current');
  expect(sql).not.toMatch(/SECURITY DEFINER|GRANT\s|notification-receipt-signer:/iu);
});
it('permits one claim mutation and no reset, delete, ordinal or budget rewrite', () => {
  for (const text of [
    "OLD.state<>'PENDING' OR NEW.state<>'CLAIMED'",
    "ARRAY['state','claim_token','claimed_at_ms']",
    'transaction_timestamp()',
    'clock_timestamp()',
    'BEFORE UPDATE',
    'NOTIFICATION-DISPATCH-ONCE',
  ])
    expect(sql).toContain(text);
  expect(sql).not.toMatch(
    /update control\.notification_delivery\s|insert into control\.|delete from control\./iu,
  );
  const schema = readFileSync(
    new URL('./delivery-start-atomic-schema.ts', import.meta.url),
    'utf8',
  );
  expect(schema).toContain("unique('notification_dispatch_claim_token_uq').on(t.claimToken)");
});
