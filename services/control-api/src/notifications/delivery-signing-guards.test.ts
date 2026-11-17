import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-signing-guards.mjs', import.meta.url).href
);
if (typeof module.notificationDeliverySigningGuardsSql !== 'string')
  throw new Error('Missing signing SQL');
const sql = module.notificationDeliverySigningGuardsSql;
it('passes ordinary shared SQL conditional validation', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('requires genuine source/native request, current generation, scope, identity and live fences before dispatch', () => {
  for (const token of [
    'relrowsecurity AND relforcerowsecurity',
    'tgtype=23',
    'tgtype=42',
    'check_notification_delivery_requested_event(event)',
    'current_notification_delivery_limit',
    'NOTIFICATION-SIGNING-GENERATION',
    'NOTIFICATION-SIGNING-NATIVE-PAYLOAD',
    'NOTIFICATION-SIGNING-FENCE',
    'notification_endpoint_verification',
    "p->'before' IS DISTINCT FROM before",
    'item.signing_attempt_id IN',
    "decode('00','hex')",
  ])
    expect(sql).toContain(token);
  expect(sql).not.toMatch(/GRANT\s|SECURITY DEFINER|SET\s+row_security\s*=\s*off/iu);
});
it('only permits PREPARED to DISPATCHED to first OBSERVED and closes deletion/truncate', () => {
  for (const token of [
    "OLD.state='PREPARED' AND NEW.state='DISPATCHED'",
    "OLD.state<>'DISPATCHED' OR NEW.state<>'OBSERVED'",
    'NOTIFICATION-SIGNING-ONCE',
    'BEFORE DELETE OR TRUNCATE',
    'archive_cose_binding',
    'NOTIFICATION-SIGNING-OBSERVATION',
  ])
    expect(sql).toContain(token);
  const schema = readFileSync(new URL('./delivery-signing-schema.ts', import.meta.url), 'utf8');
  for (const token of [
    'notification_delivery_signing_receipt_uq',
    'notification_delivery_signing_preparation_fk',
    'notification_delivery_signing_signer_fk',
    'is not null',
  ])
    expect(schema).toContain(token);
});
