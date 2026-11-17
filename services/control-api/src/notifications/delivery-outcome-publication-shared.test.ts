import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const owner: Record<string, unknown> = await import(
  new URL('./delivery-outcome-publication-shared.mjs', import.meta.url).href
);
const sql = owner.notificationOutcomePublicationSharedSql;
if (typeof sql !== 'string') throw new Error('Missing shared publication owner');
it('checks the exact installed source dispatch and separate terminal uniqueness before admitting publication', () => {
  expect(() => verifyConditionCases(sql)).not.toThrow();
  for (const required of [
    'p.prosrc=',
    'NOT p.prosecdef',
    'business_outbox_payload',
    'work_item_lifecycle',
    'notification_delivery_budget_guard',
    'outbox_notification_completion_sequence_uq',
    'i.indisunique AND i.indisvalid',
    'DEFERRABLE INITIALLY DEFERRED',
    'check_notification_outcome_publication_original(operation)',
  ])
    expect(sql).toContain(required);
  expect(sql).not.toMatch(/SECURITY DEFINER|WHEN OTHERS|GRANT INSERT|GRANT UPDATE/iu);
});

it('keeps prepared async admission outside the installed default outbox owner', async () => {
  const active: Record<string, unknown> = await import(
    new URL('../../../identity-service/src/db/business-receipt-guards.mjs', import.meta.url).href
  );
  const prepared: Record<string, unknown> = await import(
    new URL('./async-worker-proof-guards.mjs', import.meta.url).href
  );
  expect(active.businessReceiptGuardsSql).not.toContain(
    'NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE',
  );
  expect(sql).not.toContain('NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE');
  expect(prepared.notificationAsyncWorkOutboxAdmissionSql).toContain(
    'NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE',
  );
  expect(prepared.notificationAsyncWorkOutboxAdmissionSql).toContain(
    'PERFORM openpc.admit_notification_async_work_event(NEW)',
  );
  expect(prepared.notificationAsyncWorkOutboxAdmissionSql).not.toContain(
    'check_notification_async_work_event',
  );
});
