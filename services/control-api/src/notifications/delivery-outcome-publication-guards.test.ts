import { it, expect } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-outcome-publication-guards.mjs', import.meta.url).href
);
const sql = module.notificationOutcomePublicationGuardsSql;
if (typeof sql !== 'string') throw new Error('Missing publication guards');
it('validates every generated conditional using the shared SQL guard', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('requires canonical shared admission and atomic first/result/projection/event/work completeness', () => {
  for (const text of [
    'assert_notification_outcome_publication_shared_owners()',
    'check_notification_outcome_signing_current(s)',
    "s.state IS DISTINCT FROM 'OBSERVED'",
    "o->>'outcome' IS DISTINCT FROM 'SIGNED'",
    'check_notification_delivery_observation_original(first)',
    'NOTIFICATION-OUTCOME-PROJECTION-BEFORE',
    'NOTIFICATION-OUTCOME-PROJECTION-AFTER',
    'NOTIFICATION-OUTCOME-PUBLICATION-INCOMPLETE',
    'NOTIFICATION-OUTCOME-PUBLICATION-FIRST',
    'NOTIFICATION-OUTCOME-FAILURE-WORK',
    'DEFERRABLE INITIALLY DEFERRED',
    'NOTIFICATION_DELIVERY_COMPLETION_REFERENCE',
    'BEFORE INSERT ON control.notification_delivery_observation',
    'REVOKE ALL',
  ])
    expect(sql).toContain(text);
  expect(sql).not.toMatch(
    /GRANT\s|SECURITY DEFINER|current_notification_delivery_limit|current_notification_channel/iu,
  );
});
it('keeps historical WorkItem provenance after real human changes and never permits a second native claim', () => {
  expect(sql).toContain('before_revision=1');
  expect(sql).toContain('notification_failure_initial_projection(o)');
  expect(sql).not.toMatch(
    /update control\.notification_delivery_outcome_signing|set state='PREPARED'/iu,
  );
});
