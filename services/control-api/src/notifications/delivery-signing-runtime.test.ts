import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { notificationSigningRecoveryAction } from './delivery-signing-runtime.js';
it.each([
  [null, 'READ_ORIGINAL'],
  ['PREPARED', 'READ_ORIGINAL'],
  ['DISPATCHED', 'LOOKUP'],
  ['OBSERVED', 'READ_OBSERVATION'],
] as const)('classifies %s without retry authority', (state, want) =>
  expect(notificationSigningRecoveryAction(state)).toBe(want),
);
it('allows one provider perform only after a successfully awaited exclusive committed claim', () => {
  const src = readFileSync(new URL('./delivery-signing-runtime.ts', import.meta.url), 'utf8');
  expect(src.match(/\.perform\(/gu)).toHaveLength(1);
  expect(src.indexOf('await claimNotificationDeliverySigning')).toBeLessThan(
    src.indexOf('await provider.perform'),
  );
  expect(src.indexOf('if (!owned.claimed') >= 0 || src.indexOf('if(!owned.claimed') >= 0).toBe(
    true,
  );
  const recovery = src.slice(src.indexOf('async reconcile('));
  expect(recovery).toContain('provider.lookup(');
  expect(recovery).not.toMatch(/\.perform\(|claimNotification|prepareNotification/u);
  expect(src).not.toMatch(/setTimeout|setInterval|signNotificationClaim|\.deliver\(/u);
});
