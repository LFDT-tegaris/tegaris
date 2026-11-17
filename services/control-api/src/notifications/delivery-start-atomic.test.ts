import { expect, it } from 'vitest';
import { decodeNotificationDispatchClaim } from './delivery-start-atomic.js';
import { readFileSync } from 'node:fs';
import { notificationDeliverySigningSample } from '../../../../tests/integration/identity/notification-delivery-signing-cases.js';
import { notificationSigningTransition } from './delivery-signing-contract.js';
import {
  encodeNotificationDeliveryStartTransition,
  decodeNotificationDeliveryStartTransition,
} from './delivery-start-transition.js';
it('retains the original native signed transition, original ordinal and exact before/after across readback', () => {
  const { signing, observe } = notificationDeliverySigningSample(),
    transition = notificationSigningTransition(signing, observe()),
    e = encodeNotificationDeliveryStartTransition(transition);
  expect(decodeNotificationDeliveryStartTransition(e.transitionBytes, e.transitionDigest)).toEqual(
    transition,
  );
  expect(transition.receipt.deliveryRevision).toBe('1');
  expect(transition.after.state).toBe('STARTED');
  expect(transition.before.state).toBe('PENDING');
  expect(transition.attempt.attemptId).toBe(signing.request.deliveryAttemptId);
  expect(e.receiptPayload.toString('hex')).toBe(signing.request.payloadHex);
});
it('places all four writes in the same current-owner transaction before complete readback; failure recovery is read-only', () => {
  const src = readFileSync(new URL('./delivery-start-atomic.ts', import.meta.url), 'utf8');
  for (const name of [
    'notification_delivery_start',
    'notification_delivery_attempt',
    'notification_delivery_dispatch_intent',
  ])
    expect(src).toContain(`insert into control.${name}(`);
  expect(src).toContain('update control.notification_delivery set');
  expect(src).toContain('openpc.check_notification_delivery_start_complete');
  expect(src).toContain('withCurrentNotificationSigning');
  expect(src).toContain('readNotificationDeliveryStart');
  expect(src).not.toMatch(
    /\.perform\(|\.lookup\(|\.deliver\(|signNotificationClaim\(|insert into control\.outbox_event/iu,
  );
});

it('retains pending and terminal claimed history without treating either as a live grant', () => {
  expect(
    decodeNotificationDispatchClaim({ state: 'PENDING', claim_token: null, claimed_at_ms: null }),
  ).toEqual({ state: 'PENDING', claimToken: null, claimedAtMs: null });
  expect(
    decodeNotificationDispatchClaim({
      state: 'CLAIMED',
      claim_token: 'ab'.repeat(32),
      claimed_at_ms: '0',
    }),
  ).toEqual({ state: 'CLAIMED', claimToken: 'ab'.repeat(32), claimedAtMs: 0 });
});
it.each([
  { state: 'PENDING', claim_token: 'ab'.repeat(32), claimed_at_ms: null },
  { state: 'PENDING', claim_token: null, claimed_at_ms: '1' },
  { state: 'CLAIMED', claim_token: null, claimed_at_ms: '1' },
  { state: 'CLAIMED', claim_token: 'AB'.repeat(32), claimed_at_ms: '1' },
  { state: 'CLAIMED', claim_token: 'ab'.repeat(31), claimed_at_ms: '1' },
  { state: 'CLAIMED', claim_token: 'ab'.repeat(32), claimed_at_ms: null },
  ...['-1', '1.5', '01', '1e3', 'Infinity', 'NaN', '9007199254740992'].map((claimed_at_ms) => ({
    state: 'CLAIMED',
    claim_token: 'ab'.repeat(32),
    claimed_at_ms,
  })),
  { state: 'EXPIRED', claim_token: 'ab'.repeat(32), claimed_at_ms: '1' },
])('rejects corrupt claim history %#', (row) =>
  expect(() => decodeNotificationDispatchClaim(row)).toThrow(),
);
