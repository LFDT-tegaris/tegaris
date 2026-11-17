import { expect, it } from 'vitest';
import {
  assertNotificationDeliveryCancellationTransition,
  NotificationDeliveryCancellationContractError,
  proposeNotificationDeliveryCancellation,
} from './delivery-cancellation-contract.js';
import {
  notificationDeliverySnapshot,
  planNotificationDelivery,
  planNotificationObservation,
  type NotificationDeliverySnapshot,
} from './delivery-policy.js';
import type { NotificationDeliveryBudgetRecord } from './delivery-start-state.js';

// Pure projections only; none of these values establish a real source, worker,
// initiating authority, signed receipt, gateway claim or database effect.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
function record(state: NotificationDeliverySnapshot['state'] = 'PENDING') {
  return {
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: id(3),
    payloadDigest: digest('a'),
    state,
    attemptCount: state === 'PENDING' ? 0 : 2,
    attemptLimit: 6,
    nextAttemptAtMs: state === 'PENDING' ? 1000 : state === 'RETRY_WAIT' ? 31000 : null,
    lastStartedAtMs: state === 'PENDING' ? null : 1000,
    cancelRequested: state === 'CANCELLED',
    revision: '8',
    deliveryRequestEventId: id(4),
    deliveryRequestOperationId: id(5),
    budgetEnvironmentId: 'local-notification',
    budgetGenerationId: id(6),
    budgetEffectiveDigest: digest('b'),
    budgetConfiguredLimit: 100,
    budgetWorkerInstallationDigest: digest('c'),
  } satisfies NotificationDeliveryBudgetRecord;
}
function expected(p: NotificationDeliveryBudgetRecord) {
  return {
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    notificationOccurrenceId: p.notificationOccurrenceId,
    payloadDigest: p.payloadDigest,
    expectedRevision: p.revision,
  };
}
function propose(p: NotificationDeliveryBudgetRecord, now = 2000) {
  return proposeNotificationDeliveryCancellation(p, expected(p), now);
}
const rejected = NotificationDeliveryCancellationContractError;

it.each(['PENDING', 'RETRY_WAIT'] as const)(
  'proposes cancellation of %s without changing original attempts, source or budget',
  (state) => {
    const before = record(state);
    const next = propose(before);
    expect(next).toEqual({
      ...before,
      state: 'CANCELLED',
      cancelRequested: true,
      nextAttemptAtMs: null,
      revision: '9',
    });
    assertNotificationDeliveryCancellationTransition(before, next, expected(before), 2000);
    expect(before).toEqual(record(state));
    expect(Object.isFrozen(next)).toBe(true);
    expect(propose(next)).toEqual(next);
    expect(propose(next)).not.toBe(next);
  },
);

it.each(['STARTED', 'AMBIGUOUS'] as const)(
  'retains %s and its original ordinal/time even without any visible gateway claim',
  (state) => {
    const before = record(state);
    const next = propose(before);
    expect(next).toEqual({ ...before, cancelRequested: true, revision: '9' });
    expect(propose(next)).toEqual(next);
    expect(
      planNotificationDelivery(notificationDeliverySnapshot.strip().parse(next), 0, 99999999)
        .action,
    ).toBe('RECONCILE');
    for (const invented of ['CANCELLED', 'DELIVERED', 'FAILED', 'RETRY_WAIT'] as const)
      expect(() =>
        assertNotificationDeliveryCancellationTransition(
          before,
          { ...next, state: invented, nextAttemptAtMs: invented === 'RETRY_WAIT' ? 31000 : null },
          expected(before),
          2000,
        ),
      ).toThrow(rejected);
  },
);

it.each(['DELIVERED', 'FAILED', 'CANCELLED', 'QUARANTINED'] as const)(
  'preserves terminal %s without asserting retroactive cancellation or advancing revision',
  (state) => {
    for (const cancelRequested of [true, false]) {
      const before = { ...record(state), cancelRequested };
      const next = propose(before);
      expect(next).toEqual(before);
      assertNotificationDeliveryCancellationTransition(before, next, expected(before), 2000);
      expect(() =>
        assertNotificationDeliveryCancellationTransition(
          before,
          { ...next, cancelRequested: !cancelRequested, revision: '9' },
          expected(before),
          2000,
        ),
      ).toThrow(rejected);
    }
  },
);

it('delegates authenticated-result consequences to the existing policy without an alternate outcome model', () => {
  const cancelled = propose(record('STARTED'));
  const snapshot = notificationDeliverySnapshot.strip().parse(cancelled);
  const observation = {
    participantId: snapshot.participantId,
    privacyDomainId: snapshot.privacyDomainId,
    notificationOccurrenceId: snapshot.notificationOccurrenceId,
    payloadDigest: snapshot.payloadDigest,
    attemptNumber: snapshot.attemptCount,
    startedAtMs: snapshot.lastStartedAtMs!,
    observedAtMs: 2100,
  };
  for (const [outcome, state] of [
    ['AMBIGUOUS', 'AMBIGUOUS'],
    ['DELIVERED', 'DELIVERED'],
    ['PERMANENT_FAILURE', 'FAILED'],
    ['RETRYABLE_NO_EFFECT', 'CANCELLED'],
  ] as const) {
    const resolved = planNotificationObservation(snapshot, { ...observation, outcome }, 6);
    expect(resolved.state).toBe(state);
    expect(resolved.attemptCount).toBe(2);
    // A later result is not a cancellation-only transition, even if terminal.
    expect(() =>
      assertNotificationDeliveryCancellationTransition(
        cancelled,
        { ...cancelled, ...resolved, revision: '10' },
        expected(cancelled),
        2100,
      ),
    ).toThrow(rejected);
  }
});

it.each([
  ['participantId', id(21)],
  ['privacyDomainId', id(22)],
  ['notificationOccurrenceId', id(23)],
  ['payloadDigest', digest('d')],
  ['expectedRevision', '7'],
  ['expectedRevision', '9'],
] as const)('rejects mismatched expected %s', (field, value) => {
  const before = record();
  expect(() =>
    proposeNotificationDeliveryCancellation(before, { ...expected(before), [field]: value }, 2000),
  ).toThrow(rejected);
});

it.each([
  ['participantId', id(21)],
  ['privacyDomainId', id(22)],
  ['notificationOccurrenceId', id(23)],
  ['payloadDigest', digest('d')],
  ['deliveryRequestEventId', id(24)],
  ['deliveryRequestOperationId', id(25)],
  ['budgetEnvironmentId', 'other-environment'],
  ['budgetGenerationId', id(26)],
  ['budgetEffectiveDigest', digest('e')],
  ['budgetConfiguredLimit', 99],
  ['budgetWorkerInstallationDigest', digest('f')],
  ['attemptLimit', 5],
  ['attemptCount', 1],
  ['lastStartedAtMs', 999],
  ['nextAttemptAtMs', 32000],
  ['cancelRequested', false],
  ['revision', '8'],
  ['revision', '10'],
] as const)('rejects substituted after-binding %s', (field, value) => {
  const before = record('STARTED');
  expect(() =>
    assertNotificationDeliveryCancellationTransition(
      before,
      { ...propose(before), [field]: value },
      expected(before),
      2000,
    ),
  ).toThrow(rejected);
});

it('rejects stale proposals after budget, attempt, source or revision races', () => {
  const before = record('RETRY_WAIT');
  const next = propose(before);
  for (const raced of [
    { ...before, revision: '9' },
    { ...before, revision: '9', attemptLimit: 3 },
    { ...before, revision: '9', deliveryRequestEventId: id(29) },
    { ...before, revision: '9', state: 'STARTED', attemptCount: 3, nextAttemptAtMs: null },
  ]) {
    expect(() =>
      assertNotificationDeliveryCancellationTransition(raced, next, expected(before), 2000),
    ).toThrow(rejected);
    // Refreshing only the expected revision cannot reuse the old proposal.
    expect(() =>
      assertNotificationDeliveryCancellationTransition(
        raced,
        next,
        { ...expected(before), expectedRevision: '9' },
        2000,
      ),
    ).toThrow(rejected);
  }
});

it.each([0, 1, 3, 6])('preserves the lifetime budget %s, including an exhausted cap', (limit) => {
  for (const state of ['PENDING', 'RETRY_WAIT', 'STARTED', 'AMBIGUOUS'] as const) {
    const before = { ...record(state), attemptLimit: limit, budgetConfiguredLimit: limit };
    const next = propose(before);
    expect(next.attemptLimit).toBe(limit);
    expect(next.attemptCount).toBe(before.attemptCount);
    expect(next.budgetConfiguredLimit).toBe(limit);
  }
});

it('checks exact unsigned-64 revisions and permits a no-op at the maximum only', () => {
  const before = { ...record(), revision: '18446744073709551614' };
  const next = propose(before);
  expect(next.revision).toBe('18446744073709551615');
  expect(propose(next)).toEqual(next);
  expect(() => propose({ ...before, revision: next.revision })).toThrow(rejected);
  for (const revision of ['0', '01', '-1', '1.0', '1e1', '18446744073709551616'])
    expect(() => propose({ ...before, revision })).toThrow(rejected);
});

it.each([NaN, Infinity, -1, 999, 1000.5, Number.MAX_SAFE_INTEGER + 1])(
  'rejects invalid or pre-attempt clocks: %s',
  (now) => expect(() => propose(record('STARTED'), now)).toThrow(rejected),
);

it.each([undefined, null, false, 'CANCELLED', 1, [], new Date(), { cancelled: true }])(
  'rejects unknown input instead of manufacturing cancellation: %s',
  (value) => {
    const before = record();
    const next = propose(before);
    expect(() => proposeNotificationDeliveryCancellation(value, expected(before), 2000)).toThrow(
      rejected,
    );
    expect(() => proposeNotificationDeliveryCancellation(before, value, 2000)).toThrow(rejected);
    expect(() =>
      assertNotificationDeliveryCancellationTransition(before, value, expected(before), 2000),
    ).toThrow(rejected);
    expect(() =>
      assertNotificationDeliveryCancellationTransition(value, next, expected(before), 2000),
    ).toThrow(rejected);
  },
);

it('rejects unknown fields, accessors and fabricated claim/receipt shortcuts without invoking them', () => {
  const before = record();
  const next = propose(before);
  for (const extra of [
    { gatewayClaim: null },
    { noEffect: true },
    { authorized: true },
    { receipt: 'signed' },
    { attemptId: id(30) },
  ]) {
    expect(() =>
      proposeNotificationDeliveryCancellation({ ...before, ...extra }, expected(before), 2000),
    ).toThrow(rejected);
    expect(() =>
      proposeNotificationDeliveryCancellation(before, { ...expected(before), ...extra }, 2000),
    ).toThrow(rejected);
    expect(() =>
      assertNotificationDeliveryCancellationTransition(
        before,
        { ...next, ...extra },
        expected(before),
        2000,
      ),
    ).toThrow(rejected);
  }
  let called = false;
  const accessor = Object.defineProperty({ ...before }, 'cancelRequested', {
    enumerable: true,
    get() {
      called = true;
      return true;
    },
  });
  expect(() => proposeNotificationDeliveryCancellation(accessor, expected(before), 2000)).toThrow(
    rejected,
  );
  expect(called).toBe(false);
});
