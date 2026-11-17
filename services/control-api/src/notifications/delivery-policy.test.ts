import { describe, expect, it } from 'vitest';
import {
  initialDeliverySnapshot,
  planNotificationDelivery,
  planNotificationObservation,
  type NotificationDeliverySnapshot,
  type NotificationDeliveryObservation,
} from './delivery-policy.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const identity = {
  participantId: id(1),
  privacyDomainId: id(2),
  notificationOccurrenceId: id(3),
  payloadDigest: `sha256:${'ab'.repeat(32)}`,
};
const initial = () => initialDeliverySnapshot(identity, 10, 1000);
const started = () => planNotificationDelivery(initial(), 10, 1000).next;
const observe = (
  value: NotificationDeliverySnapshot,
  outcome: NotificationDeliveryObservation['outcome'],
  nowMs: number,
): NotificationDeliveryObservation => ({
  ...identity,
  attemptNumber: value.attemptCount,
  startedAtMs: value.lastStartedAtMs!,
  observedAtMs: nowMs,
  outcome,
});

describe('notification delivery deterministic policy (no dispatch or signed result)', () => {
  it('persists one initial send and five retry delays, capping delivery at six attempts', () => {
    let saved = initial();
    let now = 1000;
    const expectedDelays = [5000, 30000, 120000, 600000, 1800000];
    for (let attempt = 1; attempt <= 6; attempt += 1) {
      const plan = planNotificationDelivery(saved, 10, now);
      expect(plan.action).toBe('START');
      expect(plan.next.attemptCount).toBe(attempt);
      expect(plan.next.attemptLimit).toBe(6);
      expect(plan.next).toMatchObject(identity);
      // Simulated durable roundtrip of pure data only, not internal-service acceptance.
      saved = JSON.parse(JSON.stringify(plan.next)) as NotificationDeliverySnapshot;
      const observedAt = now + 17;
      saved = planNotificationObservation(
        saved,
        observe(saved, 'RETRYABLE_NO_EFFECT', observedAt),
        10,
      );
      if (attempt === 6) {
        expect(saved.state).toBe('FAILED');
        expect(planNotificationDelivery(saved, 100, observedAt).action).toBe('TERMINAL');
      } else {
        const due = observedAt + expectedDelays[attempt - 1]!;
        expect(saved.nextAttemptAtMs).toBe(due);
        expect(planNotificationDelivery(saved, 100, due - 1).action).toBe('WAIT');
        now = due;
      }
    }
  });

  it('zero sends nothing and a lower actual cap beats the registered six-send maximum', () => {
    const zero = planNotificationDelivery(initialDeliverySnapshot(identity, 0, 1000), 100, 1000);
    expect(zero.action).toBe('TERMINAL');
    expect(zero.next).toMatchObject({ state: 'FAILED', attemptCount: 0, attemptLimit: 0 });
    const one = planNotificationDelivery(initial(), 1, 1000).next;
    const failed = planNotificationObservation(one, observe(one, 'RETRYABLE_NO_EFFECT', 1010), 100);
    expect(failed).toMatchObject({ state: 'FAILED', attemptCount: 1, attemptLimit: 1 });
  });

  it('does not reset the consumed budget or due time when configuration changes or state is reloaded', () => {
    const first = started();
    const waiting = planNotificationObservation(
      first,
      observe(first, 'RETRYABLE_NO_EFFECT', 1010),
      10,
    );
    const reduced = planNotificationDelivery(waiting, 2, 2000);
    expect(reduced.action).toBe('WAIT');
    expect(reduced.next).toMatchObject({ attemptCount: 1, attemptLimit: 2, nextAttemptAtMs: 6010 });
    const reloaded = JSON.parse(JSON.stringify(reduced.next)) as NotificationDeliverySnapshot;
    expect(planNotificationDelivery(reloaded, 100, 6009)).toMatchObject({
      action: 'WAIT',
      next: { attemptLimit: 2, nextAttemptAtMs: 6010 },
    });
    const second = planNotificationDelivery(reloaded, 100, 6010).next;
    expect(
      planNotificationObservation(second, observe(second, 'RETRYABLE_NO_EFFECT', 6020), 100).state,
    ).toBe('FAILED');
    expect(planNotificationDelivery(waiting, 0, 2000).next).toMatchObject({
      state: 'FAILED',
      attemptCount: 1,
      attemptLimit: 0,
    });
  });

  it('cancels before STARTED without scheduling an effect', () => {
    const result = planNotificationDelivery({ ...initial(), cancelRequested: true }, 10, 1000);
    expect(result.action).toBe('TERMINAL');
    expect(result.next).toMatchObject({
      state: 'CANCELLED',
      attemptCount: 0,
      nextAttemptAtMs: null,
    });
    expect(planNotificationDelivery(result.next, 100, 9999).action).toBe('TERMINAL');
  });

  it('worker loss, lost ACK, cancellation and zero cap retain the same unresolved occurrence/attempt', () => {
    const original = started();
    for (const state of ['STARTED', 'AMBIGUOUS'] as const) {
      const outstanding = { ...original, state, cancelRequested: true };
      const result = planNotificationDelivery(outstanding, 0, 99999999);
      expect(result.action).toBe('RECONCILE');
      expect(result.next).toMatchObject({
        ...identity,
        state,
        attemptCount: 1,
        lastStartedAtMs: 1000,
        attemptLimit: 0,
      });
      expect(planNotificationDelivery(result.next, 100, 99999999).action).toBe('RECONCILE');
    }
    const ambiguous = planNotificationObservation(
      original,
      observe(original, 'AMBIGUOUS', 1100),
      10,
    );
    expect(planNotificationDelivery(ambiguous, 10, 99999999).action).toBe('RECONCILE');
  });

  it('reconciles a delayed definitive observation without turning delivery into user acknowledgement', () => {
    const original = { ...started(), cancelRequested: true };
    const unknown = planNotificationObservation(original, observe(original, 'AMBIGUOUS', 1010), 0);
    const delivered = planNotificationObservation(
      unknown,
      observe(unknown, 'DELIVERED', 2000),
      100,
    );
    expect(delivered).toMatchObject({
      ...identity,
      state: 'DELIVERED',
      attemptCount: 1,
      attemptLimit: 0,
      cancelRequested: true,
    });
    expect(delivered).not.toHaveProperty('notificationState');
    expect(delivered).not.toHaveProperty('acknowledged');
    expect(planNotificationDelivery(delivered, 100, 3000).action).toBe('TERMINAL');
    expect(() =>
      planNotificationObservation(delivered, observe(delivered, 'RETRYABLE_NO_EFFECT', 3000), 100),
    ).toThrow();
    const noEffect = planNotificationObservation(
      unknown,
      observe(unknown, 'RETRYABLE_NO_EFFECT', 2000),
      100,
    );
    expect(noEffect.state).toBe('CANCELLED');
  });

  it('permanent failure is terminal, with no new intent or retry', () => {
    const original = started();
    const failed = planNotificationObservation(
      original,
      observe(original, 'PERMANENT_FAILURE', 2000),
      10,
    );
    expect(failed).toMatchObject({ state: 'FAILED', attemptCount: 1, nextAttemptAtMs: null });
    expect(planNotificationDelivery(failed, 100, 99999999).action).toBe('TERMINAL');
  });

  it.each([
    { participantId: id(11) },
    { privacyDomainId: id(12) },
    { notificationOccurrenceId: id(13) },
    { payloadDigest: `sha256:${'cd'.repeat(32)}` },
    { attemptNumber: 2 },
    { startedAtMs: 999 },
    { observedAtMs: 999 },
    { outcome: 'TIMEOUT' },
    { acknowledged: true },
  ])('rejects substituted or unsupported observations: %j', (change) => {
    const original = started();
    expect(() =>
      planNotificationObservation(
        original,
        { ...observe(original, 'DELIVERED', 2000), ...change } as NotificationDeliveryObservation,
        10,
      ),
    ).toThrow();
  });

  it('rejects malformed persisted state, unsafe time arithmetic and invalid configuration', () => {
    for (const change of [
      { attemptCount: -1 },
      { attemptCount: 7 },
      { attemptLimit: 7 },
      { state: 'STARTED' },
      { nextAttemptAtMs: null },
      { lastStartedAtMs: 0 },
      { payloadDigest: 'invalid' },
      { notificationState: 'ACKNOWLEDGED' },
    ]) {
      expect(() =>
        planNotificationDelivery(
          { ...initial(), ...change } as NotificationDeliverySnapshot,
          10,
          1000,
        ),
      ).toThrow();
    }
    for (const value of [-1, 101, 1.5, NaN, Infinity])
      expect(() => planNotificationDelivery(initial(), value, 1000)).toThrow();
    for (const now of [-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1])
      expect(() => planNotificationDelivery(initial(), 10, now)).toThrow();
    const original = started();
    expect(() => planNotificationDelivery(original, 10, 999)).toThrow();
    expect(() =>
      planNotificationObservation(
        original,
        observe(original, 'RETRYABLE_NO_EFFECT', Number.MAX_SAFE_INTEGER),
        10,
      ),
    ).toThrow();
  });

  it('never mutates its caller-owned persisted snapshot when making a proposal', () => {
    const saved = Object.freeze(initial());
    const result = planNotificationDelivery(saved, 1, 1000);
    expect(saved).toMatchObject({ state: 'PENDING', attemptCount: 0, attemptLimit: 6 });
    const beforeObservation = Object.freeze(result.next);
    planNotificationObservation(
      beforeObservation,
      observe(beforeObservation, 'AMBIGUOUS', 1001),
      0,
    );
    expect(beforeObservation).toMatchObject({ state: 'STARTED', attemptLimit: 1 });
  });
});
