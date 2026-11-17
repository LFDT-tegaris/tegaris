import { expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  lowerNotificationDeliveryBudget,
  notificationDeliveryBudgetRecord,
  synchronizeNotificationDeliveryBudget,
  type NotificationDeliveryBudgetRecord,
} from './delivery-start-state.js';
import { planNotificationDelivery } from './delivery-policy.js';

// Component projections only; these values do not establish an effective
// generation, live worker/endpoint authority or PostgreSQL acceptance.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
const config = (limit: number) => ({
  generation_id: id(9),
  effective_digest: digest('9'),
  configured_limit: limit,
});
const original: NotificationDeliveryBudgetRecord = {
  participantId: id(1),
  privacyDomainId: id(2),
  notificationOccurrenceId: id(3),
  payloadDigest: digest('a'),
  state: 'PENDING',
  attemptCount: 0,
  attemptLimit: 6,
  nextAttemptAtMs: 1000,
  lastStartedAtMs: null,
  cancelRequested: false,
  revision: '1',
  deliveryRequestEventId: id(4),
  deliveryRequestOperationId: id(5),
  budgetEnvironmentId: 'local-notification',
  budgetGenerationId: id(6),
  budgetEffectiveDigest: digest('b'),
  budgetConfiguredLimit: 100,
  budgetWorkerInstallationDigest: digest('c'),
};

function policyProjection(p: NotificationDeliveryBudgetRecord) {
  const {
    participantId,
    privacyDomainId,
    notificationOccurrenceId,
    payloadDigest,
    state,
    attemptCount,
    attemptLimit,
    nextAttemptAtMs,
    lastStartedAtMs,
    cancelRequested,
  } = p;
  return {
    participantId,
    privacyDomainId,
    notificationOccurrenceId,
    payloadDigest,
    state,
    attemptCount,
    attemptLimit,
    nextAttemptAtMs,
    lastStartedAtMs,
    cancelRequested,
  };
}

it('lowers only the durable cap/revision/provenance without executing START or terminal policy proposals', () => {
  expect(planNotificationDelivery(policyProjection(original), 6, 1000).action).toBe('START');
  expect(planNotificationDelivery(policyProjection(original), 0, 1000).next.state).toBe('FAILED');
  for (const current of [0, 1, 5]) {
    const before = structuredClone(original);
    const next = lowerNotificationDeliveryBudget(before, config(current), digest('d'));
    expect(next).toEqual({
      ...before,
      attemptLimit: current,
      revision: '2',
      budgetGenerationId: id(9),
      budgetEffectiveDigest: digest('9'),
      budgetConfiguredLimit: current,
      budgetWorkerInstallationDigest: digest('d'),
    });
    expect(before).toEqual(original);
  }
  const cancelled = { ...original, cancelRequested: true };
  expect(planNotificationDelivery(policyProjection(cancelled), 0, 1000).next.state).toBe(
    'CANCELLED',
  );
  expect(lowerNotificationDeliveryBudget(cancelled, config(0), digest('d'))).toMatchObject({
    state: 'PENDING',
    cancelRequested: true,
    attemptCount: 0,
    nextAttemptAtMs: 1000,
    lastStartedAtMs: null,
  });
});

it('does not resurrect a lowered ceiling or write provenance/revision for equal or higher caps', () => {
  for (const limit of [0, 2, 6]) {
    const before = { ...original, attemptLimit: limit, budgetConfiguredLimit: limit };
    for (const current of [limit, 6, 100]) {
      const next = lowerNotificationDeliveryBudget(before, config(current), digest('d'));
      expect(next).toEqual(before);
      expect(next).not.toBe(before);
    }
    const low = lowerNotificationDeliveryBudget(before, config(0), digest('d'));
    expect(lowerNotificationDeliveryBudget(low, config(100), digest('e'))).toEqual(low);
  }
});

it('preserves original in-flight/terminal/cancel state and all attempt identities under cap decreases', () => {
  for (const state of [
    'STARTED',
    'AMBIGUOUS',
    'DELIVERED',
    'FAILED',
    'CANCELLED',
    'QUARANTINED',
    'RETRY_WAIT',
  ] as const) {
    const before = {
      ...original,
      state,
      attemptCount: 2,
      lastStartedAtMs: 1000,
      nextAttemptAtMs: state === 'RETRY_WAIT' ? 6000 : null,
      cancelRequested: true,
    };
    const lowered = lowerNotificationDeliveryBudget(before, config(0), digest('d'));
    expect(lowered).toEqual({
      ...before,
      attemptLimit: 0,
      revision: '2',
      budgetGenerationId: id(9),
      budgetEffectiveDigest: digest('9'),
      budgetConfiguredLimit: 0,
      budgetWorkerInstallationDigest: digest('d'),
    });
    if (state === 'STARTED' || state === 'AMBIGUOUS')
      expect(planNotificationDelivery(policyProjection(lowered), 100, 1000).action).toBe(
        'RECONCILE',
      );
  }
});

it('rejects corrupt projections, caller-shaped configuration and unsafe revision arithmetic', () => {
  for (const patch of [
    { revision: '0' },
    { revision: '01' },
    { attemptCount: 1 },
    { attemptLimit: 7 },
    { budgetConfiguredLimit: 0 },
    { budgetGenerationId: 'bad' },
    { budgetEffectiveDigest: 'bad' },
    { budgetWorkerInstallationDigest: 'bad' },
    { deliveryRequestEventId: 'bad' },
    { nextAttemptAtMs: NaN },
    { extra: true },
  ]) {
    expect(() =>
      lowerNotificationDeliveryBudget(
        { ...original, ...patch } as NotificationDeliveryBudgetRecord,
        config(0),
        digest('d'),
      ),
    ).toThrow('Notification delivery budget unavailable');
  }
  for (const patch of [
    { configured_limit: -1 },
    { configured_limit: 101 },
    { configured_limit: 0.5 },
    { configured_limit: NaN },
    { generation_id: id(0) + 'x' },
    { effective_digest: 'bad' },
    { ready: true },
  ]) {
    expect(() =>
      lowerNotificationDeliveryBudget(original, { ...config(0), ...patch }, digest('d')),
    ).toThrow('Notification delivery budget unavailable');
  }
  const maximum = { ...original, revision: '18446744073709551615' };
  expect(lowerNotificationDeliveryBudget(maximum, config(100), digest('d'))).toEqual(maximum);
  expect(() => lowerNotificationDeliveryBudget(maximum, config(0), digest('d'))).toThrow(
    'Notification delivery budget unavailable',
  );
  expect(
    lowerNotificationDeliveryBudget(
      { ...original, revision: '9007199254740993' },
      config(0),
      digest('d'),
    ).revision,
  ).toBe('9007199254740994');
  expect(() => lowerNotificationDeliveryBudget(original, config(0), 'bad')).toThrow(
    'Notification delivery budget unavailable',
  );
});

it('requires original source-only input before touching any database/TLS owner', async () => {
  const source = {
    worker: { participantId: id(1), privacyDomainId: id(2), installationDigest: digest('c') },
    notificationOccurrenceId: id(3),
    eventId: id(4),
  };
  for (const extra of [
    { configuredLimit: 6 },
    { configuration: config(6) },
    { generationId: id(9) },
    { ready: true },
    { admission: {} },
    { state: original },
    { attemptId: id(5) },
    { context: {} },
    { provider: {} },
  ]) {
    // No internal owner is mocked: parsing must reject before undefined deps
    // could be used; connected valid-input admission belongs to the PG corpus.
    let touched = false;
    const unreachable = new Proxy(
      {},
      {
        get() {
          touched = true;
          throw new Error('owner must not be reached');
        },
      },
    );
    await expect(
      synchronizeNotificationDeliveryBudget(
        unreachable as Pool,
        unreachable as IdentityKernel,
        unreachable as TLSSocket,
        { ...source, ...extra },
      ),
    ).rejects.toThrow('Notification delivery budget unavailable');
    expect(touched).toBe(false);
  }
});

it('returns detached records and rejects accessors without executing them', () => {
  const before = structuredClone(original);
  let accessed = false;
  Object.defineProperty(before, 'attemptLimit', {
    enumerable: true,
    get() {
      accessed = true;
      return 6;
    },
  });
  expect(() => lowerNotificationDeliveryBudget(before, config(0), digest('d'))).toThrow(
    'Notification delivery budget unavailable',
  );
  expect(accessed).toBe(false);
  expect(
    notificationDeliveryBudgetRecord.safeParse({ ...original, budgetConfiguredLimit: 0 }).success,
  ).toBe(false);
});
