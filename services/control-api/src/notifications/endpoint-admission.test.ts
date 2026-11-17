import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { MutationContext } from '../configuration/persistence/types.js';
import {
  installInitialNotificationChannel,
  acquireNotificationInstallationFence,
  lockNotificationInstallation,
  notificationRequestAuthorityDigest,
  type NotificationChannelInstallation,
} from './endpoint-admission.js';

// Fault doubles exercise the exported lifecycle owner only. They establish no
// real Identity, SQL, fencing or business acceptance; that remains in the PG journey.
const lifecycle = vi.hoisted(() => ({
  createPool: vi.fn(),
  fenceAuthority: vi.fn(),
  verifyAuthorization: vi.fn(),
}));
vi.mock('pg', async (importOriginal) => ({
  ...(await importOriginal<typeof import('pg')>()),
  Pool: vi.fn(function (options: unknown) {
    return lifecycle.createPool(options);
  }),
}));
vi.mock('../configuration/persistence/authority-fence.js', () => ({
  fenceConfigurationMutation: lifecycle.fenceAuthority,
}));
vi.mock('../configuration/persistence/runtime-authorization.js', () => ({
  verifyConfigurationRuntimeAuthorization: lifecycle.verifyAuthorization,
}));
afterEach(() => {
  vi.restoreAllMocks();
  lifecycle.createPool.mockReset();
  lifecycle.fenceAuthority.mockReset();
  lifecycle.verifyAuthorization.mockReset();
});

function installationFenceFaults() {
  const source = Object.assign(new EventEmitter(), {
    query: vi.fn(async (sql: string) => {
      if (sql.includes('from pg_roles')) return { rows: [{ allowed: true }], rowCount: 1 };
      if (sql.includes('pg_try_advisory_xact_lock_shared'))
        return { rows: [{ acquired: true }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }),
    release: vi.fn(),
  });
  const business = Object.assign(new EventEmitter(), {
    end: vi.fn(async () => {}),
    connect: vi.fn(async () => {
      throw new Error('Lifecycle fault test must not execute or replay a business mutation');
    }),
  });
  const connect = vi.fn(async () => source);
  const options = { max: 1 };
  lifecycle.createPool.mockReturnValue(business);
  lifecycle.fenceAuthority.mockResolvedValue(undefined);
  lifecycle.verifyAuthorization.mockResolvedValue(undefined);
  const context = {
    authorization: {
      participantId: '01900000-0000-7000-8000-000000000001',
      privacyDomainId: '01900000-0000-7000-8000-000000000002',
      evidenceKind: 'IDENTITY_RUNTIME',
    },
    actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_COLLECTION-V1',
    candidate: {},
  } as unknown as MutationContext;
  const acquire = () =>
    acquireNotificationInstallationFence(
      { connect, options } as unknown as Pool,
      context,
      {} as IdentityRuntimeVerifier,
    );
  const statementCount = (sql: string) =>
    source.query.mock.calls.filter(([statement]) => statement === sql).length;
  const assertNoRetryOrBusiness = () => {
    expect(connect).toHaveBeenCalledTimes(1);
    expect(business.connect).not.toHaveBeenCalled();
    expect(lifecycle.createPool.mock.calls.length).toBeLessThanOrEqual(1);
    expect(statementCount('begin isolation level read committed')).toBe(1);
    expect(statementCount('commit')).toBe(0);
  };
  return { source, business, acquire, statementCount, assertNoRetryOrBusiness };
}

it('rejects initial registration without the actual installer role before processing trust or writing', async () => {
  const query = vi.fn(async (sql: string) => {
    expect(sql).toContain('pg_has_role');
    return { rows: [{ allowed: false }], rowCount: 1 };
  });
  await expect(
    installInitialNotificationChannel(
      { query } as unknown as PoolClient,
      {} as NotificationChannelInstallation,
    ),
  ).rejects.toThrow('PC-DATA-6007');
  expect(query).toHaveBeenCalledTimes(1);
  expect(query.mock.calls[0]?.[0]).toContain('pg_has_role');
});
it('keeps replacement admission bound to the original actor, session and every authority epoch', () => {
  const context = {
    authorization: {
      participantId: 'p',
      privacyDomainId: 'd',
      principalId: 'a',
      sessionId: 's',
      sessionEpoch: '1',
      participantEpoch: '2',
      principalEpoch: '3',
      assignmentId: 'r',
      assignmentEpoch: '4',
      authorityEnvelopeId: 'e',
      authorityEpoch: '5',
      delegationEpoch: '6',
    },
  } as unknown as MutationContext;
  const original = notificationRequestAuthorityDigest(context);
  for (const field of Object.keys(context.authorization)) {
    expect(
      notificationRequestAuthorityDigest({
        ...context,
        authorization: { ...context.authorization, [field]: 'changed' },
      }),
    ).not.toBe(original);
  }
  // A newly authenticated proof does not rewrite the immutable dependency binding.
  expect(
    notificationRequestAuthorityDigest({
      ...context,
      sessionToken: 'new-authentication',
      idempotencyKey: 'another-key',
    }),
  ).toBe(original);
});

it('uses the same nonblocking scoped installation fence for readers and writers and fails closed on contention', async () => {
  const scope = {
    participantId: '01900000-0000-7000-8000-000000000001',
    privacyDomainId: '01900000-0000-7000-8000-000000000002',
  };
  const query = vi.fn(async () => ({ rows: [{ acquired: false }], rowCount: 1 }));
  for (const exclusive of [false, true]) {
    await expect(
      lockNotificationInstallation({ query } as unknown as PoolClient, scope, exclusive),
    ).rejects.toThrow('PC-DATA-6007');
    const [sql, values] = query.mock.calls.at(-1)! as unknown as [string, unknown[]];
    expect(sql).toContain(
      exclusive ? 'pg_try_advisory_xact_lock(' : 'pg_try_advisory_xact_lock_shared(',
    );
    expect(sql).toContain('notification-installation:');
    expect(values).toEqual([scope.participantId, scope.privacyDomainId]);
  }
});

it('a timed-out source checkout cannot later acquire authority or retain a pool slot', async () => {
  vi.useFakeTimers();
  try {
    let deliver!: (client: PoolClient) => void;
    const connect = vi.fn(
      () =>
        new Promise<PoolClient>((resolve) => {
          deliver = resolve;
        }),
    );
    const release = vi.fn();
    const query = vi.fn();
    const outcome = acquireNotificationInstallationFence(
      { connect } as unknown as Pool,
      {} as MutationContext,
      {} as IdentityRuntimeVerifier,
    ).then(
      () => undefined,
      (error) => error,
    );
    await vi.advanceTimersByTimeAsync(5001);
    expect(await outcome).toMatchObject({ code: 'PC-DATA-6007' });
    deliver({ release, query } as unknown as PoolClient);
    await Promise.resolve();
    await Promise.resolve();
    expect(release).toHaveBeenCalledExactlyOnceWith(true);
    expect(query).not.toHaveBeenCalled();
    expect(connect).toHaveBeenCalledTimes(1);
    expect(lifecycle.createPool).not.toHaveBeenCalled();
  } finally {
    vi.useRealTimers();
  }
});

it.each(['before', 'during'] as const)(
  'denies final revalidation when the retained source emits an error %s its liveness query',
  async (when) => {
    const h = installationFenceFaults();
    const fence = await h.acquire();
    const queriesBefore = h.source.query.mock.calls.length;
    const lost = new Error('source connection lost');
    if (when === 'before') h.source.emit('error', lost);
    else
      h.source.query.mockImplementationOnce(async () => {
        h.source.emit('error', lost);
        return { rows: [], rowCount: 0 };
      });
    await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
    expect(h.source.query.mock.calls.length).toBe(queriesBefore + (when === 'during' ? 1 : 0));
    // Loss is sticky even if a subsequent SQL call could succeed.
    await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
    await fence.release();
    expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
    expect(h.source.listenerCount('error')).toBe(0);
    h.assertNoRetryOrBusiness();
  },
);

it('propagates a lost-source-transaction query failure without reacquiring or replaying', async () => {
  const h = installationFenceFaults();
  const fence = await h.acquire();
  const lost = Object.freeze(
    Object.assign(new Error('source transaction lost'), { code: '25P02' }),
  );
  h.source.query.mockRejectedValueOnce(lost);
  await expect(fence.revalidate()).rejects.toBe(lost);
  await fence.release();
  expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
  expect(h.statementCount('rollback')).toBe(1);
  h.assertNoRetryOrBusiness();
});

it('denies the exact 20-second observation deadline without renewing it on successful revalidation', async () => {
  const now = vi.spyOn(performance, 'now').mockReturnValue(1000);
  const h = installationFenceFaults();
  const fence = await h.acquire();
  now.mockReturnValue(20999);
  await fence.revalidate();
  const queriesBefore = h.source.query.mock.calls.length;
  now.mockReturnValue(21000);
  await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
  expect(h.source.query).toHaveBeenCalledTimes(queriesBefore);
  await fence.release();
  h.assertNoRetryOrBusiness();
});

it('denies a liveness query that returns after the observation deadline', async () => {
  const now = vi.spyOn(performance, 'now').mockReturnValue(1000);
  const h = installationFenceFaults();
  const fence = await h.acquire();
  h.source.query.mockImplementationOnce(async () => {
    now.mockReturnValue(21000);
    return { rows: [], rowCount: 0 };
  });
  await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
  await fence.release();
  h.assertNoRetryOrBusiness();
});

it('shares one in-progress release and closes admission before business-pool shutdown completes', async () => {
  const h = installationFenceFaults();
  const fence = await h.acquire();
  let finish!: () => void;
  h.business.end.mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  const first = fence.release();
  expect(fence.release()).toBe(first);
  await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
  expect(h.statementCount('rollback')).toBe(0);
  finish();
  await first;
  expect(fence.release()).toBe(first);
  await fence.release();
  expect(h.business.end).toHaveBeenCalledTimes(1);
  expect(h.statementCount('rollback')).toBe(1);
  expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
  h.assertNoRetryOrBusiness();
});

it.each(['rollback', 'source-release', 'business-shutdown', 'both-shutdown-and-rollback'] as const)(
  'retains cleanup uncertainty for %s and never retries cleanup or reports success',
  async (fault) => {
    const h = installationFenceFaults();
    const fence = await h.acquire();
    const failure = Object.freeze(new Error('injected cleanup failure'));
    if (fault === 'rollback' || fault === 'both-shutdown-and-rollback')
      h.source.query.mockRejectedValueOnce(failure);
    if (fault === 'business-shutdown' || fault === 'both-shutdown-and-rollback')
      h.business.end.mockRejectedValueOnce(failure);
    if (fault === 'source-release')
      h.source.release.mockImplementationOnce(() => {
        throw failure;
      });
    const first = fence.release();
    expect(fence.release()).toBe(first);
    await expect(first).rejects.toMatchObject({
      code: 'PC-OPS-9002',
      diagnosticBoundary: 'notification-installation-fence-cleanup-unknown',
    });
    await expect(fence.release()).rejects.toMatchObject({ code: 'PC-OPS-9002' });
    await expect(fence.revalidate()).rejects.toMatchObject({ code: 'PC-DATA-6007' });
    expect(h.business.end).toHaveBeenCalledTimes(1);
    expect(h.statementCount('rollback')).toBe(1);
    expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
    h.assertNoRetryOrBusiness();
  },
);

const originalFaults = [
  ['undefined', undefined],
  ['frozen error', Object.freeze(new Error('original frozen admission failure'))],
] as const;

it.each(originalFaults)(
  'preserves an original %s failure exactly when admission cleanup succeeds',
  async (_label, original) => {
    const h = installationFenceFaults();
    lifecycle.verifyAuthorization.mockRejectedValueOnce(original);
    const outcome = await Promise.allSettled([h.acquire()]);
    expect(outcome).toHaveLength(1);
    expect(outcome[0]?.status).toBe('rejected');
    if (outcome[0]?.status !== 'rejected') throw new Error('Admission unexpectedly succeeded');
    expect(outcome[0].reason).toBe(original);
    expect(lifecycle.createPool).not.toHaveBeenCalled();
    expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
    expect(h.statementCount('rollback')).toBe(1);
    h.assertNoRetryOrBusiness();
  },
);

it.each(originalFaults)(
  'preserves an original %s failure alongside every cleanup uncertainty',
  async (_label, original) => {
    const h = installationFenceFaults();
    // The initial liveness query fails after the business pool exists, so this
    // traverses actual acquisition cleanup rather than a separate mock owner.
    const ordinaryQuery = h.source.query.getMockImplementation()!;
    h.source.query.mockImplementation(async (sql) => {
      if (sql === 'select 1') throw original;
      if (sql === 'rollback') throw new Error('injected rollback failure');
      return ordinaryQuery(sql);
    });
    h.business.end.mockRejectedValueOnce(new Error('injected business shutdown failure'));
    h.source.release.mockImplementationOnce(() => {
      throw new Error('injected source release failure');
    });
    const [outcome] = await Promise.allSettled([h.acquire()]);
    expect(outcome?.status).toBe('rejected');
    if (outcome?.status !== 'rejected') throw new Error('Admission unexpectedly succeeded');
    expect(outcome.reason).toBeInstanceOf(AggregateError);
    const errors = (outcome.reason as AggregateError).errors;
    expect(errors).toHaveLength(2);
    expect(errors[0]).toBe(original);
    expect(errors[1]).toMatchObject({
      code: 'PC-OPS-9002',
      diagnosticBoundary: 'notification-installation-fence-cleanup-unknown',
    });
    expect(h.business.end).toHaveBeenCalledTimes(1);
    expect(h.statementCount('rollback')).toBe(1);
    expect(h.source.release).toHaveBeenCalledExactlyOnceWith(true);
    h.assertNoRetryOrBusiness();
  },
);
