import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { beforeEach, expect, it, vi } from 'vitest';
import { NotificationOccurrenceRuntime } from './occurrence-runtime.js';
const h = vi.hoisted(() => ({
  query: vi.fn(),
  peer: vi.fn(),
  state: vi.fn(),
  events: [] as string[],
}));
vi.mock('../../../identity-service/src/domain/notification-worker.js', () => ({
  withNotificationWorkerPeer: h.peer,
}));
vi.mock('./occurrence-state.js', () => ({
  prepareNotificationOccurrence: h.state,
  dispatchNotificationOccurrence: h.state,
  markNotificationOccurrenceUnknown: h.state,
  observeNotificationOccurrence: h.state,
  readNotificationOccurrence: h.state,
  readNotificationOccurrencePublication: h.state,
  publishNotificationOccurrence: h.state,
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const selector = {
  worker: {
    participantId: id(1),
    privacyDomainId: id(2),
    installationDigest: 'sha256:' + 'aa'.repeat(32),
  },
  preparationId: id(3),
};
const pool = {} as Pool,
  kernel = {} as IdentityKernel,
  socket = {} as TLSSocket;
beforeEach(() => {
  h.events.length = 0;
  h.query.mockReset();
  h.peer.mockReset();
  h.state.mockReset();
  h.query.mockImplementation(async (sql: string) => {
    h.events.push(
      sql.includes('pg_advisory')
        ? 'lifecycle'
        : sql.includes('ACT-EVIDENCE')
          ? 'export-context'
          : 'worker-context',
    );
    return { rows: [], rowCount: 0 };
  });
  h.peer.mockImplementation(
    async (
      _pool: unknown,
      _kernel: unknown,
      _socket: unknown,
      _selector: unknown,
      operation: (client: unknown, admission: unknown) => Promise<unknown>,
    ) => {
      h.events.push('peer');
      const result = await operation({ query: h.query }, {});
      h.events.push('final-authority-and-commit');
      return result;
    },
  );
  h.state.mockImplementation(async () => {
    h.events.push('state');
    return { state: 'DISPATCHED' };
  });
});
// Composition tests only. The doubles do not establish TLS, SQL or authority;
// real owners are exercised by notification-occurrence-cases in the PG journey.
it('returns dispatch only after lifecycle scope, state write, restored action and outer commit', async () => {
  const runtime = new NotificationOccurrenceRuntime(pool, kernel);
  expect(await runtime.dispatch(socket, selector)).toEqual({ state: 'DISPATCHED' });
  expect(h.events).toEqual([
    'peer',
    'export-context',
    'lifecycle',
    'state',
    'worker-context',
    'final-authority-and-commit',
  ]);
  expect(h.peer.mock.calls[0]!.slice(0, 4)).toEqual([pool, kernel, socket, selector.worker]);
});
it('never enters Identity with injected authority fields', async () => {
  const runtime = new NotificationOccurrenceRuntime(pool, kernel);
  await expect(runtime.dispatch(socket, { ...selector, ready: true })).rejects.toThrow('INVALID');
  await expect(
    runtime.observe(socket, { ...selector, coseHex: '00', admitted: true }),
  ).rejects.toThrow('INVALID');
  expect(h.peer).not.toHaveBeenCalled();
});
it('preserves UNKNOWN on post-state commit loss and never retries the transaction', async () => {
  h.peer.mockImplementation(
    async (
      _p: unknown,
      _k: unknown,
      _s: unknown,
      _q: unknown,
      operation: (client: unknown, admission: unknown) => Promise<unknown>,
    ) => {
      await operation({ query: h.query }, {});
      throw new Error('private commit canary');
    },
  );
  await expect(
    new NotificationOccurrenceRuntime(pool, kernel).dispatch(socket, selector),
  ).rejects.toThrow('Notification occurrence UNKNOWN');
  expect(h.peer).toHaveBeenCalledTimes(1);
  expect(h.state).toHaveBeenCalledTimes(1);
});
it('does not run state after actual peer owner rejects', async () => {
  h.peer.mockRejectedValue(new Error('private peer canary'));
  await expect(
    new NotificationOccurrenceRuntime(pool, kernel).readOriginal(socket, selector),
  ).rejects.toThrow('UNAVAILABLE');
  expect(h.state).not.toHaveBeenCalled();
  expect(h.query).not.toHaveBeenCalled();
});
it('passes exact copied observation bytes, never a provider success flag', async () => {
  const coseHex = 'ab'.repeat(65);
  await new NotificationOccurrenceRuntime(pool, kernel).observe(socket, { ...selector, coseHex });
  expect(h.state.mock.calls[0]![2]).toEqual(selector);
  expect(h.state.mock.calls[0]![3]).toEqual(Buffer.from(coseHex, 'hex'));
});
it('propagates a failed state without restoring context or committing it', async () => {
  h.state.mockRejectedValue(new Error('private SQL canary'));
  await expect(
    new NotificationOccurrenceRuntime(pool, kernel).markUnknown(socket, selector),
  ).rejects.toThrow('UNKNOWN');
  expect(h.events).toEqual(['peer', 'export-context', 'lifecycle']);
});

it('keeps publication unavailable without trusted vault configuration', async () => {
  await expect(
    new NotificationOccurrenceRuntime(pool, kernel).publish(socket, selector),
  ).rejects.toThrow('UNAVAILABLE');
  expect(h.peer).not.toHaveBeenCalled();
});
it('publishes inside the actual peer transaction and returns only after commit', async () => {
  h.state.mockResolvedValue({ state: 'PUBLISHED' });
  expect(
    await new NotificationOccurrenceRuntime(pool, kernel, '/trusted/fixture-vault').publish(
      socket,
      selector,
    ),
  ).toEqual({ state: 'PUBLISHED' });
  expect(h.state.mock.calls[0]![3]).toHaveProperty('withCurrent');
  expect(h.events.at(-1)).toBe('final-authority-and-commit');
});
it('allows historical publication reconciliation without a key configuration or another write', async () => {
  h.state.mockResolvedValue({ state: 'PUBLISHED' });
  expect(
    await new NotificationOccurrenceRuntime(pool, kernel).readPublication(socket, selector),
  ).toEqual({ state: 'PUBLISHED' });
  expect(h.state.mock.calls[0]).toHaveLength(3);
});
it('returns UNKNOWN for a publication commit loss without retry or signing', async () => {
  h.peer.mockImplementation(
    async (
      _p: unknown,
      _k: unknown,
      _s: unknown,
      _q: unknown,
      operation: (client: unknown, admission: unknown) => Promise<unknown>,
    ) => {
      await operation({ query: h.query }, {});
      throw new Error('lost publication acknowledgement');
    },
  );
  await expect(
    new NotificationOccurrenceRuntime(pool, kernel, '/trusted/fixture-vault').publish(
      socket,
      selector,
    ),
  ).rejects.toThrow('UNKNOWN');
  expect(h.state).toHaveBeenCalledTimes(1);
  expect(h.peer).toHaveBeenCalledTimes(1);
});
