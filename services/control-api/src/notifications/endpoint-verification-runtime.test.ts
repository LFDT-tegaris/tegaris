import { afterEach, expect, it, vi } from 'vitest';
import {
  createNotificationVerificationRuntime,
  type NotificationVerificationRuntimeOptions,
} from './endpoint-verification-runtime.js';

// Composition contracts only. No fixture callback establishes runtime authority.
const owners = vi.hoisted(() => ({
  pools: [] as { options: Record<string, unknown>; end: ReturnType<typeof vi.fn> }[],
  transport: vi.fn(),
  close: vi.fn(),
  listen: vi.fn(),
  borrow: vi.fn(),
  workflow: vi.fn(),
  state: vi.fn(),
  kernel: vi.fn(),
  repository: vi.fn(),
}));
vi.mock('pg', () => ({
  Pool: vi.fn(function (options: Record<string, unknown>) {
    const pool = { options, end: vi.fn().mockResolvedValue(undefined) };
    owners.pools.push(pool);
    return pool;
  }),
}));
vi.mock('../../../identity-service/src/domain/identity-kernel.js', () => ({
  IdentityKernel: vi.fn(function (...args: unknown[]) {
    owners.kernel(...args);
  }),
  PostgresIdentityRepository: vi.fn(function (...args: unknown[]) {
    owners.repository(...args);
  }),
  systemClock: { now: () => new Date() },
}));
vi.mock('../../../identity-service/src/domain/notification-workload-transport.js', () => ({
  NotificationWorkloadTransport: vi.fn(function (options: Record<string, unknown>) {
    owners.transport(options);
    return { listen: owners.listen, close: owners.close, withPeer: owners.borrow };
  }),
}));
vi.mock('./endpoint-verification-workflow.js', () => ({
  NotificationEndpointVerificationWorkflow: vi.fn(function (options: Record<string, unknown>) {
    owners.workflow(options);
  }),
}));
vi.mock('./endpoint-verification-state.js', () => ({
  NotificationEndpointVerificationState: vi.fn(function (...args: unknown[]) {
    owners.state(...args);
  }),
}));
function input() {
  return {
    database: { host: 'test-only', max: 99, statement_timeout: 0 },
    tls: {
      ca: Buffer.from('test'),
      certificate: Buffer.from('test'),
      privateKey: Buffer.from('test'),
    },
    identityRuntimeVerifier: { verifyCanonicalAssertion: vi.fn() },
    businessEvidence: { environmentId: 'test', signer: { sign: vi.fn() } },
    credentialProvider: { withExactVersion: vi.fn() },
  } as unknown as NotificationVerificationRuntimeOptions;
}
afterEach(() => {
  for (const value of Object.values(owners)) if (typeof value === 'function') value.mockReset();
  owners.pools.length = 0;
});
it('uses distinct capped pools and existing Identity/recipient/workflow owners without opening listeners', async () => {
  owners.close.mockResolvedValue(undefined);
  const options = input(),
    root = createNotificationVerificationRuntime(options);
  expect(owners.pools.map((pool) => pool.options)).toEqual([
    expect.objectContaining({
      max: 2,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 30000,
    }),
    expect.objectContaining({ max: 1, connectionTimeoutMillis: 5000, statement_timeout: 5000 }),
  ]);
  expect(owners.repository).toHaveBeenCalledWith(owners.pools[1], expect.anything());
  expect(owners.workflow).toHaveBeenCalledWith(
    expect.objectContaining({
      pool: owners.pools[0],
      recipientPool: owners.pools[1],
      credentialProvider: options.credentialProvider,
      timeoutMs: 10000,
    }),
  );
  expect(owners.listen).not.toHaveBeenCalled();
  expect(options.credentialProvider.withExactVersion).not.toHaveBeenCalled();
  await root.close();
  expect(owners.close).toHaveBeenCalledTimes(1);
  for (const pool of owners.pools) expect(pool.end).toHaveBeenCalledTimes(1);
});
it('leaves physical-provider eligibility with its owner and never restores it during start or close', async () => {
  owners.close.mockResolvedValue(undefined);
  owners.listen.mockResolvedValue({ host: '127.0.0.1', port: 1234 });
  const options = input(),
    root = createNotificationVerificationRuntime(options);
  expect(await root.start({ host: '127.0.0.1', port: 1234 })).toEqual({
    host: '127.0.0.1',
    port: 1234,
  });
  await Promise.all([root.close(), root.close()]);
  expect(owners.close).toHaveBeenCalledTimes(1);
  expect(options.credentialProvider.withExactVersion).not.toHaveBeenCalled();
});
it('closes both pools after transport cleanup failure and preserves a safe failure', async () => {
  owners.close.mockRejectedValue(new Error('private input diagnostic'));
  const root = createNotificationVerificationRuntime(input());
  await expect(root.close()).rejects.toThrow('Notification runtime cleanup failed');
  for (const pool of owners.pools) expect(pool.end).toHaveBeenCalledTimes(1);
});
it('closes rejected constructor resources instead of retaining a partial runtime', async () => {
  owners.close.mockResolvedValue(undefined);
  owners.workflow.mockImplementation(() => {
    throw new Error('invalid workflow');
  });
  expect(() => createNotificationVerificationRuntime(input())).toThrow('invalid workflow');
  expect(owners.close).toHaveBeenCalledTimes(1);
  for (const pool of owners.pools) expect(pool.end).toHaveBeenCalledTimes(1);
});
it('uses the transport owner for connected preflight without a secret export or business mutation', async () => {
  owners.close.mockResolvedValue(undefined);
  owners.borrow.mockRejectedValue(new Error('no authenticated peer'));
  const options = input(),
    root = createNotificationVerificationRuntime(options);
  await expect(root.preflight({} as never)).rejects.toThrow('no authenticated peer');
  expect(options.credentialProvider.withExactVersion).not.toHaveBeenCalled();
  await root.close();
});
it('closes resources when metadata-owner construction rejects the runtime inputs', () => {
  owners.close.mockResolvedValue(undefined);
  owners.state.mockImplementation(() => {
    throw new Error('invalid metadata owner');
  });
  expect(() => createNotificationVerificationRuntime(input())).toThrow('invalid metadata owner');
  expect(owners.close).toHaveBeenCalledTimes(1);
  for (const pool of owners.pools) expect(pool.end).toHaveBeenCalledTimes(1);
});
