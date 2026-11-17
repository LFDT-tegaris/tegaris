import { Pool } from 'pg';
import { TLSSocket } from 'node:tls';
import { Socket } from 'node:net';
import { afterEach, expect, it, vi } from 'vitest';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import { NotificationDeliveryRuntime, type NotificationDeliveryPeers } from './delivery-runtime.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const source = {
  worker: { participantId: id(1), privacyDomainId: id(2), installationDigest: digest },
  notificationOccurrenceId: id(3),
  eventId: id(4),
};
const pools: Pool[] = [];
const runtimes: NotificationDeliveryRuntime[] = [];
function setup() {
  const pool = new Pool({ max: 1 });
  pools.push(pool);
  const kernel = new IdentityKernel(new PostgresIdentityRepository(pool, systemClock));
  const bytes = Buffer.from('not-used-before-real-authority');
  const provider = {
    withExactVersion: vi.fn(async () => {
      throw new Error('Not admitted');
    }),
  };
  const runtime = new NotificationDeliveryRuntime({
    pool,
    kernel,
    credentialProvider: provider,
    vaultDirectory: '/unopened-test-vault',
    kmsTls: { ca: bytes, certificate: bytes, privateKey: bytes },
    signerTls: { trustCa: bytes, certificate: bytes, privateKey: bytes },
    signers: { start: digest, outcome: digest },
  });
  runtimes.push(runtime);
  return { runtime, pool, bytes, provider };
}
afterEach(async () => {
  for (const runtime of runtimes.splice(0)) await runtime.close();
  for (const pool of pools.splice(0)) await pool.end();
});
it('constructs only borrowed owners and reports missing canonical admission without readiness or connections', async () => {
  const { runtime, pool, bytes, provider } = setup();
  expect(runtime.packagingStatus).toEqual({
    state: 'UNWIRED',
    missing: ['CURRENT_ASYNC_CONSUMER_ADMISSION', 'CANONICAL_ROOT_INVOCATION'],
  });
  expect(pool.totalCount).toBe(0);
  expect(provider.withExactVersion).not.toHaveBeenCalled();
  const first = runtime.close();
  expect(runtime.close()).toBe(first);
  await first;
  expect(bytes.toString()).toBe('not-used-before-real-authority');
  expect(pool.ended).toBe(false);
});
it('refuses fabricated and unauthenticated actual TLS peers before any database/provider work', () => {
  const { runtime, pool, provider } = setup();
  const socket = new TLSSocket(new Socket());
  try {
    for (const peer of [{ authorized: true }, socket]) {
      const peers = { delivery: peer, recipient: peer } as NotificationDeliveryPeers;
      expect(() => runtime.start(peers, source)).toThrow('INPUT');
      expect(() => runtime.lookup(peers, { source })).toThrow('INPUT');
    }
    expect(pool.totalCount).toBe(0);
    expect(provider.withExactVersion).not.toHaveBeenCalled();
  } finally {
    socket.destroy();
  }
});
it.each(['ready', 'observation', 'signal', 'configuredLimit'])(
  'rejects caller %s and malformed original links before admission',
  (key) => {
    const { runtime, pool } = setup();
    const peers = {} as NotificationDeliveryPeers;
    expect(() => runtime.start(peers, { ...source, [key]: true })).toThrow();
    expect(() =>
      runtime.lookup(peers, {
        source,
        start: {
          source: { ...source, eventId: id(8) },
          operationId: id(5),
          signerInstallationDigest: digest,
        },
      }),
    ).toThrow();
    expect(pool.totalCount).toBe(0);
  },
);
it('closed is terminal and never erases borrowed TLS material or closes the borrowed pool', async () => {
  const { runtime, pool, bytes, provider } = setup();
  await runtime.close();
  expect(() => runtime.start({} as NotificationDeliveryPeers, source)).toThrow('CLOSED');
  expect(() => runtime.lookup({} as NotificationDeliveryPeers, { source })).toThrow('CLOSED');
  expect(pool.totalCount).toBe(0);
  expect(bytes.some((x) => x !== 0)).toBe(true);
  expect(provider.withExactVersion).not.toHaveBeenCalled();
});
