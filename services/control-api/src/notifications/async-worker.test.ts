import { Pool } from 'pg';
import { afterEach, expect, it } from 'vitest';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import { NotificationAsyncWorker } from './async-worker.js';
import type { NotificationDeliveryPeers } from './delivery-runtime.js';
const pools: Pool[] = [];
const digest = `sha256:${'a'.repeat(64)}`;
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const pool = new Pool({ max: 1 });
  pools.push(pool);
  const kernel = new IdentityKernel(new PostgresIdentityRepository(pool, systemClock));
  const bytes = Buffer.from('never-used-before-authenticated-peer');
  const worker = new NotificationAsyncWorker({
    pool,
    kernel,
    vaultDirectory: '/unopened-worker-test-vault',
    kmsTls: { ca: bytes, certificate: bytes, privateKey: bytes },
    signerTls: { trustCa: bytes, certificate: bytes, privateKey: bytes },
    signers: { start: digest, outcome: digest },
    cancellationSignerInstallationDigest: digest,
    credentialProvider: {
      async withExactVersion() {
        throw new Error('Not admitted');
      },
    },
  });
  const source = {
    worker: { participantId: id(1), privacyDomainId: id(2), installationDigest: digest },
    notificationOccurrenceId: id(3),
    eventId: id(4),
  };
  return { pool, worker, source };
}
afterEach(async () => {
  for (const pool of pools.splice(0)) await pool.end();
});
it('does not create a queue, connection or background polling loop on construction', async () => {
  const { worker, pool } = fixture();
  expect(pool.totalCount).toBe(0);
  const closing = worker.close();
  expect(worker.close()).toBe(closing);
  await closing;
  expect(pool.ended).toBe(false);
});
it('rejects caller readiness and lease widening before opening an owner transaction', async () => {
  const { worker, pool, source } = fixture();
  const peers = {} as NotificationDeliveryPeers;
  expect(() => worker.enqueue(peers, { ...source, ready: true })).toThrow();
  expect(() => worker.runOnce(peers, { ...source, concurrency: 99 })).toThrow();
  await expect(
    worker.cancelLeased(
      peers,
      { eventId: source.eventId, ownerId: 'process', epoch: '1', ready: true },
      { source, causeOperationId: id(5), expectedRevision: '1' },
    ),
  ).rejects.toThrow();
  expect(pool.totalCount).toBe(0);
  await worker.close();
});
it('cannot restart after close or acquire a new queue lease', async () => {
  const { worker, pool, source } = fixture();
  await worker.close();
  expect(() => worker.runOnce({} as NotificationDeliveryPeers, source)).toThrow();
  expect(() => worker.enqueue({} as NotificationDeliveryPeers, source)).toThrow();
  expect(pool.totalCount).toBe(0);
});
