import { expect, it } from 'vitest';
import { Pool } from 'pg';
import { Socket } from 'node:net';
import { TLSSocket } from 'node:tls';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import type { NotificationAsyncInputClaims } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  assertNotificationConsumerCapacity,
  discoverNotificationDeliverySources,
} from './delivery-source-discovery.js';
const digest = `sha256:${'a'.repeat(64)}`;
const id = '01900000-0000-7000-8000-000000000001';
// Pure declared-input corpus. These bytes are never installed as qualification.
const input: NotificationAsyncInputClaims = {
  authorityId: 'local',
  environmentId: 'test',
  profile: 'test',
  participantId: id,
  privacyDomainId: id,
  task: 'ASYNC-NOTIFICATION',
  generationId: id,
  configurationDigest: digest,
  configurationSchemaDigest: digest,
  namedProfileDigest: digest,
  buildDigest: digest,
  sourceTreeDigest: digest,
  workloadIdentityDigest: digest,
  environmentIdentityDigest: digest,
  storeProfileDigest: digest,
  gatewayProfileDigest: digest,
  ratePolicyDigest: digest,
  inputId: id,
  slot: 'QINPUT-ASYNC-NOTIFICATION',
  concurrency: 2,
  batchSize: 2,
  leaseMs: 10000,
  heartbeatMs: 1000,
  attemptTimeoutMs: 1000,
  retryDelaysMs: [5000, 30000, 120000, 600000, 1800000],
  domainDeadlineMs: 3000000,
  queueItems: 8,
  queueBytes: 8000,
  maximumQueueAgeMs: 4000000,
  maximumPayloadBytes: 1000,
  dispatchRatePerSecond: 2,
  issuerKeyId: digest,
  issuerEpoch: '1',
  validFromMs: 1000,
  validUntilMs: 6001000,
};

const ceiling = {
  poolMax: 12,
  maximumConcurrency: 2,
  maximumBatchSize: 2,
  cycleTimeoutMs: 15000,
  connectionLifetimeMs: 60000,
};
it('checks the actual finite pool and transport envelope without changing signed work bounds', () => {
  const before = structuredClone(input);
  expect(assertNotificationConsumerCapacity(ceiling, input)).toEqual(ceiling);
  expect(input).toEqual(before);
});
it.each([
  { poolMax: 11 },
  { maximumConcurrency: 1 },
  { maximumBatchSize: 1 },
  { cycleTimeoutMs: 5000 },
  { connectionLifetimeMs: 20000 },
])('rejects incompatible actual ceilings %j', (change) => {
  expect(() => assertNotificationConsumerCapacity({ ...ceiling, ...change }, input)).toThrow();
});
it('rejects caller ready flags and an invalid signed retry schedule', () => {
  expect(() => assertNotificationConsumerCapacity({ ...ceiling, ready: true }, input)).toThrow();
  expect(() =>
    assertNotificationConsumerCapacity(ceiling, { ...input, retryDelaysMs: [0, 0, 0, 0, 0] }),
  ).toThrow();
});
it('requires a real authenticated peer before querying candidates or native authority', async () => {
  const pool = new Pool({ max: 1 });
  const kernel = new IdentityKernel(new PostgresIdentityRepository(pool, systemClock));
  const socket = new TLSSocket(new Socket());
  try {
    await expect(
      discoverNotificationDeliverySources(
        pool,
        kernel,
        socket,
        { participantId: id, privacyDomainId: id, installationDigest: digest },
        ceiling,
      ),
    ).rejects.toThrow();
    expect(pool.totalCount).toBe(0);
  } finally {
    socket.destroy();
    await pool.end();
  }
});
