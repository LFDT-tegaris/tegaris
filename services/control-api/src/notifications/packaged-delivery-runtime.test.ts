import { Pool } from 'pg';
import { beforeAll, afterAll, expect, it } from 'vitest';
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';
import {
  loadPackagedNotificationDeliveryRuntime,
  loadPackagedNotificationDeliveryConsumer,
} from './packaged-delivery-runtime.js';
import type { NotificationDeliveryPeers } from './delivery-runtime.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
let root: string, tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
const pool = new Pool({ max: 1 }),
  kernel = new IdentityKernel(new PostgresIdentityRepository(pool, systemClock));
beforeAll(async () => {
  root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'notification-delivery-package-'));
  tls = await runtimeSnapshotTlsFixture(`urn:openpc:participant:${id(1)}:workload:${id(3)}`);
  for (const [name, data] of Object.entries({
    'ca.pem': tls.server.ca,
    'client.pem': tls.certificate,
    'client.key': tls.privateKey,
  }))
    await writeFile(join(root, name), data, { mode: 0o600 });
});
afterAll(async () => {
  await pool.end();
  await tls?.close();
  if (root) await rm(root, { recursive: true, force: true });
});
function config() {
  const files = {
    caFile: join(root, 'ca.pem'),
    certificateFile: join(root, 'client.pem'),
    privateKeyFile: join(root, 'client.key'),
  };
  return {
    version: 1,
    worker: { participantId: id(1), privacyDomainId: id(2), installationDigest: digest },
    vaultDirectory: root,
    kmsTls: files,
    signerTls: files,
    signers: { start: digest, outcome: digest },
    timeoutMs: 1000,
    providers: [
      {
        credential: {
          participantId: id(1),
          privacyDomainId: id(2),
          credentialRef: `urn:openpc:resource:${id(10)}`,
          destinationRef: `urn:openpc:resource:${id(11)}`,
          channel: 'WEBHOOK',
          owner: 'LS-NOTIFICATION',
          secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
          reference: 'secret://local/notification#1',
          version: '1',
          epoch: '1',
          fingerprint: digest,
          validFromMs: Date.now() - 1000,
          validUntilMs: Date.now() + 60000,
          state: 'ACTIVE',
        },
        address: '127.0.0.1',
        port: 3449,
        serverName: 'notification-provider',
        serverSpkiDigest: digest,
        tls: files,
      },
    ],
  };
}
let sequence = 0;
async function load(value: unknown) {
  const file = join(root, `config-${sequence++}.json`);
  await writeFile(file, JSON.stringify(value), { mode: 0o600 });
  return loadPackagedNotificationDeliveryRuntime(file, { pool, kernel });
}
it('loads actual PEMs/strict mounts with real clients but neither connects nor starts a worker', async () => {
  expect(
    await loadPackagedNotificationDeliveryRuntime(undefined, { pool, kernel }),
  ).toBeUndefined();
  const loaded = (await load(config()))!;
  try {
    expect(loaded.packagingStatus.state).toBe('UNWIRED');
    expect(pool.totalCount).toBe(0);
    expect(() =>
      loaded.start({} as NotificationDeliveryPeers, {
        worker: { ...config().worker, privacyDomainId: id(99) },
        notificationOccurrenceId: id(4),
        eventId: id(5),
      }),
    ).toThrow();
  } finally {
    const first = loaded.close();
    expect(loaded.close()).toBe(first);
    await first;
  }
  expect(pool.ended).toBe(false);
  expect(pool.totalCount).toBe(0);
  expect(() =>
    loaded.lookup({} as NotificationDeliveryPeers, {
      source: { worker: config().worker, notificationOccurrenceId: id(4), eventId: id(5) },
    }),
  ).toThrow();
});
it.each(['ready', 'listen', 'observation', 'concurrency', 'leaseMs'])(
  'rejects injected %s instead of inventing authority/capacity/listener configuration',
  async (key) => {
    await expect(load({ ...config(), [key]: true })).rejects.toThrow('package unavailable');
    expect(pool.totalCount).toBe(0);
  },
);
it('rejects duplicate recipients, foreign scope and an omitted transport budget', async () => {
  const duplicate = config();
  duplicate.providers.push(duplicate.providers[0]!);
  await expect(load(duplicate)).rejects.toThrow();
  const foreign = config();
  foreign.providers[0]!.credential.privacyDomainId = id(8);
  await expect(load(foreign)).rejects.toThrow();
  const missing = { ...config(), timeoutMs: undefined };
  await expect(load(missing)).rejects.toThrow();
  expect(pool.totalCount).toBe(0);
});
it('rejects symlink/noncanonical mounts, duplicate JSON fields and a later malformed TLS file with no connection', async () => {
  const linked = join(root, 'linked.pem');
  await symlink(join(root, 'client.pem'), linked);
  const c = config();
  c.signerTls = { ...c.signerTls, certificateFile: linked };
  await expect(load(c)).rejects.toThrow();
  const malformed = join(root, 'malformed.pem');
  await writeFile(malformed, 'not a certificate');
  const next = config();
  next.providers[0]!.tls = { ...next.providers[0]!.tls, certificateFile: malformed };
  await expect(load(next)).rejects.toThrow();
  const file = join(root, 'duplicate.json');
  await writeFile(file, '{"version":1,"version":1}');
  await expect(loadPackagedNotificationDeliveryRuntime(file, { pool, kernel })).rejects.toThrow();
  expect(pool.totalCount).toBe(0);
});

it('a manual v1 mount cannot silently start the serving consumer', async () => {
  const file = join(root, 'manual-is-not-serving.json');
  await writeFile(file, JSON.stringify(config()), { mode: 0o600 });
  await expect(loadPackagedNotificationDeliveryConsumer(file, { database: {} })).rejects.toThrow();
  expect(pool.totalCount).toBe(0);
});
