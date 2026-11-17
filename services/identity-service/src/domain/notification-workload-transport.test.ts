import { connect, type TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import type { IdentityKernel } from './identity-kernel.js';
import { NotificationWorkloadTransport } from './notification-workload-transport.js';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';

// Real TLS handshakes, mocked SQL/Identity boundaries: connection ownership and
// cleanup contracts only. The existing PostgreSQL journey owns full admission.
const owners = vi.hoisted(() => ({ authenticate: vi.fn(), current: vi.fn(), scoped: vi.fn() }));
vi.mock('./workload-peer.js', () => ({ authenticateWorkloadPeer: owners.authenticate }));
vi.mock('../db/scoped-transaction.js', () => ({ runScopedTransaction: owners.scoped }));
vi.mock('../../../control-api/src/notifications/endpoint-admission.js', () => ({
  currentNotificationChannel: owners.current,
}));
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'1'.repeat(64)}`;
const identity = {
  participantId: id(1),
  workloadId: `urn:openpc:workload:${id(2)}`,
  principalId: id(3),
  credentialId: id(4),
  workloadEpoch: '1',
};
const credential = {
  participantId: id(1),
  privacyDomainId: id(5),
  credentialRef: `urn:openpc:resource:${id(6)}`,
  channel: 'WEBHOOK' as const,
  destinationRef: `urn:openpc:resource:${id(7)}`,
  owner: 'LS-NOTIFICATION' as const,
  secretClass: 'SECRET-NOTIFICATION-CREDENTIAL' as const,
  reference: 'secret://local/notification#1',
  version: '1',
  epoch: '1',
  fingerprint: hash,
  state: 'ACTIVE' as const,
  validFromMs: Date.now() - 10000,
  validUntilMs: Date.now() + 300000,
};
let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
const transports: NotificationWorkloadTransport[] = [],
  sockets: TLSSocket[] = [];
beforeAll(async () => {
  tls = await runtimeSnapshotTlsFixture(`urn:openpc:participant:${id(1)}:workload:${id(2)}`);
});
afterAll(async () => {
  tls.privateKey.fill(0);
  tls.server.privateKey.fill(0);
  await tls.close();
});
beforeEach(() => {
  owners.authenticate.mockResolvedValue(identity);
  owners.current.mockResolvedValue({
    credential,
    installation: {
      workloadId: identity.workloadId,
      principalId: id(3),
      workloadCredentialId: id(4),
      workloadEpoch: '1',
    },
  });
  owners.scoped.mockImplementation(
    async (
      _pool: unknown,
      _scope: unknown,
      _id: unknown,
      use: (client: unknown) => Promise<unknown>,
    ) => use({}),
  );
});
afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy();
  await Promise.all(transports.splice(0).map((value) => value.close()));
  vi.restoreAllMocks();
  for (const owner of Object.values(owners)) owner.mockReset();
});
function options() {
  return {
    pool: {
      options: {
        max: 2,
        connectionTimeoutMillis: 5000,
        statement_timeout: 5000,
        idle_in_transaction_session_timeout: 30000,
      },
    } as unknown as Pool,
    kernel: { authenticateWorkload: vi.fn() } as unknown as IdentityKernel,
    tls: tls.server,
  };
}
async function root() {
  const transport = new NotificationWorkloadTransport(options());
  transports.push(transport);
  const address = await transport.listen({ host: '127.0.0.1', port: 0 });
  return { transport, address };
}
async function peer(port: number, material = true) {
  const socket = connect({
    host: '127.0.0.1',
    port,
    ca: tls.server.ca,
    ...(material ? { cert: tls.certificate, key: tls.privateKey } : {}),
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  });
  sockets.push(socket);
  socket.on('error', () => {});
  await new Promise<void>((resolve, reject) => {
    socket.once('secureConnect', resolve);
    socket.once('error', reject);
  });
  return socket;
}
async function admitted(transport: NotificationWorkloadTransport) {
  await expect
    .poll(async () => transport.withPeer(credential, async () => true).catch(() => false), {
      timeout: 3000,
    })
    .toBe(true);
}
it('fails closed without a real accepted peer and refuses broad/unbounded constructor options', async () => {
  const { transport } = await root();
  const use = vi.fn();
  await expect(transport.withPeer(credential, use)).rejects.toThrow();
  expect(use).not.toHaveBeenCalled();
  for (const changed of [
    { maxConnections: 0 },
    { maxConnections: 9 },
    { connectionLifetimeMs: 300001 },
    { pool: { options: {} } as unknown as Pool },
  ])
    expect(() => new NotificationWorkloadTransport({ ...options(), ...changed })).toThrow();
});
it('borrows only an actual inbound TLS socket and rechecks installation and Identity each time', async () => {
  const { transport, address } = await root();
  await peer(address.port);
  await admitted(transport);
  const before = owners.authenticate.mock.calls.length;
  await transport.withPeer(credential, async (socket) => {
    expect(socket.authorized).toBe(true);
    expect(socket.getProtocol()).toBe('TLSv1.3');
    expect(socket.getPeerCertificate().raw).toBeTruthy();
  });
  expect(owners.authenticate.mock.calls.length).toBeGreaterThan(before);
  expect(owners.current).toHaveBeenCalledWith(
    expect.anything(),
    credential,
    credential.credentialRef,
  );
});
it('rejects copied version, principal, workload credential and epoch instead of using cached admission', async () => {
  const { transport, address } = await root();
  await peer(address.port);
  await admitted(transport);
  const use = vi.fn();
  await expect(transport.withPeer({ ...credential, version: '2' }, use)).rejects.toThrow();
  for (const changed of [{ principalId: id(9) }, { credentialId: id(9) }, { workloadEpoch: '2' }]) {
    owners.authenticate.mockResolvedValue({ ...identity, ...changed });
    await expect(transport.withPeer(credential, use)).rejects.toThrow();
  }
  expect(use).not.toHaveBeenCalled();
});
it('rejects foreign tenant selection, changed installation and revoked live authentication', async () => {
  const { transport, address } = await root();
  await peer(address.port);
  await admitted(transport);
  const use = vi.fn();
  owners.current.mockRejectedValueOnce(new Error('revoked installation'));
  await expect(transport.withPeer(credential, use)).rejects.toThrow();
  owners.authenticate.mockRejectedValueOnce(new Error('revoked credential'));
  await expect(transport.withPeer(credential, use)).rejects.toThrow();
  owners.current.mockResolvedValue({
    credential: { ...credential, participantId: id(9) },
    installation: { workloadId: identity.workloadId },
  });
  await expect(transport.withPeer({ ...credential, participantId: id(9) }, use)).rejects.toThrow();
  expect(use).not.toHaveBeenCalled();
});
it('rejects duplicate peers and never switches an in-flight borrow to a successor socket', async () => {
  const { transport, address } = await root();
  await peer(address.port);
  await admitted(transport);
  let finish!: () => void, entered!: () => void;
  const entry = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const pending = transport.withPeer(credential, async () => {
    entered();
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
  });
  const observed = pending.then(
    () => false,
    () => true,
  );
  await entry;
  await peer(address.port);
  expect(await observed).toBe(true);
  finish();
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
});
it('refuses concurrent borrowing and closes outstanding callbacks without accepting late results', async () => {
  const { transport, address } = await root();
  await peer(address.port);
  await admitted(transport);
  let finish!: () => void, entered!: () => void;
  const entry = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const pending = transport.withPeer(credential, async () => {
    entered();
    return new Promise<string>((resolve) => {
      finish = () => resolve('late');
    });
  });
  const observed = pending.then(
    () => 'accepted',
    () => 'closed',
  );
  await entry;
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
  let drained = false;
  const closing = transport.close().then(() => {
    drained = true;
  });
  expect(await observed).toBe('closed');
  expect(drained).toBe(false);
  finish();
  await closing;
  await expect(transport.listen({ host: '127.0.0.1', port: 0 })).rejects.toThrow();
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
});
it('does not authenticate a client lacking a trusted certificate', async () => {
  const { transport, address } = await root();
  await peer(address.port, false).catch(() => {});
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
  expect(owners.authenticate).not.toHaveBeenCalled();
});
it('bounds pending installation lookups before allocating another database task', async () => {
  const transport = new NotificationWorkloadTransport({ ...options(), maxConnections: 1 });
  transports.push(transport);
  await transport.listen({ host: '127.0.0.1', port: 0 });
  let release!: () => void;
  owners.current.mockImplementation(
    () =>
      new Promise((_resolve, reject) => {
        release = () => reject(new Error('closed admission'));
      }),
  );
  const first = transport.withPeer(credential, async () => true);
  const observed = first.catch(() => false);
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
  expect(owners.current).toHaveBeenCalledTimes(1);
  release();
  expect(await observed).toBe(false);
});
it('drains a listener whose startup overlaps shutdown', async () => {
  const transport = new NotificationWorkloadTransport(options());
  transports.push(transport);
  const starting = transport.listen({ host: '127.0.0.1', port: 0 });
  const observed = starting.then(
    () => 'started',
    () => 'closed',
  );
  await transport.close();
  expect(await observed).toBe('closed');
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
});
it('terminates a borrow at the absolute socket lifetime and ignores its late result', async () => {
  const transport = new NotificationWorkloadTransport({ ...options(), connectionLifetimeMs: 1000 });
  transports.push(transport);
  const address = await transport.listen({ host: '127.0.0.1', port: 0 });
  await peer(address.port);
  await admitted(transport);
  let finish!: () => void;
  const result = transport.withPeer(
    credential,
    async () =>
      new Promise<string>((resolve) => {
        finish = () => resolve('late');
      }),
  );
  await expect(result).rejects.toThrow();
  finish();
  await expect(transport.withPeer(credential, async () => true)).rejects.toThrow();
});

it('delivery transport rejects caller authority and invalid lifetime before a worker borrow', async () => {
  const { transport } = await root();
  const use = vi.fn(async () => true);
  for (const maximum of [0, -1, 30001, NaN])
    await expect(transport.withDeliveryPeer({}, maximum, use)).rejects.toThrow();
  await expect(
    transport.withDeliveryPeer(
      { participantId: id(1), privacyDomainId: id(5), installationDigest: hash, ready: true },
      1000,
      use,
    ),
  ).rejects.toThrow();
  expect(use).not.toHaveBeenCalled();
});
