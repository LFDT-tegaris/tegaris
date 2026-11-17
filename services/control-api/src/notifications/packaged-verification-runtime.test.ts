import { afterAll, afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';
import { loadPackagedNotificationVerificationRuntime } from './packaged-verification-runtime.js';
import type { PackagedNotificationVerificationOptions } from './packaged-verification-runtime.js';
import type { NotificationVerificationRuntimeOptions } from './endpoint-verification-runtime.js';
import type { NotificationCredentialClientOptions } from './credential-provider-client.js';

// Root composition contracts with real files/PEM parsing. Runtime/provider test
// doubles establish wiring and lifetime only, never packaged journey authority.
const calls = vi.hoisted(() => ({
  order: [] as string[],
  clients: [] as {
    options: NotificationCredentialClientOptions;
    close: ReturnType<typeof vi.fn>;
    borrow: ReturnType<typeof vi.fn>;
  }[],
  client: vi.fn(),
  runtime: vi.fn(),
  start: vi.fn(),
  stop: vi.fn(),
  preflight: vi.fn(),
  workflow: Object.freeze({ workflow: 'existing-owner' }),
  owners: Object.freeze({ owners: 'existing-owner' }),
}));
vi.mock('./credential-provider-client.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./credential-provider-client.js')>()),
  createNotificationCredentialClient: calls.client,
}));
vi.mock('./endpoint-verification-runtime.js', () => ({
  createNotificationVerificationRuntime: calls.runtime,
}));

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const urn = (n: number) => `urn:openpc:resource:${id(n)}`;
let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
let root: string;
let directory: string;
const pending = new Set<
  NonNullable<Awaited<ReturnType<typeof loadPackagedNotificationVerificationRuntime>>>
>();
beforeAll(async () => {
  root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'notification-packaged-test-'));
  tls = await runtimeSnapshotTlsFixture(`urn:openpc:participant:${id(1)}:workload:${id(3)}`);
  for (const [name, bytes] of Object.entries({
    'ca.pem': tls.server.ca,
    'server.pem': tls.server.certificate,
    'server.key': tls.server.privateKey,
    'client.pem': tls.certificate,
    'client.key': tls.privateKey,
  }))
    await writeFile(join(root, name), bytes, { mode: 0o600 });
});
afterAll(async () => {
  await tls?.close();
  await rm(root, { recursive: true, force: true });
});
beforeEach(async () => {
  directory = await mkdtemp(join(root, 'case-'));
  calls.start.mockResolvedValue({ host: '127.0.0.1', port: 3448 });
  calls.stop.mockImplementation(async () => {
    calls.order.push('runtime:close');
  });
  calls.runtime.mockImplementation(() => ({
    workflow: calls.workflow,
    owners: calls.owners,
    start: calls.start,
    close: calls.stop,
    preflight: calls.preflight,
  }));
  calls.client.mockImplementation((options: NotificationCredentialClientOptions) => {
    const index = calls.clients.length;
    const client = {
      options,
      borrow: vi.fn().mockResolvedValue(`provider-${index}`),
      close: vi.fn(() => {
        calls.order.push(`client-${index}:close`);
      }),
    };
    calls.clients.push(client);
    return { withExactVersion: client.borrow, close: client.close };
  });
});
afterEach(async () => {
  for (const runtime of pending) await runtime.close().catch(() => {});
  pending.clear();
  calls.clients.length = 0;
  calls.order.length = 0;
  vi.resetAllMocks();
});
function credential(n = 0) {
  return {
    participantId: id(1),
    privacyDomainId: id(2),
    credentialRef: urn(10 + n),
    destinationRef: urn(20 + n),
    channel: 'WEBHOOK',
    owner: 'LS-NOTIFICATION',
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    reference: `secret://local/notification-${n}#1`,
    version: '1',
    epoch: '1',
    fingerprint: `sha256:${'a'.repeat(64)}`,
    validFromMs: 1,
    validUntilMs: 2,
    state: 'ACTIVE',
  };
}
function transport(kind: string) {
  return {
    caFile: join(root, 'ca.pem'),
    certificateFile: join(root, `${kind}.pem`),
    privateKeyFile: join(root, `${kind}.key`),
  };
}
function config() {
  return {
    version: 1,
    listen: { host: '127.0.0.1', port: 3448 },
    tls: transport('server'),
    providers: [0, 1].map((n) => ({
      credential: credential(n),
      address: '127.0.0.1',
      port: 3449 + n,
      serverName: 'notification-provider',
      serverSpkiDigest: `sha256:${'b'.repeat(64)}`,
      tls: transport('client'),
    })),
  };
}
function options(): PackagedNotificationVerificationOptions {
  return {
    database: {
      host: 'control-pg',
      port: 5432,
      database: 'openpc_control',
      user: 'openpc_configuration_runtime',
      password: 'test-only',
    },
    identityRuntimeVerifier: { verifyCanonicalAssertion: vi.fn() },
    businessEvidence: { environmentId: 'test', signer: { sign: vi.fn() } },
  } as unknown as PackagedNotificationVerificationOptions;
}
async function load(value: unknown = config(), input = options()) {
  const path = join(directory, 'root.json');
  await writeFile(path, JSON.stringify(value), { mode: 0o600 });
  const runtime = await loadPackagedNotificationVerificationRuntime(path, input);
  if (runtime) pending.add(runtime);
  return runtime!;
}
function composed(): NotificationVerificationRuntimeOptions {
  return calls.runtime.mock.calls.at(-1)![0] as NotificationVerificationRuntimeOptions;
}
function request(n = 0) {
  const { participantId, privacyDomainId, credentialRef, reference, version, epoch } =
    credential(n);
  return {
    participantId,
    privacyDomainId,
    credentialRef,
    reference,
    version,
    epoch,
    purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL' as const,
    consumer: 'LS-NOTIFICATION' as const,
  };
}
it('leaves absent configuration unavailable without constructing or borrowing any owner', async () => {
  expect(await loadPackagedNotificationVerificationRuntime(undefined, options())).toBeUndefined();
  expect(calls.client).not.toHaveBeenCalled();
  expect(calls.runtime).not.toHaveBeenCalled();
});
it('loads transport PEMs, forwards runtime dependencies and starts before exposing existing owners', async () => {
  const input = options();
  let finish!: () => void;
  calls.start.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  let returned = false;
  const loading = load(config(), input).then((runtime) => {
    returned = true;
    return runtime;
  });
  await vi.waitFor(() => expect(calls.start).toHaveBeenCalledTimes(1));
  expect(returned).toBe(false);
  expect(composed()).toMatchObject({
    database: input.database,
    identityRuntimeVerifier: input.identityRuntimeVerifier,
    businessEvidence: input.businessEvidence,
    timeoutMs: 10000,
    connectionLifetimeMs: 300000,
  });
  expect(calls.start).toHaveBeenCalledWith({ host: '127.0.0.1', port: 3448 });
  for (const client of calls.clients) expect(client.borrow).not.toHaveBeenCalled();
  finish();
  const runtime = await loading;
  expect(runtime.workflow).toBe(calls.workflow);
  expect(runtime.owners).toBe(calls.owners);
});
it('selects only the exact scoped provider request and rejects extra authority or material fields', async () => {
  await load();
  const provider = composed().credentialProvider;
  const use = vi.fn();
  expect(await provider.withExactVersion(request(1), use)).toBe('provider-1');
  expect(calls.clients[0]!.borrow).not.toHaveBeenCalled();
  expect(calls.clients[1]!.borrow).toHaveBeenCalledWith(request(1), use);
  for (const changed of [
    { participantId: id(9) },
    { privacyDomainId: id(9) },
    { credentialRef: urn(9) },
    { reference: 'secret://local/other#1' },
    { version: '2' },
    { epoch: '2' },
    { consumer: 'LS-FACT-BRIDGE' },
    { purpose: 'OTHER' },
    { material: 'forbidden' },
  ])
    await expect(
      provider.withExactVersion({ ...request(1), ...changed } as never, use),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  expect(calls.clients[1]!.borrow).toHaveBeenCalledTimes(1);
});
it('delegates missing-peer denial to real runtime preflight without provider use or removing metadata owners', async () => {
  calls.preflight.mockRejectedValue(new Error('OPS_NOTIFICATION_PEER_UNAVAILABLE'));
  const runtime = await load();
  await expect(runtime.preflight(credential() as never)).rejects.toThrow(
    'OPS_NOTIFICATION_PEER_UNAVAILABLE',
  );
  expect(runtime.owners).toBe(calls.owners);
  expect(calls.clients.every((client) => !client.borrow.mock.calls.length)).toBe(true);
});
it.each([
  [
    'unknown material',
    (value: ReturnType<typeof config>) => ({ ...value, material: 'not accepted' }),
  ],
  [
    'partial TLS',
    (value: ReturnType<typeof config>) => ({ ...value, tls: { caFile: value.tls.caFile } }),
  ],
  [
    'relative path',
    (value: ReturnType<typeof config>) => ({
      ...value,
      tls: { ...value.tls, privateKeyFile: 'client.key' },
    }),
  ],
  [
    'traversal path',
    (value: ReturnType<typeof config>) => ({
      ...value,
      tls: { ...value.tls, privateKeyFile: `${root}/../client.key` },
    }),
  ],
  [
    'unbounded lifetime',
    (value: ReturnType<typeof config>) => ({ ...value, connectionLifetimeMs: 300001 }),
  ],
  [
    'zero port',
    (value: ReturnType<typeof config>) => ({ ...value, listen: { host: '127.0.0.1', port: 0 } }),
  ],
  [
    'provider hostname instead of IP',
    (value: ReturnType<typeof config>) => ({
      ...value,
      providers: [{ ...value.providers[0], address: 'provider' }],
    }),
  ],
  [
    'mutable secret alias',
    (value: ReturnType<typeof config>) => ({
      ...value,
      providers: [
        {
          ...value.providers[0],
          credential: { ...credential(), reference: 'secret://local/notification#current' },
        },
      ],
    }),
  ],
  [
    'conflicting immutable reference',
    (value: ReturnType<typeof config>) => ({
      ...value,
      providers: [
        value.providers[0],
        {
          ...value.providers[1],
          credential: { ...credential(), fingerprint: `sha256:${'c'.repeat(64)}` },
        },
      ],
    }),
  ],
  [
    'too many providers',
    (value: ReturnType<typeof config>) => ({
      ...value,
      providers: Array(9).fill(value.providers[0]),
    }),
  ],
] as const)('rejects %s before runtime construction', async (_name, change) => {
  await expect(load(change(config()))).rejects.toThrow(
    'Invalid notification verification configuration',
  );
  expect(calls.runtime).not.toHaveBeenCalled();
  expect(calls.start).not.toHaveBeenCalled();
});
it('rejects owner credentials and connection-string overrides', async () => {
  for (const database of [
    { ...options().database, user: 'openpc_control' },
    { ...options().database, connectionString: 'postgres://owner@control-pg/db' },
  ])
    await expect(load(config(), { ...options(), database })).rejects.toThrow(
      'Invalid notification verification configuration',
    );
  expect(calls.runtime).not.toHaveBeenCalled();
});
it('rejects malformed JSON, duplicate keys, symlinks, empty, oversized and non-regular files', async () => {
  const path = join(directory, 'invalid.json');
  for (const bytes of ['{', '{"version":1,"version":1}', '', ' '.repeat(262145)]) {
    await writeFile(path, bytes);
    await expect(loadPackagedNotificationVerificationRuntime(path, options())).rejects.toThrow(
      'Invalid notification verification configuration',
    );
  }
  const link = join(directory, 'link.json');
  await symlink(path, link);
  for (const invalid of [link, directory, 'relative.json', ''])
    await expect(loadPackagedNotificationVerificationRuntime(invalid, options())).rejects.toThrow(
      'Invalid notification verification configuration',
    );
  expect(calls.runtime).not.toHaveBeenCalled();
});
it('checks PEM/key matching, client usage and participant SAN before constructing runtime', async () => {
  for (const changed of [
    { ...transport('client'), privateKeyFile: join(root, 'server.key') },
    transport('server'),
  ]) {
    const value = config();
    value.providers[0]!.tls = changed;
    await expect(load(value)).rejects.toThrow('Invalid notification verification configuration');
  }
  const value = config();
  value.providers[0]!.credential.participantId = id(9);
  await expect(load(value)).rejects.toThrow('Invalid notification verification configuration');
  expect(calls.runtime).not.toHaveBeenCalled();
});
it('closes earlier clients when a later client input fails without starting the listener', async () => {
  const value = config();
  value.providers[1]!.tls.privateKeyFile = join(directory, 'absent.key');
  await expect(load(value)).rejects.toThrow('Invalid notification verification configuration');
  expect(calls.clients).toHaveLength(1);
  expect(calls.clients[0]!.close).toHaveBeenCalledTimes(1);
  expect(calls.runtime).not.toHaveBeenCalled();
});
it('closes clients on rejected runtime construction', async () => {
  calls.runtime.mockImplementation(() => {
    throw new Error('private diagnostic');
  });
  await expect(load()).rejects.toThrow('Invalid notification verification configuration');
  expect(calls.clients.every((client) => client.close.mock.calls.length === 1)).toBe(true);
});
it('initiates runtime cleanup before closing clients after failed start and propagates cleanup failure', async () => {
  calls.start.mockRejectedValue(new Error('private listen failure'));
  calls.stop.mockImplementation(async () => {
    calls.order.push('runtime:close');
    throw new Error('private pool failure');
  });
  await expect(load()).rejects.toThrow('Notification packaged runtime cleanup failed');
  expect(calls.order).toEqual(['runtime:close', 'client-0:close', 'client-1:close']);
  expect(calls.stop).toHaveBeenCalledTimes(1);
});
it('closes once, rejects later borrows, erases owned input buffers and preserves cleanup rejection', async () => {
  const runtime = await load();
  calls.clients[0]!.close.mockImplementation(() => {
    throw new Error('private client failure');
  });
  const first = runtime.close();
  expect(runtime.close()).toBe(first);
  await expect(first).rejects.toThrow('Notification packaged runtime cleanup failed');
  await expect(composed().credentialProvider.withExactVersion(request(), vi.fn())).rejects.toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(calls.clients[1]!.close).toHaveBeenCalledTimes(1);
  expect(calls.stop).toHaveBeenCalledTimes(1);
  for (const bytes of Object.values(composed().tls))
    expect(bytes.every((value) => value === 0)).toBe(true);
});
it('reopens only transport clients and preserves provider denial without any startup export', async () => {
  const first = await load();
  await first.close();
  const second = await load();
  expect(calls.clients).toHaveLength(4);
  for (const client of calls.clients) expect(client.borrow).not.toHaveBeenCalled();
  calls.clients[2]!.borrow.mockRejectedValue(new Error('OPS_SECRET_UNRESOLVED'));
  await expect(composed().credentialProvider.withExactVersion(request(), vi.fn())).rejects.toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  await second.close();
});
