import assert from 'node:assert/strict';
import test from 'node:test';
import { Pool } from 'pg';
import {
  prepareNotificationPackagedRuntime,
  prepareNotificationPackagedDeliveryMount,
  validateNotificationPackagedInputs,
  notificationPackagedConfiguration,
  parseNotificationPackagedNetworkJson,
  writeNotificationPackagedMountFile,
} from './notification-packaged-runtime.mjs';

test('packaged network input calls the strict parser with a finite depth profile', () => {
  assert.deepEqual(
    parseNotificationPackagedNetworkJson(Buffer.from('{"schema":"network","networkId":null}')),
    { schema: 'network', networkId: null },
  );
  for (const input of [
    Buffer.from('{"a":1,"a":2}'),
    Buffer.from('{"__proto__":{}}'),
    Buffer.from('{"a":'.repeat(18) + '0' + '}'.repeat(18)),
    Buffer.alloc(262145),
    'not bytes',
  ])
    assert.throws(() => parseNotificationPackagedNetworkJson(input));
});

test('closed packaged input boundary rejects absent, partial and caller-fabricated runtime authority before effects', async () => {
  for (const input of [
    undefined,
    null,
    {},
    { ready: true },
    {
      runRoot: '/tmp/owned',
      containerRoot: '/app/notification',
      installationPool: {},
      runtimePool: {},
      entries: [],
    },
    { installed: true, peer: { authenticated: true }, provider: { resurrect: true } },
  ]) {
    assert.throws(
      () => validateNotificationPackagedInputs(input),
      /BLOCKED_NOTIFICATION_PACKAGED_INPUTS/u,
    );
    await assert.rejects(
      prepareNotificationPackagedRuntime(input),
      /BLOCKED_NOTIFICATION_PACKAGED_INPUTS/u,
    );
    assert.throws(() => notificationPackagedConfiguration(input, 12345));
  }
});
test('path aliases, unknown fields, unbounded timeout and partial transport cannot reach inherited execution', async () => {
  const bounded = {
    max: 1,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 10000,
  };
  const installationPool = new Pool(bounded),
    runtimePool = new Pool(bounded);
  // No fake internal pool or fabricated cryptographic profile is used. Each
  // malformed shape rejects before the required real signed-input boundary.
  const tls = {
    ca: Buffer.from('invalid'),
    certificate: Buffer.from('invalid'),
    privateKey: Buffer.from('invalid'),
  };
  const value = {
    runRoot: '/tmp/owned',
    containerRoot: '/app/notification',
    installationPool,
    runtimePool,
    entries: [{ fixture: {}, workloadTls: tls }],
    provider: {
      tls,
      leaseMs: 1000,
      network: {
        advertisedAddress: '127.0.0.1',
        listenHost: '127.0.0.1',
        serverName: 'provider',
        serverSpkiDigest: `sha256:${'a'.repeat(64)}`,
      },
    },
    control: {
      tls,
      listen: { host: '0.0.0.0', port: 3448 },
      peer: {
        host: '127.0.0.1',
        port: 53448,
        serverName: 'control',
        serverSpkiDigest: `sha256:${'b'.repeat(64)}`,
      },
    },
  };
  try {
    for (const input of [
      { ...value, runRoot: 'relative' },
      { ...value, containerRoot: '/app/../escape' },
      { ...value, channelSecretFile: '/tmp/forbidden' },
      { ...value, ready: true },
      { ...value, timeoutMs: 30001 },
      { ...value, provider: { ...value.provider, leaseMs: 0 } },
      { ...value, control: { ...value.control, tls: { ca: tls.ca } } },
      {
        ...value,
        control: { ...value.control, peer: { ...value.control.peer, host: 'control-api' } },
      },
    ])
      await assert.rejects(
        prepareNotificationPackagedRuntime(input),
        /BLOCKED_NOTIFICATION_PACKAGED_INPUTS/u,
      );
  } finally {
    await installationPool.end();
    await runtimePool.end();
  }
});

test('packaged mounts remain readable by the container under private umask without exposing their host parent', async () => {
  const { mkdtemp, stat, chmod, readFile, rm } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const parent = await mkdtemp(join(tmpdir(), 'notification-mount-mode-'));
  const mask = process.umask(0o077);
  try {
    await chmod(parent, 0o700);
    const data = Buffer.from('test-only-transport-material');
    const path = await writeNotificationPackagedMountFile(parent, 'control-key.pem', data);
    assert.equal((await stat(path)).mode & 0o777, 0o444);
    assert.equal((await stat(parent)).mode & 0o777, 0o700);
    assert.deepEqual(await readFile(path), data);
    await assert.rejects(
      writeNotificationPackagedMountFile(parent, 'control-key.pem', Buffer.from('replacement')),
    );
    for (const name of ['../outside.pem', 'channel-key.pem', 'workload-8-key.pem'])
      await assert.rejects(writeNotificationPackagedMountFile(parent, name, data));
    await chmod(parent, 0o755);
    await assert.rejects(writeNotificationPackagedMountFile(parent, 'configuration.json', data));
  } finally {
    process.umask(mask);
    await rm(parent, { recursive: true, force: true });
  }
});

test('delivery mount preparation accepts no source, peer, qualification or readiness DTO', async () => {
  for (const value of [
    undefined,
    {},
    { ready: true },
    {
      directory: '/tmp/unsafe',
      containerRoot: '/app/delivery',
      participantId: '01900000-0000-7000-8000-000000000001',
      privacyDomainId: '01900000-0000-7000-8000-000000000001',
      sources: [],
    },
    { directory: 'relative', containerRoot: '/', participantId: 'x', privacyDomainId: 'x' },
  ])
    await assert.rejects(prepareNotificationPackagedDeliveryMount(value));
});
