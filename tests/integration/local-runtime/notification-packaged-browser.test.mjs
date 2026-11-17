import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  notificationPackagedFailureBoundary,
  notificationPackagedSourcePreflight,
  parseNotificationPackagedJson,
  notificationPackagedDatabaseEndpoint,
  readNotificationPackagedDatabaseInputs,
  notificationPackagedBrowserCliArguments,
  notificationPackagedBrowserTerminalResult,
  assertNotificationPackagedBrowserTopology,
  assertNotificationPackagedBrowserContainer,
  notificationPackagedLifecycleArguments,
  runNotificationPackagedCompose,
  validateNotificationPackagedBrowserEnvironment,
  notificationPackagedBrowserOverlay,
  notificationPackagedComposeOptions,
  NotificationPackagedBrowserFailure,
  runNotificationPackagedBrowser,
  validateNotificationPackagedBrowserRequest,
  writeNotificationPackagedBrowserOverlay,
} from './notification-packaged-browser.mjs';

test('packaged failure diagnostics expose only a closed boundary label', () => {
  assert.equal(
    notificationPackagedFailureBoundary(
      new AggregateError([
        new Error('BLOCKED_NOTIFICATION_INPUTS_ROOT'),
        new Error('postgresql://secret@host'),
      ]),
    ),
    'INPUTS_ROOT',
  );
  assert.equal(
    notificationPackagedFailureBoundary(
      new AggregateError([
        new Error('BLOCKED_NOTIFICATION_INPUTS_SECRET_VALUE'),
        new Error('postgresql://secret@host'),
      ]),
    ),
    'UNCLASSIFIED',
  );
  assert.equal(
    notificationPackagedFailureBoundary(new Error('BLOCKED_NOTIFICATION_PACKAGED_BROWSER_ROOT')),
    'ROOT',
  );
  for (const error of [
    new Error('postgresql://secret@host'),
    new Error('BLOCKED_NOTIFICATION_PACKAGED_BROWSER_ROOT\nsecret'),
    new Error('BLOCKED_NOTIFICATION_PACKAGED_BROWSER_https://secret'),
    'ROOT',
    null,
  ])
    assert.equal(notificationPackagedFailureBoundary(error), 'UNCLASSIFIED');
});

const testRoot = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
test('actual source permissions fail before runtime allocation and remain closed at use', async () => {
  const directory = await mkdtemp(join(testRoot, 'notification-source-permission-'));
  const source = join(directory, 'compose.yaml');
  try {
    await writeFile(source, 'services: {}\n', { mode: 0o600 });
    await chmod(source, 0o664);
    await assert.rejects(notificationPackagedSourcePreflight(source), /BROWSER_ROOT/u);
    await chmod(source, 0o644);
    await notificationPackagedSourcePreflight(source);
    await chmod(source, 0o646);
    await assert.rejects(notificationPackagedSourcePreflight(source), /BROWSER_ROOT/u);
    assert.deepEqual(notificationPackagedBrowserCliArguments(['preflight-source']), {
      mode: 'preflight-source',
    });
    assert.throws(
      () => notificationPackagedBrowserCliArguments(['preflight-source', source]),
      /CLI_ARGUMENTS/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
const root = '/tmp/local-runtime.notification-browser';
const repository = '/repo/openpc';
const project = 'openpc-local-e2e-0123456789ab';
const baseFile = join(repository, 'deploy/compose/local/compose.yaml');
const compose = [
  'docker',
  'compose',
  '-p',
  project,
  '-f',
  baseFile,
  '-f',
  join(root, 'data/local-runtime-network.json'),
];
const request = () => ({
  inputs: {
    runRoot: root,
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    database: {
      installationUrl: 'postgresql://openpc_control:synthetic-test@127.0.0.1:55432/openpc_control',
      runtimeUrl:
        'postgresql://openpc_configuration_runtime:synthetic-test@127.0.0.1:55432/openpc_control',
    },
    channels: ['WEBHOOK', 'WEBHOOK'],
    minimumRemainingMs: 120000,
  },
  composeArgv: compose,
});
function transport() {
  const containerRoot = '/app/notification-packaged';
  const names = [
    'configuration.json',
    ...['control', 'workload-0', 'workload-1'].flatMap((prefix) =>
      ['ca', 'certificate', 'key'].map((kind) => `${prefix}-${kind}.pem`),
    ),
  ];
  const configurationFile = join(containerRoot, 'configuration.json');
  return {
    runRoot: root,
    containerRoot,
    runtime: {
      configurationFile,
      mounts: names.map((name) => ({
        type: 'bind',
        source: join(root, 'data/notification-packaged', name),
        target: join(containerRoot, name),
        read_only: true,
      })),
      environment: { CONTROL_API_NOTIFICATION_VERIFICATION_FILE: configurationFile },
      port: { target: 3448, published: 53448, host_ip: '127.0.0.1', protocol: 'tcp' },
    },
  };
}
// Pure render examples, not fabricated running containers or grant/readiness
// receipts. Actual Compose/runtime acceptance remains with its admitted owner.
function topology() {
  const overlay = notificationPackagedBrowserOverlay(transport());
  const before = {
    name: project,
    services: {
      'control-api': {
        image: 'openpc-r1-dev/control-api:local',
        environment: { NODE_ENV: 'production' },
        volumes: [
          {
            type: 'bind',
            source: join(root, 'secrets/identity_public.der'),
            target: '/app/secrets/identity_public.der',
            read_only: true,
          },
        ],
        ports: [
          {
            mode: 'ingress',
            target: 3002,
            published: '3002',
            host_ip: '127.0.0.1',
            protocol: 'tcp',
          },
        ],
        mem_limit: '805306368',
        networks: { 'openpc-local': {} },
      },
      'admin-web': {
        image: 'openpc-r1-dev/admin-web:local',
        environment: { NODE_ENV: 'production' },
      },
    },
    networks: {
      'openpc-local': {
        name: `${project}_openpc-local`,
        ipam: { config: [{ subnet: '172.30.80.0/24', gateway: '172.30.80.1' }] },
      },
    },
  };
  const after = structuredClone(before),
    added = overlay.services['control-api'];
  after.services['control-api'].environment = {
    ...before.services['control-api'].environment,
    ...added.environment,
  };
  after.services['control-api'].volumes.push(
    ...added.volumes.map((v) => ({ ...v, bind: { create_host_path: true } })),
  );
  after.services['control-api'].ports.push({
    ...added.ports[0],
    published: String(added.ports[0].published),
    mode: 'ingress',
  });
  return { before, after, overlay };
}

test('closed browser request permits only the input owner and bounded Compose argv', () => {
  const value = validateNotificationPackagedBrowserRequest(request());
  assert.equal(value.inputs.channels.length, 2);
  assert.equal(Object.isFrozen(value.composeArgv), true);
  for (const extra of [
    { ready: true },
    { provider: {} },
    { runtime: {} },
    { run: () => {} },
    { imagesVerified: true },
    { cleanupAllowed: true },
  ])
    assert.throws(() => validateNotificationPackagedBrowserRequest({ ...request(), ...extra }));
  assert.throws(() =>
    validateNotificationPackagedBrowserRequest({
      ...request(),
      inputs: { ...request().inputs, channels: ['WEBHOOK'] },
    }),
  );
  assert.throws(() =>
    validateNotificationPackagedBrowserRequest({ ...request(), composeArgv: [...compose, '\nup'] }),
  );
  assert.throws(() =>
    validateNotificationPackagedBrowserRequest({ ...request(), composeArgv: Array(24).fill('x') }),
  );
  const getter = Object.defineProperty({}, 'inputs', {
    get() {
      throw new Error('getter ran');
    },
  });
  assert.throws(
    () => validateNotificationPackagedBrowserRequest(getter),
    /BLOCKED_NOTIFICATION_PACKAGED_BROWSER_REQUEST/u,
  );
});
test('bare options preserve exact project/files and reject commands or overrides', () => {
  assert.deepEqual(
    notificationPackagedComposeOptions({ argv: compose, runRoot: root, repository, project }),
    { project, files: [baseFile, join(root, 'data/local-runtime-network.json')] },
  );
  for (const argv of [
    [...compose, 'up', 'control-api'],
    [...compose, '--env-file', '/tmp/override'],
    [...compose, '-p', 'foreign'],
    [...compose, '-f', baseFile],
    [...compose, '-f', '/tmp/foreign/compose.json'],
    [...compose, '-f', `${root}/../escape`],
    ['bash', '-c', 'docker compose'],
    [...compose, '-f'],
    ['docker', 'compose', '-p', project, '-f', join(root, 'data/only-overlay.json')],
  ])
    assert.throws(
      () => notificationPackagedComposeOptions({ argv, runRoot: root, repository, project }),
      /BLOCKED_NOTIFICATION_PACKAGED_BROWSER_COMPOSE_OPTIONS/u,
    );
});
test('overlay contains the exact transport-only control service projection', () => {
  const source = transport(),
    overlay = notificationPackagedBrowserOverlay(source);
  assert.deepEqual(Object.keys(overlay.services), ['control-api']);
  assert.deepEqual(overlay.services['control-api'].volumes, source.runtime.mounts);
  assert.deepEqual(overlay.services['control-api'].environment, source.runtime.environment);
  assert.equal(overlay.services['control-api'].ports[0].host_ip, '127.0.0.1');
  assert.equal(Object.isFrozen(overlay.services['control-api']), true);
  assert.equal(JSON.stringify(overlay).includes('PRIVATE KEY'), false);
});
test('overlay rejects writable, extra, missing, aliased or substituted material and exposed ports', () => {
  const changes = [
    (v) => {
      v.runtime.ready = true;
    },
    (v) => {
      v.runtime.environment.OTHER = 'value';
    },
    (v) => {
      v.runtime.mounts[0].read_only = false;
    },
    (v) => {
      v.runtime.mounts[0].source = '/tmp/foreign/configuration.json';
    },
    (v) => {
      v.runtime.mounts[0].target = '/app/other/configuration.json';
    },
    (v) => {
      v.runtime.mounts[1].source = join(root, 'data/notification-packaged/channel-secret.pem');
    },
    (v) => {
      v.runtime.mounts[1].target = v.runtime.mounts[0].target;
    },
    (v) => {
      v.runtime.mounts.pop();
    },
    (v) => {
      v.runtime.mounts[4].source = join(root, 'data/notification-packaged/workload-9-ca.pem');
    },
    (v) => {
      v.runtime.port.host_ip = '0.0.0.0';
    },
    (v) => {
      v.runtime.port.target = 1;
    },
  ];
  for (const change of changes) {
    const value = transport();
    change(value);
    assert.throws(() => notificationPackagedBrowserOverlay(value));
  }
});
test('actual-render comparison allows only the exact control-api transport additions', () => {
  const input = topology(),
    original = structuredClone(input);
  assertNotificationPackagedBrowserTopology(input);
  assert.deepEqual(input, original, 'preflight never mutates the supplied topology');
  for (const volume of input.after.services['control-api'].volumes) delete volume.bind;
  assertNotificationPackagedBrowserTopology(input);
});
test('image, service, network, capability, environment and resource changes cannot hide behind the overlay', () => {
  for (const change of [
    (v) => {
      v.after.services['control-api'].image = 'foreign:latest';
    },
    (v) => {
      v.after.services['control-api'].mem_limit = '0';
    },
    (v) => {
      v.after.services['control-api'].privileged = true;
    },
    (v) => {
      v.after.services['control-api'].environment.EXTRA = 'hidden';
    },
    (v) => {
      v.after.services['admin-web'].image = 'changed';
    },
    (v) => {
      v.after.services.database = { image: 'postgres' };
    },
    (v) => {
      v.after.networks['openpc-local'].ipam.config[0].gateway = '172.30.80.2';
    },
    (v) => {
      v.after.name = 'foreign';
    },
  ]) {
    const input = topology();
    change(input);
    assert.throws(() => assertNotificationPackagedBrowserTopology(input));
  }
});
test('render rejects mount/port collisions, shadowing, duplicate targets and changed bind behavior', () => {
  for (const change of [
    (v) => {
      v.before.services['control-api'].environment.CONTROL_API_NOTIFICATION_VERIFICATION_FILE =
        '/app/already.json';
    },
    (v) => {
      v.before.services['control-api'].volumes.push({
        type: 'bind',
        source: '/tmp/shadow',
        target: '/app',
        read_only: true,
      });
    },
    (v) => {
      v.before.services['control-api'].ports[0].target = 3448;
    },
    (v) => {
      v.after.services['control-api'].volumes[1].read_only = false;
    },
    (v) => {
      v.after.services['control-api'].volumes[1].bind.propagation = 'shared';
    },
    (v) => {
      v.after.services['control-api'].volumes.push(v.after.services['control-api'].volumes[1]);
    },
    (v) => {
      v.after.services['control-api'].ports[1].host_ip = '0.0.0.0';
    },
    (v) => {
      v.after.services['control-api'].ports[1].published = 'different';
    },
    (v) => {
      v.after.services['control-api'].ports[1].protocol = 'udp';
    },
    (v) => {
      v.overlay.services['control-api'].environment.READY = 'true';
    },
  ]) {
    const input = structuredClone(topology());
    change(input);
    assert.throws(() => assertNotificationPackagedBrowserTopology(input));
  }
});
test('real private overlay write is exclusive and retains the original on a second attempt', async () => {
  const runRoot = await mkdtemp(join(testRoot, 'notification-browser-overlay-'));
  try {
    await mkdir(join(runRoot, 'data/notification-packaged'), { recursive: true, mode: 0o700 });
    const value = transport();
    value.runRoot = runRoot;
    for (const mount of value.runtime.mounts) mount.source = mount.source.replace(root, runRoot);
    const path = await writeNotificationPackagedBrowserOverlay(value);
    assert.equal(path, join(runRoot, 'data/notification-packaged/compose.json'));
    const original = await readFile(path);
    assert.deepEqual(JSON.parse(original), notificationPackagedBrowserOverlay(value));
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(writeNotificationPackagedBrowserOverlay(value), (error) => {
      assert.equal(error.disposition.state, 'UNKNOWN_RETAIN_ALL');
      assert.equal(error.disposition.genericCleanupAllowed, false);
      return true;
    });
    assert.deepEqual(await readFile(path), original);
  } finally {
    await rm(runRoot, { recursive: true, force: true });
  }
});
test('real file owner rejects directory substitution and nonprivate ownership before writing', async () => {
  const runRoot = await mkdtemp(join(testRoot, 'notification-browser-overlay-denial-'));
  try {
    const directory = join(runRoot, 'data/notification-packaged');
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const value = transport();
    value.runRoot = runRoot;
    for (const mount of value.runtime.mounts) mount.source = mount.source.replace(root, runRoot);
    await chmod(directory, 0o755);
    await assert.rejects(writeNotificationPackagedBrowserOverlay(value));
    await assert.rejects(readFile(join(directory, 'compose.json')), { code: 'ENOENT' });
    await chmod(directory, 0o700);
    const alias = `${runRoot}-alias`;
    await symlink(runRoot, alias);
    try {
      value.runRoot = alias;
      for (const mount of value.runtime.mounts) mount.source = mount.source.replace(runRoot, alias);
      await assert.rejects(writeNotificationPackagedBrowserOverlay(value));
      await assert.rejects(readFile(join(directory, 'compose.json')), { code: 'ENOENT' });
    } finally {
      await rm(alias);
    }
  } finally {
    await rm(runRoot, { recursive: true, force: true });
  }
});
test('partial and UNKNOWN dispositions retain original files and keep first failure before cleanup failure', () => {
  for (const phase of ['PREPARATION', 'OVERLAY', 'STARTUP', 'BROWSER', 'CLEANUP']) {
    const failure = new NotificationPackagedBrowserFailure(phase, true);
    assert.equal(failure.errors[0].message, `BLOCKED_NOTIFICATION_PACKAGED_BROWSER_${phase}`);
    assert.equal(
      failure.errors[1].message,
      'BLOCKED_NOTIFICATION_PACKAGED_BROWSER_CLEANUP_UNKNOWN',
    );
    assert.deepEqual(failure.disposition, {
      phase,
      state: 'UNKNOWN_RETAIN_ALL',
      genericCleanupAllowed: false,
      filesRetained: true,
      exitCode: 99,
    });
    assert.equal(Object.isFrozen(failure.disposition), true);
  }
});
test('fixed lifecycle operations preserve restart effects and cannot build, pull or allocate dependencies', async () => {
  assert.deepEqual(notificationPackagedLifecycleArguments('START_CONTROL_API'), [
    'up',
    '--detach',
    '--no-deps',
    '--no-build',
    '--pull',
    'never',
    '--wait',
    '--wait-timeout',
    '120',
    'control-api',
  ]);
  assert.deepEqual(notificationPackagedLifecycleArguments('RESTART_BROWSER_SERVICES'), [
    'restart',
    '--no-deps',
    'control-api',
    'admin-web',
  ]);
  for (const operation of ['down', 'up', 'RESTART_DATABASE', '', undefined])
    assert.throws(() => notificationPackagedLifecycleArguments(operation));
  await assert.rejects(
    runNotificationPackagedCompose({
      runRoot: root,
      composeArgv: compose,
      operation: 'RESTART_BROWSER_SERVICES',
      ready: true,
    }),
  );
});
test('environment cannot silently substitute a retained endpoint, digest or UNKNOWN intent', () => {
  validateNotificationPackagedBrowserEnvironment({});
  validateNotificationPackagedBrowserEnvironment({
    OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_BROWSER: '1',
    OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UPDATE_BROWSER: '1',
    OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER: '0',
  });
  for (const entry of [
    ['OPENPC_NOTIFICATION_ENDPOINT_REF', 'existing'],
    ['OPENPC_NOTIFICATION_ENDPOINT_DESTINATION_REF', 'existing'],
    ['OPENPC_NOTIFICATION_ENDPOINT_CHANNEL', 'EMAIL'],
    ['OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DESTINATION_REF', 'existing'],
    ['OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DIGEST', 'old'],
    ['OPENPC_NOTIFICATION_ENDPOINT_UNKNOWN_REF', 'existing'],
    ['OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER', '1'],
    ['OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UPDATE_BROWSER', '0'],
  ])
    assert.throws(() =>
      validateNotificationPackagedBrowserEnvironment(Object.fromEntries([entry])),
    );
});
function containerProjection() {
  const { after, overlay } = topology();
  const service = after.services['control-api'];
  return {
    project,
    service,
    overlay,
    container: {
      State: { Running: true },
      Config: {
        Image: service.image,
        Env: Object.entries(service.environment).map(([k, v]) => `${k}=${v}`),
        Labels: {
          'com.docker.compose.project': project,
          'com.docker.compose.service': 'control-api',
        },
      },
      Mounts: service.volumes.map((v) => ({
        Type: v.type,
        Source: v.source,
        Destination: v.target,
        RW: !v.read_only,
      })),
      NetworkSettings: { Ports: { '3448/tcp': [{ HostIp: '127.0.0.1', HostPort: '53448' }] } },
    },
  };
}
test('container projection requires applied transport, running state and original project/service', () => {
  assertNotificationPackagedBrowserContainer(containerProjection());
  for (const change of [
    (v) => {
      v.container.State.Running = false;
    },
    (v) => {
      v.container.Config.Labels['com.docker.compose.project'] = 'foreign';
    },
    (v) => {
      v.container.Config.Labels['com.docker.compose.service'] = 'admin-web';
    },
    (v) => {
      v.container.Config.Image = 'foreign';
    },
    (v) => {
      v.container.Config.Env.pop();
    },
    (v) => {
      v.container.Config.Env.push(v.container.Config.Env.at(-1));
    },
    (v) => {
      v.container.Mounts[1].RW = true;
    },
    (v) => {
      v.container.Mounts[1].Source = '/tmp/substitute';
    },
    (v) => {
      v.container.Mounts.pop();
    },
    (v) => {
      v.container.Mounts.push(v.container.Mounts[1]);
    },
    (v) => {
      v.container.Mounts.push({ Destination: '/app', Type: 'bind', RW: false });
    },
    (v) => {
      v.container.NetworkSettings.Ports['3448/tcp'][0].HostIp = '0.0.0.0';
    },
    (v) => {
      v.container.NetworkSettings.Ports['3448/tcp'].push({ HostIp: '::', HostPort: '53448' });
    },
  ]) {
    const input = containerProjection();
    change(input);
    assert.throws(() => assertNotificationPackagedBrowserContainer(input));
  }
});
test('missing real root stops preparation and returns a nonzero safe disposition without spawning runtime', async () => {
  const missing = await mkdtemp(join(testRoot, 'notification-browser-missing-owner-'));
  try {
    const value = request();
    value.inputs.runRoot = missing;
    await assert.rejects(runNotificationPackagedBrowser(value), (error) => {
      assert.ok(error instanceof NotificationPackagedBrowserFailure);
      assert.equal(error.message, 'BLOCKED_NOTIFICATION_PACKAGED_BROWSER_ADMISSION');
      assert.equal(error.disposition.state, 'NOT_STARTED');
      assert.equal(error.disposition.genericCleanupAllowed, false);
      assert.equal(error.disposition.exitCode, 96);
      return true;
    });
    await assert.rejects(readFile(join(missing, 'data/notification-packaged/compose.json')), {
      code: 'ENOENT',
    });
  } finally {
    await rm(missing, { recursive: true, force: true });
  }
});

// This case requires the root's existing full-envelope inherited admission,
// real databases/services/images and a fresh exclusively owned input scope.
// No fabricated owners, provider callbacks, TLS peers or successful browser.
test('RUNTIME: same-process packaged CREATE UPDATE VERIFY and awaited drain', async () => {
  const path = process.env.OPENPC_NOTIFICATION_PACKAGED_BROWSER_INPUT;
  assert.ok(path, 'canonical admitted root must supply its private actual request file');
  const input = JSON.parse(await readFile(path, 'utf8'));
  const result = await runNotificationPackagedBrowser(input);
  assert.deepEqual(result, {
    status: 'PASS',
    scope: 'CREATE_UPDATE_VERIFY_BROWSER',
    fullNotificationAcceptance: 'OPEN',
    visualInspection: 'PENDING',
    providerDrain: 'DRAINED',
    filesRetained: true,
    genericCleanupAllowed: false,
    exitCode: 0,
  });
});

function databaseProjection() {
  return {
    runRoot: root,
    project,
    rendered: {
      services: {
        'control-pg': {
          image: 'postgres:owned',
          ports: [{ target: 5432, published: '55432', protocol: 'tcp', host_ip: '127.0.0.1' }],
        },
      },
    },
    container: {
      State: { Running: true },
      Config: {
        Image: 'postgres:owned',
        Env: [
          'POSTGRES_DB=openpc_control',
          'POSTGRES_USER=openpc_control',
          'POSTGRES_PASSWORD_FILE=/run/secrets/control_pg_password',
        ],
        Labels: {
          'com.docker.compose.project': project,
          'com.docker.compose.service': 'control-pg',
        },
      },
      Mounts: [
        {
          Type: 'bind',
          Source: join(root, 'data/control-pg'),
          Destination: '/var/lib/postgresql',
          RW: true,
        },
      ],
      NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
    },
  };
}
test('packaged CLI uses the actual owned loopback PostgreSQL mapping, never a guessed DSN', () => {
  assert.deepEqual(notificationPackagedDatabaseEndpoint(databaseProjection()), {
    host: '127.0.0.1',
    port: 55432,
  });
  for (const change of [
    (v) => {
      v.container.State.Running = false;
    },
    (v) => {
      v.container.Config.Labels['com.docker.compose.project'] = 'foreign';
    },
    (v) => {
      v.container.Config.Labels['com.docker.compose.service'] = 'fact-pg';
    },
    (v) => {
      v.container.Config.Image = 'foreign';
    },
    (v) => {
      v.container.Config.Env[1] = 'POSTGRES_USER=postgres';
    },
    (v) => {
      v.container.Config.Env.push('POSTGRES_USER=other');
    },
    (v) => {
      v.container.Mounts[0].Source = '/foreign/data';
    },
    (v) => {
      v.container.Mounts[0].RW = false;
    },
    (v) => {
      v.container.NetworkSettings.Ports['5432/tcp'][0].HostIp = '0.0.0.0';
    },
    (v) => {
      v.container.NetworkSettings.Ports['5432/tcp'][0].HostPort = '55433';
    },
    (v) => {
      v.rendered.services['control-pg'].ports[0].host_ip = '0.0.0.0';
    },
    (v) => {
      v.rendered.services['control-pg'].ports.push(v.rendered.services['control-pg'].ports[0]);
    },
  ]) {
    const input = databaseProjection();
    change(input);
    assert.throws(() => notificationPackagedDatabaseEndpoint(input));
  }
});
test('packaged CLI reads only root-owned private password files into explicit existing roles', async () => {
  const runRoot = await mkdtemp(join(testRoot, 'notification-cli-passwords-'));
  const directory = join(runRoot, 'secrets');
  const file = join(directory, 'control_pg_password.txt');
  const runtime = join(directory, 'control_api_runtime_db_password.txt');
  try {
    await mkdir(directory, { mode: 0o700 });
    const { writeFile } = await import('node:fs/promises');
    await writeFile(file, `${'a'.repeat(64)}\n`, { mode: 0o444 });
    await writeFile(runtime, `${'b'.repeat(64)}\n`, { mode: 0o444 });
    const read = () =>
      readNotificationPackagedDatabaseInputs({
        runRoot,
        endpoint: { host: '127.0.0.1', port: 55432 },
      });
    const inputs = await read();
    const installer = new URL(inputs.installationUrl),
      consumer = new URL(inputs.runtimeUrl);
    assert.equal(installer.username, 'openpc_control');
    assert.equal(consumer.username, 'openpc_configuration_runtime');
    assert.equal(installer.password, 'a'.repeat(64));
    assert.equal(consumer.password, 'b'.repeat(64));
    assert.equal(installer.host, '127.0.0.1:55432');
    assert.equal(consumer.pathname, '/openpc_control');
    await chmod(directory, 0o755);
    await assert.rejects(read());
    await chmod(directory, 0o700);
    await chmod(file, 0o666);
    await assert.rejects(read());
    await chmod(file, 0o444);
    await rm(runtime);
    await symlink(file, runtime);
    await assert.rejects(read());
    await rm(runtime);
    await writeFile(runtime, 'invalid\n', { mode: 0o600 });
    await assert.rejects(read());
  } finally {
    await rm(runRoot, { recursive: true, force: true });
  }
});
test('packaged CLI rejects extra, retained, credential and malformed arguments before effects', () => {
  const input = request();
  const args = [
    'run',
    root,
    input.inputs.participantId,
    input.inputs.privacyDomainId,
    JSON.stringify(compose),
  ];
  assert.equal(notificationPackagedBrowserCliArguments(args).mode, 'run');
  for (const candidate of [
    [],
    [...args, 'ready'],
    ['resume', ...args.slice(1)],
    [...args.slice(0, 4), 'postgresql://privileged:password@localhost/database'],
    ['run', '/tmp/../alias', ...args.slice(2)],
    ['inspect-result', root, project, '123', '99', JSON.stringify(compose)],
    ['inspect-result', root, project, '-1', '0', JSON.stringify(compose)],
  ])
    assert.throws(() => notificationPackagedBrowserCliArguments(candidate));
});
function terminal() {
  return {
    schema: 'openpc-notification-packaged-process-v1',
    root,
    project,
    pid: 12345,
    result: {
      status: 'PASS',
      scope: 'CREATE_UPDATE_VERIFY_BROWSER',
      fullNotificationAcceptance: 'OPEN',
      visualInspection: 'PENDING',
      providerDrain: 'DRAINED',
      filesRetained: true,
      genericCleanupAllowed: false,
      exitCode: 0,
    },
  };
}
test('packaged CLI terminal parser rejects absent, foreign, partial, duplicate and cleanup-authorizing records', () => {
  const serialize = (v) => `OPENPC_NOTIFICATION_PACKAGED_RESULT|${JSON.stringify(v)}\n`;
  const read = (log) =>
    notificationPackagedBrowserTerminalResult({ log, runRoot: root, project, pid: 12345 });
  assert.equal(read('existing browser observation\n' + serialize(terminal())), 'DRAINED_RETAINED');
  for (const log of [
    '',
    'PASS\n',
    serialize(terminal()).trimEnd(),
    serialize(terminal()) + 'later failure\n',
    serialize(terminal()) + serialize(terminal()),
    'OPENPC_NOTIFICATION_PACKAGED_RESULT|{}\n',
  ])
    assert.throws(() => read(log));
  for (const change of [
    (v) => {
      v.pid++;
    },
    (v) => {
      v.root = '/other';
    },
    (v) => {
      v.project = 'foreign';
    },
    (v) => {
      v.result.providerDrain = 'UNKNOWN';
    },
    (v) => {
      v.result.genericCleanupAllowed = true;
    },
    (v) => {
      v.result.filesRetained = false;
    },
    (v) => {
      v.result.exitCode = 99;
    },
    (v) => {
      v.result.ready = true;
    },
  ]) {
    const input = terminal();
    change(input);
    assert.throws(() => read(serialize(input)));
  }
});
test('packaged actual CLI early failure is nonzero and redacted before any owner command', () => {
  const value = request();
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/notification-packaged-browser.mjs',
      'run',
      '/does-not-exist/openpc-notification-cli',
      value.inputs.participantId,
      value.inputs.privacyDomainId,
      JSON.stringify(compose),
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.ifError(result.error);
  assert.equal(result.status, 99);
  assert.equal(result.stdout, '');
  assert.match(
    result.stderr,
    /OPENPC_NOTIFICATION_PACKAGED_CLI\|UNKNOWN_RETAIN_ALL\|phase=CLI\|exit=99/u,
  );
  assert.doesNotMatch(result.stderr, /postgresql:|password|synthetic-test|Error:|stack/u);
});

test('packaged strict JSON profile calls the actual owner and rejects poison, duplicates and deep input', () => {
  assert.deepEqual(parseNotificationPackagedJson(Buffer.from('{"services":{"control-api":{}}}')), {
    services: { 'control-api': {} },
  });
  for (const input of [
    '{"x":1,"x":2}',
    '{"__proto__":{}}',
    '{"constructor":1}',
    '['.repeat(66) + '0' + ']'.repeat(66),
    '{"x":1} garbage',
  ])
    assert.throws(() => parseNotificationPackagedJson(Buffer.from(input)));
  assert.throws(() => parseNotificationPackagedJson(Buffer.alloc(4 * 1024 * 1024 + 1)));
});

test('actual CLI entrypoint finishes module initialization before its journey dynamically imports the restart owner', async () => {
  const { execFileSync } = await import('node:child_process');
  const source = await readFile(
    new URL('./notification-packaged-browser.mjs', import.meta.url),
    'utf8',
  );
  const entry = source.slice(source.lastIndexOf('if (process.argv[1] && import.meta.url'));
  assert.ok(entry.includes('runNotificationPackagedBrowserCli'));
  const directory = await mkdtemp(join(testRoot, 'notification-cli-import-'));
  try {
    const file = join(directory, 'entry.mjs');
    await writeFile(
      file,
      `import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
async function runNotificationPackagedBrowserCli() {
 await import(import.meta.url);
 process.stdout.write('RESTART_OWNER_IMPORT_RESOLVED');
 return 0;
}
${entry}`,
      { mode: 0o600 },
    );
    const output = execFileSync(process.execPath, [file], { encoding: 'utf8', timeout: 5000 });
    assert.equal(output, 'RESTART_OWNER_IMPORT_RESOLVED');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
