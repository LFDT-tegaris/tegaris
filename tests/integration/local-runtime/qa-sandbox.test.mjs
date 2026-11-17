import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import {
  copyFile,
  rename,
  mkdtemp,
  writeFile,
  symlink,
  rm,
  mkdir,
  stat,
  readFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
  qaRoot,
  qaParticipants,
  qaActions,
  qaRpcPlatformTrust,
  validateQaMaintenanceContainers,
  validateQaSerialBudget,
  validateQaBuilder,
  validateQaExecutor,
  qaPressureRejected,
  validateQaComposeCommand,
  stopQaSerialBuilder,
  qaComposeMounts,
  qaDurationComposeOverlay,
  qaDurationEnvironment,
  qaDurationRetainedContainers,
  validateQaOidcBuild,
  validateQaRetainedFixture,
  durationPrivateEnvironment,
  validateQaDurationConfiguration,
} from './qa-sandbox.mjs';
import {
  readQaAccounts,
  qaPasswordMatches,
  startOidcEmulator,
  configuredQaRedirectUri,
} from './oidc-emulator.mjs';
import {
  durationDigest,
  durationContainerState,
  durationExpectedState,
  durationTransitionPlan,
  completeDurationTransition,
  reconcileInitialDurationSave,
} from './qa-duration-transition.mjs';

const GiB = 1024 ** 3;
function transitionFixture() {
  const changed = ['identity-service', 'admin-web', 'control-api', 'policy-service', 'envoy'];
  const make = (name, id, qa = false) => ({
    Id: id,
    Image: 'pinned-image',
    Config: {
      Image: 'pinned-reference',
      Labels: { 'com.docker.compose.project': 'project', 'com.docker.compose.service': name },
      Cmd: ['serve'],
      Entrypoint: [],
      User: 'openpc',
      Env: ['PATH=/bin', ...(qa ? ['PROFILE=10'] : [])],
    },
    State: {
      Running: true,
      Health: { Status: 'healthy' },
      OOMKilled: false,
      StartedAt: 'original-start',
    },
    HostConfig: {
      Memory: GiB,
      MemorySwap: 2 * GiB,
      NanoCpus: 500_000_000,
      CpuPeriod: 0,
      CpuQuota: 0,
      PidsLimit: 128,
      ReadonlyRootfs: true,
      Privileged: false,
      SecurityOpt: ['no-new-privileges:true'],
      CapAdd: null,
      CapDrop: null,
      PortBindings: {},
    },
    NetworkSettings: { Networks: { owned: { NetworkID: 'original-network' } } },
    Mounts: [],
  });
  const actual = [...changed, 'oidc-emulator'].map((n) => make(n, 'old-' + n));
  const target = Object.fromEntries(changed.map((n) => [n, make(n, 'new-' + n, true)]));
  const pending = {
    version: 1,
    project: 'project',
    changed,
    previous: actual.map((c) => ({
      service: c.Config.Labels['com.docker.compose.service'],
      id: c.Id,
      startedAt: c.State.StartedAt,
      configuration: durationDigest(durationContainerState(c)),
    })),
    target: Object.fromEntries(
      changed.map((n) => [n, durationDigest(durationContainerState(target[n]))]),
    ),
  };
  return { actual, target, pending };
}
test('QA duration reconciliation resumes original no/partial/full transitions and lost final saves without repeating completed services', async () => {
  for (let fault = -1; fault <= 5; fault++) {
    const { actual, target, pending } = transitionFixture();
    const preserved = structuredClone(actual.at(-1));
    const sent = [];
    let fail = true;
    const ports = {
      read: async () => {
        if (fail && fault === -1) {
          fail = false;
          throw new Error('lost initial readback');
        }
        return actual;
      },
      authenticate: async () => assert.deepEqual(actual.at(-1), preserved),
      recreate: async (name) => {
        sent.push(name);
        actual[actual.findIndex((c) => c.Config.Labels['com.docker.compose.service'] === name)] =
          structuredClone(target[name]);
        if (fail && sent.length === fault) {
          fail = false;
          throw new Error('lost recreation response');
        }
      },
      finish: async () => {
        if (fail) {
          fail = false;
          throw new Error('lost final save');
        }
      },
    };
    await assert.rejects(completeDurationTransition(pending, ports), /lost /u);
    await completeDurationTransition(pending, ports);
    assert.deepEqual(sent, pending.changed);
    assert.deepEqual(actual.at(-1), preserved);
    assert.equal(durationTransitionPlan(pending, actual).complete, true);
  }
  const { actual, pending } = transitionFixture();
  assert.equal(durationTransitionPlan(pending, actual).remaining.length, 5);
});
test('QA duration reconciliation rejects same-mount image environment cap port network and security drift', () => {
  for (const change of [
    (c) => {
      c.Config.Healthcheck = { Test: ['NONE'] };
    },
    (c) => {
      c.Config.WorkingDir = '/foreign';
    },
    (c) => {
      c.HostConfig.RestartPolicy = { Name: 'always', MaximumRetryCount: 0 };
    },
    (c) => {
      c.Image = 'foreign';
    },
    (c) => {
      c.Config.Env.push('FOREIGN=1');
    },
    (c) => {
      c.HostConfig.Memory *= 2;
    },
    (c) => {
      c.HostConfig.NanoCpus *= 2;
    },
    (c) => {
      c.HostConfig.Privileged = true;
    },
    (c) => {
      c.HostConfig.ReadonlyRootfs = false;
    },
    (c) => {
      c.HostConfig.PortBindings = { '80/tcp': [{ HostIp: '0.0.0.0', HostPort: '80' }] };
    },
    (c) => {
      c.NetworkSettings.Networks.owned.NetworkID = 'replaced';
    },
  ]) {
    const { actual, pending } = transitionFixture();
    change(actual[0]);
    assert.throws(() => durationTransitionPlan(pending, actual));
  }
  const { actual, target, pending } = transitionFixture();
  actual[0] = target['identity-service'];
  actual[0].Config.Env.push('FOREIGN=1');
  assert.throws(() => durationTransitionPlan(pending, actual), /Successor configuration drift/u);
});
test('QA duration initial-save recovery authenticates and preserves the original intent before publication', async () => {
  const manifest = {
    command: ['docker', 'compose'],
    project: 'original',
    environment: { retained: 'private' },
  };
  const input = { command: manifest.command, mode: 'LOCAL_QA_10X' };
  const candidate = {
    ...structuredClone(manifest),
    durationProfilePending: {
      mode: input.mode,
      previousCommand: input.command,
      overlayPath: 'original-immutable-overlay',
    },
  };
  const events = [];
  assert.deepEqual(
    await reconcileInitialDurationSave(manifest, candidate, input, {
      authenticate: async (value) => {
        assert.deepEqual(value, candidate);
        events.push('authenticate');
      },
      preserve: async () => {
        events.push('preserve');
      },
      publish: async (value) => {
        assert.deepEqual(value, candidate);
        events.push('publish');
      },
    }),
    candidate,
  );
  assert.deepEqual(events, ['authenticate', 'preserve', 'publish']);
  for (const changed of [
    { ...candidate, project: 'foreign' },
    { ...candidate, environment: { replacement: 'denied' } },
    {
      ...candidate,
      durationProfilePending: { ...candidate.durationProfilePending, mode: 'NORMAL' },
    },
    {
      ...candidate,
      durationProfilePending: { ...candidate.durationProfilePending, previousCommand: ['foreign'] },
    },
  ])
    await assert.rejects(
      reconcileInitialDurationSave(manifest, changed, input, {
        authenticate: () => assert.fail('Unrelated intent authenticated'),
        preserve: () => assert.fail('Unrelated original replaced'),
        publish: () => assert.fail('Replacement intent published'),
      }),
    );
  await assert.rejects(
    reconcileInitialDurationSave(manifest, candidate, input, {
      authenticate: async () => {
        throw new Error('Original external state drift');
      },
      preserve: () => assert.fail('Unverified original replaced'),
      publish: () => assert.fail('Unverified intent published'),
    }),
    /Original external state drift/u,
  );
});
test('QA duration initial-save filesystem failures retain the original pending pointer until atomic publication', async () => {
  for (const failure of ['after-preserve', 'before-rename']) {
    const root = await mkdtemp(
      join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'qa-duration-initial-'),
    );
    try {
      const target = join(root, 'manifest.json'),
        temporary = target + '.maintenance-tmp',
        archive = target + '.original';
      const manifest = {
        command: ['docker', 'compose'],
        project: 'original',
        environment: { retained: 'private' },
      };
      const input = { mode: 'LOCAL_QA_10X', command: manifest.command };
      const candidate = {
        ...structuredClone(manifest),
        durationProfilePending: {
          mode: input.mode,
          previousCommand: input.command,
          overlayPath: 'same-original-overlay',
          auth: 'same-original-auth',
        },
      };
      await writeFile(target, JSON.stringify(manifest), { flag: 'wx', mode: 0o600 });
      await writeFile(temporary, JSON.stringify(candidate), { flag: 'wx', mode: 0o600 });
      let publishes = 0;
      await assert.rejects(
        reconcileInitialDurationSave(manifest, candidate, input, {
          authenticate: async (value) =>
            assert.deepEqual(JSON.parse(await readFile(temporary, 'utf8')), value),
          preserve: async () => {
            await copyFile(temporary, archive, fsConstants.COPYFILE_EXCL);
            if (failure === 'after-preserve') throw new Error('simulated cancellation');
          },
          publish: async () => {
            publishes++;
            throw Object.assign(new Error('simulated publication failure'), { code: 'ENOSPC' });
          },
        }),
      );
      assert.deepEqual(JSON.parse(await readFile(target, 'utf8')), manifest);
      assert.deepEqual(JSON.parse(await readFile(temporary, 'utf8')), candidate);
      assert.deepEqual(JSON.parse(await readFile(archive, 'utf8')), candidate);
      assert.equal(publishes, failure === 'after-preserve' ? 0 : 1);
      const retry = JSON.parse(await readFile(temporary, 'utf8'));
      const adopted = await reconcileInitialDurationSave(
        JSON.parse(await readFile(target, 'utf8')),
        retry,
        input,
        {
          authenticate: async (value) => assert.deepEqual(value, candidate),
          preserve: async () => copyFile(temporary, archive + '.retry', fsConstants.COPYFILE_EXCL),
          publish: async (value) => {
            assert.deepEqual(JSON.parse(await readFile(temporary, 'utf8')), value);
            await rename(temporary, target);
          },
        },
      );
      assert.deepEqual(adopted, candidate);
      assert.deepEqual(JSON.parse(await readFile(target, 'utf8')), candidate);
      assert.deepEqual(JSON.parse(await readFile(archive, 'utf8')), candidate);
      await assert.rejects(readFile(temporary), { code: 'ENOENT' });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});
test('QA duration expected configuration binds full image environment and security without exposing secrets', () => {
  const { actual } = transitionFixture();
  const config = {
    services: {
      'identity-service': {
        image: 'pinned-reference',
        command: ['serve'],
        user: 'openpc',
        environment: {},
        mem_limit: GiB,
        cpus: 0.5,
        pids_limit: 128,
        read_only: true,
        security_opt: ['no-new-privileges:true'],
      },
    },
  };
  const image = {
    Id: 'pinned-image',
    Config: { Env: ['PATH=/bin'], Cmd: ['serve'], User: 'openpc' },
  };
  assert.deepEqual(
    durationExpectedState(config, 'identity-service', image, { owned: 'original-network' }, []),
    durationContainerState(actual[0]),
  );
  config.services['identity-service'].healthcheck = {
    test: ['CMD-SHELL', '[ "$$status" = ready ]'],
    interval: '2s',
    timeout: '3s',
    retries: 30,
  };
  actual[0].Config.Healthcheck = {
    Test: ['CMD-SHELL', '[ "$status" = ready ]'],
    Interval: 2000000000,
    Timeout: 3000000000,
    Retries: 30,
  };
  actual[0].HostConfig.RestartPolicy = { Name: 'no', MaximumRetryCount: 0 };
  assert.deepEqual(
    durationExpectedState(config, 'identity-service', image, { owned: 'original-network' }, []),
    durationContainerState(actual[0]),
  );
});
test('QA duration NORMAL persists a removed profile and rejects a prepared QA lineage lacking a normal baseline', () => {
  const original = { OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X', OIDC_ISSUER: 'unchanged' };
  const restored = durationPrivateEnvironment(original, 'NORMAL');
  assert.equal(restored.OPENPC_LOCAL_QA_DURATION_PROFILE, undefined);
  assert.equal(restored.OIDC_ISSUER, 'unchanged');
  assert.equal(original.OPENPC_LOCAL_QA_DURATION_PROFILE, 'LOCAL_QA_10X');
  const embedded = {
    services: {
      'identity-service': { environment: { OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X' } },
    },
  };
  assert.throws(
    () => validateQaDurationConfiguration(embedded, embedded, '/repo', 'NORMAL'),
    /normal baseline/u,
  );
});
test('QA retained fixture recognizes only the exact original action catalogue without granting new actions', () => {
  const fixture = {
    fixture: 'SYNTHETIC_INITIAL_IDENTITY_TRUST',
    participants: qaParticipants,
    actions: qaActions.filter(
      (a) =>
        a !== 'ACT-POLICY_ROLLBACK_RELEASE-V1' && a !== 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1',
    ),
  };
  const original = structuredClone(fixture);
  validateQaRetainedFixture(fixture);
  assert.deepEqual(fixture, original);
  const prior = {
    ...fixture,
    actions: qaActions.filter((a) => a !== 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1'),
  };
  const retained = structuredClone(prior);
  validateQaRetainedFixture(prior);
  assert.deepEqual(prior, retained);
  assert.ok(!prior.actions.includes('ACT-POLICY_VERSIONS_READ_COLLECTION-V1'));
  validateQaRetainedFixture({ ...fixture, actions: qaActions });
  for (const actions of [
    fixture.actions.slice(1),
    [...fixture.actions, 'ACT-FOREIGN_READ_RESOURCE-V1'],
    [...fixture.actions.slice(1), fixture.actions[1]],
    fixture.actions.toReversed(),
  ])
    assert.throws(() => validateQaRetainedFixture({ ...fixture, actions }));
});
test('QA OIDC-only build custody rejects live transactions and altered fixture ownership or limits', () => {
  const configuration = { services: { 'oidc-emulator': { volumes: [], tmpfs: ['/tmp'] } } };
  const c = {
    Config: {
      Image:
        'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43',
      Labels: {
        'com.docker.compose.project': 'openpc-local-e2e-fixture',
        'com.docker.compose.service': 'oidc-emulator',
      },
      Cmd: ['node', '/app/server.mjs'],
    },
    State: { Running: true, Health: { Status: 'healthy' }, OOMKilled: false },
    HostConfig: {
      Memory: GiB / 8,
      MemorySwap: GiB / 4,
      NanoCpus: 250_000_000,
      PidsLimit: 64,
      ReadonlyRootfs: true,
      SecurityOpt: ['no-new-privileges:true'],
      PortBindings: { '3006/tcp': [{ HostIp: '127.0.0.1' }] },
    },
    Mounts: [],
  };
  validateQaOidcBuild([c], 'openpc-local-e2e-fixture', configuration);
  assert.throws(
    () => validateQaOidcBuild([c, c], 'openpc-local-e2e-fixture', configuration),
    /Only the retained OIDC/u,
  );
  for (const change of [
    (v) => {
      v.Config.Labels['com.docker.compose.service'] = 'identity-service';
    },
    (v) => {
      v.Config.Labels['com.docker.compose.project'] = 'foreign';
    },
    (v) => {
      v.Config.Image = 'node:latest';
    },
    (v) => {
      v.State.OOMKilled = true;
    },
    (v) => {
      v.State.Health.Status = 'unhealthy';
    },
    (v) => {
      v.HostConfig.Memory = GiB;
    },
    (v) => {
      v.HostConfig.MemorySwap = -1;
    },
    (v) => {
      v.HostConfig.NanoCpus = 500_000_000;
    },
    (v) => {
      v.HostConfig.ReadonlyRootfs = false;
    },
    (v) => {
      v.HostConfig.PortBindings['3006/tcp'][0].HostIp = '0.0.0.0';
    },
    (v) => {
      v.Mounts = [{ Type: 'bind', Source: '/foreign', Destination: '/app/server.mjs', RW: true }];
    },
  ]) {
    const altered = structuredClone(c);
    change(altered);
    assert.throws(() => validateQaOidcBuild([altered], 'openpc-local-e2e-fixture', configuration));
  }
});
test('QA duration transition preserves its registered manifest and leaves extra stopped services outside it', () => {
  const retained = [
    { service: 'identity-service', id: 'old' },
    { service: 'oidc-emulator', id: 'oidc' },
  ];
  const current = [
    ...retained,
    { service: 'runtime-target', id: 'target' },
    { service: 'control-migrate', id: 'migration' },
  ];
  const updated = [{ service: 'identity-service', id: 'new' }, retained[1]];
  assert.deepEqual(qaDurationRetainedContainers(retained, current, updated), updated);
  assert.deepEqual(current.slice(2), [
    { service: 'runtime-target', id: 'target' },
    { service: 'control-migrate', id: 'migration' },
  ]);
  assert.throws(
    () => qaDurationRetainedContainers(retained, current.slice(1), updated),
    /Missing or duplicate/u,
  );
  assert.throws(
    () => qaDurationRetainedContainers(retained, [...current, retained[0]], updated),
    /Missing or duplicate/u,
  );
  assert.throws(
    () => qaDurationRetainedContainers(retained, current, [...updated, updated[0]]),
    /Duplicate updated/u,
  );
});
test('QA mount admission includes Compose configs as well as secrets and volumes', () => {
  const actual = qaComposeMounts(
    {
      configs: { health: { file: '/repo/health.sh' } },
      secrets: { password: { file: '/root/password' } },
    },
    {
      volumes: [{ type: 'bind', source: '/root/data', target: '/data' }],
      configs: [{ source: 'health', target: '/health' }],
      secrets: [{ source: 'password' }],
    },
  );
  assert.deepEqual(actual, [
    { source: '/root/data', target: '/data', type: 'bind', writable: true },
    { source: '/repo/health.sh', target: '/health', type: 'bind', writable: false },
    { source: '/root/password', target: '/run/secrets/password', type: 'bind', writable: false },
  ]);
  assert.throws(() =>
    qaComposeMounts(
      { configs: { health: { external: true } } },
      { configs: [{ source: 'health' }] },
    ),
  );
});
function maintenanceFixture() {
  const names = [
    'control-pg',
    'fact-pg',
    'candidate-index-pg',
    'identity-service',
    'oidc-emulator',
    'signing-provider',
    'workload-issuer',
    'envoy',
    'admin-web',
    'control-api',
    'participant-service',
    'policy-service',
    'fact-service',
  ];
  const containers = names.map((service, i) => ({
    Id: `id-${i}`,
    Image: `image-${i}`,
    Config: {
      Labels: {
        'com.docker.compose.project': 'openpc-local-e2e-0123456789ab',
        'com.docker.compose.service': service,
      },
    },
    HostConfig: { Memory: GiB, MemorySwap: GiB },
    Mounts: [{ Source: `/owned/${service}`, Destination: '/data', Type: 'bind', RW: true }],
    State: { Running: i < 7, StartedAt: 'original' },
  }));
  const manifest = {
    fixture: true,
    project: 'openpc-local-e2e-0123456789ab',
    containers: containers.map((c) => ({
      id: c.Id,
      image: c.Image,
      service: c.Config.Labels['com.docker.compose.service'],
    })),
    maintenance: {
      baseline: containers.map((c) => ({
        id: c.Id,
        image: c.Image,
        service: c.Config.Labels['com.docker.compose.service'],
        memory: GiB,
        swap: GiB,
        mounts: [{ source: c.Mounts[0].Source, target: '/data', type: 'bind', writable: true }],
        startedAt: 'original',
      })),
    },
  };
  return { manifest, containers };
}
function builderFixture() {
  return {
    Id: 'builder-original',
    Name: '/buildx_buildkit_openpc-r1-local-v1-node',
    Config: {
      Image:
        'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8',
      Env: ['OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1'],
    },
    HostConfig: { Memory: 4 * GiB, MemorySwap: 4 * GiB, CpuPeriod: 100000, CpuQuota: 200000 },
    State: { Running: true },
    Mounts: [
      {
        Type: 'volume',
        Name: 'buildx_buildkit_openpc-r1-local-v1-node_state',
        Destination: '/var/lib/buildkit',
      },
    ],
  };
}
test('retained QA serial admission closes exact ownership, consumers, mounts and authority process starts', () => {
  const { manifest, containers } = maintenanceFixture();
  validateQaMaintenanceContainers(manifest, containers, [manifest.project], true);
  const retainedSwap = structuredClone({ manifest, containers });
  retainedSwap.containers[0].HostConfig.MemorySwap = 2 * GiB;
  retainedSwap.manifest.maintenance.baseline[0].swap = 2 * GiB;
  validateQaMaintenanceContainers(
    retainedSwap.manifest,
    retainedSwap.containers,
    [manifest.project],
    true,
  );
  for (const change of [
    (v) => v.containers.pop(),
    (v) => v.containers.push(v.containers[0]),
    (v) => (v.containers[0].Id = 'foreign'),
    (v) => (v.containers[0].Image = 'foreign'),
    (v) => (v.containers[0].Config.Labels['com.docker.compose.project'] = 'foreign'),
    (v) => (v.containers[0].Mounts[0].Source = '/foreign'),
    (v) => (v.containers[0].Mounts[0].RW = false),
    (v) => (v.containers[0].State.Running = false),
    (v) => (v.containers[7].State.Running = true),
    (v) => (v.containers[0].State.StartedAt = 'restarted'),
    (v) => (v.containers[0].HostConfig.Memory = 0),
    (v) => (v.containers[0].HostConfig.MemorySwap = 2 * GiB),
    (v) => (v.manifest.fixture = false),
  ]) {
    const changed = structuredClone({ manifest, containers });
    change(changed);
    assert.throws(() =>
      validateQaMaintenanceContainers(
        changed.manifest,
        changed.containers,
        [manifest.project],
        true,
      ),
    );
  }
  assert.throws(() =>
    validateQaMaintenanceContainers(
      manifest,
      containers,
      [manifest.project, 'openpc-local-e2e-foreign'],
      true,
    ),
  );
});
test('serial QA admission accounts for the hard builder cap, full retained peaks and uncontrolled browser reservation', () => {
  const host = (1.5 * GiB) / 1024,
    retained = 1.625 * GiB,
    keepers = 2.8125 * GiB,
    external = (10.438 * GiB) / 1024;
  validateQaSerialBudget(host, external, retained, keepers);
  for (const args of [
    [host, external - 1, retained + GiB, keepers],
    [host, external - (2 * GiB) / 1024, retained, keepers],
    [host, external, retained, keepers, 8 * GiB],
    [host, external, retained, keepers, 4 * GiB, 0],
    [host * 2, external, retained, keepers],
  ])
    assert.throws(() => validateQaSerialBudget(...args));
});
test('serial QA builder and executor proofs reject pin, cache, resource and containment drift', () => {
  validateQaBuilder(builderFixture(), 4 * GiB, true);
  for (const alter of [
    (b) => (b.Id = 'irrelevant'),
    (b) => (b.Config.Image = 'untrusted'),
    (b) => (b.Config.Env = []),
    (b) => (b.HostConfig.Memory = 8 * GiB),
    (b) => (b.HostConfig.MemorySwap = 8 * GiB),
    (b) => (b.Mounts[0].Name = 'default'),
    (b) => (b.State.Running = false),
    (b) => (b.HostConfig.CpuQuota = 400000),
  ]) {
    const value = builderFixture();
    alter(value);
    if (value.Id === 'irrelevant') continue; // Exact instance identity is checked by the cleanup owner below.
    assert.throws(() => validateQaBuilder(value, 4 * GiB, true));
  }
  validateQaExecutor('/owned', '/owned/worker', 4 * GiB, 0);
  for (const args of [
    ['/', '/worker', 4 * GiB, 0],
    ['/owned', '/owned-foreign', 4 * GiB, 0],
    ['/owned', '/other', 4 * GiB, 0],
    ['/owned', '/owned', 8 * GiB, 0],
    ['/owned', '/owned', 4 * GiB, GiB],
  ])
    assert.throws(() => validateQaExecutor(...args));
});
test('emergency serial cleanup stops only the exact owned builder even when admission or reconciliation fails', async () => {
  assert.equal(qaPressureRejected(100, 0, 0, 0), true);
  assert.equal(qaPressureRejected(2 * 1024 ** 2, 2, 0, 0), true);
  assert.equal(qaPressureRejected(2 * 1024 ** 2, 0, 1, 0), true);
  assert.equal(qaPressureRejected(2 * 1024 ** 2, 0, 0, 0), false);
  const actions = [];
  await assert.rejects(
    stopQaSerialBuilder(
      builderFixture(),
      'builder-original',
      () => actions.push('stop'),
      () => {
        actions.push('restore');
        throw Error('reconciliation failed');
      },
    ),
    /reconciliation failed/,
  );
  assert.deepEqual(actions, ['stop', 'restore']);
  await assert.rejects(
    stopQaSerialBuilder(
      builderFixture(),
      'foreign',
      () => actions.push('unsafe'),
      () => {},
    ),
  );
  assert.deepEqual(actions, ['stop', 'restore']);
});
test('retained QA compose inputs reject foreign roots, projects, commands and duplicate overlays', () => {
  const args = [
    'docker',
    'compose',
    '-p',
    'owned',
    '-f',
    '/repo/deploy/compose/local/compose.yaml',
    '-f',
    '/root/data/qa-compose.json',
  ];
  validateQaComposeCommand(args, '/root', '/repo', 'owned');
  for (const input of [
    [...args, 'up', 'admin-web'],
    [...args, '-f', '/foreign/compose.json'],
    [...args, '-f', '/root/data/qa-compose.json'],
    args.map((v) => (v === 'owned' ? 'foreign' : v)),
    args.map((v) => (v === '/root/data/qa-compose.json' ? '/root/data/../secrets/input' : v)),
  ])
    assert.throws(() => validateQaComposeCommand(input, '/root', '/repo', 'owned'));
});

test('local QA startup is off by default and rejects unrelated opt-in', () => {
  for (const args of [['qa-start'], ['run', '--local-qa-fixture']]) {
    const result = spawnSync('bash', ['scripts/operations/policy-testing.sh', ...args], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 64);
  }
});

test('serial QA web build profile rejects unknown selections and limits its compiler and page worker', async () => {
  const dockerfile = await readFile('apps/admin-web/Dockerfile', 'utf8');
  const next = await readFile('apps/admin-web/next.config.ts', 'utf8');
  const command = dockerfile
    .match(/RUN case "\$OPENPC_BUILD_PROFILE" in ([\s\S]*?)\n\s*esac/u)?.[0]
    .replace(/^RUN /, '')
    .replaceAll('\\\n', '\n');
  assert.ok(command);
  for (const profile of ['default', 'retained-qa-serial', 'unknown']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `pnpm() { printf '%s:%s\\n' "\u0024{NODE_OPTIONS:-default}" "\u0024{OPENPC_BUILD_PROFILE:-default}"; }; ${command}`,
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, NODE_OPTIONS: '', OPENPC_BUILD_PROFILE: profile },
      },
    );
    assert.equal(result.status, profile === 'unknown' ? 64 : 0, result.stderr);
    if (profile === 'retained-qa-serial')
      assert.match(result.stdout, /--max-old-space-size=1536:retained-qa-serial/);
    if (profile === 'unknown') assert.equal(result.stdout, '');
  }
  assert.match(next, /cpus: process\.env\.OPENPC_BUILD_PROFILE === 'retained-qa-serial' \? 1 : 2/u);
});
test('QA has four distinct tenant-bound Platform operators and an explicit administrative capability list', () => {
  assert.equal(new Set(qaParticipants.flatMap((p) => p.people.map((v) => v.principalId))).size, 4);
  assert.equal(new Set(qaParticipants.map((p) => p.participantId)).size, 2);
  assert.ok(
    qaParticipants.every((participant) =>
      participant.people.every((person) => person.kind === 'PLATFORM_OPERATOR'),
    ),
  );
  assert.equal(qaActions.length, new Set(qaActions).size);
  assert.ok(!qaActions.includes('ACT-PARTICIPANTS_CREATE_RESOURCE-V1'));
  assert.ok(qaActions.includes('ACT-PARTICIPANTS_READ_COLLECTION-V1'));
  assert.ok(qaActions.includes('ACT-PARTICIPANTS_READ_RESOURCE-V1'));
  assert.ok(qaActions.includes('ACT-POLICY_APPROVE_REQUEST-V1'));
  assert.ok(qaActions.includes('ACT-POLICY_VERSIONS_READ_COLLECTION-V1'));
  assert.ok(qaActions.includes('ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1'));
  assert.ok(qaActions.includes('ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1'));
  assert.ok(qaActions.includes('ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1'));
  for (const action of [
    'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
    'ACT-INDEXER_PROFILES_READ_RESOURCE-V1',
    'ACT-INDEXER_APPROVE_PROFILE-V1',
    'ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',
    'ACT-PROJECTION_PLANS_READ_RESOURCE-V1',
    'ACT-INDEXER_RECOVER_PLAN-V1',
  ])
    assert.ok(qaActions.includes(action), action);
  for (const action of [
    'ACT-PROVIDER_PROFILES_READ_COLLECTION-V1',
    'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',
    'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
    'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
    'ACT-RUNTIME_TARGETS_READ_COLLECTION-V1',
    'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
    'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
    'ACT-OPERATIONS_READ_OPERATION-V1',
    'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1',
    'ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
    'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1',
    'ACT-POLICY_ACTIVATE_PUBLISH-V1',
    'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
    'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
    'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
  ]) {
    assert.ok(qaActions.includes(action), action);
  }
  assert.match(qaRpcPlatformTrust.platformContextId, /-7[0-9a-f]{3}-/u);
  assert.match(qaRpcPlatformTrust.runtimeBindingId, /-7[0-9a-f]{3}-/u);
  assert.equal(qaRpcPlatformTrust.targetProfileId, 'devnet-rpc-v1');
});
test('QA ownership rejects missing, foreign and symlinked roots; account secrets remain explicit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'openpc-qa-test-'));
  try {
    await assert.rejects(qaRoot(root));
    await writeFile(join(root, '.openpc-local-runtime-owner'), 'foreign');
    await assert.rejects(qaRoot(root));
    await writeFile(
      join(root, '.openpc-local-runtime-owner'),
      `openpc-local-runtime:openpc-local-e2e-${'a'.repeat(12)}:${'b'.repeat(64)}\n`,
    );
    assert.equal((await qaRoot(root)).project, `openpc-local-e2e-${'a'.repeat(12)}`);
    await symlink(root, root + '-link');
    await assert.rejects(qaRoot(root + '-link'));
    const accounts = Object.fromEntries(
      qaParticipants.flatMap((p) =>
        p.people.map((person) => [
          person.hint,
          { ...person, participantId: p.participantId, password: 'a'.repeat(32) },
        ]),
      ),
    );
    const path = join(root, 'accounts.json');
    await writeFile(path, JSON.stringify(accounts), { mode: 0o600 });
    const loaded = readQaAccounts(path);
    assert.equal(qaPasswordMatches(loaded['qa-a-maker'], 'b'.repeat(32)), false);
    assert.equal(qaPasswordMatches(loaded['qa-a-maker'], 'a'.repeat(32)), true);
    assert.equal(qaPasswordMatches(loaded['qa-a-maker'], undefined), false);
    assert.equal(qaPasswordMatches(loaded['qa-a-maker'], 'é'.repeat(32)), false);
    accounts['qa-b-maker'].principalId = accounts['qa-a-maker'].principalId;
    await writeFile(path, JSON.stringify(accounts));
    assert.throws(() => readQaAccounts(path));
  } finally {
    await rm(root + '-link', { force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test('QA callback configuration excludes ambiguous and unsafe callback targets', () => {
  assert.equal(configuredQaRedirectUri(), 'http://localhost:8080/api/v1/ui/oidc-session/callback');
  for (const value of [
    'http://demo.example.org/api/v1/ui/oidc-session/callback',
    'https://user@demo.example.org/api/v1/ui/oidc-session/callback',
    'https://demo.example.org/api/v1/ui/oidc-session/callback?next=external',
    'https://demo.example.org/api/v1/ui/oidc-session/callback#fragment',
    'https://demo.example.org/api/v1/ui/oidc-session/callback?',
    'https://demo.example.org/api/v1/ui/oidc-session/callback#',
    'https://demo.example.org/other',
    ' https://demo.example.org/api/v1/ui/oidc-session/callback',
    'https://demo.example.org/a/../api/v1/ui/oidc-session/callback',
  ])
    assert.throws(() => configuredQaRedirectUri(value));
});

function recoveryQaAccounts(participantId) {
  return Object.fromEntries(
    ['executor', 'custodian-a', 'custodian-b'].map((role, index) => [
      `qa-recovery-${role}`,
      {
        participantId,
        subject: `018f0000-0000-7000-8000-00000000090${index}`,
        password: String(index + 1).repeat(32),
      },
    ]),
  );
}

test('QA recovery accounts require three distinct external subjects in the original participant', async () => {
  const root = await mkdtemp(join(tmpdir(), 'openpc-qa-recovery-accounts-'));
  try {
    const baseline = Object.fromEntries(
      qaParticipants.flatMap((p) =>
        p.people.map((person) => [
          person.hint,
          { ...person, participantId: p.participantId, password: 'a'.repeat(32) },
        ]),
      ),
    );
    const accounts = { ...baseline, ...recoveryQaAccounts(qaParticipants[0].participantId) };
    const path = join(root, 'accounts.json');
    await writeFile(path, JSON.stringify(accounts), { mode: 0o600 });
    assert.deepEqual(readQaAccounts(path), accounts);
    for (const change of [
      (value) => delete value['qa-a-maker'],
      (value) => delete value['qa-recovery-custodian-b'],
      (value) => (value['unexpected-account'] = value['qa-recovery-executor']),
      (value) => (value['qa-recovery-executor'].participantId = qaParticipants[1].participantId),
      (value) => (value['qa-recovery-executor'].subject = value['qa-a-maker'].principalId),
      (value) => (value['qa-recovery-executor'].subject = value['qa-recovery-custodian-a'].subject),
      (value) => (value['qa-recovery-executor'].principalId = value['qa-a-maker'].principalId),
      (value) => (value['qa-recovery-executor'].password = ''),
      (value) => (value['qa-a-maker'].subject = value['qa-recovery-executor'].subject),
      (value) => (value['qa-recovery-executor'] = null),
    ]) {
      const invalid = structuredClone(accounts);
      change(invalid);
      await writeFile(path, JSON.stringify(invalid));
      assert.throws(() => readQaAccounts(path));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const [configuredRedirect, secureIssuer] of [
  [undefined, false],
  ['https://demo.example.org/api/v1/ui/oidc-session/callback', false],
  ['https://demo.example.org/api/v1/ui/oidc-session/callback', true],
]) {
  test(`QA provider supports exact ${configuredRedirect ? 'HTTPS' : 'localhost'} central sign-in with ${secureIssuer ? 'HTTPS' : 'HTTP'} issuer while binding each private account and enforcing PKCE/code replay`, async () => {
    const root = await mkdtemp(join(tmpdir(), 'openpc-qa-idp-'));
    const names = [
      'OIDC_EMULATOR_ISSUER',
      'OIDC_EMULATOR_PRINCIPAL_ID',
      'OIDC_EMULATOR_VIEWER_PRINCIPAL_ID',
      'OIDC_EMULATOR_PARTICIPANT_ID',
      'OIDC_EMULATOR_LOCAL_QA',
      'OIDC_EMULATOR_QA_ACCOUNTS_FILE',
      'OIDC_EMULATOR_PORT',
      'OIDC_EMULATOR_QA_REDIRECT_URI',
    ];
    const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    let server;
    try {
      const accounts = Object.fromEntries(
        qaParticipants.flatMap((p) =>
          p.people.map((person) => [
            person.hint,
            {
              ...person,
              participantId: p.participantId,
              password: person.hint === 'qa-b-checker' ? 'b'.repeat(32) : 'a'.repeat(32),
            },
          ]),
        ),
      );
      Object.assign(accounts, recoveryQaAccounts(qaParticipants[0].participantId));
      const path = join(root, 'accounts.json');
      await writeFile(path, JSON.stringify(accounts), { mode: 0o600 });
      Object.assign(process.env, {
        OIDC_EMULATOR_ISSUER: secureIssuer ? 'https://qa-idp.test' : 'http://qa-idp.test',
        OIDC_EMULATOR_PRINCIPAL_ID: qaParticipants[0].people[0].principalId,
        OIDC_EMULATOR_VIEWER_PRINCIPAL_ID: qaParticipants[0].people[1].principalId,
        OIDC_EMULATOR_PARTICIPANT_ID: qaParticipants[0].participantId,
        OIDC_EMULATOR_LOCAL_QA: '1',
        OIDC_EMULATOR_QA_ACCOUNTS_FILE: path,
        OIDC_EMULATOR_PORT: '0',
      });
      if (configuredRedirect) process.env.OIDC_EMULATOR_QA_REDIRECT_URI = configuredRedirect;
      else delete process.env.OIDC_EMULATOR_QA_REDIRECT_URI;
      server = startOidcEmulator();
      await once(server, 'listening');
      const origin = `http://127.0.0.1:${server.address().port}`,
        verifier = 'v'.repeat(43);
      const parameters = new URLSearchParams({
        client_id: 'openpc-local-workbench',
        redirect_uri: configuredRedirect ?? 'http://localhost:8080/api/v1/ui/oidc-session/callback',
        state: 's'.repeat(32),
        nonce: 'n'.repeat(32),
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256',
        response_type: 'code',
        login_hint: 'qa-b-checker',
        openpc_test_subject: 'substitution',
        openpc_test_principal_id: qaParticipants[0].people[0].principalId,
      });
      const begin = async (authorization = parameters) => {
        const result = await fetch(`${origin}/authorize?${authorization}`, { redirect: 'manual' });
        assert.equal(result.status, 200);
        const html = await result.text();
        const styleNonce = /<style nonce="([A-Za-z0-9+/=]+)">/u.exec(html)?.[1];
        assert.ok(styleNonce);
        assert.equal(
          result.headers.get('content-security-policy'),
          `default-src 'none'; style-src 'nonce-${styleNonce}'; form-action 'self' ${parameters.get('redirect_uri')}; base-uri 'none'; frame-ancestors 'none'`,
        );
        assert.ok(!html.includes(accounts['qa-b-checker'].password));
        assert.equal(html.includes('name="username"'), !authorization.has('login_hint'));
        if (!authorization.has('login_hint'))
          for (const account of Object.values(accounts)) {
            assert.ok(!html.includes(account.hint));
            assert.ok(!html.includes(account.subject ?? account.principalId));
            assert.ok(!html.includes(account.password));
          }
        const action = /<form method="post" action="([^"]+)">/u.exec(html)?.[1];
        assert.equal(new URL(action, origin).href, `${origin}/authorize`);
        return /name="nonce" value="([A-Za-z0-9_-]+)"/u.exec(html)[1];
      };
      for (const redirect of [
        ...(configuredRedirect
          ? ['http://localhost:8080/api/v1/ui/oidc-session/callback']
          : ['https://demo.example.org/api/v1/ui/oidc-session/callback']),
        'https://unapproved.example/callback',
        'http://127.0.0.1:8080/api/v1/ui/oidc-session/callback',
        'http://localhost:8081/api/v1/ui/oidc-session/callback',
        'http://localhost:8080/unapproved',
        'http://localhost:8080/api/v1/ui/oidc-session/callback?redirect=https://unapproved.example',
        'http://localhost:8080/api/v1/ui/oidc-session/callback#unapproved',
        'http://unapproved@localhost:8080/api/v1/ui/oidc-session/callback',
        ...(configuredRedirect
          ? [
              configuredRedirect + '?redirect=external',
              configuredRedirect + '#unapproved',
              configuredRedirect.replace('demo.example.org', 'unapproved.example.org'),
            ]
          : []),
      ]) {
        const rejectedParameters = new URLSearchParams(parameters);
        rejectedParameters.set('redirect_uri', redirect);
        const result = await fetch(`${origin}/authorize?${rejectedParameters}`, {
          redirect: 'manual',
        });
        assert.equal(result.status, 400);
        assert.equal(result.headers.get('location'), null);
        assert.deepEqual(await result.json(), { error: 'invalid_local_qa_request' });
      }
      for (const field of parameters.keys()) {
        const ambiguous = new URLSearchParams(parameters);
        ambiguous.append(field, parameters.get(field));
        const refused = await fetch(`${origin}/authorize?${ambiguous}`, { redirect: 'manual' });
        assert.equal(refused.status, 400);
        assert.equal(refused.headers.get('location'), null);
        assert.deepEqual(await refused.json(), { error: 'invalid_local_qa_request' });
      }
      const login = async (nonce, password, username) =>
        fetch(`${origin}/authorize`, {
          method: 'POST',
          body: new URLSearchParams({
            nonce,
            password,
            ...(username === undefined ? {} : { username }),
          }),
          redirect: 'manual',
        });
      const expectSignInFailure = async (response) => {
        assert.equal(response.status, 403);
        assert.equal(response.headers.get('location'), null);
        assert.match(response.headers.get('content-type'), /^text\/html\b/u);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        const html = await response.text();
        assert.match(html, /<h1>Sign-in unsuccessful<\/h1>/u);
        assert.match(html, /role="alert"/u);
        const restart = /<a[^>]+href="([^"]+)"[^>]*>Back to sign in<\/a>/u.exec(html)?.[1];
        assert.equal(restart, new URL('/signin', parameters.get('redirect_uri')).href);
        assert.ok(!html.includes('invalid_local_qa_login'));
        assert.ok(!html.includes('name="password"'));
        for (const [username, account] of Object.entries(accounts)) {
          assert.ok(!html.includes(username));
          assert.ok(!html.includes(account.subject ?? account.principalId));
          assert.ok(!html.includes(account.password));
        }
        const styleNonce = /<style nonce="([A-Za-z0-9+/=]+)">/u.exec(html)?.[1];
        assert.ok(styleNonce);
        assert.equal(
          response.headers.get('content-security-policy'),
          `default-src 'none'; style-src 'nonce-${styleNonce}'; form-action 'self' ${parameters.get('redirect_uri')}; base-uri 'none'; frame-ancestors 'none'`,
        );
      };
      const rejected = await begin();
      await expectSignInFailure(await login(rejected, 'bad'));
      await expectSignInFailure(await login(rejected, 'b'.repeat(32)));
      assert.equal((await login(await begin(), 'a'.repeat(32))).status, 403);
      assert.equal((await login(await begin(), 'b'.repeat(32), 'qa-a-maker')).status, 403);
      const nonce = await begin(),
        authenticated = await login(nonce, 'b'.repeat(32));
      assert.equal(authenticated.status, 303);
      assert.equal((await login(nonce, 'b'.repeat(32))).status, 403);
      const callback = new URL(authenticated.headers.get('location'));
      assert.equal(callback.origin + callback.pathname, parameters.get('redirect_uri'));
      assert.equal(callback.searchParams.get('state'), parameters.get('state'));
      assert.deepEqual(
        [...callback.searchParams.keys()].sort(),
        secureIssuer ? ['code', 'iss', 'state'] : ['code', 'state'],
      );
      assert.equal(callback.searchParams.get('iss'), secureIssuer ? 'https://qa-idp.test' : null);
      const code = callback.searchParams.get('code');
      const exchange = async (value) =>
        fetch(`${origin}/token`, {
          method: 'POST',
          body: new URLSearchParams({
            code,
            grant_type: 'authorization_code',
            client_id: 'openpc-local-workbench',
            redirect_uri: parameters.get('redirect_uri'),
            code_verifier: value,
          }),
        });
      assert.equal((await exchange('wrong')).status, 400);
      const tokenInput = {
        code,
        grant_type: 'authorization_code',
        client_id: parameters.get('client_id'),
        redirect_uri: parameters.get('redirect_uri'),
        code_verifier: verifier,
      };
      for (const field of Object.keys(tokenInput)) {
        const ambiguous = new URLSearchParams(tokenInput);
        ambiguous.append(field, 'second-value');
        const refused = await fetch(`${origin}/token`, { method: 'POST', body: ambiguous });
        assert.equal(refused.status, 400);
        assert.deepEqual(await refused.json(), { error: 'invalid_request' });
      }
      const token = await exchange(verifier);
      assert.equal(token.status, 200);
      const claims = JSON.parse(
        Buffer.from((await token.json()).id_token.split('.')[1], 'base64url'),
      );
      assert.equal(claims.sub, qaParticipants[1].people[1].principalId);
      assert.equal(claims.openpc_participant_id, qaParticipants[1].participantId);
      assert.equal((await exchange(verifier)).status, 400);
      const central = new URLSearchParams(parameters);
      central.delete('login_hint');
      for (const username of [
        undefined,
        'unbound-account',
        '__proto__',
        'constructor',
        'qa-a-maker ',
      ]) {
        const refused = await login(await begin(central), 'a'.repeat(32), username);
        await expectSignInFailure(refused);
      }
      for (const [username, account] of Object.entries(accounts)) {
        const centralNonce = await begin(central);
        const accepted = await login(centralNonce, account.password, username);
        assert.equal(accepted.status, 303);
        assert.equal((await login(centralNonce, account.password, username)).status, 403);
        const destination = new URL(accepted.headers.get('location'));
        assert.equal(destination.origin + destination.pathname, central.get('redirect_uri'));
        assert.equal(destination.searchParams.get('state'), central.get('state'));
        const exchanged = await fetch(`${origin}/token`, {
          method: 'POST',
          body: new URLSearchParams({
            code: destination.searchParams.get('code'),
            grant_type: 'authorization_code',
            client_id: central.get('client_id'),
            redirect_uri: central.get('redirect_uri'),
            code_verifier: verifier,
          }),
        });
        assert.equal(exchanged.status, 200);
        const verifiedAccount = JSON.parse(
          Buffer.from((await exchanged.json()).id_token.split('.')[1], 'base64url'),
        );
        assert.equal(verifiedAccount.sub, account.subject ?? account.principalId);
        if (account.subject)
          assert.equal(Object.hasOwn(verifiedAccount, 'openpc_principal_id'), false);
        else assert.equal(verifiedAccount.openpc_principal_id, account.principalId);
        assert.equal(verifiedAccount.openpc_participant_id, account.participantId);
        assert.equal(verifiedAccount.nonce, central.get('nonce'));
      }
      const duplicateNonce = await begin(central);
      const ambiguous = new URLSearchParams({
        nonce: duplicateNonce,
        password: 'a'.repeat(32),
        username: 'qa-a-maker',
      });
      ambiguous.append('username', 'qa-b-checker');
      assert.equal(
        (
          await fetch(`${origin}/authorize`, {
            method: 'POST',
            body: ambiguous,
            redirect: 'manual',
          })
        ).status,
        403,
      );
      assert.equal((await login(duplicateNonce, 'a'.repeat(32), 'qa-a-maker')).status, 403);
      const expiredNonce = await begin();
      const realNow = Date.now;
      try {
        const future = realNow() + 300001;
        Date.now = () => future;
        await expectSignInFailure(await login(expiredNonce, 'b'.repeat(32)));
      } finally {
        Date.now = realNow;
      }
    } finally {
      if (server) await new Promise((resolve) => server.close(resolve));
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      await rm(root, { recursive: true, force: true });
    }
  });
}

test('protected proof fixture keeps its key private while making the mount traversable under a private umask', async () => {
  const root = await mkdtemp(join(tmpdir(), 'openpc-qa-mount-'));
  const previous = process.umask(0o077);
  try {
    const bin = join(root, 'bin');
    await mkdir(bin);
    await writeFile(
      join(bin, 'docker'),
      `#!/bin/sh
if [ "$1" = image ]; then
  printf '%s\n' '[{"Config":{"Labels":{"io.openpc.image.owner":"openpc-r1-local-runtime-v1","io.openpc.image.service":"control-api"}}}]'
fi
`,
      { mode: 0o700 },
    );
    const invoke = () =>
      spawnSync(
        process.execPath,
        [
          'tests/integration/local-runtime/protected-proof-fixture.mjs',
          root,
          'sha256:' + 'a'.repeat(64),
        ],
        { encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH } },
      );
    const first = invoke();
    assert.equal(first.status, 0, first.stderr);
    const key = join(root, 'protected-proofs/encryption.key'),
      original = await readFile(key);
    assert.equal((await stat(root)).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, 'protected-proofs'))).mode & 0o777, 0o755);
    assert.equal((await stat(key)).mode & 0o777, 0o600);
    const second = invoke();
    assert.equal(second.status, 0, second.stderr);
    assert.deepEqual(await readFile(key), original);
  } finally {
    process.umask(previous);
    await rm(root, { recursive: true, force: true });
  }
});

const qaDurationFlags = {
  OPENPC_LOCAL_RUNTIME: '1',
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
  OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
};
test('QA duration profile requires all guards and keeps normal setup unchanged', () => {
  assert.deepEqual(qaDurationComposeOverlay('/repo', {}), { services: {} });
  const active = qaDurationComposeOverlay('/repo', qaDurationFlags);
  assert.deepEqual(Object.keys(active.services).sort(), [
    'admin-web',
    'control-api',
    'envoy',
    'identity-service',
    'policy-service',
  ]);
  for (const service of ['admin-web', 'control-api', 'policy-service'])
    assert.deepEqual(active.services[service].environment, qaDurationFlags);
  assert.deepEqual(active.services['identity-service'].environment, {
    ...qaDurationFlags,
    IDENTITY_RECOVERY_LEASE_TTL_MS: '172800000',
    IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: '36000000',
  });
  for (const key of Object.keys(qaDurationFlags)) {
    const changed = { ...qaDurationFlags };
    delete changed[key];
    if (key === 'OPENPC_LOCAL_QA_DURATION_PROFILE')
      assert.deepEqual(qaDurationComposeOverlay('/repo', changed), { services: {} });
    else assert.throws(() => qaDurationComposeOverlay('/repo', changed));
  }
  for (const value of ['', '0', 'NORMAL', 'unknown'])
    assert.throws(() =>
      qaDurationComposeOverlay('/repo', {
        ...qaDurationFlags,
        OPENPC_LOCAL_QA_DURATION_PROFILE: value,
      }),
    );
});
test('QA duration switchback removes inherited profile without altering retained environment', () => {
  const original = { OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1', PRIVATE_INPUT: 'retained' };
  const normal = qaDurationEnvironment(qaDurationFlags, original, 'NORMAL');
  assert.equal(Object.hasOwn(normal, 'OPENPC_LOCAL_QA_DURATION_PROFILE'), false);
  assert.equal(normal.PRIVATE_INPUT, 'retained');
  assert.equal(Object.hasOwn(original, 'OPENPC_LOCAL_QA_DURATION_PROFILE'), false);
  assert.throws(() => qaDurationEnvironment({}, {}, 'LOCAL_QA_10X'));
});
test('QA duration configuration rejects foreign duplicate writable and unrelated mount changes', () => {
  const before = {
    networks: { owned: {} },
    services: {
      'envoy': {
        image: 'pinned',
        volumes: [
          {
            type: 'bind',
            source: '/repo/deploy/compose/local/envoy/local-gateway.yaml',
            target: '/etc/envoy/envoy.yaml',
            read_only: true,
          },
        ],
      },
      'admin-web': { environment: { existing: 'keep' }, volumes: [] },
      'identity-service': {
        environment: {
          existing: 'keep',
          IDENTITY_RECOVERY_LEASE_TTL_MS: '900000',
          IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: '3600000',
        },
      },
      'control-api': { environment: { existing: 'keep' } },
      'policy-service': { environment: { existing: 'keep' } },
      'oidc-emulator': { environment: { keep: 'old-key-process' } },
      'control-pg': { volumes: [{ source: 'original', target: '/data' }] },
    },
  };
  const after = structuredClone(before),
    overlay = qaDurationComposeOverlay('/repo', qaDurationFlags);
  for (const [name, value] of Object.entries(overlay.services)) {
    if (value.environment)
      after.services[name].environment = {
        ...after.services[name].environment,
        ...value.environment,
      };
    if (value.volumes) after.services[name].volumes = value.volumes;
  }
  validateQaDurationConfiguration(before, after, '/repo', 'LOCAL_QA_10X');
  assert.equal(
    after.services['identity-service'].environment.IDENTITY_RECOVERY_LEASE_TTL_MS,
    '172800000',
  );
  assert.equal(
    after.services['identity-service'].environment.IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS,
    '36000000',
  );
  assert.equal(
    before.services['identity-service'].environment.IDENTITY_RECOVERY_LEASE_TTL_MS,
    '900000',
  );
  assert.equal(
    before.services['identity-service'].environment.IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS,
    '3600000',
  );
  for (const change of [
    (v) => (v.services['identity-service'].environment.IDENTITY_RECOVERY_LEASE_TTL_MS = '900000'),
    (v) =>
      (v.services['identity-service'].environment.IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS =
        '3600000'),
    (v) => (v.services['admin-web'].environment.IDENTITY_RECOVERY_LEASE_TTL_MS = '172800000'),
    (v) => (v.services.envoy.volumes[0].source = '/foreign'),
    (v) => v.services.envoy.volumes.push(v.services.envoy.volumes[0]),
    (v) => (v.services.envoy.volumes[0].read_only = false),
    (v) => (v.services['control-pg'].volumes[0].source = 'new'),
    (v) => (v.services['oidc-emulator'].environment.keep = 'new-key'),
    (v) => (v.networks.owned.subnet = 'changed'),
    (v) => (v.services.envoy.image = 'unpinned'),
  ]) {
    const changed = structuredClone(after);
    change(changed);
    assert.throws(() => validateQaDurationConfiguration(before, changed, '/repo', 'LOCAL_QA_10X'));
  }
  validateQaDurationConfiguration(before, before, '/repo', 'NORMAL');
});
test('QA duration invalid startup rejects before setup dispatch or allocation', () => {
  for (const flags of [
    { OPENPC_LOCAL_QA_DURATION_PROFILE: '' },
    { OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X' },
    { ...qaDurationFlags, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0' },
  ]) {
    const child = spawnSync('bash', ['tests/integration/local-runtime/run-compose-e2e.sh'], {
      env: { ...process.env, ...flags },
      encoding: 'utf8',
    });
    assert.equal(child.status, 96);
    assert.equal(child.stdout, '');
    assert.equal(child.stderr, '');
  }
});
