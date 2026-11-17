import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  cleanupRpcEnospcRuntime,
  inspectRpcEnospcRuntime,
  planRpcEnospcRuntime,
  prepareRpcEnospcRuntime,
  resolveRpcEnospcConfiguration,
  retainRpcEnospcRuntime,
  retainedRpcEnospcReservation,
  otherRetainedRpcEnospcReservation,
  restoreRpcEnospcRuntime,
  rpcEnospcCompose,
  rpcEnospcRuntime,
} from './rpc-journal-enospc-runtime.mjs';

// Model only the external Docker boundary. These orchestration regressions do
// not claim a physical filesystem, cgroup admission, or product journey pass.
test('CLI retention diagnostics classify invalid inputs without exposing values or child commands', () => {
  assert.throws(
    () =>
      execFileSync(
        process.execPath,
        [
          'tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs',
          'retain',
          '/owned/private-root',
          '{private-owner-token',
        ],
        { encoding: 'utf8', stdio: 'pipe' },
      ),
    (error) => {
      assert.equal(error.status, 1);
      assert.match(
        error.stderr,
        /OPENPC_RPC_ENOSPC_RUNTIME\|FAIL\|phase=retain\|reason=input-json\|source_line=\d+\|retain-originals/u,
      );
      assert.doesNotMatch(
        error.stderr,
        /private-owner-token|private-root|SyntaxError|Command failed/u,
      );
      return true;
    },
  );
});
const repository = fileURLToPath(new URL('../../../', import.meta.url));
const fixtureSource = fileURLToPath(new URL('./rpc-journal-crash-fixture.mjs', import.meta.url));
const keeperId = '1'.repeat(64),
  targetId = '2'.repeat(64);
const imageId = `sha256:${'3'.repeat(64)}`;
const targetRuntimeId = '018f0000-0000-7000-8000-000000009999';
const startTime = '2026-09-24T01:00:00.000000000Z';
const ownerToken = 'a'.repeat(64),
  project = `openpc-local-e2e-${ownerToken.slice(0, 12)}`;
const clone = (value) => structuredClone(value);

async function setup(t) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
  const root = await mkdtemp(join(parent, 'rpc-enospc-contract-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'evidence/runtime-bootstrap'), { recursive: true });
  await mkdir(join(root, 'data/runtime-bootstrap/runtime'), { recursive: true });
  await writeFile(
    join(root, '.openpc-local-runtime-owner'),
    `openpc-local-runtime:${project}:${ownerToken}\n`,
  );
  const metadata = await planRpcEnospcRuntime(root, targetRuntimeId);
  const inputPath = join(root, 'evidence/runtime-bootstrap/discovery-credential-input.json');
  const input = {
    targetId: targetRuntimeId,
    credentialId: 'preserve-original-credential',
    rpcJournalEnospc: metadata,
  };
  await writeFile(inputPath, JSON.stringify(input));
  const topology = rpcEnospcCompose(metadata);
  const composePath = join(root, 'data/runtime-bootstrap/compose.json');
  const rendered = {
    'x-openpc-rpc-enospc': topology.extension,
    'volumes': topology.volumes,
    'services': {
      'rpc-provider': { image: rpcEnospcRuntime.image },
      'runtime-target': {
        environment: topology.targetEnvironment,
        volumes: [
          topology.targetMount,
          {
            type: 'bind',
            source: join(root, 'data/runtime-bootstrap/runtime'),
            target: '/runtime',
          },
        ],
      },
    },
  };
  await writeFile(composePath, JSON.stringify(rendered));
  const compose = [
    'docker',
    'compose',
    '-p',
    project,
    '-f',
    join(repository, 'deploy/compose/local/compose.yaml'),
    '-f',
    composePath,
  ];
  const labels = {
    'io.openpc.fixture': 'rpc-journal-enospc',
    'io.openpc.fixture.token': metadata.identity.token,
    'io.openpc.fixture.project': project,
    'io.openpc.fixture.target': targetRuntimeId,
    'io.openpc.fixture.owner': ownerToken,
  };
  const keeperTemplate = {
    Name: `/${metadata.identity.volumeName}-keeper`,
    Id: keeperId,
    Image: imageId,
    Config: {
      Image: rpcEnospcRuntime.image,
      User: '65532:65532',
      Labels: labels,
      Entrypoint: ['node'],
      Cmd: [
        '-e',
        'if(process.getuid()!==65532||process.getgid()!==65532)process.exit(96);setInterval(()=>{},1000)',
        metadata.identity.token,
      ],
    },
    State: { Running: true, StartedAt: startTime },
    HostConfig: {
      Privileged: false,
      ReadonlyRootfs: true,
      NetworkMode: 'none',
      CapDrop: ['ALL'],
      CapAdd: null,
      SecurityOpt: ['no-new-privileges:true'],
      Memory: 256 * 1024 ** 2,
      MemorySwap: 256 * 1024 ** 2,
      NanoCpus: 250000000,
      PidsLimit: 64,
      RestartPolicy: { Name: 'no' },
    },
    Mounts: [
      {
        Type: 'volume',
        Name: metadata.identity.volumeName,
        Destination: '/openpc-spool-enospc',
        RW: true,
      },
      {
        Type: 'bind',
        Source: fixtureSource,
        Destination: '/openpc-rpc-journal-fixture.mjs',
        RW: false,
      },
      {
        Type: 'bind',
        Source: join(root, 'data/runtime-bootstrap/runtime/rpc-enospc'),
        Destination: '/openpc-rpc-enospc-control',
        RW: true,
      },
    ],
  };
  const volumeTemplate = {
    Name: metadata.identity.volumeName,
    Driver: 'local',
    Labels: labels,
    Options: {
      type: 'tmpfs',
      device: 'tmpfs',
      o: 'size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
    },
  };
  const filesystem = {
    type: '16914836',
    bytes: 64 * 1024 ** 2,
    blockSize: 4096,
    availableBlocks: 1000,
    freeInodes: 1000,
    uid: 65532,
    gid: 65532,
    mode: 0o700,
    device: '41',
    inode: '42',
  };
  const target = {
    Id: targetId,
    State: { Running: true },
    Config: {
      User: '65532:65532',
      Labels: {
        'com.docker.compose.project': project,
        'com.docker.compose.service': 'runtime-target',
      },
    },
    Mounts: [
      {
        Type: 'volume',
        Name: metadata.identity.volumeName,
        Destination: `/runtime/evidence/${targetRuntimeId}`,
        RW: true,
      },
    ],
  };
  const model = {
    keeper: null,
    volume: null,
    target: null,
    foreignUsers: [],
    calls: [],
    fail: null,
    filesystem,
    rendered,
    claimed: false,
    archive: {
      archiveDigest: `sha256:${'7'.repeat(64)}`,
      entries: {
        '': { type: 'directory', mode: 448, uid: 65532, gid: 65532, size: 0 },
        'original-journal': {
          type: 'file',
          mode: 384,
          uid: 65532,
          gid: 65532,
          size: 123,
          digest: '8'.repeat(64),
        },
      },
    },
    restoredEntries: null,
  };
  const out = (value) => ({
    stdout: typeof value === 'string' ? value : JSON.stringify(value),
    stderr: '',
  });
  const execute = async (command, args) => {
    model.calls.push([command, ...args]);
    const failure = model.fail?.(command, args);
    if (failure) throw failure;
    if (command === 'bash') {
      assert.ok(args.includes('--reuse') || args.includes('rpc-enospc-guard'));
      return out('');
    }
    if (command === 'python3') {
      assert.ok(args[0].endsWith('/rpc-journal-enospc-archive.py'));
      if (args[1] === 'copy') {
        assert.equal((await load()).rpcJournalEnospc.state, 'restoring');
        assert.equal(args.at(-1), model.archive.archiveDigest);
        model.restoredEntries = clone(model.archive.entries);
        model.claimed = true;
      } else assert.equal(args[1], 'inspect');
      return out(model.archive);
    }
    assert.equal(command, 'docker');
    if (args[0] === 'compose') {
      if (args.includes('config')) return out(model.rendered);
      assert.ok(args.includes('ps'));
      return out(model.target ? targetId : '');
    }
    if (args[0] === 'ps') {
      const filter = args.at(-1);
      if (filter.startsWith('label=') || filter.startsWith('name='))
        return out(model.keeper ? keeperId : '');
      assert.equal(filter, `volume=${metadata.identity.volumeName}`);
      return out(
        [
          ...(model.keeper ? [keeperId] : []),
          ...(model.target ? [targetId] : []),
          ...model.foreignUsers,
        ].join('\n'),
      );
    }
    if (args[0] === 'volume') {
      if (args[1] === 'ls') return out(model.volume ? metadata.identity.volumeName : '');
      if (args[1] === 'inspect') return out([model.volume]);
      if (args[1] === 'create') {
        assert.equal((await load()).rpcJournalEnospc.state, 'allocating');
        model.volume = clone(volumeTemplate);
        return out(metadata.identity.volumeName);
      }
      if (args[1] === 'rm') {
        assert.equal(model.keeper, null, 'Last mount must be released before volume deletion');
        model.volume = null;
        return out(metadata.identity.volumeName);
      }
    }
    if (args[0] === 'image') return out([{ Id: imageId }]);
    if (args[0] === 'create') {
      model.keeper = clone(keeperTemplate);
      model.keeper.State.Running = false;
      return out(keeperId);
    }
    if (args[0] === 'start') {
      model.keeper.State.Running = true;
      return out(keeperId);
    }
    if (args[0] === 'inspect')
      return out(args.slice(1).map((id) => (id === keeperId ? model.keeper : model.target)));
    if (args[0] === 'exec') {
      if (args.includes('-e') && args.at(-1).includes("visit('')"))
        return out(model.restoredEntries ?? { '': model.archive.entries[''] });
      if (args.includes('--enospc')) {
        const action = args[args.indexOf('--enospc') + 1];
        if (action === 'claim') {
          assert.equal(model.claimed, false);
          model.claimed = true;
        } else assert.equal(action, 'inspect');
        assert.equal(model.claimed, true);
        return out({ identity: metadata.identity, filesystem: model.filesystem });
      }
      return out('');
    }
    if (args[0] === 'rm') {
      assert.deepEqual(args, ['rm', '-f', keeperId]);
      assert.equal((await load()).rpcJournalEnospc.state, 'releasing');
      model.keeper = null;
      return out(keeperId);
    }
    throw Error(`Unexpected external command: ${args[0]}`);
  };
  const load = async () => JSON.parse(await readFile(inputPath, 'utf8'));
  const mutations = () =>
    model.calls.filter(
      ([command, ...args]) =>
        command === 'docker' &&
        (['create', 'start', 'rm', 'exec'].includes(args[0]) ||
          (args[0] === 'volume' && ['create', 'rm'].includes(args[1]))),
    );
  const prepare = () => prepareRpcEnospcRuntime(root, compose, { execute });
  return {
    root,
    compose,
    inputPath,
    input,
    metadata,
    model,
    execute,
    load,
    mutations,
    prepare,
    target,
    keeperTemplate,
    volumeTemplate,
  };
}

test('preparation pins the keeper before target startup and reuses the same claim', async (t) => {
  const f = await setup(t);
  assert.equal(rpcEnospcRuntime.additionalExternalMemoryBytes, 320 * 1024 ** 2);
  assert.equal((await f.prepare()).disposition, 'ready');
  const input = await f.load();
  assert.equal(input.credentialId, f.input.credentialId);
  assert.equal(input.rpcJournalEnospc.keeper.id, keeperId);
  const create = f.model.calls.find((call) => call[1] === 'create');
  for (const argument of [
    '--read-only',
    '--network',
    'none',
    '--cap-drop',
    'ALL',
    '--memory',
    '256m',
    '--memory-swap',
    '--pids-limit',
    '64',
    '--restart',
    'no',
  ])
    assert.ok(create.includes(argument));
  assert.ok(!create.some((value) => value.startsWith('com.docker.compose.')));
  assert.ok(
    create.includes(
      'type=volume,src=' +
        f.metadata.identity.volumeName +
        ',dst=/openpc-spool-enospc,volume-nocopy',
    ),
  );
  const firstMutation = f.model.calls.findIndex(
    (call) => call[1] === 'volume' && call[2] === 'create',
  );
  const admission = f.model.calls.findIndex((call) => call.includes('--reuse'));
  assert.ok(admission >= 0 && admission < firstMutation);
  const previous = f.mutations().length;
  await f.prepare();
  assert.ok(
    f
      .mutations()
      .slice(previous)
      .every((call) => call.includes('inspect')),
  );
  assert.deepEqual(await f.load(), input);
});

test('missing lifecycle hook or insufficient admission fails before any allocation', async (t) => {
  for (const boundary of ['rpc-enospc-guard', '--reuse']) {
    const f = await setup(t);
    const original = Error(boundary);
    f.model.fail = (command, args) =>
      command === 'bash' && args.includes(boundary) ? original : null;
    await assert.rejects(f.prepare(), (error) => error === original);
    assert.equal(f.mutations().length, 0);
    assert.equal((await f.load()).rpcJournalEnospc.state, 'planned');
  }
});

test('read-only retained inspection keeps ownership and integrity without allocating the full runtime', async (t) => {
  const f = await setup(t);
  await f.prepare();
  const input = await f.load();
  f.model.calls.length = 0;
  const unavailable = Error('Full runtime admission unavailable');
  f.model.fail = (command, args) =>
    command === 'bash' && args.includes('--reuse') ? unavailable : null;
  assert.equal(
    (await inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute })).disposition,
    'ready',
  );
  assert.ok(f.model.calls.some((call) => call.includes('rpc-enospc-guard')));
  assert.ok(!f.model.calls.some((call) => call.includes('--reuse')));
  assert.ok(f.mutations().every((call) => call[1] === 'exec' && call.includes('inspect')));
  assert.deepEqual(await f.load(), input);
  await assert.rejects(f.prepare(), (error) => error === unavailable);
  f.model.fail = (command, args) =>
    command === 'bash' && args.includes('rpc-enospc-guard') ? unavailable : null;
  await assert.rejects(
    inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute }),
    (error) => error === unavailable,
  );
});

test('no allocation from a mismatched owner, project, target mount or resource declaration', async (t) => {
  for (const mutate of [
    (f) => {
      f.compose[3] = 'foreign';
    },
    (f) => {
      f.model.rendered['x-openpc-rpc-enospc'].additionalExternalMemoryBytes = 0;
    },
    (f) => {
      f.model.rendered.services['runtime-target'].volumes[0].volume.nocopy = false;
    },
    (f) => {
      f.model.rendered.services['rpc-provider'].image = 'node:latest';
    },
    async (f) => {
      const input = await f.load();
      input.rpcJournalEnospc.ownerToken = 'b'.repeat(64);
      await writeFile(f.inputPath, JSON.stringify(input));
    },
    async (f) => {
      await rm(f.inputPath);
      await symlink(join(f.root, '.openpc-local-runtime-owner'), f.inputPath);
    },
  ]) {
    const f = await setup(t);
    await mutate(f);
    await assert.rejects(f.prepare());
    assert.equal(f.mutations().length, 0);
  }
});

test('interrupted volume, keeper, start and claim operations retain intent without replay', async (t) => {
  for (const boundary of ['volume', 'create', 'start', 'claim']) {
    const f = await setup(t);
    const original = Error(`interrupted ${boundary}`);
    f.model.fail = (command, args) => {
      if (command !== 'docker') return null;
      if (boundary === 'volume')
        return args[0] === 'volume' && args[1] === 'create' ? original : null;
      if (boundary === 'claim')
        return args.includes('--enospc') && args.includes('claim') ? original : null;
      return args[0] === boundary ? original : null;
    };
    await assert.rejects(f.prepare(), (error) => error === original);
    assert.equal((await f.load()).rpcJournalEnospc.state, 'allocating');
    f.model.fail = null;
    const count = f.mutations().length;
    await assert.rejects(f.prepare(), /Never replay/u);
    assert.equal(f.mutations().length, count);
    const retained = await cleanupRpcEnospcRuntime(f.root, f.compose, {
      execute: f.execute,
      status: 1,
    });
    assert.equal(retained.disposition, 'retain');
    assert.equal(retained.dataCleanupSafe, false);
    assert.equal(f.mutations().length, count);
    await assert.rejects(
      cleanupRpcEnospcRuntime(f.root, f.compose, { execute: f.execute, status: 0 }),
      /Uncertain allocation/u,
    );
  }
});

test('retained startup rejects keeper restart, altered tmpfs, ownership and security drift', async (t) => {
  for (const mutate of [
    (f) => {
      f.model.keeper.State.StartedAt = '2026-09-24T02:00:00Z';
    },
    (f) => {
      f.model.keeper.State.Running = false;
    },
    (f) => {
      f.model.filesystem.inode = '43';
    },
    (f) => {
      f.model.filesystem.bytes *= 2;
    },
    (f) => {
      f.model.keeper.Config.Labels['com.docker.compose.project'] = project;
    },
    (f) => {
      f.model.keeper.Config.Labels['io.openpc.fixture.owner'] = 'b'.repeat(64);
    },
    (f) => {
      f.model.keeper.HostConfig.Memory = 0;
    },
    (f) => {
      f.model.keeper.HostConfig.NetworkMode = 'host';
    },
    (f) => {
      f.model.keeper.HostConfig.CapAdd = ['SYS_ADMIN'];
    },
    (f) => {
      f.model.volume.Options.o += ',size=128m';
    },
    (f) => {
      f.model.foreignUsers.push('4'.repeat(64));
    },
  ]) {
    const f = await setup(t);
    await f.prepare();
    mutate(f);
    const before = f.mutations().filter((call) => call[1] !== 'exec').length;
    await assert.rejects(inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute }));
    assert.equal(f.mutations().filter((call) => call[1] !== 'exec').length, before);
    assert.equal((await f.load()).rpcJournalEnospc.state, 'ready');
  }
});

test('only the exact live target gets physical configuration; stopped targets still retain their mount', async (t) => {
  const f = await setup(t);
  await f.prepare();
  f.model.target = clone(f.target);
  const result = await resolveRpcEnospcConfiguration(f.root, f.compose, targetRuntimeId, targetId, {
    execute: f.execute,
  });
  assert.deepEqual(result, {
    keeperContainerId: keeperId,
    token: f.metadata.identity.token,
    volumeName: f.metadata.identity.volumeName,
  });
  await assert.rejects(
    resolveRpcEnospcConfiguration(f.root, f.compose, targetRuntimeId, '5'.repeat(64), {
      execute: f.execute,
    }),
  );
  await assert.rejects(
    cleanupRpcEnospcRuntime(f.root, f.compose, { execute: f.execute, status: 0 }),
    /target consumers/u,
  );
  const retained = await retainRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
  assert.equal(retained.keeperRunning, true);
  assert.equal(retained.dataCleanupSafe, false);
  f.model.target.State.Running = false;
  await assert.rejects(
    resolveRpcEnospcConfiguration(f.root, f.compose, targetRuntimeId, targetId, {
      execute: f.execute,
    }),
  );
  await retainRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
  f.model.target.State.Running = true;
  f.model.target.Mounts[0].Name = 'foreign-volume';
  await assert.rejects(
    resolveRpcEnospcConfiguration(f.root, f.compose, targetRuntimeId, targetId, {
      execute: f.execute,
    }),
  );
});

test('success and explicit retention preserve originals until exact cleanup is permitted', async (t) => {
  const f = await setup(t);
  await f.prepare();
  const original = await f.load();
  for (const options of [{ status: 1 }, { status: 0, retain: true }]) {
    const result = await cleanupRpcEnospcRuntime(f.root, f.compose, {
      ...options,
      execute: f.execute,
    });
    assert.equal(result.dataCleanupSafe, false);
    assert.ok(f.model.keeper && f.model.volume);
    assert.deepEqual(await f.load(), original);
  }
  const result = await cleanupRpcEnospcRuntime(f.root, f.compose, {
    execute: f.execute,
    status: 0,
  });
  assert.deepEqual(result, { disposition: 'released', dataCleanupSafe: true });
  const removal = f.model.calls.filter(
    (call) => call[1] === 'rm' || (call[1] === 'volume' && call[2] === 'rm'),
  );
  assert.deepEqual(
    removal.map((call) => call.slice(0, 3)),
    [
      ['docker', 'rm', '-f'],
      ['docker', 'volume', 'rm'],
    ],
  );
  assert.equal((await f.load()).credentialId, original.credentialId);
  assert.equal((await f.load()).rpcJournalEnospc.state, 'released');
  await cleanupRpcEnospcRuntime(f.root, f.compose, { execute: f.execute, status: 0 });
});

test('cleanup interruption resumes release only and refuses a new consumer', async (t) => {
  for (const boundary of ['rm', 'volume']) {
    const f = await setup(t);
    await f.prepare();
    const original = Error('cleanup interrupted');
    f.model.fail = (command, args) =>
      command === 'docker' &&
      (boundary === 'rm' ? args[0] === 'rm' : args[0] === 'volume' && args[1] === 'rm')
        ? original
        : null;
    await assert.rejects(
      cleanupRpcEnospcRuntime(f.root, f.compose, { execute: f.execute, status: 0 }),
      (error) => error === original,
    );
    assert.equal((await f.load()).rpcJournalEnospc.state, 'releasing');
    f.model.fail = null;
    f.model.foreignUsers.push('6'.repeat(64));
    await assert.rejects(
      cleanupRpcEnospcRuntime(f.root, f.compose, { execute: f.execute, status: 0 }),
      /target consumers/u,
    );
    f.model.foreignUsers = [];
    const result = await cleanupRpcEnospcRuntime(f.root, f.compose, {
      execute: f.execute,
      status: 0,
    });
    assert.equal(result.dataCleanupSafe, true);
    assert.equal(f.model.calls.filter((call) => call[1] === 'create').length, 1);
  }
});

async function rebooted(t) {
  const f = await setup(t);
  await f.prepare();
  const original = await f.load();
  // Docker's original keeper is absent; only its durable binding and volume remain.
  original.rpcJournalEnospc.keeper.id = '9'.repeat(64);
  original.rpcJournalEnospc.keeper.startedAt = '2026-09-23T01:00:00.000000000Z';
  await writeFile(f.inputPath, JSON.stringify(original));
  f.model.keeper = null;
  f.model.claimed = false;
  f.model.calls.length = 0;
  f.restore = () => restoreRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
  return f;
}

test('explicit reboot restoration preserves original lineage and exact bytes without permitting stale inspection', async (t) => {
  const f = await rebooted(t);
  await assert.rejects(inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute }));
  const result = await f.restore();
  assert.equal(result.disposition, 'restored');
  const restored = (await f.load()).rpcJournalEnospc;
  assert.equal(restored.recovery.previousKeeper.id, '9'.repeat(64));
  assert.equal(restored.recovery.archiveDigest, f.model.archive.archiveDigest);
  assert.deepEqual(f.model.restoredEntries, f.model.archive.entries);
  await inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
  f.model.keeper.State.StartedAt = '2026-09-26T00:00:00.000000000Z';
  await assert.rejects(inspectRpcEnospcRuntime(f.root, f.compose, { execute: f.execute }));
  await assert.rejects(f.restore(), /prior recovery/u);
});

test('restore refuses existing consumers, absent original volumes and archive failure before mutation', async (t) => {
  for (const drift of ['consumer', 'keeper', 'volume', 'archive']) {
    const f = await rebooted(t);
    if (drift === 'consumer') f.model.foreignUsers.push(targetId);
    if (drift === 'keeper') f.model.keeper = clone(f.keeperTemplate);
    if (drift === 'volume') f.model.volume = null;
    if (drift === 'archive')
      f.model.fail = (command) => (command === 'python3' ? Error('archive rejected') : null);
    await assert.rejects(f.restore());
    assert.equal(f.mutations().length, 0);
    assert.equal((await f.load()).rpcJournalEnospc.state, 'ready');
  }
});

test('interrupted restore and nonempty mounts retain the exact pending lineage without replay', async (t) => {
  for (const phase of ['create', 'copy', 'nonempty', 'readback']) {
    const f = await rebooted(t);
    if (phase === 'nonempty') f.model.restoredEntries = { ...f.model.archive.entries };
    f.model.fail = (command, args) => {
      if (
        (phase === 'create' && command === 'docker' && args[0] === 'create') ||
        (phase === 'copy' && command === 'python3' && args[1] === 'copy')
      )
        return Error('interrupted');
      if (
        phase === 'readback' &&
        command === 'docker' &&
        args[0] === 'exec' &&
        f.model.restoredEntries
      )
        f.model.restoredEntries['original-journal'].digest = '0'.repeat(64);
      return null;
    };
    await assert.rejects(f.restore());
    const pending = (await f.load()).rpcJournalEnospc;
    assert.equal(pending.state, 'restoring');
    assert.equal(pending.recovery.previousKeeper.id, '9'.repeat(64));
    const before = f.mutations().length;
    await assert.rejects(f.restore(), /Interrupted recovery/u);
    assert.equal(f.mutations().length, before);
  }
});

test('real archive parser rejects traversal, links, special files, duplicate paths and altered scope or metadata', async (t) => {
  const f = await setup(t);
  const directory = join(f.root, 'data/restart-preservation');
  await mkdir(directory, { mode: 0o700 });
  const archive = join(directory, 'owned.tar');
  const helper = join(repository, 'tests/integration/local-runtime/rpc-journal-enospc-archive.py');
  const identity = JSON.stringify(f.metadata.identity);
  const create = String.raw`import tarfile,io,json,sys,os
path,identity,scenario=sys.argv[1:]
with tarfile.open(path,'w') as t:
 def add(name,data=b'',kind=tarfile.REGTYPE):
  m=tarfile.TarInfo(name);m.uid=m.gid=65532;m.mode=0o700 if kind==tarfile.DIRTYPE else 0o600;m.type=kind;m.size=len(data)
  if scenario=='uid' and name=='.openpc-enospc-owner':m.uid=0
  if scenario=='mode' and name=='.openpc-enospc-owner':m.mode=0o644
  if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):m.linkname='../../outside'
  t.addfile(m,io.BytesIO(data))
 add('.',kind=tarfile.DIRTYPE)
 add('.openpc-enospc-owner', b'{}' if scenario=='scope' else identity.encode())
 if scenario=='traversal':add('../escape',b'x')
 elif scenario=='absolute':add('/escape',b'x')
 elif scenario=='symlink':add('link',kind=tarfile.SYMTYPE)
 elif scenario=='hardlink':add('link',kind=tarfile.LNKTYPE)
 elif scenario=='fifo':add('fifo',kind=tarfile.FIFOTYPE)
 elif scenario=='duplicate':add('.openpc-enospc-owner',identity.encode())
 elif scenario=='missing-parent':add('absent/file',b'x')
 else:add('journal',b'original bytes')
os.chmod(path,0o600)
`;
  for (const scenario of [
    'valid',
    'uid',
    'mode',
    'scope',
    'traversal',
    'absolute',
    'symlink',
    'hardlink',
    'fifo',
    'duplicate',
    'missing-parent',
  ]) {
    execFileSync('python3', ['-c', create, archive, identity, scenario]);
    const inspect = () =>
      execFileSync('python3', [helper, 'inspect', archive, identity], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    if (scenario === 'valid') {
      const value = JSON.parse(inspect());
      assert.equal(value.entries.journal.size, 14);
      assert.match(value.archiveDigest, /^sha256:[0-9a-f]{64}$/u);
      const substitute = String.raw`import hashlib,importlib.util,json,os,sys
sys.dont_write_bytecode=True
helper,path,identity,phase=sys.argv[1:]
spec=importlib.util.spec_from_file_location('archive_owner',helper)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=open(path,'rb').read();expected='sha256:'+hashlib.sha256(original).hexdigest()
calls=[]
def replace():
 os.rename(path,path+'.original')
 with open(path+'.foreign','wb') as f:f.write(b'foreign bytes')
 os.symlink(path+'.foreign',path)
def copy(*args,**kwargs):
 calls.append(args)
 if phase=='during':replace()
 assert kwargs['stdin'].read()==original
m.subprocess.run=copy
inspect=m.inspect_archive
def checked(*args):
 result=inspect(*args)
 if phase=='before':replace()
 return result
m.inspect_archive=checked
try:
 try:result=m.run_archive('copy',path,json.loads(identity),['a'*64,expected])
 except AssertionError:
  assert phase!='valid'
 else:
  assert phase=='valid' and result['archiveDigest']==expected
 assert len(calls)==(0 if phase=='before' else 1)
finally:
 if os.path.lexists(path+'.original'):
  os.unlink(path);os.rename(path+'.original',path);os.unlink(path+'.foreign')
`;
      for (const phase of ['valid', 'before', 'during'])
        execFileSync('python3', ['-c', substitute, helper, archive, identity, phase], {
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      await chmod(archive, 0o644);
      assert.throws(inspect);
    } else assert.throws(inspect, scenario);
  }
});

test('retained reservation verifies whole keeper and tmpfs once across planned and retained inventory', async (t) => {
  const f = await setup(t);
  assert.equal(await retainedRpcEnospcReservation({ execute: f.execute }), 0);
  await prepareRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
  f.model.calls.length = 0;
  const original = await f.load();
  assert.equal(await retainedRpcEnospcReservation({ execute: f.execute }), 320 * 1024 ** 2);
  assert.deepEqual(await f.load(), original);
  assert.ok(
    f.model.calls.every(
      ([command, action, operation]) =>
        command === 'docker' &&
        (action === 'ps' ||
          action === 'inspect' ||
          (action === 'volume' && operation === 'inspect')),
    ),
  );
  assert.equal(f.model.calls.filter(([, action]) => action === 'ps').length, 2);
});

test('retained reservation rejects unknown, foreign, duplicate, missing or unlimited custody', async (t) => {
  for (const mutation of [
    (f) => {
      f.model.fail = () => new Error('Docker unavailable');
    },
    (f) => {
      f.model.keeper.HostConfig.Memory = 0;
    },
    (f) => {
      f.model.keeper.HostConfig.MemorySwap = -1;
    },
    (f) => {
      f.model.keeper.HostConfig.MemorySwap *= 2;
    },
    (f) => {
      delete f.model.keeper.Config.Labels['io.openpc.fixture.owner'];
    },
    (f) => {
      f.model.keeper.Name = '/foreign-keeper';
    },
    (f) => {
      f.model.volume = null;
    },
    (f) => {
      f.model.volume.Options.o = 'size=128m';
    },
    (f) => {
      f.model.volume.Options = {};
    },
    (f) => {
      f.model.volume.Labels['io.openpc.fixture.owner'] = 'foreign';
    },
    (f) => {
      f.model.keeper.Mounts[0].Name = 'foreign-volume';
    },
    (f) => {
      f.model.keeper.State.Running = false;
    },
  ]) {
    const f = await setup(t);
    await prepareRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
    mutation(f);
    await assert.rejects(retainedRpcEnospcReservation({ execute: f.execute }));
  }
  for (const mode of [
    'malformed',
    'duplicate-row',
    'duplicate-id',
    'foreign-row',
    'repeated-token',
  ]) {
    const f = await setup(t);
    await prepareRpcEnospcRuntime(f.root, f.compose, { execute: f.execute });
    const execute = async (command, args, options) => {
      const result = await f.execute(command, args, options);
      if (args[0] === 'ps') {
        if (mode === 'malformed') result.stdout = 'unknown';
        if (mode === 'duplicate-id') result.stdout = `${keeperId}\n${keeperId}`;
        if (mode === 'repeated-token') result.stdout = `${keeperId}\n${'4'.repeat(64)}`;
      }
      if (args[0] === 'inspect') {
        const row = JSON.parse(result.stdout)[0];
        if (mode === 'duplicate-row') result.stdout = JSON.stringify([row, row]);
        if (mode === 'foreign-row')
          result.stdout = JSON.stringify([{ ...row, Id: '4'.repeat(64) }]);
        if (mode === 'repeated-token')
          result.stdout = JSON.stringify([row, { ...row, Id: '4'.repeat(64) }]);
      }
      return result;
    };
    await assert.rejects(retainedRpcEnospcReservation({ execute }));
  }
});

test('phase reservation binds the actual rendered mounts before deducting the exact selected keeper', async (t) => {
  const f = await setup(t);
  const configuration = f.model.rendered;
  assert.equal(await otherRetainedRpcEnospcReservation(configuration, { execute: f.execute }), 0);
  await f.prepare();
  const withoutFixture = structuredClone(configuration);
  delete withoutFixture['x-openpc-rpc-enospc'];
  assert.equal(
    await otherRetainedRpcEnospcReservation(withoutFixture, { execute: f.execute }),
    320 * 1024 ** 2,
  );
  assert.equal(await otherRetainedRpcEnospcReservation(configuration, { execute: f.execute }), 0);
  const another = structuredClone(configuration);
  const identity = {
    ...f.metadata.identity,
    token: 'f'.repeat(32),
    volumeName: `openpc-rpc-enospc-${'f'.repeat(32)}`,
  };
  const topology = rpcEnospcCompose({ identity });
  another['x-openpc-rpc-enospc'] = topology.extension;
  another.volumes = topology.volumes;
  another.services['runtime-target'].volumes[0] = topology.targetMount;
  another.services['runtime-target'].environment = topology.targetEnvironment;
  assert.equal(
    await otherRetainedRpcEnospcReservation(another, { execute: f.execute }),
    320 * 1024 ** 2,
  );
  for (const mutate of [
    (c) => {
      c.services['runtime-target'].volumes[0].source = 'foreign-volume';
    },
    (c) => {
      c.services['runtime-target'].volumes[0].target += '/foreign';
    },
    (c) => {
      c.services['runtime-target'].volumes[0].volume.nocopy = false;
    },
    (c) => {
      c.services['runtime-target'].volumes[0].read_only = true;
    },
    (c) => {
      c.services['runtime-target'].volumes[1].source = '/foreign/runtime';
    },
    (c) => {
      c.services['runtime-target'].volumes.push({
        type: 'bind',
        source: '/foreign/control',
        target: '/runtime/rpc-enospc',
      });
    },
    (c) => {
      c.services['runtime-target'].environment.OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY =
        '/foreign';
    },
    (c) => {
      c.volumes[f.metadata.identity.volumeName].name = 'foreign-volume';
    },
    (c) => {
      c.volumes[f.metadata.identity.volumeName].external = false;
    },
    (c) => {
      c['x-openpc-rpc-enospc'].additionalExternalMemoryBytes = 256 * 1024 ** 2;
    },
    (c) => {
      c['x-openpc-rpc-enospc'].identity.targetRuntimeId = '018f0000-0000-7000-8000-000000008888';
    },
  ]) {
    const forged = structuredClone(configuration);
    mutate(forged);
    await assert.rejects(otherRetainedRpcEnospcReservation(forged, { execute: f.execute }));
  }
});
