import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, realpath, rename, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  assertRpcEnospcFilesystem,
  rpcEnospcFixture,
  rpcEnospcIdentity,
} from './rpc-journal-crash-fixture.mjs';

const repository = fileURLToPath(new URL('../../../', import.meta.url));
const fixtureSource = fileURLToPath(new URL('./rpc-journal-crash-fixture.mjs', import.meta.url));
const inputRelative = 'evidence/runtime-bootstrap/discovery-credential-input.json';
const metadataKey = 'rpcJournalEnospc';
const controlMount = '/openpc-rpc-enospc-control';
const executeDefault = promisify(execFile);

// Design reservation, not a claim of measured cgroup usage or admission. The
// shared preflight must also sum the actual selected service/fixture phases.
export const rpcEnospcRuntime = Object.freeze({
  additionalExternalMemoryBytes: 320 * 1024 ** 2,
  keeperMemoryBytes: 256 * 1024 ** 2,
  inheritedExternalMemoryGiB: '9.313',
  image:
    'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43',
});

async function canonical(path, kind = 'directory') {
  assert.equal(await realpath(path), path, 'Fixture paths must be canonical');
  const value = await lstat(path);
  assert.ok(kind === 'directory' ? value.isDirectory() : value.isFile());
  return value;
}

async function owner(runRoot) {
  assert.equal(resolve(runRoot), runRoot);
  await canonical(runRoot);
  const sentinel = join(runRoot, '.openpc-local-runtime-owner');
  await canonical(sentinel, 'file');
  const match = /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
    await readFile(sentinel, 'utf8'),
  );
  assert.ok(match, 'An existing runtime owner is required');
  assert.equal(match[1], `openpc-local-e2e-${match[2].slice(0, 12)}`);
  return { project: match[1], ownerToken: match[2] };
}

function validateMetadata(value, expectedOwner, targetRuntimeId) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      'identity',
      'keeper',
      'ownerToken',
      'project',
      'state',
      'version',
      ...(Object.hasOwn(value, 'recovery') ? ['recovery'] : []),
    ].sort(),
  );
  assert.equal(value.version, 1);
  assert.equal(value.project, expectedOwner.project);
  assert.equal(value.ownerToken, expectedOwner.ownerToken);
  rpcEnospcIdentity(value.identity);
  assert.equal(value.identity.targetRuntimeId, targetRuntimeId);
  assert.ok(
    ['planned', 'allocating', 'ready', 'restoring', 'releasing', 'released'].includes(value.state),
  );
  if (value.keeper !== null) {
    assert.deepEqual(Object.keys(value.keeper).sort(), [
      'device',
      'id',
      'imageId',
      'inode',
      'startedAt',
    ]);
    assert.match(value.keeper.id, /^[0-9a-f]{64}$/u);
    assert.match(value.keeper.imageId, /^sha256:[0-9a-f]{64}$/u);
    assert.ok(Number.isFinite(Date.parse(value.keeper.startedAt)));
    for (const field of ['device', 'inode']) assert.match(value.keeper[field], /^[1-9][0-9]*$/u);
  }
  if (['ready', 'releasing', 'released'].includes(value.state)) assert.ok(value.keeper);
  if (value.recovery !== undefined) {
    assert.deepEqual(Object.keys(value.recovery).sort(), ['archiveDigest', 'previousKeeper']);
    assert.match(value.recovery.archiveDigest, /^sha256:[0-9a-f]{64}$/u);
    assert.ok(value.recovery.previousKeeper);
    const { recovery, ...previous } = value;
    validateMetadata(
      { ...previous, state: 'ready', keeper: recovery.previousKeeper },
      expectedOwner,
      targetRuntimeId,
    );
  }
  return value;
}

// Generated discovery input is the sole lifecycle record. No side ledger or
// caller-supplied readiness flag can enable the fixture.
export async function planRpcEnospcRuntime(runRoot, targetRuntimeId) {
  const token = randomBytes(16).toString('hex');
  const metadata = {
    version: 1,
    ...(await owner(runRoot)),
    identity: rpcEnospcIdentity({
      targetRuntimeId,
      token,
      volumeName: `openpc-rpc-enospc-${token}`,
    }),
    state: 'planned',
    keeper: null,
  };
  return metadata;
}

export function rpcEnospcCompose(metadata) {
  const identity = rpcEnospcIdentity(metadata.identity);
  return {
    extension: {
      identity,
      additionalExternalMemoryBytes: rpcEnospcRuntime.additionalExternalMemoryBytes,
    },
    volumes: { [identity.volumeName]: { external: true, name: identity.volumeName } },
    targetMount: {
      type: 'volume',
      source: identity.volumeName,
      target: `/runtime/evidence/${identity.targetRuntimeId}`,
      volume: { nocopy: true },
    },
    targetEnvironment: {
      OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY: `/runtime/rpc-enospc/${identity.token}`,
    },
  };
}

function assertRenderedFixture(rendered, identity, runRoot) {
  const topology = rpcEnospcCompose({ identity });
  assert.deepEqual(rendered['x-openpc-rpc-enospc'], topology.extension);
  assert.equal(rendered.volumes[identity.volumeName].external, true);
  assert.equal(rendered.volumes[identity.volumeName].name, identity.volumeName);
  assert.equal(rendered.services['rpc-provider'].image, rpcEnospcRuntime.image);
  const service = rendered.services['runtime-target'];
  const control = topology.targetEnvironment.OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY;
  assert.equal(service.environment.OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY, control);
  const evidence = service.volumes.filter(
    (mount) =>
      mount.target === topology.targetMount.target ||
      mount.target.startsWith(`${topology.targetMount.target}/`),
  );
  assert.equal(evidence.length, 1);
  const mount = evidence[0];
  assert.equal(mount.type, 'volume');
  assert.equal(mount.source, topology.targetMount.source);
  assert.equal(mount.target, topology.targetMount.target);
  assert.equal(mount.volume?.nocopy, true);
  assert.ok(!mount.read_only);
  // The control path must resolve through the actual original writable bind.
  // A more-specific mount could redirect it while leaving metadata unchanged.
  const controls = service.volumes.filter(
    (value) => control === value.target || control.startsWith(`${value.target}/`),
  );
  assert.equal(controls.length, 1);
  assert.equal(controls[0].type, 'bind');
  assert.equal(controls[0].target, '/runtime');
  assert.ok(!controls[0].read_only);
  if (runRoot !== undefined)
    assert.equal(controls[0].source, join(runRoot, 'data/runtime-bootstrap/runtime'));
}

function validateCompose(compose, context) {
  assert.ok(Array.isArray(compose));
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const projects = [],
    files = [];
  for (let i = 2; i < compose.length; i += 2) {
    assert.ok(typeof compose[i + 1] === 'string');
    if (['-p', '--project-name'].includes(compose[i])) projects.push(compose[i + 1]);
    else {
      assert.ok(['-f', '--file'].includes(compose[i]));
      assert.equal(resolve(compose[i + 1]), compose[i + 1]);
      files.push(compose[i + 1]);
    }
  }
  assert.deepEqual(projects, [context.project]);
  assert.ok(files.includes(join(context.runRoot, 'data/runtime-bootstrap/compose.json')));
  assert.equal(new Set(files).size, files.length);
}

async function closeAfter(handle, operation) {
  let failure;
  try {
    await operation(handle);
  } catch (error) {
    failure = error;
  }
  try {
    await handle.close();
  } catch (error) {
    failure = failure
      ? new AggregateError([failure, error], 'Lifecycle write failed, then close failed')
      : error;
  }
  if (failure) throw failure;
}

async function saveInput(
  context,
  state,
  keeper = context.metadata.keeper,
  recovery = context.metadata.recovery,
) {
  const current = JSON.parse(await readFile(context.inputPath, 'utf8'));
  assert.deepEqual(current, context.input, 'Lifecycle input changed under the exclusive owner');
  const next = {
    ...current,
    [metadataKey]: { ...context.metadata, state, keeper, ...(recovery ? { recovery } : {}) },
  };
  const temporary = `${context.inputPath}.enospc-${randomBytes(8).toString('hex')}`;
  const file = await open(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await closeAfter(file, async (handle) => {
      await handle.writeFile(JSON.stringify(next));
      await handle.sync();
    });
    await rename(temporary, context.inputPath);
    const directory = await open(
      dirname(context.inputPath),
      constants.O_RDONLY | constants.O_DIRECTORY,
    );
    await closeAfter(directory, (handle) => handle.sync());
  } catch (error) {
    try {
      await unlink(temporary);
    } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT')
        throw new AggregateError(
          [error, cleanupError],
          'Lifecycle write and temporary cleanup failed',
        );
    }
    throw error;
  }
  context.input = next;
  context.metadata = next[metadataKey];
}

async function ownershipContextFor(runRoot, execute) {
  const ownership = await owner(runRoot);
  const inputPath = join(runRoot, inputRelative);
  await canonical(inputPath, 'file');
  const input = JSON.parse(await readFile(inputPath, 'utf8'));
  const metadata = validateMetadata(input[metadataKey], ownership, input.targetId);
  const context = { runRoot, inputPath, input, metadata, ...ownership };
  context.execute = async (command, args) =>
    execute(command, args, { timeout: 30000, maxBuffer: 2 * 1024 ** 2 });
  context.docker = async (...args) => (await context.execute('docker', args)).stdout.trim();
  return context;
}

async function contextFor(runRoot, compose, execute) {
  const context = await ownershipContextFor(runRoot, execute);
  validateCompose(compose, context);
  context.compose = compose;
  return context;
}

async function guard(context, action) {
  // This is deliberately an executable integration dependency. Until the
  // shared owner installs all three hooks, even a valid plan cannot allocate.
  // preflight RUN_ROOT COMPOSE_JSON ACTION runs in a fresh Bash process: derive
  // inputs from these arguments, verify live exclusive ownership and actual
  // phase charging, and do not call this helper recursively. Read-only inspection
  // and retain/cleanup require ownership, not renewed full-stack allocation.
  await context.execute('bash', [
    '-euo',
    'pipefail',
    '-c',
    'source "$1"; source "$2"; for hook in openpc_rpc_enospc_preflight openpc_rpc_enospc_on_exit openpc_rpc_enospc_before_resume; do declare -F "$hook" >/dev/null || exit 96; done; openpc_rpc_enospc_preflight "$3" "$4" "$5"',
    'rpc-enospc-guard',
    join(repository, 'scripts/maintenance/local-runtime-images.sh'),
    join(repository, 'tests/integration/local-runtime/runner-harness.sh'),
    context.runRoot,
    JSON.stringify(context.compose),
    action,
  ]);
  if (action === 'restore') {
    await context.execute('bash', [
      join(repository, 'scripts/maintenance/run-bounded.sh'),
      '--profile',
      'focused',
      '--external-memory-gib',
      '0.939',
      '--reuse',
      '--',
      'true',
    ]);
  } else if (!['inspect', 'retain', 'cleanup'].includes(action))
    await context.execute('bash', [
      join(repository, 'scripts/maintenance/run-bounded.sh'),
      '--profile',
      'runtime-target',
      '--external-memory-gib',
      rpcEnospcRuntime.inheritedExternalMemoryGiB,
      '--reuse',
      '--',
      'true',
    ]);
}

function labels(context) {
  return {
    'io.openpc.fixture': 'rpc-journal-enospc',
    'io.openpc.fixture.token': context.metadata.identity.token,
    'io.openpc.fixture.project': context.project,
    'io.openpc.fixture.target': context.metadata.identity.targetRuntimeId,
    'io.openpc.fixture.owner': context.ownerToken,
  };
}

function assertLabels(actual, context) {
  for (const [key, value] of Object.entries(labels(context))) assert.equal(actual?.[key], value);
  // A project-wide stop/down must never release the last mount.
  assert.equal(actual['com.docker.compose.project'], undefined);
  assert.equal(actual['com.docker.compose.service'], undefined);
}

const lines = (value) => (value ? value.split('\n') : []);

async function inventory(context) {
  const { volumeName, token } = context.metadata.identity;
  const names = lines(
    await context.docker(
      'volume',
      'ls',
      '--format',
      '{{.Name}}',
      '--filter',
      `name=^${volumeName}$`,
    ),
  );
  assert.ok(names.length <= 1 && names.every((name) => name === volumeName));
  const ids = lines(
    await context.docker(
      'ps',
      '-aq',
      '--no-trunc',
      '--filter',
      `label=io.openpc.fixture.token=${token}`,
    ),
  );
  assert.ok(ids.length <= 1, 'Ambiguous keeper ownership');
  const keepers = ids.length ? JSON.parse(await context.docker('inspect', ...ids)) : [];
  for (const keeper of keepers) assertLabels(keeper.Config.Labels, context);
  const volumes = names.length
    ? JSON.parse(await context.docker('volume', 'inspect', volumeName))
    : [];
  for (const volume of volumes) assertVolume(volume, context);
  const users = lines(
    await context.docker('ps', '-aq', '--no-trunc', '--filter', `volume=${volumeName}`),
  );
  return { keeper: keepers[0], volume: volumes[0], users };
}

function assertVolume(volume, context) {
  assertLabels(volume.Labels, context);
  assert.equal(volume.Name, context.metadata.identity.volumeName);
  assert.equal(volume.Driver, 'local');
  assert.deepEqual(volume.Options, {
    type: 'tmpfs',
    device: 'tmpfs',
    o: 'size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
  });
}

function assertKeeper(keeper, context) {
  assert.ok(keeper?.State.Running, 'The original keeper must still be running');
  assert.match(keeper.Id, /^[0-9a-f]{64}$/u);
  assertLabels(keeper.Config.Labels, context);
  assert.equal(keeper.Config.Image, rpcEnospcRuntime.image);
  assert.equal(keeper.Config.User, '65532:65532');
  assert.deepEqual(keeper.Config.Entrypoint, ['node']);
  assert.deepEqual(keeper.Config.Cmd, ['-e', keeperProgram, context.metadata.identity.token]);
  assert.equal(keeper.HostConfig.Privileged, false);
  assert.equal(keeper.HostConfig.ReadonlyRootfs, true);
  assert.equal(keeper.HostConfig.NetworkMode, 'none');
  assert.deepEqual(keeper.HostConfig.CapDrop, ['ALL']);
  assert.ok(!keeper.HostConfig.CapAdd?.length);
  assert.ok(
    keeper.HostConfig.SecurityOpt.some((value) => /^no-new-privileges(?::true)?$/u.test(value)),
  );
  assert.equal(keeper.HostConfig.Memory, rpcEnospcRuntime.keeperMemoryBytes);
  assert.equal(keeper.HostConfig.MemorySwap, rpcEnospcRuntime.keeperMemoryBytes);
  assert.equal(keeper.HostConfig.NanoCpus, 250000000);
  assert.equal(keeper.HostConfig.PidsLimit, 64);
  assert.equal(keeper.HostConfig.RestartPolicy.Name, 'no');
  const mounts = new Map(keeper.Mounts.map((mount) => [mount.Destination, mount]));
  assert.equal(keeper.Mounts.length, 3);
  assert.equal(mounts.size, 3);
  const volume = mounts.get(rpcEnospcFixture.root);
  assert.equal(volume?.Type, 'volume');
  assert.equal(volume.Name, context.metadata.identity.volumeName);
  assert.equal(volume.RW, true);
  for (const [destination, source, writable] of [
    [rpcEnospcFixture.script, fixtureSource, false],
    [controlMount, join(context.runRoot, 'data/runtime-bootstrap/runtime/rpc-enospc'), true],
  ]) {
    const mount = mounts.get(destination);
    assert.equal(mount?.Type, 'bind');
    assert.equal(mount.Source, source);
    assert.equal(mount.RW, writable);
  }
  if (context.metadata.keeper) {
    assert.equal(keeper.Id, context.metadata.keeper.id);
    assert.equal(
      keeper.State.StartedAt,
      context.metadata.keeper.startedAt,
      'Keeper restart loses tmpfs continuity',
    );
    assert.equal(keeper.Image, context.metadata.keeper.imageId);
  }
}

// Read-only admission inventory. It deliberately performs no fixture exec,
// lifecycle write or resource repair. Name and label inventories form one union;
// the same planned/retained keeper is charged once, while duplicate identities
// across different containers fail closed.
async function retainedRpcEnospcInventory(execute) {
  const docker = async (...args) =>
    (await execute('docker', args, { timeout: 5000, maxBuffer: 262144 })).stdout.trim();
  const ids = new Set();
  for (const filter of [
    'label=io.openpc.fixture=rpc-journal-enospc',
    'name=^/openpc-rpc-enospc-.*-keeper$',
  ]) {
    const selected = lines(await docker('ps', '-q', '--no-trunc', '--filter', filter));
    assert.equal(new Set(selected).size, selected.length);
    for (const id of selected) {
      assert.match(id, /^[0-9a-f]{64}$/u);
      ids.add(id);
    }
  }
  if (!ids.size) return new Map();
  const keepers = JSON.parse(await docker('inspect', ...ids));
  assert.equal(keepers.length, ids.size);
  const tokens = new Map();
  for (const keeper of keepers) {
    assert.ok(ids.delete(keeper.Id), 'Unexpected or repeated keeper');
    const mounts = keeper.Mounts.filter((mount) => mount.Destination === controlMount);
    assert.equal(mounts.length, 1);
    const suffix = '/data/runtime-bootstrap/runtime/rpc-enospc';
    assert.ok(mounts[0].Source.endsWith(suffix));
    const context = await ownershipContextFor(mounts[0].Source.slice(0, -suffix.length), execute);
    assert.equal(keeper.Name, `/${context.metadata.identity.volumeName}-keeper`);
    assertKeeper(keeper, context);
    const token = context.metadata.identity.token;
    assert.ok(!tokens.has(token), 'Repeated keeper identity');
    tokens.set(token, { identity: context.metadata.identity, runRoot: context.runRoot });
    const volumes = JSON.parse(
      await docker('volume', 'inspect', context.metadata.identity.volumeName),
    );
    assert.equal(volumes.length, 1);
    assertVolume(volumes[0], context);
  }
  assert.equal(ids.size, 0);
  return tokens;
}

export async function retainedRpcEnospcReservation({ execute = executeDefault } = {}) {
  return (
    (await retainedRpcEnospcInventory(execute)).size *
    rpcEnospcRuntime.additionalExternalMemoryBytes
  );
}

// The rendered phase already includes its selected fixture. Exclude exactly
// that verified identity from the retained union, never an arbitrary token or
// caller-supplied amount. A planned fixture not yet running excludes nothing.
export async function otherRetainedRpcEnospcReservation(
  configuration,
  { execute = executeDefault } = {},
) {
  const fixture = configuration['x-openpc-rpc-enospc'];
  const retained = await retainedRpcEnospcInventory(execute);
  if (fixture !== undefined) {
    assert.deepEqual(Object.keys(fixture).sort(), ['additionalExternalMemoryBytes', 'identity']);
    assert.equal(
      fixture.additionalExternalMemoryBytes,
      rpcEnospcRuntime.additionalExternalMemoryBytes,
    );
    const identity = rpcEnospcIdentity(fixture.identity);
    const original = retained.get(identity.token);
    assertRenderedFixture(configuration, identity, original?.runRoot);
    if (original) {
      assert.deepEqual(original.identity, identity);
      retained.delete(identity.token);
    }
  }
  return retained.size * rpcEnospcRuntime.additionalExternalMemoryBytes;
}

async function filesystem(context, keeper, action = 'inspect') {
  const result = JSON.parse(
    await context.docker(
      'exec',
      keeper.Id,
      'node',
      rpcEnospcFixture.script,
      '--enospc',
      action,
      JSON.stringify({ identity: context.metadata.identity }),
    ),
  );
  assert.deepEqual(result.identity, context.metadata.identity);
  assertRpcEnospcFilesystem(result.filesystem);
  if (context.metadata.keeper) {
    assert.equal(result.filesystem.device, context.metadata.keeper.device);
    assert.equal(result.filesystem.inode, context.metadata.keeper.inode);
  }
  return result.filesystem;
}

async function inspect(context, { targetContainerId, targetRequired = false } = {}) {
  assert.equal(
    context.metadata.state,
    'ready',
    'Interrupted allocation requires retention and diagnosis',
  );
  const current = await inventory(context);
  assert.ok(current.volume);
  assertKeeper(current.keeper, context);
  const state = await filesystem(context, current.keeper);
  const targetIds = lines(
    (
      await context.execute(context.compose[0], [
        ...context.compose.slice(1),
        '--profile',
        'astra05',
        'ps',
        '-aq',
        'runtime-target',
      ])
    ).stdout.trim(),
  );
  assert.ok(targetIds.length <= 1);
  if (targetRequired) assert.equal(targetIds.length, 1);
  if (targetContainerId) assert.deepEqual(targetIds, [targetContainerId]);
  assert.deepEqual(
    current.users.sort(),
    [current.keeper.Id, ...targetIds].sort(),
    'Foreign volume consumers are forbidden',
  );
  if (targetIds.length) {
    const [target] = JSON.parse(await context.docker('inspect', targetIds[0]));
    assert.equal(target.Id, targetIds[0]);
    if (targetRequired) assert.equal(target.State.Running, true);
    assert.equal(target.Config.User, '65532:65532');
    assert.equal(target.Config.Labels['com.docker.compose.project'], context.project);
    assert.equal(target.Config.Labels['com.docker.compose.service'], 'runtime-target');
    const mounts = target.Mounts.filter(
      (mount) =>
        mount.Destination === `/runtime/evidence/${context.metadata.identity.targetRuntimeId}`,
    );
    assert.equal(mounts.length, 1);
    assert.equal(mounts[0].Type, 'volume');
    assert.equal(mounts[0].Name, context.metadata.identity.volumeName);
    assert.equal(mounts[0].RW, true);
  }
  return { ...current, filesystem: state };
}

const keeperProgram =
  'if(process.getuid()!==65532||process.getgid()!==65532)process.exit(96);setInterval(()=>{},1000)';

async function createKeeper(context) {
  const control = join(context.runRoot, 'data/runtime-bootstrap/runtime/rpc-enospc');
  const volumeName = context.metadata.identity.volumeName;
  const labelArgs = Object.entries(labels(context)).flatMap(([key, value]) => [
    '--label',
    `${key}=${value}`,
  ]);
  const id = await context.docker(
    'create',
    '--pull',
    'never',
    '--platform',
    'linux/amd64',
    '--name',
    `${volumeName}-keeper`,
    ...labelArgs,
    '--user',
    '65532:65532',
    '--read-only',
    '--network',
    'none',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges:true',
    '--memory',
    '256m',
    '--memory-swap',
    '256m',
    '--cpus',
    '0.25',
    '--pids-limit',
    '64',
    '--restart',
    'no',
    '--mount',
    `type=volume,src=${volumeName},dst=${rpcEnospcFixture.root},volume-nocopy`,
    '--mount',
    `type=bind,src=${fixtureSource},dst=${rpcEnospcFixture.script},readonly`,
    '--mount',
    `type=bind,src=${control},dst=${controlMount}`,
    '--entrypoint',
    'node',
    rpcEnospcRuntime.image,
    '-e',
    keeperProgram,
    context.metadata.identity.token,
  );
  assert.match(id, /^[0-9a-f]{64}$/u);
  await context.docker('start', id);
  return id;
}

export async function prepareRpcEnospcRuntime(runRoot, compose, { execute = executeDefault } = {}) {
  const context = await contextFor(runRoot, compose, execute);
  await guard(context, 'prepare');
  if (context.metadata.state === 'ready') {
    await inspect(context);
    return { disposition: 'ready', identity: context.metadata.identity };
  }
  assert.equal(context.metadata.state, 'planned', 'Never replay an interrupted allocation');
  const current = await inventory(context);
  assert.ok(!current.keeper && !current.volume && current.users.length === 0);
  const rendered = JSON.parse(
    (
      await context.execute(compose[0], [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'config',
        '--format',
        'json',
      ])
    ).stdout,
  );
  assertRenderedFixture(rendered, context.metadata.identity, context.runRoot);
  const [image] = JSON.parse(await context.docker('image', 'inspect', rpcEnospcRuntime.image));
  assert.match(image.Id, /^sha256:[0-9a-f]{64}$/u);
  const control = join(runRoot, 'data/runtime-bootstrap/runtime/rpc-enospc');
  await canonical(dirname(control));
  await mkdir(control, { mode: 0o777 });
  await chmod(control, 0o777);
  await canonical(control);
  await canonical(fixtureSource, 'file');
  // Persist intent before the first Docker mutation. Any uncertain result is
  // retained; neither a new token nor an empty replacement can hide it.
  await saveInput(context, 'allocating');
  const labelArgs = Object.entries(labels(context)).flatMap(([key, value]) => [
    '--label',
    `${key}=${value}`,
  ]);
  const volumeName = context.metadata.identity.volumeName;
  assert.equal(
    await context.docker(
      'volume',
      'create',
      '--driver',
      'local',
      ...labelArgs,
      '--opt',
      'type=tmpfs',
      '--opt',
      'device=tmpfs',
      '--opt',
      'o=size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
      volumeName,
    ),
    volumeName,
  );
  const id = await createKeeper(context);
  // Prepare the outside directory synchronously as the keeper's unprivileged
  // UID. It cannot race PID 1 initialization or require a privileged helper.
  await context.docker(
    'exec',
    id,
    'node',
    '-e',
    'const fs=require("node:fs");const p=process.argv[1];fs.mkdirSync(p,{mode:448});const s=fs.lstatSync(p);if(!s.isDirectory()||fs.realpathSync(p)!==p||s.uid!==65532||s.gid!==65532||(s.mode&511)!==448)process.exit(96)',
    `${controlMount}/${context.metadata.identity.token}`,
  );
  const [keeper] = JSON.parse(await context.docker('inspect', id));
  assertKeeper(keeper, context);
  assert.equal(keeper.Image, image.Id);
  const state = await filesystem(context, keeper, 'claim');
  await saveInput(context, 'ready', {
    id,
    startedAt: keeper.State.StartedAt,
    imageId: keeper.Image,
    device: state.device,
    inode: state.inode,
  });
  await inspect(context);
  return { disposition: 'ready', identity: context.metadata.identity };
}

const snapshotProgram = `const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root='/openpc-spool-enospc',rows={};let bytes=0;
function visit(name){if(Object.keys(rows).length>=1024)throw Error('Entry limit');const p=path.join(root,name),s=fs.lstatSync(p);
if(!s.isFile()&&!s.isDirectory())throw Error('Unsupported entry');
const row={type:s.isDirectory()?'directory':'file',mode:s.mode&4095,uid:s.uid,gid:s.gid,size:s.isFile()?s.size:0};
bytes+=row.size;if(bytes>67108864)throw Error('Size limit');if(s.isFile())row.digest=crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
rows[name]=row;if(s.isDirectory())for(const child of fs.readdirSync(p).sort())visit(name?name+'/'+child:child);}
visit('');process.stdout.write(JSON.stringify(rows));`;

/** Explicit reboot recovery only. The original archive and prior keeper remain
 * recorded. Ordinary inspection still rejects every changed keeper/namespace.
 * An interrupted restore retains intent and must be diagnosed, never replayed. */
export async function restoreRpcEnospcRuntime(runRoot, compose, { execute = executeDefault } = {}) {
  const context = await contextFor(runRoot, compose, execute);
  await guard(context, 'restore');
  assert.equal(context.metadata.state, 'ready', 'Interrupted recovery requires diagnosis');
  assert.equal(context.metadata.recovery, undefined, 'Do not replace a prior recovery');
  const current = await inventory(context);
  assert.ok(
    current.volume && !current.keeper && current.users.length === 0,
    'Restore requires the original unused volume and no keeper',
  );
  const archive = join(
    runRoot,
    'data/restart-preservation',
    `${context.metadata.identity.volumeName}.tar`,
  );
  const helper = join(repository, 'tests/integration/local-runtime/rpc-journal-enospc-archive.py');
  const argumentsFor = [archive, JSON.stringify(context.metadata.identity)];
  const original = JSON.parse(
    (await context.execute('python3', [helper, 'inspect', ...argumentsFor])).stdout,
  );
  assert.match(original.archiveDigest, /^sha256:[0-9a-f]{64}$/u);
  const [image] = JSON.parse(await context.docker('image', 'inspect', rpcEnospcRuntime.image));
  assert.equal(image.Id, context.metadata.keeper.imageId, 'Restore uses the original pinned image');
  await canonical(join(runRoot, 'data/runtime-bootstrap/runtime/rpc-enospc'));
  await saveInput(context, 'restoring', null, {
    archiveDigest: original.archiveDigest,
    previousKeeper: context.metadata.keeper,
  });
  const id = await createKeeper(context);
  assert.notEqual(id, context.metadata.recovery.previousKeeper.id);
  const [keeper] = JSON.parse(await context.docker('inspect', id));
  assertKeeper(keeper, context);
  assert.equal(keeper.Image, image.Id);
  const snapshot = async () =>
    JSON.parse(await context.docker('exec', id, 'node', '-e', snapshotProgram));
  const empty = await snapshot();
  assert.deepEqual(Object.keys(empty), [''], 'Never overwrite any retained mount contents');
  assert.deepEqual(empty[''], original.entries['']);
  const copied = JSON.parse(
    (
      await context.execute('python3', [
        helper,
        'copy',
        ...argumentsFor,
        id,
        original.archiveDigest,
      ])
    ).stdout,
  );
  assert.deepEqual(copied, original, 'Archive changed during restore');
  assert.deepEqual(
    await snapshot(),
    original.entries,
    'Exact restored bytes and metadata required',
  );
  const state = await filesystem(context, keeper);
  const final = await inventory(context);
  assert.deepEqual(final.users, [id]);
  assert.equal(final.keeper.Id, id);
  assert.equal(final.keeper.State.StartedAt, keeper.State.StartedAt);
  assertKeeper(final.keeper, context);
  await saveInput(context, 'ready', {
    id,
    startedAt: keeper.State.StartedAt,
    imageId: keeper.Image,
    device: state.device,
    inode: state.inode,
  });
  await inspect(context);
  return {
    disposition: 'restored',
    archiveDigest: original.archiveDigest,
    keeperContainerId: id,
    previousKeeperContainerId: context.metadata.recovery.previousKeeper.id,
  };
}

export async function inspectRpcEnospcRuntime(runRoot, compose, { execute = executeDefault } = {}) {
  const context = await contextFor(runRoot, compose, execute);
  await guard(context, 'inspect');
  const current = await inspect(context);
  return {
    disposition: 'ready',
    keeperContainerId: current.keeper.Id,
    identity: context.metadata.identity,
  };
}

export async function resolveRpcEnospcConfiguration(
  runRoot,
  compose,
  targetRuntimeId,
  targetContainerId,
  { execute = executeDefault } = {},
) {
  const context = await contextFor(runRoot, compose, execute);
  assert.equal(context.metadata.identity.targetRuntimeId, targetRuntimeId);
  assert.match(targetContainerId, /^[0-9a-f]{64}$/u);
  await guard(context, 'resolve');
  const current = await inspect(context, { targetContainerId, targetRequired: true });
  const configuration = {
    keeperContainerId: current.keeper.Id,
    token: context.metadata.identity.token,
    volumeName: context.metadata.identity.volumeName,
  };
  // exerciseRpcEvidence immediately passes this exact configuration to the
  // existing connector, which verifies the target namespace/preload/control
  // directory before arming. Do not repeat its Docker probes in the live window.
  return configuration;
}

export async function retainRpcEnospcRuntime(runRoot, compose, { execute = executeDefault } = {}) {
  const context = await contextFor(runRoot, compose, execute);
  await guard(context, 'retain');
  const current = await inventory(context);
  // Retention never starts/stops/removes anything, even for partial startup.
  // Ready state additionally proves that the original mounted bytes survived.
  if (context.metadata.state === 'ready') await inspect(context);
  return {
    disposition: 'retain',
    dataCleanupSafe: false,
    state: context.metadata.state,
    keeperContainerId: current.keeper?.Id ?? null,
    keeperRunning: current.keeper?.State.Running ?? false,
    volumeName: context.metadata.identity.volumeName,
    additionalExternalMemoryBytes: rpcEnospcRuntime.additionalExternalMemoryBytes,
  };
}

export async function cleanupRpcEnospcRuntime(
  runRoot,
  compose,
  { status, retain = false, execute = executeDefault } = {},
) {
  assert.ok(Number.isInteger(status) && status >= 0 && status <= 255);
  assert.equal(typeof retain, 'boolean');
  if (status !== 0 || retain) return retainRpcEnospcRuntime(runRoot, compose, { execute });
  const context = await contextFor(runRoot, compose, execute);
  await guard(context, 'cleanup');
  assert.ok(
    ['ready', 'releasing', 'released'].includes(context.metadata.state),
    'Uncertain allocation must be retained',
  );
  const current = await inventory(context);
  if (context.metadata.state === 'released') {
    assert.ok(!current.keeper && !current.volume && current.users.length === 0);
    return { disposition: 'released', dataCleanupSafe: true };
  }
  if (current.keeper) {
    assertKeeper(current.keeper, context);
    await filesystem(context, current.keeper);
  }
  assert.deepEqual(
    current.users,
    current.keeper ? [current.keeper.Id] : [],
    'Remove all target consumers before releasing the keeper',
  );
  if (context.metadata.state === 'ready') {
    assert.ok(current.keeper && current.volume);
    await saveInput(context, 'releasing');
  }
  if (current.keeper) await context.docker('rm', '-f', current.keeper.Id);
  // Reinspect after last-mount release; never remove a newly shared resource.
  const remaining = await inventory(context);
  assert.ok(!remaining.keeper && remaining.users.length === 0);
  if (remaining.volume) await context.docker('volume', 'rm', context.metadata.identity.volumeName);
  const final = await inventory(context);
  assert.ok(!final.keeper && !final.volume && final.users.length === 0);
  await saveInput(context, 'released');
  return { disposition: 'released', dataCleanupSafe: true };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, runRoot, composeJson, status, retain] = process.argv.slice(2);
  try {
    if (action === 'reservation') {
      process.stdout.write(`${Math.ceil((await retainedRpcEnospcReservation()) / 1024)}\n`);
    } else if (action === 'phase-reservation') {
      let text = '';
      for await (const chunk of process.stdin) {
        text += chunk;
        assert.ok(Buffer.byteLength(text) <= 2 * 1024 ** 2);
      }
      const configuration = JSON.parse(text);
      process.stdout.write(`${await otherRetainedRpcEnospcReservation(configuration)}\n`);
    } else {
      const compose = JSON.parse(composeJson);
      const handlers = {
        prepare: prepareRpcEnospcRuntime,
        inspect: inspectRpcEnospcRuntime,
        retain: retainRpcEnospcRuntime,
        restore: restoreRpcEnospcRuntime,
      };
      assert.ok(action === 'cleanup' || Object.hasOwn(handlers, action));
      if (action === 'cleanup')
        assert.ok(/^(?:0|[1-9][0-9]{0,2})$/u.test(status) && ['0', '1'].includes(retain));
      const result =
        action === 'cleanup'
          ? await cleanupRpcEnospcRuntime(runRoot, compose, {
              status: Number(status),
              retain: retain === '1',
            })
          : await handlers[action](runRoot, compose);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
  } catch (error) {
    // Child errors can include command lines, owner tokens and credentials.
    // Keep a closed failure category and this module's source location, never
    // command lines, messages, stderr, values or the complete child stack.
    const phase = [
      'prepare',
      'inspect',
      'retain',
      'restore',
      'cleanup',
      'reservation',
      'phase-reservation',
    ].includes(action)
      ? action
      : 'input';
    const reason =
      error instanceof SyntaxError
        ? 'input-json'
        : error?.code === 'ERR_ASSERTION'
          ? 'contract'
          : typeof error?.code === 'number'
            ? 'subprocess'
            : ['ENOENT', 'EACCES', 'ELOOP'].includes(error?.code)
              ? 'filesystem'
              : 'unknown';
    const line =
      String(error?.stack ?? '').match(/rpc-journal-enospc-runtime\.mjs:(\d+):\d+/u)?.[1] ??
      'unavailable';
    process.stderr.write(
      `OPENPC_RPC_ENOSPC_RUNTIME|FAIL|phase=${phase}|reason=${reason}|source_line=${line}|retain-originals\n`,
    );
    process.exitCode = 1;
  }
}
