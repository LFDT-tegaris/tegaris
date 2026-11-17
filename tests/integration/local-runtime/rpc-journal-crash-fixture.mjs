import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { chmod, lstat, open, readFile, readdir, realpath, statfs, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

export function assertRpcJournalFixtureAbi(versionInfo) {
  // The packaged target is pinned to Debian Bookworm (glibc 2.36). Check the
  // actual compiled artifact before any public governance or target startup.
  const required = [...versionInfo.matchAll(/Name: GLIBC_([^\s]+)/gu)].map((match) => match[1]);
  assert.ok(required.length > 0, 'Fixture must declare its libc requirements');
  for (const version of required) {
    assert.match(version, /^\d+\.\d+(?:\.\d+)?$/u);
    const [major, minor, patch = 0] = version.split('.').map(Number);
    assert.ok(
      major < 2 || (major === 2 && (minor < 36 || (minor === 36 && patch === 0))),
      'Fixture requires a newer libc than the packaged target',
    );
  }
}

export async function prepareRpcJournalCrashFixture(runtimeRoot) {
  assert.equal(process.platform, 'linux');
  assert.ok(isAbsolute(runtimeRoot));
  assert.equal(await realpath(runtimeRoot), runtimeRoot);
  const library = join(runtimeRoot, 'rpc-journal-crash-fixture.so');
  await promisify(execFile)(
    'cc',
    [
      '-std=c11',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-O2',
      '-fPIC',
      '-shared',
      '-o',
      library,
      fileURLToPath(new URL('./rpc-journal-crash-fixture.c', import.meta.url)),
      '-ldl',
      '-pthread',
    ],
    { timeout: 10000, maxBuffer: 65536 },
  );
  const { stdout } = await promisify(execFile)('readelf', ['--version-info', library], {
    timeout: 10000,
    maxBuffer: 65536,
  });
  assertRpcJournalFixtureAbi(stdout);
  await chmod(library, 0o555);
  return library;
}

// The runtime owner creates and admits this finite mount and its keeper before
// acquiring live authority. These helpers neither mount storage nor start it.
export const rpcEnospcFixture = Object.freeze({
  bytes: 64 * 1024 * 1024,
  uid: 65532,
  root: '/openpc-spool-enospc',
  script: '/openpc-rpc-journal-fixture.mjs',
  ownerFile: '.openpc-enospc-owner',
});

export function rpcEnospcIdentity(value) {
  assert.deepEqual(Object.keys(value).sort(), ['targetRuntimeId', 'token', 'volumeName']);
  assert.match(value.token, /^[0-9a-f]{32}$/u);
  assert.equal(value.volumeName, `openpc-rpc-enospc-${value.token}`);
  assert.match(value.targetRuntimeId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u);
  return { ...value };
}

const decodeMount = (value) =>
  value.replace(/\\(040|011|012|134)/gu, (_, octal) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );

export function rpcEnospcMount(mountinfo, directory) {
  const rows = mountinfo
    .trim()
    .split('\n')
    .map((line) => {
      const [left, right, extra] = line.split(' - ');
      assert.equal(extra, undefined);
      assert.ok(left && right);
      const fields = left.split(' '),
        tail = right.split(' ');
      return {
        id: fields[0],
        root: decodeMount(fields[3]),
        point: decodeMount(fields[4]),
        options: fields[5].split(','),
        type: tail[0],
        superOptions: tail[2].split(','),
      };
    })
    .filter((row) => row.point === directory);
  assert.equal(rows.length, 1, 'An exact dedicated mount is required');
  const mount = rows[0];
  assert.equal(mount.root, '/', 'A shared tmpfs subdirectory is not a dedicated filesystem');
  assert.equal(mount.type, 'tmpfs');
  for (const option of ['rw', 'nosuid', 'nodev', 'noexec'])
    assert.ok(mount.options.includes(option), `Missing mount constraint: ${option}`);
  assert.ok(mount.superOptions.some((option) => /^size=[1-9][0-9]*[kmg]?$/u.test(option)));
  return mount;
}

export function assertRpcEnospcFilesystem(value) {
  assert.equal(value.type, '16914836'); // Linux TMPFS_MAGIC, independently of mount options.
  assert.equal(value.bytes, rpcEnospcFixture.bytes);
  assert.ok(
    Number.isSafeInteger(value.blockSize) && value.blockSize >= 512 && value.blockSize <= 65536,
  );
  assert.equal(value.bytes % value.blockSize, 0);
  assert.ok(
    Number.isSafeInteger(value.availableBlocks) &&
      value.availableBlocks >= 0 &&
      value.availableBlocks <= value.bytes / value.blockSize,
  );
  assert.ok(
    Number.isSafeInteger(value.freeInodes) && value.freeInodes > 0,
    'This case exhausts blocks, not inode capacity',
  );
  assert.equal(value.uid, rpcEnospcFixture.uid);
  assert.equal(value.gid, rpcEnospcFixture.uid);
  assert.equal(value.mode, 0o700);
  for (const field of ['device', 'inode']) assert.match(value[field], /^[1-9][0-9]*$/u);
}

async function openRpcEnospcRoot(identity, claimed = true) {
  rpcEnospcIdentity(identity);
  assert.equal(process.platform, 'linux');
  assert.equal(process.versions.node, '24.19.0');
  assert.equal(process.getuid(), rpcEnospcFixture.uid);
  assert.equal(process.getgid(), rpcEnospcFixture.uid);
  const root = rpcEnospcFixture.root;
  assert.equal(await realpath(root), root);
  rpcEnospcMount(await readFile('/proc/self/mountinfo', 'utf8'), root);
  const directory = await open(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const initial = await directory.stat({ bigint: true });
    const pinned = `/proc/self/fd/${directory.fd}`;
    const inspect = async () => {
      const current = await lstat(root, { bigint: true });
      assert.ok(current.isDirectory());
      assert.equal(current.dev, initial.dev);
      assert.equal(current.ino, initial.ino);
      const usage = await statfs(pinned, { bigint: true });
      const result = {
        device: current.dev.toString(),
        inode: current.ino.toString(),
        uid: Number(current.uid),
        gid: Number(current.gid),
        mode: Number(current.mode & 0o777n),
        type: usage.type.toString(),
        bytes: Number(usage.blocks * usage.bsize),
        blockSize: Number(usage.bsize),
        availableBlocks: Number(usage.bavail),
        freeInodes: Number(usage.ffree),
      };
      assertRpcEnospcFilesystem(result);
      return result;
    };
    await inspect();
    if (claimed) {
      const owner = await open(
        join(pinned, rpcEnospcFixture.ownerFile),
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const metadata = await owner.stat();
        assert.ok(metadata.isFile() && metadata.nlink === 1 && metadata.size <= 512);
        assert.equal(metadata.uid, rpcEnospcFixture.uid);
        assert.equal(metadata.gid, rpcEnospcFixture.uid);
        assert.equal(metadata.dev.toString(), initial.dev.toString());
        assert.equal(metadata.mode & 0o777, 0o600);
        assert.deepEqual(JSON.parse(await owner.readFile('utf8')), identity);
      } finally {
        await owner.close();
      }
    }
    return { directory, pinned, inspect };
  } catch (error) {
    await directory.close();
    throw error;
  }
}

/** Called inside the admitted, non-root keeper, with its exact mount at root.
 * claim requires a new empty mount; inspect/fill/drain require the same claim.
 * Only ballast owned by this token can be removed; product files are read-only.
 */
export async function runRpcEnospcFilesystem(action, { identity, receipt }) {
  assert.ok(['claim', 'inspect', 'fill', 'drain'].includes(action));
  const root = await openRpcEnospcRoot(identity, action !== 'claim');
  const ballastPath = join(root.pinned, `.openpc-enospc-ballast-${identity.token}`);
  try {
    if (action === 'claim') {
      assert.deepEqual(await readdir(root.pinned), [], 'Refuse to claim existing/shared state');
      const owner = await open(join(root.pinned, rpcEnospcFixture.ownerFile), 'wx', 0o600);
      try {
        await owner.writeFile(JSON.stringify(identity));
        await owner.sync();
      } finally {
        await owner.close();
      }
      await root.directory.sync();
      return { identity, filesystem: await root.inspect() };
    }
    if (action === 'inspect') return { identity, filesystem: await root.inspect() };
    if (action === 'drain') {
      assert.equal(receipt?.token, identity.token);
      const file = await open(ballastPath, constants.O_WRONLY | constants.O_NOFOLLOW);
      try {
        const metadata = await file.stat({ bigint: true });
        assert.ok(metadata.isFile() && metadata.nlink === 1n);
        assert.equal(metadata.uid, BigInt(rpcEnospcFixture.uid));
        assert.equal(metadata.gid, BigInt(rpcEnospcFixture.uid));
        assert.equal(metadata.mode & 0o777n, 0o600n);
        assert.equal(metadata.dev.toString(), receipt.device);
        assert.equal(metadata.ino.toString(), receipt.inode);
        assert.ok(
          Number.isSafeInteger(receipt.bytes) &&
            receipt.bytes > 0 &&
            receipt.bytes <= rpcEnospcFixture.bytes,
        );
        assert.equal(metadata.size, BigInt(receipt.bytes));
        const current = await lstat(ballastPath, { bigint: true });
        assert.equal(current.dev, metadata.dev);
        assert.equal(current.ino, metadata.ino);
        await root.inspect();
        await file.truncate(0);
        await file.sync();
        await unlink(ballastPath);
      } finally {
        await file.close();
      }
      return { identity, filesystem: await root.inspect() };
    }
    const committed = await lstat(join(root.pinned, 'sealed-decisions.json'));
    const before = await root.inspect();
    assert.ok(committed.isFile() && committed.nlink === 1);
    assert.equal(committed.dev.toString(), before.device);
    assert.ok(
      committed.size > 2 * before.blockSize,
      'Real admitted history must span several blocks',
    );
    assert.ok(!(await readdir(root.pinned)).includes('sealed-decisions.next'));
    const ballast = await open(
      ballastPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    let result;
    const failures = [];
    try {
      const chunk = Buffer.alloc(64 * 1024, 0x5a);
      let written = 0,
        enospc = false;
      const deadline = performance.now() + 10000;
      // Real writes only: handle partial progress and bound both bytes and calls.
      for (let attempts = 0; attempts < rpcEnospcFixture.bytes / 512 + 2; attempts++) {
        assert.ok(performance.now() < deadline, 'Bounded ballast deadline exceeded');
        await root.inspect();
        try {
          const { bytesWritten } = await ballast.write(
            chunk,
            0,
            Math.min(chunk.length, rpcEnospcFixture.bytes - written + 1),
          );
          assert.ok(bytesWritten > 0);
          written += bytesWritten;
          assert.ok(written <= rpcEnospcFixture.bytes, 'Stop at the finite filesystem bound');
        } catch (error) {
          if (error.code !== 'ENOSPC') throw error;
          enospc = true;
          break;
        }
      }
      assert.ok(enospc, 'Physical ENOSPC must come from the kernel');
      const full = await root.inspect();
      assert.equal(full.availableBlocks, 0);
      assert.ok(written >= full.blockSize && written % full.blockSize === 0);
      // Leave one real block so the journal stages a prefix before its own
      // ENOSPC. This never changes an admitted record or the product limit.
      await ballast.truncate(written - full.blockSize);
      await ballast.sync();
      const ready = await root.inspect();
      assert.equal(ready.availableBlocks, 1);
      const metadata = await ballast.stat({ bigint: true });
      result = {
        identity,
        filesystem: ready,
        receipt: {
          token: identity.token,
          device: metadata.dev.toString(),
          inode: metadata.ino.toString(),
          bytes: written - full.blockSize,
        },
      };
    } catch (error) {
      failures.push(error);
    }
    if (!result) {
      // Before returning a receipt, this call still owns its exclusive inode.
      // A failed fill never leaves an untracked ballast allocation behind.
      try {
        const metadata = await ballast.stat({ bigint: true });
        const current = await lstat(ballastPath, { bigint: true });
        assert.equal(current.dev, metadata.dev);
        assert.equal(current.ino, metadata.ino);
        await ballast.truncate(0);
        await unlink(ballastPath);
      } catch (cleanupError) {
        failures.push(cleanupError);
      }
    }
    try {
      await ballast.close();
    } catch (error) {
      failures.push(error);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(failures, 'Ballast preparation and cleanup both failed');
    return result;
  } finally {
    await root.directory.close();
  }
}

export function parseRpcEnospcObservation(text, expected) {
  const match =
    /^OPENPC_RPC_ENOSPC_V1 ([0-9a-f]{32}) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ENOSPC\n$/u.exec(
      text,
    );
  assert.ok(match, 'A bounded real-write ENOSPC observation is required');
  const [token, pid, mountNamespace, pidNamespace, device, inode, stagingInode, stagingBytes] =
    match.slice(1);
  assert.deepEqual({ token, pid, mountNamespace, pidNamespace, device, inode }, expected);
  return { stagingInode, stagingBytes };
}

/** Runtime integration hook. The lifecycle owner supplies the exact live keeper
 * ID, token and volume name. It must first run --enospc claim inside that keeper,
 * mount this module read-only at script, and configure the target's observer
 * directory /runtime/rpc-enospc/<token> (0700, UID/GID 65532, outside the tmpfs).
 * No container, mount, key, owner claim or business state is created here.
 */
export async function connectRpcEnospcFixture(
  configuration,
  { targetContainerId, targetRuntimeId, execute },
) {
  assert.deepEqual(Object.keys(configuration).sort(), ['keeperContainerId', 'token', 'volumeName']);
  const { keeperContainerId, token, volumeName } = configuration;
  const identity = rpcEnospcIdentity({ token, volumeName, targetRuntimeId });
  for (const id of [keeperContainerId, targetContainerId]) assert.match(id, /^[0-9a-f]{64}$/u);
  assert.notEqual(keeperContainerId, targetContainerId);
  const journal = `/runtime/evidence/${targetRuntimeId}`;
  const control = `/runtime/rpc-enospc/${token}`;
  const docker = async (...args) => (await execute('docker', args)).stdout;
  const helper = async (action, receipt) =>
    JSON.parse(
      await docker(
        'exec',
        keeperContainerId,
        'node',
        rpcEnospcFixture.script,
        '--enospc',
        action,
        JSON.stringify({ identity, receipt }),
      ),
    );
  const inspect = async () => {
    const [target, keeper] = JSON.parse(
      await docker('inspect', targetContainerId, keeperContainerId),
    );
    assert.equal(target.Id, targetContainerId);
    assert.equal(keeper.Id, keeperContainerId);
    assert.ok(target.State.Running && keeper.State.Running);
    assert.ok(target.Config.Cmd.includes('runtime-target'));
    assert.equal(target.Config.User, '65532:65532');
    const project = target.Config.Labels['com.docker.compose.project'];
    assert.ok(project);
    const labels = {
      'io.openpc.fixture': 'rpc-journal-enospc',
      'io.openpc.fixture.token': token,
      'io.openpc.fixture.project': project,
      'io.openpc.fixture.target': targetRuntimeId,
    };
    const [volume] = JSON.parse(await docker('volume', 'inspect', volumeName));
    assert.equal(volume.Name, volumeName);
    assert.equal(volume.Driver, 'local');
    for (const resource of [keeper, volume]) {
      const actual = resource === keeper ? keeper.Config.Labels : volume.Labels;
      for (const [key, value] of Object.entries(labels)) assert.equal(actual?.[key], value);
    }
    assert.equal(volume.Options.type, 'tmpfs');
    assert.equal(volume.Options.device, 'tmpfs');
    const volumeOptions = volume.Options.o.split(',');
    for (const option of ['nosuid', 'nodev', 'noexec', 'uid=65532', 'gid=65532', 'mode=0700'])
      assert.ok(volumeOptions.includes(option));
    assert.equal(volumeOptions.filter((option) => option.startsWith('size=')).length, 1);
    assert.ok(
      volumeOptions.some((option) => ['size=67108864', 'size=65536k', 'size=64m'].includes(option)),
    );
    const users = (await docker('ps', '-aq', '--no-trunc', '--filter', `volume=${volumeName}`))
      .trim()
      .split('\n')
      .sort();
    assert.deepEqual(
      users,
      [keeperContainerId, targetContainerId].sort(),
      'No other consumer may share the fault filesystem',
    );
    for (const [container, destination] of [
      [target, journal],
      [keeper, rpcEnospcFixture.root],
    ]) {
      const mounts = container.Mounts.filter((mount) => mount.Destination === destination);
      assert.equal(mounts.length, 1);
      assert.equal(mounts[0].Type, 'volume');
      assert.equal(mounts[0].Name, volumeName);
      assert.equal(mounts[0].RW, true);
    }
    assert.equal(keeper.Config.User, '65532:65532');
    assert.equal(keeper.HostConfig.Privileged, false);
    assert.equal(keeper.HostConfig.ReadonlyRootfs, true);
    assert.equal(keeper.HostConfig.NetworkMode, 'none');
    assert.ok(keeper.HostConfig.CapDrop.includes('ALL'));
    assert.ok(!keeper.HostConfig.CapAdd?.length);
    assert.ok(
      keeper.HostConfig.SecurityOpt.some((option) => /^no-new-privileges(?::true)?$/u.test(option)),
    );
    assert.equal(keeper.HostConfig.Memory, 256 * 1024 * 1024);
    assert.equal(keeper.HostConfig.MemorySwap, keeper.HostConfig.Memory);
    assert.ok(keeper.HostConfig.NanoCpus > 0 && keeper.HostConfig.NanoCpus <= 250000000);
    assert.ok(keeper.HostConfig.PidsLimit > 0 && keeper.HostConfig.PidsLimit <= 128);
    assert.ok(
      keeper.Mounts.some(
        (mount) =>
          mount.Destination === rpcEnospcFixture.script && mount.Type === 'bind' && !mount.RW,
      ),
    );
    for (const assignment of [
      `OPENPC_RPC_JOURNAL_FAULT_DIRECTORY=${journal}`,
      `OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY=${control}`,
    ])
      assert.ok(target.Config.Env.includes(assignment));
    assert.ok(
      (await docker('exec', targetContainerId, 'cat', '/proc/1/maps')).includes(
        '/runtime/rpc-journal-crash-fixture.so',
      ),
    );
    rpcEnospcMount(await docker('exec', targetContainerId, 'cat', '/proc/1/mountinfo'), journal);
    const state = await helper('inspect');
    assert.deepEqual(state.identity, identity);
    assertRpcEnospcFilesystem(state.filesystem);
    const metadata = (
      await docker('exec', targetContainerId, 'stat', '-c', '%d %i %u %g %a', journal)
    )
      .trim()
      .split(' ');
    assert.deepEqual(metadata, [
      state.filesystem.device,
      state.filesystem.inode,
      '65532',
      '65532',
      '700',
    ]);
    const outside = (await docker('exec', targetContainerId, 'stat', '-c', '%d %u %g %a', control))
      .trim()
      .split(' ');
    assert.equal(outside.length, 4);
    assert.notEqual(
      outside[0],
      state.filesystem.device,
      'The marker must be outside the full filesystem',
    );
    assert.deepEqual(outside.slice(1), ['65532', '65532', '700']);
    assert.equal(
      (await docker('exec', targetContainerId, 'readlink', '-f', control)).trim(),
      control,
    );
    return {
      targetStartedAt: target.State.StartedAt,
      keeperStartedAt: keeper.State.StartedAt,
      filesystem: state.filesystem,
    };
  };
  const original = await inspect();
  await docker(
    'exec',
    targetContainerId,
    'sh',
    '-ceu',
    'test ! -e "$1/enospc.arm"; test ! -e "$1/enospc.observed"',
    'sh',
    control,
  );
  const namespaces = (
    await docker('exec', targetContainerId, 'stat', '-Lc', '%i', '/proc/1/ns/mnt', '/proc/1/ns/pid')
  )
    .trim()
    .split('\n');
  assert.equal(namespaces.length, 2);
  for (const namespace of namespaces) assert.match(namespace, /^[1-9][0-9]*$/u);
  const expected = {
    token,
    pid: '1',
    mountNamespace: namespaces[0],
    pidNamespace: namespaces[1],
    device: original.filesystem.device,
    inode: original.filesystem.inode,
  };
  let receipt;
  return {
    async begin() {
      assert.equal(receipt, undefined);
      const result = await helper('fill');
      receipt = result.receipt;
      assert.deepEqual(result.identity, identity);
      assert.equal(result.filesystem.device, expected.device);
      assert.equal(result.filesystem.inode, expected.inode);
      assert.equal(result.filesystem.availableBlocks, 1);
      const arm = `OPENPC_RPC_ENOSPC_ARM_V1 ${Object.values(expected).join(' ')}`;
      await docker(
        'exec',
        targetContainerId,
        'sh',
        '-ceu',
        'set -C; umask 077; test ! -L "$1"; test "$(readlink -f "$1")" = "$1"; test ! -e "$1/enospc.arm"; test ! -e "$1/enospc.observed"; printf "%s\\n" "$2" > "$1/enospc.arm"',
        'sh',
        control,
        arm,
      );
    },
    async observed() {
      const marker = parseRpcEnospcObservation(
        await docker('exec', targetContainerId, 'cat', `${control}/enospc.observed`),
        expected,
      );
      const staged = (
        await docker(
          'exec',
          targetContainerId,
          'stat',
          '-c',
          '%d %i %s',
          `${journal}/sealed-decisions.next`,
        )
      )
        .trim()
        .split(' ');
      assert.deepEqual(staged, [expected.device, marker.stagingInode, marker.stagingBytes]);
      assert.equal(Number(marker.stagingBytes), original.filesystem.blockSize);
      await docker('exec', targetContainerId, 'test', '!', '-e', `${control}/enospc.arm`);
      return marker;
    },
    async drain() {
      if (!receipt) return;
      const result = await helper('drain', receipt);
      assert.equal(result.filesystem.device, expected.device);
      assert.equal(result.filesystem.inode, expected.inode);
      assert.ok(result.filesystem.availableBlocks > 1);
      receipt = undefined;
    },
    async restarted() {
      assert.equal(receipt, undefined, 'Ballast must drain before recovery');
      const current = await inspect();
      assert.notEqual(
        current.targetStartedAt,
        original.targetStartedAt,
        'An actual target restart is required',
      );
      assert.equal(
        current.keeperStartedAt,
        original.keeperStartedAt,
        'The keeper must preserve the original filesystem',
      );
      assert.equal(current.filesystem.device, expected.device);
      assert.equal(current.filesystem.inode, expected.inode);
      await docker(
        'exec',
        targetContainerId,
        'test',
        '!',
        '-e',
        `${journal}/sealed-decisions.next`,
      );
    },
  };
}

// Pure negative corpus for the existing runner/CI owner to invoke before any
// mount allocation. It establishes parser rejection, not physical acceptance.
export function rpcEnospcContractRegression() {
  const identity = {
    token: 'a'.repeat(32),
    volumeName: `openpc-rpc-enospc-${'a'.repeat(32)}`,
    targetRuntimeId: '018f0000-0000-7000-8000-000000000001',
  };
  rpcEnospcIdentity(identity);
  for (const change of [{ token: '' }, { volumeName: 'shared' }, { targetRuntimeId: '../other' }])
    assert.throws(() => rpcEnospcIdentity({ ...identity, ...change }));
  const mount =
    '10 1 0:99 / /openpc-spool-enospc rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k\n';
  rpcEnospcMount(mount, rpcEnospcFixture.root);
  for (const altered of [
    mount.replace('/ /openpc', '/shared /openpc'),
    mount.replace('size=65536k', 'rw'),
    mount.replace(' - tmpfs ', ' - ext4 '),
    mount.replace(',noexec', ''),
    mount + mount,
  ])
    assert.throws(() => rpcEnospcMount(altered, rpcEnospcFixture.root));
  const filesystem = {
    type: '16914836',
    bytes: rpcEnospcFixture.bytes,
    blockSize: 4096,
    availableBlocks: 10,
    freeInodes: 100,
    uid: 65532,
    gid: 65532,
    mode: 0o700,
    device: '13',
    inode: '14',
  };
  assertRpcEnospcFilesystem(filesystem);
  for (const change of [
    { type: '61267' },
    { bytes: 128 * 1024 * 1024 },
    { blockSize: 0 },
    { availableBlocks: -1 },
    { availableBlocks: Infinity },
    { freeInodes: 0 },
    { uid: 0 },
    { gid: 0 },
    { mode: 0o777 },
  ])
    assert.throws(() => assertRpcEnospcFilesystem({ ...filesystem, ...change }));
  const expected = {
    token: identity.token,
    pid: '1',
    mountNamespace: '11',
    pidNamespace: '12',
    device: '13',
    inode: '14',
  };
  const observed = `OPENPC_RPC_ENOSPC_V1 ${identity.token} 1 11 12 13 14 15 4096 ENOSPC\n`;
  parseRpcEnospcObservation(observed, expected);
  for (const field of Object.keys(expected))
    assert.throws(() => parseRpcEnospcObservation(observed, { ...expected, [field]: '99' }));
  for (const altered of [
    '',
    observed + observed,
    observed.replace('ENOSPC\n', 'EIO\n'),
    observed.replace('4096 ENOSPC', '0 ENOSPC'),
  ])
    assert.throws(() => parseRpcEnospcObservation(altered, expected));
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url) &&
  process.argv[2] === '--enospc'
) {
  try {
    const result = await runRpcEnospcFilesystem(process.argv[3], JSON.parse(process.argv[4]));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const action = ['claim', 'inspect', 'fill', 'drain'].includes(process.argv[3])
      ? process.argv[3]
      : 'input';
    const cause =
      error instanceof AggregateError
        ? 'MULTIPLE_FAILURES'
        : ['ENOSPC', 'EACCES', 'EPERM', 'ENOENT', 'EEXIST', 'ELOOP', 'EROFS'].includes(error.code)
          ? error.code
          : 'CONTRACT';
    process.stderr.write(`OPENPC_RPC_ENOSPC_FIXTURE|FAIL|phase=${action}|cause=${cause}\n`);
    process.exitCode = 1;
  }
}
