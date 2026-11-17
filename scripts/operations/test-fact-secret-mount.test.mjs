import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statfsSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { bindTestFactCandidateDatabaseReference } from './installation-consumer-bindings.mjs';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import { createTestSecretProvider } from './test-secret-provider.mjs';
import { createTestFactSecretMount } from './test-fact-secret-mount.mjs';

const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
const version = 'v1';
const password = 'synthetic_test_only_password_123456789';
const binding = bindTestFactCandidateDatabaseReference(reference, version);
const source = fileURLToPath(import.meta.url);
const TMPFS_MAGIC = 0x01021994n;
const material = (value = password) =>
  Buffer.from(
    `postgresql://openpc_fact_bridge_reader:${value}@candidate-index-pg:5432/openpc_candidate_index`,
  );

function fixture(value = password, target = binding) {
  const bytes = material(value);
  try {
    return createTestSecretProvider(target, bytes);
  } finally {
    bytes.fill(0);
  }
}

function rejection(reason) {
  return (error) => {
    assert.ok(error instanceof InstallationConfigError);
    assert.equal(error.code, 'OPS_TEST_FACT_SECRET_MOUNT_INVALID');
    assert.equal(error.reason, reason);
    assert.equal(error.message, `OPS_TEST_FACT_SECRET_MOUNT_INVALID: ${reason}`);
    assert.equal(error.cause, undefined);
    for (const value of [error.stack, error.message, JSON.stringify(error), inspect(error)]) {
      assert.ok(!value.includes(password), 'material must not enter diagnostics');
      assert.ok(!value.includes(reference), 'reference must not enter diagnostics');
      assert.ok(!value.includes('postgresql://'), 'DSN must not enter diagnostics');
    }
    return true;
  };
}

function directory(parent, name = 'publication') {
  const root = join(parent, name);
  mkdirSync(root, { mode: 0o700 });
  return root;
}

const create = (root) => createTestFactSecretMount(root, reference, version);
function sameBytes(path, expected) {
  const actual = readFileSync(path);
  try {
    assert.ok(actual.equals(expected), 'expected original bytes');
  } finally {
    actual.fill(0);
  }
}

// These are real filesystem cases executed in a separate UID/GID-65532 process.
// Only the external synthetic provider is fault-injected. No identity, kernel
// ownership/backing, database or readiness owner is replaced by a test stub.
const cases = {
  async publication(parent) {
    const root = directory(parent);
    const mount = create(root);
    const provider = fixture();
    const expected = material();
    let lent;
    const observingProvider = {
      withMaterial(request, consume) {
        return provider.withMaterial(request, (bytes) => {
          lent = bytes;
          return consume(bytes);
        });
      },
    };
    assert.equal(await mount.publish(observingProvider), undefined);
    assert.ok(
      lent.every((value) => value === 0),
      'provider loan must be erased',
    );
    const path = join(root, 'candidate-url');
    const original = lstatSync(path);
    assert.equal(original.uid, 65532);
    assert.equal(original.gid, 65532);
    assert.equal(original.mode & 0o7777, 0o400);
    assert.equal(original.nlink, 1);
    assert.throws(() => writeFileSync(path, 'must-not-overwrite'), { code: 'EACCES' });
    sameBytes(path, expected);
    await mount.publish(provider);
    assert.equal(lstatSync(path).ino, original.ino);
    assert.ok(Object.isFrozen(mount));
    for (const output of [JSON.stringify(mount), inspect(mount, { showHidden: true })]) {
      assert.ok(!output.includes(password));
      assert.ok(!output.includes(reference));
    }
    mount.dispose();
    mount.dispose();
    assert.equal(lstatSync(path).size, 0);
    assert.equal(lstatSync(path).ino, original.ino);
    assert.throws(() => create(root), rejection('ROOT_NOT_EMPTY'));
    await assert.rejects(mount.publish(provider), rejection('PUBLICATION_CLOSED'));
    expected.fill(0);
    provider.reset();
  },

  async replacement(parent) {
    const root = directory(parent);
    const mount = create(root);
    const first = fixture();
    const changed = fixture('different_synthetic_test_password_987654321');
    await mount.publish(first);
    const before = lstatSync(join(root, 'candidate-url'));
    await assert.rejects(mount.publish(changed), rejection('MATERIAL_CHANGED'));
    assert.equal(lstatSync(join(root, 'candidate-url')).ino, before.ino);
    const expected = material();
    sameBytes(join(root, 'candidate-url'), expected);
    const nextRoot = directory(parent, 'replacement');
    const next = create(nextRoot);
    await next.publish(changed);
    assert.notEqual(lstatSync(join(nextRoot, 'candidate-url')).ino, before.ino);
    // The real owner must stop/remount its consumer; this only disposes generation one.
    mount.dispose();
    assert.equal(lstatSync(join(root, 'candidate-url')).size, 0);
    assert.ok(lstatSync(join(nextRoot, 'candidate-url')).size > 0);
    next.dispose();
    expected.fill(0);
    first.reset();
    changed.reset();
  },

  async providerDenials(parent) {
    const root = directory(parent);
    const mount = create(root);
    const missing = createTestSecretProvider(binding);
    const revoked = fixture();
    revoked.revoke();
    const wrongVersion = fixture(
      password,
      bindTestFactCandidateDatabaseReference(reference.replace('#v1', '#v2'), 'v2'),
    );
    for (const provider of [missing, revoked, wrongVersion]) {
      await assert.rejects(mount.publish(provider), rejection('PROVIDER_REJECTED'));
      assert.equal(existsSync(join(root, 'candidate-url')), false);
      provider.reset();
    }
    mount.dispose();
  },

  async backing(parent, disk) {
    assert.notEqual(statfsSync(disk, { bigint: true }).type, TMPFS_MAGIC);
    assert.throws(() => create(disk), rejection('BACKING_INVALID'));
    assert.deepEqual(readdirSync(disk), []);
    const root = directory(parent);
    chmodSync(root, 0o755);
    assert.throws(() => create(root), rejection('ROOT_CHANGED'));
    assert.deepEqual(readdirSync(root), []);
    assert.notEqual(lstatSync('/dev/shm').uid, 65532);
    assert.throws(() => create('/dev/shm'), rejection('ROOT_CHANGED'));
  },

  async existing(parent) {
    for (const kind of ['file', 'symlink', 'hardlink']) {
      const root = directory(parent, kind);
      const path = join(root, 'candidate-url');
      const original = join(parent, `${kind}-original`);
      writeFileSync(original, 'unrelated-owned-fixture', { mode: 0o600 });
      if (kind === 'file') writeFileSync(path, 'existing-fixture');
      if (kind === 'symlink') symlinkSync(original, path);
      if (kind === 'hardlink') linkSync(original, path);
      assert.throws(() => create(root), rejection('ROOT_NOT_EMPTY'));
      sameBytes(original, Buffer.from('unrelated-owned-fixture'));
    }
    const actual = directory(parent, 'actual-root');
    const alias = join(parent, 'aliased-root');
    symlinkSync(actual, alias);
    assert.throws(() => create(alias), rejection('ROOT_UNAVAILABLE'));
    const intermediate = join(parent, 'aliased-parent');
    symlinkSync(parent, intermediate);
    assert.throws(() => create(join(intermediate, 'actual-root')), rejection('ROOT_CHANGED'));
    assert.deepEqual(readdirSync(actual), []);
  },

  async substitutedBeforePublication(parent) {
    const root = directory(parent);
    const mount = create(root);
    const victim = join(parent, 'unrelated');
    writeFileSync(victim, 'must-remain', { mode: 0o600 });
    symlinkSync(victim, join(root, 'candidate-url'));
    const provider = fixture();
    await assert.rejects(mount.publish(provider), rejection('ROOT_CONTENTS_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('ROOT_CONTENTS_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('ROOT_CONTENTS_CHANGED'));
    sameBytes(victim, Buffer.from('must-remain'));
    provider.reset();
  },

  async substitutedAfterPublication(parent) {
    const root = directory(parent);
    const mount = create(root);
    const provider = fixture();
    await mount.publish(provider);
    const path = join(root, 'candidate-url');
    renameSync(path, join(parent, 'original-inode'));
    writeFileSync(path, 'unrelated-replacement', { mode: 0o400 });
    await assert.rejects(mount.publish(provider), rejection('FILE_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('FILE_CHANGED'));
    sameBytes(path, Buffer.from('unrelated-replacement'));
    const expected = material();
    sameBytes(join(parent, 'original-inode'), expected);
    expected.fill(0);
    provider.reset();
  },

  async changedInodeContents(parent) {
    const root = directory(parent);
    const mount = create(root);
    const provider = fixture();
    await mount.publish(provider);
    const path = join(root, 'candidate-url');
    chmodSync(path, 0o600);
    writeFileSync(path, 'changed-by-another-writer');
    chmodSync(path, 0o400);
    await assert.rejects(mount.publish(provider), rejection('FILE_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('FILE_CHANGED'));
    sameBytes(path, Buffer.from('changed-by-another-writer'));
    provider.reset();
  },

  async hardlinkAfterPublication(parent) {
    const root = directory(parent);
    const mount = create(root);
    const provider = fixture();
    await mount.publish(provider);
    const link = join(parent, 'unexpected-link');
    linkSync(join(root, 'candidate-url'), link);
    await assert.rejects(mount.publish(provider), rejection('FILE_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('FILE_CHANGED'));
    const expected = material();
    sameBytes(link, expected);
    expected.fill(0);
    provider.reset();
  },

  async rootAndClaimSubstitution(parent) {
    const root = directory(parent);
    const mount = create(root);
    renameSync(root, join(parent, 'original-root'));
    mkdirSync(root, { mode: 0o700 });
    const provider = fixture();
    await assert.rejects(mount.publish(provider), rejection('ROOT_CHANGED'));
    assert.throws(() => mount.dispose(), rejection('ROOT_CHANGED'));
    assert.deepEqual(readdirSync(root), []);
    const secondRoot = directory(parent, 'second');
    const second = create(secondRoot);
    const claim = join(secondRoot, '.test-fact-secret-owner');
    renameSync(claim, join(parent, 'original-claim'));
    writeFileSync(claim, '', { mode: 0 });
    await assert.rejects(second.publish(provider), rejection('OWNERSHIP_CHANGED'));
    assert.throws(() => second.dispose(), rejection('OWNERSHIP_CHANGED'));
    provider.reset();
  },

  async boundedExternalInputs(parent) {
    const root = directory(parent);
    const mount = create(root);
    // External provider faults only; these cannot establish successful acceptance.
    for (const value of [Buffer.alloc(0), Buffer.alloc(4097), password, null]) {
      const faultyProvider = { withMaterial: async (_request, consume) => consume(value) };
      await assert.rejects(mount.publish(faultyProvider), rejection('MATERIAL_INVALID'));
      assert.equal(existsSync(join(root, 'candidate-url')), false);
    }
    await assert.rejects(
      mount.publish({ withMaterial: async () => undefined }),
      rejection('HANDOFF_MISSING'),
    );
    await assert.rejects(mount.publish(null), rejection('PROVIDER_REJECTED'));
    await assert.rejects(
      mount.publish({
        async withMaterial() {
          throw new InstallationConfigError(password, 'OPS_TEST_FACT_SECRET_MOUNT_INVALID');
        },
      }),
      rejection('PROVIDER_REJECTED'),
    );
    mount.dispose();
  },

  async interruption(parent) {
    const root = directory(parent);
    const interrupted = spawnSync(
      process.execPath,
      ['--import', 'tsx', source, '--mount-case', 'crashBeforeMaterial', root],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 },
    );
    assert.equal(interrupted.status, 73, 'fixture must exit with its owner still open');
    assert.equal(existsSync(join(root, 'candidate-url')), false);
    assert.throws(() => create(root), rejection('ROOT_NOT_EMPTY'));
    const nextRoot = directory(parent, 'failed-handoff');
    const mount = create(nextRoot);
    const provider = fixture();
    const interruptedProvider = {
      async withMaterial(request, consume) {
        await provider.withMaterial(request, consume);
        throw new Error(password);
      },
    };
    await assert.rejects(mount.publish(interruptedProvider), rejection('PROVIDER_REJECTED'));
    assert.equal(lstatSync(join(nextRoot, 'candidate-url')).size, 0);
    mount.dispose();
    await assert.rejects(mount.publish(provider), rejection('PUBLICATION_CLOSED'));
    provider.reset();
  },

  async busyAndRevokedHandoff(parent) {
    const root = directory(parent);
    const mount = create(root);
    const provider = fixture();
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const delayed = {
      async withMaterial(request, consume) {
        await gate;
        await provider.withMaterial(request, consume);
      },
    };
    const pending = mount.publish(delayed);
    await assert.rejects(mount.publish(provider), rejection('PUBLICATION_BUSY'));
    assert.throws(() => mount.dispose(), rejection('PUBLICATION_BUSY'));
    provider.revoke();
    release();
    await assert.rejects(pending, rejection('PROVIDER_REJECTED'));
    assert.equal(existsSync(join(root, 'candidate-url')), false);
    mount.dispose();
  },

  async lateHandoff(parent) {
    const root = directory(parent);
    const mount = create(root);
    let callback;
    await assert.rejects(
      mount.publish({
        async withMaterial(_request, consume) {
          callback = consume;
        },
      }),
      rejection('HANDOFF_MISSING'),
    );
    const bytes = material();
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const provider = fixture();
    const next = mount.publish({
      async withMaterial(request, consume) {
        await gate;
        await provider.withMaterial(request, consume);
      },
    });
    assert.throws(() => callback(bytes), rejection('HANDOFF_CLOSED'));
    assert.equal(existsSync(join(root, 'candidate-url')), false);
    release();
    await next;
    bytes.fill(0);
    mount.dispose();
    provider.reset();
  },

  crashBeforeMaterial(root) {
    create(root);
    // A real process exit closes descriptors but must not permit claim takeover.
    process.exit(73);
  },
};

if (process.argv[2] === '--mount-case') {
  try {
    const run = cases[process.argv[3]];
    assert.equal(typeof run, 'function');
    await run(process.argv[4], process.argv[5]);
    process.stdout.write('FACT_SECRET_MOUNT_CASE_PASS\n');
  } catch {
    // Never render assertion values, native paths, provider errors or secret bytes.
    process.stderr.write('FACT_SECRET_MOUNT_CASE_FAIL\n');
    process.exitCode = 1;
  }
} else {
  test('invalid reference and alternate root spelling fail before filesystem writes', () => {
    for (const bad of [reference.replace('test-memory-resolver', 'local-os-keystore'), 'inline']) {
      assert.throws(
        () => createTestFactSecretMount('/unused', bad, version),
        rejection('BINDING_INVALID'),
      );
    }
    for (const root of ['relative', '/tmp/../tmp/root', '/tmp/root/', '/tmp/root\n', null]) {
      assert.throws(() => create(root), rejection('ROOT_PATH_INVALID'));
    }
  });

  test('execution as any other UID or GID fails before opening a root', (t) => {
    if (process.geteuid?.() === 65532 && process.getegid?.() === 65532) {
      t.skip('negative execution-identity case requires a different real UID/GID');
      return;
    }
    assert.throws(() => create('/unused'), rejection('EXECUTION_IDENTITY'));
  });

  for (const name of Object.keys(cases).filter((value) => value !== 'crashBeforeMaterial')) {
    test(`real tmpfs publication: ${name}`, (t) => {
      if (
        process.platform !== 'linux' ||
        ![0, 65532].includes(process.geteuid()) ||
        (process.geteuid() === 65532 && process.getegid() !== 65532)
      ) {
        assert.notEqual(
          process.env.OPENPC_REQUIRE_FACT_SECRET_MOUNT,
          '1',
          'required kernel identity unavailable',
        );
        t.skip('PENDING: integrator must execute kernel cases as UID/GID 65532 (or root launcher)');
        return;
      }
      if (
        !existsSync('/dev/shm') ||
        statfsSync('/dev/shm', { bigint: true }).type !== TMPFS_MAGIC
      ) {
        assert.notEqual(
          process.env.OPENPC_REQUIRE_FACT_SECRET_MOUNT,
          '1',
          'required tmpfs unavailable',
        );
        t.skip('PENDING: real Linux tmpfs is required; there is no disk substitute');
        return;
      }
      const root = mkdtempSync('/dev/shm/openpc-fact-secret-mount-');
      const disk = mkdtempSync(join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'fact-mount-'));
      try {
        chmodSync(root, 0o700);
        chmodSync(disk, 0o700);
        if (process.geteuid() === 0) {
          chownSync(root, 65532, 65532);
          chownSync(disk, 65532, 65532);
        }
        if (name === 'backing' && statfsSync(disk, { bigint: true }).type === TMPFS_MAGIC) {
          assert.notEqual(
            process.env.OPENPC_REQUIRE_FACT_SECRET_MOUNT,
            '1',
            'required disk rejection fixture unavailable',
          );
          t.skip('PENDING: backing rejection also requires an owned disk-backed test directory');
          return;
        }
        const result = spawnSync(
          process.execPath,
          ['--import', 'tsx', source, '--mount-case', name, root, disk],
          {
            uid: 65532,
            gid: 65532,
            encoding: 'utf8',
            timeout: 45_000,
            maxBuffer: 65_536,
          },
        );
        assert.equal(result.status, 0, 'real kernel case failed; no secret diagnostics emitted');
        assert.equal(result.stdout, 'FACT_SECRET_MOUNT_CASE_PASS\n');
        assert.equal(result.stderr, '');
      } finally {
        // Exclusively created test roots; production disposal never does recursive removal.
        rmSync(root, { recursive: true, force: true });
        rmSync(disk, { recursive: true, force: true });
      }
    });
  }
}
