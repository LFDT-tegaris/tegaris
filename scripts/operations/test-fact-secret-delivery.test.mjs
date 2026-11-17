import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statfsSync,
  writeFileSync,
} from 'node:fs';
import { Socket } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import { TLSSocket } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { Pool } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../services/identity-service/src/domain/identity-kernel.ts';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import { createTestFactSecretDelivery } from './test-fact-secret-delivery.mjs';
import { createTestFactSecretConsumer } from './test-fact-secret-consumer.mjs';

const CODE = 'OPS_TEST_FACT_SECRET_DELIVERY_INVALID';
const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
const version = 'v1';
const password = 'synthetic_delivery_test_password_123456789';
const source = fileURLToPath(import.meta.url);
const TMPFS_MAGIC = 0x01021994n;
const request = () => ({ reference, version });
const material = () =>
  Buffer.from(
    `postgresql://openpc_fact_bridge_reader:${password}@candidate-index-pg:5432/openpc_candidate_index`,
  );

// Deliberately NOT a signed installation fixture. These tests must be rejected
// by request/transport admission before any installed-profile query. Successful
// TLS + current Identity + signed profile + mount and post-use/commit/expiry
// failures require the integrator's real PostgreSQL/TLS acceptance environment.
const installed = () => ({
  issuerSpkiDer: Buffer.from('unsigned-negative-test-pin'),
  signedBindingDigest: `sha256:${'a'.repeat(64)}`,
  installationDigest: `sha256:${'b'.repeat(64)}`,
  environmentId: 'negative-test-environment',
  generation: '1',
  participantId: '01940000-0000-7000-8000-000000000001',
  privacyDomainId: '01940000-0000-7000-8000-000000000002',
  principalId: '01940000-0000-7000-8000-000000000003',
  workloadCredentialId: '01940000-0000-7000-8000-000000000004',
  workloadCredentialEpoch: '1',
});

function secretFree(value, root = '/unused-negative-delivery-root') {
  for (const output of [JSON.stringify(value), inspect(value, { showHidden: true })]) {
    for (const forbidden of [
      password,
      reference,
      'postgresql://',
      root,
      'unsigned-negative-test-pin',
    ]) {
      assert.ok(!output.includes(forbidden), 'diagnostics must not expose fixture inputs');
    }
  }
}

function rejection(reason, expected = {}, root) {
  return (error) => {
    assert.ok(error instanceof InstallationConfigError);
    assert.equal(error.code, CODE);
    assert.equal(error.reason, reason);
    assert.equal(error.message, `${CODE}: ${reason}`);
    assert.equal(error.cause, undefined);
    for (const [key, value] of Object.entries(expected)) assert.equal(error[key], value);
    secretFree(error, root);
    return true;
  };
}

function options(rootPath = '/unused-negative-delivery-root') {
  return {
    pool: undefined,
    kernel: undefined,
    installed: installed(),
    rootPath,
    reference,
    version,
    syntheticMaterial: undefined,
  };
}

function directory(parent, name = 'publication') {
  const root = join(parent, name);
  mkdirSync(root, { mode: 0o700 });
  return root;
}

async function withDelivery(root, use) {
  // Real lazy PostgreSQL and Identity owners. No fake successful identity or
  // injected recipient callback: every negative case must leave this pool empty.
  const pool = new Pool({
    host: '127.0.0.1',
    port: 1,
    user: 'unused_delivery_negative',
    password: 'synthetic_unused_password',
    database: 'unused_delivery_negative',
    max: 1,
    connectionTimeoutMillis: 100,
  });
  const kernel = new IdentityKernel(new PostgresIdentityRepository(pool));
  const bytes = material();
  let delivery;
  let connected = false;
  pool.on('connect', () => {
    connected = true;
  });
  try {
    delivery = createTestFactSecretDelivery({
      ...options(root),
      pool,
      kernel,
      syntheticMaterial: bytes,
    });
    bytes.fill(0);
    await use(delivery, pool);
    assert.equal(connected, false, 'negative admission must never open a database session');
    assert.equal(pool.totalCount, 0);
    assert.equal(pool.waitingCount, 0);
  } finally {
    bytes.fill(0);
    if (delivery) {
      try {
        await delivery.dispose();
      } catch {
        // UNKNOWN is asserted explicitly by its case and must remain UNKNOWN.
        assert.equal(delivery.describe().state, 'UNKNOWN');
      }
    }
    await pool.end();
  }
}

function noPublication(root) {
  assert.equal(existsSync(join(root, 'candidate-url')), false);
  assert.deepEqual(readdirSync(root), ['.test-fact-secret-owner']);
}

const denied = {
  failureCode: 'PC-IDENTITY-1006',
  cleanupState: 'ERASED',
  cleanupFailure: null,
  state: 'BLOCKED',
  startupAllowed: false,
};

const cases = {
  async assertedMetadata(parent) {
    const root = directory(parent);
    await withDelivery(root, async (delivery) => {
      const asserted = {
        authorized: true,
        getProtocol: () => 'TLSv1.3',
        participantId: installed().participantId,
        workload: 'LS-FACT-BRIDGE',
      };
      await assert.rejects(
        delivery.publish(asserted, request()),
        rejection('RECIPIENT_REJECTED', denied, root),
      );
      assert.equal(delivery.describe().providerState, 'REVOKED');
      assert.equal(delivery.describe().recipientCheck, 'REJECTED');
      assert.equal(delivery.describe().publicationState, 'REVOKED');
      noPublication(root);
      secretFree(delivery, root);
      secretFree(delivery.describe(), root);
      await assert.rejects(
        delivery.publish(asserted, request()),
        rejection('RECIPIENT_REJECTED', denied, root),
      );
      assert.deepEqual(await delivery.dispose(), await delivery.dispose());
    });
  },

  async unhandshakenSocket(parent) {
    const root = directory(parent);
    await withDelivery(root, async (delivery) => {
      const socket = new TLSSocket(new Socket());
      try {
        await assert.rejects(
          delivery.publish(socket, request()),
          rejection('RECIPIENT_REJECTED', denied, root),
        );
        noPublication(root);
      } finally {
        socket.destroy();
      }
    });
  },

  async disposeBeforePublication(parent) {
    const root = directory(parent);
    await withDelivery(root, async (delivery) => {
      assert.ok(Object.isFrozen(delivery));
      assert.ok(Object.isFrozen(delivery.describe()));
      assert.equal(delivery.describe().providerState, 'ACTIVE');
      assert.equal(delivery.describe().startupAllowed, false);
      const disposed = await delivery.dispose();
      assert.equal(disposed.providerState, 'REVOKED');
      assert.equal(disposed.cleanupState, 'ERASED');
      assert.equal(disposed.recipientCheck, 'UNVERIFIED');
      assert.equal(disposed.databaseSession, 'UNVERIFIED');
      assert.equal(disposed.startupAllowed, false);
      assert.equal(disposed.failure, null);
      await assert.rejects(
        delivery.publish(null, request()),
        rejection('DELIVERY_CLOSED', { state: 'BLOCKED', startupAllowed: false }, root),
      );
      noPublication(root);
      assert.deepEqual(await delivery.dispose(), disposed);
    });
  },

  async namespaceChanged(parent) {
    const root = directory(parent);
    await withDelivery(root, async (delivery) => {
      const foreign = join(root, password);
      writeFileSync(foreign, 'foreign-owner-bytes', { mode: 0o600 });
      const expected = {
        failureCode: 'PC-IDENTITY-1006',
        cleanupState: 'UNKNOWN',
        cleanupFailure: 'MOUNT_CLEANUP_FAILED',
        cleanupFailureCode: 'OPS_TEST_FACT_SECRET_MOUNT_INVALID',
        state: 'UNKNOWN',
        startupAllowed: false,
      };
      await assert.rejects(
        delivery.publish(null, request()),
        rejection('RECIPIENT_REJECTED', expected, root),
      );
      await assert.rejects(delivery.dispose(), rejection('RECIPIENT_REJECTED', expected, root));
      await assert.rejects(
        delivery.publish(null, request()),
        rejection('RECIPIENT_REJECTED', expected, root),
      );
      assert.equal(readFileSync(foreign, 'utf8'), 'foreign-owner-bytes');
      assert.equal(existsSync(join(root, 'candidate-url')), false);
      assert.equal(delivery.describe().providerState, 'REVOKED');
      assert.equal(delivery.describe().publicationState, 'UNKNOWN');
      assert.equal(delivery.describe().failure, 'RECIPIENT_REJECTED');
      secretFree(delivery.describe(), root);
    });
  },

  async existingRoot(parent) {
    const root = directory(parent);
    const foreign = join(root, password);
    writeFileSync(foreign, 'foreign-owner-bytes', { mode: 0o600 });
    const bytes = material();
    try {
      assert.throws(
        () => createTestFactSecretDelivery({ ...options(root), syntheticMaterial: bytes }),
        rejection(
          'MOUNT_CREATION_FAILED',
          {
            failureCode: 'OPS_TEST_FACT_SECRET_MOUNT_INVALID',
            cleanupState: 'UNKNOWN',
            cleanupFailure: 'MOUNT_CREATION_UNCERTAIN',
            state: 'UNKNOWN',
            startupAllowed: false,
          },
          root,
        ),
      );
      assert.equal(readFileSync(foreign, 'utf8'), 'foreign-owner-bytes');
      assert.deepEqual(readdirSync(root), [password]);
    } finally {
      bytes.fill(0);
    }
  },

  async malformedRequest(parent) {
    let getterCalls = 0;
    const accessor = { version };
    Object.defineProperty(accessor, 'reference', {
      enumerable: true,
      get() {
        getterCalls++;
        throw new Error(password);
      },
    });
    const badRequests = [
      accessor,
      { ...request(), authenticated: true },
      { reference },
      { ...request(), [Symbol('authority')]: true },
      Object.create(request()),
    ];
    for (const [index, bad] of badRequests.entries()) {
      const root = directory(parent, `malformed-${index}`);
      await withDelivery(root, async (delivery) => {
        await assert.rejects(
          delivery.publish(null, bad),
          rejection(
            'REQUEST_INVALID',
            {
              cleanupState: 'ERASED',
              state: 'BLOCKED',
              startupAllowed: false,
            },
            root,
          ),
        );
        assert.equal(delivery.describe().providerState, 'REVOKED');
        noPublication(root);
      });
    }
    assert.equal(getterCalls, 0);
  },

  async pendingDisposal(parent) {
    const root = directory(parent);
    await withDelivery(root, async (delivery) => {
      const pending = delivery.publish(null, request());
      const second = delivery.publish(null, request());
      const disposed = delivery.dispose();
      await Promise.all([
        assert.rejects(pending, rejection('RECIPIENT_REJECTED', denied, root)),
        assert.rejects(second, rejection('DELIVERY_BUSY', {}, root)),
      ]);
      assert.equal((await disposed).cleanupState, 'ERASED');
      assert.equal(delivery.describe().providerState, 'REVOKED');
      noPublication(root);
    });
  },
};

if (process.argv[2] === '--delivery-case') {
  try {
    assert.ok(Object.hasOwn(cases, process.argv[3]));
    await cases[process.argv[3]](process.argv[4]);
    process.stdout.write('FACT_SECRET_DELIVERY_CASE_PASS\n');
  } catch {
    // Assertions may contain paths or material: never render the caught error.
    process.stderr.write('FACT_SECRET_DELIVERY_CASE_FAIL\n');
    process.exitCode = 1;
  }
} else {
  test('delivery rejects invalid real TLS material before reserving a candidate database login', async () => {
    const pool = new Pool({ host: '127.0.0.1', port: 1, connectionTimeoutMillis: 100, max: 1 });
    let attempted = false;
    const connect = pool.connect.bind(pool);
    pool.connect = (...args) => {
      attempted = true;
      return connect(...args);
    };
    try {
      await assert.rejects(
        createTestFactSecretConsumer({
          ...options(),
          candidateAdminPool: pool,
          tls: {
            ca: Buffer.from('invalid'),
            certificate: Buffer.from('invalid'),
            privateKey: Buffer.from('invalid'),
          },
        }),
      );
      assert.equal(attempted, false);
      assert.equal(pool.totalCount, 0);
    } finally {
      await pool.end();
    }
  });
  test('delivery rejects alternate providers, floating/mismatched versions and extra authority before mount allocation', () => {
    for (const input of [
      { ...options(), reference: reference.replace('test-memory-resolver', 'local-os-keystore') },
      { ...options(), version: 'v2' },
      { ...options(), reference: reference.replace('#v1', '#latest'), version: 'latest' },
      { ...options(), authenticated: true },
      {
        ...options(),
        withRecipient: () => {
          throw new Error(password);
        },
      },
      { ...options(), installed: { ...installed(), startupAllowed: true } },
      { ...options(), installed: { ...installed(), generation: 1 } },
      { ...options(), [Symbol('authority')]: true },
      Object.create(options()),
      null,
    ]) {
      assert.throws(() => createTestFactSecretDelivery(input), rejection('INPUT_INVALID'));
    }
  });

  test('delivery snapshots only data properties without invoking input accessors', () => {
    let getterCalls = 0;
    for (const target of ['rootPath', 'installed', 'issuerSpkiDer']) {
      const input = options();
      const owner = target === 'issuerSpkiDer' ? input.installed : input;
      Object.defineProperty(owner, target, {
        enumerable: true,
        get() {
          getterCalls++;
          throw new Error(password);
        },
      });
      assert.throws(() => createTestFactSecretDelivery(input), rejection('INPUT_INVALID'));
    }
    assert.equal(getterCalls, 0);
  });

  test('invalid synthetic material is rejected and redacted before mount allocation', () => {
    const bytes = Buffer.from(password);
    try {
      assert.throws(
        () => createTestFactSecretDelivery({ ...options(), syntheticMaterial: bytes }),
        rejection('PROVIDER_CREATION_FAILED', {
          failureCode: 'OPS_TEST_SECRET_PROVIDER_INVALID',
          cleanupState: 'ERASED',
          state: 'BLOCKED',
          startupAllowed: false,
        }),
      );
    } finally {
      bytes.fill(0);
    }
  });

  for (const name of Object.keys(cases)) {
    test(`real recipient denial and tmpfs cleanup: ${name}`, (t) => {
      if (
        process.platform !== 'linux' ||
        ![0, 65532].includes(process.geteuid()) ||
        (process.geteuid() === 65532 && process.getegid() !== 65532)
      ) {
        assert.notEqual(
          process.env.OPENPC_REQUIRE_FACT_SECRET_DELIVERY,
          '1',
          'required kernel identity unavailable',
        );
        t.skip('PENDING: integrator must execute as UID/GID 65532 or a root launcher');
        return;
      }
      if (
        !existsSync('/dev/shm') ||
        statfsSync('/dev/shm', { bigint: true }).type !== TMPFS_MAGIC
      ) {
        assert.notEqual(
          process.env.OPENPC_REQUIRE_FACT_SECRET_DELIVERY,
          '1',
          'required tmpfs unavailable',
        );
        t.skip('PENDING: real Linux tmpfs required');
        return;
      }
      const root = mkdtempSync('/dev/shm/openpc-fact-secret-delivery-');
      try {
        chmodSync(root, 0o700);
        if (process.geteuid() === 0) chownSync(root, 65532, 65532);
        const result = spawnSync(
          process.execPath,
          ['--import', 'tsx', source, '--delivery-case', name, root],
          { uid: 65532, gid: 65532, encoding: 'utf8', timeout: 45_000, maxBuffer: 65_536 },
        );
        assert.equal(result.status, 0, 'real kernel case failed; secret diagnostics withheld');
        assert.equal(result.stdout, 'FACT_SECRET_DELIVERY_CASE_PASS\n');
        assert.equal(result.stderr, '');
      } finally {
        // Only this test's exclusively created root; never a production mount.
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
}
