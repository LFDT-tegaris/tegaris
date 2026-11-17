import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.ts';
import { createTestFactSecretDelivery } from '../../../scripts/operations/test-fact-secret-delivery.mjs';

// The existing database test passes only its disposable fixture over stdin.
// This process runs as the real consumer UID on Docker tmpfs. No material or
// underlying exception is returned to the parent or an HTTP response.
let stage = 'input';
let root, delivery, app, runtime, admin;
try {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    assert.ok(size < 65_536);
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString());
  for (const chunk of chunks) chunk.fill(0);
  assert.equal(process.geteuid(), 65532);
  assert.equal(process.getegid(), 65532);
  assert.ok(['success', 'expiry', 'commit-loss', 'cleanup-unknown'].includes(input.mode));
  root = mkdtempSync('/dev/shm/openpc-secret-delivery-');
  const path = join(root, 'candidate-url');
  runtime = new Pool({ connectionString: input.runtimeUrl, max: 2 });
  admin = new Pool({ connectionString: input.adminUrl, max: 1 });
  const pins = { ...input.pins, issuerSpkiDer: Buffer.from(input.pins.issuerSpkiDer, 'base64') };
  const expected = Buffer.from(input.material, 'base64');
  const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
  const server = Object.fromEntries(
    Object.entries(input.tls.server).map(([key, value]) => [key, Buffer.from(value, 'base64')]),
  );
  const clientTls = {
    ca: server.ca,
    cert: Buffer.from(input.tls.certificate, 'base64'),
    key: Buffer.from(input.tls.privateKey, 'base64'),
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  };
  let injected = false;
  // Synchronization only: every SQL result still comes from real PostgreSQL.
  // Stop the actual backend at the post-publication COMMIT boundary; expiry
  // waits at the actual post-use clock query while the independent timer runs.
  runtime.on('connect', (client) => {
    client.on('error', () => {});
    const query = client.query.bind(client);
    client.query = function (...args) {
      const sql = typeof args[0] === 'string' ? args[0] : args[0]?.text;
      const published = existsSync(path) && statSync(path).size > 0;
      const expire =
        input.mode === 'expiry' && sql?.includes('floor(extract(epoch from clock_timestamp())');
      const terminate = ['commit-loss', 'cleanup-unknown'].includes(input.mode) && sql === 'commit';
      if (!injected && published && (expire || terminate)) {
        injected = true;
        return (async () => {
          assert.equal(statSync(path).mode & 0o777, 0o400);
          assert.deepEqual(readFileSync(path), expected);
          if (expire) {
            await delay(Math.max(1, input.validUntilMs - Date.now() + 40));
            assert.equal(statSync(path).size, 0, 'expiry erases before the pending SQL finishes');
          } else {
            if (input.mode === 'cleanup-unknown')
              writeFileSync(join(root, 'foreign'), 'keep-original-foreign-file');
            const pid = (await query('select pg_backend_pid() pid')).rows[0].pid;
            assert.equal(
              (await admin.query('select pg_terminate_backend($1) stopped', [pid])).rows[0].stopped,
              true,
            );
          }
          return query(...args);
        })();
      }
      return query(...args);
    };
  });
  delivery = createTestFactSecretDelivery({
    pool: runtime,
    kernel,
    installed: pins,
    rootPath: root,
    reference: input.reference,
    version: 'v1',
    syntheticMaterial: expected,
  });
  let rejection;
  const build = () => {
    const result = buildLocalWorkloadMtlsService(runtime, kernel, server);
    result.post('/test/delivery', async (req, reply) => {
      try {
        return await delivery.publish(req.raw.socket, req.body);
      } catch (error) {
        rejection = error;
        return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
      }
    });
    return result;
  };
  const post = (address) =>
    new Promise((resolve, reject) => {
      const call = request(
        `${address}/test/delivery`,
        { ...clientTls, method: 'POST', headers: { 'content-type': 'application/json' } },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('error', reject);
          res.on('end', () => {
            try {
              resolve({
                status: res.statusCode,
                body: JSON.parse(Buffer.concat(chunks).toString()),
              });
            } catch {
              reject(new Error('invalid response'));
            }
          });
        },
      );
      call.on('error', reject);
      call.setTimeout(15_000, () => call.destroy(new Error('bounded TLS request timeout')));
      call.end(JSON.stringify({ reference: input.reference, version: 'v1' }));
    });
  stage = 'publication';
  app = build();
  let address = await app.listen({ host: '127.0.0.1', port: 0 });
  const result = await post(address);
  if (input.mode === 'success') {
    assert.equal(result.status, 200);
    assert.equal(result.body.startupAllowed, false);
    assert.equal(result.body.recipientCheck, 'PASSED_AT_PUBLICATION');
    assert.equal(result.body.publicationState, 'PUBLISHED');
    const original = statSync(path);
    assert.equal(original.uid, 65532);
    assert.equal(original.gid, 65532);
    assert.equal(original.mode & 0o777, 0o400);
    assert.deepEqual(readFileSync(path), expected);
    stage = 'restart';
    await app.close();
    app = build();
    address = await app.listen({ host: '127.0.0.1', port: 0 });
    assert.equal((await post(address)).status, 200);
    assert.equal(statSync(path).ino, original.ino);
    assert.deepEqual(readFileSync(path), expected);
  } else {
    assert.equal(injected, true);
    assert.equal(result.status, 403);
    assert.equal(rejection.cause, undefined);
    assert.equal(rejection.startupAllowed, false);
    assert.equal(
      rejection.reason,
      input.mode === 'expiry' ? 'RECIPIENT_EXPIRED' : 'RECIPIENT_REJECTED',
    );
    if (input.mode !== 'expiry') assert.equal(rejection.failureCode, 'UNCLASSIFIED');
    assert.equal(delivery.describe().providerState, 'REVOKED');
  }
  stage = 'cleanup';
  if (input.mode === 'cleanup-unknown') {
    assert.equal(rejection.cleanupState, 'UNKNOWN');
    assert.equal(rejection.cleanupFailure, 'MOUNT_CLEANUP_FAILED');
    assert.equal(readFileSync(join(root, 'foreign'), 'utf8'), 'keep-original-foreign-file');
    await assert.rejects(
      delivery.dispose(),
      (error) => error.reason === 'RECIPIENT_REJECTED' && error.cleanupState === 'UNKNOWN',
    );
    assert.equal(delivery.describe().failure, 'RECIPIENT_REJECTED');
  } else {
    assert.equal((await delivery.dispose()).cleanupState, 'ERASED');
    assert.equal(statSync(path).size, 0);
    assert.equal(statSync(path).mode & 0o777, 0);
  }
  await assert.rejects(delivery.publish(null, { reference: input.reference, version: 'v1' }));
  expected.fill(0);
  process.stdout.write(`FACT_SECRET_DELIVERY_INTEGRATION|PASS|${input.mode}\n`);
} catch {
  process.stderr.write(`FACT_SECRET_DELIVERY_INTEGRATION|FAIL|${stage}\n`);
  process.exitCode = 1;
} finally {
  await app?.close();
  await delivery?.dispose().catch(() => {});
  await Promise.all([runtime?.end(), admin?.end()]);
  if (root) rmSync(root, { recursive: true, force: true });
}
