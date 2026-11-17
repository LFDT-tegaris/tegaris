import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { request } from 'node:https';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client, Pool } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import {
  createTestFactSecretConsumer,
  testFactSecretConsumerPath,
} from '../../../scripts/operations/test-fact-secret-consumer.mjs';

// Component acceptance of the real installed recipient, TLS, tmpfs and database
// login/session owner. The separate packaged Fact journey must additionally prove
// that its entrypoint consumes the exact mounted DSN and stops on invalidation.
let stage = 'input',
  failed = false,
  app,
  runtime,
  admin,
  candidate,
  reader,
  root;
try {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    assert.ok(size < 65536);
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString());
  for (const chunk of chunks) chunk.fill(0);
  assert.equal(process.geteuid(), 65532);
  assert.equal(process.getegid(), 65532);
  assert.ok(['consumer-revocation', 'consumer-expiry'].includes(input.mode));
  root = mkdtempSync('/dev/shm/openpc-secret-consumer-');
  const path = join(root, 'candidate-url');
  runtime = new Pool({ connectionString: input.runtimeUrl, max: 3 });
  admin = new Pool({ connectionString: input.adminUrl, max: 1 });
  const candidateAdmin = new URL(input.adminUrl);
  candidateAdmin.pathname = '/openpc_candidate_index';
  candidate = new Pool({ connectionString: candidateAdmin.href, max: 2 });
  const expected = Buffer.from(input.material, 'base64');
  const installed = {
    ...input.pins,
    issuerSpkiDer: Buffer.from(input.pins.issuerSpkiDer, 'base64'),
  };
  const tls = Object.fromEntries(
    Object.entries(input.tls.server).map(([name, value]) => [name, Buffer.from(value, 'base64')]),
  );
  stage = 'reserve';
  app = await createTestFactSecretConsumer({
    pool: runtime,
    kernel: new IdentityKernel(new PostgresIdentityRepository(runtime)),
    candidateAdminPool: candidate,
    installed,
    tls,
    rootPath: root,
    reference: input.reference,
    version: 'v1',
    syntheticMaterial: expected,
  });
  const login = async () =>
    (
      await candidate.query(
        "select rolcanlogin from pg_roles where rolname='openpc_fact_bridge_reader'",
      )
    ).rows[0].rolcanlogin;
  assert.equal(await login(), false);
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const expectedPins = Object.fromEntries(
    [
      'signedBindingDigest',
      'installationDigest',
      'generation',
      'participantId',
      'privacyDomainId',
      'workloadCredentialId',
      'workloadCredentialEpoch',
    ].map((name) => [name, installed[name]]),
  );
  const call = (operation, expected = expectedPins) =>
    new Promise((resolve, reject) => {
      const req = request(
        `${address}${testFactSecretConsumerPath}`,
        {
          method: 'POST',
          ca: tls.ca,
          cert: Buffer.from(input.tls.certificate, 'base64'),
          key: Buffer.from(input.tls.privateKey, 'base64'),
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          headers: { 'content-type': 'application/json' },
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on('data', (chunk) => {
            size += chunk.length;
            if (size > 4096) res.destroy();
            else chunks.push(chunk);
          });
          res.on('error', reject);
          res.on('end', () => {
            try {
              resolve({
                status: res.statusCode,
                body: JSON.parse(Buffer.concat(chunks).toString()),
              });
            } catch {
              reject(new Error('response rejected'));
            }
          });
        },
      );
      req.on('error', reject);
      req.setTimeout(5000, () => req.destroy(new Error('bounded consumer request timeout')));
      req.end(JSON.stringify({ operation, reference: input.reference, version: 'v1', expected }));
    });
  stage = 'pre-publication-pins';
  const contradictions = [
    ['signedBindingDigest', `sha256:${'ef'.repeat(32)}`],
    ['installationDigest', `sha256:${'ed'.repeat(32)}`],
    ['generation', String(BigInt(installed.generation) + 1n)],
    ['participantId', '018f0000-0000-7000-8000-000000099101'],
    ['privacyDomainId', '018f0000-0000-7000-8000-000000099201'],
    ['workloadCredentialId', '018f0000-0000-7000-8000-000000099198'],
    ['workloadCredentialEpoch', String(BigInt(installed.workloadCredentialEpoch) + 1n)],
  ];
  for (const [name, value] of contradictions) {
    const denied = await call('PUBLISH', { ...expectedPins, [name]: value });
    assert.deepEqual(denied, { status: 403, body: { code: 'OPS_SECRET_UNRESOLVED' } });
    assert.equal(await login(), false);
    assert.equal(existsSync(path), false);
  }
  assert.deepEqual(await call('PUBLISH', null), {
    status: 400,
    body: { code: 'OPS_SECRET_UNRESOLVED' },
  });
  assert.equal(await login(), false);
  assert.equal(existsSync(path), false);
  stage = 'publication';
  const first = await call('PUBLISH');
  assert.equal(first.status, 200);
  assert.equal(first.body.signedBindingDigest, installed.signedBindingDigest);
  assert.equal(first.body.validUntilMs, input.validUntilMs);
  assert.equal(Object.hasOwn(first.body, 'startupAllowed'), false);
  assert.equal(await login(), true);
  assert.deepEqual(readFileSync(path), expected);
  const inode = statSync(path).ino;
  assert.deepEqual(await call('CHECK'), first);
  assert.deepEqual(await call('PUBLISH'), first);
  assert.equal(statSync(path).ino, inode);
  for (const [name, value] of contradictions) {
    assert.deepEqual(await call('CHECK', { ...expectedPins, [name]: value }), {
      status: 403,
      body: { code: 'OPS_SECRET_UNRESOLVED' },
    });
    assert.equal(await login(), true);
    assert.equal(statSync(path).ino, inode);
    assert.deepEqual(readFileSync(path), expected);
  }
  assert.deepEqual(await call('CHECK'), first);
  // Host test routing differs from the consumer network alias. This proves the
  // same installed role/password and actual session revocation, not DSN routing.
  reader = new Client({ connectionString: input.candidateUrl });
  reader.on('error', () => {});
  await reader.connect();
  assert.equal(
    (await reader.query('select current_user')).rows[0].current_user,
    'openpc_fact_bridge_reader',
  );
  const inFlight = reader.query('select pg_sleep(20)').then(
    () => ({ code: 'UNEXPECTED_PASS' }),
    (error) => ({ code: error.code }),
  );
  stage = 'revocation';
  if (input.mode === 'consumer-revocation')
    await admin.query(
      "update control.installed_secret_recipient set state='REVOKED' where participant_id=$1",
      [installed.participantId],
    );
  const until = performance.now() + 12000;
  while (await login()) {
    assert.ok(performance.now() < until);
    await delay(25);
  }
  assert.equal((await inFlight).code, '57P01');
  assert.equal(statSync(path).size, 0);
  assert.equal(statSync(path).mode & 0o777, 0);
  assert.equal((await call('PUBLISH')).status, 403);
  assert.equal((await call('CHECK')).status, 403);
  const replacement = new Client({ connectionString: input.candidateUrl });
  await assert.rejects(replacement.connect());
  await replacement.end();
  assert.equal(
    (
      await candidate.query(
        "select count(*)::int n from pg_stat_activity where datname='openpc_candidate_index' and usename='openpc_fact_bridge_reader'",
      )
    ).rows[0].n,
    0,
  );
  expected.fill(0);
  stage = 'cleanup';
  await app.close();
  app = undefined;
  process.stdout.write(`FACT_SECRET_DELIVERY_INTEGRATION|PASS|${input.mode}\n`);
} catch {
  failed = true;
  process.stderr.write(`FACT_SECRET_DELIVERY_INTEGRATION|FAIL|${stage}\n`);
} finally {
  const cleanup = await Promise.allSettled([app?.close(), reader?.end()]);
  const stores = await Promise.allSettled([runtime?.end(), admin?.end(), candidate?.end()]);
  if ([...cleanup, ...stores].some((result) => result.status === 'rejected')) failed = true;
  if (root) {
    try {
      rmSync(root, { recursive: true });
    } catch {
      failed = true;
    }
  }
  if (failed) process.exitCode = 1;
}
