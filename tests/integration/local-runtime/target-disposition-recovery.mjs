import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { readInitialActivationDisposition } from './target-disposition-readback.mjs';

const execute = promisify(execFile);
export function dispositionExpiryDelay(expiresAtNs, nowMs = Date.now()) {
  assert.match(expiresAtNs, /^[1-9][0-9]{0,19}$/u);
  assert.ok(BigInt(expiresAtNs) <= (1n << 64n) - 1n);
  assert.ok(Number.isSafeInteger(nowMs) && nowMs > 0);
  const milliseconds = (BigInt(expiresAtNs) + 999999n) / 1000000n - BigInt(nowMs);
  assert.ok(milliseconds <= 120000n, 'Prepare the bounded original expiry case before dispatch');
  return Number(milliseconds > 0n ? milliseconds : 0n);
}
export async function waitForDispositionExpiry(original) {
  const milliseconds = dispositionExpiryDelay(original.expiresAtNs);
  if (milliseconds > 0) await delay(milliseconds + 1);
}

/** Historical recovery preserves custody and proves denial after original
 * expiry. It cannot replace the separate live-ready restart acceptance. */
export async function recoverExpiredTargetDisposition(options, compose, browserReadback) {
  await execute('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
  assert.match(
    options.targetId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  const prior = await readInitialActivationDisposition(options);
  assert.equal(
    dispositionExpiryDelay(prior.expiresAtNs),
    0,
    'Original capsule must actually be expired',
  );
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: (
      await readFile(join(options.secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
    ).trim(),
    max: 1,
  });
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)",
      [options.participantId, options.privacyDomainId],
    );
    const result = await client.query(
      `select binding,activation_proof from control.runtime_target_disposition_admission
      where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3 order by revision desc limit 1`,
      [options.participantId, options.privacyDomainId, options.targetId],
    );
    assert.equal(result.rowCount, 1);
    const row = result.rows[0];
    assert.equal(row.binding.source.original_operation_id, prior.operation);
    assert.equal(row.activation_proof.capsuleValidUntilNs, prior.expiresAtNs);
    await assert.rejects(
      client.query("select openpc.lock_runtime_target_current_sources($1,$2,$3,'CONFIRM')", [
        options.targetId,
        row.binding.source,
        row.activation_proof,
      ]),
      { code: 'P0001', message: 'TARGET-DISPOSITION-SOURCE-CONTEXT' },
    );
  } finally {
    await client.query('rollback');
    client.release();
    await pool.end();
  }
  const run = (args, timeout = 45000) =>
    execute(compose[0], [...compose.slice(1), ...args], { timeout });
  await run([
    '--profile',
    'astra05',
    'up',
    '-d',
    '--no-recreate',
    '--no-deps',
    '--no-build',
    '--pull',
    'never',
    'runtime-target',
  ]);
  const container = (await run(['ps', '-q', 'runtime-target'])).stdout.trim();
  assert.match(container, /^[0-9a-f]{12,64}$/u);
  const journal = async () =>
    (
      await execute(
        'docker',
        ['exec', container, 'cat', `/runtime/agent/${options.targetId}/activation.json`],
        { maxBuffer: 16 * 1024 * 1024, encoding: 'buffer' },
      )
    ).stdout;
  const before = await journal();
  const installed = JSON.parse(before.toString()).canonical.target_disposition.installed;
  assert.deepEqual(Buffer.from(installed.signed_delivery), prior.delivery);
  assert.deepEqual(Buffer.from(installed.signed_acknowledgement), prior.acknowledgement);
  await run(['restart', 'control-worker', 'runtime-target'], 40000);
  await run([
    '--profile',
    'astra05',
    'up',
    '-d',
    '--wait',
    '--no-recreate',
    '--no-deps',
    '--no-build',
    '--pull',
    'never',
    'control-worker',
  ]);
  const started = (
    await execute('docker', ['inspect', container, '--format', '{{.State.StartedAt}}'])
  ).stdout.trim();
  let fenced = false;
  for (let attempt = 0; attempt < 40; attempt++) {
    const logs = await execute('docker', ['logs', '--since', started, container]);
    if ((logs.stdout + logs.stderr).includes('"boundary":"disposition_unavailable"')) {
      fenced = true;
      break;
    }
    await delay(250);
  }
  assert.equal(fenced, true, 'Restarted native target must enforce original expiry');
  await assert.rejects(
    execute('docker', [
      'exec',
      container,
      '/usr/local/bin/openpc-control-worker',
      'runtime-target-ready',
    ]),
    (error) => error.code === 1 && error.stderr.includes('control_worker_stopped'),
  );
  assert.deepEqual(await journal(), before, 'Recovery must preserve every original journal byte');
  await readInitialActivationDisposition({ ...options, prior });
  await browserReadback();
  await readInitialActivationDisposition({ ...options, prior });
  assert.deepEqual(await journal(), before);
  process.stdout.write(
    'OPENPC_TARGET_EXPIRED_RECOVERY|PASS|actual-source-expiry-denial|native-fenced|not-serving|exact-journal-preserved|browser\n',
  );
}
