import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import { responseIds } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import {
  readTerminalRenewalFailure,
  refreshFirstPolicyAuthority,
  submitFirstPolicyTargetRenewal,
} from './first-policy-target-renewal.mjs';
import {
  readInitialActivationDisposition,
  readOriginalWithdrawal,
} from './target-disposition-readback.mjs';
import { waitForDispositionExpiry } from './target-disposition-recovery.mjs';

const execute = promisify(execFile);

// A real process fault, established before public admission. No test writes
// leases, execution outcomes, expiry timestamps or signed business state.
export async function expireIndependentRenewal({ secretRoot, evidenceRoot, compose }) {
  await execute('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
  const run = (args) => execute(compose[0], [...compose.slice(1), ...args], { timeout: 20000 });
  const read = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
  const input = await read('policy-set-input.json');
  const { targetId } = await read('discovery-credential-input.json');
  const checkpoint = await read('first-policy-release-checkpoint.json');
  const previous = checkpoint.targetRenewal;
  assert.ok(previous?.target, 'A completed independent renewal must precede this case');
  assert.equal(checkpoint.renewalExpiryFailure, undefined, 'Consumed failure case: reconcile only');
  const originalOptions = {
    secretRoot,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    targetId,
    renewalOperationId: previous.operation.operationId,
  };
  const original = await readInitialActivationDisposition(originalOptions);
  await waitForDispositionExpiry(original);
  const { maker } = await read('deployment-intent-actors.json');
  const publicRead = async (path) => {
    const ids = responseIds();
    const response = await fetch(`http://127.0.0.1:8080${path}`, {
      headers: {
        'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
        'X-Request-ID': ids.requestId,
        'X-Correlation-ID': ids.correlationId,
      },
      signal: AbortSignal.timeout(10000),
    });
    assert.equal(response.status, 200, `public read ${path}`);
    return response.json();
  };
  const persist = () =>
    writeFile(
      join(evidenceRoot, 'first-policy-release-checkpoint.json'),
      JSON.stringify(checkpoint),
      { mode: 0o600 },
    );
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: (
      await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
    ).trim(),
    max: 1,
  });
  const client = await pool.connect();
  const scopedRead = async (read) => {
    await client.query('begin read only');
    try {
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',false)",
        [input.participantId, input.privacyDomainId],
      );
      return await read();
    } finally {
      await client.query('rollback');
    }
  };
  let paused = false;
  let renewal;
  const workerQuiescent = async () => {
    const result = await client.query(`select not exists(
      select 1 from pg_stat_activity a where a.usename=current_user and a.pid<>pg_backend_pid()
        and (a.xact_start is not null or a.backend_xid is not null or a.backend_xmin is not null
          or a.state is distinct from 'idle' or exists(select 1 from pg_locks l
            where l.pid=a.pid and l.locktype='advisory'))) quiescent`);
    return result.rows[0].quiescent;
  };
  try {
    renewal = await submitFirstPolicyTargetRenewal({
      input,
      targetId,
      checkpoint,
      publicRead,
      persist,
      secretRoot,
      evidenceRoot,
      priorAuthorityExpiresAtNs: original.expiresAtNs,
      connect: () =>
        run([
          '--profile',
          'astra05',
          'up',
          '-d',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          'runtime-envoy',
        ]),
      beforeSubmit: async () => {
        await scopedRead(async () => {
          const active = await client.query(
            "select configuration_work_id from control.configuration_work where runtime_target_id=$1 and state not in ('COMPLETED','FAILED')",
            [targetId],
          );
          assert.equal(active.rowCount, 0, 'Do not pause unrelated or uncertain target work');
        });
        await expect.poll(workerQuiescent, { timeout: 5000, intervals: [50, 100] }).toBe(true);
        await run(['pause', 'control-worker']);
        paused = true;
        // Read after freezing: a sampled idle boundary before pause alone could
        // race a new transaction. A frozen lifecycle lock is not an expiry test.
        assert.equal(
          await workerQuiescent(),
          true,
          'Paused worker must hold no transaction or advisory lock',
        );
      },
      refresh: () =>
        refreshFirstPolicyAuthority({
          secretRoot,
          evidenceRoot,
          targetId,
          privacyDomainId: input.privacyDomainId,
        }),
    });
    assert.notEqual(renewal.operation.operationId, previous.operation.operationId);
    const queued = () =>
      scopedRead(async () => {
        const result = await client.query(
          `select state,attempt_count::text attempts,lease_owner,lease_until,
        execution_attempt_id,execution_started_at from control.configuration_work
        where operation_id=$1 and runtime_target_id=$2`,
          [renewal.operation.operationId, targetId],
        );
        assert.equal(result.rowCount, 1);
        assert.deepEqual(result.rows[0], {
          state: 'PENDING',
          attempts: '0',
          lease_owner: null,
          lease_until: null,
          execution_attempt_id: null,
          execution_started_at: null,
        });
      });
    await queued();
    const authority = await read('first-policy-workload-identity.json');
    await waitForDispositionExpiry({ expiresAtNs: authority.runtime.expiresAtNs });
    await queued();
    await readInitialActivationDisposition({
      ...originalOptions,
      prior: original,
      expectedTargetState: 'STAGING',
    });
    // The restrictive withdrawal precedes capsule preparation; its real target
    // must acknowledge it even though the new execution authority has expired.
    await run([
      '--profile',
      'astra05',
      'up',
      '-d',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'runtime-target',
    ]);
    await run(['unpause', 'control-worker']);
    paused = false;
    await expect
      .poll(
        async () => (await publicRead(`/api/v1/operations/${renewal.operation.operationId}`)).state,
        { timeout: 90000, intervals: [250, 500, 1000] },
      )
      .toBe('FAILED');
    const operation = await publicRead(`/api/v1/operations/${renewal.operation.operationId}`);
    assert.equal(operation.truthState, 'FAILED');
    const failure = await scopedRead(() => readTerminalRenewalFailure(client, targetId, renewal));
    assert.equal(failure.state, 'FAILED');
    assert.equal(failure.errorCode, 'PC-RUNTIME-3001');
    assert.equal(failure.executionAttemptId, null);
    assert.equal(failure.executionStartedAt, null);
    assert.equal(failure.admissionCount, 1);
    assert.equal(failure.observationCount, 0);
    assert.match(failure.resultReceiptDigest, /^sha256:[0-9a-f]{64}$/u);
    const withdrawal = await readOriginalWithdrawal({
      ...originalOptions,
      operationId: renewal.operation.operationId,
      requireAcknowledgement: true,
    });
    assert.deepEqual(withdrawal.immutable.predecessorChain, original.chain);
    checkpoint.renewalExpiryFailure = failure;
    await persist();
    process.stdout.write(
      'OPENPC_RENEWAL_EXPIRY_FAILURE|PASS|paused-before-admission|actual-expiry|public-terminal-result|one-restrictive-withdrawal|no-activation-or-observation|original-chain-preserved\n',
    );
    return failure;
  } finally {
    // Never release queued work merely because a test assertion failed.
    // SIGKILL terminates this isolated paused process without running its loop.
    if (paused) await run(['kill', '--signal', 'SIGKILL', 'control-worker']);
    client.release();
    await pool.end();
  }
}

export async function verifyExpiredRenewalRecovery(options, failure) {
  const { secretRoot, evidenceRoot } = options;
  const input = JSON.parse(await readFile(join(evidenceRoot, 'policy-set-input.json'), 'utf8'));
  const connection = new URL('postgresql://127.0.0.1:55432/openpc_control');
  connection.username = 'openpc_configuration_runtime';
  connection.password = (
    await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
  ).trim();
  // The acknowledged predecessor withdrawal remains restrictive. Check that a
  // separate unstarted successor can be staged without replaying original effects.
  const checked = await execute(
    'pnpm',
    [
      'exec',
      'vitest',
      'run',
      '--maxWorkers=1',
      '--config',
      'tests/integration/identity/vitest.config.ts',
      'tests/integration/identity/postgres-runtime-generation-retry.test.ts',
      '--testNamePattern',
      'bounds a separate retry after acknowledged predecessor withdrawal|checks terminal failure receipt',
    ],
    {
      timeout: 90000,
      env: {
        ...process.env,
        OPENPC_I02_RUNTIME_DATABASE_URL: connection.toString(),
        OPENPC_RUNTIME_GENERATION_RETRY_ADMITTED_WITHDRAWAL: '1',
        OPENPC_RUNTIME_GENERATION_RETRY_SOURCE: JSON.stringify({
          participantId: input.participantId,
          privacyDomainId: input.privacyDomainId,
          generationId: failure.generationId,
        }),
      },
    },
  );
  process.stdout.write(checked.stdout);
  const readOptions = {
    secretRoot,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    targetId: JSON.parse(
      await readFile(join(evidenceRoot, 'discovery-credential-input.json'), 'utf8'),
    ).targetId,
    operationId: failure.operationId,
    requireAcknowledgement: true,
  };
  const original = await readOriginalWithdrawal(readOptions);
  assert.equal(original.work.state, 'FAILED');
  assert.equal(original.work.result_receipt_digest, failure.resultReceiptDigest);
  const run = (args) =>
    execute(options.compose[0], [...options.compose.slice(1), ...args], { timeout: 45000 });
  const container = (await run(['ps', '-q', 'runtime-target'])).stdout.trim();
  assert.match(container, /^[0-9a-f]{12,64}$/u);
  const journal = async () =>
    (
      await execute(
        'docker',
        ['exec', container, 'cat', `/runtime/agent/${readOptions.targetId}/activation.json`],
        { encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 },
      )
    ).stdout;
  const before = await journal();
  const installed = JSON.parse(before.toString()).canonical.target_disposition.installed;
  assert.deepEqual(Buffer.from(installed.signed_delivery), original.immutable.delivery);
  assert.deepEqual(Buffer.from(installed.signed_acknowledgement), original.acknowledgement);
  await run(['restart', 'control-worker', 'runtime-target']);
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
  const restarted = await readOriginalWithdrawal({ ...readOptions, prior: original });
  assert.deepEqual(restarted.work, original.work);
  await assert.rejects(
    execute('docker', [
      'exec',
      container,
      '/usr/local/bin/openpc-control-worker',
      'runtime-target-ready',
    ]),
    (error) => error.code === 1 && error.stderr.includes('control_worker_stopped'),
  );
  assert.deepEqual(await journal(), before);
  process.stdout.write(
    'OPENPC_RENEWAL_EXPIRY_RECOVERY|PASS|acknowledged-withdrawal-preserved|separate-retry-bounded|same-signed-chain|restart-original-journal|not-serving|no-reactivation\n',
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [secretRoot, evidenceRoot] = process.argv.slice(2);
  const options = {
    secretRoot,
    evidenceRoot,
    compose: JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON),
  };
  const failure = await expireIndependentRenewal(options);
  await verifyExpiredRenewalRecovery(options, failure);
}
