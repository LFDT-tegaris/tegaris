import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import { responseIds } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import { startWithdrawalCommitFault } from './withdrawal-commit-fault.mjs';
import {
  refreshFirstPolicyAuthority,
  submitFirstPolicyTargetRenewal,
} from './first-policy-target-renewal.mjs';
import {
  readInitialActivationDisposition,
  readOriginalWithdrawal,
  assertUnknownWithdrawalJournal,
  withdrawalObservationBounds,
  withWithdrawalObservationClient,
} from './target-disposition-readback.mjs';
import { dispositionExpiryDelay } from './target-disposition-recovery.mjs';

const execute = promisify(execFile);

export async function retainUnknownWithdrawalBaseline({
  before,
  original,
  targetId,
  checkpoint,
  persist,
}) {
  assert.ok(
    Buffer.isBuffer(before) && before.length > 0 && before.length <= 16 * 1024 * 1024,
    'Native pre-fault journal must fit the bounded checkpoint',
  );
  const journal = JSON.parse(before.toString());
  assert.equal(journal.target_id, targetId);
  assert.ok(
    Buffer.from(journal.canonical.target_disposition.installed.signed_delivery).equals(
      original.delivery,
    ),
    'Original installed delivery required',
  );
  assert.ok(
    Buffer.from(journal.canonical.target_disposition.installed.signed_acknowledgement).equals(
      original.acknowledgement,
    ),
    'Original installed acknowledgement required',
  );
  assert.equal(
    checkpoint.unknownWithdrawalBaseline,
    undefined,
    'Retained pre-fault baseline cannot be overwritten',
  );
  checkpoint.unknownWithdrawalBaseline = {
    targetId,
    predecessorOperationId: original.operation,
    predecessorWorkId: original.work,
    admissionDigests: original.chain.map((link) => link.admission),
    journalBase64: before.toString('base64'),
  };
  await persist();
}

export async function unknownWithdrawalCommit({ secretRoot, evidenceRoot, compose, gateway }) {
  await execute('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.ok(compose[0] === 'docker' && compose[1] === 'compose');
  const run = (args, command = compose) =>
    execute(command[0], [...command.slice(1), ...args], { timeout: 45000 });
  const read = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
  const input = await read('policy-set-input.json');
  const { targetId } = await read('discovery-credential-input.json');
  const checkpoint = await read('first-policy-release-checkpoint.json');
  assert.ok(
    checkpoint.targetRenewal?.target,
    'Independent completed predecessor required; consumed unknown case is recovery-only',
  );
  assert.equal(checkpoint.unknownWithdrawal, undefined);
  const previous = checkpoint.targetRenewal;
  const original = await readInitialActivationDisposition({
    secretRoot,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    targetId,
    renewalOperationId: previous.operation.operationId,
  });
  assert.equal(
    dispositionExpiryDelay(original.expiresAtNs),
    0,
    'Actual expired predecessor required',
  );
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
    assert.equal(response.status, 200, `Public read ${path}`);
    return response.json();
  };
  const persist = () =>
    writeFile(
      join(evidenceRoot, 'first-policy-release-checkpoint.json'),
      JSON.stringify(checkpoint),
      { mode: 0o600 },
    );
  const credentials = {
    ...withdrawalObservationBounds,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: (
      await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
    ).trim(),
    max: 1,
  };
  const direct = new Pool({ ...credentials, host: '127.0.0.1', port: 55432 });
  const inspect = async (id) => JSON.parse((await execute('docker', ['inspect', id])).stdout)[0];
  let proxy;
  let proxiedCompose;
  let observedAdmission;
  let observedOperationId;
  const context = async (client) =>
    client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',false)",
      [input.participantId, input.privacyDomainId],
    );
  try {
    const client = await direct.connect();
    try {
      await client.query('begin read only');
      await context(client);
      const pending = await client.query(
        "select configuration_work_id from control.configuration_work where state not in ('COMPLETED','FAILED')",
      );
      assert.equal(
        pending.rowCount,
        0,
        'Do not reconfigure a worker with pending or uncertain work',
      );
      await client.query('rollback');
    } finally {
      client.release();
    }
    const workerId = (await run(['ps', '-q', 'control-worker'])).stdout.trim();
    assert.match(workerId, /^[0-9a-f]{12,64}$/u);
    const workerBefore = await inspect(workerId);
    assert.equal(workerBefore.Config.Labels['com.docker.compose.service'], 'control-worker');
    assert.equal(
      workerBefore.Config.Labels['com.docker.compose.project'],
      compose[compose.indexOf('-p') + 1],
    );
    assert.ok(
      Object.values(workerBefore.NetworkSettings.Networks).some(
        (network) => network.Gateway === gateway,
      ),
      'Listener must use the owned worker bridge',
    );
    await run(['stop', 'control-worker']);
    proxy = await startWithdrawalCommitFault({
      host: gateway,
      targetId,
      observeCommitted: async (fault, signal) => {
        await withWithdrawalObservationClient(direct, signal, async (reader) => {
          await reader.query('begin read only');
          await context(reader);
          const work = await reader.query(
            'select operation_id::text id from control.configuration_work where configuration_work_id=$1 and runtime_target_id=$2',
            [fault.workId, targetId],
          );
          assert.equal(work.rowCount, 1);
          observedOperationId = work.rows[0].id;
        });
        observedAdmission = await readOriginalWithdrawal({
          secretRoot,
          participantId: input.participantId,
          privacyDomainId: input.privacyDomainId,
          targetId,
          operationId: observedOperationId,
          requireUnsigned: true,
          signal,
        });
        assert.equal(observedAdmission.work.id, fault.workId);
        assert.deepEqual(observedAdmission.immutable.predecessorChain, original.chain);
      },
    });
    const override = join(evidenceRoot, 'withdrawal-commit-fault-compose.json');
    await writeFile(
      override,
      JSON.stringify({
        services: {
          'control-worker': {
            environment: {
              CONTROL_WORKER_DATABASE_HOST: gateway,
              CONTROL_WORKER_DATABASE_PORT: String(proxy.port),
            },
          },
        },
      }),
      { mode: 0o600 },
    );
    proxiedCompose = [...compose, '-f', override];
    // Real PostgreSQL authentication and both transaction outcomes through the
    // unarmed transport precede fresh authority. No business rows are seeded.
    const probe = new Pool({ ...credentials, host: gateway, port: proxy.port });
    try {
      const pg = await probe.connect();
      // Queries still reject on connection failure; retain control of cleanup
      // and the original failure instead of Node's unhandled error termination.
      pg.on('error', () => {});
      try {
        assert.equal((await pg.query('show ssl')).rows[0].ssl, 'off');
        await pg.query('begin read only');
        await context(pg);
        assert.equal(
          (await pg.query('select current_user identity')).rows[0].identity,
          credentials.user,
        );
        await pg.query('commit');
        await pg.query('begin read only');
        await context(pg);
        await assert.rejects(
          pg.query(
            'select binding,admission_digest from openpc.begin_runtime_target_withdrawal($1::text::uuid,$2::text::uuid,$3,$4,$5)',
            [targetId, original.work, '', null, -1],
          ),
          { code: 'P0001', message: 'PC-AUTH-0005' },
        );
        await pg.query('rollback');
        assert.equal(proxy.status(), null);
      } finally {
        pg.release();
      }
    } finally {
      await probe.end();
    }
    process.stdout.write(
      'OPENPC_WITHDRAWAL_COMMIT_PREFLIGHT|PASS|real-authentication|unchanged-SSL|ordinary-commit-rollback|unarmed\n',
    );
    // Real SQLx/configuration, read-only and without the business loop.
    await run(
      [
        'run',
        '--rm',
        '--no-deps',
        '-e',
        'PGOPTIONS=-c default_transaction_read_only=on',
        'control-worker',
        'healthcheck',
      ],
      proxiedCompose,
    );
    assert.equal(proxy.status(), null);
    await run(
      ['up', '-d', '--wait', '--no-deps', '--no-build', '--pull', 'never', 'control-worker'],
      proxiedCompose,
    );
    const workerAfter = await inspect(
      (await run(['ps', '-q', 'control-worker'], proxiedCompose)).stdout.trim(),
    );
    assert.equal(workerAfter.Image, workerBefore.Image);
    assert.equal(workerAfter.HostConfig.Memory, workerBefore.HostConfig.Memory);
    assert.ok(workerAfter.Config.Env.includes(`CONTROL_WORKER_DATABASE_HOST=${gateway}`));
    assert.ok(workerAfter.Config.Env.includes(`CONTROL_WORKER_DATABASE_PORT=${proxy.port}`));
    const currentWorker = async () => {
      proxy.status();
      const actual = await inspect(workerAfter.Id);
      assert.equal(actual.State.Running, true, 'Native worker exited before public admission');
      assert.equal(actual.State.StartedAt, workerAfter.State.StartedAt);
      assert.equal(actual.State.Health.Status, 'healthy');
      return actual;
    };
    const successfulHealthchecks = (actual) =>
      actual.State.Health.Log.filter(
        (check) =>
          check.ExitCode === 0 && new Date(check.Start) >= new Date(workerAfter.State.StartedAt),
      ).length;
    await expect
      .poll(
        async () => {
          await currentWorker();
          const logs = await execute('docker', [
            'logs',
            '--since',
            workerAfter.State.StartedAt,
            workerAfter.Id,
          ]);
          return (logs.stdout + logs.stderr).includes('"event":"control_worker_idle_poll"');
        },
        { timeout: 30000, intervals: [100, 250] },
      )
      .toBe(true);
    await expect
      .poll(
        async () => {
          return successfulHealthchecks(await currentWorker());
        },
        { timeout: 15000, intervals: [250, 500] },
      )
      .toBeGreaterThanOrEqual(3);
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
    const container = (await run(['ps', '-q', 'runtime-target'])).stdout.trim();
    assert.match(container, /^[0-9a-f]{12,64}$/u);
    const journal = async () =>
      (
        await execute(
          'docker',
          ['exec', container, 'cat', `/runtime/agent/${targetId}/activation.json`],
          { encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 },
        )
      ).stdout;
    const before = await journal();
    const installed = JSON.parse(before.toString()).canonical.target_disposition.installed;
    assert.deepEqual(Buffer.from(installed.signed_delivery), original.delivery);
    assert.deepEqual(Buffer.from(installed.signed_acknowledgement), original.acknowledgement);
    await retainUnknownWithdrawalBaseline({ before, original, targetId, checkpoint, persist });
    const renewal = await submitFirstPolicyTargetRenewal({
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
        assert.ok(successfulHealthchecks(await currentWorker()) >= 3);
      },
      refresh: async () => {
        await refreshFirstPolicyAuthority({
          secretRoot,
          evidenceRoot,
          targetId,
          privacyDomainId: input.privacyDomainId,
        });
        assert.ok(successfulHealthchecks(await currentWorker()) >= 3);
        proxy.arm();
      },
    });
    assert.notEqual(renewal.operation.operationId, previous.operation.operationId);
    await expect
      .poll(() => proxy.status(), { timeout: 45000, intervals: [50, 100, 250] })
      .not.toBeNull();
    const fault = proxy.status();
    const options = {
      secretRoot,
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      targetId,
      operationId: renewal.operation.operationId,
      requireUnsigned: true,
    };
    assert.equal(observedOperationId, renewal.operation.operationId);
    assert.ok(observedAdmission, 'Independent committed readback must precede native EOF/retry');
    const admission = observedAdmission;
    assert.equal(admission.work.id, fault.workId);
    assert.deepEqual(admission.immutable.predecessorChain, original.chain);
    checkpoint.unknownWithdrawal = {
      operationId: renewal.operation.operationId,
      workId: fault.workId,
      admissionDigest: admission.immutable.admission,
      fault: 'BACKEND_COMMIT_RESPONSE_LOST',
    };
    await persist();
    process.stdout.write(
      `OPENPC_WITHDRAWAL_UNKNOWN|COMMITTED|operation=${renewal.operation.operationId}|work=${fault.workId}|admission=${admission.immutable.admission}|unsigned|no-activation\n`,
    );
    await expect
      .poll(
        async () =>
          Number((await readOriginalWithdrawal({ ...options, prior: admission })).work.attempts),
        { timeout: 45000, intervals: [250, 500] },
      )
      .toBeGreaterThanOrEqual(2);
    await run(['restart', 'control-worker', 'runtime-target'], proxiedCompose);
    await run(
      [
        'up',
        '-d',
        '--wait',
        '--no-recreate',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'control-worker',
      ],
      proxiedCompose,
    );
    await expect
      .poll(
        async () => (await publicRead(`/api/v1/operations/${renewal.operation.operationId}`)).state,
        { timeout: 90000, intervals: [250, 500, 1000] },
      )
      .toBe('FAILED');
    const operation = await publicRead(`/api/v1/operations/${renewal.operation.operationId}`);
    assert.equal(operation.truthState, 'FAILED');
    const reconciled = await readOriginalWithdrawal({ ...options, prior: admission });
    assert.equal(reconciled.work.state, 'FAILED');
    assert.equal(reconciled.work.attempts, '3');
    assert.equal(
      (await publicRead(`/api/v1/runtime-targets/urn:openpc:resource:${targetId}`)).state,
      'FAILED',
    );
    assertUnknownWithdrawalJournal(before, await journal(), admission);
    await assert.rejects(
      execute('docker', [
        'exec',
        container,
        '/usr/local/bin/openpc-control-worker',
        'runtime-target-ready',
      ]),
      (error) => error.code === 1 && error.stderr.includes('control_worker_stopped'),
    );
    assert.equal(proxy.status().count, 1);
    process.stdout.write(
      'OPENPC_WITHDRAWAL_UNKNOWN|PASS|one-real-commit-response-loss|same-unsigned-admission|retry-restart-no-delivery-ACK-activation|original-journal|public-failed-execution|custody-remains-unknown\n',
    );
  } finally {
    // Preserve the unknown original. Stop its consumer before removing transport;
    // a failure never re-arms, resubmits or clears the admitted business state.
    if (proxiedCompose) {
      try {
        await run(['stop', 'control-worker'], proxiedCompose);
      } catch {
        await run(['kill', '--signal', 'SIGKILL', 'control-worker'], proxiedCompose);
      }
      const stoppedId = (await run(['ps', '-aq', 'control-worker'], proxiedCompose)).stdout.trim();
      assert.match(stoppedId, /^[0-9a-f]{12,64}$/u);
      assert.equal((await inspect(stoppedId)).State.Running, false);
    }
    await proxy?.close();
    await direct.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [secretRoot, evidenceRoot] = process.argv.slice(2);
  await unknownWithdrawalCommit({
    secretRoot,
    evidenceRoot,
    compose: JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON),
    gateway: process.env.OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY,
  });
}
