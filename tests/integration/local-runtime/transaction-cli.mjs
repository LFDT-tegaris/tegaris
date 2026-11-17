import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from '@playwright/test';
import { Pool } from 'pg';
import { run } from '../../../apps/admin-cli/src/main.ts';
import { CliError } from '../../../apps/admin-cli/src/client.ts';
import { transactionOperation } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { virtualAuthenticator } from './participant-workbench-browser.mjs';

// Only the external IdP and authenticators are test devices. CLI parsing,
// OIDC/PKCE, context, approval, persistence and execution use production owners.
await promisify(execFile)('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [mode, secretRoot, evidenceRoot, dataRoot, deploymentPolicyId, runtimeTargetId, walletId] =
  process.argv.slice(2);
assert.ok(
  [
    'authenticate',
    'submit',
    'readback',
    'resources',
    'stale',
    'native',
    'cigl',
    'lifecycle',
  ].includes(mode),
);
const actors = JSON.parse(
  await readFile(join(evidenceRoot, 'deployment-intent-actors.json'), 'utf8'),
);
const privateRoot = join(secretRoot, 'transaction-cli', basename(evidenceRoot));
await mkdir(privateRoot, { recursive: true, mode: 0o700 });
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  max: 1,
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const calls = [];
let loseExecution = false,
  lostExecution = false;
let assertions = 0;
const configuration = (name) => ({
  apiUrl: 'http://localhost:8080',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  localDevelopment: true,
  browserProfile: `${name}-profile`,
});
async function invoke(name, args, override) {
  process.stdout.write(`OPENPC_CLI_COMMAND|${name}|${args[0]}|BEGIN\n`);
  const actor = actors[name],
    configPath = join(privateRoot, `${name}.json`);
  await writeFile(configPath, JSON.stringify({ ...configuration(name), ...override }), {
    mode: 0o600,
  });
  let output, watchdog;
  const code = await run(
    ['--config', configPath, ...args],
    (value) => {
      output = value;
      process.stdout.write(`OPENPC_CLI_COMMAND|${name}|${args[0]}|READBACK\n`);
    },
    {
      launch: (profile) =>
        chromium.launchPersistentContext(profile, { headless: true, chromiumSandbox: true }),
      failure: async (page, errorName) => {
        process.stdout.write(`OPENPC_CLI_COMMAND|${name}|${args[0]}|${errorName}\n`);
        calls.push({
          actor: name,
          command: args[0],
          errorName,
          path: new URL(page.url()).pathname,
        });
        await page.screenshot({
          path: join(evidenceRoot, `transaction-cli-${mode}-${name}-failure.png`),
          fullPage: true,
        });
      },
      initialize: async (context, page) => {
        watchdog = setTimeout(() => {
          void (async () => {
            calls.push({ actor: name, command: args[0], watchdog: true });
            process.stdout.write(`OPENPC_CLI_COMMAND|${name}|${args[0]}|WATCHDOG\n`);
            setTimeout(() => process.exit(1), 5000);
            await page
              .screenshot({
                path: join(evidenceRoot, `transaction-cli-${mode}-${name}-watchdog.png`),
                fullPage: true,
              })
              .catch(() => undefined);
            await context.close();
          })();
        }, 60_000);
        const credential = await pool.query(
          "select authenticator_sign_count::text count from control.credential where credential_id=$1 and principal_id=$2 and state='ACTIVE'",
          [actor.credentialId, actor.principalId],
        );
        assert.equal(credential.rowCount, 1);
        const device = await virtualAuthenticator(
          context,
          page,
          actor.credentialId,
          actor.privateKeyPath,
          credential.rows[0].count,
        );
        context.on('close', () => {
          assertions += device.assertions();
        });
        page.on('response', (response) => {
          const url = new URL(response.url());
          if (url.origin === configuration(name).apiUrl && url.pathname.startsWith('/api/v1/ui/')) {
            calls.push({
              actor: name,
              method: response.request().method(),
              path: url.pathname,
              status: response.status(),
            });
            if (response.request().method() !== 'GET')
              process.stdout.write(
                `OPENPC_CLI_OWNER|${name}|${args[0]}|${url.pathname}|${response.status()}\n`,
              );
          }
        });
        await page.route('http://127.0.0.1:53006/authorize?*', async (route) => {
          const url = new URL(route.request().url());
          url.searchParams.set('openpc_test_subject', actor.principalId);
          url.searchParams.set('openpc_test_principal_id', actor.principalId);
          await route.continue({ url: url.href });
        });
        if (loseExecution)
          await page.route('**/api/v1/ui/transaction-workbench', async (route) => {
            if (
              route.request().method() === 'POST' &&
              route.request().postDataJSON()?.command === 'EXECUTE' &&
              !lostExecution
            ) {
              const response = await route.fetch();
              assert.equal(response.status(), 202);
              lostExecution = true;
              await route.abort('failed');
            } else await route.continue();
          });
      },
    },
  ).finally(() => clearTimeout(watchdog));
  assert.ok([0, 6].includes(code), `CLI ${args[0]} returned ${code}`);
  assert.ok(output);
  assert.doesNotMatch(
    JSON.stringify(output),
    /sessionToken|reviewToken|assertionCoseSign1|refreshToken/u,
  );
  return output;
}
async function denial(name, args, code, override) {
  await assert.rejects(
    invoke(name, args, override),
    (error) => error instanceof CliError && error.code === code,
  );
}
async function govern(kind, fields, lose = false) {
  const key = randomUUID(),
    input = join(privateRoot, `${key}.json`);
  await writeFile(
    input,
    JSON.stringify({
      fields,
      checkerId: actors.checker.principalId,
      reason: `Governed CLI ${kind} ${key}`,
    }),
    { mode: 0o600 },
  );
  const command = ['transaction', kind, '--input', input, '--request-key', key];
  const proposed = await invoke('maker', command);
  const approvalId = proposed.approval.approvalRequestId.split(':').at(-1);
  assert.equal(proposed.candidate.state, 'APPROVAL_REQUESTED');
  assert.equal(proposed.candidate.operationRef, null);
  assert.equal(
    (await invoke('maker', command)).approval.approvalRequestId,
    proposed.approval.approvalRequestId,
  );
  await denial('maker', ['approve', approvalId], 'DENIED');
  const before = assertions;
  const approved = await invoke('checker', ['approve', approvalId]);
  assert.equal(approved.candidate.state, 'APPROVED');
  assert.ok(assertions > before, 'checker must use a fresh real bound WebAuthn assertion');
  const beforeExecution = assertions;
  loseExecution = lose;
  const completed = await invoke('maker', ['execute', key]);
  loseExecution = false;
  assert.ok(
    assertions > beforeExecution,
    'maker must use a fresh command-bound WebAuthn assertion',
  );
  assert.equal(completed.candidate.state, 'CONSUMED');
  const assertionsBeforeReplay = assertions;
  const writesBeforeReplay = calls.filter(
    (call) => call.method === 'POST' && call.path === '/api/v1/ui/transaction-workbench',
  ).length;
  const replay = await invoke('maker', ['execute', key]);
  assert.equal(replay.candidate.operationRef, completed.candidate.operationRef);
  assert.equal(assertions, assertionsBeforeReplay);
  assert.equal(
    calls.filter(
      (call) => call.method === 'POST' && call.path === '/api/v1/ui/transaction-workbench',
    ).length,
    writesBeforeReplay,
  );
  return { key, approvalId, proposed, completed };
}
try {
  if (mode === 'authenticate') {
    for (const name of ['maker', 'checker']) {
      const session = await invoke(name, ['login']);
      assert.equal(session.principalId, actors[name].principalId);
      assert.equal(session.contextMode, 'PARTICIPANT');
      assert.deepEqual(await invoke(name, ['session']), session);
    }
    await denial('maker', ['session'], 'CONTEXT', {
      privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    });
  } else if (mode === 'submit') {
    const wallet = JSON.parse(
      await readFile(join(evidenceRoot, 'deployment-wallet-cli.json'), 'utf8'),
    );
    const prepared = await govern('deployment-intent', {
      deploymentPolicyId,
      runtimeTargetId,
      walletBindingId: `urn:openpc:resource:${walletId}`,
      executionWorkloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
      signingPayload: wallet.signingPayload,
    });
    assert.equal(prepared.completed.result.authority, 'NONE');
    assert.equal(prepared.completed.result.signingPayload, wallet.signingPayload);
    const submitted = await govern(
      'deployment-submission',
      {
        deploymentIntentId: prepared.completed.candidate.resourceRef,
        signedTransaction: wallet.signedTransaction,
      },
      true,
    );
    assert.equal(lostExecution, true);
    assert.equal(submitted.proposed.candidate.candidate.signedTransaction, undefined);
    let current = submitted.completed;
    const deadline = Date.now() + 30_000;
    while (current.result?.state !== 'WRITE_AMBIGUITY' && Date.now() < deadline) {
      assert.notEqual(
        current.operation?.state,
        'FAILED',
        'submission must reach its real provider attempt',
      );
      await delay(250);
      current = await invoke('maker', ['result', submitted.approvalId]);
    }
    assert.equal(current.result.state, 'WRITE_AMBIGUITY');
    assert.equal(current.operation.state, 'WRITE_AMBIGUITY');
    assert.equal(current.operation.truthState, 'WRITE_AMBIGUITY');
    await writeFile(
      join(evidenceRoot, 'transaction-cli-result.json'),
      JSON.stringify({
        preparationApprovalId: prepared.approvalId,
        submissionApprovalId: submitted.approvalId,
        requestKey: submitted.key,
        operationRef: submitted.completed.candidate.operationRef,
      }),
      { mode: 0o600 },
    );
  } else if (mode === 'readback') {
    const retained = JSON.parse(
      await readFile(join(evidenceRoot, 'transaction-cli-result.json'), 'utf8'),
    );
    const replay = await invoke('maker', ['execute', retained.requestKey]);
    assert.equal(replay.candidate.operationRef, retained.operationRef);
    const result = await invoke('maker', ['result', retained.submissionApprovalId]);
    assert.equal(result.candidate.operationRef, retained.operationRef);
    assert.ok(result.result.attempt);
    assert.equal(result.result.state, 'WRITE_AMBIGUITY');
    assert.equal(result.operation.truthState, 'WRITE_AMBIGUITY');
    const wallet = JSON.parse(
      await readFile(join(evidenceRoot, 'deployment-wallet-cli.json'), 'utf8'),
    );
    const sends = (
      await readFile(join(dataRoot, 'rpc-provider/deployment-submissions.jsonl'), 'utf8')
    )
      .trim()
      .split('\n')
      .filter(Boolean)
      .map(JSON.parse);
    assert.equal(sends.filter((send) => send.transactionHash === wallet.transactionHash).length, 1);
  } else if (mode === 'resources') {
    const retained = JSON.parse(
      await readFile(join(evidenceRoot, 'transaction-cli-result.json'), 'utf8'),
    );
    const current = await invoke('maker', [
      'result',
      retained.submissionApprovalId,
      '--wait-seconds',
      '1',
    ]);
    const id = current.candidate.resourceRef.split(':').at(-1);
    const read = await invoke('maker', ['read', 'deployment-submission', id]);
    assert.deepEqual(read.result, current.result);
    await denial('checker', ['read', 'deployment-submission', id], 'DENIED');
    const review = await invoke('checker', ['review', retained.submissionApprovalId]);
    assert.equal(review.result, null);
    assert.equal(review.operation, null);
    assert.equal(
      (await invoke('maker', ['read', 'cigl-activation', runtimeTargetId.split(':').at(-1)])).result
        .targetId,
      runtimeTargetId,
    );
    assert.equal(assertions, 0);
    assert.equal(calls.filter((call) => call.method === 'POST').length, 0);
  } else if (mode === 'stale') {
    // The shared SQL subject owner must distinguish real USER identities from
    // another tenant, a workload principal, malformed input and absent IDs.
    for (const [participantId, subject, allowed] of [
      [configuration('maker').participantId, { kind: 'USER', id: actors.maker.principalId }, true],
      [
        '018f0000-0000-7000-8000-000000000102',
        { kind: 'USER', id: actors.maker.principalId },
        false,
      ],
      [
        configuration('maker').participantId,
        { kind: 'USER', id: '018f0000-0000-7000-8000-000000000190' },
        false,
      ],
      [
        configuration('maker').participantId,
        { kind: 'USER', id: '018f0000-0000-7000-8000-000000000999' },
        false,
      ],
      [configuration('maker').participantId, { kind: 'USER', id: 'malformed' }, false],
    ]) {
      const result = await pool.query(
        'select openpc.cigl_subject_current($1::uuid,$2::jsonb) allowed',
        [participantId, JSON.stringify(subject)],
      );
      assert.equal(result.rows[0].allowed, allowed);
    }
    const requests = join(privateRoot, 'maker-profile', 'openpc-requests');
    const saved = [];
    for (const name of await readdir(requests)) {
      if (!/^[0-9a-f-]{36}\.json$/u.test(name)) continue;
      const draft = JSON.parse(await readFile(join(requests, name), 'utf8'));
      if (
        draft.kind === 'cigl-grant-status' &&
        draft.fields.expectedRevision === '9999' &&
        draft.reason.startsWith('Reject stale CLI grant status ') &&
        draft.approvalId
      )
        saved.push(draft);
    }
    assert.ok(saved.length <= 1, 'retained stale-check ownership must be unique');
    let request = saved[0];
    if (!request) {
      const method = JSON.parse(
        await readFile(join(evidenceRoot, 'configuration-contract-method-resource.json'), 'utf8'),
      );
      const granted = await govern('cigl-grant', {
        definition: {
          runtimeBindingId: method.runtimeBindingId,
          selector: method.selector,
          subject: { kind: 'USER', id: actors.maker.principalId },
          surface: 'RAW_SUBMISSION',
          effect: 'ALLOW',
        },
        expectedRuntimeBindingRevision: '1',
        expectedMethodRevision: method.revision,
      });
      const key = randomUUID(),
        input = join(privateRoot, `${key}.json`);
      await writeFile(
        input,
        JSON.stringify({
          fields: {
            targetRef: granted.completed.result.grantId,
            expectedRevision: '9999',
            status: 'ACTIVE',
          },
          reason: `Reject stale CLI grant status ${key}`,
          checkerId: actors.checker.principalId,
        }),
        { mode: 0o600 },
      );
      await invoke('maker', [
        'transaction',
        'cigl-grant-status',
        '--input',
        input,
        '--request-key',
        key,
      ]);
      request = JSON.parse(await readFile(join(requests, `${key}.json`), 'utf8'));
    }
    const resourceId = request.fields.targetRef.split(':').at(-1);
    const before = await invoke('maker', ['read', 'cigl-grant', resourceId]);
    assert.equal(before.result.status, 'DISABLED');
    assert.notEqual(before.result.revision, request.fields.expectedRevision);
    await invoke('checker', ['approve', request.approvalId]);
    await assert.rejects(
      invoke('maker', ['execute', request.requestKey]),
      (error) =>
        error instanceof CliError &&
        error.code === 'STALE' &&
        error.problem?.status === 412 &&
        error.problem?.code === 'PC-DATA-6007',
    );
    const current = await invoke('maker', ['read', 'cigl-grant', resourceId]);
    assert.deepEqual(current.result, before.result);
    const denied = await invoke('maker', ['result', request.approvalId]);
    assert.equal(denied.candidate.operationRef, null);
  } else if (mode === 'cigl') {
    const fixture = await promisify(execFile)(process.execPath, [
      'tests/integration/local-runtime/cigl-activation-journey.mjs',
      'settings',
      evidenceRoot,
      transactionOperation('cigl-settings').actionIntentDigest,
    ]);
    const { definition } = JSON.parse(fixture.stdout);
    const published = await govern('cigl-settings', { definition });
    assert.deepEqual(published.completed.result.definition, definition);
    assert.equal(published.completed.result.state, 'STAGED');
    assert.equal(published.completed.result.runtimePermission, 'NONE');
    assert.equal(published.completed.operation.state, 'SUCCEEDED');
  } else if (mode === 'native') {
    const issued = await govern('native-value', {
      walletBindingId: `urn:openpc:resource:${walletId}`,
      executionWorkloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
      chainId: '31337',
      networkId: 'openpc-local',
      genesisDigest: `sha256:${'11'.repeat(32)}`,
      amountMode: 'EXACT',
      maxAmountWei: '10',
      validUntil: new Date(Date.now() + 240_000).toISOString(),
    });
    assert.equal(issued.completed.result.state, 'UNUSED');
    assert.equal(issued.completed.result.runtimePermission, 'NONE');
    assert.equal((await invoke('maker', ['result', issued.approvalId])).result.state, 'UNUSED');
  } else {
    await invoke('maker', ['refresh']);
    await invoke('maker', ['session']);
    const retained = JSON.parse(
      await readFile(join(evidenceRoot, 'transaction-cli-result.json'), 'utf8'),
    );
    assert.equal(
      (await invoke('maker', ['execute', retained.requestKey])).candidate.operationRef,
      retained.operationRef,
    );
    await invoke('maker', ['logout']);
    await denial('maker', ['session'], 'AUTHENTICATION');
    await invoke('maker', ['login']);
    await invoke('maker', ['session']);
  }
  process.stdout.write(`OPENPC_TRANSACTION_CLI|${mode}|PASS|assertions=${assertions}\n`);
} catch (error) {
  await writeFile(
    join(evidenceRoot, `transaction-cli-${mode}-owner-calls.json`),
    JSON.stringify(calls),
    { mode: 0o600 },
  );
  if (error instanceof CliError)
    process.stderr.write(`${JSON.stringify({ error: error.code, problem: error.problem })}\n`);
  throw error;
} finally {
  await pool.end();
}
