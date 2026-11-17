import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { parseRetirementWire } from '../../../services/control-api/src/evidence/store-retirement-wire.ts';
import { transactionForms } from '../../../apps/admin-web/lib/transaction-workflow.ts';
import {
  completeWorkbenchApproval,
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
  openEvidenceRecordActions,
} from './transaction-workbench-browser.mjs';

// Consumes the already governed, custodied and withdrawn original of the clean
// source journey. The quarantined successor is never acknowledged or replayed.
const [root, composeJson] = process.argv.slice(2);
const execute = promisify(execFile);
const run = async (command, args, env = process.env) => {
  try {
    const { stdout } = await execute(command, args, {
      env,
      timeout: 120000,
      maxBuffer: 1024 * 1024,
    });
    process.stdout.write(stdout);
    return stdout.trim();
  } catch (error) {
    const failureRoot = join(root, 'evidence/runtime-bootstrap/store-retirement');
    await mkdir(failureRoot, { recursive: true, mode: 0o700 });
    const failurePath = join(failureRoot, `child-failure-${Date.now()}.log`);
    await writeFile(failurePath, `${error.stdout ?? ''}\n${error.stderr ?? ''}`, {
      flag: 'wx',
      mode: 0o600,
    });
    throw new Error(
      `Fact retirement journey child failed: status=${error.code ?? 'unknown'}; retained=${failurePath}`,
    );
  }
};
await run('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--memory-gib',
  '3',
  '--reuse',
  '--',
  'true',
]);
const baseCompose = JSON.parse(composeJson);
assert.deepEqual(baseCompose.slice(0, 2), ['docker', 'compose']);
const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const evidence = join(root, 'evidence/runtime-bootstrap');
const directory = join(evidence, 'store-retirement');
const secretRoot = join(root, 'secrets');
const dataRoot = join(root, 'data');
const privateRoot = join(dataRoot, 'runtime-bootstrap/store-retirement/private');
await mkdir(directory, { recursive: true, mode: 0o700 });
const load = (name) => json(join(directory, name));
const save = async (name, value) => {
  try {
    await writeFile(join(directory, name), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.deepEqual(await load(name), value, 'Reconcile the original browser intent');
  }
};
const optional = async (name) =>
  load(name).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
const node = (file, ...args) =>
  run(process.execPath, ['--import', 'tsx', `tests/integration/local-runtime/${file}`, ...args]);
const { participantId, privacyDomainId } = await json(
  join(evidence, 'rpc-source-policy-input.json'),
);
const { targetId } = await json(join(evidence, 'discovery-credential-input.json'));
const foreign = '018f0000-0000-7000-8000-000000000201';
assert.notEqual(privacyDomainId, foreign);
await run(baseCompose[0], [
  ...baseCompose.slice(1),
  'stop',
  'runtime-target',
  'runtime-envoy',
  'control-worker',
  'fact-service',
]);
await node(
  'deployment-intent-actors.mjs',
  secretRoot,
  directory,
  participantId,
  'bootstrap-evidence-store-retirement',
  privacyDomainId,
  foreign,
  '--preflight',
);
await node(
  'signing-provider-bootstrap.ts',
  secretRoot,
  join(dataRoot, 'signing-provider'),
  '--store-retirement',
  privacyDomainId,
);
if (!(await optional('deployment-intent-actors.json')))
  await node(
    'deployment-intent-actors.mjs',
    secretRoot,
    directory,
    participantId,
    'bootstrap-evidence-store-retirement',
    privacyDomainId,
    foreign,
  );
await node(
  'business-signing-bootstrap.mjs',
  secretRoot,
  participantId,
  privacyDomainId,
  '--store-retirement-trust',
);
await node(
  'store-retirement-installation-fixture.mjs',
  root,
  participantId,
  privacyDomainId,
  targetId,
  'sha256:6bd1b7ff42169210dab9f9a28055f450b422a47834ff4e68e8c2de9d54804efc',
);
if (!(await optional('selection-input.json')))
  await node('evidence-fact-store-retirement.mjs', 'prepare', root);
await node('evidence-fact-store-retirement.mjs', 'preflight', root);
const selection = await load('selection-input.json');
const original = (await load('original-fact.json'))[0].value;
const installed = await json(join(privateRoot, 'installation.json'));
const overridePath = join(dataRoot, 'runtime-bootstrap/store-retirement-compose.json');
const override = {
  services: {
    'control-api': {
      environment: {
        CONTROL_API_STORE_RETIREMENT_ADMISSIONS_FILE: '/app/store-retirement/admissions.json',
      },
      volumes: [
        {
          type: 'bind',
          source: join(dataRoot, 'runtime-bootstrap/store-retirement/api'),
          target: '/app/store-retirement',
          read_only: true,
        },
      ],
    },
  },
};
try {
  await writeFile(overridePath, JSON.stringify(override), { flag: 'wx', mode: 0o600 });
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
  assert.deepEqual(await json(overridePath), override);
}
const compose = [...baseCompose, '-f', overridePath];
const command = (args) => run(compose[0], [...compose.slice(1), ...args]);
await command(['stop', 'runtime-target', 'runtime-envoy', 'control-worker', 'fact-service']);
await command([
  'up',
  '-d',
  '--wait',
  '--no-deps',
  '--no-build',
  '--pull',
  'never',
  'participant-service',
]);
await command(['restart', 'signing-provider']);
await command([
  'up',
  '-d',
  '--wait',
  '--no-deps',
  '--no-build',
  '--pull',
  'never',
  'signing-provider',
  'control-api',
  'admin-web',
]);
const api = await command(['ps', '-q', 'control-api']);
for (const binary of ['fact_retirement_owner', 'policy_fact_reader']) {
  await run('docker', ['cp', `${api}:/usr/local/bin/${binary}`, join(privateRoot, binary)]);
  await chmod(join(privateRoot, binary), 0o700);
}
await run('docker', [
  'cp',
  `${api}:/app/evidence-worker.mjs`,
  join(privateRoot, 'evidence-worker.mjs'),
]);
const sourceProfile = parseRetirementWire(Buffer.from(selection.selectionWireHex, 'hex')).source
  .profile_id;
let configuration;
for (const entry of await readdir(dataRoot, { withFileTypes: true })) {
  if (!entry.isDirectory() || !entry.name.startsWith('evidence-rpc-')) continue;
  const candidate = await json(join(dataRoot, entry.name, 'fact-custody/worker.json')).catch(
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    },
  );
  if (
    candidate?.scopes.some(
      (scope) =>
        scope.participantId === participantId &&
        scope.privacyDomainId === privacyDomainId &&
        scope.source === 'FACT' &&
        scope.fact.sourceProfileId === sourceProfile,
    )
  ) {
    assert.equal(configuration, undefined, 'One original custody configuration');
    configuration = candidate;
  }
}
assert.ok(configuration);
assert.equal(configuration.scopes.length, 1);
assert.equal(configuration.scopes[0].participantId, participantId);
assert.equal(configuration.scopes[0].privacyDomainId, privacyDomainId);
configuration.storeRetirements = [
  {
    host: installed.host,
    verifierKeyFile: join(privateRoot, 'verifier.key'),
    controlPrivateKeyFile: join(privateRoot, 'control.pem'),
    targetConfigurationFile: join(privateRoot, 'target.json'),
  },
];
const workerPath = join(privateRoot, 'worker.json');
try {
  await writeFile(workerPath, JSON.stringify(configuration), { flag: 'wx', mode: 0o600 });
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
  assert.deepEqual(await json(workerPath), configuration);
}
const worker = () =>
  run(process.execPath, [join(privateRoot, 'evidence-worker.mjs'), '--once'], {
    ...process.env,
    OPENPC_EVIDENCE_WORKER_CONFIG_FILE: workerPath,
    OPENPC_FACT_RETIREMENT_OWNER_BIN: join(privateRoot, 'fact_retirement_owner'),
    OPENPC_POLICY_FACT_READER_BIN: join(privateRoot, 'policy_fact_reader'),
  });
const artifacts = join(directory, 'browser', new Date().toISOString().replaceAll(':', '-'));
await withTransactionBrowser(
  {
    secretRoot,
    evidenceRoot: directory,
    artifacts,
    privacyDomainId,
    reuseSessions: true,
    route: '/operate/evidence',
  },
  async ({ maker, checker, actors }) => {
    const govern = (options) =>
      governThroughWorkbench({ maker, checker, checkerId: actors.checker.principalId, ...options });
    const completeRetained = (approvalId, allowMutation = true) =>
      completeWorkbenchApproval(maker, checker, approvalId, allowMutation);
    const committedResource = (completed) => {
      assert.equal(completed.candidate.state, 'CONSUMED');
      assert.equal(completed.operation.state, 'SUCCEEDED');
      assert.equal(
        completed.candidate.operationRef,
        `urn:openpc:operation:${completed.operation.operationId}`,
      );
      assert.match(completed.candidate.resourceRef, /^urn:openpc:resource:[0-9a-f-]{36}$/u);
      return { ...completed.operation, resourceRef: completed.candidate.resourceRef };
    };
    let policy = await optional('policy-result.json');
    if (!policy) {
      const requested = await optional('policy-requested.json');
      const governed = requested
        ? { completed: await completeRetained(requested.approvalId) }
        : await govern({
            label: transactionForms['retention-policy'].label,
            onApprovalRequested: (approvalId) => save('policy-requested.json', { approvalId }),
            fields: {
              'Retained data class': 'ADMITTED_FACT',
              'Retention policy version': '1.0.0',
              'Retention period in milliseconds': '0',
              'Local grace in milliseconds': '0',
              'Required durable sink acknowledgements': '1',
              'Deletion mode': 'ROW_DELETE',
              'Require independent deletion approval': 'true',
            },
            reason:
              'Preserve signed Fact custody and identity while retiring the withdrawn payload.',
          });
      policy = committedResource(governed.completed);
      await save('policy-result.json', policy);
    } else {
      const requested = await load('policy-requested.json');
      const completed = await completeRetained(requested.approvalId, false);
      assert.equal(completed.operation.operationId, policy.operationId);
      assert.equal(policy.state, 'SUCCEEDED');
      // Historical saved Operation projections omit resourceRef. Reconcile it
      // through public candidate readback without rewriting retained evidence.
      const current = committedResource(completed);
      if (policy.resourceRef) assert.equal(current.resourceRef, policy.resourceRef);
      policy = current;
    }
    const refresh = async () => {
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
      await expect(
        maker.getByRole('region', { name: 'Evidence catalogue', exact: true }),
      ).toBeVisible();
      await maker
        .getByLabel('Find records by receipt digest', { exact: true })
        .fill(`sha256:${original.signed_fact_digest.slice(2)}`);
      await maker.getByRole('button', { name: 'Find evidence', exact: true }).click();
    };
    let admitted = await optional('browser-admission.json');
    if (!admitted) {
      assert.equal(
        await optional('retirement-requested.json'),
        null,
        'Read the original pending retirement approval before continuing',
      );
      await refresh();
      const item = maker
        .getByRole('region', { name: 'Evidence catalogue', exact: true })
        .locator('li')
        .filter({ hasText: selection.recordRefs[0].evidenceId });
      await expect(item).toHaveCount(1);
      await openEvidenceRecordActions(item);
      const select = item.getByRole('button', {
        name: /^Review Fact payload retirement for sequence /u,
      });
      await select.focus();
      await maker.keyboard.press('Enter');
      const prepare = maker.getByRole('button', {
        name: 'Review this Fact retirement',
        exact: true,
      });
      await expect(prepare).toBeDisabled();
      await maker
        .getByRole('combobox', { name: 'Installed Fact target', exact: true })
        .selectOption(selection.hostDigest);
      await expect(prepare).toBeDisabled();
      await maker
        .getByRole('combobox', { name: 'Active Fact retention policy', exact: true })
        .selectOption(policy.resourceRef);
      await prepare.click();
      const governed = await govern({
        prepared: true,
        onApprovalRequested: (approvalId) => save('retirement-requested.json', { approvalId }),
        label: transactionForms['evidence-deletion-fact'].label,
        reason: 'Retire this independently admitted, withdrawn and durably archived Fact payload.',
        beforeExecute: async (approved) => {
          assert.equal(approved.kind, 'evidence-deletion-fact');
          assert.equal(approved.factRetirement.candidateId, original.candidate_id);
          assert.equal(
            approved.factRetirement.signedFactDigest,
            original.signed_fact_digest.slice(2),
          );
          await expect(
            checker.getByRole('region', { name: 'Exact Fact retirement', exact: true }),
          ).toContainText(approved.factRetirement.factId);
        },
      });
      assert.equal(governed.completed.operation.state, 'SUCCEEDED');
      assert.equal(governed.completed.result.admissionState, 'ADMITTED');
      assert.equal(governed.completed.result.physicalState, 'UNKNOWN');
      admitted = {
        approvalId: governed.approvalId,
        operation: committedResource(governed.completed),
      };
      await save('browser-admission.json', admitted);
      await save('admission-result.json', admitted.operation);
    }
    // Consume original dispatch authority immediately, before visual/restart work.
    await worker();
    await node('evidence-fact-store-retirement.mjs', 'verify', root);
    const inspect = async () => {
      const value = await readWorkbenchApproval(maker, admitted.approvalId);
      assert.equal(value.candidate.state, 'CONSUMED');
      assert.equal(value.result.physicalState, 'APPLIED');
      assert.equal(value.operation.operationId, admitted.operation.operationId);
      await expect(
        maker.getByText('Admission operation: SUCCEEDED', { exact: false }),
      ).toBeVisible();
      await expect(
        maker.getByRole('button', { name: 'Execute approved request', exact: true }),
      ).toBeDisabled();
    };
    await inspect();
    await maker.setViewportSize({ width: 390, height: 844 });
    await expect
      .poll(() => maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
      .toBe(true);
    assert.deepEqual(
      (await new AxeBuilder({ page: maker }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze())
        .violations,
      [],
    );
    await maker.screenshot({
      path: join(artifacts, '1-native-fact-retirement.png'),
      fullPage: true,
    });
    await command(['restart', 'control-api', 'fact-pg', 'admin-web']);
    await command([
      'up',
      '-d',
      '--wait',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'control-api',
      'fact-pg',
      'admin-web',
    ]);
    await worker();
    await node('evidence-fact-store-retirement.mjs', 'verify-restart', root);
    await maker.reload();
    await expect(
      maker.getByRole('region', { name: 'Evidence catalogue', exact: true }),
    ).toBeVisible();
    await inspect();
    await maker.screenshot({ path: join(artifacts, '2-native-fact-restart.png'), fullPage: true });
    await writeFile(
      join(artifacts, 'result.json'),
      JSON.stringify({
        state: 'PASS',
        approvalId: admitted.approvalId,
        physicalState: 'APPLIED',
        visualInspection: 'PENDING',
        wholeJourney: 'OPEN',
      }),
      { mode: 0o600 },
    );
  },
);
process.stdout.write(
  'OPENPC_FACT_RETIREMENT_BROWSER|PASS|native-selection|independent-approval|physical-effect-distinct|signed-readback|original-restart|no-successor-replay\n',
);
