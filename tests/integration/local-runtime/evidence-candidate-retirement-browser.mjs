import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import { Pool } from 'pg';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import { candidateRetirementSelection } from '../../../services/control-api/src/evidence/candidate-archive/retirement-selection.ts';
import { retirementWireDigest } from '../../../services/control-api/src/evidence/store-retirement-wire.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import {
  readArchivedCandidatePayload,
  readCandidateArchiveCoverage,
} from '../../../services/control-api/src/evidence/candidate-archive/source.ts';
import { createPublicKey } from 'node:crypto';
import {
  retirementAttempt,
  verifyRetirementOutcome,
} from '../../../services/control-api/src/evidence/store-retirement-wire.ts';
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

// Retires only the original candidate whose public hold, native archive and
// delivered Fact receipts already exist. Preserve all original identities and bytes.
const [root, composeJson, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0);
assert.equal(await realpath(root), root);
assert.equal((await lstat(join(root, '.openpc-local-runtime-owner'))).isFile(), true);
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
      `Candidate retirement journey child failed: status=${error.code ?? 'unknown'}; retained=${failurePath}`,
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
const directory = join(evidence, 'candidate-store-retirement');
const secretRoot = join(root, 'secrets');
const dataRoot = join(root, 'data');
const privateRoot = join(dataRoot, 'runtime-bootstrap/candidate-store-retirement/private');
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
const actorsRoot = join(evidence, 'store-retirement');
const custody = await json(join(dataRoot, 'candidate-custody/case.json'));
assert.equal(custody.scope.participantId, participantId);
assert.equal(custody.scope.privacyDomainId, privacyDomainId);
await run(process.execPath, [
  '--import',
  'tsx',
  'tests/integration/local-runtime/store-retirement-installation-fixture.mjs',
  '--candidate',
  root,
  participantId,
  privacyDomainId,
  targetId,
]);
const installed = await json(join(privateRoot, 'installation.json'));
assert.equal(installed.host.store, 'openpc_candidate_index');
assert.equal(installed.host.target_id, targetId);
const hostDigest = retirementWireDigest(installed.host);
const control = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
  connectionTimeoutMillis: 5000,
  statement_timeout: 10000,
  options: '-c default_transaction_read_only=on',
});
const native = new Pool({
  host: '127.0.0.1',
  port: 55434,
  database: 'openpc_candidate_index',
  user: 'openpc_candidate_index',
  password: (await readFile(join(secretRoot, 'candidate_index_pg_password.txt'), 'utf8')).trim(),
  max: 1,
  connectionTimeoutMillis: 5000,
  statement_timeout: 10000,
  options: '-c default_transaction_read_only=on',
});
let record, manifest;
try {
  const rows = await control.query(
    `select c.evidence_id::text id,c.receipt_digest digest,a.manifest
    from control.evidence_candidate_archive a join control.evidence_catalogue c
    using(participant_id,privacy_domain_id,stream_id,record_id)
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.candidate_id=$3`,
    [participantId, privacyDomainId, custody.request.candidateId],
  );
  assert.equal(rows.rowCount, 1);
  record = rows.rows[0];
  manifest = record.manifest;
} finally {
  await control.end();
}
const selection = candidateRetirementSelection(manifest);
assert.equal(selection.rows[0].candidate_id, custody.request.candidateId);
const snapshot = async () => {
  const rows = await native.query(
    `select to_jsonb(e) value from candidate.candidate_event e order by candidate_event_id`,
  );
  assert.ok(rows.rowCount < 1000);
  const identity = await native.query(
    `select to_jsonb(i) value from candidate.retained_candidate_identity i where candidate_event_id=$1`,
    [custody.request.candidateId],
  );
  assert.equal(identity.rowCount, 1);
  return { events: rows.rows, identity: identity.rows };
};
try {
  if (!(await optional('native-before.json'))) {
    const before = await snapshot();
    const original = before.events.find(
      (row) => row.value.candidate_event_id === custody.request.candidateId,
    );
    assert.ok(original, 'The original native candidate must exist before retirement');
    assert.match(original.value.payload_cbor, /^\\x[0-9a-f]+$/u);
    await save('native-before.json', before);
  }
} finally {
  await native.end();
}
const overridePath = join(dataRoot, 'runtime-bootstrap/candidate-store-retirement-compose.json');
const override = {
  services: {
    'control-api': {
      environment: {
        CONTROL_API_STORE_RETIREMENT_ADMISSIONS_FILE:
          '/app/candidate-store-retirement/admissions.json',
      },
      volumes: [
        {
          type: 'bind',
          source: join(dataRoot, 'runtime-bootstrap/candidate-store-retirement/api'),
          target: '/app/candidate-store-retirement',
          read_only: true,
        },
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
const imageId = await run('docker', ['inspect', '--format', '{{.Image}}', api]);
assert.match(imageId, /^sha256:[0-9a-f]{64}$/u);
const packageRoot = join(privateRoot, 'packages', imageId.slice(7));
await mkdir(packageRoot, { recursive: true, mode: 0o700 });
const packaged = await mkdtemp(join(privateRoot, '.packaged-'));
let installedArtifacts = false;
try {
  for (const name of ['candidate_retirement_owner', 'policy_fact_reader', 'evidence-worker.mjs']) {
    const path = join(packaged, name),
      destination = join(packageRoot, name);
    await run('docker', [
      'cp',
      `${api}:${name.endsWith('.mjs') ? '/app/' : '/usr/local/bin/'}${name}`,
      path,
    ]);
    await chmod(path, 0o700);
    try {
      await link(path, destination);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      assert.equal(await realpath(destination), destination);
      assert.ok(
        (await readFile(path)).equals(await readFile(destination)),
        'A verified image must retain its exact packaged executable',
      );
    }
  }
  installedArtifacts = true;
} finally {
  if (installedArtifacts) await rm(packaged, { recursive: true, force: true });
}
const sourceProfile = selection.source.profile_id;
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
  run(process.execPath, [join(packageRoot, 'evidence-worker.mjs'), '--once'], {
    ...process.env,
    OPENPC_EVIDENCE_WORKER_CONFIG_FILE: workerPath,
    OPENPC_CANDIDATE_RETIREMENT_OWNER_BIN: join(packageRoot, 'candidate_retirement_owner'),
    OPENPC_POLICY_FACT_READER_BIN: join(packageRoot, 'policy_fact_reader'),
  });
const verifyPhysical = async (maker, admitted, recovering = false) => {
  const read = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
  const path = `evidence-deletions/store-retirements/attempts/${admitted.operation.resourceRef}`;
  const current = await read(path, {}, recovering);
  assert.equal(current.status, 200);
  assert.equal(current.body.physicalState, 'APPLIED');
  const denied = await read(path, { privacyDomainId: foreign });
  assert.ok([403, 404].includes(denied.status));
  assert.doesNotMatch(JSON.stringify(denied.body), /signedWire|attemptId|sourceBinding/u);
  const connection = async (user, name, port, database) =>
    new Pool({
      host: '127.0.0.1',
      port,
      database,
      user,
      password: (await readFile(join(secretRoot, name), 'utf8')).trim(),
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
      options: '-c default_transaction_read_only=on',
    });
  const controlRead = await connection(
    'openpc_control',
    'control_pg_password.txt',
    55432,
    'openpc_control',
  );
  const candidateRead = await connection(
    'openpc_candidate_index',
    'candidate_index_pg_password.txt',
    55434,
    'openpc_candidate_index',
  );
  const archiveRead = await connection(
    'openpc_local_control_worker',
    'control_worker_runtime_db_password.txt',
    55432,
    'openpc_control',
  );
  const key = await readFile(custody.keyFile);
  try {
    const scope = [participantId, privacyDomainId],
      attemptId = admitted.operation.resourceRef.slice(-36);
    const records = await controlRead.query(
      `select a.attempt_wire,o.signed_wire,h.target_spki,h.host_wire
      from control.store_retirement_admission a join control.store_retirement_outcome o using(participant_id,privacy_domain_id,attempt_id)
      join control.store_retirement_host h on h.participant_id=a.participant_id and h.privacy_domain_id=a.privacy_domain_id and h.host_digest=a.host_digest
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
      [...scope, attemptId],
    );
    assert.equal(records.rowCount, 1);
    const row = records.rows[0],
      attempt = retirementAttempt.parse(parseRetirementWire(row.attempt_wire));
    assert.deepEqual(attempt.selection, selection);
    const verified = verifyRetirementOutcome(
      row.signed_wire,
      createPublicKey({ key: row.target_spki, format: 'der', type: 'spki' }),
      parseRetirementWire(row.host_wire),
      attempt,
    );
    assert.equal(verified.outcome.effect.state, 'APPLIED');
    const before = await load('native-before.json');
    const original = before.events.find(
      (row) => row.value.candidate_event_id === custody.request.candidateId,
    );
    assert.ok(original);
    const events = await candidateRead.query(
      'select to_jsonb(e) value from candidate.candidate_event e order by candidate_event_id',
    );
    assert.deepEqual(
      events.rows,
      before.events.filter((row) => row !== original),
    );
    const identity = await candidateRead.query(
      'select to_jsonb(i) value from candidate.retained_candidate_identity i where candidate_event_id=$1',
      [custody.request.candidateId],
    );
    assert.deepEqual(identity.rows, before.identity);
    const nativeOutcome = await candidateRead.query(
      'select signed_outcome from candidate.store_retirement_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3',
      [...scope, attemptId],
    );
    assert.equal(nativeOutcome.rowCount, 1);
    assert.deepEqual(nativeOutcome.rows[0].signed_outcome, row.signed_wire);
    for (const table of ['retired_candidate_payload', 'store_retirement_outbox']) {
      const count = await candidateRead.query(
        `select count(*)::int count from candidate.${table} where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [...scope, attemptId],
      );
      assert.equal(count.rows[0].count, 1);
    }
    const archiveClient = await archiveRead.connect();
    await archiveClient.query('begin read only');
    try {
      await archiveClient.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        scope,
      );
      const bytes = await readArchivedCandidatePayload(
        archiveClient,
        custody.scope,
        manifest,
        await LocalEvidenceVault.open(custody.vaultDirectory, custody.sinkId),
        async (keyId) => {
          assert.equal(keyId, custody.keyId);
          return Buffer.from(key);
        },
      );
      try {
        assert.deepEqual(bytes, Buffer.from(original.value.payload_cbor.slice(2), 'hex'));
      } finally {
        bytes.fill(0);
      }
    } finally {
      try {
        await archiveClient.query('rollback');
      } finally {
        archiveClient.release();
      }
    }
    await save('terminal-readback.json', {
      public: current.body,
      signedOutcome: row.signed_wire.toString('hex'),
      attemptWire: row.attempt_wire.toString('hex'),
    });
  } finally {
    key.fill(0);
    await Promise.all([controlRead.end(), candidateRead.end(), archiveRead.end()]);
  }
};
const artifacts = join(directory, 'browser', new Date().toISOString().replaceAll(':', '-'));
await withTransactionBrowser(
  {
    secretRoot,
    evidenceRoot: actorsRoot,
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
              'Retained data class': 'CANDIDATE_PROJECTION',
              'Retention policy version': '1.0.0',
              'Retention period in milliseconds': '0',
              'Local grace in milliseconds': '0',
              'Required durable sink acknowledgements': '1',
              'Deletion mode': 'PROJECTION_DELETE',
              'Require independent deletion approval': 'true',
            },
            reason:
              'Preserve the encrypted candidate archive and original lineage while retiring its inactive native projection.',
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
      await maker.getByLabel('Find records by receipt digest', { exact: true }).fill(record.digest);
      await maker.getByRole('button', { name: 'Find evidence', exact: true }).click();
    };
    const prepareCandidate = async () => {
      // Reconciliation can leave the consumed hold release in this candidate's
      // retained Workbench slot. Start a new request through the supported UI
      // before remounting it; keep the original approval available by ID.
      await maker.getByRole('button', { name: 'New request', exact: true }).click();
      await refresh();
      const item = maker
        .getByRole('region', { name: 'Evidence catalogue', exact: true })
        .locator('li')
        .filter({ hasText: record.id });
      await expect(item).toHaveCount(1);
      await openEvidenceRecordActions(item);
      const select = item.getByRole('button', {
        name: /^Review candidate payload retirement for sequence /u,
      });
      await select.focus();
      await maker.keyboard.press('Enter');
      const prepare = maker.getByRole('button', {
        name: 'Review this candidate retirement',
        exact: true,
      });
      await expect(prepare).toBeDisabled();
      await maker
        .getByRole('combobox', { name: 'Installed candidate target', exact: true })
        .selectOption(hostDigest);
      await expect(prepare).toBeDisabled();
      await maker
        .getByRole('combobox', { name: 'Active candidate retention policy', exact: true })
        .selectOption(policy.resourceRef);
      await prepare.click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion-candidate',
      );
      for (const [label, value] of [
        ['Candidate manifest evidence reference', `urn:openpc:resource:${record.id}`],
        ['Selected installed target digest', hostDigest],
        ['Candidate retention policy reference', policy.resourceRef],
      ]) {
        await expect(maker.getByLabel(label, { exact: true })).toHaveValue(value);
      }
      await expect(maker.getByLabel('Reason', { exact: true })).toBeEnabled();
    };
    const read = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
    let hold = await read(`evidence-holds/urn:openpc:resource:${custody.activeHoldId}`);
    assert.equal(hold.status, 200);
    if (hold.body.state === 'ACTIVE') {
      const admissionCount = async () => {
        const db = new Pool({
          host: '127.0.0.1',
          port: 55432,
          database: 'openpc_control',
          user: 'openpc_control',
          password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
          max: 1,
          options: '-c default_transaction_read_only=on',
        });
        try {
          return (
            await db.query(
              'select count(*)::text count from control.store_retirement_admission where participant_id=$1 and privacy_domain_id=$2 and host_digest=$3',
              [participantId, privacyDomainId, hostDigest],
            )
          ).rows[0].count;
        } finally {
          await db.end();
        }
      };
      const count = await admissionCount();
      await prepareCandidate();
      await maker
        .getByLabel('Reason', { exact: true })
        .fill('Verify the original active hold prevents native candidate retirement.');
      const [denied] = await Promise.all([
        maker.waitForResponse(
          (r) =>
            r.request().method() === 'POST' &&
            new URL(r.url()).pathname === '/api/v1/ui/transaction-workbench' &&
            r.request().postDataJSON()?.command === 'PREVIEW',
        ),
        maker.getByRole('button', { name: 'Review request', exact: true }).click(),
      ]);
      assert.equal(denied.status(), 412);
      assert.equal((await denied.json()).code, 'PC-DATA-6007');
      await expect(maker.getByRole('status').filter({ hasText: '(PC-DATA-6007)' })).toBeVisible();
      assert.equal(await admissionCount(), count);
      await save('held-denial.json', {
        holdId: custody.activeHoldId,
        recordId: record.id,
        status: 412,
        code: 'PC-DATA-6007',
      });
      await maker.screenshot({
        path: join(artifacts, '0-candidate-held-denial.png'),
        fullPage: true,
      });
      const pending = await optional('hold-release-requested.json');
      const released = pending
        ? await completeRetained(pending.approvalId)
        : (
            await govern({
              label: transactionForms['evidence-hold-release'].label,
              fields: {
                'Resource reference': `urn:openpc:resource:${custody.activeHoldId}`,
                'Expected revision': hold.body.revision,
              },
              reason:
                'Release the original candidate hold after validating complete encrypted custody; preserve the archive and lineage.',
              onApprovalRequested: (approvalId) =>
                save('hold-release-requested.json', { approvalId }),
            })
          ).completed;
      assert.equal(released.operation.state, 'SUCCEEDED');
      hold = await read(`evidence-holds/urn:openpc:resource:${custody.activeHoldId}`);
    }
    assert.equal(hold.status, 200);
    assert.equal(hold.body.state, 'RELEASED');
    assert.ok(await load('held-denial.json'));
    const release = await load('hold-release-requested.json');
    await completeRetained(release.approvalId, false);
    // A governed release changes the hold revision. Its original vault must
    // durably acknowledge that revision before source retirement can proceed.
    const custodyPool = new Pool({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_local_control_worker',
      password: (
        await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
      ).trim(),
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
    try {
      const owner = new EvidenceCustody(custodyPool);
      const vault = await LocalEvidenceVault.open(custody.vaultDirectory, custody.sinkId);
      let pending;
      for (let pass = 0; pass < 256; pass++) {
        pending = await owner.reconcileHolds(custody.scope, vault);
        if (pending === 0) break;
      }
      assert.equal(pending, 0, 'Original hold release must reach durable vault acknowledgement');
      const client = await custodyPool.connect();
      try {
        await client.query('begin read only');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [participantId, privacyDomainId],
        );
        const coverage = await readCandidateArchiveCoverage(client, custody.scope, manifest, [
          custody.sinkId,
        ]);
        assert.equal(coverage.state, 'COMPLETE');
      } finally {
        try {
          await client.query('rollback');
        } finally {
          client.release();
        }
      }
    } finally {
      await custodyPool.end();
    }
    hold = await read(`evidence-holds/urn:openpc:resource:${custody.activeHoldId}`);
    assert.equal(hold.status, 200);
    assert.equal(hold.body.state, 'RELEASED');
    assert.equal(hold.body.coverage, 'VERIFIED');
    let admitted = await optional('browser-admission.json');
    if (!admitted) {
      const pending = await optional('retirement-requested.json');
      if (!pending) await prepareCandidate();
      const beforeExecute = async (approved) => {
        assert.equal(approved.kind, 'evidence-deletion-candidate');
        assert.equal(approved.factRetirement.class, 'CANDIDATE_PROJECTION');
        assert.equal(approved.factRetirement.candidateId, custody.request.candidateId);
        await expect(
          checker.getByRole('region', { name: 'Exact candidate retirement', exact: true }),
        ).toContainText(custody.request.candidateId);
      };
      const governed = pending
        ? {
            approvalId: pending.approvalId,
            completed: await completeWorkbenchApproval(
              maker,
              checker,
              pending.approvalId,
              true,
              beforeExecute,
            ),
          }
        : await govern({
            prepared: true,
            loseExecutionResponse: true,
            onApprovalRequested: (approvalId) => save('retirement-requested.json', { approvalId }),
            label: transactionForms['evidence-deletion-candidate'].label,
            reason:
              'Retire only this inactive and durably archived original candidate projection after the governed hold release.',
            beforeExecute,
          });
      assert.equal(governed.completed.operation.state, 'SUCCEEDED');
      assert.equal(governed.completed.result.admissionState, 'ADMITTED');
      assert.equal(governed.completed.result.physicalState, 'UNKNOWN');
      admitted = {
        approvalId: governed.completed.approval.approvalRequestId.slice(-36),
        operation: committedResource(governed.completed),
      };
      await save('browser-admission.json', admitted);
      await save('admission-result.json', admitted.operation);
    }
    // Consume original dispatch authority immediately, before visual/restart work.
    await worker();
    await verifyPhysical(maker, admitted);
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
      path: join(artifacts, '1-native-candidate-retirement.png'),
      fullPage: true,
    });
    await command(['restart', 'control-api', 'candidate-index-pg', 'admin-web']);
    await command([
      'up',
      '-d',
      '--wait',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'control-api',
      'candidate-index-pg',
      'admin-web',
    ]);
    await worker();
    await verifyPhysical(maker, admitted, true);
    await maker.reload();
    await expect(
      maker.getByRole('region', { name: 'Evidence catalogue', exact: true }),
    ).toBeVisible();
    await inspect();
    await maker.screenshot({
      path: join(artifacts, '2-native-candidate-restart.png'),
      fullPage: true,
    });
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
  'OPENPC_CANDIDATE_RETIREMENT_BROWSER|PASS|native-selection|independent-approval|physical-effect-distinct|signed-readback|original-restart|no-successor-replay\n',
);
