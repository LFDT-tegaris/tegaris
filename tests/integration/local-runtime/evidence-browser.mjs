import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { Pool } from 'pg';
import {
  governThroughWorkbench,
  openEvidenceManualExport,
  readWorkbenchApproval,
  withTransactionBrowser,
  workbenchInputFields,
} from './transaction-workbench-browser.mjs';
import { remoteExportBrowser } from './evidence-remote-export-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import { evidenceExportRange } from '../../../services/control-api/src/evidence/export-contracts.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
const remoteMode = process.argv.includes('--remote');
if (process.argv.includes('--preflight')) {
  evidenceExportRange.parse({
    streamId: 'control-source-preflight',
    fromSequence: '1',
    throughSequence: '3',
    redactionProfileId: 'pc.evidence.minimized-audit.v1',
  });
  workbenchInputFields('Export selected evidence', {
    'Resource reference': 'urn:openpc:resource:018f0000-0000-7000-8000-000000000101',
    'Expected revision': '1',
    'Selected request digest': 'sha256:' + 'a'.repeat(64),
  });
  process.stdout.write('OPENPC_EVIDENCE_EXPORT_PREFLIGHT|PASS|selection|governed-form\n');
  process.exit(0);
}

// SEM-055/058/061/137 and PQ-000272: public signed source -> exact selection ->
// independent public approval -> packaged worker -> verified browser download.
// The administrator connection reads custody configuration and installs only
// initial remote host trust, never intermediate business state.
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, evidenceRoot, dataRoot, composeJson] = process.argv.slice(2);
assert.ok(secretRoot && evidenceRoot && dataRoot && composeJson);
const compose = JSON.parse(composeJson);
assert.equal(compose[0], 'docker');
assert.equal(compose[1], 'compose');
const actorRoot = join(evidenceRoot, 'evidence-export-browser');
const artifacts = remoteMode
  ? join(
      evidenceRoot,
      'remote-evidence-export-browser',
      new Date().toISOString().replaceAll(':', '-'),
    )
  : actorRoot;
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const endpoint = '/api/v1/ui/evidence-workbench';
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const command = (args) =>
  exec(compose[0], [...compose.slice(1), ...args], {
    timeout: 90000,
    maxBuffer: 1024 * 1024,
  });
async function observe(page, predicate, click) {
  const response = page.waitForResponse(
    (value) => new URL(value.url()).pathname === endpoint && predicate(value.request()),
  );
  await click();
  const actual = await response;
  assert.equal(actual.status(), 200, 'evidence BFF owner read must succeed');
  assert.equal(actual.headers()['cache-control'], 'no-store');
  return actual.json();
}
async function authenticateWorkloadEvidence(scope) {
  // Select only retained initial trust that is still current; no credential or
  // intermediate authentication result is inserted by this acceptance driver.
  let selected;
  for (const stem of ['identity_mtls_rotated', 'identity_mtls_client']) {
    const certificate = new X509Certificate(await readFile(join(secretRoot, `${stem}_cert.pem`)));
    if (new Date(certificate.validTo).getTime() - Date.now() < 300_000) continue;
    const rows = (
      await pool.query(
        `select c.credential_id,c.principal_id from control.credential c
      join control.principal p using(participant_id,principal_id)
      where c.participant_id=$1 and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.state='ACTIVE'
      and c.secret_fingerprint=$2 and c.valid_until>clock_timestamp()`,
        [scope.participantId, createHash('sha256').update(certificate.raw).digest()],
      )
    ).rows;
    if (rows.length === 1) {
      selected = { stem, ...rows[0] };
      break;
    }
  }
  assert.ok(selected, 'a current owned workload certificate is required');
  const rows = async () =>
    (
      await pool.query(
        `select occurrence_id::text id,receipt_digest from control.authentication_occurrence
    where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and method='TLS13_MTLS'`,
        [scope.participantId, scope.privacyDomainId, selected.principal_id],
      )
    ).rows;
  const before = new Set((await rows()).map((row) => row.id));
  const authenticated = JSON.parse(
    (
      await exec(
        'curl',
        [
          '--silent',
          '--show-error',
          '--fail',
          '--max-time',
          '10',
          '--tlsv1.3',
          '--tls-max',
          '1.3',
          '--cacert',
          join(secretRoot, 'identity_mtls_ca.pem'),
          '--cert',
          join(secretRoot, `${selected.stem}_cert.pem`),
          '--key',
          join(secretRoot, `${selected.stem}_key.pem`),
          '-H',
          'Content-Type: application/json',
          '--data',
          '{}',
          'https://127.0.0.1:53443/internal/v1/workload/authenticate',
        ],
        { timeout: 12000 },
      )
    ).stdout,
  );
  assert.equal(authenticated.participantId, scope.participantId);
  assert.equal(authenticated.principalId, selected.principal_id);
  assert.equal(authenticated.credentialId, selected.credential_id);
  const created = (await rows()).filter((row) => !before.has(row.id));
  assert.equal(created.length, 1, 'the verified transport must commit one occurrence');
  return `sha256:${created[0].receipt_digest.toString('hex')}`;
}
let remote;
try {
  const checkpoints = (
    await pool.query(
      `select receipt from control.evidence_checkpoint where participant_id=$1
     and privacy_domain_id=$2 and stream_id like 'control-source-%' and sink_id='runtime-local-sink' order by through_sequence limit 1`,
      ['018f0000-0000-7000-8000-000000000101', '018f0000-0000-7000-8000-000000000201'],
    )
  ).rows;
  assert.equal(checkpoints.length, 1, 'real signed-source custody is required');
  const object = checkpoints[0].receipt.object;
  const sourceRoots = (await readdir(dataRoot)).filter((name) =>
    name.startsWith('evidence-source-'),
  );
  assert.equal(sourceRoots.length, 1, 'one exclusively owned source key/vault is required');
  const sourceRoot = join(dataRoot, sourceRoots[0]);
  const configuration = join(artifacts, 'worker-config.json');
  await writeFile(
    configuration,
    JSON.stringify({
      database: {
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_local_control_worker',
        passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
      },
      vaultDirectory: join(sourceRoot, 'vault'),
      sinkId: object.sinkId,
      scopes: [
        {
          participantId: object.participantId,
          privacyDomainId: object.privacyDomainId,
          streamId: object.streamId,
          activeKeyId: object.keyId,
          keys: [{ keyId: object.keyId, keyFile: join(sourceRoot, 'encryption.key') }],
          retentionSeconds: 86400,
          capacityBytes: 1024 * 1024,
        },
        {
          participantId: object.participantId,
          privacyDomainId: object.privacyDomainId,
          streamId: 'identity-authentication',
          source: 'AUTHENTICATION',
          activeKeyId: object.keyId,
          keys: [{ keyId: object.keyId, keyFile: join(sourceRoot, 'encryption.key') }],
          retentionSeconds: 86400,
          capacityBytes: 1024 * 1024,
        },
      ],
    }),
    { mode: 0o600 },
  );
  if (remoteMode)
    remote = await remoteExportBrowser({ pool, configuration, directory: artifacts, object });
  const workloadEvidenceDigest = remoteMode ? null : await authenticateWorkloadEvidence(object);
  const container = (await command(['ps', '-q', 'control-api'])).stdout.trim();
  const running = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(running.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  const executable = join(artifacts, 'evidence-worker.mjs');
  await exec('docker', ['cp', `${container}:/app/evidence-worker.mjs`, executable]);
  const runWorker = async () => {
    if (remote) {
      await exec(process.execPath, [executable, '--once'], {
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
        timeout: 30000,
        maxBuffer: 65536,
      });
      return;
    }
    const pending = (
      await pool.query(
        `select count(*)::int count from control.authentication_occurrence a
      where a.participant_id=$1 and a.privacy_domain_id=$2 and not exists(
        select 1 from control.evidence_catalogue c where c.participant_id=a.participant_id
        and c.privacy_domain_id=a.privacy_domain_id and c.stream_id='identity-authentication'
        and c.record_id=a.occurrence_id::text)`,
        [object.participantId, object.privacyDomainId],
      )
    ).rows[0].count;
    assert.ok(pending <= 512, 'authentication backlog exceeds this acceptance phase budget');
    for (let batch = 0; batch < Math.max(1, Math.ceil(pending / 8)); batch++)
      await exec(process.execPath, [executable, '--once'], {
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
        timeout: 20000,
        maxBuffer: 65536,
      });
  };

  if (remote) await remote.prime(runWorker);
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: actorRoot,
      artifacts,
      route: '/operate/evidence',
    },
    async ({ maker, checker, actors }) => {
      const errors = [];
      maker.on('pageerror', (error) => errors.push(error.name));
      checker.on('pageerror', (error) => errors.push(error.name));
      await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
      await expect(maker.getByRole('region', { name: 'Evidence catalogue' })).toContainText(
        'BUSINESS_TRANSITION',
      );
      await openEvidenceManualExport(maker);
      await maker.getByLabel('Evidence stream', { exact: true }).fill(object.streamId);
      await maker.getByLabel('First sequence', { exact: true }).fill('99');
      await maker.getByLabel('Last sequence', { exact: true }).fill('99');
      await maker.getByLabel('Purpose', { exact: true }).fill('Check unavailable range denial.');
      const deniedResponse = maker.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === endpoint && response.request().method() === 'POST',
      );
      await maker.getByRole('button', { name: 'Create export request', exact: true }).click();
      const denied = await deniedResponse;
      assert.equal(denied.status(), 412);
      const deniedProblem = await denied.json();
      await expect(
        maker.getByText(`${deniedProblem.title} (${deniedProblem.code})`, { exact: true }),
      ).toBeVisible();
      await expect(maker.getByRole('region', { name: 'Selected export', exact: true })).toHaveCount(
        0,
      );
      await maker.getByLabel('First sequence', { exact: true }).fill('1');
      await maker.getByLabel('Last sequence', { exact: true }).fill('3');
      await maker
        .getByLabel('Purpose', { exact: true })
        .fill(
          remoteMode
            ? 'Verify remote signed business evidence custody.'
            : 'Verify signed business evidence custody.',
        );
      const createdResponse = maker.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === endpoint && response.request().method() === 'POST',
      );
      await maker.getByRole('button', { name: 'Create export request', exact: true }).click();
      const created = await createdResponse;
      assert.equal(created.status(), 202, 'public selection creation must succeed');
      const resourceRef = (await created.json()).operation.resourceRef;
      if (remote)
        await writeFile(join(artifacts, 'export-reference.json'), JSON.stringify({ resourceRef }), {
          mode: 0o600,
        });
      const selectedRegion = maker.getByRole('region', { name: 'Selected export', exact: true });
      await expect(selectedRegion).toContainText('REQUESTED');
      const selected = await observe(
        maker,
        (request) => request.method() === 'GET',
        () =>
          maker.getByRole('button', { name: 'Read current export status', exact: true }).click(),
      );
      assert.equal(selected.selected.evidenceExportId, resourceRef);
      assert.equal(selected.selection.records.length, 3);
      assert.equal(selected.selected.checkpoint, '0');
      assert.equal(selected.selected.outputDigest, null);
      await expect(
        maker.getByRole('button', { name: 'Retrieve verified export', exact: true }),
      ).toHaveCount(0);

      const approved = await governThroughWorkbench({
        maker,
        checker,
        checkerId: actors.checker.principalId,
        label: 'Export selected evidence',
        fields: {
          'Resource reference': resourceRef,
          'Expected revision': selected.selected.revision,
          'Selected request digest': selected.selected.requestDigest,
        },
        reason: 'Export the exact minimized record range for custody verification.',
        loseExecutionResponse: true,
      });
      assert.deepEqual(approved.review.evidenceSelection, selected.selection);
      if (remote)
        await writeFile(join(artifacts, 'export-approval.json'), JSON.stringify(approved), {
          mode: 0o600,
        });
      assert.equal(approved.completed.operation.state, 'ACCEPTED');
      assert.equal(approved.completed.operation.truthState, 'UNKNOWN');
      const running = await observe(
        maker,
        (request) => request.method() === 'GET',
        () =>
          maker.getByRole('button', { name: 'Read current export status', exact: true }).click(),
      );
      assert.equal(running.selected.state, 'RUNNING');
      assert.equal(running.selected.outputDigest, null);
      process.stdout.write(
        'OPENPC_EVIDENCE_BROWSER|governance=PASS|response-loss=reconciled|effect=pending\n',
      );

      if (remote) {
        const reads = remote.readCount();
        remote.external.faults.denyRead = true;
        await runWorker();
        const blocked = await observe(
          maker,
          (request) => request.method() === 'GET',
          () =>
            maker.getByRole('button', { name: 'Read current export status', exact: true }).click(),
        );
        assert.equal(blocked.selected.state, 'BACKLOGGED');
        assert.equal(blocked.selected.evidenceExportId, resourceRef);
        assert.equal(blocked.selected.requestDigest, selected.selected.requestDigest);
        assert.equal(blocked.selected.outputDigest, null);
        assert.ok(remote.readCount() > reads, 'the selected exact remote version must be read');
        await expect(
          maker.getByRole('button', { name: 'Retrieve verified export', exact: true }),
        ).toHaveCount(0);
        await command(['restart', 'control-api']);
        await command([
          'up',
          '-d',
          '--wait',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          'control-api',
        ]);
        remote.external.faults.denyRead = false;
      }
      await runWorker();
      const finished = await observe(
        maker,
        (request) => request.method() === 'GET',
        () =>
          maker.getByRole('button', { name: 'Read current export status', exact: true }).click(),
      );
      assert.equal(finished.selected.state, 'SUCCEEDED');
      assert.equal(finished.selected.checkpoint, '3');
      await expect(
        maker.getByRole('region', { name: 'Export requests', exact: true }),
      ).toContainText(resourceRef);
      await expect(
        maker.getByRole('region', { name: 'Export requests', exact: true }),
      ).toContainText('SUCCEEDED');
      await expect(maker.getByText('No authorized export requests.', { exact: true })).toHaveCount(
        0,
      );
      const terminal = await readWorkbenchApproval(maker, approved.approvalId);
      assert.equal(terminal.operation.state, 'SUCCEEDED');
      const retrieve = () =>
        observe(
          maker,
          (request) => new URL(request.url()).searchParams.get('artifact') === '1',
          () =>
            maker.getByRole('button', { name: 'Retrieve verified export', exact: true }).click(),
        );
      const output = await retrieve();
      assert.equal(output.download.artifact.records.length, 3);
      assert.equal(output.download.outputDigest, finished.selected.outputDigest);
      assert.equal(JSON.stringify(output.download).includes('receiptBase64'), false);
      if (remote) {
        await remote.verify(output.download);
        const api = await publicEvidenceReader(
          maker,
          secretRoot,
          object.participantId,
          object.privacyDomainId,
        );
        for (const context of [
          { participantId: uuidv7() },
          { privacyDomainId: '018f0000-0000-7000-8000-000000004202' },
        ]) {
          const denied = await api(`evidence-exports/${resourceRef}/artifact`, context);
          assert.ok(denied.status === 403 || denied.status === 404);
          assert.equal(JSON.stringify(denied.body).includes(output.download.outputDigest), false);
        }
        const unauthenticated = await fetch(
          `http://127.0.0.1:8080/api/v1/evidence-exports/${resourceRef}/artifact`,
        );
        assert.equal(unauthenticated.status, 401);
      }
      const downloadEvent = maker.waitForEvent('download');
      await maker.getByRole('button', { name: 'Download export JSON', exact: true }).click();
      const download = await downloadEvent;
      assert.equal(digest(await readFile(await download.path())), output.download.outputDigest);

      await command(['restart', 'control-api']);
      await command([
        'up',
        '-d',
        '--wait',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'control-api',
      ]);
      await runWorker();
      const restarted = await retrieve();
      assert.deepEqual(restarted.download, output.download);
      if (remote) await remote.verify(restarted.download);
      assert.equal(
        (await readWorkbenchApproval(maker, approved.approvalId)).candidate.operationRef,
        approved.completed.candidate.operationRef,
      );
      await maker.getByRole('button', { name: 'Download export JSON', exact: true }).focus();
      await expect(
        maker.getByRole('button', { name: 'Download export JSON', exact: true }),
      ).toBeFocused();
      const accessibility = await new AxeBuilder({ page: maker })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
        .analyze();
      assert.deepEqual(
        accessibility.violations.map(({ id, nodes }) => ({
          id,
          targets: nodes.map(({ target }) => target),
        })),
        [],
      );
      await maker.screenshot({ path: join(artifacts, 'completed-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 900 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      await maker.screenshot({ path: join(artifacts, 'completed-reflow.png'), fullPage: true });
      const refreshed = await observe(
        maker,
        (request) => request.method() === 'GET' && !new URL(request.url()).search,
        () => maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click(),
      );
      if (!remote) {
        assert.ok(
          refreshed.records.items.some((record) => record.evidenceClass === 'AUTHENTICATION'),
        );
        assert.ok(
          refreshed.records.items.some((record) => record.recordDigest === workloadEvidenceDigest),
          'the occurrence from this actual workload connection must reach the public catalogue',
        );
        await expect(maker.getByRole('region', { name: 'Evidence catalogue' })).toContainText(
          'AUTHENTICATION',
        );
      }
      // Session loss must purge both catalogue/artifact and governed candidate state.
      assert.equal(
        await maker.evaluate(
          async () => (await fetch('/api/v1/ui/local-session', { method: 'DELETE' })).status,
        ),
        202,
      );
      await maker.reload();
      await expect(
        maker.getByRole('button', { name: 'Download export JSON', exact: true }),
      ).toHaveCount(0);
      await expect(maker.getByRole('region', { name: 'Selected export', exact: true })).toHaveCount(
        0,
      );
      await expect(maker.getByText(resourceRef, { exact: true })).toHaveCount(0);
      assert.deepEqual(errors, []);
      if (remote)
        process.stdout.write(
          'OPENPC_REMOTE_EXPORT_BROWSER|PASS|original-signed-source|exact-remote-version|no-local-fallback|approved-minimized-download|unavailable-backlog|same-export-recovery|no-repeat-selected-put|foreign-scope|unauthenticated|keyboard|axe|reflow|provider-not-qualified\n',
        );
      else
        process.stdout.write(
          'OPENPC_EVIDENCE_BROWSER|PASS|signed-source|oidc-pkce|distinct-checker|webauthn|mtls-occurrence|worker|immutable-download|restart|axe|reflow|session-loss\n',
        );
    },
  );
} finally {
  await remote?.close();
  await pool.end();
}
