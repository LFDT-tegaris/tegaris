import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
  openEvidenceRecordActions,
} from './transaction-workbench-browser.mjs';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.ts';

const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, participantId, privacyDomainId, composeJson] = process.argv.slice(2);
assert.equal(privacyDomainId, '018f0000-0000-7000-8000-000000004201');
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const artifacts = join(secretRoot, '..', 'evidence', 'evidence-deletion-continuation-browser');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const actorFile = join(artifacts, 'deployment-intent-actors.json');
if (
  !(await readFile(actorFile).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  }))
)
  await exec(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/deployment-intent-actors.mjs',
      secretRoot,
      artifacts,
      participantId,
      'bootstrap-evidence-deletion-batch',
    ],
    { timeout: 30000, maxBuffer: 65536 },
  );
const database = { host: '127.0.0.1', port: 55432, database: 'openpc_control' };
const pool = new Pool({
  ...database,
  user: 'openpc_control',
  max: 1,
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
try {
  const selections = await pool.query(
    `select count(*)::int n from control.business_signing_selection s join control.business_transition_profile p using(profile_digest) where s.participant_id=$1 and s.privacy_domain_id=$2 and p.profile_id='pc.control.evidence-deletion.batch'`,
    [participantId, privacyDomainId],
  );
  if (selections.rows[0].n === 0)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/business-signing-bootstrap.mjs',
        secretRoot,
        participantId,
        privacyDomainId,
        '--deletion-batch-trust',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  assert.equal(
    (
      await pool.query(
        `select count(*)::int n from control.business_signing_selection s join control.business_transition_profile p using(profile_digest) where s.participant_id=$1 and s.privacy_domain_id=$2 and p.profile_id='pc.control.evidence-deletion.batch'`,
        [participantId, privacyDomainId],
      )
    ).rows[0].n,
    1,
  );
  const root = await mkdtemp(join(secretRoot, '..', 'data', 'evidence-deletion-batch-'));
  const streamId = `deletion-batch-${uuidv7()}`,
    sinkId = `batch-sink-${uuidv7()}`;
  process.stdout.write(`OPENPC_DELETION_BATCH_BROWSER|root=${root}|stream=${streamId}\n`);
  const container = (
    await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
  ).stdout.trim();
  const running = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(running.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  await exec('docker', [
    'cp',
    `${container}:/app/evidence-worker.mjs`,
    join(root, 'evidence-worker.mjs'),
  ]);
  await writeFile(join(root, 'key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
  const configuration = join(root, 'worker.json');
  await writeFile(
    configuration,
    JSON.stringify({
      database: {
        ...database,
        user: 'openpc_local_control_worker',
        passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
      },
      vaultDirectory: join(root, 'vault'),
      sinkId,
      scopes: [
        {
          participantId,
          privacyDomainId,
          streamId,
          source: 'AUTHENTICATION',
          activeKeyId: 'batch-test-key',
          keys: [{ keyId: 'batch-test-key', keyFile: join(root, 'key') }],
          retentionSeconds: 60,
          capacityBytes: 16 * 1024 * 1024,
        },
      ],
    }),
    { mode: 0o600, flag: 'wx' },
  );
  const runWorker = () =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
      timeout: 30000,
      maxBuffer: 65536,
    });
  await withTransactionBrowser(
    { secretRoot, evidenceRoot: artifacts, artifacts, route: '/operate/evidence', privacyDomainId },
    async ({ maker, checker, actors }) => {
      const governed = (label, fields, reason, loseExecutionResponse = false) =>
        governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label,
          fields,
          reason,
          loseExecutionResponse,
        });
      const refresh = async () => {
        const response = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === '/api/v1/ui/evidence-workbench' &&
            r.request().method() === 'GET' &&
            !new URL(r.url()).search,
        );
        await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
        const result = await response;
        assert.equal(result.status(), 200);
        return result.json();
      };
      const inspect = async (button) => {
        const response = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === '/api/v1/ui/evidence-workbench' &&
            r.request().method() === 'GET' &&
            !!new URL(r.url()).search,
        );
        await button.click();
        const result = await response;
        assert.equal(result.status(), 200);
        return (await result.json()).plan;
      };
      const initial = await refresh();
      assert.ok(
        initial.retentionPolicies.items.some(
          (p) =>
            p.state === 'ACTIVE' &&
            p.dataClass === 'AUDIT_EVIDENCE' &&
            p.retentionPeriodMs === '0' &&
            p.sinkQuorum === 1,
        ),
      );
      const hold = await governed(
        'Preserve evidence under a hold',
        {
          'Hold kind': 'INCIDENT',
          'Evidence to preserve': 'SEQUENCE_RANGE',
          'Evidence stream to preserve': streamId,
          'First sequence to preserve': '1',
        },
        `Preserve the new deletion sequence ${streamId}.`,
      );
      assert.equal(hold.completed.result.state, 'ACTIVE');
      await runWorker();
      const release = await governed(
        'Release an evidence hold',
        { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
        `Release the isolated deletion sequence ${streamId}.`,
      );
      assert.equal(release.completed.result.state, 'RELEASED');
      await runWorker();
      const objects = (
        await pool.query(
          `select s.segment_id::text,to_jsonb(s) metadata,p.encrypted_segment from control.evidence_segment s join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id) where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3 order by s.segment_id`,
          [participantId, privacyDomainId, streamId],
        )
      ).rows;
      assert.equal(objects.length, 2);
      const catalogue = (
        await pool.query(
          `select evidence_id::text,record_id,segment_id::text,sequence::text from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by segment_id,sequence`,
          [participantId, privacyDomainId, streamId],
        )
      ).rows;
      const checkpoints = (
        await pool.query(
          `select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by segment_id,sink_id`,
          [participantId, privacyDomainId, streamId],
        )
      ).rows;
      assert.equal(checkpoints.length, 2);
      const sources = (
        await pool.query(
          'select * from control.authentication_occurrence where occurrence_id::text=any($1::text[]) order by occurrence_id',
          [catalogue.map((r) => r.record_id)],
        )
      ).rows;
      assert.equal(sources.length, catalogue.length);
      const archives = [];
      for (const entry of await readdir(join(root, 'vault'), {
        recursive: true,
        withFileTypes: true,
      }))
        if (entry.isFile()) {
          const path = join(entry.parentPath, entry.name);
          archives.push({ path, bytes: await readFile(path) });
        }
      const view = await refresh();
      const firstObjectRecords = new Set(
        catalogue
          .filter((r) => r.segment_id === objects[0].segment_id)
          .map((r) => `urn:openpc:resource:${r.evidence_id}`),
      );
      const index = view.records.items.findIndex((r) => firstObjectRecords.has(r.evidenceId));
      assert.ok(index >= 0);
      const anchor = view.records.items[index].evidenceId;
      const row = maker
        .getByRole('region', { name: 'Evidence catalogue', exact: true })
        .getByRole('listitem')
        .nth(index);
      await openEvidenceRecordActions(row);
      let plan = await inspect(
        row.getByRole('button', {
          name: `Review deletion sequence from ${view.records.items[index].sequence}`,
          exact: true,
        }),
      );
      assert.equal(plan.selection.targets.length, 2);
      assert.equal(plan.selection.streamId, streamId);
      assert.ok(plan.blockers.every((b) => b === 'RETENTION_NOT_ELAPSED'));
      await expect
        .poll(
          async () => {
            if (!plan.eligible)
              plan = await inspect(
                maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }),
              );
            return plan.eligible;
          },
          { timeout: 75000, intervals: [1000] },
        )
        .toBe(true);
      await maker
        .getByRole('button', { name: 'Prepare first deletion batch', exact: true })
        .click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion-batch',
      );
      const first = await governed(
        'Start a local deletion sequence',
        { 'Starting evidence record reference': anchor },
        `Delete the first signed object of ${streamId}.`,
        true,
      );
      const firstResult = first.completed.result;
      assert.equal(firstResult.selection.batchIndex, 0);
      assert.equal(firstResult.selection.targets.length, 2);
      assert.deepEqual(firstResult.selection.targets, plan.selection.targets);
      const assertReceipt = async (result) => {
        const rows = await pool.query(
          `select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.aggregate_type='evidence-deletion'`,
          [participantId, privacyDomainId, result.operationId],
        );
        assert.equal(rows.rowCount, 1);
        const r = rows.rows[0];
        assert.ok(verifyReceiptCose(r.public_key_spki_der, r.receipt_cbor, r.cose_sign1));
        assert.equal(
          decodeAdmittedReceipt(r.receipt_cbor).transitionProfileId,
          'pc.control.evidence-deletion.batch',
        );
      };
      await assertReceipt(firstResult);
      await exec(compose[0], [...compose.slice(1), 'restart', 'control-api'], {
        timeout: 30000,
        maxBuffer: 65536,
      });
      await exec(
        compose[0],
        [
          ...compose.slice(1),
          'up',
          '-d',
          '--wait',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          'control-api',
        ],
        { timeout: 30000, maxBuffer: 65536 },
      );
      assert.deepEqual((await readWorkbenchApproval(maker, first.approvalId)).result, firstResult);
      const nextView = await refresh();
      const nextIndex = nextView.deletions.items.findIndex(
        (item) => item.deletionJobId === firstResult.deletionJobId,
      );
      assert.ok(nextIndex >= 0);
      const resultRow = maker
        .getByRole('region', { name: 'Local deletion results', exact: true })
        .getByRole('listitem')
        .nth(nextIndex);
      let next = await inspect(
        resultRow.getByRole('button', { name: 'Read signed continuation', exact: true }),
      );
      assert.equal(next.selection.batchIndex, 1);
      assert.equal(next.selection.priorCursor.receiptDigest, firstResult.receiptDigest);
      await expect
        .poll(
          async () => {
            if (!next.eligible)
              next = await inspect(
                maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }),
              );
            return next.eligible;
          },
          { timeout: 75000, intervals: [1000] },
        )
        .toBe(true);
      await maker.getByRole('button', { name: 'Prepare next deletion batch', exact: true }).click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion-continuation',
      );
      await maker.screenshot({
        path: join(artifacts, 'deletion-continuation.png'),
        fullPage: true,
      });
      const second = await governed(
        'Continue local deletion',
        { 'Previous deletion result reference': firstResult.deletionJobId },
        `Delete the next signed object of ${streamId}.`,
        true,
      );
      const secondResult = second.completed.result;
      assert.equal(secondResult.selection.batchIndex, 1);
      assert.deepEqual(secondResult.selection.targets, firstResult.selection.targets);
      await assertReceipt(secondResult);
      const finalView = await refresh();
      const finalIndex = finalView.deletions.items.findIndex(
        (item) => item.deletionJobId === secondResult.deletionJobId,
      );
      assert.ok(finalIndex >= 0);
      const complete = await inspect(
        maker
          .getByRole('region', { name: 'Local deletion results', exact: true })
          .getByRole('listitem')
          .nth(finalIndex)
          .getByRole('button', { name: 'Read signed continuation', exact: true }),
      );
      assert.equal(complete.continuationState, 'COMPLETE');
      assert.equal(complete.eligible, false);
      await expect(
        maker.getByRole('button', { name: 'Prepare next deletion batch', exact: true }),
      ).toHaveCount(0);
      const payloads = (
        await pool.query(
          'select count(*)::int n from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
          [participantId, privacyDomainId, streamId],
        )
      ).rows[0].n;
      assert.equal(payloads, 0);
      assert.deepEqual(
        (
          await pool.query(
            'select to_jsonb(s) metadata from control.evidence_segment s where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by segment_id',
            [participantId, privacyDomainId, streamId],
          )
        ).rows.map((r) => r.metadata),
        objects.map((r) => r.metadata),
      );
      assert.deepEqual(
        (
          await pool.query(
            'select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by segment_id,sink_id',
            [participantId, privacyDomainId, streamId],
          )
        ).rows,
        checkpoints,
      );
      assert.deepEqual(
        (
          await pool.query(
            'select * from control.authentication_occurrence where occurrence_id::text=any($1::text[]) order by occurrence_id',
            [catalogue.map((r) => r.record_id)],
          )
        ).rows,
        sources,
      );
      for (const file of archives) assert.deepEqual(await readFile(file.path), file.bytes);
      assert.equal(
        (
          await pool.query(
            'select used_bytes::int n from control.evidence_stream where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
            [participantId, privacyDomainId, streamId],
          )
        ).rows[0].n,
        0,
      );
      assert.equal(
        (
          await pool.query(
            `select count(*)::int n from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and state='SUCCEEDED'`,
            [participantId, privacyDomainId, streamId],
          )
        ).rows[0].n,
        2,
      );
      await maker
        .getByRole('button', { name: 'Refresh deletion eligibility', exact: true })
        .focus();
      await maker.keyboard.press('Enter');
      await expect(maker.getByLabel('Signed deletion progress')).toContainText('COMPLETE');
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'deletion-complete.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 900 });
      assert.ok(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      );
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'deletion-reflow.png'), fullPage: true });
      process.stdout.write(
        'OPENPC_DELETION_BATCH_BROWSER|PASS|two-signed-batches|independent-approval|fresh-webauthn|response-loss|restart|fixed-cursor|terminal|source-archive-preserved|keyboard|axe|reflow\n',
      );
    },
  );
} finally {
  await pool.end();
}
