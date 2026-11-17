import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
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

// SEM-059: isolated initial trust; all policy/hold/approval/deletion state uses public owners.
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, participantId, privacyDomainId, composeJson, resumeRoot] = process.argv.slice(2);
assert.equal(privacyDomainId, '018f0000-0000-7000-8000-000000004201');
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const artifacts = join(secretRoot, '..', 'evidence', 'evidence-deletion-browser');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const actorFile = join(artifacts, 'deployment-intent-actors.json');
const priorActors = await readFile(actorFile).catch((error) => {
  if (error.code === 'ENOENT') return null;
  throw error;
});
if (!priorActors)
  await exec(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/deployment-intent-actors.mjs',
      secretRoot,
      artifacts,
      participantId,
      'bootstrap-evidence-deletion',
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
  const trust = (
    await pool.query(
      `select count(*)::int count from control.business_signing_selection where participant_id=$1 and privacy_domain_id=$2`,
      [participantId, privacyDomainId],
    )
  ).rows[0].count;
  if (trust === 0)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/business-signing-bootstrap.mjs',
        secretRoot,
        participantId,
        privacyDomainId,
        '--deletion-scope-trust',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  assert.equal(
    (
      await pool.query(
        `select count(*)::int count from control.business_signing_selection where participant_id=$1 and privacy_domain_id=$2`,
        [participantId, privacyDomainId],
      )
    ).rows[0].count,
    5,
  );
  const root = resumeRoot
    ? await realpath(resumeRoot)
    : await mkdtemp(join(secretRoot, '..', 'data', 'evidence-deletion-'));
  assert.equal(dirname(root), await realpath(join(secretRoot, '..', 'data')));
  const configuration = join(root, 'worker.json');
  const retained = resumeRoot ? JSON.parse(await readFile(configuration, 'utf8')) : undefined;
  const streamId = retained?.scopes[0]?.streamId ?? `deletion-authentication-${uuidv7()}`;
  const sinkId = retained?.sinkId ?? `deletion-sink-${uuidv7()}`;
  assert.match(streamId, /^deletion-authentication-[0-9a-f-]{36}$/u);
  assert.match(sinkId, /^deletion-sink-[0-9a-f-]{36}$/u);
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
  const workerConfiguration = {
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
        activeKeyId: 'deletion-test-key',
        keys: [{ keyId: 'deletion-test-key', keyFile: join(root, 'key') }],
        retentionSeconds: 60,
        capacityBytes: 16 * 1024 * 1024,
      },
    ],
  };
  if (retained) {
    assert.deepEqual(
      retained,
      workerConfiguration,
      'Resume requires the original exact worker configuration',
    );
    assert.equal((await readFile(join(root, 'key'))).length, 32);
  } else {
    await writeFile(join(root, 'key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
    await writeFile(configuration, JSON.stringify(workerConfiguration), {
      mode: 0o600,
      flag: 'wx',
    });
  }
  const runWorker = () =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
      timeout: 30000,
      maxBuffer: 65536,
    });
  await withTransactionBrowser(
    { secretRoot, evidenceRoot: artifacts, artifacts, route: '/operate/evidence', privacyDomainId },
    async ({ maker, checker, actors }) => {
      const governed = (label, fields, reason, extra = {}) =>
        governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label,
          fields,
          reason,
          ...extra,
        });
      // Context-entry assertions belong to the prior Platform context. A real
      // governed transition here supplies WebAuthn occurrences in the new scope.
      const initial = await maker.evaluate(async () => {
        const response = await fetch('/api/v1/ui/evidence-workbench', { cache: 'no-store' });
        return { status: response.status, body: await response.json() };
      });
      assert.equal(initial.status, 200);
      assert.equal(initial.body.retentionPoliciesUnavailable, false);
      assert.equal(initial.body.retentionPolicies.nextCursor, null);
      const sources = initial.body.retentionPolicies.items.filter(
        (p) => p.dataClass === 'RAW_SOURCE_BODY' && p.state === 'ACTIVE',
      );
      assert.ok(sources.length <= 1);
      if (sources.length) {
        assert.ok(resumeRoot, 'Only explicit retained continuation may reuse prior source policy');
        const policy = sources[0];
        assert.equal(policy.retentionPeriodMs, '86400000');
        assert.equal(policy.localGraceMs, '0');
        assert.equal(policy.deletionMode, 'ROW_DELETE');
        assert.equal(policy.sinkQuorum, 1);
        const owner = await pool.query(
          `select principal_id::text from control.mutation_evidence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
          [participantId, privacyDomainId, policy.activationOperationId],
        );
        assert.equal(owner.rowCount, 1);
        assert.equal(owner.rows[0].principal_id, actors.maker.principalId);
      } else {
        const sourcePolicy = await governed(
          'Activate a retention policy version',
          {
            'Retained data class': 'RAW_SOURCE_BODY',
            'Retention policy version': `0.${Date.now()}.0`,
            'Retention period in milliseconds': '86400000',
            'Local grace in milliseconds': '0',
            'Required durable sink acknowledgements': '1',
            'Deletion mode': 'ROW_DELETE',
            'Require independent deletion approval': 'true',
          },
          `Establish independent raw-source retention and real scoped authentication ${streamId}.`,
        );
        assert.equal(sourcePolicy.completed.result.state, 'ACTIVE');
      }
      await runWorker();
      const catalogue = (
        await pool.query(
          `select evidence_id::text,sequence::text,record_id,segment_id::text from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence`,
          [participantId, privacyDomainId, streamId],
        )
      ).rows;
      assert.ok(
        catalogue.length >= 2,
        'Both independently authenticated actors must have real custody',
      );
      await runWorker();
      const endpoint = '/api/v1/ui/evidence-workbench';
      let visibleRecords = [];
      const refresh = async () => {
        const response = maker.waitForResponse(
          (r) => new URL(r.url()).pathname === endpoint && !new URL(r.url()).search,
        );
        await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
        await maker.keyboard.press('Enter');
        const actual = await response;
        assert.equal(actual.status(), 200);
        const body = await actual.json();
        assert.equal(body.recordsUnavailable, false);
        assert.equal(body.holdsUnavailable, false);
        assert.equal(body.retentionPoliciesUnavailable, false);
        assert.equal(body.deletionsUnavailable, false);
        visibleRecords = body.records.items;
        return body;
      };
      const view = await refresh();
      const record = view.records.items.find(
        (r) => r.evidenceId === `urn:openpc:resource:${catalogue[0].evidence_id}`,
      );
      assert.ok(record, 'The actual admitted record must be visible in the catalogue');
      const inspect = async (button) => {
        const pending = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === endpoint &&
            new URL(r.url()).searchParams.get('deletionRecordId') === record.evidenceId.slice(-36),
        );
        const surface = button.startsWith('Check local deletion')
          ? maker
              .getByRole('region', { name: 'Evidence catalogue', exact: true })
              .locator('li')
              .nth(visibleRecords.findIndex((r) => r.evidenceId === record.evidenceId))
          : maker;
        if (button.startsWith('Check local deletion')) await openEvidenceRecordActions(surface);
        await surface.getByRole('button', { name: button, exact: true }).click();
        const response = await pending;
        assert.equal(response.status(), 200);
        return (await response.json()).plan;
      };
      const noPolicy = await inspect(`Check local deletion for sequence ${record.sequence}`);
      assert.equal(noPolicy.eligible, false);
      assert.ok(noPolicy.blockers.includes('NO_ACTIVE_POLICY'));
      await expect(
        maker.getByRole('button', { name: 'Prepare local deletion', exact: true }),
      ).toHaveCount(0);
      const policy = await governed(
        'Activate a retention policy version',
        {
          'Retained data class': 'AUDIT_EVIDENCE',
          'Retention policy version': `0.${Date.now()}.0`,
          'Retention period in milliseconds': '0',
          'Local grace in milliseconds': '0',
          'Required durable sink acknowledgements': '1',
          'Deletion mode': 'ROW_DELETE',
          'Require independent deletion approval': 'true',
        },
        `Retain archive coverage for isolated local deletion ${streamId}.`,
      );
      assert.equal(policy.completed.result.state, 'ACTIVE');
      const hold = await governed(
        'Preserve evidence under a hold',
        {
          'Hold kind': 'LEGAL',
          'Evidence to preserve': 'SEQUENCE_RANGE',
          'Evidence stream to preserve': streamId,
          'First sequence to preserve': record.sequence,
        },
        `Preserve the isolated object before independently checking deletion ${streamId}.`,
      );
      assert.equal(hold.completed.result.state, 'ACTIVE');
      assert.equal(hold.completed.result.coverage, 'PENDING');
      await refresh();
      const held = await inspect(`Check local deletion for sequence ${record.sequence}`);
      assert.equal(held.eligible, false);
      assert.ok(held.blockers.includes('ACTIVE_HOLD'));
      await expect(
        maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
      ).toContainText('An active hold preserves this object, including while coverage is pending.');
      await expect(
        maker.getByRole('button', { name: 'Prepare local deletion', exact: true }),
      ).toHaveCount(0);
      await maker.screenshot({ path: join(artifacts, 'deletion-held.png'), fullPage: true });
      const released = await governed(
        'Release an evidence hold',
        { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
        `Release only this isolated hold after the deletion denial was observed ${streamId}.`,
      );
      assert.equal(released.completed.result.state, 'RELEASED');
      await refresh();
      let plan = await inspect(`Check local deletion for sequence ${record.sequence}`);
      assert.ok(
        plan.blockers.every((b) => b === 'RETENTION_NOT_ELAPSED'),
        'Only the original storage promise may remain',
      );
      await expect
        .poll(
          async () => {
            if (!plan.eligible) plan = await inspect('Refresh deletion eligibility');
            return plan.eligible;
          },
          { timeout: 75000, intervals: [1000] },
        )
        .toBe(true);
      assert.equal(plan.selection.retentionPolicyId, policy.completed.result.retentionPolicyId);
      assert.equal(plan.selection.streamId, streamId);
      assert.equal(plan.selection.sinkReceipts.length, 1);
      await maker.getByRole('button', { name: 'Prepare local deletion', exact: true }).click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion',
      );
      await expect(maker.getByLabel('Evidence record reference', { exact: true })).toHaveValue(
        record.evidenceId,
      );
      const segment = plan.selection.segmentId;
      const before = (
        await pool.query(
          `select to_jsonb(s) metadata,p.encrypted_segment from control.evidence_segment s join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id) where s.segment_id=$1`,
          [segment],
        )
      ).rows[0];
      assert.ok(before);
      assert.equal(before.encrypted_segment.length, plan.selection.ciphertextBytes);
      const checkpoints = (
        await pool.query(
          `select * from control.evidence_checkpoint where segment_id=$1 order by sink_id`,
          [segment],
        )
      ).rows;
      const source = (
        await pool.query(
          `select * from control.authentication_occurrence where occurrence_id::text=any($1::text[]) order by occurrence_id`,
          [catalogue.map((r) => r.record_id)],
        )
      ).rows;
      assert.equal(source.length, catalogue.length);
      const files = await readdir(join(root, 'vault'), { recursive: true, withFileTypes: true });
      const archive = [];
      for (const entry of files)
        if (entry.isFile()) {
          const path = join(entry.parentPath, entry.name);
          archive.push({ path, bytes: await readFile(path) });
        }
      assert.ok(archive.length > 0, 'Real archive bytes are required before local deletion');
      const deleted = await governed(
        'Delete a local evidence payload',
        { 'Evidence record reference': record.evidenceId },
        `Delete only the eligible local object while retaining archive custody ${streamId}.`,
        { loseExecutionResponse: true },
      );
      const result = deleted.completed.result;
      assert.deepEqual(result.selection, plan.selection);
      assert.equal(result.state, 'SUCCEEDED');
      assert.equal(result.deletedCount, '1');
      assert.equal(result.deletedBytes, String(before.encrypted_segment.length));
      assert.equal(result.externalAttemptState, 'NOT_STARTED');
      assert.equal(
        (
          await pool.query(`select 1 from control.evidence_segment_payload where segment_id=$1`, [
            segment,
          ])
        ).rowCount,
        0,
      );
      assert.deepEqual(
        (
          await pool.query(
            `select to_jsonb(s) metadata from control.evidence_segment s where segment_id=$1`,
            [segment],
          )
        ).rows[0].metadata,
        before.metadata,
      );
      assert.deepEqual(
        (
          await pool.query(
            `select * from control.evidence_checkpoint where segment_id=$1 order by sink_id`,
            [segment],
          )
        ).rows,
        checkpoints,
      );
      assert.deepEqual(
        (
          await pool.query(
            `select * from control.authentication_occurrence where occurrence_id::text=any($1::text[]) order by occurrence_id`,
            [catalogue.map((r) => r.record_id)],
          )
        ).rows,
        source,
      );
      for (const file of archive) assert.deepEqual(await readFile(file.path), file.bytes);
      const receipts = await pool.query(
        `select a.receipt_cbor,a.cose_sign1,a.receipt_digest,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.operation_id=$1 and a.participant_id=$2 and a.privacy_domain_id=$3 and a.aggregate_type='evidence-deletion'`,
        [result.operationId, participantId, privacyDomainId],
      );
      assert.equal(receipts.rowCount, 1);
      const receipt = receipts.rows[0];
      assert.equal(
        verifyReceiptCose(receipt.public_key_spki_der, receipt.receipt_cbor, receipt.cose_sign1),
        true,
      );
      assert.equal(
        decodeAdmittedReceipt(receipt.receipt_cbor).transitionProfileId,
        'pc.control.evidence-deletion.local',
      );
      assert.equal(result.receiptDigest, `sha256:${receipt.receipt_digest.toString('hex')}`);
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
      assert.deepEqual((await readWorkbenchApproval(maker, deleted.approvalId)).result, result);
      const final = await refresh();
      assert.equal(
        final.deletions.items.filter((r) => r.operationId === result.operationId).length,
        1,
      );
      const region = maker.getByRole('region', { name: 'Local deletion results', exact: true });
      await expect(region).toContainText(result.receiptDigest);
      await expect(region).toContainText('1 local object');
      const gone = await inspect('Read local payload status');
      assert.equal(gone.localPayload, 'DELETED');
      assert.deepEqual(gone.blockers, ['ALREADY_DELETED']);
      await expect(
        maker.getByRole('button', { name: 'Prepare local deletion', exact: true }),
      ).toHaveCount(0);
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'deletion-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 800 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'deletion-reflow.png'), fullPage: true });
    },
  );
  process.stdout.write(
    'OPENPC_EVIDENCE_DELETION|PASS|isolated-privacy|real-oidc-webauthn|policy-hold-governance|pending-hold-denial|original-retention|packaged-custody|actual-delete|signed-receipt|lost-response|restart-readback|source-and-archive-retained|keyboard|axe|reflow\n',
  );
} finally {
  await pool.end();
}
