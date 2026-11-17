import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile, chmod } from 'node:fs/promises';
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
import {
  assertRejectionDeletionSources,
  publicEvidenceReader,
  rejectionDeletionSnapshot,
  wrongRejectionTrust,
  retryDeletion,
  withDeletionOutboxFault,
  contendingReservation,
} from './evidence-rejection-deletion-checks.mjs';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.ts';

// SEM-059 / REQ-SR01-B0-LEDGER-RTP-047: the public deployment journey
// supplies immutable terminal rejections. This driver never seeds execution,
// rejection, approval or deletion success, and never resubmits a deployment.
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
assert.equal(privacyDomainId, '018f0000-0000-7000-8000-000000000201');
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const artifacts = join(secretRoot, '..', 'evidence', 'evidence-rejection-deletion-browser');
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
      'bootstrap-evidence-rejection-deletion',
    ],
    { timeout: 30000, maxBuffer: 65536 },
  );
const database = { host: '127.0.0.1', port: 55432, database: 'openpc_control' };
const admin = new Pool({
  ...database,
  user: 'openpc_control',
  max: 3,
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const worker = new Pool({
  ...database,
  user: 'openpc_local_control_worker',
  max: 2,
  password: (
    await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
  ).trim(),
});
let result, approvalId, chosenRecord;
try {
  const selectionCount = async () =>
    (
      await admin.query(
        "select count(*)::int n from control.business_signing_selection s join control.business_transition_profile p using(profile_digest) where s.participant_id=$1 and s.privacy_domain_id=$2 and p.profile_id like 'pc.control.evidence-deletion.%'",
        [participantId, privacyDomainId],
      )
    ).rows[0].n;
  if ((await selectionCount()) === 0)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/business-signing-bootstrap.mjs',
        secretRoot,
        participantId,
        privacyDomainId,
        '--rejection-deletion-trust',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  assert.equal(await selectionCount(), 2);
  const root = await mkdtemp(join(secretRoot, '..', 'data', 'evidence-rejection-deletion-'));
  process.stdout.write(`OPENPC_REJECTION_DELETION|root=${root}\n`);
  const scope = { participantId, privacyDomainId, streamId: `rejection-deletion-${uuidv7()}` };
  const sources = (
    await admin.query(
      'select command_id::text,sequence::text,signed_bytes,result_digest from control.deployment_result where participant_id=$1 and privacy_domain_id=$2 order by created_at,command_id,sequence',
      [participantId, privacyDomainId],
    )
  ).rows;
  const isRejection = (row) =>
    JSON.parse(row.signed_bytes.toString()).claims.schema ===
    'PC-DEPLOYMENT-RESERVATION-REJECTION-1';
  assert.ok(sources.some(isRejection), 'requires a real public terminal pre-handoff rejection');
  assert.ok(
    sources.some((row) => !isRejection(row)),
    'requires real target observations for mixed-object denial',
  );
  assert.ok(sources.length <= 512);
  assertRejectionDeletionSources(sources);
  const container = (
    await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
  ).stdout.trim();
  const running = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(running.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  for (const [from, to] of [
    ['/app/evidence-worker.mjs', 'evidence-worker.mjs'],
    ['/app/result-source.sql', 'result-source.sql'],
    ['/usr/local/bin/openpc-policy-evaluator', 'openpc-policy-evaluator'],
  ])
    await exec('docker', ['cp', `${container}:${from}`, join(root, to)]);
  await chmod(join(root, 'openpc-policy-evaluator'), 0o700);
  const key = randomBytes(32),
    keyId = 'rejection-deletion-key';
  await writeFile(join(root, 'key'), key, { mode: 0o600, flag: 'wx' });
  const sinkId = `rejection-archive-${uuidv7()}`,
    configuration = join(root, 'worker.json');
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
          ...scope,
          source: 'EFFECT',
          activeKeyId: keyId,
          keys: [{ keyId, keyFile: join(root, 'key') }],
          retentionSeconds: 60,
          capacityBytes: 16 * 1024 * 1024,
        },
      ],
    }),
    { mode: 0o600, flag: 'wx' },
  );
  const runWorker = () =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: {
        ...process.env,
        OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration,
        OPENPC_POLICY_CORE_BIN: join(root, 'openpc-policy-evaluator'),
        OPENPC_DEPLOYMENT_PROJECTION_PUBLIC_KEY_FILE: join(
          secretRoot,
          'runtime_agent_projection_public_key.txt',
        ),
        OPENPC_DEPLOYMENT_REJECTION_PUBLIC_KEY_FILE: join(
          secretRoot,
          'fleet_deployment_rejection_public_key.txt',
        ),
      },
      timeout: 30000,
      maxBuffer: 65536,
    });
  const catalogue = async () =>
    (
      await admin.query(
        'select evidence_id::text,sequence::text,record_id,segment_id::text,source_format from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence',
        [participantId, privacyDomainId, scope.streamId],
      )
    ).rows;
  let records = [];
  for (let tick = 0; tick <= sources.length + 1; tick++) {
    await runWorker();
    records = await catalogue();
    if (records.length === sources.length) break;
  }
  assert.equal(
    records.length,
    sources.length,
    'format separation must not omit any original observation',
  );
  const stable = await catalogue();
  await runWorker();
  assert.deepEqual(await catalogue(), stable);
  const custody = new EvidenceCustody(worker);
  const secondSink = await LocalEvidenceVault.open(
    join(root, 'second-vault'),
    `rejection-archive-${uuidv7()}`,
  );
  for (let tick = 0; tick <= sources.length; tick++)
    if (!(await custody.exportNext(scope, secondSink))) break;
  const originalSink = await LocalEvidenceVault.open(join(root, 'vault'), sinkId);
  const archive = [];
  const sourceRecords = [];
  const checkpoints = (
    await admin.query(
      'select receipt from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sink_id,through_sequence',
      [participantId, privacyDomainId, scope.streamId],
    )
  ).rows;
  for (const { receipt } of checkpoints) {
    const sink = receipt.object.sinkId === sinkId ? originalSink : secondSink;
    const bytes = await sink.read(receipt.object);
    archive.push({ sink, object: receipt.object, bytes });
    if (sink === originalSink) {
      const inspected = inspectSegment(bytes);
      sourceRecords.push(
        ...openSegment(bytes, inspected.objectDigest, inspected.header, key).records,
      );
    }
  }
  assert.equal(sourceRecords.length, sources.length);
  for (let i = 0; i < sources.length; i++)
    assert.deepEqual(
      Buffer.from(sourceRecords[i].receiptBase64, 'base64'),
      sources[i].signed_bytes,
    );
  const originals = sourceRecords.map(
    ({ recordId, evidenceClass, sourceFormat, occurredAt, receiptDigest, receiptBase64 }) => ({
      recordId,
      evidenceClass,
      sourceFormat,
      occurredAt,
      receiptDigest,
      receiptBase64,
    }),
  );
  const rejected = originals.find(
    (r) => r.sourceFormat === 'PC-DEPLOYMENT-RESERVATION-REJECTION-1',
  );
  chosenRecord = records.find((r) => r.record_id === rejected.recordId);
  assert.ok(chosenRecord);
  assert.ok(
    records
      .filter((r) => r.segment_id === chosenRecord.segment_id)
      .every((r) => r.source_format === rejected.sourceFormat),
  );
  // Supporting negative custody fixtures use actual verified originals; they
  // cannot create a positive source or an authoritative deployment completion.
  const negativeRecords = [
    [rejected, originals.find((r) => r.sourceFormat !== rejected.sourceFormat)],
    [{ ...rejected, recordId: `deployment:${uuidv7()}:1` }],
    [{ ...rejected, sourceFormat: 'UNVERIFIED-REJECTION' }],
    [
      {
        ...rejected,
        receiptBase64: Buffer.from('{}').toString('base64'),
        receiptDigest: sha256(Buffer.from('{}')),
      },
    ],
  ];
  const negatives = [];
  for (const inputs of negativeRecords) {
    const negativeScope = { ...scope, streamId: `rejection-negative-${uuidv7()}` };
    await custody.admit(
      negativeScope,
      inputs,
      { keyId, key },
      new Date(Date.now() + 60000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      16 * 1024 * 1024,
    );
    negatives.push(
      (
        await admin.query(
          'select evidence_id::text id from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence limit 1',
          [participantId, privacyDomainId, negativeScope.streamId],
        )
      ).rows[0].id,
    );
  }
  const snapshot = () =>
    rejectionDeletionSnapshot(admin, participantId, privacyDomainId, scope.streamId);
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
      const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
      const ref = `urn:openpc:resource:${chosenRecord.evidence_id}`,
        planPath = `evidence-records/${ref}/deletion-plan`;
      const policies = await api('retention-policies');
      assert.equal(policies.status, 200);
      assert.equal(policies.body.nextCursor, null);
      let policy = policies.body.items.find(
          (p) => p.dataClass === 'AUDIT_EVIDENCE' && p.state === 'ACTIVE',
        ),
        ownPolicy = false;
      if (!policy) {
        const activated = await governed(
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
          `Authorize only local ciphertext deletion with preserved archive ${scope.streamId}.`,
        );
        policy = activated.completed.result;
        ownPolicy = true;
      }
      assert.equal(policy.deletionMode, 'ROW_DELETE');
      assert.ok(policy.sinkQuorum <= 2);
      for (const id of [
        ...negatives,
        ...records
          .filter((r) => r.source_format !== rejected.sourceFormat)
          .map((r) => r.evidence_id),
      ]) {
        const denied = await api(`evidence-records/urn:openpc:resource:${id}/deletion-plan`);
        assert.equal(denied.status, 200);
        assert.equal(denied.body.eligible, false);
        assert.ok(denied.body.blockers.includes('UNSUPPORTED_SOURCE'));
      }
      const beforeTrust = await snapshot();
      await wrongRejectionTrust(secretRoot, async () => {
        const denied = await api(planPath);
        assert.ok(denied.status >= 400);
        assert.equal(denied.body.code, 'PC-FACT-4001');
      });
      assert.deepEqual(await snapshot(), beforeTrust);
      const foreign = await api(planPath, { participantId: uuidv7() });
      assert.ok([403, 404].includes(foreign.status));
      assert.equal(JSON.stringify(foreign.body).includes(chosenRecord.evidence_id), false);
      const endpoint = '/api/v1/ui/evidence-workbench';
      const refresh = async () => {
        const pending = maker.waitForResponse(
          (r) => new URL(r.url()).pathname === endpoint && !new URL(r.url()).search,
        );
        await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
        await maker.keyboard.press('Enter');
        const response = await pending;
        assert.equal(response.status(), 200);
        return response.json();
      };
      const view = await refresh();
      assert.equal(view.recordsUnavailable, false);
      const index = view.records.items.findIndex((r) => r.evidenceId === ref);
      assert.ok(index >= 0, 'newly admitted original must be visible');
      const inspect = async (button) => {
        const pending = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === endpoint &&
            new URL(r.url()).searchParams.get('deletionRecordId') === chosenRecord.evidence_id,
        );
        const surface = button.startsWith('Check local deletion')
          ? maker
              .getByRole('region', { name: 'Evidence catalogue', exact: true })
              .locator('li')
              .nth(index)
          : maker;
        if (button.startsWith('Check local deletion')) await openEvidenceRecordActions(surface);
        await surface.getByRole('button', { name: button, exact: true }).click();
        const response = await pending;
        assert.equal(response.status(), 200);
        return (await response.json()).plan;
      };
      let plan = await inspect(`Check local deletion for sequence ${chosenRecord.sequence}`);
      assert.ok(plan.blockers.every((b) => b === 'RETENTION_NOT_ELAPSED'));
      await expect
        .poll(
          async () => {
            if (!plan.eligible) plan = await inspect('Refresh deletion eligibility');
            return plan.eligible;
          },
          { timeout: 75000, intervals: [1000] },
        )
        .toBe(true);
      assert.equal(plan.selection.sourceRejections.length, plan.selection.recordCount);
      const proof = plan.selection.sourceRejections.find((p) => p.evidenceId === ref);
      assert.ok(proof);
      assert.equal(proof.externalAttemptState, 'NOT_STARTED');
      assert.equal(proof.commandId, rejected.recordId.split(':')[1]);
      assert.equal(proof.receiptDigest, rejected.receiptDigest);
      await expect(
        maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
      ).toContainText('rejected before runtime handoff');
      await maker.getByRole('button', { name: 'Prepare local deletion', exact: true }).click();
      await expect(maker.getByLabel('Evidence record reference', { exact: true })).toHaveValue(ref);
      const before = await snapshot();
      const failed = await governed(
        'Delete a local evidence payload',
        { 'Evidence record reference': ref },
        `Delete the qualified original rejection ciphertext ${scope.streamId}.`,
        {
          expectedExecutionStatus: 503,
          beforeExecute: async () => {
            await writeFile(
              join(
                secretRoot,
                '..',
                'data',
                'signing-provider',
                'faults',
                'next-SIGN_RECEIPT.json',
              ),
              JSON.stringify({ mode: 'REJECT_NOT_APPLIED' }),
              { mode: 0o600, flag: 'wx' },
            );
          },
        },
      );
      approvalId = failed.approvalId;
      assert.deepEqual(await snapshot(), before);
      await wrongRejectionTrust(secretRoot, async () => {
        await retryDeletion(maker, approvalId, { failed: true });
        assert.deepEqual(await snapshot(), before);
      });
      await withDeletionOutboxFault(admin, scope.streamId, 'FAIL', async () => {
        await retryDeletion(maker, approvalId, { failed: true });
        assert.deepEqual(await snapshot(), before);
      });
      const completed = await withDeletionOutboxFault(admin, scope.streamId, 'WAIT', () =>
        contendingReservation({
          admin,
          worker,
          commandId: proof.commandId,
          attemptId: proof.attemptId,
          participantId,
          privacyDomainId,
          execute: (duringExecution) =>
            retryDeletion(maker, approvalId, { duringExecution, loseResponse: true }),
        }),
      );
      result = completed.result;
      assert.equal(result.state, 'SUCCEEDED');
      assert.deepEqual(result.selection, plan.selection);
      assert.equal(result.externalAttemptState, 'NOT_STARTED');
      const after = await snapshot();
      for (const field of ['results', 'reservations', 'segments', 'checkpoints'])
        assert.deepEqual(after[field], before[field]);
      assert.equal(after.payloads.length, before.payloads.length - 1);
      assert.ok(!after.payloads.some((p) => p.segment_id === chosenRecord.segment_id));
      assert.equal(
        BigInt(before.stream[0].used_bytes) - BigInt(after.stream[0].used_bytes),
        BigInt(result.deletedBytes),
      );
      for (const field of ['jobs', 'items', 'receipts', 'outbox', 'attempts'])
        assert.equal(after[field].length, before[field].length + 1);
      for (const file of archive) assert.deepEqual(await file.sink.read(file.object), file.bytes);
      const receipt = (
        await admin.query(
          "select a.receipt_cbor,a.cose_sign1,a.receipt_digest,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.operation_id=$1 and a.aggregate_type='evidence-deletion'",
          [result.operationId],
        )
      ).rows[0];
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
      assert.deepEqual((await readWorkbenchApproval(maker, approvalId)).result, result);
      assert.deepEqual(await snapshot(), after);
      await refresh();
      const gone = await inspect('Read local payload status');
      assert.equal(gone.localPayload, 'DELETED');
      assert.deepEqual(gone.blockers, ['ALREADY_DELETED']);
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({
        path: join(artifacts, 'rejection-deletion-desktop.png'),
        fullPage: true,
      });
      await maker.setViewportSize({ width: 360, height: 800 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({
        path: join(artifacts, 'rejection-deletion-reflow.png'),
        fullPage: true,
      });
      if (ownPolicy) {
        const retired = await governed(
          'Retire a retention policy version',
          { 'Resource reference': policy.retentionPolicyId, 'Expected revision': '1' },
          `Retire only this acceptance's own policy ${scope.streamId}.`,
        );
        assert.equal(retired.completed.result.state, 'RETIRED');
      }
    },
  );
  // A fresh real session with explicit authority in a second privacy domain
  // proves same-Participant isolation, rather than just missing assignments.
  const foreignPrivacy = '018f0000-0000-7000-8000-000000006201';
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: artifacts,
      artifacts: join(artifacts, 'foreign-privacy'),
      route: '/operate/evidence',
      privacyDomainId: foreignPrivacy,
    },
    async ({ maker }) => {
      const api = await publicEvidenceReader(maker, secretRoot, participantId, foreignPrivacy);
      for (const path of [
        `evidence-records/urn:openpc:resource:${chosenRecord.evidence_id}/deletion-plan`,
        `evidence-deletions/${result.deletionJobId}`,
      ]) {
        const denied = await api(path);
        assert.equal(denied.status, 404);
        const body = JSON.stringify(denied.body);
        assert.equal(body.includes(result.receiptDigest), false);
        assert.equal(body.includes(chosenRecord.evidence_id), false);
      }
    },
  );
  process.stdout.write(
    'OPENPC_REJECTION_DELETION|PASS|real-signed-source|command-binding|all-records|mixed-unknown-confirmation-reorg-denied|wrong-key|foreign-participant|same-participant-foreign-privacy|signer-rollback|post-signing-rollback|later-reservation-contention|independent-approval|lost-response|restart|archive-and-original-preserved|keyboard|axe|reflow\n',
  );
} finally {
  await worker.end();
  await admin.end();
}
