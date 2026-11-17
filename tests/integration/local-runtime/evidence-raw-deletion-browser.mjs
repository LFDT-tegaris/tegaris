import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import {
  transactionCandidate,
  transactionOperation,
} from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import {
  transactionForms,
  transactionFields,
} from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { LocalProtectedProofVault } from '../../../services/control-api/src/evidence/protected-vault.ts';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { protectedRemoteBrowser } from './evidence-protected-remote-browser.mjs';
const remoteMode = process.argv.includes('--remote');
const actorMode = remoteMode
  ? 'bootstrap-evidence-remote-protected'
  : 'bootstrap-evidence-raw-deletion';
const rawPolicy = {
  dataClass: 'RAW_SOURCE_BODY',
  policyVersion: remoteMode ? '1.0.1' : '1.0.0',
  retentionPeriodMs: '0',
  localGraceMs: '0',
  sinkQuorum: 1,
  deletionMode: 'ROW_DELETE',
  makerCheckerRequired: true,
};
const policyFields = {
  'Retained data class': rawPolicy.dataClass,
  'Retention policy version': rawPolicy.policyVersion,
  'Retention period in milliseconds': rawPolicy.retentionPeriodMs,
  'Local grace in milliseconds': rawPolicy.localGraceMs,
  'Required durable sink acknowledgements': String(rawPolicy.sinkQuorum),
  'Deletion mode': rawPolicy.deletionMode,
  'Require independent deletion approval': String(rawPolicy.makerCheckerRequired),
};
function preflight() {
  const participant = process.argv[6] ?? '018f0000-0000-7000-8000-000000000101';
  const privacy = process.argv[7] ?? '018f0000-0000-7000-8000-000000007201';
  const prepared = JSON.parse(
    execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        'preflight-only',
        'preflight-only',
        participant,
        actorMode,
        privacy,
        '018f0000-0000-7000-8000-000000000201',
        '--preflight',
      ],
      { encoding: 'utf8', timeout: 15000 },
    ),
  );
  assert.equal(prepared.participantId, participant);
  assert.ok(prepared.privacyDomainIds.includes(privacy));
  transactionCandidate(
    'retention-policy',
    transactionFields(
      'retention-policy',
      Object.fromEntries(
        Object.entries(policyFields).map(([label, value]) => [
          transactionForms['retention-policy'].fields.find((field) => field.label === label).name,
          value,
        ]),
      ),
    ),
    'Review raw proof retention.',
    participant,
  );
  for (const label of Object.keys(policyFields))
    assert.ok(transactionForms['retention-policy'].fields.some((field) => field.label === label));
  for (const kind of ['evidence-deletion-raw', 'evidence-deletion-raw-continuation']) {
    const op = transactionOperation(kind);
    assert.equal(op.actionIntentId, 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1');
    assert.equal(op.createPath, '/api/v1/evidence-deletions/raw-batches');
    assert.equal(op.binding.catalogOperationId, 'CFG-OP-DELETE-RAW-PROOF-BATCH');
  }
  process.stdout.write(
    'OPENPC_RAW_DELETION_PREFLIGHT|PASS|actual-policy|review-fields|exact-action-and-resource\n',
  );
}
preflight();
if (process.argv.includes('--preflight')) process.exit(0);
const exec = promisify(execFile);
const [secretRoot, evidenceRoot, dataRoot, composeJson, participantId, privacyDomainId] =
  process.argv.slice(2);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
assert.ok(
  secretRoot && evidenceRoot && dataRoot && composeJson && participantId && privacyDomainId,
);
const compose = JSON.parse(composeJson);
assert.equal(compose[0], 'docker');
assert.equal(compose[1], 'compose');
const command = (args) =>
  exec(compose[0], [...compose.slice(1), ...args], { timeout: 90000, maxBuffer: 1048576 });
const root = join(
    evidenceRoot,
    remoteMode ? 'remote-proof-deletion-browser' : 'raw-proof-deletion-browser',
  ),
  artifacts = join(root, new Date().toISOString().replaceAll(':', '-'));
await mkdir(artifacts, { recursive: true, mode: 0o700 });
if (
  !(await access(join(root, 'deployment-intent-actors.json')).then(
    () => true,
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return false;
    },
  ))
)
  await exec(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/deployment-intent-actors.mjs',
      secretRoot,
      root,
      participantId,
      actorMode,
      privacyDomainId,
      '018f0000-0000-7000-8000-000000000201',
    ],
    { timeout: 30000, maxBuffer: 65536 },
  );
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const time = (offset) =>
  new Date(Date.now() + offset).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
const container = (await command(['ps', '-q', 'control-api'])).stdout.trim();
const image = JSON.parse(
  (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
)[0];
assert.equal(JSON.parse((await exec('docker', ['inspect', container])).stdout)[0].Image, image.Id);
const executable = join(artifacts, 'evidence-worker.mjs');
await exec('docker', ['cp', `${container}:/app/evidence-worker.mjs`, executable]);
const sourceRoot = join(dataRoot, `raw-deletion-source-${uuidv7()}`);
await mkdir(sourceRoot, { mode: 0o700 });
await writeFile(join(sourceRoot, 'encryption.key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
const streamId = `raw-deletion-authentication-${uuidv7()}`,
  configuration = join(artifacts, 'worker-config.json');
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
    sinkId: `raw-deletion-authentication-${uuidv7()}`,
    protectedScopes: [{ participantId, privacyDomainId }],
    scopes: [
      {
        participantId,
        privacyDomainId,
        streamId,
        source: 'AUTHENTICATION',
        activeKeyId: 'source-test',
        keys: [{ keyId: 'source-test', keyFile: join(sourceRoot, 'encryption.key') }],
        retentionSeconds: 86400,
        capacityBytes: 16 * 1024 * 1024,
      },
    ],
  }),
  { mode: 0o600 },
);
const runWorker = () =>
  exec(process.execPath, [executable, '--once'], {
    env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
    timeout: 20000,
    maxBuffer: 65536,
  });
const endpoint = '/api/v1/ui/evidence-workbench';
let remote;
try {
  if (remoteMode)
    remote = await protectedRemoteBrowser({ pool, configuration, directory: artifacts });
  const trust = await pool.query(
    "select count(*)::int n from control.business_signing_selection s join control.business_transition_profile p using(profile_digest) where s.participant_id=$1 and s.privacy_domain_id=$2 and p.profile_id='pc.control.evidence-deletion.raw-proof'",
    [participantId, privacyDomainId],
  );
  if (trust.rows[0].n === 0)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/business-signing-bootstrap.mjs',
        secretRoot,
        participantId,
        privacyDomainId,
        '--raw-deletion-trust',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: root,
      artifacts,
      route: '/operate/evidence',
      privacyDomainId,
      reuseSessions: true,
    },
    async ({ maker, checker, actors }) => {
      const govern = (label, fields, reason, loseExecutionResponse = false) =>
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
        const pending = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === endpoint &&
            !new URL(r.url()).search &&
            r.request().method() === 'GET',
        );
        await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
        const response = await pending;
        assert.equal(response.status(), 200);
        return response.json();
      };
      const inspect = async (button) => {
        const pending = maker.waitForResponse(
          (r) =>
            new URL(r.url()).pathname === endpoint &&
            !!new URL(r.url()).search &&
            r.request().method() === 'GET',
        );
        await button.click();
        const response = await pending;
        assert.equal(response.status(), 200);
        return (await response.json()).plan;
      };
      const activate = await govern(
        'Activate a retention policy version',
        policyFields,
        'Establish independent raw-copy retention for the deletion journey.',
      );
      assert.equal(activate.completed.result.dataClass, 'RAW_SOURCE_BODY');
      const sourceCount = (
        await pool.query(
          'select count(*)::int n from control.authentication_occurrence where participant_id=$1 and privacy_domain_id=$2',
          [participantId, privacyDomainId],
        )
      ).rows[0].n;
      let selected;
      for (let batch = 0; batch <= Math.ceil(sourceCount / 8); batch++) {
        await runWorker();
        selected = (
          await pool.query(
            `select c.evidence_id::text id,a.operation_id::text operation_id from control.evidence_catalogue c join control.authentication_occurrence a on a.occurrence_id::text=c.record_id where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION' and a.principal_id=$4 order by c.sequence desc limit 1`,
            [participantId, privacyDomainId, streamId, actors.maker.principalId],
          )
        ).rows[0];
        if (selected) break;
      }
      assert.ok(selected, 'Actual policy governance authentication reaches source custody');
      const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
      const source = await api(
        `evidence-records/urn:openpc:resource:${selected.id}/protected-proof-source`,
      );
      assert.equal(source.status, 200);
      assert.equal(source.body.operationId, selected.operation_id);
      const objects = [];
      const retainUntil = time(remoteMode ? 90000 : 40000);
      for (let i = 0; i < 2; i++) {
        const retained = await govern(
          'Retain a protected Identity proof',
          {
            'Authentication evidence reference': `urn:openpc:resource:${selected.id}`,
            'Protected retention purpose': 'Verify class-specific retention',
            'Case reference': `raw-${selected.id}-${i}`,
            'Retain until (UTC, six fractional digits)': retainUntil,
          },
          `Retain independently reviewable encrypted copy ${i}.`,
        );
        assert.deepEqual(retained.review.candidate.candidate.source, source.body);
        objects.push(retained.completed.result);
      }
      objects.sort((a, b) => a.objectRef.localeCompare(b.objectRef));
      await refresh();
      await maker
        .getByLabel('Retained protected object reference', { exact: true })
        .fill(objects[0].objectRef);
      let plan = await inspect(
        maker.getByRole('button', { name: 'Check protected proof deletion', exact: true }),
      );
      assert.ok(plan.blockers.includes('SINK_QUORUM'));
      assert.equal(plan.eligible, false);
      const copyCount = (
        await pool.query(
          'select count(*)::int n from control.protected_proof_payload where participant_id=$1 and privacy_domain_id=$2',
          [participantId, privacyDomainId],
        )
      ).rows[0].n;
      if (remote) {
        remote.external.faults.dropPutResponse = true;
        await assert.rejects(
          runWorker,
          (error) => error.code === 1 && error.stderr.includes('remote-archive'),
        );
        assert.equal(remote.external.counts.puts, 1);
      }
      let checkpoints = [];
      for (let batch = 0; batch < copyCount; batch++) {
        await runWorker();
        checkpoints = (
          await pool.query(
            'select receipt from control.protected_proof_checkpoint where participant_id=$1 and privacy_domain_id=$2 and object_id=any($3::uuid[]) order by object_id',
            [participantId, privacyDomainId, objects.map((o) => o.objectRef.slice(-36))],
          )
        ).rows;
        if (checkpoints.length === 2) break;
      }
      assert.equal(checkpoints.length, 2);
      const config = JSON.parse(await readFile(configuration, 'utf8'));
      const vault = remote
        ? null
        : await LocalProtectedProofVault.open(config.vaultDirectory, config.sinkId);
      if (remote) {
        await remote.verify(checkpoints, objects);
        assert.equal(remote.external.counts.puts, 2);
      } else
        for (const row of checkpoints)
          assert.deepEqual(await vault.verify(row.receipt.object), row.receipt);
      const hold = await govern(
        'Preserve evidence under a hold',
        {
          'Hold kind': 'INCIDENT',
          'Evidence to preserve': 'DIGEST',
          'Receipt digest': remote ? objects[0].objectDigest : source.body.sourceReceiptDigest,
        },
        `Preserve the source of ${objects[0].objectRef}.`,
      );
      if (remote) {
        await refresh();
        await expect(
          maker
            .getByRole('region', { name: 'Preservation holds', exact: true })
            .locator('li')
            .filter({ hasText: hold.completed.result.holdId }),
        ).toContainText('PENDING');
        for (let i = 0; i < objects.length; i++) await runWorker();
        assert.equal(remote.external.counts.puts, 2);
      }
      await refresh();
      if (remote)
        await expect(
          maker
            .getByRole('region', { name: 'Preservation holds', exact: true })
            .locator('li')
            .filter({ hasText: hold.completed.result.holdId }),
        ).toContainText('VERIFIED');
      await maker
        .getByLabel('Retained protected object reference', { exact: true })
        .fill(objects[0].objectRef);
      plan = await inspect(
        maker.getByRole('button', { name: 'Check protected proof deletion', exact: true }),
      );
      assert.ok(plan.blockers.includes('ACTIVE_HOLD'));
      await expect(
        maker.getByRole('button', { name: 'Prepare first deletion batch', exact: true }),
      ).toHaveCount(0);
      await govern(
        'Release an evidence hold',
        { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
        'Release this exact raw-source preservation rule.',
      );
      if (remote) {
        await refresh();
        await expect(
          maker
            .getByRole('region', { name: 'Preservation holds', exact: true })
            .locator('li')
            .filter({ hasText: hold.completed.result.holdId }),
        ).toContainText('PENDING');
        for (let i = 0; i < objects.length; i++) await runWorker();
        assert.equal(remote.external.counts.puts, 2);
      }
      await refresh();
      if (remote)
        await expect(
          maker
            .getByRole('region', { name: 'Preservation holds', exact: true })
            .locator('li')
            .filter({ hasText: hold.completed.result.holdId }),
        ).toContainText('VERIFIED');
      await maker
        .getByLabel('Retained protected object reference', { exact: true })
        .fill(objects[0].objectRef);
      plan = await inspect(
        maker.getByRole('button', { name: 'Check protected proof deletion', exact: true }),
      );
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
          { timeout: remoteMode ? 95000 : 45000, intervals: [1000] },
        )
        .toBe(true);
      assert.equal(plan.selection.targets.length, 2);
      assert.equal(plan.selection.dataClass, 'RAW_SOURCE_BODY');
      const before = (
        await pool.query(
          'select object_id::text,length(ciphertext)::int bytes from control.protected_proof_payload where participant_id=$1 and privacy_domain_id=$2 and object_id=any($3::uuid[]) order by object_id',
          [participantId, privacyDomainId, objects.map((o) => o.objectRef.slice(-36))],
        )
      ).rows;
      assert.equal(before.length, 2);
      await maker
        .getByRole('button', { name: 'Prepare first deletion batch', exact: true })
        .click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion-raw',
      );
      const first = await govern(
        'Delete retained protected proof ciphertext',
        { 'Starting protected object reference': objects[0].objectRef },
        'Delete the first exact local raw copy with independent approval.',
        true,
      );
      const firstResult = first.completed.result;
      assert.equal(firstResult.selection.batchIndex, 0);
      assert.equal(firstResult.deletedBytes, String(before[0].bytes));
      assert.deepEqual(firstResult.selection.targets, plan.selection.targets);
      const verify = async (result) => {
        const r = (
          await pool.query(
            "select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.aggregate_type='evidence-deletion'",
            [participantId, privacyDomainId, result.operationId],
          )
        ).rows;
        assert.equal(r.length, 1);
        assert.ok(verifyReceiptCose(r[0].public_key_spki_der, r[0].receipt_cbor, r[0].cose_sign1));
        assert.equal(
          decodeAdmittedReceipt(r[0].receipt_cbor).transitionProfileId,
          'pc.control.evidence-deletion.raw-proof',
        );
      };
      await verify(firstResult);
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
      assert.deepEqual((await readWorkbenchApproval(maker, first.approvalId)).result, firstResult);
      const continueFrom = async (result) => {
        const view = await refresh();
        const index = view.deletions.items.findIndex(
          (item) => item.deletionJobId === result.deletionJobId,
        );
        assert.ok(index >= 0);
        return inspect(
          maker
            .getByRole('region', { name: 'Local deletion results', exact: true })
            .getByRole('listitem')
            .nth(index)
            .getByRole('button', { name: 'Read signed continuation', exact: true }),
        );
      };
      const next = await continueFrom(firstResult);
      assert.equal(next.selection.batchIndex, 1);
      assert.equal(next.selection.priorCursor.receiptDigest, firstResult.receiptDigest);
      await maker.getByRole('button', { name: 'Prepare next deletion batch', exact: true }).click();
      await expect(maker.getByLabel('Request type', { exact: true })).toHaveValue(
        'evidence-deletion-raw-continuation',
      );
      const second = await govern(
        'Continue protected proof deletion',
        { 'Previous protected proof deletion result': firstResult.deletionJobId },
        'Delete the next object fixed by the original signed cursor.',
      );
      const secondResult = second.completed.result;
      await verify(secondResult);
      assert.equal(secondResult.deletedBytes, String(before[1].bytes));
      assert.equal((await continueFrom(secondResult)).continuationState, 'COMPLETE');
      assert.equal(
        (
          await pool.query(
            'select count(*)::int n from control.protected_proof_payload where participant_id=$1 and privacy_domain_id=$2 and object_id=any($3::uuid[])',
            [participantId, privacyDomainId, objects.map((o) => o.objectRef.slice(-36))],
          )
        ).rows[0].n,
        0,
      );
      for (const object of objects)
        assert.deepEqual((await api(`protected-proofs/${object.objectRef}`)).body, object);
      assert.deepEqual(
        (await api(`evidence-records/urn:openpc:resource:${selected.id}/protected-proof-source`))
          .body,
        source.body,
      );
      if (remote) {
        await remote.verify(checkpoints, objects);
        const late = await govern(
          'Preserve evidence under a hold',
          {
            'Hold kind': 'INCIDENT',
            'Evidence to preserve': 'DIGEST',
            'Receipt digest': objects[0].objectDigest,
          },
          'Preserve the existing remote copies after local ciphertext retirement.',
        );
        assert.equal(late.completed.result.coverage, 'PENDING');
        remote.external.faults.dropHoldResponse = true;
        await assert.rejects(
          runWorker,
          (error) => error.code === 1 && error.stderr.includes('remote-holds'),
        );
        const holds = remote.external.counts.holds;
        await runWorker();
        assert.equal(remote.external.counts.holds, holds);
        await runWorker();
        await refresh();
        const item = maker
          .getByRole('region', { name: 'Preservation holds', exact: true })
          .locator('li')
          .filter({ hasText: late.completed.result.holdId });
        await expect(item).toContainText('VERIFIED');
        assert.equal(remote.external.counts.puts, 2);
      } else
        for (const row of checkpoints)
          assert.deepEqual(await vault.verify(row.receipt.object), row.receipt);
      await runWorker();
      assert.equal(
        (
          await pool.query(
            'select count(*)::int n from control.protected_proof_payload where participant_id=$1 and privacy_domain_id=$2 and object_id=any($3::uuid[])',
            [participantId, privacyDomainId, objects.map((o) => o.objectRef.slice(-36))],
          )
        ).rows[0].n,
        0,
      );
      for (const override of [
        { participantId: uuidv7() },
        { privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
      ]) {
        const denied = await api(
          `evidence-deletions/${secondResult.deletionJobId}/raw-continuation-plan`,
          override,
        );
        assert.ok(denied.status >= 400);
        assert.equal(JSON.stringify(denied.body).includes(secondResult.receiptDigest), false);
      }
      if (remote) {
        // The hold refresh deliberately clears the prior deletion selection.
        // Restore it through its signed public result before keyboard readback.
        assert.equal((await continueFrom(secondResult)).continuationState, 'COMPLETE');
      }
      await maker
        .getByRole('button', { name: 'Refresh deletion eligibility', exact: true })
        .focus();
      await maker.keyboard.press('Enter');
      await expect(
        maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
      ).toContainText('Selection complete.');
      assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
      await maker.screenshot({ path: join(artifacts, 'raw-deletion-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 880 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        true,
      );
      assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
      await maker.screenshot({ path: join(artifacts, 'raw-deletion-reflow.png'), fullPage: true });
      if (remote)
        process.stdout.write(
          'OPENPC_PROTECTED_REMOTE_BROWSER|PASS|signed-remote-custody|lost-put-ack|lost-hold-ack|no-repeat-put|late-hold-after-local-deletion|no-resurrection|provider-not-qualified\n',
        );
      process.stdout.write(
        'OPENPC_RAW_DELETION_BROWSER|PASS|real-auth-source|raw-policy|hold-release|exact-packaged-custody|two-physical-effects|independent-approval|fresh-step-up|signed-cursor|lost-response|restart|privacy|keyboard|axe|reflow\n',
      );
    },
  );
} finally {
  await remote?.close();
  await pool.end();
}
