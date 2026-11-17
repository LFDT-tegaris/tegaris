import assert from 'node:assert/strict';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { evidenceScope } from '../../../services/control-api/src/evidence/segment.ts';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { decodeAdmittedReceipt } from '../../../packages/security-kernel/src/index.ts';
import { readWorkbenchApproval } from './transaction-workbench-browser.mjs';

export async function prepareRetentionSearchBrowser(ownerRoot) {
  assert.equal(await realpath(ownerRoot), ownerRoot);
  assert.ok((await lstat(join(ownerRoot, '.openpc-local-runtime-owner'))).isFile());
  const secretRoot = join(ownerRoot, 'secrets');
  const evidenceRoot = join(ownerRoot, 'evidence/retention-search-runtime');
  const dataRoot = join(ownerRoot, 'data');
  const sourceRoot = join(dataRoot, 'retention-search');
  const businessConfiguration = join(sourceRoot, 'worker.json');
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const privacyDomainId = '018f0021-0000-7000-8000-000000000201';
  const scope = {
    ...evidenceScope.parse({ participantId, privacyDomainId, streamId: 'retention-policy-search' }),
    source: 'BUSINESS_TRANSITION',
    activeKeyId: 'retention-search-source',
    keys: [{ keyId: 'retention-search-source', keyFile: join(sourceRoot, 'key') }],
    retentionSeconds: 60,
    capacityBytes: 16 * 1024 * 1024,
  };
  const configuration = {
    database: {
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_local_control_worker',
      passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
    },
    vaultDirectory: join(sourceRoot, 'vault'),
    sinkId: 'retention-policy-search',
    scopes: [scope],
  };
  try {
    const retained = JSON.parse(await readFile(businessConfiguration, 'utf8'));
    assert.deepEqual(
      retained,
      configuration,
      'Preserve the original source scope, key and archive',
    );
    assert.equal((await readFile(scope.keys[0].keyFile)).length, 32);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    // Exclusive directory creation refuses incomplete retained configuration.
    await mkdir(sourceRoot, { mode: 0o700 });
    await writeFile(scope.keys[0].keyFile, randomBytes(32), { mode: 0o600, flag: 'wx' });
    await writeFile(businessConfiguration, JSON.stringify(configuration), {
      mode: 0o600,
      flag: 'wx',
    });
  }
  return {
    secretRoot,
    evidenceRoot,
    dataRoot,
    participantId,
    privacyDomainId,
    businessConfiguration,
  };
}

/** Isolated initial-trust scope, actual public policy producers and original
 * packaged custody. Never seed policy/approval/effect or replay a retired source. */
export async function retentionSearchProjectionBrowser({
  maker,
  api,
  govern,
  refresh,
  recordItem,
  inspect,
  verify,
  continueFrom,
  pool,
  scoped,
  streamId,
  configuration,
  runWorker,
  command,
  artifacts,
  foreignPrivacyDomainId,
}) {
  const urn = (id) => `urn:openpc:resource:${id}`;
  const query = async (sql, values = scoped) => (await pool.query(sql, values)).rows;
  assert.equal(configuration.scopes.length, 1);
  assert.equal(configuration.scopes[0].source, 'BUSINESS_TRANSITION');
  assert.equal(configuration.scopes[0].streamId, streamId);
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_projection_retirement
    where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
        [...scoped, streamId],
      )
    )[0].n,
    0,
    'A consumed retirement requires original readback continuation, never another source selection',
  );
  const view = await refresh();
  assert.equal(view.retentionPoliciesUnavailable, false);
  assert.equal(view.retentionPolicies.nextCursor, null);
  assert.ok(
    view.retentionPolicies.items.every((p) =>
      ['SEARCH_PROJECTION', 'AUDIT_EVIDENCE'].includes(p.dataClass),
    ),
    'Use the isolated retention-search scope',
  );
  for (const dataClass of ['SEARCH_PROJECTION', 'AUDIT_EVIDENCE']) {
    const prior = view.retentionPolicies.items.filter((p) => p.dataClass === dataClass);
    if (prior.length) {
      assert.equal(prior.length, 1);
      assert.deepEqual(
        Object.fromEntries(
          [
            'state',
            'retentionPeriodMs',
            'localGraceMs',
            'sinkQuorum',
            'deletionMode',
            'makerCheckerRequired',
          ].map((key) => [key, prior[0][key]]),
        ),
        {
          state: 'ACTIVE',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: dataClass === 'AUDIT_EVIDENCE' ? 'ROW_DELETE' : 'PROJECTION_DELETE',
          makerCheckerRequired: true,
        },
      );
    } else {
      await govern(
        'Activate a retention policy version',
        {
          'Retained data class': dataClass,
          'Retention policy version': '1.0.0',
          'Retention period in milliseconds': '0',
          'Local grace in milliseconds': '0',
          'Required durable sink acknowledgements': '1',
          'Deletion mode': dataClass === 'AUDIT_EVIDENCE' ? 'ROW_DELETE' : 'PROJECTION_DELETE',
          'Require independent deletion approval': 'true',
        },
        'Govern this isolated retention-policy search projection case.',
      );
    }
  }
  await runWorker();
  const records = await query(
    `select c.evidence_id::text id,c.record_id,c.receipt_digest,
    c.segment_id::text segment_id,c.sequence::text sequence,a.receipt_id::text receipt_id,a.receipt_cbor,a.cose_sign1
    from control.evidence_catalogue c join control.evidence_record e
      on e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id and e.evidence_record_id::text=c.record_id
    join control.audit_occurrence a on a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id
      and a.receipt_id=e.receipt_id and a.receipt_digest=e.receipt_digest
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 order by c.record_id`,
    [...scoped, streamId],
  );
  assert.equal(records.length, 2, 'Two actual public retention activations are required');
  for (const row of records)
    assert.equal(
      decodeAdmittedReceipt(row.receipt_cbor).transitionProfileId,
      'pc.control.retention-policy.activate',
    );
  const original = async () => ({
    receipts: await query(
      `select receipt_id,receipt_cbor,cose_sign1,receipt_digest from control.audit_occurrence
      where participant_id=$1 and privacy_domain_id=$2 and receipt_id::text=any($3::text[]) order by receipt_id`,
      [...scoped, records.map((r) => r.receipt_id)],
    ),
    policies: await query(
      `select * from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 order by retention_policy_id`,
    ),
    checkpoints: await query(
      `select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by through_sequence`,
      [...scoped, streamId],
    ),
  });
  const before = await original();
  assert.equal(before.receipts.length, 2);
  const vault = await LocalEvidenceVault.open(configuration.vaultDirectory, configuration.sinkId);
  const archive = await Promise.all(before.checkpoints.map((r) => vault.read(r.receipt.object)));
  assert.ok(archive.length > 0);
  const plan = async (row) => {
    const response = await api(`evidence-records/${urn(row.id)}/search-projection-deletion-plan`);
    assert.equal(response.status, 200);
    return projectionDeletionPlan.parse(response.body);
  };
  assert.ok((await plan(records[0])).blockers.includes('REFERENCES'));
  const hold = await govern(
    'Preserve evidence under a hold',
    {
      'Hold kind': 'LEGAL',
      'Evidence to preserve': 'DIGEST',
      'Receipt digest': records[0].receipt_digest,
    },
    'Preserve the exact signed retention-policy source before its search projection retirement.',
  );
  assert.ok((await plan(records[0])).blockers.includes('ACTIVE_HOLD'));
  await govern(
    'Release an evidence hold',
    { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
    'Release the exact isolated retention-policy preservation hold.',
  );
  // The storage owner's original sixty-second promise remains unchanged.
  for (const segmentId of new Set(records.map((r) => r.segment_id))) {
    const row = records.find((r) => r.segment_id === segmentId);
    await expect
      .poll(
        async () => {
          const response = await api(`evidence-records/${urn(row.id)}/deletion-plan`);
          assert.equal(response.status, 200);
          assert.ok(response.body.blockers.every((b) => b === 'RETENTION_NOT_ELAPSED'));
          return response.body.eligible;
        },
        { timeout: 65000, intervals: [1000] },
      )
      .toBe(true);
    await govern(
      'Delete a local evidence payload',
      { 'Evidence record reference': urn(row.id) },
      'Clear this local ciphertext copy through its independent governed deletion owner.',
    );
  }
  const item = await recordItem(records[0]);
  const selected = projectionDeletionPlan.parse(
    await inspect(
      item.getByRole('button', {
        name: `Review search projection deletion for sequence ${records[0].sequence}`,
        exact: true,
      }),
    ),
  );
  assert.equal(selected.eligible, true);
  assert.equal(selected.selection.sourceKind, 'RETENTION_POLICY_CATALOGUE');
  assert.equal(selected.selection.targets.length, 2);
  await maker.getByRole('button', { name: 'Prepare first deletion batch', exact: true }).click();
  const first = await govern(
    'Delete search projections',
    { 'Starting catalogue evidence reference': urn(records[0].id) },
    'Retire the first exact retention-policy search projection, preserving its signed source.',
    true,
  );
  await verify(first.completed.result);
  assert.equal((await continueFrom(first.completed.result)).continuationState, 'READY');
  const second = await govern(
    'Continue projection deletion',
    { 'Previous projection deletion result': first.completed.result.deletionJobId },
    'Continue only the original fixed retention-policy search selection.',
  );
  await verify(second.completed.result);
  assert.equal((await continueFrom(second.completed.result)).continuationState, 'COMPLETE');
  for (const result of [first, second]) {
    const receipt = (
      await query(
        `select receipt_cbor from control.audit_occurrence
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
        [...scoped, result.completed.result.operationId],
      )
    )[0];
    assert.equal(decodeAdmittedReceipt(receipt.receipt_cbor).transitionProfileVersion, 2);
  }
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
  assert.deepEqual(
    (await readWorkbenchApproval(maker, first.approvalId)).result,
    first.completed.result,
  );
  await runWorker();
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_catalogue
    where participant_id=$1 and privacy_domain_id=$2 and evidence_id=any($3::uuid[])`,
        [...scoped, records.map((r) => r.id)],
      )
    )[0].n,
    0,
  );
  const after = await original();
  assert.deepEqual(after.receipts, before.receipts);
  assert.deepEqual(after.policies, before.policies);
  for (const [index, row] of before.checkpoints.entries())
    assert.deepEqual(await vault.read(row.receipt.object), archive[index]);
  const denied = await api(
    `evidence-deletions/${second.completed.result.deletionJobId}/projection-continuation-plan`,
    { privacyDomainId: foreignPrivacyDomainId },
  );
  assert.ok(denied.status >= 400);
  assert.equal(JSON.stringify(denied.body).includes(second.completed.result.receiptDigest), false);
  await continueFrom(second.completed.result);
  await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
  await maker.keyboard.press('Enter');
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText('Selection complete.');
  await maker.setViewportSize({ width: 390, height: 880 });
  assert.equal(
    await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
  );
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await maker.screenshot({
    path: join(artifacts, 'retention-policy-search-retired.png'),
    fullPage: true,
  });
  process.stdout.write(
    'OPENPC_RETENTION_SEARCH_BROWSER|PASS|public-source|hold|physical-reference-clearance|profile-v2|signed-continuation|lost-response|restart-no-resurrection|original-cose-and-archive|privacy|keyboard|reflow|axe\n',
  );
}
