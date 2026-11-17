import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { governThroughWorkbench, readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { retryDeletion, withDeletionOutboxFault } from './evidence-rejection-deletion-checks.mjs';
import { observeFactRetirementOutbox as observeRetirementOutbox } from './evidence-fact-retirement-checks.mjs';
import { withDeploymentRetirementFenceLoss } from './evidence-deployment-retirement-checks.mjs';
import { chooseContext } from './evidence-source-holds.mjs';

/** One actual finalized deployment at the existing public journey checkpoint.
 * Its later reorg still runs through that journey after this local retirement. */
export async function deploymentProjectionRetirementBrowser({
  maker,
  checker,
  actors,
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
  secretRoot,
  artifacts,
  command,
  runWorker,
  preserve,
  foreignPrivacyDomainId,
  deploymentReadback = false,
  deploymentResumeFinalized = false,
}) {
  const urn = (id) => `urn:openpc:resource:${id}`;
  const query = async (sql, values = scoped) => (await pool.query(sql, values)).rows;
  const rows = await query(
    `select c.evidence_id::text id,c.record_id,c.receipt_digest,c.sequence::text sequence,
    p.projection,p.projection_digest from control.evidence_catalogue c join control.evidence_deployment_provenance p
    using(participant_id,privacy_domain_id,stream_id,record_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 order by c.record_id`,
    [...scoped, streamId],
  );
  assert.ok(rows.length > 1, 'Real uncertainty, reorg and finalized observations are required');
  const canonical = async () => ({
    results: await query(
      'select * from control.deployment_result where participant_id=$1 and privacy_domain_id=$2 order by command_id,sequence',
    ),
    reservations: await query(
      'select * from control.deployment_address_reservation where participant_id=$1 and privacy_domain_id=$2 order by command_id',
    ),
    lineage: await query(
      'select * from control.evidence_deployment_lineage where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id',
      [...scoped, streamId],
    ),
  });
  const snapshot = async () => ({
    projections: await query(
      'select * from control.evidence_deployment_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id',
      [...scoped, streamId],
    ),
    retirements: await query(
      'select * from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id',
      [...scoped, streamId],
    ),
    jobs: await query(
      'select * from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by deletion_job_id',
      [...scoped, streamId],
    ),
  });
  const original = await canonical(),
    before = await snapshot();
  const plan = async (row) => {
    const response = await api(
      `evidence-records/${urn(row.id)}/normalized-projection-deletion-plan`,
    );
    assert.equal(response.status, 200);
    return projectionDeletionPlan.parse(response.body);
  };
  if (deploymentReadback) {
    const retired = await query(
      `select c.evidence_id::text id,c.receipt_digest,r.deletion_job_id::text job
      from control.evidence_projection_retirement r join control.evidence_catalogue c
       using(participant_id,privacy_domain_id,stream_id,record_id)
      where r.participant_id=$1 and r.privacy_domain_id=$2 and r.stream_id=$3
       and r.data_class='NORMALIZED_JSON_PROJECTION'`,
      [...scoped, streamId],
    );
    assert.equal(retired.length, 1);
    const result = await api(`evidence-deletions/${urn(retired[0].job)}`);
    assert.equal(result.status, 200);
    await verify(result.body);
    assert.equal((await continueFrom(result.body)).continuationState, 'COMPLETE');
    const historical = await api(`evidence-records/${urn(retired[0].id)}/provenance`);
    assert.equal(historical.status, 200);
    assert.equal(historical.body.status, 'PROJECTION_RETIRED');
    assert.equal(historical.body.deployment, null);
    const reorg = rows.find((r) => r.projection.historical.finality === 'REORG');
    assert.ok(
      reorg,
      'The normal later reorg must reach its actual signed source and original stream',
    );
    const item = await recordItem(reorg);
    const denied = projectionDeletionPlan.parse(
      await inspect(
        item.getByRole('button', {
          name: `Review normalized projection deletion for sequence ${reorg.sequence}`,
          exact: true,
        }),
      ),
    );
    assert.equal(denied.eligible, false);
    assert.ok(denied.blockers.includes('REORG_FENCED'));
    const panel = maker.getByRole('region', { name: 'Local deletion eligibility', exact: true });
    await expect(panel).toContainText(
      'A reorg or invalidated deployment observation still protects this source.',
    );
    await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
    await maker.keyboard.press('Enter');
    await expect(panel).toContainText(
      'A reorg or invalidated deployment observation still protects this source.',
    );
    assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
    await maker.screenshot({
      path: join(artifacts, 'deployment-reorg-retirement-denial.png'),
      fullPage: true,
    });
    await preserve();
    assert.deepEqual(await canonical(), original);
    assert.deepEqual(await snapshot(), before);
    process.stdout.write(
      'OPENPC_DEPLOYMENT_RETIREMENT_REORG_READBACK|PASS|actual-later-reorg|original-retirement-preserved|current-denial-rendered|no-new-effect|keyboard|axe\n',
    );
    return;
  }
  const policies = (await refresh()).retentionPolicies.items.filter(
    (p) => p.dataClass === 'NORMALIZED_JSON_PROJECTION',
  );
  if (deploymentResumeFinalized && policies.length) {
    assert.equal(policies.length, 1);
    const retained = policies[0];
    for (const [key, value] of Object.entries({
      policyVersion: '1.0.0',
      retentionPeriodMs: '0',
      localGraceMs: '0',
      sinkQuorum: 1,
      deletionMode: 'PROJECTION_DELETE',
      makerCheckerRequired: true,
    }))
      assert.equal(retained[key], value, `Retained policy ${key}`);
    assert.equal(before.jobs.length, 0, 'Resume cannot repeat a physical retirement');
    assert.equal(before.retirements.length, 0);
  } else {
    assert.equal(policies.length, 0, 'The clean checkpoint has an independent class policy');
    await govern(
      'Activate a retention policy version',
      {
        'Retained data class': 'NORMALIZED_JSON_PROJECTION',
        'Retention policy version': '1.0.0',
        'Retention period in milliseconds': '0',
        'Local grace in milliseconds': '0',
        'Required durable sink acknowledgements': '1',
        'Deletion mode': 'PROJECTION_DELETE',
        'Require independent deletion approval': 'true',
      },
      'Govern retirement of the normalized deployment observation while preserving original signed history.',
    );
  }
  const eligible = [];
  for (const row of rows) {
    const current = await plan(row);
    if (current.eligible) eligible.push(row);
    else
      assert.ok(
        current.blockers.some(
          (b) =>
            ['REORG_FENCED', 'UNRESOLVED_OPERATION', 'REFERENCES'].includes(b) ||
            (b === 'UNSUPPORTED_SOURCE' &&
              row.projection.historical.occurrence === null &&
              row.projection.historical.finality === 'NOT_ESTABLISHED'),
        ),
        `Unexpected deployment blockers: ${current.blockers.join(',')}`,
      );
  }
  assert.equal(eligible.length, 1, 'Only the current real finalized observation is eligible');
  const selected = eligible[0],
    normalized = selected.projection;
  const readProvenance = async (retired) => {
    const item = await recordItem(selected);
    const pending = maker.waitForResponse(
      (r) =>
        new URL(r.url()).searchParams.has('provenanceRecordId') && r.request().method() === 'GET',
    );
    await item
      .getByRole('button', {
        name: `Read provenance for sequence ${selected.sequence}`,
        exact: true,
      })
      .click();
    const response = await pending;
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['cache-control'], 'no-store');
    const value = (await response.json()).provenance;
    assert.equal(value.status, retired ? 'PROJECTION_RETIRED' : 'VERIFIED_DEPLOYMENT_OBSERVATION');
    const panel = maker.getByRole('region', { name: 'Evidence provenance', exact: true });
    if (retired) {
      assert.equal(value.deployment, null);
      await expect(panel).toContainText(
        'This normalized projection was retired by an approved deletion.',
      );
      await expect(panel).not.toContainText(normalized.transactionHash);
    } else {
      assert.equal(value.deployment.currentChainTruth, 'NOT_QUERIED');
      assert.equal(value.deployment.historical.finality, 'FINALIZED');
      await expect(panel).toContainText(normalized.transactionHash);
    }
  };
  await readProvenance(false);
  const item = await recordItem(selected);
  const current = projectionDeletionPlan.parse(
    await inspect(
      item.getByRole('button', {
        name: `Review normalized projection deletion for sequence ${selected.sequence}`,
        exact: true,
      }),
    ),
  );
  assert.equal(current.selection.sourceKind, 'DEPLOYMENT_PROVENANCE');
  assert.equal(current.selection.sourceReceiptDigest, selected.receipt_digest);
  assert.deepEqual(
    current.selection.targets.map((t) => t.recordId),
    [selected.record_id],
  );
  const failed = await governThroughWorkbench({
    maker,
    checker,
    checkerId: actors.checker.principalId,
    label: 'Delete normalized evidence projections',
    fields: { 'Starting evidence reference': urn(selected.id) },
    reason: 'Retire this exact finalized operator observation under independent approval.',
    expectedExecutionStatus: 503,
    beforeExecute: () =>
      writeFile(
        join(secretRoot, '..', 'data', 'signing-provider', 'faults', 'next-SIGN_RECEIPT.json'),
        JSON.stringify({ mode: 'REJECT_NOT_APPLIED' }),
        { mode: 0o600, flag: 'wx' },
      ),
  });
  assert.deepEqual(await snapshot(), before);
  await preserve();
  const holdFields = {
    'Hold kind': 'LEGAL',
    'Evidence to preserve': 'BLOCK_RANGE',
    'Chain ID': normalized.chainId,
    'Genesis digest': normalized.genesisDigest,
    'First block to preserve': normalized.historical.occurrence.blockNumber,
    'Last block; leave blank for future blocks': normalized.historical.occurrence.blockNumber,
  };
  const held = await govern(
    'Preserve evidence under a hold',
    holdFields,
    'Preserve the original finalized block after deletion approval.',
  );
  assert.ok((await plan(selected)).blockers.includes('ACTIVE_HOLD'));
  await retryDeletion(maker, failed.approvalId, { failed: true, expectedFailureStatus: 412 });
  assert.deepEqual(await snapshot(), before);
  await govern(
    'Release an evidence hold',
    { 'Resource reference': held.completed.result.holdId, 'Expected revision': '1' },
    'Release the exact late hold before resuming the same deletion.',
  );
  await withDeletionOutboxFault(pool, streamId, 'LEASE_EXPIRE', () =>
    retryDeletion(maker, failed.approvalId, {
      failed: true,
      expectedFailureStatus: 412,
      duringExecution: () => observeRetirementOutbox(pool, 'PgSleep'),
    }),
  );
  assert.deepEqual(await snapshot(), before);
  await withDeploymentRetirementFenceLoss({
    admin: pool,
    streamId,
    run: (duringExecution) =>
      retryDeletion(maker, failed.approvalId, {
        failed: true,
        expectedFailureStatus: 412,
        duringExecution,
      }),
  });
  assert.deepEqual(await snapshot(), before);
  await preserve();
  // The failed original attempt keeps the same candidate and business key.
  // Let its checker authority expire naturally, then use the public successor
  // owner; never rewrite timestamps or borrow source-disclosure permission.
  const predecessor = await readWorkbenchApproval(maker, failed.approvalId);
  process.stdout.write(
    'OPENPC_DEPLOYMENT_RETIREMENT_APPROVAL|state=waiting-for-natural-expiry|signer-hold-fence-denials-passed|original-intent\n',
  );
  await expect
    .poll(
      async () =>
        (await readWorkbenchApproval(maker, failed.approvalId)).candidate.canRequestResume,
      { timeout: 330000, intervals: [1000, 5000] },
    )
    .toBe(true);
  await maker.getByRole('button', { name: 'Request fresh approval', exact: true }).click();
  await expect(
    maker.getByText(
      'A fresh approval request is ready. The previous attempt remains in its history.',
      { exact: true },
    ),
  ).toBeVisible();
  const successorId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
  assert.notEqual(successorId, failed.approvalId);
  const successor = await readWorkbenchApproval(maker, successorId);
  assert.deepEqual(successor.candidate.candidate, predecessor.candidate.candidate);
  assert.equal(
    successor.candidate.businessIdempotencyKey,
    predecessor.candidate.businessIdempotencyKey,
  );
  assert.equal(successor.candidate.operationRef, null);
  assert.equal(successor.result, null);
  assert.equal(
    (await readWorkbenchApproval(maker, failed.approvalId)).candidate.successorApprovalRef,
    urn(successorId),
  );
  const review = await readWorkbenchApproval(checker, successorId);
  assert.deepEqual(review.candidate.candidate, predecessor.candidate.candidate);
  assert.equal(review.candidate.businessIdempotencyKey, null);
  await checker.getByRole('button', { name: 'Approve with security key', exact: true }).click();
  await expect(checker.getByText('Independent approval recorded.', { exact: true })).toBeVisible();
  assert.deepEqual(await snapshot(), before);
  assert.deepEqual((await plan(selected)).selection, current.selection);
  await preserve();
  const completed = await retryDeletion(maker, successorId, { loseResponse: true });
  await verify(completed.result);
  assert.equal(completed.result.selection.sourceKind, 'DEPLOYMENT_PROVENANCE');
  assert.equal((await snapshot()).projections.length, before.projections.length - 1);
  assert.equal((await continueFrom(completed.result)).continuationState, 'COMPLETE');
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
  assert.deepEqual((await readWorkbenchApproval(maker, successorId)).result, completed.result);
  assert.equal(
    (await readWorkbenchApproval(maker, failed.approvalId)).candidate.successorApprovalRef,
    urn(successorId),
  );
  await runWorker();
  assert.equal(
    (await snapshot()).projections.some((r) => r.record_id === selected.record_id),
    false,
  );
  assert.equal((await plan(selected)).projectionState, 'RETIRED');
  assert.deepEqual(await canonical(), original);
  await preserve();
  await readProvenance(true);
  const afterHold = await govern(
    'Preserve evidence under a hold',
    holdFields,
    'Preserve the original finalized block after its normalized view was retired.',
  );
  await runWorker();
  const coverage = await query(
    `select a.object_digest from control.evidence_hold_coverage a
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.retention_hold_id=$3
     and a.hold_revision=1 and a.stream_id=$4 and a.object_digest=$5`,
    [
      ...scoped,
      afterHold.completed.result.holdId.slice(-36),
      streamId,
      current.selection.archiveObjectDigest,
    ],
  );
  assert.ok(
    coverage.length > 0,
    'Immutable lineage still supplies actual original-object hold coverage',
  );
  await govern(
    'Release an evidence hold',
    { 'Resource reference': afterHold.completed.result.holdId, 'Expected revision': '1' },
    'Release the exact original-object preservation rule.',
  );
  await runWorker();
  await preserve();
  assert.deepEqual(await canonical(), original);
  for (const context of [{ participantId: uuidv7() }, { privacyDomainId: uuidv7() }]) {
    const denied = await api(`evidence-deletions/${completed.result.deletionJobId}`, context);
    assert.ok(denied.status >= 400);
    assert.equal(JSON.stringify(denied.body).includes(selected.receipt_digest), false);
  }
  await chooseContext(maker, foreignPrivacyDomainId);
  await expect(maker.getByRole('region', { name: 'Evidence provenance', exact: true })).toHaveCount(
    0,
  );
  for (const value of [selected.id, selected.receipt_digest, normalized.transactionHash])
    await expect(maker.locator('body')).not.toContainText(value);
  const hidden = await maker.request.get(
    `http://localhost:8080/api/v1/ui/evidence-workbench?provenanceRecordId=${selected.id}`,
  );
  assert.equal(hidden.status(), 404);
  assert.equal(hidden.headers()['cache-control'], 'no-store');
  await chooseContext(maker, scoped[1]);
  await readProvenance(true);
  await refresh();
  await continueFrom(completed.result);
  await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
  await maker.keyboard.press('Enter');
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText('Selection complete.');
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await maker.screenshot({
    path: join(artifacts, 'deployment-retirement-desktop.png'),
    fullPage: true,
  });
  await maker.setViewportSize({ width: 360, height: 880 });
  assert.equal(
    await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
  );
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await maker.screenshot({
    path: join(artifacts, 'deployment-retirement-reflow.png'),
    fullPage: true,
  });
  process.stdout.write(
    'OPENPC_DEPLOYMENT_RETIREMENT_BROWSER|PASS|real-finalized-source|physical-effect|signed-result|late-block-hold|signer-no-effect|fence-expiry-and-loss|natural-approval-expiry|exact-no-effect-successor|fresh-independent-approval|lost-ack|restart|no-resurrection|immutable-history-and-lineage|archive-hold|privacy|keyboard|axe|reflow\n',
  );
}
