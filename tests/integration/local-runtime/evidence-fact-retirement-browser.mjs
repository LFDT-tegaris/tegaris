import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { retainFactProvenance } from '../../../services/control-api/src/evidence/fact-source.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { governThroughWorkbench, readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { retryDeletion, withDeletionOutboxFault } from './evidence-rejection-deletion-checks.mjs';
import {
  observeFactRetirementOutbox,
  withFactRetirementLeaseLoss,
  verifyFactRetirementHoldCoverage,
} from './evidence-fact-retirement-checks.mjs';
import { rpcRetirementPolicyFields } from './evidence-rpc-retirement-browser.mjs';
import { chooseContext } from './evidence-source-holds.mjs';

/** Actual admitted parent/child Facts and their original custody are inputs.
 * Every policy, hold, approval and physical retirement uses its public owner. */
export async function factProjectionRetirementBrowser({
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
  configuration,
  foreignPrivacyDomainId,
  resumeApprovalId,
  readbackHoldId,
}) {
  const urn = (id) => `urn:openpc:resource:${id}`;
  const rows = (
    await pool.query(
      readbackHoldId
        ? `select c.evidence_id::text id,c.record_id,c.receipt_digest,c.segment_id,c.sequence::text sequence,
       jsonb_build_object('lineage',r.preservation_metadata->'factLineage') projection,r.projection_digest,r.deletion_job_id
       from control.evidence_catalogue c join control.evidence_projection_retirement r
        using(participant_id,privacy_domain_id,stream_id,record_id)
       join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
       where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
        and r.data_class='NORMALIZED_JSON_PROJECTION' and j.state='SUCCEEDED'
        and r.retirement_digest=openpc.projection_retirement_digest(r) order by c.record_id`
        : `select c.evidence_id::text id,c.record_id,c.receipt_digest,c.segment_id,c.sequence::text sequence,
    p.projection,p.projection_digest from control.evidence_catalogue c join control.evidence_fact_provenance p
    using(participant_id,privacy_domain_id,stream_id,record_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 order by c.record_id`,
      [...scoped, streamId],
    )
  ).rows;
  assert.equal(
    rows.length,
    2,
    'Exact real parent/child fixture, with no consumed retirement replay',
  );
  const [parent, child] = rows;
  const l = parent.projection.lineage;
  assert.ok(
    [
      child.projection.lineage.predecessorDigest,
      child.projection.lineage.relationshipPredecessorDigest,
    ].includes(parent.projection.lineage.factDigest),
  );
  const plan = async (row) => {
    const response = await api(
      `evidence-records/${urn(row.id)}/normalized-projection-deletion-plan`,
    );
    assert.equal(response.status, 200);
    return projectionDeletionPlan.parse(response.body);
  };
  const provenance = async (row, retired) => {
    const item = await recordItem(row);
    const pending = maker.waitForResponse(
      (r) =>
        new URL(r.url()).searchParams.has('provenanceRecordId') && r.request().method() === 'GET',
    );
    await item
      .getByRole('button', { name: `Read provenance for sequence ${row.sequence}`, exact: true })
      .click();
    const response = await pending;
    assert.equal(response.status(), 200);
    assert.equal(response.headers()['cache-control'], 'no-store');
    const value = (await response.json()).provenance;
    assert.equal(value.status, retired ? 'PROJECTION_RETIRED' : 'VERIFIED_FACT_CUSTODY_PROJECTION');
    const panel = maker.getByRole('region', { name: 'Evidence provenance', exact: true });
    if (retired) {
      assert.equal(value.fact, null);
      await expect(panel).toContainText(
        'This normalized projection was retired by an approved deletion.',
      );
      await expect(panel).not.toContainText(row.projection.lineage.factId);
    } else {
      assert.equal(value.fact.currentReadiness, 'NOT_ESTABLISHED');
      await expect(panel).toContainText('Canonical Fact history');
      await expect(panel).toContainText(row.projection.lineage.factId);
    }
  };
  const scope = configuration.scopes.find((s) => s.streamId === streamId);
  assert.ok(scope && scope.source === 'FACT');
  const worker = new Pool({
    ...configuration.database,
    password: (await readFile(configuration.database.passwordFile, 'utf8')).trim(),
    max: 1,
  });
  const factDb = new Pool({
    ...scope.fact.database,
    password: (await readFile(scope.fact.database.passwordFile, 'utf8')).trim(),
    max: 1,
  });
  const inScope = async (owner, action, work) => {
    const client = await owner.connect();
    try {
      await client.query('begin');
      if (owner === worker)
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          ...scoped,
          uuidv7(),
          action,
        ]);
      else
        await client.query(
          "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
          scoped,
        );
      const value = await work(client);
      await client.query('commit');
      return value;
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  };
  const metadata = () =>
    inScope(
      worker,
      'ACT-EVIDENCE_EXPORT_RECORDS-V1',
      async (client) =>
        (
          await client.query(
            'select openpc.evidence_hold_record_metadata(c) metadata from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3',
            [...scoped, child.id],
          )
        ).rows[0].metadata,
    );
  const canonical = () =>
    inScope(
      factDb,
      '',
      async (client) =>
        (
          await client.query(
            `select candidate_id,generation_id,state::text,
    encode(sha256(cose_sign1),'hex') receipt_digest,encode(fact_digest,'hex') fact_digest
    from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 order by candidate_id`,
            scoped,
          )
        ).rows,
    );
  const snapshot = async () => ({
    projections: (
      await pool.query(
        'select record_id,projection,projection_digest from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id',
        [...scoped, streamId],
      )
    ).rows,
    retirements: (
      await pool.query(
        'select * from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by deletion_job_id',
        [...scoped, streamId],
      )
    ).rows,
    jobs: (
      await pool.query(
        'select * from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by deletion_job_id',
        [...scoped, streamId],
      )
    ).rows,
  });
  const canonicalBefore = await canonical(),
    lineageBefore = await metadata();
  assert.equal(lineageBefore.unresolvedReferences, false);
  assert.equal(lineageBefore.facts.length, 2);
  const before = await snapshot();
  try {
    let second;
    if (!readbackHoldId) {
      let failed;
      await provenance(parent, false);
      const existing = (await refresh()).retentionPolicies.items.filter(
        (p) => p.dataClass === 'NORMALIZED_JSON_PROJECTION',
      );
      if (resumeApprovalId) {
        assert.equal(existing.length, 3, 'Resume retains the three original class policies');
        const active = existing.filter((p) => p.state === 'ACTIVE');
        assert.equal(active.length, 1);
        assert.equal(active[0].policyVersion, '3.0.0');
        let approvalId = resumeApprovalId;
        let recovered = await readWorkbenchApproval(maker, approvalId);
        const original = recovered.candidate;
        for (let attempt = 0; attempt < 8; attempt++) {
          assert.deepEqual(recovered.candidate.candidate, original.candidate);
          assert.equal(recovered.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
          assert.equal(recovered.candidate.operationRef, null);
          assert.equal(recovered.result, null);
          if (recovered.candidate.successorApprovalRef)
            approvalId = recovered.candidate.successorApprovalRef.slice(-36);
          else if (recovered.candidate.canRequestResume) {
            await maker
              .getByRole('button', { name: 'Request fresh approval', exact: true })
              .click();
            await expect(
              maker.getByText(
                'A fresh approval request is ready. The previous attempt remains in its history.',
                { exact: true },
              ),
            ).toBeVisible();
            approvalId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
            assert.notEqual(approvalId, resumeApprovalId);
          } else break;
          recovered = await readWorkbenchApproval(maker, approvalId);
        }
        const review = await readWorkbenchApproval(checker, approvalId);
        assert.deepEqual(review.candidate.candidate, original.candidate);
        assert.equal(review.candidate.businessIdempotencyKey, null);
        if (review.approval.state === 'REQUESTED') {
          await checker
            .getByRole('button', { name: 'Approve with security key', exact: true })
            .click();
          await expect(
            checker.getByText('Independent approval recorded.', { exact: true }),
          ).toBeVisible();
        }
        recovered = await readWorkbenchApproval(maker, approvalId);
        assert.equal(recovered.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
        const current = await plan(parent);
        assert.equal(current.eligible, true);
        assert.equal(recovered.candidate.state, 'APPROVED');
        assert.equal(recovered.candidate.approvalUsable, true);
        assert.equal(recovered.result, null);
        assert.deepEqual(recovered.candidate.candidate.selection, current.selection);
        assert.equal(recovered.candidate.candidate.beforeDigest, current.beforeDigest);
        assert.ok(recovered.reviewToken);
        failed = { approvalId };
      } else {
        assert.equal(
          existing.length,
          0,
          'The fresh Fact-specific class governance must not repeat an existing policy intent',
        );
        let policy;
        for (const value of [
          {
            version: '1.0.0',
            period: '31536000000',
            grace: '0',
            quorum: '2',
            blockers: ['RETENTION_NOT_ELAPSED', 'SINK_QUORUM'],
          },
          {
            version: '2.0.0',
            period: '0',
            grace: '31536000000',
            quorum: '1',
            blockers: ['RETENTION_NOT_ELAPSED'],
          },
          { version: '3.0.0', period: '0', grace: '0', quorum: '1', blockers: [] },
        ]) {
          if (policy)
            await govern(
              'Retire a retention policy version',
              { 'Resource reference': policy.retentionPolicyId, 'Expected revision': '1' },
              'Preserve this exact Fact projection policy as the successor boundary.',
            );
          const fields = rpcRetirementPolicyFields(policy?.retentionPolicyId, value);
          if (!policy) delete fields['Previous retention policy reference'];
          await govern(
            'Activate a retention policy version',
            fields,
            'Govern the independent normalized Fact projection retention and archive requirements.',
          );
          const policies = (await refresh()).retentionPolicies.items.filter(
            (p) => p.dataClass === 'NORMALIZED_JSON_PROJECTION' && p.state === 'ACTIVE',
          );
          assert.equal(policies.length, 1);
          [policy] = policies;
          for (const row of rows) {
            const current = await plan(row);
            assert.deepEqual(current.blockers, value.blockers);
            assert.equal(current.selection.sourceKind, 'FACT_PROVENANCE');
            assert.equal(current.selection.sourceReceiptDigest, row.receipt_digest);
            assert.equal(current.selection.retentionPolicyId, policy.retentionPolicyId);
          }
        }
        const other = (
          await pool.query(
            `select evidence_id::text id from control.evidence_catalogue
      where participant_id=$1 and privacy_domain_id=$2 and stream_id=any($3::text[]) and stream_id<>$4 order by evidence_id`,
            [...scoped, configuration.scopes.map((s) => s.streamId), streamId],
          )
        ).rows;
        assert.ok(other.length > 0, 'Real still-fenced reorg history must remain protected');
        for (const row of other) {
          const current = await plan(row);
          assert.equal(current.eligible, false);
          assert.ok(current.blockers.includes('INCOMPLETE_CHECKPOINT'));
        }
        const reference = `public.fact_retirement_ref_${uuidv7().replaceAll('-', '')}`;
        await pool.query(`create table ${reference}(participant_id uuid,privacy_domain_id uuid,stream_id text,record_id text,
      foreign key(participant_id,privacy_domain_id,stream_id,record_id) references control.evidence_fact_provenance(participant_id,privacy_domain_id,stream_id,record_id))`);
        try {
          assert.ok((await plan(parent)).blockers.includes('REFERENCES'));
        } finally {
          await pool.query(`drop table ${reference}`);
        }
        for (const fields of [
          { 'Evidence to preserve': 'PRIVACY_DOMAIN' },
          { 'Evidence to preserve': 'PROJECTION', 'Projection reference': l.projectionId },
          {
            'Evidence to preserve': 'FACT_TYPE_KEY',
            'Fact type': l.factType,
            'Fact profile reference': l.factProfileId,
            'Fact key digest; leave blank for every key in this profile': l.factKeyDigest,
          },
          {
            'Evidence to preserve': 'BLOCK_RANGE',
            'Chain ID': l.chainId,
            'Genesis digest': l.genesisDigest,
            'First block to preserve': l.blockNumber,
            'Last block; leave blank for future blocks': l.blockNumber,
          },
          {
            'Evidence to preserve': 'GENERATION',
            'Generation kind': 'CANONICAL_FACT',
            'Fact profile reference': l.factProfileId,
            'Canonical Fact generation number': l.canonicalGeneration,
          },
        ]) {
          const held = await govern(
            'Preserve evidence under a hold',
            { 'Hold kind': 'LEGAL', ...fields },
            'Preserve this actual Fact lineage and every dependent historical record.',
          );
          for (const row of rows) assert.ok((await plan(row)).blockers.includes('ACTIVE_HOLD'));
          await govern(
            'Release an evidence hold',
            { 'Resource reference': held.completed.result.holdId, 'Expected revision': '1' },
            'Release this exact preservation rule before independent deletion review.',
          );
        }
        const participantHold = await govern(
          'Preserve evidence across a Participant',
          { 'Hold kind': 'INCIDENT' },
          'Preserve all Participant evidence including these Fact projections.',
        );
        for (const row of rows) assert.ok((await plan(row)).blockers.includes('ACTIVE_HOLD'));
        await govern(
          'Release a Participant-wide evidence hold',
          {
            'Resource reference': participantHold.completed.result.holdId,
            'Expected revision': '1',
          },
          'Release the exact Participant preservation rule.',
        );
        const item = await recordItem(parent);
        const selected = projectionDeletionPlan.parse(
          await inspect(
            item.getByRole('button', {
              name: `Review normalized projection deletion for sequence ${parent.sequence}`,
              exact: true,
            }),
          ),
        );
        assert.equal(selected.eligible, true);
        assert.deepEqual(
          selected.selection.targets.map((t) => t.recordId),
          rows.map((r) => r.record_id),
        );
        failed = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Delete normalized evidence projections',
          fields: { 'Starting evidence reference': urn(parent.id) },
          reason:
            'Retire the derived parent Fact projection while preserving its original and the lineage of its child.',
          expectedExecutionStatus: 503,
          beforeExecute: () =>
            writeFile(
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
            ),
        });
        assert.deepEqual(await snapshot(), before);
        await preserve();
      }
      // An approval does not freeze preservation state. These real holds arrive
      // after the deletion's independent approval and must prevent its effect.
      for (const participantWide of [true, false]) {
        const held = await govern(
          participantWide
            ? 'Preserve evidence across a Participant'
            : 'Preserve evidence under a hold',
          participantWide
            ? { 'Hold kind': 'INCIDENT' }
            : {
                'Hold kind': 'LEGAL',
                'Evidence to preserve': 'DIGEST',
                'Receipt digest': parent.receipt_digest,
              },
          `Preserve the original source while checking restored execution of approval ${failed.approvalId}.`,
        );
        await retryDeletion(maker, failed.approvalId, { failed: true, expectedFailureStatus: 412 });
        assert.deepEqual(await snapshot(), before);
        await govern(
          participantWide ? 'Release a Participant-wide evidence hold' : 'Release an evidence hold',
          { 'Resource reference': held.completed.result.holdId, 'Expected revision': '1' },
          'Release this exact late preservation rule before retrying the original approval.',
        );
      }
      await withDeletionOutboxFault(pool, streamId, 'LEASE_EXPIRE', () =>
        retryDeletion(maker, failed.approvalId, {
          failed: true,
          expectedFailureStatus: 412,
          duringExecution: () => observeFactRetirementOutbox(pool, 'PgSleep'),
        }),
      );
      assert.deepEqual(await snapshot(), before);
      await withFactRetirementLeaseLoss({
        admin: pool,
        secretRoot,
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
      const first = await retryDeletion(maker, failed.approvalId, { loseResponse: true });
      await verify(first.result);
      assert.deepEqual(
        await metadata(),
        lineageBefore,
        'The retired parent still supplies exact historical hold lineage',
      );
      assert.equal((await snapshot()).projections.length, 1);
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
        (await readWorkbenchApproval(maker, failed.approvalId)).result,
        first.result,
      );
      const next = await continueFrom(first.result);
      assert.equal(next.continuationState, 'READY');
      assert.equal(next.selection.recordId, child.record_id);
      second = await govern(
        'Continue projection deletion',
        { 'Previous projection deletion result': first.result.deletionJobId },
        'Continue the immutable selection using the retired parent preservation minimum.',
      );
      await verify(second.completed.result);
      assert.equal((await continueFrom(second.completed.result)).continuationState, 'COMPLETE');
      await runWorker();
      await inScope(worker, 'ACT-EVIDENCE_EXPORT_RECORDS-V1', (client) =>
        retainFactProvenance(
          client,
          scope,
          rows.map((row) => ({
            source: { recordId: row.record_id, receiptDigest: row.receipt_digest },
            provenance: row.projection,
          })),
        ),
      );
      assert.equal((await snapshot()).projections.length, 0);
      assert.deepEqual(await metadata(), lineageBefore);
      for (const row of rows) {
        const source = await api(`evidence-records/${urn(row.id)}/provenance`);
        assert.equal(source.body.status, 'PROJECTION_RETIRED');
        assert.equal(source.body.fact, null);
        assert.equal((await plan(row)).projectionState, 'RETIRED');
      }
    } else {
      assert.ok(resumeApprovalId, 'Readback requires the original governed intent');
      assert.equal(before.projections.length, 0);
      assert.equal(before.retirements.length, 2);
      let original = await readWorkbenchApproval(maker, resumeApprovalId);
      for (let attempt = 0; original.candidate.successorApprovalRef && attempt < 8; attempt++)
        original = await readWorkbenchApproval(
          maker,
          original.candidate.successorApprovalRef.slice(-36),
        );
      assert.equal(original.candidate.state, 'CONSUMED');
      assert.equal(original.result.deletionJobId, urn(parent.deletion_job_id));
      for (const row of rows) {
        const response = await api(`evidence-deletions/${urn(row.deletion_job_id)}`);
        assert.equal(response.status, 200);
        await verify(response.body);
        assert.equal(response.body.selection.recordId, row.record_id);
        assert.equal(response.body.selection.sourceKind, 'FACT_PROVENANCE');
        second = { completed: { result: response.body } };
        assert.equal((await api(`evidence-records/${urn(row.id)}/provenance`)).body.fact, null);
      }
      assert.equal((await continueFrom(second.completed.result)).continuationState, 'COMPLETE');
    }
    await provenance(parent, true);
    await maker.screenshot({
      path: join(artifacts, 'fact-retired-provenance.png'),
      fullPage: true,
    });
    const later = readbackHoldId
      ? { completed: { result: (await api(`evidence-holds/${urn(readbackHoldId)}`)).body } }
      : await govern(
          'Preserve evidence under a hold',
          {
            'Hold kind': 'INCIDENT',
            'Evidence to preserve': 'FACT_TYPE_KEY',
            'Fact type': l.factType,
            'Fact profile reference': l.factProfileId,
            'Fact key digest; leave blank for every key in this profile': l.factKeyDigest,
          },
          'Preserve the original parent and child evidence after their derived projections are retired.',
        );
    await runWorker();
    assert.equal(later.completed.result.state, 'ACTIVE');
    assert.deepEqual(later.completed.result.selector, {
      type: 'FACT_TYPE_KEY',
      factType: l.factType,
      factProfileId: l.factProfileId,
      factKeyDigest: l.factKeyDigest,
    });
    const coverage = await inScope(worker, 'ACT-EVIDENCE_EXPORT_RECORDS-V1', (client) =>
      verifyFactRetirementHoldCoverage(client, scoped, streamId, later.completed.result.holdId),
    );
    assert.equal(
      (await api(`evidence-holds/${later.completed.result.holdId}`)).body.coverage,
      coverage,
    );

    await govern(
      'Release an evidence hold',
      { 'Resource reference': later.completed.result.holdId, 'Expected revision': '1' },
      'Release the exact post-retirement preservation rule.',
    );
    await runWorker();
    await preserve();
    assert.deepEqual(await canonical(), canonicalBefore);
    for (const context of [{ participantId: uuidv7() }, { privacyDomainId: uuidv7() }]) {
      const denied = await api(
        `evidence-deletions/${second.completed.result.deletionJobId}/projection-continuation-plan`,
        context,
      );
      assert.ok(denied.status >= 400);
      assert.equal(JSON.stringify(denied.body).includes(parent.receipt_digest), false);
    }
    await chooseContext(maker, foreignPrivacyDomainId);
    await expect(
      maker.getByRole('region', { name: 'Evidence provenance', exact: true }),
    ).toHaveCount(0);
    for (const privateValue of [parent.id, parent.receipt_digest, parent.projection.lineage.factId])
      await expect(maker.locator('body')).not.toContainText(privateValue);
    const hidden = await maker.request.get(
      `http://localhost:8080/api/v1/ui/evidence-workbench?provenanceRecordId=${parent.id}`,
    );
    assert.equal(hidden.status(), 404);
    assert.equal(hidden.headers()['cache-control'], 'no-store');
    assert.equal((await hidden.text()).includes(parent.receipt_digest), false);
    await chooseContext(maker, scoped[1]);
    await provenance(parent, true);
    await refresh();
    await continueFrom(second.completed.result);
    await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
    await maker.keyboard.press('Enter');
    await expect(
      maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
    ).toContainText('Selection complete.');
    assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
    await maker.screenshot({
      path: join(artifacts, 'fact-retirement-desktop.png'),
      fullPage: true,
    });
    await maker.setViewportSize({ width: 360, height: 880 });
    assert.equal(
      await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
    await maker.screenshot({ path: join(artifacts, 'fact-retirement-reflow.png'), fullPage: true });
    process.stdout.write(
      readbackHoldId
        ? 'OPENPC_FACT_RETIREMENT_READBACK|PASS|retained-effects=2|original-successor-readback|post-retirement-archive-hold|public-release|privacy|keyboard|axe|reflow\n'
        : 'OPENPC_FACT_RETIREMENT_BROWSER|PASS|effects=2|real-parent-first|independent-class-policy|reorg-denial|holds|references|signer-no-effect|lease-expiry-and-loss-rollback|signed-continuation|lost-ack|restart|worker-and-source-replay|minimal-lineage|original-canonical-and-archive|no-store|privacy|keyboard|axe|reflow\n',
    );
  } finally {
    await worker.end();
    await factDb.end();
  }
}
