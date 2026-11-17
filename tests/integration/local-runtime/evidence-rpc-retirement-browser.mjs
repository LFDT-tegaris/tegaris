import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  projectionDeletionPlan,
  projectionDeletionSelection,
} from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  completeWorkbenchApproval,
} from './transaction-workbench-browser.mjs';
import { retryDeletion } from './evidence-rejection-deletion-checks.mjs';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';

export function rpcDenialRetirementInput(recordId) {
  assert.match(recordId, /^rpc:[0-9a-f]{64}:[1-9][0-9]{0,19}$/u);
  assert.ok(BigInt(recordId.split(':')[2]) <= 18446744073709551615n);
  return recordId;
}

export async function rpcDenialRetirementSource(pool, scoped, rpcStream, recordId) {
  rpcDenialRetirementInput(recordId);
  const rows = (
    await pool.query(
      `select evidence_id::text id,record_id,sequence::text sequence,receipt_digest from control.evidence_catalogue
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
      [...scoped, rpcStream, recordId],
    )
  ).rows;
  assert.equal(rows.length, 1, 'Original denial catalogue identity required');
  const row = rows[0];
  assert.match(row.id, /^[0-9a-f-]{36}$/u);
  assert.equal(row.record_id, recordId);
  assert.equal(row.sequence, recordId.split(':')[2]);
  assert.match(row.receipt_digest, /^sha256:[0-9a-f]{64}$/u);
  return row;
}

/** Connected resume-input preflight. Use this exact stored-candidate read before
 * allocating the browser stack; EXPIRED is a derived public state, never a SQL
 * enum value. Public successor/approval owners still decide all authority. */
export async function rpcDenialRetirementApproval(
  pool,
  scoped,
  rpcStream,
  recordId,
  resumeApprovalId,
) {
  assert.match(resumeApprovalId, /^[0-9a-f-]{36}$/u);
  const row = await rpcDenialRetirementSource(pool, scoped, rpcStream, recordId);
  const candidate = await pool.query(
    `select c.resource_id::text,c.candidate_document from control.mutation_candidate c
     join control.approval_request a on a.participant_id=c.participant_id and a.subject_id=c.mutation_candidate_id
     where c.participant_id=$1 and c.privacy_domain_id=$2 and a.approval_request_id=$3
     and c.state in ('APPROVED','APPROVAL_REQUESTED') and c.consumed_operation_id is null
     and a.reason='Retire the remaining original pre-admission denial projection.'`,
    [...scoped, resumeApprovalId],
  );
  assert.equal(candidate.rowCount, 1);
  const document = candidate.rows[0].candidate_document;
  const selection = projectionDeletionSelection.parse(document.selection);
  assert.equal(selection.participantId, `urn:openpc:participant:${scoped[0]}`);
  assert.equal(selection.privacyDomainId, scoped[1]);
  assert.equal(selection.streamId, rpcStream);
  assert.equal(selection.sourceKind, 'RPC_PRE_ADMISSION_DENIAL');
  assert.equal(selection.dataClass, 'NORMALIZED_JSON_PROJECTION');
  assert.equal(selection.recordId, recordId);
  assert.equal(selection.evidenceId, `urn:openpc:resource:${row.id}`);
  assert.equal(selection.sourceReceiptDigest, row.receipt_digest);
  assert.equal(selection.batchIndex, 0);
  assert.equal(selection.targets[0].recordId, recordId);
  assert.equal(document.beforeDigest, selection.targets[0].beforeDigest);
  return document;
}

/** Close the remaining original denial selection without renewing its source or
 * replacing class policy. A consumed first batch is recovered from its original
 * approval; every following batch uses the signed public continuation. */
export async function rpcDenialRetirementBrowser({
  recordId,
  resumeApprovalId,
  maker,
  checker,
  api,
  govern,
  refresh,
  recordItem,
  inspect,
  verify,
  continueFrom,
  pool,
  scoped,
  rpcStream,
  command,
  runWorker,
  preserve,
}) {
  const row = await rpcDenialRetirementSource(pool, scoped, rpcStream, recordId);
  let result;
  if (resumeApprovalId) {
    assert.match(resumeApprovalId, /^[0-9a-f-]{36}$/u);
    let original = await readWorkbenchApproval(maker, resumeApprovalId);
    if (original.candidate.state !== 'CONSUMED') {
      assert.equal(original.candidate.operationRef, null);
      assert.equal(original.result, null);
      await rpcDenialRetirementApproval(pool, scoped, rpcStream, recordId, resumeApprovalId);
      original = await completeWorkbenchApproval(
        maker,
        checker,
        resumeApprovalId,
        true,
        undefined,
        { loseExecutionResponse: true },
      );
    }
    result = original.result;
    await verify(result);
    const job = (
      await pool.query(
        `select selection,approval_request_id::text from control.deletion_job
       where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3 and state='SUCCEEDED'`,
        [...scoped, result.deletionJobId.slice(-36)],
      )
    ).rows;
    assert.equal(job.length, 1);
    assert.equal(job[0].approval_request_id, original.candidate.approvalRequestId.slice(-36));
    assert.equal(job[0].selection.sourceKind, 'RPC_PRE_ADMISSION_DENIAL');
    assert.equal(job[0].selection.targets[0].recordId, recordId);
  } else {
    const provenance = await api(`evidence-records/urn:openpc:resource:${row.id}/provenance`);
    assert.equal(provenance.status, 200);
    assert.equal(provenance.body.status, 'VERIFIED_RPC_CUSTODY_PROJECTION');
    assert.equal(provenance.body.rpc.transition.phase, 'PRE_ADMISSION_DENIAL');
    await refresh();
    const item = await recordItem(row);
    const plan = projectionDeletionPlan.parse(
      await inspect(
        item.getByRole('button', {
          name: `Review normalized projection deletion for sequence ${row.sequence}`,
          exact: true,
        }),
      ),
    );
    assert.equal(plan.eligible, true, 'Current original policy/hold/source admission required');
    assert.equal(plan.selection.sourceKind, 'RPC_PRE_ADMISSION_DENIAL');
    assert.equal(plan.selection.recordId, recordId);
    await maker.getByRole('button', { name: 'Prepare first deletion batch', exact: true }).click();
    const first = await govern(
      'Delete normalized evidence projections',
      { 'Starting evidence reference': `urn:openpc:resource:${row.id}` },
      'Retire the remaining original pre-admission denial projection.',
      true,
    );
    result = first.completed.result;
    await verify(result);
    process.stdout.write(
      `OPENPC_RPC_DENIAL_BATCH|approval=${first.approvalId}|job=${result.deletionJobId}\n`,
    );
  }
  for (let batch = 0; batch < 16; batch++) {
    const continuation = await continueFrom(result);
    if (continuation.continuationState === 'COMPLETE') break;
    assert.equal(continuation.continuationState, 'READY');
    assert.equal(continuation.selection.sourceKind, 'RPC_PRE_ADMISSION_DENIAL');
    await maker.getByRole('button', { name: 'Prepare next deletion batch', exact: true }).click();
    const next = await govern(
      'Continue projection deletion',
      { 'Previous projection deletion result': result.deletionJobId },
      'Continue this exact original denial selection using its signed cursor.',
    );
    result = next.completed.result;
    await verify(result);
    process.stdout.write(
      `OPENPC_RPC_DENIAL_BATCH|approval=${next.approvalId}|job=${result.deletionJobId}\n`,
    );
  }
  assert.equal((await continueFrom(result)).continuationState, 'COMPLETE');
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
  assert.equal((await continueFrom(result)).continuationState, 'COMPLETE');
  assert.equal(
    (await api(`evidence-records/urn:openpc:resource:${row.id}/provenance`)).body.status,
    'PROJECTION_RETIRED',
  );
  await preserve();
  process.stdout.write(
    'OPENPC_RPC_DENIAL_REMAINDER|PASS|original-selection|signed-continuation|restart|no-resurrection|prior-custody-preserved\n',
  );
}

export const rpcRetirementPolicyCases = [
  {
    version: '2.0.0',
    period: '31536000000',
    grace: '0',
    quorum: '2',
    blockers: ['RETENTION_NOT_ELAPSED', 'SINK_QUORUM'],
  },
  {
    version: '3.0.0',
    period: '0',
    grace: '31536000000',
    quorum: '1',
    blockers: ['RETENTION_NOT_ELAPSED'],
  },
  { version: '4.0.0', period: '0', grace: '0', quorum: '1', blockers: [] },
];

export function rpcTerminalResumeInputs(approvals) {
  assert.equal(approvals.length, 2);
  for (const approval of approvals)
    assert.match(approval, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
  assert.notEqual(approvals[0], approvals[1]);
  return approvals;
}

/** Resume the original terminal and first selection results after both have
 * committed. Public signed cursors govern the remaining batches; this path
 * does not reconstruct retired JSON or repeat the terminal's fault case. */
export async function rpcTerminalRemainderBrowser({
  approvals,
  maker,
  api,
  govern,
  refresh,
  verify,
  continueFrom,
  pool,
  scoped,
  rpcStream,
  runWorker,
  preserve,
  command,
  artifacts,
}) {
  rpcTerminalResumeInputs(approvals);
  const retained = [];
  for (const approvalId of approvals) {
    const original = await readWorkbenchApproval(maker, approvalId);
    assert.equal(original.candidate.state, 'CONSUMED');
    await verify(original.result);
    const jobs = await pool.query(
      `select selection,approval_request_id::text from control.deletion_job
       where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3
        and state='SUCCEEDED' and revision=1 and target_data_class='NORMALIZED_JSON_PROJECTION'`,
      [...scoped, original.result.deletionJobId.slice(-36)],
    );
    assert.equal(jobs.rowCount, 1);
    assert.equal(jobs.rows[0].approval_request_id, approvalId);
    const selection = projectionDeletionSelection.parse(jobs.rows[0].selection);
    assert.equal(selection.participantId, `urn:openpc:participant:${scoped[0]}`);
    assert.equal(selection.privacyDomainId, scoped[1]);
    assert.equal(selection.streamId, rpcStream);
    assert.equal(selection.sourceKind, 'RPC_CLOSED_TRANSITION');
    assert.equal(selection.dataClass, 'NORMALIZED_JSON_PROJECTION');
    assert.equal(selection.batchIndex, 0);
    assert.equal(selection.priorCursor, null);
    retained.push({ selection, result: original.result });
  }
  const [terminal, first] = retained;
  assert.ok(terminal.selection.rpcClosure);
  assert.ok(first.selection.rpcClosure);
  assert.equal(terminal.selection.targets.length, 1);
  assert.equal(terminal.selection.rpcClosure.terminalPhase, 'INTERRUPTED');
  assert.equal(terminal.selection.recordId, terminal.selection.rpcClosure.terminalRecordId);
  assert.equal(first.selection.targets.length, 3);
  assert.equal(first.selection.recordId, first.selection.targets[0].recordId);
  assert.equal(first.selection.rpcClosure.terminalPhase, 'COMMITTED');
  assert.equal(first.selection.rpcClosure.terminalEffect, 'DENY_TERMINAL');
  assert.equal(first.selection.policyDigest, terminal.selection.policyDigest);
  let result = first.result;
  for (const row of first.selection.targets.slice(1)) {
    const next = await continueFrom(result);
    assert.equal(next.continuationState, 'READY');
    assert.equal(next.selection.sourceKind, 'RPC_CLOSED_TRANSITION');
    assert.equal(next.selection.streamId, rpcStream);
    assert.equal(next.selection.recordId, row.recordId);
    assert.deepEqual(next.selection.targets, first.selection.targets);
    const continued = await govern(
      'Continue projection deletion',
      { 'Previous projection deletion result': result.deletionJobId },
      'Continue the fixed read selection using its exact archived completion witness.',
    );
    result = continued.completed.result;
    await verify(result);
  }
  assert.equal((await continueFrom(result)).continuationState, 'COMPLETE');
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
  assert.equal((await continueFrom(result)).continuationState, 'COMPLETE');
  const targets = [...terminal.selection.targets, ...first.selection.targets];
  assert.equal(new Set(targets.map((row) => row.recordId)).size, 4);
  const remaining = await pool.query(
    `select count(*)::int n from control.evidence_rpc_provenance
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=any($4::text[])`,
    [...scoped, rpcStream, targets.map((row) => row.recordId)],
  );
  assert.equal(
    remaining.rows[0].n,
    0,
    'All four original normalized rows must remain physically absent',
  );
  for (const row of targets) {
    const provenance = await api(`evidence-records/${row.evidenceId}/provenance`);
    assert.equal(provenance.status, 200);
    assert.equal(provenance.body.status, 'PROJECTION_RETIRED');
    assert.equal(provenance.body.rpc, null);
  }
  await preserve();
  const hold = await govern(
    'Preserve evidence under a hold',
    {
      'Hold kind': 'INCIDENT',
      'Evidence to preserve': 'DIGEST',
      'Receipt digest': terminal.selection.sourceReceiptDigest,
    },
    'Verify original read evidence remains preservable after the normalized retirements.',
  );
  await runWorker();
  const held = await api(`evidence-holds/${hold.completed.result.holdId}`);
  assert.equal(held.status, 200);
  assert.equal(held.body.coverage, 'VERIFIED');
  await govern(
    'Release an evidence hold',
    { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
    'Release this exact post-retirement archive hold.',
  );
  await runWorker();
  for (const context of [
    { participantId: uuidv7() },
    { privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
  ]) {
    const denied = await api(
      `evidence-deletions/${result.deletionJobId}/projection-continuation-plan`,
      context,
    );
    assert.ok(
      [403, 404].includes(denied.status),
      'Require scope denial, not infrastructure failure',
    );
    const body = JSON.stringify(denied.body);
    for (const value of [
      result.deletionJobId,
      result.receiptDigest,
      ...targets.flatMap((row) => [
        row.recordId,
        row.evidenceId,
        row.sourceReceiptDigest,
        row.projectionDigest,
      ]),
    ])
      assert.equal(body.includes(value), false);
    assert.equal(denied.body.selection, undefined);
    assert.equal(denied.body.continuationState, undefined);
  }
  await refresh();
  await continueFrom(result);
  await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
  await maker.keyboard.press('Enter');
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText('Selection complete.');
  for (const width of [1440, 360]) {
    await maker.setViewportSize({ width, height: 880 });
    assert.equal(
      await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
    await maker.screenshot({
      path: join(artifacts, `terminal-retirement-resumed-${width}.png`),
      fullPage: true,
    });
  }
  await preserve();
  process.stdout.write(
    'OPENPC_RPC_TERMINAL_REMAINDER|PASS|two-original-consumed-results|signed-continuations|no-replay|restart|no-resurrection|post-retirement-hold|privacy|keyboard|axe|reflow\n',
  );
}
export function rpcRetirementPolicyFields(previous, value) {
  return {
    'Retained data class': 'NORMALIZED_JSON_PROJECTION',
    'Retention policy version': value.version,
    'Previous retention policy reference': previous,
    'Retention period in milliseconds': value.period,
    'Local grace in milliseconds': value.grace,
    'Required durable sink acknowledgements': value.quorum,
    'Deletion mode': 'PROJECTION_DELETE',
    'Require independent deletion approval': 'true',
  };
}

export function rpcReadResumePolicy(policies, version) {
  assert.equal(version, '3.0.0');
  assert.equal(policies.length, 3, 'Require exactly the previously governed policy chain');
  const ordered = [...policies].sort((a, b) => a.policyVersion.localeCompare(b.policyVersion));
  const expected = [
    { version: '1.0.0', period: '0', grace: '0', quorum: 1 },
    ...rpcRetirementPolicyCases.slice(0, 2).map((p) => ({ ...p, quorum: Number(p.quorum) })),
  ];
  for (const [index, policy] of ordered.entries()) {
    const value = expected[index];
    assert.equal(policy.policyVersion, value.version);
    assert.equal(policy.state, index === 2 ? 'ACTIVE' : 'RETIRED');
    assert.equal(policy.retentionPeriodMs, value.period);
    assert.equal(policy.localGraceMs, value.grace);
    assert.equal(policy.sinkQuorum, value.quorum);
    assert.equal(policy.deletionMode, 'PROJECTION_DELETE');
    assert.equal(policy.makerCheckerRequired, true);
    assert.equal(policy.predecessorPolicyId, index ? ordered[index - 1].retentionPolicyId : null);
    assert.match(policy.activationReceiptDigest, /^sha256:[0-9a-f]{64}$/u);
  }
  assert.equal(new Set(ordered.map((p) => p.retentionPolicyId)).size, 3);
  return ordered[2];
}

/** Same actual custody and governance setup as the denial adapter. Retire the
 * terminal witness first, then prove the prior transitions do not need a rebuilt
 * normalized witness. Never issue another RPC or seed an intermediate state. */
export async function rpcProjectionRetirementBrowser({
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
  rpcStream,
  secretRoot,
  artifacts,
  command,
  runWorker,
  preserve,
  resumeRetiredPolicyVersion = process.env.OPENPC_RPC_RETIREMENT_RESUME_RETIRED_POLICY,
  resumeActivePolicyVersion,
  sourceReads = false,
  terminalCases = false,
  requireLaterSegment = process.env.OPENPC_SOURCE_RETIREMENT_REQUIRE_LATER_SEGMENT === '1',
}) {
  const urn = (id) => `urn:openpc:resource:${id}`;
  assert.equal(sourceReads && terminalCases, false);
  let rows = (
    await pool.query(
      `select c.evidence_id::text id,c.record_id,c.receipt_digest,c.segment_id,c.sequence::text sequence,p.projection
    from control.evidence_catalogue c join control.evidence_rpc_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and p.projection->'transition'->>'phase'<>'PRE_ADMISSION_DENIAL'
    order by c.sequence`,
      [...scoped, rpcStream],
    )
  ).rows;
  if (terminalCases) {
    const decisions = new Set(
      rows
        .filter(
          (row) =>
            row.projection.transition.phase === 'INTERRUPTED' ||
            (row.projection.transition.phase === 'COMMITTED' &&
              row.projection.transition.decisionEffect === 'DENY_TERMINAL'),
        )
        .map((row) => row.projection.decisionId),
    );
    assert.equal(decisions.size, 2);
    rows = rows.filter((row) => decisions.has(row.projection.decisionId));
    assert.deepEqual(
      rows.map((row) => row.projection.transition.phase),
      ['RESERVED', 'COMMITTED', 'RESERVED', 'INTERRUPTED'],
    );
    assert.equal(rows[0].projection.decisionId, rows[1].projection.decisionId);
    assert.equal(rows[2].projection.decisionId, rows[3].projection.decisionId);
  } else if (sourceReads) {
    rows.sort((a, b) => (a.record_id < b.record_id ? -1 : a.record_id > b.record_id ? 1 : 0));
    rows = rows.slice(-4);
    assert.deepEqual(
      rows.map((row) => row.projection.transition.phase),
      [
        'SOURCE_READ_STARTED',
        'SOURCE_READ_RELEASED',
        'SOURCE_READ_STARTED',
        'SOURCE_READ_RELEASED',
      ],
    );
    for (const index of [0, 2]) {
      assert.equal(rows[index].projection.decisionId, rows[index + 1].projection.decisionId);
      for (const key of ['sourceScopeDigest', 'authorityBindingDigest', 'requestDigest'])
        assert.equal(
          rows[index].projection.transition[key],
          rows[index + 1].projection.transition[key],
        );
    }
    assert.notEqual(rows[0].projection.decisionId, rows[2].projection.decisionId);
    if (requireLaterSegment)
      assert.notEqual(
        rows[2].segment_id,
        rows[3].segment_id,
        'Terminal must inhabit a later archive segment',
      );
  } else {
    assert.deepEqual(
      rows.map((row) => row.projection.transition.phase),
      ['RESERVED', 'COMMITTED', 'RELEASED'],
    );
    assert.equal(new Set(rows.map((row) => row.projection.decisionId)).size, 1);
  }
  const released = rows.at(-1),
    remaining = rows.slice(0, -1),
    reserved = remaining[0];
  const terminalFor = (row) =>
    sourceReads || terminalCases
      ? rows.find(
          (candidate) =>
            candidate.projection.decisionId === row.projection.decisionId &&
            ['SOURCE_READ_RELEASED', 'INTERRUPTED', 'COMMITTED'].includes(
              candidate.projection.transition.phase,
            ),
        )
      : released;
  const plan = async (row) => {
    const response = await api(
      `evidence-records/${urn(row.id)}/normalized-projection-deletion-plan`,
    );
    assert.equal(response.status, 200);
    return projectionDeletionPlan.parse(response.body);
  };
  const policies = async () => {
    const view = await refresh();
    assert.equal(view.retentionPoliciesUnavailable, false);
    assert.equal(view.retentionPolicies.nextCursor, null);
    return view.retentionPolicies.items.filter((p) => p.dataClass === 'NORMALIZED_JSON_PROJECTION');
  };
  const currentPolicy = async () => {
    const active = (await policies()).filter((p) => p.state === 'ACTIVE');
    assert.equal(active.length, 1);
    return active[0];
  };
  let policy;
  if (resumeActivePolicyVersion) {
    assert.equal(sourceReads || terminalCases || !!resumeRetiredPolicyVersion, false);
    policy = rpcReadResumePolicy(await policies(), resumeActivePolicyVersion);
    process.stdout.write(
      'OPENPC_RPC_RETIREMENT_RESUME|PASS|public-original-policy-chain|prior-retention-and-grace-evidence-retained|no-policy-replay\n',
    );
  } else if (resumeRetiredPolicyVersion) {
    assert.equal(resumeRetiredPolicyVersion, '1.0.0');
    const retained = await policies();
    assert.equal(
      retained.length,
      1,
      'Resume only the exact retired initial policy before any successor',
    );
    [policy] = retained;
    assert.equal(policy.policyVersion, resumeRetiredPolicyVersion);
    assert.equal(policy.state, 'RETIRED');
    process.stdout.write(
      'OPENPC_RPC_RETIREMENT_RESUME|PASS|public-retired-predecessor|no-retirement-replay\n',
    );
  } else policy = await currentPolicy();
  if (terminalCases) assert.ok(['1.0.0', '4.0.0'].includes(policy.policyVersion));
  else
    assert.equal(
      policy.policyVersion,
      sourceReads ? '4.0.0' : (resumeActivePolicyVersion ?? '1.0.0'),
      'This fresh acceptance must not replay a consumed policy intent',
    );
  if (sourceReads || terminalCases) {
    assert.equal(policy.retentionPeriodMs, '0');
    assert.equal(policy.localGraceMs, '0');
    assert.equal(policy.sinkQuorum, 1);
    assert.equal(policy.deletionMode, 'PROJECTION_DELETE');
    assert.equal(policy.makerCheckerRequired, true);
  }
  const cases =
    sourceReads || terminalCases
      ? []
      : resumeActivePolicyVersion
        ? rpcRetirementPolicyCases.slice(2)
        : rpcRetirementPolicyCases;
  for (const value of cases) {
    if (policy.state === 'ACTIVE')
      await govern(
        'Retire a retention policy version',
        { 'Resource reference': policy.retentionPolicyId, 'Expected revision': '1' },
        `Preserve normalized policy ${policy.policyVersion} as the predecessor of ${value.version}.`,
      );
    await govern(
      'Activate a retention policy version',
      rpcRetirementPolicyFields(policy.retentionPolicyId, value),
      `Govern independent normalized RPC retention, grace and archive quorum for acceptance ${value.version}.`,
    );
    policy = await currentPolicy();
    assert.equal(policy.policyVersion, value.version);
    for (const row of rows) {
      const observed = await plan(row);
      assert.deepEqual(observed.blockers, value.blockers);
      assert.equal(observed.eligible, value.blockers.length === 0);
      assert.equal(observed.selection.retentionPolicyId, policy.retentionPolicyId);
      assert.equal(observed.selection.rpcClosure.archive.sinkReceipts.length, 1);
    }
    process.stdout.write(
      `OPENPC_RPC_RETIREMENT_POLICY|PASS|version=${value.version}|retention=${value.period}|grace=${value.grace}|quorum=${value.quorum}\n`,
    );
  }
  for (const row of rows) {
    const current = await plan(row);
    assert.equal(current.eligible, true);
    assert.equal(current.selection.sourceKind, 'RPC_CLOSED_TRANSITION');
    const terminal = terminalFor(row);
    assert.equal(current.selection.rpcClosure.terminalRecordId, terminal.record_id);
    assert.equal(current.selection.rpcClosure.terminalSourceDigest, terminal.receipt_digest);
    if (sourceReads) {
      assert.equal(
        current.selection.rpcClosure.sourceScopeDigest,
        row.projection.transition.sourceScopeDigest,
      );
      assert.equal(
        current.selection.rpcClosure.authorityBindingDigest,
        row.projection.transition.authorityBindingDigest,
      );
    }
    const provenance = await api(`evidence-records/${urn(row.id)}/provenance`);
    assert.equal(provenance.body.rpc.chainFinality, 'NOT_ESTABLISHED');
    assert.equal(provenance.body.rpc.currentAuthority, 'NOT_ESTABLISHED');
  }
  // Any new incoming owner must provide clearance; absence of rows in that
  // owner's relation is not an implicit waiver. This exact empty test relation
  // is removed in finally; PostgreSQL forbids temp-to-permanent foreign keys.
  const referenceTable = `public.rpc_retirement_ref_${uuidv7().replaceAll('-', '')}`;
  await pool.query(`create table ${referenceTable}(participant_id uuid,privacy_domain_id uuid,stream_id text,record_id text,
    foreign key(participant_id,privacy_domain_id,stream_id,record_id) references control.evidence_rpc_provenance(participant_id,privacy_domain_id,stream_id,record_id))`);
  try {
    assert.ok((await plan(released)).blockers.includes('REFERENCES'));
  } finally {
    await pool.query(`drop table ${referenceTable}`);
  }
  const hold = await govern(
    'Preserve evidence under a hold',
    {
      'Hold kind': 'LEGAL',
      'Evidence to preserve': 'DIGEST',
      'Receipt digest': released.receipt_digest,
    },
    'Preserve the exact completion witness before normalized retirement.',
  );
  for (const row of rows) {
    const held = (await plan(row)).blockers.includes('ACTIVE_HOLD');
    const terminalRow = terminalFor(row);
    assert.equal(
      held,
      row.segment_id === released.segment_id || terminalRow.segment_id === released.segment_id,
    );
  }
  await govern(
    'Release an evidence hold',
    { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
    'Release this exact completed-read witness hold.',
  );
  const item = await recordItem(released);
  const selected = projectionDeletionPlan.parse(
    await inspect(
      item.getByRole('button', {
        name: `Review normalized projection deletion for sequence ${released.sequence}`,
        exact: true,
      }),
    ),
  );
  assert.equal(selected.eligible, true);
  assert.equal(selected.selection.targets.length, 1);
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText(`RPC completion witness: ${released.projection.transition.phase}`);
  await maker.screenshot({
    path: join(artifacts, 'closed-rpc-completion-witness.png'),
    fullPage: true,
  });
  const snapshot = async () => ({
    projections: (
      await pool.query(
        `select p.record_id,p.projection,p.projection_digest from control.evidence_rpc_provenance p
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.stream_id=$3 order by p.record_id`,
        [...scoped, rpcStream],
      )
    ).rows,
    jobs: (
      await pool.query(
        'select * from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by deletion_job_id',
        [...scoped, rpcStream],
      )
    ).rows,
    retirements: (
      await pool.query(
        'select * from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by deletion_job_id',
        [...scoped, rpcStream],
      )
    ).rows,
  });
  const before = await snapshot();
  const failed = await governThroughWorkbench({
    maker,
    checker,
    checkerId: actors.checker.principalId,
    label: 'Delete normalized evidence projections',
    fields: { 'Starting evidence reference': urn(released.id) },
    reason:
      'Retire the archived read completion projection while preserving its original journal and custody.',
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
  const terminal = await retryDeletion(maker, failed.approvalId, { loseResponse: true });
  await verify(terminal.result);
  assert.equal((await continueFrom(terminal.result)).continuationState, 'COMPLETE');
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
  assert.deepEqual((await readWorkbenchApproval(maker, failed.approvalId)).result, terminal.result);
  await runWorker();
  assert.equal(
    (await api(`evidence-records/${urn(released.id)}/provenance`)).body.status,
    'PROJECTION_RETIRED',
  );
  // The original terminal row is now physically absent. Its signed retirement
  // witness must still authorize only the matching historical transitions.
  const initial = await plan(reserved);
  assert.equal(initial.eligible, true);
  assert.deepEqual(
    initial.selection.targets.map((t) => t.recordId),
    remaining.map((row) => row.record_id).sort(),
  );
  const first = await govern(
    'Delete normalized evidence projections',
    { 'Starting evidence reference': urn(reserved.id) },
    'Retire the closed reservation using its already retired, receipt-bound terminal witness.',
  );
  await verify(first.completed.result);
  let result = first.completed.result;
  for (const row of remaining.slice(1)) {
    const next = await continueFrom(result);
    assert.equal(next.continuationState, 'READY');
    assert.equal(next.selection.recordId, row.record_id);
    const nextBatch = await govern(
      'Continue projection deletion',
      { 'Previous projection deletion result': result.deletionJobId },
      'Continue the fixed read selection using its exact archived completion witness.',
    );
    result = nextBatch.completed.result;
    await verify(result);
  }
  assert.equal((await continueFrom(result)).continuationState, 'COMPLETE');
  await runWorker();
  assert.equal(
    (await snapshot()).projections.some((r) =>
      rows.some((original) => original.record_id === r.record_id),
    ),
    false,
  );
  for (const row of rows) {
    const provenance = await api(`evidence-records/${urn(row.id)}/provenance`);
    assert.equal(provenance.body.status, 'PROJECTION_RETIRED');
    assert.equal(provenance.body.rpc, null);
  }
  await preserve();
  const later = await govern(
    'Preserve evidence under a hold',
    {
      'Hold kind': 'INCIDENT',
      'Evidence to preserve': 'DIGEST',
      'Receipt digest': released.receipt_digest,
    },
    'Verify original read evidence remains preservable after the normalized retirements.',
  );
  await runWorker();
  assert.equal(
    (await api(`evidence-holds/${later.completed.result.holdId}`)).body.coverage,
    'VERIFIED',
  );
  await govern(
    'Release an evidence hold',
    { 'Resource reference': later.completed.result.holdId, 'Expected revision': '1' },
    'Release this exact post-retirement archive hold.',
  );
  await runWorker();
  for (const context of [
    { participantId: uuidv7() },
    { privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
  ]) {
    const denied = await api(
      `evidence-deletions/${result.deletionJobId}/projection-continuation-plan`,
      context,
    );
    assert.ok(denied.status >= 400);
    assert.equal(JSON.stringify(denied.body).includes(released.receipt_digest), false);
  }
  await refresh();
  await continueFrom(result);
  await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
  await maker.keyboard.press('Enter');
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText('Selection complete.');
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await maker.screenshot({
    path: join(artifacts, 'closed-rpc-retirement-desktop.png'),
    fullPage: true,
  });
  await maker.setViewportSize({ width: 360, height: 880 });
  assert.equal(
    await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
  );
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await maker.screenshot({
    path: join(artifacts, 'closed-rpc-retirement-reflow.png'),
    fullPage: true,
  });
  process.stdout.write(
    `OPENPC_RPC_RETIREMENT_BROWSER|PASS|family=${terminalCases ? 'NO_FORWARD_AND_INTERRUPTED' : sourceReads ? 'SOURCE_READ' : 'READ'}|effects=${rows.length}|later-segment=${rows.some((row) => row.segment_id !== terminalFor(row).segment_id)}|terminal-first|hold-reference-denials|signer-failure-no-effect|signed-continuation|lost-ack|restart|no-resurrection|original-custody|privacy|keyboard|axe|reflow\n`,
  );
  return rows.map((row) => row.record_id).sort();
}
