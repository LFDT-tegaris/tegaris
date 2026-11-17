import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { localEvidenceDeletionPlan } from '../../../services/control-api/src/evidence/deletion-contracts.ts';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.ts';
import { readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { transactionCandidate } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';

export function assertRpcRetirementCandidate(
  approval,
  plan,
  kind,
  reason,
  participantId,
  state = 'APPROVED',
) {
  assert.equal(approval.candidate.state, state);
  if (state === 'APPROVED') assert.equal(approval.candidate.operationRef, null);
  const expected = transactionCandidate(
    kind,
    { selection: plan.selection, beforeDigest: plan.beforeDigest },
    reason,
    participantId,
  );
  assert.equal(approval.candidate.actionIntentId, expected.operation.actionIntentId);
  assert.deepEqual(
    approval.candidate.candidate,
    expected.body,
    'Approved candidate must preserve the complete inspected native selection',
  );
}

export function assertRpcRetirementPrivacyDenial(response, scopedValues) {
  assert.ok(
    response.status === 403 || response.status === 404,
    'An outage or invalid session is not a privacy denial',
  );
  const body = response.body;
  assert.deepEqual(Object.keys(body).sort(), [
    'code',
    'retryable',
    'status',
    'title',
    'traceId',
    'truthState',
    'type',
  ]);
  assert.equal(body.status, response.status);
  assert.equal(body.code, 'PC-AUTH-0005');
  assert.equal(body.truthState, 'DENIED');
  assert.equal(body.retryable, false);
  assert.equal(body.type, 'https://errors.openpc.local/hidden-or-not-found');
  assert.equal(body.title, 'Resource is unavailable');
  assert.equal(typeof body.traceId, 'string');
  assert.match(
    body.traceId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  const encoded = JSON.stringify(body);
  for (const value of scopedValues)
    assert.equal(
      encoded.includes(value),
      false,
      'Privacy denial must not disclose a scoped identifier',
    );
}

export function rpcPayloadRetirementInputs(recordIds) {
  assert.ok(Array.isArray(recordIds) && recordIds.length > 0 && recordIds.length <= 16);
  for (const [index, value] of recordIds.entries()) {
    assert.match(value, /^rpc:[0-9a-f]{64}:[1-9][0-9]{0,19}$/u);
    assert.ok(BigInt(value.split(':')[2]) <= 18446744073709551615n);
    if (index) assert.ok(value > recordIds[index - 1]);
  }
  return [...recordIds];
}

export function rpcPayloadRetirementReadbackInputs(
  recordIds,
  payloadApprovalId,
  searchApprovalIds,
) {
  if (searchApprovalIds === undefined) return false;
  const selected = rpcPayloadRetirementInputs(recordIds);
  const approvalId = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  assert.match(payloadApprovalId, approvalId);
  assert.ok(Array.isArray(searchApprovalIds));
  assert.equal(searchApprovalIds.length, selected.length);
  for (const id of searchApprovalIds) assert.match(id, approvalId);
  assert.equal(new Set([payloadApprovalId, ...searchApprovalIds]).size, selected.length + 1);
  return true;
}

/** Keep each native fixed sequence intact. A requested record behind an
 * unrequested member needs a separate starting-record proposal, never a skip. */
export function rpcSearchRetirementPrefix(targets, records) {
  assert.ok(Array.isArray(targets) && targets.length > 0);
  assert.ok(Array.isArray(records) && records.length > 0);
  const wanted = new Map(
    records.map((record) => [record.record_id, `urn:openpc:resource:${record.id}`]),
  );
  assert.equal(wanted.size, records.length);
  const prefix = [];
  for (const target of targets) {
    if (!wanted.has(target.recordId)) break;
    assert.equal(
      target.recordId,
      records[prefix.length]?.record_id,
      'Native requested prefix must preserve original record order',
    );
    assert.equal(
      target.evidenceId,
      wanted.get(target.recordId),
      'Native target must refer to the original evidence record',
    );
    prefix.push(target);
  }
  assert.ok(
    prefix.length > 0,
    'Native sequence does not start with the next requested original record',
  );
  return prefix;
}

/** Continue already governed normalized retirement through the two independent
 * physical owners. Exact source identities come from the original RPC journey;
 * this helper neither sends RPC nor repeats normalized retirement. A partially
 * consumed invocation requires reconciliation of its original jobs, not rerun. */
export async function rpcPayloadSearchRetirementBrowser({
  recordIds,
  desktopOnly = false,
  resumePayloadApprovalId,
  resumeSearchApprovalIds,
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
  assert.equal(typeof desktopOnly, 'boolean');
  const selectedIds = rpcPayloadRetirementInputs(recordIds);
  rpcPayloadRetirementReadbackInputs(recordIds, resumePayloadApprovalId, resumeSearchApprovalIds);
  const urn = (id) => `urn:openpc:resource:${id}`;
  const query = async (sql, values = scoped) => (await pool.query(sql, values)).rows;
  assert.equal(configuration.scopes.length, 1);
  assert.equal(configuration.scopes[0].source, 'RPC');
  assert.equal(configuration.scopes[0].streamId, streamId);
  const records = await query(
    resumeSearchApprovalIds
      ? `select evidence_id::text id,record_id,source_receipt_digest receipt_digest,sequence::text sequence,segment_id::text segment_id
       from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 and record_id=any($4::text[]) and data_class='SEARCH_PROJECTION' order by record_id`
      : `select evidence_id::text id,record_id,receipt_digest,sequence::text sequence,segment_id::text segment_id
       from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 and record_id=any($4::text[]) order by record_id`,
    [...scoped, streamId, selectedIds],
  );
  assert.deepEqual(
    records.map((row) => row.record_id),
    selectedIds,
    'Missing original catalogue rows require original-job readback; never select replacement RPC',
  );
  const segmentId = records[0].segment_id;
  assert.ok(records.every((row) => row.segment_id === segmentId));
  const recordUuids = records.map((row) => row.id);
  const targetValues = [...scoped, streamId, segmentId];
  if (resumePayloadApprovalId !== undefined)
    assert.match(
      resumePayloadApprovalId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
  const jobs = await query(
    `select deletion_job_id::text,approval_request_id::text,operation_id::text,state,target_data_class,selection,before_digest
     from control.deletion_job where participant_id=$1 and privacy_domain_id=$2
     and stream_id=$3 and segment_id=$4 and target_data_class in ('AUDIT_EVIDENCE','SEARCH_PROJECTION')`,
    targetValues,
  );
  assert.equal(
    jobs.length,
    resumeSearchApprovalIds ? records.length + 1 : resumePayloadApprovalId ? 1 : 0,
    'Unexpected original effects require reconciliation, never replacement intent',
  );
  const originalPayload = jobs.find((row) => row.target_data_class === 'AUDIT_EVIDENCE');
  if (resumePayloadApprovalId) assert.ok(originalPayload);
  if (originalPayload) {
    assert.equal(originalPayload.approval_request_id, resumePayloadApprovalId);
    assert.equal(originalPayload.target_data_class, 'AUDIT_EVIDENCE');
    assert.equal(originalPayload.state, 'SUCCEEDED');
    assert.equal(originalPayload.selection.segmentId, segmentId);
    assert.equal(originalPayload.selection.recordCount, records.length);
    assert.deepEqual(
      originalPayload.selection.sourceRpcRetirements.map((row) => row.recordId),
      selectedIds,
    );
  }
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_rpc_provenance where participant_id=$1
     and privacy_domain_id=$2 and stream_id=$3 and record_id=any($4::text[])`,
        [...scoped, streamId, selectedIds],
      )
    )[0].n,
    0,
    'Every selected normalized RPC projection must already be retired',
  );

  const originalJobIds = (
    await query(
      'select deletion_job_id::text id from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 order by deletion_job_id',
    )
  ).map((row) => row.id);
  const original = async () => ({
    historicalJobs: await query(
      `select to_jsonb(j) job,to_jsonb(a) receipt from control.deletion_job j
       left join control.audit_occurrence a using(participant_id,privacy_domain_id,operation_id)
       where j.participant_id=$1 and j.privacy_domain_id=$2 and j.deletion_job_id=any($3::uuid[]) order by j.deletion_job_id`,
      [...scoped, originalJobIds],
    ),
    historicalItems: await query(
      `select * from control.evidence_deletion_item where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=any($3::uuid[]) order by deletion_job_id,segment_id`,
      [...scoped, originalJobIds],
    ),
    completedEffects: resumeSearchApprovalIds
      ? await query(
          `select to_jsonb(j) job,to_jsonb(a) receipt from control.deletion_job j
        join control.audit_occurrence a using(participant_id,privacy_domain_id,operation_id)
        where j.participant_id=$1 and j.privacy_domain_id=$2 and j.stream_id=$3 and j.segment_id=$4
        and j.target_data_class in ('AUDIT_EVIDENCE','SEARCH_PROJECTION') order by j.deletion_job_id`,
          targetValues,
        )
      : undefined,
    normalized: await query(
      `select r.* from control.evidence_projection_retirement r where participant_id=$1
       and privacy_domain_id=$2 and stream_id=$3 and data_class='NORMALIZED_JSON_PROJECTION'
       and record_id=any($4::text[]) order by record_id`,
      [...scoped, streamId, selectedIds],
    ),
    signed: await query(
      `select a.* from control.evidence_projection_retirement r
       join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
       join control.audit_occurrence a on a.participant_id=j.participant_id and a.privacy_domain_id=j.privacy_domain_id
        and a.operation_id=j.operation_id
       where r.participant_id=$1 and r.privacy_domain_id=$2 and r.stream_id=$3
        and r.data_class='NORMALIZED_JSON_PROJECTION' and r.record_id=any($4::text[])
       order by r.record_id`,
      [...scoped, streamId, selectedIds],
    ),
    siblings: await query(
      `select * from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 and not(evidence_id=any($4::uuid[])) order by record_id`,
      [...scoped, streamId, recordUuids],
    ),
    otherPayloads: await query(
      `select * from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 and segment_id<>$4 order by segment_id`,
      targetValues,
    ),
    segments: await query(
      `select * from control.evidence_segment where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 order by segment_id`,
      [...scoped, streamId],
    ),
    checkpoints: await query(
      `select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2
       and stream_id=$3 order by sink_id,through_sequence`,
      [...scoped, streamId],
    ),
  });
  const before = await original();
  assert.equal(before.historicalJobs.length, originalJobIds.length);
  assert.equal(before.normalized.length, records.length);
  assert.equal(before.signed.length, records.length);
  for (const row of before.signed) {
    const receipt = decodeAdmittedReceipt(row.receipt_cbor);
    assert.equal(receipt.transitionProfileId, 'pc.control.evidence-deletion.projection');
    assert.equal(receipt.transitionProfileVersion, 1);
  }
  const vault = await LocalEvidenceVault.open(configuration.vaultDirectory, configuration.sinkId);
  const archived = await Promise.all(
    before.checkpoints.map((row) => vault.read(row.receipt.object)),
  );
  assert.ok(archived.length > 0);
  const preserve = async () => {
    assert.deepEqual(await original(), before);
    for (const [index, row] of before.checkpoints.entries())
      assert.deepEqual(await vault.read(row.receipt.object), archived[index]);
  };
  const view = await refresh();
  assert.equal(view.retentionPoliciesUnavailable, false);
  for (const dataClass of ['AUDIT_EVIDENCE', 'SEARCH_PROJECTION'])
    assert.equal(
      view.retentionPolicies.items.filter((p) => p.dataClass === dataClass && p.state === 'ACTIVE')
        .length,
      1,
    );
  let local;
  let payloadSelection;
  if (originalPayload) {
    // Recover the consumed original through its public owner; never resubmit it.
    const completed = await readWorkbenchApproval(maker, resumePayloadApprovalId);
    assert.equal(completed.candidate.state, 'CONSUMED');
    assert.equal(completed.result.operationId, originalPayload.operation_id);
    assert.equal(completed.result.deletionJobId, urn(originalPayload.deletion_job_id));
    assertRpcRetirementCandidate(
      completed,
      { selection: originalPayload.selection, beforeDigest: originalPayload.before_digest },
      'evidence-deletion',
      completed.candidate.candidate.reason,
      scoped[0],
      'CONSUMED',
    );
    local = { approvalId: resumePayloadApprovalId, completed };
    payloadSelection = originalPayload.selection;
  } else {
    const payload = await api(`evidence-records/${urn(records[0].id)}/deletion-plan`);
    assert.equal(payload.status, 200);
    const payloadPlan = localEvidenceDeletionPlan.parse(payload.body);
    assert.equal(
      payloadPlan.eligible,
      true,
      `Original RPC payload remains blocked: ${JSON.stringify({
        evidenceId: payloadPlan.evidenceId,
        blockers: payloadPlan.blockers,
        segmentId: payloadPlan.selection?.segmentId,
        firstSequence: payloadPlan.selection?.firstSequence,
        throughSequence: payloadPlan.selection?.throughSequence,
        recordCount: payloadPlan.selection?.recordCount,
        eligibleAfterMicros: payloadPlan.selection?.eligibleAfterMicros,
      })}`,
    );
    payloadSelection = payloadPlan.selection;
    assert.equal(payloadSelection.segmentId, segmentId);
    assert.equal(payloadSelection.recordCount, records.length);
    assert.deepEqual(
      payloadSelection.sourceRpcRetirements.map((p) => p.recordId),
      selectedIds,
    );
    assert.equal(payloadSelection.sourceRejections, undefined);
    const blocked = await api(
      `evidence-records/${urn(records[0].id)}/search-projection-deletion-plan`,
    );
    assert.equal(blocked.status, 200);
    assert.ok(projectionDeletionPlan.parse(blocked.body).blockers.includes('REFERENCES'));
    const reason =
      'Retire only the original RPC local ciphertext after its governed normalized retirement.';
    local = await govern(
      'Delete a local evidence payload',
      { 'Evidence record reference': urn(records[0].id) },
      reason,
      true,
      (approved) =>
        assertRpcRetirementCandidate(approved, payloadPlan, 'evidence-deletion', reason, scoped[0]),
    );
  }
  const receiptRows = await query(
    `select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a
     join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3`,
    [...scoped, local.completed.result.operationId],
  );
  assert.equal(receiptRows.length, 1);
  const signed = receiptRows[0];
  assert.equal(
    verifyReceiptCose(signed.public_key_spki_der, signed.receipt_cbor, signed.cose_sign1),
    true,
  );
  const receipt = decodeAdmittedReceipt(signed.receipt_cbor);
  assert.equal(receipt.transitionProfileId, 'pc.control.evidence-deletion.local');
  assert.equal(receipt.transitionProfileVersion, 2);
  assert.equal(local.completed.result.deletedBytes, String(payloadSelection.ciphertextBytes));
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_segment_payload where participant_id=$1
     and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
        targetValues,
      )
    )[0].n,
    0,
  );
  await preserve();
  const batches = [];
  const groups = [];
  const wantedIds = new Set(selectedIds);
  const verifySearchReceipt = async (result) => {
    await verify(result.completed.result);
    const [stored] = await query(
      `select receipt_cbor from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
      [...scoped, result.completed.result.operationId],
    );
    assert.equal(decodeAdmittedReceipt(stored.receipt_cbor).transitionProfileVersion, 3);
  };
  const verifyBoundary = async (group) => {
    const next = await continueFrom(group.last.completed.result);
    const tail = group.targets.slice(group.prefixLength);
    assert.equal(next.continuationState, tail.length ? 'BLOCKED' : 'COMPLETE');
    if (tail.length) {
      assert.equal(next.eligible, false);
      assert.ok(next.blockers.includes('REFERENCES'));
      assert.deepEqual(next.selection.targets, group.targets);
      assert.equal(next.selection.evidenceId, tail[0].evidenceId);
      await expect(
        maker.getByRole('button', { name: 'Prepare next deletion batch', exact: true }),
      ).toHaveCount(0);
    }
  };
  if (resumeSearchApprovalIds) {
    // Read each consumed original in its recorded execution order. Independent
    // fixed sequences may each start at batch zero; none may be replayed.
    const byApproval = new Map(
      jobs
        .filter((row) => row.target_data_class === 'SEARCH_PROJECTION')
        .map((row) => [row.approval_request_id, row]),
    );
    const searchJobs = resumeSearchApprovalIds.map((id) => byApproval.get(id));
    assert.ok(searchJobs.every(Boolean));
    assert.deepEqual(
      searchJobs.map((row) => row.selection.recordId),
      selectedIds,
    );
    let group;
    for (const [index, job] of searchJobs.entries()) {
      assert.equal(job.state, 'SUCCEEDED');
      assert.equal(job.selection.sourceKind, 'RPC_RETIRED_CATALOGUE');
      if (job.selection.batchIndex === 0) {
        if (group) assert.equal(group.count, group.prefixLength);
        const prefix = rpcSearchRetirementPrefix(job.selection.targets, records.slice(index));
        group = {
          targets: job.selection.targets,
          prefixLength: prefix.length,
          count: 0,
          last: undefined,
        };
        groups.push(group);
      }
      assert.ok(group);
      assert.equal(job.selection.batchIndex, group.count);
      assert.deepEqual(job.selection.targets, group.targets);
      assert.deepEqual(
        job.selection.priorCursor,
        group.last
          ? {
              deletionJobId: group.last.completed.result.deletionJobId,
              receiptDigest: group.last.completed.result.receiptDigest,
            }
          : null,
      );
      const completed = await readWorkbenchApproval(maker, job.approval_request_id);
      assert.equal(completed.candidate.state, 'CONSUMED');
      assert.equal(completed.result.operationId, job.operation_id);
      assert.equal(completed.result.deletionJobId, urn(job.deletion_job_id));
      assertRpcRetirementCandidate(
        completed,
        { selection: job.selection, beforeDigest: job.before_digest },
        job.selection.priorCursor
          ? 'evidence-deletion-projection-continuation'
          : 'evidence-deletion-search',
        completed.candidate.candidate.reason,
        scoped[0],
        'CONSUMED',
      );
      const result = { approvalId: job.approval_request_id, completed };
      await verifySearchReceipt(result);
      batches.push(result);
      group.last = result;
      group.count++;
    }
    assert.equal(group.count, group.prefixLength);
    for (const current of groups) await verifyBoundary(current);
  } else {
    let offset = 0;
    while (offset < records.length) {
      const record = records[offset];
      const item = await recordItem(record);
      const plan = projectionDeletionPlan.parse(
        await inspect(
          item.getByRole('button', {
            name: `Review search projection deletion for sequence ${record.sequence}`,
            exact: true,
          }),
        ),
      );
      assert.equal(plan.eligible, true);
      assert.equal(plan.selection.sourceKind, 'RPC_RETIRED_CATALOGUE');
      const prefix = rpcSearchRetirementPrefix(plan.selection.targets, records.slice(offset));
      const group = {
        targets: plan.selection.targets,
        prefixLength: prefix.length,
        last: undefined,
      };
      groups.push(group);
      for (const target of group.targets.slice(prefix.length)) {
        if (wantedIds.has(target.recordId)) continue;
        assert.ok(before.siblings.some((row) => urn(row.evidence_id) === target.evidenceId));
        const response = await api(
          `evidence-records/${target.evidenceId}/search-projection-deletion-plan`,
        );
        assert.equal(response.status, 200);
        const siblingPlan = projectionDeletionPlan.parse(response.body);
        assert.equal(siblingPlan.eligible, false);
        assert.ok(siblingPlan.blockers.includes('REFERENCES'));
      }
      await maker
        .getByRole('button', { name: 'Prepare first deletion batch', exact: true })
        .click();
      let currentPlan = plan;
      for (let index = 0; index < prefix.length; index++) {
        const previous = group.last;
        assert.equal(currentPlan.selection.batchIndex, index);
        assert.equal(currentPlan.selection.recordId, prefix[index].recordId);
        assert.deepEqual(currentPlan.selection.targets, group.targets);
        assert.deepEqual(
          currentPlan.selection.priorCursor,
          previous
            ? {
                deletionJobId: previous.completed.result.deletionJobId,
                receiptDigest: previous.completed.result.receiptDigest,
              }
            : null,
        );
        const reason =
          'Retire only the next requested original record; preserve the native fixed selection and its unrequested members.';
        const result = await govern(
          previous ? 'Continue projection deletion' : 'Delete search projections',
          previous
            ? { 'Previous projection deletion result': previous.completed.result.deletionJobId }
            : { 'Starting catalogue evidence reference': urn(record.id) },
          reason,
          index === 0,
          (approved) =>
            assertRpcRetirementCandidate(
              approved,
              currentPlan,
              previous ? 'evidence-deletion-projection-continuation' : 'evidence-deletion-search',
              reason,
              scoped[0],
            ),
        );
        await verifySearchReceipt(result);
        const next = await continueFrom(result.completed.result);
        if (index < prefix.length - 1) {
          assert.equal(next.continuationState, 'READY');
          assert.equal(next.selection.recordId, prefix[index + 1].recordId);
        }
        if (next.selection) assert.deepEqual(next.selection.targets, group.targets);
        currentPlan = next;
        batches.push(result);
        group.last = result;
        await preserve();
      }
      await verifyBoundary(group);
      offset += prefix.length;
    }
  }
  assert.equal(batches.length, records.length);
  const protectedGroup = groups.find((group) => group.targets.length > group.prefixLength);
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
  // A restart can interrupt a component's automatic read. Reopen the page
  // after readiness and recover the original IDs through the ordinary UI.
  await maker.reload({ waitUntil: 'domcontentloaded' });
  // The ordinary read helper opens the recovery panel after the page reload.
  for (const result of [local, ...batches])
    assert.deepEqual(
      (await readWorkbenchApproval(maker, result.approvalId)).result,
      result.completed.result,
    );
  await runWorker();
  await preserve();
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_catalogue where participant_id=$1
     and privacy_domain_id=$2 and evidence_id=any($3::uuid[])`,
        [...scoped, recordUuids],
      )
    )[0].n,
    0,
  );
  assert.equal(
    (
      await query(
        `select count(*)::int n from control.evidence_segment_payload where participant_id=$1
     and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
        targetValues,
      )
    )[0].n,
    0,
  );
  const last = batches.at(-1).completed.result;
  const denied = await api(
    `evidence-deletions/${last.deletionJobId}/projection-continuation-plan`,
    {
      privacyDomainId: foreignPrivacyDomainId,
    },
  );
  assertRpcRetirementPrivacyDenial(denied, [
    last.deletionJobId,
    last.operationId,
    last.receiptDigest,
    scoped[0],
    scoped[1],
    streamId,
    segmentId,
    ...records.flatMap((row) => [row.id, row.record_id, row.receipt_digest]),
  ]);
  await continueFrom(protectedGroup?.last.completed.result ?? last);
  await maker.getByRole('button', { name: 'Refresh deletion eligibility', exact: true }).focus();
  await maker.keyboard.press('Enter');
  await expect(
    maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
  ).toContainText(
    protectedGroup ? 'References must be cleared by their owning process.' : 'Selection complete.',
  );
  const resultItem = maker
    .getByRole('region', { name: 'Local deletion results', exact: true })
    .getByRole('listitem')
    .filter({ hasText: last.deletionJobId });
  if (process.env.OPENPC_EVALUATION_UI === '1') {
    const results = maker.getByRole('region', { name: 'Local deletion results', exact: true });
    const source = await api('evidence-deletions?limit=50');
    assert.equal(source.status, 200);
    assert.ok(source.body.items.length > 6, 'History navigation needs more than one real page');
    const expected = source.body.items.map((item) => `Deletion reference: ${item.deletionJobId}`);
    const seen = [];
    const next = results.getByRole('button', { name: 'Next results', exact: true });
    for (let page = 0; page < Math.ceil(expected.length / 6); page++) {
      const entries = results.getByRole('listitem');
      const count = await entries.count();
      assert.equal(count, Math.min(6, expected.length - page * 6));
      seen.push(
        ...(await entries
          .locator('p')
          .filter({ hasText: /^Deletion reference:/u })
          .allTextContents()),
      );
      if (page + 1 === Math.ceil(expected.length / 6)) await expect(next).toBeDisabled();
      else {
        await expect(next).toBeEnabled();
        await next.focus();
        await maker.keyboard.press('Enter');
      }
    }
    assert.deepEqual(seen, expected, 'Every loaded native result must appear once in owner order');
    const previous = results.getByRole('button', { name: 'Previous results', exact: true });
    for (
      let page = 0;
      !(await resultItem.count()) && page < Math.ceil(expected.length / 6);
      page++
    ) {
      await expect(previous).toBeEnabled();
      await previous.focus();
      await maker.keyboard.press('Enter');
    }
    await expect(resultItem).toHaveCount(1);
  }
  await expect(resultItem).toHaveCount(1);
  await expect(resultItem.getByText('Completed', { exact: true })).toBeVisible();
  await expect(resultItem.getByRole('heading')).toContainText('Search index');
  await expect(
    resultItem.getByRole('button', { name: 'Read signed continuation', exact: true }),
  ).toBeVisible();
  const auditSummary = resultItem.locator('details > summary').filter({
    hasText: /^Deletion audit details$/u,
  });
  const auditReceipt = resultItem.getByText(`Signed receipt: ${last.receiptDigest}`, {
    exact: true,
  });
  await expect(auditReceipt).not.toBeVisible();
  await auditSummary.focus();
  await maker.keyboard.press('Enter');
  await expect(auditReceipt).toBeVisible();
  await expect(resultItem.getByText(`Before: ${last.beforeDigest}`, { exact: true })).toBeVisible();
  await expect(resultItem.getByText(`After: ${last.afterDigest}`, { exact: true })).toBeVisible();
  await maker.keyboard.press('Enter');
  await expect(auditReceipt).not.toBeVisible();
  if (process.env.OPENPC_EVALUATION_UI === '1') {
    const tasks = maker.getByRole('navigation', { name: 'Evidence tasks', exact: true });
    if (await tasks.count()) {
      await tasks.getByRole('button', { name: 'Retention & holds', exact: true }).focus();
      await maker.keyboard.press('Enter');
    }
    const holds = maker.getByRole('region', { name: 'Preservation holds', exact: true });
    const inventory = holds.locator('details > summary').filter({
      hasText: /^Review preservation holds$/u,
    });
    await expect(inventory.locator('..')).not.toHaveAttribute('open', '');
    await inventory.focus();
    await maker.keyboard.press('Enter');
    const holdAudit = holds
      .locator('details > summary')
      .filter({
        hasText: /^Hold audit details$/u,
      })
      .first();
    const holdReference = holdAudit.locator('..').getByText(/^Hold reference:/u);
    await expect(holdReference).not.toBeVisible();
    await holdAudit.focus();
    await maker.keyboard.press('Enter');
    await expect(holdReference).toBeVisible();
    await maker.keyboard.press('Enter');
    await expect(holdReference).not.toBeVisible();
    await inventory.focus();
    await maker.keyboard.press('Enter');
    await expect(holds.getByText(/Active holds on this page:/u)).toBeVisible();
    if (await tasks.count()) {
      await tasks.getByRole('button', { name: 'Data removal', exact: true }).focus();
      await maker.keyboard.press('Enter');
    }
    const eligibility = maker.getByRole('region', {
      name: 'Local deletion eligibility',
      exact: true,
    });
    const selection = eligibility.locator('details > summary').filter({
      hasText: /^Selection and archive details$/u,
    });
    const reference = selection.locator('..').getByText(/^Evidence reference:/u);
    await expect(reference).not.toBeVisible();
    await selection.focus();
    await maker.keyboard.press('Enter');
    await expect(reference).toBeVisible();
    await maker.keyboard.press('Enter');
    await expect(reference).not.toBeVisible();
    const batch = eligibility.locator('details > summary').filter({
      hasText: /^Objects in this signed batch$/u,
    });
    if (await batch.count()) {
      const targets = batch.locator('..').getByRole('list', { includeHidden: true });
      await expect(targets).toHaveCount(1);
      await expect(targets).not.toBeVisible();
      const count = await targets.getByRole('listitem', { includeHidden: true }).count();
      assert.ok(count > 0);
      await batch.focus();
      await maker.keyboard.press('Enter');
      await expect(targets).toBeVisible();
      assert.equal(await targets.getByRole('listitem').count(), count);
      await maker.keyboard.press('Enter');
      await expect(targets).not.toBeVisible();
    }
  }
  await maker.setViewportSize({ width: 1440, height: 1000 });
  assert.equal(
    await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
  );
  assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
  await resultItem.evaluate((element) => element.scrollIntoView({ block: 'center' }));
  await maker.screenshot({ path: join(artifacts, 'rpc-retirement-results-desktop.png') });
  if (!desktopOnly) {
    await maker.setViewportSize({ width: 390, height: 880 });
    assert.equal(
      await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
    await resultItem.evaluate((element) => element.scrollIntoView({ block: 'center' }));
    await maker.screenshot({ path: join(artifacts, 'rpc-retirement-results-mobile.png') });
  }
  await maker.screenshot({
    path: join(artifacts, 'rpc-payload-search-retired.png'),
    fullPage: true,
  });
  process.stdout.write(
    `OPENPC_RPC_PAYLOAD_SEARCH_BROWSER|PASS|mode=${resumeSearchApprovalIds ? 'ORIGINAL_READBACK' : 'EXECUTE_PREFIX'}|original-normalized-proof|payload-v2|search-v3|signed-continuation|requested-prefix-only|protected-siblings|original-readback|lost-response|restart|no-resurrection|archive-preserved|privacy|keyboard|desktop-reflow|desktop-axe|mobile=${desktopOnly ? 'DEFERRED' : 'PASS'}\n`,
  );
}

/** The ordinary clean journey temporarily selects the distinct initial local
 * signing identity for these newer receipt families. Existing authority is
 * neither extended nor renewed. The caller retains the root/heavy locks. */
export async function withRpcPayloadRetirementSigning(inputs, run) {
  rpcPayloadRetirementInputs(inputs.recordIds);
  return withRpcRetirementSigning(inputs, run);
}

// Prepare every version before any retirement proposal. Catalogue operations
// are shared by old and new versions, so later absence is never initial trust.
export async function prepareRpcRetirementSigningTrust(inputs) {
  return withRpcRetirementSigning(inputs, async () => {
    const exec = promisify(execFile);
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/business-signing-bootstrap.mjs',
        inputs.secretRoot,
        '018f0000-0000-7000-8000-000000000101',
        inputs.privacyDomainId,
        '--rpc-retirement-trust',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  });
}

async function withRpcRetirementSigning({ secretRoot, dataRoot, compose, privacyDomainId }, run) {
  const exec = promisify(execFile);
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  assert.match(privacyDomainId, /^[0-9a-f-]{36}$/u);
  const root = resolve(dirname(secretRoot));
  assert.equal(resolve(dataRoot), join(root, 'data'));
  assert.equal(resolve(secretRoot), join(root, 'secrets'));
  const network = process.env;
  assert.equal(network.OPENPC_LOCAL_RUNTIME_NETWORK_ROOT, root);
  const project = compose[compose.indexOf('-p') + 1];
  assert.ok(compose.includes('-p'));
  assert.equal(
    (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8')).trim(),
    `openpc-local-runtime:${project}:${network.OPENPC_LOCAL_RUNTIME_NETWORK_OWNER}`,
  );
  const call = (command, args) => exec(command, args, { timeout: 90000, maxBuffer: 1048576 });
  const config = async (command) =>
    JSON.parse(
      (
        await call(command[0], [
          ...command.slice(1),
          '--profile',
          'astra05',
          'config',
          '--format',
          'json',
        ])
      ).stdout,
    );
  const guard = async (command) => {
    const rendered = await config(command);
    try {
      execFileSync(
        process.execPath,
        [
          'scripts/maintenance/local-runtime-network.mjs',
          'before',
          root,
          project,
          network.OPENPC_LOCAL_RUNTIME_NETWORK_OWNER,
          network.OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET,
          network.OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY,
          'retained',
        ],
        { input: JSON.stringify(rendered), stdio: ['pipe', 'pipe', 'pipe'] },
      );
    } catch (error) {
      // The guard argv contains the root ownership token. Keep only its closed
      // diagnostic, never the subprocess command or environment in a failure.
      const diagnostic = String(error.stderr ?? '').match(/OPENPC_NETWORK\|BLOCKED\|[a-z-]+/u)?.[0];
      throw new Error(diagnostic ?? 'RPC retirement network admission failed');
    }
  };
  await guard(compose);
  const baseline = await config(compose);
  assert.equal(
    baseline.services['control-api'].environment.CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID,
    '018f0000-0000-7000-8000-000000000195',
  );
  await call(process.execPath, [
    '--import',
    'tsx',
    'tests/integration/local-runtime/signing-provider-bootstrap.ts',
    secretRoot,
    join(dataRoot, 'signing-provider'),
    '--rpc-retirement',
    privacyDomainId,
  ]);
  const overlay = join(dataRoot, 'rpc-retirement-clean-signing.json');
  const value = JSON.stringify({
    services: {
      'control-api': {
        environment: {
          CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID: '018f0000-0000-7000-8000-000000091195',
          CONTROL_API_SIGNING_FINALIZER_ENABLED: '0',
        },
      },
      'signing-provider': { environment: { OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT: '1' } },
    },
    secrets: Object.fromEntries(
      [
        'business_provider_ca',
        'business_provider_server_cert',
        'business_provider_server_key',
        'business_api_cert',
        'business_api_key',
      ].map((name) => [
        name,
        { file: join(secretRoot, 'rpc-retirement-transport', name + '.pem') },
      ]),
    ),
  });
  try {
    await writeFile(overlay, value, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.equal(await readFile(overlay, 'utf8'), value);
  }
  const selected = [...compose, '-f', overlay];
  const start = async (command) => {
    await guard(command);
    for (const service of ['signing-provider', 'control-api'])
      await call(command[0], [
        ...command.slice(1),
        'up',
        '-d',
        '--wait',
        '--force-recreate',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        service,
      ]);
  };
  await start(selected);
  let completed = false;
  try {
    const result = await run(selected);
    completed = true;
    return result;
  } finally {
    // On failure the owning runner retains the selected configuration and the
    // original effect for diagnosis; it must never blindly replay this phase.
    if (completed) await start(compose);
  }
}
