import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evidenceCorrelationActorBootstrapInputs } from './deployment-intent-actors.mjs';
import { assertEvidenceOperationCorrelation } from './evidence-provenance-browser.mjs';
import {
  rpcTerminalResumeInputs,
  rpcReadResumePolicy,
} from './evidence-rpc-retirement-browser.mjs';
import { projectionDeletionBrowser } from './evidence-projection-deletion-browser.mjs';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';
import {
  rpcSearchRetirementPrefix,
  rpcPayloadRetirementReadbackInputs,
  assertRpcRetirementCandidate,
  assertRpcRetirementPrivacyDenial,
} from './evidence-rpc-payload-retirement-browser.mjs';
import { nativeEmulatorAccountAuthorization } from './participant-workbench-browser.mjs';
import { transactionCandidate } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';

const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n) => `urn:openpc:resource:${id(n)}`;
const hash = `sha256:${'a'.repeat(64)}`;
const time = '2026-09-25T00:00:00.123456Z';

test('desktop-only acceptance does not silently apply to an unrelated journey', async () => {
  await assert.rejects(projectionDeletionBrowser({ desktopOnly: true }), {
    code: 'ERR_ASSERTION',
  });
});

test('complete original RPC readback requires one distinct approval per original effect', () => {
  const records = [1, 2].map((n) => `rpc:${'a'.repeat(64)}:${n}`);
  assert.equal(rpcPayloadRetirementReadbackInputs(records, undefined, undefined), false);
  assert.equal(rpcPayloadRetirementReadbackInputs(records, id(1), undefined), false);
  assert.equal(rpcPayloadRetirementReadbackInputs(records, id(1), [id(2), id(3)]), true);
  for (const [payload, search] of [
    [undefined, [id(2), id(3)]],
    [id(1), []],
    [id(1), [id(2)]],
    [id(1), [id(2), id(2)]],
    [id(1), [id(1), id(2)]],
    [id(1), [id(2), ref(3)]],
  ])
    assert.throws(() => rpcPayloadRetirementReadbackInputs(records, payload, search));
});

test('incomplete RPC readback fails before allocating resources or entering initial trust setup', async () => {
  await assert.rejects(
    projectionDeletionBrowser({
      rpcPayloadRecordIds: [`rpc:${'a'.repeat(64)}:1`],
      rpcSearchResumeApprovalIds: [id(1)],
    }),
    { code: 'ERR_ASSERTION' },
  );
});

test('original RPC readback refuses missing actors before admission or artifact allocation', async () => {
  const evidenceRoot = await mkdtemp(join(tmpdir(), 'openpc-original-readback-'));
  try {
    await assert.rejects(
      projectionDeletionBrowser({
        evidenceRoot,
        rpcPayloadRecordIds: [`rpc:${'a'.repeat(64)}:1`],
        rpcPayloadResumeApprovalId: id(1),
        rpcSearchResumeApprovalIds: [id(2)],
      }),
      /Original RPC retirement actor file is required for readback/u,
    );
    assert.deepEqual(await readdir(evidenceRoot), []);
  } finally {
    await rm(evidenceRoot, { recursive: true });
  }
});

test('strict retained continuation rejects session replacement before allocating artifacts', async () => {
  await assert.rejects(
    withTransactionBrowser({ requireRetainedSessions: true }, () => {
      assert.fail('Invalid continuation must not enter the browser callback');
    }),
    /Strict continuation requires retained sessions/u,
  );
});

test('policy continuation requires the original retired predecessors and exact active version', () => {
  const policies = [1, 2, 3].map((n) => ({
    retentionPolicyId: ref(n),
    policyVersion: `${n}.0.0`,
    predecessorPolicyId: n === 1 ? null : ref(n - 1),
    state: n === 3 ? 'ACTIVE' : 'RETIRED',
    retentionPeriodMs: n === 2 ? '31536000000' : '0',
    localGraceMs: n === 3 ? '31536000000' : '0',
    sinkQuorum: n === 2 ? 2 : 1,
    deletionMode: 'PROJECTION_DELETE',
    makerCheckerRequired: true,
    activationReceiptDigest: hash,
  }));
  assert.equal(rpcReadResumePolicy(policies, '3.0.0'), policies[2]);
  assert.throws(() => rpcReadResumePolicy(policies, '4.0.0'));
  for (const change of [
    { predecessorPolicyId: ref(9) },
    { state: 'RETIRED' },
    { localGraceMs: '0' },
    { sinkQuorum: 0 },
    { makerCheckerRequired: false },
  ])
    assert.throws(() =>
      rpcReadResumePolicy([...policies.slice(0, 2), { ...policies[2], ...change }], '3.0.0'),
    );
  assert.throws(() => rpcReadResumePolicy(policies.slice(1), '3.0.0'));
  assert.throws(() => rpcReadResumePolicy([...policies, policies[2]], '3.0.0'));
});

test('terminal recovery requires two distinct original approval identities', () => {
  assert.deepEqual(rpcTerminalResumeInputs([id(1), id(2)]), [id(1), id(2)]);
  for (const approvals of [[id(1)], [id(1), id(1)], [id(1), '-'.repeat(36)], [id(1), ref(2)]])
    assert.throws(() => rpcTerminalResumeInputs(approvals));
});

test('conflicting retirement adapters fail before resource or trust setup', async () => {
  const base = {
    rpcTerminalResumeApprovals: [id(1), id(2)],
    closedRpcOnly: true,
    terminalCases: true,
  };
  for (const change of [
    { factConfiguration: '/tmp/original-fact.json' },
    { deploymentConfiguration: '/tmp/original-deployment.json' },
    { businessConfiguration: '/tmp/original-business.json' },
    { sourceReads: true },
    { closedRpcOnly: false },
  ])
    await assert.rejects(projectionDeletionBrowser({ ...base, ...change }), {
      code: 'ERR_ASSERTION',
    });
});
const expected = {
  status: 'VERIFIED_BUSINESS_TRANSITION',
  evidenceId: ref(1),
  recordDigest: hash,
  business: {
    receiptId: id(2),
    operationId: `urn:openpc:operation:${id(3)}`,
    actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
    aggregateId: id(4),
    recordedAt: time,
    after: { revision: '2' },
  },
};
const view = () => ({
  actorKey: hash,
  evidenceId: ref(1),
  receiptId: id(2),
  recordDigest: hash,
  recordedAt: time,
  historicalRevision: '2',
  operation: {
    operationId: id(3),
    resourceRef: ref(4),
    actionIntentId: expected.business.actionIntentId,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    revision: '2',
    createdAt: time,
    updatedAt: time,
  },
});

test('original historical edge survives restart while session/current status may change', () => {
  const original = assertEvidenceOperationCorrelation(view(), expected);
  const next = {
    ...view(),
    actorKey: `sha256:${'b'.repeat(64)}`,
    operation: {
      ...view().operation,
      state: 'WRITE_AMBIGUITY',
      truthState: 'WRITE_AMBIGUITY',
      revision: '3',
    },
  };
  assert.equal(assertEvidenceOperationCorrelation(next, expected, original), next);
});
test('rejects substituted operation/action/resource, historical identity and extra disclosures', () => {
  for (const change of [
    { operationId: id(9) },
    { resourceRef: ref(9) },
    { resourceRef: null },
    { actionIntentId: 'ACT-OPERATIONS_UPDATE_COMPLETE-V1' },
    { idempotencyKey: 'PRIVATE-KEY-CANARY' },
    { intentDigest: hash },
    { state: 'EFFECT_CONFIRMED' },
  ])
    assert.throws(() =>
      assertEvidenceOperationCorrelation(
        { ...view(), operation: { ...view().operation, ...change } },
        expected,
      ),
    );
  for (const change of [
    { evidenceId: ref(9) },
    { receiptId: id(9) },
    { recordDigest: `sha256:${'b'.repeat(64)}` },
    { historicalRevision: '3' },
    { rawReceipt: 'PRIVATE-KEY-CANARY' },
  ])
    assert.throws(() => assertEvidenceOperationCorrelation({ ...view(), ...change }, expected));
});
test('does not substitute a new valid receipt after restart', () => {
  const retained = view();
  const replacement = { ...view(), receiptId: id(9) };
  const replacementSource = { ...expected, business: { ...expected.business, receiptId: id(9) } };
  assert.throws(() => assertEvidenceOperationCorrelation(replacement, replacementSource, retained));
});
test('missing/unsupported source remains unqualified', () => {
  for (const change of [{ business: null }, { status: 'SOURCE_NOT_SUPPORTED' }])
    assert.throws(() => assertEvidenceOperationCorrelation(view(), { ...expected, ...change }));
});

test('correlation initial trust gives both actors receipt access and only maker operation access', () => {
  const args = [
    '/tmp/correlation-secrets',
    '/tmp/correlation-evidence',
    id(101),
    'bootstrap-evidence-correlation',
    id(201),
    '--preflight',
  ];
  const input = evidenceCorrelationActorBootstrapInputs(args);
  assert.deepEqual(input.actorActions.checker, [
    'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
    'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
  ]);
  assert.deepEqual(input.actorActions.maker, [
    ...input.actorActions.checker,
    'ACT-OPERATIONS_READ_OPERATION-V1',
  ]);
  assert.equal(
    input.actions.some((action) => /CREATE|UPDATE|DELETE|EXPORT/u.test(action)),
    false,
  );
  assert.equal(input.entryActions.includes('ACT-OPERATIONS_READ_OPERATION-V1'), false);
  const identities = Object.values(input.actors).flatMap(Object.values);
  assert.equal(new Set(identities).size, 8);
  for (const identity of identities) assert.match(identity, /^018f0022-/u);
  assert.equal(input.bootstrapEntryPrivacyDomain, '018f0022-0000-7000-8000-000000000201');
  const actual = JSON.parse(
    execFileSync(
      process.execPath,
      ['tests/integration/local-runtime/deployment-intent-actors.mjs', ...args],
      { encoding: 'utf8' },
    ),
  );
  assert.equal(actual.actorLabel, 'Evidence correlation');
  const workItem = JSON.parse(
    execFileSync(
      process.execPath,
      [
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        ...args.map((value, index) => (index === 3 ? 'bootstrap-work-items' : value)),
      ],
      { encoding: 'utf8' },
    ),
  );
  assert.notEqual(
    actual.actorLabel,
    workItem.actorLabel,
    'Principal labels must be unique across retained fixture families',
  );
  assert.deepEqual(actual.actorActions, input.actorActions);
  assert.deepEqual(actual.actors, input.actors);
  assert.deepEqual(actual.entryPrivacyDomains, input.entryPrivacyDomains);
  for (const invalid of [args.slice(0, 4), [...args, 'extra'], ['relative', ...args.slice(1)]])
    assert.throws(() => evidenceCorrelationActorBootstrapInputs(invalid));
});

test('requested RPC records behind an unrequested member use separate fixed sequences without skipping it', () => {
  const records = [...Array.from({ length: 7 }, (_, i) => i + 10), 9].map((n) => ({
    id: id(n),
    record_id: `rpc:${'a'.repeat(64)}:${n}`,
  }));
  const target = (n) => ({ evidenceId: ref(n), recordId: `rpc:${'a'.repeat(64)}:${n}` });
  const targets = [10, 11, 12, 13, 14, 15, 16, 17, 18, 9].map(target);
  const first = rpcSearchRetirementPrefix(targets, records);
  assert.deepEqual(
    first.map((t) => t.recordId),
    records.slice(0, 7).map((r) => r.record_id),
  );
  assert.equal(targets[first.length].recordId, target(17).recordId);
  const second = rpcSearchRetirementPrefix([target(9)], records.slice(7));
  assert.deepEqual(
    [...first, ...second].map((t) => t.recordId),
    records.map((r) => r.record_id),
  );
  assert.deepEqual(targets, [10, 11, 12, 13, 14, 15, 16, 17, 18, 9].map(target));
});

test('fixed RPC search prefix rejects changed evidence, reordered originals and a foreign starting target', () => {
  const records = [10, 11].map((n) => ({ id: id(n), record_id: `rpc:${'a'.repeat(64)}:${n}` }));
  const targets = records.map((r) => ({
    evidenceId: `urn:openpc:resource:${r.id}`,
    recordId: r.record_id,
  }));
  for (const changed of [
    [],
    [{ ...targets[0], evidenceId: ref(99) }],
    [targets[1], targets[0]],
    [{ ...targets[0], recordId: 'unrequested' }],
  ])
    assert.throws(() => rpcSearchRetirementPrefix(changed, records));
  assert.throws(() => rpcSearchRetirementPrefix(targets, [records[0], records[0]]));
});

test('approval observation rejects unrelated retirement adapters before resource allocation', async () => {
  await assert.rejects(
    projectionDeletionBrowser({ onApprovalRequested: () => {} }),
    /Approval observation belongs only/u,
  );
  await assert.rejects(
    projectionDeletionBrowser({
      rpcPayloadRecordIds: ['rpc:' + 'a'.repeat(64) + ':9'],
      onApprovalRequested: true,
    }),
    { code: 'ERR_ASSERTION' },
  );
});

test('native provider account selection preserves PKCE and never overwrites an original actor route', () => {
  const address =
    'http://127.0.0.1:53006/authorize?response_type=code&state=original&nonce=original-nonce&code_challenge=original-challenge&code_challenge_method=S256';
  for (const role of ['operator', 'viewer']) {
    const selected = new URL(nativeEmulatorAccountAuthorization(address, role));
    assert.equal(selected.searchParams.get('login_hint'), role);
    selected.searchParams.delete('login_hint');
    assert.equal(selected.href, address);
  }
  for (const [url, role] of [
    [address, 'admin'],
    [address.replace('127.0.0.1', 'example.com'), 'viewer'],
    [address.replace('/authorize', '/token'), 'viewer'],
    [address + '&openpc_test_subject=' + id(141), 'viewer'],
  ])
    assert.throws(() => nativeEmulatorAccountAuthorization(url, role));
});

test('privacy acceptance rejects outages, invalid sessions, wrong problem classifications and scoped leakage', () => {
  const body = {
    type: 'https://errors.openpc.local/hidden-or-not-found',
    title: 'Resource is unavailable',
    status: 403,
    code: 'PC-AUTH-0005',
    truthState: 'DENIED',
    retryable: false,
    traceId: id(999),
  };
  assertRpcRetirementPrivacyDenial({ status: 403, body }, [ref(10), hash]);
  assertRpcRetirementPrivacyDenial({ status: 404, body: { ...body, status: 404 } }, [
    ref(10),
    hash,
  ]);
  for (const status of [200, 400, 401, 409, 500, 503])
    assert.throws(() =>
      assertRpcRetirementPrivacyDenial({ status, body: { ...body, status } }, [ref(10), hash]),
    );
  for (const change of [
    { truthState: 'UNAVAILABLE' },
    { code: 'PC-INTEGRATION-5001' },
    { retryable: true },
    { selection: { targets: [ref(10)] } },
    { traceId: hash },
    { traceId: { selection: 'unlisted-private-data' } },
    { traceId: 'unlisted-private-data' },
  ])
    assert.throws(() =>
      assertRpcRetirementPrivacyDenial({ status: 403, body: { ...body, ...change } }, [
        ref(10),
        hash,
      ]),
    );
});

test('retirement approval rejects a changed cursor digest, target, before-image, reason or completed effect', () => {
  const targets = [10, 11].map((n) => ({
    evidenceId: ref(n),
    recordId: `rpc:${'a'.repeat(64)}:${n}`,
    projectionDigest: hash,
    projectionBytes: 1,
    sourceReceiptDigest: hash,
    beforeDigest: hash,
  }));
  const target = { ...targets[1] };
  delete target.beforeDigest;
  const selection = {
    version: 'OPENPC_PROJECTION_DELETION_BATCH_V1',
    participantId: `urn:openpc:participant:${id(101)}`,
    privacyDomainId: id(201),
    retentionPolicyId: ref(2),
    policyDigest: hash,
    targetDatabase: 'openpc_control',
    dataClass: 'SEARCH_PROJECTION',
    deletionMode: 'PROJECTION_DELETE',
    sourceKind: 'RPC_RETIRED_CATALOGUE',
    streamId: 'original-rpc',
    segmentId: id(3),
    sequence: '11',
    ...target,
    archiveObjectDigest: hash,
    eligibleAfterMicros: '0',
    sinkReceipts: [],
    priorCursor: { deletionJobId: ref(1), receiptDigest: hash },
    targets,
    batchIndex: 1,
  };
  const plan = { selection, beforeDigest: hash };
  const kind = 'evidence-deletion-projection-continuation';
  const expected = transactionCandidate(kind, plan, 'original reason', id(101));
  const approval = {
    candidate: {
      state: 'APPROVED',
      operationRef: null,
      actionIntentId: expected.operation.actionIntentId,
      candidate: expected.body,
    },
  };
  assertRpcRetirementCandidate(approval, plan, kind, 'original reason', id(101));
  for (const change of [
    {
      selection: {
        ...selection,
        priorCursor: { ...selection.priorCursor, receiptDigest: `sha256:${'b'.repeat(64)}` },
      },
    },
    { selection: { ...selection, targets: [{ ...targets[0], evidenceId: ref(99) }, targets[1]] } },
    { beforeDigest: `sha256:${'b'.repeat(64)}` },
    { reason: 'replacement reason' },
  ])
    assert.throws(() =>
      assertRpcRetirementCandidate(
        { candidate: { ...approval.candidate, candidate: { ...expected.body, ...change } } },
        plan,
        kind,
        'original reason',
        id(101),
      ),
    );
  for (const change of [{ state: 'CONSUMED' }, { operationRef: ref(9) }])
    assert.throws(() =>
      assertRpcRetirementCandidate(
        { candidate: { ...approval.candidate, ...change } },
        plan,
        kind,
        'original reason',
        id(101),
      ),
    );
});
