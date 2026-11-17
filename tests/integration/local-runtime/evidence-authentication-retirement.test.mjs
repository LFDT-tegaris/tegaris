import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  authenticationResumeInputs,
  authenticationResumePolicies,
  authenticationResumeState,
  retainedAuthenticationFiles,
  projectionDeletionBrowser,
} from './evidence-projection-deletion-browser.mjs';

const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const input = () => ({
  workerRoot: '/tmp/evidence/projection-deletion-browser/original',
  workerDigest: digest('worker'),
  actorsDigest: digest('actors'),
  keyDigests: { '/tmp/data/projection-authentication-original/key': digest('key') },
  records: [1, 2].map((n) => ({
    id: id(n),
    record_id: id(n + 10),
    receipt_digest: digest(`record${n}`),
    segment_id: id(20),
    sequence: String(n),
  })),
  checkpoints: [{ checkpoint: { stream_id: 'original-authentication' } }],
  trust: [{ selection: { signer_id: 'original-signer' } }],
});

test('AUTH continuation requires a complete pinned input and distinct original record keyset', () => {
  assert.equal(authenticationResumeInputs(input()).records.length, 2);
  const archived = input();
  archived.records = archived.records.map((r) => ({
    ...r,
    segment_id: 'e915900a-e455-49d6-aee8-dc300a307aaa',
  }));
  assert.equal(
    authenticationResumeInputs(archived).records.length,
    2,
    'Original archive segments use UUID v4',
  );
  for (const change of [
    { workerRoot: 'relative' },
    { workerDigest: 'unknown' },
    { actorsDigest: 'unknown' },
    { keyDigests: {} },
    { records: [] },
    { checkpoints: [] },
    { trust: [] },
    { newArchive: true },
  ])
    assert.throws(() => authenticationResumeInputs({ ...input(), ...change }));
  for (const field of Object.keys(input())) {
    const missing = input();
    delete missing[field];
    assert.throws(() => authenticationResumeInputs(missing));
  }
  for (const change of [
    { record_id: id(11) },
    { id: 'not-an-id' },
    { segment_id: 'not-an-id' },
    { receipt_digest: 'unknown' },
    { sequence: '0' },
    { sequence: '18446744073709551616' },
    { sourceReplacement: true },
  ]) {
    const changed = input();
    changed.records[1] = { ...changed.records[1], ...change };
    assert.throws(() => authenticationResumeInputs(changed));
  }
});

test('AUTH continuation rejects every other adapter before reading files or allocating resources', async () => {
  const base = { authenticationResume: input(), resumeRoot: input().workerRoot };
  for (const change of [
    { resumeRoot: '/tmp/other' },
    { closedRpcOnly: true },
    { sourceReads: true },
    { terminalCases: true },
    { rpcPayloadRecordIds: [] },
    { rpcDenialRecordId: 'rpc:original:8' },
    { rpcDenialResumeApprovalId: id(1) },
    { rpcTerminalResumeApprovals: [id(1), id(2)] },
    { rpcReadResumePolicyVersion: '3.0.0' },
    { rpcPayloadResumeApprovalId: id(1) },
    { rpcSearchResumeApprovalIds: [id(1)] },
    { factConfiguration: '/tmp/fact' },
    { factSourceProfile: 'FACT' },
    { factResumeApprovalId: id(1) },
    { factReadbackHoldId: id(1) },
    { deploymentConfiguration: '/tmp/deployment' },
    { deploymentReadback: true },
    { deploymentResumeFinalized: true },
    { businessConfiguration: '/tmp/business' },
  ])
    await assert.rejects(projectionDeletionBrowser({ ...base, ...change }), {
      code: 'ERR_ASSERTION',
    });
});

const policies = () =>
  [
    {
      dataClass: 'SEARCH_PROJECTION',
      retentionPolicyId: id(10),
      policyVersion: '1.0.0',
      state: 'ACTIVE',
      retentionPeriodMs: '0',
      localGraceMs: '0',
      sinkQuorum: 1,
      predecessorPolicyId: null,
    },
    ...[1, 2, 3, 4].map((n) => ({
      dataClass: 'NORMALIZED_JSON_PROJECTION',
      retentionPolicyId: id(n),
      policyVersion: `${n}.0.0`,
      state: n === 4 ? 'ACTIVE' : 'RETIRED',
      retentionPeriodMs: n === 2 ? '31536000000' : '0',
      localGraceMs: n === 3 ? '31536000000' : '0',
      sinkQuorum: n === 2 ? 2 : 1,
      predecessorPolicyId: n === 1 ? null : id(n - 1),
    })),
  ].map((p) => ({
    ...p,
    deletionMode: 'PROJECTION_DELETE',
    makerCheckerRequired: true,
    activationReceiptDigest: digest('receipt'),
  }));

test('AUTH policy guard rejects changed lineage, settings and already activated AUDIT policy', () => {
  assert.equal(authenticationResumePolicies(policies()).dataClass, 'SEARCH_PROJECTION');
  assert.throws(() => authenticationResumePolicies(policies().slice(1)));
  assert.throws(() =>
    authenticationResumePolicies([...policies(), { dataClass: 'AUDIT_EVIDENCE' }]),
  );
  for (const change of [
    { predecessorPolicyId: id(9) },
    { retentionPolicyId: id(1) },
    { state: 'RETIRED' },
    { retentionPeriodMs: '1' },
    { localGraceMs: '1' },
    { sinkQuorum: 0 },
    { deletionMode: 'ROW_DELETE' },
    { makerCheckerRequired: false },
    { activationReceiptDigest: 'missing' },
    { dataClass: 'AUDIT_EVIDENCE' },
    { policyVersion: '5.0.0' },
  ]) {
    const changed = policies();
    changed[4] = { ...changed[4], ...change };
    assert.throws(() => authenticationResumePolicies(changed));
  }
  const changed = policies();
  changed[0].state = 'RETIRED';
  assert.throws(() => authenticationResumePolicies(changed));
});

test('AUTH guard refuses consumed effects, an AUDIT policy or outstanding relevant intent', () => {
  const untouched = { jobs: 0, retirements: 0, audit_policies: 0, pending: 0 };
  authenticationResumeState(untouched);
  for (const field of Object.keys(untouched))
    assert.throws(() => authenticationResumeState({ ...untouched, [field]: 1 }));
});

test('retained AUTH files are pinned without fallback or replacement archive creation', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'openpc-auth-resume-'));
  const root = join(temporary, 'evidence/projection-deletion-browser');
  const workerRoot = join(root, 'original');
  const dataRoot = join(temporary, 'data');
  const sourceRoot = join(dataRoot, 'projection-authentication-original');
  const secretRoot = join(temporary, 'secrets');
  await mkdir(workerRoot, { recursive: true });
  await mkdir(join(sourceRoot, 'vault'), { recursive: true });
  const keyFile = join(sourceRoot, 'key');
  const key = Buffer.alloc(32, 7);
  await writeFile(keyFile, key);
  const actors = JSON.stringify({ maker: id(100), checker: id(101) });
  await writeFile(join(root, 'deployment-intent-actors.json'), actors);
  const config = {
    database: {
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_local_control_worker',
      passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
    },
    vaultDirectory: join(sourceRoot, 'vault'),
    sinkId: 'projection-authentication-original',
    scopes: [
      {
        participantId: id(101),
        privacyDomainId: id(7201),
        streamId: 'projection-authentication-original',
        source: 'AUTHENTICATION',
        retentionSeconds: 60,
        capacityBytes: 16 * 1024 * 1024,
        activeKeyId: 'projection-source',
        keys: [{ keyId: 'projection-source', keyFile }],
      },
    ],
  };
  const workerFile = join(workerRoot, 'worker.json');
  const original = JSON.stringify(config);
  await writeFile(workerFile, original);
  const pinned = {
    ...input(),
    workerRoot,
    workerDigest: digest(original),
    actorsDigest: digest(actors),
    keyDigests: { [keyFile]: digest(key) },
  };
  const check = (value = pinned) =>
    retainedAuthenticationFiles(value, root, dataRoot, secretRoot, id(101), id(7201));
  try {
    assert.deepEqual(await check(), config);
    await assert.rejects(check({ ...pinned, workerRoot: join(root, 'missing') }), {
      code: 'ENOENT',
    });
    await assert.rejects(check({ ...pinned, workerRoot: temporary }), { code: 'ERR_ASSERTION' });
    for (const change of [
      { source: 'RPC' },
      { streamId: 'replacement-stream' },
      { participantId: id(102) },
      { privacyDomainId: id(7202) },
      { activeKeyId: 'replacement-key' },
      { retentionSeconds: 61 },
    ]) {
      const changed = { ...config, scopes: [{ ...config.scopes[0], ...change }] };
      const bytes = JSON.stringify(changed);
      await writeFile(workerFile, bytes);
      await assert.rejects(check({ ...pinned, workerDigest: digest(bytes) }), {
        code: 'ERR_ASSERTION',
      });
    }
    await writeFile(workerFile, original);
    await writeFile(keyFile, Buffer.alloc(32, 8));
    await assert.rejects(check(), { code: 'ERR_ASSERTION' });
    await writeFile(keyFile, key);
    await writeFile(join(root, 'deployment-intent-actors.json'), '{}');
    await assert.rejects(check(), { code: 'ERR_ASSERTION' });
    await writeFile(join(root, 'deployment-intent-actors.json'), actors);
    await writeFile(workerFile, original + '\n');
    await assert.rejects(check(), { code: 'ERR_ASSERTION' });
    assert.deepEqual(await readdir(root), ['deployment-intent-actors.json', 'original']);
    assert.deepEqual(await readFile(keyFile), key);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
