import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertRequestEvidence,
  assertVisibilityDenial,
  recordedResponseStatus,
} from './visibility-response.mjs';

import { canonicalJson, pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import { stateReadSourceCustody, visibilityReadAssignment } from './typed-visibility-policy.mjs';

const sourceDigest = 'sha256:1d8bfe42b8303a6bb90237f881fefa63498ca0a662c9494b55c3d66a32db3b12';
const readMethod = {
  rpcMethodPolicyDigest: 'sha256:65b7cb209b468c126f6587d71e14ef55a29d91b38139a1aba91cd3ead0ea54bf',
};
const sourcePolicy = {
  schemaVersion: '1.0.0',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  rules: ['eth_call', 'eth_getBlockByNumber(false)'].map((method) => ({
    method,
    effect: 'ALLOW',
    requiredRoles: ['urn:openpc:role:018f0000-0000-7000-8000-000000000801'],
  })),
};
const source = {
  semanticDocument: {
    rpcPolicies: [sourcePolicy],
    indexerPolicies: [{ indexerProfileId: 'source', rpcPolicyDigest: sourceDigest }],
  },
};

test('anchored state-read preserves both source and contract-read RPC policy digests', () => {
  const custody = stateReadSourceCustody(source, readMethod);
  assert.deepEqual(
    custody.rpcPolicies.map((policy) => `sha256:${pcCbor1(policy).digest.toString('hex')}`).sort(),
    [
      sourceDigest,
      readMethod.rpcMethodPolicyDigest,
      `sha256:${pcCbor1({
        schemaVersion: '1.0.0',
        participantId: sourcePolicy.participantId,
        privacyDomainId: sourcePolicy.privacyDomainId,
        rules: ['eth_getLogs', 'eth_getTransactionByHash', 'eth_getTransactionReceipt'].map(
          (method) => ({
            method,
            effect: 'ALLOW',
            requiredRoles: sourcePolicy.rules[0].requiredRoles,
          }),
        ),
      }).digest.toString('hex')}`,
    ].sort(),
  );
  assert.deepEqual(custody.indexerPolicies, source.semanticDocument.indexerPolicies);
  const canonical = custody.rpcPolicies.map(canonicalJson);
  assert.deepEqual(canonical, [...canonical].sort());
  const repeated = stateReadSourceCustody(
    {
      semanticDocument: {
        ...custody,
        rpcPolicies: [...custody.rpcPolicies].reverse().concat(sourcePolicy),
      },
    },
    readMethod,
  );
  assert.deepEqual(repeated, custody);
  assert.equal(
    repeated.rpcPolicies.length,
    3,
    'deny-to-browser preparation must not duplicate response-family RPC policies',
  );
  custody.rpcPolicies.find((policy) => policy.rules.length === 2).rules[0].method = 'mutated';
  custody.indexerPolicies[0].rpcPolicyDigest = 'mutated';
  assert.equal(sourcePolicy.rules[0].method, 'eth_call');
  assert.equal(source.semanticDocument.indexerPolicies[0].rpcPolicyDigest, sourceDigest);
});

test('anchored state-read rejects a mismatched or missing configured RPC policy digest', () => {
  for (const invalid of [undefined, {}, { rpcMethodPolicyDigest: sourceDigest }]) {
    assert.throws(
      () => stateReadSourceCustody(source, invalid),
      /must match the configured contract-read digest/,
    );
  }
});

test('anchored state-read rejects a policy without source custody', () => {
  assert.throws(() =>
    stateReadSourceCustody({ semanticDocument: { rpcPolicies: [] } }, readMethod),
  );
  assert.throws(() =>
    stateReadSourceCustody({ semanticDocument: { indexerPolicies: [] } }, readMethod),
  );
});

test('visibility RPC grant binds the contract resource independently of invocation and source authority', () => {
  const id = '018f0000-0000-7000-8000-000000000901';
  const grant = visibilityReadAssignment(
    { runtimeBindingId: `urn:openpc:resource:${id}` },
    Date.UTC(2026, 8, 21),
  );
  assert.equal(grant.assignmentId, id);
  assert.deepEqual(grant.resourceIds, [id]);
  assert.deepEqual(grant.actionIntentIds, ['ACT-RUNTIME_READ_RPC-V1']);
  assert.deepEqual(grant.capabilityIds, []);
  assert.deepEqual(grant.riskClasses, ['LOW']);
  assert.equal(grant.onwardDelegationDepth, 0);
  for (const runtimeBindingId of ['*', id, 'urn:openpc:resource:*'])
    assert.throws(() => visibilityReadAssignment({ runtimeBindingId }));
});

test('visibility response evidence isolates current requests and preserves historical releases', () => {
  const oldRelease = { trace_id: 'old', status: { Released: { response_digest: 'same-bytes' } } };
  const prior = { records: { old: oldRelease } };
  const forward = { trace_id: 'new', status: { Committed: { effect: 'ALLOW_FORWARD' } } };
  const denied = { records: { ...prior.records, new: forward } };
  assertRequestEvidence(prior, denied, { forwarded: true, traceId: 'new' });
  const current = { records: { ...prior.records, new: { ...oldRelease, trace_id: 'new' } } };
  assertRequestEvidence(prior, current, { responseDigest: 'same-bytes' });
  assert.throws(() => assertRequestEvidence(prior, prior, { responseDigest: 'same-bytes' }));
  assert.throws(() => assertRequestEvidence(prior, current, { forwarded: true }));
  assert.throws(() => assertRequestEvidence(prior, denied, { forwarded: true, traceId: 'old' }));
  assert.throws(() =>
    assertRequestEvidence(prior, { records: { new: forward } }, { forwarded: true }),
  );
  assert.throws(() =>
    assertRequestEvidence(
      prior,
      {
        records: { ...current.records, duplicate: current.records.new },
      },
      { responseDigest: 'same-bytes' },
    ),
  );
});

test('visibility denial requires the exact native error and current request correlation', () => {
  const traceId = '018f0000-0000-7000-8000-000000000191';
  const body = {
    jsonrpc: '2.0',
    id: 1,
    error: {
      code: -32009,
      message: 'Response integrity invalid',
      data: {
        pcCode: 'PC-RUNTIME-3009',
        truthState: 'FAILED',
        retryable: false,
        traceId,
        attemptId: null,
        signedTransactionHash: null,
      },
    },
  };
  assert.equal(assertVisibilityDenial('502', '1', body, 'state-read'), traceId);
  const denied = structuredClone(body);
  denied.error.code = -32001;
  denied.error.message = 'Request denied';
  denied.error.data.pcCode = 'PC-RUNTIME-3001';
  denied.error.data.truthState = 'DENIED';
  assert.equal(assertVisibilityDenial('403', '1', denied, 'response-family'), traceId);
  for (const status of ['200', '400', '401', '403', '500', '503', '504']) {
    assert.throws(() => assertVisibilityDenial(status, '1', body, 'state-read'));
  }
  for (const status of ['200', '400', '401', '500', '502', '503', '504']) {
    assert.throws(() => assertVisibilityDenial(status, '1', denied, 'response-family'));
  }
  for (const mutate of [
    (value) => {
      value.id = 2;
    },
    (value) => {
      value.jsonrpc = '1.0';
    },
    (value) => {
      value.result = null;
    },
    (value) => {
      value.result = '0x';
    },
    (value) => {
      value.error.code = -32603;
    },
    (value) => {
      value.error.message = 'Upstream unavailable';
    },
    (value) => {
      value.error.data.pcCode = 'PC-RUNTIME-3010';
    },
    (value) => {
      value.error.data.truthState = 'DENIED';
    },
    (value) => {
      value.error.data.retryable = true;
    },
    (value) => {
      value.error.data.traceId = 'foreign-or-missing';
    },
    (value) => {
      delete value.error.data.traceId;
    },
    (value) => {
      value.error.data.attemptId = traceId;
    },
    (value) => {
      value.error.data.signedTransactionHash = '0x' + '11'.repeat(32);
    },
    (value) => {
      value.error.data.providerResult = 'private';
    },
  ]) {
    const invalid = structuredClone(body);
    mutate(invalid);
    assert.throws(() => assertVisibilityDenial('502', '1', invalid, 'state-read'));
  }
  for (const invalid of [null, {}, { result: null }, { result: '0x' }, { error: {} }]) {
    assert.throws(() => assertVisibilityDenial('502', '1', invalid, 'state-read'));
  }
  assert.throws(() => assertVisibilityDenial('502', '2', body, 'state-read'));
  assert.throws(() => assertVisibilityDenial('502', '01', body, 'state-read'));
  assert.throws(() => assertVisibilityDenial('502', '1', body, 'unknown'));
});

test('visibility retained denial uses the actual HTTP response, never an assumed status', () => {
  assert.equal(
    recordedResponseStatus('HTTP/1.1 502 Bad Gateway\r\ncontent-type: application/json\r\n'),
    '502',
  );
  assert.equal(recordedResponseStatus('HTTP/2 503\r\ncontent-type: application/json\r\n'), '503');
  for (const invalid of ['', 'x-status: 502\r\n', 'HTTP/1.1 502\r\nHTTP/1.1 503\r\n']) {
    assert.throws(() => recordedResponseStatus(invalid));
  }
});

test('visibility CLI rejects outages for direct and retained denial checks', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'openpc-visibility-oracle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const traceId = '018f0000-0000-7000-8000-000000000191';
  const failed = {
    jsonrpc: '2.0',
    id: 1,
    error: {
      code: -32010,
      message: 'Evidence admission failed',
      data: {
        pcCode: 'PC-RUNTIME-3010',
        truthState: 'FAILED',
        retryable: false,
        traceId,
        attemptId: null,
        signedTransactionHash: null,
      },
    },
  };
  // Oracle fixtures only: no runtime, credentials, policy or provider is started.
  await writeFile(join(root, 'requests.jsonl'), JSON.stringify({ method: 'eth_call' }) + '\n');
  await writeFile(join(root, 'response-denied.json'), JSON.stringify(failed));
  await writeFile(join(root, 'response-transaction-denied.json'), JSON.stringify(failed));
  await writeFile(join(root, 'response-denied.headers'), 'HTTP/1.1 503 Service Unavailable\r\n');
  const prior = { records: {} };
  const current = {
    records: { request: { trace_id: traceId, status: { Committed: { effect: 'ALLOW_FORWARD' } } } },
  };
  await writeFile(join(root, 'decisions-before-denied.json'), JSON.stringify(prior));
  await writeFile(join(root, 'decisions-denied.json'), JSON.stringify(current));
  await writeFile(join(root, 'decisions-before-transaction-denied.json'), JSON.stringify(prior));
  await writeFile(join(root, 'decisions-transaction-denied.json'), JSON.stringify(prior));
  const entry = new URL('./visibility-response.mjs', import.meta.url);
  const run = (args) =>
    spawnSync(process.execPath, [fileURLToPath(entry), ...args], {
      encoding: 'utf8',
      timeout: 5000,
      env: { ...process.env, NODE_TEST_CONTEXT: undefined },
    });
  for (const args of [
    ['denied', '503', '1', root, join(root, 'requests.jsonl'), '0'],
    ['transaction', '503', '1', root, 'denied'],
    ['evidence', 'denied', '1', root],
  ]) {
    const result = run(args);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout, /OPENPC_STATE_READ_RESPONSE\|PASS/u);
  }
  const withheld = structuredClone(failed);
  withheld.error.code = -32009;
  withheld.error.message = 'Response integrity invalid';
  withheld.error.data.pcCode = 'PC-RUNTIME-3009';
  await writeFile(join(root, 'response-denied.json'), JSON.stringify(withheld));
  await writeFile(join(root, 'response-denied.headers'), 'HTTP/1.1 502 Bad Gateway\r\n');
  for (const args of [
    ['denied', '502', '1', root, join(root, 'requests.jsonl'), '0'],
    ['evidence', 'denied', '1', root],
  ]) {
    const result = run(args);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /OPENPC_STATE_READ_RESPONSE\|PASS/u);
  }
});
