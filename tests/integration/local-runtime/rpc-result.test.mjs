import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyRpcResponse, qualifyRpcCase } from './rpc-result.mjs';

const request = { jsonrpc: '2.0', id: 17, method: 'eth_call', params: [] };
const traceId = '018f0000-0000-7000-8000-000000000901';
const denial = () => ({
  status: 403,
  body: {
    jsonrpc: '2.0',
    id: 17,
    error: {
      code: -32001,
      data: {
        pcCode: 'PC-RUNTIME-3001',
        truthState: 'DENIED',
        retryable: false,
        traceId,
      },
    },
  },
});
const qualified = (response, overrides = {}) =>
  qualifyRpcCase({
    expected: 'deny',
    request,
    response,
    // These tests exercise result qualification only. The live harness must
    // supply native fixture admission and authoritative effect/denial readback.
    verifyFixture: () => {},
    verifyOutcome: (observation) => {
      assert.equal(observation.traceId, traceId);
    },
    ...overrides,
  });

test('policy denial requires correlated native response and separate case readback', async () => {
  assert.deepEqual(classifyRpcResponse(request, denial()), {
    kind: 'DENIAL',
    traceId,
  });
  assert.equal((await qualified(denial(), { verifyOutcome: undefined })).state, 'BLOCKED');
  assert.equal((await qualified(denial())).state, 'PASS');
  assert.equal(
    (
      await qualified(denial(), {
        verifyOutcome: () => {
          throw Error('No matching committed decision');
        },
      })
    ).state,
    'FAIL',
  );
});

for (const [name, response] of [
  ['timeout', undefined],
  ['connection reset', { error: { code: 'ECONNRESET' } }],
  ['IdP HTML response', { status: 200, body: '<html>Sign in</html>' }],
  [
    'service unavailable',
    { status: 503, body: { jsonrpc: '2.0', id: 17, error: { code: -32001 } } },
  ],
  ['wrong response ID', { ...denial(), body: { ...denial().body, id: '17' } }],
  ['missing JSON-RPC version', { ...denial(), body: { ...denial().body, jsonrpc: undefined } }],
  ['result and error', { ...denial(), body: { ...denial().body, result: null } }],
  ['untyped denial', { status: 403, body: { jsonrpc: '2.0', id: 17, error: { code: -32001 } } }],
  [
    'expiry failure',
    {
      ...denial(),
      body: {
        ...denial().body,
        error: {
          ...denial().body.error,
          data: { ...denial().body.error.data, pcCode: 'PC-RUNTIME-3002' },
        },
      },
    },
  ],
  [
    'retryable failure',
    {
      ...denial(),
      body: {
        ...denial().body,
        error: {
          ...denial().body.error,
          data: { ...denial().body.error.data, retryable: true },
        },
      },
    },
  ],
  [
    'missing trace',
    {
      ...denial(),
      body: {
        ...denial().body,
        error: {
          ...denial().body.error,
          data: { ...denial().body.error.data, traceId: undefined },
        },
      },
    },
  ],
  [
    'leaked payload on denial',
    {
      ...denial(),
      body: {
        ...denial().body,
        error: {
          ...denial().body.error,
          data: {
            ...denial().body.error.data,
            payload: 'Protected workflow data',
          },
        },
      },
    },
  ],
  [
    'denial claiming a submitted transaction',
    {
      ...denial(),
      body: {
        ...denial().body,
        error: {
          ...denial().body.error,
          data: {
            ...denial().body.error.data,
            signedTransactionHash: `0x${'a'.repeat(64)}`,
          },
        },
      },
    },
  ],
])
  test(`${name} cannot pass a policy denial`, async () => {
    let readbackCalled = false;
    const result = await qualified(response, {
      verifyOutcome: () => {
        readbackCalled = true;
      },
    });
    assert.equal(result.state, 'FAIL');
    assert.equal(result.pass, false);
    assert.equal(readbackCalled, false);
  });

for (const result of [
  null,
  '0x',
  '0x0',
  [],
  { input: '0x' },
  { logs: [], logsBloom: `0x${'0'.repeat(512)}` },
])
  test(`successful empty ${JSON.stringify(result).slice(0, 35)} is not a privacy denial`, async () => {
    const response = { status: 200, body: { jsonrpc: '2.0', id: 17, result } };
    assert.equal(classifyRpcResponse(request, response).kind, 'RESULT');
    assert.equal((await qualified(response)).state, 'FAIL');
  });

test('missing or failed native fixture blocks the case, including false boolean shortcuts', async () => {
  for (const verifyFixture of [
    undefined,
    () => false,
    () => true,
    () => {
      throw Error('Workload not admitted');
    },
  ]) {
    let called = false;
    const result = await qualified(denial(), {
      verifyFixture,
      verifyOutcome: () => {
        called = true;
      },
    });
    assert.equal(result.state, 'BLOCKED');
    assert.equal(result.pass, false);
    assert.equal(called, false);
  }
});

test('allowed response requires a separate case oracle and rejects boolean shortcuts', async () => {
  const response = {
    status: 200,
    body: {
      jsonrpc: '2.0',
      id: 17,
      result: { name: 'Workflow 101', sensitiveData: 'Synthetic payload' },
    },
  };
  const verifyOutcome = () => {
    assert.equal(response.body.result.name, 'Workflow 101');
    assert.equal(response.body.result.sensitiveData, 'Synthetic payload');
  };
  assert.equal((await qualified(response, { expected: 'allow', verifyOutcome })).state, 'PASS');
  assert.equal(
    (await qualified(response, { expected: 'allow', verifyOutcome: undefined })).state,
    'BLOCKED',
  );
  assert.equal(
    (
      await qualified(response, {
        expected: 'allow',
        verifyOutcome: () => false,
      })
    ).state,
    'FAIL',
  );
  assert.equal(
    (
      await qualified(response, {
        expected: 'allow',
        verifyOutcome: () => {
          assert.equal(response.body.result.sensitiveData, 'Different payload');
        },
      })
    ).state,
    'FAIL',
  );
});

test('expected allow cannot pass on a genuine typed denial', async () => {
  assert.equal((await qualified(denial(), { expected: 'allow' })).state, 'FAIL');
});

test('explicit owner-filtered privacy representation still requires its own semantic evidence', async () => {
  const response = { status: 200, body: { jsonrpc: '2.0', id: 17, result: [] } };
  assert.equal((await qualified(response)).state, 'FAIL');
  assert.equal(
    (
      await qualified(response, {
        denyRepresentation: 'POLICY_FILTERED_RESULT',
        verifyOutcome: undefined,
      })
    ).state,
    'BLOCKED',
  );
  assert.equal(
    (
      await qualified(response, {
        denyRepresentation: 'POLICY_FILTERED_RESULT',
        verifyOutcome: () => {
          throw Error('No native projection evidence for this exact query');
        },
      })
    ).state,
    'FAIL',
  );
  assert.equal(
    (
      await qualified(response, {
        denyRepresentation: 'POLICY_FILTERED_RESULT',
        verifyOutcome: () => {
          assert.deepEqual(response.body.result, []);
        },
      })
    ).state,
    'PASS',
  );
});

test('filter representation does not forgive transport errors or change allow expectations', async () => {
  assert.equal(
    (await qualified(undefined, { denyRepresentation: 'POLICY_FILTERED_RESULT' })).state,
    'FAIL',
  );
  await assert.rejects(() =>
    qualified(denial(), { expected: 'allow', denyRepresentation: 'POLICY_FILTERED_RESULT' }),
  );
});
