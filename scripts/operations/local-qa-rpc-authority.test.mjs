import assert from 'node:assert/strict';
import test from 'node:test';
import { localQaRpcAuthority } from './local-qa-rpc-authority.mjs';

const bindings = {
  participantId: 'participant-a',
  privacyDomainId: 'privacy-a',
  runtimeBindingId: 'runtime-a',
  targetProfileId: 'devnet-rpc-v1',
};
const qa = { OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1' };
test('autonomous reads require explicit disposable QA configuration', () => {
  assert.throws(
    () =>
      localQaRpcAuthority({ OPENPC_QA_RPC_AUTHORITY_PROFILE: 'CALL_ONLY_AUTONOMOUS' }, bindings),
    /disposable QA/,
  );
  const governed = localQaRpcAuthority(qa, bindings, 1800000000000);
  assert.equal(governed.makerCheckerRequired, true);
  assert.equal(governed.stepUpRequired, true);
});
test('autonomous initial ceiling is exact CALL-only authority with no administration or delegation', () => {
  const scope = localQaRpcAuthority(
    {
      ...qa,
      OPENPC_QA_RPC_AUTHORITY_PROFILE: 'CALL_ONLY_AUTONOMOUS',
      OPENPC_QA_AUTHORITY_TTL_MS: '86400000',
    },
    bindings,
    1800000000000,
  );
  assert.deepEqual(scope.runtime.capabilityIds, ['CALL_RESULT_DISCLOSURE']);
  assert.deepEqual(scope.runtime.participantIds, ['participant-a']);
  assert.deepEqual(scope.runtime.privacyDomainIds, ['privacy-a']);
  assert.deepEqual(scope.runtime.resourceIds, ['runtime-a']);
  assert.deepEqual(scope.runtime.targetProfileIds, ['devnet-rpc-v1']);
  assert.deepEqual(scope.runtime.riskClasses, ['LOW']);
  assert.ok(Object.values(scope.administration).every((dimension) => dimension.length === 0));
  assert.equal(scope.onwardDelegationDepth, 0);
  assert.equal(scope.makerCheckerRequired, false);
  assert.equal(scope.stepUpRequired, false);
  assert.equal(BigInt(scope.validUntilNs) - BigInt(scope.validFromNs), 86400000000000n);
});
test('rejects malformed bindings, unknown profiles and out-of-bound lifetimes', () => {
  for (const ttl of ['0', '-1', '1.5', 'Infinity', '3600000x', '3599999', '86400001'])
    assert.throws(() => localQaRpcAuthority({ ...qa, OPENPC_QA_AUTHORITY_TTL_MS: ttl }, bindings));
  assert.throws(() =>
    localQaRpcAuthority({ ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'IGNORE_POLICY' }, bindings),
  );
  assert.throws(() => localQaRpcAuthority(qa, { ...bindings, runtimeBindingId: '' }));
});

test('policy-controlled RPC declares a finite initial ceiling without workload or administration grants', () => {
  assert.throws(() =>
    localQaRpcAuthority({ OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC' }, bindings),
  );
  const scope = localQaRpcAuthority(
    { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC' },
    bindings,
    1800000000000,
  );
  const read = localQaRpcAuthority(
    { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'CALL_ONLY_AUTONOMOUS' },
    bindings,
    1800000000000,
  );
  assert.deepEqual(scope.runtime.capabilityIds, [
    'CALL_RESULT_DISCLOSURE',
    'SIGNED_TRANSACTION_SUBMISSION',
  ]);
  assert.deepEqual(
    { ...scope, runtime: { ...scope.runtime, capabilityIds: read.runtime.capabilityIds } },
    read,
  );
  assert.equal(scope.makerCheckerRequired, false);
  assert.equal(scope.stepUpRequired, false);
  assert.equal(scope.onwardDelegationDepth, 0);
});

test('additional reserved bindings require an explicit finite QA scope containing the primary binding', () => {
  const id = (n) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
  const exact = { ...bindings, runtimeBindingId: id(1) };
  const environment = { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC' };
  const scope = localQaRpcAuthority(
    { ...environment, OPENPC_QA_RPC_RESOURCE_IDS: `${id(2)},${id(1)}` },
    exact,
  );
  assert.deepEqual(scope.runtime.resourceIds, [id(1), id(2)]);
  for (const input of [
    '',
    '*',
    id(2),
    `${id(1)},${id(1)}`,
    `${id(1)}, *`,
    Array.from({ length: 17 }, (_, i) => id(i + 1)).join(','),
  ])
    assert.throws(() =>
      localQaRpcAuthority({ ...environment, OPENPC_QA_RPC_RESOURCE_IDS: input }, exact),
    );
  assert.throws(() => localQaRpcAuthority({ ...qa, OPENPC_QA_RPC_RESOURCE_IDS: id(1) }, exact));
});

test('explicit QA capabilities cover customer gas estimates without granting workload authority', () => {
  const environment = {
    ...qa,
    OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC',
    OPENPC_QA_RPC_CAPABILITY_IDS:
      'SIGNED_TRANSACTION_SUBMISSION,GAS_ESTIMATE_DISCLOSURE,CALL_RESULT_DISCLOSURE,OPERATION_STATUS_DISCLOSURE',
  };
  const baseline = localQaRpcAuthority(
    { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC' },
    bindings,
    1800000000000,
  );
  const scope = localQaRpcAuthority(environment, bindings, 1800000000000);
  assert.deepEqual(scope.runtime.capabilityIds, [
    'CALL_RESULT_DISCLOSURE',
    'GAS_ESTIMATE_DISCLOSURE',
    'OPERATION_STATUS_DISCLOSURE',
    'SIGNED_TRANSACTION_SUBMISSION',
  ]);
  assert.deepEqual(
    { ...scope, runtime: { ...scope.runtime, capabilityIds: baseline.runtime.capabilityIds } },
    baseline,
  );
});

test('QA capability configuration rejects unknown, deferred, duplicate, incomplete and wildcard scopes', () => {
  const environment = { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC' };
  const baseline = 'CALL_RESULT_DISCLOSURE,SIGNED_TRANSACTION_SUBMISSION';
  for (const input of [
    '',
    '*',
    'GAS_ESTIMATE_DISCLOSURE',
    'CALL_RESULT_DISCLOSURE',
    `${baseline},`,
    `${baseline}, GAS_ESTIMATE_DISCLOSURE`,
    `${baseline},gas_estimate_disclosure`,
    `${baseline},UNKNOWN_CAPABILITY`,
    `${baseline},MULTI_CALL_SIMULATION_DISCLOSURE`,
    `${baseline},CALL_RESULT_DISCLOSURE`,
  ])
    assert.throws(() =>
      localQaRpcAuthority({ ...environment, OPENPC_QA_RPC_CAPABILITY_IDS: input }, bindings),
    );
  for (const profile of ['GOVERNED', 'CALL_ONLY_AUTONOMOUS'])
    assert.throws(() =>
      localQaRpcAuthority(
        { ...qa, OPENPC_QA_RPC_AUTHORITY_PROFILE: profile, OPENPC_QA_RPC_CAPABILITY_IDS: baseline },
        bindings,
      ),
    );
  assert.throws(() =>
    localQaRpcAuthority(
      {
        OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC',
        OPENPC_QA_RPC_CAPABILITY_IDS: baseline,
      },
      bindings,
    ),
  );
});

test('all supported single-invocation QA capabilities are explicit and deterministic', () => {
  const selected = [
    'UNSIGNED_TRANSACTION_PREPARATION',
    'SIGNED_TRANSACTION_SUBMISSION',
    'OPERATION_STATUS_DISCLOSURE',
    'GAS_ESTIMATE_DISCLOSURE',
    'CALL_RESULT_DISCLOSURE',
    'ACCESS_LIST_DISCLOSURE',
  ];
  const scope = localQaRpcAuthority(
    {
      ...qa,
      OPENPC_QA_RPC_AUTHORITY_PROFILE: 'POLICY_CONTROLLED_RPC',
      OPENPC_QA_RPC_CAPABILITY_IDS: selected.join(','),
    },
    bindings,
  );
  assert.deepEqual(scope.runtime.capabilityIds, [...selected].sort());
  assert.equal(scope.runtime.capabilityIds.includes('MULTI_CALL_SIMULATION_DISCLOSURE'), false);
});
