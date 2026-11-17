import assert from 'node:assert/strict';

const own = (value, key) => Object.hasOwn(value, key);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const only = (value, fields) => Object.keys(value).every((key) => fields.includes(key));
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** Classify transport evidence, not application acceptance. Empty results still
 * need the case's semantic oracle; a typed denial still needs native readback. */
export function classifyRpcResponse(request, response) {
  assert.ok(record(request) && request.jsonrpc === '2.0');
  assert.ok(typeof request.id === 'string' || Number.isSafeInteger(request.id));
  if (!record(response)) return { kind: 'FAILED', reason: 'TRANSPORT_FAILURE' };
  const body = response.body;
  if (!record(body) || body.jsonrpc !== '2.0' || body.id !== request.id)
    return { kind: 'FAILED', reason: 'UNCORRELATED_RESPONSE' };
  if (!only(body, ['jsonrpc', 'id', 'result', 'error']))
    return { kind: 'FAILED', reason: 'INVALID_ENVELOPE' };
  if (own(body, 'result') === own(body, 'error'))
    return { kind: 'FAILED', reason: 'INVALID_ENVELOPE' };
  if (response.status === 200 && own(body, 'result')) return { kind: 'RESULT' };
  const error = body.error;
  const data = error?.data;
  if (
    response.status === 403 &&
    record(error) &&
    only(error, ['code', 'message', 'data']) &&
    error.code === -32001 &&
    record(data) &&
    only(data, [
      'pcCode',
      'truthState',
      'retryable',
      'traceId',
      'attemptId',
      'signedTransactionHash',
    ]) &&
    (!own(data, 'attemptId') || data.attemptId === null) &&
    (!own(data, 'signedTransactionHash') || data.signedTransactionHash === null) &&
    data.pcCode === 'PC-RUNTIME-3001' &&
    data.truthState === 'DENIED' &&
    data.retryable === false &&
    typeof data.traceId === 'string' &&
    uuid.test(data.traceId)
  )
    return { kind: 'DENIAL', traceId: data.traceId };
  return { kind: 'FAILED', reason: 'RPC_FAILURE' };
}

/** The harness supplies real fixture and case-specific readback assertions.
 * Neither a response classifier nor a binary allowed flag can
 * establish accepted privacy or a mined business effect on its own. */
export async function qualifyRpcCase({
  expected,
  denyRepresentation = 'TYPED_DENIAL',
  request,
  response,
  verifyFixture,
  verifyOutcome,
}) {
  assert.ok(expected === 'allow' || expected === 'deny');
  assert.ok(
    denyRepresentation === 'TYPED_DENIAL' || denyRepresentation === 'POLICY_FILTERED_RESULT',
  );
  assert.ok(expected === 'deny' || denyRepresentation === 'TYPED_DENIAL');
  const outcome = (state, reason) => ({
    state,
    pass: state === 'PASS',
    reason,
  });
  if (typeof verifyFixture !== 'function') return outcome('BLOCKED', 'FIXTURE_NOT_VERIFIED');
  try {
    assert.equal(await verifyFixture(), undefined);
  } catch {
    return outcome('BLOCKED', 'FIXTURE_NOT_VERIFIED');
  }
  const observation = classifyRpcResponse(request, response);
  if (observation.kind === 'FAILED') return outcome('FAIL', observation.reason);
  // Some privacy cases permit owner-filtered event/record results.
  // Select that representation explicitly; an empty result alone proves none.
  const expectedKind =
    expected === 'allow' || denyRepresentation === 'POLICY_FILTERED_RESULT' ? 'RESULT' : 'DENIAL';
  if (observation.kind !== expectedKind) return outcome('FAIL', 'UNEXPECTED_OUTCOME');
  if (typeof verifyOutcome !== 'function') return outcome('BLOCKED', 'CASE_EVIDENCE_NOT_VERIFIED');
  try {
    assert.equal(await verifyOutcome(observation), undefined);
  } catch {
    return outcome('FAIL', 'CASE_EVIDENCE_NOT_VERIFIED');
  }
  return outcome('PASS', 'CORRELATED_CASE_EVIDENCE_VERIFIED');
}
