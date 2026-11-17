import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  ActivationObservationCommitBinding,
  ActivationObservationCommitCorrelation,
  ExpiredDenialCommitCorrelation,
  activationObservationQuery,
  expiredDenialQuery,
  startExpiredDenialCommitFault,
  startDeferredActivationObservationCommitFault,
} from './credential-continuity-commit-fault.mjs';

// Protocol regressions only. A synthetic CommandComplete is not database,
// admission, signature or runtime acceptance evidence.
const id = (n) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const hash = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const text = (value) => Buffer.from(value + '\0');
function u16(value) {
  const result = Buffer.alloc(2);
  result.writeUInt16BE(value);
  return result;
}
function u32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}
const expected = Object.freeze({
  participantId: id(1),
  privacyDomainId: id(2),
  targetId: id(3),
  workId: id(4),
  executionAttemptId: id(5),
  intentDigest: hash(Buffer.from('{"purpose":"isolated-original"}')),
});
const originalProof = () => ({
  intentDigest: expected.intentDigest,
  intentBytesHex: Buffer.from('{"purpose":"isolated-original"}').toString('hex'),
  source: {
    original_work_id: expected.workId,
    original_execution_attempt_id: expected.executionAttemptId,
  },
  target: {
    target_id: expected.targetId,
    participant_id: expected.participantId,
    privacy_domain_id: expected.privacyDomainId,
  },
});
const denialValues = (proof = originalProof()) => [
  Buffer.from(JSON.stringify(proof)),
  Buffer.alloc(32, 1),
  Buffer.alloc(32, 2),
];
function prepare(correlation, query, statement = 'native', portal = '') {
  correlation.frontend('P', Buffer.concat([text(statement), text(query), u16(0)]));
  return { statement, portal };
}
function execute(
  correlation,
  values,
  { statement = 'native', portal = '', binary = true, bytea = false, deferExecute = false } = {},
) {
  const parameters = values.map((value) =>
    value === null
      ? null
      : bytea && !binary
        ? Buffer.from('\\x' + value.toString('hex'))
        : Buffer.from(value),
  );
  correlation.frontend(
    'B',
    Buffer.concat([
      text(portal),
      text(statement),
      u16(1),
      u16(binary ? 1 : 0),
      u16(parameters.length),
      ...parameters.flatMap((value) =>
        value === null ? [Buffer.from([255, 255, 255, 255])] : [u32(value.length), value],
      ),
      u16(0),
    ]),
  );
  if (!deferExecute) correlation.frontend('E', Buffer.concat([text(portal), u32(0)]));
}
function finish(correlation, completion = 'SELECT 1', commit = 'COMMIT') {
  correlation.backend('C', text(completion));
  correlation.frontend('Q', text(commit));
  return correlation.backend('C', text('COMMIT'));
}

test('credential continuity correlators match exact native owner queries', async () => {
  const denial = await readFile(
    'services/fleet-controller/src/target_disposition/expired.rs',
    'utf8',
  );
  const observation = await readFile(
    'services/fleet-controller/src/bin/local_runtime_worker/activation_observation.rs',
    'utf8',
  );
  assert.ok(denial.includes('"' + expiredDenialQuery + '"'));
  assert.ok(observation.includes('"' + activationObservationQuery + '"'));
});

for (const binary of [true, false])
  test(`credential continuity denial correlates the original bound bytea intent (${binary ? 'binary' : 'text'})`, () => {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, expiredDenialQuery);
    execute(correlation, denialValues(), { binary, bytea: true });
    assert.deepEqual(finish(correlation), expected);
    assert.equal(correlation.backend('C', text('COMMIT')), null);
    assert.equal(JSON.stringify(correlation).includes('intentBytesHex'), false);
  });

for (const field of [
  'participantId',
  'privacyDomainId',
  'targetId',
  'workId',
  'executionAttemptId',
  'intentDigest',
])
  test(`credential continuity denial cannot arm for a different ${field}`, () => {
    const correlation = new ExpiredDenialCommitCorrelation({
      ...expected,
      [field]: field === 'intentDigest' ? hash('different') : id(99),
    });
    prepare(correlation, expiredDenialQuery);
    execute(correlation, denialValues());
    assert.equal(finish(correlation), null);
  });

for (const [name, values] of [
  ['null proof', denialValues(null)],
  ['array proof', denialValues([])],
  ['missing proof', denialValues({})],
  [
    'changed original bytes',
    denialValues({ ...originalProof(), intentBytesHex: Buffer.from('{}').toString('hex') }),
  ],
  ['nonhex original bytes', denialValues({ ...originalProof(), intentBytesHex: 'not-hex' })],
  ['short nonce', [denialValues()[0], Buffer.alloc(31), Buffer.alloc(32)]],
  ['short MAC', [denialValues()[0], Buffer.alloc(32), Buffer.alloc(31)]],
  ['missing parameter', denialValues().slice(0, 2)],
  ['null parameter', [null, Buffer.alloc(32), Buffer.alloc(32)]],
])
  test(`credential continuity denial ignores ${name}`, () => {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, expiredDenialQuery);
    execute(correlation, values);
    assert.equal(finish(correlation), null);
  });

test('credential continuity requires the native query, one successful result and a matching real commit completion', () => {
  for (const query of [expiredDenialQuery + '; select 1', 'select 1']) {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, query);
    execute(correlation, denialValues());
    assert.equal(finish(correlation), null);
  }
  for (const completion of ['SELECT 0', 'INSERT 0 1', 'ROLLBACK']) {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, expiredDenialQuery);
    execute(correlation, denialValues());
    assert.equal(finish(correlation, completion), null);
  }
  const multi = new ExpiredDenialCommitCorrelation(expected);
  prepare(multi, expiredDenialQuery);
  execute(multi, denialValues());
  assert.equal(finish(multi, 'SELECT 1', 'COMMIT; select 1'), null);
  const duplicate = new ExpiredDenialCommitCorrelation(expected);
  prepare(duplicate, expiredDenialQuery);
  for (let index = 0; index < 2; index++) {
    execute(duplicate, denialValues());
    duplicate.backend('C', text('SELECT 1'));
  }
  duplicate.frontend('Q', text('COMMIT'));
  assert.equal(duplicate.backend('C', text('COMMIT')), null);
});

test('credential continuity correlation resets on rollback, error and idle readiness and never crosses connections', () => {
  for (const [tag, body] of [
    ['C', text('ROLLBACK')],
    ['E', Buffer.alloc(0)],
    ['Z', Buffer.from('I')],
  ]) {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, expiredDenialQuery);
    execute(correlation, denialValues());
    correlation.backend('C', text('SELECT 1'));
    correlation.backend(tag, body);
    correlation.frontend('Q', text('COMMIT'));
    assert.equal(correlation.backend('C', text('COMMIT')), null);
  }
  const first = new ExpiredDenialCommitCorrelation(expected),
    second = new ExpiredDenialCommitCorrelation(expected);
  prepare(first, expiredDenialQuery);
  execute(first, denialValues());
  first.backend('C', text('SELECT 1'));
  second.frontend('Q', text('COMMIT'));
  assert.equal(second.backend('C', text('COMMIT')), null);
  first.frontend('Q', text('COMMIT'));
  assert.deepEqual(first.backend('C', text('COMMIT')), expected);
});

const observed = Object.freeze({
  participantId: id(1),
  privacyDomainId: id(2),
  targetId: id(3),
  workId: id(4),
  operationId: id(6),
  generationId: id(7),
  generationDigest: hash('generation'),
});
const observationValues = () =>
  [
    observed.participantId,
    observed.privacyDomainId,
    observed.workId,
    observed.operationId,
    id(5),
    observed.generationId,
    observed.targetId,
    observed.generationDigest,
    hash('capsule'),
    hash('xds'),
    '{"signed":"external-protocol-fixture-only"}',
    hash('receipt'),
  ].map((value) => Buffer.from(value));

for (const binary of [true, false])
  test(`credential continuity observation binds the exact native work and captures its original attempt (${binary ? 'binary' : 'text'})`, () => {
    const correlation = new ActivationObservationCommitCorrelation(observed);
    prepare(correlation, activationObservationQuery);
    execute(correlation, observationValues(), { binary });
    assert.deepEqual(finish(correlation, 'INSERT 0 1'), {
      ...observed,
      executionAttemptId: id(5),
      capsuleDigest: hash('capsule'),
      xdsVersionDigest: hash('xds'),
      activationReceiptDigest: hash('receipt'),
    });
  });

for (const [index, name] of [
  [0, 'participant'],
  [1, 'privacy'],
  [2, 'work'],
  [3, 'operation'],
  [5, 'generation'],
  [6, 'target'],
  [7, 'generation digest'],
  [8, 'capsule digest'],
  [9, 'xds digest'],
  [11, 'receipt digest'],
])
  test(`credential continuity observation cannot arm for a foreign or invalid ${name}`, () => {
    const correlation = new ActivationObservationCommitCorrelation(observed);
    const values = observationValues();
    values[index] = Buffer.from(index < 7 ? id(99) : 'not-a-digest');
    prepare(correlation, activationObservationQuery);
    execute(correlation, values);
    assert.equal(finish(correlation, 'INSERT 0 1'), null);
  });

test('credential continuity observation rejects a changed known attempt and never accepts a query-only receipt', () => {
  const correlation = new ActivationObservationCommitCorrelation({
    ...observed,
    executionAttemptId: id(99),
  });
  prepare(correlation, activationObservationQuery);
  execute(correlation, observationValues());
  assert.equal(finish(correlation, 'INSERT 0 1'), null);
  const wrongCommand = new ActivationObservationCommitCorrelation(observed);
  prepare(wrongCommand, activationObservationQuery);
  execute(wrongCommand, observationValues());
  assert.equal(finish(wrongCommand, 'SELECT 1'), null);
});

test('credential continuity validates exact selectors before a fault listener can be allocated', () => {
  assert.throws(
    () => new ExpiredDenialCommitCorrelation({ ...expected, privateKey: 'never-retain' }),
  );
  assert.throws(
    () => new ActivationObservationCommitCorrelation({ ...observed, targetId: 'invalid' }),
  );
  assert.throws(() =>
    startExpiredDenialCommitFault({
      expected: { ...expected, intentDigest: 'invalid' },
      host: '127.0.0.1',
    }),
  );
  const malformed = new ExpiredDenialCommitCorrelation(expected);
  assert.throws(() => malformed.frontend('B', Buffer.from([0])));
});

for (const selectedFirst of [true, false]) {
  test(`credential continuity denial excludes mixed native invocations (${selectedFirst ? 'selected first' : 'foreign first'})`, () => {
    const correlation = new ExpiredDenialCommitCorrelation(expected);
    prepare(correlation, expiredDenialQuery);
    const foreign = originalProof();
    foreign.source.original_work_id = id(99);
    const values = [denialValues(), denialValues(foreign)];
    if (!selectedFirst) values.reverse();
    for (const value of values) {
      execute(correlation, value);
      correlation.backend('C', text('SELECT 1'));
    }
    correlation.frontend('Q', text('COMMIT'));
    assert.equal(correlation.backend('C', text('COMMIT')), null);
  });
  test(`credential continuity observation excludes mixed native invocations (${selectedFirst ? 'selected first' : 'foreign first'})`, () => {
    const correlation = new ActivationObservationCommitCorrelation(observed);
    prepare(correlation, activationObservationQuery);
    const foreign = observationValues();
    foreign[2] = Buffer.from(id(99));
    const values = [observationValues(), foreign];
    if (!selectedFirst) values.reverse();
    for (const value of values) {
      execute(correlation, value);
      correlation.backend('C', text('INSERT 0 1'));
    }
    correlation.frontend('Q', text('COMMIT'));
    assert.equal(correlation.backend('C', text('COMMIT')), null);
  });
}

test('credential continuity still admits an exact native command with ordinary setup and read queries', () => {
  const correlation = new ExpiredDenialCommitCorrelation(expected);
  correlation.frontend('Q', text('BEGIN'));
  correlation.backend('C', text('BEGIN'));
  prepare(correlation, 'select current_user', 'ordinary');
  execute(correlation, [], { statement: 'ordinary' });
  correlation.backend('C', text('SELECT 1'));
  prepare(correlation, expiredDenialQuery);
  execute(correlation, denialValues());
  correlation.backend('C', text('SELECT 1'));
  execute(correlation, [], { statement: 'ordinary' });
  correlation.backend('C', text('SELECT 1'));
  correlation.frontend('Q', text('COMMIT'));
  assert.deepEqual(correlation.backend('C', text('COMMIT')), expected);
});

test('deferred observation binding preserves the original connection and prepared query', () => {
  const binding = new ActivationObservationCommitBinding();
  const correlation = binding.correlation();
  prepare(correlation, activationObservationQuery);
  execute(correlation, observationValues());
  assert.equal(finish(correlation, 'INSERT 0 1'), null, 'Unbound W1 passes without selection');
  assert.throws(() => binding.assertBound(), /must be bound/);
  const actual = { ...observed };
  binding.bind(actual);
  actual.workId = id(99);
  binding.assertBound();
  execute(correlation, observationValues());
  const selected = finish(correlation, 'INSERT 0 1');
  assert.equal(selected.workId, observed.workId, 'Caller mutation cannot change the selector');
  assert.equal(selected.executionAttemptId, id(5));
  const reconnected = binding.correlation();
  prepare(reconnected, activationObservationQuery);
  execute(reconnected, observationValues());
  assert.deepEqual(finish(reconnected, 'INSERT 0 1'), selected);
  assert.throws(() => binding.bind(observed), /already bound/);
});

test('deferred observation binding never selects a portal already bound on the wire', () => {
  const binding = new ActivationObservationCommitBinding();
  const correlation = binding.correlation();
  prepare(correlation, activationObservationQuery);
  execute(correlation, observationValues(), { deferExecute: true });
  binding.bind(observed);
  correlation.frontend('E', Buffer.concat([text(''), u32(0)]));
  assert.equal(finish(correlation, 'INSERT 0 1'), null);
});

for (const selectedFirst of [true, false])
  test(`deferred observation rejects mixed original and foreign completions (${selectedFirst})`, () => {
    const binding = new ActivationObservationCommitBinding();
    const correlation = binding.correlation();
    prepare(correlation, activationObservationQuery);
    binding.bind(observed);
    const foreign = observationValues();
    foreign[2] = Buffer.from(id(99));
    const values = [observationValues(), foreign];
    if (!selectedFirst) values.reverse();
    for (const value of values) {
      execute(correlation, value);
      correlation.backend('C', text('INSERT 0 1'));
    }
    correlation.frontend('Q', text('COMMIT'));
    assert.equal(correlation.backend('C', text('COMMIT')), null);
  });

test('deferred observation proxy cannot arm before a valid single-use binding', async () => {
  const proxy = await startDeferredActivationObservationCommitFault({
    host: '127.0.0.1',
    upstreamHost: '127.0.0.1',
    upstreamPort: 1,
  });
  try {
    assert.throws(() => proxy.arm(), /must be bound/);
    assert.throws(() => proxy.bind({ ...observed, targetId: 'invalid' }));
    assert.throws(() => proxy.arm(), /must be bound/);
    proxy.bind(observed);
    assert.throws(() => proxy.bind(observed), /already bound/);
    proxy.arm();
    assert.throws(() => proxy.arm());
    assert.equal(proxy.committed(), null);
    assert.equal(proxy.status(), null);
  } finally {
    await proxy.close();
  }
});

test('deferred binding preserves pre-bind native completions in a mixed transaction', () => {
  const binding = new ActivationObservationCommitBinding();
  const correlation = binding.correlation();
  prepare(correlation, activationObservationQuery);
  execute(correlation, observationValues());
  correlation.backend('C', text('INSERT 0 1'));
  binding.bind(observed);
  execute(correlation, observationValues());
  correlation.backend('C', text('INSERT 0 1'));
  correlation.frontend('Q', text('COMMIT'));
  assert.equal(correlation.backend('C', text('COMMIT')), null);
});
