import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { startPgCommitFault } from './withdrawal-commit-fault.mjs';

const MAX_FRAME = 16 * 1024 * 1024;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digest = /^sha256:[0-9a-f]{64}$/u;
export const expiredDenialQuery =
  'select binding,admission_digest from openpc.begin_expired_activation_denial($1,$2,$3)';
export const activationObservationQuery =
  'insert into control.runtime_activation_observation(participant_id,privacy_domain_id,configuration_work_id,operation_id,execution_attempt_id,runtime_configuration_generation_id,runtime_target_id,generation_digest,capsule_digest,xds_version_digest,activation_receipt,activation_receipt_digest) values ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8,$9,$10,$11,$12)';

function cstring(bytes, offset = 0) {
  const end = bytes.indexOf(0, offset);
  assert.ok(end >= offset, 'Invalid PostgreSQL string');
  return [bytes.toString('utf8', offset, end), end + 1];
}

function parameters(body, start) {
  let cursor = start;
  const formats = body.readUInt16BE(cursor);
  cursor += 2;
  assert.ok(formats <= 64 && cursor + formats * 2 + 2 <= body.length);
  const codes = Array.from({ length: formats }, () => {
    const code = body.readUInt16BE(cursor);
    cursor += 2;
    assert.ok(code === 0 || code === 1, 'Unsupported parameter format');
    return code;
  });
  const count = body.readUInt16BE(cursor);
  cursor += 2;
  assert.ok(count <= 64 && (formats === 0 || formats === 1 || formats === count));
  const values = Array.from({ length: count }, (_, index) => {
    const length = body.readInt32BE(cursor);
    cursor += 4;
    if (length === -1) return { bytes: null, format: codes[index] ?? codes[0] ?? 0 };
    assert.ok(length >= 0 && length <= MAX_FRAME && cursor + length <= body.length);
    const bytes = body.subarray(cursor, cursor + length);
    cursor += length;
    return { bytes, format: codes[index] ?? codes[0] ?? 0 };
  });
  const results = body.readUInt16BE(cursor);
  cursor += 2;
  assert.ok(results <= 64 && cursor + results * 2 === body.length);
  for (let index = 0; index < results; index++)
    assert.ok(body.readUInt16BE(cursor + index * 2) <= 1, 'Unsupported result format');
  return values;
}

function bytea(value) {
  if (!value?.bytes) return undefined;
  if (value.format === 1) return value.bytes;
  const text = value.bytes.toString('utf8');
  if (!/^\\x(?:[0-9a-f]{2})*$/u.test(text)) return undefined;
  return Buffer.from(text.slice(2), 'hex');
}

function exactFields(value, required, optional = []) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  const fields = new Set([...required, ...optional]);
  assert.ok(
    Object.keys(value).every((field) => fields.has(field)),
    'Unexpected correlation field',
  );
  assert.ok(
    required.every((field) => Object.hasOwn(value, field)),
    'Missing correlation field',
  );
  return Object.freeze({ ...value });
}

/** Correlation only: successful native command and real COMMIT must both be
 * observed. It cannot execute a query, admit an operation or supply a permit. */
class NativeCommitCorrelation {
  constructor(query, command, select) {
    this.query = query;
    this.command = command;
    this.select = select;
    this.statements = new Map();
    this.portals = new Map();
    this.pending = [];
    this.reset();
  }

  reset() {
    this.admitted = null;
    this.matches = 0;
    this.nativeCompletions = 0;
  }

  frontend(tag, body) {
    if (tag === 'P') {
      const [name, start] = cstring(body);
      const [query, end] = cstring(body, start);
      assert.equal(end + 2 + body.readUInt16BE(end) * 4, body.length);
      this.statements.set(name, query === this.query);
      assert.ok(this.statements.size <= 512, 'Prepared statement bound');
    } else if (tag === 'B') {
      const [portal, start] = cstring(body);
      const [statement, end] = cstring(body, start);
      const values = parameters(body, end);
      const native = this.statements.get(statement) === true;
      this.portals.set(portal, { native, selection: native ? this.select(values) : null });
      assert.ok(this.portals.size <= 512, 'Portal bound');
    } else if (tag === 'E') {
      const [portal, end] = cstring(body);
      assert.equal(end + 4, body.length);
      assert.equal(body.readUInt32BE(end), 0, 'Suspended portals unsupported');
      this.pending.push({
        native: this.portals.get(portal)?.native ?? false,
        selection: this.portals.get(portal)?.selection ?? null,
        command: null,
      });
    } else if (tag === 'Q') {
      const [query, end] = cstring(body);
      assert.equal(end, body.length);
      const command = query.trim().toUpperCase();
      this.pending.push({
        selection: null,
        command: ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(command) ? command : null,
      });
    } else if (tag === 'C') {
      const [name, end] = cstring(body, 1);
      assert.equal(end, body.length);
      if (body[0] === 83) this.statements.delete(name);
      else if (body[0] === 80) this.portals.delete(name);
      else assert.fail('Unsupported close target');
    }
    assert.ok(this.pending.length <= 64, 'Pending command bound');
  }

  backend(tag, body) {
    if (tag === 'E') {
      this.pending = [];
      this.reset();
    } else if (tag === 'Z') {
      this.pending = [];
      if (body[0] !== 84) this.reset();
    } else if (tag === 'C') {
      const command = cstring(body)[0];
      const executed = this.pending.shift();
      if (command === 'COMMIT') {
        const result =
          executed?.command === 'COMMIT' && this.matches === 1 && this.nativeCompletions === 1
            ? this.admitted
            : null;
        this.reset();
        return result;
      }
      if (command === 'ROLLBACK' || command === 'BEGIN') this.reset();
      if (command === this.command && executed?.native) {
        this.nativeCompletions++;
        if (executed.selection) {
          this.matches++;
          this.admitted = executed.selection;
        }
      }
    } else if (tag === 'I') this.pending.shift();
    return null;
  }
}

export class ExpiredDenialCommitCorrelation extends NativeCommitCorrelation {
  constructor(expected) {
    const binding = exactFields(expected, [
      'participantId',
      'privacyDomainId',
      'targetId',
      'workId',
      'executionAttemptId',
      'intentDigest',
    ]);
    for (const field of [
      'participantId',
      'privacyDomainId',
      'targetId',
      'workId',
      'executionAttemptId',
    ])
      assert.match(binding[field], uuid);
    assert.match(binding.intentDigest, digest);
    super(expiredDenialQuery, 'SELECT 1', (values) => {
      if (values.length !== 3) return null;
      const wire = bytea(values[0]),
        nonce = bytea(values[1]),
        mac = bytea(values[2]);
      if (!wire || wire.length > 2 * 1024 * 1024 || nonce?.length !== 32 || mac?.length !== 32)
        return null;
      let proof;
      try {
        proof = JSON.parse(wire.toString('utf8'));
      } catch {
        return null;
      }
      if (!proof || typeof proof !== 'object' || Array.isArray(proof)) return null;
      if (
        proof.intentDigest !== binding.intentDigest ||
        proof.source?.original_work_id !== binding.workId ||
        proof.source?.original_execution_attempt_id !== binding.executionAttemptId ||
        proof.target?.target_id !== binding.targetId ||
        proof.target?.participant_id !== binding.participantId ||
        proof.target?.privacy_domain_id !== binding.privacyDomainId ||
        typeof proof.intentBytesHex !== 'string' ||
        !/^(?:[0-9a-f]{2})+$/u.test(proof.intentBytesHex) ||
        'sha256:' +
          createHash('sha256').update(Buffer.from(proof.intentBytesHex, 'hex')).digest('hex') !==
          binding.intentDigest
      )
        return null;
      return binding;
    });
  }
}

function activationObservationBinding(expected) {
  const binding = exactFields(
    expected,
    [
      'participantId',
      'privacyDomainId',
      'targetId',
      'workId',
      'operationId',
      'generationId',
      'generationDigest',
    ],
    ['executionAttemptId'],
  );
  for (const field of [
    'participantId',
    'privacyDomainId',
    'targetId',
    'workId',
    'operationId',
    'generationId',
  ])
    assert.match(binding[field], uuid);
  assert.match(binding.generationDigest, digest);
  if (binding.executionAttemptId !== undefined) assert.match(binding.executionAttemptId, uuid);
  return binding;
}

function selectActivationObservation(binding, values) {
  if (!binding || values.length !== 12) return null;
  const text = values.map((value) => value.bytes?.toString('utf8'));
  if (
    text[0] !== binding.participantId ||
    text[1] !== binding.privacyDomainId ||
    text[2] !== binding.workId ||
    text[3] !== binding.operationId ||
    !uuid.test(text[4] ?? '') ||
    (binding.executionAttemptId !== undefined && text[4] !== binding.executionAttemptId) ||
    text[5] !== binding.generationId ||
    text[6] !== binding.targetId ||
    text[7] !== binding.generationDigest ||
    !digest.test(text[8] ?? '') ||
    !digest.test(text[9] ?? '') ||
    !digest.test(text[11] ?? '')
  )
    return null;
  return Object.freeze({
    ...binding,
    executionAttemptId: text[4],
    capsuleDigest: text[8],
    xdsVersionDigest: text[9],
    activationReceiptDigest: text[11],
  });
}

export class ActivationObservationCommitCorrelation extends NativeCommitCorrelation {
  constructor(expected) {
    const binding = activationObservationBinding(expected);
    super(activationObservationQuery, 'INSERT 0 1', (values) =>
      selectActivationObservation(binding, values),
    );
  }
}

/** Metadata only. Bind once after the public operation exists, retaining the
 * original worker's connections and prepared statements. Selection happens at
 * PostgreSQL Bind, so binding never retroactively selects an earlier command. */
export class ActivationObservationCommitBinding {
  #binding;

  bind(expected) {
    assert.equal(this.#binding, undefined, 'Observation selector is already bound');
    this.#binding = activationObservationBinding(expected);
  }

  assertBound() {
    assert.ok(this.#binding, 'Observation selector must be bound before arming');
  }

  correlation() {
    return new NativeCommitCorrelation(activationObservationQuery, 'INSERT 0 1', (values) =>
      selectActivationObservation(this.#binding, values),
    );
  }
}

export function startExpiredDenialCommitFault({ expected, ...options }) {
  const pinned = Object.freeze({ ...expected });
  // Validate before allocating the listener, including when it receives no connections.
  new ExpiredDenialCommitCorrelation(pinned);
  return startPgCommitFault({
    ...options,
    correlationFactory: () => new ExpiredDenialCommitCorrelation(pinned),
    describeCommit: (selection) => ({ ...selection, count: 1 }),
  });
}

export function startActivationObservationCommitFault({ expected, ...options }) {
  const pinned = Object.freeze({ ...expected });
  new ActivationObservationCommitCorrelation(pinned);
  return startPgCommitFault({
    ...options,
    correlationFactory: () => new ActivationObservationCommitCorrelation(pinned),
    describeCommit: (selection) => ({ ...selection, count: 1 }),
  });
}

export async function startDeferredActivationObservationCommitFault(options) {
  assert.ok(options && !Object.hasOwn(options, 'expected'), 'Use the single-use bind method');
  const binding = new ActivationObservationCommitBinding();
  const proxy = await startPgCommitFault({
    ...options,
    correlationFactory: () => binding.correlation(),
    describeCommit: (selection) => ({ ...selection, count: 1 }),
  });
  return {
    ...proxy,
    bind: (expected) => binding.bind(expected),
    arm() {
      binding.assertBound();
      proxy.arm();
    },
  };
}
