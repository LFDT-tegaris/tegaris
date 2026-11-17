import assert from 'node:assert/strict';
import { createHash, createPublicKey, ECDH, verify } from 'node:crypto';
import { Pool } from 'pg';
import { runtimeSourceDenialEnvelopeShape } from '../../../services/control-api/src/evidence/runtime-artifact-source-wire.mjs';

// Input comes from typed Rust SourceDenial/PurposeSigner, never a SQL-shaped
// fixture. This checks encoding and signature interoperability, not governance.
const mode = process.argv[2];
assert.ok(['pure', 'postgres'].includes(mode));
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const fixture = JSON.parse(Buffer.concat(chunks));
const wire = Buffer.from(fixture.wire);
const point = ECDH.convertKey(
  Buffer.from(fixture.publicKey),
  'prime256v1',
  undefined,
  undefined,
  'uncompressed',
);
const key = createPublicKey({
  format: 'jwk',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'),
  },
});
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
function ordered(value, shape) {
  if (shape === 'nullable-string' && value === null) return null;
  if (typeof shape === 'string') {
    if (shape === 'uint') assert.ok(Number.isSafeInteger(value) && value >= 0);
    else assert.equal(typeof value, 'string');
    return value;
  }
  if (Array.isArray(shape)) {
    assert.ok(Array.isArray(value));
    return value.map((item) => ordered(item, shape[0]));
  }
  assert.equal(typeof value, 'object');
  assert.notEqual(value, null);
  assert.deepEqual(Object.keys(value).sort(), Object.keys(shape).sort());
  return Object.fromEntries(
    Object.entries(shape).map(([name, child]) => [name, ordered(value[name], child)]),
  );
}
function consume(bytes) {
  const value = ordered(
    JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
    runtimeSourceDenialEnvelopeShape,
  );
  assert.deepEqual(Buffer.from(JSON.stringify(value)), bytes);
  assert.equal(value.purpose, 'openpc:runtime-artifact-source-denial:v1');
  assert.equal(value.claims.version, 2);
  assert.equal(value.claims_digest, hash(JSON.stringify(value.claims)));
  assert.match(value.signature_p1363_hex, /^[0-9a-f]{128}$/u);
  assert.equal(
    verify(
      'sha256',
      Buffer.from(JSON.stringify([value.purpose, value.claims_digest])),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(value.signature_p1363_hex, 'hex'),
    ),
    true,
  );
  return value;
}
const original = consume(wire);
const cases = [];
const changed = (name, change, kind = 'digest') => {
  const value = structuredClone(original);
  change(value);
  cases.push({ name, wire: Buffer.from(JSON.stringify(value)), kind });
};
function objectCases(value, path = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return;
  const locate = (document) => path.reduce((entry, part) => entry[part], document);
  const keys = Object.keys(value);
  changed(
    `unknown ${path.join('.')}`,
    (v) => {
      locate(v).unknown = true;
    },
    'encoding',
  );
  changed(
    `missing ${path.join('.')}`,
    (v) => {
      delete locate(v)[keys[0]];
    },
    'encoding',
  );
  const reversed = structuredClone(original);
  const parent = path.length
    ? path.slice(0, -1).reduce((entry, part) => entry[part], reversed)
    : null;
  const object = Object.fromEntries(Object.entries(locate(reversed)).reverse());
  if (parent) parent[path.at(-1)] = object;
  cases.push({
    name: `order ${path.join('.')}`,
    wire: Buffer.from(JSON.stringify(parent ? reversed : object)),
    kind: 'encoding',
  });
  for (const [name, child] of Object.entries(value)) objectCases(child, [...path, name]);
}
objectCases(original);
for (const [name, text] of [
  ['duplicate', wire.toString().replace('"version":2', '"version":2,"version":2')],
  ['whitespace', JSON.stringify(original, null, 2)],
  ['decimal', wire.toString().replace('"version":2', '"version":2.0')],
  ['exponent', wire.toString().replace('"version":2', '"version":2e0')],
  ['malformed', '{'],
])
  cases.push({ name, wire: Buffer.from(text), kind: 'encoding' });
cases.push({ name: 'invalid UTF8', wire: Buffer.from([0xff]), kind: 'encoding' });
changed('wrong sequence', (v) => {
  v.claims.sequence++;
});
changed('wrong identity', (v) => {
  v.claims.admission.input_id = v.claims.admission.operation_id;
});
changed('wrong digest', (v) => {
  v.claims_digest = '0'.repeat(64);
});
changed(
  'wrong signature',
  (v) => {
    v.signature_p1363_hex = '0'.repeat(128);
  },
  'signature',
);
changed(
  'non-integer',
  (v) => {
    v.claims.sequence = 1.5;
  },
  'encoding',
);
changed(
  'wrong type',
  (v) => {
    v.claims.custody.consumers = {};
  },
  'encoding',
);
changed(
  'null omission',
  (v) => {
    delete v.claims.previous_denial_digest;
  },
  'encoding',
);
for (const test of cases) assert.throws(() => consume(test.wire), undefined, test.name);

if (mode === 'postgres') {
  assert.ok(process.env.OPENPC_I02_ADMIN_DATABASE_URL);
  const pool = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 1 });
  const inspect = async (bytes) => {
    const {
      rows: [result],
    } = await pool.query(
      `select
      openpc.runtime_artifact_source_denial_envelope_bytes(convert_from($1,'UTF8')::jsonb)=$1 encoding,
      encode(sha256(openpc.runtime_artifact_source_denial_claims_bytes(convert_from($1,'UTF8')::jsonb->'claims')),'hex')
       =convert_from($1,'UTF8')::jsonb->>'claims_digest' digest`,
      [bytes],
    );
    return result.encoding === true && result.digest === true;
  };
  try {
    assert.equal(await inspect(wire), true);
    for (const test of cases.filter((v) => v.kind !== 'signature')) {
      let accepted;
      try {
        accepted = await inspect(test.wire);
      } catch (error) {
        assert.ok(['22P02', '22021', '22023'].includes(error.code), `${test.name}: ${error.code}`);
        accepted = false;
      }
      assert.equal(accepted, false, test.name);
    }
    assert.equal(await inspect(wire), true);
  } finally {
    await pool.end();
  }
}
process.stdout.write(
  `OPENPC_SOURCE_DENIAL_WIRE|PASS|mode=${mode}|actual-typed-Rust|native-signature|closed-shapes|negative=${cases.length}\n`,
);
