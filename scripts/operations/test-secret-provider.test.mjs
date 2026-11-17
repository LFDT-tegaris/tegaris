import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { test } from 'node:test';
import {
  bindTestFactCandidateDatabaseReference,
  testFactCandidateDatabaseConsumer,
} from './installation-consumer-bindings.mjs';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import { createTestSecretProvider } from './test-secret-provider.mjs';

const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
const password = 'synthetic_test_only_password_123456789';
const binding = () => bindTestFactCandidateDatabaseReference(reference, 'v1');
const material = (overrides = {}) => {
  const target = { ...testFactCandidateDatabaseConsumer, password, ...overrides };
  return Buffer.from(
    `postgresql://${target.databaseRole}:${target.password}@${target.databaseHost}:${target.databasePort}/${target.databaseName}`,
  );
};

function fixture() {
  const bytes = material();
  try {
    return createTestSecretProvider(binding(), bytes);
  } finally {
    bytes.fill(0);
  }
}

function rejection(reason) {
  return (error) => {
    assert.ok(error instanceof InstallationConfigError);
    assert.equal(error.code, 'OPS_TEST_SECRET_PROVIDER_INVALID');
    assert.equal(error.reason, reason);
    assert.equal(error.message, `OPS_TEST_SECRET_PROVIDER_INVALID: ${reason}`);
    assert.equal(error.cause, undefined);
    for (const output of [error.message, error.stack, JSON.stringify(error), inspect(error)]) {
      assert.ok(!output.includes(password));
      assert.ok(!output.includes(reference));
      assert.ok(!output.includes('postgresql://'));
    }
    return true;
  };
}

test('exact TEST fixture hands off isolated bytes and retains BLOCKED readiness', async () => {
  const provider = fixture();
  const expected = material();
  let delivered;
  const result = await provider.withMaterial(binding(), (bytes) => {
    assert.deepEqual(bytes, expected);
    delivered = bytes;
    return bytes;
  });
  assert.equal(result, undefined);
  assert.ok(delivered.every((value) => value === 0));
  assert.deepEqual(provider.describe(), {
    profile: 'test',
    providerId: 'test-memory-resolver',
    synthetic: true,
    providerState: 'ACTIVE',
    state: 'BLOCKED',
    startupAllowed: false,
    workloadAuthentication: 'UNVERIFIED',
    mountDelivery: 'UNVERIFIED',
  });
  assert.ok(Object.isFrozen(provider));
  assert.ok(Object.isFrozen(provider.describe()));
  provider.reset();
  expected.fill(0);
});

test('every committed consumer field is required and exact, with no added admission flags', () => {
  const original = binding();
  for (const key of Object.keys(testFactCandidateDatabaseConsumer)) {
    const absent = { ...original };
    delete absent[key];
    assert.throws(() => createTestSecretProvider(absent), rejection('BINDING_INVALID'));
    const value = original[key];
    const changed =
      typeof value === 'boolean'
        ? !value
        : typeof value === 'number'
          ? value + 1
          : `${value}-wrong`;
    assert.throws(
      () => createTestSecretProvider({ ...original, [key]: changed }),
      rejection('BINDING_INVALID'),
    );
  }
  for (const extra of [
    { authenticated: true },
    { ready: true },
    { material: password },
    { [Symbol('extra')]: true },
  ]) {
    assert.throws(
      () => createTestSecretProvider({ ...original, ...extra }),
      rejection('BINDING_INVALID'),
    );
  }
  let getterCalled = false;
  const accessor = { ...original };
  Object.defineProperty(accessor, 'reference', {
    get() {
      getterCalled = true;
      throw new Error(password);
    },
  });
  assert.throws(() => createTestSecretProvider(accessor), rejection('BINDING_INVALID'));
  assert.equal(getterCalled, false);
  for (const value of [null, undefined, [], reference, Object.create(original)]) {
    assert.throws(() => createTestSecretProvider(value), rejection('BINDING_INVALID'));
  }
  const proxy = new Proxy(original, {
    getPrototypeOf() {
      throw new Error(password);
    },
  });
  assert.throws(() => createTestSecretProvider(proxy), rejection('BINDING_INVALID'));
});

test('references reuse the shared exact-version law and forbid other providers and path aliases', () => {
  for (const [value, version] of [
    ['secret://local-os-keystore/fact/candidate-reader#v1', 'v1'],
    ['secret://kubernetes-csi/fact/candidate-reader#v1', 'v1'],
    ['secret://test-memory-resolver/fact/candidate-reader#latest', 'latest'],
    ['secret://test-memory-resolver/fact/candidate-reader#CURRENT', 'CURRENT'],
    [reference, 'v2'],
    ['secret://test-memory-resolver/fact/candidate-reader', 'v1'],
    ['secret://test-memory-resolver/fact/../reader#v1', 'v1'],
    ['secret://test-memory-resolver/fact//reader#v1', 'v1'],
    ['secret://test-memory-resolver/fact/./reader#v1', 'v1'],
    [`${reference}\n`, 'v1'],
  ]) {
    assert.throws(
      () => createTestSecretProvider({ ...binding(), reference: value, version }),
      rejection('BINDING_INVALID'),
    );
  }
});

test('material must target the exact role, store database and endpoint without URI overrides', () => {
  const valid = material().toString('utf8');
  const malformed = [
    material({ databaseRole: 'postgres' }),
    material({ databaseHost: 'other-host' }),
    material({ databaseHost: 'candidate-index-pg.attacker.test' }),
    material({ databasePort: 5433 }),
    material({ databaseName: 'openpc_control' }),
    material({ password: '' }),
    material({ password: '%00' }),
    material({ password: '%0A' }),
    material({ password: '%ZZ' }),
    material({ password: '%ff' }),
    material({ password: 'a'.repeat(1025) }),
    Buffer.from(`${valid}?host=other-host`),
    Buffer.from(`${valid}?user=postgres`),
    Buffer.from(`${valid}?sslmode=disable`),
    Buffer.from(`${valid}#fragment`),
    Buffer.from(`${valid}?`),
    Buffer.from(`${valid}\n`),
    Buffer.from(` ${valid}`),
    Buffer.from(`\ufeff${valid}`),
    Buffer.from(valid.replace('postgresql:', 'https:')),
    Buffer.from(valid.replace('candidate-index-pg', 'CANDIDATE-INDEX-PG')),
    Buffer.from(valid.replace(':5432', '')),
    Buffer.from(valid.replace(':5432', ':05432')),
    Buffer.from(valid.replace('openpc_fact_bridge_reader', 'openpc%5Ffact_bridge_reader')),
    Buffer.from(valid.replace('/openpc_candidate_index', '/ignored/../openpc_candidate_index')),
    Buffer.from(valid.replace('/openpc_candidate_index', '/openpc%5Fcandidate_index')),
    Buffer.from([0xff, 0xfe]),
    Buffer.alloc(0),
    Buffer.alloc(4097, 97),
    valid,
    null,
    { bytes: valid },
  ];
  for (const bytes of malformed) {
    assert.throws(() => createTestSecretProvider(binding(), bytes), rejection('MATERIAL_INVALID'));
    if (bytes instanceof Uint8Array) bytes.fill(0);
  }
});

test('malformed byte accessors cannot leak issuer material through errors', () => {
  const input = new Uint8Array(16);
  Object.defineProperty(input, 'byteLength', {
    get() {
      throw new Error(password);
    },
  });
  assert.throws(() => createTestSecretProvider(binding(), input), rejection('MATERIAL_INVALID'));
});

test('both direct PostgreSQL URI spellings and escaped synthetic passwords stay exact', async () => {
  for (const protocol of ['postgres:', 'postgresql:']) {
    const bytes = material({ password: 'synthetic%40password%3Awith%2Fdelimiters' });
    const input = Buffer.from(bytes.toString('utf8').replace('postgresql:', protocol));
    const provider = createTestSecretProvider(binding(), input);
    await provider.withMaterial(binding(), (value) => assert.deepEqual(value, input));
    provider.reset();
    input.fill(0);
    bytes.fill(0);
  }
});

test('missing material never invokes its consumer', async () => {
  const provider = createTestSecretProvider(binding());
  assert.equal(provider.describe().providerState, 'MISSING');
  await assert.rejects(
    provider.withMaterial(binding(), () => assert.fail('must not deliver missing bytes')),
    rejection('MATERIAL_MISSING'),
  );
  provider.reset();
});

test('resolution revalidates every field and never falls back across reference or version', async () => {
  const provider = fixture();
  for (const key of Object.keys(testFactCandidateDatabaseConsumer)) {
    const changed = { ...binding(), [key]: null };
    await assert.rejects(
      provider.withMaterial(changed, () => assert.fail('must reject changed binding')),
      rejection('BINDING_INVALID'),
    );
  }
  for (const request of [
    bindTestFactCandidateDatabaseReference(reference.replace('#v1', '#v2'), 'v2'),
    bindTestFactCandidateDatabaseReference(reference.replace('/fact/', '/other/'), 'v1'),
  ]) {
    await assert.rejects(
      provider.withMaterial(request, () => assert.fail('must not fall back')),
      rejection('REFERENCE_MISMATCH'),
    );
  }
  provider.reset();
});

test('caller and callback mutations cannot replace the retained exact-version material', async () => {
  const input = material();
  const descriptor = { ...binding() };
  const provider = createTestSecretProvider(descriptor, input);
  input.fill(0);
  descriptor.databaseRole = 'postgres';
  let previous;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await provider.withMaterial(binding(), (bytes) => {
      assert.equal(bytes.toString('utf8'), material().toString('utf8'));
      assert.notEqual(bytes, previous);
      previous = bytes;
      bytes.fill(97);
    });
    assert.ok(previous.every((value) => value === 0));
  }
  provider.reset();
});

test('revoke and reset are terminal, idempotent and never reopen material', async () => {
  for (const operation of ['revoke', 'reset']) {
    const provider = fixture();
    provider[operation]();
    provider[operation]();
    provider[operation === 'revoke' ? 'reset' : 'revoke']();
    const state = operation === 'revoke' ? 'REVOKED' : 'RESET';
    assert.equal(provider.describe().providerState, state);
    await assert.rejects(
      provider.withMaterial(binding(), () => assert.fail('must not resurrect material')),
      rejection(`MATERIAL_${state}`),
    );
    assert.equal(provider.describe().startupAllowed, false);
  }
});

test('pending handoff is exclusive and revoke/reset erase it before completion', async () => {
  for (const operation of ['revoke', 'reset']) {
    const provider = fixture();
    let finish;
    let borrowed;
    const pending = provider.withMaterial(binding(), (bytes) => {
      borrowed = bytes;
      return new Promise((resolve) => {
        finish = resolve;
      });
    });
    await assert.rejects(
      provider.withMaterial(binding(), () => assert.fail('must serialize handoffs')),
      rejection('HANDOFF_BUSY'),
    );
    provider[operation]();
    assert.ok(borrowed.every((value) => value === 0));
    finish();
    await assert.rejects(
      pending,
      rejection(operation === 'revoke' ? 'MATERIAL_REVOKED' : 'MATERIAL_RESET'),
    );
  }
});

test('sync, async and thenable callback failures are redacted, erased and retryable', async () => {
  const provider = fixture();
  for (const consume of [
    () => {
      throw new Error(`${password} ${reference}`);
    },
    async () => {
      throw new Error(material().toString('utf8'));
    },
    () => ({
      get then() {
        throw new Error(password);
      },
    }),
  ]) {
    let borrowed;
    await assert.rejects(
      provider.withMaterial(binding(), (bytes) => {
        borrowed = bytes;
        return consume();
      }),
      rejection('HANDOFF_FAILED'),
    );
    assert.ok(borrowed.every((value) => value === 0));
    await provider.withMaterial(binding(), (bytes) => assert.ok(bytes.byteLength > 0));
  }
  await assert.rejects(provider.withMaterial(binding(), null), rejection('HANDOFF_INVALID'));
  provider.reset();
});

test('public provider inspection and metadata never expose material or exact reference', () => {
  const provider = fixture();
  for (const output of [
    JSON.stringify(provider),
    inspect(provider, { showHidden: true, depth: null }),
    JSON.stringify(provider.describe()),
    inspect(provider.describe()),
  ]) {
    assert.ok(!output.includes(password));
    assert.ok(!output.includes(reference));
    assert.ok(!output.includes('postgresql://'));
  }
  provider.reset();
});
