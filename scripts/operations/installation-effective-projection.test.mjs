import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { parseNamedProfile } from './installation-config-inputs.mjs';
import {
  effectiveProjectionCanonicalJson as canonical,
  prepareEffectiveProjection,
} from './installation-effective-projection.mjs';

const schema = JSON.parse(
  await readFile(
    new URL('../../config/schema/effective-configuration.schema.json', import.meta.url),
  ),
);
const namedProfile = parseNamedProfile(
  await readFile(new URL('../../config/profiles/test.yaml', import.meta.url)),
);
const h = (n) => `sha256:${n.repeat(64)}`;
function defaults(node) {
  if (Object.hasOwn(node, 'default')) return structuredClone(node.default);
  if (Object.hasOwn(node, 'const')) return structuredClone(node.const);
  if (!node.properties) return undefined;
  return Object.fromEntries(
    Object.entries(node.properties).flatMap(([key, child]) => {
      const value = defaults(child);
      return value === undefined ? [] : [[key, value]];
    }),
  );
}
function fixture() {
  const configuration = {
    ...defaults(schema),
    environmentId: 'secret-test',
    profile: 'test',
    publicBaseUrl: 'https://fixture.test',
    generation: {
      generationId: 'urn:openpc:generation:01900000-0000-7000-8000-000000000002',
      baseGenerationId: 'urn:openpc:generation:01900000-0000-7000-8000-000000000001',
      contentDigest: h('a'),
    },
    postgres: {
      controlDsnSecretRef: 'secret://test-memory-resolver/control#v1',
      factsDsnSecretRef: 'secret://test-memory-resolver/facts#v1',
      candidateIndexDsnSecretRef: 'secret://test-memory-resolver/candidate#v1',
    },
    pki: {
      trustBundleSecretRef: 'secret://test-memory-resolver/trust#v1',
      signingKeySecretRef: 'secret://test-memory-resolver/signing#v1',
    },
    identity: {
      oidcIssuer: 'https://fixture.test/oidc',
      clientId: 'synthetic',
      clientSecretRef: 'secret://test-memory-resolver/oidc#v1',
      scimEnabled: false,
    },
    telemetry: { ...defaults(schema).telemetry, otlpEndpoint: 'grpc://fixture.test:4317' },
    qualificationInputBindings: Object.fromEntries(
      Object.keys(namedProfile.requiredSettingInputs).map((key) => [
        key,
        `qualification://test/${key}@${h('b')}`,
      ]),
    ),
  };
  Object.assign(configuration.settings, {
    'ui.export_row_limit': 1,
    'runtime.local_artifact_capacity': 1,
    'runtime.decision_deadline': '1ms',
    'evidence.local_spool_capacity': 1,
    'evidence.retention_profile': `profile://test/retention@${h('c')}`,
    'provider.read_retry_limit': 0,
    'facts.maximum_staleness': '1ms',
    'facts.reorg_retained_tail': 1,
    'module.allowed_publishers': `publisher-set://test/publishers@${h('d')}`,
    'module.ui_slot_budget': 0,
  });
  // Structural fixture inputs explicitly do not establish qualification/readiness.
  const secretResolutions = Object.entries(schema.properties).flatMap(([section, node]) =>
    Object.entries(node.properties ?? {})
      .filter(([, field]) => field.$ref === '#/$defs/SecretRef')
      .map(([field]) => ({
        field: `${section}.${field}`,
        referenceFingerprint: sha256(Buffer.from(configuration[section][field])),
        version: 'v1',
        fingerprint: h('e'),
      })),
  );
  const qualifications = Object.entries(namedProfile.requiredSettingInputs).map(
    ([setting, slot]) => ({
      setting,
      slot,
      reference: configuration.qualificationInputBindings[setting],
      value: configuration.settings[setting],
    }),
  );
  return {
    schema: structuredClone(schema),
    namedProfile: structuredClone(namedProfile),
    configuration,
    secretResolutions,
    qualifications,
  };
}

test('RFC8785 numeric serialization, escaping and UTF16 ordering use the accepted primitive', () => {
  assert.equal(
    canonical({ numbers: [Number('333333333.33333329'), 1e30, 4.5, 2e-3, 1e-27, -0] }),
    '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27,0]}',
  );
  assert.equal(
    canonical({ '\ufffd': 4, '😀': 3, '\r': 1, '€': 2 }),
    '{"\\r":1,"€":2,"😀":3,"�":4}',
  );
});

test('complete structural inputs yield no effective authority; preimage retains all semantic fields', () => {
  const input = fixture();
  const result = prepareEffectiveProjection(input);
  assert.equal(result.state, 'UNVERIFIED');
  assert.deepEqual(result.missing, []);
  assert.equal(Object.hasOwn(result, 'effectiveDigest'), false);
  const projection = JSON.parse(result.preimageBytes);
  assert.deepEqual(projection.generation, {
    generationId: input.configuration.generation.generationId,
    baseGenerationId: input.configuration.generation.baseGenerationId,
  });
  assert.deepEqual(projection.settings, input.configuration.settings);
  assert.deepEqual(projection.features, input.configuration.features);
  assert.equal(result.preimageBytes.includes(Buffer.from('secret://')), false);
  assert.equal(projection.postgres.controlDsnSecretRef.fingerprint, h('e'));
});

test('only embedded self digest is excluded; changed generation, setting and resolution change projection', () => {
  const original = fixture();
  const first = prepareEffectiveProjection(original).diagnosticProjectionDigest;
  original.configuration.generation.contentDigest = h('f');
  assert.equal(prepareEffectiveProjection(original).diagnosticProjectionDigest, first);
  for (const change of [
    (v) => {
      v.configuration.generation.generationId =
        'urn:openpc:generation:01900000-0000-7000-8000-000000000003';
    },
    (v) => {
      v.configuration.settings['operations.notification_delivery_limit'] = 3;
    },
    (v) => {
      v.secretResolutions[0].fingerprint = h('f');
    },
  ]) {
    const input = fixture();
    change(input);
    assert.notEqual(prepareEffectiveProjection(input).diagnosticProjectionDigest, first);
  }
});

test('unresolved inputs are explicitly missing and cannot disclose reference names or effective digest', () => {
  const input = fixture();
  input.secretResolutions = [];
  input.qualifications = [];
  const result = prepareEffectiveProjection(input);
  assert.equal(result.missing.length, 16);
  assert.equal(result.preimageBytes.includes(Buffer.from('secret://')), false);
  assert.equal(Object.hasOwn(result, 'effectiveDigest'), false);
});

test('mutable version aliases cannot become exact resolution fingerprints', () => {
  for (const alias of ['latest', 'CURRENT']) {
    const input = fixture();
    const resolution = input.secretResolutions[0];
    const [section, field] = resolution.field.split('.');
    const reference = input.configuration[section][field].replace(/#[^#]*$/u, `#${alias}`);
    input.configuration[section][field] = reference;
    resolution.version = alias;
    resolution.referenceFingerprint = sha256(Buffer.from(reference));
    assert.throws(() => prepareEffectiveProjection(input));
  }
});

test('wrong slot/value/ref, duplicate or additional resolutions and signing envelopes fail closed', () => {
  for (const change of [
    (v) => {
      v.qualifications[0].slot = 'QINPUT-PRODUCTION-FORGED-V1';
    },
    (v) => {
      v.qualifications[0].value = 999;
    },
    (v) => {
      v.qualifications[0].reference = `qualification://test/wrong@${h('a')}`;
    },
    (v) => {
      v.qualifications.push(v.qualifications[0]);
    },
    (v) => {
      v.secretResolutions.push(v.secretResolutions[0]);
    },
    (v) => {
      v.secretResolutions[0].version = 'v2';
    },
    (v) => {
      v.secretResolutions[0].referenceFingerprint = h('0');
    },
    (v) => {
      v.secretResolutions[0].field = 'postgres.password';
    },
    (v) => {
      v.secretResolutions[0].material = 'forbidden';
    },
    (v) => {
      v.configuration.signatureEnvelope = {};
    },
    (v) => {
      v.configuration.settings.forbidden = true;
    },
    (v) => {
      v.namedProfile.requiredSettingInputs.extra = 'QINPUT-TEST-EXTRA-V1';
    },
  ]) {
    const input = fixture();
    change(input);
    assert.throws(() => prepareEffectiveProjection(input));
  }
});

test('reject coercion, prototype, getter, cycle, sparse, non-JSON and malformed Unicode inputs', () => {
  let called = false;
  const getter = Object.defineProperty({}, 'x', {
    enumerable: true,
    get() {
      called = true;
      return 1;
    },
  });
  const cycle = {};
  cycle.self = cycle;
  const hidden = Object.defineProperty({}, 'x', { value: 1 });
  const extraArray = [1];
  extraArray.extra = 2;
  for (const value of [
    undefined,
    NaN,
    Infinity,
    1n,
    '\ud800',
    'e\u0301',
    new Date(),
    Object.create({ x: 1 }),
    getter,
    cycle,
    hidden,
    Array(1),
    extraArray,
    {
      toJSON() {
        called = true;
        return {};
      },
    },
    { [Symbol('x')]: 1 },
  ])
    assert.throws(() => canonical(value), /OPS_EFFECTIVE_PROJECTION_INVALID/u);
  assert.equal(called, false);
});
