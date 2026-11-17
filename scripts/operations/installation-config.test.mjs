import {
  bindTestFactCandidateDatabaseReference,
  testFactCandidateDatabaseConsumer,
} from './installation-consumer-bindings.mjs';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { before } from 'node:test';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { evidenceKeyId } from '../../packages/security-kernel/src/business-transition/cose.ts';
import {
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
} from '../../packages/security-kernel/src/operations-configuration/site-document.ts';
import { prepareSignedInstallationCandidate } from './installation-config-signature.mjs';
import {
  InstallationConfigError,
  environmentTargets,
  loadInstallationSources,
  parseConfigurationJson,
  parseNamedProfile,
  readConfigurationBytes,
  readEnvironment,
} from './installation-config-inputs.mjs';
import {
  prepareInstallationCandidate,
  unresolvedInstallationOwners,
} from './installation-config-validation.mjs';
import {
  materializeInstallationCandidate,
  renderInstallationCandidate,
} from './installation-config-materialize.mjs';
import { checkInstallationConfig, parseInstallationArguments } from './installation-config.mjs';

// Ordinary CI exercises the shipped installation schema and profiles. An explicitly bound
// external archive additionally checks their original bytes; neither grants readiness.
const c17Root = process.env.OPENPC_C17_PACKAGE_ROOT;
const scratchRoot = process.env.OPENPC_PNC_TMP_ROOT;
const profiles = new Map();
let schemaBytes;
let schema;
before(async () => {
  assert.ok(scratchRoot, 'The existing external scratch root must be bound by the test dispatcher');
  const operations = fileURLToPath(new URL('../../config/', import.meta.url));
  schemaBytes = await readFile(join(operations, 'schema', 'effective-configuration.schema.json'));
  schema = parseConfigurationJson(schemaBytes);
  for (const name of schema.properties.profile.enum) {
    const bytes = await readFile(join(operations, 'profiles', `${name}.yaml`));
    profiles.set(name, { bytes, value: parseNamedProfile(bytes) });
  }
});

const bytes = (value) => Buffer.from(JSON.stringify(value));
const generation = {
  generationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000002',
  baseGenerationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000001',
  contentDigest: `sha256:${'a'.repeat(64)}`,
};
function fixture(profile = 'local') {
  const named = profiles.get(profile);
  const reference = (name) => `secret://${named.value.secretProvider.providerId}/${name}#v1`;
  const site = {
    environmentId: 'local-fixture',
    publicBaseUrl: 'https://localhost:8443',
    generation: { ...generation },
    postgres: {
      controlDsnSecretRef: reference('control'),
      factsDsnSecretRef: reference('facts'),
      candidateIndexDsnSecretRef: reference('candidate'),
    },
    identity: {
      oidcIssuer: 'https://localhost:8443/oidc',
      clientId: 'synthetic-client',
      clientSecretRef: reference('oidc'),
      scimEnabled: false,
    },
    pki: { trustBundleSecretRef: reference('trust'), signingKeySecretRef: reference('signing') },
    telemetry: { otlpEndpoint: 'grpc://localhost:4317' },
    qualificationInputBindings: Object.fromEntries(
      Object.keys(named.value.requiredSettingInputs).map((key) => [
        key,
        `qualification://local/${key}@sha256:${'b'.repeat(64)}`,
      ]),
    ),
    settings: {
      'ui.export_row_limit': 1,
      'runtime.local_artifact_capacity': 1,
      'runtime.decision_deadline': '1ms',
      'evidence.local_spool_capacity': 1,
      'evidence.retention_profile': `profile://local/retention@sha256:${'c'.repeat(64)}`,
      'provider.read_retry_limit': 0,
      'facts.maximum_staleness': '1ms',
      'facts.reorg_retained_tail': 1,
      'module.allowed_publishers': `publisher-set://local/modules@sha256:${'d'.repeat(64)}`,
      'module.ui_slot_budget': 0,
    },
  };
  return {
    schema,
    schemaBytes,
    profileBytes: named.bytes,
    namedProfile: structuredClone(named.value),
    profile,
    site,
    environment: {},
  };
}
const fails = (fn, reason) =>
  assert.throws(
    fn,
    (error) =>
      error instanceof InstallationConfigError &&
      error.code === 'OPS_CONFIG_INVALID' &&
      (reason === undefined || error.reason === reason),
  );
function signedSiteFixture(profile = 'local') {
  const source = fixture(profile);
  source.site.settings['operations.notification_delivery_limit'] = 0;
  source.siteBytes = bytes(source.site);
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  const payload = encodeOperationsSiteDocument({
    environmentId: source.site.environmentId,
    profile,
    generationId: generation.generationId,
    baseGenerationId: generation.baseGenerationId,
    siteDigest: sha256(source.site),
    configurationSchemaDigest: sha256(source.schemaBytes),
    namedProfileDigest: sha256(source.profileBytes),
    declaredContentDigest: generation.contentDigest,
    issuerKeyId: evidenceKeyId(spki),
    issuerEpoch: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
  });
  return {
    source,
    pins: {
      issuerSpki: spki,
      issuerEpoch: '1',
      issuerValidFromMs: 1000,
      issuerValidUntilMs: 2000,
      environmentId: source.site.environmentId,
      profile,
      configurationSchemaDigest: sha256(source.schemaBytes),
      namedProfileDigest: sha256(source.profileBytes),
    },
    signed: {
      payload,
      cose: signOperationsSiteDocument(
        pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
        spki,
        payload,
      ),
    },
  };
}
test('AF-25 actual site bytes authenticate across all profiles without granting configuration or notification authority', () => {
  for (const profile of profiles.keys()) {
    const { source, pins, signed } = signedSiteFixture(profile);
    const result = prepareSignedInstallationCandidate(source, pins, signed, 1500);
    assert.equal(result.state, 'BLOCKED');
    assert.equal(result.startupAllowed, false);
    assert.equal(result.configuration.settings['operations.notification_delivery_limit'], 0);
    assert.deepEqual(
      result.blockers,
      unresolvedInstallationOwners.filter((v) => v !== 'SIGNED_SITE_VERIFICATION_UNBOUND'),
    );
    assert.equal(result.siteSignature.siteDigest, sha256(source.site));
    assert.equal(Object.hasOwn(result, 'effectiveDigest'), false);
    assert.equal(Object.hasOwn(result.siteSignature, 'payload'), false);
    assert.equal(Object.hasOwn(result.siteSignature, 'cose'), false);
    // JSON layout is not authority: the signature binds the RFC8785 document.
    const formatted = { ...source, siteBytes: Buffer.from(JSON.stringify(source.site, null, 2)) };
    assert.deepEqual(prepareSignedInstallationCandidate(formatted, pins, signed, 1500), result);
  }
});
test('AF-25 actual site verifier rejects source substitution, changed retry limit, stale base and malformed JSON', () => {
  const { source, pins, signed } = signedSiteFixture();
  const verify = (s = source, p = pins, signature = signed, now = 1500, options = {}) =>
    prepareSignedInstallationCandidate(s, p, signature, now, options);
  const changed = structuredClone(source.site);
  changed.settings['operations.notification_delivery_limit'] = 100;
  for (const patch of [
    { site: changed },
    { site: changed, siteBytes: bytes(changed) },
    { siteBytes: Buffer.from('{"profile":"local","profile":"production"}') },
    { siteBytes: Buffer.from('{"__proto__":{}}') },
    { siteBytes: Buffer.alloc(131073) },
    { siteBytes: JSON.stringify(source.site) },
    { schemaBytes: Buffer.from('{}') },
    { profileBytes: profiles.get('production').bytes },
    { environment: { environmentId: 'foreign-site' } },
    { profile: 'production' },
  ])
    fails(() => verify({ ...source, ...patch }), 'SIGNED_SITE_VERIFICATION_FAILED');
  fails(() => verify(source, { ...pins, issuerEpoch: '2' }), 'SIGNED_SITE_VERIFICATION_FAILED');
  fails(() => verify(source, pins, signed, 2000), 'SIGNED_SITE_VERIFICATION_FAILED');
  fails(() => verify(source, pins, signed, 999), 'SIGNED_SITE_VERIFICATION_FAILED');
  fails(
    () => verify(source, pins, signed, 1500, { expectedBaseGenerationId: generation.generationId }),
    'SIGNED_SITE_VERIFICATION_FAILED',
  );
  const altered = Buffer.from(signed.cose);
  altered[altered.length - 1] ^= 1;
  fails(
    () => verify(source, pins, { ...signed, cose: altered }),
    'SIGNED_SITE_VERIFICATION_FAILED',
  );
});
async function scratch(t) {
  const root = await mkdtemp(join(scratchRoot, 'installation-config-'));
  t.after(async () => {
    // Only this test's disposable fixture. Candidate directories are intentionally read-only.
    for (const name of await readdir(root)) {
      const path = join(root, name);
      const stat = await lstat(path);
      if (stat.isDirectory()) await chmod(path, 0o700);
    }
    await rm(root, { recursive: true });
  });
  return root;
}

test('TEST-OPS-CONFIG-001/011: all five original profiles produce deterministic blocked candidates', () => {
  for (const profile of profiles.keys()) {
    const source = fixture(profile);
    const first = prepareInstallationCandidate(source);
    assert.equal(canonicalJson(first), canonicalJson(prepareInstallationCandidate(source)));
    assert.equal(first.state, 'BLOCKED');
    assert.equal(first.startupAllowed, false);
    assert.deepEqual(first.blockers, [...unresolvedInstallationOwners]);
    assert.equal(first.configuration.settings['session.idle_timeout'], '30m');
    assert.equal(first.configuration.settings['runtime.fail_closed_on_unknown_version'], true);
    assert.ok(Object.values(first.configuration.features).every((value) => value === false));
    assert.equal(first.deploymentUnits.enabled.length, 8);
    assert.deepEqual(first.deploymentUnits.disabled, ['DU-SUBQUERY']);
    assert.equal(Object.keys(first.qualificationSlots).length, 10);
    assert.ok(
      Object.values(first.qualificationSlots).every((binding) => binding.verified === false),
    );
    assert.equal(first.sourceClasses['/settings/session.idle_timeout'], 'COMPILED_SAFE_DEFAULT');
    assert.equal(first.sourceClasses['/profile'], 'NAMED_PROFILE');
    assert.equal(first.sourceClasses['/environmentId'], 'SITE_FILE');
  }
});

test('TEST-OPS-CONFIG-003: shared strict JSON rejects duplicates, aliases, unsafe numbers and encodings', () => {
  for (const source of [
    '{"a":1,"a":2}',
    '{"a":{"x":1,"\\u0078":2}}',
    '{"__proto__":{}}',
    '{"a":1} true',
    '{"a":9007199254740993}',
    '{"a":1e999}',
    '{"a":-0}',
    '{"a":"\\ud800"}',
    '{"a":"e\\u0301"}',
    '{"a":"\\u0000"}',
    '\ufeff{"a":1}',
    '[]',
    'null',
  ])
    fails(() => parseConfigurationJson(Buffer.from(source)));
  fails(() => parseConfigurationJson(Buffer.from([123, 34, 97, 34, 58, 34, 0xff, 34, 125])));
  fails(() => parseConfigurationJson(Buffer.alloc(131073)));
  assert.deepEqual(parseConfigurationJson(Buffer.from('{"a":"é"}')), { a: 'é' });
});

test('named profile input rejects duplicates, unknown keys, aliases, wrong identity and malformed syntax', () => {
  const original = profiles.get('local').bytes.toString();
  for (const suffix of [
    'profile: local\n',
    'extra: &anchor value\n',
    'extra: *anchor\n',
    'extra: !!str value\n',
    '---\n',
    'features: {a: false, a: true}\n',
  ])
    fails(() => parseNamedProfile(Buffer.from(original + suffix)));
  for (const mutate of [
    (p) => {
      p.extra = 'unknown';
    },
    (p) => {
      p.profile = 'production';
    },
    (p) => {
      p.immutableAfterStart = false;
    },
    (p) => {
      p.tls.loopbackExemption = true;
    },
    (p) => {
      p.features.extra = false;
    },
    (p) => {
      p.deploymentUnits.enabled.pop();
    },
    (p) => {
      p.requiredSettingInputs['ui.export_row_limit'] = 'QINPUT-PRODUCTION-UI-EXPORT-V1';
    },
    (p) => {
      p.secretProvider.inlineValues = true;
    },
  ]) {
    const input = fixture();
    mutate(input.namedProfile);
    fails(() => prepareInstallationCandidate(input));
  }
});

test('TEST-OPS-CONFIG-002/004: all nine exact environment overrides have bound provenance', () => {
  const input = fixture();
  const provider = input.namedProfile.secretProvider.providerId;
  const supplied = {
    OPENPC_ENVIRONMENT_ID: 'overridden-fixture',
    OPENPC_PUBLIC_BASE_URL: 'https://localhost:9443',
    OPENPC_OTLP_ENDPOINT: 'https://localhost:4318',
    OPENPC_CONTROL_DSN_REF: `secret://${provider}/control#v2`,
    OPENPC_FACTS_DSN_REF: `secret://${provider}/facts#v2`,
    OPENPC_CANDIDATE_INDEX_DSN_REF: `secret://${provider}/candidate#v2`,
    OPENPC_OIDC_CLIENT_SECRET_REF: `secret://${provider}/oidc#v2`,
    OPENPC_TRUST_BUNDLE_REF: `secret://${provider}/trust#v2`,
    OPENPC_SIGNING_KEY_REF: `secret://${provider}/signing#v2`,
  };
  assert.equal(Object.keys(environmentTargets).length, 9);
  input.environment = readEnvironment({ PATH: '/irrelevant', ...supplied });
  const result = prepareInstallationCandidate(input);
  for (const [name, path] of Object.entries(environmentTargets)) {
    assert.equal(
      path.reduce((parent, key) => parent[key], result.configuration),
      supplied[name],
    );
    assert.equal(result.sourceClasses[`/${path.join('/')}`], 'ALLOWLISTED_ENVIRONMENT');
  }
  const references = { pki: { signingKeySecretRef: `secret://${provider}/signing#v3` } };
  const resolved = prepareInstallationCandidate(input, {
    secretReferencesBytes: bytes(references),
  });
  assert.equal(resolved.configuration.pki.signingKeySecretRef, references.pki.signingKeySecretRef);
  assert.equal(resolved.sourceClasses['/pki/signingKeySecretRef'], 'SECRET_PROVIDER_REFERENCE');
});

test('source ownership rejects undeclared env, case variants, settings/features and non-secret provider fields', () => {
  for (const name of [
    'OPENPC_SETTINGS_SESSION_IDLE_TIMEOUT',
    'OPENPC_FEATURES',
    'OPENPC_DSN',
    'openpc_environment_id',
    'OPENPC_ENVIRONMENT_id',
    'OPENPC_C17_PACKAGE_ROOT',
    'OPENPC_PROFILE',
  ])
    fails(() => readEnvironment({ [name]: 'synthetic' }), 'UNDECLARED_ENVIRONMENT');
  for (const value of ['', 1, false, null])
    fails(() => readEnvironment({ OPENPC_ENVIRONMENT_ID: value }));
  const input = fixture();
  input.environment = { settings: { 'session.idle_timeout': '2m' } };
  fails(() => prepareInstallationCandidate(input), 'ENVIRONMENT_SOURCE_FIELD');
  fails(
    () =>
      prepareInstallationCandidate(fixture(), {
        secretReferencesBytes: bytes({ environmentId: 'fake' }),
      }),
    'SECRET_SOURCE_FIELD',
  );
  const invalidSite = fixture();
  invalidSite.site.extra = 'unrecognized';
  fails(() => prepareInstallationCandidate(invalidSite), 'SOURCE_SCHEMA_INVALID');
});

test('TEST-OPS-SECRET-011/013: invalid shadowed sources fail and errors contain no supplied values', () => {
  const marker = 'PRIVATE-SENTINEL-DO-NOT-PRINT';
  for (const reference of [
    marker,
    '-----BEGIN PRIVATE KEY-----',
    'secret://local/key#v1',
    'secret://local-os-keystore/key#latest',
    'secret://local-os-keystore/key#CURRENT',
    'secret://local-os-keystore/key',
    'secret://local-os-keystore/key#%31',
    'secret://local-os-keystore/a/../key#v1',
    'secret://local-os-keystore/a//key#v1',
  ]) {
    const input = fixture();
    input.site.pki.signingKeySecretRef = reference;
    input.environment = { pki: { signingKeySecretRef: 'secret://local-os-keystore/key#v2' } };
    assert.throws(
      () => prepareInstallationCandidate(input),
      (error) => {
        assert.ok(error instanceof InstallationConfigError);
        assert.ok(!error.message.includes(marker));
        assert.ok(!JSON.stringify(error).includes(reference));
        return true;
      },
    );
  }
});

test('TEST-OPS-CONFIG-006: sealed settings and every cross-field invariant reject invalid boundaries', () => {
  const cases = [
    { 'ui.page_size_default': 200, 'ui.page_size_max': 100 },
    { 'session.idle_timeout': '12h' },
    { 'session.idle_timeout': '4m', 'session.step_up_validity': '5m' },
    { 'identity.context_assertion_ttl': '30s', 'identity.clock_skew_tolerance': '30s' },
    { 'evidence.high_watermark': 80, 'evidence.critical_watermark': 80 },
    { 'runtime.fail_closed_on_unknown_version': false },
    { 'module.require_sbom': false },
    { 'module.require_provenance': false },
    { 'security.audit_reason_required': false },
    { 'telemetry.payload_capture_enabled': true },
    { 'provider.write_retry_after_attempt_start': 1 },
    { 'release.mandatory_target_policy': 'QUORUM' },
    { 'session.absolute_timeout': '8d' },
    { 'session.idle_timeout': '59999ms' },
    { 'session.step_up_validity': '1800001ms' },
    { 'identity.clock_skew_tolerance': '121s' },
    { 'runtime.decision_deadline': '0ms' },
    { 'runtime.decision_deadline': '999999999999999999999d' },
    { 'session.idle_timeout': '01m' },
    { 'ui.default_timezone': 'Unknown/Unknown' },
  ];
  for (const change of cases) {
    const input = fixture();
    Object.assign(input.site.settings, change);
    fails(() => prepareInstallationCandidate(input));
  }
  for (const key of [
    'provider.quarantine_on_fingerprint_drift',
    'security.sensitive_copy_disabled',
  ]) {
    const input = fixture('production');
    input.site.settings[key] = false;
    fails(() => prepareInstallationCandidate(input), 'CROSS_FIELD_BOUND');
  }
  const valid = fixture();
  valid.site.settings['session.step_up_validity'] = '0ms';
  valid.site.settings['identity.clock_skew_tolerance'] = '0s';
  assert.equal(prepareInstallationCandidate(valid).startupAllowed, false);
});

test('URI, path, profile and generation bindings reject bypasses and stale bases', () => {
  for (const uri of [
    'http://localhost:8443',
    'https://user:pass@localhost/',
    'https://localhost/?token=synthetic',
    'https://localhost/#fragment',
    'https://localhost/%0a',
    'https://localhost/\\path',
  ]) {
    const input = fixture();
    input.site.publicBaseUrl = uri;
    fails(() => prepareInstallationCandidate(input));
  }
  const path = fixture();
  path.site.runtimePaths = { artifactRoot: '/tmp/artifacts' };
  fails(() => prepareInstallationCandidate(path));
  const profile = fixture();
  profile.site.profile = 'production';
  fails(() => prepareInstallationCandidate(profile), 'PROFILE_BINDING');
  const self = fixture();
  self.site.generation.generationId = generation.baseGenerationId;
  fails(() => prepareInstallationCandidate(self), 'GENERATION_SELF_REFERENCE');
  fails(
    () =>
      prepareInstallationCandidate(fixture(), {
        expectedBaseGenerationId: generation.generationId,
      }),
    'BASE_GENERATION_MISMATCH',
  );
});

test('TEST-OPS-CONFIG-009: missing qualification and forged flags never produce readiness', () => {
  const missing = fixture();
  delete missing.site.qualificationInputBindings['module.ui_slot_budget'];
  fails(() => prepareInstallationCandidate(missing), 'EFFECTIVE_SCHEMA_INVALID');
  const missingValue = fixture();
  delete missingValue.site.settings['runtime.local_artifact_capacity'];
  fails(() => prepareInstallationCandidate(missingValue), 'EFFECTIVE_SCHEMA_INVALID');
  const enabled = fixture();
  enabled.site.features = { privacyExplorerIntegration: true };
  const result = prepareInstallationCandidate(enabled, {
    verified: true,
    ready: true,
    signatureVerified: true,
  });
  assert.equal(result.startupAllowed, false);
  assert.ok(result.blockers.includes('FEATURE_COHORT_VERIFICATION_UNBOUND'));
  assert.ok(result.blockers.includes('GENERATION_ADMISSION_AND_DIGEST_UNBOUND'));
  assert.ok(result.secretReferences.every((reference) => reference.resolved === false));
  const future = fixture();
  future.site.features = { subqueryConditional: true };
  fails(() => prepareInstallationCandidate(future));
});

test('TEST-OPS-CONFIG-010: installer arguments cannot override semantic or security settings', () => {
  const base = ['--profile', 'local', '--config', '/synthetic/site.json', '--check-config'];
  assert.equal(parseInstallationArguments(base)['--profile'], 'local');
  for (const extra of [
    ['--profile', 'test'],
    ['--check-config'],
    ['--settings', 'x'],
    ['--env-file', '/tmp/x'],
    ['--skip-validation'],
    ['--secret', 'synthetic'],
    ['--activate'],
  ])
    fails(() => parseInstallationArguments([...base, ...extra]), 'INSTALLER_ARGUMENT');
});

test('actual input loader and checker report blocked state, with no effective digest or input data', async (t) => {
  const root = await scratch(t);
  const path = join(root, 'site.json');
  await writeFile(path, bytes(fixture().site), { mode: 0o600 });
  const loaded = await loadInstallationSources({
    c17Root,
    profile: 'local',
    sitePath: path,
    environment: {},
  });
  assert.equal(prepareInstallationCandidate(loaded).startupAllowed, false);
  const result = await checkInstallationConfig(
    ['--profile', 'local', '--config', path, '--print-effective-digest'],
    { c17Root, environment: {} },
  );
  assert.equal(result.exitCode, 2);
  assert.equal(result.result.effectiveDigest, null);
  assert.ok(!JSON.stringify(result).includes('secret://'));
  await assert.rejects(
    () =>
      checkInstallationConfig(['--profile', 'local', '--config', path, '--check-config'], {
        c17Root: 'relative-not-an-archive',
        environment: {},
      }),
    { reason: 'C17_INPUT_BINDING_MISSING' },
  );
  const link = join(root, 'link.json');
  await symlink(path, link);
  await assert.rejects(() => readConfigurationBytes(link), { reason: 'INPUT_UNAVAILABLE' });
});

test('materialization is deterministic, repeatable and replaces read-only inputs through a new directory', async (t) => {
  const root = await scratch(t);
  const input = fixture();
  const rendered = renderInstallationCandidate(input);
  assert.ok(!canonicalJson(rendered.summary).includes('secret://'));
  assert.deepEqual(JSON.parse(rendered.files['mount-plan.candidate.json']).consumerBindings, []);
  const first = await materializeInstallationCandidate(input, { outputRoot: root });
  const before = await readFile(join(first.directory, 'configuration.candidate.json'));
  const repeated = await materializeInstallationCandidate(input, { outputRoot: root });
  assert.equal(repeated.directory, first.directory);
  assert.equal(repeated.reused, true);
  const changed = fixture();
  changed.environment = readEnvironment({ OPENPC_ENVIRONMENT_ID: 'second-fixture' });
  const replacement = await materializeInstallationCandidate(changed, { outputRoot: root });
  assert.notEqual(replacement.directory, first.directory);
  assert.deepEqual(await readFile(join(first.directory, 'configuration.candidate.json')), before);
  assert.equal(
    (await lstat(join(first.directory, 'configuration.candidate.json'))).mode & 0o777,
    0o400,
  );
  assert.equal(replacement.startupAllowed, false);
  assert.ok((await readdir(root)).every((name) => name.startsWith('candidate-')));
});

test('materialization refuses shared/symlink paths, corrupt repeats and interrupted publisher ownership', async (t) => {
  const root = await scratch(t);
  const shared = join(root, 'shared');
  await mkdir(shared, { mode: 0o755 });
  await chmod(shared, 0o755);
  await assert.rejects(() => materializeInstallationCandidate(fixture(), { outputRoot: shared }), {
    reason: 'OUTPUT_DIRECTORY_UNSAFE',
  });
  const alias = join(root, 'alias');
  await symlink(root, alias);
  await assert.rejects(() => materializeInstallationCandidate(fixture(), { outputRoot: alias }), {
    reason: 'OUTPUT_DIRECTORY_UNSAFE',
  });
  const first = await materializeInstallationCandidate(fixture(), { outputRoot: root });
  const configPath = join(first.directory, 'configuration.candidate.json');
  await chmod(configPath, 0o600);
  await writeFile(configPath, 'corrupt');
  await chmod(configPath, 0o400);
  await assert.rejects(() => materializeInstallationCandidate(fixture(), { outputRoot: root }), {
    reason: 'MATERIALIZATION_CONFLICT',
  });
  assert.equal(await readFile(configPath, 'utf8'), 'corrupt');
  await mkdir(join(root, '.installation-publish'), { mode: 0o700 });
  const other = fixture();
  other.environment = readEnvironment({ OPENPC_ENVIRONMENT_ID: 'other-fixture' });
  await assert.rejects(() => materializeInstallationCandidate(other, { outputRoot: root }), {
    reason: 'MATERIALIZATION_BUSY',
  });
  assert.ok((await readdir(root)).includes('.installation-publish'));
  assert.ok(
    !(await readdir(root)).some(
      (name) => name.startsWith('.installation-') && name !== '.installation-publish',
    ),
  );
});

// External archive qualification is deliberately separate from portable CI.
test(
  'shipped installer inputs match the bound original C17 archive',
  { skip: !c17Root },
  async () => {
    const original = join(c17Root, 'SPECIFICATIONS', 'OPERATIONS');
    assert.deepEqual(schemaBytes, await readFile(join(original, 'configuration.schema.json')));
    for (const [name, profile] of profiles)
      assert.deepEqual(profile.bytes, await readFile(join(original, 'profiles', `${name}.yaml`)));
  },
);

test('test installation binds the exact Fact candidate consumer while unresolved provider custody still blocks startup', async () => {
  const sources = fixture('test');
  const rendered = renderInstallationCandidate(sources);
  const plan = JSON.parse(rendered.files['mount-plan.candidate.json']);
  assert.equal(plan.startupAllowed, false);
  assert.ok(plan.blockers.includes('SECRET_PROVIDER_RESOLUTION_UNBOUND'));
  assert.equal(plan.consumerBindings.length, 1);
  assert.deepEqual(plan.consumerBindings[0], {
    ...testFactCandidateDatabaseConsumer,
    reference: sources.site.postgres.candidateIndexDsnSecretRef,
    version: 'v1',
  });
  const consumer = await readFile(
    new URL('../../services/fact-service/src/deployment.rs', import.meta.url),
    'utf8',
  );
  const preparation = await readFile(
    new URL('../../tests/integration/local-runtime/runtime-configuration.sh', import.meta.url),
    'utf8',
  );
  const container = await readFile(
    new URL('../../services/fact-service/Dockerfile', import.meta.url),
    'utf8',
  );
  assert.ok(consumer.includes('database_url(&input.candidate_database_url_file)'));
  assert.ok(preparation.includes("candidate_database_url_file: '/fact-bridge/candidate-url'"));
  assert.ok(
    preparation.includes('OPENPC_FACT_BRIDGE_CONFIGURATION_FILE=/fact-bridge/deployment.json'),
  );
  assert.ok(container.includes('USER 65532:65532'));
  assert.ok(container.includes(testFactCandidateDatabaseConsumer.entrypoint));
});

test('consumer binding rejects other providers, floating/mismatched versions and ambiguous paths', () => {
  for (const [reference, version] of [
    ['secret://local-os-keystore/candidate#v1', 'v1'],
    ['secret://test-memory-resolver/candidate#latest', 'latest'],
    ['secret://test-memory-resolver/candidate#v1', 'v2'],
    ['secret://test-memory-resolver/candidate/../other#v1', 'v1'],
    ['secret://test-memory-resolver/candidate//other#v1', 'v1'],
  ])
    fails(
      () => bindTestFactCandidateDatabaseReference(reference, version),
      'SECRET_CONSUMER_BINDING',
    );
});

test('shared runtime preparation never writes or falls back to a static candidate credential for an installed recipient', async (t) => {
  const root = await scratch(t),
    data = join(root, 'data'),
    secrets = join(root, 'secrets'),
    profile = join(root, 'recipient.json');
  await mkdir(secrets);
  for (const name of ['indexer_manager', 'source_control'])
    await writeFile(join(secrets, `${name}_db_password.txt`), 'a'.repeat(64));
  // Non-secret assembly input only. The native owner separately validates this
  // complete configuration before contacting the real publication endpoint.
  const projection = { signed_binding_digest: `sha256:${'1'.repeat(64)}`, generation: '1' };
  await writeFile(profile, JSON.stringify(projection));
  const run = (selected = profile) =>
    spawnSync(
      'bash',
      [
        '-c',
        'set -euo pipefail; source tests/integration/local-runtime/runtime-configuration.sh; data_root=$1; secret_root=$2; export OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG=$3; openpc_prepare_fact_database_files',
        'fact-secret-preparation',
        data,
        secrets,
        selected,
      ],
      { encoding: 'utf8', timeout: 10000 },
    );
  assert.equal(run().status, 0);
  const config = join(data, 'fact-bridge', 'config');
  assert.deepEqual(
    JSON.parse(await readFile(join(config, 'secret-recipient.json'), 'utf8')),
    projection,
  );
  await assert.rejects(lstat(join(config, 'candidate-url')), { code: 'ENOENT' });
  assert.equal(run().status, 0);
  assert.notEqual(run('').status, 0);
  await writeFile(profile, '{"generation":"1","generation":"2"}');
  assert.notEqual(run().status, 0);
  await writeFile(profile, JSON.stringify({ ...projection, generation: '2' }));
  assert.notEqual(run().status, 0);
  await writeFile(profile, JSON.stringify(projection));
  await writeFile(join(config, 'candidate-url'), 'retained-owner');
  assert.notEqual(run().status, 0);
  assert.equal(await readFile(join(config, 'candidate-url'), 'utf8'), 'retained-owner');
});

// Source authentication is independent of the signed SITE_FILE. These use the
// shipped original accepted manifest; an explicit external archive may also be
// bound. Neither a synthetic manifest nor a caller digest grants source authority.
test('C17 source verifier rejects self-consistent forged receipt/manifest and caller trust overrides', async () => {
  const { authenticateOperationsSources, operationsSourceAnchor } =
    await import('./installation-source-authentication.mjs');
  const manifestBytes = bytes({ packageId: operationsSourceAnchor.packageId, files: [] });
  const input = {
    receiptBytes: bytes({
      receiptId: operationsSourceAnchor.receiptId,
      archive: { sha256: sha256(manifestBytes).slice(7) },
    }),
    manifestBytes,
    schemaBytes,
    profileBytes: profiles.get('local').bytes,
    profile: 'local',
  };
  fails(() => authenticateOperationsSources(input), 'C17_SOURCE_AUTHENTICATION_FAILED');
  fails(() => authenticateOperationsSources({ ...input, trustedDigest: sha256(manifestBytes) }));
  fails(() => authenticateOperationsSources({ ...input, verified: true }));
  for (const profile of ['LOCAL', '../local', 'constructor', 'unknown', null])
    fails(() => authenticateOperationsSources({ ...input, profile }));
  let called = false;
  const accessor = Object.defineProperty({ ...input }, 'manifestBytes', {
    enumerable: true,
    get() {
      called = true;
      return manifestBytes;
    },
  });
  fails(() => authenticateOperationsSources(accessor));
  assert.equal(called, false);
});
