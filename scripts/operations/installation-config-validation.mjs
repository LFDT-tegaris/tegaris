import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { isExactSigningSecretReference } from '../../packages/security-kernel/src/business-transition/secret-reference.ts';
import {
  assertUnicode,
  environmentTargets,
  invalid,
  parseConfigurationJson,
} from './installation-config-inputs.mjs';

const profileFields = [
  'schemaVersion',
  'profileId',
  'profile',
  'freezeId',
  'immutableAfterStart',
  'claimState',
  'deploymentUnits',
  'conditionalComponents',
  'bindings',
  'tls',
  'identityProfileInput',
  'secretProvider',
  'resourceEnvelopeInput',
  'topologyQualificationInput',
  'storageQualificationInput',
  'settingsDefaults',
  'requiredSettingInputs',
  'features',
  'telemetry',
  'backup',
  'retentionInput',
  'seedData',
  'externalDependencies',
  'prohibitedShortcuts',
  'trace',
];
const units = [
  'DU-PC-WORKBENCH',
  'DU-PC-CONTROL',
  'DU-PC-COMPILER',
  'DU-PC-FLEET-CONTROL',
  'DU-PC-RUNTIME',
  'DU-PC-FACT-BRIDGE',
  'DU-ENVOY',
  'DU-OTEL-COLLECTOR',
];

export const unresolvedInstallationOwners = Object.freeze([
  'C17_INPUT_AUTHENTICATION_UNBOUND',
  'SIGNED_SITE_VERIFICATION_UNBOUND',
  'QUALIFICATION_VERIFICATION_UNBOUND',
  'GENERATION_ADMISSION_AND_DIGEST_UNBOUND',
  'SECRET_PROVIDER_RESOLUTION_UNBOUND',
  'ENTRYPOINT_CONSUMER_BINDING_UNBOUND',
]);

const sameKeys = (object, keys) =>
  object !== null &&
  typeof object === 'object' &&
  !Array.isArray(object) &&
  canonicalJson(Object.keys(object).sort()) === canonicalJson([...keys].sort());

function checkProfile(profile, schema, selected) {
  if (
    !sameKeys(profile, profileFields) ||
    profile.profile !== selected ||
    !schema.properties.profile.enum.includes(selected) ||
    profile.profileId !== `PROFILE-${selected.toUpperCase()}-V1` ||
    profile.schemaVersion !== '1.0' ||
    profile.immutableAfterStart !== true ||
    profile.freezeId !== 'C03-ARCHITECTURE-SHARED-PRIMITIVES-FREEZE-20260824-01' ||
    profile.claimState !== 'PLANNED_TESTABLE' ||
    profile.settingsDefaults !== 'CONFIGURATION_SCHEMA_DEFAULTS_ONLY'
  )
    invalid('PROFILE_BINDING');
  const sections = {
    deploymentUnits: ['enabled', 'disabled', 'coLocation'],
    conditionalComponents: ['LS-INDEXER', 'STORE-VALKEY-OPTIONAL'],
    bindings: [
      'publicHttps',
      'otlpGrpc',
      'otlpHttp',
      'prometheus',
      'envoyAdmin',
      'pdsUds',
      'brokerUds',
    ],
    tls: ['required', 'minimum', 'workloadMtls', 'loopbackExemption'],
    secretProvider: [
      'providerId',
      'inlineValues',
      'versionRequired',
      ...(selected === 'test' ? ['persistence', 'fixtureReferencesOnly'] : []),
      ...(selected === 'production' ? ['workloadIdentityRequired'] : []),
    ],
    features: Object.keys(schema.properties.features.properties),
    telemetry: [
      'collectorRequired',
      'privacyProfile',
      'payloadCapture',
      'debugLogLevelAllowed',
      ...(selected === 'test' ? ['deterministicSampling'] : []),
    ],
    backup: ['requiredForAcceptance', 'restoreFixtureRequired', 'targetInput'],
    seedData: ['allowed', 'customerData', ...(selected === 'test' ? ['deterministicReset'] : [])],
    externalDependencies: [
      'realProviderRequired',
      'fakeSuccessAllowed',
      'exactProfileRequiredWhenEnabled',
      ...(selected === 'test' ? ['fixtureServerMayReturnTypedFailures'] : []),
    ],
    trace: [
      'requirementRefs',
      'decisionRefs',
      'componentRefs',
      'sourceUnitRefs',
      'testRefs',
      'claimCeilingRefs',
    ],
    requiredSettingInputs: schema.properties.qualificationInputBindings.required,
  };
  for (const [key, fields] of Object.entries(sections))
    if (!sameKeys(profile[key], fields)) invalid('PROFILE_FIELDS');
  if (
    !Array.isArray(profile.deploymentUnits.enabled) ||
    canonicalJson([...profile.deploymentUnits.enabled].sort()) !==
      canonicalJson([...units].sort()) ||
    canonicalJson(profile.deploymentUnits.disabled) !== '["DU-SUBQUERY"]' ||
    Object.values(profile.conditionalComponents).some((value) => value !== false) ||
    Object.values(profile.features).some((value) => value !== false) ||
    canonicalJson(profile.tls) !==
      canonicalJson({
        required: true,
        minimum: 'TLS1_3',
        workloadMtls: true,
        loopbackExemption: false,
      }) ||
    profile.secretProvider.inlineValues !== false ||
    profile.secretProvider.versionRequired !== true ||
    !/^[a-z][a-z0-9-]{1,31}$/u.test(profile.secretProvider.providerId) ||
    profile.telemetry.collectorRequired !== true ||
    profile.telemetry.payloadCapture !== false ||
    profile.telemetry.privacyProfile !== 'STRICT_REDACTED' ||
    profile.seedData.customerData !== false ||
    profile.externalDependencies.fakeSuccessAllowed !== false ||
    profile.externalDependencies.exactProfileRequiredWhenEnabled !== true
  )
    invalid('PROFILE_INVARIANT');
  for (const slot of [
    ...Object.values(profile.requiredSettingInputs),
    profile.identityProfileInput,
    profile.resourceEnvelopeInput,
    profile.topologyQualificationInput,
    profile.storageQualificationInput,
    profile.backup.targetInput,
    profile.retentionInput,
  ])
    if (
      typeof slot !== 'string' ||
      !slot.startsWith(`QINPUT-${selected.toUpperCase()}-`) ||
      !/^QINPUT-[A-Z0-9-]+-V1$/u.test(slot)
    )
      invalid('PROFILE_QUALIFICATION_SLOT');
  const bindings = profile.bindings;
  const host = selected === 'local' ? '127.0.0.1' : '0.0.0.0';
  if (
    bindings.publicHttps !== `${host}:8443` ||
    bindings.otlpGrpc !== `${host}:4317` ||
    bindings.otlpHttp !== `${host}:4318` ||
    bindings.prometheus !== `${host}:8889` ||
    bindings.envoyAdmin !== schema.properties.runtimePaths.properties.envoyAdminBind.const ||
    bindings.pdsUds !== schema.properties.runtimePaths.properties.pdsUdsPath.const ||
    bindings.brokerUds !== schema.properties.runtimePaths.properties.brokerUdsPath.const
  )
    invalid('PROFILE_RUNTIME_BINDING');
}

function optionalSchema(node) {
  if (Array.isArray(node)) return node.map(optionalSchema);
  if (node === null || typeof node !== 'object') return node;
  return Object.fromEntries(
    Object.entries(node)
      .filter(([key]) => key !== 'required')
      .map(([key, value]) => [key, optionalSchema(value)]),
  );
}

function defaults(node) {
  if (Object.hasOwn(node, 'default')) return structuredClone(node.default);
  if (Object.hasOwn(node, 'const')) return structuredClone(node.const);
  if (!node.properties) return undefined;
  return Object.fromEntries(
    Object.entries(node.properties)
      .map(([key, value]) => [key, defaults(value)])
      .filter(([, value]) => value !== undefined),
  );
}

function leaves(value, prefix = []) {
  return Object.entries(value).flatMap(([key, item]) =>
    item !== null && typeof item === 'object' && !Array.isArray(item)
      ? leaves(item, [...prefix, key])
      : [[...prefix, key]],
  );
}
const at = (value, path) => path.reduce((parent, key) => parent?.[key], value);
const pointer = (path) => `/${path.join('/')}`;

function merge(target, source, sourceClass, origins) {
  for (const path of leaves(source)) {
    let parent = target;
    for (const key of path.slice(0, -1)) parent = parent[key] ??= {};
    parent[path.at(-1)] = structuredClone(at(source, path));
    origins[pointer(path)] = sourceClass;
  }
}

function safeUri(value, protocols) {
  let uri;
  try {
    uri = new URL(value);
  } catch {
    invalid('URI_INVALID');
  }
  if (
    value.length > 2048 ||
    !protocols.includes(uri.protocol) ||
    !uri.hostname ||
    uri.username ||
    uri.password ||
    uri.hash ||
    uri.search ||
    /[\\\s]/u.test(value) ||
    /%(?:0[0-9a-f]|1[0-9a-f]|7f)/iu.test(value)
  )
    invalid('URI_INVALID');
}

function milliseconds(value) {
  const match = /^(0|[1-9][0-9]*)(ms|s|m|h|d)$/u.exec(value);
  if (!match) invalid('DURATION_INVALID');
  const result =
    BigInt(match[1]) * { ms: 1n, s: 1000n, m: 60000n, h: 3600000n, d: 86400000n }[match[2]];
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) invalid('DURATION_INVALID');
  return result;
}

function crossConstraints(config, schema) {
  const settings = config.settings;
  const duration = (key) => milliseconds(settings[key]);
  for (const [key, definition] of Object.entries(schema.properties.settings.properties)) {
    if (definition.$ref !== '#/$defs/Duration') continue;
    const value = duration(key);
    if (
      (definition['x-openpc-minMilliseconds'] !== undefined &&
        value < BigInt(definition['x-openpc-minMilliseconds'])) ||
      (definition['x-openpc-maxMilliseconds'] !== undefined &&
        value > BigInt(definition['x-openpc-maxMilliseconds']))
    )
      invalid('DURATION_BOUND');
  }
  if (
    settings['ui.page_size_default'] > settings['ui.page_size_max'] ||
    duration('session.idle_timeout') >= duration('session.absolute_timeout') ||
    duration('session.step_up_validity') > duration('session.idle_timeout') ||
    duration('identity.context_assertion_ttl') <= duration('identity.clock_skew_tolerance') ||
    settings['evidence.high_watermark'] >= settings['evidence.critical_watermark'] ||
    (config.profile === 'production' &&
      (settings['provider.quarantine_on_fingerprint_drift'] !== true ||
        settings['security.sensitive_copy_disabled'] !== true))
  )
    invalid('CROSS_FIELD_BOUND');
  try {
    new Intl.DateTimeFormat('en', { timeZone: settings['ui.default_timezone'] });
  } catch {
    invalid('TIMEZONE_INVALID');
  }
  safeUri(config.publicBaseUrl, ['https:']);
  safeUri(config.identity.oidcIssuer, ['https:']);
  safeUri(config.telemetry.otlpEndpoint, ['https:', 'grpc:']);
}

function checkValues(value, schema, provider, path = []) {
  if (schema.$ref === '#/$defs/SecretRef') {
    const version = typeof value === 'string' ? value.split('#')[1] : undefined;
    if (!isExactSigningSecretReference(value, version)) invalid('SECRET_REFERENCE_INVALID');
    if (value.split('/')[2] !== provider) invalid('SECRET_PROVIDER_MISMATCH');
    const name = value.slice(value.indexOf('/', 'secret://'.length) + 1, value.lastIndexOf('#'));
    if (name.split('/').some((part) => part === '' || part === '.' || part === '..'))
      invalid('SECRET_PATH_INVALID');
    return;
  }
  if (
    ['#/$defs/ProfileRef', '#/$defs/PublisherSetRef', '#/$defs/QualificationRef'].includes(
      schema.$ref,
    )
  ) {
    const name = value.slice(
      value.indexOf('/', value.indexOf('://') + 3) + 1,
      value.lastIndexOf('@sha256:'),
    );
    if (name.split('/').some((part) => part === '' || part === '.' || part === '..'))
      invalid('REFERENCE_PATH_INVALID');
  }
  if (
    typeof value === 'string' &&
    (value.length > 4096 ||
      /secret:\/\/|-----BEGIN |(?:bearer|basic)\s|data:.*base64|(?:password|client_secret|api[_-]?key)\s*[:=]/iu.test(
        value,
      ))
  )
    invalid('NON_SECRET_VALUE_REQUIRED');
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value)) {
      const definition =
        schema.properties?.[key] ??
        Object.entries(schema.patternProperties ?? {}).find(([pattern]) =>
          new RegExp(pattern, 'u').test(key),
        )?.[1];
      if (!definition) invalid('UNKNOWN_FIELD');
      checkValues(item, definition, provider, [...path, key]);
    }
  }
}

/** Structural preparation only. No parameter can mark trust, secrets or consumers verified. */
export function prepareInstallationCandidate(
  sources,
  { secretReferencesBytes = Buffer.from('{}'), expectedBaseGenerationId } = {},
) {
  const { schema, namedProfile, site, environment, profile, schemaBytes, profileBytes } = sources;
  if (
    schema?.$id !== 'urn:openpc:schema:effective-configuration:1.0' ||
    schema.additionalProperties !== false
  )
    invalid('SCHEMA_IDENTITY');
  checkProfile(namedProfile, schema, profile);
  const ajv = new Ajv2020({ strict: false, allErrors: false, validateFormats: true });
  addFormats(ajv);
  const partial = ajv.compile(optionalSchema(schema));
  const fullAjv = new Ajv2020({ strict: false, allErrors: false, validateFormats: true });
  addFormats(fullAjv);
  const full = fullAjv.compile(schema);
  const references = parseConfigurationJson(secretReferencesBytes);
  const secretPaths = Object.entries(schema.properties).flatMap(([section, node]) =>
    Object.entries(node.properties ?? {})
      .filter(([, field]) => field.$ref === '#/$defs/SecretRef')
      .map(([field]) => [section, field]),
  );
  const allowedSecrets = new Set(secretPaths.map(pointer));
  const allowedEnvironment = new Set(Object.values(environmentTargets).map(pointer));
  const origins = {};
  const configuration = {};
  const named = {
    profile,
    features: namedProfile.features,
    telemetry: { privacyProfile: namedProfile.telemetry.privacyProfile },
  };
  const layers = [
    [defaults(schema), 'COMPILED_SAFE_DEFAULT'],
    [named, 'NAMED_PROFILE'],
    [site, 'SITE_FILE'],
    [environment, 'ALLOWLISTED_ENVIRONMENT'],
    [references, 'SECRET_PROVIDER_REFERENCE'],
  ];
  for (const [source, sourceClass] of layers) {
    assertUnicode(source);
    if (!partial(source)) invalid('SOURCE_SCHEMA_INVALID');
    checkValues(source, schema, namedProfile.secretProvider.providerId);
    if (
      sourceClass === 'ALLOWLISTED_ENVIRONMENT' &&
      leaves(source).some((path) => !allowedEnvironment.has(pointer(path)))
    )
      invalid('ENVIRONMENT_SOURCE_FIELD');
    if (
      sourceClass === 'SECRET_PROVIDER_REFERENCE' &&
      leaves(source).some((path) => !allowedSecrets.has(pointer(path)))
    )
      invalid('SECRET_SOURCE_FIELD');
    merge(configuration, source, sourceClass, origins);
  }
  if (site.profile !== undefined && site.profile !== profile) invalid('PROFILE_BINDING');
  if (!full(configuration)) invalid('EFFECTIVE_SCHEMA_INVALID');
  if (configuration.generation.generationId === configuration.generation.baseGenerationId)
    invalid('GENERATION_SELF_REFERENCE');
  if (
    expectedBaseGenerationId !== undefined &&
    configuration.generation.baseGenerationId !== expectedBaseGenerationId
  )
    invalid('BASE_GENERATION_MISMATCH');
  crossConstraints(configuration, schema);
  const blockers = [...unresolvedInstallationOwners];
  if (Object.values(configuration.features).some((enabled) => enabled))
    blockers.push('FEATURE_COHORT_VERIFICATION_UNBOUND');
  const secretReferences = secretPaths.map((path) => {
    const reference = at(configuration, path);
    return {
      field: pointer(path),
      reference,
      version: reference.split('#')[1],
      referenceDigest: sha256(Buffer.from(reference)),
      resolved: false,
    };
  });
  return {
    state: 'BLOCKED',
    startupAllowed: false,
    blockers,
    // Separate from generation.contentDigest: its signed digest convention is not invented here.
    candidateDigest: sha256(configuration),
    inputDigests: { schema: sha256(schemaBytes), namedProfile: sha256(profileBytes) },
    configuration,
    sourceClasses: origins,
    secretReferences,
    qualificationSlots: Object.fromEntries(
      Object.entries(namedProfile.requiredSettingInputs).map(([key, slot]) => [
        key,
        { slot, reference: configuration.qualificationInputBindings[key], verified: false },
      ]),
    ),
    deploymentUnits: namedProfile.deploymentUnits,
  };
}
