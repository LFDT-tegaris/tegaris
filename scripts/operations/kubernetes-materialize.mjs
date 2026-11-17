import { constants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import manifest from '../../package.json' with { type: 'json' };
import { readConfigurationBytes } from './installation-config-inputs.mjs';
import {
  bindTemplate,
  canonicalJson,
  checkBindingCoverage,
  collectorTemplate,
  encodeYaml,
  expandBindings,
  invalid,
  KubernetesMaterializationError,
  parseInput,
  parseYaml,
  pointerValue,
  sha256,
  templateNames,
  templateTokens,
  utf8,
  yamlVersion,
} from './kubernetes-bindings.mjs';
import {
  renderTelemetry,
  mechanicalCorrectionRecords,
  assertCohortPlacement,
  validateKubernetesInputs,
  validateRendered,
  validateSchema,
  validateTelemetryCatalogue,
} from './kubernetes-validation.mjs';

const require = createRequire(import.meta.url);
const ajvVersion = require('ajv/package.json').version;
const base = fileURLToPath(new URL('../../deploy/kustomize/base/', import.meta.url));

/** These bytes identify inputs, not an authenticated archive or signed profile.
 * The canonical installer must bind authentication and release qualification.
 * All rendering inputs are packaged. An optional historical source root compares the
 * exact original bytes; this comparison is not archive/signature authentication.
 * There is no arbitrary rendered-config or environment fallback.
 */
export async function loadKubernetesSources({ inputPath, telemetryInputPath, c17Root }) {
  if (c17Root !== undefined && (typeof c17Root !== 'string' || !isAbsolute(c17Root)))
    invalid('C17_INPUT_BINDING');
  const read = (path) => readConfigurationBytes(path, 2 ** 20);
  const [
    schemaBytes,
    inputBytes,
    telemetrySchemaBytes,
    observabilityBytes,
    telemetryInputBytes,
    ...templates
  ] = await Promise.all([
    read(join(base, 'materialization-inputs.schema.json')),
    read(inputPath),
    read(join(base, 'telemetry-materialization.schema.json')),
    read(join(base, 'observability.yaml')),
    read(telemetryInputPath),
    ...templateNames.map((name) => read(join(base, name))),
  ]);
  const sources = {
    schemaBytes,
    inputBytes,
    templates: Object.fromEntries(templateNames.map((name, index) => [name, templates[index]])),
    telemetry: {
      schemaBytes: telemetrySchemaBytes,
      templateBytes: Buffer.from(collectorTemplate),
      observabilityBytes,
      inputBytes: telemetryInputBytes,
    },
  };
  if (c17Root !== undefined) {
    const originals = {
      'kubernetes/materialization-inputs.schema.json': schemaBytes,
      ...Object.fromEntries(
        templateNames.map((name, index) => [`kubernetes/${name}`, templates[index]]),
      ),
      'telemetry-materialization.schema.json': telemetrySchemaBytes,
      'observability.yaml': observabilityBytes,
      'otel-collector-0.159.template.yaml': sources.telemetry.templateBytes,
    };
    for (const [name, packaged] of Object.entries(originals)) {
      const original = await read(join(c17Root, 'SPECIFICATIONS/OPERATIONS', name));
      if (!packaged.equals(original)) invalid('C17_PACKAGED_INPUT_DRIFT');
    }
  }
  return sources;
}

function removeConditionalStores(template, input) {
  if (template.kind !== 'List' || !Array.isArray(template.items)) invalid('TEMPLATE_LIST');
  const removed = [];
  const items = template.items.filter((item) => {
    const store = item.metadata?.labels?.['openpc.io/store'];
    const omit =
      store === 'STORE-VALKEY-OPTIONAL'
        ? !input.valkey.enabled
        : ['STORE-CONTROL-PG', 'STORE-FACT-PG', 'STORE-CANDIDATE-INDEX-PG'].includes(store) &&
          input.postgresTopology.mode === 'EXACT_MANAGED_SERVICE_PROFILE';
    if (omit) removed.push(`${item.kind}/${item.metadata.name}`);
    return !omit;
  });
  const expected =
    (input.valkey.enabled ? 0 : 2) +
    (input.postgresTopology.mode === 'EXACT_MANAGED_SERVICE_PROFILE' ? 6 : 0);
  if (removed.length !== expected) invalid('CONDITIONAL_STORE_CARDINALITY');
  return { template: { ...template, items }, removed: removed.sort() };
}

const cohortKey = 'openpc.io/runtime-cohort';

function applyMechanicalCorrections(core, stores, targets, configMap, input) {
  const compiler = core.items?.filter(
    (item) => item.kind === 'Deployment' && item.metadata?.name === 'openpc-compiler',
  );
  if (compiler?.length !== 1) invalid('COMPILER_TMP_CORRECTION');
  const spec = compiler[0].spec?.template?.spec;
  const tmp = spec?.volumes?.filter((volume) => volume.name === 'tmp');
  const container = spec?.containers?.filter((value) => value.name === 'compiler');
  if (
    tmp?.length !== 1 ||
    container?.length !== 1 ||
    canonicalJson(tmp[0]) !==
      canonicalJson({
        name: 'tmp',
        emptyDir: {
          sizeLimit: input.resources.compiler.ephemeralStorageLimit,
        },
      }) ||
    canonicalJson(container[0].volumeMounts?.filter((value) => value.name === 'tmp')) !==
      canonicalJson([{ name: 'tmp', mountPath: '/tmp' }])
  )
    invalid('COMPILER_TMP_CORRECTION');
  if (targets.length !== input.protectedTargets.length) invalid('TARGET_BINDING');
  for (const value of [core, stores, configMap]) assertCohortPlacement(value);
  for (const [index, target] of targets.entries()) {
    const expected = input.protectedTargets[index];
    const metadata = target.metadata;
    if (
      metadata?.labels?.['openpc.io/target-id'] !== expected.targetId ||
      !/^sha256:[0-9a-f]{64}$/u.test(expected.runtimeCohortDigest) ||
      metadata?.labels?.[cohortKey] !== expected.runtimeCohortDigest ||
      !metadata.annotations ||
      typeof metadata.annotations !== 'object' ||
      Array.isArray(metadata.annotations) ||
      Object.hasOwn(metadata.annotations, cohortKey)
    )
      invalid('TARGET_COHORT_CORRECTION');
    assertCohortPlacement(target, `/metadata/labels/${cohortKey}`);
  }
  // Mutation starts only after every correction precondition passes. bindTemplate
  // made fresh objects; the packaged input buffers remain untouched.
  tmp[0].emptyDir.medium = 'Memory';
  for (const target of targets) {
    target.metadata.annotations[cohortKey] = target.metadata.labels[cohortKey];
    delete target.metadata.labels[cohortKey];
  }
  return mechanicalCorrectionRecords(input);
}

/** Full mechanical rendering, deliberately incapable of granting deployment authority. */
export function prepareKubernetesCandidate(sources, options) {
  if (process.versions.node !== manifest.engines.node || ajvVersion !== '8.20.0')
    invalid('TOOLCHAIN_MISMATCH');
  if (!options || canonicalJson(Object.keys(options)) !== '["optionalValkeyCache"]')
    invalid('RENDER_OPTIONS');
  const schema = parseInput(sources.schemaBytes);
  const input = parseInput(sources.inputBytes);
  validateSchema(schema, input, 'urn:openpc:schema:kubernetes-materialization-inputs:1.0');
  validateKubernetesInputs(input, options.optionalValkeyCache);
  if (!sources.telemetry) invalid('TELEMETRY_CONTRACT_UNBOUND');
  const telemetrySchema = parseInput(sources.telemetry.schemaBytes);
  const telemetryInput = parseInput(sources.telemetry.inputBytes);
  validateTelemetryCatalogue(parseYaml(utf8(sources.telemetry.observabilityBytes)));
  const telemetry = renderTelemetry(
    telemetrySchema,
    utf8(sources.telemetry.templateBytes),
    telemetryInput,
  );
  if (
    input.otelConfig.renderedConfig !== telemetry.config ||
    input.otelConfig.renderedConfigDigest !== telemetry.digest ||
    !input.otelConfig.qualificationRef.endsWith(`@${telemetryInput.qualificationReceiptDigest}`)
  )
    invalid('TELEMETRY_BINDING_MISMATCH');
  const rules = schema['x-openpc-tokenBindingRules'];
  if (
    canonicalJson(rules.templateSet) !== canonicalJson(templateNames) ||
    canonicalJson(Object.keys(sources.templates).sort()) !==
      canonicalJson([...templateNames].sort())
  )
    invalid('TEMPLATE_SET');
  const parsed = Object.fromEntries(
    templateNames.map((name) => [name, parseYaml(utf8(sources.templates[name]))]),
  );
  const table = expandBindings(rules);
  // Even conditionally removed values must resolve against closed, validated
  // input. Omitting resources is not a way to bypass input validation.
  for (const binding of table.values()) {
    if (binding.pointer.startsWith('@')) {
      for (const target of input.protectedTargets) pointerValue(input, binding.pointer, target);
    } else pointerValue(input, binding.pointer);
  }
  const originalTokens = new Set();
  Object.values(parsed).forEach((template) => templateTokens(template, originalTokens));
  const conditional = removeConditionalStores(parsed['postgresql-and-valkey.template.yaml'], input);
  parsed['postgresql-and-valkey.template.yaml'] = conditional.template;
  const activeTokens = new Set();
  Object.values(parsed).forEach((template) => templateTokens(template, activeTokens));
  const activeTable = new Map(
    [...table].filter(([token]) => activeTokens.has(token) || !originalTokens.has(token)),
  );
  checkBindingCoverage(parsed, activeTable);
  // Pin the two original source locations before binding. A pre-corrected or
  // substituted template is drift, even if its value happens to match this input.
  const sourceCompiler = parsed['openpc-core.template.yaml'].items?.filter(
    (item) => item.kind === 'Deployment' && item.metadata?.name === 'openpc-compiler',
  );
  const sourceTmp = sourceCompiler?.[0]?.spec?.template?.spec?.volumes?.filter(
    (volume) => volume.name === 'tmp',
  );
  if (
    sourceCompiler?.length !== 1 ||
    sourceTmp?.length !== 1 ||
    canonicalJson(sourceTmp[0]) !==
      canonicalJson({
        name: 'tmp',
        emptyDir: {
          sizeLimit: 'OPENPC_INPUT_RESOURCES_COMPILER_EPHEMERAL_STORAGE_LIMIT',
        },
      })
  )
    invalid('COMPILER_TMP_CORRECTION');
  if (
    parsed['protected-target.pod-template.yaml'].metadata?.labels?.[cohortKey] !==
    'OPENPC_INPUT_RUNTIME_COHORT_DIGEST'
  )
    invalid('TARGET_COHORT_CORRECTION');
  const counts = new Map();
  const core = bindTemplate(
    parsed['openpc-core.template.yaml'],
    activeTable,
    input,
    undefined,
    counts,
  );
  const stores = bindTemplate(
    parsed['postgresql-and-valkey.template.yaml'],
    activeTable,
    input,
    undefined,
    counts,
  );
  const configMap = bindTemplate(
    parsed['otel-configmap.template.yaml'],
    activeTable,
    input,
    undefined,
    counts,
  );
  const targets = input.protectedTargets.map((target) =>
    bindTemplate(parsed['protected-target.pod-template.yaml'], activeTable, input, target, counts),
  );
  const mechanicalCorrections = applyMechanicalCorrections(core, stores, targets, configMap, input);
  const blockers = validateRendered(core, stores, targets, configMap, input, mechanicalCorrections);
  const files = {
    'openpc-core.candidate.yaml': encodeYaml(core),
    'postgresql-and-valkey.candidate.yaml': encodeYaml(stores),
    'otel-configmap.candidate.yaml': encodeYaml(configMap),
    'otel-collector.candidate.yaml': telemetry.config,
    ...Object.fromEntries(
      targets.map((target, index) => [
        `target-${input.protectedTargets[index].targetId}.candidate.pod-template.yaml`,
        encodeYaml(target),
      ]),
    ),
  };
  for (const file of Object.values(files))
    if (file.includes('OPENPC_INPUT_')) invalid('UNRESOLVED_TOKEN');
  // Round-trip verifies the ConfigMap contains the exact digest-bound Collector
  // bytes, including newline/chomping semantics, rather than merely similar YAML.
  if (
    parseYaml(files['otel-configmap.candidate.yaml']).data['observability.yaml'] !==
    telemetry.config
  )
    invalid('COLLECTOR_CONFIG_PROJECTION');
  const renderedDigests = Object.fromEntries(
    Object.entries(files).map(([name, contents]) => [name, sha256(Buffer.from(contents))]),
  );
  const receipt = {
    schemaVersion: '1.0',
    kind: 'OPENPC_KUBERNETES_CANDIDATE_BINDING',
    state: 'BLOCKED',
    startupAllowed: false,
    claimCeiling: 'MECHANICAL_BINDING_ONLY',
    blockers,
    sourceDigests: {
      schema: sha256(sources.schemaBytes),
      input: sha256(sources.inputBytes),
      templates: Object.fromEntries(
        templateNames.map((name) => [name, sha256(sources.templates[name])]),
      ),
      telemetry: {
        schema: sha256(sources.telemetry.schemaBytes),
        template: sha256(sources.telemetry.templateBytes),
        observability: sha256(sources.telemetry.observabilityBytes),
        input: sha256(sources.telemetry.inputBytes),
      },
    },
    toolIdentities: {
      node: process.versions.node,
      ajv: ajvVersion,
      yaml: yamlVersion,
      materializer: 'OPENPC_KUBERNETES_CANDIDATE_V1',
    },
    qualificationReceiptDigest: input.qualificationReceiptDigest,
    telemetryQualificationReceiptDigest: telemetryInput.qualificationReceiptDigest,
    renderedDigests,
    renderedTreeDigest: sha256(renderedDigests),
    targetIteration: input.protectedTargets.map(({ targetId, controllerRef }, index) => ({
      targetId,
      controllerRef,
      output: `target-${input.protectedTargets[index].targetId}.candidate.pod-template.yaml`,
      insertion: 'UNBOUND',
    })),
    conditionalRemovals: conditional.removed,
    mechanicalCorrections,
    bindings: [...counts]
      .sort(([a], [b]) => a.localeCompare(b, 'en'))
      .map(([token, occurrences]) => ({ token, occurrences })),
    telemetryBindings: telemetry.bindings,
    validation: {
      closedInputs: 'PASS',
      typedBindings: 'PASS',
      quantities: 'PASS',
      telemetryTypedBindingsAndProjection: 'PASS',
      structuralChecks: 'PASS_WITH_RECORDED_TEMPLATE_BLOCKERS',
      secretReferences: 'SYNTAX_AND_OWNER_SEPARATION_ONLY',
      releaseQualification: 'BLOCKED',
    },
  };
  return { files, receipt };
}

/** One private, exclusive candidate bundle; no apply/start or overwrite behavior. */
export async function writeKubernetesCandidate(candidate, path) {
  if (
    candidate.receipt?.state !== 'BLOCKED' ||
    candidate.receipt?.startupAllowed !== false ||
    candidate.receipt?.claimCeiling !== 'MECHANICAL_BINDING_ONLY'
  )
    invalid('CANDIDATE_CLAIM');
  if (typeof path !== 'string' || !isAbsolute(path) || path !== resolve(path))
    invalid('OUTPUT_PATH');
  const parent = dirname(path);
  const stat = await lstat(parent);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    (stat.mode & 0o077) !== 0 ||
    (await realpath(parent)) !== parent
  )
    invalid('OUTPUT_DIRECTORY_UNSAFE');
  let file;
  try {
    file = await open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
    await file.writeFile(`${canonicalJson(candidate)}\n`);
    await file.chmod(0o400);
    await file.sync();
  } catch (error) {
    const failures = [error];
    if (file) {
      try {
        await file.close();
      } catch (cleanup) {
        failures.push(cleanup);
      }
      file = undefined;
      try {
        await unlink(path);
      } catch (cleanup) {
        failures.push(cleanup);
      }
    }
    if (failures.length > 1)
      throw new AggregateError(failures, 'Candidate write and cleanup failed');
    throw error;
  } finally {
    await file?.close();
  }
}

export function parseKubernetesArguments(args) {
  const names = [
    '--input',
    '--telemetry-input',
    '--c17-root',
    '--optional-valkey-cache',
    '--output',
  ];
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index],
      value = args[index + 1];
    if (!names.includes(name) || Object.hasOwn(options, name) || !value || value.startsWith('--'))
      invalid('ARGUMENT');
    options[name] = value;
  }
  if (
    names.filter((name) => name !== '--c17-root').some((name) => !Object.hasOwn(options, name)) ||
    !['true', 'false'].includes(options['--optional-valkey-cache'])
  )
    invalid('ARGUMENT');
  return options;
}

export async function materializeKubernetes(args) {
  const options = parseKubernetesArguments(args);
  const sources = await loadKubernetesSources({
    inputPath: options['--input'],
    telemetryInputPath: options['--telemetry-input'],
    c17Root: options['--c17-root'],
  });
  const candidate = prepareKubernetesCandidate(sources, {
    optionalValkeyCache: options['--optional-valkey-cache'] === 'true',
  });
  await writeKubernetesCandidate(candidate, options['--output']);
  return {
    exitCode: 2,
    result: { state: 'BLOCKED', startupAllowed: false, blockers: candidate.receipt.blockers },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { result, exitCode } = await materializeKubernetes(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = exitCode;
  } catch (error) {
    const reason =
      error instanceof KubernetesMaterializationError
        ? error.reason
        : 'INPUT_OR_OUTPUT_UNAVAILABLE';
    process.stderr.write(
      `${JSON.stringify({ state: 'BLOCKED', startupAllowed: false, reason })}\n`,
    );
    process.exitCode = 2;
  }
}
