import { createRequire } from 'node:module';
import {
  bindTemplate,
  canonicalJson,
  checkBindingCoverage,
  encodeYaml,
  invalid,
  parseYaml,
  sha256,
} from './kubernetes-bindings.mjs';

const require = createRequire(import.meta.url);
const Ajv2020 = require('ajv/dist/2020.js').default;

export const unresolvedReleaseOwners = Object.freeze([
  'C17_INPUT_AUTHENTICATION_UNBOUND',
  'SIGNED_PROFILE_AND_QUALIFICATION_VERIFICATION_UNBOUND',
  'GENERATION_ADMISSION_UNBOUND',
  'CONTROL_LOGICAL_SERVICE_COUNT_CONFLICT',
  'COM_NETWORK_PROFILE_MATERIALIZATION_UNBOUND',
  'PROTECTED_TARGET_CONTROLLER_INSERTION_UNBOUND',
  'STORAGE_PROFILE_AND_RUNTIME_PVC_QUALIFICATION_UNBOUND',
  'SECRET_PROVIDER_AND_CONSUMER_RESOLUTION_UNBOUND',
  'OCI_PLATFORM_SUPPLY_CHAIN_AND_RUNTIME_ENTRYPOINTS_UNVERIFIED',
  'KUBERNETES_1_36_2_SERVER_VALIDATION_UNEXECUTED',
  'COLLECTOR_0_159_0_VALIDATION_UNEXECUTED',
]);

export function validateSchema(schema, input, expectedId) {
  if (schema.$id !== expectedId || schema.additionalProperties !== false)
    invalid('SCHEMA_IDENTITY');
  const ajv = new Ajv2020({ strict: true, allErrors: false, validateFormats: false });
  for (const name of Object.keys(schema).filter((key) => key.startsWith('x-openpc-')))
    ajv.addKeyword({ keyword: name });
  let validate;
  try {
    validate = ajv.compile(schema);
  } catch {
    invalid('SCHEMA_INVALID');
  }
  if (!validate(input)) invalid('INPUT_SCHEMA');
}

/** Exact positive Kubernetes Quantity arithmetic for the installation's closed syntax.
 * Values finer than a nanounit round upwards, as Quantity does; no float parsing.
 */
export function quantity(value, resource = 'storage') {
  if (
    typeof value !== 'string' ||
    value.length > 128 ||
    !/^(?:[1-9][0-9]*(?:m|Ki|Mi|Gi|Ti)?|0\.[0-9]+)$/u.test(value)
  )
    invalid('QUANTITY_SYNTAX');
  const match = /^([0-9]+)(?:\.([0-9]+))?(m|Ki|Mi|Gi|Ti)?$/u.exec(value);
  const [, integer, fraction = '', unit = ''] = match;
  const factors = {
    '': 1n,
    'm': 1n,
    'Ki': 1024n,
    'Mi': 1024n ** 2n,
    'Gi': 1024n ** 3n,
    'Ti': 1024n ** 4n,
  };
  const numerator = BigInt(`${integer}${fraction}`) * factors[unit];
  const denominator = 10n ** BigInt(fraction.length) * (unit === 'm' ? 1000n : 1n);
  if (numerator === 0n || numerator > ((1n << 63n) - 1n) * denominator) invalid('QUANTITY_RANGE');
  if (
    resource === 'cpu' &&
    (['Ki', 'Mi', 'Gi', 'Ti'].includes(unit) || (numerator * 1000n) % denominator !== 0n)
  )
    invalid('CPU_QUANTITY');
  return (numerator * 1000000000n + denominator - 1n) / denominator;
}

function checkEnvelope(envelope) {
  for (const [field, resource] of [
    ['cpu', 'cpu'],
    ['memory', 'memory'],
    ['ephemeralStorage', 'storage'],
  ]) {
    if (
      quantity(envelope[`${field}Request`], resource) >
      quantity(envelope[`${field}Limit`], resource)
    )
      invalid('RESOURCE_REQUEST_EXCEEDS_LIMIT');
  }
}

function unique(values, reason) {
  if (new Set(values).size !== values.length) invalid(reason);
}

function checkReference(reference) {
  // The schemas specify the scheme, version/digest and alphabet. Forbid ambiguous
  // path identities as well; do not normalize two owner references into one.
  const path = reference.slice(reference.indexOf('://') + 3).split(/[\x23@]/u)[0];
  if (path.split('/').some((part) => !part || part === '.' || part === '..'))
    invalid('REFERENCE_PATH');
}

export function validateKubernetesInputs(input, optionalValkeyCache) {
  if (typeof optionalValkeyCache !== 'boolean' || optionalValkeyCache !== input.valkey.enabled)
    invalid('VALKEY_FLAG_MISMATCH');
  for (const envelope of Object.values(input.resources)) checkEnvelope(envelope);
  for (const target of input.protectedTargets) checkEnvelope(target.targetResources);
  for (const value of [
    input.postgresTopology.runVolumeLimit,
    input.valkey.runVolumeLimit,
    input.valkey.maxmemory,
    ...input.protectedTargets.map((target) => target.socketVolumeLimit),
  ])
    quantity(value);
  if (quantity(input.valkey.maxmemory) > quantity(input.resources.valkey.memoryLimit))
    invalid('VALKEY_MEMORY_EXCEEDS_LIMIT');
  for (const value of Object.values(input.storage))
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value <= 0))
      invalid('STORAGE_BYTES');
  for (const image of [
    ...Object.values(input.images),
    ...input.protectedTargets.map((target) => target.targetImage),
  ]) {
    const [name] = image.split('@');
    if (name.split('/').some((part) => !part || part === '.' || part === '..'))
      invalid('IMAGE_PATH');
  }
  const references = [
    ...Object.values(input.secretRefs),
    input.valkey.secretRef,
    ...Object.values(input.network).filter((value) => value.startsWith('profile://')),
    input.otelConfig.qualificationRef,
    input.topology.qualificationRef,
    input.storage.qualificationRef,
    input.postgresTopology.qualificationRef,
    input.valkey.qualificationRef,
    ...Object.values(input.resources).map((value) => value.qualificationRef),
    ...input.protectedTargets.map((target) => target.targetResources.qualificationRef),
  ];
  references.forEach(checkReference);
  unique(
    ['controlPostgres', 'factPostgres', 'candidateIndexPostgres'].map(
      (key) => input.secretRefs[key],
    ),
    'STORE_CREDENTIAL_ALIAS',
  );
  unique(
    input.protectedTargets.map((target) => target.targetId),
    'TARGET_ID_COLLISION',
  );
  unique(
    input.protectedTargets.map((target) => target.controllerRef),
    'TARGET_CONTROLLER_COLLISION',
  );
  unique(
    input.protectedTargets.flatMap((target) => [target.artifactPvc, target.evidencePvc]),
    'STORE_VOLUME_ALIAS',
  );
  for (const target of input.protectedTargets) {
    if (
      ['workbench', 'control', 'compiler', 'fleet-control', 'fact-bridge', 'otel-collector'].some(
        (name) => target.controllerRef === `Deployment/openpc-${name}`,
      )
    )
      invalid('TARGET_CONTROLLER_COLLISION');
  }
  const postgresProfiles = [
    'controlPostgresEndpointProfile',
    'factPostgresEndpointProfile',
    'candidateIndexPostgresEndpointProfile',
  ];
  for (const key of postgresProfiles) {
    const internal = input.network[key] === 'IN_CLUSTER_SELF_MANAGED';
    if (internal !== (input.postgresTopology.mode === 'SELF_MANAGED_STATEFULSET'))
      invalid('POSTGRES_TOPOLOGY_MISMATCH');
  }
}

function duration(value) {
  const [, count, unit] = /^([1-9][0-9]*)(ms|s|m|h|d)$/u.exec(value);
  if (count.length > 20) invalid('TELEMETRY_DURATION_RANGE');
  return BigInt(count) * { ms: 1n, s: 1000n, m: 60000n, h: 3600000n, d: 86400000n }[unit];
}

/** The operational catalogue is not Collector YAML. Bind its exact AF26 identity
 * alongside the separately typed executable template; no catalogue prose grants
 * deployment, signal-schema or failure-behavior qualification.
 */
export function validateTelemetryCatalogue(catalogue) {
  if (
    catalogue?.schemaVersion !== '1.0' ||
    catalogue.contractId !== 'AF26-OBSERVABILITY-V1' ||
    catalogue.collector?.distribution !== 'signed-openpc-collector' ||
    catalogue.collector?.upstreamVersion !== '0.159.0' ||
    catalogue.collector?.deploymentUnitId !== 'DU-OTEL-COLLECTOR' ||
    !catalogue.trace?.componentRefs?.includes('COM-020')
  )
    invalid('TELEMETRY_CATALOGUE_IDENTITY');
}

/** Bind the actual AF26 Collector template, never accept arbitrary rendered YAML. */
export function renderTelemetry(schema, template, input) {
  validateSchema(
    schema,
    input,
    'urn:openpc:schema:otel-collector-0.159-materialization-inputs:1.0',
  );
  if (
    input.memorySpikeLimitMiB >= input.memoryLimitMiB ||
    input.sendBatchSize > input.sendBatchMaxSize ||
    input.exportQueueSize < input.sendBatchMaxSize ||
    duration(input.retryInitialInterval) > duration(input.retryMaxInterval) ||
    duration(input.retryMaxInterval) > duration(input.retryMaxElapsedTime)
  )
    invalid('TELEMETRY_CROSS_CONSTRAINT');
  duration(input.batchTimeout);
  duration(input.metricExpiration);
  let endpoint;
  try {
    endpoint = new URL(input.approvedSinkEndpoint);
  } catch {
    invalid('TELEMETRY_ENDPOINT');
  }
  if (
    endpoint.username ||
    endpoint.password ||
    endpoint.hash ||
    endpoint.search ||
    (endpoint.port && (Number(endpoint.port) < 1 || Number(endpoint.port) > 65535))
  )
    invalid('TELEMETRY_ENDPOINT');
  const table = new Map(
    Object.entries(schema['x-openpc-tokenBindings']).map(([token, pointer]) => [
      token,
      {
        pointer,
        serialization:
          schema.properties[pointer.slice(1)]?.type === 'integer' ? 'YAML_INTEGER' : 'YAML_STRING',
      },
    ]),
  );
  const parsed = parseYaml(template);
  checkBindingCoverage({ collector: parsed }, table);
  const counts = new Map();
  const rendered = bindTemplate(parsed, table, input, undefined, counts);
  if ([...counts.values()].some((count) => count !== 1)) invalid('TELEMETRY_BINDING_CARDINALITY');
  // The normative ConfigMap uses |-. Canonical Collector bytes therefore use LF
  // line separators and no trailing LF, preserving exact bytes after projection.
  const config = encodeYaml(rendered).replace(/\n$/u, '');
  return { config, digest: sha256(Buffer.from(config)), bindings: [...counts.keys()].sort() };
}

const centralUnits = {
  'openpc-workbench': ['DU-PC-WORKBENCH', 'workbench'],
  'openpc-control': ['DU-PC-CONTROL', 'control'],
  'openpc-compiler': ['DU-PC-COMPILER', 'compiler'],
  'openpc-fleet-control': ['DU-PC-FLEET-CONTROL', 'fleet-control'],
  'openpc-fact-bridge': ['DU-PC-FACT-BRIDGE', 'fact-bridge'],
  'openpc-otel-collector': ['DU-OTEL-COLLECTOR', 'otel-collector'],
};

function checkEnvironment(container, expected) {
  const entries = container.env ?? [];
  if (container.envFrom || entries.length !== Object.keys(expected).length)
    invalid('CONSUMER_ENVIRONMENT');
  unique(
    entries.map((entry) => entry.name),
    'CONSUMER_ENVIRONMENT',
  );
  for (const entry of entries) {
    if (
      Object.keys(entry).sort().join(',') !== 'name,value' ||
      !Object.hasOwn(expected, entry.name) ||
      entry.value !== expected[entry.name]
    )
      invalid('CONSUMER_ENVIRONMENT');
  }
}

function checkSecretProjection(pod, providerClass, input) {
  const projections = (pod.spec.volumes ?? []).filter((volume) => volume.csi);
  if (projections.length !== (providerClass ? 1 : 0)) invalid('CSI_OWNER_BINDING');
  if (!providerClass) return;
  const volume = projections[0];
  if (
    volume.name !== 'secret-provider' ||
    volume.csi.driver !== input.secretCsiDriver ||
    volume.csi.volumeAttributes.secretProviderClass !== providerClass
  )
    invalid('CSI_OWNER_BINDING');
}

function validateCentralBindings(item, input) {
  const name = item.metadata.name;
  const pod = item.spec.template;
  const container = pod.spec.containers[0];
  const profile = { OPENPC_PROFILE: input.profile };
  const refs = input.secretRefs;
  const bindings = {
    'openpc-workbench': ['workbench', profile],
    'openpc-control': [
      'control',
      {
        ...profile,
        OPENPC_CONTROL_DSN_REF: refs.controlPostgres,
        OPENPC_OIDC_CLIENT_SECRET_REF: refs.oidcClient,
      },
    ],
    'openpc-compiler': ['compiler', { ...profile, OPENPC_SIGNING_KEY_REF: refs.signingKey }],
    'openpc-fleet-control': [
      'fleetControl',
      {
        ...profile,
        OPENPC_CONTROL_DSN_REF: refs.controlPostgres,
        OPENPC_OCI_CREDENTIAL_REF: refs.oci,
      },
    ],
    'openpc-fact-bridge': [
      'factBridge',
      {
        ...profile,
        OPENPC_FACTS_DSN_REF: refs.factPostgres,
        OPENPC_CANDIDATE_INDEX_DSN_REF: refs.candidateIndexPostgres,
      },
    ],
    'openpc-otel-collector': ['otelCollector', {}],
  };
  const [image, environment] = bindings[name];
  if (container.image !== input.images[image]) invalid('IMAGE_OWNER_BINDING');
  checkEnvironment(container, environment);
  checkSecretProjection(pod, name === 'openpc-workbench' ? null : name, input);
}

function validateStoreBindings(item, input) {
  const bindings = {
    'openpc-control-pg': [
      'STORE-CONTROL-PG',
      input.secretRefs.controlPostgres,
      input.storage.controlPgBytes,
    ],
    'openpc-fact-pg': ['STORE-FACT-PG', input.secretRefs.factPostgres, input.storage.factPgBytes],
    'openpc-candidate-index-pg': [
      'STORE-CANDIDATE-INDEX-PG',
      input.secretRefs.candidateIndexPostgres,
      input.storage.candidateIndexPgBytes,
    ],
    'openpc-valkey': ['STORE-VALKEY-OPTIONAL', input.valkey.secretRef],
  };
  const [store, reference, storageBytes] = bindings[item.metadata.name] ?? [];
  if (!store || item.metadata.labels?.['openpc.io/store'] !== store) invalid('STORE_OWNER_BINDING');
  if (item.kind === 'Service') return;
  const pod = item.spec.template;
  if (pod.metadata.labels?.['openpc.io/store'] !== store || pod.spec.containers.length !== 1)
    invalid('STORE_OWNER_BINDING');
  const container = pod.spec.containers[0];
  const valkey = store === 'STORE-VALKEY-OPTIONAL';
  if (
    container.name !== (valkey ? 'valkey' : 'postgresql') ||
    container.image !== input.images[valkey ? 'valkey' : 'postgresql']
  )
    invalid('STORE_OWNER_BINDING');
  checkEnvironment(
    container,
    valkey
      ? { OPENPC_VALKEY_SECRET_REF: reference }
      : {
          OPENPC_DATABASE_SECRET_REF: reference,
          OPENPC_STORE_ID: store,
        },
  );
  checkSecretProjection(pod, item.metadata.name, input);
  const claims = item.spec.volumeClaimTemplates ?? [];
  if (valkey ? claims.length !== 0 : claims.length !== 1) invalid('STORE_PVC_BINDING');
  if (!valkey) {
    const claim = claims[0];
    if (
      claim.metadata.name !== 'data' ||
      claim.spec.storageClassName !== input.storage.storageClassName ||
      canonicalArray(claim.spec.accessModes) !== '["ReadWriteOnce"]' ||
      claim.spec.resources.requests.storage !== String(storageBytes)
    )
      invalid('STORE_PVC_BINDING');
  }
}

function validatePod(pod, claims = []) {
  const spec = pod.spec;
  if (
    !spec ||
    spec.automountServiceAccountToken !== false ||
    spec.hostNetwork ||
    spec.hostPID ||
    spec.hostIPC ||
    spec.shareProcessNamespace ||
    spec.initContainers ||
    spec.ephemeralContainers ||
    spec.securityContext?.runAsUser !== 65532 ||
    spec.securityContext?.runAsGroup !== 65532 ||
    spec.securityContext?.fsGroup !== 65532 ||
    spec.securityContext?.runAsNonRoot !== true ||
    spec.securityContext?.seccompProfile?.type !== 'RuntimeDefault'
  )
    invalid('POD_SECURITY');
  const declaredVolumes = [
    ...(spec.volumes ?? []),
    ...claims.map((claim) => ({
      name: claim.metadata.name,
      persistentVolumeClaim: { claimName: claim.metadata.name },
    })),
  ];
  const volumes = new Map(declaredVolumes.map((volume) => [volume.name, volume]));
  if (volumes.size !== declaredVolumes.length) invalid('VOLUME_COLLISION');
  for (const volume of volumes.values()) {
    if (
      volume.hostPath ||
      volume.secret ||
      volume.projected ||
      !['emptyDir', 'persistentVolumeClaim', 'configMap', 'csi'].some((key) =>
        Object.hasOwn(volume, key),
      )
    )
      invalid('VOLUME_SECURITY');
    if (volume.emptyDir) {
      quantity(volume.emptyDir.sizeLimit);
      if (volume.emptyDir.medium !== 'Memory') invalid('SCRATCH_NOT_MEMORY_BACKED');
    }
    if (
      volume.csi &&
      (volume.csi.readOnly !== true || !volume.csi.volumeAttributes?.secretProviderClass)
    )
      invalid('CSI_PROJECTION');
  }
  unique(
    spec.containers.map((container) => container.name),
    'CONTAINER_COLLISION',
  );
  for (const container of spec.containers) {
    const security = container.securityContext;
    if (
      !security ||
      security.allowPrivilegeEscalation !== false ||
      security.privileged !== false ||
      security.readOnlyRootFilesystem !== true ||
      canonicalArray(security.capabilities?.drop) !== '["ALL"]' ||
      security.capabilities?.add ||
      (security.runAsUser !== undefined && security.runAsUser !== 65532) ||
      (security.runAsGroup !== undefined && security.runAsGroup !== 65532) ||
      container.volumeDevices
    )
      invalid('CONTAINER_SECURITY');
    if (!/^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/u.test(container.image))
      invalid('IMAGE_NOT_PINNED');
    for (const resource of ['cpu', 'memory', 'ephemeral-storage']) {
      if (
        quantity(container.resources?.requests?.[resource], resource) >
        quantity(container.resources?.limits?.[resource], resource)
      )
        invalid('RESOURCE_REQUEST_EXCEEDS_LIMIT');
    }
    for (const port of container.ports ?? [])
      if (
        port.hostPort ||
        port.hostIP ||
        ![8443, 5432, 6379, 4317, 4318, 8889].includes(port.containerPort)
      )
        invalid('CONTAINER_PORT');
    for (const mount of container.volumeMounts ?? []) {
      if (
        !volumes.has(mount.name) ||
        mount.subPath ||
        mount.subPathExpr ||
        mount.mountPropagation ||
        ![
          '/tmp',
          '/run/postgresql',
          '/run/valkey',
          '/run/openpc',
          '/run/openpc/secrets',
          '/var/lib/postgresql/data',
          '/var/lib/openpc/artifacts',
          '/var/lib/openpc/evidence',
          '/etc/openpc',
          '/etc/openpc-envoy',
        ].includes(mount.mountPath)
      )
        invalid('MOUNT_SECURITY');
      if (
        (volumes.get(mount.name).csi || volumes.get(mount.name).configMap) &&
        mount.readOnly !== true
      )
        invalid('MOUNT_READ_ONLY');
    }
  }
}

function canonicalArray(value) {
  return JSON.stringify(value);
}

const cohortKey = 'openpc.io/runtime-cohort';
// Fail closed if a changed template introduces a selector/downward-API/other
// consumer of the old label. Such a consumer needs its actual owner, not a
// silent selector rewrite or a shortened digest.
export function assertCohortPlacement(value, allowedPath, path = '') {
  if (typeof value === 'string') {
    if (value.includes(cohortKey)) invalid('TARGET_COHORT_CONSUMER');
  } else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const next = `${path}/${key}`;
      if (key === cohortKey && next !== allowedPath) invalid('TARGET_COHORT_CONSUMER');
      assertCohortPlacement(child, allowedPath, next);
    }
  }
}

/** These are explicit mechanical corrections, not changes to packaged source
 * bytes or a claim of historical-source or release qualification. Values remain input-bound. */
export function mechanicalCorrectionRecords(input) {
  return [
    {
      correction: 'COMPILER_TMP_MEMORY',
      sourceTemplate: 'openpc-core.template.yaml',
      output: 'openpc-core.candidate.yaml',
      resource: 'Deployment/openpc-compiler',
      volume: 'tmp',
      field: 'emptyDir.medium',
      operation: 'ADD',
      value: 'Memory',
      preservedSizeLimit: input.resources.compiler.ephemeralStorageLimit,
    },
    ...input.protectedTargets.map((target) => ({
      correction: 'RUNTIME_COHORT_ANNOTATION',
      sourceTemplate: 'protected-target.pod-template.yaml',
      output: `target-${target.targetId}.candidate.pod-template.yaml`,
      targetId: target.targetId,
      operation: 'MOVE',
      from: '/metadata/labels/openpc.io~1runtime-cohort',
      path: '/metadata/annotations/openpc.io~1runtime-cohort',
      value: target.runtimeCohortDigest,
    })),
  ];
}

function validateMechanicalCorrections(core, targets, input, corrections) {
  if (canonicalJson(corrections ?? null) !== canonicalJson(mechanicalCorrectionRecords(input)))
    invalid('MECHANICAL_CORRECTION_RECEIPT');
  const compiler = core.items?.filter(
    (item) => item.kind === 'Deployment' && item.metadata?.name === 'openpc-compiler',
  );
  if (compiler?.length !== 1) invalid('COMPILER_TMP_CORRECTION');
  const pod = compiler[0].spec?.template?.spec;
  const tmp = pod?.volumes?.filter((volume) => volume.name === 'tmp');
  const mount = pod?.containers?.filter((container) => container.name === 'compiler');
  if (
    tmp?.length !== 1 ||
    mount?.length !== 1 ||
    canonicalJson(tmp[0]) !==
      canonicalJson({
        name: 'tmp',
        emptyDir: {
          medium: 'Memory',
          sizeLimit: input.resources.compiler.ephemeralStorageLimit,
        },
      }) ||
    canonicalJson(mount[0].volumeMounts?.filter((value) => value.name === 'tmp')) !==
      canonicalJson([{ name: 'tmp', mountPath: '/tmp' }])
  )
    invalid('COMPILER_TMP_CORRECTION');
  quantity(tmp[0].emptyDir.sizeLimit);
  if (targets.length !== input.protectedTargets.length) invalid('TARGET_BINDING');
  for (const [index, target] of targets.entries()) {
    const expected = input.protectedTargets[index];
    if (
      target.metadata?.labels?.['openpc.io/target-id'] !== expected.targetId ||
      Object.hasOwn(target.metadata?.labels ?? {}, 'openpc.io/runtime-cohort') ||
      target.metadata?.annotations?.['openpc.io/runtime-cohort'] !== expected.runtimeCohortDigest
    )
      invalid('TARGET_COHORT_BINDING');
  }
}

/** Structural checks are distinct from tool validation and real runtime qualification. */
export function validateRendered(core, stores, targets, configMap, input, corrections) {
  const blockers = new Set(unresolvedReleaseOwners);
  if (core.kind !== 'List' || stores.kind !== 'List') invalid('TEMPLATE_LIST');
  validateMechanicalCorrections(core, targets, input, corrections);
  for (const value of [core, stores, configMap]) assertCohortPlacement(value);
  for (const target of targets) assertCohortPlacement(target, `/metadata/annotations/${cohortKey}`);
  const deployments = core.items.filter((item) => item.kind === 'Deployment');
  const expectedObjects = new Set([
    `Namespace/${input.namespace}`,
    'NetworkPolicy/default-deny-all',
    'PodDisruptionBudget/openpc-control',
    ...Object.keys(centralUnits).flatMap((name) =>
      ['ServiceAccount', 'Deployment', 'Service'].map((kind) => `${kind}/${name}`),
    ),
  ]);
  if (
    core.items.length !== expectedObjects.size ||
    core.items.some((item) => !expectedObjects.has(`${item.kind}/${item.metadata?.name}`))
  )
    invalid('CORE_OBJECT_TOPOLOGY');
  if (deployments.length !== Object.keys(centralUnits).length) invalid('UNIT_TOPOLOGY');
  unique(
    deployments.map((item) => item.metadata.name),
    'UNIT_COLLISION',
  );
  for (const item of deployments) {
    const expected = centralUnits[item.metadata.name];
    if (
      !expected ||
      item.metadata.labels?.['openpc.io/du'] !== expected[0] ||
      item.spec.template.metadata.labels?.['openpc.io/du'] !== expected[0] ||
      item.spec.template.spec.containers.length !== 1 ||
      item.spec.template.spec.containers[0].name !== expected[1]
    )
      invalid('UNIT_TOPOLOGY');
    validatePod(item.spec.template);
    validateCentralBindings(item, input);
  }
  const expectedStores = [
    ...(input.postgresTopology.mode === 'SELF_MANAGED_STATEFULSET'
      ? ['openpc-control-pg', 'openpc-fact-pg', 'openpc-candidate-index-pg']
      : []),
    ...(input.valkey.enabled ? ['openpc-valkey'] : []),
  ];
  if (stores.items.length !== expectedStores.length * 2) invalid('STORE_TOPOLOGY');
  for (const name of expectedStores) {
    const matches = stores.items.filter((item) => item.metadata.name === name);
    if (
      matches.length !== 2 ||
      !matches.some((item) => item.kind === 'Service') ||
      !matches.some((item) => item.kind === 'StatefulSet')
    )
      invalid('STORE_TOPOLOGY');
  }
  for (const item of stores.items.filter((item) => item.kind === 'StatefulSet'))
    validatePod(item.spec.template, item.spec.volumeClaimTemplates);
  stores.items.forEach((item) => validateStoreBindings(item, input));
  for (const [index, target] of targets.entries()) {
    validatePod(target);
    if (
      canonicalArray(target.spec.containers.map((container) => container.name)) !==
      '["protected-target","openpc-runtime","envoy"]'
    )
      invalid('PROTECTED_TARGET_TOPOLOGY');
    const [application, runtime, envoy] = target.spec.containers;
    if (
      application.image !== input.protectedTargets[index].targetImage ||
      runtime.image !== input.images.runtime ||
      envoy.image !== input.images.envoy
    )
      invalid('IMAGE_OWNER_BINDING');
    checkEnvironment(application, {});
    checkEnvironment(envoy, {});
    checkEnvironment(runtime, {
      OPENPC_PROFILE: input.profile,
      OPENPC_TRUST_BUNDLE_REF: input.secretRefs.workloadPki,
      OPENPC_OCI_CREDENTIAL_REF: input.secretRefs.oci,
      OPENPC_EVIDENCE_VAULT_REF: input.secretRefs.evidenceVault,
    });
    checkSecretProjection(target, 'openpc-runtime', input);
    for (const [volumeName, field] of [
      ['runtime-artifacts', 'artifactPvc'],
      ['runtime-evidence', 'evidencePvc'],
    ]) {
      if (
        target.spec.volumes.find((volume) => volume.name === volumeName)?.persistentVolumeClaim
          ?.claimName !== input.protectedTargets[index][field]
      )
        invalid('TARGET_PVC_BINDING');
    }
    if (
      application.volumeMounts.some((mount) => mount.name !== 'tmp-target') ||
      runtime.volumeMounts.find((mount) => mount.name === 'runtime-sockets')?.mountPath !==
        '/run/openpc' ||
      envoy.volumeMounts.find((mount) => mount.name === 'runtime-sockets')?.mountPath !==
        '/run/openpc' ||
      runtime.ports ||
      envoy.volumeMounts.some((mount) =>
        ['runtime-artifacts', 'runtime-evidence', 'secret-provider'].includes(mount.name),
      )
    )
      invalid('RUNTIME_UDS_BOUNDARY');
    if (target.metadata.labels['openpc.io/target-id'] !== input.protectedTargets[index].targetId)
      invalid('TARGET_BINDING');
  }
  const all = [...core.items, ...stores.items, configMap];
  unique(
    all.map(
      (item) =>
        `${item.apiVersion}/${item.kind}/${item.metadata?.namespace ?? ''}/${item.metadata?.name}`,
    ),
    'OBJECT_COLLISION',
  );
  for (const item of all) {
    if (
      ![
        'Namespace',
        'ServiceAccount',
        'Deployment',
        'StatefulSet',
        'Service',
        'NetworkPolicy',
        'PodDisruptionBudget',
        'ConfigMap',
      ].includes(item.kind)
    )
      invalid('OBJECT_KIND');
    if (JSON.stringify(item).includes('DU-SUBQUERY') || JSON.stringify(item).includes('LS-INDEXER'))
      invalid('FUTURE_SUBQUERY');
    if (
      item.kind === 'Service' &&
      ((item.spec.type && item.spec.type !== 'ClusterIP') ||
        item.spec.externalName ||
        item.spec.externalIPs ||
        item.spec.loadBalancerIP ||
        item.spec.ports.some(
          (port) => port.nodePort || ![8443, 5432, 6379, 4317, 4318, 8889].includes(port.port),
        ))
    )
      invalid('SERVICE_EXPOSURE');
    if (item.kind === 'ServiceAccount' && item.automountServiceAccountToken !== false)
      invalid('SERVICE_ACCOUNT_TOKEN');
    if (
      item.kind === 'NetworkPolicy' &&
      (item.metadata.name !== 'default-deny-all' ||
        canonicalArray(item.spec.policyTypes) !== '["Ingress","Egress"]' ||
        Object.keys(item.spec.podSelector).length !== 0 ||
        item.spec.ingress ||
        item.spec.egress)
    )
      invalid('NETWORK_POLICY');
  }
  if (core.items.filter((item) => item.kind === 'NetworkPolicy').length !== 1)
    invalid('DEFAULT_DENY_MISSING');
  if (
    configMap.kind !== 'ConfigMap' ||
    configMap.immutable !== true ||
    configMap.data?.['observability.yaml'] !== input.otelConfig.renderedConfig ||
    Object.keys(configMap.data).length !== 1
  )
    invalid('COLLECTOR_CONFIG_PROJECTION');
  return [...blockers].sort();
}
