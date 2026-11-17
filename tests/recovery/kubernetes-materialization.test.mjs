import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test, { before } from 'node:test';
import {
  canonicalJson,
  collectorTemplate,
  encodeYaml,
  KubernetesMaterializationError,
  parseInput,
  parseYaml,
  sha256,
  templateNames,
} from '../../scripts/operations/kubernetes-bindings.mjs';
import {
  quantity,
  renderTelemetry,
  validateRendered,
} from '../../scripts/operations/kubernetes-validation.mjs';
import {
  loadKubernetesSources,
  materializeKubernetes,
  parseKubernetesArguments,
  prepareKubernetesCandidate,
  writeKubernetesCandidate,
} from '../../scripts/operations/kubernetes-materialize.mjs';

const root = resolve(import.meta.dirname, '../..');
const c17Root = process.env.OPENPC_C17_PACKAGE_ROOT;
const scratchRoot = process.env.OPENPC_PNC_TMP_ROOT;
const bytes = (value) => Buffer.from(JSON.stringify(value));
const digest = `sha256:${'a'.repeat(64)}`;
const qualification = (name) => `qualification://test-fixture/${name}@${digest}`;
const profile = (name) => `profile://test-fixture/${name}@${digest}`;
const secret = (name) => `secret://test-fixture/${name}#v1`;
let authority;
let schema;
let telemetrySchema;

before(async () => {
  assert.ok(scratchRoot, 'Existing external scratch root must be bound by the dispatcher');
  const base = join(root, 'deploy/kustomize/base');
  const [schemaBytes, telemetrySchemaBytes, observabilityBytes, ...templates] = await Promise.all([
    readFile(join(base, 'materialization-inputs.schema.json')),
    readFile(join(base, 'telemetry-materialization.schema.json')),
    readFile(join(base, 'observability.yaml')),
    ...templateNames.map((name) => readFile(join(base, name))),
  ]);
  authority = {
    schemaBytes,
    templates: Object.fromEntries(templateNames.map((name, index) => [name, templates[index]])),
    telemetry: {
      schemaBytes: telemetrySchemaBytes,
      templateBytes: Buffer.from(collectorTemplate),
      observabilityBytes,
    },
  };
  schema = parseInput(schemaBytes);
  telemetrySchema = parseInput(telemetrySchemaBytes);
});

// These deliberately unqualified .invalid/test-fixture values exercise the real
// renderer only. They are not signed profiles, real image digests or credentials.
function fixture() {
  const telemetryInput = {
    schemaVersion: '1.0',
    qualificationReceiptDigest: digest,
    memoryLimitMiB: 128,
    memorySpikeLimitMiB: 16,
    batchTimeout: '1s',
    sendBatchSize: 16,
    sendBatchMaxSize: 32,
    approvedSinkEndpoint: 'https://telemetry.invalid',
    exportConsumers: 1,
    exportQueueSize: 64,
    retryInitialInterval: '1s',
    retryMaxInterval: '2s',
    retryMaxElapsedTime: '10s',
    metricExpiration: '1m',
  };
  const telemetry = renderTelemetry(
    telemetrySchema,
    authority.telemetry.templateBytes.toString(),
    telemetryInput,
  );
  const envelope = (name) => ({
    cpuRequest: '500m',
    cpuLimit: '1',
    memoryRequest: '64Mi',
    memoryLimit: '128Mi',
    ephemeralStorageRequest: '32Mi',
    ephemeralStorageLimit: '64Mi',
    qualificationRef: qualification(name),
  });
  const input = {
    schemaVersion: '1.0',
    profile: 'test',
    namespace: 'openpc-materialization-test',
    publicDnsName: 'renderer.invalid',
    secretCsiDriver: 'secrets-store.csi.k8s.io',
    images: Object.fromEntries(
      Object.keys(schema.properties.images.properties).map((name) => [
        name,
        `registry.invalid/openpc/${name.toLowerCase()}@${digest}`,
      ]),
    ),
    resources: Object.fromEntries(
      Object.keys(schema.properties.resources.properties).map((name) => [name, envelope(name)]),
    ),
    topology: {
      workbenchReplicas: 1,
      controlReplicas: 1,
      compilerReplicas: 1,
      fleetControlReplicas: 1,
      factBridgeReplicas: 1,
      otelCollectorReplicas: 1,
      terminationGraceSeconds: 30,
      minReadySeconds: 0,
      topologyKey: 'kubernetes.io/hostname',
      qualificationRef: qualification('topology'),
    },
    storage: {
      storageClassName: 'test-storage',
      controlPgBytes: 1048576,
      factPgBytes: 2097152,
      candidateIndexPgBytes: 3145728,
      runtimeArtifactBytes: 4194304,
      runtimeEvidenceBytes: 8388608,
      qualificationRef: qualification('storage'),
    },
    postgresTopology: {
      mode: 'SELF_MANAGED_STATEFULSET',
      controlReplicas: 1,
      factReplicas: 1,
      candidateIndexReplicas: 1,
      runVolumeLimit: '1Mi',
      qualificationRef: qualification('postgres'),
    },
    valkey: {
      enabled: false,
      replicas: 1,
      maxmemory: '32Mi',
      runVolumeLimit: '1Mi',
      secretRef: secret('valkey'),
      qualificationRef: qualification('valkey'),
    },
    secretRefs: Object.fromEntries(
      Object.keys(schema.properties.secretRefs.properties).map((name) => [name, secret(name)]),
    ),
    network: {
      ...Object.fromEntries(
        Object.keys(schema.properties.network.properties).map((name) => [name, profile(name)]),
      ),
      controlPostgresEndpointProfile: 'IN_CLUSTER_SELF_MANAGED',
      factPostgresEndpointProfile: 'IN_CLUSTER_SELF_MANAGED',
      candidateIndexPostgresEndpointProfile: 'IN_CLUSTER_SELF_MANAGED',
      fleetXdsEndpointProfile: 'IN_CLUSTER_MTLS',
      fleetReceiptEndpointProfile: 'IN_CLUSTER_MTLS',
      clientIndexerOrchestratorProfile: 'DISABLED_R1_FUTURE_CONDITIONAL',
      externalDecisionEndpointProfile: 'DISABLED',
      rpcProviderEndpointProfile: 'DISABLED',
      notificationEndpointProfile: 'DISABLED',
    },
    otelConfig: {
      collectorVersion: '0.159.0',
      configMapName: 'openpc-otel-config',
      renderedConfig: telemetry.config,
      renderedConfigDigest: telemetry.digest,
      qualificationRef: qualification('telemetry'),
    },
    protectedTargets: ['alpha', 'beta'].map((name, index) => ({
      targetId: name,
      controllerRef: `${index ? 'StatefulSet' : 'Deployment'}/target-${name}`,
      serviceAccount: `target-${name}`,
      targetImage: `registry.invalid/target/${name}@${digest}`,
      targetResources: envelope(`target-${name}`),
      runtimeCohortDigest: `sha256:${(index ? 'b' : 'a').repeat(64)}`,
      af16EnvoyConfigMap: `envoy-${name}`,
      af16EnvoyBootstrapDigest: digest,
      af17RuntimeContractDigest: digest,
      artifactPvc: `${name}-artifacts`,
      evidencePvc: `${name}-evidence`,
      socketVolumeLimit: '1Mi',
    })),
    qualificationReceiptDigest: digest,
  };
  return { input, telemetryInput };
}

function sources({ input, telemetryInput }) {
  return {
    ...authority,
    inputBytes: bytes(input),
    telemetry: { ...authority.telemetry, inputBytes: bytes(telemetryInput) },
  };
}
function render(value = fixture()) {
  return prepareKubernetesCandidate(sources(value), {
    optionalValkeyCache: value.input.valkey.enabled,
  });
}
function rejects(action, reason) {
  assert.throws(
    action,
    (error) => error instanceof KubernetesMaterializationError && error.reason === reason,
  );
}
function alteredTemplate(value, name, mutate) {
  const input = sources(value);
  const parsed = parseYaml(input.templates[name].toString());
  mutate(parsed);
  input.templates = { ...input.templates, [name]: Buffer.from(encodeYaml(parsed)) };
  return input;
}
function renderAltered(value, name, mutate) {
  return prepareKubernetesCandidate(alteredTemplate(value, name, mutate), {
    optionalValkeyCache: value.input.valkey.enabled,
  });
}

// Archive comparison is run when changed packaged inputs are integrated and at
// final release verification. Ordinary portable CI exercises all renderer paths
// from the shipped inputs; it does not require or reauthenticate external C17.
test(
  'seven packaged inputs and embedded executable Collector template are verbatim C17 product inputs',
  { skip: !c17Root },
  async () => {
    const names = ['materialization-inputs.schema.json', ...templateNames];
    for (const name of names)
      assert.deepEqual(
        await readFile(join(root, 'deploy/kustomize/base', name)),
        await readFile(join(c17Root, 'SPECIFICATIONS/OPERATIONS/kubernetes', name)),
        name,
      );
    for (const name of ['telemetry-materialization.schema.json', 'observability.yaml'])
      assert.deepEqual(
        await readFile(join(root, 'deploy/kustomize/base', name)),
        await readFile(join(c17Root, 'SPECIFICATIONS/OPERATIONS', name)),
        name,
      );
    assert.equal(
      collectorTemplate,
      await readFile(
        join(c17Root, 'SPECIFICATIONS/OPERATIONS/otel-collector-0.159.template.yaml'),
        'utf8',
      ),
    );
  },
);

test('real templates render deterministic typed candidates for multiple protected targets without granting startup', () => {
  const value = fixture();
  const first = render(value),
    second = render(value);
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(first.receipt.state, 'BLOCKED');
  assert.equal(first.receipt.startupAllowed, false);
  assert.equal(first.receipt.claimCeiling, 'MECHANICAL_BINDING_ONLY');
  assert.deepEqual(first.receipt.toolIdentities, {
    node: '24.19.0',
    ajv: '8.20.0',
    yaml: '2.9.0',
    materializer: 'OPENPC_KUBERNETES_CANDIDATE_V1',
  });
  for (const blocker of [
    'CONTROL_LOGICAL_SERVICE_COUNT_CONFLICT',
    'COM_NETWORK_PROFILE_MATERIALIZATION_UNBOUND',
    'KUBERNETES_1_36_2_SERVER_VALIDATION_UNEXECUTED',
    'COLLECTOR_0_159_0_VALIDATION_UNEXECUTED',
  ])
    assert.ok(first.receipt.blockers.includes(blocker), blocker);
  assert.equal(first.receipt.blockers.includes('C17_COMPILER_TMP_NOT_MEMORY_BACKED'), false);
  assert.equal(first.receipt.blockers.includes('C17_RUNTIME_COHORT_LABEL_INVALID'), false);
  const core = parseYaml(first.files['openpc-core.candidate.yaml']);
  assert.equal(core.items.filter((item) => item.kind === 'Deployment').length, 6);
  for (const deployment of core.items.filter((item) => item.kind === 'Deployment')) {
    assert.equal(typeof deployment.spec.replicas, 'number');
    assert.equal(
      typeof deployment.spec.template.spec.containers[0].resources.requests.cpu,
      'string',
    );
    assert.equal(deployment.spec.template.spec.securityContext.runAsUser, 65532);
  }
  const stores = parseYaml(first.files['postgresql-and-valkey.candidate.yaml']);
  assert.equal(stores.items.length, 6);
  const databases = stores.items.filter((item) => item.kind === 'StatefulSet');
  assert.deepEqual(
    databases.map((item) => item.spec.volumeClaimTemplates[0].spec.resources.requests.storage),
    ['1048576', '2097152', '3145728'],
  );
  for (const target of value.input.protectedTargets) {
    const pod = parseYaml(first.files[`target-${target.targetId}.candidate.pod-template.yaml`]);
    assert.equal(pod.metadata.labels['openpc.io/target-id'], target.targetId);
    assert.equal(Object.hasOwn(pod.metadata.labels, 'openpc.io/runtime-cohort'), false);
    assert.equal(pod.metadata.annotations['openpc.io/runtime-cohort'], target.runtimeCohortDigest);
    assert.equal(
      pod.spec.volumes.find((volume) => volume.name === 'runtime-evidence').persistentVolumeClaim
        .claimName,
      target.evidencePvc,
    );
    assert.deepEqual(
      pod.spec.containers.map((container) => container.name),
      ['protected-target', 'openpc-runtime', 'envoy'],
    );
    assert.equal(pod.spec.containers[1].ports, undefined);
    assert.ok(
      pod.spec.containers[1].volumeMounts.some((mount) => mount.mountPath === '/run/openpc'),
    );
  }
  assert.deepEqual(first.receipt.conditionalRemovals, [
    'Service/openpc-valkey',
    'StatefulSet/openpc-valkey',
  ]);
  assert.equal(JSON.stringify(first.files).includes('OPENPC_INPUT_'), false);
  assert.equal(JSON.stringify(first.files).includes('DU-SUBQUERY'), false);
  assert.equal(JSON.stringify(first.receipt).includes('secret://'), false);
});

test('explicit corrections preserve original source bytes, bounded compiler mounts and full per-target cohort identity', async () => {
  const value = fixture(),
    input = sources(value);
  const originals = Object.fromEntries(
    Object.entries(input.templates).map(([name, bytes]) => [name, Buffer.from(bytes)]),
  );
  const originalCore = parseYaml(input.templates['openpc-core.template.yaml'].toString());
  const sourceCompiler = originalCore.items.find(
    (item) => item.kind === 'Deployment' && item.metadata.name === 'openpc-compiler',
  );
  const originalTarget = parseYaml(
    input.templates['protected-target.pod-template.yaml'].toString(),
  );
  const candidate = prepareKubernetesCandidate(input, { optionalValkeyCache: false });
  for (const [name, original] of Object.entries(originals)) {
    assert.deepEqual(input.templates[name], original);
    assert.deepEqual(await readFile(join(root, 'deploy/kustomize/base', name)), original);
    assert.equal(candidate.receipt.sourceDigests.templates[name], sha256(original));
  }
  const core = parseYaml(candidate.files['openpc-core.candidate.yaml']);
  const compiler = core.items.find(
    (item) => item.kind === 'Deployment' && item.metadata.name === 'openpc-compiler',
  );
  assert.deepEqual(
    compiler.spec.template.spec.volumes.find((volume) => volume.name === 'tmp'),
    {
      name: 'tmp',
      emptyDir: {
        medium: 'Memory',
        sizeLimit: value.input.resources.compiler.ephemeralStorageLimit,
      },
    },
  );
  const container = compiler.spec.template.spec.containers[0];
  assert.deepEqual(
    container.volumeMounts,
    sourceCompiler.spec.template.spec.containers[0].volumeMounts,
  );
  assert.equal(container.resources.requests.memory, value.input.resources.compiler.memoryRequest);
  assert.equal(container.resources.limits.memory, value.input.resources.compiler.memoryLimit);
  assert.equal(
    container.resources.limits['ephemeral-storage'],
    value.input.resources.compiler.ephemeralStorageLimit,
  );
  const corrections = candidate.receipt.mechanicalCorrections;
  assert.equal(corrections.length, 3);
  assert.deepEqual(corrections[0], {
    correction: 'COMPILER_TMP_MEMORY',
    sourceTemplate: 'openpc-core.template.yaml',
    output: 'openpc-core.candidate.yaml',
    resource: 'Deployment/openpc-compiler',
    volume: 'tmp',
    field: 'emptyDir.medium',
    operation: 'ADD',
    value: 'Memory',
    preservedSizeLimit: value.input.resources.compiler.ephemeralStorageLimit,
  });
  for (const [index, target] of value.input.protectedTargets.entries()) {
    const output = `target-${target.targetId}.candidate.pod-template.yaml`;
    const pod = parseYaml(candidate.files[output]);
    assert.equal(pod.metadata.annotations['openpc.io/runtime-cohort'], target.runtimeCohortDigest);
    assert.equal(
      pod.metadata.annotations['openpc.io/runtime-contract-digest'],
      target.af17RuntimeContractDigest,
    );
    assert.equal(
      pod.metadata.annotations['openpc.io/envoy-bootstrap-digest'],
      target.af16EnvoyBootstrapDigest,
    );
    assert.deepEqual(pod.spec.topologySpreadConstraints[0].labelSelector.matchLabels, {
      'app.kubernetes.io/name': 'openpc-protected-target',
      'openpc.io/target-id': target.targetId,
    });
    assert.deepEqual(corrections[index + 1], {
      correction: 'RUNTIME_COHORT_ANNOTATION',
      sourceTemplate: 'protected-target.pod-template.yaml',
      output,
      targetId: target.targetId,
      operation: 'MOVE',
      from: '/metadata/labels/openpc.io~1runtime-cohort',
      path: '/metadata/annotations/openpc.io~1runtime-cohort',
      value: target.runtimeCohortDigest,
    });
  }
  assert.equal(
    originalTarget.metadata.labels['openpc.io/runtime-cohort'],
    'OPENPC_INPUT_RUNTIME_COHORT_DIGEST',
  );
  assert.equal(
    Object.hasOwn(originalTarget.metadata.annotations, 'openpc.io/runtime-cohort'),
    false,
  );
  assert.equal(sourceCompiler.spec.template.spec.volumes[0].emptyDir.medium, undefined);
  for (const [name, contents] of Object.entries(candidate.files))
    assert.equal(candidate.receipt.renderedDigests[name], sha256(Buffer.from(contents)));
  assert.equal(candidate.receipt.renderedTreeDigest, sha256(candidate.receipt.renderedDigests));
});

test('compiler correction rejects altered, duplicate or pre-corrected locations and preserves finite input guards', () => {
  for (const change of [
    (pod) => {
      pod.volumes[0].emptyDir.medium = 'Memory';
    },
    (pod) => {
      pod.volumes[0].emptyDir.medium = 'disk';
    },
    (pod) => {
      pod.volumes.push(structuredClone(pod.volumes[0]));
    },
    (pod) => {
      pod.volumes[0].secret = { secretName: 'forbidden' };
    },
    (pod) => {
      pod.containers[0].volumeMounts[0].mountPath = '/var/tmp';
    },
    (pod) => {
      pod.containers[0].volumeMounts.push({ name: 'tmp', mountPath: '/tmp' });
    },
  ])
    rejects(
      () =>
        renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
          change(
            template.items.find(
              (item) => item.kind === 'Deployment' && item.metadata.name === 'openpc-compiler',
            ).spec.template.spec,
          );
        }),
      'COMPILER_TMP_CORRECTION',
    );
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        template.items.push(
          structuredClone(
            template.items.find(
              (item) => item.kind === 'Deployment' && item.metadata.name === 'openpc-compiler',
            ),
          ),
        );
      }),
    'COMPILER_TMP_CORRECTION',
  );
  const value = fixture();
  value.input.resources.compiler.ephemeralStorageLimit = '0';
  assert.throws(
    () => render(value),
    (error) => error instanceof KubernetesMaterializationError,
  );
});

test('cohort annotation collisions and actual selector/downward-API consumers fail closed', () => {
  for (const annotation of [digest, 'wrong', ''])
    rejects(
      () =>
        renderAltered(fixture(), 'protected-target.pod-template.yaml', (template) => {
          template.metadata.annotations['openpc.io/runtime-cohort'] = annotation;
        }),
      'TARGET_COHORT_CORRECTION',
    );
  for (const change of [
    (template) => {
      template.spec.topologySpreadConstraints[0].labelSelector.matchLabels[
        'openpc.io/runtime-cohort'
      ] = digest;
    },
    (template) => {
      template.spec.topologySpreadConstraints[0].labelSelector.matchExpressions = [
        { key: 'openpc.io/runtime-cohort', operator: 'Exists' },
      ];
    },
    (template) => {
      template.spec.containers[1].env.push({
        name: 'COHORT',
        valueFrom: { fieldRef: { fieldPath: "metadata.labels['openpc.io/runtime-cohort']" } },
      });
    },
  ])
    rejects(
      () => renderAltered(fixture(), 'protected-target.pod-template.yaml', change),
      'TARGET_COHORT_CONSUMER',
    );
});

test('validator rejects omitted or tampered correction results, receipts and duplicate targets', () => {
  const value = fixture(),
    candidate = render(value);
  const rendered = () => ({
    core: parseYaml(candidate.files['openpc-core.candidate.yaml']),
    stores: parseYaml(candidate.files['postgresql-and-valkey.candidate.yaml']),
    targets: value.input.protectedTargets.map((target) =>
      parseYaml(candidate.files[`target-${target.targetId}.candidate.pod-template.yaml`]),
    ),
    configMap: parseYaml(candidate.files['otel-configmap.candidate.yaml']),
    corrections: structuredClone(candidate.receipt.mechanicalCorrections),
  });
  const validate = (r) =>
    validateRendered(r.core, r.stores, r.targets, r.configMap, value.input, r.corrections);
  assert.deepEqual(validate(rendered()), candidate.receipt.blockers);
  for (const mutate of [
    (r) => {
      delete r.corrections;
    },
    (r) => {
      r.corrections.pop();
    },
    (r) => {
      r.corrections[0].value = 'disk';
    },
    (r) => {
      r.corrections[1].value = digest.slice(7);
    },
    (r) => {
      r.corrections[1].output = r.corrections[2].output;
    },
  ]) {
    const r = rendered();
    mutate(r);
    rejects(() => validate(r), 'MECHANICAL_CORRECTION_RECEIPT');
  }
  for (const mutate of [
    (tmp) => {
      delete tmp.emptyDir.medium;
    },
    (tmp) => {
      tmp.emptyDir.medium = '';
    },
    (tmp) => {
      tmp.emptyDir.sizeLimit = '128Mi';
    },
    (tmp) => {
      delete tmp.emptyDir.sizeLimit;
    },
  ]) {
    const r = rendered();
    mutate(
      r.core.items.find(
        (item) => item.kind === 'Deployment' && item.metadata.name === 'openpc-compiler',
      ).spec.template.spec.volumes[0],
    );
    rejects(() => validate(r), 'COMPILER_TMP_CORRECTION');
  }
  for (const mutate of [
    (r) => {
      delete r.targets[0].metadata.annotations['openpc.io/runtime-cohort'];
    },
    (r) => {
      r.targets[0].metadata.annotations['openpc.io/runtime-cohort'] = digest.slice(7);
    },
    (r) => {
      r.targets[0].metadata.annotations['openpc.io/runtime-cohort'] =
        r.targets[1].metadata.annotations['openpc.io/runtime-cohort'];
    },
    (r) => {
      r.targets[0].metadata.labels['openpc.io/runtime-cohort'] = digest;
    },
    (r) => {
      r.targets[1] = structuredClone(r.targets[0]);
    },
  ]) {
    const r = rendered();
    mutate(r);
    rejects(() => validate(r), 'TARGET_COHORT_BINDING');
  }
  const consumer = rendered();
  consumer.targets[0].spec.nodeSelector = { 'openpc.io/runtime-cohort': digest };
  rejects(() => validate(consumer), 'TARGET_COHORT_CONSUMER');
});

test('input property order changes provenance, never rendered bytes or tree identity', () => {
  const value = fixture();
  const first = render(value);
  value.input = Object.fromEntries(Object.entries(value.input).reverse());
  const second = render(value);
  assert.deepEqual(first.files, second.files);
  assert.equal(first.receipt.renderedTreeDigest, second.receipt.renderedTreeDigest);
  assert.notEqual(first.receipt.sourceDigests.input, second.receipt.sourceDigests.input);
  for (const [name, contents] of Object.entries(first.files))
    assert.equal(first.receipt.renderedDigests[name], sha256(Buffer.from(contents)));
});

test('Valkey requires matching explicit feature input and remains optional/disposable', () => {
  const value = fixture();
  value.input.valkey.enabled = true;
  rejects(
    () => prepareKubernetesCandidate(sources(value), { optionalValkeyCache: false }),
    'VALKEY_FLAG_MISMATCH',
  );
  const candidate = render(value);
  assert.deepEqual(candidate.receipt.conditionalRemovals, []);
  const stores = parseYaml(candidate.files['postgresql-and-valkey.candidate.yaml']);
  assert.equal(stores.items.length, 8);
  const container = stores.items.find(
    (item) => item.kind === 'StatefulSet' && item.metadata.name === 'openpc-valkey',
  ).spec.template.spec.containers[0];
  assert.deepEqual(container.args.slice(0, 8), [
    '/openpc/valkey-start',
    '--tls-only',
    '--appendonly',
    'no',
    '--save',
    '',
    '--maxmemory',
    '32Mi',
  ]);
  assert.equal(container.args.at(-1), 'allkeys-lfu');
  assert.equal(candidate.receipt.startupAllowed, false);
});

test('Valkey materialization rejects caller overrides of the closed disposable cache profile', () => {
  for (const override of [
    { maxmemoryPolicy: 'noeviction' },
    { ttlMs: 0 },
    { persistence: true },
    { authoritative: true },
    { successGrantCaching: true },
  ]) {
    const value = fixture();
    Object.assign(value.input.valkey, { enabled: true }, override);
    rejects(() => render(value), 'INPUT_SCHEMA');
  }
});

test('managed PostgreSQL omits all self-managed writer objects and requires exact endpoint dispositions', () => {
  const value = fixture();
  value.input.postgresTopology.mode = 'EXACT_MANAGED_SERVICE_PROFILE';
  rejects(() => render(value), 'POSTGRES_TOPOLOGY_MISMATCH');
  for (const key of [
    'controlPostgresEndpointProfile',
    'factPostgresEndpointProfile',
    'candidateIndexPostgresEndpointProfile',
  ])
    value.input.network[key] = profile(key);
  const candidate = render(value);
  assert.deepEqual(parseYaml(candidate.files['postgresql-and-valkey.candidate.yaml']).items, []);
  assert.equal(candidate.receipt.conditionalRemovals.length, 8);
});

test('closed input rejects unknown keys, implicit types, image tags, secret bytes and incomplete authority references', () => {
  const cases = [
    (input) => {
      input.startupAllowed = true;
    },
    (input) => {
      input.images.control = 'registry.invalid/openpc/control:latest';
    },
    (input) => {
      input.images.control = `registry.invalid/openpc/control:tag@${digest}`;
    },
    (input) => {
      input.secretRefs.controlPostgres = 'password-secret-bytes';
    },
    (input) => {
      input.secretRefs.controlPostgres = 'secret://test-fixture/control';
    },
    (input) => {
      input.resources.control.cpuLimit = 1;
    },
    (input) => {
      input.topology.controlReplicas = '1';
    },
    (input) => {
      input.protectedTargets = [];
    },
    (input) => {
      delete input.qualificationReceiptDigest;
    },
    (input) => {
      input.network.clientIndexerOrchestratorProfile = profile('subquery');
    },
    (input) => {
      input.otelConfig.collectorVersion = 'latest';
    },
  ];
  for (const mutate of cases) {
    const value = fixture();
    mutate(value.input);
    rejects(() => render(value), 'INPUT_SCHEMA');
  }
});

test('strict JSON rejects duplicates, unsafe integers, invalid UTF-8, BOM and indirection keys', () => {
  for (const input of [
    Buffer.from('{"a":1,"a":2}'),
    Buffer.from('{"a":9007199254740993}'),
    Buffer.from('{"__proto__":{}}'),
    Buffer.from([0xff]),
    Buffer.from('{"a":-0}'),
  ])
    rejects(() => parseInput(input), 'INPUT_JSON');
  rejects(() => parseInput(Buffer.from('\uFEFF{}')), 'INPUT_BOM');
  rejects(() => parseInput(Buffer.alloc(2 ** 20 + 1)), 'INPUT_SIZE');
});

test('quantities compare decimal/milli/binary values without float rounding or overflow', () => {
  assert.equal(quantity('500m', 'cpu'), quantity('0.5', 'cpu'));
  assert.equal(quantity('1Gi'), quantity('1024Mi'));
  assert.equal(quantity('1000m'), quantity('1'));
  assert.equal(quantity('0.0000000001'), 1n);
  assert.ok(quantity('9007199254740993') > quantity('9007199254740992'));
  for (const value of ['0', '-1', '1e9', '1.1Gi', '1G', 'NaN', 'Infinity', '1 Mi'])
    rejects(() => quantity(value), 'QUANTITY_SYNTAX');
  for (const value of ['0.000', '9223372036854775808', '99999999999999999999Ti'])
    rejects(() => quantity(value), 'QUANTITY_RANGE');
  for (const value of ['1Mi', '0.0001']) rejects(() => quantity(value, 'cpu'), 'CPU_QUANTITY');
  for (const field of ['cpu', 'memory', 'ephemeralStorage']) {
    const value = fixture();
    value.input.resources.control[`${field}Request`] = field === 'cpu' ? '2' : '1Gi';
    rejects(() => render(value), 'RESOURCE_REQUEST_EXCEEDS_LIMIT');
  }
  const value = fixture();
  value.input.valkey.maxmemory = '1Gi';
  rejects(() => render(value), 'VALKEY_MEMORY_EXCEEDS_LIMIT');
});

test('owner collisions cannot alias credentials, targets, controllers or artifact/evidence volumes', () => {
  const cases = [
    [
      'STORE_CREDENTIAL_ALIAS',
      (input) => {
        input.secretRefs.factPostgres = input.secretRefs.controlPostgres;
      },
    ],
    [
      'STORE_VOLUME_ALIAS',
      (input) => {
        input.protectedTargets[0].evidencePvc = input.protectedTargets[0].artifactPvc;
      },
    ],
    [
      'STORE_VOLUME_ALIAS',
      (input) => {
        input.protectedTargets[1].artifactPvc = input.protectedTargets[0].evidencePvc;
      },
    ],
    [
      'TARGET_ID_COLLISION',
      (input) => {
        input.protectedTargets[1].targetId = input.protectedTargets[0].targetId;
      },
    ],
    [
      'TARGET_CONTROLLER_COLLISION',
      (input) => {
        input.protectedTargets[1].controllerRef = input.protectedTargets[0].controllerRef;
      },
    ],
    [
      'TARGET_CONTROLLER_COLLISION',
      (input) => {
        input.protectedTargets[0].controllerRef = 'Deployment/openpc-control';
      },
    ],
    [
      'REFERENCE_PATH',
      (input) => {
        input.secretRefs.controlPostgres = secret('control/../fact');
      },
    ],
    [
      'IMAGE_PATH',
      (input) => {
        input.images.control = `registry.invalid/../control@${digest}`;
      },
    ],
  ];
  for (const [reason, mutate] of cases) {
    const value = fixture();
    mutate(value.input);
    rejects(() => render(value), reason);
  }
});

test('telemetry is governed by canonical pointers and cross constraints with byte-exact ConfigMap projection', () => {
  const value = fixture(),
    candidate = render(value);
  const collector = candidate.files['otel-collector.candidate.yaml'];
  const configMap = parseYaml(candidate.files['otel-configmap.candidate.yaml']);
  assert.equal(configMap.data['observability.yaml'], collector);
  assert.equal(sha256(Buffer.from(collector)), value.input.otelConfig.renderedConfigDigest);
  assert.equal(collector.endsWith('\n'), false);
  const parsed = parseYaml(collector);
  assert.equal(parsed.processors.memory_limiter.limit_mib, 128);
  assert.equal(parsed.exporters['otlp/approved_sink'].endpoint, 'https://telemetry.invalid');
  assert.equal(parsed.exporters['otlp/approved_sink'].tls.insecure, false);
  assert.equal(
    parsed.receivers.otlp.protocols.grpc.tls.key_file,
    '/run/openpc/secrets/otel-server/tls.key',
  );
  assert.equal(collector.includes(digest), false);
  assert.equal(candidate.receipt.telemetryBindings.length, 12);
  const cases = [
    (input) => {
      input.memorySpikeLimitMiB = input.memoryLimitMiB;
    },
    (input) => {
      input.sendBatchSize = input.sendBatchMaxSize + 1;
    },
    (input) => {
      input.exportQueueSize = input.sendBatchMaxSize - 1;
    },
    (input) => {
      input.retryInitialInterval = '3s';
    },
    (input) => {
      input.retryMaxInterval = '1m';
    },
  ];
  for (const mutate of cases) {
    const failed = fixture();
    mutate(failed.telemetryInput);
    rejects(() => render(failed), 'TELEMETRY_CROSS_CONSTRAINT');
  }
});

test('arbitrary Collector YAML, wrong digests, insecure endpoints, credentials and qualification substitutions fail', () => {
  for (const mutate of [
    (value) => {
      value.input.otelConfig.renderedConfig += '\nsecret: exposed';
    },
    (value) => {
      value.input.otelConfig.renderedConfigDigest = `sha256:${'b'.repeat(64)}`;
    },
    (value) => {
      value.input.otelConfig.qualificationRef = `qualification://test-fixture/telemetry@sha256:${'b'.repeat(64)}`;
    },
  ]) {
    const value = fixture();
    mutate(value);
    rejects(() => render(value), 'TELEMETRY_BINDING_MISMATCH');
  }
  for (const endpoint of [
    'http://telemetry.invalid',
    'https://name:password@telemetry.invalid',
    'https://telemetry.invalid/?token=secret',
  ]) {
    const value = fixture();
    value.telemetryInput.approvedSinkEndpoint = endpoint;
    rejects(() => render(value), 'INPUT_SCHEMA');
  }
  const value = fixture();
  value.telemetryInput.approvedSinkEndpoint = 'https://telemetry.invalid:99999';
  rejects(() => render(value), 'TELEMETRY_ENDPOINT');
  const absent = sources(fixture());
  delete absent.telemetry;
  rejects(
    () => prepareKubernetesCandidate(absent, { optionalValkeyCache: false }),
    'TELEMETRY_CONTRACT_UNBOUND',
  );
  const wrongCatalogue = sources(fixture());
  const catalogue = parseYaml(wrongCatalogue.telemetry.observabilityBytes.toString());
  catalogue.collector.upstreamVersion = '0.160.0';
  wrongCatalogue.telemetry.observabilityBytes = Buffer.from(encodeYaml(catalogue));
  rejects(
    () => prepareKubernetesCandidate(wrongCatalogue, { optionalValkeyCache: false }),
    'TELEMETRY_CATALOGUE_IDENTITY',
  );
});

test('unknown, missing, ambiguous, unresolved and embedded bindings cannot be silently accepted', () => {
  const value = fixture();
  rejects(
    () =>
      renderAltered(value, 'openpc-core.template.yaml', (template) => {
        template.metadata.annotations.extra = 'OPENPC_INPUT_UNDECLARED';
      }),
    'BINDING_UNKNOWN',
  );
  rejects(
    () =>
      renderAltered(value, 'otel-configmap.template.yaml', (template) => {
        delete template.metadata.annotations['openpc.io/qualification-receipt-digest'];
        delete template.data['observability.yaml'];
      }),
    'BINDING_UNUSED',
  );
  rejects(
    () =>
      renderAltered(value, 'openpc-core.template.yaml', (template) => {
        template.metadata.annotations.extra = 'prefix-OPENPC_INPUT_PROFILE';
      }),
    'BINDING_EMBEDDED',
  );
  const input = sources(value),
    changed = structuredClone(schema);
  changed['x-openpc-tokenBindingRules'].direct.OPENPC_INPUT_IMAGES_CONTROL = {
    pointer: '/images/control',
    serialization: 'YAML_STRING',
  };
  input.schemaBytes = bytes(changed);
  rejects(
    () => prepareKubernetesCandidate(input, { optionalValkeyCache: false }),
    'BINDING_AMBIGUOUS',
  );
  delete changed['x-openpc-tokenBindingRules'].direct.OPENPC_INPUT_IMAGES_CONTROL;
  changed['x-openpc-tokenBindingRules'].direct.OPENPC_INPUT_NAMESPACE.pointer = '/unknown';
  input.schemaBytes = bytes(changed);
  rejects(
    () => prepareKubernetesCandidate(input, { optionalValkeyCache: false }),
    'BINDING_POINTER',
  );
});

test('YAML parser rejects duplicate keys, aliases, tags, merges and complex keys', () => {
  for (const source of [
    'a: 1\na: 2',
    'a: &x [1]\nb: *x',
    'a: !!str secret',
    'a: {<<: {key: value}}',
    '? [a, b]\n: value',
  ])
    assert.throws(() => parseYaml(source), KubernetesMaterializationError);
});

test('rendered security regressions reject root, writable roots, capabilities, host resources and secret objects', () => {
  const changes = [
    [
      'POD_SECURITY',
      (pod) => {
        pod.spec.securityContext.runAsUser = 0;
      },
    ],
    [
      'POD_SECURITY',
      (pod) => {
        pod.spec.hostNetwork = true;
      },
    ],
    [
      'POD_SECURITY',
      (pod) => {
        pod.spec.automountServiceAccountToken = true;
      },
    ],
    [
      'CONTAINER_SECURITY',
      (pod) => {
        pod.spec.containers[0].securityContext.readOnlyRootFilesystem = false;
      },
    ],
    [
      'CONTAINER_SECURITY',
      (pod) => {
        pod.spec.containers[0].securityContext.capabilities.add = ['NET_ADMIN'];
      },
    ],
    [
      'VOLUME_SECURITY',
      (pod) => {
        pod.spec.volumes[0] = { name: 'tmp', hostPath: { path: '/' } };
      },
    ],
    [
      'CONTAINER_PORT',
      (pod) => {
        pod.spec.containers[0].ports[0].hostPort = 8443;
      },
    ],
    [
      'MOUNT_SECURITY',
      (pod) => {
        pod.spec.containers[0].volumeMounts[0].mountPath = '/';
      },
    ],
  ];
  for (const [reason, mutate] of changes)
    rejects(
      () =>
        renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
          mutate(template.items.find((item) => item.kind === 'Deployment').spec.template);
        }),
      reason,
    );
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        template.items.push({
          apiVersion: 'v1',
          kind: 'Secret',
          metadata: { name: 'inline' },
          stringData: { password: 'secret' },
        });
      }),
    'CORE_OBJECT_TOPOLOGY',
  );
});

test('actual unit consumers cannot exchange database credentials, CSI owners or storage ownership', () => {
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        const pod = template.items.find(
          (item) => item.metadata.name === 'openpc-control' && item.kind === 'Deployment',
        ).spec.template;
        pod.spec.containers[0].env[1].value = 'OPENPC_INPUT_SECRETREFS_FACT_POSTGRES';
      }),
    'CONSUMER_ENVIRONMENT',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        const pod = template.items.find(
          (item) => item.metadata.name === 'openpc-control' && item.kind === 'Deployment',
        ).spec.template;
        pod.spec.volumes[1].csi.volumeAttributes.secretProviderClass = 'openpc-fact-bridge';
      }),
    'CSI_OWNER_BINDING',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'postgresql-and-valkey.template.yaml', (template) => {
        template.items.find((item) => item.kind === 'StatefulSet').spec.template.metadata.labels[
          'openpc.io/store'
        ] = 'STORE-FACT-PG';
      }),
    'STORE_OWNER_BINDING',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'postgresql-and-valkey.template.yaml', (template) => {
        template.items.find(
          (item) => item.kind === 'StatefulSet',
        ).spec.volumeClaimTemplates[0].spec.accessModes = ['ReadWriteMany'];
      }),
    'STORE_PVC_BINDING',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        const pod = template.items.find((item) => item.kind === 'Deployment').spec.template;
        pod.spec.containers[0].env.push({ name: 'PASSWORD', value: 'inline-secret' });
      }),
    'CONSUMER_ENVIRONMENT',
  );
});

test('topology rejects undeclared network edges, public admin services and Runtime TCP or custody sharing', () => {
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        template.items.find((item) => item.kind === 'NetworkPolicy').spec.egress = [{}];
      }),
    'NETWORK_POLICY',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'openpc-core.template.yaml', (template) => {
        template.items.find((item) => item.kind === 'Service').spec.ports[0].port = 9901;
      }),
    'SERVICE_EXPOSURE',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'protected-target.pod-template.yaml', (template) => {
        template.spec.containers[1].ports = [{ containerPort: 8443 }];
      }),
    'RUNTIME_UDS_BOUNDARY',
  );
  rejects(
    () =>
      renderAltered(fixture(), 'protected-target.pod-template.yaml', (template) => {
        template.spec.containers[2].volumeMounts.push({
          name: 'runtime-evidence',
          mountPath: '/var/lib/openpc/evidence',
        });
      }),
    'RUNTIME_UDS_BOUNDARY',
  );
});

test('entrypoint writes a private blocked candidate bundle and never overwrites output', async (context) => {
  const directory = await mkdtemp(join(scratchRoot, 'kubernetes-materialization-'));
  context.after(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  await chmod(directory, 0o700);
  const value = fixture();
  const inputPath = join(directory, 'input.json'),
    telemetryInputPath = join(directory, 'telemetry.json');
  await writeFile(inputPath, bytes(value.input), { mode: 0o600 });
  await writeFile(telemetryInputPath, bytes(value.telemetryInput), { mode: 0o600 });
  const output = join(directory, 'candidate.json');
  const loaded = await loadKubernetesSources({ inputPath, telemetryInputPath });
  assert.deepEqual(
    prepareKubernetesCandidate(loaded, { optionalValkeyCache: false }),
    render(value),
  );
  const compared = await loadKubernetesSources({ inputPath, telemetryInputPath, c17Root });
  assert.deepEqual(compared, loaded);
  const result = await materializeKubernetes([
    '--input',
    inputPath,
    '--telemetry-input',
    telemetryInputPath,
    '--optional-valkey-cache',
    'false',
    '--output',
    output,
  ]);
  assert.equal(result.exitCode, 2);
  assert.equal(result.result.startupAllowed, false);
  assert.equal((await lstat(output)).mode & 0o777, 0o400);
  assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), render(value));
  const original = await readFile(output);
  await assert.rejects(writeKubernetesCandidate(render(value), output), { code: 'EEXIST' });
  assert.deepEqual(await readFile(output), original);
  const forged = render(value);
  forged.receipt.startupAllowed = true;
  await assert.rejects(
    writeKubernetesCandidate(forged, join(directory, 'forged.json')),
    (error) => error.reason === 'CANDIDATE_CLAIM',
  );
  await symlink(output, join(directory, 'link.json'));
  await assert.rejects(writeKubernetesCandidate(render(value), join(directory, 'link.json')));
  await chmod(directory, 0o755);
  await assert.rejects(
    writeKubernetesCandidate(render(value), join(directory, 'shared.json')),
    (error) => error.reason === 'OUTPUT_DIRECTORY_UNSAFE',
  );
  await chmod(directory, 0o700);
});

test('optional original-byte verification fails on drift without becoming a rendering dependency', async (context) => {
  const directory = await mkdtemp(join(scratchRoot, 'kubernetes-c17-comparison-'));
  context.after(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  const inputPath = join(directory, 'input.json'),
    telemetryInputPath = join(directory, 'telemetry.json');
  const value = fixture();
  await writeFile(inputPath, bytes(value.input), { mode: 0o600 });
  await writeFile(telemetryInputPath, bytes(value.telemetryInput), { mode: 0o600 });
  const originals = join(directory, 'SPECIFICATIONS/OPERATIONS/kubernetes');
  await mkdir(originals, { recursive: true });
  await writeFile(join(originals, 'materialization-inputs.schema.json'), '{}', { mode: 0o600 });
  await assert.rejects(
    loadKubernetesSources({ inputPath, telemetryInputPath, c17Root: directory }),
    (error) => error.reason === 'C17_PACKAGED_INPUT_DRIFT',
  );
  await assert.rejects(
    loadKubernetesSources({ inputPath, telemetryInputPath, c17Root: './relative' }),
    (error) => error.reason === 'C17_INPUT_BINDING',
  );
  const packaged = await loadKubernetesSources({ inputPath, telemetryInputPath });
  assert.equal(
    prepareKubernetesCandidate(packaged, { optionalValkeyCache: false }).receipt.startupAllowed,
    false,
  );
});

test('entrypoint requires explicit paths and feature input, rejects trust/apply switches, and has no environment fallback', () => {
  for (const args of [
    [],
    ['--input', 'a'],
    ['--apply'],
    ['--startup-allowed', 'true'],
    ['--input', 'a', '--input', 'b'],
    ['--input', '--output'],
  ])
    rejects(() => parseKubernetesArguments(args), 'ARGUMENT');
  const input = sources(fixture());
  rejects(
    () => prepareKubernetesCandidate(input, { optionalValkeyCache: false, verified: true }),
    'RENDER_OPTIONS',
  );
  rejects(
    () => prepareKubernetesCandidate(input, { optionalValkeyCache: 'false' }),
    'VALKEY_FLAG_MISMATCH',
  );
});
