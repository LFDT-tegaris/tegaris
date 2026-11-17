import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { after, before, describe } from 'node:test';
import {
  InstallationConfigError,
  parseConfigurationJson,
  parseNamedProfile,
} from './installation-config-inputs.mjs';
import { prepareInstallationPreflight } from './installation-preflight.mjs';
import { checkRenderedCompose, renderedMounts } from './installation-preflight-checks.mjs';

// Synthetic observations exercise structural checks only. The separate native-render
// suite remains mandatory in an unfiltered run; its hooks never own the pure selection.
const root = fileURLToPath(new URL('../../', import.meta.url));
const services = ['fact-pg', 'fact-migrate', 'fact-service'];
const encode = (value) => Buffer.from(JSON.stringify(value));

// Schema/profile bytes are public source inputs, not observed runtime or secret state.
async function configurationSources() {
  const schemaBytes = await readFile(
    join(root, 'config/schema/effective-configuration.schema.json'),
  );
  const profileBytes = await readFile(join(root, 'config/profiles/local.yaml'));
  const schema = parseConfigurationJson(schemaBytes);
  const namedProfile = parseNamedProfile(profileBytes);
  const ref = (name) => `secret://${namedProfile.secretProvider.providerId}/${name}#v1`;
  return {
    schema,
    schemaBytes,
    profileBytes,
    namedProfile,
    profile: 'local',
    environment: {},
    site: {
      environmentId: 'local',
      publicBaseUrl: 'https://localhost:8443',
      generation: {
        generationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000002',
        baseGenerationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000001',
        contentDigest: `sha256:${'a'.repeat(64)}`,
      },
      postgres: {
        controlDsnSecretRef: ref('control'),
        factsDsnSecretRef: ref('facts'),
        candidateIndexDsnSecretRef: ref('candidate'),
      },
      identity: {
        oidcIssuer: 'https://localhost:8443/oidc',
        clientId: 'synthetic-client',
        clientSecretRef: ref('oidc'),
        scimEnabled: false,
      },
      pki: { trustBundleSecretRef: ref('trust'), signingKeySecretRef: ref('signing') },
      telemetry: { otlpEndpoint: 'grpc://localhost:4317' },
      qualificationInputBindings: Object.fromEntries(
        Object.keys(namedProfile.requiredSettingInputs).map((key) => [
          key,
          `qualification://local/${key}@sha256:${'b'.repeat(64)}`,
        ]),
      ),
      settings: {
        'ui.export_row_limit': 1,
        'runtime.local_artifact_capacity': 1048576,
        'runtime.decision_deadline': '1ms',
        'evidence.local_spool_capacity': 1,
        'evidence.retention_profile': `profile://local/retention@sha256:${'c'.repeat(64)}`,
        'provider.read_retry_limit': 0,
        'facts.maximum_staleness': '1ms',
        'facts.reorg_retained_tail': 1,
        'module.allowed_publishers': `publisher-set://local/modules@sha256:${'d'.repeat(64)}`,
        'module.ui_slot_budget': 0,
      },
    },
  };
}

function syntheticCoreCompose(secretRoot = '/synthetic-observations/secrets') {
  return {
    name: 'openpc-installation-preflight',
    services: {
      'control-api': {
        image: 'openpc-r1-dev/control-api:local',
        platform: 'linux/amd64',
        read_only: true,
        mem_limit: 805306368,
        cpus: 0.75,
        pids_limit: 256,
        environment: {
          CONTROL_API_EVIDENCE_ENVIRONMENT_ID: 'local',
          CONTROL_API_DATABASE_USER: 'openpc_configuration_runtime',
          CONTROL_API_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES:
            '/run/secrets/identity_runtime_signing_public_key',
        },
        depends_on: { 'control-migrate': { condition: 'service_completed_successfully' } },
        networks: { 'openpc-local': null },
        secrets: [{ source: 'identity_runtime_signing_public_key' }],
      },
      // Deliberately uninspected: existence/condition is structural, not an admitted
      // dependency closure. The public preflight always retains its runtime blockers.
      'control-migrate': { depends_on: { 'control-pg': { condition: 'service_healthy' } } },
      'control-pg': {},
    },
    networks: { 'openpc-local': { name: 'openpc-installation-preflight_openpc-local' } },
    secrets: {
      identity_runtime_signing_public_key: {
        file: secretRoot + '/identity_runtime_signing_public_key.der',
      },
    },
  };
}

function syntheticImage(compose) {
  const reference = compose.services['control-api'].image;
  return {
    Id: 'sha256:' + '1'.repeat(64),
    Os: 'linux',
    Architecture: 'amd64',
    RepoTags: [reference],
    RepoDigests: [],
    Config: {
      Env: [],
      Cmd: null,
      Entrypoint: null,
      User: '',
      Labels: {
        'io.openpc.image.owner': 'openpc-r1-local-runtime-v1',
        'io.openpc.image.service': 'control-api',
      },
    },
  };
}

function syntheticInput(sources, compose = syntheticCoreCompose()) {
  return {
    preparedConfigurationSources: structuredClone(sources),
    configurationSources: structuredClone(sources),
    preparedComposeBytes: encode(compose),
    currentComposeBytes: encode(compose),
    imageInspectBytes: encode([syntheticImage(compose)]),
    selectedServices: ['control-api'],
    externalMemoryKiB: '786432',
  };
}

function assertBlockedSnapshot(result) {
  assert.equal(result.state, 'BLOCKED');
  assert.equal(result.startupAllowed, false);
  assert.equal(result.structuralState, 'CONSISTENT');
  assert.equal(result.capabilityReadiness, 'UNKNOWN');
  for (const reason of [
    'RUNNER_SOURCE_AND_OBSERVATION_FRESHNESS_UNBOUND',
    'LIVE_RESOURCE_ADMISSION_UNVERIFIED',
    'FILESYSTEM_MOUNT_IDENTITY_UNVERIFIED',
    'DATABASE_ROLE_AND_MIGRATION_READBACK_UNVERIFIED',
    'REQUIRED_EXTERNAL_DEPENDENCIES_UNQUALIFIED',
  ])
    assert.ok(result.blockers.includes(reason));
}

describe('installation preflight pure', () => {
  let sources;
  before(async () => {
    sources = await configurationSources();
  });

  function rejectPure(fn, reason) {
    assert.throws(
      fn,
      (error) =>
        error instanceof InstallationConfigError &&
        error.code === 'OPS_CONFIG_INVALID' &&
        error.reason === reason,
    );
  }

  test('selected subset accounts only inspected services and never establishes readiness', () => {
    const input = syntheticInput(sources);
    const result = prepareInstallationPreflight(input);
    assert.deepEqual(result, prepareInstallationPreflight(input));
    assertBlockedSnapshot(result);
    assert.equal(result.selectedServiceCount, 1);
    assert.equal(result.selectedMemoryBytes, 805306368);
    assert.equal(result.containerBindings, 'UNOBSERVED');
    assert.equal(result.comparedConfigurationFields, 1);
    const missing = syntheticCoreCompose();
    delete missing.services['control-migrate'];
    rejectPure(
      () => prepareInstallationPreflight(syntheticInput(sources, missing)),
      'PREFLIGHT_DEPENDENCY_MISSING',
    );
  });

  test('finite memory caps and the inherited selected envelope fail closed', () => {
    for (const value of [true, false, [1], {}, null, 0, -1, '0', '01', '1e3', 'unlimited']) {
      const compose = syntheticCoreCompose();
      compose.services['control-api'].mem_limit = value;
      rejectPure(
        () => prepareInstallationPreflight(syntheticInput(sources, compose)),
        'PREFLIGHT_RESOURCE_UNBOUNDED',
      );
    }
    for (const value of [NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      const compose = syntheticCoreCompose();
      compose.services['control-api'].mem_limit = value;
      rejectPure(
        () => checkRenderedCompose(compose, ['control-api']),
        'PREFLIGHT_RESOURCE_UNBOUNDED',
      );
    }
    const overflow = syntheticCoreCompose();
    overflow.services['control-api'].mem_limit = Number.MAX_SAFE_INTEGER;
    overflow.services['second-observation'] = structuredClone(overflow.services['control-api']);
    rejectPure(
      () => checkRenderedCompose(overflow, ['control-api', 'second-observation']),
      'PREFLIGHT_RESOURCE_UNBOUNDED',
    );
    rejectPure(
      () =>
        prepareInstallationPreflight({ ...syntheticInput(sources), externalMemoryKiB: '786431' }),
      'PREFLIGHT_RESOURCE_ENVELOPE_EXCEEDED',
    );
    rejectPure(
      () =>
        prepareInstallationPreflight({ ...syntheticInput(sources), externalMemoryKiB: undefined }),
      'PREFLIGHT_RESOURCE_BINDING_MISSING',
    );
  });

  test('exact external image digest and prepared render drift cannot be substituted', () => {
    const compose = syntheticCoreCompose();
    const reference = 'registry.example.invalid/control-api@sha256:' + 'a'.repeat(64);
    compose.services['control-api'].image = reference;
    const input = syntheticInput(sources, compose);
    const image = syntheticImage(compose);
    image.RepoTags = [];
    image.RepoDigests = [reference];
    input.imageInspectBytes = encode([image]);
    assertBlockedSnapshot(prepareInstallationPreflight(input));
    image.RepoDigests = ['registry.example.invalid/control-api@sha256:' + 'b'.repeat(64)];
    input.imageInspectBytes = encode([image]);
    rejectPure(() => prepareInstallationPreflight(input), 'PREFLIGHT_IMAGE_UNBOUND');

    const changed = syntheticInput(sources);
    const current = syntheticCoreCompose();
    current.services['control-api'].mem_limit += 1024;
    changed.currentComposeBytes = encode(current);
    rejectPure(
      () => prepareInstallationPreflight(changed),
      'PREFLIGHT_SERVICE_CONFIGURATION_CHANGED',
    );
  });

  test('synthetic container consistency remains blocked and stale image evidence is rejected', () => {
    const compose = syntheticCoreCompose();
    const input = syntheticInput(sources, compose);
    const service = compose.services['control-api'];
    // Explicit external fixture: these IDs/caps/mounts were never observed from Docker/kernel.
    const container = {
      Id: '2'.repeat(64),
      Image: syntheticImage(compose).Id,
      Config: {
        Env: Object.entries(service.environment).map(([key, value]) => key + '=' + value),
        Cmd: null,
        Entrypoint: null,
        User: '',
        Labels: {
          'com.docker.compose.project': compose.name,
          'com.docker.compose.service': 'control-api',
        },
      },
      HostConfig: {
        Memory: service.mem_limit,
        PidsLimit: service.pids_limit,
        ReadonlyRootfs: true,
        NanoCpus: service.cpus * 1e9,
        Privileged: false,
      },
      NetworkSettings: {
        Networks: { 'openpc-installation-preflight_openpc-local': {} },
      },
      Mounts: [
        {
          Type: 'bind',
          Destination: '/run/secrets/identity_runtime_signing_public_key',
          Source: '/synthetic-observations/secrets/identity_runtime_signing_public_key.der',
          RW: false,
        },
      ],
    };
    input.containerInspectBytes = encode([container]);
    const result = prepareInstallationPreflight(input);
    assertBlockedSnapshot(result);
    assert.equal(result.containerBindings, 'CONSISTENT_SNAPSHOT');
    container.Image = 'sha256:' + 'f'.repeat(64);
    input.containerInspectBytes = encode([container]);
    rejectPure(() => prepareInstallationPreflight(input), 'PREFLIGHT_STALE_IMAGE_OBSERVATION');
  });
});

describe('installation preflight native render', () => {
  let scratch;
  let rendered;
  let sources;

  before(async () => {
    assert.ok(process.env.OPENPC_PNC_TMP_ROOT, 'Bind the existing external test scratch root');
    scratch = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'installation-preflight-'));
    sources = await configurationSources();
    const environment = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !key.startsWith('OPENPC_')),
    );
    Object.assign(environment, {
      OPENPC_LOCAL_DATA_ROOT: join(scratch, 'data'),
      OPENPC_LOCAL_SECRET_ROOT: join(scratch, 'secrets'),
      // Render-only external fixture: no network allocation, ownership or live admission.
      OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET: '192.0.2.0/24',
      OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY: '192.0.2.1',
      OPENPC_LOCAL_RUNTIME_NETWORK_OWNER: `render-only-${scratch.split('/').at(-1)}`,
      OPENPC_LOCAL_RUNTIME_NETWORK_ROOT: scratch,
    });
    const result = spawnSync(
      'docker',
      [
        'compose',
        '--project-name',
        'openpc-installation-preflight',
        '--env-file',
        '/dev/null',
        '-f',
        join(root, 'deploy/compose/local/compose.yaml'),
        'config',
        '--format',
        'json',
      ],
      { cwd: root, env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 },
    );
    // Never print native stderr: a future render error could include a substituted environment value.
    assert.equal(result.status, 0, 'The original Compose owner must render successfully');
    rendered = JSON.parse(result.stdout);
  });
  after(async () => {
    if (scratch) await rm(scratch, { recursive: true });
  });

  function inspectionFixture(compose = rendered, selection = services) {
    return [...new Set(selection.map((name) => compose.services[name].image))].map(
      (reference, index) => {
        const stable = /^openpc-r1-dev\/([^:]+):local$/u.exec(reference);
        return {
          Id: `sha256:${String(index + 1).padStart(64, '0')}`,
          Os: 'linux',
          Architecture: 'amd64',
          RepoTags: stable ? [reference] : [],
          // Docker records the repository digest without its input tag/default registry prefix.
          RepoDigests: stable
            ? []
            : [reference.replace(/^docker\.io\/library\//u, '').replace(/:[^/@]+@/u, '@')],
          Config: {
            Env: ['PATH=/usr/local/bin:/usr/bin:/bin'],
            Cmd: null,
            Entrypoint: null,
            User: '',
            Labels: stable
              ? {
                  'io.openpc.image.owner': 'openpc-r1-local-runtime-v1',
                  'io.openpc.image.service': stable[1],
                }
              : {},
          },
        };
      },
    );
  }

  function fixture(selection = services) {
    return {
      preparedConfigurationSources: structuredClone(sources),
      configurationSources: structuredClone(sources),
      preparedComposeBytes: encode(rendered),
      currentComposeBytes: encode(rendered),
      imageInspectBytes: encode(inspectionFixture(rendered, selection)),
      selectedServices: [...selection],
      externalMemoryKiB: String(9 * 1024 * 1024),
    };
  }
  function changeRender(input, mutate, both = false) {
    const current = JSON.parse(input.currentComposeBytes);
    mutate(current);
    input.currentComposeBytes = encode(current);
    if (both) input.preparedComposeBytes = encode(current);
    return input;
  }
  function reject(fn, reason) {
    assert.throws(
      fn,
      (error) =>
        error instanceof InstallationConfigError &&
        error.code === 'OPS_CONFIG_INVALID' &&
        (!reason || error.reason === reason),
    );
  }
  function containersFixture(compose, selection, images) {
    return selection.map((name, index) => {
      const service = compose.services[name];
      const stable = service.image.startsWith('openpc-r1-dev/');
      const image = images.find((item) =>
        stable
          ? item.RepoTags.includes(service.image)
          : item.RepoDigests.some((ref) => service.image.endsWith(ref.split('@')[1])),
      );
      const env = { PATH: '/usr/local/bin:/usr/bin:/bin', ...service.environment };
      return {
        Id: String(index + 10).padStart(64, '0'),
        Image: image.Id,
        Config: {
          Env: Object.entries(env).map(([key, value]) => `${key}=${value}`),
          Cmd: service.command ?? null,
          Entrypoint: service.entrypoint ?? null,
          User: service.user ?? '',
          Labels: {
            'com.docker.compose.project': compose.name,
            'com.docker.compose.service': name,
          },
        },
        HostConfig: {
          Memory: Number(service.mem_limit),
          PidsLimit: Number(service.pids_limit),
          ReadonlyRootfs: service.read_only === true,
          NanoCpus: Number(service.cpus) * 1e9,
          Privileged: false,
          SecurityOpt: service.security_opt ?? [],
          CapAdd: service.cap_add ?? [],
        },
        NetworkSettings: {
          Networks: Object.fromEntries(
            Object.keys(service.networks).map((key) => [
              compose.networks[key].name,
              { NetworkID: 'e'.repeat(64) },
            ]),
          ),
        },
        Mounts: [...renderedMounts(compose, name)].map(([target, mount]) => ({
          Type: mount.type,
          Destination: target,
          RW: !mount.readOnly,
          ...(mount.type === 'bind' ? { Source: mount.source } : { Name: mount.source }),
        })),
        State: { Status: 'exited', Running: false },
      };
    });
  }
  function withContainers(input) {
    input.containerInspectBytes = encode(
      containersFixture(
        JSON.parse(input.currentComposeBytes),
        input.selectedServices,
        JSON.parse(input.imageInspectBytes),
      ),
    );
    return input;
  }

  test('actual rendered local Fact slice is structurally consistent, deterministic and never startup-ready', () => {
    const input = fixture();
    const first = prepareInstallationPreflight(input);
    assert.deepEqual(first, prepareInstallationPreflight(input));
    assert.equal(first.structuralState, 'CONSISTENT');
    assert.equal(first.state, 'BLOCKED');
    assert.equal(first.startupAllowed, false);
    assert.equal(first.capabilityReadiness, 'UNKNOWN');
    assert.equal(first.selectedServiceCount, 3);
    assert.equal(
      first.selectedMemoryBytes,
      services.reduce((sum, name) => sum + Number(rendered.services[name].mem_limit), 0),
    );
    for (const reason of [
      'SIGNED_SITE_VERIFICATION_UNBOUND',
      'GENERATION_ADMISSION_AND_DIGEST_UNBOUND',
      'SECRET_PROVIDER_RESOLUTION_UNBOUND',
      'ENTRYPOINT_CONSUMER_BINDING_UNBOUND',
      'DATABASE_ROLE_AND_MIGRATION_READBACK_UNVERIFIED',
      'SIGNING_TRUST_EPOCH_AND_REVOCATION_UNVERIFIED',
    ])
      assert.ok(first.blockers.includes(reason));
    assert.equal(first.containerBindings, 'UNOBSERVED');
  });

  test('missing service/dependency and invalid or exceeded selected resource envelope fail closed', () => {
    reject(
      () => prepareInstallationPreflight({ ...fixture(), selectedServices: ['absent'] }),
      'PREFLIGHT_SERVICE_MISSING',
    );
    reject(
      () =>
        prepareInstallationPreflight({
          ...fixture(),
          selectedServices: ['fact-service', 'fact-service'],
        }),
      'PREFLIGHT_COMPOSE_INVALID',
    );
    reject(
      () =>
        prepareInstallationPreflight(
          changeRender(
            fixture(),
            (c) => {
              delete c.services['fact-migrate'];
            },
            true,
          ),
        ),
      'PREFLIGHT_SERVICE_MISSING',
    );
    for (const value of ['0', '-1', 'unlimited', '9007199254740992'])
      reject(
        () =>
          prepareInstallationPreflight(
            changeRender(
              fixture(),
              (c) => {
                c.services['fact-service'].mem_limit = value;
              },
              true,
            ),
          ),
        'PREFLIGHT_RESOURCE_UNBOUNDED',
      );
    reject(
      () => prepareInstallationPreflight({ ...fixture(), externalMemoryKiB: '1' }),
      'PREFLIGHT_RESOURCE_ENVELOPE_EXCEEDED',
    );
    reject(
      () => prepareInstallationPreflight({ ...fixture(), externalMemoryKiB: undefined }),
      'PREFLIGHT_RESOURCE_BINDING_MISSING',
    );
  });

  for (const field of ['mem_limit', 'pids_limit', 'cpus']) {
    test(`native ${field} rejects coercible types and unsupported numeric strings`, () => {
      const invalid = [
        true,
        false,
        [1],
        ['128'],
        [],
        {},
        { value: 1 },
        null,
        0,
        -1,
        '',
        ' ',
        ' 1',
        '1 ',
        '+1',
        '01',
        '0x1',
        '0b1',
        '0o1',
        '1e0',
        'Infinity',
        'NaN',
        ...(field === 'cpus'
          ? [2.01, '2.01', '.5', '1.']
          : [0.5, '0.5', '1.0', '9007199254740992']),
      ];
      for (const value of invalid) {
        const input = withContainers(
          changeRender(
            fixture(),
            (compose) => {
              compose.services['fact-service'][field] = value;
            },
            true,
          ),
        );
        reject(() => prepareInstallationPreflight(input), 'PREFLIGHT_RESOURCE_UNBOUNDED');
      }
      // Strict native JSON rejects unsafe numbers before the resource owner.
      reject(
        () =>
          prepareInstallationPreflight(
            withContainers(
              changeRender(
                fixture(),
                (compose) => {
                  compose.services['fact-service'][field] = Number.MAX_SAFE_INTEGER + 1;
                },
                true,
              ),
            ),
          ),
        'PREFLIGHT_DOCUMENT_INVALID',
      );
      // Exercise the pure resource boundary separately, including numbers that native
      // JSON rejects or JSON.stringify cannot represent faithfully.
      for (const value of [NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
        const compose = structuredClone(rendered);
        compose.services['fact-service'][field] = value;
        reject(() => checkRenderedCompose(compose, services), 'PREFLIGHT_RESOURCE_UNBOUNDED');
      }
    });
  }

  test('bounded numeric and canonical string resources retain consistent snapshots without readiness', () => {
    for (const cpus of [0.25, 1, 2, '0.25', '1', '1.0', '2', '2.000']) {
      for (const strings of [false, true]) {
        const input = withContainers(
          changeRender(
            fixture(),
            (compose) => {
              const service = compose.services['fact-service'];
              service.mem_limit = strings ? '134217728' : 134217728;
              service.pids_limit = strings ? '128' : 128;
              service.cpus = cpus;
            },
            true,
          ),
        );
        const result = prepareInstallationPreflight(input);
        assert.equal(result.structuralState, 'CONSISTENT');
        assert.equal(result.containerBindings, 'CONSISTENT_SNAPSHOT');
        assert.equal(result.state, 'BLOCKED');
        assert.equal(result.startupAllowed, false);
        assert.equal(result.capabilityReadiness, 'UNKNOWN');
      }
    }
  });

  test('exact external digest and stable image ownership/platform are required', () => {
    for (const mutate of [
      (records) => {
        records.find((r) => r.RepoTags.length).Config.Labels['io.openpc.image.owner'] = 'foreign';
      },
      (records) => {
        records.find((r) => r.RepoTags.length).Config.Labels['io.openpc.image.service'] =
          'control-api';
      },
      (records) => {
        records[0].Architecture = 'arm64';
      },
      (records) => {
        records[0].RepoDigests = [`postgres@sha256:${'f'.repeat(64)}`];
      },
      (records) => {
        records[0].Id = 'floating';
      },
      (records) => {
        records.push(structuredClone(records[0]));
      },
    ]) {
      const input = fixture();
      const records = JSON.parse(input.imageInspectBytes);
      mutate(records);
      input.imageInspectBytes = encode(records);
      reject(() => prepareInstallationPreflight(input));
    }
    reject(
      () =>
        prepareInstallationPreflight(
          changeRender(
            fixture(),
            (c) => {
              c.services['fact-pg'].image = 'postgres:latest';
            },
            true,
          ),
        ),
      'PREFLIGHT_FLOATING_IMAGE',
    );
  });

  test('changed config, generation, image, network or mount requires preparation again', () => {
    const generation = fixture();
    generation.configurationSources.site.generation.generationId =
      'urn:openpc:generation:018f0000-0000-7000-8000-000000000003';
    reject(() => prepareInstallationPreflight(generation), 'PREFLIGHT_GENERATION_CHANGED');
    const config = fixture();
    config.configurationSources.site.environmentId = 'other';
    reject(() => prepareInstallationPreflight(config), 'PREFLIGHT_CONFIGURATION_CHANGED');
    for (const mutate of [
      (c) => {
        c.services['fact-service'].environment.OPENPC_FACT_DATABASE_USER = 'other_role';
      },
      (c) => {
        c.services['fact-service'].image = 'openpc-r1-dev/control-worker:local';
      },
      (c) => {
        c.services['fact-service'].volumes[0].source += '-replacement';
      },
      (c) => {
        c.services['fact-service'].volumes[0].read_only = false;
      },
      (c) => {
        c.networks['openpc-local'].internal = true;
      },
      (c) => {
        c.secrets.fact_runtime_db_password.file += '-replacement';
      },
    ])
      reject(() => prepareInstallationPreflight(changeRender(fixture(), mutate)));
  });

  test('unsafe paths, external volumes/networks, duplicate mounts and unmounted credentials are rejected', () => {
    for (const mutate of [
      (c) => {
        c.services['fact-service'].volumes[0].source = '/tmp/../private';
      },
      (c) => {
        c.services['fact-service'].volumes.push(
          structuredClone(c.services['fact-service'].volumes[0]),
        );
      },
      (c) => {
        c.networks['openpc-local'].external = true;
      },
      (c) => {
        c.services['fact-service'].network_mode = 'host';
      },
      (c) => {
        c.secrets.fact_runtime_db_password.environment = 'PRIVATE_SECRET';
      },
      (c) => {
        c.services['fact-service'].environment.OPENPC_FACT_DATABASE_PASSWORD_FILE =
          '/unmounted/secret';
      },
      (c) => {
        c.services['fact-service'].volumes.push({
          type: 'volume',
          source: 'foreign',
          target: '/foreign',
        });
        c.volumes = { foreign: { name: 'foreign', external: true } };
      },
    ])
      reject(() => prepareInstallationPreflight(changeRender(fixture(), mutate, true)));
  });

  test('missing primary role, migration dependency or trust-file binding is a preparation error', () => {
    reject(
      () =>
        prepareInstallationPreflight(
          changeRender(
            fixture(),
            (c) => {
              delete c.services['fact-service'].environment.OPENPC_FACT_DATABASE_USER;
            },
            true,
          ),
        ),
      'PREFLIGHT_ROLE_BINDING_MISSING',
    );
    reject(
      () =>
        prepareInstallationPreflight(
          changeRender(
            fixture(),
            (c) => {
              c.services['fact-service'].depends_on = {};
            },
            true,
          ),
        ),
      'PREFLIGHT_MIGRATION_BINDING',
    );
    reject(
      () =>
        prepareInstallationPreflight(
          changeRender(
            fixture(),
            (c) => {
              delete c.services['fact-service'].environment.OPENPC_FACT_SIGNING_SECRET_FILE;
              delete c.services['fact-service'].environment.OPENPC_FACT_CAPABILITY_SECRET_FILE;
            },
            true,
          ),
        ),
      'PREFLIGHT_TRUST_BINDING_MISSING',
    );
  });

  test('a read-only source replacement works only after matching re-preparation; prior observation stays stale', () => {
    const original = withContainers(fixture());
    const fresh = changeRender(
      fixture(),
      (c) => {
        c.services['fact-service'].volumes[0].source += '-next-generation';
      },
      true,
    );
    assert.equal(prepareInstallationPreflight(fresh).structuralState, 'CONSISTENT');
    fresh.containerInspectBytes = original.containerInspectBytes;
    reject(() => prepareInstallationPreflight(fresh), 'PREFLIGHT_STALE_MOUNT_OBSERVATION');
    withContainers(fresh);
    assert.deepEqual(prepareInstallationPreflight(fresh), prepareInstallationPreflight(fresh));
    assert.equal(prepareInstallationPreflight(fresh).startupAllowed, false);
  });

  test('native inspected configuration consistency never establishes live freshness or capability readiness', () => {
    const result = prepareInstallationPreflight(withContainers(fixture()));
    assert.equal(result.containerBindings, 'CONSISTENT_SNAPSHOT');
    assert.equal(result.capabilityReadiness, 'UNKNOWN');
    assert.equal(result.startupAllowed, false);
    assert.ok(result.blockers.includes('RUNNER_SOURCE_AND_OBSERVATION_FRESHNESS_UNBOUND'));
    assert.ok(result.blockers.includes('FILESYSTEM_MOUNT_IDENTITY_UNVERIFIED'));
  });

  test('stale/replayed Docker observations and unchecked environment additions fail consistency checks', () => {
    for (const mutate of [
      (records) => {
        records[2].Image = `sha256:${'f'.repeat(64)}`;
      },
      (records) => {
        records[2].Config.Env.push('OPENPC_UNCHECKED_RUNTIME_OVERRIDE=1');
      },
      (records) => {
        records[2].Config.Env.push(records[2].Config.Env[0]);
      },
      (records) => {
        records[2].Config.Cmd = ['unexpected'];
      },
      (records) => {
        records[2].Config.Labels['com.docker.compose.project'] = 'foreign';
      },
      (records) => {
        records[2].HostConfig.Memory *= 2;
      },
      (records) => {
        records[2].HostConfig.PidMode = 'host';
      },
      (records) => {
        records[2].HostConfig.SecurityOpt = [];
      },
      (records) => {
        records[2].Mounts[0].Source += '-previous';
      },
      (records) => {
        records[2].Mounts[0].RW = !records[2].Mounts[0].RW;
      },
      (records) => {
        records[2].NetworkSettings.Networks = {};
      },
      (records) => {
        records.pop();
      },
    ]) {
      const input = withContainers(fixture());
      const records = JSON.parse(input.containerInspectBytes);
      mutate(records);
      input.containerInspectBytes = encode(records);
      reject(() => prepareInstallationPreflight(input));
    }
  });

  test('direct existing consumer configuration mismatches are rejected without inventing an adapter', () => {
    const input = fixture(['control-api']);
    changeRender(
      input,
      (c) => {
        c.services['control-api'].environment.CONTROL_API_EVIDENCE_ENVIRONMENT_ID = 'other';
      },
      true,
    );
    reject(() => prepareInstallationPreflight(input), 'PREFLIGHT_CONSUMED_CONFIGURATION_MISMATCH');
    // The fixture OIDC topology currently consumes HTTP; canonical installation requires HTTPS.
    // Keep the HTTPS requirement; do not silently convert the accepted setting.
    reject(
      () => prepareInstallationPreflight(fixture(['identity-service'])),
      'PREFLIGHT_CONSUMED_CONFIGURATION_MISMATCH',
    );
  });

  test('strict native input rejection and all ordinary diagnostics exclude private values and paths', () => {
    const input = fixture();
    reject(
      () => prepareInstallationPreflight({ ...input, ready: true }),
      'PREFLIGHT_INPUT_INVALID',
    );
    reject(
      () =>
        prepareInstallationPreflight({
          ...input,
          imageInspectBytes: Buffer.from('[{"Id":"a","Id":"b"}]'),
        }),
      'PREFLIGHT_DOCUMENT_INVALID',
    );
    reject(
      () => prepareInstallationPreflight({ ...input, currentComposeBytes: Buffer.from([0xff]) }),
      'PREFLIGHT_DOCUMENT_INVALID',
    );
    const marker = 'PRIVATE_SENTINEL_NOT_FOR_LOGS';
    changeRender(
      input,
      (c) => {
        c.services['fact-service'].environment.OPENPC_PRIVATE_SECRET = marker;
      },
      true,
    );
    assert.throws(
      () => prepareInstallationPreflight(input),
      (error) => {
        assert.ok(error instanceof InstallationConfigError);
        assert.ok(!error.message.includes(marker));
        assert.ok(!JSON.stringify(error).includes(scratch));
        return true;
      },
    );
    const summary = JSON.stringify(prepareInstallationPreflight(fixture()));
    assert.ok(!summary.includes(scratch));
    assert.ok(!summary.includes('secret://'));
    assert.ok(!summary.includes('openpc_fact_runtime'));
  });

  test('helper remains aligned with the existing image and consumed configuration owners', async () => {
    const [imageOwner, factCompose, control, identity, worker] = await Promise.all([
      readFile(join(root, 'scripts/maintenance/local-runtime-images.sh'), 'utf8'),
      readFile(join(root, 'deploy/compose/local/compose.yaml'), 'utf8'),
      readFile(join(root, 'services/control-api/src/local-runtime.ts'), 'utf8'),
      readFile(join(root, 'services/identity-service/src/local-runtime.ts'), 'utf8'),
      readFile(join(root, 'services/fleet-controller/src/bin/local_runtime_worker.rs'), 'utf8'),
    ]);
    assert.match(imageOwner, /openpc_image_owner=openpc-r1-local-runtime-v1/u);
    assert.match(
      imageOwner,
      /openpc_build_services=\(control-worker fact-service policy-service identity-service participant-service control-api admin-web\)/u,
    );
    assert.match(factCompose, /OPENPC_FACT_DATABASE_USER: openpc_fact_runtime/u);
    assert.match(control, /config\.CONTROL_API_EVIDENCE_ENVIRONMENT_ID/u);
    assert.match(identity, /IDENTITY_OIDC_ISSUER/u);
    assert.match(worker, /CONTROL_WORKER_ARTIFACT_CAPACITY_BYTES/u);
  });

  test('synthetic core fixture agrees with actual render on its relevant structural invariants', () => {
    const synthetic = syntheticCoreCompose(join(scratch, 'secrets'));
    const actual = rendered.services['control-api'];
    const expected = synthetic.services['control-api'];
    assert.equal(checkRenderedCompose(rendered, ['control-api']), expected.mem_limit);
    for (const field of ['image', 'platform', 'read_only'])
      assert.equal(actual[field], expected[field], 'Actual core render drift: ' + field);
    // The resource reader already validates canonical numeric/string encodings.
    for (const field of ['mem_limit', 'cpus', 'pids_limit'])
      assert.equal(Number(actual[field]), expected[field], 'Actual core cap drift: ' + field);
    for (const [key, value] of Object.entries(expected.environment))
      assert.equal(actual.environment[key], value, 'Actual core consumer drift: ' + key);
    assert.equal(
      actual.depends_on['control-migrate'].condition,
      expected.depends_on['control-migrate'].condition,
    );
    assert.deepEqual(Object.keys(actual.networks), Object.keys(expected.networks));
    assert.equal(rendered.networks['openpc-local'].name, synthetic.networks['openpc-local'].name);
    const target = '/run/secrets/identity_runtime_signing_public_key';
    assert.deepEqual(
      renderedMounts(rendered, 'control-api').get(target),
      renderedMounts(synthetic, 'control-api').get(target),
    );
  });
});
