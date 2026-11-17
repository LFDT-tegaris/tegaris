import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  factSecretContainerLabelOverrides,
  factSecretBindMount,
  assertFactSecretContainerLabelIsolation,
  inspectFactSecretContainerMounts,
} from './fact-secret-consumer-installation.mjs';
import {
  assertFactSecretPublishedBind,
  factSecretContainerConfiguration,
} from './fact-secret-consumer-journey.mjs';

test('fixture binds explicitly select propagation and reject option injection', () => {
  assert.deepEqual(
    factSecretBindMount(
      '/var/lib/docker/volumes/owned/_data/candidate-url',
      '/fact-bridge/candidate-url',
    ),
    [
      '--mount',
      'type=bind,src=/var/lib/docker/volumes/owned/_data/candidate-url,dst=/fact-bridge/candidate-url,bind-propagation=rprivate,readonly',
    ],
  );
  assert.ok(
    factSecretBindMount('/owned/artifacts', '/fact-artifacts', false)[1].endsWith(
      'bind-propagation=rprivate',
    ),
  );
  assert.ok(
    factSecretBindMount('/owned/file', '/secret', true, 'rslave')[1].endsWith(
      'bind-propagation=rslave,readonly',
    ),
  );
  assert.throws(() => factSecretBindMount('/owned/file', '/secret', true, 'rshared'));
  for (const path of ['/owned,readonly=false', '/owned\n--privileged', '/owned\0alias']) {
    assert.throws(() => factSecretBindMount(path, '/target'));
    assert.throws(() => factSecretBindMount('/source', path));
  }
});

test('native immutable readback preserves security fields across Docker start defaults', () => {
  const first = {
    Config: { Image: 'same' },
    State: { Status: 'created' },
    HostConfig: { ReadonlyRootfs: true, OomKillDisable: false },
    Mounts: [
      { Destination: '/a', Source: '/original/a', RW: false, Propagation: 'rprivate' },
      { Destination: '/b', Source: '/original/b', RW: false, Propagation: 'rslave' },
    ],
  };
  const shuffled = structuredClone(first);
  shuffled.Mounts.reverse();
  assert.deepEqual(
    factSecretContainerConfiguration(first),
    factSecretContainerConfiguration(shuffled),
  );
  const started = structuredClone(first);
  started.State.Status = 'running';
  started.HostConfig.OomKillDisable = null;
  assert.deepEqual(
    factSecretContainerConfiguration(first),
    factSecretContainerConfiguration(started),
  );
  for (const status of ['created', 'running', 'exited']) {
    for (const value of [true, undefined, 'false', 0]) {
      assert.throws(() =>
        factSecretContainerConfiguration({
          ...first,
          State: { Status: status },
          HostConfig: { ...first.HostConfig, OomKillDisable: value },
        }),
      );
    }
  }
  for (const change of [{ ReadonlyRootfs: false }, { Memory: 0 }, { CapAdd: ['SYS_ADMIN'] }]) {
    assert.notDeepEqual(
      factSecretContainerConfiguration(first),
      factSecretContainerConfiguration({
        ...first,
        HostConfig: { ...first.HostConfig, ...change },
      }),
    );
  }
  for (const change of [{ RW: true }, { Source: '/substitute' }, { Propagation: 'rshared' }]) {
    const changed = structuredClone(first);
    Object.assign(changed.Mounts[0], change);
    assert.notDeepEqual(
      factSecretContainerConfiguration(first),
      factSecretContainerConfiguration(changed),
    );
  }
  assert.throws(() =>
    factSecretContainerConfiguration({ ...first, Mounts: [first.Mounts[0], first.Mounts[0]] }),
  );
});

test('published secret admission rejects shared, writable, duplicate and substituted file binds', () => {
  const source = '/owned-tmpfs/candidate-url',
    volume = '/owned-tmpfs';
  const original = {
    Type: 'bind',
    Source: source,
    Destination: '/fact-bridge/candidate-url',
    RW: false,
    Propagation: 'rslave',
  };
  assertFactSecretPublishedBind({ Mounts: [original] }, source, volume);
  for (const changed of [
    { Propagation: 'rshared' },
    { Propagation: 'rprivate' },
    { RW: true },
    { Type: 'volume' },
    { Source: '/foreign/candidate-url' },
  ])
    assert.throws(() =>
      assertFactSecretPublishedBind({ Mounts: [{ ...original, ...changed }] }, source, volume),
    );
  for (const mounts of [[], [original, original], [original, { Source: volume, RW: true }]])
    assert.throws(() => assertFactSecretPublishedBind({ Mounts: mounts }, source, volume));
});

test('fixture containers neutralize inherited Compose ownership before allocation', () => {
  const inherited = {
    'com.docker.compose.project': 'retained-project',
    'com.docker.compose.service': 'fact-service',
    'com.docker.compose.version': '5.4.0',
    'io.openpc.fixture.owner': 'original-owner',
  };
  assert.throws(() => assertFactSecretContainerLabelIsolation(inherited));
  const args = factSecretContainerLabelOverrides();
  for (let index = 0; index < args.length; index += 2) {
    assert.equal(args[index], '--label');
    const [name, value] = args[index + 1].split('=');
    inherited[name] = value;
  }
  assertFactSecretContainerLabelIsolation(inherited);
  assert.equal(inherited['io.openpc.fixture.owner'], 'original-owner');
  for (const name of ['project', 'service', 'version'])
    assert.throws(() =>
      assertFactSecretContainerLabelIsolation({
        ...inherited,
        [`com.docker.compose.${name}`]: 'foreign',
      }),
    );
  assertFactSecretContainerLabelIsolation({});
});

test('volume cleanup inspects every retained container in bounded metadata batches', async () => {
  const ids = Array.from({ length: 471 }, (_, index) => (index + 1).toString(16).padStart(64, '0'));
  const calls = [];
  const inventory = await inspectFactSecretContainerMounts(async (...args) => {
    if (args[0] === 'ps') return ids.join('\n');
    assert.deepEqual(args.slice(0, 2), ['inspect', '--format']);
    assert.doesNotMatch(args[2], /\.Env|\.Cmd|json \.\}\}/u);
    const batch = args.slice(3);
    assert.ok(batch.length > 0 && batch.length <= 32);
    calls.push(...batch);
    return batch
      .map((Id) =>
        JSON.stringify({
          Id,
          Name: `/container-${Id}`,
          Image: `sha256:${'a'.repeat(64)}`,
          Config: { Labels: {} },
          Mounts:
            Id === ids.at(-1)
              ? [{ Source: '/owned-volume/payload', Destination: '/consumer' }]
              : [],
        }),
      )
      .join('\n');
  });
  assert.deepEqual(calls, ids);
  assert.equal(inventory.length, 471);
  assert.equal(inventory.at(-1).Mounts[0].Source, '/owned-volume/payload');
});

test('missing, duplicated or malformed inventory and a failed later batch remain UNKNOWN', async () => {
  const ids = Array.from({ length: 33 }, (_, index) => (index + 1).toString(16).padStart(64, '0'));
  for (const fault of [
    'duplicate-ids',
    'bad-id',
    'missing',
    'duplicate-result',
    'bad-json',
    'failed-later',
  ]) {
    await assert.rejects(
      inspectFactSecretContainerMounts(async (...args) => {
        if (args[0] === 'ps')
          return (
            fault === 'duplicate-ids' ? [...ids, ids[0]] : fault === 'bad-id' ? ['short-id'] : ids
          ).join('\n');
        const batch = args.slice(3);
        if (fault === 'failed-later' && batch[0] === ids[32])
          throw new Error('inspection unavailable');
        if (fault === 'bad-json') return '{';
        const result =
          fault === 'missing'
            ? batch.slice(1)
            : fault === 'duplicate-result'
              ? batch.map(() => batch[0])
              : batch;
        return result
          .map((Id) =>
            JSON.stringify({ Id, Name: '/fixture', Image: `sha256:${'a'.repeat(64)}`, Mounts: [] }),
          )
          .join('\n');
      }),
    );
  }
});

// Exercise the actual shell dispatcher against recorded external CLI responses.
// The shared admission result and Node journey invocation are observation seams,
// not substitutes for cgroups, SQL, authenticated delivery or container acceptance.
const repository = fileURLToPath(new URL('../../../', import.meta.url)).replace(/\/$/u, '');
const shell = join(
  repository,
  'tests/integration/local-runtime/fact-secret-consumer-installation.sh',
);
const token = 'a'.repeat(64);
const project = `openpc-local-e2e-${token.slice(0, 12)}`;
const factImage = `sha256:${'1'.repeat(64)}`;
const identityImage = `sha256:${'2'.repeat(64)}`;
const postgres =
  'docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7';
const nodeImage =
  'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43';
const dbs = ['control-pg', 'fact-pg', 'candidate-index-pg'];
const migrations = ['control-migrate', 'fact-migrate', 'candidate-index-migrate'];

async function fixture(t) {
  const parent = process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir();
  const directory = await mkdtemp(join(parent, 'fact-secret-dispatch-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, 'installation');
  await mkdir(join(root, 'data'), { recursive: true });
  await mkdir(join(root, 'secrets'), { mode: 0o700 });
  await writeFile(
    join(root, '.openpc-local-runtime-owner'),
    `openpc-local-runtime:${project}:${token}\n`,
    { mode: 0o644 },
  );
  for (const db of dbs) await mkdir(join(root, 'data', db));
  const secret = join(root, 'secrets', 'fixture-password.txt');
  await writeFile(secret, `${'a'.repeat(64)}\n`, { mode: 0o444 });
  const services = {};
  for (const [i, name] of [
    ...dbs,
    ...migrations,
    'identity-service',
    'oidc-emulator',
    'workload-issuer',
  ].entries()) {
    services[name] = {
      image: i < 6 ? postgres : i === 6 ? 'openpc-r1-dev/identity-service:local' : nodeImage,
      platform: 'linux/amd64',
      mem_limit: String(i < 6 ? 1024 ** 3 : i === 6 ? 768 * 1024 ** 2 : 128 * 1024 ** 2),
      cpus: i < 7 ? 0.75 : 0.25,
      pids_limit: 256,
      networks: { 'openpc-local': null },
      secrets: [{ source: 'fixture' }],
      depends_on:
        i < 3 || i > 6
          ? {}
          : i < 6
            ? { [dbs[i - 3]]: { condition: 'service_healthy', required: true } }
            : {
                'control-migrate': { condition: 'service_completed_successfully', required: true },
                'oidc-emulator': { condition: 'service_healthy', required: true },
                'workload-issuer': { condition: 'service_healthy', required: true },
              },
      ...(i < 3
        ? {
            volumes: [
              { type: 'bind', source: join(root, 'data', name), target: '/var/lib/postgresql' },
            ],
          }
        : {}),
    };
  }
  const config = {
    name: project,
    services,
    secrets: { fixture: { file: secret } },
    networks: { 'openpc-local': { name: `${project}_openpc-local` } },
  };
  const images = ['fact-service', 'identity-service'].map((name, i) => ({
    Id: i === 0 ? factImage : identityImage,
    Os: 'linux',
    Architecture: 'amd64',
    Config: {
      User: '65532:65532',
      Labels: {
        'io.openpc.image.owner': 'openpc-r1-local-runtime-v1',
        'io.openpc.image.service': name,
      },
      Entrypoint: i === 0 ? ['/usr/local/bin/openpc-fact-local-runtime'] : ['node'],
      Cmd: [],
    },
  }));
  async function save() {
    await writeFile(join(directory, 'config.json'), JSON.stringify(config));
    await writeFile(join(directory, 'images.json'), JSON.stringify(images));
  }
  await save();
  return { directory, root, secret, config, images, save };
}

const boundary = String.raw`
set -euo pipefail
source "$SHELL_SOURCE"
repository_root=$REPOSITORY run_root=$FIXTURE_ROOT data_root=$FIXTURE_ROOT/data secret_root=$FIXTURE_ROOT/secrets
project=$PROJECT owner_token=$OWNER_TOKEN
compose=(docker compose -p "$project" -f "$repository_root/deploy/compose/local/compose.yaml")
reuse_images=\${REUSE_IMAGES:-0} refresh_from=\${REFRESH_FROM:-}
export OPENPC_RUNTIME_OWNER_PID=$BASHPID
exec 8<"$run_root/.openpc-local-runtime-owner"
flock -n 8
openpc_compose_json() { command "$NODE" -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "\${compose[@]}"; }
openpc_require_heavy_lock() { printf 'lock\n' >> "$CALLS"; return "\${LOCK_STATUS:-0}"; }
openpc_require_execution() { [[ $1 == runtime-target ]] || return 97; printf 'admission\n' >> "$CALLS"; return "\${ADMISSION_STATUS:-0}"; }
timeout() { [[ $1 == 180 ]] || return 97; shift; "$@"; }
docker() {
  printf 'docker %s\n' "$*" >> "$CALLS"
  if [[ $1 == compose ]]; then
    [[ $2 == -p && $3 == "$project" && $4 == -f && $5 == "$repository_root/deploy/compose/local/compose.yaml" ]] || return 97
    shift 5
    case "$1" in
      config) cat "$FIXTURE/config.json"; return "\${CONFIG_STATUS:-0}" ;;
      pull) return "\${PULL_STATUS:-0}" ;;
      up)
        case " \${*: -1} " in
          ' candidate-index-migrate ') return "\${MIGRATION_UP_STATUS:-0}" ;;
          ' workload-issuer ') return "\${DEPENDENCY_UP_STATUS:-0}" ;;
          ' identity-service ') return "\${IDENTITY_UP_STATUS:-0}" ;;
          *) return 97 ;;
        esac ;;
      ps)
        [[ \${MISSING_MIGRATION:-} != "$3" ]] || return 0
        case "$3" in
          control-migrate) printf '%064d\n' 1 ;;
          fact-migrate) printf '%064d\n' 2 ;;
          candidate-index-migrate) printf '%064d\n' 3 ;;
          identity-service) printf '%064d\n' 4 ;;
          *) return 97 ;;
        esac ;;
      *) return 97 ;;
    esac
    return
  fi
  case "$1 $2" in
    'ps -aq')
      if [[ $* == *io.openpc.fixture* ]]; then printf '%s' "\${OWNED_CONTAINERS:-}"; return "\${CLEANUP_PS_STATUS:-0}"; fi
      printf '%s' "\${PROJECT_CONTAINERS:-}" ;;
    'network ls') printf '%s' "\${PROJECT_NETWORKS:-}" ;;
    'volume ls')
      if [[ $* == *io.openpc.fixture* ]]; then printf '%s' "\${OWNED_VOLUMES:-}"; return "\${CLEANUP_VOLUME_STATUS:-0}"; fi
      printf '%s' "\${PROJECT_VOLUMES:-}" ;;
    'image inspect') cat "$FIXTURE/images.json"; return "\${IMAGE_STATUS:-0}" ;;
    'inspect --format')
      if [[ $3 == *'{{.Image}}'* ]]; then printf '%s/%s/identity-service\n' "\${LIVE_IDENTITY_IMAGE:-$IDENTITY_IMAGE}" "$project"; return; fi
      case "\${4: -1}" in 1) service=control-migrate ;; 2) service=fact-migrate ;; 3) service=candidate-index-migrate ;; *) return 97 ;; esac
      printf '%s/%s\n' "\${MIGRATION_PROJECT:-$project}" "$service" ;;
    wait\ *)
      case "\${2: -1}" in 1) result=\${CONTROL_EXIT:-0} ;; 2) result=\${FACT_EXIT:-0} ;; 3) result=\${CANDIDATE_EXIT:-0} ;; *) return 97 ;; esac
      if [[ $result == timeout ]]; then return 124; fi
      printf '%s\n' "$result" ;;
    *) return 97 ;;
  esac
}
pnpm() {
  printf 'bundle\n' >> "$CALLS"
  [[ \${BUNDLE_STATUS:-0} == 0 ]] || return "$BUNDLE_STATUS"
  local arg
  for arg in "$@"; do
    if [[ $arg == --outfile=* ]]; then printf '// invocation fixture only\n' > "\${arg#--outfile=}"; return; fi
  done
  return 97
}
node() {
  if [[ \${1:-} == --import && \${3:-} == "$repository_root/tests/integration/local-runtime/fact-secret-consumer-installation.mjs" ]]; then
    [[ $2 == tsx && $4 == run && $5 == "$run_root" && $7 == "$FACT_IMAGE" && -f $8 ]] || return 97
    [[ $OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT == 1 ]] || return 97
    printf 'installation %s\n' "$*" >> "$CALLS"
    return "\${INSTALLATION_STATUS:-0}"
  fi
  command "$NODE" "$@"
}
`.replaceAll(String.fromCharCode(92) + '$', '$');

async function run(f, { env = {}, before = '', action } = {}) {
  const calls = join(f.directory, 'calls.txt');
  await writeFile(calls, '');
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) => !key.startsWith('OPENPC_LOCAL_RUNTIME_') && !key.startsWith('OPENPC_BROWSER_'),
    ),
  );
  const script = `${boundary}\n${before}\n${
    action ??
    `
if openpc_run_fact_secret_consumer_slice "$FACT_IMAGE" "$IDENTITY_IMAGE"; then result=0; else result=$?; fi
printf 'RESULT|%s|first=%s|retain=%s\\n' "$result" "\${openpc_fact_secret_first_failure:-0}" "\${OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT:-0}"
exit "$result"
`
  }`;
  const child = spawnSync('/usr/bin/bash', ['-c', script], {
    cwd: repository,
    encoding: 'utf8',
    timeout: 15000,
    maxBuffer: 1024 * 1024,
    env: {
      ...cleanEnv,
      NODE: process.execPath,
      SHELL_SOURCE: shell,
      REPOSITORY: repository,
      FIXTURE: f.directory,
      FIXTURE_ROOT: f.root,
      PROJECT: project,
      OWNER_TOKEN: token,
      FACT_IMAGE: factImage,
      IDENTITY_IMAGE: identityImage,
      CALLS: calls,
      OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: '1',
      OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB: String(9 * 1024 ** 2),
      ...env,
    },
  });
  if (child.error)
    throw new Error(`C1 dispatcher subprocess unavailable: ${child.error.code ?? 'UNKNOWN'}`);
  return { ...child, calls: await readFile(calls, 'utf8') };
}

function noAllocation(result, expected = 96) {
  assert.equal(result.status, expected, result.stderr);
  assert.doesNotMatch(result.calls, /docker compose .* (?:up|pull) |\bbundle\b|^installation /mu);
}

test('fresh C1 dispatch validates actual inputs, joins all migrations and invokes the existing native installer', async (t) => {
  const f = await fixture(t),
    result = await run(f);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS\|input-preflight\|additional_external_mib=832/u);
  assert.match(result.stdout, /RESULT\|0\|first=0\|retain=0/u);
  const lines = result.calls.trim().split('\n');
  const positions = (match) =>
    lines.map((line, i) => (match.test(line) ? i : -1)).filter((i) => i >= 0);
  const waits = positions(/^docker wait /u),
    ups = positions(/compose .* up /u);
  assert.equal(waits.length, 3);
  assert.equal(ups.length, 3);
  assert.ok(ups[0] < waits[0] && waits[2] < ups[1] && ups[1] < ups[2]);
  assert.match(lines[ups[0]], /control-migrate fact-migrate candidate-index-migrate$/u);
  assert.match(
    lines[ups[1]],
    /--no-deps .*control-pg fact-pg candidate-index-pg oidc-emulator workload-issuer$/u,
  );
  assert.match(lines[ups[2]], /--no-deps .*identity-service$/u);
  assert.doesNotMatch(
    lines.filter((line) => / up /u.test(line)).join('\n'),
    /fact-service|control-api|control-worker|policy-service|admin-web/u,
  );
  assert.ok(positions(/^bundle$/u)[0] > ups[2]);
  assert.ok(positions(/^installation /u)[0] > positions(/^bundle$/u)[0]);
  assert.equal(positions(/^admission$/u).length, 3);
});

test('fresh C1 rejects retained resume, conflicting/unknown modes and caller overrides before allocation', async (t) => {
  for (const env of [
    { REUSE_IMAGES: '1' },
    { REFRESH_FROM: '/retained-source' },
    { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: '0' },
    { OPENPC_LOCAL_RUNTIME_BUILD_ONLY: '1' },
    { OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY: '1' },
    { OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE: '1' },
    { OPENPC_LOCAL_RUNTIME_FUTURE_MODE: '1' },
    { OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG: '/old/recipient.json' },
    { OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET: '172.29.0.0/24' },
    { OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY: '172.29.0.1' },
    { OPENPC_LOCAL_RUNTIME_NETWORK_OWNER: token },
    { OPENPC_LOCAL_RUNTIME_NETWORK_ROOT: '/caller/root' },
    { OPENPC_BROWSER_SCENARIOS: 'recovery' },
    { OPENPC_BROWSER_SESSION: '1' },
    { OPENPC_LOCAL_RUNTIME_CLEANUP_PROBE: 'missing-sentinel' },
  ])
    await t.test(JSON.stringify(env), async (t) =>
      noAllocation(await run(await fixture(t), { env })),
    );
  await t.test('Compose override', async (t) => {
    const result = await run(await fixture(t), {
      before: 'compose+=(-f "$run_root/data/retained.json")',
    });
    noAllocation(result);
    assert.doesNotMatch(result.calls, /docker compose/u);
  });
});

test('fresh C1 accepts the shared generated network only after root admission and live network validation', async (t) => {
  const before = `
source "$repository_root/tests/integration/local-runtime/runner-harness.sh"
openpc_network_phase=fresh
readonly openpc_network_subnet=172.29.0.0/24 openpc_network_gateway=172.29.0.1
export OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET=$openpc_network_subnet
export OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY=$openpc_network_gateway
export OPENPC_LOCAL_RUNTIME_NETWORK_OWNER=$owner_token
export OPENPC_LOCAL_RUNTIME_NETWORK_ROOT=$run_root
openpc_network_compose_command=("\${compose[@]}")
compose=(openpc_network_compose)
openpc_network_check() { printf 'network-check\\n' >> "$CALLS"; return "\${NETWORK_STATUS:-0}"; }
openpc_network_compose() { "\${openpc_network_compose_command[@]}" "$@"; }
`;
  const accepted = await run(await fixture(t), { before });
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.match(accepted.calls, /network-check/u);
  const failed = await run(await fixture(t), { before, env: { NETWORK_STATUS: '95' } });
  noAllocation(failed, 95);
  for (const changed of [
    'openpc_network_phase=retained',
    'OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY=172.29.0.2',
    'OPENPC_LOCAL_RUNTIME_NETWORK_OWNER=foreign',
    'OPENPC_LOCAL_RUNTIME_NETWORK_ROOT=/foreign',
  ])
    noAllocation(await run(await fixture(t), { before: `${before}\n${changed}` }));
  // Even correctly paired metadata cannot authorize an initial caller override.
  const initial = await run(await fixture(t), {
    before,
    action: 'openpc_fact_secret_consumer_slice_options',
  });
  noAllocation(initial);
});

test('fresh C1 requires inherited admission and the actual root lock', async (t) => {
  for (const options of [
    { env: { LOCK_STATUS: '95' }, status: 95 },
    { env: { ADMISSION_STATUS: '94' }, status: 94 },
    { before: 'exec 8<&-', status: 96 },
    { before: 'OPENPC_RUNTIME_OWNER_PID=1', status: 96 },
    { before: 'unset -f openpc_require_execution', status: 96 },
  ])
    await t.test(JSON.stringify(options), async (t) =>
      noAllocation(await run(await fixture(t), options), options.status),
    );
});

test('fresh C1 refuses existing database bytes, prior publication and owned project resources', async (t) => {
  for (const name of [
    'control-pg/PG_VERSION',
    'fact-pg/PG_VERSION',
    'candidate-index-pg/PG_VERSION',
    'fact-secret-old',
    'fact-bridge',
    'protected-proofs',
  ]) {
    await t.test(name, async (t) => {
      const f = await fixture(t);
      await writeFile(join(f.root, 'data', name), 'retained');
      noAllocation(await run(f));
    });
  }
  for (const variable of ['PROJECT_CONTAINERS', 'PROJECT_NETWORKS', 'PROJECT_VOLUMES']) {
    await t.test(variable, async (t) =>
      noAllocation(await run(await fixture(t), { env: { [variable]: 'retained-owned-id' } })),
    );
  }
  await t.test('secret symlink', async (t) => {
    const f = await fixture(t);
    const alias = join(f.root, 'secrets', 'alias');
    await symlink(f.secret, alias);
    f.config.secrets.fixture.file = alias;
    await f.save();
    noAllocation(await run(f));
  });
  await t.test('writable secret', async (t) => {
    const f = await fixture(t);
    await chmod(f.secret, 0o666);
    noAllocation(await run(f));
  });
  await t.test('sentinel scope mismatch', async (t) => {
    const f = await fixture(t);
    await writeFile(
      join(f.root, '.openpc-local-runtime-owner'),
      `openpc-local-runtime:${project}:${'b'.repeat(64)}\n`,
    );
    noAllocation(await run(f));
  });
});

test('rendered C1 dependency, image, topology and phase envelopes fail closed', async (t) => {
  const mutations = {
    'business dependency': (c) => {
      c.services['identity-service'].depends_on['control-api'] = { condition: 'service_healthy' };
    },
    'missing prerequisite': (c) => {
      delete c.services['identity-service'].depends_on['workload-issuer'];
    },
    'migration only started': (c) => {
      c.services['identity-service'].depends_on['control-migrate'].condition = 'service_started';
    },
    'optional prerequisite': (c) => {
      c.services['identity-service'].depends_on['control-migrate'].required = false;
    },
    'floating image': (c) => {
      c.services['workload-issuer'].image = 'node:latest';
    },
    'unbounded memory': (c) => {
      c.services['control-pg'].mem_limit = 0;
    },
    'coerced memory': (c) => {
      c.services['control-pg'].mem_limit = true;
    },
    'unparsed memory unit': (c) => {
      c.services['control-pg'].mem_limit = '1g';
    },
    'unbounded swap': (c) => {
      c.services['control-pg'].memswap_limit = -1;
    },
    'missing cpu cap': (c) => {
      delete c.services['identity-service'].cpus;
    },
    'unbounded pids': (c) => {
      c.services['identity-service'].pids_limit = -1;
    },
    'replicas': (c) => {
      c.services['control-pg'].deploy = { replicas: 2 };
    },
    'migration peak overflow': (c) => {
      c.services['control-migrate'].mem_limit = 5 * 1024 ** 3;
    },
    '832 MiB fixture overflow': (c) => {
      c.services['identity-service'].mem_limit = 5 * 1024 ** 3;
    },
    'foreign database mount': (c) => {
      c.services['candidate-index-pg'].volumes[0].source = '/retained/candidate-index-pg';
    },
    'extra database mount': (c) => {
      c.services['candidate-index-pg'].volumes.push({
        type: 'volume',
        source: 'retained',
        target: '/other',
      });
    },
    'external network': (c) => {
      c.networks['openpc-local'].external = true;
    },
    'foreign network': (c) => {
      c.services['identity-service'].network_mode = 'host';
    },
    'wrong project': (c) => {
      c.name = 'retained-project';
    },
  };
  for (const [name, mutate] of Object.entries(mutations))
    await t.test(name, async (t) => {
      const f = await fixture(t);
      mutate(f.config);
      await f.save();
      noAllocation(await run(f));
    });
  await t.test('unchanged nine GiB envelope required', async (t) =>
    noAllocation(
      await run(await fixture(t), {
        env: { OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB: String(8 * 1024 ** 2) },
      }),
    ),
  );
});

test('actual image identity, native entrypoint and UID cannot be replaced by a tag or caller assertion', async (t) => {
  const mutations = {
    'stale Identity tag': (images) => {
      images[1].Id = factImage;
    },
    'wrong owner': (images) => {
      images[0].Config.Labels['io.openpc.image.owner'] = 'other';
    },
    'wrong service': (images) => {
      images[0].Config.Labels['io.openpc.image.service'] = 'control-worker';
    },
    'non-native entrypoint': (images) => {
      images[0].Config.Entrypoint = ['/bin/sh'];
    },
    'overridden command': (images) => {
      images[0].Config.Cmd = ['sleep', 'infinity'];
    },
    'privileged UID': (images) => {
      images[0].Config.User = '0';
    },
    'wrong architecture': (images) => {
      images[0].Architecture = 'arm64';
    },
  };
  for (const [name, mutate] of Object.entries(mutations))
    await t.test(name, async (t) => {
      const f = await fixture(t);
      mutate(f.images);
      await f.save();
      noAllocation(await run(f));
    });
});

test('migration failures preserve the first result, observe independent siblings and block all consumers', async (t) => {
  for (const [env, status] of [
    [{ CONTROL_EXIT: '17', FACT_EXIT: '23' }, 17],
    [{ FACT_EXIT: 'timeout' }, 124],
    [{ CANDIDATE_EXIT: '0\n1' }, 96],
    [{ CANDIDATE_EXIT: '256' }, 96],
    [{ MISSING_MIGRATION: 'fact-migrate' }, 96],
    [{ MIGRATION_PROJECT: 'retained-project' }, 96],
  ])
    await t.test(JSON.stringify(env), async (t) => {
      const result = await run(await fixture(t), { env });
      assert.equal(result.status, status, result.stderr);
      assert.match(result.stdout, new RegExp(`first=${status}`));
      assert.equal((result.calls.match(/compose .* up /gu) ?? []).length, 1);
      assert.doesNotMatch(result.calls, /bundle|^installation /mu);
      if (env.CONTROL_EXIT) assert.equal((result.calls.match(/^docker wait /gmu) ?? []).length, 3);
    });
});

test('dependency failures, changed live images and installer failures block downstream work without being hidden', async (t) => {
  for (const [env, status, installs] of [
    [{ CONFIG_STATUS: '42' }, 42, 0],
    [{ IMAGE_STATUS: '43' }, 43, 0],
    [{ PULL_STATUS: '44' }, 44, 0],
    [{ MIGRATION_UP_STATUS: '45' }, 45, 0],
    [{ DEPENDENCY_UP_STATUS: '46' }, 46, 0],
    [{ IDENTITY_UP_STATUS: '47' }, 47, 0],
    [{ LIVE_IDENTITY_IMAGE: factImage }, 96, 0],
    [{ BUNDLE_STATUS: '48' }, 48, 0],
    [{ INSTALLATION_STATUS: '49' }, 49, 1],
  ])
    await t.test(JSON.stringify(env), async (t) => {
      const result = await run(await fixture(t), { env });
      assert.equal(result.status, status, result.stderr);
      assert.equal((result.calls.match(/^installation /gmu) ?? []).length, installs);
      assert.match(result.stdout, new RegExp(`first=${status}`));
      if (env.BUNDLE_STATUS || env.INSTALLATION_STATUS) assert.match(result.stdout, /retain=1/u);
    });
});

const cleanupAction = `
if openpc_fact_secret_consumer_on_exit "\${FIRST_STATUS:-0}"; then
  printf 'GENERIC_CLEANUP_ALLOWED\\n'
  exit "$openpc_fact_secret_exit_status"
else
  printf 'CLEANUP_FORBIDDEN|blocked=%s|retain=%s\\n' "$openpc_fact_secret_cleanup_blocked" "$OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT"
  exit "$openpc_fact_secret_exit_status"
fi
`;

test('UNKNOWN cleanup blocks generic destruction and preserves the first failure even when inventory calls fail', async (t) => {
  for (const env of [
    { OWNED_CONTAINERS: 'owned-consumer' },
    { OWNED_VOLUMES: 'owned-tmpfs' },
    { CLEANUP_PS_STATUS: '55' },
    { CLEANUP_VOLUME_STATUS: '56' },
  ])
    for (const first of [0, 73])
      await t.test(`${JSON.stringify(env)} first=${first}`, async (t) => {
        const result = await run(await fixture(t), {
          env: { ...env, FIRST_STATUS: String(first) },
          action: cleanupAction,
        });
        assert.equal(result.status, first || 99, result.stderr);
        assert.match(result.stdout, /CLEANUP_FORBIDDEN\|blocked=1\|retain=1/u);
        assert.doesNotMatch(result.stdout, /GENERIC_CLEANUP_ALLOWED/u);
        assert.match(result.stderr, new RegExp(`UNKNOWN.*first_exit=${first}`));
        assert.doesNotMatch(result.calls, /docker .* (?:rm|down|stop) /u);
      });
});

test('cleanup permits teardown only with known empty inventories and retains dispatcher failure across status-zero exit', async (t) => {
  for (const first of [0, 73])
    await t.test(`known empty first=${first}`, async (t) => {
      const result = await run(await fixture(t), {
        env: { FIRST_STATUS: String(first) },
        action: cleanupAction,
      });
      assert.equal(result.status, first, result.stderr);
      assert.match(result.stdout, /GENERIC_CLEANUP_ALLOWED/u);
    });
  await t.test('original dispatcher failure', async (t) => {
    const result = await run(await fixture(t), {
      before: 'openpc_fact_secret_first_failure=71',
      env: { OWNED_VOLUMES: 'unknown' },
      action: cleanupAction,
    });
    assert.equal(result.status, 71, result.stderr);
    assert.match(result.stderr, /first_exit=71/u);
  });
  await t.test('known empty preserves earlier dispatcher failure', async (t) => {
    const result = await run(await fixture(t), {
      before: 'openpc_fact_secret_first_failure=71',
      action: cleanupAction,
    });
    assert.equal(result.status, 71, result.stderr);
    assert.match(result.stdout, /GENERIC_CLEANUP_ALLOWED/u);
  });
  await t.test('invalid owner record', async (t) => {
    const result = await run(await fixture(t), {
      before: 'printf invalid > "$run_root/.openpc-local-runtime-owner"',
      action: cleanupAction,
    });
    assert.equal(result.status, 99, result.stderr);
    assert.doesNotMatch(result.stdout, /GENERIC_CLEANUP_ALLOWED/u);
    assert.doesNotMatch(result.calls, /docker/u);
  });
});

test('C1 numeric rendered caps and preexisting retention preference remain supported', async (t) => {
  const f = await fixture(t);
  for (const service of Object.values(f.config.services))
    service.mem_limit = Number(service.mem_limit);
  await f.save();
  const result = await run(f, { env: { OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT: '1' } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /RESULT\|0\|first=0\|retain=1/u);
});

test('failed installer remains pending despite empty inventories and cannot permit destructive cleanup', async (t) => {
  for (const status of [48, 49])
    await t.test(`original failure ${status}`, async (t) => {
      const result = await run(await fixture(t), {
        env: status === 48 ? { BUNDLE_STATUS: '48' } : { INSTALLATION_STATUS: '49' },
        action: `
if openpc_run_fact_secret_consumer_slice "$FACT_IMAGE" "$IDENTITY_IMAGE"; then exit 97; fi
${cleanupAction}
`,
      });
      assert.equal(result.status, status, result.stderr);
      assert.match(result.stdout, /CLEANUP_FORBIDDEN\|blocked=1\|retain=1/u);
      assert.match(result.stderr, new RegExp(`UNKNOWN.*first_exit=${status}`));
      assert.doesNotMatch(result.calls, /io.openpc.fixture/u);
    });
});

test('cleanup rejects changed owner identity and malformed sentinel bytes', async (t) => {
  for (const before of [
    'project=another-project',
    'owner_token=changed-token',
    'printf "\\n" >> "$run_root/.openpc-local-runtime-owner"',
    'ln "$run_root/.openpc-local-runtime-owner" "$run_root/owner-hardlink"',
  ])
    await t.test(before, async (t) => {
      const result = await run(await fixture(t), { before, action: cleanupAction });
      assert.equal(result.status, 99, result.stderr);
      assert.doesNotMatch(result.stdout, /GENERIC_CLEANUP_ALLOWED/u);
      assert.doesNotMatch(result.calls, /docker/u);
    });
});

test('operations startup barrier preserves preparer publication, gates native startup and cannot resurrect after abort', async (t) => {
  const { createFactSecretPublishGate } = await import('./fact-secret-operations.mjs');
  const association = '01940000-0000-7000-8000-000000000001';
  const gate = createFactSecretPublishGate(association);
  await gate.wait(); // Original prepare-secret publication remains possible.
  assert.throws(() => gate.release(association));
  gate.arm(association);
  let passed = false;
  const waiting = gate.wait().then(() => {
    passed = true;
  });
  await Promise.resolve();
  assert.equal(passed, false);
  assert.throws(() => gate.arm(association));
  assert.throws(() => gate.release('01940000-0000-7000-8000-000000000002'));
  assert.equal(passed, false);
  gate.release(association);
  await waiting;
  assert.equal(passed, true);
  gate.abort();
  await assert.rejects(gate.wait(), /OPS_HOST_OBSERVATION_REJECTED/u);
  assert.throws(() => gate.release(association));
  const closed = createFactSecretPublishGate(association);
  closed.arm(association);
  const pending = assert.rejects(closed.wait(), /OPS_HOST_OBSERVATION_REJECTED/u);
  closed.abort();
  await pending;
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const expired = createFactSecretPublishGate(association);
  expired.arm(association);
  const timedOut = assert.rejects(expired.wait(), /OPS_HOST_OBSERVATION_REJECTED/u);
  t.mock.timers.tick(4500);
  await timedOut;
  assert.throws(() => expired.release(association));
});

test('publisher descriptor and private commands reject caller readiness, wrong reference and extra frame data', async () => {
  const { parseFactSecretResolutionDescriptor, parseFactSecretPublisherCommand } =
    await import('./fact-secret-operations.mjs');
  const { sha256 } = await import('../../../services/control-api/src/configuration/digest.ts');
  const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
  const value = {
    referenceFingerprint: sha256(Buffer.from(reference)),
    version: 'v1',
    fingerprint: `sha256:${'a'.repeat(64)}`,
  };
  assert.deepEqual(parseFactSecretResolutionDescriptor(value, reference), value);
  for (const changed of [
    { ...value, checked: true },
    { ...value, version: 'latest' },
    { ...value, fingerprint: 'opaque' },
    { ...value, material: 'forbidden' },
  ])
    assert.throws(() => parseFactSecretResolutionDescriptor(changed, reference));
  assert.throws(() =>
    parseFactSecretResolutionDescriptor(value, reference.replace('reader', 'other')),
  );
  let calls = 0;
  const getter = Object.defineProperty({ ...value }, 'fingerprint', {
    enumerable: true,
    get() {
      calls++;
      return value.fingerprint;
    },
  });
  assert.throws(() => parseFactSecretResolutionDescriptor(getter, reference));
  assert.equal(calls, 0);
  const association = '01940000-0000-7000-8000-000000000001';
  for (const operation of ['arm', 'release', 'abort'])
    assert.deepEqual(parseFactSecretPublisherCommand(`${operation} ${association}`), {
      operation,
      associationId: association,
    });
  for (const frame of [
    '',
    'release',
    `release ${association} extra`,
    `arm ${association}\nclose`,
    'release 7',
    '{"checked":true}',
  ])
    assert.throws(() => parseFactSecretPublisherCommand(frame));
});

test('private publisher input bounds fragmented frames before buffering a newline', async () => {
  const { Readable } = await import('node:stream');
  const { createFactSecretPublisherInput, assertFactSecretOperationsOwner } =
    await import('./fact-secret-operations.mjs');
  const collect = async (chunks) => {
    const values = [];
    for await (const chunk of Readable.from(chunks).pipe(createFactSecretPublisherInput()))
      values.push(chunk);
    return Buffer.concat(values).toString();
  };
  assert.equal(await collect([Buffer.from('{}\ncl'), Buffer.from('ose\n')]), '{}\nclose\n');
  for (const chunks of [
    [Buffer.alloc(65536, 'x'), Buffer.from('x')],
    [Buffer.from('{}\n'), Buffer.alloc(100, 'x'), Buffer.alloc(28, 'x')],
    [Buffer.from('{}\nclose\nclose\nclose\nclose\nclose\n')],
  ])
    await assert.rejects(collect(chunks), /OPS_HOST_OBSERVATION_REJECTED/u);
  assert.throws(() =>
    assertFactSecretOperationsOwner({ positive: async () => ({ checked: true }) }),
  );
});

test('host prepares genuine signed TEST site against actual schema with other readiness explicitly incomplete', async () => {
  const { prepareFactSecretOperationsSite } = await import('./fact-secret-operations.mjs');
  const { prepareSignedInstallationCandidate } =
    await import('../../../scripts/operations/installation-config-signature.mjs');
  const repository = fileURLToPath(new URL('../../../', import.meta.url));
  const scope = {
    participantId: '01940000-0000-7000-8000-000000000001',
    privacyDomainId: '01940000-0000-7000-8000-000000000002',
  };
  const reference = 'secret://test-memory-resolver/fact/candidate-reader#v1';
  const input = await prepareFactSecretOperationsSite(
    repository,
    scope,
    reference,
    'operations-host-test',
  );
  assert.equal(input.pins.profile, 'test');
  assert.equal(input.sources.namedProfile.profile, 'test');
  const { issuerSpkiHex, ...pins } = input.pins;
  const result = prepareSignedInstallationCandidate(
    input.sources,
    { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
    input.signed,
    Date.now(),
  );
  assert.equal(result.startupAllowed, false);
  assert.equal(result.configuration.postgres.candidateIndexDsnSecretRef, reference);
  for (const blocker of [
    'QUALIFICATION_VERIFICATION_UNBOUND',
    'SECRET_PROVIDER_RESOLUTION_UNBOUND',
    'ENTRYPOINT_CONSUMER_BINDING_UNBOUND',
  ])
    assert.ok(result.blockers.includes(blocker));
  assert.throws(() =>
    prepareSignedInstallationCandidate(
      { ...input.sources, profile: 'local' },
      { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
      input.signed,
      Date.now(),
    ),
  );
  for (const changed of [
    'secret://test-memory-resolver/fact/candidate-reader#latest',
    'secret://production/fact/candidate-reader#v1',
  ])
    await assert.rejects(
      prepareFactSecretOperationsSite(repository, scope, changed, 'operations-host-test'),
    );
  await assert.rejects(
    prepareFactSecretOperationsSite(
      repository,
      { ...scope, checked: true },
      reference,
      'operations-host-test',
    ),
  );
});
