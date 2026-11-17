import { tmpdir } from 'node:os';
import { tsImport } from 'tsx/esm/api';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createHash, createECDH } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  readFile,
  chmod,
  copyFile,
  mkdtemp,
  mkdir,
  symlink,
  writeFile,
  rm,
  stat,
  lstat,
  readdir,
  readlink,
  realpath,
} from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import test from 'node:test';
import {
  sourceOverlay,
  sourceScope,
  qaSourceScope,
  runtimeArchiveConfiguration,
  verifyRuntimeSourceContainer,
} from './runtime-source-bootstrap.mjs';
import {
  isSourceStartupRejection,
  verifyOriginalSourceJournal,
  writeSourceImportProxyOverride,
} from './runtime-source-import-journey.mjs';

test('fresh aggregate rejects original first-administrator custody before allocating', () => {
  const result = spawnSync(
    '/usr/bin/bash',
    ['tests/integration/local-runtime/run-compose-e2e.sh'],
    {
      encoding: 'utf8',
      env: {
        PATH: '/nonexistent',
        OPENPC_FIRST_ADMINISTRATOR_RESUME_CUSTODY: '/retained/private/browser-custody.json',
      },
    },
  );
  assert.equal(result.status, 96);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('envelope browser rejects retained and conflicting selections before allocation', () => {
  for (const [args, extra] of [
    [['--suite'], {}],
    [['--resume', '/retained'], {}],
    [[], { OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY: '2' }],
    [[], { OPENPC_LOCAL_RUNTIME_PARTICIPANT_WORKBENCH_ONLY: '1' }],
    [[], { OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY: '1' }],
    [[], { OPENPC_FIRST_ADMINISTRATOR_BROWSER: '1' }],
    [[], { OPENPC_BROWSER_SCENARIOS: 'recovery' }],
  ]) {
    const result = spawnSync(
      '/usr/bin/bash',
      ['tests/integration/local-runtime/run-compose-e2e.sh', ...args],
      {
        encoding: 'utf8',
        // No executable allocator exists on PATH: the option boundary must reject first.
        env: {
          PATH: '/nonexistent',
          OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY: '1',
          ...extra,
        },
      },
    );
    assert.equal(result.status, 96, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  }
});

test('envelope browser evaluations remain self-contained after named TypeScript transformation', async () => {
  const ts = await import('typescript');
  const { transform } = createRequire(import.meta.resolve('tsx'))('esbuild');
  const input = await readFile(
    'tests/integration/local-runtime/envelope-recovery-browser.ts',
    'utf8',
  );
  const source = ts.createSourceFile(
    'envelope-recovery-browser.ts',
    input,
    ts.ScriptTarget.ESNext,
    true,
  );
  const callbacks = [];
  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'evaluate'
    ) {
      const callback = node.arguments[0];
      if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)))
        callbacks.push(callback.getText(source));
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  assert.ok(callbacks.length >= 3);
  for (const callback of callbacks) {
    const compiled = await transform(`export default ${callback}`, {
      loader: 'ts',
      format: 'esm',
      keepNames: true,
      target: 'es2024',
    });
    const module = await import(
      `data:text/javascript;base64,${Buffer.from(compiled.code).toString('base64')}`
    );
    assert.doesNotMatch(String(module.default), /__name\(/);
  }
});

test('ordinary runtime suite reaches the envelope recovery browser and its type preflight', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  assert.match(
    source,
    /suite_step envelope-recovery env OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY=1 bash/,
  );
  assert.match(
    source,
    /--module esnext --moduleResolution bundler .*envelope-recovery-browser\.ts/,
  );
  assert.match(
    source,
    /node --import tsx tests\/integration\/local-runtime\/envelope-recovery-browser\.ts "\$secret_root"/,
  );
  assert.match(source, /vitest run --config vitest.config.ts --project browser-components/);
  assert.doesNotMatch(source, /pnpm --filter @openpc\/admin-web check/);
  const browser = source.indexOf(
    'node --import tsx tests/integration/local-runtime/envelope-recovery-browser.ts "$secret_root"',
  );
  assert.ok(
    browser > 0 &&
      browser <
        source.indexOf('-- The initial policy fixture retains its required approval reference.'),
  );
  assert.match(
    source.slice(browser, source.indexOf('operator_principal_id=', browser)),
    /\n {2}exit 0\nfi/,
  );
});

test('governance skips the absent Control API fixture while selected consumers fail closed', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const start = source.indexOf('if [[ $governance_browser_only != 1 ]]; then');
  assert.ok(start > 0);
  const dispatch = source.slice(start, source.indexOf('\nfi', start) + 3);
  for (const governance of [1, 0]) {
    const result = spawnSync(
      '/usr/bin/bash',
      [
        '-c',
        `set -u; governance_browser_only=${governance}; data_root=/unused; declare -A openpc_built_images=(); ${dispatch}`,
      ],
      {
        encoding: 'utf8',
        env: { PATH: '/nonexistent' },
      },
    );
    if (governance === 1) {
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, '');
    } else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /openpc_built_images\[control-api\].*unbound variable/);
    }
  }
});

test('governance skips RPC fixture pinning while selected provider absence fails before inspection', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const marker = source.indexOf('# Qualification pins this owned external fixture address.');
  const start = source.indexOf('if [[ $governance_browser_only != 1 ]]; then', marker);
  const end = source.indexOf('\ncontrol_container=', start);
  assert.ok(marker > 0 && start > marker && end > start);
  const dispatch = source.slice(start, end);
  for (const governance of [1, 0]) {
    const result = spawnSync(
      '/usr/bin/bash',
      ['-c', `set -eu; governance_browser_only=${governance}; compose=(true); ${dispatch}`],
      {
        encoding: 'utf8',
        env: { PATH: '/nonexistent' },
      },
    );
    assert.equal(result.status, governance === 1 ? 0 : 96, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(
      result.stderr,
      governance === 1 ? '' : 'OPENPC_RPC_PROVIDER|FAIL|missing-selected-provider\n',
    );
  }
});

test('runtime source bootstrap reads Docker health, scoped login and exact owned mounts', () => {
  const root = '/owned/local-runtime',
    project = 'openpc-local-e2e-0123456789ab';
  const config = {
    database_role: 'openpc_rs_login_expected',
    database_password_file: '/run/secrets/runtime_source_database_password',
  };
  const container = {
    Config: {
      Labels: {
        'com.docker.compose.project': project,
        'com.docker.compose.service': 'control-worker',
      },
      User: '65532:65532',
      Env: [
        `CONTROL_WORKER_DATABASE_USER=${config.database_role}`,
        `CONTROL_WORKER_DATABASE_PASSWORD_FILE=${config.database_password_file}`,
      ],
    },
    State: { Running: true, Health: { Status: 'healthy', FailingStreak: 0, Log: [] } },
    Mounts: [
      {
        Source: `${root}/data/runtime-source-journal`,
        Destination: '/runtime-source-journal',
        RW: true,
      },
      {
        Source: `${root}/retained-runtime-source`,
        Destination: '/runtime-source-retained',
        RW: true,
      },
    ],
    NetworkSettings: { Networks: { owned: { IPAddress: '172.16.16.9' } } },
  };
  const verify = (value) => verifyRuntimeSourceContainer(value, { root, project, config });
  assert.deepEqual(verify(container), ['172.16.16.9']);
  for (const mutate of [
    (value) => {
      value.State.Health = { status: 'healthy' };
    },
    (value) => {
      value.State.Health.Status = 'unhealthy';
    },
    (value) => {
      value.State.Running = false;
    },
    (value) => {
      value.Config.Env[0] = 'CONTROL_WORKER_DATABASE_USER=openpc_local_control_worker';
    },
    (value) => {
      value.Mounts[1].Source = `${root}/data/runtime-source-journal`;
    },
    (value) => {
      value.Mounts.push({
        Source: `${root}/secrets/control_pg_password.txt`,
        Destination: '/secret',
        RW: false,
      });
    },
    (value) => {
      value.NetworkSettings.Networks = {};
    },
  ]) {
    const altered = structuredClone(container);
    mutate(altered);
    assert.throws(() => verify(altered));
  }
});

test('runtime source startup denial requires attack-specific stage and rejects unrelated or later failures', () => {
  const expected = { stage: 'configuration', reason: 'configuration_missing' };
  const rejection = { event: 'runtime_source_startup_rejected', phase: 'startup', ...expected };
  const stopped = { event: 'control_worker_stopped', phase: 'runtime_source_custody' };
  const failure = (events, extra = {}) => ({
    code: 1,
    stderr: events.map((event) => JSON.stringify(event)).join('\n'),
    ...extra,
  });
  assert.equal(isSourceStartupRejection(failure([rejection, stopped]), expected), true);
  for (const error of [
    failure([stopped]),
    failure([{ ...rejection, stage: 'control', reason: 'control_unavailable' }, stopped]),
    failure([{ ...rejection, reason: 'configuration_unavailable' }, stopped]),
    failure([{ ...rejection, stage: 'native_custody', reason: 'custody_unavailable' }, stopped]),
    failure([{ ...rejection, stage: 'currentness', reason: 'currentness_unavailable' }, stopped]),
    failure([{ ...stopped, phase: 'runtime_source_custody_ongoing' }]),
    failure([rejection, { ...stopped, phase: 'runtime_source_custody_ongoing' }]),
    failure([rejection, rejection, stopped]),
    failure([rejection, stopped], { code: 'ETIMEDOUT', killed: true }),
    failure([rejection, stopped], { signal: 'SIGTERM' }),
  ])
    assert.equal(isSourceStartupRejection(error, expected), false);
});

test('runtime predecessor denials use the shared exact startup oracle and reject ordinary process failures', async () => {
  const { rejectPredecessorStartup } = await import('./runtime-source-predecessor-runtime.mjs');
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  assert(parent?.startsWith('/'));
  const root = await mkdtemp(join(parent, 'predecessor-denial-'));
  const binary = join(root, 'worker');
  const event = {
    event: 'runtime_source_startup_rejected',
    phase: 'startup',
    stage: 'installation',
    reason: 'predecessor_rollback',
  };
  const stopped = { event: 'control_worker_stopped', phase: 'runtime_source_custody' };
  try {
    for (const [reason, code, accepted] of [
      ['predecessor_rollback', 1, true],
      ['installation_unavailable', 1, false],
      ['predecessor_rollback', 0, false],
      ['unrelated_io', 1, false],
    ]) {
      const lines = [JSON.stringify({ ...event, reason }), JSON.stringify(stopped)];
      await writeFile(
        binary,
        `#!/bin/sh\nprintf '%s\\n' '${lines[0]}' '${lines[1]}' >&2\nexit ${code}\n`,
        { mode: 0o700 },
      );
      const result = rejectPredecessorStartup(binary, process.env, 'predecessor_rollback');
      if (accepted) await result;
      else await assert.rejects(result);
    }
  } finally {
    await rm(root, { recursive: true });
  }
});

test('runtime source transport retries preserve prior fault endpoints and private permissions', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'source-transport-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const first = await writeSourceImportProxyOverride(root, '172.16.12.1', 33531);
  const original = await readFile(first);
  const second = await writeSourceImportProxyOverride(root, '172.16.12.1', 33532);
  assert.notEqual(first, second);
  assert.deepEqual(await readFile(first), original);
  for (const [path, port] of [
    [first, '33531'],
    [second, '33532'],
  ]) {
    assert.equal((await stat(dirname(path))).mode & 0o777, 0o700);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), {
      services: {
        'control-worker': {
          environment: {
            CONTROL_WORKER_DATABASE_HOST: '172.16.12.1',
            CONTROL_WORKER_DATABASE_PORT: port,
          },
        },
      },
    });
  }
});

test('runtime source original resume rejects replacement identities, altered signed bytes and duplicate imports', () => {
  const identity = {
    input_id: 'original-input',
    module_installation_id: 'original-module',
    module_configuration_generation_id: 'original-generation',
    configuration_digest: 'a'.repeat(64),
  };
  const wire = (observation) => [
    ...Buffer.from(
      JSON.stringify({
        purpose: 'openpc:runtime-artifact-source-history:v1',
        claims: { observation },
      }),
    ),
  ];
  const original = { identity, pending: wire({ ImportPending: identity }) };
  const committed = wire({ ImportCommitted: identity });
  const journal = (originals) => Buffer.from(JSON.stringify({ history: { originals } }));
  verifyOriginalSourceJournal(journal([original.pending]), original, false);
  verifyOriginalSourceJournal(journal([original.pending, committed]), original, true);
  for (const records of [
    [original.pending],
    [original.pending, committed, committed],
    [original.pending, original.pending, committed],
    [wire({ ImportPending: { ...identity, input_id: 'new-intent' } }), committed],
    [
      original.pending,
      wire({
        ImportCommitted: { ...identity, module_configuration_generation_id: 'new-generation' },
      }),
    ],
    [[...original.pending, 32], committed],
  ])
    assert.throws(() => verifyOriginalSourceJournal(journal(records), original, true));
});

test('runtime source bootstrap preflight checks actual fixture files, mounts and execution user', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'source-mount-preflight-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const file of [
    'signing-provider-runtime.mjs',
    'workload-issuer-runtime.mjs',
    'workload-issuer-manifest.json',
  ])
    await writeFile(join(root, file), '{}');
  const mount = (file, target) => ({
    type: 'bind',
    source: join(root, file),
    target,
    read_only: true,
  });
  const config = {
    services: {
      'control-api': { environment: { CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID: sourceScope.privacy } },
      'control-worker': { environment: { CONTROL_WORKER_PRIVACY_DOMAIN_ID: sourceScope.privacy } },
      'signing-provider': {
        environment: { OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID: sourceScope.privacy },
        user: `${process.getuid()}:${process.getgid()}`,
        volumes: [mount('signing-provider-runtime.mjs', '/app/server.mjs')],
      },
      'workload-issuer': {
        user: `${process.getuid()}:${process.getgid()}`,
        volumes: [
          mount('workload-issuer-runtime.mjs', '/app/server.mjs'),
          mount('workload-issuer-manifest.json', '/issuer/manifest.json'),
        ],
      },
    },
  };
  const path = join(root, 'compose.json');
  const check = async (value) => {
    await writeFile(path, JSON.stringify(value));
    return spawnSync(
      'bash',
      [
        '-c',
        `
      set -euo pipefail
      source tests/integration/local-runtime/runner-harness.sh
      data_root=$1
      openpc_runtime_fixture_environment
      # Preserve the fixture path independently of the Compose command args.
      root=$1
      compose() { cat "$root/compose.json"; }
      compose=(compose)
      OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=$2
      openpc_first_policy_scope_preflight
    `,
        'fixture-mount-test',
        root,
        sourceScope.privacy,
      ],
      { encoding: 'utf8' },
    );
  };
  assert.equal((await check(config)).status, 0);
  for (const field of ['source', 'read_only', 'user']) {
    const invalid = structuredClone(config),
      service = invalid.services['signing-provider'];
    if (field === 'source') service.volumes[0].source = join(root, 'default-missing-bundle');
    else if (field === 'read_only') service.volumes[0].read_only = false;
    else service.user = '0:0';
    assert.notEqual((await check(invalid)).status, 0);
  }
  await rm(join(root, 'signing-provider-runtime.mjs'));
  await mkdir(join(root, 'signing-provider-runtime.mjs'));
  assert.notEqual((await check(config)).status, 0);
});

test('runtime source bootstrap registers its independent retained root and rejects aliases', async (t) => {
  const parent = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'source-root-boundary-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, 'runtime');
  await mkdir(root);
  for (const directory of [
    'data',
    'secrets',
    'evidence',
    'retained-runtime-source',
    'runtime-source-archive',
  ])
    await mkdir(join(root, directory));
  await writeFile(join(root, '.openpc-local-runtime-owner'), 'owned-root\n');
  const validate = () =>
    spawnSync(
      'bash',
      [
        '-c',
        `
    set -euo pipefail
    source tests/integration/local-runtime/runner-harness.sh
    run_root=$1 canonical_external_root=$2
    data_root=$1/data secret_root=$1/secrets evidence_root=$1/evidence
    owner_sentinel=$1/.openpc-local-runtime-owner owner_record=owned-root
    validate_run_root
  `,
        'source-root-test',
        root,
        parent,
      ],
      { encoding: 'utf8' },
    );
  assert.equal(validate().status, 0);
  await rm(join(root, 'retained-runtime-source'), { recursive: true });
  await symlink(join(root, 'data'), join(root, 'retained-runtime-source'));
  assert.notEqual(validate().status, 0);
  await rm(join(root, 'retained-runtime-source'));
  await mkdir(join(root, 'unregistered-root'));
  assert.notEqual(validate().status, 0);
});

test('retained runtime input admission rejects unsafe roots and omitted hooks before build or service callbacks', async (t) => {
  const parent = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'retained-input-admission-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const token = 'a'.repeat(64),
    project = `openpc-local-e2e-${token.slice(0, 12)}`;
  for (const mode of [
    'valid',
    'fresh',
    'no-spool',
    'unknown-root',
    'alias-root',
    'alias-retained',
    'foreign-owner',
    'foreign-project',
    'unlocked',
    'missing-overlay',
    'duplicate-overlay',
    'keeper-failed',
    'retain-failed',
  ]) {
    const root = join(parent, mode);
    await mkdir(root);
    for (const directory of [
      'data/runtime-bootstrap',
      'secrets',
      'evidence/runtime-bootstrap',
      'retained-runtime-source',
    ])
      await mkdir(join(root, directory), { recursive: true });
    const original = `openpc-local-runtime:${project}:${token}\n`;
    await writeFile(
      join(root, '.openpc-local-runtime-owner'),
      mode === 'foreign-owner' ? 'foreign\n' : original,
    );
    const overlay = join(root, 'data/runtime-bootstrap/compose.json');
    await writeFile(overlay, '{}');
    const input = mode === 'no-spool' ? {} : { rpcJournalEnospc: { ownerToken: token, project } };
    if (mode !== 'fresh')
      await writeFile(
        join(root, 'evidence/runtime-bootstrap/discovery-credential-input.json'),
        JSON.stringify(input),
      );
    if (mode === 'unknown-root') await writeFile(join(root, 'unregistered'), 'preserved');
    if (mode === 'alias-root') await symlink(root, `${root}-alias`);
    if (mode === 'alias-retained') {
      await rm(join(root, 'retained-runtime-source'), { recursive: true });
      await symlink(join(root, 'data'), join(root, 'retained-runtime-source'));
    }
    for (const entry of ['build', 'runtime']) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
repository_root=$PWD run_root=$1 canonical_external_root=$2 project=$3 mode=$4 entry=$5
data_root=$run_root/data secret_root=$run_root/secrets evidence_root=$run_root/evidence
owner_sentinel=$run_root/.openpc-local-runtime-owner
owner_record="openpc-local-runtime:$project:${token}"
export OPENPC_RUNTIME_OWNER_PID=$$
exec 8<"$owner_sentinel"
if [[ $mode != unlocked ]]; then flock -n 8; fi
openpc_require_heavy_lock() { return 0; } # Additional root ownership is real here.
compose=(docker compose -p "$project" -f "$repository_root/deploy/compose/local/compose.yaml")
if [[ $mode == foreign-project ]]; then compose[3]=openpc-local-e2e-bbbbbbbbbbbb; fi
if [[ $mode != missing-overlay ]]; then compose+=(-f "$data_root/runtime-bootstrap/compose.json"); fi
if [[ $mode == duplicate-overlay ]]; then compose+=(-f "$data_root/runtime-bootstrap/compose.json"); fi
node() {
  if [[ $1 == */rpc-journal-enospc-runtime.mjs ]]; then
    openpc_rpc_enospc_preflight "$3" "$4" "$2" || return
    [[ $mode != keeper-failed && ! ( $mode == retain-failed && $2 == retain ) ]] || return 96
    printf 'custody=%s\\n' "$2" >&2
  else command node "$@"; fi
}
openpc_validate_build_inputs() { return 0; }
openpc_builder=owned governance_browser_only=1
docker() { printf 'callback=build\\n'; }
if [[ $entry == build ]]; then
  openpc_build_selected_images control-worker
else
  openpc_fixture_preflight
  printf 'callback=runtime\\n'
fi`,
          'retained-input-test',
          mode === 'alias-root' ? `${root}-alias` : root,
          parent,
          project,
          mode,
          entry,
        ],
        {
          encoding: 'utf8',
          env: Object.fromEntries(
            Object.entries(process.env).filter(
              ([name]) => !/^OPENPC_LOCAL_RUNTIME_.*_ONLY$/u.test(name),
            ),
          ),
        },
      );
      const valid = ['valid', 'fresh', 'no-spool'].includes(mode);
      assert.equal(result.status, valid ? 0 : 96, `${mode}/${entry}: ${result.stderr}`);
      if (valid) assert.match(result.stdout, /callback=/u);
      else assert.doesNotMatch(result.stdout, /callback=/u);
      if (mode === 'valid') assert.match(result.stderr, /custody=inspect\ncustody=retain/u);
      if (['fresh', 'no-spool'].includes(mode)) assert.doesNotMatch(result.stderr, /custody=/u);
    }
    assert.equal(await readFile(overlay, 'utf8'), '{}');
    assert.equal(
      await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'),
      mode === 'foreign-owner' ? 'foreign\n' : original,
    );
  }
});

test('spool resume is idempotent across the actual wrapped Compose arguments', () => {
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
run_root=/owned repository_root=$PWD
openpc_network_compose_command=(docker compose -p owned -f /owned/base.json)
openpc_target_compose_command=(openpc_network_compose)
compose=(openpc_target_compose)
openpc_network_check() { return 0; }
openpc_rpc_enospc_present() { return 0; }
node() { if [[ $1 == */rpc-journal-enospc-runtime.mjs ]]; then [[ $2 == inspect ]]; else command node "$@"; fi; }
openpc_rpc_enospc_before_resume
openpc_rpc_enospc_before_resume
openpc_compose_json`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [
    'docker',
    'compose',
    '-p',
    'owned',
    '-f',
    '/owned/base.json',
    '-f',
    '/owned/data/runtime-bootstrap/compose.json',
  ]);
});

test('runtime source bootstrap confines installer credentials and rejects scope or mount substitution', () => {
  const root = '/owned/local-runtime';
  const config = {
    installation: {
      participant_id: sourceScope.participant,
      privacy_domain_id: sourceScope.privacy,
    },
    database_role: `openpc_rs_login_${'a'.repeat(43)}`,
    source_file: '/provider-sources/runtime-configuration.cbor',
    journal_directory: '/runtime-source-journal/owner',
    retained_root: { directory: '/runtime-source-retained/owner' },
    signing_key_file: '/run/secrets/runtime_source_signing_key',
    commit_key_file: '/run/secrets/runtime_source_commit_key',
    database_password_file: '/run/secrets/runtime_source_database_password',
  };
  const overlay = sourceOverlay(root, config);
  const worker = overlay.services['control-worker'];
  assert.equal(worker.environment.CONTROL_WORKER_DATABASE_USER, config.database_role);
  assert.equal(
    overlay.services['control-migrate'].environment.OPENPC_CONTROL_WORKER_TRUST_ROLE,
    config.database_role,
  );
  assert.ok(worker.volumes.includes(`${root}/retained-runtime-source:/runtime-source-retained`));
  assert.ok(!JSON.stringify(worker).includes('control_pg_password'));
  assert.ok(!JSON.stringify(worker).includes('installer_database_password'));
  assert.ok(!worker.volumes.some((mount) => mount.startsWith(`${root}/secrets:`)));
  const materialization = sourceOverlay(root, {
    ...config,
    retained_root: {
      ...config.retained_root,
      binding: { consumer_profile: 'openpc:local-runtime-source-consumers:v2' },
    },
  });
  for (const reader of ['control-api', 'policy-service', 'fact-service', 'runtime-target']) {
    assert.deepEqual(materialization.services[reader], {
      environment: {
        OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY: '/run/openpc-runtime-source',
      },
      volumes: [`${root}/data/runtime-source-ipc:/run/openpc-runtime-source:ro`],
    });
  }
  assert.ok(
    materialization.services['control-worker'].volumes.includes(
      `${root}/data/runtime-source-ipc:/run/openpc-runtime-source`,
    ),
  );
  assert.equal(overlay.services['control-api'], undefined);
  assert.equal(overlay.services['runtime-target'], undefined);
  const archiveConfig = {
    ...config,
    retained_root: {
      ...config.retained_root,
      binding: { consumer_profile: 'openpc:local-runtime-source-consumers:v2' },
    },
    archive_custody: structuredClone(runtimeArchiveConfiguration),
  };
  const archive = sourceOverlay(root, archiveConfig);
  assert.ok(
    archive.services['control-worker'].volumes.includes(
      `${root}/runtime-source-archive:/runtime-source-archive:ro`,
    ),
  );
  for (const reader of ['control-api', 'policy-service', 'fact-service', 'runtime-target'])
    assert.ok(!JSON.stringify(archive.services[reader]).includes('/runtime-source-archive'));
  for (const change of [
    { ...runtimeArchiveConfiguration, stream_id: 'uninstalled-stream' },
    { ...runtimeArchiveConfiguration, database_password_file: '/run/secrets/control_pg_password' },
    {
      ...runtimeArchiveConfiguration,
      keys: { 'runtime-source-archive-key': '/run/secrets/shared-key' },
    },
  ])
    assert.throws(() => sourceOverlay(root, { ...archiveConfig, archive_custody: change }));
  assert.throws(() =>
    sourceOverlay(root, {
      ...archiveConfig,
      retained_root: {
        ...config.retained_root,
        binding: { consumer_profile: 'openpc:local-runtime-source-consumers:v1' },
      },
    }),
  );
  for (const change of [
    { database_role: 'openpc_control' },
    { database_password_file: '/run/secrets/control_pg_password' },
    { retained_root: { directory: '/runtime-source-journal/owner' } },
    { source_file: '/unbound/source.cbor' },
    {
      installation: {
        ...config.installation,
        privacy_domain_id: '018f0000-0000-7000-8000-000000000201',
      },
    },
  ])
    assert.throws(() => sourceOverlay(root, { ...config, ...change }));
});

test('source-first QA source overlay pins its explicit primary scope and confines installer credentials', () => {
  const config = {
    installation: {
      participant_id: qaSourceScope.participant,
      privacy_domain_id: qaSourceScope.privacy,
    },
    database_role: `openpc_rs_login_${'a'.repeat(43)}`,
    source_file: '/provider-sources/runtime-configuration.cbor',
    journal_directory: '/runtime-source-journal/owner',
    retained_root: { directory: '/runtime-source-retained/owner' },
    signing_key_file: '/run/secrets/runtime_source_signing_key',
    commit_key_file: '/run/secrets/runtime_source_commit_key',
    database_password_file: '/run/secrets/runtime_source_database_password',
  };
  const worker = sourceOverlay('/owned/qa-source', config, qaSourceScope).services[
    'control-worker'
  ];
  assert.equal(worker.environment.CONTROL_WORKER_PARTICIPANT_ID, qaSourceScope.participant);
  assert.equal(worker.environment.CONTROL_WORKER_PRIVACY_DOMAIN_ID, qaSourceScope.privacy);
  assert.equal(worker.environment.CONTROL_WORKER_DATABASE_USER, config.database_role);
  assert.ok(!JSON.stringify(worker).includes('installer_database_password'));
  assert.ok(!JSON.stringify(worker).includes('control_pg_password'));
  assert.throws(() => sourceOverlay('/owned/qa-source', config));
  assert.throws(() =>
    sourceOverlay('/owned/qa-source', config, { ...qaSourceScope, privacy: sourceScope.privacy }),
  );
  assert.throws(() =>
    sourceOverlay('/owned/qa-source', config, {
      ...qaSourceScope,
      privacy: '018f0000-0000-7000-8000-000000009999',
    }),
  );
});

test('source-first QA rejects invalid opt-in before allocating runtime state', () => {
  for (const environment of [
    { OPENPC_LOCAL_QA_ROOTED_SOURCE: '1' },
    { OPENPC_LOCAL_QA_ROOTED_SOURCE: '1', OPENPC_LOCAL_RUNTIME: '1' },
    {
      OPENPC_LOCAL_QA_ROOTED_SOURCE: '0',
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    },
    {
      OPENPC_LOCAL_QA_ROOTED_SOURCE: 'true',
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    },
  ]) {
    const result = spawnSync(
      '/usr/bin/bash',
      ['tests/integration/local-runtime/run-compose-e2e.sh'],
      {
        env: { PATH: '/nonexistent', ...environment },
        encoding: 'utf8',
      },
    );
    assert.equal(result.status, 96);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  }
});

test('source-first QA prepares only a new explicit primary configuration and rejects reenrollment', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'source-first-qa-'));
  try {
    await mkdir(join(root, 'data'));
    await mkdir(join(root, 'secrets'));
    const invoke = (environment) =>
      spawnSync(
        process.execPath,
        [
          'tests/integration/local-runtime/runtime-source-bootstrap.mjs',
          'prepare',
          root,
          'qa-primary',
        ],
        { env: { ...process.env, ...environment }, encoding: 'utf8' },
      );
    const disabled = invoke({
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      OPENPC_LOCAL_QA_ROOTED_SOURCE: '0',
    });
    assert.notEqual(disabled.status, 0);
    assert.deepEqual(await readdir(join(root, 'data')), []);
    assert.deepEqual(await readdir(join(root, 'secrets')), []);
    const environment = {
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      OPENPC_LOCAL_QA_ROOTED_SOURCE: '1',
    };
    assert.equal(invoke(environment).status, 0);
    const path = join(root, 'data/runtime-source-config/input.json');
    const bytes = await readFile(path);
    const input = JSON.parse(bytes);
    assert.equal(input.participant_id, qaSourceScope.participant);
    assert.equal(input.privacy_domain_id, qaSourceScope.privacy);
    assert.deepEqual(await readdir(join(root, 'data/runtime-source-journal')), []);
    assert.deepEqual(await readdir(join(root, 'retained-runtime-source')), []);
    assert.notEqual(invoke(environment).status, 0);
    assert.deepEqual(await readFile(path), bytes);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('source-first QA key reuse rolls back before identity seeding and redacts secret diagnostics', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'source-first-redaction-'));
  const sourceKey = createECDH('prime256v1');
  sourceKey.generateKeys();
  const reusedKey = Buffer.alloc(32, 66),
    otherKey = Buffer.alloc(32, 119);
  try {
    const secrets = join(root, 'secrets'),
      configRoot = join(root, 'data/runtime-source-config');
    await mkdir(secrets);
    await mkdir(configRoot, { recursive: true });
    const config = {
      installation: {
        participant_id: qaSourceScope.participant,
        privacy_domain_id: qaSourceScope.privacy,
        source_owner_id: '018f0000-0000-7000-8000-000000008901',
        source_file_binding: 'a'.repeat(64),
      },
      database_role: `openpc_rs_login_${'a'.repeat(43)}`,
      source_file: '/provider-sources/runtime-configuration.cbor',
      journal_directory: '/runtime-source-journal/owner',
      retained_root: {
        directory: '/runtime-source-retained/owner',
        binding: { generation_id: '018f0000-0000-7000-8000-000000008902' },
      },
      signing_key_file: '/run/secrets/runtime_source_signing_key',
      commit_key_file: '/run/secrets/runtime_source_commit_key',
      database_password_file: '/run/secrets/runtime_source_database_password',
      fresh_scope: {
        privacy_domain_name: 'Local QA source',
        residency_profile: 'LOCAL_DEVELOPMENT',
      },
    };
    await writeFile(join(configRoot, 'configuration.json'), JSON.stringify(config));
    await writeFile(join(secrets, 'runtime_source_signing_key'), sourceKey.getPrivateKey());
    await writeFile(join(secrets, 'runtime_source_commit_key'), reusedKey);
    await writeFile(join(secrets, 'fleet_fact_admission_key.txt'), reusedKey.toString('hex'));
    await writeFile(join(secrets, 'runtime_target_disposition_key.txt'), otherKey.toString('hex'));
    const row = {
      root_privacy_domain_id: qaSourceScope.privacy,
      participant_state: 'ACTIVE',
      privacy_state: 'ACTIVE',
      domain_name: config.fresh_scope.privacy_domain_name,
      placement_profile: 'PARTICIPANT_LOCAL',
      residency_profile: config.fresh_scope.residency_profile,
      ...config.installation,
      database_role: config.database_role,
      custody_root: config.retained_root.binding,
      installation_reference: `native-source-root:${config.retained_root.binding.generation_id}`,
      commit_key_matches: true,
      archive_custody: null,
    };
    const script = `
      import {seedQa} from './tests/integration/local-runtime/qa-sandbox.mjs';
      const calls=[];const row=JSON.parse(process.argv[2]);row.source_public_key=Buffer.from(process.argv[3],'hex');
      const client={query:async(sql)=>{calls.push(sql);
        if(sql.includes('join control.runtime_artifact_source s'))return {rows:[row]};
        if(sql.includes('verifier_secret=$2'))return {rows:[{matches:true}]};
        return {rows:[],rowCount:0};}};
      try{await seedQa(client,process.argv[1]);process.exitCode=2;}
      catch(error){console.error(error);console.log(JSON.stringify({rollback:calls.includes('rollback'),seeded:calls.some(sql=>/^insert /i.test(sql))}));process.exitCode=1;}
    `;
    const result = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '--input-type=module',
        '-e',
        script,
        secrets,
        JSON.stringify(row),
        sourceKey.getPublicKey(undefined, 'compressed').toString('hex'),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 1);
    assert.deepEqual(JSON.parse(result.stdout), { rollback: true, seeded: false });
    assert.match(result.stderr, /Runtime source initial trust verification failed/u);
    assert.doesNotMatch(result.stderr, /Buffer|AssertionError|cause:|66, 66|119, 119/u);
    for (const secret of [reusedKey, otherKey, sourceKey.getPrivateKey()])
      assert.ok(!(result.stdout + result.stderr).includes(secret.toString('hex')));
  } finally {
    reusedKey.fill(0);
    otherKey.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});
import './build-inputs.test.mjs';
import './withdrawal-commit-fault.test.mjs';
import './credential-continuity-commit-fault.test.mjs';
import '../../../scripts/maintenance/local-runtime-network.test.mjs';
import { deploymentResponse } from './rpc-deployment-fixture.mjs';
import { ciglResponse } from './rpc-cigl-fixture.mjs';
import { relationshipSourceFault, relationshipSourceLogs } from './rpc-source-header-fixture.mjs';
import { selectModuleReleases } from './module-release-selection.mjs';
import {
  prepareRpcJournalCrashFixture,
  assertRpcJournalFixtureAbi,
  rpcEnospcContractRegression,
} from './rpc-journal-crash-fixture.mjs';
import { assertPublicRpcDenial, assertRpcStorageFailure } from './evidence-rpc-runtime.mjs';

test('business profile catalogue covers every canonical signing action before allocation', async () => {
  const migration = await readFile('deploy/compose/local/migrate.sh', 'utf8');
  const start = migration.indexOf('INSERT INTO control.action_intent\n');
  const end = migration.indexOf('ON CONFLICT (action_intent_id)', start);
  assert.ok(start >= 0 && end > start, 'initial action catalogue must be explicit');
  const rows = [...migration.slice(start, end).matchAll(/\('([^']+)'([^\n]+)\)/gu)];
  const actions = new Map(rows.map(([, action, fields]) => [action, fields]));
  assert.equal(actions.size, rows.length, 'initial action catalogue must be unique');
  // Ordinary startup applies the generated migrations before the local catalogue.
  // Count only actual action INSERT statements, never references in guard bodies.
  const migratedActions = new Map();
  for (const owner of ['identity', 'policy', 'control-api']) {
    const path = `migrations/postgres/${owner}`;
    for (const name of (await readdir(path))
      .filter((name) => /^\d{4}_.*\.sql$/u.test(name))
      .sort()) {
      const sql = await readFile(join(path, name), 'utf8');
      for (const [, values] of sql.matchAll(
        /INSERT INTO control\.action_intent\s*\([^;]+?\)\s*VALUES\s*([^;]+?)ON CONFLICT/gu,
      )) {
        for (const [, action, fields] of values.matchAll(/\('([^']+)'([^\n]+?)\)/gu))
          migratedActions.set(action, fields);
      }
    }
  }
  for (const [action, fields] of actions) migratedActions.set(action, fields);
  const directory = 'schemas/canonical/business-transition-profiles';
  for (const name of (await readdir(directory)).filter((name) => name.endsWith('.json'))) {
    const profile = JSON.parse(await readFile(join(directory, name), 'utf8'));
    assert.ok(
      migratedActions.has(profile.actionIntentId),
      `${name}: missing ${profile.actionIntentId}`,
    );
    assert.ok(
      migratedActions.get(profile.actionIntentId).startsWith(`,'${profile.resourceType}',`),
      `${name}: action resource type mismatch`,
    );
  }
  // Registered updateModule metadata; registering an action grants no actor authority.
  assert.equal(
    actions.get('ACT-MODULES_UPDATE_RESOURCE-V1'),
    ",'modules','UPDATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_MODULES'",
  );
  for (const action of [
    'ACT-POLICY_VERSIONS_READ_COLLECTION-V1',
    'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
  ]) {
    assert.equal(
      actions.get(action),
      ",'policy-version','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_READ'",
      'Both policy-version read routes must be installed with their scoped read contract',
    );
  }
});

// Execute the actual dispatch slices, as the other runner boundary tests do.
// These command/admission seams test orchestration, not a real C1 runtime pass.
test('held heavy lock remains verifiable in a failing EXIT trap without clearing the original failure', async () => {
  const directory = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'heavy-exit-'),
  );
  try {
    for (const [owned, expected] of [
      [true, 'VERIFIED'],
      [false, 'DENIED'],
    ]) {
      const result = c1RunnerBoundaryResult(
        `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
repository_lock_root=$1
git() { printf '%s\\n' "$repository_lock_root"; }
export OPENPC_HEAVY_LOCK_OWNER_PID=''
${owned ? 'exec 9>"$repository_lock_root/openpc-heavy.lock"\nflock -n 9' : 'exec 9>&-'}
trap 'if openpc_require_heavy_lock; then echo VERIFIED; else echo DENIED; fi' EXIT
exit 37
`,
        [directory],
      );
      assert.equal(result.status, 37, result.stderr);
      assert.equal(result.stdout.trim(), expected);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('policy browser callers hand off guarded executable Compose arguments through both wrappers', async () => {
  for (const name of ['first-policy-journey.sh', 'evidence-rpc-admission.sh']) {
    const source = await readFile(`tests/integration/local-runtime/${name}`, 'utf8');
    const assignments = source
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => /^(?:export )?OPENPC_POLICY_SET_COMPOSE_JSON=/u.test(line));
    assert.equal(assignments.length, 2, name);
    for (const assignment of assignments) {
      const result = c1RunnerBoundaryResult(`set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
compose=(openpc_target_compose -f /owned/override.json)
openpc_target_compose_command=(openpc_network_compose)
openpc_network_compose_command=(docker compose -p owned -f /canonical/compose.yaml)
openpc_network_check() { [[ $* == 'before -f /owned/override.json' ]]; }
${assignment.replace(/\\\s*$/u, '')}
printf '%s' "$OPENPC_POLICY_SET_COMPOSE_JSON"
`);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), [
        'docker',
        'compose',
        '-p',
        'owned',
        '-f',
        '/canonical/compose.yaml',
        '-f',
        '/owned/override.json',
      ]);
    }
  }
});

function c1RunnerSection(source, start, end) {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first + start.length);
  assert.ok(first >= 0 && last > first, 'C1 runner section must remain executable');
  return source.slice(first, last);
}

function c1RunnerBoundaryResult(script, args = [], environment = {}) {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !name.startsWith('OPENPC_LOCAL_RUNTIME_') && !name.startsWith('OPENPC_BROWSER_'),
    ),
  );
  const result = spawnSync('bash', ['-c', script, 'c1-boundary', ...args], {
    encoding: 'utf8',
    timeout: 10000,
    env: { ...inherited, ...environment },
  });
  if (result.error)
    throw new Error(`C1 runner subprocess unavailable: ${result.error.code ?? 'UNKNOWN'}`);
  return result;
}

test('network startup rejects environment overrides and missing heavy ownership before inspection', () => {
  for (const override of ['', 'SUBNET', 'GATEWAY', 'OWNER', 'ROOT']) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
openpc_require_heavy_lock() { printf 'LOCK_DENIED\\n'; return 96; }
node() { printf 'UNEXPECTED_INSPECTION\\n'; return 97; }
openpc_network_initialize
`,
      [],
      override ? { [`OPENPC_LOCAL_RUNTIME_NETWORK_${override}`]: 'injected' } : {},
    );
    assert.equal(result.status, 96, result.stderr);
    assert.equal(result.stdout, override ? '' : 'LOCK_DENIED\n');
    if (override) assert.match(result.stderr, /environment-override/u);
  }
});

test('retained network check renders the actual admitted overlay and rejects a substituted path', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT ?? '/tmp', 'network-overlay-'));
  try {
    await mkdir(join(root, 'data'));
    await writeFile(join(root, 'data/local-runtime-network.json'), '{}');
    for (const substitute of ['0', '1']) {
      const result = c1RunnerBoundaryResult(
        `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
run_root=$1 repository_root=$PWD project=owned owner_token=token reuse_images=1 substitute=$2
compose=(render -p owned -f /canonical/compose.yaml)
openpc_require_heavy_lock() { :; }
node() {
  case "$2" in
    plan) printf '192.168.48.0/24 192.168.48.1\\n';;
    compose-overlay) if [[ $substitute == 1 ]]; then printf '/foreign/overlay.json\\n'; else printf '%s/data/local-runtime-network.json\\n' "$run_root"; fi;;
    before) cat;;
    *) return 99;;
  esac
}
render() { printf '%s\\n' "$@"; }
openpc_network_initialize
# The ordinary entrypoint captures the admitted command after initialization.
openpc_network_compose_command=("\${compose[@]}")
openpc_network_check before
`,
        [root, substitute],
      );
      assert.equal(result.status, substitute === '1' ? 96 : 0, result.stderr);
      assert.deepEqual(
        result.stdout.trim().split('\n'),
        substitute === '1'
          ? ['']
          : [
              '-p',
              'owned',
              '-f',
              '/canonical/compose.yaml',
              '-f',
              join(root, 'data/runtime-bootstrap/compose.json'),
              '-f',
              join(root, 'data/local-runtime-network.json'),
              '--profile',
              'astra05',
              'config',
              '--format',
              'json',
            ],
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('explicit retained network recovery is isolated from ordinary reuse and business startup', async () => {
  for (const [args, status] of [
    [['--recover-network', '--resume-root', '/owned/local-runtime.original'], 0],
    [['--recover-network'], 96],
    [
      ['--recover-network', '--recover-network', '--resume-root', '/owned/local-runtime.original'],
      96,
    ],
    [['--recover-network', '--reuse-images', '--resume-root', '/owned/local-runtime.original'], 96],
    [
      [
        '--recover-network',
        '--refresh-from',
        'a'.repeat(40),
        '--resume-root',
        '/owned/local-runtime.original',
      ],
      96,
    ],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_runner_arguments "$@"
printf 'RECOVERY|%s\\n' "$recover_network"
`,
      args,
    );
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout, status ? '' : 'RECOVERY|1\n');
  }
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const recovery = c1RunnerSection(
    source,
    'if [[ $recover_network == 1 ]]; then',
    'if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then',
  );
  for (const failure of [0, 96]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
recover_network=1 failure=$1
openpc_require_execution() { [[ $1 == focused ]]; printf 'ADMISSION\\n'; }
realpath() { printf '/owned\\n'; }
openpc_resume_root() { [[ $1 == network-recovery ]]; secret_root=/owned/secrets data_root=/owned/data; printf 'LOCK_ORIGINAL\\n'; }
openpc_network_recover_retained() { printf 'RECOVERY\\n'; return "$failure"; }
${recovery}
printf 'UNEXPECTED_BUSINESS_STARTUP\\n'
`,
      [String(failure)],
      { OPENPC_LOCAL_RUNTIME_TMP_ROOT: '/owned' },
    );
    assert.equal(result.status, failure, result.stderr);
    assert.equal(result.stdout, 'ADMISSION\nLOCK_ORIGINAL\nRECOVERY\n');
  }
});

test('network dispatch verifies a stopped anchor before consumers and stops on either failed check', () => {
  for (const mode of ['fresh', 'existing', 'before-failed', 'create-failed', 'verify-failed']) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
mode=$1 openpc_network_phase=fresh
openpc_network_compose_command=(external_compose)
# These external command seams exercise dispatch ordering, not live authority.
openpc_network_check() {
  [[ $* == "$1 -f /owned/override.json" ]] || return 97
  printf 'CHECK|%s\\n' "$1" >&2
  [[ $mode != "$1-failed" ]] || return 96
  if [[ $mode == existing ]]; then printf 'existing\\n'; else printf 'absent\\n'; fi
}
external_compose() {
  [[ $1 == -f && $2 == /owned/override.json ]] || return 97
  shift 2
  if [[ $1 == create ]]; then
    [[ $* == 'create --no-build --pull missing control-pg' ]] || return 97
    printf 'STOPPED_ANCHOR\\n' >&2
    [[ $mode != create-failed ]] || return 96
  else
    [[ $* == 'up -d control-pg' ]] || return 97
    printf 'CONSUMER\\n' >&2
  fi
}
openpc_network_compose -f /owned/override.json up -d control-pg
`,
      [mode],
    );
    const expected = {
      'fresh': ['CHECK|before', 'STOPPED_ANCHOR', 'CHECK|verify', 'CONSUMER'],
      'existing': ['CHECK|before', 'CONSUMER'],
      'before-failed': ['CHECK|before'],
      'create-failed': ['CHECK|before', 'STOPPED_ANCHOR'],
      'verify-failed': ['CHECK|before', 'STOPPED_ANCHOR', 'CHECK|verify'],
    }[mode];
    assert.equal(result.status, mode.endsWith('failed') ? 96 : 0, result.stderr);
    assert.deepEqual(result.stderr.trim().split('\n'), expected);
    assert.equal(result.stdout, '');
  }
});

test('network command handoff checks fresh inputs without allocating and refuses changed topology', () => {
  for (const failure of [0, 96]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
failure=$1
compose=(openpc_network_compose -f /owned/override.json)
openpc_network_compose_command=(docker compose -p owned -f /source/compose.yaml)
openpc_network_check() { [[ $* == 'before -f /owned/override.json' ]] || return 97; printf 'CHECK\\n' >&2; return "$failure"; }
openpc_network_ensure() { printf 'UNEXPECTED_ALLOCATION\\n' >&2; return 97; }
node() { shift 2; printf '%s\\n' "$*"; }
openpc_compose_json
`,
      [String(failure)],
    );
    assert.equal(result.status, failure, result.stderr);
    assert.equal(result.stderr, 'CHECK\n');
    assert.equal(
      result.stdout,
      failure ? '' : 'docker compose -p owned -f /source/compose.yaml -f /owned/override.json\n',
    );
  }
});

test('network checks before direct container starts retain the active generated Compose override', () => {
  const result = c1RunnerBoundaryResult(`set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
compose=(openpc_target_compose)
openpc_target_compose_command=(openpc_network_compose -f /owned/original-compose.json)
openpc_network_ensure() { printf '%s\\n' "$*"; }
openpc_network_current_ensure
`);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '-f /owned/original-compose.json\n');
});

test('network cleanup passes original failure and UNKNOWN disposition and disallows Compose down', () => {
  for (const cleanupStatus of [0, 99]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
cleanup_status=$1 status=42
repository_root=/source run_root=/owned project=owned owner_token=token
openpc_network_subnet=172.18.0.0/24 openpc_network_gateway=172.18.0.1 openpc_network_phase=fresh
openpc_require_heavy_lock() { :; }
node() {
  [[ $2 == cleanup ]] || return 97
  printf '%s|%s|%s\\n' "$OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE" "$OPENPC_NETWORK_UNKNOWN" "$OPENPC_NETWORK_ORIGINAL_TOPOLOGY_REQUIRED"
  [[ $OPENPC_NETWORK_UNKNOWN == 0 ]] || return 96
}
openpc_network_cleanup
`,
      [String(cleanupStatus)],
      { OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE: '1' },
    );
    assert.equal(result.status, cleanupStatus ? 96 : 0, result.stderr);
    assert.equal(result.stdout, `1|${cleanupStatus ? 1 : 0}|0\n`);
  }
  const result = c1RunnerBoundaryResult(`set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
openpc_network_compose_command=(unexpected_docker)
unexpected_docker() { printf 'UNEXPECTED_REMOVAL\\n'; return 97; }
openpc_network_compose down --remove-orphans
`);
  assert.equal(result.status, 96, result.stderr);
  assert.equal(result.stdout, '');
});

test('C1 selector loads its actual owner and rejects conflicts before suite or root allocation', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const early = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} != 0 || ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY:-0} != 0 ]]; then',
    'if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} != 0 ]]; then',
  );
  for (const [selector, extra, args, expected] of [
    ['0', {}, [], 0],
    ['1', {}, [], 0],
    ['1', { OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY: '1' }, [], 0],
    ['0', { OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY: '1' }, [], 96],
    ['1', { OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY: '2' }, [], 96],
    ['2', {}, [], 96],
    ['1', {}, ['--suite'], 96],
    ['1', {}, ['--reuse-images', '--resume-root', '/retained'], 96],
    ['1', {}, ['--refresh-from', 'old-source', '--resume-root', '/retained'], 96],
    ['1', { OPENPC_LOCAL_RUNTIME_BUILD_ONLY: '1' }, [], 96],
    ['1', { OPENPC_LOCAL_RUNTIME_TARGET_ONLY: '1' }, [], 96],
    ['1', { OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE: '1' }, [], 96],
    ['1', { OPENPC_BROWSER_SCENARIOS: 'credentials' }, [], 96],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
git() { [[ $* == 'rev-parse --show-toplevel' ]] || return 97; printf '%s\\n' "$PWD"; }
${early}
if declare -F openpc_run_fact_secret_consumer_slice >/dev/null; then owner=loaded; else owner=absent; fi
printf 'CONTINUATION|owner=%s\\n' "$owner"
`,
      args,
      { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: selector, ...extra },
    );
    assert.equal(result.status, expected, result.stderr);
    assert.equal(
      result.stdout,
      expected ? '' : `CONTINUATION|owner=${selector === '1' ? 'loaded' : 'absent'}\n`,
    );
  }
});

test('C1 chooses existing runtime-target admission and exactly Identity and Fact images', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const admission = c1RunnerSection(
    source,
    'openpc_runner_arguments "$@"',
    'if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 &&',
  );
  const images = c1RunnerSection(source, 'governance_browser_only=0', 'postgres_image=');
  const result = c1RunnerBoundaryResult(
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
source tests/integration/local-runtime/fact-secret-consumer-installation.sh
openpc_require_execution() { printf 'ADMISSION|%s\\n' "$1"; }
openpc_build_services=(control-api admin-web)
${admission}
${images}
printf 'IMAGES|%s\\n' "\${openpc_build_services[*]}"
printf 'TARGET_ONLY|%s\\n' "\${OPENPC_LOCAL_RUNTIME_TARGET_ONLY:-unset}"
`,
    [],
    { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: '1' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.stdout,
    'ADMISSION|runtime-target\nIMAGES|identity-service fact-service\nTARGET_ONLY|unset\n',
  );
});

test('C1 suite failure prevents a sibling runtime from consuming unreconciled resources', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const suite = c1RunnerSection(
    source,
    '  suite_status=0\n',
    '  export OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE=1',
  );
  const dispatch = c1RunnerSection(
    source,
    '  suite_step fact-secret-consumer ',
    '  suite_step module-lifecycle ',
  );
  for (const failure of [0, 47, 99]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
failure=$1
env() {
  [[ $1 == OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY=1 && $2 == bash ]] || return 97
  return "$failure"
}
${suite}
${dispatch}
printf 'SIBLING_RUNTIME_ALLOWED\\n'
`,
      [String(failure)],
    );
    assert.equal(result.status, failure ? 1 : 0, result.stderr);
    assert.equal(result.stdout.includes('SIBLING_RUNTIME_ALLOWED'), failure === 0);
    if (failure)
      assert.match(result.stderr, new RegExp(`FAIL\\|fact-secret-consumer\\|exit=${failure}`));
    else assert.match(result.stdout, /PASS\|fact-secret-consumer/u);
  }
});

test('ordinary and C1 fresh roots privately retain the original owner token and locked FD8', async (t) => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const setup = c1RunnerSection(
    source,
    'external_root="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:',
    'openpc_rpc_enospc_before_resume\n',
  );
  const parent = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'c1-runner-root-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  for (const factOnly of ['0', '1']) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
umask 0002
source tests/integration/local-runtime/runner-harness.sh
source tests/integration/local-runtime/fact-secret-consumer-installation.sh
source scripts/maintenance/server-capacity.sh
repository_root=$PWD reuse_images=0 refresh_from=''
docker() { printf 'unexpected Docker call in root fixture\\n' >&2; return 97; }
# This test owns root creation only; network dispatch is covered separately.
openpc_network_initialize() { :; }
${setup}
trap - EXIT ERR
openpc_require_heavy_lock() { :; }
openpc_require_execution() { [[ $1 == runtime-target ]]; }
if [[ $OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY == 1 ]]; then openpc_fact_secret_consumer_guard "$run_root"; fi
[[ $(cat "$owner_sentinel") == "$owner_record" ]]
[[ $owner_record == "openpc-local-runtime:$project:$owner_token" ]]
[[ $project == "openpc-local-e2e-\${owner_token:0:12}" ]]
[[ $(stat -c %a "$run_root") == 700 && $(stat -c %a "$owner_sentinel") == 600 && $(stat -c %a "$secret_root") == 700 ]]
[[ ! -e $data_root/fact-bridge && ! -e $data_root/protected-proofs ]]
[[ $(readlink /proc/$$/fd/8) == "$owner_sentinel" ]]
printf 'FRESH_ROOT_LOCKED\\n'
`,
      [],
      {
        OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: factOnly,
        OPENPC_LOCAL_RUNTIME_TMP_ROOT: parent,
        OPENPC_SERVER_CAPACITY: '0',
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'FRESH_ROOT_LOCKED\n');
  }
});

test('C1 early branch preserves image failures and never prepares static credentials or business proofs', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const dispatch = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} != 1 ]]; then',
    'mkdir -p "$data_root/runtime/trust"',
  );
  const stages = ['storage', 'builder', 'prior', 'build', 'capture', 'verify', 'stop', 'slice'];
  for (const [selector, failure] of [
    ['1', 'none'],
    ...stages.map((stage) => ['1', stage]),
    ['0', 'none'],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
data_root=/unused failure=$1 governance_browser_only=0
declare -A openpc_built_images=([identity-service]=identity-id [fact-service]=fact-id [control-api]=control-id)
openpc_build_services=(identity-service fact-service)
record() { printf '%s\\n' "$1"; [[ $failure != "$1" ]] || return 43; }
openpc_prepare_fact_database_files() { record static-credentials; }
openpc_storage_preflight() { record storage; }
openpc_prepare_builder() { record builder; }
openpc_record_prior_images() { record prior; }
openpc_build_selected_images() { [[ $* == 'identity-service fact-service' ]] || return 97; record build; }
openpc_capture_built_images() { record capture; }
openpc_assert_no_project_images() { record verify; }
openpc_stop_owned_builder() { record stop; }
openpc_run_fact_secret_consumer_slice() { [[ $* == 'fact-id identity-id' ]] || return 97; record slice; }
node() { record protected-proof; }
${dispatch}
printf 'BUSINESS_CONTINUATION\\n'
`,
      [failure],
      { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: selector },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 43, result.stderr);
    const expected =
      selector === '0'
        ? ['static-credentials', ...stages.slice(0, -1), 'protected-proof', 'BUSINESS_CONTINUATION']
        : stages.slice(0, failure === 'none' ? stages.length : stages.indexOf(failure) + 1);
    assert.deepEqual(result.stdout.trim().split('\n'), expected);
  }
});

test('QA image reuse verifies service images without starting or maintaining a builder', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const dispatch = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} != 1 ]]; then',
    'mkdir -p "$data_root/runtime/trust"',
  );
  for (const [qa, reuse, failure] of [
    ['1', '1', 'none'],
    ['1', '1', 'prior'],
    ['1', '1', 'capture'],
    ['1', '1', 'verify'],
    ['1', '0', 'none'],
    ['1', '0', 'builder'],
    ['0', '0', 'none'],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
data_root=/unused failure=$1 governance_browser_only=0
openpc_build_services=(identity-service admin-web)
declare -A openpc_built_images=([control-api]=control-id)
record() { printf '%s\\n' "$1"; [[ $failure != "$1" ]] || return 43; }
openpc_prepare_fact_database_files() { record static-credentials; }
openpc_storage_preflight() { record storage; }
openpc_prepare_builder() { record builder; }
openpc_record_prior_images() { record prior; }
openpc_build_selected_images() { printf 'SELECTED|%s\\n' "$*"; record build; }
openpc_capture_built_images() { record capture; }
openpc_assert_no_project_images() { record verify; }
# The real helper is a no-op unless this command owns a prepared builder.
openpc_stop_owned_builder() { record stop; }
node() { record protected-proof; }
${dispatch}
printf 'CONTINUATION\\n'
`,
      [failure],
      { OPENPC_LOCAL_RUNTIME_QA_FIXTURE: qa, OPENPC_QA_REUSE_SERVICE_IMAGES: reuse },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 43, result.stderr);
    assert.equal(result.stdout.includes('builder\n'), reuse === '0');
    if (qa === '1' && reuse === '1') {
      assert.match(result.stdout, /^static-credentials\nstorage\nprior\n/u);
      assert.doesNotMatch(result.stdout, /SELECTED\||\nbuild\n/u);
    }
    if (failure === 'none') {
      assert.match(result.stdout, /capture\nverify\nstop\nprotected-proof\nCONTINUATION\n$/u);
      if (qa === '1' && reuse === '0') assert.match(result.stdout, /SELECTED\|identity-service\n/u);
      if (qa === '0') assert.match(result.stdout, /SELECTED\|identity-service admin-web\n/u);
    } else assert.doesNotMatch(result.stdout, /CONTINUATION/u);
  }
});

test('C1 cleanup UNKNOWN blocks all generic paths and keeps the original failure status', () => {
  for (const mode of ['unknown', 'missing', 'known', 'recovered-status', 'unselected']) {
    for (const original of [0, 73]) {
      const result = c1RunnerBoundaryResult(
        `set -uo pipefail
source tests/integration/local-runtime/runner-harness.sh
project=owned run_root=owned evidence_root=/unused
mode=$1 original=$2
if [[ $mode != missing ]]; then
  openpc_fact_secret_consumer_on_exit() {
    printf 'C1_HOOK|%s\\n' "$1"
    [[ $mode != unselected ]] || exit 97
    openpc_fact_secret_exit_status=$1
    if [[ $mode == known ]]; then return 0; fi
    if [[ $mode == recovered-status ]]; then
      [[ $1 != 0 ]] || openpc_fact_secret_exit_status=71
      return 0
    fi
    [[ $1 != 0 ]] || openpc_fact_secret_exit_status=99
    export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
    return 99
  }
fi
docker() { [[ $1 == ps ]] || { printf 'DOCKER_MUTATION\\n'; exit 97; }; }
openpc_report_container_memory() { printf 'GENERIC_ALLOWED|%s\\n' "$status"; exit 77; }
remove_inventory_containers() { printf 'INVENTORY_REMOVED\\n'; exit 97; }
openpc_rpc_enospc_on_exit() { printf 'SPOOL_TEARDOWN\\n'; exit 97; }
parent_result() { return "$original"; }
parent_result
cleanup
`,
        [mode, String(original)],
        { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: mode === 'unselected' ? '0' : '1' },
      );
      if (mode === 'unknown' || mode === 'missing') {
        assert.equal(result.status, original || 99, result.stderr);
        assert.doesNotMatch(
          result.stdout,
          /GENERIC_ALLOWED|DOCKER_MUTATION|INVENTORY_REMOVED|SPOOL_TEARDOWN/u,
        );
        if (mode === 'unknown') assert.equal(result.stdout, `C1_HOOK|${original}\n`);
        else
          assert.match(
            result.stderr,
            new RegExp(`cleanup-owner-unavailable.*first_exit=${original}`),
          );
      } else {
        assert.equal(result.status, 77, result.stderr);
        assert.match(
          result.stdout,
          new RegExp(
            `GENERIC_ALLOWED\\|${mode === 'recovered-status' && !original ? 71 : original}`,
          ),
        );
        assert.equal(result.stdout.includes('C1_HOOK'), mode !== 'unselected');
      }
    }
  }
});

test('journal fixture ABI rejects newer host libc before target startup', () => {
  assertRpcJournalFixtureAbi('Name: GLIBC_2.2.5\nName: GLIBC_2.34\nName: GLIBC_2.36');
  for (const info of ['', 'Name: GLIBC_2.38', 'Name: GLIBC_PRIVATE', 'Name: GLIBC_3.0'])
    assert.throws(() => assertRpcJournalFixtureAbi(info));
});

test('RPC source continuation rejects missing retained owners before any preparation', () => {
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_phase_begin() { printf 'unexpected-preparation'; }
source tests/integration/local-runtime/evidence-rpc-source-journey.sh
`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 96);
  assert.match(result.stderr, /Required runner input missing/u);
  assert.doesNotMatch(result.stdout, /unexpected-preparation/u);
});

test('RPC source continuation cannot acquire candidates after publication without activation', () => {
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
root=/owned secret_root=/owned/secrets evidence_root=/owned/evidence owned_data=/owned/data
participant_id=participant privacy_domain_id=privacy provider_id=provider indexer_id=indexer
projection_id=projection workload_id=workload worker_container=worker
existing_configuration() { :; }
openpc_first_policy_actors() { :; }
openpc_phase_begin() { printf 'unexpected-preparation'; }
source tests/integration/local-runtime/evidence-rpc-source-journey.sh
`,
    ],
    { encoding: 'utf8', env: { ...process.env, OPENPC_FIRST_POLICY_ACTIVATE: '0' } },
  );
  assert.equal(result.status, 96);
  assert.match(result.stderr, /requires public policy activation/u);
  assert.doesNotMatch(result.stdout, /unexpected-preparation/u);
});

test('spool lifecycle rejects malformed metadata instead of permitting generic cleanup', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'spool-presence-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'evidence/runtime-bootstrap');
  await mkdir(directory, { recursive: true });
  const input = join(directory, 'discovery-credential-input.json');
  const run = () =>
    spawnSync(
      'bash',
      [
        '-c',
        `source tests/integration/local-runtime/runner-harness.sh
run_root=$1
openpc_rpc_enospc_present`,
        'test',
        root,
      ],
      { encoding: 'utf8' },
    );
  assert.equal(run().status, 3);
  for (const [text, expected] of [
    ['{}', 3],
    ['{"rpcJournalEnospc":null}', 0],
    ['null', 96],
    ['{', 96],
  ]) {
    await writeFile(input, text);
    const result = run();
    assert.equal(result.status, expected, result.stderr);
    assert.equal(result.stderr, '');
  }
  await rm(input);
  await symlink(join(root, 'absent'), input);
  assert.equal(run().status, 96);
});

test('spool shared preflight requires the live ancestor and its exclusive root lock', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'spool-owner-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const token = 'a'.repeat(64),
    project = `openpc-local-e2e-${token.slice(0, 12)}`;
  await mkdir(join(root, 'evidence/runtime-bootstrap'), { recursive: true });
  await mkdir(join(root, 'data/runtime-bootstrap'), { recursive: true });
  await writeFile(
    join(root, '.openpc-local-runtime-owner'),
    `openpc-local-runtime:${project}:${token}\n`,
  );
  await writeFile(
    join(root, 'evidence/runtime-bootstrap/discovery-credential-input.json'),
    JSON.stringify({ rpcJournalEnospc: { ownerToken: token, project } }),
  );
  const overlay = join(root, 'data/runtime-bootstrap/compose.json');
  await writeFile(overlay, '{}');
  const compose = JSON.stringify(['docker', 'compose', '-p', project, '-f', overlay]);
  for (const [mode, action] of ['retain', 'inspect', 'restore'].flatMap((action) =>
    ['locked', 'unlocked', 'missing', 'foreign'].map((mode) => [mode, action]),
  )) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_require_heavy_lock() { return 0; } # Test the additional owned-root fence only.
export OPENPC_RUNTIME_OWNER_PID=$$
exec 8<"$1/.openpc-local-runtime-owner"
if [[ $3 != unlocked ]]; then flock -n 8; fi
if [[ $3 == missing ]]; then unset OPENPC_RUNTIME_OWNER_PID; fi
if [[ $3 == foreign ]]; then OPENPC_RUNTIME_OWNER_PID=1; fi
openpc_rpc_enospc_preflight "$1" "$2" "$4"`,
        'test',
        root,
        compose,
        mode,
        action,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, mode === 'locked' ? 0 : 96, result.stderr);
  }
});

test('spool cleanup failure prevents generic container and data removal', () => {
  for (const mode of ['hook-failure', 'invalid-retained-root']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
project=owned
openpc_report_container_memory() { :; }
docker() { [[ $1 == ps ]] || { echo unexpected-docker-mutation; return 97; }; }
openpc_rpc_enospc_on_exit() {
  if [[ $1 == 0 && $mode == invalid-retained-root ]]; then
    openpc_rpc_enospc_retained=1; export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1; return 0
  fi
  return 96
}
remove_inventory_containers() { echo inventory-removed; }
validate_run_root() { return 1; }
mode=$1
true
cleanup`,
        'test',
        mode,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 99, result.stderr);
    assert.doesNotMatch(result.stdout, /unexpected-docker-mutation/u);
    if (mode === 'hook-failure') assert.doesNotMatch(result.stdout, /inventory-removed/u);
  }
});

test('spool resume verifies original keeper before dispatching product work', () => {
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
run_root=/owned repository_root=$PWD
compose=(docker compose -p owned)
openpc_rpc_enospc_present() { return 0; }
node() { if [[ $1 == */rpc-journal-enospc-runtime.mjs ]]; then [[ $2 == inspect ]] || return 97; return 96; else command node "$@"; fi; }
openpc_rpc_enospc_before_resume
echo product-dispatch`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 96, result.stderr);
  assert.doesNotMatch(result.stdout, /product-dispatch/u);
});

test('participant gateway readiness waits for routing without retrying business mutations', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'participant-route-'));
  try {
    for (const mode of ['ready', 'malformed', 'denied', 'unavailable']) {
      const counter = join(root, 'count');
      await writeFile(counter, '0');
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
evidence_root=$1 mode=$2
curl() {
 [[ $* == *http://127.0.0.1:8080/v1/participants/contracts ]]
 [[ $* != *POST* ]]
 n=$(cat "$evidence_root/count"); n=$((n+1)); printf '%s' "$n" >"$evidence_root/count"
 if [[ $mode == denied ]]; then printf 403; return; fi
 if [[ $mode == unavailable || $n -lt 3 ]]; then printf 503; return; fi
 if [[ $mode == malformed ]]; then printf '{}' >"$evidence_root/participant-gateway-readiness.json"
 else printf '%s' '{"contractTypes":["Participant","AuthorityEnvelope","Assignment","Delegation","WalletBinding"]}' >"$evidence_root/participant-gateway-readiness.json"; fi
 printf 200
}
sleep() { :; }
openpc_wait_participant_gateway
printf 'business-dispatch\\n'`,
          'gateway-test',
          root,
          mode,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, mode === 'ready' ? 0 : 96, result.stderr);
      assert.equal(
        Number(await readFile(counter, 'utf8')),
        mode === 'unavailable' ? 60 : mode === 'denied' ? 1 : 3,
      );
      if (mode === 'ready') assert.match(result.stdout, /business-dispatch/u);
      else assert.doesNotMatch(result.stdout, /business-dispatch/u);
    }
    const journey = await readFile(
      'tests/integration/local-runtime/deployment-submission-journey.sh',
      'utf8',
    );
    assert.match(
      journey,
      /prepare_deployment_submission\(\) \{\n[^\n]+participant-service[^\n]*\n {2}openpc_wait_participant_gateway/u,
    );
    assert.match(
      journey,
      /up -d --wait --no-deps --no-build --pull never participant-service[^\n]*\n {2}openpc_wait_participant_gateway/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('child custody receives executable Compose arguments under the shell admission wrapper', () => {
  for (const wrapped of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
        source tests/integration/local-runtime/runner-harness.sh
        compose=(docker compose -p exact-owned-project -f '/retained path/compose.yaml')
        openpc_target_compose_command=("\${compose[@]}")
        if [[ $1 == true ]]; then compose=(openpc_target_compose); fi
        compose+=(-f '/retained path/generated.json')
        openpc_compose_json`,
        'test',
        String(wrapped),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), [
      'docker',
      'compose',
      '-p',
      'exact-owned-project',
      '-f',
      '/retained path/compose.yaml',
      '-f',
      '/retained path/generated.json',
    ]);
  }
  const rejected = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
    source tests/integration/local-runtime/runner-harness.sh
    compose=(unknown_wrapper)
    openpc_compose_json`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(rejected.status, 96);
  assert.equal(rejected.stdout, '');
});

test('RPC denial acceptance distinguishes the public error code from the local journal code', () => {
  const response = {
    status: 403,
    body: {
      id: 7121,
      error: {
        code: -32001,
        data: { pcCode: 'PC-RUNTIME-3001', truthState: 'DENIED', retryable: false },
      },
    },
  };
  assertPublicRpcDenial(response, 7121);
  for (const change of [
    (r) => {
      r.body.error.data.pcCode = 'PC-RUNTIME-3003';
    },
    (r) => {
      r.body.error.data.truthState = 'FAILED';
    },
    (r) => {
      r.body.result = 'unexpected provider response';
    },
    (r) => {
      r.body.id = 7122;
    },
  ]) {
    const invalid = structuredClone(response);
    change(invalid);
    assert.throws(() => assertPublicRpcDenial(invalid, 7121));
  }
});

test('physical RPC ENOSPC rejects shared mounts and forged kernel observations before allocation', () => {
  rpcEnospcContractRegression();
});

test('RPC storage failure requires its exact no-result internal-error projection', () => {
  const response = {
    status: 500,
    body: {
      id: 7102,
      error: {
        data: { pcCode: 'PC-DATA-6005', truthState: 'FAILED', retryable: false },
      },
    },
  };
  assertRpcStorageFailure(response, 7102);
  for (const bad of [
    { ...response, status: 503 },
    { ...response, body: { ...response.body, id: 7103 } },
    { ...response, body: { ...response.body, result: 'provider-result' } },
    {
      ...response,
      body: {
        ...response.body,
        error: { data: { ...response.body.error.data, pcCode: 'PC-RUNTIME-3010' } },
      },
    },
    {
      ...response,
      body: { ...response.body, error: { data: { ...response.body.error.data, retryable: true } } },
    },
  ])
    assert.throws(() => assertRpcStorageFailure(bad, 7102));
});

test('successor source generation preserves two confirmations inside its governed 10-12 acquisition range', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'rpc-source-arguments-'));
  try {
    const source = await readFile(
      'tests/integration/local-runtime/evidence-rpc-source-journey.sh',
      'utf8',
    );
    const invocation = source.split('\n').find((line) => line.includes('local-indexer-input'));
    assert.ok(invocation);
    for (const generation of [2, 5, 6]) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
        evidence_root=$1; rpc_source_prefix=rpc-source; OPENPC_RPC_SOURCE_GENERATION=$2
        worker_container=worker indexer_id=indexer projection_id=projection provider_id=provider
        docker() { printf '%s\\n' "$@"; }
        ${invocation}
      `,
          'test',
          root,
          String(generation),
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, 0, result.stderr);
      const args = (await readFile(join(root, 'rpc-source-configuration.json'), 'utf8'))
        .trim()
        .split('\n');
      assert.equal(Number(args.at(-3)), generation);
      assert.equal(Number(args.at(-2)), 2);
      assert.equal(args.at(-1), '--state-candidates');
      assert.ok(
        10 + Number(args.at(-2)) <= 12,
        'Required confirmation observations fit the separately governed source range',
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('owned journal crash barrier stops only after durable directory fsync and cannot resume dispatch', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'rpc-journal-crash-'));
  try {
    const library = await prepareRpcJournalCrashFixture(root);
    for (const mode of [
      'disarmed',
      'wrong-directory',
      'wrong-pid',
      'stale-marker',
      'crash',
      'continue',
    ]) {
      const directory = join(root, mode);
      await mkdir(directory);
      let stderr = '';
      const child = spawn(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `
        import * as fs from 'node:fs';
        const [directory,mode]=process.argv.slice(1);
        if(mode!=='disarmed') fs.writeFileSync(directory+'/acceptance-pause.arm',
          'pause-after-fsync:'+(mode==='wrong-pid'?999999999:process.pid)+'\\n',{flag:'wx',mode:0o600});
        if(mode==='stale-marker') fs.writeFileSync(directory+'/acceptance-pause.reached','stale',{flag:'wx'});
        const fd=fs.openSync(directory+'/sealed-decisions.next','wx',0o600);
        fs.writeSync(fd,'original committed bytes');fs.fsyncSync(fd);fs.closeSync(fd);
        fs.renameSync(directory+'/sealed-decisions.next',directory+'/sealed-decisions.json');
        const parent=fs.openSync(directory,'r');fs.fsyncSync(parent);fs.closeSync(parent);
        fs.writeFileSync(directory+'/continued','unexpected after pause',{flag:'wx'});
      `,
          directory,
          mode,
        ],
        {
          env: {
            ...process.env,
            LD_PRELOAD: library,
            OPENPC_RPC_JOURNAL_FAULT_DIRECTORY: mode === 'wrong-directory' ? root : directory,
          },
          stdio: ['ignore', 'ignore', 'pipe'],
        },
      );
      child.stderr.on('data', (bytes) => {
        stderr += bytes;
      });
      const exited = new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, signal) => resolve({ code, signal }));
      });
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      try {
        if (['crash', 'continue'].includes(mode)) {
          for (let attempt = 0; attempt < 400; attempt++) {
            if (
              await stat(join(directory, 'acceptance-pause.reached')).then(
                () => true,
                () => false,
              )
            )
              break;
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          assert.equal(
            await readFile(join(directory, 'acceptance-pause.reached'), 'utf8'),
            `pause-after-fsync:${child.pid}\n`,
          );
          await assert.rejects(stat(join(directory, 'continued')), { code: 'ENOENT' });
          if (mode === 'continue') {
            child.kill('SIGCONT');
            await new Promise((resolve) => setTimeout(resolve, 25));
            await assert.rejects(stat(join(directory, 'continued')), { code: 'ENOENT' });
            assert.equal(child.exitCode, null);
          }
          child.kill('SIGKILL');
        }
        const result = await exited;
        assert.deepEqual(
          result,
          ['crash', 'continue'].includes(mode)
            ? { code: null, signal: 'SIGKILL' }
            : { code: mode === 'stale-marker' ? 190 : 0, signal: null },
          stderr,
        );
        assert.equal(
          await readFile(join(directory, 'sealed-decisions.json'), 'utf8'),
          'original committed bytes',
        );
        if (['crash', 'continue', 'stale-marker'].includes(mode))
          await assert.rejects(stat(join(directory, 'continued')), { code: 'ENOENT' });
      } finally {
        clearTimeout(timer);
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await exited;
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('pre-policy denial separates closed TLS from HTTP and rejects timeout or success', () => {
  for (const [transport, http, accepted] of [
    [0, 500, true],
    [0, 503, true],
    [35, '000', true],
    [0, 200, false],
    [0, '000', false],
    [35, 200, false],
    [7, '000', false],
    [28, '000', false],
    [60, '000', false],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        'set -euo pipefail; source tests/integration/local-runtime/runtime-configuration.sh; openpc_validate_pre_release_response "$1" "$2"',
        'test',
        String(transport),
        String(http),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status === 0, accepted, `${transport}:${http}`);
  }
});

test('completed runtime activation restarts without rewinding business state or accepting changed custody', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'activation-restart-'));
  try {
    const source = await readFile(
      'tests/integration/local-runtime/runtime-configuration.sh',
      'utf8',
    );
    assert.doesNotMatch(source, /interrupted-worker|SET state='ACTIVATING',activated_at=null/u);
    const identity = source.slice(source.indexOf('openpc_runtime_activation_identity()'));
    assert.doesNotMatch(identity, /\b(?:INSERT|UPDATE|DELETE)\b/u);
    assert.match(identity, /observation\.execution_attempt_id=work\.execution_attempt_id/u);
    assert.match(identity, /observation\.activation_receipt_digest=work\.result_receipt_digest/u);
    const recovery = await readFile(
      'tests/integration/local-runtime/run-decision-owner.py',
      'utf8',
    );
    assert.match(recovery, /postgres_lost_activation_observation_uses_original_custody/u);
    for (const scenario of ['preserved', 'changed', 'missing', 'duplicate', 'start-failed']) {
      const trace = join(root, scenario);
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
source tests/integration/local-runtime/runtime-configuration.sh
compose=(compose_stub)
runtime_operation_id=operation
target_urn=target
evidence_root=$OPENPC_TEST_TMP_ROOT
configuration_initial_mfa_count=12
compose_stub() { printf '%s %s\\n' "$1" "$2" >> "$TRACE"; [[ $SCENARIO != start-failed || $1 != start ]]; }
poll_configuration_operation() { [[ $1 == operation ]]; printf 'read %s\\n' "$(basename "$2")" >> "$TRACE"; }
configuration_get() { printf 'target-read\\n' >> "$TRACE"; }
assert_json_equal() { printf 'target-unchanged\\n' >> "$TRACE"; }
read_configuration_completion() { printf '4|4|4|1|1|12|1'; }
openpc_runtime_activation_identity() {
  local id='018f0000-0000-7000-8000-000000000101' digest
  digest=$(printf 'a%.0s' {1..64})
  if [[ -f $TRACE && $SCENARIO == changed ]]; then id='018f0000-0000-7000-8000-000000000102'; fi
  [[ $SCENARIO != missing ]] || return 0
  printf '%s|sha256:%s|%s|sha256:%s\\n' "$id" "$digest" "$id" "$digest"
  [[ $SCENARIO != duplicate ]] || printf 'duplicate\\n'
}
openpc_verify_runtime_activation_restart`,
        ],
        { encoding: 'utf8', env: { ...process.env, TRACE: trace, SCENARIO: scenario } },
      );
      if (scenario === 'preserved') {
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /OPENPC_RUNTIME_ACTIVATION_RESTART\|PASS/u);
        assert.deepEqual((await readFile(trace, 'utf8')).trim().split('\n'), [
          'stop control-worker',
          'read configuration-runtime-stopped-operation.json',
          'start control-worker',
          'read configuration-runtime-reconciled-operation.json',
          'target-read',
          'target-unchanged',
        ]);
      } else {
        assert.notEqual(result.status, 0, scenario);
        assert.doesNotMatch(result.stdout, /\|PASS/u);
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('signing provider startup rebuilds the mounted current receipt catalogue and fails closed', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'signing-provider-bundle-'));
  try {
    const bundle = join(root, 'provider.mjs');
    const result = spawnSync(
      'bash',
      [
        '-c',
        'set -euo pipefail; source tests/integration/local-runtime/runner-harness.sh; openpc_prepare_signing_provider_bundle',
      ],
      {
        encoding: 'utf8',
        timeout: 30000,
        env: { ...process.env, OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE: bundle },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    const compiled = await readFile(bundle, 'utf8');
    for (const transition of ['create', 'release'])
      assert.ok(compiled.includes(`pc.control.evidence-participant-hold.${transition}`));
    assert.match(result.stderr, /name=signing-provider-bundle\|event=end\|status=0/u);
    const failed = spawnSync(
      'bash',
      [
        '-c',
        'set -euo pipefail; source tests/integration/local-runtime/runner-harness.sh; pnpm() { return 7; }; openpc_prepare_signing_provider_bundle',
      ],
      { encoding: 'utf8', env: { ...process.env, OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE: bundle } },
    );
    assert.equal(failed.status, 7);
    assert.match(failed.stderr, /name=signing-provider-bundle\|event=end\|status=7/u);
    const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
    assert.match(runner, /openpc_prepare_signing_provider_bundle/u);
    const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
    assert.match(
      harness,
      /openpc_resume_compose\(\) \{[\s\S]*?openpc_prepare_signing_provider_bundle/u,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('isolated RPC export uses an existing bootstrap context for foreign-privacy denial', async () => {
  // Exercise the browser module with the same TypeScript loader as its runtime caller.
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
    import {rpcEvidenceForeignPrivacy} from './tests/integration/local-runtime/evidence-rpc-browser.mjs';
    process.stdout.write(JSON.stringify(['018f0000-0000-7000-8000-000000007201','018f0000-0000-7000-8000-000000000201'].map(rpcEvidenceForeignPrivacy)));
  `,
    ],
    { encoding: 'utf8', timeout: 30000 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [
    '018f0000-0000-7000-8000-000000000201',
    '018f0000-0000-7000-8000-000000006201',
  ]);
});

test('RPC initial trust preserves one context-entry grant and rejects retained overlap', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/deployment-intent-actors.mjs',
    'utf8',
  );
  const start = source.indexOf('async function bootstrapContextEntryAuthority()');
  const end = source.indexOf('async function bootstrapRuntimeSourceTrust()', start);
  const modesStart = source.indexOf('const runtimeBootstrap =');
  const modesEnd = source.indexOf('const evidenceMode =', modesStart);
  const idsStart = source.indexOf('const fixtureUuid =');
  const idsEnd = source.indexOf('\n', idsStart);
  const entryIdStart = source.indexOf('function entryAuthorityId(');
  const entryIdEnd = source.indexOf('const entryAuthorities =', entryIdStart);
  const actorCheckStart = source.indexOf('function validateContextEntryActor(');
  const actorCheckEnd = source.indexOf('if (isolatedActors?.preflight', actorCheckStart);
  assert.ok(
    start > 0 &&
      end > start &&
      modesEnd > modesStart &&
      idsEnd > idsStart &&
      actorCheckEnd > actorCheckStart,
  );
  const create = new Function(
    'assert',
    'client',
    'actors',
    'mode',
    `const participantId='participant'; const isolatedActors=undefined;
     ${source.match(/^const entryPrivacy = .*;$/mu)[0]}
     ${source.match(/^ {2}const notificationMode = .*;$/mu)[0]}
     ${source.slice(modesStart, modesEnd)}
     ${source.slice(idsStart, idsEnd)}
     ${source.slice(entryIdStart, entryIdEnd)}
     ${source.slice(actorCheckStart, actorCheckEnd)}
     ${source.slice(start, end)}
     return bootstrapContextEntryAuthority;`,
  );
  const actors = {
    maker: {
      principalId: '018f0000-0000-7000-8000-000000007141',
      envelopeId: '018f0000-0000-7000-8000-000000007151',
      assignmentId: '018f0000-0000-7000-8000-000000007152',
    },
  };
  for (const protectedEvidence of [false, true]) {
    const scopedActors = protectedEvidence
      ? {
          maker: Object.fromEntries(
            Object.entries(actors.maker).map(([key, value]) => [
              key,
              value.replace('000000007', '000000009'),
            ]),
          ),
        }
      : actors;
    for (const scenario of ['covered', 'separate', 'duplicate']) {
      const writes = [];
      const client = {
        async query(sql) {
          if (sql.startsWith('select 1 from control.assignment a join'))
            return { rowCount: scenario === 'separate' ? 0 : 1 };
          if (sql.startsWith('select 1 from control.assignment where'))
            return { rowCount: scenario === 'duplicate' ? 1 : 0 };
          assert.match(sql, /^insert into control\.(authority_envelope|assignment)/u);
          writes.push(sql);
          return { rowCount: 1 };
        },
      };
      const run = create(
        assert,
        client,
        scopedActors,
        protectedEvidence ? 'bootstrap-evidence-protected' : 'bootstrap-evidence-rpc',
      );
      if (scenario === 'duplicate') await assert.rejects(run, /duplicate context-entry authority/u);
      else await run();
      assert.equal(writes.length, scenario === 'separate' ? 2 : 0);
    }
  }
});

test('public restart readback retries only the observed unavailable responses', async () => {
  const { publicReadResponse } = await import('./authenticated-http.mjs');
  const unavailable = () =>
    Response.json({ code: 'PC-INTEGRATION-5001', retryable: true }, { status: 503 });
  assert.equal(await publicReadResponse(unavailable(), true), null);
  assert.equal(
    await publicReadResponse(
      new Response(
        JSON.stringify({
          code: 'PC-INTEGRATION-5001',
          retryable: true,
          status: 503,
          truthState: 'UNAVAILABLE',
        }),
        {
          status: 503,
          headers: { 'content-type': 'application/problem+json; charset=utf-8' },
        },
      ),
      true,
    ),
    null,
  );
  for (const problem of [
    { code: 'PC-AUTH-0005', retryable: true },
    { code: 'PC-INTEGRATION-5001', retryable: false },
    { code: 'PC-INTEGRATION-5001', retryable: true, status: 200, truthState: 'UNAVAILABLE' },
    { code: 'PC-INTEGRATION-5001', retryable: true, status: 503, truthState: 'DENIED' },
  ]) {
    await assert.rejects(
      publicReadResponse(
        new Response(JSON.stringify(problem), {
          status: 503,
          headers: { 'content-type': 'application/problem+json' },
        }),
        true,
      ),
    );
  }
  assert.equal(
    await publicReadResponse(
      new Response(
        'upstream connect error or disconnect/reset before headers. reset reason: remote connection failure',
        { status: 503, headers: { 'content-type': 'text/plain' } },
      ),
      true,
    ),
    null,
  );
  await assert.rejects(publicReadResponse(unavailable()));
  await assert.rejects(
    publicReadResponse(Response.json({ code: 'PC-AUTH-0005' }, { status: 403 }), true),
  );
  await assert.rejects(
    publicReadResponse(
      Response.json({ code: 'PC-INTEGRATION-5001', retryable: false }, { status: 503 }),
      true,
    ),
  );
  await assert.rejects(
    publicReadResponse(new Response('unclassified failure', { status: 503 }), true),
  );
  const version = { policyVersionId: 'original', normalizedPolicyDigest: 'unchanged' };
  assert.deepEqual(await publicReadResponse(Response.json(version), true), version);
});

test('first-policy discovery consumes the target input through the shared shell and TLS owners', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = journey.indexOf('target_id="');
  const end = journey.indexOf('export OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST=', start);
  assert.ok(start > 0 && end > start);
  const root = await mkdtemp(join(process.env.TMPDIR ?? '/tmp', 'openpc-first-policy-input-'));
  const target = '018f0000-0000-7000-8000-000000008191';
  try {
    await mkdir(join(root, 'runtime'));
    await writeFile(
      join(root, 'discovery-credential-input.json'),
      JSON.stringify({ targetId: target }),
    );
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      source tests/integration/local-runtime/authenticated-http.sh
      source tests/integration/local-runtime/runtime-configuration.sh
      evidence_root=$1 owned_data=$1
      ${journey.slice(start, end)}
      printf '%s\\n' "$target_urn" "$workload_id"
    `,
        'first-policy-input',
        root,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `urn:openpc:resource:${target}\nurn:openpc:workload:${target}\n`);
    const bootstrap = JSON.parse(await readFile(join(root, 'runtime/envoy.json'), 'utf8'));
    assert.equal(bootstrap.node.id, target);
    assert.match(JSON.stringify(bootstrap), /ads-client\.pem/u);
    assert.match(JSON.stringify(bootstrap), /ads-ca\.pem/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('first-policy discovery reserves the provider endpoint before starting its consumers', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = journey.indexOf(
    '"${compose[@]}" up -d --wait --no-deps --no-build --pull never rpc-provider',
  );
  const end = journey.indexOf('"${compose[@]}" stop participant-service', start);
  assert.ok(start > 0 && end > start);
  for (const failure of ['none', 'rpc-provider', 'fact-service']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
        failure=$1
        compose=(dispatch)
        dispatch() {
          [[ $# == 8 ]]
          printf '%s\\n' "${'${!#}'}"
          [[ ${'${!#}'} != "$failure" ]]
        }
        ${journey.slice(start, end)}
        printf 'discovery-dispatch\\n'
      `,
        'provider-order',
        failure,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 1, result.stderr);
    assert.deepEqual(
      result.stdout.trim().split('\n'),
      failure === 'none'
        ? ['rpc-provider', 'fact-service', 'discovery-dispatch']
        : failure === 'rpc-provider'
          ? ['rpc-provider']
          : ['rpc-provider', 'fact-service'],
    );
  }
});

test('RPC connected input preflight blocks dependent dispatch on every failed prerequisite', async () => {
  const admission = await readFile(
    'tests/integration/local-runtime/evidence-rpc-admission.sh',
    'utf8',
  );
  const dispatch = admission.slice(0, admission.indexOf('openpc_reconcile_fact_bridge_identity'));
  assert.ok(dispatch.includes('openpc_rpc_fact_input_preflight'));
  const phases = ['initial-trust', 'acquisition', 'assignment', 'artifact-reader-assignment'];
  for (const failure of ['none', ...phases]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      source tests/integration/local-runtime/runner-harness.sh
      repository_root=$PWD root=owned evidence_root=owned/evidence
      secret_root=owned/secrets participant_id=participant privacy_domain_id=privacy
      compose=(true)
      openpc_require_inputs() { :; }
      openpc_first_policy_actors() { :; }
      failure=$1
      node() {
        local phase=$4
        [[ $3 != tests/integration/local-runtime/deployment-intent-actors.mjs ]] || phase=initial-trust
        printf '%s\\n' "$phase"; [[ $phase != "$failure" ]]
      }
      ${dispatch}
      printf 'consumer-dispatch\\n'
    `,
        'rpc-preflight',
        failure,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 1, result.stderr);
    assert.deepEqual(
      result.stdout.trim().split('\n'),
      failure === 'none'
        ? [...phases, 'consumer-dispatch']
        : phases.slice(0, phases.indexOf(failure) + 1),
    );
    if (failure === 'initial-trust')
      assert.doesNotMatch(result.stderr, /rpc-fact-input-preflight/u);
    else
      assert.match(
        result.stderr,
        new RegExp(`rpc-fact-input-preflight\\|event=end\\|status=${failure === 'none' ? 0 : 1}`),
      );
  }
});

test('native quarantine dispatch stops the ordinary consumer and fails closed without an RPC pass', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/evidence-rpc-admission.sh',
    'utf8',
  );
  const dispatch = source.slice(
    source.indexOf('if [[ ${OPENPC_FACT_QUARANTINE_ONLY'),
    source.indexOf('openpc_phase_begin live-authority'),
  );
  assert.ok(dispatch.includes('evidence-fleet-quarantine.mjs'));
  assert.ok(dispatch.includes('evidence-fact-withdrawal-recovery.mjs'));
  for (const failure of ['none', 'stop', 'driver', 'closure']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      failure=$1 OPENPC_FACT_QUARANTINE_ONLY=1 root=owned evidence_root=owned/evidence
      compose=(dispatch)
      dispatch() { [[ $failure != stop ]]; }
      openpc_compose_json() { printf '[]'; }
      openpc_phase_begin() { printf 'begin\\n'; }
      openpc_phase_end() { printf 'end\\n'; }
      node() {
        if [[ $* == *evidence-fact-withdrawal-recovery.mjs* ]]; then
          printf 'closure\\n'; [[ $failure != closure ]]
        else
          printf 'driver\\n'; [[ $failure != driver ]]
        fi
      }
      run_phase() {
        ${dispatch}
        printf 'unexpected-rpc\\n'
      }
      run_phase
    `,
        'native-quarantine',
        failure,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 1, result.stderr);
    assert.deepEqual(
      result.stdout.trim().split('\n').filter(Boolean),
      failure === 'none'
        ? ['begin', 'driver', 'end', 'begin', 'closure', 'end']
        : failure === 'driver'
          ? ['begin', 'driver']
          : failure === 'closure'
            ? ['begin', 'driver', 'end', 'begin', 'closure']
            : [],
    );
    assert.doesNotMatch(result.stdout, /RPC.*PASS|unexpected-rpc/u);
  }
  const first = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  assert.ok(
    first.indexOf('source tests/integration/local-runtime/evidence-rpc-configuration.sh') <
      first.indexOf('source tests/integration/local-runtime/evidence-fleet-quarantine-journey.sh'),
  );
});

test('FactBridge reconciles a changed Identity pin without replacing workload scope or trust', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'fact-identity-pin-'));
  try {
    await mkdir(join(root, 'fact-bridge/config'), { recursive: true });
    for (const scenario of ['current', 'changed', 'foreign', 'unavailable']) {
      await writeFile(
        join(root, 'fact-bridge/config/deployment.json'),
        JSON.stringify({
          participant_id: scenario === 'foreign' ? 'foreign' : 'participant',
          privacy_domain_id: 'privacy',
          runtime_target_id: 'target',
          identity_addresses: ['192.0.2.1'],
        }),
      );
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
        source tests/integration/local-runtime/runtime-configuration.sh
        target_id=target expected_root=$1
        scenario=$2
        compose=(dispatch)
        dispatch() { if [[ $1 == ps ]]; then printf 'identity'; else printf '%s\\n' "$*"; fi; }
        docker() { case "$scenario" in current) printf '192.0.2.1';; unavailable) printf '';; *) printf '192.0.2.2';; esac; }
        openpc_prepare_fact_bridge() { [[ $data_root == "$expected_root" ]]; printf 'prepare|%s|%s|%s|%s\\n' "$1" "$2" "$3" "$4"; }
        openpc_reconcile_fact_bridge_identity "$1" participant privacy original.pem original.key
        printf 'admission-dispatch\\n'
      `,
          'fact-identity-pin',
          root,
          scenario,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, ['current', 'changed'].includes(scenario) ? 0 : 1, result.stderr);
      if (scenario === 'changed') {
        assert.match(
          result.stdout,
          /prepare\|participant\|privacy\|original.pem\|original.key\nrestart fact-service\nup -d --wait --no-deps --no-build --pull never fact-service/u,
        );
        assert.match(result.stdout, /reconciled-current-address/u);
      } else {
        assert.doesNotMatch(result.stdout, /prepare|restart/u);
      }
      assert.equal(
        result.stdout.includes('admission-dispatch'),
        ['current', 'changed'].includes(scenario),
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('retained FactBridge setup replaces read-only connection files with current inputs', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'fact-bridge-prepare-'));
  try {
    const secrets = join(root, 'secrets');
    await mkdir(secrets);
    for (const digit of ['a', 'b']) {
      for (const name of ['indexer_manager', 'fact_bridge_reader', 'source_control'])
        await writeFile(join(secrets, `${name}_db_password.txt`), digit.repeat(64));
      const result = spawnSync(
        'bash',
        [
          '-c',
          'set -euo pipefail; source tests/integration/local-runtime/runtime-configuration.sh; secret_root=$1; data_root=$2; export OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY=1; openpc_prepare_fact_database_files',
          'fact-bridge-prepare',
          secrets,
          root,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, 0, result.stderr);
      for (const [name, role, host, database] of [
        ['manager-url', 'openpc_indexer_manager', 'candidate-index-pg', 'openpc_candidate_index'],
        [
          'config/candidate-url',
          'openpc_fact_bridge_reader',
          'candidate-index-pg',
          'openpc_candidate_index',
        ],
        ['config/control-url', 'openpc_source_control_reader', 'control-pg', 'openpc_control'],
      ]) {
        const path = join(root, 'fact-bridge', name);
        assert.equal(
          await readFile(path, 'utf8'),
          `postgresql://${role}:${digit.repeat(64)}@${host}:5432/${database}`,
        );
        assert.equal((await stat(path)).mode & 0o777, 0o444);
      }
      assert.equal(
        await readFile(join(root, 'fact-bridge/worker.env'), 'utf8'),
        'OPENPC_INDEXER_MANAGER_DATABASE_URL_FILE=/fact-manager-url\n',
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('approval resume bootstrap preserves the disclosure registration and BFF digest', async () => {
  const columns = [
    'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    'approval-requests',
    'UPDATE',
    'STANDARD',
    false,
    false,
    true,
    'AUTHORIZED_TYPE_ONLY',
    'AUTHORIZED_MINIMAL',
    'UPDATE_APPROVAL_REQUESTS',
  ];
  const tuple = `(${columns.map((value) => (typeof value === 'string' ? `'${value}'` : value)).join(',')})`;
  for (const path of [
    'deploy/compose/local/migrate.sh',
    'tests/integration/policy/postgres18-runtime.test.ts',
  ]) {
    assert.ok(
      (await readFile(path, 'utf8')).includes(tuple),
      `${path}: canonical approval-update registration`,
    );
  }
  const digest = `sha256:${createHash('sha256').update(columns.join('\0')).digest('hex')}`;
  const bff = await readFile('apps/admin-web/app/api/v1/ui/local-governance-api.ts', 'utf8');
  assert.ok(bff.includes(`digest: '${digest}'`), 'BFF binds the registered semantic digest');
});

test('isolated module setup selects exact dependency closure and rejects ambiguous or invalid edges', () => {
  const release = (id, dependencies = []) => ({
    manifestDigest: `digest:${id}`,
    manifest: { metadata: { id, version: '1.0.0' }, dependencies },
  });
  const dependency = (id) => ({
    moduleId: id,
    providerModuleId: id,
    version: '1.0.0',
    manifestDigest: `digest:${id}`,
  });
  const releases = [release('unrelated'), release('leaf', [dependency('root')]), release('root')];
  assert.deepEqual(selectModuleReleases(releases, ['leaf']), [2, 1]);
  assert.deepEqual(selectModuleReleases(releases, ['root', 'leaf']), [2, 1]);
  assert.throws(() => selectModuleReleases(releases, ['absent']), /Missing module/u);
  assert.throws(() => selectModuleReleases([...releases, release('root')], ['leaf']), /Ambiguous/u);
  assert.throws(
    () =>
      selectModuleReleases(
        [release('leaf', [{ ...dependency('root'), version: '2.0.0' }]), release('root')],
        ['leaf'],
      ),
    /Exact dependency version/u,
  );
  assert.throws(
    () =>
      selectModuleReleases(
        [release('leaf', [{ ...dependency('root'), manifestDigest: 'wrong' }]), release('root')],
        ['leaf'],
      ),
    /Exact dependency digest/u,
  );
  assert.throws(
    () =>
      selectModuleReleases(
        [release('leaf', [dependency('root')]), release('root', [dependency('leaf')])],
        ['leaf'],
      ),
    /Cyclic/u,
  );
});

test('relationship source faults preserve exact occurrence identity and isolate malformed data', () => {
  const owned = {
    relationshipEvents: [
      {
        block: 10,
        logIndex: 1,
        transition: 0,
        from: 10,
        entityTopic: `0x${'ab'.repeat(32)}`,
        subjectTopic: `0x${'cd'.repeat(32)}`,
      },
    ],
  };
  const logs = relationshipSourceLogs(owned);
  const original = structuredClone(logs);
  assert.deepEqual(relationshipSourceFault(logs, 'duplicate'), [logs[0], logs[0]]);
  const conflict = relationshipSourceFault(logs, 'conflict');
  assert.equal(conflict.length, 2);
  assert.notEqual(conflict[0].data, conflict[1].data);
  assert.deepEqual({ ...conflict[1], data: conflict[0].data }, conflict[0]);
  assert.deepEqual(relationshipSourceFault(logs, 'decode'), [{ ...logs[0], data: '0x00' }]);
  assert.deepEqual(logs, original);
  assert.throws(() => relationshipSourceFault(logs, 'unknown'));
  assert.throws(() => relationshipSourceFault([], 'decode'));
});

test('visibility acquisition never reuses incomplete prior executable output', async () => {
  const { visibilityAcquisitionReusable } = await import('./visibility-source-custody.mjs');
  const root = await mkdtemp(join(process.env.TMPDIR, 'visibility-incomplete-'));
  try {
    await mkdir(join(root, 'acquisition'));
    for (const value of ['', '{"outcome":']) {
      await writeFile(join(root, 'acquisition/result.json'), value);
      assert.equal(
        await visibilityAcquisitionReusable(root, root, 'participant', 'privacy', '23'),
        false,
      );
      assert.equal(await readFile(join(root, 'acquisition/result.json'), 'utf8'), value);
    }
  } finally {
    await rm(root, { recursive: true });
  }
});

test('ordinary runner gate exercises the typed visibility custody corpus', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--test',
      'tests/integration/local-runtime/typed-visibility-policy.test.mjs',
    ],
    { encoding: 'utf8', env: { ...process.env, NODE_TEST_CONTEXT: undefined } },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /visibility RPC grant binds the contract resource/);
});

test('controlled provider rejects malformed scope before reading fixture material', () => {
  for (const scope of ['{}', '["missing"]', '["invalid","invalid"]']) {
    const result = spawnSync(
      process.execPath,
      [
        'tests/integration/local-runtime/rpc-provider-bootstrap.mjs',
        'source',
        '/missing',
        '127.0.0.1',
      ],
      { encoding: 'utf8', env: { ...process.env, OPENPC_LOCAL_FIXTURE_SCOPE: scope } },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Controlled provider scope rejected/u);
    assert.doesNotMatch(result.stderr, /ENOENT/u);
  }
});

test('controlled visibility provider declares each implemented response family', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'visibility-provider-'));
  try {
    for (const args of [
      ['bootstrap', root],
      ['source', root, '127.0.0.1', 'state-candidates'],
    ]) {
      const result = spawnSync(
        '/bin/bash',
        [
          '-c',
          'umask 077; exec "$@"',
          'private-provider-fixture',
          process.execPath,
          'tests/integration/local-runtime/rpc-provider-bootstrap.mjs',
          ...args,
        ],
        {
          encoding: 'utf8',
          env: {
            ...process.env,
            OPENPC_LOCAL_FIXTURE_SCOPE:
              '["018f0000-0000-7000-8000-000000000101","018f0000-0000-7000-8000-000000007201"]',
            OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY: '0',
            OPENPC_LOCAL_RUNTIME_CIGL_ONLY: '0',
          },
        },
      );
      assert.equal(result.status, 0, result.stderr);
    }
    assert.equal((await stat(join(root, 'provider-probe-source'))).mode & 0o777, 0o755);
    assert.equal(
      (await stat(join(root, 'provider-probe-source/profile.json'))).mode & 0o777,
      0o444,
    );
    for (const name of ['server.key', 'client.key'])
      assert.equal((await stat(join(root, 'rpc-provider', name))).mode & 0o777, 0o600);
    const profile = JSON.parse(
      await readFile(join(root, 'provider-probe-source/profile.json'), 'utf8'),
    );
    assert.equal(profile.idempotency, 'IdempotentRead');
    const sourceBytes = await readFile(
      join(root, 'provider-probe-source/018f0000-0000-7000-8000-000000000930.json'),
      'utf8',
    );
    const source = JSON.parse(sourceBytes);
    assert.equal(source.participant_id, '018f0000-0000-7000-8000-000000000101');
    assert.equal(source.privacy_domain_id, '018f0000-0000-7000-8000-000000007201');
    assert.equal(
      profile.configuration_digest,
      `sha256:${createHash('sha256').update(sourceBytes).digest('hex')}`,
    );
    for (const [method, dataClass] of [
      ['eth_call', 'STATE_CALL'],
      ['eth_getBlockByNumber(false)', 'BLOCK_HEADER'],
      ['eth_getTransactionByHash', 'TRANSACTION'],
      ['eth_getTransactionReceipt', 'RECEIPT'],
      ['eth_getLogs', 'EVENT_LOG'],
    ]) {
      assert.deepEqual(
        profile.method_data_classes.filter((entry) => entry.method === method),
        [{ method, data_class: dataClass }],
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('visibility renewal qualifies the provider before admitting a replacement source', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/visibility-source-journey.sh',
    'utf8',
  );
  const renewal = source.slice(
    source.indexOf('if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} == 1 ]]'),
    source.indexOf('if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} != 1 && ! -f'),
  );
  const qualified = renewal.indexOf(
    'poll_configuration_operation "$(operation_field "$evidence_root/source-provider-generation${source_generation}-qualified.json"',
  );
  const admitted = renewal.indexOf('action=ACT-INDEXER_APPROVE_PROFILE-V1');
  const published = renewal.indexOf('action=ACT-INDEXER_RECOVER_PLAN-V1');
  assert.ok(qualified >= 0 && qualified < admitted && admitted < published);
  assert.match(source, /visibility-source-input\.mjs reuse/);
  assert.match(
    source,
    /if \[\[ \$\{OPENPC_VISIBILITY_RENEW_FACT:-0\} != 1 \]\]; then\n {4}publish_runtime_policy visibility-source/,
  );
  assert.match(source, /fact-bound-assignment-\$candidate_id\.json/);
  assert.doesNotMatch(source, /generation3|visibility-source-current-3|fact-bound-assignment-0002/);
});

test('visibility renewal never repeats initial source mutations or reads an absent initial policy', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/visibility-source-journey.sh',
    'utf8',
  );
  const start = source.indexOf('  if [[ ${OPENPC_VISIBILITY_RENEW_FACT:-0} != 1 && ! -f');
  const end = source.indexOf('  if [[ -f $evidence_root/visibility-source-current-', start);
  assert.ok(start > 0 && end > start);
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'source-renewal-'));
  try {
    for (const retained of [false, true]) {
      if (retained) await writeFile(join(root, 'visibility-source-occurrence-activate.json'), '{}');
      for (const renewal of ['0', '1']) {
        const result = spawnSync(
          'bash',
          [
            '-c',
            `set -euo pipefail
evidence_root=$CASE_ROOT
provider_id=provider;indexer_id=indexer;projection_id=projection
configuration_get() { printf 'initial-owner\\n'; exit 77; }
operation_field() { printf 'initial-operation\\n' >&2; exit 78; }
${source.slice(start, end)}
printf 'renewal-preserved\\n'`,
          ],
          {
            encoding: 'utf8',
            env: { ...process.env, CASE_ROOT: root, OPENPC_VISIBILITY_RENEW_FACT: renewal },
          },
        );
        assert.equal(result.status, renewal === '1' ? 0 : retained ? 78 : 77, result.stderr);
        if (renewal === '1') assert.equal(result.stdout, 'renewal-preserved\n');
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('retained visibility acquisition rejects mismatched, fenced and uncommitted custody', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
    import assert from 'node:assert/strict';
    import { visibilityAcquisitionMatches as matches } from './tests/integration/local-runtime/visibility-source-custody.mjs';
    const job = {participant_id:'participant',privacy_domain_id:'privacy',projection_generation_id:'generation',source_id:'source',partition_id:'partition',batch_id:'batch',sequence:1,range:{start:10,end:10}};
    const saved = {result:{outcome:'COMMITTED_CANDIDATE'},configuration:{configurationDigest:'sha256:current'},job,publication:{projection_generation_id:'generation',candidate_partition_id:'candidate-partition'},candidate:{candidateId:'candidate'}};
    const current = {...job,configuration_digest:'sha256:current',publication_state:'PUBLISHED',generation_state:'READY',candidate_state:'VALIDATED_CANDIDATE',checkpoint_state:'COMPLETE',operation_matches:true,candidate_event_id:'candidate',candidate_partition_id:'candidate-partition',batch_sequence:'1',range_start:'10',range_end:'10'};
    assert.equal(matches(saved,'sha256:current',current),true);
    assert.equal(matches(saved,'sha256:replacement',current),false);
    assert.equal(matches(saved,'sha256:current',undefined),false);
    for (const [key,value] of Object.entries({configuration_digest:'sha256:previous',publication_state:'FENCED',generation_state:'STALE',candidate_state:'REMOVED',checkpoint_state:'PENDING',operation_matches:false,candidate_event_id:'foreign',candidate_partition_id:'foreign',participant_id:'foreign',privacy_domain_id:'foreign',projection_generation_id:'previous',source_id:'foreign',partition_id:'foreign',batch_id:'foreign',batch_sequence:'2',range_start:'9',range_end:'11'})) {
      assert.equal(matches(saved,'sha256:current',{...current,[key]:value}),false,key);
    }
    assert.equal(matches(saved,'sha256:current',{...current,candidate_state:'OBSERVED'}),false);
    assert.equal(matches({...saved,result:{outcome:'DENIED'}},'sha256:current',current),false);
  `,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('initial policy bootstrap is scoped and stops on its first SQL error', async () => {
  const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const credentialInsert = runner.indexOf('INSERT INTO control.credential(\n');
  const start = runner.lastIndexOf('docker exec -i ', credentialInsert);
  const end = runner.indexOf('\nSQL', credentialInsert);
  const bootstrap = runner.slice(start, end);
  assert.match(bootstrap, /psql -X -qAt -v ON_ERROR_STOP=1/);
  assert.match(
    bootstrap,
    /BEGIN;\nSELECT openpc\.set_request_context\('PARTICIPANT',:'participant_id'::uuid,\n\s*:'privacy_domain_id'::uuid,uuidv7\(\),'ACT-POLICY_ACTIVATE_RELEASE-V1',true\)/,
  );
  assert.ok(
    bootstrap.indexOf('set_request_context') <
      bootstrap.indexOf('INSERT INTO control.policy_generation('),
  );
});

test('shared Rust source changes invalidate reuse and require an allowed affected build', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import importlib.util, os, pathlib, subprocess, tempfile
spec=importlib.util.spec_from_file_location('provenance','tests/integration/local-runtime/runner-provenance.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
with tempfile.TemporaryDirectory(dir=os.environ['OPENPC_TEST_TMP_ROOT']) as directory:
 root=pathlib.Path(directory)
 source=root/'crates/pc-policy-core/src/visibility_policy/simulation.rs'
 source.parent.mkdir(parents=True); source.write_text('original simulation')
 fleet=root/'services/fleet-controller/src/runtime_target_service/source_only/dispatch.rs'
 fleet.parent.mkdir(parents=True); fleet.write_text('original source dispatcher')
 (root/'package.json').write_text('{}')
 def git(*args): return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.DEVNULL).strip()
 git('init'); git('add','.'); git('-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','-m','Initial fixture')
 revision=git('rev-parse','HEAD')
 original=owner.source_identity(root)
 legacy=owner.refresh_source(root,revision,1)
 source.write_text('corrected simulation')
 fleet.write_text('combined source dispatcher')
 assert owner.source_identity(root)!=original
 assert owner.refresh_source(root,revision)==original
 assert owner.refresh_source(root,revision,1)==legacy
 os.environ['OPENPC_REFRESH_TEST_ONLY']='1'
 for version in (1,2):
  try: owner.refresh_source(root,revision,version)
  except ValueError: pass
  else: raise AssertionError('Rust source reused without rebuilding')
 os.environ.pop('OPENPC_REFRESH_TEST_ONLY')
 unrelated=fleet.parent.parent.parent/'local_runtime_worker.rs'
 unrelated.write_text('unreviewed activation owner')
 try: owner.refresh_source(root,revision)
 except ValueError: pass
 else: raise AssertionError('unrelated Fleet owner admitted to focused refresh')
 unrelated.unlink()
 (source.parent.parent/'semantics.rs').write_text('unreviewed semantic change')
 assert owner.source_identity(root)!=original
 try: owner.refresh_source(root,revision)
 except ValueError: pass
 else: raise AssertionError('unrelated Rust owner admitted to focused refresh')
`,
    ],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('image reuse accepts excluded web and CI assertions but rejects product and module inputs', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import importlib.util, os, pathlib, subprocess, tempfile
spec=importlib.util.spec_from_file_location('provenance','tests/integration/local-runtime/runner-provenance.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
with tempfile.TemporaryDirectory(dir=os.environ['OPENPC_TEST_TMP_ROOT']) as directory:
 root=pathlib.Path(directory)
 source=root/'apps/admin-web/components/workflow.tsx'
 source.parent.mkdir(parents=True); source.write_text('product')
 test=source.with_name('workflow.test.tsx'); test.write_text('original test')
 ci=root/'tests/integration/ci/invocation.test.mjs'
 ci.parent.mkdir(parents=True); ci.write_text('original dispatch assertions')
 (root/'.dockerignore').write_text('**/*.test.tsx\\n')
 (root/'package.json').write_text('{}')
 def git(*args): return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.DEVNULL).strip()
 git('init'); git('add','.'); git('-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','-m','Initial fixture')
 revision=git('rev-parse','HEAD'); original=owner.source_identity(root)
 test.write_text('corrected test'); os.environ['OPENPC_REFRESH_TEST_ONLY']='1'
 ci.write_text('corrected dispatch assertions')
 assert owner.refresh_source(root,revision)==original
 module=root/'tests/integration/local-runtime/module-release-build.ts'
 module.parent.mkdir(parents=True); module.write_text('changed module fixture')
 try: owner.refresh_source(root,revision)
 except ValueError: pass
 else: raise AssertionError('module fixture reused without lifecycle validation')
 module.unlink()
 source.write_text('changed product')
 try: owner.refresh_source(root,revision)
 except ValueError: pass
 else: raise AssertionError('product source reused without rebuilding')
`,
    ],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('retained Explorer refresh admits only reviewed lock and transport corrections with rebuilds', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import importlib.util, os, pathlib, subprocess, tempfile
spec=importlib.util.spec_from_file_location('provenance','tests/integration/local-runtime/runner-provenance.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
identity='services/identity-service/src/domain/identity-kernel.ts'
gateway='deploy/compose/local/envoy/local-gateway.yaml'
sources={p:pathlib.Path(p).read_text().strip() for p in (identity,gateway)}
with tempfile.TemporaryDirectory(dir=os.environ['OPENPC_TEST_TMP_ROOT']) as directory:
 root=pathlib.Path(directory)
 for path,after in sources.items():
  if path==identity:
   start=after.index('    if (lock) {',after.index('  private async activeSession('))
   end=after.index('    const result =',start)
   before=after[:start]+after[end:]
  else:
   addition='                        - match: { path_separated_prefix: "/api/v1/ui/privacy-explorer" }\\n                          route: { cluster: admin_web, timeout: 45s }'
   assert after.count(addition)==1
   before=after.replace(addition+'\\n','',1)
   # Freeze the reviewed historical insertion point. Later routes between the
   # Explorer route and fallback are not part of this retained exception.
   anchor='                        - match: { prefix: "/api/v1/ui/" }'
   after=before.replace(anchor,addition+'\\n'+anchor,1)
   sources[path]=after
  owner.validate_explorer_owner_refresh(path,before,after)
  try: owner.validate_explorer_owner_refresh(path,before,after+'\\nunauthorized change')
  except ValueError: pass
  else: raise AssertionError('unreviewed product drift admitted')
  destination=root/path; destination.parent.mkdir(parents=True,exist_ok=True); destination.write_text(before)
 def git(*args): return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.DEVNULL).strip()
 git('init'); git('add','.'); git('-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','-m','Initial fixture')
 revision=git('rev-parse','HEAD'); original=owner.source_identity(root)
 for path,after in sources.items(): (root/path).write_text(after)
 os.environ['OPENPC_REFRESH_TEST_ONLY']='0'
 assert owner.refresh_source(root,revision)==original
 os.environ['OPENPC_REFRESH_TEST_ONLY']='1'
 try: owner.refresh_source(root,revision)
 except ValueError: pass
 else: raise AssertionError('Identity product correction reused an old image')
`,
    ],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('Explorer cleanup reaps preparation before services stop and preserves the first failure', () => {
  const result = spawnSync(
    'bash',
    [
      '-c',
      `
    source tests/integration/local-runtime/runner-harness.sh
    (sleep 0.02; printf 'CHILD_REAPED\\n'; exit 17) &
    openpc_explorer_cutover_pid=$!
    docker() { :; }
    openpc_report_container_memory() { printf 'CHILDREN_MUST_BE_DONE\\n'; }
    remove_inventory_containers() { :; }
    validate_run_root() { return 0; }
    stopped_compose() { printf 'SERVICES_STOPPED\\n'; }
    openpc_stop_owned_builder() { :; }
    compose=(stopped_compose)
    project=owned run_root=owned evidence_root=/dev/null
    OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
    failed_parent() { return 23; }
    failed_parent
    cleanup
  `,
    ],
    { encoding: 'utf8', timeout: 5000 },
  );
  assert.equal(result.status, 23, result.stdout + result.stderr);
  assert.ok(result.stdout.indexOf('CHILD_REAPED') >= 0);
  assert.ok(result.stdout.indexOf('CHILD_REAPED') < result.stdout.indexOf('CHILDREN_MUST_BE_DONE'));
});

test('connected visibility and Explorer shell owners parse independently before dispatch', () => {
  for (const file of [
    'run-compose-e2e.sh',
    'visibility-journey.sh',
    'visibility-source-journey.sh',
    'relationship-visibility-journey.sh',
    'privacy-explorer-journey.sh',
  ]) {
    const result = spawnSync('bash', ['-n', `tests/integration/local-runtime/${file}`], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, `${file}: ${result.stderr}`);
  }
});

test('retained Compose rejects a lost workload issuer mount before service startup', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import copy, importlib.util, os, pathlib, tempfile
spec=importlib.util.spec_from_file_location('provenance','tests/integration/local-runtime/runner-provenance.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
with tempfile.TemporaryDirectory(dir=os.environ['OPENPC_TEST_TMP_ROOT']) as directory:
 source=pathlib.Path(directory)/'issuer.mjs'; source.write_text('external test provider')
 service={'volumes':[{'type':'bind','source':str(source),'target':'/app/server.mjs','read_only':True}], 'environment':{'ISSUER_MODE':'local'}, 'command':['node','/app/server.mjs'], 'user':'1000:1000'}
 rendered={'services':{'workload-issuer':service}}
 container={'Config':{'Labels':{'com.docker.compose.service':'workload-issuer'},'Env':['ISSUER_MODE=local'],'Cmd':service['command'],'User':'1000:1000'},'Mounts':[{'Type':'bind','Source':str(source),'Destination':'/app/server.mjs','RW':False}]}
 owner.validate_compose(rendered,[container])
 for boundary in ('missing','wrong-source','writable','environment'):
  changed=copy.deepcopy(container)
  if boundary=='missing': changed['Mounts']=[]
  elif boundary=='wrong-source': changed['Mounts'][0]['Source']=directory
  elif boundary=='writable': changed['Mounts'][0]['RW']=True
  else: changed['Config']['Env']=['ISSUER_MODE=other']
  try: owner.validate_compose(rendered,[changed])
  except ValueError: pass
  else: raise AssertionError(boundary)
 source.unlink(); source.mkdir()
 try: owner.validate_compose(rendered,[container])
 except ValueError: pass
 else: raise AssertionError('directory cannot replace provider executable')
`,
    ],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('resume selection rejects missing pairs, duplicate flags and unsupported scenarios before dispatch', () => {
  for (const [args, selected, expected] of [
    [[], '0', 0],
    [['--reuse-images'], '1', 96],
    [['--resume-root', '/owned'], '1', 96],
    [['--reuse-images', '--resume-root', '/owned'], '0', 96],
    [['--reuse-images', '--reuse-images', '--resume-root', '/owned'], '1', 96],
    [['--reuse-images', '--resume-root', '/owned'], '1', 0],
    [['--typo'], '1', 96],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        'set -euo pipefail; source tests/integration/local-runtime/runner-harness.sh; openpc_runner_arguments "$@"',
        'runner',
        ...args,
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY: selected },
      },
    );
    assert.equal(result.status, expected, result.stderr);
  }
});

test('resume provenance rejects each stale boundary and duplicate or foreign containers', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import copy, importlib.util, os, pathlib, tempfile
spec=importlib.util.spec_from_file_location('provenance','tests/integration/local-runtime/runner-provenance.py')
owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
with tempfile.TemporaryDirectory(dir=os.environ['OPENPC_TEST_TMP_ROOT']) as directory:
 root=pathlib.Path(directory); (root/'evidence').mkdir()
 checkpoint={'schema':1,'scenario':'typed-policy','originalFailure':1}
 owner.write_checkpoint(root,checkpoint)
 assert owner.read_checkpoint(root)==checkpoint
 assert (root/'evidence/runner-resume.json').stat().st_mode & 0o777 == 0o600
 assert not (root/'evidence/runner-resume.tmp').exists()
value={key: {'expected':'bound'} for key in ('owner','source','containers','images','credentials','inputs')}
value['containers']={'policy-service':{'HostConfig':{}}}
owner.validate_checkpoint(value,copy.deepcopy(value))
try: owner.validate_checkpoint(value,dict(value,sourceVersion=2))
except ValueError: pass
else: raise AssertionError('legacy source fingerprint reused without affected refresh')
for key in value:
 changed=copy.deepcopy(value); changed[key]={} if key=='containers' else {'unexpected':'drift'}
 try: owner.validate_checkpoint(value,changed)
 except ValueError: pass
 else: raise AssertionError(key)
container={'Id':'retained','Image':'verified','Config':{'Labels':{'com.docker.compose.project':'owned','com.docker.compose.service':'policy-service'}},'HostConfig':{},'Mounts':[]}
assert owner.bindings([container],'owned')['policy-service']['Image']=='verified'
container['Mounts']=[{'Destination':'/b','Source':'/owned/b','RW':False},{'Destination':'/a','Source':'/owned/a','RW':True}]
reordered=copy.deepcopy(container); reordered['Mounts'].reverse()
assert owner.bindings([container],'owned')==owner.bindings([reordered],'owned')
reordered['Mounts'][0]['RW']=False
assert owner.bindings([container],'owned')!=owner.bindings([reordered],'owned')
for containers, project in (([container,container],'owned'),([container],'foreign')):
 try: owner.bindings(containers,project)
 except ValueError: pass
 else: raise AssertionError('ownership accepted')
old=owner.bindings([container],'owned')
for key in ('Dns','DnsOptions','DnsSearch'):
 old['policy-service']['HostConfig'][key]=None
new=copy.deepcopy(old)
for key in ('Dns','DnsOptions','DnsSearch'):
 new['policy-service']['HostConfig'][key]=[]
owner.validate_checkpoint(dict(value,containers=old),dict(value,containers=new))
owner.validate_recreated(old,new)
assert all(v is None for v in old['policy-service']['HostConfig'].values())
for key in ('Dns','DnsOptions','DnsSearch'):
 changed=copy.deepcopy(new); changed['policy-service']['HostConfig'][key]=['configured-value']
 for check in (lambda:owner.validate_checkpoint(dict(value,containers=old),dict(value,containers=changed)),lambda:owner.validate_recreated(old,changed)):
  try: check()
  except ValueError: pass
  else: raise AssertionError('DNS drift accepted: '+key)
new=copy.deepcopy(old); new['policy-service']['Id']='replacement'; new['policy-service']['Image']='new-owned-image'
owner.validate_recreated(old,new)
new['policy-service']['HostConfig']['OomKillDisable']=False
new['policy-service']['HostConfig']['Mounts']=[]
new['policy-service']['HostConfig']['Binds']=[]
owner.validate_recreated(old,new)
new['policy-service']['HostConfig']['Memory']=0
try: owner.validate_recreated(old,new)
except ValueError: pass
else: raise AssertionError('resource drift accepted')
new=copy.deepcopy(old); new['policy-service']['Id']='replacement'; new['policy-service']['Config']['Env']=['TARGET=foreign']
try: owner.validate_recreated(old,new)
except ValueError: pass
else: raise AssertionError('target drift accepted')
print('resume-boundaries-pass')
`,
    ],
    { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /resume-boundaries-pass/);
});

test('release catalog extension refuses an existing owner before reading keys or copying artifacts', async () => {
  assert.ok(process.env.OPENPC_TEST_TMP_ROOT, 'owned temporary root required');
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'module-extension-'));
  const inherited = join(root, 'admitted');
  const alias = join(root, 'alias');
  try {
    await mkdir(inherited);
    await writeFile(join(inherited, 'policy-core-artifact'), 'retained admitted executable');
    await symlink(inherited, alias);
    for (const output of [inherited, alias]) {
      const result = spawnSync(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/module-release-build.ts',
          output,
          'must-not-read-key',
          'must-not-read-artifact',
          `sha256:${'a'.repeat(64)}`,
          'pc.indexing.dedicated-policy',
          inherited,
        ],
        { encoding: 'utf8', timeout: 10000 },
      );
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /EEXIST/);
      assert.doesNotMatch(result.stderr, /ENOENT/);
      assert.equal(
        await readFile(join(inherited, 'policy-core-artifact'), 'utf8'),
        'retained admitted executable',
      );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a retained source journey rejects missing readback helpers before any business request', () => {
  const run = spawnSync(
    'bash',
    [
      '-c',
      `
set -euo pipefail
source tests/integration/local-runtime/source-lifecycle-journey.sh
local_identity_session() { echo unexpected-business-request; exit 86; }
configuration_get() { exit 86; }
operation_field() { exit 86; }
action_digest() { exit 86; }
configuration_post() { exit 86; }
approved_configuration_post() { exit 86; }
poll_configuration_operation() { exit 86; }
run_source_lifecycle_journey
`,
    ],
    { encoding: 'utf8', timeout: 5000 },
  );
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, /missing=assert_json_equal/);
  assert.equal(run.stdout, '');
});

test('a deployment case cannot renew or observe a preceding case command', () => {
  const run = spawnSync(
    'bash',
    [
      '-c',
      `
set -euo pipefail
source tests/integration/local-runtime/deployment-submission-journey.sh
deployment_command_id=previous-expired-command deployment_case=replacement
deployment_installed_expiry() { printf '1'; }
deployment_fact_remaining_ms() { printf '0'; }
deployment_provider_remaining_ms() { printf '0'; }
deployment_publication_remaining_ms() { printf '0'; }
deployment_renew_runtime() { [[ -z $deployment_command_id ]] || exit 86; }
# Stop at the next phase boundary, before any real business command or file IO.
deployment_require_runtime_window() { exit 87; }
run_deployment_submission_command
`,
    ],
    { encoding: 'utf8', timeout: 5000 },
  );
  assert.equal(run.status, 87, run.stderr);
});

test('deployment status renewal preserves the expired-lease denial probe without recursion', () => {
  const run = spawnSync(
    'bash',
    [
      '-c',
      `
set -euo pipefail
export FUNCNEST=16
source tests/integration/local-runtime/deployment-submission-journey.sh
evidence_root=/unused secret_root=/unused runtime_assertion_hex=fixture deployment_command_id=fixture
renewals=0
refresh_runtime_assertion() { :; }
curl() { printf '%s' "$expected"; }
deployment_require_runtime_window() {
  renewals=$((renewals + 1))
  deployment_status /unused/expired 403
}
deployment_status /unused/current
test "$renewals" = 1
deployment_status /unused/expired 403
test "$renewals" = 1
`,
    ],
    { encoding: 'utf8', timeout: 5000 },
  );
  assert.equal(run.status, 0, run.stderr);
});

test('CIGL renewal fixture preserves exact-hash observation and advances the external nonce', async () => {
  assert.ok(process.env.OPENPC_TEST_TMP_ROOT, 'owned temporary root required');
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'cigl-rpc-'));
  const original = {
    sender: '0xsender',
    destination: '0xcontract',
    calldata: '0xdata',
    nonce: 9,
    transactionHash: '0xoriginal',
    signedTransaction: '0x01',
    gasLimit: '100000',
  };
  const renewed = {
    ...original,
    nonce: 10,
    transactionHash: '0xrenewed',
    signedTransaction: '0x02',
  };
  const call = (method, params) => ciglResponse(root, { method, params });
  try {
    await writeFile(join(root, 'cigl-wallet.json'), JSON.stringify(original));
    const firstHead = (await call('eth_getBlockByNumber', ['latest', false])).result;
    assert.equal(
      (
        await call('eth_getTransactionCount', [
          original.sender,
          { blockHash: firstHead.hash, requireCanonical: true },
        ])
      ).result,
      '0x9',
    );
    await call('eth_sendRawTransaction', [original.signedTransaction]);
    await writeFile(join(root, 'cigl-renewed-wallet.json'), JSON.stringify(renewed));
    const nextHead = (await call('eth_getBlockByNumber', ['latest', false])).result;
    assert.notEqual(nextHead.hash, firstHead.hash);
    assert.notEqual(nextHead.stateRoot, firstHead.stateRoot);
    assert.equal(
      (
        await call('eth_getTransactionCount', [
          renewed.sender,
          { blockHash: nextHead.hash, requireCanonical: true },
        ])
      ).result,
      '0xa',
    );
    await call('eth_sendRawTransaction', [renewed.signedTransaction]);
    for (const wallet of [original, renewed]) {
      assert.equal(
        (await call('eth_getTransactionReceipt', [wallet.transactionHash])).result,
        null,
      );
      assert.equal((await call('eth_getTransactionByHash', [wallet.transactionHash])).result, null);
    }
    await assert.rejects(call('eth_getTransactionReceipt', ['0xunrelated']));
    await writeFile(
      join(root, 'cigl-mined.json'),
      JSON.stringify({ transactionHash: original.transactionHash, diverged: true }),
    );
    const receipt = (await call('eth_getTransactionReceipt', [original.transactionHash])).result;
    assert.equal(receipt.transactionHash, original.transactionHash);
    assert.equal(
      receipt.blockHash,
      (await call('eth_getBlockByNumber', ['finalized', false])).result.hash,
    );
    const mined = (
      await call('debug_traceTransaction', [original.transactionHash, { tracer: 'callTracer' }])
    ).result;
    assert.equal(mined.from, original.sender);
    assert.equal(mined.input, original.calldata);
    assert.equal(mined.calls[0].to, `0x${'33'.repeat(20)}`);
    await assert.rejects(call('debug_traceTransaction', ['0xunrelated', { tracer: 'callTracer' }]));
    await assert.rejects(call('eth_sendRawTransaction', [original.signedTransaction]));
    assert.deepEqual(
      (await readFile(join(root, 'cigl-submissions.jsonl'), 'utf8'))
        .trim()
        .split('\n')
        .map(JSON.parse),
      [{ transactionHash: original.transactionHash }, { transactionHash: renewed.transactionHash }],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('replacement fixture preserves exact receipts and uses the included successor for shared chain state', async () => {
  assert.ok(process.env.OPENPC_TEST_TMP_ROOT, 'owned temporary root required');
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'replacement-rpc-'));
  const hash = (byte) => `0x${byte.repeat(32)}`;
  const wallet = {
    mechanism: 'TRANSACTION_CREATE',
    nonce: 18,
    sender: `0x${'11'.repeat(20)}`,
    expectedAddress: `0x${'22'.repeat(20)}`,
    transactionHash: hash('01'),
    signedTransaction: '0x01',
    feePerGas: '2',
    tipPerGas: '1',
  };
  const replacement = {
    ...wallet,
    transactionHash: hash('02'),
    signedTransaction: '0x02',
    feePerGas: '4',
    tipPerGas: '2',
  };
  const phase = (value) =>
    writeFile(
      join(root, 'deployment-scenario.json'),
      JSON.stringify({ wallet, replacement, phase: value }),
    );
  const call = (method, params) => deploymentResponse(root, { method, params });
  try {
    await phase('pending');
    await call('eth_sendRawTransaction', [wallet.signedTransaction]);
    assert.equal(
      (await call('eth_getTransactionByHash', [wallet.transactionHash])).result.hash,
      wallet.transactionHash,
    );
    await call('eth_sendRawTransaction', [replacement.signedTransaction]);
    await phase('included');
    assert.equal((await call('eth_getTransactionReceipt', [wallet.transactionHash])).result, null);
    assert.equal(
      (await call('eth_getTransactionReceipt', [replacement.transactionHash])).result
        .transactionHash,
      replacement.transactionHash,
    );
    assert.deepEqual((await call('eth_getBlockByNumber', ['0xb', false])).result.transactions, [
      replacement.transactionHash,
    ]);
    assert.equal(
      (
        await call('eth_getCode', [
          wallet.expectedAddress,
          { blockHash: hash('aa'), requireCanonical: true },
        ])
      ).result,
      '0x00',
    );
    await phase('finalized');
    assert.equal(
      (
        await call('eth_getCode', [
          wallet.expectedAddress,
          { blockHash: hash('cc'), requireCanonical: true },
        ])
      ).result,
      '0x00',
    );
    await phase('invalidated-reorg');
    assert.equal((await call('eth_getBlockByNumber', ['0xb', false])).result.hash, hash('bb'));
    const sends = (await readFile(join(root, 'deployment-submissions.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map(JSON.parse);
    assert.deepEqual(
      sends.map((value) => value.transactionHash),
      [wallet.transactionHash, replacement.transactionHash],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('builder admission blocks running transactions and permits stopped diagnostic containers', () => {
  const shell = `export OPENPC_SERVER_CAPACITY=0
source scripts/maintenance/local-runtime-images.sh
openpc_require_heavy_lock() { return 0; }
docker() {
  if [[ $1 == ps ]]; then
    if [[ $2 == -aq || $active == 1 ]]; then echo container; fi
    return 0
  fi
  if [[ $1 == buildx ]]; then echo reached-builder >&2; return 66; fi
  return 97
}
xargs() { local value; if read -r value; then echo openpc-local-e2e-diagnostic; fi; return 0; }
active=$1
openpc_prepare_builder`;
  const running = spawnSync('bash', ['-c', shell, '--', '1'], { encoding: 'utf8' });
  assert.equal(running.status, 75, running.stderr);
  assert.doesNotMatch(running.stderr, /reached-builder/);
  const stopped = spawnSync('bash', ['-c', shell, '--', '0'], { encoding: 'utf8' });
  assert.equal(stopped.status, 66, stopped.stderr);
  assert.match(stopped.stderr, /reached-builder/);
});

test('OIDC-only builder invocation requires its real custody owner before builder access', () => {
  const script = `set -euo pipefail
export OPENPC_SERVER_CAPACITY=0
source scripts/maintenance/local-runtime-images.sh
openpc_require_heavy_lock() { :; }
node() {
  [[ $1 == "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" && $2 == maintenance-oidc-build && $3 == /owned-root && $4 == '[]' ]] || return 97
  echo custody-owner-called >&2
  return "$1_status"
}
docker() { echo reached-builder >&2; return 66; }
repository_root=$PWD
openpc_prepare_builder retained-oidc /owned-root '[]'
`;
  for (const status of [79, 0]) {
    const result = spawnSync('bash', ['-c', script.replace('"$1_status"', String(status))], {
      encoding: 'utf8',
    });
    assert.equal(result.status, status === 79 ? 79 : 66, result.stderr);
    assert.match(result.stderr, /custody-owner-called/u);
    if (status === 79) assert.doesNotMatch(result.stderr, /reached-builder/u);
    else assert.match(result.stderr, /reached-builder/u);
  }
});

test('a successful builder stop releases ownership before cleanup repeats it', () => {
  const shell = `set -euo pipefail
export OPENPC_SERVER_CAPACITY=0
source scripts/maintenance/local-runtime-images.sh
openpc_builder_owned=1
openpc_verify_owned_builder() { echo verified; }
openpc_report_container_memory() { :; }
docker() { [[ "$*" == 'buildx stop openpc-r1-local-v1' ]] || return 97; echo stopped; }
openpc_stop_owned_builder
openpc_verify_owned_builder() { echo missing-container >&2; return 96; }
openpc_stop_owned_builder`;
  const result = spawnSync('bash', ['-c', shell], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.stdout.trim().split('\n'), ['verified', 'stopped']);
  assert.doesNotMatch(result.stderr, /missing-container/);
});

test('retained QA emergency builder stop is independent of failed admission and runtime verification', () => {
  const shell = `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
repository_root=$PWD
openpc_qa_serial_root=/owned
openpc_builder_owned=1
openpc_verify_owned_builder() { echo forbidden-verifier; return 75; }
node() { [[ "$*" == *'maintenance-stop /owned' ]] || return 96; echo exact-emergency-owner; }
openpc_stop_owned_builder
[[ -z $openpc_qa_serial_root && $openpc_builder_owned == 0 ]]
`;
  const result = spawnSync('bash', ['-c', shell], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /exact-emergency-owner/);
  assert.doesNotMatch(result.stdout, /forbidden-verifier/);
});

test('target startup cannot restart migrations, unselected services or implicit dependencies', () => {
  const shell = `source scripts/maintenance/local-runtime-images.sh
declare -A openpc_target_services=([identity-service]=1 [runtime-target]=1)
capture() { printf '%s\\0' "$@"; }
openpc_target_compose_command=(capture)
openpc_target_compose "$@"`;
  const run = (...args) => spawnSync('bash', ['-c', shell, '--', ...args], { encoding: 'utf8' });
  const admitted = run('--profile', 'astra05', 'up', '-d', '--pull', 'never', 'runtime-target');
  assert.equal(admitted.status, 0, admitted.stderr);
  assert.deepEqual(admitted.stdout.split('\0').filter(Boolean), [
    '--profile',
    'astra05',
    'up',
    '--no-deps',
    '-d',
    '--pull',
    'never',
    'runtime-target',
  ]);
  for (const args of [
    ['up', '-d'],
    ['up', 'control-migrate'],
    ['up', 'candidate-index-pg'],
    ['up', 'unselected-service'],
    ['up', '--build', 'runtime-target'],
    ['restart', 'candidate-index-pg'],
    ['start', 'control-migrate'],
    ['run', 'runtime-target'],
  ]) {
    const result = run(...args);
    assert.equal(result.status, 96, result.stderr);
    assert.equal(result.stdout, '');
  }
  assert.equal(run('restart', 'identity-service').status, 0);
  assert.equal(run('ps', '-a').status, 0);
  const start = spawnSync(
    'bash',
    [
      '-c',
      `source scripts/maintenance/local-runtime-images.sh
declare -A openpc_target_services=([control-worker]=1)
lookup() { test "$*" = 'ps -aq control-worker' && printf '0123456789abcdef'; }
docker() { printf '%s\\0' "$@"; }
openpc_target_compose_command=(lookup)
openpc_target_compose start control-worker`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(start.status, 0, start.stderr);
  assert.deepEqual(start.stdout.split('\0').filter(Boolean), ['start', '0123456789abcdef']);
});

test('target resource admission reads numeric Compose caps and rejects unsafe phase changes', () => {
  const services = {};
  for (const id of ['control-pg', 'fact-pg', 'candidate-index-pg'])
    services[id] = { mem_limit: String(1024 ** 3) };
  for (const id of ['control', 'fact', 'candidate-index'])
    services[`${id}-migrate`] = { mem_limit: String(1024 ** 3), depends_on: { [`${id}-pg`]: {} } };
  services['admin-web'] = {
    mem_limit: String(768 * 1024 ** 2),
    depends_on: { 'control-migrate': {}, 'fact-migrate': {}, 'candidate-index-migrate': {} },
  };
  for (const id of ['runtime-target', 'runtime-envoy', 'participant-service'])
    services[id] = { mem_limit: String(512 * 1024 ** 2) };
  const run = (
    config,
    candidateLive = false,
    externalKib = '8388608',
    fixture,
    otherRetainedBytes = 0,
  ) =>
    spawnSync(
      'bash',
      [
        '-c',
        `source scripts/maintenance/local-runtime-images.sh
# The exact Docker identity/volume union is tested through its real owner in
# rpc-journal-enospc-runtime.test.mjs; this case tests the shared phase arithmetic.
openpc_other_retained_fixture_bytes() { cat >/dev/null; printf '%s' '${otherRetainedBytes}'; }
openpc_target_service_order admin-web${candidateLive ? ' candidate-index-pg' : ''}`,
      ],
      {
        encoding: 'utf8',
        input: JSON.stringify({ 'services': config, 'x-openpc-rpc-enospc': fixture }),
        env: { ...process.env, OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB: externalKib },
      },
    );
  assert.equal(run(services).status, 0);
  assert.equal(run(services).stdout.trim(), 'admin-web');
  const candidate = structuredClone(services);
  candidate['runtime-target'].depends_on = { 'candidate-index-pg': {} };
  candidate['runtime-target'].mem_limit = String(4 * 1024 ** 3);
  assert.notEqual(run(candidate).status, 0, 'a live candidate dependency must be explicit');
  assert.notEqual(
    run(candidate, true).status,
    0,
    'the existing eight GiB envelope is insufficient',
  );
  assert.equal(
    run(candidate, true, '9437184').status,
    0,
    'the explicit nine GiB slice is admitted',
  );
  assert.notEqual(run(candidate, true, 'unbounded').status, 0);
  const fixture = {
    additionalExternalMemoryBytes: 320 * 1024 ** 2,
    identity: {
      token: 'a'.repeat(32),
      volumeName: `openpc-rpc-enospc-${'a'.repeat(32)}`,
      targetRuntimeId: '018f0000-0000-7000-8000-000000009999',
    },
  };
  const baseline = run(candidate, true, '9437184');
  const reserved = run(candidate, true, '9765381', fixture);
  assert.equal(reserved.status, 0, reserved.stderr);
  const phases = (text) => [...text.matchAll(/RESOURCE_PHASE\|([^|]+)\|bytes=(\d+)/gu)];
  const before = phases(baseline.stderr),
    after = phases(reserved.stderr);
  assert.equal(after.length, 3);
  for (let index = 0; index < after.length; index++) {
    assert.equal(after[index][1], before[index][1]);
    assert.equal(Number(after[index][2]) - Number(before[index][2]), 320 * 1024 ** 2);
  }
  const tight = structuredClone(candidate);
  // Exactly consume the old nine GiB slice; the external keeper must then
  // require explicit additional admission, rather than hide under its cap.
  const targetBytes = Number(before.find((entry) => entry[1] === 'target')[2]);
  tight['runtime-target'].mem_limit = String(
    Number(tight['runtime-target'].mem_limit) + 9 * 1024 ** 3 - targetBytes,
  );
  assert.equal(run(tight, true, '9437184').status, 0);
  assert.notEqual(run(tight, true, '9437184', fixture).status, 0);
  assert.equal(run(tight, true, '9765381', fixture).status, 0);
  // Static nine-GiB profile + eight whole fixtures and the actual phase
  // separately fit; the actual phase + seven other fixtures does not.
  const union = structuredClone(tight);
  union['runtime-target'].mem_limit = String(Number(union['runtime-target'].mem_limit) + 1024 ** 3);
  const completeKib = String(Math.ceil(11.691 * 1024 ** 2));
  assert.ok(9 * 1024 ** 3 + 8 * 320 * 1024 ** 2 < Number(completeKib) * 1024);
  assert.equal(run(union, true, completeKib, fixture).status, 0);
  const rejectedUnion = run(union, true, completeKib, fixture, 7 * 320 * 1024 ** 2);
  assert.notEqual(rejectedUnion.status, 0);
  assert.equal(rejectedUnion.stdout, '');
  assert.match(rejectedUnion.stderr, /exceeds external memory admission/);
  assert.equal(run(tight, true, completeKib, fixture, 7 * 320 * 1024 ** 2).status, 0);
  assert.notEqual(run(tight, true, completeKib, fixture, 'unknown').status, 0);
  for (const malformed of [
    null,
    {},
    { ...fixture, additionalExternalMemoryBytes: 1 },
    { ...fixture, extra: true },
    { ...fixture, identity: { ...fixture.identity, volumeName: 'foreign' } },
  ]) {
    assert.notEqual(run(candidate, true, '9765381', malformed).status, 0);
  }
  const duplicated = structuredClone(candidate);
  duplicated['fixture-keeper'] = {
    mem_limit: String(256 * 1024 ** 2),
    labels: { 'io.openpc.fixture': 'rpc-journal-enospc' },
  };
  assert.notEqual(run(duplicated, true, '9765381', fixture).status, 0);

  for (const mutate of [
    (config) => {
      config['control-pg'].mem_limit = String(16 * 1024 ** 3);
    },
    (config) => {
      delete config['runtime-target'].mem_limit;
    },
    (config) => {
      config['runtime-target'].depends_on = { 'candidate-index-pg': {} };
    },
    (config) => {
      config['runtime-target'].depends_on = { 'participant-service': {} };
    },
  ]) {
    const config = structuredClone(services);
    mutate(config);
    const result = run(config);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
  }
});

const compose = await readFile('deploy/compose/local/compose.yaml', 'utf8');
const gateway = await readFile('deploy/compose/local/envoy/local-gateway.yaml', 'utf8');
test('native WebAuthn routes allow bounded owner verification and durable readback before the generic UI route', () => {
  const generic = gateway.indexOf('prefix: "/api/v1/ui/"');
  assert.ok(generic > 0);
  for (const phase of ['challenge', 'verify']) {
    const path = `path: "/api/v1/ui/webauthn/assertion/${phase}"`;
    const position = gateway.indexOf(path);
    assert.ok(position >= 0 && position < generic);
    const route = gateway.slice(position, gateway.indexOf('- match:', position + path.length));
    assert.match(route, /cluster: admin_web, timeout: 120s/);
  }
});
const health = await readFile('deploy/compose/local/postgres-final-healthcheck.sh', 'utf8');
const migrate = await readFile('deploy/compose/local/migrate.sh', 'utf8');
test('shared lifecycle migration validates prefixes and emits one atomic original transition', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'lifecycle-migration-'));
  try {
    for (const owner of ['identity', 'control-api']) {
      await mkdir(join(root, owner));
      for (const name of await readdir(`migrations/postgres/${owner}`)) {
        if (
          !/^(0099_stiff_lockjaw|0100_provider_qualification_resume|014[3-9]_.+|015[0-6]_.+)\.sql$/u.test(
            name,
          )
        )
          continue;
        await symlink(
          join(process.cwd(), 'migrations/postgres', owner, name),
          join(root, owner, name),
        );
      }
    }
    const functionSource = migrate
      .slice(
        migrate.indexOf('apply_control_shared_lifecycle_transition()'),
        migrate.indexOf('apply_control_recreation_pair()'),
      )
      .replaceAll('/migrations/postgres', root);
    const script = join(root, 'test.sh');
    await writeFile(
      script,
      `#!/bin/sh
set -eu
ledger_digest() {
 name="\${1##*/}"; number="\${name%%_*}"
 if [ "\${DRIFT:-}" = "$name" ]; then printf '%s\\n' drift; return; fi
 if [ "$number" -lt 143 ] || [ "$number" -le "\${PREFIX:-142}" ] || [ "$number" -eq "\${HOLE:-0}" ]; then sha256sum "$1" | cut -d ' ' -f 1; fi
}
emit_ledger_insert() { printf '%s\\n' '' 'RESET ROLE;' "INSERT INTO openpc_local.migration(path,sha256) VALUES (:'path',:'digest');"; }
psql_base() {
 if [ "$1" = -At ]; then printf '%s\\n' "$((\${PREFIX:-142} - 142 + \${UNKNOWN:-0}))"; return; fi
 printf '%s\\n' "$1" > "$CAPTURE.args"; cat > "$CAPTURE"; return "\${SQL_EXIT:-0}";
}
${functionSource}
apply_control_shared_lifecycle_transition
`,
    );
    const run = (extra = {}) =>
      spawnSync('sh', [script], {
        env: { ...process.env, CAPTURE: join(root, 'sql'), ...extra },
        encoding: 'utf8',
      });
    assert.equal(run().status, 0);
    assert.equal((await readFile(join(root, 'sql.args'), 'utf8')).trim(), '-1');
    const sql = await readFile(join(root, 'sql'), 'utf8');
    assert.ok(sql.indexOf('pg_advisory_xact_lock') < sql.indexOf('CREATE OR REPLACE FUNCTION'));
    assert.ok(
      sql.indexOf('unexpected installed shared lifecycle') <
        sql.indexOf('CREATE OR REPLACE FUNCTION'),
    );
    assert.match(
      sql,
      /LOCK TABLE control\.work_item,control\.outbox_event,control\.notification_delivery IN ACCESS EXCLUSIVE MODE/u,
    );
    assert.equal(
      (sql.match(/INSERT INTO openpc_local\.migration\(path,sha256\)/gu) ?? []).length,
      14,
    );
    assert.ok(
      sql.lastIndexOf('shared lifecycle current restoration failed') >
        sql.lastIndexOf('INSERT INTO openpc_local.migration'),
    );
    for (const name of (await readdir(join(root, 'control-api'))).sort()) {
      assert.ok(sql.includes(await readFile(join(root, 'control-api', name), 'utf8')), name);
    }
    assert.equal(run({ PREFIX: '148' }).status, 0);
    assert.equal(
      (
        (await readFile(join(root, 'sql'), 'utf8')).match(
          /INSERT INTO openpc_local\.migration\(path,sha256\)/gu,
        ) ?? []
      ).length,
      8,
    );
    await rm(join(root, 'sql'));
    assert.equal(run({ PREFIX: '156' }).status, 0);
    await assert.rejects(stat(join(root, 'sql')), { code: 'ENOENT' });
    for (const env of [
      { HOLE: '145' },
      { UNKNOWN: '1' },
      { PREFIX: '156', UNKNOWN: '1' },
      { DRIFT: '0099_stiff_lockjaw.sql' },
      { PREFIX: '148', DRIFT: '0144_notification_publication_scope_guard.sql' },
    ]) {
      const result = run(env);
      assert.notEqual(result.status, 0, result.stderr);
      await assert.rejects(stat(join(root, 'sql')), { code: 'ENOENT' });
    }
    assert.equal(run({ SQL_EXIT: '37' }).status, 37);
    await rm(join(root, 'sql'));
    await rm(join(root, 'control-api/0156_notification_completion_shared.sql'));
    assert.notEqual(run().status, 0);
    await assert.rejects(stat(join(root, 'sql')), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('Fact roles-only restore prepares exact migration roles without schema, trust or password interpolation', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'fact-roles-mode-'));
  try {
    const secrets = join(root, 'secrets');
    await mkdir(secrets);
    await writeFile(join(secrets, 'fact_pg_password'), 'test-only-password');
    await writeFile(join(secrets, 'fact_runtime_db_password'), "writer'quoted-password");
    await writeFile(join(secrets, 'policy_fact_db_password'), "reader'quoted-password");
    // This secret must not be read, validated or installed in restore preparation.
    await mkdir(join(secrets, 'fact_capability_secret'));
    const script = join(root, 'migrate.sh');
    await writeFile(script, migrate.replaceAll('/run/secrets', secrets));
    const log = join(root, 'sql');
    const args = join(root, 'args');
    await writeFile(
      join(root, 'psql'),
      '#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGS_LOG"\ncat > "$SQL_LOG"\nexit "${PSQL_EXIT:-0}"\n',
      { mode: 0o700 },
    );
    const env = {
      ...process.env,
      PATH: `${root}:${process.env.PATH}`,
      SQL_LOG: log,
      ARGS_LOG: args,
      PGHOST: '127.0.0.1',
      PGUSER: 'openpc_facts',
      PGDATABASE: 'openpc_facts',
    };
    const result = spawnSync('sh', [script, 'fact-roles'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const sql = await readFile(log, 'utf8');
    const argv = await readFile(args, 'utf8');
    assert.match(argv, /(?:^|\n)-1(?:\n|$)/u, 'empty check and roles share one transaction');
    assert.match(argv, /ON_ERROR_STOP=1/u);
    assert.match(sql, /current_database\(\)<>'openpc_facts'/u);
    assert.match(sql, /fact roles-only restore target must be empty openpc_facts/u);
    assert.ok(sql.indexOf('RAISE EXCEPTION') < sql.indexOf('CREATE ROLE'));
    const migratedRoles = [];
    for (const name of (await readdir('migrations/postgres/facts')).filter((name) =>
      /^\d{4}_.*\.sql$/u.test(name),
    )) {
      const body = await readFile(join('migrations/postgres/facts', name), 'utf8');
      migratedRoles.push(...[...body.matchAll(/CREATE ROLE [^;]+;/gu)].map(([role]) => role));
    }
    const restoreRoles = [...sql.matchAll(/CREATE ROLE [^;]+;/gu)].map(([role]) => role);
    assert.equal(restoreRoles.length, migratedRoles.length + 2);
    for (const role of migratedRoles) assert.ok(restoreRoles.includes(role), role);
    assert.match(sql, /GRANT openpc_fact_bridge_writer TO openpc_fact_runtime/u);
    assert.match(sql, /GRANT openpc_policy_fact_reader TO openpc_policy_fact_runtime/u);
    assert.match(sql, /PASSWORD :'runtime_password'/u);
    assert.match(sql, /PASSWORD :'reader_password'/u);
    assert.doesNotMatch(sql, /CREATE SCHEMA|CREATE TABLE|INSERT INTO|mutation_capability_secret/u);
    assert.doesNotMatch(
      sql + argv + result.stdout + result.stderr,
      /quoted-password|test-only-password/u,
    );
    assert.equal(result.stdout, '');
    const failed = spawnSync('sh', [script, 'fact-roles'], {
      env: { ...env, PSQL_EXIT: '7' },
      encoding: 'utf8',
    });
    assert.equal(failed.status, 7, 'SQL failure remains a failure');
    await rm(log);
    await writeFile(join(secrets, 'fact_runtime_db_password'), '');
    const empty = spawnSync('sh', [script, 'fact-roles'], { env, encoding: 'utf8' });
    assert.notEqual(empty.status, 0);
    await assert.rejects(readFile(log), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('candidate roles-only restore preparation skips migrations, ledger and replacement trust', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'candidate-roles-mode-'));
  try {
    const secrets = join(root, 'secrets');
    await mkdir(secrets);
    await writeFile(join(secrets, 'candidate_index_pg_password'), 'test-only-password');
    await writeFile(join(secrets, 'indexer_writer_db_password'), 'test-only-writer-password');
    // A supplied capability must still be untouched by this preparation mode.
    await writeFile(join(secrets, 'candidate_retirement_capability_secret'), 'invalid-canary');
    const script = join(root, 'migrate.sh');
    await writeFile(script, migrate.replaceAll('/run/secrets', secrets));
    const log = join(root, 'sql');
    await writeFile(join(root, 'psql'), '#!/bin/sh\ncat >> "$SQL_LOG"\n', { mode: 0o700 });
    const env = {
      ...process.env,
      PATH: `${root}:${process.env.PATH}`,
      SQL_LOG: log,
      PGHOST: '127.0.0.1',
      PGUSER: 'postgres',
      PGDATABASE: 'openpc_candidate_index',
    };
    const result = spawnSync('sh', [script, 'candidate_index-roles'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const sql = await readFile(log, 'utf8');
    assert.match(sql, /current_database\(\)<>'openpc_candidate_index'/u);
    assert.match(sql, /candidate roles-only restore target must be empty/u);
    assert.match(sql, /CREATE ROLE openpc_candidate_index_owner NOLOGIN NOSUPERUSER/u);
    assert.match(
      sql,
      /ALTER DATABASE openpc_candidate_index OWNER TO openpc_candidate_index_owner/u,
    );
    assert.match(sql, /ALTER ROLE :"runtime_role" LOGIN NOSUPERUSER/u);
    assert.doesNotMatch(sql, /CREATE SCHEMA|CREATE TABLE|INSERT INTO|openpc_migration_checksum/u);
    assert.doesNotMatch(sql, /invalid-canary|test-only-password|test-only-writer-password/u);
    assert.equal(result.stdout, '');
    // A rejected emptiness prerequisite stops before role or password changes.
    await writeFile(log, '');
    await writeFile(join(root, 'psql'), '#!/bin/sh\ncat >> "$SQL_LOG"\nexit 7\n', { mode: 0o700 });
    const failed = spawnSync('sh', [script, 'candidate_index-roles'], { env, encoding: 'utf8' });
    assert.equal(failed.status, 7);
    assert.doesNotMatch(await readFile(log, 'utf8'), /CREATE ROLE|ALTER ROLE|ALTER DATABASE/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
const controlMigrationGenerator = await readFile(
  'services/control-api/src/configuration/generate-security-tail.mjs',
  'utf8',
);
const runnerEntry = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
let runner = runnerEntry;
for (const name of [
  'runner-harness',
  'authenticated-http',
  'runtime-configuration',
  'policy-lifecycle',
]) {
  runner = runner.replace(
    `source "$repository_root/tests/integration/local-runtime/${name}.sh"`,
    await readFile(`tests/integration/local-runtime/${name}.sh`, 'utf8'),
  );
}
const participantGovernedWrite = await readFile(
  'tests/integration/local-runtime/participant-governed-write.sh',
  'utf8',
);
const adminDockerfile = await readFile('apps/admin-web/Dockerfile', 'utf8');
const identityDockerfile = await readFile('services/identity-service/Dockerfile', 'utf8');
const participantDockerfile = await readFile('services/participant-service/Dockerfile', 'utf8');
const participantRuntime = await readFile(
  'services/participant-service/src/local-runtime.ts',
  'utf8',
);
const identityRuntime = await readFile('services/identity-service/src/local-runtime.ts', 'utf8');
const localWebAuthn = await readFile(
  'services/identity-service/src/domain/local-webauthn-trust-adapter.ts',
  'utf8',
);
const webAuthnBrowser = await readFile(
  'tests/integration/local-runtime/webauthn-browser.mjs',
  'utf8',
);
const configurationWebAuthnBrowser = await readFile(
  'tests/integration/local-runtime/configuration-webauthn-browser.mjs',
  'utf8',
);
const participantWorkbenchBrowser = await readFile(
  'tests/integration/local-runtime/participant-workbench-browser.mjs',
  'utf8',
);
const localIdentityAuthorization = await readFile(
  'services/identity-service/src/domain/local-identity-authorization.ts',
  'utf8',
);
const localConfigurationAuthorization = await readFile(
  'services/identity-service/src/domain/local-configuration-authorization.ts',
  'utf8',
);
const localOperationId = await readFile(
  'services/identity-service/src/domain/local-operation-id.ts',
  'utf8',
);
const atomicConfigurationMutation = await readFile(
  'services/control-api/src/configuration/persistence/atomic-mutation.ts',
  'utf8',
);
const runtimeTargetRepository = await readFile(
  'services/control-api/src/configuration/repositories/runtime-targets.ts',
  'utf8',
);
const configurationFixture = await readFile(
  'tests/integration/local-runtime/configuration-fixture.mjs',
  'utf8',
);
const runnerPath = 'tests/integration/local-runtime/run-compose-e2e.sh';
const pinnedNode =
  'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43';

function selfTest(mode) {
  return spawnSync('/usr/bin/bash', [runnerPath], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, OPENPC_LOCAL_RUNTIME_AGGREGATE_SELF_TEST: mode },
  });
}

test('PostgreSQL health admits only the final PID-1 server and exact database', () => {
  const pidIdentity = '[ "$(cat /proc/1/comm)" = postgres ]';
  assert.equal(
    health.match(new RegExp(pidIdentity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'))?.length,
    1,
  );
  assert.ok(health.indexOf(pidIdentity) < health.indexOf('psql -X'));
  assert.match(health, /-h 127\.0\.0\.1/);
  assert.match(health, /-d "\$database"/);
  assert.match(health, /\[ "\$result" = "\$database" \]/);
  assert.doesNotMatch(health, /pg_isready/);

  assert.match(compose, /healthcheck: &postgres-final-healthcheck/);
  assert.equal((compose.match(/healthcheck: \*postgres-final-healthcheck/g) ?? []).length, 3);
  assert.match(compose, /test: \["CMD", "sh", "\/postgres_final_healthcheck"\]/);
  assert.equal((compose.match(/configs: \[postgres_final_healthcheck\]/g) ?? []).length, 3);
});

test('migration discovery admits every four-digit generated migration', () => {
  assert.doesNotMatch(migrate, /\/migrations\/postgres\/[^/]+\/000\*\.sql/);
  for (const store of ['identity', 'policy', 'control-api', 'candidate-index']) {
    assert.match(
      migrate,
      new RegExp(
        `/migrations/postgres/${store.replace('-', '\\-')}/\\[0-9\\]\\[0-9\\]\\[0-9\\]\\[0-9\\]_\\*\\.sql`,
      ),
    );
  }
  assert.match(migrate, /\/migrations\/postgres\/identity\/\[0-9\]\[0-9\]\[0-9\]\[0-9\]_\*\.sql/);
  assert.match(controlMigrationGenerator, /\^\[0-9\]\{4\}_\.\*\\\.sql\$/);
  assert.doesNotMatch(controlMigrationGenerator, /\^000\[0-9\]/);
});

test('governed control routes retain finite response budgets', () => {
  const controlRoutes = [...gateway.matchAll(/route: \{ cluster: control_api([^}]*)\}/gu)];
  assert.ok(controlRoutes.length >= 33, 'Control route selection must be nonempty and complete');
  for (const route of controlRoutes) {
    const timeout = /timeout: ([1-9][0-9]*)s/u.exec(route[1]);
    assert.ok(timeout, 'Governed control routes must not inherit the short router default');
    const seconds = Number(timeout[1]);
    assert.ok(seconds >= 40 && seconds <= 120, 'Control response budgets must stay bounded');
  }
  assert.match(
    gateway,
    /prefix: "\/api\/v1\/ui\/" \}\s+route: \{ cluster: admin_web, timeout: 120s \}/u,
  );
});

test('the public gateway reaches implemented API owners before its closed fallback', () => {
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/modules", headers: \[\{ name: ":method", string_match: \{ exact: "POST" \} \}\] \}\s+route: \{ cluster: control_api, timeout: 60s \}/,
  );
  const sessionRoute = gateway.indexOf('path_separated_prefix: "/api/v1/session"');
  const policyRoute = gateway.indexOf('path_separated_prefix: "/api/v1/policy-versions"');
  const policySetRoute = gateway.indexOf('path_separated_prefix: "/api/v1/policy-sets"');
  const approvalRoute = gateway.indexOf('path_separated_prefix: "/api/v1/approval-requests"');
  const releaseRoute = gateway.indexOf('path_separated_prefix: "/api/v1/release-bundles"');
  const occurrenceRoute = gateway.indexOf(
    'path_separated_prefix: "/api/v1/activation-occurrences"',
  );
  const configurationRoute = gateway.indexOf('path_separated_prefix: "/api/v1/abi-artifacts"');
  const closedFallback = gateway.indexOf('prefix: "/api/"');
  assert.ok(sessionRoute >= 0);
  assert.ok(policyRoute > sessionRoute);
  assert.ok(approvalRoute > policyRoute);
  assert.ok(policySetRoute > policyRoute && policySetRoute < closedFallback);
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/policy-sets" \}\s+route: \{ cluster: control_api, timeout: 60s \}/u,
  );
  assert.ok(releaseRoute > approvalRoute);
  assert.ok(occurrenceRoute > releaseRoute);
  assert.ok(configurationRoute > occurrenceRoute);
  assert.ok(closedFallback > configurationRoute);
  for (const resource of [
    'abi-artifacts',
    'contract-method-policies',
    'deployment-policies',
    'deployment-intents',
    'contract-runtime-bindings',
    'indexer-profiles',
    'evidence-records',
    'logical-contract-assets',
    'operations',
    'notifications',
    'work-items',
    'projection-plans',
    'provider-profiles',
    'runtime-targets',
    'typed-argument-rule-versions',
  ]) {
    const route = gateway.indexOf(`path_separated_prefix: "/api/v1/${resource}"`);
    assert.ok(route >= configurationRoute, resource);
    assert.ok(route < closedFallback, resource);
  }
  assert.match(gateway, /route: \{ cluster: policy_service \}/);
  assert.match(gateway, /route: \{ cluster: control_api, timeout: 60s \}/);
  assert.match(gateway, /address: policy-service, port_value: 3002/);
  assert.match(gateway, /address: control-api, port_value: 3003/);
  assert.match(compose, /policy-service: \{ condition: service_healthy \}/);
  assert.match(compose, /control-api: \{ condition: service_healthy \}/);
  assert.match(compose, /oidc-emulator: \{ condition: service_healthy \}/);
  assert.match(compose, /IDENTITY_MTLS_LISTEN: 0\.0\.0\.0:3443/);
  assert.match(runner, /workload_mtls_status/);
  assert.match(runner, /workload-mtls-wrong-san/);
  assert.doesNotMatch(identityRuntime, /local\/workload\/authenticate/);
  assert.match(runner, /oidc_attempt oidc-nonce-denial nonce operator denied/);
  assert.match(runner, /oidc_attempt oidc-state-denial state viewer denied/);
  assert.match(runner, /oidc_attempt oidc-success success operator success/);
  assert.match(runner, /oidc_attempt oidc-viewer-success success viewer success/);
  assert.match(runner, /api\/v1\/ui\/oidc-session/);
  assert.match(runner, /openpc_oidc_custody/);
  assert.match(runner, /value\.stepUpVerifiedAt!==null/);
  assert.match(runner, /"sessionToken" in value/);
  assert.match(
    runner,
    /OPENPC_OIDC_BFF\|PASS\|roles=2\|denials=5\|provider_identity=durable\|account_hint=advisory\|replay=denied\|raw_session=server_only/,
  );
  assert.doesNotMatch(runner, /api\/v1\/session\/oidc\/authorization/);
  assert.match(runner, /Cookie: __Host-openpc_session=\$configuration_operator_session/);
  assert.match(runner, /127\.0\.0\.1:8080\/api\/v1\/policy-versions\/\$policy_version_urn/);
  assert.match(runner, /127\.0\.0\.1:8080\/api\/v1\/runtime-targets\/\$target_urn/);
});

test('OIDC redirect checks distinguish denial, replay and a real server-only session', async () => {
  const root = await mkdtemp('/tmp/openpc-oidc-callback-');
  const headers = join(root, 'callback.headers');
  const source = await readFile('tests/integration/local-runtime/authenticated-http.sh', 'utf8');
  const callback = source.slice(
    source.indexOf('oidc_callback_result() {'),
    source.indexOf('\noidc_attempt() {'),
  );
  const run = (outcome) =>
    spawnSync(
      '/usr/bin/bash',
      ['-c', `${callback}\noidc_callback_result "$1" "$2"`, 'callback', headers, outcome],
      { encoding: 'utf8' },
    );
  const clear =
    'set-cookie: openpc_oidc_custody=; Path=/api/v1/ui/oidc-session/callback; Max-Age=0; HttpOnly\r\n';
  const denied = `HTTP/1.1 307 Temporary Redirect\r\nlocation: http://localhost:8080/configure/policies?oidcError=authentication_failed\r\n${clear}`;
  const session =
    'set-cookie: openpc_local_runtime_session=private-test-value; Path=/; HttpOnly; SameSite=strict\r\n';
  const success = `HTTP/1.1 307 Temporary Redirect\r\nlocation: http://localhost:8080/configure/policies\r\n${clear}${session}`;
  try {
    await writeFile(headers, denied);
    assert.equal(run('denied').status, 0);
    assert.notEqual(run('success').status, 0, 'an error redirect is not success');
    await writeFile(headers, success);
    assert.equal(run('success').status, 0);
    assert.notEqual(run('denied').status, 0, 'a issued session is not a denial');
    for (const invalid of [
      denied + session,
      denied.replace('http://localhost:8080', 'https://attacker.invalid'),
      denied.replace(clear, ''),
      denied + 'set-cookie: __Host-openpc_session=raw-private-token\r\n',
      success.replace('HttpOnly; SameSite=strict', 'SameSite=strict'),
      success.replace('SameSite=strict', 'SameSite=lax'),
      success.replace(session, ''),
    ]) {
      await writeFile(headers, invalid);
      const result = run(invalid.includes('oidcError=') ? 'denied' : 'success');
      assert.notEqual(result.status, 0);
      assert.doesNotMatch(result.stderr, /private-test-value|raw-private-token/);
    }
  } finally {
    await rm(root, { recursive: true });
  }
});

test('OIDC provider selection keeps subject and principal consistent while substitution is denied', async () => {
  const source = await readFile('tests/integration/local-runtime/authenticated-http.sh', 'utf8');
  const start = source.indexOf(
    '    const fs = require("node:fs");',
    source.indexOf('authorization_url="$(node -e'),
  );
  const end = source.indexOf('\n  \' "$evidence_root/$name-begin.json"', start);
  assert.ok(start > 0 && end > start);
  const code = source.slice(start, end);
  const root = await mkdtemp('/tmp/openpc-oidc-selection-');
  const begin = join(root, 'begin.json');
  const principal = '018f0000-0000-7000-8000-000000000111';
  try {
    await writeFile(
      begin,
      JSON.stringify({ authorizationUri: 'http://provider.test/authorize?login_hint=viewer' }),
    );
    for (const mode of ['selected-subject', 'subject-substitution']) {
      const result = spawnSync(process.execPath, ['-e', code, begin, mode, principal], {
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
      const url = new URL(result.stdout);
      assert.equal(url.searchParams.get('login_hint'), 'viewer');
      assert.equal(url.searchParams.get('openpc_test_subject'), principal);
      assert.equal(
        url.searchParams.get('openpc_test_principal_id'),
        mode === 'selected-subject' ? principal : null,
      );
    }
    assert.match(
      runnerEntry,
      /oidc_attempt oidc-subject-substitution-denial subject-substitution viewer denied/u,
    );
    assert.match(
      runnerEntry,
      /oidc_attempt oidc-provider-selection selected-subject viewer success operator/u,
    );
  } finally {
    await rm(root, { recursive: true });
  }
});

test('initial enrollment retains private authenticator custody before lost-response reconciliation', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/webauthn-enrollment-browser.mjs',
    'utf8',
  );
  assert.ok(source.indexOf("flag: 'wx'") < source.indexOf('chromium.launch'));
  assert.match(source, /mkdir\(privateRoot, \{ mode: 0o700 \}\)/u);
  assert.match(source, /WebAuthn.getCredentials/u);
  assert.match(
    source,
    /committedResponseLost = true;\s+await preserveBrowserCustody\(\);\s+await route.abort/u,
  );
  assert.match(source, /finally \{\s+await preserveBrowserCustody\(\);\s+await browser.close/u);
  assert.match(runnerEntry, /webauthn-enrollment-browser\.mjs operator "\$evidence_root"/u);
  assert.match(runnerEntry, /webauthn-enrollment-browser\.mjs viewer "\$evidence_root"/u);
});

test('idempotency replay compares parsed JSON semantics rather than object key order', () => {
  assert.equal((runner.match(/^assert_json_equal\(\)/gm) ?? []).length, 1);
  assert.match(
    runner,
    /assert\.deepStrictEqual\(read\(process\.argv\[1\]\), read\(process\.argv\[2\]\)\)/,
  );
  assert.match(
    runner,
    /assert_json_equal \\\n+ {2}"\$evidence_root\/configuration-indexer\.json" \\\n+ {2}"\$evidence_root\/configuration-indexer-replay\.json"/,
  );
  assert.match(
    runner,
    /assert_json_equal "\$evidence_root\/action\.json" "\$evidence_root\/replay\.json"/,
  );
  assert.match(
    runner,
    /assert_json_equal "\$evidence_root\/action\.json" "\$evidence_root\/stale-replay\.json"/,
  );
  assert.doesNotMatch(runner, /cmp "\$evidence_root\/(?:configuration-indexer|action)\.json"/);
});

test('configuration runtime owns a real governed Participant write', () => {
  assert.match(runner, /source tests\/integration\/local-runtime\/participant-governed-write\.sh/);
  assert.match(participantGovernedWrite, /Authorization: Bearer \$configuration_operator_session/);
  assert.match(participantGovernedWrite, /ID-OP-ENVELOPE-CREATE/);
  assert.match(participantGovernedWrite, /\/api\/v1\/approval-requests/);
  assert.match(participantGovernedWrite, /checker_assertion_step_up/);
  assert.match(participantGovernedWrite, /candidate\.state\|\|/);
  assert.match(participantGovernedWrite, /control\.mutation_evidence/);
  assert.match(participantGovernedWrite, /control\.outbox_event/);
  assert.match(participantGovernedWrite, /restart participant-service/);
  assert.match(
    participantGovernedWrite,
    /OPENPC_PARTICIPANT_GOVERNED_WRITE\|PASS\|public_approval\|operator_step_up\|candidate_consumed\|evidence\|outbox\|replay\|restart/,
  );
});

test('configuration join uses frozen resources, durable operations, and real local identity proof', () => {
  assert.doesNotMatch(runner, /Authorization: Bearer \$configuration_session/);
  assert.doesNotMatch(runner, /runtime-configuration-generations|runtime_configuration_work/);
  assert.match(runner, /Cookie: __Host-openpc_session=\$configuration_operator_session/);
  assert.match(runner, /\/api\/v1\/operations\/\$operation_id/);
  assert.match(runner, /configuration-runtime-activate-0001[\s\S]*PATCH/);
  assert.match(runner, /OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY/);
  assert.match(
    runner,
    /OPENPC_CONFIGURATION_JOIN\|PASS\|configuration-work\|operations\|events\|webauthn-evidence/,
  );
  assert.match(runner, /\/v1\/identity\/webauthn\/assertion\/verify/);
  assert.match(runner, /OPENPC_LOCAL_RUNTIME_WEBAUTHN_BROWSER_ONLY/);
  assert.match(runner, /webauthn-browser\.mjs/);
  assert.match(runner, /OPENPC_LOCAL_RUNTIME_PARTICIPANT_WORKBENCH_ONLY/);
  assert.match(runner, /participant-workbench-browser\.mjs run/);
  assert.match(runner, /restart participant-service policy-service admin-web/);
  assert.match(participantWorkbenchBrowser, /authenticate\(operatorPage, 'operator'\)/);
  assert.match(participantWorkbenchBrowser, /authenticate\(checkerPage, 'viewer'\)/);
  assert.match(participantWorkbenchBrowser, /WebAuthn\.credentialAsserted/);
  assert.match(participantWorkbenchBrowser, /simulateResponseLoss: true/);
  assert.match(
    participantWorkbenchBrowser,
    /OPENPC_PARTICIPANT_WORKBENCH_RESTART\|PASS\|session=restored\|operation=durable\|effect=durable/,
  );
  assert.match(runner, /\/internal\/v1\/local\/configuration\/authorize/);
  assert.match(runner, /configuration_authorization_probe/);
  assert.match(runner, /origin: "http:\/\/127\.0\.0\.1:3001"/);
  assert.match(runner, /sha256-text 127\.0\.0\.1/);
  assert.match(runner, /control\.runtime_configuration_input_current/);
  assert.doesNotMatch(runner, /0\.0\.0-local-downstream-fixture/);
  assert.match(runner, /control\.configuration_work/);
  assert.match(
    runner,
    /local-fixture \\\n+ {2}"\$provider_id" "\$indexer_id" "\$projection_id" "\$workload_id"/,
  );
  assert.match(runner, /readiness\\":\\"UNKNOWN/);
  for (const name of ['provider_body', 'indexer_body', 'projection_body', 'target_body']) {
    const line = runner.split('\n').find((candidate) => candidate.startsWith(`${name}=`));
    assert.ok(line, name);
    for (const forbidden of [
      '\\\\"resourceId\\\\"',
      '\\\\"privacyDomainId\\\\"',
      '\\\\"idempotencyKey\\\\"',
      '\\\\"expectedRevision\\\\"',
      '\\\\"policyGenerationDigest\\\\"',
    ]) {
      assert.doesNotMatch(line, new RegExp(forbidden), `${name}:${forbidden}`);
    }
  }
  assert.match(migrate, /ACT-IDENTITY_UPDATE_STEP_UP-V1/);
  assert.match(
    migrate,
    /\('ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1','fact-artifacts','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_FACT_ARTIFACTS'\)/,
  );
  assert.match(
    migrate,
    /action_intent_ids \|\| ARRAY\[[\s\S]*'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'/,
  );
  assert.match(migrate, /ACT-OPERATIONS_READ_OPERATION-V1/);
  assert.match(compose, /IDENTITY_LOCAL_PRIVACY_DOMAIN_ID/);
  assert.match(identityRuntime, /createLocalWebAuthnTrustAdapter/);
  assert.match(identityRuntime, /createLocalIdentityAuthorizationAdapter/);
  assert.doesNotMatch(identityRuntime, /rejectingIdentityTrustAdapter/);
  for (const field of [
    'webauthnAssertionBindingDigest',
    'webauthnEvidenceCbor',
    'webauthnEvidenceDigest',
    'webauthnCoseSign1',
  ]) {
    assert.match(identityRuntime, new RegExp(`${field}\\.toString\\('base64'\\)`));
  }
  assert.match(localWebAuthn, /createPublicKey/);
  assert.match(localWebAuthn, /authenticatorData\.length !== 37/);
  assert.match(localWebAuthn, /\(authenticatorData\[32\]! & 0x05\) !== 0x05/);
  assert.match(localWebAuthn, /crossOrigin: z\.literal\(false\)/);
  assert.match(webAuthnBrowser, /WebAuthn\.addVirtualAuthenticator/);
  assert.match(webAuthnBrowser, /WebAuthn\.addCredential/);
  assert.match(webAuthnBrowser, /credentialAsserted/);
  assert.match(
    webAuthnBrowser,
    /OPENPC_WEBAUTHN_BROWSER\|PASS\|oidc=real\|context=rotated\|ceremonies=2\|counter=monotonic\|user_verification=required\|effect=completed/,
  );
  assert.match(runner, /configuration-webauthn-browser\.mjs/);
  assert.match(configurationWebAuthnBrowser, /WebAuthn\.addVirtualAuthenticator/);
  assert.match(configurationWebAuthnBrowser, /WebAuthn\.addCredential/);
  assert.match(configurationWebAuthnBrowser, /credentialAsserted/);
  assert.match(configurationWebAuthnBrowser, /ACT-POLICY_APPROVE_REQUEST-V1|actionIntentId/);
  assert.match(configurationWebAuthnBrowser, /OpenPC-Action-Intent-Digest/);
  assert.match(runner, /"openpc-action-intent-digest": actionDigest/);
  assert.match(
    configurationWebAuthnBrowser,
    /OPENPC_CONFIGURATION_WEBAUTHN_BROWSER\|PASS\|checker=distinct\|assertions=\$\{assertions\}\|counter=monotonic\|user_verification=required/,
  );
  assert.match(
    runner,
    /OPENPC_MUTATION_CANDIDATE_ADVERSARIAL\|PASS\|tamper=denied\|expiry=denied\|authority=revoked\|self=denied\|cross_privacy=denied\|staging=single_candidate\|concurrency=single_effect\|replay=idempotent/,
  );
  assert.equal(
    (runner.match(/checker_assertion_step_up "\$approval_decide_action" "\$approval_id"/g) ?? [])
      .length,
    3,
  );
  assert.match(localIdentityAuthorization, /LOCAL_IDENTITY_CREDENTIAL_BOOTSTRAP/);
  for (const localAdapter of [
    localWebAuthn,
    localIdentityAuthorization,
    localConfigurationAuthorization,
  ]) {
    assert.match(localAdapter, /localOperationId/);
    assert.doesNotMatch(localAdapter, /randomUUID/);
  }
  assert.match(localOperationId, /bytes\[6\].*\| 0x70/);
  assert.match(localOperationId, /bytes\[8\].*\| 0x80/);
  assert.match(localConfigurationAuthorization, /ar\.action_intent_id=\$3/);
  assert.match(localConfigurationAuthorization, /ar\.subject_type='CONFIGURATION_CANDIDATE'/);
  assert.match(localConfigurationAuthorization, /ar\.subject_digest=\$4/);
  assert.match(localConfigurationAuthorization, /ar\.subject_version=\$5/);
  assert.match(
    localConfigurationAuthorization,
    /proof\.checkerPrincipalId === null[\s\S]*\{ checkerPrincipalId: proof\.checkerPrincipalId \}/,
  );
  assert.match(
    localConfigurationAuthorization,
    /ad\.aggregate_version=ar\.subject_version and ad\.candidate_digest=ar\.subject_digest/,
  );
  assert.match(
    localConfigurationAuthorization,
    /principalId: session\.principalId,\n\s+sessionId: session\.sessionId,\n\s+actionIntentId: input\.actionIntentId,\n\s+candidateDigest/,
  );
  assert.doesNotMatch(
    localConfigurationAuthorization,
    /proof\.checkerPrincipalId,\n\s+input\.actionIntentId,\n\s+candidateDigest/,
  );
  assert.match(configurationFixture, /encodeIdentityCredentialPayload/);
  assert.match(configurationFixture, /signIdentityCredentialCoseSign1Es256/);
  assert.match(configurationFixture, /command === 'authorization-evidence'/);
  assert.doesNotMatch(runner, /seed_standard_configuration_authorization/);
  assert.match(localConfigurationAuthorization, /createIdentityRuntimeAuthorizationAssertion/);
  assert.match(
    localConfigurationAuthorization,
    /webauthnAssertionBindingDigest: stepUp\?\.webauthnAssertionBindingDigest/,
  );
  assert.match(runner, /ordinary-configuration-authorization\.mjs/);
  assert.doesNotMatch(runner, /seed_identity_mutation_authorization/);
  assert.match(
    runner,
    /approved_identity_mutation "\$evidence_root\/runtime-workload-assignment.json"/,
  );
  assert.match(atomicConfigurationMutation, /for update of challenge/);
  assert.doesNotMatch(atomicConfigurationMutation, /for share of challenge,verification/);
  assert.match(atomicConfigurationMutation, /error\.code === '40001'/);
  assert.match(atomicConfigurationMutation, /for \(let attempt = 0; attempt < 3; attempt \+= 1\)/);
  assert.match(
    atomicConfigurationMutation,
    /await client\.query\('rollback'\)[\s\S]*!producerGateComplete &&[\s\S]*rolledBack &&[\s\S]*isRuntimeSourceProducerContention\(error\)[\s\S]*if \(!producerContention && !isSerializationFailure\(error\)\) throw error;[\s\S]*if \(attempt === 2\)/,
  );
  for (const digestOwner of [runner, runtimeTargetRepository]) {
    assert.match(digestOwner, /encode\(sha256\(\s*configuration\.configuration_digest/);
    assert.doesNotMatch(digestOwner, /encode\(digest\(\s*configuration\.configuration_digest/);
  }
});

test('cleanup is sentinel-bound and removes root-owned data through the pinned image', () => {
  assert.match(
    runner,
    /logs --no-color --tail 200 identity-service participant-service policy-service fact-service control-api control-pg control-worker runtime-target signing-provider workload-issuer rpc-provider envoy runtime-envoy admin-web/,
  );
  assert.match(runner, /owner_sentinel="\$run_root\/\.openpc-local-runtime-owner"/);
  assert.match(runner, /\[ "\$\(cat "\$owner_sentinel"\)" = "\$owner_record" \]/);
  assert.match(runner, /\.openpc-local-runtime-owner\|data\|secrets\|evidence/);
  assert.match(runner, /find "\$run_root" -mindepth 1 -maxdepth 1 -print0/);
  assert.ok((runner.match(/\|\| return 1/g) ?? []).length >= 7);
  assert.match(
    runner,
    /docker run --rm --network none --memory 128m --memory-swap 128m --cpus 0\.5 --pids-limit 64 --entrypoint sh -v "\$run_root:\/openpc-run:rw"/,
  );
  assert.match(runner, /rm -rf -- \/openpc-run\/data/);
  assert.match(runner, /OPENPC_LOCAL_RUNTIME_CLEANUP_PROBE/);
  assert.match(runner, /docker ps -aq --filter "label=com\.docker\.compose\.project=\$project"/);
  assert.match(
    runner,
    /docker network ls -q --filter "label=com\.docker\.compose\.project=\$project"/,
  );
  assert.match(
    runner,
    /docker volume ls -q --filter "label=com\.docker\.compose\.project=\$project"/,
  );
  assert.doesNotMatch(runner, /down(?:[^\n]*)(?: --volumes| -v)(?: |$)/);
});

test('identity ESM bundle provides CommonJS builtin interop without changing its entry guard', () => {
  assert.match(identityDockerfile, /--format=esm/);
  assert.match(identityDockerfile, /createRequire \} from "node:module"/);
  assert.match(identityDockerfile, /const require = createRequire\(import\.meta\.url\)/);
  assert.match(
    identityDockerfile,
    /COPY --from=build --chown=openpc:openpc \/openpc-identity-runtime\.mjs \/app\/server\.mjs/,
  );
  assert.match(identityDockerfile, /ENTRYPOINT \["node", "\/app\/server\.mjs"\]/);
  assert.match(identityRuntime, /if \(import\.meta\.url === `file:\/\/\$\{process\.argv\[1\]\}`\)/);
});

test('participant service is a hardened identity-bound local runtime', () => {
  assert.match(compose, /participant-service:[\s\S]*PARTICIPANT_IDENTITY_URL/);
  assert.match(compose, /participant-service:[\s\S]*read_only: true/);
  assert.match(compose, /participant-service:[\s\S]*no-new-privileges:true/);
  assert.match(
    participantDockerfile,
    new RegExp(pinnedNode.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
  assert.match(participantDockerfile, /USER openpc/);
  assert.match(participantRuntime, /\/internal\/v1\/local\/session\/validate/);
  assert.match(participantRuntime, /\/internal\/v1\/local\/configuration\/authorize/);
  assert.match(participantRuntime, /sessionEpoch: epoch/);
  assert.match(participantRuntime, /AbortSignal\.timeout\(localQaExecutionTimeoutMs\(5_000\)\)/);
  assert.match(runner, /OPENPC_CONFIGURATION_JOIN\|PASS/);
  assert.match(runner, /participant-evaluation\.json/);
});

test('Envoy readiness uses exact HTTP/1.1 success framing and retains failure health logs', () => {
  assert.match(compose, /GET \/ready HTTP\/1\.1/);
  assert.match(compose, /Host: localhost/);
  assert.match(compose, /Connection: close/);
  assert.match(compose, /HTTP\/1\.1 200 OK/);
  assert.match(compose, /tr -d/);
  assert.match(compose, /grep -qx LIVE/);
  assert.doesNotMatch(compose, /GET \/ready HTTP\/1\.0/);
  assert.match(runner, /OPENPC_HEALTH\|\$\{container\.Name\}/);
  assert.match(runner, /map\(\(\{ Start, End, ExitCode \}\)/);
  assert.doesNotMatch(runner, /JSON\.stringify\(container\.State\.Health\)/);
  assert.doesNotMatch(runner, /logs --no-color control-migrate/);
  assert.match(runner, /done < <\("\$\{compose\[@\]\}" ps -aq\)/);
});

test('runtime images retain pinned entrypoints while removing package-manager closure', () => {
  assert.match(compose, /envoy:\n[\s\S]*?user: "101:101"/);
  assert.equal((adminDockerfile.match(new RegExp(pinnedNode, 'g')) ?? []).length, 2);
  assert.equal((identityDockerfile.match(new RegExp(pinnedNode, 'g')) ?? []).length, 2);
  assert.equal((participantDockerfile.match(new RegExp(pinnedNode, 'g')) ?? []).length, 2);
  for (const dockerfile of [adminDockerfile, identityDockerfile, participantDockerfile]) {
    assert.match(dockerfile, /rm -rf -- \/usr\/local\/lib\/node_modules\/npm/);
    assert.match(dockerfile, /\/usr\/local\/lib\/node_modules\/corepack/);
    for (const shim of [
      'npm',
      'npx',
      'corepack',
      'pnpm',
      'pnpx',
      'yarn',
      'yarnpkg',
      'tsc',
      'tsx',
    ]) {
      assert.match(dockerfile, new RegExp(`/usr/local/bin/${shim}(?:\\s|$)`));
    }
  }
  assert.match(adminDockerfile, /ENTRYPOINT \["node", "apps\/admin-web\/server\.js"\]/);
  assert.match(identityDockerfile, /ENTRYPOINT \["node", "\/app\/server\.mjs"\]/);
  assert.match(participantDockerfile, /ENTRYPOINT \["node", "\/app\/server\.mjs"\]/);
});

test('aggregate runner derives secret checks from one owner and reports simultaneous failures once', () => {
  assert.equal((runner.match(/^runtime_secret_names=\(/gm) ?? []).length, 1);
  assert.ok(runner.indexOf('runtime_secret_names=(') < runner.indexOf('aggregate_check_ids=('));
  const literalRegistry = runner.slice(
    runner.indexOf('aggregate_check_ids=('),
    runner.indexOf('declare -A aggregate_known'),
  );
  assert.doesNotMatch(literalRegistry, /^\s+secret_log\./m);
  assert.match(
    literalRegistry,
    /for secret_name in "\$\{runtime_secret_names\[@\]\}"; do\n\s+aggregate_check_ids\+=\("secret_log\.\$secret_name"\)/,
  );

  const success = selfTest('success');
  assert.equal(success.status, 0, success.stderr);
  const successEnds = success.stdout.match(/^OPENPC_CHECK_END\|[^\n]+$/gm) ?? [];
  assert.equal(successEnds.length, 81);
  assert.equal(new Set(successEnds.map((line) => line.split('|')[1])).size, 81);
  assert.match(
    success.stdout,
    /OPENPC_AGGREGATE\|PASS\|completed=81\|failures=0\|registry_errors=0/,
  );

  assert.match(success.stdout, /secret_log\.workload_issuer_token\|PASS/);
  assert.match(success.stdout, /secret_log\.source_control_db_password\|PASS/);
  assert.match(success.stdout, /secret_log\.candidate_retirement_capability_secret\|PASS/);
  assert.match(success.stdout, /secret_log\.fleet_fact_admission_key\|PASS/);
  assert.match(success.stdout, /secret_log\.fleet_fact_failure_signing_key\|PASS/);
  assert.match(success.stdout, /secret_log\.runtime_target_evidence_encryption_key\|PASS/);

  const dual = selfTest('dual-failure');
  assert.notEqual(dual.status, 0);
  assert.equal((dual.stdout.match(/^OPENPC_CHECK_END\|[^\n]+$/gm) ?? []).length, 81);
  assert.match(dual.stdout, /security\.admin\.user\|FAIL/);
  assert.match(dual.stdout, /secret_log\.local_viewer_credential\|FAIL/);
  assert.ok(
    dual.stdout.indexOf('security.admin.user|FAIL') <
      dual.stdout.indexOf('secret_log.local_viewer_credential|FAIL'),
  );
  assert.match(dual.stdout, /OPENPC_AGGREGATE\|FAIL\|completed=81\|failures=2/);

  const commandError = selfTest('command-error');
  assert.notEqual(commandError.status, 0);
  assert.match(
    commandError.stdout,
    /image\.identity\.inventory\|FAIL\|synthetic=sanitized_failure/,
  );
  assert.doesNotMatch(commandError.stdout, /raw secret|raw error/i);
});

test('aggregate registry and stopped-export classifier reject adversarial states', () => {
  const missing = selfTest('missing');
  assert.notEqual(missing.status, 0);
  assert.match(missing.stdout, /missing=1/);

  const duplicate = selfTest('duplicate');
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stdout, /registry=duplicate/);

  const unknown = selfTest('unknown');
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stdout, /synthetic\.unknown\|FAIL\|registry=unknown/);

  const classifier = selfTest('classifier');
  assert.equal(classifier.status, 0, classifier.stderr);
  assert.match(classifier.stdout, /OPENPC_CLASSIFIER_SELF_TEST\|PASS/);

  const ownership = selfTest('ownership');
  assert.equal(ownership.status, 0, ownership.stderr);
  assert.match(ownership.stdout, /OPENPC_INVENTORY_OWNERSHIP_SELF_TEST\|PASS/);

  assert.match(runner, /docker create --name "\$inventory_name"/);
  assert.match(runner, /docker export "\$inventory_container"[^\n]*\| tar -tf -/);
  assert.match(runner, /openpc\.inventory\.owner/);
  assert.match(runner, /inventory_labels_match/);
  assert.doesNotMatch(runner, /docker run --rm --entrypoint sh "\$image" -c '! find \//);
  for (const prerequisite of [
    'container_lookup',
    'inspect',
    'psql',
    'history',
    'create',
    'export_tar',
    'migration',
    'log_collection',
  ]) {
    assert.match(runner, new RegExp(`prerequisite=${prerequisite}`));
  }
  assert.match(runner, /pipeline_status=\("\$\{PIPESTATUS\[@\]\}"\)/);
  assert.match(runner, /if \[ "\$logs_status" -ne 0 \]/);
  assert.match(runner, /logs_status=\$\?/);
  assert.match(runner, /prerequisite=log_collection/);
});

test('real aggregate helpers are nounset-safe and fail closed through production entrypoints', () => {
  // These aggregate helpers belong to the entrypoint. Sourced journey helpers
  // have separate regression owners and may safely initialize optional inputs.
  const localDeclarations = runnerEntry.split('\n').filter((line) => /^\s*local\b/.test(line));
  assert.ok(localDeclarations.length > 0);
  for (const declaration of localDeclarations) {
    assert.doesNotMatch(declaration, /\$|=/, declaration);
  }

  for (const helper of [
    'check_container_property',
    'check_fact_role_flag',
    'check_image_history',
    'check_image_inventory',
    'check_migration_rerun',
  ]) {
    assert.equal((runner.match(new RegExp(`^${helper}\\(\\)`, 'gm')) ?? []).length, 1);
    assert.ok(
      runner.indexOf(`${helper}()`) <
        runner.indexOf('if [ -n "${OPENPC_LOCAL_RUNTIME_AGGREGATE_SELF_TEST:-}" ]'),
    );
  }

  const helperNounset = selfTest('helper-nounset');
  assert.equal(helperNounset.status, 0, helperNounset.stderr);
  assert.doesNotMatch(helperNounset.stderr, /unbound variable|nounset/i);
  const expectedIds = [
    'security.admin.user',
    'fact.role.rolsuper',
    'image.admin.history',
    'image.identity.inventory',
    'migration.control.rerun',
  ];
  for (const id of expectedIds) {
    assert.match(helperNounset.stdout, new RegExp(`OPENPC_CHECK_BEGIN\\|${id}`));
    assert.match(
      helperNounset.stdout,
      new RegExp(`OPENPC_CHECK_END\\|${id.replaceAll('.', '\\.')}\\|FAIL\\|prerequisite=`),
    );
  }
  assert.equal((helperNounset.stdout.match(/^OPENPC_CHECK_END\|/gm) ?? []).length, 5);
  assert.match(helperNounset.stdout, /OPENPC_HELPER_NOUNSET_SELF_TEST\|PASS\|completed=5/);

  assert.match(runner, /inventory_container_ids=\(\)/);
  assert.match(runner, /pipeline_status=\("\$\{PIPESTATUS\[@\]\}"\)/);
  assert.match(
    runner,
    /"\$\{compose\[@\]\}" run --rm "\$service" >\/dev\/null 2>&1\n\s+command_status=\$\?\n\s+if/,
  );
});

test('governance startup accepts completed migration jobs and rejects failed or missing jobs', () => {
  const start = runner.indexOf(
    '  "${compose[@]}" up -d --force-recreate --no-build --pull never control-migrate',
  );
  assert.ok(start > 0);
  const end = runner.indexOf('\n  done', start) + '\n  done'.length;
  const shell = `set -euo pipefail
compose_fixture() { if [ "$1" = ps ]; then [ "\${FIXTURE_MODE}" != missing ] && printf 'owned-migration\\n' || true; fi; }
docker() { if [ "\${FIXTURE_MODE}" = failed ]; then printf '7\\n'; else printf '0\\n'; fi; }
timeout() { shift; "$@"; }
compose=(compose_fixture)
${runner.slice(start, end)}
printf 'migrations-complete\\n'
`;
  for (const [mode, status] of [
    ['completed', 0],
    ['failed', 71],
    ['missing', 71],
  ]) {
    const result = spawnSync('bash', ['-c', shell], {
      env: { ...process.env, FIXTURE_MODE: mode },
      encoding: 'utf8',
    });
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout.includes('migrations-complete'), mode === 'completed');
  }
});

test('local builds reuse owned stable tags with an explicit isolated builder and current running image checks', async () => {
  const images = await readFile('scripts/maintenance/local-runtime-images.sh', 'utf8');
  for (const service of [
    'control-worker',
    'fact-service',
    'policy-service',
    'identity-service',
    'participant-service',
    'control-api',
    'admin-web',
  ]) {
    assert.ok(compose.includes(`  ${service}:\n    image: openpc-r1-dev/${service}:local\n`));
  }
  assert.equal(
    (compose.match(/io\.openpc\.image\.owner: openpc-r1-local-runtime-v1/g) ?? []).length,
    7,
  );
  assert.doesNotMatch(compose, /container_name:/);
  assert.match(
    runner,
    /build --builder "\$openpc_builder" --pull "\$\{capacity_args\[@\]\}" "\$image_service"/,
  );
  assert.match(runner, /up -d --wait --force-recreate --no-build --pull never/);
  assert.ok(
    runnerEntry.indexOf('openpc_capture_built_images') <
      runnerEntry.indexOf('openpc_verify_running_images'),
  );
  assert.doesNotMatch(runner, /for candidate_image in/);
  assert.match(runner, /openpc_assert_no_project_images/);
  assert.match(runner, /openpc_retire_replaced_images/);
  assert.match(images, /docker image rm "\$prior"/);
  assert.match(images, /ancestor=\$prior/);
  assert.match(images, /docker buildx prune --builder "\$openpc_builder" --filter 'until=168h'/);
  assert.match(images, /--filter 'until=6h'/);
  assert.match(images, /--filter 'type!=exec\.cachemount'/);
  assert.match(images, /\[ "\$cache_status" = 75 \] \|\| return "\$cache_status"/);
  assert.match(
    images,
    /--max-used-space 48GB --min-free-space 100GB --force \|\| return\n {2}openpc_cache_within_bound/,
  );
  assert.doesNotMatch(images, /docker (system|image|builder) prune/);
  assert.doesNotMatch(images, /create[^\n]*--use/);
  assert.match(images, /OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1/);
  assert.match(runner, /OPENPC_RETAINED_FAILURE/);
});

test('dedicated server capacity reaches image builds only when selected', () => {
  for (const [selected, jobs] of [
    ['0', '2'],
    ['1', '1'],
    ['1', '2'],
    ['1', '8'],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-euc',
        `
source tests/integration/local-runtime/runner-harness.sh
compose=(printf '%s\\n')
openpc_builder=openpc-r1-local-v1
openpc_build_one_image fact-service
`,
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, OPENPC_SERVER_CAPACITY: selected, CARGO_BUILD_JOBS: jobs },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n'), [
      'build',
      '--builder',
      'openpc-r1-local-v1',
      '--pull',
      ...(selected === '1' ? ['--build-arg', `OPENPC_CARGO_BUILD_JOBS=${jobs}`] : []),
      'fact-service',
    ]);
  }
});

test('dedicated image builds reject invalid Rust limits before Docker', () => {
  for (const jobs of ['', '0', '9', 'two', '2 --other']) {
    const result = spawnSync(
      'bash',
      [
        '-euc',
        `
source tests/integration/local-runtime/runner-harness.sh
compose=(printf '%s\\n')
openpc_builder=openpc-r1-local-v1
openpc_build_one_image fact-service
`,
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, OPENPC_SERVER_CAPACITY: '1', CARGO_BUILD_JOBS: jobs },
      },
    );
    assert.equal(result.status, 64, result.stderr);
    assert.equal(result.stdout, '');
  }
});

test('cache recovery runs only for capacity pressure and preserves the admission failure if cleanup is insufficient', () => {
  // External Docker is simulated here; real ownership/configuration verification is
  // exercised by the Compose runner. This regression targets recovery control flow.
  const shell = `set -euo pipefail
repository_root="$PWD"
export OPENPC_SERVER_CAPACITY=0
source scripts/maintenance/local-runtime-images.sh
openpc_require_heavy_lock() { :; }
openpc_verify_owned_builder() { :; }
checks=0
openpc_cache_within_bound() {
  checks=$((checks+1))
  if [ "$checks" = 1 ]; then return "$FIRST_STATUS"; fi
  return "$SECOND_STATUS"
}
docker() {
  if [ "$1" = exec ]; then cat deploy/compose/local/buildkitd.toml; return; fi
  if [ "$1 $2" = 'buildx prune' ]; then
    printf '%s\\n' "$*"
    case "$*" in *until=6h*) return "$PRUNE_STATUS";; esac
  fi
}
openpc_prepare_builder
printf 'checks=%s\\n' "$checks"
`;
  for (const [first, second, prune, expected, recovery] of [
    [0, 0, 0, 0, false],
    [96, 0, 0, 96, false],
    [75, 0, 0, 0, true],
    [75, 75, 0, 75, true],
    [75, 0, 78, 78, true],
  ]) {
    const result = spawnSync('bash', ['-c', shell], {
      encoding: 'utf8',
      env: {
        ...process.env,
        FIRST_STATUS: String(first),
        SECOND_STATUS: String(second),
        PRUNE_STATUS: String(prune),
      },
    });
    assert.equal(result.status, expected, result.stderr);
    assert.equal(
      result.stdout.includes('--filter until=6h --filter type!=exec.cachemount'),
      recovery,
    );
    if (expected === 0) assert.match(result.stdout, new RegExp(`checks=${recovery ? 2 : 1}`));
  }
});

test('builder cache diagnostics measure the admitted bound and fail closed on unavailable records', () => {
  const bound = 64 * 1024 ** 3;
  const shell = `set -euo pipefail
source scripts/maintenance/local-runtime-images.sh
docker() {
  [[ "$1 $2" == 'buildx du' ]] || exit 97
  printf '%s' "$CACHE_RECORDS"
  return "$CACHE_STATUS"
}
openpc_cache_within_bound
`;
  for (const [records, sourceStatus, expectedStatus, bytes] of [
    ['', 0, 0, 0], // Successful empty cache on a new builder.
    [JSON.stringify({ Size: `${bound - 1}B` }), 0, 0, bound - 1],
    [JSON.stringify({ Size: '64GiB' }), 0, 0, bound],
    [JSON.stringify({ Size: `${bound + 1}B` }), 0, 75, bound + 1],
    [
      `${JSON.stringify({ Size: '63GiB' })}\n${JSON.stringify({ Size: '2GiB' })}`,
      0,
      75,
      bound + 1024 ** 3,
    ],
    [JSON.stringify({ Size: '0.1kB' }), 0, 0, 100],
    ['{broken', 0, 96, null],
    ['{}', 0, 96, null],
    ['null', 0, 96, null],
    [JSON.stringify({ Size: 'unknown' }), 0, 96, null],
    [JSON.stringify({ Size: '-1B' }), 0, 96, null],
    [JSON.stringify({ Size: 1 }), 0, 96, null],
    ['', 42, 96, null],
    [JSON.stringify({ Size: '1B' }), 42, 96, null],
  ]) {
    const result = spawnSync('bash', ['-c', shell], {
      encoding: 'utf8',
      env: { ...process.env, CACHE_RECORDS: String(records), CACHE_STATUS: String(sourceStatus) },
    });
    assert.equal(result.status, expectedStatus, result.stderr);
    if (bytes === null) {
      assert.match(
        result.stderr,
        /OPENPC_CACHE_USAGE\|status=unavailable\|reason=(invalid-record|command-failed)/u,
      );
      assert.doesNotMatch(result.stdout, /used_bytes=|within-bound/u);
    } else {
      assert.equal(
        result.stdout.trim(),
        `OPENPC_CACHE_USAGE|status=${expectedStatus === 75 ? 'over-bound' : 'within-bound'}|measurement=reported-record-sum|used_bytes=${bytes}|bound_bytes=${bound}|shortfall_bytes=${Math.max(0, Number(bytes) - bound)}|records=${records === '' ? 0 : String(records).split('\n').length}`,
      );
    }
  }
});

test('Explorer profile governance dispatches the public proposal before mutation', () => {
  for (const [action, path] of [
    ['ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1', '/api/v1/privacy-explorer-profiles'],
    [
      'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1',
      '/api/v1/privacy-explorer-profiles/profile/revoke',
    ],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `
      set -eu
      source tests/integration/local-runtime/runtime-configuration.sh
      openpc_require_inputs() { :; }
      configuration_post() { printf '%s|%s' "$3" "$7"; exit 0; }
      approved_configuration_post /tmp/unused.json "$1" "$2" profile-key '' POST explorer-profile
    `,
        'proposal-check',
        JSON.stringify({ actionIntentId: action }),
        path,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${path}/proposals|200`);
  }
});

test('retained approval provenance allows only exact Explorer and retirement proposal additions', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import pathlib, runpy
owner=runpy.run_path('tests/integration/local-runtime/runner-provenance.py')
check=owner['validate_shared_approval_refresh']
current=pathlib.Path('tests/integration/local-runtime/runtime-configuration.sh').read_text().strip()
# Later runtime-source dispatch cases require a fresh lifecycle; they are not
# covered by the historical Explorer/store-retirement refresh exception.
current=current.replace('|ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1|ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1','',1)
addition='|ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1|ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1'
assert current.count(addition)==1
prior=current.replace(addition,'',1)
check(prior,current); check(current,current)
retirement='|ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1'
assert current.count(retirement)==1
check(current.replace(retirement,'',1),current)
check(prior.replace(retirement,'',1),current)
for changed in [current.replace('configuration_post','changed_mutation',1), current.replace('public_candidate_readback=1','public_candidate_readback=0',1), current.replace(addition,addition+'|ACT-MODULES_CREATE_RESOURCE-V1',1)]:
 try: check(prior,changed)
 except ValueError: pass
 else: raise AssertionError('unrelated approval semantics admitted')
`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('visibility evidence admits an absent first journal without hiding invalid storage', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'visibility-journal-'));
  const snapshot = () =>
    spawnSync(
      'bash',
      [
        '-c',
        `set -eu
        source tests/integration/local-runtime/visibility-journey.sh
        fake_compose() { sh -ec "$6" "$7" "$TEST_JOURNAL_ROOT" "$9"; }
        compose=(fake_compose)
        target_id=target
        visibility_decision_snapshot`,
      ],
      { encoding: 'utf8', env: { ...process.env, TEST_JOURNAL_ROOT: root } },
    );
  try {
    assert.deepEqual(JSON.parse(snapshot().stdout), { records: {} });
    await mkdir(join(root, 'target'));
    assert.deepEqual(JSON.parse(snapshot().stdout), { records: {} });
    const journal = join(root, 'target', 'decisions.json');
    const prior = { records: { old: { status: { Released: { response_digest: 'kept' } } } } };
    await writeFile(journal, JSON.stringify(prior));
    assert.deepEqual(JSON.parse(snapshot().stdout), prior);
    const sealed = join(root, 'target', 'sealed-decisions.json');
    await writeFile(sealed, 'invalid sealed journal must never fall back to legacy');
    assert.notEqual(snapshot().status, 0);
    await rm(sealed);
    await writeFile(journal, 'invalid existing journal');
    assert.throws(() => JSON.parse(snapshot().stdout));
    await rm(journal);
    await symlink(join(root, 'missing'), journal);
    assert.notEqual(snapshot().status, 0);
    await rm(journal);
    await mkdir(journal);
    assert.notEqual(snapshot().status, 0);
    await rm(join(root, 'target'), { recursive: true });
    await writeFile(join(root, 'target'), 'not a directory');
    assert.notEqual(snapshot().status, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Explorer operator assignment is limited to the five registered journey actions', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/privacy-explorer-journey.mjs',
      'assignment',
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  const grant = JSON.parse(result.stdout);
  assert.deepEqual(grant.actionIntentIds, [
    'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1',
    'ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1',
    'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1',
    'ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1',
    'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1',
  ]);
  assert.deepEqual(grant.capabilityIds, []);
  assert.deepEqual(grant.privacyDomainIds, ['018f0000-0000-7000-8000-000000000201']);
  assert.equal(grant.principalId, '018f0000-0000-7000-8000-000000000111');
  assert.equal(grant.authorityEnvelopeId, '018f0000-0000-7000-8000-000000000139');
  assert.equal(grant.roleId, 'urn:openpc:role:018f0000-0000-7000-8000-000000000805');
  assert.equal(grant.makerCheckerRequired, true);
  assert.equal(grant.onwardDelegationDepth, 0);
});

test('Explorer session handoff observes browser credential counter advances before shell assertions', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'explorer-counter-'));
  try {
    for (const retained of [false, true, 'expired', 'failed']) {
      if (retained) await writeFile(join(root, 'explorer-storage.json'), '{}');
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
          source tests/integration/local-runtime/privacy-explorer-journey.sh
          evidence_root=$1 data_root=$1
          participant_id=participant operator_credential_id=credential
          operator_private_key_path=unused control_password=unused control_container=unused
          next_operator_sign_count=4 current_counter=4
          node() {
            if [[ $* == *'privacy-explorer-journey.mjs session'* ]]; then
              [[ $session_case != expired ]] || return 75
              [[ $session_case != failed ]] || return 96
            fi
            current_counter=40
          }
          docker() {
            read -r query
            [[ $query == select*authenticator_sign_count* ]] || return 96
            if [[ $query == *'authenticator_sign_count+1'* ]]; then
              printf '%s\\n' "$((current_counter+1))"
            else printf '%s\\n' "$current_counter"; fi
          }
          openpc_prepare_explorer_session
          test "$next_operator_sign_count" = 41
          printf 'counter-current\\n'`,
          'counter-test',
          root,
        ],
        { encoding: 'utf8', env: { ...process.env, session_case: String(retained) } },
      );
      if (retained === 'failed') {
        assert.equal(result.status, 96, result.stderr);
        assert.equal(result.stdout, '');
        continue;
      }
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'counter-current\n');
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('retained refresh builds only selected services and preserves the shared closure', () => {
  for (const shared of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
        source tests/integration/local-runtime/runner-harness.sh
        refresh_from=previous run_root=owned project=owned evidence_root=owned
        openpc_builder=owned openpc_build_services=(control-worker control-api admin-web)
        compose=(compose_probe)
        openpc_select_refresh_images() {
          if [[ $shared == true ]]; then refresh_services=(control-worker control-api admin-web);
          else refresh_services=(admin-web); fi
        }
        openpc_require_inputs() { :; }
        openpc_wait_existing_service() { :; }
        openpc_provenance() { :; }
        openpc_storage_preflight() { :; }
        openpc_prepare_builder() { :; }
        openpc_record_prior_images() { :; }
        openpc_include_unverified_images() { :; }
        openpc_runtime_input_admission() { :; } # Covered by real retained-root scenarios.
        openpc_validate_build_inputs() { :; }
        openpc_admin_web_preflight() { :; }
        compose_probe() { if [[ $1 == build ]]; then printf '%s\\n' "\${@: -1}"; fi; }
        openpc_capture_built_images() { exit 77; }
        shared=$1
        openpc_refresh_visibility`,
        'refresh-test',
        String(shared),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 77, result.stderr);
    assert.equal(
      result.stdout,
      shared ? 'control-worker\ncontrol-api\nadmin-web\n' : 'admin-web\n',
    );
  }
});

test('relationship fixture refresh admits canonical ordering without changing admission meaning', () => {
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import pathlib, runpy
check=runpy.run_path('tests/integration/local-runtime/runner-provenance.py')['validate_relationship_fixture_refresh']
current=pathlib.Path('services/fleet-controller/src/local_fixture/indexer.rs').read_text()
addition='''        profile
            .method_data_classes
            .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));\n'''
assert current.count(addition)==1
prior=current.replace(addition,'',1).split('\\n#[cfg(test)]',1)[0]
check(prior,current)
check(current,current)
for changed in [current.replace('maximum_staleness_ms: 60_000','maximum_staleness_ms: 600_000'), current.replace('namespace: "local.relationship"','namespace: "other"'), current.replace('.sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)))','.reverse()',1)]:
 try: check(prior,changed)
 except ValueError: pass
 else: raise AssertionError('unrelated fixture meaning admitted')
`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('native Fact browser dispatch requires completed custody and withdrawal and retains its failure', async () => {
  const first = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const prior = first.indexOf(
    'source tests/integration/local-runtime/evidence-fleet-quarantine-journey.sh',
  );
  const next = first.indexOf('openpc_phase_begin fact-retirement-browser');
  assert.ok(
    prior > first.indexOf('source tests/integration/local-runtime/evidence-rpc-configuration.sh'),
  );
  assert.ok(next > prior);
  const dispatch = first.slice(prior, first.indexOf('openpc_phase_begin candidate-custody', next));
  for (const failure of ['none', 'withdrawal', 'work-item', 'browser']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      root=owned failure=$1
      source() { printf 'withdrawal\\n'; [[ $failure != withdrawal ]]; }
      openpc_native_fleet_work_item_browser() { printf 'work-item\\n'; [[ $failure != work-item ]]; }
      openpc_compose_json() { printf '[]'; }
      openpc_phase_begin() { :; }
      openpc_phase_end() { :; }
      node() { printf 'browser\\n'; [[ $failure != browser ]]; }
      ${dispatch}
      printf 'complete\\n'
    `,
        'retirement-dispatch',
        failure,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 'none' ? 0 : 1, result.stderr);
    assert.deepEqual(
      result.stdout.trim().split('\n'),
      failure === 'none'
        ? ['withdrawal', 'work-item', 'browser', 'complete']
        : failure === 'withdrawal'
          ? ['withdrawal']
          : failure === 'work-item'
            ? ['withdrawal', 'work-item']
            : ['withdrawal', 'work-item', 'browser'],
    );
  }
});

test('module collection observations fail closed at each governed lifecycle boundary', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/module-admission-journey.sh',
    'utf8',
  );
  const definition = source.slice(
    source.indexOf('module_collection() {'),
    source.indexOf('module_registration_body() {'),
  );
  const phases = [...source.matchAll(/^module_collection ([a-z-]+)$/gmu)].map((match) => match[1]);
  assert.deepEqual(phases, [
    'empty',
    'registered',
    'restart-registered',
    'installed',
    'active',
    'restart-active',
  ]);
  for (const full of ['0', '1']) {
    for (const phase of phases) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
module_full_acceptance=$1
expected_phase=$2
secret_root=/owned/secrets participant_id=participant privacy_domain_id=privacy evidence_root=/owned/evidence module_catalog=/owned/catalog
configuration_operator_session=operator-secret configuration_checker_session=checker-secret
local_identity_session() { [[ $1 == viewer ]] && printf 'denied-secret'; }
node() {
  [[ $OPENPC_MODULE_LIST_OPERATOR == operator-secret && $OPENPC_MODULE_LIST_CHECKER == checker-secret && $OPENPC_MODULE_LIST_DENIED == denied-secret ]]
  [[ $* != *-secret* ]]
  [[ $* == *collection-$expected_phase* ]] && return 21
  return 22
}
${definition}
module_collection "$2"
printf 'dependent-work'
`,
          'collection-boundary',
          full,
          phase,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, full === '1' ? 21 : 0, result.stderr);
      assert.equal(result.stdout, full === '1' ? '' : 'dependent-work');
    }
  }
});

test('Fact admission callers pass no session or CSRF credential as a process argument', async () => {
  for (const name of ['evidence-rpc-journey.mjs', 'evidence-fleet-quarantine.mjs']) {
    const caller = await readFile(`tests/integration/local-runtime/${name}`, 'utf8');
    const invocation = caller.slice(caller.indexOf("'evidence-rpc-fact.mjs'"));
    assert.doesNotMatch(caller, /browser\.actors\.(maker|checker)\.sessionToken/u);
    assert.doesNotMatch(invocation, /csrfToken/u);
  }
  const source = await readFile('tests/integration/local-runtime/evidence-rpc-fact.mjs', 'utf8');
  assert.ok(source.includes('assert.equal(process.argv.length, 5'));
  assert.ok(source.includes("load(join(evidence, 'deployment-intent-actors.json'))"));
});

test('candidate custody follows accepted Fact retirement and blocks its completion marker on failure', async () => {
  const source = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = source.indexOf('openpc_phase_begin fact-retirement-browser');
  assert.ok(start > 0);
  for (const failed of [
    'none',
    'fact',
    'candidate',
    'delivery',
    'retirement',
    'search',
    'fact-preflight',
    'recovery',
    'fact-recovery',
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
root=/owned
openpc_compose_json() { printf '[]'; }
openpc_candidate_database_recovery() { [[ $OPENPC_TEST_FAILED != recovery ]] || return 19; }
openpc_fact_database_recovery() {
  if [[ $1 == --preflight ]]; then [[ $OPENPC_TEST_FAILED != fact-preflight ]] || return 19;
  else [[ $1 == --fresh && $OPENPC_TEST_FAILED != fact-recovery ]] || return 19; fi
}
openpc_phase_begin() { :; }
openpc_phase_end() { printf '%s\\n' "$1"; }
node() {
  if [[ $* == *evidence-projection-deletion-browser.mjs* && $OPENPC_TEST_FAILED == search ]]; then return 19; fi
  if [[ $* == *evidence-fact-store-retirement-browser.mjs* && $OPENPC_TEST_FAILED == fact ]]; then return 19; fi
  if [[ $* == *evidence-candidate-custody.mjs* && $OPENPC_TEST_FAILED == candidate ]]; then return 19; fi
  if [[ $* == *candidate-delivery-reconciliation.mjs* && $OPENPC_TEST_FAILED == delivery ]]; then return 19; fi
  if [[ $* == *evidence-candidate-retirement-browser.mjs* && $OPENPC_TEST_FAILED == retirement ]]; then return 19; fi
}
${source.slice(start)}
`,
        'candidate-dispatch',
      ],
      { encoding: 'utf8', env: { ...process.env, OPENPC_TEST_FAILED: failed } },
    );
    assert.equal(result.status, failed === 'none' ? 0 : 19, result.stderr);
    assert.equal(
      result.stdout.includes('candidate-custody'),
      [
        'none',
        'delivery',
        'retirement',
        'search',
        'fact-preflight',
        'recovery',
        'fact-recovery',
      ].includes(failed),
    );
    assert.equal(
      result.stdout.includes('candidate-delivery'),
      ['none', 'retirement', 'search', 'fact-preflight', 'recovery', 'fact-recovery'].includes(
        failed,
      ),
    );
    assert.equal(
      result.stdout.includes('candidate-retirement-browser'),
      ['none', 'search', 'fact-preflight', 'recovery', 'fact-recovery'].includes(failed),
    );
    assert.equal(
      result.stdout.includes('retention-search-browser'),
      ['none', 'fact-preflight', 'recovery', 'fact-recovery'].includes(failed),
    );
    assert.equal(
      result.stdout.includes('fact-database-recovery-preflight'),
      ['none', 'recovery', 'fact-recovery'].includes(failed),
    );
    assert.equal(
      result.stdout.includes('candidate-database-recovery'),
      ['none', 'fact-recovery'].includes(failed),
    );
    assert.equal(result.stdout.split('\n').includes('fact-database-recovery'), failed === 'none');
    assert.equal(result.stdout.includes('fact-retirement-browser'), failed !== 'fact');
  }
});

test('candidate custody CLI rejects unsafe selection before governance and preserves originals', async (t) => {
  assert.ok(process.env.OPENPC_TEST_TMP_ROOT, 'owned temporary root required');
  const temporary = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'candidate-cli-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const root = join(await realpath(temporary), 'owned');
  const outside = join(await realpath(temporary), 'outside');
  const alias = join(await realpath(temporary), 'alias');
  // Deliberately invalid preservation sentinels, not seeded custody/approval state.
  // Any attempt to advance past admission must fail rather than invent a success.
  for (const directory of [root, outside]) {
    for (const file of [
      'data/candidate-custody/case.json',
      'data/candidate-custody/archive.key',
      'data/candidate-custody/native-reader.json',
      'data/candidate-custody/candidate_archive_reader',
      'evidence/runtime-bootstrap/store-retirement/original-fact.json',
      'evidence/runtime-bootstrap/store-retirement/deployment-intent-actors.json',
      'evidence/runtime-bootstrap/rpc-acquisition/candidate.json',
    ]) {
      await mkdir(dirname(join(directory, file)), { recursive: true, mode: 0o700 });
      await writeFile(join(directory, file), `retain original ${file}\n`, {
        flag: 'wx',
        mode: 0o600,
      });
    }
  }
  await symlink(outside, alias);
  const snapshot = async (directory) => {
    const entries = [];
    const visit = async (path) => {
      const info = await lstat(path, { bigint: true });
      entries.push({
        path: relative(temporary, path),
        inode: info.ino,
        mode: info.mode,
        modified: info.mtimeNs,
        content: info.isFile()
          ? await readFile(path)
          : info.isSymbolicLink()
            ? await readlink(path)
            : null,
      });
      if (info.isDirectory())
        for (const child of (await readdir(path)).sort()) await visit(join(path, child));
    };
    await visit(directory);
    return entries;
  };
  const original = await snapshot(temporary);
  // Run the real CLI and its real imports. Every external-effect boundary throws;
  // even the admission subprocess is refused. Only the installed tsx transpiler
  // may start its exact esbuild service. No database or business owner is mocked.
  const tripwire = `
import childProcess from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const require = createRequire(pathToFileURL(join(process.cwd(), 'package.json')));
const tsxRequire = createRequire(require.resolve('tsx/package.json'));
const esbuildRequire = createRequire(tsxRequire.resolve('esbuild/package.json'));
const esbuild = esbuildRequire.resolve('@esbuild/' + process.platform + '-' + process.arch + '/bin/esbuild');
const service = '--service=' + esbuildRequire('./package.json').version;
const admission = ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--memory-gib', '3', '--reuse', '--', 'true'];
function refuse(kind, file, args) {
  // Do not print command arguments, URLs or credentials from an unexpected call.
  process.stderr.write('CANDIDATE_CLI_EFFECT|' + JSON.stringify({
    kind,
    admission: kind === 'execFile' && file === 'bash' && JSON.stringify(args) === JSON.stringify(admission),
  }) + '\\n');
  throw Object.assign(new Error('Candidate CLI effect refused by test'), { code: 'CANDIDATE_CLI_EFFECT' });
}
for (const kind of ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']) {
  const original = childProcess[kind];
  childProcess[kind] = function(file, args, ...rest) {
    const loaderArgs = kind === 'spawn' ? [service, '--ping'] : [service];
    if ((kind === 'spawn' || kind === 'execFileSync') && file === esbuild && JSON.stringify(args) === JSON.stringify(loaderArgs))
      return original.call(this, file, args, ...rest);
    return refuse(kind, file, args);
  };
}
net.Socket.prototype.connect = () => refuse('socket');
net.Server.prototype.listen = () => refuse('listen');
tls.connect = () => refuse('tls');
globalThis.fetch = () => refuse('fetch');
syncBuiltinESMExports();
`;
  const run = (args, env = {}) =>
    spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '--import',
        `data:text/javascript,${encodeURIComponent(tripwire)}`,
        'tests/integration/local-runtime/evidence-candidate-custody.mjs',
        ...args,
      ],
      {
        encoding: 'utf8',
        timeout: 30000,
        maxBuffer: 1024 * 1024,
        env: {
          ...process.env,
          NODE_OPTIONS: undefined,
          NODE_TEST_CONTEXT: undefined,
          ESBUILD_BINARY_PATH: undefined,
          OPENPC_CANDIDATE_CONTROL_RESTORE: undefined,
          OPENPC_RPC_SOURCE_GENERATION: undefined,
          ...env,
        },
      },
    );
  const compose = JSON.stringify(['docker', 'compose']);
  const check = async (args, env, admission, message) => {
    const result = run(args, env);
    // Keep the preservation oracle ahead of error matching, including crashes.
    assert.deepEqual(await snapshot(temporary), original, 'original custody inputs changed');
    assert.ifError(result.error);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.equal(result.stdout, '', 'no success/output marker before input admission');
    const effects = result.stderr
      .split('\n')
      .filter((line) => line.startsWith('CANDIDATE_CLI_EFFECT|'))
      .map((line) => JSON.parse(line.slice('CANDIDATE_CLI_EFFECT|'.length)));
    assert.deepEqual(effects, admission ? [{ kind: 'execFile', admission: true }] : []);
    assert.match(result.stderr, message);
  };
  await t.test('malformed modes and extra arguments', async () => {
    for (const tail of [[''], ['unknown'], ['acquisition', 'extra'], ['original-fact', 'extra']])
      await check([root, compose, ...tail], {}, false, /ERR_ASSERTION/u);
  });
  await t.test('relative, noncanonical and symlink roots', async () => {
    for (const selected of [relative(process.cwd(), root), `${root}/../owned`, alias])
      await check(
        [selected, compose, 'acquisition'],
        {},
        false,
        /Existing owned runtime root required/u,
      );
  });
  await t.test('restore selection is rejected even when empty or zero', async () => {
    for (const mode of ['original-fact', 'acquisition'])
      for (const restore of ['', '0', '1'])
        await check(
          [root, compose, mode],
          { OPENPC_CANDIDATE_CONTROL_RESTORE: restore },
          false,
          /BLOCKED: run isolated recovery separately/u,
        );
  });
  await t.test('default and explicit source modes require unchanged real admission', async () => {
    // The default ignores the acquisition generation selector. This proves CLI
    // selection only: actual source reads/native custody still require admission.
    for (const mode of [[], ['original-fact']])
      await check(
        [root, compose, ...mode],
        { OPENPC_RPC_SOURCE_GENERATION: 'invalid' },
        true,
        /Candidate CLI effect refused by test/u,
      );
    for (const generation of [undefined, '3'])
      await check(
        [root, compose, 'acquisition'],
        { OPENPC_RPC_SOURCE_GENERATION: generation },
        true,
        /Candidate CLI effect refused by test/u,
      );
    for (const generation of ['invalid', '1', '2.5', '9007199254740992'])
      await check(
        [root, compose, 'acquisition'],
        { OPENPC_RPC_SOURCE_GENERATION: generation },
        false,
        /Existing source generation required/u,
      );
  });
});

test('first-policy runtime reserves retirement installation memory before allocating services', async () => {
  const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const begin = runner.indexOf(
    'if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 && ${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0} != 1 ]]; then',
  );
  const end = runner.indexOf('\nfi', begin) + 3;
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('openpc_storage_preflight\n'));
  const dispatch = runner.slice(begin, end);
  for (const available of [2, 3]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      repository_root=owned
      OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
      bash() { [[ "$*" == *'--memory-gib 3'* ]] || return 96; [[ ${available} -ge 3 ]] || return 75; }
      ${dispatch}
      printf 'ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, available === 3 ? 0 : 75, result.stderr);
    assert.equal(result.stdout.includes('ALLOCATION_ALLOWED'), available === 3);
  }
  const browser = await readFile(
    'tests/integration/local-runtime/evidence-fact-store-retirement-browser.mjs',
    'utf8',
  );
  assert.match(browser, /'runtime-target',\s*'--memory-gib',\s*'3',\s*'--reuse'/u);
});

test('packaged notification selector rejects conflicts and retained arguments before allocation', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const early = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} != 0 ]]; then',
    '# Reject retained/conflicting C1 invocations',
  );
  for (const [selection, metadata, extra, args, status] of [
    ['0', '1', {}, [], 0],
    ['1', '1', {}, [], 0],
    ['2', '1', {}, [], 96],
    ['1', '0', {}, [], 96],
    ['1', '1', {}, ['--suite'], 96],
    ['1', '1', {}, ['--reuse-images', '--resume-root', '/original'], 96],
    ['1', '1', {}, ['--recover-network', '--resume-root', '/original'], 96],
    ['1', '1', {}, ['--refresh-from', 'revision', '--resume-root', '/original'], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_BUILD_ONLY: '1' }, [], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY: '1' }, [], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY: '1' }, [], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_FUTURE_JOURNEY: '1' }, [], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS: '1' }, [], 96],
    ['1', '1', { OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER: '1' }, [], 96],
    ['1', '1', { OPENPC_NOTIFICATION_ENDPOINT_REF: 'retained' }, [], 96],
    ['1', '1', { OPENPC_NOTIFICATION_ENDPOINT_DESTINATION_REF: '' }, [], 96],
    ['1', '1', { OPENPC_BROWSER_SCENARIOS: 'credentials' }, [], 96],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
${early}
printf 'ALLOCATE\\n'
`,
      args,
      {
        OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER: selection,
        OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY: metadata,
        ...extra,
      },
    );
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout, status ? '' : 'ALLOCATE\n');
  }
});

test('packaged notification fresh parents are private without changing database child permissions', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const selected = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} == 1 ]]; then\n  chmod',
    '  exec 8<',
  );
  const directory = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT, 'notification-root-modes-'),
  );
  try {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail
run_root=$1 data_root=$1/data evidence_root=$1/evidence owner_sentinel=$1/.openpc-local-runtime-owner
mkdir -m 0777 "$data_root" "$data_root/control-pg"
mkdir -m 0755 "$evidence_root"
printf 'fixture\\n' > "$owner_sentinel"
${selected}
[[ $(stat -c %a "$run_root") == 700 && $(stat -c %a "$data_root") == 700 &&
   $(stat -c %a "$evidence_root") == 700 && $(stat -c %a "$owner_sentinel") == 600 &&
   $(stat -c %a "$data_root/control-pg") == 777 ]]
`,
      [directory],
      { OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER: '1' },
    );
    assert.equal(result.status, 0, result.stderr);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('packaged notification dispatch keeps metadata mode and arms UNKNOWN before child launch', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const body = c1RunnerSection(
    source,
    'if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY:-0} == 1 ]]; then\n',
    '\noidc_attempt oidc-nonce-denial',
  );
  assert.ok(body.indexOf('openpc_notification_packaged_pending=1') < body.indexOf('mkdir -m 0700'));
  assert.ok(body.indexOf('openpc_notification_packaged_pending=1') < body.indexOf('exec node'));
  assert.match(body, /set -o noclobber/u);
  assert.doesNotMatch(body, /installationUrl|runtimeUrl|postgresql:|password/u);
  const directory = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'notification-dispatch-'));
  try {
    for (const packaged of ['0', '1']) {
      const selected = join(directory, packaged);
      await mkdir(selected);
      const result = c1RunnerBoundaryResult(
        `set -euo pipefail
secret_root=/owned/secrets evidence_root=$1 run_root=/owned
participant_id=participant privacy_domain_id=privacy
openpc_notification_packaged_pending=0
openpc_compose_json() { printf '[]'; }
node() {
  if [[ $* == *business-signing-bootstrap.mjs* ]]; then return 0; fi
  [[ $* == *notification-browser.mjs* ]] || return 97
  printf 'METADATA_ORIGINAL\\n'
}
# The actual process invocation above uses exec node, so a missing tsx import in
# this deliberately empty cwd fails before any runtime. It cannot fabricate PASS.
cd "$1"
trap 'printf "PENDING|%s|CHILD|%s\\n" "$openpc_notification_packaged_pending" "\${openpc_notification_packaged_pid:-absent}"' EXIT
${body}
`,
        [selected],
        {
          OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY: '1',
          OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER: packaged,
        },
      );
      if (packaged === '0') {
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /METADATA_ORIGINAL\nPENDING\|0\|CHILD\|absent/u);
      } else {
        assert.notEqual(result.status, 0);
        assert.match(result.stdout, /PENDING\|1\|CHILD\|[1-9][0-9]*/u);
        const log = join(selected, 'notification-browser/packaged-runtime.log');
        assert.equal((await stat(log)).mode & 0o777, 0o600);
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('packaged notification UNKNOWN fence precedes every generic cleanup and preserves primary exit', () => {
  for (const mode of ['missing', 'failed', 'pending', 'bad-state']) {
    for (const original of [0, 73]) {
      const result = c1RunnerBoundaryResult(
        `set -uo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_notification_packaged_pending=1
openpc_notification_packaged_exit=''
openpc_notification_packaged_pid=''
if [[ $1 == missing ]]; then unset -f openpc_notification_packaged_on_exit; fi
if [[ $1 == bad-state ]]; then openpc_notification_packaged_pending=invalid; fi
if [[ $1 == failed ]]; then openpc_notification_packaged_exit=47; fi
validate_run_root() { printf 'UNEXPECTED_ROOT_INSPECTION\\n'; return 97; }
docker() { printf 'UNEXPECTED_DOCKER\\n'; return 97; }
remove_inventory_containers() { printf 'UNEXPECTED_INVENTORY\\n'; return 97; }
openpc_network_cleanup() { printf 'UNEXPECTED_NETWORK\\n'; return 97; }
openpc_stop_owned_builder() { printf 'UNEXPECTED_BUILDER\\n'; return 97; }
parent_status() { return "$2"; }
parent_status "$@"
cleanup
`,
        [mode, String(original)],
      );
      assert.equal(result.status, original || (mode === 'failed' ? 47 : 99), result.stderr);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /UNKNOWN_RETAIN_ALL/u);
    }
  }
});

test('packaged notification zero child exit with missing or malformed handoff permits no stop', () => {
  for (const response of ['', 'true', 'DRAINED', 'DRAINED_RETAINED extra']) {
    const result = c1RunnerBoundaryResult(
      `set -uo pipefail
source tests/integration/local-runtime/runner-harness.sh
project=owned run_root=/owned data_root=/owned/data repository_root=$PWD
compose=(docker compose) inventory_container_ids=()
openpc_notification_packaged_pending=1 openpc_notification_packaged_exit=0 openpc_notification_packaged_pid=123
validate_run_root() { return 0; }
openpc_compose_json() { printf '[]'; }
# Boundary-only malformed observation. No success/provider/SQL owner is mocked.
node() { printf '%s' "$RESPONSE"; }
openpc_verify_running_images() { printf 'UNEXPECTED_IMAGE_CHECK\\n'; return 97; }
docker() { printf 'UNEXPECTED_DOCKER\\n'; return 97; }
true
cleanup
`,
      [],
      { RESPONSE: response },
    );
    assert.equal(result.status, 99, result.stderr);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /UNKNOWN_RETAIN_ALL/u);
  }
});

// Candidate continuation executes the real embedded runner with external command
// seams and real private backup files. This is orchestration coverage only; the
// PostgreSQL/source-authentication journey remains the canonical runtime owner's.
async function candidateRecoveryRunnerFixture() {
  const binding = await tsImport('../identity/candidate-recovery-binding.ts', import.meta.url);
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'candidate-runner-'),
  );
  const token = 'a'.repeat(64),
    project = `openpc-local-e2e-${token.slice(0, 12)}`;
  const directory = join(root, 'data/candidate-database-recovery');
  for (const path of [
    directory,
    join(root, 'secrets'),
    join(root, 'data/candidate-custody'),
    join(root, 'evidence/runtime-bootstrap/candidate-store-retirement'),
    join(root, 'data/runtime-bootstrap/candidate-store-retirement/private'),
  ])
    await mkdir(path, { recursive: true, mode: 0o700 });
  const marker = `openpc-local-runtime:${project}:${token}\n`;
  await writeFile(join(root, '.openpc-local-runtime-owner'), marker, { mode: 0o600 });
  const passwords = Object.fromEntries(
    [
      'openpc_candidate_index',
      'openpc_indexer_manager',
      'openpc_indexer_writer',
      'openpc_candidate_index_reader',
    ].map((role) => [role, join(root, 'secrets', role)]),
  );
  const input = binding.candidateDatabaseRecoveryCase.parse({
    version: 1,
    phase: 'RETIRED',
    project,
    backupDirectory: directory,
    source: {
      containerId: 'b'.repeat(64),
      dataDirectory: join(root, 'data/candidate-index-pg'),
      port: 55434,
      passwords,
    },
    target: {
      containerId: 'c'.repeat(64),
      dataDirectory: join(directory, 'postgres'),
      port: 15434,
      passwords,
    },
    control: {
      port: 55432,
      adminPasswordFile: join(root, 'secrets/control-admin'),
      workerPasswordFile: join(root, 'secrets/control-worker'),
    },
    participantId: '018f0000-0000-7000-8000-000000000001',
    privacyDomainId: '018f0000-0000-7000-8000-000000000002',
    custodyCaseFile: join(root, 'data/candidate-custody/case.json'),
    nativeBeforeFile: join(
      root,
      'evidence/runtime-bootstrap/candidate-store-retirement/native-before.json',
    ),
    terminalReadbackFile: join(
      root,
      'evidence/runtime-bootstrap/candidate-store-retirement/terminal-readback.json',
    ),
    nativeConfigurationFile: join(
      root,
      'data/runtime-bootstrap/candidate-store-retirement/private/target.json',
    ),
    nativeExecutable: join(directory, 'candidate_retirement_owner'),
  });
  for (const file of [
    ...Object.values(passwords),
    input.control.adminPasswordFile,
    input.control.workerPasswordFile,
  ])
    await writeFile(file, 'd'.repeat(64), { mode: 0o600 });
  for (const file of [
    input.nativeBeforeFile,
    input.nativeConfigurationFile,
    input.nativeExecutable,
  ])
    await writeFile(file, '{}', { mode: 0o600 });
  await writeFile(
    input.custodyCaseFile,
    JSON.stringify({
      scope: { participantId: input.participantId, privacyDomainId: input.privacyDomainId },
    }),
    { mode: 0o600 },
  );
  await writeFile(
    input.terminalReadbackFile,
    JSON.stringify({ public: { physicalState: 'APPLIED' } }),
    { mode: 0o600 },
  );
  const caseFile = join(directory, 'case.json');
  await binding.retainCandidateRecoveryCase(directory, input);
  const imageId = `sha256:${'e'.repeat(64)}`;
  const original = {
    version: 1,
    kind: 'OPENPC-CANDIDATE-RECOVERY-ORIGINAL-1',
    provenance: {
      project,
      ownerDigest: createHash('sha256').update(marker).digest('hex'),
      selectionDigest: createHash('sha256').update(JSON.stringify(input)).digest('hex'),
      phase: 'RETIRED',
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      database: 'openpc_candidate_index',
      databaseOwner: 'openpc_candidate_index_owner',
      source: {
        ...input.source,
        passwords: undefined,
        imageId,
        systemIdentifier: '123456789',
        databaseOid: '16384',
      },
      target: {
        ...input.target,
        passwords: undefined,
        imageId,
        systemIdentifier: '987654321',
        databaseOid: '16385',
      },
    },
    epoch: {
      exportedSnapshot: '00000003-000000AB-1',
      snapshot: '100:110:',
      backendPid: 123,
      observedAt: '2026-09-25T12:00:00.000Z',
      connectionLimit: -1,
    },
    comparison: {
      data: binding.candidateRecoveryData({
        'candidate.schema_migration': [],
        'candidate.store_retirement_attempt': [],
        'openpc_local.migration': [],
      }),
      security: binding.candidateRecoverySecurity(
        Object.fromEntries(
          [
            'relations',
            'policies',
            'functions',
            'triggers',
            'constraints',
            'schemas',
            'defaults',
            'roles',
            'databases',
            'settings',
          ].map((key) => [key, []]),
        ),
      ),
      control: binding.candidateRecoveryData({ store_retirement_outcome: [] }, 'control.'),
      vault: [{ name: `${'f'.repeat(64)}.segment`, bytes: 1, digest: 'a'.repeat(64) }],
    },
  };
  delete original.provenance.source.passwords;
  delete original.provenance.target.passwords;
  await binding.retainCandidateRecoveryOriginal(directory, original);
  await writeFile(
    join(directory, 'candidate-database-recovery.dump'),
    Buffer.from('PGDMP\x01original-runner-fixture'),
    { mode: 0o600 },
  );
  await binding.sealCandidateRecoveryBinding(directory, original.provenance);
  return { root, project, directory, input, caseFile, imageId, original, binding };
}

async function candidateRecoveryRunnerBody(fixture, options = {}) {
  const component = fixture.component ?? 'candidate';
  const source = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const section = c1RunnerSection(
    source,
    `openpc_${component}_database_recovery() {`,
    component === 'fact' ? '\n# End Fact database recovery' : '\n# The native producer identity',
  );
  const body = section.slice(section.indexOf("<<'JS'\n") + 7, section.lastIndexOf('\nJS\n}'));
  const code = body.replace(/^import [^\n]+;\n/gmu, '');
  assert.ok(!/^import /mu.test(code));
  const effects = [],
    output = [];
  const { input, root, project, imageId, binding } = fixture;
  const image =
    'docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7';
  const caps = {
    Memory: 1073741824,
    MemorySwap: 1073741824,
    Privileged: false,
    NetworkMode: 'bridge',
    NanoCpus: 750000000,
    PidsLimit: 256,
    SecurityOpt: ['no-new-privileges:true'],
  };
  const inspect = (id, data, port, labels, running = true) => ({
    Id: id,
    Image: imageId,
    Config: { Image: image, Labels: labels },
    State: { Running: running, OOMKilled: false },
    HostConfig: caps,
    Mounts: [{ Type: 'bind', Source: data, Destination: '/var/lib/postgresql', RW: true }],
    NetworkSettings: {
      Ports: { '5432/tcp': running ? [{ HostIp: '127.0.0.1', HostPort: String(port) }] : null },
    },
  });
  const sourceInfo = inspect(
    input.source.containerId,
    input.source.dataDirectory,
    input.source.port,
    {
      'com.docker.compose.project': project,
      'com.docker.compose.service': component === 'fact' ? 'fact-pg' : 'candidate-index-pg',
    },
  );
  const targetInfo = inspect(
    input.target.containerId,
    input.target.dataDirectory,
    15435,
    { 'io.openpc.test-owner': root, 'io.openpc.recovery-role': `${component}-target` },
    false,
  );
  if (options.changedCpu) targetInfo.HostConfig = { ...caps, NanoCpus: 1_000_000_000 };
  const controlInfo = inspect('d'.repeat(64), join(root, 'data/control-pg'), input.control.port, {
    'com.docker.compose.project': project,
    'com.docker.compose.service': 'control-pg',
  });
  const apiInfo = inspect('a'.repeat(64), '', 0, {
    'com.docker.compose.project': project,
    'com.docker.compose.service': 'control-api',
  });
  const siblingService = component === 'candidate' ? 'fact-pg' : 'candidate-index-pg';
  const siblingInfo = inspect(
    'f'.repeat(64),
    join(root, 'data', siblingService),
    component === 'candidate' ? 55433 : 55434,
    {
      'com.docker.compose.project': project,
      'com.docker.compose.service': siblingService,
    },
  );
  const freshContainers = [sourceInfo, controlInfo, apiInfo, siblingInfo];
  const execute = async (file, args) => {
    assert.equal(file, 'docker');
    effects.push(args);
    if (args[0] === 'ps')
      return {
        stdout: options.fresh
          ? freshContainers.map((value) => value.Id).join('\n')
          : controlInfo.Id,
      };
    if (args[0] === 'inspect')
      return {
        stdout: JSON.stringify(
          options.fresh && args.includes(sourceInfo.Id)
            ? freshContainers
            : args.length === 4
              ? [sourceInfo, targetInfo, controlInfo]
              : [targetInfo],
        ),
      };
    if (options.fresh && args[0] === 'cp') {
      await writeFile(args[2], 'unit-native-executable', { mode: 0o700, flag: 'wx' });
      return { stdout: '' };
    }
    if (options.fresh && args[0] === 'run') {
      targetInfo.State.Running = true;
      targetInfo.NetworkSettings.Ports['5432/tcp'] = [{ HostIp: '127.0.0.1', HostPort: '15435' }];
      return { stdout: targetInfo.Id };
    }
    if (options.fresh && args[0] === 'exec' && args.includes('/local/migrate.sh')) {
      assert.equal(args.at(-1), component === 'fact' ? 'fact-roles' : 'candidate_index-roles');
      return { stdout: '' };
    }
    if (args[0] === 'start') {
      targetInfo.State.Running = true;
      targetInfo.NetworkSettings.Ports['5432/tcp'] = [{ HostIp: '127.0.0.1', HostPort: '15435' }];
      return { stdout: targetInfo.Id };
    }
    if (args[0] === 'stop') {
      if (options.stopFails) throw new Error('stop failed');
      return { stdout: targetInfo.Id };
    }
    if (args[0] === 'exec' && args[1] === targetInfo.Id && args.join(' ').includes('pg_isready'))
      return { stdout: '' };
    throw new Error(`Unexpected runner command ${args[0]}`);
  };
  const child = (file, args, childOptions, callback) => {
    assert.equal(file, 'pnpm');
    if (childOptions.env.OPENPC_FACT_DATABASE_RECOVERY_PREFLIGHT_INPUT !== undefined) {
      const selected = binding.factRecoverySourceCase.parse(
        JSON.parse(childOptions.env.OPENPC_FACT_DATABASE_RECOVERY_PREFLIGHT_INPUT),
      );
      assert.equal(selected.source.containerId, input.source.containerId);
      assert.equal(selected.control.port, input.control.port);
      assert.equal(
        selected.nativeExecutable,
        join(root, 'data/runtime-bootstrap/store-retirement/private/fact_retirement_owner'),
      );
      assert.equal('target' in selected, false);
      assert.equal(childOptions.env.OPENPC_FACT_DATABASE_RESTORE, undefined);
      assert.equal(childOptions.env.OPENPC_FACT_DATABASE_RECOVERY_CASE_FILE, undefined);
      assert.equal(childOptions.env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE, undefined);
      assert.ok(
        args.includes(
          'preflights original Fact recovery dependencies without allocating or fencing',
        ),
      );
      effects.push(['native-preflight']);
      callback(
        options.nativePreflightFails ? new Error('native preflight failed') : null,
        options.nativePreflightFails || options.preflightMarkerMissing
          ? ''
          : 'OPENPC_FACT_DATABASE_PREFLIGHT|PASS|original-native-readback|archive-and-source-dependencies|no-target-or-fence',
        '',
      );
      return { stdin: { end() {} } };
    }
    assert.equal(
      childOptions.env[`OPENPC_${component.toUpperCase()}_DATABASE_RECOVERY_CONTINUE`],
      options.fresh ? undefined : '1',
    );
    assert.equal(
      childOptions.env[`OPENPC_${component.toUpperCase()}_DATABASE_RECOVERY_CASE_FILE`],
      fixture.caseFile,
    );
    effects.push([
      options.fresh ? 'invoke-fresh' : 'invoke-retained',
      childOptions.env[`OPENPC_${component.toUpperCase()}_DATABASE_RECOVERY_CASE_FILE`],
    ]);
    callback(options.childFails ? new Error('original child failed') : null, '', '');
    return { stdin: { end() {} } };
  };
  class ReadOnlyPool {
    constructor(configuration) {
      this.port = configuration.port;
      assert.equal(configuration.database, 'postgres');
      assert.match(configuration.options, /default_transaction_read_only=on/u);
      effects.push(['pool', this.port]);
    }
    async query(sql) {
      assert.match(sql, /^select /u);
      if (!sql.includes('pg_control_system')) return { rows: [] };
      const original =
        this.port === input.source.port
          ? fixture.original.provenance.source
          : fixture.original.provenance.target;
      return {
        rows: [
          {
            system_identifier:
              options.changedSource && this.port === input.source.port
                ? '111111111'
                : original.systemIdentifier,
            database_oid: original.databaseOid,
            owner: fixture.original.provenance.databaseOwner,
            datallowconn: options.sourceUnfenced === true,
            datconnlimit: 0,
          },
        ],
      };
    }
    async end() {
      effects.push(['pool-end', this.port]);
    }
  }
  const processFacade = {
    argv: [
      'node',
      '-',
      root,
      project,
      options.fresh ? imageId : '',
      ...(options.args ?? ['--retained']),
    ],
    execPath: process.execPath,
    env: options.environment ?? {},
    cwd: () => process.cwd(),
    getuid: () => process.getuid(),
    stdout: { write: (value) => output.push(value) },
    stderr: { write: (value) => output.push(value) },
  };
  const dependencies = {
    assert,
    execFile: child,
    chmod: (await import('node:fs/promises')).chmod,
    lstat,
    mkdir,
    readFile,
    realpath,
    writeFile,
    join,
    promisify: () => execute,
    Pool: ReadOnlyPool,
    process: processFacade,
    ...Object.fromEntries(
      ['RecoveryImage', 'RecoveryRunnerMode', 'RecoveryTargetPort'].map((suffix) => [
        component + suffix,
        binding[component + suffix],
      ]),
    ),
    [`retain${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryCase`]:
      binding[`retain${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryCase`],
    [`read${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryContinuation`]:
      binding[`read${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryContinuation`],
    [`finish${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryRunner`]:
      binding[`finish${component === 'fact' ? 'Fact' : 'Candidate'}RecoveryRunner`],
    ...(component === 'fact'
      ? {
          factRecoveryInputPaths: binding.factRecoveryInputPaths,
          factRecoverySourceCase: binding.factRecoverySourceCase,
          ...fixture.wire,
        }
      : {}),
  };
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  let error;
  try {
    await new AsyncFunction(...Object.keys(dependencies), code)(...Object.values(dependencies));
  } catch (caught) {
    error = caught;
  }
  return { effects, output: output.join(''), error };
}

for (const fault of [
  'none',
  'missing-binding',
  'changed-binding',
  'changed-archive',
  'changed-case',
  'unfenced-source',
  'changed-live-source',
  'changed-cpu',
  'fresh-conflict',
  'directory-conflict',
  'child-and-stop',
  'stop',
])
  test(`candidate recovery runner retained continuation: ${fault}`, async () => {
    const fixture = await candidateRecoveryRunnerFixture();
    try {
      const before = await readFile(fixture.caseFile);
      if (fault === 'missing-binding')
        await rm(join(fixture.directory, 'candidate-database-recovery.binding.json'));
      if (fault === 'changed-binding') {
        const seal = join(fixture.directory, 'candidate-database-recovery.binding.json');
        const value = JSON.parse(await readFile(seal, 'utf8'));
        value.archive.sha256 = 'f'.repeat(64);
        await writeFile(seal, JSON.stringify(value));
      }
      if (fault === 'changed-archive')
        await writeFile(
          join(fixture.directory, 'candidate-database-recovery.dump'),
          'PGDMPchanged',
        );
      if (fault === 'changed-case')
        await writeFile(
          fixture.caseFile,
          JSON.stringify({
            ...fixture.input,
            participantId: '018f0000-0000-7000-8000-000000000099',
          }),
        );
      const result = await candidateRecoveryRunnerBody(fixture, {
        sourceUnfenced: fault === 'unfenced-source',
        changedSource: fault === 'changed-live-source',
        changedCpu: fault === 'changed-cpu',
        childFails: fault === 'child-and-stop',
        stopFails: ['child-and-stop', 'stop'].includes(fault),
        args: ['fresh-conflict', 'directory-conflict'].includes(fault)
          ? ['--fresh']
          : ['--retained'],
        environment:
          fault === 'fresh-conflict' ? { OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE: '1' } : {},
      });
      assert.ok(result.effects.every((args) => !['run', 'cp', 'rm'].includes(args[0])));
      assert.ok(
        result.effects.every(
          (args) => !args.join(' ').includes('migrate.sh') && !args.join(' ').includes('pg_dump'),
        ),
      );
      if (fault === 'none') {
        assert.equal(result.error, undefined);
        assert.match(result.output, /PASS\|retained-original-binding/u);
        assert.ok(result.effects.some((args) => args[0] === 'pool' && args[1] === 15435));
        assert.ok(
          result.effects.findIndex(
            (args) => args[0] === 'pool-end' && args[1] === fixture.input.source.port,
          ) < result.effects.findIndex((args) => args[0] === 'start'),
        );
        assert.deepEqual(await readFile(fixture.caseFile), before);
      } else {
        assert.ok(result.error);
        assert.doesNotMatch(result.output, /\|PASS\|/u);
        if (fault === 'child-and-stop')
          assert.match(result.error.cause.message, /Candidate component recovery failed/u);
        if (!['child-and-stop', 'stop'].includes(fault))
          assert.ok(
            result.effects.every((args) => !['start', 'stop', 'invoke-retained'].includes(args[0])),
          );
      }
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

test('candidate recovery runner preflight selects binding and actual caller before allocation', async () => {
  const source = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const section = c1RunnerSection(
    source,
    'openpc_candidate_database_recovery() {',
    '\n# The native producer identity',
  );
  const dispatch = section.indexOf('  node --import tsx');
  for (const file of [
    'candidate-recovery-binding.test.ts',
    'postgres-candidate-database-recovery.test.ts',
  ])
    assert.ok(section.indexOf(file) > 0 && section.indexOf(file) < dispatch);
});

test('candidate recovery runner cleanup retains falsy primary failures and denies PASS on cleanup failure', async () => {
  const { finishCandidateRecoveryRunner, candidateRecoveryRunnerMode } = await tsImport(
    '../identity/candidate-recovery-binding.ts',
    import.meta.url,
  );
  assert.equal(candidateRecoveryRunnerMode([]), 'fresh');
  assert.equal(candidateRecoveryRunnerMode(['--fresh'], '0'), 'fresh');
  assert.equal(candidateRecoveryRunnerMode(['--retained']), 'retained');
  assert.equal(candidateRecoveryRunnerMode([], '1'), 'retained');
  for (const fault of [undefined, null, false, 0, '']) {
    const steps = [];
    await assert.rejects(
      finishCandidateRecoveryRunner(
        async () => {
          steps.push('run');
          throw fault;
        },
        async () => {
          steps.push('stop');
          throw new Error('cleanup');
        },
      ),
      (error) => error.message.startsWith('UNKNOWN') && error.cause === fault,
    );
    assert.deepEqual(steps, ['run', 'stop']);
  }
  for (const args of [['--fresh', '--retained'], ['unknown']])
    assert.throws(() => candidateRecoveryRunnerMode(args));
  assert.throws(() => candidateRecoveryRunnerMode(['--fresh'], '1'));
  assert.throws(() => candidateRecoveryRunnerMode(['--retained'], '0'));
});

// Actual Fact runner heredoc plus real private encrypted artifacts. Only Docker,
// PostgreSQL observations and the child test process are seams in this unit test.
async function factRecoveryRunnerFixture() {
  const binding = await tsImport('../identity/fact-recovery-binding.ts', import.meta.url);
  const wire = await tsImport(
    '../../../services/control-api/src/evidence/store-retirement-wire.ts',
    import.meta.url,
  );
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'fact-runner-'));
  const token = 'a'.repeat(64),
    project = `openpc-local-e2e-${token.slice(0, 12)}`,
    directory = join(root, 'data/fact-database-recovery');
  for (const path of [
    directory,
    join(root, 'secrets'),
    join(root, 'evidence/runtime-bootstrap/store-retirement'),
    join(root, 'data/runtime-bootstrap/store-retirement/private'),
  ])
    await mkdir(path, { recursive: true, mode: 0o700 });
  const marker = `openpc-local-runtime:${project}:${token}\n`;
  await writeFile(join(root, '.openpc-local-runtime-owner'), marker, { mode: 0o600 });
  const passwords = Object.fromEntries(
    ['openpc_facts', 'openpc_fact_runtime', 'openpc_policy_fact_runtime'].map((role) => [
      role,
      join(root, 'secrets', role),
    ]),
  );
  const input = binding.factDatabaseRecoveryCase.parse({
    version: 1,
    phase: 'RETIRED',
    project,
    backupDirectory: directory,
    source: {
      containerId: 'b'.repeat(64),
      dataDirectory: join(root, 'data/fact-pg'),
      port: 55433,
      passwords,
    },
    target: {
      containerId: 'c'.repeat(64),
      dataDirectory: join(directory, 'postgres'),
      port: 15434,
      passwords,
    },
    control: {
      port: 55432,
      adminPasswordFile: join(root, 'secrets/control-admin'),
      workerPasswordFile: join(root, 'secrets/control-worker'),
    },
    participantId: '018f0000-0000-7000-8000-000000000001',
    privacyDomainId: '018f0000-0000-7000-8000-000000000002',
    ...binding.factRecoveryInputPaths(root),
    nativeExecutable: join(directory, 'fact_retirement_owner'),
  });
  for (const file of [
    ...Object.values(passwords),
    input.control.adminPasswordFile,
    input.control.workerPasswordFile,
  ])
    await writeFile(file, 'd'.repeat(64), { mode: 0o600 });
  for (const file of [
    ...Object.values(binding.factRecoveryInputPaths(root)),
    input.nativeExecutable,
  ])
    await writeFile(file, '{}', { mode: 0o600 });
  const scope = { participant_id: input.participantId, privacy_domain_id: input.privacyDomainId };
  const selection = wire.retirementSelection.parse({
    class: 'ADMITTED_FACT',
    source: {
      profile_id: 'profile',
      generation_id: 'generation',
      partition_id: 'partition',
      identity_digest: '1'.repeat(64),
    },
    fact_generation_id: 'fact-generation',
    canonical_generation: 1n,
    rows: [
      {
        candidate_id: 'candidate',
        fact_id: 'fact',
        fact_delta_sequence: 1n,
        candidate_feed_sequence: 1n,
        payload_digest: '2'.repeat(64),
        payload_bytes: 12n,
        signed_fact_digest: '3'.repeat(64),
        lineage_digest: '4'.repeat(64),
        checkpoint_digest: '5'.repeat(64),
      },
    ],
  });
  const attempt = wire.retirementAttempt.parse({
    scope,
    store: 'openpc_facts',
    business_intent_id: 'intent',
    attempt_id: 'attempt',
    governance: {
      retention_policy_digest: '6'.repeat(64),
      archive_manifest_digest: '7'.repeat(64),
      archive_acknowledgement_digest: '8'.repeat(64),
      approval_digest: '9'.repeat(64),
      lifecycle_revision: 1n,
      retention_not_before_ms: 1n,
    },
    selection,
    selection_digest: wire.retirementSelectionDigest(scope, selection),
  });
  await writeFile(
    input.terminalReadbackFile,
    JSON.stringify({
      public: { physicalState: 'APPLIED' },
      attemptWire: wire.retirementWireBytes(attempt).toString('hex'),
    }),
  );
  await binding.retainFactRecoveryCase(directory, input);
  const imageId = 'sha256:' + 'e'.repeat(64),
    fp = { count: 0, sha256: '1'.repeat(64) };
  const identity = (value, id) => ({
    containerId: value.containerId,
    dataDirectory: value.dataDirectory,
    port: value.port,
    imageId,
    systemIdentifier: id,
    databaseOid: '16384',
  });
  const original = {
    version: 1,
    kind: 'OPENPC-FACT-RECOVERY-ORIGINAL-1',
    provenance: {
      project,
      ownerDigest: createHash('sha256').update(marker).digest('hex'),
      selectionDigest: createHash('sha256').update(JSON.stringify(input)).digest('hex'),
      phase: 'RETIRED',
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      database: 'openpc_facts',
      databaseOwner: 'openpc_facts',
      source: identity(input.source, '123456789'),
      target: identity(input.target, '987654321'),
    },
    epoch: {
      exportedSnapshot: '00000003-000000AB-1',
      snapshot: '100:110:',
      backendPid: 123,
      timelineId: 1,
      walLsn: '0/1000',
      observedAt: '2026-09-25T12:00:00.000Z',
      connectionLimit: -1,
    },
    comparison: {
      data: [
        'openpc_local.migration',
        'facts.canonical_fact',
        'facts.retained_fact_identity',
        'facts.signed_fact_custody',
        'facts.store_retirement_attempt',
        'facts.retired_fact_payload',
        'facts.store_retirement_outbox',
        'facts.control_admission_custody_ack',
        'facts.fleet_admission_ack',
      ]
        .sort()
        .map((name) => ({ name, ...fp })),
      security: Object.fromEntries(
        [
          'relations',
          'policies',
          'functions',
          'triggers',
          'constraints',
          'schemas',
          'defaults',
          'roles',
          'databases',
          'settings',
          'indexes',
          'extensions',
        ].map((name) => [name, fp]),
      ),
      control: [{ name: 'control.store_retirement_outcome', ...fp }],
      vault: [{ name: 'f'.repeat(64) + '.segment', bytes: 1, digest: 'a'.repeat(64) }],
      inputs: Array.from({ length: 8 }, (_, i) => ({
        name: 'input' + i,
        bytes: 64,
        sha256: '3'.repeat(64),
      })),
    },
  };
  await binding.retainFactRecoveryOriginal(directory, original);
  await binding.captureFactRecoveryArchive(directory, original.provenance, async () =>
    Buffer.from('PGDMPencrypted Fact runner fixture'),
  );
  await binding.sealFactRecoveryBinding(directory, original.provenance);
  return {
    component: 'fact',
    root,
    project,
    directory,
    input,
    caseFile: join(directory, 'case.json'),
    imageId,
    original,
    binding,
    wire: {
      parseRetirementWire: wire.parseRetirementWire,
      retirementAttempt: wire.retirementAttempt,
    },
  };
}
for (const fault of [
  'none',
  'missing-binding',
  'missing-key',
  'changed-archive',
  'changed-case',
  'unfenced-source',
  'changed-live-source',
  'changed-cpu',
  'fresh-conflict',
  'directory-conflict',
  'child-and-stop',
  'stop',
])
  test(`fact recovery runner retained continuation: ${fault}`, async () => {
    const fixture = await factRecoveryRunnerFixture();
    try {
      const before = await readFile(fixture.caseFile);
      if (fault === 'missing-binding')
        await rm(join(fixture.directory, fixture.binding.factRecoveryFiles.seal));
      if (fault === 'missing-key')
        await rm(join(fixture.directory, fixture.binding.factRecoveryFiles.key));
      if (fault === 'changed-archive')
        await writeFile(
          join(fixture.directory, fixture.binding.factRecoveryFiles.archive),
          'corrupt',
        );
      if (fault === 'changed-case')
        await writeFile(
          fixture.caseFile,
          JSON.stringify({
            ...fixture.input,
            participantId: '018f0000-0000-7000-8000-000000000099',
          }),
        );
      const result = await candidateRecoveryRunnerBody(fixture, {
        sourceUnfenced: fault === 'unfenced-source',
        changedSource: fault === 'changed-live-source',
        changedCpu: fault === 'changed-cpu',
        childFails: fault === 'child-and-stop',
        stopFails: ['child-and-stop', 'stop'].includes(fault),
        args: ['fresh-conflict', 'directory-conflict'].includes(fault)
          ? ['--fresh']
          : ['--retained'],
        environment:
          fault === 'fresh-conflict' ? { OPENPC_FACT_DATABASE_RECOVERY_CONTINUE: '1' } : {},
      });
      assert.ok(result.effects.every((args) => !['run', 'cp', 'rm'].includes(args[0])));
      assert.ok(
        result.effects.every(
          (args) => !args.join(' ').includes('migrate.sh') && !args.join(' ').includes('pg_dump'),
        ),
      );
      if (fault === 'none') {
        assert.equal(result.error, undefined);
        assert.match(result.output, /PASS\|retained-original-binding/u);
        assert.ok(result.effects.some((args) => args[0] === 'pool' && args[1] === 15435));
        assert.ok(
          result.effects.findIndex(
            (args) => args[0] === 'pool-end' && args[1] === fixture.input.source.port,
          ) < result.effects.findIndex((args) => args[0] === 'start'),
        );
        assert.deepEqual(await readFile(fixture.caseFile), before);
      } else {
        assert.ok(result.error);
        assert.doesNotMatch(result.output, /\|PASS\|/u);
        if (fault === 'child-and-stop')
          assert.match(result.error.cause.message, /Fact component recovery failed/u);
        if (!['child-and-stop', 'stop'].includes(fault))
          assert.ok(
            result.effects.every((args) => !['start', 'stop', 'invoke-retained'].includes(args[0])),
          );
      }
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
for (const fault of ['none', 'native-preflight', 'preflight-marker', 'preflight-only', 'child'])
  test(`fact recovery runner fresh dispatch: ${fault}`, async () => {
    const fixture = await factRecoveryRunnerFixture();
    try {
      // Discard only this test's fabricated retained case to exercise fresh
      // orchestration. No business owner is replaced or claimed accepted here.
      await rm(fixture.directory, { recursive: true, force: true });
      await writeFile(
        join(fixture.root, 'data/runtime-bootstrap/store-retirement/private/fact_retirement_owner'),
        'unit-original-native',
        { mode: 0o700, flag: 'wx' },
      );
      for (const name of [
        'fact_pg_password',
        'fact_runtime_db_password',
        'policy_fact_db_password',
        'control_pg_password',
        'control_worker_runtime_db_password',
      ])
        await writeFile(join(fixture.root, 'secrets', name + '.txt'), 'd'.repeat(64), {
          mode: 0o600,
          flag: 'wx',
        });
      const terminal = JSON.parse(await readFile(fixture.input.terminalReadbackFile, 'utf8'));
      terminal.public.dispatchNotAfterMs = '1';
      await writeFile(fixture.input.terminalReadbackFile, JSON.stringify(terminal));
      const result = await candidateRecoveryRunnerBody(fixture, {
        fresh: true,
        args: [fault === 'preflight-only' ? '--preflight' : '--fresh'],
        nativePreflightFails: fault === 'native-preflight',
        preflightMarkerMissing: fault === 'preflight-marker',
        childFails: fault === 'child',
      });
      if (['native-preflight', 'preflight-marker', 'preflight-only'].includes(fault)) {
        if (fault === 'preflight-only') {
          assert.equal(result.error, undefined);
          assert.match(
            result.output,
            /OPENPC_FACT_DATABASE_PREFLIGHT\|PASS\|original-dependencies/u,
          );
        } else assert.match(result.error.message, /Fact component recovery failed/u);
        assert.ok(result.effects.every((args) => !['run', 'cp', 'invoke-fresh'].includes(args[0])));
        assert.deepEqual(
          result.effects.filter((args) => args[0] === 'stop'),
          [['stop', 'a'.repeat(64)]],
        );
        await assert.rejects(lstat(fixture.directory), { code: 'ENOENT' });
      } else {
        const input = fixture.binding.factDatabaseRecoveryCase.parse(
          JSON.parse(await readFile(fixture.caseFile, 'utf8')),
        );
        assert.deepEqual(input.source.passwords, {
          openpc_facts: join(fixture.root, 'secrets/fact_pg_password.txt'),
          openpc_fact_runtime: join(fixture.root, 'secrets/fact_runtime_db_password.txt'),
          openpc_policy_fact_runtime: join(fixture.root, 'secrets/policy_fact_db_password.txt'),
        });
        assert.deepEqual(input.target.passwords, input.source.passwords);
        assert.equal(input.target.port, 15435);
        const allocation = result.effects.find((args) => args[0] === 'run');
        for (const name of [
          'fact_pg_password',
          'fact_runtime_db_password',
          'policy_fact_db_password',
        ])
          assert.ok(
            allocation.includes(
              `type=bind,src=${join(fixture.root, 'secrets', name + '.txt')},dst=/run/secrets/${name},readonly`,
            ),
          );
        assert.ok(
          result.effects.findIndex((args) => args[0] === 'native-preflight') <
            result.effects.indexOf(allocation),
        );
        assert.ok(
          result.effects.some(
            (args) => args.includes('/local/migrate.sh') && args.at(-1) === 'fact-roles',
          ),
        );
        assert.ok(result.effects.some((args) => args[0] === 'invoke-fresh'));
        assert.deepEqual(result.effects.at(-1), ['stop', input.target.containerId]);
        if (fault === 'none') {
          assert.equal(result.error, undefined);
          assert.match(result.output, /PASS\|original-retired-payload-absent/u);
        } else assert.match(result.error.cause.message, /Fact component recovery failed/u);
      }
      if (fault !== 'none')
        assert.doesNotMatch(result.output, /OPENPC_FACT_DATABASE_RESTORE\|PASS\|/u);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
test('fact recovery runner preflight selects actual caller and canonical roles-only mode', async () => {
  const source = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const section = c1RunnerSection(
    source,
    'openpc_fact_database_recovery() {',
    '\n# End Fact database recovery',
  );
  const dispatch = section.indexOf('  node --import tsx');
  for (const file of ['fact-recovery-binding.test.ts', 'postgres-fact-database-recovery.test.ts'])
    assert.ok(section.indexOf(file) > 0 && section.indexOf(file) < dispatch);
  assert.match(section, /'fact-roles'/u);
  assert.ok(
    section.indexOf('await invoke(undefined,false,preflightInput)') <
      section.indexOf("target=await run(['run'"),
  );
  assert.doesNotMatch(section, /create role|CREATE ROLE/u);
});

test('candidate recovery runner fresh dispatch preserves the next original Fact database', async () => {
  const fixture = await candidateRecoveryRunnerFixture();
  try {
    await rm(fixture.directory, { recursive: true, force: true });
    for (const name of [
      'candidate_index_pg_password',
      'indexer_manager_db_password',
      'indexer_writer_db_password',
      'candidate_index_reader_db_password',
      'fact_bridge_reader_db_password',
      'control_pg_password',
      'control_worker_runtime_db_password',
    ])
      await writeFile(join(fixture.root, 'secrets', name + '.txt'), 'd'.repeat(64), {
        mode: 0o600,
        flag: 'wx',
      });
    const result = await candidateRecoveryRunnerBody(fixture, { fresh: true, args: ['--fresh'] });
    assert.equal(result.error, undefined);
    assert.match(result.output, /OPENPC_CANDIDATE_DATABASE_RESTORE\|PASS\|/u);
    const allocation = result.effects.findIndex((args) => args[0] === 'run');
    assert.ok(allocation > 0);
    assert.deepEqual(
      result.effects.slice(0, allocation).filter((args) => args[0] === 'stop'),
      [['stop', 'a'.repeat(64)]],
    );
    assert.ok(result.effects.every((args) => !['start', 'restart'].includes(args[0])));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('component recovery terminal dispatch preflights both source dependencies before permanent fencing', async () => {
  const source = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = source.indexOf('openpc_phase_begin fact-database-recovery-preflight');
  assert.ok(start > source.indexOf('openpc_phase_end retention-search-browser 0'));
  const terminal = source.slice(start);
  assert.doesNotMatch(terminal, /\bsource |\bnode |\bdocker |\bcompose\b/u);
  for (const failure of ['none', 'preflight', 'candidate', 'fact']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
failed=$1
candidate_fenced=0
openpc_phase_begin() { :; }
openpc_phase_end() { printf 'done:%s\\n' "$1"; }
openpc_candidate_database_recovery() {
  [[ $1 == --fresh && $candidate_fenced == 0 ]]
  printf 'candidate:fence\\n'; candidate_fenced=1
  [[ $failed != candidate ]] || return 23
}
openpc_fact_database_recovery() {
  if [[ $1 == --preflight ]]; then
    [[ $candidate_fenced == 0 ]]; printf 'fact:preflight\\n'
    [[ $failed != preflight ]] || return 21
  else
    [[ $1 == --fresh && $candidate_fenced == 1 ]]; printf 'fact:fence\\n'
    [[ $failed != fact ]] || return 25
  fi
}
${terminal}
printf 'aggregate:complete\\n'
`,
        'component-terminal',
        failure,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(
      result.status,
      { none: 0, preflight: 21, candidate: 23, fact: 25 }[failure],
      result.stderr,
    );
    const expected = ['fact:preflight'];
    if (failure !== 'preflight')
      expected.push('done:fact-database-recovery-preflight', 'candidate:fence');
    if (['none', 'fact'].includes(failure))
      expected.push('done:candidate-database-recovery', 'fact:fence');
    if (failure === 'none') expected.push('done:fact-database-recovery', 'aggregate:complete');
    assert.deepEqual(result.stdout.trim().split('\n'), expected);
  }
});

test('component recovery cleanup retains originals and preserves the first failure on every disposition', async (t) => {
  const source = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const cleanup = c1RunnerSection(source, 'cleanup() {', '\nopenpc_refresh_visibility() {');
  assert.ok(process.env.OPENPC_TEST_TMP_ROOT);
  const temporary = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'component-cleanup-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  for (const initial of [0, 23])
    for (const failure of ['none', 'owner', 'keeper', 'compose', 'builder']) {
      const evidence = join(temporary, `${initial}-${failure}`);
      await mkdir(evidence, { mode: 0o700 });
      const failureFile = join(evidence, 'runner-failure.txt');
      const prior = initial === 23 && failure === 'builder';
      if (prior) await writeFile(failureFile, 'exit_status=41\n', { mode: 0o600 });
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
declare -A openpc_phase_started=()
openpc_component_recovery_pending=1
run_root=/owned
failed=$2
evidence_root=$3
compose=(compose_call)
validate_run_root() { [[ $failed != owner ]]; }
openpc_rpc_enospc_on_exit() { printf 'keeper:%s\\n' "$1"; [[ $failed != keeper ]]; }
compose_call() { [[ $* == '--profile astra05 stop' && $failed != compose ]]; }
openpc_stop_owned_builder() { printf 'builder\\n'; [[ $failed != builder ]]; }
docker() { printf 'FORBIDDEN-docker\\n'; return 97; }
rm() { printf 'FORBIDDEN-rm\\n'; return 97; }
remove_inventory_containers() { printf 'FORBIDDEN-inventory\\n'; return 97; }
${cleanup}
trap cleanup EXIT
exit "$1"
`,
          'component-cleanup',
          String(initial),
          failure,
          evidence,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, initial || (failure === 'none' ? 0 : 99), result.stderr);
      assert.match(
        result.stderr,
        /OPENPC_COMPONENT_RECOVERY_ROOT\|(?:UNKNOWN_RETAIN_ALL|RETAIN_ALL)/u,
      );
      assert.doesNotMatch(result.stdout, /FORBIDDEN/u);
      if (failure === 'owner') assert.equal(result.stdout, '');
      else assert.equal(result.stdout, `keeper:${initial}\nbuilder\n`);
      if (failure === 'owner' || (initial === 0 && failure === 'none'))
        await assert.rejects(lstat(failureFile), { code: 'ENOENT' });
      else {
        assert.equal(
          await readFile(failureFile, 'utf8'),
          `exit_status=${prior ? 41 : result.status}\n`,
        );
        assert.equal((await stat(failureFile)).mode & 0o777, 0o600);
      }
    }
  for (const component of ['candidate', 'fact']) {
    const section = source.slice(source.indexOf(`openpc_${component}_database_recovery() {`));
    assert.ok(
      section.indexOf('openpc_component_recovery_pending=1') < section.indexOf('pnpm exec vitest'),
    );
  }
});

test('activation readback cannot renew or complete an unfinished original occurrence', async () => {
  const { activationContinuationMode } = await import('./first-policy-activation-browser.mjs');
  const original = { state: 'ACTIVE_MATCHED', matchedTargetCount: '1', totalTargetCount: '1' };
  const options = { historicalReadbackOnly: true, completedRpc: false, historical: true };
  assert.equal(activationContinuationMode(original, options), 'READBACK');
  for (const state of ['REQUESTED', 'STAGING', 'ACTIVATING', 'PARTIAL', 'FAILED', 'ROLLED_BACK'])
    assert.throws(() => activationContinuationMode({ ...original, state }, options));
  assert.throws(() =>
    activationContinuationMode({ ...original, matchedTargetCount: '0' }, options),
  );
  assert.equal(
    activationContinuationMode(original, { ...options, historicalReadbackOnly: false }),
    'RENEW',
  );
  for (const state of ['REQUESTED', 'STAGING', 'ACTIVATING', 'PARTIAL'])
    assert.equal(
      activationContinuationMode(
        { ...original, state, matchedTargetCount: '0' },
        { ...options, historicalReadbackOnly: false },
      ),
      'ACTIVATE',
      'an expired observation must not manufacture a matched predecessor for renewal',
    );
  assert.equal(
    activationContinuationMode(original, {
      ...options,
      historicalReadbackOnly: false,
      historical: false,
    }),
    'ACTIVATE',
  );
});

test('historical activation binds its original digest and preserves the current successor parent', async () => {
  const { assertActivationPolicyReadback } = await import('./first-policy-activation-browser.mjs');
  const original = `sha256:${'a'.repeat(64)}`,
    successor = `sha256:${'b'.repeat(64)}`;
  const occurrence = { targetGenerationDigest: original };
  const parent = {
    policySetId: 'urn:openpc:policy-set:original',
    state: 'ACTIVE',
    activeVersionDigest: successor,
    revision: '8',
  };
  const options = {
    policySetId: parent.policySetId,
    semanticDigest: original,
    historicalReadbackOnly: true,
  };
  assertActivationPolicyReadback(occurrence, parent, options);
  assert.throws(() =>
    assertActivationPolicyReadback(occurrence, parent, {
      ...options,
      historicalReadbackOnly: false,
    }),
  );
  assert.throws(() =>
    assertActivationPolicyReadback({ targetGenerationDigest: successor }, parent, options),
  );
  assert.throws(() =>
    assertActivationPolicyReadback(occurrence, { ...parent, policySetId: 'other' }, options),
  );
  assert.throws(() =>
    assertActivationPolicyReadback(occurrence, { ...parent, state: 'DRAFT' }, options),
  );
  assertActivationPolicyReadback(
    occurrence,
    { ...parent, activeVersionDigest: original },
    { ...options, historicalReadbackOnly: false },
  );
});

test('first activation gate rejects suite, resume and conflicting modes before allocation', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  const block = c1RunnerSection(source, '# This fresh bounded gate', '# Packaged verification');
  for (const [args, environment, expected] of [
    [[], {}, 0],
    [['--suite'], {}, 96],
    [['--resume-root', '/original'], {}, 96],
    [[], { OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY: '1' }, 96],
    [[], { OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE: '1' }, 96],
    [[], { OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY: 'invalid' }, 96],
    [[], { OPENPC_LOCAL_RUNTIME_BUILD_ONLY: '1' }, 0],
  ]) {
    const result = c1RunnerBoundaryResult(
      `set -euo pipefail\n${block}\nprintf '%s' "$OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY"`,
      args,
      { OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY: '1', ...environment },
    );
    assert.equal(result.status, expected, result.stderr);
    assert.equal(result.stdout, expected === 0 ? '1' : '');
  }
});

test('disposition readback requires actual purpose-bound signature and exact claim digest', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { verifyDispositionEnvelope } = await import('./target-disposition-readback.mjs');
  const { canonicalJson } = await tsImport(
    '../../../services/control-api/src/configuration/digest.ts',
    import.meta.url,
  );
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const purpose = 'openpc:target-disposition-delivery:v1';
  const claims = JSON.parse(nativeDispositionGoldenWire.toString()).claims;
  const claims_digest = createHash('sha256').update(JSON.stringify(claims)).digest('hex');
  const envelope = {
    purpose,
    claims,
    claims_digest,
    signature_p1363_hex: sign('sha256', Buffer.from(canonicalJson([purpose, claims_digest])), {
      key: key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
  const wire = (value) => Buffer.from(JSON.stringify(value));
  assert.deepEqual(verifyDispositionEnvelope(wire(envelope), purpose, key.publicKey), claims);
  for (const change of [
    { claims: { ...claims, revision: 3 } },
    { purpose: 'openpc:target-disposition-acknowledgement:v1' },
    { claims_digest: '00'.repeat(32) },
    { signature_p1363_hex: '00'.repeat(64) },
    { extra: true },
  ])
    assert.throws(() =>
      verifyDispositionEnvelope(wire({ ...envelope, ...change }), purpose, key.publicKey),
    );
  // Even a valid signature must not admit fields/encodings rejected by the
  // native typed roundtrip. These cases recompute the digest and signature.
  for (const changedClaims of [
    { ...claims, unexpected: true },
    { ...claims, target: { ...claims.target, unexpected: true } },
    { ...claims, cause: { ...claims.cause, unexpected: true } },
    { ...claims, source: { ...claims.source, unexpected: true } },
    Object.fromEntries(Object.entries(claims).sort()),
  ]) {
    const changedDigest = createHash('sha256').update(JSON.stringify(changedClaims)).digest('hex');
    const signed = {
      purpose,
      claims: changedClaims,
      claims_digest: changedDigest,
      signature_p1363_hex: sign('sha256', Buffer.from(JSON.stringify([purpose, changedDigest])), {
        key: key.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex'),
    };
    assert.throws(() => verifyDispositionEnvelope(wire(signed), purpose, key.publicKey));
  }
  assert.throws(() =>
    verifyDispositionEnvelope(
      wire(envelope),
      purpose,
      generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey,
    ),
  );
});

test('configuration recovery preserves original identity and never resubmits consumed effects', async () => {
  const root = await mkdtemp(join(process.env.TMPDIR ?? '/tmp', 'openpc-configuration-resume-'));
  const body = {
    actionIntentId: 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
    reason: 'Original intent',
    expectedRevision: '2',
  };
  const candidateDigest = spawnSync(
    'node',
    ['tests/integration/local-runtime/configuration-fixture.mjs', 'digest', JSON.stringify(body)],
    { encoding: 'utf8' },
  ).stdout;
  const resource = '018f0000-0000-7000-8000-000000000111';
  const original = {
    candidate: body,
    candidateDigest,
    businessIdempotencyKey: 'original-key',
    resourceRef: `urn:openpc:resource:${resource}`,
    actionIntentId: body.actionIntentId,
    expectedRevision: '2',
    canRequestResume: false,
    approvalUsable: true,
    attemptId: resource,
    state: 'APPROVED',
  };
  try {
    await writeFile(
      join(root, 'approval.json'),
      JSON.stringify({
        makerSubjectRef: 'urn:openpc:resource:maker',
        checkerSubjectRef: 'urn:openpc:resource:checker',
        revision: '2',
      }),
    );
    for (const [state, change, expected] of [
      ['APPROVED', {}, 0],
      ['CONSUMED', {}, 0],
      ['APPROVED', { businessIdempotencyKey: 'changed-key' }, 1],
      ['APPROVED', { candidate: { ...body, reason: 'Changed intent' } }, 1],
      ['APPROVED', { expectedRevision: '3' }, 1],
      ['APPROVED', { approvalUsable: false }, 1],
    ]) {
      await writeFile(
        join(root, 'candidate.json'),
        JSON.stringify({
          ...original,
          state,
          operationRef: `urn:openpc:operation:${resource}`,
          ...change,
        }),
      );
      const result = spawnSync(
        'bash',
        [
          '-c',
          `
set -euo pipefail
source tests/integration/local-runtime/runtime-configuration.sh
root=$1; body=$2; resource=$3
configuration_operator_session=maker-session
configuration_checker_session=checker-session
operator_principal_id=maker
checker_principal_id=checker
action_digest() { printf 'digest'; }
policy_get() { if [[ $2 == */candidate ]]; then cp "$root/candidate.json" "$1"; else cp "$root/approval.json" "$1"; fi; }
operator_assertion_step_up() { [[ $1 == ACT-PROVIDER_APPROVE_QUALIFICATION-V1 && $2 == "$resource" ]] || exit 93; printf 'STEPUP\\n'; }
configuration_post() { [[ $4 == original-key && $6 == POST && $7 == 202 && $8 == maker-session ]] || exit 94; printf 'EXECUTE\\n'; }
configuration_get() { [[ $2 == */operations/urn:openpc:operation:* ]] || exit 95; printf 'READBACK\\n'; }
poll_configuration_operation() { printf 'POLL\\n'; }
resume_approved_configuration "$root/result.json" "$body" "$body" http://localhost/provider/qualify original-key "$resource" urn:openpc:resource:approval original 2
`,
          'test',
          root,
          JSON.stringify(body),
          resource,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, expected, result.stderr);
      if (change.approvalUsable === false)
        assert.match(result.stderr, /OPENPC_CONFIGURATION_CONTINUATION\|blocked\|state=APPROVED/u);
      if (expected !== 0) assert.equal(result.stdout, '');
      else
        assert.equal(
          result.stdout,
          state === 'CONSUMED' ? 'READBACK\nPOLL\n' : 'STEPUP\nEXECUTE\n',
        );
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('target renewal successor preserves terminal originals and rejects uncertainty or effects', async () => {
  const { preserveTerminalRenewal } = await import('./first-policy-target-renewal.mjs');
  const selected = '01a0dd90-49e0-7db2-836c-54c7da35aeca';
  const prior = {
    key: 'original-key',
    body: { expectedRevision: '8' },
    operation: { operationId: selected, revision: '9' },
  };
  const before = { state: 'FAILED', revision: '10' };
  const operation = { operationId: selected, state: 'FAILED', truthState: 'FAILED' };
  const failure = {
    workId: '01a0dd90-4a0a-7dc0-98cb-159824f79d0e',
    operationId: selected,
    state: 'FAILED',
    attemptCount: '3',
    executionAttemptId: null,
    executionStartedAt: null,
    resultEventId: '01a0dd90-4ab0-7704-bc84-0ac58fdf9386',
    resultReceiptDigest: `sha256:${'a'.repeat(64)}`,
    targetRevision: '10',
    observationCount: 0,
    admissionCount: 0,
  };
  const checkpoint = { targetRenewal: structuredClone(prior) };
  preserveTerminalRenewal(checkpoint, before, operation, failure, selected);
  assert.equal(checkpoint.targetRenewal, undefined);
  assert.deepEqual(checkpoint.priorTargetRenewals, [{ ...prior, failure }]);
  assert.deepEqual(prior, {
    key: 'original-key',
    body: { expectedRevision: '8' },
    operation: { operationId: selected, revision: '9' },
  });
  for (const delta of [
    { state: 'LEASED' },
    { executionAttemptId: failure.workId },
    { executionStartedAt: '2026-09-26T00:00:00Z' },
    { observationCount: 1 },
    { admissionCount: 1 },
    { targetRevision: '9' },
    { resultReceiptDigest: null },
    { resultEventId: null },
    { attemptCount: '0' },
    { operationId: failure.workId },
  ]) {
    const unchanged = { targetRenewal: structuredClone(prior) };
    assert.throws(() =>
      preserveTerminalRenewal(unchanged, before, operation, { ...failure, ...delta }, selected),
    );
    assert.deepEqual(unchanged, { targetRenewal: prior });
  }
  for (const changed of [
    { ...operation, state: 'WRITE_AMBIGUITY' },
    { ...operation, truthState: 'UNKNOWN' },
  ])
    assert.throws(() =>
      preserveTerminalRenewal({ targetRenewal: prior }, before, changed, failure, selected),
    );
  assert.throws(() =>
    preserveTerminalRenewal({ targetRenewal: prior }, before, operation, failure, undefined),
  );
  assert.throws(() => preserveTerminalRenewal(checkpoint, before, operation, failure, selected));
});

test('disposition successor readback verifies every signed withdrawal and acknowledgement link', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { verifyTargetDispositionChain } = await import('./target-disposition-readback.mjs');
  const { canonicalJson } = await tsImport(
    '../../../services/control-api/src/configuration/digest.ts',
    import.meta.url,
  );
  const control = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const target = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const digest = (value) => createHash('sha256').update(value).digest('hex');
  const encode = (claims, purpose, key) => {
    const claims_digest = digest(JSON.stringify(claims));
    return Buffer.from(
      JSON.stringify({
        purpose,
        claims,
        claims_digest,
        signature_p1363_hex: sign('sha256', Buffer.from(canonicalJson([purpose, claims_digest])), {
          key,
          dsaEncoding: 'ieee-p1363',
        }).toString('hex'),
      }),
    );
  };
  const golden = JSON.parse(nativeDispositionGoldenWire.toString()).claims;
  const identity = {
    ...golden.target,
    participant_id: 'participant',
    privacy_domain_id: 'privacy',
    target_id: 'target',
  };
  const original = {
    ...golden.source,
    original_work_id: 'original-work',
    original_operation_id: 'original-operation',
    original_execution_attempt_id: 'original-attempt',
    capsule_digest: 'a'.repeat(64),
    predecessor_capsule_digest: null,
  };
  const successor = {
    ...golden.source,
    original_work_id: 'successor-work',
    original_operation_id: 'successor-operation',
    original_execution_attempt_id: 'successor-attempt',
    capsule_digest: 'b'.repeat(64),
    predecessor_capsule_digest: original.capsule_digest,
  };
  const rows = [];
  for (const [index, action] of ['ConfirmActivation', 'Withdraw', 'ConfirmActivation'].entries()) {
    const source = index === 2 ? successor : original;
    const causeSource = index === 0 ? original : successor;
    const binding = {
      version: 1,
      target: identity,
      source,
      cause: {
        kind: 'Activation',
        work_id: causeSource.original_work_id,
        operation_id: causeSource.original_operation_id,
        execution_attempt_id:
          action === 'Withdraw' ? null : causeSource.original_execution_attempt_id,
      },
      action,
      revision: index + 1,
      previous_revision: index,
      previous_delivery_digest: rows.at(-1)?.delivery_digest.slice(7) ?? null,
    };
    const proof = action === 'ConfirmActivation' ? { sourceMode: 'FACT_FREE' } : null;
    const admission_digest = `sha256:${digest(canonicalJson(proof ? { binding, activationProof: proof } : binding))}`;
    const claims = { ...binding, committed_admission_digest: admission_digest.slice(7) };
    const signed_delivery = encode(
      claims,
      'openpc:target-disposition-delivery:v1',
      control.privateKey,
    );
    const delivery_digest = `sha256:${digest(signed_delivery)}`;
    const acknowledgement = {
      version: 1,
      target: identity,
      delivery_digest: delivery_digest.slice(7),
      disposition_revision: index + 1,
      journal_sequence: index + 1,
      installed_state: action === 'Withdraw' ? 'NewUseDenied' : 'ActivationConfirmed',
    };
    const signed_acknowledgement = encode(
      acknowledgement,
      'openpc:target-disposition-acknowledgement:v1',
      target.privateKey,
    );
    rows.push({
      binding,
      activation_proof: proof,
      admission_digest,
      claims,
      signed_delivery,
      delivery_digest,
      acknowledgement,
      signed_acknowledgement,
      acknowledgement_digest: `sha256:${digest(signed_acknowledgement)}`,
    });
  }
  const input = {
    rows,
    participantId: 'participant',
    privacyDomainId: 'privacy',
    targetId: 'target',
    controlKey: control.publicKey,
    targetKey: target.publicKey,
  };
  assert.equal(verifyTargetDispositionChain(input).chain.length, 3);
  for (const broken of [
    [rows[0], rows[2]],
    [rows[1], rows[0], rows[2]],
    [rows[0], { ...rows[1], signed_acknowledgement: null }, rows[2]],
    [rows[0], { ...rows[1], admission_digest: `sha256:${'0'.repeat(64)}` }, rows[2]],
    [rows[0], rows[1], { ...rows[2], signed_acknowledgement: rows[0].signed_acknowledgement }],
  ])
    assert.throws(() => verifyTargetDispositionChain({ ...input, rows: broken }));
});

// Public wire and public verification key emitted by native PurposeSigner during
// the real governed withdrawal. No private signing material is part of this vector.
const nativeDispositionGoldenWire = Buffer.from(
  '{"purpose":"openpc:target-disposition-delivery:v1","claims":{"version":1,"target":{"participant_id":"018f0000-0000-7000-8000-000000000101","privacy_domain_id":"018f0000-0000-7000-8000-000000007201","target_id":"01a0dc10-59a1-7f0e-aa0d-29235563be8e","credential_id":"018f0000-0000-7000-8000-000000008192","principal_id":"018f0000-0000-7000-8000-000000008190","credential_epoch":1,"principal_epoch":1,"certificate_digest":"6f1bf1d69d77e6b77c9c715ea66f7db34b684323cfd66cfcbb13528d31434443"},"source":{"runtime_configuration_input_id":"01a0dc11-fb7b-7ffb-a6c2-bf8504d836ca","configuration_digest":"1d8d6b49bec1429650779f1964ce996e02cead9bff5a05ec9d062e4f2c578b12","module_installation_id":"01a0dc08-948a-77f9-bdeb-e8ec266e3124","module_configuration_generation_id":"01a0dc08-adc9-797f-bd5c-3404e46e245c","runtime_configuration_generation_id":"01a0dce3-fc56-7de7-92fb-18c371eda763","capsule_digest":"b6cfacab1df5527228c77a4da59db03f328e4e7bc29f6ea1004767c29aeb7af3","xds_version_digest":"1cbed054d0b1d883504db20ab32536cf14ca40fcd9d19f5521fa1b5f62b905e8","predecessor_capsule_digest":null,"original_work_id":"01a0dce3-fc5b-787b-ac18-2c173d3ca1a0","original_operation_id":"01a0dce3-fc5b-78d8-8dab-66b5c0d614ad","original_execution_attempt_id":"01a0dcf0-3aa4-78a2-83b1-cbbf102f476a"},"cause":{"kind":"Activation","work_id":"01a0df10-97a1-7eb4-ba07-53bfd94fa4c7","operation_id":"01a0df10-976e-7916-9ac2-577253118d8b","execution_attempt_id":null},"action":"Withdraw","revision":2,"previous_revision":1,"previous_delivery_digest":"ca7ef8b7adcdaf7a3a0a597939168afad4564c039e1395b66a2c84af60e2c07f","committed_admission_digest":"d45a9a01dc5f8821654e693ba2d3d86700d5c3c5ed58dde855292e920096289b"},"claims_digest":"dcf940d29c2200c9337dc3b83b8d954a62d847c8859cd75166d1aca43b77daea","signature_p1363_hex":"8993d6d605874bd66905aeb74f282023326dc5f0e24df379895e633ba1594cdddaa9c4c73f5137737fae6f879ecf647f9b3634b01c2aa9147e8a415883a8101b"}',
);

test('disposition readback accepts native declaration-order golden bytes and rejects altered encodings', async () => {
  const { createPublicKey } = await import('node:crypto');
  const { verifyDispositionEnvelope } = await import('./target-disposition-readback.mjs');
  const wire = nativeDispositionGoldenWire;
  const publicKey = createPublicKey(
    '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp/3oeDduFmdfZWblaOpblvxkkqMq\ndwJoL/6KNqhHGhHVXKqPgPzSEq6GKWm2aeNRHBAnDCvAr6LSHEeZqzAMyQ==\n-----END PUBLIC KEY-----\n',
  );
  const purpose = 'openpc:target-disposition-delivery:v1';
  const claims = verifyDispositionEnvelope(wire, purpose, publicKey);
  assert.equal(claims.action, 'Withdraw');
  assert.equal(claims.revision, 2);
  const envelope = JSON.parse(wire.toString());
  assert.notEqual(
    createHash('sha256')
      .update(JSON.stringify(Object.fromEntries(Object.entries(claims).sort())))
      .digest('hex'),
    envelope.claims_digest,
  );
  for (const changed of [
    Buffer.concat([Buffer.from(' '), wire]),
    Buffer.from(wire.toString().replace('"revision":2', '"revision":2.0')),
    Buffer.from(wire.toString().replace('"revision":2', '"revision":1,"revision":2')),
    Buffer.from(
      JSON.stringify({ ...envelope, claims: Object.fromEntries(Object.entries(claims).sort()) }),
    ),
    Buffer.from(JSON.stringify({ ...envelope, claims: { ...claims, revision: 9007199254740992 } })),
    Buffer.from(JSON.stringify({ ...envelope, claims: { ...claims, action: 'Restore' } })),
    Buffer.from(JSON.stringify({ ...envelope, signature_p1363_hex: '00'.repeat(64) })),
  ])
    assert.throws(() => verifyDispositionEnvelope(changed, purpose, publicKey));
});

test('disposition expiry phase rejects invalid authority representations and unbounded waits', async () => {
  const { dispositionExpiryDelay } = await import('./target-disposition-recovery.mjs');
  const now = 1800000000000;
  assert.equal(dispositionExpiryDelay(String(BigInt(now) * 1000000n - 1n), now), 0);
  assert.equal(dispositionExpiryDelay(String(BigInt(now) * 1000000n + 1n), now), 1);
  assert.equal(dispositionExpiryDelay(String(BigInt(now + 60000) * 1000000n), now), 60000);
  for (const expiry of [
    '0',
    '-1',
    '01',
    '1e18',
    '18446744073709551616',
    String(BigInt(now + 120001) * 1000000n),
  ])
    assert.throws(() => dispositionExpiryDelay(expiry, now));
});

test('target renewal input preparation observes fresh discovery snapshots and releases aborted attempts', async () => {
  const { prepareTargetRenewalInputs } = await import('./first-policy-target-renewal.mjs');
  const events = [],
    discoveries = [false, true, true, true];
  let next = 0,
    preparations = 0;
  const pool = {
    async connect() {
      const id = ++next;
      events.push([id, 'connect']);
      return {
        async query(sql) {
          events.push([id, sql]);
          if (sql.includes('runtime_target_discovery_current'))
            return { rows: [{ current: discoveries.shift() }] };
          return { rows: [] };
        },
        release() {
          events.push([id, 'release']);
        },
      };
    },
  };
  const checkpoint = {};
  const prepared = await prepareTargetRenewalInputs(
    pool,
    {
      participantId: 'participant',
      privacyDomainId: 'privacy',
      targetId: 'target',
    },
    async () => {
      assert.deepEqual(checkpoint, {});
      if (++preparations === 1) throw Object.assign(new Error('serialization'), { code: '40001' });
      return { digest: 'prepared' };
    },
  );
  checkpoint.prepared = prepared;
  assert.equal(next, 4);
  assert.equal(preparations, 2);
  assert.deepEqual(checkpoint, { prepared: { digest: 'prepared' } });
  for (let id = 1; id <= next; id += 1) {
    const local = events.filter(([owner]) => owner === id).map(([, sql]) => sql);
    assert.equal(local[1], id <= 2 ? 'begin' : 'begin isolation level serializable');
    assert.ok(local.includes('set local role openpc_control_reader'));
    assert.ok(local.includes('set local row_security=on'));
    assert.deepEqual(local.slice(-2), ['rollback', 'release']);
    if (id < next)
      assert.ok(
        events.findIndex(([owner, sql]) => owner === id && sql === 'release') <
          events.findIndex(([owner, sql]) => owner === id + 1 && sql === 'connect'),
      );
  }
});

test('target renewal preparation never persists failed inputs or retries denials and lost connections', async () => {
  const { prepareTargetRenewalInputs } = await import('./first-policy-target-renewal.mjs');
  for (const [code, attempts] of [
    ['40001', 3],
    ['40P01', 3],
    ['P0001', 1],
    ['ECONNRESET', 1],
  ]) {
    let calls = 0,
      released = 0,
      persisted = 0;
    const checkpoint = {};
    const error = Object.assign(new Error('PC-DATA-6007'), { code });
    const pool = {
      async connect() {
        return {
          async query() {
            return { rows: [{ current: true }] };
          },
          release() {
            released += 1;
          },
        };
      },
    };
    await assert.rejects(
      async () => {
        const result = await prepareTargetRenewalInputs(pool, {}, async () => {
          calls += 1;
          throw error;
        });
        checkpoint.result = result;
        persisted += 1;
      },
      (actual) => actual === error,
    );
    assert.equal(calls, attempts);
    assert.equal(released, attempts + 1);
    assert.equal(persisted, 0);
    assert.deepEqual(checkpoint, {});
  }
  let prepares = 0,
    releases = 0;
  const observations = [true, false];
  const pool = {
    async connect() {
      return {
        async query(sql) {
          return {
            rows: [
              {
                current: sql.includes('runtime_target_discovery_current')
                  ? observations.shift()
                  : undefined,
              },
            ],
          };
        },
        release() {
          releases += 1;
        },
      };
    },
  };
  await assert.rejects(
    prepareTargetRenewalInputs(pool, {}, async () => {
      prepares += 1;
    }),
    /Current discovery required/,
  );
  assert.equal(prepares, 0);
  assert.equal(releases, 2);
});

test('withdrawal observation abort destroys its actual PostgreSQL read socket', async () => {
  const { Pool } = await import('pg');
  const net = await import('node:net');
  const { once } = await import('node:events');
  const { withdrawalObservationBounds, withWithdrawalObservationClient } =
    await import('./target-disposition-readback.mjs');
  const sockets = [];
  let queried;
  const queryStarted = new Promise((resolve) => {
    queried = resolve;
  });
  const server = net.createServer((socket) => {
    sockets.push(socket);
    socket.on('error', () => {});
    socket.once('data', () => {
      socket.write(Buffer.from([82, 0, 0, 0, 8, 0, 0, 0, 0, 90, 0, 0, 0, 5, 73]));
      socket.once('data', queried);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const pool = new Pool({
    ...withdrawalObservationBounds,
    host: '127.0.0.1',
    port: server.address().port,
    user: 'fixture',
    database: 'fixture',
    max: 1,
  });
  const cancellation = new AbortController();
  try {
    const pending = withWithdrawalObservationClient(pool, cancellation.signal, (client) =>
      client.query('select 1'),
    );
    const rejected = assert.rejects(pending);
    await queryStarted;
    const closed = once(sockets[0], 'close');
    cancellation.abort(new Error('Observation deadline'));
    await rejected;
    await closed;
    assert.equal(pool.totalCount, 0);
    await assert.rejects(
      withWithdrawalObservationClient(pool, cancellation.signal, () =>
        assert.fail('Cancelled read ran'),
      ),
      /Observation deadline/u,
    );
  } finally {
    await pool.end();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('unknown withdrawal journal permits only the exact unsigned observed head', async () => {
  const { assertUnknownWithdrawalJournal } = await import('./target-disposition-readback.mjs');
  const source = { capsule_digest: 'retained-capsule' };
  const admission = {
    immutable: {
      admission: `sha256:${'4'.repeat(64)}`,
      binding: { source, revision: 4, previous_revision: 3 },
      predecessorChain: [
        {
          delivery: Buffer.from('signed-delivery'),
          acknowledgement: Buffer.from('signed-ack'),
          admission: `sha256:${'3'.repeat(64)}`,
        },
      ],
    },
  };
  const original = {
    version: 1,
    sequence: 0,
    canonical: {
      sequence: 2,
      active: { capsule: 'retained-capsule' },
      target_disposition: {
        sequence: 3,
        observed: { revision: 3, admission_digest: '3'.repeat(64) },
        installed: {
          source,
          signed_delivery: [...Buffer.from('signed-delivery')],
          signed_acknowledgement: [...Buffer.from('signed-ack')],
        },
      },
    },
  };
  const bytes = (value) => Buffer.from(JSON.stringify(value));
  const next = structuredClone(original);
  next.canonical.target_disposition.observed = { revision: 4, admission_digest: '4'.repeat(64) };
  assertUnknownWithdrawalJournal(bytes(original), bytes(next), admission);
  assertUnknownWithdrawalJournal(bytes(next), bytes(next), admission);
  const mutations = [
    (j) => j.canonical.target_disposition.observed.revision++,
    (j) => (j.canonical.target_disposition.observed.admission_digest = '5'.repeat(64)),
    (j) => j.canonical.target_disposition.installed.signed_delivery.push(1),
    (j) => j.canonical.target_disposition.installed.signed_acknowledgement.push(1),
    (j) => (j.canonical.target_disposition.installed.source.capsule_digest = 'other'),
    (j) => j.canonical.target_disposition.sequence++,
    (j) => j.canonical.sequence++,
    (j) => (j.canonical.active.capsule = 'other'),
    (j) => (j.extra = true),
    (j) => (j.canonical.target_disposition.observed.extra = true),
  ];
  for (const mutate of mutations) {
    const bad = structuredClone(next);
    mutate(bad);
    assert.throws(() => assertUnknownWithdrawalJournal(bytes(original), bytes(bad), admission));
  }
  assert.throws(() => assertUnknownWithdrawalJournal(bytes(original), bytes(original), admission));
});

test('unknown withdrawal persists its bounded pre-fault baseline before public submission or arming', async () => {
  const { retainUnknownWithdrawalBaseline } = await tsImport(
    './first-policy-withdrawal-unknown.mjs',
    import.meta.url,
  );
  const original = {
    operation: 'prior-operation',
    work: 'prior-work',
    delivery: Buffer.from('signed'),
    acknowledgement: Buffer.from('ack'),
    chain: [{ admission: 'prior-admission' }],
  };
  const before = Buffer.from(
    JSON.stringify({
      target_id: 'target',
      canonical: {
        target_disposition: {
          installed: {
            signed_delivery: [...original.delivery],
            signed_acknowledgement: [...original.acknowledgement],
          },
        },
      },
    }),
  );
  const checkpoint = {};
  let saved;
  await retainUnknownWithdrawalBaseline({
    before,
    original,
    targetId: 'target',
    checkpoint,
    persist: async () => {
      saved = JSON.stringify(checkpoint);
    },
  });
  const retained = JSON.parse(saved).unknownWithdrawalBaseline;
  assert.deepEqual(Buffer.from(retained.journalBase64, 'base64'), before);
  assert.equal(retained.predecessorOperationId, original.operation);
  assert.equal(retained.predecessorWorkId, original.work);
  assert.deepEqual(retained.admissionDigests, ['prior-admission']);
  await assert.rejects(
    retainUnknownWithdrawalBaseline({
      before,
      original,
      targetId: 'target',
      checkpoint,
      persist: () => assert.fail('Overwrite reached persistence'),
    }),
    /cannot be overwritten/u,
  );
  await assert.rejects(
    retainUnknownWithdrawalBaseline({
      before,
      original,
      targetId: 'target',
      checkpoint: {},
      persist: async () => {
        throw new Error('Disk unavailable');
      },
    }),
    /Disk unavailable/u,
  );
  await assert.rejects(
    retainUnknownWithdrawalBaseline({
      before: Buffer.alloc(16 * 1024 * 1024 + 1),
      original,
      targetId: 'target',
      checkpoint: {},
      persist: () => assert.fail('Oversized persistence'),
    }),
    /bounded checkpoint/u,
  );
  const source = await readFile(
    'tests/integration/local-runtime/first-policy-withdrawal-unknown.mjs',
    'utf8',
  );
  assert.ok(
    source.indexOf('await retainUnknownWithdrawalBaseline(') <
      source.indexOf('const renewal = await submitFirstPolicyTargetRenewal('),
  );
  assert.ok(
    source.indexOf('await retainUnknownWithdrawalBaseline(') < source.indexOf('proxy.arm()'),
  );
});

test('runtime predecessor current binary survives shared cache overwrite and rejects retained substitution', async () => {
  const { verifyRetainedCurrentWorker } = await tsImport(
    './runtime-source-predecessor-runtime.mjs',
    import.meta.url,
  );
  const root = await mkdtemp(
    join(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT, 'current-worker-pin.'),
  );
  const name = 'current-worker-018f0000-0000-7000-8000-000000000001';
  const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2, 3]);
  const path = join(root, name);
  await writeFile(join(root, 'shared-cache-worker'), bytes, { mode: 0o700 });
  await copyFile(join(root, 'shared-cache-worker'), path);
  const record = {
    producer: 'cargo-build-locked-offline-local-runtime-worker',
    binding: 'actual-build-inputs',
    name,
    executableDigest: createHash('sha256').update(bytes).digest('hex'),
    compilerInputs: [],
  };
  assert.equal(await verifyRetainedCurrentWorker(root, record, record.binding), path);
  await writeFile(join(root, 'shared-cache-worker'), Buffer.from('replaced by predecessor build'));
  assert.equal(await verifyRetainedCurrentWorker(root, record, record.binding), path);
  await assert.rejects(verifyRetainedCurrentWorker(root, record, 'changed-inputs'));
  await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 9]));
  await assert.rejects(verifyRetainedCurrentWorker(root, record, record.binding));
});

test('runtime predecessor host denial decoder rejects unrelated failures and only accepts exact owned reasons', async () => {
  const { isRuntimePredecessorHostRejection, runtimePredecessorHostFailure } = await tsImport(
    '../../../scripts/operations/runtime-source-predecessor.mjs',
    import.meta.url,
  );
  for (const [reason, stage] of [
    ['executable_mismatch', 'run'],
    ['run_state_rejected', 'run'],
    ['cluster_mismatch', 'installation'],
    ['capture_state_rejected', 'capture'],
    ['reconcile_state_rejected', 'reconcile'],
    ['consume_state_rejected', 'consume'],
  ]) {
    const record = { event: 'runtime_source_predecessor_rejected', stage, reason };
    const failure = { code: 1, signal: null, stdout: '', stderr: `${JSON.stringify(record)}\n` };
    assert.equal(isRuntimePredecessorHostRejection(failure, reason), true);
    for (const changed of [
      { code: 0 },
      { code: 'ECONNREFUSED' },
      { code: 'ETIMEDOUT' },
      { signal: 'SIGTERM' },
      { killed: true },
      { stdout: 'unexpected' },
      { stderr: 'RUNTIME_SOURCE_PREDECESSOR_HOST_REJECTED\n' },
      { stderr: JSON.stringify({ ...record, event: 'runtime_source_predecessor_unavailable' }) },
      { stderr: JSON.stringify({ ...record, stage: 'host' }) },
      { stderr: JSON.stringify({ ...record, reason: 'unavailable' }) },
      { stderr: JSON.stringify({ ...record, extra: 'field' }) },
      { stderr: `${JSON.stringify(record)}\nunrelated output` },
    ])
      assert.equal(isRuntimePredecessorHostRejection({ ...failure, ...changed }, reason), false);
    assert.equal(isRuntimePredecessorHostRejection(failure, 'caller-invented'), false);
    for (const error of [
      new Error('bad configuration'),
      new Error('resource admission failed'),
      Object.assign(new Error('database unavailable'), { code: 'ECONNREFUSED' }),
      Object.assign(new Error('SQL permission denied'), { code: '42501' }),
      Object.assign(new Error('query timeout'), { code: '57014' }),
      Object.assign(new Error('forged reason'), { reason }),
    ]) {
      const output = runtimePredecessorHostFailure(error);
      assert.deepEqual(output, {
        event: 'runtime_source_predecessor_unavailable',
        stage: 'host',
        reason: 'unavailable',
      });
      assert.equal(
        isRuntimePredecessorHostRejection({ ...failure, stderr: JSON.stringify(output) }, reason),
        false,
      );
    }
  }
});

test('runtime predecessor CHECK restore producer fails before any migration consumer', async () => {
  const source = await readFile('deploy/compose/local/migrate.sh', 'utf8');
  const start = source.indexOf('emit_control_check_restore() (');
  const end = source.indexOf('\n# Identity 0100', start);
  assert(start > 0 && end > start);
  const directory = await mkdtemp(
    join(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT, 'restore-producer.'),
  );
  const fixture = join(directory, 'migrations/postgres/control-api');
  await mkdir(fixture, { recursive: true });
  for (const name of ['0123_curved_firelord.sql', '0156_notification_completion_shared.sql'])
    await writeFile(join(fixture, name), await readFile(`migrations/postgres/control-api/${name}`));
  const pending = join(fixture, '0171_pending.sql');
  await writeFile(pending, 'SELECT 1;');
  const definitions = source
    .slice(start, end)
    .replaceAll('/migrations/postgres/control-api', fixture);
  for (const failure of ['missing', 'hash', 'ledger', 'mid-emitter', 'consumer']) {
    const script = `set -eu
mode=control
control_checks_reconciled=0
${definitions}
ledger_digest() {
 case "$1" in *0171_pending.sql) return 0 ;; esac
 ${failure === 'ledger' ? 'return 71' : ''}
 command sha256sum "$1" | cut -d ' ' -f 1
}
psql_base() { printf 'CONSUMER\n'; return ${failure === 'consumer' ? '31' : '0'}; }
emit_ledger_insert() { printf 'SELECT 1;\n'; }
${failure === 'missing' ? `check_marker=${fixture}/0123_curved_firelord.sql; mv "$check_marker" "$check_marker.hidden"` : ''}
${failure === 'hash' ? 'sha256sum() { case "$1" in *0123_*) return 72 ;; *) command sha256sum "$@" ;; esac; }' : ''}
${failure === 'mid-emitter' ? 'awk() { case "$*" in *completion_disposition_bytes_ck*) return 73 ;; *) command awk "$@" ;; esac; }' : ''}
if apply_owned_file '${pending}'; then result=0; else result=$?; fi
${failure === 'missing' ? 'mv "$check_marker.hidden" "$check_marker"' : ''}
printf 'RESULT=%s RECONCILED=%s\n' "$result" "$control_checks_reconciled"
exit "$result"
`;
    const result = spawnSync('sh', ['-c', script], { encoding: 'utf8' });
    assert.notEqual(result.status, 0, failure);
    assert.match(result.stdout, /RECONCILED=0/u, failure);
    assert.equal(result.stdout.includes('CONSUMER'), failure === 'consumer', failure);
    if (failure === 'consumer') assert.equal(result.status, 31);
  }
});

test('runtime predecessor host rejects ambiguous arguments, public configs and untrusted scope input before connection', async () => {
  const { parseRuntimePredecessorHostArguments, runRuntimePredecessorHost } = await tsImport(
    '../../../scripts/operations/runtime-source-predecessor.mjs',
    import.meta.url,
  );
  for (const args of [
    [],
    ['--action', 'reset', '--config', '/private/config.json'],
    ['--action', 'status', '--config', 'relative.json'],
    ['--action', 'status', '--config', '/private/../config.json'],
    ['--action', 'status', '--config', '/private/config.json', '--force'],
  ])
    assert.throws(() => parseRuntimePredecessorHostArguments(args));
  const root = await mkdtemp(
    join(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT, 'predecessor-host-config.'),
  );
  const config = join(root, 'config.json');
  const input = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    database: {
      host: '127.0.0.1',
      port: 5432,
      name: 'openpc_control',
      user: 'openpc_control',
      passwordFile: join(root, 'unread-secret'),
    },
  };
  const prior = process.env.OPENPC_LOCAL_RUNTIME;
  process.env.OPENPC_LOCAL_RUNTIME = '1';
  let connections = 0;
  const pool = {
    connect() {
      connections++;
      throw new Error('Unexpected connection');
    },
  };
  try {
    await writeFile(config, JSON.stringify(input), { mode: 0o644 });
    await assert.rejects(
      runRuntimePredecessorHost(['--action', 'status', '--config', config], pool),
    );
    await chmod(config, 0o600);
    const alias = join(root, 'alias.json');
    await symlink(config, alias);
    await assert.rejects(
      runRuntimePredecessorHost(['--action', 'status', '--config', alias], pool),
    );
    for (const bytes of [
      JSON.stringify({ ...input, callerReady: true }),
      JSON.stringify({ ...input, database: { ...input.database, host: '203.0.113.1' } }),
      JSON.stringify(input).replace(
        '{',
        '{"participantId":"018f0000-0000-7000-8000-000000000999",',
      ),
    ]) {
      await writeFile(config, bytes);
      await assert.rejects(
        runRuntimePredecessorHost(['--action', 'status', '--config', config], pool),
      );
    }
    assert.equal(connections, 0);
  } finally {
    if (prior === undefined) delete process.env.OPENPC_LOCAL_RUNTIME;
    else process.env.OPENPC_LOCAL_RUNTIME = prior;
  }
});

test('QA duration gateway preserves routing and scales all finite serving deadlines', async () => {
  const { format } = await import('prettier');
  const normal = await readFile('deploy/compose/local/envoy/local-gateway.yaml', 'utf8');
  const qa = await readFile('deploy/compose/local/envoy/local-gateway-qa-10x.yaml', 'utf8');
  const expected = normal
    .replace(
      '                stat_prefix: public\n',
      [
        '                stat_prefix: public',
        '                # Envoy normal implicit stream idle is 300s; QA is exactly 10x.',
        '                # Routes inherit this finite bound (including long silent responses).',
        '                stream_idle_timeout: 3000s',
        '                common_http_protocol_options:',
        '                  idle_timeout: 36000s',
        '                drain_timeout: 50s',
        '',
      ].join('\n'),
    )
    .replace(/\btimeout: ([1-9][0-9]*)s/gu, (_, seconds) => `timeout: ${Number(seconds) * 10}s`)
    .replace(
      /connect_timeout: ([1-9][0-9]*)s/gu,
      (_, seconds) => `connect_timeout: ${Number(seconds) * 10}s`,
    )
    .replace(
      /route: \{ cluster: ([a-z_]+) \}/gu,
      (_, cluster) => `route: { cluster: ${cluster}, timeout: 150s }`,
    );
  assert.notEqual(expected, normal);
  assert.equal(await format(qa, { parser: 'yaml' }), await format(expected, { parser: 'yaml' }));
});

test('runtime source bootstrap preserves declared input permissions under a private umask', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'source-permissions-'));
  try {
    await chmod(root, 0o700);
    await mkdir(join(root, 'data'), { mode: 0o700 });
    await mkdir(join(root, 'secrets'), { mode: 0o700 });
    const invoke = () =>
      spawnSync(
        'bash',
        [
          '-euc',
          'umask 077; exec node tests/integration/local-runtime/runtime-source-bootstrap.mjs prepare "$1"',
          'bootstrap-permissions',
          root,
        ],
        { encoding: 'utf8' },
      );
    const result = invoke();
    assert.equal(result.status, 0, result.stderr);
    assert.equal((await stat(root)).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, 'secrets'))).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, 'data/runtime-source-config'))).mode & 0o777, 0o755);
    for (const path of [
      'data/runtime-source-config/input.json',
      'secrets/runtime_source_signing_key',
      'secrets/runtime_source_commit_key',
      'secrets/runtime_source_database_password',
    ])
      assert.equal((await stat(join(root, path))).mode & 0o777, 0o444);
    const original = await readFile(join(root, 'data/runtime-source-config/input.json'));
    assert.notEqual(invoke().status, 0, 'Existing bootstrap state must not be overwritten');
    assert.deepEqual(await readFile(join(root, 'data/runtime-source-config/input.json')), original);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('provider readback retries only confirmed contention rollbacks and releases each client', async () => {
  const { withProviderReadbackRollback } =
    await import('./provider-probe-readback-transaction.mjs');
  const events = [];
  let attempts = 0;
  const pool = {
    async connect() {
      const attempt = ++attempts;
      return {
        async query(sql) {
          assert.equal(sql, 'rollback');
          events.push(`rollback-${attempt}`);
        },
        release() {
          events.push(`release-${attempt}`);
        },
      };
    },
  };
  const result = await withProviderReadbackRollback(
    pool,
    async () => {
      if (attempts === 1) throw Object.assign(new Error('PC-DATA-6007'), { code: 'P0001' });
      if (attempts === 2) throw Object.assign(new Error('serialization'), { code: '40001' });
      return 'original readback';
    },
    { retryContention: true },
  );
  assert.equal(result, 'original readback');
  assert.deepEqual(events, [
    'rollback-1',
    'release-1',
    'rollback-2',
    'release-2',
    'rollback-3',
    'release-3',
  ]);
});

test('provider readback preserves first failures without replay after denial or uncertain cleanup', async () => {
  const { withProviderReadbackRollback } =
    await import('./provider-probe-readback-transaction.mjs');
  for (const [code, retryContention, cleanupFailure, expectedAttempts] of [
    ['40001', false, '', 1],
    ['P0001', true, '', 1],
    ['42501', true, '', 1],
    ['ECONNRESET', true, '', 1],
    ['40001', true, 'rollback', 1],
    ['40001', true, 'release', 1],
    ['40001', true, '', 3],
  ]) {
    let attempts = 0,
      releases = 0;
    const original = Object.assign(new Error('first failure'), { code });
    const pool = {
      async connect() {
        attempts += 1;
        return {
          async query() {
            if (cleanupFailure === 'rollback') throw new Error('lost rollback');
          },
          release() {
            releases += 1;
            if (cleanupFailure === 'release') throw new Error('lost client');
          },
        };
      },
    };
    await assert.rejects(
      withProviderReadbackRollback(
        pool,
        async () => {
          throw original;
        },
        { retryContention },
      ),
      (error) => error === original,
    );
    assert.equal(attempts, expectedAttempts);
    assert.equal(releases, expectedAttempts);
  }
});

test('both public gateways route runtime profile bindings before the closed fallback', async () => {
  for (const [name, timeout] of [
    ['local-gateway.yaml', '60s'],
    ['local-gateway-qa-10x.yaml', '600s'],
  ]) {
    const config = await readFile(`deploy/compose/local/envoy/${name}`, 'utf8');
    const profileRoute =
      /path_separated_prefix: ['"]\/api\/v1\/runtime-target-profile-bindings['"] \}\s+route: \{ cluster: control_api, timeout: ([0-9]+s) \}/u.exec(
        config,
      );
    assert.ok(profileRoute, `${name}: permission-profile bindings must reach their owner`);
    assert.equal(profileRoute[1], timeout);
    const fallback = /prefix: ['"]\/api\/['"] \}\s+direct_response: \{ status: 404 \}/u.exec(
      config,
    );
    assert.ok(
      fallback && profileRoute.index < fallback.index,
      `${name}: closed fallback follows known owners`,
    );
  }
});
