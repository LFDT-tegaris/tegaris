import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

const selector = 'tests/integration/local-runtime/build-inputs.py';
const services = [
  'control-worker',
  'fact-service',
  'policy-service',
  'identity-service',
  'participant-service',
  'control-api',
  'admin-web',
];
function run(command, args, options = {}) {
  // Each scenario selects its own journey, including when run from a retained journey.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !/^OPENPC_LOCAL_RUNTIME_.*_ONLY$/u.test(name)),
  );
  return spawnSync(command, args, { encoding: 'utf8', env, ...options });
}
function python(body, data) {
  return run(
    'python3',
    [
      '-B',
      '-c',
      `import json, pathlib, runpy, sys
ns=runpy.run_path('${selector}')
root=pathlib.Path.cwd().resolve()
data=json.load(sys.stdin)
${body}`,
    ],
    { input: JSON.stringify(data) },
  );
}

test('build inputs select actual Compose consumers and ignore non-runtime changes', () => {
  const rendered = run('docker', [
    'compose',
    '-f',
    'deploy/compose/local/compose.yaml',
    'config',
    '--no-interpolate',
    '--no-normalize',
    '--format',
    'json',
  ]);
  assert.equal(rendered.status, 0, rendered.stderr);
  const configuration = JSON.parse(rendered.stdout);
  const builds = Object.fromEntries(
    services.map((name) => [name, configuration.services[name].build]),
  );
  const native = ['control-worker', 'fact-service', 'policy-service', 'control-api'];
  for (const [paths, expected] of [
    [['AGENTS.md', 'apps/admin-web/AGENTS.md', 'apps/admin-web/example.test.ts'], []],
    [
      [
        'tests/integration/local-runtime/runner-harness.sh',
        'scripts/maintenance/local-runtime-images.sh',
        'tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs',
        'tests/integration/local-runtime/rpc-journal-enospc-runtime.test.mjs',
        'tests/integration/local-runtime/runner-boundary.test.mjs',
        'tests/integration/local-runtime/build-inputs.test.mjs',
      ],
      [],
    ],
    [
      [
        'tests/integration/local-runtime/deployment-submission-journey.sh',
        'tests/integration/local-runtime/evidence-deployment-retirement.mjs',
        'tests/integration/local-runtime/evidence-effect-custody.mjs',
        'tests/integration/local-runtime/run-compose-e2e.sh',
        'tests/integration/ci/invocation.test.mjs',
      ],
      [],
    ],
    [['apps/admin-web/components/privacy-explorer-workflow.tsx', 'AGENTS.md'], ['admin-web']],
    [['services/fleet-controller/src/local_fixture/indexer.rs'], native],
    [['services/fact-service/src/candidate_feed/reorg.rs'], native],
    [['services/fact-service/tests/fixture.rs'], native],
    [['crates/pc-policy-core/src/lib.rs'], native],
    [
      ['packages/security-kernel/src/index.ts'],
      ['policy-service', 'identity-service', 'participant-service', 'control-api', 'admin-web'],
    ],
    [['services/fact-service/Dockerfile'], ['fact-service']],
    [['Cargo.lock'], native],
    [['.dockerignore'], services],
  ]) {
    const result = python(
      "print(json.dumps(ns['selected_services'](root,data['builds'],[pathlib.Path(p) for p in data['paths']])))",
      { builds, paths },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), expected, paths.join(', '));
  }
});

test('build inputs validate every copied Cargo member and reject a missing transitive owner', () => {
  const result = python(
    `inputs,targets=ns['docker_inputs'](root,'services/fact-service/Dockerfile')
ns['validate_cargo_inputs'](root,inputs,targets)
inputs=[p for p in inputs if p != pathlib.Path('services/pds')]
try: ns['validate_cargo_inputs'](root,inputs,targets)
except ValueError: print('rejected')
else: raise AssertionError('missing dependency accepted')`,
    {},
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'rejected\n');
});

test('locked builds reject omission of an unrelated workspace member before image dispatch', () => {
  const result = python(
    `inputs,targets=ns['docker_inputs'](root,'services/fleet-controller/Dockerfile')
inputs=[p for p in inputs if p != pathlib.Path('services/explorer-adapter')]
try: ns['validate_cargo_inputs'](root,inputs,targets)
except ValueError as error: assert 'locked workspace omits member' in str(error)
else: raise AssertionError('changed workspace lock accepted')`,
    {},
  );
  assert.equal(result.status, 0, result.stderr);
  const dispatch = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
openpc_validate_build_inputs() { return 96; }
compose=(probe) openpc_builder=owned
probe() { printf 'unexpected image dispatch'; }
if openpc_build_selected_images first; then exit 1; else exit $?; fi`,
  ]);
  assert.equal(dispatch.status, 96, dispatch.stderr);
  assert.equal(dispatch.stdout, '');
});

test('retained build refresh accepts context narrowing but rejects semantic drift and missing owners', () => {
  const result = python(
    `validate=ns['validate_refresh_build_inputs']
for path in ['services/fact-service/Dockerfile','services/fleet-controller/Dockerfile','services/module-registry/Dockerfile','services/control-api/Dockerfile']:
 after=(root/path).read_text()
 before=after.replace('COPY crates/ crates/','COPY services/non-cargo-fixture/ services/non-cargo-fixture/\\nCOPY crates/ crates/')
 validate(root,path,before,after)
 for bad in [after.replace('WORKDIR /workspace','WORKDIR /unsafe'),after.replace('ARG OPENPC_CARGO_BUILD_JOBS=1','ARG OPENPC_CARGO_BUILD_JOBS=9'),after.replace('COPY services/pds/ services/pds/\\n','')]:
  assert bad != after
  try: validate(root,path,before,bad)
  except ValueError: pass
  else: raise AssertionError('unsafe context change accepted')
after=(root/'.dockerignore').read_text()
before=after.replace('**/Dockerfile\\n','')
validate(root,'.dockerignore',before,after)
try: validate(root,'.dockerignore',before,after+'\\nservices/fact-service\\n')
except ValueError: pass
else: raise AssertionError('unsafe ignore change accepted')
print('checked')`,
    {},
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'checked\n');
});

test('image reuse requires the retained image ID and does not trust a stable tag', () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
openpc_build_services=(changed same stale missing)
refresh_services=(changed) compose=(probe)
probe() { printf '%s' "\${@: -1}"; }
openpc_image_tag() { printf '%s' "$1"; }
docker() {
  if [[ $1 == inspect ]]; then printf retained;
  elif [[ \${@: -1} == same ]]; then printf retained;
  elif [[ \${@: -1} == missing ]]; then return 1;
  else printf stale; fi
}
openpc_include_unverified_images
printf 'selected=%s\\n' "\${refresh_services[*]}"`,
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /selected=changed stale missing/);
  assert.doesNotMatch(result.stdout, /service=same/);
});

test('build inputs include deletion, staged and untracked inputs and fail conservatively on unknown context', async () => {
  for (const kind of ['deleted', 'staged', 'untracked', 'bind-mount', 'ignore-override']) {
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT, 'build-inputs-'));
    try {
      await mkdir(join(root, 'src'));
      await writeFile(join(root, 'src', 'original'), 'initial');
      await writeFile(join(root, '.dockerignore'), 'AGENTS.md\n');
      await writeFile(join(root, 'Dockerfile'), 'FROM scratch\nCOPY src/ /src/\n');
      for (const args of [
        ['init', '-q'],
        ['add', '.'],
        ['-c', 'user.name=Test', '-c', 'user.email=test@invalid', 'commit', '-qm', 'fixture'],
      ]) {
        const result = run('git', ['-C', root, ...args]);
        assert.equal(result.status, 0, result.stderr);
      }
      const revision = run('git', ['-C', root, 'rev-parse', 'HEAD']).stdout.trim();
      if (kind === 'deleted') await rm(join(root, 'src', 'original'));
      if (kind === 'untracked' || kind === 'staged') {
        await writeFile(join(root, 'src', 'added'), 'new');
        if (kind === 'staged') assert.equal(run('git', ['-C', root, 'add', '.']).status, 0);
      }
      if (kind === 'bind-mount')
        await writeFile(
          join(root, 'Dockerfile'),
          'FROM scratch\nRUN --mount=type=bind,source=other,target=/other true\n',
        );
      if (kind === 'ignore-override')
        await writeFile(join(root, 'Dockerfile.dockerignore'), '!AGENTS.md\n');
      const compose = {
        services: { first: { build: { context: root, dockerfile: 'Dockerfile' } } },
      };
      const result = run('python3', ['-B', selector, root, revision, 'first'], {
        input: JSON.stringify(compose),
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'first\n', kind);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test('build phase failure retains exit status and prevents downstream image builds', () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
openpc_validate_build_inputs() { return 0; }
compose=(probe) openpc_builder=owned
probe() { printf '%s\\n' "\${@: -1}"; return 17; }
if openpc_build_selected_images first second; then exit 1; else exit $?; fi`,
  ]);
  assert.equal(result.status, 17, result.stderr);
  assert.equal(result.stdout, 'first\n');
  assert.match(result.stderr, /name=build-first\|event=end\|status=17\|elapsed_ms=\d+/);
  assert.doesNotMatch(result.stderr, /build-second/);
});

test('admin-web contract preflight discovers the server tests once before every selected image', async () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD
openpc_validate_build_inputs() { return 0; }
compose=(probe) openpc_builder=owned
export OPENPC_POLICY_CORE_BIN=/owned/retained-policy-evaluator
export OPENPC_POLICY_UNKNOWN=forbidden
pnpm() {
  if [[ $3 == exec ]]; then
    [[ ! -v OPENPC_POLICY_CORE_BIN ]] || return 23
    [[ $OPENPC_POLICY_UNKNOWN == forbidden ]] || return 23
  fi
  printf 'preflight'; printf '|%s' "$@"; printf '\\n';
}
probe() { printf 'image=%s\\n' "\${@: -1}"; }
openpc_build_selected_images control-api admin-web identity-service
[[ $OPENPC_POLICY_CORE_BIN == /owned/retained-policy-evaluator ]]
[[ $OPENPC_POLICY_UNKNOWN == forbidden ]]`,
  ]);
  assert.equal(result.status, 0, result.stderr);
  const [typecheck, preflight, ...images] = result.stdout.trim().split('\n');
  const directory = join(process.cwd(), 'apps/admin-web');
  assert.deepEqual(typecheck.split('|'), ['preflight', '--dir', directory, 'check']);
  const owner = join(directory, 'app/api/v1/ui');
  const files = (await readdir(owner))
    .filter((name) => name.endsWith('.test.ts'))
    .sort()
    .map((name) => join(owner, name));
  assert.ok(files.length > 0);
  assert.ok(files.some((file) => file.endsWith('/local-transaction-workbench.test.ts')));
  assert.ok(files.some((file) => file.endsWith('/local-evidence-workbench.test.ts')));
  assert.deepEqual(preflight.split('|'), [
    'preflight',
    '--dir',
    directory,
    'exec',
    'vitest',
    'run',
    '--maxWorkers=1',
    '--environment',
    'node',
    '--config',
    'vitest.config.ts',
    ...files,
  ]);
  assert.deepEqual(images, ['image=control-api', 'image=admin-web', 'image=identity-service']);
  assert.match(result.stderr, /name=bff-preflight\|event=end\|status=0\|elapsed_ms=\d+/);
  assert.equal((result.stderr.match(/name=bff-preflight\|event=begin/g) ?? []).length, 1);
});

test('admin-web preflight failure blocks every image even under a conditional caller', () => {
  for (const failure of ['check', 'exec']) {
    const result = run('bash', [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD
openpc_validate_build_inputs() { return 0; }
compose=(probe) openpc_builder=owned
pnpm() { if [[ $3 == ${failure} ]]; then return 23; fi; }
probe() { printf 'unexpected image dispatch'; }
if openpc_build_selected_images control-api admin-web; then exit 1; else exit $?; fi`,
    ]);
    assert.equal(result.status, 23, result.stderr);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /name=bff-preflight\|event=end\|status=23/);
    assert.doesNotMatch(result.stderr, /name=build-/);
  }
});

test('non-web image selection pays no BFF preflight and empty discovery fails closed', () => {
  for (const web of [false, true]) {
    const result = run('bash', [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD/tests/integration/local-runtime
openpc_validate_build_inputs() { return 0; }
compose=(probe) openpc_builder=owned
pnpm() { printf 'unexpected preflight dispatch'; return 23; }
probe() { printf 'image=%s\\n' "\${@: -1}"; }
if openpc_build_selected_images control-api ${web ? 'admin-web' : 'identity-service'}; then exit 0; else exit $?; fi`,
    ]);
    assert.equal(result.status, web ? 96 : 0, result.stderr);
    assert.equal(result.stdout, web ? '' : 'image=control-api\nimage=identity-service\n');
    if (web) assert.match(result.stderr, /OPENPC_BFF_PREFLIGHT\|FAIL\|no-contract-tests/);
    else assert.doesNotMatch(result.stderr, /bff-preflight/);
  }
});

test('fixture preflight preserves failure even under a conditional caller', () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY=1
node() { return 19; }
if openpc_fixture_preflight; then exit 1; else exit $?; fi`,
  ]);
  assert.equal(result.status, 19, result.stderr);
  assert.match(result.stderr, /name=input-preflight\|event=end\|status=19/);
});

test('ordinary runtime dispatch runs fixture preflight before refresh and uses timed image builds', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  assert.ok(
    source.indexOf('\nopenpc_fixture_preflight\n') <
      source.indexOf('\n  openpc_refresh_visibility\n'),
  );
  assert.match(source, /openpc_build_selected_images "\$\{openpc_build_services\[@\]\}"/);
});

test('raw deletion input preflight blocks deployment dispatch and is absent from unrelated slices', () => {
  for (const enabled of [0, 1])
    for (const status of [0, 19]) {
      const result = run('bash', [
        '-c',
        `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY=${enabled}
openpc_receipt_contract_preflight() { return 0; }
node() { [[ "$*" == *evidence-raw-deletion-browser.mjs*--preflight* ]] || return 98; printf 'raw-input-check\\n'; return ${status}; }
if openpc_fixture_preflight; then printf 'runtime-dispatch\\n'; else exit $?; fi`,
      ]);
      assert.equal(result.status, enabled ? status : 0, result.stderr);
      if (enabled) assert.match(result.stdout, /raw-input-check/u);
      else assert.doesNotMatch(result.stdout, /raw-input-check/u);
      if (enabled && status) assert.doesNotMatch(result.stdout, /runtime-dispatch/u);
      else assert.match(result.stdout, /runtime-dispatch/u);
    }
});

test('projection deletion input preflight blocks first-policy dispatch and is absent from unrelated slices', () => {
  for (const enabled of [0, 1])
    for (const status of [0, 19]) {
      const result = run('bash', [
        '-c',
        `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=${enabled}
openpc_receipt_contract_preflight() { return 0; }
node() {
  case "$*" in
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs --preflight"|"--import tsx $repository_root/tests/integration/local-runtime/runtime-source-retirement-journey.mjs --preflight") return 0 ;;
  esac
  if [[ "$*" == *runner-boundary.test.mjs* ]]; then return 0; fi
  [[ "$*" == *evidence-projection-deletion-browser.mjs*--preflight* ]] || return 98
  printf 'projection-input-check\\n'; return ${status}
}
if openpc_fixture_preflight; then printf 'runtime-dispatch\\n'; else exit $?; fi`,
      ]);
      assert.equal(result.status, enabled ? status : 0, result.stderr);
      if (enabled) assert.match(result.stdout, /projection-input-check/u);
      else assert.doesNotMatch(result.stdout, /projection-input-check/u);
      if (enabled && status) assert.doesNotMatch(result.stdout, /runtime-dispatch/u);
      else assert.match(result.stdout, /runtime-dispatch/u);
    }
});

test('journal ABI preflight failure blocks later inputs and first-policy runtime dispatch', () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
# Retained admission has its own real owner/Compose boundary scenarios.
openpc_runtime_input_admission() { return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
openpc_receipt_contract_preflight() { return 0; }
node() {
  case "$*" in
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs --preflight"|"--import tsx $repository_root/tests/integration/local-runtime/runtime-source-retirement-journey.mjs --preflight") return 0 ;;
  esac
  [[ "$*" == *runner-boundary.test.mjs* ]] || return 98
  printf 'journal-abi-check\\n'; return 19
}
if openpc_fixture_preflight; then printf 'runtime-dispatch\\n'; else exit $?; fi`,
  ]);
  assert.equal(result.status, 19, result.stderr);
  assert.match(result.stdout, /journal-abi-check/u);
  assert.doesNotMatch(result.stdout, /runtime-dispatch/u);
});

test('first-policy preflight preserves each failed stage, closes timing and blocks dependent dispatch', () => {
  const stages = ['disposition', 'retirement', 'journal', 'projection', 'retention'];
  for (const [failure, status] of [
    ['disposition', 17],
    ['retirement', 23],
    ['journal', 19],
    ['projection', 29],
    ['retention', 31],
    ['none', 0],
  ]) {
    const result = run('bash', [
      '-c',
      `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_runtime_input_admission() { return 0; }
openpc_receipt_contract_preflight() { return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
node() {
  local stage
  case "$*" in
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs --preflight") stage=disposition ;;
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-retirement-journey.mjs --preflight") stage=retirement ;;
    "--test --test-name-pattern=journal fixture ABI|owned journal crash barrier|runtime source bootstrap|runtime source startup|runtime source original resume|source import fault $repository_root/tests/integration/local-runtime/runner-boundary.test.mjs") stage=journal ;;
    "--import tsx $repository_root/tests/integration/local-runtime/evidence-projection-deletion-browser.mjs --preflight") stage=projection ;;
    "--import tsx $repository_root/tests/integration/local-runtime/evidence-projection-deletion-browser.mjs --preflight 018f0000-0000-7000-8000-000000000101 018f0021-0000-7000-8000-000000000201 018f0000-0000-7000-8000-000000000201 bootstrap-evidence-retention-search") stage=retention ;;
    *) return 98 ;;
  esac
  printf '%s\\n' "$stage"
  if [[ "$stage" == ${failure} ]]; then return ${status}; fi
}
if openpc_fixture_preflight; then printf 'runtime-dispatch\\n'; else exit $?; fi`,
    ]);
    assert.equal(result.status, status, `${failure}: ${result.stderr}`);
    const expected =
      failure === 'none'
        ? [...stages, 'runtime-dispatch']
        : stages.slice(0, stages.indexOf(failure) + 1);
    assert.deepEqual(result.stdout.trim().split('\n'), expected, failure);
    assert.equal((result.stderr.match(/name=input-preflight\|event=begin/gu) ?? []).length, 1);
    assert.equal((result.stderr.match(/name=input-preflight\|event=end/gu) ?? []).length, 1);
    assert.match(
      result.stderr,
      new RegExp(`name=input-preflight\\|event=end\\|status=${status}\\|elapsed_ms=\\d+`, 'u'),
    );
  }
});

test('fixture preflight refuses a duplicate phase before any input dispatch', () => {
  const result = run('bash', [
    '-c',
    `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_runtime_input_admission() { return 0; }
openpc_receipt_contract_preflight() { printf 'unexpected-receipt\\n'; return 0; }
node() { printf 'unexpected-input\\n'; return 0; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
openpc_phase_started[input-preflight]=1
if openpc_fixture_preflight; then printf 'runtime-dispatch\\n'; else exit $?; fi`,
  ]);
  assert.equal(result.status, 96, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('runtime source preflight retains the original failure if timing closure also fails', () => {
  for (const [failedStage, status] of [
    ['disposition', 17],
    ['retirement', 23],
  ]) {
    for (const conditional of [false, true]) {
      const result = run('bash', [
        '-c',
        `set -euo pipefail
source tests/integration/local-runtime/runner-harness.sh
openpc_runtime_input_admission() { return 0; }
openpc_receipt_contract_preflight() { return 0; }
openpc_phase_end() { return 91; }
repository_root=$PWD OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
node() {
  local stage
  case "$*" in
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs --preflight") stage=disposition ;;
    "--import tsx $repository_root/tests/integration/local-runtime/runtime-source-retirement-journey.mjs --preflight") stage=retirement ;;
    *) return 98 ;;
  esac
  printf '%s\\n' "$stage"
  if [[ "$stage" == ${failedStage} ]]; then return ${status}; fi
}
${conditional ? 'if openpc_fixture_preflight; then printf "unexpected-dispatch\\n"; else exit $?; fi' : 'openpc_fixture_preflight; printf "unexpected-dispatch\\n"'}`,
      ]);
      assert.equal(result.status, status, `${failedStage}/${conditional}: ${result.stderr}`);
      assert.deepEqual(
        result.stdout.trim().split('\n'),
        failedStage === 'disposition' ? ['disposition'] : ['disposition', 'retirement'],
      );
    }
  }
});

test('raw fixture IDs retain UUID width before any database or credential allocation', () => {
  const result = run(process.execPath, [
    '--import',
    'tsx',
    'tests/integration/local-runtime/deployment-intent-actors.mjs',
    'must-not-read-secrets',
    'must-not-write-actors',
    '018f0000-0000-7000-8000-000000000101',
    'bootstrap-evidence-raw-deletion',
    '018f0000-0000-7000-8000-000000007201',
    '018f0000-0000-7000-8000-000000000201',
    '--preflight',
  ]);
  assert.equal(result.status, 0, result.stderr);
  const prepared = JSON.parse(result.stdout);
  assert.equal(
    prepared.entryAuthorities.maker.assignmentId,
    '018f0013-0000-7000-8000-000000000252',
  );
  assert.equal(
    prepared.entryAuthorities.checker.envelopeId,
    '018f0013-0000-7000-8000-000000000261',
  );
});
