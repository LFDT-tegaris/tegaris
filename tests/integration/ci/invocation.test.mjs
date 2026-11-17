import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import test from 'node:test';
import { orderIdentityEnvelopeSigningPrerequisite } from '../../../services/identity-service/src/db/identity-envelope-signing-upgrade.mjs';
import { orderQaSessionDurationUpgrade } from '../../../services/identity-service/src/db/qa-duration-profile-guards.mjs';

function readbackCleanupSource(runner) {
  const helperStart = runner.indexOf('openpc_readback_keep_failure_state() {');
  const start = helperStart >= 0 ? helperStart : runner.indexOf('cleanup() {');
  const end = runner.indexOf('\ntrap cleanup EXIT', start);
  assert(start > 0 && end > start);
  return runner.slice(start, end);
}

test('Root-expiry installation checks prerequisites before allocating its current-schema database', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  for (const file of [
    'tests/integration/identity/postgres-root-expiry-installation.test.ts',
    'tests/integration/identity/postgres-root-expiry-recovery.test.ts',
  ]) {
    assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
    const begin = runner.indexOf('case "${test_files[0]}" in');
    const finish = runner.indexOf('\nesac', begin) + 6;
    assert(begin > 0 && finish > begin && finish < runner.indexOf('\nroot=$(mktemp'));
    const preflight = runner.slice(begin, finish);
    const branchStart = preflight.indexOf('  ' + file + ')');
    const branchEnd = preflight.indexOf('\n    ;;', branchStart);
    assert(branchStart >= 0 && branchEnd > branchStart);
    const command = preflight
      .slice(branchStart, branchEnd)
      .split('\n')
      .find((line) => line.includes('pnpm exec vitest') && line.includes(file));
    assert(command);
    const selectedPattern = /--testNamePattern '([^']+)'/u.exec(command);
    assert(selectedPattern?.[1]);
    const selected = new RegExp(selectedPattern[1], 'u');
    const required = [
      ...(file.endsWith('/postgres-root-expiry-recovery.test.ts')
        ? [
            'authenticates finite Root recovery sources before database allocation',
            'signs finite Root recovery authenticator assertions for the real verifier',
          ]
        : []),
      'authenticates Root-expiry installation sources before allocating PostgreSQL',
      'binds Root-expiry installation to its owned database',
      'rejects Root-expiry installation target: foreign owner',
    ];
    assert.equal(required.filter((name) => selected.test(name)).length, required.length);
    assert(
      !selected.test(
        'recovers finite Root validity with real OIDC and independent authenticator proofs without adding permissions',
      ),
    );
    assert(
      !selected.test(
        'installs finite recovery trust after genuine Root expiry without granting authority and retains it after restart',
      ),
    );
    for (let failed = 0; failed <= 3; failed++) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
test_files=(${file})
calls=0
pnpm() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
${runner.slice(begin, finish)}
test "$calls" = 3
printf 'DATABASE_ALLOCATION_ALLOWED\\n'
`,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
      assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
    }
    const start = runner.indexOf(
      'if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-remote-upgrade.test.ts',
    );
    const end = runner.indexOf('\ndocker exec -i', start);
    assert(start > 0 && end > start);
    const root = await mkdtemp(
      join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'root-expiry-invocation-'),
    );
    try {
      for (const failed of [false, true]) {
        const selected = join(root, failed ? 'failure' : 'pass');
        await mkdir(selected);
        const result = spawnSync(
          'bash',
          [
            '-c',
            `set -euo pipefail
repo="$1"
root="$2"
container=owned-test-database
test_files=(${file})
docker() { printf '%s\\n' "$*"; return ${failed ? 23 : 0}; }
${runner.slice(start, end)}
printf 'CURRENT_SCHEMA_DISPATCH\\n'
`,
            'bash',
            root,
            selected,
          ],
          { encoding: 'utf8' },
        );
        assert.equal(result.status, failed ? 23 : 0, result.stderr);
        assert.equal(result.stdout.includes('CURRENT_SCHEMA_DISPATCH'), !failed);
        await assert.rejects(readFile(join(selected, 'predecessor/identity/0000_initial.sql')), {
          code: 'ENOENT',
        });
        const log = await readFile(join(selected, 'migrations.log'), 'utf8');
        assert.match(log, /exec .*owned-test-database sh \/local\/migrate\.sh control/u);
        assert(!log.includes('/predecessor:'));
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test('ordinary runtime CI runs the Root-expiry installation gate and stops on unresolved ownership', async () => {
  const source = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  for (const [label, file] of [
    [
      'root-expiry-installation',
      'tests/integration/identity/postgres-root-expiry-installation.test.ts',
    ],
    ['finite-root-recovery', 'tests/integration/identity/postgres-root-expiry-recovery.test.ts'],
  ]) {
    const step =
      '  suite_step ' +
      label +
      ' bash tests/integration/identity/run-participant-readback.sh ' +
      file;
    const start = source.indexOf(step),
      end = source.indexOf('\n  suite_step ', start + step.length);
    const helperStart = source.indexOf('  suite_step() {'),
      helperEnd = source.indexOf('  export OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE', helperStart);
    assert(start > 0 && end > start && helperStart > 0 && helperEnd > helperStart);
    for (const status of [0, 1, 99]) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
suite_status=0
suite_step_status=0
bash() { printf 'CHILD:%s\\n' "$*"; return ${status}; }
${source.slice(helperStart, helperEnd)}
${source.slice(start, end)}
printf 'NEXT_INDEPENDENT_PHASE\\n'
exit "$suite_status"
`,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, status === 0 ? 0 : 1, result.stderr);
      assert(
        result.stdout.includes(
          'CHILD:tests/integration/identity/run-participant-readback.sh ' + file,
        ),
      );
      assert.equal(result.stdout.includes('NEXT_INDEPENDENT_PHASE'), status !== 99);
    }
  }
});

const discoveryApprovalResumeFile =
  'tests/integration/identity/postgres-discovery-approval-resume.test.ts';

function discoveryApprovalResumeSelection(runner) {
  const start = runner.indexOf('test_files=(');
  const end = runner.indexOf('\ntest_filter=()', start);
  assert(start > 0 && end > start);
  return runner.slice(start, end);
}

function discoveryApprovalResumeMigration(runner) {
  const start = runner.indexOf('  control_mode=control\n');
  const end = runner.indexOf('\nfi\ndocker exec -i "$container" psql', start);
  assert(start > 0 && end > start);
  assert(end < runner.indexOf('export OPENPC_I02_ADMIN_DATABASE_URL='));
  return runner.slice(start, end);
}

function discoveryApprovalResumeDispatch(runner) {
  const start = runner.indexOf(
    'if [[ "${test_files[0]}" == tests/integration/local-runtime/control-installation.test.mjs ',
    runner.indexOf('export OPENPC_I02_ADMIN_DATABASE_URL='),
  );
  const end = runner.indexOf('\nfi\n# Initial trust verification', start);
  assert(start > 0 && end > start);
  return runner.slice(start, end + 4);
}

async function discoveryApprovalResumeScratch(t) {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'discovery-resume-invocation-'),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

// Execute the actual bounded runner branches with closed command stubs. These
// tests qualify invocation/setup only; they never allocate PostgreSQL or claim
// the five database cases passed.
test('Discovery approval RESUME selects installation-only setup without changing existing selectors', async (t) => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const root = await discoveryApprovalResumeScratch(t);
  for (const [file, mode] of [
    [discoveryApprovalResumeFile, 'control-installation'],
    ['tests/integration/local-runtime/control-installation.test.mjs', 'control-installation'],
    ['tests/integration/local-runtime/qa-sandbox-postgres.test.mjs', 'control-installation'],
    ['tests/integration/identity/postgres-recovery-journey.test.ts', 'control'],
    [discoveryApprovalResumeFile + '.bak', 'control'],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
root=$1
container=stub-discovery-postgres
test_files=("$2")
docker() {
  [[ "$*" == "exec -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE=openpc_control $container sh /local/migrate.sh "* ]] || return 97
  printf '%s\\n' "\${@: -1}"
}
${discoveryApprovalResumeMigration(runner)}
printf 'SETUP_COMPLETED\\n'
`,
        'discovery-resume-mode',
        root,
        file,
      ],
      { encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'SETUP_COMPLETED\n');
    assert.equal(await readFile(join(root, 'migrations.log'), 'utf8'), mode + '\n', file);
  }
});

test('Discovery approval RESUME focused dispatch selects exactly the existing five unconditional cases', async (t) => {
  const [runner, cases, config] = await Promise.all([
    readFile('tests/integration/identity/run-participant-readback.sh', 'utf8'),
    readFile(discoveryApprovalResumeFile, 'utf8'),
    readFile('tests/integration/identity/vitest.config.ts', 'utf8'),
  ]);
  const names = [...cases.matchAll(/^ {2}it\('([^']+)'/gmu)].map((match) => match[1]);
  assert.equal(names.length, 5);
  assert.equal(new Set(names).size, 5);
  assert.doesNotMatch(cases, /\bit\.(?:skip|todo|only|each|skipIf|runIf)\b/u);
  assert.match(config, /include: \['tests\/integration\/identity\/\*\*\/\*\.test\.ts'\]/u);
  const root = await discoveryApprovalResumeScratch(t);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
root=$1
shift
node() { return 97; }
${discoveryApprovalResumeSelection(runner)}
test_filter=()
pnpm() {
  [[ $# == 6 && "$*" == 'exec vitest run --config tests/integration/identity/vitest.config.ts ${discoveryApprovalResumeFile}' ]] || return 97
  printf 'SELECTED:%s\\n' "$6"
}
${discoveryApprovalResumeDispatch(runner)}
`,
      'discovery-resume-selection',
      root,
      discoveryApprovalResumeFile,
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `SELECTED:${discoveryApprovalResumeFile}\n`);
  assert.equal(await readFile(join(root, 'test.log'), 'utf8'), result.stdout);
});

test('Discovery approval RESUME ordinary CI includes its database file exactly once', async () => {
  // The actual default array is evaluated, rather than matching a filename in
  // an unrelated comment or an inactive branch.
  const [runner, ci, packageSource, compose] = await Promise.all([
    readFile('tests/integration/identity/run-participant-readback.sh', 'utf8'),
    readFile('.github/workflows/ci.yml', 'utf8'),
    readFile('package.json', 'utf8'),
    readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8'),
  ]);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
node() { return 97; }
${discoveryApprovalResumeSelection(runner)}
printf '%s\\n' "\${test_files[@]}"
`,
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.stdout.split('\n').filter((file) => file === discoveryApprovalResumeFile).length,
    1,
  );
  assert.match(ci, /pnpm run test:integration:runtime/u);
  assert.match(
    JSON.parse(packageSource).scripts['test:integration:runtime'],
    /run-compose-e2e\.sh --suite/u,
  );
  assert.match(
    compose,
    /suite_step identity bash tests\/integration\/identity\/run-participant-readback\.sh/u,
  );
});

test('Discovery approval RESUME failed execution admission prevents database allocation', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const start = runner.indexOf('openpc_require_execution database\n');
  const end = runner.indexOf('test_files=(', start);
  const allocation = runner.indexOf('docker run -d --name "$container"');
  assert(start > 0 && end > start && allocation > end);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
openpc_require_execution() { [[ "$*" == database ]] || return 97; return 75; }
${runner.slice(start, end)}
printf 'DATABASE_ALLOCATION_ALLOWED\\n'
`,
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(result.status, 75, result.stderr);
  assert.equal(result.stdout, '');
});

test('Discovery approval RESUME migration and empty-test failures remain nonzero before success', async (t) => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const root = await discoveryApprovalResumeScratch(t);
  const migration = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
root=$1
container=stub-discovery-postgres
test_files=('${discoveryApprovalResumeFile}')
test_filter=()
docker() { return 37; }
pnpm() { printf 'DATABASE_TEST_DISPATCHED\\n'; }
node() { return 97; }
${discoveryApprovalResumeMigration(runner)}
${discoveryApprovalResumeDispatch(runner)}
printf 'QUALIFICATION_COMPLETED\\n'
`,
      'discovery-resume-migration-failure',
      root,
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(migration.status, 37, migration.stderr);
  assert.equal(migration.stdout, '');
  // Model Vitest's required nonzero missing/zero-test result, not a fabricated
  // successful database report. The real pipeline must preserve that status.
  const empty = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
root=$1
test_files=('${discoveryApprovalResumeFile}')
test_filter=()
pnpm() { [[ $# == 6 ]] || return 97; return 1; }
node() { return 97; }
${discoveryApprovalResumeDispatch(runner)}
printf 'QUALIFICATION_COMPLETED\\n'
`,
      'discovery-resume-empty-selection',
      root,
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(empty.status, 1, empty.stderr);
  assert.equal(empty.stdout, '');
});

test('ordinary Identity CI selects the empty Control installation proof with its real database', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/local-runtime/control-installation.test.mjs';
  const selections = runner.slice(runner.indexOf('test_files=('), runner.indexOf('\n)'));
  assert.ok(selections.includes(file));
  assert.match(runner, /control_mode=control\n[\s\S]*control_mode=control-installation/u);
  assert.match(runner, /export OPENPC_CONTROL_INSTALLATION_TEST_CONTAINER="\$container"/u);
  assert.match(runner, /sh \/local\/migrate\.sh "\$control_mode" > "\$root\/migrations.log"/u);
  const dispatch = runner.indexOf('node --test "${test_files[0]}"');
  assert.ok(dispatch > runner.indexOf('control_mode=control-installation'));
  assert.ok(runner.slice(runner.lastIndexOf('if [[', dispatch), dispatch).includes(file));
});

test('ordinary Identity CI dispatches isolated QA fixture PostgreSQL proof without a business journey', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/local-runtime/qa-sandbox-postgres.test.mjs';
  assert.ok(runner.slice(runner.indexOf('test_files=('), runner.indexOf('\n)')).includes(file));
  const pure = runner.indexOf('node --test tests/integration/local-runtime/qa-sandbox.test.mjs');
  assert.ok(pure > 0 && pure < runner.indexOf('container=openpc-participant-readback-'));
  assert.match(
    runner,
    /qa-sandbox-postgres\.test\.mjs[^\n]*\n\s+control_mode=control-installation/u,
  );
  const dispatch = runner.indexOf('node --test "${test_files[0]}"');
  assert.ok(runner.slice(runner.lastIndexOf('if [[', dispatch), dispatch).includes(file));
});

test('failed envelope signing cleanup stops owned PostgreSQL and preserves original keys', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const cleanup = readbackCleanupSource(runner);
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'envelope-cleanup-'),
  );
  try {
    for (const outcome of ['failed', 'passed']) {
      const directory = join(root, outcome);
      await mkdir(join(directory, 'secrets'), { recursive: true });
      await writeFile(join(directory, 'secrets', 'original'), 'fixture-key');
      const result = spawnSync(
        'bash',
        [
          '-c',
          `
root=$1
created=1
container=owned-envelope-postgres
test_files=(tests/integration/identity/postgres-envelope-proposal.test.ts)
docker() {
  case "$1" in
    logs) return 0 ;;
    inspect) echo "$root" ;;
    ps) echo "$container" ;;
    stop) echo stop >> "$root/action" ;;
    rm) echo remove >> "$root/action" ;;
    *) return 91 ;;
  esac
}
${cleanup}
test "$2" = passed
cleanup
`,
          'envelope-cleanup',
          directory,
          outcome,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, outcome === 'failed' ? 1 : 0, result.stderr);
      if (outcome === 'failed') {
        assert.equal(await readFile(join(directory, 'secrets', 'original'), 'utf8'), 'fixture-key');
        assert.equal(await readFile(join(directory, 'action'), 'utf8'), 'stop\n');
      } else
        await assert.rejects(readFile(join(directory, 'secrets', 'original')), { code: 'ENOENT' });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('identity envelope migration orders only its exact generated key purpose prerequisite', () => {
  const create = 'CREATE TABLE "control"."identity_envelope_signing_grant" (x integer);';
  const column =
    'ALTER TABLE "control"."business_signing_key" ADD COLUMN "signing_purpose_code" smallint DEFAULT 338 NOT NULL;';
  const fk =
    'ALTER TABLE "control"."identity_envelope_signing_grant" ADD CONSTRAINT "identity_envelope_signing_grant_key_fk" FOREIGN KEY (x) REFERENCES key(x);';
  const unique =
    'ALTER TABLE "control"."business_signing_key" ADD CONSTRAINT "business_signing_key_purpose_uq" UNIQUE(x);';
  const original = [create, column, fk, unique].join('\n');
  const fixed = orderIdentityEnvelopeSigningPrerequisite(original);
  assert(fixed.indexOf(column) < fixed.indexOf(unique));
  assert(fixed.indexOf(unique) < fixed.indexOf(fk));
  assert.equal(orderIdentityEnvelopeSigningPrerequisite(fixed), fixed);
  assert.equal(
    orderIdentityEnvelopeSigningPrerequisite('unrelated migration'),
    'unrelated migration',
  );
  for (const invalid of [
    original.replace(column, ''),
    original.replace(unique, ''),
    original.replace(fk, ''),
    original + '\n' + unique,
  ])
    assert.throws(() => orderIdentityEnvelopeSigningPrerequisite(invalid), /Missing generated/u);
});

test('clean Control installation orders Discovery succession after its Identity tables and fails closed', async (t) => {
  const installer = await readFile('deploy/compose/local/migrate.sh', 'utf8');
  const start = installer.indexOf('    ensure_ledger\n', installer.indexOf('case "$mode" in'));
  const end = installer.indexOf('    if [ "$control_checks_reconciled" = 0 ];', start);
  assert(start > 0 && end > start);
  const root = await discoveryApprovalResumeScratch(t);
  for (const [owner, names] of [
    ['identity', ['0128_base', '0129_withdrawal', '0132_recovery', '0189_qa']],
    [
      'control-api',
      [
        '0004_remove',
        '0005_recreate',
        '0143_shared',
        '0192_withdrawal',
        '0196_base',
        '0197_runtime_discovery_credential_succession',
        '0198_smart_contract_discovery_integration',
        '0199_familiar_energizer',
        '0200_source_authentication_document_reuse',
        '0201_lush_black_widow',
        '0202_original_activation_worker_identity',
        '0203_demonic_celestials',
        '0204_expired_denial_hex_validation',
        '0205_expired_denial_issuance_ordinal',
        '0206_expired_denial_handover',
        '0207_expired_credential_denial_handover',
        '0208_public_operations_source_v1',
      ],
    ],
    ['policy', ['0000_yummy_plazm']],
  ]) {
    await mkdir(join(root, owner));
    for (const name of names) await writeFile(join(root, owner, name + '.sql'), name);
  }
  const phase = installer.slice(start, end).replaceAll('/migrations/postgres', '"$root"');
  for (const fail of [
    '',
    '0132_recovery.sql',
    '0197_runtime_discovery_credential_succession.sql',
    '0198_smart_contract_discovery_integration.sql',
    '0199_familiar_energizer.sql',
    '0200_source_authentication_document_reuse.sql',
    '0201_lush_black_widow.sql',
    '0202_original_activation_worker_identity.sql',
    '0203_demonic_celestials.sql',
    '0204_expired_denial_hex_validation.sql',
    '0205_expired_denial_issuance_ordinal.sql',
    '0206_expired_denial_handover.sql',
    '0207_expired_credential_denial_handover.sql',
    '0208_public_operations_source_v1.sql',
  ]) {
    const result = spawnSync(
      'sh',
      [
        '-c',
        `set -eu
root=$1
fail=$2
ensure_ledger() { :; }
ledger_digest() { sha256sum "$1" | cut -d ' ' -f 1; }
apply_file() {
  name=\${1##*/}
  printf 'IDENTITY|%s\\n' "$name"
  [ "$name" != "$fail" ] || return 79
}
apply_owned_file() {
  name=\${1##*/}
  printf 'CONTROL|%s\\n' "$name"
  [ "$name" != "$fail" ] || return 79
}
apply_control_recreation_pair() { printf 'CONTROL|pair\\n'; }
apply_control_shared_lifecycle_transition() { printf 'CONTROL|shared\\n'; }
${phase}
printf 'INSTALL_COMPLETED\\n'
`,
        'control-dependencies',
        root,
        fail,
      ],
      { encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.status, fail ? 79 : 0, result.stderr);
    const lines = result.stdout.trim().split('\n');
    const discovery = lines.indexOf('CONTROL|0197_runtime_discovery_credential_succession.sql');
    if (fail === '0132_recovery.sql') assert.equal(discovery, -1);
    else {
      assert(discovery > lines.indexOf('IDENTITY|0189_qa.sql'));
      assert.equal(
        lines.filter((line) => line === 'CONTROL|0197_runtime_discovery_credential_succession.sql')
          .length,
        1,
      );
      assert(
        lines.indexOf('CONTROL|0192_withdrawal.sql') <
          lines.indexOf('IDENTITY|0129_withdrawal.sql'),
      );
    }
    const updates = [
      '0198_smart_contract_discovery_integration.sql',
      '0199_familiar_energizer.sql',
      '0200_source_authentication_document_reuse.sql',
      '0201_lush_black_widow.sql',
      '0202_original_activation_worker_identity.sql',
      '0203_demonic_celestials.sql',
      '0204_expired_denial_hex_validation.sql',
      '0205_expired_denial_issuance_ordinal.sql',
      '0206_expired_denial_handover.sql',
      '0207_expired_credential_denial_handover.sql',
      '0208_public_operations_source_v1.sql',
    ];
    let predecessor = discovery;
    for (const [index, name] of updates.entries()) {
      const update = lines.indexOf(`CONTROL|${name}`);
      const earlierFailure =
        fail === '0132_recovery.sql' ||
        fail === '0197_runtime_discovery_credential_succession.sql' ||
        updates.slice(0, index).includes(fail);
      if (earlierFailure) assert.equal(update, -1);
      else {
        assert(update > predecessor);
        assert.equal(lines.filter((line) => line === `CONTROL|${name}`).length, 1);
      }
      predecessor = update;
    }
    assert.equal(lines.includes('INSTALL_COMPLETED'), !fail);
  }
});

test('session duration migration classifies exact legacy metadata before checks without changing expiry', () => {
  const columns = ['duration_profile', 'idle_timeout_ms', 'absolute_timeout_ms'].map(
    (name) => `ALTER TABLE "control"."session" ADD COLUMN "${name}" text;`,
  );
  const boundary =
    'ALTER TABLE "control"."session" ADD CONSTRAINT "session_duration_profile_ck" CHECK (true);';
  const original = [...columns, boundary].join('\n');
  const fixed = orderQaSessionDurationUpgrade(original);
  assert(fixed.indexOf('UPDATE "control"."session"') > fixed.indexOf(columns[2]));
  assert(fixed.indexOf('UPDATE "control"."session"') < fixed.indexOf(boundary));
  assert.equal(orderQaSessionDurationUpgrade(fixed), fixed);
  assert.equal(orderQaSessionDurationUpgrade('unrelated migration'), 'unrelated migration');
  const update = fixed.slice(
    fixed.indexOf('UPDATE "control"."session"'),
    fixed.indexOf(';', fixed.indexOf('UPDATE "control"."session"')),
  );
  const [set, where] = update.split('WHERE');
  assert.match(where, /"absolute_expires_at"="issued_at"\+interval '24 hours'/u);
  assert.match(where, /"idle_expires_at"=least/u);
  for (const field of [
    'idle_expires_at',
    'absolute_expires_at',
    'issued_at',
    'last_seen_at',
    'session_epoch',
    'state',
  ])
    assert.equal(set.includes(field), false);
  for (const invalid of [
    original.replace(columns[1], ''),
    original.replace(columns[2], ''),
    original.replace(boundary, ''),
    original + '\n' + boundary,
  ])
    assert.throws(
      () => orderQaSessionDurationUpgrade(invalid),
      /Missing generated session duration/u,
    );
});

test('envelope native invocation rejects failure and zero selection', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const start = runner.indexOf('if [ "$envelope_activation_interop" = 1 ]; then\n  test -s');
  const end = runner.indexOf('\nfi', start) + 3;
  assert(start > 0 && end > start);
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'envelope-native-dispatch-'),
  );
  try {
    await writeFile(join(root, 'fixture.json'), '{}');
    for (const outcome of ['pass', 'empty', 'fail']) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
root=$1
envelope_activation_interop=1
export OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE="$root/fixture.json"
cargo() {
  if [ "$2" = ignored ]; then return 95; fi
  case "$native_outcome" in
    pass) echo 'test identity_envelope::tests::postgres_envelope_activation_original_wire ... ok' ;;
    empty) echo 'running 0 tests' ;;
    fail) return 19 ;;
  esac
}
native_outcome=$2
${runner.slice(start, end)}
`,
          'envelope-native',
          root,
          outcome,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status === 0, outcome === 'pass', result.stderr);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

const [workflow, packageDocument, postgresPolicyRunner, composeRunner] = await Promise.all([
  readFile('.github/workflows/ci.yml', 'utf8'),
  readFile('package.json', 'utf8').then((source) => JSON.parse(source)),
  readFile('tests/integration/policy/run-postgres18-trace-owner-proof.sh', 'utf8'),
  readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8'),
]);

test('workload rotation requires its certificate preflight before any database allocation', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-workload-certificate-rotation.test.ts';
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  assert(
    composeRunner.includes(
      'suite_step identity bash tests/integration/identity/run-participant-readback.sh',
    ),
  );
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + 6;
  const allocation = runner.indexOf('\nroot=$(mktemp -d "$scratch_parent/participant-readback.');
  assert(begin > 0 && end > begin && allocation > end);
  const branch = runner.slice(begin, end);
  for (const mode of ['pass', 'types-fail', 'certificate-fail']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
test_files=("$1")
mode=$2
pnpm() {
  if [[ "$1 $2" == 'exec tsc' ]]; then
    [[ " $* " == *' tests/integration/identity/postgres-workload-certificate-rotation.test.ts '* ]] || return 96
    printf 'TYPES\\n'
    [[ "$mode" != types-fail ]] || return 47
  elif [[ "$1 $2 $3" == 'exec vitest run' ]]; then
    [[ " $* " == *' --testNamePattern ^authenticates independent expired and current workload fixture certificates before database allocation$ '* ]] || return 96
    printf 'CERTIFICATES\\n'
    [[ "$mode" != certificate-fail ]] || return 48
  else
    return 96
  fi
}
${branch}
printf 'DATABASE_ALLOCATION_REACHED\\n'
`,
        'workload-preflight',
        file,
        mode,
      ],
      { encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(
      result.status,
      mode === 'pass' ? 0 : mode === 'types-fail' ? 47 : 48,
      result.stderr,
    );
    assert.equal(
      result.stdout,
      mode === 'pass'
        ? 'TYPES\nCERTIFICATES\nDATABASE_ALLOCATION_REACHED\n'
        : mode === 'types-fail'
          ? 'TYPES\n'
          : 'TYPES\nCERTIFICATES\n',
    );
  }
});

test('ordinary CI explicitly runs the populated envelope proposal lifecycle and rejects failed prerequisites', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-envelope-proposal.test.ts';
  assert(
    composeRunner.includes(
      'suite_step identity bash tests/integration/identity/run-participant-readback.sh',
    ),
  );
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  assert(
    runner.includes(
      'bash "$repo/tests/integration/identity/run-participant-readback.sh" "$test_file"',
    ),
  );
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const finish = runner.indexOf('\nesac', begin) + 6;
  const start = runner.indexOf(`  ${file})`);
  const end = runner.indexOf('\n    ;;', start);
  assert(start > 0 && end > start && end < runner.indexOf('root=$(mktemp'));
  assert.match(
    runner.slice(start, end),
    /--testNamePattern 'authenticates envelope lifecycle installation inputs'/u,
  );
  assert.match(runner, /lane == identity && \$\{name%%_\*\} > 0106/u);
  assert.match(runner, /export OPENPC_ENVELOPE_PROPOSAL_CONTAINER="\$container"/u);
  const compile = runner.indexOf('cargo test -p pc-policy-core --lib --locked --offline --no-run');
  const allocation = runner.indexOf('docker run -d --name "$container"');
  const source = runner.indexOf(
    'pnpm exec vitest run --config tests/integration/identity/vitest.config.ts "${test_files[@]}"',
  );
  const consume = runner.indexOf(
    'identity_envelope::tests::postgres_envelope_activation_original_wire -- --exact --include-ignored',
  );
  assert(compile > 0 && compile < allocation && source > allocation && consume > source);
  for (let failed = 0; failed <= 3; failed++) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${file})
      calls=0
      check() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
      pnpm() { check; }
      node() { check; }
      ${runner.slice(begin, finish)}
      test "$calls" = 3
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('ordinary identity CI invokes populated envelope purpose upgrade after exact preflight', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-identity-envelope-signing.test.ts';
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const start = runner.indexOf(`  ${file})`);
  const end = runner.indexOf('\n    ;;', start);
  assert(start > 0 && end > start && end < runner.indexOf('root=$(mktemp'));
  const preflight = runner.slice(start, end);
  assert.match(preflight, /tsc --ignoreConfig[^\n]+postgres-identity-envelope-signing\.test\.ts/u);
  assert.match(preflight, /generate:check/u);
  assert.match(preflight, /src\/identity-envelope\/signing-trust\.test\.ts/u);
  assert.match(runner, /lane == identity && \$\{name%%_\*\} > 0104/u);
  assert.match(runner, /export OPENPC_IDENTITY_ENVELOPE_UPGRADE_CONTAINER="\$container"/u);
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const finish = runner.indexOf('\nesac', begin) + '\nesac'.length;
  for (let failed = 0; failed <= 3; failed++) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${file})
      calls=0
      pnpm() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
      ${runner.slice(begin, finish)}
      test "$calls" = 3
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('ordinary identity CI denies Platform scope database allocation on any failed prerequisite', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-platform-envelope-scope.test.ts';
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const start = runner.indexOf(`  ${file})`),
    end = runner.indexOf('\n    ;;', start);
  assert(start > 0 && end > start && end < runner.indexOf('root=$(mktemp'));
  const selected = runner.slice(start, end);
  assert.match(selected, /tsc --ignoreConfig[^\n]+postgres-platform-envelope-scope\.test\.ts/u);
  assert.match(selected, /src\/identity-envelope\/platform-scope\.test\.ts/u);
  assert.match(selected, /--testNamePattern 'authenticates Platform installation sources'/u);
  assert.match(runner, /export OPENPC_PLATFORM_SCOPE_CONTAINER="\$container"/u);
  assert.match(runner, /lane == identity && \$\{name%%_\*\} > 0105/u);
  const begin = runner.indexOf('case "${test_files[0]}" in'),
    finish = runner.indexOf('\nesac', begin) + 6;
  for (let failed = 0; failed <= 3; failed++) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${file})
      calls=0
      pnpm() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
      ${runner.slice(begin, finish)}
      test "$calls" = 3
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('public CI validates source without fetching a private predecessor', () => {
  const jobs = workflow.split(/\n {2}(?:quality|runtime-integration):\n/u).slice(1);
  assert.equal(jobs.length, 2);
  for (const job of jobs) {
    assert(job.includes('actions/checkout'));
    assert(!job.includes('git fetch'));
    const browserInstall = job.indexOf('pnpm exec playwright install --with-deps chromium');
    const dependentCheck = job.indexOf(
      job.includes('name: Quality checks')
        ? 'name: Quality checks'
        : 'pnpm run test:integration:runtime',
    );
    assert(browserInstall > 0 && dependentCheck > browserInstall);
  }
  const entry = packageDocument.scripts['test:integration:runtime'];
  assert.equal(
    entry,
    'bash scripts/maintenance/run-project.sh --profile runtime -- bash tests/integration/local-runtime/run-compose-e2e.sh --suite',
  );
  assert(!composeRunner.includes('runtime-source-predecessor-journey.mjs'));
});

test('public runtime integration propagates admission failure', () => {
  const entry = packageDocument.scripts['test:integration:runtime'];
  for (const status of [0, 75]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `
set -euo pipefail
bash() {
  [[ "$*" == *"--profile runtime -- bash tests/integration/local-runtime/run-compose-e2e.sh --suite"* ]] || return 96
  printf 'runtime\\n'
  return ${status}
}
${entry}
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, status);
    assert.equal(result.stdout, 'runtime\n');
  }
});

test('ordinary CI invokes portable profile authentication and both focused recovery admissions', async () => {
  const command = packageDocument.scripts['test:unit'];
  assert.ok(
    command.includes(
      'node --test tests/recovery/profile-authentication.test.mjs tests/recovery/profile-authentication-package.test.mjs || status=1;',
    ),
  );
  assert.ok(
    command.includes(
      'node --test tests/recovery/recovery-result.test.mjs tests/recovery/recovery-package.test.mjs || status=1;',
    ),
  );
  assert.doesNotMatch(command, /tests\/system\/[^;]*release-evidence/u);
  const source = await readFile('tests/recovery/recovery-result.test.mjs', 'utf8');
  assert(!source.includes('artifacts/release-candidate'));
  const names = [...source.matchAll(/test\('([^']+)'/gu)].map((match) => match[1]);
  assert.deepEqual(names, [
    'recovery admission rejects status-only substitution and isolated mutations',
    'current recovery row, consumer and release admission reject legacy cache results and unsafe overrides',
  ]);
});

test('ordinary CI keeps retained-input admission in both shared dispatch owners', async () => {
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --test [^;]*tests\/integration\/local-runtime\/qa-sandbox\.test\.mjs/u,
  );
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --test [^;]*tests\/integration\/local-runtime\/runner-boundary\.test\.mjs[^;]*tests\/integration\/local-runtime\/build-inputs\.test\.mjs/u,
  );
  const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  for (const name of ['openpc_build_selected_images', 'openpc_fixture_preflight']) {
    const body = harness.slice(harness.indexOf(`${name}() {`)).split('\n}')[0];
    assert.match(body, /openpc_runtime_input_admission \|\| return/u);
    const callbacks = ['openpc_validate_build_inputs', 'openpc_phase_begin'];
    for (const callback of callbacks) {
      if (body.includes(callback))
        assert.ok(body.indexOf('openpc_runtime_input_admission') < body.indexOf(callback));
    }
  }
});

test('ordinary CI invokes signed site input regressions and canonical security profile checks', async () => {
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --import tsx --test [^;]*scripts\/operations\/installation-config\.test\.mjs/u,
  );
  assert.match(
    packageDocument.scripts['test:unit'],
    /pnpm -r --no-bail --workspace-concurrency=1/u,
  );
  const security = JSON.parse(await readFile('packages/security-kernel/package.json', 'utf8'));
  assert.match(security.scripts.test, /generate-business-transition\.mjs --check && vitest run/u);
});

test('ordinary PostgreSQL CI invokes operations generation denial and connected signed-input preflight', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.match(
    runner,
    /test_files=\([\s\S]*?tests\/integration\/identity\/postgres-operations-generation\.test\.ts[\s\S]*?\n\)/u,
  );
  const start = runner.indexOf(
    'tests/integration/identity/postgres-operations-generation.test.ts)',
  );
  const end = runner.indexOf('\n    ;;', start);
  assert.ok(start > 0 && end > start && end < runner.search(/^root="?\$\(mktemp/mu));
  const preflight = runner.slice(start, end);
  assert.match(preflight, /tsc --ignoreConfig --noEmit/u);
  assert.match(preflight, /generate:check/u);
  assert.match(preflight, /site-document\.test\.ts/u);
  assert.match(preflight, /secret-resolution\.test\.ts/u);
  assert.match(preflight, /qualification-wire\.test\.ts/u);
  assert.match(preflight, /provider-retry-qualification\.test\.ts/u);
  assert.match(preflight, /notification-async\.test\.ts/u);
  assert.match(preflight, /src\/operations-configuration\/provider-retry-input\.test\.ts/u);
  assert.match(preflight, /postgres-operations-provider-retry-input\.test\.ts/u);
  assert.match(
    runner.slice(runner.indexOf('export OPENPC_I02_ADMIN_DATABASE_URL')),
    /postgres-operations-provider-retry-input\.test\.ts \| tee/u,
  );
  assert.match(preflight, /postgres-operations-provider-retry-probe-source\.test\.ts/u);
  assert.match(
    preflight,
    /rejects incomplete, mixed-format and caller-eligibility probe source references before PostgreSQL/u,
  );
  assert.match(
    runner.slice(runner.indexOf('export OPENPC_I02_ADMIN_DATABASE_URL')),
    /--testNamePattern '\^denies probe read-action writes under composed installed policies\$'/u,
  );
  assert.match(
    runner.slice(runner.indexOf('export OPENPC_I02_ADMIN_DATABASE_URL')),
    /--testNamePattern '\^verifies installed async trust on the actual scoped transaction without granting qualification\$'/u,
  );
  assert.match(preflight, /rejects missing authority\/executed-input fixture/u);
  assert.match(preflight, /installation-config\.test\.mjs/u);
  assert.match(preflight, /installation-effective-projection\.test\.mjs/u);
  assert.match(preflight, /postgres-operations-secret-binding\.test\.ts/u);
  assert.ok(
    runner
      .slice(0, runner.indexOf('if [ "$#"'))
      .includes('tests/integration/identity/postgres-operations-secret-binding.test.ts'),
  );

  assert.match(
    preflight,
    /validates actual signed operations generation inputs before PostgreSQL allocation/u,
  );
  const tail = await readFile(
    'services/control-api/src/configuration/generate-security-tail.mjs',
    'utf8',
  );
  assert.ok(
    tail.indexOf('${providerRetryQualificationRolesSql}') <
      tail.indexOf('${operationsGenerationGuardsSql}'),
  );
  assert.ok(
    tail.indexOf('${providerRetryQualificationGuardsSql}') <
      tail.indexOf('${operationsGenerationGuardsSql}'),
  );
});

test('notification runtime fault cases use independent governed exports behind real admission', async () => {
  const caller = await readFile('tests/integration/identity/postgres-evidence-kms.test.ts', 'utf8');
  const module = await readFile(
    'tests/integration/identity/notification-delivery-runtime-cases.ts',
    'utf8',
  );
  assert.match(caller, /from '\.\/notification-delivery-runtime-cases\.js'/u);
  assert.ok(
    caller.indexOf('await requireNotificationProducerGeneration(') <
      caller.indexOf("streamId: 'notification-runtime-authentication'"),
  );
  assert.match(caller, /await prepareExports\(\s*runtimeScope,/u);
  assert.match(caller, /await prepareProducerSource\(runtimeExports\[index\]!/u);
  assert.match(caller, /exerciseNotificationDeliveryRuntimeCase\(kind,/u);
  for (const name of [
    'SQL_DRAIN',
    'RECIPIENT_DRAIN',
    'START_SIGNING_UNKNOWN',
    'OUTCOME_SIGNING_UNKNOWN',
    'CONCURRENT_START',
  ]) {
    assert.ok(caller.includes(`'${name}'`));
    assert.ok(module.includes(`case '${name}'`));
  }
  assert.match(caller, /await occurrenceCases\.reopen\(\)/u);
  assert.match(
    caller,
    /Notification runtime \$\{kind\} failed; dependent preparation\/publication\/readback blocked/u,
  );
});

test('RPC retirement preflight includes distinct denial and admitted proof contracts', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const start = runner.indexOf(
    'if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-projection-deletion.test.ts ]]',
  );
  const end = runner.indexOf('\n    fi', start);
  assert.ok(start > 0 && end > start && end < runner.search(/^root="?\$\(mktemp/mu));
  assert.match(runner.slice(start, end), /rpc-search-retirement\.test\.ts/u);
  assert.match(runner.slice(start, end), /rpc-retirement\.test\.ts/u);
});

test('CI executes JavaScript tests and the real runtime integration owner', () => {
  assert.match(workflow, /pnpm run test(?:\s|$)/);
  assert.match(workflow, /pnpm run test:integration:runtime(?:\s|$)/);
  assert.match(workflow, /OPENPC_LOCAL_RUNTIME_TMP_ROOT=\$RUNNER_TEMP\/openpc-local-runtime/);
  for (const file of [
    'rpc-journal-enospc-runtime',
    'evidence-provenance-browser',
    'work-item-browser',
    'work-item-actor-bootstrap',
    'fact-secret-consumer-installation',
    'notification-credential-provider-fixture',
    'notification-browser',
    'rpc-retirement-signing',
    'fixture-certificate',
  ]) {
    assert.ok(packageDocument.scripts['test:unit'].includes(`node --import tsx --test `));
    assert.match(
      packageDocument.scripts['test:unit'],
      new RegExp(
        `node --import tsx --test [^;]*tests/integration/local-runtime/${file}\\.test\\.mjs`,
      ),
    );
  }
  assert.match(
    composeRunner,
    /cargo test -p openpc-fleet-controller --test ads_transport --locked -- --include-ignored/,
  );
});

test('ordinary unit CI invokes packaged notification contracts without claiming the separate PG gate', () => {
  const preflight = composeRunner.indexOf('notification-packaged-browser.mjs" preflight-source');
  assert.ok(preflight > 0 && preflight < composeRunner.indexOf('mktemp -d'));
  assert.ok(
    packageDocument.scripts['test:unit'].includes(
      'node --import tsx --test --test-skip-pattern="^PG:" tests/integration/local-runtime/notification-packaged-runtime.test.mjs tests/integration/local-runtime/notification-runtime-bootstrap.test.mjs tests/integration/local-runtime/notification-packaged-inputs.test.mjs || status=1',
    ),
  );
  assert.ok(
    packageDocument.scripts['test:unit'].includes(
      'node --import tsx --test --test-skip-pattern="^RUNTIME:" tests/integration/local-runtime/notification-packaged-browser.test.mjs || status=1',
    ),
  );
});

test('ordinary runtime CI dispatches fresh C1 before the module lifecycle', () => {
  assert.match(workflow, /pnpm run test:integration:runtime(?:\s|$)/);
  const dispatch =
    'suite_step fact-secret-consumer env OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY=1 bash "$0"';
  const start = composeRunner.indexOf(dispatch);
  const module = composeRunner.indexOf('suite_step module-lifecycle');
  assert.ok(start > 0 && module > start);
  assert.ok(composeRunner.slice(start, module).includes('[[ $suite_step_status == 0 ]] || exit 1'));
  assert.ok(
    packageDocument.scripts['test:unit'].includes(
      'tests/integration/local-runtime/fact-secret-consumer-installation.test.mjs',
    ),
  );
  assert.ok(
    packageDocument.scripts['test:unit'].includes(
      'tests/integration/local-runtime/runner-boundary.test.mjs',
    ),
  );
});

test('ordinary CI and resource guard invoke the packaged Kubernetes materializer', () => {
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --import tsx --test [^;]*tests\/recovery\/kubernetes-materialization\.test\.mjs/,
  );
  assert.equal(
    packageDocument.scripts['materialize:kubernetes'],
    'bash scripts/maintenance/run-project.sh -- node --import tsx scripts/operations/kubernetes-materialize.mjs',
  );
  assert.match(workflow, /pnpm run test(?:\s|$)/);
});

test('work-item runtime dispatch requires signing trust and isolated actors before the browser', () => {
  const start = composeRunner.indexOf(
    'if [[ ${OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY:-0} == 1 ]]; then\n',
  );
  const end = composeRunner.indexOf('\nfi', start);
  assert.ok(start > 0 && end > start);
  assert.match(
    composeRunner,
    /suite_step work-items env OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY=1/,
  );
  const block = composeRunner.slice(start, end + 3);
  for (const failure of ['', 'business-signing-bootstrap.mjs', 'deployment-intent-actors.mjs']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY=1
secret_root=/owned/secrets
evidence_root=/owned/evidence
participant_id=participant
privacy_domain_id=privacy
mkdir() { :; }
openpc_compose_json() { printf '[]'; }
node() {
  printf '%s\\n' "$*"
  if [[ -n $FAILED && $* == *"$FAILED"* ]]; then return 17; fi
}
${block}
`,
      ],
      { encoding: 'utf8', env: { ...process.env, FAILED: failure } },
    );
    assert.equal(result.status, failure ? 17 : 0, result.stderr);
    assert.equal(result.stdout.includes('work-item-browser.mjs'), !failure);
    if (!failure)
      assert.match(
        result.stdout,
        /deployment-intent-actors\.mjs \/owned\/secrets \/owned\/evidence\/work-item-browser participant bootstrap-work-items privacy/u,
      );
  }
});

test('ordinary evidence export dispatch reaches remote browser and blocks dependents on failure', () => {
  const needle = '  node --import tsx tests/integration/local-runtime/evidence-browser.mjs';
  const start = composeRunner.indexOf(needle);
  const end = composeRunner.indexOf('\nfi', start);
  assert.ok(start > 0 && end > start);
  const dispatch = composeRunner.slice(start, end);
  for (const failed of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
secret_root=/owned/secrets
evidence_root=/owned/evidence
data_root=/owned/data
participant_id=owned-participant
privacy_domain_id=owned-privacy
compose=(docker compose)
openpc_compose_json() { printf '[]'; }
node() {
  if [[ $1 == -e ]]; then printf '[]'; return; fi
  printf '%s\\n' "$*"
  if [[ $* == *' --remote' ]]; then return ${failed ? 17 : 0}; fi
}
${dispatch}
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 17 : 0, result.stderr);
    assert.match(result.stdout, /evidence-browser\.mjs[^\n]+ --remote/u);
    assert.equal(result.stdout.includes('evidence-protected-browser.mjs'), !failed);
  }
  const preflight = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/evidence-browser.mjs',
      '--preflight',
      '--remote',
    ],
    { encoding: 'utf8' },
  );
  assert.equal(preflight.status, 0, preflight.stderr);
  assert.match(preflight.stdout, /OPENPC_EVIDENCE_EXPORT_PREFLIGHT\|PASS/u);
});

test('ordinary runtime CI dispatches clean first-policy RPC and stops on a failed journey', () => {
  assert.match(
    composeRunner,
    /suite_step first-policy-rpc env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 bash "\$0"/u,
  );
  const needle = '  source tests/integration/local-runtime/first-policy-journey.sh';
  const start = composeRunner.lastIndexOf('\nif [[ ', composeRunner.indexOf(needle));
  const end = composeRunner.indexOf('\nfi', start) + 3;
  assert.ok(start > 0 && end > start);
  assert.ok(end < composeRunner.indexOf('INSERT INTO control.policy('));
  const dispatch = composeRunner.slice(start, end);
  for (const failed of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      export OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
      source() { printf 'journey-dispatch\\n'; return ${failed ? 19 : 0}; }
      ${dispatch}
      printf 'historical-seed-dispatch\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 19 : 0, result.stderr);
    assert.match(result.stdout, /journey-dispatch/u);
    assert.doesNotMatch(result.stdout, /historical-seed-dispatch/u);
    assert.equal(result.stdout.includes('OPENPC_FIRST_POLICY_RPC|PASS'), !failed);
  }
});

test('ordinary PostgreSQL runner reaches joined endpoint verification through its connected preflight', async () => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const testFile = 'tests/integration/identity/postgres-notification-endpoint-journey.test.ts';
  assert.ok(
    source.slice(source.indexOf('test_files=('), source.indexOf('if [ "$#"')).includes(testFile),
  );
  const start = source.indexOf('  tests/integration/identity/postgres-notification-*.test.ts|');
  const preflight = source.slice(start, source.indexOf('    ;;', start));
  assert.ok(start > 0 && start < source.indexOf('scratch_parent='));
  for (const required of [
    'delivery-start-contract.test.ts',
    'notification-gateway/worker-contract.test.ts',
    'notification-verification-contract.test.ts',
    'endpoint-admission.test.ts',
    'endpoint-verification-state.test.ts',
    'endpoint-verification-provider.test.ts',
    'endpoint-repository.test.ts',
    'endpoint-verification-workflow.test.ts',
    'endpoint-verification-runtime.test.ts',
    'endpoint-http.test.ts',
    'notification-secret-recipient.test.ts',
    'notification-credential-material.test.ts',
    'notification-workload-transport.test.ts',
  ])
    assert.ok(preflight.includes(required), required);
  const begin = source.indexOf('case "${test_files[0]}" in');
  const end = source.indexOf('\nesac', begin) + '\nesac'.length;
  assert.ok(begin > 0 && end > begin && end < source.indexOf('docker run -d'));
  for (const failed of [0, 1, 2, 3, 4, 5, 6]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
test_files=("$1")
calls=0
check() { calls=$((calls+1)); if [[ $calls == ${failed} ]]; then return 19; fi; }
node() { check; }
pnpm() { check; }
${source.slice(begin, end)}
printf 'DATABASE_ALLOCATION_ALLOWED\\n'
`,
        'notification-preflight',
        testFile,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('ordinary PostgreSQL CI reaches completion-worker cryptographic preflight before database allocation', async () => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-notification-completion-worker.test.ts';
  assert.ok(
    source.slice(source.indexOf('test_files=('), source.indexOf('if [ "$#"')).includes(file),
  );
  const begin = source.indexOf(`  ${file})`),
    end = source.indexOf('\n    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < source.indexOf('scratch_parent='));
  const selected = source.slice(begin, end);
  for (const check of [
    'tsc --noEmit',
    'completion-worker-installation-contract.test.ts',
    'completion-worker-installation-guards.test.ts',
    'completion-worker-installation.test.ts',
    'completion-disposition-registration.test.ts',
    'notification-gateway/codec.test.ts',
    'notification-gateway/completion-worker-contract.test.ts',
  ]) {
    assert.ok(selected.includes(check), check);
  }
  const selection = source.slice(
    source.indexOf('for test_file in'),
    source.indexOf('scratch_parent='),
  );
  assert.ok(selection.includes('postgres-evidence-kms.test.ts'));
  assert.ok(selection.includes('notification_completion_bridge=1'));
  const bridge = source.slice(source.indexOf('if [ "$notification_completion_bridge" = 1 ]; then'));
  assert.ok(
    bridge
      .slice(0, bridge.indexOf('\nfi'))
      .includes('OPENPC_NOTIFICATION_COMPLETION_TEST_KEY_FILE'),
  );
});

test('ordinary PostgreSQL CI reaches target disposition denial and schema preflight', async () => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-target-disposition.test.ts';
  assert.ok(
    source.slice(source.indexOf('test_files=('), source.indexOf('if [ "$#"')).includes(file),
  );
  const begin = source.indexOf(`  ${file})`),
    end = source.indexOf('\n    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < source.indexOf('scratch_parent='));
  assert.ok(source.slice(begin, end).includes(`tsc --noEmit`));
  assert.ok(source.slice(begin, end).includes(file));
  assert.match(source, /target_issuance_interop=1/);
  assert.match(
    source,
    /\[ "\$target_issuance_interop" = 1 \]; then\n {2}cargo test -p openpc-fleet-controller --lib --locked --offline \\\n {4}postgres_first_issue_ -- --include-ignored/,
  );
});

test('current custody read contention regressions run in the real database gate', async () => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.ok(source.includes('postgres_current_read_ -- --include-ignored'));
  for (const name of [
    'postgres_current_read_busy_retry_releases_original_locks',
    'postgres_current_read_retry_rejects_denial_exhaustion_and_lost_rollback',
  ]) {
    assert.ok(source.includes(`rg -q '^test target_disposition::current_read_tests::${name}`));
  }
});

test('isolated candidate recovery refuses retained and malformed dispatch before runtime allocation', () => {
  const inputCheck = composeRunner.indexOf(
    "--testNamePattern 'validates candidate recovery migration journals before runtime allocation'",
  );
  assert.ok(inputCheck > composeRunner.indexOf('openpc_require_execution "$execution_profile"'));
  assert.ok(inputCheck < composeRunner.indexOf('mkdir -p "$external_root"'));
  for (const selection of ['2', 'true', '1']) {
    const result = spawnSync(
      'bash',
      ['tests/integration/local-runtime/run-compose-e2e.sh', '--suite'],
      {
        encoding: 'utf8',
        env: { ...process.env, OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE: selection },
      },
    );
    assert.equal(result.status, 96, result.stderr);
    assert.equal(result.stdout, '');
  }
  const marker = 'if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then';
  const start = composeRunner.indexOf(
    marker,
    composeRunner.indexOf('openpc_runner_arguments "$@"'),
  );
  const block = composeRunner.slice(start, composeRunner.indexOf('\nfi', start) + 3);
  for (const state of [
    'reuse_images=1 refresh_from=',
    'reuse_images=0 refresh_from=old',
    'reuse_images=0 refresh_from= OPENPC_LOCAL_RUNTIME_BUILD_ONLY=1',
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1
${state}
${block}
printf 'unexpected-allocation'
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 96, result.stderr);
    assert.doesNotMatch(result.stdout, /unexpected-allocation/u);
  }
});

test('isolated candidate recovery dispatch stops before Fact admission and retains failures', async () => {
  assert.match(
    composeRunner,
    /suite_step candidate-control-recovery env OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1 bash "\$0"/u,
  );
  const source = await readFile(
    'tests/integration/local-runtime/evidence-rpc-source-journey.sh',
    'utf8',
  );
  const marker = 'if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then';
  const start = source.indexOf(marker);
  assert.ok(start > source.indexOf('evidence-rpc-fact.mjs candidate'));
  const dispatch = source.slice(start);
  for (const failure of ['', 'producer', 'restore', 'trust']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1
root=/owned secret_root=/owned/secrets evidence_root=/owned/evidence participant_id=participant privacy_domain_id=privacy
compose=(compose_stub)
openpc_phase_begin() { :; }
openpc_phase_end() { :; }
openpc_compose_json() { printf '[]'; }
compose_stub() { :; }
openpc_wait_participant_gateway() { :; }
mkdir() { :; }
node() {
  if [[ $* == *business-signing-bootstrap.mjs* && $failure == trust ]]; then return 17; fi
  if [[ $* == *evidence-candidate-custody.mjs* ]]; then
    [[ \${!#} == acquisition ]] || return 99
    printf 'producer\\n'
    [[ $failure != producer ]] || return 18
  fi
}
openpc_candidate_control_recovery() { printf 'restore\\n'; [[ $failure != restore ]] || return 19; }
source() { printf 'unexpected-fact-admission\\n'; }
dispatch() {
${dispatch}
}
dispatch
[[ \${openpc_candidate_control_restore_complete:-0} == 1 ]] || exit 96
printf 'component-pass\\n'
`,
      ],
      { encoding: 'utf8', env: { ...process.env, failure } },
    );
    assert.equal(
      result.status,
      failure === 'trust' ? 17 : failure === 'producer' ? 18 : failure === 'restore' ? 19 : 0,
      result.stderr,
    );
    assert.doesNotMatch(result.stdout, /unexpected-fact-admission/u);
    assert.equal(
      result.stdout.includes('restore\n'),
      failure !== 'producer' && failure !== 'trust',
    );
    assert.equal(result.stdout.includes('component-pass'), failure === '');
  }
});

test('isolated candidate recovery cannot claim the complete first-policy RPC journey', async () => {
  const firstPolicy = await readFile(
    'tests/integration/local-runtime/first-policy-journey.sh',
    'utf8',
  );
  const tail = firstPolicy.slice(
    firstPolicy.indexOf('source tests/integration/local-runtime/evidence-rpc-configuration.sh'),
  );
  for (const complete of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1
source() { [[ $1 == *evidence-rpc-configuration.sh ]] || { echo unexpected-journey; return 99; }; ${complete ? 'openpc_candidate_control_restore_complete=1' : ':'}; }
dispatch() {
${tail}
}
dispatch
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, complete ? 0 : 96, result.stderr);
    assert.doesNotMatch(result.stdout, /unexpected-journey/u);
  }
  const needle = '  source tests/integration/local-runtime/first-policy-journey.sh';
  const start = composeRunner.lastIndexOf('\nif [[ ', composeRunner.indexOf(needle));
  const dispatch = composeRunner.slice(start, composeRunner.indexOf('\nfi', start) + 3);
  for (const complete of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1
source() { ${complete ? 'openpc_candidate_control_restore_complete=1' : ':'}; }
${dispatch}
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, complete ? 0 : 96, result.stderr);
    assert.equal(result.stdout.includes('OPENPC_CANDIDATE_CONTROL_RESTORE|PASS'), complete);
    assert.doesNotMatch(result.stdout, /OPENPC_FIRST_POLICY_RPC\|PASS/u);
  }
});

test('first-policy trust prerequisites fail closed before application startup', () => {
  const preparation = composeRunner.indexOf('\n    openpc_prepare_first_policy_trust\n');
  assert.ok(preparation > 0);
  assert.ok(
    preparation < composeRunner.indexOf('while IFS= read -r target_service; do', preparation),
  );
  for (const failure of [0, 1, 2, 3, 4, 5, 6]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      source tests/integration/local-runtime/runner-harness.sh
      repository_root=$PWD run_root=owned secret_root=owned/secrets
      OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=018f0000-0000-7000-8000-000000007201
      mkdir() { :; }
      step=0
      node() { step=$((step + 1)); printf 'prerequisite=%s\\n' "$step"; [[ $step != ${failure} ]]; }
      openpc_prepare_first_policy_trust
      printf 'application-startup\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 0 ? 0 : 1, result.stderr);
    assert.equal(result.stdout.includes('application-startup'), failure === 0);
    if (failure !== 0) assert.equal(result.stdout.trim().split('\n').length, failure);
  }
});

test('default RPC custody executes terminal, completed-read and source-read retirement with prerequisite failure blocking', async () => {
  const source = await readFile('tests/integration/local-runtime/evidence-rpc-custody.mjs', 'utf8');
  const start = source.indexOf(
    "  if (process.env.OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY === '1') {",
  );
  const end = source.indexOf('  // Return ownership to the caller', start);
  assert.ok(start > 0 && end > start);
  const block = source.slice(start, end);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  for (const enabled of [false, true])
    for (const failAt of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
      const calls = [];
      const run = new AsyncFunction(
        'process',
        'prepareRpcRetirementSigningTrust',
        'projectionDeletionBrowser',
        'sourceReadCustody',
        'withRpcPayloadRetirementSigning',
        'const secretRoot="secret",root="root",ownedData="data",api="api",compose=[],participantId="participant",privacyDomainId="privacy",configuration="worker";' +
          block,
      );
      const execution = run(
        { env: { OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY: enabled ? '1' : '0' } },
        async (input) => {
          calls.push(input);
          if (calls.length === failAt) throw new Error('projection prerequisite failed');
        },
        async (input) => {
          calls.push(input);
          if (calls.length === failAt) throw new Error('projection prerequisite failed');
          return ['original-read-1', 'original-read-2'];
        },
        async (input) => {
          calls.push(input);
          if (calls.length === failAt) throw new Error('projection prerequisite failed');
          return 'source-worker';
        },
        async (input, consume) => {
          calls.push(input);
          if (calls.length === failAt) throw new Error('projection prerequisite failed');
          await consume(['original-signing-compose']);
        },
      );
      if (enabled && failAt) await assert.rejects(execution, /projection prerequisite failed/u);
      else await execution;
      assert.equal(calls.length, enabled ? failAt || 8 : 0);
      if (calls.length >= 1)
        assert.deepEqual(calls[0], {
          secretRoot: 'secret',
          dataRoot: 'data',
          compose: [],
          privacyDomainId: 'privacy',
        });
      if (calls.length >= 3) {
        assert.equal(calls[1].closedRpcOnly, undefined);
        assert.equal(calls[2].closedRpcOnly, true);
        assert.equal(calls[2].terminalCases, true);
        assert.equal(calls[1].rpcConfiguration, calls[2].rpcConfiguration);
      }
      if (calls.length >= 4) {
        assert.equal(calls[3].closedRpcOnly, true);
        assert.equal(calls[3].terminalCases, undefined);
      }
      if (calls.length >= 6) {
        assert.equal(calls[5].sourceReads, true);
        assert.equal(calls[5].rpcConfiguration, 'source-worker');
      }
      if (calls.length >= 7)
        assert.deepEqual(calls[6].recordIds, ['original-read-1', 'original-read-2']);
      if (calls.length === 8) {
        assert.deepEqual(calls[7].rpcPayloadRecordIds, calls[6].recordIds);
        assert.deepEqual(calls[7].compose, ['original-signing-compose']);
        assert.equal(calls[7].rpcConfiguration, 'worker');
      }
    }
});

test('relationship custody requires real predecessor references after closing and propagates failure', () => {
  for (const phase of ['opening', 'closing']) {
    for (const failed of [false, true]) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
        source tests/integration/local-runtime/runner-harness.sh
        source tests/integration/local-runtime/relationship-visibility-journey.sh
        secret_root=owned/secrets participant_id=participant privacy_domain_id=privacy evidence_root=owned/evidence
        OPENPC_RELATIONSHIP_PHASE=${phase}
        compose=(docker compose)
        docker() { printf 'verified-api-container'; }
        node() { printf '%s\\n' "$@"; return ${failed ? 19 : 0}; }
        openpc_relationship_fact_custody
        printf 'custody-completed\\n'
      `,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed ? 19 : 0, result.stderr);
      assert.match(result.stdout, /evidence-fact-custody\.mjs/u);
      assert.match(
        result.stdout,
        /owned\/secrets\nparticipant\nprivacy\nowned\/evidence\nverified-api-container\n/u,
      );
      assert.match(result.stdout, phase === 'closing' ? /\nrequired\n/u : /\noptional\n/u);
      assert.match(
        result.stdout,
        phase === 'closing' ? /\nretirement-browser\n/u : /\nretirement\n/u,
      );
      assert.match(result.stdout, /\ndocker\ncompose\n/u);
      assert.equal(result.stdout.includes('custody-completed'), !failed);
    }
  }
});

test('first-policy scope preflight rejects mismatched API, worker and external signer before startup', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT, 'scope-preflight.'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const signer = join(root, 'signer.mjs'),
    issuer = join(root, 'issuer.mjs'),
    manifest = join(root, 'manifest.json');
  for (const file of [signer, issuer, manifest]) await writeFile(file, '{}', { mode: 0o600 });
  const user = `${process.getuid()}:${process.getgid()}`;
  assert.match(composeRunner, /FIRST_POLICY_ONLY[^\n]*openpc_first_policy_scope_preflight/u);
  const fields = {
    'control-api': 'CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID',
    'control-worker': 'CONTROL_WORKER_PRIVACY_DOMAIN_ID',
    'signing-provider': 'OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID',
  };
  const scope = '018f0000-0000-7000-8000-000000007201';
  for (const failure of [undefined, ...Object.keys(fields)]) {
    const services = Object.fromEntries(
      Object.entries(fields).map(([service, field]) => [
        service,
        {
          environment: {
            [field]: service === failure ? '018f0000-0000-7000-8000-000000000201' : scope,
          },
        },
      ]),
    );
    services['signing-provider'].user = user;
    services['signing-provider'].volumes = [
      { type: 'bind', source: signer, target: '/app/server.mjs', read_only: true },
    ];
    services['workload-issuer'] = {
      user,
      volumes: [
        { type: 'bind', source: issuer, target: '/app/server.mjs', read_only: true },
        { type: 'bind', source: manifest, target: '/issuer/manifest.json', read_only: true },
      ],
    };
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      source tests/integration/local-runtime/runner-harness.sh
      export OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=$1
      rendered=$2
      render() { printf '%s' "$rendered"; }
      compose=(render)
      openpc_first_policy_scope_preflight
      printf 'dependent-startup\\n'
    `,
        'scope-preflight',
        scope,
        JSON.stringify({ services }),
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE: signer,
          OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE: issuer,
          OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST: manifest,
          OPENPC_LOCAL_UID: String(process.getuid()),
          OPENPC_LOCAL_GID: String(process.getgid()),
        },
      },
    );
    assert.equal(result.status, failure === undefined ? 0 : 1, result.stderr);
    assert.equal(result.stdout.includes('dependent-startup'), failure === undefined);
    if (failure === undefined)
      assert.equal(
        result.stdout,
        'OPENPC_FIRST_POLICY_SCOPE_PREFLIGHT|PASS|api-worker-signer|same-privacy\ndependent-startup\n',
      );
  }
});

test('runtime receipt preflight rejects producer, consumer and empty-corpus failures before dispatch', async () => {
  const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  assert.match(harness, /openpc_fixture_preflight\(\)[\s\S]*openpc_receipt_contract_preflight/u);
  const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  assert.ok(
    runner.indexOf('\nopenpc_fixture_preflight\n') < runner.indexOf('\nopenpc_storage_preflight\n'),
  );
  for (const failure of [0, 1, 2, 3, 4, 5, 6, 7]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `
set -euo pipefail
repository_root=$PWD
source tests/integration/local-runtime/runner-harness.sh
step=0
check() { step=$((step + 1)); printf 'check=%s\\n' "$step"; [[ $step != ${failure} ]]; }
node() { check; }
pnpm() { check; }
cargo() {
  check || return
  if [[ ${failure} != 7 ]]; then
    printf '%s\\n' 'signed_indexer_profiles_preserve_v1_and_bind_v2_presence_to_grant_state_and_outbox ... ok' 'signed_v2_state_rejects_ambiguous_absence_and_unknown_projection_fields ... ok'
  fi
}
openpc_receipt_contract_preflight
printf 'runtime-dispatch\\n'
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status === 0, failure === 0, result.stdout + result.stderr);
    if (failure !== 0) assert.doesNotMatch(result.stdout, /runtime-dispatch/u);
    else assert.match(result.stderr, /receipt-preflight\|event=end\|status=0/u);
  }
});

test('evidence contracts fail closed before database allocation and unrelated scenarios skip them', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const start = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', start) + '\nesac'.length;
  assert.ok(start > 0 && end > start);
  assert.ok(end < runner.indexOf('\nroot=$(mktemp'));
  assert.ok(end < runner.indexOf('\ndocker run'));
  const preflight = runner.slice(start, end);
  assert.match(preflight, /generate-business-transition\.mjs --check/u);
  assert.match(preflight, /src\/db\/function-grants\.test\.ts/u);
  assert.match(preflight, /src\/evidence\/hold-contracts\.test\.ts/u);
  assert.match(preflight, /src\/evidence\/deletion-business-state\.test\.ts/u);
  assert.match(preflight, /validates exact evidence signing inputs before database allocation/u);
  assert.match(preflight, /src\/evidence-export\/codec\.test\.ts/u);
  assert.match(preflight, /src\/evidence\/export-producer-installation\.test\.ts/u);
  assert.match(preflight, /src\/notifications\/source-reader\.test\.ts/u);
  assert.match(
    preflight,
    /pnpm exec tsc [^\n]*tests\/integration\/identity\/postgres-evidence-export\.test\.ts/u,
  );
  assert.match(
    await readFile('tests/integration/identity/postgres-evidence-export.test.ts', 'utf8'),
    /await assertNotificationSourceReadbackCases\(\{/u,
  );
  assert.match(
    await readFile('tests/integration/identity/postgres-evidence-export.test.ts', 'utf8'),
    /await assertExportCompletionPreparationCases\(admin, workerPool, scope, exportId,\s*\{\s*participantId: foreign\.participantId,\s*privacyDomainId: foreign\.privacyDomainId,/u,
  );
  assert.match(preflight, /tests\/integration\/policy\/approval-candidate-contract\.test\.ts/u);
  for (const scenario of [
    'evidence-holds',
    'evidence-deletion',
    'evidence-deletion-eligibility',
    'evidence-projection-deletion',
    'retention-policy',
    'evidence-export',
    'evidence-protected',
    'evidence-raw-deletion',
    'evidence-remote-archive',
    'evidence-protected-remote-archive',
    'evidence-remote-runtime',
    'evidence-remote-upgrade',
    'role-journey',
  ]) {
    const checkCount =
      scenario === 'evidence-export'
        ? 7
        : scenario === 'evidence-projection-deletion'
          ? 6
          : scenario.includes('remote')
            ? 6
            : [
                  'evidence-protected',
                  'evidence-raw-deletion',
                  'evidence-projection-deletion',
                  'evidence-export',
                ].includes(scenario)
              ? 5
              : 4;
    for (let failedStep = 0; failedStep <= checkCount; failedStep += 1) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
test_files=(tests/integration/identity/postgres-${scenario}.test.ts)
step=0
check() { step=$((step + 1)); printf 'check=%s\\n' "$step"; [[ $step != ${failedStep} ]]; }
node() { check; }
pnpm() { check; }
${preflight}
printf 'database-dispatch\\n'
`,
        ],
        { encoding: 'utf8' },
      );
      const applicable = scenario !== 'role-journey';
      assert.equal(result.status, applicable && failedStep !== 0 ? 1 : 0, result.stderr);
      if (applicable && failedStep !== 0) {
        assert.doesNotMatch(result.stdout, /event=passed|database-dispatch/u);
        assert.equal((result.stdout.match(/check=/gu) ?? []).length, failedStep);
      } else if (applicable) {
        assert.ok(
          result.stdout.includes(`check=${checkCount}\nOPENPC_IDENTITY_PREFLIGHT|event=passed`),
        );
      } else {
        assert.equal(result.stdout, 'database-dispatch\n');
      }
    }
  }
});

test('remote upgrade initializes the actual predecessor and blocks dispatch on installer failure', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.match(
    runner,
    / {2}tests\/integration\/identity\/postgres-evidence-remote-upgrade\.test\.ts\n/u,
  );
  const start = runner.indexOf(
    'if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-remote-upgrade.test.ts',
  );
  const end = runner.indexOf('\ndocker exec -i', start);
  assert.ok(start > 0 && end > start);
  const fixture = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? '/tmp', 'remote-upgrade-invocation-'),
  );
  try {
    for (const lane of ['identity', 'policy', 'control-api']) {
      await mkdir(join(fixture, 'migrations/postgres', lane), { recursive: true });
      await writeFile(
        join(fixture, 'migrations/postgres', lane, '0000_initial.sql'),
        'select 1;\n',
      );
    }
    await writeFile(
      join(fixture, 'migrations/postgres/control-api/0081_deployment_projection_fence.sql'),
      'select 81;\n',
    );
    await writeFile(
      join(fixture, 'migrations/postgres/control-api/0082_remote_archive_attempt.sql'),
      'select 82;\n',
    );
    for (const failed of [false, true]) {
      const root = join(fixture, failed ? 'failure' : 'pass');
      await mkdir(root);
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
repo="$1"
root="$2"
container=owned-test-database
test_files=(tests/integration/identity/postgres-evidence-remote-upgrade.test.ts)
docker() { printf '%s\\n' "$*"; return ${failed ? 1 : 0}; }
${runner.slice(start, end)}
printf 'journey-dispatch\\n'
`,
          'bash',
          fixture,
          root,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed ? 1 : 0, result.stderr);
      assert.equal(result.stdout.includes('journey-dispatch'), !failed);
      assert.equal(
        await readFile(
          join(root, 'predecessor/control-api/0081_deployment_projection_fence.sql'),
          'utf8',
        ),
        'select 81;\n',
      );
      await assert.rejects(
        readFile(join(root, 'predecessor/control-api/0082_remote_archive_attempt.sql')),
        { code: 'ENOENT' },
      );
      const log = await readFile(join(root, 'migrations.log'), 'utf8');
      assert.match(log, /--memory 128m --memory-swap 128m/u);
      assert.ok(log.includes(`${root}/predecessor:/migrations/postgres:ro`));
      assert.match(log, /sh \/local\/migrate\.sh control/u);
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('ordinary admin-web tests partition server contracts from browser components without a coverage gap', async () => {
  const { default: configuration } = await import('../../../apps/admin-web/vitest.config.ts');
  const { configDefaults } = await import('vitest/config');
  const [server, browser] = configuration.test.projects;
  assert.equal(server.test.environment, 'node');
  assert.deepEqual(server.test.include, ['app/api/v1/ui/*.test.ts']);
  assert.equal(browser.test.environment, 'jsdom');
  assert.equal(browser.test.include, undefined);
  assert.deepEqual(server.test.exclude, [...configDefaults.exclude, '**/._*']);
  assert.deepEqual(browser.test.exclude, [...server.test.exclude, ...server.test.include]);
  assert.deepEqual(browser.test.setupFiles, ['./test/setup.ts']);
});

test('deployment CI archives real effect history through the guarded packaged worker', async () => {
  const custody = await readFile(
    'tests/integration/local-runtime/evidence-effect-custody.mjs',
    'utf8',
  );
  assert.match(custody, /await verifyDeploymentProvenanceSources\(/u);
  assert.match(custody, /await verifyPublicProvenance\(/u);
  assert.match(custody, /await inspectProvenanceWorkbench\(/u);
  assert.match(composeRunner, /suite_step deployment env OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY=1/);
  assert.match(
    composeRunner,
    /run_deployment_submission[\s\S]+node --import tsx tests\/integration\/local-runtime\/evidence-effect-custody\.mjs/u,
  );
  const result = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'tests/integration/local-runtime/evidence-effect-custody.mjs'],
    {
      encoding: 'utf8',
      timeout: 15000,
      env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /live canonical execution owner/u);
  assert.doesNotMatch(result.stderr, /JSON\.parse|Pool|AssertionError/u);
});

test('deployment retirement runs at real finality and failure blocks later source restart', async () => {
  const source = await readFile(
    'tests/integration/local-runtime/deployment-submission-journey.sh',
    'utf8',
  );
  assert.match(
    source,
    /deployment_wait_observation FINALIZED[\s\S]+deployment_management_result SUCCEEDED\s+if \[\[ \$deployment_case == direct \]\]; then\s+deployment_finalized_retirement/u,
  );
  const fn = source.match(/^deployment_finalized_retirement\(\) \{[\s\S]*?^\}/mu)?.[0];
  assert.ok(fn);
  assert.match(
    composeRunner,
    /test -f "\$data_root\/deployment-retirement\/worker.json"[\s\S]+evidence-deployment-retirement\.mjs[\s\S]+--readback/u,
  );
  for (const fail of ['0', '1']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      compose=(fixture_compose); secret_root=secret; evidence_root=evidence; data_root=data
      participant_id=participant; privacy_domain_id=privacy
      fixture_compose() { printf 'compose %s\\n' "$*"; }
      openpc_phase_begin() { :; }; openpc_phase_end() { printf 'phase complete\\n'; }
      openpc_compose_json() { printf '["docker","compose"]'; }
      deployment_reactivate_runtime() { printf 'public renewal and runtime restart\\n'; }
      node() { if [[ $1 == -e ]]; then printf '[]'; else printf 'retirement prerequisite\\n'; return "$1_RETIREMENT_FAILURE"; fi; }
      ${fn}
      deployment_finalized_retirement
    `.replace('$1_RETIREMENT_FAILURE', fail),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, Number(fail), result.stderr);
    assert.match(result.stdout, /retirement prerequisite/u);
    assert.equal(result.stdout.includes('runtime restart'), fail === '0');
    assert.equal(result.stdout.includes('phase complete'), fail === '0');
  }
  const guarded = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'tests/integration/local-runtime/evidence-deployment-retirement.mjs'],
    {
      encoding: 'utf8',
      timeout: 15000,
      env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
    },
  );
  assert.notEqual(guarded.status, 0);
  assert.match(guarded.stderr, /live canonical execution owner/u);
  assert.doesNotMatch(guarded.stderr, /JSON\.parse|Pool|AssertionError/u);
});

test('deployment and Fact journeys prepare root projection signing keys before services', () => {
  const bootstrap = composeRunner.match(
    /^if \[\[ \$\{OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0\} == 1[^\n]*\n[^\n]*--projection-deletion[^\n]*\nfi/mu,
  )?.[0];
  assert.ok(bootstrap);
  for (const [fact, deployment, expected] of [
    ['0', '0', ''],
    ['1', '0', 'root-projection-trust\n'],
    ['0', '1', 'root-projection-trust\n'],
    ['1', '1', 'root-projection-trust\n'],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
secret_root=secret; data_root=data
node() { [[ $* == '--import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts secret data/signing-provider --projection-deletion 018f0000-0000-7000-8000-000000000201' ]]; printf 'root-projection-trust\\n'; }
${bootstrap}`,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY: fact,
          OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY: deployment,
        },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, expected);
  }
});

test('ordinary RPC CI connects real decisions to encrypted custody and governed browser export', async () => {
  assert.match(
    composeRunner,
    /suite_step visibility-and-explorer env OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY=1/u,
  );
  const journey = await readFile('tests/integration/local-runtime/visibility-journey.sh', 'utf8');
  const recovery = journey.slice(
    journey.indexOf('openpc_recover_visibility_reads() {'),
    journey.indexOf('openpc_grant_visibility_reads() {'),
  );
  assert.ok(
    recovery.indexOf('visibility_runtime_request restarted 3') <
      recovery.indexOf('evidence-rpc-custody.mjs'),
  );
  assert.match(
    recovery,
    /node --import tsx tests\/integration\/local-runtime\/evidence-rpc-custody\.mjs/u,
  );
  const result = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'tests/integration/local-runtime/evidence-rpc-custody.mjs'],
    {
      encoding: 'utf8',
      timeout: 15000,
      env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /live canonical execution owner/u);
  assert.doesNotMatch(result.stderr, /JSON\.parse|Pool|AssertionError/u);
});

test('ordinary CI reaches the governed hold database and browser custody journeys', async () => {
  const gateway = await readFile('deploy/compose/local/envoy/local-gateway.yaml', 'utf8');
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/evidence-holds"[\s\S]*?cluster: control_api/u,
  );
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.match(runner, /tests\/integration\/identity\/postgres-evidence-holds\.test\.ts/u);
  assert.match(runner, /tests\/integration\/policy\/approval-candidate-contract\.test\.ts/u);
  const holdJourney = await readFile(
    'tests/integration/local-runtime/evidence-hold-custody.mjs',
    'utf8',
  );
  for (const input of [
    'PROJECTION',
    'FACT_TYPE_KEY',
    'BLOCK_RANGE',
    'RUNTIME_CONFIGURATION',
    'CANONICAL_FACT',
    'PARTICIPANT',
  ])
    assert.ok(holdJourney.includes(input));
  assert.match(holdJourney, /bootstrap-evidence-hold-selectors/u);
  assert.match(runner, /tests\/integration\/identity\/postgres-evidence-protected\.test\.ts/u);
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-protected-browser\.mjs/u,
  );
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/protected-proofs"[\s\S]*?cluster: control_api/u,
  );
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/protected-proof-access"[\s\S]*?cluster: control_api/u,
  );
  assert.match(runner, /tests\/integration\/identity\/postgres-evidence-deletion\.test\.ts/u);
  assert.match(runner, /tests\/integration\/identity\/postgres-evidence-raw-deletion\.test\.ts/u);
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-raw-deletion-browser\.mjs/u,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-raw-deletion-browser\.mjs[^\n]*\n[^\n]*\n[^\n]* --remote/u,
  );
  assert.match(
    runner,
    /tests\/integration\/identity\/postgres-evidence-deletion-continuation\.test\.ts/u,
  );
  assert.match(runner, /tests\/integration\/identity\/postgres-session-contexts\.test\.ts/u);
  assert.match(
    runner,
    /tests\/integration\/identity\/postgres-evidence-deletion-eligibility\.test\.ts/u,
  );
  assert.match(runner, /tests\/integration\/identity\/postgres-retention-policy\.test\.ts/u);
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/retention-policy-browser\.mjs/u,
  );
  assert.match(
    gateway,
    /path_separated_prefix: "\/api\/v1\/retention-policies"[\s\S]*?cluster: control_api/u,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-hold-custody\.mjs/u,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-deletion-browser\.mjs/u,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-deletion-continuation-browser\.mjs/u,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/evidence-rejection-deletion-browser\.mjs/u,
  );
  assert.ok(
    composeRunner.indexOf('evidence-rejection-deletion-browser.mjs') <
      composeRunner.indexOf('retention-policy-browser.mjs'),
  );
  for (const script of [
    'evidence-hold-custody',
    'retention-policy-browser',
    'evidence-deletion-browser',
    'evidence-deletion-continuation-browser',
    'evidence-raw-deletion-browser',
    'evidence-rejection-deletion-browser',
  ]) {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', `tests/integration/local-runtime/${script}.mjs`],
      {
        encoding: 'utf8',
        timeout: 15000,
        env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /live canonical execution owner/u);
    assert.doesNotMatch(result.stderr, /JSON\.parse|Pool|AssertionError/u);
  }
});

test('runtime CI executes the Fleet source resolver against installed database roles', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.match(
    composeRunner,
    /suite_step identity bash tests\/integration\/identity\/run-participant-readback\.sh/,
  );
  assert.match(runner, /\n {2}source-policy-compilation\n/);
  assert.match(runner, /--profile database --memory-gib 8 --peak-disk-gib 40 --reuse/);
  assert.match(
    runner,
    /postgres_source_policy_resolution_with_initial_reference_rows -- --include-ignored/,
  );
  assert.match(runner, /openpc_local_control_worker:/);
  assert.match(
    runner,
    /postgres_cigl_claim_defers_only_unclaimed_lifecycle_contention -- --include-ignored/,
  );
  assert.match(
    runner,
    /postgres_publication_observation_defers_lifecycle_before_source_or_effect -- --include-ignored/,
  );
});

test('runtime CI verifies installed fact feed receipts and both migration paths', async () => {
  assert.match(
    composeRunner,
    /suite_step fact-store bash tests\/integration\/facts\/run-postgres18-gate3-proof\.sh/,
  );
  const runner = await readFile('tests/integration/facts/run-postgres18-gate3-proof.sh', 'utf8');
  assert.match(runner, /openpc_require_execution database/);
  assert.match(runner, /0004_candidate_feed_receipts\.sql/);
  assert.match(runner, /0006_canonical_fact_identity\.sql/);
  assert.match(runner, /0007_signed_shard_publication\.sql/);
  assert.match(runner, /0008_source_withdrawal_lineage\.sql/);
  assert.match(runner, /0009_canonical_reorg_lineage\.sql/);
  assert.match(runner, /0010_signed_reorg_replacement\.sql/);
  assert.match(runner, /0011_store_retirement\.sql/);
  assert.match(runner, /0012_store_retirement_preflight\.sql/);
  const selectionPreflight = runner.indexOf('--lib retirement_selection');
  assert.ok(selectionPreflight > 0 && selectionPreflight < runner.indexOf('docker run --detach'));
  assert.match(runner, /0013_admission_delivery\.sql/);
  assert.match(runner, /0014_delivery_identity_readback\.sql/);
  assert.match(
    runner,
    /--ignored --exact store::retirement_preflight::tests::reader_privileges_context_store_and_unavailable_fail_closed/,
  );
  assert.match(runner, /"\$\{psql\[@\]\}" --single-transaction "\$@" <"\$path"/u);
  assert.match(runner, /FAILURE_ATOMIC_INSTALLATION/u);
  assert.match(runner, /DID_NOT_REACH_FINAL_FAULT/u);
  for (const name of [
    'verified_cancel_before_dispatch_survives_restart_and_late_execution',
    'exact_replay_keeps_original_outcome_and_altered_approval_is_rejected',
    'execute_cancel_race_commits_one_original_signed_outcome',
    'target_signer_failure_rolls_back_and_scope_purpose_failures_have_no_effect',
    'sql_consumes_exact_cancellation_nonce_and_rejects_execution_domain_reuse',
    'outbox_failure_rolls_back_attempt_and_nonce_before_exact_retry',
  ])
    assert.ok(runner.includes(name), name);
  assert.match(runner, /-- --ignored --exact "store::retirement::tests::\$retirement_case"/u);
  assert.match(
    runner,
    /--ignored --exact store::relationship::tests::relationship_transitions_are_atomic_ordered_and_replay_safe/,
  );
  assert.match(
    runner,
    /--ignored --exact store::relationship::tests::empty_checkpoint_preserves_latest_signed_relationship_transition/,
  );
  assert.match(
    runner,
    /--ignored --exact store::feed::tests::external_observations_preserve_boolean_meaning_through_signed_publication/,
  );
  assert.match(
    runner,
    /--ignored --exact store::identity::tests::complete_batch_is_atomic_and_publication_verifies_every_record/,
  );
  assert.match(
    runner,
    /--ignored --exact store::identity::tests::complete_record_allocation_is_atomic_scoped_and_restart_safe/,
  );
  assert.match(
    runner,
    /--ignored --exact store::occurrence::tests::upgrade_preserves_populated_signed_legacy_facts/,
  );
  assert.match(
    runner,
    /--ignored --exact store::occurrence::tests::conflicts_fence_all_generations_atomically_and_survive_restart/,
  );
  assert.match(runner, /CREATE DATABASE openpc_facts_greenfield/);
  assert.match(
    runner,
    /--ignored --exact store::feed::tests::installed_feed_receipts_are_atomic_ordered_and_restart_safe/,
  );
  assert.ok(runner.includes('--bin fact_retirement_owner'));
  assert.ok(
    runner.includes('protocol::installed_target_preserves_unknown_cancellation_and_original_bytes'),
  );
  assert.ok(runner.indexOf('cargo test --quiet') < runner.indexOf('docker run --detach'));
});

test('focused Fact delivery retains an independent failure while running the remaining cases', async () => {
  const runner = await readFile('tests/integration/facts/run-postgres18-gate3-proof.sh', 'utf8');
  const start = runner.indexOf('if [[ $delivery_only == true ]]');
  const end = runner.indexOf('\nfi', start);
  assert.ok(start > 0 && end > start);
  const block = runner.slice(start, end + 3);
  assert.ok(runner.includes('0018_withdrawal_checkpoint.sql'));
  assert.ok(
    block.includes(
      'withdrawal::checkpoint::tests::untrusted_checkpoint_inputs_and_roles_cannot_mutate',
    ),
  );
  for (const failure of [0, 1, 3, 7]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      delivery_only=true database_url=fixture reader_database_url=fixture capability_secret_hex=fixture
      step=0
      cargo() { step=$((step + 1)); printf 'case=%s\\n' "$step"; [[ $step != ${failure} ]]; }
      ${block}
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failure === 0 ? 0 : 1, result.stderr);
    assert.equal((result.stdout.match(/^case=/gmu) ?? []).length, 7);
    assert.equal(result.stdout.includes('CONSUMER_ACK_PENDING'), failure === 0);
    assert.equal(result.stderr.includes('FACT_ADMISSION_DELIVERY_CASE|FAIL|'), failure !== 0);
  }
});

test('ordinary identity CI executes the durable remote archive journal against PostgreSQL', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.match(runner, /tests\/integration\/identity\/postgres-evidence-remote-archive\.test\.ts/u);
});

test('ordinary identity CI checks store-retirement contracts before its scoped PostgreSQL owner', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const testFile = 'tests/integration/identity/postgres-evidence-store-retirement.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(testFile));
  const preflight = runner.indexOf('src/evidence/store-retirement-business-state.test.ts');
  assert.ok(preflight > 0 && preflight < runner.indexOf('docker run -d'));
  assert.ok(runner.includes('src/evidence/store-retirement-wire.test.ts'));
  assert.ok(runner.includes('src/evidence/store-retirement-preflight.test.ts'));
  assert.ok(runner.includes('src/evidence/store-retirement-selection.test.ts'));
  assert.ok(runner.includes('src/evidence/store-retirement-contracts.test.ts'));
  assert.ok(runner.includes('src/evidence/store-retirement-dispatcher.test.ts'));
  assert.ok(runner.includes('src/evidence/store-retirement-installation.test.ts'));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const contract = runner.slice(begin, runner.indexOf('\nesac', begin) + '\nesac'.length);
  for (const failed of [0, 1, 2, 3, 4, 5]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${testFile})
      calls=0
      check() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
      node() { check; }
      pnpm() { check; }
      ${contract}
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('ordinary identity CI executes the mounted remote archive worker', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const journey = await readFile(
    'tests/integration/identity/postgres-evidence-remote-runtime.test.ts',
    'utf8',
  );
  assert.ok(runner.includes('tests/integration/identity/postgres-evidence-remote-runtime.test.ts'));
  assert.ok(journey.includes("'src/evidence/runtime.ts'"));
  assert.ok(journey.includes('trust.runtimeConfiguration'));
  assert.ok(journey.includes("'REMOTE_INTERFACE_VERIFIED'"));
});

test('ordinary identity CI executes migrated protected remote source predicates', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const generator = await readFile(
    'services/control-api/src/configuration/generate-security-tail.mjs',
    'utf8',
  );
  assert.ok(
    runner.includes(
      'tests/integration/identity/postgres-evidence-protected-remote-archive.test.ts',
    ),
  );
  assert.ok(generator.includes('${protectedRemoteArchiveSourceSql}'));
});

test('Identity runtime acceptance executes the real FactBridge mTLS consumer', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const journey = await readFile(
    'tests/integration/identity/postgres-runtime-snapshot.test.ts',
    'utf8',
  );
  assert.match(runner, /OPENPC_FACT_WORKLOAD_TEST_BINARY/);
  assert.match(runner, /GRANT openpc_control_reader TO openpc_fact_authority_test_reader/);
  assert.ok(runner.indexOf('cargo test -p openpc-fact-service') < runner.indexOf('docker run -d'));
  assert.ok(runner.indexOf('cargo test -p openpc-runtime-agent') < runner.indexOf('docker run -d'));
  assert.match(journey, /installed_mtls_identity_requires_current_scoped_fact_permission/);
  assert.match(journey, /promisify\(execFile\)\(\s*factConsumer/);
  assert.match(runner, /\n {2}tests\/integration\/identity\/postgres-platform-context\.test\.ts\n/);
});

test('candidate database acceptance is guarded and uses installed migration privileges', async () => {
  assert.match(
    composeRunner,
    /suite_step candidate-store bash tests\/integration\/indexers\/run-candidate-store\.sh/,
  );
  const path = 'tests/integration/indexers/run-candidate-store.sh';
  const runner = await readFile(path, 'utf8');
  assert.match(runner, /openpc_require_execution database/);
  assert.match(runner, /--peak-disk-gib 40 --reuse/);
  assert.match(runner, /--memory 1g --memory-swap 1g --cpus 1 --pids-limit 128/);
  assert.match(runner, /cargo test --locked -p openpc-indexer-adapter\nprove_admission_upgrade/);
  assert.match(runner, /migrations\/postgres\/candidate-index\/\*\.sql/);
  assert.doesNotMatch(runner, /GRANT EXECUTE/);
  assert.ok(runner.indexOf('--lib --no-run') < runner.indexOf('docker create'));
  for (const name of [
    'verified_cancel_before_dispatch_survives_restart_and_late_execution',
    'exact_replay_keeps_original_outcome_and_altered_approval_is_rejected',
    'execute_cancel_race_commits_one_original_signed_outcome',
    'target_signer_failure_rolls_back_and_scope_purpose_failures_have_no_effect',
    'sql_consumes_exact_cancellation_nonce_and_rejects_execution_domain_reuse',
    'outbox_failure_rolls_back_attempt_and_nonce_before_exact_retry',
    'expired_authority_and_foreign_readback_cannot_create_or_disclose_outcomes',
  ])
    assert.ok(runner.includes(name), name);
  assert.match(runner, /-- --ignored --exact "store::retirement::tests::\$retirement_case"/u);
  assert.match(
    runner,
    /--ignored --exact store::retirement::tests::upgrade::populated_upgrade_preserves_payload_identity_checkpoints_and_feed_high_water/u,
  );
  assert.match(runner, /PHYSICAL_JOURNEY_NOT_RUN/u);
  assert.match(runner, /OPENPC_CANDIDATE_RETIREMENT_SECRET_HEX="\$\(openssl rand -hex 32\)"/u);
  assert.match(
    composeRunner,
    /candidate_migration_files=\(migrations\/postgres\/candidate-index\//,
  );
  assert.match(composeRunner, /"\$migration_count" = "\$\{#candidate_migration_files\[@\]\}"/);
  const result = spawnSync('bash', [path], {
    encoding: 'utf8',
    timeout: 15_000,
    env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
  });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, /Compiling|Candidate diagnostics/);
});

test('runtime CI builds and executes the real projection source completion fence', async () => {
  assert.match(composeRunner, /suite_step projection-source-build prepare_projection_source_test/);
  assert.match(composeRunner, /export OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE=1/);
  assert.match(
    composeRunner,
    /source tests\/integration\/local-runtime\/source-lifecycle-journey\.sh/,
  );
  assert.match(composeRunner, /run_source_lifecycle_journey/);
  assert.match(
    composeRunner,
    /source "\$repository_root\/tests\/integration\/local-runtime\/runtime-configuration\.sh"/,
  );
  const configuration = await readFile(
    'tests/integration/local-runtime/runtime-configuration.sh',
    'utf8',
  );
  assert.match(
    configuration,
    /node tests\/integration\/local-runtime\/projection-source-fence\.mjs/,
  );
  const result = spawnSync(
    process.execPath,
    ['tests/integration/local-runtime/projection-source-fence.mjs'],
    { encoding: 'utf8', timeout: 15_000, env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' } },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /live bounded owner required/);
  assert.doesNotMatch(result.stdout, /running 1 test/);
});

test('Workbench driver resolves actual optional labels before browser dispatch', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
    import assert from 'node:assert/strict';
    import {workbenchInputFields} from './tests/integration/local-runtime/transaction-workbench-browser.mjs';
    const label='Activate a retention policy version';
    const optional='Previous retention policy reference';
    const bare=workbenchInputFields(label,{[optional]:'reference'});
    assert.deepEqual(bare,[{name:'predecessorPolicyId',label:optional+' (optional)',value:'reference'}]);
    assert.deepEqual(workbenchInputFields(label,{[optional+' (optional)']:'reference'}),bare);
    assert.equal(workbenchInputFields(label,{'Retention policy version':'2.0.0'})[0].label,'Retention policy version');
    assert.throws(()=>workbenchInputFields(label,{'Unknown field':'value'}),/Unknown.*field/u);
  `,
    ],
    { encoding: 'utf8', timeout: 15000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

for (const entrypoint of [
  'transaction-workbench-browser',
  'transaction-cigl-browser',
  'approval-resume-browser',
  'runtime-discovery-credential',
]) {
  test(`${entrypoint} refuses dispatch without a live bounded execution owner`, () => {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', `tests/integration/local-runtime/${entrypoint}.mjs`],
      {
        encoding: 'utf8',
        timeout: 15_000,
        env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
      },
    );
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /A live canonical execution owner is required/);
    assert.doesNotMatch(result.stderr, /browserType\.launch|AssertionError/);
  });
}

test('module CI reaches natural approval expiry and the public browser resume journey', async () => {
  const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  assert.match(runner, /suite_step module-lifecycle env OPENPC_LOCAL_RUNTIME_MODULES_ONLY=1/);
  const journey = await readFile(
    'tests/integration/local-runtime/module-admission-journey.sh',
    'utf8',
  );
  assert.match(journey, /202 1 approve-only/);
  assert.match(
    journey,
    /node --import tsx tests\/integration\/local-runtime\/approval-resume-browser\.mjs/,
  );
  assert.match(journey, /--wait-for-expiry/);
  const browser = await readFile(
    'tests/integration/local-runtime/approval-resume-browser.mjs',
    'utf8',
  );
  assert.match(browser, /Date\.parse\(original\[0\]\.proof\.expires_at\)/);
  assert.doesNotMatch(
    browser,
    /update control\.(mfa_challenge|mutation_candidate|approval_request)/i,
  );
});

test(
  'governed CLI integration refuses dispatch without its resource owner',
  {
    skip: process.env.OPENPC_R11_CLI !== '1',
  },
  () => {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', 'tests/integration/local-runtime/transaction-cli.mjs'],
      {
        encoding: 'utf8',
        timeout: 15_000,
        env: { ...process.env, OPENPC_HEAVY_LOCK_OWNER_PID: '' },
      },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /A live canonical execution owner is required/);
    assert.doesNotMatch(result.stderr, /browserType\.launch|AssertionError/);
  },
);

test('R1 retains shared owners while administration CLI dispatch is explicit R1.1 opt-in', async () => {
  const journey = await readFile(
    'tests/integration/local-runtime/deployment-submission-journey.sh',
    'utf8',
  );
  const dispatch = journey.match(
    /if \[\[ \$\{OPENPC_R11_CLI:-0\} == 1 \]\]; then run_transaction_cli; fi/,
  );
  assert.ok(dispatch);
  for (const enabled of ['', '0', '1']) {
    const result = spawnSync(
      'bash',
      ['-c', `run_transaction_cli() { echo invoked; }; ${dispatch[0]}`],
      {
        encoding: 'utf8',
        env: { ...process.env, OPENPC_R11_CLI: enabled },
      },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stdout.trim(), enabled === '1' ? 'invoked' : '');
  }
  assert.match(
    composeRunner,
    /if \[\[ \$\{OPENPC_R11_CLI:-0\} == 1 \]\]; then\n\s+printf[^\n]+administration-cli-readback\.mjs/,
  );
  assert.doesNotMatch(packageDocument.scripts.test, /cli/);
  assert.equal(packageDocument.scripts.openpc, undefined);
  assert.match(packageDocument.scripts['test:r1.1:cli'], /apps\/admin-cli\/vitest.config.ts/);
  for (const scope of ['transactions', 'cigl'])
    assert.match(packageDocument.scripts[`test:r1.1:cli:${scope}`], /OPENPC_R11_CLI=1/);
  const ownerRunner = await readFile(
    'tests/integration/identity/run-participant-readback.sh',
    'utf8',
  );
  assert.match(ownerRunner, /tests\/integration\/identity\/postgres-cigl-grants\.test\.ts/);
  const ownerTest = await readFile(
    'tests/integration/identity/postgres-cigl-grants.test.ts',
    'utf8',
  );
  assert.match(ownerTest, /openpc\.cigl_subject_current/);
  assert.match(ownerTest, /stale\.commit\(\)/);
  assert.match(ownerTest, /userGrant\.commit\(\)/);
  const dockerIgnore = await readFile('.dockerignore', 'utf8');
  assert.match(dockerIgnore, /^apps\/admin-cli$/m);
  for (const mode of [
    'authenticate',
    'submit',
    'readback',
    'resources',
    'stale',
    'native',
    'cigl',
    'lifecycle',
  ])
    assert.match(journey, new RegExp(`transaction-cli\\.mjs ${mode}`));
  assert.equal(packageDocument.scripts['openpc:r1.1'], 'bash apps/admin-cli/openpc.sh');
  const entrypoint = await readFile('apps/admin-cli/openpc.sh', 'utf8');
  assert.match(entrypoint, /exec bash scripts\/maintenance\/run-bounded\.sh/);
  assert.match(entrypoint, /--memory-gib 2 --peak-disk-gib 1/);
});

test('external workflow actions use immutable commits', async () => {
  const references = (source) =>
    [...source.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gmu)].map((match) => match[1]);
  const immutable = (reference) =>
    reference.startsWith('./') || /^[\w.-]+\/[\w./-]+@[a-f0-9]{40}$/u.test(reference);
  for (const file of await readdir('.github/workflows')) {
    if (!/\.ya?ml$/u.test(file)) continue;
    const actions = references(await readFile(join('.github/workflows', file), 'utf8'));
    for (const action of actions) assert(immutable(action), `${file}: ${action}`);
  }
  for (const reference of ['actions/checkout@v4', 'owner/action@main', 'owner/action@abc123']) {
    assert.equal(immutable(reference), false);
  }
  assert.equal(immutable('owner/action@0123456789abcdef0123456789abcdef01234567'), true);
});

test('clean CI jobs install tools and dependencies before their consumers', () => {
  const [quality, runtime] = workflow.split('  runtime-integration:');
  for (const job of [quality, runtime]) {
    const node = job.indexOf('uses: actions/setup-node@');
    const pnpm = job.indexOf('uses: pnpm/action-setup@');
    const store = job.indexOf('pnpm store path --silent');
    const cache = job.indexOf('uses: actions/cache@');
    const install = job.indexOf(
      'pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies',
    );
    assert.ok(node >= 0 && node < pnpm && pnpm < store && store < cache && cache < install);
    assert.doesNotMatch(job, /cache: pnpm/);
  }
  assert.ok(quality.indexOf('cargo fetch --locked') < quality.indexOf('pnpm run test'));
  const browser = runtime.indexOf('pnpm exec playwright install --with-deps chromium');
  assert.ok(browser > runtime.indexOf('pnpm install --frozen-lockfile'));
  assert.ok(browser < runtime.indexOf('pnpm run test:integration:runtime'));
});

test('R1 quality excludes only deferred CLI owners and preserves explicit opt-in checks', async () => {
  const cliPaths = [
    'apps/admin-cli/src/main.ts',
    'tests/integration/local-runtime/transaction-cli.mjs',
    'tests/integration/local-runtime/administration-cli-readback.mjs',
  ];
  const sharedPaths = [
    'apps/admin-web/app/api/v1/ui/local-transaction-workbench.test.ts',
    'tests/integration/identity/postgres-cigl-grants.test.ts',
  ];
  for (const enabled of ['0', '1']) {
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
      import { ESLint } from 'eslint';
      const eslint = new ESLint();
      const paths = ${JSON.stringify([...cliPaths, ...sharedPaths])};
      process.stdout.write(JSON.stringify(await Promise.all(paths.map(path => eslint.isPathIgnored(path)))));
    `,
      ],
      { encoding: 'utf8', env: { ...process.env, OPENPC_R11_CLI: enabled }, timeout: 15000 },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), [
      ...cliPaths.map(() => enabled !== '1'),
      false,
      false,
    ]);
  }
  const { getFileInfo } = await import('prettier');
  for (const path of [...cliPaths, ...sharedPaths]) {
    assert.equal(
      (await getFileInfo(path, { ignorePath: '.prettierignore' })).ignored,
      cliPaths.includes(path),
    );
    assert.equal((await getFileInfo(path, { ignorePath: '/dev/null' })).ignored, false);
  }
  assert.match(packageDocument.scripts['lint:r1.1:cli'], /OPENPC_R11_CLI=1/);
  assert.match(packageDocument.scripts['format:r1.1:cli'], /--ignore-path \/dev\/null/);
});

test('the runtime integration command cannot silently omit either database path', async () => {
  const entry = packageDocument.scripts?.['test:integration:runtime'];
  assert.match(entry, /run-project\.sh --profile runtime/);
  const command = composeRunner;
  assert.equal(typeof command, 'string');
  assert.match(command, /python3 tests\/integration\/local-runtime\/run-decision-owner\.py/);
  assert.match(
    command,
    /suite_step deployment-reservations python3 tests\/integration\/local-runtime\/run-decision-owner\.py --reservations/,
  );
  assert.match(workflow, /OPENPC_DECISION_OWNER_TMP_ROOT=\$RUNNER_TEMP\/openpc-decision-owner/);
  assert.match(command, /suite_step deployment env OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY=1 bash/);
  assert.match(
    command,
    /suite_step transaction-browser env OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER=1 bash/,
  );
  assert.match(command, /run_deployment_workbench/);
  assert.match(command, /suite_step cigl-browser env OPENPC_LOCAL_RUNTIME_CIGL_BROWSER=1 bash/);
  assert.match(command, /transaction-cigl-browser\.mjs journey/);
  assert.match(command, /administration-cli-readback\.mjs/);
  assert.match(command, /node --test tests\/integration\/local-runtime\/business-cbor\.test\.mjs/);
  assert.match(command, /tests\/integration\/policy\/run-postgres18-trace-owner-proof\.sh/);
  assert.match(
    postgresPolicyRunner,
    /pattern='executes all 422 operations and participant traces through activatePolicyGeneration\|/,
  );
  assert.match(postgresPolicyRunner, /--testNamePattern "\$pattern"/);
  assert.match(
    postgresPolicyRunner,
    /one-use step-up\|recovers policy session-touch conflicts\|M1a\|M2'/,
  );
  assert.match(postgresPolicyRunner, /--module-preflight/);
  assert.match(postgresPolicyRunner, /sh \/openpc-migrate\.sh control-schema/);
  assert.doesNotMatch(postgresPolicyRunner, /for migration in/);
  assert.ok(
    postgresPolicyRunner.indexOf('cargo build') <
      postgresPolicyRunner.indexOf('docker run --detach'),
  );
  const identityRunner = await readFile(
    'tests/integration/identity/run-participant-readback.sh',
    'utf8',
  );
  assert.match(
    identityRunner,
    /test_files=\([\s\S]*?tests\/integration\/policy\/postgres18-runtime\.test\.ts[\s\S]*?\n\)/,
  );
  assert.match(identityRunner, /--config tests\/integration\/policy\/vitest\.config\.ts/);
  assert.match(
    identityRunner,
    /--testNamePattern 'changes a CIGL binding through governed publication after the preflight fence releases'/,
  );
  assert.match(
    postgresPolicyRunner,
    /rejects signed untyped semantics and caller-authored authority or currentness over HTTP/,
  );
  assert.match(command, /run-control-migration-upgrade\.sh/);
  assert.match(command, /tests\/integration\/identity\/run-participant-readback\.sh/);
  assert.match(command, /OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY=1/);
  assert.match(command, /suite_step roles env OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY=1 bash/);
  assert.match(
    command,
    /suite_step notifications env OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY=1 bash/,
  );
  assert.match(
    command,
    /node --import tsx tests\/integration\/local-runtime\/notification-browser\.mjs/,
  );
  assert.match(
    command,
    /suite_step governance env OPENPC_BROWSER_SCENARIOS=recovery,credentials,groups bash/,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/recovery-browser\.ts/,
  );
  assert.match(
    command,
    /suite_step governance env OPENPC_BROWSER_SCENARIOS=recovery,credentials,groups bash/,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/credential-browser\.ts/,
  );
  assert.match(
    command,
    /suite_step workloads env OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY=1 bash/,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/workload-browser\.ts/,
  );
  assert.match(
    command,
    /suite_step governance env OPENPC_BROWSER_SCENARIOS=recovery,credentials,groups bash/,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/group-browser\.ts/,
  );
  assert.match(composeRunner, /participant-role-browser\.mjs run/);
  assert.match(
    command,
    /suite_step directory env OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY=1 bash/,
  );
  assert.match(
    composeRunner,
    /node --import tsx tests\/integration\/local-runtime\/directory-browser\.ts/,
  );
  assert.match(composeRunner, /participant-role-browser\.mjs readback/);
  assert.match(composeRunner, /run_principal_browser\n {2}exit 0/);
  assert.match(composeRunner, /principal-browser\.mjs run/);
  assert.match(composeRunner, /principal-browser\.mjs readback/);
  assert.match(composeRunner, /run_principal_browser\n {2}run_grant_browser\n {2}exit 0/);
  assert.match(composeRunner, /grant-browser\.mjs run/);
  assert.match(composeRunner, /grant-browser\.mjs readback/);
  assert.match(composeRunner, /source tests\/integration\/local-runtime\/typed-policy-journey\.sh/);
  const policyJourney = await readFile(
    'tests/integration/local-runtime/typed-policy-journey.sh',
    'utf8',
  );
  const policyBrowser = await readFile(
    'tests/integration/local-runtime/policy-workbench-browser.mjs',
    'utf8',
  );
  assert.match(policyJourney, /policy-workbench-browser\.mjs run/u);
  assert.match(policyBrowser, /createPolicySetDraft\([\s\S]*\.policySetId/u);
  const databaseJourney = await readFile(
    'tests/integration/identity/run-participant-readback.sh',
    'utf8',
  );
  assert.match(databaseJourney, /tests\/integration\/identity\/postgres-policy-set\.test\.ts/u);
  assert.match(
    databaseJourney,
    /tests\/integration\/identity\/postgres-assignment-resume\.test\.ts/u,
  );
  assert.match(
    command,
    /suite_step visibility-and-explorer env OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY=1 bash/,
  );
  assert.match(
    composeRunner,
    /OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY.*export OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY=1/,
  );
  const explorerJourney = await readFile(
    'tests/integration/local-runtime/privacy-explorer-journey.sh',
    'utf8',
  );
  assert.match(explorerJourney, /privacy-explorer-journey\.mjs read/);
  assert.match(explorerJourney, /privacy-explorer-browser\.mjs/);
  assert.match(explorerJourney, /openpc_begin_explorer_pause paused-revoke/);
  assert.match(explorerJourney, /privacy-explorer-journey\.mjs "\$mode"/);
  assert.match(explorerJourney, /openpc_finish_explorer_pause/);
  assert.match(
    composeRunner,
    /typed_policy_reorg\s+if \[ "\$\{OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY/,
  );
  assert.match(entry, /run-compose-e2e\.sh --suite/);
  assert.match(
    command,
    /suite_step invitations env OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY=1 bash/,
  );
  assert.match(command, /suite_step signing env OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED=1 bash/);
});

test('CI reaches the guarded suite and ordinary tests reach operational regressions', () => {
  const runtime = workflow.split('  runtime-integration:')[1];
  assert.match(runtime, /OPENPC_SYSTEM_SCOPE: 1/);
  assert.match(runtime, /pnpm run test:integration:runtime/);
  assert.doesNotMatch(runtime, /exec 9>/);
  assert.match(
    packageDocument.scripts['test:integration:runtime'],
    /run-project\.sh --profile runtime -- bash .*run-compose-e2e\.sh --suite/,
  );
  assert.match(packageDocument.scripts['test:unit'], /browser-scenarios\.test\.mjs/);
  assert.match(packageDocument.scripts['test:unit'], /runner-boundary\.test\.mjs/);
  assert.match(packageDocument.scripts['test:unit'], /project-config\.test\.mjs/);
  assert.match(packageDocument.scripts['test:resources'], /project-toolchain\.test\.sh/);
  assert.match(packageDocument.scripts['test:resources'], /run-bounded\.test\.sh/);
});

test('ordinary resource admission rejects incomplete retained keeper budgets before dispatch', async () => {
  assert.match(packageDocument.scripts['test:resources'], /run-bounded\.test\.sh/);
  const result = spawnSync(
    'bash',
    ['scripts/maintenance/run-bounded.test.sh', '--memory-admission-only'],
    { encoding: 'utf8', timeout: 15000, maxBuffer: 65536 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /complete totals, no double charge and changed caps reject before dispatch/,
  );
  const owner = await readFile('scripts/maintenance/run-bounded.sh', 'utf8');
  assert.equal(
    owner.match(/retained_keeper_kib=\$\(openpc_retained_keeper_memory_kib\)/gu)?.length,
    2,
  );
  assert.match(owner, /openpc_admit_server_capacity/);
  assert.match(owner, /phase_floor_kib=\$OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB/);
  assert.match(owner, /reserve_disk_gib < 50/);
});

test('joined spool runner preserves Fact migration transactions and exact test selection', async () => {
  const runner = await readFile('tests/integration/local-runtime/run-decision-owner.py', 'utf8');
  assert.match(
    composeRunner,
    /suite_step spool-capacity python3 tests\/integration\/local-runtime\/run-decision-owner\.py --spool-capacity/u,
  );
  assert.match(runner, /"postgres_tls_joined_capacity_owner" if spool_capacity/u);
  assert.match(
    runner,
    /"identity_publication_tests::decision_owner::capacity::" if spool_capacity/u,
  );
  assert.match(runner, /"--", "--ignored", "--exact", full_test/u);
  const native = await readFile('services/runtime-agent/src/decision_owner_capacity.rs', 'utf8');
  assert.match(native, /async fn postgres_tls_joined_capacity_owner\(\)/u);
  const result = spawnSync(
    'python3',
    [
      '-c',
      `
import ast
from pathlib import Path
source = ast.parse(Path('tests/integration/local-runtime/run-decision-owner.py').read_text())
main = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
sql = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'sql')
calls = []
def run(*args, **kwargs):
    calls.append((args, kwargs))
    if kwargs['data'] == 'failed migration':
        raise RuntimeError('original migration failure')
namespace = dict(run=run, name='isolated-fixture')
exec(compile(ast.Module(body=[sql], type_ignores=[]), '<actual-runner-sql>', 'exec'), namespace)
namespace['sql']('openpc_control', 'CREATE DATABASE fixture;')
namespace['sql']('openpc_facts', 'LOCK TABLE facts.canonical_fact;', transaction=True)
assert '--single-transaction' not in calls[0][0]
assert calls[1][0][-3:] == ('--single-transaction', '-f', '-')
assert 'ON_ERROR_STOP=1' in calls[1][0]
try:
    namespace['sql']('openpc_facts', 'failed migration', transaction=True)
except RuntimeError as error:
    assert str(error) == 'original migration failure'
else:
    raise AssertionError('migration failure was swallowed')
migrations = [n for n in ast.walk(main) if isinstance(n, ast.Call)
    and isinstance(n.func, ast.Name) and n.func.id == 'sql'
    and len(n.args) == 2 and isinstance(n.args[1], ast.Call)
    and isinstance(n.args[1].func, ast.Attribute)
    and ast.unparse(n.args[1].func) == 'migration.read_text']
assert len(migrations) == 1
assert any(k.arg == 'transaction' and isinstance(k.value, ast.Constant) and k.value.value is True
    for k in migrations[0].keywords)
`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('the actual runtime suite continues independent commands and retains the first failure', async () => {
  const parent = resolve(process.env.RUNNER_TEMP ?? '../Agents/tmp');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'openpc-suite-dispatch-'));
  try {
    const helper = `#!/usr/bin/bash
printf '%s|%s\\n' "$(basename "$0")" "$*" >> "$OPENPC_TEST_INVOCATIONS"
if [[ "$*" == *'--test ads_transport'* ]]; then exit 29; fi
exit 0
`;
    for (const name of ['bash', 'cargo', 'node', 'python3'])
      await writeFile(join(root, name), helper, { mode: 0o700 });
    const invocations = join(root, 'calls');
    const result = spawnSync(
      '/usr/bin/bash',
      ['tests/integration/local-runtime/run-compose-e2e.sh', '--suite'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${root}:${process.env.PATH}`,
          OPENPC_TEST_INVOCATIONS: invocations,
        },
      },
    );
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /FAIL\|ads\|exit=29/);
    const calls = await readFile(invocations, 'utf8');
    assert.match(calls, /run-bounded\.sh --profile runtime --reuse -- true/);
    assert.match(calls, /provider_probe_worker::tests/);
    assert.match(result.stdout, /PASS\|module-lifecycle/);
    assert.match(
      calls,
      /python3\|tests\/integration\/local-runtime\/run-decision-owner\.py --spool-capacity/,
    );
    assert.match(result.stdout, /PASS\|spool-capacity/);
    assert.match(
      calls,
      /python3\|tests\/integration\/local-runtime\/run-decision-owner\.py --submission/,
    );
    assert.match(result.stdout, /PASS\|submission-owner/);
    assert.match(
      calls,
      /python3\|tests\/integration\/local-runtime\/run-decision-owner\.py --cigl-analysis/,
    );
    assert.match(result.stdout, /PASS\|cigl-analysis/);
    assert.match(
      calls,
      /python3\|tests\/integration\/local-runtime\/run-decision-owner\.py --cigl-revocation/,
    );
    assert.match(result.stdout, /PASS\|cigl-revocation/);
    assert.match(result.stdout, /PASS\|invitations/);
    assert.match(result.stdout, /PASS\|governance/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('portable CI selects public module behavior without historical qualification commands', () => {
  assert.match(packageDocument.scripts?.test, /test:unit.*test:resources/);
  const portable = packageDocument.scripts?.['test:unit'];
  assert.equal(typeof portable, 'string');
  assert.match(portable, /test:portable:ui-shell/);
  assert.match(portable, /test:portable:policy/);
  assert.doesNotMatch(portable, /bff-owner\.test\.ts/);
  assert.match(portable, /test:portable:modules/);
  assert.match(
    packageDocument.scripts?.['test:portable:modules'],
    /tests\/conformance\/modules\/portable\.vitest\.config\.ts/,
  );
  assert.equal(Object.hasOwn(packageDocument.scripts, 'test:c17'), false);
});

test('public resource guard refuses historical qualification before dispatch', async (t) => {
  const { root, env } = await closedPublicRunnerTools(t);
  delete env.OPENPC_OWNED_QA_ROOT;
  for (const capacity of ['0', '1']) {
    const result = spawnSync(
      '/bin/bash',
      [
        'scripts/maintenance/run-bounded.sh',
        '--profile',
        'legacy-qualification',
        '--',
        '/bin/sh',
        '-c',
        'printf dispatched',
      ],
      { env: { ...env, OPENPC_SERVER_CAPACITY: capacity }, encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 78, result.stderr);
    assert.match(result.stderr, /Legacy qualification has no verified resource owner/u);
    assert.equal(result.stdout, '');
  }
  assert.ok(!(await readdir(root)).includes('tools.log'), 'No owner or container tool may run');
  for (const name of [
    'assurance:repository-binding',
    'test:i01',
    'test:i04:local-overlay',
    'qualify:i04:local-overlay',
    'test:i08',
    'test:c17',
  ])
    assert.equal(Object.hasOwn(packageDocument.scripts, name), false, name);
});

test('ordinary tests continue independent suites and retain an earlier failure', async () => {
  const parent = resolve(process.env.RUNNER_TEMP ?? '../Agents/tmp');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'openpc-unit-dispatch-'));
  try {
    const calls = join(root, 'calls');
    await writeFile(
      join(root, 'bash'),
      `#!/usr/bin/bash
if [[ "$1" == scripts/maintenance/run-project.sh ]]; then
  shift
  while [[ "$1" != -- ]]; do shift; done
  shift
  exec "$@"
fi
exec /usr/bin/bash "$@"
`,
      { mode: 0o700 },
    );
    const helper = `#!/usr/bin/bash
printf '%s|%s\\n' "$(basename "$0")" "$*" >> "$OPENPC_TEST_INVOCATIONS"
if [[ "$*" == 'run test:unit' || "$*" == '-r '* ]]; then exit 29; fi
exit 0
`;
    for (const name of ['pnpm', 'node']) await writeFile(join(root, name), helper, { mode: 0o700 });
    for (const script of ['test', 'test:unit']) {
      const result = spawnSync('/usr/bin/bash', ['-c', packageDocument.scripts[script]], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${root}:${process.env.PATH}`,
          OPENPC_TEST_INVOCATIONS: calls,
        },
        timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1, result.stderr);
    }
    const executed = await readFile(calls, 'utf8');
    for (const suite of [
      'test:resources',
      'test:portable:ui-shell',
      'test:portable:modules',
      'test:portable:policy',
    ])
      assert.ok(executed.includes(`run ${suite}`), suite);
    assert.match(executed, /-r --no-bail --workspace-concurrency=1/);
    assert.match(executed, /node\|--test tests\/integration\/ci\/invocation\.test\.mjs/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('existing custody journeys execute family-specific provenance and browser oracles', async () => {
  const source = await readFile(
    new URL('../local-runtime/evidence-source-custody.mjs', import.meta.url),
    'utf8',
  );
  const effect = await readFile(
    new URL('../local-runtime/evidence-effect-custody.mjs', import.meta.url),
    'utf8',
  );
  const rpc = await readFile(
    new URL('../local-runtime/evidence-rpc-custody.mjs', import.meta.url),
    'utf8',
  );
  const rpcBrowser = await readFile(
    new URL('../local-runtime/evidence-rpc-browser.mjs', import.meta.url),
    'utf8',
  );
  for (const driver of [source, effect, rpc])
    assert.match(driver, /await verifyReceiptProvenanceSources\(/u);
  assert.match(source, /COSE_SIGN1_24001_1_338/u);
  assert.match(effect, /OPENPC_AUTHENTICATION_OCCURRENCE_V1/u);
  assert.match(effect, /requireRejection \? \['PC-DEPLOYMENT-RESERVATION-REJECTION-1'\]/u);
  assert.match(rpc, /await verifyRpcProjectionSqlGuards\(worker,\s*scope\)/u);
  assert.match(rpcBrowser, /await verifyPublicProvenance\(api,\s*provenance,\s*secretRoot\)/u);
  assert.match(rpcBrowser, /await inspectProvenanceWorkbench\(maker,\s*view,\s*artifacts\)/u);
});

test('ordinary identity CI restores quiesced current-schema remote custody and resumes only the restored owner', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-evidence-remote-restore.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const test = await readFile(path, 'utf8');
  const owner = await readFile(
    'tests/integration/identity/control-database-recovery-fixture.ts',
    'utf8',
  );
  assert.ok(test.includes('controlDatabaseRecoveryFixture'));
  assert.match(owner, /'pg_dump',\s*'-Fc'/u);
  assert.ok(owner.includes("'pg_restore'"));
  assert.ok(owner.includes("'--single-transaction'"));
  assert.ok(owner.includes('allow_connections false'));
  assert.ok(owner.includes("where datname='openpc_control'"));
  assert.ok(test.includes('await recovery.restore()'));
  assert.ok(test.includes('await reopened.forScope(scope).exportNext()'));
});

test('ordinary work-item CI runs connected contracts before allocating PostgreSQL and fails closed', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  for (const name of [
    'postgres-work-item-receipt-contract.test.ts',
    'postgres-work-item-journey.test.ts',
  ])
    assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(name));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + '\nesac'.length;
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.ok(preflight.includes('src/configuration/persistence/business-state/work-item.test.ts'));
  assert.ok(preflight.includes('src/db/function-grants.test.ts'));
  for (const failed of [0, 1, 2, 3]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(tests/integration/identity/postgres-work-item-journey.test.ts)
      calls=0
      check() { calls=$((calls+1)); if [ "$calls" = "$1" ]; then return 19; fi; }
      node() { check ${failed}; }
      pnpm() { check ${failed}; }
      ${preflight}
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
    assert.equal(result.stdout.includes('event=passed'), failed === 0);
  }
});

test('installed secret recipient CI rejects failed connected contracts before PostgreSQL allocation', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + '\nesac'.length;
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  for (const name of ['recipient', 'delivery']) {
    const file = `tests/integration/identity/postgres-secret-${name}.test.ts`;
    assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
    for (const failed of name === 'delivery' ? [0, 1, 2, 3, 4, 5] : [0, 1]) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
        test_files=(${file})
        calls=0
        check() { calls=$((calls+1)); if [ "$calls" = "${failed}" ]; then return 19; fi; }
        pnpm() { check; }
        node() { check; }
        ${preflight}
        printf 'DATABASE_ALLOCATION_ALLOWED\\n'
      `,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed ? 19 : 0, result.stderr);
      assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
    }
  }
  assert.ok(runner.includes('--profile database --external-memory-gib 1.5 --reuse -- true'));
  assert.ok(runner.includes('secret_consumer_interop=1'));
  assert.ok(
    runner.includes(
      'if [[ "$snapshot_interop" = 1 || "$secret_consumer_interop" = 1 ]]; then\n  # Real isolated candidate store',
    ),
  );
});

test('ordinary CI executes installation configuration behavior with the existing TypeScript loader', () => {
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --import tsx --test (?:[\w./-]+\.mjs )*scripts\/operations\/installation-config\.test\.mjs scripts\/operations\/installation-effective-projection\.test\.mjs scripts\/operations\/installation-preflight\.test\.mjs scripts\/operations\/test-secret-provider\.test\.mjs scripts\/operations\/test-fact-secret-mount\.test\.mjs scripts\/operations\/test-fact-secret-delivery\.test\.mjs tests\/recovery\/kubernetes-materialization\.test\.mjs \|\| status=1/u,
  );
  assert.match(packageDocument.scripts['test:unit'], /exit "\$status"/u);
  const kernel = workflow.slice(
    workflow.indexOf('- name: Real Fact secret tmpfs publication'),
    workflow.indexOf('\n  runtime-integration:'),
  );
  for (const required of [
    'run-project.sh --profile focused --external-memory-gib 0.25',
    '--memory 256m',
    '--cap-add DAC_OVERRIDE',
    '--env OPENPC_REQUIRE_FACT_SECRET_MOUNT=1',
    '--env OPENPC_REQUIRE_FACT_SECRET_DELIVERY=1',
    'node --import tsx --test --test-concurrency=1 scripts/operations/test-fact-secret-mount.test.mjs scripts/operations/test-fact-secret-delivery.test.mjs',
  ])
    assert.ok(kernel.includes(required), required);
});

test('Fact consumer CI fails closed before database allocation on every connected preflight', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const name = 'tests/integration/identity/postgres-evidence-fact-delivery.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(name));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + '\nesac'.length;
  const preflight = runner.slice(begin, end);
  assert.ok(preflight.includes('src/evidence/fact-delivery-contract.test.ts'));
  assert.ok(preflight.includes('src/fact-consumer/profile.test.ts'));
  for (const failed of [0, 1, 2, 3, 4, 5, 6]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
  test_files=(${name})
  calls=0
  check() { calls=$((calls+1)); if [ "$calls" = "$1" ]; then return 19; fi; }
  node() { check ${failed}; }
  pnpm() { check ${failed}; }
  ${preflight}
  printf 'DATABASE_ALLOCATION_ALLOWED\\n'
  `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('ordinary Fact custody verifies both native ACKs and final original producer delivery', async () => {
  const custody = await readFile(
    'tests/integration/local-runtime/evidence-fact-custody.mjs',
    'utf8',
  );
  assert.ok(custody.includes("from './evidence-fact-delivery-recovery.mjs'"));
  assert.ok(
    custody.includes(
      "await exerciseFactDeliveryRecovery(secretRoot, join(root, 'worker.json'), false)",
    ),
  );
  const recovery = await readFile(
    'tests/integration/local-runtime/evidence-fact-delivery-recovery.mjs',
    'utf8',
  );
  assert.ok(recovery.includes('await readFactEvidenceBatch('));
  assert.ok(recovery.includes('TEST_FACT_INBOX_COMMIT_LOSS'));
  assert.ok(
    recovery.includes(
      'original catalogue, payload custody and retired projection absence survive recovery',
    ),
  );
  assert.ok(recovery.includes("outboxState: 'DELIVERED'"));
  assert.ok(recovery.includes('await verifyProducerFactDelivery('));
  assert.ok(recovery.includes('await verifyFleetFactDelivery('));
  assert.ok(recovery.includes('facts.control_admission_custody_ack'));
  assert.ok(recovery.includes('controlCustodyAcks: acks.length'));
});

test('ordinary notification CI runs connected contracts before allocating PostgreSQL and fails closed', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  for (const name of [
    'postgres-notification-receipt-contract.test.ts',
    'postgres-notification-journey.test.ts',
    'postgres-notification-endpoint-journey.test.ts',
  ])
    assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(name));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + '\nesac'.length;
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.ok(preflight.includes('src/notifications/business-state.test.ts'));
  assert.ok(preflight.includes('src/notifications/gateway-contracts.test.ts'));
  assert.ok(preflight.includes('src/notifications/endpoint-binding.test.ts'));
  assert.ok(preflight.includes('src/notifications/endpoint-business-state.test.ts'));
  assert.ok(preflight.includes('src/notifications/endpoint-owner-contract.test.ts'));
  assert.ok(preflight.includes('src/notification-gateway/codec.test.ts'));
  assert.ok(preflight.includes('src/notification-gateway/worker-contract.test.ts'));
  assert.ok(preflight.includes('src/db/function-grants.test.ts'));
  assert.ok(preflight.includes('src/notifications/routing-installation-contract.test.ts'));
  assert.ok(preflight.includes('src/notifications/template-renderer.test.ts'));
  assert.ok(preflight.includes('notification-routing-installation-cases.ts'));
  for (const [file, count] of [
    ['postgres-notification-journey.test.ts', 4],
    ['postgres-notification-endpoint-journey.test.ts', 7],
  ]) {
    for (let failed = 0; failed <= count; failed++) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
      test_files=(tests/integration/identity/${file})
      calls=0
      check() { calls=$((calls+1)); if [ "$calls" = "$1" ]; then return 19; fi; }
      node() { check ${failed}; }
      pnpm() { check ${failed}; }
      ${preflight}
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
      assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
      assert.equal(result.stdout.includes('event=passed'), failed === 0);
    }
  }
});

test('ordinary CI executes notification gateway TLS with its real database prerequisite', async () => {
  const file = 'tests/integration/local-runtime/notification-gateway-fixture.test.mjs';
  assert.ok(!packageDocument.scripts['test:unit'].includes(file));
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  assert.ok(
    runner.slice(runner.indexOf('test_files=('), runner.indexOf('if [ "$#"')).includes(file),
  );
  assert.ok(runner.includes('node --import tsx --test "${test_files[0]}"'));
});

test('Fact PostgreSQL readiness waits for the final TCP server, not the temporary bootstrap socket', async () => {
  const runner = await readFile('tests/integration/facts/run-postgres18-gate3-proof.sh', 'utf8');
  const start = runner.indexOf('for _ in $(seq 1 60); do');
  const end = runner.indexOf('\nphase=migrations', start);
  assert.ok(start > 0 && end > start);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
    container_name=fixture
    probes=0
    docker() {
      [[ $* == 'exec fixture pg_isready -h 127.0.0.1 -U postgres -d openpc_facts' ]] || return 22
      probes=$((probes+1))
      [[ $probes -ge 2 ]]
    }
    sleep() { :; }
    ${runner.slice(start, end)}
    [[ $probes == 3 ]]
  `,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.ok(runner.includes('FACT_STORE_DIAGNOSTICS|phase=%s|path=%s'));
});

test('Fleet admission is included in ordinary database CI and its preflight fails closed', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const name = 'tests/integration/identity/postgres-fleet-fact-admission.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(name));
  assert.ok(
    runner
      .slice(0, runner.indexOf('if [ "$#"'))
      .includes('tests/integration/identity/postgres-fact-consumer-profile.test.ts'),
  );
  const start = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', start) + '\nesac'.length;
  assert.ok(runner.slice(start, end).includes('src/fact-consumer/profile.test.ts'));
  assert.ok(runner.slice(start, end).includes('src/evidence/fact-failure-source.test.ts'));
  for (const failed of [0, 1, 2, 3, 4]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${name})
      calls=0
      check() { calls=$((calls+1)); if [[ $calls == ${failed} ]]; then return 19; fi; }
      node() { check; }
      pnpm() { check; }
      ${runner.slice(start, end)}
      echo DATABASE_ALLOCATION_ALLOWED
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed === 0 ? 0 : 19, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
  }
});

test('Fleet native profile verifier compilation blocks database allocation on failure', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const start = runner.indexOf(
    'if [ "$snapshot_interop" = 1 ] || [ "$fleet_profile_interop" = 1 ]; then',
  );
  const end = runner.indexOf('\nmkdir "$root/secrets"', start);
  assert.ok(start > 0 && end > start);
  const scratch = resolve(process.env.RUNNER_TEMP ?? '../Agents/tmp');
  await mkdir(scratch, { recursive: true });
  const root = await mkdtemp(join(scratch, 'fleet-profile-dispatch-'));
  try {
    for (const failed of ['none', 'compile', 'native']) {
      const result = spawnSync(
        'bash',
        [
          '-c',
          `set -euo pipefail
root=$1
snapshot_interop=0
fleet_profile_interop=1
cargo() {
  [[ $* == 'test -p openpc-fact-service --lib --locked --offline --no-run --message-format=json' ]] || return 23
  if [[ ${failed === 'compile' ? 1 : 0} == 1 ]]; then return 19; fi
  printf '%s\\n' '{"reason":"compiler-artifact","target":{"name":"openpc_fact_service"},"profile":{"test":true},"executable":"/owned/native-profile-test"}'
}
pnpm() {
  [[ $* == *'src/fact-consumer/profile.test.ts src/fact-consumer/failure.test.ts --testNamePattern=native (failure|profile) wire interoperability' ]] || return 23
  [[ $OPENPC_FACT_WORKLOAD_TEST_BINARY == /owned/native-profile-test ]] || return 23
  if [[ ${failed === 'native' ? 1 : 0} == 1 ]]; then return 19; fi
}
${runner.slice(start, end)}
[[ $OPENPC_FACT_WORKLOAD_TEST_BINARY == /owned/native-profile-test ]]
echo DATABASE_ALLOCATION_ALLOWED
`,
          'fleet-profile-dispatch',
          root,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(result.status, failed === 'none' ? 0 : 19, result.stderr);
      assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 'none');
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('I03 fault fixture holds a private live owner lock and cleans up before failed allocation', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'i03-owner-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const start = postgresPolicyRunner.indexOf('readonly fixture_parent=');
  const end = postgresPolicyRunner.indexOf('\ndocker run --detach', start);
  assert.ok(start > 0 && end > start);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
export OPENPC_LOCAL_RUNTIME_TMP_ROOT="$1"
docker() { return 1; }
cargo() {
  [[ $OPENPC_I03_FIXTURE_OWNER_PID == $$ ]]
  [[ $(readlink /proc/$$/fd/8) == "$OPENPC_I03_FIXTURE_ROOT/.owner" ]]
  if flock -n "$OPENPC_I03_FIXTURE_ROOT/.owner" true; then return 97; fi
  printf 'OWNED_FIXTURE_LOCKED\\n'
  return 19
}
${postgresPolicyRunner.slice(start, end)}
`,
      'i03-owner-test',
      root,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 19, result.stderr);
  assert.equal(result.stdout.trim(), 'OWNED_FIXTURE_LOCKED');
  assert.deepEqual(await readdir(root), []);
  assert.match(postgresPolicyRunner, /--label "io.openpc.test-owner=\$fixture_root"/);
  assert.match(postgresPolicyRunner, /OPENPC_I03_FIXTURE_CONTAINER_ID=\$\(docker inspect/);
});

test('notification gateway TLS dispatch requires the real I02 database owner', async (t) => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'notification-dispatch-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/local-runtime/notification-gateway-fixture.test.mjs';
  assert.ok(!packageDocument.scripts['test:unit'].includes(file));
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const start = runner.indexOf(
    'if [[ "${test_files[0]}" == tests/integration/local-runtime/control-installation.test.mjs ',
    runner.indexOf('export OPENPC_I02_RUNTIME_DATABASE_URL='),
  );
  const end = runner.indexOf('\n# Initial trust verification', start);
  assert.ok(start > runner.indexOf('export OPENPC_I02_RUNTIME_DATABASE_URL='));
  assert.ok(end > start);
  const result = spawnSync(
    'bash',
    [
      '-c',
      `set -euo pipefail
test_files=("$1")
root="$2"
node() { printf '%s\\n' "$*"; }
pnpm() { return 97; }
${runner.slice(start, end)}
`,
      'notification-dispatch',
      file,
      root,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), '--import tsx --test ' + file);
});

test('Fact candidate lifecycle stays on the real Identity interoperability path', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const caller = await readFile(
    'tests/integration/identity/postgres-runtime-snapshot.test.ts',
    'utf8',
  );
  const native = await readFile('services/fact-service/src/workload_authority/tests.rs', 'utf8');
  assert.ok(runner.includes('tests/integration/identity/postgres-runtime-snapshot.test.ts'));
  assert.ok(runner.includes('sh /local/migrate.sh candidate_index'));
  assert.ok(runner.includes('export OPENPC_FACT_CANDIDATE_SESSION_TEST_URL='));
  assert.ok(
    caller.includes(
      'workload_authority::tests::installed_mtls_identity_requires_current_scoped_fact_permission',
    ),
  );
  assert.ok(native.includes('assert_installed_connection_lifecycle('));
});

test('fresh configuration step-up CI rejects failed proof contracts before database allocation', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const scenario = 'tests/integration/identity/postgres-configuration-step-up.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(scenario));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + '\nesac'.length;
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  for (const status of [0, 19]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
      test_files=(${scenario})
      pnpm() { [[ "$*" == *src/configuration/local-authorization-contract.test.ts* ]] || return 23; return ${status}; }
      ${preflight}
      printf 'DATABASE_ALLOCATION_ALLOWED\\n'
    `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), status === 0);
  }
});

test('retention search browser has isolated initial actors and fails closed in the terminal runtime phase', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const block = journey.slice(
    journey.indexOf('openpc_phase_begin retention-search-browser'),
    journey.indexOf('openpc_phase_end retention-search-browser 0') +
      'openpc_phase_end retention-search-browser 0'.length,
  );
  assert.ok(block.startsWith('openpc_phase_begin retention-search-browser'));
  assert.match(composeRunner, /--projection-deletion 018f0021-0000-7000-8000-000000000201/u);
  for (const fails of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
root=owned
openpc_phase_begin() { printf 'begin:%s\\n' "$1"; }
openpc_phase_end() { printf 'end:%s:%s\\n' "$1" "$2"; }
openpc_compose_json() { printf '[]'; }
node() { [[ $* == *'evidence-projection-deletion-browser.mjs --retention-search owned []' ]]; ${fails ? 'return 73' : ':'}; }
${block}`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, fails ? 73 : 0, result.stderr);
    assert.equal(result.stdout.includes('end:retention-search-browser:0'), !fails);
  }
  const participant = '018f0000-0000-7000-8000-000000000101';
  const privacy = '018f0021-0000-7000-8000-000000000201';
  const foreign = '018f0000-0000-7000-8000-000000000201';
  const actor = (selected, other) =>
    spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        'preflight-only',
        'preflight-only',
        participant,
        'bootstrap-evidence-retention-search',
        selected,
        other,
        '--preflight',
      ],
      { encoding: 'utf8', timeout: 15000 },
    );
  const valid = actor(privacy, foreign);
  assert.equal(valid.status, 0, valid.stderr);
  const definition = JSON.parse(valid.stdout);
  assert.deepEqual(definition.privacyDomainIds, [privacy, foreign]);
  assert.equal(definition.actors.maker.principalId, '018f0021-0000-7000-8000-000000000141');
  assert.equal(definition.actors.checker.principalId, '018f0021-0000-7000-8000-000000000142');
  assert.notEqual(actor(foreign, privacy).status, 0);
  assert.notEqual(actor(privacy, privacy).status, 0);
});

test('terminal Candidate database recovery requires prior journeys and preserves failure', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = journey.indexOf('openpc_phase_begin candidate-database-recovery');
  assert.ok(start > journey.indexOf('openpc_phase_end retention-search-browser 0'));
  const block = journey.slice(start);
  for (const failed of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
openpc_phase_begin() { :; }
openpc_candidate_database_recovery() { ${failed ? 'return 71' : ':'}; }
openpc_fact_database_recovery() { :; }
openpc_phase_end() { printf '%s:%s\\n' "$1" "$2"; }
${block}`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 71 : 0, result.stderr);
    assert.equal(result.stdout.includes('candidate-database-recovery:0'), !failed);
  }
  const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const body = harness.slice(harness.indexOf('openpc_candidate_database_recovery()'));
  assert.match(body, /openpc_require_execution runtime-target/u);
  assert.match(body, /candidate_index-roles/u);
  assert.match(body, /assert\.equal\(api\.Image,apiImage\)/u);
  assert.doesNotMatch(body, /openpc_verify_running_images control-api/u);
  assert.match(body, /assert\.equal\(source\.State\.Running,true\)/u);
  assert.doesNotMatch(body, /DROP DATABASE|pg_restore --create/u);
  assert.match(body, /--memory-swap','1g'/u);
  assert.match(body, /OPENPC_CANDIDATE_DATABASE_RESTORE:'1'/u);
  assert.match(body, /postgres-candidate-database-recovery\.test\.ts/u);
  assert.ok(body.indexOf("run(['stop',...stopped") < body.indexOf("run(['run','-d'"));
});

test('native Fleet work-item lifecycle follows its producer and blocks terminal recovery on failure', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = journey.indexOf('openpc_phase_begin native-fleet-work-item-browser');
  const end = journey.indexOf('openpc_phase_begin fact-retirement-browser', start);
  assert.ok(
    start >
      journey.indexOf(
        'source tests/integration/local-runtime/evidence-fleet-quarantine-journey.sh',
      ),
  );
  assert.ok(end > start && end < journey.indexOf('openpc_phase_begin candidate-database-recovery'));
  for (const failed of [false, true]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
openpc_phase_begin() { :; }
openpc_native_fleet_work_item_browser() { ${failed ? 'return 73' : ':'}; }
openpc_phase_end() { printf '%s:%s\\n' "$1" "$2"; }
${journey.slice(start, end)}
printf 'dependent-phase-ready\\n'
`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 73 : 0, result.stderr);
    assert.equal(result.stdout.includes('dependent-phase-ready'), !failed);
  }
  const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  const body = harness.slice(harness.indexOf('openpc_native_fleet_work_item_browser()'));
  assert.match(body, /OPENPC_WORK_ITEM_NATIVE_FLEET_MODE=LIFECYCLE/u);
  assert.match(body, /--work-item-trust/u);
  assert.match(composeRunner, /signing-provider-bootstrap\.ts[^\n]+--work-item/u);
  assert.match(body, /rpc-acquisition-\$\{generation\}\/candidate\.json/u);
  assert.doesNotMatch(body, /ORDER BY.*DESC|LIMIT 1/iu);
  assert.ok(body.indexOf('--preflight') < body.indexOf('business-signing-bootstrap.mjs'));
});

test('ordinary evidence KMS CI checks contracts before isolated PostgreSQL recovery', async () => {
  const tail = await readFile(
    'services/control-api/src/configuration/generate-security-tail.mjs',
    'utf8',
  );
  assert.ok(tail.includes('verifyConditionCases(migrationSql);'));
  assert.ok(
    tail.indexOf('verifyConditionCases(migrationSql);') <
      tail.indexOf('await writeFile(path, migrationSql'),
  );
  assert.ok(
    tail.indexOf('${evidenceKmsPreparationGuardsSql}') <
      tail.indexOf('${evidenceKmsReceiptGuardsSql}'),
  );
  assert.ok(
    tail.indexOf('${notificationKeyCustodyGuardsSql}') >
      tail.indexOf('${evidenceKmsReceiptGuardsSql}'),
  );
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-evidence-kms.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const start = runner.indexOf(`  ${file})`);
  const end = runner.indexOf('    ;;', start);
  assert.ok(start >= 0 && end > start);
  const preflight = runner.slice(start, end);
  for (const name of [
    'src/evidence-kms/codec.test.ts',
    'src/notification-gateway/codec.test.ts',
    'src/notification-gateway/worker-contract.test.ts',
    'src/domain/evidence-key-recipient.test.ts',
    'src/domain/notification-receipt-provider.test.ts',
    'src/domain/notification-cancellation-receipt-provider.test.ts',
    'src/domain/notification-outcome-receipt-provider.test.ts',
    'src/domain/notification-completion-worker.test.ts',
    'src/domain/notification-completion-disposition-provider.test.ts',
    'src/notifications/completion-disposition-publication.test.ts',
    'src/notifications/completion-disposition-registration.test.ts',
    'src/domain/http-notification-receipt-provider.test.ts',
    'src/notifications/receipt-signer-installation.test.ts',
    'src/notifications/delivery-failure-work-contract.test.ts',
    'src/notifications/delivery-cancellation-contract.test.ts',
    'src/notifications/delivery-outcome-contract.test.ts',
    'src/notifications/delivery-outcome-state.test.ts',
    'src/notifications/delivery-outcome-runtime.test.ts',
    'src/notifications/delivery-outcome-guards.test.ts',
    'src/notifications/delivery-cancellation-state.test.ts',
    'src/notifications/receipt-signer-guards.test.ts',
    'src/notifications/delivery-runtime.test.ts',
    'src/notifications/packaged-delivery-runtime.test.ts',
    'src/notifications/async-admission.test.ts',
    'src/operations-configuration/notification-async.test.ts',
    'src/notifications/delivery-material-context.test.ts',
    'src/notifications/delivery-material.test.ts',
    'src/notifications/delivery-provider.test.ts',
    'src/notifications/gateway-adapter.test.ts',
    'src/notifications/gateway-contracts.test.ts',
    'src/notifications/delivery-signing-contract.test.ts',
    'src/notifications/delivery-signing-state.test.ts',
    'src/notifications/delivery-signing-runtime.test.ts',
    'src/notifications/delivery-signing-guards.test.ts',
    'src/notifications/delivery-start-atomic.test.ts',
    'src/notifications/delivery-dispatch-state.test.ts',
    'src/notifications/delivery-dispatch-guards.test.ts',
    'src/notifications/delivery-start-atomic-guards.test.ts',
    'src/evidence/kms-contracts.test.ts',
    'src/evidence/kms-state.test.ts',
    'src/evidence/notification-payload-crypto.test.ts',
    'src/evidence/notification-key-custody.test.ts',
    'src/evidence/notification-payload-retirement-source.test.ts',
    'src/evidence/notification-payload-reader.test.ts',
    'src/notifications/routing-installation-contract.test.ts',
    'src/notifications/template-renderer.test.ts',
    'src/notifications/delivery-start-state.test.ts',
    'src/notifications/delivery-start-guards.test.ts',
    'src/notifications/delivery-start-preparation.test.ts',
    'src/notifications/delivery-start-preparation-guards.test.ts',
    'src/notifications/delivery-adapter-context.test.ts',
    'src/notifications/delivery-policy.test.ts',
  ])
    assert.ok(preflight.includes(name));
  assert.ok(preflight.includes('pnpm exec tsc'));
  assert.ok(!preflight.includes('|| true'));
  const migration = await readFile(
    'migrations/postgres/control-api/0118_notification_key_custody.sql',
    'utf8',
  );
  const referenceGrant = migration.indexOf(
    'GRANT REFERENCES(participant_id,privacy_domain_id,key_id)',
  );
  const referenceUse = migration.indexOf('ADD CONSTRAINT "notification_key_ciphertext_wrapped_fk"');
  const referenceRevoke = migration.indexOf(
    'REVOKE ALL ON control.evidence_kms_attempt,control.evidence_wrapped_key,control.evidence_kms_exchange FROM openpc_control_owner',
  );
  assert.ok(referenceGrant >= 0 && referenceGrant < referenceUse && referenceUse < referenceRevoke);
  const scenario = await readFile(file, 'utf8');
  assert.ok(scenario.includes('controlDatabaseRecoveryFixture'));
  assert.ok(scenario.includes('await recovery.restore()'));
  assert.ok(scenario.includes('assertNotificationKeyCustodyCases'));
  assert.ok(scenario.includes('prepareNotificationKeyExports'));
  assert.ok(scenario.includes('prepareNotificationKeyRouting'));
  assert.ok(scenario.includes('assertNotificationPayloadReadCases'));
});

test('ordinary export CI joins published notification source and real worker admission', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const block = runner.slice(
    runner.indexOf(
      'if [[ "${test_files[0]}" == tests/integration/identity/postgres-evidence-export.test.ts ]]',
    ),
  );
  for (const name of [
    'src/notifications/published-source.test.ts',
    'src/notifications/worker-installation-contract.test.ts',
  ])
    assert.ok(block.slice(0, block.indexOf('    fi')).includes(name));
  const cases = await readFile(
    'tests/integration/identity/export-completion-preparation-cases.ts',
    'utf8',
  );
  assert.ok(cases.includes('await assertPublishedNotificationSourceReadbackCases({'));
  assert.ok(cases.includes('await assertNotificationWorkerAdmissionCases({'));
  assert.ok(cases.includes('await withNotificationWorkerPeer('));
});

test('ordinary first-policy CI connects the actual retired RPC IDs to payload and search acceptance', async () => {
  assert.match(
    composeRunner,
    /suite_step first-policy-rpc env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1/,
  );
  const source = await readFile('tests/integration/local-runtime/evidence-rpc-custody.mjs', 'utf8');
  assert.match(source, /const retiredRpcRecordIds = await projectionDeletionBrowser/);
  assert.match(source, /await withRpcPayloadRetirementSigning/);
  assert.match(source, /recordIds: retiredRpcRecordIds/);
  assert.match(source, /compose: signingCompose/);
  assert.match(source, /rpcPayloadRecordIds: retiredRpcRecordIds/);
  const driver = await readFile(
    'tests/integration/local-runtime/evidence-projection-deletion-browser.mjs',
    'utf8',
  );
  assert.match(driver, /retiredRpcRecordIds = await rpcProjectionRetirementBrowser/);
  assert.match(driver, /return retiredRpcRecordIds/);
});

test('notification database admission preflight includes historical STARTED transition integrity', async () => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const begin = source.indexOf('tests/integration/identity/postgres-notification-*.test.ts|');
  const end = source.indexOf(';;', begin);
  assert.ok(begin > 0 && end > begin);
  assert.ok(
    source.slice(begin, end).includes('src/notifications/delivery-start-transition.test.ts'),
  );
});

test('ordinary identity CI exercises runtime artifact producer and disposition contention', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-runtime-artifact-fence.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  assert.match(
    runner.slice(begin, end),
    /pnpm exec tsc[^\n]+postgres-runtime-artifact-fence\.test\.ts/u,
  );
});

test('ordinary identity CI checks runtime artifact source custody under its real database roles', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-runtime-artifact-source.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(`  ${path})`);
  const end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  assert.match(
    runner.slice(begin, end),
    /pnpm exec tsc[^\n]+postgres-runtime-artifact-source\.test\.ts/u,
  );
  assert.match(runner.slice(begin, end), /cargo test[^\n]+runtime_artifact_source/u);
  assert.match(
    runner.slice(begin, end),
    /cargo test[^\n]+physical_retirement_consumes_real_typescript_profile_cose_trust_state_and_event/u,
  );
  for (const required of [
    'src/evidence/runtime-artifact-disposition-state.test.ts',
    'src/configuration/problem.test.ts',
    'src/db/function-grants.test.ts',
    'validates source-disposition request inputs before database allocation|classifies only exact runtime-source producer contention',
  ])
    assert.ok(
      runner.slice(begin, end).includes(required),
      `Missing connected source preflight: ${required}`,
    );
  assert.ok(
    runner.includes(
      'runtime_artifact_source::postgres_tests:: -- --include-ignored --test-threads=1',
    ),
  );
  const native = await readFile(
    'services/fleet-controller/src/runtime_artifact_source/disposition.rs',
    'utf8',
  );
  const installed = await readFile(
    'services/fleet-controller/src/runtime_artifact_source/postgres_tests.rs',
    'utf8',
  );
  assert.ok(native.includes('fn source_denial_wire_matches_control_consumer()'));
  assert.ok(native.includes('tests/integration/identity/runtime-artifact-denial-wire.mjs'));
  assert.ok(installed.includes('fn postgres_source_denial_wire_matches_control_consumer()'));
  assert.ok(installed.includes('super::disposition::tests::control_wire(true)'));
  const admission = runner.indexOf(
    'if [[ "$test_file" == tests/integration/identity/postgres-runtime-artifact-source.test.ts ]]',
  );
  assert.ok(admission > 0 && admission < runner.indexOf('docker run -d'));
  assert.match(
    runner.slice(admission, runner.indexOf('\n  fi', admission)),
    /--memory-gib 8 --peak-disk-gib 40 --reuse/u,
  );
});

test('ordinary runtime CI dispatches governed source disposition with packaged input preflight', async () => {
  const runner = await readFile('tests/integration/local-runtime/run-compose-e2e.sh', 'utf8');
  assert.ok(
    runner.includes('--runtime-source-disposition "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"'),
  );
  assert.match(
    runner,
    /suite_step runtime-source-disposition env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY=1 bash "\$0"/u,
  );
  const harness = await readFile('tests/integration/local-runtime/runner-harness.sh', 'utf8');
  assert.ok(
    harness.includes('"$secret_root" "$participant" "$privacy" --runtime-source-disposition-trust'),
  );
  assert.ok(harness.includes('runtime-source-disposition-journey.mjs" --preflight'));
  assert.ok(harness.includes('runtime-source-retirement-journey.mjs" --preflight'));
  assert.ok(
    harness.includes(
      'runtime-source-disposition-journey.mjs" --native-preflight "${openpc_built_images[control-worker]}"',
    ),
  );
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const dispatch = journey.indexOf(
    'source tests/integration/local-runtime/runtime-source-disposition-journey.sh',
  );
  assert.ok(dispatch > journey.indexOf('openpc_phase_end first-policy-discovery 0'));
  assert.ok(dispatch < journey.indexOf('openpc_phase_begin first-policy-source'));
  const retirementDispatch = journey.indexOf(
    'source tests/integration/local-runtime/runtime-source-retirement-journey.sh',
  );
  assert.ok(
    retirementDispatch > dispatch &&
      retirementDispatch < journey.indexOf('openpc_phase_begin first-policy-source'),
  );
  const source = await readFile(
    'tests/integration/local-runtime/runtime-source-disposition-journey.sh',
    'utf8',
  );
  for (const step of [
    'source_journey import old',
    'source_journey import successor',
    'source_journey archive',
    'node --import tsx tests/integration/local-runtime/runtime-source-disposition-selection.mjs "$root" "$retention_urn" "$source_case"',
    'source_journey plan successor',
    'source_journey plan old',
    'source_journey reconcile "$source_disposition_evidence/native-resume-before.json"',
    'native_readback="$source_disposition_evidence/native-reconciled-readback.json"',
    'approved_configuration_post "$source_disposition_evidence/admission.json"',
    'source_journey verify "$source_disposition_evidence/restart-readback.json"',
  ])
    assert.ok(source.includes(step), step);
  const sourceHelper = await readFile(
    'tests/integration/local-runtime/runtime-source-disposition-journey.mjs',
    'utf8',
  );
  assert.ok(
    sourceHelper.includes(
      'await continueRuntimeSourceArchive(root, compose, database, sourceCase)',
    ),
  );
});

test('physical retirement consumes exact live replay before native recovery and blocks dependent dispatch', () => {
  for (const [resume, failedPhase] of [
    ['', ''],
    ['', 'plan'],
    ['', 'replay'],
    ['native', ''],
    ['approval', ''],
    ['approval', 'recovery'],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `
set -euo pipefail
root=/fixture
compose=(compose_stub)
worker_container=worker
participant_id=participant
privacy_domain_id=privacy
evidence_root=/fixture/evidence
retention_urn=urn:openpc:resource:policy
openpc_require_inputs() { :; }
openpc_compose_json() { printf '[]'; }
action_digest() { printf 'digest'; }
assert_json_equal() { printf 'equal\\n' >&2; }
openpc_verify_running_images() { :; }
compose_stub() { printf 'compose:%s\\n' "$1" >&2; }
approved_configuration_post() { printf 'commit:%s\\n' "$1" >&2; }
configuration_post() {
  printf 'replay:%s\\n' "$4" >&2
  [[ $FAILED_PHASE != replay ]] || return 73
}
node() {
  if [[ $* == *runtime-source-retirement-recovery.mjs* ]]; then
    printf 'recovery:%s\\n' "$4" >&2
    [[ $4 != resume || $FAILED_PHASE != recovery ]] || return 73
  elif [[ $* == *runtime-source-retirement-journey.mjs* ]]; then
    printf 'phase:%s:%s\\n' "$4" "\${7:-}" >&2
    [[ $4 != "$FAILED_PHASE" ]] || return 73
  elif [[ $* == *runtime-source-disposition-selection.mjs* ]]; then
    printf 'selection:%s\\n' "\${7:-}" >&2
  elif [[ $1 == - ]]; then cat >/dev/null; printf '{}'; fi
}
source tests/integration/local-runtime/runtime-source-retirement-journey.sh
`,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          OPENPC_RUNTIME_SOURCE_RETIREMENT_RESUME: resume,
          FAILED_PHASE: failedPhase,
        },
      },
    );
    assert.equal(result.status, failedPhase ? 73 : 0, result.stderr);
    const steps = result.stderr.trim().split('\n');
    const at = (prefix) => steps.findIndex((step) => step.startsWith(prefix));
    if (resume) {
      assert.equal(at('commit:'), -1);
      assert.equal(at('replay:'), -1);
      assert.equal(at('selection:'), -1);
      if (resume === 'approval') assert.ok(at('recovery:resume') >= 0);
      else assert.equal(at('recovery:resume'), -1);
    } else if (failedPhase === 'plan') {
      assert.equal(at('commit:'), -1);
      assert.equal(at('replay:'), -1);
    } else {
      assert.ok(at('commit:') > at('phase:validate-body:'));
      assert.ok(at('phase:effect:before-replay') > at('commit:'));
      assert.ok(at('replay:runtime-source-retirement-0001') > at('phase:effect:before-replay'));
      if (!failedPhase) assert.ok(at('phase:effect:after-replay') > at('replay:'));
    }
    if (failedPhase) {
      assert.equal(at('phase:verify:'), -1);
      assert.equal(at('compose:restart'), -1);
    } else {
      assert.ok(at('recovery:committed') >= 0);
      assert.ok(at('phase:continuation:') > at('phase:verify:native'));
      assert.ok(at('compose:restart') > at('phase:continuation:'));
      assert.ok(at('phase:verify:restart') > at('compose:restart'));
    }
  }
});

test('source disposition consumes live replay before polling and recovery never resubmits', () => {
  for (const [sourceCase, resume, replayFails] of [
    ['original', 'governed', false],
    ['live-replay', '', false],
    ['original', 'native', false],
    ['original', 'restart', false],
    ['original', 'governed', true],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `
set -euo pipefail
root=/fixture
compose=(compose_stub)
worker_container=worker
participant_id=participant
privacy_domain_id=privacy
evidence_root=/fixture/evidence
openpc_require_inputs() { :; }
openpc_compose_json() { printf '[]'; }
operation_field() { printf 'urn:openpc:resource:original'; }
action_digest() { printf 'digest'; }
assert_json_equal() { printf 'equal\\n' >&2; }
openpc_verify_running_images() { :; }
compose_stub() { printf 'compose:%s\\n' "$1" >&2; }
configuration_get() { printf 'get:%s\\n' "$1" >&2; }
configuration_post() {
  printf 'post:%s:%s\\n' "$1" "$4" >&2
  if [[ $1 == */replay.json && $REPLAY_FAILS == 1 ]]; then return 73; fi
}
approved_configuration_post() { printf 'commit:%s\\n' "$1" >&2; }
node() {
  if [[ $* == *runtime-source-disposition-journey.mjs* ]]; then
    printf 'phase:%s:%s\\n' "$4" "\${7:-}" >&2
  elif [[ $* == *runtime-source-disposition-selection.mjs* ]]; then
    printf 'selection\\n' >&2
  elif [[ $* == *runtime-source-disposition-recovery.mjs* ]]; then
    printf 'retention-readback\\n' >&2
  elif [[ $1 == - ]]; then
    cat >/dev/null
    printf '{}'
  fi
}
source tests/integration/local-runtime/runtime-source-disposition-journey.sh
`,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          OPENPC_RUNTIME_SOURCE_DISPOSITION_CASE: sourceCase,
          OPENPC_RUNTIME_SOURCE_DISPOSITION_RESUME: resume,
          REPLAY_FAILS: replayFails ? '1' : '0',
        },
      },
    );
    assert.equal(result.status, replayFails ? 73 : 0, result.stderr);
    const steps = result.stderr.trim().split('\n');
    const index = (prefix) => steps.findIndex((v) => v.startsWith(prefix));
    const commit = index('commit:'),
      replay =
        index('post:') >= 0
          ? steps.findIndex((v) => v.startsWith('post:') && v.includes('/replay.json:'))
          : -1;
    if (resume === 'native' || resume === 'restart') {
      assert.equal(commit, -1);
      assert.equal(replay, -1);
      assert.ok(index('compose:restart') > index('get:'));
    } else {
      assert.ok(commit >= 0 && replay > commit);
      assert.ok(index('phase:effect:before-replay') > commit);
      assert.ok(index('phase:effect:before-replay') < replay);
      if (replayFails) {
        assert.equal(index('get:'), -1);
        assert.equal(index('compose:restart'), -1);
      } else {
        assert.ok(index('phase:effect:after-replay') > replay);
        assert.ok(index('get:') > replay);
        assert.ok(index('compose:restart') > index('get:'));
      }
      if (sourceCase === 'live-replay') {
        assert.ok(index('retention-readback') > index('phase:archive:'));
        assert.ok(
          steps.some((v) =>
            v.includes('/live-replay/replay.json:runtime-source-live-replay-disposition-0001'),
          ),
        );
        assert.equal(steps.filter((v) => v.startsWith('commit:')).length, 1);
      }
    }
  }
});

test('ordinary identity CI dispatches runtime artifact observation and checks its connected contracts before PostgreSQL', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-runtime-artifact-references.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(
    '  tests/integration/identity/postgres-runtime-artifact-references.test.ts)',
  );
  const end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.match(preflight, /pnpm exec tsc[^\n]+postgres-runtime-artifact-references\.test\.ts/u);
  assert.ok(preflight.includes('src/evidence/runtime-artifact-references.test.ts'));
  assert.ok(preflight.includes('src/evidence/runtime-artifact-archive-contract.test.ts'));
});

test('notification PostgreSQL dispatch verifies shared native outbox proof branches before allocation', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const begin = runner.indexOf('owner=notification-contracts');
  const end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  assert.ok(runner.slice(begin, end).includes('src/db/notification-outbox-dispatch.test.ts'));
  for (const test of [
    'src/notifications/delivery-outcome-publication-contract.test.ts',
    'src/notifications/delivery-outcome-publication.test.ts',
    'src/notifications/delivery-outcome-publication-guards.test.ts',
    'src/notifications/delivery-outcome-publication-shared.test.ts',
    'src/evidence/notification-outcome-source.test.ts',
  ])
    assert.ok(runner.slice(begin, end).includes(test));
  assert.ok(
    runner
      .slice(0, runner.indexOf('if [ "$#"'))
      .includes('tests/integration/identity/postgres-notification-delivery-publication.test.ts'),
  );
});

test('ordinary identity CI dispatches runtime artifact custody with connected input guards before PostgreSQL', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-runtime-artifact-custody.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(`  ${path})`),
    end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.match(preflight, /pnpm exec tsc[^\n]+postgres-runtime-artifact-custody\.test\.ts/u);
  for (const name of [
    'runtime-artifact-archive-contract',
    'runtime-artifact-archive-custody',
    'runtime-artifact-archive-guards',
    'runtime-artifact-retirement',
    'runtime-artifact-retirement-guards',
  ])
    assert.ok(preflight.includes(`src/evidence/${name}.test.ts`));
  assert.ok(preflight.includes('src/evidence/candidate-archive/source.test.ts'));
});

test('ordinary identity CI runs native key custody and legacy pinned transport with owned scratch', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-operations-qualification-key-custody.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(`  ${path})`),
    end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.match(
    preflight,
    /pnpm exec tsc[^\n]+postgres-operations-qualification-key-custody\.test\.ts/u,
  );
  for (const name of [
    'qualification-key-provider',
    'http-qualification-key-provider',
    'qualification-key-custody-peer',
    'pinned-signing-transport',
    'http-notification-receipt-provider',
  ])
    assert.ok(preflight.includes(`src/domain/${name}.test.ts`));
  assert.ok(
    preflight.indexOf('export OPENPC_TEST_TMP_ROOT=') <
      preflight.indexOf('pnpm --dir services/identity-service exec vitest'),
  );
});

test('ordinary identity CI checks closed async scheduling and its payload owner before native admission', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-notification-async-custody.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(`  ${path})`),
    end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.ok(preflight.includes('tests/integration/identity/notification-async-worker-cases.ts'));
  for (const name of [
    'async-worker-policy',
    'async-worker-guards',
    'async-worker',
    'delivery-start-preparation-guards',
    'delivery-cancellation-state',
  ])
    assert.ok(preflight.includes(`src/notifications/${name}.test.ts`));
});

test('ordinary identity CI checks native deployment inputs before PostgreSQL and pins owned clients', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const path = 'tests/integration/identity/postgres-operations-qualification-deployment.test.ts';
  assert.ok(runner.slice(0, runner.indexOf('if [ "$#"')).includes(path));
  const begin = runner.indexOf(`  ${path})`),
    end = runner.indexOf('    ;;', begin);
  assert.ok(begin > 0 && end > begin && end < runner.indexOf('docker run -d'));
  const preflight = runner.slice(begin, end);
  assert.ok(preflight.includes('--profile database --external-memory-gib 1.5 --reuse -- true'));
  assert.match(
    preflight,
    /pnpm exec tsc[^\n]+postgres-operations-qualification-deployment\.test\.ts/u,
  );
  for (const name of [
    'installation-process-observation.test.mjs',
    'qualification-deployment-observation.test.mjs',
    'qualification-deployment-peer.test.ts',
  ])
    assert.ok(preflight.includes(name));
  assert.ok(preflight.includes('openpc_image_tag identity-service'));
  assert.ok(preflight.includes('export OPENPC_QUALIFICATION_DEPLOYMENT_IMAGE_ID'));
  const root = JSON.parse(await readFile('package.json', 'utf8'));
  for (const path of [
    'scripts/operations/installation-qualification-inputs.test.mjs',
    'scripts/operations/installation-qualification-runtime.test.mjs',
    'tests/integration/local-runtime/qualification-observer-packaged.test.mjs',
  ])
    assert.ok(root.scripts['test:unit'].includes(path));
  const identity = JSON.parse(await readFile('services/identity-service/package.json', 'utf8'));
  assert.match(
    identity.scripts['build:qualification-observer'],
    /run-project\.sh -- pnpm exec esbuild/u,
  );
});

test('first-policy runtime dispatch isolates terminal withdrawal expiry and propagates prerequisites', async () => {
  const source = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = source.indexOf('openpc_phase_begin first-policy-activation\n');
  const end = source.indexOf(
    'source tests/integration/local-runtime/evidence-rpc-configuration.sh',
    start,
  );
  assert.ok(start > 0 && end > start);
  const block = source.slice(start, end);
  assert.ok(
    composeRunner.includes('source tests/integration/local-runtime/first-policy-journey.sh'),
  );
  assert.ok(
    composeRunner.includes(
      'suite_step first-policy-rpc env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1',
    ),
  );
  assert.ok(
    block.indexOf('first-policy-withdrawal-journey.mjs') < block.indexOf('FIRST_ACTIVATION_ONLY'),
  );
  assert.ok(
    block.indexOf('first-policy-renewal-failure.mjs') > block.indexOf('FIRST_ACTIVATION_ONLY'),
  );
  for (const [initial, withdrawal, expiry, mode, status, unknown = false] of [
    [0, 0, 0, 1, 0],
    [23, 0, 0, 1, 23],
    [0, 24, 0, 1, 24],
    [0, 0, 25, 1, 25],
    [0, 0, 0, 0, 0],
    [0, 24, 0, 0, 24],
    [0, 0, 25, 0, 0],
    [0, 0, 0, 1, 0, true],
    [0, 0, 26, 1, 26, true],
    [0, 24, 0, 1, 24, true],
  ]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
fixture() { :; }
compose=(fixture)
secret_root=/isolated/secrets
evidence_root=/isolated/evidence
openpc_compose_json() { printf '[]'; }
openpc_phase_begin() { printf 'begin:%s\\n' "$1"; }
openpc_phase_end() { printf 'end:%s\\n' "$1"; }
node() {
 case "$*" in
  *first-policy-workbench-browser.mjs*) printf 'initial-call\\n'; return "$INITIAL";;
  *first-policy-withdrawal-journey.mjs*) printf 'withdrawal-call\\n'; return "$WITHDRAWAL";;
  *first-policy-withdrawal-unknown.mjs*) printf 'unknown-call\\n'; return "$EXPIRY";;
  *first-policy-renewal-failure.mjs*) printf 'expiry-call\\n'; return "$EXPIRY";;
  *) return 96;;
 esac
}
run_case() {
${block}
}
run_case
printf 'complete\\n'
`,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          INITIAL: String(initial),
          WITHDRAWAL: String(withdrawal),
          EXPIRY: String(expiry),
          OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY: String(mode),
          OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE: unknown ? 'UNKNOWN_COMMIT' : 'EXPIRY',
        },
      },
    );
    assert.equal(result.status, status, result.stderr);
    assert.equal(result.stdout.includes('withdrawal-call'), initial === 0);
    assert.equal(
      result.stdout.includes('end:first-policy-withdrawal'),
      initial === 0 && withdrawal === 0,
    );
    assert.equal(
      result.stdout.includes('expiry-call'),
      mode === 1 && initial === 0 && withdrawal === 0 && !unknown,
    );
    assert.equal(
      result.stdout.includes('end:first-policy-renewal-expiry'),
      mode === 1 && status === 0 && !unknown,
    );
    assert.equal(
      result.stdout.includes('unknown-call'),
      unknown && initial === 0 && withdrawal === 0,
    );
    assert.equal(
      result.stdout.includes('end:first-policy-withdrawal-unknown'),
      unknown && status === 0,
    );
    assert.equal(result.stdout.includes('complete'), status === 0);
  }
});

test('ordinary runtime suite dispatches the bounded withdrawal case once and retains aggregate failure', () => {
  const definition = composeRunner.slice(
    composeRunner.indexOf('  suite_status=0\n'),
    composeRunner.indexOf('  export OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE=1'),
  );
  const lines = composeRunner
    .split('\n')
    .filter((line) => /^ {2}suite_step first-policy-withdrawal-(adverse|unknown) /u.test(line));
  assert.equal(lines.length, 2);
  assert.match(lines[0], /OPENPC_EVALUATION_UI=1/u);
  assert.doesNotMatch(lines[1], /OPENPC_EVALUATION_UI=/u);
  for (const failure of [0, 27]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
calls=0
env() {
  [[ $1 == OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 && $2 == OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY=1 ]] || return 96
  shift 2
  if [[ $1 == OPENPC_EVALUATION_UI=1 ]]; then shift; fi
  if [[ $1 == OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE=UNKNOWN_COMMIT ]]; then shift; fi
  [[ $1 == bash && $# == 2 ]] || return 96
  calls=$((calls + 1))
  return "$FAILURE"
}
${definition}
${lines.join('\n')}
suite_step unrelated-success true
[[ $calls == 2 ]]
exit "$suite_status"
`,
      ],
      { encoding: 'utf8', env: { ...process.env, FAILURE: String(failure) } },
    );
    assert.equal(result.status, failure ? 1 : 0, result.stderr);
    assert.match(result.stdout, /PASS\|unrelated-success/u);
    if (failure) assert.match(result.stderr, /FAIL\|first-policy-withdrawal-adverse\|exit=27/u);
    else assert.match(result.stdout, /PASS\|first-policy-withdrawal-adverse/u);
  }
});

test('unknown withdrawal mode rejects accidental normal-RPC and unsupported selections before allocation', () => {
  const guard = composeRunner.slice(0, composeRunner.indexOf('# Packaged verification'));
  for (const [mode, selected, expected] of [
    ['0', 'UNKNOWN_COMMIT', 96],
    ['1', 'INVALID', 96],
    ['1', 'UNKNOWN_COMMIT', 0],
  ]) {
    const result = spawnSync('bash', ['-c', `${guard}\nprintf 'admitted\\n'`], {
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY: mode,
        OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE: selected,
      },
    });
    assert.equal(result.status, expected, result.stderr);
    assert.equal(result.stdout.includes('admitted'), expected === 0);
  }
});

test('ordinary Identity CI selects setup candidate runtime-role proof without an unrelated native wallet build', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-setup-workbench.test.ts';
  assert.ok(runner.slice(runner.indexOf('test_files=('), runner.indexOf('\n)')).includes(file));
  assert.ok(
    !runner
      .slice(
        runner.indexOf('for test_file in'),
        runner.indexOf('done', runner.indexOf('for test_file in')),
      )
      .includes(file),
  );
  assert.match(
    runner,
    /vitest run --config tests\/integration\/identity\/vitest.config.ts "\$\{test_files\[@\]\}"/u,
  );
});

test('first-policy discovery adopts the target-key mount before credential admission', async () => {
  const journey = await readFile('tests/integration/local-runtime/first-policy-journey.sh', 'utf8');
  const start = journey.indexOf('# Discovery replaces the target-key secret source.');
  const end = journey.indexOf('openpc_first_policy_scope_preflight', start);
  assert.ok(start > journey.indexOf('compose+=(-f "$owned_data/compose.json")'));
  assert.ok(end > start);
  for (const failure of ['none', 'recreate', 'image']) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
compose=(docker compose -f discovery-overlay.json)
secret_root=secrets
evidence_root=evidence
docker() {
  [[ "$*" == 'compose -f discovery-overlay.json up -d --wait --no-deps --no-build --pull never --force-recreate control-api' ]] || return 97
  [[ $FAILURE != recreate ]] || return 71
  printf 'target-key-mount-adopted\\n'
}
openpc_verify_running_images() {
  [[ $* == control-api ]] || return 97
  [[ $FAILURE != image ]] || return 72
  printf 'image-verified\\n'
}
node() {
  [[ "$*" == '--import tsx tests/integration/local-runtime/runtime-discovery-credential.mjs secrets evidence evidence/discovery-credential-input.json' ]] || return 97
  printf 'credential-admission\\n'
}
${journey.slice(start, end)}`,
      ],
      { encoding: 'utf8', env: { ...process.env, FAILURE: failure } },
    );
    assert.equal(result.status, failure === 'none' ? 0 : failure === 'recreate' ? 71 : 72);
    assert.equal(result.stdout.includes('credential-admission'), failure === 'none');
    if (failure === 'none')
      assert.equal(
        result.stdout,
        'target-key-mount-adopted\nimage-verified\ncredential-admission\n',
      );
  }
});

test('scoped Participant hold signing bootstrap preserves existing keys and exact privacy', async (t) => {
  const root = await discoveryApprovalResumeScratch(t);
  const secrets = join(root, 'secrets');
  const provider = join(root, 'provider');
  await mkdir(secrets);
  const privacy = '018f0000-0000-7000-8000-000000007201';
  const bootstrap = (...args) =>
    spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/signing-provider-bootstrap.ts',
        secrets,
        provider,
        ...args,
      ],
      { encoding: 'utf8', timeout: 30000 },
    );
  assert.equal(bootstrap().status, 0, 'Initial provider preparation');
  const originals = new Map();
  for (const directory of [secrets, join(provider, 'keys'), join(provider, 'public')])
    for (const file of await readdir(directory)) {
      const path = join(directory, file);
      originals.set(path, await readFile(path));
    }
  assert.notEqual(bootstrap('--participant-hold', 'wrong-scope').status, 0);
  assert.equal(bootstrap('--participant-hold', privacy).status, 0);
  const descriptor = JSON.parse(
    await readFile(
      join(secrets, `control_participant_hold_${privacy}_signing_descriptor.json`),
      'utf8',
    ),
  );
  assert.equal(descriptor.privacyDomainId, privacy);
  assert.equal(
    descriptor.reference,
    `secret://local/control-participant-hold-${privacy}-evidence#1`,
  );
  assert.equal(descriptor.state, 'ACTIVE');
  const legacy = JSON.parse(
    await readFile(join(secrets, 'control_participant_hold_signing_descriptor.json'), 'utf8'),
  );
  assert.equal(legacy.privacyDomainId, '018f0000-0000-7000-8000-000000000201');
  assert.notEqual(descriptor.fingerprint, legacy.fingerprint);
  assert.equal(bootstrap('--participant-hold', privacy).status, 0);
  const repeated = JSON.parse(
    await readFile(
      join(secrets, `control_participant_hold_${privacy}_signing_descriptor.json`),
      'utf8',
    ),
  );
  assert.deepEqual(repeated, descriptor);
  for (const [path, bytes] of originals)
    assert.equal(
      (await readFile(path)).equals(bytes),
      true,
      'Original provider material is unchanged',
    );
});

async function closedPublicRunnerTools(t) {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'public-runner-tools-'),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  await mkdir(bin);
  await writeFile(
    join(bin, 'dirname'),
    '#!/bin/sh\nif [ "$1" = -- ]; then shift; fi\nvalue=$1\nprintf "%s\\n" "${value%/*}"\n',
    {
      mode: 0o700,
    },
  );
  for (const command of ['node', 'git', 'docker', 'systemctl', 'systemd-run', 'flock']) {
    await writeFile(
      join(bin, command),
      '#!/bin/sh\nprintf "%s\\n" "$0" >> "$CLOSED_TOOL_LOG"\nexit 99\n',
      { mode: 0o700 },
    );
  }
  return { root, env: { ...process.env, PATH: bin, CLOSED_TOOL_LOG: join(root, 'tools.log') } };
}

for (const [name, args, inherited] of [
  ['command option', ['--owned-qa', '/synthetic/retained-runtime'], false],
  ['environment', [], true],
  ['reuse environment', ['--reuse'], true],
  ['profile reuse environment', ['--profile', 'focused', '--reuse'], true],
]) {
  test(`public runner rejects retained overrides: ${name}`, async (t) => {
    const { root, env } = await closedPublicRunnerTools(t);
    delete env.OPENPC_OWNED_QA_ROOT;
    if (inherited) env.OPENPC_OWNED_QA_ROOT = '/synthetic/retained-runtime';
    const result = spawnSync(
      '/bin/bash',
      ['scripts/maintenance/run-bounded.sh', ...args, '--', '/bin/sh', '-c', 'printf dispatched'],
      { env, encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.status, 64, result.stderr);
    assert.equal(result.stdout, '');
    assert.ok(
      !(await readdir(root)).includes('tools.log'),
      'No external owner or container tool may be invoked',
    );
  });
}

test('public runner does not advertise the retired retained-environment mode', async () => {
  const result = spawnSync('/bin/bash', ['scripts/maintenance/run-bounded.sh', '--help'], {
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /--profile focused\|database\|governance\|image-build\|runtime-target\|runtime/u,
  );
  assert.doesNotMatch(result.stdout, /--owned-qa/u);
});

test('public sandbox rejects retired retained-environment action before reading custody or containers', async (t) => {
  const { root, env } = await closedPublicRunnerTools(t);
  const result = spawnSync(
    process.execPath,
    [
      'tests/integration/local-runtime/qa-sandbox.mjs',
      'bounded-check',
      '/synthetic/retained-runtime',
      '9437184',
    ],
    { env, encoding: 'utf8', timeout: 10000 },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unknown QA sandbox action/u);
  assert.equal(result.stdout, '');
  assert.ok(
    !(await readdir(root)).includes('tools.log'),
    'No owner or container tool may be invoked',
  );
});

test('resource reuse regression stops immediately when a denial assertion fails', async (t) => {
  const source = await readFile('scripts/maintenance/run-bounded.test.sh', 'utf8');
  const marker = "-- bash -c '\n";
  const owner = source.indexOf('bash "$runner" --profile focused "${external_args[@]}"');
  const start = source.indexOf(marker, owner) + marker.length;
  const end = source.indexOf('\n\' _ "$test_root"', start);
  assert(owner >= 0 && start > owner && end > start);
  const body = source.slice(start, end).replaceAll("'\\''", "'");
  const root = await discoveryApprovalResumeScratch(t);
  const result = spawnSync(
    '/bin/bash',
    [
      '-c',
      `
    fixture_root=$1
    bash() {
      if [[ $1 == scripts/maintenance/run-bounded.sh ]]; then
        local target
        for target; do :; done
        printf unexpected-dispatch > "$target"
        return 0
      fi
      [[ " $* " != *" node --version "* ]] || return 0
      return 96
    }
    node() { printf reached > "$fixture_root/node-reached"; }
    ${body}
  `,
      '_',
      root,
    ],
    {
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB: '9437184' },
    },
  );
  assert.equal(result.status, 1, result.stderr);
  assert.equal(await readFile(join(root, 'forbidden'), 'utf8'), 'unexpected-dispatch');
  assert.ok(!(await readdir(root)).includes('node-reached'));
});

test('ordinary unit CI checks the isolated public recovery package', () => {
  assert.match(
    packageDocument.scripts['test:unit'],
    /node --test tests\/recovery\/recovery-result\.test\.mjs tests\/recovery\/recovery-package\.test\.mjs/u,
  );
});

test('readback cleanup retains failed signing state and keys for every selected position and uncertain ownership', async (t) => {
  const source = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const cleanup = readbackCleanupSource(source);
  const root = await discoveryApprovalResumeScratch(t);
  const signing = 'tests/integration/identity/postgres-workload-certificate-rotation.test.ts',
    platformScope = 'tests/integration/identity/postgres-platform-envelope-scope.test.ts',
    rootExpiry = 'tests/integration/identity/postgres-root-expiry-installation.test.ts',
    ordinary = 'tests/integration/identity/postgres-policy-set.test.ts';
  const cases = [
    { status: 1, files: [signing], retain: true },
    { status: 1, files: [ordinary, signing], retain: true },
    { status: 1, files: [platformScope], retain: true },
    { status: 1, files: [rootExpiry], retain: true },
    { status: 1, files: [ordinary, rootExpiry], retain: true },
    { status: 0, files: [rootExpiry], retain: false },
    { status: 1, files: [rootExpiry], foreign: true, retain: true, exit: 99 },
    { status: 1, files: [ordinary, platformScope], retain: true },
    { status: 0, files: [platformScope], retain: false },
    { status: 1, files: [platformScope], foreign: true, retain: true, exit: 99 },
    {
      status: 1,
      files: ['tests/integration/identity/postgres-envelope-proposal.test.ts'],
      retain: true,
    },
    { status: 0, files: [signing], retain: false },
    { status: 1, files: [ordinary], retain: false },
    { status: 1, files: [signing], foreign: true, retain: true, exit: 99 },
    { status: 0, files: [ordinary], removeFails: true, retain: true, exit: 99 },
  ];
  for (const [index, entry] of cases.entries()) {
    const scratch = join(root, String(index));
    await mkdir(scratch);
    const result = spawnSync(
      '/bin/bash',
      [
        '-c',
        `set -uo pipefail
root="$OPENPC_READBACK_CLEANUP_TEST_ROOT"
trace="$root/actions"
created=1
container=owned-readback
IFS='|' read -r -a test_files <<< "$OPENPC_READBACK_TEST_SELECTION"
docker() {
  case "$1" in
    logs) printf 'synthetic database diagnostics\\n' ;;
    inspect) if [[ "$OPENPC_READBACK_FOREIGN_OWNER" == 1 ]]; then printf '/foreign-owner\\n'; else printf '%s\\n' "$root"; fi ;;
    ps) printf '%s\\n' "$container" ;;
    stop) printf 'stop:%s\\n' "$2" >> "$trace" ;;
    rm) printf 'remove:%s\\n' "$*" >> "$trace"; [[ "$OPENPC_READBACK_REMOVE_FAILS" != 1 ]] ;;
    *) return 98 ;;
  esac
}
rm() { printf 'remove-path:%s\\n' "$*" >> "$trace"; }
${cleanup}
(exit "$OPENPC_READBACK_INCOMING_STATUS")
cleanup
`,
      ],
      {
        env: {
          ...process.env,
          OPENPC_READBACK_CLEANUP_TEST_ROOT: scratch,
          OPENPC_READBACK_TEST_SELECTION: entry.files.join('|'),
          OPENPC_READBACK_FOREIGN_OWNER: entry.foreign ? '1' : '0',
          OPENPC_READBACK_REMOVE_FAILS: entry.removeFails ? '1' : '0',
          OPENPC_READBACK_INCOMING_STATUS: String(entry.status),
        },
        encoding: 'utf8',
        timeout: 10000,
      },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, entry.exit ?? entry.status, result.stderr);
    const actions = await readFile(join(scratch, 'actions'), 'utf8').catch((error) => {
      if (error.code === 'ENOENT') return '';
      throw error;
    });
    if (entry.foreign) {
      assert.equal(actions, '');
      continue;
    }
    assert.equal(actions.includes('stop:'), entry.retain && !entry.removeFails, actions);
    assert.equal(
      actions.includes('remove:docker') || actions.includes('remove:rm'),
      !entry.retain || Boolean(entry.removeFails),
      actions,
    );
    assert.equal(actions.includes('/secrets'), !entry.retain, actions);
  }
});

test('Fact reader credentials use owned scratch and missing scratch refuses before allocation', async (t) => {
  const source = await readFile('tests/integration/facts/run-postgres18-gate3-proof.sh', 'utf8');
  const start = source.indexOf('readonly policy_reader_secret_root=');
  const end = source.indexOf('readonly container_name=', start);
  assert.ok(start > 0 && end > start && end < source.indexOf('phase=build'));
  const createStart = source.indexOf('policy_reader_secret="$(mktemp');
  const createEnd = source.indexOf('\nexport POLICY_FACT_DATABASE_HOST=', createStart);
  assert.ok(createStart > end && createEnd > createStart);
  const root = await discoveryApprovalResumeScratch(t);
  const owned = join(root, 'runtime scratch');
  const override = join(root, 'explicit scratch');
  await mkdir(owned);
  await mkdir(override);
  for (const [runtime, explicit, expected] of [
    [owned, undefined, owned],
    [owned, override, override],
    [undefined, override, override],
    [undefined, undefined, undefined],
    [join(root, 'missing'), undefined, undefined],
  ]) {
    const env = { ...process.env };
    delete env.OPENPC_LOCAL_RUNTIME_TMP_ROOT;
    delete env.OPENPC_TEST_ROOT;
    if (runtime !== undefined) env.OPENPC_LOCAL_RUNTIME_TMP_ROOT = runtime;
    if (explicit !== undefined) env.OPENPC_TEST_ROOT = explicit;
    const result = spawnSync(
      '/bin/bash',
      [
        '-c',
        `set -euo pipefail\n${source.slice(start, end)}\npostgres_password=synthetic-only\n${source.slice(createStart, createEnd)}\nprintf '%s' "$policy_reader_secret"`,
      ],
      { env, encoding: 'utf8', timeout: 10000 },
    );
    assert.equal(result.error, undefined);
    if (expected === undefined) {
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
    } else {
      assert.equal(result.status, 0, result.stderr);
      assert.ok(result.stdout.startsWith(`${expected}/fact-reader-password.`));
      assert.equal(await readFile(result.stdout, 'utf8'), 'synthetic-only');
      assert.equal((await stat(result.stdout)).mode & 0o777, 0o600);
    }
  }
});

test('credential continuity validates type and real transport before allocating its isolated database', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-workload-credential-continuity.test.ts';
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + 6;
  assert(begin > 0 && end > begin && end < runner.indexOf('\nroot=$(mktemp'));
  for (const failed of [0, 1, 2]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
 test_files=(${file})
 calls=0
 pnpm() { calls=$((calls+1)); printf 'PREREQUISITE:%s\\n' "$*"; if [ "$calls" = "${failed}" ];then return 29;fi; }
 ${runner.slice(begin, end)}
 test "$calls" = 2
 printf 'DATABASE_ALLOCATION_ALLOWED\\n'
 `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 29 : 0, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
    assert(result.stdout.includes('exec tsc --ignoreConfig --noEmit'));
    assert.equal(
      result.stdout.includes(
        '--testNamePattern ^(authenticates independent expired and current continuity certificates before database allocation|binds a prepared authority once to the exact runtime target without changing its signed identity)$',
      ),
      failed !== 1,
    );
  }
  const keep = runner.slice(
    runner.indexOf('openpc_readback_keep_failure_state()'),
    runner.indexOf('cleanup()'),
  );
  assert(keep.includes(file));
});

test('workload handover setup gates its owning database on types and real finite certificate checks', async () => {
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const file = 'tests/integration/identity/postgres-runtime-credential-handover-workload.test.ts';
  assert(runner.slice(0, runner.indexOf('if [ "$#"')).includes(file));
  const begin = runner.indexOf('case "${test_files[0]}" in');
  const end = runner.indexOf('\nesac', begin) + 6;
  assert(begin > 0 && end > begin && end < runner.indexOf('\nroot=$(mktemp'));
  for (const failed of [0, 1, 2]) {
    const result = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
 test_files=(${file})
 calls=0
 pnpm() { calls=$((calls+1)); printf 'PREREQUISITE:%s\\n' "$*"; if [ "$calls" = "${failed}" ];then return 29;fi; }
 ${runner.slice(begin, end)}
 test "$calls" = 2
 printf 'DATABASE_ALLOCATION_ALLOWED\\n'
 `,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, failed ? 29 : 0, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ALLOCATION_ALLOWED'), failed === 0);
    assert(result.stdout.includes('exec tsc --ignoreConfig --noEmit'));
    assert.equal(
      result.stdout.includes(
        'runtime-credential-handover-inputs.test.ts --testNamePattern ^signs a finite initial native-test credential without extending an existing signed leaf$',
      ),
      failed !== 1,
    );
  }
  const keep = runner.slice(
    runner.indexOf('openpc_readback_keep_failure_state()'),
    runner.indexOf('cleanup()'),
  );
  assert(keep.includes(file));
});

test('Workbench driver maps guided interaction fields without accepting unrelated labels', () => {
  const result = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      '--input-type=module',
      '-e',
      `
      import assert from 'node:assert/strict';
      import {workbenchInputFields} from './tests/integration/local-runtime/transaction-workbench-browser.mjs';
      const analysis = {
        'Runtime target reference': 'targetRuntimeId',
        'Installed generation digest': 'expectedGenerationDigest',
        'Runtime binding reference': 'runtimeBindingId',
        'Method policy reference': 'contractMethodPolicyId',
        'Runtime binding revision': 'expectedRuntimeBindingRevision',
        'Method policy revision': 'expectedMethodRevision',
        'Workload reference': 'workloadId',
        'Transaction hash': 'transactionHash',
        'Analysis lifetime (seconds)': 'expiresInSeconds',
      };
      const grant = {
        'Runtime binding reference': 'runtimeBindingId', 'Method selector': 'selector',
        'Recipient type': 'subject.kind', 'Role reference': 'subject.id',
        'User identifier': 'subject.id', 'Group identifier': 'subject.id',
        'Workload reference': 'subject.id', 'Participant identifier': 'subject.id',
        Interface: 'surface', Decision: 'effect',
      };
      for (const [label, fields] of [['Create interaction analysis', analysis], ['Create method grant', grant]]) {
        for (const [name, path] of Object.entries(fields)) {
          assert.deepEqual(workbenchInputFields(label, {[name]: 'exact-value'}), [{name:'definition.'+path,label:name,value:'exact-value'}]);
        }
        for (const name of ['Unknown field', 'toString', 'constructor', '__proto__'])
          assert.throws(()=>workbenchInputFields(label,Object.fromEntries([[name,'value']])),/Unknown.*field/u);
      }
      assert.deepEqual(workbenchInputFields('Create method grant', {'Expected method revision':'18446744073709551615'}), [{name:'expectedMethodRevision',label:'Expected method revision',value:'18446744073709551615'}]);
      assert.throws(()=>workbenchInputFields('Create method grant',{'Transaction hash':'value'}),/Unknown.*field/u);
      assert.throws(()=>workbenchInputFields('Create interaction analysis',{'Decision':'ALLOW'}),/Unknown.*field/u);
      assert.throws(()=>workbenchInputFields('Publish interaction settings',{'Method selector':'value'}),/Unknown.*field/u);
      assert.throws(()=>workbenchInputFields('Unknown request',{}),/Unknown Workbench request/u);
    `,
    ],
    { encoding: 'utf8', timeout: 15000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test('public installation source CI selects actual public checks and blocks allocation after prerequisite failure', async () => {
  const file = 'tests/integration/identity/postgres-public-operations-source.test.ts';
  const runner = await readFile('tests/integration/identity/run-participant-readback.sh', 'utf8');
  const packageSource = JSON.parse(await readFile('package.json', 'utf8'));
  assert.ok(
    packageSource.scripts['test:unit'].includes(
      'scripts/operations/public-operations-source.test.mjs',
    ),
  );
  assert.ok(
    !packageSource.scripts['test:unit'].includes(
      'installation-source-authentication.internal.test.mjs',
    ),
  );
  const array = runner.slice(runner.indexOf('test_files=('), runner.indexOf('\n)') + 2);
  const selected = spawnSync('bash', ['-c', array + '\nprintf "%s\\n" "${test_files[@]}"'], {
    encoding: 'utf8',
  });
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(
    selected.stdout
      .trim()
      .split('\n')
      .filter((value) => value === file).length,
    1,
  );
  assert.ok(!selected.stdout.includes('operations-generation-legacy.internal.test.ts'));
  const start = runner.indexOf('  ' + file + ')');
  const end = runner.indexOf('    ;;', start) + '    ;;'.length;
  assert.ok(start > 0 && end > start && end < runner.indexOf('docker run -d'));
  const branch = runner.slice(start, end);
  const pattern = branch.match(/--testNamePattern '([^']+)'/u)?.[1];
  assert.ok(pattern);
  const cases = await readFile(file, 'utf8');
  const actual = cases.match(/it\('([^']+)'/u)?.[1];
  assert.ok(actual && new RegExp(pattern, 'u').test(actual));
  for (const failure of ['none', 'source', 'signed']) {
    const script = `set -e
pnpm() { printf 'PNPM_PREREQUISITE\\n'; if [[ "$*" == *--testNamePattern* && "$FAILURE" == signed ]]; then return 7; fi; return 0; }
node() { printf 'PUBLIC_SOURCE_PREREQUISITE\\n'; if [[ "$FAILURE" == source ]]; then return 7; fi; return 0; }
case "$1" in
${branch}
esac
printf 'DATABASE_ADMISSION_REACHED\\n'
`;
    const result = spawnSync('bash', ['-c', script, '--', file], {
      encoding: 'utf8',
      env: { ...process.env, FAILURE: failure },
    });
    assert.equal(result.status, failure === 'none' ? 0 : 7, result.stderr);
    assert.equal(result.stdout.includes('DATABASE_ADMISSION_REACHED'), failure === 'none');
    assert.ok(result.stdout.includes('PUBLIC_SOURCE_PREREQUISITE'));
  }
});
