import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

// Compilation belongs to the host prebuild phase. This entrypoint runs only
// the already-built test against the real public qualification fixture.
const guarded = spawnSync(
  'bash',
  [
    'scripts/maintenance/run-bounded.sh',
    '--memory-gib',
    '0.25',
    '--external-memory-gib',
    '1.25',
    '--reuse',
    '--',
    'true',
  ],
  { stdio: 'inherit' },
);
assert.equal(guarded.status, 0, 'live bounded owner required');
const [secrets, resourceId, executable] = process.argv.slice(2);
assert.ok(secrets && isAbsolute(secrets));
assert.match(resourceId ?? '', /^[0-9a-f-]{36}$/u);
assert.ok(executable && isAbsolute(executable), 'prebuilt owner test executable required');
const database = new URL('postgresql://openpc_local_control_worker@127.0.0.1:55432/openpc_control');
database.password = (
  await readFile(join(secrets, 'control_worker_runtime_db_password.txt'), 'utf8')
).trim();
const failures = [];
for (const test of [
  'projection_admission::database_tests::postgres_current_source_fences_revision_scope_and_concurrent_update',
  'source_revision::database_tests::postgres_accepted_revision_fences_completion_and_failure',
]) {
  const result = spawnSync(executable, [test, '--exact', '--ignored', '--nocapture'], {
    encoding: 'utf8',
    timeout: 30_000,
    env: {
      ...process.env,
      OPENPC_PROJECTION_ADMISSION_DATABASE_URL: database.href,
      OPENPC_PROJECTION_ADMISSION_RESOURCE_ID: resourceId,
    },
  });
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  if (result.status !== 0 || !/test result: ok\. 1 passed;/u.test(result.stdout ?? '')) {
    failures.push(test);
  }
}
assert.deepEqual(failures, [], 'source completion fences must each run and pass');
process.stdout.write(
  'OPENPC_PROJECTION_SOURCE_FENCE|PASS|current-receipt|accepted-revision|stale-completion-and-failure|scope|retirement|concurrent-update|rollback-no-effects\n',
);
