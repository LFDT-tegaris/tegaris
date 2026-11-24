import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const runner = await readFile(
  new URL('../integration/identity/run-participant-readback.sh', import.meta.url),
  'utf8',
);
const start = runner.indexOf('\npostgres_command=(postgres)\n');
const end = runner.indexOf('\ncreated=1\n', start);
assert.ok(start > 0 && end > start);

for (const name of [
  'tests/integration/identity/postgres-runtime-artifact-source.test.ts',
  'tests/integration/local-runtime/control-installation.test.mjs',
  'tests/integration/identity/postgres-first-administrator.test.ts',
]) {
  test(`PostgreSQL launch preserves resource limits for ${name}`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'tegaris-custody-pg-')));
    try {
      const record = join(root, 'launch.json');
      const result = spawnSync(
        '/bin/bash',
        [
          '-euc',
          `
test_files=("$TEGARIS_TEST_FILE")
docker() { node -e 'require("node:fs").writeFileSync(process.env.TEGARIS_TEST_RECORD,JSON.stringify(process.argv.slice(1)))' -- "$@"; }
${runner.slice(start, end)}
`,
        ],
        {
          encoding: 'utf8',
          env: {
            ...process.env,
            TEGARIS_TEST_FILE: name,
            TEGARIS_TEST_RECORD: record,
            root,
            repo: root,
            container: 'openpc-participant-readback-123',
            password: 'synthetic-fixture',
          },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      const args = JSON.parse(await readFile(record, 'utf8'));
      for (const [option, value] of [
        ['--memory', '1g'],
        ['--memory-swap', '1g'],
        ['--cpus', '1'],
        ['--pids-limit', '256'],
        ['--label', `io.openpc.test-owner=${root}`],
        ['-p', '127.0.0.1::5432'],
      ])
        assert.equal(args[args.indexOf(option) + 1], value);
      const image = args.findIndex((arg) =>
        arg.startsWith('docker.io/library/postgres:18.6@sha256:'),
      );
      assert.ok(image > 0);
      assert.deepEqual(
        args.slice(image + 1),
        name.endsWith('/postgres-runtime-artifact-source.test.ts')
          ? ['postgres', '-c', 'max_locks_per_transaction=1024']
          : ['postgres'],
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
