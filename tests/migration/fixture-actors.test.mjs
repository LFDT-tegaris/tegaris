import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const runner = await readFile(
  new URL('../integration/identity/run-participant-readback.sh', import.meta.url),
  'utf8',
);
const start = runner.indexOf('\nplatform_login=openpc_test_platform\n');
const end = runner.indexOf('\nif [[ "$snapshot_interop"', start);
assert.ok(start > 0 && end > start);
const command = runner.slice(start, end);

for (const compact of [false, true]) {
  test(`${compact ? 'compact' : 'legacy'} fixture selects its actors without unexpected role writes`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'tegaris-fixture-actors-')));
    try {
      if (compact) await mkdir(join(root, 'migrations/postgres/baseline-v1'), { recursive: true });
      // The selector tests a file, so create only the explicit compact marker.
      if (compact) {
        const { writeFile } = await import('node:fs/promises');
        await writeFile(join(root, 'migrations/postgres/baseline-v1/install.sql'), '-- fixture\n');
      }
      const result = spawnSync(
        '/bin/bash',
        [
          '-euc',
          `
docker() { printf 'FIXTURE_WRITE\\n'; cat; }
${command}
printf '\\nACTORS=%s|%s\\n' "$platform_login" "$fact_reader_login"
`,
        ],
        {
          encoding: 'utf8',
          env: { ...process.env, repo: root, container: 'fixture', password: 'synthetic-fixture' },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      if (compact) {
        assert.doesNotMatch(result.stdout, /FIXTURE_WRITE|CREATE ROLE|GRANT /u);
        assert.match(
          result.stdout,
          /ACTORS=openpc_participant_runtime\|openpc_source_control_reader/u,
        );
      } else {
        assert.match(result.stdout, /CREATE ROLE openpc_test_platform/u);
        assert.match(
          result.stdout,
          /GRANT openpc_control_reader TO openpc_fact_authority_test_reader/u,
        );
        assert.match(
          result.stdout,
          /ACTORS=openpc_test_platform\|openpc_fact_authority_test_reader/u,
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

test('compact fixture actors have exactly the intended role inheritance without extra direct privileges', async () => {
  const catalog = JSON.parse(
    await readFile(
      new URL('../../migrations/postgres/baseline-v1/catalog.json', import.meta.url),
      'utf8',
    ),
  );
  for (const [name, parents] of [
    ['openpc_participant_runtime', ['openpc_control_platform_runtime', 'openpc_control_runtime']],
    ['openpc_source_control_reader', ['openpc_control_reader']],
  ]) {
    assert.deepEqual(
      catalog.memberships.filter((row) => row[1] === name).map((row) => [row[0], ...row.slice(3)]),
      parents.map((parent) => [parent, false, true, true]),
    );
    assert.equal(
      catalog.functions.some(
        (row) => row[4].some((acl) => acl[0] === name) || row[5].includes(name),
      ),
      false,
    );
    assert.equal(
      catalog.relations.some((row) => row[6].some((acl) => acl[0] === name)),
      false,
    );
    assert.equal(
      catalog.policies.some((row) => JSON.stringify(row).includes(name)),
      false,
    );
  }
});
