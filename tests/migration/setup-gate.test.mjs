import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const workflow = await readFile(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
const heading = '      - name: Fresh compact checkout setup and governed RPC acceptance';
const start = workflow.indexOf(heading);
assert.ok(start >= 0, 'Fresh compact-checkout qualification must remain in CI');
const end = workflow.indexOf('\n      - name:', start + heading.length);
const step = workflow.slice(start, end < 0 ? undefined : end);
const run = step.indexOf('        run: |\n');
assert.ok(run >= 0, 'Fresh setup gate must have an executable run block');
const command = step
  .slice(run + '        run: |\n'.length)
  .split('\n')
  .map((line) => line.replace(/^ {10}/u, ''))
  .join('\n');

for (const [mode, baseline, historical, accepted] of [
  ['compact', true, false, true],
  ['legacy view', false, true, false],
  ['rehydrated checkout', true, true, false],
]) {
  test(`fresh setup gate ${accepted ? 'admits' : 'rejects'} ${mode} before workload dispatch`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'tegaris-setup-gate-')));
    try {
      const source = join(root, 'source');
      const bin = join(root, 'bin');
      const record = join(root, 'dispatch.json');
      await mkdir(join(source, 'migrations/postgres/baseline-v1'), { recursive: true });
      await mkdir(join(source, 'migrations/postgres/policy'), { recursive: true });
      await mkdir(bin);
      if (baseline)
        await writeFile(
          join(source, 'migrations/postgres/baseline-v1/install.sql'),
          '-- fixture\n',
        );
      if (historical)
        await writeFile(
          join(source, 'migrations/postgres/policy/0000_yummy_plazm.sql'),
          '-- fixture\n',
        );
      // Replace only the workload command. The actual CI admission shell above
      // still runs; invalid source layouts must fail before reaching this stub.
      await writeFile(
        join(bin, 'bash'),
        `#!/usr/bin/env node
require('node:fs').writeFileSync(process.env.TEGARIS_SETUP_DISPATCH, JSON.stringify({cwd:process.cwd(),args:process.argv.slice(2)}));
`,
        { mode: 0o700 },
      );
      const result = spawnSync('sh', ['-c', `set -eu\n${command}`], {
        cwd: source,
        encoding: 'utf8',
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TEGARIS_SETUP_DISPATCH: record },
      });
      if (accepted) {
        assert.equal(result.status, 0, result.stderr);
        const dispatch = JSON.parse(await readFile(record, 'utf8'));
        assert.equal(dispatch.cwd, source);
        assert.deepEqual(dispatch.args, [
          'scripts/maintenance/run-project.sh',
          '--profile',
          'runtime',
          '--',
          'env',
          'OPENPC_LOCAL_RUNTIME=1',
          'OPENPC_EVALUATION_UI=1',
          'OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1',
          'bash',
          'tests/integration/local-runtime/run-compose-e2e.sh',
        ]);
      } else {
        assert.notEqual(result.status, 0);
        await assert.rejects(readFile(record), { code: 'ENOENT' });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
