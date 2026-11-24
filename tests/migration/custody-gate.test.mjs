import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = await readFile(
  new URL('../../scripts/migrations/run-linux-custody.sh', import.meta.url),
);
for (const [mode, baseline, history, admitted] of [
  ['compact', true, false, true],
  ['legacy view', false, true, false],
  ['rehydrated checkout', true, true, false],
]) {
  test(`custody gate ${admitted ? 'admits' : 'rejects'} ${mode} before allocating a workload`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'tegaris-custody-gate-')));
    try {
      await mkdir(join(root, 'scripts/migrations'), { recursive: true });
      await mkdir(join(root, 'migrations/postgres/baseline-v1'), { recursive: true });
      await mkdir(join(root, 'migrations/postgres/policy'), { recursive: true });
      await mkdir(join(root, 'bin'));
      const entry = join(root, 'scripts/migrations/run-linux-custody.sh');
      const record = join(root, 'dispatch.json');
      await writeFile(entry, script);
      if (baseline)
        await writeFile(join(root, 'migrations/postgres/baseline-v1/install.sql'), '-- fixture\n');
      if (history)
        await writeFile(
          join(root, 'migrations/postgres/policy/0000_yummy_plazm.sql'),
          '-- fixture\n',
        );
      // Only the OS probe and final workload are substituted. The deployed
      // source-layout guard and exact bounded invocation execute unchanged.
      await writeFile(join(root, 'bin/uname'), '#!/bin/sh\necho Linux\n', { mode: 0o700 });
      await writeFile(
        join(root, 'bin/bash'),
        `#!/usr/bin/env node
require('node:fs').writeFileSync(process.env.TEGARIS_CUSTODY_DISPATCH, JSON.stringify({cwd:process.cwd(),args:process.argv.slice(2)}));
`,
        { mode: 0o700 },
      );
      const result = spawnSync('/bin/bash', [entry], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${join(root, 'bin')}:${process.env.PATH}`,
          TEGARIS_CUSTODY_DISPATCH: record,
        },
      });
      if (admitted) {
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(JSON.parse(await readFile(record, 'utf8')), {
          cwd: root,
          args: [
            'scripts/maintenance/run-project.sh',
            '--profile',
            'database',
            '--memory-gib',
            '8',
            '--peak-disk-gib',
            '40',
            '--',
            'bash',
            'tests/integration/identity/run-participant-readback.sh',
            'tests/integration/identity/postgres-runtime-artifact-source.test.ts',
          ],
        });
      } else {
        assert.notEqual(result.status, 0);
        await assert.rejects(readFile(record), { code: 'ENOENT' });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
