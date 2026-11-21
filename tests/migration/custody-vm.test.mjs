import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const workflow = await readFile(
  new URL('../../.github/workflows/migration-readiness.yml', import.meta.url),
  'utf8',
);
assert.ok(!workflow.slice(0, workflow.indexOf('  source-custody:\n')).includes('sudo rm -rf'));
const custody = workflow.slice(workflow.indexOf('  source-custody:\n'));
const begin = custody.indexOf('      - name: Prepare disk on this fresh GitHub custody VM\n');
assert.ok(begin >= 0);
const end = custody.indexOf('\n      - uses:', begin);
const step = custody.slice(begin, end);
const run = step.indexOf('        run: |\n');
assert.ok(run >= 0);
const command = step
  .slice(run + '        run: |\n'.length)
  .split('\n')
  .map((line) => line.replace(/^ {10}/u, ''))
  .join('\n');

for (const [name, github, kind, os, allowed] of [
  ['self-hosted runner', 'true', 'self-hosted', 'Linux', false],
  ['local execution', 'false', 'github-hosted', 'Linux', false],
  ['non-Linux runner', 'true', 'github-hosted', 'macOS', false],
  ['fresh hosted Linux VM', 'true', 'github-hosted', 'Linux', true],
]) {
  test(`custody VM preparation ${allowed ? 'admits' : 'rejects'} ${name} before SDK removal`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'tegaris-vm-gate-')));
    try {
      const bin = join(root, 'bin');
      const record = join(root, 'commands.jsonl');
      await mkdir(bin);
      // No real deletion or capacity claim: these stubs record only the
      // deployed shell's VM boundary and the exact allowlisted SDK commands.
      await writeFile(
        join(bin, 'sudo'),
        `#!/usr/bin/env node
require('node:fs').appendFileSync(process.env.TEGARIS_VM_RECORD, JSON.stringify(process.argv.slice(2))+'\\n');
`,
        { mode: 0o700 },
      );
      await writeFile(join(bin, 'python3'), '#!/bin/sh\ncat >/dev/null\n', { mode: 0o700 });
      const result = spawnSync('/bin/bash', ['-euc', command], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          GITHUB_ACTIONS: github,
          TEGARIS_RUNNER_KIND: kind,
          RUNNER_OS: os,
          TEGARIS_VM_RECORD: record,
        },
      });
      if (allowed) {
        assert.equal(result.status, 0, result.stderr);
        const calls = (await readFile(record, 'utf8'))
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line));
        assert.deepEqual(calls, [
          ['rm', '-rf', '--one-file-system', '--', '/usr/share/dotnet'],
          ['rm', '-rf', '--one-file-system', '--', '/usr/local/lib/android'],
        ]);
      } else {
        assert.equal(result.status, 78, result.stderr);
        await assert.rejects(readFile(record), { code: 'ENOENT' });
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
