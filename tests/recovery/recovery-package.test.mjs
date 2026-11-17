import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('isolated public recovery package runs without a historical source tree', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-public-recovery-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  // The behavior tests are copied; this package test stays outside the capsule.
  for (const name of ['recovery-result.mjs', 'recovery-result.test.mjs'])
    await copyFile(new URL('./' + name, import.meta.url), join(root, name));
  const result = spawnSync(
    process.execPath,
    ['--test', '--test-reporter=tap', join(root, 'recovery-result.test.mjs')],
    {
      cwd: root,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, NODE_TEST_CONTEXT: undefined },
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, /# pass [1-9][0-9]*/u);
  assert.match(result.stdout, /# fail 0/u);
});
