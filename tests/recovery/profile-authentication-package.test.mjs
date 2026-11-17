import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('public profile checks run without retained profile files, registries or historical source', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-public-profiles-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  // Keep this package test outside the copied capsule to prevent child recursion.
  for (const name of [
    'profile-authentication.mjs',
    'profile-authentication.fixture.mjs',
    'profile-authentication.test.mjs',
  ])
    await copyFile(new URL('./' + name, import.meta.url), join(root, name));
  const result = spawnSync(
    process.execPath,
    ['--test', '--test-reporter=tap', join(root, 'profile-authentication.test.mjs')],
    {
      cwd: root,
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, NODE_TEST_CONTEXT: undefined },
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /# pass [1-9][0-9]*/u);
  assert.match(result.stdout, /# fail 0/u);
});
