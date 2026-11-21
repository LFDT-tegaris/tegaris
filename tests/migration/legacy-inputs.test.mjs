import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrationInputs } from '../../scripts/migrations/legacy-inputs.mjs';

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-generation-input-'));
  const directory = join(root, 'identity');
  await mkdir(directory);
  const prior = process.env.OPENPC_LEGACY_SOURCE_ROOT;
  try {
    await run(root, directory);
  } finally {
    if (prior === undefined) delete process.env.OPENPC_LEGACY_SOURCE_ROOT;
    else process.env.OPENPC_LEGACY_SOURCE_ROOT = prior;
    await rm(root, { recursive: true });
  }
}

test('missing historical inputs require an explicit offline cache', async () => {
  await fixture(async (_root, directory) => {
    delete process.env.OPENPC_LEGACY_SOURCE_ROOT;
    await assert.rejects(migrationInputs(directory), /verified offline compatibility package/u);
  });
});

test('modified applied anchors are rejected before their SQL is returned', async () => {
  await fixture(async (root, directory) => {
    process.env.OPENPC_LEGACY_SOURCE_ROOT = root;
    await writeFile(join(directory, '0245_runtime_profile_approval_resume.sql'), 'SELECT 1;');
    const inputs = await migrationInputs(directory);
    await assert.rejects(
      inputs.readMigration('0245_runtime_profile_approval_resume.sql'),
      /Immutable/u,
    );
  });
});

test('new files remain readable while unknown names cannot escape the input set', async () => {
  await fixture(async (root, directory) => {
    process.env.OPENPC_LEGACY_SOURCE_ROOT = root;
    await writeFile(join(directory, '0246_new_guard.sql'), 'SELECT 1;');
    const inputs = await migrationInputs(directory);
    assert.equal(await inputs.readMigration('0246_new_guard.sql'), 'SELECT 1;');
    await assert.rejects(inputs.readMigration('../outside.sql'), /Unknown/u);
    await assert.rejects(inputs.readMigration('0247_unregistered.sql'), /Unknown/u);
  });
});
