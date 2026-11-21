import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const repository = fileURLToPath(new URL('../../', import.meta.url));
const lane = 'migrations/postgres/policy';
const anchor = '0014_module_installation_direct_assignment_epoch.sql';
const manifest = JSON.parse(
  await readFile(join(repository, 'migrations/postgres/baseline-v1/legacy-package.json'), 'utf8'),
);

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-policy-readiness-'));
  const source = join(root, 'source');
  const cache = join(root, 'cache');
  try {
    const current = join(source, lane);
    await mkdir(current, { recursive: true });
    await mkdir(join(source, 'scripts/migrations'), { recursive: true });
    await mkdir(join(source, 'migrations/postgres/baseline-v1'), { recursive: true });
    await mkdir(join(source, 'services/module-registry/src'), { recursive: true });
    await cp(
      join(repository, 'services/module-registry/src/db'),
      join(source, 'services/module-registry/src/db'),
      { recursive: true },
    );
    for (const name of [
      'scripts/migrations/legacy-inputs.mjs',
      'migrations/postgres/baseline-v1/legacy-package.json',
      `${lane}/${anchor}`,
    ])
      await cp(join(repository, name), join(source, name));
    await mkdir(join(cache, lane), { recursive: true });
    for (const path of Object.keys(manifest.files).filter(
      (name) => name.startsWith(`${lane}/`) && name.endsWith('.sql'),
    )) {
      const { stdout } = await execute(
        'git',
        ['-C', repository, 'show', `${manifest.source_commit}:${path}`],
        { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 },
      );
      await writeFile(join(cache, path), stdout);
    }
    const before = await readFile(join(current, anchor));
    async function command(name, environment = { OPENPC_LEGACY_SOURCE_ROOT: cache }) {
      const env = { ...process.env, ...environment };
      if (environment.OPENPC_LEGACY_SOURCE_ROOT === undefined) delete env.OPENPC_LEGACY_SOURCE_ROOT;
      return execute(process.execPath, [join(source, 'services/module-registry/src/db', name)], {
        cwd: source,
        env,
        encoding: 'utf8',
      });
    }
    await run({ source, cache, current, command });
    assert.deepEqual(await readFile(join(current, anchor)), before);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('Policy verification works in a compact checkout with authenticated historical inputs', async () => {
  await fixture(async ({ current, command }) => {
    await command('verify-policy-security.mjs');
    assert.deepEqual((await readdir(current)).sort(), [anchor]);
  });
});

test('new Policy migration receives the complete security projection without changing its anchor', async () => {
  await fixture(async ({ current, command }) => {
    const name = '0015_readiness_probe.sql';
    await writeFile(
      join(current, name),
      '-- Synthetic custom migration for generation validation.\n',
    );
    await command('generate-policy-security-tail.mjs');
    await command('verify-policy-security.mjs');
    assert.match(
      await readFile(join(current, name), 'utf8'),
      /CREATE TRIGGER policy_artifact_immutable/u,
    );
    assert.deepEqual((await readdir(current)).sort(), [anchor, name]);
  });
});

test('Policy generation refuses to overwrite an applied migration', async () => {
  await fixture(async ({ command }) => {
    await assert.rejects(command('generate-policy-security-tail.mjs'), /immutable/u);
  });
});

test('Policy verification rejects changed historical cache bytes', async () => {
  await fixture(async ({ cache, command }) => {
    await writeFile(join(cache, lane, '0000_yummy_plazm.sql'), 'SELECT 1;\n');
    await assert.rejects(command('verify-policy-security.mjs'), /Immutable/u);
  });
});

test('Policy verification explains the missing offline source prerequisite', async () => {
  await fixture(async ({ command }) => {
    await assert.rejects(
      command('verify-policy-security.mjs', { OPENPC_LEGACY_SOURCE_ROOT: undefined }),
      /verified offline compatibility package/u,
    );
  });
});
