import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

import { loadPublicModuleSource, moduleGenerationArguments } from './public-module-source.mjs';
import { publishModuleOutputs } from './module-generation-output.mjs';
import { withModuleFile } from './module-file-io.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const generator = 'services/module-registry/scripts/generate-module-contracts.mjs';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function temporary(t) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(path.join(parent, 'module-source-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function fixture(t) {
  const root = await temporary(t);
  await cp(
    path.join(repositoryRoot, 'policies/modules/source'),
    path.join(root, 'policies/modules/source'),
    {
      recursive: true,
    },
  );
  for (const name of [
    'generate-module-contracts.mjs',
    'public-module-source.mjs',
    'module-generation-output.mjs',
    'module-file-io.mjs',
  ]) {
    const destination = path.join(root, 'services/module-registry/scripts', name);
    await mkdir(path.dirname(destination), { recursive: true });
    await cp(path.join(repositoryRoot, 'services/module-registry/scripts', name), destination);
  }
  return root;
}

function invoke(root, args, extraEnvironment = {}) {
  const environment = { ...process.env, ...extraEnvironment };
  delete environment.OPENPC_C17_PACKAGE_ROOT;
  Object.assign(environment, extraEnvironment);
  return spawnSync(
    process.execPath,
    ['--max-old-space-size=1024', path.join(root, generator), ...args],
    {
      cwd: root,
      env: environment,
      encoding: 'utf8',
      timeout: 60_000,
      maxBuffer: 1024 * 1024,
    },
  );
}

async function generatedSnapshot(root, baseline) {
  const result = {};
  for (const item of baseline.outputs) {
    const absolute = path.join(root, item.path);
    result[item.path] = {
      sha256: hash(await readFile(absolute)),
      mode: (await lstat(absolute)).mode & 0o777,
    };
  }
  const provenance = 'policies/modules/generated/public-source-provenance.json';
  result[provenance] = { sha256: hash(await readFile(path.join(root, provenance))), mode: 0o644 };
  return result;
}

test('source profiles are explicit, closed and preserve historical default selection', () => {
  assert.deepEqual(moduleGenerationArguments([], {}), {
    profile: 'historical-c17',
    checkOnly: false,
  });
  assert.deepEqual(moduleGenerationArguments(['--check'], {}), {
    profile: 'historical-c17',
    checkOnly: true,
  });
  assert.deepEqual(moduleGenerationArguments(['--source-profile', 'public-v2', '--check'], {}), {
    profile: 'public-v2',
    checkOnly: true,
  });
  for (const args of [
    ['--source-profile'],
    ['--source-profile', 'unknown'],
    ['--source-profile', 'public-v1'],
    ['--skip-verification'],
    ['--check', '--check'],
    ['--source-profile', 'public-v2', '--source-profile', 'historical-c17'],
  ])
    assert.throws(() => moduleGenerationArguments(args, {}));
  for (const historical of ['', '/private-package'])
    assert.throws(
      () =>
        moduleGenerationArguments(['--source-profile', 'public-v2'], {
          OPENPC_C17_PACKAGE_ROOT: historical,
        }),
      /cannot be mixed/u,
    );
});

test('public source loads only the committed 46-input baseline and preserves all 55 output commitments', async (t) => {
  const root = await fixture(t);
  const source = await loadPublicModuleSource(root);
  assert.equal(source.baseline.inputs.length, 46);
  assert.equal(source.baseline.outputs.length, 55);
  assert.equal(source.baseline.historicalSourceVerification, 'NOT_PERFORMED');
  assert.equal(source.authorityCatalog.schemaVersion, '2.0');
  assert.throws(() => source.verifyOutputs(new Map()), /output inventory/u);
});

for (const corruption of [
  'definition',
  'catalogue',
  'manifest and input',
  'missing input',
  'unexpected input',
  'linked input',
  'linked directory',
]) {
  test(`public source rejects ${corruption} before generating any contract`, async (t) => {
    const root = await fixture(t);
    const source = path.join(root, 'policies/modules/source');
    const baseline = JSON.parse(await readFile(path.join(source, 'baseline.json'), 'utf8'));
    const definition = baseline.inputs.find((item) => item.path.startsWith('definitions/'));
    const target = path.join(source, definition.path);
    if (corruption === 'definition' || corruption === 'manifest and input') {
      await writeFile(target, 'altered definition');
      if (corruption === 'manifest and input') {
        definition.bytes = 18;
        definition.sha256 = hash(Buffer.from('altered definition'));
        await writeFile(path.join(source, 'baseline.json'), JSON.stringify(baseline));
      }
    } else if (corruption === 'catalogue')
      await writeFile(path.join(source, 'authority-catalog.json'), '{}');
    else if (corruption === 'missing input') await rm(target);
    else if (corruption === 'unexpected input')
      await writeFile(path.join(source, 'extra.json'), '{}');
    else if (corruption === 'linked input') {
      const outside = path.join(root, 'outside.json');
      await cp(target, outside);
      await rm(target);
      await symlink(outside, target);
    } else {
      const directory = path.join(source, 'definitions');
      const outside = path.join(root, 'outside-definitions');
      await cp(directory, outside, { recursive: true });
      await rm(directory, { recursive: true });
      await symlink(outside, directory);
    }
    const result = invoke(root, ['--source-profile', 'public-v2']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Public module source:/u);
    await assert.rejects(lstat(path.join(root, 'policies/modules/generated')), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(root, '.openpc-module-generation.lock')), {
      code: 'ENOENT',
    });
  });
}

test('public generation reproduces the committed contracts, adds provenance and checks without writing', async (t) => {
  const root = await fixture(t);
  const source = await loadPublicModuleSource(root);
  const incomplete = invoke(root, ['--source-profile', 'public-v2', '--check']);
  assert.notEqual(incomplete.status, 0);
  await assert.rejects(lstat(path.join(root, 'policies/modules/generated')), { code: 'ENOENT' });
  const generated = invoke(root, ['--source-profile', 'public-v2']);
  assert.equal(generated.status, 0, generated.stderr);
  const report = JSON.parse(generated.stdout);
  assert.equal(report.sourceProfile, 'TEGARIS_PUBLIC_MODULE_SOURCE_V2');
  assert.equal(report.historicalSourceVerification, 'NOT_PERFORMED');
  for (const item of source.baseline.outputs) {
    const bytes = await readFile(path.join(root, item.path));
    assert.equal(bytes.length, item.bytes, item.path);
    assert.equal(hash(bytes), item.sha256, item.path);
  }
  const proof = JSON.parse(
    await readFile(
      path.join(root, 'policies/modules/generated/public-source-provenance.json'),
      'utf8',
    ),
  );
  assert.equal(proof.historicalSourceVerification, 'NOT_PERFORMED');
  assert.equal(proof.runtimeAuthorityGranted, false);
  assert.deepEqual(proof.outputs, source.baseline.outputs);
  const before = await generatedSnapshot(root, source.baseline);
  const checked = invoke(root, ['--source-profile', 'public-v2', '--check']);
  assert.equal(checked.status, 0, checked.stderr);
  assert.deepEqual(await generatedSnapshot(root, source.baseline), before);
  const repeated = invoke(root, ['--source-profile', 'public-v2']);
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.deepEqual(await generatedSnapshot(root, source.baseline), before);
  assert.equal((await readdir(path.join(root, 'policies/modules/generated/manifests'))).length, 33);
  const foreign = path.join(root, 'policies/modules/generated/manifests/foreign.json');
  await writeFile(foreign, '{}');
  for (const args of [[], ['--check']]) {
    const rejected = invoke(root, ['--source-profile', 'public-v2', ...args]);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Unexpected generated output/u);
    assert.deepEqual(await generatedSnapshot(root, source.baseline), before);
    assert.equal(await readFile(foreign, 'utf8'), '{}');
  }
  await rm(foreign);
  const drift = path.join(root, source.baseline.outputs[0].path);
  await writeFile(drift, 'deliberately changed output');
  const withDrift = await generatedSnapshot(root, source.baseline);
  const rejected = invoke(root, ['--source-profile', 'public-v2', '--check']);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /Generated output drift/u);
  assert.deepEqual(await generatedSnapshot(root, source.baseline), withDrift);
});

test('historical default still requires its package and never falls back to public source', async (t) => {
  const root = await fixture(t);
  const missing = invoke(root, ['--check']);
  assert.notEqual(missing.status, 0);
  assert.match(
    missing.stderr,
    /OPENPC_C17_PACKAGE_ROOT must be an absolute authenticated C17 package path/u,
  );
  const invalid = invoke(root, ['--check'], {
    OPENPC_C17_PACKAGE_ROOT: path.join(root, 'missing-history'),
  });
  assert.notEqual(invalid.status, 0);
  assert.doesNotMatch(invalid.stdout, /"result":"PASS"/u);
  await assert.rejects(lstat(path.join(root, 'policies/modules/generated')), { code: 'ENOENT' });
});

test('publication restores the whole previous output set after a real replacement failure', async (t) => {
  assert.notEqual(process.getuid?.(), 0, 'Run permission-boundary tests as a non-root account');
  const root = await temporary(t);
  const first = path.join(root, 'policies/modules/generated/first.json');
  const second = path.join(root, 'crates/pc-module-sdk/src/generated.rs');
  for (const file of [first, second]) await mkdir(path.dirname(file), { recursive: true });
  await writeFile(first, 'original first');
  await writeFile(second, 'original second');
  await chmod(path.dirname(second), 0o555);
  try {
    await assert.rejects(
      publishModuleOutputs(
        root,
        new Map([
          [first, Buffer.from('replacement first')],
          [second, Buffer.from('replacement second')],
        ]),
        { checkOnly: false },
      ),
      { code: 'EACCES' },
    );
    assert.equal(await readFile(first, 'utf8'), 'original first');
    assert.equal(await readFile(second, 'utf8'), 'original second');
    await assert.rejects(lstat(path.join(root, '.openpc-module-generation.lock')), {
      code: 'ENOENT',
    });
  } finally {
    await chmod(path.dirname(second), 0o755);
  }
});

test('a generator never removes a lock owned by another writer', async (t) => {
  const root = await temporary(t);
  const lock = path.join(root, '.openpc-module-generation.lock');
  await mkdir(lock);
  await writeFile(path.join(lock, 'retained-owner'), 'another writer');
  const file = path.join(root, 'policies/modules/generated/first.json');
  await assert.rejects(
    publishModuleOutputs(root, new Map([[file, Buffer.from('{}')]]), { checkOnly: false }),
    { code: 'EEXIST' },
  );
  assert.equal(await readFile(path.join(lock, 'retained-owner'), 'utf8'), 'another writer');
  await assert.rejects(lstat(file), { code: 'ENOENT' });
});

test('concurrent publishers admit one writer and leave a complete result', async (t) => {
  const root = await temporary(t);
  const file = path.join(root, 'policies/modules/generated/first.json');
  const results = await Promise.allSettled(
    ['first', 'second'].map((value) =>
      publishModuleOutputs(root, new Map([[file, Buffer.from(value)]]), { checkOnly: false }),
    ),
  );
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = results.find((result) => result.status === 'rejected');
  assert.equal(rejected.reason.code, 'EEXIST');
  assert(['first', 'second'].includes(await readFile(file, 'utf8')));
  await assert.rejects(lstat(path.join(root, '.openpc-module-generation.lock')), {
    code: 'ENOENT',
  });
});

test('file operations preserve the original failure if closing also fails', async () => {
  for (const operation of ['read', 'write', 'sync']) {
    const original = new Error(operation + ' failed');
    const closing = new Error('close failed');
    const handle = {
      close: async () => {
        throw closing;
      },
    };
    await assert.rejects(
      withModuleFile(handle, async () => {
        throw original;
      }),
      (error) => {
        assert(error instanceof AggregateError);
        assert.deepEqual(error.errors, [original, closing]);
        return true;
      },
    );
  }
  const closing = new Error('close failed');
  await assert.rejects(
    withModuleFile(
      {
        close: async () => {
          throw closing;
        },
      },
      async () => 'read',
    ),
    (error) => error === closing,
  );
});

test('ordinary generation and CI invoke the explicit public profile without changing historical commands', async () => {
  const root = JSON.parse(await readFile(path.join(repositoryRoot, 'package.json'), 'utf8'));
  const module = JSON.parse(
    await readFile(path.join(repositoryRoot, 'services/module-registry/package.json'), 'utf8'),
  );
  assert.equal(module.scripts.generate, 'node scripts/generate-module-contracts.mjs');
  assert.equal(
    module.scripts['generate:check'],
    'node scripts/generate-module-contracts.mjs --check',
  );
  assert.equal(
    module.scripts['generate:public'],
    'node scripts/generate-module-contracts.mjs --source-profile public-v2',
  );
  assert.equal(
    module.scripts['generate:public:check'],
    module.scripts['generate:public'] + ' --check',
  );
  assert.match(root.scripts.generate, /--filter "!@openpc\/module-registry"/u);
  assert(
    root.scripts.generate.endsWith("pnpm --filter @openpc/module-registry run generate:public'"),
  );
  assert(
    root.scripts['test:unit'].includes(
      'node --test services/module-registry/scripts/public-module-source.test.mjs || status=1;',
    ),
  );
  const ci = await readFile(path.join(repositoryRoot, '.github/workflows/ci.yml'), 'utf8');
  assert(
    ci.includes(
      'run: bash scripts/maintenance/run-project.sh -- pnpm --filter @openpc/module-registry run generate:public:check',
    ),
  );
});

test('a FIFO at an external generated target is rejected without blocking', async (t) => {
  const root = await temporary(t);
  const target = path.join(root, 'crates/pc-policy-core/src/generated.rs');
  await mkdir(path.dirname(target), { recursive: true });
  const fifo = spawnSync('mkfifo', [target], { encoding: 'utf8', timeout: 3000 });
  assert.equal(fifo.status, 0, fifo.stderr);
  const helper = pathToFileURL(
    path.join(repositoryRoot, 'services/module-registry/scripts/module-generation-output.mjs'),
  ).href;
  const script = `import { publishModuleOutputs } from ${JSON.stringify(helper)}; await publishModuleOutputs(${JSON.stringify(root)}, new Map([[${JSON.stringify(target)}, Buffer.from('expected')]]), { checkOnly: true });`;
  const rejected = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
    encoding: 'utf8',
    timeout: 3000,
  });
  assert.notEqual(rejected.error?.code, 'ETIMEDOUT');
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /not a bounded regular file/u);
  assert((await lstat(target)).isFIFO());
  await assert.rejects(lstat(path.join(root, '.openpc-module-generation.lock')), {
    code: 'ENOENT',
  });
});
