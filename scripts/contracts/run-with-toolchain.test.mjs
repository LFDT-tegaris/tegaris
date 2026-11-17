import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./run-with-toolchain.mjs', import.meta.url));
const publicVariable = 'OPENPC_CONTRACT_TOOLCHAIN_BIN';
const previousVariable = 'OPENPC_C17_TOOLCHAIN_BIN';

function fixture(run) {
  const parent = process.env.OPENPC_PNC_TMP_ROOT ?? resolve('.openpc-tmp');
  mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, 'contract-toolchain-'));
  const bin = join(root, 'bin');
  mkdirSync(bin);
  const environment = { ...process.env, OPENPC_PNC_TMP_ROOT: join(root, 'temporary') };
  delete environment[publicVariable];
  delete environment[previousVariable];
  const invoke = (
    settings = {},
    args = [
      'run-node',
      '-e',
      `process.stdout.write(JSON.stringify({selected:process.env.${publicVariable}??null,previous:process.env.${previousVariable}??null}))`,
    ],
  ) => {
    const result = spawnSync(process.execPath, [runner, ...args], {
      env: { ...environment, ...settings },
      encoding: 'utf8',
    });
    assert.ifError(result.error);
    return result;
  };
  try {
    run({ root, bin, invoke });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('contributor toolchain setting reaches existing child consumers', () => {
  fixture(({ bin, invoke }) => {
    const result = invoke({ [publicVariable]: bin });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { selected: bin, previous: bin });
  });
});

test('existing toolchain configuration remains supported', () => {
  fixture(({ bin, invoke }) => {
    const result = invoke({ [previousVariable]: bin });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { selected: bin, previous: bin });
  });
});

test('equivalent toolchain settings select the same directory', () => {
  fixture(({ bin, invoke }) => {
    const result = invoke({ [publicVariable]: bin, [previousVariable]: join(bin, '.') });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { selected: bin, previous: bin });
  });
});

test('conflicting toolchain settings stop before child execution', () => {
  fixture(({ root, bin, invoke }) => {
    const result = invoke({ [publicVariable]: bin, [previousVariable]: join(root, 'other') });
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Contract toolchain directory settings conflict/u);
  });
});

test('empty and relative contributor toolchain settings are rejected', () => {
  fixture(({ invoke }) => {
    for (const value of ['', 'relative/tools']) {
      const result = invoke({ [publicVariable]: value });
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /OPENPC_CONTRACT_TOOLCHAIN_BIN must be an absolute directory/u);
    }
  });
});

test('Node-only contract commands do not require compiler tools', () => {
  fixture(({ invoke }) => {
    const result = invoke();
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { selected: null, previous: null });
  });
});

test('compiler actions reject missing directories and executables', () => {
  fixture(({ root, bin, invoke }) => {
    for (const value of [join(root, 'missing'), bin]) {
      const result = invoke({ [publicVariable]: value }, ['generate-rust']);
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(
        result.stderr,
        /must name an existing directory|Required executable is unavailable/u,
      );
    }
  });
});

test(
  'Rust generation receives the selected compiler path and unchanged arguments',
  { skip: process.platform === 'win32' },
  () => {
    fixture(({ bin, invoke }) => {
      writeFileSync(join(bin, 'protoc'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      writeFileSync(
        join(bin, 'cargo'),
        `#!/usr/bin/env node
process.stdout.write(JSON.stringify({arguments:process.argv.slice(2),protoc:process.env.PROTOC,firstPath:process.env.PATH.split(${JSON.stringify(delimiter)})[0]}));
`,
        { mode: 0o755 },
      );
      const result = invoke({ [publicVariable]: bin }, ['generate-rust']);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), {
        arguments: ['run', '--locked', '-p', 'pc-contracts', '--bin', 'generate-rust-contracts'],
        protoc: join(bin, 'protoc'),
        firstPath: bin,
      });
    });
  },
);

test(
  'compiler command failures keep their nonzero status',
  { skip: process.platform === 'win32' },
  () => {
    fixture(({ bin, invoke }) => {
      writeFileSync(join(bin, 'protoc'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      writeFileSync(join(bin, 'cargo'), '#!/bin/sh\nexit 7\n', { mode: 0o755 });
      assert.equal(invoke({ [publicVariable]: bin }, ['generate-rust']).status, 7);
    });
  },
);

test('ordinary unit CI includes contributor toolchain coverage and uses the public setting', () => {
  const document = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.match(document.scripts['test:unit'], /scripts\/contracts\/run-with-toolchain\.test\.mjs/u);
  const workflow = readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.match(workflow, /OPENPC_CONTRACT_TOOLCHAIN_BIN:/u);
  assert.match(workflow, /install-contract-toolchain\.sh "\$OPENPC_CONTRACT_TOOLCHAIN_BIN"/u);
  assert.doesNotMatch(workflow, /OPENPC_C17_TOOLCHAIN_BIN/u);
});
