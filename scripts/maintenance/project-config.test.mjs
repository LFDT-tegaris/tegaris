import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const repository = execFileSync('git', ['rev-parse', '--show-toplevel'], {
  encoding: 'utf8',
}).trim();
const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
  encoding: 'utf8',
}).trim();
const pins = JSON.parse(readFileSync(join(dirname(common), 'package.json'), 'utf8'));
assert.equal(
  process.version,
  `v${pins.engines.node}`,
  'Use the project toolchain before this regression',
);
const scratch = join(dirname(dirname(common)), 'Agents/tmp');
const fixture = mkdtempSync(join(scratch, 'openpc-config-test.'));
const expected = {
  autoInstallPeers: false,
  engineStrict: true,
  ignoreScripts: true,
  nodeLinker: 'isolated',
  pmOnFail: 'error',
  preferFrozenLockfile: true,
  saveExact: true,
  sharedWorkspaceLockfile: true,
  strictPeerDependencies: true,
  verifyStoreIntegrity: true,
  verifyDepsBeforeRun: 'error',
};
const env = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^pnpm_config_/iu.test(key)),
  ),
  COREPACK_ENABLE_NETWORK: '0',
  COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
  COREPACK_ENABLE_AUTO_PIN: '0',
  CI: 'true',
  pnpm_config_offline: 'true',
  pnpm_config_registry: 'http://127.0.0.1:9/',
  pnpm_config_config_dir: join(fixture, 'config'),
  pnpm_config_cache_dir: join(fixture, 'cache'),
  pnpm_config_state_dir: join(fixture, 'state'),
  pnpm_config_store_dir: join(fixture, 'store'),
  pnpm_config_npmrc_auth_file: join(fixture, 'auth.ini'),
};
function pnpm(args) {
  const result = spawnSync('pnpm', args, {
    cwd: fixture,
    env,
    encoding: 'utf8',
    timeout: 15_000,
    maxBuffer: 256 * 1024,
  });
  assert.equal(
    result.error,
    undefined,
    'The bounded pnpm process must terminate without prompting',
  );
  return result;
}
function files(directory, prefix = '') {
  const result = {};
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const name = join(prefix, entry.name);
    const path = join(directory, entry.name);
    if (entry.isDirectory()) Object.assign(result, files(path, name));
    else {
      assert.ok(!entry.isSymbolicLink(), 'Unexpected fixture symlink');
      result[name] = readFileSync(path).toString('base64');
    }
  }
  return result;
}
try {
  for (const directory of ['config', 'cache', 'state', 'store'])
    mkdirSync(join(fixture, directory));
  writeFileSync(join(fixture, 'auth.ini'), '');
  for (const path of ['.npmrc', 'pnpm-workspace.yaml'])
    writeFileSync(join(fixture, path), readFileSync(join(repository, path)));
  const manifest = {
    name: 'openpc-config-guard-fixture',
    private: true,
    version: '0.0.0',
    packageManager: pins.packageManager,
    engines: pins.engines,
    scripts: { sentinel: `node -e 'require("fs").writeFileSync("SENTINEL", "ran")'` },
  };
  const manifestPath = join(fixture, 'package.json');
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const version = pnpm(['--version']);
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), pins.engines.pnpm);
  const configResult = pnpm(['config', 'list', '--json']);
  assert.equal(configResult.status, 0);
  const config = JSON.parse(configResult.stdout);
  for (const [key, value] of Object.entries(expected)) assert.equal(config[key], value, key);

  // Real fixture installation has no dependencies and is offline. It establishes
  // pnpm's own workspace state without touching the project lock/modules/store.
  const prepared = pnpm(['install', '--offline', '--ignore-scripts']);
  assert.equal(prepared.status, 0, prepared.stderr || prepared.stdout);
  manifest.dependencies = { 'openpc-deliberately-uninstalled-fixture': '0.0.0' };
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const before = files(fixture);
  const stale = pnpm(['run', 'sentinel']);
  assert.notEqual(stale.status, 0, 'A stale workspace must not run its workload');
  assert.match(stale.stdout + stale.stderr, /ERR_PNPM_VERIFY_DEPS_BEFORE_RUN/u);
  assert.deepEqual(
    files(fixture),
    before,
    'Rejected run must not mutate workspace, lockfile or store',
  );
  assert.ok(!Object.hasOwn(files(fixture), 'SENTINEL'));

  // Check lock policy independently of application/test status.
  const lockPath = join(repository, 'pnpm-lock.yaml');
  const lock = existsSync(lockPath)
    ? readFileSync(lockPath, 'utf8')
    : execFileSync('git', ['show', 'HEAD:pnpm-lock.yaml'], { cwd: repository, encoding: 'utf8' });
  const lockedAutoPeers = /^ {2}autoInstallPeers: (true|false)$/mu.exec(lock)?.[1];
  assert.ok(lockedAutoPeers, 'Lockfile must explicitly record its peer installation policy');
  assert.equal(
    lockedAutoPeers,
    String(expected.autoInstallPeers),
    'The lock must match the accepted peer policy',
  );
  process.stdout.write(
    'PASS: effective pnpm 11 configuration; offline stale run refuses before sentinel without mutation\n',
  );
} finally {
  rmSync(resolve(fixture), { recursive: true, force: true });
}
