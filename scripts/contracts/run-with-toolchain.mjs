import { constants, accessSync, mkdirSync, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const action = process.argv[2];
const command = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';

function requiredDirectory(variableName, environment = process.env) {
  const value = environment[variableName];
  if (!value) {
    throw new Error(`${variableName} is required.`);
  }

  const directory = resolve(value);
  try {
    if (!statSync(directory).isDirectory()) {
      throw new Error('not a directory');
    }
  } catch {
    throw new Error(`${variableName} must name an existing directory: ${directory}`);
  }
  return directory;
}

function requiredExecutable(directory, executable) {
  const path = resolve(directory, executable);
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new Error(`Required executable is unavailable: ${path}`);
  }
  return path;
}

function requiredTemporaryDirectory() {
  const value = process.env.OPENPC_PNC_TMP_ROOT;
  if (!value) {
    throw new Error('OPENPC_PNC_TMP_ROOT is required.');
  }

  const directory = resolve(value);
  if (directory === '/tmp' || directory.startsWith('/tmp/')) {
    throw new Error('OPENPC_PNC_TMP_ROOT must not use /tmp.');
  }
  mkdirSync(directory, { recursive: true });
  if (!statSync(directory).isDirectory()) {
    throw new Error(`OPENPC_PNC_TMP_ROOT must name a directory: ${directory}`);
  }
  return directory;
}

function run(program, args, environment) {
  const result = spawnSync(program, args, {
    cwd: process.cwd(),
    env: environment,
    stdio: 'inherit',
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const toolchainBin = process.env.OPENPC_CONTRACT_TOOLCHAIN_BIN;
const previousToolchainBin = process.env.OPENPC_C17_TOOLCHAIN_BIN;
if (toolchainBin !== undefined && (!toolchainBin || !isAbsolute(toolchainBin))) {
  throw new Error('OPENPC_CONTRACT_TOOLCHAIN_BIN must be an absolute directory.');
}
if (
  toolchainBin &&
  previousToolchainBin &&
  resolve(toolchainBin) !== resolve(previousToolchainBin)
) {
  throw new Error('Contract toolchain directory settings conflict.');
}
const selectedToolchainBin = toolchainBin ?? previousToolchainBin;
const temporaryRoot = requiredTemporaryDirectory();
const temporaryEnvironment = {
  ...process.env,
  ...(selectedToolchainBin === undefined
    ? {}
    : {
        OPENPC_CONTRACT_TOOLCHAIN_BIN: selectedToolchainBin,
        OPENPC_C17_TOOLCHAIN_BIN: selectedToolchainBin,
      }),
  ASYNCAPI_METRICS_CONFIG_PATH: resolve(temporaryRoot, 'asyncapi-analytics.json'),
  CI: 'true',
  TMPDIR: temporaryRoot,
  TMP: temporaryRoot,
  TEMP: temporaryRoot,
};

if (action === 'run-pnpm') {
  run(command, process.argv.slice(3), temporaryEnvironment);
} else if (action === 'run-node') {
  run(process.execPath, process.argv.slice(3), temporaryEnvironment);
} else if (action === 'run-tsx') {
  run(process.execPath, ['--import', 'tsx', ...process.argv.slice(3)], temporaryEnvironment);
} else {
  const directory = requiredDirectory('OPENPC_CONTRACT_TOOLCHAIN_BIN', temporaryEnvironment);
  const protoc = requiredExecutable(directory, 'protoc');
  const environment = {
    ...temporaryEnvironment,
    PATH: `${directory}:${process.env.PATH ?? ''}`,
    PROTOC: protoc,
  };

  if (action === 'generate-rust') {
    run(
      'cargo',
      ['run', '--locked', '-p', 'pc-contracts', '--bin', 'generate-rust-contracts'],
      environment,
    );
  } else if (action === 'validate-proto') {
    requiredExecutable(directory, 'buf');
    run(
      process.execPath,
      ['--import', 'tsx', 'tests/conformance/bootstrap/scripts/validate-proto.ts'],
      environment,
    );
  } else {
    throw new Error(
      'Expected a contract toolchain action: run-pnpm, run-node, run-tsx, generate-rust, or validate-proto.',
    );
  }
}
