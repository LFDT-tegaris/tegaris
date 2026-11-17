import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const root = process.cwd();
const toolchain = process.env.OPENPC_C17_TOOLCHAIN_BIN;
const programmeControlTemporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!toolchain) {
  throw new Error('OPENPC_C17_TOOLCHAIN_BIN is required for C17 proto validation.');
}
if (!programmeControlTemporaryRoot) {
  throw new Error('OPENPC_PNC_TMP_ROOT is required; OpenPC validation may not use /tmp.');
}
const environment = { ...process.env, PATH: `${toolchain}:${process.env.PATH}` };
const execute = (command: string, args: string[]) => {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', env: environment });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed:\n${result.stderr || result.stdout}`);
  }
};

execute('buf', ['lint', 'proto']);
execute('buf', ['format', '--diff', 'proto']);

await mkdir(programmeControlTemporaryRoot, { recursive: true });
const descriptorDirectory = await mkdtemp(
  join(resolve(programmeControlTemporaryRoot), 'i01-proto-'),
);
try {
  const protos = [
    'common/v1/common.proto',
    'control/v1/control.proto',
    'evidence/v1/evidence.proto',
    'facts/v1/facts.proto',
    'fleet/v1/fleet.proto',
    'runtime/v1/runtime.proto',
  ].map((path) => `openpc/${path}`);
  execute('protoc', [
    '--proto_path=proto',
    `--descriptor_set_out=${resolve(descriptorDirectory, 'openpc.pb')}`,
    '--include_imports',
    ...protos,
  ]);
} finally {
  await rm(descriptorDirectory, { force: true, recursive: true });
}
