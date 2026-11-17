import { closeSync, openSync, readFileSync } from 'node:fs';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const packageManager = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
const repositoryRoot = process.cwd();
const artifactDirectory = resolve(repositoryRoot, 'artifacts/i01');
const configuredTemporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!configuredTemporaryRoot) {
  throw new Error('OPENPC_PNC_TMP_ROOT is required.');
}
const temporaryRoot = resolve(configuredTemporaryRoot);

function runJson(program, args, name) {
  const outputPath = resolve(temporaryRoot, `${name}-${process.pid}.json`);
  const errorPath = resolve(temporaryRoot, `${name}-${process.pid}.stderr`);
  const output = openSync(outputPath, 'w');
  const error = openSync(errorPath, 'w');
  const result = spawnSync(program, args, {
    cwd: repositoryRoot,
    env: process.env,
    stdio: ['ignore', output, error],
  });
  closeSync(output);
  closeSync(error);
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `${program} ${args.join(' ')} failed:\n${readFileSync(errorPath, 'utf8') || readFileSync(outputPath, 'utf8')}`,
    );
  }
  const raw = readFileSync(outputPath, 'utf8').trim();
  const value = JSON.parse(raw);
  if (value && typeof value === 'object' && 'error' in value) {
    throw new Error(`${program} ${args.join(' ')} returned an error object.`);
  }
  return { errorPath, outputPath, raw, value };
}

async function writeAtomically(path, contents) {
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, contents, 'utf8');
  await rename(temporaryPath, path);
}

await mkdir(temporaryRoot, { recursive: true });
const pnpmLicenses = runJson(packageManager, ['licenses', 'list', '--json'], 'pnpm-licenses');
const cargoMetadata = runJson(
  'cargo',
  ['metadata', '--locked', '--format-version', '1'],
  'cargo-metadata',
);

await mkdir(artifactDirectory, { recursive: true });
await writeAtomically(
  resolve(artifactDirectory, 'licenses-pnpm.json'),
  `${JSON.stringify(pnpmLicenses.value, null, 2)}\n`,
);
await writeAtomically(resolve(artifactDirectory, 'cargo-metadata.json'), `${cargoMetadata.raw}\n`);
await Promise.all(
  [
    pnpmLicenses.outputPath,
    pnpmLicenses.errorPath,
    cargoMetadata.outputPath,
    cargoMetadata.errorPath,
  ].map((path) => rm(path, { force: true })),
);
