import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import path from 'node:path';

import { withModuleFile } from './module-file-io.mjs';

export const publicModuleProfile = 'TEGARIS_PUBLIC_MODULE_SOURCE_V1';
export const publicModuleBaselineSha256 =
  'f32398631cac109afe00083a5e0beaf9738f3a3b4b97db4143df1d59dc58e915';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (message) => {
  throw new Error(`Public module source: ${message}`);
};

export function moduleGenerationArguments(args, environment = process.env) {
  let profile = 'historical-c17';
  let checkOnly = false;
  let selected = false;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--check' && !checkOnly) checkOnly = true;
    else if (argument === '--source-profile' && !selected) {
      profile = args[++index];
      if (!['public-v1', 'historical-c17'].includes(profile)) fail('unknown source profile');
      selected = true;
    } else fail('unknown or repeated argument');
  }
  if (profile === 'public-v1' && environment.OPENPC_C17_PACKAGE_ROOT !== undefined)
    fail('public and historical source profiles cannot be mixed');
  return { profile, checkOnly };
}

function safeRelative(name) {
  return (
    typeof name === 'string' &&
    /^[A-Za-z0-9_./-]+$/u.test(name) &&
    !path.isAbsolute(name) &&
    !name.split('/').some((part) => ['', '.', '..'].includes(part))
  );
}

async function inventory(root, prefix = '') {
  const status = await lstat(root);
  if (!status.isDirectory() || status.isSymbolicLink()) fail('source directory is not regular');
  const files = [];
  for (const name of (await readdir(root)).sort()) {
    const relative = prefix ? `${prefix}/${name}` : name;
    if (!safeRelative(relative)) fail('invalid source path');
    const item = path.join(root, name);
    const entry = await lstat(item);
    if (entry.isSymbolicLink()) fail(`source links are not allowed: ${relative}`);
    if (entry.isDirectory()) files.push(...(await inventory(item, relative)));
    else if (entry.isFile()) files.push(relative);
    else fail(`nonregular source: ${relative}`);
  }
  return files.sort();
}

async function readRegular(root, name, expected) {
  if (!safeRelative(name)) fail('invalid source path');
  if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number')
    fail('no-follow file validation is unavailable');
  const handle = await open(
    path.join(root, name),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  return withModuleFile(handle, async () => {
    const before = await handle.stat();
    if (!before.isFile() || before.size > 32 * 1024 * 1024) fail('invalid source file');
    if (expected && before.size !== expected.bytes) fail(`source size mismatch: ${name}`);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      before.ino !== after.ino ||
      before.dev !== after.dev ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      bytes.length !== before.size
    )
      fail(`source changed during read: ${name}`);
    if (expected && digest(bytes) !== expected.sha256) fail(`source digest mismatch: ${name}`);
    return bytes;
  });
}

function validateRecords(records, count, label) {
  if (!Array.isArray(records) || records.length !== count) fail(`invalid ${label} inventory`);
  const names = new Set();
  for (const item of records) {
    if (
      !item ||
      Object.keys(item).sort().join(',') !== 'bytes,path,sha256' ||
      !safeRelative(item.path) ||
      !Number.isSafeInteger(item.bytes) ||
      item.bytes < 1 ||
      item.bytes > 40 * 1024 * 1024 ||
      !/^[0-9a-f]{64}$/u.test(item.sha256) ||
      names.has(item.path)
    )
      fail(`invalid ${label} commitment`);
    names.add(item.path);
    Object.freeze(item);
  }
  Object.freeze(records);
  return names;
}

export async function loadPublicModuleSource(repositoryRoot) {
  const root = path.join(repositoryRoot, 'policies/modules/source');
  const files = await inventory(root);
  const baselineBytes = await readRegular(root, 'baseline.json');
  if (digest(baselineBytes) !== publicModuleBaselineSha256) fail('baseline commitment mismatch');
  const baseline = JSON.parse(baselineBytes.toString('utf8'));
  if (
    Object.keys(baseline).sort().join(',') !==
      'authority,historicalSourceVerification,inputs,outputs,profileId,schemaVersion,sourcePackageId' ||
    baseline.schemaVersion !== '1.0' ||
    baseline.profileId !== publicModuleProfile ||
    baseline.sourcePackageId !== 'tegaris-module-contracts-v1' ||
    baseline.authority !== 'CONTRACT_GENERATION_ONLY' ||
    baseline.historicalSourceVerification !== 'NOT_PERFORMED'
  )
    fail('invalid baseline profile');
  const inputNames = validateRecords(baseline.inputs, 46, 'input');
  validateRecords(baseline.outputs, 55, 'output');
  if (
    !inputNames.has('authority-catalog.json') ||
    [...inputNames].filter((name) => name.startsWith('definitions/')).length !== 45
  )
    fail('invalid definition inventory');
  const expectedFiles = [...inputNames, 'baseline.json', 'README.md'].sort();
  if (
    files.length !== expectedFiles.length ||
    files.some((name, index) => name !== expectedFiles[index])
  )
    fail('source inventory mismatch');
  let authorityCatalog;
  for (const item of baseline.inputs) {
    const bytes = await readRegular(root, item.path, item);
    if (item.path === 'authority-catalog.json')
      authorityCatalog = JSON.parse(bytes.toString('utf8'));
  }
  if (
    authorityCatalog?.schemaVersion !== '2.0' ||
    authorityCatalog?.catalogId !== 'OPENPC-I03-TRACE-AUTHORITY-CATALOG-R7'
  )
    fail('invalid projected authority catalogue');
  return {
    sourceRoot: path.join(root, 'definitions'),
    authorityCatalog,
    baseline: Object.freeze(baseline),
    verifyOutputs(outputs) {
      if (outputs.size !== baseline.outputs.length) fail('generated output inventory mismatch');
      for (const item of baseline.outputs) {
        const bytes = outputs.get(path.join(repositoryRoot, item.path));
        if (!bytes || bytes.length !== item.bytes || digest(bytes) !== item.sha256)
          fail(`generated contract differs from the approved baseline: ${item.path}`);
      }
    },
    provenance() {
      return Buffer.from(
        `${JSON.stringify(
          {
            schemaVersion: '1.0',
            sourceProfile: publicModuleProfile,
            sourcePackageId: baseline.sourcePackageId,
            baselineSha256: publicModuleBaselineSha256,
            historicalSourceVerification: 'NOT_PERFORMED',
            runtimeAuthorityGranted: false,
            outputs: baseline.outputs,
          },
          null,
          2,
        )}\n`,
      );
    },
  };
}
