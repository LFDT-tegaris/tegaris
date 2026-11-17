import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir } from 'node:fs/promises';
import { readFile, mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  authenticateOperationsSources,
  publicOperationsSourceAnchor,
  publicOperationsSourceProfiles,
} from './installation-source-authentication.mjs';
import { readPublicOperationsSources } from './read-public-installation-sources.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
const sourceProfile = 'PUBLIC_OPERATIONS_SOURCE_V1';
const schemaBytes = await readFile(join(root, publicOperationsSourceAnchor.schemaPath));
const inventoryBytes = await readFile(
  join(root, 'config/source-authentication/public-operations-source-v1.json'),
);
const local = await readFile(join(root, 'config/profiles/local.yaml'));
const input = { sourceProfile, inventoryBytes, schemaBytes, profileBytes: local, profile: 'local' };
const rejects = (fn) =>
  assert.throws(fn, (error) => error.reason === 'C17_SOURCE_AUTHENTICATION_FAILED');

test('public source authentication covers every named profile with truthful bounded provenance', async () => {
  for (const [profile, entry] of Object.entries(publicOperationsSourceProfiles)) {
    const profileBytes = await readFile(join(root, entry.path));
    const result = authenticateOperationsSources({ ...input, profile, profileBytes });
    assert.equal(result.custody.version, 2);
    assert.equal(result.custody.sourceProfile, sourceProfile);
    assert.equal(result.custody.inventoryHex, inventoryBytes.toString('hex'));
    assert.equal(result.identity.sourceProfile, sourceProfile);
    assert.equal(result.identity.profile, profile);
    assert.deepEqual(Object.keys(result.identity).sort(), [
      'configurationSchemaDigest',
      'inventoryDigest',
      'namedProfileDigest',
      'profile',
      'sourceProfile',
    ]);
    assert.ok(
      Object.isFrozen(result) &&
        Object.isFrozen(result.identity) &&
        Object.isFrozen(result.custody),
    );
    assert.deepEqual(await readPublicOperationsSources({ sourceProfile, profile }), result);
  }
});
test('rejects changed configuration bytes, self-consistent forged inventory and cross-profile substitution', async () => {
  const forged = JSON.parse(inventoryBytes);
  forged.files[0].digest = 'sha256:' + '0'.repeat(64);
  const production = await readFile(join(root, 'config/profiles/production.yaml'));
  for (const change of [
    { schemaBytes: Buffer.concat([schemaBytes, Buffer.from(' ')]) },
    { profileBytes: Buffer.concat([local, Buffer.from('\n')]) },
    { inventoryBytes: Buffer.from(JSON.stringify(forged)) },
    { profileBytes: production },
    { profile: 'production' },
    { inventoryBytes: Buffer.alloc(publicOperationsSourceAnchor.inventoryBytes + 1) },
    { schemaBytes: Buffer.alloc(publicOperationsSourceAnchor.schemaBytes + 1) },
    { profileBytes: Buffer.alloc(65537) },
  ])
    rejects(() => authenticateOperationsSources({ ...input, ...change }));
});
test('requires the explicit public source and rejects downgrade, mixed inputs and caller pins', () => {
  const { sourceProfile: ignored, ...missing } = input;
  assert.equal(ignored, sourceProfile);
  for (const value of [
    missing,
    { ...input, sourceProfile: 'UNKNOWN' },
    { ...input, sourceProfile: null },
    { ...input, profile: 'constructor' },
    { ...input, profile: 'LOCAL' },
    { ...input, manifestBytes: inventoryBytes },
    { ...input, receiptBytes: Buffer.from('{}') },
    { ...input, inventoryDigest: publicOperationsSourceAnchor.inventoryDigest },
    { ...input, verified: true },
    { ...input, trustedPins: {} },
  ])
    rejects(() => authenticateOperationsSources(value));
});
test('rejects accessors without executing them and copies input bytes into immutable custody', () => {
  let called = false;
  const accessor = Object.defineProperty({ ...input }, 'inventoryBytes', {
    enumerable: true,
    get() {
      called = true;
      return inventoryBytes;
    },
  });
  rejects(() => authenticateOperationsSources(accessor));
  assert.equal(called, false);
  const copy = Buffer.from(local);
  const result = authenticateOperationsSources({ ...input, profileBytes: copy });
  copy.fill(0);
  assert.equal(result.custody.profileHex, local.toString('hex'));
});
test('loader authenticates unselected profiles too and rejects missing or linked inputs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'public-operations-source-'));
  try {
    const members = [
      publicOperationsSourceAnchor.schemaPath,
      'config/source-authentication/public-operations-source-v1.json',
      ...Object.values(publicOperationsSourceProfiles).map((v) => v.path),
    ];
    for (const path of members) {
      const target = join(directory, path);
      await mkdir(join(target, '..'), { recursive: true });
      await writeFile(target, await readFile(join(root, path)));
    }
    assert.equal(
      (await readPublicOperationsSources({ sourceProfile, profile: 'local', root: directory }))
        .custody.version,
      2,
    );
    const staging = join(directory, publicOperationsSourceProfiles.staging.path),
      original = await readFile(staging);
    await writeFile(staging, Buffer.concat([original, Buffer.from(' ')]));
    await assert.rejects(() =>
      readPublicOperationsSources({ sourceProfile, profile: 'local', root: directory }),
    );
    await writeFile(staging, original);
    await rm(staging);
    await assert.rejects(() =>
      readPublicOperationsSources({ sourceProfile, profile: 'local', root: directory }),
    );
    await symlink(join(root, publicOperationsSourceProfiles.staging.path), staging);
    await assert.rejects(() =>
      readPublicOperationsSources({ sourceProfile, profile: 'local', root: directory }),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test('loader rejects missing source/profile and trust overrides before filesystem access', async () => {
  for (const value of [
    { profile: 'local' },
    { sourceProfile },
    { sourceProfile, profile: 'constructor', root: '/missing' },
    { sourceProfile, profile: 'local', root: 'relative' },
    { sourceProfile, profile: 'local', trustedPins: {} },
  ])
    await assert.rejects(() => readPublicOperationsSources(value));
});

test('invalid generator invocation cannot rewrite the latest migration', async () => {
  const directory = join(root, 'migrations/postgres/control-api');
  const last = (await readdir(directory))
    .filter((name) => name.endsWith('.sql'))
    .sort()
    .at(-1);
  assert.ok(last);
  const path = join(directory, last),
    before = await readFile(path);
  const execute = promisify(execFile);
  for (const args of [['--unknown-public-source'], ['--operations-source-only', '--extra']])
    await assert.rejects(
      () =>
        execute(
          process.execPath,
          [
            '--import',
            'tsx',
            join(root, 'services/control-api/src/configuration/generate-security-tail.mjs'),
            ...args,
          ],
          { cwd: root, timeout: 30000 },
        ),
      (error) =>
        error.code === 1 && error.stderr.includes('Unsupported security-tail generation arguments'),
    );
  assert.deepEqual(await readFile(path), before);
});
