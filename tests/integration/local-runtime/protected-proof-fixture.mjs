import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, open, readFile, lstat, writeFile } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const [dataRoot, image] = process.argv.slice(2);
assert.ok(dataRoot && isAbsolute(dataRoot));
assert.match(image ?? '', /^sha256:[0-9a-f]{64}$/u);
const inspected = JSON.parse((await exec('docker', ['image', 'inspect', image])).stdout)[0];
assert.equal(inspected.Config.Labels['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
assert.equal(inspected.Config.Labels['io.openpc.image.service'], 'control-api');
const directory = join(dataRoot, 'protected-proofs');
await mkdir(directory, { recursive: true, mode: 0o755 });
const directoryStat = await lstat(directory);
assert.ok(directoryStat.isDirectory() && !directoryStat.isSymbolicLink());
assert.equal(directoryStat.uid, process.getuid());
// The enclosing owned run root remains private. This mounted directory must
// be traversable by the image UID even when the caller uses umask 077.
await chmod(directory, 0o755);
const path = join(directory, 'encryption.key');
try {
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(randomBytes(32));
  } finally {
    await file.close();
  }
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
}
const stat = await lstat(path);
assert.equal(stat.isFile(), true);
assert.equal(stat.mode & 0o077, 0);
assert.equal(stat.size, 32);
const config = {
  activeKeyId: 'local-protected-v1',
  keys: [{ keyId: 'local-protected-v1', keyFile: '/app/protected-proofs/encryption.key' }],
};
for (const [name, value] of [
  ['keys.json', JSON.stringify(config)],
  ['control.env', 'CONTROL_API_PROTECTED_PROOF_KEYS_FILE=/app/protected-proofs/keys.json\n'],
]) {
  try {
    await writeFile(join(directory, name), value, {
      flag: 'wx',
      mode: name === 'keys.json' ? 0o444 : 0o600,
    });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const retained = await lstat(join(directory, name));
  const mode = name === 'keys.json' ? 0o444 : 0o600;
  assert.ok(retained.isFile() && !retained.isSymbolicLink());
  assert.equal(retained.uid, process.getuid());
  assert.ok([mode, mode & 0o700].includes(retained.mode & 0o777));
  assert.equal(await readFile(join(directory, name), 'utf8'), value);
  await chmod(join(directory, name), mode);
}
// Resolve the actual image user; the private key is mounted only in Control API.
await exec(
  'docker',
  [
    'run',
    '--rm',
    '--pull',
    'never',
    '--network',
    'none',
    '--memory',
    '128m',
    '--memory-swap',
    '128m',
    '--cpus',
    '0.5',
    '--pids-limit',
    '32',
    '--read-only',
    '--user',
    '0',
    '--security-opt',
    'no-new-privileges:true',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'CHOWN',
    '--mount',
    `type=bind,source=${directory},target=/protected`,
    '--entrypoint',
    'sh',
    image,
    '-ec',
    'test -f /protected/encryption.key && test ! -L /protected/encryption.key; chown "$(id -u openpc):$(id -g openpc)" /protected/encryption.key',
  ],
  { timeout: 15000 },
);
process.stdout.write('OPENPC_PROTECTED_PROOF_FIXTURE|PASS|dedicated-key|retained-configuration\n');
