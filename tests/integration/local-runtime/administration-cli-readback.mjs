import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

// The caller supplies its real public OIDC session through stdin, never argv.
// No internal identity, database or business state is constructed here.
const [evidenceRoot, targetRef, operationId] = process.argv.slice(2);
assert.ok(evidenceRoot && targetRef && operationId);
let input = '';
for await (const chunk of process.stdin) {
  input += chunk.toString();
  if (input.length > 256) throw new Error('Invalid session input');
}
const sessionToken = input.trim();
if (!/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u.test(sessionToken)) throw new Error('Invalid session input');
const configPath = join(evidenceRoot, 'cli-config.json');
const secretPath = join(evidenceRoot, 'cli-session.json');
const origin = 'http://localhost:8080';
const config = {
  apiUrl: origin,
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  localDevelopment: true,
  sessionFile: 'cli-session.json',
};
async function cli(args, expectedExit = 0) {
  try {
    const result = await promisify(execFile)(
      process.execPath,
      ['--import', 'tsx', 'apps/admin-cli/src/main.ts', '--config', configPath, ...args],
      { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
    );
    assert.equal(expectedExit, 0);
    assert.equal(result.stderr, '');
    assert.ok(!result.stdout.includes(sessionToken));
    return JSON.parse(result.stdout);
  } catch (error) {
    assert.equal(error.code, expectedExit);
    assert.notEqual(expectedExit, 0);
    assert.equal(error.stdout, '');
    assert.ok(!error.stderr.includes(sessionToken));
    return JSON.parse(error.stderr);
  }
}
try {
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600, flag: 'wx' });
  await writeFile(secretPath, JSON.stringify({ origin, sessionToken }), {
    mode: 0o600,
    flag: 'wx',
  });
  const session = await cli(['session']);
  assert.equal(session.contextMode, 'PARTICIPANT');
  assert.equal(session.participantId, config.participantId);
  const target = await cli(['runtime-target', targetRef]);
  assert.equal(target.targetId, targetRef);
  assert.equal(target.state, 'ACTIVE_MATCHED');
  assert.equal(target.activeGenerationDigest, target.desiredGenerationDigest);
  const operation = await cli(['operation', operationId, '--wait-seconds', '2']);
  assert.equal(operation.operationId, operationId);
  assert.equal(operation.state, 'SUCCEEDED');
  await writeFile(
    configPath,
    JSON.stringify({ ...config, privacyDomainId: '018f0000-0000-7000-8000-000000000202' }),
  );
  assert.deepEqual(await cli(['runtime-target', targetRef], 3), { error: 'CONTEXT' });
  await writeFile(configPath, JSON.stringify(config));
  await writeFile(
    secretPath,
    JSON.stringify({
      origin,
      sessionToken: `${config.participantId}.018f0000-0000-7000-8000-000000009999`,
    }),
  );
  assert.deepEqual(await cli(['runtime-target', targetRef], 3), { error: 'AUTHENTICATION' });
  process.stdout.write(
    'OPENPC_ADMIN_CLI_READBACK|PASS|real-public-session|exact-target|original-operation|resumable-read|privacy-denial|invalid-session-denial|no-mutation\n',
  );
} finally {
  await rm(secretPath, { force: true });
  await rm(configPath, { force: true });
}
