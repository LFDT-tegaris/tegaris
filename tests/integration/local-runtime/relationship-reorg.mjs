// REQ-SR01-B0-REQ-MOD-PC_DYNAMIC_EVENT_ORDERING-03: a real source fork
// invalidates dynamic authority while a protected provider response is held.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, rm, rename } from 'node:fs/promises';
import { join } from 'node:path';
import https from 'node:https';
import { assertRequestEvidence } from './visibility-response.mjs';

const [root, evidence, image, targetContainer, targetId, policyContainer] = process.argv.slice(2);
const data = join(root, 'data/rpc-provider');
const secrets = join(root, 'secrets');
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const fact = await load(join(evidence, 'typed-policy-fact.json'));
assert.ok(fact.freshUntilMs - Date.now() > 7_000, 'reorg requires a live original Fact window');
const candidate = await load(join(evidence, 'acquisition/candidate.json'));
const config = await load(join(evidence, 'acquisition/config.json'));
const readDecisions = () => {
  const result = spawnSync(
    'docker',
    [
      'exec',
      targetContainer,
      '/usr/local/bin/openpc-control-worker',
      'runtime-evidence-snapshot',
      'rpc',
    ],
    { encoding: 'utf8', timeout: 10_000 },
  );
  assert.equal(result.status, 0, 'protected decision readback failed');
  const snapshot = JSON.parse(result.stdout);
  assert.equal(snapshot.target_id, targetId, 'protected readback must name the requested target');
  return snapshot;
};
const readFact = () => {
  const result = spawnSync(
    'docker',
    ['exec', '-i', policyContainer, '/usr/local/bin/policy_fact_reader'],
    {
      input: JSON.stringify({
        participantId: config.participant_id,
        privacyDomainId: config.privacy_domain_id,
        candidateIds: [candidate.candidateId],
      }),
      encoding: 'utf8',
      timeout: 5_000,
    },
  );
  assert.equal(result.status, 0, 'signed Fact readback failed');
  return JSON.parse(result.stdout);
};
const before = readDecisions();
const hold = join(data, 'visibility-hold'),
  contact = join(data, 'visibility-contact');
const verificationHold = join(data, 'reorg-observation-hold'),
  verificationContact = join(data, 'reorg-observation-contact');
const branch = join(data, 'source-chain.json');
const previousBranch = await readFile(branch).catch((error) => {
  if (error.code === 'ENOENT') return null;
  throw error;
});
assert.equal(previousBranch, null, 'the owned external chain must begin unforked');
await rm(contact, { force: true });
await rm(verificationContact, { force: true });
await writeFile(join(data, 'visibility-mode'), 'CLOSED_RELATIONSHIP');
await writeFile(hold, 'hold', { mode: 0o600 });
await writeFile(verificationHold, 'hold', { mode: 0o600 });
const body = JSON.stringify({
  jsonrpc: '2.0',
  id: 34,
  method: 'eth_getLogs',
  params: [
    {
      address: `0x${'11'.repeat(20)}`,
      fromBlock: '0xa',
      toBlock: '0xa',
      topics: ['0x938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b829'],
    },
  ],
});
const options = {
  host: '127.0.0.1',
  port: 18545,
  servername: 'localhost',
  method: 'POST',
  path: '/rpc',
  ca: await readFile(join(secrets, 'identity_mtls_ca.pem')),
  cert: await readFile(join(secrets, 'identity_mtls_rotated_cert.pem')),
  key: await readFile(join(secrets, 'identity_mtls_rotated_key.pem')),
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  headers: {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'x-openpc-identity-assertion': process.env.OPENPC_RELATIONSHIP_ASSERTION,
  },
};
let request,
  pending,
  completed = false;
async function waitContact(path, maximumMs, protectedRequest = false) {
  const started = Date.now();
  let contactedAt;
  while (contactedAt === undefined) {
    if (protectedRequest)
      assert.equal(completed, false, 'protected request must reach the external barrier');
    const value = await readFile(path, 'utf8').catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (value !== null) contactedAt = Number(value);
    else {
      assert.ok(
        Date.now() - started < maximumMs,
        'external verification/response barrier not observed',
      );
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  return contactedAt;
}
try {
  await writeFile(`${branch}.next`, JSON.stringify({ forkHeight: 10, hashOffset: 64 }), {
    mode: 0o600,
  });
  await rename(`${branch}.next`, branch);
  const result = spawnSync(
    'docker',
    [
      'run',
      '--rm',
      '--network',
      'host',
      '--cpus',
      '1',
      '--memory',
      '256m',
      '--memory-swap',
      '256m',
      '--pids-limit',
      '64',
      '--user',
      `${process.getuid()}:${process.getgid()}`,
      '-v',
      `${root}:${root}:ro`,
      '-e',
      `OPENPC_ACQUISITION_CONFIG_FILE=${join(evidence, 'acquisition/reorg-config.json')}`,
      '--entrypoint',
      '/usr/local/bin/openpc-acquire-candidate-batch',
      image,
    ],
    { encoding: 'utf8', timeout: 10_000 },
  );
  await writeFile(join(evidence, 'acquisition/relationship-reorg-result.json'), result.stdout, {
    mode: 0o600,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).outcome, 'REORG_INVALIDATED');
  await waitContact(verificationContact, 4_000);
  // The Candidate event cannot itself invalidate a signed Fact. Keep the
  // independent final header response held while the protected read begins.
  assert.equal(readFact().snapshots[0].outcome, 'PRESENT');
  assert.ok(
    fact.freshUntilMs - Date.now() > 2_000,
    'fresh authority required before the timed read',
  );
  const requestStarted = Date.now();
  pending = new Promise((resolve, reject) => {
    request = https.request(options, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () =>
        resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }),
      );
    });
    request.on('error', reject);
    request.setTimeout(5_000, () => request.destroy(new Error('protected request timed out')));
    request.end(body);
  });
  void pending.then(
    () => {
      completed = true;
    },
    () => {
      completed = true;
    },
  );
  await waitContact(contact, 1_500, true);
  await writeFile(verificationHold, 'release');
  let observed;
  do {
    observed = readFact();
    if (observed.snapshots[0].outcome === 'REORG') break;
    assert.ok(
      Date.now() - requestStarted < 1_700,
      'reorg must precede the protected response deadline',
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
  } while (observed.snapshots[0].outcome !== 'REORG');
  await writeFile(join(evidence, 'relationship-fact-reorg.json'), JSON.stringify(observed), {
    mode: 0o600,
  });
  assert.ok(Date.now() - requestStarted < 1_700, 'invalidation must occur during the live request');
  assert.ok(fact.freshUntilMs > Date.now(), 'the original Fact must still be live');
  await writeFile(hold, 'release');
  const response = await pending;
  await writeFile(join(evidence, 'response-relationship-reorg.json'), JSON.stringify(response), {
    mode: 0o600,
  });
  const value = JSON.parse(response.body);
  assert.notEqual(response.status, 200, 'forked dynamic authority must suppress protected bytes');
  assert.equal(value.id, 34);
  assert.equal(value.result, undefined);
  assert.ok(
    ['PC-RUNTIME-3004', 'PC-RUNTIME-3009'].includes(value.error?.data?.pcCode),
    response.body,
  );
  assert.ok(fact.freshUntilMs > Date.now(), 'expiry cannot stand in for reorg suppression');
  assert.ok(
    Date.now() - requestStarted < 2_000,
    'provider timeout cannot stand in for reorg suppression',
  );
  const after = readDecisions();
  assertRequestEvidence(before, after, { forwarded: true, traceId: value.error?.data?.traceId });
  await writeFile(join(evidence, 'decisions-relationship-reorg.json'), JSON.stringify(after), {
    mode: 0o600,
  });
  process.stdout.write(
    'OPENPC_RELATIONSHIP_REORG|PASS|real-source-fork|signed-reorg|live-original-fact|held-response-suppressed\n',
  );
} finally {
  request?.destroy();
  await pending?.catch(() => {});
  await writeFile(verificationHold, 'release');
  await rm(hold, { force: true });
  await rm(contact, { force: true });
  await rm(verificationHold, { force: true });
  await rm(verificationContact, { force: true });
  await rm(branch, { force: true });
}
