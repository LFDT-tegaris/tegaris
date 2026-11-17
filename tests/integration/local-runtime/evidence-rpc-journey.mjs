import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';
import { authorRpcPolicy } from './evidence-rpc-policy.mjs';
import { releaseFirstPolicy } from './first-policy-workbench-browser.mjs';
import { terminalRpcAcceptance } from './evidence-rpc-terminal-custody.mjs';
import { factTargetActivationAcceptance } from './target-disposition-fact-journey.mjs';

const run = (command, args, input = '') =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'], timeout: 60000 });
    let output = '';
    child.stdout.on('data', (bytes) => {
      output += bytes;
      if (output.length > 1024 * 1024) child.kill();
    });
    child.once('error', () => reject(new Error('RPC journey child failed to start')));
    child.once('exit', (code, signal) => {
      if (code === 0) resolve(output);
      else reject(new Error(`RPC journey child failed: exit=${code}, signal=${signal}`));
    });
    child.stdin.end(input);
  });
await run('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [root, evidenceRoot] = process.argv.slice(2);
const secretRoot = join(root, 'secrets');
const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
assert.ok(Number.isSafeInteger(generation) && generation >= 2);
const suffix = generation === 2 ? '' : `-${generation}`;
const rpcJourney = `rpc-policy${suffix}`;
const input = JSON.parse(
  await readFile(join(evidenceRoot, `rpc-source${suffix}-policy-input.json`), 'utf8'),
);
const { candidateId } = JSON.parse(
  await readFile(join(evidenceRoot, `rpc-acquisition${suffix}/candidate.json`), 'utf8'),
);
const compose = JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const policyContainer = (
  await run(compose[0], [...compose.slice(1), 'ps', '-q', 'policy-service'])
).trim();
await withTransactionBrowser(
  {
    secretRoot,
    evidenceRoot,
    privacyDomainId: input.privacyDomainId,
    reuseSessions: true,
    artifacts: join(
      evidenceRoot,
      'rpc-journey-browser',
      new Date().toISOString().replaceAll(':', '-'),
    ),
  },
  async (browser) => {
    // Browser initialization and virtual-authenticator synchronization precede
    // the bounded Fact. Both subsequent journeys use these same real sessions.
    const started = Date.now();
    process.stdout.write(
      await run(process.execPath, [
        '--import',
        'tsx',
        'tests/integration/local-runtime/evidence-rpc-fact.mjs',
        'admission',
        root,
        evidenceRoot,
      ]),
    );
    const value = JSON.parse(
      await run(
        'docker',
        ['exec', '-i', policyContainer, '/usr/local/bin/policy_fact_reader'],
        JSON.stringify({
          participantId: input.participantId,
          privacyDomainId: input.privacyDomainId,
          candidateIds: [candidateId],
        }),
      ),
    );
    assert.equal(value.identity, 'OPENPC-FACT-OWNER-READ-1');
    assert.equal(value.snapshots.length, 1);
    const fact = value.snapshots[0];
    assert.equal(fact.outcome, 'PRESENT');
    assert.ok(
      fact.freshUntilMs > Date.now() + 20000,
      'Live source authority before timed browser path',
    );
    assert.ok(fact.shardDigest);
    await writeFile(join(evidenceRoot, `${rpcJourney}-fact.json`), JSON.stringify(fact), {
      mode: 0o600,
    });
    process.stdout.write(
      `OPENPC_RPC_TIMING|fact-ready|elapsed_ms=${Date.now() - started}|remaining_ms=${fact.freshUntilMs - Date.now()}\n`,
    );
    await authorRpcPolicy({ secretRoot, evidenceRoot, family: 'rpc', browser });
    process.stdout.write(
      `OPENPC_RPC_TIMING|authored|elapsed_ms=${Date.now() - started}|remaining_ms=${fact.freshUntilMs - Date.now()}\n`,
    );
    assert.ok(fact.freshUntilMs > Date.now(), 'Authoring never renews a Fact');
    await releaseFirstPolicy({
      secretRoot,
      evidenceRoot,
      inputPath: join(evidenceRoot, `${rpcJourney}-input.json`),
      journey: rpcJourney,
      browser,
      onRuntimeActivated: (context) =>
        factTargetActivationAcceptance({
          secretRoot,
          participantId: input.participantId,
          privacyDomainId: input.privacyDomainId,
          discovery: context.discovery,
          fact,
          rpc: () =>
            process.env.OPENPC_RPC_TERMINAL_ARCHIVE_ROOT
              ? terminalRpcAcceptance({
                  secretRoot,
                  archiveRoot: process.env.OPENPC_RPC_TERMINAL_ARCHIVE_ROOT,
                  ...context,
                })
              : new Promise((resolve, reject) => {
                  // Preserve releaseFirstPolicy's ordinary RPC custody path when
                  // supplying its composition hook, including its full duration.
                  const child = spawn(
                    process.execPath,
                    [
                      '--import',
                      'tsx',
                      'tests/integration/local-runtime/evidence-rpc-custody.mjs',
                      secretRoot,
                      input.participantId,
                      input.privacyDomainId,
                      context.discovery.targetId,
                      JSON.stringify(context.compose),
                      join(context.ownerRoot, 'data/runtime-bootstrap'),
                    ],
                    { stdio: 'inherit' },
                  );
                  child.once('error', reject);
                  child.once('exit', (code, signal) => {
                    if (code === 0) resolve();
                    else reject(new Error(`RPC custody failed: exit=${code}, signal=${signal}`));
                  });
                }),
        }),
    });
  },
);
