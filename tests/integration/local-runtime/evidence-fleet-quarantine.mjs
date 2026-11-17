import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createECDH } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';
import { archiveNativeFleetFailure } from './evidence-fleet-failure-archive.mjs';

// A distinct, publicly acquired candidate is admitted through its real owner.
// The original Fact is never edited: only this consumer's verification key is
// deliberately wrong. Native leases/retries/quarantine own every resulting effect.
const execute = promisify(execFile);
const run = async (command, args, env = process.env) => {
  try {
    return (await execute(command, args, { env, timeout: 60000, maxBuffer: 1024 * 1024 })).stdout;
  } catch (error) {
    // execFile errors embed arguments, which may include real local sessions.
    throw new Error(`Native Fleet journey child failed: status=${error.code ?? 'unknown'}`);
  }
};
await run('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [root, evidenceRoot] = process.argv.slice(2);
const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION);
assert.ok(Number.isSafeInteger(generation) && generation >= 3);
const suffix = `-${generation}`;
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const { participantId, privacyDomainId } = await load(
  join(evidenceRoot, `rpc-source${suffix}-policy-input.json`),
);
const { candidateId } = await load(join(evidenceRoot, `rpc-acquisition${suffix}/candidate.json`));
const compose = JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const secretRoot = join(root, 'secrets');
const archiveRoot = join(evidenceRoot, `native-fleet-quarantine${suffix}`);
await mkdir(archiveRoot, { recursive: true, mode: 0o700 });
const password = async (name) => (await readFile(join(secretRoot, name), 'utf8')).trim();
const control = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: await password('control_pg_password.txt'),
  max: 1,
  options: '-c default_transaction_read_only=on',
});
const facts = new Pool({
  host: '127.0.0.1',
  port: 55433,
  database: 'openpc_facts',
  user: 'openpc_facts',
  password: await password('fact_pg_password.txt'),
  max: 1,
  options: '-c default_transaction_read_only=on',
});
const scope = [participantId, privacyDomainId];
const delivery = async () =>
  (
    await control.query(
      'select * from control.fleet_fact_delivery where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
      [...scope, candidateId],
    )
  ).rows;
const forbidden = async () => ({
  inbox: (
    await control.query(
      'select * from control.fleet_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2 order by event_id',
      scope,
    )
  ).rows,
  cursor: (
    await control.query(
      'select * from control.fleet_fact_admission_cursor where participant_id=$1 and privacy_domain_id=$2 order by fact_type',
      scope,
    )
  ).rows,
  acks: (
    await facts.query(
      'select * from facts.fleet_admission_ack where participant_id=$1 and privacy_domain_id=$2 order by event_id',
      scope,
    )
  ).rows,
});
try {
  assert.equal(
    (await run(compose[0], [...compose.slice(1), 'ps', '-q', 'control-worker'])).trim(),
    '',
    'Background Fleet consumer must be stopped before admission',
  );
  const initial = await forbidden();
  assert.ok(!initial.inbox.some((row) => row.candidate_id === candidateId));
  const profile = (
    await control.query(
      `select p.claims from control.fact_consumer_profile p
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.consumer_id='LS-FLEET-CONTROL'
    order by p.revision desc limit 1`,
      scope,
    )
  ).rows;
  assert.equal(profile.length, 1);
  assert.ok(
    Number(profile[0].claims.validUntilMs) > Date.now() + 120000,
    'Installed authority must cover the bounded failure journey',
  );
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot,
      privacyDomainId,
      reuseSessions: true,
      artifacts: join(
        archiveRoot,
        'admission-browser',
        new Date().toISOString().replaceAll(':', '-'),
      ),
    },
    async () => {
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
    },
  );
  const originals = async () =>
    (
      await facts.query(
        `select f.candidate_id,f.generation_id,f.cose_sign1,f.fact_digest,e.event_id::text,e.envelope
    from facts.canonical_fact f join facts.admission_delivery_event e using(participant_id,privacy_domain_id,candidate_id)
    where f.participant_id=$1 and f.privacy_domain_id=$2 order by e.event_id`,
        scope,
      )
    ).rows;
  const originalFacts = await originals();
  const source = originalFacts.filter((row) => row.candidate_id === candidateId);
  assert.equal(source.length, 1);
  const assertProducerPending = async () => {
    const pending = (
      await facts.query(
        `select o.delivery_state,
      exists(select 1 from facts.control_admission_custody_ack a where a.candidate_id=o.candidate_id
        and a.participant_id=o.participant_id and a.privacy_domain_id=o.privacy_domain_id) control_ack
      from facts.outbox o where o.participant_id=$1 and o.privacy_domain_id=$2 and o.candidate_id=$3`,
        [...scope, candidateId],
      )
    ).rows;
    assert.deepEqual(pending, [{ delivery_state: 'PENDING', control_ack: false }]);
  };
  await assertProducerPending();
  assert.deepEqual(
    originalFacts
      .filter((row) => !initial.inbox.some((item) => item.event_id === row.event_id))
      .map((row) => row.candidate_id),
    [candidateId],
    'No unrelated pending Fact may be poisoned',
  );
  const wrongKey = join(archiveRoot, 'wrong-public-key.sec1');
  try {
    const key = createECDH('prime256v1');
    key.generateKeys();
    await writeFile(wrongKey, key.getPublicKey(), { flag: 'wx', mode: 0o444 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  assert.notDeepEqual(
    await readFile(wrongKey),
    await readFile(join(secretRoot, 'policy_fact_verify_key.sec1')),
  );
  const tick = async (wrong = true) => {
    const args = [...compose.slice(1), 'run', '--rm', '--no-deps', '--pull', 'never'];
    if (wrong)
      args.push(
        '-v',
        `${wrongKey}:/wrong-fact-key:ro`,
        '-e',
        'CONTROL_WORKER_FACT_VERIFY_KEY_FILE=/wrong-fact-key',
      );
    args.push('control-worker', 'fact-admission-once');
    assert.match(
      await run(compose[0], args),
      /FLEET_FACT_ADMISSION\|PASS\|committed=0\|runtime_authority=NONE/u,
    );
  };
  for (let invocation = 0; invocation < 16; invocation++) {
    const before = await delivery();
    assert.ok(before.length <= 1);
    if (before[0]?.state === 'QUARANTINED') break;
    if (before[0]) {
      assert.ok(['WAITING', 'EXHAUSTED'].includes(before[0].state));
      const wait = Math.max(0, Number(before[0].next_attempt_ms) - Date.now());
      assert.ok(wait <= 30000, 'Bounded installed retry profile');
      await new Promise((resolve) => setTimeout(resolve, wait + 5));
    }
    await tick();
    const after = (await delivery())[0];
    assert.ok(after);
    assert.ok(after.failed_attempts <= after.maximum_attempts);
    assert.equal(after.last_problem, 'PC-DATA-6005');
    assert.deepEqual(await forbidden(), initial);
    assert.deepEqual(await originals(), originalFacts);
    await assertProducerPending();
  }
  const terminal = (await delivery())[0];
  assert.equal(terminal.state, 'QUARANTINED');
  assert.equal(terminal.failed_attempts, terminal.maximum_attempts);
  const attempts = (
    await control.query(
      'select * from control.fleet_fact_delivery_attempt where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 order by lease_generation',
      [...scope, source[0].event_id],
    )
  ).rows;
  assert.equal(attempts.length, terminal.maximum_attempts);
  assert.ok(attempts.every((row) => row.outcome === 'FAILED' && row.problem === 'PC-DATA-6005'));
  assert.equal(new Set(attempts.map((row) => row.lease_id)).size, attempts.length);
  const receiptRows = async () =>
    (
      await control.query(
        `select q.* from control.fleet_fact_quarantine q
    join control.fleet_fact_failure_outbox o using(participant_id,privacy_domain_id,receipt_id)
    join control.work_item w using(participant_id,work_item_id)
    where q.participant_id=$1 and q.privacy_domain_id=$2 and q.event_id=$3 and q.state='COMMITTED'
      and o.receipt_digest=q.receipt_digest and w.privacy_domain_id=q.privacy_domain_id
      and w.kind='FLEET_FAILURE' and w.state='OPEN' and w.row_version=1
      and w.resource_ref='urn:openpc:resource:'||$4 and w.payload_digest=q.material_digest`,
        [...scope, source[0].event_id, candidateId],
      )
    ).rows;
  const receipts = await receiptRows();
  assert.equal(receipts.length, 1);
  await tick(false);
  await tick();
  assert.deepEqual(await delivery(), [terminal]);
  assert.deepEqual(await receiptRows(), receipts);
  const api = (await run(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])).trim();
  assert.ok(api);
  await archiveNativeFleetFailure({
    root: archiveRoot,
    secretRoot,
    scope: { participantId, privacyDomainId, streamId: `fleet-failure-${generation}` },
    receipt: receipts[0],
    control,
    api,
    run,
  });
  assert.deepEqual(await receiptRows(), receipts);
  assert.deepEqual(await forbidden(), initial);
  assert.deepEqual(await originals(), originalFacts);
  await assertProducerPending();
  process.stdout.write(
    `FLEET_NATIVE_QUARANTINE|PASS|failed-attempts=${attempts.length}|public-admission|signed-work-item|no-ack-or-cursor|restart\n`,
  );
} finally {
  await Promise.all([control.end(), facts.end()]);
}
