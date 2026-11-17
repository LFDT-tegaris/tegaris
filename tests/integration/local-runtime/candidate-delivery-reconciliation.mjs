import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, readFile, mkdir, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { candidateArchiveRequest } from '../../../services/control-api/src/evidence/candidate-archive/contract.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
// Continue actual custody/withdrawal inputs. No admission, withdrawal or delivery
// is seeded. The operator probe injects only a rollback fault and removes it.
const [root, composeJson] = process.argv.slice(2);
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--memory-gib',
  '3',
  '--reuse',
  '--',
  'true',
]);
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const dir = root + '/data/candidate-custody/delivery-probe';
await mkdir(dir, { recursive: true, mode: 0o700 });
const worker = (
  await exec(compose[0], [...compose.slice(1), 'ps', '-aq', 'control-worker'])
).stdout.trim();
assert.match(worker, /^[0-9a-f]{64}$/u);
// Physical retirement keeps the Fleet consumer stopped. Copy the qualified
// packaged reconciler without restarting that independent business writer.
const retainedWorker = JSON.parse((await exec('docker', ['inspect', worker])).stdout)[0];
const workerImage = JSON.parse(
  (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-worker:local'])).stdout,
)[0];
assert.equal(retainedWorker.State.Running, false, 'Fleet consumer must remain stopped');
assert.equal(retainedWorker.Config.Labels['com.docker.compose.service'], 'control-worker');
assert.equal(retainedWorker.Image, workerImage.Id, 'Qualified packaged reconciler required');
assert.equal(workerImage.Config.Labels['io.openpc.image.service'], 'control-worker');
const executable = dir + '/reconcile_candidate_delivery';
await exec('docker', [
  'cp',
  `${worker}:/usr/local/bin/openpc-reconcile-candidate-delivery`,
  executable,
]);
await chmod(executable, 0o700);
const f = JSON.parse(await readFile(root + '/data/candidate-custody/case.json', 'utf8'));
const request = candidateArchiveRequest.parse(f.request);
const participantId = request.participantId,
  privacyDomainId = request.privacyDomainId;
const generationId = request.generationId,
  partitionId = request.partitionId,
  sourceProfileId = request.sourceProfileId;
await mkdir(dir, { recursive: true, mode: 0o700 });
const config = {
  participantId,
  privacyDomainId,
  sourceProfileId,
  candidate: {
    host: '127.0.0.1',
    port: 55434,
    user: 'openpc_indexer_writer',
    passwordFile: root + '/secrets/indexer_writer_db_password.txt',
  },
  facts: {
    host: '127.0.0.1',
    port: 55433,
    user: 'openpc_policy_fact_runtime',
    passwordFile: root + '/secrets/policy_fact_db_password.txt',
  },
};
const save = async (name, value) => {
  await writeFile(dir + '/' + name, JSON.stringify(value), { mode: 0o600 });
  return dir + '/' + name;
};
for (const [name, database] of [
  ['candidate-password.txt', config.candidate],
  ['fact-reader-password.txt', config.facts],
]) {
  const bytes = await readFile(database.passwordFile);
  await writeFile(dir + '/' + name, bytes, { mode: 0o600 });
  database.passwordFile = dir + '/' + name;
}
const path = await save('installed.json', config);
const invoke = (input, file = path) =>
  new Promise((resolve, reject) => {
    const child = execFile(
      executable,
      [],
      {
        env: { ...process.env, OPENPC_CANDIDATE_DELIVERY_CONFIGURATION_FILE: file },
        timeout: 35000,
        maxBuffer: 65536,
      },
      (error, stdout, stderr) => {
        if (error)
          return reject(
            new Error(
              /^OPENPC-CANDIDATE-DELIVERY-REJECTED\|[A-Z0-9-]+\s*$/.test(stderr)
                ? stderr.trim()
                : 'Native acknowledgement rejected',
            ),
          );
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('Invalid native acknowledgement output'));
        }
      },
    );
    child.stdin.on('error', reject);
    child.stdin.end(JSON.stringify(input));
  });
const pool = new Pool({
  host: '127.0.0.1',
  port: 55434,
  database: 'openpc_candidate_index',
  user: 'openpc_indexer_writer',
  password: (await readFile(config.candidate.passwordFile, 'utf8')).trim(),
  max: 1,
});
const admin = new Pool({
  host: '127.0.0.1',
  port: 55434,
  database: 'openpc_candidate_index',
  user: 'openpc_candidate_index',
  password: (await readFile(root + '/secrets/candidate_index_pg_password.txt', 'utf8')).trim(),
  max: 1,
});
const snapshot = async () => {
  const c = await pool.connect();
  try {
    await c.query('begin read only');
    await c.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CANDIDATE_WRITE-V1',true)",
      [participantId, privacyDomainId, id()],
    );
    return {
      events: (
        await c.query(
          'select event_id,aggregate_sequence::text,payload_digest,payload_cbor,state::text,attempt_count,published_at from candidate.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 order by aggregate_sequence',
          [participantId, privacyDomainId, partitionId],
        )
      ).rows,
      attempts: (
        await c.query(
          'select a.* from candidate.outbox_delivery_attempt a join candidate.outbox_event o using(participant_id,event_id) where o.participant_id=$1 and o.privacy_domain_id=$2 and o.aggregate_id=$3 order by a.event_id,a.attempt_number',
          [participantId, privacyDomainId, partitionId],
        )
      ).rows,
      candidate: (
        await c.query(
          'select payload_cbor,payload_digest,state::text from candidate.candidate_event where candidate_event_id=$1',
          [request.candidateId],
        )
      ).rows,
      siblings: (
        await c.query(
          'select event_id,payload_digest,state::text,attempt_count from candidate.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id<>$3 order by event_id',
          [participantId, privacyDomainId, partitionId],
        )
      ).rows,
    };
  } finally {
    await c.query('rollback');
    c.release();
  }
};
let fault = false;
try {
  const before = await snapshot();
  assert.ok(before.events.length >= 3 && before.events.length <= 1024);
  assert.equal(before.candidate.length, 1);
  assert.ok(before.candidate[0].payload_cbor.length > 0);
  await assert.rejects(invoke({ generationId: id(), partitionId }));
  await assert.rejects(invoke({ generationId, partitionId: id() }));
  await assert.rejects(invoke({ generationId, partitionId, acknowledged: true }));
  await assert.rejects(
    invoke(
      { generationId, partitionId },
      await save('foreign-scope.json', { ...config, privacyDomainId: id() }),
    ),
  );
  await assert.rejects(
    invoke(
      { generationId, partitionId },
      await save('foreign-source.json', { ...config, sourceProfileId: id() }),
    ),
  );
  assert.deepEqual(await snapshot(), before);
  const pending = before.events.filter((e) => e.state !== 'DELIVERED').length;
  if (pending) {
    assert.equal(pending, before.events.length);
    assert.equal(before.attempts.length, 0);
    assert.equal(
      (
        await admin.query(
          "select to_regprocedure('candidate.openpc_ack_rollback_probe()') is null absent",
        )
      ).rows[0].absent,
      true,
    );
    await admin.query(
      `create function candidate.openpc_ack_rollback_probe() returns trigger language plpgsql as $$ begin if new.event_id='${before.events[1].event_id}'::uuid then raise exception 'OPENPC_TEST_ACK_ROLLBACK'; end if; return new; end $$`,
    );
    fault = true;
    await admin.query(
      'create trigger openpc_ack_rollback_probe before insert on candidate.outbox_delivery_attempt for each row execute function candidate.openpc_ack_rollback_probe()',
    );
    await assert.rejects(invoke({ generationId, partitionId }), /SQLSTATE-P0001/);
    assert.deepEqual(
      await snapshot(),
      before,
      'Late second-event failure rolls back the first acknowledgement and attempt',
    );
    await admin.query(
      'drop trigger openpc_ack_rollback_probe on candidate.outbox_delivery_attempt',
    );
    await admin.query('drop function candidate.openpc_ack_rollback_probe()');
    fault = false;
  }
  // Concurrent invocations reconcile one immutable intent under the generation lock.
  // Deliberately do not use the first result as authority; recover from the database.
  const results = await Promise.all([
    invoke({ generationId, partitionId }),
    invoke({ generationId, partitionId }),
  ]);
  assert.equal(
    results.reduce((sum, r) => sum + r.reconciledEvents, 0),
    pending,
  );
  for (const r of results) {
    assert.equal(r.protocol, 'OPENPC-CANDIDATE-DELIVERY-1');
    assert.equal(r.authority, 'HISTORICAL_RECEIPTS_ONLY');
  }
  const after = await snapshot();
  assert.ok(
    after.events.every((e) => e.state === 'DELIVERED' && e.attempt_count === 1 && e.published_at),
  );
  assert.equal(after.attempts.length, before.events.length);
  assert.ok(
    after.attempts.every(
      (a) => a.state === 'RECONCILED' && a.transport_receipt_digest.length === 32 && a.finished_at,
    ),
  );
  assert.deepEqual(after.candidate, before.candidate);
  assert.deepEqual(after.siblings, before.siblings);
  for (let i = 0; i < before.events.length; i++) {
    assert.deepEqual(after.events[i].payload_cbor, before.events[i].payload_cbor);
    assert.deepEqual(after.events[i].payload_digest, before.events[i].payload_digest);
  }
  assert.equal((await invoke({ generationId, partitionId })).reconciledEvents, 0);
  assert.deepEqual(
    await snapshot(),
    after,
    'Process restart/replay preserves original attempts and timestamps',
  );
  process.stdout.write(
    `OPENPC_CANDIDATE_ACK|PASS|events=${pending}|scope-source-and-forgery-denied|late-failure=${pending ? 'PASS' : 'NOT_REPEATED_ALREADY_RECONCILED'}|concurrent-replay|native-restart-readback|original-candidate-and-siblings-unchanged\n`,
  );
} finally {
  if (fault) {
    await admin.query(
      'drop trigger if exists openpc_ack_rollback_probe on candidate.outbox_delivery_attempt',
    );
    await admin.query('drop function candidate.openpc_ack_rollback_probe()');
  }
  await pool.end();
  await admin.end();
}
