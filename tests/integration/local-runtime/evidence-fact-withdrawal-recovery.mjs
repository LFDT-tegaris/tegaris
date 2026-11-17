import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';

// Observe the original publicly acquired/admitted source after its governed
// successor fenced it. Only the packaged Fact owner may close completeness.
// This driver neither resubmits the source nor writes business state with SQL.
const [root, evidenceRoot, composeJson, mode] = process.argv.slice(2);
const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
const { participantId, privacyDomainId } = await load('rpc-source-policy-input.json');
const { candidateId } = await load('rpc-acquisition/candidate.json');
const publication = await load('rpc-acquisition/publication.json');
for (const id of [
  participantId,
  privacyDomainId,
  candidateId,
  publication.candidate_partition_id,
  publication.projection_generation_id,
])
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
assert.ok(mode === undefined || ['--preflight', '--database-preflight'].includes(mode));
const execute = promisify(execFile);
const run = async (args) => {
  try {
    return (
      await execute(compose[0], [...compose.slice(1), ...args], {
        timeout: 90000,
        maxBuffer: 1024 * 1024,
      })
    ).stdout.trim();
  } catch (error) {
    throw new Error(`Fact withdrawal process failed: status=${error.code ?? 'unknown'}`);
  }
};
if (mode === '--preflight') {
  process.stdout.write(
    'OPENPC_FACT_WITHDRAWAL_INPUTS|PASS|original-candidate-and-source-identity\n',
  );
} else {
  await execute('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    mode === '--database-preflight' ? 'database' : 'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const pool = async (port, database, user, password) =>
    new Pool({
      host: '127.0.0.1',
      port,
      database,
      user,
      password: (await readFile(join(root, 'secrets', password), 'utf8')).trim(),
      options: '-c default_transaction_read_only=on',
      connectionTimeoutMillis: 5000,
      query_timeout: 10000,
      max: 1,
    });
  const facts = await pool(55433, 'openpc_facts', 'openpc_facts', 'fact_pg_password.txt');
  const candidates = await pool(
    55434,
    'openpc_candidate_index',
    'openpc_fact_bridge_reader',
    'fact_bridge_reader_db_password.txt',
  );
  const reader = await pool(
    55433,
    'openpc_facts',
    'openpc_policy_fact_runtime',
    'policy_fact_db_password.txt',
  );
  const control = await pool(55432, 'openpc_control', 'openpc_control', 'control_pg_password.txt');
  const scope = [participantId, privacyDomainId];
  const rows = async (db, sql, values = scope) => {
    if (db !== candidates) return (await db.query(sql, values)).rows;
    const client = await db.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',false)",
        [...scope, localOperationId()],
      );
      return (await client.query(sql, values)).rows;
    } finally {
      await client.query('rollback');
      client.release();
    }
  };
  const snapshot = async () => ({
    facts: await rows(
      facts,
      'select * from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 order by candidate_id',
    ),
    lineage: await rows(
      facts,
      'select * from facts.lineage_outbox where participant_id=$1 and privacy_domain_id=$2 order by lineage_action_id',
    ),
    readiness: await rows(
      facts,
      'select * from facts.readiness_gate where participant_id=$1 and privacy_domain_id=$2 order by generation_id',
    ),
    feed: await rows(
      facts,
      'select * from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2 order by partition_id,candidate_sequence',
    ),
    outbox: await rows(
      facts,
      'select * from facts.outbox where participant_id=$1 and privacy_domain_id=$2 order by candidate_id',
    ),
    acks: await rows(
      facts,
      'select * from facts.fleet_admission_ack where participant_id=$1 and privacy_domain_id=$2 order by event_id',
    ),
    fleet: await rows(
      control,
      'select * from control.fleet_fact_delivery where participant_id=$1 and privacy_domain_id=$2 order by event_id',
    ),
    quarantine: await rows(
      control,
      'select * from control.fleet_fact_quarantine where participant_id=$1 and privacy_domain_id=$2 order by event_id',
    ),
    inbox: await rows(
      control,
      'select * from control.fleet_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2 order by event_id',
    ),
  });
  try {
    assert.equal(await run(['ps', '-q', 'control-worker']), '', 'Fleet writer must remain stopped');
    // A fresh journey may already have closed the checkpoint. A retained upgrade
    // starts with GAP_BLOCKED; both retain the original signed records.
    if (mode === '--database-preflight') assert.equal(await run(['ps', '-q', 'fact-service']), '');
    else await run(['stop', 'fact-service']);
    const original = await snapshot();
    const fact = original.facts.find((row) => row.candidate_id === candidateId);
    assert.ok(fact);
    assert.equal(fact.state, 'RETIRED');
    assert.equal(fact.complete, true);
    assert.equal(fact.finality_verified, true);
    const readiness = original.readiness.find((row) => row.generation_id === fact.generation_id);
    assert.equal(readiness.state, 'STALE');
    assert.equal(readiness.shard_verified, false);
    const feed = original.feed.filter(
      (row) => row.partition_id === publication.candidate_partition_id,
    );
    assert.ok(feed.length >= 2);
    assert.equal(feed.at(-1).event_kind, 'CHECKPOINT');
    const profile = feed[0].source_profile_id;
    assert.ok(
      feed.every(
        (row, index) =>
          row.candidate_sequence === String(index + 1) &&
          row.source_profile_id === profile &&
          row.source_generation_id === publication.projection_generation_id,
      ),
    );
    const candidateRows = await rows(
      candidates,
      'select outbox_sequence::text,event_id::text,event_type,event_payload_digest,publication_digest,source_profile_id::text,generation_state,publication_state from candidate.fact_bridge_admission_v1 where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3 order by outbox_sequence',
      [...scope, publication.candidate_partition_id],
    );
    assert.equal(candidateRows.length, feed.length + 1);
    for (const [index, row] of feed.entries()) {
      assert.equal(candidateRows[index].outbox_sequence, row.candidate_sequence);
      assert.equal(candidateRows[index].event_id, row.event_id);
      assert.deepEqual(
        candidateRows[index].event_payload_digest,
        createHash('sha256').update(row.event_payload_cbor).digest(),
      );
    }
    const fence = candidateRows.at(-1);
    assert.equal(fence.event_type, 'io.openpc.indexer.projection.source.fenced.v1');
    assert.equal(fence.source_profile_id, profile);
    assert.equal(fence.generation_state, 'STALE');
    assert.equal(fence.publication_state, 'FENCED');
    const prefix = createHash('sha256')
      .update(
        feed
          .map(
            (row) =>
              `${row.candidate_sequence}:${row.event_id}:${createHash('sha256').update(row.event_payload_cbor).digest('hex')}`,
          )
          .join('\n'),
      )
      .digest();
    const checkpoint = async () =>
      rows(
        facts,
        'select * from facts.source_checkpoint where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3',
        [...scope, profile],
      );
    const closure = async () =>
      rows(
        facts,
        'select * from facts.withdrawal_checkpoint where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3',
        [...scope, publication.candidate_partition_id],
      );
    const before = await checkpoint();
    assert.equal(before.length, 1);
    assert.ok(['GAP_BLOCKED', 'COMPLETE'].includes(before[0].state));
    assert.equal(before[0].recovery_cursor_cbor, null);
    const closedBefore = await closure();
    assert.equal(closedBefore.length, before[0].state === 'COMPLETE' ? 1 : 0);
    if (mode === '--database-preflight') {
      process.stdout.write(
        `OPENPC_FACT_WITHDRAWAL_DATABASE|PASS|checkpoint=${before[0].state}|real-reader-context|all-original-readback|no-business-mutation\n`,
      );
    } else {
      await run([
        'up',
        '-d',
        '--wait',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'fact-service',
      ]);
      const deadline = performance.now() + 20000;
      while ((await checkpoint())[0].state !== 'COMPLETE') {
        assert.ok(performance.now() < deadline, 'Native withdrawal checkpoint remains incomplete');
        await delay(200);
      }
      const after = await checkpoint(),
        closed = await closure();
      assert.equal(closed.length, 1);
      assert.equal(closed[0].source_event_id, fence.event_id);
      assert.equal(closed[0].source_sequence, fence.outbox_sequence);
      assert.equal(closed[0].source_generation_id, publication.projection_generation_id);
      assert.deepEqual(closed[0].prefix_digest, prefix);
      assert.deepEqual(
        closed[0].material_digest,
        createHash('sha256').update(closed[0].material).digest(),
      );
      const material = JSON.parse(closed[0].material);
      assert.equal(
        material.sourcePayloadDigest,
        `sha256:${fence.event_payload_digest.toString('hex')}`,
      );
      assert.equal(
        material.publicationDigest,
        `sha256:${fence.publication_digest.toString('hex')}`,
      );
      assert.equal(after[0].last_sequence, before[0].last_sequence);
      assert.equal(after[0].recovery_cursor_cbor, null);
      assert.deepEqual(
        await snapshot(),
        original,
        'Closure must preserve original signed effects and stale readiness',
      );
      if (closedBefore.length) assert.deepEqual(closed, closedBefore);
      const client = await reader.connect();
      try {
        await client.query('begin read only');
        await client.query(
          "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
          scope,
        );
        assert.equal(
          (
            await client.query(
              'select count(*)::int n from facts.withdrawal_checkpoint where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3',
              [...scope, publication.candidate_partition_id],
            )
          ).rows[0].n,
          1,
        );
        await client.query(
          "select set_config('openpc.privacy_domain_id','018f0000-0000-7000-8000-000000000201',true)",
        );
        assert.notEqual(privacyDomainId, '018f0000-0000-7000-8000-000000000201');
        assert.equal(
          (
            await client.query(
              'select count(*)::int n from facts.withdrawal_checkpoint where participant_id=$1 and privacy_domain_id=$2',
              scope,
            )
          ).rows[0].n,
          0,
        );
      } finally {
        await client.query('rollback');
        client.release();
      }
      await run(['restart', '--no-deps', 'fact-service']);
      await run([
        'up',
        '-d',
        '--wait',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'fact-service',
      ]);
      await delay(2500); // Includes at least one ordinary two-second maintenance cycle.
      assert.deepEqual(await checkpoint(), after);
      assert.deepEqual(await closure(), closed);
      assert.deepEqual(await snapshot(), original);
      process.stdout.write(
        `OPENPC_FACT_WITHDRAWAL_RECOVERY|PASS|prior=${before[0].state}|complete-prefix|original-cose-preserved|stale-readiness|scope-denial|native-restart|physical-retirement=OPEN\n`,
      );
    }
  } finally {
    await Promise.all([facts.end(), candidates.end(), reader.end(), control.end()]);
  }
}
