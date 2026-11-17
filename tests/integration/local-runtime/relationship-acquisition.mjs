// Real bounded source jobs and read-only custody checks. Only the external
// provider's owned response file is changed to inject malformed observations.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';

const [phase, root, evidence, image, targetContainer, targetId] = process.argv.slice(2);
assert.ok(['before', 'after'].includes(phase));
const jobRoot = join(evidence, 'acquisition');
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const save = async (path, value) => {
  await writeFile(`${path}.next`, JSON.stringify(value), { mode: 0o600 });
  await rename(`${path}.next`, path);
};
const config = await load(join(jobRoot, 'config.json'));
const publication = await load(join(jobRoot, 'publication.json'));
const pool = new Pool({
  host: '127.0.0.1',
  port: 55434,
  database: 'openpc_candidate_index',
  user: 'openpc_candidate_index',
  password: (await readFile(join(root, 'secrets/candidate_index_pg_password.txt'), 'utf8')).trim(),
  max: 1,
  options: '-c default_transaction_read_only=on',
});
async function snapshot() {
  const scope = [config.participant_id, config.privacy_domain_id, config.projection_generation_id];
  const result = {};
  for (const table of ['candidate_event', 'candidate_block', 'checkpoint']) {
    const rows = await pool.query(
      `select to_jsonb(t) as value from candidate.${table} t
       where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3
       order by to_jsonb(t)::text`,
      scope,
    );
    result[table] = rows.rows.map((row) => row.value);
  }
  result.events = (
    await pool.query(
      `select event_id::text,event_type,aggregate_sequence::text,payload_json
     from candidate.outbox_event where participant_id=$1 and privacy_domain_id=$2
     and aggregate_id=$3 order by aggregate_sequence`,
      [scope[0], scope[1], publication.candidate_partition_id],
    )
  ).rows;
  return result;
}
function sourceDecisions() {
  const result = spawnSync(
    'docker',
    [
      'exec',
      targetContainer,
      '/usr/local/bin/openpc-control-worker',
      'runtime-evidence-snapshot',
      'source',
    ],
    { encoding: 'utf8', timeout: 10_000 },
  );
  assert.equal(result.status, 0, 'source decision readback failed');
  const snapshot = JSON.parse(result.stdout);
  assert.equal(snapshot.target_id, targetId, 'source readback must name the requested target');
  return snapshot;
}
async function run(name, job, expected) {
  const path = join(jobRoot, `relationship-${name}-config.json`);
  await save(path, job);
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
      `OPENPC_ACQUISITION_CONFIG_FILE=${path}`,
      '--entrypoint',
      '/usr/local/bin/openpc-acquire-candidate-batch',
      image,
    ],
    { encoding: 'utf8', timeout: 45_000 },
  );
  await writeFile(join(jobRoot, `relationship-${name}-stdout`), result.stdout, { mode: 0o600 });
  await writeFile(join(jobRoot, `relationship-${name}-stderr`), result.stderr, { mode: 0o600 });
  assert.equal(result.error, undefined, `${name}: acquisition process failed`);
  if (expected) {
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      outcome: expected,
      authority: 'NON_AUTHORITATIVE',
    });
  } else {
    assert.equal(result.status, 1, `${name}: invalid source/job must be rejected`);
    const errors = result.stderr.trim().split('\n').map(JSON.parse);
    assert.ok(
      errors.some(
        (error) =>
          error.event === 'candidate_acquisition_rejected' &&
          error.code ===
            'source acquisition inputs or observations rejected: DATA-6202-CANDIDATE-BATCH-INVALID',
      ),
      result.stderr,
    );
    assert.equal(result.stdout, '');
  }
}
try {
  const before = await snapshot();
  if (phase === 'before') {
    assert.equal(before.candidate_event.length, 0, 'negative source cases need a fresh generation');
    assert.equal(before.checkpoint.length, 0);
    const path = join(root, 'data/rpc-provider/fact-inputs.json');
    const owned = await load(path);
    try {
      for (const fault of ['duplicate', 'conflict', 'decode']) {
        await save(path, { ...owned, relationshipFault: fault });
        const requests = await readFile(join(root, 'data/rpc-provider/requests.jsonl'), 'utf8');
        await run(fault, {
          ...config,
          operation_id: localOperationId(),
          correlation_id: localOperationId(),
        });
        const observed = (await readFile(join(root, 'data/rpc-provider/requests.jsonl'), 'utf8'))
          .slice(requests.length)
          .trim()
          .split('\n')
          .filter(Boolean)
          .map(JSON.parse);
        assert.ok(
          observed.some((request) => request.method === 'eth_getLogs'),
          `${fault}: actual external event response required`,
        );
        assert.deepEqual(
          await snapshot(),
          before,
          `${fault}: rejected source must not advance custody`,
        );
        process.stdout.write(
          `OPENPC_RELATIONSHIP_SOURCE|PASS|${fault}|real-source-read|zero-candidate-effect\n`,
        );
      }
    } finally {
      await save(path, owned);
    }
  } else {
    assert.equal(
      before.candidate_event.length,
      process.env.OPENPC_RELATIONSHIP_PHASE === 'closing' ? 2 : 1,
    );
    assert.equal(before.checkpoint.length, 1);
    assert.equal(before.checkpoint[0].state, 'COMPLETE');
    const decisions = sourceDecisions();
    await run('replay', config, 'REPLAYED_CANDIDATE');
    assert.deepEqual(await snapshot(), before, 'replay must preserve the exact original effect');
    assert.deepEqual(sourceDecisions(), decisions, 'replay must not repeat source reads');
    process.stdout.write(
      'OPENPC_RELATIONSHIP_SOURCE|PASS|exact-replay|one-effect|no-source-reread\n',
    );
    await run('conflicting-job', { ...config, range: { start: 10, end: 11 } });
    const checkpoint = before.checkpoint[0];
    const batchDigest = checkpoint.batch_digest;
    assert.match(batchDigest, /^\\x[0-9a-f]{64}$/u);
    await run('first-gap', {
      ...config,
      operation_id: localOperationId(),
      correlation_id: localOperationId(),
      batch_id: 'relationship-skip-first-gap',
      sequence: 2,
      predecessor_digest: `sha256:${batchDigest.slice(2)}`,
      range: { start: 12, end: 12 },
    });
    assert.deepEqual(await snapshot(), before, 'conflict/gap must preserve the exact checkpoint');
    assert.deepEqual(sourceDecisions(), decisions, 'conflict/gap must stop before source dispatch');
    process.stdout.write(
      'OPENPC_RELATIONSHIP_SOURCE|PASS|conflicting-job|first-gap|unchanged-checkpoint|no-source-dispatch\n',
    );
  }
} finally {
  await pool.end();
}
