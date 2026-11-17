import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client, Pool } from 'pg';
import { withDeletionOutboxFault } from './evidence-rejection-deletion-checks.mjs';
import {
  FactRetirementBlocked,
  verifyFactRetirementBatch,
} from '../../../services/control-api/src/evidence/fact-retirement.ts';

export async function observeFactRetirementOutbox(admin, waitEvent) {
  assert.ok(['advisory', 'PgSleep'].includes(waitEvent));
  for (let attempt = 0; attempt < 80; attempt++) {
    const waiting = (
      await admin.query(
        "select exists(select 1 from pg_stat_activity where wait_event=$1 and query like '%control.outbox_event%' and pid<>pg_backend_pid()) waiting",
        [waitEvent],
      )
    ).rows[0].waiting;
    if (waiting) return;
    await delay(20);
  }
  assert.fail('The real deletion must reach its uncommitted outbox boundary');
}

/** Pause the real Control transaction after its physical write and signing,
 * then remove its actual Fact connection. No business owner is substituted. */
export async function withFactRetirementLeaseLoss({ admin, secretRoot, streamId, run }) {
  const barrier = new Client(admin.options);
  const facts = new Client({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_facts',
    password: (await readFile(join(secretRoot, 'fact_pg_password.txt'), 'utf8')).trim(),
  });
  await barrier.connect();
  await facts.connect();
  try {
    await barrier.query(
      "select pg_advisory_lock(hashtextextended('openpc:rejection-deletion-test',0))",
    );
    await withDeletionOutboxFault(admin, streamId, 'WAIT', async () => {
      try {
        return await run(async () => {
          try {
            await observeFactRetirementOutbox(admin, 'advisory');
            const leases = (
              await facts.query(`select distinct a.pid,extract(epoch from clock_timestamp()-a.xact_start) age
        from pg_stat_activity a join pg_locks l using(pid)
        where a.datname=current_database() and a.usename='openpc_policy_fact_runtime'
        and a.state='idle in transaction' and l.locktype='advisory' and l.mode='ShareLock' and l.granted`)
            ).rows;
            assert.equal(leases.length, 1, 'One exact owned Fact lease must protect this deletion');
            assert.ok(Number(leases[0].age) < 4, 'Connection loss must precede lease expiry');
            assert.equal(
              (await facts.query('select pg_terminate_backend($1) stopped', [leases[0].pid]))
                .rows[0].stopped,
              true,
            );
          } finally {
            await barrier.query(
              "select pg_advisory_unlock(hashtextextended('openpc:rejection-deletion-test',0))",
            );
          }
        });
      } finally {
        await barrier.query('select pg_advisory_unlock_all()');
      }
    });
  } finally {
    await barrier.end();
    await facts.end();
  }
}

/** Real original COSE, source state and mutation-fence protocol. This exercises
 * the source prerequisite only; it neither creates a Fact nor proves deletion. */
export async function verifyFactRetirementOwner({
  secretRoot,
  participantId,
  privacyDomainId,
  views,
  executable,
}) {
  assert.ok(views.length > 0 && views.length <= 128);
  const password = async (name) => (await readFile(join(secretRoot, name), 'utf8')).trim();
  const reader = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_policy_fact_runtime',
    password: await password('policy_fact_db_password.txt'),
    max: 1,
    connectionTimeoutMillis: 3000,
    statement_timeout: 3000,
  });
  const writer = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_fact_runtime',
    password: await password('fact_runtime_db_password.txt'),
    max: 1,
    connectionTimeoutMillis: 3000,
    statement_timeout: 3000,
  });
  const context = async (client) => {
    await client.query('begin');
    await client.query(
      "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
      [participantId, privacyDomainId],
    );
  };
  const lease = async (p, work) => {
    const child = execFile(executable, ['--evidence-lease'], {
      timeout: 10000,
      maxBuffer: 4194304,
      env: {
        ...process.env,
        POLICY_FACT_DATABASE_HOST: '127.0.0.1',
        POLICY_FACT_DATABASE_PORT: '55433',
        POLICY_FACT_DATABASE_NAME: 'openpc_facts',
        POLICY_FACT_DATABASE_USER: 'openpc_policy_fact_runtime',
        POLICY_FACT_DATABASE_PASSWORD_FILE: join(secretRoot, 'policy_fact_db_password.txt'),
        POLICY_FACT_VERIFY_KEY_FILE: join(secretRoot, 'policy_fact_verify_key.sec1'),
        POLICY_FACT_VERIFY_KEY_ID: p.verificationKeyId,
      },
    });
    let buffered = '',
      pending,
      failed = false;
    const stop = () => {
      failed = true;
      pending?.reject(new Error('Fact lease closed'));
      pending = undefined;
    };
    child.on('error', stop);
    child.stdin.on('error', stop);
    const completed = new Promise((resolve) =>
      child.once('close', (code) => {
        stop();
        resolve(code);
      }),
    );
    const receive = () =>
      new Promise((resolve, reject) => {
        if (failed || pending) {
          reject(new Error('Fact lease unavailable'));
          return;
        }
        pending = { resolve, reject };
      });
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > 4194304) {
        stop();
        child.kill();
        return;
      }
      const index = buffered.indexOf('\n');
      if (index < 0) return;
      if (!pending || index !== buffered.length - 1) {
        stop();
        child.kill();
        return;
      }
      const waiter = pending;
      pending = undefined;
      const value = buffered.slice(0, index);
      buffered = '';
      waiter.resolve(value);
    });
    const release = async () => {
      child.stdin.end('RELEASE\n');
      assert.equal(await completed, 0);
    };
    try {
      const ready = receive();
      child.stdin.write(
        JSON.stringify({
          participantId,
          privacyDomainId,
          sourceProfileId: p.sourceProfileId,
          afterSequence: (BigInt(p.sourceSequence) - 1n).toString(),
        }) + '\n',
      );
      const response = JSON.parse(await ready);
      await work({
        response,
        release,
        check: async () => {
          const checked = receive();
          child.stdin.write('CHECK\n');
          assert.deepEqual(JSON.parse(await checked), {
            identity: 'OPENPC-FACT-EVIDENCE-LEASE-1',
            state: 'HELD',
          });
        },
      });
    } finally {
      if (!failed && child.exitCode === null) child.stdin.end('RELEASE\n');
      await completed;
    }
  };
  let eligible = 0,
    reorg = 0,
    fenced = false;
  const read = await reader.connect(),
    write = await writer.connect();
  try {
    assert.equal(
      (
        await write.query(
          "select has_function_privilege(current_user,'facts.finalize_fact(text,text,text,bytea,bytea,bytea)','EXECUTE') admitted",
        )
      ).rows[0].admitted,
      true,
    );
    await context(read);
    for (const view of views) {
      const p = view.fact;
      assert.ok(p && view.status === 'VERIFIED_FACT_CUSTODY_PROJECTION');
      const state = (
        await read.query(
          `select c.state::text checkpoint,f.state::text state,
        f.fresh_until_ms<floor(extract(epoch from clock_timestamp())*1000)::bigint expired
        from facts.admission_inbox i join facts.source_checkpoint c using(participant_id,privacy_domain_id,source_profile_id)
        join facts.canonical_fact f using(participant_id,privacy_domain_id,candidate_id)
        where i.participant_id=$1 and i.privacy_domain_id=$2 and i.candidate_id=$3`,
          [participantId, privacyDomainId, p.candidateId],
        )
      ).rows;
      assert.equal(state.length, 1);
      await lease(p, async ({ response, check, release }) => {
        const verify = () =>
          verifyFactRetirementBatch(response, p, p.verificationKeyDigest, p.verificationKeyId);
        if (state[0].checkpoint !== 'COMPLETE') {
          assert.throws(
            verify,
            (error) =>
              error instanceof FactRetirementBlocked && error.blocker === 'INCOMPLETE_CHECKPOINT',
          );
          if (state[0].checkpoint === 'REORG_FENCED') reorg++;
        } else {
          verify();
          eligible++;
          await check();
          if (!fenced) {
            await context(write);
            try {
              const pid = (await write.query('select pg_backend_pid() pid')).rows[0].pid;
              const queued = write
                // The runtime may call the capability-gated owner, never its
                // internal helper. Invalid capability proves no business effect.
                .query('select facts.finalize_fact($1,$2,$3,$4,$5,$6)', [
                  participantId,
                  privacyDomainId,
                  p.candidateId,
                  Buffer.alloc(32),
                  Buffer.alloc(32),
                  Buffer.alloc(32),
                ])
                .then(
                  () => null,
                  (error) => error,
                );
              let blocked = false;
              for (let attempt = 0; attempt < 50; attempt++) {
                blocked = (
                  await read.query(
                    "select exists(select 1 from pg_locks where pid=$1 and locktype='advisory' and not granted) blocked",
                    [pid],
                  )
                ).rows[0].blocked;
                if (blocked) break;
                await delay(10);
              }
              assert.equal(
                blocked,
                true,
                'The real lifecycle writer must queue behind the historical read fence',
              );
              await check();
              await release();
              assert.equal((await queued)?.code, '42501');
              fenced = true;
            } finally {
              await write.query('rollback');
            }
          }
        }
      });
    }
    assert.ok(
      eligible > 0 && fenced,
      'At least one complete real source and actual queued lifecycle fence are required',
    );
    process.stdout.write(
      `OPENPC_FACT_RETIREMENT_OWNER|PASS|verified=${eligible}|reorg-denied=${reorg}|original-cose|queued-lifecycle-fence|no-fact-renewal\n`,
    );
  } finally {
    await read.query('rollback');
    read.release();
    write.release();
    await reader.end();
    await writer.end();
  }
}

/** Overall coverage stays unavailable for unrelated unresolved source adapters.
 * The retired parent/child archive must nevertheless have its exact current,
 * guarded sink acknowledgement; a global UNKNOWN cannot substitute for it. */
export async function verifyFactRetirementHoldCoverage(client, scoped, streamId, holdId) {
  const segments = (
    await client.query(
      `select s.stream_id,s.segment_id,
  openpc.evidence_hold_match_state(h.selector,s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id) match,
  (select count(*)::int from control.evidence_checkpoint p where p.participant_id=s.participant_id and p.privacy_domain_id=s.privacy_domain_id
   and p.stream_id=s.stream_id and p.segment_id=s.segment_id) checkpoints,
  (select count(*)::int from control.evidence_checkpoint p join control.evidence_hold_coverage c
   on c.participant_id=p.participant_id and c.privacy_domain_id=p.privacy_domain_id and c.stream_id=p.stream_id and c.segment_id=p.segment_id
    and c.sink_id=p.sink_id and c.object_digest=p.object_digest and c.retention_hold_id=h.retention_hold_id and c.hold_revision=h.revision
   where p.participant_id=s.participant_id and p.privacy_domain_id=s.privacy_domain_id and p.stream_id=s.stream_id and p.segment_id=s.segment_id) covered
  from control.retention_hold h join control.evidence_segment s using(participant_id,privacy_domain_id)
  where h.participant_id=$1 and h.privacy_domain_id=$2 and h.retention_hold_id=$3 and h.state='ACTIVE'`,
      [...scoped, holdId.slice(-36)],
    )
  ).rows;
  const selected = segments.filter((s) => s.stream_id === streamId);
  assert.ok(selected.length > 0);
  for (const s of selected) {
    assert.equal(s.match, 'MATCH');
    assert.ok(s.checkpoints > 0);
    assert.equal(s.covered, s.checkpoints);
  }
  const unknown = segments.filter((s) => s.match === 'UNKNOWN');
  assert.ok(unknown.every((s) => s.stream_id !== streamId));
  for (const s of segments.filter((s) => s.match === 'MATCH'))
    assert.equal(s.covered, s.checkpoints);
  return unknown.length ? 'UNAVAILABLE' : 'VERIFIED';
}
