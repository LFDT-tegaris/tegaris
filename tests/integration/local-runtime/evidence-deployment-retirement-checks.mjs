import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from 'pg';
import { withDeletionOutboxFault } from './evidence-rejection-deletion-checks.mjs';
import { observeFactRetirementOutbox as observeRetirementOutbox } from './evidence-fact-retirement-checks.mjs';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { acquireDeploymentRetirementFence } from '../../../services/control-api/src/evidence/deployment-retirement.ts';
import { readEvidenceProvenance } from '../../../services/control-api/src/evidence/provenance.ts';

const scoped = async (pool, scope, intent, work, readOnly = false) => {
  const client = await pool.connect();
  try {
    await client.query(readOnly ? 'begin read only' : 'begin');
    await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      scope.participantId,
      scope.privacyDomainId,
      uuidv7(),
      intent,
    ]);
    return await work(client);
  } finally {
    await client.query('rollback');
    client.release();
  }
};

/** Remove the actual source connection while the real business transaction
 * waits before its outbox write. Its uncommitted physical effect must roll back. */
export async function withDeploymentRetirementFenceLoss({ admin, streamId, run }) {
  const barrier = new Client(admin.options);
  await barrier.connect();
  try {
    await barrier.query(
      "select pg_advisory_lock(hashtextextended('openpc:rejection-deletion-test',0))",
    );
    await withDeletionOutboxFault(admin, streamId, 'WAIT', async () => {
      try {
        return await run(async () => {
          try {
            await observeRetirementOutbox(admin, 'advisory');
            const sources = (
              await admin.query(`select distinct a.pid,extract(epoch from clock_timestamp()-a.xact_start) age
              from pg_stat_activity a join pg_locks l using(pid)
              where a.datname=current_database() and a.usename='openpc_configuration_runtime'
               and a.state='idle in transaction' and a.query='select 1'
               and l.relation='control.deployment_address_reservation'::regclass
               and l.mode='RowShareLock' and l.granted`)
            ).rows;
            assert.equal(sources.length, 1, 'One exact deployment source fence must be live');
            assert.ok(Number(sources[0].age) < 4, 'Source connection loss must precede expiry');
            assert.equal(
              (await admin.query('select pg_terminate_backend($1) stopped', [sources[0].pid]))
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
  }
}

/** Real publicly produced observations are inputs. These probes neither seed
 * intermediate business state nor claim a deletion/approval journey. */
export async function verifyDeploymentRetirementSource({
  admin,
  runtime,
  worker,
  scope,
  requireClosed = true,
  requireReorg = true,
}) {
  const rows = await scoped(
    runtime,
    scope,
    'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
    async (client) =>
      (
        await client.query(
          `select c.evidence_id::text id,c.record_id,c.stream_id,c.receipt_digest,p.projection,p.projection_digest,
         openpc.deployment_projection_retirement_blockers(c,p.projection) blockers
         from control.evidence_catalogue c join control.evidence_deployment_provenance p
          using(participant_id,privacy_domain_id,stream_id,record_id)
         where c.participant_id=$1 and c.privacy_domain_id=$2
          and ($3::text is null or c.stream_id=$3) order by c.record_id limit 128`,
          [scope.participantId, scope.privacyDomainId, scope.streamId ?? null],
        )
      ).rows,
    true,
  );
  assert.ok(rows.length > 0);
  const finalized = rows.filter((row) => row.blockers.length === 0);
  if (requireClosed) assert.ok(finalized.length > 0, 'Real closed finalized deployment required');
  if (requireReorg)
    assert.ok(
      rows.some((row) => row.blockers.includes('REORG_FENCED')),
      'Real reorg history remains protected',
    );
  for (const row of rows) {
    const view = await scoped(
      runtime,
      scope,
      'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
      (client) =>
        readEvidenceProvenance(client, row.id, scope.participantId, scope.privacyDomainId),
      true,
    );
    assert.equal(view.status, 'VERIFIED_DEPLOYMENT_OBSERVATION');
    assert.equal(view.deployment.historical.receiptDigest, row.receipt_digest);
    assert.equal(row.projection_digest, sha256(row.projection));
    if (view.deployment.latestRetained.finality === 'REORG')
      assert.ok(row.blockers.includes('REORG_FENCED'));
    if (view.deployment.historical.state === 'WRITE_AMBIGUITY')
      assert.ok(row.blockers.includes('UNRESOLVED_OPERATION'));
  }
  const selected = finalized[0] ?? rows[0];
  await scoped(worker, scope, 'ACT-EVIDENCE_EXPORT_RECORDS-V1', async (client) => {
    const insert = (projection) =>
      client.query(
        `insert into control.evidence_deployment_provenance(participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
       values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
        [
          scope.participantId,
          scope.privacyDomainId,
          selected.stream_id,
          selected.record_id,
          projection,
          sha256(projection),
        ],
      );
    await insert(selected.projection);
    for (const changed of [
      { ...selected.projection, rawReceipt: 'private' },
      { ...selected.projection, transactionHash: `0x${'0'.repeat(64)}` },
      {
        ...selected.projection,
        historical: { ...selected.projection.historical, sourceVersion: '18446744073709551615' },
      },
      {
        ...selected.projection,
        historical: {
          ...selected.projection.historical,
          finality:
            selected.projection.historical.finality === 'NOT_ESTABLISHED'
              ? 'FINALIZED'
              : 'NOT_ESTABLISHED',
        },
      },
    ]) {
      await client.query('savepoint malformed');
      await assert.rejects(insert(changed), /PC-DATA-6007/u);
      await client.query('rollback to savepoint malformed');
    }
    await assert.rejects(
      client.query('delete from control.evidence_deployment_provenance where record_id=$1', [
        selected.record_id,
      ]),
      (error) => error.code === '42501',
    );
  });
  await scoped(runtime, scope, 'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1', async (client) => {
    await assert.rejects(
      client.query('delete from control.evidence_deployment_provenance where record_id=$1', [
        selected.record_id,
      ]),
      /PC-AUTH-0005/u,
    );
  });
  await scoped(
    runtime,
    scope,
    'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
    async (client) => {
      assert.equal(
        (
          await client.query(
            "select has_table_privilege(current_user,'control.deployment_address_reservation','UPDATE') allowed",
          )
        ).rows[0].allowed,
        false,
      );
      await assert.rejects(
        client.query(
          'update control.deployment_address_reservation set command_id=command_id where command_id=$1',
          [selected.record_id.split(':')[1]],
        ),
        /PC-DATA-6004/u,
      );
    },
  );
  await scoped(
    runtime,
    { ...scope, privacyDomainId: uuidv7() },
    'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
    async (client) => {
      assert.equal(
        (
          await client.query(
            'select 1 from control.evidence_deployment_provenance where record_id=$1',
            [selected.record_id],
          )
        ).rowCount,
        0,
      );
    },
    true,
  );
  const binding = (row) => ({
    sourceKind: 'DEPLOYMENT_PROVENANCE',
    dataClass: 'NORMALIZED_JSON_PROJECTION',
    participantId: `urn:openpc:participant:${scope.participantId}`,
    privacyDomainId: scope.privacyDomainId,
    streamId: row.stream_id,
    evidenceId: `urn:openpc:resource:${row.id}`,
    recordId: row.record_id,
    sourceReceiptDigest: row.receipt_digest,
    projectionDigest: row.projection_digest,
  });
  // The actual API transaction already occupies a connection. Even a one-slot
  // mutation pool must not starve the independent current-source read.
  assert.equal(runtime.options.max, 1);
  const occupied = await runtime.connect();
  let attempt, timer;
  try {
    await occupied.query('begin isolation level serializable');
    await occupied.query('select 1');
    attempt = acquireDeploymentRetirementFence(runtime, binding(selected));
    const bounded = Promise.race([
      attempt,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error('Source fence waited for an occupied mutation pool')),
          7500,
        );
      }),
    ]);
    if (finalized.length) await bounded;
    else await assert.rejects(bounded, /PC-DATA-6007/u);
  } finally {
    clearTimeout(timer);
    await occupied.query('rollback');
    occupied.release();
    if (attempt)
      await attempt.then(
        (fence) => fence.release(),
        () => undefined,
      );
  }
  for (const row of rows.filter((row) => row.blockers.length > 0))
    await assert.rejects(acquireDeploymentRetirementFence(runtime, binding(row)), /PC-DATA-6007/u);
  if (finalized.length === 0) {
    process.stdout.write(
      `OPENPC_DEPLOYMENT_RETIREMENT_SOURCE|PASS|observations=${rows.length}|closed=0|purpose-binding|runtime-grants|protected-source-denial\n`,
    );
    return rows;
  }
  const fence = await acquireDeploymentRetirementFence(runtime, binding(selected));
  const blocked = await worker.connect();
  let writer,
    released = false;
  try {
    await blocked.query('begin');
    await blocked.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true)",
      [scope.participantId, scope.privacyDomainId, uuidv7()],
    );
    const pid = (await blocked.query('select pg_backend_pid() pid')).rows[0].pid;
    // Replaying this exact retained signed result is forbidden. The real source
    // guard must first queue on the held reservation, then reject after release.
    writer = blocked
      .query(
        `insert into control.deployment_result(participant_id,privacy_domain_id,command_id,sequence,signed_bytes,result_digest)
      select participant_id,privacy_domain_id,command_id,sequence,signed_bytes,result_digest from control.deployment_result
      where participant_id=$1 and privacy_domain_id=$2 and command_id=$3 and sequence=$4`,
        [
          scope.participantId,
          scope.privacyDomainId,
          selected.record_id.split(':')[1],
          selected.record_id.split(':')[2],
        ],
      )
      .then(
        () => ({ success: true }),
        (error) => ({ error }),
      );
    let waiting = false;
    for (let attempt = 0; attempt < 50; attempt++) {
      waiting = (
        await admin.query(
          "select exists(select 1 from pg_stat_activity where pid=$1 and wait_event_type='Lock') waiting",
          [pid],
        )
      ).rows[0].waiting;
      if (waiting) break;
      await delay(20);
    }
    assert.equal(waiting, true, 'The actual result insert must wait behind the retirement fence');
    await fence.revalidate();
    await fence.release();
    released = true;
    const result = await writer;
    assert.equal(result.success, undefined);
    assert.match(result.error.message, /PC-DATA-6004/u);
  } finally {
    if (!released) await fence.release();
    if (writer) await writer;
    await blocked.query('rollback');
    blocked.release();
  }
  process.stdout.write(
    `OPENPC_DEPLOYMENT_RETIREMENT_SOURCE|PASS|observations=${rows.length}|closed=${finalized.length}|purpose-binding|actual-runtime-grants|reorg-denial|queued-real-writer|no-effect\n`,
  );
  return rows;
}
