import assert from 'node:assert/strict';
import { writeFile, readFile, chmod } from 'node:fs/promises';
import { createECDH } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { join } from 'node:path';
import { expect } from '@playwright/test';
import { decodeBffSession } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { publicReadResponse } from './authenticated-http.mjs';

export function assertRejectionDeletionSources(sources) {
  const claims = sources.map((row) => JSON.parse(row.signed_bytes.toString('utf8')).claims);
  assert.ok(claims.some((source) => source.schema === 'PC-DEPLOYMENT-RESERVATION-REJECTION-1'));
  const observations = claims.filter(
    (source) => source.schema === 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1',
  );
  // Operation acceptance is not effect success. Require real uncertainty,
  // confirmation and reorg sources before claiming their deletion denials.
  for (const truthState of ['UNKNOWN', 'SUCCESS', 'REORG'])
    assert.ok(
      observations.some((source) => source.status.truthState === truthState),
      `Missing real ${truthState} source`,
    );
}

export async function publicEvidenceReader(page, secretRoot, participantId, privacyDomainId) {
  const cookie = (await page.context().cookies()).find(
    (c) => c.name === 'openpc_local_runtime_session',
  );
  assert.ok(cookie);
  const key = (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim();
  const session = decodeBffSession(cookie.value, Buffer.from(key));
  assert.ok(session);
  return async (path, context = {}, recovering = false) => {
    for (let attempt = 0; attempt < (recovering ? 40 : 1); attempt++) {
      const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
        headers: {
          'Cookie': `__Host-openpc_session=${session.sessionToken}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${context.participantId ?? participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.privacyDomainId ?? privacyDomainId}`,
          'X-Request-ID': uuidv7(),
          'X-Correlation-ID': uuidv7(),
        },
        signal: AbortSignal.timeout(15000),
      });
      if (recovering && response.status === 503) {
        assert.equal(await publicReadResponse(response, true), null);
        if (attempt === 0)
          process.stdout.write(
            'OPENPC_EVIDENCE_RESTART_READBACK|WAIT|classified-unavailable|original-read-only\n',
          );
        await delay(250);
        continue;
      }
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return { status: response.status, body: await response.json() };
    }
    throw new Error('Original evidence readback did not recover after restart');
  };
}

// Real immutable source and custody state, excluding unrelated authentication
// occurrences produced by the browser's fresh security-key ceremonies.
export async function rejectionDeletionSnapshot(admin, participantId, privacyDomainId, streamId) {
  const scope = [participantId, privacyDomainId];
  const query = async (sql, values = scope) => (await admin.query(sql, values)).rows;
  return {
    results: await query(
      'select * from control.deployment_result where participant_id=$1 and privacy_domain_id=$2 order by command_id,sequence',
    ),
    reservations: await query(
      'select * from control.deployment_address_reservation where participant_id=$1 and privacy_domain_id=$2 order by command_id',
    ),
    segments: await query(
      'select * from control.evidence_segment where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by first_sequence',
      [...scope, streamId],
    ),
    checkpoints: await query(
      'select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sink_id,through_sequence',
      [...scope, streamId],
    ),
    payloads: await query(
      'select * from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by segment_id',
      [...scope, streamId],
    ),
    stream: await query(
      'select * from control.evidence_stream where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
      [...scope, streamId],
    ),
    jobs: await query(
      'select * from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 order by deletion_job_id',
    ),
    items: await query(
      'select * from control.evidence_deletion_item where participant_id=$1 and privacy_domain_id=$2 order by deletion_job_id,segment_id',
    ),
    receipts: await query(
      "select * from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='evidence-deletion' order by operation_id",
    ),
    outbox: await query(
      "select * from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='evidence-deletion' order by event_id",
    ),
    attempts: await query(
      "select a.* from control.receipt_signing_attempt a join control.business_transition_profile p using(profile_digest) where participant_id=$1 and privacy_domain_id=$2 and p.profile_id like 'pc.control.evidence-deletion.%' order by attempt_id",
    ),
  };
}

export async function wrongRejectionTrust(secretRoot, operation) {
  const file = join(secretRoot, 'fleet_deployment_rejection_public_key.txt');
  const original = await readFile(file);
  const key = createECDH('secp256k1');
  key.generateKeys();
  // This is the owned local fixture's public key, never a production secret.
  await chmod(file, 0o644);
  try {
    await writeFile(file, key.getPublicKey('hex', 'compressed'));
    await operation();
  } finally {
    await writeFile(file, original);
    await chmod(file, 0o444);
  }
}

export async function retryDeletion(
  page,
  approvalId,
  { failed = false, expectedFailureStatus, duringExecution, loseResponse = false } = {},
) {
  const endpoint = '/api/v1/ui/transaction-workbench';
  const original = await readWorkbenchApproval(page, approvalId);
  assert.equal(original.candidate.state, 'APPROVED');
  let lost = false;
  const route = async (request) => {
    if (
      request.request().method() === 'POST' &&
      request.request().postDataJSON()?.command === 'EXECUTE'
    ) {
      const response = await request.fetch();
      assert.equal(response.status(), 202);
      lost = true;
      await request.abort('failed');
    } else await request.continue();
  };
  if (loseResponse) await page.route(`**${endpoint}`, route);
  const pending = loseResponse
    ? undefined
    : page.waitForResponse(
        (r) =>
          r.request().method() === 'POST' &&
          new URL(r.url()).pathname === endpoint &&
          r.request().postDataJSON()?.command === 'EXECUTE',
      );
  await page.getByRole('button', { name: 'Execute approved request', exact: true }).click();
  await duringExecution?.();
  if (pending) {
    const response = await pending;
    if (failed) {
      assert.ok(response.status() >= 400);
      if (expectedFailureStatus !== undefined)
        assert.equal(response.status(), expectedFailureStatus);
      const problem = await response.json();
      await expect(
        page.getByText(`${problem.title} (${problem.code})`, { exact: true }),
      ).toBeVisible();
    } else assert.equal(response.status(), 202);
  } else {
    await expect(
      page.getByText(
        'The response was lost. Read the approval and original result before retrying.',
        { exact: true },
      ),
    ).toBeVisible();
    assert.equal(lost, true);
    await page.unroute(`**${endpoint}`, route);
  }
  const completed = await readWorkbenchApproval(page, approvalId);
  assert.equal(completed.candidate.state, failed ? 'APPROVED' : 'CONSUMED');
  if (failed) {
    assert.equal(completed.result, null);
    assert.equal(completed.candidate.operationRef, null);
  }
  return completed;
}

export async function withDeletionOutboxFault(admin, streamId, mode, run) {
  assert.match(
    streamId,
    /^(?:rejection-deletion|canonical-facts|deployment-effects)-[0-9a-f-]{36}$/u,
  );
  assert.ok(['FAIL', 'WAIT', 'LEASE_EXPIRE'].includes(mode));
  // Fault injection at the actual last durable owner, scoped to this new intent.
  await admin.query(`create function public.rejection_deletion_outbox_test() returns trigger language plpgsql as $$
    begin if NEW.aggregate_type='evidence-deletion' and exists(select 1 from control.deletion_job j
      where j.deletion_job_id=NEW.aggregate_id and j.stream_id='${streamId}') then
      ${mode === 'FAIL' ? "raise exception 'local test storage failure';" : mode === 'LEASE_EXPIRE' ? 'perform pg_sleep(5.2);' : "perform pg_advisory_xact_lock(hashtextextended('openpc:rejection-deletion-test',0));"}
    end if; return NEW; end $$;
    create trigger rejection_deletion_outbox_test before insert on control.outbox_event
      for each row execute function public.rejection_deletion_outbox_test()`);
  try {
    return await run();
  } finally {
    await admin.query(
      'drop trigger rejection_deletion_outbox_test on control.outbox_event; drop function public.rejection_deletion_outbox_test()',
    );
  }
}

export async function contendingReservation({
  admin,
  worker,
  commandId,
  attemptId,
  participantId,
  privacyDomainId,
  execute,
}) {
  const barrier = await admin.connect(),
    contender = await worker.connect();
  let pending;
  try {
    await barrier.query('begin');
    await barrier.query(
      "select pg_advisory_xact_lock(hashtextextended('openpc:rejection-deletion-test',0))",
    );
    await contender.query('begin');
    await contender.query("set local statement_timeout='15s'");
    await contender.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true)",
      [participantId, privacyDomainId, uuidv7()],
    );
    const pid = (await contender.query('select pg_backend_pid() pid')).rows[0].pid;
    return await execute(async () => {
      await expect
        .poll(
          async () =>
            (
              await admin.query(
                "select count(*)::int n from pg_stat_activity where wait_event='advisory' and query like '%control.outbox_event%' and pid<>pg_backend_pid()",
              )
            ).rows[0].n,
          { timeout: 10000, intervals: [50] },
        )
        .toBe(1);
      // The actual INSERT trigger takes the same command fence before any
      // reservation/handoff can be established. No execution worker is started.
      pending = contender
        .query(
          `insert into control.deployment_address_reservation select
        (jsonb_populate_record(null::control.deployment_address_reservation,
          (select to_jsonb(r) from control.deployment_address_reservation r where participant_id=$3 and privacy_domain_id=$4 order by command_id limit 1)
          ||jsonb_build_object('command_id',$1::text,'attempt_id',$2::text,'state','RESERVED',
            'handoff_at',null,'expired_at',null,'predecessor_command_id',null,'expires_at',clock_timestamp()+interval '1 minute'))).*`,
          [commandId, attemptId, participantId, privacyDomainId],
        )
        .then(
          () => ({ accepted: true }),
          (error) => ({ error }),
        );
      await expect
        .poll(
          async () =>
            (await admin.query('select wait_event from pg_stat_activity where pid=$1', [pid]))
              .rows[0]?.wait_event,
          { timeout: 5000, intervals: [50] },
        )
        .toBe('advisory');
      await barrier.query('commit');
      const outcome = await pending;
      assert.equal(outcome.accepted, undefined);
      assert.match(outcome.error.message, /PC-DATA-6004/u);
      await contender.query('rollback');
      assert.equal(
        (
          await admin.query(
            'select 1 from control.deployment_address_reservation where command_id=$1',
            [commandId],
          )
        ).rowCount,
        0,
      );
    });
  } finally {
    await barrier.query('rollback');
    if (pending) await pending;
    await contender.query('rollback');
    barrier.release();
    contender.release();
  }
}
