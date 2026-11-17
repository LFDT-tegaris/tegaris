import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from 'pg';

const [secretRoot, participantId, privacyDomainId, candidateRef] = process.argv.slice(2);
const client = new Client({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_configuration_runtime',
  password: (
    await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
  ).trim(),
});
try {
  await client.connect();
  await client.query('begin');
  await client.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1',true)",
    [participantId, privacyDomainId],
  );
  const generation = (
    await client.query(
      `select g.*,c.candidate_document from control.signing_authorization_generation g join control.mutation_candidate c on c.mutation_candidate_id=g.candidate_id where g.candidate_id=$1`,
      [candidateRef.split(':').at(-1)],
    )
  ).rows[0];
  assert.ok(generation);
  assert.equal(generation.state, 'STAGED');
  const check = () =>
    client.query('select openpc.check_signing_generation_current($1)', [generation.generation_id]);
  await check();
  assert.deepEqual(
    (
      await client.query(`select
      has_column_privilege(current_user,'control.signing_authorization_generation','target_state','UPDATE') as target,
      has_column_privilege(current_user,'control.signing_authorization_generation','state','UPDATE') as state,
      has_column_privilege(current_user,'control.session','session_epoch','UPDATE') as session`)
    ).rows[0],
    { target: false, state: true, session: true },
    'the runtime can consume a signed generation but cannot choose its target',
  );
  await client.query('savepoint forged_target');
  await assert.rejects(
    client.query(
      "update control.signing_authorization_generation set target_state='COMPLETE' where generation_id=$1",
      [generation.generation_id],
    ),
    { code: '42501' },
  );
  await client.query('rollback to savepoint forged_target');
  assert.equal(
    (
      await client.query(
        'select target_state from control.signing_authorization_generation where generation_id=$1',
        [generation.generation_id],
      )
    ).rows[0].target_state,
    generation.target_state,
  );
  await client.query('savepoint authority_changed');
  const session =
    generation.candidate_document.context.originalAuthority.dependencies.session[0].session_id;
  await client.query(
    'update control.session set session_epoch=session_epoch+1 where session_id=$1',
    [session],
  );
  await assert.rejects(
    check(),
    /SIGNING-GOVERNANCE-STALE/,
    'new authority invalidates the approved plan',
  );
  await client.query('rollback to savepoint authority_changed');
  await check();
  await client.query('savepoint cross_scope');
  await client.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1',true)",
    [participantId, '018f0000-0000-7000-8000-000000000202'],
  );
  assert.equal(
    (
      await client.query(
        'select generation_id from control.signing_authorization_generation where generation_id=$1',
        [generation.generation_id],
      )
    ).rowCount,
    0,
  );
  await client.query('rollback to savepoint cross_scope');
  await client.query('rollback');
  process.stdout.write(
    'OPENPC_SIGNING_GOVERNANCE_BOUNDARIES|PASS|approved-exact-context|changed-authority-stale|caller-target-denied|cross-privacy-hidden|no-probe-effects\n',
  );
} finally {
  await client.query('rollback').catch(() => {});
  await client.end();
}
