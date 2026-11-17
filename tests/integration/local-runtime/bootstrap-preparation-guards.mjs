// Rollback-only SQL boundary checks. These are not public bootstrap acceptance.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';

const [secretRoot, participant, privacy, foreignPrivacy] = process.argv.slice(2);
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const client = await pool.connect();
async function context(scope = privacy) {
  await client.query(
    "select openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true),openpc.assert_request_context(true)",
    [participant, scope],
  );
}
async function denied(sql, values, expected) {
  await client.query('savepoint denied');
  try {
    await assert.rejects(client.query(sql, values), expected);
  } finally {
    await client.query('rollback to savepoint denied');
    await client.query('release savepoint denied');
  }
}
try {
  await client.query('begin');
  await client.query('set local role openpc_control_runtime');
  await context();
  assert.equal(
    (await client.query('select count(*)::int n from control.policy_generation')).rows[0].n,
    0,
    'requires a real isolated never-generated context',
  );
  assert.equal(
    (
      await client.query(
        'select openpc.configuration_policy_provenance($1::uuid,$2::uuid) provenance',
        [participant, privacy],
      )
    ).rows[0].provenance,
    null,
  );
  const target = (
    await client.query(
      `insert into control.runtime_target(runtime_target_id,participant_id,privacy_domain_id,observed_at,policy_generation_digest,requires_authenticated_discovery)
    values(uuidv7(),$1,$2,clock_timestamp(),null,true) returning runtime_target_id::text,state,desired_generation_digest,active_generation_digest,xds_version_digest`,
      [participant, privacy],
    )
  ).rows[0];
  assert.equal(target.state, 'OFFLINE');
  assert.equal(target.desired_generation_digest, null);
  assert.equal(target.active_generation_digest, null);
  assert.equal(target.xds_version_digest, null);
  assert.equal(
    (
      await client.query('select openpc.runtime_target_discovery_current($1,$2,$3) ready', [
        participant,
        privacy,
        target.runtime_target_id,
      ])
    ).rows[0].ready,
    false,
  );
  await denied(
    "update control.runtime_target set state='DISCOVERED' where runtime_target_id=$1",
    [target.runtime_target_id],
    /TARGET-DISCOVERY-REQUIRED/u,
  );
  await denied(
    'update control.runtime_target set requires_authenticated_discovery=false where runtime_target_id=$1',
    [target.runtime_target_id],
    /TARGET-ENROLLMENT-IMMUTABLE/u,
  );
  await denied(
    'select openpc.configuration_policy_provenance($1,$2)',
    [participant, foreignPrivacy],
    /CONTEXT-INVALID/u,
  );
  await denied(
    'select * from openpc.lock_runtime_discovery_authority($1,$2)',
    [target.runtime_target_id, `sha256:${'71'.repeat(32)}`],
    /permission denied/u,
  );
  await denied(
    'insert into control.runtime_target_connection select * from control.runtime_target_connection',
    [],
    /permission denied/u,
  );
  await client.query('set local role openpc_control_worker');
  await denied(
    'select * from openpc.lock_runtime_discovery_authority($1,$2)',
    [target.runtime_target_id, `sha256:${'71'.repeat(32)}`],
    /DISCOVERY-CREDENTIAL-CARDINALITY/u,
  );
  await denied(
    "update control.runtime_target set state='DISCOVERED' where runtime_target_id=$1",
    [target.runtime_target_id],
    /TARGET-DISCOVERY-REQUIRED/u,
  );
  await context(foreignPrivacy);
  assert.equal(
    (
      await client.query(
        'select count(*)::int n from control.runtime_target where runtime_target_id=$1',
        [target.runtime_target_id],
      )
    ).rows[0].n,
    0,
  );
  assert.equal(
    (
      await client.query('select openpc.runtime_target_discovery_current($1,$2,$3) ready', [
        participant,
        privacy,
        target.runtime_target_id,
      ])
    ).rows[0].ready,
    false,
  );
  console.log(
    'OPENPC_BOOTSTRAP_PREPARATION|PASS|non-serving-absence|runtime-cannot-discover|worker-needs-current-credential|scope-isolation|rollback-only',
  );
} finally {
  await client.query('rollback');
  client.release();
  await pool.end();
}
