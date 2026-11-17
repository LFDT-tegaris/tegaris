import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from 'pg';
import { canonicalDefinitionJson } from '../../../packages/security-kernel/src/business-transition/definition.ts';
import { createHash } from 'node:crypto';
import { validateBusinessProviderObservation } from '../../../services/identity-service/src/domain/business-signing-provider.ts';

// The public owners created and approved this rotation and dispatched PREPARE. Only the
// genuinely external provider lost its response. Never synthesize an internal business state.
const [secretRoot, participantId, privacyDomainId, operationId, mode] = process.argv.slice(2);
assert.ok(['rollback', 'commit'].includes(mode));
const client = new Client({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_local_control_worker',
  password: (
    await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
  ).trim(),
  statement_timeout: 15000,
});
const context = (
  operation = operationId,
  privacy = privacyDomainId,
  action = 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
) =>
  client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
    participantId,
    privacy,
    operation,
    action,
  ]);
try {
  await client.connect();
  await client.query('begin');
  await context();
  const attempt = (
    await client.query(
      `select attempt_id,request,state,observation from control.signing_provider_attempt
    where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and request->>'method'='PREPARE'`,
      [participantId, privacyDomainId, operationId],
    )
  ).rows[0];
  assert.ok(attempt);
  assert.equal(attempt.state, 'DISPATCHING');
  assert.equal(attempt.observation, null);
  const external = JSON.parse(
    await readFile(
      join(secretRoot, '../data/signing-provider/attempts', attempt.attempt_id + '.json'),
      'utf8',
    ),
  );
  assert.deepEqual(external.request, attempt.request);
  validateBusinessProviderObservation(attempt.request, external.observation);
  const digest = createHash('sha256')
    .update(canonicalDefinitionJson(external.observation))
    .digest();
  const ledger = async () =>
    (
      await client.query(
        `select o.observation_id,o.observation_digest,
    o.observation_digest=sha256(o.observation_preimage) as valid_digest,
    observation_preimage=openpc.signing_observation_preimage(a,'PROVIDER_RESULT') as valid_binding
    from control.signing_rotation_observation o join control.signing_provider_attempt a using(participant_id,privacy_domain_id,attempt_id)
    where o.attempt_id=$1 and o.kind='PROVIDER_RESULT'`,
        [attempt.attempt_id],
      )
    ).rows;
  const complete = () =>
    client.query(
      `update control.signing_provider_attempt set state='OBSERVED',observation=$2,observation_digest=$3
    where attempt_id=$1 and state='DISPATCHING'`,
      [attempt.attempt_id, external.observation, digest],
    );
  assert.deepEqual(await ledger(), []);
  await client.query('savepoint first_result');
  assert.equal((await complete()).rowCount, 1);
  const first = await ledger();
  assert.equal(first.length, 1);
  assert.equal(first[0].valid_digest, true);
  assert.equal(first[0].valid_binding, true);
  for (let n = 0; n < 2; n++) {
    const replay = (
      await client.query("select * from openpc.record_signing_observation($1,'PROVIDER_RESULT')", [
        attempt.attempt_id,
      ])
    ).rows;
    assert.equal(replay[0].observation_id, first[0].observation_id);
    assert.deepEqual(replay[0].observation_digest, first[0].observation_digest);
  }
  assert.deepEqual(await ledger(), first);
  await client.query('savepoint immutable_result');
  await assert.rejects(
    client.query(
      "update control.signing_provider_attempt set observation=jsonb_set(observation,'{providerId}','\"changed\"') where attempt_id=$1",
      [attempt.attempt_id],
    ),
    /DATA-6020-ATTEMPT-OBSERVATION/,
  );
  await client.query('rollback to savepoint immutable_result');
  assert.deepEqual(await ledger(), first);
  await client.query('rollback to savepoint first_result');
  assert.deepEqual(
    await ledger(),
    [],
    'rolling back provider completion also rolls back its canonical observation',
  );
  assert.equal(
    (
      await client.query(
        'select observation from control.signing_provider_attempt where attempt_id=$1',
        [attempt.attempt_id],
      )
    ).rows[0].observation,
    null,
  );
  for (const badContext of [
    () => context(attempt.attempt_id),
    () => context(operationId, privacyDomainId, 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1'),
  ]) {
    await client.query('savepoint wrong_context');
    await badContext();
    await assert.rejects(complete(), /DATA-6021-SIGNING-OBSERVATION-CONTEXT/);
    await client.query('rollback to savepoint wrong_context');
    assert.deepEqual(await ledger(), []);
  }
  await client.query('savepoint wrong_tenant');
  await context(operationId, participantId);
  assert.equal(
    (await complete()).rowCount,
    0,
    'another partition cannot see or complete this attempt',
  );
  await client.query('rollback to savepoint wrong_tenant');
  if (mode === 'commit') {
    assert.equal((await complete()).rowCount, 1);
    assert.equal((await ledger()).length, 1);
    await client.query('commit');
    await client.query('begin');
    await context();
    assert.equal(
      (await complete()).rowCount,
      0,
      'completion replay does not rewrite the provider result',
    );
    assert.equal((await ledger()).length, 1);
  }
  await client.query('rollback');
  process.stdout.write(
    `OPENPC_SIGNING_PROVIDER_RESULT|PASS|atomic-rollback|digest-binding|deduplication|immutable|operation-action-partition-denials|${mode}\n`,
  );
} finally {
  await client.query('rollback').catch(() => {});
  await client.end();
}
