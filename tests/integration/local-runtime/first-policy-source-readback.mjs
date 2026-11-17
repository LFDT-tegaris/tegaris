import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
const repo = process.cwd();
const { Pool } = createRequire(join(repo, 'package.json'))('pg');
const { decodeCbor, encodeCbor } = await import(
  join(repo, 'packages/security-kernel/src/business-transition/cbor.ts')
);
const { decodeReceiptStructure } = await import(
  join(repo, 'packages/security-kernel/src/business-transition/payload.ts')
);
const root = process.argv[2];
assert.ok(root?.startsWith('/'));
const renewedOperation = process.argv[3] || undefined;
if (renewedOperation)
  assert.match(
    renewedOperation,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const evidence = join(root, 'evidence/runtime-bootstrap');
const load = async (name) => JSON.parse(await readFile(join(evidence, name + '.json'), 'utf8'));
const pid = '018f0000-0000-7000-8000-000000000101',
  privacy = '018f0000-0000-7000-8000-000000007201';
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const hash = (bytes) => createHash('sha256').update(bytes).digest();
try {
  const ids = [],
    operations = [];
  for (const [kind, state, revision] of [
    ['provider', 'QUALIFIED', '4'],
    ['indexer', 'QUALIFIED', '3'],
    ['projection', 'VALIDATED', '3'],
  ]) {
    const op = await load(`configuration-${kind}`);
    ids.push(op.resourceRef.split(':').at(-1));
    operations.push(op.operationId);
    const view = await load(
      kind === 'provider' && renewedOperation
        ? 'configuration-provider-renewed-qualified-resource'
        : `configuration-${kind}-${kind === 'projection' ? 'validated' : 'qualified'}-resource`,
    );
    assert.equal(view.state, state);
    if (kind === 'provider' && renewedOperation) {
      // The existing native reader binds this exact operation, live observation,
      // work/result/authorization chain and observed+2 revision on its real client.
      await promisify(execFile)(process.execPath, [
        '--import',
        'tsx',
        'tests/integration/local-runtime/provider-probe-readback.mjs',
        join(root, 'secrets'),
        join(root, 'data/runtime-bootstrap'),
        ids.at(-1),
        renewedOperation,
        'current',
        view.revision,
      ]);
    } else assert.equal(view.revision, revision);
    if (kind === 'projection') assert.equal(view.readiness, 'READY');
  }
  for (const table of ['policy_generation', 'runtime_configuration_generation'])
    assert.equal(
      (
        await pool.query(
          `select count(*)::int n from control.${table} where participant_id=$1 and privacy_domain_id=$2`,
          [pid, privacy],
        )
      ).rows[0].n,
      0,
    );
  for (const [table, pk, id] of [
    ['provider_profile', 'provider_profile_id', ids[0]],
    ['indexer_profile', 'indexer_profile_id', ids[1]],
    ['projection_plan', 'projection_plan_id', ids[2]],
  ])
    assert.equal(
      (
        await pool.query(`select policy_generation_digest from control.${table} where ${pk}=$1`, [
          id,
        ])
      ).rows[0].policy_generation_digest,
      null,
    );
  const works = (
    await pool.query(
      `select w.work_kind,w.state,w.policy_generation_digest,w.result_receipt,w.result_receipt_digest,e.event_id from control.configuration_work w left join control.outbox_event e on e.event_id=w.result_event_id and e.participant_id=w.participant_id and e.privacy_domain_id=w.privacy_domain_id where w.participant_id=$1 and w.privacy_domain_id=$2
        and ($3::uuid is null or w.work_kind<>'PROVIDER_QUALIFICATION' or w.operation_id=$3::uuid) order by w.work_kind`,
      [pid, privacy, renewedOperation ?? null],
    )
  ).rows;
  assert.deepEqual(
    works.map((w) => w.work_kind),
    ['INDEXER_ADMISSION', 'PROJECTION_VALIDATION', 'PROVIDER_QUALIFICATION'],
  );
  for (const w of works) {
    assert.equal(w.state, 'COMPLETED');
    assert.equal(w.policy_generation_digest, null);
    assert.ok(w.result_receipt && w.result_receipt_digest && w.event_id);
  }
  const authorization = (
    await pool.query(
      `select operation_id::text,aggregate_id::text,evidence_cbor,evidence_digest from control.mutation_evidence where participant_id=$1 and privacy_domain_id=$2 and operation_id=any($3::uuid[])`,
      [pid, privacy, operations],
    )
  ).rows;
  assert.equal(authorization.length, 3);
  for (const row of authorization) {
    assert.equal(row.aggregate_id, ids[operations.indexOf(row.operation_id)]);
    assert.deepEqual(hash(row.evidence_cbor), row.evidence_digest);
  }
  for (const [id, eventType] of [
    [ids[0], 'provider-profile.registered.v1'],
    [ids[2], 'projection-plan.created.v1'],
  ]) {
    const event = (
      await pool.query(
        `select payload_cbor,payload_digest from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and aggregate_sequence=1 and event_type=$4`,
        [pid, privacy, id, eventType],
      )
    ).rows;
    assert.equal(event.length, 1);
    assert.deepEqual(hash(event[0].payload_cbor), event[0].payload_digest);
    const payload = JSON.parse(event[0].payload_cbor.toString('utf8'));
    assert.equal(payload.aggregateId, id);
    assert.equal(payload.participantId, pid);
    assert.equal(payload.privacyDomainId, privacy);
    assert.equal(payload.revision, '1');
  }
  const receipts = (
    await pool.query(
      `select a.*,k.public_key_spki_der,e.receipt_id evidence_receipt from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) join control.evidence_record e using(participant_id,privacy_domain_id,receipt_id,receipt_digest) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_id=any($3::uuid[])`,
      [pid, privacy, ids],
    )
  ).rows;
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].aggregate_id, ids[1]);
  for (const row of receipts) {
    const receipt = decodeReceiptStructure(row.receipt_cbor),
      cose = decodeCbor(row.cose_sign1.subarray(1));
    assert.equal(row.cose_sign1[0], 0xd2);
    const [protectedBytes, , payload, signature] = cose;
    assert.deepEqual(payload, row.receipt_cbor);
    assert.deepEqual(hash(payload), row.receipt_digest);
    assert.equal(receipt.participantId, pid);
    assert.equal(receipt.privacyDomainId, privacy);
    assert.deepEqual(hash(row.before_state_preimage), receipt.before.stateDigest);
    assert.deepEqual(hash(row.after_state_preimage), receipt.after.stateDigest);
    const key = createPublicKey({ key: row.public_key_spki_der, format: 'der', type: 'spki' });
    const structure = encodeCbor([
      'Signature1',
      protectedBytes,
      Buffer.from('7063706c616e653a636f73652d7369676e313a763200', 'hex'),
      payload,
    ]);
    assert.ok(verify('sha256', structure, { key, dsaEncoding: 'ieee-p1363' }, signature));
    assert.equal(
      (
        await pool.query('select count(*)::int n from control.outbox_event where receipt_id=$1', [
          row.receipt_id,
        ])
      ).rows[0].n,
      1,
    );
  }
  const accepted = (
    await pool.query(
      `select i.sequence::text,i.receipt_id::text,i.receipt_digest,c.last_sequence::text,c.last_receipt_id::text,a.receipt_digest expected_digest,a.profile_version::text from control.qualified_receipt_inbox i join control.qualified_receipt_checkpoint c using(participant_id,privacy_domain_id,namespace,aggregate_type,aggregate_id) join control.audit_occurrence a using(participant_id,privacy_domain_id,receipt_id) where i.participant_id=$1 and i.privacy_domain_id=$2 and i.aggregate_id=$3 and i.namespace='CONTROL_BUSINESS_TRANSITION_V1'`,
      [pid, privacy, ids[1]],
    )
  ).rows;
  assert.equal(accepted.length, 1);
  assert.equal(accepted[0].sequence, '1');
  assert.equal(accepted[0].last_sequence, '1');
  assert.equal(accepted[0].profile_version, '2');
  assert.equal(accepted[0].last_receipt_id, accepted[0].receipt_id);
  assert.deepEqual(accepted[0].receipt_digest, accepted[0].expected_digest);
  process.stdout.write(
    'OPENPC_BOOTSTRAP_SOURCE_PREPARATION|PASS|public-created|real-qualified|indexer-admitted|projection-ready|signed-indexer-create|all-create-authorization-outbox|v2-qualified-inbox-original-receipt|no-generation\n',
  );
} finally {
  await pool.end();
}
