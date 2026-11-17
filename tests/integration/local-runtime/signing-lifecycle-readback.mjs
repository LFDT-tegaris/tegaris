import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  decodeCbor,
  encodeCbor,
} from '../../../packages/security-kernel/src/business-transition/cbor.ts';
import { decodeReceiptStructureV2 } from '../../../packages/security-kernel/src/business-transition/payload.ts';

const [secretRoot, participantId, privacyDomainId, rotationRef, signerRole] = process.argv.slice(2);
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const recovery = process.env.OPENPC_LOCAL_RUNTIME_SIGNING_RECOVERY === '1';
const combined = process.env.OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED === '1';
const receiptCount = 8 + Number(recovery) + 3 * Number(combined);
const digest = (bytes) => createHash('sha256').update(bytes).digest();
try {
  const history = (
    await pool.query(
      `select h.*,r.receipt_cbor,r.cose_sign1,r.before_state_preimage,r.after_state_preimage,
    k.public_key_spki_der,a.payload_cbor,a.payload_digest,a.reservation_kind,a.admission_version,p.observation
    from control.signing_rotation_history h left join control.audit_occurrence r
     on r.participant_id=h.participant_id and r.privacy_domain_id=h.privacy_domain_id and r.receipt_id=h.receipt_id
    left join control.business_signing_key k on k.participant_id=r.participant_id and k.privacy_domain_id=r.privacy_domain_id and k.signer_id=r.signer_id
    left join control.receipt_signing_attempt a on a.attempt_id=r.receipt_id
    left join control.signing_provider_attempt p on p.attempt_id=a.attempt_id
    where h.participant_id=$1 and h.privacy_domain_id=$2 and h.rotation_id=$3 order by h.revision`,
      [participantId, privacyDomainId, rotationRef.split(':').at(-1)],
    )
  ).rows;
  const states = [
    'REQUESTED',
    'APPROVED',
    ...(recovery ? ['RECOVERING'] : []),
    'PREPARED',
    ...(combined ? ['PREPARED'] : []),
    'DISTRIBUTED',
    'VERIFIED',
    'CUTOVER_FENCED',
    'OBSERVING',
    'OLD_REVOKED',
    ...(combined ? ['FAILED', 'RECOVERING'] : []),
    'OLD_RETIRED',
    'COMPLETE',
  ];
  assert.deepEqual(
    history.map((r) => r.state),
    states,
    'every revision came through the public request, approval and advance owners',
  );
  const publicReadback = JSON.parse(
    await readFile(join(secretRoot, '../evidence/signing-read-COMPLETE.json'), 'utf8'),
  );
  assert.deepEqual(
    publicReadback.history.map((row) => row.revision),
    states.map((_, index) => String(index + 1)),
    'public history is ordered numerically beyond revision nine',
  );
  assert.deepEqual(
    publicReadback.history.map((row) => row.state),
    states,
  );
  assert.deepEqual(
    publicReadback.history.map((row) => row.receiptId),
    history.map((row) => row.receipt_id),
  );
  const rotation = (
    await pool.query(
      `select old_signer_id,new_signer_id from control.signing_key_rotation where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3`,
      [participantId, privacyDomainId, rotationRef.split(':').at(-1)],
    )
  ).rows[0];
  const inbox = (
    await pool.query(
      `select i.sequence::text,i.receipt_id,i.signer_id,i.key_epoch::text from control.qualified_receipt_inbox i where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and namespace='CONTROL_SIGNING_LIFECYCLE_V1' order by i.sequence`,
      [participantId, privacyDomainId, rotationRef.split(':').at(-1)],
    )
  ).rows;
  assert.equal(
    inbox.length,
    receiptCount,
    'worker verified every receipt, including zero-event effects',
  );
  assert.deepEqual(
    inbox.map((r) => r.sequence),
    Array.from({ length: receiptCount }, (_, i) => String(i + 1)),
  );
  assert.deepEqual(
    inbox.map((r) => r.receipt_id),
    history.slice(2).map((r) => r.receipt_id),
  );
  const checkpoint = (
    await pool.query(
      `select last_sequence::text,last_receipt_id from control.qualified_receipt_checkpoint where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and namespace='CONTROL_SIGNING_LIFECYCLE_V1'`,
      [participantId, privacyDomainId, rotationRef.split(':').at(-1)],
    )
  ).rows[0];
  assert.equal(checkpoint.last_sequence, String(receiptCount));
  assert.equal(checkpoint.last_receipt_id, inbox[receiptCount - 1].receipt_id);
  for (const [index, row] of history.entries()) {
    assert.deepEqual(digest(row.history_preimage), row.history_digest);
    assert.deepEqual(row.prior_digest, index === 0 ? null : history[index - 1].history_digest);
    if (index < 2) {
      assert.equal(row.receipt_id, null);
      continue;
    }
    assert.equal(row.receipt_namespace, 'CONTROL_SIGNING_LIFECYCLE_V1');
    assert.equal(row.receipt_ordinal, String(index - 1));
    assert.equal(row.reservation_kind, 'LIFECYCLE_DURABLE');
    const retainedHistory = JSON.parse(row.history_preimage.toString('utf8'));
    assert.equal(String(retainedHistory.attester.admissionVersion), row.admission_version);
    assert.ok(retainedHistory.selections.every((selection) => selection.admissionVersion > 0));
    assert.deepEqual(row.payload_cbor, row.receipt_cbor);
    assert.deepEqual(row.payload_digest, digest(row.receipt_cbor));
    assert.equal(row.observation.outcome, 'SUCCEEDED');
    assert.equal(row.observation.resultHex, row.cose_sign1.toString('hex'));
    const receipt = decodeReceiptStructureV2(row.receipt_cbor);
    assert.equal(receipt.receiptId, row.receipt_id);
    if (signerRole === 'LIFECYCLE_EVIDENCE') {
      assert.equal(
        receipt.signerId,
        index <= states.indexOf('CUTOVER_FENCED') ? rotation.old_signer_id : rotation.new_signer_id,
      );
      assert.equal(
        inbox[index - 2].key_epoch,
        index <= states.indexOf('CUTOVER_FENCED') ? '1' : '2',
      );
    } else assert.notEqual(receipt.signerId, rotation.new_signer_id);
    assert.equal(
      receipt.transitionProfileId,
      row.state === 'RECOVERING' || (combined && index === states.indexOf('PREPARED') + 1)
        ? 'pc.control.signing-rotation.recover'
        : 'pc.control.signing-rotation.advance',
    );
    assert.equal(receipt.before.revision, BigInt(index));
    assert.equal(receipt.after.revision, BigInt(index + 1));
    assert.deepEqual(receipt.before.stateDigest, digest(row.before_state_preimage));
    assert.deepEqual(receipt.after.stateDigest, digest(row.after_state_preimage));
    assert.deepEqual(decodeCbor(row.after_state_preimage)[8].get(2), row.history_digest);
    const terminal =
      row.state === 'OLD_REVOKED' ? 'revoked' : row.state === 'COMPLETE' ? 'rotated' : undefined;
    assert.equal(receipt.outboxEvents.length, terminal === undefined ? 0 : 1);
    assert.equal(row.event_id, terminal === undefined ? null : receipt.outboxEvents[0].eventId);
    if (terminal)
      assert.equal(receipt.outboxEvents[0].eventType, `io.openpc.ops.secret.${terminal}.v1`);
    assert.equal(row.cose_sign1[0], 0xd2);
    const [header, unprotected, payload, signature] = decodeCbor(row.cose_sign1.subarray(1));
    assert.equal(unprotected.size, 0);
    assert.deepEqual(payload, row.receipt_cbor);
    const protectedFields = decodeCbor(header);
    assert.equal(protectedFields.get(100), 24001n);
    assert.equal(protectedFields.get(101), 2n);
    assert.equal(protectedFields.get(102), 338n);
    assert.equal(protectedFields.get(4).toString(), receipt.signerId);
    const signed = encodeCbor([
      'Signature1',
      header,
      Buffer.from('pcplane:cose-sign1:v2\0'),
      payload,
    ]);
    assert.ok(
      verify(
        'sha256',
        signed,
        {
          key: createPublicKey({ key: row.public_key_spki_der, type: 'spki', format: 'der' }),
          dsaEncoding: 'ieee-p1363',
        },
        signature,
      ),
    );
  }
  if (combined) {
    const params = [participantId, privacyDomainId, rotationRef.split(':').at(-1)];
    const commands = (
      await pool.query(
        `select c.operation_id,c.result_kind,c.state,c.authorization_generation_id,
      (select count(*)::int from control.signing_rotation_history h where h.operation_id=c.operation_id) history_count,
      (select count(*)::int from control.signing_rotation_operation_evidence e where e.operation_id=c.operation_id) failure_evidence
      from control.signing_rotation_command c where c.participant_id=$1 and c.privacy_domain_id=$2 and c.rotation_id=$3`,
        params,
      )
    ).rows;
    for (const kind of ['AUTHORITY_CHANGED_BEFORE_DISPATCH', 'NO_EFFECT_RETRYABLE']) {
      const failed = commands.filter((c) => c.result_kind === kind);
      assert.equal(failed.length, 1);
      assert.equal(failed[0].state, 'FAILED');
      assert.equal(failed[0].history_count, 0);
      assert.equal(failed[0].failure_evidence, 1);
    }
    assert.equal(
      commands.filter(
        (c) =>
          c.result_kind === 'PROVIDER_REJECTED' && c.state === 'FAILED' && c.history_count === 1,
      ).length,
      1,
    );
    const generations = (
      await pool.query(
        `select * from control.signing_authorization_generation where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 order by result_revision`,
        params,
      )
    ).rows;
    assert.equal(generations.length, 4);
    const staleGeneration = generations.filter((g) => g.state === 'STAGED');
    assert.equal(staleGeneration.length, 1);
    const consumedGenerations = generations.filter((g) => g.state === 'CONSUMED');
    assert.equal(consumedGenerations.length, 3);
    assert.deepEqual(
      consumedGenerations.map((g) => g.prior_generation_id),
      [null, consumedGenerations[0].generation_id, consumedGenerations[1].generation_id],
    );
    const staleCommand = commands.find(
      (c) =>
        c.authorization_generation_id === staleGeneration[0].generation_id &&
        c.result_kind === 'SIGNATURE_UNAVAILABLE',
    );
    assert.ok(staleCommand);
    assert.equal(staleCommand.state, 'FAILED');
    assert.equal(staleCommand.history_count, 0);
    assert.equal(staleCommand.failure_evidence, 0);
    const holds = (
      await pool.query(
        `select * from control.signing_rotation_authority_hold where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3`,
        params,
      )
    ).rows;
    assert.equal(holds.length, 1);
    assert.equal(holds[0].state, 'CLEARED');
    const continuations = (
      await pool.query(
        `select c.* from control.signing_continuation c join control.signing_rotation_command r using(participant_id,privacy_domain_id,operation_id) where c.participant_id=$1 and c.privacy_domain_id=$2 and r.rotation_id=$3 and c.state='CONSUMED'`,
        params,
      )
    ).rows;
    assert.equal(
      continuations.filter((c) => c.consumed_receipt_id === null).length,
      1,
      'only definitive no-effect completes without a lifecycle receipt',
    );
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)",
        params.slice(0, 2),
      );
      await client.query('set local role openpc_control_worker');
      await client.query('savepoint checkpoint_jump');
      await assert.rejects(
        client.query(
          `update control.qualified_receipt_checkpoint set last_sequence=last_sequence+2 where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and namespace='CONTROL_SIGNING_LIFECYCLE_V1'`,
          params,
        ),
        /CHECKPOINT-ACCEPTANCE/,
      );
      await client.query('rollback to savepoint checkpoint_jump');
      assert.equal(
        (
          await client.query(
            `select last_sequence::text from control.qualified_receipt_checkpoint where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and namespace='CONTROL_SIGNING_LIFECYCLE_V1'`,
            params,
          )
        ).rows[0].last_sequence,
        String(receiptCount),
      );
      await client.query('rollback');
      await client.query('begin');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1',true)",
        params.slice(0, 2),
      );
      await client.query('set local role openpc_configuration_runtime');
      await assert.rejects(
        client.query(
          "update control.signing_authorization_generation set state='STAGED' where generation_id=$1",
          [generations[0].generation_id],
        ),
        /SIGNING-GENERATION-SIGNED-COMMIT/,
        'consumed old generation cannot be replayed',
      );
    } finally {
      await client.query('rollback');
      client.release();
    }
  }
  process.stdout.write(
    'OPENPC_SIGNING_LIFECYCLE_RECEIPTS|PASS|all-v2-receipts|independent-ordinals|immutable-attempts|history-chain|two-state-owned-events|qualified-worker-ordinals\n',
  );
} finally {
  await pool.end();
}
