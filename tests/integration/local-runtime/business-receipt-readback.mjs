import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  decodeCbor,
  encodeCbor,
} from '../../../packages/security-kernel/src/business-transition/cbor.ts';
import { decodeReceiptStructure } from '../../../packages/security-kernel/src/business-transition/payload.ts';

const [secretRoot, participantId, privacyDomainId] = process.argv.slice(2);
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const hash = (bytes) => createHash('sha256').update(bytes).digest();
try {
  const rows = (
    await pool.query(
      `select a.*,k.public_key_spki_der,k.trust_preimage,
    i.principal_id,i.idempotency_key,i.expected_aggregate_version::text,i.terminal_state,
    e.custody,e.sink_quorum,e.evidence_role,e.evidence_format
    from control.audit_occurrence a
    join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
    join control.idempotency_record i using(participant_id,privacy_domain_id,operation_id,idempotency_record_id)
    join control.evidence_record e using(participant_id,privacy_domain_id,receipt_id,receipt_digest)
    where a.participant_id=$1 and a.privacy_domain_id=$2 order by a.receipt_id`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.equal(
    rows.length,
    3,
    'two public creates and one update; replay, denial and no-op add no receipts',
  );
  const streams = new Map();
  const attempts = (
    await pool.query(
      `select * from control.receipt_signing_attempt where participant_id=$1 and privacy_domain_id=$2`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.equal(
    attempts.length,
    rows.length,
    'every ordinary attempt commits with one occurrence; failed calls retain none',
  );
  for (const row of rows) {
    const receipt = decodeReceiptStructure(row.receipt_cbor);
    const attemptContext = decodeCbor(row.receipt_cbor);
    attemptContext.set(0, attemptContext.get(8));
    const attemptDigest = createHash('sha256')
      .update('pc.control.receipt-signing-attempt.v1\0')
      .update(encodeCbor(attemptContext))
      .digest();
    const attemptBytes = Buffer.from(receipt.operationId.replaceAll('-', ''), 'hex');
    attemptDigest.copy(attemptBytes, 6, 0, 10);
    attemptBytes[6] = (attemptBytes[6] & 15) | 0x70;
    attemptBytes[8] = (attemptBytes[8] & 63) | 0x80;
    assert.equal(
      attemptBytes.toString('hex'),
      receipt.receiptId.replaceAll('-', ''),
      'provider attempt identity binds the complete normalized receipt context',
    );
    const attempt = attempts.find((a) => a.attempt_id === row.receipt_id);
    assert.ok(attempt, 'committed provider signature has an exact immutable reservation');
    assert.equal(attempt.operation_id, row.operation_id);
    assert.equal(attempt.reservation_kind, 'ORDINARY_ATOMIC');
    assert.equal(attempt.schema_version, 1);
    assert.equal(attempt.signer_id, row.signer_id);
    assert.equal(attempt.key_epoch, '1');
    assert.equal(attempt.selection_version, '1');
    assert.equal(attempt.fence_generation, '1');
    assert.deepEqual(attempt.signer_trust_digest, row.signer_trust_snapshot_digest);
    assert.deepEqual(attempt.profile_digest, row.profile_digest);
    assert.deepEqual(attempt.payload_cbor, row.receipt_cbor);
    assert.deepEqual(attempt.payload_digest, row.receipt_digest);
    assert.ok(BigInt(attempt.reserved_at_ns) >= receipt.recordedAtNs);
    const providerAttempt = JSON.parse(
      await readFile(
        join(secretRoot, '..', 'data', 'signing-provider', 'attempts', row.receipt_id + '.json'),
        'utf8',
      ),
    );
    assert.equal(providerAttempt.request.method, 'SIGN_RECEIPT');
    assert.equal(providerAttempt.request.attemptId, receipt.receiptId);
    assert.equal(providerAttempt.request.operationId, receipt.operationId);
    assert.equal(providerAttempt.request.payloadHex, row.receipt_cbor.toString('hex'));
    assert.equal(providerAttempt.observation.outcome, 'SUCCEEDED');
    assert.equal(providerAttempt.observation.resultHex, row.cose_sign1.toString('hex'));
    assert.equal(providerAttempt.observation.descriptor.fingerprint, receipt.signerId);
    assert.equal(
      providerAttempt.request.callerWorkloadCredentialId,
      '018f0000-0000-7000-8000-000000000195',
    );
    assert.equal(decodeCbor(row.receipt_cbor).size, 27);
    assert.equal(receipt.participantId, participantId);
    assert.equal(receipt.privacyDomainId, privacyDomainId);
    assert.equal(receipt.operationId, row.operation_id);
    assert.equal(receipt.idempotencyRecordId, row.idempotency_record_id);
    assert.equal(receipt.signerId, `sha256:${hash(row.public_key_spki_der).toString('hex')}`);
    assert.deepEqual(hash(row.receipt_cbor), row.receipt_digest);
    assert.deepEqual(hash(row.trust_preimage), receipt.signerTrustSnapshotDigest);
    assert.deepEqual(hash(row.authority_snapshot), receipt.preCommitAuthorityDigest);
    assert.deepEqual(hash(row.before_state_preimage), receipt.before.stateDigest);
    assert.deepEqual(hash(row.after_state_preimage), receipt.after.stateDigest);
    assert.equal(receipt.before.revision, BigInt(row.before_revision));
    assert.equal(receipt.after.revision, receipt.before.revision + 1n);
    assert.equal(receipt.after.revision, BigInt(row.after_revision));
    assert.equal(receipt.before.existence, receipt.before.revision === 0n ? 0 : 1);
    assert.equal(receipt.after.existence, 1);
    assert.notDeepEqual(receipt.before.stateDigest, receipt.after.stateDigest);
    const authority = JSON.parse(row.authority_snapshot.toString('utf8'));
    assert.equal(authority.operationId, row.operation_id);
    assert.equal(authority.decision, 'ALLOW');
    assert.deepEqual(Object.keys(authority.dependencies).sort(), [
      'assignment',
      'authority_envelope',
      'authority_role',
      'credential',
      'delegation',
      'participant',
      'principal',
      'privacy_domain',
      'session',
    ]);
    assert.ok(BigInt(authority.recordedAtNs) <= receipt.recordedAtNs);
    assert.equal(receipt.recordedAtNs % 1000n, 0n);
    assert.equal(row.terminal_state, 'COMMITTED');
    assert.equal(row.custody, 'CONTROL_STORE');
    assert.equal(row.sink_quorum, 0);
    assert.equal(row.evidence_role, 'BUSINESS_TRANSITION_RECEIPT');
    assert.equal(row.evidence_format, 'COSE_SIGN1_24001_1_338');
    // Reconstruct request framing independently from durable normalized inputs.
    const request = createHash('sha256').update('pc.control.configuration-request.v1\0');
    for (const value of [
      participantId,
      privacyDomainId,
      row.principal_id,
      row.action_intent_id,
      row.catalog_operation_id,
      row.aggregate_type,
      row.aggregate_id,
      row.expected_aggregate_version,
      `sha256:${row.candidate_digest.toString('hex')}`,
      row.idempotency_key,
    ]) {
      const bytes = Buffer.from(value),
        length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      request.update(length).update(bytes);
    }
    assert.deepEqual(request.digest(), receipt.requestDigest);
    // Check purpose/header/AAD and ES256 with Node crypto, without the production verifier.
    assert.equal(row.cose_sign1[0], 0xd2);
    const [protectedBytes, unprotected, payload, signature] = decodeCbor(
      row.cose_sign1.subarray(1),
    );
    assert.deepEqual(unprotected, new Map());
    assert.deepEqual(payload, row.receipt_cbor);
    assert.equal(signature.length, 64);
    assert.deepEqual(
      decodeCbor(protectedBytes),
      new Map([
        [1, -7n],
        [2, [100n, 101n, 102n, 103n]],
        [3, 'application/pc+cbor'],
        [4, Buffer.from(receipt.signerId)],
        [100, 24001n],
        [101, 1n],
        [102, 338n],
        [103, 2n],
      ]),
    );
    const structure = encodeCbor([
      'Signature1',
      protectedBytes,
      Buffer.from('7063706c616e653a636f73652d7369676e313a763200', 'hex'),
      payload,
    ]);
    const key = createPublicKey({ key: row.public_key_spki_der, format: 'der', type: 'spki' });
    assert.ok(verify('sha256', structure, { key, dsaEncoding: 'ieee-p1363' }, signature));
    const changed = Buffer.from(structure);
    changed[changed.length - 1] ^= 1;
    assert.equal(verify('sha256', changed, { key, dsaEncoding: 'ieee-p1363' }, signature), false);
    const events = (
      await pool.query(
        `select * from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and receipt_id=$3`,
        [participantId, privacyDomainId, row.receipt_id],
      )
    ).rows;
    assert.equal(events.length, 1);
    const event = events[0],
      reference = receipt.outboxEvents[0];
    assert.equal(event.proof_kind, 'BUSINESS_RECEIPT_REFERENCE');
    assert.equal(event.sequence_namespace, 'CONTROL_BUSINESS_TRANSITION_V1');
    assert.equal(event.aggregate_sequence, null);
    assert.equal(event.cose_sign1, null);
    assert.equal(event.event_id, reference.eventId);
    assert.equal(BigInt(event.business_sequence), reference.aggregateSequence);
    assert.deepEqual(hash(event.payload_cbor), reference.payloadDigest);
    assert.equal(decodeCbor(event.payload_cbor).size, 4);
    assert.equal(event.correlation_id, receipt.operationId);
    const entries = streams.get(row.aggregate_id) ?? [];
    entries.push(reference.aggregateSequence);
    streams.set(row.aggregate_id, entries);
  }
  assert.equal(streams.size, 2);
  for (const [id, sequences] of streams) {
    sequences.sort((a, b) => (a < b ? -1 : 1));
    assert.deepEqual(
      sequences,
      Array.from({ length: sequences.length }, (_, i) => BigInt(i + 1)),
    );
    const head = (
      await pool.query(
        `select last_sequence::text from control.business_outbox_head where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='indexer-profile' and aggregate_id=$3`,
        [participantId, privacyDomainId, id],
      )
    ).rows;
    assert.equal(head.length, 1);
    assert.equal(BigInt(head[0].last_sequence), sequences.at(-1));
  }
  process.stdout.write(
    `OPENPC_SIGNED_RECEIPT_READBACK|PASS|receipts=3|streams=2|${rows.map((row) => row.receipt_digest.toString('hex')).join(',')}\n`,
  );
} finally {
  await pool.end();
}
