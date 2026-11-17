import assert from 'node:assert/strict';
import { createECDH, createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.ts';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
// Match the closed serde structs and tagged enum in pc-runtime-types/target_disposition.rs.
function assertNativeDispositionShape(claims, purpose) {
  const fields = (object, names) => assert.deepEqual(Object.keys(object), names.split(' '));
  const strings = (object, names) => {
    for (const name of names.split(' ')) assert.equal(typeof object[name], 'string');
  };
  const counter = (value) => assert.ok(Number.isSafeInteger(value) && value > 0);
  assert.equal(claims.version, 1);
  fields(
    claims.target,
    'participant_id privacy_domain_id target_id credential_id principal_id credential_epoch principal_epoch certificate_digest',
  );
  strings(
    claims.target,
    'participant_id privacy_domain_id target_id credential_id principal_id certificate_digest',
  );
  counter(claims.target.credential_epoch);
  counter(claims.target.principal_epoch);
  if (purpose === 'openpc:target-disposition-delivery:v1') {
    fields(
      claims,
      'version target source cause action revision previous_revision previous_delivery_digest committed_admission_digest',
    );
    fields(
      claims.source,
      'runtime_configuration_input_id configuration_digest module_installation_id module_configuration_generation_id runtime_configuration_generation_id capsule_digest xds_version_digest predecessor_capsule_digest original_work_id original_operation_id original_execution_attempt_id',
    );
    strings(
      claims.source,
      'runtime_configuration_input_id configuration_digest module_installation_id module_configuration_generation_id runtime_configuration_generation_id capsule_digest xds_version_digest original_work_id original_operation_id original_execution_attempt_id',
    );
    for (const value of [claims.previous_delivery_digest, claims.source.predecessor_capsule_digest])
      assert.ok(value === null || typeof value === 'string');
    assert.equal(typeof claims.committed_admission_digest, 'string');
    assert.ok(['Withdraw', 'Restore', 'ConfirmActivation'].includes(claims.action));
    counter(claims.revision);
    assert.ok(Number.isSafeInteger(claims.previous_revision) && claims.previous_revision >= 0);
    const cause = claims.cause;
    if (cause.kind === 'Activation') {
      fields(cause, 'kind work_id operation_id execution_attempt_id');
      strings(cause, 'work_id operation_id');
      assert.ok(
        cause.execution_attempt_id === null || typeof cause.execution_attempt_id === 'string',
      );
    } else if (cause.kind === 'RuntimeArtifactRetirement') {
      fields(cause, 'kind deletion_job_id operation_id');
      strings(cause, 'deletion_job_id operation_id');
    } else {
      assert.equal(cause.kind, 'Dependency');
      fields(cause, 'kind owner resource_id operation_id revision');
      assert.ok(['Module', 'Policy', 'Source', 'Workload'].includes(cause.owner));
      strings(cause, 'resource_id operation_id');
      counter(cause.revision);
    }
  } else {
    assert.equal(purpose, 'openpc:target-disposition-acknowledgement:v1');
    fields(
      claims,
      'version target delivery_digest disposition_revision journal_sequence installed_state',
    );
    assert.equal(typeof claims.delivery_digest, 'string');
    counter(claims.disposition_revision);
    counter(claims.journal_sequence);
    assert.ok(
      ['NewUseDenied', 'SuspensionCleared', 'ActivationConfirmed'].includes(claims.installed_state),
    );
  }
}
export function verifyDispositionEnvelope(wire, purpose, publicKey) {
  const envelope = JSON.parse(wire.toString('utf8'), (_key, value) => {
    if (typeof value === 'number') assert.ok(Number.isSafeInteger(value));
    return value;
  });
  // Native PurposeSigner hashes serde_json's typed-struct encoding in declaration
  // order. Control's sorted-key canonicalJson is a different admission profile.
  // Preserve the signed wire order and reject lossy/alternate JSON roundtrips.
  assert.deepEqual(Buffer.from(JSON.stringify(envelope)), wire);
  assert.deepEqual(Object.keys(envelope), [
    'purpose',
    'claims',
    'claims_digest',
    'signature_p1363_hex',
  ]);
  assert.equal(envelope.purpose, purpose);
  assertNativeDispositionShape(envelope.claims, purpose);
  assert.equal(envelope.claims_digest, hash(Buffer.from(JSON.stringify(envelope.claims))));
  assert.match(envelope.signature_p1363_hex, /^[0-9a-f]{128}$/u);
  assert.ok(
    verify(
      'sha256',
      Buffer.from(canonicalJson([purpose, envelope.claims_digest])),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(envelope.signature_p1363_hex, 'hex'),
    ),
  );
  return envelope.claims;
}
async function installedPublicKey(secretRoot, name) {
  const raw = Buffer.from((await readFile(join(secretRoot, `${name}.txt`), 'utf8')).trim(), 'hex');
  assert.equal(raw.length, 32);
  try {
    const curve = createECDH('prime256v1');
    curve.setPrivateKey(raw);
    const point = curve.getPublicKey(undefined, 'uncompressed');
    return createPublicKey({
      key: Buffer.concat([
        Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
        point,
      ]),
      format: 'der',
      type: 'spki',
    });
  } finally {
    raw.fill(0);
  }
}

/** Verify every signed link, including withdrawals, before a latest-row or
 * restart assertion can claim custody. This confers no current authority. */
export function verifyTargetDispositionChain({
  rows,
  participantId,
  privacyDomainId,
  targetId,
  controlKey,
  targetKey,
}) {
  assert.ok(rows.length > 0, 'A completed native disposition is required');
  let previous = null;
  const chain = rows.map((r, index) => {
    assert.ok(r.signed_delivery && r.signed_acknowledgement, 'Pending custody cannot pass');
    const delivery = verifyDispositionEnvelope(
      r.signed_delivery,
      'openpc:target-disposition-delivery:v1',
      controlKey,
    );
    const ack = verifyDispositionEnvelope(
      r.signed_acknowledgement,
      'openpc:target-disposition-acknowledgement:v1',
      targetKey,
    );
    assert.deepEqual(delivery, r.claims);
    assert.deepEqual(ack, r.acknowledgement);
    assert.ok(['ConfirmActivation', 'Withdraw', 'Restore'].includes(delivery.action));
    assert.equal(delivery.revision, index + 1);
    assert.equal(delivery.previous_revision, index);
    assert.equal(delivery.previous_delivery_digest, previous?.digest ?? null);
    assert.equal(delivery.target.participant_id, participantId);
    assert.equal(delivery.target.privacy_domain_id, privacyDomainId);
    assert.equal(delivery.target.target_id, targetId);
    if (previous) assert.deepEqual(delivery.target, previous.delivery.target);
    assert.deepEqual(delivery, {
      ...r.binding,
      committed_admission_digest: r.admission_digest.slice(7),
    });
    const proof =
      delivery.action === 'ConfirmActivation'
        ? r.activation_proof
        : delivery.action === 'Restore'
          ? r.restoration_proof
          : null;
    const admitted = proof
      ? {
          binding: r.binding,
          [delivery.action === 'Restore' ? 'restorationProof' : 'activationProof']: proof,
        }
      : r.binding;
    assert.equal(r.admission_digest, `sha256:${hash(Buffer.from(canonicalJson(admitted)))}`);
    assert.equal(r.delivery_digest, `sha256:${hash(r.signed_delivery)}`);
    assert.equal(r.acknowledgement_digest, `sha256:${hash(r.signed_acknowledgement)}`);
    assert.equal(ack.delivery_digest, r.delivery_digest.slice(7));
    assert.equal(ack.disposition_revision, delivery.revision);
    assert.deepEqual(ack.target, delivery.target);
    assert.equal(
      ack.installed_state,
      {
        ConfirmActivation: 'ActivationConfirmed',
        Withdraw: 'NewUseDenied',
        Restore: 'SuspensionCleared',
      }[delivery.action],
    );
    assert.ok(Number.isSafeInteger(ack.journal_sequence) && ack.journal_sequence > 0);
    if (previous) assert.ok(ack.journal_sequence > previous.sequence);
    if (delivery.action === 'Restore') {
      assert.equal(previous?.delivery.action, 'Withdraw');
      assert.deepEqual(delivery.source, previous.delivery.source);
      assert.deepEqual(delivery.cause, previous.delivery.cause);
    }
    if (delivery.action === 'ConfirmActivation') {
      assert.deepEqual(delivery.cause, {
        kind: 'Activation',
        work_id: delivery.source.original_work_id,
        operation_id: delivery.source.original_operation_id,
        execution_attempt_id: delivery.source.original_execution_attempt_id,
      });
      if (previous) {
        assert.equal(previous.delivery.action, 'Withdraw');
        assert.equal(
          delivery.source.predecessor_capsule_digest,
          previous.delivery.source.capsule_digest,
        );
        assert.equal(previous.delivery.cause.kind, 'Activation');
        assert.equal(previous.delivery.cause.work_id, delivery.cause.work_id);
        assert.equal(previous.delivery.cause.operation_id, delivery.cause.operation_id);
        assert.ok(
          previous.delivery.cause.execution_attempt_id === null ||
            previous.delivery.cause.execution_attempt_id === delivery.cause.execution_attempt_id,
        );
      }
    }
    previous = { delivery, digest: r.delivery_digest.slice(7), sequence: ack.journal_sequence };
    return {
      delivery: r.signed_delivery,
      acknowledgement: r.signed_acknowledgement,
      admission: r.admission_digest,
    };
  });
  return { chain, delivery: previous.delivery };
}

/** Verify persisted evidence against the actual Fact reader result. This is
 * historical custody readback; it grants neither freshness nor serving rights. */
export function verifyFactDispositionRows({
  rows,
  participantId,
  privacyDomainId,
  targetId,
  fact,
  controlKey,
  targetKey,
  action = 'ConfirmActivation',
  prior,
}) {
  assert.ok(['ConfirmActivation', 'Restore'].includes(action));
  assert.ok(rows.length > 0, 'A completed native disposition is required');
  assert.equal(fact.participantId, participantId);
  assert.equal(fact.privacyDomainId, privacyDomainId);
  assert.equal(fact.outcome, 'PRESENT');
  const factDigest = Buffer.from(fact.factDigest).toString('hex');
  const shardDigest = Buffer.from(fact.shardDigest).toString('hex');
  for (const digest of [factDigest, shardDigest]) assert.match(digest, /^[0-9a-f]{64}$/u);
  const dependencyDigest = hash(
    Buffer.from(
      canonicalJson([
        'openpc:target-fact-dependencies:v1',
        participantId,
        privacyDomainId,
        fact.generationId,
        shardDigest,
        [
          {
            candidateId: fact.candidateId,
            generationId: fact.generationId,
            factDigest: `sha256:${factDigest}`,
          },
        ],
      ]),
    ),
  );
  const { chain, delivery } = verifyTargetDispositionChain({
    rows,
    participantId,
    privacyDomainId,
    targetId,
    controlKey,
    targetKey,
  });
  const r = rows.at(-1);
  assert.equal(delivery.action, action);
  const proof = action === 'Restore' ? r.restoration_proof : r.activation_proof;
  assert.equal(proof.sourceMode, 'FACT_BOUND');
  const custody = proof.factCustody;
  assert.deepEqual(Object.keys(custody).sort(), [
    'capsuleDigest',
    'dependencyDigest',
    'factStateDigest',
    'originalRecordsDigest',
    'validUntilNs',
    'version',
  ]);
  assert.equal(custody.version, 1);
  assert.equal(custody.capsuleDigest, delivery.source.capsule_digest);
  assert.equal(custody.capsuleDigest, proof.capsuleDigest);
  // This is the semantic digest of the signed authority artifact, not the
  // shard content digest. The native retained-capsule test checks that join.
  assert.match(custody.factStateDigest, /^[0-9a-f]{64}$/u);
  assert.equal(custody.dependencyDigest, dependencyDigest);
  assert.match(custody.originalRecordsDigest, /^[0-9a-f]{64}$/u);
  for (const value of [custody.validUntilNs, proof.capsuleValidUntilNs]) {
    assert.match(value, /^[1-9][0-9]*$/u);
    assert.ok(BigInt(value) <= (1n << 64n) - 1n);
  }
  assert.ok(Number.isSafeInteger(fact.freshUntilMs));
  assert.ok(BigInt(custody.validUntilNs) <= BigInt(fact.freshUntilMs) * 1_000_000n);
  assert.ok(BigInt(custody.validUntilNs) <= BigInt(proof.capsuleValidUntilNs));
  assert.equal(delivery.source.original_work_id, r.work);
  assert.equal(delivery.source.original_operation_id, r.operation);
  assert.equal(delivery.source.original_execution_attempt_id, r.attempt);
  assert.equal(r.work_state, 'COMPLETED');
  assert.ok(r.result_event);
  assert.equal(r.result_receipt_digest, r.activation_receipt_digest);
  assert.equal(r.capsule_digest, `sha256:${custody.capsuleDigest}`);
  assert.equal(
    proof.originalReceiptDigest,
    hash(Buffer.from(r.activation_receipt.activationReceiptCoseHex, 'hex')),
  );
  if (!prior) {
    assert.equal(r.generation_state, 'ACTIVE');
    // Restoration grants currentness to the original capsule; it preserves
    // the failed successor's desired-state outcome rather than rewriting it.
    assert.equal(r.target_state, action === 'Restore' ? 'FAILED' : 'ACTIVE_MATCHED');
    assert.equal(r.active_generation_digest, r.capsule_digest);
  }
  const retained = {
    chain,
    work: r.work,
    operation: r.operation,
    attempt: r.attempt,
    receipt: r.result_receipt_digest,
    event: r.result_event,
    proof,
  };
  if (prior)
    assert.deepEqual(retained, prior, 'Readback must preserve original custody and effects');
  return retained;
}

export async function readFactActivationDisposition({ secretRoot, ...input }) {
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    const { rows } = await pool.query(
      `
      select a.binding,a.activation_proof,a.restoration_proof,a.admission_digest,
      d.claims,d.signed_delivery,d.delivery_digest,k.claims acknowledgement,
      k.signed_acknowledgement,k.acknowledgement_digest,
      w.configuration_work_id::text work,w.operation_id::text operation,
      w.execution_attempt_id::text attempt,w.result_receipt_digest,w.state work_state,
      w.result_event_id::text result_event,o.activation_receipt_digest,o.capsule_digest,
      o.activation_receipt,t.state target_state,t.active_generation_digest,g.state generation_state
      from control.runtime_target_disposition_admission a
      left join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
      left join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
      left join control.configuration_work w on w.participant_id=a.participant_id and w.privacy_domain_id=a.privacy_domain_id
       and w.configuration_work_id=(a.binding->'source'->>'original_work_id')::uuid
      left join control.runtime_activation_observation o on o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id
       and o.configuration_work_id=w.configuration_work_id and o.execution_attempt_id=w.execution_attempt_id and o.operation_id=w.operation_id
      left join control.runtime_target t on t.participant_id=a.participant_id and t.privacy_domain_id=a.privacy_domain_id and t.runtime_target_id=a.runtime_target_id
      left join control.runtime_configuration_generation g on g.participant_id=w.participant_id and g.privacy_domain_id=w.privacy_domain_id
       and g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.runtime_target_id=$3 order by a.revision`,
      [input.participantId, input.privacyDomainId, input.targetId],
    );
    return verifyFactDispositionRows({
      ...input,
      rows,
      controlKey: await installedPublicKey(secretRoot, 'fleet_controller_signing_secret'),
      targetKey: await installedPublicKey(secretRoot, 'runtime_agent_signing_secret'),
    });
  } finally {
    await pool.end();
  }
}

/** Read-only proof after the real public policy activation. No intermediate
 * business state, disposition, ACK or receipt is seeded by this observer. */
// An interrupted successor may have a signed withdrawal without an ACK. Verify
// its immutable predecessor chain and original native signature independently;
// only an actual target ACK completes custody. Neither state grants serving.
// An unsigned authoritative head fences use without installing a delivery or
// acknowledgement. Only this precise observation may change the native journal.
export function assertUnknownWithdrawalJournal(before, after, admission) {
  const { binding, predecessorChain } = admission.immutable;
  const expected = JSON.parse(before.toString());
  const disposition = expected.canonical.target_disposition;
  const predecessor = predecessorChain.at(-1);
  assert.deepEqual(Buffer.from(disposition.installed.signed_delivery), predecessor.delivery);
  assert.deepEqual(
    Buffer.from(disposition.installed.signed_acknowledgement),
    predecessor.acknowledgement,
  );
  assert.deepEqual(disposition.installed.source, binding.source);
  assert.equal(disposition.sequence, binding.previous_revision);
  const head = {
    revision: binding.revision,
    admission_digest: admission.immutable.admission.slice(7),
  };
  assert.deepEqual(
    disposition.observed,
    disposition.observed.revision === binding.revision
      ? head
      : { revision: binding.previous_revision, admission_digest: predecessor.admission.slice(7) },
  );
  disposition.observed = head;
  assert.ok(
    after.equals(Buffer.from(JSON.stringify(expected))),
    'Only the exact committed unsigned head may advance; installed custody and every other journal byte must remain unchanged',
  );
}

// Finite connection/query/server bounds plus actual socket teardown on abort.
// Promise.race alone must not leave an observer holding a database connection.
export const withdrawalObservationBounds = Object.freeze({
  connectionTimeoutMillis: 2000,
  query_timeout: 2000,
  statement_timeout: 2000,
});
export async function withWithdrawalObservationClient(pool, signal, read) {
  signal?.throwIfAborted();
  const client = await pool.connect();
  let released = false;
  const destroy = () => {
    if (!released) {
      released = true;
      client.release(true);
    }
  };
  client.on('error', () => {});
  signal?.addEventListener('abort', destroy, { once: true });
  try {
    signal?.throwIfAborted();
    return await read(client);
  } finally {
    signal?.removeEventListener('abort', destroy);
    destroy();
  }
}

export async function readOriginalWithdrawal({
  secretRoot,
  participantId,
  privacyDomainId,
  targetId,
  operationId,
  requireAcknowledgement = false,
  requireUnsigned = false,
  prior,
  signal,
}) {
  assert.ok(!(requireAcknowledgement && requireUnsigned));
  const pool = new Pool({
    ...withdrawalObservationBounds,
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    return await withWithdrawalObservationClient(pool, signal, async (client) => {
      const result = await client.query(
        `select a.binding,a.activation_proof,a.restoration_proof,a.admission_digest,
      d.claims,d.signed_delivery,d.delivery_digest,k.claims acknowledgement,k.signed_acknowledgement,k.acknowledgement_digest
      from control.runtime_target_disposition_admission a
      left join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
      left join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.runtime_target_id=$3 order by a.revision`,
        [participantId, privacyDomainId, targetId],
      );
      assert.ok(result.rowCount >= 2 && result.rowCount % 2 === 0);
      const rows = result.rows,
        last = rows.at(-1);
      const controlKey = await installedPublicKey(secretRoot, 'fleet_controller_signing_secret');
      const targetKey = await installedPublicKey(secretRoot, 'runtime_agent_signing_secret');
      const previous = verifyTargetDispositionChain({
        rows: rows.slice(0, -1),
        participantId,
        privacyDomainId,
        targetId,
        controlKey,
        targetKey,
      });
      if (requireUnsigned) {
        for (const field of [
          'claims',
          'signed_delivery',
          'delivery_digest',
          'acknowledgement',
          'signed_acknowledgement',
          'acknowledgement_digest',
        ])
          assert.equal(
            last[field],
            null,
            `Unknown committed admission must remain unsigned: ${field}`,
          );
        assert.equal(last.activation_proof, null);
        assert.equal(last.restoration_proof, null);
      }
      const delivery = requireUnsigned
        ? { ...last.binding, committed_admission_digest: last.admission_digest.slice(7) }
        : verifyDispositionEnvelope(
            last.signed_delivery,
            'openpc:target-disposition-delivery:v1',
            controlKey,
          );
      if (!requireUnsigned) assert.deepEqual(delivery, last.claims);
      assert.deepEqual(delivery, {
        ...last.binding,
        committed_admission_digest: last.admission_digest.slice(7),
      });
      assert.equal(
        last.admission_digest,
        `sha256:${hash(Buffer.from(canonicalJson(last.binding)))}`,
      );
      if (!requireUnsigned)
        assert.equal(last.delivery_digest, `sha256:${hash(last.signed_delivery)}`);
      assert.equal(delivery.action, 'Withdraw');
      assert.equal(delivery.revision, result.rowCount);
      assert.equal(delivery.previous_revision, result.rowCount - 1);
      assert.equal(delivery.previous_delivery_digest, rows.at(-2).delivery_digest.slice(7));
      assert.deepEqual(delivery.target, previous.delivery.target);
      assert.deepEqual(delivery.source, previous.delivery.source);
      assert.equal(delivery.cause.kind, 'Activation');
      assert.equal(delivery.cause.operation_id, operationId);
      assert.equal(delivery.cause.execution_attempt_id, null);
      const work = await client.query(
        `select configuration_work_id::text id,state,attempt_count::text attempts,
      execution_started_at,execution_attempt_id,result_receipt_digest,result_event_id::text,
      (select count(*)::int from control.runtime_activation_observation o where o.configuration_work_id=w.configuration_work_id) observations
      from control.configuration_work w where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and runtime_target_id=$4`,
        [participantId, privacyDomainId, operationId, targetId],
      );
      assert.equal(work.rowCount, 1);
      assert.equal(work.rows[0].id, delivery.cause.work_id);
      assert.equal(work.rows[0].execution_started_at, null);
      assert.equal(work.rows[0].execution_attempt_id, null);
      assert.equal(work.rows[0].observations, 0);
      if (requireAcknowledgement || last.signed_acknowledgement)
        verifyTargetDispositionChain({
          rows,
          participantId,
          privacyDomainId,
          targetId,
          controlKey,
          targetKey,
        });
      else assert.equal(last.signed_acknowledgement, null);
      const immutable = {
        predecessorChain: previous.chain,
        admission: last.admission_digest,
        binding: last.binding,
        delivery: last.signed_delivery,
        causeWork: work.rows[0].id,
        operationId,
      };
      if (prior) {
        assert.deepEqual(
          immutable,
          prior.immutable,
          'Original signed withdrawal must never be replaced',
        );
        if (prior.acknowledgement)
          assert.deepEqual(last.signed_acknowledgement, prior.acknowledgement);
      }
      return { immutable, acknowledgement: last.signed_acknowledgement, work: work.rows[0] };
    });
  } finally {
    await pool.end();
  }
}

export async function readInitialActivationDisposition({
  secretRoot,
  participantId,
  privacyDomainId,
  targetId,
  prior,
  renewalOperationId,
  expectedTargetState = 'ACTIVE_MATCHED',
}) {
  assert.ok(['ACTIVE_MATCHED', 'STAGING', 'FAILED'].includes(expectedTargetState));
  if (expectedTargetState !== 'ACTIVE_MATCHED') assert.ok(prior, 'Original custody required');
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    const rows = await pool.query(
      `select a.binding,a.activation_proof,a.admission_digest,d.claims,d.signed_delivery,
      d.delivery_digest,k.claims acknowledgement,k.signed_acknowledgement,k.acknowledgement_digest,
      w.configuration_work_id::text work,w.operation_id::text operation,w.execution_attempt_id::text attempt,
      w.result_receipt_digest,w.state work_state,w.result_event_id::text result_event,
      o.activation_receipt_digest,o.capsule_digest,o.activation_receipt,
      t.state target_state,t.active_generation_digest,g.state generation_state
      from control.runtime_target_disposition_admission a
      left join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
      left join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
      join control.configuration_work w on w.participant_id=a.participant_id and w.privacy_domain_id=a.privacy_domain_id
       and w.configuration_work_id=(a.binding->'source'->>'original_work_id')::uuid
      join control.runtime_activation_observation o on o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id
       and o.configuration_work_id=w.configuration_work_id and o.execution_attempt_id=w.execution_attempt_id and o.operation_id=w.operation_id
      join control.runtime_target t on t.participant_id=a.participant_id and t.privacy_domain_id=a.privacy_domain_id and t.runtime_target_id=a.runtime_target_id
      join control.runtime_configuration_generation g on g.participant_id=w.participant_id and g.privacy_domain_id=w.privacy_domain_id
       and g.runtime_configuration_generation_id=w.runtime_configuration_generation_id
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.runtime_target_id=$3 order by a.revision`,
      [participantId, privacyDomainId, targetId],
    );
    if (renewalOperationId) {
      assert.ok(
        rows.rowCount >= 3 && rows.rowCount % 2 === 1,
        'Complete confirmation/withdrawal/successor chain required',
      );
    } else {
      assert.equal(
        rows.rowCount,
        1,
        'Initial public activation must have one original confirmation',
      );
    }
    const controlKey = await installedPublicKey(secretRoot, 'fleet_controller_signing_secret');
    const targetKey = await installedPublicKey(secretRoot, 'runtime_agent_signing_secret');
    const { chain } = verifyTargetDispositionChain({
      rows: rows.rows,
      participantId,
      privacyDomainId,
      targetId,
      controlKey,
      targetKey,
    });
    const r = rows.rows.at(-1);
    const delivery = verifyDispositionEnvelope(
      r.signed_delivery,
      'openpc:target-disposition-delivery:v1',
      controlKey,
    );
    const ack = verifyDispositionEnvelope(
      r.signed_acknowledgement,
      'openpc:target-disposition-acknowledgement:v1',
      targetKey,
    );
    assert.deepEqual(delivery, r.claims);
    assert.deepEqual(ack, r.acknowledgement);
    assert.equal(delivery.action, 'ConfirmActivation');
    assert.equal(delivery.revision, rows.rowCount);
    assert.equal(delivery.previous_revision, rows.rowCount - 1);
    if (renewalOperationId) {
      assert.equal(r.operation, renewalOperationId);
      assert.equal(delivery.previous_delivery_digest, rows.rows.at(-2).delivery_digest.slice(7));
      assert.equal(
        delivery.source.predecessor_capsule_digest,
        rows.rows.at(-2).claims.source.capsule_digest,
      );
    } else {
      assert.equal(delivery.previous_delivery_digest, null);
      assert.equal(delivery.source.predecessor_capsule_digest, null);
    }
    assert.equal(delivery.source.original_work_id, r.work);
    assert.equal(delivery.source.original_operation_id, r.operation);
    assert.equal(delivery.source.original_execution_attempt_id, r.attempt);
    assert.deepEqual(delivery.cause, {
      kind: 'Activation',
      work_id: r.work,
      operation_id: r.operation,
      execution_attempt_id: r.attempt,
    });
    assert.equal(delivery.target.participant_id, participantId);
    assert.equal(delivery.target.privacy_domain_id, privacyDomainId);
    assert.equal(delivery.target.target_id, targetId);
    assert.equal(r.activation_proof.sourceMode, 'FACT_FREE');
    assert.equal(
      r.admission_digest,
      'sha256:' +
        hash(
          Buffer.from(canonicalJson({ binding: r.binding, activationProof: r.activation_proof })),
        ),
    );
    assert.equal(delivery.committed_admission_digest, r.admission_digest.slice(7));
    assert.equal(r.delivery_digest, 'sha256:' + hash(r.signed_delivery));
    assert.equal(r.acknowledgement_digest, 'sha256:' + hash(r.signed_acknowledgement));
    assert.equal(ack.delivery_digest, r.delivery_digest.slice(7));
    assert.equal(ack.disposition_revision, rows.rowCount);
    assert.equal(ack.installed_state, 'ActivationConfirmed');
    assert.ok(Number.isSafeInteger(ack.journal_sequence) && ack.journal_sequence > 0);
    assert.deepEqual(ack.target, delivery.target);
    assert.equal(r.work_state, 'COMPLETED');
    assert.ok(r.result_event);
    assert.equal(r.generation_state, 'ACTIVE');
    assert.equal(r.target_state, expectedTargetState);
    assert.equal(r.active_generation_digest, r.capsule_digest);
    assert.equal(r.capsule_digest, 'sha256:' + delivery.source.capsule_digest);
    assert.equal(r.result_receipt_digest, r.activation_receipt_digest);
    assert.equal(
      r.activation_proof.originalReceiptDigest,
      hash(Buffer.from(r.activation_receipt.activationReceiptCoseHex, 'hex')),
    );
    const retained = {
      chain,
      expiresAtNs: r.activation_proof.capsuleValidUntilNs,
      delivery: r.signed_delivery,
      acknowledgement: r.signed_acknowledgement,
      work: r.work,
      operation: r.operation,
      attempt: r.attempt,
      receipt: r.result_receipt_digest,
      event: r.result_event,
    };
    if (prior)
      assert.deepEqual(
        retained,
        prior,
        'Restart must preserve original confirmation, ACK and effect',
      );
    process.stdout.write(
      `OPENPC_TARGET_CONFIRMATION|PASS|public-source-activation|native-signatures|durable-ack|complete-chain|${prior ? 'restart-originals' : 'initial-originals'}\n`,
    );
    return retained;
  } finally {
    await pool.end();
  }
}
