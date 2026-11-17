import assert from 'node:assert/strict';
import { moduleReleaseSelection } from './module-release-selection.mjs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  decodeCbor,
  encodeCbor,
} from '../../../packages/security-kernel/src/business-transition/cbor.ts';
import { decodeReceiptStructure } from '../../../packages/security-kernel/src/business-transition/payload.ts';

const [secretRoot, participantId, privacyDomainId, evidenceRoot, phase, catalogPath] =
  process.argv.slice(2);
if (phase?.startsWith('collection-')) {
  const {
    assertPublicModuleListEmpty,
    capturePublicModuleListPhase,
    assertPublicModuleListChanged,
    assertPublicModuleListRestart,
  } = await import('../policy/public-module-list-cases.ts');
  const actors = ['OPERATOR', 'CHECKER', 'DENIED'].map((role) => {
    const sessionToken = process.env[`OPENPC_MODULE_LIST_${role}`];
    assert.ok(sessionToken);
    return { sessionToken, participantId, privacyDomainId };
  });
  const fixture = {
    apiUrl: 'http://127.0.0.1:8080',
    reader: actors[0],
    secondReader: actors[1],
    deniedReader: actors[2],
    foreignParticipantId: '018f0000-0000-7000-8000-000000000102',
    foreignPrivacyDomainId: '018f0000-0000-7000-8000-000000000202',
  };
  const checkpointPath = (state) => join(evidenceRoot, `module-collection-${state}.json`);
  const load = async (state) => JSON.parse(await readFile(checkpointPath(state), 'utf8'));
  const state = phase.slice('collection-'.length);
  if (state === 'empty') await assertPublicModuleListEmpty(fixture);
  else if (state === 'restart-registered' || state === 'restart-active')
    await assertPublicModuleListRestart(fixture, await load(state.slice('restart-'.length)));
  else {
    assert.ok(['registered', 'installed', 'active'].includes(state));
    if (state !== 'registered')
      await assertPublicModuleListChanged(
        fixture,
        await load(state === 'installed' ? 'registered' : 'installed'),
      );
    const indices = await moduleReleaseSelection(catalogPath);
    const refs = await Promise.all(
      indices.map(
        async (index) =>
          JSON.parse(await readFile(join(evidenceRoot, `module-admission-${index}.json`), 'utf8'))
            .resourceRef,
      ),
    );
    const checkpoint = await capturePublicModuleListPhase(fixture, refs, state.toUpperCase());
    await writeFile(checkpointPath(state), JSON.stringify(checkpoint), { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(`OPENPC_MODULE_COLLECTION|PASS|phase=${state}|authority=public\n`);
  process.exit(0);
}
const enabled = phase === 'enabled';
assert.ok(phase === undefined || phase === 'admitted' || enabled);
const indices = catalogPath
  ? await moduleReleaseSelection(catalogPath)
  : Array.from({ length: 25 }, (_, index) => index);
const catalog = catalogPath ? JSON.parse(await readFile(catalogPath, 'utf8')) : undefined;
const deploymentSelected = catalogPath
  ? (
      await Promise.all(
        indices.map(async (index) => {
          const manifest = JSON.parse(
            await readFile(join(catalogPath, '..', catalog.releases[index].manifestBytes), 'utf8'),
          );
          return manifest.metadata.id;
        }),
      )
    ).includes('pc.policy.deployment')
  : true;
const catalogOperation = enabled ? 'MOD-OP-ENABLE' : 'MOD-OP-REGISTER';
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const hash = (bytes) => createHash('sha256').update(bytes).digest();
function verifyReceiptSignature(row, receipt) {
  assert.equal(row.cose_sign1[0], 0xd2);
  const [protectedBytes, unprotected, payload, signature] = decodeCbor(row.cose_sign1.subarray(1));
  assert.deepEqual(unprotected, new Map());
  assert.deepEqual(payload, row.receipt_cbor);
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
}
try {
  // The first consumer uses its actual least-privilege role and scope after restart.
  await pool.query('begin');
  try {
    await pool.query('set local role openpc_control_worker');
    await pool.query(
      "select openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,uuidv7(),'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true),openpc.assert_request_context(true)",
      [participantId, privacyDomainId],
    );
    const { digest, foreignParticipant, foreignPrivacy } = (
      await pool.query(
        `select openpc.deployment_module_generation($1::uuid,$2::uuid) digest,
          openpc.deployment_module_generation('018f0000-0000-7000-8000-000000000102',$2::uuid) as "foreignParticipant",
          openpc.deployment_module_generation($1::uuid,'018f0000-0000-7000-8000-000000000202') as "foreignPrivacy"`,
        [participantId, privacyDomainId],
      )
    ).rows[0];
    if (enabled && deploymentSelected) assert.ok(Buffer.isBuffer(digest) && digest.length === 32);
    else
      assert.equal(
        digest,
        null,
        'absent or unenabled deployment module cannot authorize its consumer',
      );
    assert.equal(foreignParticipant, null);
    assert.equal(foreignPrivacy, null);
  } finally {
    await pool.query('rollback');
  }
  const rows = (
    await pool.query(
      `select a.*,k.public_key_spki_der,k.trust_preimage,
    i.result_payload,i.terminal_state,e.evidence_format,e.custody
    from control.audit_occurrence a
    join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
    join control.idempotency_record i using(participant_id,privacy_domain_id,operation_id,idempotency_record_id)
    join control.evidence_record e using(participant_id,privacy_domain_id,receipt_id,receipt_digest)
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.catalog_operation_id=$3`,
      [participantId, privacyDomainId, catalogOperation],
    )
  ).rows;
  assert.equal(rows.length, indices.length, 'denial and replay must not add business receipts');
  for (const index of indices) {
    const operation = JSON.parse(
      await readFile(
        join(
          evidenceRoot,
          enabled ? `module-activate-${index}-main.json` : `module-admission-${index}.json`,
        ),
        'utf8',
      ),
    );
    const module = JSON.parse(
      await readFile(
        join(
          evidenceRoot,
          enabled ? `module-activate-${index}-main-read.json` : `module-read-${index}.json`,
        ),
        'utf8',
      ),
    );
    const row = rows.find(
      (r) => r.operation_id === operation.operationId.replace('urn:openpc:operation:', ''),
    );
    assert.ok(row, 'every returned operation has its own committed receipt');
    assert.deepEqual(row.result_payload, operation);
    assert.equal(row.terminal_state, 'COMMITTED');
    assert.equal(row.evidence_format, 'COSE_SIGN1_24001_1_338');
    assert.equal(row.custody, 'CONTROL_STORE');
    const receipt = decodeReceiptStructure(row.receipt_cbor);
    assert.equal(
      receipt.transitionProfileId,
      enabled ? 'pc.control.module.enable' : 'pc.control.module.register',
    );
    assert.equal(receipt.catalogOperationId, catalogOperation);
    assert.equal(receipt.participantId, participantId);
    assert.equal(receipt.privacyDomainId, privacyDomainId);
    assert.equal(receipt.aggregateId, module.moduleId.split(':').at(-1));
    assert.equal(receipt.before.existence, enabled ? 1 : 0);
    assert.equal(receipt.before.revision, enabled ? 2n : 0n);
    assert.equal(receipt.after.existence, 1);
    assert.equal(receipt.after.revision, enabled ? 3n : 1n);
    assert.deepEqual(hash(row.receipt_cbor), row.receipt_digest);
    assert.deepEqual(hash(row.trust_preimage), receipt.signerTrustSnapshotDigest);
    assert.deepEqual(hash(row.authority_snapshot), receipt.preCommitAuthorityDigest);
    assert.deepEqual(hash(row.before_state_preimage), receipt.before.stateDigest);
    assert.deepEqual(hash(row.after_state_preimage), receipt.after.stateDigest);
    const projection = decodeCbor(row.after_state_preimage)[8];
    const durable = (
      await pool.query(
        `select v.module_id,v.semantic_version,v.manifest_digest,
      m.admission_dependency_digest,c.configuration_digest,m.state,m.active_manifest_digest,c.generation,c.active,m.lifecycle_evaluation_digest
      from control.module_installation m join control.module_version v using(module_version_id)
      join control.module_configuration_generation c using(module_installation_id)
      where m.module_installation_id=$1 and m.participant_id=$2 and m.privacy_domain_id=$3`,
        [receipt.aggregateId, participantId, privacyDomainId],
      )
    ).rows[0];
    assert.equal(durable.state, enabled ? 'ENABLED' : 'ADMITTED');
    assert.deepEqual(durable.active_manifest_digest, enabled ? durable.manifest_digest : null);
    assert.equal(durable.generation, '1');
    assert.equal(durable.active, enabled);
    assert.deepEqual(
      projection,
      new Map([
        [0, durable.module_id],
        [1, durable.semantic_version],
        [2, durable.manifest_digest],
        [3, durable.admission_dependency_digest],
        [4, durable.configuration_digest],
        [5, enabled ? 'ENABLED' : 'ADMITTED'],
        [6, enabled ? 1n : 0n],
        [7, 1n],
        [8, enabled ? 1n : 0n],
        ...(enabled
          ? [
              [9, durable.lifecycle_evaluation_digest],
              [10, durable.manifest_digest],
            ]
          : []),
      ]),
    );
    verifyReceiptSignature(row, receipt);
    if (enabled) {
      const prior = (
        await pool.query(
          `select a.*,k.public_key_spki_der from control.audit_occurrence a
        join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_id=$3
          and a.catalog_operation_id='MOD-OP-INSTALL'`,
          [participantId, privacyDomainId, receipt.aggregateId],
        )
      ).rows;
      assert.equal(prior.length, 1);
      const install = decodeReceiptStructure(prior[0].receipt_cbor);
      assert.equal(install.transitionProfileId, 'pc.control.module.install');
      assert.equal(install.before.revision, 1n);
      assert.equal(install.after.revision, 2n);
      verifyReceiptSignature(prior[0], install);
      assert.deepEqual(hash(prior[0].receipt_cbor), prior[0].receipt_digest);
      assert.deepEqual(hash(prior[0].after_state_preimage), install.after.stateDigest);
      const installed = decodeCbor(prior[0].after_state_preimage)[8];
      assert.equal(installed.get(5), 'INSTALLED_DISABLED');
      assert.equal(installed.get(6), 0n);
      assert.equal(installed.get(8), 0n);
      assert.deepEqual(installed, decodeCbor(row.before_state_preimage)[8]);
      const simulations = (
        await pool.query(
          `select revision,input_cbor,result_cbor,result_digest from control.module_lifecycle_evaluation
        where participant_id=$1 and privacy_domain_id=$2 and module_installation_id=$3 order by revision`,
          [participantId, privacyDomainId, receipt.aggregateId],
        )
      ).rows;
      assert.deepEqual(
        simulations.map((v) => v.revision),
        ['2', '3'],
      );
      for (const [ordinal, simulation] of simulations.entries()) {
        assert.ok(simulation.input_cbor.length > 0);
        assert.deepEqual(hash(simulation.result_cbor), simulation.result_digest);
        assert.deepEqual((ordinal === 0 ? installed : projection).get(9), simulation.result_digest);
      }
    }
    const events = (
      await pool.query('select * from control.outbox_event where receipt_id=$1', [
        receipt.receiptId,
      ])
    ).rows;
    assert.equal(events.length, 1);
    const event = events[0];
    assert.equal(event.proof_kind, 'BUSINESS_RECEIPT_REFERENCE');
    assert.equal(event.cose_sign1, null);
    assert.equal(event.event_type, 'io.openpc.control.command.committed.v1');
    assert.equal(event.business_sequence, enabled ? '3' : '1');
    assert.equal(event.sequence_namespace, 'CONTROL_BUSINESS_TRANSITION_V1');
    assert.deepEqual(hash(event.payload_cbor), receipt.outboxEvents[0].payloadDigest);
    assert.equal(decodeCbor(event.payload_cbor).size, 4);
    const authorization = (
      await pool.query('select * from control.mutation_evidence where operation_id=$1', [
        receipt.operationId,
      ])
    ).rows;
    assert.equal(authorization.length, 1);
    assert.deepEqual(
      receipt.authorizationEvidence.map((e) => e.kind),
      [3, 4],
    );
    assert.deepEqual(
      authorization[0].evidence_digest,
      receipt.authorizationEvidence[0].evidenceDigest,
    );
    const approval = (
      await pool.query(
        'select * from control.approval_decision_record where approval_decision_id=$1 and participant_id=$2 and privacy_domain_id=$3',
        [receipt.authorizationEvidence[0].evidenceId, participantId, privacyDomainId],
      )
    ).rows[0];
    assert.ok(approval);
    assert.equal(approval.approval_request_id, authorization[0].approval_request_id);
    assert.equal(approval.approver_principal_id, authorization[0].checker_principal_id);
    assert.notEqual(approval.approver_principal_id, authorization[0].principal_id);
    assert.equal(approval.decision, 'APPROVE');
    assert.deepEqual(approval.evidence_cbor, authorization[0].evidence_cbor);
    assert.deepEqual(hash(approval.evidence_cbor), receipt.authorizationEvidence[0].evidenceDigest);
    // The decision request digest and signed credential evidence digest have distinct preimages.
    assert.deepEqual(
      approval.decision_digest,
      hash(
        Buffer.from(
          JSON.stringify({
            actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
            approvalRequestId: `urn:openpc:resource:${approval.approval_request_id}`,
            candidateDigest: `sha256:${receipt.candidateDigest.toString('hex')}`,
            decision: 'APPROVE',
            expectedRevision: '1',
          }),
        ),
      ),
    );
    const verification = (
      await pool.query(
        `select v.*,c.used_operation_id from control.mutation_evidence v
         join control.mfa_challenge c using(participant_id,mfa_challenge_id)
         where v.mutation_evidence_id=$1 and v.participant_id=$2 and v.privacy_domain_id=$3`,
        [receipt.authorizationEvidence[1].evidenceId, participantId, privacyDomainId],
      )
    ).rows[0];
    assert.ok(verification);
    assert.equal(verification.catalog_operation_id, 'ID-OP-WEBAUTHN-VERIFY');
    assert.equal(verification.principal_id, authorization[0].principal_id);
    assert.equal(verification.used_operation_id, receipt.operationId);
    assert.deepEqual(
      hash(verification.evidence_cbor),
      receipt.authorizationEvidence[1].evidenceDigest,
    );
    const attempt = (
      await pool.query('select * from control.receipt_signing_attempt where attempt_id=$1', [
        receipt.receiptId,
      ])
    ).rows;
    assert.equal(attempt.length, 1);
    assert.deepEqual(attempt[0].payload_cbor, row.receipt_cbor);
    // Exercise the database's module owner against retained real journey state.
    // These are read-only function calls, so each forged receipt must fail at its binding.
    const checkAdmission = (patch) =>
      pool.query(
        `select openpc.check_module_admission_receipt(jsonb_populate_record(a,$2::jsonb))
       from control.audit_occurrence a where receipt_id=$1`,
        [receipt.receiptId, JSON.stringify(patch)],
      );
    await checkAdmission({});
    if (index === 0) {
      const forgedReferences = decodeCbor(row.receipt_cbor);
      forgedReferences.set(20, [
        new Map([
          [0, 2n],
          [1, authorization[0].mutation_evidence_id],
          [2, authorization[0].evidence_digest],
        ]),
        ...forgedReferences.get(20).slice(1),
      ]);
      for (const patch of [
        { after_revision: '2' },
        { actor_key_digest: `\\x${'00'.repeat(32)}` },
        { candidate_digest: `\\x${'00'.repeat(32)}` },
        { receipt_cbor: `\\x${encodeCbor(forgedReferences).toString('hex')}` },
      ]) {
        await assert.rejects(
          checkAdmission(patch),
          (error) => error.code === 'P0001' || error.code === 'P0002',
        );
      }
    }
  }
  for (const table of ['idempotency_record', 'mutation_evidence']) {
    const count = (
      await pool.query(
        `select count(*)::int as count from control.${table} where participant_id=$1 and privacy_domain_id=$2 and catalog_operation_id=$3`,
        [participantId, privacyDomainId, catalogOperation],
      )
    ).rows[0].count;
    assert.equal(count, indices.length, `${table}: rejected registration leaves no effects`);
  }
  process.stdout.write(
    `phase=${enabled ? 'enabled' : 'admitted'}|` +
      `OPENPC_MODULE_RECEIPTS|PASS|receipts=${indices.length}|signatures=verified|state=durable|outbox=atomic|denial=no_effect|replay=unique\n`,
  );
} finally {
  await pool.end();
}
