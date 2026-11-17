import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { stageMutationCandidateInTransaction } from '../../../services/identity-service/src/db/mutation-candidate-store.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization.ts';

// Supporting transaction-owner regression; the caller subsequently completes the public checker journey.
const [secretRoot, participantId, privacyDomainId, resourceId, initialActionId] =
  process.argv.slice(2);
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_configuration_runtime',
  password: (
    await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
  ).trim(),
  max: 2,
});
const client = await pool.connect();
const observer = await pool.connect();
const proposalId = localOperationId();
const idempotencyKey = `candidate-transaction-${proposalId}`;
async function scope(connection, sessionId = proposalId, actionIntentId = initialActionId) {
  await connection.query('begin');
  await connection.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [participantId, privacyDomainId, sessionId, actionIntentId],
  );
}
try {
  await scope(client);
  const selected = await client.query(
    `select candidate.*, 'sha256:'||encode(intent.semantic_digest,'hex') action_digest
    from control.mutation_candidate candidate join control.action_intent intent using(action_intent_id)
    where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3 and candidate.state='PROPOSED'`,
    [participantId, privacyDomainId, resourceId],
  );
  assert.equal(selected.rowCount, 1);
  const row = selected.rows[0];
  await client.query('rollback');
  await scope(client, row.maker_session_id, row.action_intent_id);
  const candidate = {
    ...row.candidate_document,
    reason: `Rollback boundary regression ${proposalId}`,
  };
  const context = {
    authorization: {
      participantId,
      privacyDomainId,
      principalId: row.maker_principal_id,
      sessionId: row.maker_session_id,
      sessionEpoch: String(row.maker_session_epoch),
      participantEpoch: String(row.maker_participant_epoch),
      principalEpoch: String(row.maker_principal_epoch),
      assignmentId: row.maker_assignment_id,
      assignmentRowVersion: String(row.maker_assignment_row_version),
      authorityEnvelopeId: row.maker_authority_envelope_id,
      authorityEpoch: String(row.maker_authority_epoch),
      delegationEpoch: String(row.maker_delegation_epoch),
    },
    participantId,
    privacyDomainId,
    actionIntentId: row.action_intent_id,
    actionIntentDigest: row.action_digest,
    catalogOperationId: row.catalog_operation_id,
    resourceType: row.resource_type,
    operationClass: row.operation_class,
    resourceId: proposalId,
    serverGeneratedResourceId: true,
    expectedRevision: String(row.expected_revision),
    idempotencyKey,
    candidateDigest: canonicalAuthorizationDigest(candidate),
    candidate,
  };
  assert.equal(await stageMutationCandidateInTransaction(client, context), proposalId);
  const count = async (connection) =>
    (
      await connection.query(
        `select count(*)::int n from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and idempotency_key=$3`,
        [participantId, privacyDomainId, idempotencyKey],
      )
    ).rows[0].n;
  assert.equal(await count(client), 1);
  await scope(observer, row.maker_session_id, row.action_intent_id);
  assert.equal(await count(observer), 0, 'staging must not commit the outer business transaction');
  await client.query('rollback');
  assert.equal(await count(observer), 0, 'an outer failure must remove the exact candidate');
  await observer.query('rollback');
  await scope(client, row.maker_session_id, row.action_intent_id);
  await assert.rejects(
    stageMutationCandidateInTransaction(client, context, {
      principal: [{ id: localOperationId() }],
    }),
    /authority dependency is unavailable/,
  );
  await client.query('rollback');
  const sharedKey = `candidate-race-${proposalId}`;
  const sharedCandidate = { ...candidate, reason: `Concurrent proposal ${proposalId}` };
  const shared = {
    ...context,
    idempotencyKey: sharedKey,
    candidate: sharedCandidate,
    candidateDigest: canonicalAuthorizationDigest(sharedCandidate),
  };
  const stageAndCommit = async (connection, resourceId) => {
    await scope(connection, row.maker_session_id, row.action_intent_id);
    const selected = await stageMutationCandidateInTransaction(connection, {
      ...shared,
      resourceId,
    });
    await connection.query('commit');
    return selected;
  };
  const resources = await Promise.all([
    stageAndCommit(client, localOperationId()),
    stageAndCommit(observer, localOperationId()),
  ]);
  assert.equal(
    resources[0],
    resources[1],
    'both unique indexes must coalesce the identical proposal',
  );
  await scope(client, row.maker_session_id, row.action_intent_id);
  await assert.rejects(
    stageMutationCandidateInTransaction(client, {
      ...shared,
      idempotencyKey: `different-key-${proposalId}`,
    }),
    /PC-DATA-6007/,
    'same digest cannot be rebound to another proposal key',
  );
  await client.query('rollback');
  await scope(client, row.maker_session_id, row.action_intent_id);
  const changed = { ...sharedCandidate, reason: 'Changed after staging' };
  await assert.rejects(
    stageMutationCandidateInTransaction(client, {
      ...shared,
      candidate: changed,
      candidateDigest: canonicalAuthorizationDigest(changed),
    }),
    /PC-DATA-6007/,
    'same proposal key cannot acquire another candidate',
  );
  await client.query('rollback');
  process.stdout.write(
    'OPENPC_MUTATION_CANDIDATE_TRANSACTION|PASS|outer-rollback|authority-fence|concurrent-unique-indexes|rebind-denied\n',
  );
} finally {
  await Promise.allSettled([client.query('rollback'), observer.query('rollback')]);
  client.release();
  observer.release();
  await pool.end();
}
