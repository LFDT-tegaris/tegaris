import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  assignmentCreate,
  assignmentCreateCandidate,
} from '../../../services/participant-service/src/contracts/assignment.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';

const [mode, secretRoot, evidenceRoot] = process.argv.slice(2);
const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, `${name}.json`), 'utf8'));
const input = await load('policy-set-input');
const actors = await load('deployment-intent-actors');
const discovery = await load('discovery-credential-input');
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
  if (mode === 'input') {
    const scope = {
      privacyDomainIds: [input.privacyDomainId],
      actionIntentIds: ['ACT-RUNTIME_READ_RPC-V1'],
      capabilityIds: [],
      resourceIds: [input.sourceRequest.indexerProfileId],
      riskClasses: ['LOW'],
      makerCheckerRequired: false,
      stepUpRequired: false,
      onwardDelegationDepth: 0,
    };
    const envelopes = await pool.query(
      `select authority_envelope_id::text from control.authority_envelope where participant_id=$1 and principal_id=$2 and state='ACTIVE' and privacy_domain_ids=$3 and action_intent_ids=$4 and runtime_capability_ids='{}'::text[] and maker_checker_required=false and step_up_required=false`,
      [
        input.participantId,
        actors.maker.principalId,
        scope.privacyDomainIds,
        scope.actionIntentIds,
      ],
    );
    assert.equal(envelopes.rowCount, 1);
    const body = JSON.parse(
      JSON.stringify(
        assignmentCreate.parse({
          assignmentId: localOperationId(),
          principalId: discovery.principalId,
          roleId: input.semanticDocument.indexerPolicies[0].rules[0].requiredRoles[0],
          authorityEnvelopeId: envelopes.rows[0].authority_envelope_id,
          scopeDigest: `sha256:${createHash('sha256').update(JSON.stringify(scope)).digest('hex')}`,
          ...scope,
          validFrom: new Date().toISOString(),
          validUntil: new Date(Date.now() + 86400000).toISOString(),
        }),
      ),
    );
    const candidate = assignmentCreateCandidate.parse({
      id: body.assignmentId,
      participantId: input.participantId,
      state: 'ACTIVE',
      delegationEpoch: '0',
      ...body,
    });
    await writeFile(
      join(evidenceRoot, 'source-assignment-input.json'),
      JSON.stringify({ body, candidate }),
      { flag: 'wx', mode: 0o600 },
    );
  } else if (mode === 'readback') {
    const { body } = await load('source-assignment-input');
    const response = await fetch(
      `http://127.0.0.1:8080/v1/participants/${input.participantId}/assignments/${body.assignmentId}`,
      {
        headers: {
          'Authorization': `Bearer ${actors.maker.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
        },
      },
    );
    assert.equal(response.status, 200);
    const readback = await response.json();
    assert.equal(readback.effect.id, body.assignmentId);
    assert.equal(readback.effect.state, 'ACTIVE');
    for (const key of [
      'principalId',
      'roleId',
      'authorityEnvelopeId',
      'actionIntentIds',
      'resourceIds',
      'privacyDomainIds',
    ])
      assert.deepEqual(readback.effect[key], body[key]);
    const rows = await pool.query(
      `select c.state,c.consumed_operation_id::text operation_id,
      (select count(*)::int from control.mutation_evidence e where e.operation_id=c.consumed_operation_id) evidence,
      (select count(*)::int from control.outbox_event e where e.aggregate_id=c.resource_id and e.event_type='openpc.assignment.mutation.committed.v1') outbox
      from control.mutation_candidate c where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3 and c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE'`,
      [input.participantId, input.privacyDomainId, body.assignmentId],
    );
    assert.equal(rows.rows.filter((row) => row.operation_id !== null).length, 1);
    assert.deepEqual(
      rows.rows.filter((row) => row.state === 'CONSUMED'),
      [{ state: 'CONSUMED', operation_id: readback.operationId, evidence: 1, outbox: 1 }],
    );
  } else throw new Error('Unknown first-policy assignment phase');
  process.stdout.write(
    `OPENPC_INITIAL_SOURCE_ASSIGNMENT|PASS|${mode}|exact-source-workload|authoritative-owner\n`,
  );
} finally {
  await pool.end();
}
