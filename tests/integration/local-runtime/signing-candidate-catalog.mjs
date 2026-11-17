import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client } from 'pg';
import {
  signingRotationCandidateOperations,
  signingRotationCandidateOperation,
} from '../../../packages/security-kernel/src/signing-operations.ts';
import { participantMutationOperations } from '../../../packages/security-kernel/src/participant-mutation-operations.ts';
import {
  signingCandidateStagingSql,
  signingCandidateApprovalSql,
} from '../../../services/identity-service/src/db/signing-candidate-catalog.ts';

// Specification oracle is deliberately independent of the projection that emits the database and query predicates.
const expected = [
  [
    'OPS-OP-CREATE-SIGNING-KEY-ROTATION',
    'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1',
    'signing-key-rotation',
    'CREATE',
  ],
  [
    'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
    'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
    'signing-key-rotation',
    'UPDATE',
  ],
  [
    'OPS-OP-RECOVER-SIGNING-KEY-ROTATION',
    'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1',
    'signing-key-rotation',
    'RECOVER',
  ],
];
const expectedParticipants = participantMutationOperations.map((operation) => [
  operation.catalogOperationId,
  operation.actionIntentId,
  operation.resourceType,
  operation.operationClass,
]);
const expectedHandover = [
  [
    'ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT',
    'ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1',
    'workload-signing-handover',
    'ACTIVATE',
  ],
];
const expectedModules = [
  ['MOD-OP-REGISTER', 'ACT-MODULES_CREATE_RESOURCE-V1', 'modules', 'CREATE'],
  ['MOD-OP-INSTALL', 'ACT-MODULE_CREATE_INSTALL-V1', 'module', 'CREATE'],
  ['MOD-OP-ENABLE', 'ACT-MODULE_ACTIVATE_RESOURCE-V1', 'module', 'ACTIVATE'],
];
assert.deepEqual(
  signingRotationCandidateOperations.map((o) => [
    o.catalogOperationId,
    o.actionIntentId,
    o.resourceType,
    o.operationClass,
  ]),
  expected,
);
for (const tuple of expected)
  assert.equal(signingRotationCandidateOperation(tuple[1]).catalogOperationId, tuple[0]);
assert.throws(() =>
  signingRotationCandidateOperation('ACT-SIGNING_KEY_ROTATIONS_READ_RESOURCE-V1'),
);
// Verify that the two real owners embed the shared generated predicate, rather than merely testing an unused helper.
assert.match(
  await readFile(
    new URL(
      '../../../services/identity-service/src/db/mutation-candidate-store.ts',
      import.meta.url,
    ),
    'utf8',
  ),
  /and \$\{signingCandidateStagingSql\}/,
);
assert.match(
  await readFile(
    new URL('../../../services/module-registry/src/db/public-approval-store.ts', import.meta.url),
    'utf8',
  ),
  /and \$\{signingCandidateApprovalSql\}/,
);
const [host, passwordFile, portText] = process.argv.slice(2);
const port = portText === undefined ? 5432 : Number(portText);
assert.ok(
  Number.isInteger(port) && port >= 1 && port <= 65535,
  'A valid PostgreSQL port is required',
);
const client = new Client({
  host,
  port,
  database: 'openpc_control',
  user: 'postgres',
  password: (await readFile(passwordFile, 'utf8')).trim(),
});
try {
  await client.connect();
  const definition = (
    await client.query(
      "select pg_get_constraintdef(oid) as definition from pg_constraint where conrelid='control.mutation_candidate'::regclass and conname='mutation_candidate_catalog_operation_ck'",
    )
  ).rows[0].definition;
  const expression = /^CHECK \((.*)\)$/s.exec(definition)?.[1];
  assert.ok(expression);
  const cases = new Map();
  const add = (tuple, allowed) => cases.set(JSON.stringify(tuple), { tuple, allowed });
  const sealed = [...expected, ...expectedHandover, ...expectedParticipants, ...expectedModules];
  for (const catalog of sealed.map((r) => r[0]))
    for (const action of sealed.map((r) => r[1]))
      for (const kind of [
        'signing-key-rotation',
        'workload-signing-handover',
        'participant',
        'principal',
        'provider-profile',
        'module',
        'modules',
      ])
        for (const operation of ['CREATE', 'UPDATE', 'RECOVER', 'READ', 'ACTIVATE']) {
          const tuple = [catalog, action, kind, operation];
          add(
            tuple,
            sealed.some((row) => JSON.stringify(row) === JSON.stringify(tuple)),
          );
        }
  for (const tuple of [...expected, ...expectedHandover]) {
    for (let index = 0; index < 4; index++) {
      const missing = [...tuple];
      missing[index] = '';
      add(missing, false);
    }
    add(['OPS-OP-ARBITRARY', ...tuple.slice(1)], false);
    add(['CFG-OP-CREATE-PROVIDER-PROFILE', ...tuple.slice(1)], false);
  }
  for (const tuple of expectedParticipants) {
    for (let index = 0; index < 4; index++) {
      const missing = [...tuple];
      missing[index] = '';
      add(missing, false);
    }
  }
  // Initial module lifecycle must cross all persisted receipt owners, not only candidate staging.
  for (const [table, constraint] of [
    ['business_transition_profile', 'business_profile_catalog_ck'],
    ['idempotency_record', 'idempotency_catalog_operation_ck'],
    ['mutation_evidence', 'mutation_evidence_catalog_operation_ck'],
  ]) {
    const stored = (
      await client.query(
        'select pg_get_constraintdef(oid) as definition from pg_constraint where conrelid=$1::regclass and conname=$2',
        [`control.${table}`, constraint],
      )
    ).rows[0].definition;
    const predicate = /^CHECK \((.*)\)$/s.exec(stored)?.[1];
    assert.ok(predicate);
    for (const operation of [...expectedModules.map((tuple) => tuple[0]), 'MOD-OP-UNINSTALL']) {
      const result = (
        await client.query(
          `select (${predicate}) as allowed from (values($1::text)) candidate(catalog_operation_id)`,
          [operation],
        )
      ).rows[0].allowed;
      assert.equal(result, operation !== 'MOD-OP-UNINSTALL', `${constraint}: ${operation}`);
    }
  }
  add(
    [
      'CFG-OP-CREATE-PROVIDER-PROFILE',
      'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
      'provider-profile',
      'CREATE',
    ],
    true,
  );
  for (const { tuple, allowed } of cases.values()) {
    const values = Array(18).fill('');
    values[17] = tuple[0];
    values[5] = tuple[1];
    values[14] = tuple[2];
    values[15] = tuple[3];
    const row = (
      await client.query(
        `select (${signingCandidateStagingSql}) as staging,(${signingCandidateApprovalSql}) as approval,(${expression}) as stored
      from (values($18::text,$6::text,$15::text,$16::text)) candidate(catalog_operation_id,action_intent_id,resource_type,operation_class)
      cross join (select ${values.map((_, i) => `$${i + 1}::text as parameter_${i + 1}`).join(',')}) typed_parameters`,
        values,
      )
    ).rows[0];
    assert.deepEqual(
      row,
      { staging: allowed, approval: allowed, stored: allowed },
      JSON.stringify(tuple),
    );
  }
  process.stdout.write(
    `OPENPC_SIGNING_CANDIDATE_CATALOG|PASS|exact-participant-and-signing-operations|staging-approval-constraint-parity|${cases.size}-tuple-cases|missing-extra-mismatch-denied\n`,
  );
} finally {
  await client.end();
}
