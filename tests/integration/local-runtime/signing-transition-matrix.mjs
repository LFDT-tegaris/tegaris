import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client } from 'pg';
import {
  signingTransitionEffects,
  signingTransitionMatrix,
} from '../../../packages/security-kernel/src/signing-transitions.ts';

// Independent acceptance oracle. Neither the generated SQL nor its source projection supplies these states/effects.
const advance = 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1';
const recover = 'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1';
const stages = [
  ['APPROVED', 'PREPARED', [['new', 'PREPARE']], 'prepare'],
  ['PREPARED', 'DISTRIBUTED', [['new', 'DISTRIBUTE']], null],
  [
    'DISTRIBUTED',
    'VERIFIED',
    [
      ['old', 'PROVE'],
      ['new', 'PROVE'],
    ],
    'admitTrust',
  ],
  ['VERIFIED', 'CUTOVER_FENCED', [], 'cutover'],
  ['CUTOVER_FENCED', 'OBSERVING', [['effective', 'PROVE']], null],
  ['OBSERVING', 'OLD_REVOKED', [['old', 'REVOKE']], 'revoke'],
  ['OLD_REVOKED', 'OLD_RETIRED', [['old', 'RETIRE']], null],
  ['OLD_RETIRED', 'COMPLETE', [], null],
];
const none = (kind) => ({
  kind,
  providerSteps: [],
  prepare: false,
  admitTrust: false,
  cutover: false,
  revoke: false,
  eventType: null,
  resumeFrom: null,
});
const expected = new Map();
const add = (action, prior, target, effects) =>
  expected.set(JSON.stringify([action, prior, target]), effects);
for (const [prior, target, providerSteps, flag] of stages) {
  const effects = {
    ...none('ADVANCE'),
    providerSteps,
    eventType:
      target === 'COMPLETE'
        ? 'io.openpc.ops.secret.rotated.v1'
        : target === 'OLD_REVOKED'
          ? 'io.openpc.ops.secret.revoked.v1'
          : null,
  };
  if (flag) effects[flag] = true;
  add(advance, prior, target, effects);
  add(advance, 'RECOVERING', target, { ...effects, resumeFrom: prior });
  add(advance, prior, 'FAILED', none('FAILURE'));
  add(recover, prior, prior, none('RENEWAL'));
  add(recover, prior, 'RECOVERING', none('RECOVERY'));
}
add(advance, 'RECOVERING', 'FAILED', none('FAILURE'));
add(recover, 'RECOVERING', 'RECOVERING', none('RECOVERY'));
add(recover, 'FAILED', 'RECOVERING', none('FORWARD_RECOVERY'));
assert.equal(signingTransitionMatrix.length, expected.size, 'no duplicate or extra allowed tuple');
const states = [
  'REQUESTED',
  ...stages.map(([prior]) => prior),
  'COMPLETE',
  'FAILED',
  'RECOVERING',
  'UNKNOWN',
];
const cases = [];
for (const action of [
  advance,
  recover,
  'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1',
  'ARBITRARY',
])
  for (const prior of states)
    for (const target of states) {
      const effects = expected.get(JSON.stringify([action, prior, target])) ?? null;
      assert.deepEqual(
        signingTransitionEffects(action, prior, target) ?? null,
        effects,
        JSON.stringify([action, prior, target]),
      );
      cases.push({ action, prior, target, effects });
    }
const [host, passwordFile] = process.argv.slice(2);
if (host) {
  const client = new Client({
    host,
    port: 5432,
    database: 'openpc_control',
    user: 'postgres',
    password: (await readFile(passwordFile, 'utf8')).trim(),
  });
  try {
    await client.connect();
    const rows = (
      await client.query(
        `select c.*,openpc.signing_transition_effects(action,prior,target) as actual
      from jsonb_to_recordset($1::jsonb) c(action text,prior text,target text,effects jsonb)`,
        [JSON.stringify(cases)],
      )
    ).rows;
    assert.equal(rows.length, cases.length);
    for (const { action, prior, target, effects, actual } of rows)
      assert.deepEqual(actual, effects, JSON.stringify([action, prior, target]));
  } finally {
    await client.end();
  }
}
process.stdout.write(
  `OPENPC_SIGNING_TRANSITION_MATRIX|PASS|${cases.length}-action-prior-target-cases|advance-provider-and-key-effects|recovery-no-provider-or-selection-effects|substitutions-denied${host ? '|real-postgres-parity' : ''}\n`,
);
