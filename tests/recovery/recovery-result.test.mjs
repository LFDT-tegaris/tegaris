import assert from 'node:assert/strict';
import test from 'node:test';
import {
  validateRecoveryResult,
  validateRecovery,
  recoveryResult,
  migrationResult,
  postgresResult,
  valkeyResult,
} from './recovery-result.mjs';

const clone = (value) => structuredClone(value);

const i09 = {
  schemaVersion: '2.0',
  status: 'PASS',
  profileId: 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2',
  profileRegistrySha256: '1'.repeat(64),
  databases: [
    ['openpc_control', 35, 605, 98, 28],
    ['openpc_facts', 10, 139, 13, 10],
    ['openpc_candidate_index', 20, 378, 71, 18],
  ].map(([database, tables, constraints, indexes, forcedRlsTables]) => ({
    database,
    dumpSha256: '2'.repeat(64),
    schemaSha256: '3'.repeat(64),
    tables,
    constraints,
    indexes,
    forcedRlsTables,
  })),
  stores: [
    'STORE-CONTROL-PG',
    'STORE-FACT-PG',
    'STORE-CANDIDATE-INDEX-PG',
    'STORE-OCI',
    'STORE-LOCAL-ARTIFACT',
    'STORE-LOCAL-EVIDENCE',
    'STORE-EVIDENCE-VAULT',
    'STORE-VALKEY-OPTIONAL',
  ],
  ociObjectSha256: '4'.repeat(64),
  evidenceCheckpointSha256: '5'.repeat(64),
  oldWriterExcluded: true,
  valkey: {
    empty: true,
    tls: true,
    authenticated: true,
    persistence: false,
    maxmemoryPolicy: 'allkeys-lfu',
  },
  cleanup: 'PASS_ZERO_CONTAINER_AND_VOLUME_RESIDUE',
  claimCeiling:
    'LOCAL_SYNTHETIC_ISOLATED_RECOVERY_TECHNICAL_PROOF_ONLY; PROVIDER_SIGNED_PRODUCTION_LIVE_MIGRATION_ACTIVATION_PROMOTION_EXTERNAL_ACCEPTANCE_NOT_PROVEN_OPEN',
};
test('recovery admission rejects status-only substitution and isolated mutations', () => {
  validateRecoveryResult(i09);
  assert.throws(
    () =>
      validateRecoveryResult({
        status: 'PASS',
        cleanup: 'PASS_ZERO_CONTAINER_AND_VOLUME_RESIDUE',
        databases: [{}, {}, {}],
      }),
    /UNKNOWN_OR_OMITTED_REJECTED/u,
  );
  for (const mutate of [
    (x) => {
      x.stores[0] = 'WRONG';
    },
    (x) => {
      x.databases.reverse();
    },
    (x) => {
      x.databases[0].dumpSha256 = '0';
    },
    (x) => {
      x.databases[1].forcedRlsTables = 0;
    },
    (x) => {
      x.oldWriterExcluded = false;
    },
    (x) => {
      x.cleanup = 'PASS';
    },
  ]) {
    const value = clone(i09);
    mutate(value);
    assert.throws(() => validateRecoveryResult(value));
  }
});

test('current recovery row, consumer and release admission reject legacy cache results and unsafe overrides', () => {
  const row = { surfaceId: 'DATA_VALKEY', consumer: 'valkey-result' };
  const fact = validateRecovery(row, { recovery: i09 });
  assert.deepEqual(valkeyResult(row, fact), {
    authoritative: false,
    empty: true,
    tls: true,
  });
  for (const mutate of [
    (value) => {
      value.profileId = 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V1';
    },
    (value) => {
      value.valkey.maxmemoryPolicy = 'noeviction';
    },
    (value) => {
      value.valkey.ttlMs = 0;
    },
    (value) => {
      value.valkey.persistence = true;
    },
    (value) => {
      value.valkey.authoritative = true;
    },
    (value) => {
      value.valkey.successGrantCaching = true;
    },
  ]) {
    const invalid = clone(i09);
    mutate(invalid);
    assert.throws(() => validateRecoveryResult(invalid));
    assert.throws(() => validateRecovery(row, { recovery: invalid }));
    assert.throws(() =>
      valkeyResult(row, {
        ...fact,
        profileId: invalid.profileId,
        valkey: invalid.valkey,
      }),
    );
  }
});

for (const [consumer, surfaceId, consume, expected] of [
  [
    'recovery-result',
    'FAILURE_RECOVERY',
    recoveryResult,
    { storeCount: 8, checkpoint: '5'.repeat(64) },
  ],
  [
    'migration-result',
    'MIGRATION_COMPATIBILITY',
    migrationResult,
    { profileId: 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2', databaseCount: 3 },
  ],
  [
    'postgres-result',
    'DATA_POSTGRES',
    postgresResult,
    { databaseCount: 3, checkpoint: '5'.repeat(64) },
  ],
  ['valkey-result', 'DATA_VALKEY', valkeyResult, { authoritative: false, empty: true, tls: true }],
]) {
  test(`recovery consumer ${consumer} binds its result and rejects an unfenced writer`, () => {
    const row = { consumer, surfaceId };
    const fact = validateRecovery(row, { recovery: i09 });
    assert.deepEqual(consume(row, fact), expected);
    assert.throws(() => consume({ ...row, consumer: 'foreign-consumer' }, fact));
    assert.throws(() => consume(row, { ...fact, oldWriterExcluded: false }));
  });
}
