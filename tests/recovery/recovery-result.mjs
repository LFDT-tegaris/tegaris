import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';

const structurallyEqual = isDeepStrictEqual;
const fail = (code, detail = '') => {
  throw new Error(`${code}${detail ? `:${detail}` : ''}`);
};
function closed(value, keys, at) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')
  )
    fail('UNKNOWN_OR_OMITTED_REJECTED', at);
}

/** Validate isolated recovery facts before accepting a release qualification result. */
export function validateRecoveryResult(value) {
  closed(
    value,
    [
      'claimCeiling',
      'cleanup',
      'databases',
      'evidenceCheckpointSha256',
      'ociObjectSha256',
      'oldWriterExcluded',
      'profileId',
      'profileRegistrySha256',
      'schemaVersion',
      'status',
      'stores',
      'valkey',
    ],
    '$i09',
  );
  if (
    value.schemaVersion !== '2.0' ||
    value.status !== 'PASS' ||
    value.profileId !== 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2' ||
    value.oldWriterExcluded !== true ||
    value.cleanup !== 'PASS_ZERO_CONTAINER_AND_VOLUME_RESIDUE'
  )
    fail('I09_STATE_REJECTED');
  for (const digest of [
    value.profileRegistrySha256,
    value.ociObjectSha256,
    value.evidenceCheckpointSha256,
  ])
    if (!/^[0-9a-f]{64}$/u.test(digest)) fail('I09_DIGEST_REJECTED');
  const stores = [
    'STORE-CONTROL-PG',
    'STORE-FACT-PG',
    'STORE-CANDIDATE-INDEX-PG',
    'STORE-OCI',
    'STORE-LOCAL-ARTIFACT',
    'STORE-LOCAL-EVIDENCE',
    'STORE-EVIDENCE-VAULT',
    'STORE-VALKEY-OPTIONAL',
  ];
  if (!Array.isArray(value.stores) || !Array.isArray(value.databases))
    fail('I09_COLLECTION_TYPE_REJECTED');
  if (
    !structurallyEqual(value.stores, stores) ||
    !structurallyEqual(
      value.databases.map((row) => row.database),
      ['openpc_control', 'openpc_facts', 'openpc_candidate_index'],
    )
  )
    fail('I09_STORE_REJECTED');
  for (const row of value.databases) {
    closed(
      row,
      [
        'constraints',
        'database',
        'dumpSha256',
        'forcedRlsTables',
        'indexes',
        'schemaSha256',
        'tables',
      ],
      '$i09.database',
    );
    if (
      !/^[0-9a-f]{64}$/u.test(row.dumpSha256) ||
      !/^[0-9a-f]{64}$/u.test(row.schemaSha256) ||
      ['tables', 'constraints', 'indexes', 'forcedRlsTables'].some(
        (key) => !Number.isSafeInteger(row[key]) || row[key] < 1,
      ) ||
      row.forcedRlsTables > row.tables
    )
      fail('I09_DATABASE_FACT_REJECTED');
  }
  closed(
    value.valkey,
    ['authenticated', 'empty', 'maxmemoryPolicy', 'persistence', 'tls'],
    '$i09.valkey',
  );
  if (
    !structurallyEqual(value.valkey, {
      empty: true,
      tls: true,
      authenticated: true,
      persistence: false,
      maxmemoryPolicy: 'allkeys-lfu',
    }) ||
    value.claimCeiling !==
      'LOCAL_SYNTHETIC_ISOLATED_RECOVERY_TECHNICAL_PROOF_ONLY; PROVIDER_SIGNED_PRODUCTION_LIVE_MIGRATION_ACTIVATION_PROMOTION_EXTERNAL_ACCEPTANCE_NOT_PROVEN_OPEN'
  )
    fail('I09_AUXILIARY_FACT_REJECTED');
}

const exactKeys = (value, expected, label) =>
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} is not closed`);
const assertDigest = (value, label) => {
  assert.match(value, /^[a-f0-9]{64}$/, `${label} is not a SHA-256`);
};

export function validateRecovery(row, { recovery }) {
  exactKeys(
    recovery,
    [
      'schemaVersion',
      'status',
      'profileId',
      'profileRegistrySha256',
      'databases',
      'stores',
      'ociObjectSha256',
      'evidenceCheckpointSha256',
      'oldWriterExcluded',
      'valkey',
      'cleanup',
      'claimCeiling',
    ],
    'recovery result',
  );
  assert.equal(recovery.schemaVersion, '2.0');
  assert.equal(recovery.status, 'PASS');
  assert.equal(recovery.profileId, 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2');
  assert.equal(recovery.oldWriterExcluded, true);
  assert.equal(recovery.cleanup, 'PASS_ZERO_CONTAINER_AND_VOLUME_RESIDUE');
  assert.equal(
    recovery.claimCeiling,
    'LOCAL_SYNTHETIC_ISOLATED_RECOVERY_TECHNICAL_PROOF_ONLY; PROVIDER_SIGNED_PRODUCTION_LIVE_MIGRATION_ACTIVATION_PROMOTION_EXTERNAL_ACCEPTANCE_NOT_PROVEN_OPEN',
  );
  assertDigest(recovery.profileRegistrySha256, 'profile registry');
  assertDigest(recovery.ociObjectSha256, 'OCI object');
  assertDigest(recovery.evidenceCheckpointSha256, 'evidence checkpoint');
  assert.deepEqual(recovery.stores, [
    'STORE-CONTROL-PG',
    'STORE-FACT-PG',
    'STORE-CANDIDATE-INDEX-PG',
    'STORE-OCI',
    'STORE-LOCAL-ARTIFACT',
    'STORE-LOCAL-EVIDENCE',
    'STORE-EVIDENCE-VAULT',
    'STORE-VALKEY-OPTIONAL',
  ]);
  assert.deepEqual(
    recovery.databases.map(({ database }) => database),
    ['openpc_control', 'openpc_facts', 'openpc_candidate_index'],
  );
  for (const database of recovery.databases) {
    assert.ok(database.tables > 0);
    assert.ok(database.constraints > 0);
    assert.ok(database.indexes > 0);
    assert.ok(database.forcedRlsTables > 0);
    assertDigest(database.dumpSha256, `${database.database} dump`);
    assertDigest(database.schemaSha256, `${database.database} schema`);
  }
  if (row.surfaceId === 'DATA_VALKEY') {
    assert.deepEqual(recovery.valkey, {
      empty: true,
      tls: true,
      authenticated: true,
      persistence: false,
      maxmemoryPolicy: 'allkeys-lfu',
    });
  }
  return {
    profileId: recovery.profileId,
    databaseCount: recovery.databases.length,
    storeCount: recovery.stores.length,
    evidenceCheckpointSha256: recovery.evidenceCheckpointSha256,
    oldWriterExcluded: recovery.oldWriterExcluded,
    valkey: row.surfaceId === 'DATA_VALKEY' ? recovery.valkey : undefined,
  };
}

export function recoveryResult(row, fact) {
  assert.equal(row.consumer, 'recovery-result');
  assert.equal(fact.storeCount, 8);
  assert.equal(fact.oldWriterExcluded, true);
  assertDigest(fact.evidenceCheckpointSha256, 'recovery checkpoint');
  return { storeCount: fact.storeCount, checkpoint: fact.evidenceCheckpointSha256 };
}

export function migrationResult(row, fact) {
  assert.equal(row.consumer, 'migration-result');
  assert.equal(fact.profileId, 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2');
  assert.equal(fact.databaseCount, 3);
  assert.equal(fact.oldWriterExcluded, true);
  return { profileId: fact.profileId, databaseCount: fact.databaseCount };
}

export function postgresResult(row, fact) {
  assert.equal(row.consumer, 'postgres-result');
  assert.equal(fact.databaseCount, 3);
  assert.equal(fact.oldWriterExcluded, true);
  assertDigest(fact.evidenceCheckpointSha256, 'PostgreSQL evidence checkpoint');
  return { databaseCount: fact.databaseCount, checkpoint: fact.evidenceCheckpointSha256 };
}

export function valkeyResult(row, fact) {
  assert.equal(row.consumer, 'valkey-result');
  assert.equal(fact.profileId, 'OPENPC-I09-LOCAL-MIGRATION-RECOVERY-V2');
  assert.deepEqual(fact.valkey, {
    empty: true,
    tls: true,
    authenticated: true,
    persistence: false,
    maxmemoryPolicy: 'allkeys-lfu',
  });
  assert.equal(fact.oldWriterExcluded, true);
  return { authoritative: false, empty: fact.valkey.empty, tls: fact.valkey.tls };
}
