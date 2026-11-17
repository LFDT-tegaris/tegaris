import assert from 'node:assert/strict';
import { Client } from 'pg';

const ADMIN_DATABASE_URL = process.env.OPENPC_I05_GATE3_ADMIN_DATABASE_URL;
const RUNTIME_DATABASE_URL = process.env.OPENPC_I05_GATE3_RUNTIME_DATABASE_URL;

if (!ADMIN_DATABASE_URL || !RUNTIME_DATABASE_URL) {
  throw new Error('I05 Gate3 capability harness requires isolated admin and runtime URLs');
}

const ORIGINAL = `
  SELECT inbox.candidate_id, inbox.participant_id, inbox.privacy_domain_id,
         inbox.source_profile_id, fact.generation_id, inbox.source_sequence,
         inbox.payload_digest, fact.schema_id, fact.schema_version, fact.schema_digest,
         fact.canonical_payload, fact.fact_digest, fact.finality_anchor,
         fact.observed_at_ms, fact.fresh_until_ms, fact.cose_sign1,
         fact.signed_fact_digest, fact.signer_key_id, lineage.provenance_digest
    FROM facts.admission_inbox AS inbox
    JOIN facts.canonical_fact AS fact USING (candidate_id, participant_id, privacy_domain_id)
    JOIN facts.fact_lineage AS lineage USING (candidate_id, participant_id, privacy_domain_id)
   WHERE inbox.candidate_id = 'candidate-1'`;

function admitCall() {
  return `SELECT facts.admit_fact(
    $1::text, $2::text, $3::text, $4::text, $5::text, $6::bigint, $7::bytea,
    $8::bigint, $9::text, $10::bytea, $11::bytea, $12::bytea, $13::bytea,
    $14::bigint, $15::bigint, $16::bytea, $17::bytea, $18::bytea, $19::bytea,
    $20::bytea, $21::bytea
  )`;
}

function admitArgs(original, nonce, mac, overrides = {}) {
  return [
    original.candidate_id,
    overrides.participant ?? original.participant_id,
    original.privacy_domain_id,
    original.source_profile_id,
    original.generation_id,
    original.source_sequence,
    original.payload_digest,
    overrides.schema ?? original.schema_id,
    original.schema_version,
    original.schema_digest,
    overrides.payload ?? original.canonical_payload,
    original.fact_digest,
    original.finality_anchor,
    original.observed_at_ms,
    original.fresh_until_ms,
    overrides.cose ?? original.cose_sign1,
    original.signed_fact_digest,
    original.signer_key_id,
    original.provenance_digest,
    nonce,
    mac,
  ];
}

async function rejected(runtime, label, text, values, expectedMessage) {
  await assert.rejects(
    () => runtime.query({ text, values }),
    (error) => error?.message === expectedMessage,
    label,
  );
}

async function main() {
  const admin = new Client({ connectionString: ADMIN_DATABASE_URL });
  const runtime = new Client({ connectionString: RUNTIME_DATABASE_URL });
  await admin.connect();
  await runtime.connect();
  try {
    const consumed = await admin.query({
      text: `SELECT capability_nonce, capability_mac
               FROM facts.mutation_capability_replay
              WHERE operation = 'ADMIT_FACT'
              ORDER BY consumed_at, capability_nonce
              LIMIT 1`,
    });
    assert.equal(
      consumed.rowCount,
      1,
      'privileged harness found one consumed ADMIT_FACT capability',
    );
    const [{ capability_nonce: nonce, capability_mac: mac }] = consumed.rows;
    assert.equal(Buffer.isBuffer(nonce), true, 'harness nonce is binary');
    assert.equal(Buffer.isBuffer(mac), true, 'harness MAC is binary');
    assert.equal(nonce.length, 32, 'harness nonce length');
    assert.equal(mac.length, 32, 'harness MAC length');

    for (const key of ['openpc.test_capability_nonce_hex', 'openpc.test_capability_mac_hex']) {
      const missing = await runtime.query({
        text: 'SELECT current_setting($1, true) AS value',
        values: [key],
      });
      assert.equal(missing.rows[0].value, null, `${key} missing_ok absence`);
      await assert.rejects(
        () => runtime.query({ text: 'SELECT current_setting($1)', values: [key] }),
        (error) => error?.code === '42704',
        `${key} required read denied`,
      );
    }
    const settings = await runtime.query({
      text: `SELECT count(*)::int AS count FROM pg_catalog.pg_settings
              WHERE name IN ('openpc.test_capability_nonce_hex', 'openpc.test_capability_mac_hex')`,
    });
    assert.equal(settings.rows[0].count, 0, 'capability GUCs absent from pg_settings');

    const originalQuery = await runtime.query({ text: ORIGINAL });
    assert.equal(originalQuery.rowCount, 1, 'runtime reads one public lifecycle input record');
    const [original] = originalQuery.rows;

    await rejected(
      runtime,
      'replay',
      admitCall(),
      admitArgs(original, nonce, mac),
      'OPENPC_FACTSTORE_CAPABILITY_REPLAY',
    );
    await rejected(
      runtime,
      'schema rebind',
      admitCall(),
      admitArgs(original, nonce, mac, { schema: Number(original.schema_id) + 1 }),
      'OPENPC_FACTSTORE_CAPABILITY_INVALID',
    );
    const reboundPayload = Buffer.from(original.canonical_payload);
    reboundPayload[0] ^= 1;
    await rejected(
      runtime,
      'payload rebind',
      admitCall(),
      admitArgs(original, nonce, mac, { payload: reboundPayload }),
      'OPENPC_FACTSTORE_CAPABILITY_INVALID',
    );
    const reboundCose = Buffer.from(original.cose_sign1);
    reboundCose[0] ^= 1;
    await rejected(
      runtime,
      'signature rebind',
      admitCall(),
      admitArgs(original, nonce, mac, { cose: reboundCose }),
      'OPENPC_FACTSTORE_CAPABILITY_INVALID',
    );
    await runtime.query({
      text: "SELECT pg_catalog.set_config('openpc.participant_id', 'participant-b', false)",
    });
    try {
      await rejected(
        runtime,
        'tenant rebind',
        admitCall(),
        admitArgs(original, nonce, mac, { participant: 'participant-b' }),
        'OPENPC_FACTSTORE_CAPABILITY_INVALID',
      );
    } finally {
      await runtime.query({
        text: "SELECT pg_catalog.set_config('openpc.participant_id', 'participant-a', false)",
      });
    }
    const reboundNonce = Buffer.from(nonce);
    reboundNonce[0] ^= 1;
    await rejected(
      runtime,
      'nonce rebind',
      admitCall(),
      admitArgs(original, reboundNonce, mac),
      'OPENPC_FACTSTORE_CAPABILITY_INVALID',
    );
    await rejected(
      runtime,
      'lifecycle rebind',
      'SELECT facts.finalize_fact($1::text, $2::text, $3::text, $4::bytea, $5::bytea, $6::bytea)',
      [
        original.participant_id,
        original.privacy_domain_id,
        original.candidate_id,
        original.finality_anchor,
        nonce,
        mac,
      ],
      'OPENPC_FACTSTORE_CAPABILITY_INVALID',
    );
  } finally {
    await Promise.all([runtime.end(), admin.end()]);
  }
}

await main();
process.stdout.write(
  'RUNTIME_CAPABILITY_HARNESS|PASS|PARAMETERIZED_ONE_SHOT_REPLAY_REBIND_GUC_ABSENCE\n',
);
