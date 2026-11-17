import { execFile } from 'node:child_process';
import { createPublicKey } from 'node:crypto';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool } from 'pg';
import { z } from 'zod';
import { expect, it } from 'vitest';
import {
  currentFactMigrations,
  assertFactMigrationJournals,
  factDatabaseRecoveryFixture,
  factDatabaseSnapshot,
  factDatabaseSecurity,
  privateRecoveryInput,
  recoveryDatabasePassword,
  recoveryPool,
} from './fact-database-recovery-fixture.js';
import {
  factRecoveryInputPaths,
  readFactRecoveryCase,
  readFactRecoveryContinuation,
  factRecoveryData,
  factRecoverySourceCase,
} from './fact-recovery-binding.js';
import type {
  FactDatabaseRecoveryCase,
  FactRecoveryComparison,
  FactRecoverySourceCase,
} from './fact-recovery-binding.js';
import { recoveryBytes, recoveryHash } from './postgres-component-recovery.js';
import {
  parseRetirementWire,
  retirementAttempt,
  retirementSelection,
  retirementHost,
  retirementWireBytes,
  retirementWireDigest,
  verifyRetirementOutcome,
} from '../../../services/control-api/src/evidence/store-retirement-wire.js';
import { parseFactRetirementTarget } from '../../../services/control-api/src/evidence/store-retirement-dispatcher.js';
import {
  LocalEvidenceVault,
  vaultObject,
  sinkDurabilityReceipt,
} from '../../../services/control-api/src/evidence/local-vault.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { openSegment } from '../../../services/control-api/src/evidence/segment.js';

const foreign = '018f0000-0000-7000-8000-000000000201';
const hex = z
  .string()
  .regex(/^(?:[0-9a-f]{2})+$/u)
  .max(2097152);
const rows = z.array(z.strictObject({ value: z.record(z.string(), z.unknown()) })).max(1000);
const nativeConfiguration = z.strictObject({
  host: retirementHost,
  authority: z.strictObject({
    version: z.literal(1),
    host: retirementHost,
    control_public_key_sec1: z.array(z.number().int().min(0).max(255)).length(33),
    target_public_key_sec1: z.array(z.number().int().min(0).max(255)).length(33),
  }),
  targetSigningKeyFile: z.string(),
  capabilitySecretFile: z.string(),
  factVerifyKeyFile: z.string(),
  factVerifyKeyId: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  database: z.strictObject({
    host: z.literal('127.0.0.1'),
    port: z.number().int().min(1024).max(65535),
    name: z.literal('openpc_facts'),
    user: z.literal('openpc_fact_runtime'),
    passwordFile: z.string(),
  }),
});
async function json(root: string, file: string) {
  await privateRecoveryInput(root, file);
  return JSON.parse(await readFile(file, 'utf8'));
}
async function originals(
  root: string,
  input: FactRecoverySourceCase & { target?: FactDatabaseRecoveryCase['target'] },
  control: Pool,
) {
  for (const [name, file] of Object.entries(factRecoveryInputPaths(root)))
    expect(input[name as keyof typeof input]).toBe(file);
  const original = rows.length(1).parse(await json(root, input.originalFactFile));
  const custody = rows.length(1).parse(await json(root, input.originalCustodyFile));
  const siblings = rows.min(1).parse(await json(root, input.protectedFactsFile));
  const terminal = z
    .object({
      signedOutcome: hex,
      attemptWire: hex,
      public: z
        .object({
          physicalState: z.literal('APPLIED'),
          dispatchNotAfterMs: z.union([z.string(), z.number()]),
        })
        .passthrough(),
    })
    .parse(await json(root, input.terminalReadbackFile));
  const attempt = retirementAttempt.parse(
    parseRetirementWire(Buffer.from(terminal.attemptWire, 'hex')),
  );
  expect(attempt.scope).toEqual({
    participant_id: input.participantId,
    privacy_domain_id: input.privacyDomainId,
  });
  expect(attempt.store).toBe('openpc_facts');
  if (attempt.selection.class !== 'ADMITTED_FACT')
    throw new Error('BLOCKED: original Fact selection required');
  const selection = attempt.selection;
  expect(attempt.selection.rows).toHaveLength(1);
  const chosen = selection.rows[0]!;
  expect(original[0]!.value.candidate_id).toBe(chosen.candidate_id);
  expect(custody[0]!.value.candidate_id).toBe(chosen.candidate_id);
  const cose = Buffer.from(
    z
      .string()
      .regex(/^\\x[0-9a-f]+$/u)
      .parse(custody[0]!.value.cose_sign1)
      .slice(2),
    'hex',
  );
  expect(recoveryHash(cose)).toBe(chosen.signed_fact_digest);
  const originalPayload = Buffer.from(
    z
      .string()
      .regex(/^\\x[0-9a-f]+$/u)
      .parse(original[0]!.value.canonical_payload)
      .slice(2),
    'hex',
  );
  try {
    expect(recoveryHash(originalPayload)).toBe(chosen.payload_digest);
    expect(BigInt(originalPayload.length)).toBe(chosen.payload_bytes);
  } finally {
    originalPayload.fill(0);
  }
  const selected = z
    .object({
      hostDigest: z.string(),
      selectionWireHex: hex,
      recordRefs: z.array(z.object({ candidateId: z.string(), evidenceId: z.string() })).length(1),
    })
    .parse(await json(root, input.selectionFile));
  expect(
    retirementWireBytes(
      retirementSelection.parse(parseRetirementWire(Buffer.from(selected.selectionWireHex, 'hex'))),
    ).equals(retirementWireBytes(selection)),
  ).toBe(true);
  expect(selected.recordRefs[0]!.candidateId).toBe(chosen.candidate_id);
  const installed = z
    .object({ host: retirementHost })
    .passthrough()
    .parse(await json(root, input.installationFile));
  expect(selected.hostDigest).toBe(retirementWireDigest(installed.host));
  const configuration = nativeConfiguration.parse(await json(root, input.nativeConfigurationFile));
  expect(configuration.host).toEqual(installed.host);
  expect(configuration.authority.host).toEqual(installed.host);
  expect(configuration.database.port).toBe(input.source.port);
  for (const file of [
    configuration.targetSigningKeyFile,
    configuration.capabilitySecretFile,
    configuration.factVerifyKeyFile,
    configuration.database.passwordFile,
  ])
    await privateRecoveryInput(root, file);
  const records = (
    await control.query(
      `select a.attempt_wire,o.signed_wire,h.target_spki,h.host_wire from control.store_retirement_admission a
 join control.store_retirement_outcome o using(participant_id,privacy_domain_id,attempt_id)
 join control.store_retirement_host h on h.participant_id=a.participant_id and h.privacy_domain_id=a.privacy_domain_id and h.host_digest=a.host_digest
 where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
      [input.participantId, input.privacyDomainId, attempt.attempt_id],
    )
  ).rows;
  expect(records).toHaveLength(1);
  const record = records[0]!;
  expect(record.attempt_wire.equals(Buffer.from(terminal.attemptWire, 'hex'))).toBe(true);
  expect(record.signed_wire.equals(Buffer.from(terminal.signedOutcome, 'hex'))).toBe(true);
  const verified = verifyRetirementOutcome(
    record.signed_wire,
    createPublicKey({ key: record.target_spki, format: 'der', type: 'spki' }),
    installed.host,
    attempt,
  );
  expect(verified.outcome.effect.state).toBe('APPLIED');
  const worker = z
    .object({
      vaultDirectory: z.string(),
      sinkId: z.string(),
      scopes: z
        .array(
          z
            .object({
              participantId: z.string(),
              privacyDomainId: z.string(),
              streamId: z.string(),
              source: z.literal('FACT'),
              activeKeyId: z.string(),
              keys: z.array(z.object({ keyId: z.string(), keyFile: z.string() })).min(1),
              fact: z
                .object({
                  sourceProfileId: z.string(),
                  verificationKeyFile: z.string(),
                  verificationKeyId: z.string(),
                })
                .passthrough(),
            })
            .passthrough(),
        )
        .length(1),
    })
    .passthrough()
    .parse(await json(root, input.workerConfigurationFile));
  const scope = worker.scopes[0]!;
  expect(scope.participantId).toBe(input.participantId);
  expect(scope.privacyDomainId).toBe(input.privacyDomainId);
  expect(scope.fact.sourceProfileId).toBe(attempt.selection.source.profile_id);
  expect(worker.vaultDirectory.startsWith(join(root, 'data/evidence-rpc-'))).toBe(true);
  expect(await realpath(worker.vaultDirectory)).toBe(worker.vaultDirectory);
  expect(worker.vaultDirectory.endsWith('/fact-custody/vault')).toBe(true);
  for (const key of scope.keys) await privateRecoveryInput(root, key.keyFile);
  expect(scope.fact.verificationKeyId).toBe(configuration.factVerifyKeyId);
  expect(
    (await readFile(scope.fact.verificationKeyFile)).equals(
      await readFile(configuration.factVerifyKeyFile),
    ),
  ).toBe(true);
  const password = await readFile(configuration.database.passwordFile);
  try {
    for (const cluster of [input.source, ...(input.target ? [input.target] : [])])
      expect(
        password.toString().trim() ===
          (await recoveryDatabasePassword(root, cluster.passwords.openpc_fact_runtime)),
      ).toBe(true);
  } finally {
    password.fill(0);
  }
  await privateRecoveryInput(root, input.nativeExecutable);
  expect((await lstat(input.nativeExecutable)).mode & 0o111).not.toBe(0);
  const fingerprintPaths: Record<string, string> = {
    ...factRecoveryInputPaths(root),
    nativeExecutable: input.nativeExecutable,
    targetSigningKey: configuration.targetSigningKeyFile,
    capabilitySecret: configuration.capabilitySecretFile,
    factVerifyKey: configuration.factVerifyKeyFile,
    nativePassword: configuration.database.passwordFile,
  };
  for (const [index, key] of scope.keys.entries())
    fingerprintPaths[`archiveKey${index}`] = key.keyFile;
  const inputFingerprints = async (): Promise<FactRecoveryComparison['inputs']> => {
    const result = [];
    for (const [name, file] of Object.entries(fingerprintPaths).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    )) {
      await privateRecoveryInput(root, file);
      const bytes = await readFile(file);
      try {
        result.push({ name, bytes: bytes.length, sha256: recoveryHash(bytes) });
      } finally {
        bytes.fill(0);
      }
    }
    return result;
  };
  return {
    original,
    custody,
    siblings,
    terminal,
    attempt,
    chosen,
    selection,
    cose,
    installed,
    configuration,
    worker,
    scope,
    inputFingerprints,
  };
}
type Original = Awaited<ReturnType<typeof originals>>;
async function nativeReadback(
  input: Pick<FactDatabaseRecoveryCase, 'nativeExecutable'>,
  configurationFile: string,
  original: Original,
  attempt = original.attempt,
) {
  return new Promise<Buffer>((resolve, reject) => {
    const child = execFile(
      input.nativeExecutable,
      [],
      {
        env: { ...process.env, OPENPC_RETIREMENT_FACT_CONFIGURATION_FILE: configurationFile },
        timeout: 25000,
        maxBuffer: 2200000,
        encoding: 'buffer',
      },
      (error, stdout, stderr) => {
        stderr.fill(0);
        try {
          if (error) throw new Error('unavailable');
          const result = parseFactRetirementTarget(stdout, original.installed.host, true);
          if (!result) throw new Error('unknown original outcome');
          resolve(result);
        } catch {
          reject(new Error('UNKNOWN: original native Fact readback unavailable'));
        } finally {
          stdout.fill(0);
        }
      },
    );
    child.stdin?.on('error', () => reject(new Error('UNKNOWN: native Fact input unavailable')));
    child.stdin?.end(retirementWireBytes({ mode: 'READBACK', attempt }));
  });
}
async function assertRetired(facts: Pool, input: FactRecoverySourceCase, original: Original) {
  const scope = [input.participantId, input.privacyDomainId, original.chosen.candidate_id];
  expect(
    (
      await facts.query(
        'select 1 from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
        scope,
      )
    ).rows,
  ).toEqual([]);
  for (const [table, comparison, expected] of [
    ['signed_fact_custody', '=', original.custody],
    ['canonical_fact', '<>', original.siblings],
  ] as const) {
    const actual = (
      await facts.query(
        `select to_jsonb(f) value from facts.${table} f where participant_id=$1 and privacy_domain_id=$2 and candidate_id${comparison}$3 order by candidate_id`,
        scope,
      )
    ).rows;
    expect(recoveryHash(recoveryBytes(actual))).toBe(recoveryHash(recoveryBytes(expected)));
  }
  const identity = (
    await facts.query(
      `select a.fact_id::text,a.delta_sequence::text,encode(i.payload_digest,'hex') payload_digest,encode(i.signed_fact_digest,'hex') signed_fact_digest,
 i.generation_id from facts.canonical_identity_allocation a join facts.retained_fact_identity i using(candidate_id,participant_id,privacy_domain_id,generation_id)
 where a.participant_id=$1 and a.privacy_domain_id=$2 and a.candidate_id=$3`,
      scope,
    )
  ).rows;
  expect(identity).toEqual([
    {
      fact_id: original.chosen.fact_id,
      delta_sequence: String(original.chosen.fact_delta_sequence),
      payload_digest: original.chosen.payload_digest,
      signed_fact_digest: original.chosen.signed_fact_digest,
      generation_id: original.selection.fact_generation_id,
    },
  ]);
  for (const table of [
    'fact_lineage',
    'outbox',
    'admission_delivery_event',
    'control_admission_custody_ack',
    'fleet_admission_ack',
  ])
    expect(
      (
        await facts.query(
          `select 1 from facts.${table} where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3`,
          scope,
        )
      ).rowCount,
      table,
    ).toBe(1);
  const terminal = (
    await facts.query(
      `select a.signed_outcome,a.attempt_document,a.state,encode(a.outcome_digest,'hex') digest,
 r.retained_selection,o.event_payload from facts.store_retirement_attempt a join facts.retired_fact_payload r using(participant_id,privacy_domain_id,attempt_id,outcome_digest)
 join facts.store_retirement_outbox o using(participant_id,privacy_domain_id,attempt_id,outcome_digest)
 where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3 and r.candidate_id=$4`,
      [...scope.slice(0, 2), original.attempt.attempt_id, scope[2]],
    )
  ).rows;
  expect(terminal).toHaveLength(1);
  expect(terminal[0].state).toBe('APPLIED');
  expect(
    terminal[0].signed_outcome.equals(Buffer.from(original.terminal.signedOutcome, 'hex')),
  ).toBe(true);
  expect(terminal[0].digest).toBe(
    recoveryHash(Buffer.from(original.terminal.signedOutcome, 'hex')),
  );
  const readiness = (
    await facts.query(
      'select state from facts.readiness_gate where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3',
      [input.participantId, input.privacyDomainId, original.selection.fact_generation_id],
    )
  ).rows;
  expect(readiness).toHaveLength(1);
  expect(readiness[0].state).not.toBe('READY');
  expect(
    (
      await facts.query(
        'select state from facts.source_checkpoint where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3',
        [input.participantId, input.privacyDomainId, original.selection.source.profile_id],
      )
    ).rows,
  ).toEqual([{ state: 'COMPLETE' }]);
  expect(
    (
      await facts.query(
        'select 1 from facts.withdrawal_checkpoint where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3 and source_generation_id=$4 and partition_id=$5',
        [
          input.participantId,
          input.privacyDomainId,
          original.selection.source.profile_id,
          original.selection.source.generation_id,
          original.selection.source.partition_id,
        ],
      )
    ).rowCount,
  ).toBe(1);
}
async function archiveRead(
  worker: Pool,
  original: Original,
  privacy = original.scope.privacyDomainId,
  keyOverride?: Buffer,
) {
  const client = await worker.connect();
  try {
    await client.query('begin read only');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      [original.scope.participantId, privacy, original.attempt.attempt_id],
    );
    const rows = (
      await client.query(
        `select c.record_id,c.receipt_digest,c.sequence::text,s.segment_id::text,s.first_sequence::text,s.through_sequence::text,s.previous_segment_digest,s.object_digest,s.key_id,
 to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') retention_until,p.encrypted_segment,
 k.receipt,k.receipt_digest as sink_receipt_digest from control.evidence_catalogue c join control.evidence_segment s using(participant_id,privacy_domain_id,stream_id,segment_id)
 join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id)
 join control.evidence_checkpoint k using(participant_id,privacy_domain_id,stream_id,segment_id)
 where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.receipt_digest=$4 and k.sink_id=$5`,
        [
          original.scope.participantId,
          original.scope.privacyDomainId,
          original.scope.streamId,
          'sha256:' + original.chosen.signed_fact_digest,
          original.worker.sinkId,
        ],
      )
    ).rows;
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    const header = {
      version: 'OPENPC_EVIDENCE_SEGMENT_V1' as const,
      participantId: original.scope.participantId,
      privacyDomainId: original.scope.privacyDomainId,
      streamId: original.scope.streamId,
      segmentId: row.segment_id,
      firstSequence: row.first_sequence,
      throughSequence: row.through_sequence,
      previousSegmentDigest: row.previous_segment_digest,
      keyId: row.key_id,
      retentionUntil: row.retention_until,
    };
    const receipt = sinkDurabilityReceipt.parse(row.receipt);
    expect(receipt.object).toEqual(vaultObject(original.worker.sinkId, header, row.object_digest));
    expect(receipt.versionId).toBe(row.object_digest);
    expect(receipt.receiptDigest).toBe(row.sink_receipt_digest);
    expect(receipt.receiptDigest).toBe(
      sha256({
        object: receipt.object,
        versionId: receipt.versionId,
        assurance: receipt.assurance,
      }),
    );
    const keyInput = original.scope.keys.filter((value) => value.keyId === row.key_id);
    expect(keyInput).toHaveLength(1);
    const key = keyOverride ? Buffer.from(keyOverride) : await readFile(keyInput[0]!.keyFile);
    try {
      expect(key.length).toBe(32);
      const vault = await LocalEvidenceVault.open(
        original.worker.vaultDirectory,
        original.worker.sinkId,
      );
      const encrypted = await vault.read(
        vaultObject(original.worker.sinkId, header, row.object_digest),
      );
      try {
        expect(encrypted.equals(row.encrypted_segment)).toBe(true);
        const opened = openSegment(encrypted, row.object_digest, header, key);
        const entry = opened.records.filter((record) => record.recordId === row.record_id);
        expect(entry).toHaveLength(1);
        expect(Buffer.from(entry[0]!.receiptBase64, 'base64').equals(original.cose)).toBe(true);
      } finally {
        encrypted.fill(0);
      }
    } finally {
      key.fill(0);
    }
  } finally {
    try {
      await client.query('rollback');
    } finally {
      client.release(true);
    }
  }
}
async function targetConfiguration(
  root: string,
  input: FactDatabaseRecoveryCase,
  original: Original,
  port: number,
) {
  const file = join(input.backupDirectory, `fact-readback-target-${port}.json`);
  const encoded = JSON.stringify({
    ...original.configuration,
    database: { ...original.configuration.database, port },
  });
  try {
    await writeFile(file, encoded, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    await privateRecoveryInput(root, file);
    expect(await readFile(file, 'utf8')).toBe(encoded);
  }
  return file;
}
async function deniedResurrection(
  target: Pool,
  input: FactDatabaseRecoveryCase,
  original: Original,
) {
  const client = await target.connect();
  try {
    await client.query('begin');
    await client.query('set local role openpc_facts_lifecycle_owner');
    await client.query(
      "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
      [input.participantId, input.privacyDomainId],
    );
    // The restored PostgreSQL index order is not an integrity contract: this
    // exact original collides with all three retained-identity uniqueness keys.
    // Verify their actual columns and require the denial from this table, not
    // whichever valid unique index PostgreSQL happens to check first.
    const identities = await client.query<{ conname: string; keys: string[] }>(
      `select c.conname,array(select a.attname::text from unnest(c.conkey) with ordinality k(attnum,n)
       join pg_attribute a on a.attrelid=c.conrelid and a.attnum=k.attnum order by k.n) keys
       from pg_constraint c where c.conrelid='facts.retained_fact_identity'::regclass and c.contype in ('p','u')`,
    );
    expect(identities.rows.map((row) => row.keys).sort()).toEqual(
      [
        ['candidate_id'],
        ['candidate_id', 'participant_id', 'privacy_domain_id', 'generation_id'],
        ['participant_id', 'privacy_domain_id', 'generation_id', 'fact_digest'],
      ].sort(),
    );
    await client.query('savepoint payload');
    await expect(
      client.query(
        'insert into facts.canonical_fact select * from jsonb_populate_record(null::facts.canonical_fact,$1::jsonb)',
        [JSON.stringify(original.original[0]!.value)],
      ),
    ).rejects.toMatchObject({
      code: '23505',
      schema: 'facts',
      table: 'retained_fact_identity',
      constraint: expect.toSatisfy((name: string) =>
        identities.rows.some((row) => row.conname === name),
      ),
    });
    await client.query('rollback to savepoint payload');
    await expect(
      client.query(
        "update facts.readiness_gate set state='READY' where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3",
        [input.participantId, input.privacyDomainId, original.selection.fact_generation_id],
      ),
    ).rejects.toMatchObject({ code: '23514' });
  } finally {
    try {
      await client.query('rollback');
    } finally {
      client.release(true);
    }
  }
}

it('Fact recovery preflight enumerates the actual SQLx-owned local migration journal', async () => {
  const files = await currentFactMigrations();
  expect(files[0]!.path).toBe('/migrations/postgres/common-primitives.sql');
  expect(files.some((row) => row.path.endsWith('/0018_withdrawal_checkpoint.sql'))).toBe(true);
  expect(new Set(files.map((row) => row.path)).size).toBe(files.length);
  expect(files.every((row) => /^[a-f0-9]{64}$/u.test(row.sha256))).toBe(true);
});
const selection = process.env.OPENPC_FACT_DATABASE_RESTORE;
const caseFile = process.env.OPENPC_FACT_DATABASE_RECOVERY_CASE_FILE;
const preflightInput = process.env.OPENPC_FACT_DATABASE_RECOVERY_PREFLIGHT_INPUT;
(preflightInput === undefined ? it.skip : it.sequential)(
  'preflights original Fact recovery dependencies without allocating or fencing',
  async () => {
    if (
      selection !== undefined ||
      caseFile !== undefined ||
      process.env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE !== undefined ||
      !process.env.OPENPC_TEST_TMP_ROOT
    )
      throw new Error('BLOCKED: source-only preflight requires exclusive inputs');
    const root = process.env.OPENPC_TEST_TMP_ROOT;
    expect(await realpath(root)).toBe(root);
    const input = factRecoverySourceCase.parse(JSON.parse(preflightInput!));
    expect(input.backupDirectory).toBe(join(root, 'data/fact-database-recovery'));
    expect(input.source.dataDirectory).toBe(join(root, 'data/fact-pg'));
    expect(input.nativeExecutable).toBe(
      join(root, 'data/runtime-bootstrap/store-retirement/private/fact_retirement_owner'),
    );
    const marker = join(root, '.openpc-local-runtime-owner');
    await privateRecoveryInput(root, marker);
    const ownership =
      /^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/u.exec(
        await readFile(marker, 'utf8'),
      );
    expect(ownership?.[1]).toBe(input.project);
    expect(input.project).toBe(`openpc-local-e2e-${ownership?.[2]?.slice(0, 12)}`);
    const pools: Pool[] = [];
    const connect = async (port: number, user: string, file: string, database: string) => {
      const pool = await recoveryPool(root, port, user, file, database);
      pools.push(pool);
      return pool;
    };
    let original: Original | undefined,
      failed = false,
      primary: unknown;
    const remember = (error: unknown) => {
      if (!failed) {
        failed = true;
        primary = error;
      }
    };
    try {
      const control = await connect(
        input.control.port,
        'openpc_control',
        input.control.adminPasswordFile,
        'openpc_control',
      );
      const worker = await connect(
        input.control.port,
        'openpc_local_control_worker',
        input.control.workerPasswordFile,
        'openpc_control',
      );
      const source = await connect(
        input.source.port,
        'openpc_facts',
        input.source.passwords.openpc_facts,
        'openpc_facts',
      );
      expect(
        (
          await source.query(
            "select current_database() database,current_user,current_setting('server_version_num')::int version",
          )
        ).rows,
      ).toEqual([{ database: 'openpc_facts', current_user: 'openpc_facts', version: 180006 }]);
      const databases = (
        await source.query(
          'select datallowconn,datconnlimit,pg_get_userbyid(datdba) owner from pg_database where datname=current_database()',
        )
      ).rows;
      expect(databases).toHaveLength(1);
      expect(databases[0]).toMatchObject({ datallowconn: true, owner: 'openpc_facts' });
      expect(z.number().int().min(-1).parse(databases[0].datconnlimit)).not.toBe(0);
      const exclusive = async () => {
        expect(
          (
            await source.query(
              'select pid from pg_stat_activity where datname=current_database() and pid<>pg_backend_pid()',
            )
          ).rows,
        ).toEqual([]);
        expect(
          (
            await source.query(
              'select gid from pg_prepared_xacts where database=current_database()',
            )
          ).rows,
        ).toEqual([]);
      };
      await exclusive();
      await assertFactMigrationJournals(source);
      original = await originals(root, input, control);
      expect(BigInt(original.terminal.public.dispatchNotAfterMs) < BigInt(Date.now())).toBe(true);
      await assertRetired(source, input, original);
      expect(
        (await nativeReadback(input, input.nativeConfigurationFile, original)).equals(
          Buffer.from(original.terminal.signedOutcome, 'hex'),
        ),
      ).toBe(true);
      await archiveRead(worker, original);
      await original.inputFingerprints();
      await exclusive();
      for (const role of ['openpc_fact_runtime', 'openpc_policy_fact_runtime'] as const) {
        const pool = await connect(
          input.source.port,
          role,
          input.source.passwords[role],
          'openpc_facts',
        );
        expect((await pool.query('select current_user,session_user')).rows).toEqual([
          { current_user: role, session_user: role },
        ]);
      }
    } catch (error) {
      remember(error);
    } finally {
      original?.cose.fill(0);
      for (const pool of pools)
        try {
          await pool.end();
        } catch (error) {
          remember(error);
        }
    }
    if (failed)
      throw new Error(
        'BLOCKED: original Fact recovery dependency preflight failed; no target or fence',
        { cause: primary },
      );
    process.stdout.write(
      'OPENPC_FACT_DATABASE_PREFLIGHT|PASS|original-native-readback|archive-and-source-dependencies|no-target-or-fence\n',
    );
  },
  60000,
);
const integration = selection === undefined && caseFile === undefined ? it.skip : it.sequential;
integration(
  'restores an original isolated Fact database and reconciles the original retirement',
  async () => {
    if (
      selection !== '1' ||
      !caseFile ||
      !process.env.OPENPC_TEST_TMP_ROOT ||
      !['0', '1', undefined].includes(process.env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE)
    )
      throw new Error('BLOCKED: explicit owned Fact recovery inputs required');
    const root = await realpath(process.env.OPENPC_TEST_TMP_ROOT),
      retained = process.env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE === '1';
    const input = await readFactRecoveryCase(dirname(caseFile));
    expect(caseFile).toBe(join(input.backupDirectory, 'case.json'));
    expect(input.privacyDomainId).not.toBe(foreign);
    if (retained) await readFactRecoveryContinuation(root, input.project);
    const pools = new Set<Pool>();
    const track = (pool: Pool) => {
      pools.add(pool);
      return pool;
    };
    const close = async (pool: Pool) => {
      await pool.end();
      pools.delete(pool);
    };
    let fixture: Awaited<ReturnType<typeof factDatabaseRecoveryFixture>> | undefined,
      original: Original | undefined;
    let failed = false,
      primary: unknown;
    const remember = (error: unknown) => {
      if (!failed) {
        failed = true;
        primary = error;
      }
    };
    try {
      const control = track(
        await recoveryPool(
          root,
          input.control.port,
          'openpc_control',
          input.control.adminPasswordFile,
          'openpc_control',
        ),
      );
      const worker = track(
        await recoveryPool(
          root,
          input.control.port,
          'openpc_local_control_worker',
          input.control.workerPasswordFile,
          'openpc_control',
        ),
      );
      original = await originals(root, input, control);
      fixture = await factDatabaseRecoveryFixture(input, root, retained);
      const related = {
        control,
        vaultDirectory: original.worker.vaultDirectory,
        inputFingerprints: original.inputFingerprints,
      };
      if (!retained) {
        const source = track(await fixture.source());
        await assertFactMigrationJournals(source);
        await assertRetired(source, input, original);
        expect(
          (await nativeReadback(input, input.nativeConfigurationFile, original)).equals(
            Buffer.from(original.terminal.signedOutcome, 'hex'),
          ),
        ).toBe(true);
        await archiveRead(worker, original);
        await close(source);
      }
      const bound = await (retained ? fixture.restoreRetained(related) : fixture.restore(related));
      const target = track(await fixture.target());
      await assertFactMigrationJournals(target);
      await assertRetired(target, input, original);
      // Original authority may have expired while components recovered. Native READBACK
      // requires no renewed authority; bound the wait by its canonical 60-second limit.
      const expiry = BigInt(original.terminal.public.dispatchNotAfterMs);
      const remaining = expiry - BigInt(Date.now());
      expect(remaining <= 60000n).toBe(true);
      if (remaining >= 0n) await delay(Number(remaining) + 1);
      const nativeTarget = await targetConfiguration(root, input, original, fixture.targetPort);
      expect(
        (await nativeReadback(input, nativeTarget, original)).equals(
          Buffer.from(original.terminal.signedOutcome, 'hex'),
        ),
      ).toBe(true);
      await archiveRead(worker, original);
      for (const role of ['openpc_fact_runtime', 'openpc_policy_fact_runtime'] as const) {
        const old = track(await fixture.source(role));
        await expect(old.query('select 1')).rejects.toMatchObject({ code: '55000' });
        await close(old);
        const restored = track(await fixture.target(role));
        expect((await restored.query('select current_user,session_user')).rows).toEqual([
          { current_user: role, session_user: role },
        ]);
        await restored.query('begin');
        await restored.query(
          "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
          [input.participantId, foreign],
        );
        expect((await restored.query('select 1 from facts.canonical_fact')).rowCount).toBe(0);
        await restored.query('rollback');
        await expect(
          restored.query('delete from facts.canonical_fact where false'),
        ).rejects.toMatchObject({ code: '42501' });
        await close(restored);
      }
      const before = await factDatabaseSnapshot(target),
        security = await factDatabaseSecurity(target);
      await deniedResurrection(target, input, original);
      await assertRetired(target, input, original);
      expect(factRecoveryData(await factDatabaseSnapshot(target))).toEqual(
        factRecoveryData(before),
      );
      expect(await factDatabaseSecurity(target)).toEqual(security);
      await expect(archiveRead(worker, original, foreign)).rejects.toThrow();
      await expect(archiveRead(worker, original, undefined, Buffer.alloc(32))).rejects.toThrow();
      await expect(
        nativeReadback(input, nativeTarget, original, {
          ...original.attempt,
          scope: { ...original.attempt.scope, privacy_domain_id: foreign },
        }),
      ).rejects.toThrow();
      expect(await original.inputFingerprints()).toEqual(bound.original.comparison.inputs);
      await fixture.assertSourceFenced();
    } catch (error) {
      remember(error);
    } finally {
      original?.cose.fill(0);
      for (const pool of pools)
        try {
          await pool.end();
        } catch (error) {
          remember(error);
        }
      try {
        await fixture?.close();
      } catch (error) {
        remember(error);
      }
    }
    if (failed)
      throw new Error(
        'UNKNOWN: Fact component recovery or cleanup failed; original effects and artifacts retained',
        { cause: primary },
      );
    process.stdout.write(
      'OPENPC_FACT_DATABASE_RECOVERY|PASS|original-encrypted-archive|permanent-old-writer-fence|native-original-readback|signed-custody-and-acks|no-resurrection|component-only\n',
    );
  },
  270000,
);
