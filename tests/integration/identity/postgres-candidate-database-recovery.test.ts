import { execFile } from 'node:child_process';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Pool } from 'pg';
import { z } from 'zod';
import { expect, it } from 'vitest';
import {
  candidateDatabaseRecoveryCase,
  candidateControlSnapshot as controlSnapshot,
  candidateVaultInventory as vaultInventory,
  candidateDatabaseRecoveryFixture,
  candidateDatabaseSecurity,
  candidateRecoveryAcl,
  candidateDatabaseSnapshot,
  candidateScope,
  assertCandidateMigrationJournals,
  currentCandidateMigrations,
  privateRecoveryInput,
  readCandidateRecoveryCase,
  recoveryPool,
  recoveryDatabasePassword,
  requireDistinctCandidateClusters,
  type CandidateDatabaseRecoveryCase,
} from './candidate-database-recovery-fixture.js';
import { recoveryDirectory } from './control-database-recovery-fixture.js';
import {
  assertCandidateRecoveryComparison,
  candidateRecoveryData,
  candidateRecoverySecurity,
} from './candidate-recovery-binding.js';
import {
  candidateArchiveManifest,
  candidateArchiveRequest,
} from '../../../services/control-api/src/evidence/candidate-archive/contract.js';
import {
  candidateArchiveSource,
  readArchivedCandidatePayload,
  readCandidateArchiveCoverage,
} from '../../../services/control-api/src/evidence/candidate-archive/source.js';
import { candidateRetirementSelection } from '../../../services/control-api/src/evidence/candidate-archive/retirement-selection.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { evidenceScope } from '../../../services/control-api/src/evidence/segment.js';
import {
  retirementAttempt,
  retirementHost,
  retirementWireBytes,
  retirementWireDigest,
  retirementSelectionDigest,
  parseRetirementWire,
  verifyRetirementOutcome,
} from '../../../services/control-api/src/evidence/store-retirement-wire.js';

const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const foreignId = '018f0000-0000-7000-8000-000000000201';
const hex = z
  .string()
  .regex(/^(?:[0-9a-f]{2})+$/u)
  .max(2_097_152);
const custodyCase = z.strictObject({
  source: candidateArchiveSource,
  request: candidateArchiveRequest,
  scope: evidenceScope,
  keyFile: z.string().refine(isAbsolute),
  keyId: z.string().min(1).max(160),
  retentionUntil: z.iso.datetime({ precision: 6 }),
  capacityBytes: z.number().int().min(1024).max(1073741824),
  vaultDirectory: z.string().refine(isAbsolute),
  sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  activeHoldId: z.uuidv7(),
});
type RetiredCase = Extract<CandidateDatabaseRecoveryCase, { phase: 'RETIRED' }>;

// These checks run without DB allocation in the ordinary identity test family.
// Sample paths/IDs have no authority; the runtime test requires real originals.
const sample = (): CandidateDatabaseRecoveryCase => {
  const passwords = {
    openpc_candidate_index: '/tmp/candidate/admin',
    openpc_indexer_manager: '/tmp/candidate/manager',
    openpc_indexer_writer: '/tmp/candidate/writer',
    openpc_candidate_index_reader: '/tmp/candidate/reader',
  };
  return {
    version: 1,
    phase: 'PRISTINE',
    project: 'openpc-recovery',
    backupDirectory: '/tmp/candidate/backup',
    source: {
      containerId: 'a'.repeat(64),
      port: 55434,
      dataDirectory: '/tmp/candidate/source',
      passwords,
    },
    target: {
      containerId: 'b'.repeat(64),
      port: 55435,
      dataDirectory: '/tmp/candidate/target',
      passwords,
    },
    control: {
      port: 55432,
      adminPasswordFile: '/tmp/control/admin',
      workerPasswordFile: '/tmp/control/worker',
    },
    participantId: '018f0000-0000-7000-8000-000000000001',
    privacyDomainId: '018f0000-0000-7000-8000-000000000002',
    projectionPlanId: '018f0000-0000-7000-8000-000000000003',
  };
};
it('rejects shared Candidate clusters, endpoints, nested data and authority-shaped inputs before allocation', () => {
  expect(() =>
    requireDistinctCandidateClusters(candidateDatabaseRecoveryCase.parse(sample())),
  ).not.toThrow();
  for (const field of ['containerId', 'port', 'dataDirectory'] as const) {
    const value = sample();
    Object.assign(value.target, { [field]: value.source[field] });
    expect(() => requireDistinctCandidateClusters(value)).toThrow('distinct');
  }
  for (const directory of ['/tmp/candidate/source/nested', '/tmp/candidate']) {
    const value = sample();
    value.target.dataDirectory = directory;
    expect(() => requireDistinctCandidateClusters(value)).toThrow('distinct');
  }
  const collision = sample();
  collision.target.port = collision.control.port;
  expect(() => requireDistinctCandidateClusters(collision)).toThrow('distinct');
  for (const value of [
    { ...sample(), phase: 'RETIRED' },
    { ...sample(), currentReadiness: 'READY' },
    { ...sample(), restoreSucceeded: true },
    { ...sample(), expectedSnapshot: {} },
    { ...sample(), originalComparison: {} },
    { ...sample(), version: 2 },
    { ...sample(), source: { ...sample().source, database: 'renamed' } },
  ])
    expect(candidateDatabaseRecoveryCase.safeParse(value).success).toBe(false);
});
// Keep this causal input check under the existing runner's connected preflight
// selection, before it stops consumers or allocates a target container.
it('rejects shared Candidate clusters with unsafe installed-password custody', async () => {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'candidate-recovery-input-'),
  );
  const directory = join(root, 'secrets');
  const file = join(directory, 'indexer_writer_db_password.txt');
  const password = 'a'.repeat(64);
  try {
    await mkdir(directory, { mode: 0o700 });
    await writeFile(file, `${password}\n`, { mode: 0o600, flag: 'wx' });
    for (const mode of [0o400, 0o444, 0o600]) {
      await chmod(file, mode);
      expect((await recoveryDatabasePassword(root, file)) === password).toBe(true);
    }
    await chmod(file, 0o444);
    await expect(privateRecoveryInput(root, file)).rejects.toThrow('private owned');
    await chmod(directory, 0o755);
    await expect(recoveryDatabasePassword(root, file)).rejects.toThrow('directory must be private');
    await chmod(directory, 0o700);
    await chmod(file, 0o644);
    await expect(recoveryDatabasePassword(root, file)).rejects.toThrow('password file');
    await chmod(file, 0o444);
    const outside = join(root, 'outside-password');
    await writeFile(outside, password, { mode: 0o444, flag: 'wx' });
    await expect(recoveryDatabasePassword(root, outside)).rejects.toThrow('password path');
    const symbolic = join(directory, 'symbolic-password');
    await symlink(outside, symbolic);
    await expect(recoveryDatabasePassword(root, symbolic)).rejects.toThrow('password file');
    const hard = join(directory, 'hard-password');
    await link(file, hard);
    await expect(recoveryDatabasePassword(root, hard)).rejects.toThrow('password file');
    const malformed = join(directory, 'malformed-password');
    await writeFile(malformed, 'not-an-installed-password', { mode: 0o400, flag: 'wx' });
    await expect(recoveryDatabasePassword(root, malformed)).rejects.toThrow(
      'invalid installed database password',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it('enumerates the current SQLx-owned Candidate migration inputs without fixed migration counts', async () => {
  const migrations = await currentCandidateMigrations();
  expect(migrations.length).toBeGreaterThan(0);
  for (const migration of migrations) {
    expect(migration.id).toMatch(/^OPENPC-MIG-CANDIDATE-[0-9]{4}$/u);
    expect(migration.path).toMatch(
      /^\/migrations\/postgres\/candidate-index\/[0-9]{4}_[a-z0-9_]+\.sql$/u,
    );
    expect(migration.sha256).toMatch(/^[0-9a-f]{64}$/u);
  }
});

// Exercise PostgreSQL's actual default ACL semantics before fencing an original.
// Equivalent owner defaults must compare equal; public access and grant options
// remain security differences, even when another entry is the implicit default.
export async function assertCandidateAclComparison(pool: Pool) {
  const fallback = "acldefault('r',r.oid)";
  const rows = (
    await pool.query(`select
      ${candidateRecoveryAcl('null::aclitem[]', fallback)} implicit,
      ${candidateRecoveryAcl(fallback, fallback)} explicit,
      ${candidateRecoveryAcl("array_append(acldefault('r',r.oid),'=r/openpc_candidate_index_owner'::aclitem)", fallback)} public_read,
      ${candidateRecoveryAcl("array_append(acldefault('r',r.oid),'openpc_candidate_index_reader=r/openpc_candidate_index_owner'::aclitem)", fallback)} reader,
      ${candidateRecoveryAcl("array_append(acldefault('r',r.oid),'openpc_candidate_index_reader=r*/openpc_candidate_index_owner'::aclitem)", fallback)} delegable
      from pg_roles r where r.rolname='openpc_candidate_index_owner'`)
  ).rows;
  expect(rows).toHaveLength(1);
  expect(rows[0].implicit).toEqual(rows[0].explicit);
  expect(rows[0].implicit).not.toEqual(rows[0].public_read);
  expect(rows[0].implicit).not.toEqual(rows[0].reader);
  expect(rows[0].reader).not.toEqual(rows[0].delegable);
}

/** Real PG sensitivity checks, run only on the isolated restored target. All
 * schema changes roll back; the sequence is new and never a business identity. */
async function assertCandidateRecoveryComparisonSensitivity(pool: Pool) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('create sequence candidate.recovery_comparison_probe');
    await client.query(
      'alter sequence candidate.recovery_comparison_probe owner to openpc_candidate_index_owner',
    );
    const beforeSequence = candidateRecoveryData(await candidateDatabaseSnapshot(pool, client));
    await client.query("select nextval('candidate.recovery_comparison_probe')");
    const afterSequence = candidateRecoveryData(await candidateDatabaseSnapshot(pool, client));
    expect(
      afterSequence.find((row) => row.name === 'sequence.recovery_comparison_probe'),
    ).not.toEqual(beforeSequence.find((row) => row.name === 'sequence.recovery_comparison_probe'));
    await client.query('savepoint comparison_security');
    const beforeSecurity = candidateRecoverySecurity(await candidateDatabaseSecurity(pool, client));
    // Release the helper's temporary constraint-parser relations before reusing
    // the same connection; retain the real normalized metadata comparison.
    await client.query('rollback to savepoint comparison_security');
    await client.query(
      'alter table candidate.store_retirement_attempt no force row level security',
    );
    // The ordinary security oracle must reject this weakening before equality.
    await expect(candidateDatabaseSecurity(pool, client)).rejects.toThrow();
    await client.query('rollback to savepoint comparison_security');
    await client.query('grant select on candidate.store_retirement_attempt to public');
    const afterSecurity = candidateRecoverySecurity(await candidateDatabaseSecurity(pool, client));
    expect(afterSecurity.relations).not.toEqual(beforeSecurity.relations);
  } finally {
    try {
      await client.query('rollback');
    } finally {
      client.release();
    }
  }
}

/** Real historical qualification from the current indexer publication source
 * owner. The returned rows are observations, never new publication authority. */
async function assertPristineSource(control: Pool, input: CandidateDatabaseRecoveryCase) {
  if (input.phase !== 'PRISTINE') throw new Error('Wrong recovery phase');
  const rows = (
    await control.query(
      `select p.projection_plan_id::text,i.indexer_profile_id::text
     from control.projection_plan p join control.indexer_profile i on i.indexer_profile_id=p.indexer_profile_id
      and i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id
     join control.configuration_work validation on validation.resource_id=p.projection_plan_id
      and validation.participant_id=p.participant_id and validation.privacy_domain_id=p.privacy_domain_id
      and validation.work_kind='PROJECTION_VALIDATION' and validation.state='COMPLETED' and validation.input_digest=p.plan_digest
     join control.idempotency_record validated on validated.operation_id=validation.operation_id
      and validated.participant_id=p.participant_id and validated.privacy_domain_id=p.privacy_domain_id
      and validated.terminal_state='COMMITTED' and validated.result_payload->>'state'='SUCCEEDED'
      and validated.result_aggregate_version=p.revision
     join control.configuration_work qualification on qualification.resource_id=i.indexer_profile_id
      and qualification.participant_id=i.participant_id and qualification.privacy_domain_id=i.privacy_domain_id
      and qualification.work_kind='INDEXER_ADMISSION' and qualification.state='COMPLETED'
      and qualification.input_digest=i.method_profile_digest
      and qualification.operation_id::text=validation.result_receipt->>'profileQualificationOperationId'
     join control.idempotency_record qualified on qualified.operation_id=qualification.operation_id
      and qualified.participant_id=i.participant_id and qualified.privacy_domain_id=i.privacy_domain_id
      and qualified.terminal_state='COMMITTED' and qualified.result_payload->>'state'='SUCCEEDED'
      and qualified.result_aggregate_version=i.revision
     join control.module_installation installation on installation.participant_id=p.participant_id
      and installation.privacy_domain_id=p.privacy_domain_id and installation.state='ENABLED'
     join control.module_version version on version.module_version_id=installation.module_version_id
      and version.module_id='pc.config.assets'
     join control.runtime_configuration_input_current configuration
      on configuration.module_installation_id=installation.module_installation_id and configuration.active
     where p.participant_id=$1 and p.privacy_domain_id=$2 and p.projection_plan_id=$3
      and p.state='VALIDATED' and p.readiness='READY' and i.state in ('QUALIFIED','ACTIVE')
      and validation.result_receipt->>'profileQualificationRevision'=i.revision::text
      and validation.result_receipt->>'profileResourceId'=i.indexer_profile_id::text
      and validation.result_receipt->>'profileArtifactDigest'=i.method_profile_digest`,
      [input.participantId, input.privacyDomainId, input.projectionPlanId],
    )
  ).rows;
  expect(rows, 'BLOCKED: real governed pre-publication source required').toHaveLength(1);
  return rows;
}

async function retiredInputs(root: string, input: RetiredCase, control: Pool) {
  for (const file of [
    input.custodyCaseFile,
    input.nativeBeforeFile,
    input.terminalReadbackFile,
    input.nativeConfigurationFile,
  ])
    await privateRecoveryInput(root, file);
  const custody = custodyCase.parse(JSON.parse(await readFile(input.custodyCaseFile, 'utf8')));
  expect(custody.scope.participantId).toBe(input.participantId);
  expect(custody.scope.privacyDomainId).toBe(input.privacyDomainId);
  expect(custody.request.participantId).toBe(input.participantId);
  expect(custody.request.privacyDomainId).toBe(input.privacyDomainId);
  await privateRecoveryInput(root, custody.keyFile);
  await recoveryDirectory(root, custody.vaultDirectory);
  expect((await lstat(custody.vaultDirectory)).isDirectory()).toBe(true);
  const before = z
    .strictObject({
      events: z
        .array(z.strictObject({ value: z.record(z.string(), z.unknown()) }))
        .min(2)
        .max(1000),
      identity: z.array(z.strictObject({ value: z.record(z.string(), z.unknown()) })).length(1),
    })
    .parse(JSON.parse(await readFile(input.nativeBeforeFile, 'utf8')));
  const original = before.events.find(
    (row) => row.value.candidate_event_id === custody.request.candidateId,
  );
  expect(original, 'BLOCKED: original pre-retirement candidate bytes required').toBeDefined();
  if (!original) throw new Error('BLOCKED: original candidate unavailable');
  const payload = z
    .string()
    .regex(/^\\x(?:[0-9a-f]{2})+$/u)
    .parse(original.value.payload_cbor);
  const terminal = z
    .object({
      signedOutcome: hex,
      attemptWire: hex,
      public: z.object({ physicalState: z.literal('APPLIED') }).passthrough(),
    })
    .parse(JSON.parse(await readFile(input.terminalReadbackFile, 'utf8')));
  const attempt = retirementAttempt.parse(
    parseRetirementWire(Buffer.from(terminal.attemptWire, 'hex')),
  );
  expect(attempt.scope).toEqual({
    participant_id: input.participantId,
    privacy_domain_id: input.privacyDomainId,
  });
  expect(attempt.store).toBe('openpc_candidate_index');
  const records = (
    await control.query(
      `select a.attempt_wire,o.signed_wire,h.target_spki,h.host_wire
     from control.store_retirement_admission a join control.store_retirement_outcome o using(participant_id,privacy_domain_id,attempt_id)
     join control.store_retirement_host h on h.participant_id=a.participant_id
      and h.privacy_domain_id=a.privacy_domain_id and h.host_digest=a.host_digest
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
      [input.participantId, input.privacyDomainId, attempt.attempt_id],
    )
  ).rows;
  expect(records, 'BLOCKED: original admitted terminal outcome required').toHaveLength(1);
  const record = records[0]!;
  expect(record.attempt_wire.equals(Buffer.from(terminal.attemptWire, 'hex'))).toBe(true);
  expect(record.signed_wire.equals(Buffer.from(terminal.signedOutcome, 'hex'))).toBe(true);
  const host = retirementHost.parse(parseRetirementWire(record.host_wire));
  const verified = verifyRetirementOutcome(
    record.signed_wire,
    createPublicKey({ key: record.target_spki, format: 'der', type: 'spki' }),
    host,
    attempt,
  );
  expect(verified.outcome.effect.state).toBe('APPLIED');
  const manifests = (
    await control.query(
      `select manifest from control.evidence_candidate_archive
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and candidate_id=$4`,
      [
        input.participantId,
        input.privacyDomainId,
        custody.scope.streamId,
        custody.request.candidateId,
      ],
    )
  ).rows;
  expect(manifests).toHaveLength(1);
  const manifest = candidateArchiveManifest.parse(manifests[0]!.manifest);
  expect(manifest.identity).toMatchObject(custody.request);
  expect(candidateRetirementSelection(manifest)).toEqual(attempt.selection);
  expect(manifest).toMatchObject({ authority: 'NONE', currentReadiness: 'NOT_ESTABLISHED' });
  const expected = Buffer.from(payload.slice(2), 'hex');
  expect(digest(expected)).toBe(manifest.identity.payloadDigest.replace(/^sha256:/u, ''));
  return { custody, before, original, terminal, attempt, host, manifest, expected };
}
type Original = Awaited<ReturnType<typeof retiredInputs>>;

async function assertRetiredState(
  native: Pool,
  control: Pool,
  input: RetiredCase,
  original: Original,
) {
  const { custody, before, attempt, terminal } = original;
  const scope = [input.participantId, input.privacyDomainId];
  expect(
    (
      await native.query('select 1 from candidate.candidate_event where candidate_event_id=$1', [
        custody.request.candidateId,
      ])
    ).rowCount,
  ).toBe(0);
  const siblings = (
    await native.query(
      'select to_jsonb(e) value from candidate.candidate_event e order by candidate_event_id',
    )
  ).rows;
  expect(siblings.length).toBeGreaterThan(0);
  // Do not display original payloads in assertion failure diffs.
  expect(
    JSON.stringify(siblings) ===
      JSON.stringify(before.events.filter((row) => row !== original.original)),
  ).toBe(true);
  const identity = (
    await native.query(
      'select to_jsonb(i) value from candidate.retained_candidate_identity i where candidate_event_id=$1',
      [custody.request.candidateId],
    )
  ).rows;
  expect(JSON.stringify(identity) === JSON.stringify(before.identity)).toBe(true);
  const outcome = (
    await native.query(
      `select state,encode(signed_outcome,'hex') wire,encode(outcome_digest,'hex') digest,attempt_document::text attempt_document
     from candidate.store_retirement_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
      [...scope, attempt.attempt_id],
    )
  ).rows;
  expect(outcome).toHaveLength(1);
  expect(outcome[0]!.state).toBe('APPLIED');
  expect(outcome[0]!.wire === terminal.signedOutcome).toBe(true);
  expect(outcome[0]!.digest).toBe(digest(Buffer.from(terminal.signedOutcome, 'hex')));
  expect(
    retirementWireDigest(
      retirementAttempt.parse(parseRetirementWire(Buffer.from(outcome[0]!.attempt_document))),
    ),
  ).toBe(retirementWireDigest(attempt));
  const tombstones = (
    await native.query(
      `select candidate_id::text,encode(outcome_digest,'hex') digest,retained_selection::text retained_selection
     from candidate.retired_candidate_payload where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
      [...scope, attempt.attempt_id],
    )
  ).rows;
  expect(tombstones).toHaveLength(1);
  expect(tombstones[0]).toMatchObject({
    candidate_id: custody.request.candidateId,
    digest: outcome[0]!.digest,
  });
  expect(parseRetirementWire(Buffer.from(tombstones[0]!.retained_selection))).toEqual(
    attempt.selection.rows[0]!,
  );
  const outbox = (
    await native.query(
      `select encode(outcome_digest,'hex') digest,event_digest=sha256(event_payload) valid
     from candidate.store_retirement_outbox where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
      [...scope, attempt.attempt_id],
    )
  ).rows;
  expect(outbox).toEqual([{ digest: outcome[0]!.digest, valid: true }]);
  const delivered = (
    await native.query(
      `select state,published_at is not null acknowledged from candidate.outbox_event
     where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='candidate-partition' and aggregate_id=$3`,
      [...scope, custody.request.partitionId],
    )
  ).rows;
  expect(
    delivered.length,
    'BLOCKED: original publication acknowledgement required',
  ).toBeGreaterThan(0);
  for (const row of delivered) expect(row).toEqual({ state: 'DELIVERED', acknowledged: true });
  const hold = (
    await control.query(
      `select revision::text,state from control.retention_hold where participant_id=$1 and retention_hold_id=$2
     and (selector_type='PARTICIPANT' or privacy_domain_id=$3)`,
      [input.participantId, custody.activeHoldId, input.privacyDomainId],
    )
  ).rows;
  expect(hold).toHaveLength(1);
  expect(hold[0]!.state).toBe('RELEASED');
  expect(BigInt(hold[0]!.revision)).toBeGreaterThan(1n);
}

async function archiveRead(
  worker: Pool,
  original: Original,
  key: Buffer,
  privacy = original.custody.scope.privacyDomainId,
) {
  const { custody, manifest } = original;
  const scope = { ...custody.scope, privacyDomainId: privacy };
  return candidateScope(worker, scope.participantId, scope.privacyDomainId, async (client) => {
    const vault = await LocalEvidenceVault.open(custody.vaultDirectory, custody.sinkId);
    const coverage = await readCandidateArchiveCoverage(client, scope, manifest, [custody.sinkId]);
    expect(coverage.state).toBe('COMPLETE');
    if (coverage.state !== 'COMPLETE') throw new Error('Original archive coverage incomplete');
    // Original released revision acknowledgements must survive; no reconcile or
    // export is performed by this component to make absent coverage appear.
    const holds = (
      await client.query(
        `select c.segment_id::text from control.evidence_hold_coverage c join control.retention_hold h
       on h.participant_id=c.participant_id and h.retention_hold_id=c.retention_hold_id and h.revision=c.hold_revision
       where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.retention_hold_id=$4 and c.sink_id=$5`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.streamId,
          custody.activeHoldId,
          custody.sinkId,
        ],
      )
    ).rows.map((row) => row.segment_id);
    for (const segment of coverage.segments) expect(holds).toContain(segment.segmentId);
    return readArchivedCandidatePayload(client, scope, manifest, vault, async (keyId) => {
      expect(keyId).toBe(custody.keyId);
      if (key.length === 0) throw new Error('Original archive key unavailable');
      return Buffer.from(key);
    });
  });
}

async function nativeReadback(
  executable: string,
  configurationFile: string,
  attempt: Original['attempt'],
) {
  // Exact original bytes are encoded with the wire owner's integer-preserving
  // encoder. Ordinary JSON.stringify would lose u64 precision.
  const input = Buffer.concat([
    Buffer.from('{"mode":"READBACK","attempt":'),
    retirementWireBytes(attempt),
    Buffer.from('}'),
  ]);
  return new Promise<unknown>((resolve, reject) => {
    const child = execFile(
      executable,
      [],
      {
        env: { ...process.env, OPENPC_RETIREMENT_CANDIDATE_CONFIGURATION_FILE: configurationFile },
        timeout: 25000,
        maxBuffer: 2_200_000,
      },
      (error, stdout) => {
        if (error) return reject(new Error('Native original-attempt readback unavailable'));
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('Native readback shape invalid'));
        }
      },
    );
    child.stdin!.on('error', () => reject(new Error('Native readback input unavailable')));
    child.stdin!.end(input);
  });
}

async function targetConfiguration(root: string, input: RetiredCase, original: Original) {
  const configuration = z
    .strictObject({
      host: retirementHost,
      authority: z.strictObject({
        version: z.literal(1),
        host: retirementHost,
        control_public_key_sec1: z.array(z.number().int().min(0).max(255)).length(33),
        target_public_key_sec1: z.array(z.number().int().min(0).max(255)).length(33),
      }),
      targetSigningKeyFile: z.string(),
      capabilitySecretFile: z.string(),
      database: z.strictObject({
        host: z.literal('127.0.0.1'),
        port: z.number().int(),
        name: z.literal('openpc_candidate_index'),
        user: z.literal('openpc_indexer_writer'),
        passwordFile: z.string(),
      }),
    })
    .parse(JSON.parse(await readFile(input.nativeConfigurationFile, 'utf8')));
  expect(configuration.host).toEqual(original.host);
  expect(configuration.authority.host).toEqual(original.host);
  expect(configuration.database.port).toBe(input.source.port);
  for (const file of [
    configuration.targetSigningKeyFile,
    configuration.capabilitySecretFile,
    configuration.database.passwordFile,
  ])
    await privateRecoveryInput(root, file);
  // The installed native owner deliberately rejects mounted 0444 password files.
  // Retain its original private password after proving the canonical target was
  // provisioned with those same bytes; change only the isolated endpoint.
  const privatePassword = await readFile(configuration.database.passwordFile);
  try {
    for (const cluster of [input.source, input.target])
      expect(
        privatePassword.toString().trim() ===
          (await recoveryDatabasePassword(root, cluster.passwords.openpc_indexer_writer)),
      ).toBe(true);
  } finally {
    privatePassword.fill(0);
  }
  // Preserve installed key/trust/capability files byte-for-byte. Target credentials
  // were provisioned by the canonical roles owner, not copied from pg_authid.
  const executable = await lstat(input.nativeExecutable);
  expect(executable.isFile() && !executable.isSymbolicLink()).toBe(true);
  expect(await realpath(input.nativeExecutable)).toBe(input.nativeExecutable);
  expect(executable.mode & 0o111).not.toBe(0);
  const target = {
    ...configuration,
    database: {
      ...configuration.database,
      port: input.target.port,
    },
  };
  const file = join(input.backupDirectory, 'candidate-readback-target.json');
  await writeFile(file, JSON.stringify(target), { flag: 'wx', mode: 0o600 });
  return { file, configuration: target };
}

async function assertNativeCapability(pool: Pool, file: string) {
  const encoded = await readFile(file);
  try {
    expect(encoded.toString().trim()).toMatch(/^[0-9a-f]{64}$/u);
    const bytes = Buffer.from(encoded.toString().trim(), 'hex');
    try {
      expect(
        (
          await pool.query(
            "select encode(sha256(verifier_secret),'hex') digest from candidate.retirement_capability_secret where secret_version=1",
          )
        ).rows,
      ).toEqual([{ digest: digest(bytes) }]);
    } finally {
      bytes.fill(0);
    }
  } finally {
    encoded.fill(0);
  }
}

// Absence is a skip only when the phase was not requested. Any selected but
// incomplete/malformed case fails before allocating or fencing a source.
const selection = process.env.OPENPC_CANDIDATE_DATABASE_RESTORE;
const caseFile = process.env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CASE_FILE;
const continuation = process.env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE;
const integration =
  selection === undefined && caseFile === undefined && continuation === undefined
    ? it.skip
    : it.sequential;
integration(
  'restores an original isolated Candidate database with source fencing and no renewed authority (O2a)',
  async () => {
    if (
      selection !== '1' ||
      !caseFile ||
      !process.env.OPENPC_TEST_TMP_ROOT ||
      (continuation !== undefined && continuation !== '1')
    )
      throw new Error(
        'BLOCKED: explicit Candidate restore selection and complete owned inputs required',
      );
    const root = await realpath(process.env.OPENPC_TEST_TMP_ROOT);
    const input = await readCandidateRecoveryCase(caseFile, root);
    expect(input.privacyDomainId).not.toBe(foreignId);
    const pools = new Set<Pool>();
    const track = (pool: Pool) => {
      pools.add(pool);
      return pool;
    };
    const close = async (pool: Pool) => {
      await pool.end();
      pools.delete(pool);
    };
    let fixture: Awaited<ReturnType<typeof candidateDatabaseRecoveryFixture>> | undefined;
    let original: Original | undefined;
    let preparedReadback: Awaited<ReturnType<typeof targetConfiguration>> | undefined;
    let originalVault: Awaited<ReturnType<typeof vaultInventory>> | undefined;
    let key: Buffer | undefined;
    let failure: unknown;
    let phase = 'input preflight';
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
      fixture = await candidateDatabaseRecoveryFixture(input, root, continuation === '1');
      if (continuation === '1') {
        phase = 'sealed original binding and retained target reconciliation';
        // This path never opens the source DB or recreates original comparison
        // metadata. It resumes only the database recovery slice, not consumed
        // business effects or the fresh run's later adversarial native commands.
        if (input.phase === 'RETIRED') original = await retiredInputs(root, input, control);
        await fixture.restoreRetained({
          control,
          vaultDirectory: original?.custody.vaultDirectory,
        });
        const target = track(await fixture.target());
        await assertCandidateMigrationJournals(target);
        if (input.phase === 'RETIRED') await assertRetiredState(target, control, input, original!);
        else await assertPristineSource(control, input);
        await fixture.assertSourceFenced();
      } else {
        const source = track(await fixture.source());
        phase = 'original schema and state';
        await assertCandidateMigrationJournals(source);
        await assertCandidateAclComparison(source);
        const security = await candidateDatabaseSecurity(source);
        const before = await candidateDatabaseSnapshot(source);
        const controlBefore = await controlSnapshot(control, input.participantId);
        for (const role of [
          'openpc_indexer_writer',
          'openpc_indexer_manager',
          'openpc_candidate_index_reader',
        ] as const) {
          const current = track(await fixture.source(role));
          expect(
            (await current.query('select current_database() database,current_user,session_user'))
              .rows[0],
          ).toEqual({ database: 'openpc_candidate_index', current_user: role, session_user: role });
          await close(current);
        }
        let qualified;
        if (input.phase === 'PRISTINE') {
          qualified = await assertPristineSource(control, input);
          expect(
            (
              await source.query(
                "select count(*)::int count from pg_sequences where schemaname='candidate' and last_value is not null",
              )
            ).rows[0].count,
          ).toBe(0);
          for (const [table, rows] of Object.entries(before))
            if (
              !table.startsWith('sequence.') &&
              ![
                'candidate.schema_migration',
                'candidate.retirement_capability_secret',
                'openpc_local.migration',
              ].includes(table)
            )
              expect(rows, `BLOCKED: pre-first-publication requires empty ${table}`).toEqual([]);
        } else {
          original = await retiredInputs(root, input, control);
          await assertRetiredState(source, control, input, original);
          preparedReadback = await targetConfiguration(root, input, original);
          await assertNativeCapability(source, preparedReadback.configuration.capabilitySecretFile);
          expect(
            await nativeReadback(
              input.nativeExecutable,
              input.nativeConfigurationFile,
              original.attempt,
            ),
          ).toEqual({
            identity: 'OPENPC-CANDIDATE-RETIREMENT-TARGET-1',
            hostDigest: retirementWireDigest(original.host),
            result: { state: 'TERMINAL', signedWireHex: original.terminal.signedOutcome },
          });
          originalVault = await vaultInventory(root, original.custody.vaultDirectory);
          key = await readFile(original.custody.keyFile);
          expect(key.length).toBe(32);
          const payload = await archiveRead(worker, original, key);
          try {
            expect(payload.equals(original.expected)).toBe(true);
          } finally {
            payload.fill(0);
          }
        }
        // No component source connection survives the independently checked zero-
        // session gate. Canonical stopped external owners; no session is killed here.
        await close(source);
        phase = 'fenced original dump and isolated restore';
        const bound = await fixture.restore({
          control,
          vaultDirectory: original?.custody.vaultDirectory,
        });
        assertCandidateRecoveryComparison(bound.original.comparison, {
          data: candidateRecoveryData(before),
          security: candidateRecoverySecurity(security),
          control: candidateRecoveryData(controlBefore, 'control.'),
          vault: originalVault ?? null,
        });
        const target = track(await fixture.target());
        phase = 'restored migration journals';
        await assertCandidateMigrationJournals(target);
        phase = 'restored security metadata';
        expect(await candidateDatabaseSecurity(target)).toEqual(security);
        phase = 'restored data and sequences';
        expect(await candidateDatabaseSnapshot(target)).toEqual(before);
        phase = 'real sequence and security comparison sensitivity';
        await assertCandidateRecoveryComparisonSensitivity(target);
        expect(await candidateDatabaseSnapshot(target)).toEqual(before);
        expect(await candidateDatabaseSecurity(target)).toEqual(security);
        phase = 'unchanged Control state after restore';
        expect(await controlSnapshot(control, input.participantId)).toEqual(controlBefore);
        for (const role of [
          'openpc_indexer_writer',
          'openpc_indexer_manager',
          'openpc_candidate_index_reader',
        ] as const) {
          const old = track(await fixture.source(role));
          await expect(old.query('select 1')).rejects.toMatchObject({ code: '55000' });
          await close(old);
          const restored = track(await fixture.target(role));
          expect(
            (await restored.query('select current_database() database,current_user,session_user'))
              .rows[0],
          ).toEqual({ database: 'openpc_candidate_index', current_user: role, session_user: role });
          await close(restored);
        }
        if (input.phase === 'PRISTINE')
          expect(await assertPristineSource(control, input)).toEqual(qualified);
        else {
          if (!original || !key || !preparedReadback || !originalVault)
            throw new Error('BLOCKED: original retired inputs unavailable');
          await assertRetiredState(target, control, input, original);
          const installed = preparedReadback;
          // Source preflight checked the original capability fingerprint. The
          // restored full-table snapshot above includes that exact private row.
          const writer = track(await fixture.target('openpc_indexer_writer'));
          const manager = track(await fixture.target('openpc_indexer_manager'));
          const reader = track(await fixture.target('openpc_candidate_index_reader'));
          const columns = (
            await target.query<{ name: string }>(
              `select quote_ident(attname) name from pg_attribute where attrelid='candidate.candidate_event'::regclass
         and attnum>0 and not attisdropped and attgenerated='' and attidentity<>'a' order by attnum`,
            )
          ).rows
            .map((row) => row.name)
            .join(',');
          const preserved = original,
            originalKey = key;
          // Independent denials share this one setup. A failure is retained while
          // safe siblings continue; an unchanged-state failure blocks all dependents.
          const checks: [string, () => Promise<void>][] = [
            [
              'same-key original archive',
              async () => {
                const bytes = await archiveRead(worker, preserved, originalKey);
                try {
                  expect(bytes.equals(preserved.expected)).toBe(true);
                } finally {
                  bytes.fill(0);
                }
              },
            ],
            [
              'original native signed readback',
              async () => {
                const expected = {
                  identity: 'OPENPC-CANDIDATE-RETIREMENT-TARGET-1',
                  hostDigest: retirementWireDigest(preserved.host),
                  result: { state: 'TERMINAL', signedWireHex: preserved.terminal.signedOutcome },
                };
                expect(
                  await nativeReadback(input.nativeExecutable, installed.file, preserved.attempt),
                ).toEqual(expected);
                // A second process is restart readback, never another execution.
                expect(
                  await nativeReadback(input.nativeExecutable, installed.file, preserved.attempt),
                ).toEqual(expected);
              },
            ],
            [
              'wrong archive key',
              async () => {
                const wrong = Buffer.from(originalKey);
                wrong[0] = wrong[0]! ^ 1;
                try {
                  await expect(archiveRead(worker, preserved, wrong)).rejects.toThrow();
                } finally {
                  wrong.fill(0);
                }
              },
            ],
            [
              'absent archive key',
              async () => {
                await expect(archiveRead(worker, preserved, Buffer.alloc(0))).rejects.toThrow();
              },
            ],
            [
              'foreign archive scope',
              async () => {
                await expect(
                  archiveRead(worker, preserved, originalKey, foreignId),
                ).rejects.toThrow();
              },
            ],
            [
              'foreign native scope',
              async () => {
                const scope = { ...preserved.attempt.scope, privacy_domain_id: foreignId };
                await expect(
                  nativeReadback(input.nativeExecutable, installed.file, {
                    ...preserved.attempt,
                    scope,
                    selection_digest: retirementSelectionDigest(scope, preserved.attempt.selection),
                  }),
                ).rejects.toThrow();
              },
            ],
            [
              'original identity resurrection',
              async () => {
                await expect(
                  candidateScope(
                    writer,
                    input.participantId,
                    input.privacyDomainId,
                    (client) =>
                      client.query(
                        `insert into candidate.candidate_event(${columns}) select ${columns} from jsonb_populate_record(null::candidate.candidate_event,$1::jsonb)`,
                        [JSON.stringify(preserved.original.value)],
                      ),
                    false,
                  ),
                ).rejects.toMatchObject({
                  code: '23514',
                  message: 'OPENPC_RETIRED_CANDIDATE_GENERATION',
                });
              },
            ],
            [
              'generation revival',
              async () => {
                await expect(
                  candidateScope(
                    manager,
                    input.participantId,
                    input.privacyDomainId,
                    (client) =>
                      client.query(
                        "update candidate.projection_generation set state='ACTIVE' where projection_generation_id=$1",
                        [preserved.custody.request.generationId],
                      ),
                    false,
                  ),
                ).rejects.toMatchObject({
                  code: '23514',
                  message: 'OPENPC_RETIRED_CANDIDATE_READINESS',
                });
              },
            ],
            [
              'foreign native retained identity',
              async () => {
                expect(
                  (
                    await candidateScope(reader, input.participantId, foreignId, (client) =>
                      client.query(
                        'select 1 from candidate.retained_candidate_identity where candidate_event_id=$1',
                        [preserved.custody.request.candidateId],
                      ),
                    )
                  ).rowCount,
                ).toBe(0);
              },
            ],
          ];
          for (const variant of ['wrong', 'absent'] as const)
            checks.push([
              `${variant} native signing key`,
              async () => {
                const keyFile = join(input.backupDirectory, `${variant}-native-signing-key.hex`);
                if (variant === 'wrong') {
                  const bytes = randomBytes(32);
                  try {
                    await writeFile(keyFile, bytes.toString('hex'), { flag: 'wx', mode: 0o600 });
                  } finally {
                    bytes.fill(0);
                  }
                } else await expect(lstat(keyFile)).rejects.toMatchObject({ code: 'ENOENT' });
                const file = join(
                  input.backupDirectory,
                  `${variant}-native-key-configuration.json`,
                );
                await writeFile(
                  file,
                  JSON.stringify({ ...installed.configuration, targetSigningKeyFile: keyFile }),
                  { flag: 'wx', mode: 0o600 },
                );
                await expect(
                  nativeReadback(input.nativeExecutable, file, preserved.attempt),
                ).rejects.toThrow();
              },
            ]);
          let first: Error | undefined;
          for (const [name, check] of checks) {
            phase = name;
            try {
              await check();
            } catch {
              first ??= new Error(`Candidate recovery assertion failed: ${name}`);
            }
            // Any unexpected durable change stops dependent observations immediately.
            expect(await candidateDatabaseSnapshot(target)).toEqual(before);
            expect(await controlSnapshot(control, input.participantId)).toEqual(controlBefore);
            expect(await vaultInventory(root, preserved.custody.vaultDirectory)).toEqual(
              originalVault,
            );
          }
          if (first) throw first;
        }
        phase = 'final preserved state and old-writer fence';
        await fixture.assertSourceFenced();
        expect(await candidateDatabaseSnapshot(target)).toEqual(before);
        expect(await candidateDatabaseSecurity(target)).toEqual(security);
        expect(await controlSnapshot(control, input.participantId)).toEqual(controlBefore);
      }
    } catch (error) {
      // Driver/SQL errors can carry credential-bearing input or raw payloads. Keep
      // the failing phase and original private backup; never print those details.
      failure = new Error(
        `Candidate component recovery FAIL/BLOCKED (retained state UNKNOWN) at ${phase}${
          error instanceof Error && error.message.startsWith('Candidate recovery assertion failed:')
            ? ` (${error.message})`
            : ''
        }`,
      );
    } finally {
      key?.fill(0);
      original?.expected.fill(0);
      for (const pool of pools)
        try {
          await pool.end();
        } catch {
          failure ??= new Error('Candidate recovery pool cleanup failed');
        }
      try {
        await fixture?.close();
      } catch {
        failure ??= new Error('Candidate recovery administrator cleanup failed');
      }
    }
    if (failure) throw failure;
  },
  240000,
);
