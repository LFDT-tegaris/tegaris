import { cp, lstat, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, sep } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { z } from 'zod';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import {
  evidenceScope,
  MAX_SEGMENT_BYTES,
} from '../../../services/control-api/src/evidence/segment.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  candidateArchiveRequest,
  reconstructCandidateArchive,
} from '../../../services/control-api/src/evidence/candidate-archive/contract.js';
import {
  candidateArchiveSource,
  readCandidateArchiveSource,
  nextCandidateArchiveRecords,
  retainCandidateArchive,
  readCandidateArchiveCoverage,
  readArchivedCandidatePayload,
} from '../../../services/control-api/src/evidence/candidate-archive/source.js';
import { controlDatabaseRecoveryFixture } from './control-database-recovery-fixture.js';

const caseFile = process.env.OPENPC_CANDIDATE_ARCHIVE_CASE_FILE;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = caseFile && workerUrl ? it.sequential : it.skip;
const absolute = z.string().refine(isAbsolute);
const governedCase = z.strictObject({
  source: candidateArchiveSource,
  request: candidateArchiveRequest,
  scope: evidenceScope,
  keyFile: absolute,
  keyId: z.string().min(1).max(160),
  retentionUntil: z.iso.datetime({ precision: 6 }),
  capacityBytes: z.number().int().min(1024).max(1073741824),
  vaultDirectory: absolute,
  sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  activeHoldId: z.uuidv7(),
});

// Component restore compares actual durable rows, including absence. It does
// not synthesize a retirement outcome, revive a credential or manufacture a
// positive tombstone case. Fingerprints keep private material out of test diffs.
const candidateRestoreTables = [
  'evidence_candidate_archive',
  'evidence_candidate_archive_part',
  'evidence_stream',
  'evidence_catalogue',
  'evidence_segment',
  'evidence_segment_payload',
  'evidence_checkpoint',
  'evidence_hold_coverage',
  'retention_hold',
  'retention_policy',
  'deletion_job',
  'evidence_deletion_item',
  'evidence_projection_retirement',
  'store_retirement_host',
  'store_retirement_verifier_key',
  'store_retirement_admission',
  'store_retirement_cancellation',
  'store_retirement_delivery',
  'store_retirement_outcome',
  'evidence_archive_trust',
  'evidence_archive_profile',
  'evidence_archive_receipt',
  'evidence_archive_outbox',
  'evidence_archive_commit_nonce',
  'evidence_archive_commit_key',
  'evidence_remote_archive_intent',
  'evidence_remote_archive_attempt',
  'mutation_evidence',
  'outbox_event',
  'credential',
  'session',
  'policy_generation',
  'runtime_configuration_generation',
] as const;
async function candidateRestoreSnapshot(pool: Pool, participantId: string) {
  const client = await pool.connect();
  try {
    await client.query('begin isolation level repeatable read read only');
    const rows: Record<string, string[]> = {};
    for (const table of candidateRestoreTables) {
      rows[table] = (
        await client.query<{ fingerprint: string }>(
          `select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') fingerprint
         from control.${table} t where participant_id=$1 order by fingerprint`,
          [participantId],
        )
      ).rows.map((row) => row.fingerprint);
    }
    const migrations = (
      await client.query<{ path: string; sha256: string; appliedAt: string }>(
        'select path,sha256,applied_at::text "appliedAt" from openpc_local.migration order by path',
      )
    ).rows;
    await client.query('rollback');
    return { rows, migrations };
  } catch (error) {
    await client.query('rollback').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
async function currentControlMigrationPaths() {
  const paths: string[] = [];
  for (const owner of ['identity', 'policy', 'control-api']) {
    const journal = z
      .object({
        entries: z.array(z.object({ tag: z.string().regex(/^[0-9]{4}_[a-zA-Z0-9_-]+$/u) })).min(1),
      })
      .parse(
        JSON.parse(
          await readFile(
            new URL(`../../../migrations/postgres/${owner}/meta/_journal.json`, import.meta.url),
            'utf8',
          ),
        ),
      );
    for (const entry of journal.entries)
      paths.push(`/migrations/postgres/${owner}/${entry.tag}.sql`);
  }
  return paths.sort();
}
it('validates candidate recovery migration journals before runtime allocation', async () => {
  const paths = await currentControlMigrationPaths();
  expect(new Set(paths).size).toBe(paths.length);
  for (const path of paths) {
    const file = new URL(`../../..${path}`, import.meta.url);
    expect((await lstat(file)).isFile(), path).toBe(true);
  }
});
async function candidateRestoreSecurity(pool: Pool) {
  const tables = ['evidence_candidate_archive', 'evidence_candidate_archive_part'];
  const relations = (
    await pool.query<{
      name: string;
      owner: string;
      rls: boolean;
      forced: boolean;
      runtimeRead: boolean;
      runtimeWrite: boolean;
      workerRead: boolean;
      workerInsert: boolean;
      workerChange: boolean;
      publicGrant: boolean;
      policies: unknown;
      constraints: unknown;
      grants: unknown;
    }>(
      `select c.relname name,pg_get_userbyid(c.relowner) owner,c.relrowsecurity rls,c.relforcerowsecurity forced,
    has_table_privilege('openpc_control_runtime',c.oid,'SELECT') "runtimeRead",
    has_table_privilege('openpc_control_runtime',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') "runtimeWrite",
    has_table_privilege('openpc_control_worker',c.oid,'SELECT') "workerRead",
    has_table_privilege('openpc_control_worker',c.oid,'INSERT') "workerInsert",
    has_table_privilege('openpc_control_worker',c.oid,'UPDATE,DELETE,TRUNCATE') "workerChange",
    exists(select 1 from aclexplode(c.relacl) a where a.grantee=0) "publicGrant",
    (select jsonb_agg(jsonb_build_object('name',p.polname,'command',p.polcmd,'permissive',p.polpermissive,
      'roles',(select jsonb_agg(case when role=0 then 'PUBLIC' else pg_get_userbyid(role) end order by role) from unnest(p.polroles) role),
      'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid)) order by p.polname)
      from pg_policy p where p.polrelid=c.oid) policies,
    (select jsonb_agg(jsonb_build_object('name',x.conname,'type',x.contype,'validated',x.convalidated,
      'deferrable',x.condeferrable,'deferred',x.condeferred,'definition',pg_get_constraintdef(x.oid)) order by x.conname)
      from pg_constraint x where x.conrelid=c.oid) constraints,
    (select jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(a.grantor),
      'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
      'privilege',a.privilege_type,'grantable',a.is_grantable) order by a.grantee,a.privilege_type)
      from aclexplode(c.relacl) a) grants
    from pg_class c where c.relnamespace='control'::regnamespace and c.relname=any($1::text[]) order by c.relname`,
      [tables],
    )
  ).rows;
  expect(relations.map((row) => row.name)).toEqual(tables);
  for (const row of relations)
    expect(row).toMatchObject({
      owner: 'openpc_control_owner',
      rls: true,
      forced: true,
      runtimeRead: true,
      runtimeWrite: false,
      workerRead: true,
      workerInsert: true,
      workerChange: false,
      publicGrant: false,
    });
  const triggers = (
    await pool.query(
      `select c.relname "table",t.tgname name,t.tgenabled enabled,
    pg_get_triggerdef(t.oid,false) definition from pg_trigger t join pg_class c on c.oid=t.tgrelid
    where c.relnamespace='control'::regnamespace and c.relname=any($1::text[]) and not t.tgisinternal
    order by c.relname,t.tgname`,
      [tables],
    )
  ).rows;
  expect(triggers.map((row) => row.name)).toEqual([
    'candidate_archive_guard',
    'candidate_archive_parts',
    'candidate_archive_part_guard',
  ]);
  for (const row of triggers) expect(row.enabled).toBe('O');
  const functions = (
    await pool.query(
      `select p.proname name,pg_get_userbyid(p.proowner) owner,
    pg_get_function_identity_arguments(p.oid) arguments,pg_get_functiondef(p.oid) definition,
    p.prosecdef definer,p.proconfig configuration,
    (select jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(a.grantor),
      'grantee',case when a.grantee=0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end,
      'privilege',a.privilege_type,'grantable',a.is_grantable) order by a.grantee,a.privilege_type)
      from aclexplode(p.proacl) a) grants
    from pg_proc p where p.pronamespace='openpc'::regnamespace and p.proname=any($1::text[]) order by p.proname`,
      [
        [
          'guard_candidate_archive',
          'index_candidate_archive_parts',
          'guard_candidate_archive_part',
          'candidate_archive_hold_metadata',
          'candidate_archive_coverage',
        ],
      ],
    )
  ).rows;
  expect(functions).toHaveLength(5);
  for (const row of functions) expect(row.owner).toBe('openpc_control_owner');
  return { relations, triggers, functions };
}
async function candidateRestoreVaultInventory(directory: string) {
  const result: { name: string; digest: string; bytes: number }[] = [];
  for (const name of (await readdir(directory)).sort()) {
    if (!/^[a-f0-9]{64}\.(?:segment|hold-[12])$/u.test(name))
      throw new Error('BLOCKED: candidate vault contains an unfinished or unknown object');
    const file = join(directory, name),
      stat = await lstat(file);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      (stat.mode & 0o077) !== 0 ||
      stat.size > MAX_SEGMENT_BYTES * 2
    )
      throw new Error('BLOCKED: candidate vault object is not a bounded private regular file');
    const bytes = await readFile(file);
    result.push({ name, digest: sha256(bytes), bytes: bytes.length });
  }
  return result;
}

// Consumes original candidate + hold identities created by the existing real
// governed source/hold journeys. No intermediate candidate/publication/approval/
// delivery state, custody receipt or target eligibility is seeded by this test.
// Shared migration/ingestion/CI registration belongs to the canonical integrator.
integration(
  'archives a real governed candidate with original-byte restart, no-effect denials and hold coverage on every segment',
  async () => {
    const fixture = governedCase.parse(
      JSON.parse(await readFile(absolute.parse(caseFile), 'utf8')),
    );
    const key = await readFile(fixture.keyFile);
    expect(key.length).toBe(32);
    const pool = new Pool({
      connectionString: workerUrl,
      max: 2,
      connectionTimeoutMillis: 5000,
      statement_timeout: 30000,
    });
    const custody = new EvidenceCustody(pool);
    const resolveKey = async (keyId: string) => {
      if (keyId !== fixture.keyId) throw new Error('Original candidate archive key unavailable');
      return key;
    };
    const sink = await LocalEvidenceVault.open(fixture.vaultDirectory, fixture.sinkId);
    async function transaction<T>(work: (client: PoolClient) => Promise<T>) {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [fixture.scope.participantId, fixture.scope.privacyDomainId, id()],
        );
        const result = await work(client);
        await client.query('commit');
        return result;
      } catch (error) {
        await client.query('rollback').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    }
    const count = () =>
      transaction(
        async (client) =>
          (
            await client.query(
              'select count(*)::int count from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
              [fixture.scope.participantId, fixture.scope.privacyDomainId, fixture.scope.streamId],
            )
          ).rows[0].count as number,
      );
    const ingest = (capacity = fixture.capacityBytes) =>
      custody.ingestCandidate(
        fixture.scope,
        fixture.source,
        fixture.request,
        { keyId: fixture.keyId, key },
        fixture.retentionUntil,
        capacity,
        resolveKey,
      );
    const retained = () =>
      transaction(
        async (client) =>
          (
            await client.query(
              'select 1 from control.evidence_candidate_archive where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and candidate_id=$4',
              [
                fixture.scope.participantId,
                fixture.scope.privacyDomainId,
                fixture.scope.streamId,
                fixture.request.candidateId,
              ],
            )
          ).rowCount === 1,
      );
    try {
      const prepared = await readCandidateArchiveSource(fixture.source, fixture.request);
      expect(prepared.manifest.identity.participantId).toBe(fixture.scope.participantId);
      expect(prepared.manifest.identity.privacyDomainId).toBe(fixture.scope.privacyDomainId);
      const expected = reconstructCandidateArchive(prepared.manifest, prepared.batches.flat());
      try {
        // This hold is a real signed/governed existing effect, not a fixture flag.
        await transaction(async (client) => {
          const hold = await client.query(
            `select 1 from control.retention_hold h where h.participant_id=$1 and h.retention_hold_id=$2 and h.state='ACTIVE'
           and (h.selector_type='PARTICIPANT' or h.privacy_domain_id=$3)`,
            [fixture.scope.participantId, fixture.activeHoldId, fixture.scope.privacyDomainId],
          );
          expect(hold.rowCount).toBe(1);
        });
        const before = await count();
        await expect(
          readCandidateArchiveSource(fixture.source, { ...fixture.request, privacyDomainId: id() }),
        ).rejects.toThrow();
        await expect(
          readCandidateArchiveSource(fixture.source, { ...fixture.request, candidateId: id() }),
        ).rejects.toThrow();
        expect(await count()).toBe(before);
        // Deterministic capacity failure through the actual custody transaction.
        // The same business source is preserved; no retry varies its identity.
        if (before === 0) {
          expect(
            await transaction((client) =>
              retainCandidateArchive(client, fixture.scope, prepared.manifest, resolveKey),
            ),
          ).toBe(false);
          await expect(
            transaction(async (client) => {
              await client.query(
                'insert into control.evidence_candidate_archive(participant_id,privacy_domain_id,stream_id,record_id,candidate_id,manifest,manifest_digest) values($1,$2,$3,$4,$5,$6,$7)',
                [
                  fixture.scope.participantId,
                  fixture.scope.privacyDomainId,
                  fixture.scope.streamId,
                  prepared.manifestRecord.recordId,
                  fixture.request.candidateId,
                  prepared.manifest,
                  sha256(prepared.manifest),
                ],
              );
            }),
          ).rejects.toThrow();
          await expect(ingest(1024)).rejects.toMatchObject({ code: 'CAPACITY' });
          expect(await count()).toBe(0);
        }
        let observedPending = false;
        for (let phase = 0; phase <= prepared.batches.length; phase++) {
          const batch = await transaction((client) =>
            nextCandidateArchiveRecords(client, fixture.scope, prepared, resolveKey),
          );
          if (batch.length === 0) break;
          // The first chunk remains incomplete. Concurrent continuation then
          // serializes through the real custody owner without holes or duplicates.
          if (phase === 0) await ingest();
          else await Promise.all([ingest(), ingest()]);
          if (!(await retained())) observedPending = true;
        }
        expect(await retained()).toBe(true);
        expect(await ingest()).toBeNull();
        await transaction(async (client) => {
          const metadata = await client.query<{ metadata: Record<string, unknown> }>(
            `select openpc.evidence_hold_record_metadata(c) metadata from control.evidence_catalogue c
             where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence`,
            [fixture.scope.participantId, fixture.scope.privacyDomainId, fixture.scope.streamId],
          );
          expect(metadata.rowCount).toBe(prepared.batches.flat().length);
          for (const row of metadata.rows) {
            expect(row.metadata.projections).toEqual([
              `urn:openpc:resource:${prepared.manifest.identity.projectionId}`,
            ]);
            expect(row.metadata.unresolvedReferences).toBe(true);
          }
        });
        expect(
          await transaction((client) =>
            nextCandidateArchiveRecords(client, fixture.scope, prepared, resolveKey),
          ),
        ).toEqual([]);
        if (before === 0) expect(observedPending).toBe(true);
        const originalCount = await count();
        await expect(
          transaction((client) =>
            nextCandidateArchiveRecords(client, fixture.scope, prepared, async () =>
              randomBytes(32),
            ),
          ),
        ).rejects.toThrow();
        const corrupt = structuredClone(prepared);
        corrupt.batches[0]![0]!.receiptBase64 = 'AQ==';
        await expect(
          transaction((client) =>
            nextCandidateArchiveRecords(client, fixture.scope, corrupt, resolveKey),
          ),
        ).rejects.toThrow();
        expect(await count()).toBe(originalCount);
        await expect(
          transaction((client) =>
            readCandidateArchiveCoverage(
              client,
              { ...fixture.scope, privacyDomainId: id() },
              prepared.manifest,
              [fixture.sinkId],
            ),
          ),
        ).rejects.toThrow();
        expect(
          (
            await transaction((client) =>
              readCandidateArchiveCoverage(client, fixture.scope, prepared.manifest, [
                'missing-candidate-sink',
              ]),
            )
          ).state,
        ).toBe('PENDING');

        let coverage = await transaction((client) =>
          readCandidateArchiveCoverage(client, fixture.scope, prepared.manifest, [fixture.sinkId]),
        );
        const initiallyComplete = coverage.state === 'COMPLETE';
        if (before === 0) expect(coverage.state).toBe('PENDING');
        for (let attempt = 0; attempt < 256 && coverage.state !== 'COMPLETE'; attempt++) {
          await custody.exportNext(fixture.scope, sink);
          await custody.reconcileHolds(fixture.scope, sink);
          coverage = await transaction((client) =>
            readCandidateArchiveCoverage(client, fixture.scope, prepared.manifest, [
              fixture.sinkId,
            ]),
          );
          if (before === 0 && attempt === 0) expect(coverage.state).toBe('PENDING');
        }
        expect(coverage.state).toBe('COMPLETE');
        if (coverage.state !== 'COMPLETE')
          throw new Error('Candidate archive checkpoints remain incomplete');
        expect(coverage.segments.length).toBeGreaterThanOrEqual(2);
        await transaction(async (client) => {
          const covered = await client.query<{ segment_id: string }>(
            `select c.segment_id::text from control.evidence_hold_coverage c join control.retention_hold h
           on h.participant_id=c.participant_id and h.retention_hold_id=c.retention_hold_id and h.revision=c.hold_revision
           where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.retention_hold_id=$4
           and c.sink_id=$5 and c.segment_id=any($6::uuid[])`,
            [
              fixture.scope.participantId,
              fixture.scope.privacyDomainId,
              fixture.scope.streamId,
              fixture.activeHoldId,
              fixture.sinkId,
              coverage.state === 'COMPLETE'
                ? coverage.segments.map((segment) => segment.segmentId)
                : [],
            ],
          );
          expect(new Set(covered.rows.map((row) => row.segment_id)).size).toBe(
            coverage.state === 'COMPLETE' ? coverage.segments.length : 0,
          );
        });
        // Fresh owner/vault objects simulate restart. Recovery never consults the
        // native payload or re-acquires/re-publishes the original business intent.
        const restartedSink = await LocalEvidenceVault.open(fixture.vaultDirectory, fixture.sinkId);
        const restored = await transaction((client) =>
          readArchivedCandidatePayload(
            client,
            fixture.scope,
            prepared.manifest,
            restartedSink,
            resolveKey,
          ),
        );
        expect(restored).toEqual(expected);
        restored.fill(0);
        const replayed = await new EvidenceCustody(pool).exportNext(fixture.scope, restartedSink);
        if (!initiallyComplete) expect(replayed).toBeNull();
        expect(await count()).toBe(originalCount);
        for (const mutation of [
          'update control.evidence_candidate_archive set manifest_digest=manifest_digest where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
          'delete from control.evidence_candidate_archive_part where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
        ])
          await expect(
            transaction(async (client) => {
              await client.query(mutation, [
                fixture.scope.participantId,
                fixture.scope.privacyDomainId,
                fixture.scope.streamId,
              ]);
            }),
          ).rejects.toThrow();
        // The original source remains available and unchanged; archive production
        // has not retired anything or granted candidate/Fact readiness.
        expect(
          (await readCandidateArchiveSource(fixture.source, fixture.request)).manifest,
        ).toEqual(prepared.manifest);
      } finally {
        expected.fill(0);
      }
    } finally {
      key.fill(0);
      await pool.end();
    }
  },
  120000,
);

// The ordinary custody caller uses retained business state and must never select
// destructive recovery implicitly. The canonical isolated participant runner
// selects O2a explicitly with OPENPC_CANDIDATE_CONTROL_RESTORE=1. Once selected,
// missing governed inputs fail BLOCKED rather than skip or clone retained state.
const restoreRequested = process.env.OPENPC_CANDIDATE_CONTROL_RESTORE;
const restoreIntegration = restoreRequested === undefined ? it.skip : it.sequential;
restoreIntegration(
  'restores populated candidate custody with original bytes, hold coverage and fenced old writers (O2a)',
  async () => {
    if (restoreRequested !== '1')
      throw new Error('BLOCKED: candidate Control restore selection must be exactly 1');
    if (!caseFile || !adminUrl || !workerUrl || !runtimeUrl || !process.env.OPENPC_TEST_TMP_ROOT)
      throw new Error(
        'BLOCKED: O2a requires the original governed candidate case in an isolated participant recovery fixture',
      );
    const recovery = await controlDatabaseRecoveryFixture(
      'evidence-candidate-restore.dump',
      dirname(caseFile),
    );
    const root = await realpath(process.env.OPENPC_TEST_TMP_ROOT);
    const requireOwnedInput = async (file: string, newDirectory = false) => {
      const child = relative(root, file);
      if (
        !isAbsolute(file) ||
        child === '' ||
        child === '..' ||
        child.startsWith(`..${sep}`) ||
        isAbsolute(child) ||
        (await realpath(dirname(file))) !== dirname(file)
      )
        throw new Error('BLOCKED: candidate recovery inputs must belong to this isolated fixture');
      try {
        const stat = await lstat(file);
        if ((await realpath(file)) !== file || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
          throw new Error('BLOCKED: candidate recovery input must be private and nonsymlink');
      } catch (error) {
        if (
          !newDirectory ||
          !(error instanceof Error) ||
          !('code' in error) ||
          error.code !== 'ENOENT'
        )
          throw error;
      }
    };
    await requireOwnedInput(caseFile);
    const fixture = governedCase.parse(JSON.parse(await readFile(caseFile, 'utf8')));
    await requireOwnedInput(fixture.keyFile);
    await requireOwnedInput(fixture.vaultDirectory, true);
    await requireOwnedInput(fixture.source.configurationFile);
    const key = await readFile(fixture.keyFile);
    if (key.length !== 32) {
      key.fill(0);
      throw new Error('BLOCKED: original candidate archive key is invalid');
    }
    const pools = new Set<Pool>();
    const connect = (connectionString: string) => {
      const pool = new Pool({
        connectionString,
        max: 2,
        connectionTimeoutMillis: 5000,
        statement_timeout: 30000,
      });
      pools.add(pool);
      return pool;
    };
    const closePools = async () => {
      const current = [...pools];
      pools.clear();
      const outcomes = await Promise.allSettled(current.map((pool) => pool.end()));
      const failures = outcomes.flatMap((outcome) =>
        outcome.status === 'rejected' ? [outcome.reason as unknown] : [],
      );
      if (failures.length)
        throw new AggregateError(failures, 'Candidate recovery connection shutdown failed');
    };
    const scoped = async <T>(
      pool: Pool,
      scope: typeof fixture.scope,
      work: (client: PoolClient) => Promise<T>,
    ) => {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query('set local row_security=on');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [scope.participantId, scope.privacyDomainId, id()],
        );
        const result = await work(client);
        // All post-restore probes are observations or forbidden-write probes.
        await client.query('rollback');
        return result;
      } catch (error) {
        await client.query('rollback').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    };
    const resolveKey = async (keyId: string) => {
      if (keyId !== fixture.keyId) throw new Error('Original candidate archive key unavailable');
      return key;
    };
    let originalBytes: Buffer | undefined;
    let scratch: string | undefined;
    let failed = false;
    let firstFailure: unknown;
    try {
      let admin = connect(adminUrl),
        worker = connect(workerUrl);
      const prepared = await readCandidateArchiveSource(fixture.source, fixture.request);
      expect(prepared.manifest.identity.participantId).toBe(fixture.scope.participantId);
      expect(prepared.manifest.identity.privacyDomainId).toBe(fixture.scope.privacyDomainId);
      expect(prepared.manifest.authority).toBe('NONE');
      expect(prepared.manifest.currentReadiness).toBe('NOT_ESTABLISHED');
      originalBytes = reconstructCandidateArchive(prepared.manifest, prepared.batches.flat());
      const originalKeyDigest = sha256(key);
      const custody = new EvidenceCustody(worker);
      const sink = await LocalEvidenceVault.open(fixture.vaultDirectory, fixture.sinkId);
      // Require the original real governed hold before admitting archive work.
      const hold = (
        await admin.query(
          `select revision::text from control.retention_hold
        where participant_id=$1 and retention_hold_id=$2 and state='ACTIVE'
          and (selector_type='PARTICIPANT' or privacy_domain_id=$3)`,
          [fixture.scope.participantId, fixture.activeHoldId, fixture.scope.privacyDomainId],
        )
      ).rows;
      expect(hold, 'BLOCKED: original governed hold unavailable').toHaveLength(1);
      for (let phase = 0; phase <= prepared.batches.length; phase++) {
        const pending = await scoped(worker, fixture.scope, (client) =>
          nextCandidateArchiveRecords(client, fixture.scope, prepared, resolveKey),
        );
        if (pending.length === 0) break;
        await custody.ingestCandidate(
          fixture.scope,
          fixture.source,
          fixture.request,
          { keyId: fixture.keyId, key },
          fixture.retentionUntil,
          fixture.capacityBytes,
          resolveKey,
        );
      }
      expect(
        await scoped(worker, fixture.scope, (client) =>
          nextCandidateArchiveRecords(client, fixture.scope, prepared, resolveKey),
        ),
      ).toEqual([]);
      const coverage = () =>
        scoped(worker, fixture.scope, (client) =>
          readCandidateArchiveCoverage(client, fixture.scope, prepared.manifest, [fixture.sinkId]),
        );
      let covered = await coverage();
      for (let step = 0; covered.state !== 'COMPLETE' && step < 256; step++) {
        await custody.exportNext(fixture.scope, sink);
        await custody.reconcileHolds(fixture.scope, sink);
        covered = await coverage();
      }
      expect(
        covered.state,
        'BLOCKED: all candidate segments and current hold coverage required',
      ).toBe('COMPLETE');
      if (covered.state !== 'COMPLETE') throw new Error('BLOCKED: candidate custody incomplete');
      expect(covered.authority).toBe('NONE');
      expect(covered.segments.length).toBeGreaterThanOrEqual(2);
      const protectedSegments = (
        await admin.query<{ segmentId: string }>(
          `select segment_id::text "segmentId" from control.evidence_hold_coverage
         where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and retention_hold_id=$4
           and hold_revision=$5 and sink_id=$6 order by segment_id`,
          [
            fixture.scope.participantId,
            fixture.scope.privacyDomainId,
            fixture.scope.streamId,
            fixture.activeHoldId,
            hold[0].revision,
            fixture.sinkId,
          ],
        )
      ).rows.map((row) => row.segmentId);
      for (const segment of covered.segments)
        expect(protectedSegments).toContain(segment.segmentId);
      const readPayload = (vault: LocalEvidenceVault, resolver = resolveKey) =>
        scoped(worker, fixture.scope, (client) =>
          readArchivedCandidatePayload(client, fixture.scope, prepared.manifest, vault, resolver),
        );
      const originalReadback = await readPayload(sink);
      try {
        expect(originalReadback.equals(originalBytes)).toBe(true);
      } finally {
        originalReadback.fill(0);
      }
      // Copy only owned immutable encrypted archive files; keys remain at their
      // original installation path and are never included in a new artifact.
      scratch = await mkdtemp(join(dirname(caseFile), 'candidate-restore-'));
      const vaultBefore = await candidateRestoreVaultInventory(fixture.vaultDirectory);
      const recoveredVault = join(scratch, 'vault');
      await cp(fixture.vaultDirectory, recoveredVault, {
        recursive: true,
        force: false,
        errorOnExist: true,
      });
      expect(await candidateRestoreVaultInventory(recoveredVault)).toEqual(vaultBefore);
      const before = await candidateRestoreSnapshot(admin, fixture.scope.participantId);
      const securityBefore = await candidateRestoreSecurity(admin);
      const installedPaths = new Set(before.migrations.map((row) => row.path));
      for (const path of await currentControlMigrationPaths())
        expect(installedPaths.has(path), `BLOCKED: current migration not applied: ${path}`).toBe(
          true,
        );
      for (const table of [
        'evidence_candidate_archive',
        'evidence_candidate_archive_part',
        'evidence_catalogue',
        'evidence_checkpoint',
        'evidence_hold_coverage',
        'mutation_evidence',
        'outbox_event',
      ])
        expect(before.rows[table]!.length, `populated original ${table}`).toBeGreaterThan(0);
      // Close every caller connection. The shared owner independently refuses
      // any other connected source, fences it permanently, and restores once.
      await closePools();
      await recovery.restore();
      admin = connect(recovery.adminUrl);
      worker = connect(recovery.workerUrl);
      const runtime = connect(recovery.runtimeUrl);
      expect(await candidateRestoreSnapshot(admin, fixture.scope.participantId)).toEqual(before);
      expect(await candidateRestoreSecurity(admin)).toEqual(securityBefore);
      for (const originalUrl of [workerUrl, runtimeUrl]) {
        const old = connect(originalUrl);
        await expect(old.query('select 1')).rejects.toMatchObject({ code: '55000' });
        pools.delete(old);
        await old.end();
      }
      const role = (
        await worker.query(`select rolsuper,rolbypassrls,
        pg_has_role(current_user,'openpc_control_owner','MEMBER') owner
        from pg_roles where rolname=current_user`)
      ).rows;
      expect(role).toEqual([{ rolsuper: false, rolbypassrls: false, owner: false }]);
      const reopened = await LocalEvidenceVault.open(recoveredVault, fixture.sinkId);
      expect(await coverage()).toEqual(covered);
      const restoredBytes = await readPayload(reopened);
      try {
        expect(restoredBytes.equals(originalBytes)).toBe(true);
      } finally {
        restoredBytes.fill(0);
      }
      expect(sha256(key)).toBe(originalKeyDigest);
      const retainedKey = await readFile(fixture.keyFile);
      try {
        expect(sha256(retainedKey)).toBe(originalKeyDigest);
      } finally {
        retainedKey.fill(0);
      }
      expect(prepared.manifest).toMatchObject({
        authority: 'NONE',
        currentReadiness: 'NOT_ESTABLISHED',
      });
      // Continue only the existing observation owner; no native source read,
      // ingest, export, reapproval or new target execution runs after restore.
      expect(
        await scoped(worker, fixture.scope, (client) =>
          nextCandidateArchiveRecords(client, fixture.scope, prepared, resolveKey),
        ),
      ).toEqual([]);
      const expectedCounts = [1, prepared.manifest.chunks.length + 1];
      for (const [index, table] of [
        'evidence_candidate_archive',
        'evidence_candidate_archive_part',
      ].entries()) {
        const count = (pool: Pool, scope: typeof fixture.scope) =>
          scoped(
            pool,
            scope,
            async (client) =>
              (
                await client.query(
                  `select count(*)::int n from control.${table}
             where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
                  [
                    fixture.scope.participantId,
                    fixture.scope.privacyDomainId,
                    fixture.scope.streamId,
                  ],
                )
              ).rows[0].n,
          );
        expect(await count(runtime, fixture.scope)).toBe(expectedCounts[index]);
        for (const foreign of [
          { ...fixture.scope, participantId: id() },
          { ...fixture.scope, privacyDomainId: id() },
        ]) {
          expect(await count(runtime, foreign)).toBe(0);
          expect(await count(worker, foreign)).toBe(0);
        }
      }
      for (const pool of [runtime, worker])
        await expect(
          scoped(pool, fixture.scope, (client) =>
            client.query(
              `update control.evidence_candidate_archive set manifest_digest=manifest_digest
          where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
              [fixture.scope.participantId, fixture.scope.privacyDomainId, fixture.scope.streamId],
            ),
          ),
        ).rejects.toMatchObject({ code: '42501' });
      for (const foreign of [
        { ...fixture.scope, participantId: id() },
        { ...fixture.scope, privacyDomainId: id() },
      ])
        await expect(
          scoped(worker, foreign, (client) =>
            readArchivedCandidatePayload(client, foreign, prepared.manifest, reopened, resolveKey),
          ),
        ).rejects.toThrow();
      await expect(
        readPayload(reopened, async () => {
          throw new Error('Original candidate archive key unavailable');
        }),
      ).rejects.toThrow('Original candidate archive key unavailable');
      const wrongKey = Buffer.from(key);
      wrongKey[0] = wrongKey[0]! ^ 1;
      try {
        await expect(readPayload(reopened, async () => wrongKey)).rejects.toThrow();
      } finally {
        wrongKey.fill(0);
      }
      const missingSink = await LocalEvidenceVault.open(
        join(scratch, 'missing-sink'),
        `missing-candidate-${id()}`,
      );
      expect(
        (
          await scoped(worker, fixture.scope, (client) =>
            readCandidateArchiveCoverage(client, fixture.scope, prepared.manifest, [
              missingSink.sinkId,
            ]),
          )
        ).state,
      ).toBe('PENDING');
      await expect(readPayload(missingSink)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
      const missingObject = await LocalEvidenceVault.open(
        join(scratch, 'missing-object'),
        fixture.sinkId,
      );
      await expect(readPayload(missingObject)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
      const corruptPath = join(scratch, 'corrupt-vault');
      await cp(recoveredVault, corruptPath, { recursive: true, force: false, errorOnExist: true });
      const segmentName = `${sha256({
        sinkId: fixture.sinkId,
        participantId: fixture.scope.participantId,
        privacyDomainId: fixture.scope.privacyDomainId,
        streamId: fixture.scope.streamId,
        segmentId: covered.segments[0]!.segmentId,
      }).slice(7)}.segment`;
      expect(vaultBefore.some((entry) => entry.name === segmentName)).toBe(true);
      const corruptFile = join(corruptPath, segmentName);
      const corruptBytes = await readFile(corruptFile);
      corruptBytes[0] = corruptBytes[0]! ^ 1;
      await writeFile(corruptFile, corruptBytes, { mode: 0o600 });
      const corruptVault = await LocalEvidenceVault.open(corruptPath, fixture.sinkId);
      await expect(readPayload(corruptVault)).rejects.toMatchObject({ code: 'INTEGRITY' });
      expect(await candidateRestoreSnapshot(admin, fixture.scope.participantId)).toEqual(before);
      expect(await coverage()).toEqual(covered);
      expect(await candidateRestoreVaultInventory(recoveredVault)).toEqual(vaultBefore);
      expect(await candidateRestoreVaultInventory(fixture.vaultDirectory)).toEqual(vaultBefore);
      // Restored outbox/attempt absence stays absent, terminal bytes stay exact,
      // and all applicable tombstones/revocations/generations stay unchanged.
      // This does not qualify restoration of the separate physical candidate DB.
    } catch (error) {
      failed = true;
      firstFailure = error;
    }
    originalBytes?.fill(0);
    key.fill(0);
    let cleanupFailure: unknown;
    try {
      await closePools();
    } catch (error) {
      cleanupFailure = error;
    }
    if (cleanupFailure !== undefined)
      throw new AggregateError(
        failed ? [firstFailure, cleanupFailure] : [cleanupFailure],
        'Candidate restore result retained with connection cleanup failure',
      );
    if (failed) throw firstFailure;
    if (scratch) await rm(scratch, { recursive: true, force: true });
  },
  240_000,
);
