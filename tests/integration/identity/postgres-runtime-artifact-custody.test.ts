import { readFile, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { z } from 'zod';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { readArchivedSourceRecords } from '../../../services/control-api/src/evidence/archive-source-readback.js';
import {
  readRuntimeArtifactArchiveSource,
  runtimeArtifactArchiveRequest,
} from '../../../services/control-api/src/evidence/runtime-artifact-archive-source.js';
import { reconstructRuntimeArtifactArchive } from '../../../services/control-api/src/evidence/runtime-artifact-archive-contract.js';
import { evidenceScope } from '../../../services/control-api/src/evidence/segment.js';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { prepareRuntimeArtifactArchive } from '../../../services/control-api/src/evidence/runtime-artifact-archive-contract.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';

const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const scope = { participantId: id(), privacyDomainId: id() };
const scoped = <T>(pool: Pool, operation: (client: PoolClient) => Promise<T>) =>
  runScopedTransaction(
    pool,
    { ...scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
    id,
    operation,
  );

it.runIf(runtimeUrl && workerUrl)(
  'keeps native archive metadata worker-only and rejects a manifest without its original input',
  async () => {
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 }),
      worker = new Pool({ connectionString: workerUrl, max: 1 });
    try {
      for (const [pool, writable] of [
        [runtime, false],
        [worker, true],
      ] as const) {
        const grants = await pool.query(`select relrowsecurity,relforcerowsecurity,
        has_table_privilege(current_user,c.oid,'INSERT') as insert,
        has_table_privilege(current_user,c.oid,'UPDATE') as update,
        has_table_privilege(current_user,c.oid,'DELETE') as delete
        from pg_class c where c.oid='control.evidence_runtime_artifact_archive'::regclass`);
        expect(grants.rows).toEqual([
          {
            relrowsecurity: true,
            relforcerowsecurity: true,
            insert: writable,
            update: false,
            delete: false,
          },
        ]);
      }
      const bytes = Buffer.from('not a retained input');
      const prepared = prepareRuntimeArtifactArchive(
        {
          ...scope,
          runtimeConfigurationInputId: id(),
          moduleInstallationId: id(),
          moduleConfigurationGenerationId: id(),
          configurationDigest: sha256(bytes),
          configurationBytes: bytes.length,
          resourceBindingsDigest: sha256([]),
          createdAt: '2026-09-25T00:00:00.000000Z',
        },
        bytes,
      );
      const insert = () =>
        scoped(worker, (client) =>
          client.query(
            `insert into control.evidence_runtime_artifact_archive
      (participant_id,privacy_domain_id,stream_id,record_id,runtime_configuration_input_id,manifest,manifest_digest)
      values($1,$2,$3,$4,$5,$6,$7)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              'native-archive-test',
              prepared.groups.at(-1)![0]!.recordId,
              prepared.manifest.identity.runtimeConfigurationInputId,
              prepared.manifest,
              sha256(prepared.manifest),
            ],
          ),
        );
      await expect(insert()).rejects.toMatchObject({ code: 'P0002' });
      if (adminUrl) {
        const blocker = new Pool({ connectionString: adminUrl, max: 1 }),
          locked = await blocker.connect();
        try {
          await locked.query('begin');
          await locked.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
            `evidence-lifecycle:${scope.participantId}`,
          ]);
          await expect(insert()).rejects.toMatchObject({ message: 'PC-DATA-6007' });
        } finally {
          await locked.query('rollback');
          locked.release();
          await blocker.end();
        }
      }
      await scoped(worker, async (client) => {
        const rows = await client.query(
          'select count(*) n from control.evidence_runtime_artifact_archive where participant_id=$1 and privacy_domain_id=$2',
          [scope.participantId, scope.privacyDomainId],
        );
        expect(rows.rows[0]?.n).toBe('0');
      });
    } finally {
      await runtime.end();
      await worker.end();
    }
  },
);

it.runIf(runtimeUrl && adminUrl)(
  'serializes the new-use check and denies wrong scope, invalid digest and absent forced retirement scope',
  async () => {
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 }),
      admin = new Pool({ connectionString: adminUrl, max: 1 });
    const hash = Buffer.alloc(32, 7);
    try {
      await scoped(runtime, async (client) => {
        const result = await client.query(
          'select openpc.runtime_artifact_new_use_allowed($1,$2,$3) allowed',
          [scope.participantId, scope.privacyDomainId, hash],
        );
        expect(result.rows[0]?.allowed).toBe(true); // Only absence of a retirement; no execution authority.
      });
      for (const [participant, privacy, digest] of [
        [id(), scope.privacyDomainId, hash],
        [scope.participantId, id(), hash],
        [scope.participantId, scope.privacyDomainId, Buffer.alloc(31)],
      ] as const)
        await expect(
          scoped(runtime, (client) =>
            client.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3)', [
              participant,
              privacy,
              digest,
            ]),
          ),
        ).rejects.toMatchObject({ message: 'PC-AUTH-0005' });
      const lock = await admin.connect();
      try {
        await lock.query('begin');
        await lock.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
          `evidence-lifecycle:${scope.participantId}`,
        ]);
        await expect(
          scoped(runtime, (client) =>
            client.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3)', [
              scope.participantId,
              scope.privacyDomainId,
              hash,
            ]),
          ),
        ).rejects.toMatchObject({ message: 'PC-DATA-6007' });
      } finally {
        await lock.query('rollback');
        lock.release();
      }
      for (const defect of [
        'alter table control.runtime_artifact_retirement no force row level security',
        ...[
          'runtime_artifact_retirement_statement_guard',
          'runtime_artifact_retirement_guard',
          'runtime_artifact_retirement_commit_required',
        ].map((name) => `alter table control.runtime_artifact_retirement disable trigger ${name}`),
      ]) {
        const client = await admin.connect();
        try {
          await client.query('begin');
          await client.query('set local role openpc_control_owner');
          await client.query(defect);
          await client.query('set local role openpc_control_runtime');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [scope.participantId, scope.privacyDomainId, id()],
          );
          await expect(
            client.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3)', [
              scope.participantId,
              scope.privacyDomainId,
              hash,
            ]),
          ).rejects.toMatchObject({ message: 'RUNTIME-ARTIFACT-RETIREMENT-OWNER-UNAVAILABLE' });
        } finally {
          await client.query('rollback');
          client.release();
        }
      }
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
);

// Only real public/native-owner input identities are accepted here. No direct
// INSERT of configuration, work, approvals, receipts or retirement fixtures.
const originalCaseFile = process.env.OPENPC_RUNTIME_ARTIFACT_CUSTODY_FIXTURE;
const originalCase = z.strictObject({
  request: runtimeArtifactArchiveRequest,
  scope: evidenceScope,
  expectedDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  keyFile: z.string().refine(isAbsolute),
  keyId: z.string().min(1).max(160),
  vaultDirectory: z.string().refine(isAbsolute),
  sinkId: z.string().min(1).max(160),
  retentionUntil: z.iso.datetime({ precision: 6 }),
});
it.runIf(originalCaseFile && workerUrl)(
  'archives retained original native inputs through the worker and verifies vault readback and restart without duplicate custody',
  async () => {
    const file = await stat(originalCaseFile!);
    expect(file.isFile() && file.size <= 16384).toBe(true);
    const cases = z
      .array(originalCase)
      .min(1)
      .max(8)
      .parse(JSON.parse(await readFile(originalCaseFile!, 'utf8')));
    const pool = new Pool({ connectionString: workerUrl, max: 1 });
    try {
      for (const q of cases) {
        expect(q.scope.participantId).toBe(q.request.participantId);
        expect(q.scope.privacyDomainId).toBe(q.request.privacyDomainId);
        const keyStat = await stat(q.keyFile);
        expect(keyStat.isFile() && keyStat.size === 32 && (keyStat.mode & 0o077) === 0).toBe(true);
        const key = await readFile(q.keyFile);
        const resolveKey = async (keyId: string) => {
          expect(keyId).toBe(q.keyId);
          return key;
        };
        const transaction = <T>(operation: (client: PoolClient) => Promise<T>) =>
          runScopedTransaction(
            pool,
            { ...q.scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
            id,
            operation,
          );
        try {
          const original = await transaction((client) =>
            readRuntimeArtifactArchiveSource(client, q.request),
          );
          expect(original.manifest.identity.configurationDigest).toBe(q.expectedDigest);
          const custody = new EvidenceCustody(pool);
          const snapshot = () =>
            transaction(async (client) => {
              const result = await client.query(
                `select last_sequence::text as sequence,last_segment_digest as digest,used_bytes::text as bytes,
              (select count(*)::text from control.evidence_runtime_artifact_archive a where a.participant_id=s.participant_id and a.privacy_domain_id=s.privacy_domain_id and a.stream_id=s.stream_id) manifests,
              (select count(*)::text from control.evidence_runtime_artifact_archive_part a where a.participant_id=s.participant_id and a.privacy_domain_id=s.privacy_domain_id and a.stream_id=s.stream_id) parts
              from control.evidence_stream s where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
                [q.scope.participantId, q.scope.privacyDomainId, q.scope.streamId],
              );
              expect(result.rowCount).toBe(1);
              return result.rows[0];
            });
          const retained =
            process.env.OPENPC_RUNTIME_ARTIFACT_EXPECT_RETAINED === '1'
              ? await snapshot()
              : undefined;
          const ingest = () =>
            custody.ingestRuntimeArtifact(
              q.scope,
              q.request,
              { keyId: q.keyId, key },
              q.retentionUntil,
              16 * 1024 * 1024,
              resolveKey,
            );
          for (let n = 0; n <= original.groups.length; n++) {
            const admitted = await ingest();
            if (retained) expect(admitted).toBeNull();
            if (admitted === null) break;
            expect(n).toBeLessThan(original.groups.length);
          }
          const vault = await LocalEvidenceVault.open(q.vaultDirectory, q.sinkId);
          for (let n = 0; n <= original.groups.length; n++) {
            const exported = await custody.exportNext(q.scope, vault);
            if (retained) expect(exported).toBeNull();
            if (exported === null) break;
            expect(n).toBeLessThan(original.groups.length);
          }
          const before = await snapshot();
          if (retained) expect(before).toEqual(retained);
          expect(before.manifests).toBe('1');
          expect(before.parts).toBe(String(original.groups.flat().length));
          await transaction(async (client) => {
            const recordId = original.groups.at(-1)![0]!.recordId;
            const coverage = await client.query(
              'select openpc.runtime_artifact_archive_coverage($1,$2,$3,$4,$5) proof',
              [
                q.scope.participantId,
                q.scope.privacyDomainId,
                q.scope.streamId,
                recordId,
                [q.sinkId],
              ],
            );
            expect(coverage.rows[0]?.proof.state).toBe('COMPLETE');
            expect(coverage.rows[0]?.proof.authority).toBe('NONE');
            const ids = original.groups.flat().map((record) => record.recordId);
            const records = await readArchivedSourceRecords(
              client,
              q.scope,
              ids,
              resolveKey,
              vault,
            );
            const restored = reconstructRuntimeArtifactArchive(
              original.manifest.identity,
              ids.map((id) => records.get(id)!),
            );
            try {
              expect(sha256(restored.payload)).toBe(q.expectedDigest);
              expect(restored.manifest).toEqual(original.manifest);
            } finally {
              restored.payload.fill(0);
            }
          });
          const restarted = new EvidenceCustody(pool);
          expect(
            await restarted.ingestRuntimeArtifact(
              q.scope,
              q.request,
              { keyId: q.keyId, key },
              q.retentionUntil,
              16 * 1024 * 1024,
              resolveKey,
            ),
          ).toBeNull();
          expect(await restarted.exportNext(q.scope, vault)).toBeNull();
          expect(await snapshot()).toEqual(before);
          const after = await transaction((client) =>
            readRuntimeArtifactArchiveSource(client, q.request),
          );
          expect(after.manifest).toEqual(original.manifest);
          process.stdout.write(
            `OPENPC_RUNTIME_ARTIFACT_CUSTODY_ORIGINAL|PASS|input=${q.request.runtimeConfigurationInputId}|bytes=${original.manifest.identity.configurationBytes}|records=${before.parts}|vault=verified|restart=no-duplicate|authority=NONE\n`,
          );
        } finally {
          key.fill(0);
        }
      }
    } finally {
      await pool.end();
    }
  },
  120000,
);
