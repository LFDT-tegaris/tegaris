import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import {
  LocalEvidenceVault,
  sinkDurabilityReceipt,
} from '../../../services/control-api/src/evidence/local-vault.js';
import { archiveProtectedProof } from '../../../services/control-api/src/evidence/protected-custody.js';
import { LocalProtectedProofVault } from '../../../services/control-api/src/evidence/protected-vault.js';
import { protectedSinkReceipt } from '../../../services/control-api/src/evidence/protected-custody-contracts.js';
import { ProtectedRemoteArchiveCustody } from '../../../services/control-api/src/evidence/protected-remote-custody.js';
import { PostgresRemoteArchiveAttemptOwner } from '../../../services/control-api/src/evidence/remote-archive-owner.js';
import { RemoteEvidenceArchive } from '../../../services/control-api/src/evidence/remote-archive.js';
import {
  remoteArchiveIntent,
  remoteArchiveReceipt,
  retentionMicros,
  type RemoteArchiveProfile,
} from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { evidenceArchiveAuthorityFixture } from './evidence-archive-authority-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;
const repository = fileURLToPath(new URL('../../../', import.meta.url));
const execute = promisify(execFile);
const upgrades = [
  '0082_remote_archive_attempt.sql',
  '0083_remote_archive_custody.sql',
  '0084_remote_archive_export.sql',
  '0085_protected_object_version_identity.sql',
  '0086_protected_remote_archive.sql',
] as const;
const time = (offset: number) =>
  new Date(Date.now() + offset).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
type Scope = { participantId: string; privacyDomainId: string };
type Governance = Awaited<ReturnType<typeof contractAdministrationFixture>>;
type Signing = Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>;
interface ExternalArchive {
  endpoint: string;
  faults: { dropPutResponse: boolean; dropHoldResponse: boolean };
  counts: { puts: number; holds: number; gets: number; lists: number };
  close(): Promise<void>;
}
const fixtureUrl = new URL('../local-runtime/evidence-remote-archive-fixture.mjs', import.meta.url);
const { startRemoteArchiveFixture } = (await import(fixtureUrl.href)) as {
  startRemoteArchiveFixture(options: {
    root: string;
    bucket: string;
    expectedOwner: string;
    region: string;
    credentials: S3ArchiveCredentials;
  }): Promise<ExternalArchive>;
};

// Required runner wiring: initialize this file's disposable database with the
// unchanged Identity/Policy migrations and Control through 0081, retaining the
// ordinary current migration/script mounts and runtime-role bootstrap. The
// default all-current participant runner must fail this prerequisite, not turn
// a greenfield run into a claimed upgrade. No downgrade or business-row seeding.
//
// 0081 has local protected custody, but neither segment transport journals nor
// signed remote custody (0083) nor protected remote dispatch (0086). This case
// populates the local-only boundary. Existing unsigned 0082 attempts and signed
// 0083/0084 remote history need their actual predecessor runtime in another
// case; current PostgresRemoteArchiveAttemptOwner requires 0086 source columns.
// The local mutation/custody APIs used below retain their predecessor implementation;
// current hold coverage readback is deliberately used only after migration.
// Database backup/restore and packaged-process acceptance remain separate.
async function requirePredecessor(admin: Pool) {
  const ledger = await admin.query<{ path: string; sha256: string; applied_at: string }>(
    `select path,sha256,applied_at::text from openpc_local.migration
     where path like '/migrations/postgres/control-api/%' order by path`,
  );
  expect(
    ledger.rows.at(-1)?.path,
    'BLOCKED: participant-readback must install the actual Control 0081 predecessor before this test',
  ).toBe('/migrations/postgres/control-api/0081_deployment_projection_fence.sql');
  expect(
    (
      await admin.query(`select
        to_regclass('control.evidence_archive_profile') is null no_signed_profiles,
        not exists(select 1 from information_schema.columns where table_schema='control'
          and table_name='evidence_remote_archive_intent' and column_name='source_kind') no_typed_dispatch,
        not exists(select 1 from pg_constraint where conrelid='control.protected_proof_object'::regclass
          and conname='protected_proof_object_version_uq') no_later_unique,
        to_regclass('control.evidence_remote_archive_intent') is null no_remote_journal`)
    ).rows[0],
  ).toEqual({
    no_signed_profiles: true,
    no_typed_dispatch: true,
    no_later_unique: true,
    no_remote_journal: true,
  });
  return ledger.rows;
}

/** Reuse the existing mounted installer and its atomic checksum ledger. The
 * participant runner owns this one capped container, all services and cleanup.
 * No DDL reconstruction, copied guards or second migration implementation. */
async function migrationCommand() {
  const root = await realpath(process.env.OPENPC_TEST_TMP_ROOT!);
  const containers = (
    await execute('docker', ['ps', '-q', '--filter', `label=io.openpc.test-owner=${root}`])
  ).stdout
    .trim()
    .split(/\s+/u);
  expect(
    containers,
    'Exactly the participant runner database must own this test root',
  ).toHaveLength(1);
  const container = containers[0]!;
  expect(container).toMatch(/^[0-9a-f]{12,64}$/u);
  const format =
    '{"owner":{{json (index .Config.Labels "io.openpc.test-owner")}},"memory":{{.HostConfig.Memory}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}';
  const inspected = JSON.parse(
    (await execute('docker', ['inspect', '--format', format, container])).stdout,
  ) as {
    owner: string;
    memory: number;
    mounts: { Source: string; Destination: string; RW: boolean }[];
    ports: Record<string, { HostIp: string; HostPort: string }[]>;
  };
  expect(inspected.owner).toBe(root);
  expect(inspected.memory).toBe(1073741824);
  const database = new URL(adminUrl!);
  expect(database.hostname).toBe('127.0.0.1');
  expect(database.pathname).toBe('/openpc_control');
  expect(inspected.ports['5432/tcp']).toContainEqual({
    HostIp: '127.0.0.1',
    HostPort: database.port,
  });
  for (const [destination, source] of [
    ['/migrations/postgres', join(repository, 'migrations/postgres')],
    ['/local/migrate.sh', join(repository, 'deploy/compose/local/migrate.sh')],
    ['/run/secrets', join(root, 'secrets')],
  ] as const) {
    expect(inspected.mounts).toContainEqual(
      expect.objectContaining({
        Destination: destination,
        Source: await realpath(source),
        RW: false,
      }),
    );
  }
  return async (label: string) => {
    const log = join(root, `evidence-remote-upgrade-${label}.log`);
    try {
      const result = await execute(
        'docker',
        [
          'exec',
          '-e',
          'PGHOST=127.0.0.1',
          '-e',
          'PGUSER=postgres',
          '-e',
          'PGDATABASE=openpc_control',
          container,
          'sh',
          '/local/migrate.sh',
          'control-schema',
        ],
        { timeout: 60000, maxBuffer: 4 * 1024 * 1024 },
      );
      await writeFile(log, result.stdout + result.stderr, { mode: 0o600 });
    } catch (error) {
      const result = error as { stdout?: string; stderr?: string };
      await writeFile(log, (result.stdout ?? '') + (result.stderr ?? ''), { mode: 0o600 });
      throw new Error(`Actual migration owner failed; diagnostics retained at ${log}`);
    }
  };
}

const preservedTables = [
  'authentication_occurrence',
  'mutation_evidence',
  'audit_occurrence',
  'outbox_event',
  'evidence_stream',
  'evidence_catalogue',
  'evidence_segment',
  'evidence_segment_payload',
  'evidence_checkpoint',
  'protected_proof_object',
  'protected_proof_payload',
  'protected_proof_checkpoint',
  'retention_hold',
  'retention_policy',
  'deletion_job',
  'evidence_deletion_item',
] as const;
async function snapshot(admin: Pool, participantId: string) {
  const result: Record<string, unknown[]> = {};
  for (const table of preservedTables) {
    result[table] = (
      await admin.query(
        `select to_jsonb(t) value from control.${table} t
        where participant_id=$1 order by to_jsonb(t)::text`,
        [participantId],
      )
    ).rows.map((row: { value: unknown }) => row.value);
  }
  return result;
}

async function isolatedCounts(worker: Pool, context: Scope, owner: string) {
  const client = await worker.connect();
  try {
    await client.query('begin');
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true),openpc.assert_request_context(true)",
      [context.participantId, context.privacyDomainId, id()],
    );
    const hasJournal = (
      await client.query(
        "select to_regclass('control.evidence_remote_archive_intent') is not null present",
      )
    ).rows[0].present;
    return (
      await client.query(
        `select
        (select count(*)::int from control.protected_proof_object where participant_id=$1) objects,
        (select count(*)::int from control.protected_proof_payload where participant_id=$1) payloads,
        (select count(*)::int from control.protected_proof_checkpoint where participant_id=$1) checkpoints,
        (select count(*)::int from control.evidence_segment where participant_id=$1) segments,
        ${hasJournal ? '(select count(*)::int from control.evidence_remote_archive_intent where participant_id=$1)' : '0::int'} intents`,
        [owner],
      )
    ).rows[0];
  } finally {
    await client.query('rollback');
    client.release();
  }
}

// Governed local state must survive the additive remote migrations without gaining
// remote assurance or resurrecting an independently deleted ciphertext copy.
integration(
  'upgrades populated 0081 local proof custody through 0086 and recovers new remote custody',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    let worker = new Pool({ connectionString: workerUrl, max: 1 });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'remote-upgrade-source' };
    const rawScope = { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId };
    const participantId = `urn:openpc:participant:${scope.participantId}`;
    const foreignPrivacy = id();
    const foreignScope = { participantId: id(), privacyDomainId: id() };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'remote-upgrade-'));
    const proofKey = randomBytes(32);
    const sourceKey = randomBytes(32);
    const signers: Signing[] = [];
    let fixture: Governance | undefined;
    let foreign: Governance | undefined;
    let external: ExternalArchive | undefined;
    let authority: Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>> | undefined;
    let passed = false;
    try {
      const oldLedger = await requirePredecessor(admin);
      const migrate = await migrationCommand();
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
        {
          protectedProofKeys: {
            activeKeyId: 'upgrade-proof-key',
            keys: new Map([['upgrade-proof-key', proofKey]]),
          },
        },
      );
      foreign = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        foreignScope.participantId,
        foreignScope.privacyDomainId,
      );
      // Initial scope only; all proof, policy, hold and deletion effects below go
      // through real HTTP governance, approval, step-up and immutable owners.
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Upgrade foreign privacy','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [foreignPrivacy, scope.participantId],
      );
      for (const family of ['retention-policy', 'evidence-deletion', 'evidence-hold'] as const) {
        signers.push(
          await evidenceGovernanceSigningFixture(
            admin,
            scope.participantId,
            scope.privacyDomainId,
            family,
          ),
        );
      }
      const [policySigner, deletionSigner, holdSigner] = signers;
      await fixture.restartConfiguration(policySigner!.evidence);
      await fixture.create('retention-policies', 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1', {
        participantId,
        predecessorPolicyId: null,
        policy: {
          dataClass: 'RAW_SOURCE_BODY',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      await fixture.governance.client.stepUp(
        fixture.governance.maker,
        'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
        id(),
        sha256({ purpose: 'migration source' }),
      );
      const local = new EvidenceCustody(worker);
      await local.ingestAuthentication(
        scope,
        { keyId: 'upgrade-source-key', key: sourceKey },
        time(86400000),
        1048576,
      );
      const source = (
        await admin.query(
          `select c.evidence_id::text id from control.evidence_catalogue c
        join control.authentication_occurrence a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
         and a.occurrence_id::text=c.record_id where c.participant_id=$1 and c.privacy_domain_id=$2
         and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION' order by c.sequence desc limit 1`,
          [scope.participantId, scope.privacyDomainId, scope.streamId],
        )
      ).rows[0];
      expect(source).toBeDefined();
      const discovery = await fixture.read(
        `evidence-records/urn:openpc:resource:${source.id}/protected-proof-source`,
      );
      expect(discovery.status).toBe(200);
      const retain = async (caseReference: string, retainUntil: string) => {
        const response = await fixture!.create(
          'protected-proofs',
          'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
          {
            participantId,
            source: discovery.body,
            purpose: 'Preserve original migration history',
            caseReference,
            retainUntil,
          },
        );
        return String(response.body.resourceRef);
      };
      const deletedDeadline = time(8000);
      const deletedRef = await retain('deleted-before-upgrade', deletedDeadline);
      const proofVault = await LocalProtectedProofVault.open(
        join(root, 'proofs'),
        'upgrade-local-proof',
      );
      const segmentVault = await LocalEvidenceVault.open(
        join(root, 'segments'),
        'upgrade-local-segment',
      );
      expect(await archiveProtectedProof(worker, rawScope, proofVault)).toMatchObject({
        objectRef: deletedRef,
      });
      expect(await local.exportNext(scope, segmentVault)).not.toBeNull();
      expect(await local.exportNext(scope, segmentVault)).toBeNull();
      const segmentCheckpoint = sinkDurabilityReceipt.parse(
        (
          await admin.query(
            'select receipt from control.evidence_checkpoint where participant_id=$1 and sink_id=$2',
            [scope.participantId, segmentVault.sinkId],
          )
        ).rows[0].receipt,
      );
      const segmentBytes = await segmentVault.read(segmentCheckpoint.object);
      const deletedCheckpoint = protectedSinkReceipt.parse(
        (
          await admin.query(
            'select receipt from control.protected_proof_checkpoint where object_id=$1',
            [deletedRef.slice(-36)],
          )
        ).rows[0].receipt,
      );
      const deletedPacket = await proofVault.read(deletedCheckpoint.object);
      await delay(Math.max(0, Date.parse(deletedDeadline) - Date.now() + 25));
      const plan = await fixture.read(`protected-proofs/${deletedRef}/deletion-plan`);
      expect(plan).toMatchObject({ status: 200, body: { eligible: true, blockers: [] } });
      expect(plan.body.selection.targets).toHaveLength(1);
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const deletion = await fixture.create(
        'evidence-deletions/raw-batches',
        'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
        {
          participantId,
          selection: plan.body.selection,
          beforeDigest: plan.body.beforeDigest,
        },
      );
      expect(
        (await fixture.read(`protected-proofs/${deletedRef}/deletion-plan`)).body,
      ).toMatchObject({
        localPayload: 'DELETED',
        blockers: ['ALREADY_DELETED'],
      });
      const liveDeadline = time(86400000);
      const liveRef = await retain('retained-through-upgrade', liveDeadline);
      expect(await archiveProtectedProof(worker, rawScope, proofVault)).toMatchObject({
        objectRef: liveRef,
      });
      expect(await archiveProtectedProof(worker, rawScope, proofVault)).toBeNull();
      const liveCheckpoint = protectedSinkReceipt.parse(
        (
          await admin.query(
            'select receipt from control.protected_proof_checkpoint where object_id=$1',
            [liveRef.slice(-36)],
          )
        ).rows[0].receipt,
      );
      const livePacket = await proofVault.read(liveCheckpoint.object);
      expect(liveCheckpoint.object.retainUntil).toBe(liveDeadline);
      await fixture.restartConfiguration(holdSigner!.evidence);
      const hold = await fixture.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
        {
          participantId,
          holdKind: 'LEGAL',
          selector: { type: 'PARTICIPANT' },
        },
      );
      const holdRef = String(hold.body.resourceRef);
      const liveView = (await fixture.read(`protected-proofs/${liveRef}`)).body;
      expect(liveView).toMatchObject({
        objectRef: liveRef,
        objectVersion: '1',
        source: discovery.body,
      });
      const correctCounts = await isolatedCounts(worker, scope, scope.participantId);
      expect(correctCounts).toEqual({
        objects: 2,
        payloads: 1,
        checkpoints: 2,
        segments: 1,
        intents: 0,
      });
      const empty = { objects: 0, payloads: 0, checkpoints: 0, segments: 0, intents: 0 };
      expect(
        await isolatedCounts(
          worker,
          { ...scope, privacyDomainId: foreignPrivacy },
          scope.participantId,
        ),
      ).toEqual(empty);
      expect(await isolatedCounts(worker, foreignScope, scope.participantId)).toEqual(empty);

      const before = await snapshot(admin, scope.participantId);
      expect(before.mutation_evidence!.length).toBeGreaterThan(0);
      expect(before.audit_occurrence!.length).toBeGreaterThan(0);
      expect(before.evidence_deletion_item).toHaveLength(1);
      expect(before.retention_hold).toHaveLength(1);
      // Real generated migration files, role ownership and atomic ledger, in the
      // same sequence as a supported host upgrade; no current guards preinstalled.
      await migrate('apply');
      expect(await snapshot(admin, scope.participantId)).toEqual(before);
      const ledger = (
        await admin.query<{ path: string; sha256: string; applied_at: string }>(
          `select path,sha256,applied_at::text from openpc_local.migration
       where path like '/migrations/postgres/control-api/%' order by path`,
        )
      ).rows;
      expect(ledger.slice(0, oldLedger.length)).toEqual(oldLedger);
      expect(ledger.slice(oldLedger.length).map((row) => row.path.split('/').at(-1))).toEqual(
        upgrades,
      );
      for (const migration of upgrades) {
        const bytes = await readFile(
          join(repository, 'migrations/postgres/control-api', migration),
        );
        expect(ledger.find((row) => row.path.endsWith(`/${migration}`))?.sha256).toBe(
          sha256(bytes).slice(7),
        );
      }
      expect(
        (
          await admin.query(`select
      (select applied_at from openpc_local.migration where path like '%/0085_protected_object_version_identity.sql') <
      (select applied_at from openpc_local.migration where path like '%/0086_protected_remote_archive.sql') ordered,
      exists(select 1 from pg_constraint where conrelid='control.protected_proof_object'::regclass
        and conname='protected_proof_object_version_uq' and convalidated) unique_valid,
      exists(select 1 from pg_constraint where conrelid='control.evidence_remote_archive_intent'::regclass
        and conname='evidence_remote_archive_proof_fk' and convalidated) fk_valid`)
        ).rows[0],
      ).toEqual({ ordered: true, unique_valid: true, fk_valid: true });
      const securityTables = [
        'protected_proof_object',
        'protected_proof_payload',
        'protected_proof_checkpoint',
        'retention_hold',
        'evidence_segment',
        'evidence_checkpoint',
        'evidence_remote_archive_intent',
        'evidence_remote_archive_attempt',
        'evidence_archive_profile',
        'evidence_archive_receipt',
        'evidence_archive_outbox',
      ];
      const security = await admin.query(
        `select relname,relrowsecurity,relforcerowsecurity,
      pg_get_userbyid(relowner) owner from pg_class where relnamespace='control'::regnamespace and relname=any($1::text[])`,
        [securityTables],
      );
      expect(security.rowCount).toBe(securityTables.length);
      for (const row of security.rows)
        expect(row).toMatchObject({
          relrowsecurity: true,
          relforcerowsecurity: true,
          owner: 'openpc_control_owner',
        });
      await migrate('idempotent');
      expect(
        (
          await admin.query(`select path,sha256,applied_at::text from openpc_local.migration
      where path like '/migrations/postgres/control-api/%' order by path`)
        ).rows,
      ).toEqual(ledger);
      expect(await snapshot(admin, scope.participantId)).toEqual(before);

      await worker.end();
      worker = new Pool({ connectionString: workerUrl, max: 1 });
      await fixture.restartConfiguration(holdSigner!.evidence);
      expect(await isolatedCounts(worker, scope, scope.participantId)).toEqual(correctCounts);
      expect(
        await isolatedCounts(
          worker,
          { ...scope, privacyDomainId: foreignPrivacy },
          scope.participantId,
        ),
      ).toEqual(empty);
      expect(await isolatedCounts(worker, foreignScope, scope.participantId)).toEqual(empty);
      expect((await fixture.read(`protected-proofs/${liveRef}`)).body).toEqual(liveView);
      expect((await foreign.read(`protected-proofs/${liveRef}`)).status).toBe(404);
      expect(
        (await fixture.read(`protected-proofs/${deletedRef}/deletion-plan`)).body,
      ).toMatchObject({ localPayload: 'DELETED' });
      expect((await fixture.read(`evidence-holds/${holdRef}`)).body).toMatchObject({
        state: 'ACTIVE',
        revision: '1',
      });
      expect((await fixture.read(`evidence-deletions/${deletion.body.resourceRef}`)).status).toBe(
        200,
      );
      const reopened = await LocalProtectedProofVault.open(join(root, 'proofs'), proofVault.sinkId);
      expect(await reopened.read(liveCheckpoint.object)).toEqual(livePacket);
      expect(await reopened.read(deletedCheckpoint.object)).toEqual(deletedPacket);
      expect(await archiveProtectedProof(worker, rawScope, reopened)).toBeNull();
      const reopenedSegments = await LocalEvidenceVault.open(
        join(root, 'segments'),
        segmentVault.sinkId,
      );
      expect(await reopenedSegments.read(segmentCheckpoint.object)).toEqual(segmentBytes);
      expect(await reopenedSegments.verify(segmentCheckpoint.object)).toEqual(segmentCheckpoint);
      expect(await new EvidenceCustody(worker).exportNext(scope, reopenedSegments)).toBeNull();

      // Remote custody is first created AFTER the upgrade. The old local receipts
      // retain LOCAL_FSYNC_READBACK and their digest-shaped versions unchanged.
      const credentials = {
        accessKeyId: `TEST${randomBytes(12).toString('hex')}`,
        secretAccessKey: randomBytes(32).toString('base64'),
      };
      external = await startRemoteArchiveFixture({
        root: join(root, 'remote'),
        credentials,
        bucket: 'upgrade-proof',
        expectedOwner: '123456789012',
        region: 'us-east-1',
      });
      const profile: RemoteArchiveProfile = {
        profileId: 'upgrade-proof',
        sinkId: 'upgrade-remote-proof',
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'us-east-1',
        bucket: 'upgrade-proof',
        expectedBucketOwner: '123456789012',
        prefix: 'proofs',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 10000,
        maxVersionPages: 4,
      };
      authority = await evidenceArchiveAuthorityFixture(
        admin,
        worker,
        scope,
        [scope.streamId],
        profile,
        undefined,
        'PROTECTED_PROOF',
      );
      const owner = () =>
        new PostgresRemoteArchiveAttemptOwner(worker, scope, authority!.authority);
      const custody = () =>
        new ProtectedRemoteArchiveCustody(owner(), authority!.authority, async () => credentials);
      external.faults.dropPutResponse = true;
      await expect(custody().exportNext()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.puts).toBe(1);
      const attemptQuery = `select i.intent,i.source_kind,i.segment_id,i.protected_object_id::text,
      a.attempt_id::text,a.binding,a.state,a.observation from control.evidence_remote_archive_intent i
      join control.evidence_remote_archive_attempt a using(participant_id,privacy_domain_id,intent_id) where i.participant_id=$1`;
      const pending = (await admin.query(attemptQuery, [scope.participantId])).rows;
      expect(pending).toHaveLength(1);
      expect(pending[0]).toMatchObject({
        source_kind: 'PROTECTED_PROOF',
        segment_id: null,
        protected_object_id: liveRef.slice(-36),
        state: 'AMBIGUOUS',
      });
      const intent = remoteArchiveIntent.parse(pending[0]!.intent);
      expect(intent.source.object).toEqual({ ...liveCheckpoint.object, sinkId: profile.sinkId });
      expect(intent.payloadDigest).toBe(sha256(livePacket));
      expect(intent.payloadBytes).toBe(Buffer.byteLength(canonicalJson(livePacket)));
      expect(intent.initialProtection.rules).toMatchObject([
        { holdId: holdRef.slice(-36), state: 'ACTIVE', revision: '1' },
      ]);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_archive_receipt where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0].n,
      ).toBe(0);
      await worker.end();
      worker = new Pool({ connectionString: workerUrl, max: 1 });
      await fixture.restartConfiguration(holdSigner!.evidence);
      expect(await custody().exportNext()).toMatchObject({
        kind: 'SIGNED_REMOTE_PROTECTED_ARCHIVE_V1',
        result: 'CHECKPOINT',
      });
      expect(external.counts.puts).toBe(1);
      const observed = (await admin.query(attemptQuery, [scope.participantId])).rows;
      expect(observed).toHaveLength(1);
      expect(observed[0]).toMatchObject({
        intent,
        binding: pending[0]!.binding,
        attempt_id: pending[0]!.attempt_id,
        state: 'OBSERVED',
      });
      const observation = remoteArchiveReceipt.parse(observed[0]!.observation);
      const transport = new RemoteEvidenceArchive(profile, async () => credentials, owner());
      expect(await transport.readExact(intent, observation.locator)).toEqual(
        Buffer.from(canonicalJson(livePacket)),
      );
      const sealedQuery = `select r.receipt_id::text,r.receipt_digest,r.payload,r.cose,
      c.receipt,c.payload_digest,c.checkpoint_digest,o.event,o.event_digest from control.evidence_archive_receipt r
      join control.evidence_archive_outbox o using(participant_id,privacy_domain_id,receipt_id)
      join control.protected_proof_checkpoint c using(participant_id,privacy_domain_id,receipt_digest)
      where r.participant_id=$1`;
      const sealed = (await admin.query(sealedQuery, [scope.participantId])).rows;
      expect(sealed).toHaveLength(1);
      const receipt = authority.authority.verifyProtected(sealed[0]!.payload, sealed[0]!.cose);
      expect(receipt.receiptDigest).toBe(sealed[0]!.receipt_digest);
      expect(receipt.claims).toMatchObject({
        intentId: intent.intentId,
        attemptId: pending[0]!.attempt_id,
        objectId: liveRef.slice(-36),
        objectVersion: '1',
        objectDigest: liveCheckpoint.object.objectDigest,
        payloadDigest: sha256(livePacket),
        proofRetainUntilMicros: retentionMicros(liveDeadline).toString(),
        locatorDigest: sha256(observation.locator),
        protectionDigest: observation.protectionDigest,
      });
      expect(sealed[0]!.event_digest).toBe(sha256(sealed[0]!.event));
      await worker.end();
      worker = new Pool({ connectionString: workerUrl, max: 1 });
      expect(await custody().exportNext()).toBeNull();
      expect(await custody().reconcileHolds()).toBeNull();
      expect(external.counts.puts).toBe(1);
      expect((await admin.query(attemptQuery, [scope.participantId])).rows).toEqual(observed);
      expect((await admin.query(sealedQuery, [scope.participantId])).rows).toEqual(sealed);
      expect(
        (
          await admin.query(
            'select receipt from control.protected_proof_checkpoint where object_id=$1 and sink_id=$2',
            [liveRef.slice(-36), proofVault.sinkId],
          )
        ).rows[0].receipt,
      ).toEqual(liveCheckpoint);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_payload where object_id=$1',
            [deletedRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_remote_archive_intent where protected_object_id=$1',
            [deletedRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(await reopened.read(deletedCheckpoint.object)).toEqual(deletedPacket);
      expect(await isolatedCounts(worker, foreignScope, scope.participantId)).toEqual(empty);
      expect(
        await isolatedCounts(
          worker,
          { ...scope, privacyDomainId: foreignPrivacy },
          scope.participantId,
        ),
      ).toEqual(empty);
      const afterRecovery = await snapshot(admin, scope.participantId);
      for (const table of preservedTables) {
        expect(afterRecovery[table], `Original ${table} rows survive recovery`).toEqual(
          expect.arrayContaining(before[table]!),
        );
      }
      passed = true;
    } finally {
      authority?.close();
      await external?.close();
      await fixture?.close();
      await foreign?.close();
      for (const signer of signers) await signer.close();
      await Promise.all([admin.end(), worker.end()]);
      proofKey.fill(0);
      sourceKey.fill(0);
      if (passed) await rm(root, { recursive: true, force: true });
    }
  },
  180000,
);
