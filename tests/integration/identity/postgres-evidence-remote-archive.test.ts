import { randomBytes } from 'node:crypto';
import {
  archiveDigest,
  evidenceKeyId,
  type ArchiveSinkReceiptClaims,
} from '../../../packages/security-kernel/src/index.js';
import {
  RemoteArchiveCustody,
  archiveReceiptEvent,
} from '../../../services/control-api/src/evidence/remote-archive-custody.js';
import { retentionMicros } from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceExportWorker } from '../../../services/control-api/src/evidence/export-worker.js';
import { RemoteArchiveEvidenceReader } from '../../../services/control-api/src/evidence/remote-archive-reader.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { inspectSegment } from '../../../services/control-api/src/evidence/segment.js';
import {
  LocalEvidenceVault,
  vaultObject,
} from '../../../services/control-api/src/evidence/local-vault.js';
import { RemoteEvidenceArchive } from '../../../services/control-api/src/evidence/remote-archive.js';
import { PostgresRemoteArchiveAttemptOwner } from '../../../services/control-api/src/evidence/remote-archive-owner.js';
import type {
  RemoteArchiveIntent,
  RemoteArchiveProfile,
  RemoteArchiveReceipt,
} from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { evidenceArchiveAuthorityFixture } from './evidence-archive-authority-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;
interface ExternalArchive {
  endpoint: string;
  faults: {
    dropPutResponse: boolean;
    dropHoldResponse: boolean;
    denyRead: boolean;
    corruptRead: boolean;
    malformedListing: boolean;
  };
  counts: { puts: number; holds: number };
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

// This proves the real attempt/hold/transport boundary. Labelled custody fixture
// records do not establish original receipt authentication, signed archive
// custody, checkpoint advancement, packaged acceptance or provider qualification.
integration(
  'persists archive dispatch before I/O and reconciles original PUT and governed hold attempts',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'archive-owner-'));
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'archive-owner' };
    const credentials = {
      accessKeyId: `TEST${randomBytes(12).toString('hex')}`,
      secretAccessKey: randomBytes(32).toString('base64'),
    };
    let external: ExternalArchive | undefined;
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    let archiveSigning: Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>> | undefined;
    const encryption = { keyId: 'archive-owner-fixture', key: randomBytes(32) };
    // A real deferred PostgreSQL failure exercises the COMMIT boundary. It does
    // not intercept the production pool/client or fabricate a durable result.
    const faultName = `archive_commit_${scope.participantId.replaceAll('-', '')}`;
    const clearCommitFault = async () => {
      await admin.query(
        `drop trigger if exists ${faultName} on control.evidence_remote_archive_attempt`,
      );
      await admin.query(`drop function if exists openpc.${faultName}()`);
    };
    const failCommit = async (state: 'STARTED' | 'OBSERVED') => {
      await admin.query(`create function openpc.${faultName}() returns trigger language plpgsql as $$
      begin if NEW.participant_id::text=TG_ARGV[0] and NEW.state=TG_ARGV[1]
       then raise exception 'TEST_ARCHIVE_COMMIT_FAILURE'; end if; return NEW; end $$;
      create constraint trigger ${faultName} after insert or update on control.evidence_remote_archive_attempt
       deferrable initially deferred for each row execute function openpc.${faultName}('${scope.participantId}','${state}')`);
    };
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
      );
      signing = await evidenceGovernanceSigningFixture(
        admin,
        scope.participantId,
        scope.privacyDomainId,
      );
      await fixture.restartConfiguration(signing.evidence);
      external = await startRemoteArchiveFixture({
        root,
        credentials,
        bucket: 'archive-owner',
        expectedOwner: '123456789012',
        region: 'us-east-1',
      });
      const profile: RemoteArchiveProfile = {
        profileId: 'archive-owner-fixture',
        sinkId: 'archive-owner-sink',
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'us-east-1',
        bucket: 'archive-owner',
        expectedBucketOwner: '123456789012',
        prefix: 'evidence',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 3000,
        maxVersionPages: 4,
      };
      archiveSigning = await evidenceArchiveAuthorityFixture(
        admin,
        worker,
        scope,
        [scope.streamId, 'archive-unresolved'],
        profile,
      );
      const authority = archiveSigning.authority;
      const source = Buffer.from('labelled custody source fixture; no original receipt acceptance');
      const admission = await new EvidenceCustody(worker).admit(
        scope,
        [
          {
            recordId: id(),
            evidenceClass: 'AUTHENTICATION',
            sourceFormat: 'FIXTURE',
            occurredAt: '2026-09-23T00:00:00.000000Z',
            receiptDigest: sha256(source),
            receiptBase64: source.toString('base64'),
          },
        ],
        encryption,
        '2027-01-01T00:00:00.000000Z',
        65536,
      );
      const bytes = (
        await admin.query<{ bytes: Buffer }>(
          'select encrypted_segment bytes from control.evidence_segment_payload where segment_id=$1',
          [admission.segmentId],
        )
      ).rows[0]!.bytes;
      const intent: RemoteArchiveIntent = {
        intentId: id(),
        profileDigest: sha256(profile),
        source: {
          kind: 'SEGMENT',
          object: vaultObject(profile.sinkId, inspectSegment(bytes).header, admission.objectDigest),
        },
        payloadDigest: admission.objectDigest,
        payloadBytes: bytes.length,
        initialProtection: { revision: '1', rules: [] },
      };
      const attemptId = id();
      const owner = new PostgresRemoteArchiveAttemptOwner(worker, scope, authority);
      const archive = new RemoteEvidenceArchive(profile, async () => credentials, {
        run(binding, perform) {
          return owner.run(binding, async (dispatch) => {
            // This is an observer around the real SQL owner, not an admission stub.
            expect(
              (
                await admin.query(
                  'select state from control.evidence_remote_archive_attempt where attempt_id=$1',
                  [binding.attemptId],
                )
              ).rows[0]?.state,
            ).toBe('STARTED');
            const competing = await admin.connect();
            try {
              const locked = await competing.query<{ held: boolean }>(
                'select pg_try_advisory_lock(hashtextextended($1,0)) held',
                [`evidence-lifecycle:${scope.participantId}`],
              );
              expect(locked.rows[0]?.held).toBe(false);
            } finally {
              competing.release();
            }
            return perform(dispatch);
          });
        },
      });
      await failCommit('STARTED');
      await expect(archive.put(intent, bytes, attemptId)).rejects.toThrow(
        'TEST_ARCHIVE_COMMIT_FAILURE',
      );
      expect(external.counts.puts).toBe(0);
      expect(
        (
          await admin.query(
            'select 1 from control.evidence_remote_archive_attempt where attempt_id=$1',
            [attemptId],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await admin.query(
            'select 1 from control.evidence_remote_archive_intent where intent_id=$1',
            [intent.intentId],
          )
        ).rowCount,
      ).toBe(0);
      await clearCommitFault();
      external.faults.dropPutResponse = true;
      await expect(archive.put(intent, bytes, attemptId)).rejects.toMatchObject({
        code: 'AMBIGUOUS',
      });
      expect(external.counts.puts).toBe(1);
      expect(
        (
          await admin.query(
            'select state from control.evidence_remote_archive_attempt where attempt_id=$1',
            [attemptId],
          )
        ).rows,
      ).toEqual([{ state: 'AMBIGUOUS' }]);
      const restarted = new RemoteEvidenceArchive(
        profile,
        async () => credentials,
        new PostgresRemoteArchiveAttemptOwner(worker, scope, authority),
      );
      const observed = await restarted.reconcilePut(intent);
      const malformed: Array<(value: RemoteArchiveReceipt) => void> = [
        (value) => {
          value.locator.bucket = 'foreign-bucket';
        },
        (value) => {
          value.locator.key = value.locator.key.replace('/segment/', '/proof/');
        },
        (value) => {
          value.locator.versionId = 'null';
        },
        (value) => {
          value.observedLegalHold = 'ON';
        },
        (value) => {
          value.observedRetention.retainUntil = '2026-01-01T00:00:00Z';
        },
        (value) => {
          Object.assign(value.observedRetention, { unsupported: true });
        },
        (value) => {
          Object.assign(value, { callerApproved: true });
        },
      ];
      for (const mutate of malformed) {
        const altered = structuredClone(observed);
        mutate(altered);
        const body = Object.fromEntries(
          Object.entries(altered).filter(([name]) => name !== 'receiptDigest'),
        );
        altered.receiptDigest = sha256(body);
        const client = await worker.connect();
        try {
          await client.query('begin');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [scope.participantId, scope.privacyDomainId, id()],
          );
          await client.query("select set_config('openpc.archive_profile_digest',$1,true)", [
            authority.profileDigest,
          ]);
          await expect(
            client.query(
              `update control.evidence_remote_archive_attempt
          set state='OBSERVED',observation=$2,observation_digest=$3 where attempt_id=$1`,
              [attemptId, altered, sha256(altered)],
            ),
          ).rejects.toThrow('PC-DATA-6007');
        } finally {
          await client.query('rollback');
          client.release();
        }
      }
      await failCommit('OBSERVED');
      await expect(restarted.put(intent, bytes, attemptId)).rejects.toThrow(
        'TEST_ARCHIVE_COMMIT_FAILURE',
      );
      expect(external.counts.puts).toBe(1);
      expect(
        (
          await admin.query(
            'select state from control.evidence_remote_archive_attempt where attempt_id=$1',
            [attemptId],
          )
        ).rows,
      ).toEqual([{ state: 'AMBIGUOUS' }]);
      await clearCommitFault();
      const receipt = await restarted.put(intent, bytes, attemptId);
      expect(external.counts.puts).toBe(1);
      expect(
        (
          await admin.query(
            'select state,observation from control.evidence_remote_archive_attempt where attempt_id=$1',
            [attemptId],
          )
        ).rows,
      ).toEqual([{ state: 'OBSERVED', observation: receipt }]);
      await expect(restarted.put(intent, bytes, id())).rejects.toThrow();
      expect(external.counts.puts).toBe(1);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_checkpoint where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0]?.n,
      ).toBe(0);

      const emptyScope = { ...scope, streamId: 'archive-unresolved' };
      const emptyAdmission = await new EvidenceCustody(worker).admit(
        emptyScope,
        [
          {
            recordId: id(),
            evidenceClass: 'AUTHENTICATION',
            sourceFormat: 'FIXTURE',
            occurredAt: '2026-09-23T00:00:00.000000Z',
            receiptDigest: sha256(source),
            receiptBase64: source.toString('base64'),
          },
        ],
        encryption,
        '2027-01-01T00:00:00.000000Z',
        65536,
      );
      const emptyBytes = (
        await admin.query<{ bytes: Buffer }>(
          'select encrypted_segment bytes from control.evidence_segment_payload where segment_id=$1',
          [emptyAdmission.segmentId],
        )
      ).rows[0]!.bytes;
      const emptyIntent: RemoteArchiveIntent = {
        intentId: id(),
        profileDigest: sha256(profile),
        source: {
          kind: 'SEGMENT',
          object: vaultObject(
            profile.sinkId,
            inspectSegment(emptyBytes).header,
            emptyAdmission.objectDigest,
          ),
        },
        payloadDigest: emptyAdmission.objectDigest,
        payloadBytes: emptyBytes.length,
        initialProtection: { revision: '1', rules: [] },
      };
      const absent = new RemoteEvidenceArchive(
        profile,
        async () => credentials,
        new PostgresRemoteArchiveAttemptOwner(worker, emptyScope, authority),
      );
      const absentAttempt = id();
      external.faults.malformedListing = true;
      await expect(absent.put(emptyIntent, emptyBytes, absentAttempt)).rejects.toThrow();
      external.faults.malformedListing = false;
      await expect(absent.put(emptyIntent, emptyBytes, absentAttempt)).rejects.toMatchObject({
        code: 'AMBIGUOUS',
      });
      await expect(absent.put(emptyIntent, emptyBytes, id())).rejects.toMatchObject({
        code: 'AMBIGUOUS',
      });
      expect(external.counts.puts).toBe(1);
      expect(
        (
          await admin.query(
            'select state from control.evidence_remote_archive_attempt where attempt_id=$1',
            [absentAttempt],
          )
        ).rows,
      ).toEqual([{ state: 'AMBIGUOUS' }]);

      const hold = await fixture.prepareMutation(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'PRIVACY_DOMAIN' },
        },
        true,
      );
      await hold.stepUp();
      expect(await hold.commit()).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      const protection = await owner.currentProtection(intent);
      expect(protection.revision).toBe('2');
      expect(protection.rules).toHaveLength(1);
      expect(protection.rules[0]).toMatchObject({
        holdId: hold.resourceId,
        state: 'ACTIVE',
        revision: '1',
      });
      const protectionAttempt = id();
      external.faults.dropHoldResponse = true;
      await expect(
        restarted.reconcileProtection(intent, receipt.locator, protection, protectionAttempt),
      ).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.holds).toBe(1);
      const preserved = await restarted.reconcileProtection(
        intent,
        receipt.locator,
        protection,
        protectionAttempt,
      );
      expect(preserved.observedLegalHold).toBe('ON');
      expect(external.counts.holds).toBe(1);
      expect(await owner.readObservation(intent, attemptId)).toEqual(receipt);
      expect(await owner.readObservation(intent, protectionAttempt)).toEqual(preserved);
      expect(await owner.readObservation(intent, id())).toBeNull();
      expect(
        (
          await admin.query(
            'select observation from control.evidence_remote_archive_attempt where attempt_id=$1',
            [attemptId],
          )
        ).rows[0]?.observation,
      ).toEqual(receipt);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_checkpoint where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0]?.n,
      ).toBe(0);

      const local = await LocalEvidenceVault.open(join(root, 'local-vault'), 'local-control-sink');
      const custody = new EvidenceCustody(worker);
      expect(await custody.exportNext(scope, local)).not.toBeNull();
      expect(await custody.exportNext(emptyScope, local)).not.toBeNull();
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.evidence_hold_coverage
        where participant_id=$1 and retention_hold_id=$2 and sink_id=$3`,
            [scope.participantId, hold.resourceId, local.sinkId],
          )
        ).rows[0]?.n,
      ).toBe(2);
      expect(
        await fixture.read(`evidence-holds/urn:openpc:resource:${hold.resourceId}`),
      ).toMatchObject({
        status: 200,
        body: { state: 'ACTIVE', coverage: 'PENDING' },
      });

      const client = await worker.connect();
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await client.query("select set_config('openpc.archive_profile_digest',$1,true)", [
          authority.profileDigest,
        ]);
        await expect(
          client.query(
            "update control.evidence_remote_archive_attempt set state='STARTED',observation=null,observation_digest=null where attempt_id=$1",
            [attemptId],
          ),
        ).rejects.toThrow('IMMUTABLE');
        await client.query('rollback');
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [scope.participantId, id(), id()],
        );
        expect(
          (await client.query('select 1 from control.evidence_remote_archive_attempt')).rowCount,
        ).toBe(0);
        await client.query('rollback');
      } finally {
        await client.query('rollback');
        client.release();
      }
    } finally {
      await clearCommitFault();
      encryption.key.fill(0);
      signing?.close();
      archiveSigning?.close();
      await fixture?.close();
      await external?.close();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);

integration(
  'commits signed remote custody and current governed hold coverage through the real SQL owner',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 }),
      worker = new Pool({ connectionString: workerUrl, max: 2 });
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'archive-custody-'));
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'archive-custody' };
    const encryption = { keyId: 'archive-custody-fixture', key: randomBytes(32) };
    const credentials = {
      accessKeyId: `TEST${randomBytes(12).toString('hex')}`,
      secretAccessKey: randomBytes(32).toString('base64'),
    };
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    let archiveSigning: Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>> | undefined;
    let external: ExternalArchive | undefined;
    const faultName = `archive_signed_${scope.participantId.replaceAll('-', '')}`;
    const clearFault = async () => {
      await admin.query(`drop trigger if exists ${faultName} on control.evidence_archive_receipt`);
      await admin.query(`drop function if exists openpc.${faultName}()`);
    };
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
      );
      signing = await evidenceGovernanceSigningFixture(
        admin,
        scope.participantId,
        scope.privacyDomainId,
      );
      await fixture.restartConfiguration(signing.evidence);
      external = await startRemoteArchiveFixture({
        root,
        credentials,
        bucket: 'archive-custody',
        expectedOwner: '123456789012',
        region: 'us-east-1',
      });
      const profile: RemoteArchiveProfile = {
        profileId: 'archive-custody',
        sinkId: 'archive-custody',
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'us-east-1',
        bucket: 'archive-custody',
        expectedBucketOwner: '123456789012',
        prefix: 'evidence',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 10000,
        maxVersionPages: 4,
      };
      archiveSigning = await evidenceArchiveAuthorityFixture(
        admin,
        worker,
        scope,
        [scope.streamId],
        profile,
      );
      const authority = archiveSigning.authority;
      const owner = () => new PostgresRemoteArchiveAttemptOwner(worker, scope, authority);
      const custody = () => new RemoteArchiveCustody(owner(), authority, async () => credentials);
      // Supporting source admission only: this test does not claim the source's
      // receipt-authentication journey, packaged browser acceptance or WORM qualification.
      const source = Buffer.from('labelled custody source for signed remote owner regression');
      const admitted = await new EvidenceCustody(worker).admit(
        scope,
        [
          {
            recordId: id(),
            evidenceClass: 'AUTHENTICATION',
            sourceFormat: 'FIXTURE',
            occurredAt: '2026-09-23T00:00:00.000000Z',
            receiptDigest: archiveDigest(source),
            receiptBase64: source.toString('base64'),
          },
        ],
        encryption,
        '2027-01-01T00:00:00.000000Z',
        65536,
      );
      const counts = async () =>
        (
          await admin.query<{
            receipts: number;
            events: number;
            nonces: number;
            checkpoints: number;
          }>(
            `select
      (select count(*)::int from control.evidence_archive_receipt where participant_id=$1) receipts,
      (select count(*)::int from control.evidence_archive_outbox where participant_id=$1) events,
      (select count(*)::int from control.evidence_archive_commit_nonce where participant_id=$1) nonces,
      (select count(*)::int from control.evidence_checkpoint where participant_id=$1) checkpoints`,
            [scope.participantId],
          )
        ).rows[0];
      await expect(
        worker.query('select verifier_secret from control.evidence_archive_commit_key'),
      ).rejects.toThrow('permission denied');
      await expect(
        worker.query('select * from control.evidence_archive_commit_nonce'),
      ).rejects.toThrow('permission denied');
      external.faults.dropPutResponse = true;
      await expect(custody().exportNext()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.puts).toBe(1);
      expect(await counts()).toEqual({ receipts: 0, events: 0, nonces: 0, checkpoints: 0 });
      await admin.query(`create function openpc.${faultName}() returns trigger language plpgsql as $$
      begin if NEW.participant_id::text=TG_ARGV[0] then raise exception 'TEST_ARCHIVE_SIGNED_COMMIT';end if;return NEW;end $$;
      create constraint trigger ${faultName} after insert on control.evidence_archive_receipt deferrable initially deferred
      for each row execute function openpc.${faultName}('${scope.participantId}')`);
      await expect(custody().exportNext()).rejects.toThrow('TEST_ARCHIVE_SIGNED_COMMIT');
      expect(external.counts.puts).toBe(1);
      expect(await counts()).toEqual({ receipts: 0, events: 0, nonces: 0, checkpoints: 0 });
      await clearFault();
      const attempt = (
        await admin.query<{
          binding: import('../../../services/control-api/src/evidence/remote-archive-contracts.js').ArchiveAttemptBinding;
          observation: RemoteArchiveReceipt;
        }>(
          'select binding,observation from control.evidence_remote_archive_attempt where participant_id=$1',
          [scope.participantId],
        )
      ).rows[0]!;
      // Exercise valid canonical structure with an invalid signature/MAC, and an
      // authentic signed commit missing its mandatory outbox. Neither can commit.
      for (const mode of ['forged-signature', 'missing-outbox'] as const) {
        const client = await worker.connect();
        try {
          await client.query('begin');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [scope.participantId, scope.privacyDomainId, id()],
          );
          const now = await authority.admit(client, scope),
            b = attempt.binding,
            o = attempt.observation;
          const claims: ArchiveSinkReceiptClaims = {
            ...scope,
            environmentId: authority.trust.environmentId,
            receiptId: id(),
            intentId: b.intent.intentId,
            attemptId: b.attemptId,
            signedProfileDigest: authority.profileDigest,
            observationDigest: sha256(o),
            attemptBindingDigest: sha256(b),
            objectDigest: admitted.objectDigest,
            locatorDigest: sha256(o.locator),
            protectionDigest: b.protectionDigest,
            protectionRevision: b.protection.revision,
            retentionUntilMicros: retentionMicros(o.observedRetention.retainUntil).toString(),
            recordedAtMicros: now,
            previousReceiptDigest: null,
            action: 'PUT',
            signerKeyId: evidenceKeyId(Buffer.from(authority.claims.receiptSignerSpki, 'hex')),
            segmentId: admitted.segmentId,
            throughSequence: '1',
            assurance: 'REMOTE_INTERFACE_VERIFIED',
            providerQualification: 'NOT_ESTABLISHED',
          };
          const signed = authority.sign(claims),
            cap = authority.commitCapability(signed);
          if (mode === 'forged-signature') {
            signed.cose[signed.cose.length - 1] = signed.cose[signed.cose.length - 1]! ^ 1;
            signed.receiptDigest = archiveDigest(signed.cose);
          }
          const insert = () =>
            client.query(
              `insert into control.evidence_archive_receipt(participant_id,privacy_domain_id,receipt_id,intent_id,attempt_id,
          profile_digest,receipt_digest,payload,cose,commit_nonce,commit_mac,recorded_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,timestamptz 'epoch'+($12||' microseconds')::interval)`,
              [
                scope.participantId,
                scope.privacyDomainId,
                claims.receiptId,
                claims.intentId,
                claims.attemptId,
                authority.profileDigest,
                signed.receiptDigest,
                signed.payload,
                signed.cose,
                cap.nonce,
                cap.mac,
                now,
              ],
            );
          if (mode === 'forged-signature') await expect(insert()).rejects.toThrow('PC-AUTH-0005');
          else {
            await insert();
            await expect(client.query('commit')).rejects.toThrow('PC-DATA-6007');
          }
          expect(archiveReceiptEvent(signed).length).toBeGreaterThan(0);
        } finally {
          await client.query('rollback');
          client.release();
        }
        expect(await counts()).toEqual({ receipts: 0, events: 0, nonces: 0, checkpoints: 0 });
      }
      const checkpoint = await custody().exportNext();
      expect(checkpoint).toMatchObject({
        segmentId: admitted.segmentId,
        throughSequence: '1',
        assurance: 'REMOTE_INTERFACE_VERIFIED',
      });
      expect(await counts()).toEqual({ receipts: 1, events: 1, nonces: 1, checkpoints: 1 });
      expect(await custody().exportNext()).toBeNull();
      expect(external.counts.puts).toBe(1);
      const hold = await fixture.prepareMutation(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'PRIVACY_DOMAIN' },
        },
        true,
      );
      await hold.stepUp();
      expect(await hold.commit()).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      expect(
        await fixture.read(`evidence-holds/urn:openpc:resource:${hold.resourceId}`),
      ).toMatchObject({ status: 200, body: { coverage: 'PENDING' } });
      external.faults.dropHoldResponse = true;
      await expect(custody().reconcileHolds()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.holds).toBe(1);
      expect(await custody().reconcileHolds()).toMatchObject({
        result: 'PROTECTION',
        assurance: 'REMOTE_INTERFACE_VERIFIED',
      });
      expect(external.counts.holds).toBe(1);
      expect(await counts()).toEqual({ receipts: 2, events: 2, nonces: 2, checkpoints: 1 });
      expect(
        await fixture.read(`evidence-holds/urn:openpc:resource:${hold.resourceId}`),
      ).toMatchObject({ status: 200, body: { coverage: 'VERIFIED' } });
      expect(await custody().reconcileHolds()).toBeNull();
      const receipts = (
        await admin.query<{ previous: string | null; digest: string }>(
          `select previous_receipt_digest as previous,receipt_digest as digest
      from control.evidence_archive_receipt where participant_id=$1 order by recorded_at`,
          [scope.participantId],
        )
      ).rows;
      expect(receipts[0]!.previous).toBeNull();
      expect(receipts[1]!.previous).toBe(receipts[0]!.digest);
      expect(
        (
          await admin.query(
            'select receipt_digest from control.evidence_checkpoint where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0]!.receipt_digest,
      ).toBe(receipts[0]!.digest);
      const exporter = () =>
        new EvidenceExportWorker(
          worker,
          new RemoteArchiveEvidenceReader(worker, authority, async () => credentials),
          async (requestedScope, keyId) => {
            expect(requestedScope).toEqual(scope);
            expect(keyId).toBe(encryption.keyId);
            return encryption.key;
          },
        );
      const startExport = async () => {
        const created = await fixture!.attemptMutation(
          'evidence-exports/from-selection',
          'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
          {
            participantId: `urn:openpc:participant:${scope.participantId}`,
            selection: {
              streamId: scope.streamId,
              fromSequence: '1',
              throughSequence: '1',
              redactionProfileId: 'pc.evidence.minimized-audit.v1',
            },
          },
        );
        expect(created).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
        const ref = String(created.body.resourceRef);
        const requested = await fixture!.read(`evidence-exports/${ref}`);
        const prepared = await fixture!.prepareMutation(
          `evidence-exports/${ref}/export`,
          'ACT-EVIDENCE_EXPORT_RECORDS-V1',
          {
            targetRef: ref,
            expectedRevision: '1',
            inputDigest: String(requested.body.requestDigest),
          },
          true,
        );
        expect((await prepared.commit()).status).toBe(403);
        await prepared.stepUp();
        expect(await prepared.commit()).toMatchObject({ status: 202, body: { state: 'ACCEPTED' } });
        return ref;
      };
      // Approved exports use original signed history and exact remote bytes.
      // A transient denial keeps the same request; corrupt bytes never produce output.
      const exportRef = await startExport();
      external.faults.denyRead = true;
      expect(await exporter().runNext(scope)).toMatchObject({ state: 'BACKLOGGED' });
      expect((await fixture.read(`evidence-exports/${exportRef}/artifact`)).status).toBe(404);
      external.faults.denyRead = false;
      expect(await exporter().runNext(scope)).toMatchObject({ state: 'SUCCEEDED' });
      const download = await fixture.read(`evidence-exports/${exportRef}/artifact`);
      expect(download).toMatchObject({
        status: 200,
        body: {
          artifact: {
            assurance: 'REMOTE_INTERFACE_VERIFIED',
            providerQualification: 'NOT_ESTABLISHED',
          },
        },
      });
      expect(sha256(download.body.artifact)).toBe(download.body.outputDigest);
      expect(JSON.stringify(download.body)).not.toMatch(
        /receiptBase64|sourceRecordId|ciphertext|cose|commitNonce|keyId/,
      );
      await fixture.restartConfiguration(signing.evidence);
      expect((await fixture.read(`evidence-exports/${exportRef}/artifact`)).body).toEqual(
        download.body,
      );
      const corruptRef = await startExport();
      external.faults.corruptRead = true;
      expect(await exporter().runNext(scope)).toMatchObject({ state: 'FAILED' });
      expect((await fixture.read(`evidence-exports/${corruptRef}/artifact`)).status).toBe(404);
      external.faults.corruptRead = false;
      expect(external.counts.puts).toBe(1);
      expect(external.counts.holds).toBe(1);
      const revokedExportRef = await startExport();
      await admin.query("update control.credential set state='REVOKED' where credential_id=$1", [
        archiveSigning.workloadCredentialId,
      ]);
      await expect(custody().exportNext()).rejects.toThrow('PC-AUTH-0005');
      await expect(exporter().runNext(scope)).rejects.toThrow('PC-AUTH-0005');
      expect((await fixture.read(`evidence-exports/${revokedExportRef}`)).body.state).toBe(
        'RUNNING',
      );
      expect((await fixture.read(`evidence-exports/${revokedExportRef}/artifact`)).status).toBe(
        404,
      );
      expect(external.counts.puts).toBe(1);
      expect(external.counts.holds).toBe(1);
      expect(await counts()).toEqual({ receipts: 2, events: 2, nonces: 2, checkpoints: 1 });
    } finally {
      await clearFault();
      archiveSigning?.close();
      signing?.close();
      encryption.key.fill(0);
      await fixture?.close();
      await external?.close();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
