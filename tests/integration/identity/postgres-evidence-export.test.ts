import { assertExportCompletionPreparationCases } from './export-completion-preparation-cases.js';
import { assertNotificationSourceReadbackCases } from './notification-source-readback-cases.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import type { TLSSocket } from 'node:tls';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { withEvidenceExportProducerPeer } from '../../../services/control-api/src/evidence/export-producer-peer.js';
import {
  installEvidenceExportProducer,
  fenceEvidenceExportProducer,
  withdrawEvidenceExportProducer,
  validateEvidenceExportProducerInstallation,
} from '../../../services/control-api/src/evidence/export-producer-installation.js';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { EvidenceExportWorker } from '../../../services/control-api/src/evidence/export-worker.js';
import { readEvidenceExportCompletionSource } from '../../../services/control-api/src/evidence/export-completion-source.js';
import { encodeEvidenceExportCompletedData } from '../../../packages/security-kernel/src/index.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;

// SEM-055/058/061/137 and PQ-000272: real public governance, database, encrypted
// custody and sink. Initial receipt bytes here are explicit source fixtures;
// source authentication is exercised by the local-runtime signed-business journey.
integration(
  'exports an approved exact scoped range only after verified custody, with immutable redacted restart readback',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const workerPool = new Pool({ connectionString: workerUrl, max: 2 });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'control-receipts' };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'evidence-export-'));
    const key = randomBytes(32),
      keyId = 'test-key';
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      const executable = join(root, 'evidence-worker.mjs');
      await promisify(execFile)(
        'pnpm',
        [
          '--dir',
          'services/control-api',
          'exec',
          'esbuild',
          'src/evidence/runtime.ts',
          '--bundle',
          '--platform=node',
          '--format=esm',
          '--banner:js=import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          `--outfile=${executable}`,
        ],
        { timeout: 10000, maxBuffer: 16384 },
      );
      const database = new URL(workerUrl!);
      await writeFile(join(root, 'password'), decodeURIComponent(database.password), {
        mode: 0o600,
      });
      await writeFile(join(root, 'encryption.key'), key, { mode: 0o600 });
      const configuration = join(root, 'worker-config.json');
      await writeFile(
        configuration,
        JSON.stringify({
          database: {
            host: database.hostname,
            port: Number(database.port),
            database: database.pathname.slice(1),
            user: database.username,
            passwordFile: join(root, 'password'),
          },
          vaultDirectory: join(root, 'vault'),
          sinkId: 'local-sink',
          scopes: [
            {
              ...scope,
              activeKeyId: keyId,
              keys: [{ keyId, keyFile: join(root, 'encryption.key') }],
              retentionSeconds: 86400,
              capacityBytes: 65536,
            },
          ],
        }),
        { mode: 0o600 },
      );
      const runWorker = () =>
        promisify(execFile)(process.execPath, [executable, '--once'], {
          env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
          timeout: 10000,
          maxBuffer: 16384,
        });
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      expect((await fixture.read('evidence-exports')).status).toBe(200);
      const selection = {
        streamId: scope.streamId,
        fromSequence: '1',
        throughSequence: '3',
        redactionProfileId: 'pc.evidence.minimized-audit.v1',
      };
      const createAction = 'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
        startAction = 'ACT-EVIDENCE_EXPORT_RECORDS-V1';
      const create = () =>
        fixture!.attemptMutation('evidence-exports/from-selection', createAction, {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          selection,
        });
      expect((await create()).status).toBe(412);
      const custody = new EvidenceCustody(workerPool);
      const records = (['AUTHENTICATION', 'BUSINESS_TRANSITION', 'EFFECT'] as const).map(
        (evidenceClass) => {
          const bytes = Buffer.from(`private credential claim and source fixture ${id()}`);
          return {
            recordId: id(),
            evidenceClass,
            sourceFormat: 'FIXTURE',
            occurredAt: '2026-09-21T00:00:00.000000Z',
            receiptDigest: sha256(bytes),
            receiptBase64: bytes.toString('base64'),
          };
        },
      );
      await custody.admit(scope, records, { keyId, key }, '2027-01-01T00:00:00.000000Z', 65536);
      const created = await create();
      expect(created, JSON.stringify(created)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
      });
      const ref = String(created.body.resourceRef),
        exportId = ref.slice(-36);
      const requested = await fixture.read(`evidence-exports/${ref}`);
      expect(requested).toMatchObject({
        status: 200,
        body: { state: 'REQUESTED', checkpoint: '0', outputDigest: null, revision: '1' },
      });
      const digest = String(requested.body.requestDigest);
      const clone = await fixture.attemptMutation('evidence-exports', createAction, {
        participantId: `urn:openpc:participant:${scope.participantId}`,
        requestDigest: digest,
        checkpoint: '0',
        outputDigest: null,
      });
      expect(clone.status, JSON.stringify(clone)).toBe(202);
      const smaller = await fixture.attemptMutation(
        'evidence-exports/from-selection',
        createAction,
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          selection: { ...selection, throughSequence: '2' },
        },
      );
      expect(smaller.status, JSON.stringify(smaller)).toBe(202);
      const smallerRef = String(smaller.body.resourceRef);
      const smallerDigest = String(
        (await fixture.read(`evidence-exports/${smallerRef}`)).body.requestDigest,
      );
      const update = () =>
        fixture!.attemptMutation(
          `evidence-exports/${clone.body.resourceRef}`,
          'ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1',
          {
            expectedRevision: '1',
            replacementDigest: smallerDigest,
          },
          'PATCH',
        );
      expect((await update()).status).toBe(202);
      expect((await update()).status).toBe(412);
      expect((await fixture.read(`evidence-exports/${clone.body.resourceRef}`)).body).toMatchObject(
        { revision: '2', requestDigest: smallerDigest },
      );
      const selected = await fixture.read(`evidence-exports/${ref}/selection`);
      expect(selected.status).toBe(200);
      expect(selected.body).toMatchObject({ requestDigest: digest, range: selection });
      expect(selected.body.records).toHaveLength(3);
      expect(JSON.stringify(selected.body)).not.toMatch(/sourceRecordId|receiptBase64|keyId/);
      expect((await fixture.read(`evidence-exports/${ref}/artifact`)).status).toBe(404);
      const invented = await fixture.attemptMutation('evidence-exports', createAction, {
        participantId: `urn:openpc:participant:${scope.participantId}`,
        requestDigest: sha256('invented'),
        checkpoint: '0',
        outputDigest: null,
      });
      expect(invented.status).toBe(412);
      expect(
        (
          await fixture.attemptMutation('evidence-exports', createAction, {
            participantId: `urn:openpc:participant:${scope.participantId}`,
            requestDigest: digest,
            checkpoint: '3',
            outputDigest: sha256('invented'),
          })
        ).status,
      ).toBe(400);
      const sink = await LocalEvidenceVault.open(join(root, 'vault'), 'local-sink');
      const exporter = new EvidenceExportWorker(
        workerPool,
        sink,
        async (requestScope, requestedKey) => {
          expect(requestScope).toEqual(scope);
          expect(requestedKey).toBe(keyId);
          return key;
        },
      );
      expect(await exporter.runNext(scope)).toBeNull();
      const prepared = await fixture.prepareMutation(
        `evidence-exports/${ref}/export`,
        startAction,
        {
          targetRef: ref,
          expectedRevision: '1',
          inputDigest: digest,
        },
        true,
      );
      expect((await prepared.commit()).status).toBe(403); // independent approval alone is insufficient
      expect((await fixture.read(`evidence-exports/${ref}`)).body.state).toBe('REQUESTED');
      await prepared.stepUp();
      const started = await prepared.commit();
      expect(started, JSON.stringify(started)).toMatchObject({
        status: 202,
        body: { state: 'ACCEPTED', truthState: 'UNKNOWN' },
      });
      expect((await prepared.commit()).body).toEqual(started.body);
      expect((await fixture.read(`operations/${started.body.operationId}`)).body).toMatchObject({
        state: 'ACCEPTED',
        truthState: 'UNKNOWN',
      });
      // A later Identity upgrade runs after Control's grants already exist.
      // Exercise that populated order before the worker's real checkpoint and
      // export guards call the shared encoder; clean-install order hid this bug.
      const migrations = new URL('../../../migrations/postgres/identity/', import.meta.url);
      const latestMigration = (await readdir(migrations))
        .filter((name) => name.endsWith('.sql'))
        .sort()
        .at(-1)!;
      const migration = await readFile(new URL(latestMigration, migrations), 'utf8');
      const marker = '-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT';
      expect(migration.includes(marker)).toBe(true);
      await admin.query(migration.slice(migration.indexOf(marker)));
      expect(
        (
          await workerPool.query(`select
        has_function_privilege(current_user,'openpc.signing_canonical_json(jsonb)','EXECUTE') encoder,
        has_function_privilege(current_user,'openpc.check_signing_generation_current(uuid)','EXECUTE') signing`)
        ).rows,
      ).toEqual([{ encoder: true, signing: false }]);
      // Archive absence cannot be turned into a successful export by a caller.
      expect(await exporter.runNext(scope)).toEqual({
        evidenceExportId: exportId,
        state: 'BACKLOGGED',
      });
      expect((await fixture.read(`evidence-exports/${ref}`)).body).toMatchObject({
        state: 'BACKLOGGED',
        checkpoint: '0',
        outputDigest: null,
      });
      expect((await fixture.read(`evidence-exports/${ref}/artifact`)).status).toBe(404);
      await custody.exportNext(scope, sink);
      const forged = await workerPool.connect();
      try {
        await forged.query('begin');
        await forged.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, started.body.operationId],
        );
        const bytes = Buffer.from('{"unfilteredSecret":"forbidden"}');
        await expect(
          forged.query(
            `insert into control.evidence_export_output(participant_id,privacy_domain_id,stream_id,
          evidence_export_id,sink_id,output_digest,artifact) values($1,$2,$3,$4,$5,$6,$7)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              scope.streamId,
              exportId,
              sink.sinkId,
              sha256(bytes),
              bytes,
            ],
          ),
        ).rejects.toThrow('PC-DATA-6007');
        await forged.query('rollback');
      } finally {
        forged.release();
      }
      // An interrupted completion transaction leaves no partial artifact and is restartable.
      await admin.query(`create function openpc.test_evidence_export_failure() returns trigger language plpgsql as $$ begin
      if NEW.state='SUCCEEDED' then raise exception 'TEST_EXPORT_COMMIT_FAILURE'; end if; return NEW; end $$;
      create trigger test_evidence_export_failure before update on control.evidence_export_request for each row execute function openpc.test_evidence_export_failure()`);
      await expect(exporter.runNext(scope)).rejects.toThrow('TEST_EXPORT_COMMIT_FAILURE');
      expect(
        (
          await admin.query(
            'select 1 from control.evidence_export_output where evidence_export_id=$1',
            [exportId],
          )
        ).rowCount,
      ).toBe(0);
      await admin.query(
        'drop trigger test_evidence_export_failure on control.evidence_export_request; drop function openpc.test_evidence_export_failure()',
      );
      expect(await runWorker()).toMatchObject({ stdout: '', stderr: '' });
      // Real WebAuthn verifications above produce independent immutable
      // authentication occurrences; fixture receipt bytes do not prove this path.
      const authenticationScope = { ...scope, streamId: 'identity-authentication' };
      const occurrences = (
        await admin.query(
          `select occurrence_id::text id,receipt from control.authentication_occurrence
         where participant_id=$1 and privacy_domain_id=$2 order by occurred_at,occurrence_id`,
          [scope.participantId, scope.privacyDomainId],
        )
      ).rows;
      expect(occurrences.length).toBeGreaterThan(0);
      expect(occurrences.length).toBeLessThanOrEqual(8);
      const workerConfiguration = JSON.parse(await readFile(configuration, 'utf8'));
      workerConfiguration.scopes.push({
        ...workerConfiguration.scopes[0],
        ...authenticationScope,
        source: 'AUTHENTICATION',
      });
      await writeFile(configuration, JSON.stringify(workerConfiguration), { mode: 0o600 });
      expect(await runWorker()).toMatchObject({ stdout: '', stderr: '' });
      expect(
        await custody.ingestAuthentication(
          authenticationScope,
          { keyId, key },
          '2027-01-01T00:00:00.000000Z',
          65536,
        ),
      ).toBeNull();
      await custody.exportNext(authenticationScope, sink);
      const authenticationCheckpoint = (
        await admin.query(
          `select receipt from control.evidence_checkpoint
         where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
          [scope.participantId, scope.privacyDomainId, authenticationScope.streamId],
        )
      ).rows[0].receipt;
      expect(authenticationCheckpoint.object.throughSequence).toBe(String(occurrences.length));
      const authenticationBytes = await sink.read(authenticationCheckpoint.object);
      const openedAuthentication = openSegment(
        authenticationBytes,
        authenticationCheckpoint.object.objectDigest,
        inspectSegment(authenticationBytes).header,
        key,
      );
      expect(openedAuthentication.records.map((record) => record.evidenceClass)).toEqual(
        occurrences.map(() => 'AUTHENTICATION'),
      );
      expect(
        openedAuthentication.records.map((record) => Buffer.from(record.receiptBase64, 'base64')),
      ).toEqual(occurrences.map((row) => row.receipt));
      for (const record of openedAuthentication.records) {
        const receipt = JSON.parse(Buffer.from(record.receiptBase64, 'base64').toString('utf8'));
        expect(receipt).toMatchObject({
          method: 'WEBAUTHN_ASSERTION',
          authorityEffect: 'NONE',
          integrity: 'CONTROL_DATABASE_IMMUTABLE',
        });
        expect(record.sourceFormat).toBe('OPENPC_AUTHENTICATION_OCCURRENCE_V1');
      }
      const catalogue = await fixture.read('evidence-records?limit=100');
      expect(catalogue.status).toBe(200);
      expect(
        (catalogue.body.items as { evidenceClass: string }[]).filter(
          (row) => row.evidenceClass === 'AUTHENTICATION',
        ),
      ).toHaveLength(occurrences.length + 1); // Includes the explicitly labelled original fixture.
      expect(
        (
          await admin.query(
            'select 1 from control.evidence_export_output where evidence_export_id=$1',
            [exportId],
          )
        ).rowCount,
      ).toBe(1);
      const artifact = await fixture.read(`evidence-exports/${ref}/artifact`);
      expect(artifact.status, JSON.stringify(artifact.body)).toBe(200);
      expect(artifact.headers.get('cache-control')).toBe('no-store');
      expect(sha256(artifact.body.artifact)).toBe(artifact.body.outputDigest);
      expect(
        artifact.body.artifact.records.map((r: { recordDigest: string }) => r.recordDigest),
      ).toEqual(records.map((r) => r.receiptDigest));
      expect(JSON.stringify(artifact.body)).not.toMatch(
        /receiptBase64|sourceRecordId|private credential|keyId|FIXTURE/,
      );
      const completed = await fixture.read(`evidence-exports/${ref}`);
      expect(completed.body).toMatchObject({
        state: 'SUCCEEDED',
        checkpoint: '3',
        outputDigest: artifact.body.outputDigest,
      });
      const sourceReader = await workerPool.connect();
      try {
        await sourceReader.query('begin');
        await sourceReader.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        const completion = await readEvidenceExportCompletionSource(sourceReader, scope, exportId);
        expect(completion.source).toMatchObject({
          ...scope,
          evidenceExportId: exportId,
          startOperationId: started.body.operationId,
          requestDigest: digest,
          checkpoint: '3',
          recordCount: '3',
          outputDigest: artifact.body.outputDigest,
        });
        expect(completion.data).toEqual(
          encodeEvidenceExportCompletedData({
            evidenceExportId: exportId,
            checkpoint: '3',
            recordCount: '3',
            outputDigest: artifact.body.outputDigest,
          }),
        );
        expect(completion.dataDigest).toBe(sha256(completion.data));
        const cause = await sourceReader.query(
          `select event_type,payload_digest=sha256(payload_cbor) valid
          from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
          [scope.participantId, scope.privacyDomainId, completion.source.causationId],
        );
        expect(cause.rows).toEqual([
          { event_type: 'openpc.evidence.export.started.v1', valid: true },
        ]);
        await expect(
          readEvidenceExportCompletionSource(
            sourceReader,
            { ...scope, streamId: 'foreign-stream' },
            exportId,
          ),
        ).rejects.toMatchObject({ code: 'INTEGRITY' });
        await sourceReader.query('rollback');
        await sourceReader.query('begin');
        await sourceReader.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, id(), id()],
        );
        await expect(
          readEvidenceExportCompletionSource(sourceReader, scope, exportId),
        ).rejects.toThrow('EVIDENCE-EXPORT-COMPLETION-SOURCE');
      } finally {
        await sourceReader.query('rollback');
        sourceReader.release();
      }
      expect((await fixture.read(`operations/${started.body.operationId}`)).body).toMatchObject({
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
      });
      await fixture.restartConfiguration();
      expect((await fixture.read(`evidence-exports/${ref}/artifact`)).body).toEqual(artifact.body);
      expect(
        await new EvidenceExportWorker(
          workerPool,
          await LocalEvidenceVault.open(join(root, 'vault'), 'local-sink'),
          async () => key,
        ).runNext(scope),
      ).toBeNull();
      expect((await prepared.commit()).body).toEqual(started.body); // original acceptance remains immutable
      const rejected = await fixture.prepareMutation(
        `evidence-exports/${smallerRef}/export`,
        startAction,
        {
          targetRef: smallerRef,
          expectedRevision: '1',
          inputDigest: smallerDigest,
        },
        true,
      );
      await rejected.stepUp();
      const rejectedStart = await rejected.commit();
      expect(rejectedStart.status).toBe(202);
      const invalidKey = randomBytes(32);
      const invalidExporter = new EvidenceExportWorker(workerPool, sink, async () => invalidKey);
      const concurrent = await Promise.all([
        invalidExporter.runNext(scope),
        invalidExporter.runNext(scope),
      ]);
      expect(concurrent.filter(Boolean)).toHaveLength(1);
      expect(concurrent.find(Boolean)).toMatchObject({
        evidenceExportId: smallerRef.slice(-36),
        state: 'FAILED',
      });
      invalidKey.fill(0);
      expect((await fixture.read(`evidence-exports/${smallerRef}`)).body).toMatchObject({
        state: 'FAILED',
        outputDigest: null,
        checkpoint: '0',
      });
      expect((await fixture.read(`evidence-exports/${smallerRef}/artifact`)).status).toBe(404);
      expect(
        (await fixture.read(`operations/${rejectedStart.body.operationId}`)).body,
      ).toMatchObject({ state: 'FAILED', truthState: 'FAILED' });
      expect(await runWorker()).toMatchObject({ stdout: '', stderr: '' });
      expect((await fixture.read(`evidence-exports/${ref}/artifact`, { Cookie: '' })).status).toBe(
        401,
      );
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read('evidence-exports')).body).toMatchObject({
        items: [],
        total: '0',
        authorizedEmpty: true,
      });
      expect((await foreign.read(`evidence-exports/${ref}/artifact`)).status).toBe(404);
      expect(
        (
          await foreign.attemptMutation('evidence-exports', createAction, {
            participantId: `urn:openpc:participant:${foreign.participantId}`,
            requestDigest: digest,
            checkpoint: '0',
            outputDigest: null,
          })
        ).status,
      ).toBe(412);
      // Join the original approved output to the notification adapter without
      // producer publication, new export effects or replacement signed bytes.
      // Output rows cannot be overwritten, even by the worker with the exact operation context.
      const client = await workerPool.connect();
      try {
        await client.query('begin');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, started.body.operationId],
        );
        await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
        await assertNotificationSourceReadbackCases({
          client,
          scope,
          completionSource: await readEvidenceExportCompletionSource(client, scope, exportId),
          fixture,
          foreign,
        });
        await expect(
          client.query(
            'update control.evidence_export_output set artifact=$2 where evidence_export_id=$1',
            [exportId, Buffer.from('forged')],
          ),
        ).rejects.toThrow('permission denied');
        await client.query('rollback');
      } finally {
        client.release();
      }
      await assertExportCompletionPreparationCases(admin, workerPool, scope, exportId, {
        participantId: foreign.participantId,
        privacyDomainId: foreign.privacyDomainId,
        streamId: scope.streamId,
      });
    } finally {
      key.fill(0);
      await foreign?.close();
      await fixture?.close();
      await workerPool.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  30000,
);

// Initial public trust, real mTLS and credential-state fences. Provider signing
// and durable completion/outbox acceptance remain separate obligations.
integration(
  'fences exact installed export trust, withdrawal and current credentials without granting runtime enrollment',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const installer = new Pool({
      connectionString: adminUrl,
      max: 2,
      options: '-c role=openpc_control_owner',
    });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
      max: 2,
    });
    let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
    let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
    const scope = { participantId: id(), privacyDomainId: id() };
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const signingKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      type: 'spki',
      format: 'der',
    });
    const principalId = id(),
      credentialId = id(),
      workloadId = `urn:openpc:workload:${id()}`;
    const now = BigInt(Date.now()) * 1000000n;
    const pins = {
      owner: 'LS-EVIDENCE-EXPORT' as const,
      purpose: 'pc.cose.evidence-export-completion-receipt.v1' as const,
      environmentId: 'local-export',
      ...scope,
      sourceId: id(),
      principalId,
      workloadCredentialId: credentialId,
      workloadEpoch: '1',
      workloadId,
      secretClass: 'SECRET-SIGNING-KEY' as const,
      secretReference: 'secret://export-test/signer#v1',
      secretVersion: 'v1',
      publicKeySpkiHex: signingKey.toString('hex'),
      keyEpoch: '1',
      validFromNs: String(now - 1000000000n),
      validUntilNs: String(now + 600000000000n),
      installationReference: 'local-initial-trust',
    };
    const scoped = async <T>(
      pool: Pool,
      fn: (client: import('pg').PoolClient) => Promise<T>,
      privacy = scope.privacyDomainId,
    ) => {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, privacy, id()],
        );
        const result = await fn(client);
        await client.query('commit');
        return result;
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    };
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      tls = await runtimeSnapshotTlsFixture(
        `urn:openpc:participant:${scope.participantId}:workload:${workloadId.slice(-36)}`,
      );
      const tlsKey = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Export producer initial trust','ACTIVE',1)`,
        [principalId, scope.participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-export-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          scope.participantId,
          principalId,
          `urn:openpc:participant:${scope.participantId}:workload:${workloadId.slice(-36)}`,
          workloadId,
          Buffer.from(sha256(tlsKey).slice(7), 'hex'),
          tlsKey,
          Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      await expect(
        installEvidenceExportProducer(installer, {
          ...pins,
          publicKeySpkiHex: tlsKey.toString('hex'),
        }),
      ).rejects.toThrow('DATA-6021-EXPORT-PRODUCER-IDENTITY');
      expect((await installer.query('select current_user,session_user')).rows[0]).toMatchObject({
        current_user: 'openpc_control_owner',
        session_user: 'postgres',
      });
      const trustDigest = await installEvidenceExportProducer(installer, pins);
      expect(await installEvidenceExportProducer(installer, pins)).toBe(trustDigest);
      await expect(installEvidenceExportProducer(worker, pins)).rejects.toThrow(
        'permission denied',
      );
      await expect(
        installEvidenceExportProducer(installer, { ...pins, keyEpoch: '2' }),
      ).rejects.toThrow('installation conflict');
      await expect(
        scoped(worker, (client) => fenceEvidenceExportProducer(client, scope, trustDigest)),
      ).rejects.toThrow('permission denied');
      const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      app = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
      let admitted = 0;
      app.post('/test/export-producer', async (req, reply) => {
        try {
          await withEvidenceExportProducerPeer(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            req.body,
            async () => {
              admitted++;
            },
          );
          return { ok: true };
        } catch {
          return reply.code(403).send({ code: 'EXPORT_PRODUCER_UNAVAILABLE' });
        }
      });
      const address = await app.listen({ host: '127.0.0.1', port: 0 });
      const request = { ...scope, trustDigest };
      expect(await tls.post(`${address}/test/export-producer`, request)).toMatchObject({
        status: 200,
      });
      expect(admitted).toBe(1);
      for (const changed of [
        { ...request, participantId: id() },
        { ...request, privacyDomainId: id() },
        { ...request, trustDigest: 'sha256:' + '00'.repeat(32) },
        { ...request, authorized: true },
      ])
        expect(await tls.post(`${address}/test/export-producer`, changed)).toMatchObject({
          status: 403,
        });
      await expect(tls.post(`${address}/test/export-producer`, request, null)).rejects.toThrow();
      expect(admitted).toBe(1);
      const expired = await installEvidenceExportProducer(installer, {
        ...pins,
        sourceId: id(),
        validFromNs: String(now - 2000000000n),
        validUntilNs: String(now - 1000000000n),
      });
      expect(
        await tls.post(`${address}/test/export-producer`, { ...request, trustDigest: expired }),
      ).toMatchObject({ status: 403 });
      expect(admitted).toBe(1);
      const selected = await scoped(runtime, (client) =>
        fenceEvidenceExportProducer(client, scope, trustDigest),
      );
      expect(selected.bytes).toEqual(validateEvidenceExportProducerInstallation(pins).bytes);
      expect(selected.authorityDigest).toBe(sha256(selected.authority));
      expect(JSON.parse(selected.authority.toString())).toMatchObject({
        installationDigest: trustDigest,
        workloadEpoch: '1',
        workloadCredentialId: credentialId,
      });
      await expect(
        scoped(runtime, (client) =>
          fenceEvidenceExportProducer(client, { ...scope, privacyDomainId: id() }, trustDigest),
        ),
      ).rejects.toThrow('unavailable');
      await expect(
        scoped(admin, (client) =>
          client.query(
            `update control.evidence_export_producer_installation set environment_id='substituted' where trust_digest=$1`,
            [trustDigest],
          ),
        ),
      ).rejects.toThrow('IMMUTABLE');
      await expect(
        scoped(admin, (client) =>
          client.query(
            `delete from control.evidence_export_producer_installation where trust_digest=$1`,
            [trustDigest],
          ),
        ),
      ).rejects.toThrow('IMMUTABLE');
      // A competing direct writer cannot wait with a reversed row/fence order.
      await scoped(runtime, async (reader) => {
        await fenceEvidenceExportProducer(reader, scope, trustDigest);
        await expect(
          scoped(admin, (writer) =>
            writer.query(
              `update control.evidence_export_producer_installation set state='REVOKED' where trust_digest=$1`,
              [trustDigest],
            ),
          ),
        ).rejects.toThrow('PC-DATA-6007');
      });
      await withdrawEvidenceExportProducer(installer, scope, trustDigest);
      expect(await tls.post(`${address}/test/export-producer`, request)).toMatchObject({
        status: 403,
      });
      expect(admitted).toBe(1);
      await withdrawEvidenceExportProducer(installer, scope, trustDigest);
      await expect(
        scoped(runtime, (client) => fenceEvidenceExportProducer(client, scope, trustDigest)),
      ).rejects.toThrow('withdrawn');
      await expect(installEvidenceExportProducer(installer, pins)).rejects.toThrow(
        'installation conflict',
      );
      await expect(
        scoped(admin, (client) =>
          client.query(
            `update control.evidence_export_producer_installation set state='ACTIVE' where trust_digest=$1`,
            [trustDigest],
          ),
        ),
      ).rejects.toThrow('IMMUTABLE');
      // A separate, explicitly installed source tests current epoch rejection;
      // it does not replace or renew the withdrawn original trust.
      const next = await installEvidenceExportProducer(installer, { ...pins, sourceId: id() });
      await admin.query(
        `update control.credential set credential_epoch=credential_epoch+1 where participant_id=$1 and credential_id=$2`,
        [scope.participantId, credentialId],
      );
      await expect(
        scoped(runtime, (client) => fenceEvidenceExportProducer(client, scope, next)),
      ).rejects.toThrow('authority unavailable');
    } finally {
      await app?.close();
      await tls?.close();
      await runtime.end();
      await fixture?.close();
      await worker.end();
      await installer.end();
      await admin.end();
    }
  },
  30000,
);
