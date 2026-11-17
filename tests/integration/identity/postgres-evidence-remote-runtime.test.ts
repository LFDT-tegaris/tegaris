import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceArchiveAuthorityFixture } from './evidence-archive-authority-fixture.js';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;
const fixtureUrl = new URL('../local-runtime/evidence-remote-archive-fixture.mjs', import.meta.url);
const { startRemoteArchiveFixture } = (await import(fixtureUrl.href)) as {
  startRemoteArchiveFixture(options: {
    root: string;
    bucket: string;
    expectedOwner: string;
    region: string;
    credentials: S3ArchiveCredentials;
  }): Promise<{
    endpoint: string;
    counts: { puts: number; holds: number };
    close(): Promise<void>;
  }>;
};

// Real executable, mounted host trust and PostgreSQL owners. The labelled
// admitted source is supporting data, not acceptance of its authentication journey.
integration(
  'runs mounted remote custody and approved minimized export across worker restarts',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'remote-runtime-'));
    const key = randomBytes(32),
      keyId = 'runtime-encryption';
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'remote-runtime' };
    let governance: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let trust: Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>> | undefined;
    let external: Awaited<ReturnType<typeof startRemoteArchiveFixture>> | undefined;
    try {
      // Build stable prerequisites before acquiring the signed profile window.
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
        { timeout: 20000, maxBuffer: 16384 },
      );
      governance = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
      );
      const credentials = {
        accessKeyId: 'RUNTIMEARCHIVEKEY',
        secretAccessKey: randomBytes(32).toString('hex'),
      };
      external = await startRemoteArchiveFixture({
        root: join(root, 'external'),
        credentials,
        bucket: 'runtime-archive',
        expectedOwner: '123456789012',
        region: 'local-1',
      });
      const transport = {
        profileId: 'runtime-archive',
        sinkId: 'remote-runtime-sink',
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST' as const,
        region: 'local-1',
        bucket: 'runtime-archive',
        expectedBucketOwner: '123456789012',
        prefix: 'evidence',
        lockMode: 'COMPLIANCE' as const,
        requestTimeoutMs: 10000,
        maxVersionPages: 4,
      };
      trust = await evidenceArchiveAuthorityFixture(
        admin,
        worker,
        scope,
        [scope.streamId],
        transport,
        { directory: root, credentials },
      );
      expect(trust.runtimeConfiguration).toBeDefined();
      const source = Buffer.from('private labelled source for packaged remote custody');
      await new EvidenceCustody(worker).admit(
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
        { keyId, key },
        '2027-01-01T00:00:00.000000Z',
        65536,
      );
      const database = new URL(workerUrl!);
      const passwordFile = join(root, 'password'),
        encryptionFile = join(root, 'encryption.key'),
        configuration = join(root, 'worker.json');
      await writeFile(passwordFile, decodeURIComponent(database.password), { mode: 0o600 });
      await writeFile(encryptionFile, key, { mode: 0o600 });
      await writeFile(
        configuration,
        JSON.stringify({
          database: {
            host: database.hostname,
            port: Number(database.port),
            database: database.pathname.slice(1),
            user: database.username,
            passwordFile,
          },
          vaultDirectory: join(root, 'vault'),
          sinkId: 'local-runtime-sink',
          remoteArchives: [trust.runtimeConfiguration],
          scopes: [
            {
              ...scope,
              exportSinkId: transport.sinkId,
              activeKeyId: keyId,
              keys: [{ keyId, keyFile: encryptionFile }],
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
          timeout: 30000,
          maxBuffer: 16384,
        });
      await runWorker();
      const created = await governance.attemptMutation(
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
      const requested = await governance.read(`evidence-exports/${ref}`);
      const prepared = await governance.prepareMutation(
        `evidence-exports/${ref}/export`,
        'ACT-EVIDENCE_EXPORT_RECORDS-V1',
        {
          targetRef: ref,
          expectedRevision: '1',
          inputDigest: String(requested.body.requestDigest),
        },
        true,
      );
      await prepared.stepUp();
      expect(await prepared.commit()).toMatchObject({ status: 202, body: { state: 'ACCEPTED' } });
      await runWorker();
      const download = await governance.read(`evidence-exports/${ref}/artifact`);
      expect(download).toMatchObject({
        status: 200,
        body: {
          artifact: {
            sinkId: transport.sinkId,
            assurance: 'REMOTE_INTERFACE_VERIFIED',
            providerQualification: 'NOT_ESTABLISHED',
          },
        },
      });
      expect(sha256(download.body.artifact)).toBe(download.body.outputDigest);
      expect(JSON.stringify(download.body)).not.toMatch(
        /receiptBase64|ciphertext|sourceRecordId|private labelled source/,
      );
      const puts = external.counts.puts;
      await runWorker();
      expect(external.counts.puts).toBe(puts);
      expect((await governance.read(`evidence-exports/${ref}/artifact`)).body).toEqual(
        download.body,
      );
      const journal = await admin.query(
        `select count(*)::int attempts from control.evidence_remote_archive_attempt
      where participant_id=$1 and action='PUT' and state='OBSERVED'`,
        [scope.participantId],
      );
      expect(journal.rows[0].attempts).toBe(puts);
      expect(puts).toBeGreaterThan(0);
    } finally {
      trust?.close();
      key.fill(0);
      await governance?.close();
      await external?.close();
      await Promise.all([worker.end(), admin.end()]);
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
