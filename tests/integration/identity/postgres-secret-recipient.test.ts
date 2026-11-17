import { createHash, generateKeyPairSync } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signSecretRecipientProfile,
  type SecretRecipientProfile,
  type InstalledSecretRecipient,
} from '../../../packages/security-kernel/src/index.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import {
  installInitialSecretRecipient,
  assertInstalledSecretRecipientNotRevoked,
  withInstalledSecretRecipient,
} from '../../../services/identity-service/src/domain/secret-recipient.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const sha = (b: Buffer) => createHash('sha256').update(b).digest();
// Initial installation trust is a real signed local fixture. This tests the
// authenticated recipient boundary, not secret publication or pool revocation.
integration(
  'requires installed exact recipient pins and fences revocation through real TLS',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 }),
      runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const scope = { participantId: id(), privacyDomainId: id() };
    const principalId = id(),
      credentialId = id(),
      workloadId = id();
    const uriSan = `urn:openpc:participant:${scope.participantId}:workload:${workloadId}`;
    const tls = await runtimeSnapshotTlsFixture(uriSan);
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
      );
      const publicKey = tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
      const input = {
        participantId: scope.participantId,
        workloadId: `urn:openpc:workload:${workloadId}`,
        uriSan,
        keyId: `sha256:${sha(publicKey).toString('hex')}`,
        certificateFingerprint: sha(tls.parsed.raw),
        notBefore: new Date(tls.parsed.validFrom),
        notAfter: new Date(tls.parsed.validTo),
        participantEpoch: '1',
        workloadEpoch: '1',
        tlsVersion: 'TLS1.3' as const,
        issuerTrusted: true,
        keyTrusted: true,
        revoked: false,
      };
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Authentication evidence initial trust','ACTIVE',1)`,
        [principalId, scope.participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          scope.participantId,
          principalId,
          uriSan,
          input.workloadId,
          sha(publicKey),
          publicKey,
          input.certificateFingerprint,
          input.notBefore,
          input.notAfter,
        ],
      );

      const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const spki = key.publicKey.export({ format: 'der', type: 'spki' });
      const privateKey = key.privateKey.export({ format: 'der', type: 'pkcs8' });
      const profile: SecretRecipientProfile = {
        ...scope,
        environmentId: 'local-test',
        installationDigest: `sha256:${sha(Buffer.from('isolated installed configuration')).toString('hex')}`,
        generation: '1',
        consumerId: 'LS-FACT-BRIDGE',
        secretClass: 'SECRET-DB-CREDENTIAL',
        purpose: 'POSTGRES_CONNECT',
        store: 'STORE-CANDIDATE-INDEX-PG',
        reference: 'secret://test-memory-resolver/candidate-db#v1',
        version: 'v1',
        principalId,
        workloadCredentialId: credentialId,
        workloadCredentialEpoch: '1',
        validFromMs: Date.now() - 1000,
        validUntilMs: Date.now() + 600000,
        issuerKeyId: evidenceKeyId(spki),
      };
      const { payload, cose } = signSecretRecipientProfile(privateKey, spki, profile);
      privateKey.fill(0);
      const pins: InstalledSecretRecipient = {
        ...profile,
        issuerSpkiDer: spki,
        signedBindingDigest: `sha256:${sha(cose).toString('hex')}`,
      };
      const initial = await admin.connect();
      try {
        await initial.query('begin');
        await installInitialSecretRecipient(
          initial,
          pins,
          payload,
          cose,
          'test-initial-installed-configuration',
        );
        await installInitialSecretRecipient(
          initial,
          pins,
          payload,
          cose,
          'test-initial-installed-configuration',
        );
        await initial.query('commit');
      } finally {
        initial.release();
      }
      const retained = async () =>
        (
          await admin.query(
            'select * from control.installed_secret_recipient where participant_id=$1',
            [scope.participantId],
          )
        ).rows;
      const original = await retained();
      expect(original).toHaveLength(1);
      const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      let installed = pins,
        calls = 0;
      let callback: () => Promise<void> = async () => {};
      const build = () => {
        const server = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
        server.post('/test/recipient', async (req, reply) => {
          try {
            await withInstalledSecretRecipient(
              runtime,
              kernel,
              req.raw.socket as TLSSocket,
              installed,
              req.body as { reference: string; version: string },
              async (admitted) => {
                expect(admitted).toEqual(profile);
                calls++;
                await callback();
              },
            );
            return { ok: true };
          } catch {
            return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
          }
        });
        return server;
      };
      app = build();
      let address = await app.listen({ host: '127.0.0.1', port: 0 });
      const request = { reference: profile.reference, version: profile.version };
      const resolve = (body: unknown = request) => tls.post(`${address}/test/recipient`, body);
      expect(await resolve()).toEqual({ status: 200, body: { ok: true } });
      expect(calls).toBe(1);
      await assertInstalledSecretRecipientNotRevoked(runtime, pins);
      for (const wrong of [
        { reference: profile.reference, version: 'v2' },
        { reference: 'secret://test-memory-resolver/other#v1', version: 'v1' },
      ])
        expect(await resolve(wrong)).toMatchObject({ status: 403 });
      for (const change of [
        { installationDigest: `sha256:${'f'.repeat(64)}` },
        { generation: '2' },
        { principalId: id() },
        { workloadCredentialId: id() },
        { workloadCredentialEpoch: '2' },
        { privacyDomainId: id() },
      ]) {
        installed = { ...pins, ...change };
        expect(await resolve()).toMatchObject({ status: 403 });
        await expect(
          assertInstalledSecretRecipientNotRevoked(runtime, installed),
        ).rejects.toThrow();
      }
      installed = pins;
      expect(calls).toBe(1);
      const denied = await runtime.connect();
      try {
        await denied.query('begin');
        await expect(
          installInitialSecretRecipient(
            denied,
            pins,
            payload,
            cose,
            'test-initial-installed-configuration',
          ),
        ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
        await denied.query('rollback');
        for (const sql of [
          'insert into control.installed_secret_recipient select * from control.installed_secret_recipient where false',
          "update control.installed_secret_recipient set state='REVOKED'",
          'delete from control.installed_secret_recipient',
        ])
          await expect(denied.query(sql)).rejects.toMatchObject({ code: '42501' });
      } finally {
        denied.release();
      }
      expect(await retained()).toEqual(original);
      await expect(
        admin.query(
          'update control.installed_secret_recipient set installation_digest=$2 where participant_id=$1',
          [scope.participantId, `sha256:${'b'.repeat(64)}`],
        ),
      ).rejects.toThrow('OPS-SECRET-INSTALLATION-IMMUTABLE');
      await app.close();
      app = build();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      expect(await resolve()).toEqual({ status: 200, body: { ok: true } });
      expect(calls).toBe(2);
      expect(await retained()).toEqual(original);
      const entered = Promise.withResolvers<void>(),
        release = Promise.withResolvers<void>();
      callback = async () => {
        entered.resolve();
        await release.promise;
      };
      const inFlight = resolve();
      const revoker = await admin.connect();
      let revocation: Promise<unknown> | undefined;
      try {
        await entered.promise;
        const pid = (await revoker.query('select pg_backend_pid() pid')).rows[0].pid;
        revocation = revoker.query(
          "update control.installed_secret_recipient set state='REVOKED' where participant_id=$1",
          [scope.participantId],
        );
        await expect
          .poll(
            async () =>
              (
                await admin.query('select wait_event_type from pg_stat_activity where pid=$1', [
                  pid,
                ])
              ).rows[0]?.wait_event_type,
          )
          .toBe('Lock');
        release.resolve();
        expect(await inFlight).toMatchObject({ status: 200 });
        await revocation;
      } finally {
        release.resolve();
        await inFlight;
        await revocation;
        revoker.release();
      }
      expect(calls).toBe(3);
      expect(await resolve()).toMatchObject({ status: 403 });
      await expect(assertInstalledSecretRecipientNotRevoked(runtime, pins)).rejects.toThrow();
      expect(calls).toBe(3);
      const revoked = await retained();
      expect(revoked[0].payload).toEqual(payload);
      expect(revoked[0].cose).toEqual(cose);
      await expect(
        admin.query(
          "update control.installed_secret_recipient set state='ACTIVE' where participant_id=$1",
          [scope.participantId],
        ),
      ).rejects.toThrow('OPS-SECRET-INSTALLATION-IMMUTABLE');
      const repeat = await admin.connect();
      try {
        await repeat.query('begin');
        await expect(
          installInitialSecretRecipient(
            repeat,
            pins,
            payload,
            cose,
            'test-initial-installed-configuration',
          ),
        ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
        await repeat.query('rollback');
      } finally {
        repeat.release();
      }
    } finally {
      await app?.close();
      await fixture?.close();
      await Promise.all([admin.end(), runtime.end(), tls.close()]);
    }
  },
);
