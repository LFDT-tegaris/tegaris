import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import {
  withAuthenticatedWorkloadPeer,
  type ConfirmWorkloadAuthorities,
} from '../../../services/identity-service/src/domain/workload-peer.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest } from './public-governance-client.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && runtimeUrl && workerUrl ? it : it.skip;
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest();

// SEM-145: actual X.509 transport authentication, durable occurrence and custody.
// SQL establishes initial identity/trust only; no workload grant is seeded.
integration(
  'archives only real TLS authentication occurrences and fails authentication if custody cannot commit',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const scope = {
      participantId: id(),
      privacyDomainId: id(),
      streamId: 'workload-authentication',
    };
    const principalId = id(),
      credentialId = id(),
      workloadId = id();
    const uriSan = `urn:openpc:participant:${scope.participantId}:workload:${workloadId}`;
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'workload-evidence-'));
    const tls = await runtimeSnapshotTlsFixture(uriSan);
    const rogue = await runtimeSnapshotTlsFixture(uriSan);
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
      const occurrences = async () =>
        (
          await admin.query(
            `select occurrence_id::text id,receipt,session_id,method,context_mode
      from control.authentication_occurrence where participant_id=$1 and principal_id=$2 order by occurred_at,occurrence_id`,
            [scope.participantId, principalId],
          )
        ).rows;
      const lastUsed = async () =>
        (
          await admin.query('select last_used_at from control.credential where credential_id=$1', [
            credentialId,
          ])
        ).rows[0].last_used_at;
      const repository = new PostgresIdentityRepository(runtime, systemClock);
      // This legacy internal credential-state check remains useful, but is not
      // claimed as a verified peer authentication occurrence.
      expect(await repository.authenticateWorkload(input)).toMatchObject({
        principalId,
        credentialId,
      });
      expect(await occurrences()).toEqual([]);
      await expect(repository.authenticateWorkload(input, undefined, { ...input })).rejects.toThrow(
        'PC-IDENTITY-1006',
      );
      expect(await occurrences()).toEqual([]);
      const kernel = new IdentityKernel(repository);
      const authenticateOwner = kernel.authenticateWorkload.bind(kernel);
      let capturedPeer: Parameters<IdentityKernel['authenticateWorkload']>[2];
      // Observe the opaque argument while leaving the real owner in the path.
      kernel.authenticateWorkload = (input, context, peer) => {
        capturedPeer = peer;
        return authenticateOwner(input, context, peer);
      };
      app = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
      let address = await app.listen({ host: '127.0.0.1', port: 0 });
      const authenticate = (body = {}) =>
        tls.post(`${address}/internal/v1/workload/authenticate`, body);
      await expect(
        tls.post(`${address}/internal/v1/workload/authenticate`, {}, null),
      ).rejects.toThrow();
      await expect(
        tls.post(`${address}/internal/v1/workload/authenticate`, {}, rogue),
      ).rejects.toThrow();
      expect(await occurrences()).toEqual([]);
      expect(await authenticate()).toMatchObject({
        status: 200,
        body: { principalId, credentialId },
      });
      expect(await occurrences()).toHaveLength(1);
      expect(capturedPeer).toBeDefined();
      await expect(repository.authenticateWorkload(input, undefined, capturedPeer)).rejects.toThrow(
        'PC-IDENTITY-1006',
      );
      expect(await occurrences()).toHaveLength(1);
      const first = (await occurrences())[0];
      const original = JSON.parse(first.receipt.toString('utf8'));
      expect(original).toMatchObject({
        version: 'OPENPC_AUTHENTICATION_OCCURRENCE_V1',
        method: 'TLS13_MTLS',
        contextMode: 'WORKLOAD',
        authorityEffect: 'NONE',
        integrity: 'CONTROL_DATABASE_IMMUTABLE',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        principalId,
      });
      expect(original.transportBindingDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(original).not.toHaveProperty('sessionBindingDigest');
      expect(first.session_id).toBeNull();
      expect(first.receipt.toString('utf8')).not.toContain(tls.certificate.toString());
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1 and principal_id=$2',
            [scope.participantId, principalId],
          )
        ).rows,
      ).toEqual([{ count: 0 }]);
      // Actual persistence failure must roll back last-use and the occurrence and
      // must not return an authenticated identity to the caller.
      const priorUse = await lastUsed();
      await admin.query(`create function openpc.test_authentication_failure() returns trigger language plpgsql as $$
      begin if NEW.method='TLS13_MTLS' then raise exception 'test occurrence unavailable'; end if; return NEW; end $$;
      create trigger test_authentication_failure before insert on control.authentication_occurrence for each row execute function openpc.test_authentication_failure()`);
      try {
        expect(await authenticate()).toEqual({ status: 401, body: { code: 'PC-IDENTITY-1006' } });
        expect(await lastUsed()).toEqual(priorUse);
        expect(await occurrences()).toHaveLength(1);
      } finally {
        await admin.query(
          'drop trigger test_authentication_failure on control.authentication_occurrence; drop function openpc.test_authentication_failure()',
        );
      }
      await app.close();
      app = buildLocalWorkloadMtlsService(
        runtime,
        new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock)),
        tls.server,
      );
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      expect((await occurrences())[0]).toEqual(first);
      expect(await authenticate()).toMatchObject({ status: 200, body: { principalId } });
      const records = await occurrences();
      expect(records).toHaveLength(2);
      expect(records[0]).toEqual(first);
      expect(records[1].id).not.toBe(first.id);
      expect(JSON.parse(records[1].receipt.toString('utf8')).transportBindingDigest).not.toBe(
        original.transportBindingDigest,
      );
      const custody = new EvidenceCustody(worker),
        key = randomBytes(32);
      const sink = await LocalEvidenceVault.open(join(root, 'vault'), 'workload-test-sink');
      const encryption = { keyId: 'workload-test-key', key };
      const retention = new Date(Date.now() + 86_400_000)
        .toISOString()
        .replace(/\.(\d{3})Z$/u, '.$1000Z');
      await custody.ingestAuthentication(scope, encryption, retention, 65536);
      expect(await custody.ingestAuthentication(scope, encryption, retention, 65536)).toBeNull();
      await custody.exportNext(scope, sink);
      const checkpoint = (
        await admin.query(
          'select receipt from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
          [scope.participantId, scope.privacyDomainId, scope.streamId],
        )
      ).rows[0].receipt;
      const bytes = await sink.read(checkpoint.object);
      const archived = openSegment(
        bytes,
        checkpoint.object.objectDigest,
        inspectSegment(bytes).header,
        key,
      );
      expect(archived.records.map((record) => Buffer.from(record.receiptBase64, 'base64'))).toEqual(
        records.map((record) => record.receipt),
      );
      expect(archived.records.every((record) => record.evidenceClass === 'AUTHENTICATION')).toBe(
        true,
      );
      const catalogue = await fixture.read('evidence-records?limit=100');
      expect(catalogue.status).toBe(200);
      expect(
        (catalogue.body.items as { evidenceClass: string }[]).map((record) => record.evidenceClass),
      ).toEqual(['AUTHENTICATION', 'AUTHENTICATION']);
      for (const record of catalogue.body.items as { evidenceId: string }[]) {
        const response = await fixture.read(
          `evidence-records/${encodeURIComponent(record.evidenceId)}/provenance`,
        );
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('VERIFIED_AUTHENTICATION_OCCURRENCE');
        expect(response.body.authentication).toMatchObject({
          method: 'TLS13_MTLS',
          contextMode: 'WORKLOAD',
          integrity: 'CONTROL_DATABASE_IMMUTABLE',
          authority: 'NONE',
        });
        expect(JSON.stringify(response.body)).not.toMatch(
          /receiptBase64|signedBytes|sessionId|privateKey/,
        );
      }
      key.fill(0);

      // The recipient seam is authentication plus a current dependency fence,
      // not secret delivery or an installed-service authorization assertion.
      await app.close();
      const peerKernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      let calls = 0;
      let deniedAfterAuthentication = 0;
      let callback: () => Promise<void> = async () => {};
      app = buildLocalWorkloadMtlsService(runtime, peerKernel, tls.server);
      app.post('/test/current-peer', async (request, reply) => {
        try {
          await withAuthenticatedWorkloadPeer(
            runtime,
            peerKernel,
            request.raw.socket as TLSSocket,
            async (client, identity) => {
              calls++;
              expect(identity).toMatchObject({ principalId, credentialId });
              // A separate connection sees the committed original authentication
              // before the dependent callback, even if that callback later fails.
              expect(await occurrences()).toHaveLength(2 + calls + deniedAfterAuthentication);
              expect((await client.query('select current_user name')).rows[0].name).not.toBe(
                'openpc_control',
              );
              await callback();
            },
          );
          return { ok: true };
        } catch {
          return reply.code(401).send({ code: 'PC-IDENTITY-1006' });
        }
      });
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      const currentPeer = () => tls.post(`${address}/test/current-peer`, {});
      await expect(
        withAuthenticatedWorkloadPeer(runtime, peerKernel, {} as TLSSocket, async () => {
          throw new Error('Fabricated peer reached the callback');
        }),
      ).rejects.toThrow('PC-IDENTITY-1006');
      expect(calls).toBe(0);
      expect(await currentPeer()).toEqual({ status: 200, body: { ok: true } });
      callback = async () => {
        throw new Error('Dependent owner failed');
      };
      expect(await currentPeer()).toEqual({ status: 401, body: { code: 'PC-IDENTITY-1006' } });
      expect(calls).toBe(2);
      expect(await occurrences()).toHaveLength(4);

      // A committed authority change between authentication and fence acquisition
      // rejects the dependent action rather than trusting the returned metadata.
      const peerAuthenticate = peerKernel.authenticateWorkload.bind(peerKernel);
      peerKernel.authenticateWorkload = async (...args) => {
        const identity = await peerAuthenticate(...args);
        await admin.query(
          'update control.principal set authority_epoch=authority_epoch+1 where principal_id=$1',
          [principalId],
        );
        deniedAfterAuthentication++;
        return identity;
      };
      expect(await currentPeer()).toEqual({ status: 401, body: { code: 'PC-IDENTITY-1006' } });
      expect(calls).toBe(2);
      expect(await occurrences()).toHaveLength(5);
      peerKernel.authenticateWorkload = peerAuthenticate;

      const entered = Promise.withResolvers<void>();
      const release = Promise.withResolvers<void>();
      callback = async () => {
        entered.resolve();
        await release.promise;
      };
      const inFlight = currentPeer();
      const revoker = await admin.connect();
      let revocation: Promise<unknown> | undefined;
      try {
        await entered.promise;
        const pid = (await revoker.query('select pg_backend_pid() pid')).rows[0].pid;
        revocation = revoker.query(
          "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
          [credentialId],
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
        expect(await inFlight).toEqual({ status: 200, body: { ok: true } });
        await revocation;
      } finally {
        release.resolve();
        await inFlight;
        await revocation;
        revoker.release();
      }
      expect(calls).toBe(3);
      expect(await currentPeer()).toEqual({ status: 401, body: { code: 'PC-IDENTITY-1006' } });
      expect(calls).toBe(3);
      expect(await occurrences()).toHaveLength(6);
    } finally {
      await app?.close();
      await fixture?.close();
      await Promise.all([admin.end(), runtime.end(), worker.end(), tls.close(), rogue.close()]);
      await rm(root, { recursive: true, force: true });
    }
  },
);

integration(
  'holds the complete installed peer union through actual public reviewer revocation',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 3 });
    const participantId = id(),
      privacyDomainId = id();
    const actors = [];
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      for (let n = 0; n < 4; n++) {
        const principalId = id(),
          credentialId = id(),
          workload = id();
        const tls = await runtimeSnapshotTlsFixture(
          `urn:openpc:participant:${participantId}:workload:${workload}`,
        );
        actors.push({ principalId, credentialId, tls });
        const spki = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
        await admin.query(
          "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD',$3,'ACTIVE',1)",
          [principalId, participantId, `Installed peer initial trust ${n}`],
        );
        await admin.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until,certificate_der)
        values($1,$2,$3,'WORKLOAD_MTLS','local-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10,$11)`,
          [
            credentialId,
            participantId,
            principalId,
            `urn:openpc:participant:${participantId}:workload:${workload}`,
            `urn:openpc:workload:${workload}`,
            sha(spki),
            spki,
            sha(tls.parsed.raw),
            tls.parsed.validFromDate,
            tls.parsed.validToDate,
            tls.parsed.raw,
          ],
        );
      }
      // Reviewer UUIDs precede the transported subject. One ordered union must
      // acquire reviewer principals before the subject credential, not append late locks.
      const subject = actors[3]!;
      let selected = actors[0]!,
        selectionVersion = 1;
      let calls = 0,
        callbackPid = 0;
      let callback: (
        client: import('pg').PoolClient,
        confirm: ConfirmWorkloadAuthorities,
      ) => Promise<void> = async () => {};
      let escaped: ConfirmWorkloadAuthorities | undefined;
      let escapedClient: import('pg').PoolClient | undefined;
      const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      app = buildLocalWorkloadMtlsService(runtime, kernel, subject.tls.server);
      app.post('/test/installed-peers', async (request, reply) => {
        try {
          await withAuthenticatedWorkloadPeer(
            runtime,
            kernel,
            request.raw.socket as TLSSocket,
            async (c, _identity, _confirm, confirmAuthorities) => {
              calls++;
              callbackPid = (await c.query('select pg_backend_pid() pid')).rows[0].pid;
              await confirmAuthorities(c, [selected]);
              escaped = confirmAuthorities;
              escapedClient = c;
              await callback(c, confirmAuthorities);
            },
            { privacyDomainId },
            async (c) => {
              const pinned = selected,
                version = selectionVersion;
              return {
                dependencies: [pinned, pinned],
                confirmCurrent: async () => {
                  if (selected !== pinned || selectionVersion !== version)
                    throw new Error('Installed dependency changed');
                  const r = await c.query(
                    `select 1 from control.principal p join control.credential k using(participant_id,principal_id)
              where p.participant_id=$1 and p.principal_id=$2 and k.credential_id=$3 and p.state='ACTIVE' and p.authority_epoch=1
              and k.kind='WORKLOAD_MTLS' and k.state='ACTIVE' and k.credential_epoch=1
              and k.valid_from<=clock_timestamp() and k.valid_until>clock_timestamp()`,
                    [participantId, pinned.principalId, pinned.credentialId],
                  );
                  if (r.rowCount !== 1) throw new Error('Installed dependency revoked or rotated');
                },
              };
            },
          );
          return { ok: true };
        } catch {
          return reply.code(401).send({ code: 'PC-IDENTITY-1006' });
        }
      });
      const address = await app.listen({ host: '127.0.0.1', port: 0 });
      const invoke = () => subject.tls.post(`${address}/test/installed-peers`, {});
      const prepareRevoke = async (credentialId: string) => {
        const { client, maker, checker } = fixture!.governance;
        const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          candidateDigest = digest({ credentialId, state: 'REVOKED' }),
          key = `reviewer-revoke-${id()}`;
        expect(
          await client.mutation(
            maker,
            '/v1/identity/workloads/prepare',
            { mutation: 'REVOKE', credentialId },
            key,
            '1',
          ),
        ).toMatchObject({ status: 202, body: { candidateDigest, expectedRevision: '1' } });
        const createAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
        const proposed = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createAction,
          actionIntentDigest: client.actionDigests.get(createAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
          reason: 'Revoke exact installed reviewer.',
        });
        expect(proposed.status).toBe(202);
        const ref = String(proposed.body.resourceRef),
          approvalId = ref.slice(-36);
        const decision = digest({
          actionIntentId: approveAction,
          approvalRequestId: ref,
          candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approveAction, approvalId, decision);
        expect(
          await client.policyMutation(
            checker,
            `/api/v1/approval-requests/${ref}/approve`,
            {
              targetRef: ref,
              actionIntentId: approveAction,
              actionIntentDigest: client.actionDigests.get(approveAction),
              inputDigest: decision,
              expectedRevision: '1',
              reason: 'Independent reviewer revocation approval.',
            },
            '1',
          ),
        ).toMatchObject({ status: 202 });
        await client.stepUp(maker, action, credentialId, candidateDigest);
        return {
          commit: () =>
            client.mutation(
              maker,
              `/v1/identity/workloads/${credentialId}/revoke`,
              {},
              key,
              '1',
              approvalId,
            ),
        };
      };
      const first = await prepareRevoke(selected.credentialId);
      expect(await first.commit()).toMatchObject({ status: 200, body: { state: 'REVOKED' } });
      expect(await invoke()).toMatchObject({ status: 401 });
      expect(calls).toBe(0);

      selected = actors[1]!;
      const next = await prepareRevoke(selected.credentialId);
      const entered = Promise.withResolvers<void>(),
        release = Promise.withResolvers<void>();
      callback = async () => {
        entered.resolve();
        await release.promise;
      };
      const inFlight = invoke();
      let revocation: ReturnType<typeof next.commit> | undefined;
      try {
        await entered.promise;
        revocation = next.commit();
        await expect
          .poll(
            async () =>
              (
                await admin.query(
                  'select exists(select 1 from pg_stat_activity where $1=any(pg_blocking_pids(pid))) blocked',
                  [callbackPid],
                )
              ).rows[0]?.blocked,
          )
          .toBe(true);
        release.resolve();
        expect(await inFlight).toMatchObject({ status: 200 });
        expect(await revocation).toMatchObject({ status: 200, body: { state: 'REVOKED' } });
      } finally {
        release.resolve();
        await inFlight;
        await revocation;
      }
      await expect(escaped!(escapedClient!, [selected])).rejects.toThrow();
      expect(await invoke()).toMatchObject({ status: 401 });
      expect(calls).toBe(1);

      selected = actors[2]!;
      callback = async (c, confirm) => confirm(c, [{ principalId: id(), credentialId: id() }]);
      expect(await invoke()).toMatchObject({ status: 401 });
      callback = async (_c, confirm) => {
        const other = await runtime.connect();
        try {
          await confirm(other, [selected]);
        } finally {
          other.release();
        }
      };
      expect(await invoke()).toMatchObject({ status: 401 });
      callback = async () => {
        selectionVersion++;
      };
      expect(await invoke()).toMatchObject({ status: 401 });
      callback = async (c, confirm) => {
        await c.query('rollback');
        await confirm(c, [selected]);
      };
      expect(await invoke()).toMatchObject({ status: 401 });
      callback = async () => {};
      expect(await invoke()).toMatchObject({ status: 200 });
      // A distinct active credential epoch models post-rotation stale installed
      // pins; public rotation/issuance remains in the connected owner gate.
      await admin.query(
        'update control.credential set credential_epoch=credential_epoch+1 where credential_id=$1',
        [selected.credentialId],
      );
      const before = calls;
      expect(await invoke()).toMatchObject({ status: 401 });
      expect(calls).toBe(before);
    } finally {
      await app?.close();
      await fixture?.close();
      await Promise.all([admin.end(), runtime.end(), ...actors.map((a) => a.tls.close())]);
    }
  },
  120000,
);
