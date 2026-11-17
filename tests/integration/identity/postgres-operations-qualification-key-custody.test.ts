import { tmpdir } from 'node:os';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import { expect, it } from 'vitest';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { createQualificationKeyCustodyPeer } from '../../../services/identity-service/src/domain/qualification-key-custody-peer.js';
import { createHttpQualificationKeyProvider } from '../../../services/identity-service/src/domain/http-qualification-key-provider.js';
import {
  qualificationKeyInstallation,
  qualificationKeyRequestSchema,
  type QualificationKeyPeer,
  type QualificationKeyInstallation,
  type QualificationKeyDescriptor,
  type QualificationKeyRequest,
} from '../../../services/identity-service/src/domain/qualification-key-provider.js';
import {
  installInitialQualificationKeyCustody,
  withdrawQualificationKeyCustody,
  readQualificationKeyAttempt,
  retainQualificationKeyObservation,
  type QualificationKeyIntent,
} from '../../../services/control-api/src/configuration/operations/qualification-key-custody.js';
import {
  installProviderRetryQualificationRoot,
  ProviderRetryQualificationStore,
  withInstalledQualificationIssuer,
} from '../../../services/control-api/src/configuration/operations/provider-retry-qualification.js';
import {
  qualificationDigest as hash,
  qualificationCanonicalJson as canonical,
  encodeProviderRetryQualification,
  providerRetryQualificationProfiles,
  type QualificationAuthorityEnvelope,
  type QualificationFamily,
} from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import { signConsumerCose } from '../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import { createFixtureSigningProvider } from '../local-runtime/signing-provider-fixture.js';
import type { QualificationFixtureConfiguration } from '../local-runtime/signing-provider-qualification-store.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
async function waitHeld(root: string, attemptId: string) {
  const file = join(root, 'qualification', 'faults', attemptId + '.held'),
    deadline = Date.now() + 2000;
  while (Date.now() < deadline) {
    try {
      await access(file);
      return;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Provider response barrier was not reached while original authority was live');
}
const pair = () => {
  const p = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    key: p.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: p.publicKey.export({ format: 'der', type: 'spki' }),
  };
};

async function fixture(
  ownerRole:
    'openpc_control_owner' | 'openpc_operations_qualification_owner' = 'openpc_control_owner',
) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
  const root = await mkdtemp(join(parent, 'qualification-key-native-'));
  const admin = new Pool({ connectionString: adminUrl, max: 2 }),
    runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
  // Actual current role is configured by the privileged host, never elevated by
  // the peer adapter. DISCARD/transaction behavior is part of this real test.
  const owner = new Pool({
    connectionString: adminUrl,
    options: `-c role=${ownerRole}`,
    max: 2,
  });
  const participantId = id(),
    privacyDomainId = id(),
    environmentId = 'key-' + id().slice(-12),
    installationId = id();
  const scope = { participantId, privacyDomainId, requestId: id() },
    selection = { participantId, privacyDomainId, installationId };
  const actors: {
    tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
    peer: QualificationKeyPeer;
    role: string;
  }[] = [];
  let server: Awaited<ReturnType<typeof createFixtureSigningProvider>> | undefined;
  let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
  const tx = async <T>(role: string, fn: (c: PoolClient) => Promise<T>, commit = false) => {
    if (
      ![
        'openpc_control_owner',
        'openpc_operations_qualification_owner',
        'openpc_operations_qualification_bootstrap',
        'openpc_identity_runtime',
      ].includes(role)
    )
      throw new Error('Unsupported test role');
    const c = await admin.connect();
    await c.query('begin isolation level read committed');
    try {
      await c.query(`set local role ${role}`);
      await c.query('set local row_security=on');
      await c.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [participantId, privacyDomainId, id()],
      );
      const r = await fn(c);
      await c.query(commit ? 'commit' : 'rollback');
      return r;
    } catch (e) {
      await c.query('rollback');
      throw e;
    } finally {
      c.release();
    }
  };
  const cleanup = async () => {
    await app?.close();
    await server?.close();
    await Promise.all([owner.end(), runtime.end(), admin.end()]);
    for (const a of actors) await a.tls.close();
    await rm(root, { recursive: true, force: true });
  };
  try {
    await admin.query(
      "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Qualification initial trust','ACTIVE',1)",
      [participantId],
    );
    await admin.query(
      "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Qualification initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
      [privacyDomainId, participantId],
    );
    // Initial identities only. No observation/run/review/qualification state is seeded.
    for (const role of ['observer', 'requester', 'harness', 'reviewer']) {
      const workloadId = 'urn:openpc:workload:' + id(),
        principalId = id(),
        credentialId = id();
      const tls = await runtimeSnapshotTlsFixture(
        `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
      );
      const spki = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      const peer: QualificationKeyPeer = {
        principalId,
        credentialId,
        participantEpoch: '1',
        principalEpoch: '1',
        credentialEpoch: '1',
        workloadId,
        keyDigest: hash(spki),
        certificateDigest: hash(tls.parsed.raw),
      };
      actors.push({ tls, peer, role });
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD',$3,'ACTIVE',1)",
        [principalId, participantId, role],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
        values($1,$2,$3,'WORKLOAD_MTLS','qualification-local-test',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          participantId,
          principalId,
          `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
          workloadId,
          Buffer.from(peer.keyDigest.slice(7), 'hex'),
          spki,
          Buffer.from(peer.certificateDigest.slice(7), 'hex'),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
    }
    const a = actors[0]!,
      rootKey = pair(),
      online = pair(),
      siteKey = pair(),
      now = Date.now();
    const authorityId = 'qualification-custody';
    const schemaBytes = await readFile('config/schema/effective-configuration.schema.json'),
      profileBytes = await readFile('config/profiles/local.yaml');
    const sourceAuthentication = (
      await readPublicOperationsSources({
        sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
        profile: 'local',
      })
    ).custody;
    await installInitialOperationsEnvironment(
      admin,
      { participantId, privacyDomainId },
      {
        pins: {
          environmentId,
          profile: 'local',
          issuerSpkiHex: siteKey.spki.toString('hex'),
          issuerEpoch: '1',
          issuerValidFromMs: now - 1000,
          issuerValidUntilMs: now + 300000,
          configurationSchemaDigest: hash(schemaBytes),
          namedProfileDigest: hash(profileBytes),
        },
        initialBaseGenerationId: id(),
        schemaBytes,
        profileBytes,
        sourceAuthentication,
      },
    );
    const rootPins = {
      authorityId,
      rootKeyId: hash(rootKey.spki),
      rootEpoch: '1',
      rootSpki: rootKey.spki,
      policySigner: 'OFFLINE_TRUST_ROOT' as const,
      validFromMs: now - 5000,
      validUntilMs: now + 600000,
    };
    await installProviderRetryQualificationRoot(admin, scope, environmentId, rootPins);
    const store = new ProviderRetryQualificationStore(admin);
    const signature = {
      format: 'COSE_Sign1',
      algorithm: 'ES256',
      curve: 'P-256',
      hash: 'SHA-256',
      canonicalization: 'PC-CBOR-1',
    };
    const sign = <F extends QualificationFamily>(
      family: F,
      claims: Parameters<typeof encodeProviderRetryQualification<F>>[1],
    ) => {
      const payload = encodeProviderRetryQualification(family, claims);
      return {
        payload,
        cose: signConsumerCose(
          providerRetryQualificationProfiles[family],
          rootKey.key,
          rootKey.spki,
          payload,
        ),
      };
    };
    const state = (sequence: number, revoked = false): QualificationAuthorityEnvelope => {
      const at = now - 500 + sequence;
      const rd = Buffer.from(
        canonical({
          schemaVersion: '1.0',
          authorityId,
          revocations: revoked
            ? [
                {
                  schemaVersion: '1.0',
                  authorityId,
                  keyId: hash(online.spki),
                  keyEpoch: 1,
                  state: 'REVOKED',
                  effectiveAt: new Date(at).toISOString(),
                  receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
                  evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
                  signatureEnvelope: signature,
                },
              ]
            : [],
        }),
      );
      const revocations = {
        ...sign('revocations', {
          authorityId,
          snapshotId: id(),
          sequence: String(sequence),
          revocationDocumentDigest: hash(rd),
          rootKeyId: rootPins.rootKeyId,
          rootEpoch: '1',
          issuedAtMs: at,
          validUntilMs: now + 300000,
        }),
        document: rd,
      };
      // This root-signed declaration is not proof of fixture hardware custody.
      const kd = Buffer.from(
        canonical({
          schemaVersion: '1.0',
          authorityId,
          policySigner: 'OFFLINE_TRUST_ROOT',
          issuedAt: new Date(at).toISOString(),
          signatureEnvelope: signature,
          keys: [
            {
              keyId: hash(online.spki),
              epoch: 1,
              state: 'ACTIVE',
              purpose: 'pc.cose.operations-qualification-executed-receipt.v1',
              nonExportable: true,
              backend: 'HSM',
              publicKeySpkiHex: online.spki.toString('hex'),
              validFromMs: now - 1000,
              validUntilMs: now + 300000,
            },
          ],
        }),
      );
      return {
        revocations,
        keyset: {
          ...sign('keyset', {
            authorityId,
            keysetId: id(),
            sequence: String(sequence),
            keysetDocumentDigest: hash(kd),
            revocationPayloadDigest: hash(revocations.payload),
            policySigner: 'OFFLINE_TRUST_ROOT',
            rootKeyId: rootPins.rootKeyId,
            rootEpoch: '1',
            issuedAtMs: at,
            validUntilMs: now + 300000,
          }),
          document: kd,
        },
      };
    };
    const firstState = state(1);
    await store.installAuthorityState(scope, environmentId, authorityId, firstState);
    const descriptor: QualificationKeyDescriptor = {
      schemaVersion: 1,
      providerId: 'qualification-external-test',
      participantId,
      privacyDomainId,
      environmentId,
      authorityId,
      rootEpoch: '1',
      keyId: hash(online.spki),
      keyEpoch: '1',
      purpose: 'pc.cose.operations-qualification-executed-receipt.v1',
      reference: 'secret://test-provider/qualification#v1',
      version: 'v1',
      publicKeySpkiHex: online.spki.toString('hex'),
      algorithm: 'ES256',
      state: 'ACTIVE',
      validFromMs: now - 1000,
      validUntilMs: now + 300000,
      policyRevision: '1',
      custody: 'EXTERNAL_SOFTWARE_FIXTURE',
      clients: [
        {
          credentialId: a.peer.credentialId,
          credentialEpoch: '1',
          certificateDigest: a.peer.certificateDigest,
          methods: ['INSPECT', 'PROVE'],
        },
      ],
    };
    const qconfig: QualificationFixtureConfiguration = {
      clients: actors.map((v) => ({
        certificate: v.tls.certificate,
        peer: v.peer,
        participantId,
        privacyDomainId,
        environmentId,
      })),
      initialKeys: [{ descriptor, privateKeyPkcs8Der: online.key }],
    };
    const ca = Buffer.concat(actors.map((v) => v.tls.server.ca));
    let performs = 0,
      lookups = 0;
    const openProvider = async (port = 0) => {
      server = await createFixtureSigningProvider({
        root,
        clients: [],
        initialKeys: [],
        certificate: a.tls.server.certificate,
        privateKey: a.tls.server.privateKey,
        ca,
        qualification: qconfig,
      });
      server.server.on('request', (r) => {
        if (r.url === '/v1/qualification-keys/observe') performs++;
        if (r.url === '/v1/qualification-keys/lookup') lookups++;
      });
      await new Promise<void>((resolve) => server!.server.listen(port, '127.0.0.1', resolve));
      return (server.server.address() as { port: number }).port;
    };
    const port = await openProvider();
    const pins: QualificationKeyInstallation = {
      schemaVersion: 1,
      installationId,
      participantId,
      privacyDomainId,
      environmentId,
      authorityId,
      rootEpoch: '1',
      keyId: descriptor.keyId,
      keyEpoch: '1',
      purpose: descriptor.purpose,
      publicKeySpkiHex: descriptor.publicKeySpkiHex,
      reference: descriptor.reference,
      version: 'v1',
      providerId: descriptor.providerId,
      providerOrigin: `https://127.0.0.1:${port}`,
      providerTlsSpkiDigest: hash(
        new X509Certificate(a.tls.server.certificate).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      ),
      peer: a.peer,
      validFromMs: now - 1000,
      validUntilMs: now + 300000,
    };
    await tx(
      'openpc_operations_qualification_bootstrap',
      (c) => installInitialQualificationKeyCustody(c, pins),
      true,
    );
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
    const tls = { certificate: a.tls.certificate, privateKey: a.tls.privateKey, trustCa: ca };
    let adapter = createQualificationKeyCustodyPeer({ ownerPool: owner, kernel, tls });
    app = buildLocalWorkloadMtlsService(runtime, kernel, { ...a.tls.server, ca });
    app.post('/test/observe', async (req, reply) => {
      try {
        return await adapter.observe(
          req.raw.socket as TLSSocket,
          selection,
          req.body as QualificationKeyIntent,
        );
      } catch {
        return reply.code(403).send({ code: 'KEY_OBSERVATION_UNAVAILABLE' });
      }
    });
    const address = await app.listen({ host: '127.0.0.1', port: 0 });
    const observe = (intent: QualificationKeyIntent) =>
      a.tls.post(address + '/test/observe', intent);
    const inspect = () => ({ method: 'INSPECT' as const, operationId: id(), attemptId: id() });
    const read = (attemptId: string) =>
      tx('openpc_control_owner', (c) => readQualificationKeyAttempt(c, selection, attemptId));
    const restart = async () => {
      await server!.close();
      server = undefined;
      await openProvider(port);
      adapter = createQualificationKeyCustodyPeer({ ownerPool: owner, kernel, tls });
    };
    return {
      root,
      admin,
      runtime,
      owner,
      scope,
      selection,
      pins,
      descriptor,
      actors,
      tx,
      observe,
      inspect,
      read,
      restart,
      get adapter() {
        return adapter;
      },
      get provider() {
        return server!.qualification!;
      },
      get counts() {
        return { performs, lookups };
      },
      revoke: () => store.installAuthorityState(scope, environmentId, authorityId, state(2, true)),
      cleanup,
    };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

it('rejects arbitrary key signing and detached capability fields in the closed request corpus', () => {
  for (const method of ['SIGN', 'SIGN_RECEIPT', 'EXPORT', 'REVOKE'])
    expect(() =>
      qualificationKeyRequestSchema.parse({ method, current: true, nonExportable: true }),
    ).toThrow();
});

integration(
  'uses actual Identity TLS, installed issuer, external ACL and original key proof without promoting qualification',
  async () => {
    const f = await fixture('openpc_operations_qualification_owner');
    try {
      const input = f.inspect();
      expect(await f.observe(input)).toMatchObject({
        status: 200,
        body: { state: 'OBSERVED' },
      });
      const first = await f.read(input.attemptId);
      expect(first.observation?.descriptor?.custody).toBe('EXTERNAL_SOFTWARE_FIXTURE');
      const proof = {
        method: 'PROVE' as const,
        operationId: id(),
        attemptId: id(),
        inspectionAttemptId: input.attemptId,
      };
      expect(await f.observe(proof)).toMatchObject({
        status: 200,
        body: { state: 'OBSERVED' },
      });
      const original = await f.read(proof.attemptId);
      expect(original.observation?.proofHex).toMatch(/^[0-9a-f]{128}$/u);
      const count = f.counts.performs;
      expect(await f.observe(proof)).toMatchObject({ status: 200 });
      expect(f.counts.performs).toBe(count);
      expect(await f.observe({ ...proof, operationId: id() })).toMatchObject({ status: 403 });
      for (const actor of f.actors.slice(1)) {
        const trust = { ...f.pins, peer: actor.peer, installationId: id() },
          installed = qualificationKeyInstallation(trust);
        const request: QualificationKeyRequest = {
          ...first.request,
          attemptId: id(),
          operationId: id(),
          peer: actor.peer,
          installationDigest: installed.digest,
        };
        const provider = createHttpQualificationKeyProvider({
          trust,
          certificate: actor.tls.certificate,
          privateKey: actor.tls.privateKey,
          trustCa: f.actors[0]!.tls.server.ca,
        });
        try {
          expect(await provider.perform(request)).toMatchObject({
            outcome: 'REJECTED',
            reason: 'DENIED',
            descriptor: null,
            proofHex: null,
          });
        } finally {
          provider.close();
        }
      }
      // Same real authenticated external peer, deliberately wrong requested key
      // epoch/purpose. These are negative provider calls, not installed trust.
      for (const change of [
        { keyEpoch: '2' },
        { purpose: 'pc.cose.operations-qualification-input.v1' as const },
      ]) {
        const trust = { ...f.pins, ...change },
          installed = qualificationKeyInstallation(trust),
          actor = f.actors[0]!;
        const provider = createHttpQualificationKeyProvider({
          trust,
          certificate: actor.tls.certificate,
          privateKey: actor.tls.privateKey,
          trustCa: actor.tls.server.ca,
        });
        try {
          expect(
            await provider.perform({
              ...first.request,
              ...change,
              attemptId: id(),
              operationId: id(),
              installationDigest: installed.digest,
            }),
          ).toMatchObject({ outcome: 'REJECTED', reason: 'DENIED' });
        } finally {
          provider.close();
        }
      }
      expect(
        (
          await f.admin.query(
            'select count(*)::int n from control.operations_provider_retry_qualification where environment_id=$1',
            [f.pins.environmentId],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(
        (
          await f.admin.query(
            'select count(*)::int n from control.operations_generation_binding where environment_id=$1',
            [f.pins.environmentId],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(
        (
          await f.admin.query(
            'select count(*)::int n from control.qualification_key_attempt where participant_id=$1',
            [f.scope.participantId],
          )
        ).rows[0].n,
      ).toBe(2);
    } finally {
      await f.cleanup();
    }
  },
  120000,
);

integration(
  'keeps lost replies and incomplete provider attempts lookup-only across real provider/adapter restart',
  async () => {
    const f = await fixture();
    try {
      const input = f.inspect();
      await writeFile(
        join(f.root, 'qualification', 'faults', input.attemptId + '.json'),
        JSON.stringify({ mode: 'DROP_AFTER_PERSIST' }),
      );
      expect(await f.observe(input)).toMatchObject({ status: 200, body: { state: 'UNKNOWN' } });
      expect((await f.read(input.attemptId)).observation).toBeUndefined();
      const count = f.counts.performs;
      await f.restart();
      expect(await f.adapter.reconcile(f.selection, input.attemptId)).toMatchObject({
        state: 'HISTORICAL',
        observation: { outcome: 'OBSERVED' },
      });
      expect(f.counts.performs).toBe(count);
      expect(f.counts.lookups).toBeGreaterThan(0);
      const original = (await f.read(input.attemptId)).observation;
      expect(await f.adapter.reconcile(f.selection, input.attemptId)).toMatchObject({
        observation: original,
      });
      expect(f.counts.performs).toBe(count);
      const incomplete = f.inspect();
      await writeFile(
        join(f.root, 'qualification', 'faults', incomplete.attemptId + '.json'),
        JSON.stringify({ mode: 'STOP_BEFORE_RESULT' }),
      );
      expect(await f.observe(incomplete)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      const stopped = f.counts.performs;
      const before = await readFile(
        join(f.root, 'qualification', 'attempts', incomplete.attemptId + '.json'),
      );
      await f.restart();
      expect(await f.adapter.reconcile(f.selection, incomplete.attemptId)).toMatchObject({
        state: 'UNKNOWN',
      });
      expect(f.counts.performs).toBe(stopped);
      expect(
        await readFile(join(f.root, 'qualification', 'attempts', incomplete.attemptId + '.json')),
      ).toEqual(before);
    } finally {
      await f.cleanup();
    }
  },
  120000,
);

integration(
  'retains authentic late originals after concurrent root revocation and prevents revoked key/installation new use',
  async () => {
    const f = await fixture();
    try {
      const input = f.inspect();
      await writeFile(
        join(f.root, 'qualification', 'faults', input.attemptId + '.json'),
        JSON.stringify({ mode: 'HOLD_AFTER_PERSIST' }),
      );
      const pending = f.observe(input);
      await waitHeld(f.root, input.attemptId);
      const count = f.counts.performs;
      const live = await f.read(input.attemptId);
      expect(live.request.deadlineAtMs - Date.now()).toBeGreaterThan(1000);
      await f.revoke();
      expect(live.request.deadlineAtMs - Date.now()).toBeGreaterThan(1000);
      await writeFile(join(f.root, 'qualification', 'faults', input.attemptId + '.release'), '');
      expect(await pending).toMatchObject({
        status: 200,
        body: { state: 'HISTORICAL', observation: { outcome: 'OBSERVED' } },
      });
      expect(await f.adapter.reconcile(f.selection, input.attemptId)).toMatchObject({
        state: 'HISTORICAL',
        observation: { outcome: 'OBSERVED' },
      });
      expect(await f.observe(input)).toMatchObject({ status: 403 });
      expect(await f.observe(f.inspect())).toMatchObject({ status: 403 });
      expect(f.counts.performs).toBe(count);
      const saved = (await f.read(input.attemptId)).observation;
      await f.tx(
        'openpc_operations_qualification_bootstrap',
        (c) => withdrawQualificationKeyCustody(c, f.selection),
        true,
      );
      await expect(
        f.tx(
          'openpc_operations_qualification_bootstrap',
          (c) => installInitialQualificationKeyCustody(c, f.pins),
          true,
        ),
      ).rejects.toThrow();
      expect((await f.read(input.attemptId)).observation).toEqual(saved);
    } finally {
      await f.cleanup();
    }
  },
  120000,
);

integration(
  'denies replaced external policy, foreign scope, wrong role/context and original mutation through real SQL',
  async () => {
    const f = await fixture();
    try {
      for (const [table, column] of [
        ['participant', 'display_name'],
        ['privacy_domain', 'domain_name'],
        ['principal', 'state'],
        ['credential', 'state'],
      ]) {
        await f.tx('openpc_operations_qualification_owner', async (c) => {
          expect(
            (
              await c.query(`select 1 from control.${table} where participant_id=$1 for share`, [
                f.scope.participantId,
              ])
            ).rowCount,
          ).toBeGreaterThan(0);
        });
        await expect(
          f.tx('openpc_operations_qualification_owner', (c) =>
            c.query(`update control.${table} set ${column}=${column} where participant_id=$1`, [
              f.scope.participantId,
            ]),
          ),
        ).rejects.toThrow();
      }
      expect(
        (
          await f.admin.query(
            "select pg_has_role('openpc_identity_runtime','openpc_operations_qualification_owner','MEMBER') member",
          )
        ).rows[0].member,
      ).toBe(false);
      const input = f.inspect();
      expect(await f.observe(input)).toMatchObject({
        status: 200,
        body: { state: 'OBSERVED' },
      });
      await f.provider.replacePolicy(f.pins.keyId, {
        state: 'ACTIVE',
        clients: [...f.descriptor.clients.map((c) => ({ ...c, methods: ['INSPECT' as const] }))],
      });
      const proof = {
        method: 'PROVE' as const,
        operationId: id(),
        attemptId: id(),
        inspectionAttemptId: input.attemptId,
      };
      expect(await f.observe(proof)).toMatchObject({
        status: 200,
        body: { state: 'HISTORICAL', observation: { outcome: 'REJECTED' } },
      });
      const original = await f.read(input.attemptId);
      await expect(
        f.tx('openpc_identity_runtime', (c) =>
          readQualificationKeyAttempt(c, f.selection, input.attemptId),
        ),
      ).rejects.toThrow();
      await expect(
        f.tx('openpc_control_owner', (c) =>
          readQualificationKeyAttempt(
            c,
            { ...f.selection, privacyDomainId: id() },
            input.attemptId,
          ),
        ),
      ).rejects.toThrow();
      await expect(
        f.tx('openpc_control_owner', async (c) => {
          await c.query("set local openpc.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'");
          return readQualificationKeyAttempt(c, f.selection, input.attemptId);
        }),
      ).rejects.toThrow();
      await expect(
        f.tx('openpc_control_owner', async (c) => {
          await c.query('rollback');
          await c.query('begin');
          return readQualificationKeyAttempt(c, f.selection, input.attemptId);
        }),
      ).rejects.toThrow();
      for (const table of ['qualification_key_attempt', 'qualification_key_observation']) {
        await expect(
          f.tx('openpc_control_owner', (c) =>
            c.query(`delete from control.${table} where attempt_id=$1`, [input.attemptId]),
          ),
        ).rejects.toThrow();
        await expect(
          f.tx('openpc_control_owner', (c) => c.query(`truncate control.${table} cascade`)),
        ).rejects.toThrow();
      }
      await expect(
        f.tx('openpc_identity_runtime', (c) =>
          c.query(
            'insert into control.qualification_key_observation select * from control.qualification_key_observation',
          ),
        ),
      ).rejects.toThrow();
      await expect(
        f.tx('openpc_control_owner', (c) =>
          retainQualificationKeyObservation(c, f.selection, input.attemptId, {
            ...original.observation,
            observedAtMs: Date.now(),
          }),
        ),
      ).rejects.toThrow();
      expect((await f.read(input.attemptId)).observation).toEqual(original.observation);
      const issuer = {
        authorityId: f.pins.authorityId,
        keyId: f.pins.keyId,
        epoch: f.pins.keyEpoch,
        purpose: f.pins.purpose,
      };
      for (const mismatch of [
        { epoch: '2' },
        { keyId: hash(Buffer.from('foreign-key')) },
        { purpose: 'pc.cose.operations-qualification-input.v1' as const },
      ]) {
        await expect(
          f.tx('openpc_control_owner', async (c) => {
            const requestId = (await c.query('select openpc.current_operation_id()::text id'))
              .rows[0].id;
            return withInstalledQualificationIssuer(
              c,
              { ...f.scope, requestId },
              f.pins.environmentId,
              { ...issuer, ...mismatch },
              async () => {
                throw new Error('forbidden callback');
              },
            );
          }),
        ).rejects.not.toThrow('forbidden callback');
      }
      await expect(
        f.tx('openpc_control_owner', async (c) => {
          const requestId = (await c.query('select openpc.current_operation_id()::text id')).rows[0]
            .id;
          return withInstalledQualificationIssuer(
            c,
            { ...f.scope, requestId },
            f.pins.environmentId,
            issuer,
            async (same) => {
              await same.query('rollback');
              await same.query('begin');
              await same.query(
                "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
                [f.scope.participantId, f.scope.privacyDomainId, requestId],
              );
            },
          );
        }),
      ).rejects.toThrow();
      await f.tx('openpc_control_owner', async (c) => {
        const requestId = (await c.query('select openpc.current_operation_id()::text id')).rows[0]
          .id;
        await withInstalledQualificationIssuer(
          c,
          { ...f.scope, requestId },
          f.pins.environmentId,
          issuer,
          async (same) => {
            expect(same).toBe(c);
            const concurrent = await f.admin.connect();
            try {
              await concurrent.query('begin');
              await expect(
                concurrent.query(
                  'select 1 from control.operations_qualification_root where environment_id=$1 for update nowait',
                  [f.pins.environmentId],
                ),
              ).rejects.toMatchObject({ code: '55P03' });
            } finally {
              await concurrent.query('rollback');
              concurrent.release();
            }
          },
        );
      });
    } finally {
      await f.cleanup();
    }
  },
  120000,
);

integration(
  'original expiry never becomes revocation-race evidence or renewal and historic lookup keeps original signed bytes',
  async () => {
    const f = await fixture();
    try {
      const input = f.inspect();
      expect(await f.observe(input)).toMatchObject({
        status: 200,
        body: { state: 'OBSERVED' },
      });
      const original = await f.read(input.attemptId),
        count = f.counts.performs;
      const remaining = original.request.deadlineAtMs - Date.now();
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(10000);
      await f.admin.query('select pg_sleep($1)', [(remaining + 30) / 1000]);
      expect(await f.adapter.reconcile(f.selection, input.attemptId)).toMatchObject({
        state: 'HISTORICAL',
        observation: original.observation,
      });
      expect(await f.observe(input)).toMatchObject({ status: 200, body: { state: 'HISTORICAL' } });
      expect(f.counts.performs).toBe(count);
      expect((await f.read(input.attemptId)).request).toEqual(original.request);
    } finally {
      await f.cleanup();
    }
  },
  120000,
);

integration(
  'a credential fence independently denies new native use while already observed originals remain historical',
  async () => {
    const f = await fixture();
    try {
      const input = f.inspect();
      expect(await f.observe(input)).toMatchObject({
        status: 200,
        body: { state: 'OBSERVED' },
      });
      const original = await f.read(input.attemptId),
        count = f.counts.performs;
      // Controlled authority-store invalidation: this proves the native joined
      // credential fence, not the separate public credential-revocation journey.
      await f.admin.query(
        "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
        [f.pins.peer.credentialId],
      );
      expect(await f.observe(f.inspect())).toMatchObject({ status: 403 });
      expect(await f.adapter.reconcile(f.selection, input.attemptId)).toMatchObject({
        state: 'HISTORICAL',
        observation: original.observation,
      });
      expect(f.counts.performs).toBe(count);
    } finally {
      await f.cleanup();
    }
  },
  120000,
);
