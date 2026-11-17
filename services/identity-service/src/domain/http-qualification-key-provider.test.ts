import { tmpdir } from 'node:os';
import { expect, it } from 'vitest';
import { createHttpQualificationKeyProvider } from './http-qualification-key-provider.js';
import {
  QualificationKeyProviderUnknown,
  type QualificationKeyInstallation,
} from './qualification-key-provider.js';
it('rejects response-selected trust and arbitrary signer capabilities before transport allocation', () => {
  for (const trust of [
    { providerOrigin: 'https://response.example', authenticated: true },
    { purpose: 'SIGN_ANY', nonExportable: true },
    null,
  ])
    expect(() =>
      createHttpQualificationKeyProvider({
        trust: trust as unknown as QualificationKeyInstallation,
        certificate: Buffer.alloc(0),
        privateKey: Buffer.alloc(0),
        trustCa: Buffer.alloc(0),
      }),
    ).toThrow(QualificationKeyProviderUnknown);
});

it('uses only observer TLS for v2, recovers the original proof after lost reply and provider restart', async () => {
  const { mkdtemp, rm, writeFile } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { generateKeyPairSync, X509Certificate } = await import('node:crypto');
  const { runtimeSnapshotTlsFixture } =
    await import('../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js');
  const { createFixtureSigningProvider } =
    await import('../../../../tests/integration/local-runtime/signing-provider-fixture.js');
  const { qualificationDigest: hash } =
    await import('../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js');
  const {
    qualificationKeyInstallation,
    qualificationKeyRequestSchema,
    qualificationKeyDescriptorDigest,
  } = await import('./qualification-key-provider.js');
  const { localOperationId: id } = await import('./local-operation-id.js');
  const participantId = id(),
    privacyDomainId = id(),
    environmentId = 'observer-test';
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'qualification-observer-transport-'),
  );
  const actors = [];
  let server: Awaited<ReturnType<typeof createFixtureSigningProvider>> | undefined;
  let provider: ReturnType<typeof createHttpQualificationKeyProvider> | undefined;
  try {
    for (let n = 0; n < 2; n++) {
      const workload = id();
      const tls = await runtimeSnapshotTlsFixture(
        `urn:openpc:participant:${participantId}:workload:${workload}`,
      );
      actors.push({
        tls,
        peer: {
          principalId: id(),
          credentialId: id(),
          participantEpoch: '1',
          principalEpoch: '1',
          credentialEpoch: '1',
          workloadId: 'urn:openpc:workload:' + workload,
          keyDigest: hash(tls.parsed.publicKey.export({ type: 'spki', format: 'der' })),
          certificateDigest: hash(tls.parsed.raw),
        },
      });
    }
    const subject = actors[0]!,
      observer = actors[1]!;
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = key.publicKey.export({ type: 'spki', format: 'der' });
    const now = Date.now();
    const descriptor = {
      schemaVersion: 2 as const,
      providerId: 'external-test',
      participantId,
      privacyDomainId,
      environmentId,
      authorityId: 'qualification-test',
      rootEpoch: '1',
      keyId: hash(spki),
      keyEpoch: '1',
      purpose: 'pc.cose.operations-notification-async-input.v1' as const,
      reference: 'secret://test-provider/qualification#v1',
      version: 'v1',
      publicKeySpkiHex: spki.toString('hex'),
      algorithm: 'ES256' as const,
      state: 'ACTIVE' as const,
      validFromMs: now - 1000,
      validUntilMs: now + 60000,
      policyRevision: '1',
      custody: 'EXTERNAL_SOFTWARE_FIXTURE' as const,
      clients: [
        {
          credentialId: subject.peer.credentialId,
          credentialEpoch: '1',
          certificateDigest: subject.peer.certificateDigest,
          methods: ['INSPECT', 'PROVE'] as ('INSPECT' | 'PROVE')[],
        },
      ],
      observers: [
        {
          observer: observer.peer,
          subject: subject.peer,
          methods: ['INSPECT', 'PROVE'] as ('INSPECT' | 'PROVE')[],
        },
      ],
    };
    const config = {
      root,
      clients: [],
      initialKeys: [],
      ...subject.tls.server,
      ca: Buffer.concat(actors.map((a) => a.tls.server.ca)),
      qualification: {
        clients: actors.map((a) => ({
          certificate: a.tls.certificate,
          peer: a.peer,
          participantId,
          privacyDomainId,
          environmentId,
        })),
        initialKeys: [
          {
            descriptor,
            privateKeyPkcs8Der: key.privateKey.export({ type: 'pkcs8', format: 'der' }),
          },
        ],
      },
    };
    const start = async (port = 0) => {
      server = await createFixtureSigningProvider(config);
      await new Promise<void>((resolve) => server!.server.listen(port, '127.0.0.1', resolve));
      return (server.server.address() as { port: number }).port;
    };
    const port = await start();
    const trust = qualificationKeyInstallation({
      schemaVersion: 2,
      installationId: id(),
      participantId,
      privacyDomainId,
      environmentId,
      authorityId: descriptor.authorityId,
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
        new X509Certificate(subject.tls.server.certificate).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      ),
      peer: subject.peer,
      observer: observer.peer,
      validFromMs: now - 1000,
      validUntilMs: now + 60000,
    });
    const tls = {
      certificate: observer.tls.certificate,
      privateKey: observer.tls.privateKey,
      trustCa: subject.tls.server.ca,
    };
    provider = createHttpQualificationKeyProvider({ ...tls, trust: trust.pins });
    expect(() =>
      createHttpQualificationKeyProvider({
        ...tls,
        certificate: subject.tls.certificate,
        privateKey: subject.tls.privateKey,
        trust: trust.pins,
      }),
    ).toThrow(QualificationKeyProviderUnknown);
    const binding: Record<string, unknown> = { ...trust.pins };
    for (const field of [
      'installationId',
      'providerOrigin',
      'providerTlsSpkiDigest',
      'publicKeySpkiHex',
      'validFromMs',
      'validUntilMs',
    ])
      delete binding[field];
    // Actual native SQL reservation is tested separately. This pure transport
    // test exercises the external provider with exact immutable request bytes.
    const request = qualificationKeyRequestSchema.parse({
      ...binding,
      method: 'INSPECT',
      installationDigest: trust.digest,
      keysetDigest: hash(Buffer.from('keyset')),
      revocationsDigest: hash(Buffer.from('revocations')),
      operationId: id(),
      attemptId: id(),
      issuedAtMs: Date.now(),
      deadlineAtMs: Date.now() + 10000,
    });
    const inspected = await provider.perform(request);
    expect(inspected.outcome).toBe('OBSERVED');
    const proof = qualificationKeyRequestSchema.parse({
      ...request,
      method: 'PROVE',
      attemptId: id(),
      inspectionAttemptId: request.attemptId,
      descriptorDigest: qualificationKeyDescriptorDigest(descriptor),
      challengeHex: 'ab'.repeat(32),
    });
    await writeFile(
      join(root, 'qualification', 'faults', proof.attemptId + '.json'),
      JSON.stringify({ mode: 'DROP_AFTER_PERSIST' }),
    );
    await expect(provider.perform(proof)).rejects.toThrow(QualificationKeyProviderUnknown);
    const original = await provider.lookup(proof);
    expect(original?.outcome).toBe('OBSERVED');
    expect(original?.proofHex).toHaveLength(128);
    await server!.close();
    await start(port);
    expect(await provider.lookup(proof, original)).toEqual(original);
    expect(await provider.lookup({ ...request, attemptId: id() })).toBeUndefined();
    const deniedTrust = qualificationKeyInstallation({
      ...trust.pins,
      peer: { ...subject.peer, credentialId: id() },
    });
    const deniedProvider = createHttpQualificationKeyProvider({ ...tls, trust: deniedTrust.pins });
    try {
      const denied = await deniedProvider.perform({
        ...request,
        attemptId: id(),
        installationDigest: deniedTrust.digest,
        peer: deniedTrust.pins.peer,
      });
      expect(denied.outcome).toBe('REJECTED');
      expect(denied.reason).toBe('DENIED');
    } finally {
      deniedProvider.close();
    }
  } finally {
    provider?.close();
    await server?.close();
    await Promise.all(actors.map((a) => a.tls.close()));
    await rm(root, { recursive: true, force: true });
  }
}, 20000);

it('signs only closed 369/370 payloads under a separate exact observer-to-subject grant', async () => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const { generateKeyPairSync } = await import('node:crypto');
  const { runtimeSnapshotTlsFixture } =
    await import('../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js');
  const { createQualificationFixtureStore } =
    await import('../../../../tests/integration/local-runtime/signing-provider-qualification-store.js');
  const { qualificationSigningWireFixture } =
    await import('../../../../tests/integration/local-runtime/qualification-signing-cases.js');
  const { qualificationDigest: hash } =
    await import('../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js');
  const { encodeNotificationAsync } =
    await import('../../../../packages/security-kernel/src/operations-configuration/notification-async.js');
  const { qualificationKeyInstallation } = await import('./qualification-key-provider.js');
  const { qualificationSigningRequestSchema, validateQualificationSigningObservation } =
    await import('./qualification-signing-provider.js');
  const { localOperationId: id } = await import('./local-operation-id.js');
  const sample = qualificationSigningWireFixture();
  const participantId = sample.trust.participantId;
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'qualification-key-signing-'),
  );
  const actors = [];
  try {
    for (let n = 0; n < 3; n++) {
      const actorParticipantId = n === 2 ? id() : participantId;
      const workload = id();
      const tls = await runtimeSnapshotTlsFixture(
        `urn:openpc:participant:${actorParticipantId}:workload:${workload}`,
      );
      actors.push({
        tls,
        participantId: actorParticipantId,
        peer: {
          principalId: id(),
          credentialId: id(),
          participantEpoch: '1',
          principalEpoch: '1',
          credentialEpoch: '1',
          workloadId: 'urn:openpc:workload:' + workload,
          keyDigest: hash(tls.parsed.publicKey.export({ type: 'spki', format: 'der' })),
          certificateDigest: hash(tls.parsed.raw),
        },
      });
    }
    const subject = actors[0]!,
      observer = actors[1]!;
    for (const family of ['input', 'capacity'] as const) {
      const wire = qualificationSigningWireFixture(family),
        now = Date.now();
      const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const spki = key.publicKey.export({ type: 'spki', format: 'der' });
      const trust = qualificationKeyInstallation({
        ...wire.trust,
        peer: subject.peer,
        observer: observer.peer,
        keyId: hash(spki),
        publicKeySpkiHex: spki.toString('hex'),
        validFromMs: now - 10000,
        validUntilMs: now + 60000,
      });
      const claims =
        family === 'input'
          ? {
              ...wire.input,
              issuerKeyId: trust.pins.keyId,
              validFromMs: now - 10000,
              validUntilMs: now + 60000,
            }
          : {
              ...wire.capacity,
              issuerKeyId: trust.pins.keyId,
              signerPrincipalId: subject.peer.principalId,
              issuedAtMs: now,
              expiresAtMs: now + 60000,
            };
      const payload = encodeNotificationAsync(family, claims);
      const request = qualificationSigningRequestSchema.parse({
        ...wire.request,
        keyInstallationId: trust.pins.installationId,
        installationDigest: trust.digest,
        keyId: trust.pins.keyId,
        peer: subject.peer,
        observer: observer.peer,
        issuedAtMs: now,
        deadlineAtMs: now + 10000,
        payloadHex: payload.toString('hex'),
        payloadDigest: hash(payload),
      });
      const descriptor = {
        schemaVersion: 2 as const,
        providerId: request.providerId,
        participantId,
        privacyDomainId: request.privacyDomainId,
        environmentId: request.environmentId,
        authorityId: request.authorityId,
        rootEpoch: request.rootEpoch,
        keyId: request.keyId,
        keyEpoch: request.keyEpoch,
        purpose: request.purpose,
        reference: request.reference,
        version: request.version,
        publicKeySpkiHex: trust.pins.publicKeySpkiHex,
        algorithm: 'ES256' as const,
        state: 'ACTIVE' as const,
        validFromMs: now - 10000,
        validUntilMs: now + 60000,
        policyRevision: '1',
        custody: 'EXTERNAL_SOFTWARE_FIXTURE' as const,
        clients: [
          {
            credentialId: subject.peer.credentialId,
            credentialEpoch: '1',
            certificateDigest: subject.peer.certificateDigest,
            methods: ['INSPECT', 'PROVE'] as ('INSPECT' | 'PROVE')[],
          },
        ],
        observers: [
          {
            subject: subject.peer,
            observer: observer.peer,
            methods: ['INSPECT', 'PROVE'] as ('INSPECT' | 'PROVE')[],
          },
        ],
      };
      const config = {
        clients: actors.map((a) => ({
          certificate: a.tls.certificate,
          peer: a.peer,
          participantId: a.participantId,
          privacyDomainId: request.privacyDomainId,
          environmentId: request.environmentId,
        })),
        initialKeys: [
          {
            descriptor,
            privateKeyPkcs8Der: key.privateKey.export({ type: 'pkcs8', format: 'der' }),
          },
        ],
      };
      const directory = join(root, family);
      const inspectOnly = await createQualificationFixtureStore(directory, config);
      expect(
        await inspectOnly.signQualification(request, observer.peer.certificateDigest),
      ).toMatchObject({ outcome: 'REJECTED', reason: 'DENIED' });
      const grant = {
        installation: trust.pins,
        qualificationInstallationId: request.qualificationInstallationId,
        family,
      };
      const store = await createQualificationFixtureStore(directory, {
        ...config,
        signingGrants: [grant],
      });
      expect(() =>
        inspectOnly.authenticateQualificationSigningPeer(request, observer.peer.certificateDigest),
      ).not.toThrow();
      expect(() =>
        store.authenticateQualificationSigningPeer(request, observer.peer.certificateDigest),
      ).not.toThrow();
      const foreign = actors[2]!;
      for (const [candidate, actualCertificate] of [
        [request, subject.peer.certificateDigest],
        [{ ...request, observer: foreign.peer }, foreign.peer.certificateDigest],
        [
          { ...request, observer: { ...observer.peer, principalId: id() } },
          observer.peer.certificateDigest,
        ],
        [{ ...request, payloadHex: request.payloadHex + '00' }, observer.peer.certificateDigest],
      ] as const) {
        expect(() =>
          store.authenticateQualificationSigningPeer(candidate, actualCertificate),
        ).toThrow();
        await expect(store.signQualification(candidate, actualCertificate)).rejects.toThrow();
      }
      for (const field of ['participantId', 'privacyDomainId', 'environmentId'] as const) {
        const changed = field === 'environmentId' ? 'foreign-env' : id();
        const changedPayload = encodeNotificationAsync(family, { ...claims, [field]: changed });
        const candidate = qualificationSigningRequestSchema.parse({
          ...request,
          [field]: changed,
          payloadHex: changedPayload.toString('hex'),
          payloadDigest: hash(changedPayload),
        });
        expect(() =>
          store.authenticateQualificationSigningPeer(candidate, observer.peer.certificateDigest),
        ).toThrow('denied');
      }
      const signed = await store.signQualification(request, observer.peer.certificateDigest);
      expect(validateQualificationSigningObservation(request, signed, trust.pins).outcome).toBe(
        'SIGNED',
      );
      await expect(
        store.signQualification(request, subject.peer.certificateDigest),
      ).rejects.toThrow('denied');
      await expect(
        store.signQualification(
          { ...request, payloadHex: request.payloadHex + '00' },
          observer.peer.certificateDigest,
        ),
      ).rejects.toThrow();
      expect(
        await store.signQualification(
          { ...request, qualificationInstallationId: id() },
          observer.peer.certificateDigest,
        ),
      ).toMatchObject({ outcome: 'REJECTED', reason: 'DENIED' });
      const ambiguous = await createQualificationFixtureStore(directory, {
        ...config,
        signingGrants: [grant, grant],
      });
      expect(
        await ambiguous.signQualification(request, observer.peer.certificateDigest),
      ).toMatchObject({ outcome: 'REJECTED', reason: 'DENIED' });
      if (family === 'input') {
        expect(() =>
          store.authenticateQualificationSigningPeer(
            { ...request, issuedAtMs: now - 5000, deadlineAtMs: now - 4000 },
            observer.peer.certificateDigest,
          ),
        ).not.toThrow();
        expect(
          await store.signQualification(
            { ...request, issuedAtMs: now - 5000, deadlineAtMs: now - 4000 },
            observer.peer.certificateDigest,
          ),
        ).toMatchObject({ outcome: 'REJECTED', reason: 'EXPIRED' });
      }
      await store.replacePolicy(request.keyId, { clients: descriptor.clients, state: 'REVOKED' });
      expect(() =>
        store.authenticateQualificationSigningPeer(request, observer.peer.certificateDigest),
      ).not.toThrow();
      expect(await store.signQualification(request, observer.peer.certificateDigest)).toMatchObject(
        { outcome: 'REJECTED', reason: 'REVOKED' },
      );
      // Cryptographic original remains verifiable; revocation cannot replace it.
      expect(validateQualificationSigningObservation(request, signed, trust.pins, signed)).toEqual(
        signed,
      );
    }
  } finally {
    await Promise.all(actors.map((a) => a.tls.close()));
    await rm(root, { recursive: true, force: true });
  }
}, 20000);
