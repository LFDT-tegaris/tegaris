import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import {
  authorityEnvelopeDigest,
  decodeIdentityAuthorityEnvelope,
  decodeEnvelopeProposal,
  encodeEnvelopeProposal,
  encodeIdentityAuthorityEnvelope,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import {
  identityEnvelopeFixture,
  envelopeFixtureId as id,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';
import { createFixtureSigningProvider } from '../../../../tests/integration/local-runtime/signing-provider-fixture.js';
import { createHttpIdentityEnvelopeSigningProvider } from './http-identity-envelope-signing-provider.js';
import {
  identityEnvelopeProviderRequestSchema,
  identityEnvelopeProviderRequestDigest,
  validateIdentityEnvelopeProviderObservation,
  validateIdentityEnvelopeProviderLookup,
  type IdentityEnvelopeProviderRequest,
  type IdentityEnvelopeProviderDescriptor,
} from './identity-envelope-signing-provider.js';

const hash = (value: Buffer) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const publicDigest = (certificate: Buffer) =>
  hash(new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' }));

it('pins371 over actual mTLS, keeps receipt-only grants separate, and reconciles original bytes across ambiguity and restart', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent) throw new Error('Owned test scratch is required');
  const root = await mkdtemp(join(parent, 'identity-envelope-provider-'));
  const tls = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${id(1)}:workload:${id(901)}`,
  );
  const receiptTls = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${id(1)}:workload:${id(902)}`,
  );
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' });
  const timestamp = BigInt(Date.now()) * 1000000n;
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    signerId: evidenceKeyId(publicKey),
    publicKeySpkiDer: publicKey,
    workloadCredentialId: id(221),
    workloadCredentialEpoch: 11n,
    workloadParticipantEpoch: 2n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: timestamp - 1000000000n,
    validUntilNs: timestamp + 3600000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'independent-envelope-provider-installation',
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/identity-envelope-provider#version-1',
    secretVersion: 'version-1',
    purpose: 'pc.cose.identity-authority-envelope.v1',
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const binding = {
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    workloadCredentialId: trust.workloadCredentialId,
    workloadCredentialEpoch: '11',
    secretClass: trust.secretClass,
    reference: trust.secretReference,
    version: trust.secretVersion,
    purpose: trust.purpose,
    purposeCode: 371 as const,
    schemaId: 24034 as const,
    schemaVersion: 1 as const,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: trust.profileId,
    profileVersion: 1 as const,
    profileDigest: identityEnvelopeSigningProfileDigest,
    trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
  } as const;
  const descriptor: IdentityEnvelopeProviderDescriptor = {
    ...binding,
    algorithm: 'ES256',
    publicKeySpkiHex: publicKey.toString('hex'),
    fingerprint: trust.signerId,
    validFromNs: trust.validFromNs.toString(),
    validUntilNs: trust.validUntilNs.toString(),
    state: 'ACTIVE',
  };
  function request(caseId: number): IdentityEnvelopeProviderRequest {
    // Independent codec/provider cases only. No public lifecycle result is seeded.
    const artifact = identityEnvelopeFixture(trust.signerId);
    const proposal = decodeEnvelopeProposal(artifact.proposalBytes);
    proposal.envelopeId = id(caseId + 1000);
    artifact.proposalBytes = encodeEnvelopeProposal(proposal);
    artifact.proposalDigest = authorityEnvelopeDigest(artifact.proposalBytes);
    artifact.activation.operationId = id(caseId + 1100);
    artifact.signer = {
      ...artifact.signer,
      profileId: trust.profileId,
      profileDigest: trust.profileDigest,
      trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
    };
    artifact.issuedAtNs = (BigInt(Date.now()) * 1000000n).toString();
    return {
      ...binding,
      method: 'SIGN_AUTHORITY_ENVELOPE',
      callerWorkloadCredentialId: id(903),
      attemptId: id(caseId + 1200),
      operationId: artifact.activation.operationId,
      expectedFingerprint: trust.signerId,
      payloadHex: encodeIdentityAuthorityEnvelope(artifact).toString('hex'),
    };
  }
  const configuration = {
    root,
    ...tls.server,
    ca: Buffer.concat([tls.server.ca, receiptTls.server.ca]),
    clients: [
      {
        certificate: receiptTls.certificate,
        credentialId: id(904),
        workloadId: id(902),
        participantId: id(1),
        privacyDomainId: id(2),
        environmentId: 'test',
        methods: ['INSPECT', 'PROVE'] as const,
        managedKeyOwners: [id(221)],
        signingProfiles: [],
      },
    ],
    initialKeys: [],
    envelope: {
      clients: [
        {
          certificate: tls.certificate,
          credentialId: id(903),
          workloadId: id(901),
          participantId: id(1),
          privacyDomainId: id(2),
          environmentId: 'test',
          keyOwnerCredentialId: id(221),
          methods: ['SIGN_AUTHORITY_ENVELOPE', 'ORIGINAL_LOOKUP'] as const,
        },
        {
          certificate: receiptTls.certificate,
          credentialId: id(904),
          workloadId: id(902),
          participantId: id(1),
          privacyDomainId: id(2),
          environmentId: 'test',
          keyOwnerCredentialId: id(221),
          methods: ['ORIGINAL_LOOKUP'] as const,
        },
      ],
      initialKeys: [{ descriptor, privateKeyPkcs8Der: privateKey }],
    },
  };
  let provider: Awaited<ReturnType<typeof createFixtureSigningProvider>> | undefined;
  let client: ReturnType<typeof createHttpIdentityEnvelopeSigningProvider> | undefined;
  let receiptClient: typeof client;
  let passed = false;
  const attempts = () => readdir(join(root, 'identity-envelope', 'attempts'));
  async function start() {
    provider = await createFixtureSigningProvider(configuration);
    await new Promise<void>((resolve) => provider!.server.listen(0, '127.0.0.1', resolve));
    const address = provider.server.address();
    if (address === null || typeof address === 'string') throw new Error();
    const config = {
      providerOrigin: `https://127.0.0.1:${address.port}`,
      providerTlsSpkiDigest: publicDigest(tls.server.certificate),
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: tls.server.ca,
      callerWorkloadKeyDigest: publicDigest(tls.certificate),
    };
    client = createHttpIdentityEnvelopeSigningProvider(config);
    receiptClient = createHttpIdentityEnvelopeSigningProvider({
      ...config,
      certificate: receiptTls.certificate,
      privateKey: receiptTls.privateKey,
      callerWorkloadKeyDigest: publicDigest(receiptTls.certificate),
    });
    return config;
  }
  try {
    const config = await start();
    const original = request(1);
    expect(await attempts()).toEqual([]);
    for (const change of [
      { purposeCode: 338 },
      { purpose: 'pc.cose.control-business-transition.v1' },
      { profileId: 'pc.control.business.v1' },
      { schemaId: 24001 },
      { workloadCredentialEpoch: '12' },
      { operationId: id(999) },
      { version: 'wrong' },
      { extra: 'private-material' },
    ]) {
      const invalid = { ...original, ...change };
      expect(identityEnvelopeProviderRequestSchema.safeParse(invalid).success).toBe(false);
      await expect(client!.perform(invalid as IdentityEnvelopeProviderRequest)).rejects.toThrow(
        'reconciliation',
      );
    }
    await expect(
      client!.perform({ ...original, callerWorkloadCredentialId: id(999) }),
    ).rejects.toThrow('reconciliation');
    await expect(
      receiptClient!.perform({ ...original, callerWorkloadCredentialId: id(904) }),
    ).rejects.toThrow('reconciliation');
    expect(
      (await receiptClient!.lookup({ ...original, callerWorkloadCredentialId: id(904) })).state,
    ).toBe('NOT_FOUND');
    const foreignPayload = decodeIdentityAuthorityEnvelope(Buffer.from(original.payloadHex, 'hex'));
    foreignPayload.signer.privacyDomainId = id(999);
    const foreign = {
      ...original,
      privacyDomainId: id(999),
      payloadHex: encodeIdentityAuthorityEnvelope(foreignPayload).toString('hex'),
    };
    expect(identityEnvelopeProviderRequestSchema.safeParse(foreign).success).toBe(true);
    await expect(client!.perform(foreign)).rejects.toThrow('reconciliation');
    await expect(
      tls.post(config.providerOrigin + '/v1/identity-envelope-signing/perform', original, null),
    ).rejects.toThrow();
    const wrongPin = createHttpIdentityEnvelopeSigningProvider({
      ...config,
      providerTlsSpkiDigest: 'sha256:' + '0'.repeat(64),
    });
    try {
      await expect(wrongPin.perform(original)).rejects.toThrow('reconciliation');
    } finally {
      wrongPin.close();
    }
    expect(await attempts()).toEqual([]);
    const observation = await client!.perform(original);
    expect(validateIdentityEnvelopeProviderObservation(original, observation)).toEqual(observation);
    expect(await client!.perform(original)).toEqual(observation);
    expect(await client!.lookup(original, observation)).toEqual({ state: 'OBSERVED', observation });
    await expect(
      receiptClient!.lookup({ ...original, callerWorkloadCredentialId: id(904) }),
    ).rejects.toThrow('reconciliation');
    expect(await attempts()).toEqual([original.attemptId + '.json']);
    const originalJournal = await readFile(
      join(root, 'identity-envelope', 'attempts', original.attemptId + '.json'),
    );
    await expect(
      client!.perform({ ...original, callerWorkloadCredentialId: id(999) }),
    ).rejects.toThrow();
    expect(
      await readFile(join(root, 'identity-envelope', 'attempts', original.attemptId + '.json')),
    ).toEqual(originalJournal);
    for (const changed of [
      { ...observation, operationId: id(999) },
      { ...observation, attemptId: id(999) },
      { ...observation, requestDigest: 'sha256:' + '0'.repeat(64) },
      { ...observation, descriptor: { ...observation.descriptor, purposeCode: 338 } },
      {
        ...observation,
        coseHex:
          observation.coseHex.slice(0, -2) +
          (Number.parseInt(observation.coseHex.slice(-2), 16) ^ 1).toString(16).padStart(2, '0'),
      },
      { ...observation, privateKey: 'forbidden' },
    ])
      expect(() => validateIdentityEnvelopeProviderObservation(original, changed)).toThrow(
        'reconciliation',
      );
    expect(JSON.stringify(observation)).not.toContain(privateKey.toString('hex'));
    expect(() =>
      validateIdentityEnvelopeProviderLookup(
        original,
        {
          state: 'NOT_FOUND',
          attemptId: original.attemptId,
          operationId: original.operationId,
          requestDigest: identityEnvelopeProviderRequestDigest(original),
        },
        observation,
      ),
    ).toThrow('reconciliation');

    const dropped = request(2);
    await writeFile(join(root, 'identity-envelope', 'faults', dropped.attemptId + '.drop'), '');
    await expect(client!.perform(dropped)).rejects.toThrow('reconciliation');
    const recovered = await client!.lookup(dropped);
    expect(recovered.state).toBe('OBSERVED');
    const unknown = request(3);
    await writeFile(join(root, 'identity-envelope', 'faults', unknown.attemptId + '.unknown'), '');
    await expect(client!.perform(unknown)).rejects.toThrow('reconciliation');
    const unresolved = await client!.lookup(unknown);
    expect(unresolved.state).toBe('UNKNOWN');
    const uncertainJournal = await readFile(
      join(root, 'identity-envelope', 'attempts', unknown.attemptId + '.json'),
    );
    const missing = request(4);
    expect((await client!.lookup(missing)).state).toBe('NOT_FOUND');
    expect((await attempts()).length).toBe(3);
    client!.close();
    receiptClient!.close();
    await provider!.close();
    provider = undefined;
    await start();
    expect(await client!.lookup(original, observation)).toEqual({ state: 'OBSERVED', observation });
    expect(await client!.lookup(dropped)).toEqual(recovered);
    expect(await client!.lookup(unknown)).toEqual(unresolved);
    await expect(client!.perform(unknown)).rejects.toThrow('reconciliation');
    expect(
      await readFile(join(root, 'identity-envelope', 'attempts', unknown.attemptId + '.json')),
    ).toEqual(uncertainJournal);
    expect((await attempts()).length).toBe(3);
    passed = true;
  } finally {
    client?.close();
    receiptClient?.close();
    await provider?.close();
    privateKey.fill(0);
    await tls.close();
    await receiptTls.close();
    if (passed) await rm(root, { recursive: true, force: true });
  }
}, 30000);
