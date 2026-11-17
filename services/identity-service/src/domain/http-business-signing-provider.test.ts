import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  businessSigningTrustDigest,
  businessSigningSchemaVersion,
  verifyReceiptCose,
  verifyReceiptCoseV2,
  evidenceKeyId,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import { signBusinessReceipt } from './business-receipt-signer.js';
import { createProviderBusinessReceiptSigner } from './provider-business-receipt-signer.js';
import {
  encodeReceiptStructure,
  type BusinessTransitionReceipt,
} from '../../../../packages/security-kernel/src/business-transition/payload.js';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import {
  createFixtureSigningProvider,
  type FixtureSigningClient,
} from '../../../../tests/integration/local-runtime/signing-provider-fixture.js';
import { createHttpBusinessSigningProvider } from './http-business-signing-provider.js';
import {
  businessSigningPurpose,
  validateBusinessProviderObservation,
  type BusinessProviderDescriptor,
  type BusinessProviderRequest,
} from './business-signing-provider.js';

const participantId = '01990000-0000-7000-8000-000000000001';
const privacyDomainId = '01990000-0000-7000-8000-000000000002';
const apiCredential = '01990000-0000-7000-8000-000000000003';
const workerCredential = '01990000-0000-7000-8000-000000000004';
let counter = 10;
const id = () => `01990000-0000-7000-8000-${String(counter++).padStart(12, '0')}`;
const profile = businessTransitionProfiles.find(
  (value) => value.catalogOperationId === 'CFG-OP-CREATE-INDEXER-PROFILE',
)!;
const lifecycleProfile = businessTransitionProfiles.find(
  (value) => value.catalogOperationId === 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
)!;

describe('real mTLS business signing provider adapter and independent durable provider', () => {
  it('authenticates separate workloads, reconciles ambiguous effects, preserves revocation across restart and never exports private bytes', async () => {
    const parent = process.env.OPENPC_TEST_TMP_ROOT;
    if (!parent) throw new Error('Owned OPENPC_TEST_TMP_ROOT is required');
    const root = await mkdtemp(join(parent, 'signing-provider-'));
    const tls = join(root, 'tls'),
      state = join(root, 'provider');
    await mkdir(tls, { mode: 0o700 });
    const openssl = (args: string[]) =>
      execFileSync('openssl', args, { cwd: tls, stdio: 'ignore' });
    openssl([
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      'ca.key',
      '-out',
      'ca.crt',
      '-days',
      '1',
      '-subj',
      '/CN=OpenPC-test-signing-provider-CA',
    ]);
    async function certificate(name: string, san: string, serial: number, usage: string) {
      openssl([
        'req',
        '-new',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        name + '.key',
        '-out',
        name + '.csr',
        '-subj',
        `/CN=fixture-${name}`,
      ]);
      await writeFile(
        join(tls, name + '.ext'),
        `subjectAltName=${san}\nextendedKeyUsage=${usage}\nkeyUsage=digitalSignature\n`,
      );
      openssl([
        'x509',
        '-req',
        '-in',
        name + '.csr',
        '-CA',
        'ca.crt',
        '-CAkey',
        'ca.key',
        '-set_serial',
        String(serial),
        '-days',
        '1',
        '-extfile',
        name + '.ext',
        '-out',
        name + '.crt',
      ]);
      return {
        certificate: await readFile(join(tls, name + '.crt')),
        privateKey: await readFile(join(tls, name + '.key')),
      };
    }
    const apiWorkload = id(),
      workerWorkload = id();
    const serverTls = await certificate('server', 'DNS:localhost,IP:127.0.0.1', 1, 'serverAuth');
    const apiTls = await certificate(
      'api',
      `URI:urn:openpc:participant:${participantId}:workload:${apiWorkload}`,
      2,
      'clientAuth',
    );
    const workerTls = await certificate(
      'worker',
      `URI:urn:openpc:participant:${participantId}:workload:${workerWorkload}`,
      3,
      'clientAuth',
    );
    const unknownTls = await certificate(
      'unknown',
      `URI:urn:openpc:participant:${participantId}:workload:${id()}`,
      4,
      'clientAuth',
    );
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateBytes = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
    const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
    const descriptor: BusinessProviderDescriptor = {
      participantId,
      privacyDomainId,
      workloadCredentialId: apiCredential,
      environmentId: 'local',
      secretClass: 'SECRET-SIGNING-KEY',
      purpose: businessSigningPurpose,
      reference: 'secret://local/control-evidence#1',
      version: '1',
      algorithm: 'ES256',
      publicKeySpkiHex: spki.toString('hex'),
      fingerprint: evidenceKeyId(spki),
      validFromNs: (BigInt(Date.now() - 1000) * 1000000n).toString(),
      validUntilNs: (BigInt(Date.now() + 86400000) * 1000000n).toString(),
      state: 'ACTIVE',
      revokedAtNs: null,
      retiredAtNs: null,
    };
    const additionalPrivacy = id();
    const scopedPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const scopedPublic = scopedPair.publicKey.export({ format: 'der', type: 'spki' });
    const scopedDescriptor: BusinessProviderDescriptor = {
      ...descriptor,
      privacyDomainId: additionalPrivacy,
      reference: 'secret://local/scoped-evidence#1',
      publicKeySpkiHex: scopedPublic.toString('hex'),
      fingerprint: evidenceKeyId(scopedPublic),
    };
    const clients: FixtureSigningClient[] = [
      {
        credentialId: apiCredential,
        workloadId: apiWorkload,
        certificate: apiTls.certificate,
        participantId,
        privacyDomainId,
        environmentId: 'local',
        methods: ['INSPECT', 'PROVE', 'SIGN_RECEIPT'],
        additionalPrivacyDomainIds: [additionalPrivacy],
        managedKeyOwners: [apiCredential],
        signingProfiles: [
          {
            profileId: profile.profileId,
            profileVersion: profile.profileVersion,
            profileDigest: profile.profileDigest,
          },
          {
            profileId: lifecycleProfile.profileId,
            profileVersion: lifecycleProfile.profileVersion,
            profileDigest: lifecycleProfile.profileDigest,
          },
        ],
      },
      {
        credentialId: workerCredential,
        workloadId: workerWorkload,
        certificate: workerTls.certificate,
        participantId,
        privacyDomainId,
        environmentId: 'local',
        methods: ['INSPECT', 'PREPARE', 'DISTRIBUTE', 'PROVE', 'REVOKE', 'RETIRE'],
        managedKeyOwners: [apiCredential],
        signingProfiles: [],
      },
    ];
    const lifecyclePair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const lifecyclePublic = lifecyclePair.publicKey.export({ format: 'der', type: 'spki' });
    const lifecycleDescriptor: BusinessProviderDescriptor = {
      ...descriptor,
      reference: 'secret://local/lifecycle-evidence#1',
      publicKeySpkiHex: lifecyclePublic.toString('hex'),
      fingerprint: evidenceKeyId(lifecyclePublic),
    };
    const fixtureConfig = {
      root: state,
      ...serverTls,
      ca: await readFile(join(tls, 'ca.crt')),
      clients,
      initialKeys: [
        { descriptor, privateKeyPkcs8Der: privateBytes },
        {
          descriptor: scopedDescriptor,
          privateKeyPkcs8Der: scopedPair.privateKey.export({ format: 'der', type: 'pkcs8' }),
        },
        {
          descriptor: lifecycleDescriptor,
          privateKeyPkcs8Der: lifecyclePair.privateKey.export({ format: 'der', type: 'pkcs8' }),
        },
      ],
    };
    let fixture: Awaited<ReturnType<typeof createFixtureSigningProvider>> | undefined;
    const transports: ReturnType<typeof createHttpBusinessSigningProvider>[] = [];
    const start = async () => {
      fixture = await createFixtureSigningProvider(fixtureConfig);
      await new Promise<void>((resolve) => fixture!.server.listen(0, '127.0.0.1', resolve));
      const address = fixture.server.address();
      if (address === null || typeof address === 'string')
        throw new Error('Missing fixture listener');
      const connect = (identity: typeof apiTls, timeoutMs = 1000) => {
        const provider = createHttpBusinessSigningProvider({
          origin: `https://127.0.0.1:${address.port}`,
          ...identity,
          trustCa: fixtureConfig.ca,
          timeoutMs,
        });
        transports.push(provider);
        return provider;
      };
      return { api: connect(apiTls), worker: connect(workerTls), unknown: connect(unknownTls) };
    };
    const base = (): Omit<Extract<BusinessProviderRequest, { method: 'INSPECT' }>, 'method'> => ({
      participantId,
      privacyDomainId,
      workloadCredentialId: apiCredential,
      environmentId: 'local',
      secretClass: 'SECRET-SIGNING-KEY' as const,
      purpose: businessSigningPurpose,
      reference: descriptor.reference,
      version: '1',
      attemptId: id(),
      operationId: id(),
      callerWorkloadCredentialId: apiCredential,
    });
    try {
      let { api, worker, unknown } = await start();
      const inspect = { ...base(), method: 'INSPECT' as const };
      const initial = await api.perform(inspect);
      validateBusinessProviderObservation(inspect, initial);
      expect(initial.descriptor?.fingerprint).toBe(descriptor.fingerprint);
      const scopedInspect = {
        ...base(),
        privacyDomainId: additionalPrivacy,
        reference: scopedDescriptor.reference,
        method: 'INSPECT' as const,
      };
      const scoped = await api.perform(scopedInspect);
      validateBusinessProviderObservation(scopedInspect, scoped);
      expect(scoped.descriptor).toEqual(scopedDescriptor);
      expect(await api.lookup(scopedInspect.attemptId)).toEqual(scoped);
      await expect(worker.lookup(scopedInspect.attemptId)).rejects.toThrow();
      await expect(
        worker.perform({
          ...scopedInspect,
          attemptId: id(),
          callerWorkloadCredentialId: workerCredential,
        }),
      ).rejects.toThrow();
      const foreignInspect = { ...base(), privacyDomainId: id(), method: 'INSPECT' as const };
      await expect(api.perform(foreignInspect)).rejects.toThrow();
      expect(await api.lookup(foreignInspect.attemptId)).toBeUndefined();
      expect(
        (await api.perform({ ...base(), privacyDomainId: additionalPrivacy, method: 'INSPECT' }))
          .reason,
      ).toBe('WRONG_SCOPE');

      await expect(unknown.perform({ ...base(), method: 'INSPECT' })).rejects.toThrow();
      const forbidden = {
        ...base(),
        method: 'REVOKE' as const,
        rotationId: id(),
        expectedFingerprint: descriptor.fingerprint,
      };
      await expect(api.perform(forbidden)).rejects.toThrow();
      expect(await api.lookup(forbidden.attemptId)).toBeUndefined();
      await expect(worker.perform({ ...base(), method: 'INSPECT' })).rejects.toThrow();
      const rotationId = id();
      const prepared: BusinessProviderRequest = {
        ...base(),
        callerWorkloadCredentialId: workerCredential,
        method: 'PREPARE',
        rotationId,
        reference: 'secret://local/control-evidence#2',
        version: '2',
      };
      const preparation = await worker.perform(prepared);
      validateBusinessProviderObservation(prepared, preparation);
      const fingerprint = preparation.descriptor!.fingerprint;
      const next = () => ({
        ...base(),
        reference: prepared.reference,
        version: '2',
        rotationId,
        expectedFingerprint: fingerprint,
      });
      const distribute = {
        ...next(),
        callerWorkloadCredentialId: workerCredential,
        method: 'DISTRIBUTE' as const,
      };
      validateBusinessProviderObservation(distribute, await worker.perform(distribute));
      const prove = { ...next(), method: 'PROVE' as const, challengeHex: '71'.repeat(32) };
      const proof = await api.perform(prove);
      validateBusinessProviderObservation(prove, proof);
      const trust: BusinessSigningTrust = {
        participantId,
        privacyDomainId,
        environmentId: 'local',
        signerId: fingerprint,
        publicKeySpkiDer: Buffer.from(preparation.descriptor!.publicKeySpkiHex, 'hex'),
        workloadCredentialId: apiCredential,
        workloadCredentialEpoch: 1n,
        keyEpoch: 2n,
        validFromNs: BigInt(preparation.descriptor!.validFromNs),
        validUntilNs: BigInt(preparation.descriptor!.validUntilNs),
        admissionKind: 'BOOTSTRAP',
        admissionReference: 'Provider capability test only',
        admissionDigest: Buffer.alloc(32, 9),
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: prepared.reference,
        secretVersion: '2',
        grants: [
          {
            profileId: profile.profileId,
            profileVersion: profile.profileVersion,
            profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
            actionIntentId: profile.actionIntentId,
            catalogOperationId: profile.catalogOperationId,
          },
        ],
      };
      // Structural provider-signature exercise only; the separate public vertical proves actual business state.
      const receipt: BusinessTransitionReceipt = {
        receiptId: id(),
        schemaDefinitionDigest: Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
        transitionProfileId: profile.profileId,
        transitionProfileVersion: profile.profileVersion,
        transitionProfileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
        environmentId: 'local',
        participantId,
        privacyDomainId,
        operationId: id(),
        actionIntentId: profile.actionIntentId,
        catalogOperationId: profile.catalogOperationId,
        aggregateType: profile.aggregateType,
        aggregateId: id(),
        actorKeyDigest: Buffer.alloc(32, 1),
        preCommitAuthorityDigest: Buffer.alloc(32, 2),
        actionIntentDigest: Buffer.alloc(32, 3),
        candidateDigest: Buffer.alloc(32, 4),
        idempotencyRecordId: id(),
        before: { existence: 0, revision: 0n, stateDigest: Buffer.alloc(32, 5) },
        after: { existence: 1, revision: 1n, stateDigest: Buffer.alloc(32, 6) },
        authorizationEvidence: [{ kind: 2, evidenceId: id(), evidenceDigest: Buffer.alloc(32, 7) }],
        outboxEvents: [
          {
            eventId: id(),
            eventType: 'io.openpc.control.command.committed.v1',
            dataSchemaUri:
              'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted',
            source: 'urn:openpc:service:control-api',
            subject: 'urn:openpc:indexer-profile:fixture',
            aggregateSequence: 1n,
            occurredAtNs: BigInt(Date.now()) * 1000000n,
            correlationId: id(),
            payloadDigest: Buffer.alloc(32, 8),
          },
        ],
        transitionKind: 1,
        recordedAtNs: BigInt(Date.now()) * 1000000n,
        signerId: fingerprint,
        signerTrustSnapshotDigest: businessSigningTrustDigest(trust),
        requestDigest: Buffer.alloc(32, 10),
      };
      const signing: Extract<BusinessProviderRequest, { method: 'SIGN_RECEIPT' }> = {
        ...base(),
        reference: prepared.reference,
        version: '2',
        method: 'SIGN_RECEIPT',
        attemptId: receipt.receiptId,
        operationId: receipt.operationId,
        expectedFingerprint: fingerprint,
        payloadHex: encodeReceiptStructure(receipt).toString('hex'),
      };
      const capability = createProviderBusinessReceiptSigner(api, apiCredential);
      const capabilityResult = await signBusinessReceipt(receipt, trust, capability);
      const signed = await api.perform(signing);
      validateBusinessProviderObservation(signing, signed);
      expect(capabilityResult.coseSign1.toString('hex')).toBe(signed.resultHex);
      expect(capabilityResult.payload).toEqual(Buffer.from(signing.payloadHex, 'hex'));
      const lifecycleTrust: BusinessSigningTrust = {
        ...trust,
        signerId: lifecycleDescriptor.fingerprint,
        publicKeySpkiDer: lifecyclePublic,
        keyEpoch: 1n,
        secretReference: lifecycleDescriptor.reference,
        secretVersion: '1',
        validFromNs: BigInt(lifecycleDescriptor.validFromNs),
        validUntilNs: BigInt(lifecycleDescriptor.validUntilNs),
        grants: [
          {
            profileId: lifecycleProfile.profileId,
            profileVersion: lifecycleProfile.profileVersion,
            profileDigest: Buffer.from(lifecycleProfile.profileDigest.slice(7), 'hex'),
            actionIntentId: lifecycleProfile.actionIntentId,
            catalogOperationId: lifecycleProfile.catalogOperationId,
          },
        ],
      };
      const lifecycleReceipt: BusinessTransitionReceipt = {
        ...receipt,
        receiptId: id(),
        operationId: id(),
        transitionProfileId: lifecycleProfile.profileId,
        transitionProfileVersion: lifecycleProfile.profileVersion,
        transitionProfileDigest: Buffer.from(lifecycleProfile.profileDigest.slice(7), 'hex'),
        schemaDefinitionDigest: Buffer.from(
          lifecycleProfile.schemaDefinitionDigest.slice(7),
          'hex',
        ),
        actionIntentId: lifecycleProfile.actionIntentId,
        catalogOperationId: lifecycleProfile.catalogOperationId,
        aggregateType: lifecycleProfile.aggregateType,
        before: { existence: 1, revision: 2n, stateDigest: Buffer.alloc(32, 5) },
        after: { existence: 1, revision: 3n, stateDigest: Buffer.alloc(32, 6) },
        outboxEvents: [],
        signerId: lifecycleTrust.signerId,
        signerTrustSnapshotDigest: businessSigningTrustDigest(lifecycleTrust),
      };
      const lifecycleSigned = await signBusinessReceipt(
        lifecycleReceipt,
        lifecycleTrust,
        capability,
      );
      expect(businessSigningSchemaVersion(trust)).toBe(1);
      expect(businessSigningSchemaVersion(lifecycleTrust)).toBe(2);
      expect(
        verifyReceiptCoseV2(lifecyclePublic, lifecycleSigned.payload, lifecycleSigned.coseSign1),
      ).toBe(true);
      expect(
        verifyReceiptCose(lifecyclePublic, lifecycleSigned.payload, lifecycleSigned.coseSign1),
      ).toBe(false);
      await expect(signBusinessReceipt(lifecycleReceipt, trust, capability)).rejects.toThrow();
      expect(() =>
        businessSigningTrustDigest({
          ...lifecycleTrust,
          grants: [...trust.grants, ...lifecycleTrust.grants],
        }),
      ).toThrow();
      expect(() =>
        businessSigningTrustDigest({
          ...lifecycleTrust,
          grants: [{ ...lifecycleTrust.grants[0]!, profileDigest: Buffer.alloc(32, 1) }],
        }),
      ).toThrow();
      await expect(
        signBusinessReceipt(
          receipt,
          trust,
          createProviderBusinessReceiptSigner(worker, workerCredential),
        ),
      ).rejects.toThrow();
      expect(() =>
        validateBusinessProviderObservation(signing, {
          ...signed,
          recordedAtNs: (receipt.recordedAtNs + 1000000n).toString(),
          descriptor: {
            ...signed.descriptor!,
            validFromNs: (receipt.recordedAtNs + 1000n).toString(),
          },
        }),
      ).toThrow();
      expect(await api.perform(signing)).toEqual(signed);
      const wrongWorkload = await worker.perform({
        ...prove,
        attemptId: id(),
        callerWorkloadCredentialId: workerCredential,
      });
      expect(wrongWorkload.reason).toBe('WRONG_SCOPE');
      const revoke = {
        ...next(),
        callerWorkloadCredentialId: workerCredential,
        method: 'REVOKE' as const,
      };
      await writeFile(
        join(state, 'faults', revoke.attemptId + '.json'),
        JSON.stringify({ mode: 'DROP_AFTER_EFFECT' }),
      );
      await expect(worker.perform(revoke)).rejects.toThrow();
      const recovered = await worker.lookup(revoke.attemptId);
      expect(recovered?.descriptor?.state).toBe('REVOKED');
      validateBusinessProviderObservation(revoke, recovered!);
      const attemptsBefore = await readdir(join(state, 'attempts'));
      expect(await worker.perform(revoke)).toEqual(recovered);
      expect(await readdir(join(state, 'attempts'))).toEqual(attemptsBefore);
      expect((await api.perform({ ...prove, attemptId: id() })).reason).toBe('REVOKED');
      const blockedReceipt = { ...receipt, receiptId: id() };
      expect(
        (
          await api.perform({
            ...signing,
            attemptId: blockedReceipt.receiptId,
            payloadHex: encodeReceiptStructure(blockedReceipt).toString('hex'),
          })
        ).reason,
      ).toBe('REVOKED');
      for (const transport of transports) transport.close();
      await fixture!.close();
      fixture = undefined;
      ({ api, worker, unknown } = await start());
      expect(await worker.lookup(revoke.attemptId)).toEqual(recovered);
      expect((await api.perform({ ...prove, attemptId: id() })).reason).toBe('REVOKED');
      validateBusinessProviderObservation(prove, proof); // old public verification remains valid
      validateBusinessProviderObservation(signing, signed);
      const retire = {
        ...next(),
        callerWorkloadCredentialId: workerCredential,
        method: 'RETIRE' as const,
      };
      const retired = await worker.perform(retire);
      validateBusinessProviderObservation(retire, retired);
      expect(retired.descriptor?.state).toBe('RETIRED');
      expect(retired.descriptor?.publicKeySpkiHex).toBe(preparation.descriptor?.publicKeySpkiHex);
      const privateId = createHash('sha256').update(prepared.reference).digest('hex');
      await expect(readFile(join(state, 'keys', privateId + '.der'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
      const poisonedResponse = {
        ...prepared,
        attemptId: id(),
        operationId: id(),
        reference: 'secret://local/control-evidence#7',
        version: '7',
      };
      await writeFile(
        join(state, 'faults', poisonedResponse.attemptId + '.json'),
        JSON.stringify({ mode: 'MISMATCH_AFTER_EFFECT' }),
      );
      await expect(worker.perform(poisonedResponse)).rejects.toThrow();
      const trustedAfterPoison = await worker.lookup(poisonedResponse.attemptId);
      validateBusinessProviderObservation(poisonedResponse, trustedAfterPoison!);
      expect(trustedAfterPoison?.operationId).toBe(poisonedResponse.operationId);
      expect(trustedAfterPoison?.outcome).toBe('SUCCEEDED');
      const beforeEffect = {
        ...prepared,
        attemptId: id(),
        reference: 'secret://local/control-evidence#3',
        version: '3',
      };
      await writeFile(
        join(state, 'faults', beforeEffect.attemptId + '.json'),
        JSON.stringify({ mode: 'DROP_BEFORE_EFFECT' }),
      );
      await expect(worker.perform(beforeEffect)).rejects.toThrow();
      expect((await worker.lookup(beforeEffect.attemptId))?.reason).toBe('NOT_APPLIED');
      const timeout = {
        ...prepared,
        attemptId: id(),
        reference: 'secret://local/control-evidence#4',
        version: '4',
      };
      await writeFile(
        join(state, 'faults', timeout.attemptId + '.json'),
        JSON.stringify({ mode: 'TIMEOUT_AFTER_EFFECT', delayMs: 1500 }),
      );
      await expect(worker.perform(timeout)).rejects.toThrow();
      const timed = await worker.lookup(timeout.attemptId);
      validateBusinessProviderObservation(timeout, timed!);
      const interruptedPrepare = {
        ...prepared,
        attemptId: id(),
        reference: 'secret://local/control-evidence#5',
        version: '5',
      };
      await writeFile(
        join(state, 'faults', interruptedPrepare.attemptId + '.json'),
        JSON.stringify({ mode: 'DROP_AFTER_PRIVATE_MATERIAL' }),
      );
      await expect(worker.perform(interruptedPrepare)).rejects.toThrow();
      const preparedFileId = createHash('sha256')
        .update(interruptedPrepare.reference)
        .digest('hex');
      const persistedPrivate = await readFile(join(state, 'keys', preparedFileId + '.der'));
      const persistedPublic = createPublicKey(
        createPrivateKey({ key: persistedPrivate, type: 'pkcs8', format: 'der' }),
      ).export({ type: 'spki', format: 'der' });
      persistedPrivate.fill(0);
      await expect(readFile(join(state, 'public', preparedFileId + '.json'))).rejects.toMatchObject(
        { code: 'ENOENT' },
      );
      for (const transport of transports) transport.close();
      await fixture!.close();
      fixture = undefined;
      ({ api, worker, unknown } = await start());
      const reconciledPreparation = await worker.lookup(interruptedPrepare.attemptId);
      validateBusinessProviderObservation(interruptedPrepare, reconciledPreparation!);
      expect(reconciledPreparation?.descriptor?.publicKeySpkiHex).toBe(
        persistedPublic.toString('hex'),
      );
      expect(await worker.perform(interruptedPrepare)).toEqual(reconciledPreparation);

      const revokeInitial = {
        ...base(),
        callerWorkloadCredentialId: workerCredential,
        method: 'REVOKE' as const,
        rotationId,
        expectedFingerprint: descriptor.fingerprint,
      };
      validateBusinessProviderObservation(revokeInitial, await worker.perform(revokeInitial));
      const interruptedRetire = { ...revokeInitial, attemptId: id(), method: 'RETIRE' as const };
      await writeFile(
        join(state, 'faults', interruptedRetire.attemptId + '.json'),
        JSON.stringify({ mode: 'DROP_AFTER_PRIVATE_RETIREMENT' }),
      );
      await expect(worker.perform(interruptedRetire)).rejects.toThrow();
      for (const transport of transports) transport.close();
      await fixture!.close();
      fixture = undefined;
      ({ api, worker, unknown } = await start());
      const reconciledRetirement = await worker.lookup(interruptedRetire.attemptId);
      validateBusinessProviderObservation(interruptedRetire, reconciledRetirement!);
      expect(reconciledRetirement?.descriptor?.state).toBe('RETIRED');
      expect(reconciledRetirement?.descriptor?.publicKeySpkiHex).toBe(descriptor.publicKeySpkiHex);
      const initialFileId = createHash('sha256').update(descriptor.reference).digest('hex');
      await expect(readFile(join(state, 'keys', initialFileId + '.der'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
      expect(
        (
          await api.perform({
            ...base(),
            method: 'PROVE',
            rotationId,
            expectedFingerprint: descriptor.fingerprint,
            challengeHex: '19'.repeat(32),
          })
        ).reason,
      ).toBe('REVOKED');
      for (const file of await readdir(join(state, 'attempts'))) {
        const bytes = await readFile(join(state, 'attempts', file), 'utf8');
        expect(bytes).not.toContain(privateBytes.toString('hex'));
        expect(bytes).not.toContain('PRIVATE KEY');
      }
    } finally {
      for (const transport of transports) transport.close();
      if (fixture !== undefined) await fixture.close();
      privateBytes.fill(0);
      await rm(root, { recursive: true, force: true });
    }
  }, 20000);
});
