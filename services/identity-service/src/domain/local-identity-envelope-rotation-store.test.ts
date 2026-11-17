import { tmpdir } from 'node:os';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { afterEach, expect, it } from 'vitest';
import { createLocalIdentityEnvelopeRotationStore } from '../../../../scripts/operations/local-identity-envelope-rotation-store.js';
import {
  startLocalSigningProviderRuntime,
  localSigningProviderCredentialBindings,
} from '../../../../scripts/operations/local-signing-provider-runtime.js';
import { createEnvelopeFixtureStore } from '../../../../tests/integration/local-runtime/signing-provider-envelope-store.js';
import {
  identityEnvelopeFixture,
  envelopeFixtureId as id,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  decodeEnvelopeProposal,
  encodeEnvelopeProposal,
  encodeIdentityAuthorityEnvelope,
  authorityEnvelopeDigest,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  identityEnvelopeProviderDescriptorSchema,
  validateIdentityEnvelopeProviderObservation,
} from './identity-envelope-signing-provider.js';
import {
  identityEnvelopeRotationRequestSchema,
  type IdentityEnvelopeRotationRequest,
} from './identity-envelope-rotation-provider.js';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
const temporary: string[] = [];
afterEach(async () => {
  for (const path of temporary.splice(0)) await rm(path, { recursive: true });
});
const fileId = (reference: string) => createHash('sha256').update(reference).digest('hex');

it('requires a complete distinct successor binding without changing default workload trust', () => {
  expect(localSigningProviderCredentialBindings({})).toEqual({
    apiCredentialId: '018f0000-0000-7000-8000-000000000195',
    workerCredentialId: '018f0000-0000-7000-8000-000000000198',
  });
  const configured = {
    OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID: id(950),
    OPENPC_SIGNING_PROVIDER_WORKER_CREDENTIAL_ID: id(951),
  };
  expect(localSigningProviderCredentialBindings(configured)).toEqual({
    apiCredentialId: id(950),
    workerCredentialId: id(951),
  });
  for (const invalid of [
    { OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID: id(950) },
    { OPENPC_SIGNING_PROVIDER_WORKER_CREDENTIAL_ID: id(951) },
    { ...configured, OPENPC_SIGNING_PROVIDER_WORKER_CREDENTIAL_ID: id(950) },
    { ...configured, OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID: 'unissued-credential' },
    { ...configured, OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT: '1' },
  ])
    expect(() => localSigningProviderCredentialBindings(invalid)).toThrow(
      'LOCAL_PROVIDER_CONFIGURATION_INVALID',
    );
});

it('rejects missing state custody and unsupported fixture flags before startup', async () => {
  await expect(startLocalSigningProviderRuntime({})).rejects.toThrow(
    'LOCAL_PROVIDER_CONFIGURATION_INVALID',
  );
  await expect(
    startLocalSigningProviderRuntime({
      OPENPC_SIGNING_PROVIDER_STATE_ROOT: '/unused',
      OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT: '0',
    }),
  ).rejects.toThrow('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  await expect(
    startLocalSigningProviderRuntime({ OPENPC_SIGNING_PROVIDER_STATE_ROOT: 'relative' }),
  ).rejects.toThrow('LOCAL_PROVIDER_CONFIGURATION_INVALID');
});
async function fixture(distributeKey = true, continuedCredential = false) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'envelope-provider-unit.'));
  temporary.push(root);
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-sha256',
      '-days',
      '1',
      '-subj',
      '/CN=OpenPC provider unit',
      '-addext',
      `subjectAltName=URI:urn:openpc:participant:${id(1)}:workload:${id(222)}`,
      '-keyout',
      join(root, 'client.key'),
      '-out',
      join(root, 'client.pem'),
    ],
    { stdio: 'ignore' },
  );
  const certificate = await readFile(join(root, 'client.pem'));
  const peer =
    'sha256:' + createHash('sha256').update(new X509Certificate(certificate).raw).digest('hex');
  const client = {
    certificate,
    credentialId: id(221),
    workloadId: id(222),
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    keyOwnerCredentialId: id(221),
    methods: ['SIGN_AUTHORITY_ENVELOPE', 'ORIGINAL_LOOKUP'] as const,
  };
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
  const at = BigInt(Date.now()) * 1000000n;
  const legacy = identityEnvelopeProviderDescriptorSchema.parse({
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    workloadCredentialId: id(221),
    workloadCredentialEpoch: '11',
    secretClass: 'SECRET-SIGNING-KEY',
    reference: 'secret://test/envelope-original#1',
    version: '1',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371,
    schemaId: 24034,
    schemaVersion: 1,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
    algorithm: 'ES256',
    publicKeySpkiHex: spki.toString('hex'),
    fingerprint: evidenceKeyId(spki),
    validFromNs: (at - 86400000000000n).toString(),
    validUntilNs: (at - 1000000n).toString(),
    state: 'ACTIVE',
    trustContextDigest: 'sha256:' + '61'.repeat(32),
  });
  const privateBytes = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  await createEnvelopeFixtureStore(root, {
    clients: [client],
    initialKeys: [{ descriptor: legacy, privateKeyPkcs8Der: privateBytes }],
  });
  privateBytes.fill(0);
  const currentClient = continuedCredential
    ? { ...client, credentialId: id(223), keyOwnerCredentialId: id(223) }
    : client;
  const config = {
    root,
    clients: [currentClient],
    predecessorReference: legacy.reference,
    predecessorFingerprint: legacy.fingerprint,
    keyValiditySeconds: 3600,
  };
  let store = await createLocalIdentityEnvelopeRotationStore(config);
  let next = 600;
  const request = (
    method: IdentityEnvelopeRotationRequest['method'],
    reference = 'secret://test/envelope-recovery#2',
    extra: Record<string, unknown> = {},
  ) =>
    identityEnvelopeRotationRequestSchema.parse({
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: 'test',
      workloadCredentialId: currentClient.keyOwnerCredentialId,
      workloadCredentialEpoch: continuedCredential ? '12' : '11',
      secretClass: 'SECRET-SIGNING-KEY',
      reference,
      version: reference.split('#')[1],
      purpose: identityEnvelopeContext.purpose,
      purposeCode: 371,
      schemaId: 24034,
      schemaVersion: 1,
      schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
      profileId: 'pc.identity.authority-envelope.v1',
      profileVersion: 1,
      profileDigest: identityEnvelopeSigningProfileDigest,
      callerWorkloadCredentialId: currentClient.credentialId,
      rotationId: id(500),
      operationId: id(next++),
      attemptId: id(next++),
      issuerParticipantEpoch: '7',
      issuerPrincipalEpoch: '2',
      governanceDigest: 'sha256:' + '62'.repeat(32),
      method,
      ...extra,
    });
  const prepare = request('PREPARE');
  const prepared = await store.perform(prepare, peer);
  const key = prepared.descriptor!;
  const distribute = request('DISTRIBUTE', key.reference, {
    expectedFingerprint: key.fingerprint,
    trustContextDigest: 'sha256:' + '63'.repeat(32),
  });
  if (distributeKey) await store.perform(distribute, peer);
  const prove = (old = false) => {
    const timestamp = BigInt(Date.now()) * 1000000n;
    return request('PROVE', old ? legacy.reference : key.reference, {
      expectedFingerprint: old ? legacy.fingerprint : key.fingerprint,
      challengeHex: '64'.repeat(32),
      challengeIssuedAtNs: timestamp.toString(),
      challengeExpiresAtNs: (timestamp + 300000000000n).toString(),
      ...(old
        ? {
            recoveryPredecessor: {
              purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
              enrollmentId: id(510),
              enrollmentDigest: 'sha256:' + '65'.repeat(32),
              recoveryId: id(511),
              activationOperationId: id(512),
              leaseDigest: 'sha256:' + '66'.repeat(32),
              oldTrustDigest: 'sha256:' + '67'.repeat(32),
            },
          }
        : {}),
    });
  };
  const normalRequest = () => {
    const envelope = identityEnvelopeFixture(key.fingerprint);
    const proposal = decodeEnvelopeProposal(envelope.proposalBytes);
    for (const scope of [proposal.usable, proposal.grantable]) {
      scope.validFromNs = key.validFromNs;
      scope.validUntilNs = key.validUntilNs;
    }
    envelope.proposalBytes = encodeEnvelopeProposal(proposal);
    envelope.proposalDigest = authorityEnvelopeDigest(envelope.proposalBytes);
    envelope.issuedAtNs = (BigInt(Date.now()) * 1000000n).toString();
    envelope.signer = {
      ...envelope.signer,
      profileId: key.profileId,
      profileDigest: key.profileDigest,
      keyVersion: key.version,
      trustContextDigest: 'sha256:' + '63'.repeat(32),
      workloadCredentialId: key.workloadCredentialId,
      workloadCredentialEpoch: key.workloadCredentialEpoch,
    };
    return {
      participantId: key.participantId,
      privacyDomainId: key.privacyDomainId,
      environmentId: key.environmentId,
      workloadCredentialId: key.workloadCredentialId,
      workloadCredentialEpoch: key.workloadCredentialEpoch,
      secretClass: key.secretClass,
      reference: key.reference,
      version: key.version,
      purpose: key.purpose,
      purposeCode: key.purposeCode,
      schemaId: key.schemaId,
      schemaVersion: key.schemaVersion,
      schemaDefinitionDigest: key.schemaDefinitionDigest,
      profileId: key.profileId,
      profileVersion: key.profileVersion,
      profileDigest: key.profileDigest,
      trustContextDigest: envelope.signer.trustContextDigest,
      method: 'SIGN_AUTHORITY_ENVELOPE' as const,
      callerWorkloadCredentialId: currentClient.credentialId,
      attemptId: id(next++),
      operationId: envelope.activation.operationId,
      expectedFingerprint: key.fingerprint,
      payloadHex: encodeIdentityAuthorityEnvelope(envelope).toString('hex'),
    };
  };
  const journal = (attemptId: string) =>
    join(root, 'identity-envelope', 'rotation-attempts', attemptId + '.json');
  return {
    root,
    peer,
    legacy,
    key,
    prepare,
    distribute,
    request,
    prove,
    normalRequest,
    journal,
    get store() {
      return store;
    },
    async restart() {
      await store.close();
      store = await createLocalIdentityEnvelopeRotationStore(config);
    },
  };
}

it('uses real new-key normal signing and old-only expired custody possession, then fences and retires original private material across cold restart', async () => {
  const f = await fixture();
  const signed = f.normalRequest();
  const result = await f.store.normalPerform(signed, f.peer);
  expect(
    validateIdentityEnvelopeProviderObservation(signed, result.observation).descriptor.fingerprint,
  ).toBe(f.key.fingerprint);
  const original = await f.store.perform(f.prove(true), f.peer);
  expect(original.outcome).toBe('SUCCEEDED');
  expect(original.descriptor?.validUntilNs).toBe(f.legacy.validUntilNs);
  const ordinary = f.prove(true);
  if (ordinary.method !== 'PROVE') throw Error();
  delete ordinary.recoveryPredecessor;
  expect((await f.store.perform(ordinary, f.peer)).reason).toBe('EXPIRED');
  const revoke = f.request('REVOKE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const revoked = await f.store.perform(revoke, f.peer);
  expect(revoked.descriptor?.state).toBe('REVOKED');
  await expect(
    f.store.normalPerform({ ...signed, reference: f.legacy.reference, version: '1' }, f.peer),
  ).rejects.toThrow();
  const retire = f.request('RETIRE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const retired = await f.store.perform(retire, f.peer);
  expect(retired.descriptor?.revokedAtNs).toBe(revoked.descriptor?.revokedAtNs);
  await expect(
    readFile(join(f.root, 'identity-envelope', 'keys', fileId(f.legacy.reference) + '.der')),
  ).rejects.toMatchObject({ code: 'ENOENT' });
  await f.restart();
  expect(await f.store.lookup(retire, f.peer)).toEqual({ state: 'OBSERVED', observation: retired });
  expect(await f.store.normalLookup(signed, f.peer)).toEqual({
    state: 'OBSERVED',
    observation: result.observation,
  });
  expect(
    (await f.store.normalPerform(f.normalRequest(), f.peer)).observation?.descriptor.fingerprint,
  ).toBe(f.key.fingerprint);
  await f.store.close();
});

it('keeps original credential metadata during pinned predecessor proof and retirement with a renewed caller', async () => {
  const f = await fixture(true, true);
  expect(f.key.workloadCredentialId).toBe(id(223));
  const original = await f.store.perform(f.prove(true), f.peer);
  expect(original.outcome).toBe('SUCCEEDED');
  expect(original.descriptor?.workloadCredentialId).toBe(id(221));
  expect(original.descriptor?.workloadCredentialEpoch).toBe('11');
  const ordinary = f.prove(true);
  if (ordinary.method !== 'PROVE') throw Error();
  delete ordinary.recoveryPredecessor;
  expect((await f.store.perform(ordinary, f.peer)).reason).toBe('WRONG_SCOPE');
  const wrongCaller = { ...f.prove(true), callerWorkloadCredentialId: id(221) };
  await expect(f.store.perform(wrongCaller, f.peer)).rejects.toThrow();
  const wrongReference = { ...f.prove(true), reference: f.key.reference, version: f.key.version };
  await expect(f.store.perform(wrongReference, f.peer)).rejects.toThrow();
  const signed = f.normalRequest();
  expect(
    (await f.store.normalPerform(signed, f.peer)).observation?.descriptor.workloadCredentialId,
  ).toBe(id(223));
  const revoke = f.request('REVOKE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const revoked = await f.store.perform(revoke, f.peer);
  expect(revoked.descriptor?.workloadCredentialId).toBe(id(221));
  const retire = f.request('RETIRE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const retired = await f.store.perform(retire, f.peer);
  expect(retired.descriptor?.state).toBe('RETIRED');
  await f.restart();
  expect(await f.store.lookup(retire, f.peer)).toEqual({ state: 'OBSERVED', observation: retired });
  expect(
    (await f.store.normalPerform(f.normalRequest(), f.peer)).observation?.descriptor
      .workloadCredentialId,
  ).toBe(id(223));
  await f.store.close();
});

it('recovers PREPARE after private publication but before manifest publication without changing the key or enabling normal signing', async () => {
  const f = await fixture(false);
  const path = f.journal(f.prepare.attemptId);
  const started = JSON.parse(await readFile(path, 'utf8'));
  started.observation = null;
  await writeFile(path, JSON.stringify(started));
  await rm(join(f.root, 'identity-envelope', 'rotation-keys', fileId(f.key.reference) + '.json'));
  const keyPath = join(f.root, 'identity-envelope', 'keys', fileId(f.key.reference) + '.der');
  const before = createHash('sha256')
    .update(await readFile(keyPath))
    .digest('hex');
  await f.restart();
  const recovered = await f.store.lookup(f.prepare, f.peer);
  expect(recovered.state).toBe('OBSERVED');
  if (recovered.state !== 'OBSERVED') throw Error();
  expect(recovered.observation.descriptor).toEqual(f.key);
  expect(await f.store.perform(f.prepare, f.peer)).toEqual(recovered.observation);
  expect(
    createHash('sha256')
      .update(await readFile(keyPath))
      .digest('hex'),
  ).toBe(before);
  await expect(f.store.normalPerform(f.normalRequest(), f.peer)).rejects.toThrow();
  expect((await f.store.perform(f.distribute, f.peer)).outcome).toBe('SUCCEEDED');
  expect((await f.store.normalPerform(f.normalRequest(), f.peer)).observation).toBeDefined();
  await f.store.close();
});

it('keeps missing PREPARE material unknown and never generates a replacement on replay', async () => {
  const f = await fixture(false);
  const path = f.journal(f.prepare.attemptId);
  const started = JSON.parse(await readFile(path, 'utf8'));
  started.observation = null;
  await writeFile(path, JSON.stringify(started));
  await rm(join(f.root, 'identity-envelope', 'rotation-keys', fileId(f.key.reference) + '.json'));
  const keyPath = join(f.root, 'identity-envelope', 'keys', fileId(f.key.reference) + '.der');
  await rm(keyPath);
  await f.restart();
  expect((await f.store.lookup(f.prepare, f.peer)).state).toBe('UNKNOWN');
  await expect(f.store.perform(f.prepare, f.peer)).rejects.toThrow();
  await expect(readFile(keyPath)).rejects.toMatchObject({ code: 'ENOENT' });
  await f.store.close();
});

it('reconciles RETIRE after unlink without repeating destruction or replacing the original retirement timestamp', async () => {
  const f = await fixture();
  const revoke = f.request('REVOKE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  await f.store.perform(revoke, f.peer);
  const manifest = join(
    f.root,
    'identity-envelope',
    'rotation-keys',
    fileId(f.legacy.reference) + '.json',
  );
  const publicPath = join(
    f.root,
    'identity-envelope',
    'public',
    fileId(f.legacy.reference) + '.json',
  );
  const revokedManifest = await readFile(manifest);
  const revokedPublic = await readFile(publicPath);
  const retire = f.request('RETIRE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const original = await f.store.perform(retire, f.peer);
  const path = f.journal(retire.attemptId);
  const started = JSON.parse(await readFile(path, 'utf8'));
  expect(original.descriptor?.retiredAtNs).toBe(started.startedAtNs);
  started.observation = null;
  await writeFile(path, JSON.stringify(started));
  await writeFile(manifest, revokedManifest);
  await writeFile(publicPath, revokedPublic);
  await f.restart();
  const recovered = await f.store.lookup(retire, f.peer);
  expect(recovered.state).toBe('OBSERVED');
  if (recovered.state !== 'OBSERVED') throw Error();
  expect(recovered.observation.descriptor).toEqual(original.descriptor);
  expect(await f.store.perform(retire, f.peer)).toEqual(recovered.observation);
  await expect(
    readFile(join(f.root, 'identity-envelope', 'keys', fileId(f.legacy.reference) + '.der')),
  ).rejects.toMatchObject({ code: 'ENOENT' });
  await f.store.close();
});

it('reconciles original revocation response loss from its durable manifest without replacing the effect timestamp', async () => {
  const f = await fixture();
  const request = f.request('REVOKE', f.legacy.reference, {
    expectedFingerprint: f.legacy.fingerprint,
  });
  const original = await f.store.perform(request, f.peer);
  const path = f.journal(request.attemptId);
  const lost = JSON.parse(await readFile(path, 'utf8'));
  lost.observation = null;
  await writeFile(path, JSON.stringify(lost));
  await f.restart();
  expect(await f.store.lookup(request, f.peer)).toEqual({
    state: 'OBSERVED',
    observation: original,
  });
  expect(await f.store.perform(request, f.peer)).toEqual(original);
  await expect(f.store.lookup({ ...request, operationId: id(999) }, f.peer)).rejects.toThrow();
  await f.store.close();
});

it('preserves an unknown original possession effect and never signs again on lookup or perform replay', async () => {
  const f = await fixture();
  const request = f.prove();
  await f.store.perform(request, f.peer);
  const path = f.journal(request.attemptId);
  const lost = JSON.parse(await readFile(path, 'utf8'));
  lost.observation = null;
  await writeFile(path, JSON.stringify(lost));
  await f.restart();
  expect((await f.store.lookup(request, f.peer)).state).toBe('UNKNOWN');
  await expect(f.store.perform(request, f.peer)).rejects.toThrow();
  expect(JSON.parse(await readFile(path, 'utf8')).observation).toBeNull();
  await f.store.close();
});

it('denies foreign peers and successor destructive effects before creating an attempt', async () => {
  const f = await fixture();
  const before = await readdir(join(f.root, 'identity-envelope', 'rotation-attempts'));
  await expect(f.store.perform(f.prove(), 'sha256:' + '99'.repeat(32))).rejects.toThrow();
  await expect(
    f.store.perform(
      f.request('REVOKE', f.key.reference, { expectedFingerprint: f.key.fingerprint }),
      f.peer,
    ),
  ).rejects.toThrow();
  await expect(
    f.store.perform({ ...f.prove(), privacyDomainId: id(999) }, f.peer),
  ).rejects.toThrow();
  expect(await readdir(join(f.root, 'identity-envelope', 'rotation-attempts'))).toEqual(before);
  await f.store.close();
});

it('serves rotation lookup over actual TLS 1.3, denies a foreign or absent certificate, and leaves provider effects empty', async () => {
  const f = await fixture();
  const ca = await readFile(join(f.root, 'client.pem'));
  const secrets = join(f.root, 'tls-secrets');
  await mkdir(secrets, { mode: 0o700 });
  const participant = '018f0000-0000-7000-8000-000000000101';
  const credential = '018f0000-0000-7000-8000-000000000195';
  for (const [name, san, usage] of [
    [
      'business_api',
      `URI:urn:openpc:participant:${participant}:workload:018f0000-0000-7000-8000-000000000196`,
      'clientAuth',
    ],
    [
      'business_worker',
      `URI:urn:openpc:participant:${participant}:workload:018f0000-0000-7000-8000-000000000199`,
      'clientAuth',
    ],
    ['business_provider_server', 'DNS:localhost,IP:127.0.0.1', 'serverAuth'],
  ] as const) {
    const csr = join(secrets, name + '.csr');
    execFileSync(
      'openssl',
      [
        'req',
        '-new',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        '/CN=' + name,
        '-addext',
        'subjectAltName=' + san,
        '-addext',
        'extendedKeyUsage=' + usage,
        '-keyout',
        join(secrets, name + '_key'),
        '-out',
        csr,
      ],
      { stdio: 'ignore' },
    );
    execFileSync(
      'openssl',
      [
        'x509',
        '-req',
        '-sha256',
        '-days',
        '1',
        '-copy_extensions',
        'copy',
        '-in',
        csr,
        '-CA',
        join(f.root, 'client.pem'),
        '-CAkey',
        join(f.root, 'client.key'),
        '-set_serial',
        String(100 + name.length),
        '-out',
        join(secrets, name + '_cert'),
      ],
      { stdio: 'ignore' },
    );
  }
  await writeFile(join(secrets, 'business_provider_ca'), ca);
  const reference = 'secret://local/identity-envelope-activation#1';
  const legacy = {
    ...f.legacy,
    participantId: participant,
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    environmentId: 'local',
    workloadCredentialId: credential,
    reference,
  };
  await writeFile(
    join(f.root, 'identity-envelope', 'public', fileId(reference) + '.json'),
    canonicalDefinitionJson(legacy),
  );
  const api = {
    cert: await readFile(join(secrets, 'business_api_cert')),
    key: await readFile(join(secrets, 'business_api_key')),
  };
  const worker = {
    cert: await readFile(join(secrets, 'business_worker_cert')),
    key: await readFile(join(secrets, 'business_worker_key')),
  };
  const runtime = await startLocalSigningProviderRuntime({
    OPENPC_SIGNING_PROVIDER_STATE_ROOT: f.root,
    OPENPC_SIGNING_PROVIDER_SECRET_ROOT: secrets,
  });
  const body = {
    ...f.prove(),
    participantId: participant,
    privacyDomainId: legacy.privacyDomainId,
    environmentId: 'local',
    workloadCredentialId: credential,
    callerWorkloadCredentialId: credential,
    reference: 'secret://local/recovery#2',
  };
  const before = await readdir(join(f.root, 'identity-envelope', 'rotation-attempts'));
  const call = (peer: typeof api | undefined, wire = canonicalDefinitionJson(body)) =>
    new Promise<{ status: number; body: unknown; protocol: string | null }>((resolve, reject) => {
      let protocol: string | null = null;
      const request = httpsRequest(
        {
          hostname: '127.0.0.1',
          servername: 'localhost',
          port: 3007,
          path: '/v1/identity-envelope-signing/rotation/lookup',
          method: 'POST',
          ca,
          ...peer,
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          timeout: 5000,
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(wire),
          },
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on('data', (bytes) => chunks.push(bytes));
          response.on('end', () =>
            resolve({
              status: response.statusCode!,
              body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
              protocol,
            }),
          );
        },
      );
      request.on('socket', (socket) =>
        (socket as TLSSocket).on('secureConnect', () => {
          expect((socket as TLSSocket).authorized).toBe(true);
          protocol = (socket as TLSSocket).getProtocol();
        }),
      );
      request.on('error', reject);
      request.on('timeout', () => request.destroy(Error('TLS_TIMEOUT')));
      request.end(wire);
    });
  try {
    const allowed = await call(api);
    expect(allowed.status).toBe(200);
    expect(allowed.protocol).toBe('TLSv1.3');
    expect(allowed.body).toMatchObject({
      state: 'NOT_FOUND',
      attemptId: body.attemptId,
      operationId: body.operationId,
    });
    expect(await call(worker)).toMatchObject({ status: 403, body: { code: 'DENIED' } });
    await expect(call(undefined)).rejects.toThrow();
    expect(await call(api, JSON.stringify(body, null, 2))).toMatchObject({
      status: 400,
      body: { code: 'INVALID_REQUEST' },
    });
    expect(await readdir(join(f.root, 'identity-envelope', 'rotation-attempts'))).toEqual(before);
  } finally {
    await runtime.close();
    await f.store.close();
  }
});
