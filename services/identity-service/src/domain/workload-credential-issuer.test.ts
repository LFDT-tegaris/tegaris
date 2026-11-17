import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign,
  X509Certificate,
} from 'node:crypto';
import {
  encodeWorkloadRenewalRequest,
  signWorkloadRenewalCose,
  workloadRenewalDigest,
} from '@openpc/security-kernel';
import {
  createLocalWorkloadIssuerFixture,
  localWorkloadIssuerManifestDigest,
  readLocalWorkloadIssuerProfiles,
  readLocalWorkloadIssuerUnknownRecovery,
} from '../../../../tests/integration/local-runtime/workload-issuer-runtime.js';
import { renewalRequestFixture } from '../../../../packages/security-kernel/src/workload-renewal/fixture.js';
import { execFileSync, spawn } from 'node:child_process';
import { connect, createServer as netServer } from 'node:net';
import { createServer as httpServer } from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  captureOwnedLocalIssuerClaims,
  issuerProcessStartTicks,
  LocalIssuerCaptureFailure,
  preflightOwnedLocalIssuerClaims,
} from '../../../../tests/integration/local-runtime/workload-issuer-claims-capture.js';
import { setTimeout as delay } from 'node:timers/promises';
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

const journalFault = vi.hoisted(() => ({ path: '', mode: '', calls: 0 }));
vi.mock('node:fs/promises', async (original) => {
  const actual = await original<typeof import('node:fs/promises')>();
  const { constants } = await import('node:fs');
  const failure = () =>
    Object.assign(new Error('Injected isolated journal I/O failure'), { code: 'EIO' });
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const file = await actual.open(...args);
      if (
        args[0] !== journalFault.path ||
        typeof args[1] !== 'number' ||
        !(args[1] & constants.O_APPEND)
      )
        return file;
      journalFault.calls++;
      const mode = journalFault.mode;
      return new Proxy(file, {
        get(target, key) {
          if (key === 'writeFile' && mode === 'partial write')
            return async (bytes: Buffer) => {
              await target.writeFile(bytes.subarray(0, Math.max(1, Math.floor(bytes.length / 2))));
              throw failure();
            };
          if (key === 'sync' && mode === 'fsync ambiguity')
            return async () => {
              await target.sync();
              throw failure();
            };
          if (key === 'close' && mode === 'close ambiguity')
            return async () => {
              await target.close();
              throw failure();
            };
          const value: unknown = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
});

import {
  createHttpWorkloadCredentialIssuer,
  readImmutableLocalWorkloadIssuerProfile,
  authenticateHistoricalLocalWorkloadIssuerProfile,
  workloadCertificateRequestDigest,
  verifyIssuedWorkloadCertificate,
  type WorkloadCertificateRequest,
} from './workload-credential-issuer.js';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  workloadRenewalOriginalSchema,
  encodeWorkloadRenewalProviderRequest,
  renewalBytesDigest,
} from '../contracts/workload-renewal.js';
import { verifyWorkloadRenewalObservation } from './workload-renewal-provider.js';

const roots: string[] = [];
const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000190';
const workloadId = 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191';
const credentialId = '018f0000-0000-7000-8000-000000000192';

async function certificateFixture(validity?: {
  caFrom: Date;
  caUntil: Date;
  clientFrom: Date;
  clientUntil: Date;
}) {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_ROOT ?? tmpdir(), 'openpc-workload-certificate-'),
  );
  roots.push(root);
  const caKey = join(root, 'ca-key.pem');
  const ca = join(root, 'ca.pem');
  const key = join(root, 'client-key.pem');
  const csr = join(root, 'client.csr');
  const certificate = join(root, 'client.pem');
  const extensions = join(root, 'extensions.cnf');
  const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId.split(':').at(-1)}`;
  await writeFile(
    extensions,
    `[client]\nsubjectAltName=URI:${uriSan}\nextendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:false\n`,
  );
  execFileSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-sha256',
    '-days',
    '2',
    '-subj',
    '/CN=OpenPC test workload CA',
    '-addext',
    'basicConstraints=critical,CA:true',
    '-keyout',
    caKey,
    '-out',
    ca,
  ]);
  execFileSync('openssl', [
    'req',
    '-new',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-subj',
    '/CN=OpenPC test workload',
    '-keyout',
    key,
    '-out',
    csr,
  ]);
  execFileSync('openssl', [
    'x509',
    '-req',
    '-sha256',
    '-days',
    '1',
    '-in',
    csr,
    '-CA',
    ca,
    '-CAkey',
    caKey,
    '-CAcreateserial',
    '-extfile',
    extensions,
    '-extensions',
    'client',
    '-out',
    certificate,
  ]);
  if (validity) {
    // Real independently signed certificates with explicit fixture timestamps.
    // No system clock or retained credential is changed.
    const config = join(root, 'ca.cnf');
    const index = join(root, 'index.txt');
    const serial = join(root, 'serial.txt');
    const seedCa = join(root, 'seed-ca.pem');
    const caCsr = join(root, 'ca.csr');
    const caExtensions = join(root, 'ca-extensions.cnf');
    await writeFile(seedCa, await readFile(ca));
    await writeFile(index, '');
    await writeFile(serial, '10\n');
    await writeFile(
      config,
      `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=${index}\nserial=${serial}\nnew_certs_dir=${root}\ncertificate=${seedCa}\nprivate_key=${caKey}\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n`,
    );
    await writeFile(
      caExtensions,
      '[authority]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n',
    );
    execFileSync('openssl', [
      'req',
      '-new',
      '-key',
      caKey,
      '-subj',
      '/CN=OpenPC test workload CA',
      '-out',
      caCsr,
    ]);
    const time = (date: Date) =>
      date
        .toISOString()
        .replace(/[-:T]/gu, '')
        .replace(/\.\d{3}Z$/u, 'Z');
    execFileSync('openssl', [
      'ca',
      '-batch',
      '-selfsign',
      '-notext',
      '-config',
      config,
      '-in',
      caCsr,
      '-out',
      ca,
      '-startdate',
      time(validity.caFrom),
      '-enddate',
      time(validity.caUntil),
      '-extfile',
      caExtensions,
      '-extensions',
      'authority',
    ]);
    execFileSync('openssl', [
      'ca',
      '-batch',
      '-notext',
      '-config',
      config,
      '-cert',
      ca,
      '-in',
      csr,
      '-out',
      certificate,
      '-startdate',
      time(validity.clientFrom),
      '-enddate',
      time(validity.clientUntil),
      '-extfile',
      extensions,
      '-extensions',
      'client',
    ]);
  }
  const certificatePem = await readFile(certificate);
  const certificateObject = new X509Certificate(certificatePem);
  const request: WorkloadCertificateRequest = {
    credentialId,
    participantId,
    principalId,
    workloadId,
    publicKeySpkiDer: Buffer.from(
      certificateObject.publicKey.export({ format: 'der', type: 'spki' }),
    ),
  };
  return {
    ca: await readFile(ca),
    certificateDer: certificateObject.raw,
    privateKeyPkcs8: createPrivateKey(await readFile(key)).export({ format: 'der', type: 'pkcs8' }),
    request,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

it('authenticates v2 issued DER and its exact CA, SPKI, SAN and finite interval without admitting business use', async () => {
  const fixture = await certificateFixture();
  const certificate = new X509Certificate(fixture.certificateDer);
  const now = new Date();
  const signer = generateKeyPairSync('ed25519');
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const digest = `sha256:${'11'.repeat(32)}` as const;
  const identity = {
    version: 2 as const,
    renewalId: id(1),
    providerRequestId: id(1),
    operationId: id(2),
    credentialId,
    participantId,
    principalId,
    workloadId,
    privacyDomainId: id(5),
    familyId: id(8),
    instanceId: id(9),
    instanceGeneration: '1',
    predecessorCredentialId: id(10),
    expectedFamilyGeneration: '2',
    policyId: id(11),
    policyRevision: '3',
    policyDigest: digest,
    attestationProfileDigest: digest,
    attestationDigest: digest,
    issuerProfileDigest: digest,
    providerQualificationDigest: digest,
  };
  const payload = encodeWorkloadRenewalRequest({
    ...renewalRequestFixture(workloadRenewalDigest(fixture.request.publicKeySpkiDer)),
    participantId,
    privacyDomainId: identity.privacyDomainId,
    principalId,
    workloadId,
    familyId: identity.familyId,
    instanceId: identity.instanceId,
    instanceGeneration: identity.instanceGeneration,
    renewalId: identity.renewalId,
    predecessorCredentialId: identity.predecessorCredentialId,
    predecessorGeneration: identity.expectedFamilyGeneration,
    policyId: identity.policyId,
    policyRevision: identity.policyRevision,
    policyDigest: identity.policyDigest,
    attestationProfileDigest: identity.attestationProfileDigest,
    attestationDigest: identity.attestationDigest,
    issuerProfileDigest: identity.issuerProfileDigest,
    providerQualificationDigest: identity.providerQualificationDigest,
    requestedCertificateNotBeforeNs: (
      BigInt(Date.parse(certificate.validFrom)) * 1000000n
    ).toString(),
    requestedCertificateNotAfterNs: (BigInt(Date.parse(certificate.validTo)) * 1000000n).toString(),
    requestValidFromNs: (BigInt(now.getTime()) * 1000000n).toString(),
    requestValidUntilNs: (BigInt(now.getTime() + 120000) * 1000000n).toString(),
  });
  const bytes = encodeWorkloadRenewalProviderRequest({
    ...identity,
    publicKeySpkiDerBase64: fixture.request.publicKeySpkiDer.toString('base64'),
    requestPayloadBase64: payload.toString('base64'),
    newKeyProofBase64: signWorkloadRenewalCose(
      'REQUEST',
      fixture.privateKeyPkcs8,
      fixture.request.publicKeySpkiDer,
      payload,
    ).toString('base64'),
    algorithm: 'ECDSA_P256_SHA256',
    uriSan: `urn:openpc:participant:${participantId}:workload:${workloadId.split(':').at(-1)}`,
    audience: 'test-runtime',
    validFrom: new Date(certificate.validFrom).toISOString(),
    validUntil: new Date(certificate.validTo).toISOString(),
  });
  const original = workloadRenewalOriginalSchema.parse({
    ...identity,
    providerRequestBase64: bytes.toString('base64'),
    providerRequestDigest: renewalBytesDigest(bytes),
  });
  const statement = {
    domain: 'OPENPC_WORKLOAD_RENEWAL_PROVIDER_OBSERVATION',
    version: 2,
    kind: 'CERTIFICATE',
    providerRequestId: id(1),
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    observationRevision: '1',
    observedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + 60000).toISOString(),
    certificateDigest: renewalBytesDigest(fixture.certificateDer),
  };
  const proof = {
    statement,
    signatureBase64: sign(
      null,
      Buffer.from(canonicalDefinitionJson(statement)),
      signer.privateKey,
    ).toString('base64'),
  };
  const observation = {
    kind: 'CERTIFICATE' as const,
    providerRequestId: id(1),
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    certificateDerBase64: fixture.certificateDer.toString('base64'),
    proofBase64: Buffer.from(canonicalDefinitionJson(proof)).toString('base64'),
  };
  const profile = {
    endpoint: 'https://issuer.test/',
    audience: 'test-runtime',
    maximumLeafLifetimeMs: 86400000,
    qualificationDigest: digest,
    issuerProfileDigest: digest,
    observationSignerSpkiDer: Buffer.from(signer.publicKey.export({ type: 'spki', format: 'der' })),
    trustedCaPem: fixture.ca,
  };
  expect(
    verifyWorkloadRenewalObservation(original, observation, profile, now)?.certificate
      ?.certificateDer,
  ).toEqual(fixture.certificateDer);
  expect(
    verifyWorkloadRenewalObservation(
      original,
      observation,
      { ...profile, trustedCaPem: Buffer.from('untrusted CA') },
      now,
    ),
  ).toMatchObject({ kind: 'CERTIFICATE', certificate: undefined });
});

describe('workload certificate issuer trust boundary', () => {
  it.each(['expired CA', 'future CA', 'leaf outlives CA'] as const)(
    'rejects a correctly signed current leaf under %s',
    async (failure) => {
      const now = new Date(Math.floor(Date.now() / 1000) * 1000);
      const at = (offset: number) => new Date(now.getTime() + offset);
      const fixture = await certificateFixture({
        caFrom: at(failure === 'future CA' ? 3600000 : -3600000),
        caUntil: at(
          failure === 'expired CA' ? -60000 : failure === 'leaf outlives CA' ? 1800000 : 7200000,
        ),
        clientFrom: at(-60000),
        clientUntil: at(3600000),
      });
      const leaf = new X509Certificate(fixture.certificateDer);
      const ca = new X509Certificate(fixture.ca);
      expect(leaf.checkIssued(ca)).toBe(true);
      expect(leaf.verify(ca.publicKey)).toBe(true);
      expect(new Date(leaf.validFrom).getTime()).toBeLessThan(now.getTime());
      expect(new Date(leaf.validTo).getTime()).toBeGreaterThan(now.getTime());
      expect(
        verifyIssuedWorkloadCertificate(
          fixture.certificateDer,
          fixture.ca,
          fixture.request,
          now,
        ) === undefined,
      ).toBe(true);
    },
  );
  it('accepts only the issuer-signed exact workload, SAN, client purpose, key, and lifetime', async () => {
    const fixture = await certificateFixture();
    const verified = verifyIssuedWorkloadCertificate(
      fixture.certificateDer,
      fixture.ca,
      fixture.request,
    );
    expect(verified).toMatchObject({
      participantId,
      principalId,
      workloadId,
      credentialId,
      uriSan: `urn:openpc:participant:${participantId}:workload:${workloadId.split(':').at(-1)}`,
    });
    expect(verified?.certificateFingerprint).toHaveLength(32);
    expect(verified?.certificateDer).toEqual(fixture.certificateDer);
    expect(verified?.keyId).toMatch(/^sha256:[0-9a-f]{64}$/u);

    expect(
      verifyIssuedWorkloadCertificate(fixture.certificateDer, fixture.ca, {
        ...fixture.request,
        participantId: '018f0000-0000-7000-8000-000000000102',
      }),
    ).toBeUndefined();
    const foreignKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
      format: 'der',
      type: 'spki',
    });
    expect(
      verifyIssuedWorkloadCertificate(fixture.certificateDer, fixture.ca, {
        ...fixture.request,
        publicKeySpkiDer: foreignKey,
      }),
    ).toBeUndefined();
  });

  it('rejects malformed issuer responses and returns only locally verified certificate facts', async () => {
    const fixture = await certificateFixture();
    const issuer = createHttpWorkloadCredentialIssuer({
      endpoint: 'https://issuer.openpc.test/v1/certificates',
      authorizationToken: 't'.repeat(32),
      trustedCaPem: fixture.ca,
      fetch: async (_url, request) => {
        expect(request?.redirect).toBe('error');
        expect(request?.headers).toMatchObject({ authorization: `Bearer ${'t'.repeat(32)}` });
        return new Response(
          JSON.stringify({ certificateDer: fixture.certificateDer.toString('base64') }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      },
    });
    await expect(issuer.issue(fixture.request)).resolves.toMatchObject({
      credentialId,
      participantId,
      workloadId,
    });

    const malformed = createHttpWorkloadCredentialIssuer({
      endpoint: 'https://issuer.openpc.test/v1/certificates',
      authorizationToken: 't'.repeat(32),
      trustedCaPem: fixture.ca,
      fetch: async () => new Response(JSON.stringify({ certificateDer: 'not-base64' })),
    });
    await expect(malformed.issue(fixture.request)).rejects.toThrow(
      'Invalid workload certificate encoding',
    );

    expect(() =>
      createHttpWorkloadCredentialIssuer({
        endpoint: 'http://issuer.openpc.test/v1/certificates',
        authorizationToken: 't'.repeat(32),
        trustedCaPem: fixture.ca,
      }),
    ).toThrow('requires HTTPS');
  });
});

it('defaults to readback-required uncertainty and pins local QA replay to the exact immutable request and certificate', async () => {
  const f = await certificateFixture();
  const fetch = vi.fn(
    async () =>
      new Response(JSON.stringify({ certificateDer: f.certificateDer.toString('base64') }), {
        status: 200,
      }),
  );
  const config = {
    endpoint: 'https://issuer.openpc.test/v1/certificates',
    authorizationToken: 'test-token',
    trustedCaPem: f.ca,
    fetch,
  };
  const ordinary = createHttpWorkloadCredentialIssuer(config);
  expect(ordinary.recovery?.replayProfile).toBe('READBACK_REQUIRED');
  const manifest = {
    localQaEnabled: true,
    manifestDigest: Buffer.alloc(32, 1),
    certificates: [
      {
        requestDigest: workloadCertificateRequestDigest(f.request),
        certificateFingerprint: createHash('sha256').update(f.certificateDer).digest(),
        validity: {
          validFromMs: Date.parse(new X509Certificate(f.certificateDer).validFrom),
          validUntilMs: Date.parse(new X509Certificate(f.certificateDer).validTo),
        },
      },
    ],
  };
  const issuer = createHttpWorkloadCredentialIssuer({
    ...config,
    immutableLocalManifest: manifest,
  });
  expect(issuer.recovery?.replayProfile).toBe('IMMUTABLE_REQUEST_RESPONSE');
  expect(issuer.recovery?.profileDigest).not.toEqual(ordinary.recovery?.profileDigest);
  const first = await issuer.issue(f.request),
    repeated = await issuer.issue(f.request);
  expect(repeated.certificateDer).toEqual(first.certificateDer);
  expect(
    issuer.recovery?.verifyObservation(f.request, first.certificateDer, new Date()),
  ).toBeDefined();
  expect(
    issuer.recovery?.verifyObservation(
      f.request,
      first.certificateDer,
      new Date(first.notAfter.getTime() + 1),
    ),
  ).toBeUndefined();
  const other = { ...f.request, credentialId: '018f0000-0000-7000-8000-000000000999' };
  await expect(issuer.issue(other)).rejects.toThrow();
  expect(
    issuer.recovery?.verifyObservation(other, first.certificateDer, new Date()),
  ).toBeUndefined();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(() =>
    createHttpWorkloadCredentialIssuer({
      ...config,
      immutableLocalManifest: { ...manifest, localQaEnabled: false },
    }),
  ).toThrow();
  expect(() =>
    createHttpWorkloadCredentialIssuer({
      ...config,
      immutableLocalManifest: {
        ...manifest,
        certificates: [manifest.certificates[0]!, manifest.certificates[0]!],
      },
    }),
  ).toThrow();
  const wrong = createHttpWorkloadCredentialIssuer({
    ...config,
    immutableLocalManifest: {
      ...manifest,
      certificates: [{ ...manifest.certificates[0]!, certificateFingerprint: Buffer.alloc(32, 9) }],
    },
  });
  await expect(wrong.issue(f.request)).rejects.toThrow();
  expect(
    wrong.recovery?.verifyObservation(f.request, first.certificateDer, new Date()),
  ).toBeUndefined();
});

const profileId = '018f0000-0000-7000-8000-000000000901';
const profileEndpoint = `http://issuer.openpc.test/v1/certificates/${profileId}`;
function providerEntry(
  f: Awaited<ReturnType<typeof certificateFixture>>,
  id = f.request.credentialId,
) {
  return {
    ...f.request,
    credentialId: id,
    publicKeySpkiDer: f.request.publicKeySpkiDer.toString('base64'),
    certificateDer: f.certificateDer.toString('base64'),
  };
}
function providerProfile(f: Awaited<ReturnType<typeof certificateFixture>>) {
  return {
    profileId,
    endpoint: profileEndpoint,
    trustedCaPem: f.ca.toString('utf8'),
    certificates: [providerEntry(f)],
  };
}
async function issuerJournal(manifest: unknown, observations: unknown[] = []) {
  const root = await mkdtemp(join(tmpdir(), 'openpc-issuer-journal-'));
  roots.push(root);
  const journalFile = join(root, 'claims.ndjson');
  const certificates = manifest as ReturnType<typeof providerEntry>[];
  const captureBytes = Buffer.from(
    JSON.stringify({
      schema: 'pc.local.workload-issuer-claims-capture.v1',
      sourceBundleDigest: createHash('sha256').update('isolated unit provider').digest('hex'),
      legacyManifestDigest: localWorkloadIssuerManifestDigest(manifest),
      processIdentity: 'isolated-unit-provider:' + process.pid,
      claims: (observations as { credentialId: string }[]).map((observed) => {
        const selected = certificates.find((v) => v.credentialId === observed.credentialId)!;
        return {
          credentialId: selected.credentialId,
          requestJson: JSON.stringify({
            credentialId: selected.credentialId,
            participantId: selected.participantId,
            principalId: selected.principalId,
            workloadId: selected.workloadId,
            publicKeySpkiDer: selected.publicKeySpkiDer,
          }),
        };
      }),
    }),
  );
  const originalClaimsCapture = {
    bytes: captureBytes,
    expectedDigest: createHash('sha256').update(captureBytes).digest('hex'),
  };
  await writeFile(
    journalFile,
    JSON.stringify({
      kind: 'HEADER',
      schema: 'pc.local.workload-issuer-journal.v1',
      legacyManifestDigest: localWorkloadIssuerManifestDigest(manifest),
      originalCaptureDigest: originalClaimsCapture.expectedDigest,
      observations,
    }) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  return {
    journalFile,
    originalClaimsCapture,
    journalHead: await isolatedInstallerHead(journalFile),
  };
}
// Synthetic installer setup only. A real restart must install the authenticated
// live owner's verified committed head, never trust surviving bytes as history.
async function isolatedInstallerHead(journalFile: string) {
  const stat = await lstat(journalFile, { bigint: true });
  const bytes = await readFile(journalFile);
  return {
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    owner: Number(stat.uid),
    mode: 0o600 as const,
    bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}
async function unknownIssuerFixture() {
  const old = await certificateFixture(),
    fresh = await certificateFixture();
  const manifest = [providerEntry(old), providerEntry(old, '018f0000-0000-7000-8000-000000000193')];
  const issuedId = '018f0000-0000-7000-8000-000000000999';
  const profile = { ...providerProfile(fresh), certificates: [providerEntry(fresh, issuedId)] };
  const profiles = {
    schema: 'pc.local.workload-issuer-profiles.v1',
    legacyManifestDigest: localWorkloadIssuerManifestDigest(manifest),
    profiles: [profile],
  };
  const recovery = {
    schema: 'pc.local.workload-issuer-unknown-recovery.v1',
    recoveryId: '018f0000-0000-7000-8000-000000000903',
    reason: 'ORIGINAL_PROCESS_RESTART_BEFORE_CAPTURE',
    sourceBundleDigest: createHash('sha256').update('isolated original adapter').digest('hex'),
    lostProcessIdentity: {
      containerId: 'a'.repeat(64),
      startedAt: '2026-10-03T10:00:00Z',
      hostPid: 12345,
    },
    legacyManifestDigest: profiles.legacyManifestDigest,
    profilesDigest: createHash('sha256').update(JSON.stringify(profiles)).digest('hex'),
    quarantined: manifest.map((value) => ({
      credentialId: value.credentialId,
      requestDigest: workloadCertificateRequestDigest({
        ...value,
        publicKeySpkiDer: Buffer.from(value.publicKeySpkiDer, 'base64'),
      }).toString('hex'),
      certificateFingerprint: createHash('sha256')
        .update(Buffer.from(value.certificateDer, 'base64'))
        .digest('hex'),
      outcome: 'UNKNOWN',
    })),
  };
  const bytes = Buffer.from(JSON.stringify(recovery));
  const unknownRecovery = {
    bytes,
    expectedDigest: createHash('sha256').update(bytes).digest('hex'),
  };
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_ROOT ?? tmpdir(), 'openpc-issuer-quarantine-'),
  );
  roots.push(root);
  const journalFile = join(root, 'claims.ndjson');
  await writeFile(
    journalFile,
    JSON.stringify({
      kind: 'RECOVERY_HEADER',
      schema: 'pc.local.workload-issuer-unknown-journal.v1',
      recoveryId: recovery.recoveryId,
      unknownRecoveryDigest: unknownRecovery.expectedDigest,
      legacyManifestDigest: profiles.legacyManifestDigest,
    }) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  return {
    input: {
      manifest,
      profiles,
      unknownRecovery,
      journalFile,
      journalHead: await isolatedInstallerHead(journalFile),
      localQaEnabled: true,
      token: 't'.repeat(32),
    },
    recovery,
    old,
    fresh,
    issuedId,
  };
}

function pinnedProfileExtension(profiles: unknown, added: unknown[]) {
  const bytes = Buffer.from(
    JSON.stringify({
      schema: 'pc.local.workload-issuer-profile-extension.v1',
      baseProfilesDigest: createHash('sha256').update(JSON.stringify(profiles)).digest('hex'),
      profiles: added,
    }),
  );
  return { bytes, expectedDigest: createHash('sha256').update(bytes).digest('hex') };
}
function extensionProfile(v: Awaited<ReturnType<typeof unknownIssuerFixture>>) {
  return {
    ...providerProfile(v.fresh),
    profileId: '018f0000-0000-7000-8000-000000000904',
    endpoint: 'http://issuer.openpc.test/v1/certificates/018f0000-0000-7000-8000-000000000904',
    certificates: [providerEntry(v.fresh, '018f0000-0000-7000-8000-000000000905')],
  };
}
it('adds independently pinned issuer profiles without rewriting retained quarantine, profiles or journal history', async () => {
  const v = await unknownIssuerFixture(),
    profile = extensionProfile(v);
  const originalBase = JSON.stringify(v.input.profiles),
    originalRecovery = Buffer.from(v.input.unknownRecovery.bytes);
  const base = await serveIssuer(await createLocalWorkloadIssuerFixture(v.input));
  await base.close();
  const originalJournal = await readFile(v.input.journalFile);
  const input = {
    ...v.input,
    journalHead: await isolatedInstallerHead(v.input.journalFile),
    profileExtension: pinnedProfileExtension(v.input.profiles, [profile]),
  };
  const running = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
  const request = {
    ...v.fresh.request,
    credentialId: profile.certificates[0]!.credentialId,
    publicKeySpkiDer: v.fresh.request.publicKeySpkiDer.toString('base64'),
  };
  const post = (url: string, path: string, body: unknown) =>
    fetch(url + path, {
      method: 'POST',
      headers: { 'authorization': 'Bearer ' + v.input.token, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  let head: unknown;
  try {
    const old = {
      ...v.old.request,
      publicKeySpkiDer: v.old.request.publicKeySpkiDer.toString('base64'),
    };
    expect((await post(running.url, '/v1/certificates', old)).status).toBe(409);
    expect((await post(running.url, '/v1/certificates/' + profile.profileId, request)).status).toBe(
      201,
    );
    const observation = await (
      await fetch(running.url + '/v1/observations', {
        headers: { authorization: 'Bearer ' + v.input.token },
      })
    ).json();
    expect(observation).toMatchObject({
      quarantined: v.recovery.quarantined,
      claims: [{ credentialId: request.credentialId, profileId: profile.profileId }],
    });
    head = observation.journalHead;
  } finally {
    await running.close();
  }
  const committed = await readFile(v.input.journalFile);
  expect(committed.subarray(0, originalJournal.length)).toEqual(originalJournal);
  expect(JSON.stringify(v.input.profiles)).toBe(originalBase);
  expect(v.input.unknownRecovery.bytes).toEqual(originalRecovery);
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow('head changed');
  await expect(
    createLocalWorkloadIssuerFixture({ ...input, profileExtension: undefined, journalHead: head }),
  ).rejects.toThrow('Historical issuer profile changed');
  const restarted = await serveIssuer(
    await createLocalWorkloadIssuerFixture({ ...input, journalHead: head }),
  );
  try {
    expect(
      (await post(restarted.url, '/v1/certificates/' + profile.profileId, request)).status,
    ).toBe(201);
  } finally {
    await restarted.close();
  }
  expect(await readFile(v.input.journalFile)).toEqual(committed);
});
it.each([
  'wrong SHA',
  'wrong base',
  'not QA',
  'missing custody',
  'shadow base profile',
  'shadow base credential',
  'shadow unknown credential',
  'profile equals credential',
  'duplicate extension profile',
  'cross profile credential',
  'wrong CA',
  'wrong endpoint',
  'too many profiles',
])('denies issuer profile extension %s before any journal effect', async (fault) => {
  const v = await unknownIssuerFixture(),
    profile = extensionProfile(v);
  let added = [profile],
    base = v.input.profiles;
  if (fault === 'shadow base profile') profile.profileId = profileId;
  if (fault === 'shadow base credential') profile.certificates[0]!.credentialId = v.issuedId;
  if (fault === 'shadow unknown credential')
    profile.certificates[0]!.credentialId = v.input.manifest[0]!.credentialId;
  if (fault === 'profile equals credential')
    profile.profileId = profile.certificates[0]!.credentialId;
  if (fault === 'duplicate extension profile') added = [profile, profile];
  if (fault === 'cross profile credential')
    added = [profile, { ...profile, profileId: '018f0000-0000-7000-8000-000000000906' }];
  if (fault === 'wrong CA') profile.trustedCaPem = v.old.ca.toString('utf8');
  if (fault === 'wrong endpoint') profile.endpoint += '/foreign';
  if (fault === 'wrong base') base = { ...base, legacyManifestDigest: '0'.repeat(64) };
  if (fault === 'too many profiles') added = Array.from({ length: 32 }, () => profile);
  const extension = pinnedProfileExtension(base, added);
  if (fault === 'wrong SHA') extension.expectedDigest = '0'.repeat(64);
  const input = {
    ...v.input,
    profileExtension: extension,
    ...(fault === 'not QA' ? { localQaEnabled: false } : {}),
    ...(fault === 'missing custody' ? { profiles: undefined, unknownRecovery: undefined } : {}),
  };
  const before = await readFile(v.input.journalFile);
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow();
  expect(await readFile(v.input.journalFile)).toEqual(before);
});

it('preserves lost legacy outcomes as UNKNOWN while issuing only disjoint journaled profiles across restart', async () => {
  const v = await unknownIssuerFixture();
  expect(
    readLocalWorkloadIssuerUnknownRecovery(
      v.input.unknownRecovery.bytes,
      v.input.unknownRecovery.expectedDigest,
    ),
  ).toEqual(v.recovery);
  const post = (url: string, path: string, body: unknown) =>
    fetch(url + path, {
      method: 'POST',
      headers: { 'authorization': 'Bearer ' + v.input.token, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  const request = {
    ...v.fresh.request,
    credentialId: v.issuedId,
    publicKeySpkiDer: v.fresh.request.publicKeySpkiDer.toString('base64'),
  };
  const originalRequest = {
    ...v.old.request,
    publicKeySpkiDer: v.old.request.publicKeySpkiDer.toString('base64'),
  };
  const first = await serveIssuer(await createLocalWorkloadIssuerFixture(v.input));
  let head: unknown;
  try {
    const initial = await fetch(first.url + '/v1/observations', {
      headers: { authorization: 'Bearer ' + v.input.token },
    });
    expect(await initial.json()).toMatchObject({
      claims: [],
      quarantined: v.recovery.quarantined,
      recoveryId: v.recovery.recoveryId,
    });
    const denied = await post(first.url, '/v1/certificates', originalRequest);
    expect(denied.status).toBe(409);
    expect(await denied.json()).toEqual({ outcome: 'UNKNOWN', issuance: 'QUARANTINED' });
    expect((await post(first.url, '/v1/certificates/' + profileId, originalRequest)).status).toBe(
      403,
    );
    const issued = await post(first.url, '/v1/certificates/' + profileId, request);
    expect(issued.status).toBe(201);
    expect(await issued.json()).toEqual({
      certificateDer: v.fresh.certificateDer.toString('base64'),
    });
    const observed = await (
      await fetch(first.url + '/v1/observations', {
        headers: { authorization: 'Bearer ' + v.input.token },
      })
    ).json();
    expect(observed).toMatchObject({
      quarantined: v.recovery.quarantined,
      claims: [{ credentialId: v.issuedId, profileId }],
    });
    head = observed.journalHead;
  } finally {
    await first.close();
  }
  const bytes = await readFile(v.input.journalFile);
  await expect(createLocalWorkloadIssuerFixture(v.input)).rejects.toThrow('head changed');
  const restart = await serveIssuer(
    await createLocalWorkloadIssuerFixture({ ...v.input, journalHead: head }),
  );
  try {
    const observed = await (
      await fetch(restart.url + '/v1/observations', {
        headers: { authorization: 'Bearer ' + v.input.token },
      })
    ).json();
    expect(observed).toMatchObject({
      recoveryId: v.recovery.recoveryId,
      quarantined: v.recovery.quarantined,
      claims: [{ credentialId: v.issuedId, profileId }],
      journalHead: head,
    });
    expect((await post(restart.url, '/v1/certificates', originalRequest)).status).toBe(409);
    expect((await post(restart.url, '/v1/certificates/' + profileId, request)).status).toBe(201);
  } finally {
    await restart.close();
  }
  expect(await readFile(v.input.journalFile)).toEqual(bytes);
  const records = bytes
    .toString()
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line));
  expect(records.filter((record) => record.kind === 'CLAIM')).toEqual([
    expect.objectContaining({ credentialId: v.issuedId, profileId }),
  ]);
  expect(records.some((record) => record.profileId === 'LEGACY')).toBe(false);
});

it.each([
  'missing pin',
  'not QA',
  'capture conflict',
  'missing unknown',
  'duplicate unknown',
  'changed fingerprint',
  'changed manifest',
  'changed profiles',
  'legacy overlap',
  'cross profile overlap',
  'legacy profile ID',
  'profile credential overlap',
  'original header',
  'old claim',
  'wrong journal generation',
  'wrong journal recovery digest',
  'wrong journal manifest',
  'partial journal suffix',
])('denies UNKNOWN recovery %s before becoming available', async (failure) => {
  const v = await unknownIssuerFixture();
  const input = v.input;
  const recovery = structuredClone(v.recovery);
  if (failure === 'missing pin') input.unknownRecovery.expectedDigest = '0'.repeat(64);
  if (failure === 'not QA') input.localQaEnabled = false;
  if (failure === 'capture conflict')
    Object.assign(input, {
      originalClaimsCapture: { bytes: Buffer.from('{}'), expectedDigest: '0'.repeat(64) },
    });
  if (failure === 'missing unknown') recovery.quarantined.pop();
  if (failure === 'duplicate unknown') recovery.quarantined[1] = { ...recovery.quarantined[0]! };
  if (failure === 'changed fingerprint')
    recovery.quarantined[0]!.certificateFingerprint = '0'.repeat(64);
  if (failure === 'changed manifest') recovery.legacyManifestDigest = '0'.repeat(64);
  if (failure === 'changed profiles') recovery.profilesDigest = '0'.repeat(64);
  if (failure === 'legacy overlap')
    input.profiles.profiles[0]!.certificates[0] = providerEntry(v.fresh);
  if (failure === 'cross profile overlap')
    input.profiles.profiles.push({
      ...input.profiles.profiles[0]!,
      profileId: '018f0000-0000-7000-8000-000000000902',
      endpoint: 'http://issuer.openpc.test/v1/certificates/018f0000-0000-7000-8000-000000000902',
    });
  if (failure === 'legacy profile ID') {
    input.profiles.profiles[0]!.profileId = credentialId;
    input.profiles.profiles[0]!.endpoint =
      'http://issuer.openpc.test/v1/certificates/' + credentialId;
  }
  if (failure === 'profile credential overlap')
    input.profiles.profiles[0]!.certificates[0] = providerEntry(v.fresh, profileId);
  if (
    [
      'legacy overlap',
      'cross profile overlap',
      'legacy profile ID',
      'profile credential overlap',
    ].includes(failure)
  )
    recovery.profilesDigest = createHash('sha256')
      .update(JSON.stringify(input.profiles))
      .digest('hex');
  if (!['missing pin', 'not QA', 'capture conflict'].includes(failure)) {
    const bytes = Buffer.from(JSON.stringify(recovery));
    input.unknownRecovery = {
      bytes,
      expectedDigest: createHash('sha256').update(bytes).digest('hex'),
    };
    const header = JSON.parse((await readFile(input.journalFile, 'utf8')).trim());
    header.unknownRecoveryDigest = input.unknownRecovery.expectedDigest;
    if (failure === 'wrong journal generation')
      header.recoveryId = '018f0000-0000-7000-8000-000000000904';
    if (failure === 'wrong journal recovery digest') header.unknownRecoveryDigest = '0'.repeat(64);
    if (failure === 'wrong journal manifest') header.legacyManifestDigest = '0'.repeat(64);
    let suffix = '';
    if (failure === 'partial journal suffix') suffix = '{"kind":"CLAIM"';
    if (failure === 'original header')
      Object.assign(header, {
        kind: 'HEADER',
        schema: 'pc.local.workload-issuer-journal.v1',
        originalCaptureDigest: '0'.repeat(64),
        observations: [],
      });
    if (failure === 'old claim') {
      const { credentialId, requestDigest, certificateFingerprint } = recovery.quarantined[0]!;
      const fact = { credentialId, requestDigest, certificateFingerprint };
      suffix = JSON.stringify({ kind: 'CLAIM', profileId: 'LEGACY', ...fact }) + '\n';
    }
    await writeFile(input.journalFile, JSON.stringify(header) + '\n' + suffix);
    input.journalHead = await isolatedInstallerHead(input.journalFile);
  }
  const before = await readFile(input.journalFile);
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow();
  expect(await readFile(input.journalFile)).toEqual(before);
});

it.each(['partial write', 'fsync ambiguity', 'close ambiguity'])(
  'poisons UNKNOWN issuance after %s without a response, visible claim or cold reconstruction',
  async (mode) => {
    const v = await unknownIssuerFixture();
    const running = await serveIssuer(await createLocalWorkloadIssuerFixture(v.input));
    const headers = {
      'authorization': 'Bearer ' + v.input.token,
      'content-type': 'application/json',
    };
    const observed = await (await fetch(running.url + '/v1/observations', { headers })).json();
    const before = await readFile(v.input.journalFile);
    journalFault.path = v.input.journalFile;
    journalFault.mode = mode;
    journalFault.calls = 0;
    const post = () =>
      fetch(running.url + '/v1/certificates/' + profileId, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ...v.fresh.request,
          credentialId: v.issuedId,
          publicKeySpkiDer: v.fresh.request.publicKeySpkiDer.toString('base64'),
        }),
      });
    try {
      expect((await post()).status).toBe(503);
      expect(journalFault.calls).toBe(1);
      expect((await post()).status).toBe(503);
      expect(journalFault.calls).toBe(1);
      const unavailable = await fetch(running.url + '/v1/observations', { headers });
      expect(unavailable.status).toBe(503);
      expect(await unavailable.json()).toEqual({ status: 'unavailable', durable: false });
    } finally {
      journalFault.path = '';
      journalFault.mode = '';
      await running.close();
    }
    const failed = await readFile(v.input.journalFile);
    expect(failed.length).toBeGreaterThan(before.length);
    expect(failed.subarray(0, before.length)).toEqual(before);
    // The last independently observed head precedes the ambiguous write. Never
    // manufacture a replacement pin from the surviving file to declare success.
    await expect(
      createLocalWorkloadIssuerFixture({ ...v.input, journalHead: observed.journalHead }),
    ).rejects.toThrow('head changed');
    expect(await readFile(v.input.journalFile)).toEqual(failed);
  },
);
async function serveIssuer(server: Awaited<ReturnType<typeof createLocalWorkloadIssuerFixture>>) {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture server unavailable');
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

it('qualifies only installed immutable endpoint, CA, request and DER inputs', async () => {
  const f = await certificateFixture(),
    g = await certificateFixture();
  const bytes = Buffer.from(JSON.stringify(providerProfile(f))),
    expectedDigest = createHash('sha256').update(bytes).digest('hex');
  const config = {
    bytes,
    expectedDigest,
    endpoint: profileEndpoint,
    trustedCaPem: f.ca,
    localQaEnabled: true,
  };
  const manifest = readImmutableLocalWorkloadIssuerProfile(config);
  const issuer = createHttpWorkloadCredentialIssuer({
    endpoint: profileEndpoint,
    authorizationToken: 't'.repeat(32),
    trustedCaPem: f.ca,
    allowInsecureHttp: true,
    immutableLocalManifest: manifest,
  });
  expect(issuer.recovery?.replayProfile).toBe('IMMUTABLE_REQUEST_RESPONSE');
  expect(issuer.recovery?.verifyObservation(f.request, f.certificateDer, new Date())).toBeDefined();
  for (const change of [
    { localQaEnabled: false },
    { expectedDigest: '0'.repeat(64) },
    { endpoint: 'http://issuer.openpc.test/v1/certificates' },
    { trustedCaPem: g.ca },
    { now: new Date(Date.parse(new X509Certificate(f.certificateDer).validTo) + 1) },
  ])
    expect(() => readImmutableLocalWorkloadIssuerProfile({ ...config, ...change })).toThrow();
  const bad = {
    ...providerProfile(f),
    certificates: [
      { ...providerEntry(f), publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64') },
    ],
  };
  const badBytes = Buffer.from(JSON.stringify(bad));
  expect(() =>
    readImmutableLocalWorkloadIssuerProfile({
      ...config,
      bytes: badBytes,
      expectedDigest: createHash('sha256').update(badBytes).digest('hex'),
    }),
  ).toThrow();
});

it('preserves exact legacy and new provider claims through journaled restart without profile shadowing', async () => {
  const f = await certificateFixture(),
    g = await certificateFixture();
  const legacy = [providerEntry(f)],
    profile = providerProfile(g);
  const profiles = {
    schema: 'pc.local.workload-issuer-profiles.v1',
    legacyManifestDigest: localWorkloadIssuerManifestDigest(legacy),
    profiles: [profile],
  };
  const { journalFile, originalClaimsCapture, journalHead } = await issuerJournal(legacy),
    token = 't'.repeat(32);
  const input = {
    manifest: legacy,
    profiles,
    journalFile,
    journalHead,
    originalClaimsCapture,
    token,
    localQaEnabled: true,
  };
  const bytes = Buffer.from(JSON.stringify(profiles));
  expect(
    readLocalWorkloadIssuerProfiles(bytes, createHash('sha256').update(bytes).digest('hex')),
  ).toEqual(profiles);
  expect(() => readLocalWorkloadIssuerProfiles(bytes, '0'.repeat(64))).toThrow();
  const request = { ...g.request, publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64') };
  const post = async (
    url: string,
    path: string,
    body: unknown,
    authorization = `Bearer ${token}`,
  ) =>
    fetch(url + path, {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  const first = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
  let installedRestartHead: unknown;
  try {
    expect(
      (await post(first.url, `/v1/certificates/${profileId}`, request, 'Bearer wrong')).status,
    ).toBe(403);
    expect((await post(first.url, '/' + profileId, request)).status).toBe(403);
    expect(
      (
        await post(first.url, `/v1/certificates/${profileId}`, {
          ...request,
          participantId: '018f0000-0000-7000-8000-000000000999',
        })
      ).status,
    ).toBe(403);
    const issued = await post(first.url, `/v1/certificates/${profileId}`, request);
    expect(issued.status).toBe(201);
    expect(await issued.json()).toEqual({ certificateDer: g.certificateDer.toString('base64') });
    expect(
      (
        await post(first.url, '/v1/certificates', {
          ...f.request,
          publicKeySpkiDer: f.request.publicKeySpkiDer.toString('base64'),
        })
      ).status,
    ).toBe(409);
    const observed = await fetch(first.url + '/v1/observations', {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(observed.status).toBe(200);
    installedRestartHead = (await observed.json()).journalHead;
  } finally {
    await first.close();
  }
  const original = await readFile(journalFile, 'utf8');
  expect(original.split('\n').filter((v) => v.includes('"kind":"CLAIM"'))).toHaveLength(1);
  const restartInput = { ...input, journalHead: installedRestartHead };
  // A stale installation pin cannot silently accept a newly committed suffix.
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow('head changed');
  const restarted = await serveIssuer(await createLocalWorkloadIssuerFixture(restartInput));
  try {
    const replay = await post(restarted.url, `/v1/certificates/${profileId}`, request);
    expect(replay.status).toBe(201);
    expect(await replay.json()).toEqual({ certificateDer: g.certificateDer.toString('base64') });
    const observed = await fetch(restarted.url + '/v1/observations', {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(observed.status).toBe(200);
    expect(await observed.json()).toMatchObject({
      durable: true,
      claims: [{ credentialId, profileId }],
    });
  } finally {
    await restarted.close();
  }
  expect(await readFile(journalFile, 'utf8')).toBe(original);
  await expect(
    createLocalWorkloadIssuerFixture({
      ...restartInput,
      profiles: {
        ...profiles,
        profiles: [
          {
            ...profile,
            endpoint: profile.endpoint.replace('issuer.openpc.test', 'changed-issuer.openpc.test'),
          },
        ],
      },
    }),
  ).rejects.toThrow('Historical issuer profile changed');
  await writeFile(journalFile, original + '{"partial":');
  await expect(createLocalWorkloadIssuerFixture(restartInput)).rejects.toThrow('head changed');
});

it('retains reconciled legacy observations and rejects missing, foreign or unqualified journal/profile inputs', async () => {
  const f = await certificateFixture(),
    g = await certificateFixture(),
    legacy = [providerEntry(f)];
  const observed = {
    credentialId,
    requestDigest: workloadCertificateRequestDigest(f.request).toString('hex'),
    certificateFingerprint: createHash('sha256').update(f.certificateDer).digest('hex'),
  };
  const { journalFile, originalClaimsCapture, journalHead } = await issuerJournal(legacy, [
    observed,
  ]);
  const profile = providerProfile(g),
    profiles = {
      schema: 'pc.local.workload-issuer-profiles.v1',
      legacyManifestDigest: localWorkloadIssuerManifestDigest(legacy),
      profiles: [profile],
    };
  const input = {
    manifest: legacy,
    profiles,
    journalFile,
    journalHead,
    originalClaimsCapture,
    token: 't'.repeat(32),
    localQaEnabled: true,
  };
  await expect(
    createLocalWorkloadIssuerFixture({ ...input, localQaEnabled: false }),
  ).rejects.toThrow();
  await expect(
    createLocalWorkloadIssuerFixture({ ...input, journalHead: undefined }),
  ).rejects.toThrow();
  await expect(
    createLocalWorkloadIssuerFixture({
      ...input,
      journalHead: { ...journalHead, owner: journalHead.owner + 1 },
    }),
  ).rejects.toThrow('head changed');
  await expect(
    createLocalWorkloadIssuerFixture({ ...input, journalFile: journalFile + '.missing' }),
  ).rejects.toMatchObject({ code: 'ENOENT' });
  await expect(
    createLocalWorkloadIssuerFixture({
      ...input,
      profiles: { ...profiles, profiles: [{ ...profile, trustedCaPem: f.ca.toString('utf8') }] },
    }),
  ).rejects.toThrow('Invalid issuer profile certificate');
  const running = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
  try {
    const result = await fetch(running.url + `/v1/certificates/${profileId}`, {
      method: 'POST',
      headers: { 'authorization': `Bearer ${input.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        ...g.request,
        publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64'),
      }),
    });
    expect(result.status).toBe(409);
    expect((await readFile(journalFile, 'utf8')).includes('"kind":"CLAIM"')).toBe(false);
  } finally {
    await running.close();
  }
  const header = JSON.parse((await readFile(journalFile, 'utf8')).split('\n')[0]!);
  header.observations[0].certificateFingerprint = '0'.repeat(64);
  await writeFile(journalFile, JSON.stringify(header) + '\n');
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow(
    'committed contents changed',
  );
});

it('does not recreate a missing journal or acknowledge issuance after durable I/O failure', async () => {
  const f = await certificateFixture(),
    g = await certificateFixture(),
    legacy = [providerEntry(f)];
  const { journalFile, originalClaimsCapture, journalHead } = await issuerJournal(legacy);
  const profiles = {
    schema: 'pc.local.workload-issuer-profiles.v1',
    legacyManifestDigest: localWorkloadIssuerManifestDigest(legacy),
    profiles: [providerProfile(g)],
  };
  const input = {
    manifest: legacy,
    profiles,
    journalFile,
    journalHead,
    originalClaimsCapture,
    token: 't'.repeat(32),
    localQaEnabled: true,
  };
  const first = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
  const original = await readFile(journalFile, 'utf8');
  const issue = (url: string) =>
    fetch(url + `/v1/certificates/${profileId}`, {
      method: 'POST',
      headers: { 'authorization': `Bearer ${input.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        ...g.request,
        publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64'),
      }),
    });
  try {
    await rm(journalFile);
    expect((await issue(first.url)).status).toBe(503);
    await expect(readFile(journalFile)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await fetch(first.url + '/healthz')).status).toBe(503);
    await writeFile(journalFile, original, { flag: 'wx', mode: 0o600 });
    expect((await issue(first.url)).status).toBe(503);
    expect(await readFile(journalFile, 'utf8')).toBe(original);
  } finally {
    await first.close();
  }
  await expect(createLocalWorkloadIssuerFixture(input)).rejects.toThrow('head changed');
  expect(
    (await readFile(journalFile, 'utf8')).split('\n').filter((v) => v.includes('"kind":"CLAIM"')),
  ).toHaveLength(0);
});

it.each([
  'unlink',
  'replacement',
  'symlink',
  'hardlink',
  'mode',
  'empty',
  'header-only',
  'last-complete-claim',
  'same-size-content',
] as const)(
  'fails replay, readback and cold reconstruction permanently after committed journal %s drift',
  async (drift) => {
    const f = await certificateFixture(),
      g = await certificateFixture(),
      legacy = [providerEntry(f)];
    const original = await issuerJournal(legacy);
    const input = {
      ...original,
      manifest: legacy,
      token: 't'.repeat(32),
      localQaEnabled: true,
      profiles: {
        schema: 'pc.local.workload-issuer-profiles.v1',
        legacyManifestDigest: localWorkloadIssuerManifestDigest(legacy),
        profiles: [providerProfile(g)],
      },
    };
    const running = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
    const issue = () =>
      fetch(running.url + `/v1/certificates/${profileId}`, {
        method: 'POST',
        headers: { 'authorization': `Bearer ${input.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          ...g.request,
          publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64'),
        }),
      });
    const readback = () =>
      fetch(running.url + '/v1/observations', {
        headers: { authorization: `Bearer ${input.token}` },
      });
    try {
      expect((await issue()).status).toBe(201);
      const observed = await readback();
      expect(observed.status).toBe(200);
      const committed = await observed.json();
      expect(committed.durable).toBe(true);
      const restart = { ...input, journalHead: committed.journalHead };
      const bytes = await readFile(original.journalFile),
        backup = original.journalFile + '.original';
      if (drift === 'unlink') await rm(original.journalFile);
      else if (drift === 'replacement' || drift === 'symlink') {
        await rename(original.journalFile, backup);
        if (drift === 'replacement')
          await writeFile(original.journalFile, bytes, { mode: 0o600, flag: 'wx' });
        else await symlink(backup, original.journalFile);
      } else if (drift === 'hardlink') await link(original.journalFile, backup);
      else if (drift === 'mode') await chmod(original.journalFile, 0o400);
      else if (drift === 'same-size-content') {
        const corrupt = Buffer.from(bytes);
        corrupt[20] = corrupt[20] === 32 ? 33 : 32;
        await writeFile(original.journalFile, corrupt);
      } else {
        const lines = bytes.toString().trimEnd().split('\n');
        await writeFile(
          original.journalFile,
          drift === 'empty'
            ? ''
            : (drift === 'header-only' ? lines.slice(0, 1) : lines.slice(0, -1)).join('\n') + '\n',
        );
      }
      expect((await issue()).status).toBe(503);
      const denied = await readback();
      expect(denied.status).toBe(503);
      expect(await denied.json()).toEqual({ status: 'unavailable', durable: false });
      expect((await fetch(running.url + '/healthz')).status).toBe(503);
      await expect(createLocalWorkloadIssuerFixture(restart)).rejects.toThrow();
      // Even exact restoration cannot unpoison the warm instance or acknowledge
      // a claim after the independently pinned durability boundary was lost.
      if (drift === 'symlink') {
        await rm(original.journalFile);
        await rename(backup, original.journalFile);
      } else if (drift === 'replacement') {
        await rm(original.journalFile);
        await rename(backup, original.journalFile);
      } else if (drift === 'hardlink') await rm(backup);
      else if (drift === 'unlink')
        await writeFile(original.journalFile, bytes, { mode: 0o600, flag: 'wx' });
      else {
        await chmod(original.journalFile, 0o600);
        await writeFile(original.journalFile, bytes);
      }
      expect((await issue()).status).toBe(503);
      expect(await readFile(original.journalFile)).toEqual(bytes);
    } finally {
      await running.close();
    }
  },
);

const inspectorErrorCodes = [
  'ERR_INSPECTOR_NOT_ACTIVE',
  'ERR_INSPECTOR_NOT_AVAILABLE',
  'ERR_INSPECTOR_NOT_CONNECTED',
  'ERR_INSPECTOR_ALREADY_ACTIVATED',
  'ERR_INSPECTOR_CLOSED',
  'ERR_INSPECTOR_COMMAND',
  'ERR_HTTP_HEADERS_SENT',
  'ERR_STREAM_WRITE_AFTER_END',
  'ERR_STREAM_DESTROYED',
  'ERR_UNHANDLED_ERROR',
  'ERR_INVALID_ARG_TYPE',
] as const;
function redactedInspectorErrors(bytes: Buffer) {
  const text = bytes.toString();
  const tokens = new Set(text.match(/\bERR_[A-Z0-9_]+\b/gu) ?? []);
  return {
    errorCodes: inspectorErrorCodes.filter((code) => tokens.has(code)),
    unknownErrorCode: [...tokens].some(
      (code) => !inspectorErrorCodes.some((known) => code === known),
    ),
    errorKinds: ['ReferenceError', 'TypeError', 'SyntaxError', 'AssertionError'].filter((kind) =>
      text.includes(kind),
    ),
  };
}
it('keeps inspector exit diagnostics byte-bounded and redacts unknown error tokens', () => {
  const secret = 'ERR_PRIVATE_CAUSE_SENTINEL';
  const long = 'ERR_' + 'A'.repeat(20000);
  const diagnostic = redactedInspectorErrors(
    Buffer.from(`${secret} ${long} ERR_INSPECTOR_CLOSED TypeError`),
  );
  const wire = JSON.stringify(diagnostic);
  expect(diagnostic).toEqual({
    errorCodes: ['ERR_INSPECTOR_CLOSED'],
    unknownErrorCode: true,
    errorKinds: ['TypeError'],
  });
  expect(wire).not.toContain(secret);
  expect(wire).not.toContain(long);
  expect(Buffer.byteLength(wire)).toBeLessThan(1024);
});

async function inspectorFixture(
  manifest: ReturnType<typeof providerEntry>[],
  claims: [string, string][],
) {
  const root = await mkdtemp(join(tmpdir(), 'openpc-issuer-inspector-unit-'));
  roots.push(root);
  const probe = netServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const address = probe.address();
  if (!address || typeof address === 'string') throw new Error('No isolated port');
  const inspectorPort = address.port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const script = join(root, 'original.mjs');
  const source = `import { createServer } from 'node:http';
const privateSentinel='DO_NOT_EXPORT_OTHER_SCOPE';
const manifest=${JSON.stringify(manifest)};
const claims=new Map(${JSON.stringify(claims)});
const server=createServer((request,response)=>{
  if (request.method === "GET" && request.url === "/healthz") {
    response.writeHead(200).end('ok'); return;
  }
  response.writeHead(403).end(JSON.stringify({size:claims.size,configured:manifest.length}));
});
server.listen(0,'127.0.0.1',()=>process.stdout.write(JSON.stringify({port:server.address().port})+'\\n'));
`;
  await writeFile(script, source, { mode: 0o600, flag: 'wx' });
  const child = spawn(process.execPath, [`--inspect-port=127.0.0.1:${inspectorPort}`, script], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errors = Buffer.alloc(0);
  let stderrBytesSeen = 0;
  let stderrOverflow = false;
  let eventOrder = 0;
  let cleanupRequested: number | null = null;
  let terminal: { code: number | null; signal: NodeJS.Signals | null; order: number } | null = null;
  const terminationRequests: {
    owner: 'stderr-bound' | 'fixture-cleanup';
    order: number;
    accepted: boolean;
  }[] = [];
  const requestTermination = (owner: 'stderr-bound' | 'fixture-cleanup') => {
    if (terminationRequests.some((request) => request.owner === owner)) return;
    const order = ++eventOrder;
    terminationRequests.push({ owner, order, accepted: child.kill('SIGTERM') });
  };
  child.stderr.on('data', (chunk) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    stderrBytesSeen = Math.min(Number.MAX_SAFE_INTEGER, stderrBytesSeen + bytes.length);
    const remaining = 16384 - errors.length;
    if (remaining > 0) errors = Buffer.concat([errors, bytes.subarray(0, remaining)]);
    if (stderrBytesSeen > 16384 && !stderrOverflow) {
      stderrOverflow = true;
      requestTermination('stderr-bound');
    }
  });
  child.on('exit', (code, signal) => {
    terminal = { code, signal, order: ++eventOrder };
  });
  const exitDiagnostic = () => {
    const wire = JSON.stringify({
      terminal,
      cleanupRequested,
      terminationRequests,
      stderrBytesSeen,
      stderrRetainedBytes: errors.length,
      stderrOverflow,
      ...redactedInspectorErrors(errors),
    });
    expect(Buffer.byteLength(wire)).toBeLessThan(1024);
    return wire;
  };
  const port = await new Promise<number>((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('Isolated issuer startup timeout')), 3000);
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      if (output.includes('\n')) {
        clearTimeout(timer);
        resolve(JSON.parse(output.trim()).port);
      }
    });
    child.once('error', reject);
    child.once('exit', () => {
      clearTimeout(timer);
      reject(new Error('Isolated issuer exited'));
    });
  });
  const input = {
    pid: child.pid!,
    startTicks: await issuerProcessStartTicks(child.pid!),
    scriptUrl: pathToFileURL(script).href,
    scriptDigest: createHash('sha256').update(source).digest('hex'),
    manifest,
    inspectorPort,
    issuerPort: port,
  };
  const close = async () => {
    cleanupRequested ??= ++eventOrder;
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      // Only this disposable mock child can receive SIGKILL. A bounded teardown
      // keeps the original failed capture predicate visible if SIGTERM stalls.
      const timer = setTimeout(() => child.kill('SIGKILL'), 1500);
      child.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
      requestTermination('fixture-cleanup');
    });
  };
  return { input, child, close, exitDiagnostic, stderrText: () => errors.toString() };
}
async function captureFixtureClaims(
  fixture: Awaited<ReturnType<typeof inspectorFixture>>,
  options?: Parameters<typeof captureOwnedLocalIssuerClaims>[1],
) {
  try {
    return await captureOwnedLocalIssuerClaims(fixture.input, options);
  } catch (error) {
    if (error instanceof LocalIssuerCaptureFailure)
      Object.defineProperty(error, 'unitExitDiagnostic', {
        value: fixture.exitDiagnostic(),
        enumerable: true,
      });
    throw error;
  }
}
async function assertInspectorClosed(fixture: Awaited<ReturnType<typeof inspectorFixture>>) {
  const refused = await new Promise<boolean>((resolve) => {
    const socket = connect({ host: '127.0.0.1', port: fixture.input.inspectorPort });
    socket.once('connect', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', (error: NodeJS.ErrnoException) => resolve(error.code === 'ECONNREFUSED'));
    socket.setTimeout(300, () => {
      socket.destroy();
      resolve(false);
    });
  });
  expect(refused).toBe(true);
  expect(fixture.child.exitCode, fixture.exitDiagnostic()).toBeNull();
  expect(await issuerProcessStartTicks(fixture.input.pid)).toBe(fixture.input.startTicks);
  expect(
    (
      await fetch(`http://127.0.0.1:${fixture.input.issuerPort}/healthz`, {
        signal: AbortSignal.timeout(1000),
      })
    ).status,
  ).toBe(200);
}

it('captures zero, subset and full original lexical claim maps and closes the inspector without exporting other scope', async () => {
  const f = await certificateFixture();
  const manifest = Array.from({ length: 7 }, (_, i) =>
    providerEntry(f, `018f0000-0000-7000-8000-${String(192 + i).padStart(12, '0')}`),
  );
  const entries = manifest.map(({ certificateDer, ...request }) => {
    void certificateDer;
    return [request.credentialId, JSON.stringify(request)] as [string, string];
  });
  for (const count of [0, 3, 7]) {
    const fixture = await inspectorFixture(manifest, entries.slice(0, count));
    try {
      const read = await captureFixtureClaims(fixture);
      expect(read.capture.claims).toEqual(
        entries
          .slice(0, count)
          .map(([credentialId, requestJson]) => ({ credentialId, requestJson })),
      );
      expect(read.diagnostic).toMatchObject({
        listenerClosed: true,
        originalProcessUnchanged: true,
      });
      expect(JSON.stringify(read)).not.toContain('DO_NOT_EXPORT_OTHER_SCOPE');
      expect(fixture.child.exitCode).toBeNull();
      await assertInspectorClosed(fixture);
      expect((await fetch(`http://127.0.0.1:${fixture.input.issuerPort}/healthz`)).status).toBe(
        200,
      );
    } finally {
      await fixture.close();
    }
  }
}, 30_000);

it('denies target drift and unknown original claims while preserving the original HTTP process and closing diagnostics', async () => {
  const f = await certificateFixture(),
    manifest = [providerEntry(f)];
  const fixture = await inspectorFixture(manifest, [
    ['018f0000-0000-7000-8000-000000000999', 'unknown'],
  ]);
  try {
    await expect(
      captureOwnedLocalIssuerClaims({ ...fixture.input, startTicks: '0' }),
    ).rejects.toThrow();
    await expect(captureFixtureClaims(fixture)).rejects.toThrow('ORIGINAL_ISSUER_CAPTURE_FAILED');
    expect(fixture.child.exitCode, fixture.exitDiagnostic()).toBeNull();
    const finalHealth = await fetch(`http://127.0.0.1:${fixture.input.issuerPort}/healthz`).catch(
      () => {
        throw new Error('ISOLATED_ISSUER_HEALTH_FAILED|' + fixture.exitDiagnostic());
      },
    );
    expect(finalHealth.status).toBe(200);
    await assertInspectorClosed(fixture);
  } finally {
    await fixture.close();
  }
});

it.each([
  'after-signal',
  'after-discovery',
  'after-connect',
  'after-identity',
  'after-breakpoint',
  'paused',
  'after-map',
] as const)(
  'closes the original owned inspector and preserves HTTP after capture phase %s fails',
  async (fault) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    try {
      const failure = await captureFixtureClaims(fixture, {
        onPhase: (phase) => {
          if (phase === fault) throw new Error('ISOLATED_PHASE_FAULT');
        },
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
      expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
        capturePhase: fault,
        listener: 'closed',
        originalProcess: 'verified',
      });
      await assertInspectorClosed(fixture);
    } finally {
      await fixture.close();
    }
  },
  30000,
);

it.each(['cleanup-resume', 'cleanup-remove', 'cleanup-disable', 'cleanup-close'] as const)(
  'independently closes the original inspector after one %s step fails',
  async (fault) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    let injected = false;
    try {
      const read = await captureFixtureClaims(fixture, {
        onPhase: (phase) => {
          if (phase === fault && !injected) {
            injected = true;
            throw new Error('ISOLATED_CLEANUP_FAULT');
          }
        },
      });
      expect(injected).toBe(true);
      expect(read.diagnostic.cleanupReplyLost).toBe(true);
      await assertInspectorClosed(fixture);
    } finally {
      await fixture.close();
    }
  },
  30000,
);

it('cleans up cancellation while paused and rejects a wrong configured port before signaling', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  try {
    await expect(
      captureOwnedLocalIssuerClaims({
        ...fixture.input,
        inspectorPort:
          fixture.input.inspectorPort === 65535 ? 65534 : fixture.input.inspectorPort + 1,
      }),
    ).rejects.toThrow();
    await assertInspectorClosed(fixture);
    const controller = new AbortController();
    await expect(
      captureFixtureClaims(fixture, {
        signal: controller.signal,
        onPhase: (phase) => {
          if (phase === 'paused') controller.abort();
        },
      }),
    ).rejects.toThrow('ORIGINAL_ISSUER_CAPTURE_FAILED');
    await assertInspectorClosed(fixture);
  } finally {
    await fixture.close();
  }
});

it.each(['malformed', 'disconnect', 'timeout', 'lost-close-reply'] as const)(
  'cleans up controlled inspector %s failure without exporting private causes',
  async (fault) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    const send = WebSocket.prototype.send;
    let injected = false;
    const spy = vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
      this: WebSocket,
      data,
    ) {
      const command = JSON.parse(String(data));
      const selected =
        fault === 'lost-close-reply'
          ? command.method === 'Runtime.evaluate' &&
            command.params.expression.includes('node:inspector')
          : command.method === 'Debugger.getScriptSource';
      if (!injected && selected) {
        injected = true;
        if (fault === 'malformed')
          this.dispatchEvent(new MessageEvent('message', { data: '{PRIVATE_CAUSE_SENTINEL' }));
        else if (fault === 'disconnect') this.close();
        else if (fault === 'lost-close-reply') {
          send.call(this, data);
          this.close();
        }
        return;
      }
      send.call(this, data);
    });
    try {
      if (fault === 'lost-close-reply')
        await expect(captureFixtureClaims(fixture)).resolves.toMatchObject({
          diagnostic: { listenerClosed: true },
        });
      else {
        const failure = await captureFixtureClaims(fixture).catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toBe('ORIGINAL_ISSUER_CAPTURE_FAILED');
        expect((failure as Error).cause).toBeUndefined();
      }
      expect(injected).toBe(true);
      await assertInspectorClosed(fixture);
    } finally {
      spy.mockRestore();
      await fixture.close();
    }
  },
  30000,
);

it.each([false, true])(
  'denies a same-size journal mutation during read, including restoration=%s',
  async (restore) => {
    const f = await certificateFixture(),
      g = await certificateFixture(),
      legacy = [providerEntry(f)];
    const original = await issuerJournal(legacy);
    let armed = false;
    const input = {
      ...original,
      manifest: legacy,
      token: 't'.repeat(32),
      localQaEnabled: true,
      profiles: {
        schema: 'pc.local.workload-issuer-profiles.v1',
        legacyManifestDigest: localWorkloadIssuerManifestDigest(legacy),
        profiles: [providerProfile(g)],
      },
      afterJournalRead: async () => {
        if (!armed) return;
        armed = false;
        const bytes = await readFile(original.journalFile),
          changed = Buffer.from(bytes);
        changed[20] = changed[20] === 32 ? 33 : 32;
        await writeFile(original.journalFile, changed);
        if (restore) await writeFile(original.journalFile, bytes);
      },
    };
    const running = await serveIssuer(await createLocalWorkloadIssuerFixture(input));
    const issue = () =>
      fetch(running.url + `/v1/certificates/${profileId}`, {
        method: 'POST',
        headers: { 'authorization': `Bearer ${input.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          ...g.request,
          publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64'),
        }),
      });
    try {
      expect((await issue()).status).toBe(201);
      armed = true;
      expect((await issue()).status).toBe(503);
      const observation = await fetch(running.url + '/v1/observations', {
        headers: { authorization: `Bearer ${input.token}` },
      });
      expect(observation.status).toBe(503);
      expect(await observation.json()).toEqual({ status: 'unavailable', durable: false });
      expect(
        (await readFile(original.journalFile, 'utf8'))
          .split('\n')
          .filter((line) => line.includes('"kind":"CLAIM"')),
      ).toHaveLength(1);
    } finally {
      await running.close();
    }
  },
);

it.each(['constructor', 'connect-error'] as const)(
  'cleans up inspector %s before protocol assignment',
  async (fault) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    const OriginalWebSocket = WebSocket;
    let injected = false;
    class FaultSocket extends OriginalWebSocket {
      constructor(url: string | URL, protocols?: string | string[]) {
        if (!injected && fault === 'constructor') {
          injected = true;
          throw new Error('ISOLATED_CONNECT_FAULT');
        }
        super(url, protocols);
        if (!injected && fault === 'connect-error') {
          injected = true;
          queueMicrotask(() => this.dispatchEvent(new Event('error')));
        }
      }
    }
    vi.stubGlobal('WebSocket', FaultSocket);
    try {
      await expect(captureFixtureClaims(fixture)).rejects.toThrow('ORIGINAL_ISSUER_CAPTURE_FAILED');
      expect(injected).toBe(true);
      await assertInspectorClosed(fixture);
    } finally {
      vi.unstubAllGlobals();
      await fixture.close();
    }
  },
  30000,
);

it('denies an occupied foreign diagnostic endpoint before signaling or closing the foreign listener', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const foreign = netServer();
  await new Promise<void>((resolve) =>
    foreign.listen(fixture.input.inspectorPort, '127.0.0.1', resolve),
  );
  try {
    await expect(captureFixtureClaims(fixture)).rejects.toThrow('ORIGINAL_ISSUER_CAPTURE_FAILED');
    expect(foreign.listening).toBe(true);
    expect(await issuerProcessStartTicks(fixture.input.pid)).toBe(fixture.input.startTicks);
    expect((await fetch(`http://127.0.0.1:${fixture.input.issuerPort}/healthz`)).status).toBe(200);
  } finally {
    await new Promise<void>((resolve) => foreign.close(() => resolve()));
    await assertInspectorClosed(fixture);
    await fixture.close();
  }
});

it('preflights the exact original process and owned HTTP socket without signaling', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  let foreignRequests = 0;
  const foreign = httpServer((_request, response) => {
    foreignRequests++;
    response.writeHead(200).end('ok');
  });
  await new Promise<void>((resolve) => foreign.listen(0, '127.0.0.1', resolve));
  const address = foreign.address();
  if (!address || typeof address === 'string') throw new Error('No isolated HTTP port');
  try {
    const ready = await preflightOwnedLocalIssuerClaims(fixture.input);
    expect(ready.pid).toBe(fixture.input.pid);
    expect(ready.startTicks).toBe(fixture.input.startTicks);
    expect(ready.scriptDigest).toBe(fixture.input.scriptDigest);
    await expect(
      preflightOwnedLocalIssuerClaims({ ...fixture.input, issuerPort: address.port }),
    ).rejects.toBeInstanceOf(LocalIssuerCaptureFailure);
    expect(foreignRequests).toBe(0);
    expect(fixture.stderrText()).not.toContain('Debugger listening');
    await assertInspectorClosed(fixture);
  } finally {
    await new Promise<void>((resolve) => foreign.close(() => resolve()));
    await fixture.close();
  }
}, 30000);

it('reconnects to the same original inspector after transport fails with a paused HTTP response', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const send = WebSocket.prototype.send;
  const originalFetch = globalThis.fetch;
  let pendingHealthResponses = 0;
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((request, init) => {
    if (String(request) !== `http://127.0.0.1:${fixture.input.issuerPort}/healthz`)
      return originalFetch(request, init);
    pendingHealthResponses++;
    return originalFetch(request, init)
      .then(async (response) => {
        await response.clone().arrayBuffer();
        return response;
      })
      .finally(() => {
        pendingHealthResponses--;
      });
  });
  let injected = false;
  const spy = vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
    this: WebSocket,
    data,
  ) {
    const command = JSON.parse(String(data));
    if (!injected && command.method === 'Debugger.evaluateOnCallFrame') {
      injected = true;
      this.close();
      return;
    }
    send.call(this, data);
  });
  try {
    const failure = await captureFixtureClaims(fixture).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'paused',
      listener: 'closed',
      originalProcess: 'verified',
    });
    expect(injected).toBe(true);
    expect(pendingHealthResponses).toBe(0);
    await assertInspectorClosed(fixture);
  } finally {
    spy.mockRestore();
    fetchSpy.mockRestore();
    await fixture.close();
  }
}, 30000);

it('keeps final identity-read failure inside the signaled lifecycle diagnostic', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const path = fileURLToPath(fixture.input.scriptUrl),
    before = await readFile(path);
  const phases = new Map<string, number>();
  let injected = false;
  try {
    const failure = await captureFixtureClaims(fixture, {
      onPhase: async (phase) => {
        phases.set(phase, (phases.get(phase) ?? 0) + 1);
        if (phase === 'final-identity') {
          expect(phases.get('after-map')).toBe(2);
          expect(await readFile(path)).toEqual(before);
          await assertInspectorClosed(fixture);
          injected = true;
          await writeFile(
            path,
            Buffer.concat([before, Buffer.from('\n// isolated final-read drift')]),
          );
        }
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect(injected).toBe(true);
    expect((failure as LocalIssuerCaptureFailure).failures).toEqual([
      { owner: 'final-identity', reason: 'ASSERTION' },
    ]);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'final-identity',
      listener: 'closed',
      originalProcess: 'unverified',
    });
    await assertInspectorClosed(fixture);
  } finally {
    await writeFile(path, before);
    await fixture.close();
  }
}, 30000);

it('retains the earlier capture failure when final identity also fails', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const path = fileURLToPath(fixture.input.scriptUrl),
    before = await readFile(path);
  let injected = false;
  try {
    const failure = await captureFixtureClaims(fixture, {
      onPhase: async (phase) => {
        if (phase === 'after-map') throw new Error('ISOLATED_EARLIER_CAPTURE_FAULT');
        if (phase === 'final-identity') {
          await assertInspectorClosed(fixture);
          expect(await readFile(path)).toEqual(before);
          injected = true;
          await writeFile(
            path,
            Buffer.concat([before, Buffer.from('\n// isolated combined final-read drift')]),
          );
        }
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect(injected).toBe(true);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'after-map',
      listener: 'closed',
      originalProcess: 'unverified',
    });
    expect((failure as LocalIssuerCaptureFailure).failures).toEqual([
      { owner: 'capture', reason: 'REJECTED' },
      { owner: 'final-identity', reason: 'ASSERTION' },
    ]);
    await assertInspectorClosed(fixture);
  } finally {
    await writeFile(path, before);
    await fixture.close();
  }
}, 30000);

it('preserves capture failure and original cleanup when stderr output would throw', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const privateCause = 'ERR_PRIVATE_OUTPUT_CAUSE_SENTINEL';
  const writer = vi.spyOn(process.stderr, 'write').mockImplementation(() => {
    throw new Error(privateCause);
  });
  try {
    const failure = await captureFixtureClaims(fixture, {
      onPhase: (phase) => {
        if (phase === 'after-map') throw new Error(privateCause);
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'after-map',
      listener: 'closed',
      originalProcess: 'verified',
    });
    expect((failure as LocalIssuerCaptureFailure).failures).toEqual([
      { owner: 'capture', reason: 'REJECTED' },
    ]);
    expect(JSON.stringify(failure)).not.toContain(privateCause);
    expect((failure as Error).message).not.toContain(privateCause);
    expect(writer).not.toHaveBeenCalled();
    await assertInspectorClosed(fixture);
  } finally {
    writer.mockRestore();
    await fixture.close();
  }
}, 30000);

it.each(Array.from({ length: 8 }, (_, index) => index))(
  'avoids competing client close during native inspector shutdown %s',
  async () => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    const send = WebSocket.prototype.send,
      close = WebSocket.prototype.close;
    let nativeCloseSent = false,
      competingCloses = 0;
    const sendSpy = vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
      this: WebSocket,
      data,
    ) {
      const command = JSON.parse(String(data));
      if (
        command.method === 'Runtime.evaluate' &&
        command.params?.expression ===
          'void setImmediate(()=>process.getBuiltinModule("node:inspector").close())'
      )
        nativeCloseSent = true;
      send.call(this, data);
    });
    const closeSpy = vi.spyOn(WebSocket.prototype, 'close').mockImplementation(function (
      this: WebSocket,
      ...args
    ) {
      if (nativeCloseSent) competingCloses++;
      close.apply(this, args);
    });
    try {
      const failure = await captureFixtureClaims(fixture, {
        onPhase: (phase) => {
          if (phase === 'after-breakpoint') throw new Error('ISOLATED_SHUTDOWN_BOUNDARY_FAULT');
        },
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
      expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
        capturePhase: 'after-breakpoint',
        listener: 'closed',
        originalProcess: 'verified',
      });
      expect(nativeCloseSent).toBe(true);
      expect(competingCloses).toBe(0);
      await assertInspectorClosed(fixture);
    } finally {
      sendSpy.mockRestore();
      closeSpy.mockRestore();
      await fixture.close();
    }
  },
  30000,
);

it('disposes the request timer when an inspector send throws synchronously', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  const send = WebSocket.prototype.send;
  const timers = vi.spyOn(globalThis, 'setTimeout'),
    clears = vi.spyOn(globalThis, 'clearTimeout');
  let injected = false;
  let requestTimer: ReturnType<typeof setTimeout> | undefined;
  const writer = vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
    this: WebSocket,
    data,
  ) {
    if (!injected) {
      injected = true;
      requestTimer = timers.mock.results.at(-1)?.value;
      throw new Error('ERR_PRIVATE_SEND_CAUSE_SENTINEL');
    }
    send.call(this, data);
  });
  try {
    const failure = await captureFixtureClaims(fixture).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'after-connect',
      listener: 'closed',
      originalProcess: 'verified',
    });
    expect(injected).toBe(true);
    expect(requestTimer).toBeDefined();
    expect(clears.mock.calls.filter(([timer]) => timer === requestTimer)).toHaveLength(1);
    expect(JSON.stringify(failure)).not.toContain('ERR_PRIVATE_SEND_CAUSE_SENTINEL');
    await assertInspectorClosed(fixture);
  } finally {
    writer.mockRestore();
    timers.mockRestore();
    clears.mockRestore();
    await fixture.close();
  }
}, 30000);

it.each([false, true])(
  'reconciles ambiguous native close without sending it again, delivered=%s',
  async (delivered) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    const send = WebSocket.prototype.send;
    let closeAttempts = 0;
    const writer = vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
      this: WebSocket,
      data,
    ) {
      const command = JSON.parse(String(data));
      if (
        command.method === 'Runtime.evaluate' &&
        command.params?.expression ===
          'void setImmediate(()=>process.getBuiltinModule("node:inspector").close())'
      ) {
        closeAttempts++;
        if (delivered) send.call(this, data);
        throw new Error('ERR_PRIVATE_AMBIGUOUS_SEND_SENTINEL');
      }
      send.call(this, data);
    });
    try {
      const outcome = await captureFixtureClaims(fixture).catch((error: unknown) => error);
      expect(closeAttempts).toBe(1);
      expect(JSON.stringify(outcome)).not.toContain('ERR_PRIVATE_AMBIGUOUS_SEND_SENTINEL');
      if (delivered) {
        expect(outcome).not.toBeInstanceOf(Error);
        expect(outcome).toHaveProperty('diagnostic.listenerClosed', true);
        expect(outcome).toHaveProperty('diagnostic.cleanupReplyLost', true);
        await assertInspectorClosed(fixture);
      } else {
        expect(outcome).toBeInstanceOf(LocalIssuerCaptureFailure);
        expect((outcome as LocalIssuerCaptureFailure).diagnostic.listener).toBe('unresolved');
        expect(await issuerProcessStartTicks(fixture.input.pid)).toBe(fixture.input.startTicks);
        const health = await fetch(`http://127.0.0.1:${fixture.input.issuerPort}/healthz`);
        expect(health.status).toBe(200);
        await health.arrayBuffer();
      }
    } finally {
      writer.mockRestore();
      await fixture.close();
    }
  },
  30000,
);

it('bounds an unsettled async phase callback and independently closes the signaled inspector', async () => {
  const f = await certificateFixture(),
    fixture = await inspectorFixture([providerEntry(f)], []);
  try {
    const failure = await captureFixtureClaims(fixture, {
      onPhase: (phase) => {
        if (phase === 'after-signal') return new Promise<void>(() => undefined);
      },
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
    expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
      capturePhase: 'after-signal',
      listener: 'closed',
      originalProcess: 'verified',
    });
    await assertInspectorClosed(fixture);
  } finally {
    await fixture.close();
  }
}, 30000);

async function stoppedIssuer(pid: number) {
  const deadline = Date.now() + 1000;
  while (Date.now() < deadline) {
    const status = await readFile(`/proc/${pid}/status`, 'utf8');
    if (/^State:\s+T/mu.test(status)) return status;
    await delay(5);
  }
  throw new Error('ISOLATED_STOP_BARRIER_NOT_OBSERVED');
}
it.each([false, true])(
  'preserves delayed inspector-start ambiguity and reports unresolved=%s accurately',
  async (unresolved) => {
    const f = await certificateFixture(),
      fixture = await inspectorFixture([providerEntry(f)], []);
    try {
      const failure = await captureFixtureClaims(fixture, {
        onPhase: async (phase) => {
          if (phase === 'before-signal') {
            process.kill(fixture.input.pid, 'SIGSTOP');
            await stoppedIssuer(fixture.input.pid);
          }
          if (phase === 'after-signal') {
            const status = await stoppedIssuer(fixture.input.pid);
            const pending = status.match(/^ShdPnd:\s+([0-9a-f]+)$/mu);
            expect(pending).not.toBeNull();
            expect(BigInt('0x' + pending![1]) & 0x200n).toBe(0x200n);
            if (!unresolved) setImmediate(() => process.kill(fixture.input.pid, 'SIGCONT'));
            throw new Error('ISOLATED_PENDING_START_FAULT');
          }
        },
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LocalIssuerCaptureFailure);
      expect((failure as LocalIssuerCaptureFailure).diagnostic, fixture.exitDiagnostic()).toEqual({
        capturePhase: 'after-signal',
        listener: unresolved ? 'unresolved' : 'closed',
        originalProcess: unresolved ? 'unverified' : 'verified',
      });
      expect(await issuerProcessStartTicks(fixture.input.pid)).toBe(fixture.input.startTicks);
      if (!unresolved) await assertInspectorClosed(fixture);
      else await stoppedIssuer(fixture.input.pid);
    } finally {
      // Only this isolated disposable child is resumed/terminated. The unresolved
      // result never claims that an original live listener is closed or recovered.
      if (fixture.child.exitCode === null) process.kill(fixture.input.pid, 'SIGCONT');
      await fixture.close();
    }
  },
  30000,
);

it.each(['expired', 'future', 'expired CA', 'future CA'] as const)(
  'authenticates retained %s provider bytes but denies live use before any provider POST',
  async (state) => {
    const now = Date.now(),
      expired = state.startsWith('expired'),
      f = await certificateFixture({
        caFrom: new Date(state === 'future CA' ? now + 120000 : now - 3600000),
        caUntil: new Date(state === 'expired CA' ? now - 30000 : now + 24 * 3600000),
        clientFrom: new Date(expired ? now - 1800000 : now + 60000),
        clientUntil: new Date(expired ? now - 60000 : now + 3600000),
      });
    const bytes = Buffer.from(JSON.stringify(providerProfile(f))),
      config = {
        bytes,
        expectedDigest: createHash('sha256').update(bytes).digest('hex'),
        endpoint: profileEndpoint,
        trustedCaPem: f.ca,
        localQaEnabled: true,
      };
    expect(() => readImmutableLocalWorkloadIssuerProfile(config)).toThrow(
      'Untrusted local issuer profile certificate',
    );
    const manifest = authenticateHistoricalLocalWorkloadIssuerProfile(config),
      before = Buffer.from(bytes);
    const fetch = vi.fn();
    const issuer = createHttpWorkloadCredentialIssuer({
      endpoint: profileEndpoint,
      authorizationToken: 't'.repeat(32),
      trustedCaPem: f.ca,
      allowInsecureHttp: true,
      immutableLocalManifest: manifest,
      fetch,
    });
    await expect(issuer.issue(f.request)).rejects.toThrow(
      'Installed issuer certificate is not current',
    );
    expect(fetch).not.toHaveBeenCalled();
    Object.assign(manifest.certificates[0]!.validity, {
      validFromMs: now - 1000,
      validUntilMs: now + 3600000,
    });
    await expect(issuer.issue(f.request)).rejects.toThrow(
      'Installed issuer certificate is not current',
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(
      issuer.recovery?.verifyObservation(f.request, f.certificateDer, new Date()),
    ).toBeUndefined();
    expect(bytes).toEqual(before);
    expect(manifest.certificates[0]!.certificateFingerprint).toEqual(
      createHash('sha256').update(f.certificateDer).digest(),
    );
  },
);
it('historical installation authentication preserves current qualification and exact recovery profile digests', async () => {
  const f = await certificateFixture(),
    bytes = Buffer.from(JSON.stringify(providerProfile(f))),
    config = {
      bytes,
      expectedDigest: createHash('sha256').update(bytes).digest('hex'),
      endpoint: profileEndpoint,
      trustedCaPem: f.ca,
      localQaEnabled: true,
    };
  const current = readImmutableLocalWorkloadIssuerProfile(config),
    historical = authenticateHistoricalLocalWorkloadIssuerProfile(config);
  expect(historical).toEqual(current);
  const common = {
    endpoint: profileEndpoint,
    authorizationToken: 't'.repeat(32),
    trustedCaPem: f.ca,
    allowInsecureHttp: true,
  };
  expect(
    createHttpWorkloadCredentialIssuer({ ...common, immutableLocalManifest: historical }).recovery
      ?.profileDigest,
  ).toEqual(
    createHttpWorkloadCredentialIssuer({ ...common, immutableLocalManifest: current }).recovery
      ?.profileDigest,
  );
  for (const change of [
    { localQaEnabled: false },
    { expectedDigest: '0'.repeat(64) },
    { endpoint: profileEndpoint + '/foreign' },
  ])
    expect(() =>
      authenticateHistoricalLocalWorkloadIssuerProfile({ ...config, ...change }),
    ).toThrow();
});

it('historical configuration rejects substituted request, signature, trust and noncanonical installed bytes', async () => {
  const f = await certificateFixture(),
    g = await certificateFixture(),
    profile = providerProfile(f);
  const malformed = [
    { ...profile, trustedCaPem: g.ca.toString('utf8') },
    {
      ...profile,
      certificates: [{ ...providerEntry(f), certificateDer: g.certificateDer.toString('base64') }],
    },
    {
      ...profile,
      certificates: [
        { ...providerEntry(f), publicKeySpkiDer: g.request.publicKeySpkiDer.toString('base64') },
      ],
    },
    {
      ...profile,
      certificates: [
        { ...providerEntry(f), participantId: '018f0000-0000-7000-8000-000000000999' },
      ],
    },
    {
      ...profile,
      certificates: [
        { ...providerEntry(f), certificateDer: providerEntry(f).certificateDer + '\n' },
      ],
    },
    { ...profile, certificates: [providerEntry(f), providerEntry(f)] },
  ];
  for (const value of malformed) {
    const bytes = Buffer.from(JSON.stringify(value));
    expect(() =>
      authenticateHistoricalLocalWorkloadIssuerProfile({
        bytes,
        expectedDigest: createHash('sha256').update(bytes).digest('hex'),
        endpoint: profileEndpoint,
        trustedCaPem: f.ca,
        localQaEnabled: true,
      }),
    ).toThrow();
  }
});
it.each(['no CA overlap', 'excessive lifetime', 'beyond CA expiry'] as const)(
  'historical configuration rejects intrinsic %s even with authentic installed digests',
  async (kind) => {
    const now = Date.now(),
      f = await certificateFixture({
        caFrom: new Date(kind === 'no CA overlap' ? now + 7200000 : now - 3600000),
        caUntil: new Date(kind === 'beyond CA expiry' ? now + 1800000 : now + 48 * 3600000),
        clientFrom: new Date(now - 60000),
        clientUntil: new Date(kind === 'excessive lifetime' ? now + 25 * 3600000 : now + 3600000),
      });
    const bytes = Buffer.from(JSON.stringify(providerProfile(f)));
    expect(() =>
      authenticateHistoricalLocalWorkloadIssuerProfile({
        bytes,
        expectedDigest: createHash('sha256').update(bytes).digest('hex'),
        endpoint: profileEndpoint,
        trustedCaPem: f.ca,
        localQaEnabled: true,
      }),
    ).toThrow('Untrusted local issuer profile certificate');
  },
);
