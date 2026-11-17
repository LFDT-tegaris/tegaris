import { generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, request as tlsRequest } from 'node:https';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runWorkloadRenewalWorkerOnce } from './workload-renewal-worker.js';
import {
  encodeWorkloadRenewalRequest,
  signWorkloadRenewalCose,
  workloadRenewalDigest,
} from '@openpc/security-kernel';
import { renewalRequestFixture } from '../../../../packages/security-kernel/src/workload-renewal/fixture.js';
import { expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import { createInstalledWorkloadRenewalWorker } from './installed-workload-renewal-worker.js';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  encodeWorkloadRenewalProviderRequest,
  renewalBytesDigest,
  workloadRenewalOriginalSchema,
  workloadRenewalProviderRequestSchema,
  type WorkloadRenewalProviderRequest,
} from '../contracts/workload-renewal.js';
import {
  createWorkloadRenewalStore,
  currentWorkloadRenewalLease,
} from '../db/workload-renewal-store.js';
import {
  createHttpWorkloadRenewalProvider,
  verifyWorkloadRenewalObservation,
} from './workload-renewal-provider.js';
import type {
  WorkloadRenewalClaim,
  WorkloadRenewalNonIssuance,
  WorkloadRenewalOriginal,
  WorkloadRenewalStore,
  WorkloadRenewalRecorded,
} from './workload-renewal-worker-contract.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = `sha256:${'11'.repeat(32)}` as const;
const now = new Date('2026-10-04T00:00:00.000Z');
const leaf = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const signer = generateKeyPairSync('ed25519');
const unsignedRequest: Omit<
  WorkloadRenewalProviderRequest,
  'requestPayloadBase64' | 'newKeyProofBase64'
> = {
  version: 2,
  renewalId: id(1),
  providerRequestId: id(1),
  operationId: id(2),
  credentialId: id(3),
  participantId: id(4),
  privacyDomainId: id(5),
  principalId: id(6),
  workloadId: `urn:openpc:workload:${id(7)}`,
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
  publicKeySpkiDerBase64: Buffer.from(
    leaf.publicKey.export({ type: 'spki', format: 'der' }),
  ).toString('base64'),
  algorithm: 'ECDSA_P256_SHA256',
  uriSan: `urn:openpc:participant:${id(4)}:workload:${id(7)}`,
  audience: 'openpc-runtime',
  validFrom: now.toISOString(),
  validUntil: '2026-10-05T00:00:00.000Z',
};
const payload = encodeWorkloadRenewalRequest({
  ...renewalRequestFixture(
    workloadRenewalDigest(Buffer.from(unsignedRequest.publicKeySpkiDerBase64, 'base64')),
  ),
  participantId: unsignedRequest.participantId,
  privacyDomainId: unsignedRequest.privacyDomainId,
  principalId: unsignedRequest.principalId,
  workloadId: unsignedRequest.workloadId,
  renewalId: unsignedRequest.renewalId,
  familyId: unsignedRequest.familyId,
  instanceId: unsignedRequest.instanceId,
  instanceGeneration: unsignedRequest.instanceGeneration,
  predecessorCredentialId: unsignedRequest.predecessorCredentialId,
  predecessorGeneration: unsignedRequest.expectedFamilyGeneration,
  policyId: unsignedRequest.policyId,
  policyRevision: unsignedRequest.policyRevision,
  policyDigest: unsignedRequest.policyDigest,
  attestationProfileDigest: unsignedRequest.attestationProfileDigest,
  attestationDigest: unsignedRequest.attestationDigest,
  issuerProfileDigest: unsignedRequest.issuerProfileDigest,
  providerQualificationDigest: unsignedRequest.providerQualificationDigest,
  requestedCertificateNotBeforeNs: (
    BigInt(Date.parse(unsignedRequest.validFrom)) * 1000000n
  ).toString(),
  requestedCertificateNotAfterNs: (
    BigInt(Date.parse(unsignedRequest.validUntil)) * 1000000n
  ).toString(),
  requestValidFromNs: (BigInt(now.getTime()) * 1000000n).toString(),
  requestValidUntilNs: (BigInt(now.getTime() + 120000) * 1000000n).toString(),
});
const request: WorkloadRenewalProviderRequest = {
  ...unsignedRequest,
  requestPayloadBase64: payload.toString('base64'),
  newKeyProofBase64: signWorkloadRenewalCose(
    'REQUEST',
    leaf.privateKey.export({ format: 'der', type: 'pkcs8' }),
    Buffer.from(unsignedRequest.publicKeySpkiDerBase64, 'base64'),
    payload,
  ).toString('base64'),
};
const original: WorkloadRenewalOriginal = (() => {
  const identity = Object.fromEntries(
    Object.keys(workloadRenewalOriginalSchema.shape)
      .filter((key) => key in request)
      .map((key) => [key, request[key as keyof typeof request]]),
  );
  const bytes = encodeWorkloadRenewalProviderRequest(request);
  return workloadRenewalOriginalSchema.parse({
    ...identity,
    providerRequestBase64: bytes.toString('base64'),
    providerRequestDigest: renewalBytesDigest(bytes),
  });
})();
const profile = {
  endpoint: 'https://issuer.test/',
  audience: 'openpc-runtime',
  maximumLeafLifetimeMs: 86400000,
  qualificationDigest: digest,
  issuerProfileDigest: digest,
  observationSignerSpkiDer: Buffer.from(signer.publicKey.export({ type: 'spki', format: 'der' })),
  trustedCaPem: Buffer.from('unconfigured fixture CA'),
};
const claim: WorkloadRenewalClaim = {
  original,
  attemptId: id(12),
  workerId: 'installed-worker',
  leaseFence: '1',
  leaseExpiresAt: '2026-10-04T00:01:30.000Z',
  renewalDeadline: '2026-10-04T00:20:00.000Z',
  providerTimeoutMs: 30000,
};
function observation(changes: Record<string, unknown> = {}): WorkloadRenewalNonIssuance {
  const statement = {
    domain: 'OPENPC_WORKLOAD_RENEWAL_PROVIDER_OBSERVATION',
    version: 2,
    kind: 'NOT_ISSUED',
    providerRequestId: original.providerRequestId,
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    observationRevision: '1',
    observedAt: now.toISOString(),
    validUntil: '2026-10-04T00:01:00.000Z',
    certificateDigest: null,
    ...changes,
  };
  const signatureBase64 = sign(
    null,
    Buffer.from(canonicalDefinitionJson(statement)),
    signer.privateKey,
  ).toString('base64');
  return {
    kind: 'NOT_ISSUED',
    providerRequestId: original.providerRequestId,
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    proofBase64: Buffer.from(canonicalDefinitionJson({ statement, signatureBase64 })).toString(
      'base64',
    ),
  };
}

it('binds exact canonical public request bytes to all original fields without a private key', () => {
  expect(workloadRenewalOriginalSchema.parse(original)).toEqual(original);
  expect(JSON.parse(Buffer.from(original.providerRequestBase64, 'base64').toString())).toEqual(
    request,
  );
});
it('rejects replaced scope, successor proof or transported key before original admission', () => {
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  for (const change of [
    { attestationDigest: `sha256:${'ff'.repeat(32)}` },
    { expectedFamilyGeneration: '3' },
    { newKeyProofBase64: Buffer.alloc(128).toString('base64') },
    { requestPayloadBase64: Buffer.from('unregistered JSON authority').toString('base64') },
    {
      publicKeySpkiDerBase64: other.publicKey
        .export({ format: 'der', type: 'spki' })
        .toString('base64'),
    },
  ])
    expect(workloadRenewalProviderRequestSchema.safeParse({ ...request, ...change }).success).toBe(
      false,
    );
});
it.each([
  'participantId',
  'privacyDomainId',
  'principalId',
  'familyId',
  'instanceId',
  'policyId',
  'operationId',
  'credentialId',
  'predecessorCredentialId',
] as const)(
  'rejects an original %s changed without changing its signed public request',
  (field) => {
    expect(workloadRenewalOriginalSchema.safeParse({ ...original, [field]: id(99) }).success).toBe(
      false,
    );
  },
);
it.each([
  { providerRequestId: id(99) },
  { credentialId: id(1) },
  { algorithm: 'RSA' },
  { uriSan: 'urn:openpc:participant:foreign' },
  { validUntil: '2026-10-05T00:00:01.000Z' },
  { validUntil: request.validFrom },
  { validFrom: '2026-10-04T00:00:00.001Z' },
  { instanceGeneration: '18446744073709551616' },
  { policyRevision: '01' },
  { privateKey: 'must never be accepted' },
])('rejects unsupported provider input %#', (change) => {
  expect(workloadRenewalProviderRequestSchema.safeParse({ ...request, ...change }).success).toBe(
    false,
  );
});
it('rejects a semantically equivalent reconstruction with noncanonical bytes', () => {
  const bytes = Buffer.from(JSON.stringify(request));
  expect(
    workloadRenewalOriginalSchema.safeParse({
      ...original,
      providerRequestBase64: bytes.toString('base64'),
      providerRequestDigest: renewalBytesDigest(bytes),
    }).success,
  ).toBe(false);
});
it('authenticates provider proof but does not claim installed qualification or business authority', () => {
  expect(verifyWorkloadRenewalObservation(original, observation(), profile, now)).toMatchObject({
    kind: 'NOT_ISSUED',
    fresh: true,
    proofRevision: '1',
    certificate: undefined,
  });
});
it.each([
  { domain: 'OTHER_DOMAIN' },
  { version: 1 },
  { kind: 'CERTIFICATE' },
  { providerRequestId: id(99) },
  { providerRequestDigest: digest },
  { providerQualificationDigest: `sha256:${'22'.repeat(32)}` },
  { observationRevision: '0' },
  { observedAt: '2026-10-04T00:00:06.000Z' },
  { validUntil: '2026-10-04T00:01:01.000Z' },
  { certificateDigest: digest },
])('rejects authenticated but incompatible provider statement %#', (change) => {
  expect(
    verifyWorkloadRenewalObservation(original, observation(change), profile, now),
  ).toBeUndefined();
});
it('retains authenticated expired proof as nonfresh evidence without issuance authority', () => {
  expect(
    verifyWorkloadRenewalObservation(
      original,
      observation(),
      profile,
      new Date('2026-10-04T00:01:00.000Z'),
    )?.fresh,
  ).toBe(false);
});
it.each([
  { audience: 'other-runtime' },
  { maximumLeafLifetimeMs: 3600000 },
  { maximumLeafLifetimeMs: 86400001 },
])('rejects a request outside the installed issuer audience/lifetime profile %#', (change) => {
  expect(
    verifyWorkloadRenewalObservation(original, observation(), { ...profile, ...change }, now),
  ).toBeUndefined();
});
it('rejects foreign signer and altered signature bytes', () => {
  const foreign = generateKeyPairSync('ed25519');
  expect(
    verifyWorkloadRenewalObservation(
      original,
      observation(),
      {
        ...profile,
        observationSignerSpkiDer: Buffer.from(
          foreign.publicKey.export({ type: 'spki', format: 'der' }),
        ),
      },
      now,
    ),
  ).toBeUndefined();
  const o = observation();
  const proof = JSON.parse(Buffer.from(o.proofBase64, 'base64').toString());
  proof.signatureBase64 = Buffer.alloc(64).toString('base64');
  expect(
    verifyWorkloadRenewalObservation(
      original,
      { ...o, proofBase64: Buffer.from(canonicalDefinitionJson(proof)).toString('base64') },
      profile,
      now,
    ),
  ).toBeUndefined();
});
it('fails before any claim without real installed worker admission', async () => {
  const store = createWorkloadRenewalStore();
  await expect(store.claimDue('caller-invented-worker')).rejects.toThrow(
    'authority is unavailable',
  );
  await expect(store.authorizeOriginalIssue(claim, observation())).rejects.toThrow(
    'authority is unavailable',
  );
  await expect(
    store.checkCommittedPermit(
      { claim, issuanceAuthorizationId: id(99) },
      { endpoint: profile.endpoint, qualificationDigest: digest },
    ),
  ).rejects.toThrow('authority is unavailable');
});
it.each([
  { lease_fence: '2' },
  { worker_id: 'foreign-worker' },
  { lease_expires_at: new Date('2026-10-04T00:01:31.000Z') },
  { now: new Date(claim.leaseExpiresAt) },
  { original: { ...original, instanceGeneration: '2' } },
])('rejects stale or changed durable lease %#', (change) => {
  expect(
    currentWorkloadRenewalLease(claim, {
      original,
      lease_fence: '1',
      worker_id: claim.workerId,
      lease_expires_at: new Date(claim.leaseExpiresAt),
      now,
      ...change,
    }),
  ).toBe(false);
});
it('accepts the original lease only within its exact finite interval', () => {
  expect(
    currentWorkloadRenewalLease(claim, {
      original,
      lease_fence: '1',
      worker_id: claim.workerId,
      lease_expires_at: new Date(claim.leaseExpiresAt),
      now,
    }),
  ).toBe(true);
});
it('treats404 as UNKNOWN, never qualified nonissuance', async () => {
  const fetcher = vi.fn(async () => new Response('', { status: 404 }));
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: 'https://issuer.test',
    authorizationToken: 'test-only-token',
    qualificationDigest: digest,
    fetch: fetcher,
    checkCommittedPermit: async () => {
      throw new Error('unavailable');
    },
  });
  expect(await provider.readOriginal(original, new AbortController().signal)).toEqual({
    kind: 'UNKNOWN',
    reason: 'UNQUALIFIED_RESPONSE',
  });
  expect(fetcher.mock.calls).toHaveLength(1);
});
it('does not send PUT for a caller-fabricated authorization ID', async () => {
  const fetcher = vi.fn();
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: 'https://issuer.test',
    authorizationToken: 'test-only-token',
    qualificationDigest: digest,
    fetch: fetcher,
    checkCommittedPermit: async () => {
      throw new Error('unavailable');
    },
  });
  expect(
    await provider.issueExact(
      { claim, issuanceAuthorizationId: id(99) },
      new AbortController().signal,
    ),
  ).toEqual({ kind: 'UNKNOWN', reason: 'UNQUALIFIED_RESPONSE' });
  expect(fetcher).not.toHaveBeenCalled();
});
it('sends only exact committed public bytes after successful durable permit checking', async () => {
  const o = observation();
  const issued = { ...o, kind: 'CERTIFICATE', certificateDerBase64: 'not-a-certificate' };
  const fetcher = vi.fn(async () => new Response(JSON.stringify(issued)));
  const check = vi.fn(async () => {});
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: 'https://issuer.test/pki',
    authorizationToken: 'test-only-token',
    qualificationDigest: digest,
    fetch: fetcher,
    checkCommittedPermit: check,
  });
  const permit = { claim, issuanceAuthorizationId: id(13) };
  await provider.issueExact(permit, new AbortController().signal);
  expect(check).toHaveBeenCalledWith(permit, {
    endpoint: 'https://issuer.test/pki',
    qualificationDigest: digest,
  });
  expect(fetcher).toHaveBeenCalledWith(
    new URL(`https://issuer.test/pki/v2/certificates/${original.renewalId}`),
    expect.objectContaining({
      method: 'PUT',
      redirect: 'error',
      body: Buffer.from(original.providerRequestBase64, 'base64').toString('utf8'),
    }),
  );
  // Transport parsing is not certificate/proof verification or installation.
  expect(verifyWorkloadRenewalObservation(original, issued as never, profile, now)).toBeUndefined();
});

it('keeps configured transport and permit checking bound across asynchronous reconciliation', async () => {
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => {
    release = resolve;
  });
  const check = vi.fn(async () => waiting);
  const issued = { ...observation(), kind: 'CERTIFICATE', certificateDerBase64: 'fixture-der' };
  const fetcher = vi.fn(async () => new Response(JSON.stringify(issued)));
  const input = {
    endpoint: 'https://issuer.test/pki',
    authorizationToken: 'original-fixture-token',
    qualificationDigest: digest as `sha256:${string}`,
    checkCommittedPermit: check,
    fetch: fetcher,
  };
  const provider = createHttpWorkloadRenewalProvider(input);
  const permit = {
    claim: { ...claim, original: { ...original } },
    issuanceAuthorizationId: id(13),
  };
  const running = provider.issueExact(permit, new AbortController().signal);
  input.authorizationToken = 'replaced-fixture-token';
  input.qualificationDigest = `sha256:${'22'.repeat(32)}`;
  input.checkCommittedPermit = vi.fn(async () => {});
  release();
  expect(await running).toEqual(issued);
  expect(check).toHaveBeenCalledExactlyOnceWith(permit, {
    endpoint: 'https://issuer.test/pki',
    qualificationDigest: digest,
  });
  expect(input.checkCommittedPermit).not.toHaveBeenCalled();
  expect(fetcher).toHaveBeenCalledExactlyOnceWith(
    new URL(`https://issuer.test/pki/v2/certificates/${original.renewalId}`),
    expect.objectContaining({
      method: 'PUT',
      headers: expect.objectContaining({ authorization: 'Bearer original-fixture-token' }),
      body: Buffer.from(original.providerRequestBase64, 'base64').toString('utf8'),
    }),
  );
  expect(provider.qualificationDigest).toBe(digest);
});
it('seals exact original bytes and attempt fence before committed permit checking', async () => {
  const permit = {
    claim: { ...claim, original: { ...original } },
    issuanceAuthorizationId: id(13),
  };
  const fetcher = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(observation())));
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: 'https://issuer.test',
    authorizationToken: 'fixture-token',
    qualificationDigest: digest,
    fetch: fetcher,
    checkCommittedPermit: async (checked) => {
      expect(checked).toBe(permit);
      for (const target of [checked, checked.claim, checked.claim.original])
        expect(Object.isFrozen(target)).toBe(true);
      expect(() => Object.assign(checked, { issuanceAuthorizationId: id(99) })).toThrow();
      expect(() => Object.assign(checked.claim, { leaseFence: '99' })).toThrow();
      expect(() =>
        Object.assign(checked.claim.original, { providerRequestBase64: 'YWx0ZXJlZA==' }),
      ).toThrow();
    },
  });
  expect(await provider.issueExact(permit, new AbortController().signal)).toEqual({
    kind: 'UNKNOWN',
    reason: 'UNQUALIFIED_RESPONSE',
  });
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0]?.[1]?.body).toBe(
    Buffer.from(original.providerRequestBase64, 'base64').toString('utf8'),
  );
});
it.each(['headers', 'body'] as const)(
  'does not report a late certificate after abort during %s',
  async (stage) => {
    const controller = new AbortController();
    const issued = { ...observation(), kind: 'CERTIFICATE', certificateDerBase64: 'fixture-der' };
    const bytes = Buffer.from(JSON.stringify(issued));
    const fetcher = vi.fn(async () => {
      if (stage === 'headers') controller.abort();
      return new Response(
        new ReadableStream<Uint8Array>({
          pull(stream) {
            if (stage === 'body') controller.abort();
            stream.enqueue(bytes);
            stream.close();
          },
        }),
      );
    });
    const provider = createHttpWorkloadRenewalProvider({
      endpoint: 'https://issuer.test',
      authorizationToken: 'fixture-token',
      qualificationDigest: digest,
      fetch: fetcher,
      checkCommittedPermit: async () => {},
    });
    expect(
      await provider.issueExact({ claim, issuanceAuthorizationId: id(13) }, controller.signal),
    ).toEqual({ kind: 'UNKNOWN', reason: 'TRANSPORT_UNAVAILABLE' });
    expect(fetcher).toHaveBeenCalledOnce();
  },
);
it('does not check or dispatch a permit cancelled before issueExact', async () => {
  const controller = new AbortController();
  controller.abort();
  const check = vi.fn(async () => {}),
    fetcher = vi.fn();
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: 'https://issuer.test',
    authorizationToken: 'fixture-token',
    qualificationDigest: digest,
    fetch: fetcher,
    checkCommittedPermit: check,
  });
  expect(
    await provider.issueExact({ claim, issuanceAuthorizationId: id(13) }, controller.signal),
  ).toEqual({ kind: 'UNKNOWN', reason: 'TRANSPORT_UNAVAILABLE' });
  expect(check).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});

it('reconciles a native TLS lost-write response using the same original request and next attempt fence', async () => {
  // Native transport and port orchestration only: generated local fixture keys,
  // no installed issuer grant, SQL authority, usable credential or adoption.
  const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'renewal-tls-'));
  const certPath = join(root, 'server.pem'),
    keyPath = join(root, 'server-key.pem');
  let server: ReturnType<typeof createServer> | undefined;
  try {
    execFileSync(
      '/usr/bin/openssl',
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
        '/CN=OpenPC isolated renewal fixture',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
        '-keyout',
        keyPath,
        '-out',
        certPath,
      ],
      { timeout: 10000, stdio: 'ignore' },
    );
    const cert = await readFile(certPath),
      key = await readFile(keyPath);
    const der = new X509Certificate(cert).raw;
    const issued = {
      ...observation({ kind: 'CERTIFICATE', certificateDigest: renewalBytesDigest(der) }),
      kind: 'CERTIFICATE' as const,
      certificateDerBase64: der.toString('base64'),
    };
    const calls: {
      method: string;
      path: string;
      bytes: Buffer;
      digest: string | string[] | undefined;
    }[] = [];
    let effectExists = false;
    server = createServer({ cert, key }, async (incoming, outgoing) => {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      calls.push({
        method: incoming.method ?? '',
        path: incoming.url ?? '',
        bytes: Buffer.concat(chunks),
        digest: incoming.headers['x-openpc-request-digest'],
      });
      if (incoming.method === 'PUT') {
        effectExists = true;
        outgoing.destroy(); // Actual external write completed; TLS reply lost.
      } else {
        outgoing.setHeader('content-type', 'application/json');
        outgoing.end(JSON.stringify(effectExists ? issued : observation()));
      }
    });
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Fixture listener unavailable');
    const endpoint = `https://127.0.0.1:${address.port}`;
    const nativeFetch: typeof fetch = async (input, options) => {
      const url =
        input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
      return new Promise<Response>((resolve, reject) => {
        const request = tlsRequest(
          url,
          {
            ca: cert,
            method: options?.method,
            headers: Object.fromEntries(new Headers(options?.headers)),
            signal: options?.signal ?? undefined,
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on('data', (chunk: Buffer) => chunks.push(chunk));
            response.on('error', reject);
            response.on('end', () =>
              resolve(
                new Response(new Uint8Array(Buffer.concat(chunks)), {
                  status: response.statusCode,
                }),
              ),
            );
          },
        );
        request.on('error', reject);
        request.end(typeof options?.body === 'string' ? options.body : undefined);
      });
    };
    let nextClaim: WorkloadRenewalClaim = { ...claim, providerTimeoutMs: 2000 };
    const recorded: WorkloadRenewalRecorded = {
      renewalId: original.renewalId,
      operationId: original.operationId,
      revision: '1',
      observedAt: now.toISOString(),
      state: 'RECOVERING',
      providerOutcome: 'UNRESOLVED',
    };
    const store = {
      claimDue: vi.fn<WorkloadRenewalStore['claimDue']>(async () => nextClaim),
      recordReadback: vi.fn<WorkloadRenewalStore['recordReadback']>(async () => recorded),
      authorizeOriginalIssue: vi.fn<WorkloadRenewalStore['authorizeOriginalIssue']>(
        async (claimed) => ({ claim: claimed, issuanceAuthorizationId: id(13) }),
      ),
      recordIssue: vi.fn<WorkloadRenewalStore['recordIssue']>(async () => recorded),
    } satisfies WorkloadRenewalStore;
    const check = vi.fn(async () => {});
    const provider = createHttpWorkloadRenewalProvider({
      endpoint,
      authorizationToken: 'ephemeral-fixture-token',
      qualificationDigest: digest,
      fetch: nativeFetch,
      checkCommittedPermit: check,
    });
    await runWorkloadRenewalWorkerOnce(store, provider, nextClaim.workerId);
    expect(store.recordIssue).toHaveBeenCalledExactlyOnceWith(
      { claim: nextClaim, issuanceAuthorizationId: id(13) },
      { kind: 'UNKNOWN', reason: 'TRANSPORT_UNAVAILABLE' },
    );
    nextClaim = { ...nextClaim, attemptId: id(14), leaseFence: '2' };
    await runWorkloadRenewalWorkerOnce(store, provider, nextClaim.workerId);
    expect(store.recordReadback).toHaveBeenLastCalledWith(nextClaim, issued);
    expect(store.authorizeOriginalIssue).toHaveBeenCalledOnce();
    expect(store.recordIssue).toHaveBeenCalledOnce();
    expect(check).toHaveBeenCalledOnce();
    expect(calls.map((call) => call.method)).toEqual(['GET', 'PUT', 'GET']);
    for (const call of calls) {
      expect(call.path).toBe(`/v2/certificates/${original.providerRequestId}`);
      expect(call.digest).toBe(original.providerRequestDigest);
      expect(call.bytes).toEqual(
        call.method === 'PUT'
          ? Buffer.from(original.providerRequestBase64, 'base64')
          : Buffer.alloc(0),
      );
    }
  } finally {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server!.close((error) => (error ? reject(error) : resolve())),
      );
    }
    await rm(root, { recursive: true, force: true });
  }
}, 15000);

/** Projection/fence unit regression only. The mocked transaction below cannot
 * establish real SQL/RLS, installed worker, admitted policy or attestation. */
function storeFixture() {
  const row = {
    original,
    state: 'RECOVERING',
    provider_outcome: 'UNRESOLVED',
    row_version: '1',
    worker_id: claim.workerId as string | null,
    lease_fence: '1',
    lease_expires_at: new Date(claim.leaseExpiresAt) as Date | null,
    renewal_deadline: new Date(claim.renewalDeadline),
    now,
    family_security_epoch: '1',
    attestation_evidence: Buffer.from('test-only evidence'),
    attestation_valid_until: new Date(claim.renewalDeadline),
    latest_observation_id: null as string | null,
  };
  const observations: {
    proof_revision: string | null;
    proof_digest: Buffer | null;
    disposition: unknown;
    payload: unknown;
  }[] = [];
  const query = vi.fn(async (sql: string, values: unknown[] = []) => {
    const rows = (items: unknown[]) => ({ rowCount: items.length, rows: items });
    if (sql.includes('assert_request_context')) return rows([{}]);
    if (sql.includes('from pg_roles') || sql.includes('from control.workload_renewal_attempt'))
      return rows([{ valid: true }]);
    if (sql.includes('from control.workload_renewal_policy')) return rows([]);
    if (sql.startsWith('select') && sql.includes('from control.workload_renewal_intent'))
      return rows([{ ...row }]);
    if (sql.includes('from control.workload_renewal_observation')) {
      const known = observations
        .filter((o) => o.proof_revision !== null)
        .sort((a, b) => Number(b.proof_revision) - Number(a.proof_revision));
      return rows(known.slice(0, 1));
    }
    if (sql.includes('insert into control.workload_renewal_observation')) {
      observations.push({
        proof_revision: values[6] as string | null,
        proof_digest: values[5] as Buffer | null,
        disposition: values[7],
        payload: JSON.parse(values[4] as string),
      });
      return rows([{ observation_id: id(20 + observations.length) }]);
    }
    if (sql.includes('update control.workload_renewal_intent set state=')) {
      row.state = values[3] as string;
      row.provider_outcome = values[4] as string;
      row.latest_observation_id = values[5] as string;
      row.row_version = String(Number(row.row_version) + 1);
      if (values[10] === true) {
        row.worker_id = null;
        row.lease_expires_at = null;
      }
      return rows([{ ...row }]);
    }
    throw new Error('Unexpected unit query');
  });
  const client = { query } as unknown as PoolClient;
  const attestation = vi.fn(async () => {});
  const store = createWorkloadRenewalStore({
    async assertOriginalAdmission() {},
    async withTransaction(workerId, operation) {
      return operation({
        client,
        workerId,
        participantId: original.participantId,
        privacyDomainId: original.privacyDomainId,
        providerProfile: profile,
      });
    },
    assertCurrentAttestation: attestation,
  });
  return { store, row, observations, query, attestation };
}
it('cannot reuse an old signed nonissuance proof after a later UNKNOWN observation', async () => {
  const f = storeFixture();
  expect((await f.store.recordReadback(claim, observation())).providerOutcome).toBe('NOT_ISSUED');
  expect(
    (await f.store.recordReadback(claim, { kind: 'UNKNOWN', reason: 'PROVIDER_OUTCOME_UNKNOWN' }))
      .providerOutcome,
  ).toBe('UNRESOLVED');
  const before = { ...f.row };
  expect((await f.store.recordReadback(claim, observation())).providerOutcome).toBe('UNRESOLVED');
  expect(f.observations.at(-1)?.disposition).toBe('STALE');
  expect(f.row).toEqual(before);
  f.row.worker_id = claim.workerId;
  f.row.lease_fence = '2';
  f.row.lease_expires_at = new Date(claim.leaseExpiresAt);
  const reclaimed = { ...claim, attemptId: id(14), leaseFence: '2' };
  expect(
    (await f.store.recordReadback(reclaimed, observation({ observationRevision: '2' })))
      .providerOutcome,
  ).toBe('NOT_ISSUED');
});
it('retains stale-worker evidence without changing current projection or lease', async () => {
  const f = storeFixture();
  f.row.lease_fence = '2';
  const before = { ...f.row };
  await f.store.recordReadback(claim, observation());
  expect(f.observations).toHaveLength(1);
  expect(f.observations[0]?.disposition).toBe('STALE');
  expect(f.row).toEqual(before);
});
it('does not authorize issuance from a qualified proof when the actual policy is unavailable', async () => {
  const f = storeFixture();
  await f.store.recordReadback(claim, observation());
  expect(await f.store.authorizeOriginalIssue(claim, observation())).toBeUndefined();
  expect(
    f.query.mock.calls.some(([sql]) =>
      sql.includes('insert into control.workload_renewal_issue_authorization'),
    ),
  ).toBe(false);
});
it('does not authorize issuance after the original deadline', async () => {
  const f = storeFixture();
  f.row.now = new Date(claim.renewalDeadline);
  expect(await f.store.authorizeOriginalIssue(claim, observation())).toBeUndefined();
  expect(f.attestation).not.toHaveBeenCalled();
});
it('redacts unqualified adapter fields instead of persisting arbitrary raw data', async () => {
  const f = storeFixture();
  await f.store.recordReadback(claim, {
    kind: 'UNKNOWN',
    reason: 'TRANSPORT_UNAVAILABLE',
    authorization: 'must not persist',
  } as never);
  expect(f.observations[0]?.payload).toEqual({ kind: 'UNKNOWN', reason: 'TRANSPORT_UNAVAILABLE' });
});

it('connects the worker to a fail-closed installation owner without external I/O', async () => {
  const fetcher = vi.fn();
  const worker = createInstalledWorkloadRenewalWorker({
    endpoint: profile.endpoint,
    authorizationToken: 'test-only-token',
    qualificationDigest: digest,
    fetch: fetcher,
  });
  await expect(worker.runOnce('uninstalled-worker')).rejects.toThrow('authority is unavailable');
  expect(fetcher).not.toHaveBeenCalled();
});
it('denies a transport endpoint different from the current installed provider qualification', async () => {
  const f = storeFixture();
  await expect(
    f.store.checkCommittedPermit(
      { claim, issuanceAuthorizationId: id(13) },
      { endpoint: 'https://foreign.test/', qualificationDigest: digest },
    ),
  ).rejects.toThrow('authority is unavailable');
  expect(
    f.query.mock.calls.some(([sql]) => sql.includes('from control.workload_renewal_attempt')),
  ).toBe(false);
});
