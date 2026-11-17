import { generateKeyPairSync } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import type { MutationCandidateAuthority } from './db/mutation-candidate-store.js';
import { buildIdentityService } from './app.js';
import { IdentityKernel } from './domain/identity-kernel.js';
import { canonicalAuthorizationDigest } from './contracts/authorization.js';
const id = (tail: string) => `018f0000-0000-7000-8000-${tail.padStart(12, '0')}`;
const participantId = id('101'),
  principalId = id('111'),
  credentialId = id('192');
const intentDigest = `sha256:${'a'.repeat(64)}`;
it('prepares the exact authorized workload candidate without an approval placeholder or issuer effect', async () => {
  const stage = vi.fn(async () => id('801')),
    issue = vi.fn();
  const verifyCsrf = vi.fn(async () => undefined);
  const kernel = {
    sessionSnapshot: vi.fn(async () => ({ participantId, principalId })),
    actionIntentSemanticDigest: vi.fn(async () => intentDigest),
    verifyCsrf,
  } as unknown as IdentityKernel;
  const authority = {
    participantId,
    principalId,
    privacyDomainId: id('201'),
  } as MutationCandidateAuthority;
  const propose = vi.fn(async () => authority);
  const app = buildIdentityService(
    kernel,
    undefined,
    undefined,
    { authorize: vi.fn(async () => ({ allowed: false })), propose },
    undefined,
    undefined,
    { issue },
    { stage },
  );
  const publicKeySpkiDer = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .publicKey.export({ format: 'der', type: 'spki' })
    .toString('base64');
  const input = {
    mutation: 'ISSUE',
    credentialId,
    principalId: id('190'),
    workloadId: `urn:openpc:workload:${id('191')}`,
    publicKeySpkiDer,
  };
  const headers = {
    'cookie': `__Host-openpc_session=${participantId}.${id('701')}`,
    'origin': 'https://workload.test',
    'host': 'workload.test',
    'x-csrf-token': 'test-csrf',
    'idempotency-key': 'workload-prepare-0001',
    'x-openpc-aggregate-version': '0',
    'openpc-action-intent-digest': intentDigest,
  };
  try {
    const prepared = await app.inject({
      method: 'POST',
      url: '/v1/identity/workloads/prepare',
      headers,
      payload: input,
    });
    const candidate = {
      credentialId,
      principalId: id('190'),
      participantId,
      workloadId: input.workloadId,
      publicKeySpkiDer,
    };
    expect(prepared.statusCode, prepared.body).toBe(202);
    expect(prepared.json()).toEqual({
      state: 'PREPARED',
      resourceId: credentialId,
      candidateDigest: canonicalAuthorizationDigest(candidate),
      expectedRevision: '0',
    });
    expect(stage).toHaveBeenCalledWith(
      expect.objectContaining({
        candidate,
        catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
        expectedRevision: '0',
        authorization: authority,
      }),
      { sessionToken: `${participantId}.${id('701')}` },
    );
    expect(propose).toHaveBeenCalledWith(
      expect.objectContaining({
        candidate,
        expectedRevision: '0',
        catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
      }),
    );
    expect(issue).not.toHaveBeenCalled();
    expect(verifyCsrf).toHaveBeenCalledOnce();
    const malformed = await app.inject({
      method: 'POST',
      url: '/v1/identity/workloads/prepare',
      headers,
      payload: { ...input, publicKeySpkiDer: 'bad-key' },
    });
    expect(malformed.statusCode).toBeGreaterThanOrEqual(400);
    expect(stage).toHaveBeenCalledOnce();
    expect(propose).toHaveBeenCalledOnce();
    const noCsrf: Record<string, string> = { ...headers };
    delete noCsrf['x-csrf-token'];
    const absentCsrf = await app.inject({
      method: 'POST',
      url: '/v1/identity/workloads/prepare',
      headers: noCsrf,
      payload: input,
    });
    expect(absentCsrf.statusCode).toBeGreaterThanOrEqual(400);
  } finally {
    await app.close();
  }
});
