import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, openBffPayload, type IdentitySession } from './local-runtime';
import {
  mutatePrincipalWorkbench,
  readPrincipalWorkbench,
  readPrincipalCatalogue,
} from './local-principal-workbench';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operator: IdentitySession = {
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000117`,
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId,
  contextMode: 'PARTICIPANT',
  privacyDomainId,
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const viewer: IdentitySession = {
  ...operator,
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000118`,
  role: 'viewer',
  sessionId: '018f0000-0000-7000-8000-000000000118',
  principalId: '018f0000-0000-7000-8000-000000000112',
};
const approvalId = '018f0000-0000-7000-8000-000000000301';
const operationId = '018f0000-0000-7000-8000-000000000501';
const now = '2026-09-12T06:00:00.000000Z';
let root = '';
const original = { ...process.env };

function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function sha256(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function request(session: IdentitySession, body: unknown, path = '/api/v1/ui/principal-workbench') {
  const cookieKey = Buffer.from('cookie'.repeat(32));
  return new NextRequest(`http://127.0.0.1:8080${path}`, {
    method: 'POST',
    headers: {
      'cookie': `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function operation(actionIntentId: string, intentDigest: string, idempotencyKey: string) {
  return {
    operationId,
    actionIntentId,
    intentDigest,
    idempotencyKey,
    resourceRef: `urn:openpc:resource:${approvalId}`,
    revision: '1',
    state: 'ACCEPTED',
    truthState: 'SUCCESS',
    createdAt: now,
    updatedAt: now,
  };
}

function approval(candidateDigest: string, state: 'REQUESTED' | 'APPROVED' = 'REQUESTED') {
  return {
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest,
    state,
    makerSubjectRef: `urn:openpc:resource:${operator.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${viewer.principalId}`,
    revision: state === 'REQUESTED' ? '1' : '2',
    createdAt: now,
    updatedAt: now,
  };
}

it('reads the global subject and selected membership through their public owners and rejects inconsistent state', async () => {
  const target = '018f0000-0000-7000-8000-000000000891';
  const effect = {
    principalId: target,
    participantId,
    displayLabel: 'Governed person',
    kind: 'USER',
    state: 'ACTIVE',
    revision: '2',
    identityEpoch: '1',
    identitySubjectId: target,
    membershipId: target,
  };
  const membership = {
    membershipId: target,
    identitySubjectId: target,
    participantId,
    state: 'ACTIVE',
    revision: '2',
    membershipEpoch: '1',
  };
  const mock = (membershipState = 'ACTIVE') =>
    vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(
        Response.json({
          items: [],
          nextCursor: null,
          total: '0',
          completeness: 'COMPLETE',
          authorizedEmpty: true,
          snapshotRevision: '1',
        }),
      )
      .mockResolvedValueOnce(Response.json({ effect, operationId }))
      .mockResolvedValueOnce(
        Response.json({
          effect: { identitySubjectId: target, createdAt: now },
          membership: effect,
          membershipOperationId: operationId,
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ effect: { ...membership, state: membershipState }, operationId }),
      );
  const fetch = mock();
  const result = await readPrincipalWorkbench(
    request(operator, {}, `/api/v1/ui/principal-workbench?principalId=${target}`),
  );
  expect(result?.status).toBe(200);
  expect(await result!.json()).toMatchObject({
    effect: { humanIdentity: { ...membership, createdAt: now } },
  });
  expect(String(fetch.mock.calls[3]![0])).toContain(`/v1/identity/identity-subjects/${target}`);
  expect(String(fetch.mock.calls[4]![0])).toContain(`/v1/identity/memberships/${target}`);
  vi.restoreAllMocks();
  mock('SUSPENDED');
  const stale = await readPrincipalWorkbench(
    request(operator, {}, `/api/v1/ui/principal-workbench?principalId=${target}`),
  );
  expect(stale?.status).toBe(412);
  expect(await stale!.json()).not.toHaveProperty('effect');
});

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-participant-workbench-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie']) {
    await writeFile(join(root, name), name.repeat(32));
  }
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: 'http://gateway:8080',
    OPENPC_IDENTITY_INTERNAL_URL: 'http://identity:3001',
    OPENPC_FACT_INTERNAL_URL: 'http://fact:8081',
    OPENPC_POLICY_INTERNAL_URL: 'http://policy:3002',
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: 'http://127.0.0.1:53006/authorize',
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'identity'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'fact'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'policy'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...original };
  await rm(root, { recursive: true, force: true });
});

async function preview() {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const response = await mutatePrincipalWorkbench(
    request(operator, {
      command: 'PREVIEW_PROVISION',
      displayLabel: 'New governed reader',
      kind: 'USER',
      reason: 'Provision this approved user.',
    }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as {
    reviewToken: string;
    review: {
      candidateDigest: string;
      expectedRevision: string;
      proposedPrincipal: {
        principalId: string;
        participantId: string;
        displayLabel: string;
        kind: string;
        state: string;
      };
    };
  };
}
it('seals the exact provisioning candidate to the actor, context and principal review purpose', async () => {
  const value = await preview();
  expect(value.review.candidateDigest).toBe(
    sha256({ ...value.review.proposedPrincipal, identityEpoch: '0' }),
  );
  const key = Buffer.from('cookie'.repeat(32));
  expect(openBffPayload(value.reviewToken, key, 'principal-review')).toMatchObject({
    sessionId: operator.sessionId,
    contextEpoch: '2',
  });
  expect(openBffPayload(value.reviewToken, key, 'role-review')).toBeUndefined();
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...operator, contextEpoch: '3' }));
  const response = await mutatePrincipalWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
  );
  expect(response.status).toBe(412);
  expect(fetch).toHaveBeenCalledTimes(1);
});
it('requires the exact public proposal after a staging rejection', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(64) }))
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1005' } }, { status: 409 }))
    .mockResolvedValueOnce(Response.json({}, { status: 404 }));
  const response = await mutatePrincipalWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
  );
  expect(response.status).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(4);
});
it('submits the owner-confirmed proposal using public approval and matching action digests', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(64) }))
    .mockResolvedValueOnce(Response.json({}, { status: 409 }))
    .mockResolvedValueOnce(
      Response.json({
        proposedPrincipal: value.review.proposedPrincipal,
        candidateDigest: value.review.candidateDigest,
        expectedRevision: value.review.expectedRevision,
        mutation: 'PROVISION',
        resourceId: value.review.proposedPrincipal.principalId,
        state: 'PROPOSED',
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      }),
    )
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(64) }))
    .mockImplementationOnce(async (_url, init) => {
      const body = JSON.parse(init!.body as string);
      const headers = init!.headers as Record<string, string>;
      expect(headers['OpenPC-Action-Intent-Digest']).toBe(body.actionIntentDigest);
      expect(headers['X-OpenPC-Action-Intent-Digest']).toBe(body.actionIntentDigest);
      return Response.json(
        operation(body.actionIntentId, body.actionIntentDigest, headers['Idempotency-Key']!),
        { status: 202 },
      );
    })
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest)));
  const response = await mutatePrincipalWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
  );
  expect(response.status).toBe(202);
  expect((await response.json()).approval.candidateDigest).toBe(value.review.candidateDigest);
});
it('keeps a lost committed-write response ambiguous for supported readback', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest, 'APPROVED')))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(64) }))
    .mockRejectedValueOnce(new Error('Connection lost'));
  const response = await mutatePrincipalWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: approvalId,
    }),
  );
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({
    truthState: 'WRITE_AMBIGUITY',
    principalId: value.review.proposedPrincipal.principalId,
  });
});

it('reviews only an existing human membership and requires fresh authentication after removal', async () => {
  const target = '018f0000-0000-7000-8000-000000000891';
  const effect = {
    principalId: target,
    participantId,
    displayLabel: 'Governed person',
    kind: 'USER',
    state: 'SUSPENDED',
    revision: '3',
    identityEpoch: '2',
    identitySubjectId: target,
    membershipId: target,
  };
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ effect, operationId }));
  const preview = await mutatePrincipalWorkbench(
    request(operator, {
      command: 'PREVIEW_REMOVE',
      principalId: target,
      reason: 'Remove this membership permanently.',
    }),
  );
  expect(preview.status).toBe(201);
  const value = await preview.json();
  expect(value.review).toMatchObject({
    mutation: 'REMOVE',
    expectedRevision: '3',
    candidateDigest: sha256({ principalId: target, state: 'OFFBOARDED' }),
  });
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest, 'APPROVED')))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(64) }))
    .mockResolvedValueOnce(
      Response.json({ ...effect, state: 'OFFBOARDED', revision: '4', identityEpoch: '3' }),
    );
  const result = await mutatePrincipalWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: approvalId,
    }),
  );
  expect(result.status).toBe(202);
  expect(await result.json()).toEqual({
    truthState: 'REAUTH_REQUIRED',
    principalId: target,
    reconciliation: 'SIGN_IN_THEN_READ_AUTHORITATIVE_EFFECT',
  });
  expect(String(fetch.mock.calls[3]![0])).toContain(`/v1/identity/memberships/${target}/remove`);
  expect(fetch).toHaveBeenCalledTimes(4);
  for (const invalid of [
    { ...effect, state: 'OFFBOARDED' },
    { ...effect, membershipId: undefined, identitySubjectId: undefined },
  ]) {
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(Response.json({ effect: invalid, operationId }));
    expect(
      (
        await mutatePrincipalWorkbench(
          request(operator, {
            command: 'PREVIEW_REMOVE',
            principalId: target,
            reason: 'Remove this membership permanently.',
          }),
        )
      ).status,
    ).toBe(412);
  }
});

it('binds principal discovery to the public owner, validates pages and never turns failure into an empty result', async () => {
  const page = {
    items: [],
    nextCursor: null,
    authorizedEmpty: true,
    completeness: 'COMPLETE',
    observedAt: now,
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(operator));
  const response = await readPrincipalCatalogue(
    request(
      operator,
      {},
      '/api/v1/ui/principal-catalogue?search=Reader&state=OFFBOARDED&kind=USER&limit=1',
    ),
  );
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({
    ...page,
    actor: { sessionId: operator.sessionId, contextEpoch: '2', privacyDomainId },
  });
  expect(String(fetch.mock.calls[1]?.[0])).toBe(
    'http://gateway:8080/v1/identity/principals?search=Reader&state=OFFBOARDED&kind=USER&limit=1',
  );
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    headers: { 'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}` },
  });
  fetch
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({}, { status: 503 }));
  const unavailable = await readPrincipalCatalogue(
    request(operator, {}, '/api/v1/ui/principal-catalogue'),
  );
  expect(unavailable.status).toBe(503);
  expect(await unavailable.json()).not.toHaveProperty('items');
  fetch
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ ...page, nextCursor: approvalId }));
  const inconsistent = await readPrincipalCatalogue(
    request(operator, {}, '/api/v1/ui/principal-catalogue'),
  );
  expect(inconsistent.status).toBe(503);
  expect(await inconsistent.json()).not.toHaveProperty('items');
});

const catalogueSession: IdentitySession = {
  ...operator,
  participantId: '018f0000-0000-7000-8000-000000000102',
  privacyDomainId: '018f0000-0000-7000-8000-000000000202',
  sessionEpoch: '3',
  participantEpoch: '4',
  principalEpoch: '5',
  assignmentId: '018f0000-0000-7000-8000-000000000901',
  assignmentRowVersion: '6',
  authorityEnvelopeId: '018f0000-0000-7000-8000-000000000902',
  authorityEpoch: '7',
  delegationEpoch: '8',
  platformBootstrapEligible: false,
  availableContexts: [{ participantId, privacyDomainId }],
};
function catalogueResult(empty = false) {
  return {
    items: empty
      ? []
      : [
          {
            effect: {
              principalId: approvalId,
              participantId: catalogueSession.participantId,
              displayLabel: 'Current scoped workload',
              kind: 'WORKLOAD',
              state: 'ACTIVE',
              identityEpoch: '1',
              revision: '2',
            },
            operationId: null,
          },
        ],
    nextCursor: null,
    authorizedEmpty: empty,
    completeness: 'COMPLETE',
    observedAt: now,
  };
}
it.each([false, true])(
  'releases a nonfixture Participant catalogue only after the final fence, empty=%s',
  async (empty) => {
    const page = catalogueResult(empty);
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(Response.json(page))
      .mockResolvedValueOnce(
        Response.json({
          ...catalogueSession,
          stepUpVerifiedAt: '2026-10-04T00:00:00Z',
          sessionToken: 'rotated-opaque-token',
        }),
      );
    const response = await readPrincipalCatalogue(
      request(catalogueSession, {}, '/api/v1/ui/principal-catalogue?kind=WORKLOAD&state=ACTIVE'),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      ...page,
      actor: {
        sessionId: catalogueSession.sessionId,
        principalId: catalogueSession.principalId,
        participantId: catalogueSession.participantId,
        privacyDomainId: catalogueSession.privacyDomainId,
        contextEpoch: catalogueSession.contextEpoch,
      },
    });
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[1]?.[1]?.headers).toMatchObject({
      'OpenPC-Participant-ID': `urn:openpc:participant:${catalogueSession.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${catalogueSession.privacyDomainId}`,
    });
  },
);
it.each([
  ['session', { sessionId: approvalId }],
  ['principal', { principalId: approvalId }],
  ['Participant', { participantId }],
  ['privacy', { privacyDomainId }],
  ['context mode', { contextMode: 'PLATFORM' }],
  ['role', { role: 'viewer' }],
  ['bootstrap eligibility', { platformBootstrapEligible: true }],
  ['context epoch', { contextEpoch: '9' }],
  ['session epoch', { sessionEpoch: '9' }],
  ['Participant epoch', { participantEpoch: '9' }],
  ['principal epoch', { principalEpoch: '9' }],
  ['assignment', { assignmentId: approvalId }],
  ['assignment revision', { assignmentRowVersion: '9' }],
  ['authority envelope', { authorityEnvelopeId: approvalId }],
  ['authority epoch', { authorityEpoch: '9' }],
  ['delegation epoch', { delegationEpoch: '9' }],
  ['available contexts', { availableContexts: [] }],
  ['removed privacy', { privacyDomainId: undefined }],
  ['removed context epoch', { contextEpoch: undefined }],
  ['removed authority epoch', { authorityEpoch: undefined }],
  ['removed assignment', { assignmentId: undefined }],
] as const)('conceals the entire catalogue when final %s changes', async (_label, changed) => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession))
    .mockResolvedValueOnce(Response.json(catalogueResult()))
    .mockResolvedValueOnce(Response.json({ ...catalogueSession, ...changed }));
  const response = await readPrincipalCatalogue(
    request(catalogueSession, {}, '/api/v1/ui/principal-catalogue'),
  );
  expect(response.status).toBe(404);
  const body = await response.json();
  expect(body.code).toBe('PC-AUTH-0005');
  for (const key of ['items', 'actor', 'nextCursor', 'authorizedEmpty', 'observedAt'])
    expect(body).not.toHaveProperty(key);
  expect(JSON.stringify(body)).not.toContain('Current scoped workload');
});
it.each([false, true])(
  'conceals nonempty and empty catalogues when the final session is gone, empty=%s',
  async (empty) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(Response.json(catalogueResult(empty)))
      .mockResolvedValueOnce(new Response(null, { status: 401 }));
    const response = await readPrincipalCatalogue(
      request(catalogueSession, {}, '/api/v1/ui/principal-catalogue'),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).not.toHaveProperty('authorizedEmpty');
  },
);
it.each([
  [
    'foreign Participant',
    {
      items: [
        {
          ...catalogueResult().items[0],
          effect: { ...catalogueResult().items[0]!.effect, participantId },
        },
      ],
    },
  ],
  [
    'wrong state',
    {
      items: [
        {
          ...catalogueResult().items[0],
          effect: { ...catalogueResult().items[0]!.effect, state: 'REVOKED' },
        },
      ],
    },
  ],
  [
    'wrong kind',
    {
      items: [
        {
          ...catalogueResult().items[0],
          effect: { ...catalogueResult().items[0]!.effect, kind: 'USER' },
        },
      ],
    },
  ],
  ['bad cursor', { nextCursor: operationId }],
  ['false empty', { authorizedEmpty: true }],
  ['malformed effect', { items: [{ effect: { principalId: approvalId }, operationId: null }] }],
] as const)('rejects a %s page without final release or disclosure', async (_label, patch) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession))
    .mockResolvedValueOnce(Response.json({ ...catalogueResult(), ...patch }));
  const response = await readPrincipalCatalogue(
    request(
      catalogueSession,
      {},
      '/api/v1/ui/principal-catalogue?state=ACTIVE&kind=WORKLOAD&limit=1',
    ),
  );
  expect(response.status).toBe(503);
  expect(await response.json()).toMatchObject({ code: 'PC-INTEGRATION-5001' });
  expect(fetch).toHaveBeenCalledTimes(2);
});
it.each([
  'kind=USER&kind=WORKLOAD',
  'search=a&search=b',
  'limit=1&limit=2',
  'after=bad',
  'unknown=true',
  'state=wrong',
])('rejects raw duplicate or invalid catalogue query %s before owner dispatch', async (query) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession));
  const response = await readPrincipalCatalogue(
    request(catalogueSession, {}, `/api/v1/ui/principal-catalogue?${query}`),
  );
  expect(response.status).toBe(400);
  expect(fetch).toHaveBeenCalledTimes(1);
});
it.each([401, 403, 404, 503])(
  'preserves upstream denial/unavailability at %s without existence detail',
  async (status) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(
        Response.json({ title: 'protected-catalogue-detail', items: ['private'] }, { status }),
      );
    const response = await readPrincipalCatalogue(
      request(catalogueSession, {}, '/api/v1/ui/principal-catalogue'),
    );
    expect(response.status).toBe(status === 503 ? 503 : 404);
    const body = await response.json();
    expect(body).not.toHaveProperty('items');
    expect(JSON.stringify(body)).not.toContain('protected-catalogue-detail');
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
it('retains bounded ordered cursor pages in the actual nonfixture Participant', async () => {
  const first = catalogueResult();
  const secondRow = {
    ...first.items[0]!,
    effect: { ...first.items[0]!.effect, principalId: operationId },
  };
  const page = { ...first, items: [first.items[0]!, secondRow], nextCursor: operationId };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession))
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(catalogueSession));
  const response = await readPrincipalCatalogue(
    request(
      catalogueSession,
      {},
      '/api/v1/ui/principal-catalogue?state=ACTIVE&kind=WORKLOAD&limit=2',
    ),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ items: page.items, nextCursor: operationId });
  expect(fetch).toHaveBeenCalledTimes(3);
});
it.each(['duplicate', 'unordered', 'behind cursor'])(
  'rejects %s identities at the catalogue order boundary',
  async (kind) => {
    const page = catalogueResult();
    const row = page.items[0]!;
    const high = { ...row, effect: { ...row.effect, principalId: operationId } };
    const items = kind === 'duplicate' ? [row, row] : kind === 'unordered' ? [high, row] : [row];
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(Response.json({ ...page, items }));
    const response = await readPrincipalCatalogue(
      request(
        catalogueSession,
        {},
        `/api/v1/ui/principal-catalogue?limit=2${kind === 'behind cursor' ? `&after=${approvalId}` : ''}`,
      ),
    );
    expect(response.status).toBe(503);
    expect(await response.json()).not.toHaveProperty('items');
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
