import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import {
  createPolicySet,
  policySetCreateAction,
  readPolicySets,
} from './local-policy-set-workbench';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<object>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const pid = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000007201';
const resource = '018f0000-0000-7000-8000-000000008301';
const requestKey = '018f0000-0000-7000-8000-000000008302';
const session = {
  role: 'viewer',
  contextMode: 'PARTICIPANT',
  participantId: pid,
  privacyDomainId: privacy,
  sessionToken: 'private-session',
  principalId: resource,
  contextEpoch: '1',
};
const draft = {
  policySetId: `urn:openpc:policy-set:${resource}`,
  participantId: `urn:openpc:participant:${pid}`,
  name: 'Scope policy',
  activeVersionDigest: null,
  state: 'DRAFT',
  revision: '1',
  createdAt: '2026-09-22T00:00:00.000000Z',
  updatedAt: '2026-09-22T00:00:00.000000Z',
};
const page = {
  items: [draft],
  total: '1',
  nextCursor: null,
  completeness: 'COMPLETE',
  authorizedEmpty: false,
  snapshotRevision: '1',
};
const request = (body: unknown) =>
  new NextRequest('http://localhost/api/v1/ui/policy-sets', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'origin': 'http://localhost',
      'host': 'localhost',
    },
    body: JSON.stringify(body),
  });
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session as Awaited<ReturnType<typeof authenticated>>);
  vi.mocked(localRuntimeConfig).mockResolvedValue({ publicApiUrl: 'http://owner' } as Awaited<
    ReturnType<typeof localRuntimeConfig>
  >);
});
afterEach(() => {
  vi.restoreAllMocks();
});

it('creates only an explicit draft with server-derived context and stable command identity', async () => {
  const operation = {
    operationId: resource,
    resourceRef: `urn:openpc:resource:${resource}`,
    actionIntentId: policySetCreateAction.id,
    intentDigest: policySetCreateAction.digest,
    idempotencyKey: `policy-set-${requestKey}`,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    revision: '1',
    createdAt: draft.createdAt,
    updatedAt: draft.updatedAt,
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(32) }))
    .mockResolvedValueOnce(Response.json(operation, { status: 202 }));
  const response = await createPolicySet(
    request({ requestKey, name: draft.name, reason: 'Initial draft' }),
  );
  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({ operation });
  const [url, init] = fetch.mock.calls[1]!;
  expect(url).toBe('http://owner/api/v1/policy-sets');
  expect(JSON.parse(String(init?.body))).toEqual({
    participantId: draft.participantId,
    name: draft.name,
    activeVersionDigest: null,
    reason: 'Initial draft',
    actionIntentId: policySetCreateAction.id,
    actionIntentDigest: policySetCreateAction.digest,
  });
  expect(new Headers(init?.headers).get('openpc-privacy-domain-id')).toBe(
    `urn:openpc:privacy-domain:${privacy}`,
  );
  expect(response.headers.get('cache-control')).toBe('no-store');
});

it('reads actual owner resources and refuses malformed or foreign-context selectors', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(draft));
  expect(
    await (await readPolicySets(new NextRequest('http://localhost/api/v1/ui/policy-sets'))).json(),
  ).toEqual(page);
  expect(
    await (
      await readPolicySets(
        new NextRequest(`http://localhost/api/v1/ui/policy-sets?policySetId=${draft.policySetId}`),
      )
    ).json(),
  ).toEqual(draft);
  for (const query of [
    'participantId=foreign',
    'cursor=a&cursor=b',
    'policySetId=wrong',
    `policySetId=${draft.policySetId}&cursor=a`,
  ])
    expect(
      (await readPolicySets(new NextRequest(`http://localhost/api/v1/ui/policy-sets?${query}`)))
        .status,
    ).toBe(400);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('denies caller authority fields, malformed owner results and unauthorized sessions', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  for (const extra of [
    { participantId: pid },
    { activeVersionDigest: `sha256:${'12'.repeat(32)}` },
    { state: 'ACTIVE' },
  ])
    expect(
      (
        await createPolicySet(
          request({ requestKey, name: draft.name, reason: 'Initial', ...extra }),
        )
      ).status,
    ).toBe(400);
  expect(fetch).not.toHaveBeenCalled();
  fetch.mockResolvedValueOnce(Response.json({ items: [{ ...draft, state: 'PREPARED' }] }));
  expect(
    (await readPolicySets(new NextRequest('http://localhost/api/v1/ui/policy-sets'))).status,
  ).toBeGreaterThanOrEqual(400);
  vi.mocked(authenticated).mockResolvedValue({ ...session, contextMode: 'PLATFORM' } as Awaited<
    ReturnType<typeof authenticated>
  >);
  expect(
    (await createPolicySet(request({ requestKey, name: draft.name, reason: 'Initial' }))).status,
  ).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('rejects well-formed owner data for a different participant or selected policy', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({
        ...page,
        items: [{ ...draft, participantId: `urn:openpc:participant:${resource}` }],
      }),
    )
    .mockResolvedValueOnce(
      Response.json({ ...draft, policySetId: `urn:openpc:policy-set:${requestKey}` }),
    );
  expect(
    (await readPolicySets(new NextRequest('http://localhost/api/v1/ui/policy-sets'))).status,
  ).toBeGreaterThanOrEqual(400);
  expect(
    (
      await readPolicySets(
        new NextRequest(`http://localhost/api/v1/ui/policy-sets?policySetId=${draft.policySetId}`),
      )
    ).status,
  ).toBeGreaterThanOrEqual(400);
});
