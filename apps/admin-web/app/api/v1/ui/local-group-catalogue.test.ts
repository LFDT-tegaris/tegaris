// Pure BFF contract tests: every Identity/Participant HTTP response is mocked.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { encodeBffSession, type IdentitySession } from './local-runtime';
import { readGroupCatalogue } from './local-group-workbench';
const operator: IdentitySession = {
  sessionToken: 'mock-opaque-session',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const now = '2026-09-12T06:00:00.000000Z';
let root = '';
const original = { ...process.env };
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

const catalogueId = (value: number) => `018f0000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const catalogueSession: IdentitySession = {
  ...operator,
  participantId: catalogueId(102),
  privacyDomainId: catalogueId(202),
  sessionEpoch: '3',
  participantEpoch: '4',
  principalEpoch: '5',
  assignmentId: catalogueId(610),
  assignmentRowVersion: '6',
  authorityEnvelopeId: catalogueId(611),
  authorityEpoch: '7',
  delegationEpoch: '8',
  platformBootstrapEligible: false,
  availableContexts: [{ participantId: catalogueId(102), privacyDomainId: catalogueId(202) }],
};
function catalogueRequest(query = '', session = catalogueSession) {
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/group-catalogue${query}`, {
    headers: {
      cookie: `openpc_local_runtime_session=${encodeBffSession(session, Buffer.from('cookie'.repeat(32)))}`,
    },
  });
}
function catalogueItem(value = 801, overrides: Record<string, unknown> = {}) {
  const effect = {
    groupId: catalogueId(value),
    participantId: catalogueSession.participantId,
    groupName: 'Audit readers',
    createdAt: now,
    updatedAt: now,
    operationId: null,
    state: 'ACTIVE',
    revision: '1',
    ...overrides,
  };
  return { effect };
}
function catalogueResult(
  items: unknown[] = [catalogueItem()],
  overrides: Record<string, unknown> = {},
) {
  return {
    items,
    nextCursor: null,
    completeness: 'COMPLETE',
    authorizedEmpty: items.length === 0,
    observedAt: now,
    ...overrides,
  };
}
function catalogueFetch(page: unknown, current: IdentitySession = catalogueSession) {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession))
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(current));
}
async function expectCatalogueProblem(response: Response, code: string) {
  const body = await response.json();
  expect(body).toMatchObject({ code });
  for (const field of ['items', 'actor', 'nextCursor', 'authorizedEmpty', 'observedAt'])
    expect(body).not.toHaveProperty(field);
  expect(JSON.stringify(body)).not.toContain('private-owner-detail');
}
it('uses the actual nonfixture Participant/privacy with Bearer authorization, filtered UUID pagination and final admission', async () => {
  const items = [
    catalogueItem(802, { state: 'RETIRED' }),
    catalogueItem(803, { state: 'RETIRED' }),
  ];
  const fetch = catalogueFetch(catalogueResult(items, { nextCursor: catalogueId(803) }));
  const response = await readGroupCatalogue(
    catalogueRequest(`?search=aUdIt&state=RETIRED&after=${catalogueId(801)}&limit=2`),
  );
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({
    items,
    nextCursor: catalogueId(803),
    actor: {
      sessionId: catalogueSession.sessionId,
      principalId: catalogueSession.principalId,
      participantId: catalogueSession.participantId,
      privacyDomainId: catalogueSession.privacyDomainId,
      contextEpoch: catalogueSession.contextEpoch,
    },
  });
  expect(String(fetch.mock.calls[1]?.[0])).toBe(
    `http://gateway:8080/v1/participants/${catalogueSession.participantId}/groups?search=aUdIt&state=RETIRED&limit=2&after=${catalogueId(801)}`,
  );
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    cache: 'no-store',
    headers: {
      'Authorization': `Bearer ${catalogueSession.sessionToken}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${catalogueSession.privacyDomainId}`,
    },
  });
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(fetch.mock.calls[1]?.[1]?.method).toBeUndefined();
  expect(fetch.mock.calls.some(([url]) => /approve|proposal|commit|csrf/u.test(String(url)))).toBe(
    false,
  );
});
it('returns a final-admitted authorized empty page and allows token/step-up metadata changes', async () => {
  const fetch = catalogueFetch(catalogueResult([]), {
    ...catalogueSession,
    sessionToken: 'renewed-opaque-token',
    stepUpVerifiedAt: now,
  });
  const response = await readGroupCatalogue(catalogueRequest());
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    items: [],
    authorizedEmpty: true,
    nextCursor: null,
  });
  expect(fetch).toHaveBeenCalledTimes(3);
});
const catalogueDrift: [string, Partial<IdentitySession>][] = [
  ['session', { sessionId: catalogueId(119) }],
  ['principal', { principalId: catalogueId(113) }],
  ['Participant', { participantId: catalogueId(103) }],
  ['privacy', { privacyDomainId: catalogueId(203) }],
  ['context', { contextEpoch: '9' }],
  ['mode', { contextMode: 'PLATFORM' }],
  ['role', { role: 'viewer' }],
  ['session epoch', { sessionEpoch: '9' }],
  ['Participant epoch', { participantEpoch: '9' }],
  ['principal epoch', { principalEpoch: '9' }],
  ['assignment', { assignmentId: catalogueId(612) }],
  ['assignment version', { assignmentRowVersion: '9' }],
  ['authority envelope', { authorityEnvelopeId: catalogueId(613) }],
  ['authority epoch', { authorityEpoch: '9' }],
  ['delegation epoch', { delegationEpoch: '9' }],
  ['assignment removed', { assignmentId: undefined }],
  ['privacy removed', { privacyDomainId: undefined }],
  ['available contexts', { availableContexts: [] }],
  ['bootstrap eligibility', { platformBootstrapEligible: true }],
];
it.each(catalogueDrift)(
  'rejects full-session %s drift before disclosing a populated or empty catalogue',
  async (_, changed) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    for (const items of [[catalogueItem()], []]) {
      fetch
        .mockResolvedValueOnce(Response.json(catalogueSession))
        .mockResolvedValueOnce(Response.json(catalogueResult(items)))
        .mockResolvedValueOnce(Response.json({ ...catalogueSession, ...changed }));
      await expectCatalogueProblem(await readGroupCatalogue(catalogueRequest()), 'PC-AUTH-0005');
    }
    expect(fetch).toHaveBeenCalledTimes(6);
  },
);
it.each(['revoked', 'transport failure'])(
  'rejects final authentication %s even after a valid empty page',
  async (reason) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(Response.json(catalogueResult([])));
    if (reason === 'revoked') fetch.mockResolvedValueOnce(Response.json({}, { status: 403 }));
    else fetch.mockRejectedValueOnce(new Error('private-owner-detail'));
    await expectCatalogueProblem(await readGroupCatalogue(catalogueRequest()), 'PC-AUTH-0005');
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
it.each([
  [
    'foreign Participant',
    catalogueResult([catalogueItem(801, { participantId: catalogueId(103) })]),
    '',
  ],
  ['wrong state', catalogueResult([catalogueItem(801, { state: 'RETIRED' })]), '?state=ACTIVE'],
  ['wrong filter', catalogueResult(), '?search=missing'],
  [
    'requested limit exceeded',
    catalogueResult([catalogueItem(801), catalogueItem(802)]),
    '?limit=1',
  ],
  ['duplicate IDs', catalogueResult([catalogueItem(801), catalogueItem(801)]), ''],
  ['descending IDs', catalogueResult([catalogueItem(802), catalogueItem(801)]), ''],
  ['at cursor', catalogueResult(), `?after=${catalogueId(801)}`],
  ['before cursor', catalogueResult(), `?after=${catalogueId(802)}`],
  ['partial-page cursor', catalogueResult([catalogueItem()], { nextCursor: catalogueId(801) }), ''],
  [
    'wrong last-row cursor',
    catalogueResult([catalogueItem()], { nextCursor: catalogueId(802) }),
    '?limit=1',
  ],
  ['empty cursor', catalogueResult([], { nextCursor: catalogueId(801) }), ''],
  ['false empty proof', catalogueResult([], { authorizedEmpty: false }), ''],
  ['contradictory empty proof', catalogueResult([catalogueItem()], { authorizedEmpty: true }), ''],
  ['non-UUID ID', catalogueResult([catalogueItem(801, { groupId: 'private-owner-detail' })]), ''],
  ['incomplete page', catalogueResult([], { completeness: 'PARTIAL' }), ''],
])('rejects malformed producer %s without a page projection', async (_, page, query) => {
  catalogueFetch(page);
  await expectCatalogueProblem(
    await readGroupCatalogue(catalogueRequest(query)),
    'PC-INTEGRATION-5001',
  );
});
it.each([
  '?state=ACTIVE&state=ALL',
  '?search=Audit&search=ignored',
  '?limit=1&limit=2',
  `?after=${catalogueId(801)}&after=${catalogueId(802)}`,
  '?unknown=value',
  '?limit=0',
  '?limit=51',
  '?after=invalid',
])('rejects ambiguous/invalid query %s without contacting the catalogue owner', async (query) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession));
  await expectCatalogueProblem(await readGroupCatalogue(catalogueRequest(query)), 'PC-DATA-6004');
  expect(fetch).toHaveBeenCalledTimes(1);
});
it.each([
  [403, 'PC-AUTH-0005'],
  [404, 'PC-AUTH-0005'],
  [409, 'PC-RUNTIME-3007'],
  [412, 'PC-DATA-6007'],
  [422, 'PC-DATA-6004'],
  [503, 'PC-INTEGRATION-5001'],
] as const)(
  'preserves safe upstream status %s mapping without relaying private text',
  async (status, code) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(
        Response.json({ title: 'private-owner-detail', code: 'private-owner-detail' }, { status }),
      );
    await expectCatalogueProblem(await readGroupCatalogue(catalogueRequest()), code);
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
it.each(['transport', 'unreadable'])(
  'redacts %s owner errors rather than authorizing an empty page',
  async (failure) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession));
    if (failure === 'transport') fetch.mockRejectedValueOnce(new Error('private-owner-detail'));
    else
      fetch.mockResolvedValueOnce(
        new Response('private-owner-detail', { headers: { 'Content-Type': 'application/json' } }),
      );
    await expectCatalogueProblem(
      await readGroupCatalogue(catalogueRequest()),
      'PC-INTEGRATION-5001',
    );
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
it('refuses initial invalid context before any catalogue call', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...catalogueSession, contextMode: 'PLATFORM' }));
  await expectCatalogueProblem(await readGroupCatalogue(catalogueRequest()), 'PC-AUTH-0005');
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([1, 25, 50])(
  'honors a real requested limit of %s and the mixed ALL-state filter',
  async (limit) => {
    const items = Array.from({ length: limit }, (_, index) =>
      catalogueItem(801 + index, { state: index % 2 ? 'RETIRED' : 'ACTIVE' }),
    );
    const fetch = catalogueFetch(catalogueResult(items));
    const response = await readGroupCatalogue(
      catalogueRequest(`?search=%20AUDIT%20&state=ALL&limit=${limit}`),
    );
    expect(response.status).toBe(200);
    expect((await response.json()).items).toHaveLength(limit);
    expect(String(fetch.mock.calls[1]?.[0])).toContain(`search=AUDIT&state=ALL&limit=${limit}`);
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
