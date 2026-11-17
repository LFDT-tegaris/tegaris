import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import { readPolicyVersions } from './local-policy-version-workbench';
vi.mock('./local-runtime', async (original) => ({
  ...(await original<object>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const session = {
  contextMode: 'PARTICIPANT',
  sessionToken: 'private-token',
  sessionId: id(117),
  principalId: id(111),
  participantId: id(101),
  privacyDomainId: id(201),
  contextEpoch: '2',
};
const actor = {
  sessionId: session.sessionId,
  principalId: session.principalId,
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId,
  contextEpoch: session.contextEpoch,
};
const version = {
  policyVersionId: `urn:openpc:policy-version:${id(921)}`,
  policySetId: `urn:openpc:policy-set:${id(920)}`,
  semanticVersion: '1.2.0',
  normalizedPolicyDigest: `sha256:${'a1'.repeat(32)}`,
  dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
  state: 'DRAFT',
  revision: '1',
  createdAt: '2026-09-22T15:01:01.123456Z',
  updatedAt: '2026-09-22T15:01:01.123456Z',
};
const page = {
  items: [version],
  nextCursor: null,
  total: '1',
  authorizedEmpty: false,
  completeness: 'COMPLETE',
  snapshotRevision: '1',
};
const request = (query = '') =>
  new NextRequest(
    `http://localhost/api/v1/ui/policy-versions?policySetId=${version.policySetId}${query}`,
  );
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session as Awaited<ReturnType<typeof authenticated>>);
  vi.mocked(localRuntimeConfig).mockResolvedValue({ publicApiUrl: 'http://owner' } as Awaited<
    ReturnType<typeof localRuntimeConfig>
  >);
});
afterEach(() => vi.restoreAllMocks());
it('uses the public collection with a server-owned scope filter and returns a bound display projection', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page));
  const response = await readPolicyVersions(request());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ ...page, actor, policySetId: version.policySetId });
  const [url, options] = fetch.mock.calls[0]!;
  const native = new URL(String(url));
  expect(native.pathname).toBe('/api/v1/policy-versions');
  expect(native.searchParams.get('filter')).toBe(`policySetId:eq:${version.policySetId}`);
  expect(options?.cache).toBe('no-store');
  expect(options?.method).toBeUndefined();
  expect(vi.mocked(authenticated)).toHaveBeenCalledTimes(2);
});
it('verifies the exact selected version through its public resource read', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(version));
  const response = await readPolicyVersions(request(`&policyVersionId=${version.policyVersionId}`));
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ actor, version });
  expect(String(fetch.mock.calls[0]![0])).toBe(
    `http://owner/api/v1/policy-versions/${encodeURIComponent(version.policyVersionId)}`,
  );
});
it.each([
  'sessionId',
  'principalId',
  'participantId',
  'privacyDomainId',
  'contextEpoch',
  'sessionToken',
] as const)('withholds records if the current %s changes during the owner read', async (field) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page));
  vi.mocked(authenticated)
    .mockResolvedValueOnce(session as Awaited<ReturnType<typeof authenticated>>)
    .mockResolvedValueOnce({
      ...session,
      [field]: field === 'contextEpoch' ? '99' : id(999),
    } as Awaited<ReturnType<typeof authenticated>>);
  const response = await readPolicyVersions(request());
  expect(response.status).not.toBe(200);
  expect(await response.json()).not.toHaveProperty('items');
});
it.each([
  { ...page, items: [{ ...version, policySetId: `urn:openpc:policy-set:${id(999)}` }] },
  { ...page, authorizedEmpty: true },
  { ...page, items: [version, version], total: '2' },
  { ...page, items: [{ ...version, semanticCbor: 'hidden' }] },
  { ...page, items: [version], total: '0' },
])('rejects inconsistent or excess owner data', async (data) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(data));
  const response = await readPolicyVersions(request());
  expect(response.status).not.toBe(200);
  expect(await response.json()).not.toHaveProperty('items');
});
it.each([403, 500, 503])(
  'does not turn an owner %s into an authorized empty list',
  async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ error: 'private diagnostic' }, { status }),
    );
    const response = await readPolicyVersions(request());
    expect(response.status).not.toBe(200);
    expect(await response.text()).not.toContain('private diagnostic');
  },
);
it.each(['&cursor=x&policyVersionId=bad', '&policySetId=duplicate', '&unknown=x'])(
  'rejects invalid query %s without calling the owner',
  async (query) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    const response = await readPolicyVersions(request(query));
    expect(response.status).not.toBe(200);
    expect(fetch).not.toHaveBeenCalled();
  },
);
