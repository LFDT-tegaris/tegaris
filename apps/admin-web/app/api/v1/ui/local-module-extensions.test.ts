import { NextRequest } from 'next/server';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { authenticated, localRuntimeConfig } from './local-runtime';
import { readModuleExtensions, observeModuleExtensions } from './local-module-extensions';

// BFF contract fixtures only. Actual Identity/module journey acceptance remains
// in the admitted runtime; no mock result can open publisher/bundle admission.
vi.mock('./local-runtime', async () => ({
  ...(await vi.importActual<typeof import('./local-runtime')>('./local-runtime')),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const session = {
  sessionToken: 'unit-only',
  role: 'operator' as const,
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextMode: 'PARTICIPANT' as const,
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const runtime = {
  publicApiUrl: 'http://owner.invalid',
  identityUrl: 'http://identity.invalid',
  factUrl: 'http://fact.invalid',
  policyUrl: 'http://policy.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'unit-only',
  factToken: 'unit-only',
  policyToken: 'unit-only',
  cookieKey: Buffer.alloc(32),
};
const module = {
  moduleId: `urn:openpc:resource:${id(5)}`,
  name: 'pc.example',
  semanticVersion: '1.0.0',
  manifestDigest: `sha256:${'a'.repeat(64)}`,
  supportProfile: 'R1',
  state: 'ACTIVE',
  revision: '3',
  createdAt: '2026-09-25T00:00:00.000001Z',
  updatedAt: '2026-09-25T00:00:00.000002Z',
};
const page = () => ({
  items: [module],
  nextCursor: null,
  total: '1',
  authorizedEmpty: false,
  completeness: 'COMPLETE',
  snapshotRevision: '1',
});
const request = (query = 'routeId=ROUTE-MODULE-LIFECYCLE') =>
  new NextRequest(`http://localhost/api/v1/ui/module-extensions?${query}`);
beforeEach(() => {
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(Response.json(page(), { headers: { 'Cache-Control': 'no-store' } })),
  );
});
afterEach(() => {
  vi.resetAllMocks();
  vi.unstubAllGlobals();
});
it('does not admit ACTIVE module rows without the canonical publisher/bundle contract', async () => {
  const response = await readModuleExtensions(request());
  expect(response.status).toBe(503);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({
    code: 'PC-INTEGRATION-5001',
    truthState: 'UNAVAILABLE',
  });
  expect(fetch).toHaveBeenCalledTimes(1);
  const [url, init] = vi.mocked(fetch).mock.calls[0]!;
  expect(String(url)).toBe('http://owner.invalid/api/v1/modules?limit=200&sort=moduleId');
  expect(init).toMatchObject({ cache: 'no-store', redirect: 'error' });
  expect(authenticated).toHaveBeenCalledTimes(2);
});
it('does not turn a genuine empty collection into an admitted empty UI catalogue', async () => {
  vi.mocked(fetch).mockResolvedValue(
    Response.json({ ...page(), items: [], total: '0', authorizedEmpty: true }),
  );
  expect((await readModuleExtensions(request())).status).toBe(503);
});
it.each([
  'routeId=ROUTE-MODULE-LIFECYCLE&enabled=true',
  'routeId=ROUTE-MODULE-LIFECYCLE&routeId=ROUTE-PLATFORM-ADMINISTRATION',
  'routeId=ROUTE-MODULE-LIFECYCLE&actorKey=forged',
  'routeId=ROUTE-MODULE-LIFECYCLE&objectRef=foreign',
  'routeId=not-a-route',
])('rejects caller-selected admission/query state: %s', async (query) => {
  expect((await readModuleExtensions(request(query))).status).toBe(400);
  expect(fetch).not.toHaveBeenCalled();
});
it('denies unauthenticated and changed sessions without returning source data', async () => {
  vi.mocked(authenticated).mockResolvedValueOnce(undefined);
  expect((await readModuleExtensions(request())).status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
  vi.mocked(authenticated)
    .mockResolvedValueOnce(session)
    .mockResolvedValueOnce({ ...session, contextEpoch: '2' });
  const response = await readModuleExtensions(request());
  expect(response.status).toBe(404);
  expect(JSON.stringify(await response.json())).not.toContain('pc.example');
});
it.each([
  { completeness: 'UNKNOWN' },
  { total: '2' },
  { items: [module, module], total: '2' },
  { nextCursor: 'pc1.a.b' },
  { authorizedEmpty: true },
])('does not use incomplete/ambiguous readback %j', async (change) => {
  vi.mocked(fetch).mockResolvedValue(Response.json({ ...page(), ...change }));
  expect((await readModuleExtensions(request())).status).toBe(503);
});
it('returns typed failure, never a fixture CURRENT frame, while admission is closed', async () => {
  const response = await observeModuleExtensions(request());
  expect(response.status).toBe(503);
  expect(response.headers.get('content-type')).toContain('application/problem+json');
  expect(await response.text()).not.toContain('event:');
});
