import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readAccessReview } from './local-access-review';
import {
  authenticated,
  localRuntimeConfig,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
vi.mock('./local-runtime', async (original) => ({
  ...(await original<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const session = {
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextEpoch: '1',
  contextMode: 'PARTICIPANT',
  sessionToken: 'test-only',
  role: 'operator',
  stepUpVerifiedAt: null,
} satisfies IdentitySession;
const page = {
  authoritative: false,
  participantId: id(3),
  privacyDomainId: id(4),
  subject: { id: id(5), kind: 'USER', state: 'ACTIVE', authorityEpoch: '1' },
  participantEpoch: '1',
  observedAt: new Date().toISOString(),
  items: [],
  nextCursor: null,
  completeness: 'COMPLETE',
  authorizedEmpty: true,
  decisionBoundary: 'CURRENT_GRANT_INTERSECTION_REQUIRES_LIVE_REQUEST_AUTHORIZATION',
};
const request = (suffix = '') =>
  new NextRequest(`http://localhost:8080/api/v1/ui/access-review?subjectId=${id(5)}${suffix}`);
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue({
    publicApiUrl: 'http://owner.test',
  } as LocalConfig);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});
it('binds an authorized empty review to the real subject and context without caching', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(page));
  const response = await readAccessReview(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect((await response.json()).page).toEqual(page);
  expect(String(fetcher.mock.calls[0]![0])).toContain(
    `/v1/participants/${id(3)}/access-review/${id(5)}`,
  );
  expect(new Headers(fetcher.mock.calls[0]![1]?.headers).get('Authorization')).toBe(
    'Bearer test-only',
  );
});
it.each([
  { subject: { ...page.subject, id: id(6) } },
  { privacyDomainId: id(7) },
  { authorizedEmpty: false },
  { completeness: 'MORE' },
])('rejects mismatched or incomplete owner readback: %j', async (change) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ ...page, ...change }));
  expect((await readAccessReview(request())).status).toBeGreaterThanOrEqual(400);
});
it('rejects duplicate selectors before contacting the owner', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  expect((await readAccessReview(request(`&subjectId=${id(6)}`))).status).toBe(400);
  expect(fetcher).not.toHaveBeenCalled();
});
it('does not convert an unavailable owner into empty access', async () => {
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('unavailable'));
  const response = await readAccessReview(request());
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(await response.json()).not.toHaveProperty('page');
});
