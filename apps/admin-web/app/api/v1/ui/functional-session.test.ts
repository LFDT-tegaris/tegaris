import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { selectFunctionalActor } from './functional-session';
import * as runtime from './local-runtime';

vi.mock('./local-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./local-runtime')>()),
  localRuntimeConfig: vi.fn(),
  functionalIdentitySession: vi.fn(),
}));
function request(body: unknown, origin = 'https://demo.example.org') {
  return new NextRequest('https://demo.example.org/api/v1/ui/functional-session', {
    method: 'POST',
    headers: { origin, 'host': 'demo.example.org', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
const session = {
  sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000401',
  role: 'operator' as const,
  sessionId: '018f0000-0000-7000-8000-000000000401',
  participantId: '018f0000-0000-7000-8000-000000000101',
  principalId: '018f0000-0000-7000-8000-000000000111',
  contextMode: 'PLATFORM' as const,
  contextEpoch: '1',
  platformBootstrapEligible: true,
  stepUpVerifiedAt: null,
};
beforeEach(() => {
  vi.mocked(runtime.localRuntimeConfig).mockResolvedValue({
    functionalTest: {},
  } as unknown as runtime.LocalConfig);
  vi.mocked(runtime.functionalIdentitySession).mockResolvedValue(session);
});
afterEach(() => vi.clearAllMocks());

it('publishes only a selection confirmed by the native-session validator and seals HTTPS selection cookies', async () => {
  const response = await selectFunctionalActor(request({ role: 'operator', context: 'PLATFORM' }));
  expect(response.status).toBe(200);
  expect(runtime.functionalIdentitySession).toHaveBeenCalledWith(
    expect.anything(),
    'operator',
    'PLATFORM',
  );
  expect(await response.json()).toEqual({
    status: 'selected',
    role: 'operator',
    contextMode: 'PLATFORM',
  });
  expect(response.cookies.get('openpc_functional_actor')?.value).toBe('operator');
  expect(response.cookies.get('openpc_functional_context')?.value).toBe('PLATFORM');
  for (const cookie of response.cookies.getAll()) {
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe('strict');
  }
});
it.each([
  { role: 'administrator', context: 'PLATFORM' },
  { role: 'operator', context: 'GLOBAL' },
  { role: 'operator', context: 'PLATFORM', sessionToken: session.sessionToken },
])('rejects caller-supplied authority or unknown selections: %j', async (body) => {
  const response = await selectFunctionalActor(request(body));
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(runtime.functionalIdentitySession).not.toHaveBeenCalled();
  expect(response.cookies.getAll()).toEqual([]);
});
it('rejects cross-origin selection before native validation or cookie changes', async () => {
  const response = await selectFunctionalActor(
    request({ role: 'operator', context: 'PLATFORM' }, 'https://other.example'),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(runtime.functionalIdentitySession).not.toHaveBeenCalled();
  expect(response.cookies.getAll()).toEqual([]);
});
it('keeps failed or expired native authority from becoming a selection', async () => {
  vi.mocked(runtime.functionalIdentitySession).mockResolvedValue(undefined);
  const response = await selectFunctionalActor(request({ role: 'operator', context: 'PLATFORM' }));
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(response.cookies.getAll()).toEqual([]);
});
it('preserves the original role-only response and Participant default', async () => {
  vi.mocked(runtime.functionalIdentitySession).mockResolvedValue({
    ...session,
    contextMode: 'PARTICIPANT',
  });
  const response = await selectFunctionalActor(request({ role: 'operator' }));
  expect(await response.json()).toEqual({ status: 'selected', role: 'operator' });
  expect(runtime.functionalIdentitySession).toHaveBeenCalledWith(
    expect.anything(),
    'operator',
    undefined,
  );
  expect(response.cookies.get('openpc_functional_context')?.value).toBe('PARTICIPANT');
});
