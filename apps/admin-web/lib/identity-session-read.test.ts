import { expect, it } from 'vitest';
import { readIdentitySessionResponse } from './identity-session-read';

const session = {
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
it('accepts a validated current snapshot without exposing an unexpected session token', async () => {
  expect(
    await readIdentitySessionResponse(
      Promise.resolve(Response.json({ ...session, sessionToken: 'private' })),
    ),
  ).toEqual({
    state: 'AUTHENTICATED',
    session,
  });
});
it('recognizes only the explicit owner denial as signed out', async () => {
  expect(
    await readIdentitySessionResponse(
      Promise.resolve(Response.json({ code: 'PC-AUTH-0005' }, { status: 401 })),
    ),
  ).toEqual({ state: 'SIGNED_OUT' });
});
it.each([400, 403, 404, 429, 500, 502, 503, 504])(
  'keeps HTTP %s distinct from sign-out',
  async (status) => {
    expect(
      await readIdentitySessionResponse(
        Promise.resolve(Response.json({ code: 'PC-AUTH-0005' }, { status })),
      ),
    ).toEqual({ state: 'UNAVAILABLE' });
  },
);
it.each([
  { ...session, principalId: 'invalid' },
  { ...session, role: 'admin' },
  { ...session, contextEpoch: '0' },
  { ...session, contextMode: 'PLATFORM' },
  { ...session, privacyDomainId: undefined },
  { ...session, stepUpVerifiedAt: 'invalid' },
  {
    ...session,
    availableContexts: [{ participantId: session.participantId, privacyDomainId: 'invalid' }],
  },
  { ...session, authorityEpoch: 'unknown' },
  { ...session, assignmentId: 'invalid' },
])('conceals malformed owner snapshots: %j', async (value) => {
  expect(await readIdentitySessionResponse(Promise.resolve(Response.json(value)))).toEqual({
    state: 'UNAVAILABLE',
  });
});
it.each([
  () => Response.json({ code: 'unexpected' }, { status: 401 }),
  () => new Response('not json', { status: 401, headers: { 'content-type': 'application/json' } }),
  () => new Response('not json', { status: 200, headers: { 'content-type': 'application/json' } }),
  () => new Response(JSON.stringify(session), { headers: { 'content-type': 'text/html' } }),
  () => new Response(null, { status: 204 }),
])('does not infer sign-out from an unreadable or unrecognized response', async (response) => {
  expect(await readIdentitySessionResponse(Promise.resolve(response()))).toEqual({
    state: 'UNAVAILABLE',
  });
});
it('treats transport rejection as unavailable without retaining private error details', async () => {
  expect(
    await readIdentitySessionResponse(Promise.reject(new Error('private diagnostic'))),
  ).toEqual({ state: 'UNAVAILABLE' });
});

it('accepts the original zero delegation epoch for direct authority', async () => {
  expect(
    await readIdentitySessionResponse(
      Promise.resolve(Response.json({ ...session, delegationEpoch: '0' })),
    ),
  ).toEqual({ state: 'AUTHENTICATED', session: { ...session, delegationEpoch: '0' } });
});
