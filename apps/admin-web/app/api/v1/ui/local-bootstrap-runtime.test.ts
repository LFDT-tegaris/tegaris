import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, type IdentitySession } from './local-runtime';
import {
  beginInitialWebAuthnRegistration,
  completeInitialWebAuthnRegistration,
  selectLocalParticipantContext,
  readLocalWebAuthnEnrollment,
} from './local-bootstrap-runtime';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000701';
const nextSessionId = '018f0000-0000-7000-8000-000000000702';
const enrollmentId = '018f0000-0000-7000-8000-000000000711';
const credentialId = '018f0000-0000-7000-8000-000000000712';
const challenge = 'initial-registration-challenge-000000000000000001';
const platformSession: IdentitySession = {
  sessionToken: `${participantId}.${sessionId}`,
  role: 'operator',
  sessionId,
  principalId,
  participantId,
  contextMode: 'PLATFORM',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const participantSession: IdentitySession = {
  ...platformSession,
  sessionToken: `${participantId}.${nextSessionId}`,
  sessionId: nextSessionId,
  contextMode: 'PARTICIPANT',
  privacyDomainId,
  contextEpoch: '2',
  stepUpVerifiedAt: '2026-09-12T05:00:00.000Z',
};
let root = '';
const original = { ...process.env };

function request(path: string, cookie: string, body: unknown, origin = 'http://localhost:8080') {
  return new NextRequest(`${origin}${path}`, {
    method: 'POST',
    headers: {
      cookie,
      'host': new URL(origin).host,
      'origin': origin,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function ownerResponse(body: unknown, status = 200, sessionToken?: string) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      ...(sessionToken === undefined
        ? {}
        : { 'set-cookie': `__Host-openpc_session=${sessionToken}; Path=/; HttpOnly` }),
    },
  });
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-bff-bootstrap-'));
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

it('forwards initial registration with sealed session custody and an authenticated browser origin', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(platformSession))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(
      ownerResponse(
        {
          enrollmentId,
          expiresAt: '2026-09-12T05:05:00.000Z',
          publicKey: {
            challenge,
            rp: { id: 'localhost', name: 'OpenPC' },
            user: {
              id: Buffer.from(principalId).toString('base64url'),
              name: principalId,
              displayName: 'Local operator',
            },
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
            excludeCredentials: [],
          },
        },
        201,
      ),
    );
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const cookie = `openpc_local_runtime_session=${encodeBffSession(platformSession, cookieKey)}`;
  const response = await beginInitialWebAuthnRegistration(
    request('/api/v1/ui/webauthn/initial-registration/options', cookie, {
      hardwareAttestation: true,
    }),
  );

  expect(response.status).toBe(201);
  expect(await response.json()).toMatchObject({ enrollmentId, publicKey: { challenge } });
  expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toEqual({
    hardwareAttestation: true,
  });
  expect(fetchMock.mock.calls[2]?.[1]?.headers).toMatchObject({
    'Authorization': `Bearer ${'identity'.repeat(32)}`,
    'Cookie': `__Host-openpc_session=${platformSession.sessionToken}`,
    'Origin': 'http://identity:3001',
    'X-OpenPC-Browser-Origin': 'http://localhost:8080',
    'X-CSRF-Token': 'c'.repeat(43),
  });
});

it('passes a bounded attestation response to the identity owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(platformSession))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(
      ownerResponse(
        {
          credentialId,
          externalCredentialId: 'ZXh0ZXJuYWwtY3JlZGVudGlhbA',
          credentialEpoch: '1',
          state: 'ACTIVE',
        },
        201,
      ),
    );
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const cookie = `openpc_local_runtime_session=${encodeBffSession(platformSession, cookieKey)}`;
  const response = await completeInitialWebAuthnRegistration(
    request('/api/v1/ui/webauthn/initial-registration/complete', cookie, {
      enrollmentId,
      response: {
        id: 'ZXh0ZXJuYWwtY3JlZGVudGlhbA',
        rawId: 'ZXh0ZXJuYWwtY3JlZGVudGlhbA',
        type: 'public-key',
        response: {
          attestationObject: 'YXR0ZXN0YXRpb24',
          clientDataJSON: 'Y2xpZW50LWRhdGE',
          transports: ['internal'],
        },
        clientExtensionResults: {},
        authenticatorAttachment: 'platform',
      },
    }),
  );

  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({
    credentialId,
    externalCredentialId: 'ZXh0ZXJuYWwtY3JlZGVudGlhbA',
    credentialEpoch: '1',
    state: 'ACTIVE',
  });
  expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toMatchObject({ enrollmentId });
});

it.each(['http://localhost:8080', 'https://demo.example.org'])(
  'reseals only an owner-rotated Participant session after authoritative readback (%s)',
  async (origin) => {
    const selected = {
      sessionId: nextSessionId,
      sessionToken: participantSession.sessionToken,
      principalId,
      participantId,
      contextMode: 'PARTICIPANT',
      privacyDomainId,
      contextEpoch: '2',
      participantEpoch: '1',
      authorityEpoch: '1',
      sessionEpoch: '2',
      refreshFamilyId: '018f0000-0000-7000-8000-000000000703',
      state: 'ACTIVE',
      issuedAt: '2026-09-12T05:00:00.000Z',
      lastSeenAt: '2026-09-12T05:00:00.000Z',
      idleExpiresAt: '2026-09-12T05:30:00.000Z',
      absoluteExpiresAt: '2026-09-12T17:00:00.000Z',
      stepUpVerifiedAt: '2026-09-12T05:00:00.000Z',
    };
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(platformSession))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(ownerResponse(selected, 201, participantSession.sessionToken))
      .mockResolvedValueOnce(Response.json(participantSession));
    const cookieKey = Buffer.from('cookie'.repeat(32));
    const cookie = `openpc_local_runtime_session=${encodeBffSession(platformSession, cookieKey)}`;
    const response = await selectLocalParticipantContext(
      request('/api/v1/ui/session/context', cookie, { participantId, privacyDomainId }, origin),
    );

    expect(response.status).toBe(201);
    expect(response.cookies.get('openpc_local_runtime_session')?.secure).toBe(
      origin.startsWith('https:'),
    );
    expect(await response.json()).toEqual({
      sessionId: nextSessionId,
      participantId,
      contextMode: 'PARTICIPANT',
      privacyDomainId,
      contextEpoch: '2',
    });
    expect(response.headers.get('set-cookie')).toContain('openpc_local_runtime_session=');
    expect(response.headers.get('set-cookie')).not.toContain(participantSession.sessionToken);
  },
);

it('rejects an enrollment action left open in a different authenticated session', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(platformSession))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }));
  const cookie = `openpc_local_runtime_session=${encodeBffSession(platformSession, Buffer.from('cookie'.repeat(32)))}`;
  const response = await beginInitialWebAuthnRegistration(
    request('/api/v1/ui/webauthn/initial-registration/options', cookie, {
      expectedSessionId: nextSessionId,
    }),
  );
  expect(response.status).toBe(404);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

async function functionalContextFixture() {
  const actor = {
    sessionToken: participantSession.sessionToken,
    platformSessionToken: platformSession.sessionToken,
    principalId,
    participantId,
    privacyDomainId,
    credentialId,
    assertionCredentialId: credentialId,
    privateKeyFile: join(root, 'operator.der'),
    counterFile: join(root, 'operator.counter'),
  };
  const profile = {
    version: 1,
    actors: {
      operator: actor,
      viewer: {
        ...actor,
        sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000703`,
        platformSessionToken: `${participantId}.018f0000-0000-7000-8000-000000000704`,
        principalId: '018f0000-0000-7000-8000-000000000112',
        credentialId: '018f0000-0000-7000-8000-000000000713',
        assertionCredentialId: '018f0000-0000-7000-8000-000000000713',
        privateKeyFile: join(root, 'viewer.der'),
        counterFile: join(root, 'viewer.counter'),
      },
    },
  };
  await writeFile(join(root, 'functional.json'), JSON.stringify(profile));
  Object.assign(process.env, {
    OPENPC_FUNCTIONAL_TEST: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_FUNCTIONAL_TEST_PROFILE_FILE: join(root, 'functional.json'),
  });
  return 'openpc_functional_actor=operator; openpc_functional_context=PLATFORM';
}
it('selects the existing native Participant session in functional mode without rotating or changing the Platform session', async () => {
  const cookie = await functionalContextFixture();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...platformSession, platformBootstrapEligible: true }))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json(participantSession));
  const response = await selectLocalParticipantContext(
    request(
      '/api/v1/ui/session/context',
      cookie,
      { participantId, privacyDomainId, expectedSessionId: sessionId },
      'https://demo.example.org',
    ),
  );
  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({
    sessionId: nextSessionId,
    participantId,
    contextMode: 'PARTICIPANT',
    privacyDomainId,
    contextEpoch: '2',
  });
  expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
    'http://identity:3001/internal/v1/local/session/validate',
    'http://identity:3001/api/v1/session/csrf',
    'http://identity:3001/internal/v1/local/session/validate',
  ]);
  expect(JSON.parse(String(fetcher.mock.calls[2]?.[1]?.body))).toEqual({
    sessionToken: participantSession.sessionToken,
  });
  expect(response.cookies.get('openpc_functional_context')?.value).toBe('PARTICIPANT');
  expect(response.cookies.get('openpc_local_runtime_session')).toBeUndefined();
  expect(response.headers.get('set-cookie')).not.toContain(participantSession.sessionToken);
});
it.each([
  { participantId: '018f0000-0000-7000-8000-000000000102', privacyDomainId },
  { participantId, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
  { participantId, privacyDomainId, expectedSessionId: nextSessionId },
])(
  'denies a foreign or stale functional context selection without changing native sessions: %j',
  async (body) => {
    const cookie = await functionalContextFixture();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ ...platformSession, platformBootstrapEligible: true }))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(Response.json(participantSession));
    const response = await selectLocalParticipantContext(
      request('/api/v1/ui/session/context', cookie, body),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.cookies.getAll()).toEqual([]);
    expect(
      fetcher.mock.calls.some(([url]) => String(url).endsWith('/api/v1/session/context')),
    ).toBe(false);
  },
);
it('denies an expired installed Participant session instead of mutating the Platform session as a fallback', async () => {
  const cookie = await functionalContextFixture();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...platformSession, platformBootstrapEligible: true }))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status: 401 }));
  const response = await selectLocalParticipantContext(
    request('/api/v1/ui/session/context', cookie, { participantId, privacyDomainId }),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(response.cookies.getAll()).toEqual([]);
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/api/v1/session/context'))).toBe(
    false,
  );
});

it.each([false, true])(
  'reads only this subject’s durable enrollment (foreign=%s)',
  async (foreign) => {
    const value = {
      enrollmentId,
      principalId: foreign ? nextSessionId : principalId,
      participantId,
      principalEpoch: '2',
      state: 'COMPLETED',
      expiresAt: '2026-09-12T05:05:00.000Z',
      completedAt: '2026-09-12T05:01:00.000Z',
      credential: { credentialId, credentialEpoch: '1', active: true },
    };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(platformSession))
      .mockResolvedValueOnce(Response.json(value));
    const cookie = `openpc_local_runtime_session=${encodeBffSession(platformSession, Buffer.from('cookie'.repeat(32)))}`;
    const response = await readLocalWebAuthnEnrollment(
      new NextRequest(
        `http://localhost:8080/api/v1/ui/webauthn/enrollment?enrollmentId=${enrollmentId}`,
        { headers: { cookie } },
      ),
    );
    if (foreign) expect(response.status).toBe(503);
    else {
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(value);
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      `http://identity:3001/v1/identity/webauthn/enrollments/${enrollmentId}`,
    );
  },
);
