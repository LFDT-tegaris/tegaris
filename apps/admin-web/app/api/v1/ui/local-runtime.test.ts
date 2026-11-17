import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { localFactAction } from '@openpc/ui-shell';

import {
  localOwnerFetch,
  functionalIdentitySession,
  decodeBffSession,
  localAction,
  localBootstrap,
  localLogin,
  localLogout,
  localRefreshSession,
  localRuntimeStatus,
  localSnapshot,
  openBffPayload,
  readLocalRuntimeConfig,
  sealBffPayload,
} from './local-runtime';

let root = '';
const original = { ...process.env };
const operator = {
  sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000117',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PARTICIPANT',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
  stepUpVerifiedAt: new Date().toISOString(),
} as const;
const requestId = '018f0000-0000-7000-8000-000000000501';
const correlationId = '018f0000-0000-7000-8000-000000000502';

function snapshotHeaders(cookie: string) {
  return {
    cookie,
    'openpc-api-version': '1',
    'openpc-participant-id': localFactAction.participantRef,
    'x-request-id': requestId,
    'x-correlation-id': correlationId,
  };
}

function framedDigest(separator: string, values: readonly string[]) {
  const hash = createHash('sha256');
  for (const value of [separator, ...values]) {
    const bytes = Buffer.from(value);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return `sha256:${hash.digest('hex')}`;
}

function projectionEtag(
  factCount: number,
  latestCandidateId: string | null,
  latestState: string | null,
  observedAtMs: number | null,
) {
  return `"${framedDigest('openpc:ui-snapshot-etag:v1', [
    String(factCount),
    latestCandidateId ?? '',
    latestState ?? '',
    String(observedAtMs ?? 0),
  ])}"`;
}

async function loginCookie(): Promise<string> {
  const login = await localLogin(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
      method: 'POST',
      headers: { origin: 'http://127.0.0.1:8080', host: '127.0.0.1:8080' },
      body: JSON.stringify({ role: 'operator', credential: 'generated-credential' }),
    }),
  );
  expect(login.status).toBe(201);
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  expect(cookie).toBeTruthy();
  return cookie!;
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-bff-runtime-'));
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

it('loads the installed HTTPS realm authorization endpoint', async () => {
  const endpoint = 'https://idp.example/realms/tegaris/protocol/openid-connect/auth';
  const configured = await readLocalRuntimeConfig({
    ...process.env,
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: endpoint,
  });
  expect(configured?.oidcAuthorizationUrl).toBe(endpoint);
});

const functionalActorFixture = {
  sessionToken: operator.sessionToken,
  platformSessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000118',
  principalId: operator.principalId,
  participantId: operator.participantId,
  privacyDomainId: operator.privacyDomainId,
  credentialId: '018f0000-0000-7000-8000-000000000301',
  assertionCredentialId: '018f0000-0000-7000-8000-000000000301',
  privateKeyFile: '/private/operator.der',
  counterFile: '/private/operator.counter',
};
async function functionalRuntime() {
  const runtime = await readLocalRuntimeConfig(process.env);
  if (!runtime) throw new Error('Runtime fixture missing');
  return {
    ...runtime,
    functionalTest: {
      version: 1 as const,
      actors: {
        operator: functionalActorFixture,
        viewer: {
          ...functionalActorFixture,
          sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000119',
          platformSessionToken:
            '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000120',
          principalId: '018f0000-0000-7000-8000-000000000112',
          credentialId: '018f0000-0000-7000-8000-000000000302',
          assertionCredentialId: '018f0000-0000-7000-8000-000000000302',
          privateKeyFile: '/private/viewer.der',
          counterFile: '/private/viewer.counter',
        },
      },
    },
  };
}
const nativePlatform = {
  ...operator,
  sessionId: '018f0000-0000-7000-8000-000000000118',
  contextMode: 'PLATFORM',
  privacyDomainId: undefined,
  platformBootstrapEligible: true,
};
it('keeps Participant as the default and validates its original native session', async () => {
  const fetcher = vi.fn().mockResolvedValue(Response.json(operator));
  vi.stubGlobal('fetch', fetcher);
  const session = await functionalIdentitySession(await functionalRuntime());
  expect(session?.sessionToken).toBe(operator.sessionToken);
  expect(JSON.parse(fetcher.mock.calls[0]![1].body)).toEqual({
    sessionToken: operator.sessionToken,
  });
});
it('selects a separate native Platform session and preserves the native eligibility verdict', async () => {
  const fetcher = vi.fn().mockResolvedValue(Response.json(nativePlatform));
  vi.stubGlobal('fetch', fetcher);
  const session = await functionalIdentitySession(
    await functionalRuntime(),
    'operator',
    'PLATFORM',
  );
  expect(session?.contextMode).toBe('PLATFORM');
  expect(session?.platformBootstrapEligible).toBe(true);
  expect(session?.sessionToken).toBe(functionalActorFixture.platformSessionToken);
  expect(JSON.parse(fetcher.mock.calls[0]![1].body)).toEqual({
    sessionToken: functionalActorFixture.platformSessionToken,
  });
});
it.each([
  { role: 'viewer' },
  { principalId: '018f0000-0000-7000-8000-000000000112' },
  { participantId: '018f0000-0000-7000-8000-000000000102' },
  { contextMode: 'PARTICIPANT' },
  { privacyDomainId: operator.privacyDomainId },
  { platformBootstrapEligible: false },
  { platformBootstrapEligible: undefined },
])('rejects a Platform selection that disagrees with native authority: %j', async (change) => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(Response.json({ ...nativePlatform, ...change })),
  );
  expect(
    await functionalIdentitySession(await functionalRuntime(), 'operator', 'PLATFORM'),
  ).toBeUndefined();
});
it('rejects expired native sessions, unknown contexts and missing installed Platform sessions', async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValue(Response.json({ code: 'PC-AUTH-0005' }, { status: 401 }));
  vi.stubGlobal('fetch', fetcher);
  const runtime = await functionalRuntime();
  expect(await functionalIdentitySession(runtime, 'operator', 'PLATFORM')).toBeUndefined();
  fetcher.mockClear();
  expect(await functionalIdentitySession(runtime, 'operator', 'administrator')).toBeUndefined();
  expect(fetcher).not.toHaveBeenCalled();
  const withoutPlatform = {
    ...runtime,
    functionalTest: {
      ...runtime.functionalTest,
      actors: {
        ...runtime.functionalTest.actors,
        operator: { ...functionalActorFixture, platformSessionToken: undefined },
      },
    },
  };
  expect(await functionalIdentitySession(withoutPlatform, 'operator', 'PLATFORM')).toBeUndefined();
  expect(fetcher).not.toHaveBeenCalled();
});
it.each([
  'http://idp.example/authorize',
  'https://user:password@idp.example/auth',
  'https://idp.example/auth?client_id=other',
  'https://idp.example/auth#other',
])('rejects unsafe sign-in configuration before use (%s)', async (endpoint) => {
  await expect(
    readLocalRuntimeConfig({ ...process.env, OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: endpoint }),
  ).rejects.toThrow('local runtime owner URL invalid');
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  process.env = { ...original };
  await rm(root, { recursive: true, force: true });
});

it.each([
  ['http://127.0.0.1:8080', 'http://127.0.0.1:8080', true],
  ['https://demo.example.org', 'https://demo.example.org', true],
  ['https://demo.example.org', 'http://demo.example.org', false],
  ['http://127.0.0.1:8080', 'https://127.0.0.1:8080', false],
  ['https://demo.example.org', 'https://other.example.org', false],
  ['https://demo.example.org', 'https://demo.example.org/path', false],
  ['https://demo.example.org', 'https://user@demo.example.org', false],
  ['https://demo.example.org', 'null', false],
])('admits only the full browser origin before login (%s, %s)', async (url, origin, admitted) => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(operator));
  const response = await localLogin(
    new NextRequest(`${url}/api/v1/ui/local-session`, {
      method: 'POST',
      headers: { host: new URL(url).host, origin },
      body: JSON.stringify({ role: 'operator', credential: 'generated-credential' }),
    }),
  );
  expect(response.status).toBe(admitted ? 201 : 403);
  expect(fetcher).toHaveBeenCalledTimes(admitted ? 1 : 0);
  if (admitted) {
    expect(response.cookies.get('openpc_local_runtime_session')).toMatchObject({
      httpOnly: true,
      secure: url.startsWith('https:'),
      sameSite: 'strict',
      path: '/',
    });
  } else {
    expect(response.headers.has('set-cookie')).toBe(false);
  }
});

it('logs in and reads the real projection', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        factCount: 1,
        latestCandidateId: localFactAction.idempotencyKey,
        latestState: 'ADMITTED',
        observedAtMs: 1_767_225_600_000,
        resourceRef: localFactAction.resourceRef,
        etag: projectionEtag(1, localFactAction.idempotencyKey, 'ADMITTED', 1_767_225_600_000),
        requestId,
        correlationId,
      }),
    );
  const cookie = await loginCookie();
  const sealedValue = cookie.slice(cookie.indexOf('=') + 1);
  expect(Buffer.from(sealedValue, 'base64url').toString('utf8')).not.toContain(
    operator.sessionToken,
  );
  const snapshot = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      {
        headers: snapshotHeaders(cookie),
      },
    ),
    'fact-source-projection-bridge',
  );
  expect(snapshot?.status).toBe(200);
  const body = await snapshot?.json();
  expect(body.items).toHaveLength(1);
  expect(body.scope).toEqual({
    plane: 'PARTICIPANT',
    participantId: localFactAction.participantRef,
    privacyDomainId: localFactAction.privacyDomainRef,
  });
  expect(body.contextDigest).toBe(
    framedDigest('openpc:ui-authority-context:v1', [
      'ROUTE-FACT-SOURCE-PROJECTION-BRIDGE',
      'FACT_SOURCE_PROJECTION_BRIDGE',
      localFactAction.participantRef,
      localFactAction.privacyDomainRef,
      '1',
      '1',
    ]),
  );
  expect(body.items[0].scopeDigest).toBe(
    framedDigest('openpc:ui-authorized-scope:v1', [
      'PARTICIPANT',
      localFactAction.participantRef,
      localFactAction.privacyDomainRef,
    ]),
  );
  expect(body.contextDigest).not.toBe(body.items[0].scopeDigest);
  expect(body.items[0].resourceRef).toBe(localFactAction.resourceRef);
  expect(body.observedAt).toMatch(/\.\d{6}Z$/u);
  expect(snapshot?.headers.get('x-request-id')).toBe(requestId);
  expect(snapshot?.headers.get('x-correlation-id')).toBe(correlationId);
  expect(snapshot?.headers.get('etag')).toMatch(/^"sha256:[0-9a-f]{64}"$/u);
});

it.each([
  { availableContexts: [] },
  {
    availableContexts: [
      {
        participantId: operator.participantId,
        privacyDomainId: '018f0000-0000-7000-8000-000000000999',
      },
    ],
  },
])(
  'reads authenticated contexts from Identity without exposing its token (%j)',
  async ({ availableContexts }) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
      .mockResolvedValueOnce(Response.json({ ...operator, availableContexts }));
    const cookie = await loginCookie();
    const response = await localRuntimeStatus(
      new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
        headers: { cookie },
      }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      enabled: true,
      authenticated: true,
      role: 'operator',
      sessionId: operator.sessionId,
      principalId: operator.principalId,
      participantId: operator.participantId,
      contextMode: operator.contextMode,
      privacyDomainId: operator.privacyDomainId,
      contextEpoch: operator.contextEpoch,
      stepUpVerifiedAt: operator.stepUpVerifiedAt,
      availableContexts,
    });
  },
);

it('revokes the server session before clearing BFF custody and returns its durable operation', async () => {
  const actionIntentDigest = `sha256:${'a'.repeat(64)}`;
  const operation = {
    operationId: '018f0000-0000-7000-8000-000000000601',
    resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000117',
    actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
    intentDigest: actionIntentDigest,
    idempotencyKey: `session-logout-${createHash('sha256')
      .update(operator.sessionToken)
      .digest('hex')}`,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-09-11T02:00:00.000000Z',
    updatedAt: '2026-09-11T02:00:00.000000Z',
    revision: '2',
  } as const;
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(
      Response.json({
        revision: '1',
        actionIntentDigest,
        participantId: operator.participantId,
        privacyDomainId: localFactAction.privacyDomainRef.split(':').at(-1),
        role: operator.role,
        replay: false,
      }),
    )
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json(operation, { status: 202 }));
  const cookie = await loginCookie();
  const response = await localLogout(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
      method: 'DELETE',
      headers: {
        cookie,
        'origin': 'http://127.0.0.1:8080',
        'host': '127.0.0.1:8080',
        'x-request-id': requestId,
        'x-correlation-id': correlationId,
      },
    }),
  );
  expect(response.status).toBe(202);
  expect(await response.json()).toEqual(operation);
  expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
  expect(fetchMock.mock.calls[3]?.[0]).toBe('http://identity:3001/api/v1/session/logout');
  const ownerHeaders = fetchMock.mock.calls[3]?.[1]?.headers as Record<string, string>;
  expect(ownerHeaders.Cookie).toContain(operator.sessionToken);
  expect(ownerHeaders['OpenPC-Action-Intent-Digest']).toBe(actionIntentDigest);
  expect(ownerHeaders['OpenPC-Privacy-Domain-ID']).toBe(localFactAction.privacyDomainRef);
  expect(ownerHeaders['X-CSRF-Token']).toBe('c'.repeat(43));
  expect(String(fetchMock.mock.calls[4]?.[1]?.body)).not.toContain(operator.sessionToken);
});

it.each([operator.privacyDomainId, '018f0000-0000-7000-8000-000000000999'])(
  'rotates identity custody in the owner-selected domain %s without exposing the replacement token',
  async (privacyDomainId) => {
    const actionIntentDigest = `sha256:${'d'.repeat(64)}`;
    const nextToken = '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000118';
    const operation = {
      operationId: '018f0000-0000-7000-8000-000000000602',
      resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000117',
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      intentDigest: actionIntentDigest,
      idempotencyKey: `session-refresh-${createHash('sha256')
        .update(operator.sessionToken)
        .digest('hex')}`,
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
      createdAt: '2026-09-11T02:00:00.000000Z',
      updatedAt: '2026-09-11T02:00:00.000000Z',
      revision: '2',
    } as const;
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ ...operator, privacyDomainId }, { status: 201 }))
      .mockResolvedValueOnce(
        Response.json({
          revision: '1',
          actionIntentDigest,
          participantId: operator.participantId,
          privacyDomainId,
          role: operator.role,
          replay: false,
        }),
      )
      .mockResolvedValueOnce(Response.json({ csrfToken: 'f'.repeat(43) }))
      .mockResolvedValueOnce(
        Response.json(operation, {
          status: 202,
          headers: { 'set-cookie': `__Host-openpc_session=${nextToken}; HttpOnly; Secure` },
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ ...operator, privacyDomainId, sessionToken: undefined }),
      );
    const cookie = await loginCookie();
    const response = await localRefreshSession(
      new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
        method: 'PATCH',
        headers: {
          cookie,
          'origin': 'http://127.0.0.1:8080',
          'host': '127.0.0.1:8080',
          'x-request-id': requestId,
          'x-correlation-id': correlationId,
        },
      }),
    );
    expect(response.status).toBe(202);
    expect(JSON.stringify(await response.json())).not.toContain(nextToken);
    const sealed = response.headers.get('set-cookie')?.split(';')[0]?.split('=')[1];
    expect(decodeBffSession(sealed, Buffer.from('cookie'.repeat(32)))?.sessionToken).toBe(
      nextToken,
    );
    const contextRequest = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body));
    expect(contextRequest).not.toHaveProperty('privacyDomainId');
    const ownerHeaders = fetchMock.mock.calls[3]?.[1]?.headers as Record<string, string>;
    expect(ownerHeaders['OpenPC-Privacy-Domain-ID']).toBe(
      `urn:openpc:privacy-domain:${privacyDomainId}`,
    );
  },
);

it('recovers an exact committed rotation after owner-response loss without reusing the CSRF route', async () => {
  const actionIntentDigest = `sha256:${'d'.repeat(64)}`;
  const replayCsrfToken = 'r'.repeat(43);
  const nextToken = '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000118';
  const operation = {
    operationId: '018f0000-0000-7000-8000-000000000602',
    resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000117',
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    intentDigest: actionIntentDigest,
    idempotencyKey: `session-refresh-${createHash('sha256')
      .update(operator.sessionToken)
      .digest('hex')}`,
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '2026-09-11T02:00:00.000000Z',
    updatedAt: '2026-09-11T02:00:00.000000Z',
    revision: '2',
  } as const;
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(
      Response.json({
        revision: '1',
        actionIntentDigest,
        participantId: operator.participantId,
        privacyDomainId: localFactAction.privacyDomainRef.split(':').at(-1),
        role: operator.role,
        replay: true,
        replayCsrfToken,
      }),
    )
    .mockResolvedValueOnce(
      Response.json(operation, {
        status: 202,
        headers: { 'set-cookie': `__Host-openpc_session=${nextToken}; HttpOnly; Secure` },
      }),
    )
    .mockResolvedValueOnce(Response.json({ ...operator, sessionToken: undefined }));
  const cookie = await loginCookie();
  const response = await localRefreshSession(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
      method: 'PATCH',
      headers: {
        cookie,
        'origin': 'http://127.0.0.1:8080',
        'host': '127.0.0.1:8080',
        'x-request-id': requestId,
        'x-correlation-id': correlationId,
      },
    }),
  );
  expect(response.status).toBe(202);
  expect(await response.json()).toEqual(operation);
  expect(fetchMock).toHaveBeenCalledTimes(4);
  const ownerHeaders = fetchMock.mock.calls[2]?.[1]?.headers as Record<string, string>;
  expect(ownerHeaders['X-CSRF-Token']).toBe(replayCsrfToken);
  const sealed = response.headers.get('set-cookie')?.split(';')[0]?.split('=')[1];
  expect(decodeBffSession(sealed, Buffer.from('cookie'.repeat(32)))?.sessionToken).toBe(nextToken);
});

it('cryptographically separates session and OIDC custody payloads', () => {
  const key = Buffer.from('cookie'.repeat(32));
  const session = sealBffPayload({ sessionToken: operator.sessionToken }, key, 'session');
  const custody = sealBffPayload({ transactionId: requestId }, key, 'oidc-custody');
  expect(openBffPayload(session, key, 'oidc-custody')).toBeUndefined();
  expect(openBffPayload(custody, key, 'session')).toBeUndefined();
});

it('rejects a missing or malformed GET authority header before the fact owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  const denied = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      {
        headers: {
          ...snapshotHeaders(cookie),
          'x-request-id': '018f0000-0000-4000-8000-000000000501',
        },
      },
    ),
    'fact-source-projection-bridge',
  );
  expect(denied?.status).toBe(400);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('rejects an internally inconsistent fact projection', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        factCount: 0,
        latestCandidateId: localFactAction.idempotencyKey,
        latestState: 'ADMITTED',
        observedAtMs: 1_767_225_600_000,
        resourceRef: localFactAction.resourceRef,
        etag: `"sha256:${'a'.repeat(64)}"`,
        requestId,
        correlationId,
      }),
    );
  const cookie = await loginCookie();
  const denied = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      { headers: snapshotHeaders(cookie) },
    ),
    'fact-source-projection-bridge',
  );
  expect(denied?.status).toBe(503);
});

it('rejects a fact projection whose ETag does not bind its exact fields', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        factCount: 1,
        latestCandidateId: localFactAction.idempotencyKey,
        latestState: 'ADMITTED',
        observedAtMs: 1_767_225_600_000,
        resourceRef: localFactAction.resourceRef,
        etag: `"sha256:${'a'.repeat(64)}"`,
        requestId,
        correlationId,
      }),
    );
  const cookie = await loginCookie();
  const denied = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      { headers: snapshotHeaders(cookie) },
    ),
    'fact-source-projection-bridge',
  );
  expect(denied?.status).toBe(503);
  expect(await denied?.json()).toMatchObject({
    code: 'PC-INTEGRATION-5001',
    truthState: 'UNAVAILABLE',
    retryable: true,
  });
});

it('rejects missing, unknown, malformed URL, and malformed secret configuration', async () => {
  await expect(
    readLocalRuntimeConfig({ ...process.env, OPENPC_FACT_INTERNAL_URL: undefined }),
  ).rejects.toThrow('owner URL invalid');
  for (const variable of ['OPENPC_FACT_UNKNOWN', 'OPENPC_POLICY_UNKNOWN'])
    await expect(
      readLocalRuntimeConfig({ ...process.env, [variable]: 'forbidden' }),
    ).rejects.toThrow('unknown local BFF variable');
  await expect(
    readLocalRuntimeConfig({ ...process.env, OPENPC_FACT_INTERNAL_URL: 'https://fact/' }),
  ).rejects.toThrow('owner URL invalid');
  await writeFile(join(root, 'fact'), 'short');
  await expect(readLocalRuntimeConfig(process.env)).rejects.toThrow('secret invalid');
});

it('validates every mutation binding before calling the fact owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  const bootstrap = await localBootstrap(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/session-bootstrap', {
      headers: { cookie },
    }),
  );
  expect(bootstrap?.status).toBe(200);
  const { csrfToken, idempotencyKey, etag } = (await bootstrap?.json()) as {
    csrfToken: string;
    idempotencyKey: string;
    etag: string;
  };
  expect(localFactAction.actionIntentDigest).toBe(
    'sha256:2da81e172788f4fc9d713b9579c40d5fc1f0a8ea29dc79a4b6d2f386913afc3b',
  );
  expect(localFactAction.downstreamActionIntentDigest).toBe(
    'sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a',
  );
  expect(localFactAction.actionIntentDigest).not.toBe(localFactAction.downstreamActionIntentDigest);
  const operation = {
    actionIntentId: localFactAction.downstreamActionIntentId,
    createdAt: '2026-01-01T00:00:00.000000Z',
    idempotencyKey,
    intentDigest: localFactAction.downstreamActionIntentDigest,
    operationId: '018f0000-0000-7000-8000-000000000401',
    resourceRef: localFactAction.resourceRef,
    revision: '1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    updatedAt: '2026-01-01T00:00:00.000000Z',
  } as const;
  fetchMock.mockResolvedValueOnce(
    Response.json({ outcome: 'ADMITTED_NOT_READY', operation, etag, requestId, correlationId }),
  );
  const response = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      {
        method: 'POST',
        headers: {
          cookie,
          'content-type': 'application/json',
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'x-csrf-token': csrfToken,
          'idempotency-key': idempotencyKey,
          'if-match': etag,
          'openpc-action-intent-digest': localFactAction.actionIntentDigest,
          'openpc-api-version': '1',
          'openpc-participant-id': localFactAction.participantRef,
          'x-request-id': requestId,
          'x-correlation-id': correlationId,
        },
        body: JSON.stringify({
          actionIntentId: localFactAction.actionIntentId,
          actionIntentDigest: localFactAction.actionIntentDigest,
          expectedRevision: '1',
          inputDigest: localFactAction.inputDigest,
          reason: 'Authorized local qualification and admission.',
          targetRef: localFactAction.targetRef,
        }),
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(response?.status).toBe(202);
  expect(fetchMock.mock.calls[3]?.[1]?.headers).toMatchObject({
    'X-OpenPC-Action-Intent': localFactAction.downstreamActionIntentId,
    'Idempotency-Key': 'local-runtime-qualify-admit-v1',
    'If-Match': etag,
  });
  const forwarded = JSON.parse(String(fetchMock.mock.calls[3]?.[1]?.body));
  expect(forwarded).toMatchObject({
    uiActionIntentId: localFactAction.actionIntentId,
    downstreamActionIntentId: localFactAction.downstreamActionIntentId,
    replacementDigest: localFactAction.inputDigest,
    targetRef: localFactAction.targetRef,
    resourceRef: localFactAction.resourceRef,
  });
  expect(await response?.json()).toEqual(operation);
});

it('returns non-disclosing denial for a viewer', async () => {
  const viewer = {
    sessionToken: '018f0000-0000-7000-8000-000000000101.viewer',
    role: 'viewer',
    principalId: '018f0000-0000-7000-8000-000000000112',
    participantId: '018f0000-0000-7000-8000-000000000101',
    stepUpVerifiedAt: null,
  } as const;
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer, { status: 201 }))
    .mockResolvedValueOnce(Response.json(viewer));
  const login = await localLogin(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
      method: 'POST',
      headers: { origin: 'http://127.0.0.1:8080', host: '127.0.0.1:8080' },
      body: JSON.stringify({ role: 'viewer', credential: 'generated-credential' }),
    }),
  );
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  const denied = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      {
        headers: { cookie: cookie! },
      },
    ),
    'fact-source-projection-bridge',
  );
  expect(denied?.status).toBe(404);
  expect((await denied?.json())?.code).toBe('PC-AUTH-0005');
});

it('rejects malformed mutation headers before calling the fact owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  const request = new NextRequest(
    'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
    {
      method: 'POST',
      headers: {
        cookie,
        'host': '127.0.0.1:8080',
        'origin': 'http://127.0.0.1:8080',
        'x-csrf-token': 'invalid',
        'idempotency-key': 'invalid',
        'if-match': 'invalid',
        'openpc-action-intent-digest': localFactAction.actionIntentDigest,
      },
      body: JSON.stringify({
        actionIntentId: localFactAction.actionIntentId,
        actionIntentDigest: localFactAction.actionIntentDigest,
        expectedRevision: '1',
        inputDigest: localFactAction.inputDigest,
        reason: 'Authorized local qualification and admission.',
        targetRef: localFactAction.targetRef,
      }),
    },
  );
  const denied = await localAction(request, 'fact-source-projection-bridge', 'qualify-admit');
  expect(denied?.status).toBe(403);
  expect((await denied?.json())?.code).toBe('PC-AUTH-0002');
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('rejects a fact owner result whose ETag is not the exact target ETag', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  const bootstrap = await localBootstrap(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/session-bootstrap', {
      headers: { cookie },
    }),
  );
  const value = (await bootstrap?.json()) as {
    csrfToken: string;
    idempotencyKey: string;
    etag: string;
  };
  const operation = {
    actionIntentId: localFactAction.downstreamActionIntentId,
    createdAt: '2026-01-01T00:00:00.000000Z',
    idempotencyKey: value.idempotencyKey,
    intentDigest: localFactAction.downstreamActionIntentDigest,
    operationId: '018f0000-0000-7000-8000-000000000401',
    resourceRef: localFactAction.resourceRef,
    revision: '1',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    updatedAt: '2026-01-01T00:00:00.000000Z',
  };
  fetchMock.mockResolvedValueOnce(
    Response.json({
      outcome: 'ADMITTED_NOT_READY',
      operation,
      etag: `"sha256:${'a'.repeat(64)}"`,
      requestId,
      correlationId,
    }),
  );
  const denied = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      {
        method: 'POST',
        headers: {
          ...snapshotHeaders(cookie),
          'content-type': 'application/json',
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'x-csrf-token': value.csrfToken,
          'idempotency-key': value.idempotencyKey,
          'if-match': value.etag,
          'openpc-action-intent-digest': localFactAction.actionIntentDigest,
        },
        body: JSON.stringify({
          actionIntentId: localFactAction.actionIntentId,
          actionIntentDigest: localFactAction.actionIntentDigest,
          expectedRevision: '1',
          inputDigest: localFactAction.inputDigest,
          reason: 'Authorized local qualification and admission.',
          targetRef: localFactAction.targetRef,
        }),
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(denied?.status).toBe(503);
  expect((await denied?.json())?.code).toBe('PC-INTEGRATION-5001');
});

it('rejects duplicate public semantic keys before calling the fact owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  const bootstrap = await localBootstrap(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/session-bootstrap', {
      headers: { cookie },
    }),
  );
  const value = (await bootstrap?.json()) as { csrfToken: string; etag: string };
  const body = `{"actionIntentId":"${localFactAction.actionIntentId}","actionIntentId":"${localFactAction.actionIntentId}","actionIntentDigest":"${localFactAction.actionIntentDigest}","expectedRevision":"1","inputDigest":"${localFactAction.inputDigest}","reason":"duplicate","targetRef":"${localFactAction.targetRef}"}`;
  const denied = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      {
        method: 'POST',
        headers: {
          ...snapshotHeaders(cookie),
          'content-type': 'application/json',
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'x-csrf-token': value.csrfToken,
          'idempotency-key': localFactAction.idempotencyKey,
          'if-match': value.etag,
          'openpc-action-intent-digest': localFactAction.actionIntentDigest,
        },
        body,
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(denied?.status).toBe(400);
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it('binds CSRF to expiry, method, path, session, and UI action digest', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-09-09T14:00:00.000Z'));
  const at = () => new Date().toISOString();
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
    Promise.resolve(
      Response.json({
        ...operator,
        stepUpVerifiedAt: at(),
      }),
    ),
  );
  const cookie = await loginCookie();
  const bootstrap = await localBootstrap(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/session-bootstrap', {
      headers: { cookie },
    }),
  );
  const value = (await bootstrap?.json()) as { csrfToken: string; etag: string };
  const baseHeaders = {
    ...snapshotHeaders(cookie),
    'content-type': 'application/json',
    'host': '127.0.0.1:8080',
    'origin': 'http://127.0.0.1:8080',
    'x-csrf-token': value.csrfToken,
    'idempotency-key': localFactAction.idempotencyKey,
    'if-match': value.etag,
    'openpc-action-intent-digest': localFactAction.actionIntentDigest,
  };
  const body = JSON.stringify({
    actionIntentId: localFactAction.actionIntentId,
    actionIntentDigest: localFactAction.actionIntentDigest,
    expectedRevision: '1',
    inputDigest: localFactAction.inputDigest,
    reason: 'Authorized local qualification and admission.',
    targetRef: localFactAction.targetRef,
  });
  const wrongMethod = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      {
        method: 'PUT',
        headers: baseHeaders,
        body,
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(wrongMethod?.status).toBe(400);
  const wrongPath = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/other',
      {
        method: 'POST',
        headers: baseHeaders,
        body,
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(wrongPath?.status).toBe(400);
  vi.setSystemTime(new Date('2026-09-09T14:05:00.001Z'));
  const expired = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      {
        method: 'POST',
        headers: baseHeaders,
        body,
      },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(expired?.status).toBe(403);
  expect(fetchMock.mock.calls.every(([url]) => !String(url).includes('fact:8081'))).toBe(true);
});

it('denies a stale local step-up before calling the fact owner', async () => {
  const stale = { ...operator, stepUpVerifiedAt: new Date(Date.now() - 300_001).toISOString() };
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(stale));
  const cookie = await loginCookie();
  const denied = await localAction(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit',
      { method: 'POST', headers: { cookie }, body: '{}' },
    ),
    'fact-source-projection-bridge',
    'qualify-admit',
  );
  expect(denied?.status).toBe(403);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('translates fact-owner failure without disclosing details', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(new Response('database detail', { status: 503 }));
  const cookie = await loginCookie();
  const response = await localSnapshot(
    new NextRequest(
      'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge',
      { headers: snapshotHeaders(cookie) },
    ),
    'fact-source-projection-bridge',
  );
  expect(response?.status).toBe(503);
  expect(await response?.json()).toMatchObject({
    code: 'PC-INTEGRATION-5001',
    status: 503,
    truthState: 'UNAVAILABLE',
    retryable: true,
  });
  expect(response?.headers.get('content-type')).toContain('application/problem+json');
});

it('bounds each new owner request with the trusted profile and preserves caller abort', async () => {
  const deadline = new AbortController(),
    caller = new AbortController();
  caller.abort();
  const timer = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(deadline.signal);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({}));
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  await localOwnerFetch('http://identity:3001/read', { signal: caller.signal });
  expect(timer).toHaveBeenLastCalledWith(120000);
  expect(fetcher.mock.calls[0]![1]!.signal!.aborted).toBe(true);
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  });
  await localOwnerFetch('http://identity:3001/read');
  expect(timer).toHaveBeenLastCalledWith(1200000);
  process.env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE = '0';
  expect(() => localOwnerFetch('http://identity:3001/read')).toThrow();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it.each([
  ['UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT'],
  ['ECONNRESET', 'ECONNRESET'],
  ['secret-cookie-provider-code', 'UNCLASSIFIED_TRANSPORT'],
])('retains the original owner transport error and redacts %s', async (code, failure) => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const secret = 'secret-cookie-assertion-url';
  const error = new Error(secret, { cause: Object.assign(new Error(secret), { code }) });
  const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(error);
  await expect(
    localOwnerFetch(`http://identity:3001/${secret}`, {
      method: 'PATCH',
      headers: { Cookie: secret },
      body: secret,
    }),
  ).rejects.toBe(error);
  expect(output).toHaveBeenCalledTimes(1);
  const line = String(output.mock.calls[0]![0]);
  expect(line).not.toContain(secret);
  expect(line).not.toContain('secret-cookie-provider-code');
  expect(JSON.parse(line)).toEqual({
    boundary: 'local_owner_fetch',
    failure,
    budgetMs: 120000,
    elapsedMs: expect.any(Number),
  });
});

it('cannot mask an original error through an accessor or a revoked proxy cause', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  let getterCalls = 0;
  const accessor = Object.defineProperty(new Error('private'), 'cause', {
    get() {
      getterCalls++;
      throw new Error('private');
    },
  });
  const proxy = Proxy.revocable({}, {});
  proxy.revoke();
  const original = new Error('private', { cause: proxy.proxy });
  const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi.spyOn(globalThis, 'fetch');
  for (const error of [accessor, original]) {
    fetcher.mockRejectedValueOnce(error);
    await expect(localOwnerFetch('http://identity:3001/read')).rejects.toBe(error);
  }
  expect(getterCalls).toBe(0);
  for (const [line] of output.mock.calls) {
    expect(String(line)).not.toContain('private');
    expect(JSON.parse(String(line)).failure).toBe('UNCLASSIFIED_TRANSPORT');
  }
});

it.each(['REQUEST_DEADLINE', 'CALLER_ABORT', 'CALLER_AND_DEADLINE_ABORTED'])(
  'distinguishes %s without changing abort or expiry budgets',
  async (failure) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    const deadline = new AbortController(),
      caller = new AbortController();
    if (failure !== 'CALLER_ABORT') deadline.abort();
    if (failure !== 'REQUEST_DEADLINE') caller.abort();
    const timer = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(deadline.signal);
    const error = new Error('private');
    const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(error);
    await expect(
      localOwnerFetch('http://identity:3001/read', { signal: caller.signal }),
    ).rejects.toBe(error);
    expect(fetcher.mock.calls[0]![1]!.signal!.aborted).toBe(true);
    expect(timer).toHaveBeenCalledWith(120000);
    expect(JSON.parse(String(output.mock.calls[0]![0])).failure).toBe(failure);
  },
);

it('preserves the exact fetch rejection even when its diagnostic sink throws', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const original = new Error('private original', {
    cause: Object.assign(new Error('private cause'), { code: 'UND_ERR_HEADERS_TIMEOUT' }),
  });
  const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => {
    throw new Error('private diagnostic sink');
  });
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(original);
  await expect(localOwnerFetch('http://identity:3001/private')).rejects.toBe(original);
  expect(output).toHaveBeenCalledTimes(1);
  const line = String(output.mock.calls[0]![0]);
  expect(line).not.toContain('private');
  expect(JSON.parse(line).failure).toBe('UND_ERR_HEADERS_TIMEOUT');
});

it.each(['EAI_AGAIN', 'ECONNREFUSED'])(
  'retries one GET connection-establishment failure without renewing its deadline or credentials: %s',
  async (code) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    const secret = 'private-read-cookie';
    const headers = { Cookie: secret };
    const input = new URL('http://identity:3001/read');
    const response = Response.json({ state: 'ACTIVE' });
    const error = new Error('private transport', { cause: { code } });
    const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const timer = vi.spyOn(AbortSignal, 'timeout');
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementationOnce(async () => {
        headers.Cookie = 'different-account';
        input.pathname = '/different-resource';
        throw error;
      })
      .mockResolvedValueOnce(response);
    expect(await localOwnerFetch(input, { headers })).toBe(response);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(timer).toHaveBeenCalledTimes(1);
    expect(timer).toHaveBeenCalledWith(120000);
    for (const [url, options] of fetcher.mock.calls) {
      expect(url).toBe('http://identity:3001/read');
      expect(new Headers(options?.headers).get('Cookie')).toBe(secret);
      expect(options?.signal).toBe(fetcher.mock.calls[0]![1]!.signal);
    }
    expect(JSON.parse(String(output.mock.calls[0]![0]))).toEqual({
      boundary: 'local_owner_read_retry',
      failure: code,
    });
    expect(String(output.mock.calls[0]![0])).not.toContain(secret);
  },
);

it('stops after the second GET failure and retains that original rejection', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const first = new Error('private first', { cause: { code: 'EAI_AGAIN' } });
  const second = new Error('private second', { cause: { code: 'ECONNREFUSED' } });
  const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockRejectedValueOnce(first)
    .mockRejectedValueOnce(second);
  await expect(localOwnerFetch('http://identity:3001/read')).rejects.toBe(second);
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(JSON.parse(String(output.mock.calls.at(-1)![0])).failure).toBe('ECONNREFUSED');
  for (const [line] of output.mock.calls) expect(String(line)).not.toContain('private');
});

it.each(['POST', 'PATCH', 'PUT', 'DELETE', 'HEAD'])(
  'never retries %s on connection-establishment failure',
  async (method) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    const original = new Error('private', { cause: { code: 'EAI_AGAIN' } });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(original);
    await expect(localOwnerFetch('http://identity:3001/change', { method })).rejects.toBe(original);
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it('uses a Request object’s mutation method when no method override is supplied', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const request = new Request('http://identity:3001/change', { method: 'POST', body: 'private' });
  const original = new Error('private', { cause: { code: 'ECONNREFUSED' } });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(original);
  await expect(localOwnerFetch(request)).rejects.toBe(original);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]![0]).toBe(request);
  expect(request.bodyUsed).toBe(false);
});

it.each(['ECONNRESET', 'UND_ERR_SOCKET', 'UND_ERR_HEADERS_TIMEOUT', 'ENOTFOUND'])(
  'never retries a GET with an ambiguous or persistent transport failure: %s',
  async (code) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    const original = new Error('private', { cause: { code } });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(original);
    await expect(localOwnerFetch('http://identity:3001/read')).rejects.toBe(original);
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it.each([401, 403, 404, 409, 412, 429, 500, 503])(
  'returns HTTP %i without a read retry',
  async (status) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    const response = Response.json({ state: 'UNAVAILABLE' }, { status });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response);
    expect(await localOwnerFetch('http://identity:3001/read')).toBe(response);
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it('caller cancellation during the read retry delay prevents a second dispatch', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const caller = new AbortController();
  const original = new Error('private', { cause: { code: 'EAI_AGAIN' } });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    setTimeout(() => caller.abort(), 10);
    throw original;
  });
  await expect(
    localOwnerFetch('http://identity:3001/read', { signal: caller.signal }),
  ).rejects.toMatchObject({ name: 'AbortError' });
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('an elapsed owner deadline prevents a read retry', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const deadline = new AbortController();
  const original = new Error('private', { cause: { code: 'ECONNREFUSED' } });
  vi.spyOn(AbortSignal, 'timeout').mockReturnValue(deadline.signal);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    deadline.abort();
    throw original;
  });
  await expect(localOwnerFetch('http://identity:3001/read')).rejects.toBe(original);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('retains a GET Request’s own cancellation during the retry delay', async () => {
  delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
  const caller = new AbortController();
  const request = new Request('http://identity:3001/read', { signal: caller.signal });
  const original = new Error('private', { cause: { code: 'EAI_AGAIN' } });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    setTimeout(() => caller.abort(), 10);
    throw original;
  });
  await expect(localOwnerFetch(request)).rejects.toMatchObject({ name: 'AbortError' });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]![1]!.signal!.aborted).toBe(true);
});

it.each(['GET', 'POST'])(
  'reads a changing method accessor once and classifies the dispatched %s method',
  async (first) => {
    delete process.env.OPENPC_LOCAL_QA_DURATION_PROFILE;
    let reads = 0;
    const init = Object.defineProperty({}, 'method', {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? first : first === 'GET' ? 'POST' : 'GET';
      },
    });
    const original = new Error('private', { cause: { code: 'ECONNREFUSED' } });
    const response = Response.json({ state: 'ACTIVE' });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(original)
      .mockResolvedValueOnce(response);
    if (first === 'GET')
      expect(await localOwnerFetch('http://identity:3001/read', init)).toBe(response);
    else await expect(localOwnerFetch('http://identity:3001/change', init)).rejects.toBe(original);
    expect(reads).toBe(1);
    expect(fetcher).toHaveBeenCalledTimes(first === 'GET' ? 2 : 1);
    for (const [, options] of fetcher.mock.calls) expect(options?.method).toBe(first);
  },
);

it.each([503, 502, 429, 403, 404])(
  'keeps a session-status owner failure (%s) unavailable without changing custody',
  async (status) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
      .mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status }));
    const cookie = await loginCookie();
    const response = await localRuntimeStatus(
      new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', { headers: { cookie } }),
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      code: 'PC-INTEGRATION-5001',
      truthState: 'UNAVAILABLE',
    });
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);
it('retains the original cookie through unavailable, restored and confirmed signed-out reads', async () => {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
    .mockRejectedValueOnce(new Error('private transport diagnostic'))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status: 401 }));
  const cookie = await loginCookie();
  const request = () =>
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', { headers: { cookie } });
  const unavailable = await localRuntimeStatus(request());
  expect(unavailable.status).toBe(503);
  expect(JSON.stringify(await unavailable.json())).not.toContain('private');
  const restored = await localRuntimeStatus(request());
  expect(await restored.json()).toMatchObject({
    authenticated: true,
    sessionId: operator.sessionId,
  });
  const signedOut = await localRuntimeStatus(request());
  expect(await signedOut.json()).toEqual({ enabled: true, authenticated: false });
  for (const response of [unavailable, restored, signedOut])
    expect(response.headers.get('set-cookie')).toBeNull();
  expect(
    fetcher.mock.calls.slice(1).map(([, init]) => JSON.parse(String(init?.body)).sessionToken),
  ).toEqual([operator.sessionToken, operator.sessionToken, operator.sessionToken]);
});
it.each(['PARTICIPANT', 'PLATFORM'] as const)(
  'preserves unavailable native status for a private %s selection',
  async (contextMode) => {
    const runtime = await functionalRuntime();
    const profile = {
      ...runtime.functionalTest,
      actors: {
        ...runtime.functionalTest.actors,
        viewer: { ...runtime.functionalTest.actors.viewer, counterFile: '/private/viewer.counter' },
      },
    };
    const file = join(root, 'functional-profile.json');
    await writeFile(file, JSON.stringify(profile), { mode: 0o600 });
    Object.assign(process.env, {
      OPENPC_FUNCTIONAL_TEST: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      OPENPC_FUNCTIONAL_TEST_PROFILE_FILE: file,
    });
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ code: 'PC-INTEGRATION-5001' }, { status: 503 }))
      .mockResolvedValueOnce(Response.json(contextMode === 'PLATFORM' ? nativePlatform : operator));
    const request = () =>
      new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
        headers: {
          cookie: `openpc_functional_actor=operator; openpc_functional_context=${contextMode}`,
        },
      });
    const unavailable = await localRuntimeStatus(request());
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get('set-cookie')).toBeNull();
    const restored = await localRuntimeStatus(request());
    expect(await restored.json()).toMatchObject({
      authenticated: true,
      functionalTest: true,
      contextMode,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);
it('keeps failed installed configuration distinct from a disabled session service', async () => {
  process.env.OPENPC_BFF_COOKIE_KEY_FILE = join(root, 'missing-cookie-key');
  const failed = await localRuntimeStatus(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session'),
  );
  expect(failed.status).toBe(503);
  expect(failed.headers.get('set-cookie')).toBeNull();
  process.env.OPENPC_LOCAL_RUNTIME = '0';
  const disabled = await localRuntimeStatus(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session'),
  );
  expect(await disabled.json()).toEqual({ enabled: false });
});
