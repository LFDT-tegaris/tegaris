import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { beginLocalOidc, completeLocalOidc } from './local-oidc-runtime';

let root = '';
const original = { ...process.env };
const state = 'oidc-state-value-00000000000000000000000001';
const transactionId = '018f0000-0000-7000-8000-000000000701';
const rawSessionToken = '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000702';

it.each(
  ['http://127.0.0.1:8080', 'https://demo.example.org'].flatMap((origin) =>
    ['valid', 'wrong issuer', 'missing issuer', 'duplicate issuer', 'injected role'].map(
      (variant) => [origin, variant] as const,
    ),
  ),
)(
  'binds a secured-provider login callback to native sealed custody (%s, %s)',
  async (origin, variant) => {
    const issuer = 'https://idp.example/realms/tegaris';
    process.env.OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL = `${issuer}/protocol/openid-connect/auth`;
    process.env.OPENPC_OIDC_PARTICIPANT_ID = '018f0000-0000-7000-8000-000000000101';
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      Response.json(
        {
          transactionId,
          state,
          nonce: 'N'.repeat(43),
          codeChallenge: 'A'.repeat(43),
          issuer,
          clientId: 'tegaris',
          redirectUri: `${origin}/api/v1/ui/oidc-session/callback`,
        },
        {
          headers: {
            'set-cookie': `__Host-openpc_oidc=${transactionId}.browser-secret.verifier-secret; Secure; HttpOnly; Path=/`,
          },
        },
      ),
    );
    const started = await beginLocalOidc(
      request(
        '/api/v1/ui/oidc-session',
        {
          method: 'POST',
          headers: {
            'origin': origin,
            'host': new URL(origin).host,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            returnPath: '/home/session',
          }),
        },
        origin,
      ),
    );
    expect(started.status).toBe(200);
    expect(JSON.parse(fetcher.mock.calls[0]?.[1]?.body as string)).toEqual({
      participantId: '018f0000-0000-7000-8000-000000000101',
    });
    expect(started.cookies.get('openpc_oidc_custody')?.secure).toBe(origin.startsWith('https:'));
    const auth = new URL((await started.json()).authorizationUri);
    expect(auth.origin).toBe('https://idp.example');
    expect(auth.pathname).toBe('/realms/tegaris/protocol/openid-connect/auth');
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
    const params = new URLSearchParams({
      code: 'provider-code',
      state,
      iss: issuer,
      session_state: 'provider-session_1',
    });
    if (variant === 'wrong issuer') params.set('iss', 'https://attacker.example');
    if (variant === 'missing issuer') params.delete('iss');
    if (variant === 'duplicate issuer') params.append('iss', issuer);
    if (variant === 'injected role') params.set('role', 'admin');
    if (variant === 'valid')
      fetcher
        .mockResolvedValueOnce(
          Response.json(
            {},
            {
              status: 201,
              headers: {
                'set-cookie': `__Host-openpc_session=${rawSessionToken}; Secure; HttpOnly; Path=/`,
              },
            },
          ),
        )
        .mockResolvedValueOnce(
          Response.json({
            role: 'viewer',
            sessionId: '018f0000-0000-7000-8000-000000000702',
            principalId: '018f0000-0000-7000-8000-000000000112',
            participantId: '018f0000-0000-7000-8000-000000000101',
            contextMode: 'PLATFORM',
            contextEpoch: '1',
            stepUpVerifiedAt: null,
          }),
        );
    const completed = await completeLocalOidc(
      request(
        `/api/v1/ui/oidc-session/callback?${params}`,
        {
          headers: { cookie: cookieFrom(started, 'openpc_oidc_custody') },
        },
        origin,
      ),
    );
    expect(completed.cookies.get('openpc_oidc_custody')?.secure).toBe(origin.startsWith('https:'));
    if (variant === 'valid') {
      expect(completed.cookies.get('openpc_local_runtime_session')?.secure).toBe(
        origin.startsWith('https:'),
      );
      expect(completed.headers.get('location')).toBe(`${origin}/home/session`);
      expect(fetcher).toHaveBeenCalledTimes(3);
      expect(JSON.parse(String(fetcher.mock.calls[1]![1]?.body))).toEqual({
        transactionId,
        state,
        authorizationCode: 'provider-code',
      });
    } else {
      expect(completed.headers.get('location')).toContain('oidcError=authentication_failed');
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(completed.headers.get('set-cookie')).not.toContain('openpc_local_runtime_session=');
    }
  },
);

function request(
  path: string,
  init?: ConstructorParameters<typeof NextRequest>[1],
  origin = 'http://127.0.0.1:8080',
) {
  return new NextRequest(`${origin}${path}`, init);
}

function cookieFrom(response: Response, name: string): string {
  const match = new RegExp(`${name}=([^;,]+)`, 'u').exec(response.headers.get('set-cookie') ?? '');
  if (!match?.[1]) throw new Error(`missing ${name}`);
  return `${name}=${match[1]}`;
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-bff-oidc-'));
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

describe('local OIDC BFF custody', () => {
  it.each([
    undefined,
    '018f0000-0000-7000-8000-000000000101',
    '018f0000-0000-7000-8000-000000000999',
  ])('keeps custody opaque and fences the selected Participant (%s)', async (participantId) => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        Response.json(
          {
            transactionId,
            state,
            nonce: 'oidc-nonce-value-00000000000000000000000001',
            codeChallenge: 'A'.repeat(43),
            issuer: 'http://oidc-emulator:3006',
            clientId: 'openpc-local-workbench',
            redirectUri: 'http://127.0.0.1:8080/api/v1/ui/oidc-session/callback',
          },
          {
            headers: {
              'set-cookie': `__Host-openpc_oidc=${transactionId}.browser-session.code-verifier; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=300`,
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        Response.json(
          { status: 'authenticated' },
          {
            status: 201,
            headers: {
              'set-cookie': `__Host-openpc_session=${rawSessionToken}; Secure; HttpOnly; SameSite=Strict; Path=/`,
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        Response.json({
          role: 'viewer',
          sessionId: '018f0000-0000-7000-8000-000000000702',
          principalId: '018f0000-0000-7000-8000-000000000112',
          participantId: '018f0000-0000-7000-8000-000000000101',
          contextMode: 'PLATFORM',
          contextEpoch: '1',
          stepUpVerifiedAt: null,
          assignmentId: '018f0000-0000-7000-8000-000000000703',
          authorityEpoch: '1',
        }),
      );
    const begin = await beginLocalOidc(
      request('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: {
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          returnPath: '/configure/policies',
          freshAuthentication: true,
          loginHint: 'qa-a-checker',
          ...(participantId === undefined ? {} : { participantId }),
        }),
      }),
    );
    expect(begin.status).toBe(200);
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual(
      participantId === undefined ? {} : { participantId },
    );
    const authorization = await begin.json();
    expect(authorization).toMatchObject({ state });
    expect(new URL(authorization.authorizationUri).searchParams.get('login_hint')).toBe(
      'qa-a-checker',
    );
    expect(new URL(authorization.authorizationUri).searchParams.get('max_age')).toBe('0');
    expect(new URL(authorization.authorizationUri).searchParams.get('prompt')).toBe('login');
    const custodyCookie = cookieFrom(begin, 'openpc_oidc_custody');
    expect(Buffer.from(custodyCookie.split('=')[1]!, 'base64url').toString('utf8')).not.toContain(
      '__Host-openpc_oidc',
    );

    const callback = await completeLocalOidc(
      new NextRequest(
        `http://0.0.0.0:3000/api/v1/ui/oidc-session/callback?code=${'c'.repeat(32)}&state=${state}`,
        {
          headers: { cookie: custodyCookie },
        },
      ),
    );
    if (participantId?.endsWith('999')) {
      expect(callback.status).toBe(307);
      expect(callback.headers.get('location')).toBe(
        'http://127.0.0.1:8080/signin?returnTo=%2Fconfigure%2Fpolicies&oidcError=authentication_failed',
      );
      expect(
        /openpc_local_runtime_session=([^;]*)/u.exec(
          callback.headers.get('set-cookie') ?? '',
        )?.[1] ?? '',
      ).toBe('');
      expect(callback.headers.get('set-cookie')).toContain('openpc_oidc_custody=;');
      return;
    }
    expect(callback.status).toBe(307);
    expect(callback.headers.get('location')).toBe('http://127.0.0.1:8080/configure/policies');
    const sessionCookie = cookieFrom(callback, 'openpc_local_runtime_session');
    expect(Buffer.from(sessionCookie.split('=')[1]!, 'base64url').toString('utf8')).not.toContain(
      rawSessionToken,
    );
    expect(fetchMock.mock.calls[1]?.[1]?.headers).toMatchObject({
      Cookie: expect.stringContaining('__Host-openpc_oidc='),
    });
    expect(String(fetchMock.mock.calls[2]?.[1]?.body)).toContain(rawSessionToken);
  });

  it('rejects cross-origin begin and tampered callback custody before identity calls', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    const crossOrigin = await beginLocalOidc(
      request('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: {
          'host': '127.0.0.1:8080',
          'origin': 'https://attacker.example',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ returnPath: '/' }),
      }),
    );
    expect(crossOrigin.status).toBe(403);
    const networkPath = await beginLocalOidc(
      request('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: {
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ returnPath: '//attacker.example' }),
      }),
    );
    expect(networkPath.status).toBe(400);
    const callbackReturnPath = await beginLocalOidc(
      request('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: {
          'host': '127.0.0.1:8080',
          'origin': 'http://127.0.0.1:8080',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          returnPath: '/api/v1/ui/oidc-session/callback?code=reused',
        }),
      }),
    );
    expect(callbackReturnPath.status).toBe(400);
    const tampered = await completeLocalOidc(
      request(`/api/v1/ui/oidc-session/callback?code=${'c'.repeat(32)}&state=${state}`, {
        headers: { cookie: `openpc_oidc_custody=${'A'.repeat(80)}` },
      }),
    );
    expect(tampered.status).toBe(307);
    expect(tampered.headers.get('location')).toBe(
      'http://localhost:8080/signin?oidcError=authentication_failed',
    );
    expect(tampered.headers.get('set-cookie')).toContain('openpc_oidc_custody=;');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

it('pins a shorter normal OIDC owner expiry and rejects it after QA opt-in', async () => {
  const issuedAt = Date.now(),
    expiry = issuedAt + 30000;
  let now = issuedAt;
  vi.spyOn(Date, 'now').mockImplementation(() => now);
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
    Response.json(
      {
        transactionId,
        state,
        nonce: 'oidc-nonce-value-00000000000000000000000001',
        codeChallenge: 'A'.repeat(43),
        issuer: 'http://oidc-emulator:3006',
        clientId: 'openpc-local-workbench',
        redirectUri: 'http://127.0.0.1:8080/api/v1/ui/oidc-session/callback',
        expiresAt: new Date(expiry).toISOString(),
      },
      {
        headers: {
          'set-cookie': `__Host-openpc_oidc=${transactionId}.browser-session.code-verifier; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=30`,
        },
      },
    ),
  );
  const begun = await beginLocalOidc(
    request('/api/v1/ui/oidc-session', {
      method: 'POST',
      headers: {
        'host': '127.0.0.1:8080',
        'origin': 'http://127.0.0.1:8080',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ returnPath: '/home/session' }),
    }),
  );
  expect(begun.status).toBe(200);
  expect(Date.parse((await begun.json()).expiresAt)).toBe(expiry);
  const cookie = cookieFrom(begun, 'openpc_oidc_custody');
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  });
  now = expiry;
  const result = await completeLocalOidc(
    request(`/api/v1/ui/oidc-session/callback?code=unused&state=${state}`, {
      headers: { host: '127.0.0.1:8080', cookie },
    }),
  );
  expect(result.headers.get('location')).toContain('oidcError=authentication_failed');
  expect(fetcher).toHaveBeenCalledOnce();
});
