import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { beginInvitationProof, readInvitationResult } from './local-invitation-proof';
import { completeLocalOidc } from './local-oidc-runtime';
import { POST as firstAdministratorCommand } from './invitation-proof/first-administrator/route';
const environment = { ...process.env };
let root = '';
const id = (suffix: string) => `018f0000-0000-7000-8000-000000000${suffix}`;
const input = {
  invitationId: id('701'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  tokenVersion: '1',
  token: Buffer.alloc(32, 7).toString('base64url'),
};
const state = 'S'.repeat(43),
  callback = '/api/v1/ui/oidc-session/callback';
const accepted = {
  invitationId: input.invitationId,
  participantId: input.participantId,
  privacyDomainId: input.privacyDomainId,
  state: 'ACCEPTED',
  tokenVersion: '1',
  membershipId: id('703'),
  membershipStateAtAcceptance: 'PROVISIONED',
  roleIntent: { roleId: id('704'), authorityGranted: false },
  acceptedAt: '2026-09-15T12:00:00.000Z',
  operationId: id('705'),
};
const request = (path: string, init?: ConstructorParameters<typeof NextRequest>[1]) =>
  new NextRequest(`http://localhost:8080${path}`, init);
const cookie = (response: Response, name: string) =>
  `${name}=${new RegExp(`${name}=([^;,]+)`, 'u').exec(response.headers.get('set-cookie') ?? '')?.[1]}`;
function authorized(overrides: Readonly<Record<string, unknown>> = {}) {
  return Response.json(
    {
      transactionId: id('702'),
      state,
      nonce: 'N'.repeat(43),
      codeChallenge: 'A'.repeat(43),
      issuer: 'http://provider:3006',
      clientId: 'workbench',
      redirectUri: `http://localhost:8080${callback}`,
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      ...overrides,
    },
    {
      headers: {
        'set-cookie': `__Host-openpc_invitation_oidc=${id('702')}.browser-secret.verifier-secret; Secure; HttpOnly; SameSite=Strict; Path=/`,
      },
    },
  );
}
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-bff-invitation-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie'])
    await writeFile(join(root, name), name.repeat(32));
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: 'http://gateway:8080',
    OPENPC_IDENTITY_INTERNAL_URL: 'http://identity:3001',
    OPENPC_FACT_INTERNAL_URL: 'http://fact:8081',
    OPENPC_POLICY_INTERNAL_URL: 'http://policy:3002',
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: 'http://localhost:53006/authorize',
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'identity'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'fact'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'policy'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...environment };
  await rm(root, { recursive: true, force: true });
});
const begin = (body: unknown = input, origin = 'http://localhost:8080') =>
  beginInvitationProof(
    request('/api/v1/ui/invitation-proof', {
      method: 'POST',
      headers: { origin, 'host': 'localhost:8080', 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
it.each(['valid', 'wrong issuer', 'missing issuer', 'duplicate issuer', 'injected role'])(
  'binds secured-provider invitation proof to its original issuer without granting authority (%s)',
  async (variant) => {
    const issuer = 'https://idp.example/realms/tegaris';
    process.env.OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL = `${issuer}/protocol/openid-connect/auth`;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(authorized({ issuer }));
    const started = await begin();
    expect(started.status).toBe(200);
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
      fetcher.mockResolvedValueOnce(Response.json(accepted, { status: 201 }));
    const completed = await completeLocalOidc(
      request(`${callback}?${params}`, {
        headers: { cookie: cookie(started, 'openpc_invitation_custody') },
      }),
    );
    expect(completed.headers.get('set-cookie') ?? '').not.toContain('openpc_local_runtime_session');
    if (variant === 'valid') {
      expect(completed.status).toBe(303);
      expect(fetcher).toHaveBeenCalledTimes(2);
      const saved = await readInvitationResult(
        request('/api/v1/ui/invitation-proof', {
          headers: { cookie: cookie(completed, 'openpc_invitation_result') },
        }),
      );
      expect(await saved.json()).toEqual({ acceptance: accepted });
      expect(accepted.roleIntent.authorityGranted).toBe(false);
      expect(JSON.parse(String(fetcher.mock.calls[1]![1]?.body))).toEqual({
        participantId: input.participantId,
        privacyDomainId: input.privacyDomainId,
        transactionId: id('702'),
        state,
        authorizationCode: 'provider-code',
      });
    } else {
      expect(completed.status).not.toBe(303);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  },
);
it('accepts native authorization expiry metadata and caps QA browser custody at five minutes', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
    authorized({
      durationProfile: 'LOCAL_QA_10X',
      expiresAt: new Date(Date.now() + 3_000_000).toISOString(),
    }),
  );
  const started = await begin();
  expect(started.status).toBe(200);
  expect(started.headers.get('set-cookie')).toContain('Max-Age=300');
  expect(await started.text()).not.toContain('LOCAL_QA_10X');
  const now = Date.now();
  vi.spyOn(Date, 'now').mockReturnValue(now + 300_001);
  const expired = await completeLocalOidc(
    request(`${callback}?code=code&state=${state}`, {
      headers: { cookie: cookie(started, 'openpc_invitation_custody') },
    }),
  );
  expect(expired.status).not.toBe(303);
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('expires browser proof at an earlier native deadline before any callback exchange', async () => {
  const now = Date.now();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(authorized({ expiresAt: new Date(now + 30_000).toISOString() }));
  const started = await begin();
  expect(started.status).toBe(200);
  vi.spyOn(Date, 'now').mockReturnValue(now + 30_001);
  const expired = await completeLocalOidc(
    request(`${callback}?code=code&state=${state}`, {
      headers: { cookie: cookie(started, 'openpc_invitation_custody') },
    }),
  );
  expect(expired.status).not.toBe(303);
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each([
  { expiresAt: new Date(Date.now() - 1000).toISOString() },
  { expiresAt: 'not-a-date' },
  { durationProfile: 'UNKNOWN_PROFILE' },
  { injectedAuthority: true },
])('rejects expired, malformed or additional native authorization metadata', async (metadata) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(authorized(metadata));
  const response = await begin();
  expect(response.status).toBe(503);
  expect(response.headers.has('set-cookie')).toBe(false);
});

it('keeps first-administrator custody private and validates command responses against the bound invitation', async () => {
  const bootstrap = {
    mandateId: id('706'),
    sessionToken: `${id('101')}.${id('707')}`,
    state: 'CLAIM_PENDING',
  };
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(authorized())
    .mockResolvedValueOnce(Response.json({ ...accepted, bootstrap }, { status: 201 }));
  const started = await begin();
  const completed = await completeLocalOidc(
    request(`${callback}?code=provider-code&state=${state}`, {
      headers: { cookie: cookie(started, 'openpc_invitation_custody') },
    }),
  );
  const savedCookie = cookie(completed, 'openpc_invitation_result');
  const saved = await readInvitationResult(
    request('/api/v1/ui/invitation-proof', { headers: { cookie: savedCookie } }),
  );
  expect(await saved.json()).toEqual({ acceptance: accepted, firstAdministrator: true });
  const pending = {
    state: 'CLAIM_PENDING',
    mandateId: bootstrap.mandateId,
    participantId: input.participantId,
    invitationId: input.invitationId,
    displayName: 'Administrator',
    enrollmentRequired: true,
    intentDigest: `sha256:${'aa'.repeat(32)}`,
    expiresAt: '2026-09-16T12:00:00.000Z',
    roleId: id('704'),
    actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
  };
  const run = (body: unknown = { command: 'READ' }, origin = 'http://localhost:8080') =>
    firstAdministratorCommand(
      request('/api/v1/ui/invitation-proof/first-administrator', {
        method: 'POST',
        headers: {
          origin,
          'host': 'localhost:8080',
          'Content-Type': 'application/json',
          'cookie': savedCookie,
        },
        body: JSON.stringify(body),
      }),
    );
  fetcher.mockResolvedValueOnce(Response.json(pending));
  const response = await run();
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(pending);
  expect(fetcher.mock.calls.at(-1)![1]?.headers).toMatchObject({
    'Authorization': `Bearer ${'identity'.repeat(32)}`,
    'Cookie': `__Host-openpc_first_admin_custody=${bootstrap.sessionToken}`,
    'Origin': 'http://identity:3001',
    'X-OpenPC-Browser-Origin': 'http://localhost:8080',
  });
  expect(JSON.parse(String(fetcher.mock.calls.at(-1)![1]?.body))).toEqual({
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    request: { command: 'READ' },
  });
  const count = fetcher.mock.calls.length;
  expect((await run({ command: 'READ', participantId: id('999') })).status).not.toBe(200);
  expect((await run({ command: 'READ' }, 'http://foreign.example')).status).not.toBe(200);
  expect(fetcher.mock.calls.length).toBe(count);
  for (const invalid of [
    { ...pending, participantId: id('999') },
    { ...pending, sessionToken: bootstrap.sessionToken },
    { state: 'ACCEPTED' },
  ]) {
    fetcher.mockResolvedValueOnce(Response.json(invalid));
    const rejected = await run();
    expect(rejected.status).not.toBe(200);
    expect(await rejected.text()).not.toContain(bootstrap.sessionToken);
  }
});
it('keeps proof custody opaque, dispatches the exact callback and returns an unprivileged sealed receipt', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(authorized())
    .mockResolvedValueOnce(Response.json(accepted, { status: 201 }));
  const started = await begin({ ...input, loginHint: 'invited-account' });
  expect(started.status).toBe(200);
  const authorization = await started.json();
  const url = new URL(authorization.authorizationUri);
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('login_hint')).toBe('invited-account');
  expect(JSON.stringify(authorization)).not.toContain(input.token);
  expect(started.headers.get('set-cookie')).not.toContain('browser-secret');
  expect(started.headers.get('set-cookie')).not.toContain('verifier-secret');
  const custody = cookie(started, 'openpc_invitation_custody');
  const result = await completeLocalOidc(
    request(`${callback}?code=provider-code&state=${state}`, { headers: { cookie: custody } }),
  );
  expect(result.status).toBe(303);
  expect(result.headers.get('location')).toBe(
    'http://localhost:8080/govern/memberships?view=invitation-acceptance',
  );
  expect(result.headers.get('set-cookie')).not.toContain('openpc_local_runtime_session');
  const saved = await readInvitationResult(
    request('/api/v1/ui/invitation-proof', {
      headers: { cookie: cookie(result, 'openpc_invitation_result') },
    }),
  );
  expect(await saved.json()).toEqual({ acceptance: accepted });
  expect(saved.headers.get('cache-control')).toBe('no-store');
  expect(fetcher).toHaveBeenCalledTimes(2);
  const sent = JSON.parse(String(fetcher.mock.calls[1]![1]?.body));
  expect(sent).toEqual({
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    transactionId: id('702'),
    state,
    authorizationCode: 'provider-code',
  });
});
it.each([401, 403])(
  'returns a native %s denial to the fixed invitation screen without proof or authority',
  async (status) => {
    const privateFailure = 'PRIVATE provider-code original-secret sql=SELECT';
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(authorized())
      .mockResolvedValueOnce(Response.json({ title: privateFailure }, { status }));
    const started = await begin();
    const result = await completeLocalOidc(
      request(`${callback}?code=provider-code&state=${state}`, {
        headers: { cookie: cookie(started, 'openpc_invitation_custody') },
      }),
    );
    expect(result.status).toBe(303);
    expect(result.headers.get('location')).toBe(
      'http://localhost:8080/govern/memberships?view=invitation-acceptance&invitationError=identity_not_verified',
    );
    expect(result.headers.get('cache-control')).toBe('no-store');
    expect(result.headers.get('set-cookie')).toContain('openpc_invitation_custody=;');
    expect(result.headers.get('set-cookie')).toContain('openpc_invitation_result=;');
    expect(result.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(result.headers.get('set-cookie')).not.toContain('openpc_local_runtime_session');
    expect(await result.text()).not.toContain(privateFailure);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);
it.each([500, 503, 'transport'])(
  'retains original callback custody after an uncertain %s response',
  async (status) => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(authorized());
    if (status === 'transport') fetcher.mockRejectedValueOnce(new Error('lost response'));
    else
      fetcher.mockResolvedValueOnce(
        Response.json({ title: 'unavailable' }, { status: Number(status) }),
      );
    const started = await begin();
    const result = await completeLocalOidc(
      request(`${callback}?code=provider-code&state=${state}`, {
        headers: { cookie: cookie(started, 'openpc_invitation_custody') },
      }),
    );
    expect(result.status).toBeGreaterThanOrEqual(400);
    expect(result.headers.has('location')).toBe(false);
    expect(result.headers.has('set-cookie')).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);
it('rejects injected claims, foreign origins, wrong state and custody substitution before exchange', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(authorized());
  expect((await begin({ ...input, subject: 'caller-identity' })).status).toBeGreaterThanOrEqual(
    400,
  );
  expect((await begin(input, 'https://foreign.example')).status).toBeGreaterThanOrEqual(400);
  expect(fetcher).not.toHaveBeenCalled();
  const started = await begin(),
    custody = cookie(started, 'openpc_invitation_custody');
  for (const headers of [
    { cookie: custody },
    { cookie: custody.replace('openpc_invitation_custody', 'openpc_oidc_custody') },
    { cookie: `${custody}x` },
  ]) {
    const value = await completeLocalOidc(
      request(
        `${callback}?code=provider-code&state=${headers.cookie === custody ? 'wrong-state' : state}`,
        { headers },
      ),
    );
    expect(value.status).toBe(307);
    const destination = new URL(value.headers.get('location')!);
    expect(destination.origin).toBe('http://localhost:8080');
    expect(destination.searchParams.get('oidcError')).toBe('authentication_failed');
    expect(value.headers.get('set-cookie')).toContain('openpc_oidc_custody=');
  }
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each([
  { ...accepted, participantId: id('999') },
  { ...accepted, tokenVersion: '2' },
  { ...accepted, roleIntent: { ...accepted.roleIntent, authorityGranted: true } },
])('refuses mismatched or authority-granting acceptance readback', async (body) => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(authorized())
    .mockResolvedValueOnce(Response.json(body, { status: 201 }));
  const started = await begin();
  expect(started.status).toBe(200);
  const result = await completeLocalOidc(
    request(`${callback}?code=provider-code&state=${state}`, {
      headers: { cookie: cookie(started, 'openpc_invitation_custody') },
    }),
  );
  expect(result.status).toBeGreaterThanOrEqual(400);
  expect(result.headers.get('set-cookie')).toBeNull();
});
