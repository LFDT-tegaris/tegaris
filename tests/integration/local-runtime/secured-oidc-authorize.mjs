import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

export async function authorizeSecuredOidcAccount(fixture, account, nativeAuthorization) {
  const issuer = new URL(fixture.issuer);
  assert(
    issuer.protocol === 'https:' &&
      !issuer.username &&
      !issuer.password &&
      !issuer.search &&
      !issuer.hash,
  );
  const redirectUri = 'http://localhost:8080/api/v1/ui/oidc-session/callback';
  assert(typeof account.password === 'string' && account.password.length >= 32);
  assert(typeof account.externalSubject === 'string' && account.externalSubject.length > 0);
  const verifier = randomBytes(48).toString('base64url');
  const nonce = nativeAuthorization?.nonce ?? randomBytes(32).toString('base64url');
  const state = nativeAuthorization?.state ?? randomBytes(32).toString('base64url');
  const cookies = new Map();
  async function request(url, options = {}) {
    assert(new URL(url).origin === issuer.origin, 'Provider origin changed');
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; '),
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';', 1)[0];
      const equals = pair.indexOf('=');
      assert(equals > 0, 'Malformed provider cookie');
      cookies.set(pair.slice(0, equals), pair.slice(equals + 1));
    }
    return response;
  }
  const authorization = new URL(`${fixture.issuer}/protocol/openid-connect/auth`);
  authorization.search = new URLSearchParams({
    response_type: 'code',
    client_id: fixture.clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile',
    prompt: 'login',
    state,
    nonce,
    code_challenge_method: 'S256',
    code_challenge:
      nativeAuthorization?.codeChallenge ??
      createHash('sha256').update(verifier).digest('base64url'),
  }).toString();
  const page = await request(authorization);
  assert(page.status === 200, 'Expected genuine provider password form');
  const html = await page.text();
  const form = html.match(/<form\b[^>]*\bid="kc-form-login"[^>]*>/iu)?.[0];
  const action = form?.match(/\baction="([^"]+)"/iu)?.[1];
  assert(action, 'Provider login form missing');
  const destination = new URL(action.replaceAll('&amp;', '&'));
  assert(destination.origin === issuer.origin, 'Foreign login destination rejected');
  assert(
    destination.pathname === `${issuer.pathname}/login-actions/authenticate`,
    'Unexpected provider action',
  );
  const result = await request(destination, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      username: account.username,
      password: account.password,
      credentialId: '',
    }),
  });
  assert(result.status === 302, 'Fixture login did not produce an authorization code');
  const callback = new URL(result.headers.get('location'));
  assert(callback.origin + callback.pathname === redirectUri, 'Callback destination changed');
  assert(callback.searchParams.get('state') === state, 'Callback state mismatch');
  assert(callback.searchParams.get('iss') === fixture.issuer, 'Callback issuer mismatch');
  const code = callback.searchParams.get('code');
  assert(code, 'Authorization code missing');
  if (nativeAuthorization) {
    return { transactionId: nativeAuthorization.transactionId, state, authorizationCode: code };
  }
  return {
    issuer: fixture.issuer,
    clientId: fixture.clientId,
    redirectUri,
    authorizationCode: code,
    codeVerifier: verifier,
    expectedNonceDigest: `sha256:${createHash('sha256').update(nonce).digest('hex')}`,
  };
}
