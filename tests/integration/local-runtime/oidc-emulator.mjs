import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const defaultQaRedirectUri = 'http://localhost:8080/api/v1/ui/oidc-session/callback';
export function configuredQaRedirectUri(value = defaultQaRedirectUri) {
  const parsed = new URL(value);
  if (
    parsed.href !== value ||
    parsed.origin + parsed.pathname !== value ||
    (parsed.protocol !== 'https:' && value !== defaultQaRedirectUri) ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/api/v1/ui/oidc-session/callback' ||
    parsed.search ||
    parsed.hash
  )
    throw new Error('Invalid local QA callback URI');
  return value;
}
const hasRepeatedFields = (parameters) =>
  [...parameters.keys()].some((key) => parameters.getAll(key).length !== 1);

export function scenarioAccounts(path) {
  if (!path) return {};
  const value = JSON.parse(readFileSync(path, 'utf8'));
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.values(value).some((id) => typeof id !== 'string' || !/^[0-9a-f-]{36}$/u.test(id))
  ) {
    throw new Error('Invalid scenario accounts');
  }
  return value;
}

export function readQaAccounts(path) {
  const accounts = JSON.parse(readFileSync(path, 'utf8'));
  const baseline = ['qa-a-checker', 'qa-a-maker', 'qa-b-checker', 'qa-b-maker'];
  const recovery = ['qa-recovery-executor', 'qa-recovery-custodian-a', 'qa-recovery-custodian-b'];
  const uuid = (value) => typeof value === 'string' && /^[0-9a-f-]{36}$/u.test(value);
  if (
    !accounts ||
    typeof accounts !== 'object' ||
    Array.isArray(accounts) ||
    baseline.some((name) => !Object.hasOwn(accounts, name)) ||
    Object.keys(accounts).some((name) => ![...baseline, ...recovery].includes(name)) ||
    (recovery.some((name) => Object.hasOwn(accounts, name)) &&
      !recovery.every((name) => Object.hasOwn(accounts, name))) ||
    Object.entries(accounts).some(([name, account]) => {
      if (
        !account ||
        !uuid(account.participantId) ||
        typeof account.password !== 'string' ||
        !/^[A-Za-z0-9_-]{32}$/u.test(account.password)
      )
        return true;
      if (baseline.includes(name)) return !uuid(account.principalId) || 'subject' in account;
      // These are external accounts. The native invitation owner creates the
      // internal membership and binds its subject; the IdP supplies no role or grant.
      return (
        Object.keys(account).sort().join(',') !== 'participantId,password,subject' ||
        !uuid(account.subject) ||
        account.participantId !== accounts['qa-a-maker'].participantId
      );
    }) ||
    new Set(Object.values(accounts).map((account) => account.subject ?? account.principalId))
      .size !== Object.keys(accounts).length
  )
    throw new Error('Invalid local QA accounts');
  return accounts;
}
export function qaPasswordMatches(account, password) {
  return (
    typeof password === 'string' &&
    Buffer.byteLength(password) === Buffer.byteLength(account.password) &&
    timingSafeEqual(Buffer.from(password), Buffer.from(account.password))
  );
}
export function startOidcEmulator() {
  const issuer = process.env.OIDC_EMULATOR_ISSUER;
  const principalId = process.env.OIDC_EMULATOR_PRINCIPAL_ID;
  const viewerPrincipalId = process.env.OIDC_EMULATOR_VIEWER_PRINCIPAL_ID;
  const participantId = process.env.OIDC_EMULATOR_PARTICIPANT_ID;
  if (!issuer || !principalId || !viewerPrincipalId || !participantId) process.exit(64);

  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify(publicJwk)).digest('base64url');
  const accounts = {
    operator: principalId,
    viewer: viewerPrincipalId,
    ...JSON.parse(process.env.OIDC_EMULATOR_EXTRA_ACCOUNTS ?? '{}'),
  };
  const codes = new Map();
  const qa =
    process.env.OIDC_EMULATOR_LOCAL_QA === '1'
      ? readQaAccounts(process.env.OIDC_EMULATOR_QA_ACCOUNTS_FILE)
      : undefined;
  const qaRedirectUri = configuredQaRedirectUri(process.env.OIDC_EMULATOR_QA_REDIRECT_URI);
  if (process.env.OIDC_EMULATOR_LOCAL_QA && process.env.OIDC_EMULATOR_LOCAL_QA !== '1')
    process.exit(64);
  const logins = new Map();
  const issue = (response, parameters, account, participant, internalPrincipalId) => {
    const code = randomBytes(32).toString('base64url');
    codes.set(code, {
      ...Object.fromEntries(parameters),
      account,
      participant,
      internalPrincipalId,
      expiresAt: Date.now() + 300000,
    });
    const redirect = new URL(parameters.get('redirect_uri'));
    redirect.searchParams.set('code', code);
    redirect.searchParams.set('state', parameters.get('state'));
    if (new URL(issuer).protocol === 'https:') redirect.searchParams.set('iss', issuer);
    // A native password-form submission must become a GET at the callback.
    response.writeHead(303, { 'location': redirect.href, 'cache-control': 'no-store' });
    response.end();
  };
  const subjects = JSON.parse(process.env.OIDC_EMULATOR_SUBJECTS ?? '{}');
  const encoded = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const sendJson = (response, status, body) => {
    response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(body));
  };
  const sendQaPage = (response, status, heading, description, content) => {
    const styleNonce = randomBytes(16).toString('base64');
    response.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': `default-src 'none'; style-src 'nonce-${styleNonce}'; form-action 'self' ${qaRedirectUri}; base-uri 'none'; frame-ancestors 'none'`,
    });
    return response.end(
      `<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>${heading} | Tegaris</title><style nonce="${styleNonce}">*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 0;background:#f1f5f8;color:#142d43;font:16px/1.5 system-ui,sans-serif}main{width:min(440px,calc(100% - 32px));padding:clamp(24px,5vw,36px);background:#fff;border:1px solid #d8e2e9;border-radius:20px;box-shadow:0 16px 48px #142d430d}.brand{display:flex;align-items:center;gap:12px}.brand-mark{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:#142d43;color:white;font-size:22px;font-weight:700}.brand-name{font-weight:700;letter-spacing:.01em}.brand-product{display:block;color:#52677a;font-size:12px;font-weight:400}h1{font-size:26px;line-height:1.25;margin:28px 0 12px;letter-spacing:-.025em}p{color:#52677a}label{display:block;margin:20px 0;font-size:14px;font-weight:600}input{display:block;width:100%;min-height:48px;margin-top:8px;padding:12px;border:1px solid #7b8da0;border-radius:10px;color:#142d43;background:#fff;font:16px/1.5 system-ui,sans-serif}button,.primary-action{display:block;width:100%;min-height:48px;border:0;border-radius:10px;padding:13px;background:#0c6f65;color:white;font:600 16px/1.5 system-ui,sans-serif;text-align:center;text-decoration:none;cursor:pointer}button:hover,.primary-action:hover{background:#095c54}input:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid #0c6f65;outline-offset:3px}.notice{margin:24px 0 0;padding-top:20px;border-top:1px solid #e2e9ee;font-size:12px;line-height:1.6}.account{overflow-wrap:anywhere}.sign-in-error{margin:24px 0;padding:14px 16px;border:1px solid #c48787;border-radius:10px;background:#fff5f5;color:#7d2525;font-size:14px}</style></head><body><main><div class="brand"><span class="brand-mark" aria-hidden="true">T</span><div class="brand-name">Tegaris<span class="brand-product">Application Privacy</span></div></div><h1>${heading}</h1>${description ? `<p>${description}</p>` : ''}${content}<p class="notice">Demo workspace. Use the account provided by your administrator.</p></main></body></html>`,
    );
  };
  const sendQaSignInFailure = (response) =>
    sendQaPage(
      response,
      403,
      'Sign-in unsuccessful',
      '',
      `<p class="sign-in-error" role="alert">Start a new sign-in and check your account details.</p><a class="primary-action" href="${new URL('/signin', qaRedirectUri).href}">Back to sign in</a>`,
    );

  return createServer(async (request, response) => {
    const url = new URL(request.url, issuer);
    if (request.method === 'GET' && url.pathname === '/healthz')
      return sendJson(response, 200, { status: 'ok' });
    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return sendJson(response, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
        id_token_signing_alg_values_supported: ['RS256'],
      });
    }
    if (request.method === 'GET' && url.pathname === '/jwks') {
      return sendJson(response, 200, { keys: [{ ...publicJwk, kid, use: 'sig', alg: 'RS256' }] });
    }
    if (qa && request.method === 'POST' && url.pathname === '/authorize') {
      let body = '';
      for await (const chunk of request) {
        body += chunk;
        if (body.length > 4096) return sendJson(response, 400, { error: 'invalid_request' });
      }
      const form = new URLSearchParams(body),
        nonce = form.get('nonce'),
        pending = logins.get(nonce);
      logins.delete(nonce);
      const hint = pending?.hint ?? form.get('username');
      if (
        !pending ||
        pending.expiresAt <= Date.now() ||
        hasRepeatedFields(form) ||
        !Object.hasOwn(qa, hint ?? '') ||
        (pending.hint !== undefined &&
          form.has('username') &&
          form.get('username') !== pending.hint) ||
        !qaPasswordMatches(qa[hint], form.get('password'))
      )
        return sendQaSignInFailure(response);
      return issue(
        response,
        pending.parameters,
        qa[hint].subject ?? qa[hint].principalId,
        qa[hint].participantId,
        qa[hint].principalId,
      );
    }
    if (request.method === 'GET' && url.pathname === '/authorize') {
      const required = ['client_id', 'redirect_uri', 'state', 'nonce', 'code_challenge'];
      if (
        required.some((name) => !url.searchParams.get(name)) ||
        url.searchParams.get('response_type') !== 'code' ||
        url.searchParams.get('code_challenge_method') !== 'S256'
      )
        return sendJson(response, 400, { error: 'invalid_request' });
      if (qa) {
        const hint = url.searchParams.get('login_hint');
        if (
          hasRepeatedFields(url.searchParams) ||
          (hint !== null && !Object.hasOwn(qa, hint)) ||
          url.searchParams.get('client_id') !== 'openpc-local-workbench' ||
          url.searchParams.get('redirect_uri') !== qaRedirectUri
        )
          return sendJson(response, 400, { error: 'invalid_local_qa_request' });
        for (const [key, pending] of logins)
          if (pending.expiresAt <= Date.now()) logins.delete(key);
        if (logins.size >= 128) return sendJson(response, 429, { error: 'too_many_requests' });
        const nonce = randomBytes(32).toString('base64url');
        logins.set(nonce, {
          hint: hint ?? undefined,
          parameters: new URLSearchParams(url.searchParams),
          expiresAt: Date.now() + 300000,
        });
        const account =
          hint === null
            ? '<label>Username <input name="username" autocomplete="username" required maxlength="256" autofocus></label>'
            : `<p class="account">Account: ${hint}</p>`;
        return sendQaPage(
          response,
          200,
          'Sign in to your account',
          'Continue to your organization’s workspace.',
          `<form method="post" action="/authorize"><input type="hidden" name="nonce" value="${nonce}">${account}<label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="64"${hint === null ? '' : ' autofocus'}></label><button type="submit">Sign in</button></form>`,
        );
      }
      let scopedAccounts = {};
      if (process.env.OIDC_EMULATOR_SCENARIO_ACCOUNTS_FILE) {
        try {
          scopedAccounts = scenarioAccounts(process.env.OIDC_EMULATOR_SCENARIO_ACCOUNTS_FILE);
        } catch {
          return sendJson(response, 503, { error: 'scenario_accounts_unavailable' });
        }
      }
      const account = { ...accounts, ...scopedAccounts }[
        url.searchParams.get('login_hint') ?? 'operator'
      ];
      if (!account) return sendJson(response, 400, { error: 'unknown_account' });
      const code = randomBytes(32).toString('base64url');
      codes.set(code, { ...Object.fromEntries(url.searchParams), account });
      const redirect = new URL(url.searchParams.get('redirect_uri'));
      redirect.searchParams.set('code', code);
      redirect.searchParams.set('state', url.searchParams.get('state'));
      response.writeHead(302, { 'location': redirect.href, 'cache-control': 'no-store' });
      return response.end();
    }
    if (request.method === 'POST' && url.pathname === '/token') {
      let body = '';
      for await (const chunk of request) {
        body += chunk;
        if (qa && body.length > 4096) return sendJson(response, 400, { error: 'invalid_request' });
      }
      const form = new URLSearchParams(body);
      if (qa && hasRepeatedFields(form))
        return sendJson(response, 400, { error: 'invalid_request' });
      const code = form.get('code');
      const grant = code ? codes.get(code) : undefined;
      if (
        !grant ||
        (grant.expiresAt !== undefined && grant.expiresAt <= Date.now()) ||
        form.get('grant_type') !== 'authorization_code' ||
        form.get('client_id') !== grant.client_id ||
        form.get('redirect_uri') !== grant.redirect_uri ||
        createHash('sha256')
          .update(form.get('code_verifier') ?? '')
          .digest('base64url') !== grant.code_challenge
      )
        return sendJson(response, 400, { error: 'invalid_grant' });
      codes.delete(code);
      const now = Math.floor(Date.now() / 1000);
      const header = encoded({ alg: 'RS256', typ: 'JWT', kid });
      const payload = encoded({
        iss: issuer,
        aud: grant.client_id,
        azp: grant.client_id,
        sub: qa
          ? grant.account
          : (grant.openpc_test_subject ??
            subjects[grant.login_hint ?? 'operator'] ??
            grant.account),
        nonce: grant.nonce,
        iat: now,
        auth_time:
          qa || grant.openpc_test_auth_time === undefined
            ? now
            : Number(grant.openpc_test_auth_time),
        exp: now + 300,
        openpc_principal_id: qa
          ? grant.internalPrincipalId
          : (grant.openpc_test_principal_id ?? grant.account),
        openpc_participant_id: qa ? grant.participant : participantId,
      });
      const signature = sign(
        'RSA-SHA256',
        Buffer.from(`${header}.${payload}`),
        privateKey,
      ).toString('base64url');
      return sendJson(response, 200, {
        token_type: 'Bearer',
        expires_in: 300,
        id_token: `${header}.${payload}.${signature}`,
      });
    }
    return sendJson(response, 404, { error: 'not_found' });
  }).listen(Number(process.env.OIDC_EMULATOR_PORT ?? 3006), '0.0.0.0');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) startOidcEmulator();
