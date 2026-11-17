import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { startOidcEmulator } from './oidc-emulator.mjs';

const redirectUri = 'https://console.example.test/api/v1/ui/oidc-session/callback';

async function withProvider(run) {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-signin-'));
  const participantIds = [randomUUID(), randomUUID()];
  const accounts = Object.fromEntries(
    ['qa-a-maker', 'qa-a-checker', 'qa-b-maker', 'qa-b-checker'].map((name, index) => [
      name,
      {
        participantId: participantIds[Math.floor(index / 2)],
        principalId: randomUUID(),
        password: randomBytes(24).toString('base64url'),
      },
    ]),
  );
  const settings = {
    OIDC_EMULATOR_ISSUER: 'http://signin.example.test',
    OIDC_EMULATOR_PRINCIPAL_ID: accounts['qa-a-maker'].principalId,
    OIDC_EMULATOR_VIEWER_PRINCIPAL_ID: accounts['qa-a-checker'].principalId,
    OIDC_EMULATOR_PARTICIPANT_ID: participantIds[0],
    OIDC_EMULATOR_LOCAL_QA: '1',
    OIDC_EMULATOR_QA_ACCOUNTS_FILE: join(root, 'accounts.json'),
    OIDC_EMULATOR_QA_REDIRECT_URI: redirectUri,
    OIDC_EMULATOR_EXTRA_ACCOUNTS: '{}',
    OIDC_EMULATOR_SUBJECTS: '{}',
    OIDC_EMULATOR_PORT: '0',
  };
  const previous = Object.fromEntries(
    Object.keys(settings).map((name) => [name, process.env[name]]),
  );
  let server;
  try {
    await writeFile(settings.OIDC_EMULATOR_QA_ACCOUNTS_FILE, JSON.stringify(accounts), {
      mode: 0o600,
    });
    Object.assign(process.env, settings);
    server = startOidcEmulator();
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    const verifier = randomBytes(32).toString('base64url');
    const parameters = new URLSearchParams({
      response_type: 'code',
      client_id: 'openpc-local-workbench',
      redirect_uri: redirectUri,
      state: randomBytes(24).toString('base64url'),
      nonce: randomBytes(24).toString('base64url'),
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    const begin = async () => {
      const response = await fetch(`${origin}/authorize?${parameters}`, { redirect: 'manual' });
      assert.equal(response.status, 200);
      const html = await response.text();
      const nonce = /name="nonce" value="([A-Za-z0-9_-]+)"/u.exec(html)?.[1];
      assert.ok(nonce);
      return { response, html, nonce };
    };
    const submit = (nonce, password, username = 'qa-a-maker') =>
      fetch(`${origin}/authorize`, {
        method: 'POST',
        body: new URLSearchParams({ nonce, password, username }),
        redirect: 'manual',
      });
    await run({ accounts, origin, parameters, verifier, begin, submit });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
}

async function assertFailure(response, accounts) {
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('location'), null);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('content-type'), /^text\/html\b/u);
  const html = await response.text();
  assert.match(html, /<h1>Sign-in unsuccessful<\/h1>/u);
  assert.match(html, /role="alert"/u);
  assert.match(html, /href="https:\/\/console\.example\.test\/signin">Back to sign in<\/a>/u);
  assert.ok(!html.includes('invalid_local_qa_login'));
  assert.ok(!html.includes('name="password"'));
  for (const [name, account] of Object.entries(accounts)) {
    for (const secret of [name, account.principalId, account.participantId, account.password])
      assert.ok(!html.includes(secret));
  }
  const nonce = /<style nonce="([A-Za-z0-9+/=]+)">/u.exec(html)?.[1];
  assert.ok(nonce);
  assert.equal(
    response.headers.get('content-security-policy'),
    `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self' ${redirectUri}; base-uri 'none'; frame-ancestors 'none'`,
  );
  return html;
}

test('sign-in page presents labelled controls without revealing demo account records', async () => {
  await withProvider(async ({ accounts, begin }) => {
    const { html } = await begin();
    assert.match(html, /<h1>Sign in to your account<\/h1>/u);
    assert.match(html, /Username <input name="username" autocomplete="username"/u);
    assert.match(
      html,
      /Password <input type="password" name="password" autocomplete="current-password"/u,
    );
    assert.match(html, /Demo workspace\./u);
    for (const [name, account] of Object.entries(accounts)) {
      assert.ok(!html.includes(name));
      assert.ok(!html.includes(account.password));
    }
  });
});

test('rejected sign-in shows a safe restart action and keeps its nonce consumed', async () => {
  await withProvider(async ({ accounts, begin, submit }) => {
    const { nonce } = await begin();
    await assertFailure(await submit(nonce, 'incorrect-password'), accounts);
    await assertFailure(await submit(nonce, accounts['qa-a-maker'].password), accounts);
    const fresh = await begin();
    const html = await assertFailure(
      await submit(fresh.nonce, accounts['qa-a-maker'].password, '<script>untrusted</script>'),
      accounts,
    );
    assert.ok(!html.includes('<script>untrusted</script>'));
  });
});

test('expired sign-in shows the same restart page without extending the request', async () => {
  await withProvider(async ({ accounts, begin, submit }) => {
    const { nonce } = await begin();
    const realNow = Date.now;
    try {
      const afterExpiry = realNow() + 300001;
      Date.now = () => afterExpiry;
      await assertFailure(await submit(nonce, accounts['qa-a-maker'].password), accounts);
    } finally {
      Date.now = realNow;
    }
    await assertFailure(await submit(nonce, accounts['qa-a-maker'].password), accounts);
  });
});

test('successful sign-in still binds its account, callback, PKCE and one-time code', async () => {
  await withProvider(async ({ accounts, origin, parameters, verifier, begin, submit }) => {
    const { nonce } = await begin();
    const response = await submit(nonce, accounts['qa-a-maker'].password);
    assert.equal(response.status, 303);
    const callback = new URL(response.headers.get('location'));
    assert.equal(callback.origin + callback.pathname, redirectUri);
    assert.equal(callback.searchParams.get('state'), parameters.get('state'));
    const exchange = (proof) =>
      fetch(`${origin}/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: parameters.get('client_id'),
          redirect_uri: redirectUri,
          code: callback.searchParams.get('code'),
          code_verifier: proof,
        }),
      });
    assert.equal((await exchange('incorrect-verifier')).status, 400);
    const token = await exchange(verifier);
    assert.equal(token.status, 200);
    const claims = JSON.parse(
      Buffer.from((await token.json()).id_token.split('.')[1], 'base64url'),
    );
    assert.equal(claims.sub, accounts['qa-a-maker'].principalId);
    assert.equal(claims.openpc_participant_id, accounts['qa-a-maker'].participantId);
    assert.equal(claims.nonce, parameters.get('nonce'));
    assert.equal((await exchange(verifier)).status, 400);
    await assertFailure(await submit(nonce, accounts['qa-a-maker'].password), accounts);
  });
});
