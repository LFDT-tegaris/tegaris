import assert from 'node:assert/strict';
import { readFile, realpath, stat } from 'node:fs/promises';
import { authorizeSecuredOidcAccount } from './secured-oidc-authorize.mjs';

async function privateJson(path) {
  assert(path && (await realpath(path)) === path);
  const metadata = await stat(path);
  assert((metadata.mode & 0o777) === 0o600 && metadata.uid === process.getuid());
  return JSON.parse(await readFile(path, 'utf8'));
}

assert(process.env.NODE_EXTRA_CA_CERTS && process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0');
const fixture = await privateJson(process.argv[2]);
const initial = await privateJson(process.argv[3]);
assert(fixture.providerReadback === 'PASS' && fixture.nativeAuthority === 'NOT_ASSIGNED');
assert(initial.owner === 'tegaris-secured-oidc-initial:20261011');
assert(initial.state === 'FRESH_INITIAL_TRUST_ONLY' && initial.issuer === fixture.issuer);
assert(initial.bindings.length === 2 && fixture.accounts.length === 9);
assert(fixture.clientId === 'openpc-local-workbench');
assert(new Set(fixture.accounts.map((a) => a.username)).size === 9);
assert(new Set(fixture.accounts.map((a) => a.externalSubject)).size === 9);
assert(new Set(initial.bindings.map((a) => a.principalId)).size === 2);
assert.deepEqual(initial.bindings.map((a) => [a.username, a.principalId]).sort(), [
  ['tegaris-test-admin', '018f0000-0000-7000-8000-000000000111'],
  ['tegaris-test-auditor', '018f0000-0000-7000-8000-000000000112'],
]);
for (const binding of initial.bindings) {
  const account = fixture.accounts.find((a) => a.username === binding.username);
  assert(account && account.externalSubject === binding.externalSubject);
}
assert(initial.restartReadyPath === '/probe-coordination/restart-complete');
const identity = 'http://tegaris-native-oidc-initial:3001';
const participantId = '018f0000-0000-7000-8000-000000000101';
const sessions = [];

async function native(path, options = {}) {
  return fetch(`${identity}${path}`, {
    ...options,
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  });
}

for (const account of fixture.accounts) {
  const bound = initial.bindings.find((b) => b.username === account.username);
  if (bound) assert(bound.externalSubject === account.externalSubject);
  const started = await native('/api/v1/session/oidc/authorization', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ participantId }),
  });
  assert(started.status === 200);
  const authorization = await started.json();
  assert(authorization.issuer === fixture.issuer && authorization.clientId === fixture.clientId);
  assert(authorization.redirectUri === 'http://localhost:8080/api/v1/ui/oidc-session/callback');
  assert(typeof authorization.transactionId === 'string');
  assert(/^[A-Za-z0-9_-]{43,128}$/u.test(authorization.codeChallenge));
  assert(typeof authorization.state === 'string' && authorization.state.length >= 32);
  assert(typeof authorization.nonce === 'string' && authorization.nonce.length >= 32);
  const custody = started.headers
    .getSetCookie()
    .map((c) => c.split(';', 1)[0])
    .find((c) => c.startsWith('__Host-openpc_oidc='));
  assert(custody);
  const body = await authorizeSecuredOidcAccount(fixture, account, authorization);
  const options = {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cookie': custody },
    body: JSON.stringify(body),
  };
  const callback = await native('/api/v1/session/oidc/callback', options);
  assert(callback.status === (bound ? 201 : 401), 'Native initial binding result differed');
  const cookie = callback.headers
    .getSetCookie()
    .map((c) => c.split(';', 1)[0])
    .find((c) => c.startsWith('__Host-openpc_session='));
  if (bound) {
    assert(cookie);
    const readback = await native('/api/v1/session', { headers: { cookie } });
    assert(readback.status === 200);
    const snapshot = await readback.json();
    assert(snapshot.participantId === participantId && snapshot.principalId === bound.principalId);
    assert(snapshot.contextMode === 'PLATFORM' && !('stepUpVerifiedAt' in snapshot));
    assert(snapshot.state === 'ACTIVE' && typeof snapshot.sessionId === 'string');
    sessions.push({ cookie, snapshot });
  } else {
    assert(!cookie && (await callback.json()).error?.code === 'PC-AUTH-0002');
    assert((await native('/api/v1/session', { headers: { cookie: custody } })).status === 401);
  }
  const replay = await native('/api/v1/session/oidc/callback', options);
  assert(replay.status === 401 && (await replay.json()).error?.code === 'PC-AUTH-0002');
  assert(!replay.headers.getSetCookie().some((c) => c.startsWith('__Host-openpc_session=')));
}
assert(sessions.length === 2);
process.stdout.write('SECURED_OIDC_INITIAL_RESTART_READY\n');
const deadline = Date.now() + 90_000;
while (true) {
  try {
    assert((await readFile(initial.restartReadyPath, 'utf8')) === initial.owner + '\n');
    break;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    assert(Date.now() < deadline, 'Owned restart did not finish');
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}
for (const { cookie, snapshot } of sessions) {
  const response = await native('/api/v1/session', { headers: { cookie } });
  assert(response.status === 200);
  const recovered = await response.json();
  for (const key of [
    'sessionId',
    'principalId',
    'participantId',
    'contextMode',
    'contextEpoch',
    'state',
  ])
    assert(recovered[key] === snapshot[key], `Restart changed ${key}`);
  assert(!('stepUpVerifiedAt' in recovered));
}
process.stdout.write(
  'SECURED_OIDC_INITIAL_SESSION|PASS|real-provider-Code-PKCE|2-exact-initial-bindings|7-unbound-denied|all-replays-denied|native-restart-readback|cookies-memory-only|governed-onboarding-and-role-grants-NOT_TESTED\n',
);
