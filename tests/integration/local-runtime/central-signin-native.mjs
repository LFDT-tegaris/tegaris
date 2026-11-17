import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { authorizeSecuredOidcAccount } from './secured-oidc-authorize.mjs';
import {
  beginLocalOidc,
  completeLocalOidc,
} from '../../../apps/admin-web/app/api/v1/ui/local-oidc-runtime.ts';
import { readWorkspaceSession } from '../../../apps/admin-web/app/api/v1/ui/workspace-session.ts';
const require = createRequire(new URL('../../../apps/admin-web/package.json', import.meta.url));
const { NextRequest } = await import(pathToFileURL(require.resolve('next/server')));
const fixture = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert(fixture.providerReadback === 'PASS' && fixture.nativeAuthority === 'NOT_ASSIGNED');
const account = fixture.accounts.find((value) => value.username === 'tegaris-test-auditor');
assert(account);
const origin = 'http://localhost:8080';
const start = await beginLocalOidc(
  new NextRequest(`${origin}/api/v1/ui/oidc-session`, {
    method: 'POST',
    headers: { 'host': 'localhost:8080', 'origin': origin, 'content-type': 'application/json' },
    // The central page supplies no Participant or principal identifiers.
    body: JSON.stringify({ returnPath: '/operate/evidence' }),
  }),
);
assert.equal(start.status, 200);
const issued = await start.json();
const uri = new URL(issued.authorizationUri);
const authorization = {
  issuer: fixture.issuer,
  clientId: fixture.clientId,
  redirectUri: uri.searchParams.get('redirect_uri'),
  state: uri.searchParams.get('state'),
  nonce: uri.searchParams.get('nonce'),
  codeChallenge: uri.searchParams.get('code_challenge'),
};
assert.equal(uri.origin, new URL(fixture.issuer).origin);
assert.equal(uri.searchParams.get('code_challenge_method'), 'S256');
const returned = await authorizeSecuredOidcAccount(fixture, account, authorization);
const callback = new URL('/api/v1/ui/oidc-session/callback', origin);
callback.searchParams.set('code', returned.authorizationCode);
callback.searchParams.set('state', returned.state);
callback.searchParams.set('iss', fixture.issuer);
const custody = start.cookies.get('openpc_oidc_custody')?.value;
assert(custody);
const finish = await completeLocalOidc(
  new NextRequest(callback, {
    headers: { host: 'localhost:8080', cookie: `openpc_oidc_custody=${custody}` },
  }),
);
assert.equal(finish.status, 307);
assert.equal(finish.headers.get('location'), `${origin}/operate/evidence`);
assert.equal(finish.headers.get('cache-control'), 'no-store');
const cookie = finish.cookies.get('openpc_local_runtime_session')?.value;
assert(cookie);
const session = await readWorkspaceSession(cookie);
assert(session?.authenticated);
assert.equal(session.principalId, '018f0000-0000-7000-8000-000000000112');
assert.equal(session.participantId, process.env.OPENPC_OIDC_PARTICIPANT_ID);
assert.equal(session.role, 'viewer');
assert.equal(Object.hasOwn(session, 'stepUpVerifiedAt'), false);
const replay = await completeLocalOidc(
  new NextRequest(callback, {
    headers: { host: 'localhost:8080', cookie: `openpc_oidc_custody=${custody}` },
  }),
);
assert.equal(new URL(replay.headers.get('location')).pathname, '/signin');
assert.equal(replay.cookies.get('openpc_local_runtime_session'), undefined);
process.stdout.write(
  'CENTRAL_SIGNIN_NATIVE|PASS|standard-provider-claims|configured-organization|native-session-gate|safe-deep-link|replay-denied\n',
);
