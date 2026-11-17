import assert from 'node:assert/strict';
import { authorizeSecuredOidcAccount } from './secured-oidc-authorize.mjs';
import { randomBytes } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import {
  createHttpOidcIdentityProofAdapter,
  createHttpOidcTrustAdapter,
} from '../../../services/identity-service/src/domain/http-oidc-trust-adapter.ts';

const fixturePath = process.argv[2];
assert(fixturePath && (await realpath(fixturePath)) === fixturePath, 'Exact fixture path required');
const metadata = await stat(fixturePath);
assert((metadata.mode & 0o777) === 0o600, 'Fixture must remain owner-only');
assert(metadata.uid === process.getuid(), 'Fixture owner mismatch');
assert(process.env.NODE_EXTRA_CA_CERTS, 'Explicit provider certificate trust required');
assert(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'TLS validation must remain enabled');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
assert(fixture.nativeAuthority === 'NOT_ASSIGNED', 'Use external identity fixtures only');
assert(fixture.providerReadback === 'PASS', 'Provider account readback required');
assert(
  Array.isArray(fixture.accounts) && fixture.accounts.length > 1,
  'Independent actors required',
);
assert(
  new Set(fixture.accounts.map((account) => account.username)).size === fixture.accounts.length &&
    new Set(fixture.accounts.map((account) => account.externalSubject)).size ===
      fixture.accounts.length,
  'Distinct account names and external subjects required',
);
const issuer = new URL(fixture.issuer);
assert(
  issuer.protocol === 'https:' &&
    !issuer.username &&
    !issuer.password &&
    !issuer.search &&
    !issuer.hash,
  'Secured installed issuer required',
);
const redirectUri = 'http://localhost:8080/api/v1/ui/oidc-session/callback';
const proofAdapter = createHttpOidcIdentityProofAdapter();
const membershipAdapter = createHttpOidcTrustAdapter({
  verifyWebAuthnAssertion: async () => undefined,
});

const authorize = (account, nativeAuthorization) =>
  authorizeSecuredOidcAccount(fixture, account, nativeAuthorization);

for (const account of fixture.accounts) {
  const input = await authorize(account);
  const proof = await proofAdapter.exchangeIdentityProof(input);
  assert(proof && proof.subject === account.externalSubject, 'Signed subject not verified');
  assert(proof.issuer === fixture.issuer && proof.audience === fixture.clientId);
  assert(proof.proofEvidence, 'Cryptographic proof evidence missing');
  assert(
    !('principalId' in proof) && !('participantId' in proof),
    'Identity proof granted membership',
  );
  assert((await proofAdapter.exchangeIdentityProof(input)) === undefined, 'Code replay accepted');
  const unbound = await authorize(account);
  assert(
    (await membershipAdapter.exchangeAuthorizationCode(unbound)) === undefined,
    'Token without required membership hints accepted',
  );
}
const selected = fixture.accounts[0];
const wrongNonce = await authorize(selected);
assert(
  (await proofAdapter.exchangeIdentityProof({
    ...wrongNonce,
    expectedNonceDigest: `sha256:${'0'.repeat(64)}`,
  })) === undefined,
  'Nonce substitution accepted',
);
const wrongVerifier = await authorize(selected);
assert(
  (await proofAdapter.exchangeIdentityProof({
    ...wrongVerifier,
    codeVerifier: randomBytes(48).toString('base64url'),
  })) === undefined,
  'PKCE verifier substitution accepted',
);
process.stdout.write(
  `SECURED_OIDC_PROVIDER|PASS|actors=${fixture.accounts.length}|distinct-account-names-and-subjects|real-HTTPS-Code-PKCE-S256-RS256-JWKS|exact-issuer-state-subject-audience-nonce|replay-and-substitution-denied|membership-hints-path-rejected|native-callback-and-durable-membership-NOT_TESTED\n`,
);

// This optional mode is admitted only by the isolated native runtime owner.
// External role labels and identity proofs remain insufficient for membership.
if (process.argv[3]) {
  const identity = new URL(process.argv[3]);
  assert(
    identity.href === 'http://tegaris-native-oidc-denial:3001/',
    'Use the finite private native callback fixture only',
  );
  const participantId = '018f0000-0000-7000-8000-000000000101';
  async function nativeRequest(path, options) {
    return fetch(new URL(path, identity), {
      ...options,
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
  }
  for (const account of fixture.accounts) {
    const begin = await nativeRequest('/api/v1/session/oidc/authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ participantId }),
    });
    assert(begin.status === 200, 'Native authorization did not begin');
    const nativeAuthorization = await begin.json();
    assert(nativeAuthorization.issuer === fixture.issuer);
    assert(nativeAuthorization.clientId === fixture.clientId);
    assert(nativeAuthorization.redirectUri === redirectUri);
    assert(typeof nativeAuthorization.transactionId === 'string');
    assert(/^[A-Za-z0-9_-]{43,128}$/u.test(nativeAuthorization.codeChallenge));
    assert(typeof nativeAuthorization.state === 'string' && nativeAuthorization.state.length >= 32);
    assert(typeof nativeAuthorization.nonce === 'string' && nativeAuthorization.nonce.length >= 32);
    const custody = begin.headers
      .getSetCookie()
      .map((cookie) => cookie.split(';', 1)[0])
      .find((cookie) => /^__Host-openpc_oidc=[A-Za-z0-9._-]+$/u.test(cookie));
    assert(custody, 'Native browser custody cookie missing');
    const body = await authorize(account, nativeAuthorization);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const callback = await nativeRequest('/api/v1/session/oidc/callback', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cookie': custody },
        body: JSON.stringify(body),
      });
      assert(callback.status === 401, 'Unbound external account gained a native session');
      assert((await callback.json()).error?.code === 'PC-AUTH-0002');
      assert(
        !callback.headers
          .getSetCookie()
          .some((cookie) => cookie.startsWith('__Host-openpc_session=')),
        'Denied callback issued a native session cookie',
      );
    }
    const readback = await nativeRequest('/api/v1/session', {
      headers: { cookie: custody },
    });
    assert(readback.status === 401, 'Denied account obtained authenticated session readback');
  }
  process.stdout.write(
    `SECURED_OIDC_NATIVE_CALLBACK|PASS|actors=${fixture.accounts.length}|actual-public-begin-and-selected-Participant-callback|unbound-accounts-and-replay-denied|no-session-cookie|authenticated-readback-denied|rejection-stage-UNCONFIRMED|positive-onboarding-NOT_TESTED\n`,
  );
}
