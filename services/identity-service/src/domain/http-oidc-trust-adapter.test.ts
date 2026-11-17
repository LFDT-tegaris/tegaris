import { createHash, generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';

import { exportJWK, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  createHttpOidcTrustAdapter,
  createHttpOidcIdentityProofAdapter,
} from './http-oidc-trust-adapter.js';

const principalId = '018f0000-0000-7000-8000-000000000111';
const participantId = '018f0000-0000-7000-8000-000000000101';
const clientId = 'openpc-local-workbench';
const redirectUri = 'http://127.0.0.1:8080/api/v1/session/oidc/callback';
const nonce = 'oidc-nonce-00000000000000000000000000000001';
let subject: string | undefined = 'exact-external-account';
let authenticatedAt: number | undefined;
let includeMembershipHints = true;
let tokenIssuer: string | undefined;
let tokenAudience: string | undefined;
let tokenAuthorizedParty: string | undefined;
let issuedAtOffset = 0;
const codeVerifier = 'oidc-code-verifier-000000000000000000000000000001';
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...(await exportJWK(keys.publicKey)), kid: 'local-test-key', alg: 'RS256' };
let issuer: string;
let requestedDiscoveryPath: string | undefined;
let discoveryRedirect = false;
let tokenRedirect = false;
let redirectReceiverRequests = 0;

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', issuer);
  const send = (status: number, body: object) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(JSON.stringify(body));
  };
  if (request.method === 'GET' && url.pathname.includes('openid-configuration')) {
    requestedDiscoveryPath = request.url;
    if (request.url !== '/.well-known/openid-configuration') return send(404, {});
    if (discoveryRedirect) {
      response.writeHead(307, { location: `${issuer}/redirect-receiver` });
      return response.end();
    }
    return send(200, {
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
    return send(200, { keys: [publicJwk] });
  }
  if (request.method === 'POST' && url.pathname === '/token') {
    if (tokenRedirect) {
      response.writeHead(307, { location: `${issuer}/redirect-receiver` });
      return response.end();
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    const form = new URLSearchParams(body);
    if (
      form.get('grant_type') !== 'authorization_code' ||
      form.get('code') !== 'authorization-code-long-enough' ||
      form.get('client_id') !== clientId ||
      form.get('redirect_uri') !== redirectUri ||
      form.get('code_verifier') !== codeVerifier
    ) {
      return send(400, { error: 'invalid_grant' });
    }
    const now = Math.floor(Date.now() / 1_000);
    const idToken = await new SignJWT({
      sub: subject,
      azp: tokenAuthorizedParty ?? clientId,
      nonce,
      ...(authenticatedAt === undefined ? {} : { auth_time: authenticatedAt }),
      ...(includeMembershipHints
        ? { openpc_principal_id: principalId, openpc_participant_id: participantId }
        : {}),
    })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid })
      .setIssuer(tokenIssuer ?? issuer)
      .setAudience(tokenAudience ?? clientId)
      .setIssuedAt(now + issuedAtOffset)
      .setExpirationTime(now + 300)
      .sign(keys.privateKey);
    return send(200, { token_type: 'Bearer', id_token: idToken });
  }
  if (url.pathname === '/redirect-receiver') {
    redirectReceiverRequests++;
    return send(200, {});
  }
  return send(404, {});
});

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('missing OIDC test address');
  issuer = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error === undefined ? resolve() : reject(error))),
  );
});

describe('HTTP OIDC trust boundary', () => {
  it.each(['token_endpoint', 'jwks_uri'] as const)(
    'rejects an HTTPS issuer advertising an HTTP %s before code exchange',
    async (endpoint) => {
      const securedIssuer = 'https://idp.example/realms/tegaris';
      const discovery = {
        issuer: securedIssuer,
        token_endpoint: `${securedIssuer}/token`,
        jwks_uri: `${securedIssuer}/jwks`,
        [endpoint]: `${issuer}/${endpoint}`,
      };
      const provider = vi.spyOn(globalThis, 'fetch');
      provider.mockResolvedValue(
        new Response(JSON.stringify(discovery), {
          headers: { 'content-type': 'application/json' },
        }),
      );
      try {
        const adapter = createHttpOidcIdentityProofAdapter({ allowInsecureHttp: true });
        expect(
          await adapter.exchangeIdentityProof({
            authorizationCode: 'authorization-code-long-enough',
            codeVerifier,
            issuer: securedIssuer,
            clientId,
            redirectUri,
            expectedNonceDigest: `sha256:${createHash('sha256').update(nonce).digest('hex')}`,
          }),
        ).toBeUndefined();
        expect(provider).toHaveBeenCalledTimes(1);
        expect(provider.mock.calls[0]?.[0]?.toString()).toBe(
          `${securedIssuer}/.well-known/openid-configuration`,
        );
        expect(provider.mock.calls[0]?.[1]).toMatchObject({ redirect: 'error' });
      } finally {
        provider.mockRestore();
      }
    },
  );

  it.each(['discovery', 'token'] as const)(
    'does not forward identity traffic through a %s redirect',
    async (endpoint) => {
      discoveryRedirect = endpoint === 'discovery';
      tokenRedirect = endpoint === 'token';
      redirectReceiverRequests = 0;
      try {
        const adapter = createHttpOidcIdentityProofAdapter({ allowInsecureHttp: true });
        expect(
          await adapter.exchangeIdentityProof({
            authorizationCode: 'authorization-code-long-enough',
            codeVerifier,
            issuer,
            clientId,
            redirectUri,
            expectedNonceDigest: `sha256:${createHash('sha256').update(nonce).digest('hex')}`,
          }),
        ).toBeUndefined();
        expect(redirectReceiverRequests).toBe(0);
      } finally {
        discoveryRedirect = false;
        tokenRedirect = false;
      }
    },
  );

  it('verifies an exact transaction nonce without trusting provider membership hints', async () => {
    const adapter = createHttpOidcIdentityProofAdapter({ allowInsecureHttp: true });
    const input = {
      authorizationCode: 'authorization-code-long-enough',
      codeVerifier,
      issuer,
      clientId,
      redirectUri,
      expectedNonceDigest: `sha256:${createHash('sha256').update(nonce).digest('hex')}`,
    };
    try {
      includeMembershipHints = false;
      const proof = await adapter.exchangeIdentityProof(input);
      expect(proof).toMatchObject({ issuer, subject: 'exact-external-account', nonce });
      expect(proof).not.toHaveProperty('principalId');
      expect(proof).not.toHaveProperty('participantId');
      const login = createHttpOidcTrustAdapter(
        { verifyWebAuthnAssertion: async () => undefined },
        { allowInsecureHttp: true },
      );
      expect(await login.exchangeAuthorizationCode(input)).toBeUndefined();
      includeMembershipHints = true;
      const withHints = await adapter.exchangeIdentityProof(input);
      expect(withHints).not.toHaveProperty('principalId');
      expect(withHints).not.toHaveProperty('participantId');
      expect(
        await adapter.exchangeIdentityProof({
          ...input,
          expectedNonceDigest: `sha256:${'a'.repeat(64)}`,
        }),
      ).toBeUndefined();
      expect(
        await adapter.exchangeIdentityProof({ ...input, codeVerifier: 'wrong-verifier' }),
      ).toBeUndefined();
      expect(
        await adapter.exchangeIdentityProof({ ...input, redirectUri: `${redirectUri}/other` }),
      ).toBeUndefined();
    } finally {
      includeMembershipHints = true;
    }
  });

  it('rejects provider proofs for another issuer, audience, authorized party or future issuance', async () => {
    const adapter = createHttpOidcIdentityProofAdapter({ allowInsecureHttp: true });
    const input = {
      authorizationCode: 'authorization-code-long-enough',
      codeVerifier,
      issuer,
      clientId,
      redirectUri,
      expectedNonceDigest: `sha256:${createHash('sha256').update(nonce).digest('hex')}`,
    };
    try {
      tokenIssuer = `${issuer}/other`;
      expect(await adapter.exchangeIdentityProof(input)).toBeUndefined();
      tokenIssuer = undefined;
      tokenAudience = 'another-client';
      expect(await adapter.exchangeIdentityProof(input)).toBeUndefined();
      tokenAudience = undefined;
      tokenAuthorizedParty = 'another-party';
      expect(await adapter.exchangeIdentityProof(input)).toBeUndefined();
      tokenAuthorizedParty = undefined;
      issuedAtOffset = 60;
      expect(await adapter.exchangeIdentityProof(input)).toBeUndefined();
    } finally {
      tokenIssuer = undefined;
      tokenAudience = undefined;
      tokenAuthorizedParty = undefined;
      issuedAtOffset = 0;
    }
  });

  it('discovers a root issuer and verifies its signed authorization-code result', async () => {
    const adapter = createHttpOidcTrustAdapter(
      { verifyWebAuthnAssertion: async () => undefined },
      { allowInsecureHttp: true },
    );
    const claims = await adapter.exchangeAuthorizationCode({
      authorizationCode: 'authorization-code-long-enough',
      codeVerifier,
      issuer,
      clientId,
      redirectUri,
    });

    expect(requestedDiscoveryPath).toBe('/.well-known/openid-configuration');
    expect(claims).toMatchObject({
      issuer,
      audience: clientId,
      authorizedParty: clientId,
      nonce,
      subject: 'exact-external-account',
      principalId,
      participantId,
    });
  });

  it('preserves a signed authentication time and rejects a future or malformed value', async () => {
    const adapter = createHttpOidcTrustAdapter(
      { verifyWebAuthnAssertion: async () => undefined },
      { allowInsecureHttp: true },
    );
    const input = {
      authorizationCode: 'authorization-code-long-enough',
      codeVerifier,
      issuer,
      clientId,
      redirectUri,
    };
    try {
      authenticatedAt = Math.floor(Date.now() / 1000) - 2;
      expect(await adapter.exchangeAuthorizationCode(input)).toMatchObject({
        authenticatedAt: new Date(authenticatedAt * 1000),
      });
      for (const invalid of [-1, 1.5, Math.floor(Date.now() / 1000) + 60]) {
        authenticatedAt = invalid;
        expect(await adapter.exchangeAuthorizationCode(input)).toBeUndefined();
      }
    } finally {
      authenticatedAt = undefined;
    }
  });

  it.each([undefined, '', 'x'.repeat(256)])(
    'rejects a missing or invalid subject (%s)',
    async (invalid) => {
      subject = invalid;
      try {
        const adapter = createHttpOidcTrustAdapter(
          { verifyWebAuthnAssertion: async () => undefined },
          { allowInsecureHttp: true },
        );
        expect(
          await adapter.exchangeAuthorizationCode({
            authorizationCode: 'authorization-code-long-enough',
            codeVerifier,
            issuer,
            clientId,
            redirectUri,
          }),
        ).toBeUndefined();
      } finally {
        subject = 'exact-external-account';
      }
    },
  );
});
