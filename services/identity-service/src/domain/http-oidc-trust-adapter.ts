import { localQaExecutionTimeoutMs } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { createRemoteJWKSet, jwtVerify, exportJWK, calculateJwkThumbprint } from 'jose';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { z } from 'zod';

import type {
  IdentityTrustAdapter,
  OidcCodeExchange,
  OidcIdentityProofAdapter,
  VerifiedOidcClaims,
  VerifiedOidcIdentity,
} from './trust-adapter.js';

const discoverySchema = z
  .object({
    issuer: z.url(),
    token_endpoint: z.url(),
    jwks_uri: z.url(),
  })
  .passthrough();

const tokenSchema = z
  .object({ id_token: z.string().min(1), token_type: z.literal('Bearer') })
  .passthrough();

const claimsSchema = z.object({
  sub: z.string().min(1).max(255),
  nonce: z.string().min(32).max(256),
  azp: z.string().min(1),
  iat: z.number().int().nonnegative(),
  auth_time: z.number().int().nonnegative().optional(),
  exp: z.number().int().positive(),
});

const membershipHintsSchema = z.object({
  openpc_principal_id: z.uuid(),
  openpc_participant_id: z.uuid(),
});

export interface HttpOidcTrustOptions {
  readonly allowInsecureHttp?: boolean;
}

function permitted(url: URL, allowInsecureHttp: boolean): boolean {
  return url.protocol === 'https:' || (allowInsecureHttp && url.protocol === 'http:');
}

/** Shared cryptographic boundary. It never infers an OpenPC principal from a provider label. */
async function exchangeCode(input: OidcCodeExchange, options: HttpOidcTrustOptions) {
  try {
    const issuer = new URL(input.issuer);
    if (!permitted(issuer, options.allowInsecureHttp === true)) return undefined;
    const allowInsecureEndpoints =
      issuer.protocol === 'http:' && options.allowInsecureHttp === true;
    const discoveryUrl = new URL(issuer);
    discoveryUrl.pathname = `${issuer.pathname.replace(/\/+$/u, '')}/.well-known/openid-configuration`;
    discoveryUrl.search = '';
    discoveryUrl.hash = '';
    const discoveryResponse = await fetch(discoveryUrl, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(localQaExecutionTimeoutMs(5_000)),
    });
    if (!discoveryResponse.ok) return undefined;
    const discovery = discoverySchema.parse(await discoveryResponse.json());
    const tokenEndpoint = new URL(discovery.token_endpoint);
    const jwksUri = new URL(discovery.jwks_uri);
    if (
      discovery.issuer !== input.issuer ||
      !permitted(tokenEndpoint, allowInsecureEndpoints) ||
      !permitted(jwksUri, allowInsecureEndpoints)
    ) {
      return undefined;
    }
    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'POST',
      redirect: 'error',
      headers: {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.authorizationCode,
        client_id: input.clientId,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
      }),
      signal: AbortSignal.timeout(localQaExecutionTimeoutMs(5_000)),
    });
    if (!tokenResponse.ok) return undefined;
    const token = tokenSchema.parse(await tokenResponse.json());
    const verified = await jwtVerify(token.id_token, createRemoteJWKSet(jwksUri), {
      issuer: input.issuer,
      audience: input.clientId,
      algorithms: ['RS256'],
      requiredClaims: ['sub', 'nonce', 'azp', 'iat', 'exp'],
    });
    const claims = claimsSchema.parse(verified.payload);
    if (
      claims.azp !== input.clientId ||
      claims.iat > Math.floor(Date.now() / 1000) ||
      claims.exp <= claims.iat ||
      (claims.auth_time !== undefined && claims.auth_time > claims.iat)
    )
      return undefined;
    const identity: VerifiedOidcIdentity = {
      nonce: claims.nonce,
      issuer: input.issuer,
      subject: claims.sub,
      audience: input.clientId,
      authorizedParty: claims.azp,
      issuedAt: new Date(claims.iat * 1_000),
      ...(claims.auth_time === undefined
        ? {}
        : { authenticatedAt: new Date(claims.auth_time * 1000) }),
      expiresAt: new Date(claims.exp * 1_000),
      proofEvidence: {
        idTokenDigest: `sha256:${createHash('sha256').update(token.id_token).digest('hex')}`,
        signingKeyDigest: `sha256:${Buffer.from(await calculateJwkThumbprint(await exportJWK(verified.key), 'sha256'), 'base64url').toString('hex')}`,
        claimsDigest: canonicalAuthorizationDigest(verified.payload),
        verifiedAt: new Date(),
      },
    };
    return { identity, payload: verified.payload };
  } catch {
    return undefined;
  }
}

/** Verify authorization-code results against issuer discovery and signed OIDC claims. */
export function createHttpOidcTrustAdapter(
  webAuthn: Pick<IdentityTrustAdapter, 'verifyWebAuthnAssertion'>,
  options: HttpOidcTrustOptions = {},
): IdentityTrustAdapter {
  return {
    verifyWebAuthnAssertion: (input) => webAuthn.verifyWebAuthnAssertion(input),
    exchangeIdentityProof: createHttpOidcIdentityProofAdapter(options).exchangeIdentityProof,
    async exchangeAuthorizationCode(input): Promise<VerifiedOidcClaims | undefined> {
      const verified = await exchangeCode(input, options);
      if (!verified) return undefined;
      const hints = membershipHintsSchema.safeParse(verified.payload);
      if (!hints.success) return undefined;
      return {
        ...verified.identity,
        principalId: hints.data.openpc_principal_id,
        participantId: hints.data.openpc_participant_id,
      };
    },
  };
}

/** Onboarding proof uses standard signed identity claims, with no pre-existing OpenPC membership. */
export function createHttpOidcIdentityProofAdapter(
  options: HttpOidcTrustOptions = {},
): OidcIdentityProofAdapter {
  return {
    async exchangeIdentityProof(input) {
      if (!/^sha256:[0-9a-f]{64}$/u.test(input.expectedNonceDigest)) return undefined;
      const verified = await exchangeCode(input, options);
      if (
        !verified ||
        `sha256:${createHash('sha256').update(verified.identity.nonce).digest('hex')}` !==
          input.expectedNonceDigest
      )
        return undefined;
      return verified.identity;
    },
  };
}
import { createHash } from 'node:crypto';
