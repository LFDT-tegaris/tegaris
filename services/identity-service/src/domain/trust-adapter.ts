import { createHash } from 'node:crypto';

/**
 * Boundary between unauthenticated HTTP input and cryptographically verified
 * identity evidence.  The service deliberately has no permissive default:
 * deployment wiring must provide an adapter backed by the configured OIDC
 * issuer and WebAuthn credential store.
 */
/** Verified provider identity. Participant authority is resolved by the durable membership owner. */
export interface VerifiedOidcIdentity {
  readonly nonce: string;
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly authorizedParty: string;
  readonly issuedAt: Date;
  readonly authenticatedAt?: Date;
  readonly expiresAt: Date;
  readonly proofEvidence?: {
    readonly idTokenDigest: string;
    readonly signingKeyDigest: string;
    readonly claimsDigest: string;
    readonly verifiedAt: Date;
  };
}

/** Existing login compatibility hints; neither hint establishes a membership or grants authority. */
export interface VerifiedOidcClaims extends VerifiedOidcIdentity {
  readonly principalId: string;
  readonly participantId: string;
}

export interface OidcCodeExchange {
  readonly authorizationCode: string;
  readonly codeVerifier: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
}

export interface OidcIdentityProofAdapter {
  /** expectedNonceDigest comes from the exact unconsumed, browser-bound server transaction. */
  exchangeIdentityProof(
    input: OidcCodeExchange & { readonly expectedNonceDigest: string },
  ): Promise<VerifiedOidcIdentity | undefined>;
}

const verifiedWebAuthnAssertionBrand: unique symbol = Symbol('verifiedWebAuthnAssertion');
const sha256Text = /^sha256:[0-9a-f]{64}$/u;
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const actionIntent = /^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u;
const uint64Text = /^(0|[1-9][0-9]*)$/u;

export interface VerifiedWebAuthnAssertion {
  readonly [verifiedWebAuthnAssertionBrand]: true;
  readonly version: 'OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1';
  readonly credentialId: string;
  readonly credentialPublicKeyDigest: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly actionIntentId: string;
  readonly resourceDigest: string;
  readonly challengeDigest: string;
  readonly rpIdHash: string;
  readonly origin: string;
  readonly authenticatorDataDigest: string;
  readonly clientDataJsonDigest: string;
  readonly signatureDigest: string;
  readonly signCount: string;
  readonly verifiedAt: string;
  readonly userVerification: 'REQUIRED_VERIFIED';
}

export type VerifiedWebAuthnAssertionInput = Omit<
  VerifiedWebAuthnAssertion,
  typeof verifiedWebAuthnAssertionBrand | 'version' | 'userVerification'
>;

export function createVerifiedWebAuthnAssertion(
  input: VerifiedWebAuthnAssertionInput,
): VerifiedWebAuthnAssertion {
  let normalizedOrigin: string;
  try {
    normalizedOrigin = new URL(input.origin).origin;
  } catch {
    throw new Error('invalid verified WebAuthn origin');
  }
  if (
    !uuidV7.test(input.credentialId) ||
    !sha256Text.test(input.credentialPublicKeyDigest) ||
    !uuidV7.test(input.principalId) ||
    !uuidV7.test(input.sessionId) ||
    !actionIntent.test(input.actionIntentId) ||
    !sha256Text.test(input.resourceDigest) ||
    !sha256Text.test(input.challengeDigest) ||
    !sha256Text.test(input.rpIdHash) ||
    !sha256Text.test(input.authenticatorDataDigest) ||
    !sha256Text.test(input.clientDataJsonDigest) ||
    !sha256Text.test(input.signatureDigest) ||
    !uint64Text.test(input.signCount) ||
    BigInt(input.signCount) > 18_446_744_073_709_551_615n ||
    Number.isNaN(Date.parse(input.verifiedAt)) ||
    normalizedOrigin !== input.origin
  ) {
    throw new Error('invalid verified WebAuthn assertion binding');
  }
  return Object.freeze({
    ...input,
    version: 'OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1',
    userVerification: 'REQUIRED_VERIFIED',
    [verifiedWebAuthnAssertionBrand]: true as const,
  });
}

export function verifiedWebAuthnAssertionDigest(assertion: VerifiedWebAuthnAssertion): Buffer {
  if (
    assertion[verifiedWebAuthnAssertionBrand] !== true ||
    !Object.isFrozen(assertion) ||
    assertion.version !== 'OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1' ||
    assertion.userVerification !== 'REQUIRED_VERIFIED'
  ) {
    throw new Error('untrusted WebAuthn assertion binding');
  }
  return createHash('sha256')
    .update(
      [
        assertion.version,
        assertion.credentialId,
        assertion.credentialPublicKeyDigest,
        assertion.principalId,
        assertion.sessionId,
        assertion.actionIntentId,
        assertion.resourceDigest,
        assertion.challengeDigest,
        assertion.rpIdHash,
        assertion.origin,
        assertion.authenticatorDataDigest,
        assertion.clientDataJsonDigest,
        assertion.signatureDigest,
        assertion.signCount,
        assertion.verifiedAt,
        assertion.userVerification,
      ].join('\u0000'),
    )
    .digest();
}

export interface IdentityTrustAdapter {
  readonly exchangeIdentityProof?: OidcIdentityProofAdapter['exchangeIdentityProof'];
  exchangeAuthorizationCode(input: OidcCodeExchange): Promise<VerifiedOidcClaims | undefined>;
  verifyWebAuthnAssertion(input: {
    readonly participantId?: string;
    readonly assertion: string;
    readonly challenge: string;
    readonly rpIdHash: string;
    readonly principalId: string;
    readonly sessionId: string;
    readonly actionIntentId: string;
    readonly resourceDigest: string;
    readonly allowedOrigin: string;
  }): Promise<VerifiedWebAuthnAssertion | undefined>;
}

/** Rejects all unverified identity evidence. Safe only production default. */
export const rejectingIdentityTrustAdapter: IdentityTrustAdapter = {
  async exchangeAuthorizationCode() {
    return undefined;
  },
  async verifyWebAuthnAssertion() {
    return undefined;
  },
};
