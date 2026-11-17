import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import type { IdentityRuntimeVerifier } from './identity-runtime-crypto.js';

const digest = (purpose: string, value: unknown) =>
  canonicalAuthorizationDigestBytes({
    purpose: `pc.identity.invitation-proof.${purpose}.v1`,
    value,
  });

/** Factual proof inputs, never a session, assignment or recipient authorization. All secrets are commitments. */
export interface InvitationProofEvidence {
  readonly operationId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly membershipId: string;
  readonly participantEpoch: string;
  readonly invitationId: string;
  readonly tokenVersion: string;
  readonly tokenDigest: string;
  readonly issuanceAuthorityDigest: string;
  readonly recipientDigest: string;
  readonly oidcConfigurationDigest: string;
  readonly transactionId: string;
  readonly stateDigest: string;
  readonly nonceDigest: string;
  readonly codeVerifierDigest: string;
  readonly browserSessionDigest: string;
  readonly codeChallenge: string;
  readonly authorizationCodeDigest: string;
  readonly idTokenDigest: string;
  readonly signingKeyDigest: string;
  readonly claimsDigest: string;
  readonly resultDigest: string;
  readonly verifiedAt: Date;
  readonly validUntil: Date;
}

export function createInvitationProofAssertion(input: InvitationProofEvidence): Buffer {
  const issuedAt = input.verifiedAt.getTime();
  const expiresAt = Math.min(issuedAt + 60_000, input.validUntil.getTime());
  if (
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    issuedAt < 0 ||
    expiresAt <= issuedAt
  )
    throw new Error('invalid invitation proof time');
  return encodeIdentityAuthContextAssertionPayload({
    assertionId: input.operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(input.participantId, input.membershipId),
    participantContextDigest: digest('context', [input.participantId, input.participantEpoch]),
    audienceDigest: digest('redemption', [
      input.operationId,
      input.invitationId,
      input.tokenVersion,
      input.tokenDigest,
      input.participantId,
      input.privacyDomainId,
      input.recipientDigest,
      input.issuanceAuthorityDigest,
      input.resultDigest,
    ]),
    senderBindingKind: 1,
    senderCredentialBindingDigest: digest('browser-custody', [
      input.transactionId,
      input.stateDigest,
      input.nonceDigest,
      input.codeVerifierDigest,
      input.codeChallenge,
      input.browserSessionDigest,
    ]),
    assuranceProfileDigest: digest('assurance', [
      'verified-oidc-code-pkce-s256',
      'exact-recipient',
      'consumed-invitation-proof',
      'no-participant-authority',
      input.oidcConfigurationDigest,
    ]),
    authorityVectorDigest: digest('provenance', [
      input.invitationId,
      input.tokenVersion,
      input.tokenDigest,
      input.issuanceAuthorityDigest,
      input.participantEpoch,
      input.oidcConfigurationDigest,
    ]),
    authenticationEvidenceDigest: digest('verified-identity', [
      input.transactionId,
      input.idTokenDigest,
      input.signingKeyDigest,
      input.claimsDigest,
      input.nonceDigest,
      input.authorizationCodeDigest,
    ]),
    issuedAtNs: BigInt(issuedAt) * 1_000_000n,
    expiresAtNs: BigInt(expiresAt) * 1_000_000n,
  });
}

/** Separate proof consumer; never route these records through mutation authorization. */
export async function verifyInvitationProofAssertion(
  input: InvitationProofEvidence,
  evidenceCbor: Buffer,
  coseSign1: Buffer,
  verifier: IdentityRuntimeVerifier,
): Promise<boolean> {
  try {
    return (
      evidenceCbor.equals(createInvitationProofAssertion(input)) &&
      (await verifier.verifyCanonicalAssertion(evidenceCbor, coseSign1)) !== undefined
    );
  } catch {
    return false;
  }
}
