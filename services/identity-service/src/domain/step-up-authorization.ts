import {
  type VerifiedWebAuthnAssertion,
  verifiedWebAuthnAssertionDigest,
} from './trust-adapter.js';

export interface StepUpAuthorizationCandidate {
  readonly sessionToken: string;
  readonly actionIntentId: string;
  readonly resourceDigest: string;
  readonly resourceId?: string;
  readonly challenge: string;
  readonly rpIdHash: string;
  readonly verifiedAssertionDigest: string;
}

export interface StepUpAuthorizationInput {
  readonly sessionToken: string;
  readonly actionIntentId: string;
  readonly resourceDigest: string;
  readonly resourceId?: string;
  readonly challenge: string;
  readonly rpIdHash: string;
  readonly verifiedAssertion: VerifiedWebAuthnAssertion;
}

/** Projects trusted WebAuthn evidence into canonical plain data. */
export function stepUpAuthorizationCandidate(
  input: StepUpAuthorizationInput,
): StepUpAuthorizationCandidate {
  return Object.freeze({
    sessionToken: input.sessionToken,
    actionIntentId: input.actionIntentId,
    resourceDigest: input.resourceDigest,
    ...(input.resourceId === undefined ? {} : { resourceId: input.resourceId }),
    challenge: input.challenge,
    rpIdHash: input.rpIdHash,
    verifiedAssertionDigest: `sha256:${verifiedWebAuthnAssertionDigest(
      input.verifiedAssertion,
    ).toString('hex')}`,
  });
}
