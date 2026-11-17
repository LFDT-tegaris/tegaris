import { createHash } from 'node:crypto';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryIntent,
} from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeRecoveryEvidencePayload } from './identity-envelope-recovery-evidence.js';
import type { IdentityRuntimeVerifier } from './identity-runtime-crypto.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

/** Original activation evidence only. The caller authenticates native installed
 * custody and original consumed proof/challenge records separately. This helper
 * verifies their signed lease commitment; it does not independently read proofs,
 * authorize an actor, establish current authority or extend any validity window.
 */
export async function authenticateHistoricalIdentityEnvelopeRecoveryLease(
  input: {
    enrollment: IdentityEnvelopeRecoveryEnrollment;
    intent: IdentityEnvelopeRecoveryIntent;
    bindings: unknown;
    activationOperationId: string | null;
    activatedAt: Date | null;
    evidenceCbor: Buffer | null;
    evidenceDigest: Buffer | null;
    coseSign1: Buffer | null;
  },
  verifier: IdentityRuntimeVerifier | undefined,
) {
  try {
    const enrollment = identityEnvelopeRecoveryEnrollment.parse(input.enrollment);
    const intent = identityEnvelopeRecoveryIntent.parse(input.intent);
    const lease = identityEnvelopeRecoveryLease.parse(input.bindings);
    if (
      !verifier ||
      !input.activatedAt ||
      !Buffer.isBuffer(input.evidenceCbor) ||
      !Buffer.isBuffer(input.evidenceDigest) ||
      input.evidenceDigest.length !== 32 ||
      !Buffer.isBuffer(input.coseSign1) ||
      input.activationOperationId !== lease.activationOperationId ||
      input.activatedAt.toISOString() !== lease.validFrom ||
      intent.enrollmentId !== enrollment.enrollmentId ||
      intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
      intent.sourceParticipantEpoch !== enrollment.issuerParticipantEpoch ||
      intent.sourceIssuerPrincipalEpoch !== enrollment.issuerPrincipalEpoch ||
      intent.sourceIssuerCredentialEpoch !== enrollment.issuerCredentialEpoch ||
      lease.recoveryId !== intent.recoveryId ||
      lease.rotationId !== intent.rotationId ||
      lease.creationOperationId !== intent.creationOperationId ||
      lease.enrollmentId !== enrollment.enrollmentId ||
      lease.enrollmentDigest !== intent.enrollmentDigest ||
      lease.intentDigest !== canonicalAuthorizationDigest(intent) ||
      lease.executorPrincipalId !== enrollment.recoveryPrincipal.principalId ||
      lease.oldTrustDigest !== intent.oldTrustDigest ||
      lease.oldTrustDigest !== enrollment.oldTrustDigest ||
      lease.selectionAdmissionVersion !== intent.selectionAdmissionVersion ||
      lease.selectionAdmissionVersion !== enrollment.selectionAdmissionVersion ||
      Date.parse(lease.validFrom) < Date.parse(intent.validFrom) ||
      Date.parse(lease.validFrom) < Date.parse(enrollment.validFrom) ||
      Date.parse(lease.validUntil) > Date.parse(intent.validUntil) ||
      Date.parse(lease.validUntil) > Date.parse(enrollment.validUntil) ||
      canonicalAuthorizationDigest(lease.lifetimes ?? null) !==
        canonicalAuthorizationDigest(intent.lifetimes ?? null) ||
      lease.issuer.participantId !== enrollment.participantId ||
      lease.issuer.privacyDomainId !== enrollment.privacyDomainId ||
      lease.issuer.workloadCredentialId !== enrollment.request.workloadCredentialId ||
      lease.issuer.workloadPublicKeyDigest !== enrollment.issuerCredentialPublicKeyDigest ||
      lease.issuer.workloadPrincipalId !== enrollment.issuerPrincipalId ||
      lease.issuer.workloadPrincipalEpoch !==
        (BigInt(intent.sourceIssuerPrincipalEpoch) + 1n).toString() ||
      lease.issuer.workloadParticipantEpoch !== intent.sourceParticipantEpoch ||
      lease.issuer.workloadCredentialEpoch !== intent.sourceIssuerCredentialEpoch ||
      BigInt(lease.issuer.credentialValidFromNs) > BigInt(Date.parse(lease.validFrom)) * 1000000n ||
      (lease.issuer.credentialValidUntilNs !== null &&
        BigInt(lease.issuer.credentialValidUntilNs) <
          BigInt(Date.parse(lease.validUntil)) * 1000000n) ||
      !input.evidenceDigest.equals(createHash('sha256').update(input.evidenceCbor).digest()) ||
      !input.evidenceCbor.equals(
        identityEnvelopeRecoveryEvidencePayload({
          enrollment,
          operationId: lease.activationOperationId,
          actorPrincipalId: lease.executorPrincipalId,
          purpose: 'activation',
          value: lease,
          authenticationDigest: lease.proofEvidenceDigest,
          issuedAt: lease.validFrom,
          expiresAt: lease.validUntil,
        }),
      ) ||
      !(await verifier.verifyCanonicalAssertion(input.evidenceCbor, input.coseSign1))
    )
      throw new PlatformRecoveryError();
    Object.freeze(lease.issuer);
    Object.freeze(lease.proofIds);
    if (lease.lifetimes) Object.freeze(lease.lifetimes);
    return Object.freeze(lease);
  } catch {
    throw new PlatformRecoveryError();
  }
}
