import type { MutationAuthorization } from './control-mutation-authorization.js';

/** These catalogue actions require the actor's fresh WebAuthn, without approval.
 * Other action families remain closed until their own admission is implemented. */
export const stepUpOnlyConfigurationOperations: readonly string[] = Object.freeze([
  'CFG-OP-CREATE-NOTIFICATION-ENDPOINT',
  'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
]);

/** The ordinary verifier authenticates this unchanged signed runtime assertion.
 * Callers must independently validate and consume the accompanying step-up. */
export function stepUpRuntimeAssertion(
  proof: Extract<MutationAuthorization, { evidenceKind: 'IDENTITY_RUNTIME_STEP_UP' }>,
): Extract<MutationAuthorization, { evidenceKind: 'IDENTITY_RUNTIME' }> {
  return {
    evidenceKind: 'IDENTITY_RUNTIME',
    sessionId: proof.sessionId,
    sessionEpoch: proof.sessionEpoch,
    participantId: proof.participantId,
    privacyDomainId: proof.privacyDomainId,
    principalId: proof.principalId,
    principalEpoch: proof.principalEpoch,
    participantEpoch: proof.participantEpoch,
    authorityEnvelopeId: proof.authorityEnvelopeId,
    authorityEpoch: proof.authorityEpoch,
    delegationEpoch: proof.delegationEpoch,
    assignmentId: proof.assignmentId,
    assignmentEpoch: proof.assignmentEpoch,
    signerKeyDigest: proof.signerKeyDigest,
    evidenceCbor: proof.evidenceCbor,
    evidenceDigest: proof.evidenceDigest,
    coseSign1: proof.coseSign1,
  };
}
