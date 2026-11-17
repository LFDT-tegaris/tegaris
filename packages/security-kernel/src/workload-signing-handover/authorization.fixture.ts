import type { HandoverAdmissionAuthorization } from './generated.js';

/** Synthetic format-only fixture. No authority or durable admission is provisioned. */
export function handoverAdmissionAuthorizationFixture(): HandoverAdmissionAuthorization {
  const id = (n: number) => '01a10000-0000-7000-8000-' + n.toString().padStart(12, '0');
  const hash = (n: number) => 'sha256:' + n.toString(16).padStart(64, '0');
  return {
    statementType: 'ADMISSION_AUTHORIZATION',
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'synthetic-admission',
    workloadPrincipalId: id(3),
    workloadId: 'synthetic-api',
    handoverId: id(4),
    operationId: id(5),
    mutationCandidateId: id(6),
    candidateDigest: hash(1),
    actionIntentDigest: hash(2),
    generationId: id(7),
    generationDigest: hash(3),
    sourceDigest: hash(4),
    predecessorCredentialId: id(8),
    predecessorCredentialEpoch: '4',
    successorCredentialId: id(9),
    successorCredentialEpoch: '5',
    nativeReplacementProvenanceDigest: hash(5),
    makerPrincipalId: id(10),
    checkerPrincipalId: id(11),
    makerAuthorityDigest: hash(6),
    checkerAuthorityDigest: hash(7),
    makerStepUpProofDigest: hash(8),
    checkerStepUpProofDigest: hash(9),
    approvalRequestId: id(12),
    approvalDecisionId: id(13),
    approvalDecisionDigest: hash(10),
    admittedAtNs: '1793772000000000000',
    authorizationExpiresAtNs: '1793772060000000000',
    successorTrustSetDigest: hash(11),
    selectorTransitionDigest: hash(12),
    catalogOperationId: 'ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT',
    actionIntentId: 'ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1',
    expectedRevision: '1',
  };
}
