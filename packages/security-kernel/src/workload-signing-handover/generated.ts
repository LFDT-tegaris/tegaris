// Generated from schemas/canonical/workload-signing-handover-admission-authorization-v1.json. Do not edit.
export const handoverAdmissionAuthorizationContext = {
  schemaId: 24042,
  schemaVersion: 1,
  purpose: 'pc.cose.identity.workload-signing-handover-admission-authorization.v1',
  purposeCode: 379,
  definitionDigest: 'sha256:1ef43404e0afa8ee6c9c688c7fac4a26411cfc139dd1b82bdb7061dc9fb5503a',
  contentType: 'application/pc+cbor',
  externalAadHex: '7063706c616e653a636f73652d7369676e313a763200',
  signatureProfileVersion: 2,
  fields: [
    {
      key: 1,
      name: 'statementType',
      type: 'literal',
      value: 'ADMISSION_AUTHORIZATION',
    },
    {
      key: 2,
      name: 'participantId',
      type: 'uuid',
    },
    {
      key: 3,
      name: 'privacyDomainId',
      type: 'uuid',
    },
    {
      key: 4,
      name: 'environmentId',
      type: 'id',
    },
    {
      key: 5,
      name: 'workloadPrincipalId',
      type: 'uuid',
    },
    {
      key: 6,
      name: 'workloadId',
      type: 'id',
    },
    {
      key: 7,
      name: 'handoverId',
      type: 'uuid',
    },
    {
      key: 8,
      name: 'operationId',
      type: 'uuid',
    },
    {
      key: 9,
      name: 'mutationCandidateId',
      type: 'uuid',
    },
    {
      key: 10,
      name: 'candidateDigest',
      type: 'H32',
    },
    {
      key: 11,
      name: 'actionIntentDigest',
      type: 'H32',
    },
    {
      key: 12,
      name: 'generationId',
      type: 'uuid',
    },
    {
      key: 13,
      name: 'generationDigest',
      type: 'H32',
    },
    {
      key: 14,
      name: 'sourceDigest',
      type: 'H32',
    },
    {
      key: 15,
      name: 'predecessorCredentialId',
      type: 'uuid',
    },
    {
      key: 16,
      name: 'predecessorCredentialEpoch',
      type: 'u64p',
    },
    {
      key: 17,
      name: 'successorCredentialId',
      type: 'uuid',
    },
    {
      key: 18,
      name: 'successorCredentialEpoch',
      type: 'u64p',
    },
    {
      key: 19,
      name: 'nativeReplacementProvenanceDigest',
      type: 'H32',
    },
    {
      key: 20,
      name: 'makerPrincipalId',
      type: 'uuid',
    },
    {
      key: 21,
      name: 'checkerPrincipalId',
      type: 'uuid',
    },
    {
      key: 22,
      name: 'makerAuthorityDigest',
      type: 'H32',
    },
    {
      key: 23,
      name: 'checkerAuthorityDigest',
      type: 'H32',
    },
    {
      key: 24,
      name: 'makerStepUpProofDigest',
      type: 'H32',
    },
    {
      key: 25,
      name: 'checkerStepUpProofDigest',
      type: 'H32',
    },
    {
      key: 26,
      name: 'approvalRequestId',
      type: 'uuid',
    },
    {
      key: 27,
      name: 'approvalDecisionId',
      type: 'uuid',
    },
    {
      key: 28,
      name: 'approvalDecisionDigest',
      type: 'H32',
    },
    {
      key: 29,
      name: 'admittedAtNs',
      type: 'nanos',
    },
    {
      key: 30,
      name: 'authorizationExpiresAtNs',
      type: 'nanos',
    },
    {
      key: 31,
      name: 'successorTrustSetDigest',
      type: 'H32',
    },
    {
      key: 32,
      name: 'selectorTransitionDigest',
      type: 'H32',
    },
    {
      key: 33,
      name: 'catalogOperationId',
      type: 'literal',
      value: 'ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT',
    },
    {
      key: 34,
      name: 'actionIntentId',
      type: 'literal',
      value: 'ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1',
    },
    {
      key: 35,
      name: 'expectedRevision',
      type: 'literal',
      value: '1',
    },
  ],
} as const;
export interface HandoverAdmissionAuthorization {
  readonly statementType: 'ADMISSION_AUTHORIZATION';
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly workloadPrincipalId: string;
  readonly workloadId: string;
  readonly handoverId: string;
  readonly operationId: string;
  readonly mutationCandidateId: string;
  readonly candidateDigest: string;
  readonly actionIntentDigest: string;
  readonly generationId: string;
  readonly generationDigest: string;
  readonly sourceDigest: string;
  readonly predecessorCredentialId: string;
  readonly predecessorCredentialEpoch: string;
  readonly successorCredentialId: string;
  readonly successorCredentialEpoch: string;
  readonly nativeReplacementProvenanceDigest: string;
  readonly makerPrincipalId: string;
  readonly checkerPrincipalId: string;
  readonly makerAuthorityDigest: string;
  readonly checkerAuthorityDigest: string;
  readonly makerStepUpProofDigest: string;
  readonly checkerStepUpProofDigest: string;
  readonly approvalRequestId: string;
  readonly approvalDecisionId: string;
  readonly approvalDecisionDigest: string;
  readonly admittedAtNs: string;
  readonly authorizationExpiresAtNs: string;
  readonly successorTrustSetDigest: string;
  readonly selectorTransitionDigest: string;
  readonly catalogOperationId: 'ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT';
  readonly actionIntentId: 'ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1';
  readonly expectedRevision: '1';
}
