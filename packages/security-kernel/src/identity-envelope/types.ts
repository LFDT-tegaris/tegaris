/** Signing-envelope semantics, separate from the public projection. The envelope
 * does not establish current issuer authority. All lists are explicit,
 * sorted, duplicate-free finite sets; an empty list grants nothing. */
export interface EnvelopeDimensions {
  participantIds: string[];
  privacyDomainIds: string[];
  resourceIds: string[];
  dataClasses: string[];
  targetProfileIds: string[];
  riskClasses: ('LOW' | 'STANDARD' | 'HIGH' | 'BREAK_GLASS')[];
}
export interface EnvelopeAdministrationSlice extends EnvelopeDimensions {
  actionIntentIds: string[];
}
export interface EnvelopeRuntimeSlice extends EnvelopeDimensions {
  capabilityIds: (
    | 'CALL_RESULT_DISCLOSURE'
    | 'GAS_ESTIMATE_DISCLOSURE'
    | 'ACCESS_LIST_DISCLOSURE'
    | 'UNSIGNED_TRANSACTION_PREPARATION'
    | 'SIGNED_TRANSACTION_SUBMISSION'
    | 'OPERATION_STATUS_DISCLOSURE'
    | 'MULTI_CALL_SIMULATION_DISCLOSURE'
  )[];
}
export interface EnvelopeScope {
  administration: EnvelopeAdministrationSlice;
  runtime: EnvelopeRuntimeSlice;
  validFromNs: string;
  validUntilNs: string;
  makerCheckerRequired: boolean;
  stepUpRequired: boolean;
  onwardDelegationDepth: number;
}
export interface EnvelopeParent {
  envelopeId: string;
  activeVersion: string;
  semanticRevision: string;
  artifactDigest: string;
  authorityEpoch: string;
  delegationEpoch: string;
}
export interface EnvelopeAuthorityBinding {
  participantId: string;
  participantEpoch: string;
  principalId: string;
  principalEpoch: string;
  sessionId: string;
  sessionEpoch: string;
  assignmentId: string;
  assignmentVersion: string;
  authorityEnvelopeId: string;
  authorityEpoch: string;
  delegationEpoch: string;
  roleId: string;
  roleVersion: string;
  roleDigest: string;
  authorityDigest: string;
}
export interface EnvelopeActorEvidence {
  authority: EnvelopeAuthorityBinding;
  stepUpChallengeId: string;
  stepUpEvidenceDigest: string;
  signerCredentialId: string;
  signerCredentialEpoch: string;
}
export interface EnvelopeIssuer {
  kind: 'PLATFORM' | 'PARTICIPANT';
  authority: EnvelopeAuthorityBinding;
  platformContextId: string;
  platformAuthorityEpoch: string;
  platformAuthorityDigest: string;
  parent: EnvelopeParent | null;
}
export interface EnvelopeProposal {
  envelopeId: string;
  semanticRevision: string;
  participantId: string;
  participantEpoch: string;
  authorityEpoch: string;
  delegationEpoch: string;
  issuance: 'PLATFORM_ROOT' | 'CHILD' | 'ROTATION';
  usable: EnvelopeScope;
  grantable: EnvelopeScope;
  issuer: EnvelopeIssuer;
}
export interface EnvelopeSubmission {
  operationId: string;
  candidateId: string;
  candidateDigest: string;
  approvalRequestId: string;
  approvalDigest: string;
  submittedVersion: string;
  approvedVersion: string;
  maker: EnvelopeActorEvidence;
  checker: EnvelopeActorEvidence;
}
export interface EnvelopeActivation {
  operationId: string;
  candidateId: string;
  candidateDigest: string;
  approvalRequestId: string;
  approvalDigest: string;
  expectedApprovedVersion: string;
  activeVersion: string;
  idempotencyBindingDigest: string;
  actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';
  catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE';
  maker: EnvelopeActorEvidence;
  checker: EnvelopeActorEvidence;
}
export interface EnvelopeSigner {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  profileId: string;
  profileVersion: string;
  profileDigest: string;
  keyId: string;
  keyVersion: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  trustContextDigest: string;
}
export interface IdentityAuthorityEnvelope {
  /** Exact submitted canonical bytes, never regenerated at activation. */
  proposalBytes: Buffer;
  proposalDigest: string;
  submission: EnvelopeSubmission;
  activation: EnvelopeActivation;
  signer: EnvelopeSigner;
  issuedAtNs: string;
}
