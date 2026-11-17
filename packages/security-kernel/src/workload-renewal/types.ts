/** Successor key possession only. Current mTLS, independent attestation and
 * governed policy admission are separately authenticated by their owners. */
export interface WorkloadRenewalRequest {
  profileId: 'pc.identity.workload-renewal.request.v1';
  profileVersion: '1';
  participantId: string;
  privacyDomainId: string;
  familyId: string;
  instanceId: string;
  instanceGeneration: string;
  workloadId: string;
  principalId: string;
  renewalId: string;
  predecessorCredentialId: string;
  predecessorGeneration: string;
  policyId: string;
  policyRevision: string;
  policyDigest: string;
  attestationProfileDigest: string;
  attestationDigest: string;
  issuerProfileDigest: string;
  providerQualificationDigest: string;
  newKeyDigest: string;
  challengeId: string;
  challengeDigest: string;
  requestedCertificateNotBeforeNs: string;
  requestedCertificateNotAfterNs: string;
  expectedFamilyRevision: string;
  requestValidFromNs: string;
  requestValidUntilNs: string;
}

/** The actual admitted signer is distinct from the successor request key.
 * The trust digest/profile and credential/key epochs retain their meanings. */
export interface WorkloadRenewalAuthorizationSigner {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  workloadId: string;
  credentialId: string;
  credentialEpoch: string;
  keyId: string;
  keyEpoch: string;
  profileDigest: string;
  trustDigest: string;
}

/** Exact dedicated admission assertion. It is neither a human approval nor a
 * business receipt, and crypto verification alone never proves current use. */
export interface WorkloadRenewalPolicyAuthorization {
  profileId: 'pc.identity.workload-renewal.policy-authorization.v1';
  profileVersion: '1';
  authorizationMode: 'POLICY_AUTHORIZED';
  requestBytes: Buffer;
  requestDigest: string;
  operationId: string;
  credentialId: string;
  familySecurityEpoch: string;
  participantEpoch: string;
  principalEpoch: string;
  workloadEpoch: string;
  policyGovernanceReceiptId: string;
  policyGovernanceReceiptDigest: string;
  instanceAdmissionReceiptId: string;
  instanceAdmissionReceiptDigest: string;
  businessAncestorsDigest: string;
  mTlsPeerFingerprint: string;
  providerRequestDigest: string;
  attestationValidUntilNs: string;
  signer: WorkloadRenewalAuthorizationSigner;
  issuedAtNs: string;
  validUntilNs: string;
}
