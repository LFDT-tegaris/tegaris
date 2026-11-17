import { workloadRenewalDigest } from './codec.js';
import type { WorkloadRenewalRequest, WorkloadRenewalPolicyAuthorization } from './types.js';
import {
  workloadRenewalSigningProfileDigest,
  type WorkloadRenewalSigningTrust,
} from './signing-trust.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
export function renewalSigningTrustFixture(spki: Buffer): WorkloadRenewalSigningTrust {
  return {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'local-qualification',
    principalId: id(30),
    workloadId: `urn:openpc:workload:${id(26)}`,
    familyId: id(31),
    familySecurityEpoch: 2n,
    participantSecurityInvalidationEpoch: 0n,
    keySecurityGeneration: 2n,
    signerId: workloadRenewalDigest(spki),
    publicKeySpkiDer: spki,
    keyEpoch: 2n,
    validFromNs: 1800000000000000000n,
    validUntilNs: 1800086400000000000n,
    providerQualificationDigest: digest(32),
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'urn:openpc:installation:local-test',
    admissionDigest: digest(33),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/workload-renewal#2',
    secretVersion: '2',
    purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1',
    profileId: 'pc.identity.workload-renewal.policy-authorization.v1',
    profileVersion: 2,
    profileDigest: workloadRenewalSigningProfileDigest,
  };
}
export function renewalRequestFixture(newKeyDigest = digest(100)): WorkloadRenewalRequest {
  return {
    profileId: 'pc.identity.workload-renewal.request.v1',
    profileVersion: '1',
    participantId: id(1),
    privacyDomainId: id(2),
    familyId: id(3),
    instanceId: id(4),
    instanceGeneration: '2',
    workloadId: `urn:openpc:workload:${id(5)}`,
    principalId: id(6),
    renewalId: id(7),
    predecessorCredentialId: id(8),
    predecessorGeneration: '12',
    policyId: id(9),
    policyRevision: '3',
    policyDigest: digest(10),
    attestationProfileDigest: digest(11),
    attestationDigest: digest(12),
    issuerProfileDigest: digest(13),
    providerQualificationDigest: digest(14),
    newKeyDigest,
    challengeId: id(15),
    challengeDigest: digest(16),
    requestedCertificateNotBeforeNs: '1800000000000000000',
    requestedCertificateNotAfterNs: '1800086400000000000',
    expectedFamilyRevision: '13',
    requestValidFromNs: '1800000000000000000',
    requestValidUntilNs: '1800000120000000000',
  };
}
export function renewalAuthorizationFixture(
  requestBytes: Buffer,
  signerKeyId = digest(200),
): WorkloadRenewalPolicyAuthorization {
  return {
    profileId: 'pc.identity.workload-renewal.policy-authorization.v1',
    profileVersion: '1',
    authorizationMode: 'POLICY_AUTHORIZED',
    requestBytes,
    requestDigest: workloadRenewalDigest(requestBytes),
    operationId: id(17),
    credentialId: id(18),
    familySecurityEpoch: '2',
    participantEpoch: '3',
    principalEpoch: '4',
    workloadEpoch: '2',
    policyGovernanceReceiptId: id(19),
    policyGovernanceReceiptDigest: digest(20),
    instanceAdmissionReceiptId: id(21),
    instanceAdmissionReceiptDigest: digest(22),
    businessAncestorsDigest: digest(23),
    mTlsPeerFingerprint: digest(24),
    providerRequestDigest: digest(25),
    attestationValidUntilNs: '1800000100000000000',
    signer: {
      environmentId: 'local-qualification',
      participantId: id(1),
      privacyDomainId: id(2),
      workloadId: `urn:openpc:workload:${id(26)}`,
      credentialId: id(27),
      credentialEpoch: '3',
      keyId: signerKeyId,
      keyEpoch: '2',
      profileDigest: digest(28),
      trustDigest: digest(29),
    },
    issuedAtNs: '1800000001000000000',
    validUntilNs: '1800000031000000000',
  };
}
