// Generated from schemas/canonical/workload-renewal-policy-authorization-v1.json. Do not edit.
export const workloadRenewalAuthorizationContext = {
  schemaId: 24039,
  schemaVersion: 1,
  purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1',
  purposeCode: 376,
  definitionDigest: 'sha256:0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d',
  contentType: 'application/pc+cbor',
  externalAadHex: '7063706c616e653a636f73652d7369676e313a763200',
  signatureProfileVersion: 2,
  types: {
    Authorization: [
      {
        key: 0,
        name: 'definitionDigest',
        type: 'definitionDigest',
      },
      {
        key: 1,
        name: 'profileId',
        type: 'authorizationProfile',
      },
      {
        key: 2,
        name: 'profileVersion',
        type: 'version1',
      },
      {
        key: 3,
        name: 'authorizationMode',
        type: 'policyAuthorized',
      },
      {
        key: 4,
        name: 'requestBytes',
        type: 'requestBytes',
      },
      {
        key: 5,
        name: 'requestDigest',
        type: 'H32',
      },
      {
        key: 6,
        name: 'operationId',
        type: 'uuid',
      },
      {
        key: 7,
        name: 'credentialId',
        type: 'uuid',
      },
      {
        key: 8,
        name: 'familySecurityEpoch',
        type: 'u64',
      },
      {
        key: 9,
        name: 'participantEpoch',
        type: 'u64p',
      },
      {
        key: 10,
        name: 'principalEpoch',
        type: 'u64p',
      },
      {
        key: 11,
        name: 'workloadEpoch',
        type: 'u64p',
      },
      {
        key: 12,
        name: 'policyGovernanceReceiptId',
        type: 'uuid',
      },
      {
        key: 13,
        name: 'policyGovernanceReceiptDigest',
        type: 'H32',
      },
      {
        key: 14,
        name: 'instanceAdmissionReceiptId',
        type: 'uuid',
      },
      {
        key: 15,
        name: 'instanceAdmissionReceiptDigest',
        type: 'H32',
      },
      {
        key: 16,
        name: 'businessAncestorsDigest',
        type: 'H32',
      },
      {
        key: 17,
        name: 'mTlsPeerFingerprint',
        type: 'H32',
      },
      {
        key: 18,
        name: 'providerRequestDigest',
        type: 'H32',
      },
      {
        key: 19,
        name: 'attestationValidUntilNs',
        type: 'nanos',
      },
      {
        key: 20,
        name: 'signer',
        type: 'Signer',
      },
      {
        key: 21,
        name: 'issuedAtNs',
        type: 'nanos',
      },
      {
        key: 22,
        name: 'validUntilNs',
        type: 'nanos',
      },
    ],
    Signer: [
      {
        key: 0,
        name: 'environmentId',
        type: 'id',
      },
      {
        key: 1,
        name: 'participantId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'privacyDomainId',
        type: 'uuid',
      },
      {
        key: 3,
        name: 'workloadId',
        type: 'workload',
      },
      {
        key: 4,
        name: 'credentialId',
        type: 'uuid',
      },
      {
        key: 5,
        name: 'credentialEpoch',
        type: 'u64p',
      },
      {
        key: 6,
        name: 'keyId',
        type: 'H32',
      },
      {
        key: 7,
        name: 'keyEpoch',
        type: 'u64p',
      },
      {
        key: 8,
        name: 'profileDigest',
        type: 'H32',
      },
      {
        key: 9,
        name: 'trustDigest',
        type: 'H32',
      },
    ],
  },
} as const;
