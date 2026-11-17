// Generated from schemas/canonical/workload-renewal-request-v1.json. Do not edit.
export const workloadRenewalRequestContext = {
  schemaId: 24038,
  schemaVersion: 1,
  purpose: 'pc.cose.identity.workload-renewal-request.v1',
  purposeCode: 375,
  definitionDigest: 'sha256:3fb38baea7d460c08bc8d05ab888b2a3f03671a23a0a8d7314371aa1ca5adc73',
  contentType: 'application/pc+cbor',
  externalAadHex: '7063706c616e653a636f73652d7369676e313a763200',
  signatureProfileVersion: 2,
  types: {
    Request: [
      {
        key: 0,
        name: 'definitionDigest',
        type: 'definitionDigest',
      },
      {
        key: 1,
        name: 'profileId',
        type: 'requestProfile',
      },
      {
        key: 2,
        name: 'profileVersion',
        type: 'version1',
      },
      {
        key: 3,
        name: 'participantId',
        type: 'uuid',
      },
      {
        key: 4,
        name: 'privacyDomainId',
        type: 'uuid',
      },
      {
        key: 5,
        name: 'familyId',
        type: 'uuid',
      },
      {
        key: 6,
        name: 'instanceId',
        type: 'uuid',
      },
      {
        key: 7,
        name: 'instanceGeneration',
        type: 'u64p',
      },
      {
        key: 8,
        name: 'workloadId',
        type: 'workload',
      },
      {
        key: 9,
        name: 'principalId',
        type: 'uuid',
      },
      {
        key: 10,
        name: 'renewalId',
        type: 'uuid',
      },
      {
        key: 11,
        name: 'predecessorCredentialId',
        type: 'uuid',
      },
      {
        key: 12,
        name: 'predecessorGeneration',
        type: 'u64p',
      },
      {
        key: 13,
        name: 'policyId',
        type: 'uuid',
      },
      {
        key: 14,
        name: 'policyRevision',
        type: 'u64p',
      },
      {
        key: 15,
        name: 'policyDigest',
        type: 'H32',
      },
      {
        key: 16,
        name: 'attestationProfileDigest',
        type: 'H32',
      },
      {
        key: 17,
        name: 'attestationDigest',
        type: 'H32',
      },
      {
        key: 18,
        name: 'issuerProfileDigest',
        type: 'H32',
      },
      {
        key: 19,
        name: 'providerQualificationDigest',
        type: 'H32',
      },
      {
        key: 20,
        name: 'newKeyDigest',
        type: 'H32',
      },
      {
        key: 21,
        name: 'challengeId',
        type: 'uuid',
      },
      {
        key: 22,
        name: 'challengeDigest',
        type: 'H32',
      },
      {
        key: 23,
        name: 'requestedCertificateNotBeforeNs',
        type: 'nanos',
      },
      {
        key: 24,
        name: 'requestedCertificateNotAfterNs',
        type: 'nanos',
      },
      {
        key: 25,
        name: 'expectedFamilyRevision',
        type: 'u64p',
      },
      {
        key: 26,
        name: 'requestValidFromNs',
        type: 'nanos',
      },
      {
        key: 27,
        name: 'requestValidUntilNs',
        type: 'nanos',
      },
    ],
  },
} as const;
