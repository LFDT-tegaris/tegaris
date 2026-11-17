// Generated from schemas/canonical/identity-authority-envelope-v1.json and schemas/canonical/identity-envelope-signing-profiles/authority-envelope-v1.json. Do not edit.
export const identityEnvelopeContext = {
  schemaId: 24034,
  schemaVersion: 1,
  purpose: 'pc.cose.identity-authority-envelope.v1',
  purposeCode: 371,
  definitionDigest: 'sha256:6cf5c91789d9488014d3ec9445d5852c4aa686534305c6516d67210176ea3cc5',
  contentType: 'application/pc+cbor',
  externalAadHex: '7063706c616e653a636f73652d7369676e313a763200',
  signatureProfileVersion: 2,
  types: {
    Administration: [
      {
        key: 1,
        name: 'participantIds',
        type: 'uuidSet',
      },
      {
        key: 2,
        name: 'privacyDomainIds',
        type: 'uuidSet',
      },
      {
        key: 3,
        name: 'resourceIds',
        type: 'idSet',
      },
      {
        key: 4,
        name: 'dataClasses',
        type: 'idSet',
      },
      {
        key: 5,
        name: 'targetProfileIds',
        type: 'idSet',
      },
      {
        key: 6,
        name: 'riskClasses',
        type: 'riskSet',
      },
      {
        key: 7,
        name: 'actionIntentIds',
        type: 'actionSet',
      },
    ],
    Runtime: [
      {
        key: 1,
        name: 'participantIds',
        type: 'uuidSet',
      },
      {
        key: 2,
        name: 'privacyDomainIds',
        type: 'uuidSet',
      },
      {
        key: 3,
        name: 'resourceIds',
        type: 'idSet',
      },
      {
        key: 4,
        name: 'dataClasses',
        type: 'idSet',
      },
      {
        key: 5,
        name: 'targetProfileIds',
        type: 'idSet',
      },
      {
        key: 6,
        name: 'riskClasses',
        type: 'riskSet',
      },
      {
        key: 7,
        name: 'capabilityIds',
        type: 'capabilitySet',
      },
    ],
    Scope: [
      {
        key: 1,
        name: 'administration',
        type: 'Administration',
      },
      {
        key: 2,
        name: 'runtime',
        type: 'Runtime',
      },
      {
        key: 3,
        name: 'validFromNs',
        type: 'nanos',
      },
      {
        key: 4,
        name: 'validUntilNs',
        type: 'nanos',
      },
      {
        key: 5,
        name: 'makerCheckerRequired',
        type: 'flag',
      },
      {
        key: 6,
        name: 'stepUpRequired',
        type: 'flag',
      },
      {
        key: 7,
        name: 'onwardDelegationDepth',
        type: 'depth',
      },
    ],
    Parent: [
      {
        key: 1,
        name: 'envelopeId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'activeVersion',
        type: 'u64p',
      },
      {
        key: 3,
        name: 'semanticRevision',
        type: 'u64p',
      },
      {
        key: 4,
        name: 'artifactDigest',
        type: 'H32',
      },
      {
        key: 5,
        name: 'authorityEpoch',
        type: 'u64',
      },
      {
        key: 6,
        name: 'delegationEpoch',
        type: 'u64',
      },
    ],
    Authority: [
      {
        key: 1,
        name: 'participantId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'participantEpoch',
        type: 'u64',
      },
      {
        key: 3,
        name: 'principalId',
        type: 'uuid',
      },
      {
        key: 4,
        name: 'principalEpoch',
        type: 'u64',
      },
      {
        key: 5,
        name: 'sessionId',
        type: 'uuid',
      },
      {
        key: 6,
        name: 'sessionEpoch',
        type: 'u64',
      },
      {
        key: 7,
        name: 'assignmentId',
        type: 'uuid',
      },
      {
        key: 8,
        name: 'assignmentVersion',
        type: 'u64p',
      },
      {
        key: 9,
        name: 'authorityEnvelopeId',
        type: 'uuid',
      },
      {
        key: 10,
        name: 'authorityEpoch',
        type: 'u64',
      },
      {
        key: 11,
        name: 'delegationEpoch',
        type: 'u64',
      },
      {
        key: 12,
        name: 'roleId',
        type: 'id',
      },
      {
        key: 13,
        name: 'roleVersion',
        type: 'u64p',
      },
      {
        key: 14,
        name: 'roleDigest',
        type: 'H32',
      },
      {
        key: 15,
        name: 'authorityDigest',
        type: 'H32',
      },
    ],
    Actor: [
      {
        key: 1,
        name: 'authority',
        type: 'Authority',
      },
      {
        key: 2,
        name: 'stepUpChallengeId',
        type: 'uuid',
      },
      {
        key: 3,
        name: 'stepUpEvidenceDigest',
        type: 'H32',
      },
      {
        key: 4,
        name: 'signerCredentialId',
        type: 'uuid',
      },
      {
        key: 5,
        name: 'signerCredentialEpoch',
        type: 'u64',
      },
    ],
    Issuer: [
      {
        key: 1,
        name: 'kind',
        type: 'issuerKind',
      },
      {
        key: 2,
        name: 'authority',
        type: 'Authority',
      },
      {
        key: 3,
        name: 'platformContextId',
        type: 'uuid',
      },
      {
        key: 4,
        name: 'platformAuthorityEpoch',
        type: 'u64',
      },
      {
        key: 5,
        name: 'platformAuthorityDigest',
        type: 'H32',
      },
      {
        key: 6,
        name: 'parent',
        type: 'optionalParent',
      },
    ],
    Proposal: [
      {
        key: 0,
        name: 'schemaDefinitionDigest',
        type: 'definitionDigest',
      },
      {
        key: 1,
        name: 'envelopeId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'semanticRevision',
        type: 'u64p',
      },
      {
        key: 3,
        name: 'participantId',
        type: 'uuid',
      },
      {
        key: 4,
        name: 'participantEpoch',
        type: 'u64',
      },
      {
        key: 5,
        name: 'authorityEpoch',
        type: 'u64',
      },
      {
        key: 6,
        name: 'delegationEpoch',
        type: 'u64',
      },
      {
        key: 7,
        name: 'issuance',
        type: 'issuance',
      },
      {
        key: 8,
        name: 'usable',
        type: 'Scope',
      },
      {
        key: 9,
        name: 'grantable',
        type: 'Scope',
      },
      {
        key: 10,
        name: 'issuer',
        type: 'Issuer',
      },
    ],
    Submission: [
      {
        key: 1,
        name: 'operationId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'candidateId',
        type: 'uuid',
      },
      {
        key: 3,
        name: 'candidateDigest',
        type: 'H32',
      },
      {
        key: 4,
        name: 'approvalRequestId',
        type: 'uuid',
      },
      {
        key: 5,
        name: 'approvalDigest',
        type: 'H32',
      },
      {
        key: 6,
        name: 'submittedVersion',
        type: 'u64p',
      },
      {
        key: 7,
        name: 'approvedVersion',
        type: 'u64p',
      },
      {
        key: 8,
        name: 'maker',
        type: 'Actor',
      },
      {
        key: 9,
        name: 'checker',
        type: 'Actor',
      },
    ],
    Activation: [
      {
        key: 1,
        name: 'operationId',
        type: 'uuid',
      },
      {
        key: 2,
        name: 'candidateId',
        type: 'uuid',
      },
      {
        key: 3,
        name: 'candidateDigest',
        type: 'H32',
      },
      {
        key: 4,
        name: 'approvalRequestId',
        type: 'uuid',
      },
      {
        key: 5,
        name: 'approvalDigest',
        type: 'H32',
      },
      {
        key: 6,
        name: 'expectedApprovedVersion',
        type: 'u64p',
      },
      {
        key: 7,
        name: 'activeVersion',
        type: 'u64p',
      },
      {
        key: 8,
        name: 'idempotencyBindingDigest',
        type: 'H32',
      },
      {
        key: 9,
        name: 'actionIntentId',
        type: 'activateAction',
      },
      {
        key: 10,
        name: 'catalogOperationId',
        type: 'activateOperation',
      },
      {
        key: 11,
        name: 'maker',
        type: 'Actor',
      },
      {
        key: 12,
        name: 'checker',
        type: 'Actor',
      },
    ],
    Signer: [
      {
        key: 1,
        name: 'environmentId',
        type: 'id',
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
        name: 'profileId',
        type: 'id',
      },
      {
        key: 5,
        name: 'profileVersion',
        type: 'u64p',
      },
      {
        key: 6,
        name: 'profileDigest',
        type: 'H32',
      },
      {
        key: 7,
        name: 'keyId',
        type: 'H32',
      },
      {
        key: 8,
        name: 'keyVersion',
        type: 'id',
      },
      {
        key: 9,
        name: 'workloadCredentialId',
        type: 'uuid',
      },
      {
        key: 10,
        name: 'workloadCredentialEpoch',
        type: 'u64',
      },
      {
        key: 11,
        name: 'trustContextDigest',
        type: 'H32',
      },
    ],
    Envelope: [
      {
        key: 0,
        name: 'schemaDefinitionDigest',
        type: 'definitionDigest',
      },
      {
        key: 1,
        name: 'proposalBytes',
        type: 'proposalBytes',
      },
      {
        key: 2,
        name: 'proposalDigest',
        type: 'H32',
      },
      {
        key: 3,
        name: 'submission',
        type: 'Submission',
      },
      {
        key: 4,
        name: 'activation',
        type: 'Activation',
      },
      {
        key: 5,
        name: 'signer',
        type: 'Signer',
      },
      {
        key: 6,
        name: 'issuedAtNs',
        type: 'nanos',
      },
    ],
  },
} as const;
export const identityEnvelopeSigningProfile = Object.freeze({
  profileId: 'pc.identity.authority-envelope.v1',
  profileVersion: 1,
  schemaId: 24034,
  schemaVersion: 1,
  schemaDefinitionDigest: 'sha256:6cf5c91789d9488014d3ec9445d5852c4aa686534305c6516d67210176ea3cc5',
  purpose: 'pc.cose.identity-authority-envelope.v1',
  purposeCode: 371,
  actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
  aggregateType: 'authority-envelope',
} as const);
export const identityEnvelopeSigningProfileJson =
  '{"actionIntentId":"ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1","aggregateType":"authority-envelope","catalogOperationId":"ID-OP-ENVELOPE-ACTIVATE","profileId":"pc.identity.authority-envelope.v1","profileVersion":1,"purpose":"pc.cose.identity-authority-envelope.v1","purposeCode":371,"schemaDefinitionDigest":"sha256:6cf5c91789d9488014d3ec9445d5852c4aa686534305c6516d67210176ea3cc5","schemaId":24034,"schemaVersion":1}';
export const identityEnvelopeSigningProfileDigest =
  'sha256:54d85c86019a4475f8207f375fa571565e9e6e0adb5b0bd55abc03e4beb81f74';
