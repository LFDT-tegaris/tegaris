// Generated from schemas/canonical/workload-renewal-signing-profiles/policy-authorization-v2.json. Do not edit.
export const workloadRenewalSigningProfile = {
  profileId: 'pc.identity.workload-renewal.policy-authorization.v1',
  profileVersion: 2,
  schemaId: 24039,
  schemaVersion: 1,
  schemaDefinitionDigest: 'sha256:0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d',
  purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1',
  purposeCode: 376,
  authorizationMode: 'POLICY_AUTHORIZED',
  actionIntentId: 'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1',
  catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-ADMIT',
  signedArtifactProfileVersion: 1,
  trustDomain: 'pc.identity.workload-renewal-signing-trust.v2',
  trustFields: [
    ['participantId', 'uuid'],
    ['privacyDomainId', 'uuid'],
    ['environmentId', 'identifier'],
    ['principalId', 'uuid'],
    ['workloadId', 'workload'],
    ['familyId', 'uuid'],
    ['familySecurityEpoch', 'unsigned'],
    ['participantSecurityInvalidationEpoch', 'unsigned'],
    ['keySecurityGeneration', 'positive'],
    ['signerId', 'hash'],
    ['publicKeySpkiDer', 'p256spki'],
    ['keyEpoch', 'positive'],
    ['validFromNs', 'nanos'],
    ['validUntilNs', 'nanos'],
    ['providerQualificationDigest', 'hash'],
    ['admissionKind', 'admissionKind'],
    ['admissionReference', 'admissionReference'],
    ['admissionDigest', 'hash'],
    ['secretClass', 'secretClass'],
    ['secretReference', 'secretReference'],
    ['secretVersion', 'secretVersion'],
  ],
  securityOwners: {
    familySecurityEpoch: 'control.workload_credential_family.security_epoch',
    participantSecurityInvalidationEpoch:
      'latest control.participant_lifecycle_transition.new_epoch where mutation=ARCHIVE; zero only for authoritative absence',
    keySecurityGeneration:
      'control.business_signing_key_state.row_version under its closed key lifecycle',
    keyEpoch: 'control.business_signing_key.key_epoch',
  },
  currentUse:
    'Exact admitted selection and current key lifecycle, provider qualification, family/current verified transport credential, Participant/principal state and current policy/instance/runtime permission are separate mandatory fences; historical original transport credential grants no current permission.',
  consumerAdmission:
    'TS, SQL and native readers must prove this exact profile and canonical trust before selection; mixed or missing capability denies.',
} as const;
export const workloadRenewalSigningProfileCanonicalJson =
  '{"actionIntentId":"ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1","authorizationMode":"POLICY_AUTHORIZED","catalogOperationId":"ID-OP-WORKLOAD-RENEWAL-ADMIT","consumerAdmission":"TS, SQL and native readers must prove this exact profile and canonical trust before selection; mixed or missing capability denies.","currentUse":"Exact admitted selection and current key lifecycle, provider qualification, family/current verified transport credential, Participant/principal state and current policy/instance/runtime permission are separate mandatory fences; historical original transport credential grants no current permission.","profileId":"pc.identity.workload-renewal.policy-authorization.v1","profileVersion":2,"purpose":"pc.cose.identity.workload-renewal-policy-authorization.v1","purposeCode":376,"schemaDefinitionDigest":"sha256:0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d","schemaId":24039,"schemaVersion":1,"securityOwners":{"familySecurityEpoch":"control.workload_credential_family.security_epoch","keyEpoch":"control.business_signing_key.key_epoch","keySecurityGeneration":"control.business_signing_key_state.row_version under its closed key lifecycle","participantSecurityInvalidationEpoch":"latest control.participant_lifecycle_transition.new_epoch where mutation=ARCHIVE; zero only for authoritative absence"},"signedArtifactProfileVersion":1,"trustDomain":"pc.identity.workload-renewal-signing-trust.v2","trustFields":[["participantId","uuid"],["privacyDomainId","uuid"],["environmentId","identifier"],["principalId","uuid"],["workloadId","workload"],["familyId","uuid"],["familySecurityEpoch","unsigned"],["participantSecurityInvalidationEpoch","unsigned"],["keySecurityGeneration","positive"],["signerId","hash"],["publicKeySpkiDer","p256spki"],["keyEpoch","positive"],["validFromNs","nanos"],["validUntilNs","nanos"],["providerQualificationDigest","hash"],["admissionKind","admissionKind"],["admissionReference","admissionReference"],["admissionDigest","hash"],["secretClass","secretClass"],["secretReference","secretReference"],["secretVersion","secretVersion"]]}';
export const workloadRenewalSigningProfileDigest =
  'sha256:bba6435c44c28f630d498d0d43cb4968fb2cef2828fb831908b7e7bff5cf39df';
