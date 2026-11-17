// Generated from schemas/canonical/workload-renewal-signing-profiles/policy-authorization-v2.json. Do not edit.
pub const SIGNING_PROFILE_DIGEST: &str =
    "sha256:bba6435c44c28f630d498d0d43cb4968fb2cef2828fb831908b7e7bff5cf39df";
pub const SIGNING_PROFILE_VERSION: u64 = 2;
pub const SIGNING_TRUST_DOMAIN: &str = "pc.identity.workload-renewal-signing-trust.v2";
pub const SIGNING_TRUST_FIELDS: &[(&str, &str)] = &[
    ("participantId", "uuid"),
    ("privacyDomainId", "uuid"),
    ("environmentId", "identifier"),
    ("principalId", "uuid"),
    ("workloadId", "workload"),
    ("familyId", "uuid"),
    ("familySecurityEpoch", "unsigned"),
    ("participantSecurityInvalidationEpoch", "unsigned"),
    ("keySecurityGeneration", "positive"),
    ("signerId", "hash"),
    ("publicKeySpkiDer", "p256spki"),
    ("keyEpoch", "positive"),
    ("validFromNs", "nanos"),
    ("validUntilNs", "nanos"),
    ("providerQualificationDigest", "hash"),
    ("admissionKind", "admissionKind"),
    ("admissionReference", "admissionReference"),
    ("admissionDigest", "hash"),
    ("secretClass", "secretClass"),
    ("secretReference", "secretReference"),
    ("secretVersion", "secretVersion"),
];
