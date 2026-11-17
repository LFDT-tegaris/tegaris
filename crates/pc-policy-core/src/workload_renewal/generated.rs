// Generated from the adopted canonical workload renewal definitions. Do not edit.
use super::*;

pub const REQUEST_DEFINITION_DIGEST: &str =
    "sha256:3fb38baea7d460c08bc8d05ab888b2a3f03671a23a0a8d7314371aa1ca5adc73";
pub const REQUEST_SCHEMA_ID: u64 = 24038;
pub const REQUEST_PURPOSE_CODE: u64 = 375;

renewal_record!(Request, Some(REQUEST_DEFINITION_DIGEST),
    profile_id: RequestProfile => 1,
    profile_version: VersionOne => 2,
    participant_id: DomainUuid => 3,
    privacy_domain_id: DomainUuid => 4,
    family_id: DomainUuid => 5,
    instance_id: DomainUuid => 6,
    instance_generation: Positive => 7,
    workload_id: Workload => 8,
    principal_id: DomainUuid => 9,
    renewal_id: DomainUuid => 10,
    predecessor_credential_id: DomainUuid => 11,
    predecessor_generation: Positive => 12,
    policy_id: DomainUuid => 13,
    policy_revision: Positive => 14,
    policy_digest: Hash32 => 15,
    attestation_profile_digest: Hash32 => 16,
    attestation_digest: Hash32 => 17,
    issuer_profile_digest: Hash32 => 18,
    provider_qualification_digest: Hash32 => 19,
    new_key_digest: Hash32 => 20,
    challenge_id: DomainUuid => 21,
    challenge_digest: Hash32 => 22,
    requested_certificate_not_before_ns: Nanos => 23,
    requested_certificate_not_after_ns: Nanos => 24,
    expected_family_revision: Positive => 25,
    request_valid_from_ns: Nanos => 26,
    request_valid_until_ns: Nanos => 27,
);

pub const AUTHORIZATION_DEFINITION_DIGEST: &str =
    "sha256:0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d";
pub const AUTHORIZATION_SCHEMA_ID: u64 = 24039;
pub const AUTHORIZATION_PURPOSE_CODE: u64 = 376;

renewal_record!(Authorization, Some(AUTHORIZATION_DEFINITION_DIGEST),
    profile_id: AuthorizationProfile => 1,
    profile_version: VersionOne => 2,
    authorization_mode: PolicyAuthorized => 3,
    request_bytes: RequestBytes => 4,
    request_digest: Hash32 => 5,
    operation_id: DomainUuid => 6,
    credential_id: DomainUuid => 7,
    family_security_epoch: Unsigned => 8,
    participant_epoch: Positive => 9,
    principal_epoch: Positive => 10,
    workload_epoch: Positive => 11,
    policy_governance_receipt_id: DomainUuid => 12,
    policy_governance_receipt_digest: Hash32 => 13,
    instance_admission_receipt_id: DomainUuid => 14,
    instance_admission_receipt_digest: Hash32 => 15,
    business_ancestors_digest: Hash32 => 16,
    m_tls_peer_fingerprint: Hash32 => 17,
    provider_request_digest: Hash32 => 18,
    attestation_valid_until_ns: Nanos => 19,
    signer: Signer => 20,
    issued_at_ns: Nanos => 21,
    valid_until_ns: Nanos => 22,
);

renewal_record!(Signer, None::<&str>,
    environment_id: Identifier => 0,
    participant_id: DomainUuid => 1,
    privacy_domain_id: DomainUuid => 2,
    workload_id: Workload => 3,
    credential_id: DomainUuid => 4,
    credential_epoch: Positive => 5,
    key_id: Hash32 => 6,
    key_epoch: Positive => 7,
    profile_digest: Hash32 => 8,
    trust_digest: Hash32 => 9,
);
