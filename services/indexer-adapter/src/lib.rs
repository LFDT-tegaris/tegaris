#![forbid(unsafe_code)]

//! Replaceable, non-authoritative candidate adapter and candidate-store boundary.

pub mod acquisition;
mod acquisition_configuration;
mod candidate;
pub mod control_materialization;
pub mod control_source;
mod finality_rule;
mod publication;
pub mod retirement;
pub mod retirement_capability;
mod source_request;
mod store;

use pc_provider_api::{
    ClientIndexerProfileV1, ProjectionPlanV1, decode_client_indexer_profile_pc_cbor,
    decode_projection_plan_pc_cbor, validate_client_indexer_profile, validate_projection_plan,
};
use sha2::{Digest as _, Sha256};

pub use acquisition_configuration::{
    AcquisitionConfiguration, AcquisitionRateLimit, AcquisitionRequest,
};
pub use candidate::{
    CandidateBatchMaterialV1, CandidateBlockFinalityV1, CandidateBlockObservationV1,
    CandidatePersistenceBinding, CandidateRecordIdentityV1, CandidateRecordMaterialV1,
};
pub use finality_rule::{FinalityMode, FinalityRule};
pub use publication::{
    CandidatePublicationStore, GovernedSourcePublication, PublishedAcquisitionInputs,
    PublishedSource,
};
pub use source_request::DecodedAcquisitionRequest;
pub use store::delivery::FactDeliveryReader;
pub use store::{CandidateStore, CandidateStoreError, PersistenceOutcome, ReorgInvalidation};

pub use pc_facts_core::wire;

pub const CANDIDATE_STORE_ID: &str = "STORE-CANDIDATE-INDEX-PG";
pub const FACT_STORE_ID: &str = "STORE-FACT-PG";
pub const CANDIDATE_OUTPUT: &str = "CandidateOutboxEnvelopeV1";
pub const PROFILE_OPERATIONS: [&str; 3] = ["RegisterProfile", "ReconcilePlan", "RetireProfile"];
pub const SOURCE_AUTHORITY: &str = "NON_AUTHORITATIVE";
pub const FACT_STORE_WRITE: &str = "FORBIDDEN";

fn exact_digest(bytes: &[u8], expected: &str) -> bool {
    let actual = Sha256::digest(bytes);
    let mut encoded = String::from("sha256:");
    for byte in actual {
        use std::fmt::Write as _;
        if write!(encoded, "{byte:02x}").is_err() {
            return false;
        }
    }
    encoded == expected
}

pub fn admit_client_indexer_profile(
    profile_cbor: &[u8],
    expected_artifact_digest: &str,
) -> Result<ClientIndexerProfileV1, &'static str> {
    if !exact_digest(profile_cbor, expected_artifact_digest) {
        return Err("client indexer profile digest");
    }
    let profile = decode_client_indexer_profile_pc_cbor(profile_cbor)
        .map_err(|_| "client indexer profile PC-CBOR")?;
    validate_client_indexer_profile(&profile).map_err(|_| "client indexer profile admission")?;
    if SOURCE_AUTHORITY != "NON_AUTHORITATIVE" || FACT_STORE_WRITE != "FORBIDDEN" {
        return Err("candidate authority boundary");
    }
    Ok(profile)
}

pub fn validate_projection_admission(
    profile_cbor: &[u8],
    plan_cbor: &[u8],
    expected_plan_digest: &str,
) -> Result<ProjectionPlanV1, &'static str> {
    let profile = decode_client_indexer_profile_pc_cbor(profile_cbor)
        .map_err(|_| "client indexer profile PC-CBOR")?;
    let plan = decode_projection_plan_pc_cbor(plan_cbor).map_err(|_| "projection plan PC-CBOR")?;
    if !exact_digest(plan_cbor, expected_plan_digest) {
        return Err("projection plan digest");
    }
    validate_projection_plan(&profile, &plan).map_err(|_| "projection plan admission")?;
    Ok(plan)
}

/// Bind admitted artifact bytes to the governing control-store scope. UUIDs here
/// follow the runtime configuration owner; public-envelope URNs are not aliases.
pub fn admit_scoped_client_indexer_profile(
    profile_cbor: &[u8],
    expected_artifact_digest: &str,
    participant_id: &str,
    privacy_domain_id: &str,
) -> Result<ClientIndexerProfileV1, &'static str> {
    let profile = admit_client_indexer_profile(profile_cbor, expected_artifact_digest)?;
    if profile.participant_binding != participant_id || profile.privacy_binding != privacy_domain_id
    {
        return Err("client indexer profile scope");
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_cannot_become_fact_authority() {
        assert_ne!(CANDIDATE_STORE_ID, FACT_STORE_ID);
        assert_eq!(SOURCE_AUTHORITY, "NON_AUTHORITATIVE");
        assert_eq!(FACT_STORE_WRITE, "FORBIDDEN");
        assert_eq!(PROFILE_OPERATIONS.len(), 3);
    }
}
