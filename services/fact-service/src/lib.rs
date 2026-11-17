#![forbid(unsafe_code)]

//! Fact Bridge service ownership and communication contract.

pub mod admission;
pub mod candidate_feed;
mod capability;
pub mod consumer_profile;
pub mod deployment;
mod policy_lease;
pub mod retirement;
pub mod source_authority;
pub mod workload_authority;
pub use policy_lease::{FactLease, FactLeaseError, FactLeaseReader};
pub mod runtime;
mod shard_publication;
mod signing;
mod state_value;
mod store;

pub use pc_evidence as evidence;
pub use pc_facts_core as facts;
pub use signing::{
    FactSignatureVerifier, FactSigningError, LocalFactContext, PurposeBoundFactSigner, SignedFact,
    SignedShard, VerifiedLocalFacts, VerifiedShard, signed_fact_digest,
};
pub use store::{
    ArtifactFilter, ArtifactPage, ArtifactPageRequest, DurableAdmissionOutcome,
    FactAdmissionReadback, FactArtifact, FactEvidenceBatch, FactEvidenceLease, FactEvidenceRequest,
    FactFeedBatch, FactFeedEvent, FactFeedPosition, FactOperation, FactOperationBinding,
    FactProjection, FactRetirementBlocker, FactRetirementPreflight, FactRetirementPreflightRequest,
    FactRetirementPreflightResult, FactRetirementSelection, FactRetirementSelectionRequest,
    FactStore, FactStoreError, LifecycleSnapshot, PendingFactAdmissionDelivery, PolicyFactLease,
    PolicyFactReader, PolicyFactSnapshot, PreparedTargetFacts, VerifiedFactAdmissionDelivery,
    VerifiedPolicyFactValue,
};

pub const LOGICAL_SERVICE_ID: &str = "LS-FACT-BRIDGE";
pub const MODULE_ID: &str = "pc.fact-bridge";
pub const DEPLOYMENT_UNIT_ID: &str = "DU-PC-FACT-BRIDGE";
pub const CANDIDATE_STORE_ID: &str = "STORE-CANDIDATE-INDEX-PG";
pub const AUTHORITATIVE_STORE_ID: &str = "STORE-FACT-PG";
pub const CANDIDATE_INPUT_BOUNDARY: &str = "COM-017_READ_ONLY";
pub const AUTHORITATIVE_WRITE_BOUNDARY: &str = "COM-018_SOLE_SEMANTIC_WRITER";
pub const SHARD_PUBLICATION_BOUNDARY: &str = "COM-019_IMMUTABLE_SIGNED_DIGEST";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactServiceOwnership {
    pub candidate_store_authoritative: bool,
    pub mutates_candidate_semantics: bool,
    pub sole_fact_store_semantic_writer: bool,
    pub shard_publication_grants_readiness_before_verification: bool,
}

pub const OWNERSHIP: FactServiceOwnership = FactServiceOwnership {
    candidate_store_authoritative: false,
    mutates_candidate_semantics: false,
    sole_fact_store_semantic_writer: true,
    shard_publication_grants_readiness_before_verification: false,
};

#[must_use]
pub const fn ownership_is_fail_closed(ownership: FactServiceOwnership) -> bool {
    !ownership.candidate_store_authoritative
        && !ownership.mutates_candidate_semantics
        && ownership.sole_fact_store_semantic_writer
        && !ownership.shard_publication_grants_readiness_before_verification
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_ownership_separates_candidate_and_authoritative_stores() {
        assert!(ownership_is_fail_closed(OWNERSHIP));
        assert_ne!(CANDIDATE_STORE_ID, AUTHORITATIVE_STORE_ID);

        let mut forged = OWNERSHIP;
        forged.candidate_store_authoritative = true;
        assert!(!ownership_is_fail_closed(forged));

        forged = OWNERSHIP;
        forged.mutates_candidate_semantics = true;
        assert!(!ownership_is_fail_closed(forged));
    }
}
