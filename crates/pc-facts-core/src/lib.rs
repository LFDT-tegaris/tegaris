#![forbid(unsafe_code)]

//! Frozen Fact Bridge semantic identities and fail-closed state contracts.
//!
//! Gate2 deliberately contains no admission, persistence, signing, reorg, or
//! publication implementation. Those obligations remain owned by I05 Gate3.

mod admission;
mod catalog;
mod identity;
mod record;
mod state;

pub use admission::{
    AdmissionError, FactAdmissionCandidate, TrustedAdmissionContext, ValidatedAdmission,
    canonical_fact_digest, encode_pc_cbor, sha256, validate_admission, validate_pc_cbor,
};
pub use catalog::{
    FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_ADMISSION_GATES, FACT_BRIDGE_OPERATIONS,
    FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_RECORD_SCHEMA_ID, FACT_SCHEMA_IDENTITIES,
    FACT_SCHEMA_VERSION_V1, FACT_SHARD_MANIFEST_SCHEMA_ID, RELATIONSHIP_CANDIDATE_SCHEMA_ID,
    RELATIONSHIP_FACT_SCHEMA_ID, RELATIONSHIP_SCHEMA_DIGEST_V1, RELATIONSHIP_SCHEMA_IDENTITIES,
    RELATIONSHIP_SHARD_SCHEMA_ID, SchemaIdentity, fact_schema_identity, record_schema,
    record_schema_digest, validate_schema_identities,
};
pub use identity::{CanonicalFactIdentity, FactChainAnchor, FactObject, FactSubject};
pub use record::{FactCompletenessScope, FactGapState, FactRecord, fact_timestamp_from_ms};
pub use state::{
    AdmissionOutcome, CandidateState, CheckpointState, FactLifecycleState, FactQueryOutcome,
    FactReadinessState, LineageAction, RelationshipResult, replacement_is_admissible,
};

pub use pc_contracts::generated::openpc::facts::v1 as wire;

/// A fact is positive-eligible only at the exact finalized/ready intersection.
#[must_use]
pub const fn is_positive_eligible(
    lifecycle: FactLifecycleState,
    readiness: FactReadinessState,
) -> bool {
    matches!(lifecycle, FactLifecycleState::Finalized)
        && matches!(readiness, FactReadinessState::Ready)
}
