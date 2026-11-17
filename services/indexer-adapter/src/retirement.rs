//! Authenticated target-store retirement. Host wiring and committed Control
//! admission belong to the integration owner; this module exposes no HTTP route.

pub use crate::store::retirement::{
    CandidateRetirementOwner, CandidateRetirementPreflight, CandidateRetirementReadback,
};

#[derive(Debug, thiserror::Error)]
pub enum CandidateRetirementError {
    #[error("retirement authority rejected")]
    Authority,
    #[error("retirement attempt binding changed")]
    AlteredReplay,
    #[error("stored retirement outcome rejected")]
    StoredOutcome,
    #[error(transparent)]
    Store(#[from] crate::CandidateStoreError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub(crate) type Result<T> = std::result::Result<T, CandidateRetirementError>;
