#![forbid(unsafe_code)]

//! Closed runtime boundary types and deterministic authorization envelopes.

mod authorization;
mod configuration;
mod digest;
mod error;
mod generation;
mod local_journal;
mod request;
pub mod runtime_source_identity;
pub mod store_retirement;
pub mod store_retirement_authority;
pub mod target_disposition;

pub use authorization::{PurposeSigner, PurposeVerifier, ReplayAdmission, SignedEnvelope};
pub use configuration::RuntimeConfiguration;
pub use digest::{Digest, canonical_bytes};
pub use error::{PublicRuntimeError, RuntimeError, RuntimeResult};
pub use generation::{
    ActivationReceipt, ActivationToken, DesiredGeneration, PreparedGeneration, TargetState,
};
pub use local_journal::LocalJournal;
pub use request::{
    AttemptResolution, BrokerCapability, ContractInvocation, DecisionEffect, DeploymentInvocation,
    EvidenceCapacity, PolicyConjunct, ProviderResponse, RequestClass, RuntimeBindings,
    RuntimeDecision, RuntimeRequest, Transport, VisibilityRead, VisibilityReadQuery,
};

pub const PURPOSE_BROKER_CAPABILITY_V1: &str = "openpc:broker-capability:v1";
pub const PURPOSE_DESIRED_GENERATION_V1: &str = "openpc:desired-generation:v1";
pub const PURPOSE_ACTIVATION_TOKEN_V1: &str = "openpc:activation-token:v1";
pub const PURPOSE_ACTIVATION_RECEIPT_V1: &str = "openpc:activation-receipt:v1";
