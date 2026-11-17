#![forbid(unsafe_code)]

//! Frozen policy compilation and simulation contract identities.

mod canonical;
mod evaluator;
mod wire;

pub mod cigl;
pub mod contract_policy;
pub mod contract_simulation;
pub mod decision_input;
pub mod decision_material;
pub mod deployment_policy;
pub mod fact_condition;
pub mod fact_profile;
pub mod generated;
pub mod identity_context;
pub mod identity_permissions;
pub mod identity_source;
pub mod indexer_policy;
pub mod invocation;
pub mod invocation_capability;
pub mod invocation_profile;
pub mod module_lifecycle;
pub mod native_value;
pub mod rpc_policy;
pub mod runtime_wire;
pub mod semantics;
pub mod transaction_policy;
pub mod visibility_policy;

pub use evaluator::{
    CompletenessBindings, Contribution, Effect, EpochBindings, EvaluationInput, EvaluationResult,
    IdentityBindings, RequestBindings, TruthState, VersionBindings, evaluate, normalize,
};

pub use canonical::{pc_cbor_1, pc_cbor_1_digest, pc_cbor_1_semantic_digest};
pub mod identity_envelope;
pub mod workload_renewal;

pub use wire::{
    PolicyCompilationInput, PolicyGenerationArtifact, SimulationAuthority, SimulationInput,
    SimulationResult,
};
