use pc_policy_core::{
    PolicyCompilationInput, PolicyGenerationArtifact, SimulationInput, SimulationResult,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompilerRequest {
    Compile(PolicyCompilationInput),
    Simulate(SimulationInput),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompilerResponse {
    Compiled {
        artifact: PolicyGenerationArtifact,
        receipt_digest: [u8; 32],
    },
    Simulated(SimulationResult),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyCompilerContractError {
    #[error("required immutable input is missing or incompatible")]
    InvalidInput,
    #[error("contract digest does not match the frozen module graph")]
    DigestMismatch,
    #[error("simulation attempted an authoritative side effect")]
    SimulationSideEffect,
}
