#![forbid(unsafe_code)]

//! Process-role boundary for the deterministic compiler and side-effect-free simulator.

mod compiler;
mod contract;

pub use compiler::{SimulationEnvelope, compile, simulate};
pub use contract::{CompilerRequest, CompilerResponse, PolicyCompilerContractError};
