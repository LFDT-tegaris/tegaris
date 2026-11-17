#![forbid(unsafe_code)]

//! Stable Rust adapter boundary for generated OpenPC contracts.

pub use pc_primitives::{ContractError, ContractResult, ContractVersion};

pub mod generated;
