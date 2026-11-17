#![forbid(unsafe_code)]

//! Domain-neutral primitives shared by OpenPC crates.

mod contract_error;
mod version;

pub use contract_error::{ContractError, ContractResult};
pub use version::ContractVersion;
