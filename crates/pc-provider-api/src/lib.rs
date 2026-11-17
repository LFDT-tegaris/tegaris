#![forbid(unsafe_code)]

//! Closed provider and indexer contract types. Runtime behavior is deferred to Gate3.

mod catalog;
mod execution;
mod model;
mod validation;

pub use catalog::{
    PROVIDER_SCHEMA_IDENTITIES, SchemaIdentity, provider_schema_identity, validate_schema_catalog,
};
pub use execution::RouteExecutionContractV1;
pub use model::*;
pub use validation::*;
