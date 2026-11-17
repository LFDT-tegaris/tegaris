#![forbid(unsafe_code)]

//! Validated Multi-RPC routing and durable governed-write execution boundary.

pub mod cigl;
mod contract;
pub mod deployment;
mod error;
mod event;
mod evm_trace;
pub mod external_decision;
pub mod fact_observation;
pub mod governed_write;
pub mod journal;
mod normalization;
mod observation_rpc;
pub mod provider_connection;
pub mod provider_probe;
pub mod provider_probe_source;
pub mod route_witness;
pub mod route_witness_set;
mod runtime;
pub mod runtime_profile;
pub mod signed_transaction;
pub mod source_header;
mod state;
pub mod submission_operation;
pub mod submission_status;
pub mod write_preflight;

pub use contract::*;
pub use error::{JournalError, MultiRpcError};
pub use normalization::{
    CanonicalEthGetLogsRecordV1, LocalNormalizedResponseV1, parse_strict_json,
    rfc8785_canonical_bytes,
};
pub use runtime::{LocalFixtureRouteExecutorV1, ReadExecutionResult, SelectedCanonicalReadV1};
