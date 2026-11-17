#![forbid(unsafe_code)]

//! Fail-closed authorization contracts and the frozen I02 surface catalog.

mod catalog;
mod context;
mod decision;

pub use catalog::{
    ERROR_CATALOG, EVENT_CATALOG, ErrorDescriptor, EventDescriptor, OPERATION_CATALOG,
    OperationDescriptor,
};
pub use context::{AuthorityContext, AuthorityEvaluation};
pub use decision::AuthorityDecision;

pub const AUTHORIZATION_CONTRACT_TYPE_COUNT: usize = 2;
pub const FROZEN_I02_TYPE_COUNT: usize = 14;
pub const FROZEN_I02_OPERATION_COUNT: usize = 23;
pub const FROZEN_I02_STATE_COUNT: usize = 58;
pub const FROZEN_I02_ERROR_COUNT: usize = 16;
pub const FROZEN_I02_EVENT_COUNT: usize = 8;
