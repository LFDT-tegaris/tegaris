//! Stable public facade for the owner-oriented Gate2 aggregate validators.

mod explorer;
mod indexer;
mod provider;
mod shared;
mod subquery;
mod thegraph;

pub use explorer::{validate_explorer_page, validate_explorer_profile};
pub use indexer::{
    validate_candidate_projection_batch, validate_candidate_projection_batch_structure,
    validate_candidate_projection_batch_with_predecessor, validate_client_indexer_profile,
    validate_projection_plan,
};
pub use provider::{
    provider_profile_admission_enabled, validate_provider_profile, validate_route_request,
};
pub use subquery::{validate_subquery_batch, validate_subquery_profile};
pub use thegraph::{validate_thegraph_batch, validate_thegraph_manifest};

pub(super) use provider::canonicalize_provider_collections;
pub(crate) use provider::{
    profile_key_from_profile, validate_profile_request_binding, validate_route_plan,
};
pub use shared::validate_chain_anchor;
