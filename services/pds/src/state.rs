//! The runtime owner supplies a consistent local view; request callers do not.

use pc_runtime_types::{
    Digest, EvidenceCapacity, RuntimeBindings, RuntimeDecision, RuntimeRequest, RuntimeResult,
};
use serde::Serialize;

use crate::{
    IdentityAssertionBindings, ValidatedInvocationAuthorization, ValidatedInvocationPolicy,
};

/// A lease must hold the owner fences for activation, revocation, fact eligibility
/// and evidence reservation until it is dropped. Implementations belong to the
/// target-local runtime owner, never to an HTTP request decoder or remote lookup.
pub trait LocalDecisionOwner: Send + Sync {
    fn acquire(&self, request: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>>;
}

pub trait LocalDecisionLease {
    fn state(&self) -> &LocalDecisionState;

    /// Check durable owner health while the fences remain held. Failure must not
    /// mint a capability. Dropping the lease releases any unused reservation.
    fn revalidate(&self) -> RuntimeResult<()>;

    /// Persist the exact decision and its required evidence, consuming the
    /// reservation atomically under the same fences. An uncertain commit must
    /// return an error; PDS then withholds the capability for owner reconciliation.
    fn commit(&mut self, decision: &RuntimeDecision) -> RuntimeResult<()>;
}

/// Trusted owner projection, deliberately not deserializable. The owner resolves
/// roles from current assignment/delegation state and identity bindings from the
/// authenticated sender. Matching digests alone do not establish this provenance.
#[derive(Clone, Debug, Serialize)]
pub struct LocalDecisionState {
    /// Target-scoped ID from the owner's durable reservation. Commit consumes
    /// this reservation atomically with evidence; restart cannot reuse its ID.
    pub decision_id: String,
    pub request_digest: Digest,
    /// Exact internal route/preflight evidence from the current owner. This is
    /// included in the signed decision input; it is never caller input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submission_witness_digest: Option<Digest>,
    pub bindings: RuntimeBindings,
    pub active_invocation_policies: Vec<ValidatedInvocationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_policy: Option<pc_policy_core::deployment_policy::ValidatedDeploymentPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility_read: Option<pc_policy_core::visibility_policy::ValidatedVisibilityRead>,
    pub authorization: ValidatedInvocationAuthorization,
    pub identity: IdentityAssertionBindings,
    pub emergency_deny: bool,
    pub evidence: EvidenceCapacity,
    pub valid_until_ms: u64,
}
