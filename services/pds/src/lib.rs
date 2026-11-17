#![forbid(unsafe_code)]

//! Target-local Policy Decision Service. This crate deliberately has no network client dependency.

mod decision;
mod identity;
mod invocation;
mod snapshot;
mod state;
pub use snapshot::{IdentitySnapshotTrust, RuntimeAuthorityProfile, VerifiedIdentitySnapshot};

pub use decision::{EvaluationInput, PolicyDecisionService};
pub use identity::{
    IdentityAssertionBindings, IdentityAssertionEvidence, IdentityAssertionVerifier,
    VerifiedActorProjection, VerifiedIdentityAssertion,
};
pub use state::{LocalDecisionLease, LocalDecisionOwner, LocalDecisionState};

pub use invocation::{
    AbiType, ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
    ActiveInvocationScope, ApprovalRequirement, ArgumentRule, ArgumentValue, Comparator,
    ConfigurationArtifactKind, ConfigurationArtifactV1, InvocationAuthorization,
    InvocationConfigurationAssetV1, InvocationPolicyAssetV1, NamedSet, PathSegment, RuleValues,
    ValidatedInvocationAuthorization, ValidatedInvocationPolicy, VerifiedApprovalFact,
    VerifiedWebauthnFact, decode_active_invocation_configuration,
    encode_active_invocation_configuration, encode_active_invocation_policy_generation,
    load_active_configuration_artifact,
};

#[cfg(test)]
mod tests;
