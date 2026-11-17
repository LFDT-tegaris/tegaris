//! Typed response permissions. These expressions do not establish identity,
//! Fact currentness or release custody; their owning services supply those inputs.

use std::collections::BTreeSet;

use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

use crate::{
    fact_condition::{FactCondition, validate_conditions},
    rpc_policy::RpcEffect,
    semantics::{FactReference, digest, uuid_v7},
};

mod compilation;
mod read;
pub use read::{ValidatedVisibilityRead, VisibilityReadPolicySet, read_purpose, read_resource};
mod simulation;
pub(crate) use compilation::compile as compile_resources;
pub use compilation::{AdmittedVisibilityResource, VisibilityContractBinding, validate_resources};
pub use simulation::{
    VisibilitySimulationInput, VisibilitySimulationRequest, evaluate_visibility_simulation,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VisibilityDimension {
    Existence,
    Metadata,
    Payload,
    Evidence,
    Export,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VisibilityMode {
    Static,
    Dynamic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VisibilitySelector {
    #[serde(rename_all = "camelCase")]
    StateRead {
        contract_method_policy_id: String,
        revision: String,
    },
    #[serde(rename_all = "camelCase")]
    Event {
        runtime_binding_id: String,
        binding_revision: String,
        abi_digest: String,
        event_signature: String,
    },
    #[serde(rename_all = "camelCase")]
    Transaction {
        runtime_binding_id: String,
        binding_revision: String,
    },
    #[serde(rename_all = "camelCase")]
    Receipt {
        runtime_binding_id: String,
        binding_revision: String,
    },
    #[serde(rename_all = "camelCase")]
    Disclosure {
        profile_id: String,
        profile_digest: String,
        data_class_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VisibilitySubject {
    #[serde(rename_all = "camelCase")]
    Principal { principal_id: String },
    #[serde(rename_all = "camelCase")]
    Workload { workload_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VisibilityPolicy {
    pub policy_id: String,
    pub selector: VisibilitySelector,
    pub mode: VisibilityMode,
    pub effect: RpcEffect,
    pub subject: VisibilitySubject,
    pub purpose: String,
    pub required_roles: Vec<String>,
    pub dimensions: Vec<VisibilityDimension>,
    /// Explicit admitted field identities. Receipts have no field projection:
    /// their complete standard response is either visible or withheld.
    pub fields: Vec<String>,
    pub conditions: Vec<FactCondition>,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains('*')
}

fn unique_labels(values: &[String], maximum: usize) -> bool {
    values.len() <= maximum
        && values.iter().all(|value| label(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn revision(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|parsed| parsed > 0 && parsed.to_string() == value)
}

impl VisibilitySubject {
    fn validate(&self) -> bool {
        match self {
            Self::Principal { principal_id } => uuid_v7(principal_id),
            Self::Workload { workload_id } => workload_id
                .strip_prefix("urn:openpc:workload:")
                .is_some_and(uuid_v7),
        }
    }
}

impl VisibilitySelector {
    pub fn resource_id(&self) -> &str {
        match self {
            Self::StateRead {
                contract_method_policy_id,
                ..
            } => contract_method_policy_id,
            Self::Event {
                runtime_binding_id, ..
            }
            | Self::Transaction {
                runtime_binding_id, ..
            }
            | Self::Receipt {
                runtime_binding_id, ..
            } => runtime_binding_id,
            Self::Disclosure { profile_id, .. } => profile_id,
        }
    }
    fn validate(&self) -> bool {
        match self {
            Self::StateRead {
                contract_method_policy_id,
                revision,
            } => {
                uuid_v7(contract_method_policy_id)
                    && revision
                        .parse::<u64>()
                        .is_ok_and(|value| value > 0 && value.to_string() == *revision)
            }
            Self::Event {
                runtime_binding_id,
                binding_revision,
                abi_digest,
                event_signature,
            } => {
                uuid_v7(runtime_binding_id)
                    && revision(binding_revision)
                    && digest(abi_digest)
                    && label(event_signature)
                    && event_signature.contains('(')
                    && event_signature.ends_with(')')
            }
            Self::Transaction {
                runtime_binding_id,
                binding_revision,
            }
            | Self::Receipt {
                runtime_binding_id,
                binding_revision,
            } => uuid_v7(runtime_binding_id) && revision(binding_revision),
            Self::Disclosure {
                profile_id,
                profile_digest,
                data_class_id,
            } => uuid_v7(profile_id) && digest(profile_digest) && label(data_class_id),
        }
    }
}

impl VisibilityPolicy {
    pub fn module_id(&self) -> &'static str {
        match (&self.selector, self.mode) {
            (VisibilitySelector::StateRead { .. }, _) => "pc.policy.state-read",
            (VisibilitySelector::Event { .. }, VisibilityMode::Static) => {
                "pc.policy.event-visibility"
            }
            (VisibilitySelector::Event { .. }, VisibilityMode::Dynamic) => {
                "pc.policy.dynamic-event-visibility"
            }
            (VisibilitySelector::Transaction { .. } | VisibilitySelector::Receipt { .. }, _) => {
                "pc.policy.ptv"
            }
            (VisibilitySelector::Disclosure { .. }, _) => "pc.policy.selective-disclosure",
        }
    }

    pub fn validate(&self, facts: &[FactReference]) -> RuntimeResult<()> {
        validate_conditions(&self.conditions, facts)?;
        if !uuid_v7(&self.policy_id)
            || !self.selector.validate()
            || !self.subject.validate()
            || !label(&self.purpose)
            || !unique_labels(&self.required_roles, 64)
            || !unique_labels(&self.fields, 64)
            || self.dimensions.len() > 5
            || self.dimensions.iter().collect::<BTreeSet<_>>().len() != self.dimensions.len()
            || (self.effect == RpcEffect::Allow
                && (self.required_roles.is_empty() || self.dimensions.is_empty()))
            || (self.mode == VisibilityMode::Dynamic && self.conditions.is_empty())
            || (matches!(self.selector, VisibilitySelector::Receipt { .. })
                && !self.fields.is_empty())
            || (!matches!(self.selector, VisibilitySelector::Receipt { .. })
                && self.effect == RpcEffect::Allow
                && self.dimensions.contains(&VisibilityDimension::Payload)
                && self.fields.is_empty())
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

pub fn validate_policies(
    policies: &[VisibilityPolicy],
    facts: &[FactReference],
    modules: &BTreeSet<&str>,
) -> Result<(), String> {
    if policies.len() > 256 {
        return Err("visibility policy bound rejected".into());
    }
    let mut ids = BTreeSet::new();
    for policy in policies {
        policy
            .validate(facts)
            .map_err(|_| "visibility policy rejected")?;
        if !ids.insert(&policy.policy_id)
            || !modules.contains(policy.module_id())
            || (policy.mode == VisibilityMode::Dynamic
                && matches!(policy.selector, VisibilitySelector::Event { .. })
                && (!modules.contains("pc.policy.dynamic-event-ordering")
                    || !modules.contains("pc.policy.event-visibility")))
            || policy.conditions.iter().any(|condition| {
                matches!(condition, FactCondition::Relationship { .. })
                    && !modules.contains(crate::fact_condition::RELATIONSHIP_MODULE)
            })
        {
            return Err("visibility policy module or duplicate rejected".into());
        }
    }
    Ok(())
}

/// An owner-resolved request; never accepted as a public current-authority claim.
pub struct VisibilityRequest<'a> {
    pub selector: &'a VisibilitySelector,
    pub mode: VisibilityMode,
    pub subject: &'a VisibilitySubject,
    pub purpose: &'a str,
    pub roles: &'a [String],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VisibilityDecision {
    pub dimensions: BTreeSet<VisibilityDimension>,
    pub fields: BTreeSet<String>,
    pub whole_receipt: bool,
}

/// Intersect every applicable contribution. A role or required Fact failure is
/// denial, not a reason to skip a restrictive rule. Fact checks remain with the
/// existing verified local reader; no external observation can grant here.
pub fn evaluate_visibility(
    policies: &[VisibilityPolicy],
    required_facts: &[FactReference],
    request: &VisibilityRequest<'_>,
    condition_allows: impl Fn(&FactCondition) -> bool,
) -> RuntimeResult<VisibilityDecision> {
    let mut result: Option<VisibilityDecision> = None;
    let mut static_matched = false;
    let mut dynamic_matched = false;
    let mut dynamic_required = request.mode == VisibilityMode::Dynamic;
    for policy in policies {
        policy.validate(required_facts)?;
        if policy.selector != *request.selector {
            continue;
        }
        dynamic_required |= policy.mode == VisibilityMode::Dynamic;
        if policy.subject != *request.subject || policy.purpose != request.purpose {
            continue;
        }
        if policy.effect == RpcEffect::Deny
            || !policy
                .required_roles
                .iter()
                .all(|role| request.roles.contains(role))
            || !policy.conditions.iter().all(&condition_allows)
        {
            return Err(RuntimeError::Denied);
        }
        match policy.mode {
            VisibilityMode::Static => static_matched = true,
            VisibilityMode::Dynamic => dynamic_matched = true,
        }
        let dimensions = policy.dimensions.iter().copied().collect();
        let fields = policy.fields.iter().cloned().collect();
        if let Some(result) = &mut result {
            result.dimensions = result
                .dimensions
                .intersection(&dimensions)
                .copied()
                .collect();
            result.fields = result.fields.intersection(&fields).cloned().collect();
        } else {
            result = Some(VisibilityDecision {
                dimensions,
                fields,
                whole_receipt: false,
            });
        }
    }
    if !static_matched || (dynamic_required && !dynamic_matched) {
        return Err(RuntimeError::Denied);
    }
    let mut result = result.ok_or(RuntimeError::Denied)?;
    if matches!(request.selector, VisibilitySelector::Receipt { .. }) {
        result.whole_receipt = [
            VisibilityDimension::Existence,
            VisibilityDimension::Metadata,
            VisibilityDimension::Payload,
        ]
        .iter()
        .all(|dimension| result.dimensions.contains(dimension));
        if !result.whole_receipt {
            return Err(RuntimeError::Denied);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
