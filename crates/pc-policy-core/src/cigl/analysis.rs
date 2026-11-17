//! Sanitized method analysis for the public review owner. Structural validity
//! is not provenance, review completion, activation or invocation permission.
use super::{CallKind, TraceLimits};
use crate::invocation::{ValidatedInvocationPolicy, resolve_nested_contract_invocation};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod review;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnresolvedReason {
    UnregisteredMethod,
    AmbiguousMethod,
    RegistrationMismatch,
    MissingSelector,
    UnsupportedCallKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MethodResolution {
    #[serde(rename_all = "camelCase")]
    Registered {
        contract_method_policy_id: String,
        runtime_binding_id: String,
    },
    Unresolved {
        reason: UnresolvedReason,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzedInteraction {
    pub ordinal: u16,
    pub parent: u16,
    pub depth: u16,
    pub call_kind: CallKind,
    pub caller: [u8; 20],
    pub target: [u8; 20],
    pub execution_address: [u8; 20],
    pub selector: Option<[u8; 4]>,
    pub input_digest: Digest,
    pub message_value_digest: Digest,
    pub code_digest: Digest,
    pub failed: bool,
    pub resolution: MethodResolution,
}
impl AnalyzedInteraction {
    pub fn action_digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:cigl-analysis-action:v1", self)).map(Digest::of)
    }
}

/// An offline, non-granting document. Only the live acquisition owner can
/// establish its provenance; clients may never upload this as trace evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodAnalysisV1 {
    pub schema_version: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub root_contract_method_policy_id: String,
    pub root_runtime_binding_id: String,
    pub configuration_digest: Digest,
    pub policy_artifact_digest: Digest,
    pub policy_generation_digest: Digest,
    pub request_digest: Digest,
    pub authority_digest: Digest,
    pub observation_digest: Digest,
    pub observation_context_digest: Digest,
    pub route_witness_set_digest: Digest,
    pub anchor_digest: Digest,
    pub limits: TraceLimits,
    pub interactions: Vec<AnalyzedInteraction>,
}
impl MethodAnalysisV1 {
    pub fn validate(&self) -> RuntimeResult<()> {
        self.limits.validate()?;
        if self.schema_version != "1.0"
            || [
                &self.participant_id,
                &self.privacy_domain_id,
                &self.root_contract_method_policy_id,
                &self.root_runtime_binding_id,
            ]
            .into_iter()
            .any(|id| !crate::semantics::uuid_v7(id))
            || self.workload_id.is_empty()
            || self.workload_id.len() > 256
            || !self.workload_id.bytes().all(|b| b.is_ascii_graphic())
            || self.interactions.len() >= usize::from(self.limits.max_frames)
            || [
                &self.configuration_digest,
                &self.policy_artifact_digest,
                &self.policy_generation_digest,
                &self.request_digest,
                &self.authority_digest,
                &self.observation_digest,
                &self.observation_context_digest,
                &self.route_witness_set_digest,
                &self.anchor_digest,
            ]
            .into_iter()
            .any(|digest| *digest == Digest::of([]))
        {
            return Err(RuntimeError::InvalidInput);
        }
        for (index, interaction) in self.interactions.iter().enumerate() {
            let parent_depth = if interaction.parent == 0 {
                Some(0)
            } else {
                self.interactions
                    .get(usize::from(interaction.parent) - 1)
                    .map(|p| p.depth)
            };
            if usize::from(interaction.ordinal) != index + 1
                || interaction.parent >= interaction.ordinal
                || interaction.depth == 0
                || interaction.depth > self.limits.max_depth
                || parent_depth.and_then(|d| d.checked_add(1)) != Some(interaction.depth)
            {
                return Err(RuntimeError::InvalidInput);
            }
            if let MethodResolution::Registered {
                contract_method_policy_id,
                runtime_binding_id,
            } = &interaction.resolution
                && (!crate::semantics::uuid_v7(contract_method_policy_id)
                    || !crate::semantics::uuid_v7(runtime_binding_id)
                    || interaction.selector.is_none()
                    || !matches!(
                        interaction.call_kind,
                        CallKind::Call
                            | CallKind::Staticcall
                            | CallKind::Delegatecall
                            | CallKind::Callcode
                    ))
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.validate()?;
        canonical_bytes(&("openpc:cigl-method-analysis:v1", self)).map(Digest::of)
    }
    pub fn unresolved_count(&self) -> usize {
        self.interactions
            .iter()
            .filter(|i| matches!(i.resolution, MethodResolution::Unresolved { .. }))
            .count()
    }
}

/// Index existing admitted policies, without inventing method authority. Only
/// the root's exact tenant/workload/generation/chain environment participates.
pub struct MethodAnalysisIndex<'a> {
    methods: BTreeMap<([u8; 20], [u8; 4]), Vec<&'a ValidatedInvocationPolicy>>,
}
impl<'a> MethodAnalysisIndex<'a> {
    pub fn new(
        root: &ValidatedInvocationPolicy,
        policies: &'a [ValidatedInvocationPolicy],
    ) -> RuntimeResult<Self> {
        root.configured_identity()?;
        let source = root.artifact();
        let mut methods: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for policy in policies {
            let candidate = policy.artifact();
            if candidate.tenant_id == source.tenant_id
                && candidate.privacy_domain_id == source.privacy_domain_id
                && candidate.workload_id == source.workload_id
                && candidate.policy_generation_digest == source.policy_generation_digest
                && candidate.policy_artifact_digest == source.policy_artifact_digest
                && candidate.chain_id == source.chain_id
                && candidate.network_id == source.network_id
                && candidate.genesis_digest == source.genesis_digest
                && policy.configured_identity().is_ok()
            {
                methods
                    .entry((policy.exposed_contract_address(), policy.selector()))
                    .or_default()
                    .push(policy);
            }
        }
        Ok(Self { methods })
    }
    pub fn resolve(
        &self,
        kind: CallKind,
        target: [u8; 20],
        input: &[u8],
        code_at: impl Fn(&[u8; 20]) -> RuntimeResult<Digest>,
    ) -> MethodResolution {
        let unresolved = |reason| MethodResolution::Unresolved { reason };
        if !matches!(
            kind,
            CallKind::Call | CallKind::Staticcall | CallKind::Delegatecall | CallKind::Callcode
        ) {
            return unresolved(UnresolvedReason::UnsupportedCallKind);
        }
        let Some(selector) = input.get(..4).and_then(|v| v.try_into().ok()) else {
            return unresolved(UnresolvedReason::MissingSelector);
        };
        let Some(candidates) = self.methods.get(&(target, selector)) else {
            return unresolved(UnresolvedReason::UnregisteredMethod);
        };
        if candidates.len() != 1 {
            return unresolved(UnresolvedReason::AmbiguousMethod);
        }
        let method = candidates[0];
        let Ok(identity) = method.configured_identity() else {
            return unresolved(UnresolvedReason::RegistrationMismatch);
        };
        if resolve_nested_contract_invocation(
            std::slice::from_ref(method),
            identity.contract_method_policy_id(),
            target,
            input.to_vec(),
            code_at,
        )
        .is_err()
        {
            return unresolved(UnresolvedReason::RegistrationMismatch);
        }
        MethodResolution::Registered {
            contract_method_policy_id: identity.contract_method_policy_id().into(),
            runtime_binding_id: identity.runtime_binding_id().into(),
        }
    }
}
