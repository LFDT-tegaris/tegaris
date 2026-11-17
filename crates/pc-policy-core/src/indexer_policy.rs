//! Dedicated indexer policy meaning, shared by authoring and evaluation.
//! These rules only narrow an independently authorized workload request. A
//! successful contribution is not a grant, live-source proof or dispatch token.
use std::collections::BTreeSet;

use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

use crate::{
    invocation::ValidatedInvocationAuthorization,
    pc_cbor_1,
    rpc_policy::{RpcEffect, RpcSurfacePolicy},
    semantics::{digest, uuid_v7},
};

mod compilation;
mod simulation;
pub use compilation::{IndexerCompilationInput, compile_indexer_sources};
pub(crate) use compilation::{attach_indexer_assets, configuration_context, validate_selection};
pub use simulation::{
    IndexerSimulationInput, IndexerSimulationRequest, WorkloadPolicyPrediction,
    evaluate_indexer_simulation,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndexerDataClass {
    ExternalObservation,
    EventLog,
    StateCall,
    Receipt,
    BlockHeader,
    FullBlockTransactions,
}

impl IndexerDataClass {
    pub fn data_class(self) -> &'static str {
        match self {
            Self::ExternalObservation => "EXTERNAL_OBSERVATION",
            Self::EventLog => "EVENT_LOG",
            Self::StateCall => "STATE_CALL",
            Self::Receipt => "RECEIPT",
            Self::BlockHeader => "BLOCK_HEADER",
            Self::FullBlockTransactions => "FULL_BLOCK_TRANSACTIONS",
        }
    }

    pub fn for_profile_method(method: &str) -> Option<Self> {
        Some(match method {
            "acquireObservation" => Self::ExternalObservation,
            "eth_getLogs" => Self::EventLog,
            "eth_call" => Self::StateCall,
            "eth_getTransactionReceipt" => Self::Receipt,
            "eth_getBlockByNumber(false)" => Self::BlockHeader,
            "eth_getBlockByNumber(true)" => Self::FullBlockTransactions,
            _ => return None,
        })
    }

    /// Exact registered profile method. Header and complete-block permission
    /// remain distinct despite sharing a JSON-RPC transport method name.
    pub fn profile_method(self) -> &'static str {
        match self {
            Self::ExternalObservation => "acquireObservation",
            Self::EventLog => "eth_getLogs",
            Self::StateCall => "eth_call",
            Self::Receipt => "eth_getTransactionReceipt",
            Self::BlockHeader => "eth_getBlockByNumber(false)",
            Self::FullBlockTransactions => "eth_getBlockByNumber(true)",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexerDataRule {
    pub data_class: IndexerDataClass,
    pub effect: RpcEffect,
    pub required_roles: Vec<String>,
}

/// Authored immutable requirements. The outer policy version owns review,
/// publication and activation; profile qualification never activates this rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexerPolicy {
    pub schema_version: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub indexer_profile_id: String,
    pub profile_artifact_digest: String,
    pub projection_plan_id: String,
    pub plan_artifact_digest: String,
    /// Exact acquisition configuration, including target and request shape.
    /// The adapter must derive it from the actual governed bytes and dispatch
    /// only the request constructed from those bytes, never a caller's digest.
    pub acquisition_configuration_digest: String,
    pub rpc_policy_digest: String,
    pub range_start: String,
    pub range_end: String,
    pub maximum_range_blocks: String,
    pub maximum_response_bytes: u32,
    pub rules: Vec<IndexerDataRule>,
}

/// Request data only. The trusted acquisition owner resolves all artifact
/// commitments from current published inputs before evaluating this contribution.
pub struct IndexerPolicyRequest<'a> {
    pub indexer_profile_id: &'a str,
    pub profile_artifact_digest: &'a str,
    pub projection_plan_id: &'a str,
    pub plan_artifact_digest: &'a str,
    pub acquisition_configuration_digest: &'a str,
    pub data_class: IndexerDataClass,
    pub range_start: u64,
    pub range_end: u64,
    pub maximum_response_bytes: u32,
}

fn number(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == value)
        .ok_or_else(|| "indexer policy range rejected".into())
}

impl IndexerPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0.0"
            || [
                self.participant_id.as_str(),
                self.privacy_domain_id.as_str(),
                self.indexer_profile_id.as_str(),
                self.projection_plan_id.as_str(),
            ]
            .iter()
            .any(|id| !uuid_v7(id))
            || self
                .workload_id
                .strip_prefix("urn:openpc:workload:")
                .is_none_or(|id| !uuid_v7(id))
            || [
                &self.profile_artifact_digest,
                &self.plan_artifact_digest,
                &self.acquisition_configuration_digest,
                &self.rpc_policy_digest,
            ]
            .iter()
            .any(|value| !digest(value))
            || number(&self.range_start)? == 0
            || number(&self.range_start)? > number(&self.range_end)?
            || number(&self.maximum_range_blocks)? == 0
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > 16 * 1024 * 1024
            || self.rules.is_empty()
            || self.rules.len() > 5
        {
            return Err("indexer policy binding rejected".into());
        }
        let mut classes = BTreeSet::new();
        for rule in &self.rules {
            if !classes.insert(rule.data_class)
                || rule.required_roles.len() > 64
                || (rule.effect == RpcEffect::Allow && rule.required_roles.is_empty())
                || rule.required_roles.iter().any(|role| {
                    role.is_empty()
                        || role.len() > 160
                        || !role.bytes().all(|b| b.is_ascii_graphic())
                })
                || rule.required_roles.iter().collect::<BTreeSet<_>>().len()
                    != rule.required_roles.len()
            {
                return Err("indexer policy rule rejected".into());
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        Ok(Digest::of(pc_cbor_1(self)))
    }
}

/// Intersect every applicable rule. Identity resolves the actor and current
/// grants; the acquisition owner separately holds policy/source/credential and
/// evidence fences and enforces the method's response/disclosure contract.
/// This function performs no I/O and produces no forwarding capability.
pub fn evaluate_indexer_policies(
    policies: &[IndexerPolicy],
    request: &IndexerPolicyRequest<'_>,
    authorization: &ValidatedInvocationAuthorization,
    rpc_policies: &[RpcSurfacePolicy],
) -> RuntimeResult<()> {
    let actor = authorization.facts();
    let mut matched = false;
    let count = request
        .range_end
        .checked_sub(request.range_start)
        .and_then(|n| n.checked_add(1))
        .ok_or(RuntimeError::InvalidInput)?;
    if request.range_start == 0 || request.maximum_response_bytes == 0 {
        return Err(RuntimeError::InvalidInput);
    }
    for policy in policies {
        policy.validate().map_err(|_| RuntimeError::InvalidInput)?;
        if policy.participant_id != actor.participant_id
            || policy.privacy_domain_id != actor.privacy_domain_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if policy.workload_id != actor.workload_id
            || policy.indexer_profile_id != request.indexer_profile_id
            || policy.projection_plan_id != request.projection_plan_id
        {
            continue;
        }
        // Stale rules do not disappear from an active intersection merely
        // because another rule happens to match a newer tuple.
        if policy.profile_artifact_digest != request.profile_artifact_digest
            || policy.plan_artifact_digest != request.plan_artifact_digest
            || policy.acquisition_configuration_digest != request.acquisition_configuration_digest
            || request.range_start
                < number(&policy.range_start).map_err(|_| RuntimeError::InvalidInput)?
            || request.range_end
                > number(&policy.range_end).map_err(|_| RuntimeError::InvalidInput)?
            || count
                > number(&policy.maximum_range_blocks).map_err(|_| RuntimeError::InvalidInput)?
            || request.maximum_response_bytes > policy.maximum_response_bytes
        {
            return Err(RuntimeError::Denied);
        }
        let rule = policy
            .rules
            .iter()
            .find(|rule| rule.data_class == request.data_class)
            .ok_or(RuntimeError::Denied)?;
        let rpc_digest = Digest::parse(&policy.rpc_policy_digest[7..])
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let rpc = RpcSurfacePolicy::resolve(
            rpc_policies,
            &rpc_digest,
            &actor.participant_id,
            &actor.privacy_domain_id,
            request.data_class.profile_method(),
        )
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
        if rule.effect == RpcEffect::Deny
            || !rule
                .required_roles
                .iter()
                .all(|role| actor.roles.contains(role))
            || rpc.effect == RpcEffect::Deny
            || !rpc
                .required_roles
                .iter()
                .all(|role| actor.roles.contains(role))
        {
            return Err(RuntimeError::Denied);
        }
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(RuntimeError::Denied)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod compilation_tests;
