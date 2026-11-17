use std::collections::BTreeSet;

use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::Serialize;

use super::{AdmittedDeploymentPolicy, ConfiguredDeploymentPolicy};
use crate::invocation::{
    ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1, ActiveInvocationScope,
    decode_active_invocation_configuration, decode_active_invocation_policy_generation,
};

pub(crate) fn validate_configuration(policies: &[ConfiguredDeploymentPolicy]) -> RuntimeResult<()> {
    if policies.len() > 256 {
        return Err(RuntimeError::InvalidInput);
    }
    let mut ids = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    for configured in policies {
        let publication = &configured.publication;
        publication
            .validate()
            .map_err(|_| RuntimeError::InvalidInput)?;
        if configured.workload_id.is_empty()
            || configured.workload_id.len() > 256
            || !ids.insert(&publication.deployment_policy_id)
            || !profiles.insert((
                &publication.participant_id,
                &publication.privacy_domain_id,
                &publication.definition.profile_id,
                &publication.definition.profile_version,
            ))
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(())
}

pub(crate) fn validate_selection(
    configuration: &ActiveInvocationConfigurationV1,
    generation: &ActiveInvocationPolicyGenerationV1,
) -> RuntimeResult<()> {
    validate_configuration(&configuration.deployment_policies)?;
    if generation.deployment_policies.len() != configuration.deployment_policies.len() {
        return Err(RuntimeError::InvalidInput);
    }
    let mut selected = BTreeSet::new();
    for reference in &generation.deployment_policies {
        reference
            .validate()
            .map_err(|_| RuntimeError::InvalidInput)?;
        if !selected.insert(&reference.deployment_policy_id)
            || !configuration.deployment_policies.iter().any(|configured| {
                configured.publication.deployment_policy_id == reference.deployment_policy_id
                    && configured.publication.definition_digest == reference.definition_digest
            })
            || configuration
                .assets
                .iter()
                .any(|asset| asset.asset_id == reference.deployment_policy_id)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(())
}

/// Exact installed policy data, never a capability to prepare or submit. Live
/// identity, policy, provider, fact, approval and step-up fences remain mandatory.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatedDeploymentPolicy {
    publication: AdmittedDeploymentPolicy,
    workload_id: String,
    policy_generation_digest: Digest,
    configuration_digest: Digest,
    policy_artifact_digest: Digest,
    rpc_policies: Vec<crate::rpc_policy::RpcSurfacePolicy>,
}

impl ValidatedDeploymentPolicy {
    pub fn load_active(
        configuration_bytes: &[u8],
        configuration_digest: &Digest,
        policy_bytes: &[u8],
        policy_artifact_digest: &Digest,
        scope: &ActiveInvocationScope<'_>,
    ) -> RuntimeResult<Vec<Self>> {
        if scope.tenant_id.is_empty()
            || scope.privacy_domain_id.is_empty()
            || scope.workload_id.is_empty()
            || *scope.policy_generation_digest == Digest::of([])
        {
            return Err(RuntimeError::InvalidInput);
        }
        let configuration =
            decode_active_invocation_configuration(configuration_bytes, configuration_digest)?;
        let generation =
            decode_active_invocation_policy_generation(policy_bytes, policy_artifact_digest)?;
        if generation.schema_version != "1.0" {
            return Err(RuntimeError::InvalidInput);
        }
        validate_selection(&configuration, &generation)?;
        configuration
            .deployment_policies
            .into_iter()
            .map(|configured| {
                if configured.workload_id != scope.workload_id
                    || configured.publication.participant_id != scope.tenant_id
                    || configured.publication.privacy_domain_id != scope.privacy_domain_id
                {
                    return Err(RuntimeError::InvalidAuthorization);
                }
                Ok(Self {
                    publication: configured.publication,
                    workload_id: configured.workload_id,
                    policy_generation_digest: scope.policy_generation_digest.clone(),
                    configuration_digest: configuration_digest.clone(),
                    policy_artifact_digest: policy_artifact_digest.clone(),
                    rpc_policies: generation.rpc_policies.clone(),
                })
            })
            .collect()
    }

    pub fn publication(&self) -> &AdmittedDeploymentPolicy {
        &self.publication
    }
    /// Evaluate the installed deployment and RPC families against the real
    /// workload grant. Signed transaction/preparation/custody and live provider
    /// evidence are joined by the runtime owner before this decision can send.
    pub fn evaluate(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
        authorization: &crate::invocation::ValidatedInvocationAuthorization,
        active_generation: &Digest,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        request.validate_digest()?;
        let deployment = request.deployment.as_ref().ok_or(RuntimeError::Denied)?;
        let actor = authorization.facts();
        let definition = &self.publication.definition;
        if request.invocation.is_some()
            || request.class != pc_runtime_types::RequestClass::Write
            || request.method != "eth_sendRawTransaction"
            || deployment.deployment_policy_id != self.publication.deployment_policy_id
            || self.policy_generation_digest != *active_generation
            || actor.participant_id != self.publication.participant_id
            || actor.privacy_domain_id != self.publication.privacy_domain_id
            || actor.workload_id != self.workload_id
            || !self.publication_is_unexpired(now_ms)
            || now_ms < request.received_at_ms
            || now_ms >= request.deadline_at_ms
            || definition.approval_requirement != "NONE"
            || definition.webauthn_required
            || actor.approval.is_some()
            || actor.webauthn.is_some()
            || definition
                .required_roles
                .iter()
                .any(|role| !actor.roles.contains(role))
        {
            return Err(RuntimeError::Denied);
        }
        let mut matched = false;
        for policy in &self.rpc_policies {
            if policy.participant_id != actor.participant_id
                || policy.privacy_domain_id != actor.privacy_domain_id
            {
                return Err(RuntimeError::Denied);
            }
            for rule in policy
                .rules
                .iter()
                .filter(|rule| rule.method == request.method)
            {
                matched = true;
                if rule.effect != crate::rpc_policy::RpcEffect::Allow
                    || rule
                        .required_roles
                        .iter()
                        .any(|role| !actor.roles.contains(role))
                {
                    return Err(RuntimeError::Denied);
                }
            }
        }
        if !matched {
            return Err(RuntimeError::Denied);
        }
        Ok(())
    }
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    pub fn policy_generation_digest(&self) -> &Digest {
        &self.policy_generation_digest
    }
    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }
    pub fn policy_artifact_digest(&self) -> &Digest {
        &self.policy_artifact_digest
    }
    pub fn publication_is_unexpired(&self, now_ms: u64) -> bool {
        self.publication
            .definition
            .expires_at_ms()
            .is_ok_and(|expiry| now_ms < expiry)
    }
}
