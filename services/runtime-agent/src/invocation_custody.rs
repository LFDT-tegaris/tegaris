//! Typed invocation source admission under primary 1010 and capsule custody.
//! This establishes policy material only; identity, revocation, facts, routing,
//! evidence and runtime guards must still participate in a decision.
use crate::{
    ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireVerifier, WorkloadPeer,
    authority_artifact::AuthoritySourceBinding,
};
use pc_policy_core::deployment_policy::ValidatedDeploymentPolicy;
use pc_policy_core::invocation::{
    ActiveInvocationScope, ValidatedInvocationPolicy, active_invocation_workload,
    decode_active_invocation_policy_generation,
};
use pc_policy_core::semantics::{FactReference, validate_fact_references};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg(test)]
#[path = "deployment_custody_tests.rs"]
mod deployment_tests;

pub struct InvocationArtifactAdmission {
    verifier: RuntimeWireVerifier,
    participant_id: String,
    privacy_domain_id: String,
    configuration: AuthoritySourceBinding,
    policy: AuthoritySourceBinding,
    remaining: Arc<dyn ArtifactAdmission>,
}
pub struct InstalledInvocationPolicies {
    participant_id: String,
    privacy_domain_id: String,
    workload_id: String,
    capsule_digest: Digest,
    policy_bundle_digest: Digest,
    policies: Vec<ValidatedInvocationPolicy>,
    deployment_policies: Vec<ValidatedDeploymentPolicy>,
    pub(crate) cigl_settings: pc_policy_core::cigl::settings::InstalledCiglSettings,
    pub(crate) cigl_profiles: Vec<pc_policy_core::cigl::profile::ValidatedMethodProfile>,
    required_facts: Vec<FactReference>,
    indexer_policies: Vec<pc_policy_core::indexer_policy::IndexerPolicy>,
    pub(crate) fact_conditions: Vec<pc_policy_core::fact_condition::FactCondition>,
    pub(crate) rpc_policies: Vec<pc_policy_core::rpc_policy::RpcSurfacePolicy>,
    pub(crate) visibility_policies: Vec<pc_policy_core::visibility_policy::VisibilityPolicy>,
    pub(crate) visibility_resources:
        Vec<pc_policy_core::visibility_policy::AdmittedVisibilityResource>,
}
impl InstalledInvocationPolicies {
    /// Project only after normal signed invocation admission. Source and
    /// invocation custody retain the same scope, generation and dependencies.
    pub(crate) fn into_indexer_policies(self) -> crate::indexer_custody::InstalledIndexerPolicies {
        crate::indexer_custody::InstalledIndexerPolicies {
            participant_id: self.participant_id,
            privacy_domain_id: self.privacy_domain_id,
            workload_id: self.workload_id,
            capsule_digest: self.capsule_digest,
            policy_generation_digest: self.policy_bundle_digest,
            policies: self.indexer_policies,
            visibility_policies: self.visibility_policies,
            rpc_policies: self.rpc_policies,
            required_facts: self.required_facts,
        }
    }

    pub fn deployment_policies_for(
        &self,
        peer: &WorkloadPeer,
        privacy_domain_id: &str,
        capsule: &RuntimeCapsule,
    ) -> RuntimeResult<&[ValidatedDeploymentPolicy]> {
        self.policies_for(peer, privacy_domain_id, capsule)?;
        Ok(&self.deployment_policies)
    }
    pub fn required_facts_for(
        &self,
        peer: &WorkloadPeer,
        privacy_domain_id: &str,
        capsule: &RuntimeCapsule,
    ) -> RuntimeResult<&[FactReference]> {
        self.policies_for(peer, privacy_domain_id, capsule)?;
        if !self.required_facts.is_empty() {
            validate_fact_references(&self.required_facts)
                .map_err(|_| RuntimeError::InvalidAuthorization)?;
        }
        Ok(&self.required_facts)
    }
    /// An authenticated workload can only select its own compiled scope.
    pub fn policies_for(
        &self,
        peer: &WorkloadPeer,
        privacy_domain_id: &str,
        capsule: &RuntimeCapsule,
    ) -> RuntimeResult<&[ValidatedInvocationPolicy]> {
        if peer.participant_id() != self.participant_id
            || peer.workload_id() != self.workload_id
            || privacy_domain_id != self.privacy_domain_id
            || capsule.digest()? != self.capsule_digest
            || capsule.policy_bundle_digest != self.policy_bundle_digest
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(&self.policies)
    }
}
impl InvocationArtifactAdmission {
    pub fn source_scope(&self) -> (&str, &str) {
        (&self.participant_id, &self.privacy_domain_id)
    }
    /// Borrow exact source bytes from the caller's admitted capsule. Fleet uses
    /// this same owner when compiling an approved live analysis; source headers
    /// and content remain verified against the installed authority bindings.
    pub fn analysis_source_bytes<'a>(
        &self,
        capsule: &'a RuntimeCapsule,
        artifacts: &'a BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(&'a [u8], &'a [u8])> {
        let (_, _, configuration) =
            self.configuration
                .in_capsule(&self.verifier, capsule, artifacts)?;
        let (_, policy, bytes) = self.policy.in_capsule(&self.verifier, capsule, artifacts)?;
        if policy.source_content_sha256 != capsule.semantic_model_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok((configuration, bytes))
    }
    /// Retain only the two verified sources and their signed headers. Other
    /// custody artifacts can be large and are not inputs to profile compilation.
    pub fn analysis_source_snapshot(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeMap<Digest, Vec<u8>>> {
        let mut selected = BTreeMap::new();
        for (binding, is_policy) in [(&self.configuration, false), (&self.policy, true)] {
            let (component, header, source) =
                binding.in_capsule(&self.verifier, capsule, artifacts)?;
            if is_policy && header.source_content_sha256 != capsule.semantic_model_digest {
                return Err(RuntimeError::InvalidDigest);
            }
            selected.insert(header.source_content_sha256, source.to_vec());
            selected.insert(
                component.content_digest.clone(),
                artifacts
                    .get(&component.content_digest)
                    .ok_or(RuntimeError::InvalidInput)?
                    .clone(),
            );
        }
        Ok(selected)
    }
    pub fn admit_provider_profile(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        provider_id: &str,
        expected_digest: &Digest,
    ) -> RuntimeResult<Vec<u8>> {
        let (_, source, bytes) =
            self.configuration
                .in_capsule(&self.verifier, capsule, artifacts)?;
        pc_policy_core::invocation::load_active_configuration_artifact(
            bytes,
            &source.source_content_sha256,
            provider_id,
            pc_policy_core::invocation::ConfigurationArtifactKind::ProviderProfile,
            expected_digest,
        )
    }
    pub fn new(
        verifier: RuntimeWireVerifier,
        participant_id: String,
        privacy_domain_id: String,
        configuration: AuthoritySourceBinding,
        policy: AuthoritySourceBinding,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        if participant_id.is_empty()
            || privacy_domain_id.is_empty()
            || configuration.artifact_id == policy.artifact_id
            || configuration.source_media_type != "application/cbor"
            || policy.source_media_type != "application/cbor"
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            verifier,
            participant_id,
            privacy_domain_id,
            configuration,
            policy,
            remaining,
        })
    }
    pub fn admit_policies(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(InstalledInvocationPolicies, BTreeSet<Digest>)> {
        let (configuration_component, configuration, configuration_bytes) = self
            .configuration
            .in_capsule(&self.verifier, capsule, artifacts)
            .inspect_err(|error| {
                eprintln!(
                    "runtime_invocation_admission stage=configuration_binding reason={error:?}"
                )
            })?;
        let (policy_component, policy, policy_bytes) = self
            .policy
            .in_capsule(&self.verifier, capsule, artifacts)
            .inspect_err(|error| {
                eprintln!("runtime_invocation_admission stage=policy_binding reason={error:?}")
            })?;
        if policy.source_content_sha256 != capsule.semantic_model_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        let workload_id = active_invocation_workload(
            configuration_bytes,
            &configuration.source_content_sha256,
            &self.participant_id,
            &self.privacy_domain_id,
        )
        .inspect_err(|error| {
            eprintln!("runtime_invocation_admission stage=workload_scope reason={error:?}")
        })?;
        // The active signed policy bundle is the target-local generation
        // identity. Source byte identity remains distinct from that identity.
        let policies = ValidatedInvocationPolicy::load_active(
            configuration_bytes,
            &configuration.source_content_sha256,
            policy_bytes,
            &policy.source_content_sha256,
            &ActiveInvocationScope {
                policy_generation_digest: &capsule.policy_bundle_digest,
                tenant_id: &self.participant_id,
                privacy_domain_id: &self.privacy_domain_id,
                workload_id: &workload_id,
            },
        )
        .inspect_err(|error| {
            eprintln!("runtime_invocation_admission stage=active_policy reason={error:?}")
        })?;
        let generation =
            decode_active_invocation_policy_generation(policy_bytes, &policy.source_content_sha256)
                .inspect_err(|error| {
                    eprintln!("runtime_invocation_admission stage=generation reason={error:?}")
                })?;
        let visibility_resources =
            pc_policy_core::invocation::decode_active_invocation_configuration(
                configuration_bytes,
                &configuration.source_content_sha256,
            )?
            .visibility_resources;
        let cigl_settings = pc_policy_core::cigl::settings::InstalledCiglSettings::load(
            configuration_bytes,
            &configuration.source_content_sha256,
            &self.participant_id,
            &self.privacy_domain_id,
        )
        .inspect_err(|error| {
            eprintln!("runtime_invocation_admission stage=cigl_settings reason={error:?}")
        })?;
        let cigl_profiles = pc_policy_core::cigl::profile::ValidatedMethodProfile::load_active(
            configuration_bytes,
            &configuration.source_content_sha256,
            policy_bytes,
            &policy.source_content_sha256,
            &ActiveInvocationScope {
                policy_generation_digest: &capsule.policy_bundle_digest,
                tenant_id: &self.participant_id,
                privacy_domain_id: &self.privacy_domain_id,
                workload_id: &workload_id,
            },
        )
        .inspect_err(|error| {
            eprintln!("runtime_invocation_admission stage=cigl_profiles reason={error:?}")
        })?;
        let deployment_policies = if generation.deployment_policies.is_empty() {
            Vec::new()
        } else {
            ValidatedDeploymentPolicy::load_active(
                configuration_bytes,
                &configuration.source_content_sha256,
                policy_bytes,
                &policy.source_content_sha256,
                &ActiveInvocationScope {
                    policy_generation_digest: &capsule.policy_bundle_digest,
                    tenant_id: &self.participant_id,
                    privacy_domain_id: &self.privacy_domain_id,
                    workload_id: &workload_id,
                },
            )?
        };
        let closure = BTreeSet::from([
            configuration_component.content_digest.clone(),
            configuration.source_content_sha256,
            policy_component.content_digest.clone(),
            policy.source_content_sha256,
        ]);
        Ok((
            InstalledInvocationPolicies {
                participant_id: self.participant_id.clone(),
                privacy_domain_id: self.privacy_domain_id.clone(),
                workload_id,
                capsule_digest: capsule.digest()?,
                policy_bundle_digest: capsule.policy_bundle_digest.clone(),
                policies,
                deployment_policies,
                cigl_profiles,
                cigl_settings,
                required_facts: generation.required_facts,
                indexer_policies: generation.indexer_policies,
                fact_conditions: generation.fact_conditions,
                rpc_policies: generation.rpc_policies,
                visibility_policies: generation.visibility_policies,
                visibility_resources,
            },
            closure,
        ))
    }
}
impl ArtifactAdmission for InvocationArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.component_id == self.configuration.artifact_id
            || component.component_id == self.policy.artifact_id
        {
            return Err(RuntimeError::InvalidInput);
        }
        self.remaining.validate(component, bytes)
    }
    fn validate_component_in_bundle(
        &self,
        capsule: &RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if component.component_id == self.configuration.artifact_id
            || component.component_id == self.policy.artifact_id
        {
            self.admit_policies(capsule, artifacts)
                .map(|(_, closure)| closure)
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}
