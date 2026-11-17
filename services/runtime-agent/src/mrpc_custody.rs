//! MRPC profile admission inside the target's exact capsule artifact closure.
//! Routing snapshots, certifications and local eligibility still require their
//! own owners; this profile cannot supply those owners' successful decisions.
use crate::{ArtifactAdmission, ArtifactComponent, RuntimeCapsule};
use openpc_multi_rpc::runtime_profile::MrpcRuntimeProfile;
use pc_policy_core::runtime_wire::Verifier;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Bootstrap resolves these identities from the active signed authorities.
pub struct MrpcProfileTrust {
    pub profile_id: String,
    pub signer_id: String,
    pub capability_registry_digest: Digest,
    pub endpoint_role_rules_digest: Digest,
    pub coherence_rules_digest: Digest,
}
pub struct MrpcProfileAdmission {
    verifier: Verifier,
    trust: MrpcProfileTrust,
    remaining: Arc<dyn ArtifactAdmission>,
}
impl MrpcProfileAdmission {
    pub fn new(
        verifier: Verifier,
        trust: MrpcProfileTrust,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        crate::capsule::text(&trust.profile_id, 160)?;
        crate::capsule::text(&trust.signer_id, 160)?;
        Ok(Self {
            verifier,
            trust,
            remaining,
        })
    }
    pub fn admit_profile(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(MrpcRuntimeProfile, Digest)> {
        let mut candidates = capsule
            .artifact_components
            .iter()
            .filter(|c| c.schema_id == 2014);
        let component = candidates.next().ok_or(RuntimeError::InvalidInput)?;
        if candidates.next().is_some()
            || !component.required
            || component.schema_version != 3
            || component.semantic_digest != capsule.mrpc_runtime_profile_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bytes = artifacts
            .get(&component.content_digest)
            .ok_or(RuntimeError::InvalidInput)?;
        if bytes.len() as u64 != component.size_bytes
            || Digest::of(bytes) != component.content_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
        let profile = MrpcRuntimeProfile::verify(&self.verifier, bytes)?;
        if profile.semantic_digest()? != component.semantic_digest
            || profile.profile_id != self.trust.profile_id
            || profile.signer_id != self.trust.signer_id
            || profile.capability_registry_digest != self.trust.capability_registry_digest
            || profile.endpoint_role_rules_digest != self.trust.endpoint_role_rules_digest
            || profile.coherence_rules_digest != self.trust.coherence_rules_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok((profile, component.content_digest.clone()))
    }
}
impl ArtifactAdmission for MrpcProfileAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.schema_id == 2014 {
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
        if component.schema_id == 2014 {
            self.admit_profile(capsule, artifacts)
                .map(|(_, digest)| BTreeSet::from([digest]))
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}
