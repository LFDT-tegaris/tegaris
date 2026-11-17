//! Primary 3121 profile admission. Its referenced disclosure, transaction,
//! composition, anchor, fault and budget owners remain distinct consumers;
//! accepting this signed profile does not execute those policies.
use crate::{ArtifactAdmission, ArtifactComponent, RuntimeCapsule};
use pc_policy_core::{invocation_profile::InvocationProfileMaterial, runtime_wire::Verifier};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct InvocationProfileTrust {
    pub profile_id: String,
    pub release: String,
    pub capability_registry_id: String,
    pub request_form_registry_id: String,
    pub error_registry_id: String,
}
pub struct InvocationProfileAdmission {
    verifier: Verifier,
    trust: InvocationProfileTrust,
    remaining: Arc<dyn ArtifactAdmission>,
}
impl InvocationProfileAdmission {
    pub fn new(
        verifier: Verifier,
        trust: InvocationProfileTrust,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        for value in [
            &trust.profile_id,
            &trust.release,
            &trust.capability_registry_id,
            &trust.request_form_registry_id,
            &trust.error_registry_id,
        ] {
            crate::capsule::text(value, 160)?;
        }
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
    ) -> RuntimeResult<(InvocationProfileMaterial, Digest)> {
        let mut candidates = capsule
            .artifact_components
            .iter()
            .filter(|c| c.schema_id == 3121);
        let component = candidates.next().ok_or(RuntimeError::InvalidInput)?;
        if candidates.next().is_some()
            || !component.required
            || component.schema_version != 2
            || component.semantic_digest != capsule.rpc_invocation_profile_digest
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
        let profile = InvocationProfileMaterial::verify(&self.verifier, bytes)?;
        if profile.semantic_digest()? != component.semantic_digest
            || profile.profile_id != self.trust.profile_id
            || profile.release != self.trust.release
            || profile.capability_registry_id != self.trust.capability_registry_id
            || profile.request_form_registry_id != self.trust.request_form_registry_id
            || profile.error_registry_id != self.trust.error_registry_id
            || profile.capability_registry_digest != capsule.capability_registry_digest
            || profile.request_form_registry_digest != capsule.request_form_registry_digest
            || profile.error_registry_digest != capsule.error_registry_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok((profile, component.content_digest.clone()))
    }
}
impl ArtifactAdmission for InvocationProfileAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.schema_id == 3121 {
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
        if component.schema_id == 3121 {
            self.admit_profile(capsule, artifacts)
                .map(|(_, content)| BTreeSet::from([content]))
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use pc_policy_core::{
        pc_cbor_1,
        runtime_wire::{
            Signer,
            fields::{digest, map, text, uint},
        },
    };

    struct RejectOther;
    impl ArtifactAdmission for RejectOther {
        fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
            Err(RuntimeError::InvalidInput)
        }
    }

    #[test]
    fn profile_admission_binds_primary_schema_and_all_three_active_registries() {
        // Independent primary 3121 field categories. Values are fixture data,
        // not an accepted deployment profile or authority grant.
        let payload = map((0..=20)
            .map(|key| {
                let value = match key {
                    1 => uint(2),
                    0 | 2 | 3 | 5 | 7 | 20 => text(&format!("fixture-{key}"), 160).unwrap(),
                    9..=12 | 18 => {
                        Value::Array(vec![text(&format!("fixture-{key}"), 256).unwrap()])
                    }
                    _ => digest(&Digest::of(format!("fixture-{key}"))).unwrap(),
                };
                (key, value)
            })
            .collect());
        let profile = InvocationProfileMaterial::decode(&pc_cbor_1(&payload)).unwrap();
        let signer = Signer::from_secret_bytes([72; 32]).unwrap();
        let admission = InvocationProfileAdmission::new(
            signer.verifier(),
            InvocationProfileTrust {
                profile_id: profile.profile_id.clone(),
                release: profile.release.clone(),
                capability_registry_id: profile.capability_registry_id.clone(),
                request_form_registry_id: profile.request_form_registry_id.clone(),
                error_registry_id: profile.error_registry_id.clone(),
            },
            Arc::new(RejectOther),
        )
        .unwrap();
        let signed = profile.sign(&signer).unwrap();
        let content = Digest::of(&signed);
        let mut capsule = crate::wire_tests::capsule();
        capsule.rpc_invocation_profile_digest = profile.semantic_digest().unwrap();
        capsule.capability_registry_digest = profile.capability_registry_digest.clone();
        capsule.request_form_registry_digest = profile.request_form_registry_digest.clone();
        capsule.error_registry_digest = profile.error_registry_digest.clone();
        capsule.artifact_components = vec![ArtifactComponent {
            component_id: "invocation-profile".into(),
            component_type: "invocation-profile".into(),
            content_digest: content.clone(),
            semantic_digest: profile.semantic_digest().unwrap(),
            schema_id: 3121,
            schema_version: 2,
            size_bytes: signed.len() as u64,
            required: true,
        }];
        let artifacts = BTreeMap::from([(content, signed)]);
        assert_eq!(
            admission.admit_profile(&capsule, &artifacts).unwrap().0,
            profile
        );
        for field in 0..=6 {
            let mut changed = capsule.clone();
            match field {
                0 => changed.rpc_invocation_profile_digest = Digest::of(b"other"),
                1 => changed.capability_registry_digest = Digest::of(b"other"),
                2 => changed.request_form_registry_digest = Digest::of(b"other"),
                3 => changed.error_registry_digest = Digest::of(b"other"),
                4 => changed.artifact_components[0].required = false,
                5 => changed.artifact_components[0].schema_version = 3,
                _ => changed
                    .artifact_components
                    .push(changed.artifact_components[0].clone()),
            }
            assert!(
                admission.admit_profile(&changed, &artifacts).is_err(),
                "field {field}"
            );
        }
        let mut changed = artifacts.clone();
        changed.values_mut().next().unwrap().push(0);
        assert!(admission.admit_profile(&capsule, &changed).is_err());
    }
}
