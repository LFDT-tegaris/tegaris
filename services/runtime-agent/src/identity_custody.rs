//! Identity's complete artifact closure inside canonical capsule custody.
use crate::{
    ArtifactAdmission, ArtifactComponent, RuntimeCapsule,
    capsule::{field, fields, read_digest},
    identity_state::{InstalledWorkloadIdentities, RuntimeIdentityContext},
};
use openpc_pds::{IdentityAssertionEvidence, IdentityAssertionVerifier, IdentitySnapshotTrust};
use pc_policy_core::pc_cbor_1_semantic_digest;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Identity trust is installed by the target's bootstrap owner. Remaining
/// component types must be admitted by their actual owners; there is no fallback
/// that accepts opaque content merely because its hash matches.
pub struct IdentityArtifactAdmission {
    verifier: IdentityAssertionVerifier,
    context: RuntimeIdentityContext,
    profile_digest: Digest,
    signer_id: String,
    maximum_bytes: usize,
    remaining: Arc<dyn ArtifactAdmission>,
}
fn array(d: &Digest) -> RuntimeResult<[u8; 32]> {
    crate::capsule::digest(d)?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(RuntimeError::InvalidDigest)
}
fn hex(d: [u8; 32]) -> RuntimeResult<Digest> {
    Digest::parse(d.iter().map(|v| format!("{v:02x}")).collect::<String>())
}
impl IdentityArtifactAdmission {
    pub fn new(
        verifier: IdentityAssertionVerifier,
        context: RuntimeIdentityContext,
        profile_digest: Digest,
        signer_id: String,
        maximum_bytes: usize,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        if signer_id.is_empty() || maximum_bytes == 0 || maximum_bytes > 16 * 1024 * 1024 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            verifier,
            context,
            profile_digest,
            signer_id,
            maximum_bytes,
            remaining,
        })
    }

    /// Reconstruct the complete verified identity state. Admission is checked at
    /// capsule issuance for restart validation; request authorization separately
    /// checks wall time under the active capsule/freshness lease.
    pub fn admit_identity(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(InstalledWorkloadIdentities, BTreeSet<Digest>)> {
        if capsule.target_runtime_id != self.context.target_runtime_id {
            return Err(RuntimeError::TargetIdentity);
        }
        let mut total = 0usize;
        for bytes in artifacts.values() {
            total = total
                .checked_add(bytes.len())
                .ok_or(RuntimeError::BudgetExhausted)?;
        }
        if total > self.maximum_bytes {
            return Err(RuntimeError::BudgetExhausted);
        }
        let component = |schema| -> RuntimeResult<&ArtifactComponent> {
            let mut matches = capsule
                .artifact_components
                .iter()
                .filter(|c| c.schema_id == schema);
            let c = matches.next().ok_or_else(|| {
                eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"component_missing\",\"schema\":{schema}}}");
                RuntimeError::InvalidInput
            })?;
            if matches.next().is_some() || c.schema_version != 2 || !c.required {
                eprintln!(
                    "{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"component_shape\",\"schema\":{schema}}}"
                );
                return Err(RuntimeError::InvalidInput);
            }
            Ok(c)
        };
        let manifest_component = component(3004)?;
        let profile_component = component(3010)?;
        if manifest_component.semantic_digest != capsule.identity_snapshot_manifest_digest
            || profile_component.semantic_digest != self.profile_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
        let evidence = |c: &ArtifactComponent| {
            let bytes = artifacts
                .get(&c.content_digest)
                .ok_or_else(|| {
                    eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"component_content_missing\",\"schema\":{}}}", c.schema_id);
                    RuntimeError::InvalidInput
                })?;
            if bytes.len() as u64 != c.size_bytes || Digest::of(bytes) != c.content_digest {
                return Err(RuntimeError::InvalidDigest);
            }
            IdentityAssertionEvidence::from_cose_sign1(bytes).inspect_err(|error| {
                eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"component_cose\",\"schema\":{},\"reason\":\"{:?}\"}}", c.schema_id, error);
            })
        };
        let profile = self.verifier.verify_runtime_authority_profile(
            &evidence(profile_component)?,
            &array(&self.profile_digest)?,
            &self.signer_id,
        ).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"profile_verification\",\"reason\":\"{:?}\"}}", error);
        })?;
        let manifest = evidence(manifest_component)?;
        let value = crate::cose::decode(&manifest.payload_cbor, 262_144).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"manifest_cbor\",\"reason\":\"{:?}\"}}", error);
        })?;
        let mf = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8]).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"manifest_fields\",\"reason\":\"{:?}\"}}", error);
        })?;
        let ordered = field(&mf, 5)?.as_array().ok_or_else(|| {
            eprintln!(
                "{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"manifest_shard_index\"}}"
            );
            RuntimeError::InvalidInput
        })?;
        let mut shards_by_semantic = BTreeMap::new();
        // Only source content which is structurally a canonical shard enters the
        // candidate index. Every selected shard is then verified against the
        // signed manifest, exact index, vector and actor count by PDS.
        for (content_digest, bytes) in artifacts {
            if let Ok(value) = crate::cose::decode(bytes, 4 * 1024 * 1024)
                && fields(&value, &[0, 1, 2, 3, 4]).is_ok_and(|f| f.len() == 5)
            {
                let semantic = hex(pc_cbor_1_semantic_digest(3005, 2, &value))?;
                if shards_by_semantic
                    .insert(semantic, (content_digest, bytes))
                    .is_some()
                {
                    eprintln!(
                        "{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"duplicate_shard\"}}"
                    );
                    return Err(RuntimeError::InvalidInput);
                }
            }
        }
        let mut closure = BTreeSet::from([
            manifest_component.content_digest.clone(),
            profile_component.content_digest.clone(),
        ]);
        let mut shards = Vec::new();
        for expected in ordered {
            let (key, bytes) = shards_by_semantic
                .get(&read_digest(expected)?)
                .ok_or_else(|| {
                    eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"shard_missing\"}}");
                    RuntimeError::InvalidInput
                })?;
            if Digest::of(bytes) != **key {
                return Err(RuntimeError::InvalidDigest);
            }
            closure.insert((*key).clone());
            shards.push((*bytes).clone());
        }
        let snapshot = self.verifier.verify_snapshot(
            &manifest,
            &shards,
            &IdentitySnapshotTrust {
                manifest_digest: array(&capsule.identity_snapshot_manifest_digest)?,
                target_scope_digest: self.context.target_scope_digest(),
                release_profile_registry_digest: array(&self.profile_digest)?,
                signer_id: self.signer_id.clone(),
                profiles: vec![profile.clone()],
                maximum_total_bytes: self.maximum_bytes,
            },
            capsule.issued_at_ns,
        ).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"snapshot_verification\",\"reason\":\"{:?}\"}}", error);
        })?;
        if capsule.hard_expiry_ns > snapshot.expires_at_ns() {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        for actor in snapshot.actors() {
            closure.insert(hex(*actor.role_assignment_set_digest())?);
            closure.insert(hex(*actor.participant_envelope_digest())?);
        }
        let identities = InstalledWorkloadIdentities::admit(
            snapshot,
            artifacts,
            self.context.clone(),
            &profile,
        ).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"installed_identities\",\"reason\":\"{:?}\"}}", error);
        })?;
        Ok((identities, closure))
    }
}
impl ArtifactAdmission for IdentityArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if matches!(component.schema_id, 3004 | 3010 | 3005) {
            // These objects only establish authority in a complete bundle.
            return Err(RuntimeError::InvalidInput);
        }
        self.remaining.validate(component, bytes)
    }
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        let (_, mut closure) = self.admit_identity(capsule, artifacts)?;
        for component in &capsule.artifact_components {
            if matches!(component.schema_id, 3004 | 3010) {
                continue;
            }
            closure.extend(self.remaining.validate_component_in_bundle(capsule, component, artifacts).inspect_err(|error| {
                eprintln!("{{\"boundary\":\"runtime_identity_admission\",\"stage\":\"next_owner\",\"component\":\"{}\",\"schema\":{},\"reason\":\"{:?}\"}}", component.component_id, component.schema_id, error);
            })?);
        }
        Ok(closure)
    }
}
