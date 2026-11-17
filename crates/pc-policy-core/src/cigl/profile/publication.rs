//! Signed compilation provenance. This proves an immutable candidate's producer
//! and exact dependencies; it is not a runtime activation or grant decision.
use super::ConfiguredMethodProfile;
use crate::invocation::decode_exact;
use pc_runtime_types::{
    Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope,
    canonical_bytes,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PURPOSE: &str = "openpc:cigl-profile-compilation:v1";
pub const MAX_RECEIPT_BYTES: usize = 65_536;
pub const MAX_PROFILE_BYTES: usize = 4 * 1024 * 1024;

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(D::Error::custom)?;
        if value != parsed.to_string() {
            return Err(D::Error::custom("noncanonical revision"));
        }
        Ok(parsed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodSourceVersion {
    pub method_id: String,
    pub runtime_binding_id: String,
    #[serde(with = "decimal")]
    pub method_revision: u64,
    #[serde(with = "decimal")]
    pub binding_revision: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantSourceVersion {
    pub grant_id: String,
    #[serde(with = "decimal")]
    pub revision: u64,
    pub digest: Digest,
}

pub fn method_sources_digest(sources: &[MethodSourceVersion]) -> RuntimeResult<Digest> {
    if sources.is_empty() || sources.len() > 2049 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_by_key(|s| &s.method_id);
    for (i, s) in sorted.iter().enumerate() {
        if !crate::semantics::uuid_v7(&s.method_id)
            || !crate::semantics::uuid_v7(&s.runtime_binding_id)
            || s.method_revision == 0
            || s.binding_revision == 0
            || (i > 0 && sorted[i - 1].method_id == s.method_id)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    canonical_bytes(&sorted).map(Digest::of)
}
pub fn grant_sources_digest(sources: &[GrantSourceVersion]) -> RuntimeResult<Digest> {
    if sources.len() > 4096 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_by_key(|s| &s.grant_id);
    for (i, s) in sorted.iter().enumerate() {
        if !crate::semantics::uuid_v7(&s.grant_id)
            || s.revision == 0
            || s.digest == Digest::of([])
            || (i > 0 && sorted[i - 1].grant_id == s.grant_id)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    canonical_bytes(&sorted).map(Digest::of)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileCompilationReceipt {
    pub schema_version: String,
    pub configuration_work_id: String,
    pub operation_id: String,
    pub analysis_id: String,
    pub profile_id: String,
    #[serde(with = "decimal")]
    pub profile_revision: u64,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_runtime_id: String,
    pub capsule_digest: Digest,
    pub review_digest: Digest,
    pub analysis_digest: Digest,
    pub policy_generation_digest: Digest,
    pub profile_digest: Digest,
    pub artifact_digest: Digest,
    pub method_sources_digest: Digest,
    pub grant_sources_digest: Digest,
    /// Older compilation history did not retain paths and cannot support a
    /// dependency import. It remains readable without acquiring that authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_paths_digest: Option<Digest>,
    pub compiled_at_ms: u64,
    pub signer_id: String,
}
impl ProfileCompilationReceipt {
    pub fn verify_dependency_paths(
        &self,
        paths: &[crate::cigl::grants::dependencies::NestedDependency],
    ) -> RuntimeResult<()> {
        if self.dependency_paths_digest.as_ref()
            != Some(&crate::cigl::grants::dependencies::dependency_paths_digest(
                paths,
            )?)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub fn validate(&self) -> RuntimeResult<()> {
        if self.schema_version != "1.0"
            || self.profile_revision == 0
            || self.compiled_at_ms == 0
            || self.signer_id.is_empty()
            || self.signer_id.len() > 256
            || !self.signer_id.bytes().all(|b| b.is_ascii_graphic())
            || [
                &self.configuration_work_id,
                &self.operation_id,
                &self.analysis_id,
                &self.profile_id,
                &self.participant_id,
                &self.privacy_domain_id,
                &self.target_runtime_id,
            ]
            .into_iter()
            .any(|id| !crate::semantics::uuid_v7(id))
            || [
                &self.capsule_digest,
                &self.review_digest,
                &self.analysis_digest,
                &self.policy_generation_digest,
                &self.profile_digest,
                &self.artifact_digest,
                &self.method_sources_digest,
                &self.grant_sources_digest,
            ]
            .into_iter()
            .any(|d| *d == Digest::of([]))
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
    pub fn sign(&self, signer: &PurposeSigner) -> RuntimeResult<Vec<u8>> {
        self.validate()?;
        let signed = signer.sign(self.clone())?;
        if signed.purpose != PURPOSE {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bytes = canonical_bytes(&signed)?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(RuntimeError::BudgetExhausted);
        }
        Ok(bytes)
    }
    pub fn verify(
        signed_bytes: &[u8],
        trusted_key: &[u8],
        expected: &Self,
        profile_bytes: &[u8],
        methods: &[MethodSourceVersion],
        grants: &[GrantSourceVersion],
    ) -> RuntimeResult<ConfiguredMethodProfile> {
        if signed_bytes.is_empty()
            || signed_bytes.len() > MAX_RECEIPT_BYTES
            || profile_bytes.is_empty()
            || profile_bytes.len() > MAX_PROFILE_BYTES
        {
            return Err(RuntimeError::BudgetExhausted);
        }
        let signed: SignedEnvelope<Self> =
            serde_json::from_slice(signed_bytes).map_err(|_| RuntimeError::InvalidInput)?;
        if canonical_bytes(&signed)? != signed_bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        PurposeVerifier::from_sec1_bytes(PURPOSE, trusted_key)?.verify(&signed)?;
        signed.claims.validate()?;
        if signed.claims != *expected
            || expected.artifact_digest != Digest::of(profile_bytes)
            || expected.method_sources_digest != method_sources_digest(methods)?
            || expected.grant_sources_digest != grant_sources_digest(grants)?
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let profile: ConfiguredMethodProfile = decode_exact(profile_bytes)?;
        profile.validate()?;
        let definition = &profile.definition;
        let grant_index: BTreeMap<_, _> = grants.iter().map(|g| (&g.grant_id, &g.digest)).collect();
        let required_methods: BTreeSet<_> =
            std::iter::once(&definition.root_contract_method_policy_id)
                .chain(
                    definition
                        .interactions
                        .iter()
                        .map(|rule| &rule.contract_method_policy_id),
                )
                .collect();
        if definition.profile_id != expected.profile_id
            || definition.revision != expected.profile_revision
            || definition.participant_id != expected.participant_id
            || definition.privacy_domain_id != expected.privacy_domain_id
            || definition.analysis_digest != expected.analysis_digest
            || definition.digest()? != expected.profile_digest
            || required_methods != methods.iter().map(|s| &s.method_id).collect()
            || profile.grants.grants.len() != grants.len()
            || profile.grants.grants.iter().any(|g| {
                !g.digest()
                    .is_ok_and(|digest| grant_index.get(&g.grant_id) == Some(&&digest))
            })
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(profile)
    }
}
