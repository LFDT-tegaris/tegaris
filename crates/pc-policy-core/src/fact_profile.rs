//! Fact admission settings carried by the existing governed configuration.
//! These bytes define meaning and bounds; they do not prove publication,
//! current authority, provider observations, or permission to consume a fact.
use crate::invocation::{
    ActiveInvocationConfigurationV1, ConfigurationArtifactKind, ConfigurationArtifactV1,
    decode_exact, encode_exact,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateFactProfile {
    pub schema_version: String,
    /// Identity and meaning of the fact, distinct from this document's schema.
    pub fact_profile_id: String,
    pub fact_semantic_version: String,
    pub admission_policy_version: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub source_profile_id: String,
    pub projection_plan_id: String,
    pub projection_plan_digest: Digest,
    pub mapping: StateFactMapping,
    /// Required signed-profile value; there is no process/default fallback.
    pub maximum_staleness_ms: u64,
    /// Required signed-profile value used by the reorg/rebootstrap owner.
    pub reorg_retained_tail_blocks: u64,
    pub shard_entry_limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StateFactMapping {
    AbiStateResultV1,
    RgraEventRelationshipV1 {
        namespace: String,
        relationship_kind: String,
        role_predicates: Vec<String>,
    },
    /// Closed off-path ExternalDecisionAdapterV1 observation. The exact signed
    /// provider version/configuration and independent admission remain required.
    ExternalDecisionAdapterV1 {
        provider_id: String,
        provider_version: String,
        provider_configuration_digest: Digest,
        condition: String,
    },
}

impl StateFactProfile {
    pub fn validate(&self) -> RuntimeResult<()> {
        if let StateFactMapping::RgraEventRelationshipV1 {
            namespace,
            relationship_kind,
            role_predicates,
        } = &self.mapping
            && ([namespace, relationship_kind]
                .iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
                || role_predicates.is_empty()
                || role_predicates.len() > 64
                || role_predicates
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
                || role_predicates.windows(2).any(|v| v[0] >= v[1]))
        {
            return Err(RuntimeError::InvalidInput);
        }
        if let StateFactMapping::ExternalDecisionAdapterV1 {
            provider_id,
            provider_version,
            provider_configuration_digest,
            condition,
        } = &self.mapping
            && ([provider_id, provider_version, condition]
                .iter()
                .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
                || Digest::parse(provider_configuration_digest.as_str()).as_ref()
                    != Ok(provider_configuration_digest))
        {
            return Err(RuntimeError::InvalidInput);
        }
        for digest in [&self.projection_plan_digest] {
            if Digest::parse(digest.as_str()).as_ref() != Ok(digest) {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if self.schema_version != "1.0.0"
            || self.fact_semantic_version != "1.0.0"
            || self.admission_policy_version != "1.0.0"
            || [
                &self.fact_profile_id,
                &self.participant_id,
                &self.privacy_domain_id,
                &self.source_profile_id,
                &self.projection_plan_id,
            ]
            .iter()
            .any(|id| !crate::semantics::uuid_v7(id))
            || self.maximum_staleness_ms == 0
            || i64::try_from(self.maximum_staleness_ms).is_err()
            || self.reorg_retained_tail_blocks == 0
            || !(1..=1_000_000).contains(&self.shard_entry_limit)
            || self.projection_plan_digest == Digest::of([])
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> RuntimeResult<Vec<u8>> {
        self.validate()?;
        encode_exact(self)
    }

    pub fn from_cbor(bytes: &[u8]) -> RuntimeResult<Self> {
        let profile: Self = decode_exact(bytes)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn artifact(&self) -> RuntimeResult<ConfigurationArtifactV1> {
        let payload_cbor = self.to_cbor()?;
        Ok(ConfigurationArtifactV1 {
            artifact_id: self.projection_plan_id.clone(),
            artifact_kind: ConfigurationArtifactKind::FactAdmissionProfile,
            artifact_digest: Digest::of(&payload_cbor),
            payload_cbor,
        })
    }

    /// The governed source commits this profile's bytes, including its exact
    /// mapping and mandatory bounds. Mere inclusion in a deployment input is
    /// insufficient. The service must also verify current source governance.
    pub fn resolve(
        configuration: &ActiveInvocationConfigurationV1,
        plan_id: &str,
    ) -> RuntimeResult<Self> {
        let exact = |kind, id: &str| {
            let mut matches = configuration
                .resource_artifacts
                .iter()
                .filter(|a| a.artifact_kind == kind && a.artifact_id == id);
            let artifact = matches.next().ok_or(RuntimeError::InvalidInput)?;
            if matches.next().is_some()
                || Digest::of(&artifact.payload_cbor) != artifact.artifact_digest
            {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(artifact)
        };
        let artifact = exact(ConfigurationArtifactKind::FactAdmissionProfile, plan_id)?;
        let profile = Self::from_cbor(&artifact.payload_cbor)?;
        if let StateFactMapping::RgraEventRelationshipV1 { namespace, .. } = &profile.mapping {
            for other in configuration.resource_artifacts.iter().filter(|entry| {
                entry.artifact_kind == ConfigurationArtifactKind::FactAdmissionProfile
                    && entry.artifact_id != plan_id
            }) {
                if Digest::of(&other.payload_cbor) != other.artifact_digest {
                    return Err(RuntimeError::InvalidDigest);
                }
                let other = Self::from_cbor(&other.payload_cbor)?;
                if other.participant_id == profile.participant_id
                    && other.privacy_domain_id == profile.privacy_domain_id
                    && matches!(&other.mapping, StateFactMapping::RgraEventRelationshipV1 { namespace: other_namespace, .. } if other_namespace == namespace)
                {
                    return Err(RuntimeError::GenerationMismatch);
                }
            }
        }
        let source = exact(
            ConfigurationArtifactKind::ClientIndexerProfile,
            &profile.source_profile_id,
        )?;
        let plan = exact(ConfigurationArtifactKind::ProjectionPlan, plan_id)?;
        let decoded_source =
            pc_provider_api::decode_client_indexer_profile_pc_cbor(&source.payload_cbor)
                .map_err(|_| RuntimeError::InvalidInput)?;
        let decoded_plan = pc_provider_api::decode_projection_plan_pc_cbor(&plan.payload_cbor)
            .map_err(|_| RuntimeError::InvalidInput)?;
        pc_provider_api::validate_projection_plan(&decoded_source, &decoded_plan)
            .map_err(|_| RuntimeError::InvalidInput)?;
        if profile.projection_plan_id != plan_id
            || plan.artifact_digest != profile.projection_plan_digest
            || decoded_source
                .artifact_digests
                .iter()
                .filter(|entry| {
                    entry.name == "fact-admission-profile"
                        && entry.digest == format!("sha256:{}", artifact.artifact_digest.as_str())
                })
                .count()
                != 1
            || decoded_source
                .artifact_digests
                .iter()
                .filter(|entry| entry.name == "fact-admission-profile")
                .count()
                != 1
            || decoded_source.participant_binding != profile.participant_id
            || decoded_source.privacy_binding != profile.privacy_domain_id
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> StateFactProfile {
        StateFactProfile {
            schema_version: "1.0.0".into(),
            fact_profile_id: "018f0000-0000-7000-8000-000000000501".into(),
            fact_semantic_version: "1.0.0".into(),
            admission_policy_version: "1.0.0".into(),
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            source_profile_id: "018f0000-0000-7000-8000-000000000301".into(),
            projection_plan_id: "018f0000-0000-7000-8000-000000000401".into(),
            projection_plan_digest: Digest::of(b"plan"),
            mapping: StateFactMapping::AbiStateResultV1,
            maximum_staleness_ms: 60_000,
            reorg_retained_tail_blocks: 64,
            shard_entry_limit: 1_000_000,
        }
    }
    #[test]
    fn required_freshness_and_reorg_bounds_have_no_defaults() {
        let profile = profile();
        assert_eq!(
            StateFactProfile::from_cbor(&profile.to_cbor().unwrap()).unwrap(),
            profile
        );
        for name in [
            "factProfileId",
            "factSemanticVersion",
            "admissionPolicyVersion",
            "maximumStalenessMs",
            "reorgRetainedTailBlocks",
            "shardEntryLimit",
        ] {
            let mut value = serde_json::to_value(&profile).unwrap();
            value.as_object_mut().unwrap().remove(name);
            assert!(serde_json::from_value::<StateFactProfile>(value).is_err());
        }
        for name in [
            "maximumStalenessMs",
            "reorgRetainedTailBlocks",
            "shardEntryLimit",
        ] {
            let mut value = serde_json::to_value(&profile).unwrap();
            value[name] = 0.into();
            assert!(
                serde_json::from_value::<StateFactProfile>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut wrong = profile.clone();
        wrong.shard_entry_limit = 1_000_001;
        assert!(wrong.validate().is_err());
        let mut unknown = serde_json::to_value(profile).unwrap();
        unknown["ready"] = true.into();
        assert!(serde_json::from_value::<StateFactProfile>(unknown).is_err());
    }
}
