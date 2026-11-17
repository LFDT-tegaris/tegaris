//! Additional conditions intersect existing permission; they never select an
//! allow rule or acquire observations on the protected request path.
use crate::semantics::{FactReference, validate_fact_references};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

pub const RELATIONSHIP_MODULE: &str = "pc.policy.relationship-facts";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FactCondition {
    #[serde(rename_all = "camelCase")]
    Relationship {
        fact: FactReference,
        fact_profile_id: String,
        profile_digest: Digest,
        namespace: String,
        entity_key_digest: Digest,
        relationship_kind: String,
        role_predicate: String,
        trusted_subject_selector: TrustedSubjectSelector,
    },
    #[serde(rename_all = "camelCase")]
    ExternalObservation {
        fact: FactReference,
        provider_id: String,
        provider_version: String,
        provider_configuration_digest: Digest,
        request_digest: Digest,
        condition: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustedSubjectSelector {
    /// The authenticated workload UUID, left padded to bytes32 before the
    /// registered Participant/privacy digest projection. No caller subject key.
    #[serde(rename = "WORKLOAD_UUID_V1")]
    WorkloadUuidV1,
}

impl FactCondition {
    pub fn fact(&self) -> &FactReference {
        match self {
            Self::Relationship { fact, .. } | Self::ExternalObservation { fact, .. } => fact,
        }
    }
    pub fn validate(&self) -> RuntimeResult<()> {
        validate_fact_references(std::slice::from_ref(self.fact()))
            .map_err(|_| RuntimeError::InvalidInput)?;
        let label = |v: &str| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control);
        let digest =
            |v: &Digest| Digest::parse(v.as_str()).as_ref() == Ok(v) && *v != Digest::of([]);
        let valid = match self {
            Self::Relationship {
                fact_profile_id,
                profile_digest,
                namespace,
                entity_key_digest,
                relationship_kind,
                role_predicate,
                ..
            } => {
                crate::semantics::uuid_v7(fact_profile_id)
                    && digest(profile_digest)
                    && digest(entity_key_digest)
                    && [namespace, relationship_kind, role_predicate]
                        .into_iter()
                        .all(|v| label(v))
            }
            Self::ExternalObservation {
                provider_id,
                provider_version,
                provider_configuration_digest,
                request_digest,
                condition,
                ..
            } => {
                digest(provider_configuration_digest)
                    && digest(request_digest)
                    && [provider_id, provider_version, condition]
                        .into_iter()
                        .all(|v| label(v))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RuntimeError::InvalidInput)
        }
    }
}

pub fn validate_conditions(
    conditions: &[FactCondition],
    required: &[FactReference],
) -> RuntimeResult<()> {
    if conditions.len() > 16 {
        return Err(RuntimeError::InvalidInput);
    }
    let mut seen = std::collections::BTreeSet::new();
    for condition in conditions {
        condition.validate()?;
        if !required.contains(condition.fact()) || !seen.insert(&condition.fact().candidate_id) {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(())
}
