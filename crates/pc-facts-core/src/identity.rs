//! Closed CanonicalFactIdentityV1. This is identity, never authorization or
//! readiness. Admission supplies independently verified semantics and current
//! authority; FactStore supplies the canonical generation and durable fact ID.
use ciborium::value::Value;
use pc_policy_core::invocation::ArgumentValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AdmissionError, FACT_SCHEMA_VERSION_V1, FactLifecycleState, encode_pc_cbor, sha256,
    validate_pc_cbor,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FactSubject {
    #[serde(rename_all = "camelCase")]
    ContractStateCall {
        contract_address: String,
        code_digest: String,
        abi_digest: String,
        canonical_signature: String,
        arguments: Vec<ArgumentValue>,
    },
    #[serde(rename_all = "camelCase")]
    Relationship {
        namespace: String,
        entity_key_digest: String,
        subject_key_digest: String,
        relationship_kind: String,
        role_predicates: Vec<String>,
        profile_digest: String,
        transaction_hash: String,
    },
    #[serde(rename_all = "camelCase")]
    ExternalDecision {
        provider_id: String,
        configuration_digest: String,
        provider_version: String,
        request_digest: String,
        source_occurrence: String,
        condition: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FactObject {
    AbiResult {
        values: Vec<ArgumentValue>,
    },
    #[serde(rename_all = "camelCase")]
    RelationshipInterval {
        transition: String,
        effective_from_block: u64,
        effective_through_block: Option<u64>,
        completed_watermark: u64,
        successful_execution: bool,
    },
    #[serde(rename_all = "camelCase")]
    ExternalObservation {
        satisfied: bool,
        response_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactChainAnchor {
    pub chain_id: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub finality_rule_id: String,
    pub transaction_index: Option<u64>,
    pub log_index: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalFactIdentity {
    pub fact_id: String,
    pub fact_profile_id: String,
    pub fact_semantic_version: String,
    pub fact_schema_id: u32,
    pub fact_schema_version: String,
    pub fact_schema_digest: String,
    pub typed_subject: FactSubject,
    pub typed_object: FactObject,
    pub participant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_domain_id: Option<String>,
    pub platform_authority_epoch: u64,
    pub participant_authority_envelope_id: String,
    pub delegation_epoch: u64,
    pub chain_anchor: FactChainAnchor,
    pub canonical_generation: u64,
    pub admission_policy_version: String,
    pub admission_policy_digest: String,
    pub local_signing_key_id: String,
    pub local_fact_digest: String,
    pub fact_status: FactLifecycleState,
}

impl PartialEq for CanonicalFactIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.fact_id == other.fact_id
            && self.fact_profile_id == other.fact_profile_id
            && self.fact_semantic_version == other.fact_semantic_version
            && self.fact_schema_id == other.fact_schema_id
            && self.fact_schema_version == other.fact_schema_version
            && self.fact_schema_digest == other.fact_schema_digest
            && self.typed_subject == other.typed_subject
            && self.typed_object == other.typed_object
            && self.participant_id == other.participant_id
            && self.privacy_domain_id == other.privacy_domain_id
            && self.platform_authority_epoch == other.platform_authority_epoch
            && self.participant_authority_envelope_id == other.participant_authority_envelope_id
            && self.delegation_epoch == other.delegation_epoch
            && self.chain_anchor == other.chain_anchor
            && self.canonical_generation == other.canonical_generation
            && self.admission_policy_version == other.admission_policy_version
            && self.admission_policy_digest == other.admission_policy_digest
            && self.local_signing_key_id == other.local_signing_key_id
            && self.local_fact_digest == other.local_fact_digest
    }
}
impl Eq for CanonicalFactIdentity {}

pub(crate) fn urn(value: &str, kind: &str) -> bool {
    value
        .strip_prefix(&format!("urn:openpc:{kind}:"))
        .and_then(|v| Uuid::parse_str(v).ok())
        .is_some_and(|id| id.get_version_num() == 7 && value == format!("urn:openpc:{kind}:{id}"))
}
fn hex(value: &str, prefix: &str, length: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|v| {
        v.len() == length * 2
            && v.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
pub(crate) fn digest(value: &str) -> bool {
    hex(value, "sha256:", 32)
}
pub(crate) fn digest_text(value: &[u8; 32]) -> String {
    format!(
        "sha256:{}",
        value.iter().map(|v| format!("{v:02x}")).collect::<String>()
    )
}
fn uint256(value: &str) -> bool {
    const MAX: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    !value.is_empty()
        && value.bytes().all(|c| c.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && (value.len() < MAX.len() || (value.len() == MAX.len() && value <= MAX))
}

impl CanonicalFactIdentity {
    /// Scoped typed key for preservation across observations and generations.
    /// The profile, chain namespace and typed subject define the key; individual
    /// transaction/source occurrences, observed values and mutable lifecycle do
    /// not. This digest
    /// grants no read authority and is not an identifier-erasure alias.
    pub fn preservation_key_digest(&self) -> Result<String, AdmissionError> {
        self.validate()?;
        let mut subject =
            Value::serialized(&self.typed_subject).map_err(|_| AdmissionError::SchemaOrEncoding)?;
        let Value::Map(fields) = &mut subject else {
            return Err(AdmissionError::SchemaOrEncoding);
        };
        // These identify an observation of the key, not the preserved subject.
        // The relationship owner's transition key uses the same distinction.
        fields.retain(|(key, _)| {
            !matches!(key, Value::Text(name) if name == "transactionHash" || name == "sourceOccurrence")
        });
        let bytes = encode_pc_cbor(Value::Array(vec![
            Value::Text("pc.fact.preservation-key.v1".into()),
            Value::Text(self.participant_id.clone()),
            self.privacy_domain_id
                .clone()
                .map_or(Value::Null, Value::Text),
            Value::Text(self.fact_profile_id.clone()),
            Value::Text(self.fact_semantic_version.clone()),
            Value::Text(self.chain_anchor.chain_id.clone()),
            Value::Text(self.chain_anchor.genesis_hash.clone()),
            Value::Text(self.chain_anchor.network_id.clone()),
            subject,
        ]))?;
        Ok(digest_text(&sha256(&bytes)))
    }

    fn semantic_fields_valid(&self) -> bool {
        let anchor = &self.chain_anchor;
        let semantics = match (&self.typed_subject, &self.typed_object) {
            (
                FactSubject::ContractStateCall {
                    contract_address,
                    code_digest,
                    abi_digest,
                    canonical_signature,
                    arguments,
                },
                FactObject::AbiResult { values },
            ) => {
                hex(contract_address, "0x", 20)
                    && digest(code_digest)
                    && digest(abi_digest)
                    && !canonical_signature.is_empty()
                    && canonical_signature.len() <= 4096
                    && arguments.len() <= 256
                    && !values.is_empty()
                    && values.len() <= 256
                    && anchor.transaction_index.is_none()
                    && anchor.log_index.is_none()
            }
            (
                FactSubject::Relationship {
                    namespace,
                    entity_key_digest,
                    subject_key_digest,
                    relationship_kind,
                    role_predicates,
                    profile_digest,
                    transaction_hash,
                },
                FactObject::RelationshipInterval {
                    transition,
                    effective_from_block,
                    effective_through_block,
                    completed_watermark,
                    successful_execution,
                },
            ) => {
                label(namespace)
                    && label(relationship_kind)
                    && digest(entity_key_digest)
                    && digest(subject_key_digest)
                    && digest(profile_digest)
                    && hex(transaction_hash, "0x", 32)
                    && !role_predicates.is_empty()
                    && role_predicates.len() <= 64
                    && role_predicates.iter().all(|v| label(v))
                    && role_predicates.windows(2).all(|v| v[0] < v[1])
                    && matches!(transition.as_str(), "OPEN" | "CLOSE" | "REPLACE")
                    && *effective_from_block <= *completed_watermark
                    && effective_through_block.is_none_or(|end| {
                        end >= *effective_from_block && end <= *completed_watermark
                    })
                    && *completed_watermark >= anchor.block_height
                    && *successful_execution
                    && anchor.transaction_index.is_some()
                    && anchor.log_index.is_some()
            }
            (
                FactSubject::ExternalDecision {
                    provider_id,
                    configuration_digest,
                    provider_version,
                    request_digest,
                    source_occurrence,
                    condition,
                },
                FactObject::ExternalObservation {
                    response_digest, ..
                },
            ) => {
                label(provider_id)
                    && label(provider_version)
                    && label(source_occurrence)
                    && label(condition)
                    && digest(configuration_digest)
                    && digest(request_digest)
                    && digest(response_digest)
                    && anchor.transaction_index.is_none()
                    && anchor.log_index.is_none()
            }
            _ => false,
        };
        urn(&self.fact_id, "fact")
            && urn(&self.fact_profile_id, "fact-profile")
            && urn(&self.participant_id, "participant")
            && self
                .privacy_domain_id
                .as_ref()
                .is_none_or(|id| urn(id, "privacy-domain"))
            && urn(
                &self.participant_authority_envelope_id,
                "authority-envelope",
            )
            && urn(&anchor.finality_rule_id, "finality-rule")
            && self.fact_semantic_version == "1.0.0"
            && self.admission_policy_version == "1.0.0"
            && self.fact_schema_id
                == crate::record_schema(matches!(
                    self.typed_subject,
                    FactSubject::Relationship { .. }
                ))
            && self.fact_schema_version == FACT_SCHEMA_VERSION_V1
            && self.fact_schema_digest
                == digest_text(crate::record_schema_digest(matches!(
                    self.typed_subject,
                    FactSubject::Relationship { .. }
                )))
            && self.canonical_generation > 0
            && digest(&self.admission_policy_digest)
            && digest(&self.local_signing_key_id)
            && semantics
            && uint256(&anchor.chain_id)
            && hex(&anchor.genesis_hash, "0x", 32)
            && hex(&anchor.block_hash, "0x", 32)
            && !anchor.network_id.is_empty()
            && anchor.network_id.len() <= 256
            && !matches!(
                self.fact_status,
                FactLifecycleState::ObservedCandidate | FactLifecycleState::ValidatedCandidate
            )
    }

    fn projected(&self, excluded: &[&str]) -> Result<Vec<u8>, AdmissionError> {
        let Value::Map(mut entries) =
            Value::serialized(self).map_err(|_| AdmissionError::SchemaOrEncoding)?
        else {
            return Err(AdmissionError::SchemaOrEncoding);
        };
        entries.retain(
            |(key, _)| !matches!(key,Value::Text(name) if excluded.contains(&name.as_str())),
        );
        encode_pc_cbor(Value::Map(entries))
    }

    /// Digest excludes only its own field and mutable lifecycle status. The
    /// signed record separately binds provenance, lineage and temporal bounds.
    pub fn with_derived_digest(mut self) -> Result<Self, AdmissionError> {
        if !self.semantic_fields_valid() {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        self.local_fact_digest = digest_text(&sha256(
            &self.projected(&["localFactDigest", "factStatus"])?,
        ));
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdmissionError> {
        if !self.semantic_fields_valid()
            || !digest(&self.local_fact_digest)
            || self.local_fact_digest
                != digest_text(&sha256(
                    &self.projected(&["localFactDigest", "factStatus"])?,
                ))
        {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, AdmissionError> {
        self.validate()?;
        self.projected(&[])
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() > 131_072 {
            return Err(AdmissionError::SchemaOrEncoding);
        }
        validate_pc_cbor(bytes)?;
        let value: Self =
            ciborium::de::from_reader(bytes).map_err(|_| AdmissionError::SchemaOrEncoding)?;
        if value.to_cbor()? != bytes {
            return Err(AdmissionError::SchemaOrEncoding);
        }
        Ok(value)
    }
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_RECORD_SCHEMA_ID};

    pub(crate) fn identity() -> CanonicalFactIdentity {
        let id = "018f0000-0000-7000-8000-000000000101";
        CanonicalFactIdentity {
            fact_id: format!("urn:openpc:fact:{id}"),
            fact_profile_id: format!("urn:openpc:fact-profile:{id}"),
            fact_semantic_version: "1.0.0".into(),
            fact_schema_id: FACT_RECORD_SCHEMA_ID,
            fact_schema_version: FACT_SCHEMA_VERSION_V1.into(),
            fact_schema_digest: digest_text(&FACT_BRIDGE_SCHEMA_DIGEST_V1),
            typed_subject: FactSubject::ContractStateCall {
                contract_address: format!("0x{}", "11".repeat(20)),
                code_digest: digest_text(&[2; 32]),
                abi_digest: digest_text(&[3; 32]),
                canonical_signature: "balanceOf(address)".into(),
                arguments: vec![ArgumentValue::Address([4; 20])],
            },
            typed_object: FactObject::AbiResult {
                values: vec![ArgumentValue::Uint([5; 32])],
            },
            participant_id: format!("urn:openpc:participant:{id}"),
            privacy_domain_id: Some(format!("urn:openpc:privacy-domain:{id}")),
            platform_authority_epoch: u64::MAX,
            participant_authority_envelope_id: format!("urn:openpc:authority-envelope:{id}"),
            delegation_epoch: 7,
            chain_anchor: FactChainAnchor {
                chain_id: "31337".into(),
                genesis_hash: format!("0x{}", "06".repeat(32)),
                network_id: "local-chain".into(),
                block_height: 10,
                block_hash: format!("0x{}", "07".repeat(32)),
                finality_rule_id: format!("urn:openpc:finality-rule:{id}"),
                transaction_index: None,
                log_index: None,
            },
            canonical_generation: 1,
            admission_policy_version: "1.0.0".into(),
            admission_policy_digest: digest_text(&[8; 32]),
            local_signing_key_id: digest_text(&[9; 32]),
            local_fact_digest: String::new(),
            fact_status: FactLifecycleState::Admitted,
        }
        .with_derived_digest()
        .unwrap()
    }

    #[test]
    fn exact_identity_keeps_u64_and_excludes_only_lifecycle_status() {
        let original = identity();
        assert_eq!(
            CanonicalFactIdentity::from_cbor(&original.to_cbor().unwrap()).unwrap(),
            original
        );
        let mut finalized = original.clone();
        finalized.fact_status = FactLifecycleState::Finalized;
        assert_eq!(finalized, original);
        assert_ne!(finalized.to_cbor().unwrap(), original.to_cbor().unwrap());

        let mut reorged = original.clone();
        reorged.chain_anchor.block_hash = format!("0x{}", "08".repeat(32));
        assert!(reorged.validate().is_err());
        let reorged = reorged.with_derived_digest().unwrap();
        assert_ne!(reorged, original);
        assert_ne!(reorged.local_fact_digest, original.local_fact_digest);

        let mut rotated = original.clone();
        rotated.local_signing_key_id = digest_text(&[10; 32]);
        assert_ne!(rotated.with_derived_digest().unwrap(), original);
        let mut narrowed = original.clone();
        narrowed.delegation_epoch += 1;
        assert_ne!(narrowed.with_derived_digest().unwrap(), original);
        let mut generation = original.clone();
        generation.canonical_generation += 1;
        assert_ne!(generation.with_derived_digest().unwrap(), original);
    }

    #[test]
    fn incomplete_unknown_or_noncanonical_identity_cannot_be_decoded() {
        let identity = identity();
        let Value::Map(entries) = Value::serialized(&identity).unwrap() else {
            panic!()
        };
        for field in [
            "platformAuthorityEpoch",
            "participantAuthorityEnvelopeId",
            "factProfileId",
            "factSemanticVersion",
            "localSigningKeyId",
        ] {
            let missing: Vec<_> = entries
                .iter()
                .filter(|(name, _)| name != &Value::Text(field.into()))
                .cloned()
                .collect();
            assert!(
                CanonicalFactIdentity::from_cbor(&encode_pc_cbor(Value::Map(missing)).unwrap())
                    .is_err()
            );
        }
        let mut unknown = entries.clone();
        unknown.push((Value::Text("ready".into()), Value::Bool(true)));
        assert!(
            CanonicalFactIdentity::from_cbor(&encode_pc_cbor(Value::Map(unknown)).unwrap())
                .is_err()
        );
        let mut scoped = identity.clone();
        scoped.participant_id = "018f0000-0000-7000-8000-000000000101".into();
        assert!(scoped.with_derived_digest().is_err());
        let mut absent = identity.clone();
        absent.privacy_domain_id = None;
        let absent = absent.with_derived_digest().unwrap();
        assert!(CanonicalFactIdentity::from_cbor(&absent.to_cbor().unwrap()).is_ok());
        let Value::Map(mut explicit_null) = Value::serialized(&absent).unwrap() else {
            panic!()
        };
        explicit_null.push((Value::Text("privacyDomainId".into()), Value::Null));
        assert!(
            CanonicalFactIdentity::from_cbor(&encode_pc_cbor(Value::Map(explicit_null)).unwrap())
                .is_err()
        );
        let mut malformed = identity;
        malformed.chain_anchor.chain_id = "031337".into();
        assert!(malformed.with_derived_digest().is_err());
    }

    #[test]
    fn preservation_key_binds_scoped_typed_subject_without_freezing_observation() {
        let original = identity();
        let digest = original.preservation_key_digest().unwrap();
        let mut later = original.clone();
        later.canonical_generation += 1;
        later.chain_anchor.block_height += 1;
        later.chain_anchor.block_hash = format!("0x{}", "12".repeat(32));
        later.typed_object = FactObject::AbiResult {
            values: vec![ArgumentValue::Uint([13; 32])],
        };
        assert_eq!(
            later
                .with_derived_digest()
                .unwrap()
                .preservation_key_digest()
                .unwrap(),
            digest
        );
        for field in 0..5 {
            let mut other = original.clone();
            match field {
                0 => {
                    other.participant_id =
                        "urn:openpc:participant:018f0000-0000-7000-8000-000000000102".into()
                }
                1 => {
                    other.fact_profile_id =
                        "urn:openpc:fact-profile:018f0000-0000-7000-8000-000000000102".into()
                }
                2 => other.chain_anchor.chain_id = "31338".into(),
                3 => other.chain_anchor.genesis_hash = format!("0x{}", "14".repeat(32)),
                _ => {
                    if let FactSubject::ContractStateCall { arguments, .. } =
                        &mut other.typed_subject
                    {
                        *arguments = vec![ArgumentValue::Address([15; 20])];
                    }
                }
            }
            assert_ne!(
                other
                    .with_derived_digest()
                    .unwrap()
                    .preservation_key_digest()
                    .unwrap(),
                digest
            );
        }
        let mut invalid = original;
        invalid.canonical_generation = 0;
        assert!(invalid.preservation_key_digest().is_err());
    }

    #[test]
    fn preservation_keys_follow_relationship_and_external_subjects_across_occurrences() {
        let mut relationship = identity();
        relationship.fact_schema_id = crate::record_schema(true);
        relationship.fact_schema_digest = digest_text(crate::record_schema_digest(true));
        relationship.typed_subject = FactSubject::Relationship {
            namespace: "membership".into(),
            entity_key_digest: format!("sha256:{}", "11".repeat(32)),
            subject_key_digest: format!("sha256:{}", "22".repeat(32)),
            relationship_kind: "member".into(),
            role_predicates: vec!["reader".into()],
            profile_digest: format!("sha256:{}", "33".repeat(32)),
            transaction_hash: format!("0x{}", "44".repeat(32)),
        };
        relationship.chain_anchor.transaction_index = Some(0);
        relationship.chain_anchor.log_index = Some(0);
        relationship.typed_object = FactObject::RelationshipInterval {
            transition: "OPEN".into(),
            effective_from_block: relationship.chain_anchor.block_height,
            effective_through_block: None,
            completed_watermark: relationship.chain_anchor.block_height,
            successful_execution: true,
        };
        let mut external = identity();
        external.typed_subject = FactSubject::ExternalDecision {
            provider_id: "provider".into(),
            configuration_digest: format!("sha256:{}", "55".repeat(32)),
            provider_version: "1".into(),
            request_digest: format!("sha256:{}", "66".repeat(32)),
            source_occurrence: "first".into(),
            condition: "allowed".into(),
        };
        external.typed_object = FactObject::ExternalObservation {
            satisfied: true,
            response_digest: format!("sha256:{}", "77".repeat(32)),
        };
        for original in [relationship, external] {
            let original = original.with_derived_digest().unwrap();
            let key = original.preservation_key_digest().unwrap();
            let mut later = original.clone();
            match &mut later.typed_subject {
                FactSubject::Relationship {
                    transaction_hash, ..
                } => {
                    *transaction_hash = format!("0x{}", "88".repeat(32));
                }
                FactSubject::ExternalDecision {
                    source_occurrence, ..
                } => {
                    *source_occurrence = "next".into();
                }
                _ => unreachable!(),
            }
            let later = later.with_derived_digest().unwrap();
            assert_ne!(later.local_fact_digest, original.local_fact_digest);
            assert_eq!(later.preservation_key_digest().unwrap(), key);
            let mut other = later;
            match &mut other.typed_subject {
                FactSubject::Relationship {
                    subject_key_digest, ..
                } => {
                    *subject_key_digest = format!("sha256:{}", "99".repeat(32));
                }
                FactSubject::ExternalDecision { request_digest, .. } => {
                    *request_digest = format!("sha256:{}", "99".repeat(32));
                }
                _ => unreachable!(),
            }
            assert_ne!(
                other
                    .with_derived_digest()
                    .unwrap()
                    .preservation_key_digest()
                    .unwrap(),
                key
            );
        }
    }
}
