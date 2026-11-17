//! Semantic occurrence identity for independently verified ABI state calls.
//! Source delivery, publication, authority, timestamps and returned value are
//! deliberately not part of the occurrence: changing them cannot hide conflict.
use pc_facts_core::{AdmissionError, encode_pc_cbor, sha256, validate_pc_cbor};
use pc_policy_core::invocation::ArgumentValue;
use pc_runtime_types::Digest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateFactValue {
    pub mapping: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_hash: String,
    pub block_number: String,
    pub block_hash: String,
    pub target_address: String,
    pub code_digest: Digest,
    pub runtime_binding_id: Uuid,
    pub binding_revision: String,
    pub abi_digest: Digest,
    pub signature: String,
    pub typed_arguments: Vec<ArgumentValue>,
    pub typed_result: Vec<ArgumentValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specialization: Option<(pc_facts_core::FactSubject, pc_facts_core::FactObject)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
}

pub(crate) struct SemanticOccurrence {
    pub canonical: Vec<u8>,
    pub digest: [u8; 32],
    pub value_digest: [u8; 32],
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, AdmissionError> {
    encode_pc_cbor(
        ciborium::value::Value::serialized(value).map_err(|_| AdmissionError::SchemaOrEncoding)?,
    )
}

impl StateFactValue {
    pub fn from_payload(
        bytes: &[u8],
        participant: &str,
        privacy: &str,
    ) -> Result<Self, AdmissionError> {
        validate_pc_cbor(bytes)?;
        let value: Self =
            ciborium::de::from_reader(bytes).map_err(|_| AdmissionError::SchemaOrEncoding)?;
        if !matches!(
            value.mapping.as_str(),
            "openpc:abi-state-result:v1"
                | "openpc:external-decision-observation:v1"
                | "RGRA_EVENT_RELATIONSHIP_V1"
        ) || (value.mapping == "openpc:external-decision-observation:v1"
            && (!matches!(
                &value.specialization,
                Some((
                    pc_facts_core::FactSubject::ExternalDecision { .. },
                    pc_facts_core::FactObject::ExternalObservation { .. }
                ))
            ) || !value.typed_result.is_empty()
                || value.transaction_index.is_some()
                || value.log_index.is_some()))
            || value.participant_id != participant
            || value.privacy_domain_id != privacy
            || value.signature.is_empty()
            || (value.mapping == "openpc:abi-state-result:v1"
                && (value.typed_result.is_empty()
                    || value.specialization.is_some()
                    || value.transaction_index.is_some()
                    || value.log_index.is_some()))
            || (value.mapping == "RGRA_EVENT_RELATIONSHIP_V1"
                && (!matches!(
                    &value.specialization,
                    Some((
                        pc_facts_core::FactSubject::Relationship { .. },
                        pc_facts_core::FactObject::RelationshipInterval { .. }
                    ))
                ) || value.transaction_index.is_none()
                    || value.log_index.is_none()))
            || canonical(&value)? != bytes
        {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        Ok(value)
    }

    pub fn occurrence(&self) -> Result<SemanticOccurrence, AdmissionError> {
        if let Some((
            pc_facts_core::FactSubject::ExternalDecision {
                provider_id,
                provider_version,
                configuration_digest,
                source_occurrence,
                request_digest,
                condition,
            },
            object,
        )) = &self.specialization
        {
            let canonical = canonical(&(
                "openpc:external-decision-occurrence:v1",
                &self.participant_id,
                &self.privacy_domain_id,
                provider_id,
                provider_version,
                configuration_digest,
                source_occurrence,
                request_digest,
                condition,
            ))?;
            return Ok(SemanticOccurrence {
                digest: sha256(&canonical),
                canonical,
                value_digest: sha256(&crate::state_value::canonical(object)?),
            });
        }
        if let Some((subject, object)) = &self.specialization {
            let pc_facts_core::FactSubject::Relationship {
                namespace,
                entity_key_digest,
                subject_key_digest,
                relationship_kind,
                role_predicates,
                transaction_hash,
                ..
            } = subject
            else {
                return Err(AdmissionError::SemanticOrPrivacy);
            };
            let canonical = canonical(&(
                "openpc:rgra-event-occurrence:v1",
                &self.participant_id,
                &self.privacy_domain_id,
                &self.chain_id,
                &self.network_id,
                &self.genesis_hash,
                &self.block_hash,
                &self.target_address,
                namespace,
                entity_key_digest,
                subject_key_digest,
                relationship_kind,
                role_predicates,
                transaction_hash,
                self.transaction_index,
                self.log_index,
            ))?;
            return Ok(SemanticOccurrence {
                digest: sha256(&canonical),
                canonical,
                value_digest: sha256(&crate::state_value::canonical(object)?),
            });
        }
        let canonical = canonical(&serde_json::json!({
            "purpose":"openpc:abi-state-occurrence:v1", "mapping":self.mapping,
            "participantId":self.participant_id,"privacyDomainId":self.privacy_domain_id,
            "chainId":self.chain_id,"networkId":self.network_id,"genesisHash":self.genesis_hash,
            "blockNumber":self.block_number,"blockHash":self.block_hash,
            "targetAddress":self.target_address,"codeDigest":self.code_digest,
            "abiDigest":self.abi_digest,"signature":self.signature,"typedArguments":self.typed_arguments,
        }))?;
        Ok(SemanticOccurrence {
            digest: sha256(&canonical),
            canonical,
            value_digest: sha256(&crate::state_value::canonical(&self.typed_result)?),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn value(participant: &str, privacy: &str, result: u8) -> StateFactValue {
        StateFactValue {
            mapping: "openpc:abi-state-result:v1".into(),
            specialization: None,
            transaction_index: None,
            log_index: None,
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            chain_id: "31337".into(),
            network_id: "local".into(),
            genesis_hash: "11".repeat(32),
            block_number: "10".into(),
            block_hash: "22".repeat(32),
            target_address: "33".repeat(20),
            code_digest: Digest::of(b"code"),
            runtime_binding_id: Uuid::now_v7(),
            binding_revision: "1".into(),
            abi_digest: Digest::of(b"abi"),
            signature: "balanceOf(address)".into(),
            typed_arguments: vec![ArgumentValue::Address([4; 20])],
            typed_result: vec![ArgumentValue::Uint([result; 32])],
        }
    }
    #[test]
    fn occurrence_is_value_and_delivery_independent_but_exactly_scoped_and_anchored() {
        let original = value("participant", "privacy", 1);
        let key = original.occurrence().unwrap();
        let mut changed = original.clone();
        changed.typed_result = vec![ArgumentValue::Uint([2; 32])];
        changed.runtime_binding_id = Uuid::now_v7();
        changed.binding_revision = "2".into();
        assert_eq!(changed.occurrence().unwrap().digest, key.digest);
        assert_ne!(changed.occurrence().unwrap().value_digest, key.value_digest);
        for change in [
            "participant",
            "privacy",
            "block",
            "chain",
            "contract",
            "argument",
            "abi",
        ] {
            let mut value = original.clone();
            match change {
                "participant" => value.participant_id = "other".into(),
                "privacy" => value.privacy_domain_id = "other".into(),
                "block" => value.block_hash = "44".repeat(32),
                "chain" => value.genesis_hash = "55".repeat(32),
                "contract" => value.target_address = "66".repeat(20),
                "argument" => value.typed_arguments = vec![ArgumentValue::Address([7; 20])],
                _ => value.abi_digest = Digest::of(b"other"),
            }
            assert_ne!(value.occurrence().unwrap().digest, key.digest, "{change}");
        }
        let bytes = canonical(&original).unwrap();
        assert_eq!(
            StateFactValue::from_payload(&bytes, "participant", "privacy").unwrap(),
            original
        );
        assert!(StateFactValue::from_payload(&bytes, "other", "privacy").is_err());
        let mut forged = serde_json::to_value(original).unwrap();
        forged["ready"] = true.into();
        assert!(
            StateFactValue::from_payload(&canonical(&forged).unwrap(), "participant", "privacy")
                .is_err()
        );
    }
    #[test]
    fn external_occurrence_requires_typed_binding_and_detects_changed_response() {
        use pc_facts_core::{FactObject, FactSubject};
        let mut original = value("participant", "privacy", 1);
        original.mapping = "openpc:external-decision-observation:v1".into();
        original.typed_result.clear();
        original.specialization = Some((
            FactSubject::ExternalDecision {
                provider_id: "provider".into(),
                provider_version: "1".into(),
                configuration_digest: format!("sha256:{}", Digest::of(b"configuration").as_str()),
                source_occurrence: format!("sha256:{}", Digest::of(b"occurrence").as_str()),
                request_digest: format!("sha256:{}", Digest::of(b"request").as_str()),
                condition: "eligible".into(),
            },
            FactObject::ExternalObservation {
                satisfied: true,
                response_digest: format!("sha256:{}", Digest::of(b"response").as_str()),
            },
        ));
        let key = original.occurrence().unwrap();
        let bytes = canonical(&original).unwrap();
        assert_eq!(
            StateFactValue::from_payload(&bytes, "participant", "privacy").unwrap(),
            original
        );
        let mut changed = original.clone();
        changed.binding_revision = "2".into();
        changed.runtime_binding_id = Uuid::now_v7();
        assert_eq!(changed.occurrence().unwrap().digest, key.digest);
        if let Some((_, FactObject::ExternalObservation { satisfied, .. })) =
            &mut changed.specialization
        {
            *satisfied = false;
        }
        assert_eq!(changed.occurrence().unwrap().digest, key.digest);
        assert_ne!(changed.occurrence().unwrap().value_digest, key.value_digest);
        changed.specialization = None;
        changed.typed_result = vec![ArgumentValue::Bool(true)];
        assert!(
            StateFactValue::from_payload(&canonical(&changed).unwrap(), "participant", "privacy")
                .is_err()
        );
        changed = original.clone();
        changed.privacy_domain_id = "foreign".into();
        assert_ne!(changed.occurrence().unwrap().digest, key.digest);
        changed = original;
        if let Some((FactSubject::ExternalDecision { request_digest, .. }, _)) =
            &mut changed.specialization
        {
            *request_digest = format!("sha256:{}", Digest::of(b"other-request").as_str());
        }
        assert_ne!(changed.occurrence().unwrap().digest, key.digest);
    }
}
