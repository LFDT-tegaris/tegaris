//! Complete record input captured only after the real contract mapper has
//! independently checked source values and retained current authority custody.
use super::*;
use crate::store::identity::FactIdentityAllocation;
use pc_facts_core::{
    CanonicalFactIdentity, FACT_SCHEMA_VERSION_V1, FactChainAnchor, FactCompletenessScope,
    FactGapState, FactLifecycleState, FactObject, FactRecord, FactSubject, ValidatedAdmission,
    fact_timestamp_from_ms,
};
use pc_policy_core::fact_profile::StateFactProfile;

pub(crate) struct StateFactRecordSource {
    profile: StateFactProfile,
    value: StateFactValue,
    platform_epoch: u64,
    envelope: Uuid,
    delegation_epoch: u64,
    finality_rule: String,
    source_digest: [u8; 32],
}

impl StateFactRecordSource {
    pub(super) fn new(
        profile: &StateFactProfile,
        value: StateFactValue,
        workload: &FactWorkloadAdmission,
        finality_rule: &str,
        source_digest: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            profile: profile.clone(),
            value,
            platform_epoch: workload
                .platform_authority_epoch
                .parse()
                .map_err(|_| SourceAuthorityError::Binding)?,
            envelope: workload.participant_authority_envelope_id,
            delegation_epoch: workload
                .delegation_epoch
                .parse()
                .map_err(|_| SourceAuthorityError::Binding)?,
            finality_rule: finality_rule.into(),
            source_digest,
        })
    }

    pub(crate) fn profile_urn(&self) -> String {
        format!("urn:openpc:fact-profile:{}", self.profile.fact_profile_id)
    }

    pub(crate) fn retained_tail_blocks(&self) -> u64 {
        self.profile.reorg_retained_tail_blocks
    }

    pub(crate) fn shard_entry_limit(&self) -> u64 {
        u64::from(self.profile.shard_entry_limit)
    }

    pub(crate) fn record(
        &self,
        allocation: &FactIdentityAllocation,
        admission: &ValidatedAdmission,
        event: &FactFeedEvent,
        key_id: &str,
    ) -> std::result::Result<FactRecord, pc_facts_core::AdmissionError> {
        use pc_facts_core::AdmissionError;
        let value = &self.value;
        let batch = &event.batch;
        if crate::state_value::canonical(value)? != admission.canonical_payload()
            || value.participant_id != admission.participant_id()
            || value.privacy_domain_id != admission.privacy_domain_id()
            || batch.record_count == 0
            || batch.record_count > self.shard_entry_limit()
        {
            return Err(AdmissionError::SemanticOrPrivacy);
        }
        let (subject, object) = match &self.profile.mapping {
            pc_policy_core::fact_profile::StateFactMapping::RgraEventRelationshipV1 { .. } => value
                .specialization
                .clone()
                .ok_or(AdmissionError::SemanticOrPrivacy)?,
            pc_policy_core::fact_profile::StateFactMapping::AbiStateResultV1 => (
                FactSubject::ContractStateCall {
                    contract_address: format!("0x{}", value.target_address),
                    code_digest: format!("sha256:{}", value.code_digest.as_str()),
                    abi_digest: format!("sha256:{}", value.abi_digest.as_str()),
                    canonical_signature: value.signature.clone(),
                    arguments: value.typed_arguments.clone(),
                },
                FactObject::AbiResult {
                    values: value.typed_result.clone(),
                },
            ),
            pc_policy_core::fact_profile::StateFactMapping::ExternalDecisionAdapterV1 {
                provider_id,
                provider_version,
                provider_configuration_digest,
                condition,
            } => {
                let Some((
                    FactSubject::ExternalDecision {
                        provider_id: id,
                        provider_version: version,
                        configuration_digest,
                        condition: observed_condition,
                        ..
                    },
                    FactObject::ExternalObservation { .. },
                )) = &value.specialization
                else {
                    return Err(AdmissionError::SemanticOrPrivacy);
                };
                if id != provider_id
                    || version != provider_version
                    || configuration_digest
                        != &format!("sha256:{}", provider_configuration_digest.as_str())
                    || observed_condition != condition
                {
                    return Err(AdmissionError::SemanticOrPrivacy);
                }
                value
                    .specialization
                    .clone()
                    .ok_or(AdmissionError::SemanticOrPrivacy)?
            }
        };
        let identity = CanonicalFactIdentity {
            fact_id: format!("urn:openpc:fact:{}", allocation.fact_id),
            fact_profile_id: self.profile_urn(),
            fact_semantic_version: self.profile.fact_semantic_version.clone(),
            fact_schema_id: pc_facts_core::record_schema(matches!(
                subject,
                FactSubject::Relationship { .. }
            )),
            fact_schema_version: FACT_SCHEMA_VERSION_V1.into(),
            fact_schema_digest: digest(pc_facts_core::record_schema_digest(matches!(
                subject,
                FactSubject::Relationship { .. }
            ))),
            typed_subject: subject,
            typed_object: object.clone(),
            participant_id: format!("urn:openpc:participant:{}", value.participant_id),
            privacy_domain_id: Some(format!(
                "urn:openpc:privacy-domain:{}",
                value.privacy_domain_id
            )),
            platform_authority_epoch: self.platform_epoch,
            participant_authority_envelope_id: format!(
                "urn:openpc:authority-envelope:{}",
                self.envelope
            ),
            delegation_epoch: self.delegation_epoch,
            chain_anchor: FactChainAnchor {
                chain_id: value.chain_id.clone(),
                genesis_hash: format!(
                    "0x{}",
                    crate::source_authority::digest(&value.genesis_hash)
                        .map_err(|_| AdmissionError::SemanticOrPrivacy)?
                        .as_str()
                ),
                network_id: value.network_id.clone(),
                block_height: value
                    .block_number
                    .parse()
                    .map_err(|_| AdmissionError::SemanticOrPrivacy)?,
                block_hash: format!("0x{}", value.block_hash),
                finality_rule_id: self.finality_rule.clone(),
                transaction_index: value.transaction_index,
                log_index: value.log_index,
            },
            canonical_generation: allocation.generation,
            admission_policy_version: self.profile.admission_policy_version.clone(),
            admission_policy_digest: digest(&sha256(
                &self
                    .profile
                    .to_cbor()
                    .map_err(|_| AdmissionError::SemanticOrPrivacy)?,
            )),
            local_signing_key_id: key_id.into(),
            local_fact_digest: String::new(),
            fact_status: FactLifecycleState::Admitted,
        }
        .with_derived_digest()?;
        let record = FactRecord {
            identity,
            value: object,
            not_before: fact_timestamp_from_ms(admission.observed_at_ms())?,
            expires_at: fact_timestamp_from_ms(admission.fresh_until_ms())?,
            max_age_ms: self.profile.maximum_staleness_ms,
            completeness_scope: FactCompletenessScope {
                partition_id: format!("urn:openpc:candidate-partition:{}", batch.partition_id),
                range_start: batch.range_start,
                range_end: batch.range_end,
                record_count: batch.record_count,
                checkpoint_id: format!("urn:openpc:fact-checkpoint:{}", batch.checkpoint_id),
                checkpoint_digest: digest(&batch.checkpoint_digest),
            },
            gap_state: FactGapState::Complete,
            source_digest: digest(&self.source_digest),
            derivation_digest: digest(admission.payload_digest()),
            provenance_digest: digest(admission.provenance_digest()),
            predecessor_digest: allocation.predecessor_digest.as_ref().map(digest),
            relationship_predecessor_digest: None,
            relationship_candidate_cose: None,
            snapshot_root: String::new(),
            delta_sequence: allocation.sequence,
            replacement_generation: None,
            reorg_replacement_of: None,
            admitted_at: allocation.admitted_at.clone(),
            finalized_at: None,
        };
        if batch.record_count == 1 {
            record.with_single_entry_root()
        } else {
            Ok(record)
        }
    }
}

#[cfg(test)]
impl StateFactRecordSource {
    pub(crate) fn fixture_mapping(
        candidate: &FactAdmissionCandidate,
        profile_id: Uuid,
        mapping: pc_policy_core::fact_profile::StateFactMapping,
    ) -> Self {
        let mut source = Self::fixture(candidate, profile_id);
        source.profile.mapping = mapping;
        source.profile.shard_entry_limit = 64;
        source
    }
    /// An explicit persistence-owner fixture. This proves no source authority.
    pub(crate) fn fixture(candidate: &FactAdmissionCandidate, profile_id: Uuid) -> Self {
        use pc_policy_core::fact_profile::StateFactMapping;
        Self {
            profile: StateFactProfile {
                schema_version: "1.0.0".into(),
                fact_profile_id: profile_id.to_string(),
                fact_semantic_version: "1.0.0".into(),
                admission_policy_version: "1.0.0".into(),
                participant_id: candidate.participant_id.clone(),
                privacy_domain_id: candidate.privacy_domain_id.clone(),
                source_profile_id: candidate.source_profile_id.clone(),
                projection_plan_id: profile_id.to_string(),
                projection_plan_digest: Digest::of(b"installed-test-plan"),
                mapping: StateFactMapping::AbiStateResultV1,
                maximum_staleness_ms: 60_000,
                reorg_retained_tail_blocks: 16,
                shard_entry_limit: 2,
            },
            value: StateFactValue::from_payload(
                &candidate.canonical_payload,
                &candidate.participant_id,
                &candidate.privacy_domain_id,
            )
            .unwrap(),
            platform_epoch: 7,
            envelope: profile_id,
            delegation_epoch: 3,
            finality_rule: format!("urn:openpc:finality-rule:{profile_id}"),
            source_digest: sha256(&candidate.canonical_payload),
        }
    }
}

fn digest(bytes: &[u8; 32]) -> String {
    format!("sha256:{}", hex(bytes))
}
