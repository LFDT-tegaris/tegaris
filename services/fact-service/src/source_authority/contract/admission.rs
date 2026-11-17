//! Construct facts only from independently observed, ABI-checked source values.
//! Candidate provenance/finality labels are compared, never promoted to trust.
use super::*;
use crate::state_value::StateFactValue;
use crate::{FactFeedEvent, workload_authority::FactWorkloadAdmission};
use pc_facts_core::{FactAdmissionCandidate, TrustedAdmissionContext, sha256};

mod record;
pub(crate) use record::StateFactRecordSource;

pub(crate) struct ObservedStateAdmission {
    pub candidate: FactAdmissionCandidate,
    pub trusted: TrustedAdmissionContext,
    pub record_source: StateFactRecordSource,
}

impl CurrentFactContract<'_> {
    pub(crate) fn admission(
        &self,
        material: &CandidateMaterial,
        observations: &[BoundFactObservation],
        workload: &FactWorkloadAdmission,
        event: &FactFeedEvent,
        fact_sequence: u64,
    ) -> Result<ObservedStateAdmission> {
        self.assert_fresh()?;
        let source = &material.source;
        let inputs = &source.inputs;
        let profile = inputs.profile();
        let plan = inputs.plan();
        let now_ms = now_ns()? / 1_000_000;
        if workload.participant_id != self.source.participant
            || workload.privacy_domain_id != self.source.privacy
            || workload.resource_id != format!("urn:openpc:resource:{}", material.candidate_id)
            || event.candidate_id.as_deref() != Some(material.candidate_id.to_string().as_str())
            || material.record_sequence != event.record_ordinal
            || event.batch.range_start > material.block_number
            || event.batch.range_end < material.block_number
            || plan.partitions.len() != 1
            || plan.partitions[0].partition_id != source.partition_id
            || observations.len() != self.providers().len()
            || observations.len() < usize::from(inputs.finality_rule().required_observations)
            || material.observed_at_ms < 0
            || material.observed_at_ms as u64 > now_ms
        {
            return Err(SourceAuthorityError::Binding);
        }
        let mut provider_ids = std::collections::BTreeSet::new();
        let mut value = None;
        let mut evidence = Vec::new();
        let mut observed_at_ms = u64::MAX;
        let mut expires_at_ms = self.source.valid_until_ns.min(workload.expires_at_ns) / 1_000_000;
        let mut anchor = None;
        for bound in observations {
            let projection = self.project(material, bound)?;
            let observation = &bound.observation;
            let mapping = match &self.admission_profile.mapping {
                pc_policy_core::fact_profile::StateFactMapping::AbiStateResultV1 => {
                    "openpc:abi-state-result:v1"
                }
                pc_policy_core::fact_profile::StateFactMapping::RgraEventRelationshipV1 {
                    ..
                } => "RGRA_EVENT_RELATIONSHIP_V1",
                pc_policy_core::fact_profile::StateFactMapping::ExternalDecisionAdapterV1 {
                    provider_id,
                    provider_version,
                    provider_configuration_digest,
                    ..
                } => {
                    if observations.len() != 1
                        || provider_id != &observation.connection().provider_id
                        || provider_version != &bound.provider_profile_version
                        || provider_configuration_digest != &bound.provider_artifact_digest
                        || !matches!(
                            &projection.specialization,
                            Some((
                                pc_facts_core::FactSubject::ExternalDecision { .. },
                                pc_facts_core::FactObject::ExternalObservation { .. }
                            ))
                        )
                    {
                        return Err(SourceAuthorityError::Binding);
                    }
                    "openpc:external-decision-observation:v1"
                }
            };
            if !provider_ids.insert(observation.connection().provider_id.clone())
                || material.finality_head_number != Some(observation.head_number())
                || material.finality_head_hash.as_deref().map(hex).as_deref()
                    != Some(observation.head_hash().as_str())
            {
                return Err(SourceAuthorityError::Binding);
            }
            // The stable value excludes observation timestamps/credentials. Those
            // belong in signed provenance, so concurrent delivery can reconcile.
            let current = StateFactValue {
                mapping: mapping.into(),
                participant_id: profile.participant_binding.clone(),
                privacy_domain_id: profile.privacy_binding.clone(),
                chain_id: profile.chain_id.clone(),
                network_id: profile.network_id.clone(),
                genesis_hash: profile.genesis_hash.clone(),
                block_number: material.block_number.to_string(),
                block_hash: hex(&material.block_hash),
                target_address: hex(&self.query.target),
                code_digest: self.query.code_digest.clone(),
                runtime_binding_id: projection.runtime_binding_id,
                binding_revision: projection.binding_revision.to_string(),
                abi_digest: projection.abi_digest,
                signature: projection.canonical_signature,
                typed_arguments: projection.arguments,
                typed_result: projection.result,
                specialization: projection.specialization,
                transaction_index: material.transaction_index,
                log_index: material.log_index,
            };
            let current_anchor = serde_json::json!({"chainId":profile.chain_id,"networkId":profile.network_id,
                "genesisHash":profile.genesis_hash,"blockNumber":material.block_number.to_string(),
                "blockHash":hex(&material.block_hash),"finalityRuleDigest":profile.finality_rule_digest,
                "headNumber":observation.head_number().to_string(),"headHash":observation.head_hash()});
            if value.as_ref().is_some_and(|prior| prior != &current)
                || anchor
                    .as_ref()
                    .is_some_and(|prior| prior != &current_anchor)
            {
                return Err(SourceAuthorityError::Binding);
            }
            value = Some(current);
            anchor = Some(current_anchor);
            observed_at_ms = observed_at_ms.min(observation.completed_at_ms());
            expires_at_ms = expires_at_ms.min(observation.valid_until_ms());
            evidence.push(serde_json::json!({"provider":observation.connection(),
                "providerArtifactDigest":bound.provider_artifact_digest,"observationDigest":projection.observation_digest,
                "canonicalBlocks":observation.canonical_blocks(),
                "observedAtMs":observation.completed_at_ms().to_string(),"validUntilMs":observation.valid_until_ms().to_string()}));
        }
        expires_at_ms = expires_at_ms.min(
            observed_at_ms
                .checked_add(self.admission_profile.maximum_staleness_ms)
                .ok_or(SourceAuthorityError::Expired)?,
        );
        if observed_at_ms > now_ms || now_ms >= expires_at_ms {
            return Err(SourceAuthorityError::Expired);
        }
        let canonical_payload =
            crate::state_value::canonical(value.as_ref().ok_or(SourceAuthorityError::Binding)?)
                .map_err(|_| SourceAuthorityError::Binding)?;
        let finality_anchor = sha256(&canonical(
            anchor.as_ref().ok_or(SourceAuthorityError::Binding)?,
        )?);
        let publication = inputs.source();
        let canonical_provenance = canonical(&serde_json::json!({
            "purpose":"openpc:independent-state-admission:v1", "workload":workload,
            "factAdmissionProfile":self.admission_profile,
            "factAdmissionProfileDigest":Digest::of(self.admission_profile.to_cbor()
                .map_err(|_| SourceAuthorityError::Binding)?),
            "sourceProfileId":source.source_profile_id,"sourceId":source.source_id,"partitionId":source.partition_id,
            "sourceRevision":publication.source_revision.to_string(),"qualificationOperationId":publication.qualification_operation_id,
            "projectionPlanId":publication.projection_plan_id,"projectionRevision":publication.projection_revision.to_string(),
            "validationOperationId":publication.validation_operation_id,"configurationDigest":publication.configuration_digest,
            "sourceProfileDigest":Digest::of(&publication.profile_cbor),"mappingManifestDigest":Digest::of(&publication.plan_cbor),
            "publicationDigest":format!("sha256:{}",hex(&inputs.published().publication_digest)),
            "sourceCandidateId":material.candidate_id,"sourcePayloadDigest":Digest::of(&material.payload_cbor),
            "sourceObservedAtMs":material.observed_at_ms.to_string(),"sourceCheckpointId":material.checkpoint_id,
            "sourceCheckpointDigest":hex(&material.checkpoint_digest),"derivationDigest":Digest::of(&canonical_payload),
            "finalityAnchor":hex(&finality_anchor),"providerObservations":evidence,
        }))?;
        let provenance_digest = sha256(&canonical_provenance);
        let schema = pc_facts_core::fact_schema_identity(if self.event_signature.is_some() {
            pc_facts_core::RELATIONSHIP_CANDIDATE_SCHEMA_ID
        } else {
            pc_facts_core::FACT_ADMISSION_CANDIDATE_SCHEMA_ID
        })
        .ok_or(SourceAuthorityError::Binding)?;
        let candidate = FactAdmissionCandidate {
            candidate_id: material.candidate_id.to_string(),
            participant_id: profile.participant_binding.clone(),
            privacy_domain_id: profile.privacy_binding.clone(),
            source_profile_id: source.source_profile_id.to_string(),
            generation_id: event.batch.fact_generation_id.clone(),
            schema_id: schema.numeric_schema_id,
            schema_version: pc_facts_core::FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: *pc_facts_core::record_schema_digest(self.event_signature.is_some()),
            schema_purpose: schema.purpose_separator.into(),
            sequence: fact_sequence,
            observed_at_ms: i64::try_from(observed_at_ms)
                .map_err(|_| SourceAuthorityError::Binding)?,
            declared_payload_digest: sha256(&canonical_payload),
            canonical_payload,
            declared_provenance_digest: provenance_digest,
            canonical_provenance,
            finality_anchor,
            complete: true,
            semantic_valid: true,
            conflict_detected: false,
            terminal_denial: false,
        };
        let trusted = TrustedAdmissionContext {
            participant_id: candidate.participant_id.clone(),
            privacy_domain_id: candidate.privacy_domain_id.clone(),
            source_profile_id: candidate.source_profile_id.clone(),
            generation_id: candidate.generation_id.clone(),
            expected_sequence: fact_sequence,
            now_ms: i64::try_from(now_ms).map_err(|_| SourceAuthorityError::Binding)?,
            maximum_age_ms: i64::try_from(expires_at_ms - observed_at_ms)
                .map_err(|_| SourceAuthorityError::Binding)?,
            independently_derived_provenance_digest: provenance_digest,
            trusted_finality_anchor: finality_anchor,
            profile_active: true,
            generation_fenced: false,
        };
        let record_source = StateFactRecordSource::new(
            &self.admission_profile,
            value.ok_or(SourceAuthorityError::Binding)?,
            workload,
            &inputs.finality_rule().rule_id,
            sha256(&material.payload_cbor),
        )?;
        Ok(ObservedStateAdmission {
            candidate,
            trusted,
            record_source,
        })
    }
}

fn canonical(value: &serde_json::Value) -> Result<Vec<u8>> {
    let value =
        ciborium::value::Value::serialized(value).map_err(|_| SourceAuthorityError::Binding)?;
    pc_facts_core::encode_pc_cbor(value).map_err(|_| SourceAuthorityError::Binding)
}
