use super::*;
use crate::{FactFeedBatch, FactFeedEvent};
use pc_facts_core::{sha256, validate_pc_cbor};
use serde_json::{Value, json};

impl CandidateFeedRead {
    /// Load an entire checkpoint closure under the held repeatable-read snapshot.
    /// Callers name its first record; no suffix can stand in for a complete batch.
    pub(crate) async fn batch(
        &mut self,
        first_sequence: u64,
    ) -> Result<(Vec<(CandidateMaterial, FactFeedEvent)>, FactFeedEvent), CandidateFeedError> {
        let first = self.candidate(first_sequence).await?;
        let (event, closing) = self.receipt_events(&first, first.checkpoint_id).await?;
        let count = event.batch.record_count;
        if first.record_sequence != 1 || count == 0 || count > 1_000_000 {
            return Err(CandidateFeedError::Material);
        }
        let mut entries = vec![(first, event)];
        for ordinal in 2..=count {
            let sequence = first_sequence
                .checked_add(ordinal - 1)
                .ok_or(CandidateFeedError::Material)?;
            let material = self.candidate(sequence).await?;
            let (event, end) = self
                .receipt_events(&material, material.checkpoint_id)
                .await?;
            if event.batch != entries[0].1.batch
                || end != closing
                || material.record_sequence != ordinal
                || material.source.inputs.published().publication_digest
                    != entries[0].0.source.inputs.published().publication_digest
                || material.source.source_profile_id != entries[0].0.source.source_profile_id
            {
                return Err(CandidateFeedError::Material);
            }
            entries.push((material, event));
        }
        Ok((entries, closing))
    }

    /// Projects the actual observed and closing events from this one snapshot.
    /// The returned persistence inputs establish no independent admission trust.
    pub async fn receipt_events(
        &mut self,
        material: &CandidateMaterial,
        fact_generation: Uuid,
    ) -> Result<(FactFeedEvent, FactFeedEvent), CandidateFeedError> {
        let m = material;
        let source = m.source.inputs.source();
        if source.participant_id != self.scope.participant
            || source.privacy_domain_id != self.scope.privacy
            || fact_generation.get_version_num() != 7
        {
            return Err(CandidateFeedError::Scope);
        }
        let count = m.checkpoint["recordCount"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(CandidateFeedError::Material)?;
        let closing_sequence = count
            .checked_sub(m.record_sequence)
            .and_then(|v| v.checked_add(m.sequence))
            .and_then(|v| v.checked_add(1))
            .ok_or(CandidateFeedError::Material)?;
        let candidate = self
            .event(m.sequence)
            .await?
            .ok_or(CandidateFeedError::Material)?;
        let closing = self
            .event(closing_sequence)
            .await?
            .ok_or(CandidateFeedError::Material)?;
        let generation = m.source.inputs.published().projection_generation_id;
        for e in [&candidate, &closing] {
            if e.generation_id != generation
                || e.publication_state.as_deref() != Some("PUBLISHED")
                || !matches!(e.generation_state.as_str(), "READY" | "ACTIVE")
                || sha256(&e.payload_cbor).as_slice() != e.payload_digest
                || validate_pc_cbor(&e.payload_cbor).is_err()
            {
                return Err(CandidateFeedError::Material);
            }
        }
        let digest = |bytes: &[u8]| -> Result<String, CandidateFeedError> {
            let fixed: [u8; 32] = bytes.try_into().map_err(|_| CandidateFeedError::Material)?;
            Ok(format!(
                "sha256:{}",
                fixed.iter().map(|v| format!("{v:02x}")).collect::<String>()
            ))
        };
        let candidate_value: Value = ciborium::de::from_reader(candidate.payload_cbor.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        let closing_value: Value = ciborium::de::from_reader(closing.payload_cbor.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        if candidate.event_id != m.event_id
            || candidate.event_type != "io.openpc.indexer.projection.candidate.observed.v1"
            || candidate.schema_uri
                != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateObserved"
            || closing.event_type != "io.openpc.indexer.projection.checkpoint.completed.v1"
            || closing.schema_uri
                != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCheckpointCompleted"
            || candidate_value
                != json!({
                    "indexerProfileId":format!("urn:openpc:indexer-profile:{}",source.indexer_profile_id),
                    "candidateId":format!("urn:openpc:candidate:{}",m.candidate_id),
                    "candidateDigest":digest(&sha256(&m.payload_cbor))?,
                    "sourceCursorDigest":digest(&m.checkpoint_digest)?,"authority":"CANDIDATE_ONLY"
                })
            || closing_value
                != json!({
                    "candidatePartitionId":format!("urn:openpc:candidate-partition:{}",self.partition),
                    "indexerProfileId":format!("urn:openpc:indexer-profile:{}",source.indexer_profile_id),
                    "projectionGenerationId":format!("urn:openpc:projection-generation:{generation}"),
                    "batchId":m.checkpoint["batchId"],"batchDigest":digest(&m.batch_digest)?,
                    "predecessorBatchDigest":m.predecessor_batch_digest.as_deref().map(digest).transpose()?,
                    "range":{"start":m.range_start.to_string(),"end":m.range_end.to_string()},
                    "checkpointDigest":digest(&m.checkpoint_digest)?,
                    "orderedObservationEvidence":m.checkpoint["orderedObservationEvidence"],
                    "missingIntervals":[],"decodeFailures":[],"recordCount":count.to_string(),
                    "authoritativeEmpty":false,"authority":"CANDIDATE_ONLY"
                })
        {
            return Err(CandidateFeedError::Material);
        }
        let fixed = |value: &[u8]| value.try_into().map_err(|_| CandidateFeedError::Material);
        let batch = FactFeedBatch {
            participant_id: self.scope.participant.to_string(),
            privacy_domain_id: self.scope.privacy.to_string(),
            partition_id: self.partition,
            source_profile_id: m.source.source_profile_id.to_string(),
            source_generation_id: generation.to_string(),
            fact_generation_id: fact_generation.to_string(),
            checkpoint_id: m.checkpoint_id,
            batch_sequence: m.batch_sequence,
            batch_digest: fixed(&m.batch_digest)?,
            predecessor_batch_digest: m
                .predecessor_batch_digest
                .as_deref()
                .map(fixed)
                .transpose()?,
            range_start: m.range_start,
            range_end: m.range_end,
            record_count: count,
            checkpoint_digest: fixed(&m.checkpoint_digest)?,
        };
        Ok((
            FactFeedEvent {
                batch: batch.clone(),
                sequence: candidate.sequence,
                event_id: candidate.event_id,
                record_ordinal: m.record_sequence,
                payload_cbor: candidate.payload_cbor,
                candidate_id: Some(m.candidate_id.to_string()),
            },
            FactFeedEvent {
                batch,
                sequence: closing.sequence,
                event_id: closing.event_id,
                record_ordinal: count.checked_add(1).ok_or(CandidateFeedError::Material)?,
                payload_cbor: closing.payload_cbor,
                candidate_id: None,
            },
        ))
    }
}
