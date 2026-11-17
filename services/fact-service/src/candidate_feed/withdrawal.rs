//! A candidate-manager withdrawal occurrence is data. Independent Control
//! confirmation and the exact signed local admission must precede retirement.
use super::*;
use pc_facts_core::{sha256, validate_pc_cbor};
use serde_json::json;

pub(crate) struct SourceFence {
    pub participant: Uuid,
    pub privacy: Uuid,
    pub partition: Uuid,
    pub generation: Uuid,
    pub event_id: Uuid,
    pub correlation_id: Uuid,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub publication_digest: Vec<u8>,
    pub publication: ciborium::Value,
    pub source_profile: Uuid,
    pub terminal_prefix: Option<super::closure::WithdrawalPrefix>,
}

impl SourceFence {
    pub fn publication_text(&self, name: &str) -> Result<&str, CandidateFeedError> {
        self.publication
            .as_map()
            .and_then(|fields| fields.iter().find(|(key, _)| key.as_text() == Some(name)))
            .and_then(|(_, value)| value.as_text())
            .ok_or(CandidateFeedError::Material)
    }
}

impl CandidateFeedRead {
    pub(crate) async fn source_fence(
        &mut self,
        sequence: u64,
    ) -> Result<Option<SourceFence>, CandidateFeedError> {
        let Some(event) = self.event(sequence).await? else {
            return Ok(None);
        };
        if matches!(
            event.event_type.as_str(),
            "io.openpc.indexer.projection.candidate.observed.v1"
                | "io.openpc.indexer.projection.checkpoint.completed.v1"
        ) {
            return Ok(None);
        }
        if event.event_type != "io.openpc.indexer.projection.source.fenced.v1"
            || event.schema_uri
                != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionSourceFenced"
            || !matches!(
                event.publication_state.as_deref(),
                Some("FENCED" | "RETIRED")
            )
            || !matches!(
                event.generation_state.as_str(),
                "STALE" | "REORG" | "RETIRED" | "FAILED"
            )
            || sha256(&event.payload_cbor).as_slice() != event.payload_digest
        {
            return Err(CandidateFeedError::Material);
        }
        validate_pc_cbor(&event.payload_cbor).map_err(|_| CandidateFeedError::Material)?;
        let row = sqlx::query("select publication_cbor,publication_digest,correlation_id,source_profile_id from candidate.fact_bridge_admission_v1
            where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3 and outbox_sequence=$4::numeric")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(sequence.to_string())
            .fetch_one(&mut *self.transaction).await?;
        let bytes: Vec<u8> = row.try_get("publication_cbor")?;
        let publication_digest: Vec<u8> = row.try_get("publication_digest")?;
        if bytes.len() > 131072 || sha256(&bytes).as_slice() != publication_digest {
            return Err(CandidateFeedError::Material);
        }
        validate_pc_cbor(&bytes).map_err(|_| CandidateFeedError::Material)?;
        let payload: serde_json::Value = ciborium::de::from_reader(event.payload_cbor.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        if payload
            != json!({
                "candidatePartitionId":format!("urn:openpc:candidate-partition:{}",self.partition),
                "projectionGenerationId":format!("urn:openpc:projection-generation:{}",event.generation_id),
                "publicationDigest":crate::signing::shard::digest_text(&publication_digest),
                "reasonCode":"GOVERNED_SOURCE_NOT_CURRENT","authority":"CANDIDATE_ONLY",
            })
        {
            return Err(CandidateFeedError::Material);
        }
        let mut fence = SourceFence {
            participant: self.scope.participant,
            privacy: self.scope.privacy,
            partition: self.partition,
            generation: event.generation_id,
            event_id: event.event_id,
            correlation_id: row.try_get("correlation_id")?,
            sequence,
            payload: event.payload_cbor,
            publication_digest,
            publication: ciborium::de::from_reader(bytes.as_slice())
                .map_err(|_| CandidateFeedError::Material)?,
            source_profile: row.try_get("source_profile_id")?,
            terminal_prefix: None,
        };
        if fence.publication_text("participantId")? != fence.participant.to_string()
            || fence.publication_text("privacyDomainId")? != fence.privacy.to_string()
            || fence.publication_text("purpose")?
                != "openpc:governed-candidate-source-publication:v1"
        {
            return Err(CandidateFeedError::Scope);
        }
        fence.terminal_prefix = self.withdrawal_prefix(&fence).await?;
        Ok(Some(fence))
    }
}
