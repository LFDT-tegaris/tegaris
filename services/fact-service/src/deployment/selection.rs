//! Scoped candidate preview for the existing Fact runtime command. This is
//! immutable input selection, never an authority or readiness assertion.
use super::*;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateSelection {
    pub candidate_id: Uuid,
    pub partition_id: Uuid,
    pub candidate_sequence: String,
    pub source_profile_id: Uuid,
    pub source_generation_id: String,
    pub checkpoint_id: Uuid,
    pub payload_digest: Digest,
    pub publication_digest: Digest,
    pub etag: String,
    pub authority: &'static str,
    pub observed_at_ms: i64,
    pub configuration_digest: String,
}

impl DeployedFactBridge {
    pub async fn select_artifact(
        &self,
        scope: CandidateReadScope,
        candidate: Uuid,
    ) -> Result<Option<CandidateSelection>, CandidateFeedError> {
        if (scope.participant, scope.privacy) != self.scope() {
            return Err(CandidateFeedError::Scope);
        }
        let next_scope =
            CandidateReadScope::new(scope.participant, scope.privacy, scope.operation)?;
        let Some((partition, sequence)) = self
            .authenticated_candidates()
            .await?
            .locate(scope, candidate)
            .await?
        else {
            return Ok(None);
        };
        self.select_candidate(next_scope, partition, sequence)
            .await
            .map(Some)
    }

    pub fn scope(&self) -> (Uuid, Uuid) {
        (self.input.participant_id, self.input.privacy_domain_id)
    }

    pub async fn select_candidate(
        &self,
        scope: CandidateReadScope,
        partition: Uuid,
        sequence: u64,
    ) -> Result<CandidateSelection, CandidateFeedError> {
        if (scope.participant, scope.privacy) != self.scope() {
            return Err(CandidateFeedError::Scope);
        }
        let mut feed = self
            .authenticated_candidates()
            .await?
            .read_partition(scope, partition)
            .await?;
        let material = feed.candidate(sequence).await?;
        let publication_digest = Digest::parse(
            material
                .source
                .inputs
                .published()
                .publication_digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .map_err(|_| CandidateFeedError::Material)?;
        let payload_digest = Digest::of(&material.payload_cbor);
        let selected = serde_json::json!({
            "purpose":"openpc:fact-admission-selection:v1",
            "participantId":self.input.participant_id,"privacyDomainId":self.input.privacy_domain_id,
            "partitionId":partition,"candidateSequence":sequence.to_string(),
            "candidateId":material.candidate_id,"checkpointId":material.checkpoint_id,
            "publicationDigest":publication_digest,"payloadDigest":payload_digest,
        });
        let digest =
            Digest::of(serde_json::to_vec(&selected).map_err(|_| CandidateFeedError::Material)?);
        feed.close().await?;
        Ok(CandidateSelection {
            candidate_id: material.candidate_id,
            partition_id: partition,
            candidate_sequence: sequence.to_string(),
            source_profile_id: material.source.source_profile_id,
            source_generation_id: material
                .source
                .inputs
                .published()
                .projection_generation_id
                .to_string(),
            checkpoint_id: material.checkpoint_id,
            payload_digest,
            publication_digest,
            etag: format!("\"sha256:{}\"", digest.as_str()),
            authority: "NON_AUTHORITATIVE_CANDIDATE",
            observed_at_ms: material.observed_at_ms,
            configuration_digest: material.source.inputs.source().configuration_digest.clone(),
        })
    }
}
