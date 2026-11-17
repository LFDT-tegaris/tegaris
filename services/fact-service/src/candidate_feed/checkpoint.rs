//! Checkpoint-only batches use the existing feed and never invent a candidate.
use super::*;
use crate::{FactFeedBatch, FactFeedEvent};
use pc_facts_core::{sha256, validate_pc_cbor};
use serde_json::{Value, json};

pub(crate) struct CheckpointBlock {
    pub number: u64,
    pub hash: Vec<u8>,
    pub parent: Vec<u8>,
    pub head_number: u64,
    pub head_hash: Vec<u8>,
}
pub(crate) struct EmptyCheckpoint {
    pub source: CandidateSourceMaterial,
    pub event: FactFeedEvent,
    pub blocks: Vec<CheckpointBlock>,
}

impl CandidateFeedRead {
    pub(crate) async fn checkpoint_blocks(
        &mut self,
        checkpoint: Uuid,
        start: u64,
        end: u64,
    ) -> Result<Vec<CheckpointBlock>, CandidateFeedError> {
        let rows = sqlx::query("select block_number::text,block_hash,parent_hash,finality_head_number::text,finality_head_hash from candidate.fact_bridge_checkpoint_blocks_v1 where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3 and checkpoint_id=$4 order by block_number limit 65")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(checkpoint)
            .fetch_all(&mut *self.transaction).await?;
        if end.checked_sub(start).and_then(|v| v.checked_add(1)) != Some(rows.len() as u64)
            || rows.is_empty()
            || rows.len() > 64
        {
            return Err(CandidateFeedError::Material);
        }
        let mut blocks: Vec<CheckpointBlock> = Vec::new();
        for row in rows {
            let number = row
                .try_get::<String, _>("block_number")?
                .parse()
                .map_err(|_| CandidateFeedError::Material)?;
            let block = CheckpointBlock {
                number,
                hash: row.try_get("block_hash")?,
                parent: row.try_get("parent_hash")?,
                head_number: row
                    .try_get::<String, _>("finality_head_number")?
                    .parse()
                    .map_err(|_| CandidateFeedError::Material)?,
                head_hash: row.try_get("finality_head_hash")?,
            };
            if number != start + blocks.len() as u64
                || block.hash.len() != 32
                || block.parent.len() != 32
                || block.head_hash.len() != 32
                || blocks.last().is_some_and(|prior| {
                    prior.hash != block.parent
                        || prior.head_number != block.head_number
                        || prior.head_hash != block.head_hash
                })
            {
                return Err(CandidateFeedError::Material);
            }
            blocks.push(block);
        }
        Ok(blocks)
    }
    pub(crate) async fn empty_checkpoint(
        &mut self,
        sequence: u64,
    ) -> Result<Option<EmptyCheckpoint>, CandidateFeedError> {
        let Some(event) = self.event(sequence).await? else {
            return Ok(None);
        };
        if event.event_type != "io.openpc.indexer.projection.checkpoint.completed.v1" {
            return Ok(None);
        }
        if event.schema_uri
            != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCheckpointCompleted"
            || event.publication_state.as_deref() != Some("PUBLISHED")
            || !matches!(event.generation_state.as_str(), "READY" | "ACTIVE")
            || sha256(&event.payload_cbor).as_slice() != event.payload_digest
        {
            return Err(CandidateFeedError::Material);
        }
        validate_pc_cbor(&event.payload_cbor).map_err(|_| CandidateFeedError::Material)?;
        let row = sqlx::query("select v.*,batch_sequence::text sequence_text,batch_range_start::text start_text,batch_range_end::text end_text from candidate.fact_bridge_admission_v1 v where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3 and outbox_sequence=$4::numeric")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(sequence.to_string()).fetch_one(&mut *self.transaction).await?;
        let source = material::source_material(&row, self.scope.participant, self.scope.privacy)?;
        if !row.try_get::<bool, _>("authoritative_empty")?
            || row.try_get::<String, _>("checkpoint_state")? != "COMPLETE"
        {
            return Err(CandidateFeedError::Material);
        }
        let bytes: Vec<u8> = row.try_get("checkpoint_cbor")?;
        let checkpoint_digest: Vec<u8> = row.try_get("checkpoint_digest")?;
        validate_pc_cbor(&bytes).map_err(|_| CandidateFeedError::Material)?;
        if sha256(&bytes).as_slice() != checkpoint_digest {
            return Err(CandidateFeedError::Material);
        }
        let checkpoint: Value = ciborium::de::from_reader(bytes.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        let parse = |key| -> Result<u64, CandidateFeedError> {
            row.try_get::<String, _>(key)?
                .parse()
                .map_err(|_| CandidateFeedError::Material)
        };
        let start = parse("start_text")?;
        let end = parse("end_text")?;
        let id = row.try_get("checkpoint_id")?;
        let blocks = self.checkpoint_blocks(id, start, end).await?;
        let batch_digest: Vec<u8> = row.try_get("batch_digest")?;
        let predecessor: Option<Vec<u8>> = row.try_get("predecessor_batch_digest")?;
        let digest = |v: &[u8]| {
            format!(
                "sha256:{}",
                v.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        };
        let counts: i64=sqlx::query_scalar("select count(*) from candidate.fact_bridge_admission_v1 where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3 and checkpoint_id=$4")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(id).fetch_one(&mut *self.transaction).await?;
        let expected = json!({"authoritativeEmpty":true,"batchId":row.try_get::<String,_>("batch_id")?,"batchSequence":parse("sequence_text")?.to_string(),
            "completedWatermark":{"blockNumber":end.to_string(),"blockHash":format!("0x{}",&digest(&blocks.last().unwrap().hash)[7..])},
            "decodeFailures":[],"missingIntervals":[],"orderedObservationEvidence":checkpoint["orderedObservationEvidence"],
            "partitionId":source.partition_id,"planDigest":format!("sha256:{}",source.inputs.plan().plan_digest.trim_start_matches("sha256:")),
            "predecessorBatchDigest":predecessor.as_deref().map(digest),"profileDigest":format!("sha256:{}",source.inputs.profile().profile_digest.trim_start_matches("sha256:")),
            "range":{"start":start.to_string(),"end":end.to_string()},"recordCount":"0","sourceId":source.source_id});
        let value: Value = ciborium::de::from_reader(event.payload_cbor.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        if counts != 1
            || checkpoint != expected
            || value
                != json!({"candidatePartitionId":format!("urn:openpc:candidate-partition:{}",self.partition),
            "indexerProfileId":format!("urn:openpc:indexer-profile:{}",source.inputs.source().indexer_profile_id),"projectionGenerationId":format!("urn:openpc:projection-generation:{}",event.generation_id),
            "batchId":checkpoint["batchId"],"batchDigest":digest(&batch_digest),"predecessorBatchDigest":checkpoint["predecessorBatchDigest"],"range":checkpoint["range"],
            "checkpointDigest":digest(&checkpoint_digest),"orderedObservationEvidence":checkpoint["orderedObservationEvidence"],"missingIntervals":[],"decodeFailures":[],"recordCount":"0","authoritativeEmpty":true,"authority":"CANDIDATE_ONLY"})
        {
            return Err(CandidateFeedError::Material);
        }
        let fixed = |v: Vec<u8>| v.try_into().map_err(|_| CandidateFeedError::Material);
        Ok(Some(EmptyCheckpoint {
            source,
            blocks,
            event: FactFeedEvent {
                batch: FactFeedBatch {
                    participant_id: self.scope.participant.to_string(),
                    privacy_domain_id: self.scope.privacy.to_string(),
                    partition_id: self.partition,
                    source_profile_id: row.try_get::<Uuid, _>("source_profile_id")?.to_string(),
                    source_generation_id: event.generation_id.to_string(),
                    fact_generation_id: id.to_string(),
                    checkpoint_id: id,
                    batch_sequence: parse("sequence_text")?,
                    batch_digest: fixed(batch_digest)?,
                    predecessor_batch_digest: predecessor.map(fixed).transpose()?,
                    range_start: start,
                    range_end: end,
                    record_count: 0,
                    checkpoint_digest: fixed(checkpoint_digest)?,
                },
                sequence,
                event_id: event.event_id,
                record_ordinal: 1,
                payload_cbor: event.payload_cbor,
                candidate_id: None,
            },
        }))
    }
}
