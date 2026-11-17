//! Candidate reorg observations remain untrusted until independently verified.
use super::*;
use pc_facts_core::{sha256, validate_pc_cbor};
use serde_json::json;

pub(crate) struct SourceReorg {
    pub scope: CandidateReadScope,
    pub partition: Uuid,
    pub source: CandidateSourceMaterial,
    pub event: CandidateFeedEvent,
    pub correlation: Uuid,
    pub start: u64,
    pub end: u64,
    pub old_hash: Vec<u8>,
    pub new_hash: Vec<u8>,
    pub candidates: std::collections::BTreeMap<Uuid, (u64, Vec<u8>)>,
}

impl CandidateFeedRead {
    pub(crate) async fn source_reorg(
        &mut self,
        sequence: u64,
    ) -> Result<Option<SourceReorg>, CandidateFeedError> {
        let Some(event) = self.event(sequence).await? else {
            return Ok(None);
        };
        if event.event_type != "io.openpc.indexer.projection.candidate.invalidated.v1" {
            return Ok(None);
        }
        if event.schema_uri
            != "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateInvalidated"
            || event.publication_state.as_deref() != Some("PUBLISHED")
            || !matches!(event.generation_state.as_str(), "READY" | "ACTIVE")
            || sha256(&event.payload_cbor).as_slice() != event.payload_digest
        {
            return Err(CandidateFeedError::Material);
        }
        validate_pc_cbor(&event.payload_cbor).map_err(|_| CandidateFeedError::Material)?;
        let row=sqlx::query("select v.*,affected_start::text range_first,affected_end::text range_last,old_block_number::text old_number,new_block_number::text new_number
            from candidate.fact_bridge_admission_v1 v where participant_id=$1 and privacy_domain_id=$2
            and candidate_partition_id=$3 and outbox_sequence=$4::numeric")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(sequence.to_string()).fetch_one(&mut *self.transaction).await?;
        let source = material::source_material(&row, self.scope.participant, self.scope.privacy)?;
        let parse = |column| -> Result<u64, CandidateFeedError> {
            let value: String = row.try_get(column)?;
            let number: u64 = value.parse().map_err(|_| CandidateFeedError::Material)?;
            if number.to_string() != value {
                return Err(CandidateFeedError::Material);
            }
            Ok(number)
        };
        let start = parse("range_first")?;
        let end = parse("range_last")?;
        let old_hash: Vec<u8> = row.try_get("old_block_hash")?;
        let new_hash: Vec<u8> = row.try_get("new_block_hash")?;
        let genesis: Vec<u8> = row.try_get("old_genesis_hash")?;
        let evidence: Vec<u8> = row.try_get("invalidation_evidence_digest")?;
        let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let profile = source.inputs.profile();
        if start == 0
            || end < start
            || parse("old_number")? != start
            || parse("new_number")? != start
            || [&old_hash, &new_hash, &genesis, &evidence]
                .iter()
                .any(|v| v.len() != 32)
            || old_hash == new_hash
            || row.try_get::<String, _>("old_chain_id")? != profile.chain_id
            || row.try_get::<String, _>("old_network_id")? != profile.network_id
            || profile
                .genesis_hash
                .trim_start_matches("sha256:")
                .trim_start_matches("0x")
                != hex(&genesis)
        {
            return Err(CandidateFeedError::Material);
        }
        // Bind the complete removed candidate set and its stored canonical range.
        let candidates:Vec<(Uuid,String,Vec<u8>)>=sqlx::query_as("select candidate_event_id,block_number::text,block_hash from candidate.fact_bridge_admission_v1
            where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3
            and event_type='io.openpc.indexer.projection.candidate.observed.v1' and candidate_state='REMOVED'
            and candidate_removed_at is not null and block_finality_state='REMOVED' and checkpoint_state='REORG'
            and block_number between $4::numeric and $5::numeric order by candidate_event_id")
            .bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition).bind(start.to_string()).bind(end.to_string()).fetch_all(&mut *self.transaction).await?;
        let candidates = candidates
            .into_iter()
            .map(|(id, number, hash)| {
                Ok((
                    id,
                    (
                        number
                            .parse::<u64>()
                            .map_err(|_| CandidateFeedError::Material)?,
                        hash,
                    ),
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, CandidateFeedError>>()?;
        if candidates.len() > 1000
            || candidates
                .values()
                .any(|(number, hash)| hash.len() != 32 || (*number == start && hash != &old_hash))
        {
            return Err(CandidateFeedError::Material);
        }
        let payload: serde_json::Value = ciborium::de::from_reader(event.payload_cbor.as_slice())
            .map_err(|_| CandidateFeedError::Material)?;
        let anchor = |hash: &[u8]| {
            json!({"chainId":profile.chain_id,"genesisHash":format!("0x{}",hex(&genesis)),"networkId":profile.network_id,
            "selectorKind":"PINNED","blockNumber":start.to_string(),"blockHash":format!("0x{}",hex(hash)),"pendingAuthorizedByProfile":false})
        };
        let invalidation: Uuid = row.try_get("invalidation_id")?;
        if invalidation.get_version_num() != 7
            || payload
                != json!({"candidatePartitionId":format!("urn:openpc:candidate-partition:{}",self.partition),
            "affectedCandidateIds":candidates.keys().map(|id|format!("urn:openpc:candidate:{id}")).collect::<Vec<_>>(),
            "oldAnchor":anchor(&old_hash),"newAnchor":anchor(&new_hash),"affectedRange":{"start":start.to_string(),"end":end.to_string()},
            "invalidationId":invalidation,"reorgEvidenceDigest":format!("sha256:{}",hex(&evidence)),"authority":"CANDIDATE_ONLY"})
        {
            return Err(CandidateFeedError::Material);
        }
        Ok(Some(SourceReorg {
            scope: CandidateReadScope::new(
                self.scope.participant,
                self.scope.privacy,
                self.scope.operation,
            )?,
            partition: self.partition,
            source,
            event,
            correlation: row.try_get("correlation_id")?,
            start,
            end,
            old_hash,
            new_hash,
            candidates,
        }))
    }
}
