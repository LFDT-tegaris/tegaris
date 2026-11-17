//! A closed candidate prefix is observation, never Fact authority. The manager
//! serializes its terminal fence with acquisition/reorg at the generation root;
//! stale/retired generations cannot append through either native writer.
use super::{CandidateFeedError, CandidateFeedRead, withdrawal::SourceFence};
use sqlx::Row;

pub(crate) struct WithdrawalPrefix {
    pub digest: [u8; 32],
}

impl CandidateFeedRead {
    pub(crate) async fn withdrawal_prefix(
        &mut self,
        fence: &SourceFence,
    ) -> Result<Option<WithdrawalPrefix>, CandidateFeedError> {
        // Exact scoped snapshot, including every occurrence before the fence.
        // Unknown event types, missing/duplicate sequence, nonfinal data and any
        // reorg remain ineligible. The Fact owner separately matches this digest
        // to its immutable independently admitted feed receipts.
        let row = sqlx::query(
            "select count(*)::bigint records,count(distinct outbox_sequence)::bigint sequences,
              min(outbox_sequence)::text first,max(outbox_sequence)::text last,
              bool_and(coalesce(projection_generation_id=$4 and source_profile_id=$5
                and generation_state in ('STALE','RETIRED') and publication_state in ('FENCED','RETIRED')
                and publication_digest=$6 and event_payload_digest=sha256(event_payload_cbor)
                and case when outbox_sequence=$7::numeric then
                  event_id=$8 and event_type='io.openpc.indexer.projection.source.fenced.v1'
                else checkpoint_state='COMPLETE' and checkpoint_completed_at is not null
                  and invalidation_id is null and (
                    (event_type='io.openpc.indexer.projection.candidate.observed.v1'
                      and candidate_state in ('OBSERVED','VALIDATED_CANDIDATE')
                      and candidate_removed_at is null and block_finality_state in ('SAFE','FINALIZED'))
                    or event_type='io.openpc.indexer.projection.checkpoint.completed.v1') end,false)) complete,
              count(*) filter(where outbox_sequence=$7::numeric-1
                and event_type='io.openpc.indexer.projection.checkpoint.completed.v1')::bigint checkpoint_tail,
              sha256(convert_to(string_agg(outbox_sequence::text||':'||event_id::text||':'||
                encode(event_payload_digest,'hex'),E'\\n' order by outbox_sequence)
                filter(where outbox_sequence<$7::numeric),'UTF8')) prefix_digest
             from candidate.fact_bridge_admission_v1
             where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3",
        )
        .bind(fence.participant)
        .bind(fence.privacy)
        .bind(fence.partition)
        .bind(fence.generation)
        .bind(fence.source_profile)
        .bind(&fence.publication_digest)
        .bind(fence.sequence.to_string())
        .bind(fence.event_id)
        .fetch_one(&mut *self.transaction)
        .await?;
        if fence.sequence < 2
            || row.try_get::<i64, _>("records")? != i64::try_from(fence.sequence).unwrap_or(-1)
            || row.try_get::<i64, _>("sequences")? != i64::try_from(fence.sequence).unwrap_or(-1)
            || row.try_get::<Option<String>, _>("first")?.as_deref() != Some("1")
            || row.try_get::<Option<String>, _>("last")? != Some(fence.sequence.to_string())
            || row.try_get::<Option<bool>, _>("complete")? != Some(true)
            || row.try_get::<i64, _>("checkpoint_tail")? != 1
        {
            return Ok(None);
        }
        let digest: Vec<u8> = row.try_get("prefix_digest")?;
        Ok(Some(WithdrawalPrefix {
            digest: digest
                .try_into()
                .map_err(|_| CandidateFeedError::Material)?,
        }))
    }
}
