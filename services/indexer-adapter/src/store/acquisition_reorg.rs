//! Stored chain custody for the authenticated acquisition owner's continuity
//! check. Candidate invalidation remains the existing atomic writer operation.
use super::*;
use crate::{PublishedAcquisitionInputs, acquisition::AcquisitionBatch};
use openpc_multi_rpc::source_header::SourceBlockHeader;

impl CandidateStore {
    pub(crate) async fn acquisition_tail(
        &self,
        inputs: &PublishedAcquisitionInputs,
        job: &AcquisitionBatch,
    ) -> Result<Vec<(u64, String, String)>, CandidateStoreError> {
        let binding = &job.binding;
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, binding).await?;
        lock_generation_root(&mut tx, binding).await?;
        let database =
            validate_database_binding(&mut tx, inputs.profile(), inputs.plan(), binding, None)
                .await?;
        let partition = exact_partition(inputs.plan(), &job.source_id, &job.partition_id)?;
        let registered = registered_partition(
            &mut tx,
            binding,
            database.source_profile_id,
            &database.plan_content_digest,
            partition,
        )
        .await?;
        let latest = sqlx::query("select batch_sequence::text,range_end::text,batch_digest,state::text
            from candidate.checkpoint where participant_id=$1 and privacy_domain_id=$2
            and projection_generation_id=$3 and candidate_partition_id=$4 order by batch_sequence desc limit 1")
            .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id())
            .bind(registered.candidate_partition_id).fetch_optional(&mut *tx).await?;
        let Some(latest) = latest else {
            if job.sequence != 1 || job.predecessor_digest != "GENESIS" {
                return Err(CandidateStoreError::InvalidBatch);
            }
            tx.rollback().await?;
            return Ok(Vec::new());
        };
        let end = parse_u64(&latest.try_get::<String, _>("range_end")?)?;
        if parse_u64(&latest.try_get::<String, _>("batch_sequence")?)?.checked_add(1)
            != Some(job.sequence)
            || latest.try_get::<Vec<u8>, _>("batch_digest")?
                != decode_digest(&job.predecessor_digest)?
        {
            return Err(CandidateStoreError::InvalidBatch);
        }
        if latest.try_get::<String, _>("state")? == "REORG" {
            reorg_replay_anchor(
                &mut tx,
                binding,
                registered.candidate_partition_id,
                &job.range,
            )
            .await?;
            tx.rollback().await?;
            // No removed block is a canonical predecessor. New observations
            // must cover the exact fenced interval and match the recorded fork
            // anchor again under the persistence lock before any commit.
            return Ok(Vec::new());
        }
        if latest.try_get::<String, _>("state")? != "COMPLETE"
            || end.checked_add(1) != Some(job.range.start)
        {
            return Err(CandidateStoreError::InvalidBatch);
        }
        // This is an observation-work bound, not a retention or recovery policy.
        // Exhausting it cannot authorize a replacement or restore readiness.
        let rows = sqlx::query("select block_number::text,encode(block_hash,'hex') block_hash,encode(parent_hash,'hex') parent_hash
            from candidate.candidate_block where participant_id=$1 and privacy_domain_id=$2
              and projection_generation_id=$3 and candidate_partition_id=$4 and finality_state<>'REMOVED'
              and block_number<=$5::numeric order by block_number desc limit 64")
            .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id())
            .bind(registered.candidate_partition_id).bind(end.to_string()).fetch_all(&mut *tx).await?;
        let mut result = Vec::new();
        for row in rows {
            result.push((
                parse_u64(&row.try_get::<String, _>("block_number")?)?,
                row.try_get::<String, _>("block_hash")?,
                row.try_get::<String, _>("parent_hash")?,
            ));
        }
        if result.first().map(|row| row.0) != Some(end)
            || result
                .windows(2)
                .any(|pair| pair[1].0.checked_add(1) != Some(pair[0].0) || pair[0].2 != pair[1].1)
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        tx.rollback().await?;
        Ok(result)
    }
}

/// The same durable cursor gate runs before acquisition and at commit. It
/// permits candidate replay only; FactBridge owns signed recovery admission,
/// retained-tail policy, rebootstrap authorization and positive readiness.
pub(super) async fn reorg_replay_anchor(
    tx: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
    partition: Uuid,
    range: &pc_provider_api::InclusiveRangeV1,
) -> Result<Vec<u8>, CandidateStoreError> {
    let row=sqlx::query("select i.affected_start::text,i.affected_end::text,i.new_block_number::text,i.new_block_hash,i.old_block_hash,
        c.position_cbor,c.position_digest,c.range_end::text checkpoint_end
        from candidate.candidate_invalidation i
        join lateral (select position_cbor,position_digest,range_end,state from candidate.checkpoint c
          where c.participant_id=i.participant_id and c.privacy_domain_id=i.privacy_domain_id
            and c.projection_generation_id=i.projection_generation_id and c.candidate_partition_id=i.candidate_partition_id
          order by batch_sequence desc limit 1) c on c.state='REORG'
        where i.participant_id=$1 and i.privacy_domain_id=$2 and i.projection_generation_id=$3
          and i.candidate_partition_id=$4 order by i.occurred_at desc,i.candidate_invalidation_id desc limit 1")
        .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id()).bind(partition)
        .fetch_optional(&mut **tx).await?.ok_or(CandidateStoreError::InvalidBatch)?;
    let start = parse_u64(&row.try_get::<String, _>("affected_start")?)?;
    let end = parse_u64(&row.try_get::<String, _>("affected_end")?)?;
    let cursor: Vec<u8> = row.try_get("position_cbor")?;
    let hash: Vec<u8> = row.try_get("new_block_hash")?;
    if start != range.start
        || end != range.end
        || end != parse_u64(&row.try_get::<String, _>("checkpoint_end")?)?
        || start != parse_u64(&row.try_get::<String, _>("new_block_number")?)?
        || hash.len() != 32
        || hash == row.try_get::<Vec<u8>, _>("old_block_hash")?
        || cursor.len() > 131072
        || Sha256::digest(&cursor).as_slice() != row.try_get::<Vec<u8>, _>("position_digest")?
        || pc_provider_api::validate_canonical_pc_cbor_bytes(&cursor).is_err()
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    Ok(hash)
}

impl ReorgInvalidation {
    /// Crate-private construction for the source owner, after its real mTLS
    /// header observations. External callers still need the runtime witness.
    pub(crate) fn from_acquisition(
        inputs: &PublishedAcquisitionInputs,
        job: &AcquisitionBatch,
        old: (u64, String),
        observed: &SourceBlockHeader,
        end: u64,
        evidence_digest: String,
    ) -> Result<Self, CandidateStoreError> {
        if observed.number != old.0
            || inputs.published().projection_generation_id != job.binding.projection_generation_id()
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let profile = inputs.profile();
        let method = profile
            .method_data_classes
            .iter()
            .find(|pair| {
                matches!(
                    pair.method.as_str(),
                    "eth_getBlockByNumber" | "eth_getBlockByNumber(false)"
                ) && pair.data_class == "BLOCK_HEADER"
            })
            .ok_or(CandidateStoreError::InvalidBinding)?;
        let anchor = |hash| ChainReadAnchorV1 {
            chain_id: profile.chain_id.clone(),
            genesis_hash: profile.genesis_hash.clone(),
            network_id: profile.network_id.clone(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(old.0),
            block_hash: Some(hash),
            pending_authorized_by_profile: false,
        };
        let value = Self {
            binding: job.binding.clone(),
            source_id: job.source_id.clone(),
            partition_id: job.partition_id.clone(),
            observation_profile_cbor: inputs.source().profile_cbor.clone(),
            observation_plan_cbor: inputs.source().plan_cbor.clone(),
            old_anchor: anchor(old.1),
            new_anchor: anchor(observed.hash.clone()),
            affected_start: old.0,
            affected_end: end,
            evidence_digest,
            observation_method: method.method.clone(),
            observation_data_class: method.data_class.clone(),
        };
        validate_reorg(&value)?;
        Ok(value)
    }
}
