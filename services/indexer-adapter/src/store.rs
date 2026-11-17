mod acquisition_reorg;
pub mod delivery;
pub(crate) mod retirement;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use openpc_multi_rpc::ReadExecutionResult;
use pc_provider_api::{
    BlockSelectorKind, CandidateProjectionBatchV1, ChainReadAnchorV1, ClientIndexerProfileV1,
    IdempotencyClass, ProjectionPartitionV1, ProjectionPlanV1, RangeEndV1, ResolutionTruth,
    RouteExecutionV1, RouteOutcomeV1, decode_client_indexer_profile_pc_cbor,
    decode_projection_plan_pc_cbor, encode_candidate_projection_batch_pc_cbor,
    encode_client_indexer_profile_pc_cbor, encode_projection_plan_pc_cbor,
    validate_projection_plan,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::candidate::{
    CandidateBatchMaterialV1, CandidateBlockFinalityV1, CandidatePersistenceBinding,
    CandidateRecordIdentityV1, decode_digest, decode_fixed_hex, digest_hex, identity_columns,
};

const CANDIDATE_DATABASE: &str = "openpc_candidate_index";
const INDEXER_WRITER_ROLE: &str = "openpc_indexer_writer";
const CANDIDATE_ACTION: &str = "ACT-CANDIDATE_WRITE-V1";
const OBSERVED_EVENT: &str = "io.openpc.indexer.projection.candidate.observed.v1";
const CHECKPOINT_EVENT: &str = "io.openpc.indexer.projection.checkpoint.completed.v1";
const INVALIDATED_EVENT: &str = "io.openpc.indexer.projection.candidate.invalidated.v1";
const OBSERVED_SCHEMA: &str = "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateObserved";
const CHECKPOINT_SCHEMA: &str = "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCheckpointCompleted";
const INVALIDATED_SCHEMA: &str = "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateInvalidated";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateDecodeFailureV1 {
    source_id: String,
    sequence: String,
    error_digest: String,
    evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CandidateInclusiveRangeV1 {
    start: String,
    end: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateAnchorV1 {
    chain_id: String,
    genesis_hash: String,
    network_id: String,
    selector_kind: &'static str,
    block_number: String,
    block_hash: String,
    pending_authorized_by_profile: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexerProjectionCandidateObservedV1<'a> {
    indexer_profile_id: &'a str,
    candidate_id: String,
    source_cursor_digest: String,
    candidate_digest: String,
    authority: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateCheckpointPositionV1<'a> {
    authoritative_empty: bool,
    batch_id: &'a str,
    batch_sequence: String,
    completed_watermark: CandidateCompletedWatermarkV1,
    decode_failures: &'a [CandidateDecodeFailureV1],
    missing_intervals: Vec<CandidateInclusiveRangeV1>,
    ordered_observation_evidence: Vec<String>,
    partition_id: &'a str,
    plan_digest: String,
    predecessor_batch_digest: Option<String>,
    profile_digest: String,
    range: CandidateInclusiveRangeV1,
    record_count: String,
    source_id: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CandidateCompletedWatermarkV1 {
    block_hash: String,
    block_number: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexerProjectionCheckpointCompletedV1<'a> {
    candidate_partition_id: &'a str,
    indexer_profile_id: &'a str,
    projection_generation_id: &'a str,
    batch_id: &'a str,
    batch_digest: String,
    predecessor_batch_digest: Option<String>,
    range: CandidateInclusiveRangeV1,
    checkpoint_digest: String,
    ordered_observation_evidence: Vec<String>,
    missing_intervals: Vec<CandidateInclusiveRangeV1>,
    decode_failures: &'a [CandidateDecodeFailureV1],
    record_count: String,
    authoritative_empty: bool,
    authority: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexerProjectionCandidateInvalidatedV1<'a> {
    candidate_partition_id: &'a str,
    affected_candidate_ids: Vec<String>,
    old_anchor: CandidateAnchorV1,
    new_anchor: CandidateAnchorV1,
    affected_range: CandidateInclusiveRangeV1,
    invalidation_id: String,
    reorg_evidence_digest: String,
    authority: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorgInvalidation {
    binding: CandidatePersistenceBinding,
    source_id: String,
    partition_id: String,
    observation_profile_cbor: Vec<u8>,
    observation_plan_cbor: Vec<u8>,
    old_anchor: ChainReadAnchorV1,
    new_anchor: ChainReadAnchorV1,
    affected_start: u64,
    affected_end: u64,
    evidence_digest: String,
    observation_method: String,
    observation_data_class: String,
}

impl ReorgInvalidation {
    pub fn try_new(
        observation: (&ReadExecutionResult, &CandidateBatchMaterialV1),
        binding: CandidatePersistenceBinding,
        source_id: impl Into<String>,
        partition_id: impl Into<String>,
        old_anchor: ChainReadAnchorV1,
        affected_range: (u64, u64),
    ) -> Result<Self, CandidateStoreError> {
        let (runtime_result, observation_material) = observation;
        let witness = runtime_result.witness();
        let (affected_start, affected_end) = affected_range;
        let source_id = source_id.into();
        let partition_id = partition_id.into();
        let observation_profile = observation_material.profile();
        let observation_plan = observation_material.plan();
        let observation_batch = observation_material.batch();
        if observation_material.binding() != &binding
            || observation_batch.source_id != source_id
            || observation_batch.partition_id != partition_id
            || witness.request().participant_binding != observation_profile.participant_binding
            || witness.request().privacy_binding != observation_profile.privacy_binding
            || witness.request().method.is_empty()
            || !observation_profile.method_data_classes.iter().any(|value| {
                value.method == witness.request().method
                    && value.data_class == witness.request().data_class
                    && value.data_class == observation_material.admitted_data_class()
            })
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let selected = match witness.execution() {
            RouteExecutionV1::IdempotentRead {
                outcome: RouteOutcomeV1::Selected(selected),
                ..
            } if witness.idempotency() == IdempotencyClass::IdempotentRead
                && selected.truth() == ResolutionTruth::Success =>
            {
                selected
            }
            _ => {
                return Err(CandidateStoreError::InvalidBinding);
            }
        };
        if selected.agreement_attempt_ids().is_empty()
            || selected
                .agreement_attempt_ids()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != selected.agreement_attempt_ids().len()
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let request_anchor = &witness.request().anchor;
        let selected_digest = selected.selected_result_digest().as_str();
        let mut provider_observed_anchor: Option<ChainReadAnchorV1> = None;
        let mut provider_normalized_bytes: Option<&[u8]> = None;
        for agreement_id in selected.agreement_attempt_ids() {
            let mut matching = witness
                .attempts()
                .iter()
                .filter(|attempt| &attempt.envelope().identity().attempt_id == agreement_id);
            let attempt = matching.next().ok_or(CandidateStoreError::InvalidBinding)?;
            let resolution = attempt
                .resolution()
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let provider = witness
                .eligibility()
                .admitted_profiles()
                .iter()
                .find(|profile| {
                    profile.profile_digest
                        == attempt
                            .envelope()
                            .identity()
                            .provider
                            .profile_digest
                            .as_str()
                        && profile.provider_instance_id
                            == attempt
                                .envelope()
                                .identity()
                                .provider
                                .provider_instance_id
                                .as_str()
                })
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let normalized_bytes = runtime_result
                .selected_normalized_bytes(agreement_id.as_str())
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let normalized_digest = runtime_result
                .selected_normalized_digest(agreement_id.as_str())
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let observed_anchor = runtime_result
                .selected_provider_observed_anchor(agreement_id.as_str())
                .ok_or(CandidateStoreError::InvalidBinding)?;
            if matching.next().is_some()
                || attempt.envelope().identity().anchor != *request_anchor
                || resolution.truth() != selected.truth()
                || resolution.observed_anchor() != observed_anchor
                || resolution.normalized_response_digest()
                    != Some(selected.selected_result_digest())
                || normalized_digest != selected_digest
                || digest_hex(normalized_bytes) != selected_digest
                || resolution.evidence_refs().is_empty()
                || provider.chain_id != observation_profile.chain_id
                || decode_digest(&provider.genesis_hash)?
                    != decode_digest(&observation_profile.genesis_hash)?
                || provider.network_id != observation_profile.network_id
                || !provider.method_data_classes.iter().any(|value| {
                    value.method == witness.request().method
                        && value.data_class == witness.request().data_class
                })
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            match &provider_observed_anchor {
                Some(anchor) if anchor != observed_anchor => {
                    return Err(CandidateStoreError::InvalidBinding);
                }
                None => provider_observed_anchor = Some(observed_anchor.clone()),
                _ => {}
            }
            match provider_normalized_bytes {
                Some(bytes) if bytes != normalized_bytes => {
                    return Err(CandidateStoreError::InvalidBinding);
                }
                None => provider_normalized_bytes = Some(normalized_bytes),
                _ => {}
            }
        }
        let provider_observed_anchor =
            provider_observed_anchor.ok_or(CandidateStoreError::InvalidBinding)?;
        let provider_normalized_bytes =
            provider_normalized_bytes.ok_or(CandidateStoreError::InvalidBinding)?;
        let mut matching_observations = observation_batch.observations.iter().filter(|value| {
            value.normalized_digest == selected_digest
                && value.anchor == provider_observed_anchor
                && value.anchor.block_number == Some(affected_start)
        });
        let observation = matching_observations
            .next()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        if matching_observations.next().is_some()
            || &provider_observed_anchor != request_anchor
            || !anchor_matches_profile(&provider_observed_anchor, observation_profile)?
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let observation_profile_cbor = encode_client_indexer_profile_pc_cbor(observation_profile)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let observation_plan_cbor = encode_projection_plan_pc_cbor(observation_plan)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let observation_batch_cbor = encode_candidate_projection_batch_pc_cbor(observation_batch)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let witness_value =
            serde_json::to_value(witness).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let evidence_value = json!({
            "witness": witness_value,
            "candidateObservationBatchCbor": observation_batch_cbor,
            "candidateObservationEvidenceDigest": observation.evidence_digest.as_str(),
            "candidateObservationSequence": observation.sequence.to_string(),
            "providerObservedAnchor": &provider_observed_anchor,
            "providerNormalizedBytes": provider_normalized_bytes,
            "selectedResultDigest": selected_digest,
            "participantId": binding.participant_id().to_string(),
            "privacyDomainId": binding.privacy_domain_id().to_string(),
            "projectionGenerationId": binding.projection_generation_id().to_string(),
            "sourceId": source_id,
            "partitionId": partition_id,
            "oldAnchor": old_anchor,
            "affectedRange": {"start": affected_start.to_string(), "end": affected_end.to_string()},
        });
        let value = Self {
            binding,
            source_id,
            partition_id,
            observation_profile_cbor,
            observation_plan_cbor,
            old_anchor,
            new_anchor: provider_observed_anchor,
            affected_start,
            affected_end,
            evidence_digest: digest_hex(&canonical_cbor(&evidence_value)),
            observation_method: witness.request().method.clone(),
            observation_data_class: witness.request().data_class.clone(),
        };
        validate_reorg(&value)?;
        Ok(value)
    }

    pub fn old_anchor(&self) -> &ChainReadAnchorV1 {
        &self.old_anchor
    }

    pub fn new_anchor(&self) -> &ChainReadAnchorV1 {
        &self.new_anchor
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn affected_range(&self) -> (u64, u64) {
        (self.affected_start, self.affected_end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceOutcome {
    Committed,
    ReplayedSameDigest,
    ReorgInvalidated,
    QuarantinedDigestConflict,
    BlockedSequenceGap,
    QuarantinedPredecessorMismatch,
}

#[derive(Debug, Error)]
pub enum CandidateStoreError {
    #[error("DATA-6202-CANDIDATE-BATCH-INVALID")]
    InvalidBatch,
    #[error("DATA-6203-CANDIDATE-BINDING-INVALID")]
    InvalidBinding,
    #[error("DATA-6204-CANDIDATE-STORE-IDENTITY")]
    WrongStoreIdentity,
    #[error("DATA-6205-CANDIDATE-DATABASE")]
    Database(#[from] sqlx::Error),
}

pub struct CandidateStore {
    pool: PgPool,
}

impl CandidateStore {
    pub async fn connect(candidate_database_url: &str) -> Result<Self, CandidateStoreError> {
        if candidate_database_url.is_empty() {
            return Err(CandidateStoreError::WrongStoreIdentity);
        }
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(candidate_database_url)
            .await?;
        Self::check_pool(pool).await
    }

    /// Installed bounded target adapter; connection material never comes from
    /// a retirement request. Preserve the ordinary candidate writer identity.
    pub async fn connect_retirement_target(
        options: PgConnectOptions,
    ) -> Result<Self, CandidateStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await?;
        let restricted: bool = sqlx::query_scalar(
            "select current_user=session_user and not rolsuper and not rolbypassrls
             and not pg_has_role(current_user,'openpc_candidate_index_owner','MEMBER')
             and not pg_has_role(current_user,'openpc_candidate_index_maintenance','MEMBER')
             from pg_roles where rolname=current_user",
        )
        .fetch_one(&pool)
        .await?;
        if !restricted {
            pool.close().await;
            return Err(CandidateStoreError::WrongStoreIdentity);
        }
        Self::check_pool(pool).await
    }

    async fn check_pool(pool: PgPool) -> Result<Self, CandidateStoreError> {
        let row = sqlx::query("SELECT current_database(), current_user")
            .fetch_one(&pool)
            .await?;
        let database: String = row.try_get(0)?;
        let role: String = row.try_get(1)?;
        if database != CANDIDATE_DATABASE || role != INDEXER_WRITER_ROLE {
            pool.close().await;
            return Err(CandidateStoreError::WrongStoreIdentity);
        }
        Ok(Self { pool })
    }

    /// Read the manager's exact immutable inputs under the candidate writer's
    /// scoped database identity. This is not current Control/Identity/policy
    /// authorization, and cannot authorize a source request by itself.
    pub async fn acquisition_inputs(
        &self,
        binding: &CandidatePersistenceBinding,
    ) -> Result<crate::PublishedAcquisitionInputs, CandidateStoreError> {
        crate::publication::load_acquisition_inputs(&self.pool, binding).await
    }

    /// Restart readback for an already complete job. Exact immutable source and
    /// scheduler input bindings must still match; no source call is repeated.
    pub(crate) async fn acquisition_replayed(
        &self,
        inputs: &crate::PublishedAcquisitionInputs,
        job: &crate::acquisition::AcquisitionBatch,
    ) -> Result<bool, CandidateStoreError> {
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
        let row = sqlx::query("select batch_sequence::text,range_start::text,range_end::text,predecessor_batch_digest,state::text from candidate.checkpoint where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3 and candidate_partition_id=$4 and batch_id=$5")
            .bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id())
            .bind(registered.candidate_partition_id).bind(&job.batch_id).fetch_optional(&mut *tx).await?;
        let replay = if let Some(row) = row {
            let predecessor = if job.predecessor_digest == "GENESIS" {
                None
            } else {
                Some(decode_digest(&job.predecessor_digest)?)
            };
            if parse_u64(&row.try_get::<String, _>(0)?)? != job.sequence
                || parse_u64(&row.try_get::<String, _>(1)?)? != job.range.start
                || parse_u64(&row.try_get::<String, _>(2)?)? != job.range.end
                || row.try_get::<Option<Vec<u8>>, _>(3)? != predecessor
                || row.try_get::<String, _>(4)? != "COMPLETE"
            {
                return Err(CandidateStoreError::InvalidBatch);
            }
            true
        } else {
            false
        };
        tx.commit().await?;
        Ok(replay)
    }

    pub async fn register_partition(
        &self,
        profile: &ClientIndexerProfileV1,
        plan: &ProjectionPlanV1,
        binding: &CandidatePersistenceBinding,
        source_id: &str,
        partition_id: &str,
    ) -> Result<(), CandidateStoreError> {
        binding.validate_profile_scope(profile)?;
        validate_projection_plan(profile, plan).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let partition = exact_partition(plan, source_id, partition_id)?;
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, binding).await?;
        lock_generation_root(&mut transaction, binding).await?;
        let database =
            validate_database_binding(&mut transaction, profile, plan, binding, None).await?;
        registered_partition(
            &mut transaction,
            binding,
            database.source_profile_id,
            &database.plan_content_digest,
            partition,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn persist_batch(
        &self,
        material: &CandidateBatchMaterialV1,
    ) -> Result<PersistenceOutcome, CandidateStoreError> {
        let profile = material.profile();
        let plan = material.plan();
        let batch = material.batch();
        let binding = material.binding();
        let partition = exact_partition(plan, &batch.source_id, &batch.partition_id)?;
        let batch_cbor = encode_candidate_projection_batch_pc_cbor(batch)
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        let batch_digest = Sha256::digest(&batch_cbor).to_vec();
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, binding).await?;
        lock_generation_root(&mut transaction, binding).await?;
        let database =
            validate_database_binding(&mut transaction, profile, plan, binding, Some(material))
                .await?;
        let registered = registered_partition(
            &mut transaction,
            binding,
            database.source_profile_id,
            &database.plan_content_digest,
            partition,
        )
        .await?;
        let checkpoint_state = read_partition_checkpoint_state_after_generation_lock(
            &mut transaction,
            binding,
            registered.candidate_partition_id,
            &batch.batch_id,
        )
        .await?;
        if let Some(existing_digest) = checkpoint_state.existing_batch_digest {
            if existing_digest == batch_digest {
                transaction.commit().await?;
                return Ok(PersistenceOutcome::ReplayedSameDigest);
            }
            quarantine(
                &mut transaction,
                binding,
                &batch_digest,
                "DATA-6042-INBOX-DIGEST-CONFLICT",
            )
            .await?;
            transaction.commit().await?;
            return Ok(PersistenceOutcome::QuarantinedDigestConflict);
        }
        let expected_sequence = checkpoint_state.latest.as_ref().map_or(Ok(1), |prior| {
            prior
                .batch_sequence
                .checked_add(1)
                .ok_or(CandidateStoreError::InvalidBatch)
        })?;
        if expected_sequence != batch.batch_sequence {
            quarantine(
                &mut transaction,
                binding,
                &batch_digest,
                "DATA-6043-INBOX-SEQUENCE-GAP",
            )
            .await?;
            transaction.commit().await?;
            return Ok(PersistenceOutcome::BlockedSequenceGap);
        }
        let predecessor_matches = match checkpoint_state.latest {
            None => batch.batch_sequence == 1 && batch.predecessor_batch_digest == "GENESIS",
            Some(prior) => {
                let same_predecessor =
                    predecessor_digest(batch)?.as_deref() == Some(prior.batch_digest.as_slice());
                if prior.state == "REORG" && same_predecessor {
                    let anchor = acquisition_reorg::reorg_replay_anchor(
                        &mut transaction,
                        binding,
                        registered.candidate_partition_id,
                        &batch.range,
                    )
                    .await?;
                    material
                        .blocks()
                        .iter()
                        .find(|block| block.block_number == batch.range.start)
                        .is_some_and(|block| {
                            decode_fixed_hex(&block.canonical_block_hash, 32)
                                .is_ok_and(|hash| hash == anchor)
                        })
                } else {
                    prior.state == "COMPLETE"
                        && same_predecessor
                        && prior.range_end.checked_add(1) == Some(batch.range.start)
                }
            }
        };
        if !predecessor_matches {
            quarantine(
                &mut transaction,
                binding,
                &batch_digest,
                "DATA-6044-FBC-011-PC-RUNTIME-3009",
            )
            .await?;
            transaction.commit().await?;
            return Ok(PersistenceOutcome::QuarantinedPredecessorMismatch);
        }
        let decode_failures = candidate_decode_failures(batch);
        let checkpoint_cbor =
            checkpoint_cbor(batch, material.authoritative_empty(), &decode_failures)?;
        let checkpoint_digest = Sha256::digest(&checkpoint_cbor).to_vec();
        let source = source_profile_urn(database.source_profile_id)?;
        let partition_urn = candidate_partition_urn(registered.candidate_partition_id)?;
        let indexer_profile_urn = indexer_profile_urn(database.indexer_profile_id)?;
        let generation_urn = projection_generation_urn(binding.projection_generation_id())?;

        let mut block_ids = BTreeMap::new();
        for block in material.blocks() {
            validate_finality_against_database(block, &database)?;
            let (finality_state, finality_kind, evidence, head_number, head_hash) =
                finality_columns(&block.finality)?;
            let block_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO candidate.candidate_block(
                   participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,chain_namespace,
                   block_hash,parent_hash,block_number,block_timestamp,finality_state,observed_at,
                   source_payload_digest,finality_kind,finality_evidence_digest,finality_head_number,finality_head_hash)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::timestamptz,$10,clock_timestamp(),$11,$12,$13,$14::numeric,$15)
                   RETURNING candidate_block_id"#,
            )
            .bind(binding.participant_id())
            .bind(binding.privacy_domain_id())
            .bind(binding.projection_generation_id())
            .bind(registered.candidate_partition_id)
            .bind(&database.chain_namespace)
            .bind(decode_fixed_hex(&block.canonical_block_hash, 32)?)
            .bind(decode_fixed_hex(&block.parent_hash, 32)?)
            .bind(block.block_number.to_string())
            .bind(&block.block_timestamp)
            .bind(finality_state)
            .bind(decode_digest(&block.evidence_digest)?)
            .bind(finality_kind)
            .bind(evidence)
            .bind(head_number.map(|value| value.to_string()))
            .bind(head_hash)
            .fetch_one(&mut *transaction)
            .await?;
            block_ids.insert(
                (block.block_number, block.canonical_block_hash.clone()),
                block_id,
            );
        }

        let mut persisted_records = Vec::with_capacity(material.records().len());
        for record_material in material.records() {
            let record = &record_material.record;
            let block_id = block_ids
                .get(&(record.block_number, record.canonical_block_hash.clone()))
                .ok_or(CandidateStoreError::InvalidBatch)?;
            let identity = identity_columns(&record_material.identity);
            // Material validation, the current database profile/finality check,
            // and contiguous checkpoint admission all precede this handoff.
            // Rows become visible with the checkpoint/outbox commit below;
            // VALIDATED_CANDIDATE still grants no fact or policy authority.
            let candidate_event_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO candidate.candidate_event(
                   participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,
                   record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,
                   transaction_hash,transaction_index,log_index,contract_address,event_signature,
                   target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13::numeric,$14::numeric,$15,$16,$17,$18,$19,$20,$21,'VALIDATED_CANDIDATE',clock_timestamp())
                   RETURNING candidate_event_id"#,
            )
            .bind(binding.participant_id())
            .bind(binding.privacy_domain_id())
            .bind(binding.projection_generation_id())
            .bind(registered.candidate_partition_id)
            .bind(block_id)
            .bind(record_material.identity.kind())
            .bind(record.sequence.to_string())
            .bind(&record.record_id)
            .bind(decode_digest(&record.schema_digest)?)
            .bind(decode_digest(&record.normalized_digest)?)
            .bind(decode_digest(&record.evidence_digest)?)
            .bind(identity.transaction_hash)
            .bind(identity.transaction_index.map(|value| value.to_string()))
            .bind(identity.log_index.map(|value| value.to_string()))
            .bind(identity.contract_address)
            .bind(identity.event_signature)
            .bind(identity.target_address)
            .bind(identity.call_parameter_digest)
            .bind(Sha256::digest(record.record_id.as_bytes()).to_vec())
            .bind(&record_material.payload_cbor)
            .bind(Sha256::digest(&record_material.payload_cbor).to_vec())
            .fetch_one(&mut *transaction)
            .await?;
            persisted_records.push((candidate_event_id, record));
        }

        sqlx::query(
            r#"INSERT INTO candidate.checkpoint(
               participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,checkpoint_kind,
               position_cbor,position_digest,state,batch_id,batch_sequence,batch_digest,predecessor_batch_digest,
               range_start,range_end,authoritative_empty,observed_at,completed_at)
               VALUES ($1,$2,$3,$4,'BLOCK',$5,$6,'COMPLETE',$7,$8::numeric,$9,$10,$11::numeric,$12::numeric,$13,clock_timestamp(),clock_timestamp())"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(registered.candidate_partition_id)
        .bind(&checkpoint_cbor)
        .bind(&checkpoint_digest)
        .bind(&batch.batch_id)
        .bind(batch.batch_sequence.to_string())
        .bind(&batch_digest)
        .bind(predecessor_digest(batch)?)
        .bind(batch.range.start.to_string())
        .bind(batch.range.end.to_string())
        .bind(material.authoritative_empty())
        .execute(&mut *transaction)
        .await?;

        lock_outbox_head(
            &mut transaction,
            binding.participant_id(),
            registered.candidate_partition_id,
        )
        .await?;

        for (candidate_event_id, record) in persisted_records {
            let payload = IndexerProjectionCandidateObservedV1 {
                indexer_profile_id: &indexer_profile_urn,
                candidate_id: candidate_urn(candidate_event_id)?,
                source_cursor_digest: sha_digest(&checkpoint_digest),
                candidate_digest: canonical_digest(&record.normalized_digest),
                authority: "CANDIDATE_ONLY",
            };
            emit_event(
                &mut transaction,
                binding,
                EventEmission {
                    candidate_partition_id: registered.candidate_partition_id,
                    source: &source,
                    subject: &partition_urn,
                    event_type: OBSERVED_EVENT,
                    schema: OBSERVED_SCHEMA,
                    payload: &payload,
                },
            )
            .await?;
        }

        let checkpoint_payload = IndexerProjectionCheckpointCompletedV1 {
            candidate_partition_id: &partition_urn,
            indexer_profile_id: &indexer_profile_urn,
            projection_generation_id: &generation_urn,
            batch_id: &batch.batch_id,
            batch_digest: sha_digest(&batch_digest),
            predecessor_batch_digest: wire_predecessor_digest(batch),
            range: inclusive_range(batch.range.start, batch.range.end),
            checkpoint_digest: sha_digest(&checkpoint_digest),
            ordered_observation_evidence: batch
                .observations
                .iter()
                .map(|value| canonical_digest(&value.evidence_digest))
                .collect(),
            missing_intervals: batch
                .missing_intervals
                .iter()
                .map(|value| inclusive_range(value.start, value.end))
                .collect(),
            decode_failures: &decode_failures,
            record_count: batch.records.len().to_string(),
            authoritative_empty: material.authoritative_empty(),
            authority: "CANDIDATE_ONLY",
        };
        emit_event(
            &mut transaction,
            binding,
            EventEmission {
                candidate_partition_id: registered.candidate_partition_id,
                source: &source,
                subject: &partition_urn,
                event_type: CHECKPOINT_EVENT,
                schema: CHECKPOINT_SCHEMA,
                payload: &checkpoint_payload,
            },
        )
        .await?;

        transaction.commit().await?;
        Ok(PersistenceOutcome::Committed)
    }

    pub async fn invalidate_reorg(
        &self,
        invalidation: &ReorgInvalidation,
    ) -> Result<(), CandidateStoreError> {
        validate_reorg(invalidation)?;
        let binding = &invalidation.binding;
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, binding).await?;
        lock_generation_root(&mut transaction, binding).await?;
        let row = sqlx::query(
            r#"SELECT cp.candidate_partition_id,sp.source_profile_id,sp.indexer_profile_id,
               sp.source_profile_cbor,pp.mapping_cbor,cp.range_start::text,cp.range_end::text,cp.range_end_open
               FROM candidate.candidate_partition cp
               JOIN candidate.projection_generation g
                 ON g.participant_id=cp.participant_id AND g.privacy_domain_id=cp.privacy_domain_id
                AND g.projection_generation_id=cp.projection_generation_id
               JOIN candidate.projection_profile pp
                 ON pp.participant_id=g.participant_id AND pp.privacy_domain_id=g.privacy_domain_id
                AND pp.projection_profile_id=g.projection_profile_id
               JOIN candidate.source_profile sp
                 ON sp.participant_id=pp.participant_id AND sp.privacy_domain_id=pp.privacy_domain_id
                AND sp.source_profile_id=pp.source_profile_id
               WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2
                 AND cp.projection_generation_id=$3 AND cp.source_profile_id=sp.source_profile_id
                 AND cp.source_id=$4 AND cp.partition_id=$5
                 AND g.state IN ('READY','ACTIVE') AND pp.state='QUALIFIED' AND sp.state='QUALIFIED'"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(&invalidation.source_id)
        .bind(&invalidation.partition_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CandidateStoreError::InvalidBinding)?;
        let candidate_partition_id: Uuid = row.try_get(0)?;
        let source_profile_id: Uuid = row.try_get(1)?;
        let _indexer_profile_id: Uuid = row.try_get(2)?;
        let profile_cbor: Vec<u8> = row.try_get(3)?;
        let plan_cbor: Vec<u8> = row.try_get(4)?;
        let range_start: String = row.try_get(5)?;
        let range_end: Option<String> = row.try_get(6)?;
        let range_end_open: bool = row.try_get(7)?;
        if profile_cbor != invalidation.observation_profile_cbor
            || plan_cbor != invalidation.observation_plan_cbor
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let profile = decode_client_indexer_profile_pc_cbor(&profile_cbor)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let qualified_observation = profile.method_data_classes.iter().any(|value| {
            value.method == invalidation.observation_method
                && value.data_class == invalidation.observation_data_class
        });
        if invalidation.affected_start < parse_u64(&range_start)?
            || (!range_end_open
                && invalidation.affected_end
                    > parse_u64(
                        range_end
                            .as_deref()
                            .ok_or(CandidateStoreError::InvalidBinding)?,
                    )?)
            || !anchor_matches_profile(&invalidation.old_anchor, &profile)?
            || !anchor_matches_profile(&invalidation.new_anchor, &profile)?
            || !qualified_observation
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        // The generation root serializes append and reorg. This is an observation,
        // not a checkpoint lock: acquire child locks before checkpoint locks.
        let observed_head_rows = sqlx::query(
            r#"SELECT batch_sequence::text,state::text,range_end::text
               FROM candidate.checkpoint c
               WHERE c.participant_id=$1 AND c.privacy_domain_id=$2 AND c.projection_generation_id=$3
                 AND c.candidate_partition_id=$4 AND c.batch_sequence=(
                   SELECT max(latest.batch_sequence) FROM candidate.checkpoint latest
                   WHERE latest.participant_id=$1 AND latest.privacy_domain_id=$2
                     AND latest.projection_generation_id=$3 AND latest.candidate_partition_id=$4
                 )
               ORDER BY c.checkpoint_kind,c.batch_sequence,c.checkpoint_id"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(candidate_partition_id)
        .fetch_all(&mut *transaction)
        .await?;
        if observed_head_rows.len() != 1 {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let observed_head = &observed_head_rows[0];
        let observed_head_sequence = parse_u64(&observed_head.try_get::<String, _>(0)?)?;
        let observed_head_state: String = observed_head.try_get(1)?;
        let affected_end = parse_u64(&observed_head.try_get::<String, _>(2)?)?;
        if observed_head_state != "COMPLETE" || invalidation.affected_end != affected_end {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let block_rows = sqlx::query(
            r#"SELECT candidate_block_id,block_number::text,encode(block_hash,'hex')
               FROM candidate.candidate_block
               WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3
                 AND candidate_partition_id=$4 AND block_number BETWEEN $5::numeric AND $6::numeric
                 AND finality_state <> 'REMOVED' ORDER BY candidate_block_id FOR UPDATE"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(candidate_partition_id)
        .bind(invalidation.affected_start.to_string())
        .bind(affected_end.to_string())
        .fetch_all(&mut *transaction)
        .await?;
        let old_number = invalidation.affected_start.to_string();
        let old_block_hash = decode_fixed_hex(
            invalidation
                .old_anchor
                .block_hash
                .as_deref()
                .ok_or(CandidateStoreError::InvalidBinding)?,
            32,
        )?;
        let has_old_block = block_rows.iter().try_fold(false, |found, row| {
            let row_number: String = row.try_get(1)?;
            let row_hash = decode_fixed_hex(&row.try_get::<String, _>(2)?, 32)?;
            Ok::<_, CandidateStoreError>(
                found || (row_number == old_number && row_hash == old_block_hash),
            )
        })?;
        if block_rows.is_empty() || !has_old_block {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let block_ids = block_rows
            .iter()
            .map(|row| row.try_get::<Uuid, _>(0))
            .collect::<Result<Vec<_>, _>>()?;
        let event_rows = sqlx::query(
            r#"SELECT candidate_event_id,record_sequence::text FROM candidate.candidate_event
               WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3
                 AND candidate_partition_id=$4 AND candidate_block_id=ANY($5)
                 AND state IN ('OBSERVED','VALIDATED_CANDIDATE') ORDER BY candidate_event_id FOR UPDATE"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(candidate_partition_id)
        .bind(&block_ids)
        .fetch_all(&mut *transaction)
        .await?;
        let mut event_ids_by_record_sequence = event_rows
            .iter()
            .map(|row| {
                Ok::<(u64, Uuid), CandidateStoreError>((
                    parse_u64(&row.try_get::<String, _>(1)?)?,
                    row.try_get::<Uuid, _>(0)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        event_ids_by_record_sequence.sort_unstable();
        let event_ids = event_ids_by_record_sequence
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        validate_affected_event_ids(&event_ids)?;
        let checkpoint_rows = sqlx::query(
            r#"SELECT checkpoint_id,batch_sequence::text,state::text,range_start::text,range_end::text
               FROM candidate.checkpoint c
               WHERE c.participant_id=$1 AND c.privacy_domain_id=$2
                 AND c.projection_generation_id=$3 AND c.candidate_partition_id=$4
                 AND c.state='COMPLETE' AND c.range_start <= $6::numeric AND c.range_end >= $5::numeric
               ORDER BY checkpoint_kind,batch_sequence,checkpoint_id FOR UPDATE"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(candidate_partition_id)
        .bind(invalidation.affected_start.to_string())
        .bind(affected_end.to_string())
        .fetch_all(&mut *transaction)
        .await?;
        let mut checkpoint_ids = Vec::new();
        let mut locked_head_matches = 0_u8;
        for row in checkpoint_rows {
            let checkpoint_id: Uuid = row.try_get(0)?;
            let batch_sequence = parse_u64(&row.try_get::<String, _>(1)?)?;
            let state: String = row.try_get(2)?;
            let checkpoint_start = parse_u64(&row.try_get::<String, _>(3)?)?;
            let checkpoint_end = parse_u64(&row.try_get::<String, _>(4)?)?;
            if batch_sequence == observed_head_sequence
                && state == observed_head_state
                && checkpoint_end == affected_end
            {
                locked_head_matches = locked_head_matches
                    .checked_add(1)
                    .ok_or(CandidateStoreError::InvalidBinding)?;
            }
            if state == "COMPLETE"
                && checkpoint_start <= affected_end
                && checkpoint_end >= invalidation.affected_start
            {
                checkpoint_ids.push(checkpoint_id);
            }
        }
        if checkpoint_ids.is_empty() || locked_head_matches != 1 {
            return Err(CandidateStoreError::InvalidBinding);
        }
        lock_outbox_head(
            &mut transaction,
            binding.participant_id(),
            candidate_partition_id,
        )
        .await?;
        let event_count = sqlx::query(
            "UPDATE candidate.candidate_event SET state='REMOVED',removed_at=clock_timestamp() WHERE candidate_event_id=ANY($1)",
        )
        .bind(&event_ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let block_count = sqlx::query(
            "UPDATE candidate.candidate_block SET finality_state='REMOVED' WHERE candidate_block_id=ANY($1)",
        )
        .bind(&block_ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let checkpoint_count = sqlx::query(
            "UPDATE candidate.checkpoint SET state='REORG',completed_at=NULL,row_version=row_version+1 WHERE checkpoint_id=ANY($1)",
        )
        .bind(&checkpoint_ids)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if event_count != event_ids.len() as u64
            || block_count != block_ids.len() as u64
            || checkpoint_count != checkpoint_ids.len() as u64
        {
            return Err(CandidateStoreError::InvalidBinding);
        }

        let invalidation_id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO candidate.candidate_invalidation(
               participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,
               affected_start,affected_end,old_chain_id,old_genesis_hash,old_network_id,old_selector_kind,
               old_block_number,old_block_hash,old_pending_authorized,new_chain_id,new_genesis_hash,new_network_id,
               new_selector_kind,new_block_number,new_block_hash,new_pending_authorized,evidence_digest)
               VALUES ($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9,'PINNED',$10::numeric,$11,false,
                       $12,$13,$14,'PINNED',$15::numeric,$16,false,$17) RETURNING candidate_invalidation_id"#,
        )
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.projection_generation_id())
        .bind(candidate_partition_id)
        .bind(invalidation.affected_start.to_string())
        .bind(affected_end.to_string())
        .bind(&invalidation.old_anchor.chain_id)
        .bind(decode_digest(&invalidation.old_anchor.genesis_hash)?)
        .bind(&invalidation.old_anchor.network_id)
        .bind(invalidation.affected_start.to_string())
        .bind(decode_fixed_hex(invalidation.old_anchor.block_hash.as_deref().ok_or(CandidateStoreError::InvalidBinding)?, 32)?)
        .bind(&invalidation.new_anchor.chain_id)
        .bind(decode_digest(&invalidation.new_anchor.genesis_hash)?)
        .bind(&invalidation.new_anchor.network_id)
        .bind(invalidation.affected_start.to_string())
        .bind(decode_fixed_hex(invalidation.new_anchor.block_hash.as_deref().ok_or(CandidateStoreError::InvalidBinding)?, 32)?)
        .bind(decode_digest(&invalidation.evidence_digest)?)
        .fetch_one(&mut *transaction)
        .await?;
        let source = source_profile_urn(source_profile_id)?;
        let partition_urn = candidate_partition_urn(candidate_partition_id)?;
        require_uuid_v7(invalidation_id)?;
        let payload = IndexerProjectionCandidateInvalidatedV1 {
            candidate_partition_id: &partition_urn,
            affected_candidate_ids: event_ids
                .into_iter()
                .map(candidate_urn)
                .collect::<Result<Vec<_>, _>>()?,
            old_anchor: anchor_payload(&invalidation.old_anchor)?,
            new_anchor: anchor_payload(&invalidation.new_anchor)?,
            affected_range: inclusive_range(invalidation.affected_start, affected_end),
            invalidation_id: invalidation_id.to_string(),
            reorg_evidence_digest: canonical_digest(&invalidation.evidence_digest),
            authority: "CANDIDATE_ONLY",
        };
        emit_event(
            &mut transaction,
            binding,
            EventEmission {
                candidate_partition_id,
                source: &source,
                subject: &partition_urn,
                event_type: INVALIDATED_EVENT,
                schema: INVALIDATED_SCHEMA,
                payload: &payload,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

struct DatabaseBinding {
    source_profile_id: Uuid,
    indexer_profile_id: Uuid,
    chain_namespace: String,
    finality_mode: String,
    confirmation_count: Option<u32>,
    plan_content_digest: Vec<u8>,
}

struct RegisteredPartition {
    candidate_partition_id: Uuid,
}

struct LatestCheckpoint {
    batch_sequence: u64,
    batch_digest: Vec<u8>,
    range_end: u64,
    state: String,
}

struct CheckpointState {
    latest: Option<LatestCheckpoint>,
    existing_batch_digest: Option<Vec<u8>>,
}

async fn lock_generation_root(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
) -> Result<(), CandidateStoreError> {
    let row: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT projection_generation_id
           FROM candidate.projection_generation
           WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3
             AND state IN ('READY','ACTIVE')
           FOR UPDATE"#,
    )
    .bind(binding.participant_id())
    .bind(binding.privacy_domain_id())
    .bind(binding.projection_generation_id())
    .fetch_optional(&mut **transaction)
    .await?;
    if row != Some(binding.projection_generation_id()) {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(())
}

async fn read_partition_checkpoint_state_after_generation_lock(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
    candidate_partition_id: Uuid,
    incoming_batch_id: &str,
) -> Result<CheckpointState, CandidateStoreError> {
    let rows = sqlx::query(
        r#"SELECT batch_id,batch_sequence::text,batch_digest,range_end::text,state::text
           FROM candidate.checkpoint c
           WHERE c.participant_id=$1 AND c.privacy_domain_id=$2 AND c.projection_generation_id=$3
             AND c.candidate_partition_id=$4
             AND (c.batch_id=$5 OR c.batch_sequence=(
               SELECT max(latest.batch_sequence) FROM candidate.checkpoint latest
               WHERE latest.participant_id=$1 AND latest.privacy_domain_id=$2
                 AND latest.projection_generation_id=$3 AND latest.candidate_partition_id=$4
             ))
           ORDER BY c.checkpoint_kind,c.batch_sequence,c.checkpoint_id"#,
    )
    .bind(binding.participant_id())
    .bind(binding.privacy_domain_id())
    .bind(binding.projection_generation_id())
    .bind(candidate_partition_id)
    .bind(incoming_batch_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut latest = None;
    let mut existing_batch_digest = None;
    for row in rows {
        let batch_id: String = row.try_get(0)?;
        let checkpoint = LatestCheckpoint {
            batch_sequence: parse_u64(&row.try_get::<String, _>(1)?)?,
            batch_digest: row.try_get(2)?,
            range_end: parse_u64(&row.try_get::<String, _>(3)?)?,
            state: row.try_get(4)?,
        };
        if batch_id == incoming_batch_id
            && existing_batch_digest
                .replace(checkpoint.batch_digest.clone())
                .is_some()
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        if latest
            .as_ref()
            .is_none_or(|value: &LatestCheckpoint| value.batch_sequence < checkpoint.batch_sequence)
        {
            latest = Some(checkpoint);
        }
    }
    Ok(CheckpointState {
        latest,
        existing_batch_digest,
    })
}

async fn lock_outbox_head(
    transaction: &mut Transaction<'_, Postgres>,
    participant_id: Uuid,
    candidate_partition_id: Uuid,
) -> Result<(), CandidateStoreError> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT last_sequence::text FROM candidate.outbox_aggregate_head
           WHERE participant_id=$1 AND aggregate_type='candidate-partition' AND aggregate_id=$2
           FOR UPDATE"#,
    )
    .bind(participant_id)
    .bind(candidate_partition_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(())
}

async fn validate_database_binding(
    transaction: &mut Transaction<'_, Postgres>,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    binding: &CandidatePersistenceBinding,
    material: Option<&CandidateBatchMaterialV1>,
) -> Result<DatabaseBinding, CandidateStoreError> {
    binding.validate_profile_scope(profile)?;
    let row = sqlx::query(
        r#"SELECT sp.source_profile_id,sp.indexer_profile_id,sp.participant_id,sp.privacy_domain_id,sp.chain_namespace,
           sp.source_contract_urn::text,sp.source_profile_cbor,sp.source_profile_digest,sp.reorg_profile_digest,
           sp.finality_mode,sp.confirmation_count,sp.state::text,pp.fact_type,pp.data_class,pp.source_event_type,
           encode(pp.source_contract_address,'hex'),pp.mapping_cbor,pp.mapping_digest,pp.schema_digest,pp.state::text,
           g.generation_digest,g.source_profile_digest,g.projection_schema_digest,g.state::text
           FROM candidate.projection_generation g
           JOIN candidate.projection_profile pp ON pp.projection_profile_id=g.projection_profile_id
           JOIN candidate.source_profile sp ON sp.source_profile_id=pp.source_profile_id
           WHERE g.projection_generation_id=$1"#,
    )
    .bind(binding.projection_generation_id())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(CandidateStoreError::InvalidBinding)?;

    let source_profile_id: Uuid = row.try_get(0)?;
    let indexer_profile_id: Uuid = row.try_get(1)?;
    let participant: Uuid = row.try_get(2)?;
    let privacy: Uuid = row.try_get(3)?;
    let chain_namespace: String = row.try_get(4)?;
    let source_urn: String = row.try_get(5)?;
    let source_cbor: Vec<u8> = row.try_get(6)?;
    let source_digest: Vec<u8> = row.try_get(7)?;
    let reorg_digest: Vec<u8> = row.try_get(8)?;
    let finality_mode: String = row.try_get(9)?;
    let confirmation_count: Option<i32> = row.try_get(10)?;
    let source_state: String = row.try_get(11)?;
    let fact_type: String = row.try_get(12)?;
    let data_class: String = row.try_get(13)?;
    let source_event_type: Option<String> = row.try_get(14)?;
    let source_contract_address: Option<String> = row.try_get(15)?;
    let plan_cbor: Vec<u8> = row.try_get(16)?;
    let plan_digest: Vec<u8> = row.try_get(17)?;
    let schema_digest: Vec<u8> = row.try_get(18)?;
    let plan_state: String = row.try_get(19)?;
    let generation_digest: Vec<u8> = row.try_get(20)?;
    let generation_source_digest: Vec<u8> = row.try_get(21)?;
    let generation_schema_digest: Vec<u8> = row.try_get(22)?;
    let generation_state: String = row.try_get(23)?;

    let exact_source = encode_client_indexer_profile_pc_cbor(profile)
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
    let exact_plan =
        encode_projection_plan_pc_cbor(plan).map_err(|_| CandidateStoreError::InvalidBinding)?;
    let source_content_digest = Sha256::digest(&exact_source).to_vec();
    let plan_content_digest = Sha256::digest(&exact_plan).to_vec();
    let ordered_schemas = plan
        .candidate_schema_digests
        .iter()
        .map(|item| decode_digest(&item.digest))
        .collect::<Result<Vec<_>, _>>()?;
    let exact_schema_digest = Sha256::digest(encode_byte_array(&ordered_schemas)).to_vec();
    let exact_generation_digest = generation_digest_bytes(
        &source_content_digest,
        &plan_content_digest,
        plan.lifecycle_generation,
        &ordered_schemas,
    );
    let expected_namespace = if profile.chain_id.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("eip155:{}", profile.chain_id)
    } else {
        profile.chain_id.clone()
    };
    let expected_fact_type = plan
        .candidate_schema_digests
        .first()
        .map(|v| v.name.as_str())
        .ok_or(CandidateStoreError::InvalidBinding)?;
    let expected_event_type = plan
        .extractor_digests
        .first()
        .map(|v| v.name.as_str())
        .ok_or(CandidateStoreError::InvalidBinding)?;
    let expected_data_class = crate::candidate::authoritative_profile_data_class(profile)?;
    let admitted_data_class = material
        .map(CandidateBatchMaterialV1::admitted_data_class)
        .unwrap_or(expected_data_class);
    if expected_data_class != admitted_data_class || data_class != admitted_data_class {
        return Err(CandidateStoreError::InvalidBinding);
    }
    let event_address = material
        .into_iter()
        .flat_map(|value| value.records().iter())
        .filter_map(|value| match &value.identity {
            CandidateRecordIdentityV1::EventLog {
                contract_address, ..
            } => Some(trim_hex(contract_address).to_owned()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let exact_event_scalars = projection_profile_scalars_match(
        &data_class,
        source_event_type.as_deref(),
        source_contract_address.as_deref(),
        expected_event_type,
        &event_address,
        material,
    );

    if participant != binding.participant_id()
        || privacy != binding.privacy_domain_id()
        || decode_client_indexer_profile_pc_cbor(&source_cbor)
            .map_err(|_| CandidateStoreError::InvalidBinding)?
            != *profile
        || decode_projection_plan_pc_cbor(&plan_cbor)
            .map_err(|_| CandidateStoreError::InvalidBinding)?
            != *plan
        || source_cbor != exact_source
        || plan_cbor != exact_plan
        || source_digest != source_content_digest
        || plan_digest != plan_content_digest
        || generation_source_digest != source_content_digest
        || schema_digest != exact_schema_digest
        || generation_schema_digest != exact_schema_digest
        || generation_digest != exact_generation_digest
        || reorg_digest != decode_digest(&profile.reorg_behavior_digest)?
        || chain_namespace != expected_namespace
        || source_urn != format!("urn:openpc:source-profile:{source_profile_id}")
        || fact_type != expected_fact_type
        || !exact_event_scalars
        || source_state != "QUALIFIED"
        || plan_state != "QUALIFIED"
        || !matches!(generation_state.as_str(), "READY" | "ACTIVE")
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    validate_publication_binding(transaction, profile, binding, material).await?;
    Ok(DatabaseBinding {
        source_profile_id,
        indexer_profile_id,
        chain_namespace,
        finality_mode,
        confirmation_count: confirmation_count
            .map(u32::try_from)
            .transpose()
            .map_err(|_| CandidateStoreError::InvalidBinding)?,
        plan_content_digest,
    })
}

async fn validate_publication_binding(
    transaction: &mut Transaction<'_, Postgres>,
    profile: &ClientIndexerProfileV1,
    binding: &CandidatePersistenceBinding,
    material: Option<&CandidateBatchMaterialV1>,
) -> Result<(), CandidateStoreError> {
    // The generation lock acquired by both mutation owners serializes this
    // read with manager fencing. Legacy component fixtures have no publication;
    // independent admission must require one rather than promote those rows.
    let publication = sqlx::query("select state,acquisition_configuration_cbor,finality_rule_cbor from candidate.source_publication where projection_generation_id=$1")
        .bind(binding.projection_generation_id()).fetch_optional(&mut **transaction).await?;
    if let Some(publication) = publication {
        if publication.try_get::<String, _>(0)? != "PUBLISHED" {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let acquisition = crate::AcquisitionConfiguration::resolve(
            profile,
            &publication.try_get::<Vec<u8>, _>(1)?,
        )?;
        crate::FinalityRule::resolve(profile, &publication.try_get::<Vec<u8>, _>(2)?)?;
        for record in material.into_iter().flat_map(|material| material.records()) {
            let exact = match (&acquisition.request, &record.identity) {
                (
                    crate::AcquisitionRequest::StateCall { target_address, .. },
                    CandidateRecordIdentityV1::StateCall {
                        target_address: observed,
                        call_parameter_digest,
                    },
                ) => {
                    decode_fixed_hex(target_address, 20)? == decode_fixed_hex(observed, 20)?
                        && decode_digest(call_parameter_digest)?
                            == decode_digest(
                                &acquisition
                                    .state_call_parameter_digest(record.record.block_number)?,
                            )?
                }
                (
                    crate::AcquisitionRequest::ExternalDecision { target_address, .. },
                    CandidateRecordIdentityV1::ExternalObservation {
                        target_address: observed,
                        call_parameter_digest,
                    },
                ) => {
                    let request = acquisition.external_request(
                        profile,
                        record.record.block_number,
                        &record.record.canonical_block_hash,
                    )?;
                    decode_fixed_hex(target_address, 20)? == decode_fixed_hex(observed, 20)?
                        && request
                            .digest()
                            .map_err(|_| CandidateStoreError::InvalidBinding)?
                            .as_str()
                            == call_parameter_digest.trim_start_matches("sha256:")
                }
                (
                    crate::AcquisitionRequest::EventLogs {
                        contract_address,
                        event_signature,
                        ..
                    },
                    CandidateRecordIdentityV1::EventLog {
                        contract_address: observed_address,
                        event_signature: observed_signature,
                        ..
                    },
                ) => {
                    decode_fixed_hex(contract_address, 20)?
                        == decode_fixed_hex(observed_address, 20)?
                        && decode_fixed_hex(event_signature, 32)?
                            == decode_fixed_hex(observed_signature, 32)?
                }
                _ => false,
            };
            if !exact {
                return Err(CandidateStoreError::InvalidBinding);
            }
        }
    }
    Ok(())
}

fn exact_partition<'a>(
    plan: &'a ProjectionPlanV1,
    source_id: &str,
    partition_id: &str,
) -> Result<&'a ProjectionPartitionV1, CandidateStoreError> {
    let mut values = plan
        .partitions
        .iter()
        .filter(|value| value.source_id == source_id && value.partition_id == partition_id);
    let value = values.next().ok_or(CandidateStoreError::InvalidBinding)?;
    if values.next().is_some() {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(value)
}

fn partition_end(partition: &ProjectionPartitionV1) -> (Option<u64>, bool) {
    match partition.range.end {
        RangeEndV1::Open => (None, true),
        RangeEndV1::Inclusive(value) => (Some(value), false),
    }
}

pub(crate) fn partition_binding(
    binding: &CandidatePersistenceBinding,
    source_profile_id: Uuid,
    plan_digest: &[u8],
    partition: &ProjectionPartitionV1,
) -> (Vec<u8>, Vec<u8>) {
    let (range_end, range_end_open) = partition_end(partition);
    let value = json!({
        "participantId": binding.participant_id().to_string(),
        "privacyDomainId": binding.privacy_domain_id().to_string(),
        "projectionGenerationId": binding.projection_generation_id().to_string(),
        "sourceProfileId": source_profile_id.to_string(),
        "planContentDigest": sha_digest(plan_digest),
        "sourceId": partition.source_id,
        "partitionId": partition.partition_id,
        "range": {"start": partition.range.start.to_string(), "end": range_end.map(|v| v.to_string()), "endOpen": range_end_open},
    });
    let cbor = canonical_cbor(&value);
    let digest = Sha256::digest(&cbor).to_vec();
    (cbor, digest)
}

async fn registered_partition(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
    source_profile_id: Uuid,
    plan_digest: &[u8],
    partition: &ProjectionPartitionV1,
) -> Result<RegisteredPartition, CandidateStoreError> {
    let (expected_cbor, expected_digest) =
        partition_binding(binding, source_profile_id, plan_digest, partition);
    let (expected_range_end, expected_range_end_open) = partition_end(partition);
    let row = sqlx::query(
        r#"SELECT candidate_partition_id,source_profile_id,plan_digest,
                  range_start::text,range_end::text,range_end_open,binding_cbor,binding_digest
           FROM candidate.candidate_partition
           WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3
             AND source_profile_id=$4 AND source_id=$5 AND partition_id=$6"#,
    )
    .bind(binding.participant_id())
    .bind(binding.privacy_domain_id())
    .bind(binding.projection_generation_id())
    .bind(source_profile_id)
    .bind(&partition.source_id)
    .bind(&partition.partition_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(CandidateStoreError::InvalidBinding)?;
    let candidate_partition_id: Uuid = row.try_get(0)?;
    let stored_source_profile_id: Uuid = row.try_get(1)?;
    let stored_plan_digest: Vec<u8> = row.try_get(2)?;
    let range_start: String = row.try_get(3)?;
    let range_end: Option<String> = row.try_get(4)?;
    let range_end_open: bool = row.try_get(5)?;
    let binding_cbor: Vec<u8> = row.try_get(6)?;
    let binding_digest: Vec<u8> = row.try_get(7)?;
    if stored_source_profile_id != source_profile_id
        || stored_plan_digest != plan_digest
        || parse_u64(&range_start)? != partition.range.start
        || range_end.as_deref().map(parse_u64).transpose()? != expected_range_end
        || range_end_open != expected_range_end_open
        || binding_cbor != expected_cbor
        || binding_digest != expected_digest
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(RegisteredPartition {
        candidate_partition_id,
    })
}

fn validate_finality_against_database(
    block: &crate::CandidateBlockObservationV1,
    database: &DatabaseBinding,
) -> Result<(), CandidateStoreError> {
    match (&block.finality, database.finality_mode.as_str()) {
        (CandidateBlockFinalityV1::SafeTag { .. }, "SAFE_TAG")
        | (CandidateBlockFinalityV1::FinalizedTag { .. }, "FINALIZED_TAG") => Ok(()),
        (CandidateBlockFinalityV1::Confirmations { head_anchor, .. }, "CONFIRMATIONS") => {
            let required = database
                .confirmation_count
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let additional_confirmations = u64::from(required)
                .checked_sub(1)
                .ok_or(CandidateStoreError::InvalidBinding)?;
            let minimum_head = block
                .block_number
                .checked_add(additional_confirmations)
                .ok_or(CandidateStoreError::InvalidBinding)?;
            if head_anchor
                .block_number
                .is_some_and(|head| head >= minimum_head)
            {
                Ok(())
            } else {
                Err(CandidateStoreError::InvalidBinding)
            }
        }
        _ => Err(CandidateStoreError::InvalidBinding),
    }
}

type FinalityColumns = (
    &'static str,
    &'static str,
    Vec<u8>,
    Option<u64>,
    Option<Vec<u8>>,
);
fn finality_columns(
    value: &CandidateBlockFinalityV1,
) -> Result<FinalityColumns, CandidateStoreError> {
    match value {
        CandidateBlockFinalityV1::Unfinalized { evidence_digest } => Ok((
            "UNFINALIZED",
            "UNFINALIZED",
            decode_digest(evidence_digest)?,
            None,
            None,
        )),
        CandidateBlockFinalityV1::SafeTag {
            evidence_digest, ..
        } => Ok((
            "SAFE",
            "SAFE_TAG",
            decode_digest(evidence_digest)?,
            None,
            None,
        )),
        CandidateBlockFinalityV1::FinalizedTag {
            evidence_digest, ..
        } => Ok((
            "FINALIZED",
            "FINALIZED_TAG",
            decode_digest(evidence_digest)?,
            None,
            None,
        )),
        CandidateBlockFinalityV1::Confirmations {
            head_anchor,
            evidence_digest,
        } => Ok((
            "FINALIZED",
            "CONFIRMATIONS",
            decode_digest(evidence_digest)?,
            head_anchor.block_number,
            head_anchor
                .block_hash
                .as_deref()
                .map(|v| decode_fixed_hex(v, 32))
                .transpose()?,
        )),
    }
}

fn validate_reorg(value: &ReorgInvalidation) -> Result<(), CandidateStoreError> {
    let (old_genesis_hash, old_block_hash) = decode_anchor_identity(&value.old_anchor)?;
    let (new_genesis_hash, new_block_hash) = decode_anchor_identity(&value.new_anchor)?;
    if value.source_id.is_empty()
        || value.partition_id.is_empty()
        || value.affected_start == 0
        || value.affected_start > value.affected_end
        || value.old_anchor.chain_id != value.new_anchor.chain_id
        || old_genesis_hash != new_genesis_hash
        || value.old_anchor.network_id != value.new_anchor.network_id
        || value.old_anchor.block_number != value.new_anchor.block_number
        || old_block_hash == new_block_hash
        || value.old_anchor.block_number != Some(value.affected_start)
        || !matches!(value.old_anchor.selector_kind, BlockSelectorKind::Pinned)
        || !matches!(value.new_anchor.selector_kind, BlockSelectorKind::Pinned)
        || value.old_anchor.pending_authorized_by_profile
        || value.new_anchor.pending_authorized_by_profile
        || decode_digest(&value.evidence_digest).is_err()
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(())
}

fn validate_affected_event_ids(event_ids: &[Uuid]) -> Result<(), CandidateStoreError> {
    if event_ids.iter().collect::<BTreeSet<_>>().len() != event_ids.len() {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(())
}

fn decode_anchor_identity(
    anchor: &ChainReadAnchorV1,
) -> Result<(Vec<u8>, Vec<u8>), CandidateStoreError> {
    Ok((
        decode_digest(&anchor.genesis_hash)?,
        decode_fixed_hex(
            anchor
                .block_hash
                .as_deref()
                .ok_or(CandidateStoreError::InvalidBinding)?,
            32,
        )?,
    ))
}

fn anchor_matches_profile(
    anchor: &ChainReadAnchorV1,
    profile: &ClientIndexerProfileV1,
) -> Result<bool, CandidateStoreError> {
    let (anchor_genesis_hash, _) = decode_anchor_identity(anchor)?;
    Ok(anchor.chain_id == profile.chain_id
        && anchor_genesis_hash == decode_digest(&profile.genesis_hash)?
        && anchor.network_id == profile.network_id)
}

async fn set_context(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
) -> Result<(), CandidateStoreError> {
    sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
        .bind(binding.participant_id())
        .bind(binding.privacy_domain_id())
        .bind(binding.operation_id())
        .bind(CANDIDATE_ACTION)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT openpc.assert_request_context(true)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
    digest: &[u8],
    reason: &str,
) -> Result<(), CandidateStoreError> {
    sqlx::query(
        r#"INSERT INTO candidate.quarantine_record(participant_id,privacy_domain_id,object_type,object_id,reason_code,payload_digest,retry_exhausted_at,recovery_state)
           VALUES ($1,$2,'SOURCE_PAYLOAD',$3,$4,$5,clock_timestamp(),'RECOVERY') ON CONFLICT (object_type,object_id,payload_digest) DO NOTHING"#,
    ).bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(binding.projection_generation_id())
      .bind(reason).bind(digest).execute(&mut **transaction).await?;
    Ok(())
}

struct EventEmission<'a, T: ?Sized> {
    candidate_partition_id: Uuid,
    source: &'a str,
    subject: &'a str,
    event_type: &'a str,
    schema: &'a str,
    payload: &'a T,
}

async fn emit_event<T: Serialize + ?Sized>(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &CandidatePersistenceBinding,
    event: EventEmission<'_, T>,
) -> Result<Uuid, CandidateStoreError> {
    let payload_json =
        serde_json::to_value(event.payload).map_err(|_| CandidateStoreError::InvalidBatch)?;
    let payload_cbor = canonical_cbor(&payload_json);
    let payload_digest = Sha256::digest(&payload_cbor).to_vec();
    sqlx::query_scalar(
        "SELECT candidate.emit_outbox_event($1,$2,'candidate-partition',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    ).bind(binding.participant_id()).bind(binding.privacy_domain_id()).bind(event.candidate_partition_id)
      .bind(event.source).bind(event.subject).bind(event.event_type).bind(event.schema).bind(binding.correlation_id())
      .bind(binding.operation_id()).bind(payload_cbor).bind(&payload_json).bind(payload_digest)
      .fetch_one(&mut **transaction).await.map_err(Into::into)
}

fn predecessor_digest(
    batch: &CandidateProjectionBatchV1,
) -> Result<Option<Vec<u8>>, CandidateStoreError> {
    if batch.predecessor_batch_digest == "GENESIS" {
        Ok(None)
    } else {
        decode_digest(&batch.predecessor_batch_digest).map(Some)
    }
}

fn checkpoint_cbor(
    batch: &CandidateProjectionBatchV1,
    authoritative_empty: bool,
    decode_failures: &[CandidateDecodeFailureV1],
) -> Result<Vec<u8>, CandidateStoreError> {
    let position = CandidateCheckpointPositionV1 {
        authoritative_empty,
        batch_id: &batch.batch_id,
        batch_sequence: batch.batch_sequence.to_string(),
        completed_watermark: CandidateCompletedWatermarkV1 {
            block_hash: canonical_hex(&batch.completed_watermark.canonical_block_hash),
            block_number: batch.completed_watermark.block_number.to_string(),
        },
        decode_failures,
        missing_intervals: batch
            .missing_intervals
            .iter()
            .map(|value| inclusive_range(value.start, value.end))
            .collect(),
        ordered_observation_evidence: batch
            .observations
            .iter()
            .map(|value| canonical_digest(&value.evidence_digest))
            .collect(),
        partition_id: &batch.partition_id,
        plan_digest: canonical_digest(&batch.plan_digest),
        predecessor_batch_digest: wire_predecessor_digest(batch),
        profile_digest: canonical_digest(&batch.profile_digest),
        range: inclusive_range(batch.range.start, batch.range.end),
        record_count: batch.records.len().to_string(),
        source_id: &batch.source_id,
    };
    let logical_value =
        serde_json::to_value(position).map_err(|_| CandidateStoreError::InvalidBatch)?;
    Ok(canonical_cbor(&logical_value))
}

fn candidate_decode_failures(batch: &CandidateProjectionBatchV1) -> Vec<CandidateDecodeFailureV1> {
    batch
        .decode_failures
        .iter()
        .map(|value| CandidateDecodeFailureV1 {
            source_id: value.source_id.clone(),
            sequence: value.sequence.to_string(),
            error_digest: canonical_digest(&value.error_digest),
            evidence_digest: canonical_digest(&value.evidence_digest),
        })
        .collect()
}

fn wire_predecessor_digest(batch: &CandidateProjectionBatchV1) -> Option<String> {
    (batch.predecessor_batch_digest != "GENESIS")
        .then(|| canonical_digest(&batch.predecessor_batch_digest))
}

fn inclusive_range(start: u64, end: u64) -> CandidateInclusiveRangeV1 {
    CandidateInclusiveRangeV1 {
        start: start.to_string(),
        end: end.to_string(),
    }
}

fn anchor_payload(anchor: &ChainReadAnchorV1) -> Result<CandidateAnchorV1, CandidateStoreError> {
    let (genesis_hash, block_hash) = decode_anchor_identity(anchor)?;
    Ok(CandidateAnchorV1 {
        chain_id: anchor.chain_id.clone(),
        genesis_hash: format!("0x{}", hex_bytes(&genesis_hash)),
        network_id: anchor.network_id.clone(),
        selector_kind: "PINNED",
        block_number: anchor
            .block_number
            .ok_or(CandidateStoreError::InvalidBinding)?
            .to_string(),
        block_hash: format!("0x{}", hex_bytes(&block_hash)),
        pending_authorized_by_profile: false,
    })
}

fn projection_profile_scalars_match(
    data_class: &str,
    source_event_type: Option<&str>,
    source_contract_address: Option<&str>,
    expected_event_type: &str,
    event_addresses: &BTreeSet<String>,
    material: Option<&CandidateBatchMaterialV1>,
) -> bool {
    match data_class {
        "EVENT_LOG" => {
            source_event_type == Some(expected_event_type)
                && source_contract_address.is_some()
                && material.is_none_or(|value| {
                    value.records().is_empty()
                        || (event_addresses.len() == 1
                            && source_contract_address
                                == event_addresses.first().map(String::as_str))
                })
        }
        "STATE_CALL"
        | "EXTERNAL_OBSERVATION"
        | "TRANSACTION_RECEIPT"
        | "BLOCK_HEADER"
        | "FULL_BLOCK_TRANSACTIONS" => {
            source_event_type.is_none() && source_contract_address.is_none()
        }
        _ => false,
    }
}

fn require_uuid_v7(value: Uuid) -> Result<(), CandidateStoreError> {
    if value.get_version_num() == 7 {
        Ok(())
    } else {
        Err(CandidateStoreError::InvalidBinding)
    }
}

fn source_profile_urn(value: Uuid) -> Result<String, CandidateStoreError> {
    require_uuid_v7(value)?;
    Ok(format!("urn:openpc:source-profile:{value}"))
}

fn indexer_profile_urn(value: Uuid) -> Result<String, CandidateStoreError> {
    require_uuid_v7(value)?;
    Ok(format!("urn:openpc:indexer-profile:{value}"))
}

fn projection_generation_urn(value: Uuid) -> Result<String, CandidateStoreError> {
    require_uuid_v7(value)?;
    Ok(format!("urn:openpc:projection-generation:{value}"))
}

fn candidate_partition_urn(value: Uuid) -> Result<String, CandidateStoreError> {
    require_uuid_v7(value)?;
    Ok(format!("urn:openpc:candidate-partition:{value}"))
}

fn candidate_urn(value: Uuid) -> Result<String, CandidateStoreError> {
    require_uuid_v7(value)?;
    Ok(format!("urn:openpc:candidate:{value}"))
}

pub(crate) fn canonical_cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_json_cbor(&mut out, value);
    out
}
fn encode_json_cbor(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Number(v) => cbor_uint(out, v.as_u64().expect("unsigned JSON number")),
        Value::String(v) => cbor_text(out, v),
        Value::Array(values) => {
            cbor_len(out, 4, values.len() as u64);
            for value in values {
                encode_json_cbor(out, value);
            }
        }
        Value::Object(values) => encode_canonical_map(out, values),
    }
}
fn encode_canonical_map(out: &mut Vec<u8>, values: &Map<String, Value>) {
    let mut entries = values
        .iter()
        .map(|(key, value)| {
            let mut encoded = Vec::new();
            cbor_text(&mut encoded, key);
            (encoded, value)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| match left.len().cmp(&right.len()) {
        Ordering::Equal => left.cmp(right),
        value => value,
    });
    cbor_len(out, 5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(&key);
        encode_json_cbor(out, value);
    }
}
pub(crate) fn generation_digest_bytes(
    source: &[u8],
    plan: &[u8],
    generation: u64,
    schemas: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_len(&mut out, 4, 4);
    cbor_bytes(&mut out, source);
    cbor_bytes(&mut out, plan);
    cbor_uint(&mut out, generation);
    out.extend_from_slice(&encode_byte_array(schemas));
    Sha256::digest(out).to_vec()
}
pub(crate) fn encode_byte_array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_len(&mut out, 4, values.len() as u64);
    for value in values {
        cbor_bytes(&mut out, value);
    }
    out
}
fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_len(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_len(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    cbor_len(out, 0, value);
}
fn cbor_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}
pub(crate) fn sha_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_bytes(bytes))
}
fn canonical_digest(value: &str) -> String {
    format!("sha256:{}", value.strip_prefix("sha256:").unwrap_or(value))
}
fn canonical_hex(value: &str) -> String {
    format!("0x{}", trim_hex(value))
}
fn trim_hex(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}
fn parse_u64(value: &str) -> Result<u64, CandidateStoreError> {
    value
        .parse()
        .map_err(|_| CandidateStoreError::InvalidBinding)
}
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgRow;

    fn take_exactly_one_proof_row(mut rows: Vec<PgRow>, owner: &str) -> PgRow {
        assert_eq!(rows.len(), 1, "{owner}: expected exactly one row");
        rows.remove(0)
    }

    #[tokio::test]
    async fn store_internal_outbox_json_cbor_proof_emits_exact_owned_ids() {
        let Ok(database_url) = std::env::var("OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect isolated Gate3 proof database");
        let mut transaction = pool.begin().await.expect("begin read-only proof");
        sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
            .bind(
                Uuid::parse_str("018f47a5-4a58-7b21-8f3a-111111111111")
                    .expect("participant UUIDv7"),
            )
            .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-222222222222").expect("privacy UUIDv7"))
            .bind(
                Uuid::parse_str("018f47a5-4a58-7b21-8f3a-666666666666").expect("operation UUIDv7"),
            )
            .bind(CANDIDATE_ACTION)
            .execute(&mut *transaction)
            .await
            .expect("set exact proof context");
        sqlx::query("SELECT openpc.assert_request_context(true)")
            .execute(&mut *transaction)
            .await
            .expect("assert exact proof context");

        let partition_rows = sqlx::query(
            "SELECT candidate_partition_id::text FROM candidate.candidate_partition WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3 AND source_profile_id=$4 AND source_id=$5 AND partition_id=$6",
        )
        .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-111111111111").expect("participant UUIDv7"))
        .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-222222222222").expect("privacy UUIDv7"))
        .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-555555555555").expect("generation UUIDv7"))
        .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-333333333333").expect("source profile UUIDv7"))
        .bind("source")
        .bind("partition")
        .fetch_all(&mut *transaction)
        .await
        .expect("resolve exact primary candidate partition");
        let partition = take_exactly_one_proof_row(partition_rows, "primary candidate partition");
        let partition_id = partition
            .try_get::<String, _>(0)
            .expect("primary candidate partition UUID");

        let checkpoint_rows = sqlx::query(
            "SELECT payload_json::text,payload_cbor FROM candidate.outbox_event WHERE aggregate_type='candidate-partition' AND aggregate_id=$1 AND event_type=$2 AND aggregate_sequence=3 AND payload_json->>'batchId'='batch-1'",
        )
        .bind(Uuid::parse_str(&partition_id).expect("primary candidate partition UUIDv7"))
        .bind(CHECKPOINT_EVENT)
        .fetch_all(&mut *transaction)
        .await
        .expect("actual checkpoint outbox payload");
        let checkpoint = take_exactly_one_proof_row(checkpoint_rows, "batch-1 checkpoint outbox");
        let checkpoint_json: Value = serde_json::from_str(
            &checkpoint
                .try_get::<String, _>(0)
                .expect("checkpoint JSON text"),
        )
        .expect("typed checkpoint JSON value");
        let checkpoint_cbor = checkpoint
            .try_get::<Vec<u8>, _>(1)
            .expect("checkpoint CBOR bytes");
        let failures = checkpoint_json["decodeFailures"]
            .as_array()
            .expect("closed decodeFailures array");
        assert!(failures.is_empty());
        assert!(
            checkpoint_json["missingIntervals"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        assert_eq!(checkpoint_json["authoritativeEmpty"], false);
        assert_eq!(canonical_cbor(&checkpoint_json), checkpoint_cbor);
        println!("I06_GATE3_ASSERTION|RUST_STORE|I06-G3-M14-I17-P-JSON-CBOR|PASS");

        let decode_failures = vec![
            CandidateDecodeFailureV1 {
                source_id: "source".into(),
                sequence: "1".into(),
                error_digest: format!("sha256:{}", "11".repeat(32)),
                evidence_digest: format!("sha256:{}", "22".repeat(32)),
            },
            CandidateDecodeFailureV1 {
                source_id: "source".into(),
                sequence: "2".into(),
                error_digest: format!("sha256:{}", "33".repeat(32)),
                evidence_digest: format!("sha256:{}", "44".repeat(32)),
            },
        ];
        let decode_json =
            serde_json::to_value(&decode_failures).expect("serialize closed failures");
        let decoded = decode_json.as_array().expect("decode failure array");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0]["sequence"], "1");
        assert_eq!(decoded[1]["sequence"], "2");
        assert!(decoded.iter().all(|failure| {
            failure.as_object().is_some_and(|object| {
                object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["errorDigest", "evidenceDigest", "sequence", "sourceId"])
            })
        }));
        let mut changed_checkpoint = checkpoint_json.clone();
        changed_checkpoint["decodeFailures"] = decode_json;
        assert_ne!(canonical_cbor(&changed_checkpoint), checkpoint_cbor);
        println!("I06_GATE3_ASSERTION|RUST_STORE|I06-G3-M14-I17-N-DECODE-JSON-CBOR|PASS");

        let candidate_rows = sqlx::query(
            "SELECT candidate_event_id::text FROM candidate.candidate_event WHERE projection_generation_id=$1 AND candidate_partition_id=$2 AND record_kind='EVENT_LOG' AND record_id='record-1-1'",
        )
        .bind(Uuid::parse_str("018f47a5-4a58-7b21-8f3a-555555555555").expect("generation UUIDv7"))
        .bind(Uuid::parse_str(&partition_id).expect("primary candidate partition UUIDv7"))
        .fetch_all(&mut *transaction)
        .await
        .expect("resolve exact primary EVENT_LOG candidate");
        let candidate = take_exactly_one_proof_row(candidate_rows, "primary EVENT_LOG candidate");
        let candidate_id = candidate
            .try_get::<String, _>(0)
            .expect("primary EVENT_LOG candidate UUID");
        let observed_rows = sqlx::query(
            "SELECT payload_json::text,payload_cbor,event_type::text,schema_uri::text,aggregate_id::text FROM candidate.outbox_event WHERE aggregate_type='candidate-partition' AND aggregate_id=$1 AND event_type=$2 AND aggregate_sequence=1 AND payload_json->>'candidateId'=$3",
        )
        .bind(Uuid::parse_str(&partition_id).expect("primary candidate partition UUIDv7"))
        .bind(OBSERVED_EVENT)
        .bind(format!("urn:openpc:candidate:{candidate_id}"))
        .fetch_all(&mut *transaction)
        .await
        .expect("actual observed outbox payload");
        let observed = take_exactly_one_proof_row(observed_rows, "record-1-1 observed outbox");
        assert_eq!(
            observed.try_get::<String, _>(2).expect("event type"),
            OBSERVED_EVENT
        );
        assert_eq!(
            observed.try_get::<String, _>(3).expect("schema"),
            OBSERVED_SCHEMA
        );
        assert!(
            observed.try_get::<String, _>(4).is_ok_and(
                |value| Uuid::parse_str(&value).is_ok_and(|id| id.get_version_num() == 7)
            )
        );
        let observed_json: Value = serde_json::from_str(
            &observed
                .try_get::<String, _>(0)
                .expect("observed JSON text"),
        )
        .expect("typed observed JSON value");
        let observed_cbor = observed
            .try_get::<Vec<u8>, _>(1)
            .expect("observed CBOR bytes");
        assert_eq!(canonical_cbor(&observed_json), observed_cbor);
        let mut changed_observed = observed_json;
        changed_observed["candidateDigest"] = Value::String(format!("sha256:{}", "ff".repeat(32)));
        assert_ne!(canonical_cbor(&changed_observed), observed_cbor);
        println!("I06_GATE3_ASSERTION|RUST_STORE|I06-G3-M14-I18-N-JSON-CBOR|PASS");

        transaction
            .rollback()
            .await
            .expect("rollback read-only proof");
        pool.close().await;
    }

    fn reorg_validation_anchor(genesis_hash: String, block_hash: String) -> ChainReadAnchorV1 {
        ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash,
            network_id: "openpc-local".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(8),
            block_hash: Some(block_hash),
            pending_authorized_by_profile: false,
        }
    }

    fn reorg_validation_fixture(
        old_anchor: ChainReadAnchorV1,
        new_anchor: ChainReadAnchorV1,
    ) -> ReorgInvalidation {
        let id = Uuid::parse_str("018f47a5-4a58-7b21-8f3a-111111111111").expect("fixture UUIDv7");
        ReorgInvalidation {
            binding: CandidatePersistenceBinding::try_new(id, id, id, id, id)
                .expect("fixture binding"),
            source_id: "source".into(),
            partition_id: "partition".into(),
            observation_profile_cbor: Vec::new(),
            observation_plan_cbor: Vec::new(),
            old_anchor,
            new_anchor,
            affected_start: 8,
            affected_end: 8,
            evidence_digest: "33".repeat(32),
            observation_method: "eth_getLogs".into(),
            observation_data_class: "EVENT_LOG".into(),
        }
    }

    #[test]
    fn reorg_anchor_validation_uses_decoded_hash_identity_and_canonical_wire_hex() {
        let genesis = "ab".repeat(32);
        let old_hash = "22".repeat(32);
        let new_hash = "33".repeat(32);
        let valid = reorg_validation_fixture(
            reorg_validation_anchor(genesis.clone(), old_hash.clone()),
            reorg_validation_anchor(format!("0x{genesis}"), format!("0x{new_hash}")),
        );
        assert!(validate_reorg(&valid).is_ok());
        let payload = anchor_payload(valid.new_anchor()).expect("canonical wire anchor");
        assert_eq!(payload.genesis_hash, format!("0x{genesis}"));
        assert_eq!(payload.block_hash, format!("0x{new_hash}"));

        let published_genesis = reorg_validation_fixture(
            reorg_validation_anchor(format!("sha256:{genesis}"), old_hash.clone()),
            reorg_validation_anchor(format!("sha256:{genesis}"), new_hash.clone()),
        );
        validate_reorg(&published_genesis).expect("published genesis encoding");
        assert_eq!(
            anchor_payload(published_genesis.new_anchor())
                .unwrap()
                .genesis_hash,
            payload.genesis_hash
        );

        let same_identity = reorg_validation_fixture(
            reorg_validation_anchor(genesis.clone(), old_hash.clone()),
            reorg_validation_anchor(format!("0x{genesis}"), format!("0x{old_hash}")),
        );
        assert!(matches!(
            validate_reorg(&same_identity),
            Err(CandidateStoreError::InvalidBinding)
        ));

        let mut missing_old_block = valid.clone();
        missing_old_block.old_anchor.block_hash = None;
        let mut missing_new_block = valid.clone();
        missing_new_block.new_anchor.block_hash = None;

        for invalid in [
            missing_old_block,
            missing_new_block,
            reorg_validation_fixture(
                reorg_validation_anchor("not-a-genesis-hash".into(), old_hash.clone()),
                reorg_validation_anchor(genesis.clone(), new_hash.clone()),
            ),
            reorg_validation_fixture(
                reorg_validation_anchor(genesis.clone(), old_hash.clone()),
                reorg_validation_anchor("not-a-genesis-hash".into(), new_hash.clone()),
            ),
            reorg_validation_fixture(
                reorg_validation_anchor(genesis.clone(), "not-a-block-hash".into()),
                reorg_validation_anchor(genesis.clone(), new_hash.clone()),
            ),
            reorg_validation_fixture(
                reorg_validation_anchor(genesis.clone(), old_hash.clone()),
                reorg_validation_anchor(genesis.clone(), "not-a-block-hash".into()),
            ),
            reorg_validation_fixture(
                reorg_validation_anchor(genesis.to_uppercase(), old_hash),
                reorg_validation_anchor(genesis, new_hash),
            ),
        ] {
            assert!(matches!(
                validate_reorg(&invalid),
                Err(CandidateStoreError::InvalidBinding)
            ));
        }

        assert!(validate_affected_event_ids(&[]).is_ok());
        let event_id =
            Uuid::parse_str("018f47a5-4a58-7b21-8f3a-777777777777").expect("fixture UUIDv7");
        assert!(validate_affected_event_ids(&[event_id]).is_ok());
        assert!(matches!(
            validate_affected_event_ids(&[event_id, event_id]),
            Err(CandidateStoreError::InvalidBinding)
        ));
    }

    #[test]
    fn canonical_wire_cbor_and_digest_helpers_are_deterministic() {
        let first = json!({"z":"sha256:aa","a":["1",null,false]});
        let second = json!({"a":["1",null,false],"z":"sha256:aa"});
        assert_eq!(canonical_cbor(&first), canonical_cbor(&second));
        assert_eq!(canonical_cbor(&first)[0], 0xa2);
        assert_eq!(
            generation_digest_bytes(&[1_u8; 32], &[2_u8; 32], 1, &[vec![3_u8; 32]]).len(),
            32
        );
    }

    #[test]
    fn decode_failure_wire_owner_is_closed_and_field_complete() {
        let value = serde_json::to_value(CandidateDecodeFailureV1 {
            source_id: "source".into(),
            sequence: "1".into(),
            error_digest: format!("sha256:{}", "11".repeat(32)),
            evidence_digest: format!("sha256:{}", "22".repeat(32)),
        })
        .expect("serializable wire owner");
        let object = value.as_object().expect("closed object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["errorDigest", "evidenceDigest", "sequence", "sourceId"])
        );
        assert!(!object.contains_key("anchor"));
        assert_eq!(canonical_cbor(&value), canonical_cbor(&value.clone()));
    }

    #[test]
    fn projection_profile_truth_table_is_closed() {
        let address = "11".repeat(20);
        let addresses = BTreeSet::from([address.clone()]);
        assert!(projection_profile_scalars_match(
            "EVENT_LOG",
            Some("event"),
            Some(&address),
            "event",
            &addresses,
            None,
        ));
        for data_class in [
            "STATE_CALL",
            "TRANSACTION_RECEIPT",
            "BLOCK_HEADER",
            "FULL_BLOCK_TRANSACTIONS",
        ] {
            assert!(projection_profile_scalars_match(
                data_class,
                None,
                None,
                "event",
                &BTreeSet::new(),
                None,
            ));
            assert!(!projection_profile_scalars_match(
                data_class,
                Some("event"),
                None,
                "event",
                &BTreeSet::new(),
                None,
            ));
            assert!(!projection_profile_scalars_match(
                data_class,
                None,
                Some(&address),
                "event",
                &BTreeSet::new(),
                None,
            ));
        }
        assert!(!projection_profile_scalars_match(
            "EVENT_LOG",
            None,
            Some(&address),
            "event",
            &addresses,
            None,
        ));
        assert!(!projection_profile_scalars_match(
            "EVENT_LOG",
            Some("event"),
            None,
            "event",
            &addresses,
            None,
        ));
        assert!(!projection_profile_scalars_match(
            "UNKNOWN",
            None,
            None,
            "event",
            &BTreeSet::new(),
            None,
        ));
    }
}
