//! Authenticated source acquisition into the separate candidate store. All
//! source requests cross the runtime target; candidates confer no fact authority.
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpc_multi_rpc::{provider_connection::ProviderConnection, source_header::SourceBlockHeader};
use pc_provider_api::{
    BlockSelectorKind, CandidateProjectionBatchV1, CandidateRecordV1, ChainReadAnchorV1,
    CompletedWatermarkV1, InclusiveRangeV1, RangeEndV1, SequencedObservationV1, SourceAuthority,
};
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::{
    AcquisitionRequest, CandidateBatchMaterialV1, CandidateBlockFinalityV1,
    CandidateBlockObservationV1, CandidatePersistenceBinding, CandidateRecordIdentityV1,
    CandidateRecordMaterialV1, CandidateStore, CandidateStoreError, DecodedAcquisitionRequest,
    FinalityMode, PersistenceOutcome, PublishedAcquisitionInputs, candidate::digest_hex,
    store::canonical_cbor,
};

mod codec;
mod relationship;
mod reorg;
pub use codec::{state_result_extractor, state_result_schema};
pub use relationship::{
    RGRA_EVENT_NAME, RGRA_EVENT_SIGNATURE, relationship_candidate, relationship_extractor,
    relationship_schema,
};

pub fn external_schema() -> pc_provider_api::NamedDigestV1 {
    pc_provider_api::NamedDigestV1 {
        name: "FactAdmissionCandidateV1".into(),
        digest: "sha256:b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525".into(),
    }
}
pub fn external_extractor() -> pc_provider_api::NamedDigestV1 {
    pc_provider_api::NamedDigestV1 { name:"ExternalDecisionAdapterV1".into(),digest:format!("sha256:{}",digest_hex(b"ExternalDecisionObservationV1:closed-scope-provider-request-occurrence-response-boolean:v1")) }
}

/// Stable scheduler identity and bounded requested work, never caller-supplied
/// source observations, authority, completeness or finality assertions.
pub struct AcquisitionBatch {
    pub binding: CandidatePersistenceBinding,
    pub source_id: String,
    pub partition_id: String,
    pub batch_id: String,
    pub sequence: u64,
    pub predecessor_digest: String,
    pub range: InclusiveRangeV1,
}

#[derive(Debug, thiserror::Error)]
pub enum AcquisitionError {
    #[error("source acquisition inputs or observations rejected: {0}")]
    Acquisition(#[from] CandidateStoreError),
    #[error("candidate material rejected: {0}")]
    Material(CandidateStoreError),
    #[error("candidate persistence rejected: {0}")]
    Persistence(CandidateStoreError),
}

struct SourceRead {
    value: Value,
    evidence: String,
}
struct Source<'a> {
    connection: &'a ProviderConnection,
    inputs: &'a PublishedAcquisitionInputs,
    remaining_bytes: usize,
    deadline: Instant,
}
impl Source<'_> {
    async fn read(&mut self, block: u64, header: bool) -> Result<SourceRead, CandidateStoreError> {
        let acquisition = self.inputs.acquisition();
        let (method, params) = if header {
            (
                "eth_getBlockByNumber",
                json!([format!("0x{block:x}"), false]),
            )
        } else {
            (
                acquisition.request.method(),
                acquisition.primary_params(block)?,
            )
        };
        let request = json!({"jsonrpc":"2.0","id":format!("openpc-acquire-{method}-{block}"),"method":method,"params":params});
        let encoded =
            serde_json::to_vec(&request).map_err(|_| CandidateStoreError::InvalidBatch)?;
        let decoded = DecodedAcquisitionRequest::decode(
            self.inputs.profile(),
            self.inputs.plan(),
            &self.inputs.source().acquisition_configuration_cbor,
            &encoded,
        )?;
        let maximum = self
            .inputs
            .profile()
            .limits
            .max_response_bytes
            .min(self.inputs.plan().limits.max_response_bytes)
            .min(131_072) as usize;
        if maximum == 0 || self.remaining_bytes < maximum || Instant::now() >= self.deadline {
            return Err(CandidateStoreError::InvalidBatch);
        }
        let response = self
            .connection
            .post_json_with_response_limit(
                decoded.body().to_vec(),
                self.deadline.min(Instant::now() + Duration::from_secs(5)),
                maximum,
            )
            .await
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        let response = decoded.validate_response(
            &response,
            maximum,
            self.inputs
                .profile()
                .limits
                .max_depth
                .min(self.inputs.plan().limits.max_depth) as usize,
        )?;
        self.remaining_bytes -= response.len();
        let evidence = digest_hex(&canonical_cbor(&json!([
            "openpc:acquired-source-exchange:v1",
            digest_hex(decoded.body()),
            digest_hex(&response)
        ])));
        let value =
            serde_json::from_slice(&response).map_err(|_| CandidateStoreError::InvalidBatch)?;
        Ok(SourceRead { value, evidence })
    }
}

/// The caller supplies a deployment-prepared mTLS connection to the exact target.
/// Target verification and workload authorization occur on every actual request.
/// No in-memory observation may bypass this path into this acquisition owner.
pub async fn acquire_batch(
    store: &CandidateStore,
    connection: &ProviderConnection,
    target_runtime_id: &str,
    job: &AcquisitionBatch,
) -> Result<PersistenceOutcome, AcquisitionError> {
    let inputs = store.acquisition_inputs(&job.binding).await?;
    let profile = inputs.profile();
    let plan = inputs.plan();
    let target_address = match &inputs.acquisition().request {
        AcquisitionRequest::ExternalDecision { target_address, .. } => {
            if plan.candidate_schema_digests != [external_schema()]
                || plan.extractor_digests != [external_extractor()]
            {
                return Err(CandidateStoreError::InvalidBinding.into());
            }
            target_address
        }
        AcquisitionRequest::StateCall { target_address, .. } => {
            codec::validate_mapping(plan)?;
            target_address
        }
        AcquisitionRequest::EventLogs {
            contract_address,
            event_name,
            ..
        } => {
            if event_name != RGRA_EVENT_NAME
                || plan.candidate_schema_digests != [relationship_schema()]
                || plan.extractor_digests != [relationship_extractor()]
            {
                return Err(CandidateStoreError::InvalidBinding.into());
            }
            contract_address
        }
    };
    let FinalityMode::Confirmations { count } = inputs.finality_rule().mode else {
        return Err(CandidateStoreError::InvalidBinding.into());
    };
    let span = job
        .range
        .end
        .checked_sub(job.range.start)
        .and_then(|v| v.checked_add(1))
        .ok_or(CandidateStoreError::InvalidBatch)?;
    let head = job
        .range
        .end
        .checked_add(u64::from(count) - 1)
        .ok_or(CandidateStoreError::InvalidBatch)?;
    if job.range.start == 0
        || span > 64
        || head - job.range.start >= 64
        || span > profile.limits.max_range.min(plan.limits.max_range)
        || span > profile.limits.max_batch.min(plan.limits.max_batch)
        || inputs.acquisition().runtime_target_id != target_runtime_id
        || job.batch_id.is_empty()
        || job.batch_id.len() > 160
        || job.sequence == 0
        || (job.sequence == 1 && job.predecessor_digest != "GENESIS")
        || (job.sequence > 1 && crate::candidate::decode_digest(&job.predecessor_digest).is_err())
        || !plan.partitions.iter().any(|p| {
            p.source_id == job.source_id
                && p.partition_id == job.partition_id
                && job.range.start >= p.range.start
                && match p.range.end {
                    RangeEndV1::Open => true,
                    RangeEndV1::Inclusive(end) => job.range.end <= end,
                }
        })
    {
        return Err(CandidateStoreError::InvalidBinding.into());
    }
    store
        .register_partition(
            profile,
            plan,
            &job.binding,
            &job.source_id,
            &job.partition_id,
        )
        .await?;
    if store.acquisition_replayed(&inputs, job).await? {
        return Ok(PersistenceOutcome::ReplayedSameDigest);
    }
    let tail = store.acquisition_tail(&inputs, job).await?;
    let mut source = Source {
        connection,
        inputs: &inputs,
        remaining_bytes: 1_048_576,
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let mut headers = BTreeMap::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CandidateStoreError::InvalidBatch)?
        .as_secs();
    let mut evidence = Vec::new();
    for number in job.range.start..=head {
        let read = source.read(number, true).await?;
        let header = SourceBlockHeader::decode(&read.value["result"], number)
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        if let Some((previous, _)) = headers.last_key_value().map(|(_, value)| value) {
            let previous: &SourceBlockHeader = previous;
            if header.parent_hash != previous.hash
                || header.timestamp_seconds < previous.timestamp_seconds
            {
                return Err(CandidateStoreError::InvalidBatch.into());
            }
        }
        if header.timestamp_seconds > now {
            return Err(CandidateStoreError::InvalidBatch.into());
        }
        evidence.push(read.evidence.clone());
        headers.insert(number, (header, read.evidence));
    }
    if reorg::invalidate_changed_tail(store, &mut source, job, &tail, &headers[&job.range.start].0)
        .await?
    {
        return Ok(PersistenceOutcome::ReorgInvalidated);
    }
    let finality = &headers[&head];
    let anchor = |header: &SourceBlockHeader| ChainReadAnchorV1 {
        chain_id: profile.chain_id.clone(),
        genesis_hash: profile.genesis_hash.clone(),
        network_id: profile.network_id.clone(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(header.number),
        block_hash: Some(header.hash.clone()),
        pending_authorized_by_profile: false,
    };
    let mut records = Vec::new();
    let mut blocks = Vec::new();
    for number in job.range.start..=job.range.end {
        let read = source.read(number, false).await?;
        let (header, header_evidence) = &headers[&number];
        if header.timestamp_seconds > now {
            return Err(CandidateStoreError::InvalidBatch.into());
        }
        let timestamp = time::OffsetDateTime::from_unix_timestamp(
            header
                .timestamp_seconds
                .try_into()
                .map_err(|_| CandidateStoreError::InvalidBatch)?,
        )
        .map_err(|_| CandidateStoreError::InvalidBatch)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| CandidateStoreError::InvalidBatch)?;
        let candidates = match &inputs.acquisition().request {
            AcquisitionRequest::ExternalDecision { .. } => {
                let request =
                    inputs
                        .acquisition()
                        .external_request(profile, number, &header.hash)?;
                let observation:openpc_multi_rpc::external_decision::ExternalDecisionObservationV1=serde_json::from_value(read.value["result"].clone()).map_err(|_|CandidateStoreError::InvalidBatch)?;
                observation
                    .validate(
                        &request,
                        u64::try_from(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_err(|_| CandidateStoreError::InvalidBatch)?
                                .as_millis(),
                        )
                        .map_err(|_| CandidateStoreError::InvalidBatch)?,
                        u64::MAX,
                    )
                    .map_err(|_| CandidateStoreError::InvalidBatch)?;
                let payload = canonical_cbor(
                    &serde_json::to_value(&observation)
                        .map_err(|_| CandidateStoreError::InvalidBatch)?,
                );
                vec![(
                    CandidateRecordIdentityV1::ExternalObservation {
                        target_address: target_address.trim_start_matches("0x").into(),
                        call_parameter_digest: request
                            .digest()
                            .map_err(|_| CandidateStoreError::InvalidBatch)?
                            .as_str()
                            .into(),
                    },
                    payload,
                    digest_hex(&canonical_cbor(&json!([
                        "openpc:external-candidate:v1",
                        request.source_occurrence,
                        request
                            .digest()
                            .map_err(|_| CandidateStoreError::InvalidBatch)?
                    ]))),
                    external_schema().digest,
                )]
            }
            AcquisitionRequest::StateCall { .. } => {
                let parameter_digest = inputs.acquisition().state_call_parameter_digest(number)?;
                vec![(
                    CandidateRecordIdentityV1::StateCall {
                        target_address: target_address.trim_start_matches("0x").into(),
                        call_parameter_digest: parameter_digest.clone(),
                    },
                    codec::state_payload(&read.value)?,
                    digest_hex(&canonical_cbor(&json!([
                        "openpc:state-candidate-identity:v1",
                        profile.profile_id,
                        job.partition_id,
                        number,
                        header.hash,
                        target_address,
                        parameter_digest
                    ]))),
                    state_result_schema().digest,
                )]
            }
            AcquisitionRequest::EventLogs {
                contract_address,
                event_signature,
                ..
            } => {
                let logs = read.value["result"]
                    .as_array()
                    .filter(|logs| logs.len() <= 64)
                    .ok_or(CandidateStoreError::InvalidBatch)?;
                let mut mapped = Vec::with_capacity(logs.len());
                let mut previous = None;
                for log in logs {
                    let (identity, payload) = relationship_candidate(
                        log,
                        &profile.participant_binding,
                        &profile.privacy_binding,
                        contract_address,
                        event_signature,
                        number,
                        &header.hash,
                    )?;
                    let CandidateRecordIdentityV1::EventLog {
                        transaction_hash,
                        transaction_index,
                        log_index,
                        ..
                    } = &identity
                    else {
                        return Err(CandidateStoreError::InvalidBatch.into());
                    };
                    let order = (*transaction_index, *log_index);
                    if previous.is_some_and(|v| v >= order) {
                        return Err(CandidateStoreError::InvalidBatch.into());
                    }
                    previous = Some(order);
                    let id = digest_hex(&canonical_cbor(&json!([
                        "openpc:rgra-event-candidate:v1",
                        profile.profile_id,
                        job.partition_id,
                        header.hash,
                        transaction_hash,
                        log_index
                    ])));
                    mapped.push((identity, payload, id, relationship_schema().digest));
                }
                mapped
            }
        };
        for (identity, payload, record_id, schema_digest) in candidates {
            let record = CandidateRecordV1 {
                sequence: records.len() as u64 + 1,
                record_id,
                schema_digest,
                normalized_digest: digest_hex(&payload),
                block_number: number,
                canonical_block_hash: header.hash.clone(),
                evidence_digest: read.evidence.clone(),
            };
            records.push(CandidateRecordMaterialV1 {
                record,
                identity,
                payload_cbor: payload,
            });
        }
        blocks.push(CandidateBlockObservationV1 {
            block_number: number,
            canonical_block_hash: header.hash.clone(),
            parent_hash: header.parent_hash.clone(),
            block_timestamp: timestamp,
            evidence_digest: header_evidence.clone(),
            finality: CandidateBlockFinalityV1::Confirmations {
                head_anchor: anchor(&finality.0),
                evidence_digest: finality.1.clone(),
            },
        });
        evidence.push(read.evidence);
    }
    // Re-observe the whole bounded chain after data acquisition. A hash change
    // or partial/error response admits no candidate and advances no checkpoint.
    for number in job.range.start..=head {
        let read = source.read(number, true).await?;
        let current = SourceBlockHeader::decode(&read.value["result"], number)
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        let original = &headers[&number].0;
        if current.hash != original.hash
            || current.parent_hash != original.parent_hash
            || current.state_root != original.state_root
        {
            return Err(CandidateStoreError::InvalidBatch.into());
        }
    }
    evidence.sort();
    evidence.dedup();
    let last = &headers[&job.range.end].0;
    let batch = CandidateProjectionBatchV1 {
        profile_id: profile.profile_id.clone(),
        profile_version: profile.profile_version.clone(),
        profile_digest: profile.profile_digest.clone(),
        plan_digest: plan.plan_digest.clone(),
        source_id: job.source_id.clone(),
        source_profile_digest: profile.profile_digest.clone(),
        partition_id: job.partition_id.clone(),
        batch_id: job.batch_id.clone(),
        batch_sequence: job.sequence,
        range: job.range.clone(),
        observations: vec![SequencedObservationV1 {
            sequence: 1,
            anchor: anchor(last),
            normalized_digest: records
                .last()
                .map(|record| record.record.normalized_digest.clone())
                .unwrap_or_else(|| {
                    digest_hex(&canonical_cbor(&json!([
                        "openpc:complete-empty-event-range:v1",
                        profile.profile_digest,
                        plan.plan_digest,
                        job.range.start,
                        job.range.end,
                        last.hash,
                        evidence
                    ])))
                }),
            evidence_digest: headers[&job.range.end].1.clone(),
        }],
        records: records.iter().map(|r| r.record.clone()).collect(),
        decode_failures: vec![],
        missing_intervals: vec![],
        completed_watermark: CompletedWatermarkV1 {
            block_number: job.range.end,
            canonical_block_hash: last.hash.clone(),
        },
        predecessor_batch_digest: job.predecessor_digest.clone(),
        evidence_refs: evidence,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    };
    let empty = records.is_empty();
    let material = CandidateBatchMaterialV1::try_new(
        (profile, plan, &batch, &job.binding),
        blocks,
        records,
        empty,
    )
    .map_err(AcquisitionError::Material)?;
    store
        .persist_batch(&material)
        .await
        .map_err(AcquisitionError::Persistence)
}
