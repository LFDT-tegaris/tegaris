use std::collections::BTreeSet;

use pc_provider_api::{
    CandidateProjectionBatchV1, CandidateRecordV1, ChainReadAnchorV1, ClientIndexerProfileV1,
    ProjectionPlanV1, SourceAuthority, validate_candidate_projection_batch_structure,
    validate_canonical_pc_cbor_bytes,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::store::CandidateStoreError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePersistenceBinding {
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    projection_generation_id: Uuid,
    operation_id: Uuid,
    correlation_id: Uuid,
}

impl CandidatePersistenceBinding {
    pub fn try_new(
        participant_id: Uuid,
        privacy_domain_id: Uuid,
        projection_generation_id: Uuid,
        operation_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<Self, CandidateStoreError> {
        for value in [
            participant_id,
            privacy_domain_id,
            projection_generation_id,
            operation_id,
            correlation_id,
        ] {
            if value.get_version_num() != 7 {
                return Err(CandidateStoreError::InvalidBinding);
            }
        }
        Ok(Self {
            participant_id,
            privacy_domain_id,
            projection_generation_id,
            operation_id,
            correlation_id,
        })
    }

    pub(crate) fn validate_profile_scope(
        &self,
        profile: &ClientIndexerProfileV1,
    ) -> Result<(), CandidateStoreError> {
        // Match the canonical UUID bindings used by governed runtime configuration.
        // Public-envelope URNs are not alternate spellings of these internal fields.
        if profile.participant_binding != self.participant_id.to_string()
            || profile.privacy_binding != self.privacy_domain_id.to_string()
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(())
    }

    pub(crate) fn participant_id(&self) -> Uuid {
        self.participant_id
    }
    pub(crate) fn privacy_domain_id(&self) -> Uuid {
        self.privacy_domain_id
    }
    pub(crate) fn projection_generation_id(&self) -> Uuid {
        self.projection_generation_id
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(crate) fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateBlockFinalityV1 {
    Unfinalized {
        evidence_digest: String,
    },
    SafeTag {
        anchor: ChainReadAnchorV1,
        evidence_digest: String,
    },
    FinalizedTag {
        anchor: ChainReadAnchorV1,
        evidence_digest: String,
    },
    Confirmations {
        head_anchor: ChainReadAnchorV1,
        evidence_digest: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateBlockObservationV1 {
    pub block_number: u64,
    pub canonical_block_hash: String,
    pub parent_hash: String,
    pub block_timestamp: String,
    pub evidence_digest: String,
    pub finality: CandidateBlockFinalityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateRecordIdentityV1 {
    ExternalObservation {
        target_address: String,
        call_parameter_digest: String,
    },
    EventLog {
        transaction_hash: String,
        transaction_index: u64,
        log_index: u64,
        contract_address: String,
        event_signature: String,
    },
    StateCall {
        target_address: String,
        call_parameter_digest: String,
    },
    TransactionReceipt {
        transaction_hash: String,
    },
    BlockHeader,
    FullBlockTransactions,
}

impl CandidateRecordIdentityV1 {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::EventLog { .. } => "EVENT_LOG",
            Self::StateCall { .. } => "STATE_CALL",
            Self::ExternalObservation { .. } => "EXTERNAL_OBSERVATION",
            Self::TransactionReceipt { .. } => "TRANSACTION_RECEIPT",
            Self::BlockHeader => "BLOCK_HEADER",
            Self::FullBlockTransactions => "FULL_BLOCK_TRANSACTIONS",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRecordMaterialV1 {
    pub record: CandidateRecordV1,
    pub identity: CandidateRecordIdentityV1,
    pub payload_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateBatchMaterialV1 {
    profile: ClientIndexerProfileV1,
    plan: ProjectionPlanV1,
    batch: CandidateProjectionBatchV1,
    binding: CandidatePersistenceBinding,
    blocks: Vec<CandidateBlockObservationV1>,
    records: Vec<CandidateRecordMaterialV1>,
    authoritative_empty: bool,
    admitted_data_class: String,
}

impl CandidateBatchMaterialV1 {
    pub fn try_new(
        context: (
            &ClientIndexerProfileV1,
            &ProjectionPlanV1,
            &CandidateProjectionBatchV1,
            &CandidatePersistenceBinding,
        ),
        blocks: Vec<CandidateBlockObservationV1>,
        records: Vec<CandidateRecordMaterialV1>,
        authoritative_empty: bool,
    ) -> Result<Self, CandidateStoreError> {
        let (profile, plan, batch, binding) = context;
        let admitted_data_class = authoritative_profile_data_class(profile)?.to_owned();
        let material = Self {
            profile: profile.clone(),
            plan: plan.clone(),
            batch: batch.clone(),
            binding: binding.clone(),
            blocks,
            records,
            authoritative_empty,
            admitted_data_class,
        };
        material.validate()?;
        Ok(material)
    }

    fn validate(&self) -> Result<(), CandidateStoreError> {
        let profile = &self.profile;
        self.binding.validate_profile_scope(profile)?;
        let plan = &self.plan;
        let batch = &self.batch;
        if batch.source_authority != SourceAuthority::NonAuthoritativeCandidateOnly
            || self.records.len() != batch.records.len()
            || self.blocks.is_empty()
        {
            return Err(CandidateStoreError::InvalidBatch);
        }
        let expected_records = batch
            .records
            .iter()
            .map(|record| (record.sequence, record.record_id.as_str()))
            .collect::<Vec<_>>();
        let supplied_records = self
            .records
            .iter()
            .map(|record| (record.record.sequence, record.record.record_id.as_str()))
            .collect::<Vec<_>>();
        if expected_records != supplied_records {
            return Err(CandidateStoreError::InvalidBatch);
        }
        for record in &self.records {
            if record.identity.kind() != self.admitted_data_class {
                return Err(CandidateStoreError::InvalidBinding);
            }
        }
        validate_batch_local_uniqueness(&self.records)?;
        validate_supplied_block_identity_uniqueness(&self.blocks)?;
        validate_candidate_projection_batch_structure(profile, plan, batch)
            .map_err(|_| CandidateStoreError::InvalidBatch)?;
        if batch.records.is_empty() {
            validate_empty_batch(profile, plan, batch)?;
        }
        validate_complete_durable_coverage(batch, self.authoritative_empty)?;
        let required_block_keys: BTreeSet<_> = batch
            .records
            .iter()
            .map(|record| (record.block_number, record.canonical_block_hash.clone()))
            .collect();
        let mut block_keys = BTreeSet::new();
        for block in &self.blocks {
            if !block_keys.insert((block.block_number, block.canonical_block_hash.clone()))
                || block.block_timestamp.is_empty()
                || decode_fixed_hex(&block.canonical_block_hash, 32).is_err()
                || decode_fixed_hex(&block.parent_hash, 32).is_err()
                || decode_digest(&block.evidence_digest).is_err()
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            validate_finality(profile, block)?;
            if matches!(block.finality, CandidateBlockFinalityV1::Unfinalized { .. }) {
                return Err(CandidateStoreError::InvalidBatch);
            }
        }
        // Existing sparse projection contracts retain their exact block set.
        // Acquired ranges may also include a complete contiguous header chain.
        let expected = if batch.records.is_empty() {
            BTreeSet::from([(
                batch.completed_watermark.block_number,
                batch.completed_watermark.canonical_block_hash.clone(),
            )])
        } else {
            required_block_keys.clone()
        };
        let complete = batch
            .range
            .end
            .checked_sub(batch.range.start)
            .and_then(|n| n.checked_add(1))
            == Some(self.blocks.len() as u64)
            && self.blocks.iter().enumerate().all(|(i, b)| {
                b.block_number == batch.range.start + i as u64
                    && (i == 0 || b.parent_hash == self.blocks[i - 1].canonical_block_hash)
            });
        if !required_block_keys.is_subset(&block_keys) || (block_keys != expected && !complete) {
            return Err(CandidateStoreError::InvalidBatch);
        }
        for (expected, supplied) in batch.records.iter().zip(&self.records) {
            if expected != &supplied.record
                || !block_keys
                    .contains(&(expected.block_number, expected.canonical_block_hash.clone()))
                || validate_canonical_pc_cbor_bytes(&supplied.payload_cbor).is_err()
                || digest_hex(&supplied.payload_cbor) != trim_digest(&expected.normalized_digest)
                || decode_digest(&expected.schema_digest).is_err()
                || decode_digest(&expected.normalized_digest).is_err()
                || decode_digest(&expected.evidence_digest).is_err()
                || validate_identity(&supplied.identity).is_err()
            {
                return Err(CandidateStoreError::InvalidBatch);
            }
        }
        Ok(())
    }

    pub(crate) fn profile(&self) -> &ClientIndexerProfileV1 {
        &self.profile
    }
    pub(crate) fn plan(&self) -> &ProjectionPlanV1 {
        &self.plan
    }
    pub(crate) fn batch(&self) -> &CandidateProjectionBatchV1 {
        &self.batch
    }
    pub(crate) fn binding(&self) -> &CandidatePersistenceBinding {
        &self.binding
    }
    pub(crate) fn blocks(&self) -> &[CandidateBlockObservationV1] {
        &self.blocks
    }
    pub(crate) fn records(&self) -> &[CandidateRecordMaterialV1] {
        &self.records
    }
    pub(crate) fn authoritative_empty(&self) -> bool {
        self.authoritative_empty
    }
    pub(crate) fn admitted_data_class(&self) -> &str {
        &self.admitted_data_class
    }
}

fn validate_complete_durable_coverage(
    batch: &CandidateProjectionBatchV1,
    authoritative_empty: bool,
) -> Result<(), CandidateStoreError> {
    let watermark_proven = batch.records.iter().any(|record| {
        record.block_number == batch.range.end
            && record.canonical_block_hash == batch.completed_watermark.canonical_block_hash
    }) || batch.observations.iter().any(|observation| {
        observation.anchor.block_number == Some(batch.range.end)
            && observation.anchor.block_hash.as_deref()
                == Some(batch.completed_watermark.canonical_block_hash.as_str())
    });
    if authoritative_empty != batch.records.is_empty()
        || batch.completed_watermark.block_number != batch.range.end
        || !watermark_proven
        || !batch.missing_intervals.is_empty()
        || !batch.decode_failures.is_empty()
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    Ok(())
}

fn validate_supplied_block_identity_uniqueness(
    blocks: &[CandidateBlockObservationV1],
) -> Result<(), CandidateStoreError> {
    let mut decoded_block_keys = BTreeSet::new();
    for block in blocks {
        let decoded_block_hash = decode_fixed_hex(&block.canonical_block_hash, 32)?;
        if !decoded_block_keys.insert((block.block_number, decoded_block_hash)) {
            return Err(CandidateStoreError::InvalidBinding);
        }
    }
    Ok(())
}

fn validate_batch_local_uniqueness(
    records: &[CandidateRecordMaterialV1],
) -> Result<(), CandidateStoreError> {
    let mut record_ids = BTreeSet::new();
    let mut event_logs = BTreeSet::new();
    let mut state_calls = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut block_kinds = BTreeSet::new();
    for material in records {
        let record = &material.record;
        if !record_ids.insert(record.record_id.as_str()) {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let unique = match &material.identity {
            CandidateRecordIdentityV1::EventLog {
                transaction_hash,
                log_index,
                ..
            } => event_logs.insert((decode_fixed_hex(transaction_hash, 32)?, *log_index)),
            CandidateRecordIdentityV1::StateCall {
                target_address,
                call_parameter_digest,
            }
            | CandidateRecordIdentityV1::ExternalObservation {
                target_address,
                call_parameter_digest,
            } => state_calls.insert((
                record.block_number,
                decode_fixed_hex(&record.canonical_block_hash, 32)?,
                decode_fixed_hex(target_address, 20)?,
                decode_digest(call_parameter_digest)?,
            )),
            CandidateRecordIdentityV1::TransactionReceipt { transaction_hash } => {
                receipts.insert(decode_fixed_hex(transaction_hash, 32)?)
            }
            CandidateRecordIdentityV1::BlockHeader
            | CandidateRecordIdentityV1::FullBlockTransactions => block_kinds.insert((
                record.block_number,
                decode_fixed_hex(&record.canonical_block_hash, 32)?,
                material.identity.kind(),
            )),
        };
        if !unique {
            return Err(CandidateStoreError::InvalidBinding);
        }
    }
    Ok(())
}

pub(crate) fn authoritative_profile_data_class(
    profile: &ClientIndexerProfileV1,
) -> Result<&str, CandidateStoreError> {
    let classes = profile
        .method_data_classes
        .iter()
        .map(|value| value.data_class.as_str())
        .collect::<BTreeSet<_>>();
    // A separately authorized header read supplies block metadata for the one
    // primary projection. It cannot change the candidate record's data class.
    let primary = classes
        .iter()
        .copied()
        .filter(|class| *class != "BLOCK_HEADER")
        .collect::<Vec<_>>();
    if primary.len() == 1 {
        return Ok(primary[0]);
    }
    if !primary.is_empty() || classes.len() != 1 {
        return Err(CandidateStoreError::InvalidBinding);
    }
    classes
        .first()
        .copied()
        .ok_or(CandidateStoreError::InvalidBinding)
}

fn validate_empty_batch(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
) -> Result<(), CandidateStoreError> {
    if batch.profile_id != profile.profile_id
        || batch.profile_version != profile.profile_version
        || batch.profile_digest != profile.profile_digest
        || batch.plan_digest != plan.plan_digest
        || batch.source_profile_digest != profile.profile_digest
        || batch.batch_id.is_empty()
        || batch.batch_sequence == 0
        || batch.range.start == 0
        || batch.range.start > batch.range.end
        || batch.observations.is_empty()
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    let partition = plan
        .partitions
        .iter()
        .find(|part| part.partition_id == batch.partition_id && part.source_id == batch.source_id)
        .ok_or(CandidateStoreError::InvalidBatch)?;
    let partition_end = match partition.range.end {
        pc_provider_api::RangeEndV1::Inclusive(value) => value,
        pc_provider_api::RangeEndV1::Open => u64::MAX,
    };
    if batch.range.start < partition.range.start || batch.range.end > partition_end {
        return Err(CandidateStoreError::InvalidBatch);
    }
    if batch
        .observations
        .iter()
        .enumerate()
        .any(|(index, observation)| {
            observation.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
                || observation.anchor.chain_id != profile.chain_id
                || observation.anchor.genesis_hash != profile.genesis_hash
                || observation.anchor.network_id != profile.network_id
                || observation.anchor.block_number != Some(batch.range.end)
                || observation.anchor.block_hash.as_deref()
                    != Some(&batch.completed_watermark.canonical_block_hash)
                || observation.normalized_digest.len() != 64
                || decode_fixed_hex(&observation.normalized_digest, 32).is_err()
                || observation.evidence_digest.len() != 64
                || decode_fixed_hex(&observation.evidence_digest, 32).is_err()
        })
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    Ok(())
}

fn validate_finality(
    profile: &ClientIndexerProfileV1,
    block: &CandidateBlockObservationV1,
) -> Result<(), CandidateStoreError> {
    let (anchor, evidence) = match &block.finality {
        CandidateBlockFinalityV1::Unfinalized { evidence_digest } => (None, evidence_digest),
        CandidateBlockFinalityV1::SafeTag {
            anchor,
            evidence_digest,
        }
        | CandidateBlockFinalityV1::FinalizedTag {
            anchor,
            evidence_digest,
        } => (Some(anchor), evidence_digest),
        CandidateBlockFinalityV1::Confirmations {
            head_anchor,
            evidence_digest,
        } => {
            if !complete_pinned_anchor(head_anchor, profile)
                || head_anchor
                    .block_number
                    .is_none_or(|head| head < block.block_number)
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            (None, evidence_digest)
        }
    };
    if decode_digest(evidence).is_err() {
        return Err(CandidateStoreError::InvalidBinding);
    }
    if let Some(anchor) = anchor
        && (!complete_pinned_anchor(anchor, profile)
            || anchor.block_number != Some(block.block_number)
            || anchor.block_hash.as_deref() != Some(&block.canonical_block_hash))
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(())
}

fn complete_pinned_anchor(anchor: &ChainReadAnchorV1, profile: &ClientIndexerProfileV1) -> bool {
    anchor.chain_id == profile.chain_id
        && anchor.genesis_hash == profile.genesis_hash
        && anchor.network_id == profile.network_id
        && matches!(
            anchor.selector_kind,
            pc_provider_api::BlockSelectorKind::Pinned
        )
        && anchor.block_number.is_some()
        && anchor
            .block_hash
            .as_deref()
            .is_some_and(|value| decode_fixed_hex(value, 32).is_ok())
        && decode_digest(&anchor.genesis_hash).is_ok()
        && !anchor.pending_authorized_by_profile
}

fn validate_identity(value: &CandidateRecordIdentityV1) -> Result<(), CandidateStoreError> {
    match value {
        CandidateRecordIdentityV1::EventLog {
            transaction_hash,
            contract_address,
            event_signature,
            ..
        } => {
            decode_fixed_hex(transaction_hash, 32)?;
            decode_fixed_hex(contract_address, 20)?;
            decode_fixed_hex(event_signature, 32)?;
        }
        CandidateRecordIdentityV1::StateCall {
            target_address,
            call_parameter_digest,
        }
        | CandidateRecordIdentityV1::ExternalObservation {
            target_address,
            call_parameter_digest,
        } => {
            decode_fixed_hex(target_address, 20)?;
            decode_digest(call_parameter_digest)?;
        }
        CandidateRecordIdentityV1::TransactionReceipt { transaction_hash } => {
            decode_fixed_hex(transaction_hash, 32)?;
        }
        CandidateRecordIdentityV1::BlockHeader
        | CandidateRecordIdentityV1::FullBlockTransactions => {}
    }
    Ok(())
}

pub(crate) fn identity_columns(value: &CandidateRecordIdentityV1) -> IdentityColumns {
    match value {
        CandidateRecordIdentityV1::EventLog {
            transaction_hash,
            transaction_index,
            log_index,
            contract_address,
            event_signature,
        } => IdentityColumns {
            transaction_hash: Some(decode_fixed_hex(transaction_hash, 32).expect("validated")),
            transaction_index: Some(*transaction_index),
            log_index: Some(*log_index),
            contract_address: Some(decode_fixed_hex(contract_address, 20).expect("validated")),
            event_signature: Some(decode_fixed_hex(event_signature, 32).expect("validated")),
            target_address: None,
            call_parameter_digest: None,
        },
        CandidateRecordIdentityV1::StateCall {
            target_address,
            call_parameter_digest,
        }
        | CandidateRecordIdentityV1::ExternalObservation {
            target_address,
            call_parameter_digest,
        } => IdentityColumns {
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            contract_address: None,
            event_signature: None,
            target_address: Some(decode_fixed_hex(target_address, 20).expect("validated")),
            call_parameter_digest: Some(decode_digest(call_parameter_digest).expect("validated")),
        },
        CandidateRecordIdentityV1::TransactionReceipt { transaction_hash } => IdentityColumns {
            transaction_hash: Some(decode_fixed_hex(transaction_hash, 32).expect("validated")),
            transaction_index: None,
            log_index: None,
            contract_address: None,
            event_signature: None,
            target_address: None,
            call_parameter_digest: None,
        },
        CandidateRecordIdentityV1::BlockHeader
        | CandidateRecordIdentityV1::FullBlockTransactions => IdentityColumns {
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            contract_address: None,
            event_signature: None,
            target_address: None,
            call_parameter_digest: None,
        },
    }
}

pub(crate) struct IdentityColumns {
    pub(crate) transaction_hash: Option<Vec<u8>>,
    pub(crate) transaction_index: Option<u64>,
    pub(crate) log_index: Option<u64>,
    pub(crate) contract_address: Option<Vec<u8>>,
    pub(crate) event_signature: Option<Vec<u8>>,
    pub(crate) target_address: Option<Vec<u8>>,
    pub(crate) call_parameter_digest: Option<Vec<u8>>,
}
pub(crate) fn decode_digest(value: &str) -> Result<Vec<u8>, CandidateStoreError> {
    decode_fixed_hex(trim_digest(value), 32)
}
pub(crate) fn decode_fixed_hex(
    value: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, CandidateStoreError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != expected_bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| CandidateStoreError::InvalidBinding)?;
            u8::from_str_radix(text, 16).map_err(|_| CandidateStoreError::InvalidBinding)
        })
        .collect()
}
pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn trim_digest(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_provider_api::{
        BlockSelectorKind, ClientIndexerFamily, ClientIndexerLifecycle, DependencyV1, DesiredState,
        IndexerBehaviorV1, IndexerCapability, IndexerLimitsV1, IndexerProtocolKind,
        MethodDataClass, NamedDigestV1, PartitionState, ProjectionPartitionV1, RangeEndV1,
        SecretPurposeV1, SecretReferenceV1, SourceRangeV1, WorkloadIdentityV1,
    };

    fn hex(byte: u8, count: usize) -> String {
        format!("{byte:02x}").repeat(count)
    }

    fn named(name: &str) -> NamedDigestV1 {
        NamedDigestV1 {
            name: name.into(),
            digest: digest_hex(name.as_bytes()),
        }
    }

    fn source_range() -> SourceRangeV1 {
        SourceRangeV1 {
            start: 1,
            end: RangeEndV1::Inclusive(10),
        }
    }

    fn limits() -> IndexerLimitsV1 {
        IndexerLimitsV1 {
            max_request_bytes: 10_000,
            max_range: 10,
            max_batch: 10,
            max_response_bytes: 10_000,
            max_depth: 10,
            max_resource: 10,
            rate_limit_contract_digest: digest_hex(b"rate"),
        }
    }

    fn profile(data_class: &str) -> ClientIndexerProfileV1 {
        ClientIndexerProfileV1 {
            profile_id: "client".into(),
            profile_version: "1".into(),
            profile_digest: digest_hex(b"profile"),
            client_family: ClientIndexerFamily::CustomEvmIndexer,
            engine_or_runtime: "runtime".into(),
            engine_version: "1".into(),
            dependencies: vec![DependencyV1 {
                name: "dep".into(),
                version: "1".into(),
                digest: digest_hex(b"dep"),
            }],
            configuration_digest: digest_hex(b"config"),
            participant_binding: binding().participant_id().to_string(),
            privacy_binding: binding().privacy_domain_id().to_string(),
            workload_binding: "workload".into(),
            deployment_owner: "owner".into(),
            boundary_declaration_digest: digest_hex(b"boundary"),
            protocol_kind: IndexerProtocolKind::JsonRpc,
            protocol_version: "2".into(),
            chain_id: "1".into(),
            genesis_hash: hex(0x01, 32),
            network_id: "network".into(),
            capability_profiles: vec![IndexerCapability::ProjectSessionCore],
            method_data_classes: vec![MethodDataClass {
                method: "method".into(),
                data_class: data_class.into(),
            }],
            source_range: source_range(),
            finality_rule_digest: digest_hex(b"finality"),
            reorg_behavior_digest: digest_hex(b"reorg"),
            removed_event_behavior_digest: digest_hex(b"removed"),
            checkpoint_semantics_digest: digest_hex(b"checkpoint"),
            completed_watermark_semantics_digest: digest_hex(b"watermark"),
            artifact_digests: vec![named("abi")],
            limits: limits(),
            behavior: IndexerBehaviorV1 {
                visibility_miss_digest: digest_hex(b"miss"),
                empty_digest: digest_hex(b"empty"),
                partial_digest: digest_hex(b"partial"),
                error_digest: digest_hex(b"error"),
                retry_digest: digest_hex(b"retry"),
                recovery_digest: digest_hex(b"recovery"),
                retirement_digest: digest_hex(b"retire"),
            },
            candidate_store_contract_digest: digest_hex(b"candidate"),
            outbox_contract_digest: digest_hex(b"outbox"),
            fact_bridge_contract_digest: digest_hex(b"bridge"),
            security_evidence_digest: digest_hex(b"security"),
            privacy_evidence_digest: digest_hex(b"privacy"),
            licensing_digest: digest_hex(b"license"),
            supply_chain_digest: digest_hex(b"supply"),
            telemetry_classification_digest: digest_hex(b"telemetry"),
            rollback_digest: digest_hex(b"rollback"),
            uninstall_digest: digest_hex(b"uninstall"),
            corpus_digest: digest_hex(b"corpus"),
            conformance_receipt_digest: digest_hex(b"receipt"),
            lifecycle: ClientIndexerLifecycle::Active,
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }

    fn plan(profile: &ClientIndexerProfileV1) -> ProjectionPlanV1 {
        ProjectionPlanV1 {
            profile_id: profile.profile_id.clone(),
            profile_version: profile.profile_version.clone(),
            profile_digest: profile.profile_digest.clone(),
            plan_digest: digest_hex(b"plan"),
            workload_identity: WorkloadIdentityV1::ExternalOwner {
                owner: "owner".into(),
                boundary_digest: digest_hex(b"workload"),
            },
            partitions: vec![ProjectionPartitionV1 {
                partition_id: "partition".into(),
                source_id: "source".into(),
                range: source_range(),
                state: PartitionState::Complete,
                finality_digest: profile.finality_rule_digest.clone(),
                checkpoint_digest: digest_hex(b"checkpoint"),
            }],
            source_range: source_range(),
            finality_rule_digest: profile.finality_rule_digest.clone(),
            extractor_digests: vec![named("extractor")],
            candidate_schema_digests: vec![named("schema")],
            limits: limits(),
            secret_references: vec![SecretReferenceV1 {
                purpose: SecretPurposeV1::ApiToken,
                reference: "ref:token".into(),
            }],
            lifecycle_generation: 1,
            desired_state: DesiredState::Active,
        }
    }

    fn anchor() -> ChainReadAnchorV1 {
        ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: hex(0x01, 32),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(10),
            block_hash: Some(hex(0x10, 32)),
            pending_authorized_by_profile: false,
        }
    }

    fn identity(kind: &str) -> CandidateRecordIdentityV1 {
        match kind {
            "EVENT_LOG" => CandidateRecordIdentityV1::EventLog {
                transaction_hash: hex(0x11, 32),
                transaction_index: 1,
                log_index: 2,
                contract_address: hex(0x12, 20),
                event_signature: hex(0x13, 32),
            },
            "STATE_CALL" => CandidateRecordIdentityV1::StateCall {
                target_address: hex(0x21, 20),
                call_parameter_digest: hex(0x22, 32),
            },
            "TRANSACTION_RECEIPT" => CandidateRecordIdentityV1::TransactionReceipt {
                transaction_hash: hex(0x31, 32),
            },
            "BLOCK_HEADER" => CandidateRecordIdentityV1::BlockHeader,
            "FULL_BLOCK_TRANSACTIONS" => CandidateRecordIdentityV1::FullBlockTransactions,
            _ => panic!("unknown fixture identity"),
        }
    }

    fn binding() -> CandidatePersistenceBinding {
        let value = Uuid::parse_str("018f47a5-4a58-7b21-8f3a-111111111111").expect("UUIDv7");
        CandidatePersistenceBinding::try_new(value, value, value, value, value).expect("binding")
    }

    fn material(
        profile: &ClientIndexerProfileV1,
        identities: Vec<CandidateRecordIdentityV1>,
        authoritative_empty: bool,
    ) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
        material_with_observation_digests(
            profile,
            identities,
            authoritative_empty,
            hex(0x51, 32),
            hex(0x52, 32),
        )
    }

    fn material_with_observation_digests(
        profile: &ClientIndexerProfileV1,
        identities: Vec<CandidateRecordIdentityV1>,
        authoritative_empty: bool,
        normalized_digest: String,
        evidence_digest: String,
    ) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
        let plan = plan(profile);
        let payload = vec![0xa0];
        let records = identities
            .into_iter()
            .enumerate()
            .map(|(index, identity)| CandidateRecordMaterialV1 {
                record: CandidateRecordV1 {
                    sequence: u64::try_from(index + 1).expect("sequence"),
                    record_id: format!("record-{index}"),
                    schema_digest: hex(0x41, 32),
                    normalized_digest: digest_hex(&payload),
                    block_number: 10,
                    canonical_block_hash: hex(0x10, 32),
                    evidence_digest: hex(0x42, 32),
                },
                identity,
                payload_cbor: payload.clone(),
            })
            .collect::<Vec<_>>();
        let batch = CandidateProjectionBatchV1 {
            profile_id: profile.profile_id.clone(),
            profile_version: profile.profile_version.clone(),
            profile_digest: profile.profile_digest.clone(),
            plan_digest: plan.plan_digest.clone(),
            source_id: "source".into(),
            source_profile_digest: profile.profile_digest.clone(),
            partition_id: "partition".into(),
            batch_id: "batch".into(),
            batch_sequence: 1,
            range: pc_provider_api::InclusiveRangeV1 { start: 1, end: 10 },
            observations: vec![pc_provider_api::SequencedObservationV1 {
                sequence: 1,
                anchor: anchor(),
                normalized_digest,
                evidence_digest,
            }],
            records: records.iter().map(|value| value.record.clone()).collect(),
            decode_failures: Vec::new(),
            missing_intervals: Vec::new(),
            completed_watermark: pc_provider_api::CompletedWatermarkV1 {
                block_number: 10,
                canonical_block_hash: hex(0x10, 32),
            },
            predecessor_batch_digest: "GENESIS".into(),
            evidence_refs: vec!["evidence".into()],
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        };
        CandidateBatchMaterialV1::try_new(
            (profile, &plan, &batch, &binding()),
            vec![CandidateBlockObservationV1 {
                block_number: 10,
                canonical_block_hash: hex(0x10, 32),
                parent_hash: hex(0x09, 32),
                block_timestamp: "2026-09-02T00:00:00Z".into(),
                evidence_digest: hex(0x53, 32),
                finality: CandidateBlockFinalityV1::FinalizedTag {
                    anchor: anchor(),
                    evidence_digest: hex(0x54, 32),
                },
            }],
            records,
            authoritative_empty,
        )
    }

    fn rematerialize(
        material: CandidateBatchMaterialV1,
        mutate: impl FnOnce(
            &mut CandidateProjectionBatchV1,
            &mut Vec<CandidateBlockObservationV1>,
            &mut Vec<CandidateRecordMaterialV1>,
            &mut bool,
        ),
    ) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
        let mut batch = material.batch;
        let mut blocks = material.blocks;
        let mut records = material.records;
        let mut authoritative_empty = material.authoritative_empty;
        mutate(
            &mut batch,
            &mut blocks,
            &mut records,
            &mut authoritative_empty,
        );
        CandidateBatchMaterialV1::try_new(
            (&material.profile, &material.plan, &batch, &material.binding),
            blocks,
            records,
            authoritative_empty,
        )
    }

    fn add_second_record(
        material: CandidateBatchMaterialV1,
        mutate: impl FnOnce(&mut CandidateRecordMaterialV1, &mut Vec<CandidateBlockObservationV1>),
    ) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
        rematerialize(material, |batch, blocks, records, _| {
            let mut second = records[0].clone();
            second.record.sequence = 2;
            second.record.record_id = "record-1".into();
            mutate(&mut second, blocks);
            batch.records.push(second.record.clone());
            records.push(second);
        })
    }

    fn add_distinct_block_record(
        material: CandidateBatchMaterialV1,
    ) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
        rematerialize(material, |batch, blocks, records, _| {
            let mut terminal = records[0].clone();
            terminal.record.sequence = 2;
            terminal.record.record_id = "record-1".into();
            batch.records[0].block_number = 9;
            batch.records[0].canonical_block_hash = hex(0x09, 32);
            records[0].record = batch.records[0].clone();
            let mut earlier_block = blocks[0].clone();
            earlier_block.block_number = 9;
            earlier_block.canonical_block_hash = hex(0x09, 32);
            earlier_block.parent_hash = hex(0x08, 32);
            if let CandidateBlockFinalityV1::FinalizedTag { anchor, .. } =
                &mut earlier_block.finality
            {
                anchor.block_number = Some(9);
                anchor.block_hash = Some(hex(0x09, 32));
            }
            blocks.insert(0, earlier_block);
            batch.records.push(terminal.record.clone());
            records.push(terminal);
        })
    }

    #[test]
    fn candidate_finality_preserves_qualified_genesis_digest_identity() {
        let mut acquired = material(&profile("STATE_CALL"), vec![identity("STATE_CALL")], false)
            .expect("initial material");
        let genesis = format!("sha256:{}", acquired.profile.genesis_hash);
        acquired.profile.genesis_hash.clone_from(&genesis);
        acquired.batch.observations[0]
            .anchor
            .genesis_hash
            .clone_from(&genesis);
        let mut head = anchor();
        head.genesis_hash = genesis;
        head.block_number = Some(11);
        head.block_hash = Some(hex(0x11, 32));
        acquired.blocks[0].finality = CandidateBlockFinalityV1::Confirmations {
            head_anchor: head,
            evidence_digest: hex(0x54, 32),
        };
        acquired
            .validate()
            .expect("published digest-prefixed genesis");
        if let CandidateBlockFinalityV1::Confirmations { head_anchor, .. } =
            &mut acquired.blocks[0].finality
        {
            head_anchor.genesis_hash = format!("sha256:{}", hex(0x02, 32));
        }
        assert!(matches!(
            acquired.validate(),
            Err(CandidateStoreError::InvalidBinding)
        ));
    }

    #[test]
    fn candidate_material_binds_each_identity_kind_to_the_single_profile_data_class() {
        for data_class in [
            "EVENT_LOG",
            "STATE_CALL",
            "TRANSACTION_RECEIPT",
            "BLOCK_HEADER",
            "FULL_BLOCK_TRANSACTIONS",
        ] {
            let profile = profile(data_class);
            let material = material(&profile, vec![identity(data_class)], false)
                .expect("matching identity class");
            assert_eq!(material.admitted_data_class(), data_class);
        }
    }

    #[test]
    fn candidate_material_rejects_cross_class_mixed_and_ambiguous_profile_identity() {
        let classes = [
            "EVENT_LOG",
            "STATE_CALL",
            "TRANSACTION_RECEIPT",
            "BLOCK_HEADER",
            "FULL_BLOCK_TRANSACTIONS",
        ];
        for data_class in classes {
            for identity_class in classes {
                if data_class == identity_class {
                    continue;
                }
                let result = material(&profile(data_class), vec![identity(identity_class)], false);
                assert!(matches!(result, Err(CandidateStoreError::InvalidBinding)));
            }
        }

        let event_profile = profile("EVENT_LOG");
        assert!(matches!(
            material(
                &event_profile,
                vec![identity("EVENT_LOG"), identity("STATE_CALL")],
                false,
            ),
            Err(CandidateStoreError::InvalidBinding)
        ));

        let mut no_class = event_profile.clone();
        no_class.method_data_classes.clear();
        assert!(matches!(
            material(&no_class, vec![identity("EVENT_LOG")], false),
            Err(CandidateStoreError::InvalidBinding)
        ));

        let mut multiple_classes = event_profile;
        multiple_classes.method_data_classes.push(MethodDataClass {
            method: "second".into(),
            data_class: "STATE_CALL".into(),
        });
        assert!(matches!(
            material(&multiple_classes, vec![identity("EVENT_LOG")], false),
            Err(CandidateStoreError::InvalidBinding)
        ));
    }

    #[test]
    fn authoritative_empty_material_has_no_record_identity_and_preserves_empty_invariants() {
        let profile = profile("EVENT_LOG");
        let material = material(&profile, Vec::new(), true).expect("authoritative empty material");
        assert!(material.authoritative_empty());
        assert!(material.records().is_empty());
        assert!(material.batch().records.is_empty());
        assert_eq!(material.admitted_data_class(), "EVENT_LOG");

        let malformed = [
            format!("sha256:{}", hex(0x61, 32)),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            format!("{}g", "a".repeat(63)),
        ];
        for value in malformed {
            for (normalized_digest, evidence_digest) in
                [(value.clone(), hex(0x52, 32)), (hex(0x51, 32), value)]
            {
                assert!(matches!(
                    material_with_observation_digests(
                        &profile,
                        Vec::new(),
                        true,
                        normalized_digest,
                        evidence_digest,
                    ),
                    Err(CandidateStoreError::InvalidBatch)
                ));
            }
        }
    }

    #[test]
    fn candidate_material_requires_complete_durable_coverage() {
        let profile = profile("EVENT_LOG");
        let complete = material(&profile, vec![identity("EVENT_LOG")], false)
            .expect("complete durable material");

        let mut watermark_before_end = complete.batch().clone();
        watermark_before_end.completed_watermark.block_number = 9;
        assert!(matches!(
            validate_complete_durable_coverage(&watermark_before_end, false),
            Err(CandidateStoreError::InvalidBatch)
        ));

        let mut terminal_anchor_absent = complete.batch().clone();
        terminal_anchor_absent.records[0].block_number = 9;
        terminal_anchor_absent.observations[0].anchor.block_number = Some(9);
        assert!(matches!(
            validate_complete_durable_coverage(&terminal_anchor_absent, false),
            Err(CandidateStoreError::InvalidBatch)
        ));

        let mut missing_interval = complete.batch().clone();
        missing_interval.missing_intervals =
            vec![pc_provider_api::InclusiveRangeV1 { start: 9, end: 10 }];
        assert!(matches!(
            validate_complete_durable_coverage(&missing_interval, false),
            Err(CandidateStoreError::InvalidBatch)
        ));

        let mut decode_partial = complete.batch().clone();
        decode_partial.decode_failures = vec![pc_provider_api::DecodeFailureV1 {
            sequence: 1,
            source_id: decode_partial.source_id.clone(),
            anchor: ChainReadAnchorV1 {
                block_number: Some(9),
                block_hash: Some(hex(0x09, 32)),
                ..anchor()
            },
            error_digest: hex(0x61, 32),
            evidence_digest: hex(0x62, 32),
        }];
        assert!(matches!(
            validate_complete_durable_coverage(&decode_partial, false),
            Err(CandidateStoreError::InvalidBatch)
        ));

        assert!(matches!(
            validate_complete_durable_coverage(complete.batch(), true),
            Err(CandidateStoreError::InvalidBatch)
        ));
        assert!(matches!(
            rematerialize(complete, |_, blocks, _, _| {
                blocks[0].finality = CandidateBlockFinalityV1::Unfinalized {
                    evidence_digest: hex(0x63, 32),
                };
            }),
            Err(CandidateStoreError::InvalidBatch)
        ));
    }

    #[test]
    fn candidate_material_rejects_all_batch_local_database_identity_duplicates() {
        let event_profile = profile("EVENT_LOG");
        let event = identity("EVENT_LOG");
        let two_events = material(&event_profile, vec![event.clone(), event], false);
        assert!(matches!(
            two_events,
            Err(CandidateStoreError::InvalidBinding)
        ));

        for data_class in [
            "STATE_CALL",
            "TRANSACTION_RECEIPT",
            "BLOCK_HEADER",
            "FULL_BLOCK_TRANSACTIONS",
        ] {
            let duplicate = identity(data_class);
            assert!(matches!(
                material(
                    &profile(data_class),
                    vec![duplicate.clone(), duplicate],
                    false,
                ),
                Err(CandidateStoreError::InvalidBinding)
            ));
        }

        let alias_cases = [
            ("EVENT_LOG", "transaction_hash"),
            ("STATE_CALL", "block_hash"),
            ("STATE_CALL", "target_address"),
            ("STATE_CALL", "call_parameter_digest"),
            ("TRANSACTION_RECEIPT", "transaction_hash"),
            ("BLOCK_HEADER", "block_hash"),
            ("FULL_BLOCK_TRANSACTIONS", "block_hash"),
        ];
        for (data_class, field) in alias_cases {
            let base = material(&profile(data_class), vec![identity(data_class)], false)
                .expect("alias baseline");
            let result = add_second_record(base, |second, _| match (&mut second.identity, field) {
                (
                    CandidateRecordIdentityV1::EventLog {
                        transaction_hash, ..
                    }
                    | CandidateRecordIdentityV1::TransactionReceipt { transaction_hash },
                    "transaction_hash",
                ) => *transaction_hash = format!("0x{transaction_hash}"),
                (CandidateRecordIdentityV1::StateCall { .. }, "block_hash")
                | (CandidateRecordIdentityV1::BlockHeader, "block_hash")
                | (CandidateRecordIdentityV1::FullBlockTransactions, "block_hash") => {
                    second.record.canonical_block_hash =
                        format!("0x{}", second.record.canonical_block_hash);
                }
                (CandidateRecordIdentityV1::StateCall { target_address, .. }, "target_address") => {
                    *target_address = format!("0x{target_address}");
                }
                (
                    CandidateRecordIdentityV1::StateCall {
                        call_parameter_digest,
                        ..
                    },
                    "call_parameter_digest",
                ) => *call_parameter_digest = format!("sha256:{call_parameter_digest}"),
                _ => panic!("unsupported alias fixture"),
            });
            assert!(matches!(result, Err(CandidateStoreError::InvalidBinding)));
        }

        let block_alias_base = material(&event_profile, vec![identity("EVENT_LOG")], false)
            .expect("block alias baseline");
        let block_alias = add_second_record(block_alias_base, |second, blocks| {
            if let CandidateRecordIdentityV1::EventLog {
                transaction_hash, ..
            } = &mut second.identity
            {
                *transaction_hash = hex(0x14, 32);
            }
            second.record.canonical_block_hash =
                format!("0x{}", second.record.canonical_block_hash);
            let mut alias = blocks[0].clone();
            alias.canonical_block_hash = format!("0x{}", alias.canonical_block_hash);
            blocks.push(alias);
        });
        assert!(matches!(
            block_alias,
            Err(CandidateStoreError::InvalidBinding)
        ));

        for data_class in ["EVENT_LOG", "STATE_CALL", "TRANSACTION_RECEIPT"] {
            let base = material(&profile(data_class), vec![identity(data_class)], false)
                .expect("distinct-key baseline");
            let distinct = add_second_record(base, |second, _| match &mut second.identity {
                CandidateRecordIdentityV1::EventLog {
                    transaction_hash, ..
                }
                | CandidateRecordIdentityV1::TransactionReceipt { transaction_hash } => {
                    *transaction_hash = hex(0x71, 32);
                }
                CandidateRecordIdentityV1::StateCall { target_address, .. } => {
                    *target_address = hex(0x72, 20);
                }
                _ => unreachable!(),
            });
            assert!(
                distinct.is_ok(),
                "distinct {data_class} key must be admitted"
            );
        }
        for data_class in ["BLOCK_HEADER", "FULL_BLOCK_TRANSACTIONS"] {
            let base = material(&profile(data_class), vec![identity(data_class)], false)
                .expect("distinct-block baseline");
            assert!(
                add_distinct_block_record(base).is_ok(),
                "distinct {data_class} block identity must be admitted"
            );
        }

        let base = material(&event_profile, vec![identity("EVENT_LOG")], false)
            .expect("record-id baseline");
        assert!(matches!(
            rematerialize(base, |batch, _, records, _| {
                let mut second = records[0].clone();
                second.record.sequence = 2;
                records.push(second.clone());
                batch.records.push(second.record);
            }),
            Err(CandidateStoreError::InvalidBinding)
        ));
    }

    #[test]
    fn auxiliary_headers_do_not_change_the_primary_candidate_class() {
        let mut source = profile("STATE_CALL");
        source
            .method_data_classes
            .push(pc_provider_api::MethodDataClass {
                method: "eth_getBlockByNumber(false)".into(),
                data_class: "BLOCK_HEADER".into(),
            });
        source
            .method_data_classes
            .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));
        assert_eq!(
            authoritative_profile_data_class(&source).unwrap(),
            "STATE_CALL"
        );
        assert!(material(&source, vec![identity("STATE_CALL")], false).is_ok());
        assert!(material(&source, vec![identity("BLOCK_HEADER")], false).is_err());
        source
            .method_data_classes
            .push(pc_provider_api::MethodDataClass {
                method: "eth_getLogs".into(),
                data_class: "EVENT_LOG".into(),
            });
        assert!(authoritative_profile_data_class(&source).is_err());
    }

    #[test]
    fn candidate_schema_is_variant_closed_and_content_bound() {
        let identities = [
            CandidateRecordIdentityV1::EventLog {
                transaction_hash: hex(0x11, 32),
                transaction_index: 1,
                log_index: 2,
                contract_address: hex(0x22, 20),
                event_signature: hex(0x33, 32),
            },
            CandidateRecordIdentityV1::StateCall {
                target_address: hex(0x44, 20),
                call_parameter_digest: hex(0x55, 32),
            },
            CandidateRecordIdentityV1::TransactionReceipt {
                transaction_hash: hex(0x66, 32),
            },
            CandidateRecordIdentityV1::BlockHeader,
            CandidateRecordIdentityV1::FullBlockTransactions,
        ];
        assert_eq!(
            identities
                .iter()
                .map(CandidateRecordIdentityV1::kind)
                .collect::<Vec<_>>(),
            [
                "EVENT_LOG",
                "STATE_CALL",
                "TRANSACTION_RECEIPT",
                "BLOCK_HEADER",
                "FULL_BLOCK_TRANSACTIONS"
            ]
        );
        for identity in &identities {
            assert!(validate_identity(identity).is_ok());
            let columns = identity_columns(identity);
            match identity {
                CandidateRecordIdentityV1::EventLog { .. } => {
                    assert!(columns.transaction_hash.is_some());
                    assert!(columns.contract_address.is_some());
                    assert!(columns.target_address.is_none());
                }
                CandidateRecordIdentityV1::StateCall { .. }
                | CandidateRecordIdentityV1::ExternalObservation { .. } => {
                    assert!(columns.transaction_hash.is_none());
                    assert!(columns.target_address.is_some());
                    assert!(columns.call_parameter_digest.is_some());
                }
                CandidateRecordIdentityV1::TransactionReceipt { .. } => {
                    assert!(columns.transaction_hash.is_some());
                    assert!(columns.transaction_index.is_none());
                    assert!(columns.log_index.is_none());
                }
                CandidateRecordIdentityV1::BlockHeader
                | CandidateRecordIdentityV1::FullBlockTransactions => {
                    assert!(columns.transaction_hash.is_none());
                    assert!(columns.target_address.is_none());
                }
            }
        }
        let invalid = CandidateRecordIdentityV1::StateCall {
            target_address: "AA".repeat(20),
            call_parameter_digest: hex(0x55, 32),
        };
        assert!(validate_identity(&invalid).is_err());
        assert_eq!(digest_hex(b"payload"), digest_hex(b"payload"));
        assert_ne!(digest_hex(b"payload"), digest_hex(b"payload-drift"));
    }

    #[test]
    fn candidate_profile_cannot_select_a_different_persistence_scope() {
        let admitted = profile("EVENT_LOG");
        assert!(material(&admitted, vec![identity("EVENT_LOG")], false).is_ok());
        for (participant, privacy) in [
            (Uuid::now_v7().to_string(), admitted.privacy_binding.clone()),
            (
                admitted.participant_binding.clone(),
                Uuid::now_v7().to_string(),
            ),
            (
                format!("urn:openpc:participant:{}", binding().participant_id()),
                admitted.privacy_binding.clone(),
            ),
            (
                admitted.participant_binding.clone(),
                format!(
                    "urn:openpc:privacy-domain:{}",
                    binding().privacy_domain_id()
                ),
            ),
            (
                admitted.participant_binding.to_uppercase(),
                admitted.privacy_binding.clone(),
            ),
        ] {
            let mut changed = admitted.clone();
            changed.participant_binding = participant;
            changed.privacy_binding = privacy;
            assert!(matches!(
                material(&changed, vec![identity("EVENT_LOG")], false),
                Err(CandidateStoreError::InvalidBinding)
            ));
            assert!(matches!(
                material(&changed, Vec::new(), true),
                Err(CandidateStoreError::InvalidBinding)
            ));
        }
    }

    #[test]
    fn candidate_binding_accepts_only_uuid_v7() {
        let value = Uuid::parse_str("018f47a5-4a58-7b21-8f3a-111111111111").expect("UUIDv7");
        assert!(CandidatePersistenceBinding::try_new(value, value, value, value, value).is_ok());
        let v4 = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("UUIDv4");
        assert!(CandidatePersistenceBinding::try_new(v4, value, value, value, value).is_err());
    }
}
