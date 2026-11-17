use super::super::*;
use super::shared::*;

pub fn validate_client_indexer_profile(
    value: &ClientIndexerProfileV1,
) -> Result<(), ProviderContractError> {
    validate_candidate_authority(value.source_authority)?;
    required(&[
        &value.profile_id,
        &value.profile_version,
        &value.profile_digest,
        &value.engine_or_runtime,
        &value.engine_version,
        &value.configuration_digest,
        &value.participant_binding,
        &value.privacy_binding,
        &value.workload_binding,
        &value.deployment_owner,
        &value.boundary_declaration_digest,
        &value.protocol_version,
        &value.chain_id,
        &value.genesis_hash,
        &value.network_id,
        &value.finality_rule_digest,
        &value.reorg_behavior_digest,
        &value.removed_event_behavior_digest,
        &value.checkpoint_semantics_digest,
        &value.completed_watermark_semantics_digest,
        &value.candidate_store_contract_digest,
        &value.outbox_contract_digest,
        &value.fact_bridge_contract_digest,
        &value.security_evidence_digest,
        &value.privacy_evidence_digest,
        &value.licensing_digest,
        &value.supply_chain_digest,
        &value.telemetry_classification_digest,
        &value.rollback_digest,
        &value.uninstall_digest,
        &value.corpus_digest,
        &value.conformance_receipt_digest,
    ])?;
    if !matches!(
        value.lifecycle,
        ClientIndexerLifecycle::Qualified | ClientIndexerLifecycle::Active
    ) || !protocol_matches_family(value.client_family, value.protocol_kind)
        || !canonical_capabilities(&value.capability_profiles)
    {
        return Err(invalid("exact client indexer tuple"));
    }
    positive_source_range(&value.source_range)?;
    validate_limits(&value.limits)?;
    validate_methods(&value.method_data_classes)?;
    canonical_dependencies(&value.dependencies)?;
    canonical_named(&value.artifact_digests)?;
    required(&[
        &value.behavior.visibility_miss_digest,
        &value.behavior.empty_digest,
        &value.behavior.partial_digest,
        &value.behavior.error_digest,
        &value.behavior.retry_digest,
        &value.behavior.recovery_digest,
        &value.behavior.retirement_digest,
    ])?;
    Ok(())
}

fn protocol_matches_family(family: ClientIndexerFamily, protocol: IndexerProtocolKind) -> bool {
    matches!(
        (family, protocol),
        (
            ClientIndexerFamily::TheGraphEvmJsonRpc
                | ClientIndexerFamily::SubQueryEvmJsonRpc
                | ClientIndexerFamily::CustomEvmIndexer,
            IndexerProtocolKind::JsonRpc
        ) | (
            ClientIndexerFamily::SubQueryDataNode,
            IndexerProtocolKind::Http
        )
    )
}

pub fn validate_projection_plan(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
) -> Result<(), ProviderContractError> {
    validate_client_indexer_profile(profile)?;
    if plan.profile_id != profile.profile_id
        || plan.profile_version != profile.profile_version
        || plan.profile_digest != profile.profile_digest
        || plan.plan_digest.is_empty()
        || plan.finality_rule_digest != profile.finality_rule_digest
        || plan.lifecycle_generation == 0
        || plan.desired_state != DesiredState::Active
        || plan.source_range.start == 0
        || positive_source_range(&plan.source_range).is_err()
        || !source_range_within(&plan.source_range, &profile.source_range)
        || !limits_narrower(&plan.limits, &profile.limits)
    {
        return Err(invalid("projection plan binding"));
    }
    match &plan.workload_identity {
        WorkloadIdentityV1::ExternalOwner {
            owner,
            boundary_digest,
        } => required(&[owner, boundary_digest])?,
        WorkloadIdentityV1::ImageBuild {
            image_digest,
            build_digest,
            sbom_digest,
            provenance_digest,
        } => required(&[image_digest, build_digest, sbom_digest, provenance_digest])?,
    }
    canonical_named(&plan.extractor_digests)?;
    canonical_named(&plan.candidate_schema_digests)?;
    if !plan.secret_references.windows(2).all(|pair| {
        (secret_rank(pair[0].purpose), pair[0].reference.as_bytes())
            < (secret_rank(pair[1].purpose), pair[1].reference.as_bytes())
    }) || plan
        .secret_references
        .iter()
        .any(|value| !value.reference.starts_with("ref:") || value.reference.len() == 4)
    {
        return Err(invalid("secret references"));
    }
    validate_partition_coverage(profile, plan)
}

fn secret_rank(value: SecretPurposeV1) -> u8 {
    match value {
        SecretPurposeV1::SourceCredential => 0,
        SecretPurposeV1::ApiToken => 1,
        SecretPurposeV1::HmacKey => 2,
    }
}

fn validate_partition_coverage(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
) -> Result<(), ProviderContractError> {
    if plan.partitions.is_empty()
        || !unique(plan.partitions.iter().map(|value| &value.partition_id))
        || plan.partitions.iter().any(|part| {
            part.partition_id.is_empty()
                || part.source_id.is_empty()
                || part.range.start == 0
                || positive_source_range(&part.range).is_err()
                || part.finality_digest != profile.finality_rule_digest
                || part.checkpoint_digest.is_empty()
                || !matches!(
                    part.state,
                    PartitionState::Complete | PartitionState::CatchingUp
                )
                || !source_range_within(&part.range, &plan.source_range)
        })
    {
        return Err(invalid("projection partitions"));
    }
    let mut expected_start = plan.source_range.start;
    for (index, partition) in plan.partitions.iter().enumerate() {
        let is_final = index + 1 == plan.partitions.len();
        if partition.range.start != expected_start {
            return Err(invalid("partition gap or overlap"));
        }
        match partition.range.end {
            RangeEndV1::Inclusive(end) => {
                if is_final {
                    return match plan.source_range.end {
                        RangeEndV1::Inclusive(plan_end) if end == plan_end => Ok(()),
                        _ => Err(invalid("partition coverage")),
                    };
                }
                expected_start = end
                    .checked_add(1)
                    .ok_or_else(|| invalid("partition range overflow"))?;
            }
            RangeEndV1::Open => {
                if !is_final || plan.source_range.end != RangeEndV1::Open {
                    return Err(invalid("open partition coverage"));
                }
                return Ok(());
            }
        }
    }
    Err(invalid("partition coverage"))
}

pub fn validate_candidate_projection_batch(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
) -> Result<(), ProviderContractError> {
    validate_candidate_projection_batch_with_predecessor(profile, plan, batch, None)
}

pub fn validate_candidate_projection_batch_with_predecessor(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    predecessor: Option<(&CandidateProjectionBatchV1, &str)>,
) -> Result<(), ProviderContractError> {
    validate_candidate_projection_batch_structure(profile, plan, batch)?;
    validate_candidate_records(&batch.records, true)?;
    validate_predecessor(batch, predecessor)
}

/// Validates the current candidate batch and the closed syntax of its lineage claim.
/// Durable predecessor truth remains the persistence owner's transaction-local decision.
pub fn validate_candidate_projection_batch_structure(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
) -> Result<(), ProviderContractError> {
    validate_projection_plan(profile, plan)?;
    validate_candidate_authority(batch.source_authority)?;
    let partition = plan
        .partitions
        .iter()
        .find(|part| part.partition_id == batch.partition_id && part.source_id == batch.source_id)
        .ok_or_else(|| invalid("batch partition"))?;
    if batch.profile_id != profile.profile_id
        || batch.profile_version != profile.profile_version
        || batch.profile_digest != profile.profile_digest
        || batch.plan_digest != plan.plan_digest
        || batch.source_profile_digest != profile.profile_digest
        || batch.batch_id.is_empty()
        || batch.batch_sequence == 0
        || !sequenced(&batch.observations)
        || !canonical_set(&batch.evidence_refs)
        || batch.completed_watermark.canonical_block_hash.is_empty()
    {
        return Err(invalid("candidate projection batch"));
    }
    validate_candidate_records(&batch.records, false)?;
    if batch.range.start == 0 || batch.range.start > batch.range.end {
        return Err(invalid("candidate projection batch limits"));
    }
    let record_count = u64::try_from(batch.records.len())
        .map_err(|_| invalid("candidate projection batch limits"))?;
    let batch_span = checked_inclusive_span(&batch.range)
        .ok_or_else(|| invalid("candidate projection batch limits"))?;
    if record_count > plan.limits.max_batch
        || record_count > profile.limits.max_batch
        || batch_span > plan.limits.max_range
        || batch_span > profile.limits.max_range
    {
        return Err(invalid("candidate projection batch limits"));
    }
    if !inclusive_within_source(&batch.range, &partition.range)
        || batch.completed_watermark.block_number < batch.range.start
        || batch.completed_watermark.block_number > batch.range.end
    {
        return Err(invalid("candidate projection batch"));
    }
    validate_missing_intervals(
        &batch.missing_intervals,
        &batch.range,
        batch.completed_watermark.block_number,
    )?;
    if (batch.batch_sequence == 1 && batch.predecessor_batch_digest != "GENESIS")
        || (batch.batch_sequence > 1
            && (batch.predecessor_batch_digest.is_empty()
                || batch.predecessor_batch_digest == "GENESIS"))
    {
        return Err(invalid("candidate predecessor syntax"));
    }
    for observation in &batch.observations {
        if validate_chain_anchor(&observation.anchor).is_err()
            || observation.anchor.chain_id != profile.chain_id
            || observation.anchor.genesis_hash != profile.genesis_hash
            || observation.anchor.network_id != profile.network_id
            || !observation
                .anchor
                .block_number
                .is_some_and(|block| inclusive_contains(&batch.range, block))
        {
            return Err(invalid("observation range or anchor"));
        }
        if !is_exact_raw_sha256(&observation.normalized_digest)
            || !is_exact_raw_sha256(&observation.evidence_digest)
        {
            return Err(invalid("observation digest"));
        }
    }
    let watermark_proven = batch
        .records
        .iter()
        .any(|record| record.block_number == batch.completed_watermark.block_number)
        || batch.observations.iter().any(|observation| {
            observation.anchor.block_number == Some(batch.completed_watermark.block_number)
        });
    if !watermark_proven
        || batch
            .records
            .iter()
            .any(|record| !inclusive_contains(&batch.range, record.block_number))
    {
        return Err(invalid("batch range or watermark"));
    }
    for (index, failure) in batch.decode_failures.iter().enumerate() {
        if failure.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
            || failure.source_id != batch.source_id
            || validate_chain_anchor(&failure.anchor).is_err()
            || failure.anchor.chain_id != profile.chain_id
            || failure.anchor.genesis_hash != profile.genesis_hash
            || failure.anchor.network_id != profile.network_id
            || !failure
                .anchor
                .block_number
                .is_some_and(|block| inclusive_contains(&batch.range, block))
        {
            return Err(invalid("decode failure anchor"));
        }
        if !is_exact_raw_sha256(&failure.error_digest)
            || !is_exact_raw_sha256(&failure.evidence_digest)
        {
            return Err(invalid("decode failure digest"));
        }
        if failure
            .anchor
            .block_number
            .is_some_and(|block| block <= batch.completed_watermark.block_number)
        {
            return Err(invalid("decode failure completeness"));
        }
    }
    let mut canonical_anchors = BTreeMap::<u64, String>::new();
    let mut insert_anchor = |block_number: u64, block_hash: &str| {
        if canonical_anchors
            .insert(block_number, block_hash.to_owned())
            .is_some_and(|existing| existing != block_hash)
        {
            Err(invalid("batch canonical anchor coherence"))
        } else {
            Ok(())
        }
    };
    for record in &batch.records {
        insert_anchor(record.block_number, &record.canonical_block_hash)?;
    }
    for observation in &batch.observations {
        insert_anchor(
            observation
                .anchor
                .block_number
                .expect("validated pinned anchor"),
            observation
                .anchor
                .block_hash
                .as_deref()
                .expect("validated pinned anchor"),
        )?;
    }
    for failure in &batch.decode_failures {
        insert_anchor(
            failure
                .anchor
                .block_number
                .expect("validated pinned anchor"),
            failure
                .anchor
                .block_hash
                .as_deref()
                .expect("validated pinned anchor"),
        )?;
    }
    insert_anchor(
        batch.completed_watermark.block_number,
        &batch.completed_watermark.canonical_block_hash,
    )?;
    Ok(())
}

fn is_exact_raw_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_predecessor(
    batch: &CandidateProjectionBatchV1,
    predecessor: Option<(&CandidateProjectionBatchV1, &str)>,
) -> Result<(), ProviderContractError> {
    match (batch.batch_sequence, predecessor) {
        (1, None) if batch.predecessor_batch_digest == "GENESIS" => Ok(()),
        (sequence, Some((prior, prior_digest)))
            if prior.batch_sequence.checked_add(1) == Some(sequence)
                && !prior_digest.is_empty()
                && batch.predecessor_batch_digest == prior_digest
                && batch.profile_id == prior.profile_id
                && batch.profile_version == prior.profile_version
                && batch.profile_digest == prior.profile_digest
                && batch.plan_digest == prior.plan_digest
                && batch.source_id == prior.source_id
                && batch.partition_id == prior.partition_id
                && prior.range.end.checked_add(1) == Some(batch.range.start)
                && batch.completed_watermark.block_number
                    >= prior.completed_watermark.block_number =>
        {
            Ok(())
        }
        _ => Err(invalid("candidate predecessor relation")),
    }
}
