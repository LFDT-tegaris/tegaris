use super::super::*;
use super::shared::*;

pub fn validate_explorer_profile(
    value: &ExplorerFactSourceProfileV1,
) -> Result<(), ProviderContractError> {
    validate_candidate_authority(value.source_authority)?;
    required(&[
        &value.adapter_schema_digest,
        &value.profile_id,
        &value.profile_version,
        &value.profile_digest,
        &value.product_id,
        &value.instance_id,
        &value.release_digest,
        &value.build_digest,
        &value.api_digest,
        &value.current_receipt_digest,
        &value.participant_binding,
        &value.privacy_binding,
        &value.source_trust_binding,
        &value.checkpoint_protocol_digest,
        &value.resume_protocol_digest,
        &value.chain_id,
        &value.genesis_hash,
        &value.network_id,
        &value.canonicality_digest,
        &value.finality_digest,
        &value.reorg_digest,
        &value.removal_digest,
        &value.completeness_digest,
        &value.watermark_digest,
        &value.freshness_digest,
        &value.trust_digest,
        &value.revocation_digest,
        &value.provenance_digest,
        &value.conflict_digest,
        &value.privacy_projection_digest,
        &value.redaction_digest,
        &value.hmac_key_version,
        &value.privacy_evidence_digest,
        &value.rate_law_digest,
        &value.timeout_law_digest,
        &value.retry_law_digest,
        &value.upgrade_digest,
        &value.rollback_digest,
        &value.disable_digest,
        &value.uninstall_digest,
        &value.corpus_digest,
        &value.conformance_receipt_digest,
    ])?;
    if value.adapter_contract_id != "OPENEXPLORER_FACT_SOURCE_V1"
        || value.adapter_contract_version != "1.0.0"
        || !matches!(
            value.lifecycle,
            ExplorerLifecycle::Qualified | ExplorerLifecycle::Active
        )
        || !canonical_set(&value.supported_fact_profiles)
        || !canonical_set(&value.allowed_operations)
        || !canonical_set(&value.allowed_data_classes)
        || !canonical_set(&value.allowed_fields)
        || !canonical_set(&value.allowed_filters)
        || !canonical_set(&value.telemetry_classifications)
        || value.page_limits.max_page_items == 0
        || value.page_limits.max_page_bytes == 0
    {
        return Err(invalid("explorer exact profile"));
    }
    validate_limits(&value.limits)?;
    canonical_named(&value.dynamic_event_schemas)?;
    canonical_named(&value.response_schema_digests)?;
    canonical_named(&value.scope_digests)?;
    if value.source_partitions.is_empty()
        || !unique(
            value
                .source_partitions
                .iter()
                .map(|partition| &partition.partition_id),
        )
        || value.source_partitions.iter().any(|partition| {
            partition.partition_id.is_empty()
                || partition.source_id != value.instance_id
                || partition.finality_digest != value.finality_digest
                || partition.checkpoint_digest.is_empty()
                || positive_source_range(&partition.range).is_err()
        })
        || !value.source_partitions.windows(2).all(|pair| {
            matches!(pair[0].range.end, RangeEndV1::Inclusive(left_end) if left_end < pair[1].range.start)
                && (pair[0].range.start, pair[0].partition_id.as_bytes())
                    < (pair[1].range.start, pair[1].partition_id.as_bytes())
        })
    {
        return Err(invalid("explorer source partitions"));
    }
    Ok(())
}

pub fn validate_explorer_page(
    profile: &ExplorerFactSourceProfileV1,
    page: &ExplorerCandidatePageV1,
) -> Result<(), ProviderContractError> {
    validate_explorer_profile(profile)?;
    validate_candidate_authority(page.source_authority)?;
    if page.request_id.is_empty()
        || page.participant_binding != profile.participant_binding
        || page.privacy_binding != profile.privacy_binding
        || page.profile_id != profile.profile_id
        || page.profile_version != profile.profile_version
        || page.profile_digest != profile.profile_digest
        || page.source_instance_id != profile.instance_id
        || !profile
            .scope_digests
            .iter()
            .any(|scope| scope.digest == page.authorized_scope_digest)
        || page.page_id.is_empty()
        || page.response_digest.is_empty()
        || page.derivation_digest.is_empty()
        || page.provenance_digest.is_empty()
        || !canonical_set(&page.evidence_refs)
        || !cursor_transition(&page.resume_cursor, &page.next_cursor)
        || page.completed_watermark.canonical_block_hash.is_empty()
    {
        return Err(invalid("explorer candidate page"));
    }
    validate_candidate_records(&page.records, false)?;
    if page.range.start == 0 || page.range.start > page.range.end {
        return Err(invalid("explorer candidate page limits"));
    }
    let record_count =
        u64::try_from(page.records.len()).map_err(|_| invalid("explorer candidate page limits"))?;
    let page_span = checked_inclusive_span(&page.range)
        .ok_or_else(|| invalid("explorer candidate page limits"))?;
    if record_count > profile.page_limits.max_page_items
        || record_count > profile.limits.max_batch
        || page_span > profile.limits.max_range
    {
        return Err(invalid("explorer candidate page limits"));
    }
    if page.completed_watermark.block_number < page.range.start
        || page.completed_watermark.block_number > page.range.end
    {
        return Err(invalid("explorer candidate page"));
    }
    let mut owning_partitions = profile
        .source_partitions
        .iter()
        .filter(|partition| inclusive_within_source(&page.range, &partition.range));
    let owning_partition = owning_partitions
        .next()
        .ok_or_else(|| invalid("explorer partition state"))?;
    if owning_partitions.next().is_some() {
        return Err(invalid("explorer partition state"));
    }
    let has_gap = !page.missing_intervals.is_empty();
    let has_invalidation =
        !page.reorg_observations.is_empty() || !page.removal_observations.is_empty();
    let plain_empty = page.records.is_empty() && !has_gap && !has_invalidation;
    if !partition_state_admits_page(
        owning_partition.state,
        page,
        has_gap,
        has_invalidation,
        plain_empty,
    ) {
        return Err(invalid("explorer partition state"));
    }
    if plain_empty {
        let valid_incoming_cursor = matches!(page.resume_cursor, ExplorerCursorV1::Initial)
            || matches!(
                &page.resume_cursor,
                ExplorerCursorV1::Resume { digest } if !digest.is_empty()
            );
        if !valid_incoming_cursor
            || page.next_cursor != ExplorerCursorV1::Complete
            || page.completed_watermark.block_number != page.range.end
        {
            return Err(invalid("explorer authoritative empty"));
        }
        return Ok(());
    }
    validate_missing_intervals(
        &page.missing_intervals,
        &page.range,
        page.completed_watermark.block_number,
    )?;
    if page.next_cursor == ExplorerCursorV1::Complete && !page.missing_intervals.is_empty() {
        return Err(invalid("explorer candidate page"));
    }
    if !observations_in_range(profile, page, &page.reorg_observations)
        || !observations_in_range(profile, page, &page.removal_observations)
    {
        return Err(invalid("explorer range or watermark relation"));
    }
    validate_explorer_canonical_anchors(page)?;
    let watermark_proven = page.records.iter().any(|record| {
        record.block_number == page.completed_watermark.block_number
            && record.canonical_block_hash == page.completed_watermark.canonical_block_hash
    }) || page
        .reorg_observations
        .iter()
        .chain(&page.removal_observations)
        .any(|observation| {
            observation.anchor.block_number == Some(page.completed_watermark.block_number)
                && observation.anchor.block_hash.as_deref()
                    == Some(page.completed_watermark.canonical_block_hash.as_str())
        });
    if (!has_gap && !has_invalidation && !watermark_proven)
        || page.records.iter().any(|record| {
            !inclusive_contains(&page.range, record.block_number)
                || (record.block_number == page.completed_watermark.block_number
                    && record.canonical_block_hash != page.completed_watermark.canonical_block_hash)
        })
        || page
            .reorg_observations
            .iter()
            .chain(&page.removal_observations)
            .any(|observation| {
                observation
                    .anchor
                    .block_number
                    .is_some_and(|block| block <= page.completed_watermark.block_number)
            })
    {
        return Err(invalid("explorer range or watermark relation"));
    }
    Ok(())
}

fn partition_state_admits_page(
    state: PartitionState,
    page: &ExplorerCandidatePageV1,
    has_gap: bool,
    has_invalidation: bool,
    plain_empty: bool,
) -> bool {
    match state {
        PartitionState::Bootstrap | PartitionState::CatchingUp | PartitionState::Complete => {
            !has_gap && !has_invalidation
        }
        PartitionState::GapBlocked => {
            has_gap && !has_invalidation && page.next_cursor != ExplorerCursorV1::Complete
        }
        PartitionState::ReorgFenced => {
            page.records.is_empty()
                && has_invalidation
                && !has_gap
                && page.next_cursor != ExplorerCursorV1::Complete
        }
        PartitionState::Recovering => !plain_empty,
        PartitionState::Quarantined | PartitionState::Disabled | PartitionState::Retired => false,
    }
}

fn cursor_transition(current: &ExplorerCursorV1, next: &ExplorerCursorV1) -> bool {
    match (current, next) {
        (ExplorerCursorV1::Initial, ExplorerCursorV1::Resume { digest }) => !digest.is_empty(),
        (ExplorerCursorV1::Resume { digest: current }, ExplorerCursorV1::Resume { digest }) => {
            !current.is_empty() && !digest.is_empty() && current != digest
        }
        (ExplorerCursorV1::Initial, ExplorerCursorV1::Complete) => true,
        (ExplorerCursorV1::Resume { digest }, ExplorerCursorV1::Complete) => !digest.is_empty(),
        _ => false,
    }
}

fn validate_explorer_canonical_anchors(
    page: &ExplorerCandidatePageV1,
) -> Result<(), ProviderContractError> {
    let mut canonical_anchors = BTreeMap::<u64, String>::new();
    let mut insert_anchor = |block_number: u64, block_hash: &str| {
        if canonical_anchors
            .insert(block_number, block_hash.to_owned())
            .is_some_and(|existing| existing != block_hash)
        {
            Err(invalid("explorer canonical anchor coherence"))
        } else {
            Ok(())
        }
    };
    for record in &page.records {
        insert_anchor(record.block_number, &record.canonical_block_hash)?;
    }
    for observation in page
        .reorg_observations
        .iter()
        .chain(&page.removal_observations)
    {
        insert_anchor(
            observation
                .anchor
                .block_number
                .expect("validated pinned explorer anchor"),
            observation
                .anchor
                .block_hash
                .as_deref()
                .expect("validated pinned explorer anchor"),
        )?;
    }
    insert_anchor(
        page.completed_watermark.block_number,
        &page.completed_watermark.canonical_block_hash,
    )
}

fn observations_in_range(
    profile: &ExplorerFactSourceProfileV1,
    page: &ExplorerCandidatePageV1,
    values: &[SequencedObservationV1],
) -> bool {
    (values.is_empty() || sequenced(values))
        && values.iter().all(|value| {
            value.anchor.chain_id == profile.chain_id
                && value.anchor.genesis_hash == profile.genesis_hash
                && value.anchor.network_id == profile.network_id
                && value
                    .anchor
                    .block_number
                    .is_some_and(|block| inclusive_contains(&page.range, block))
        })
}
