use super::super::*;

pub(super) fn required(values: &[&String]) -> Result<(), ProviderContractError> {
    if values.iter().any(|value| value.is_empty()) {
        Err(invalid("required profile field"))
    } else {
        Ok(())
    }
}

pub fn validate_chain_anchor(anchor: &ChainReadAnchorV1) -> Result<(), ProviderContractError> {
    nonempty(&anchor.chain_id, "chain")?;
    nonempty(&anchor.genesis_hash, "genesis")?;
    nonempty(&anchor.network_id, "network")?;
    match anchor.selector_kind {
        BlockSelectorKind::Pinned
            if anchor.block_number.is_some()
                && anchor
                    .block_hash
                    .as_deref()
                    .is_some_and(|hash| !hash.is_empty())
                && !anchor.pending_authorized_by_profile =>
        {
            Ok(())
        }
        BlockSelectorKind::Pending
            if anchor.pending_authorized_by_profile
                && anchor.block_number.is_none()
                && anchor.block_hash.is_none() =>
        {
            Ok(())
        }
        _ => Err(invalid("pinned or authorized pending anchor")),
    }
}

pub(super) fn positive_source_range(range: &SourceRangeV1) -> Result<(), ProviderContractError> {
    if matches!(range.end, RangeEndV1::Inclusive(end) if end < range.start) {
        Err(invalid("source range"))
    } else {
        Ok(())
    }
}

pub(super) fn source_range_within(inner: &SourceRangeV1, outer: &SourceRangeV1) -> bool {
    if inner.start < outer.start {
        return false;
    }
    match (&inner.end, &outer.end) {
        (_, RangeEndV1::Open) => true,
        (RangeEndV1::Inclusive(inner_end), RangeEndV1::Inclusive(outer_end)) => {
            inner_end <= outer_end
        }
        (RangeEndV1::Open, RangeEndV1::Inclusive(_)) => false,
    }
}

pub(super) fn inclusive_within_source(inner: &InclusiveRangeV1, outer: &SourceRangeV1) -> bool {
    inner.start <= inner.end
        && inner.start >= outer.start
        && match outer.end {
            RangeEndV1::Open => true,
            RangeEndV1::Inclusive(end) => inner.end <= end,
        }
}

pub(super) fn inclusive_contains(outer: &InclusiveRangeV1, block: u64) -> bool {
    outer.start <= block && block <= outer.end
}

pub(super) fn checked_inclusive_span(range: &InclusiveRangeV1) -> Option<u64> {
    range.end.checked_sub(range.start)?.checked_add(1)
}

pub(super) fn validate_limits(limits: &IndexerLimitsV1) -> Result<(), ProviderContractError> {
    if limits.max_request_bytes == 0
        || limits.max_range == 0
        || limits.max_batch == 0
        || limits.max_response_bytes == 0
        || limits.max_depth == 0
        || limits.max_resource == 0
        || limits.rate_limit_contract_digest.is_empty()
    {
        Err(invalid("indexer limits"))
    } else {
        Ok(())
    }
}

pub(super) fn limits_narrower(inner: &IndexerLimitsV1, outer: &IndexerLimitsV1) -> bool {
    inner.max_request_bytes <= outer.max_request_bytes
        && inner.max_range <= outer.max_range
        && inner.max_batch <= outer.max_batch
        && inner.max_response_bytes <= outer.max_response_bytes
        && inner.max_depth <= outer.max_depth
        && inner.max_resource <= outer.max_resource
        && inner.rate_limit_contract_digest == outer.rate_limit_contract_digest
}

pub(super) fn validate_methods(methods: &[MethodDataClass]) -> Result<(), ProviderContractError> {
    if methods.is_empty()
        || methods
            .iter()
            .any(|method| method.method.is_empty() || method.data_class.is_empty())
        || !methods.windows(2).all(|pair| {
            (&pair[0].method, &pair[0].data_class) < (&pair[1].method, &pair[1].data_class)
        })
    {
        Err(invalid("method data classes"))
    } else {
        Ok(())
    }
}

pub(super) fn canonical_named(values: &[NamedDigestV1]) -> Result<(), ProviderContractError> {
    if values.is_empty()
        || values
            .iter()
            .any(|value| value.name.is_empty() || value.digest.is_empty())
        || !values
            .windows(2)
            .all(|pair| pair[0].name.as_bytes() < pair[1].name.as_bytes())
    {
        Err(invalid("named digests"))
    } else {
        Ok(())
    }
}

pub(super) fn canonical_dependencies(values: &[DependencyV1]) -> Result<(), ProviderContractError> {
    if values.is_empty()
        || values.iter().any(|value| {
            value.name.is_empty() || value.version.is_empty() || value.digest.is_empty()
        })
        || !values
            .windows(2)
            .all(|pair| pair[0].name.as_bytes() < pair[1].name.as_bytes())
    {
        Err(invalid("dependencies"))
    } else {
        Ok(())
    }
}

pub(super) fn canonical_selectors(values: &[TypedSelectorV1]) -> Result<(), ProviderContractError> {
    if values.is_empty()
        || values.iter().any(|value| {
            value.field_id.is_empty()
                || value.schema_digest.is_empty()
                || value.selector_digest.is_empty()
        })
        || !values
            .windows(2)
            .all(|pair| pair[0].field_id.as_bytes() < pair[1].field_id.as_bytes())
    {
        Err(invalid("typed selectors"))
    } else {
        Ok(())
    }
}

pub(super) fn canonical_set(values: &[String]) -> bool {
    !values.is_empty()
        && values
            .windows(2)
            .all(|pair| !pair[0].is_empty() && pair[0].as_bytes() < pair[1].as_bytes())
        && values.last().is_some_and(|value| !value.is_empty())
}

pub(super) fn canonical_capabilities(values: &[IndexerCapability]) -> bool {
    !values.is_empty()
        && values
            .windows(2)
            .all(|pair| capability_rank(pair[0]) < capability_rank(pair[1]))
}

fn capability_rank(value: IndexerCapability) -> u8 {
    match value {
        IndexerCapability::ProjectSessionCore => 0,
        IndexerCapability::EventOnly => 1,
        IndexerCapability::StateRead => 2,
        IndexerCapability::TransactionReceiptFullBlock => 3,
        IndexerCapability::TraceCallHandler => 4,
        IndexerCapability::DynamicTemplate => 5,
        IndexerCapability::SubQueryDataNodeProfile => 6,
        IndexerCapability::FirehoseSubstreams => 7,
    }
}

pub(super) fn unique<'a>(mut values: impl Iterator<Item = &'a String>) -> bool {
    let mut seen = BTreeSet::new();
    values.all(|value| seen.insert(value))
}

pub(super) fn canonical_ranges(values: &[InclusiveRangeV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].start <= pair[0].end && pair[0].end < pair[1].start)
        && values.last().is_none_or(|value| value.start <= value.end)
}

pub(super) fn validate_candidate_records(
    values: &[CandidateRecordV1],
    require_nonempty: bool,
) -> Result<(), ProviderContractError> {
    if values.iter().any(|value| value.record_id.is_empty())
        || !unique(values.iter().map(|value| &value.record_id))
    {
        return Err(invalid("candidate record identity"));
    }
    if (require_nonempty && values.is_empty())
        || values.iter().enumerate().any(|(index, value)| {
            value.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
                || value.schema_digest.is_empty()
                || value.normalized_digest.is_empty()
                || value.evidence_digest.is_empty()
                || value.canonical_block_hash.is_empty()
        })
    {
        return Err(invalid("candidate records"));
    }
    Ok(())
}

pub(super) fn validate_missing_intervals(
    values: &[InclusiveRangeV1],
    owner_range: &InclusiveRangeV1,
    completed_watermark: u64,
) -> Result<(), ProviderContractError> {
    if !canonical_ranges(values) {
        return Err(invalid("missing interval canonicality"));
    }
    if values.iter().any(|value| {
        value.start < owner_range.start || value.end > owner_range.end || value.start > value.end
    }) {
        return Err(invalid("missing interval containment"));
    }
    if values
        .iter()
        .any(|value| value.start <= completed_watermark)
    {
        return Err(invalid("missing interval watermark"));
    }
    Ok(())
}

pub(super) fn sequenced(values: &[SequencedObservationV1]) -> bool {
    !values.is_empty()
        && values.iter().enumerate().all(|(index, value)| {
            value.sequence == u64::try_from(index + 1).unwrap_or(u64::MAX)
                && !value.normalized_digest.is_empty()
                && !value.evidence_digest.is_empty()
                && validate_chain_anchor(&value.anchor).is_ok()
        })
}
