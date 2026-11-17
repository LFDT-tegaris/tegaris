use super::super::*;
use super::indexer::{validate_candidate_projection_batch, validate_projection_plan};
use super::shared::*;

pub fn validate_subquery_profile(
    client: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    value: &SubQueryClientProfileV1,
) -> Result<(), ProviderContractError> {
    validate_projection_plan(client, plan)?;
    validate_candidate_authority(value.source_authority)?;
    required(&[
        &value.profile_id,
        &value.profile_version,
        &value.profile_digest,
        &value.project_id,
        &value.manifest_spec_version,
        &value.manifest_digest,
        &value.chain_id,
        &value.genesis_hash,
        &value.network_id,
        &value.checkpoint_digest,
        &value.finality_digest,
        &value.reorg_digest,
        &value.privacy_law_digest,
        &value.current_receipt_digest,
    ])?;
    if !matches!(
        value.lifecycle,
        ClientIndexerLifecycle::Qualified | ClientIndexerLifecycle::Active
    ) || value.client_profile_id != client.profile_id
        || value.client_profile_version != client.profile_version
        || value.client_profile_digest != client.profile_digest
        || value.plan_digest != plan.plan_digest
        || value.chain_id != client.chain_id
        || value.genesis_hash != client.genesis_hash
        || value.network_id != client.network_id
        || value.finality_digest != client.finality_rule_digest
        || value.privacy_law_digest != client.privacy_evidence_digest
        || value.managed_lifecycle != ManagedSubqueryLifecycle::FutureAbsent
        || !limits_narrower(&value.limits, &plan.limits)
    {
        return Err(invalid("subquery exact profile"));
    }
    if !surface_matches_family(client, value) {
        return Err(invalid("subquery data node surface"));
    }
    for dependency in [
        &value.runner,
        &value.node,
        &value.query_service,
        &value.package_manager,
    ] {
        required(&[&dependency.name, &dependency.version, &dependency.digest])?;
    }
    canonical_dependencies(&value.dependencies)?;
    if value
        .assets
        .iter()
        .chain(value.abi_schema_code_digests.iter())
        .any(|item| !immutable_content_locator(&item.name))
    {
        return Err(invalid("subquery immutable content locator"));
    }
    canonical_named(&value.mappings)?;
    canonical_named(&value.processors)?;
    if !value.assets.is_empty() {
        canonical_named(&value.assets)?;
    }
    canonical_selectors(&value.filters)?;
    canonical_named(&value.abi_schema_code_digests)?;
    if !unique(value.mappings.iter().map(|item| &item.digest))
        || !unique(value.processors.iter().map(|item| &item.digest))
        || !unique(value.assets.iter().map(|item| &item.digest))
        || !unique(
            value
                .abi_schema_code_digests
                .iter()
                .map(|item| &item.digest),
        )
    {
        return Err(invalid("subquery content catalog uniqueness"));
    }
    if !canonical_set(&value.project_schema_digests) {
        return Err(invalid("subquery project schema"));
    }
    if value.data_sources.iter().any(|source| {
        !canonical_optional_set(&source.asset_digests)
            || !canonical_optional_set(&source.abi_digests)
    }) {
        return Err(invalid("subquery source content references"));
    }
    if !canonical_ids(
        value
            .data_sources
            .iter()
            .map(|source| &source.data_source_id),
    ) || !canonical_ids(value.handlers.iter().map(|handler| &handler.handler_id))
    {
        return Err(invalid("subquery canonical identifiers"));
    }
    for source in &value.data_sources {
        required(&[&source.data_source_id, &source.kind, &source.mapping_digest])?;
        let range = SourceRangeV1 {
            start: source.start,
            end: source.end,
        };
        if source.start == 0
            || positive_source_range(&range).is_err()
            || !source_range_within(&range, &plan.source_range)
            || plan
                .partitions
                .iter()
                .filter(|partition| {
                    partition.source_id == source.data_source_id
                        && source_range_within(&range, &partition.range)
                })
                .count()
                != 1
            || value
                .mappings
                .iter()
                .filter(|mapping| mapping.digest == source.mapping_digest)
                .count()
                != 1
        {
            return Err(invalid("subquery source relation"));
        }
    }
    for handler in &value.handlers {
        required(&[
            &handler.handler_id,
            &handler.data_source_id,
            &handler.processor_id,
            &handler.filter_id,
        ])?;
        if validate_methods(&handler.required_method_data).is_err()
            || !handler
                .required_method_data
                .iter()
                .all(|method| client.method_data_classes.contains(method))
            || value
                .data_sources
                .iter()
                .filter(|source| source.data_source_id == handler.data_source_id)
                .count()
                != 1
            || value
                .processors
                .iter()
                .filter(|processor| processor.name == handler.processor_id)
                .count()
                != 1
            || value
                .filters
                .iter()
                .filter(|filter| filter.field_id == handler.filter_id)
                .count()
                != 1
        {
            return Err(invalid("subquery handler relation"));
        }
    }
    let resolves_once = |catalog: &[NamedDigestV1], digest: &str| {
        catalog.iter().filter(|item| item.digest == digest).count() == 1
    };
    if value
        .project_schema_digests
        .iter()
        .any(|digest| !resolves_once(&value.abi_schema_code_digests, digest))
    {
        return Err(invalid("subquery project schema reference"));
    }
    if value.data_sources.iter().any(|source| {
        source
            .asset_digests
            .iter()
            .any(|digest| !resolves_once(&value.assets, digest))
            || source
                .abi_digests
                .iter()
                .any(|digest| !resolves_once(&value.abi_schema_code_digests, digest))
    }) {
        return Err(invalid("subquery source content reference"));
    }
    if value
        .mappings
        .iter()
        .any(|mapping| !resolves_once(&value.abi_schema_code_digests, &mapping.digest))
        || value
            .processors
            .iter()
            .any(|processor| !resolves_once(&value.abi_schema_code_digests, &processor.digest))
    {
        return Err(invalid("subquery executable content reference"));
    }
    if value.mappings.iter().any(|mapping| {
        !value
            .data_sources
            .iter()
            .any(|source| source.mapping_digest == mapping.digest)
    }) || value.processors.iter().any(|processor| {
        !value
            .handlers
            .iter()
            .any(|handler| handler.processor_id == processor.name)
    }) || value.filters.iter().any(|filter| {
        !value
            .handlers
            .iter()
            .any(|handler| handler.filter_id == filter.field_id)
    }) || value.assets.iter().any(|asset| {
        !value
            .data_sources
            .iter()
            .any(|source| source.asset_digests.contains(&asset.digest))
    }) || value.abi_schema_code_digests.iter().any(|content| {
        !value.project_schema_digests.contains(&content.digest)
            && !value
                .data_sources
                .iter()
                .any(|source| source.abi_digests.contains(&content.digest))
            && !value
                .mappings
                .iter()
                .any(|mapping| mapping.digest == content.digest)
            && !value
                .processors
                .iter()
                .any(|processor| processor.digest == content.digest)
    }) {
        return Err(invalid("subquery orphan declaration"));
    }
    Ok(())
}

pub fn validate_subquery_batch(
    client: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    profile: &SubQueryClientProfileV1,
    batch: &SubQueryCandidateBatchV1,
) -> Result<(), ProviderContractError> {
    validate_subquery_profile(client, plan, profile)?;
    validate_candidate_projection_batch(client, plan, &batch.base)?;
    let handler = profile
        .handlers
        .iter()
        .find(|handler| {
            handler.handler_id == batch.handler_id && handler.data_source_id == batch.data_source_id
        })
        .ok_or_else(|| invalid("subquery handler ownership"))?;
    let source = profile
        .data_sources
        .iter()
        .find(|source| source.data_source_id == batch.data_source_id)
        .ok_or_else(|| invalid("subquery source ownership"))?;
    let source_range = SourceRangeV1 {
        start: source.start,
        end: source.end,
    };
    if batch.subquery_profile_id != profile.profile_id
        || batch.subquery_profile_version != profile.profile_version
        || batch.subquery_profile_digest != profile.profile_digest
        || batch.project_id != profile.project_id
        || batch.data_source_id != batch.base.source_id
        || !inclusive_within_source(&batch.base.range, &source_range)
    {
        return Err(invalid("subquery candidate batch"));
    }
    match &batch.operation {
        SubQueryOperationV1::JsonRpc(method)
            if client.client_family == ClientIndexerFamily::SubQueryEvmJsonRpc
                && handler.required_method_data.contains(method)
                && client.method_data_classes.contains(method) =>
        {
            Ok(())
        }
        SubQueryOperationV1::DataNodeCapabilities
            if client.client_family == ClientIndexerFamily::SubQueryDataNode
                && client.method_data_classes.contains(&MethodDataClass {
                    method: "subql_filterBlocksCapabilities".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                })
                && handler.required_method_data.contains(&MethodDataClass {
                    method: "subql_filterBlocksCapabilities".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                })
                && matches!(
                    &profile.data_node_surface,
                    SubQueryDataNodeSurfaceV1::Exact { .. }
                ) =>
        {
            Ok(())
        }
        SubQueryOperationV1::DataNodeFilterBlocks(selector)
            if client.client_family == ClientIndexerFamily::SubQueryDataNode
                && client.method_data_classes.contains(&MethodDataClass {
                    method: "subql_filterBlocks".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                })
                && handler.required_method_data.contains(&MethodDataClass {
                    method: "subql_filterBlocks".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                })
                && handler.filter_id == selector.field_id
                && profile.filters.contains(selector)
                && matches!(
                    &profile.data_node_surface,
                    SubQueryDataNodeSurfaceV1::Exact {
                        allowed_fields,
                        allowed_selectors,
                        ..
                    } if allowed_fields.contains(&selector.field_id)
                        && allowed_selectors.contains(selector)
                ) =>
        {
            Ok(())
        }
        _ => Err(invalid("subquery operation")),
    }
}

fn surface_matches_family(
    client: &ClientIndexerProfileV1,
    profile: &SubQueryClientProfileV1,
) -> bool {
    match (client.client_family, &profile.data_node_surface) {
        (ClientIndexerFamily::SubQueryEvmJsonRpc, SubQueryDataNodeSurfaceV1::NotDeclared) => true,
        (
            ClientIndexerFamily::SubQueryDataNode,
            SubQueryDataNodeSurfaceV1::Exact {
                protocol_version,
                schema_version,
                allowed_fields,
                allowed_selectors,
            },
        ) => {
            let exact_methods = vec![
                MethodDataClass {
                    method: "subql_filterBlocks".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                },
                MethodDataClass {
                    method: "subql_filterBlocksCapabilities".into(),
                    data_class: "SUBQUERY_FILTERED_BLOCK".into(),
                },
            ];
            let canonical_filter_fields = profile
                .filters
                .iter()
                .map(|selector| selector.field_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            !protocol_version.is_empty()
                && !schema_version.is_empty()
                && client.method_data_classes == exact_methods
                && allowed_fields == &canonical_filter_fields
                && allowed_selectors == &profile.filters
                && canonical_set(allowed_fields)
                && canonical_selectors(allowed_selectors).is_ok()
                && client
                    .capability_profiles
                    .contains(&IndexerCapability::SubQueryDataNodeProfile)
        }
        _ => false,
    }
}

fn canonical_ids<'a>(values: impl Iterator<Item = &'a String>) -> bool {
    let values = values.collect::<Vec<_>>();
    !values.is_empty()
        && values
            .windows(2)
            .all(|pair| !pair[0].is_empty() && pair[0].as_bytes() < pair[1].as_bytes())
        && values.last().is_some_and(|value| !value.is_empty())
}

fn canonical_optional_set(values: &[String]) -> bool {
    values.is_empty()
        || values
            .windows(2)
            .all(|pair| !pair[0].is_empty() && pair[0].as_bytes() < pair[1].as_bytes())
            && values.last().is_some_and(|value| !value.is_empty())
}

fn immutable_content_locator(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains("://")
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}
