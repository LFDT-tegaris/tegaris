use super::super::*;
use super::indexer::{validate_candidate_projection_batch, validate_projection_plan};
use super::shared::*;

pub fn validate_thegraph_manifest(
    client: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    value: &TheGraphManifestProfileV1,
) -> Result<(), ProviderContractError> {
    validate_projection_plan(client, plan)?;
    validate_candidate_authority(value.source_authority)?;
    required(&[
        &value.profile_id,
        &value.profile_version,
        &value.profile_digest,
        &value.manifest_digest,
        &value.spec_version,
        &value.network,
    ])?;
    if client.client_family != ClientIndexerFamily::TheGraphEvmJsonRpc
        || value.client_profile_id != client.profile_id
        || value.client_profile_version != client.profile_version
        || value.client_profile_digest != client.profile_digest
        || value.projection_plan_digest != plan.plan_digest
        || value.network != client.network_id
    {
        return Err(invalid("thegraph exact manifest"));
    }
    let range_end = match value.range.end {
        RangeEndV1::Inclusive(end) if value.range.start <= end => end,
        _ => return Err(invalid("thegraph bounded range")),
    };
    if !source_range_within(&value.range, &plan.source_range) || !canonical_set(&value.features) {
        return Err(invalid("thegraph exact manifest"));
    }
    canonical_named(&value.referenced_files)?;
    canonical_named(&value.entity_projection_schemas)?;
    validate_methods(&value.state_read_dependencies)?;
    if !unique(value.referenced_files.iter().map(|file| &file.digest))
        || value
            .referenced_files
            .iter()
            .any(|file| !immutable_declared_name(&file.name))
        || !canonical_ids(value.data_sources.iter().map(|item| &item.data_source_id))
        || !canonical_ids(value.mappings.iter().map(|item| &item.mapping_id))
        || !canonical_ids(value.handlers.iter().map(|item| &item.handler_id))
        || (!value.dynamic_templates.is_empty()
            && !canonical_ids(value.dynamic_templates.iter().map(|item| &item.template_id)))
    {
        return Err(invalid("thegraph canonical identifiers"));
    }
    for source in &value.data_sources {
        required(&[
            &source.data_source_id,
            &source.kind,
            &source.name,
            &source.network,
            &source.address,
            &source.abi_digest,
            &source.mapping_id,
        ])?;
        if source.start_block < value.range.start || source.start_block > range_end {
            return Err(invalid("graph data source range"));
        }
        if source.network != value.network
            || !referenced_digest(value, &source.abi_digest)
            || value
                .mappings
                .iter()
                .filter(|mapping| {
                    mapping.mapping_id == source.mapping_id
                        && mapping.data_source_id == source.data_source_id
                })
                .count()
                != 1
        {
            return Err(invalid("graph data source"));
        }
    }
    for mapping in &value.mappings {
        required(&[
            &mapping.mapping_id,
            &mapping.data_source_id,
            &mapping.language,
            &mapping.api_version,
            &mapping.file_digest,
        ])?;
        if !canonical_set(&mapping.entities)
            || !referenced_digest(value, &mapping.file_digest)
            || !mapping.entities.iter().all(|entity| {
                value
                    .entity_projection_schemas
                    .iter()
                    .any(|schema| schema.name == *entity)
            })
            || value
                .data_sources
                .iter()
                .filter(|source| {
                    source.data_source_id == mapping.data_source_id
                        && source.mapping_id == mapping.mapping_id
                })
                .count()
                != 1
        {
            return Err(invalid("graph mapping"));
        }
    }
    for handler in &value.handlers {
        required(&[
            &handler.handler_id,
            &handler.data_source_id,
            &handler.mapping_id,
            &handler.signature,
            &handler.filter,
            &handler.function,
        ])?;
        if validate_methods(&handler.required_method_data).is_err()
            || !handler.required_method_data.iter().all(|method| {
                client.method_data_classes.contains(method)
                    && value.state_read_dependencies.contains(method)
                    && method_matches_handler(method, handler.kind)
            })
            || value
                .mappings
                .iter()
                .filter(|mapping| {
                    mapping.mapping_id == handler.mapping_id
                        && mapping.data_source_id == handler.data_source_id
                })
                .count()
                != 1
        {
            return Err(invalid("graph handler"));
        }
    }
    for template in &value.dynamic_templates {
        required(&[
            &template.template_id,
            &template.mapping_id,
            &template.digest,
            &template.creation_binding,
        ])?;
        if !referenced_digest(value, &template.digest)
            || value
                .mappings
                .iter()
                .filter(|mapping| mapping.mapping_id == template.mapping_id)
                .count()
                != 1
        {
            return Err(invalid("graph template"));
        }
    }
    Ok(())
}

pub fn validate_thegraph_batch(
    client: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    manifest: &TheGraphManifestProfileV1,
    batch: &TheGraphCandidateBatchV1,
) -> Result<(), ProviderContractError> {
    validate_thegraph_manifest(client, plan, manifest)?;
    validate_candidate_projection_batch(client, plan, &batch.base)?;
    if batch.manifest_profile_id != manifest.profile_id
        || batch.manifest_profile_version != manifest.profile_version
        || batch.manifest_profile_digest != manifest.profile_digest
        || batch.manifest_digest != manifest.manifest_digest
        || batch.data_source_id != batch.base.source_id
        || batch.observations != batch.base.observations
        || !inclusive_within_source(&batch.base.range, &manifest.range)
    {
        return Err(invalid("graph candidate batch"));
    }
    match &batch.template_use {
        GraphTemplateUse::Static => {
            let source = manifest
                .data_sources
                .iter()
                .find(|source| source.data_source_id == batch.data_source_id)
                .ok_or_else(|| invalid("graph data source ownership"))?;
            let handler = manifest
                .handlers
                .iter()
                .find(|handler| {
                    handler.handler_id == batch.handler_id
                        && handler.data_source_id == batch.data_source_id
                })
                .ok_or_else(|| invalid("graph handler ownership"))?;
            let source_range = SourceRangeV1 {
                start: source.start_block,
                end: manifest.range.end,
            };
            if handler.mapping_id != source.mapping_id
                || !inclusive_within_source(&batch.base.range, &source_range)
            {
                return Err(invalid("graph candidate batch"));
            }
            Ok(())
        }
        GraphTemplateUse::Dynamic {
            template_id,
            creation_binding,
            creation_anchor,
        } => {
            let mut templates = manifest
                .dynamic_templates
                .iter()
                .filter(|template| template.template_id == *template_id);
            let template = templates
                .next()
                .ok_or_else(|| invalid("graph dynamic template"))?;
            if templates.next().is_some() {
                return Err(invalid("graph dynamic template"));
            }
            let mut mappings = manifest
                .mappings
                .iter()
                .filter(|mapping| mapping.mapping_id == template.mapping_id);
            let mapping = mappings
                .next()
                .ok_or_else(|| invalid("graph dynamic template"))?;
            if mappings.next().is_some() {
                return Err(invalid("graph dynamic template"));
            }
            let mut sources = manifest.data_sources.iter().filter(|source| {
                source.data_source_id == mapping.data_source_id
                    && source.mapping_id == mapping.mapping_id
            });
            let prototype_source = sources
                .next()
                .ok_or_else(|| invalid("graph dynamic template"))?;
            if sources.next().is_some() {
                return Err(invalid("graph dynamic template"));
            }
            let mut handlers = manifest.handlers.iter().filter(|handler| {
                handler.handler_id == batch.handler_id
                    && handler.data_source_id == prototype_source.data_source_id
                    && handler.mapping_id == mapping.mapping_id
            });
            let handler = handlers
                .next()
                .ok_or_else(|| invalid("graph dynamic template"))?;
            if handlers.next().is_some()
                || handler.mapping_id != template.mapping_id
                || template.creation_binding != *creation_binding
                || !batch.base.evidence_refs.contains(creation_binding)
                || manifest
                    .data_sources
                    .iter()
                    .any(|source| source.data_source_id == batch.data_source_id)
                || plan
                    .partitions
                    .iter()
                    .filter(|partition| {
                        partition.source_id == batch.data_source_id
                            && inclusive_within_source(&batch.base.range, &partition.range)
                    })
                    .count()
                    != 1
                || validate_chain_anchor(creation_anchor).is_err()
                || creation_anchor.chain_id != client.chain_id
                || creation_anchor.genesis_hash != client.genesis_hash
                || creation_anchor.network_id != client.network_id
                || !creation_anchor.block_number.is_some_and(|block| {
                    block >= manifest.range.start
                        && block >= prototype_source.start_block
                        && block < batch.base.range.start
                })
            {
                return Err(invalid("graph dynamic template"));
            }
            Ok(())
        }
    }
}

fn method_matches_handler(method: &MethodDataClass, kind: GraphHandlerKind) -> bool {
    match kind {
        GraphHandlerKind::Event => {
            method.method == "eth_getLogs" && method.data_class == "EVENT_LOG"
        }
        GraphHandlerKind::Call => method.method == "eth_call" && method.data_class == "STATE_CALL",
        GraphHandlerKind::Block => matches!(
            (method.method.as_str(), method.data_class.as_str()),
            ("eth_getBlockByNumber(false)", "BLOCK_HEADER")
                | ("eth_getBlockByNumber(true)", "FULL_BLOCK_TRANSACTIONS")
        ),
    }
}

fn referenced_digest(value: &TheGraphManifestProfileV1, digest: &str) -> bool {
    !digest.is_empty()
        && value
            .referenced_files
            .iter()
            .filter(|file| file.digest == digest)
            .count()
            == 1
}

fn immutable_declared_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains("://")
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn canonical_ids<'a>(values: impl Iterator<Item = &'a String>) -> bool {
    let values = values.collect::<Vec<_>>();
    !values.is_empty()
        && values
            .windows(2)
            .all(|pair| !pair[0].is_empty() && pair[0].as_bytes() < pair[1].as_bytes())
        && values.last().is_some_and(|value| !value.is_empty())
}
