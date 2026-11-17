//! Non-production inputs for the public source publication journey. This only
//! edits configuration bytes; qualification and validation still require their
//! authenticated public operations. It creates no fact/conformance authority.
use super::*;
use openpc_indexer_adapter::{
    AcquisitionConfiguration, AcquisitionRequest, FinalityMode, FinalityRule,
};
use pc_provider_api::{
    decode_client_indexer_profile_pc_cbor, decode_projection_plan_pc_cbor,
    decode_provider_profile_pc_cbor,
};

pub struct AcquisitionFixtureOptions {
    pub generation: u64,
    pub confirmation_count: u32,
    pub state_candidates: bool,
}

/// Prepare the local balance-read fixture from an existing public contract
/// binding and ABI readback. The resulting bytes must still pass governance;
/// this helper neither changes Control rows nor confers admission authority.
pub fn bind_state_contract(
    fixture: &mut serde_json::Value,
    binding: &serde_json::Value,
) -> Result<(), String> {
    let text = |key| {
        binding
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "source contract fixture field missing".to_owned())
    };
    let decode = |value: &str| -> Result<Vec<u8>, String> {
        if value.is_empty()
            || value.len() > 262_144
            || !value.len().is_multiple_of(2)
            || !value.bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err("source contract fixture encoding rejected".into());
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "fixture hex")?, 16)
                    .map_err(|_| "fixture hex".to_owned())
            })
            .collect()
    };
    let bytes = decode(
        fixture["configurationCborHex"]
            .as_str()
            .ok_or("source fixture missing")?,
    )?;
    let mut configuration =
        openpc_pds::decode_active_invocation_configuration(&bytes, &Digest::of(&bytes))
            .map_err(|_| "source configuration rejected")?;
    if configuration.assets.len() != 1
        || [
            "proxy_address",
            "implementation_address",
            "implementation_code_digest",
        ]
        .iter()
        .any(|key| binding.get(key) != Some(&serde_json::Value::Null))
    {
        return Err("source contract fixture requires one direct bound asset".into());
    }
    let runtime_binding_id = text("runtime_binding_id")?;
    if uuid::Uuid::parse_str(runtime_binding_id)
        .map_err(|_| "source binding ID")?
        .get_version_num()
        != 7
    {
        return Err("source binding ID".into());
    }
    let abi_bytes = decode(text("canonical_abi_hex")?)?;
    let abi_digest = Digest::parse(
        text("abi_digest")?
            .strip_prefix("sha256:")
            .ok_or("source ABI digest")?,
    )
    .map_err(|_| "source ABI digest")?;
    if Digest::of(&abi_bytes) != abi_digest {
        return Err("source ABI bytes mismatch".into());
    }
    let abi = serde_json::from_slice(&abi_bytes).map_err(|_| "source ABI rejected")?;
    let selector = [0x70, 0xa0, 0x82, 0x31];
    let (input_types, _) =
        pc_policy_core::contract_policy::read_method_types(&abi, "balanceOf(address)", &selector)
            .map_err(|_| "source read method absent from registered ABI")?;
    let asset = &mut configuration.assets[0];
    asset.asset_id = text("logical_contract_id")?.into();
    asset.runtime_binding_id = Some(runtime_binding_id.into());
    asset.chain_id = text("chain_id")?.into();
    asset.network_id = text("network_id")?.into();
    asset.genesis_digest = Digest::parse(
        text("genesis_digest")?
            .strip_prefix("sha256:")
            .ok_or("source genesis digest")?,
    )
    .map_err(|_| "source genesis digest")?;
    asset.code_digest = Digest::parse(
        text("code_digest")?
            .strip_prefix("sha256:")
            .ok_or("source code digest")?,
    )
    .map_err(|_| "source code digest")?;
    asset.contract_address = decode(
        text("contract_address")?
            .strip_prefix("0x")
            .ok_or("source address")?,
    )?
    .try_into()
    .map_err(|_| "source address")?;
    asset.abi_digest = abi_digest;
    asset.canonical_signature = "balanceOf(address)".into();
    asset.selector = selector;
    asset.input_types = input_types;
    let bytes = encode_active_invocation_configuration(&configuration)
        .map_err(|_| "source fixture encoding rejected")?;
    fixture["configurationCborHex"] = serde_json::Value::String(hex(&bytes));
    fixture["configurationDigest"] = serde_json::Value::String(prefixed(&Digest::of(&bytes)));
    Ok(())
}

pub fn acquisition_input(
    bytes: &[u8],
    source_id: &str,
    projection_id: &str,
    provider_id: &str,
    mut acquisition: AcquisitionConfiguration,
    options: AcquisitionFixtureOptions,
) -> Result<serde_json::Value, String> {
    let mut configuration =
        openpc_pds::decode_active_invocation_configuration(bytes, &Digest::of(bytes))
            .map_err(|_| "source fixture configuration invalid")?;
    let provider = configuration
        .resource_artifacts
        .iter_mut()
        .find(|artifact| {
            artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                && artifact.artifact_id == provider_id
        })
        .ok_or("source fixture provider missing")?;
    let mut provider_profile = decode_provider_profile_pc_cbor(&provider.payload_cbor)
        .map_err(|_| "source fixture provider invalid")?;
    if options.state_candidates
        && !matches!(acquisition.request, AcquisitionRequest::StateCall { .. })
    {
        for pair in [
            MethodDataClass {
                method: acquisition.request.method().into(),
                data_class: acquisition.request.data_class().into(),
            },
            MethodDataClass {
                method: "eth_getBlockByNumber(false)".into(),
                data_class: "BLOCK_HEADER".into(),
            },
            MethodDataClass {
                method: "eth_getCode".into(),
                data_class: "STATE_CALL".into(),
            },
        ] {
            if !provider_profile.method_data_classes.contains(&pair) {
                provider_profile.method_data_classes.push(pair);
            }
        }
        if matches!(acquisition.request, AcquisitionRequest::EventLogs { .. }) {
            let pair = MethodDataClass {
                method: "eth_getTransactionReceipt".into(),
                data_class: "RECEIPT".into(),
            };
            if !provider_profile.method_data_classes.contains(&pair) {
                provider_profile.method_data_classes.push(pair);
            }
        }
        provider_profile
            .method_data_classes
            .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));
    }
    if let Some(rate) = &acquisition.rate_limit {
        provider_profile.rate_limit_contract_digest =
            rate.digest().map_err(|_| "source fixture rate rejected")?;
        provider.payload_cbor = pc_provider_api::encode_provider_profile_pc_cbor(&provider_profile)
            .map_err(|_| "source fixture provider encoding invalid")?;
        provider.artifact_digest = Digest::of(&provider.payload_cbor);
    }
    provider.payload_cbor = pc_provider_api::encode_provider_profile_pc_cbor(&provider_profile)
        .map_err(|_| "source fixture provider encoding invalid")?;
    provider.artifact_digest = Digest::of(&provider.payload_cbor);
    let provider_digest = prefixed(&provider.artifact_digest);
    if let AcquisitionRequest::ExternalDecision {
        provider_id: id,
        provider_version,
        provider_configuration_digest,
        ..
    } = &mut acquisition.request
    {
        *id = provider_id.into();
        *provider_version = provider_profile.profile_version.clone();
        *provider_configuration_digest = provider_digest.clone();
    }
    let finality = FinalityRule {
        rule_id: "urn:openpc:finality-rule:018f0000-0000-7000-8000-000000000919".into(),
        receipt_digest: format!(
            "sha256:{}",
            digest("unadmitted-local-source-finality-receipt")
        ),
        mode: FinalityMode::Confirmations {
            count: options.confirmation_count,
        },
        canonical_provider_digests: vec![prefixed(&provider.artifact_digest)],
        required_observations: 1,
    };
    let finality_cbor = finality
        .encode()
        .map_err(|_| "source fixture finality invalid")?;
    let acquisition_cbor = acquisition
        .encode()
        .map_err(|_| "source fixture acquisition invalid")?;
    let asset = configuration
        .assets
        .first()
        .ok_or("source fixture workload missing")?;
    let workload = pc_policy_core::invocation::active_invocation_workload(
        bytes,
        &Digest::of(bytes),
        &asset.tenant_id,
        &asset.privacy_domain_id,
    )
    .map_err(|_| "source fixture workload invalid")?;
    let source = configuration
        .resource_artifacts
        .iter_mut()
        .find(|artifact| {
            artifact.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
                && artifact.artifact_id == source_id
        })
        .ok_or("source fixture source missing")?;
    let mut profile = decode_client_indexer_profile_pc_cbor(&source.payload_cbor)
        .map_err(|_| "source fixture profile invalid")?;
    profile.workload_binding = workload;
    profile.chain_id = provider_profile.chain_id;
    profile.genesis_hash = provider_profile.genesis_hash;
    profile.network_id = provider_profile.network_id;
    profile.configuration_digest = prefixed(&Digest::of(&acquisition_cbor));
    profile.finality_rule_digest = prefixed(&Digest::of(&finality_cbor));
    if acquisition.rate_limit.is_some() {
        profile.limits.rate_limit_contract_digest = provider_profile.rate_limit_contract_digest;
    }
    profile.method_data_classes = vec![MethodDataClass {
        method: acquisition.request.method().into(),
        data_class: acquisition.request.data_class().into(),
    }];
    if options.state_candidates {
        profile.method_data_classes.push(MethodDataClass {
            method: "eth_getBlockByNumber(false)".into(),
            data_class: "BLOCK_HEADER".into(),
        });
        profile
            .method_data_classes
            .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));
        // This test stream starts at the corpus block. Its policy separately
        // bounds released data/header reads; an open partition can advance its
        // completed watermark without claiming that the stream has ended.
        let pc_provider_api::RangeEndV1::Inclusive(last) = profile.source_range.end else {
            return Err("candidate fixture requires a closed source range".into());
        };
        profile.source_range.start = last;
        profile.source_range.end = pc_provider_api::RangeEndV1::Open;
    }
    source.payload_cbor = encode_client_indexer_profile_pc_cbor(&profile)
        .map_err(|_| "source fixture profile encoding invalid")?;
    source.artifact_digest = Digest::of(&source.payload_cbor);
    let mut source_digest = prefixed(&source.artifact_digest);
    let projection = configuration
        .resource_artifacts
        .iter_mut()
        .find(|artifact| {
            artifact.artifact_kind == ConfigurationArtifactKind::ProjectionPlan
                && artifact.artifact_id == projection_id
        })
        .ok_or("source fixture projection missing")?;
    let mut plan = decode_projection_plan_pc_cbor(&projection.payload_cbor)
        .map_err(|_| "source fixture projection invalid")?;
    plan.lifecycle_generation = options.generation;
    plan.finality_rule_digest = profile.finality_rule_digest.clone();
    plan.limits.rate_limit_contract_digest = profile.limits.rate_limit_contract_digest.clone();
    // The old local fixture used a display label with hyphens. The installed
    // candidate fact-type column requires its canonical dotted identifier.
    for schema in &mut plan.candidate_schema_digests {
        schema.name = schema.name.replace('-', ".");
    }
    if let AcquisitionRequest::EventLogs { event_name, .. } = &acquisition.request {
        plan.extractor_digests[0].name = event_name.clone();
    }
    if options.state_candidates {
        plan.source_range = profile.source_range.clone();
        let (schema, extractor) = match &acquisition.request {
            AcquisitionRequest::StateCall { .. } => (
                openpc_indexer_adapter::acquisition::state_result_schema(),
                openpc_indexer_adapter::acquisition::state_result_extractor(),
            ),
            AcquisitionRequest::ExternalDecision { .. } => (
                openpc_indexer_adapter::acquisition::external_schema(),
                openpc_indexer_adapter::acquisition::external_extractor(),
            ),
            AcquisitionRequest::EventLogs { .. } => (
                openpc_indexer_adapter::acquisition::relationship_schema(),
                openpc_indexer_adapter::acquisition::relationship_extractor(),
            ),
        };
        plan.candidate_schema_digests = vec![schema];
        plan.extractor_digests = vec![extractor];
        for partition in &mut plan.partitions {
            partition.range.start = profile.source_range.start;
            partition.range.end = pc_provider_api::RangeEndV1::Open;
        }
    }
    for partition in &mut plan.partitions {
        partition.finality_digest = profile.finality_rule_digest.clone();
    }
    pc_provider_api::validate_projection_plan(&profile, &plan)
        .map_err(|_| "source fixture plan rejected")?;
    projection.payload_cbor = encode_projection_plan_pc_cbor(&plan)
        .map_err(|_| "source fixture plan encoding invalid")?;
    projection.artifact_digest = Digest::of(&projection.payload_cbor);
    let projection_digest = prefixed(&projection.artifact_digest);
    configuration.resource_artifacts.retain(|artifact| {
        artifact.artifact_id != source_id
            || !matches!(
                artifact.artifact_kind,
                ConfigurationArtifactKind::IndexerFinalityRule
                    | ConfigurationArtifactKind::IndexerAcquisitionConfiguration
            )
    });
    for (kind, payload) in [
        (
            ConfigurationArtifactKind::IndexerFinalityRule,
            finality_cbor,
        ),
        (
            ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
            acquisition_cbor,
        ),
    ] {
        configuration
            .resource_artifacts
            .push(ConfigurationArtifactV1 {
                artifact_id: source_id.into(),
                artifact_kind: kind,
                artifact_digest: Digest::of(&payload),
                payload_cbor: payload,
            });
    }
    if options.state_candidates {
        use pc_policy_core::fact_profile::{StateFactMapping, StateFactProfile};
        configuration.resource_artifacts.retain(|artifact| {
            artifact.artifact_kind != ConfigurationArtifactKind::FactAdmissionProfile
                || artifact.artifact_id != projection_id
        });
        // Explicit local qualification values, carried through the actual
        // configuration approval/publication. These are not runtime defaults.
        let admission = StateFactProfile {
            schema_version: "1.0.0".into(),
            fact_profile_id: uuid::Uuid::now_v7().to_string(),
            fact_semantic_version: "1.0.0".into(),
            admission_policy_version: "1.0.0".into(),
            participant_id: profile.participant_binding.clone(),
            privacy_domain_id: profile.privacy_binding.clone(),
            source_profile_id: source_id.into(),
            projection_plan_id: projection_id.into(),
            projection_plan_digest: Digest::parse(
                projection_digest
                    .strip_prefix("sha256:")
                    .ok_or("fact plan digest")?,
            )
            .map_err(|_| "fact plan digest")?,
            mapping: match &acquisition.request {
                AcquisitionRequest::StateCall { .. } => StateFactMapping::AbiStateResultV1,
                AcquisitionRequest::ExternalDecision {
                    provider_id,
                    provider_version,
                    provider_configuration_digest,
                    condition,
                    ..
                } => StateFactMapping::ExternalDecisionAdapterV1 {
                    provider_id: provider_id.clone(),
                    provider_version: provider_version.clone(),
                    provider_configuration_digest: Digest::parse(
                        provider_configuration_digest.trim_start_matches("sha256:"),
                    )
                    .map_err(|_| "external fixture profile digest")?,
                    condition: condition.clone(),
                },
                AcquisitionRequest::EventLogs { .. } => StateFactMapping::RgraEventRelationshipV1 {
                    namespace: "local.relationship".into(),
                    relationship_kind: "membership".into(),
                    role_predicates: vec!["member".into()],
                },
            },
            maximum_staleness_ms: 60_000,
            reorg_retained_tail_blocks: 64,
            shard_entry_limit: 1_000_000,
        };
        let artifact = admission.artifact().map_err(|_| "fact profile rejected")?;
        // Changing a bound requires a new governed indexer-profile digest;
        // replacing only this local input cannot alter admission meaning.
        profile
            .artifact_digests
            .retain(|entry| entry.name != "fact-admission-profile");
        profile
            .artifact_digests
            .push(pc_provider_api::NamedDigestV1 {
                name: "fact-admission-profile".into(),
                digest: prefixed(&artifact.artifact_digest),
            });
        profile.artifact_digests.sort_by(|a, b| a.name.cmp(&b.name));
        let source = configuration
            .resource_artifacts
            .iter_mut()
            .find(|a| {
                a.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
                    && a.artifact_id == source_id
            })
            .ok_or("fact source missing")?;
        source.payload_cbor =
            encode_client_indexer_profile_pc_cbor(&profile).map_err(|_| "fact source encoding")?;
        source.artifact_digest = Digest::of(&source.payload_cbor);
        source_digest = prefixed(&source.artifact_digest);
        configuration.resource_artifacts.push(artifact);
    }
    let bytes = encode_active_invocation_configuration(&configuration)
        .map_err(|_| "source fixture configuration encoding invalid")?;
    Ok(serde_json::json!({
        "configurationCborHex":hex(&bytes),"configurationDigest":prefixed(&Digest::of(&bytes)),
        "indexerArtifactDigest":source_digest,"projectionArtifactDigest":projection_digest,
        "providerArtifactDigest":provider_digest,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_source_fixture_orders_event_and_header_methods() {
        let provider = "018f0000-0000-7000-8000-000000000901";
        let source = "018f0000-0000-7000-8000-000000000902";
        let projection = "018f0000-0000-7000-8000-000000000903";
        let fixture = super::super::build_local_configuration_fixture(
            Some(provider),
            Some(source),
            Some(projection),
            Some("018f0000-0000-7000-8000-000000000191"),
        )
        .unwrap();
        let bytes: Vec<u8> = fixture
            .configuration_cbor_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let input = AcquisitionConfiguration {
            runtime_target_id: "018f0000-0000-7000-8000-000000000919".into(),
            request: AcquisitionRequest::EventLogs {
                contract_address: format!("0x{}", "11".repeat(20)),
                event_name: openpc_indexer_adapter::acquisition::RGRA_EVENT_NAME.into(),
                event_signature: openpc_indexer_adapter::acquisition::RGRA_EVENT_SIGNATURE.into(),
            },
            rate_limit: None,
        };
        let result = acquisition_input(
            &bytes,
            source,
            projection,
            provider,
            input,
            AcquisitionFixtureOptions {
                generation: 2,
                confirmation_count: 2,
                state_candidates: true,
            },
        )
        .unwrap();
        assert!(result["configurationCborHex"].as_str().is_some());
        assert_ne!(result["configurationDigest"], fixture.configuration_digest);
    }
}
