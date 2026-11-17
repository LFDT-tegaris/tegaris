use super::super::*;
use serde::Deserialize;
use serde::de::value::{Error as ValueError, MapDeserializer};
fn named(name: &str) -> NamedDigestV1 {
    NamedDigestV1 {
        name: name.into(),
        digest: format!("{name}-digest"),
    }
}

fn source_range() -> SourceRangeV1 {
    SourceRangeV1 {
        start: 1,
        end: RangeEndV1::Inclusive(10),
    }
}
fn inclusive_range() -> InclusiveRangeV1 {
    InclusiveRangeV1 { start: 1, end: 10 }
}
fn anchor() -> ChainReadAnchorV1 {
    ChainReadAnchorV1 {
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(10),
        block_hash: Some("block-10".into()),
        pending_authorized_by_profile: false,
    }
}
fn method() -> MethodDataClass {
    MethodDataClass {
        method: "eth_call".into(),
        data_class: "STATE_CALL".into(),
    }
}
fn limits() -> IndexerLimitsV1 {
    IndexerLimitsV1 {
        max_request_bytes: 1,
        max_range: 10,
        max_batch: 1,
        max_response_bytes: 1,
        max_depth: 1,
        max_resource: 1,
        rate_limit_contract_digest: "rate".into(),
    }
}

fn client_indexer() -> ClientIndexerProfileV1 {
    ClientIndexerProfileV1 {
        profile_id: "client".into(),
        profile_version: "1".into(),
        profile_digest: "client-digest".into(),
        client_family: ClientIndexerFamily::SubQueryEvmJsonRpc,
        engine_or_runtime: "runtime".into(),
        engine_version: "1".into(),
        dependencies: vec![DependencyV1 {
            name: "dep".into(),
            version: "1".into(),
            digest: "dep-digest".into(),
        }],
        configuration_digest: "config".into(),
        participant_binding: "participant".into(),
        privacy_binding: "privacy".into(),
        workload_binding: "workload".into(),
        deployment_owner: "owner".into(),
        boundary_declaration_digest: "boundary".into(),
        protocol_kind: IndexerProtocolKind::JsonRpc,
        protocol_version: "2".into(),
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        capability_profiles: vec![IndexerCapability::ProjectSessionCore],
        method_data_classes: vec![method()],
        source_range: source_range(),
        finality_rule_digest: "finality".into(),
        reorg_behavior_digest: "reorg".into(),
        removed_event_behavior_digest: "removed".into(),
        checkpoint_semantics_digest: "checkpoint".into(),
        completed_watermark_semantics_digest: "watermark".into(),
        artifact_digests: vec![named("abi")],
        limits: limits(),
        behavior: IndexerBehaviorV1 {
            visibility_miss_digest: "miss".into(),
            empty_digest: "empty".into(),
            partial_digest: "partial".into(),
            error_digest: "error".into(),
            retry_digest: "retry".into(),
            recovery_digest: "recovery".into(),
            retirement_digest: "retire".into(),
        },
        candidate_store_contract_digest: "candidate".into(),
        outbox_contract_digest: "outbox".into(),
        fact_bridge_contract_digest: "bridge".into(),
        security_evidence_digest: "security".into(),
        privacy_evidence_digest: "privacy-evidence".into(),
        licensing_digest: "license".into(),
        supply_chain_digest: "supply".into(),
        telemetry_classification_digest: "telemetry".into(),
        rollback_digest: "rollback".into(),
        uninstall_digest: "uninstall".into(),
        corpus_digest: "corpus".into(),
        conformance_receipt_digest: "receipt".into(),
        lifecycle: ClientIndexerLifecycle::Active,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

fn projection_plan() -> ProjectionPlanV1 {
    ProjectionPlanV1 {
        profile_id: "client".into(),
        profile_version: "1".into(),
        profile_digest: "client-digest".into(),
        plan_digest: "plan".into(),
        workload_identity: WorkloadIdentityV1::ImageBuild {
            image_digest: "image".into(),
            build_digest: "build".into(),
            sbom_digest: "sbom".into(),
            provenance_digest: "provenance".into(),
        },
        partitions: vec![ProjectionPartitionV1 {
            partition_id: "partition".into(),
            source_id: "datasource".into(),
            range: source_range(),
            state: PartitionState::Complete,
            finality_digest: "finality".into(),
            checkpoint_digest: "checkpoint".into(),
        }],
        source_range: source_range(),
        finality_rule_digest: "finality".into(),
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

fn candidate_batch() -> CandidateProjectionBatchV1 {
    CandidateProjectionBatchV1 {
        profile_id: "client".into(),
        profile_version: "1".into(),
        profile_digest: "client-digest".into(),
        plan_digest: "plan".into(),
        source_id: "datasource".into(),
        source_profile_digest: "client-digest".into(),
        partition_id: "partition".into(),
        batch_id: "batch".into(),
        batch_sequence: 1,
        range: inclusive_range(),
        observations: vec![SequencedObservationV1 {
            sequence: 1,
            anchor: anchor(),
            normalized_digest: "11".repeat(32),
            evidence_digest: "22".repeat(32),
        }],
        records: vec![CandidateRecordV1 {
            sequence: 1,
            record_id: "record".into(),
            schema_digest: "schema".into(),
            normalized_digest: "record-digest".into(),
            block_number: 10,
            canonical_block_hash: "block-10".into(),
            evidence_digest: "record-evidence".into(),
        }],
        decode_failures: vec![],
        missing_intervals: vec![],
        completed_watermark: CompletedWatermarkV1 {
            block_number: 10,
            canonical_block_hash: "block-10".into(),
        },
        predecessor_batch_digest: "GENESIS".into(),
        evidence_refs: vec!["batch-evidence".into()],
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

fn subquery_profile() -> SubQueryClientProfileV1 {
    let dependency = |name: &str| DependencyV1 {
        name: name.into(),
        version: "1".into(),
        digest: format!("{name}-digest"),
    };
    SubQueryClientProfileV1 {
        profile_id: "subquery".into(),
        profile_version: "1".into(),
        profile_digest: "subquery-digest".into(),
        client_profile_id: "client".into(),
        client_profile_version: "1".into(),
        client_profile_digest: "client-digest".into(),
        plan_digest: "plan".into(),
        project_id: "project".into(),
        manifest_spec_version: "1".into(),
        manifest_digest: "manifest".into(),
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        runner: dependency("runner"),
        node: dependency("node"),
        query_service: dependency("query"),
        package_manager: dependency("pnpm"),
        dependencies: vec![dependency("dep")],
        data_sources: vec![SubQueryDataSourceV1 {
            data_source_id: "datasource".into(),
            kind: "evm".into(),
            start: 1,
            end: RangeEndV1::Inclusive(10),
            mapping_digest: "mapping-digest".into(),
            asset_digests: vec!["asset-digest".into()],
            abi_digests: vec!["abi-digest".into()],
        }],
        mappings: vec![named("mapping")],
        processors: vec![named("processor")],
        assets: vec![named("asset")],
        handlers: vec![SubQueryHandlerV1 {
            handler_id: "handler".into(),
            data_source_id: "datasource".into(),
            processor_id: "processor".into(),
            filter_id: "filter".into(),
            required_method_data: vec![method()],
        }],
        filters: vec![TypedSelectorV1 {
            field_id: "filter".into(),
            schema_digest: "schema".into(),
            selector_digest: "selector".into(),
        }],
        abi_schema_code_digests: vec![
            NamedDigestV1 {
                name: "abis/erc20.json".into(),
                digest: "abi-digest".into(),
            },
            NamedDigestV1 {
                name: "dist/mapping.js".into(),
                digest: "mapping-digest".into(),
            },
            NamedDigestV1 {
                name: "dist/processor.js".into(),
                digest: "processor-digest".into(),
            },
            NamedDigestV1 {
                name: "schemas/project.graphql".into(),
                digest: "schema-digest".into(),
            },
        ],
        project_schema_digests: vec!["schema-digest".into()],
        data_node_surface: SubQueryDataNodeSurfaceV1::NotDeclared,
        checkpoint_digest: "checkpoint".into(),
        finality_digest: "finality".into(),
        reorg_digest: "reorg".into(),
        limits: limits(),
        privacy_law_digest: "privacy-evidence".into(),
        lifecycle: ClientIndexerLifecycle::Active,
        managed_lifecycle: ManagedSubqueryLifecycle::FutureAbsent,
        current_receipt_digest: "receipt".into(),
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

#[test]
fn manifest_graph_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let profile = subquery_profile();
    assert!(validate_subquery_profile(&client, &plan, &profile).is_ok());
    for mutate in [
        |v: &mut SubQueryClientProfileV1| v.profile_id.clear(),
        |v: &mut SubQueryClientProfileV1| v.profile_version.clear(),
        |v: &mut SubQueryClientProfileV1| v.profile_digest.clear(),
        |v: &mut SubQueryClientProfileV1| v.client_profile_digest = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.plan_digest = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.project_id.clear(),
        |v: &mut SubQueryClientProfileV1| v.manifest_spec_version.clear(),
        |v: &mut SubQueryClientProfileV1| v.manifest_digest.clear(),
        |v: &mut SubQueryClientProfileV1| v.chain_id = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.genesis_hash = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.network_id = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.dependencies.clear(),
        |v: &mut SubQueryClientProfileV1| v.data_sources.clear(),
        |v: &mut SubQueryClientProfileV1| v.mappings.clear(),
        |v: &mut SubQueryClientProfileV1| v.processors.clear(),
        |v: &mut SubQueryClientProfileV1| v.assets.clear(),
        |v: &mut SubQueryClientProfileV1| v.handlers.clear(),
        |v: &mut SubQueryClientProfileV1| v.filters.clear(),
        |v: &mut SubQueryClientProfileV1| v.abi_schema_code_digests.clear(),
    ] {
        let mut drift = profile.clone();
        mutate(&mut drift);
        assert!(validate_subquery_profile(&client, &plan, &drift).is_err());
    }
}

#[test]
fn surface_lifecycle_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let profile = subquery_profile();
    for mutate in [
        |v: &mut SubQueryClientProfileV1| v.checkpoint_digest.clear(),
        |v: &mut SubQueryClientProfileV1| v.finality_digest.clear(),
        |v: &mut SubQueryClientProfileV1| v.reorg_digest.clear(),
        |v: &mut SubQueryClientProfileV1| v.limits.max_range += 1,
        |v: &mut SubQueryClientProfileV1| v.privacy_law_digest = "other".into(),
        |v: &mut SubQueryClientProfileV1| v.lifecycle = ClientIndexerLifecycle::Draft,
        |v: &mut SubQueryClientProfileV1| v.current_receipt_digest.clear(),
    ] {
        let mut drift = profile.clone();
        mutate(&mut drift);
        assert!(validate_subquery_profile(&client, &plan, &drift).is_err());
    }
}

#[test]
fn nested_relations_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let profile = subquery_profile();
    for mutate in [
        |v: &mut SubQueryClientProfileV1| v.data_sources[0].mapping_digest = "missing".into(),
        |v: &mut SubQueryClientProfileV1| v.data_sources[0].start = 0,
        |v: &mut SubQueryClientProfileV1| v.handlers[0].data_source_id = "missing".into(),
        |v: &mut SubQueryClientProfileV1| v.handlers[0].processor_id = "missing".into(),
        |v: &mut SubQueryClientProfileV1| v.handlers[0].filter_id = "missing".into(),
        |v: &mut SubQueryClientProfileV1| {
            v.handlers[0].required_method_data[0].method = "other".into()
        },
    ] {
        let mut drift = profile.clone();
        mutate(&mut drift);
        assert!(validate_subquery_profile(&client, &plan, &drift).is_err());
    }
}

#[test]
fn content_reference_graph_accepts() {
    fn assert_wire<T: serde::Serialize + serde::de::DeserializeOwned + Eq + PartialEq>() {}
    assert_wire::<SubQueryClientProfileV1>();
    assert_wire::<SubQueryDataSourceV1>();
    let client = client_indexer();
    let plan = projection_plan();
    let base = subquery_profile();
    assert_eq!(validate_subquery_profile(&client, &plan, &base), Ok(()));
    for (project_schema_digests, reason) in [
        (vec![], "subquery project schema"),
        (vec!["missing".into()], "subquery project schema reference"),
        (vec!["z".into(), "a".into()], "subquery project schema"),
        (
            vec!["schema-digest".into(), "schema-digest".into()],
            "subquery project schema",
        ),
    ] {
        let mut drift = base.clone();
        let before = drift.project_schema_digests.clone();
        drift.project_schema_digests = project_schema_digests;
        assert_ne!(drift.project_schema_digests, before);
        assert_eq!(
            validate_subquery_profile(&client, &plan, &drift),
            Err(ProviderContractError::Invalid(reason))
        );
    }
    for (asset_digests, reason) in [
        (vec!["missing".into()], "subquery source content reference"),
        (
            vec!["asset-digest".into(), "asset-digest".into()],
            "subquery source content references",
        ),
        (
            vec!["z".into(), "a".into()],
            "subquery source content references",
        ),
        (vec!["".into()], "subquery source content references"),
    ] {
        let mut drift = base.clone();
        let before = drift.data_sources[0].asset_digests.clone();
        drift.data_sources[0].asset_digests = asset_digests;
        assert_ne!(drift.data_sources[0].asset_digests, before);
        assert_eq!(
            validate_subquery_profile(&client, &plan, &drift),
            Err(ProviderContractError::Invalid(reason))
        );
    }
    for (abi_digests, reason) in [
        (vec!["missing".into()], "subquery source content reference"),
        (
            vec!["abi-digest".into(), "abi-digest".into()],
            "subquery source content references",
        ),
        (
            vec!["z".into(), "a".into()],
            "subquery source content references",
        ),
        (vec!["".into()], "subquery source content references"),
    ] {
        let mut drift = base.clone();
        let before = drift.data_sources[0].abi_digests.clone();
        drift.data_sources[0].abi_digests = abi_digests;
        assert_ne!(drift.data_sources[0].abi_digests, before);
        assert_eq!(
            validate_subquery_profile(&client, &plan, &drift),
            Err(ProviderContractError::Invalid(reason))
        );
    }

    let mut drift = base.clone();
    let before = drift.abi_schema_code_digests[1].digest.clone();
    drift.abi_schema_code_digests[1].digest = "missing-mapping-code".into();
    assert_ne!(drift.abi_schema_code_digests[1].digest, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery executable content reference"
        ))
    );
    let mut drift = base.clone();
    let before = drift.abi_schema_code_digests[2].digest.clone();
    drift.abi_schema_code_digests[2].digest = "missing-processor-code".into();
    assert_ne!(drift.abi_schema_code_digests[2].digest, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery executable content reference"
        ))
    );
    let mut drift = base.clone();
    let before = drift.abi_schema_code_digests[1].digest.clone();
    drift.abi_schema_code_digests[1].digest = "abi-digest".into();
    assert_ne!(drift.abi_schema_code_digests[1].digest, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery content catalog uniqueness"
        ))
    );
    let mut drift = base.clone();
    let before = drift.mappings.clone();
    drift.mappings.push(NamedDigestV1 {
        name: "z-duplicate".into(),
        digest: "mapping-digest".into(),
    });
    assert_ne!(drift.mappings, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery content catalog uniqueness"
        ))
    );
    let mut drift = base.clone();
    let before = drift.processors.clone();
    drift.processors.push(NamedDigestV1 {
        name: "z-duplicate".into(),
        digest: "processor-digest".into(),
    });
    assert_ne!(drift.processors, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery content catalog uniqueness"
        ))
    );
    let mut drift = base.clone();
    let before = drift.assets.clone();
    drift.assets.push(NamedDigestV1 {
        name: "z-duplicate".into(),
        digest: "asset-digest".into(),
    });
    assert_ne!(drift.assets, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &drift),
        Err(ProviderContractError::Invalid(
            "subquery content catalog uniqueness"
        ))
    );
}

#[test]
fn content_orphan_policy_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let base = subquery_profile();
    let expected = Err(ProviderContractError::Invalid(
        "subquery orphan declaration",
    ));
    let mut drift = base.clone();
    let before = drift.mappings.clone();
    drift.mappings.push(NamedDigestV1 {
        name: "orphan".into(),
        digest: "abi-digest".into(),
    });
    assert_ne!(drift.mappings, before);
    assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
    let mut drift = base.clone();
    let before = drift.processors.clone();
    drift.processors.push(NamedDigestV1 {
        name: "z-orphan".into(),
        digest: "abi-digest".into(),
    });
    assert_ne!(drift.processors, before);
    assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
    let mut drift = base.clone();
    let before = drift.filters.clone();
    drift.filters.push(TypedSelectorV1 {
        field_id: "z-orphan".into(),
        schema_digest: "schema".into(),
        selector_digest: "selector-orphan".into(),
    });
    assert_ne!(drift.filters, before);
    assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
    let mut drift = base.clone();
    let before = drift.assets.clone();
    drift.assets.push(NamedDigestV1 {
        name: "z-orphan".into(),
        digest: "orphan-asset-digest".into(),
    });
    assert_ne!(drift.assets, before);
    assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
    let mut drift = base.clone();
    let before = drift.abi_schema_code_digests.clone();
    drift.abi_schema_code_digests.push(NamedDigestV1 {
        name: "z-orphan".into(),
        digest: "orphan-content-digest".into(),
    });
    assert_ne!(drift.abi_schema_code_digests, before);
    assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
}

#[test]
fn optional_and_shared_content_ownership_accepts() {
    let client = client_indexer();
    let mut plan = projection_plan();
    let mut no_assets = subquery_profile();
    let before_assets = no_assets.assets.clone();
    let before_source_assets = no_assets.data_sources[0].asset_digests.clone();
    no_assets.assets.clear();
    no_assets.data_sources[0].asset_digests.clear();
    assert_ne!(no_assets.assets, before_assets);
    assert_ne!(
        no_assets.data_sources[0].asset_digests,
        before_source_assets
    );
    assert_eq!(
        validate_subquery_profile(&client, &plan, &no_assets),
        Ok(())
    );

    let before_partitions = plan.partitions.clone();
    plan.partitions[0].range.end = RangeEndV1::Inclusive(5);
    plan.partitions.push(ProjectionPartitionV1 {
        partition_id: "partition-2".into(),
        source_id: "datasource-2".into(),
        range: SourceRangeV1 {
            start: 6,
            end: RangeEndV1::Inclusive(10),
        },
        state: PartitionState::Complete,
        finality_digest: "finality".into(),
        checkpoint_digest: "checkpoint-2".into(),
    });
    assert_ne!(plan.partitions, before_partitions);
    let mut shared = subquery_profile();
    let before_data_sources = shared.data_sources.clone();
    let before_handlers = shared.handlers.clone();
    shared.data_sources[0].end = RangeEndV1::Inclusive(5);
    shared.data_sources.push(SubQueryDataSourceV1 {
        data_source_id: "datasource-2".into(),
        kind: "evm".into(),
        start: 6,
        end: RangeEndV1::Inclusive(10),
        mapping_digest: "mapping-digest".into(),
        asset_digests: vec!["asset-digest".into()],
        abi_digests: vec!["abi-digest".into()],
    });
    assert_ne!(shared.data_sources, before_data_sources);
    shared.handlers.push(SubQueryHandlerV1 {
        handler_id: "handler-2".into(),
        data_source_id: "datasource-2".into(),
        processor_id: "processor".into(),
        filter_id: "filter".into(),
        required_method_data: vec![method()],
    });
    assert_ne!(shared.handlers, before_handlers);
    assert_eq!(validate_subquery_profile(&client, &plan, &shared), Ok(()));
}

#[test]
fn immutable_content_locators_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut accepted = subquery_profile();
    accepted.assets[0].name = "erc20-abi".into();
    accepted.abi_schema_code_digests[0].name = "abis/erc20.json".into();
    accepted.abi_schema_code_digests[1].name = "dist/index.js".into();
    accepted.abi_schema_code_digests[3].name = "schemas/project.graphql".into();
    assert_eq!(validate_subquery_profile(&client, &plan, &accepted), Ok(()));
    let expected = Err(ProviderContractError::Invalid(
        "subquery immutable content locator",
    ));
    for locator in [
        "",
        "/abis/erc20.json",
        "http://example.test/abi",
        "https://example.test/abi",
        "../abi.json",
        "abis/./erc20.json",
        "abis//erc20.json",
    ] {
        let mut drift = accepted.clone();
        drift.assets[0].name = locator.into();
        assert_ne!(drift.assets[0].name, accepted.assets[0].name);
        assert_eq!(validate_subquery_profile(&client, &plan, &drift), expected);
    }
}

#[test]
fn candidate_batch_relations_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let profile = subquery_profile();
    let batch = subquery_batch();
    assert!(validate_subquery_batch(&client, &plan, &profile, &batch).is_ok());
    for mutate in [
        |v: &mut SubQueryCandidateBatchV1| v.subquery_profile_id = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| v.subquery_profile_version = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| v.subquery_profile_digest = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| v.project_id = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| v.data_source_id = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| v.handler_id = "other".into(),
        |v: &mut SubQueryCandidateBatchV1| {
            v.operation = SubQueryOperationV1::JsonRpc(MethodDataClass {
                method: "other".into(),
                data_class: "STATE_CALL".into(),
            })
        },
        |v: &mut SubQueryCandidateBatchV1| {
            v.base.completed_watermark.canonical_block_hash = "other".into()
        },
    ] {
        let mut drift = batch.clone();
        mutate(&mut drift);
        assert!(validate_subquery_batch(&client, &plan, &profile, &drift).is_err());
    }
}
fn subquery_batch() -> SubQueryCandidateBatchV1 {
    SubQueryCandidateBatchV1 {
        base: candidate_batch(),
        subquery_profile_id: "subquery".into(),
        subquery_profile_version: "1".into(),
        subquery_profile_digest: "subquery-digest".into(),
        project_id: "project".into(),
        data_source_id: "datasource".into(),
        handler_id: "handler".into(),
        operation: SubQueryOperationV1::JsonRpc(method()),
    }
}

#[test]
fn subquery_source_and_batch_ranges_are_closed() {
    let client = client_indexer();
    let plan = projection_plan();
    let profile = subquery_profile();
    let batch = subquery_batch();
    assert_eq!(
        validate_subquery_batch(&client, &plan, &profile, &batch),
        Ok(())
    );

    let mut equality_profile = profile.clone();
    equality_profile.data_sources[0].start = 10;
    equality_profile.data_sources[0].end = RangeEndV1::Inclusive(10);
    let mut equality_batch = batch.clone();
    equality_batch.base.range.start = 10;
    assert_eq!(
        validate_subquery_batch(&client, &plan, &equality_profile, &equality_batch),
        Ok(())
    );

    let mut open_client = client.clone();
    open_client.source_range.end = RangeEndV1::Open;
    let mut open_plan = plan.clone();
    open_plan.source_range.end = RangeEndV1::Open;
    open_plan.partitions[0].range.end = RangeEndV1::Open;
    let mut open_profile = profile.clone();
    open_profile.data_sources[0].end = RangeEndV1::Open;
    assert_eq!(
        validate_subquery_batch(&open_client, &open_plan, &open_profile, &batch),
        Ok(())
    );

    let mut zero_source = profile.clone();
    let before = zero_source.data_sources[0].start;
    zero_source.data_sources[0].start = 0;
    assert_ne!(zero_source.data_sources[0].start, before);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &zero_source),
        Err(ProviderContractError::Invalid("subquery source relation"))
    );

    let mut inverted_source = profile.clone();
    let before = inverted_source.data_sources[0].end;
    inverted_source.data_sources[0].end = RangeEndV1::Inclusive(0);
    assert_ne!(inverted_source.data_sources[0].end, before);
    assert_eq!(inverted_source.data_sources[0].start, 1);
    assert_eq!(
        validate_subquery_profile(&client, &plan, &inverted_source),
        Err(ProviderContractError::Invalid("subquery source relation"))
    );

    let mut narrowed_profile = profile.clone();
    narrowed_profile.data_sources[0].start = 3;
    narrowed_profile.data_sources[0].end = RangeEndV1::Inclusive(9);
    let mut contained_batch = batch.clone();
    contained_batch.base.range.start = 3;
    contained_batch.base.range.end = 9;
    contained_batch.base.records[0].block_number = 9;
    contained_batch.base.records[0].canonical_block_hash = "block-9".into();
    contained_batch.base.observations[0].anchor.block_number = Some(9);
    contained_batch.base.observations[0].anchor.block_hash = Some("block-9".into());
    contained_batch.base.completed_watermark.block_number = 9;
    contained_batch
        .base
        .completed_watermark
        .canonical_block_hash = "block-9".into();
    assert_eq!(
        validate_subquery_batch(&client, &plan, &narrowed_profile, &contained_batch),
        Ok(())
    );

    let mut before_source = contained_batch.clone();
    let before = before_source.base.range.start;
    before_source.base.range.start = 2;
    assert_ne!(before_source.base.range.start, before);
    assert_eq!(
        validate_subquery_batch(&client, &plan, &narrowed_profile, &before_source),
        Err(ProviderContractError::Invalid("subquery candidate batch"))
    );

    let mut after_source = contained_batch;
    let before = after_source.base.range.end;
    after_source.base.range.end = 10;
    assert_ne!(after_source.base.range.end, before);
    assert_eq!(
        validate_subquery_batch(&client, &plan, &narrowed_profile, &after_source),
        Err(ProviderContractError::Invalid("subquery candidate batch"))
    );
}

#[test]
fn subquery_operation_surface_is_closed() {
    let evm_client = client_indexer();
    let plan = projection_plan();
    let evm_profile = subquery_profile();
    let evm_batch = subquery_batch();
    assert_eq!(
        validate_subquery_batch(&evm_client, &plan, &evm_profile, &evm_batch),
        Ok(())
    );

    let mut undeclared_method = evm_batch.clone();
    let before = undeclared_method.operation.clone();
    undeclared_method.operation = SubQueryOperationV1::JsonRpc(MethodDataClass {
        method: "eth_getTransactionReceipt".into(),
        data_class: "RECEIPT".into(),
    });
    assert_ne!(undeclared_method.operation, before);
    assert_eq!(
        validate_subquery_batch(&evm_client, &plan, &evm_profile, &undeclared_method),
        Err(ProviderContractError::Invalid("subquery operation"))
    );

    let mut data_node_client = evm_client.clone();
    data_node_client.client_family = ClientIndexerFamily::SubQueryDataNode;
    data_node_client.protocol_kind = IndexerProtocolKind::Http;
    data_node_client.capability_profiles = vec![IndexerCapability::SubQueryDataNodeProfile];
    let filter_blocks_pair = MethodDataClass {
        method: "subql_filterBlocks".into(),
        data_class: "SUBQUERY_FILTERED_BLOCK".into(),
    };
    let capabilities_pair = MethodDataClass {
        method: "subql_filterBlocksCapabilities".into(),
        data_class: "SUBQUERY_FILTERED_BLOCK".into(),
    };
    data_node_client.method_data_classes =
        vec![filter_blocks_pair.clone(), capabilities_pair.clone()];
    let mut data_node_profile = evm_profile.clone();
    data_node_profile.handlers[0].required_method_data =
        vec![filter_blocks_pair.clone(), capabilities_pair.clone()];
    let selector = data_node_profile.filters[0].clone();
    data_node_profile.data_node_surface = SubQueryDataNodeSurfaceV1::Exact {
        protocol_version: "1".into(),
        schema_version: "1".into(),
        allowed_fields: vec![selector.field_id.clone()],
        allowed_selectors: vec![selector.clone()],
    };
    let mut capabilities = evm_batch.clone();
    capabilities.operation = SubQueryOperationV1::DataNodeCapabilities;
    assert!(
        data_node_client
            .method_data_classes
            .contains(&capabilities_pair)
    );
    assert_eq!(
        validate_subquery_batch(&data_node_client, &plan, &data_node_profile, &capabilities,),
        Ok(())
    );
    let mut filter_blocks = evm_batch.clone();
    filter_blocks.operation = SubQueryOperationV1::DataNodeFilterBlocks(selector.clone());
    assert!(
        data_node_client
            .method_data_classes
            .contains(&filter_blocks_pair)
    );
    assert_eq!(
        validate_subquery_batch(&data_node_client, &plan, &data_node_profile, &filter_blocks,),
        Ok(())
    );

    let mut missing_capabilities_pair = data_node_client.clone();
    let before = missing_capabilities_pair.method_data_classes.clone();
    missing_capabilities_pair
        .method_data_classes
        .retain(|pair| pair != &capabilities_pair);
    assert_ne!(missing_capabilities_pair.method_data_classes, before);
    assert!(
        !missing_capabilities_pair
            .method_data_classes
            .contains(&capabilities_pair)
    );
    let mut missing_capabilities_profile = data_node_profile.clone();
    let handler_before = missing_capabilities_profile.handlers[0]
        .required_method_data
        .clone();
    missing_capabilities_profile.handlers[0].required_method_data =
        missing_capabilities_pair.method_data_classes.clone();
    assert_ne!(
        missing_capabilities_profile.handlers[0].required_method_data,
        handler_before
    );
    assert_eq!(
        validate_subquery_batch(
            &missing_capabilities_pair,
            &plan,
            &missing_capabilities_profile,
            &capabilities,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let mut wrong_capabilities_pair = data_node_client.clone();
    let before = wrong_capabilities_pair.method_data_classes[1]
        .data_class
        .clone();
    wrong_capabilities_pair.method_data_classes[1].data_class = "WRONG_CLASS".into();
    assert_ne!(
        wrong_capabilities_pair.method_data_classes[1].data_class,
        before
    );
    let mut wrong_capabilities_profile = data_node_profile.clone();
    let handler_before = wrong_capabilities_profile.handlers[0]
        .required_method_data
        .clone();
    wrong_capabilities_profile.handlers[0].required_method_data =
        wrong_capabilities_pair.method_data_classes.clone();
    assert_ne!(
        wrong_capabilities_profile.handlers[0].required_method_data,
        handler_before
    );
    assert_eq!(
        validate_subquery_batch(
            &wrong_capabilities_pair,
            &plan,
            &wrong_capabilities_profile,
            &capabilities,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let mut missing_filter_pair = data_node_client.clone();
    let before = missing_filter_pair.method_data_classes.clone();
    missing_filter_pair
        .method_data_classes
        .retain(|pair| pair != &filter_blocks_pair);
    assert_ne!(missing_filter_pair.method_data_classes, before);
    assert!(
        !missing_filter_pair
            .method_data_classes
            .contains(&filter_blocks_pair)
    );
    let mut missing_filter_profile = data_node_profile.clone();
    let handler_before = missing_filter_profile.handlers[0]
        .required_method_data
        .clone();
    missing_filter_profile.handlers[0].required_method_data =
        missing_filter_pair.method_data_classes.clone();
    assert_ne!(
        missing_filter_profile.handlers[0].required_method_data,
        handler_before
    );
    assert_eq!(
        validate_subquery_batch(
            &missing_filter_pair,
            &plan,
            &missing_filter_profile,
            &filter_blocks,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let mut wrong_filter_pair = data_node_client.clone();
    let before = wrong_filter_pair.method_data_classes[0].data_class.clone();
    wrong_filter_pair.method_data_classes[0].data_class = "WRONG_CLASS".into();
    assert_ne!(wrong_filter_pair.method_data_classes[0].data_class, before);
    let mut wrong_filter_profile = data_node_profile.clone();
    let handler_before = wrong_filter_profile.handlers[0]
        .required_method_data
        .clone();
    wrong_filter_profile.handlers[0].required_method_data =
        wrong_filter_pair.method_data_classes.clone();
    assert_ne!(
        wrong_filter_profile.handlers[0].required_method_data,
        handler_before
    );
    assert_eq!(
        validate_subquery_batch(
            &wrong_filter_pair,
            &plan,
            &wrong_filter_profile,
            &filter_blocks,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let crossed_capabilities = missing_capabilities_pair;
    assert!(
        crossed_capabilities
            .method_data_classes
            .contains(&filter_blocks_pair)
    );
    assert_eq!(
        validate_subquery_batch(
            &crossed_capabilities,
            &plan,
            &missing_capabilities_profile,
            &capabilities,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let crossed_filter = missing_filter_pair;
    assert!(
        crossed_filter
            .method_data_classes
            .contains(&capabilities_pair)
    );
    assert_eq!(
        validate_subquery_batch(
            &crossed_filter,
            &plan,
            &missing_filter_profile,
            &filter_blocks,
        ),
        Err(ProviderContractError::Invalid("subquery data node surface"))
    );

    let mut cross_family = evm_batch.clone();
    let before = cross_family.operation.clone();
    cross_family.operation = SubQueryOperationV1::DataNodeCapabilities;
    assert_ne!(cross_family.operation, before);
    assert_eq!(
        validate_subquery_batch(&evm_client, &plan, &evm_profile, &cross_family),
        Err(ProviderContractError::Invalid("subquery operation"))
    );

    let mut data_node_json_rpc = capabilities.clone();
    let before = data_node_json_rpc.operation.clone();
    data_node_json_rpc.operation = SubQueryOperationV1::JsonRpc(method());
    assert_ne!(data_node_json_rpc.operation, before);
    assert_eq!(
        validate_subquery_batch(
            &data_node_client,
            &plan,
            &data_node_profile,
            &data_node_json_rpc,
        ),
        Err(ProviderContractError::Invalid("subquery operation"))
    );

    let mut unknown_selector = filter_blocks;
    let before = unknown_selector.operation.clone();
    unknown_selector.operation = SubQueryOperationV1::DataNodeFilterBlocks(TypedSelectorV1 {
        field_id: "unknown".into(),
        schema_digest: "schema".into(),
        selector_digest: "unknown-selector".into(),
    });
    assert_ne!(unknown_selector.operation, before);
    assert_eq!(
        validate_subquery_batch(
            &data_node_client,
            &plan,
            &data_node_profile,
            &unknown_selector,
        ),
        Err(ProviderContractError::Invalid("subquery operation"))
    );

    for legacy_variant in ["Capability", "Selector"] {
        let legacy = std::iter::once((legacy_variant.to_owned(), "legacy".to_owned()));
        assert!(
            SubQueryOperationV1::deserialize(MapDeserializer::<_, ValueError>::new(legacy))
                .is_err()
        );
    }
}

#[test]
fn data_node_selected_handler_and_surface_are_exact() {
    let mut client = client_indexer();
    client.client_family = ClientIndexerFamily::SubQueryDataNode;
    client.protocol_kind = IndexerProtocolKind::Http;
    client.capability_profiles = vec![IndexerCapability::SubQueryDataNodeProfile];
    let filter_pair = MethodDataClass {
        method: "subql_filterBlocks".into(),
        data_class: "SUBQUERY_FILTERED_BLOCK".into(),
    };
    let capabilities_pair = MethodDataClass {
        method: "subql_filterBlocksCapabilities".into(),
        data_class: "SUBQUERY_FILTERED_BLOCK".into(),
    };
    client.method_data_classes = vec![filter_pair.clone(), capabilities_pair.clone()];
    let plan = projection_plan();
    let mut profile = subquery_profile();
    profile.handlers[0].required_method_data = client.method_data_classes.clone();
    let selector = profile.filters[0].clone();
    profile.data_node_surface = SubQueryDataNodeSurfaceV1::Exact {
        protocol_version: "1".into(),
        schema_version: "1".into(),
        allowed_fields: vec![selector.field_id.clone()],
        allowed_selectors: vec![selector.clone()],
    };
    let mut capabilities = subquery_batch();
    capabilities.operation = SubQueryOperationV1::DataNodeCapabilities;
    let mut filter = subquery_batch();
    filter.operation = SubQueryOperationV1::DataNodeFilterBlocks(selector.clone());
    assert_eq!(
        validate_subquery_batch(&client, &plan, &profile, &capabilities),
        Ok(())
    );
    assert_eq!(
        validate_subquery_batch(&client, &plan, &profile, &filter),
        Ok(())
    );

    let surface_error = Err(ProviderContractError::Invalid("subquery data node surface"));
    let mut extra_method = client.clone();
    let methods_before = extra_method.method_data_classes.clone();
    extra_method.method_data_classes.push(MethodDataClass {
        method: "subql_other".into(),
        data_class: "SUBQUERY_FILTERED_BLOCK".into(),
    });
    assert_ne!(extra_method.method_data_classes, methods_before);
    assert_eq!(
        validate_subquery_batch(&extra_method, &plan, &profile, &capabilities),
        surface_error
    );

    let mut wrong_fields = profile.clone();
    let fields_before = match &wrong_fields.data_node_surface {
        SubQueryDataNodeSurfaceV1::Exact { allowed_fields, .. } => allowed_fields.clone(),
        SubQueryDataNodeSurfaceV1::NotDeclared => unreachable!(),
    };
    if let SubQueryDataNodeSurfaceV1::Exact { allowed_fields, .. } =
        &mut wrong_fields.data_node_surface
    {
        *allowed_fields = vec!["other".into()];
    }
    assert_ne!(
        match &wrong_fields.data_node_surface {
            SubQueryDataNodeSurfaceV1::Exact { allowed_fields, .. } => allowed_fields,
            SubQueryDataNodeSurfaceV1::NotDeclared => unreachable!(),
        },
        &fields_before
    );
    assert_eq!(
        validate_subquery_batch(&client, &plan, &wrong_fields, &capabilities),
        surface_error
    );

    let mut wrong_selectors = profile.clone();
    let selectors_before = match &wrong_selectors.data_node_surface {
        SubQueryDataNodeSurfaceV1::Exact {
            allowed_selectors, ..
        } => allowed_selectors.clone(),
        SubQueryDataNodeSurfaceV1::NotDeclared => unreachable!(),
    };
    if let SubQueryDataNodeSurfaceV1::Exact {
        allowed_selectors, ..
    } = &mut wrong_selectors.data_node_surface
    {
        allowed_selectors[0].selector_digest = "other-selector".into();
    }
    assert_ne!(
        match &wrong_selectors.data_node_surface {
            SubQueryDataNodeSurfaceV1::Exact {
                allowed_selectors, ..
            } => allowed_selectors,
            SubQueryDataNodeSurfaceV1::NotDeclared => unreachable!(),
        },
        &selectors_before
    );
    assert_eq!(
        validate_subquery_batch(&client, &plan, &wrong_selectors, &capabilities),
        surface_error
    );

    let operation_error = Err(ProviderContractError::Invalid("subquery operation"));
    let mut capabilities_not_owned = profile.clone();
    let methods_before = capabilities_not_owned.handlers[0]
        .required_method_data
        .clone();
    capabilities_not_owned.handlers[0]
        .required_method_data
        .retain(|pair| pair != &capabilities_pair);
    assert_ne!(
        capabilities_not_owned.handlers[0].required_method_data,
        methods_before
    );
    assert_eq!(
        validate_subquery_batch(&client, &plan, &capabilities_not_owned, &capabilities),
        operation_error
    );

    let mut filter_not_owned = profile.clone();
    let methods_before = filter_not_owned.handlers[0].required_method_data.clone();
    filter_not_owned.handlers[0]
        .required_method_data
        .retain(|pair| pair != &filter_pair);
    assert_ne!(
        filter_not_owned.handlers[0].required_method_data,
        methods_before
    );
    assert_eq!(
        validate_subquery_batch(&client, &plan, &filter_not_owned, &filter),
        operation_error
    );

    let mut crossed_handler = profile;
    let second_selector = TypedSelectorV1 {
        field_id: "other".into(),
        schema_digest: "other-schema".into(),
        selector_digest: "other-selector".into(),
    };
    crossed_handler.filters.push(second_selector.clone());
    crossed_handler.handlers[0].filter_id = second_selector.field_id.clone();
    crossed_handler.handlers.push(SubQueryHandlerV1 {
        handler_id: "handler-z".into(),
        data_source_id: "datasource".into(),
        processor_id: "processor".into(),
        filter_id: selector.field_id.clone(),
        required_method_data: client.method_data_classes.clone(),
    });
    crossed_handler.data_node_surface = SubQueryDataNodeSurfaceV1::Exact {
        protocol_version: "1".into(),
        schema_version: "1".into(),
        allowed_fields: vec![selector.field_id.clone(), second_selector.field_id.clone()],
        allowed_selectors: vec![selector, second_selector],
    };
    assert_eq!(
        validate_subquery_batch(&client, &plan, &crossed_handler, &filter),
        operation_error
    );
}
