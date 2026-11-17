use super::super::*;
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
        method: "eth_getLogs".into(),
        data_class: "EVENT_LOG".into(),
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
        client_family: ClientIndexerFamily::TheGraphEvmJsonRpc,
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

fn graph_manifest() -> TheGraphManifestProfileV1 {
    TheGraphManifestProfileV1 {
        profile_id: "graph".into(),
        profile_version: "1".into(),
        profile_digest: "graph-digest".into(),
        client_profile_id: "client".into(),
        client_profile_version: "1".into(),
        client_profile_digest: "client-digest".into(),
        projection_plan_digest: "plan".into(),
        manifest_digest: "manifest".into(),
        referenced_files: vec![named("abi"), named("file")],
        spec_version: "1".into(),
        features: vec!["feature".into()],
        network: "network".into(),
        range: source_range(),
        data_sources: vec![GraphDataSourceV1 {
            data_source_id: "datasource".into(),
            kind: "ethereum".into(),
            name: "source".into(),
            network: "network".into(),
            address: "address".into(),
            abi_digest: "abi-digest".into(),
            start_block: 1,
            mapping_id: "mapping".into(),
        }],
        mappings: vec![GraphMappingV1 {
            mapping_id: "mapping".into(),
            data_source_id: "datasource".into(),
            language: "wasm".into(),
            api_version: "1".into(),
            file_digest: "file-digest".into(),
            entities: vec!["entity".into()],
        }],
        handlers: vec![GraphHandlerV1 {
            handler_id: "handler".into(),
            data_source_id: "datasource".into(),
            mapping_id: "mapping".into(),
            kind: GraphHandlerKind::Event,
            signature: "event".into(),
            filter: "filter".into(),
            function: "handle".into(),
            required_method_data: vec![method()],
        }],
        dynamic_templates: vec![],
        state_read_dependencies: vec![method()],
        entity_projection_schemas: vec![named("entity")],
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}
fn graph_batch() -> TheGraphCandidateBatchV1 {
    let base = candidate_batch();
    TheGraphCandidateBatchV1 {
        observations: base.observations.clone(),
        base,
        manifest_profile_id: "graph".into(),
        manifest_profile_version: "1".into(),
        manifest_profile_digest: "graph-digest".into(),
        manifest_digest: "manifest".into(),
        data_source_id: "datasource".into(),
        handler_id: "handler".into(),
        template_use: GraphTemplateUse::Static,
    }
}

#[test]
fn manifest_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let manifest = graph_manifest();
    assert!(validate_thegraph_manifest(&client, &plan, &manifest).is_ok());
    for mutate in [
        |v: &mut TheGraphManifestProfileV1| v.profile_id.clear(),
        |v: &mut TheGraphManifestProfileV1| v.profile_version.clear(),
        |v: &mut TheGraphManifestProfileV1| v.profile_digest.clear(),
        |v: &mut TheGraphManifestProfileV1| v.client_profile_digest = "other".into(),
        |v: &mut TheGraphManifestProfileV1| v.projection_plan_digest = "other".into(),
        |v: &mut TheGraphManifestProfileV1| v.manifest_digest.clear(),
        |v: &mut TheGraphManifestProfileV1| v.referenced_files.clear(),
        |v: &mut TheGraphManifestProfileV1| v.spec_version.clear(),
        |v: &mut TheGraphManifestProfileV1| v.features.clear(),
        |v: &mut TheGraphManifestProfileV1| v.network = "other".into(),
        |v: &mut TheGraphManifestProfileV1| v.range.start = 0,
        |v: &mut TheGraphManifestProfileV1| v.data_sources.clear(),
        |v: &mut TheGraphManifestProfileV1| v.mappings.clear(),
        |v: &mut TheGraphManifestProfileV1| v.handlers.clear(),
        |v: &mut TheGraphManifestProfileV1| v.state_read_dependencies.clear(),
        |v: &mut TheGraphManifestProfileV1| v.entity_projection_schemas.clear(),
    ] {
        let mut drift = manifest.clone();
        mutate(&mut drift);
        assert!(validate_thegraph_manifest(&client, &plan, &drift).is_err());
    }
}

#[test]
fn bounded_manifest_range_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut lower = graph_manifest();
    lower.data_sources[0].start_block = lower.range.start;
    assert_eq!(validate_thegraph_manifest(&client, &plan, &lower), Ok(()));
    let mut upper = graph_manifest();
    let before = upper.data_sources[0].start_block;
    upper.data_sources[0].start_block = 10;
    assert_ne!(upper.data_sources[0].start_block, before);
    assert_eq!(validate_thegraph_manifest(&client, &plan, &upper), Ok(()));

    let mut below = graph_manifest();
    let before = below.range.start;
    below.range.start = 2;
    assert_ne!(below.range.start, before);
    assert_eq!(
        validate_thegraph_manifest(&client, &plan, &below),
        Err(ProviderContractError::Invalid("graph data source range"))
    );
    let mut above = graph_manifest();
    let before = above.data_sources[0].start_block;
    above.data_sources[0].start_block = 11;
    assert_ne!(above.data_sources[0].start_block, before);
    assert_eq!(
        validate_thegraph_manifest(&client, &plan, &above),
        Err(ProviderContractError::Invalid("graph data source range"))
    );
    let mut inverted = graph_manifest();
    let before = inverted.range.end;
    inverted.range.end = RangeEndV1::Inclusive(0);
    assert_ne!(inverted.range.end, before);
    assert_eq!(
        validate_thegraph_manifest(&client, &plan, &inverted),
        Err(ProviderContractError::Invalid("thegraph bounded range"))
    );
    let mut open = graph_manifest();
    let before = open.range.end;
    open.range.end = RangeEndV1::Open;
    assert_ne!(open.range.end, before);
    assert_eq!(
        validate_thegraph_manifest(&client, &plan, &open),
        Err(ProviderContractError::Invalid("thegraph bounded range"))
    );
}

#[test]
fn graph_relations_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let manifest = graph_manifest();
    for mutate in [
        |v: &mut TheGraphManifestProfileV1| v.data_sources[0].abi_digest = "missing".into(),
        |v: &mut TheGraphManifestProfileV1| v.data_sources[0].mapping_id = "missing".into(),
        |v: &mut TheGraphManifestProfileV1| v.mappings[0].file_digest = "missing".into(),
        |v: &mut TheGraphManifestProfileV1| v.mappings[0].entities[0] = "missing".into(),
        |v: &mut TheGraphManifestProfileV1| v.handlers[0].data_source_id = "missing".into(),
        |v: &mut TheGraphManifestProfileV1| v.handlers[0].kind = GraphHandlerKind::Call,
        |v: &mut TheGraphManifestProfileV1| {
            v.handlers[0].required_method_data[0].method = "eth_call".into()
        },
    ] {
        let mut drift = manifest.clone();
        mutate(&mut drift);
        assert!(validate_thegraph_manifest(&client, &plan, &drift).is_err());
    }
}

#[test]
fn batch_relations_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let manifest = graph_manifest();
    let batch = graph_batch();
    assert!(validate_thegraph_batch(&client, &plan, &manifest, &batch).is_ok());
    for mutate in [
        |v: &mut TheGraphCandidateBatchV1| v.manifest_profile_id = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.manifest_profile_version = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.manifest_profile_digest = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.manifest_digest = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.data_source_id = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.handler_id = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| v.observations[0].normalized_digest = "other".into(),
        |v: &mut TheGraphCandidateBatchV1| {
            v.base.completed_watermark.canonical_block_hash = "other".into()
        },
    ] {
        let mut drift = batch.clone();
        mutate(&mut drift);
        assert!(validate_thegraph_batch(&client, &plan, &manifest, &drift).is_err());
    }
}

#[test]
fn graph_batch_is_within_manifest_and_data_source_range() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut manifest = graph_manifest();
    manifest.data_sources[0].start_block = 3;
    let mut batch = graph_batch();
    batch.base.range.start = 3;
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &batch),
        Ok(())
    );

    let mut before_source = batch.clone();
    let before = before_source.base.range.start;
    before_source.base.range.start = 2;
    assert_ne!(before_source.base.range.start, before);
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &before_source),
        Err(ProviderContractError::Invalid("graph candidate batch"))
    );

    let mut short_manifest = graph_manifest();
    let full_batch = graph_batch();
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &short_manifest, &full_batch),
        Ok(())
    );
    let before = short_manifest.range.end;
    short_manifest.range.end = RangeEndV1::Inclusive(9);
    assert_ne!(short_manifest.range.end, before);
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &short_manifest, &full_batch),
        Err(ProviderContractError::Invalid("graph candidate batch"))
    );

    let mut equality_manifest = graph_manifest();
    equality_manifest.data_sources[0].start_block = 10;
    let mut equality_batch = graph_batch();
    equality_batch.base.range.start = 10;
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &equality_manifest, &equality_batch),
        Ok(())
    );
}

#[test]
fn graph_block_handler_method_data_class_is_exact() {
    let plan = projection_plan();
    let exact_pairs = [
        ("eth_getBlockByNumber(false)", "BLOCK_HEADER"),
        ("eth_getBlockByNumber(true)", "FULL_BLOCK_TRANSACTIONS"),
    ];
    for (method_name, data_class) in exact_pairs {
        let pair = MethodDataClass {
            method: method_name.into(),
            data_class: data_class.into(),
        };
        let mut client = client_indexer();
        client.method_data_classes = vec![pair.clone()];
        let mut manifest = graph_manifest();
        manifest.state_read_dependencies = vec![pair.clone()];
        manifest.handlers[0].kind = GraphHandlerKind::Block;
        manifest.handlers[0].required_method_data = vec![pair];
        assert_eq!(
            validate_thegraph_manifest(&client, &plan, &manifest),
            Ok(())
        );
    }

    for (method_name, data_class) in [
        ("eth_getBlockByNumber", "BLOCK_HEADER"),
        ("eth_getBlockByNumber(false)-suffix", "BLOCK_HEADER"),
        ("eth_getBlockByNumber(false)", "FULL_BLOCK_TRANSACTIONS"),
        ("eth_getBlockByNumber(true)", "BLOCK_HEADER"),
    ] {
        let pair = MethodDataClass {
            method: method_name.into(),
            data_class: data_class.into(),
        };
        let mut client = client_indexer();
        let mut manifest = graph_manifest();
        assert_eq!(
            validate_thegraph_manifest(&client, &plan, &manifest),
            Ok(())
        );
        let methods_before = client.method_data_classes.clone();
        let dependencies_before = manifest.state_read_dependencies.clone();
        let kind_before = manifest.handlers[0].kind;
        let required_before = manifest.handlers[0].required_method_data.clone();
        client.method_data_classes = vec![pair.clone()];
        manifest.state_read_dependencies = vec![pair.clone()];
        manifest.handlers[0].kind = GraphHandlerKind::Block;
        manifest.handlers[0].required_method_data = vec![pair];
        assert_ne!(client.method_data_classes, methods_before);
        assert_ne!(manifest.state_read_dependencies, dependencies_before);
        assert_ne!(manifest.handlers[0].kind, kind_before);
        assert_ne!(manifest.handlers[0].required_method_data, required_before);
        assert_eq!(
            validate_thegraph_manifest(&client, &plan, &manifest),
            Err(ProviderContractError::Invalid("graph handler"))
        );
    }
}

#[test]
fn dynamic_template_creation_and_derived_source_are_exact() {
    let client = client_indexer();
    let mut plan = projection_plan();
    plan.partitions[0].source_id = "derived-source".into();
    let mut manifest = graph_manifest();
    manifest.referenced_files.push(named("template"));
    manifest.dynamic_templates = vec![GraphTemplateV1 {
        template_id: "template".into(),
        mapping_id: "mapping".into(),
        digest: "template-digest".into(),
        creation_binding: "creation-evidence".into(),
    }];
    manifest.data_sources[0].start_block = 2;
    let mut batch = graph_batch();
    batch.base.source_id = "derived-source".into();
    batch.base.range.start = 3;
    batch.base.evidence_refs = vec!["creation-evidence".into()];
    batch.data_source_id = "derived-source".into();
    let creation_anchor = ChainReadAnchorV1 {
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(2),
        block_hash: Some("block-2".into()),
        pending_authorized_by_profile: false,
    };
    batch.template_use = GraphTemplateUse::Dynamic {
        template_id: "template".into(),
        creation_binding: "creation-evidence".into(),
        creation_anchor: creation_anchor.clone(),
    };
    assert_eq!(
        plan.partitions
            .iter()
            .filter(|partition| partition.source_id == batch.base.source_id)
            .count(),
        1
    );
    assert!(
        manifest
            .data_sources
            .iter()
            .all(|source| source.data_source_id != batch.data_source_id)
    );
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &batch),
        Ok(())
    );

    let dynamic_error = Err(ProviderContractError::Invalid("graph dynamic template"));
    let mut binding_drift = batch.clone();
    let binding_before = match &binding_drift.template_use {
        GraphTemplateUse::Dynamic {
            creation_binding, ..
        } => creation_binding.clone(),
        GraphTemplateUse::Static => unreachable!(),
    };
    if let GraphTemplateUse::Dynamic {
        creation_binding, ..
    } = &mut binding_drift.template_use
    {
        *creation_binding = "other-evidence".into();
    }
    assert_ne!(
        match &binding_drift.template_use {
            GraphTemplateUse::Dynamic {
                creation_binding, ..
            } => creation_binding,
            GraphTemplateUse::Static => unreachable!(),
        },
        &binding_before
    );
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &binding_drift),
        dynamic_error
    );

    let mut missing_evidence = batch.clone();
    let evidence_before = missing_evidence.base.evidence_refs.clone();
    missing_evidence.base.evidence_refs = vec!["other-evidence".into()];
    assert_ne!(missing_evidence.base.evidence_refs, evidence_before);
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &missing_evidence),
        dynamic_error
    );

    type AnchorMutation = (&'static str, fn(&mut ChainReadAnchorV1));
    let anchor_mutations: &[AnchorMutation] = &[
        ("pending", |anchor: &mut ChainReadAnchorV1| {
            anchor.selector_kind = BlockSelectorKind::Pending;
            anchor.block_number = None;
            anchor.block_hash = None;
            anchor.pending_authorized_by_profile = true;
        }),
        ("wrong-chain", |anchor: &mut ChainReadAnchorV1| {
            anchor.chain_id = "other".into();
        }),
        ("wrong-genesis", |anchor: &mut ChainReadAnchorV1| {
            anchor.genesis_hash = "other".into();
        }),
        ("wrong-network", |anchor: &mut ChainReadAnchorV1| {
            anchor.network_id = "other".into();
        }),
        ("empty-hash", |anchor: &mut ChainReadAnchorV1| {
            anchor.block_hash = Some(String::new());
        }),
        ("below-manifest-start", |anchor: &mut ChainReadAnchorV1| {
            anchor.block_number = Some(0);
            anchor.block_hash = Some("block-0".into());
        }),
        ("below-prototype-start", |anchor: &mut ChainReadAnchorV1| {
            anchor.block_number = Some(1);
            anchor.block_hash = Some("block-1".into());
        }),
        ("not-before", |anchor: &mut ChainReadAnchorV1| {
            anchor.block_number = Some(3);
            anchor.block_hash = Some("block-3".into());
        }),
    ];
    for (name, mutate) in anchor_mutations {
        let mut drift = batch.clone();
        let anchor_before = match &drift.template_use {
            GraphTemplateUse::Dynamic {
                creation_anchor, ..
            } => creation_anchor.clone(),
            GraphTemplateUse::Static => unreachable!(),
        };
        if let GraphTemplateUse::Dynamic {
            creation_anchor, ..
        } = &mut drift.template_use
        {
            mutate(creation_anchor);
        }
        assert_ne!(
            match &drift.template_use {
                GraphTemplateUse::Dynamic {
                    creation_anchor, ..
                } => creation_anchor,
                GraphTemplateUse::Static => unreachable!(),
            },
            &anchor_before,
            "{name}"
        );
        assert_eq!(
            validate_thegraph_batch(&client, &plan, &manifest, &drift),
            dynamic_error,
            "{name}"
        );
    }

    let mut wrong_handler = batch.clone();
    let handler_before = wrong_handler.handler_id.clone();
    wrong_handler.handler_id = "other-handler".into();
    assert_ne!(wrong_handler.handler_id, handler_before);
    assert_eq!(
        validate_thegraph_batch(&client, &plan, &manifest, &wrong_handler),
        dynamic_error
    );

    let mut static_identity_plan = plan;
    static_identity_plan.partitions[0].source_id = "datasource".into();
    let mut static_identity = batch;
    let source_before = static_identity.data_source_id.clone();
    static_identity.data_source_id = "datasource".into();
    static_identity.base.source_id = "datasource".into();
    assert_ne!(static_identity.data_source_id, source_before);
    assert_eq!(
        validate_thegraph_batch(&client, &static_identity_plan, &manifest, &static_identity),
        dynamic_error
    );
}
