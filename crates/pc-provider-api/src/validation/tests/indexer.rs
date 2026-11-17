use super::super::*;
type ClientProfileMutation = (&'static str, fn(&mut ClientIndexerProfileV1));
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
        data_class: "call-result".into(),
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
        client_family: ClientIndexerFamily::CustomEvmIndexer,
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
            source_id: "source".into(),
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
        source_id: "source".into(),
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

#[test]
fn client_profile_exact_tuple_accepts() {
    let value = client_indexer();
    assert!(validate_client_indexer_profile(&value).is_ok());
    let mutations: &[ClientProfileMutation] = &[
        ("profile_id", |v| v.profile_id.clear()),
        ("profile_version", |v| v.profile_version.clear()),
        ("profile_digest", |v| v.profile_digest.clear()),
        ("engine_or_runtime", |v| v.engine_or_runtime.clear()),
        ("engine_version", |v| v.engine_version.clear()),
        ("configuration_digest", |v| v.configuration_digest.clear()),
        ("participant_binding", |v| v.participant_binding.clear()),
        ("privacy_binding", |v| v.privacy_binding.clear()),
        ("workload_binding", |v| v.workload_binding.clear()),
        ("deployment_owner", |v| v.deployment_owner.clear()),
        ("boundary", |v| v.boundary_declaration_digest.clear()),
        ("protocol_version", |v| v.protocol_version.clear()),
        ("chain", |v| v.chain_id.clear()),
        ("genesis", |v| v.genesis_hash.clear()),
        ("network", |v| v.network_id.clear()),
        ("dependencies", |v| v.dependencies.clear()),
        ("capabilities", |v| v.capability_profiles.clear()),
        ("methods", |v| v.method_data_classes.clear()),
        ("family_surface", |v| {
            v.client_family = ClientIndexerFamily::SubQueryDataNode
        }),
    ];
    for (name, mutate) in mutations {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_client_indexer_profile(&drift).is_err(), "{name}");
    }
}

#[test]
fn client_profile_laws_accept() {
    let value = client_indexer();
    let mutations: &[ClientProfileMutation] = &[
        ("range", |v| v.source_range.end = RangeEndV1::Inclusive(0)),
        ("finality", |v| v.finality_rule_digest.clear()),
        ("reorg", |v| v.reorg_behavior_digest.clear()),
        ("removed", |v| v.removed_event_behavior_digest.clear()),
        ("checkpoint", |v| v.checkpoint_semantics_digest.clear()),
        ("watermark", |v| {
            v.completed_watermark_semantics_digest.clear()
        }),
        ("artifacts", |v| v.artifact_digests.clear()),
        ("limits", |v| v.limits.max_range = 0),
        ("behavior", |v| v.behavior.partial_digest.clear()),
        ("candidate", |v| v.candidate_store_contract_digest.clear()),
        ("outbox", |v| v.outbox_contract_digest.clear()),
        ("bridge", |v| v.fact_bridge_contract_digest.clear()),
        ("security", |v| v.security_evidence_digest.clear()),
        ("privacy", |v| v.privacy_evidence_digest.clear()),
        ("licensing", |v| v.licensing_digest.clear()),
        ("supply_chain", |v| v.supply_chain_digest.clear()),
        ("telemetry", |v| v.telemetry_classification_digest.clear()),
        ("rollback", |v| v.rollback_digest.clear()),
        ("uninstall", |v| v.uninstall_digest.clear()),
        ("corpus", |v| v.corpus_digest.clear()),
        ("receipt", |v| v.conformance_receipt_digest.clear()),
        ("lifecycle", |v| v.lifecycle = ClientIndexerLifecycle::Draft),
    ];
    for (name, mutate) in mutations {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_client_indexer_profile(&drift).is_err(), "{name}");
    }
}

#[test]
fn nested_exact_values_accept() {
    let mut value = client_indexer();
    assert!(validate_client_indexer_profile(&value).is_ok());
    value.dependencies[0].version.clear();
    assert!(validate_client_indexer_profile(&value).is_err());
    let mut value = client_indexer();
    value
        .artifact_digests
        .push(value.artifact_digests[0].clone());
    assert!(validate_client_indexer_profile(&value).is_err());
    for mutate in [
        |v: &mut ClientIndexerProfileV1| v.limits.max_request_bytes = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.max_range = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.max_batch = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.max_response_bytes = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.max_depth = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.max_resource = 0,
        |v: &mut ClientIndexerProfileV1| v.limits.rate_limit_contract_digest.clear(),
    ] {
        let mut drift = client_indexer();
        mutate(&mut drift);
        assert!(validate_client_indexer_profile(&drift).is_err());
    }
}

#[test]
fn projection_plan_coverage_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    assert!(validate_projection_plan(&client, &plan).is_ok());
    for mutate in [
        |v: &mut ProjectionPlanV1| v.profile_digest = "drift".into(),
        |v: &mut ProjectionPlanV1| v.finality_rule_digest = "drift".into(),
        |v: &mut ProjectionPlanV1| v.source_range.start = 0,
        |v: &mut ProjectionPlanV1| v.limits.max_range += 1,
        |v: &mut ProjectionPlanV1| v.partitions[0].range.start = 2,
        |v: &mut ProjectionPlanV1| v.partitions[0].range.end = RangeEndV1::Inclusive(9),
        |v: &mut ProjectionPlanV1| v.partitions[0].source_id.clear(),
        |v: &mut ProjectionPlanV1| v.lifecycle_generation = 0,
    ] {
        let mut drift = plan.clone();
        mutate(&mut drift);
        assert!(validate_projection_plan(&client, &drift).is_err());
    }
}

#[test]
fn projection_nested_accepts() {
    let client = client_indexer();
    let mut plan = projection_plan();
    assert!(validate_projection_plan(&client, &plan).is_ok());
    plan.secret_references[0].reference = "raw-secret".into();
    assert!(validate_projection_plan(&client, &plan).is_err());
    let mut plan = projection_plan();
    if let WorkloadIdentityV1::ImageBuild { image_digest, .. } = &mut plan.workload_identity {
        image_digest.clear();
    }
    assert!(validate_projection_plan(&client, &plan).is_err());
}

#[test]
fn candidate_batch_relations_accept() {
    let client = client_indexer();
    let plan = projection_plan();
    let batch = candidate_batch();
    assert!(validate_candidate_projection_batch(&client, &plan, &batch).is_ok());
    for mutate in [
        |v: &mut CandidateProjectionBatchV1| v.profile_digest = "drift".into(),
        |v: &mut CandidateProjectionBatchV1| v.plan_digest = "drift".into(),
        |v: &mut CandidateProjectionBatchV1| v.source_id = "drift".into(),
        |v: &mut CandidateProjectionBatchV1| v.partition_id = "drift".into(),
        |v: &mut CandidateProjectionBatchV1| v.records[0].block_number = 11,
        |v: &mut CandidateProjectionBatchV1| {
            v.missing_intervals = vec![InclusiveRangeV1 { start: 9, end: 10 }]
        },
        |v: &mut CandidateProjectionBatchV1| v.predecessor_batch_digest = "drift".into(),
    ] {
        let mut drift = batch.clone();
        mutate(&mut drift);
        assert!(validate_candidate_projection_batch(&client, &plan, &drift).is_err());
    }
    let mut prior = batch.clone();
    prior.range.end = 5;
    prior.observations[0].anchor.block_number = Some(5);
    prior.observations[0].anchor.block_hash = Some("block-5".into());
    prior.records[0].block_number = 5;
    prior.records[0].canonical_block_hash = "block-5".into();
    prior.completed_watermark.block_number = 5;
    prior.completed_watermark.canonical_block_hash = "block-5".into();
    let mut next = batch;
    next.batch_sequence = 2;
    next.range.start = 6;
    next.predecessor_batch_digest = "prior-digest".into();
    assert!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &next,
            Some((&prior, "prior-digest"))
        )
        .is_ok()
    );
    assert!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &next,
            Some((&prior, "wrong"))
        )
        .is_err()
    );
}

#[test]
fn candidate_batch_structure_defers_durable_predecessor_truth() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut successor = candidate_batch();
    successor.batch_sequence = 2;
    successor.predecessor_batch_digest = "11".repeat(32);
    assert_eq!(
        validate_candidate_projection_batch_structure(&client, &plan, &successor),
        Ok(())
    );
    assert_eq!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &successor,
            Some((&candidate_batch(), &"22".repeat(32))),
        ),
        Err(ProviderContractError::Invalid(
            "candidate predecessor relation"
        ))
    );

    let mut material_empty = candidate_batch();
    material_empty.records.clear();
    assert_eq!(
        validate_candidate_projection_batch_structure(&client, &plan, &material_empty),
        Ok(())
    );
    assert!(validate_candidate_projection_batch(&client, &plan, &material_empty).is_err());
}

#[test]
fn candidate_nested_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let base = candidate_batch();
    for mutate in [
        |v: &mut CandidateProjectionBatchV1| v.observations[0].sequence = 2,
        |v: &mut CandidateProjectionBatchV1| v.observations[0].anchor.chain_id = "other".into(),
        |v: &mut CandidateProjectionBatchV1| v.records[0].sequence = 2,
        |v: &mut CandidateProjectionBatchV1| v.records[0].canonical_block_hash = "other".into(),
        |v: &mut CandidateProjectionBatchV1| v.completed_watermark.canonical_block_hash.clear(),
    ] {
        let mut drift = base.clone();
        mutate(&mut drift);
        assert!(validate_candidate_projection_batch(&client, &plan, &drift).is_err());
    }
}

fn anchored_decode_batch() -> CandidateProjectionBatchV1 {
    let mut batch = candidate_batch();
    batch.completed_watermark = CompletedWatermarkV1 {
        block_number: 8,
        canonical_block_hash: "block-8".into(),
    };
    batch.records[0].block_number = 8;
    batch.records[0].canonical_block_hash = "block-8".into();
    batch.observations[0].anchor.block_number = Some(9);
    batch.observations[0].anchor.block_hash = Some("block-9".into());
    batch.decode_failures = vec![DecodeFailureV1 {
        sequence: 1,
        source_id: "source".into(),
        anchor: ChainReadAnchorV1 {
            block_number: Some(10),
            block_hash: Some("block-10".into()),
            ..anchor()
        },
        error_digest: "33".repeat(32),
        evidence_digest: "44".repeat(32),
    }];
    batch
}

#[test]
fn candidate_batch_digest_fields_accept_exact_raw_sha256() {
    let client = client_indexer();
    let plan = projection_plan();
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &candidate_batch()),
        Ok(())
    );
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &anchored_decode_batch()),
        Ok(())
    );
}

#[test]
fn candidate_batch_digest_fields_reject_typed_and_serialized_malformed_values() {
    let malformed = [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        format!("{}g", "a".repeat(63)),
        format!("sha256:{}", "a".repeat(64)),
        format!("0x{}", "a".repeat(64)),
        format!("sha256:sha256:{}", "a".repeat(64)),
        format!("{} ", "a".repeat(64)),
    ];
    for value in malformed {
        for mutate in [
            |batch: &mut CandidateProjectionBatchV1, value: String| {
                batch.observations[0].normalized_digest = value;
            },
            |batch: &mut CandidateProjectionBatchV1, value: String| {
                batch.observations[0].evidence_digest = value;
            },
            |batch: &mut CandidateProjectionBatchV1, value: String| {
                batch.decode_failures[0].error_digest = value;
            },
            |batch: &mut CandidateProjectionBatchV1, value: String| {
                batch.decode_failures[0].evidence_digest = value;
            },
        ] {
            let mut typed = anchored_decode_batch();
            mutate(&mut typed, value.clone());
            assert!(
                validate_candidate_projection_batch(&client_indexer(), &projection_plan(), &typed)
                    .is_err()
            );

            let encoded = encode_candidate_projection_batch_pc_cbor(&typed)
                .expect("malformed digest remains serializable");
            let decoded: CandidateProjectionBatchV1 =
                decode_canonical_cbor(&encoded, "candidate projection batch PC-CBOR")
                    .expect("real canonical PC-CBOR decode");
            assert_eq!(decoded, typed);
            assert!(
                validate_candidate_projection_batch(
                    &client_indexer(),
                    &projection_plan(),
                    &decoded
                )
                .is_err()
            );
        }
    }
}

#[test]
fn candidate_batch_role_digests_preserve_valid_swapped_values_for_projection_oracle() {
    let mut swapped = anchored_decode_batch();
    swapped.observations[0].normalized_digest = "22".repeat(32);
    swapped.observations[0].evidence_digest = "11".repeat(32);
    swapped.decode_failures[0].error_digest = "44".repeat(32);
    swapped.decode_failures[0].evidence_digest = "33".repeat(32);
    assert_eq!(
        validate_candidate_projection_batch(&client_indexer(), &projection_plan(), &swapped),
        Ok(())
    );

    let encoded =
        encode_candidate_projection_batch_pc_cbor(&swapped).expect("canonical PC-CBOR encode");
    let decoded: CandidateProjectionBatchV1 =
        decode_canonical_cbor(&encoded, "candidate projection batch PC-CBOR")
            .expect("real canonical PC-CBOR decode");
    assert_eq!(decoded.observations[0].normalized_digest, "22".repeat(32));
    assert_eq!(decoded.observations[0].evidence_digest, "11".repeat(32));
    assert_eq!(decoded.decode_failures[0].error_digest, "44".repeat(32));
    assert_eq!(decoded.decode_failures[0].evidence_digest, "33".repeat(32));
}

#[test]
fn decode_failure_anchor_and_watermark_relations_accept() {
    fn assert_wire<T: serde::Serialize + serde::de::DeserializeOwned + Eq + PartialEq>() {}
    assert_wire::<DecodeFailureV1>();
    let client = client_indexer();
    let plan = projection_plan();
    let base = anchored_decode_batch();
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &base),
        Ok(())
    );
    let anchor_mutations: &[fn(&mut CandidateProjectionBatchV1)] = &[
        |value| {
            value.decode_failures[0].anchor.selector_kind = BlockSelectorKind::Pending;
            value.decode_failures[0].anchor.block_number = None;
            value.decode_failures[0].anchor.block_hash = None;
            value.decode_failures[0]
                .anchor
                .pending_authorized_by_profile = true;
        },
        |value| value.decode_failures[0].anchor.chain_id = "wrong".into(),
        |value| value.decode_failures[0].anchor.genesis_hash = "wrong".into(),
        |value| value.decode_failures[0].anchor.network_id = "wrong".into(),
        |value| value.decode_failures[0].anchor.block_number = Some(11),
    ];
    for mutate in anchor_mutations {
        let mut drift = base.clone();
        let before = drift.decode_failures[0].anchor.clone();
        mutate(&mut drift);
        assert_ne!(drift.decode_failures[0].anchor, before);
        assert_eq!(
            validate_candidate_projection_batch(&client, &plan, &drift),
            Err(ProviderContractError::Invalid("decode failure anchor"))
        );
    }
    for block_number in [Some(8), Some(7)] {
        let mut drift = base.clone();
        let before = drift.decode_failures[0].anchor.block_number;
        drift.decode_failures[0].anchor.block_number = block_number;
        assert_ne!(drift.decode_failures[0].anchor.block_number, before);
        assert_eq!(
            validate_candidate_projection_batch(&client, &plan, &drift),
            Err(ProviderContractError::Invalid(
                "decode failure completeness"
            ))
        );
    }
    let mut drift = base.clone();
    let before = drift.decode_failures[0].sequence;
    drift.decode_failures[0].sequence = 2;
    assert_ne!(drift.decode_failures[0].sequence, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        Err(ProviderContractError::Invalid("decode failure anchor"))
    );
    let mut drift = base.clone();
    let before = drift.decode_failures[0].source_id.clone();
    drift.decode_failures[0].source_id = "wrong".into();
    assert_ne!(drift.decode_failures[0].source_id, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        Err(ProviderContractError::Invalid("decode failure anchor"))
    );
    let mut drift = base.clone();
    let before = drift.decode_failures[0].error_digest.clone();
    drift.decode_failures[0].error_digest.clear();
    assert_ne!(drift.decode_failures[0].error_digest, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        Err(ProviderContractError::Invalid("decode failure digest"))
    );
    let mut drift = base.clone();
    let before = drift.decode_failures[0].evidence_digest.clone();
    drift.decode_failures[0].evidence_digest.clear();
    assert_ne!(drift.decode_failures[0].evidence_digest, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        Err(ProviderContractError::Invalid("decode failure digest"))
    );
}

#[test]
fn batch_canonical_anchor_coherence_accepts() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut base = anchored_decode_batch();
    base.records[0].block_number = 9;
    base.records[0].canonical_block_hash = "block-9".into();
    base.observations.insert(
        0,
        SequencedObservationV1 {
            sequence: 1,
            anchor: ChainReadAnchorV1 {
                block_number: Some(8),
                block_hash: Some("block-8".into()),
                ..anchor()
            },
            normalized_digest: "55".repeat(32),
            evidence_digest: "66".repeat(32),
        },
    );
    base.observations[1].sequence = 2;
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &base),
        Ok(())
    );
    let expected = Err(ProviderContractError::Invalid(
        "batch canonical anchor coherence",
    ));
    let mut drift = base.clone();
    let before = drift.records[0].canonical_block_hash.clone();
    drift.records[0].canonical_block_hash = "record-drift".into();
    assert_ne!(drift.records[0].canonical_block_hash, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        expected
    );

    let mut drift = base.clone();
    let before = drift.observations[1].anchor.block_hash.clone();
    drift.observations[1].anchor.block_hash = Some("observation-drift".into());
    assert_ne!(drift.observations[1].anchor.block_hash, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        expected
    );

    let mut drift = base.clone();
    let before = drift.decode_failures[0].anchor.clone();
    drift.decode_failures[0].anchor.block_number = Some(9);
    drift.decode_failures[0].anchor.block_hash = Some("failure-drift".into());
    assert_ne!(drift.decode_failures[0].anchor, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        expected
    );

    let mut drift = base.clone();
    let before = drift.completed_watermark.canonical_block_hash.clone();
    drift.completed_watermark.canonical_block_hash = "watermark-drift".into();
    assert_ne!(drift.completed_watermark.canonical_block_hash, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &drift),
        expected
    );
}

#[test]
fn candidate_record_identity_is_nonempty_and_unique() {
    let mut client = client_indexer();
    client.limits.max_batch = 2;
    let mut plan = projection_plan();
    plan.limits.max_batch = 2;
    let mut base = candidate_batch();
    let mut second = base.records[0].clone();
    second.sequence = 2;
    second.record_id = "record-2".into();
    second.normalized_digest = "normalized-2".into();
    second.evidence_digest = "evidence-2".into();
    base.records.push(second);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &base),
        Ok(())
    );

    let mut empty_identity = base.clone();
    let before = empty_identity.records[0].record_id.clone();
    empty_identity.records[0].record_id.clear();
    assert_ne!(empty_identity.records[0].record_id, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &empty_identity),
        Err(ProviderContractError::Invalid("candidate record identity"))
    );

    let mut duplicate_identity = base.clone();
    let before = duplicate_identity.records[1].record_id.clone();
    duplicate_identity.records[1].record_id = duplicate_identity.records[0].record_id.clone();
    assert_ne!(duplicate_identity.records[1].record_id, before);
    assert_eq!(
        duplicate_identity.records[1].record_id,
        duplicate_identity.records[0].record_id
    );
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &duplicate_identity),
        Err(ProviderContractError::Invalid("candidate record identity"))
    );

    let mut empty_records = base.clone();
    let before = empty_records.records.len();
    empty_records.records.clear();
    assert_ne!(empty_records.records.len(), before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &empty_records),
        Err(ProviderContractError::Invalid("candidate records"))
    );

    let mut missing_schema = base;
    let before = missing_schema.records[0].schema_digest.clone();
    missing_schema.records[0].schema_digest.clear();
    assert_ne!(missing_schema.records[0].schema_digest, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &missing_schema),
        Err(ProviderContractError::Invalid("candidate records"))
    );
}

#[test]
fn projection_plan_partition_and_candidate_limits_are_closed() {
    let client = client_indexer();
    let plan = projection_plan();
    assert_eq!(validate_projection_plan(&client, &plan), Ok(()));

    let mut equality_client = client.clone();
    equality_client.source_range = SourceRangeV1 {
        start: 1,
        end: RangeEndV1::Inclusive(1),
    };
    let mut equality_plan = plan.clone();
    equality_plan.source_range = equality_client.source_range.clone();
    equality_plan.partitions[0].range = equality_client.source_range.clone();
    assert_eq!(
        validate_projection_plan(&equality_client, &equality_plan),
        Ok(())
    );

    let mut open_client = client.clone();
    open_client.source_range.end = RangeEndV1::Open;
    let mut open_plan = plan.clone();
    open_plan.source_range.end = RangeEndV1::Open;
    open_plan.partitions[0].range.end = RangeEndV1::Open;
    assert_eq!(validate_projection_plan(&open_client, &open_plan), Ok(()));

    let mut zero_plan = plan.clone();
    let before = zero_plan.source_range.start;
    zero_plan.source_range.start = 0;
    assert_ne!(zero_plan.source_range.start, before);
    assert_eq!(
        validate_projection_plan(&client, &zero_plan),
        Err(ProviderContractError::Invalid("projection plan binding"))
    );

    let mut inverted_plan = plan.clone();
    let before = inverted_plan.source_range.end;
    inverted_plan.source_range.end = RangeEndV1::Inclusive(0);
    assert_ne!(inverted_plan.source_range.end, before);
    assert_eq!(
        validate_projection_plan(&client, &inverted_plan),
        Err(ProviderContractError::Invalid("projection plan binding"))
    );

    let mut zero_partition = plan.clone();
    let before = zero_partition.partitions[0].range.start;
    zero_partition.partitions[0].range.start = 0;
    assert_ne!(zero_partition.partitions[0].range.start, before);
    assert_eq!(
        validate_projection_plan(&client, &zero_partition),
        Err(ProviderContractError::Invalid("projection partitions"))
    );

    let mut inverted_partition = plan.clone();
    let before = inverted_partition.partitions[0].range.clone();
    inverted_partition.partitions[0].range = SourceRangeV1 {
        start: 5,
        end: RangeEndV1::Inclusive(4),
    };
    assert_ne!(inverted_partition.partitions[0].range, before);
    assert_eq!(
        validate_projection_plan(&client, &inverted_partition),
        Err(ProviderContractError::Invalid("projection partitions"))
    );

    let base = candidate_batch();
    let limit_error = Err(ProviderContractError::Invalid(
        "candidate projection batch limits",
    ));
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &base),
        Ok(())
    );

    let second_record = CandidateRecordV1 {
        sequence: 2,
        record_id: "record-2".into(),
        schema_digest: "schema".into(),
        normalized_digest: "record-digest-2".into(),
        block_number: 9,
        canonical_block_hash: "block-9".into(),
        evidence_digest: "record-evidence-2".into(),
    };
    let mut original_batch_limit = base.clone();
    let before = original_batch_limit.records.len();
    original_batch_limit.records.push(second_record.clone());
    assert_eq!(before, 1);
    assert_eq!(original_batch_limit.records.len(), 2);
    assert_ne!(original_batch_limit.records.len(), before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &original_batch_limit),
        limit_error
    );

    let mut plan_limited_client = client.clone();
    plan_limited_client.limits.max_batch = 2;
    assert_eq!(
        validate_candidate_projection_batch(&plan_limited_client, &plan, &base),
        Ok(())
    );
    let mut plan_batch_excess = base.clone();
    let before = plan_batch_excess.records.len();
    plan_batch_excess.records.push(second_record.clone());
    assert_ne!(plan_batch_excess.records.len(), before);
    assert_eq!(
        validate_candidate_projection_batch(&plan_limited_client, &plan, &plan_batch_excess),
        limit_error
    );

    let mut two_record_client = client.clone();
    two_record_client.limits.max_batch = 2;
    let mut two_record_plan = plan.clone();
    two_record_plan.limits.max_batch = 2;
    let mut exact_two_records = base.clone();
    exact_two_records.records.push(second_record);
    assert_eq!(exact_two_records.records.len(), 2);
    assert_eq!(
        validate_candidate_projection_batch(
            &two_record_client,
            &two_record_plan,
            &exact_two_records
        ),
        Ok(())
    );
    let mut three_records = exact_two_records;
    let before = three_records.records.len();
    three_records.records.push(CandidateRecordV1 {
        sequence: 3,
        record_id: "record-3".into(),
        schema_digest: "schema".into(),
        normalized_digest: "record-digest-3".into(),
        block_number: 8,
        canonical_block_hash: "block-8".into(),
        evidence_digest: "record-evidence-3".into(),
    });
    assert_eq!(before, 2);
    assert_eq!(three_records.records.len(), 3);
    assert_ne!(three_records.records.len(), before);
    assert_eq!(
        validate_candidate_projection_batch(&two_record_client, &two_record_plan, &three_records),
        limit_error
    );

    let mut extended_client = client.clone();
    extended_client.source_range.end = RangeEndV1::Inclusive(11);
    let mut extended_plan = plan.clone();
    extended_plan.source_range.end = RangeEndV1::Inclusive(11);
    extended_plan.partitions[0].range.end = RangeEndV1::Inclusive(11);
    assert_eq!(
        validate_candidate_projection_batch(&extended_client, &extended_plan, &base),
        Ok(())
    );
    let mut profile_range_excess = base.clone();
    let before = profile_range_excess.range.end;
    profile_range_excess.range.end = 11;
    assert_eq!(before, 10);
    assert_eq!(profile_range_excess.range.end, 11);
    assert_ne!(profile_range_excess.range.end, before);
    assert_eq!(
        validate_candidate_projection_batch(
            &extended_client,
            &extended_plan,
            &profile_range_excess
        ),
        limit_error
    );

    let mut narrowed_plan = extended_plan.clone();
    narrowed_plan.limits.max_range = 5;
    let mut exact_narrowed_range = base.clone();
    exact_narrowed_range.range.end = 5;
    exact_narrowed_range.observations[0].anchor.block_number = Some(5);
    exact_narrowed_range.observations[0].anchor.block_hash = Some("block-5".into());
    exact_narrowed_range.records[0].block_number = 5;
    exact_narrowed_range.records[0].canonical_block_hash = "block-5".into();
    exact_narrowed_range.completed_watermark.block_number = 5;
    exact_narrowed_range
        .completed_watermark
        .canonical_block_hash = "block-5".into();
    assert_eq!(
        validate_candidate_projection_batch(
            &extended_client,
            &narrowed_plan,
            &exact_narrowed_range
        ),
        Ok(())
    );
    let mut plan_range_excess = exact_narrowed_range;
    let before = plan_range_excess.range.end;
    plan_range_excess.range.end = 6;
    assert_eq!(before, 5);
    assert_eq!(plan_range_excess.range.end, 6);
    assert_ne!(plan_range_excess.range.end, before);
    assert_eq!(
        validate_candidate_projection_batch(&extended_client, &narrowed_plan, &plan_range_excess),
        limit_error
    );

    let mut open_client = client.clone();
    open_client.source_range.end = RangeEndV1::Open;
    let mut open_plan = plan.clone();
    open_plan.source_range.end = RangeEndV1::Open;
    open_plan.partitions[0].range.end = RangeEndV1::Open;
    assert_eq!(
        validate_candidate_projection_batch(&open_client, &open_plan, &base),
        Ok(())
    );

    let mut inverted = base.clone();
    let before = inverted.range.start;
    inverted.range.start = 11;
    assert_eq!(before, 1);
    assert_eq!(inverted.range.start, 11);
    assert_ne!(inverted.range.start, before);
    assert!(inverted.range.start > inverted.range.end);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &inverted),
        limit_error
    );

    let mut zero_range = base.clone();
    let before = zero_range.range.start;
    zero_range.range.start = 0;
    assert_eq!(before, 1);
    assert_eq!(zero_range.range.start, 0);
    assert_ne!(zero_range.range.start, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &zero_range),
        limit_error
    );

    let mut arithmetic_client = open_client;
    arithmetic_client.limits.max_range = u64::MAX;
    let mut arithmetic_plan = open_plan;
    arithmetic_plan.limits.max_range = u64::MAX;
    let mut maximum_span = base;
    maximum_span.range.end = u64::MAX;
    assert_eq!(
        validate_candidate_projection_batch(&arithmetic_client, &arithmetic_plan, &maximum_span),
        Ok(())
    );
}

#[test]
fn candidate_predecessor_continuity_is_checked() {
    let mut client = client_indexer();
    client.source_range = SourceRangeV1 {
        start: u64::MAX - 1,
        end: RangeEndV1::Inclusive(u64::MAX),
    };
    client.limits.max_range = 2;
    let mut plan = projection_plan();
    plan.source_range = client.source_range.clone();
    plan.partitions[0].range = client.source_range.clone();
    plan.limits.max_range = 2;
    assert_eq!(validate_projection_plan(&client, &plan), Ok(()));

    let mut adjacent_plan = plan.clone();
    adjacent_plan.partitions[0].range.end = RangeEndV1::Inclusive(u64::MAX - 1);
    adjacent_plan.partitions.push(ProjectionPartitionV1 {
        partition_id: "partition-max".into(),
        source_id: "source".into(),
        range: SourceRangeV1 {
            start: u64::MAX,
            end: RangeEndV1::Inclusive(u64::MAX),
        },
        state: PartitionState::Complete,
        finality_digest: "finality".into(),
        checkpoint_digest: "checkpoint-max".into(),
    });
    assert_eq!(validate_projection_plan(&client, &adjacent_plan), Ok(()));

    let mut overflow_client = client.clone();
    overflow_client.source_range.start = 1;
    let mut overflowing_adjacency = plan.clone();
    overflowing_adjacency.source_range.start = 1;
    overflowing_adjacency.partitions[0].range.start = 1;
    overflowing_adjacency
        .partitions
        .push(ProjectionPartitionV1 {
            partition_id: "partition-after-max".into(),
            source_id: "source".into(),
            range: SourceRangeV1 {
                start: u64::MAX,
                end: RangeEndV1::Inclusive(u64::MAX),
            },
            state: PartitionState::Complete,
            finality_digest: "finality".into(),
            checkpoint_digest: "checkpoint-after-max".into(),
        });
    assert_eq!(
        validate_projection_plan(&overflow_client, &overflowing_adjacency),
        Err(ProviderContractError::Invalid("partition range overflow"))
    );

    let mut prior = candidate_batch();
    prior.batch_sequence = u64::MAX - 1;
    prior.range = InclusiveRangeV1 {
        start: u64::MAX - 1,
        end: u64::MAX - 1,
    };
    prior.observations[0].anchor.block_number = Some(u64::MAX - 1);
    prior.observations[0].anchor.block_hash = Some("block-max-minus-one".into());
    prior.records[0].block_number = u64::MAX - 1;
    prior.records[0].canonical_block_hash = "block-max-minus-one".into();
    prior.completed_watermark.block_number = u64::MAX - 1;
    prior.completed_watermark.canonical_block_hash = "block-max-minus-one".into();

    let mut next = candidate_batch();
    next.batch_sequence = u64::MAX;
    next.range = InclusiveRangeV1 {
        start: u64::MAX,
        end: u64::MAX,
    };
    next.observations[0].anchor.block_number = Some(u64::MAX);
    next.observations[0].anchor.block_hash = Some("block-max".into());
    next.records[0].block_number = u64::MAX;
    next.records[0].canonical_block_hash = "block-max".into();
    next.completed_watermark.block_number = u64::MAX;
    next.completed_watermark.canonical_block_hash = "block-max".into();
    next.predecessor_batch_digest = "prior-digest".into();
    assert_eq!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &next,
            Some((&prior, "prior-digest")),
        ),
        Ok(())
    );

    let predecessor_error = Err(ProviderContractError::Invalid(
        "candidate predecessor relation",
    ));
    let mut maximum_sequence = prior.clone();
    let sequence_before = maximum_sequence.batch_sequence;
    maximum_sequence.batch_sequence = u64::MAX;
    assert_ne!(maximum_sequence.batch_sequence, sequence_before);
    assert_eq!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &next,
            Some((&maximum_sequence, "prior-digest")),
        ),
        predecessor_error
    );

    let mut maximum_range_end = prior;
    let range_end_before = maximum_range_end.range.end;
    maximum_range_end.range.end = u64::MAX;
    assert_ne!(maximum_range_end.range.end, range_end_before);
    assert_eq!(
        validate_candidate_projection_batch_with_predecessor(
            &client,
            &plan,
            &next,
            Some((&maximum_range_end, "prior-digest")),
        ),
        predecessor_error
    );
}

#[test]
fn candidate_missing_intervals_are_contained_and_watermark_safe() {
    let client = client_indexer();
    let plan = projection_plan();
    let mut base = candidate_batch();
    base.records[0].block_number = 5;
    base.records[0].canonical_block_hash = "block-5".into();
    base.observations[0].anchor.block_number = Some(5);
    base.observations[0].anchor.block_hash = Some("block-5".into());
    base.completed_watermark.block_number = 5;
    base.completed_watermark.canonical_block_hash = "block-5".into();
    base.missing_intervals = vec![InclusiveRangeV1 { start: 6, end: 10 }];
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &base),
        Ok(())
    );

    let mut noncanonical = base.clone();
    let before = noncanonical.missing_intervals.clone();
    noncanonical.missing_intervals = vec![
        InclusiveRangeV1 { start: 6, end: 8 },
        InclusiveRangeV1 { start: 8, end: 9 },
    ];
    assert_ne!(noncanonical.missing_intervals, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &noncanonical),
        Err(ProviderContractError::Invalid(
            "missing interval canonicality"
        ))
    );

    let mut outside = base.clone();
    let before = outside.missing_intervals[0].end;
    outside.missing_intervals[0].end = 11;
    assert_ne!(outside.missing_intervals[0].end, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &outside),
        Err(ProviderContractError::Invalid(
            "missing interval containment"
        ))
    );

    let mut inverted = base.clone();
    let before = inverted.missing_intervals[0].end;
    inverted.missing_intervals[0].end = 5;
    assert_ne!(inverted.missing_intervals[0].end, before);
    assert!(inverted.missing_intervals[0].start > inverted.missing_intervals[0].end);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &inverted),
        Err(ProviderContractError::Invalid(
            "missing interval canonicality"
        ))
    );

    let mut before_owner = base.clone();
    let before = before_owner.missing_intervals[0].clone();
    before_owner.missing_intervals[0] = InclusiveRangeV1 { start: 0, end: 1 };
    assert_ne!(before_owner.missing_intervals[0], before);
    assert!(before_owner.missing_intervals[0].start < before_owner.range.start);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &before_owner),
        Err(ProviderContractError::Invalid(
            "missing interval containment"
        ))
    );

    let mut before_watermark = base;
    let before = before_watermark.missing_intervals[0].start;
    before_watermark.missing_intervals[0].start = 5;
    assert_ne!(before_watermark.missing_intervals[0].start, before);
    assert_eq!(
        validate_candidate_projection_batch(&client, &plan, &before_watermark),
        Err(ProviderContractError::Invalid("missing interval watermark"))
    );
}
