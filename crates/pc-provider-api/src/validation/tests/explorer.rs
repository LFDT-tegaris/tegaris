use super::super::*;
type ExplorerProfileMutation = (&'static str, fn(&mut ExplorerFactSourceProfileV1));
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

fn explorer_profile() -> ExplorerFactSourceProfileV1 {
    ExplorerFactSourceProfileV1 {
        adapter_contract_id: "OPENEXPLORER_FACT_SOURCE_V1".into(),
        adapter_contract_version: "1.0.0".into(),
        adapter_schema_digest: "schema".into(),
        profile_id: "explorer".into(),
        profile_version: "1".into(),
        profile_digest: "explorer-digest".into(),
        product_id: "product".into(),
        instance_id: "instance".into(),
        release_digest: "release".into(),
        build_digest: "build".into(),
        api_digest: "api".into(),
        current_receipt_digest: "receipt".into(),
        participant_binding: "participant".into(),
        privacy_binding: "privacy".into(),
        source_trust_binding: "trust".into(),
        supported_fact_profiles: vec!["fact".into()],
        dynamic_event_schemas: vec![named("event")],
        allowed_operations: vec!["read".into()],
        allowed_data_classes: vec!["event".into()],
        allowed_fields: vec!["field".into()],
        allowed_filters: vec!["filter".into()],
        limits: limits(),
        page_limits: ExplorerPageLimitsV1 {
            max_page_items: 1,
            max_page_bytes: 1,
        },
        checkpoint_protocol_digest: "checkpoint".into(),
        resume_protocol_digest: "resume".into(),
        response_schema_digests: vec![named("response")],
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        source_partitions: vec![ProjectionPartitionV1 {
            partition_id: "explorer-partition".into(),
            source_id: "instance".into(),
            range: source_range(),
            state: PartitionState::Complete,
            finality_digest: "finality".into(),
            checkpoint_digest: "checkpoint".into(),
        }],
        scope_digests: vec![named("scope")],
        canonicality_digest: "canonicality".into(),
        finality_digest: "finality".into(),
        reorg_digest: "reorg".into(),
        removal_digest: "removal".into(),
        completeness_digest: "completeness".into(),
        watermark_digest: "watermark".into(),
        freshness_digest: "freshness".into(),
        trust_digest: "trust".into(),
        revocation_digest: "revocation".into(),
        provenance_digest: "provenance".into(),
        conflict_digest: "conflict".into(),
        privacy_projection_digest: "projection".into(),
        redaction_digest: "redaction".into(),
        hmac_key_version: "key-v1".into(),
        privacy_evidence_digest: "privacy-evidence".into(),
        telemetry_classifications: vec!["telemetry".into()],
        rate_law_digest: "rate".into(),
        timeout_law_digest: "timeout".into(),
        retry_law_digest: "retry".into(),
        lifecycle: ExplorerLifecycle::Active,
        upgrade_digest: "upgrade".into(),
        rollback_digest: "rollback".into(),
        disable_digest: "disable".into(),
        uninstall_digest: "uninstall".into(),
        corpus_digest: "corpus".into(),
        conformance_receipt_digest: "receipt".into(),
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

fn explorer_page() -> ExplorerCandidatePageV1 {
    ExplorerCandidatePageV1 {
        request_id: "request".into(),
        participant_binding: "participant".into(),
        privacy_binding: "privacy".into(),
        profile_id: "explorer".into(),
        profile_version: "1".into(),
        profile_digest: "explorer-digest".into(),
        source_instance_id: "instance".into(),
        authorized_scope_digest: "scope-digest".into(),
        range: inclusive_range(),
        page_id: "page".into(),
        resume_cursor: ExplorerCursorV1::Initial,
        response_digest: "response".into(),
        records: vec![CandidateRecordV1 {
            sequence: 1,
            record_id: "page-record".into(),
            schema_digest: "schema".into(),
            normalized_digest: "digest".into(),
            block_number: 10,
            canonical_block_hash: "block-10".into(),
            evidence_digest: "evidence".into(),
        }],
        missing_intervals: vec![],
        completed_watermark: CompletedWatermarkV1 {
            block_number: 10,
            canonical_block_hash: "block-10".into(),
        },
        reorg_observations: vec![],
        removal_observations: vec![],
        derivation_digest: "derivation".into(),
        provenance_digest: "provenance".into(),
        evidence_refs: vec!["page-evidence".into()],
        next_cursor: ExplorerCursorV1::Complete,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

#[test]
fn identity_accepts() {
    let value = explorer_profile();
    assert!(validate_explorer_profile(&value).is_ok());
    let mutations: &[ExplorerProfileMutation] = &[
        ("adapter_id", |v| v.adapter_contract_id = "other".into()),
        ("adapter_version", |v| {
            v.adapter_contract_version = "2.0.0".into()
        }),
        ("adapter_schema", |v| v.adapter_schema_digest.clear()),
        ("profile_id", |v| v.profile_id.clear()),
        ("profile_version", |v| v.profile_version.clear()),
        ("profile_digest", |v| v.profile_digest.clear()),
        ("product", |v| v.product_id.clear()),
        ("instance", |v| v.instance_id.clear()),
        ("release", |v| v.release_digest.clear()),
        ("build", |v| v.build_digest.clear()),
        ("api", |v| v.api_digest.clear()),
        ("receipt", |v| v.current_receipt_digest.clear()),
        ("participant", |v| v.participant_binding.clear()),
        ("privacy", |v| v.privacy_binding.clear()),
        ("trust", |v| v.source_trust_binding.clear()),
    ];
    for (name, mutate) in mutations {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_explorer_profile(&drift).is_err(), "{name}");
    }
}

#[test]
fn query_scope_accepts() {
    let value = explorer_profile();
    let mutations: &[ExplorerProfileMutation] = &[
        ("facts", |v| v.supported_fact_profiles.clear()),
        ("events", |v| v.dynamic_event_schemas.clear()),
        ("operations", |v| v.allowed_operations.clear()),
        ("classes", |v| v.allowed_data_classes.clear()),
        ("fields", |v| v.allowed_fields.clear()),
        ("filters", |v| v.allowed_filters.clear()),
        ("limits", |v| v.limits.max_range = 0),
        ("page_items", |v| v.page_limits.max_page_items = 0),
        ("page_bytes", |v| v.page_limits.max_page_bytes = 0),
        ("checkpoint", |v| v.checkpoint_protocol_digest.clear()),
        ("resume", |v| v.resume_protocol_digest.clear()),
        ("responses", |v| v.response_schema_digests.clear()),
        ("chain", |v| v.chain_id.clear()),
        ("genesis", |v| v.genesis_hash.clear()),
        ("network", |v| v.network_id.clear()),
        ("partitions", |v| v.source_partitions.clear()),
        ("scopes", |v| v.scope_digests.clear()),
    ];
    for (name, mutate) in mutations {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_explorer_profile(&drift).is_err(), "{name}");
    }
}

#[test]
fn truth_privacy_lifecycle_accepts() {
    let value = explorer_profile();
    let mutations: &[ExplorerProfileMutation] = &[
        ("canonicality", |v| v.canonicality_digest.clear()),
        ("finality", |v| v.finality_digest.clear()),
        ("reorg", |v| v.reorg_digest.clear()),
        ("removal", |v| v.removal_digest.clear()),
        ("completeness", |v| v.completeness_digest.clear()),
        ("watermark", |v| v.watermark_digest.clear()),
        ("freshness", |v| v.freshness_digest.clear()),
        ("trust", |v| v.trust_digest.clear()),
        ("revocation", |v| v.revocation_digest.clear()),
        ("provenance", |v| v.provenance_digest.clear()),
        ("conflict", |v| v.conflict_digest.clear()),
        ("projection", |v| v.privacy_projection_digest.clear()),
        ("redaction", |v| v.redaction_digest.clear()),
        ("hmac", |v| v.hmac_key_version.clear()),
        ("privacy_evidence", |v| v.privacy_evidence_digest.clear()),
        ("telemetry", |v| v.telemetry_classifications.clear()),
        ("rate", |v| v.rate_law_digest.clear()),
        ("timeout", |v| v.timeout_law_digest.clear()),
        ("retry", |v| v.retry_law_digest.clear()),
        ("upgrade", |v| v.upgrade_digest.clear()),
        ("rollback", |v| v.rollback_digest.clear()),
        ("disable", |v| v.disable_digest.clear()),
        ("uninstall", |v| v.uninstall_digest.clear()),
        ("corpus", |v| v.corpus_digest.clear()),
        ("conformance", |v| v.conformance_receipt_digest.clear()),
        ("lifecycle", |v| {
            v.lifecycle = ExplorerLifecycle::DesignTarget
        }),
    ];
    for (name, mutate) in mutations {
        let mut drift = value.clone();
        mutate(&mut drift);
        assert!(validate_explorer_profile(&drift).is_err(), "{name}");
    }
}

#[test]
fn page_relations_accept() {
    let profile = explorer_profile();
    let page = explorer_page();
    assert!(validate_explorer_page(&profile, &page).is_ok());
    for mutate in [
        |v: &mut ExplorerCandidatePageV1| v.request_id.clear(),
        |v: &mut ExplorerCandidatePageV1| v.participant_binding = "other".into(),
        |v: &mut ExplorerCandidatePageV1| v.privacy_binding = "other".into(),
        |v: &mut ExplorerCandidatePageV1| v.profile_digest = "other".into(),
        |v: &mut ExplorerCandidatePageV1| v.source_instance_id = "other".into(),
        |v: &mut ExplorerCandidatePageV1| v.authorized_scope_digest = "other".into(),
        |v: &mut ExplorerCandidatePageV1| v.records[0].block_number = 11,
        |v: &mut ExplorerCandidatePageV1| {
            v.missing_intervals = vec![InclusiveRangeV1 { start: 9, end: 10 }]
        },
        |v: &mut ExplorerCandidatePageV1| v.next_cursor = ExplorerCursorV1::Initial,
        |v: &mut ExplorerCandidatePageV1| v.derivation_digest.clear(),
        |v: &mut ExplorerCandidatePageV1| v.provenance_digest.clear(),
    ] {
        let mut drift = page.clone();
        mutate(&mut drift);
        assert!(validate_explorer_page(&profile, &drift).is_err());
    }
    let mut reorg = page;
    reorg.reorg_observations.push(SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(9),
            block_hash: Some("block-9".into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: "reorg".into(),
        evidence_digest: "reorg-evidence".into(),
    });
    assert!(validate_explorer_page(&profile, &reorg).is_err());
}

#[test]
fn explorer_page_item_limit_counts_records() {
    let profile = explorer_profile();
    let base = explorer_page();
    let limit_error = Err(ProviderContractError::Invalid(
        "explorer candidate page limits",
    ));
    assert_eq!(validate_explorer_page(&profile, &base), Ok(()));

    let second_record = CandidateRecordV1 {
        sequence: 2,
        record_id: "page-record-2".into(),
        schema_digest: "schema".into(),
        normalized_digest: "digest-2".into(),
        block_number: 9,
        canonical_block_hash: "block-9".into(),
        evidence_digest: "evidence-2".into(),
    };

    let mut page_item_profile = profile.clone();
    page_item_profile.limits.max_batch = 2;
    assert_eq!(validate_explorer_page(&page_item_profile, &base), Ok(()));
    let mut page_item_excess = base.clone();
    let before = page_item_excess.records.len();
    page_item_excess.records.push(second_record.clone());
    assert_eq!(before, 1);
    assert_eq!(page_item_excess.records.len(), 2);
    assert_ne!(page_item_excess.records.len(), before);
    assert_eq!(
        validate_explorer_page(&page_item_profile, &page_item_excess),
        limit_error
    );

    let mut batch_limit_profile = profile.clone();
    batch_limit_profile.page_limits.max_page_items = 2;
    assert_eq!(validate_explorer_page(&batch_limit_profile, &base), Ok(()));
    let mut batch_limit_excess = base.clone();
    let before = batch_limit_excess.records.len();
    batch_limit_excess.records.push(second_record);
    assert_eq!(before, 1);
    assert_eq!(batch_limit_excess.records.len(), 2);
    assert_ne!(batch_limit_excess.records.len(), before);
    assert_eq!(
        validate_explorer_page(&batch_limit_profile, &batch_limit_excess),
        limit_error
    );

    let mut extended_profile = profile.clone();
    let partition_end_before = extended_profile.source_partitions[0].range.end;
    extended_profile.source_partitions[0].range.end = RangeEndV1::Inclusive(11);
    assert_ne!(
        extended_profile.source_partitions[0].range.end,
        partition_end_before
    );
    assert_eq!(validate_explorer_page(&extended_profile, &base), Ok(()));
    let mut range_excess = base.clone();
    let before = range_excess.range.end;
    range_excess.range.end = 11;
    assert_eq!(before, 10);
    assert_eq!(range_excess.range.end, 11);
    assert_ne!(range_excess.range.end, before);
    assert_eq!(
        validate_explorer_page(&extended_profile, &range_excess),
        limit_error
    );

    let mut zero_range = base.clone();
    let before = zero_range.range.start;
    zero_range.range.start = 0;
    assert_eq!(before, 1);
    assert_eq!(zero_range.range.start, 0);
    assert_ne!(zero_range.range.start, before);
    assert_eq!(validate_explorer_page(&profile, &zero_range), limit_error);

    let mut inverted_range = base.clone();
    let before = inverted_range.range.start;
    inverted_range.range.start = 11;
    assert_eq!(before, 1);
    assert_eq!(inverted_range.range.start, 11);
    assert_ne!(inverted_range.range.start, before);
    assert!(inverted_range.range.start > inverted_range.range.end);
    assert_eq!(
        validate_explorer_page(&profile, &inverted_range),
        limit_error
    );

    let mut evidence_profile = profile;
    evidence_profile.source_partitions[0].state = PartitionState::Recovering;
    let mut evidence_heavy = base;
    evidence_heavy.records[0].block_number = 5;
    evidence_heavy.records[0].canonical_block_hash = "block-5".into();
    evidence_heavy.completed_watermark.block_number = 5;
    evidence_heavy.completed_watermark.canonical_block_hash = "block-5".into();
    evidence_heavy.missing_intervals = vec![InclusiveRangeV1 { start: 6, end: 7 }];
    evidence_heavy.reorg_observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(8),
            block_hash: Some("block-8".into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: "reorg-8".into(),
        evidence_digest: "reorg-evidence-8".into(),
    }];
    evidence_heavy.removal_observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            block_number: Some(9),
            block_hash: Some("block-9".into()),
            ..evidence_heavy.reorg_observations[0].anchor.clone()
        },
        normalized_digest: "removal-9".into(),
        evidence_digest: "removal-evidence-9".into(),
    }];
    evidence_heavy.next_cursor = ExplorerCursorV1::Resume {
        digest: "next".into(),
    };
    assert_eq!(
        validate_explorer_page(&evidence_profile, &evidence_heavy),
        Ok(())
    );
}

#[test]
fn explorer_missing_intervals_are_contained_and_watermark_safe() {
    let mut profile = explorer_profile();
    profile.source_partitions[0].state = PartitionState::GapBlocked;
    let mut base = explorer_page();
    base.records[0].block_number = 5;
    base.records[0].canonical_block_hash = "block-5".into();
    base.completed_watermark.block_number = 5;
    base.completed_watermark.canonical_block_hash = "block-5".into();
    base.missing_intervals = vec![InclusiveRangeV1 { start: 6, end: 10 }];
    base.next_cursor = ExplorerCursorV1::Resume {
        digest: "next".into(),
    };
    assert_eq!(validate_explorer_page(&profile, &base), Ok(()));

    let mut noncanonical = base.clone();
    let before = noncanonical.missing_intervals.clone();
    noncanonical.missing_intervals = vec![
        InclusiveRangeV1 { start: 6, end: 8 },
        InclusiveRangeV1 { start: 8, end: 9 },
    ];
    assert_ne!(noncanonical.missing_intervals, before);
    assert_eq!(
        validate_explorer_page(&profile, &noncanonical),
        Err(ProviderContractError::Invalid(
            "missing interval canonicality"
        ))
    );

    let mut outside = base.clone();
    let before = outside.missing_intervals[0].end;
    outside.missing_intervals[0].end = 11;
    assert_ne!(outside.missing_intervals[0].end, before);
    assert_eq!(
        validate_explorer_page(&profile, &outside),
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
        validate_explorer_page(&profile, &inverted),
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
        validate_explorer_page(&profile, &before_owner),
        Err(ProviderContractError::Invalid(
            "missing interval containment"
        ))
    );

    let mut before_watermark = base.clone();
    let before = before_watermark.missing_intervals[0].start;
    before_watermark.missing_intervals[0].start = 5;
    assert_ne!(before_watermark.missing_intervals[0].start, before);
    assert_eq!(
        validate_explorer_page(&profile, &before_watermark),
        Err(ProviderContractError::Invalid("missing interval watermark"))
    );

    let mut completed_with_gap = base;
    let before = completed_with_gap.next_cursor.clone();
    completed_with_gap.next_cursor = ExplorerCursorV1::Complete;
    assert_ne!(completed_with_gap.next_cursor, before);
    assert_eq!(
        validate_explorer_page(&profile, &completed_with_gap),
        Err(ProviderContractError::Invalid("explorer partition state"))
    );
}

#[test]
fn explorer_page_canonical_hashes_are_coherent() {
    let mut profile = explorer_profile();
    profile.source_partitions[0].state = PartitionState::Recovering;
    profile.page_limits.max_page_items = 2;
    profile.limits.max_batch = 2;
    let mut base = explorer_page();
    base.records[0].block_number = 5;
    base.records[0].canonical_block_hash = "block-5".into();
    base.records.push(CandidateRecordV1 {
        sequence: 2,
        record_id: "page-record-8".into(),
        schema_digest: "schema".into(),
        normalized_digest: "digest-8".into(),
        block_number: 8,
        canonical_block_hash: "block-8".into(),
        evidence_digest: "evidence-8".into(),
    });
    base.completed_watermark.block_number = 5;
    base.completed_watermark.canonical_block_hash = "block-5".into();
    base.reorg_observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(8),
            block_hash: Some("block-8".into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: "reorg-8".into(),
        evidence_digest: "reorg-evidence-8".into(),
    }];
    base.removal_observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: base.reorg_observations[0].anchor.clone(),
        normalized_digest: "removal-8".into(),
        evidence_digest: "removal-evidence-8".into(),
    }];
    base.next_cursor = ExplorerCursorV1::Resume {
        digest: "next".into(),
    };
    assert_eq!(validate_explorer_page(&profile, &base), Ok(()));

    let mut record_drift = base.clone();
    let before = record_drift.records[1].canonical_block_hash.clone();
    record_drift.records[1].canonical_block_hash = "record-8-drift".into();
    assert_ne!(record_drift.records[1].canonical_block_hash, before);
    assert_eq!(
        validate_explorer_page(&profile, &record_drift),
        Err(ProviderContractError::Invalid(
            "explorer canonical anchor coherence"
        ))
    );

    let mut reorg_drift = base.clone();
    let before = reorg_drift.reorg_observations[0].anchor.block_hash.clone();
    reorg_drift.reorg_observations[0].anchor.block_hash = Some("reorg-8-drift".into());
    assert_ne!(reorg_drift.reorg_observations[0].anchor.block_hash, before);
    assert_eq!(
        validate_explorer_page(&profile, &reorg_drift),
        Err(ProviderContractError::Invalid(
            "explorer canonical anchor coherence"
        ))
    );

    let mut removal_drift = base.clone();
    let before = removal_drift.removal_observations[0]
        .anchor
        .block_hash
        .clone();
    removal_drift.removal_observations[0].anchor.block_hash = Some("removal-8-drift".into());
    assert_ne!(
        removal_drift.removal_observations[0].anchor.block_hash,
        before
    );
    assert_eq!(
        validate_explorer_page(&profile, &removal_drift),
        Err(ProviderContractError::Invalid(
            "explorer canonical anchor coherence"
        ))
    );

    let mut watermark_drift = base;
    let before = watermark_drift
        .completed_watermark
        .canonical_block_hash
        .clone();
    watermark_drift.completed_watermark.canonical_block_hash = "watermark-5-drift".into();
    assert_ne!(
        watermark_drift.completed_watermark.canonical_block_hash,
        before
    );
    assert_eq!(
        validate_explorer_page(&profile, &watermark_drift),
        Err(ProviderContractError::Invalid(
            "explorer canonical anchor coherence"
        ))
    );
}

#[test]
fn explorer_authoritative_empty_is_exact() {
    let profile = explorer_profile();
    let mut base = explorer_page();
    base.records.clear();
    assert_eq!(validate_explorer_page(&profile, &base), Ok(()));

    let mut resumed = base.clone();
    resumed.resume_cursor = ExplorerCursorV1::Resume {
        digest: "incoming".into(),
    };
    assert_eq!(validate_explorer_page(&profile, &resumed), Ok(()));

    let authoritative_error = Err(ProviderContractError::Invalid(
        "explorer authoritative empty",
    ));

    let mut next_resume = base.clone();
    let before = next_resume.next_cursor.clone();
    next_resume.next_cursor = ExplorerCursorV1::Resume {
        digest: "next".into(),
    };
    assert_ne!(next_resume.next_cursor, before);
    assert_eq!(
        validate_explorer_page(&profile, &next_resume),
        authoritative_error
    );

    let mut missing = base.clone();
    let before = missing.missing_intervals.clone();
    missing.missing_intervals = vec![InclusiveRangeV1 { start: 9, end: 10 }];
    assert_ne!(missing.missing_intervals, before);
    assert_eq!(
        validate_explorer_page(&profile, &missing),
        Err(ProviderContractError::Invalid("explorer partition state"))
    );

    let mut watermark_inside = base.clone();
    let before = watermark_inside.completed_watermark.block_number;
    watermark_inside.completed_watermark.block_number = 9;
    assert_ne!(watermark_inside.completed_watermark.block_number, before);
    assert!(watermark_inside.completed_watermark.block_number < watermark_inside.range.end);
    assert_eq!(
        validate_explorer_page(&profile, &watermark_inside),
        authoritative_error
    );

    let mut watermark_outside = base.clone();
    let before = watermark_outside.completed_watermark.block_number;
    watermark_outside.completed_watermark.block_number = 11;
    assert_ne!(watermark_outside.completed_watermark.block_number, before);
    assert!(watermark_outside.completed_watermark.block_number > watermark_outside.range.end);
    assert_eq!(
        validate_explorer_page(&profile, &watermark_outside),
        Err(ProviderContractError::Invalid("explorer candidate page"))
    );

    let observation = SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(10),
            block_hash: Some("block-10".into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: "observation".into(),
        evidence_digest: "observation-evidence".into(),
    };
    let mut reorg = base.clone();
    let before = reorg.reorg_observations.clone();
    reorg.reorg_observations = vec![observation.clone()];
    assert_ne!(reorg.reorg_observations, before);
    assert_eq!(
        validate_explorer_page(&profile, &reorg),
        Err(ProviderContractError::Invalid("explorer partition state"))
    );

    let mut removal = base.clone();
    let before = removal.removal_observations.clone();
    removal.removal_observations = vec![observation];
    assert_ne!(removal.removal_observations, before);
    assert_eq!(
        validate_explorer_page(&profile, &removal),
        Err(ProviderContractError::Invalid("explorer partition state"))
    );

    let mut empty_evidence = base.clone();
    let before = empty_evidence.evidence_refs.clone();
    empty_evidence.evidence_refs.clear();
    assert_ne!(empty_evidence.evidence_refs, before);
    assert_eq!(
        validate_explorer_page(&profile, &empty_evidence),
        Err(ProviderContractError::Invalid("explorer candidate page"))
    );

    let mut unowned_range = base;
    let range_before = unowned_range.range.clone();
    let watermark_before = unowned_range.completed_watermark.block_number;
    unowned_range.range = InclusiveRangeV1 { start: 11, end: 11 };
    unowned_range.completed_watermark.block_number = 11;
    assert_ne!(unowned_range.range, range_before);
    assert_ne!(
        unowned_range.completed_watermark.block_number,
        watermark_before
    );
    assert_eq!(
        unowned_range.completed_watermark.block_number,
        unowned_range.range.end
    );
    assert_eq!(
        validate_explorer_page(&profile, &unowned_range),
        Err(ProviderContractError::Invalid("explorer partition state"))
    );
}

#[test]
fn candidate_page_partition_state_is_eligible() {
    let state_error = Err(ProviderContractError::Invalid("explorer partition state"));
    let ordinary = explorer_page();
    let mut authoritative_empty = ordinary.clone();
    authoritative_empty.records.clear();

    for state in [
        PartitionState::Bootstrap,
        PartitionState::CatchingUp,
        PartitionState::Complete,
    ] {
        let mut profile = explorer_profile();
        profile.source_partitions[0].state = state;
        assert_eq!(validate_explorer_page(&profile, &ordinary), Ok(()));
        assert_eq!(
            validate_explorer_page(&profile, &authoritative_empty),
            Ok(())
        );
    }

    for state in [
        PartitionState::Quarantined,
        PartitionState::Disabled,
        PartitionState::Retired,
    ] {
        let mut profile = explorer_profile();
        profile.source_partitions[0].state = state;
        assert_eq!(validate_explorer_page(&profile, &ordinary), state_error);
    }

    let mut gap_page = ordinary.clone();
    gap_page.records.clear();
    gap_page.completed_watermark.block_number = 5;
    gap_page.completed_watermark.canonical_block_hash = "block-5".into();
    gap_page.missing_intervals = vec![InclusiveRangeV1 { start: 6, end: 10 }];
    gap_page.next_cursor = ExplorerCursorV1::Resume {
        digest: "gap-next".into(),
    };
    let mut gap_profile = explorer_profile();
    gap_profile.source_partitions[0].state = PartitionState::GapBlocked;
    assert_eq!(validate_explorer_page(&gap_profile, &gap_page), Ok(()));
    assert_eq!(validate_explorer_page(&gap_profile, &ordinary), state_error);
    assert_eq!(
        validate_explorer_page(&gap_profile, &authoritative_empty),
        state_error
    );
    let mut completed_gap = gap_page.clone();
    let cursor_before = completed_gap.next_cursor.clone();
    completed_gap.next_cursor = ExplorerCursorV1::Complete;
    assert_ne!(completed_gap.next_cursor, cursor_before);
    assert_eq!(
        validate_explorer_page(&gap_profile, &completed_gap),
        state_error
    );

    let mut invalidation_page = ordinary.clone();
    invalidation_page.records.clear();
    invalidation_page.completed_watermark.block_number = 5;
    invalidation_page.completed_watermark.canonical_block_hash = "block-5".into();
    invalidation_page.reorg_observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: ChainReadAnchorV1 {
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            selector_kind: BlockSelectorKind::Pinned,
            block_number: Some(6),
            block_hash: Some("block-6".into()),
            pending_authorized_by_profile: false,
        },
        normalized_digest: "reorg-6".into(),
        evidence_digest: "reorg-evidence-6".into(),
    }];
    invalidation_page.next_cursor = ExplorerCursorV1::Resume {
        digest: "reorg-next".into(),
    };
    let mut reorg_profile = explorer_profile();
    reorg_profile.source_partitions[0].state = PartitionState::ReorgFenced;
    assert_eq!(
        validate_explorer_page(&reorg_profile, &invalidation_page),
        Ok(())
    );
    assert_eq!(
        validate_explorer_page(&reorg_profile, &ordinary),
        state_error
    );
    assert_eq!(
        validate_explorer_page(&reorg_profile, &authoritative_empty),
        state_error
    );
    let mut fenced_with_record = invalidation_page.clone();
    let records_before = fenced_with_record.records.clone();
    fenced_with_record.records = ordinary.records.clone();
    assert_ne!(fenced_with_record.records, records_before);
    assert_eq!(
        validate_explorer_page(&reorg_profile, &fenced_with_record),
        state_error
    );
    let mut completed_invalidation = invalidation_page.clone();
    let cursor_before = completed_invalidation.next_cursor.clone();
    completed_invalidation.next_cursor = ExplorerCursorV1::Complete;
    assert_ne!(completed_invalidation.next_cursor, cursor_before);
    assert_eq!(
        validate_explorer_page(&reorg_profile, &completed_invalidation),
        state_error
    );
    assert_eq!(
        validate_explorer_page(&gap_profile, &invalidation_page),
        state_error
    );
    assert_eq!(
        validate_explorer_page(&reorg_profile, &gap_page),
        state_error
    );

    let mut complete_profile = explorer_profile();
    complete_profile.source_partitions[0].state = PartitionState::Complete;
    assert_eq!(
        validate_explorer_page(&complete_profile, &invalidation_page),
        state_error
    );

    let mut recovering_profile = explorer_profile();
    recovering_profile.source_partitions[0].state = PartitionState::Recovering;
    assert_eq!(
        validate_explorer_page(&recovering_profile, &ordinary),
        Ok(())
    );
    assert_eq!(
        validate_explorer_page(&recovering_profile, &gap_page),
        Ok(())
    );
    assert_eq!(
        validate_explorer_page(&recovering_profile, &invalidation_page),
        Ok(())
    );
    assert_eq!(
        validate_explorer_page(&recovering_profile, &fenced_with_record),
        Ok(())
    );
    assert_eq!(
        validate_explorer_page(&recovering_profile, &authoritative_empty),
        state_error
    );

    for state in [
        PartitionState::Quarantined,
        PartitionState::Disabled,
        PartitionState::Retired,
    ] {
        let mut profile = explorer_profile();
        profile.source_partitions[0].state = state;
        for page in [&authoritative_empty, &gap_page, &invalidation_page] {
            assert_eq!(validate_explorer_page(&profile, page), state_error);
        }
    }

    let mut ordinary_with_gap = ordinary.clone();
    ordinary_with_gap.completed_watermark.block_number = 5;
    ordinary_with_gap.completed_watermark.canonical_block_hash = "block-5".into();
    ordinary_with_gap.records[0].block_number = 5;
    ordinary_with_gap.records[0].canonical_block_hash = "block-5".into();
    ordinary_with_gap.missing_intervals = vec![InclusiveRangeV1 { start: 6, end: 10 }];
    ordinary_with_gap.next_cursor = ExplorerCursorV1::Resume {
        digest: "ordinary-gap-next".into(),
    };
    assert_eq!(
        validate_explorer_page(&explorer_profile(), &ordinary_with_gap),
        state_error
    );

    let mut frozen_too_late = gap_page;
    let watermark_before = frozen_too_late.completed_watermark.block_number;
    frozen_too_late.completed_watermark.block_number = 6;
    frozen_too_late.completed_watermark.canonical_block_hash = "block-6".into();
    assert_ne!(
        frozen_too_late.completed_watermark.block_number,
        watermark_before
    );
    assert_eq!(
        validate_explorer_page(&gap_profile, &frozen_too_late),
        Err(ProviderContractError::Invalid("missing interval watermark"))
    );

    let mut reorg_too_early = invalidation_page;
    let watermark_before = reorg_too_early.completed_watermark.block_number;
    reorg_too_early.completed_watermark.block_number = 6;
    reorg_too_early.completed_watermark.canonical_block_hash = "block-6".into();
    assert_ne!(
        reorg_too_early.completed_watermark.block_number,
        watermark_before
    );
    assert_eq!(
        validate_explorer_page(&reorg_profile, &reorg_too_early),
        Err(ProviderContractError::Invalid(
            "explorer range or watermark relation"
        ))
    );
}
