use super::*;
use crate::PurposeBoundFactSigner;

fn id(n: u8) -> String {
    format!("01950000-0000-7000-8000-{n:012x}")
}
fn fixture() -> (VerifiedShard, FactReference, PolicyFactSnapshot) {
    let owner = PurposeBoundFactSigner::from_secret_bytes(b"retained-fact-unit".to_vec(), [71; 32])
        .unwrap();
    let shard = owner.sign_shard(&id(1), &id(2), &id(3), [74; 32]).unwrap();
    let shard = owner.verifier().verify_shard(&shard).unwrap();
    let reference = FactReference {
        candidate_id: id(4),
        generation_id: id(3),
        fact_digest: format!("sha256:{}", "4b".repeat(32)),
    };
    let snapshot = PolicyFactSnapshot {
        outcome: FactQueryOutcome::Present,
        participant_id: id(1),
        privacy_domain_id: id(2),
        candidate_id: id(4),
        generation_id: id(3),
        fact_digest: vec![75; 32],
        shard_digest: Some(vec![74; 32]),
        observed_at_ms: 10,
        fresh_until_ms: 30,
        snapshot_at_ms: 20,
    };
    (shard, reference, snapshot)
}
fn provenance() -> serde_json::Value {
    serde_json::json!({
        "purpose":"openpc:independent-state-admission:v1", "sourceCandidateId":id(4), "sourceProfileId":id(5),
        "projectionPlanId":id(6), "sourceRevision":"2", "projectionRevision":"3",
        "qualificationOperationId":id(7), "validationOperationId":id(8),
        "configurationDigest":format!("sha256:{}", "11".repeat(32)),
        "sourceProfileDigest":"22".repeat(32), "mappingManifestDigest":"33".repeat(32),
        "publicationDigest":format!("sha256:{}", "44".repeat(32)),
        "partitionId":"domain-specific-partition-not-a-uuid"
    })
}
fn parse(value: &serde_json::Value) -> Result<RetainedFactSource, FactStoreError> {
    parse_source(
        &crate::state_value::canonical(value).unwrap(),
        &id(4),
        &id(5),
        &id(9),
        Uuid::parse_str(&id(10)).unwrap(),
    )
}
fn record() -> RetainedFactRecord {
    RetainedFactRecord {
        candidate: id(4),
        fact_id: format!("urn:openpc:fact:{}", id(11)),
        fact_digest: vec![75; 32],
        signed_digest: Digest::of(b"original signed fact"),
        provenance_digest: Digest::of(b"original signed provenance"),
        observed_at_ms: 10,
        fresh_until_ms: 30,
        source: parse(&provenance()).unwrap(),
    }
}

#[test]
fn exact_original_snapshot_is_required_even_with_a_valid_shard_signature() {
    let (shard, reference, original) = fixture();
    assert!(validate_inputs(&shard, std::slice::from_ref(&reference), 30_000_000, 100).is_ok());
    assert!(
        match_snapshots(
            &shard,
            std::slice::from_ref(&reference),
            std::slice::from_ref(&original)
        )
        .is_ok()
    );
    for case in 0..10 {
        let mut changed = original.clone();
        match case {
            0 => changed.participant_id = id(12),
            1 => changed.privacy_domain_id = id(12),
            2 => changed.candidate_id = id(12),
            3 => changed.generation_id = id(12),
            4 => changed.fact_digest[0] ^= 1,
            5 => changed.shard_digest = None,
            6 => changed.shard_digest = Some(vec![1; 32]),
            7 => changed.observed_at_ms = 21,
            8 => changed.fresh_until_ms = 20,
            _ => changed.observed_at_ms = -1,
        }
        assert!(
            match_snapshots(&shard, std::slice::from_ref(&reference), &[changed]).is_err(),
            "case {case}"
        );
    }
    assert!(match_snapshots(&shard, &[reference], &[]).is_err());
}

#[test]
fn no_negative_unknown_retired_or_reorg_outcome_becomes_custody() {
    let (shard, reference, original) = fixture();
    for outcome in [
        FactQueryOutcome::AbsentConfirmed,
        FactQueryOutcome::Denied,
        FactQueryOutcome::Unknown,
        FactQueryOutcome::NotReady,
        FactQueryOutcome::Unavailable,
        FactQueryOutcome::Stale,
        FactQueryOutcome::Reorg,
        FactQueryOutcome::Partial,
        FactQueryOutcome::Conflicting,
        FactQueryOutcome::Tampered,
    ] {
        let mut snapshot = original.clone();
        snapshot.outcome = outcome;
        assert!(
            match_snapshots(&shard, std::slice::from_ref(&reference), &[snapshot]).is_err(),
            "{outcome:?}"
        );
    }
}

#[test]
fn selectors_cannot_supply_aliases_duplicates_or_a_new_generation() {
    let (shard, reference, _) = fixture();
    assert!(validate_inputs(&shard, &[], 30, 100).is_err());
    assert!(validate_inputs(&shard, &[reference.clone(), reference.clone()], 30, 100).is_err());
    for case in 0..5 {
        let mut changed = reference.clone();
        match case {
            0 => changed.generation_id = id(12),
            1 => changed.candidate_id = "candidate-alias".into(),
            2 => changed.candidate_id = "01950000-0000-4000-8000-000000000004".into(),
            3 => changed.fact_digest = "4b".repeat(32),
            _ => changed.fact_digest = format!("sha256:{}", "4B".repeat(32)),
        }
        assert!(validate_inputs(&shard, &[changed], 30, 100).is_err());
    }
    for (until, budget) in [(0, 100), (30, 0), (30, 5001)] {
        assert!(validate_inputs(&shard, std::slice::from_ref(&reference), until, budget).is_err());
    }
}

#[test]
fn signed_provenance_retains_exact_source_ids_revisions_and_digest_spelling() {
    let value = provenance();
    let source = parse(&value).unwrap();
    assert_eq!(source.plan.to_string(), id(6));
    assert_eq!(source.source_profile.to_string(), id(5));
    assert_eq!(source.source_generation.to_string(), id(9));
    assert_eq!(source.partition.to_string(), id(10));
    for (field, replacement) in [
        ("purpose", "anything".into()),
        ("sourceCandidateId", id(15)),
        ("sourceProfileId", id(15)),
        ("projectionPlanId", "alias".into()),
        (
            "qualificationOperationId",
            "01950000-0000-4000-8000-000000000007".into(),
        ),
        ("sourceRevision", "0".into()),
        ("projectionRevision", "03".into()),
        ("sourceRevision", "9223372036854775808".into()),
        ("configurationDigest", "11".repeat(32)),
        ("publicationDigest", format!("sha256:{}", "AB".repeat(32))),
        ("sourceProfileDigest", format!("sha256:{}", "22".repeat(32))),
        ("mappingManifestDigest", "33".repeat(31)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement.into();
        assert!(parse(&changed).is_err(), "{field}");
    }
    for field in [
        "sourceProfileId",
        "validationOperationId",
        "configurationDigest",
        "publicationDigest",
    ] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(parse(&changed).is_err(), "missing {field}");
    }
    let mut numeric = value;
    numeric["sourceRevision"] = 2.into();
    assert!(parse(&numeric).is_err());
}

#[test]
fn noncanonical_or_trailing_provenance_and_wrong_receipt_identity_are_rejected() {
    let bytes = crate::state_value::canonical(&provenance()).unwrap();
    for invalid in [vec![], vec![0xbf, 0xff], [bytes.as_slice(), &[0]].concat()] {
        assert!(
            parse_source(
                &invalid,
                &id(4),
                &id(5),
                &id(9),
                Uuid::parse_str(&id(10)).unwrap()
            )
            .is_err()
        );
    }
    assert!(
        parse_source(
            &bytes,
            &id(4),
            &id(15),
            &id(9),
            Uuid::parse_str(&id(10)).unwrap()
        )
        .is_err()
    );
    assert!(
        parse_source(
            &bytes,
            &id(4),
            &id(5),
            "source-alias",
            Uuid::parse_str(&id(10)).unwrap()
        )
        .is_err()
    );
}

#[test]
fn original_expiry_is_never_renewed_by_a_later_capsule_or_a_new_read() {
    let original = record();
    assert_eq!(
        original_deadline(90_000_000, std::slice::from_ref(&original)).unwrap(),
        30_000_000
    );
    assert_eq!(
        original_deadline(15_000_000, std::slice::from_ref(&original)).unwrap(),
        15_000_000
    );
    let mut earlier = original.clone();
    earlier.fresh_until_ms = 20;
    assert_eq!(
        original_deadline(u64::MAX, &[original.clone(), earlier]).unwrap(),
        20_000_000
    );
    for expiry in [-1, 10, i64::MAX] {
        let mut changed = original.clone();
        changed.fresh_until_ms = expiry;
        assert!(original_deadline(u64::MAX, &[changed]).is_err());
    }
    assert!(original_deadline(u64::MAX, &[]).is_err());
}

#[tokio::test]
async fn malformed_input_is_denied_without_allocating_a_database_connection() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/openpc_facts")
        .unwrap();
    let signer =
        PurposeBoundFactSigner::from_secret_bytes(b"retained-fact-unit".to_vec(), [71; 32])
            .unwrap();
    let reader = PolicyFactReader::new(pool.clone(), signer.verifier());
    let (shard, reference, _) = fixture();
    assert!(
        reader
            .prepare_target_custody(&shard, &[reference], 30, 0)
            .await
            .is_err()
    );
    assert_eq!(pool.size(), 0);
    pool.close().await;
}

#[test]
fn native_commitments_have_independent_fixed_preimages_and_ignore_input_order() {
    let (shard, reference, _) = fixture();
    let original = record();
    let (dependencies, records) = original_commitments(
        &shard,
        std::slice::from_ref(&reference),
        std::slice::from_ref(&original),
    )
    .unwrap();
    // Independently encoded sorted-key compact JSON and SHA-256, not generated
    // by the Rust commitment producer. The two preimages are 420/1405 bytes.
    assert_eq!(
        dependencies.as_str(),
        "c292d5b8871a3f0723992280062751a9ab7554e00db0164b406fe68112c6ec20"
    );
    assert_eq!(
        records.as_str(),
        "502e3f7e7f815e159397b9f69e7296cca315a4420d6d21a17dc1521f0eba299f"
    );
    let mut other_reference = reference.clone();
    other_reference.candidate_id = id(12);
    let mut other_record = original.clone();
    other_record.candidate = id(12);
    other_record.fact_id = format!("urn:openpc:fact:{}", id(13));
    let ordered = original_commitments(
        &shard,
        &[reference.clone(), other_reference.clone()],
        &[original.clone(), other_record.clone()],
    )
    .unwrap();
    let reversed = original_commitments(
        &shard,
        &[other_reference, reference],
        &[other_record, original],
    )
    .unwrap();
    assert_eq!(ordered, reversed);
}

#[test]
fn native_original_commitment_binds_every_signed_and_source_qualification_field() {
    let (shard, reference, _) = fixture();
    let original = record();
    let expected = original_commitments(
        &shard,
        std::slice::from_ref(&reference),
        std::slice::from_ref(&original),
    )
    .unwrap();
    for case in 0..18 {
        let mut changed = original.clone();
        match case {
            0 => changed.fact_id = format!("urn:openpc:fact:{}", id(14)),
            1 => changed.fact_digest[0] ^= 1,
            2 => changed.signed_digest = Digest::of(b"other signature"),
            3 => changed.provenance_digest = Digest::of(b"other provenance"),
            4 => changed.observed_at_ms += 1,
            5 => changed.fresh_until_ms += 1,
            6 => changed.source.source_profile = Uuid::parse_str(&id(14)).unwrap(),
            7 => changed.source.plan = Uuid::parse_str(&id(14)).unwrap(),
            8 => changed.source.source_revision += 1,
            9 => changed.source.projection_revision += 1,
            10 => changed.source.qualification = Uuid::parse_str(&id(14)).unwrap(),
            11 => changed.source.validation = Uuid::parse_str(&id(14)).unwrap(),
            12 => changed.source.configuration = Digest::of(b"other configuration"),
            13 => changed.source.profile = Digest::of(b"other profile"),
            14 => changed.source.mapping = Digest::of(b"other mapping"),
            15 => changed.source.publication = Digest::of(b"other publication"),
            16 => changed.source.source_generation = Uuid::parse_str(&id(14)).unwrap(),
            _ => changed.source.partition = Uuid::parse_str(&id(14)).unwrap(),
        }
        let actual =
            original_commitments(&shard, std::slice::from_ref(&reference), &[changed]).unwrap();
        assert_eq!(
            actual.0, expected.0,
            "case {case}: selectors remain the original dependency"
        );
        assert_ne!(
            actual.1, expected.1,
            "case {case}: original tuple cannot be substituted"
        );
    }
}

#[test]
fn native_commitment_rejects_missing_duplicate_or_foreign_record_sets() {
    let (shard, reference, _) = fixture();
    let original = record();
    assert!(original_commitments(&shard, std::slice::from_ref(&reference), &[]).is_err());
    assert!(
        original_commitments(
            &shard,
            std::slice::from_ref(&reference),
            &[original.clone(), original.clone()]
        )
        .is_err()
    );
    let mut foreign = original;
    foreign.candidate = id(15);
    assert!(original_commitments(&shard, &[reference], &[foreign]).is_err());
}
