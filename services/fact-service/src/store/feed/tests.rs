use super::*;
use ciborium::value::Value;
use pc_facts_core::{
    FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_SCHEMA_VERSION_V1,
    encode_pc_cbor, fact_schema_identity,
};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
#[ignore = "requires installed FactStore roles; ordinary PostgreSQL gate invokes it"]
async fn empty_checkpoint_advances_without_facts_and_preserves_gap_replay_fences() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let store = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().unwrap(),
    );
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
    let mut empty = event();
    empty.candidate_id = None;
    empty.batch.record_count = 0;
    let proof = signer
        .sign_checkpoint(&Value::Text("independently verified empty fixture".into()))
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &empty.batch.participant_id,
        &empty.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    assert!(
        store
            .record_feed_receipt(
                &mut tx,
                Receipt {
                    event: &empty,
                    fact_digest: None,
                    canonical_provenance: None
                }
            )
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &empty.batch.participant_id,
        &empty.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    store
        .record_feed_receipt(
            &mut tx,
            Receipt {
                event: &empty,
                fact_digest: None,
                canonical_provenance: Some(&proof),
            },
        )
        .await
        .unwrap();
    let stored:Vec<u8>=sqlx::query_scalar("select canonical_provenance from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3")
        .bind(&empty.batch.participant_id).bind(&empty.batch.privacy_domain_id).bind(empty.batch.partition_id).fetch_one(&mut *tx).await.unwrap();
    signer
        .verifier()
        .verified_stored_claims(21008, &stored)
        .unwrap();
    let count:i64=sqlx::query_scalar("select count(*) from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2")
        .bind(&empty.batch.participant_id).bind(&empty.batch.privacy_domain_id).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(count, 0);
    tx.commit().await.unwrap();
    let restarted = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().unwrap(),
    );
    assert!(restarted.replay_feed_receipt(&empty).await.unwrap());
    let position = restarted
        .feed_position(
            &empty.batch.participant_id,
            &empty.batch.privacy_domain_id,
            empty.batch.partition_id,
            &empty.batch.source_profile_id,
        )
        .await
        .unwrap();
    assert_eq!(position.completed_watermark, Some(10));
    assert_eq!(position.last_fact_sequence, 0);
    let mut gap = empty.clone();
    gap.sequence = 2;
    gap.event_id = Uuid::now_v7();
    gap.batch.checkpoint_id = Uuid::now_v7();
    gap.batch.fact_generation_id = Uuid::now_v7().to_string();
    gap.batch.batch_sequence = 2;
    gap.batch.predecessor_batch_digest = Some(empty.batch.batch_digest);
    gap.batch.batch_digest = sha256(b"next-empty");
    gap.batch.range_start = 12;
    gap.batch.range_end = 12;
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &gap.batch.participant_id,
        &gap.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    assert!(
        restarted
            .record_feed_receipt(
                &mut tx,
                Receipt {
                    event: &gap,
                    fact_digest: None,
                    canonical_provenance: Some(&proof)
                }
            )
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    gap.batch.range_start = 11;
    gap.batch.range_end = 11;
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &gap.batch.participant_id,
        &gap.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    restarted
        .record_feed_receipt(
            &mut tx,
            Receipt {
                event: &gap,
                fact_digest: None,
                canonical_provenance: Some(&proof),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut changed = empty;
    changed.batch.range_end = 11;
    assert!(restarted.replay_feed_receipt(&changed).await.is_err());
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires installed FactStore roles; ordinary PostgreSQL gate invokes it"]
async fn external_observations_preserve_boolean_meaning_through_signed_publication() {
    use pc_policy_core::{
        fact_condition::FactCondition, fact_profile::StateFactMapping, invocation::ArgumentValue,
    };
    use pc_runtime_types::Digest;
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let read_pool =
        sqlx::PgPool::connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let store = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().unwrap(),
    );
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
    for satisfied in [true, false] {
        let first = event();
        let profile = Uuid::now_v7();
        let (mut observations, events, closing) =
            crate::store::identity::tests::batch_fixture(&first, profile);
        let observation = &mut observations[0];
        let candidate = &mut observation.candidate;
        let mut value = crate::state_value::StateFactValue::from_payload(
            &candidate.canonical_payload,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )
        .unwrap();
        value.mapping = "openpc:external-decision-observation:v1".into();
        value.typed_result.clear();
        value.specialization = Some((
            pc_facts_core::FactSubject::ExternalDecision {
                provider_id: "provider-1".into(),
                provider_version: "1".into(),
                configuration_digest: format!(
                    "sha256:{}",
                    Digest::of(b"governed-provider").as_str()
                ),
                request_digest: format!("sha256:{}", Digest::of(b"external-request").as_str()),
                source_occurrence: format!(
                    "sha256:{}",
                    Digest::of(b"external-occurrence").as_str()
                ),
                condition: "eligible".into(),
            },
            pc_facts_core::FactObject::ExternalObservation {
                satisfied,
                response_digest: format!("sha256:{}", Digest::of([u8::from(satisfied)]).as_str()),
            },
        ));
        candidate.canonical_payload = crate::state_value::canonical(&value).unwrap();
        candidate.declared_payload_digest = sha256(&candidate.canonical_payload);
        observation.record_source = crate::source_authority::StateFactRecordSource::fixture_mapping(
            candidate,
            profile,
            StateFactMapping::ExternalDecisionAdapterV1 {
                provider_id: "provider-1".into(),
                provider_version: "1".into(),
                provider_configuration_digest: Digest::of(b"governed-provider"),
                condition: "eligible".into(),
            },
        );
        let mut tx = pool.begin().await.unwrap();
        store
            .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(store.replay_feed_batch(&events, &closing).await.unwrap());
        let root = std::env::var_os("OPENPC_TEST_ROOT")
            .or_else(|| std::env::var_os("OPENPC_TEST_TMP_ROOT"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("external-shard-{}", Uuid::now_v7()));
        store
            .publish_candidate(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                first.candidate_id.as_deref().unwrap(),
                &signer,
                &root,
            )
            .await
            .unwrap();
        let reader = PolicyFactReader::new(read_pool.clone(), signer.verifier());
        let (shard, snapshots) = reader
            .publication(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                &[first.candidate_id.clone().unwrap()],
            )
            .await
            .unwrap()
            .unwrap();
        let local = signer
            .verifier()
            .verify_local_facts(&shard, shard.local_content().unwrap())
            .unwrap();
        let condition = FactCondition::ExternalObservation {
            fact: pc_policy_core::semantics::FactReference {
                candidate_id: first.candidate_id.clone().unwrap(),
                generation_id: first.batch.fact_generation_id.clone(),
                fact_digest: crate::signing::shard::digest_text(&snapshots[0].fact_digest),
            },
            provider_id: "provider-1".into(),
            provider_version: "1".into(),
            provider_configuration_digest: Digest::of(b"governed-provider"),
            request_digest: Digest::of(b"external-request"),
            condition: "eligible".into(),
        };
        let hash = Digest::parse("22".repeat(32)).unwrap();
        let workload = profile.to_string();
        let context = crate::LocalFactContext {
            participant_id: &first.batch.participant_id,
            privacy_domain_id: &first.batch.privacy_domain_id,
            workload_id: &workload,
            chain_id: 31337,
            block_number: 10,
            block_hash: &hash,
        };
        assert_eq!(local.permits_condition(&condition, &context), satisfied);
        check_process_lease(
            &read_pool, &first, &signer, &root, &condition, &workload, satisfied,
        )
        .await;
        let mut wrong = condition.clone();
        if let FactCondition::ExternalObservation {
            provider_version, ..
        } = &mut wrong
        {
            *provider_version = "2".into();
        }
        assert!(!local.permits_condition(&wrong, &context));
        let mut malformed = value;
        malformed.typed_result = vec![ArgumentValue::Uint([0; 32])];
        assert!(
            crate::state_value::StateFactValue::from_payload(
                &crate::state_value::canonical(&malformed).unwrap(),
                &first.batch.participant_id,
                &first.batch.privacy_domain_id
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    read_pool.close().await;
    pool.close().await;
}

// Exercise the executable protocol under the same real installed owner as the
// publication test. An in-process snapshot alone cannot establish held custody.
async fn check_process_lease(
    read_pool: &PgPool,
    event: &FactFeedEvent,
    signer: &PurposeBoundFactSigner,
    root: &std::path::Path,
    condition: &pc_policy_core::fact_condition::FactCondition,
    workload: &str,
    satisfied: bool,
) {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let executable = std::env::var("OPENPC_POLICY_FACT_READER_BIN").expect("built Fact reader");
    let public_key = root.join("lease-public-key.sec1");
    std::fs::write(&public_key, signer.verifier().sec1_bytes()).unwrap();
    let mut command = Command::new(executable);
    command
        .arg("--lease")
        .env("POLICY_FACT_VERIFY_KEY_FILE", public_key)
        .env(
            "POLICY_FACT_VERIFY_KEY_ID",
            format!("sha256:{}", "2a".repeat(32)),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let request = serde_json::json!({
        "participantId":event.batch.participant_id,"privacyDomainId":event.batch.privacy_domain_id,
        "candidateIds":[event.candidate_id],"conditions":[condition],"workloadId":workload
    });
    writeln!(input, "{request}").unwrap();
    let read = |output: &mut std::io::BufReader<std::process::ChildStdout>| {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };
    let initial = read(&mut output);
    assert_eq!(initial["identity"], "OPENPC-FACT-OWNER-LEASE-1");
    assert_eq!(initial["snapshots"][0]["outcome"], "PRESENT");
    assert_eq!(
        initial["snapshots"][0]["conditions"][0]["outcome"],
        if satisfied {
            "MEMBER_CONFIRMED"
        } else {
            "DENIED"
        }
    );
    let mut writer = read_pool.begin().await.unwrap();
    set_context(
        &mut writer,
        &event.batch.participant_id,
        &event.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    sqlx::query("set local lock_timeout='100ms'")
        .execute(&mut *writer)
        .await
        .unwrap();
    let blocked = sqlx::query("select pg_advisory_xact_lock(facts.policy_fence_key($1,$2))")
        .bind(&event.batch.participant_id)
        .bind(&event.batch.privacy_domain_id)
        .execute(&mut *writer)
        .await
        .unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    writer.rollback().await.unwrap();
    writeln!(input, "CHECK").unwrap();
    assert_eq!(read(&mut output)["state"], "HELD");
    writeln!(input, "RELEASE").unwrap();
    drop(input);
    assert!(child.wait().unwrap().success());
    let mut writer = read_pool.begin().await.unwrap();
    set_context(
        &mut writer,
        &event.batch.participant_id,
        &event.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    sqlx::query("set local lock_timeout='100ms'")
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query("select pg_advisory_xact_lock(facts.policy_fence_key($1,$2))")
        .bind(&event.batch.participant_id)
        .bind(&event.batch.privacy_domain_id)
        .execute(&mut *writer)
        .await
        .unwrap();
    writer.rollback().await.unwrap();
    let mut malformed = command.spawn().unwrap();
    let mut input = malformed.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(malformed.stdout.take().unwrap());
    writeln!(input, "{request}").unwrap();
    assert_eq!(read(&mut output)["identity"], "OPENPC-FACT-OWNER-LEASE-1");
    writeln!(input, "FORGED_HELD").unwrap();
    drop(input);
    let rejected = malformed.wait_with_output().unwrap();
    assert!(!rejected.status.success());
    let mut trailing = String::new();
    assert_eq!(output.read_line(&mut trailing).unwrap(), 0);
}

pub(crate) fn candidate(
    event: &FactFeedEvent,
    sequence: u64,
) -> (FactAdmissionCandidate, TrustedAdmissionContext) {
    let b = &event.batch;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let payload = crate::state_value::canonical(&crate::state_value::tests::value(
        &b.participant_id,
        &b.privacy_domain_id,
        1,
    ))
    .unwrap();
    let anchor = sha256(b"independent-test-owner-anchor");
    // Complete synthetic source provenance belongs to this component fixture;
    // these digests do not stand in for governed source journey acceptance.
    let provenance = crate::state_value::canonical(&serde_json::json!({
        "source":b.source_profile_id,
        "finalityAnchor":crate::signing::shard::digest_text(&anchor)[7..].to_owned(),
        "sourceProfileDigest":crate::signing::shard::digest_text(&sha256(b.source_profile_id.as_bytes())),
        "sourcePayloadDigest":crate::signing::shard::digest_text(&sha256(&event.payload_cbor)),
        "configurationDigest":crate::signing::shard::digest_text(&sha256(b"fixture configuration"))
    })).unwrap();
    let candidate = FactAdmissionCandidate {
        candidate_id: event.candidate_id.clone().unwrap(),
        participant_id: b.participant_id.clone(),
        privacy_domain_id: b.privacy_domain_id.clone(),
        source_profile_id: b.source_profile_id.clone(),
        generation_id: b.fact_generation_id.clone(),
        schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
        schema_version: FACT_SCHEMA_VERSION_V1.into(),
        schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
        schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
            .unwrap()
            .purpose_separator
            .into(),
        sequence,
        observed_at_ms: now,
        declared_payload_digest: sha256(&payload),
        canonical_payload: payload,
        declared_provenance_digest: sha256(&provenance),
        canonical_provenance: provenance,
        finality_anchor: anchor,
        complete: true,
        semantic_valid: true,
        conflict_detected: false,
        terminal_denial: false,
    };
    let trusted = TrustedAdmissionContext {
        participant_id: b.participant_id.clone(),
        privacy_domain_id: b.privacy_domain_id.clone(),
        source_profile_id: b.source_profile_id.clone(),
        generation_id: b.fact_generation_id.clone(),
        expected_sequence: sequence,
        now_ms: now,
        maximum_age_ms: 60_000,
        independently_derived_provenance_digest: candidate.declared_provenance_digest,
        trusted_finality_anchor: anchor,
        profile_active: true,
        generation_fenced: false,
    };
    (candidate, trusted)
}

pub(crate) fn event() -> FactFeedEvent {
    FactFeedEvent {
        batch: FactFeedBatch {
            participant_id: Uuid::now_v7().to_string(),
            privacy_domain_id: Uuid::now_v7().to_string(),
            partition_id: Uuid::now_v7(),
            source_profile_id: Uuid::now_v7().to_string(),
            source_generation_id: Uuid::now_v7().to_string(),
            fact_generation_id: Uuid::now_v7().to_string(),
            checkpoint_id: Uuid::now_v7(),
            batch_sequence: 1,
            batch_digest: sha256(b"batch-1"),
            predecessor_batch_digest: None,
            range_start: 10,
            range_end: 10,
            record_count: 1,
            checkpoint_digest: sha256(b"checkpoint-1"),
        },
        sequence: 1,
        event_id: Uuid::now_v7(),
        record_ordinal: 1,
        payload_cbor: encode_pc_cbor(Value::Map(vec![(
            Value::Text("candidate".into()),
            Value::Text("first".into()),
        )]))
        .unwrap(),
        candidate_id: Some(Uuid::now_v7().to_string()),
    }
}

/// Populate the actual pre-delivery schema through the original signed-record
/// owner, before the upgrade under test exists. Never used by production code.
pub(in crate::store) async fn admit_pre_delivery_fixture(
    store: &FactStore,
    observation: crate::source_authority::ObservedStateAdmission,
    event: &FactFeedEvent,
    signer: &PurposeBoundFactSigner,
) {
    let mut tx = store.pool.begin().await.unwrap();
    let installed: bool =
        sqlx::query_scalar("select to_regclass('facts.admission_delivery_event') is not null")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(
        !installed,
        "only the genuine predecessor may use this fixture"
    );
    store
        .admit_feed_records_in_transaction(
            &mut tx,
            vec![observation],
            std::slice::from_ref(event),
            &complete_event(event),
            signer,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

// Complete-record fixtures enter the same atomic batch owner as acquired facts.
// Concurrent replay is reconciled only after the losing transaction rolls back.
pub(crate) async fn admit_complete_fixture(
    store: &FactStore,
    candidate: FactAdmissionCandidate,
    trusted: TrustedAdmissionContext,
    event: &FactFeedEvent,
    closing: &FactFeedEvent,
    profile: Uuid,
    signer: &PurposeBoundFactSigner,
) -> Result<DurableAdmissionOutcome, FactStoreError> {
    let record_source =
        crate::source_authority::StateFactRecordSource::fixture(&candidate, profile);
    let observed = crate::source_authority::ObservedStateAdmission {
        candidate,
        trusted,
        record_source,
    };
    let mut tx = store.pool.begin().await?;
    match store
        .admit_feed_batch_in_transaction(
            &mut tx,
            vec![observed],
            std::slice::from_ref(event),
            closing,
            signer,
        )
        .await
    {
        Ok(outcome) => {
            tx.commit().await?;
            Ok(outcome)
        }
        Err(error) => {
            tx.rollback().await?;
            if matches!(
                error,
                FactStoreError::SequenceRace | FactStoreError::ReplayDigestMismatch
            ) && store
                .replay_feed_batch(std::slice::from_ref(event), closing)
                .await?
            {
                Ok(DurableAdmissionOutcome::IdempotentReplay)
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) fn complete_event(event: &FactFeedEvent) -> FactFeedEvent {
    let mut closing = event.clone();
    closing.sequence += 1;
    closing.record_ordinal += 1;
    closing.event_id = event.batch.checkpoint_id;
    closing.candidate_id = None;
    closing.payload_cbor = encode_pc_cbor(Value::Text("complete".into())).unwrap();
    closing
}

// Reproduce the pre-0005 installed owner for populated upgrade acceptance.
// This invokes the real signed admission/receipt functions, without direct
// business DML or a fabricated ready row.
pub(crate) async fn admit_before_occurrence_migration(
    store: &FactStore,
    candidate: FactAdmissionCandidate,
    trusted: &TrustedAdmissionContext,
    event: &FactFeedEvent,
    signer: &PurposeBoundFactSigner,
) {
    let provenance = candidate.canonical_provenance.clone();
    let admission = validate_admission(candidate, trusted).unwrap();
    let signed = signer.sign_admission(&admission).unwrap();
    signer.verifier().verify_fact(&admission, &signed).unwrap();
    let capability = store
        .capabilities
        .admit(&admission, &signed, admission.sequence() as i64);
    let mut tx = store.pool.begin().await.unwrap();
    set_context(
        &mut tx,
        admission.participant_id(),
        admission.privacy_domain_id(),
    )
    .await
    .unwrap();
    FactStore::insert_admission(
        &mut tx,
        &admission,
        &signed,
        admission.sequence() as i64,
        &capability,
    )
    .await
    .unwrap();
    store
        .record_feed_receipt(
            &mut tx,
            Receipt {
                event,
                fact_digest: Some(admission.canonical_fact_digest()),
                canonical_provenance: Some(&provenance),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn counts(store: &FactStore, e: &FactFeedEvent) -> (i64, i64, i64, i64) {
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, &e.batch.participant_id, &e.batch.privacy_domain_id)
        .await
        .unwrap();
    let result = sqlx::query_as("select
      (select count(*) from facts.canonical_fact), (select count(*) from facts.candidate_feed_receipt),
      (select count(*) from facts.evidence_occurrence), (select count(*) from facts.outbox)")
        .fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "requires installed FactStore writer and capability secret; ordinary PostgreSQL gate invokes it"]
async fn installed_feed_receipts_are_atomic_ordered_and_restart_safe() {
    let url = std::env::var("DATABASE_URL").expect("installed writer URL");
    let secret =
        super::super::tests::external_capability_secret().expect("installed capability secret");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let store = FactStore::new(pool.clone(), secret);
    let signer =
        PurposeBoundFactSigner::generate_ephemeral_local(b"feed-regression".to_vec()).unwrap();
    let verifier = signer.verifier();
    let first = event();
    let (c, trusted) = candidate(&first, 1);
    assert!(!store.replay_feed_receipt(&first).await.unwrap());

    // Two fresh transport attempts serialize to one semantic effect.
    let (a, b) = tokio::join!(
        store.admit_from_feed(c.clone(), &trusted, &first, &signer, &verifier),
        store.admit_from_feed(c.clone(), &trusted, &first, &signer, &verifier),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert!(outcomes.contains(&DurableAdmissionOutcome::AdmittedNotReady));
    assert!(outcomes.contains(&DurableAdmissionOutcome::IdempotentReplay));
    assert_eq!(counts(&store, &first).await, (1, 1, 1, 1));
    assert!(store.replay_feed_receipt(&first).await.unwrap());
    let mut foreign = first.clone();
    foreign.batch.privacy_domain_id = Uuid::now_v7().to_string();
    assert!(!store.replay_feed_receipt(&foreign).await.unwrap());
    for field in 0..4 {
        let mut changed = first.clone();
        match field {
            0 => changed.batch.checkpoint_digest = [99; 32],
            1 => changed.candidate_id = Some(Uuid::now_v7().to_string()),
            2 => changed.batch.fact_generation_id = Uuid::now_v7().to_string(),
            _ => changed.payload_cbor = encode_pc_cbor(Value::Text("altered".into())).unwrap(),
        }
        assert!(matches!(
            store.replay_feed_receipt(&changed).await,
            Err(FactStoreError::ReplayDigestMismatch)
        ));
    }

    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    let provenance: Vec<u8> = sqlx::query_scalar(
        "select canonical_provenance from facts.candidate_feed_receipt where candidate_id=$1",
    )
    .bind(&c.candidate_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(provenance, c.canonical_provenance);
    let write =
        sqlx::query("update facts.candidate_feed_receipt set receipt_digest=receipt_digest")
            .execute(&mut *tx)
            .await
            .unwrap_err();
    assert_eq!(
        write.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    tx.rollback().await.unwrap();

    // Finality and a valid shard signature cannot conceal an unconsumed checkpoint.
    store
        .finalize(
            &c.participant_id,
            &c.privacy_domain_id,
            &c.candidate_id,
            c.finality_anchor,
        )
        .await
        .unwrap();
    let shard = signer
        .sign_shard(
            &c.participant_id,
            &c.privacy_domain_id,
            &c.generation_id,
            sha256(b"shard-one"),
        )
        .unwrap();
    let shard = verifier.verify_shard_cose(&shard.cose_sign1).unwrap();
    assert!(matches!(
        store.mark_signed_shard_ready(&shard).await,
        Err(FactStoreError::Feed)
    ));

    let mut altered = first.clone();
    altered.payload_cbor = encode_pc_cbor(Value::Text("substituted".into())).unwrap();
    assert!(matches!(
        store
            .admit_from_feed(c.clone(), &trusted, &altered, &signer, &verifier)
            .await,
        Err(FactStoreError::ReplayDigestMismatch)
    ));

    let mut checkpoint = first.clone();
    checkpoint.sequence = 2;
    checkpoint.record_ordinal = 2;
    checkpoint.event_id = Uuid::now_v7();
    checkpoint.candidate_id = None;
    checkpoint.payload_cbor = encode_pc_cbor(Value::Text("checkpoint-one".into())).unwrap();
    let receipt = Receipt {
        event: &checkpoint,
        fact_digest: None,
        canonical_provenance: None,
    };
    let cap = store.capabilities.candidate_feed(&receipt.digest());
    let mut substituted = checkpoint.clone();
    substituted.batch.checkpoint_digest = [55; 32];
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    assert!(matches!(
        FactStore::write_feed_receipt(
            &mut tx,
            Receipt {
                event: &substituted,
                fact_digest: None,
                canonical_provenance: None
            },
            &cap
        )
        .await,
        Err(FactStoreError::Lifecycle)
    ));
    tx.rollback().await.unwrap();

    let mut next = first.clone();
    next.sequence = 3;
    next.event_id = Uuid::now_v7();
    next.candidate_id = Some(Uuid::now_v7().to_string());
    next.batch.batch_sequence = 2;
    next.batch.batch_digest = sha256(b"batch-2");
    next.batch.predecessor_batch_digest = Some(first.batch.batch_digest);
    next.batch.fact_generation_id = Uuid::now_v7().to_string();
    next.batch.checkpoint_id = Uuid::now_v7();
    next.batch.checkpoint_digest = sha256(b"checkpoint-2");
    next.batch.range_start = 11;
    next.batch.range_end = 11;
    let (second, second_trusted) = candidate(&next, 2);
    // Missing feed event rolls back the already inserted fact/evidence/outbox.
    assert!(matches!(
        store
            .admit_from_feed(second.clone(), &second_trusted, &next, &signer, &verifier)
            .await,
        Err(FactStoreError::Feed)
    ));
    assert_eq!(counts(&store, &first).await, (1, 1, 1, 1));

    store.complete_feed_batch(&checkpoint).await.unwrap();
    store.complete_feed_batch(&checkpoint).await.unwrap();
    store.mark_signed_shard_ready(&shard).await.unwrap();
    assert_eq!(
        store
            .read_policy_fact(
                &c.participant_id,
                &c.privacy_domain_id,
                &c.candidate_id,
                &verifier
            )
            .await
            .unwrap()
            .unwrap()
            .outcome,
        pc_facts_core::FactQueryOutcome::NotReady,
        "legacy feed records remain historical without a complete canonical identity"
    );
    assert_eq!(
        store
            .feed_position(
                &c.participant_id,
                &c.privacy_domain_id,
                first.batch.partition_id,
                &c.source_profile_id
            )
            .await
            .unwrap(),
        FactFeedPosition {
            last_event_sequence: 2,
            last_fact_sequence: 1,
            completed_watermark: Some(10)
        }
    );
    assert_eq!(
        store
            .feed_position(
                "foreign",
                &c.privacy_domain_id,
                first.batch.partition_id,
                &c.source_profile_id
            )
            .await
            .unwrap(),
        FactFeedPosition {
            last_event_sequence: 0,
            last_fact_sequence: 0,
            completed_watermark: None
        }
    );

    for mutation in 0..3 {
        let mut wrong = next.clone();
        match mutation {
            0 => wrong.batch.predecessor_batch_digest = Some([1; 32]),
            1 => wrong.batch.source_generation_id = Uuid::now_v7().to_string(),
            _ => {
                wrong.batch.range_start = 12;
                wrong.batch.range_end = 12;
            }
        }
        assert!(matches!(
            store
                .admit_from_feed(second.clone(), &second_trusted, &wrong, &signer, &verifier)
                .await,
            Err(FactStoreError::Feed)
        ));
    }
    assert_eq!(counts(&store, &first).await, (1, 2, 1, 1));
    store
        .admit_from_feed(second.clone(), &second_trusted, &next, &signer, &verifier)
        .await
        .unwrap();
    let mut incomplete = next.clone();
    incomplete.sequence = 4;
    incomplete.record_ordinal = 2;
    incomplete.event_id = Uuid::now_v7();
    incomplete.candidate_id = None;
    incomplete.batch.record_count = 2;
    assert!(store.complete_feed_batch(&incomplete).await.is_err());
    assert_eq!(counts(&store, &first).await, (2, 3, 2, 2));

    // A process restart reads original receipt and repeats no business effect.
    drop(store);
    pool.close().await;
    let store = FactStore::new(PgPoolOptions::new().connect(&url).await.unwrap(), secret);
    assert!(store.replay_feed_receipt(&next).await.unwrap());
    assert_eq!(
        store
            .admit_from_feed(second, &second_trusted, &next, &signer, &verifier)
            .await
            .unwrap(),
        DurableAdmissionOutcome::IdempotentReplay
    );
    assert_eq!(counts(&store, &first).await, (2, 3, 2, 2));
    assert_eq!(
        store
            .feed_position(
                &c.participant_id,
                &c.privacy_domain_id,
                first.batch.partition_id,
                &c.source_profile_id
            )
            .await
            .unwrap(),
        FactFeedPosition {
            last_event_sequence: 3,
            last_fact_sequence: 2,
            completed_watermark: Some(10)
        }
    );
    store.pool.close().await;
}
