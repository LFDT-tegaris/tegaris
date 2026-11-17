use super::super::feed::tests::{admit_complete_fixture, candidate, complete_event, event};
use super::*;
use crate::source_authority::StateFactRecordSource;
use pc_facts_core::{FACT_RECORD_SCHEMA_ID, FactRecord, encode_pc_cbor};
use sqlx::postgres::PgPoolOptions;

pub(in crate::store) fn batch_fixture(
    first: &FactFeedEvent,
    profile: Uuid,
) -> (
    Vec<crate::source_authority::ObservedStateAdmission>,
    Vec<FactFeedEvent>,
    FactFeedEvent,
) {
    let mut observations = Vec::new();
    let mut events = Vec::new();
    for index in 0..first.batch.record_count {
        let mut event = first.clone();
        event.sequence = index + 1;
        event.record_ordinal = index + 1;
        if index > 0 {
            event.candidate_id = Some(Uuid::now_v7().to_string());
            event.event_id = Uuid::now_v7();
        }
        let (mut candidate, trusted) = candidate(&event, index + 1);
        let mut value = crate::state_value::StateFactValue::from_payload(
            &candidate.canonical_payload,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )
        .unwrap();
        value.block_number = (first.batch.range_start + index).to_string();
        candidate.canonical_payload = crate::state_value::canonical(&value).unwrap();
        candidate.declared_payload_digest = sha256(&candidate.canonical_payload);
        let record_source = StateFactRecordSource::fixture(&candidate, profile);
        observations.push(crate::source_authority::ObservedStateAdmission {
            candidate,
            trusted,
            record_source,
        });
        events.push(event);
    }
    let mut closing = first.clone();
    closing.sequence = first.batch.record_count + 1;
    closing.record_ordinal = closing.sequence;
    closing.event_id = Uuid::now_v7();
    closing.candidate_id = None;
    (observations, events, closing)
}

#[tokio::test]
#[ignore = "requires installed FactStore roles; ordinary PostgreSQL gate invokes it"]
async fn complete_batch_is_atomic_and_publication_verifies_every_record() {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let store = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().unwrap(),
    );
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
    let mut first = event();
    first.batch.record_count = 2;
    first.batch.range_end = 11;
    let profile = Uuid::now_v7();
    for failure in ["reordered", "missing", "scope", "stale", "limit"] {
        let mut input = first.clone();
        if failure == "limit" {
            input.batch.record_count = 3;
            input.batch.range_end = 12;
        }
        let (mut observations, mut events, closing) = batch_fixture(&input, profile);
        match failure {
            "reordered" => events.swap(0, 1),
            "missing" => {
                events.pop();
            }
            "scope" => events[1].batch.privacy_domain_id = Uuid::now_v7().to_string(),
            "stale" => observations[1].trusted.now_ms += 120_000,
            "limit" => (),
            _ => unreachable!(),
        }
        let mut tx = pool.begin().await.unwrap();
        assert!(
            store
                .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
                .await
                .is_err(),
            "{failure}"
        );
        tx.rollback().await.unwrap();
        assert!(!store.replay_feed_receipt(&input).await.unwrap());
    }
    let (observations, events, closing) = batch_fixture(&first, profile);
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        store
            .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
            .await
            .unwrap(),
        DurableAdmissionOutcome::AdmittedNotReady
    );
    tx.rollback().await.unwrap();
    assert!(!store.replay_feed_batch(&events, &closing).await.unwrap());
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    for statement in [
        "select count(*) from facts.admission_delivery_event",
        "select count(*) from facts.admission_delivery_head",
    ] {
        let count: i64 = sqlx::query_scalar(statement)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0, "rollback must include {statement}");
    }
    tx.rollback().await.unwrap();

    let (observations, events, closing) = batch_fixture(&first, profile);
    let mut tx = pool.begin().await.unwrap();
    store
        .admit_feed_batch_in_transaction(&mut tx, observations, &events, &closing, &signer)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    super::super::delivery::tests::verify_original_delivery(
        &store,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
        events[0].candidate_id.as_ref().unwrap(),
        &signer.verifier(),
    )
    .await;
    assert!(store.replay_feed_batch(&events, &closing).await.unwrap());
    let mut forged = events.clone();
    forged[1].payload_cbor =
        pc_facts_core::encode_pc_cbor(ciborium::Value::Text("different replay".into())).unwrap();
    assert!(store.replay_feed_batch(&forged, &closing).await.is_err());
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    let rows = super::super::signed_record::load_generation(
        &mut tx,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
        &first.batch.fact_generation_id,
    )
    .await
    .unwrap();
    let records: Vec<_> = rows
        .iter()
        .map(|row| {
            super::super::signed_record::verify(
                row,
                &signer.verifier(),
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
            )
            .unwrap()
            .unwrap()
        })
        .collect();
    FactRecord::validate_batch(&records).unwrap();
    assert_eq!(records.len(), 2);
    let delivery = sqlx::query("select e.event_id,e.sequence,e.envelope,e.data_bytes,e.source_material_digest,o.delivery_state from facts.admission_delivery_event e join facts.outbox o using(candidate_id,participant_id,privacy_domain_id) where e.participant_id=$1 and e.privacy_domain_id=$2 order by e.sequence")
        .bind(&first.batch.participant_id).bind(&first.batch.privacy_domain_id).fetch_all(&mut *tx).await.unwrap();
    assert_eq!(delivery.len(), 2);
    for (index, row) in delivery.iter().enumerate() {
        assert_eq!(row.get::<i64, _>("sequence"), index as i64 + 1);
        assert_eq!(row.get::<String, _>("delivery_state"), "PENDING");
        let event: serde_json::Value = row.get("envelope");
        assert_eq!(event["id"], row.get::<Uuid, _>("event_id").to_string());
        assert_eq!(event["type"], "io.openpc.fact.candidate.admitted.v1");
        assert_eq!(
            event["data"]["factArtifactId"],
            format!(
                "urn:openpc:resource:{}",
                events[index].candidate_id.as_ref().unwrap()
            )
        );
        assert_eq!(
            event["datadigest"],
            crate::signing::shard::digest_text(&sha256(&row.get::<Vec<u8>, _>("data_bytes")))
        );
        assert_eq!(event["data"].as_object().unwrap().len(), 5);
        let replay = store
            .record_admission_delivery(
                &mut tx,
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                events[index].candidate_id.as_ref().unwrap(),
                &signer.verifier(),
            )
            .await
            .unwrap();
        assert_eq!(replay, event);
    }
    let signed: Vec<Vec<u8>> = rows.iter().map(|row| row.get("cose_sign1")).collect();
    let content = crate::signing::shard::content_bytes(&signed).unwrap();
    let manifest = crate::signing::shard::FactShardManifest::from_records(
        &records,
        &content,
        &first.batch.fact_generation_id,
        None,
    )
    .unwrap();
    let signed_manifest = signer.sign_complete_shard(&manifest).unwrap();
    let verified = signer
        .verifier()
        .verify_shard_cose(&signed_manifest.cose_sign1)
        .unwrap();
    assert!(
        verified
            .manifest
            .as_ref()
            .unwrap()
            .matches(&records, &content)
    );
    let mut reordered = signed.clone();
    reordered.swap(0, 1);
    assert!(!manifest.matches(
        &records,
        &crate::signing::shard::content_bytes(&reordered).unwrap()
    ));
    assert!(!manifest.matches(
        &records,
        &crate::signing::shard::content_bytes(&signed[..1]).unwrap()
    ));
    assert_eq!(
        records[1].predecessor_digest.as_ref(),
        Some(&records[0].identity.local_fact_digest)
    );
    tx.rollback().await.unwrap();
    let directory = std::env::temp_dir().join(format!("openpc-fact-batch-{}", Uuid::now_v7()));
    std::fs::write(&directory, b"unavailable destination").unwrap();
    assert!(
        store
            .publish_candidate(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                first.candidate_id.as_deref().unwrap(),
                &signer,
                &directory
            )
            .await
            .is_err()
    );
    std::fs::remove_file(&directory).unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(
        store
            .publish_candidate_in_transaction(
                &mut tx,
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                first.candidate_id.as_deref().unwrap(),
                &signer,
                &directory
            )
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    assert!(
        store
            .publish_candidate(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                first.candidate_id.as_deref().unwrap(),
                &signer,
                &directory
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .publish_candidate(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                first.candidate_id.as_deref().unwrap(),
                &signer,
                &directory
            )
            .await
            .unwrap()
    );
    for event in &events {
        let snapshot = store
            .read_policy_fact(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                event.candidate_id.as_deref().unwrap(),
                &signer.verifier(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.outcome, pc_facts_core::FactQueryOutcome::Present);
    }
    super::super::producer_delivery::tests::verify_completion_owner(
        &store,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
        &first.batch.fact_generation_id,
        &signer.verifier(),
        &directory,
    )
    .await;
    std::fs::remove_dir_all(directory).unwrap();
    pool.close().await;
}

#[test]
fn complete_record_normalizes_supported_genesis_encodings_and_rejects_malformed_hashes() {
    let event = event();
    let hash = "11".repeat(32);
    for (genesis, accepted) in [
        (hash.clone(), true),
        (format!("sha256:{hash}"), true),
        (format!("0x{hash}"), true),
        (format!("sha256:0x{hash}"), false),
        ("11".repeat(31), false),
    ] {
        let (mut candidate, trusted) = candidate(&event, 1);
        let mut value = crate::state_value::StateFactValue::from_payload(
            &candidate.canonical_payload,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )
        .unwrap();
        value.genesis_hash = genesis;
        candidate.canonical_payload = crate::state_value::canonical(&value).unwrap();
        candidate.declared_payload_digest = sha256(&candidate.canonical_payload);
        let source = StateFactRecordSource::fixture(&candidate, Uuid::now_v7());
        let admission = pc_facts_core::validate_admission(candidate, &trusted).unwrap();
        let allocation = FactIdentityAllocation {
            fact_id: Uuid::now_v7(),
            generation: 1,
            sequence: 1,
            admitted_at: pc_facts_core::fact_timestamp_from_ms(trusted.now_ms).unwrap(),
            predecessor_digest: None,
        };
        let record = source.record(&allocation, &admission, &event, &format!("sha256:{hash}"));
        if accepted {
            let record = record.unwrap();
            assert_eq!(
                record.identity.chain_anchor.genesis_hash,
                format!("0x{hash}")
            );
            admission.bind_complete_record(record).unwrap();
        } else {
            assert!(matches!(
                record,
                Err(pc_facts_core::AdmissionError::SemanticOrPrivacy)
            ));
        }
    }
}

async fn stored(
    store: &FactStore,
    e: &FactFeedEvent,
    signer: &PurposeBoundFactSigner,
) -> (FactRecord, Vec<u8>) {
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, &e.batch.participant_id, &e.batch.privacy_domain_id)
        .await
        .unwrap();
    let row=sqlx::query("select f.cose_sign1,f.fact_digest,a.fact_id,g.canonical_generation::text,a.delta_sequence::text
        from facts.canonical_fact f join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
        join facts.canonical_generation g using(participant_id,privacy_domain_id,generation_id,fact_profile_id)
        where f.candidate_id=$1")
        .bind(e.candidate_id.as_ref().unwrap()).fetch_one(&mut *tx).await.unwrap();
    let signed: Vec<u8> = row.try_get("cose_sign1").unwrap();
    let verified = signer
        .verifier()
        .verified_stored_claims(FACT_RECORD_SCHEMA_ID, &signed)
        .unwrap();
    let record = FactRecord::from_cbor(&encode_pc_cbor(verified).unwrap()).unwrap();
    assert_eq!(
        record.identity.fact_id,
        format!(
            "urn:openpc:fact:{}",
            row.try_get::<Uuid, _>("fact_id").unwrap()
        )
    );
    assert_eq!(
        record.identity.canonical_generation.to_string(),
        row.try_get::<String, _>("canonical_generation").unwrap()
    );
    assert_eq!(
        record.delta_sequence.to_string(),
        row.try_get::<String, _>("delta_sequence").unwrap()
    );
    let expected = row
        .try_get::<Vec<u8>, _>("fact_digest")
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        record.identity.local_fact_digest,
        format!("sha256:{expected}")
    );
    tx.rollback().await.unwrap();
    (record, signed)
}

#[tokio::test]
#[ignore = "requires installed FactStore roles; ordinary PostgreSQL gate invokes it"]
async fn complete_record_allocation_is_atomic_scoped_and_restart_safe() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let secret = crate::store::tests::external_capability_secret().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let store = FactStore::new(pool.clone(), secret);
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
    let verifier = signer.verifier();
    let first = event();
    let (c, t) = candidate(&first, 1);
    let profile = Uuid::now_v7();
    let source = StateFactRecordSource::fixture(&c, profile);
    let closing = complete_event(&first);
    let (left, right) = tokio::join!(
        admit_complete_fixture(
            &store,
            c.clone(),
            t.clone(),
            &first,
            &closing,
            profile,
            &signer
        ),
        admit_complete_fixture(
            &store,
            c.clone(),
            t.clone(),
            &first,
            &closing,
            profile,
            &signer
        )
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert!(outcomes.contains(&DurableAdmissionOutcome::AdmittedNotReady));
    assert!(outcomes.contains(&DurableAdmissionOutcome::IdempotentReplay));
    let (record, signed) = stored(&store, &first, &signer).await;
    assert_eq!(record.identity.platform_authority_epoch, 7);
    assert_eq!(record.identity.delegation_epoch, 3);
    assert_eq!(record.identity.canonical_generation, 1);
    assert_eq!(record.delta_sequence, 1);
    assert!(record.predecessor_digest.is_none());
    assert_eq!(
        record.identity.local_signing_key_id,
        format!("sha256:{}", "2a".repeat(32))
    );
    assert!(record.finalized_at.is_none());
    assert!(store.replay_feed_receipt(&first).await.unwrap());

    // A structurally valid record cannot claim a different installed COSE key.
    let mut wrong_key = record.clone();
    wrong_key.identity.local_signing_key_id = format!("sha256:{}", "2b".repeat(32));
    wrong_key.identity = wrong_key.identity.with_derived_digest().unwrap();
    let wrong_key = validate_admission(c.clone(), &t)
        .unwrap()
        .bind_complete_record(wrong_key.with_single_entry_root().unwrap())
        .unwrap();
    assert!(signer.sign_admission(&wrong_key).is_err());

    // Multiple contiguous identities in one complete generation are exercised
    // by complete_batch_is_atomic_and_publication_verifies_every_record.

    // A new source-generation UUID is not used as the canonical uint64.
    let mut third = event();
    third.batch.participant_id = first.batch.participant_id.clone();
    third.batch.privacy_domain_id = first.batch.privacy_domain_id.clone();
    let (c3, t3) = candidate(&third, 1);
    admit_complete_fixture(
        &store,
        c3,
        t3,
        &third,
        &complete_event(&third),
        profile,
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(
        stored(&store, &third, &signer)
            .await
            .0
            .identity
            .canonical_generation,
        2
    );

    // Gapped input rolls allocation, generation, fact, receipt and evidence back.
    let mut gap = event();
    gap.sequence = 2;
    let (cg, tg) = candidate(&gap, 1);
    let sg = StateFactRecordSource::fixture(&cg, profile);
    assert!(
        admit_complete_fixture(
            &store,
            cg.clone(),
            tg.clone(),
            &gap,
            &complete_event(&gap),
            profile,
            &signer
        )
        .await
        .is_err()
    );
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &cg.participant_id, &cg.privacy_domain_id)
        .await
        .unwrap();
    let counts:(i64,i64,i64,i64)=sqlx::query_as("select (select count(*) from facts.canonical_identity_allocation),
        (select count(*) from facts.canonical_generation),(select count(*) from facts.canonical_fact),(select count(*) from facts.outbox)")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
    tx.rollback().await.unwrap();

    // Existing legacy signed facts remain history; allocation cannot retrofit
    // a fact identity onto them, even through the legitimate capability owner.
    let legacy_event = event();
    let (legacy, legacy_trusted) = candidate(&legacy_event, 1);
    store
        .admit_from_feed(
            legacy.clone(),
            &legacy_trusted,
            &legacy_event,
            &signer,
            &verifier,
        )
        .await
        .unwrap();
    let legacy = validate_admission(legacy, &legacy_trusted).unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, legacy.participant_id(), legacy.privacy_domain_id())
        .await
        .unwrap();
    assert!(
        store
            .allocate_identity(&mut tx, &legacy, &source.profile_urn())
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();

    // The allocation FK is deferred only to permit atomic signing/admission;
    // an isolated allocation cannot commit, even with a real capability.
    let validated = validate_admission(cg, &tg).unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(
        &mut tx,
        validated.participant_id(),
        validated.privacy_domain_id(),
    )
    .await
    .unwrap();
    store
        .allocate_identity(&mut tx, &validated, &sg.profile_urn())
        .await
        .unwrap();
    assert!(tx.commit().await.is_err());

    // Installed runtime role cannot change history or bypass the capability.
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    assert!(
        sqlx::query("update facts.canonical_identity_allocation set delta_sequence=9")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    assert!(
        sqlx::query("select * from facts.allocate_canonical_fact_identity($1,$2,$3,$4,$5,$6,$7)")
            .bind(&c.participant_id)
            .bind(&c.privacy_domain_id)
            .bind(&c.candidate_id)
            .bind(source.profile_urn())
            .bind(&c.generation_id)
            .bind(vec![0u8; 32])
            .bind(vec![0u8; 32])
            .fetch_one(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &Uuid::now_v7().to_string(), &c.privacy_domain_id)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from facts.canonical_identity_allocation")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0
    );
    tx.rollback().await.unwrap();

    pool.close().await;
    let reopened = FactStore::new(PgPoolOptions::new().connect(&url).await.unwrap(), secret);
    assert_eq!(stored(&reopened, &first, &signer).await.1, signed);
    assert!(reopened.replay_feed_receipt(&first).await.unwrap());
    reopened.pool.close().await;
}
