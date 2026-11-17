use super::*;
use crate::state_value::{StateFactValue, canonical};
use pc_facts_core::{FactQueryOutcome, encode_pc_cbor};
use sqlx::{Executor, postgres::PgPoolOptions};
use std::time::Duration;
use uuid::Uuid;

async fn store() -> FactStore {
    FactStore::new(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap(),
        super::super::tests::external_capability_secret().unwrap(),
    )
}
fn closing(event: &FactFeedEvent) -> FactFeedEvent {
    let mut close = event.clone();
    close.sequence += 1;
    close.record_ordinal += 1;
    close.event_id = Uuid::now_v7();
    close.candidate_id = None;
    close.payload_cbor = encode_pc_cbor(ciborium::value::Value::Text("complete".into())).unwrap();
    close
}
async fn ready(
    store: &FactStore,
    c: &FactAdmissionCandidate,
    signer: &PurposeBoundFactSigner,
) -> VerifiedShard {
    store
        .finalize(
            &c.participant_id,
            &c.privacy_domain_id,
            &c.candidate_id,
            c.finality_anchor,
        )
        .await
        .unwrap();
    let signed = signer
        .sign_shard(
            &c.participant_id,
            &c.privacy_domain_id,
            &c.generation_id,
            sha256(c.generation_id.as_bytes()),
        )
        .unwrap();
    let shard = signer
        .verifier()
        .verify_shard_cose(&signed.cose_sign1)
        .unwrap();
    // Reproduce the installed pre-0006 owner before the allocation table exists.
    // The current public helper deliberately requires that newer local fence.
    let capability = store.capabilities.mark_signed_shard_ready(&shard);
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("select facts.mark_signed_shard_ready($1,$2,$3,$4,$5,$6,$7)")
            .bind(&c.participant_id)
            .bind(&c.privacy_domain_id)
            .bind(&c.generation_id)
            .bind(shard.shard_digest().as_slice())
            .bind(shard.cose_sign1())
            .bind(capability.nonce.as_slice())
            .bind(capability.mac.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    shard
}
async fn signed_bytes(store: &FactStore, c: &FactAdmissionCandidate) -> (Vec<u8>, Vec<u8>) {
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    let bytes = sqlx::query_as(
        "select fact_digest,cose_sign1 from facts.canonical_fact where candidate_id=$1",
    )
    .bind(&c.candidate_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    bytes
}

#[tokio::test]
#[ignore = "ordinary Fact PostgreSQL gate invokes this once before installing migration0005"]
async fn upgrade_preserves_populated_signed_legacy_facts() {
    let store = store().await;
    let e = super::super::feed::tests::event();
    let (c, t) = super::super::feed::tests::candidate(&e, 1);
    let signer =
        PurposeBoundFactSigner::generate_ephemeral_local(b"occurrence-upgrade".to_vec()).unwrap();
    store
        .admit(c.clone(), &t, &signer, &signer.verifier())
        .await
        .unwrap();
    ready(&store, &c, &signer).await;
    let before = signed_bytes(&store, &c).await;
    let feed = super::super::feed::tests::event();
    let (feed_candidate, feed_trust) = super::super::feed::tests::candidate(&feed, 1);
    super::super::feed::tests::admit_before_occurrence_migration(
        &store,
        feed_candidate.clone(),
        &feed_trust,
        &feed,
        &signer,
    )
    .await;
    store.complete_feed_batch(&closing(&feed)).await.unwrap();
    let old_shard = ready(&store, &feed_candidate, &signer).await;
    let old_feed_bytes = signed_bytes(&store, &feed_candidate).await;
    let admin = PgPool::connect(&std::env::var("OPENPC_I05_GATE3_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0005_semantic_occurrence_conflicts.sql"
        ))
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0006_canonical_fact_identity.sql"
        ))
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0007_signed_shard_publication.sql"
        ))
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0008_source_withdrawal_lineage.sql"
        ))
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0009_canonical_reorg_lineage.sql"
        ))
        .await
        .unwrap();
    admin
        .execute(include_str!(
            "../../../../../migrations/postgres/facts/0010_signed_reorg_replacement.sql"
        ))
        .await
        .unwrap();
    let mut retirement_upgrade = admin.begin().await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../../migrations/postgres/facts/0011_store_retirement.sql"
    ))
    .execute(&mut *retirement_upgrade)
    .await
    .unwrap();
    retirement_upgrade.commit().await.unwrap();
    for (candidate, expected) in [(&c, &before), (&feed_candidate, &old_feed_bytes)] {
        let mut tx = store.pool.begin().await.unwrap();
        set_context(
            &mut tx,
            &candidate.participant_id,
            &candidate.privacy_domain_id,
        )
        .await
        .unwrap();
        let custody: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "select i.fact_digest,c.cose_sign1 from facts.retained_fact_identity i
             join facts.signed_fact_custody c using(candidate_id,participant_id,privacy_domain_id)
             where i.candidate_id=$1",
        )
        .bind(&candidate.candidate_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(&custody, expected);
        tx.rollback().await.unwrap();
    }
    assert_eq!(signed_bytes(&store, &c).await, before);
    assert_eq!(signed_bytes(&store, &feed_candidate).await, old_feed_bytes);
    assert_eq!(
        store
            .read_policy_fact(
                &feed_candidate.participant_id,
                &feed_candidate.privacy_domain_id,
                &feed_candidate.candidate_id,
                &signer.verifier()
            )
            .await
            .unwrap()
            .unwrap()
            .outcome,
        FactQueryOutcome::NotReady
    );
    assert!(matches!(
        store.mark_signed_shard_ready(&old_shard).await,
        Err(FactStoreError::Lifecycle)
    ));
    assert_eq!(
        store
            .read_policy_fact(
                &c.participant_id,
                &c.privacy_domain_id,
                &c.candidate_id,
                &signer.verifier()
            )
            .await
            .unwrap()
            .unwrap()
            .outcome,
        FactQueryOutcome::Present
    );
    admin.close().await;
    store.pool.close().await;
}

#[tokio::test]
#[ignore = "ordinary Fact PostgreSQL gate invokes installed capability, RLS, reader and concurrency coverage"]
async fn conflicts_fence_all_generations_atomically_and_survive_restart() {
    let store = store().await;
    let e = super::super::feed::tests::event();
    let (c, t) = super::super::feed::tests::candidate(&e, 1);
    // The eligible predecessor uses the same complete record and COM-019
    // owners as acquired facts. The conflicting observations remain fixtures.
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![43; 32]).unwrap();
    let verifier = signer.verifier();
    assert_eq!(
        super::super::feed::tests::admit_complete_fixture(
            &store,
            c.clone(),
            t,
            &e,
            &closing(&e),
            Uuid::now_v7(),
            &signer
        )
        .await
        .unwrap(),
        DurableAdmissionOutcome::AdmittedNotReady
    );
    let artifacts = std::env::temp_dir().join(format!("openpc-occurrence-{}", Uuid::now_v7()));
    assert!(
        store
            .publish_candidate(
                &c.participant_id,
                &c.privacy_domain_id,
                &c.candidate_id,
                &signer,
                &artifacts
            )
            .await
            .unwrap()
    );
    let before = signed_bytes(&store, &c).await;
    let reader_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let reader = PolicyFactReader::new(reader_pool.clone(), verifier.clone());

    // A distinct source/delivery/generation reporting a different independently
    // checked value for the SAME semantic occurrence cannot become a new truth.
    let mut second = super::super::feed::tests::event();
    second.batch.participant_id = c.participant_id.clone();
    second.batch.privacy_domain_id = c.privacy_domain_id.clone();
    let (mut different, dt) = super::super::feed::tests::candidate(&second, 1);
    let mut value = StateFactValue::from_payload(
        &different.canonical_payload,
        &c.participant_id,
        &c.privacy_domain_id,
    )
    .unwrap();
    value.typed_result = vec![pc_policy_core::invocation::ArgumentValue::Uint([2; 32])];
    different.canonical_payload = canonical(&value).unwrap();
    different.declared_payload_digest = sha256(&different.canonical_payload);
    // A contradictory value arriving through a sequence gap is not an
    // admitted observation and must not fence existing eligible authority.
    let mut gap = second.clone();
    gap.sequence = 2;
    assert!(matches!(
        store
            .admit_from_feed(different.clone(), &dt, &gap, &signer, &verifier)
            .await,
        Err(FactStoreError::Feed)
    ));
    assert_eq!(
        reader
            .read(&c.participant_id, &c.privacy_domain_id, &c.candidate_id)
            .await
            .unwrap()
            .unwrap()
            .outcome,
        FactQueryOutcome::Present
    );
    let lease = reader
        .lease_many_with_values(
            &c.participant_id,
            &c.privacy_domain_id,
            std::slice::from_ref(&c.candidate_id),
            std::slice::from_ref(&c.candidate_id),
            1000,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.snapshot().outcome, FactQueryOutcome::Present);
    assert_eq!(lease.values().len(), 1);

    {
        let admission = store.admit_from_feed(different.clone(), &dt, &second, &signer, &verifier);
        tokio::pin!(admission);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut admission)
                .await
                .is_err(),
            "conflict mutation must wait for policy decision custody"
        );
        lease.release().await.unwrap();
        assert_eq!(
            admission.await.unwrap(),
            DurableAdmissionOutcome::Conflicting
        );
    }
    store.complete_feed_batch(&closing(&second)).await.unwrap();
    assert_eq!(signed_bytes(&store, &c).await, before);
    assert!(matches!(
        store
            .publish_candidate(
                &c.participant_id,
                &c.privacy_domain_id,
                &c.candidate_id,
                &signer,
                &artifacts
            )
            .await,
        Err(FactStoreError::Database(_))
    ));

    // Later agreeing observations and concurrent exact replays cannot heal the
    // conflict or duplicate its immutable evidence/outbox occurrence.
    let mut third = super::super::feed::tests::event();
    third.batch.participant_id = c.participant_id.clone();
    third.batch.privacy_domain_id = c.privacy_domain_id.clone();
    let (agree, at) = super::super::feed::tests::candidate(&third, 1);
    let (a, b) = tokio::join!(
        store.admit_from_feed(agree.clone(), &at, &third, &signer, &verifier),
        store.admit_from_feed(agree.clone(), &at, &third, &signer, &verifier)
    );
    assert_eq!(a.unwrap(), DurableAdmissionOutcome::Conflicting);
    assert_eq!(b.unwrap(), DurableAdmissionOutcome::Conflicting);
    for id in [
        &c.candidate_id,
        &different.candidate_id,
        &agree.candidate_id,
    ] {
        let denied = reader
            .lease_many_with_values(
                &c.participant_id,
                &c.privacy_domain_id,
                std::slice::from_ref(id),
                std::slice::from_ref(id),
                1000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(denied.snapshot().outcome, FactQueryOutcome::Conflicting);
        assert!(denied.values().is_empty());
        assert!(
            reader
                .read(&c.participant_id, &Uuid::now_v7().to_string(), id)
                .await
                .unwrap()
                .is_none()
        );
        denied.release().await.unwrap();
    }
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, &c.participant_id, &c.privacy_domain_id)
        .await
        .unwrap();
    let counts:(i64,i64,i64)=sqlx::query_as("select (select count(*) from facts.semantic_occurrence),
        (select count(*) from facts.occurrence_conflict),(select count(*) from facts.occurrence_conflict_outbox)")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!(counts, (3, 1, 1));
    let untrusted = sqlx::query("select facts.bind_fact_occurrence($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(&c.participant_id)
        .bind(&c.privacy_domain_id)
        .bind(&c.candidate_id)
        .bind(&before.0)
        .bind(b"forged occurrence".as_slice())
        .bind([0u8; 32].as_slice())
        .bind([1u8; 32].as_slice())
        .bind([2u8; 32].as_slice())
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(
        untrusted.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    tx.rollback().await.unwrap();
    for table in [
        "semantic_occurrence",
        "occurrence_conflict",
        "occurrence_conflict_outbox",
    ] {
        let allowed: bool = sqlx::query_scalar(
            "select has_table_privilege(current_user,$1,'INSERT,UPDATE,DELETE')",
        )
        .bind(format!("facts.{table}"))
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!allowed);
    }
    reader_pool.close().await;
    let restarted =
        PgPool::connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
            .await
            .unwrap();
    assert_eq!(
        PolicyFactReader::new(restarted.clone(), verifier)
            .read(&c.participant_id, &c.privacy_domain_id, &c.candidate_id)
            .await
            .unwrap()
            .unwrap()
            .outcome,
        FactQueryOutcome::Conflicting
    );
    assert!(store.replay_feed_receipt(&e).await.unwrap());
    assert_eq!(signed_bytes(&store, &c).await, before);
    restarted.close().await;
    std::fs::remove_dir_all(artifacts).unwrap();
    store.pool.close().await;
}
