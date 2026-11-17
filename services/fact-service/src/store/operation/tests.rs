use super::super::feed::tests::{admit_complete_fixture, candidate, complete_event, event};
use super::*;
use crate::source_authority::{ObservedStateAdmission, StateFactRecordSource};
use sqlx::postgres::PgPoolOptions;

fn observation(event: &super::super::feed::FactFeedEvent, profile: Uuid) -> ObservedStateAdmission {
    let (mut candidate, mut trusted) = candidate(event, 1);
    candidate.canonical_provenance = crate::state_value::canonical(&serde_json::json!({
        "sourcePayloadDigest": "11".repeat(32), "configurationDigest": "22".repeat(32),
        "sourceProfileDigest": "44".repeat(32),
        "finalityAnchor": crate::signing::shard::digest_text(&candidate.finality_anchor)[7..].to_string()
    })).unwrap();
    candidate.declared_provenance_digest = pc_facts_core::sha256(&candidate.canonical_provenance);
    trusted.independently_derived_provenance_digest = candidate.declared_provenance_digest;
    let record_source = StateFactRecordSource::fixture(&candidate, profile);
    ObservedStateAdmission {
        candidate,
        trusted,
        record_source,
    }
}

#[tokio::test]
#[ignore = "requires installed FactStore writer; ordinary PostgreSQL gate invokes it"]
async fn public_operation_is_atomic_scoped_replay_safe_and_restart_readable() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let secret = crate::store::tests::external_capability_secret().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let store = FactStore::new(pool.clone(), secret);
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![51; 32]).unwrap();
    let first = event();
    let profile = Uuid::now_v7();
    let first_observed = observation(&first, profile);
    if std::env::var_os("OPENPC_FACT_ARTIFACT_UPGRADE").is_some() {
        super::super::feed::tests::admit_pre_delivery_fixture(
            &store,
            first_observed,
            &first,
            &signer,
        )
        .await;
    } else {
        admit_complete_fixture(
            &store,
            first_observed.candidate,
            first_observed.trusted,
            &first,
            &complete_event(&first),
            profile,
            &signer,
        )
        .await
        .unwrap();
    }
    if std::env::var_os("OPENPC_FACT_ARTIFACT_UPGRADE").is_some() {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("OPENPC_I05_GATE3_ADMIN_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let mut tx = admin.begin().await.unwrap();
        sqlx::raw_sql(
            include_str!(
                "../../../../../migrations/postgres/facts/0010_signed_reorg_replacement.sql"
            )
            .split_once(
                "-- parallel operation/fact table and no readiness assertion is introduced.\n",
            )
            .unwrap()
            .1,
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // Upgrade the populated predecessor through every currently required
        // owner before running current admission code. Preserve the original
        // signed candidate and public operation binding across the upgrade.
        for migration in [
            include_str!("../../../../../migrations/postgres/facts/0011_store_retirement.sql"),
            include_str!(
                "../../../../../migrations/postgres/facts/0012_store_retirement_preflight.sql"
            ),
            include_str!("../../../../../migrations/postgres/facts/0013_admission_delivery.sql"),
        ] {
            let mut tx = admin.begin().await.unwrap();
            sqlx::raw_sql(migration).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }
        // Invalid historical trust cannot mint an event or consume the original
        // pending row during upgrade recovery.
        let wrong_signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![52; 32]).unwrap();
        assert!(
            store
                .materialize_pending_admissions(
                    &first.batch.participant_id,
                    &first.batch.privacy_domain_id,
                    &wrong_signer.verifier()
                )
                .await
                .is_err()
        );
        let count: i64 = sqlx::query_scalar("select count(*) from facts.admission_delivery_event")
            .fetch_one(&admin)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let pending: String =
            sqlx::query_scalar("select delivery_state from facts.outbox where candidate_id=$1")
                .bind(first.candidate_id.as_ref().unwrap())
                .fetch_one(&admin)
                .await
                .unwrap();
        assert_eq!(pending, "PENDING");
        // Two restarting callers reconcile the same original identity. The
        // SQL scope fence and immutable replay owner must allocate it once.
        let verifier = signer.verifier();
        let (left, right) = tokio::join!(
            store.materialize_pending_admissions(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                &verifier
            ),
            store.materialize_pending_admissions(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                &verifier
            )
        );
        assert!(left.unwrap());
        assert!(right.unwrap());
        let count: i64 = sqlx::query_scalar("select count(*) from facts.admission_delivery_event")
            .fetch_one(&admin)
            .await
            .unwrap();
        assert_eq!(count, 1);
        admin.close().await;
    }
    assert!(
        store
            .materialize_pending_admissions(
                &first.batch.participant_id,
                &first.batch.privacy_domain_id,
                &signer.verifier()
            )
            .await
            .unwrap()
    );
    // Migration preserves the original pending row; materialization resumes
    // the same signed identity rather than replacing or re-admitting it.
    let mut delivery = pool.begin().await.unwrap();
    set_context(
        &mut delivery,
        &first.batch.participant_id,
        &first.batch.privacy_domain_id,
    )
    .await
    .unwrap();
    let original = store
        .record_admission_delivery(
            &mut delivery,
            &first.batch.participant_id,
            &first.batch.privacy_domain_id,
            first.candidate_id.as_ref().unwrap(),
            &signer.verifier(),
        )
        .await
        .unwrap();
    let pending: String =
        sqlx::query_scalar("select delivery_state from facts.outbox where candidate_id=$1")
            .bind(first.candidate_id.as_ref().unwrap())
            .fetch_one(&mut *delivery)
            .await
            .unwrap();
    assert_eq!(pending, "PENDING");
    assert_eq!(
        original["data"]["artifactDigest"],
        format!("sha256:{}", "11".repeat(32))
    );
    delivery.commit().await.unwrap();
    let binding = FactOperationBinding {
        operation_id: Uuid::now_v7(),
        principal_id: Uuid::now_v7(),
        candidate_id: first.candidate_id.as_ref().unwrap().parse().unwrap(),
        idempotency_key: "fact-artifact-operation-0001".into(),
        input_digest: format!("sha256:{}", "33".repeat(32)),
        expected_revision: "1".into(),
    };
    let p = &first.batch.participant_id;
    let d = &first.batch.privacy_domain_id;
    let mut stale = binding.clone();
    stale.expected_revision = "2".into();
    assert!(matches!(
        store.bind_feed_operation(p, d, &stale).await,
        Err(FactStoreError::ReplayDigestMismatch)
    ));
    // The first public receipt can bind a pre-upgrade effect without re-admission.
    store.bind_feed_operation(p, d, &binding).await.unwrap();
    let operation = store
        .admission_operation(
            p,
            d,
            binding.principal_id,
            Some(binding.operation_id),
            None,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(operation.state, "SUCCEEDED");
    assert_eq!(
        operation.resource_ref,
        format!("urn:openpc:resource:{}", binding.candidate_id)
    );
    let mut replay = binding.clone();
    replay.operation_id = Uuid::now_v7();
    let (a, b) = tokio::join!(
        store.bind_feed_operation(p, d, &replay),
        store.bind_feed_operation(p, d, &replay)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        store
            .admission_operation(
                p,
                d,
                binding.principal_id,
                None,
                Some(&binding.idempotency_key),
                Some(&replay)
            )
            .await
            .unwrap(),
        Some(operation.clone())
    );
    for change in ["digest", "key", "candidate"] {
        let mut altered = binding.clone();
        match change {
            "digest" => altered.input_digest = format!("sha256:{}", "44".repeat(32)),
            "key" => altered.idempotency_key = "fact-artifact-operation-0002".into(),
            _ => altered.candidate_id = Uuid::now_v7(),
        }
        assert!(
            matches!(
                store.bind_feed_operation(p, d, &altered).await,
                Err(FactStoreError::ReplayDigestMismatch)
            ),
            "{change}"
        );
    }
    for (participant, privacy, principal) in [
        (Uuid::now_v7().to_string(), d.clone(), binding.principal_id),
        (p.clone(), Uuid::now_v7().to_string(), binding.principal_id),
        (p.clone(), d.clone(), Uuid::now_v7()),
    ] {
        assert!(
            store
                .admission_operation(
                    &participant,
                    &privacy,
                    principal,
                    Some(binding.operation_id),
                    None,
                    None
                )
                .await
                .unwrap()
                .is_none()
        );
    }
    let page = store
        .artifact_page(
            p,
            d,
            &crate::ArtifactPageRequest {
                limit: 1,
                filter: None,
                sort: "updatedAt".into(),
                snapshot_at: "2099-01-01T00:00:00.000000Z".into(),
                snapshot_revision: "1".into(),
                after: None,
            },
            &signer.verifier(),
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].state, "STALE",
        "admission alone must never imply ready"
    );
    assert_eq!(
        page.items[0].artifact_digest,
        format!("sha256:{}", "11".repeat(32))
    );
    // Direct writer DML cannot forge or replace an operation on the receipt.
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, p, d).await.unwrap();
    assert!(
        sqlx::query(
            "update facts.candidate_feed_receipt set operation_binding=null where candidate_id=$1"
        )
        .bind(binding.candidate_id.to_string())
        .execute(&mut *tx)
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();

    let second = event();
    let mut atomic = binding.clone();
    atomic.operation_id = Uuid::now_v7();
    atomic.candidate_id = second.candidate_id.as_ref().unwrap().parse().unwrap();
    for commit in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        let outcome = store
            .admit_feed_batch_in_transaction(
                &mut tx,
                vec![observation(&second, profile)],
                std::slice::from_ref(&second),
                &complete_event(&second),
                &signer,
            )
            .await
            .unwrap();
        store
            .bind_feed_operation_in(
                &mut tx,
                &second.batch.participant_id,
                &second.batch.privacy_domain_id,
                &atomic,
                outcome,
            )
            .await
            .unwrap();
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        assert_eq!(store.replay_feed_receipt(&second).await.unwrap(), commit);
        assert_eq!(
            store
                .admission_operation(
                    &second.batch.participant_id,
                    &second.batch.privacy_domain_id,
                    atomic.principal_id,
                    Some(atomic.operation_id),
                    None,
                    None
                )
                .await
                .unwrap()
                .is_some(),
            commit
        );
    }
    // A reused key on a different fresh candidate must roll back the entire
    // admission, including any conflict fence discovered before the key check.
    let mut collision = event();
    collision.batch.participant_id = p.clone();
    collision.batch.privacy_domain_id = d.clone();
    let mut changed = binding.clone();
    changed.operation_id = Uuid::now_v7();
    changed.candidate_id = collision.candidate_id.as_ref().unwrap().parse().unwrap();
    let mut tx = pool.begin().await.unwrap();
    let outcome = store
        .admit_feed_batch_in_transaction(
            &mut tx,
            vec![observation(&collision, profile)],
            std::slice::from_ref(&collision),
            &complete_event(&collision),
            &signer,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .bind_feed_operation_in(&mut tx, p, d, &changed, outcome)
            .await,
        Err(FactStoreError::ReplayDigestMismatch)
    ));
    tx.rollback().await.unwrap();
    assert!(!store.replay_feed_receipt(&collision).await.unwrap());
    pool.close().await;
    let reopened = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let store = FactStore::new(reopened.clone(), secret);
    assert_eq!(
        store
            .admission_operation(
                p,
                d,
                binding.principal_id,
                Some(binding.operation_id),
                None,
                None
            )
            .await
            .unwrap(),
        Some(operation)
    );
    reopened.close().await;
}
