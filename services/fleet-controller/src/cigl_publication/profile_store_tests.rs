//! Actual installed SQL/role regression. Only migrated initial trust is used;
//! this empty-queue check does not claim a completed CIGL business journey.
use super::*;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires the migrated database in run-participant-readback.sh"]
async fn postgres_cigl_claim_defers_only_unclaimed_lifecycle_contention() {
    let pool =
        PgPool::connect(&std::env::var("OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let role: (bool, bool) =
        sqlx::query_as("select rolsuper,rolbypassrls from pg_roles where rolname=current_user")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(role, (false, false));
    let admin = PgPool::connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let counts = async || {
        sqlx::query_as::<_, (i64, i64, i64, i64)>(
            "select
             (select count(*) from control.configuration_work where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid),
             (select coalesce(sum(attempt_count),0)::bigint from control.configuration_work where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid),
             (select count(*) from control.outbox_event where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid),
             (select count(*) from control.audit_occurrence where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid)",
        )
        .bind(participant)
        .bind(privacy)
        .fetch_one(&admin)
        .await
        .unwrap()
    };
    let before = counts().await;
    assert_eq!(before.0, 0, "no business work is seeded by this regression");

    let mut fence = pool.begin().await.unwrap();
    context(&mut fence, participant, privacy).await.unwrap();
    sqlx::query(
        "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
    )
    .bind(participant)
    .execute(&mut *fence)
    .await
    .unwrap();
    let mut probe = pool.begin().await.unwrap();
    context(&mut probe, participant, privacy).await.unwrap();
    let error = sqlx::query(
        "update control.configuration_work set attempt_count=attempt_count where false",
    )
    .execute(&mut *probe)
    .await
    .unwrap_err();
    let database_error = error.as_database_error().unwrap();
    assert_eq!(database_error.code().as_deref(), Some("40001"));
    assert_eq!(database_error.message(), "PC-DATA-6007");
    probe.rollback().await.unwrap();
    // BEFORE STATEMENT runs even for an empty queue. This used to terminate
    // the shared worker and strand unrelated public indexer work.
    let deferred = tokio::time::timeout(
        Duration::from_secs(2),
        claim_next(&pool, participant, privacy, "cigl-contention-regression"),
    )
    .await
    .expect("a conflicting lifecycle owner must not reverse-wait")
    .unwrap();
    assert!(deferred.is_none());
    assert_eq!(
        counts().await,
        before,
        "no lease, attempt, result, outbox or audit write"
    );
    fence.rollback().await.unwrap();
    // The same installed claimant continues after the fence releases. Public
    // indexer/projection execution remains covered by the retained real journey.
    for _ in 0..2 {
        assert!(
            claim_next(&pool, participant, privacy, "cigl-contention-regression")
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(counts().await, before);
    assert!(
        claim_next(&pool, "malformed-scope", privacy, "denied")
            .await
            .is_err()
    );
    let reader = PgPool::connect(&std::env::var("OPENPC_FACT_WORKLOAD_TEST_READER_URL").unwrap())
        .await
        .unwrap();
    assert!(
        claim_next(&reader, participant, privacy, "denied-role")
            .await
            .is_err()
    );
    reader.close().await;
    // Both installed contention forms are definite aborts. Exact SQLSTATE and
    // message remain coupled; other serialization failures are not this fence.
    for code in ["P0001", "40001"] {
        let statement = format!(
            "do $$ begin raise exception using errcode='{code}',message='PC-DATA-6007'; end $$"
        );
        let error = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            runtime_artifact_database_error(error),
            RUNTIME_ARTIFACT_BUSY
        );
    }
    for statement in [
        "do $$ begin raise exception using errcode='P0001',message='PC-AUTH-0005'; end $$",
        "do $$ begin raise exception using errcode='P0001',message='PC-DATA-6007 extra'; end $$",
        "do $$ begin raise exception using errcode='42501',message='PC-DATA-6007'; end $$",
        "do $$ begin raise exception using errcode='40001',message='PC-DATA-6007 extra'; end $$",
        "do $$ begin raise exception using errcode='40001',message='PC-AUTH-0005'; end $$",
    ] {
        let error = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert_ne!(
            runtime_artifact_database_error(error),
            RUNTIME_ARTIFACT_BUSY
        );
    }
    assert_ne!(
        runtime_artifact_database_error(sqlx::Error::PoolClosed),
        RUNTIME_ARTIFACT_BUSY
    );
    assert_eq!(counts().await, before);
    pool.close().await;
    assert!(
        claim_next(&pool, participant, privacy, "closed-pool")
            .await
            .is_err()
    );
    admin.close().await;
}
