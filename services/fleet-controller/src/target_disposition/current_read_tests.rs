//! Real PostgreSQL rollback boundaries for current custody reads. These tests
//! acquire isolated advisory locks; they create no business authority or delivery.
use super::*;
use sqlx::postgres::PgPoolOptions;

async fn pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_current_read_busy_retry_releases_original_locks() {
    let pool = pool().await;
    let key = uuid::Uuid::now_v7().to_string();
    let mut failed = pool.begin().await.unwrap();
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&key)
        .execute(&mut *failed)
        .await
        .unwrap();
    let mut observer = pool.begin().await.unwrap();
    let locked: bool =
        sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&key)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(!locked);
    let error = sqlx::query("do $$ begin raise exception 'PC-DATA-6007'; end $$")
        .execute(&mut *failed)
        .await
        .unwrap_err();
    assert!(
        retry_current_read_after_rollback(failed, &database_error(error), 0)
            .await
            .unwrap()
    );
    let released: bool =
        sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&key)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(
        released,
        "A retry cannot retain locks from its aborted read"
    );
    observer.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_current_read_retry_rejects_denial_exhaustion_and_lost_rollback() {
    let pool = pool().await;
    for (error, attempt) in [
        ("PC-AUTH-0005", 0),
        ("TARGET-DISPOSITION-SOURCE-CONTEXT", 0),
        ("transport uncertainty", 0),
        (TARGET_DISPOSITION_BUSY, 4),
    ] {
        assert!(
            !retry_current_read_after_rollback(pool.begin().await.unwrap(), error, attempt)
                .await
                .unwrap()
        );
    }
    let mut lost = pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("select pg_backend_pid()")
        .fetch_one(&mut *lost)
        .await
        .unwrap();
    sqlx::query("select pg_terminate_backend($1)")
        .bind(pid)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        retry_current_read_after_rollback(lost, TARGET_DISPOSITION_BUSY, 0)
            .await
            .is_err()
    );
    pool.close().await;
}
