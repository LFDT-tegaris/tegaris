//! Real PostgreSQL commit/signing primitive coverage. The isolated marker table
//! is not an admitted business operation; public Fact issuance remains covered
//! by the runtime fixture, not by these transaction-level regressions.
use super::*;
use pc_runtime_types::target_disposition::{
    TargetDispositionAction, TargetDispositionCause, TargetDispositionIdentity,
    TargetDispositionSource,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn id(n: u32) -> String {
    format!("018f0000-0000-7000-8000-{n:012x}")
}
fn identity() -> TargetDispositionIdentity {
    TargetDispositionIdentity {
        participant_id: id(1),
        privacy_domain_id: id(2),
        target_id: id(3),
        credential_id: id(4),
        principal_id: id(12),
        credential_epoch: 1,
        principal_epoch: 2,
        certificate_digest: Digest::of(b"actual certificate"),
    }
}
fn source() -> TargetDispositionSource {
    TargetDispositionSource {
        runtime_configuration_input_id: id(5),
        configuration_digest: Digest::of(b"original full input"),
        module_installation_id: id(6),
        module_configuration_generation_id: id(7),
        runtime_configuration_generation_id: id(8),
        capsule_digest: Digest::of(b"capsule"),
        xds_version_digest: Digest::of(b"xds"),
        predecessor_capsule_digest: Some(Digest::of(b"predecessor")),
        original_work_id: id(9),
        original_operation_id: id(10),
        original_execution_attempt_id: id(11),
    }
}
fn withdrawal() -> TargetDispositionDelivery {
    TargetDispositionDelivery {
        version: 1,
        target: identity(),
        source: source(),
        cause: TargetDispositionCause::Activation {
            work_id: id(12),
            operation_id: id(13),
            execution_attempt_id: Some(id(14)),
        },
        action: TargetDispositionAction::Withdraw,
        revision: 1,
        previous_revision: 0,
        previous_delivery_digest: None,
        committed_admission_digest: Digest::of(b"committed original admission"),
    }
}

struct CountedSigner {
    real: PurposeSigner,
    calls: AtomicUsize,
}
impl CountedSigner {
    fn new() -> Self {
        Self {
            real: PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_DELIVERY_PURPOSE, [21; 32])
                .unwrap(),
            calls: AtomicUsize::new(0),
        }
    }
}
impl DeliverySigner for CountedSigner {
    fn sign_delivery(&self, claims: TargetDispositionDelivery) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.real.sign_delivery(claims)
    }
}

// Dynamic identifiers below consist solely of this fixed prefix plus a native
// generated UUID; no environment, request or arbitrary SQL enters an identifier.
async fn database() -> (PgPool, String) {
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let table = format!(
        "public.openpc_issuance_test_{}",
        uuid::Uuid::now_v7().simple()
    );
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "create table {table}(id integer primary key)"
    )))
    .execute(&pool)
    .await
    .unwrap();
    (pool, table)
}
async fn inserted<'a>(pool: &'a PgPool, table: &str) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "insert into {table} values(1)"
    )))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx
}
async fn count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("select count(*) from {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn cleanup(pool: PgPool, table: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!("drop table {table}")))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_first_issue_commit_is_visible_before_real_signer_call() {
    let (pool, table) = database().await;
    let signer = CountedSigner::new();
    let tx = inserted(&pool, &table).await;
    assert_eq!(count(&pool, &table).await, 0);
    let permit = FirstIssuePermit::commit_new(tx, None, withdrawal())
        .await
        .unwrap();
    // Independent connection sees the irreversible marker before crypto runs.
    assert_eq!(count(&pool, &table).await, 1);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    let bytes = permit.sign(&signer).unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    let signed: pc_runtime_types::SignedEnvelope<TargetDispositionDelivery> =
        serde_json::from_slice(&bytes).unwrap();
    signer.real.verifier().verify(&signed).unwrap();
    cleanup(pool, &table).await;
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_first_issue_signing_error_keeps_committed_marker() {
    let (pool, table) = database().await;
    let signer = CountedSigner::new();
    let mut invalid = withdrawal();
    invalid.revision = 0; // Real typed encoder rejects after the crypto call.
    let permit = FirstIssuePermit::commit_new(inserted(&pool, &table).await, None, invalid)
        .await
        .unwrap();
    assert!(permit.sign(&signer).is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(count(&pool, &table).await, 1);
    cleanup(pool, &table).await;
}

// Transparent local wire fault: real PostgreSQL authenticates and executes every
// statement. Only its COMMIT response is lost, before SQLx can observe it. This
// is not a successful commit whose return value the test chooses to ignore.
async fn lose_commit_response(options: PgConnectOptions) -> (PgPool, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream_host = options.get_host().to_owned();
    let upstream_port = options.get_port();
    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect((upstream_host.as_str(), upstream_port))
            .await
            .unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = server.into_split();
        let forward = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut sw).await });
        loop {
            let tag = sr.read_u8().await.unwrap();
            let length = sr.read_u32().await.unwrap();
            assert!((4..=16 * 1024 * 1024).contains(&length));
            let mut body = vec![0; (length - 4) as usize];
            sr.read_exact(&mut body).await.unwrap();
            if tag == b'C' && body == b"COMMIT\0" {
                // Server CommandComplete proves it really committed. Neither
                // that message nor ReadyForQuery reaches the application.
                forward.abort();
                cw.shutdown().await.unwrap();
                break;
            }
            cw.write_u8(tag).await.unwrap();
            cw.write_u32(length).await.unwrap();
            cw.write_all(&body).await.unwrap();
        }
    });
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .test_before_acquire(false)
        .connect_with(
            options
                .host("127.0.0.1")
                .port(port)
                .ssl_mode(PgSslMode::Disable),
        )
        .await
        .unwrap();
    (pool, task)
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_first_issue_lost_commit_response_never_yields_signing_permit() {
    let (observer, table) = database().await;
    let options: PgConnectOptions = std::env::var("OPENPC_I02_ADMIN_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    let (pool, proxy) = lose_commit_response(options).await;
    let signer = CountedSigner::new();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        FirstIssuePermit::commit_new(inserted(&pool, &table).await, None, withdrawal()),
    )
    .await
    .unwrap();
    proxy.await.unwrap();
    assert!(
        result.is_err(),
        "SQLx must observe actual transport uncertainty"
    );
    if let Ok(permit) = result {
        let _ = permit.sign(&signer);
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        count(&observer, &table).await,
        1,
        "Original server commit must survive the lost response"
    );
    pool.close().await;
    cleanup(observer, &table).await;
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_first_issue_busy_rollback_retains_only_the_original_unsigned_permit() {
    let (pool, table) = database().await;
    let signer = CountedSigner::new();
    let mut permit = Some(
        FirstIssuePermit::commit_new(inserted(&pool, &table).await, None, withdrawal())
            .await
            .unwrap(),
    );
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&table)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let acquired: bool =
        sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&table)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(!acquired);
    // The production lock owner raises this exact error when acquisition fails.
    let error = sqlx::query("do $$ begin raise exception 'PC-DATA-6007'; end $$")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(
        retry_unsigned_after_rollback(tx, &database_error(error), &permit, 0)
            .await
            .unwrap()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(count(&pool, &table).await, 1);
    blocker.rollback().await.unwrap();
    let mut retry = pool.begin().await.unwrap();
    let acquired: bool =
        sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&table)
            .fetch_one(&mut *retry)
            .await
            .unwrap();
    assert!(acquired);
    permit.take().unwrap().sign(&signer).unwrap();
    retry.commit().await.unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert!(
        !retry_unsigned_after_rollback(
            pool.begin().await.unwrap(),
            TARGET_DISPOSITION_BUSY,
            &permit,
            1
        )
        .await
        .unwrap()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    cleanup(pool, &table).await;
}

#[tokio::test]
#[ignore = "requires the real disposable PostgreSQL transaction owner"]
async fn postgres_first_issue_unsigned_retry_rejects_denial_exhaustion_and_lost_rollback() {
    let (pool, table) = database().await;
    let signer = CountedSigner::new();
    let permit = Some(
        FirstIssuePermit::commit_new(inserted(&pool, &table).await, None, withdrawal())
            .await
            .unwrap(),
    );
    for (error, attempt) in [
        ("PC-AUTH-0005", 0),
        ("transport uncertainty", 0),
        (TARGET_DISPOSITION_BUSY, 4),
    ] {
        assert!(
            !retry_unsigned_after_rollback(pool.begin().await.unwrap(), error, &permit, attempt)
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
        retry_unsigned_after_rollback(lost, TARGET_DISPOSITION_BUSY, &permit, 0)
            .await
            .is_err()
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(count(&pool, &table).await, 1);
    cleanup(pool, &table).await;
}

#[test]
fn operator_window_is_rechecked_inside_the_consuming_sign_boundary() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    for (issued, expires) in [
        (now - 1000, now - 1),
        (now + 60_000, now + 61_000),
        (now - 1000, now + 120_000),
    ] {
        let signer = CountedSigner::new();
        let permit = FirstIssuePermit {
            claims: withdrawal(),
            operator_window: None,
        }
        .with_operator_window(issued, expires);
        assert!(permit.sign(&signer).is_err());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    }
    let signer = CountedSigner::new();
    let permit = FirstIssuePermit {
        claims: withdrawal(),
        operator_window: None,
    }
    .with_operator_window(now - 1000, now + 60_000);
    assert!(permit.sign(&signer).is_ok());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}
