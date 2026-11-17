//! Acquire source locks before materialization or any provider/evidence effect.
use pc_runtime_types::{RuntimeError, RuntimeResult};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

pub(super) async fn begin(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
    target: &str,
    capsule: &str,
) -> RuntimeResult<Option<(Transaction<'static, Postgres>, String)>> {
    for attempt in 0..3 {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        sqlx::query("set local statement_timeout='4s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_READ_RPC-V1',false)")
            .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_| RuntimeError::InvalidAuthorization)?;
        let plan: String = sqlx::query_scalar(
            "select openpc.lock_indexer_dispatch_source($1::text::uuid,$2)::text",
        )
        .bind(target)
        .bind(capsule)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| RuntimeError::GenerationMismatch)?;
        // Keep the existing participant/module/source lock order. The lifecycle
        // owner may already hold locks we need, so never wait in reverse order.
        // The payload guard takes this same transaction lock again on every read.
        let available: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
            .fetch_one(&mut *tx).await.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if available {
            return Ok(Some((tx, plan)));
        }
        tx.rollback()
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(10 * 3u64.pow(attempt))).await;
        }
    }
    // Busy is distinct from uncertain transaction cleanup: every attempt has
    // completed rollback, so the caller can release coordination without fencing.
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (PgPool, PgPool, String, String, String, String) {
        let admin = PgPool::connect(&std::env::var("OPENPC_I02_ADMIN_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let reader = PgPool::connect(&std::env::var("OPENPC_SOURCE_FENCE_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let participant = std::env::var("OPENPC_SOURCE_FENCE_PARTICIPANT").unwrap();
        let privacy = std::env::var("OPENPC_SOURCE_FENCE_PRIVACY").unwrap();
        let target = std::env::var("OPENPC_SOURCE_FENCE_TARGET").unwrap();
        let capsule: String = sqlx::query_scalar("select active_generation_digest from control.runtime_target where runtime_target_id=$1::text::uuid and state='ACTIVE_MATCHED'")
            .bind(&target).fetch_one(&admin).await.unwrap();
        (admin, reader, participant, privacy, target, capsule)
    }

    #[tokio::test]
    #[ignore = "requires the retained public source and its real read-only database role"]
    async fn postgres_source_dispatch_busy_releases_rows_before_retry() {
        let (admin, reader, participant, privacy, target, capsule) = fixture().await;
        let mut lifecycle = admin.begin().await.unwrap();
        sqlx::query(
            "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
        )
        .bind(&participant)
        .execute(&mut *lifecycle)
        .await
        .unwrap();
        let denied = tokio::time::timeout(
            Duration::from_secs(2),
            begin(&reader, &participant, &privacy, &target, &capsule),
        )
        .await
        .unwrap();
        assert!(
            denied.unwrap().is_none(),
            "Busy exhaustion confirms rollback"
        );
        sqlx::query("select runtime_target_id from control.runtime_target where runtime_target_id=$1::text::uuid for update nowait")
            .bind(&target).fetch_one(&mut *lifecycle).await.expect("Busy exhaustion must release source row locks");
        let module_free: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('module-admission:'||$1::text||':'||$2::text,0))")
            .bind(&participant).bind(&privacy).fetch_one(&mut *lifecycle).await.unwrap();
        assert!(
            module_free,
            "Busy exhaustion must release the earlier module fence"
        );
        lifecycle.rollback().await.unwrap();

        let (mut tx, plan) = begin(&reader, &participant, &privacy, &target, &capsule)
            .await
            .unwrap()
            .unwrap();
        assert!(!plan.is_empty());
        let role: String = sqlx::query_scalar("select current_user::text")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(role, "openpc_source_control_reader");
        let mut contender = admin.begin().await.unwrap();
        let lifecycle_free: bool = sqlx::query_scalar(
            "select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
        )
        .bind(&participant)
        .fetch_one(&mut *contender)
        .await
        .unwrap();
        assert!(
            !lifecycle_free,
            "The successful source read retains lifecycle custody"
        );
        contender.rollback().await.unwrap();
        tx.rollback().await.unwrap();
        reader.close().await;
        admin.close().await;
    }

    #[tokio::test]
    #[ignore = "requires the retained public source and its real read-only database role"]
    async fn postgres_source_dispatch_rejects_wrong_generation_scope_and_closed_pool() {
        let (admin, reader, participant, privacy, target, capsule) = fixture().await;
        let wrong = format!("sha256:{}", "0".repeat(64));
        for (scope, generation) in [
            (&privacy, &wrong),
            (&uuid::Uuid::now_v7().to_string(), &capsule),
        ] {
            assert!(
                begin(&reader, &participant, scope, &target, generation)
                    .await
                    .is_err()
            );
        }
        assert!(matches!(
            begin(&reader, "not-a-uuid", &privacy, &target, &capsule).await,
            Err(RuntimeError::InvalidAuthorization)
        ));
        reader.close().await;
        assert!(matches!(
            begin(&reader, &participant, &privacy, &target, &capsule).await,
            Err(RuntimeError::RuntimeUnavailable)
        ));
        admin.close().await;
    }
}
