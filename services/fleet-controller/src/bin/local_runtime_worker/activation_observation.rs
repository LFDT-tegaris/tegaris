//! Retry only the receipt transaction after a confirmed database abort.
use super::discovery_retry::ObservationFailure;
use super::*;
use sqlx::Acquire;
use std::future::Future;

pub(super) fn require_activation_budget(expires_ns: u64, now_ns: u64) -> WorkerResult<()> {
    if expires_ns.saturating_sub(now_ns) < 20_000_000_000 {
        return Err("identity publication has insufficient activation validity".into());
    }
    Ok(())
}

async fn retry_aborted<F, Fut, Pause, Delay>(
    mut observe: F,
    mut pause: Pause,
) -> Result<(), ObservationFailure>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), ObservationFailure>>,
    Pause: FnMut(Duration) -> Delay,
    Delay: Future<Output = ()>,
{
    for attempt in 1..=8 {
        match observe().await {
            Ok(()) => return Ok(()),
            Err(mut error) => {
                error.attempt = attempt;
                if !error.retryable() || attempt == 8 {
                    return Err(error);
                }
                pause(Duration::from_millis((25u64 << (attempt - 1)).min(400))).await;
            }
        }
    }
    unreachable!("eighth receipt transaction is terminal")
}

pub(super) async fn record(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    execution_attempt_id: &str,
    capsule_digest: &Digest,
    receipt: &Value,
) -> WorkerResult<Digest> {
    let receipt_digest = Digest::of(
        canonical_bytes(receipt).map_err(|_| "activation receipt encoding rejected".to_owned())?,
    );
    retry_aborted(
        || {
            record_once(
                pool,
                work,
                config,
                execution_attempt_id,
                capsule_digest,
                receipt,
                &receipt_digest,
            )
        },
        tokio::time::sleep,
    )
    .await
    .map_err(|error| {
        eprintln!(
            "{}",
            serde_json::json!({"level":"warn","event":"activation_observation_rejected",
            "work_id":work.work_id,"execution_attempt_id":execution_attempt_id,
            "stage":error.stage,"sqlstate":error.sqlstate,"attempt":error.attempt,
            "disposition":if error.retryable(){"RETRIES_EXHAUSTED"}else{"FAIL_CLOSED"}})
        );
        "activation observation unavailable; reconcile original attempt".to_owned()
    })?;
    Ok(receipt_digest)
}

async fn record_once(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    execution_attempt_id: &str,
    capsule_digest: &Digest,
    receipt: &Value,
    receipt_digest: &Digest,
) -> Result<(), ObservationFailure> {
    let generation_id = work
        .generation_id
        .as_deref()
        .ok_or_else(|| ObservationFailure::terminal("generation"))?;
    let target_id = work
        .target_id
        .as_deref()
        .ok_or_else(|| ObservationFailure::terminal("target"))?;
    let generation_digest = work
        .generation_digest
        .as_ref()
        .ok_or_else(|| ObservationFailure::terminal("generation_digest"))?;
    let xds_version_digest = work
        .xds_version_digest
        .as_ref()
        .ok_or_else(|| ObservationFailure::terminal("xds_digest"))?;
    let mut connection = pool
        .acquire()
        .await
        .map_err(|e| ObservationFailure::database("acquire", e))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|e| ObservationFailure::database("begin", e))?;
    let result: Result<(), ObservationFailure> = async {
        set_context(&mut transaction, config).await.map_err(|_| ObservationFailure::terminal("context"))?;
        sqlx::query("insert into control.runtime_activation_observation(participant_id,privacy_domain_id,configuration_work_id,operation_id,execution_attempt_id,runtime_configuration_generation_id,runtime_target_id,generation_digest,capsule_digest,xds_version_digest,activation_receipt,activation_receipt_digest) values ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::text::uuid,$8,$9,$10,$11,$12)")
            .bind(&work.participant_id).bind(&work.privacy_domain_id).bind(&work.work_id)
            .bind(&work.operation_id).bind(execution_attempt_id).bind(generation_id).bind(target_id)
            .bind(format!("sha256:{}", generation_digest.as_str()))
            .bind(format!("sha256:{}", capsule_digest.as_str()))
            .bind(format!("sha256:{}", xds_version_digest.as_str())).bind(receipt)
            .bind(format!("sha256:{}", receipt_digest.as_str()))
            .execute(&mut *transaction).await.map_err(|e| ObservationFailure::database("insert", e))?;
        Ok(())
    }.await;
    if let Err(error) = result {
        if let Err(rollback) = transaction.rollback().await {
            eprintln!(
                "{}",
                serde_json::json!({"level":"warn","event":"activation_observation_rollback_unavailable",
                "work_id":work.work_id,"primary_stage":error.stage,"primary_sqlstate":error.sqlstate})
            );
            return Err(ObservationFailure::database("rollback", rollback));
        }
        return Err(error);
    }
    if let Err(error) = transaction.commit().await {
        // Flush SQLx's queued rollback on this same connection before considering
        // a COMMIT 40001. A transport error never authorizes another INSERT.
        sqlx::Connection::ping(&mut *connection)
            .await
            .map_err(|e| ObservationFailure::database("rollback", e))?;
        return Err(ObservationFailure::database("commit", error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, future::ready};
    fn failure(stage: &'static str, code: Option<&str>) -> ObservationFailure {
        ObservationFailure {
            stage,
            sqlstate: code.map(str::to_owned),
            attempt: 0,
        }
    }
    #[tokio::test]
    async fn retries_only_confirmed_aborts_with_same_observation() {
        let count = Cell::new(0);
        let waits = Cell::new(0);
        retry_aborted(
            || {
                count.set(count.get() + 1);
                ready(if count.get() < 3 {
                    Err(failure("insert", Some("40001")))
                } else {
                    Ok(())
                })
            },
            |_| {
                waits.set(waits.get() + 1);
                ready(())
            },
        )
        .await
        .unwrap();
        assert_eq!((count.get(), waits.get()), (3, 2));
    }
    #[tokio::test]
    async fn never_retries_uncertain_commit_or_failed_rollback_or_denial() {
        for (stage, code) in [
            ("commit", None),
            ("commit", Some("08006")),
            ("rollback", Some("40001")),
            ("insert", Some("42501")),
            ("insert", Some("23505")),
            ("insert", Some("57014")),
        ] {
            let count = Cell::new(0);
            let e = retry_aborted(
                || {
                    count.set(count.get() + 1);
                    ready(Err(failure(stage, code)))
                },
                |_| ready(()),
            )
            .await
            .unwrap_err();
            assert_eq!(count.get(), 1);
            assert_eq!(e.attempt, 1);
        }
    }
    #[tokio::test]
    async fn exhausted_aborts_are_bounded_and_return_original_phase() {
        let count = Cell::new(0);
        let e = retry_aborted(
            || {
                count.set(count.get() + 1);
                ready(Err(failure("commit", Some("40001"))))
            },
            |_| ready(()),
        )
        .await
        .unwrap_err();
        assert_eq!(count.get(), 8);
        assert_eq!(e.attempt, 8);
        assert_eq!(e.stage, "commit");
    }
    #[test]
    fn activation_budget_is_checked_before_effect_without_extending_expiry() {
        assert!(require_activation_budget(30_000_000_000, 10_000_000_000).is_ok());
        assert!(require_activation_budget(30_000_000_000, 10_000_000_001).is_err());
        assert!(require_activation_budget(9, 10).is_err());
    }
}
