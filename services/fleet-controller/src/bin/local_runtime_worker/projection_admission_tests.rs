//! Regression of the completion fence using a source qualified through public
//! owners. All fault injection rolls back; this is not acquired-fact acceptance.
use super::*;
use crate::{result_transaction, tests};
use sqlx::{Row, postgres::PgPoolOptions};

#[tokio::test]
#[ignore = "requires the public indexer/projection fixture in the local runtime journey"]
async fn postgres_current_source_fences_revision_scope_and_concurrent_update() {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_PROJECTION_ADMISSION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut work = tests::work();
    let config = tests::test_config(&work);
    let mut tx = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
        .await
        .unwrap();
    let row = sqlx::query(
        "select w.resource_id::text,w.input_digest,w.configuration_digest,w.result_receipt,w.operation_id::text from control.configuration_work w join control.projection_plan p on p.projection_plan_id=w.resource_id and p.participant_id=w.participant_id and p.privacy_domain_id=w.privacy_domain_id join control.idempotency_record r on r.participant_id=w.participant_id and r.operation_id=w.operation_id where w.work_kind='PROJECTION_VALIDATION' and w.state='COMPLETED' and w.resource_id=$1::text::uuid and w.input_digest=p.plan_digest and r.terminal_state='COMMITTED' and r.result_payload->>'state'='SUCCEEDED' and r.result_aggregate_version=p.revision",
    )
    .bind(std::env::var("OPENPC_PROJECTION_ADMISSION_RESOURCE_ID").unwrap())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    work.resource_id = row.get("resource_id");
    work.input_digest = row.get("input_digest");
    work.configuration_digest = parse_digest(row.get("configuration_digest")).unwrap();
    let receipt: Value = row.get("result_receipt");
    let operation_id: String = row.get("operation_id");
    let source_id = field(&receipt, "profileResourceId").unwrap();
    tx.rollback().await.unwrap();

    for mutation in [
        "none",
        "digest",
        "revision",
        "quarantine",
        "retire",
        "scope",
        "qualification-operation",
        "qualification-revision",
    ] {
        let mut tx = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
            .await
            .unwrap();
        // Re-enter the pre-completion state only inside this rolled-back owner
        // regression. Qualification and its successful result remain real.
        sqlx::query("update control.projection_plan set state='DRAFT',readiness='UNKNOWN' where projection_plan_id=$1::text::uuid")
            .bind(&work.resource_id).execute(&mut *tx).await.unwrap();
        match mutation {
            "digest" => {
                sqlx::query("update control.indexer_profile set method_profile_digest='sha256:'||repeat('71',32) where indexer_profile_id=$1::text::uuid")
                    .bind(source_id).execute(&mut *tx).await.unwrap();
            }
            "revision" => {
                // A -> B -> A has the original bytes but a newer revision.
                sqlx::query("update control.indexer_profile set revision=revision+2 where indexer_profile_id=$1::text::uuid")
                    .bind(source_id).execute(&mut *tx).await.unwrap();
            }
            "quarantine" | "retire" => {
                sqlx::query("update control.indexer_profile set state=$2 where indexer_profile_id=$1::text::uuid")
                    .bind(source_id).bind(if mutation == "retire" { "RETIRED" } else { "QUARANTINED" })
                    .execute(&mut *tx).await.unwrap();
            }
            _ => {}
        }
        let mut candidate = work.clone();
        let mut completion_receipt = receipt.clone();
        if mutation == "scope" {
            candidate.privacy_domain_id = "018f0000-0000-7000-8000-000000000299".into();
        } else if mutation == "qualification-operation" {
            completion_receipt["profileQualificationOperationId"] =
                Value::String("018f0000-0000-7000-8000-000000000999".into());
        } else if mutation == "qualification-revision" {
            completion_receipt["profileQualificationRevision"] = Value::String("0".into());
        }
        let result = assert_current(&mut tx, &candidate, &completion_receipt).await;
        if mutation == "none" {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err(),
                crate::source_revision::SUPERSEDED,
                "{mutation}"
            );
        }
        tx.rollback().await.unwrap();
    }

    let mut held = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
        .await
        .unwrap();
    sqlx::query("update control.projection_plan set state='DRAFT',readiness='UNKNOWN' where projection_plan_id=$1::text::uuid")
        .bind(&work.resource_id).execute(&mut *held).await.unwrap();
    assert_current(&mut held, &work, &receipt).await.unwrap();
    let mut update = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
        .await
        .unwrap();
    sqlx::query("set local lock_timeout='250ms'")
        .execute(&mut *update)
        .await
        .unwrap();
    let blocked = sqlx::query("update control.indexer_profile set revision=revision+1 where indexer_profile_id=$1::text::uuid")
        .bind(source_id).execute(&mut *update).await.unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    update.rollback().await.unwrap();
    held.rollback().await.unwrap();

    let mut tx = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
        .await
        .unwrap();
    let retained: Value = sqlx::query_scalar("select result_receipt from control.configuration_work where work_kind='PROJECTION_VALIDATION' and state='COMPLETED' and resource_id=$1::text::uuid and operation_id=$2::text::uuid")
        .bind(&work.resource_id).bind(operation_id).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(retained, receipt);
    let ready: bool = sqlx::query_scalar("select state='VALIDATED' and readiness='READY' from control.projection_plan where projection_plan_id=$1::text::uuid")
        .bind(&work.resource_id).fetch_one(&mut *tx).await.unwrap();
    assert!(
        ready,
        "fault injection did not persist any business transition"
    );
    tx.rollback().await.unwrap();
    pool.close().await;
}
