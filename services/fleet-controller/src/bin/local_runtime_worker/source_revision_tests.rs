//! Rollback-only adversarial checks using real publicly accepted work. These
//! exercise the shared completion/failure owner, not a seeded journey success.
use super::*;
use crate::{Value, result_transaction, tests};
use sqlx::postgres::PgPoolOptions;

async fn rewind(tx: &mut Transaction<'_, Postgres>, work: &ClaimedWork, accepted: i64) {
    sqlx::query("update control.idempotency_record set result_aggregate_version=$2,result_payload=jsonb_set(jsonb_set(result_payload,'{state}','\"ACCEPTED\"'),'{truthState}','\"UNKNOWN\"') where operation_id=$1::text::uuid")
        .bind(&work.operation_id).bind(accepted).execute(&mut **tx).await.unwrap();
    let query = if work.work_kind == "INDEXER_ADMISSION" {
        "update control.indexer_profile set state='SHADOW',revision=$2 where indexer_profile_id=$1::text::uuid"
    } else {
        "update control.projection_plan set state='DRAFT',readiness='UNKNOWN',revision=$2 where projection_plan_id=$1::text::uuid"
    };
    sqlx::query(query)
        .bind(&work.resource_id)
        .bind(accepted)
        .execute(&mut **tx)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the public indexer/projection fixture in the local runtime journey"]
async fn postgres_accepted_revision_fences_completion_and_failure() {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_PROJECTION_ADMISSION_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let base = tests::work();
    let config = tests::test_config(&base);
    let mut tx = result_transaction(&pool, &config, "PROJECTION_VALIDATION")
        .await
        .unwrap();
    let rows = sqlx::query(
        "with current_resources as (select p.projection_plan_id as resource_id,p.participant_id,p.privacy_domain_id,p.revision,p.plan_digest as digest,'PROJECTION_VALIDATION' as kind from control.projection_plan p where p.projection_plan_id=$1::text::uuid union all select i.indexer_profile_id,i.participant_id,i.privacy_domain_id,i.revision,i.method_profile_digest,'INDEXER_ADMISSION' from control.indexer_profile i join control.projection_plan p on p.indexer_profile_id=i.indexer_profile_id and p.participant_id=i.participant_id and p.privacy_domain_id=i.privacy_domain_id where p.projection_plan_id=$1::text::uuid) select w.configuration_work_id::text,w.operation_id::text,w.resource_id::text,w.work_kind,w.input_digest,r.result_aggregate_version::bigint as revision from current_resources resource join control.configuration_work w on w.resource_id=resource.resource_id and w.participant_id=resource.participant_id and w.privacy_domain_id=resource.privacy_domain_id and w.work_kind=resource.kind and w.input_digest=resource.digest join control.idempotency_record r on r.participant_id=w.participant_id and r.privacy_domain_id=w.privacy_domain_id and r.operation_id=w.operation_id where w.state='COMPLETED' and r.terminal_state='COMMITTED' and r.result_payload->>'state'='SUCCEEDED' and r.result_aggregate_version=resource.revision order by w.work_kind",
    ).bind(std::env::var("OPENPC_PROJECTION_ADMISSION_RESOURCE_ID").unwrap())
        .fetch_all(&mut *tx).await.unwrap();
    assert_eq!(rows.len(), 2);
    tx.rollback().await.unwrap();
    for row in rows {
        let mut work = base.clone();
        work.work_id = row.get("configuration_work_id");
        work.operation_id = row.get("operation_id");
        work.resource_id = row.get("resource_id");
        work.work_kind = row.get("work_kind");
        work.input_digest = row.get("input_digest");
        let accepted = row.get::<i64, _>("revision") - 1;
        let indexer = work.work_kind == "INDEXER_ADMISSION";
        let read = if indexer {
            "select to_jsonb(resource) from control.indexer_profile resource where indexer_profile_id=$1::text::uuid"
        } else {
            "select to_jsonb(resource) from control.projection_plan resource where projection_plan_id=$1::text::uuid"
        };
        let bump = if indexer {
            "update control.indexer_profile set revision=revision+2 where indexer_profile_id=$1::text::uuid"
        } else {
            "update control.projection_plan set revision=revision+2 where projection_plan_id=$1::text::uuid"
        };
        for mutation in [
            "none",
            "revision",
            "digest",
            "retired",
            "operation",
            "scope",
        ] {
            for success in [true, false] {
                let mut tx = result_transaction(&pool, &config, &work.work_kind)
                    .await
                    .unwrap();
                rewind(&mut tx, &work, accepted).await;
                let update = match (indexer, mutation) {
                    (_, "revision") => Some(bump),
                    (true, "digest") => Some(
                        "update control.indexer_profile set method_profile_digest='sha256:'||repeat('71',32) where indexer_profile_id=$1::text::uuid",
                    ),
                    (false, "digest") => Some(
                        "update control.projection_plan set plan_digest='sha256:'||repeat('71',32) where projection_plan_id=$1::text::uuid",
                    ),
                    (true, "retired") => Some(
                        "update control.indexer_profile set state='RETIRED' where indexer_profile_id=$1::text::uuid",
                    ),
                    (false, "retired") => Some(
                        "update control.projection_plan set state='RETIRED' where projection_plan_id=$1::text::uuid",
                    ),
                    _ => None,
                };
                if let Some(update) = update {
                    sqlx::query(update)
                        .bind(&work.resource_id)
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                }
                let before: Value = sqlx::query_scalar(read)
                    .bind(&work.resource_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                let mut candidate = work.clone();
                if mutation == "operation" {
                    candidate.operation_id = "018f0000-0000-7000-8000-000000000999".into();
                } else if mutation == "scope" {
                    candidate.privacy_domain_id = "018f0000-0000-7000-8000-000000000299".into();
                }
                let result = lock(&mut tx, &candidate).await;
                if mutation == "operation" || mutation == "scope" {
                    assert!(
                        result.is_err(),
                        "foreign work cannot bind the accepted revision"
                    );
                } else {
                    let fence = result.unwrap().unwrap();
                    assert_eq!(fence.current, mutation == "none");
                    let result = fence.finish(&mut tx, &candidate, success).await;
                    if mutation == "none" {
                        assert_eq!(result.unwrap(), accepted + 1);
                    } else if success {
                        assert_eq!(result.unwrap_err(), "source work revision superseded");
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            accepted,
                            "stale failure reports only its accepted revision"
                        );
                    }
                }
                let after: Value = sqlx::query_scalar(read)
                    .bind(&work.resource_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                if mutation != "none" {
                    assert_eq!(
                        before, after,
                        "stale work must not change the replacement: {mutation}"
                    );
                } else if success {
                    assert_eq!(
                        after["state"],
                        if work.work_kind == "INDEXER_ADMISSION" {
                            "QUALIFIED"
                        } else {
                            "VALIDATED"
                        }
                    );
                } else if work.work_kind == "INDEXER_ADMISSION" {
                    assert_eq!(after["state"], "QUARANTINED");
                } else {
                    assert_eq!(after["readiness"], "NOT_READY");
                }
                tx.rollback().await.unwrap();
            }
        }
        // Only alter the operation here. The resource lock must come from the
        // production fence itself, not from test setup's UPDATE of that row.
        let mut held = result_transaction(&pool, &config, &work.work_kind)
            .await
            .unwrap();
        sqlx::query("update control.idempotency_record set result_payload=jsonb_set(jsonb_set(result_payload,'{state}','\"ACCEPTED\"'),'{truthState}','\"UNKNOWN\"') where operation_id=$1::text::uuid")
            .bind(&work.operation_id).execute(&mut *held).await.unwrap();
        assert!(!lock(&mut held, &work).await.unwrap().unwrap().current);
        let mut competing = result_transaction(&pool, &config, &work.work_kind)
            .await
            .unwrap();
        sqlx::query("set local lock_timeout='250ms'")
            .execute(&mut *competing)
            .await
            .unwrap();
        let error = sqlx::query(bump)
            .bind(&work.resource_id)
            .execute(&mut *competing)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        competing.rollback().await.unwrap();
        held.rollback().await.unwrap();
    }
    pool.close().await;
}
