//! Separate pre-0008 invocation over the supported predecessor migration fixture
//! or existing CandidateStore producer. This proves preservation only; historical
//! fixture rows never establish current source or governed retirement authority.
use super::*;
use sha2::{Digest as _, Sha256};

#[tokio::test]
#[ignore = "requires an exclusively owned populated pre-0008 candidate database and scope"]
async fn populated_upgrade_preserves_payload_identity_checkpoints_and_feed_high_water() {
    let scope: RetirementScope = serde_json::from_str(
        &std::env::var("OPENPC_CANDIDATE_UPGRADE_SCOPE_JSON").unwrap_or_else(|_| {
            panic!(
                "OPENPC_CANDIDATE_RETIREMENT|status=BLOCKED|reason=MISSING_POPULATED_UPGRADE_SCOPE"
            )
        }),
    )
    .unwrap();
    let store =
        CandidateStore::connect(&std::env::var("OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_I06_GATE3_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = store.pool.begin().await.unwrap();
    context(&mut tx, &scope).await;
    let installed: bool =
        sqlx::query_scalar("select to_regclass('candidate.store_retirement_attempt') is not null")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(!installed, "upgrade requires actual prior schema");
    let before: serde_json::Value=sqlx::query_scalar("select jsonb_build_object(
      'events',(select jsonb_agg(to_jsonb(e) order by e.candidate_event_id) from candidate.candidate_event e),
      'checkpoints',(select jsonb_agg(to_jsonb(c) order by c.checkpoint_id) from candidate.checkpoint c),
      'heads',(select jsonb_agg(to_jsonb(h) order by h.aggregate_id) from candidate.outbox_aggregate_head h))")
        .fetch_one(&mut *tx).await.unwrap();
    assert!(
        before["events"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "populated upgrade cannot pass on an empty fixture"
    );
    tx.rollback().await.unwrap();
    let migration = include_str!(
        "../../../../../../migrations/postgres/candidate-index/0008_store_retirement.sql"
    );
    let body = migration
        .split_once("BEGIN;\n")
        .unwrap()
        .1
        .split_once("INSERT INTO candidate.schema_migration(")
        .unwrap()
        .0;
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("set local role openpc_candidate_index_owner")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(body))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "insert into candidate.schema_migration(migration_id,migration_checksum,profile,phase)
      values('OPENPC-MIG-CANDIDATE-0008',$1,'MIG-PREDECESSOR-V1','M1_ADDITIVE_INACTIVE')",
    )
    .bind(Sha256::digest(migration.as_bytes()).to_vec())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut tx = store.pool.begin().await.unwrap();
    context(&mut tx, &scope).await;
    let after: serde_json::Value=sqlx::query_scalar("select jsonb_build_object(
      'events',(select jsonb_agg(to_jsonb(e) order by e.candidate_event_id) from candidate.candidate_event e),
      'checkpoints',(select jsonb_agg(to_jsonb(c) order by c.checkpoint_id) from candidate.checkpoint c),
      'heads',(select jsonb_agg(to_jsonb(h) order by h.aggregate_id) from candidate.outbox_aggregate_head h))")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!(before, after);
    let matched: bool=sqlx::query_scalar("select not exists(select 1 from candidate.candidate_event e
      left join candidate.retained_candidate_identity i using(candidate_event_id)
      where i.candidate_event_id is null or i.original_identity<>to_jsonb(e)-'payload_cbor'
        or i.payload_digest<>sha256(e.payload_cbor) or i.payload_bytes<>octet_length(e.payload_cbor))")
        .fetch_one(&mut *tx).await.unwrap();
    assert!(matched);
    let rls_restored: bool=sqlx::query_scalar("select count(*)=3 and bool_and(relrowsecurity and relforcerowsecurity)
      from pg_class where oid in ('candidate.candidate_event'::regclass,'candidate.candidate_relation'::regclass,
      'candidate.retained_candidate_identity'::regclass)")
        .fetch_one(&mut *tx).await.unwrap();
    assert!(
        rls_restored,
        "migration must restore FORCE RLS before commit"
    );
    tx.rollback().await.unwrap();
    let foreign = RetirementScope {
        participant_id: scope.participant_id.clone(),
        privacy_domain_id: Uuid::now_v7().to_string(),
    };
    let mut tx = store.pool.begin().await.unwrap();
    context(&mut tx, &foreign).await;
    let visible: i64 =
        sqlx::query_scalar("select count(*) from candidate.retained_candidate_identity")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        visible, 0,
        "retained identities must preserve privacy isolation"
    );
    tx.rollback().await.unwrap();
}
