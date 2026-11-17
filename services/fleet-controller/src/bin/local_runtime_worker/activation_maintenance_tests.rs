//! Native acceptance uses the existing signed original, original worker role
//! and installed journal. Every qualification transaction is rolled back.
use super::*;

async fn snapshot(pool: &PgPool, config: &Config, intent: &Intent) -> Value {
    let mut tx = result_roots_with_deadlines(pool, config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    let state = original_state_digest_in(&mut tx, intent).await.unwrap();
    let audit: Value = sqlx::query_scalar("select coalesce(jsonb_agg(to_jsonb(a) order by a.configuration_work_id),'[]') from control.runtime_activation_maintenance a")
        .fetch_one(&mut *tx).await.unwrap();
    let events: Value = sqlx::query_scalar("select coalesce(jsonb_agg(to_jsonb(e) order by e.event_id),'[]') from control.outbox_event e where e.aggregate_type='runtime-targets' and e.aggregate_id=$1::text::uuid")
        .bind(&intent.runtime_target_id).fetch_one(&mut *tx).await.unwrap();
    let operation: Value = sqlx::query_scalar(
        "select to_jsonb(i) from control.idempotency_record i where i.operation_id=$1::text::uuid",
    )
    .bind(&intent.operation_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let heads: Value = sqlx::query_scalar("select coalesce(jsonb_agg(to_jsonb(h) order by h.aggregate_type,h.aggregate_id),'[]') from control.outbox_aggregate_head h where h.aggregate_id=$1::text::uuid")
        .bind(&intent.runtime_target_id).fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    serde_json::json!({"originalStateDigest":state,"audit":audit,"events":events,"operation":operation,"heads":heads})
}

#[tokio::test]
#[ignore = "requires exact private original signed activation, installed journal and actual worker role"]
async fn postgres_original_settlement_is_atomic_and_failed_intents_have_no_effect() {
    let path = PathBuf::from(required("OPENPC_ORIGINAL_ACTIVATION_INTENT_FILE").unwrap());
    let bytes = private_file(&path).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let intent: Intent = serde_json::from_slice(&bytes).unwrap();
    intent.validate().unwrap();
    let config = Config::read().unwrap();
    let pool = config.connect().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("select current_user::text")
            .fetch_one(&pool)
            .await
            .unwrap(),
        config.user
    );
    assert!(sqlx::query_scalar::<_, bool>("select current_user=session_user and current_setting('role')='none' and pg_has_role(current_user,'openpc_control_worker','USAGE') and not pg_has_role(current_user,'openpc_control_owner','USAGE') and not has_schema_privilege(current_user,'control','CREATE') and not exists(select 1 from pg_roles where rolname=current_user and (rolsuper or rolbypassrls))").fetch_one(&pool).await.unwrap());
    let baseline = snapshot(&pool, &config, &intent).await;
    assert_eq!(
        baseline["originalStateDigest"],
        intent.original_state_digest
    );
    let digest = format!("sha256:{}", Digest::of(&bytes).as_str());
    // The source-lock owner still rejects activation purpose, even when the
    // same transaction already holds its fences. No SQL guard was widened.
    let mut wrong_context = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    let denied = sqlx::query("select openpc.lock_cigl_invalidation_participant()")
        .execute(&mut *wrong_context)
        .await
        .unwrap_err();
    assert!(matches!(denied, sqlx::Error::Database(ref db)
        if db.code().as_deref()==Some("P0001") && db.message()=="PC-AUTH-0005-CIGL-INVALIDATION-PARTICIPANT"));
    wrong_context.rollback().await.unwrap();
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // Two successful rehearsals must each restore the exact original state,
    // result/event cardinality and aggregate head when rolled back.
    for _ in 0..2 {
        let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
            .await
            .unwrap();
        assert!(
            !settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("select openpc.current_action_intent_id()::text")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            "ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("select current_setting('statement_timeout')")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            "5s"
        );
        let completed: bool = sqlx::query_scalar("select state='COMPLETED' and execution_attempt_id=$2::text::uuid and attempt_count=$3 and result_receipt_digest=$4 from control.configuration_work where configuration_work_id=$1::text::uuid")
            .bind(&intent.work_id).bind(&intent.execution_attempt_id).bind(intent.claim_count).bind(&intent.receipt_digest)
            .fetch_one(&mut *tx).await.unwrap();
        assert!(completed);
        let audit_count: i64 = sqlx::query_scalar("select count(*) from control.runtime_activation_maintenance where configuration_work_id=$1::text::uuid and intent_digest=$2")
            .bind(&intent.work_id).bind(&digest).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(audit_count, 1);
        let original_authorization: bool = sqlx::query_scalar(r#"select result.cose_sign1=authorization_row.cose_sign1
            and authorization_row.catalog_operation_id='CFG-OP-RENEW-POLICY-ACTIVATION'
            and authorization_row.aggregate_type='policy-activation-renewal'
            and authorization_row.evidence_role='LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE' and authorization_row.evidence_format='LEGACY'
            and authorization_row.aggregate_id=cohort.activation_occurrence_id
            and authorization_row.webauthn_assertion_binding_digest is not null
            from control.configuration_work w
            join control.policy_activation_occurrence_target cohort using(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id)
            join control.mutation_evidence authorization_row on authorization_row.participant_id=cohort.participant_id
              and authorization_row.privacy_domain_id=cohort.privacy_domain_id and authorization_row.operation_id=cohort.command_operation_id
            join control.outbox_event result on result.participant_id=w.participant_id
              and result.privacy_domain_id=w.privacy_domain_id and result.event_id=w.result_event_id
            where w.configuration_work_id=$1::text::uuid and cohort.phase='FORWARD'"#)
            .bind(&intent.work_id).fetch_one(&mut *tx).await.unwrap();
        assert!(original_authorization);
        // Exact replay is read-only even in the still-uncommitted same session.
        assert!(
            settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
                .await
                .unwrap()
        );
        // A changed operator intent cannot borrow the completed record's audit.
        let mut changed = value.clone();
        changed["reason"] = serde_json::json!("Different operator intent");
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        let changed_intent: Intent = serde_json::from_slice(&changed_bytes).unwrap();
        let changed_digest = format!("sha256:{}", Digest::of(&changed_bytes).as_str());
        assert!(
            settle_in(
                &mut tx,
                &config,
                &pool,
                &changed_intent,
                &changed_bytes,
                &changed_digest
            )
            .await
            .is_err()
        );
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind("018f0000-0000-7000-8000-000000000999").bind("018f0000-0000-7000-8000-000000000998")
            .execute(&mut *tx).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "select count(*) from control.runtime_activation_maintenance"
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            0
        );
        set_context(&mut tx, &config).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "select count(*) from control.runtime_activation_maintenance"
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            1
        );
        tx.rollback().await.unwrap();
        assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    }
    let foreign = "018f0000-0000-7000-8000-000000000999";
    let wrong_digest = format!("sha256:{}", "f".repeat(64));
    for (key, replacement) in [
        ("participantId", serde_json::json!(foreign)),
        ("privacyDomainId", serde_json::json!(foreign)),
        ("workId", serde_json::json!(foreign)),
        ("operationId", serde_json::json!(foreign)),
        ("executionAttemptId", serde_json::json!(foreign)),
        ("occurrenceId", serde_json::json!(foreign)),
        ("runtimeTargetId", serde_json::json!(foreign)),
        ("generationId", serde_json::json!(foreign)),
        ("generationDigest", serde_json::json!(wrong_digest)),
        ("configurationDigest", serde_json::json!(wrong_digest)),
        ("xdsVersionDigest", serde_json::json!(wrong_digest)),
        ("capsuleDigest", serde_json::json!(wrong_digest)),
        ("receiptDigest", serde_json::json!(wrong_digest)),
        ("deliveryDigest", serde_json::json!(wrong_digest)),
        ("acknowledgementDigest", serde_json::json!(wrong_digest)),
        ("originalStateDigest", serde_json::json!(wrong_digest)),
        (
            "dispositionRevision",
            serde_json::json!(intent.disposition_revision + 1),
        ),
        ("claimCount", serde_json::json!(intent.claim_count + 1)),
        ("databaseServerAddress", serde_json::json!("203.0.113.10")),
        ("databaseOid", serde_json::json!("1")),
        ("databaseRole", serde_json::json!("foreign_worker_login")),
        ("workerRole", serde_json::json!("openpc_control_reader")),
    ] {
        let mut altered = value.clone();
        altered[key] = replacement;
        let altered_bytes = serde_json::to_vec(&altered).unwrap();
        let altered_intent: Intent = serde_json::from_slice(&altered_bytes).unwrap();
        let altered_digest = format!("sha256:{}", Digest::of(&altered_bytes).as_str());
        let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
            .await
            .unwrap();
        assert!(
            settle_in(
                &mut tx,
                &config,
                &pool,
                &altered_intent,
                &altered_bytes,
                &altered_digest
            )
            .await
            .is_err(),
            "{key}"
        );
        tx.rollback().await.unwrap();
        assert_eq!(snapshot(&pool, &config, &intent).await, baseline, "{key}");
    }
    // Deliberately fail the LAST audit write after valid completion writes.
    // The digest mismatch must roll the entire transaction back to infinity.
    let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    assert!(
        settle_in(&mut tx, &config, &pool, &intent, &bytes, &wrong_digest)
            .await
            .unwrap_err()
            .contains("audit write")
    );
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // A concurrent owner must fail immediately without claiming or requeueing.
    let mut other = pool.begin().await.unwrap();
    sqlx::query(
        "select pg_advisory_xact_lock(hashtextextended('original-activation-maintenance',0))",
    )
    .execute(&mut *other)
    .await
    .unwrap();
    let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    assert_eq!(
        settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
            .await
            .unwrap_err(),
        "maintenance owner busy"
    );
    tx.rollback().await.unwrap();
    other.rollback().await.unwrap();
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // Losing this exact test connection after ALL completion/audit writes,
    // before COMMIT, cannot leave any durable effect. Terminate only our own
    // worker-role backend; no service or unrelated session is targeted.
    let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    assert!(
        !settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
            .await
            .unwrap()
    );
    let application = format!("maint-qual-{}", uuid::Uuid::now_v7());
    sqlx::query("select set_config('application_name',$1,true)")
        .bind(&application)
        .execute(&mut *tx)
        .await
        .unwrap();
    let backend = sqlx::query("select pid,backend_start::text,usename::text,datname,application_name from pg_stat_activity where pid=pg_backend_pid()")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!(backend.get::<String, _>("usename"), config.user);
    assert_eq!(backend.get::<String, _>("datname"), config.database);
    assert_eq!(backend.get::<String, _>("application_name"), application);
    // Match the captured backend incarnation and our unique test identity in
    // the same statement which signals it. No PID-only fallback is permitted.
    assert!(sqlx::query_scalar::<_, bool>("select pg_terminate_backend(pid,5000) from pg_stat_activity where pid=$1 and backend_start=$2::text::timestamptz and application_name=$3 and usename=current_user and datname=current_database() and pid<>pg_backend_pid()")
        .bind(backend.get::<i32,_>("pid")).bind(backend.get::<String,_>("backend_start")).bind(&application)
        .fetch_one(&pool).await.unwrap());
    assert!(tx.rollback().await.is_err());
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // A real server statement deadline after the writes also aborts the entire
    // transaction. The production entry sets this same finite deadline.
    let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    assert!(
        !settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
            .await
            .unwrap()
    );
    let timeout = sqlx::query("select pg_sleep(11)")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(matches!(timeout, sqlx::Error::Database(ref db)
        if db.code().as_deref()==Some("57014") && db.message()=="canceling statement due to statement timeout"));
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // An effective role switch is rejected even when it names the worker
    // group. This is a rollback-only denial, never the maintenance execution identity.
    let mut tx = result_roots_with_deadlines(&pool, &config, "RUNTIME_ACTIVATION", true)
        .await
        .unwrap();
    sqlx::query("set local role openpc_control_worker")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        settle_in(&mut tx, &config, &pool, &intent, &bytes, &digest)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&pool, &config, &intent).await, baseline);
    // Same-transaction xid comparison keeps the low 32-bit representation
    // across epochs rather than comparing xid to the epoch-bearing bigint.
    assert!(
        sqlx::query_scalar::<_, bool>("select '4294967297'::xid8::xid='1'::xid")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}
