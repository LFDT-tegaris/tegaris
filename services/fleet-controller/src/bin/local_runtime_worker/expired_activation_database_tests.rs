//! Rollback-only qualification against the original expired effect and the
//! installed worker login. No delivery is signed and no business row commits.
use super::*;
use sqlx::{Postgres, Transaction};

async fn attempt(
    tx: &mut Transaction<'_, Postgres>,
    config: &Config,
    intent: &Value,
    original: &retained_target::RetainedTarget,
) -> Result<Value, sqlx::Error> {
    let source: Value = sqlx::query_scalar("select jsonb_build_object('runtime_configuration_input_id',i.runtime_configuration_input_id::text,'configuration_digest',encode(i.configuration_digest,'hex'),'module_installation_id',i.module_installation_id::text,'module_configuration_generation_id',i.module_configuration_generation_id::text,'runtime_configuration_generation_id',w.runtime_configuration_generation_id::text,'capsule_digest',substring(o.capsule_digest from 8),'xds_version_digest',substring(w.xds_version_digest from 8),'predecessor_capsule_digest',substring(w.predecessor_digest from 8),'original_work_id',w.configuration_work_id::text,'original_operation_id',w.operation_id::text,'original_execution_attempt_id',w.execution_attempt_id::text) from control.configuration_work w join control.runtime_activation_observation o using(configuration_work_id,participant_id,privacy_domain_id,runtime_target_id,execution_attempt_id) join control.runtime_configuration_input i on i.participant_id=w.participant_id and i.privacy_domain_id=w.privacy_domain_id and i.configuration_digest=decode(substring(w.configuration_digest from 8),'hex') where w.configuration_work_id=$1::text::uuid")
        .bind(intent["custody"]["workId"].as_str().unwrap()).fetch_one(&mut **tx).await?;
    let target: Value=sqlx::query_scalar("select binding->'target' from control.runtime_target_disposition_admission where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid order by revision desc limit 1")
        .bind(intent["custody"]["runtimeTargetId"].as_str().unwrap()).fetch_one(&mut **tx).await?;
    let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
        .fetch_one(&mut **tx)
        .await?;
    let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .unwrap()
        .verifier()
        .verify_receipt(&original.activation_receipt)
        .unwrap();
    let bytes = canonical_bytes(intent).unwrap();
    let proof = serde_json::json!({"version":1,"transactionId":transaction,"intent":intent,"intentBytesHex":hex_bytes(&bytes),"intentDigest":format!("sha256:{}",Digest::of(&bytes).as_str()),"source":source,"target":target,"capsuleGeneration":original.capsule.generation,"capsuleNotBeforeNs":original.capsule.not_before_ns.to_string(),"capsuleExpiresAtNs":original.capsule.hard_expiry_ns.to_string(),"observedAtNs":receipt.observed_at_ns.to_string(),"receiptWireDigest":Digest::of(&original.activation_receipt),"tokenDigest":Digest::of(&original.activation_token)});
    let wire = canonical_bytes(&proof).unwrap();
    let nonce = [41u8; 32];
    let key = read_key(&required("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE").unwrap()).unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(b"OPENPC_EXPIRED_ACTIVATION_DENIAL_V1");
    mac.update(&Sha256::digest(&wire));
    mac.update(&nonce);
    sqlx::query_scalar("select binding from openpc.begin_expired_activation_denial($1,$2,$3)")
        .bind(wire)
        .bind(nonce.as_slice())
        .bind(mac.finalize().into_bytes().as_slice())
        .fetch_one(&mut **tx)
        .await
}

#[tokio::test]
#[ignore = "requires exact expired demo effect, original journal and authenticated installed worker login"]
async fn postgres_expired_observed_denial_is_new_only_scoped_and_rollback_safe() {
    let config = Config::read().unwrap();
    let pool = config.connect().await.unwrap();
    let path = required("OPENPC_EXPIRED_DENIAL_TEST_INTENT_FILE").unwrap();
    let mut intent: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let target = intent["custody"]["runtimeTargetId"]
        .as_str()
        .unwrap()
        .to_owned();
    let work = intent["custody"]["workId"].as_str().unwrap().to_owned();
    let journal = required("OPENPC_EXPIRED_DENIAL_TEST_JOURNAL_ROOT").unwrap();
    let original =
        retained_target::read_installed_from(&config, &target, Path::new(&journal)).unwrap();
    assert!(original.capsule.hard_expiry_ns < now_ms().unwrap() * 1_000_000);
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &config).await.unwrap();
    let actual: String = sqlx::query_scalar("select current_user::text")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(actual, intent["custody"]["databaseRole"].as_str().unwrap());
    let restricted:bool=sqlx::query_scalar("select current_user=session_user and current_setting('role')='none' and pg_has_role(current_user,'openpc_control_worker','USAGE') and not pg_has_role(current_user,'openpc_control_owner','USAGE') and not exists(select 1 from pg_roles where rolname=current_user and(rolsuper or rolbypassrls))").fetch_one(&mut *tx).await.unwrap();
    assert!(restricted);
    let before: String =
        sqlx::query_scalar("select openpc.expired_activation_state_digest($1::text::uuid)")
            .bind(&work)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    intent["custody"]["originalStateDigest"] = Value::String(before.clone());
    let now = now_ms().unwrap();
    intent["issuedAtMs"] = now.into();
    intent["expiresAtMs"] = (now + 120_000).into();
    intent["requestId"] = uuid::Uuid::now_v7().to_string().into();
    for key in [
        "workId",
        "executionAttemptId",
        "participantId",
        "generationDigest",
        "receiptDigest",
        "originalStateDigest",
    ] {
        sqlx::query("savepoint negative")
            .execute(&mut *tx)
            .await
            .unwrap();
        let mut wrong = intent.clone();
        wrong["custody"][key] = Value::String(if key.ends_with("Id") {
            uuid::Uuid::now_v7().to_string()
        } else {
            format!("sha256:{}", "00".repeat(32))
        });
        let error = attempt(&mut tx, &config, &wrong, &original)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, sqlx::Error::RowNotFound)
                || matches!(&error,
            sqlx::Error::Database(db) if db.code().as_deref()==Some("P0001")
                && (db.message().starts_with("EXPIRED-ACTIVATION-") || db.message().starts_with("TARGET-DISPOSITION-") || db.message()=="PC-AUTH-0005")),
            "unexpected failure for changed {key}: {error}"
        );
        sqlx::query("rollback to savepoint negative")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("savepoint positive")
        .execute(&mut *tx)
        .await
        .unwrap();
    let binding = attempt(&mut tx, &config, &intent, &original).await.unwrap();
    assert_eq!(binding["action"], "Withdraw");
    assert_eq!(
        binding["cause"]["execution_attempt_id"],
        intent["custody"]["executionAttemptId"]
    );
    let revision = binding["revision"].as_i64().unwrap();
    let digest = format!(
        "sha256:{}",
        Digest::of(canonical_bytes(&binding).unwrap()).as_str()
    );
    let valid: bool = sqlx::query_scalar(
        "select openpc.expired_denial_issuance_matches($1::text::uuid,$2,$3,$4)",
    )
    .bind(&target)
    .bind(revision)
    .bind(&digest)
    .bind(&config.worker_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(valid);
    // Exercise the owning caller too: its stored revision is numeric, while
    // the admitted wanted_revision and helper parameter are bounded bigint.
    sqlx::query("select openpc.lock_runtime_target_disposition_issuance($1::text::uuid,$2,$3,$4)")
        .bind(&target)
        .bind(revision)
        .bind(&digest)
        .bind(&config.worker_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("savepoint duplicate")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(attempt(&mut tx, &config, &intent, &original).await.is_err());
    sqlx::query("rollback to savepoint duplicate")
        .execute(&mut *tx)
        .await
        .unwrap();
    let unsigned:bool=sqlx::query_scalar("select not exists(select 1 from control.runtime_target_disposition_delivery where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid and revision=$2) and not exists(select 1 from control.runtime_denied_predecessor where configuration_work_id=$3::text::uuid)").bind(&target).bind(revision).bind(&work).fetch_one(&mut *tx).await.unwrap();
    assert!(unsigned);
    sqlx::query("rollback to savepoint positive")
        .execute(&mut *tx)
        .await
        .unwrap();
    let now = now_ms().unwrap();
    intent["issuedAtMs"] = now.into();
    intent["expiresAtMs"] = (now + 2000).into();
    let binding = attempt(&mut tx, &config, &intent, &original).await.unwrap();
    let digest = format!(
        "sha256:{}",
        Digest::of(canonical_bytes(&binding).unwrap()).as_str()
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let valid: bool = sqlx::query_scalar(
        "select openpc.expired_denial_issuance_matches($1::text::uuid,$2,$3,$4)",
    )
    .bind(&target)
    .bind(revision)
    .bind(&digest)
    .bind(&config.worker_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!valid, "operator expiry at signing must deny");
    tx.rollback().await.unwrap();
    let mut read = pool.begin().await.unwrap();
    set_context(&mut read, &config).await.unwrap();
    let after: String =
        sqlx::query_scalar("select openpc.expired_activation_state_digest($1::text::uuid)")
            .bind(&work)
            .fetch_one(&mut *read)
            .await
            .unwrap();
    assert_eq!(before, after);
    let no_fact:bool=sqlx::query_scalar("select not exists(select 1 from control.runtime_expired_activation_denial where configuration_work_id=$1::text::uuid)").bind(&work).fetch_one(&mut *read).await.unwrap();
    assert!(no_fact);
    read.rollback().await.unwrap();
}
