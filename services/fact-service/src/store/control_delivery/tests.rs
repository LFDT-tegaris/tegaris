use super::*;
use serde_json::{Value, json};

/// SQL capability/atomicity regression only. The synthetic consumer material
/// is always rolled back; real consumer readback is exercised by the runtime.
pub(in crate::store) async fn verify_ack_owner(
    store: &FactStore,
    participant: &str,
    privacy: &str,
    candidate: &str,
) {
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let row = sqlx::query("select envelope,generation_id,fact_type,sequence,convert_from(source_material,'UTF8')::jsonb->>'signedFactDigest' source_digest from facts.admission_delivery_event where candidate_id=$1")
        .bind(candidate).fetch_one(&mut *tx).await.unwrap();
    let event: Value = row.get("envelope");
    let original = json!({
        "participantId":participant,"privacyDomainId":privacy,"candidateId":candidate,
        "generationId":row.get::<String,_>("generation_id"),"factType":row.get::<String,_>("fact_type"),
        "sequence":row.get::<i64,_>("sequence").to_string(),"eventId":event["id"],
        "consumerId":"LS-CONTROL-WORK","streamId":"component-only","recordId":"component-only",
        "sourceReceiptDigest":row.get::<String,_>("source_digest"),"envelope":event,
    });
    tx.rollback().await.unwrap();
    for case in [
        "mac",
        "domain",
        "scope",
        "generation",
        "sequence",
        "event",
        "digest",
        "consumer",
        "null",
        "extra",
        "envelope",
    ] {
        let mut material = original.clone();
        match case {
            "generation" => material["generationId"] = Uuid::now_v7().to_string().into(),
            "sequence" => material["sequence"] = "999999".into(),
            "event" => material["eventId"] = Uuid::now_v7().to_string().into(),
            "digest" => {
                material["sourceReceiptDigest"] = format!("sha256:{}", "00".repeat(32)).into()
            }
            "consumer" => material["consumerId"] = "LS-FLEET-CONTROL".into(),
            "null" => material["candidateId"] = Value::Null,
            "extra" => material["delivered"] = true.into(),
            "envelope" => {
                material["envelope"]["authoritygeneration"] =
                    format!("sha256:{}", "11".repeat(32)).into()
            }
            _ => (),
        }
        let bytes = serde_json::to_vec(&material).unwrap();
        let mut capability = store.capabilities.control_delivery_ack(&bytes);
        if case == "mac" {
            capability.mac[0] ^= 1;
        }
        if case == "domain" {
            capability = store.capabilities.admission_delivery(&bytes, b"{}");
        }
        let mut tx = store.pool.begin().await.unwrap();
        set_context(
            &mut tx,
            participant,
            if case == "scope" {
                "foreign-privacy"
            } else {
                privacy
            },
        )
        .await
        .unwrap();
        let error =
            sqlx::query_scalar::<_, bool>("select facts.acknowledge_control_custody($1,$2,$3)")
                .bind(bytes)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await
                .expect_err(case);
        assert!(
            matches!(
                error
                    .as_database_error()
                    .and_then(|e| e.code())
                    .unwrap()
                    .as_ref(),
                "23514" | "42501"
            ),
            "{case}: {error}"
        );
        tx.rollback().await.unwrap();
    }
    let bytes = serde_json::to_vec(&original).unwrap();
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    for expected in [true, false] {
        let capability = store.capabilities.control_delivery_ack(&bytes);
        let inserted: bool =
            sqlx::query_scalar("select facts.acknowledge_control_custody($1,$2,$3)")
                .bind(&bytes)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(inserted, expected);
    }
    let outbox: String =
        sqlx::query_scalar("select delivery_state from facts.outbox where candidate_id=$1")
            .bind(candidate)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(outbox, "PENDING");
    set_context(&mut tx, participant, "foreign-privacy")
        .await
        .unwrap();
    let hidden: i64 = sqlx::query_scalar(
        "select count(*) from facts.control_admission_custody_ack where candidate_id=$1",
    )
    .bind(candidate)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(hidden, 0);
    set_context(&mut tx, participant, privacy).await.unwrap();
    // A changed custody identity cannot replace the first immutable receipt.
    let mut changed = original.clone();
    changed["streamId"] = "different-stream".into();
    let changed = serde_json::to_vec(&changed).unwrap();
    let capability = store.capabilities.control_delivery_ack(&changed);
    let error = sqlx::query("select facts.acknowledge_control_custody($1,$2,$3)")
        .bind(changed)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(error.as_database_error().unwrap().code().unwrap(), "23514");
    tx.rollback().await.unwrap();
    // Exact request-nonce replay is rejected even when the material is equal;
    // lost-response reconciliation uses a fresh native capability.
    let capability = store.capabilities.control_delivery_ack(&bytes);
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    sqlx::query("select facts.acknowledge_control_custody($1,$2,$3)")
        .bind(&bytes)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
    let replay = sqlx::query("select facts.acknowledge_control_custody($1,$2,$3)")
        .bind(&bytes)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(replay.as_database_error().unwrap().code().unwrap(), "23505");
    tx.rollback().await.unwrap();
    for statement in [
        "update facts.control_admission_custody_ack set material='x' where candidate_id=$1",
        "delete from facts.control_admission_custody_ack where candidate_id=$1",
        "insert into facts.control_admission_custody_ack(candidate_id) values($1)",
    ] {
        let mut tx = store.pool.begin().await.unwrap();
        set_context(&mut tx, participant, privacy).await.unwrap();
        let error = sqlx::query(statement)
            .bind(candidate)
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().unwrap(), "42501");
        tx.rollback().await.unwrap();
    }
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "select count(*) from facts.control_admission_custody_ack where candidate_id=$1",
    )
    .bind(candidate)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count, 0, "rollback must retain original pending identity");
    tx.rollback().await.unwrap();

    // Two real transactions contend on the producer scope fence. If the first
    // response is lost with rollback, the waiting retry owns the sole effect.
    let mut first = store.pool.begin().await.unwrap();
    set_context(&mut first, participant, privacy).await.unwrap();
    let cap = store.capabilities.control_delivery_ack(&bytes);
    sqlx::query("select facts.acknowledge_control_custody($1,$2,$3)")
        .bind(&bytes)
        .bind(cap.nonce.as_slice())
        .bind(cap.mac.as_slice())
        .execute(&mut *first)
        .await
        .unwrap();
    let second = async {
        let mut tx = store.pool.begin().await.unwrap();
        set_context(&mut tx, participant, privacy).await.unwrap();
        let cap = store.capabilities.control_delivery_ack(&bytes);
        let inserted: bool =
            sqlx::query_scalar("select facts.acknowledge_control_custody($1,$2,$3)")
                .bind(&bytes)
                .bind(cap.nonce.as_slice())
                .bind(cap.mac.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(inserted);
        tx.rollback().await.unwrap();
    };
    tokio::pin!(second);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut second)
            .await
            .is_err()
    );
    first.rollback().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .unwrap();
}
