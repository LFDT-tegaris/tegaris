use super::*;
use serde_json::{Value, json};

/// Capability and SQL atomicity segment only: synthetic ACKs always roll back.
/// Packaged runtime acceptance supplies the actual independent consumer effects.
pub(in crate::store) async fn verify_completion_owner(
    store: &FactStore,
    participant: &str,
    privacy: &str,
    generation: &str,
    verifier: &FactSignatureVerifier,
    directory: &Path,
) {
    assert_eq!(
        store
            .reconcile_producer_deliveries(participant, privacy, verifier, directory)
            .await
            .unwrap(),
        0
    );
    assert!(
        store
            .complete_producer_delivery(participant, privacy, generation, verifier, directory)
            .await
            .is_err(),
        "publication alone cannot complete delivery"
    );
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let publication = sqlx::query("select content_digest,manifest_digest from facts.shard_publication where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3")
        .bind(participant).bind(privacy).bind(generation).fetch_one(&mut *tx).await.unwrap();
    let events = sqlx::query("select e.*,f.fact_digest from facts.admission_delivery_event e
        join facts.canonical_fact f using(candidate_id,participant_id,privacy_domain_id,generation_id)
        where e.participant_id=$1 and e.privacy_domain_id=$2 and e.generation_id=$3 order by e.sequence")
        .bind(participant).bind(privacy).bind(generation).fetch_all(&mut *tx).await.unwrap();
    let original = json!({"participantId":participant,"privacyDomainId":privacy,"generationId":generation,
        "contentDigest":digest_text(&publication.get::<Vec<u8>,_>("content_digest")),
        "manifestDigest":digest_text(&publication.get::<Vec<u8>,_>("manifest_digest"))});
    tx.rollback().await.unwrap();
    for case in [
        "valid",
        "mac",
        "domain",
        "scope",
        "content",
        "manifest",
        "extra",
        "null",
        "missing-control",
        "missing-fleet",
        "missing-sibling",
    ] {
        let mut tx = store.pool.begin().await.unwrap();
        set_context(&mut tx, participant, privacy).await.unwrap();
        for (index, event) in events.iter().enumerate() {
            if case == "missing-sibling" && index > 0 {
                continue;
            }
            let source: Value =
                serde_json::from_slice(&event.get::<Vec<u8>, _>("source_material")).unwrap();
            let envelope: Value = event.get("envelope");
            let common = json!({"participantId":participant,"privacyDomainId":privacy,
                "candidateId":event.get::<String,_>("candidate_id"),"generationId":generation,
                "factType":event.get::<String,_>("fact_type"),"sequence":event.get::<i64,_>("sequence").to_string(),
                "envelope":envelope});
            if case != "missing-control" {
                let mut material = common.clone();
                material["eventId"] = envelope["id"].clone();
                material["consumerId"] = "LS-CONTROL-WORK".into();
                material["streamId"] = "component-only".into();
                material["recordId"] = "component-only".into();
                material["sourceReceiptDigest"] = source["signedFactDigest"].clone();
                let bytes = serde_json::to_vec(&material).unwrap();
                let cap = store.capabilities.control_delivery_ack(&bytes);
                sqlx::query("select facts.acknowledge_control_custody($1,$2,$3)")
                    .bind(bytes)
                    .bind(cap.nonce.as_slice())
                    .bind(cap.mac.as_slice())
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            if case != "missing-fleet" {
                let mut material = common;
                material["consumerId"] = "LS-FLEET-CONTROL".into();
                material["signedFactDigest"] = source["signedFactDigest"].clone();
                material["factDigest"] =
                    digest_text(&event.get::<Vec<u8>, _>("fact_digest")).into();
                let bytes = serde_json::to_vec(&material).unwrap();
                let cap = store.capabilities.fleet_delivery_ack(&bytes);
                sqlx::query("select facts.acknowledge_fleet_admission($1,$2,$3)")
                    .bind(bytes)
                    .bind(cap.nonce.as_slice())
                    .bind(cap.mac.as_slice())
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
        }
        let mut m = original.clone();
        match case {
            "content" => m["contentDigest"] = format!("sha256:{}", "00".repeat(32)).into(),
            "manifest" => m["manifestDigest"] = format!("sha256:{}", "00".repeat(32)).into(),
            "extra" => m["ready"] = true.into(),
            "null" => m["generationId"] = Value::Null,
            "scope" => set_context(&mut tx, participant, "foreign").await.unwrap(),
            _ => (),
        }
        let bytes = serde_json::to_vec(&m).unwrap();
        let mut cap = if case == "domain" {
            store.capabilities.fleet_delivery_ack(&bytes)
        } else {
            store.capabilities.producer_delivery(&bytes)
        };
        if case == "mac" {
            cap.mac[0] ^= 1;
        }
        let result =
            sqlx::query_scalar::<_, bool>("select facts.complete_producer_delivery($1,$2,$3)")
                .bind(&bytes)
                .bind(cap.nonce.as_slice())
                .bind(cap.mac.as_slice())
                .fetch_one(&mut *tx)
                .await;
        if case == "valid" {
            assert!(result.unwrap());
            let states: Vec<String> = sqlx::query_scalar("select o.delivery_state from facts.outbox o join facts.canonical_fact f using(candidate_id,participant_id,privacy_domain_id) where f.generation_id=$1")
                .bind(generation).fetch_all(&mut *tx).await.unwrap();
            assert_eq!(states, vec!["DELIVERED"; events.len()]);
            let state: String = sqlx::query_scalar(
                "select state::text from facts.readiness_gate where generation_id=$1",
            )
            .bind(generation)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(state, "READY", "delivery cannot change readiness");
            let replay = store.capabilities.producer_delivery(&bytes);
            assert!(
                !sqlx::query_scalar::<_, bool>("select facts.complete_producer_delivery($1,$2,$3)")
                    .bind(&bytes)
                    .bind(replay.nonce.as_slice())
                    .bind(replay.mac.as_slice())
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap()
            );
            assert!(
                sqlx::query("select facts.complete_producer_delivery($1,$2,$3)")
                    .bind(&bytes)
                    .bind(cap.nonce.as_slice())
                    .bind(cap.mac.as_slice())
                    .execute(&mut *tx)
                    .await
                    .is_err()
            );
        } else {
            assert!(result.is_err(), "{case}");
        }
        tx.rollback().await.unwrap();
    }
    for statement in [
        "update facts.outbox set delivery_state='DELIVERED'",
        "update facts.shard_publication set delivery_state='DELIVERED'",
    ] {
        let mut tx = store.pool.begin().await.unwrap();
        set_context(&mut tx, participant, privacy).await.unwrap();
        let error = sqlx::query(statement).execute(&mut *tx).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().unwrap(), "42501");
        tx.rollback().await.unwrap();
    }
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let pending: bool = sqlx::query_scalar(
        "select delivery_state='PENDING' from facts.shard_publication where generation_id=$1",
    )
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(pending, "all synthetic effects must roll back");
    tx.rollback().await.unwrap();
    let blob = directory
        .join("blobs/sha256")
        .join(&original["manifestDigest"].as_str().unwrap()[7..]);
    let hidden = blob.with_extension("withheld");
    std::fs::rename(&blob, &hidden).unwrap();
    assert!(matches!(
        store
            .complete_producer_delivery(participant, privacy, generation, verifier, directory)
            .await,
        Err(FactStoreError::Publication(_))
    ));
    assert!(
        !blob.exists(),
        "recovery never republishes a missing original"
    );
    std::fs::rename(hidden, blob).unwrap();
}
