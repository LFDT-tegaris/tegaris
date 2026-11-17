use super::*;

/// Exercise the installed owner with an already committed canonical admission.
/// No consumer receipt is seeded and the original outbox must remain pending.
pub(in crate::store) async fn verify_original_delivery(
    store: &FactStore,
    participant: &str,
    privacy: &str,
    candidate: &str,
    verifier: &FactSignatureVerifier,
) {
    super::super::control_delivery::tests::verify_ack_owner(store, participant, privacy, candidate)
        .await;
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let row = sqlx::query("select source_material,data_bytes,envelope from facts.admission_delivery_event where candidate_id=$1")
        .bind(candidate).fetch_one(&mut *tx).await.unwrap();
    let material: Vec<u8> = row.get("source_material");
    let data: Vec<u8> = row.get("data_bytes");
    let original: Value = row.get("envelope");
    tx.rollback().await.unwrap();
    let reader_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let reader = super::super::PolicyFactReader::new(reader_pool.clone(), verifier.clone());
    let source: Value = serde_json::from_slice(&material).unwrap();
    let kind = source["factType"].as_str().unwrap();
    let sequence: i64 = original["sequence"].as_str().unwrap().parse().unwrap();
    let delivered = reader
        .admission_deliveries(participant, privacy, kind, sequence - 1)
        .await
        .unwrap();
    let first = delivered.first().unwrap();
    assert_eq!(first.participant_id(), participant);
    assert_eq!(first.privacy_domain_id(), privacy);
    assert_eq!(first.candidate_id(), candidate);
    assert_eq!(first.fact_type(), kind);
    assert_eq!(first.sequence(), sequence);
    assert_eq!(first.envelope(), &original);
    assert_eq!(
        first.generation_id(),
        source["generationId"].as_str().unwrap()
    );
    assert_eq!(
        crate::signing::shard::digest_text(&pc_facts_core::sha256(first.original_cose())),
        source["signedFactDigest"].as_str().unwrap()
    );
    assert!(
        reader
            .admission_deliveries(participant, &Uuid::now_v7().to_string(), kind, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        reader
            .admission_deliveries(participant, privacy, "unknown", 0)
            .await
            .is_err()
    );
    assert!(
        reader
            .admission_deliveries(participant, privacy, kind, -1)
            .await
            .is_err()
    );
    let replay = reader
        .admission_deliveries(participant, privacy, kind, sequence - 1)
        .await
        .unwrap();
    assert_eq!(replay[0].original_cose(), first.original_cose());
    assert_eq!(replay[0].envelope(), first.envelope());
    let wrong_signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![91; 32]).unwrap();
    let pending = reader
        .pending_admission_deliveries(participant, privacy, kind, sequence - 1)
        .await
        .unwrap();
    let observed = pending.first().unwrap();
    assert_eq!(observed.participant_id(), participant);
    assert_eq!(observed.privacy_domain_id(), privacy);
    assert_eq!(observed.candidate_id(), candidate);
    assert_eq!(observed.generation_id(), first.generation_id());
    assert_eq!(observed.fact_type(), kind);
    assert_eq!(observed.sequence(), sequence);
    assert_eq!(
        observed.event_id().to_string(),
        original["id"].as_str().unwrap()
    );
    assert_eq!(observed.envelope(), &original);
    assert_eq!(
        observed.envelope_digest(),
        &pc_facts_core::sha256(&serde_json::to_vec(&original).unwrap())
    );
    assert_eq!(observed.data_digest(), &pc_facts_core::sha256(&data));
    assert_eq!(
        reader
            .verify_admission_delivery(observed)
            .await
            .unwrap()
            .original_cose(),
        first.original_cose()
    );
    let wrong_reader =
        super::super::PolicyFactReader::new(reader_pool.clone(), wrong_signer.verifier());
    assert!(
        wrong_reader
            .verify_admission_delivery(observed)
            .await
            .is_err()
    );
    // Failed verification preserves the exact original transport identity for
    // durable retry/quarantine. It never manufactures a verified Fact or ACK.
    assert_eq!(observed.envelope(), &original);
    let retained = wrong_reader
        .pending_admission_deliveries(participant, privacy, kind, sequence - 1)
        .await
        .unwrap();
    assert_eq!(retained[0].envelope_digest(), observed.envelope_digest());
    assert_eq!(retained[0].data_digest(), observed.data_digest());
    assert_eq!(retained[0].event_id(), observed.event_id());
    assert_eq!(
        reader
            .verify_admission_delivery(&retained[0])
            .await
            .unwrap()
            .original_cose(),
        first.original_cose()
    );
    assert!(
        super::super::PolicyFactReader::new(reader_pool.clone(), wrong_signer.verifier())
            .admission_deliveries(participant, privacy, kind, sequence - 1)
            .await
            .is_err()
    );
    let fleet_material = json!({
        "participantId":participant,"privacyDomainId":privacy,"candidateId":candidate,
        "generationId":first.generation_id(),"factType":kind,"sequence":sequence.to_string(),
        "envelope":original,"signedFactDigest":source["signedFactDigest"],
        "factDigest":crate::signing::shard::digest_text(first.fact_digest()),
        "consumerId":"LS-FLEET-CONTROL",
    });
    // Owner capability checks only; these synthetic ACKs are rolled back.
    // A real ACK is accepted separately from Fleet's actual native commit.
    for case in [
        "valid",
        "mac",
        "domain",
        "scope",
        "generation",
        "digest",
        "consumer",
        "extra",
    ] {
        let mut value = fleet_material.clone();
        match case {
            "generation" => value["generationId"] = Uuid::now_v7().to_string().into(),
            "digest" => value["factDigest"] = format!("sha256:{}", "00".repeat(32)).into(),
            "consumer" => value["consumerId"] = "LS-CONTROL-WORK".into(),
            "extra" => value["ready"] = true.into(),
            _ => (),
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut capability = if case == "domain" {
            store.capabilities.control_delivery_ack(&bytes)
        } else {
            store.capabilities.fleet_delivery_ack(&bytes)
        };
        if case == "mac" {
            capability.mac[0] ^= 1;
        }
        let mut tx = store.pool.begin().await.unwrap();
        set_context(
            &mut tx,
            participant,
            if case == "scope" { "foreign" } else { privacy },
        )
        .await
        .unwrap();
        let result =
            sqlx::query_scalar::<_, bool>("select facts.acknowledge_fleet_admission($1,$2,$3)")
                .bind(bytes)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await;
        if case == "valid" {
            assert!(result.unwrap());
        } else {
            assert!(result.is_err(), "{case}");
        }
        tx.rollback().await.unwrap();
    }
    reader_pool.close().await;
    for case in [
        "mac",
        "domain",
        "scope",
        "generation",
        "digest",
        "null",
        "extra",
        "data",
    ] {
        let mut m: Value = serde_json::from_slice(&material).unwrap();
        let mut d = data.clone();
        match case {
            "generation" => m["generationId"] = Uuid::now_v7().to_string().into(),
            "digest" => m["signedFactDigest"] = format!("sha256:{}", "00".repeat(32)).into(),
            "null" => m["factType"] = Value::Null,
            "extra" => m["delivered"] = true.into(),
            "data" => d = b"{}".to_vec(),
            _ => (),
        }
        let changed = if matches!(case, "generation" | "digest" | "null" | "extra") {
            serde_json::to_vec(&m).unwrap()
        } else {
            material.clone()
        };
        let mut capability = store.capabilities.admission_delivery(&changed, &d);
        if case == "mac" {
            capability.mac[0] ^= 1;
        }
        if case == "domain" {
            capability = store.capabilities.fact_occurrence(&[7; 32]);
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
        let result = sqlx::query_scalar::<_, Value>(
            "select facts.materialize_admission_delivery($1,$2,$3,$4)",
        )
        .bind(changed)
        .bind(d)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut *tx)
        .await;
        let error = result.expect_err(case);
        let code = error.as_database_error().and_then(|e| e.code()).unwrap();
        assert!(
            matches!(code.as_ref(), "42501" | "23514"),
            "{case}: {error}"
        );
        tx.rollback().await.unwrap();
    }
    // The runtime cannot turn custody into a delivery acknowledgement or edit
    // its ordering cursor/envelope through direct SQL privileges.
    for statement in [
        "update facts.admission_delivery_event set envelope='{}' where candidate_id=$1",
        "update facts.outbox set delivery_state='DELIVERED' where candidate_id=$1",
        "delete from facts.admission_delivery_event where candidate_id=$1",
        "update facts.admission_delivery_head set sequence=sequence+1 where participant_id=$1",
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
    set_context(&mut tx, participant, "foreign-privacy")
        .await
        .unwrap();
    let invisible: i64 = sqlx::query_scalar(
        "select count(*) from facts.admission_delivery_event where candidate_id=$1",
    )
    .bind(candidate)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(invisible, 0);
    tx.rollback().await.unwrap();

    // A reopened pool represents loss of the original producer response. It
    // verifies the signed original again and returns the original identity.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let reopened = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().unwrap(),
    );
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let replay = reopened
        .record_admission_delivery(&mut tx, participant, privacy, candidate, verifier)
        .await
        .unwrap();
    assert_eq!(replay, original);
    assert_eq!(
        read_verified(&mut tx, participant, privacy, candidate, verifier)
            .await
            .unwrap(),
        Some(original.clone())
    );
    let wrong = PurposeBoundFactSigner::generate_ephemeral_local(vec![98; 32]).unwrap();
    assert!(
        read_verified(&mut tx, participant, privacy, candidate, &wrong.verifier())
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    pool.close().await;
    // The installed policy-reader role, not just the producer writer, can
    // verify the exact original envelope without mutation privileges.
    let reader_pool =
        PgPool::connect(&std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap())
            .await
            .unwrap();
    let mut read = reader_pool.begin().await.unwrap();
    sqlx::query("set transaction read only")
        .execute(&mut *read)
        .await
        .unwrap();
    set_context(&mut read, participant, privacy).await.unwrap();
    assert_eq!(
        read_verified(&mut read, participant, privacy, candidate, verifier)
            .await
            .unwrap(),
        Some(original.clone())
    );
    read.rollback().await.unwrap();
    let mut foreign = reader_pool.begin().await.unwrap();
    set_context(&mut foreign, participant, "foreign-privacy")
        .await
        .unwrap();
    let invisible: i64 =
        sqlx::query_scalar("select count(candidate_id) from facts.retained_fact_identity")
            .fetch_one(&mut *foreign)
            .await
            .unwrap();
    assert_eq!(invisible, 0);
    foreign.rollback().await.unwrap();
    for statement in [
        "select signed_fact_digest from facts.retained_fact_identity",
        "update facts.retained_fact_identity set admitted_at=admitted_at",
    ] {
        let mut denied = reader_pool.begin().await.unwrap();
        set_context(&mut denied, participant, privacy)
            .await
            .unwrap();
        let error = sqlx::query(statement)
            .execute(&mut *denied)
            .await
            .unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().unwrap(), "42501");
        denied.rollback().await.unwrap();
    }
    reader_pool.close().await;
    let mut tx = store.pool.begin().await.unwrap();
    set_context(&mut tx, participant, privacy).await.unwrap();
    let row = sqlx::query("select e.envelope,o.delivery_state from facts.admission_delivery_event e join facts.outbox o using(candidate_id,participant_id,privacy_domain_id) where candidate_id=$1")
        .bind(candidate).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(row.get::<Value, _>("envelope"), original);
    assert_eq!(row.get::<String, _>("delivery_state"), "PENDING");
    tx.rollback().await.unwrap();
}
