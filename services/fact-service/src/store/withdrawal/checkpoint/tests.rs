use super::*;

#[tokio::test]
#[ignore = "requires migrated PostgreSQL; ordinary Fact delivery gate invokes it"]
async fn untrusted_checkpoint_inputs_and_roles_cannot_mutate() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("runtime database"))
        .await
        .unwrap();
    let store = FactStore::new(
        pool.clone(),
        crate::store::tests::external_capability_secret().expect("capability secret"),
    );
    let participant = Uuid::now_v7().to_string();
    let privacy = Uuid::now_v7().to_string();
    let original = serde_json::json!({
        "participantId":participant,"privacyDomainId":privacy,
        "sourceProfileId":Uuid::now_v7().to_string(),"partitionId":Uuid::now_v7().to_string(),
        "sourceGenerationId":Uuid::now_v7().to_string(),"sourceEventId":Uuid::now_v7().to_string(),
        "sourceSequence":"3","sourcePayloadDigest":digest_text(&[1;32]),
        "publicationDigest":digest_text(&[2;32]),"prefixDigest":digest_text(&[3;32]),
        "authorityDigest":digest_text(&[4;32]),
    });
    let restricted: bool = sqlx::query_scalar(
        "select exists(select 1 from pg_roles where rolname=current_user and not rolsuper and not rolbypassrls)
          and has_function_privilege(current_user,'facts.close_source_withdrawal(bytea,bytea,bytea)','EXECUTE')
          and not has_function_privilege(current_user,'facts.verify_withdrawal_checkpoint_capability(bytea,bytea,bytea)','EXECUTE')
          and not has_function_privilege('openpc_policy_fact_reader','facts.close_source_withdrawal(bytea,bytea,bytea)','EXECUTE')
          and not has_table_privilege(current_user,'facts.withdrawal_checkpoint','INSERT,UPDATE,DELETE,TRUNCATE')",
    ).fetch_one(&pool).await.unwrap();
    assert!(restricted);
    for case in [
        "mac",
        "domain",
        "scope",
        "extra",
        "null",
        "digest",
        "sequence",
        "absent-owner",
    ] {
        let mut material = original.clone();
        match case {
            "scope" => material["privacyDomainId"] = Uuid::now_v7().to_string().into(),
            "extra" => material["ready"] = true.into(),
            "null" => material["prefixDigest"] = serde_json::Value::Null,
            "digest" => material["publicationDigest"] = "unverified".into(),
            "sequence" => material["sourceSequence"] = "03".into(),
            _ => {}
        }
        let bytes = serde_json::to_vec(&material).unwrap();
        let mut cap = if case == "domain" {
            store.capabilities.lineage(&sha256(&bytes))
        } else {
            store.capabilities.withdrawal_checkpoint(&sha256(&bytes))
        };
        if case == "mac" {
            cap.mac[0] ^= 1;
        }
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &participant, &privacy).await.unwrap();
        let error = sqlx::query_scalar::<_, bool>("select facts.close_source_withdrawal($1,$2,$3)")
            .bind(bytes)
            .bind(cap.nonce.as_slice())
            .bind(cap.mac.as_slice())
            .fetch_one(&mut *tx)
            .await
            .expect_err(case);
        let expected = match case {
            "mac" | "domain" | "scope" => "42501",
            "absent-owner" => "P0002",
            _ => "23514",
        };
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some(expected),
            "{case}"
        );
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        set_context(&mut tx, &participant, &privacy).await.unwrap();
        let count: i64 = sqlx::query_scalar("select count(*) from facts.withdrawal_checkpoint")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0, "{case}");
        tx.rollback().await.unwrap();
    }
    pool.close().await;
}
