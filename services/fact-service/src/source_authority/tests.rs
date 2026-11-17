use super::*;
use crate::candidate_feed::CandidateFeedReader;
use uuid::Uuid;

#[derive(serde::Deserialize)]
struct Input {
    candidate_database_url_file: String,
    control_database_url_file: String,
    control_admin_url_file: String,
    participant: Uuid,
    privacy: Uuid,
    operation: Uuid,
    partition: Uuid,
}

async fn context(
    tx: &mut Transaction<'_, Postgres>,
    participant: Uuid,
    privacy: Uuid,
    operation: Uuid,
) {
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',false)")
        .bind(participant).bind(privacy).bind(operation).execute(&mut **tx).await.unwrap();
}
fn secret(path: &str) -> String {
    std::fs::read_to_string(path).unwrap().trim().to_owned()
}

#[tokio::test]
#[ignore = "requires publicly qualified source, published candidate, installed roles and Control fence migration"]
async fn installed_source_fence_preserves_scope_locks_and_real_provider_expiry() {
    let file = std::env::var("OPENPC_FACT_SOURCE_TEST_INPUT_FILE").unwrap();
    let input: Input = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    let reader = CandidateFeedReader::connect(&secret(&input.candidate_database_url_file))
        .await
        .unwrap();
    let scope =
        || CandidateReadScope::new(input.participant, input.privacy, input.operation).unwrap();
    let mut feed = reader
        .read_partition(scope(), input.partition)
        .await
        .unwrap();
    let material = feed.candidate(1).await.unwrap();
    let source = FactSourceAuthority::connect(&secret(&input.control_database_url_file))
        .await
        .unwrap();
    let admin = PgPool::connect(&secret(&input.control_admin_url_file))
        .await
        .unwrap();
    assert!(matches!(
        FactSourceAuthority::connect(&secret(&input.control_admin_url_file)).await,
        Err(SourceAuthorityError::Identity)
    ));
    let plan = material.source.inputs.source().projection_plan_id;
    let source_id = material.source.inputs.source().indexer_profile_id;
    let mut fence = source.pool.begin().await.unwrap();
    context(
        &mut fence,
        input.participant,
        input.privacy,
        input.operation,
    )
    .await;
    sqlx::query("select openpc.lock_fact_candidate_source($1)")
        .bind(plan)
        .execute(&mut *fence)
        .await
        .unwrap();
    let rows = control_source::load(
        &mut fence,
        &input.participant.to_string(),
        &input.privacy.to_string(),
        Some(&plan.to_string()),
        false,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String, _>("indexer_profile_id"),
        source_id.to_string()
    );
    let configuration = decode_active_invocation_configuration(
        &rows[0].get::<Vec<u8>, _>("configuration_cbor"),
        &digest(rows[0].get("active_configuration_digest")).unwrap(),
    )
    .unwrap();
    eprintln!(
        "selected source configuration methods and durable-binding presence: {:?}",
        configuration
            .assets
            .iter()
            .take(16)
            .map(|asset| (
                &asset.canonical_signature,
                asset.runtime_binding_id.is_some()
            ))
            .collect::<Vec<_>>()
    );
    let binding:Option<Uuid>=sqlx::query_scalar("select runtime_binding_id from control.contract_runtime_binding where state='BOUND' and quarantined_at is null order by runtime_binding_id limit 1")
        .fetch_optional(&mut *fence).await.unwrap();
    let binding = binding
        .expect("contract-fence acceptance requires an existing registered contract binding");
    let contract = sqlx::query("select * from openpc.lock_fact_contract_binding($1)")
        .bind(binding)
        .fetch_one(&mut *fence)
        .await
        .unwrap();
    assert_eq!(
        Digest::of(contract.get::<Vec<u8>, _>("canonical_abi_bytes")),
        digest(contract.get("abi_digest")).unwrap()
    );
    // The read-only caller has actual source locks but no table mutation privilege.
    let writable: bool = sqlx::query_scalar(
        "select has_table_privilege(current_user,'control.indexer_profile','UPDATE')",
    )
    .fetch_one(&mut *fence)
    .await
    .unwrap();
    assert!(!writable);
    for (table, column, id) in [
        ("indexer_profile", "indexer_profile_id", source_id),
        ("projection_plan", "projection_plan_id", plan),
        ("contract_runtime_binding", "runtime_binding_id", binding),
        ("participant", "participant_id", input.participant),
    ] {
        let mut contender = admin.begin().await.unwrap();
        context(
            &mut contender,
            input.participant,
            input.privacy,
            input.operation,
        )
        .await;
        let mut query = sqlx::QueryBuilder::<Postgres>::new("select ");
        // All identifiers come from this closed test table, never caller text.
        query
            .push(column)
            .push(" from control.")
            .push(table)
            .push(" where ")
            .push(column)
            .push("=")
            .push_bind(id)
            .push(" for update nowait");
        let failure = query.build().fetch_all(&mut *contender).await.unwrap_err();
        assert_eq!(
            failure
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55P03")
        );
        contender.rollback().await.unwrap();
    }
    fence.rollback().await.unwrap();
    // Determine provider freshness from the actual Control observation, without
    // extending its lifetime or seeding a replacement qualification.
    let mut current = source.pool.begin().await.unwrap();
    context(
        &mut current,
        input.participant,
        input.privacy,
        input.operation,
    )
    .await;
    let mut qualified = 0;
    for expected in &material
        .source
        .inputs
        .finality_rule()
        .canonical_provider_digests
    {
        let available: bool=sqlx::query_scalar("select exists(select 1 from control.provider_profile p join control.provider_probe_observation o on o.observation_id=p.qualification_observation_id where p.behavior_fingerprint=$1 and o.valid_until>clock_timestamp())")
            .bind(expected).fetch_one(&mut *current).await.unwrap();
        qualified += usize::from(available);
    }
    current.rollback().await.unwrap();
    let result = source.acquire(&scope(), &material.source).await;
    if qualified < usize::from(material.source.inputs.finality_rule().required_observations) {
        assert!(matches!(result, Err(SourceAuthorityError::Binding)));
        eprintln!("actual expired provider qualification rejected; no fact admission attempted");
    } else {
        let mut lease = result.expect("current source authority");
        lease.confirm_live().await.unwrap();
        assert!(!lease.providers().is_empty());
        lease.close().await.unwrap();
    }
    let foreign = Uuid::parse_str("018f0000-0000-7000-8000-000000000999").unwrap();
    for (participant, privacy) in [(foreign, input.privacy), (input.participant, foreign)] {
        let denied = CandidateReadScope::new(participant, privacy, input.operation).unwrap();
        assert!(matches!(
            source.acquire(&denied, &material.source).await,
            Err(SourceAuthorityError::Binding)
        ));
        let mut tx = source.pool.begin().await.unwrap();
        context(&mut tx, participant, privacy, input.operation).await;
        assert!(
            sqlx::query("select openpc.lock_fact_candidate_source($1)")
                .bind(plan)
                .execute(&mut *tx)
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
    }
    feed.close().await.unwrap();
    reader.close().await;
    source.close().await;
    admin.close().await;
}
