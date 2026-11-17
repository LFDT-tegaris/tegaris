use super::*;

#[tokio::test]
async fn prepared_pool_never_connects_and_terminal_close_never_reopens() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let reader = CandidateFeedReader::prepare(&format!(
        "postgresql://openpc_fact_bridge_reader:unusable@{address}/openpc_candidate_index"
    ))
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    reader.close().await;
    let scope = CandidateReadScope::new(Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()).unwrap();
    assert!(matches!(
        reader.read_partition(scope, Uuid::now_v7()).await,
        Err(CandidateFeedError::Database(sqlx::Error::PoolClosed))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

/// Called by the existing real Identity TLS/PostgreSQL interoperability
/// test, against an independently migrated empty candidate database.
pub(crate) async fn assert_installed_connection_lifecycle(
    authenticator: &crate::workload_authority::FactWorkloadAuthenticator,
    admin: &PgPool,
    participant: Uuid,
    privacy: Uuid,
) {
    use sqlx::Connection;
    let url = std::env::var("OPENPC_FACT_CANDIDATE_SESSION_TEST_URL").unwrap();
    let scope = || CandidateReadScope::new(participant, privacy, Uuid::now_v7()).unwrap();
    let count = || {
        sqlx::query_scalar::<_, i64>(
        "select count(*) from pg_stat_activity where datname='openpc_candidate_index' and usename='openpc_fact_bridge_reader'"
    ).fetch_one(admin)
    };
    let reader = CandidateFeedReader::prepare(&url).unwrap();
    assert_eq!(count().await.unwrap(), 0, "preparation must not log in");
    assert!(matches!(
        reader.authenticate(authenticator, privacy).await,
        Err(CandidateFeedError::Authentication)
    ));
    assert_eq!(
        count().await.unwrap(),
        0,
        "wrong peer context must not log in"
    );
    assert!(
        reader.pool.is_closed(),
        "authentication rejection is terminal"
    );

    let reader = CandidateFeedReader::prepare(&url).unwrap();
    let mut read = reader
        .authenticate(authenticator, participant)
        .await
        .unwrap()
        .read_partition(scope(), Uuid::now_v7())
        .await
        .unwrap();
    assert!(read.event(1).await.unwrap().is_none());
    assert_eq!(
        count().await.unwrap(),
        1,
        "real authenticated database session"
    );
    read.close().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while count().await.unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut read = reader
        .authenticate(authenticator, participant)
        .await
        .unwrap()
        .read_partition(scope(), Uuid::now_v7())
        .await
        .unwrap();
    let original_pid: i32 = sqlx::query_scalar("select pg_backend_pid()")
        .fetch_one(&mut *read.transaction)
        .await
        .unwrap();
    // Authoritative DB login revocation blocks replacements; pool closure
    // separately fences acquisitions and drains the already-owned session.
    sqlx::query("alter role openpc_fact_bridge_reader nologin")
        .execute(admin)
        .await
        .unwrap();
    assert!(sqlx::PgConnection::connect(&url).await.is_err());
    let closing = reader.clone();
    let drain = tokio::spawn(async move { closing.close().await });
    reader.pool.close_event().await;
    assert!(
        !drain.is_finished(),
        "an in-use session must not be reported drained"
    );
    assert!(matches!(
        reader.read_partition(scope(), Uuid::now_v7()).await,
        Err(CandidateFeedError::Database(sqlx::Error::PoolClosed))
    ));
    read.close().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), drain)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while count().await.unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let remaining: i64 = sqlx::query_scalar("select count(*) from pg_stat_activity where pid=$1")
        .bind(original_pid)
        .fetch_one(admin)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "original backend is physically gone");
    assert!(
        reader
            .authenticate(authenticator, participant)
            .await
            .is_err()
    );
    assert!(
        sqlx::PgConnection::connect(&url).await.is_err(),
        "restart cannot bypass NOLOGIN"
    );
}

#[derive(serde::Deserialize)]
struct InstalledInput {
    database_url_file: String,
    participant: Uuid,
    privacy: Uuid,
    operation: Uuid,
    partition: Uuid,
    generation: Uuid,
}

#[tokio::test]
#[ignore = "requires an installed reader and owner-published candidate/checkpoint"]
async fn installed_candidate_reader_is_scoped_ordered_and_read_only() {
    let config = std::env::var("OPENPC_FACT_CANDIDATE_TEST_INPUT_FILE").unwrap();
    let input: InstalledInput = serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
    let url = std::fs::read_to_string(&input.database_url_file).unwrap();
    let reader = CandidateFeedReader::connect(url.trim()).await.unwrap();
    let scope =
        || CandidateReadScope::new(input.participant, input.privacy, input.operation).unwrap();
    let mut read = reader
        .read_partition(scope(), input.partition)
        .await
        .unwrap();
    let first = read.event(1).await.unwrap().expect("observed event");
    assert_eq!(first.generation_id, input.generation);
    assert_eq!(first.publication_state.as_deref(), Some("PUBLISHED"));
    assert_eq!(
        first.event_type,
        "io.openpc.indexer.projection.candidate.observed.v1"
    );
    assert_eq!(
        pc_facts_core::sha256(&first.payload_cbor).as_slice(),
        first.payload_digest
    );
    let material = read
        .candidate(1)
        .await
        .expect("exact immutable candidate material");
    assert_eq!(
        material.source.inputs.published().projection_generation_id,
        input.generation
    );
    assert_eq!(material.block_number, 10);
    assert_eq!(material.finality_head_number, Some(11));
    assert_eq!(material.record_kind, "STATE_CALL");
    assert_eq!(material.record_sequence, 1);
    assert_eq!(material.batch_sequence, 1);
    assert_eq!(material.range_start, 10);
    assert_eq!(material.range_end, 10);
    assert!(material.observed_at_ms > 0);
    assert_eq!(material.checkpoint["recordCount"], "1");
    let (candidate_receipt, checkpoint_receipt) = read
        .receipt_events(&material, Uuid::now_v7())
        .await
        .expect("actual candidate and closing checkpoint receipt bindings");
    assert_eq!(candidate_receipt.sequence, 1);
    assert_eq!(checkpoint_receipt.sequence, 2);
    assert_eq!(
        candidate_receipt.candidate_id,
        Some(material.candidate_id.to_string())
    );
    assert!(checkpoint_receipt.candidate_id.is_none());
    assert_eq!(
        candidate_receipt.batch.checkpoint_digest.as_slice(),
        material.checkpoint_digest
    );
    let payload: serde_json::Value =
        ciborium::de::from_reader(material.payload_cbor.as_slice()).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"result":format!("0x{}1234", "00".repeat(30))})
    );
    assert!(matches!(
        read.candidate(2).await,
        Err(CandidateFeedError::Material)
    ));
    let checkpoint = read.event(2).await.unwrap().expect("checkpoint event");
    assert_eq!(
        checkpoint.event_type,
        "io.openpc.indexer.projection.checkpoint.completed.v1"
    );
    assert_eq!(checkpoint.generation_id, first.generation_id);
    assert!(read.event(3).await.unwrap().is_none());
    assert!(matches!(
        read.event(0).await,
        Err(CandidateFeedError::Scope)
    ));
    let read_only: String = sqlx::query_scalar("show transaction_read_only")
        .fetch_one(&mut *read.transaction)
        .await
        .unwrap();
    assert_eq!(read_only, "on");
    let denied = sqlx::query("delete from candidate.candidate_event")
        .execute(&mut *read.transaction)
        .await;
    assert!(denied.is_err());
    read.close().await.unwrap();
    reader.close().await;

    let restarted = CandidateFeedReader::connect(url.trim()).await.unwrap();
    let mut same = restarted
        .read_partition(scope(), input.partition)
        .await
        .unwrap();
    let replay = same.event(1).await.unwrap().unwrap();
    assert_eq!(replay.event_id, first.event_id);
    assert_eq!(replay.payload_cbor, first.payload_cbor);
    same.close().await.unwrap();
    let foreign = Uuid::parse_str("018f0000-0000-7000-8000-000000000299").unwrap();
    assert_ne!(input.participant, foreign);
    assert_ne!(input.privacy, foreign);
    for (participant, privacy) in [(foreign, input.privacy), (input.participant, foreign)] {
        let scope = CandidateReadScope::new(participant, privacy, input.operation).unwrap();
        let mut denied = restarted
            .read_partition(scope, input.partition)
            .await
            .unwrap();
        assert!(denied.event(1).await.unwrap().is_none());
        denied.close().await.unwrap();
    }
    restarted.close().await;
}
