use super::*;
use openpc_multi_rpc::provider_connection::NetworkRange;
use pc_policy_core::identity_context::RuntimeIdentityContext;
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Input {
    participant: Uuid,
    privacy: Uuid,
    target: Uuid,
    principal: Uuid,
    assignment: Uuid,
    envelope: Uuid,
    platform: Uuid,
    endpoint: String,
    ca: Vec<u8>,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    server_digest: String,
    identity_key: Vec<u8>,
    profile_digest: String,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}
async fn scoped(pool: &PgPool, input: &Input) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
        .bind(input.participant)
        .bind(input.privacy)
        .bind(input.target)
        .bind(ACTION)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select openpc.lock_fact_workload_context()")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

#[tokio::test]
#[ignore = "requires real Identity mTLS owner, current signed publication and migrated read-only Control role"]
async fn installed_mtls_identity_requires_current_scoped_fact_permission() {
    let input: Input = serde_json::from_slice(
        &std::fs::read(std::env::var("OPENPC_FACT_WORKLOAD_TEST_INPUT_FILE").unwrap()).unwrap(),
    )
    .unwrap();
    let context = || RuntimeIdentityContext {
        participant_id: input.participant.to_string(),
        privacy_domain_id: input.privacy.to_string(),
        target_runtime_id: input.target.to_string(),
    };
    let port: u16 = input
        .endpoint
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let client = FactWorkloadAuthenticator::prepare(
        &EndpointDescriptor {
            endpoint_id: "identity-test".into(),
            normalized_uri: input.endpoint.clone(),
            reference_identity: "127.0.0.1".into(),
            port,
            path: "/internal/v1/workload/authenticate".into(),
            dns_policy_ref: "local-only".into(),
            tls_policy_ref: "pinned-identity".into(),
            credential_ref: "actual-workload".into(),
            egress_policy_ref: "local-only".into(),
            endpoint_generation: 1,
        },
        &DestinationPolicy {
            allowed_ranges: vec![NetworkRange::parse("127.0.0.1/32").unwrap()],
            private_network_ranges: vec![NetworkRange::parse("127.0.0.1/32").unwrap()],
            allow_ip_endpoint: true,
        },
        Resolution {
            addresses: vec!["127.0.0.1".parse().unwrap()],
            resolved_at_ms: now() / 1_000_000,
            valid_until_ms: now() / 1_000_000 + 30_000,
            generation: 1,
        },
        LocalTlsMaterial {
            roots: vec![input.ca.clone().into()],
            client_chain: vec![input.certificate.clone().into()],
            client_key: input.private_key.clone().try_into().unwrap(),
            expected_server_certificate: Digest::parse(&input.server_digest).unwrap(),
        },
    )
    .unwrap();
    let trust = FactIdentityTrust::new(
        std::slice::from_ref(&input.identity_key),
        prefixed_digest(&format!("sha256:{}", input.profile_digest)).unwrap(),
        "local-test-identity".into(),
    )
    .unwrap();
    let pool = PgPool::connect(&std::env::var("OPENPC_FACT_WORKLOAD_TEST_READER_URL").unwrap())
        .await
        .unwrap();
    let admin = PgPool::connect(&std::env::var("OPENPC_ASTRA05_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    crate::candidate_feed::tests::assert_installed_connection_lifecycle(
        &client,
        &admin,
        input.participant,
        input.privacy,
    )
    .await;
    // Identity-only startup admission does not require/publish runtime authority.
    client.authenticate_peer(input.participant).await.unwrap();
    assert!(client.authenticate_peer(input.privacy).await.is_err());
    let authentication = client.authenticate(context()).await.unwrap();
    let mut tx = scoped(&pool, &input).await;
    let authority = authentication
        .authorize_in(
            &mut tx,
            input.participant,
            input.privacy,
            "fact-owner-test",
            &trust,
            now(),
        )
        .await
        .unwrap();
    assert_eq!(authority.principal_id, input.principal);
    assert_eq!(authority.platform_context_id, input.platform);
    assert_eq!(authority.platform_authority_epoch, "7");
    assert_eq!(authority.participant_authority_envelope_id, input.envelope);
    assert_eq!(authority.delegation_epoch, "1");
    assert_ne!(
        authority.platform_authority_epoch,
        authority.participant_epoch
    );
    assert!(authority.expires_at_ns > now());
    sqlx::query("savepoint foreign_context")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
        .bind(input.target)
        .bind(input.privacy)
        .bind(input.target)
        .bind(ACTION)
        .execute(&mut *tx)
        .await
        .unwrap();
    let hidden: i64 = sqlx::query_scalar("select count(*) from control.platform_context")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(hidden, 0);
    let hidden: i64 = sqlx::query_scalar(
        "select count(*) from openpc.lock_authority_envelope_platform_context($1)",
    )
    .bind(input.envelope)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(hidden, 0);
    sqlx::query("rollback to savepoint foreign_context")
        .execute(&mut *tx)
        .await
        .unwrap();
    // Installed reader cannot mutate authority, even while holding the lock.
    sqlx::query("savepoint mutation_denied")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query(
            "update control.principal set authority_epoch=authority_epoch+1 where principal_id=$1"
        )
        .bind(input.principal)
        .execute(&mut *tx)
        .await
        .is_err()
    );
    sqlx::query("rollback to savepoint mutation_denied")
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut competing = admin.begin().await.unwrap();
    sqlx::query("set local lock_timeout='150ms'")
        .execute(&mut *competing)
        .await
        .unwrap();
    let blocked = sqlx::query(
        "select participant_id from control.participant where participant_id=$1 for share",
    )
    .bind(input.participant)
    .fetch_one(&mut *competing)
    .await
    .unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    competing.rollback().await.unwrap();
    let mut competing = admin.begin().await.unwrap();
    sqlx::query("set local lock_timeout='150ms'")
        .execute(&mut *competing)
        .await
        .unwrap();
    let blocked = sqlx::query(
        "update control.platform_context set authority_epoch=authority_epoch+1,
         row_version=row_version+1,updated_at=clock_timestamp() where platform_context_id=$1",
    )
    .bind(input.platform)
    .execute(&mut *competing)
    .await
    .unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    competing.rollback().await.unwrap();
    tx.rollback().await.unwrap();

    let authentication = client.authenticate(context()).await.unwrap();
    let mut tx = scoped(&pool, &input).await;
    assert!(matches!(
        authentication
            .authorize_in(
                &mut tx,
                input.target,
                input.privacy,
                "fact-owner-test",
                &trust,
                now()
            )
            .await,
        Err(WorkloadAuthorityError::Authority)
    ));
    tx.rollback().await.unwrap();

    let mut authentication = client.authenticate(context()).await.unwrap();
    authentication.certificate_digest = [99; 32];
    let mut tx = scoped(&pool, &input).await;
    assert!(matches!(
        authentication
            .authorize_in(
                &mut tx,
                input.participant,
                input.privacy,
                "fact-owner-test",
                &trust,
                now()
            )
            .await,
        Err(WorkloadAuthorityError::Authority)
    ));
    tx.rollback().await.unwrap();

    // A still-valid signed snapshot cannot survive a committed dependency revision.
    let authentication = client.authenticate(context()).await.unwrap();
    sqlx::query("update control.assignment set row_version=row_version+1 where assignment_id=$1")
        .bind(input.assignment)
        .execute(&admin)
        .await
        .unwrap();
    let mut tx = scoped(&pool, &input).await;
    assert!(matches!(
        authentication
            .authorize_in(
                &mut tx,
                input.participant,
                input.privacy,
                "fact-owner-test",
                &trust,
                now()
            )
            .await,
        Err(WorkloadAuthorityError::Authority)
    ));
    tx.rollback().await.unwrap();
    // Refresh remains owned by real mTLS authentication and signed publication.
    let authentication = client.authenticate(context()).await.unwrap();
    let mut tx = scoped(&pool, &input).await;
    authentication
        .authorize_in(
            &mut tx,
            input.participant,
            input.privacy,
            "fact-owner-test",
            &trust,
            now(),
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    // Even maintenance cannot retrofit Platform authority onto old envelopes.
    assert!(sqlx::query("update control.authority_envelope set platform_authority_epoch=8 where authority_envelope_id=$1")
        .bind(input.envelope).execute(&admin).await.is_err());

    // Fresh mTLS publication cannot renew an immutable envelope after the
    // independent Platform epoch changes. Reconnect retains that denial.
    sqlx::query(
        "update control.platform_context set authority_epoch=authority_epoch+1,
        row_version=row_version+1,updated_at=clock_timestamp() where platform_context_id=$1",
    )
    .bind(input.platform)
    .execute(&admin)
    .await
    .unwrap();
    let restarted =
        PgPool::connect(&std::env::var("OPENPC_FACT_WORKLOAD_TEST_READER_URL").unwrap())
            .await
            .unwrap();
    let authentication = client.authenticate(context()).await.unwrap();
    let mut tx = scoped(&restarted, &input).await;
    assert!(matches!(
        authentication
            .authorize_in(
                &mut tx,
                input.participant,
                input.privacy,
                "fact-owner-test",
                &trust,
                now()
            )
            .await,
        Err(WorkloadAuthorityError::Authority)
    ));
    tx.rollback().await.unwrap();
    restarted.close().await;
    pool.close().await;
    admin.close().await;
}
