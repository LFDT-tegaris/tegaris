//! Target-owner PostgreSQL regressions. These exercise real signatures, RLS,
//! locks and commits; they do not stand in for Control/browser journey acceptance.
use super::*;
use pc_runtime_types::PurposeSigner;
use pc_runtime_types::store_retirement::{
    FactPayloadSelection, RetirementGovernance, RetirementScope, RetirementSource,
};
use pc_runtime_types::store_retirement_authority::{
    CANCEL_PURPOSE, OUTCOME_PURPOSE, REQUEST_PURPOSE, RetirementCancelClaims,
    RetirementDispatchSigner, RetirementRequestClaims,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod physical;
mod protocol;

fn capability_secret() -> [u8; 32] {
    crate::store::tests::external_capability_secret().unwrap_or_else(|| {
        panic!("OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=CAPABILITY_SECRET_REQUIRED")
    })
}

// The required target gate explicitly selects --ignored. A compile-only or
// ordinary unit invocation that skips these tests is not PostgreSQL acceptance.
async fn runtime_pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        panic!("OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=MISSING_RUNTIME_DATABASE_URL")
    });
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap_or_else(|_| {
            panic!("OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=RUNTIME_DATABASE_UNAVAILABLE")
        });
    let installed: bool = sqlx::query_scalar(
        "select to_regclass('facts.store_retirement_attempt') is not null
          and to_regclass('facts.retirement_capability_replay') is not null",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        installed,
        "OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=MIGRATION_0011_REQUIRED"
    );
    let restricted: bool = sqlx::query_scalar(
        "select current_user=session_user and exists(select 1 from pg_roles r
           where r.rolname=current_user and not r.rolsuper and not r.rolbypassrls)
         and pg_has_role(current_user,'openpc_fact_bridge_writer','MEMBER')
         and not pg_has_role(current_user,'openpc_facts_lifecycle_owner','MEMBER')
         and not pg_has_role(current_user,'openpc_facts_capability_owner','MEMBER')
         and has_function_privilege(current_user,'facts.lock_store_retirement(text,text)','EXECUTE')
         and has_function_privilege(current_user,'facts.check_store_retirement(jsonb)','EXECUTE')
         and has_function_privilege(current_user,'facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea)','EXECUTE')
         and has_function_privilege(current_user,'facts.cancel_store_retirement(bytea,bytea,bytea,bytea)','EXECUTE')
         and not has_function_privilege(current_user,'facts.commit_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea,boolean)','EXECUTE')
         and not has_function_privilege(current_user,'facts.consume_retirement_capability(text,bytea,bytea,bytea,bytea,bytea)','EXECUTE')
         and not has_function_privilege(current_user,'facts.verify_retirement_execution(bytea,bytea,bytea,bytea,bytea)','EXECUTE')
         and not has_function_privilege(current_user,'facts.verify_retirement_cancellation(bytea,bytea,bytea,bytea,bytea)','EXECUTE')
         and has_table_privilege(current_user,'facts.store_retirement_attempt','SELECT')
         and has_table_privilege(current_user,'facts.signed_fact_custody','SELECT')
         and has_table_privilege(current_user,'facts.retained_fact_identity','SELECT')
         and has_table_privilege(current_user,'facts.retired_fact_payload','SELECT')
         and has_table_privilege(current_user,'facts.store_retirement_outbox','SELECT')
         and not has_table_privilege(current_user,'facts.canonical_fact','INSERT,UPDATE,DELETE,TRUNCATE')
         and not has_table_privilege(current_user,'facts.store_retirement_attempt','INSERT,UPDATE,DELETE,TRUNCATE')
         and not has_table_privilege(current_user,'facts.retirement_capability_replay','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        restricted,
        "OPENPC_FACT_RETIREMENT|status=BLOCKED|reason=RUNTIME_ROLE_OR_GRANTS_INVALID"
    );
    pool
}

struct Fixture {
    owner: FactRetirementOwner,
    dispatch: RetirementDispatchSigner,
    claims: RetirementRequestClaims,
    configuration: RetirementAuthorityConfiguration,
}

impl Fixture {
    async fn new() -> Self {
        let secret = capability_secret();
        let pool = runtime_pool().await;
        let store = FactStore::new(pool, secret);
        let scope = RetirementScope {
            participant_id: Uuid::now_v7().to_string(),
            privacy_domain_id: Uuid::now_v7().to_string(),
        };
        let host = RetirementHost {
            environment_id: "local-retirement-test".into(),
            target_id: "fact-target".into(),
            scope: scope.clone(),
            store: RetirementStore::Facts,
        };
        let selection = RetirementSelection::Facts {
            source: RetirementSource {
                profile_id: Uuid::now_v7().to_string(),
                generation_id: Uuid::now_v7().to_string(),
                partition_id: Uuid::now_v7().to_string(),
                identity_digest: Digest::of(b"not-yet-dispatched-source"),
            },
            fact_generation_id: Uuid::now_v7().to_string(),
            canonical_generation: 1,
            rows: vec![FactPayloadSelection {
                candidate_id: Uuid::now_v7().to_string(),
                fact_id: Uuid::now_v7().to_string(),
                fact_delta_sequence: 1,
                candidate_feed_sequence: 3,
                payload_digest: Digest::of(b"payload"),
                payload_bytes: 7,
                signed_fact_digest: Digest::of(b"signed-fact"),
                lineage_digest: Digest::of(b"lineage"),
                checkpoint_digest: Digest::of(b"checkpoint"),
            }],
        };
        let configuration = RetirementAuthorityConfiguration {
            version: 1,
            host: host.clone(),
            control_public_key_sec1: PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
            target_public_key_sec1: PurposeSigner::from_secret_bytes(OUTCOME_PURPOSE, [32; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
        };
        let fact_signer =
            crate::PurposeBoundFactSigner::generate_ephemeral_local(vec![42; 32]).unwrap();
        let owner = FactRetirementOwner::from_host_configuration(
            store,
            host.clone(),
            configuration.clone(),
            [32; 32],
            fact_signer.verifier(),
        )
        .unwrap();
        let mut tx = owner.begin().await.unwrap();
        let now = now_ms(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
        let attempt = RetirementAttempt {
            scope: scope.clone(),
            store: RetirementStore::Facts,
            business_intent_id: Uuid::now_v7().to_string(),
            attempt_id: Uuid::now_v7().to_string(),
            governance: RetirementGovernance {
                retention_policy_digest: Digest::of(b"policy"),
                archive_manifest_digest: Digest::of(b"archive"),
                archive_acknowledgement_digest: Digest::of(b"ack"),
                approval_digest: Digest::of(b"approval"),
                lifecycle_revision: 1,
                retention_not_before_ms: 1,
            },
            selection_digest: selection.digest(&scope).unwrap(),
            selection,
        };
        let claims = RetirementRequestClaims {
            version: 1,
            host: host.clone(),
            attempt,
            admission_receipt_digest: Digest::of(b"admission"),
            committed_admission_digest: Digest::of(b"committed admission"),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        };
        Self {
            owner,
            dispatch: RetirementDispatchSigner::from_host_key(host, [31; 32]).unwrap(),
            claims,
            configuration,
        }
    }

    fn request(&self) -> Vec<u8> {
        self.dispatch
            .sign_committed_request(self.claims.clone(), self.claims.issued_at_ms)
            .unwrap()
    }

    fn cancellation(&self) -> Vec<u8> {
        self.dispatch
            .sign_committed_cancellation(
                RetirementCancelClaims {
                    version: 1,
                    host: self.claims.host.clone(),
                    attempt: self.claims.attempt.clone(),
                    cancellation_id: Uuid::now_v7().to_string(),
                    lifecycle_revision: 2,
                    committed_cancellation_digest: Digest::of(b"committed cancellation"),
                    issued_at_ms: self.claims.issued_at_ms,
                    expires_at_ms: self.claims.expires_at_ms,
                },
                self.claims.issued_at_ms,
            )
            .unwrap()
    }

    async fn counts(&self) -> (i64, i64, i64) {
        let mut tx = self.owner.begin().await.unwrap();
        let result = sqlx::query_as("select
            (select count(*) from facts.store_retirement_attempt where participant_id=$1 and privacy_domain_id=$2),
            (select count(*) from facts.store_retirement_outbox where participant_id=$1 and privacy_domain_id=$2),
            (select count(*) from facts.retired_fact_payload where participant_id=$1 and privacy_domain_id=$2)")
            .bind(&self.claims.attempt.scope.participant_id).bind(&self.claims.attempt.scope.privacy_domain_id)
            .fetch_one(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
        result
    }
}

fn terminal(result: FactRetirementReadback) -> (RetirementEffect, Vec<u8>) {
    match result {
        FactRetirementReadback::Terminal {
            claims,
            signed_outcome,
        } => (claims.outcome.effect, signed_outcome),
        FactRetirementReadback::Unknown => panic!("expected original signed terminal outcome"),
    }
}

#[tokio::test]
#[ignore = "requires migrated FactStore and installed runtime role/capability secret"]
async fn verified_cancel_before_dispatch_survives_restart_and_late_execution() {
    let fixture = Fixture::new().await;
    assert!(matches!(
        fixture
            .owner
            .readback(&fixture.claims.attempt)
            .await
            .unwrap(),
        FactRetirementReadback::Unknown
    ));
    assert_eq!(fixture.counts().await, (0, 0, 0));
    let (effect, original) = terminal(fixture.owner.cancel(&fixture.cancellation()).await.unwrap());
    assert_eq!(effect, RetirementEffect::CancelledNoEffect {});
    let (_, late) = terminal(fixture.owner.execute(&fixture.request()).await.unwrap());
    assert_eq!(late, original);
    let restarted = FactRetirementOwner::from_host_configuration(
        fixture.owner.store.clone(),
        fixture.claims.host.clone(),
        fixture.configuration.clone(),
        [32; 32],
        fixture.owner.fact_verifier.clone(),
    )
    .unwrap();
    let (_, readback) = terminal(restarted.readback(&fixture.claims.attempt).await.unwrap());
    assert_eq!(readback, original);
    assert_eq!(fixture.counts().await, (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires migrated FactStore and installed runtime role/capability secret"]
async fn exact_replay_keeps_original_outcome_and_altered_approval_is_rejected() {
    let mut fixture = Fixture::new().await;
    let (effect, original) = terminal(fixture.owner.execute(&fixture.request()).await.unwrap());
    assert_eq!(
        effect,
        RetirementEffect::RejectedNoEffect {
            rejection: RetirementRejection::SourceChanged
        }
    );
    let (_, replay) = terminal(fixture.owner.execute(&fixture.request()).await.unwrap());
    assert_eq!(replay, original);
    fixture.claims.attempt.governance.approval_digest = Digest::of(b"different approval");
    assert!(matches!(
        fixture.owner.execute(&fixture.request()).await,
        Err(FactRetirementError::AlteredReplay)
    ));
    assert_eq!(fixture.counts().await, (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires migrated FactStore and installed runtime role/capability secret"]
async fn execute_cancel_race_commits_one_original_signed_outcome() {
    let fixture = Fixture::new().await;
    let request = fixture.request();
    let cancellation = fixture.cancellation();
    let (executed, cancelled) = tokio::join!(
        fixture.owner.execute(&request),
        fixture.owner.cancel(&cancellation)
    );
    let (effect, first) = terminal(executed.unwrap());
    let (other, second) = terminal(cancelled.unwrap());
    assert_eq!(first, second);
    assert_eq!(effect, other);
    assert!(matches!(
        effect,
        RetirementEffect::CancelledNoEffect {}
            | RetirementEffect::RejectedNoEffect {
                rejection: RetirementRejection::SourceChanged
            }
    ));
    assert_eq!(fixture.counts().await, (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires migrated FactStore and installed runtime role/capability secret"]
async fn target_signer_failure_rolls_back_and_scope_purpose_failures_have_no_effect() {
    let fixture = Fixture::new().await;
    let wrong_signer = FactRetirementOwner::from_host_configuration(
        fixture.owner.store.clone(),
        fixture.claims.host.clone(),
        fixture.configuration.clone(),
        [33; 32],
        fixture.owner.fact_verifier.clone(),
    )
    .unwrap();
    assert!(matches!(
        wrong_signer.cancel(&fixture.cancellation()).await,
        Err(FactRetirementError::Authority)
    ));
    assert_eq!(fixture.counts().await, (0, 0, 0));
    let wrong_purpose = PurposeSigner::from_secret_bytes(CANCEL_PURPOSE, [31; 32])
        .unwrap()
        .sign(fixture.claims.clone())
        .unwrap();
    assert!(
        fixture
            .owner
            .execute(&canonical_bytes(&wrong_purpose).unwrap())
            .await
            .is_err()
    );
    let mut foreign = fixture.claims.clone();
    foreign.host.scope.privacy_domain_id = Uuid::now_v7().to_string();
    let bytes = canonical_bytes(
        &PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32])
            .unwrap()
            .sign(foreign)
            .unwrap(),
    )
    .unwrap();
    assert!(fixture.owner.execute(&bytes).await.is_err());
    assert_eq!(fixture.counts().await, (0, 0, 0));
    fixture.owner.cancel(&fixture.cancellation()).await.unwrap();
    assert_eq!(fixture.counts().await, (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires migrated FactStore and installed runtime role/capability secret"]
async fn sql_consumes_exact_cancellation_nonce_and_rejects_execution_domain_reuse() {
    let fixture = Fixture::new().await;
    let cancellation = fixture.cancellation();
    let now = fixture.claims.issued_at_ms;
    let outcome = fixture
        .owner
        .sign(
            &fixture.claims.attempt,
            RetirementEffect::CancelledNoEffect {},
            now,
        )
        .unwrap();
    let capability = fixture
        .owner
        .store
        .capabilities
        .retirement_cancellation(&cancellation, &outcome, &fixture.owner.trust, now)
        .unwrap();
    let mut tx = fixture.owner.begin().await.unwrap();
    // A valid cancel MAC must not admit execution, even with the exact same
    // signed bytes and caller identity. Failed verification consumes nothing.
    let rejected = sqlx::query("select facts.execute_store_retirement($1,$2,$3,$4,$5,$6)")
        .bind(&cancellation)
        .bind(&outcome)
        .bind(Vec::<u8>::new())
        .bind(Vec::<u8>::new())
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await;
    assert!(rejected.is_err());
    tx.rollback().await.unwrap();
    assert_eq!(fixture.counts().await, (0, 0, 0));
    let mut tx = fixture.owner.begin().await.unwrap();
    let original: Vec<u8> = sqlx::query_scalar("select facts.cancel_store_retirement($1,$2,$3,$4)")
        .bind(&cancellation)
        .bind(&outcome)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(original, outcome);
    let mut tx = fixture.owner.begin().await.unwrap();
    let replay = sqlx::query("select facts.cancel_store_retirement($1,$2,$3,$4)")
        .bind(&cancellation)
        .bind(&outcome)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await;
    assert!(replay.is_err());
    tx.rollback().await.unwrap();
    let (_, readback) = terminal(fixture.owner.cancel(&cancellation).await.unwrap());
    assert_eq!(readback, original);
    assert_eq!(fixture.counts().await, (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires migrated FactStore, writer capability and existing gate admin connection"]
async fn outbox_failure_rolls_back_attempt_and_nonce_before_exact_retry() {
    let fixture = Fixture::new().await;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("OPENPC_I05_GATE3_ADMIN_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let cancellation = fixture.cancellation();
    let now = fixture.claims.issued_at_ms;
    let outcome = fixture
        .owner
        .sign(
            &fixture.claims.attempt,
            RetirementEffect::CancelledNoEffect {},
            now,
        )
        .unwrap();
    let capability = fixture
        .owner
        .store
        .capabilities
        .retirement_cancellation(&cancellation, &outcome, &fixture.owner.trust, now)
        .unwrap();
    let constraint = format!("retirement_fault_{}", Uuid::now_v7().simple());
    let attempt = Uuid::parse_str(&fixture.claims.attempt.attempt_id).unwrap();
    // The fault is confined to this independently allocated test attempt. The
    // UUID parser above prevents arbitrary caller text from becoming SQL syntax.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "alter table facts.store_retirement_outbox add constraint {constraint}
        check(attempt_id<>'{attempt}')"
    )))
    .execute(&admin)
    .await
    .unwrap();
    let mut tx = fixture.owner.begin().await.unwrap();
    let failed = sqlx::query("select facts.cancel_store_retirement($1,$2,$3,$4)")
        .bind(&cancellation)
        .bind(&outcome)
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .execute(&mut *tx)
        .await;
    tx.rollback().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "alter table facts.store_retirement_outbox drop constraint {constraint}"
    )))
    .execute(&admin)
    .await
    .unwrap();
    assert!(failed.is_err());
    assert_eq!(fixture.counts().await, (0, 0, 0));
    let consumed: bool = sqlx::query_scalar(
        "select exists(select 1 from facts.retirement_capability_replay where nonce=$1)",
    )
    .bind(capability.nonce.as_slice())
    .fetch_one(&admin)
    .await
    .unwrap();
    assert!(!consumed);
    let mut tx = fixture.owner.begin().await.unwrap();
    let committed: Vec<u8> =
        sqlx::query_scalar("select facts.cancel_store_retirement($1,$2,$3,$4)")
            .bind(&cancellation)
            .bind(&outcome)
            .bind(capability.nonce.as_slice())
            .bind(capability.mac.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(committed, outcome);
    assert_eq!(fixture.counts().await, (1, 1, 0));
}
