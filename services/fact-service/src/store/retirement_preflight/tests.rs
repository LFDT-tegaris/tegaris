use super::*;
use crate::{PolicyFactReader, PurposeBoundFactSigner};
use pc_runtime_types::store_retirement::{
    CandidatePayloadSelection, FactPayloadSelection, RetirementGovernance, RetirementSource,
};
use sqlx::postgres::PgPoolOptions;
use std::{fs, path::PathBuf};
use uuid::Uuid;

// Shape-only input. It creates no source, signed authority or business state.
fn request() -> FactRetirementPreflightRequest {
    let scope = RetirementScope {
        participant_id: Uuid::now_v7().to_string(),
        privacy_domain_id: Uuid::now_v7().to_string(),
    };
    let selection = RetirementSelection::Facts {
        source: RetirementSource {
            profile_id: Uuid::now_v7().to_string(),
            generation_id: Uuid::now_v7().to_string(),
            partition_id: Uuid::now_v7().to_string(),
            identity_digest: Digest::of(b"source"),
        },
        fact_generation_id: Uuid::now_v7().to_string(),
        canonical_generation: 1,
        rows: vec![FactPayloadSelection {
            candidate_id: Uuid::now_v7().to_string(),
            fact_id: Uuid::now_v7().to_string(),
            fact_delta_sequence: 1,
            candidate_feed_sequence: 1,
            payload_digest: Digest::of(b"payload"),
            payload_bytes: 7,
            signed_fact_digest: Digest::of(b"signed"),
            lineage_digest: Digest::of(b"lineage"),
            checkpoint_digest: Digest::of(b"checkpoint"),
        }],
    };
    FactRetirementPreflightRequest {
        participant_id: scope.participant_id.clone(),
        privacy_domain_id: scope.privacy_domain_id.clone(),
        attempt: RetirementAttempt {
            selection_digest: selection.digest(&scope).unwrap(),
            selection,
            scope,
            store: RetirementStore::Facts,
            business_intent_id: Uuid::now_v7().to_string(),
            attempt_id: Uuid::now_v7().to_string(),
            governance: RetirementGovernance {
                retention_policy_digest: Digest::of(b"policy"),
                archive_manifest_digest: Digest::of(b"archive"),
                archive_acknowledgement_digest: Digest::of(b"ack"),
                approval_digest: Digest::of(b"not-authority"),
                lifecycle_revision: 1,
                retention_not_before_ms: 1,
            },
        },
    }
}

fn rebind(request: &mut FactRetirementPreflightRequest) {
    request.attempt.selection_digest = request
        .attempt
        .selection
        .digest(&request.attempt.scope)
        .unwrap();
}

#[test]
fn strict_input_rejects_forged_authority_flags_and_unknown_fields() {
    let original = request();
    original.validate().unwrap();
    for flag in ["eligible", "holdFree", "referencesClear", "signedAuthority"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[flag] = true.into();
        assert!(serde_json::from_value::<FactRetirementPreflightRequest>(value).is_err());
    }
    let mut value = serde_json::to_value(original).unwrap();
    value["attempt"]["selection"]["ready"] = true.into();
    assert!(serde_json::from_value::<FactRetirementPreflightRequest>(value).is_err());
}

#[tokio::test]
async fn malformed_foreign_context_and_candidate_store_fail_before_connection() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://unavailable:unused@127.0.0.1:1/openpc_facts")
        .unwrap();
    let signer = PurposeBoundFactSigner::generate_ephemeral_local(vec![91; 32]).unwrap();
    let reader = PolicyFactReader::new(pool, signer.verifier());
    let original = request();
    let mut cases = Vec::new();
    let mut changed = original.clone();
    changed.participant_id = Uuid::now_v7().to_string();
    cases.push(changed);
    let mut changed = original.clone();
    changed.privacy_domain_id = Uuid::now_v7().to_string();
    cases.push(changed);
    let mut changed = original.clone();
    changed.attempt.selection_digest = Digest::of(b"altered");
    cases.push(changed);
    let mut changed = original.clone();
    let RetirementSelection::Facts { rows, .. } = &mut changed.attempt.selection else {
        unreachable!()
    };
    rows[0].payload_bytes = 0;
    cases.push(changed);
    let mut changed = original.clone();
    let RetirementSelection::Facts { source, rows, .. } = original.attempt.selection else {
        unreachable!()
    };
    changed.attempt.selection = RetirementSelection::Candidates {
        source,
        rows: rows
            .into_iter()
            .map(|row| CandidatePayloadSelection {
                candidate_id: row.candidate_id,
                candidate_feed_sequence: row.candidate_feed_sequence,
                payload_digest: row.payload_digest,
                payload_bytes: row.payload_bytes,
                checkpoint_digest: row.checkpoint_digest,
            })
            .collect(),
    };
    changed.attempt.store = RetirementStore::CandidateIndex;
    rebind(&mut changed);
    cases.push(changed);
    for changed in cases {
        assert!(matches!(
            reader.retirement_preflight(&changed).await,
            Err(FactRetirementError::Authority)
        ));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingCase {
    request: FactRetirementPreflightRequest,
    fact_public_key_file: PathBuf,
    fact_signer_key_id: String,
    blocked_cases: Vec<BlockedCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockedCase {
    request: FactRetirementPreflightRequest,
    blocker: RetirementRejection,
}

fn bounded_file(path: &std::path::Path, maximum: u64) -> Vec<u8> {
    assert!(path.is_absolute());
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && metadata.len() <= maximum);
    fs::read(path).unwrap()
}

fn existing_case() -> ExistingCase {
    let path = std::env::var_os("OPENPC_FACT_RETIREMENT_PREFLIGHT_CASE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("OPENPC_FACT_PREFLIGHT|BLOCKED|MISSING_REAL_SOURCE_CASE"));
    let case: ExistingCase = serde_json::from_slice(&bounded_file(&path, 8_388_608)).unwrap();
    case.request.validate().unwrap();
    assert!(case.blocked_cases.len() <= 16);
    case
}

async fn pool(variable: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(
            &std::env::var(variable)
                .unwrap_or_else(|_| panic!("OPENPC_FACT_PREFLIGHT|BLOCKED|{variable}")),
        )
        .await
        .unwrap()
}

// Compare exact row contents, not just counts, without printing payloads or
// recording a new evidence artifact. The integration fixture owns these scopes.
async fn snapshot(pool: &PgPool, request: &FactRetirementPreflightRequest) -> Vec<String> {
    let mut tx = pool.begin().await.unwrap();
    set_context(&mut tx, &request.participant_id, &request.privacy_domain_id)
        .await
        .unwrap();
    let mut result = Vec::new();
    for table in [
        "canonical_fact",
        "admission_inbox",
        "candidate_feed_receipt",
        "source_checkpoint",
        "readiness_gate",
        "retained_fact_identity",
        "signed_fact_custody",
        "store_retirement_attempt",
        "retired_fact_payload",
        "outbox",
        "store_retirement_outbox",
    ] {
        let query = format!(
            "select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb)::text from facts.{table} t where participant_id=$1 and privacy_domain_id=$2"
        );
        result.push(
            // The identifier comes only from the fixed table list above; all
            // scope values remain bound parameters.
            sqlx::query_scalar(sqlx::AssertSqlSafe(query))
                .bind(&request.participant_id)
                .bind(&request.privacy_domain_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
        );
    }
    tx.rollback().await.unwrap();
    result
}

fn blocked(result: &FactRetirementPreflight, expected: RetirementRejection) {
    assert!(
        matches!(result.result(), FactRetirementPreflightResult::Blocked { blocker } if *blocker==expected)
    );
}

#[tokio::test]
#[ignore = "requires migrated read-only role and a real owner-produced terminal source selection; no governance or terminal state is seeded"]
async fn real_source_preflight_is_read_only_exact_and_fail_closed() {
    let case = existing_case();
    let pool = pool("OPENPC_POLICY_FACT_READER_DATABASE_URL").await;
    let admin = pool_from_admin().await;
    let verifier = FactSignatureVerifier::from_key_identifier(
        &case.fact_signer_key_id,
        &bounded_file(&case.fact_public_key_file, 1024),
    )
    .unwrap();
    let reader = PolicyFactReader::new(pool.clone(), verifier);
    let before = snapshot(&admin, &case.request).await;
    let result = reader.retirement_preflight(&case.request).await.unwrap();
    assert_eq!(
        result.attempt_digest(),
        &case.request.attempt.digest().unwrap()
    );
    assert_eq!(
        result.selection_digest(),
        &case.request.attempt.selection_digest
    );
    let FactRetirementPreflightResult::Clear {
        selection,
        checked_at_ms,
    } = result.result()
    else {
        panic!("OPENPC_FACT_PREFLIGHT|FAIL|ORIGINAL_REAL_SOURCE_NOT_CLEAR");
    };
    assert_eq!(selection, &case.request.attempt.selection);
    assert!(checked_at_ms.parse::<u64>().unwrap() > 0);
    let output = serde_json::to_value(&result).unwrap();
    assert_eq!(output["authority"], "ADVISORY_ONLY");
    assert_eq!(output["identity"], "OPENPC-FACT-RETIREMENT-PREFLIGHT-1");
    assert!(output.get("signedOutcome").is_none());

    for field in [
        "identity",
        "source-generation",
        "fact-generation",
        "checkpoint",
        "signed-digest",
        "missing",
        "scope",
    ] {
        let mut altered = case.request.clone();
        let RetirementSelection::Facts {
            source,
            fact_generation_id,
            rows,
            ..
        } = &mut altered.attempt.selection
        else {
            unreachable!()
        };
        let expected = match field {
            "identity" => {
                source.identity_digest = Digest::of(b"changed-publication");
                RetirementRejection::SourceChanged
            }
            "source-generation" => {
                source.generation_id = Uuid::now_v7().to_string();
                RetirementRejection::GenerationChanged
            }
            "fact-generation" => {
                *fact_generation_id = Uuid::now_v7().to_string();
                RetirementRejection::GenerationChanged
            }
            "checkpoint" => {
                rows[0].checkpoint_digest = Digest::of(b"changed-checkpoint");
                RetirementRejection::SourceChanged
            }
            "signed-digest" => {
                rows[0].signed_fact_digest = Digest::of(b"changed-signature");
                RetirementRejection::SourceChanged
            }
            "missing" => {
                rows[0].candidate_id = Uuid::now_v7().to_string();
                RetirementRejection::SourceChanged
            }
            "scope" => {
                altered.privacy_domain_id = Uuid::now_v7().to_string();
                altered.attempt.scope.privacy_domain_id = altered.privacy_domain_id.clone();
                RetirementRejection::SourceChanged
            }
            _ => unreachable!(),
        };
        rebind(&mut altered);
        let result = reader.retirement_preflight(&altered).await.unwrap();
        blocked(&result, expected);
        assert!(
            serde_json::to_value(result).unwrap()["result"]
                .get("selection")
                .is_none()
        );
    }
    let mut retained = case.request.clone();
    retained.attempt.governance.retention_not_before_ms = i64::MAX as u64;
    blocked(
        &reader.retirement_preflight(&retained).await.unwrap(),
        RetirementRejection::RetentionNotElapsed,
    );
    let wrong_key = PurposeBoundFactSigner::generate_ephemeral_local(vec![92; 32]).unwrap();
    blocked(
        &PolicyFactReader::new(pool.clone(), wrong_key.verifier())
            .retirement_preflight(&case.request)
            .await
            .unwrap(),
        RetirementRejection::SourceChanged,
    );

    // A clear read releases its advisory fence. It is never a future-atomicity
    // token and cannot replace the target's later exclusive mutation transaction.
    let mut tx = admin.begin().await.unwrap();
    let released: bool =
        sqlx::query_scalar("select pg_try_advisory_xact_lock(facts.policy_fence_key($1,$2))")
            .bind(&case.request.participant_id)
            .bind(&case.request.privacy_domain_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(released);
    tx.rollback().await.unwrap();
    assert_eq!(before, snapshot(&admin, &case.request).await);
}

async fn pool_from_admin() -> PgPool {
    pool("OPENPC_I05_GATE3_ADMIN_DATABASE_URL").await
}

#[tokio::test]
#[ignore = "requires actual independent owner-produced blocker cases and read-only database role"]
async fn real_blockers_do_not_mutate_or_expose() {
    let case = existing_case();
    let reader_pool = pool("OPENPC_POLICY_FACT_READER_DATABASE_URL").await;
    let admin = pool_from_admin().await;
    let verifier = FactSignatureVerifier::from_key_identifier(
        &case.fact_signer_key_id,
        &bounded_file(&case.fact_public_key_file, 1024),
    )
    .unwrap();
    let reader = PolicyFactReader::new(reader_pool.clone(), verifier.clone());
    for required in [
        RetirementRejection::ReferencesProtected,
        RetirementRejection::ReadinessProtected,
        RetirementRejection::CheckpointIncomplete,
        RetirementRejection::ReorgFenced,
        RetirementRejection::PublicationProtected,
        RetirementRejection::SourceChanged,
    ] {
        assert!(
            case.blocked_cases
                .iter()
                .any(|case| case.blocker == required),
            "OPENPC_FACT_PREFLIGHT|BLOCKED|MISSING_REAL_BLOCKER_CASE|{required:?}"
        );
    }
    for case in &case.blocked_cases {
        let before = snapshot(&admin, &case.request).await;
        blocked(
            &reader.retirement_preflight(&case.request).await.unwrap(),
            case.blocker,
        );
        assert_eq!(before, snapshot(&admin, &case.request).await);
    }
}

#[tokio::test]
#[ignore = "requires migrated reader/writer roles and disposable test admin; no source fixture or signing authority"]
async fn reader_privileges_context_store_and_unavailable_fail_closed() {
    let request = request();
    let reader_pool = pool("OPENPC_POLICY_FACT_READER_DATABASE_URL").await;
    let admin = pool_from_admin().await;
    let verifier = PurposeBoundFactSigner::generate_ephemeral_local(vec![93; 32])
        .unwrap()
        .verifier();
    let privileges: (bool, bool, bool, bool, bool) = sqlx::query_as("select
        has_function_privilege(current_user,'facts.preflight_store_retirement(jsonb)','EXECUTE'),
        has_function_privilege(current_user,'facts.check_store_retirement(jsonb)','EXECUTE'),
        has_function_privilege(current_user,'facts.store_retirement_predicates(jsonb)','EXECUTE'),
        has_function_privilege(current_user,'facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea)','EXECUTE'),
        has_function_privilege(current_user,'facts.cancel_store_retirement(bytea,bytea,bytea,bytea)','EXECUTE')")
        .fetch_one(&reader_pool).await.unwrap();
    assert_eq!(privileges, (true, false, false, false, false));
    for table in [
        "store_retirement_attempt",
        "signed_fact_custody",
        "retained_fact_identity",
        "retirement_capability_replay",
    ] {
        let granted: bool = sqlx::query_scalar(
            "select has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
        )
        .bind(format!("facts.{table}"))
        .fetch_one(&reader_pool)
        .await
        .unwrap();
        assert!(!granted);
    }
    // Raw SQL cannot select another context or use missing context. No role
    // escalation or writer permission is needed to call the read-only wrapper.
    for scope in [
        None,
        Some((Uuid::now_v7().to_string(), Uuid::now_v7().to_string())),
    ] {
        let mut tx = reader_pool.begin().await.unwrap();
        sqlx::query("set transaction read only")
            .execute(&mut *tx)
            .await
            .unwrap();
        if let Some((p, d)) = scope {
            set_context(&mut tx, &p, &d).await.unwrap();
        }
        let result = sqlx::query("select facts.preflight_store_retirement($1::jsonb)")
            .bind(serde_json::to_string(&request.attempt).unwrap())
            .execute(&mut *tx)
            .await;
        assert!(result.is_err());
        tx.rollback().await.unwrap();
    }
    let before = snapshot(&admin, &request).await;
    let unavailable = PolicyFactReader::new(admin.clone(), verifier.clone())
        .retirement_preflight(&request)
        .await
        .unwrap();
    assert!(matches!(
        unavailable.result(),
        FactRetirementPreflightResult::Unavailable {}
    ));
    // Correct scope with no source is an explicit blocker, never a positive
    // result inferred from an empty table, absent attempt or broken connection.
    let reader = PolicyFactReader::new(reader_pool.clone(), verifier.clone());
    blocked(
        &reader.retirement_preflight(&request).await.unwrap(),
        RetirementRejection::SourceChanged,
    );
    // Exercise the actual mounted protocol with configured database and public
    // trust, including rejected caller authority. No internal source is mocked.
    use std::io::Write;
    use std::process::{Command, Stdio};
    let public_key = std::env::var_os("OPENPC_TEST_ROOT")
        .or_else(|| std::env::var_os("OPENPC_TEST_TMP_ROOT"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("retirement-preflight-{}.sec1", Uuid::now_v7()));
    fs::write(&public_key, verifier.sec1_bytes()).unwrap();
    let invoke = |input: &[u8]| {
        let mut child = Command::new(std::env::var("OPENPC_POLICY_FACT_READER_BIN").unwrap())
            .arg("--retirement-preflight")
            .env("POLICY_FACT_VERIFY_KEY_FILE", &public_key)
            .env(
                "POLICY_FACT_VERIFY_KEY_ID",
                format!("sha256:{}", "5d".repeat(32)),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    };
    let output = invoke(&serde_json::to_vec(&request).unwrap());
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["identity"], "OPENPC-FACT-RETIREMENT-PREFLIGHT-1");
    assert_eq!(value["authority"], "ADVISORY_ONLY");
    assert_eq!(
        value["attemptDigest"],
        serde_json::to_value(request.attempt.digest().unwrap()).unwrap()
    );
    assert_eq!(
        value["selectionDigest"],
        serde_json::to_value(&request.attempt.selection_digest).unwrap()
    );
    assert_eq!(
        value["result"],
        serde_json::json!({"state":"BLOCKED","blocker":"SOURCE_CHANGED"})
    );
    let mut forged = serde_json::to_value(&request).unwrap();
    forged["eligible"] = true.into();
    for input in [b"{}".to_vec(), serde_json::to_vec(&forged).unwrap()] {
        let output = invoke(&input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    fs::remove_file(public_key).unwrap();
    let wrong_store = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            reader_pool
                .connect_options()
                .as_ref()
                .clone()
                .database("postgres"),
        )
        .await
        .unwrap();
    assert!(matches!(
        PolicyFactReader::new(wrong_store, verifier.clone())
            .retirement_preflight(&request)
            .await
            .unwrap()
            .result(),
        FactRetirementPreflightResult::Unavailable {}
    ));
    let writer = pool("DATABASE_URL").await;
    assert!(matches!(
        PolicyFactReader::new(writer, verifier)
            .retirement_preflight(&request)
            .await
            .unwrap()
            .result(),
        FactRetirementPreflightResult::Unavailable {}
    ));
    assert_eq!(before, snapshot(&admin, &request).await);
}
