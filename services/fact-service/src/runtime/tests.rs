use super::*;

mod installed;

#[test]
fn projection_query_requires_canonical_field_names() {
    let partition = Uuid::now_v7();
    let canonical = format!(
        "/internal/v1/fact-source-projection-bridge?partitionId={partition}&candidateSequence=1"
    );
    let Query(parsed) = Query::<ProjectionQuery>::try_from_uri(&canonical.parse().unwrap())
        .expect("the installed native consumer fixture must reach the actual query parser");
    assert_eq!(parsed.partition_id, Some(partition));
    assert_eq!(parsed.candidate_sequence.as_deref(), Some("1"));
    assert!(parsed.candidate_id.is_none());
    for query in [
        format!("partition_id={partition}&candidate_sequence=1"),
        format!("partitionId={partition}&candidateSequence=1&checked=true"),
    ] {
        let uri = format!("/internal/v1/fact-source-projection-bridge?{query}");
        assert!(Query::<ProjectionQuery>::try_from_uri(&uri.parse().unwrap()).is_err());
    }
}

fn scope() -> (Uuid, Uuid) {
    (
        Uuid::parse_str(PARTICIPANT_ID).unwrap(),
        Uuid::parse_str(PRIVACY_DOMAIN_ID).unwrap(),
    )
}

fn command(candidate: Uuid, partition: Uuid, request: Uuid) -> OwnerCommand {
    let document = serde_json::json!({"partitionId":partition,"candidateSequence":"1"}).to_string();
    OwnerCommand {
        schema_version: "1.0".into(),
        ui_action_intent_id: UI_ACTION_INTENT.into(),
        ui_action_intent_digest: UI_ACTION_DIGEST.into(),
        downstream_action_intent_id: DOWNSTREAM_ACTION_INTENT.into(),
        downstream_action_intent_digest: DOWNSTREAM_ACTION_DIGEST.into(),
        expected_revision: "1".into(),
        replacement_digest: format!("sha256:{}", hex(&sha256(document.as_bytes()))),
        replacement_document: document,
        reason: "Admit the independently verified acquired candidate.".into(),
        target_ref: TARGET_REF.into(),
        resource_ref: format!("urn:openpc:resource:{candidate}"),
        participant_id: format!("urn:openpc:participant:{}", scope().0),
        privacy_domain_id: format!("urn:openpc:privacy-domain:{}", scope().1),
        idempotency_key: format!("fact-admission-{candidate}"),
        etag: format!("\"sha256:{}\"", "ab".repeat(32)),
        request_id: request.to_string(),
        correlation_id: request.to_string(),
    }
}

#[test]
fn admission_commands_select_real_inputs_and_reject_caller_trust() {
    let request = Uuid::now_v7();
    let original = command(Uuid::now_v7(), Uuid::now_v7(), request);
    let valid = |command: &OwnerCommand| {
        valid_command(command, &request.to_string(), &request.to_string(), scope()).is_some()
    };
    assert!(valid(&original));
    macro_rules! rejected {
        ($field:ident,$value:expr) => {{
            let mut changed = original.clone();
            changed.$field = $value.into();
            assert!(!valid(&changed));
        }};
    }
    rejected!(schema_version, "2.0");
    rejected!(ui_action_intent_id, DOWNSTREAM_ACTION_INTENT);
    rejected!(ui_action_intent_digest, DOWNSTREAM_ACTION_DIGEST);
    rejected!(downstream_action_intent_id, UI_ACTION_INTENT);
    rejected!(downstream_action_intent_digest, UI_ACTION_DIGEST);
    rejected!(target_ref, TARGET_REF.replace("ui-process", "resource"));
    rejected!(
        resource_ref,
        "urn:openpc:participant:018f0000-0000-7000-8000-000000000501"
    );
    rejected!(reason, "");
    rejected!(request_id, Uuid::now_v7().to_string());
    rejected!(correlation_id, Uuid::now_v7().to_string());
    for field in [
        "profileActive",
        "semanticValid",
        "finalityAnchor",
        "observedAtMs",
        "provenance",
        "ready",
    ] {
        let mut changed = original.clone();
        let mut document: serde_json::Value =
            serde_json::from_str(&changed.replacement_document).unwrap();
        document[field] = serde_json::json!(true);
        changed.replacement_document = document.to_string();
        changed.replacement_digest = format!(
            "sha256:{}",
            hex(&sha256(changed.replacement_document.as_bytes()))
        );
        assert!(!valid(&changed), "caller supplied {field}");
    }
    for document in [
        "{\"factType\":\"qualification\",\"state\":\"ADMITTED\"}",
        "{}",
    ] {
        let mut changed = original.clone();
        changed.replacement_document = document.into();
        changed.replacement_digest = format!("sha256:{}", hex(&sha256(document.as_bytes())));
        assert!(!valid(&changed));
    }
    let mut changed = original.clone();
    changed.participant_id = format!("urn:openpc:participant:{}", Uuid::now_v7());
    assert!(!valid(&changed));
    let mut changed = original.clone();
    changed.idempotency_key = "fact-admission-other".into();
    assert!(!valid(&changed));
    let mut changed = original.clone();
    changed.replacement_digest = format!("sha256:{}", "00".repeat(32));
    assert!(!valid(&changed));
    let mut changed = original;
    changed.expected_revision = "2".into();
    assert!(!valid(&changed));
}

#[test]
fn secret_and_transport_parsers_fail_closed() {
    let temporary =
        std::env::temp_dir().join(format!("openpc-fact-secret-test-{}", Uuid::now_v7()));
    fs::write(&temporary, "aa").unwrap();
    assert!(read_hex_secret(temporary.to_str().unwrap()).is_err());
    fs::write(&temporary, "x".repeat(32)).unwrap();
    assert!(read_token(temporary.to_str().unwrap()).is_ok());
    fs::remove_file(&temporary).unwrap();
    assert!(read_token(temporary.to_str().unwrap()).is_err());
    assert!(identifier("fact_store").is_ok());
    assert!(identifier("fact-store").is_err());
    let allowed = BTreeSet::from(["OPENPC_FACT_LISTEN"]);
    assert!(reject_unknown_fact_keys(["OPENPC_FACT_UNKNOWN".into()], &allowed).is_err());
    assert!(!uuid_v7("018f0000-0000-4000-8000-000000000501"));
    assert!(!quoted_sha_etag("sha256:abc"));
    assert_eq!(problem(ProblemKind::Unauthenticated).status(), 401);
    assert_eq!(problem(ProblemKind::Hidden).status(), 404);
    assert_eq!(problem(ProblemKind::InvalidParams).status(), 400);
    assert_eq!(problem(ProblemKind::ReplayRejected).status(), 409);
    assert_eq!(problem(ProblemKind::StaleEtag).status(), 412);
    assert_eq!(problem(ProblemKind::Unavailable).status(), 503);
}

#[tokio::test]
async fn unavailable_candidate_owner_is_not_hidden_or_retryable_validation_failure() {
    let unavailable = candidate_problem(crate::candidate_feed::CandidateFeedError::Database(
        sqlx::Error::PoolClosed,
    ));
    let hidden = candidate_problem(crate::candidate_feed::CandidateFeedError::Material);
    for (response, code, retryable) in [
        (unavailable, "PC-INTEGRATION-5001", true),
        (hidden, "PC-AUTH-0005", false),
        (
            problem(ProblemKind::AdmissionRejected),
            "PC-RUNTIME-3010",
            false,
        ),
    ] {
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], code);
        assert_eq!(value["retryable"], retryable);
    }
}
