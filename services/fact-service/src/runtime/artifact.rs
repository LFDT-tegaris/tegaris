//! Canonical Fact Artifact semantics behind the authenticated Control API hop.
//! Public session authorization belongs to that existing boundary; this hop
//! requires its private token and independently scoped owner headers.
use super::*;
use axum::extract::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    page: String,
}

fn owner<'a>(
    state: &RuntimeState,
    headers: &'a HeaderMap,
    action: &str,
    digest: Option<&str>,
) -> Result<(&'a str, &'a str, Uuid), Box<Response>> {
    if !authorized(headers, &state.internal_token) {
        return Err(Box::new(forbidden()));
    }
    let Some((request, correlation)) = valid_owner_headers(headers, state.scope(), action, digest)
    else {
        return Err(Box::new(problem(ProblemKind::InvalidParams)));
    };
    let principal = header(headers, "x-openpc-principal-id")
        .and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| v.get_version_num() == 7)
        .ok_or_else(|| Box::new(problem(ProblemKind::InvalidParams)))?;
    Ok((request, correlation, principal))
}

pub(super) async fn list(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    query: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(response) = owner(
        &state,
        &headers,
        "ACT-FACT_ARTIFACTS_READ_COLLECTION-V1",
        Some(DOWNSTREAM_READ_DIGEST),
    ) {
        return *response;
    }
    let Ok(Query(query)) = query else {
        return problem(ProblemKind::InvalidParams);
    };
    if query.page.len() > 8192 {
        return problem(ProblemKind::InvalidParams);
    }
    let Ok(page) = serde_json::from_str::<crate::ArtifactPageRequest>(&query.page) else {
        return problem(ProblemKind::InvalidParams);
    };
    let (participant, privacy) = state.scope();
    match state
        .store
        .artifact_page(
            &participant.to_string(),
            &privacy.to_string(),
            &page,
            &state.signer.verifier(),
        )
        .await
    {
        Ok(page) => Json(page).into_response(),
        Err(crate::FactStoreError::SequenceRace) => problem(ProblemKind::StaleEtag),
        Err(crate::FactStoreError::Feed) => problem(ProblemKind::InvalidParams),
        Err(_) => unavailable(),
    }
}

// The canonical resource read supplies the exact candidate selection ETag used
// by PATCH. A candidate preview is never presented as signed readiness.
pub(super) async fn get(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (request, _, _) = match owner(
        &state,
        &headers,
        "ACT-FACT_ARTIFACTS_READ_RESOURCE-V1",
        None,
    ) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(candidate_id) = candidate(&id) else {
        return problem(ProblemKind::InvalidParams);
    };
    let (participant, privacy) = state.scope();
    let page = crate::ArtifactPageRequest {
        limit: 1,
        filter: Some(crate::ArtifactFilter {
            field: "factArtifactId".into(),
            operator: "eq".into(),
            value: id.clone(),
        }),
        sort: "updatedAt".into(),
        snapshot_at: "9999-01-01T00:00:00.000000Z".into(),
        snapshot_revision: "1".into(),
        after: None,
    };
    let existing = match state
        .store
        .artifact_page(
            &participant.to_string(),
            &privacy.to_string(),
            &page,
            &state.signer.verifier(),
        )
        .await
    {
        Ok(page) => page.items.into_iter().next(),
        Err(_) => return unavailable(),
    };
    let selection = if let Some(bridge) = &state.bridge {
        let scope =
            CandidateReadScope::new(participant, privacy, Uuid::parse_str(request).unwrap())
                .expect("validated scope");
        match bridge.select_artifact(scope, candidate_id).await {
            Ok(value) => value,
            // Retained local evidence remains readable after its acquisition
            // source withdraws. Its content ETag cannot authorize a new input.
            Err(_) if existing.is_some() => None,
            Err(error) => return candidate_problem(error),
        }
    } else {
        None
    };
    let etag = selection.as_ref().map(|v| v.etag.clone());
    let artifact = if let Some(value) = existing {
        value
    } else if let Some(selected) = selection {
        let Ok(observed) = pc_facts_core::fact_timestamp_from_ms(selected.observed_at_ms) else {
            return unavailable();
        };
        crate::FactArtifact {
            fact_artifact_id: id,
            participant_id: format!("urn:openpc:participant:{participant}"),
            privacy_domain_id: format!("urn:openpc:privacy-domain:{privacy}"),
            artifact_digest: format!("sha256:{}", selected.payload_digest.as_str()),
            authority_generation: format!(
                "sha256:{}",
                selected
                    .configuration_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&selected.configuration_digest)
            ),
            state: "CANDIDATE".into(),
            source_neutral: true,
            revision: selected.candidate_sequence,
            created_at: observed.clone(),
            updated_at: observed,
        }
    } else {
        return problem(ProblemKind::Hidden);
    };
    let etag = etag.unwrap_or_else(|| {
        format!(
            "\"sha256:{}\"",
            hex(&sha256(&serde_json::to_vec(&artifact).expect("artifact")))
        )
    });
    ([("etag", etag)], Json(artifact)).into_response()
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Update {
    action_intent_id: String,
    action_intent_digest: String,
    expected_revision: String,
    replacement_digest: String,
    reason: String,
}
fn candidate(value: &str) -> Option<Uuid> {
    value
        .strip_prefix("urn:openpc:resource:")
        .and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| v.get_version_num() == 7)
}

pub(super) async fn update(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<Update>, JsonRejection>,
) -> Response {
    let (request_id, _, principal) = match owner(
        &state,
        &headers,
        DOWNSTREAM_ACTION_INTENT,
        Some(DOWNSTREAM_ACTION_DIGEST),
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let (Some(candidate), Ok(Json(body)), Some(key), Some(etag)) = (
        candidate(&id),
        payload,
        header(&headers, "idempotency-key"),
        header(&headers, "if-match"),
    ) else {
        return problem(ProblemKind::InvalidParams);
    };
    if body.action_intent_id != DOWNSTREAM_ACTION_INTENT
        || body.action_intent_digest != DOWNSTREAM_ACTION_DIGEST
        || body.reason.is_empty()
        || body.reason.len() > 1024
        || !quoted_sha_etag(etag)
        || body.replacement_digest.len() != 71
        || !body.replacement_digest.starts_with("sha256:")
    {
        return problem(ProblemKind::InvalidParams);
    }
    let binding = crate::FactOperationBinding {
        operation_id: Uuid::now_v7(),
        principal_id: principal,
        candidate_id: candidate,
        idempotency_key: key.into(),
        expected_revision: body.expected_revision.clone(),
        input_digest: format!(
            "sha256:{}",
            hex(&sha256(
                &serde_json::to_vec(&(id.as_str(), &body, etag)).expect("bounded command")
            ))
        ),
    };
    if !binding.valid() {
        return problem(ProblemKind::InvalidParams);
    }
    let (participant, privacy) = state.scope();
    let participant_text = participant.to_string();
    let privacy_text = privacy.to_string();
    let read = || {
        state.store.admission_operation(
            &participant_text,
            &privacy_text,
            principal,
            None,
            Some(key),
            Some(&binding),
        )
    };
    // Operation replay needs current public authorization, not reconstruction
    // of historical acquisition authority or a second provider observation.
    match read().await {
        Ok(Some(operation)) => {
            if operation.state == "SUCCEEDED" {
                publish(&state, candidate, request_id).await;
            }
            return (StatusCode::ACCEPTED, Json(operation)).into_response();
        }
        Err(crate::FactStoreError::ReplayDigestMismatch) => {
            return problem(ProblemKind::ReplayRejected);
        }
        Err(_) => return unavailable(),
        Ok(None) => {}
    }
    let Some(bridge) = &state.bridge else {
        return unavailable();
    };
    let scope = || {
        CandidateReadScope::new(participant, privacy, Uuid::parse_str(request_id).unwrap())
            .expect("validated scope")
    };
    let selection = match bridge.select_artifact(scope(), candidate).await {
        Ok(Some(value)) => value,
        Ok(None) => return problem(ProblemKind::Hidden),
        Err(error) => return candidate_problem(error),
    };
    if body.expected_revision != selection.candidate_sequence
        || etag != selection.etag
        || body.replacement_digest != format!("sha256:{}", selection.payload_digest.as_str())
    {
        return problem(ProblemKind::StaleEtag);
    }
    let result = bridge
        .consume_with_operation(
            scope(),
            selection.partition_id,
            selection
                .candidate_sequence
                .parse()
                .expect("candidate sequence"),
            &state.store,
            &state.signer,
            Some(&binding),
        )
        .await;
    if let Err(error) = result {
        // Typed owner codes carry no credentials, provider bodies or SQL text.
        let code = match &error {
            crate::admission::StateAdmissionError::Workload(error) => error.to_string(),
            crate::admission::StateAdmissionError::Source(error) => error.to_string(),
            crate::admission::StateAdmissionError::Candidate(error) => error.to_string(),
            crate::admission::StateAdmissionError::Store(error) => match error {
                crate::FactStoreError::Database(error) => format!(
                    "FACT-STORE-DATABASE-{}",
                    error
                        .as_database_error()
                        .and_then(|error| error.code())
                        .as_deref()
                        .unwrap_or("UNAVAILABLE")
                ),
                crate::FactStoreError::Validation(_) => "FACT-STORE-VALIDATION".into(),
                crate::FactStoreError::Signing(_) => "FACT-STORE-SIGNING".into(),
                crate::FactStoreError::ReplayDigestMismatch => "FACT-STORE-REPLAY".into(),
                crate::FactStoreError::SequenceRace => "FACT-STORE-SEQUENCE".into(),
                crate::FactStoreError::Lifecycle => "FACT-STORE-LIFECYCLE".into(),
                crate::FactStoreError::Feed => "FACT-STORE-FEED".into(),
                crate::FactStoreError::Replacement => "FACT-STORE-REPLACEMENT".into(),
                crate::FactStoreError::Publication(_) => "FACT-STORE-PUBLICATION".into(),
            },
        };
        eprintln!(
            "{}",
            serde_json::json!({"level":"warn","event":"fact_public_admission_denied","code":code})
        );
        return match error {
            crate::admission::StateAdmissionError::Store(
                crate::FactStoreError::ReplayDigestMismatch | crate::FactStoreError::SequenceRace,
            ) => problem(ProblemKind::ReplayRejected),
            crate::admission::StateAdmissionError::Candidate(error) => candidate_problem(error),
            crate::admission::StateAdmissionError::Workload(
                crate::workload_authority::WorkloadAuthorityError::Database(_),
            )
            | crate::admission::StateAdmissionError::Source(
                crate::source_authority::SourceAuthorityError::Database(_)
                | crate::source_authority::SourceAuthorityError::Workload(
                    crate::workload_authority::WorkloadAuthorityError::Database(_),
                ),
            ) => unavailable(),
            crate::admission::StateAdmissionError::Workload(_)
            | crate::admission::StateAdmissionError::Source(_) => problem(ProblemKind::Hidden),
            _ => unavailable(),
        };
    }
    publish(&state, candidate, request_id).await;
    match read().await {
        Ok(Some(operation)) => (StatusCode::ACCEPTED, Json(operation)).into_response(),
        _ => unavailable(),
    }
}

async fn publish(state: &RuntimeState, candidate: Uuid, request_id: &str) {
    let Some(bridge) = &state.bridge else { return };
    let (participant, privacy) = state.scope();
    let scope = CandidateReadScope::new(participant, privacy, Uuid::parse_str(request_id).unwrap())
        .expect("validated scope");
    if bridge
        .publish(scope, candidate, &state.store, &state.signer)
        .await
        .is_err()
    {
        eprintln!("{{\"level\":\"warn\",\"event\":\"fact_shard_publication_deferred\"}}");
    }
}

pub(super) async fn operation(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let (_, _, principal) = match owner(&state, &headers, "ACT-OPERATIONS_READ_OPERATION-V1", None)
    {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (participant, privacy) = state.scope();
    match state
        .store
        .admission_operation(
            &participant.to_string(),
            &privacy.to_string(),
            principal,
            Some(id),
            None,
            None,
        )
        .await
    {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => problem(ProblemKind::Hidden),
        Err(_) => unavailable(),
    }
}
