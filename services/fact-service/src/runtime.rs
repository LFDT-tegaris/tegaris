use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    candidate_feed::CandidateReadScope,
    deployment::{CandidateSelection, DeployedFactBridge},
};
use axum::{
    Json, Router,
    extract::{Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pc_facts_core::sha256;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::{FactStore, PurposeBoundFactSigner};

pub const PARTICIPANT_ID: &str = "018f0000-0000-7000-8000-000000000101";
pub const PRIVACY_DOMAIN_ID: &str = "018f0000-0000-7000-8000-000000000201";
const UI_ACTION_INTENT: &str = "ACT-UI_FACT_SOURCE_PROJECTION_BRIDGE_QUALIFY_ADMIT-V1";
const UI_ACTION_DIGEST: &str =
    "sha256:2da81e172788f4fc9d713b9579c40d5fc1f0a8ea29dc79a4b6d2f386913afc3b";
const DOWNSTREAM_ACTION_INTENT: &str = "ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1";
const DOWNSTREAM_ACTION_DIGEST: &str =
    "sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a";
const DOWNSTREAM_READ_DIGEST: &str =
    "sha256:a671fa20f95424230312b71c2c6e9198f9add32f0c7f874d216f2ad1b7c7c452";
const TARGET_REF: &str = "urn:openpc:ui-process:6ac3e161-8930-7329-b132-946785fe269b";

#[derive(Clone)]
pub struct RuntimeConfig {
    pub database_host: String,
    pub database_port: u16,
    pub database_name: String,
    pub database_user: String,
    pub database_password: String,
    pub capability_secret: [u8; 32],
    pub signing_secret: [u8; 32],
    pub internal_token: String,
    pub listen: SocketAddr,
    pub bridge_configuration: Option<PathBuf>,
}

impl RuntimeConfig {
    pub fn from_env() -> Result<Self, String> {
        let allowed = BTreeSet::from([
            "OPENPC_FACT_DATABASE_HOST",
            "OPENPC_FACT_DATABASE_PORT",
            "OPENPC_FACT_DATABASE_NAME",
            "OPENPC_FACT_DATABASE_USER",
            "OPENPC_FACT_DATABASE_PASSWORD_FILE",
            "OPENPC_FACT_CAPABILITY_SECRET_FILE",
            "OPENPC_FACT_SIGNING_SECRET_FILE",
            "OPENPC_FACT_INTERNAL_TOKEN_FILE",
            "OPENPC_FACT_LISTEN",
            "OPENPC_FACT_BRIDGE_CONFIGURATION_FILE",
            "OPENPC_LOCAL_RUNTIME",
        ]);
        reject_unknown_fact_keys(std::env::vars().map(|(key, _)| key), &allowed)?;
        if std::env::var("OPENPC_LOCAL_RUNTIME").as_deref() != Ok("1") {
            return Err("OPENPC_LOCAL_RUNTIME=1 is required".into());
        }
        let required = |key: &str| std::env::var(key).map_err(|_| format!("{key} is required"));
        let database_host = required("OPENPC_FACT_DATABASE_HOST")?;
        let database_port = required("OPENPC_FACT_DATABASE_PORT")?
            .parse::<u16>()
            .map_err(|_| "OPENPC_FACT_DATABASE_PORT is invalid".to_string())?;
        let database_name = identifier(&required("OPENPC_FACT_DATABASE_NAME")?)?;
        let database_user = identifier(&required("OPENPC_FACT_DATABASE_USER")?)?;
        let database_password = read_token(&required("OPENPC_FACT_DATABASE_PASSWORD_FILE")?)?;
        let capability_secret = read_hex_secret(&required("OPENPC_FACT_CAPABILITY_SECRET_FILE")?)?;
        let signing_secret = read_hex_secret(&required("OPENPC_FACT_SIGNING_SECRET_FILE")?)?;
        let internal_token = read_token(&required("OPENPC_FACT_INTERNAL_TOKEN_FILE")?)?;
        let listen = required("OPENPC_FACT_LISTEN")?
            .parse()
            .map_err(|_| "OPENPC_FACT_LISTEN must be a socket address".to_string())?;
        Ok(Self {
            database_host,
            database_port,
            database_name,
            database_user,
            database_password,
            capability_secret,
            signing_secret,
            internal_token,
            listen,
            bridge_configuration: std::env::var_os("OPENPC_FACT_BRIDGE_CONFIGURATION_FILE")
                .map(PathBuf::from),
        })
    }
}

fn reject_unknown_fact_keys(
    keys: impl IntoIterator<Item = String>,
    allowed: &BTreeSet<&str>,
) -> Result<(), String> {
    for key in keys {
        if key.starts_with("OPENPC_FACT_") && !allowed.contains(key.as_str()) {
            return Err(format!("unknown fact runtime variable: {key}"));
        }
    }
    Ok(())
}

fn identifier(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("fact database identifier is invalid".into());
    }
    Ok(value.into())
}

fn read_hex_secret(path: &str) -> Result<[u8; 32], String> {
    let encoded = fs::read_to_string(Path::new(path))
        .map_err(|_| "fact secret file is unavailable".to_string())?;
    let encoded = encoded.trim();
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("fact secret must contain exactly 32 hex-encoded bytes".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| "fact secret is not hexadecimal".to_string())?;
    }
    Ok(bytes)
}

fn read_token(path: &str) -> Result<String, String> {
    let token = fs::read_to_string(Path::new(path))
        .map_err(|_| "internal token file is unavailable".to_string())?;
    let token = token.trim();
    if token.len() < 32 || token.len() > 256 || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("internal token is invalid".into());
    }
    Ok(token.into())
}

#[derive(Clone)]
pub struct RuntimeState {
    pool: PgPool,
    store: FactStore,
    signer: PurposeBoundFactSigner,
    internal_token: String,
    bridge: Option<Arc<DeployedFactBridge>>,
}

impl RuntimeState {
    pub async fn connect(config: &RuntimeConfig) -> Result<Self, String> {
        let options = sqlx::postgres::PgConnectOptions::new()
            .host(&config.database_host)
            .port(config.database_port)
            .database(&config.database_name)
            .username(&config.database_user)
            .password(&config.database_password);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|_| "fact database unavailable".to_string())?;
        let signer = PurposeBoundFactSigner::for_local_runtime(config.signing_secret)
            .map_err(|_| "fact signing secret is invalid".to_string())?;
        Ok(Self {
            store: FactStore::new(pool.clone(), config.capability_secret),
            pool,
            signer,
            internal_token: config.internal_token.clone(),
            bridge: match &config.bridge_configuration {
                Some(path) => Some(Arc::new(DeployedFactBridge::connect(path).await?)),
                None => None,
            },
        })
    }
}

impl RuntimeState {
    fn scope(&self) -> (Uuid, Uuid) {
        self.bridge.as_ref().map_or_else(
            || {
                (
                    Uuid::parse_str(PARTICIPANT_ID).expect("local participant"),
                    Uuid::parse_str(PRIVACY_DOMAIN_ID).expect("local privacy"),
                )
            },
            |bridge| bridge.scope(),
        )
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectionRequest {
    partition_id: Uuid,
    candidate_sequence: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectionQuery {
    candidate_id: Option<Uuid>,
    partition_id: Option<Uuid>,
    candidate_sequence: Option<String>,
}
impl SelectionRequest {
    fn sequence(&self) -> Option<u64> {
        let sequence = self.candidate_sequence.parse::<u64>().ok()?;
        (self.partition_id.get_version_num() == 7
            && sequence > 0
            && sequence.to_string() == self.candidate_sequence)
            .then_some(sequence)
    }
}

mod artifact;

pub fn router(state: RuntimeState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/fact-artifacts", get(artifact::list))
        .route(
            "/api/v1/fact-artifacts/{id}",
            get(artifact::get).patch(artifact::update),
        )
        .route("/api/v1/operations/{id}", get(artifact::operation))
        .route("/readyz", get(ready))
        .route(
            "/internal/v1/fact-source-projection-bridge",
            get(projection),
        )
        .route(
            "/internal/v1/fact-source-projection-bridge/actions/qualify-admit",
            post(admit),
        )
        .with_state(state)
}

async fn health() -> Json<Status> {
    Json(Status { status: "ok" })
}

async fn ready(State(state): State<RuntimeState>) -> Response {
    if state
        .bridge
        .as_ref()
        .is_some_and(|bridge| bridge.candidate_connections_closed())
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Status {
                status: "unavailable",
            }),
        )
            .into_response();
    }
    match sqlx::query_scalar::<_, Option<String>>(
        "SELECT to_regclass('facts.canonical_fact')::text",
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(Some(_)) => Json(Status { status: "ready" }).into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Status {
                status: "unavailable",
            }),
        )
            .into_response(),
    }
}

async fn projection(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    query: Result<Query<ProjectionQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if !authorized(&headers, &state.internal_token) {
        return forbidden();
    }
    let Some((request_id, correlation_id)) = valid_owner_headers(
        &headers,
        state.scope(),
        "ACT-FACT_ARTIFACTS_READ_COLLECTION-V1",
        Some(DOWNSTREAM_READ_DIGEST),
    ) else {
        return problem(ProblemKind::InvalidParams);
    };
    let (participant, privacy) = state.scope();
    let Ok(Query(query)) = query else {
        return problem(ProblemKind::InvalidParams);
    };
    if query
        .candidate_id
        .is_some_and(|id| id.get_version_num() != 7)
        || (query.candidate_id.is_some()
            && (query.partition_id.is_some() || query.candidate_sequence.is_some()))
    {
        return problem(ProblemKind::InvalidParams);
    }
    let selection = if query.partition_id.is_some() || query.candidate_sequence.is_some() {
        let (Some(partition_id), Some(candidate_sequence)) =
            (query.partition_id, query.candidate_sequence)
        else {
            return problem(ProblemKind::InvalidParams);
        };
        let query = SelectionRequest {
            partition_id,
            candidate_sequence,
        };
        let Some(sequence) = query.sequence() else {
            return problem(ProblemKind::InvalidParams);
        };
        let Some(bridge) = &state.bridge else {
            return unavailable();
        };
        let scope = CandidateReadScope::new(
            participant,
            privacy,
            Uuid::parse_str(request_id).expect("validated request"),
        );
        match bridge
            .select_candidate(
                scope.expect("configured scope"),
                query.partition_id,
                sequence,
            )
            .await
        {
            Ok(value) => Some(value),
            Err(error) => return candidate_problem(error),
        }
    } else {
        None
    };
    match state
        .store
        .projection(&participant.to_string(), &privacy.to_string())
        .await
    {
        Ok(value) => {
            let mut etag = selection
                .as_ref()
                .map(|v| v.etag.clone())
                .unwrap_or_else(|| {
                    quoted_digest(&[
                        "openpc:fact-projection:v2",
                        &participant.to_string(),
                        &privacy.to_string(),
                        &value.fact_count.to_string(),
                        value.latest_candidate_id.as_deref().unwrap_or(""),
                        value.latest_state.as_deref().unwrap_or(""),
                    ])
                });
            let candidate = query
                .candidate_id
                .or_else(|| selection.as_ref().map(|v| v.candidate_id));
            let receipt = if let Some(candidate) = candidate {
                match state
                    .store
                    .admission_readback(participant, privacy, candidate)
                    .await
                {
                    Ok(None) if query.candidate_id.is_some() => {
                        return problem(ProblemKind::Hidden);
                    }
                    Ok(receipt) => receipt,
                    Err(_) => return unavailable(),
                }
            } else {
                None
            };
            if let Some(receipt) = &receipt
                && query.candidate_id.is_some()
            {
                etag = quoted_digest(&[
                    "openpc:fact-receipt-readback:v1",
                    &receipt.candidate_id,
                    &receipt.receipt_digest,
                    &receipt.state,
                ]);
            }
            let resource_ref = candidate
                .map(|id| format!("urn:openpc:resource:{id}"))
                .or_else(|| {
                    value
                        .latest_candidate_id
                        .as_ref()
                        .map(|id| format!("urn:openpc:resource:{id}"))
                });
            Json(OwnerProjection {
                fact_count: value.fact_count,
                latest_candidate_id: value.latest_candidate_id,
                latest_state: value.latest_state,
                observed_at_ms: value.latest_observed_at_ms,
                resource_ref,
                etag,
                selection,
                receipt,
                request_id: request_id.into(),
                correlation_id: correlation_id.into(),
            })
            .into_response()
        }
        Err(error) => {
            log_store_failure("fact_projection_failed", &error);
            unavailable()
        }
    }
}

async fn admit(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    payload: Result<Json<OwnerCommand>, JsonRejection>,
) -> Response {
    if !authorized(&headers, &state.internal_token) {
        return forbidden();
    }
    let Ok(Json(command)) = payload else {
        return problem(ProblemKind::InvalidParams);
    };
    let Some((request_id, correlation_id)) = valid_owner_headers(
        &headers,
        state.scope(),
        DOWNSTREAM_ACTION_INTENT,
        Some(DOWNSTREAM_ACTION_DIGEST),
    ) else {
        return problem(ProblemKind::InvalidParams);
    };
    let Some(selection_request) =
        valid_command(&command, request_id, correlation_id, state.scope())
    else {
        return problem(ProblemKind::InvalidParams);
    };
    if header(&headers, "idempotency-key") != Some(command.idempotency_key.as_str())
        || header(&headers, "if-match") != Some(command.etag.as_str())
        || !quoted_sha_etag(&command.etag)
    {
        return problem(ProblemKind::InvalidParams);
    }
    let Some(bridge) = &state.bridge else {
        return unavailable();
    };
    let (participant, privacy) = state.scope();
    let scope = || {
        CandidateReadScope::new(
            participant,
            privacy,
            Uuid::parse_str(request_id).expect("validated request"),
        )
        .expect("configured scope")
    };
    let sequence = selection_request.sequence().expect("validated selection");
    let selection = match bridge
        .select_candidate(scope(), selection_request.partition_id, sequence)
        .await
    {
        Ok(value) => value,
        Err(error) => return candidate_problem(error),
    };
    if command.resource_ref != format!("urn:openpc:resource:{}", selection.candidate_id)
        || command.etag != selection.etag
    {
        return problem(ProblemKind::StaleEtag);
    }
    match bridge
        .consume(
            scope(),
            selection.partition_id,
            sequence,
            &state.store,
            &state.signer,
        )
        .await
    {
        Ok(outcome) => {
            // The admission outcome describes the committed admission effect.
            // Publication is a separate retryable stage; SQL readback survives
            // an unavailable artifact store and eligibility stays fail-closed.
            if bridge
                .publish(scope(), selection.candidate_id, &state.store, &state.signer)
                .await
                .is_err()
            {
                eprintln!(r#"{{"level":"warn","event":"fact_shard_publication_deferred"}}"#);
            }
            match state
                .store
                .admission_readback(participant, privacy, selection.candidate_id)
                .await
            {
                Ok(Some(receipt)) => Json(OwnerResult {
                    outcome,
                    receipt,
                    etag: selection.etag,
                    request_id: request_id.into(),
                    correlation_id: correlation_id.into(),
                })
                .into_response(),
                _ => unavailable(),
            }
        }
        Err(
            crate::admission::StateAdmissionError::Workload(
                crate::workload_authority::WorkloadAuthorityError::Database(_),
            )
            | crate::admission::StateAdmissionError::Source(
                crate::source_authority::SourceAuthorityError::Database(_)
                | crate::source_authority::SourceAuthorityError::Workload(
                    crate::workload_authority::WorkloadAuthorityError::Database(_),
                ),
            ),
        ) => unavailable(),
        Err(crate::admission::StateAdmissionError::Workload(_)) => problem(ProblemKind::Hidden),
        Err(crate::admission::StateAdmissionError::Source(_)) => problem(ProblemKind::Hidden),
        Err(crate::admission::StateAdmissionError::Candidate(error)) => candidate_problem(error),
        Err(crate::admission::StateAdmissionError::Store(
            crate::FactStoreError::ReplayDigestMismatch | crate::FactStoreError::SequenceRace,
        )) => problem(ProblemKind::ReplayRejected),
        Err(crate::admission::StateAdmissionError::Store(crate::FactStoreError::Database(_))) => {
            unavailable()
        }
        Err(_) => problem(ProblemKind::AdmissionRejected),
    }
}

fn candidate_problem(error: crate::candidate_feed::CandidateFeedError) -> Response {
    match error {
        crate::candidate_feed::CandidateFeedError::Database(_) => unavailable(),
        _ => problem(ProblemKind::Hidden),
    }
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    header(headers, "authorization") == Some(&format!("Bearer {expected}"))
}

fn valid_owner_headers<'a>(
    headers: &'a HeaderMap,
    scope: (Uuid, Uuid),
    intent: &str,
    digest: Option<&str>,
) -> Option<(&'a str, &'a str)> {
    let request_id = header(headers, "x-request-id")?;
    let correlation_id = header(headers, "x-correlation-id")?;
    (header(headers, "openpc-api-version") == Some("1")
        && header(headers, "openpc-participant-id")
            == Some(format!("urn:openpc:participant:{}", scope.0).as_str())
        && header(headers, "openpc-privacy-domain-id")
            == Some(format!("urn:openpc:privacy-domain:{}", scope.1).as_str())
        && header(headers, "x-openpc-action-intent") == Some(intent)
        && digest.is_none_or(|value| header(headers, "openpc-action-intent-digest") == Some(value))
        && uuid_v7(request_id)
        && uuid_v7(correlation_id))
    .then_some((request_id, correlation_id))
}

fn uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
        })
}

fn quoted_sha_etag(value: &str) -> bool {
    value.len() == 73
        && value.starts_with("\"sha256:")
        && value.ends_with('"')
        && value[8..72]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_command(
    command: &OwnerCommand,
    request_id: &str,
    correlation_id: &str,
    scope: (Uuid, Uuid),
) -> Option<SelectionRequest> {
    if command.replacement_document.len() > 8192 {
        return None;
    }
    let selection: SelectionRequest = serde_json::from_str(&command.replacement_document).ok()?;
    selection.sequence()?;
    let candidate = command.resource_ref.strip_prefix("urn:openpc:resource:")?;
    (uuid_v7(candidate)
        && command.schema_version == "1.0"
        && command.ui_action_intent_id == UI_ACTION_INTENT
        && command.ui_action_intent_digest == UI_ACTION_DIGEST
        && command.downstream_action_intent_id == DOWNSTREAM_ACTION_INTENT
        && command.downstream_action_intent_digest == DOWNSTREAM_ACTION_DIGEST
        && command.expected_revision == selection.candidate_sequence
        && hex_digest_matches(
            command.replacement_document.as_bytes(),
            &command.replacement_digest,
        )
        && (1..=1024).contains(&command.reason.chars().count())
        && command.target_ref == TARGET_REF
        && command.participant_id == format!("urn:openpc:participant:{}", scope.0)
        && command.privacy_domain_id == format!("urn:openpc:privacy-domain:{}", scope.1)
        && command.idempotency_key == format!("fact-admission-{candidate}")
        && command.request_id == request_id
        && command.correlation_id == correlation_id)
        .then_some(selection)
}

fn hex_digest_matches(bytes: &[u8], claimed: &str) -> bool {
    claimed == format!("sha256:{}", hex(&sha256(bytes)))
}

fn framed_digest(values: &[&str]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for value in values {
        let value = value.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(value.len())
                .expect("bounded local value")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
    }
    sha256(&bytes)
}

fn quoted_digest(values: &[&str]) -> String {
    format!("\"sha256:{}\"", hex(&framed_digest(values)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}
fn forbidden() -> Response {
    problem(ProblemKind::Unauthenticated)
}
fn unavailable() -> Response {
    problem(ProblemKind::Unavailable)
}
fn log_store_failure(event: &'static str, error: &crate::FactStoreError) {
    eprintln!(
        "{}",
        serde_json::json!({
            "level": "error",
            "event": event,
            "classification": error.to_string(),
        })
    );
}
#[derive(Clone, Copy)]
enum ProblemKind {
    Unauthenticated,
    Hidden,
    InvalidParams,
    ReplayRejected,
    StaleEtag,
    Unavailable,
    AdmissionRejected,
}

fn problem(kind: ProblemKind) -> Response {
    let (status, code, truth_state, retryable, problem_type) = match kind {
        ProblemKind::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            "PC-AUTH-0001",
            "DENIED",
            false,
            "hidden-or-not-found",
        ),
        ProblemKind::Hidden => (
            StatusCode::NOT_FOUND,
            "PC-AUTH-0005",
            "DENIED",
            false,
            "hidden-or-not-found",
        ),
        ProblemKind::InvalidParams => (
            StatusCode::BAD_REQUEST,
            "PC-DATA-6004",
            "FAILED",
            false,
            "invalid-request",
        ),
        ProblemKind::ReplayRejected => (
            StatusCode::CONFLICT,
            "PC-RUNTIME-3007",
            "FAILED",
            false,
            "conflict",
        ),
        ProblemKind::StaleEtag => (
            StatusCode::PRECONDITION_FAILED,
            "PC-DATA-6007",
            "STALE",
            false,
            "stale",
        ),
        ProblemKind::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PC-INTEGRATION-5001",
            "UNAVAILABLE",
            true,
            "unavailable",
        ),
        ProblemKind::AdmissionRejected => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PC-RUNTIME-3010",
            "FAILED",
            false,
            "evidence-admission-failed",
        ),
    };
    (
        status,
        Json(Problem {
            r#type: format!("https://errors.openpc.local/{problem_type}"),
            code,
            status: status.as_u16(),
            title: "The requested process is unavailable.",
            truth_state,
            retryable,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct Status {
    status: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Problem {
    r#type: String,
    code: &'static str,
    status: u16,
    title: &'static str,
    truth_state: &'static str,
    retryable: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerCommand {
    schema_version: String,
    ui_action_intent_id: String,
    ui_action_intent_digest: String,
    downstream_action_intent_id: String,
    downstream_action_intent_digest: String,
    expected_revision: String,
    replacement_digest: String,
    replacement_document: String,
    reason: String,
    target_ref: String,
    resource_ref: String,
    participant_id: String,
    privacy_domain_id: String,
    idempotency_key: String,
    etag: String,
    request_id: String,
    correlation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerProjection {
    selection: Option<CandidateSelection>,
    receipt: Option<crate::FactAdmissionReadback>,
    fact_count: i64,
    latest_candidate_id: Option<String>,
    latest_state: Option<String>,
    observed_at_ms: Option<i64>,
    resource_ref: Option<String>,
    etag: String,
    request_id: String,
    correlation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerResult {
    outcome: crate::DurableAdmissionOutcome,
    receipt: crate::FactAdmissionReadback,
    etag: String,
    request_id: String,
    correlation_id: String,
}

pub async fn serve(config: RuntimeConfig) -> Result<(), String> {
    let state = RuntimeState::connect(&config).await?;
    // Reconcile populated upgrades before accepting newer admissions. Otherwise
    // a new event could overtake an older still-unmaterialized original event.
    if let Some(bridge) = &state.bridge {
        while !bridge
            .materialize_pending_admissions(&state.store, &state.signer)
            .await
            .map_err(|_| "fact admission delivery recovery unavailable".to_string())?
        {}
    }
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| "fact listen address unavailable".to_string())?;
    let maintenance = async {
        let mut failed = false;
        loop {
            if let Some(bridge) = &state.bridge {
                let result = bridge
                    .reconcile_source_withdrawals(&state.store, &state.signer)
                    .await;
                if result.is_err() && !failed {
                    eprintln!(r#"{{"level":"warn","event":"fact_source_withdrawal_pending"}}"#);
                }
                failed = result.is_err();
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    };
    // Historical custody lag must not delay current source withdrawal fences.
    let delivery = async {
        let mut failed = false;
        let mut fleet_failed = false;
        let mut producer_failed = false;
        loop {
            if let Some(bridge) = &state.bridge {
                let result = bridge
                    .reconcile_control_deliveries(&state.store, &state.signer)
                    .await;
                if result.is_err() && !failed {
                    eprintln!(r#"{{"level":"warn","event":"fact_control_custody_ack_pending"}}"#);
                }
                failed = result.is_err();
                let fleet_result = bridge
                    .reconcile_fleet_deliveries(&state.store, &state.signer)
                    .await;
                if fleet_result.is_err() && !fleet_failed {
                    eprintln!(r#"{{"level":"warn","event":"fact_fleet_admission_ack_pending"}}"#);
                }
                fleet_failed = fleet_result.is_err();
                let producer_result = bridge
                    .reconcile_producer_deliveries(&state.store, &state.signer)
                    .await;
                if producer_result.is_err() && !producer_failed {
                    eprintln!(r#"{{"level":"warn","event":"fact_producer_delivery_pending"}}"#);
                }
                producer_failed = producer_result.is_err();
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    };
    let secret_recipient = async {
        loop {
            if let Some(bridge) = &state.bridge {
                bridge
                    .check_candidate_secret_recipient()
                    .await
                    .map_err(|_| "fact secret recipient revoked".to_string())?;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    tokio::select! {
        result=async { axum::serve(listener,router(state.clone())).await } => result.map_err(|_|"fact server failed".to_string()),
        ()=maintenance => Err("fact maintenance stopped".into()),
        ()=delivery => Err("fact delivery reconciliation stopped".into()),
        result=secret_recipient => result,
    }
}

#[cfg(test)]
mod tests;
