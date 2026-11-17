//! Actual HTTP over the retained real dual-store source. No candidate, grant,
//! approval, admission or readiness business state is manufactured here.
use super::*;
use serde_json::{Value, json};
use std::io::{Read, Write};

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: String,
    body: String,
) -> (u16, Value) {
    let wire = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    );
    tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream.write_all(wire.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap())
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires actual governed source/candidate/fact and live Identity/provider TLS"]
async fn retained_admission_http_uses_scoped_candidates_and_durable_receipts() {
    let input: Value = serde_json::from_slice(
        &fs::read(std::env::var("OPENPC_FACT_ADMISSION_TEST_INPUT_FILE").unwrap()).unwrap(),
    )
    .unwrap();
    let text = |key: &str| input[key].as_str().unwrap();
    let pool = PgPool::connect(
        fs::read_to_string(text("fact_database_url_file"))
            .unwrap()
            .trim(),
    )
    .await
    .unwrap();
    let store = FactStore::new(
        pool.clone(),
        read_hex_secret(text("capability_secret_file")).unwrap(),
    );
    let bridge = DeployedFactBridge::connect(Path::new(text("deployment_file")))
        .await
        .unwrap();
    let scope = bridge.scope();
    let partition = Uuid::parse_str(text("partition")).unwrap();
    let sequence = input["candidate_sequence"].as_u64().unwrap();
    let signer = PurposeBoundFactSigner::for_local_runtime(
        read_hex_secret(text("signing_secret_file")).unwrap(),
    )
    .unwrap();
    let token = format!("local-fact-http-test-{}", Uuid::now_v7());
    let state = RuntimeState {
        pool: pool.clone(),
        store: store.clone(),
        signer,
        internal_token: token.clone(),
        bridge: Some(Arc::new(bridge)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let request_id = Uuid::now_v7();
    let headers = |action: &str, digest: &str| {
        format!(
            "Authorization: Bearer {token}\r\nOpenPC-API-Version: 1\r\nOpenPC-Participant-ID: urn:openpc:participant:{}\r\nOpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:{}\r\nX-OpenPC-Action-Intent: {action}\r\nOpenPC-Action-Intent-Digest: {digest}\r\nX-Request-ID: {request_id}\r\nX-Correlation-ID: {request_id}\r\n",
            scope.0, scope.1
        )
    };
    let read_headers = headers(
        "ACT-FACT_ARTIFACTS_READ_COLLECTION-V1",
        DOWNSTREAM_READ_DIGEST,
    );
    let path = format!(
        "/internal/v1/fact-source-projection-bridge?partitionId={partition}&candidateSequence={sequence}"
    );
    assert_eq!(
        request(address, "GET", &path, String::new(), String::new())
            .await
            .0,
        401
    );
    let (status, preview) =
        request(address, "GET", &path, read_headers.clone(), String::new()).await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(
        preview["selection"]["authority"],
        "NON_AUTHORITATIVE_CANDIDATE"
    );
    let candidate = Uuid::parse_str(preview["selection"]["candidateId"].as_str().unwrap()).unwrap();
    let before = store
        .admission_readback(scope.0, scope.1, candidate)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.authority, "HISTORICAL_RECEIPT_ONLY");
    assert_eq!(before.partition_id, partition);
    assert_eq!(before.candidate_sequence, sequence.to_string());
    let historical = format!("/internal/v1/fact-source-projection-bridge?candidateId={candidate}");
    let (status, readback) = request(
        address,
        "GET",
        &historical,
        read_headers.clone(),
        String::new(),
    )
    .await;
    assert_eq!(status, 200, "{readback}");
    assert_eq!(readback["receipt"], serde_json::to_value(&before).unwrap());
    assert!(readback["selection"].is_null());
    assert_ne!(before.committed_at, "2026-01-01T00:00:00.000000Z");
    assert!(
        store
            .admission_readback(Uuid::now_v7(), scope.1, candidate)
            .await
            .unwrap()
            .is_none()
    );
    let foreign = read_headers.replace(&scope.1.to_string(), &Uuid::now_v7().to_string());
    assert_eq!(
        request(address, "GET", &path, foreign, String::new())
            .await
            .0,
        400
    );
    let mut command = super::command(candidate, partition, request_id);
    command.etag = preview["selection"]["etag"].as_str().unwrap().into();
    command.expected_revision = sequence.to_string();
    command.replacement_document =
        json!({"partitionId":partition,"candidateSequence":sequence.to_string()}).to_string();
    command.replacement_digest = format!(
        "sha256:{}",
        hex(&sha256(command.replacement_document.as_bytes()))
    );
    let command_headers = |command: &OwnerCommand| {
        format!(
            "{}Idempotency-Key: {}\r\nIf-Match: {}\r\n",
            headers(DOWNSTREAM_ACTION_INTENT, DOWNSTREAM_ACTION_DIGEST),
            command.idempotency_key,
            command.etag
        )
    };
    let action = "/internal/v1/fact-source-projection-bridge/actions/qualify-admit";
    let mut stale = command.clone();
    stale.etag = format!("\"sha256:{}\"", "00".repeat(32));
    assert_eq!(
        request(
            address,
            "POST",
            action,
            command_headers(&stale),
            serde_json::to_string(&stale).unwrap()
        )
        .await
        .0,
        412
    );
    let mut forged = serde_json::to_value(&command).unwrap();
    forged["profileActive"] = json!(true);
    assert_eq!(
        request(
            address,
            "POST",
            action,
            command_headers(&command),
            forged.to_string()
        )
        .await
        .0,
        400
    );
    let (status, result) = request(
        address,
        "POST",
        action,
        command_headers(&command),
        serde_json::to_string(&command).unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["outcome"], "IDEMPOTENT_REPLAY");
    assert!(result.get("operation").is_none());
    assert_eq!(result["receipt"], serde_json::to_value(&before).unwrap());
    assert_eq!(
        store
            .admission_readback(scope.0, scope.1, candidate)
            .await
            .unwrap()
            .unwrap(),
        before
    );
    server.abort();
    let _ = server.await;
    pool.close().await;
}
