//! Transport component regressions; the fixture is not runtime-owner acceptance.
use super::*;
use openpc_pds::IdentityAssertionEvidence;
use pc_runtime_types::{Digest, RequestClass, RuntimeRequest, Transport};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Owner(Arc<AtomicUsize>);
enum PendingResponse {
    Local(Vec<u8>),
    Write(Vec<u8>),
    Release(Arc<tokio::sync::Notify>, Vec<u8>),
}
struct Context(Arc<AtomicUsize>, Option<String>, Option<PendingResponse>);
impl LocalDecisionOwner for Context {
    fn acquire(
        &self,
        _: &RuntimeRequest,
    ) -> RuntimeResult<Box<dyn openpc_pds::LocalDecisionLease + '_>> {
        Err(RuntimeError::RuntimeUnavailable)
    }
}
impl ExtProcRequestOwner for Owner {
    fn begin(
        &self,
        _: &crate::WorkloadPeer,
        generation: &EnvoyGeneration,
        _: &[(String, Vec<u8>)],
        _: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        assert_eq!(generation.capsule_id(), "capsule-1");
        Ok(Box::new(Context(self.0.clone(), None, None)))
    }
    fn record_transport_denial(&self, _: &RuntimeError, _: &RequestTraceId) -> RuntimeResult<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
impl ProtectedRequest for Context {
    fn durable_write_response(&mut self) -> Option<RuntimeResult<Vec<u8>>> {
        match self.2.take() {
            Some(PendingResponse::Write(body)) => Some(Ok(body)),
            other => {
                self.2 = other;
                None
            }
        }
    }
    fn local_response(&mut self, _: &[u8]) -> RuntimeResult<Option<Vec<u8>>> {
        match self.2.take() {
            Some(PendingResponse::Local(body)) => Ok(Some(body)),
            other => {
                self.2 = other;
                Ok(None)
            }
        }
    }
    fn request_id(&self) -> Option<&str> {
        self.1.as_deref()
    }
    fn decision_owner(&self) -> &dyn LocalDecisionOwner {
        self
    }
    fn evaluation(&mut self, body: &[u8]) -> RuntimeResult<EvaluationInput> {
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "\"transport-component\"".into(),
            method: "eth_call".into(),
            params_digest: Digest::of(body),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Read,
            received_at_ms: 1,
            deadline_at_ms: 2,
            response_budget_bytes: 256,
            invocation: None,
        };
        request.request_digest = request.computed_digest()?;
        self.1 = Some(request.request_id.clone());
        Ok(EvaluationInput {
            request,
            identity_assertion: IdentityAssertionEvidence {
                payload_cbor: vec![],
                cose_sign1: vec![],
            },
        })
    }
    fn authorize(&mut self, _: &RuntimeDecision) -> RuntimeResult<String> {
        panic!("unconnected PDS must never authorize")
    }
    fn record_denial(&mut self, _: &RuntimeDecision, _: &RequestTraceId) -> RuntimeResult<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn response_headers(
        &mut self,
        _: &[(String, Vec<u8>)],
    ) -> RuntimeResult<Vec<(String, Vec<u8>)>> {
        Ok(vec![("content-type".into(), b"application/json".to_vec())])
    }
    fn release_response(&mut self, _: &[u8]) -> RuntimeResult<Vec<u8>> {
        Err(RuntimeError::ResponseWithheld)
    }
    fn prepare_release_response<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RuntimeResult<Vec<u8>>> + Send + 'a>>
    {
        Box::pin(async move {
            match self.2.take() {
                Some(PendingResponse::Release(resume, expected)) => {
                    assert_eq!(body, expected);
                    resume.notified().await;
                    self.0.fetch_add(1, Ordering::Relaxed);
                    Ok(expected)
                }
                other => {
                    self.2 = other;
                    self.release_response(body)
                }
            }
        })
    }
}

#[tokio::test]
async fn final_response_waits_for_its_owner_without_another_provider_handoff() {
    let (service, released) = service();
    let resume = Arc::new(tokio::sync::Notify::new());
    let body = br#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#.to_vec();
    let mut context: Option<Box<dyn ProtectedRequest>> = Some(Box::new(Context(
        released.clone(),
        Some("1".into()),
        Some(PendingResponse::Release(resume.clone(), body.clone())),
    )));
    let mut stage = 3;
    let generation = generation();
    let trace = RequestTraceId::new();
    let mut pending = Box::pin(service.process(
        request(RequestBody::ResponseBody(HttpBody {
            body: body.clone(),
            end_of_stream: true,
        })),
        &mut stage,
        &mut context,
        &generation,
        &trace,
    ));
    assert!(futures::poll!(&mut pending).is_pending());
    assert_eq!(released.load(Ordering::Relaxed), 0);
    resume.notify_one();
    let response = pending.await.unwrap();
    let Some(ResponseBody::ResponseBody(response)) = response.response else {
        panic!("final body must pass through its asynchronous owner")
    };
    assert_eq!(
        response
            .response
            .unwrap()
            .body_mutation
            .unwrap()
            .body
            .unwrap(),
        body
    );
    assert_eq!(stage, 4);
    assert_eq!(released.load(Ordering::Relaxed), 1);
}
fn service() -> (ExtProcService, Arc<AtomicUsize>) {
    let owner = Arc::new(Owner::default());
    let recorded = owner.0.clone();
    (
        ExtProcService::new(
            Arc::new(PolicyDecisionService::new([7; 32], 10).unwrap()),
            owner,
            ExtProcLimits {
                headers: 8,
                header_bytes: 8192,
                body_bytes: 256,
            },
        )
        .unwrap(),
        recorded,
    )
}

#[test]
fn public_denials_use_c17_meanings_closed_data_and_exact_json_rpc_ids() {
    for (local, public, rpc, http, truth) in [
        ("PC-RUNTIME-3003", "PC-RUNTIME-3001", -32001, 403, "DENIED"),
        ("PC-RUNTIME-3002", "PC-RUNTIME-3004", -32004, 412, "STALE"),
        ("PC-RUNTIME-3008", "PC-RUNTIME-3010", -32010, 503, "FAILED"),
        ("PC-RUNTIME-3010", "PC-DATA-6005", -32603, 500, "FAILED"),
        ("PC-RUNTIME-3006", "PC-RUNTIME-3007", -32007, 409, "FAILED"),
    ] {
        let error = RuntimeError::from_local_code(local).unwrap();
        for id in ["1", "\"1\"", "\"λ\""] {
            let trace = RequestTraceId::new();
            let response = denial_with_id(&error, Some(id), &trace);
            let Some(ResponseBody::Immediate(response)) = response.response else {
                panic!()
            };
            assert_eq!(response.status.unwrap().code, http);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body.as_object().unwrap().len(), 3);
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(
                body["id"],
                serde_json::from_str::<serde_json::Value>(id).unwrap()
            );
            assert_eq!(body["error"].as_object().unwrap().len(), 3);
            assert_eq!(body["error"]["code"], rpc);
            let data = &body["error"]["data"];
            assert_eq!(data.as_object().unwrap().len(), 6);
            assert_eq!(data["pcCode"], public);
            assert_eq!(data["truthState"], truth);
            assert_eq!(data["retryable"], false);
            assert_eq!(data["traceId"], trace.as_str());
            assert!(data["attemptId"].is_null());
            assert!(data["signedTransactionHash"].is_null());
            assert_eq!(
                uuid::Uuid::parse_str(data["traceId"].as_str().unwrap())
                    .unwrap()
                    .get_version_num(),
                7
            );
        }
    }
    for id in [
        None,
        Some("{\"provider\":\"private\"}"),
        Some("9007199254740992"),
        Some("false"),
    ] {
        let response = denial_with_id(&RuntimeError::Denied, id, &RequestTraceId::new());
        let Some(ResponseBody::Immediate(response)) = response.response else {
            panic!()
        };
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["id"].is_null());
        assert!(
            !String::from_utf8(response.body)
                .unwrap()
                .contains("private")
        );
    }
    assert!(RuntimeError::from_local_code("provider-private-detail").is_none());
}
fn request(body: RequestBody) -> ProcessingRequest {
    ProcessingRequest {
        observability_mode: false,
        request: Some(body),
    }
}
fn headers() -> HttpHeaders {
    HttpHeaders {
        headers: Some(HeaderMap {
            headers: vec![
                HeaderValue {
                    key: ":method".into(),
                    value: String::new(),
                    raw_value: b"POST".to_vec(),
                },
                HeaderValue {
                    key: "x-forwarded-client-cert".into(),
                    value: String::new(),
                    raw_value: crate::workload_peer::tests::forwarded().into_bytes(),
                },
            ],
        }),
        end_of_stream: false,
    }
}
#[tokio::test]
async fn unconnected_pds_denial_is_recorded_terminal_and_never_hands_off() {
    let (service, recorded) = service();
    let (mut stage, mut context) = (0, None);
    let response = service
        .process(
            request(RequestBody::RequestHeaders(headers())),
            &mut stage,
            &mut context,
            &generation(),
            &RequestTraceId::new(),
        )
        .await
        .unwrap();
    let Some(ResponseBody::RequestHeaders(response)) = response.response else {
        panic!()
    };
    let mutation = response.response.unwrap().header_mutation.unwrap();
    assert_eq!(mutation.remove_headers, ["x-openpc-runtime-capability"]);
    assert_eq!(mutation.set_headers.len(), 1);
    let path = &mutation.set_headers[0];
    assert_eq!(path.append_action, 2);
    let path = path.header.as_ref().unwrap();
    assert_eq!(path.key, ":path");
    assert!(path.value.is_empty());
    assert_eq!(path.raw_value, b"/openpc/broker/v1/dispatch");
    let response = service
        .process(
            request(RequestBody::RequestBody(HttpBody {
                body: b"{}".to_vec(),
                end_of_stream: true,
            })),
            &mut stage,
            &mut context,
            &generation(),
            &RequestTraceId::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.response,
        Some(ResponseBody::Immediate(_))
    ));
    assert_eq!(stage, 4);
    assert_eq!(recorded.load(Ordering::Relaxed), 1);
    assert!(
        service
            .process(
                request(RequestBody::ResponseHeaders(headers())),
                &mut stage,
                &mut context,
                &generation(),
                &RequestTraceId::new(),
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn rejects_unbuffered_oversized_out_of_order_and_observation_messages() {
    let (service, _) = service();
    for (message, mut stage) in [
        (
            request(RequestBody::RequestBody(HttpBody {
                body: vec![],
                end_of_stream: true,
            })),
            0,
        ),
        (
            request(RequestBody::RequestBody(HttpBody {
                body: vec![],
                end_of_stream: false,
            })),
            1,
        ),
        (
            request(RequestBody::RequestBody(HttpBody {
                body: vec![0; 257],
                end_of_stream: true,
            })),
            1,
        ),
        (
            ProcessingRequest {
                observability_mode: true,
                request: Some(RequestBody::RequestHeaders(headers())),
            },
            0,
        ),
    ] {
        assert!(
            service
                .process(
                    message,
                    &mut stage,
                    &mut None,
                    &generation(),
                    &RequestTraceId::new()
                )
                .await
                .is_err()
        );
    }
    // Pinned Envoy uses field 10; obsolete field 1 is reserved.
    use prost::Message;
    let wire = ProcessingRequest::decode(&[0x50, 1][..]).unwrap();
    assert!(wire.observability_mode);
}
#[tokio::test]
async fn response_release_failure_never_returns_original_provider_bytes() {
    let (service, _) = service();
    let mut stage = 2;
    let mut context: Option<Box<dyn ProtectedRequest>> =
        Some(Box::new(Context(Arc::default(), None, None)));
    let upstream_headers = HttpHeaders {
        headers: Some(HeaderMap {
            headers: [
                (":status", "200"),
                ("content-length", "23"),
                ("x-private", "secret"),
            ]
            .into_iter()
            .map(|(key, value)| HeaderValue {
                key: key.into(),
                value: String::new(),
                raw_value: value.as_bytes().to_vec(),
            })
            .collect(),
        }),
        end_of_stream: false,
    };
    let response = service
        .process(
            request(RequestBody::ResponseHeaders(upstream_headers)),
            &mut stage,
            &mut context,
            &generation(),
            &RequestTraceId::new(),
        )
        .await
        .unwrap();
    let Some(ResponseBody::ResponseHeaders(response)) = response.response else {
        panic!()
    };
    assert!(
        response
            .response
            .unwrap()
            .header_mutation
            .unwrap()
            .remove_headers
            .contains(&"content-length".into())
    );
    assert_eq!(
        service
            .process(
                request(RequestBody::ResponseBody(HttpBody {
                    body: b"private-provider-result".to_vec(),
                    end_of_stream: true
                })),
                &mut stage,
                &mut context,
                &generation(),
                &RequestTraceId::new(),
            )
            .await,
        Err(RuntimeError::ResponseWithheld)
    );
}

#[tokio::test]
async fn actual_unix_grpc_stream_checks_peer_and_ends_on_pds_denial() {
    use crate::ipc::{OwnedUnixListener, UnixSocketPolicy};
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
    };
    use tokio::net::UnixStream;
    let root =
        std::env::temp_dir().join(format!("ep-{:016x}", uuid::Uuid::now_v7().as_u128() as u64));
    fs::DirBuilder::new().mode(0o750).create(&root).unwrap();
    let metadata = fs::metadata(&root).unwrap();
    let socket = root.join("p.sock");
    let listener = OwnedUnixListener::bind(
        &socket,
        UnixSocketPolicy {
            owner_uid: metadata.uid(),
            group_gid: metadata.gid(),
            envoy_uid: metadata.uid(),
        },
    )
    .await
    .unwrap();
    let (service, recorded) = service();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(crate::ext_proc_server::serve_ext_proc(
        service,
        listener,
        async {
            let _ = stopped.await;
        },
    ));
    let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move {
                UnixStream::connect(socket)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    sender
        .send(request(RequestBody::RequestHeaders(headers())))
        .await
        .unwrap();
    let mut call = tonic::Request::new(ReceiverStream::new(receiver));
    call.metadata_mut()
        .insert("x-openpc-runtime-capsule-id", "capsule-1".parse().unwrap());
    call.metadata_mut()
        .insert("x-openpc-runtime-generation", "1".parse().unwrap());
    let mut response = client
        .streaming(
            call,
            http::uri::PathAndQuery::from_static(
                "/envoy.service.ext_proc.v3.ExternalProcessor/Process",
            ),
            tonic_prost::ProstCodec::<ProcessingRequest, ProcessingResponse>::default(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        response.message().await.unwrap().unwrap().response,
        Some(ResponseBody::RequestHeaders(_))
    ));
    sender
        .send(request(RequestBody::RequestBody(HttpBody {
            body: b"{}".to_vec(),
            end_of_stream: true,
        })))
        .await
        .unwrap();
    assert!(matches!(
        response.message().await.unwrap().unwrap().response,
        Some(ResponseBody::Immediate(_))
    ));
    assert!(response.message().await.unwrap().is_none());
    assert_eq!(recorded.load(Ordering::Relaxed), 1);
    drop(sender);
    drop(response);
    drop(client);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    fs::remove_dir_all(root).unwrap();
}

fn generation() -> EnvoyGeneration {
    EnvoyGeneration {
        capsule_id: "capsule-1".into(),
        generation: 1,
    }
}

#[test]
fn generation_observation_requires_unique_canonical_service_metadata() {
    let mut metadata = tonic::metadata::MetadataMap::new();
    assert!(EnvoyGeneration::from_metadata(&metadata).is_err());
    metadata.insert("x-openpc-runtime-capsule-id", "capsule-1".parse().unwrap());
    for value in ["0", "01", "-1", "18446744073709551616"] {
        metadata.insert("x-openpc-runtime-generation", value.parse().unwrap());
        assert!(EnvoyGeneration::from_metadata(&metadata).is_err());
    }
    metadata.insert("x-openpc-runtime-generation", "1".parse().unwrap());
    assert_eq!(
        EnvoyGeneration::from_metadata(&metadata)
            .unwrap()
            .generation(),
        1
    );
    metadata.append("x-openpc-runtime-generation", "1".parse().unwrap());
    assert!(EnvoyGeneration::from_metadata(&metadata).is_err());
}

#[tokio::test]
async fn local_status_response_ends_the_stream_without_a_provider_handoff() {
    let (service, recorded) = service();
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{"operationId":"known"}}"#.to_vec();
    let mut context: Option<Box<dyn ProtectedRequest>> = Some(Box::new(Context(
        recorded.clone(),
        None,
        Some(PendingResponse::Local(body.clone())),
    )));
    let mut stage = 1;
    let response = service
        .process(
            request(RequestBody::RequestBody(HttpBody {
                body: b"status".to_vec(),
                end_of_stream: true,
            })),
            &mut stage,
            &mut context,
            &generation(),
            &RequestTraceId::new(),
        )
        .await
        .unwrap();
    let Some(ResponseBody::Immediate(response)) = response.response else {
        panic!("local status must be immediate")
    };
    assert_eq!(response.status.unwrap().code, 200);
    assert_eq!(response.body, body);
    assert_eq!(stage, 4);
    assert_eq!(
        recorded.load(Ordering::Relaxed),
        0,
        "no PDS/provider denial or handoff"
    );
    assert!(
        service
            .process(
                request(RequestBody::ResponseHeaders(headers())),
                &mut stage,
                &mut context,
                &generation(),
                &RequestTraceId::new()
            )
            .await
            .is_err()
    );
}

#[test]
fn retained_write_outcome_precedes_transport_and_evidence_failures() {
    let (service, recorded) = service();
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{"state":"WRITE_AMBIGUITY"}}"#.to_vec();
    for error in [
        RuntimeError::GenerationMismatch,
        RuntimeError::ExpiredAuthorization,
        RuntimeError::BudgetExhausted,
        RuntimeError::ResponseWithheld,
        RuntimeError::EvidenceCapacity,
        RuntimeError::RuntimeUnavailable,
    ] {
        let mut context: Option<Box<dyn ProtectedRequest>> = Some(Box::new(Context(
            recorded.clone(),
            Some("1".into()),
            Some(PendingResponse::Write(body.clone())),
        )));
        let response = service.failure_response(&mut context, error, &RequestTraceId::new());
        let Some(ResponseBody::Immediate(response)) = response.response else {
            panic!("durable outcome must terminate the stream");
        };
        assert_eq!(response.body, body);
        assert_eq!(
            recorded.load(Ordering::Relaxed),
            0,
            "new denial admission cannot hide an existing outcome"
        );
        assert!(context.as_mut().unwrap().durable_write_response().is_none());
    }
}

#[tokio::test]
async fn tracked_stream_drain_cancels_input_and_backpressured_response() {
    for blocked_response in [false, true] {
        let (service, recorded) = service();
        let lifecycle = service.stream_lifecycle();
        let (input, incoming) = mpsc::channel(2);
        // One slot makes the second real protocol response wait while its
        // receiver remains alive; the production loop must cancel that send.
        let (output, receiver) = mpsc::channel(1);
        input
            .send(Ok(request(RequestBody::RequestHeaders(headers()))))
            .await
            .unwrap();
        if blocked_response {
            input
                .send(Ok(request(RequestBody::RequestBody(HttpBody {
                    body: b"{}".to_vec(),
                    end_of_stream: true,
                }))))
                .await
                .unwrap();
        }
        let owned = service.clone();
        service
            .spawn_stream_task(async move {
                owned
                    .run_stream(
                        ReceiverStream::new(incoming),
                        output,
                        generation(),
                        RequestTraceId::new(),
                    )
                    .await;
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while receiver.len() != 1 || (blocked_response && recorded.load(Ordering::Relaxed) == 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!input.is_closed());
        tokio::time::timeout(Duration::from_secs(2), lifecycle.drain())
            .await
            .unwrap()
            .unwrap();
        assert!(input.is_closed());
        assert_eq!(
            recorded.load(Ordering::Relaxed),
            usize::from(blocked_response)
        );
        assert!(
            service.spawn_stream_task(async {}).is_err(),
            "closed registry cannot restart serving"
        );
        assert!(service.streams.jobs.lock().unwrap().is_empty());
        drop(receiver);
    }
}

#[tokio::test]
async fn stream_drain_waits_for_started_owner_and_preserves_task_failure() {
    let (service, _) = self::service();
    let lifecycle = service.stream_lifecycle();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let completed = Arc::new(AtomicUsize::new(0));
    let (started, released, finished) = (entered.clone(), release.clone(), completed.clone());
    service
        .spawn_stream_task(async move {
            started.notify_one();
            released.notified().await;
            finished.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();
    entered.notified().await;
    lifecycle.cancel();
    assert_eq!(completed.load(Ordering::Relaxed), 0);
    let drain = lifecycle.drain();
    tokio::pin!(drain);
    assert!(
        futures::poll!(&mut drain).is_pending(),
        "started owner must be collected"
    );
    release.notify_one();
    drain.await.unwrap();
    assert_eq!(completed.load(Ordering::Relaxed), 1);

    let (service, _) = self::service();
    let lifecycle = service.stream_lifecycle();
    service
        .spawn_stream_task(async { panic!("component child failure") })
        .unwrap();
    assert_eq!(
        lifecycle.drain().await,
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert!(service.streams.jobs.lock().unwrap().is_empty());
}

struct DrainDirectory(std::path::PathBuf);
impl DrainDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let root =
            std::env::temp_dir().join(format!("dr-{:016x}", uuid::Uuid::now_v7().as_u128() as u64));
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&root)
            .unwrap();
        Self(root)
    }
    async fn listener(&self, name: &str, reject_peer: bool) -> crate::ipc::OwnedUnixListener {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&self.0).unwrap();
        crate::ipc::OwnedUnixListener::bind(
            &self.0.join(name),
            crate::ipc::UnixSocketPolicy {
                owner_uid: metadata.uid(),
                group_gid: metadata.gid(),
                envoy_uid: metadata.uid() + u32::from(reject_peer),
            },
        )
        .await
        .unwrap()
    }
    fn agent(&self) -> RuntimeResult<crate::RuntimeAgent> {
        let signer = pc_runtime_types::PurposeSigner::from_secret_bytes(
            pc_runtime_types::PURPOSE_DESIRED_GENERATION_V1,
            [21; 32],
        )
        .unwrap();
        crate::RuntimeAgent::open(
            "drain-target",
            &signer.verifier().sec1_bytes(),
            [22; 32],
            8,
            4096,
            &self.0.join("agent"),
        )
    }
}
impl Drop for DrainDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct JournalOwner {
    inner: Owner,
    _journal: Arc<crate::RuntimeAgent>,
}
impl ExtProcRequestOwner for JournalOwner {
    fn begin(
        &self,
        peer: &crate::WorkloadPeer,
        generation: &EnvoyGeneration,
        headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        self.inner.begin(peer, generation, headers, trace)
    }
    fn record_transport_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.inner.record_transport_denial(error, trace)
    }
}
struct FailingBrokerEvidence;
impl crate::broker_server::BrokerServerEvidence for FailingBrokerEvidence {
    fn record_transport_denial(&self, _: &RuntimeError) -> RuntimeResult<()> {
        Err(RuntimeError::EvidenceCapacity)
    }
}

async fn held_grpc(
    socket: std::path::PathBuf,
) -> (
    mpsc::Sender<ProcessingRequest>,
    tonic::Streaming<ProcessingResponse>,
) {
    let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move {
                tokio::net::UnixStream::connect(socket)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let (sender, receiver) = mpsc::channel(2);
    sender
        .send(request(RequestBody::RequestHeaders(headers())))
        .await
        .unwrap();
    let mut call = tonic::Request::new(ReceiverStream::new(receiver));
    call.metadata_mut()
        .insert("x-openpc-runtime-capsule-id", "capsule-1".parse().unwrap());
    call.metadata_mut()
        .insert("x-openpc-runtime-generation", "1".parse().unwrap());
    let mut response = client
        .streaming(
            call,
            http::uri::PathAndQuery::from_static(
                "/envoy.service.ext_proc.v3.ExternalProcessor/Process",
            ),
            tonic_prost::ProstCodec::<ProcessingRequest, ProcessingResponse>::default(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        response.message().await.unwrap().unwrap().response,
        Some(ResponseBody::RequestHeaders(_))
    ));
    (sender, response)
}

#[tokio::test]
async fn both_servers_drain_held_grpc_and_release_journal_on_shutdown_failure_or_cancel() {
    // Source-only and paired serving, paired child failure, and cancellation of
    // each enclosing server future. This is real Unix/gRPC/journal custody,
    // still not the governed Control/restoration business journey.
    for (source_only, child_failure, cancelled) in [
        (true, false, false),
        (false, false, false),
        (false, true, false),
        (false, false, true),
        (true, false, true),
    ] {
        let directory = DrainDirectory::new();
        let agent = Arc::new(directory.agent().unwrap());
        let custody = Arc::downgrade(&agent);
        let recorded = Arc::new(AtomicUsize::new(0));
        let service = ExtProcService::new(
            Arc::new(PolicyDecisionService::new([7; 32], 10).unwrap()),
            Arc::new(JournalOwner {
                inner: Owner(recorded.clone()),
                _journal: agent,
            }),
            ExtProcLimits {
                headers: 8,
                header_bytes: 8192,
                body_bytes: 256,
            },
        )
        .unwrap();
        let pds = directory.listener("p.sock", false).await;
        let broker = if source_only {
            None
        } else {
            Some(directory.listener("b.sock", child_failure).await)
        };
        let signer = pc_runtime_types::PurposeSigner::from_secret_bytes(
            pc_runtime_types::PURPOSE_BROKER_CAPABILITY_V1,
            [23; 32],
        )
        .unwrap();
        let broker_owner = Arc::new(
            openpc_broker::BrokerService::new(&signer.verifier().sec1_bytes(), 8).unwrap(),
        );
        let handoffs = Arc::new(
            crate::broker_handoff::BrokerHandoffStore::new(broker_owner, 4, 1024).unwrap(),
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            match broker {
                None => crate::ext_proc_server::serve_ext_proc(service, pds, shutdown).await,
                Some(broker) => {
                    crate::target_server::serve_protected_target(
                        service,
                        pds,
                        handoffs,
                        Arc::new(FailingBrokerEvidence),
                        broker,
                        256,
                        shutdown,
                    )
                    .await
                }
            }
        });
        let held = tokio::time::timeout(
            Duration::from_secs(3),
            held_grpc(directory.0.join("p.sock")),
        )
        .await
        .unwrap();
        assert!(
            directory.agent().is_err(),
            "serving owner must retain exclusive journal custody"
        );
        if child_failure {
            let _rejected_peer = tokio::net::UnixStream::connect(directory.0.join("b.sock"))
                .await
                .unwrap();
        } else if cancelled {
            server.abort();
        } else {
            stop.send(()).unwrap();
        }
        let result = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap();
        if cancelled {
            assert!(result.unwrap_err().is_cancelled());
        } else if child_failure {
            assert_eq!(
                result.unwrap(),
                Err(RuntimeError::EvidenceCapacity),
                "preserve the first child failure after draining its sibling"
            );
        } else {
            result.unwrap().unwrap();
        }
        // An aborted enclosing future is not a successful drain. Its owned
        // guards must nevertheless cancel children and relinquish custody.
        tokio::time::timeout(Duration::from_secs(3), async {
            while custody.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!directory.0.join("p.sock").exists());
        assert!(!directory.0.join("b.sock").exists());
        let worker = directory.agent().unwrap();
        assert_eq!(
            recorded.load(Ordering::Relaxed),
            0,
            "shutdown must not fabricate request denials"
        );
        drop(worker);
        drop(held);
    }
}

struct RefreshingOwner {
    resumed: Arc<tokio::sync::Notify>,
    captured: Arc<AtomicUsize>,
    failure: Option<RuntimeError>,
}
impl ExtProcRequestOwner for RefreshingOwner {
    fn begin(
        &self,
        _: &crate::WorkloadPeer,
        _: &EnvoyGeneration,
        _: &[(String, Vec<u8>)],
        _: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        panic!("transport must use the coordinated capture")
    }
    fn prepare_begin<'a>(
        &'a self,
        _: &'a crate::WorkloadPeer,
        generation: &'a EnvoyGeneration,
        _: &'a [(String, Vec<u8>)],
        _: &'a RequestTraceId,
    ) -> crate::ext_proc::RequestBeginFuture<'a> {
        Box::pin(async move {
            self.resumed.notified().await;
            assert_eq!(generation.capsule_id(), "capsule-1");
            if let Some(error) = &self.failure {
                return Err(error.clone());
            }
            self.captured.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(Context(self.captured.clone(), None, None)) as Box<dyn ProtectedRequest>)
        })
    }
    fn record_transport_denial(&self, _: &RuntimeError, _: &RequestTraceId) -> RuntimeResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn request_headers_wait_for_refresh_and_preserve_failed_admission() {
    for failure in [
        None,
        Some(RuntimeError::ExpiredAuthorization),
        Some(RuntimeError::RuntimeUnavailable),
    ] {
        let (mut service, _) = service();
        let resumed = Arc::new(tokio::sync::Notify::new());
        let captured = Arc::new(AtomicUsize::new(0));
        service.owner = Arc::new(RefreshingOwner {
            resumed: resumed.clone(),
            captured: captured.clone(),
            failure: failure.clone(),
        });
        let mut stage = 0;
        let mut context = None;
        let generation = generation();
        let trace = RequestTraceId::new();
        let mut pending = Box::pin(service.process(
            request(RequestBody::RequestHeaders(headers())),
            &mut stage,
            &mut context,
            &generation,
            &trace,
        ));
        assert!(futures::poll!(&mut pending).is_pending());
        assert_eq!(captured.load(Ordering::Relaxed), 0);
        resumed.notify_one();
        let result = pending.await;
        if let Some(error) = failure {
            assert!(matches!(result, Err(actual) if actual == error));
            assert!(context.is_none());
            assert_eq!(stage, 0);
            assert_eq!(captured.load(Ordering::Relaxed), 0);
        } else {
            assert!(result.is_ok());
            assert!(context.is_some());
            assert_eq!(stage, 1);
            assert_eq!(captured.load(Ordering::Relaxed), 1);
        }
    }
}
