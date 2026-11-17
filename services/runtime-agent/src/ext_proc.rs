//! Buffered ext_proc process boundary. All authority and response release belong
//! to the installed local owners, never to caller headers or the stream adapter.
pub use crate::RequestTraceId;
use crate::ext_proc_wire::*;
use futures::{Stream, StreamExt};
use openpc_pds::{EvaluationInput, LocalDecisionOwner, PolicyDecisionService};
use pc_runtime_types::{DecisionEffect, RuntimeDecision, RuntimeError, RuntimeResult};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

#[path = "ext_proc_response.rs"]
mod response_headers;

/// Immutable limits are loaded from the admitted target profile at startup.
#[derive(Clone, Copy)]
pub struct ExtProcLimits {
    pub headers: usize,
    pub header_bytes: usize,
    pub body_bytes: usize,
}

/// Observation from Envoy's configured gRPC service metadata, received only on
/// the kernel-authenticated private channel. Workload HTTP headers cannot create
/// or replace this value. It identifies configuration, not workload authority.
#[derive(Clone, Debug)]
pub struct EnvoyGeneration {
    capsule_id: String,
    generation: u64,
}
impl EnvoyGeneration {
    pub fn capsule_id(&self) -> &str {
        &self.capsule_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn from_metadata(metadata: &tonic::metadata::MetadataMap) -> RuntimeResult<Self> {
        let one = |name: &'static str| -> RuntimeResult<&str> {
            let all = metadata.get_all(name);
            let mut values = all.iter();
            let value = values.next().ok_or(RuntimeError::GenerationMismatch)?;
            if values.next().is_some() {
                return Err(RuntimeError::GenerationMismatch);
            }
            value.to_str().map_err(|_| RuntimeError::GenerationMismatch)
        };
        let value = one("x-openpc-runtime-capsule-id")?;
        crate::capsule::text(value, 160)?;
        let number = one("x-openpc-runtime-generation")?;
        let generation = number
            .parse::<u64>()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        if generation == 0 || generation.to_string() != number {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(Self {
            capsule_id: value.into(),
            generation,
        })
    }
}
pub type LocalResponseFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = RuntimeResult<Option<Vec<u8>>>> + Send + 'a>,
>;

pub trait ProtectedRequest: Send {
    /// Internal provider safety observations complete before the final PDS
    /// decision. Ordinary read owners retain their synchronous preparation.
    fn prepare_evaluation<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = RuntimeResult<EvaluationInput>> + Send + 'a>,
    > {
        Box::pin(async move { self.evaluation(body) })
    }
    /// An admitted write owns its outcome even when the transport/authority
    /// path later fails. Returning it must never initiate or authorize I/O.
    fn durable_write_response(&mut self) -> Option<RuntimeResult<Vec<u8>>> {
        None
    }
    /// Canonical JSON scalar from this request's completed strict decoding.
    /// None before decoding; transport metadata cannot supply a correlation ID.
    fn request_id(&self) -> Option<&str>;
    /// Local owner captured from the verified peer passed to begin(). It must
    /// never resolve identity by an unauthenticated request-digest lookup alone.
    fn decision_owner(&self) -> &dyn LocalDecisionOwner;
    /// Decode only request data and bind it to this transport-authenticated
    /// request's local identity view before calling the actual PDS owner.
    fn evaluation(&mut self, body: &[u8]) -> RuntimeResult<EvaluationInput>;
    /// A local operation read may finish here after its own current authority,
    /// RPC policy and durable disclosure-evidence checks. No provider is called.
    fn local_response(&mut self, _body: &[u8]) -> RuntimeResult<Option<Vec<u8>>> {
        Ok(None)
    }
    /// An explicitly selected analysis or dedicated source owner may await its
    /// own authorized pinned I/O. It must validate the result and commit its
    /// evidence without returning an invocation dispatch route or capability.
    fn prepare_local_response<'a>(&'a mut self, body: &'a [u8]) -> LocalResponseFuture<'a> {
        Box::pin(async move { self.local_response(body) })
    }
    /// Commit the broker handoff and return its opaque one-use capability.
    /// A returned token is never a replacement for a PDS allow decision.
    fn authorize(&mut self, decision: &RuntimeDecision) -> RuntimeResult<String>;
    /// Persist terminal outcomes idempotently, including denials before PDS could
    /// acquire a lease. The owner deduplicates a decision already committed by PDS.
    fn record_denial(
        &mut self,
        decision: &RuntimeDecision,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()>;
    /// Admit provider status/metadata against this request's response pipeline.
    /// Return only explicitly releasable ordinary headers. Provider headers are
    /// otherwise removed; body framing is recomputed after filtering.
    fn response_headers(
        &mut self,
        headers: &[(String, Vec<u8>)],
    ) -> RuntimeResult<Vec<(String, Vec<u8>)>>;
    /// Revalidate the owner and commit response/effect evidence before release.
    fn release_response(&mut self, body: &[u8]) -> RuntimeResult<Vec<u8>>;
    /// Wait for an in-flight owner refresh before the final synchronous checks.
    /// This hook must not dispatch a provider or retry an evidence commit.
    fn prepare_release_response<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RuntimeResult<Vec<u8>>> + Send + 'a>>
    {
        Box::pin(async move { self.release_response(body) })
    }
}
pub type RequestBeginFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = RuntimeResult<Box<dyn ProtectedRequest>>> + Send + 'a>,
>;

pub trait ExtProcRequestOwner: Send + Sync {
    /// Wait for an in-flight owner refresh before capturing request authority.
    /// Implementations must preserve exact generation and durable-outcome checks.
    fn prepare_begin<'a>(
        &'a self,
        peer: &'a crate::WorkloadPeer,
        generation: &'a EnvoyGeneration,
        headers: &'a [(String, Vec<u8>)],
        trace: &'a RequestTraceId,
    ) -> RequestBeginFuture<'a> {
        Box::pin(async move { self.begin(peer, generation, headers, trace) })
    }
    fn begin(
        &self,
        peer: &crate::WorkloadPeer,
        generation: &EnvoyGeneration,
        headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>>;
    fn record_transport_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()>;
}
#[derive(Clone)]
pub struct ExtProcService {
    pds: Arc<PolicyDecisionService>,
    owner: Arc<dyn ExtProcRequestOwner>,
    limits: ExtProcLimits,
    streams: Arc<StreamTasks>,
}

struct StreamTasks {
    jobs: Mutex<JoinSet<()>>,
    stop: watch::Sender<bool>,
    failed: AtomicBool,
}

/// One guard belongs to the serving socket, including Tonic's connection tasks.
/// Request tasks share the registry, but cannot outlive a successful drain.
pub(crate) struct StreamLifecycle(Arc<StreamTasks>);
impl StreamLifecycle {
    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.stop.subscribe()
    }
    pub(crate) fn cancel(&self) {
        self.0.stop.send_replace(true);
    }
    pub(crate) async fn drain(self) -> RuntimeResult<()> {
        self.cancel();
        let mut jobs = {
            let mut registered = self
                .0
                .jobs
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            std::mem::replace(&mut *registered, JoinSet::new())
        };
        let completed = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(result) = jobs.join_next().await {
                if result.is_err() {
                    self.0.failed.store(true, Ordering::Release);
                }
            }
        })
        .await;
        if completed.is_err() {
            // An admitted write remains with its original durable owner. Task
            // cancellation does not claim a denial, success or absent effect.
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
            return Err(RuntimeError::RuntimeUnavailable);
        }
        if self.0.failed.load(Ordering::Acquire) {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        Ok(())
    }
}
impl Drop for StreamLifecycle {
    fn drop(&mut self) {
        self.cancel();
        // Also covers cancellation of the enclosing serving future. A JoinSet
        // moved into drain() is itself abort-on-drop.
        match self.0.jobs.lock() {
            Ok(mut jobs) => jobs.abort_all(),
            Err(poisoned) => poisoned.into_inner().abort_all(),
        }
    }
}

pub(crate) async fn stream_stopped(mut stop: watch::Receiver<bool>) {
    while !*stop.borrow() && stop.changed().await.is_ok() {}
}

async fn send_response(
    sender: &mpsc::Sender<Result<ProcessingResponse, Status>>,
    response: ProcessingResponse,
    stop: watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        () = stream_stopped(stop) => false,
        sent = sender.send(Ok(response)) => sent.is_ok(),
    }
}

impl ExtProcService {
    pub fn new(
        pds: Arc<PolicyDecisionService>,
        owner: Arc<dyn ExtProcRequestOwner>,
        limits: ExtProcLimits,
    ) -> RuntimeResult<Self> {
        if limits.headers == 0
            || limits.header_bytes == 0
            || limits.header_bytes > 64 * 1024
            || limits.headers > 256
            || limits.body_bytes == 0
            || limits.body_bytes > 4 * 1024 * 1024
        {
            return Err(RuntimeError::InvalidInput);
        }
        let (stop, _) = watch::channel(false);
        Ok(Self {
            pds,
            owner,
            limits,
            streams: Arc::new(StreamTasks {
                jobs: Mutex::new(JoinSet::new()),
                stop,
                failed: AtomicBool::new(false),
            }),
        })
    }
    pub(crate) fn stream_lifecycle(&self) -> StreamLifecycle {
        StreamLifecycle(self.streams.clone())
    }
    fn spawn_stream_task(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), Status> {
        let mut jobs = self
            .streams
            .jobs
            .lock()
            .map_err(|_| Status::unavailable("protected stream custody unavailable"))?;
        while let Some(result) = jobs.try_join_next() {
            if result.is_err() {
                self.streams.failed.store(true, Ordering::Release);
                self.streams.stop.send_replace(true);
            }
        }
        if *self.streams.stop.borrow() {
            return Err(Status::unavailable("protected stream is draining"));
        }
        jobs.spawn(task);
        Ok(())
    }
    pub(crate) fn message_limit(&self) -> usize {
        self.limits
            .body_bytes
            .max(self.limits.header_bytes)
            .saturating_add(4096)
    }
    pub(crate) fn peer_denial(&self, error: &RuntimeError) -> RuntimeResult<()> {
        self.owner
            .record_transport_denial(error, &RequestTraceId::new())
    }
    pub(crate) async fn stream(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<ReceiverStream<Result<ProcessingResponse, Status>>>, Status> {
        if request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|i| i.peer_cred)
            .is_none()
        {
            return Err(Status::unauthenticated("verified Unix peer required"));
        }
        let trace = RequestTraceId::new();
        let generation = EnvoyGeneration::from_metadata(request.metadata()).map_err(|error| {
            let _ = self.owner.record_transport_denial(&error, &trace);
            Status::failed_precondition("configured Envoy generation required")
        })?;
        let incoming = request.into_inner();
        let service = self.clone();
        let (sender, receiver) = mpsc::channel(2);
        self.spawn_stream_task(async move {
            service
                .run_stream(incoming, sender, generation, trace)
                .await;
        })?;
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
    async fn run_stream(
        &self,
        mut incoming: impl Stream<Item = Result<ProcessingRequest, Status>> + Unpin,
        sender: mpsc::Sender<Result<ProcessingResponse, Status>>,
        generation: EnvoyGeneration,
        trace: RequestTraceId,
    ) {
        let stop = self.streams.stop.subscribe();
        let mut stage = 0;
        let mut context: Option<Box<dyn ProtectedRequest>> = None;
        loop {
            let received = tokio::select! {
                biased;
                () = stream_stopped(stop.clone()) => break,
                result = tokio::time::timeout(Duration::from_secs(10), incoming.next()) => result,
            };
            let message = match received {
                Ok(Some(Ok(message))) => message,
                result => {
                    if stage != 4 && !*stop.borrow() {
                        let error = if result.is_err() {
                            RuntimeError::BudgetExhausted
                        } else {
                            RuntimeError::RuntimeUnavailable
                        };
                        eprintln!(
                            "{}",
                            serde_json::json!({"event":"protected_stream_ended","stage":stage,"pcCode":error.pc_code(),"traceId":trace.as_str()})
                        );
                        let response = self.failure_response(&mut context, error, &trace);
                        send_response(&sender, response, stop.clone()).await;
                    }
                    break;
                }
            };
            // Let an in-flight owner finish within the drain budget. Cancelling
            // the transport never invents a terminal business result.
            let result = self
                .process(message, &mut stage, &mut context, &generation, &trace)
                .await;
            if *stop.borrow() {
                break;
            }
            let (response, terminal) = match result {
                Ok(response) => (response, stage == 4),
                Err(error) => (self.failure_response(&mut context, error, &trace), true),
            };
            if !send_response(&sender, response, stop.clone()).await || terminal {
                break;
            }
        }
    }
    fn failure_response(
        &self,
        context: &mut Option<Box<dyn ProtectedRequest>>,
        error: RuntimeError,
        trace: &RequestTraceId,
    ) -> ProcessingResponse {
        if let Some(response) = context
            .as_mut()
            .and_then(|request| request.durable_write_response())
        {
            return match response {
                Ok(body) if !body.is_empty() && body.len() <= self.limits.body_bytes => {
                    local_response(body)
                }
                _ => denial_with_id(
                    &RuntimeError::WriteAmbiguity,
                    context.as_ref().and_then(|request| request.request_id()),
                    trace,
                ),
            };
        }
        let error = self
            .owner
            .record_transport_denial(&error, trace)
            .err()
            .unwrap_or(error);
        denial_with_id(
            &error,
            context.as_ref().and_then(|request| request.request_id()),
            trace,
        )
    }

    async fn process(
        &self,
        message: ProcessingRequest,
        stage: &mut u8,
        context: &mut Option<Box<dyn ProtectedRequest>>,
        generation: &EnvoyGeneration,
        trace: &RequestTraceId,
    ) -> RuntimeResult<ProcessingResponse> {
        if message.observability_mode {
            return Err(RuntimeError::InvalidInput);
        }
        let response = match (message.request, *stage) {
            (Some(RequestBody::RequestHeaders(headers)), 0) => {
                if headers.end_of_stream {
                    return Err(RuntimeError::InvalidInput);
                }
                let headers = self.headers(headers)?;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?
                    .as_millis()
                    .try_into()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
                let peer = crate::WorkloadPeer::from_envoy_headers(&headers, now_ms)?;
                *context = Some(
                    self.owner
                        .prepare_begin(&peer, generation, &headers, trace)
                        .await?,
                );
                *stage = 1;
                ResponseBody::RequestHeaders(common(
                    Some(HeaderMutation {
                        set_headers: vec![HeaderValueOption {
                            header: Some(HeaderValue {
                                key: ":path".into(),
                                value: String::new(),
                                raw_value: b"/openpc/broker/v1/dispatch".to_vec(),
                            }),
                            append_action: 2,
                        }],
                        remove_headers: vec!["x-openpc-runtime-capability".into()],
                    }),
                    None,
                ))
            }
            (Some(RequestBody::RequestBody(body)), 1) => {
                self.body(&body)?;
                let context = context.as_mut().ok_or(RuntimeError::RuntimeUnavailable)?;
                if let Some(response) = context.prepare_local_response(&body.body).await? {
                    if response.is_empty() || response.len() > self.limits.body_bytes {
                        return Err(RuntimeError::BudgetExhausted);
                    }
                    *stage = 4;
                    return Ok(local_response(response));
                }
                let input = context.prepare_evaluation(&body.body).await?;
                let decision = self.pds.evaluate_for(&input, context.decision_owner())?;
                if decision.effect != DecisionEffect::AllowForward || decision.capability.is_none()
                {
                    context.record_denial(&decision, trace)?;
                    *stage = 4;
                    let error = RuntimeError::from_local_code(&decision.pc_code)
                        .unwrap_or(RuntimeError::RuntimeUnavailable);
                    return Ok(denial_with_id(
                        &error,
                        Some(&input.request.request_id),
                        trace,
                    ));
                }
                let capability = context.authorize(&decision)?;
                if capability.is_empty()
                    || capability.len() > 16 * 1024
                    || !capability
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                {
                    return Err(RuntimeError::InvalidAuthorization);
                }
                *stage = 2;
                ResponseBody::RequestBody(common(
                    Some(HeaderMutation {
                        set_headers: vec![HeaderValueOption {
                            header: Some(HeaderValue {
                                key: "x-openpc-runtime-capability".into(),
                                value: String::new(),
                                raw_value: capability.into_bytes(),
                            }),
                            append_action: 2,
                        }],
                        remove_headers: vec![],
                    }),
                    None,
                ))
            }
            (Some(RequestBody::ResponseHeaders(headers)), 2) => {
                if headers.end_of_stream {
                    return Err(RuntimeError::ResponseWithheld);
                }
                let headers = self.headers(headers)?;
                let admitted = context
                    .as_mut()
                    .ok_or(RuntimeError::RuntimeUnavailable)?
                    .response_headers(&headers)?;
                let mutation = response_headers::mutation(&headers, admitted, self.limits)?;
                *stage = 3;
                ResponseBody::ResponseHeaders(common(Some(mutation), None))
            }
            (Some(RequestBody::ResponseBody(body)), 3) => {
                self.body(&body)?;
                let filtered = context
                    .as_mut()
                    .ok_or(RuntimeError::RuntimeUnavailable)?
                    .prepare_release_response(&body.body)
                    .await?;
                if filtered.len() > self.limits.body_bytes {
                    return Err(RuntimeError::ResponseWithheld);
                }
                *stage = 4;
                ResponseBody::ResponseBody(common(
                    None,
                    Some(BodyMutation {
                        body: Some(filtered),
                    }),
                ))
            }
            _ => return Err(RuntimeError::InvalidInput),
        };
        Ok(ProcessingResponse {
            response: Some(response),
        })
    }
    fn headers(&self, input: HttpHeaders) -> RuntimeResult<Vec<(String, Vec<u8>)>> {
        let headers = input.headers.ok_or(RuntimeError::InvalidInput)?.headers;
        if headers.len() > self.limits.headers {
            return Err(RuntimeError::BudgetExhausted);
        }
        let mut bytes = 0usize;
        let mut result = Vec::new();
        for header in headers {
            if !header.value.is_empty()
                || header.key.is_empty()
                || !header
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_:".contains(&b))
            {
                return Err(RuntimeError::InvalidInput);
            }
            bytes = bytes
                .saturating_add(header.key.len())
                .saturating_add(header.raw_value.len());
            if bytes > self.limits.header_bytes {
                return Err(RuntimeError::BudgetExhausted);
            }
            result.push((header.key, header.raw_value));
        }
        Ok(result)
    }
    fn body(&self, body: &HttpBody) -> RuntimeResult<()> {
        if !body.end_of_stream || body.body.len() > self.limits.body_bytes {
            return Err(RuntimeError::BudgetExhausted);
        }
        Ok(())
    }
}
fn common(
    header_mutation: Option<HeaderMutation>,
    body_mutation: Option<BodyMutation>,
) -> CommonWrapper {
    CommonWrapper {
        response: Some(CommonResponse {
            status: 0,
            header_mutation,
            body_mutation,
        }),
    }
}

fn local_response(body: Vec<u8>) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(ResponseBody::Immediate(ImmediateResponse {
            status: Some(HttpStatus { code: 200 }),
            headers: Some(HeaderMutation {
                set_headers: [
                    ("content-type", "application/json"),
                    ("cache-control", "no-store"),
                ]
                .into_iter()
                .map(|(name, value)| HeaderValueOption {
                    header: Some(HeaderValue {
                        key: name.into(),
                        value: String::new(),
                        raw_value: value.as_bytes().to_vec(),
                    }),
                    append_action: 2,
                })
                .collect(),
                remove_headers: vec![],
            }),
            body,
            details: "openpc_local_operation_status".into(),
        })),
    }
}
fn denial_with_id(
    error: &RuntimeError,
    request_id: Option<&str>,
    trace: &RequestTraceId,
) -> ProcessingResponse {
    // RuntimeRequest preserves the canonical JSON scalar, including the
    // distinction between numeric and string IDs. Unknown/malformed IDs are
    // null, never reflected from arbitrary transport or provider bytes.
    let id = request_id
        .filter(|id| id.len() <= 1024)
        .and_then(|id| serde_json::from_str::<serde_json::Value>(id).ok())
        .filter(|id| crate::request_decode::request_id(id).is_ok())
        .unwrap_or(serde_json::Value::Null);
    let fault = error.public_error();
    ProcessingResponse {
        response: Some(ResponseBody::Immediate(ImmediateResponse {
            status: Some(HttpStatus {
                code: fault.http_status,
            }),
            headers: Some(HeaderMutation {
                set_headers: vec![HeaderValueOption {
                    header: Some(HeaderValue {
                        key: "content-type".into(),
                        value: String::new(),
                        raw_value: b"application/json".to_vec(),
                    }),
                    append_action: 2,
                }],
                remove_headers: vec![],
            }),
            body: serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0", "id":id,
                "error":{
                    "code":fault.json_rpc_code, "message":fault.message,
                    "data":{
                        "pcCode":fault.pc_code, "truthState":fault.truth_state,
                        "retryable":false, "traceId":trace.as_str(),
                        "attemptId":null, "signedTransactionHash":null,
                    },
                },
            }))
            .expect("closed JSON-RPC error values serialize"),
            details: "openpc_runtime_denial".into(),
        })),
    }
}

#[cfg(test)]
#[path = "ext_proc_tests.rs"]
mod tests;
