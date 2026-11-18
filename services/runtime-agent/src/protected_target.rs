//! Production ext_proc owner for the target-local decision and Broker path.
//! Transport supplies only an authenticated workload peer, an observed Envoy
//! generation and signed evidence. Authority remains in the installed owners.

use crate::{
    RequestTraceId, WorkloadPeer,
    broker_handoff::BrokerHandoffStore,
    ext_proc::{EnvoyGeneration, ExtProcRequestOwner, ProtectedRequest},
    request_decode::RequestDecodeLimits,
    request_route::{CapturedRequestRoute, RequestRouteEvidence},
    target_state::{CapturedTargetRequest, CapturedTargetState, TargetState},
};
use openpc_broker::BrokerService;
use openpc_pds::{
    EvaluationInput, IdentityAssertionEvidence, LocalDecisionLease, LocalDecisionOwner,
};
use pc_runtime_types::{
    DecisionEffect, Digest, RuntimeDecision, RuntimeError, RuntimeRequest, RuntimeResult,
    canonical_bytes,
};
use std::sync::Arc;

#[path = "target_cigl_analysis.rs"]
mod analysis;
pub(crate) mod visibility;
pub(crate) mod visibility_response;

/// Independently owned signed material needed after transport capture. The
/// implementation may read target-local publications or retained provider
/// discovery state; request headers cannot construct route authority.
pub trait ProtectedTargetAuthority: Send + Sync {
    fn identity_assertion(
        &self,
        peer: &WorkloadPeer,
        headers: &[(String, Vec<u8>)],
    ) -> RuntimeResult<IdentityAssertionEvidence>;

    fn route_evidence(
        &self,
        request: &CapturedTargetRequest,
    ) -> RuntimeResult<RequestRouteEvidence>;

    fn submission_connection(
        &self,
        _: &CapturedTargetRequest,
    ) -> RuntimeResult<Arc<openpc_multi_rpc::provider_connection::ConnectionLease>> {
        Err(RuntimeError::Denied)
    }
    fn submission_route_evidence(
        &self,
        _: &CapturedTargetRequest,
        _: &openpc_multi_rpc::write_preflight::PreflightAnchor,
    ) -> RuntimeResult<RequestRouteEvidence> {
        Err(RuntimeError::Denied)
    }
    fn replacement_observation_evidence(
        &self,
        _: &openpc_multi_rpc::journal::ObservationTarget,
    ) -> RuntimeResult<RequestRouteEvidence> {
        Err(RuntimeError::Denied)
    }
}

/// Durable sink for denials that occur before a decision reservation exists.
/// It receives only the closed error category and request-local trace ID.
pub trait TargetTransportEvidence: Send + Sync {
    fn record(&self, error: &RuntimeError, trace: &RequestTraceId) -> RuntimeResult<()>;

    fn record_pre_admission_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.record(error, trace)
    }
}

pub struct ProtectedTargetOwner {
    analysis_exporter: Option<Arc<analysis::AnalysisExporter>>,
    deployment_worker_key: Option<Vec<u8>>,
    state: Arc<TargetState>,
    broker: Arc<BrokerService>,
    submissions: Option<Arc<openpc_broker::write_dispatch::SubmissionBroker>>,
    handoffs: Arc<BrokerHandoffStore>,
    authority: Arc<dyn ProtectedTargetAuthority>,
    transport_evidence: Arc<dyn TargetTransportEvidence>,
    decode: OwnedDecodeLimits,
}

#[derive(Clone)]
struct OwnedDecodeLimits {
    maximum_request_bytes: usize,
    maximum_response_bytes: u64,
    timeout_ms: u64,
    block_selector: String,
}

impl ProtectedTargetOwner {
    pub fn new(
        state: Arc<TargetState>,
        broker: Arc<BrokerService>,
        handoffs: Arc<BrokerHandoffStore>,
        authority: Arc<dyn ProtectedTargetAuthority>,
        transport_evidence: Arc<dyn TargetTransportEvidence>,
        limits: RequestDecodeLimits<'_>,
    ) -> RuntimeResult<Self> {
        if limits.maximum_request_bytes == 0
            || limits.maximum_request_bytes > 4 * 1024 * 1024
            || limits.maximum_response_bytes == 0
            || limits.maximum_response_bytes > 4 * 1024 * 1024
            || limits.timeout_ms == 0
            || limits.timeout_ms > 120_000
            || limits.block_selector.is_empty()
            || limits.block_selector.len() > 160
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            analysis_exporter: None,
            deployment_worker_key: None,
            state,
            broker,
            submissions: handoffs.submissions(),
            handoffs,
            authority,
            transport_evidence,
            decode: OwnedDecodeLimits {
                maximum_request_bytes: limits.maximum_request_bytes,
                maximum_response_bytes: limits.maximum_response_bytes,
                timeout_ms: limits.timeout_ms,
                block_selector: limits.block_selector.into(),
            },
        })
    }
    pub fn with_deployment_worker_key(mut self, key: &[u8]) -> RuntimeResult<Self> {
        pc_runtime_types::PurposeVerifier::from_sec1_bytes(
            openpc_multi_rpc::deployment::custody::HANDOFF_PURPOSE,
            key,
        )?;
        self.deployment_worker_key = Some(key.to_vec());
        Ok(self)
    }
}

impl ProtectedTargetOwner {
    fn begin_captured(
        &self,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
        capture_error: Option<RuntimeError>,
        deadline_at_ms: u64,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        let analysis_id = analysis::request_analysis_id(headers)?;
        if analysis_id.is_some() && self.analysis_exporter.is_none() {
            return Err(RuntimeError::Denied);
        }
        let managed = headers.iter().any(|(name, value)| {
            name == ":path" && value == b"/internal/v1/deployment-submissions"
        });
        let deployment_worker_key = if managed {
            Some(
                self.deployment_worker_key
                    .clone()
                    .ok_or(RuntimeError::Denied)?,
            )
        } else {
            None
        };
        // Retain current-owner failures until the body is bound. They may deny
        // a new invocation but cannot mask an already-started exact operation.
        let captured =
            capture_error.map_or_else(|| self.state.capture(peer, generation, trace), Err);
        let assertion = self.authority.identity_assertion(peer, headers);
        Ok(Box::new(TargetRequest {
            trace: trace.clone(),
            analysis_id,
            analysis_exporter: self.analysis_exporter.clone(),
            deployment_worker_key,
            state: self.state.clone(),
            peer: peer.clone(),
            captured: Some(captured),
            assertion: Some(assertion),
            request_id: None,
            route: None,
            submission_outcome: None,
            replacement: None,
            body: None,
            broker: Arc::clone(&self.broker),
            submissions: self.submissions.clone(),
            handoffs: Arc::clone(&self.handoffs),
            authority: Arc::clone(&self.authority),
            transport_evidence: Arc::clone(&self.transport_evidence),
            recorded_unbound_denial: None,
            evaluation_permit: None,
            deadline_at_ms,
            decode: self.decode.clone(),
        }))
    }
}

impl ExtProcRequestOwner for ProtectedTargetOwner {
    fn begin(
        &self,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        let deadline = (crate::target_state::wall_clock_ns()? / 1_000_000)
            .checked_add(self.decode.timeout_ms)
            .ok_or(RuntimeError::BudgetExhausted)?;
        self.begin_captured(peer, generation, headers, trace, None, deadline)
    }

    fn prepare_begin<'a>(
        &'a self,
        peer: &'a WorkloadPeer,
        generation: &'a EnvoyGeneration,
        headers: &'a [(String, Vec<u8>)],
        trace: &'a RequestTraceId,
    ) -> crate::ext_proc::RequestBeginFuture<'a> {
        Box::pin(async move {
            let deadline = (crate::target_state::wall_clock_ns()? / 1_000_000)
                .checked_add(self.decode.timeout_ms)
                .ok_or(RuntimeError::BudgetExhausted)?;
            match self.state.coordinate_response_release(deadline).await {
                Ok(_permit) => {
                    self.begin_captured(peer, generation, headers, trace, None, deadline)
                }
                // Keep failures until the body is known: an existing durable
                // outcome remains readable without authorizing a new request.
                Err(error) => {
                    self.begin_captured(peer, generation, headers, trace, Some(error), deadline)
                }
            }
        })
    }

    fn record_transport_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.transport_evidence.record(error, trace)
    }
}

struct TargetRequest {
    trace: RequestTraceId,
    analysis_id: Option<String>,
    analysis_exporter: Option<Arc<analysis::AnalysisExporter>>,
    deployment_worker_key: Option<Vec<u8>>,
    state: Arc<TargetState>,
    peer: WorkloadPeer,
    captured: Option<RuntimeResult<CapturedTargetState>>,
    assertion: Option<RuntimeResult<IdentityAssertionEvidence>>,
    request_id: Option<String>,
    route: Option<Arc<CapturedRequestRoute>>,
    submission_outcome: Option<crate::request_route::SubmissionOutcome>,
    replacement: Option<openpc_broker::write_dispatch::ReplacementObservation>,
    body: Option<Vec<u8>>,
    broker: Arc<BrokerService>,
    submissions: Option<Arc<openpc_broker::write_dispatch::SubmissionBroker>>,
    handoffs: Arc<BrokerHandoffStore>,
    authority: Arc<dyn ProtectedTargetAuthority>,
    transport_evidence: Arc<dyn TargetTransportEvidence>,
    recorded_unbound_denial: Option<RuntimeDecision>,
    evaluation_permit: Option<crate::target_disposition::OwnedResponseReleasePermit>,
    deadline_at_ms: u64,
    decode: OwnedDecodeLimits,
}

struct UnavailableDecisionOwner;
static UNAVAILABLE_DECISION_OWNER: UnavailableDecisionOwner = UnavailableDecisionOwner;
impl LocalDecisionOwner for UnavailableDecisionOwner {
    fn acquire(&self, _: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>> {
        Err(RuntimeError::RuntimeUnavailable)
    }
}

impl ProtectedRequest for TargetRequest {
    fn prepare_evaluation<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = RuntimeResult<EvaluationInput>> + Send + 'a>,
    > {
        Box::pin(async move {
            if self.analysis_id.is_some() {
                return Err(RuntimeError::Denied);
            }
            if self.evaluation_permit.take().is_some() {
                return Err(RuntimeError::Replay);
            }
            let mut evaluation_permit = self
                .state
                .coordinate_evaluation(self.deadline_at_ms)
                .await?;
            let request = self.bind_body(body)?;
            if request.decoded().signed_transaction().is_some()
                || request.decoded().deployment().is_some()
            {
                // Writes retain their own asynchronous observation gates. A
                // retained read permit must never surround nested source I/O.
                evaluation_permit.take();
            }
            let input = request.evaluation();
            let route = if request.decoded().signed_transaction().is_some() {
                let connection = self.authority.submission_connection(&request)?;
                request
                    .clone()
                    .prepare_submission_route(connection, |head| {
                        self.authority.submission_route_evidence(&request, head)
                    })
                    .await?
            } else {
                let evidence = self
                    .authority
                    .route_evidence(&request)
                    .inspect_err(|error| {
                        log_request_rejection(&self.trace, "route_evidence", error);
                    })?;
                request
                    .clone()
                    .bind_route_evidence(evidence)
                    .inspect_err(|error| {
                        log_request_rejection(&self.trace, "route_binding", error);
                    })?
            };
            if let Some(predecessor) = request.decoded().deployment().and_then(|deployment| {
                deployment
                    .handoff()
                    .claims()
                    .predecessor_command_id
                    .as_ref()
            }) {
                let owner = {
                    let lease = request.acquire()?;
                    let grant = lease.authorize_invocation()?;
                    let scope = grant.authorization.facts();
                    openpc_multi_rpc::submission_operation::SubmissionOwner {
                        participant_id: scope.participant_id.clone(),
                        privacy_domain_id: scope.privacy_domain_id.clone(),
                        actor_principal_id: scope.actor_principal_id.clone(),
                        workload_id: scope.workload_id.clone(),
                    }
                };
                let broker = self.submissions.as_ref().ok_or(RuntimeError::Denied)?;
                let target = broker.replacement_target(predecessor, &owner)?;
                let evidence = self.authority.replacement_observation_evidence(&target)?;
                self.replacement = Some(
                    self.state
                        .prepare_recovery(broker.clone(), target, evidence)?
                        .observe_for_replacement()
                        .await?,
                );
            }
            self.body = Some(body.to_vec());
            self.route = Some(Arc::new(route));
            self.evaluation_permit = evaluation_permit;
            Ok(input)
        })
    }
    fn durable_write_response(&mut self) -> Option<RuntimeResult<Vec<u8>>> {
        self.submission_outcome
            .take()
            .map(|outcome| outcome.response())
    }
    fn local_response(&mut self, body: &[u8]) -> RuntimeResult<Option<Vec<u8>>> {
        if self.analysis_id.is_some() {
            return Err(RuntimeError::Denied);
        }
        if self.route.is_some() || self.body.is_some() {
            return Err(RuntimeError::Replay);
        }
        let rpc = self
            .deployment_worker_key
            .as_ref()
            .map(|_| {
                crate::request_decode::deployment_rpc_body(body, self.decode.maximum_request_bytes)
            })
            .transpose()?;
        let outcome_body = rpc.as_deref().unwrap_or(body);
        self.request_id = Some(crate::request_decode::request_id_from_body(
            outcome_body,
            self.decode.maximum_request_bytes,
        )?);
        if let Some(submissions) = &self.submissions
            && let Some(response) = self.state.repeated_submission_response(
                submissions,
                &self.peer,
                outcome_body,
                self.decode.maximum_request_bytes,
                self.decode.maximum_response_bytes,
            )?
        {
            self.body = Some(body.to_vec());
            return Ok(Some(response));
        }
        let Some(decoded) = crate::operation_status_rpc::OperationStatusRequest::decode(
            outcome_body,
            self.decode.maximum_request_bytes,
            crate::target_state::wall_clock_ns()? / 1_000_000,
            self.decode.timeout_ms.min(10_000),
            self.decode.maximum_response_bytes.min(8192),
        )?
        else {
            return Ok(None);
        };
        let submissions = self.submissions.as_ref().ok_or(RuntimeError::Denied)?;
        let captured = self.captured.take().ok_or(RuntimeError::Replay)??;
        let assertion = self
            .assertion
            .take()
            .ok_or(RuntimeError::RuntimeUnavailable)??;
        self.body = Some(body.to_vec());
        captured
            .release_submission_status(submissions, &decoded, &assertion)
            .map(Some)
    }
    fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    fn prepare_local_response<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> crate::ext_proc::LocalResponseFuture<'a> {
        Box::pin(async move {
            if self.analysis_id.is_some() {
                self.observe_analysis(body).await.map(Some)
            } else {
                self.local_response(body)
            }
        })
    }

    fn decision_owner(&self) -> &dyn LocalDecisionOwner {
        self.route
            .as_deref()
            .map(|route| route as &dyn LocalDecisionOwner)
            .unwrap_or(&UNAVAILABLE_DECISION_OWNER)
    }

    fn evaluation(&mut self, body: &[u8]) -> RuntimeResult<EvaluationInput> {
        if self.analysis_id.is_some() {
            return Err(RuntimeError::Denied);
        }
        let request = self.bind_body(body)?;
        if request.decoded().signed_transaction().is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let evidence = self.authority.route_evidence(&request)?;
        let route = Arc::new(request.bind_route_evidence(evidence)?);
        let evaluation = route.request().evaluation();
        self.body = Some(body.to_vec());
        self.route = Some(route);
        Ok(evaluation)
    }

    fn authorize(&mut self, decision: &RuntimeDecision) -> RuntimeResult<String> {
        // Keep the permit through every synchronous admission and handoff check;
        // all exits release it before the Broker starts provider I/O.
        let _permit = self.evaluation_permit.take();
        if self.analysis_id.is_some() || decision.effect != DecisionEffect::AllowForward {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let route = self
            .route
            .as_ref()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let body = self.body.as_ref().ok_or(RuntimeError::RuntimeUnavailable)?;
        if route.request().decoded().signed_transaction().is_some() {
            let broker = self.submissions.as_ref().ok_or(RuntimeError::Denied)?;
            let prepared = match self.replacement.take() {
                Some(replacement) => {
                    route.admit_broker_replacement(broker.clone(), decision, replacement)?
                }
                None => route.admit_broker_submission(broker.clone(), decision)?,
            };
            self.submission_outcome = Some(prepared.outcome());
            return self.handoffs.publish_submission(prepared, body.clone());
        }
        let prepared = route.admit_broker_read(&self.broker, decision)?;
        let transport = route.provider_transport()?;
        self.handoffs
            .publish(prepared, body.clone(), Box::new(transport), None)
    }

    fn record_denial(
        &mut self,
        decision: &RuntimeDecision,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        let _permit = self.evaluation_permit.take();
        let route = self
            .route
            .as_ref()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        if route.request().trace().as_str() != trace.as_str()
            || decision.effect == DecisionEffect::AllowForward
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let Some((decision_id, evidence)) =
            route.request().evidence().read_for_trace(trace.as_str())?
        else {
            // Lease acquisition can deny before any decision reservation exists.
            // Retain that closed failure in transport evidence, without inventing
            // a committed decision or a capability. Bind it to this exact input.
            let input_digest = Digest::of(canonical_bytes(&route.request().evaluation())?);
            let decision_digest = Digest::of(canonical_bytes(&(
                &decision.decision_id,
                DecisionEffect::DenyTerminal,
                &input_digest,
                &decision.pc_code,
            ))?);
            if decision.effect != DecisionEffect::DenyTerminal
                || decision.capability.is_some()
                || decision.active_generation_digest != Digest::of([])
                || decision.decision_input_digest != input_digest
                || decision.decision_digest != decision_digest
                || decision.protective_degradation
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            let error = RuntimeError::from_local_code(&decision.pc_code)
                .ok_or(RuntimeError::InvalidAuthorization)?;
            if let Some(recorded) = &self.recorded_unbound_denial {
                return if recorded == decision {
                    Ok(())
                } else {
                    Err(RuntimeError::InvalidAuthorization)
                };
            }
            self.transport_evidence
                .record_pre_admission_denial(&error, trace)?;
            self.recorded_unbound_denial = Some(decision.clone());
            return Ok(());
        };
        if decision_id != decision.decision_id
            || evidence.request_digest != route.request().decoded().request().request_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    fn response_headers(
        &mut self,
        headers: &[(String, Vec<u8>)],
    ) -> RuntimeResult<Vec<(String, Vec<u8>)>> {
        let statuses = headers
            .iter()
            .filter(|(name, _)| name == ":status")
            .collect::<Vec<_>>();
        if statuses.len() != 1 || statuses[0].1.as_slice() != b"200" {
            return Err(RuntimeError::ResponseWithheld);
        }
        Ok(vec![
            ("content-type".into(), b"application/json".to_vec()),
            ("cache-control".into(), b"no-store".to_vec()),
        ])
    }

    fn release_response(&mut self, body: &[u8]) -> RuntimeResult<Vec<u8>> {
        if let Some(outcome) = self.submission_outcome.take() {
            // The private hop cannot supply operation truth. Reconstruct the
            // response from the exact durable operation admitted by this request.
            // Invalidation after STARTED cannot turn it into a pre-attempt denial.
            return outcome.response().map_err(|_| RuntimeError::WriteAmbiguity);
        }
        let route = self
            .route
            .as_ref()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        // Broker already filtered the provider response. Reapplying the same
        // canonical projection both revalidates current authority and proves no
        // different body was introduced on the private HTTP hop.
        route.release_provider_response(body)
    }

    fn prepare_release_response<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RuntimeResult<Vec<u8>>> + Send + 'a>>
    {
        Box::pin(async move {
            // Already-started writes retain their durable outcome path, even
            // when current authority has subsequently been withdrawn.
            if self.submission_outcome.is_some() {
                return self.release_response(body);
            }
            let deadline_at_ms = self
                .route
                .as_ref()
                .ok_or(RuntimeError::RuntimeUnavailable)?
                .request()
                .decoded()
                .request()
                .deadline_at_ms;
            let state = self.state.clone();
            let _permit = state.coordinate_response_release(deadline_at_ms).await?;
            self.release_response(body)
        })
    }
}

impl TargetRequest {
    fn bind_body(&mut self, body: &[u8]) -> RuntimeResult<Arc<CapturedTargetRequest>> {
        if self.route.is_some() || self.body.is_some() {
            return Err(RuntimeError::Replay);
        }
        let rpc = self
            .deployment_worker_key
            .as_ref()
            .map(|_| {
                crate::request_decode::deployment_rpc_body(body, self.decode.maximum_request_bytes)
            })
            .transpose()?;
        self.request_id = Some(crate::request_decode::request_id_from_body(
            rpc.as_deref().unwrap_or(body),
            self.decode.maximum_request_bytes,
        )?);
        let captured = self
            .captured
            .take()
            .ok_or(RuntimeError::RuntimeUnavailable)?
            .inspect_err(|error| log_request_rejection(&self.trace, "captured_authority", error))?;
        let assertion = self
            .assertion
            .take()
            .ok_or(RuntimeError::RuntimeUnavailable)?
            .inspect_err(|error| log_request_rejection(&self.trace, "identity_assertion", error))?;
        let limits = RequestDecodeLimits {
            maximum_request_bytes: self.decode.maximum_request_bytes,
            maximum_response_bytes: self.decode.maximum_response_bytes,
            timeout_ms: self
                .deadline_at_ms
                .checked_sub(crate::target_state::wall_clock_ns()? / 1_000_000)
                .filter(|remaining| *remaining > 0)
                .ok_or(RuntimeError::BudgetExhausted)?,
            block_selector: &self.decode.block_selector,
        };
        let bound = match &self.deployment_worker_key {
            Some(key) => captured.bind_deployment_request(body, limits, assertion, key),
            None => captured.bind_request(body, limits, assertion),
        };
        let request = Arc::new(bound.inspect_err(|error| {
            log_request_rejection(&self.trace, "request_binding", error);
        })?);
        Ok(request)
    }
}

fn log_request_rejection(trace: &RequestTraceId, stage: &str, error: &RuntimeError) {
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "protected_request_rejected",
            "stage": stage,
            "pcCode": error.pc_code(),
            "traceId": trace.as_str(),
        })
    );
}
