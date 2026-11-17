#![forbid(unsafe_code)]

//! Capability-bound provider dispatch and durable attempt semantics.

use std::{collections::BTreeMap, future::Future, path::Path, pin::Pin, sync::Mutex};

use pc_runtime_types::{
    AttemptResolution, BrokerCapability, DecisionEffect, Digest, LocalJournal,
    PURPOSE_BROKER_CAPABILITY_V1, ProviderResponse, PurposeVerifier, RequestClass, RuntimeBindings,
    RuntimeDecision, RuntimeError, RuntimeRequest, RuntimeResult, SignedEnvelope, canonical_bytes,
};

mod journal;
pub mod write_dispatch;
use journal::BrokerJournal;
pub use journal::{ReadAttemptMetadata, ReadAttemptStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadLaw {
    pub same_route_retries: u8,
    pub parity_failover: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    Response(ProviderResponse),
    TransientUnavailable,
    UnknownWriteOutcome,
    /// A local transport owner rejected the request before or after contact.
    /// The closed runtime category is retained so Broker can commit the exact
    /// terminal outcome without exposing provider/library diagnostics.
    Rejected(RuntimeError),
}

pub trait ProviderTransport {
    fn send(&mut self, request: &RuntimeRequest, attempt_id: &str) -> ProviderOutcome;
    fn reconcile(&mut self, signed_transaction_hash: &Digest) -> Option<ProviderResponse>;
}

/// Asynchronous provider transport for deployed runtimes. The synchronous
/// transport remains available for deterministic component fixtures, but a live
/// TLS connection must never block the Tokio executor while Broker owns the
/// capability-consumption and provider-dispatch boundary.
pub trait AsyncProviderTransport: Send {
    fn send<'a>(
        &'a mut self,
        request: &'a RuntimeRequest,
        attempt_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReconciliationContext {
    request: RuntimeRequest,
    expected_anchor: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttemptRecord {
    request_digest: Digest,
    signed_transaction_hash: Option<Digest>,
    resolution: AttemptResolution,
    reconciliation: ReconciliationContext,
}

pub struct BrokerService {
    capability_verifier: PurposeVerifier,
    journal: Mutex<LocalJournal<BrokerJournal>>,
    replay_capacity: usize,
    attempts: Mutex<BTreeMap<String, AttemptRecord>>,
}

/// Non-constructible one-use dispatch produced only after Broker has durably
/// consumed the PDS capability. A private UDS adapter may hold this while Envoy
/// forwards the exact request body, then execute it without re-consuming the
/// capability. Dropping it leaves an admitted record which restart recovers as
/// interrupted and never retries automatically.
pub struct PreparedReadDispatch {
    attempt_id: String,
    request: RuntimeRequest,
    expected_anchor: Digest,
    read_law: ReadLaw,
}

impl PreparedReadDispatch {
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    #[must_use]
    pub fn deadline_at_ms(&self) -> u64 {
        self.request.deadline_at_ms
    }
}

impl BrokerService {
    pub fn new(capability_public_key: &[u8], replay_capacity: usize) -> RuntimeResult<Self> {
        if replay_capacity == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            capability_verifier: PurposeVerifier::from_sec1_bytes(
                PURPOSE_BROKER_CAPABILITY_V1,
                capability_public_key,
            )?,
            journal: Mutex::new(LocalJournal::volatile(BrokerJournal::empty(None))),
            replay_capacity,
            attempts: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn open(
        target_id: &str,
        capability_public_key: &[u8],
        replay_capacity: usize,
        directory: &Path,
    ) -> RuntimeResult<Self> {
        let mut service = Self::new(capability_public_key, replay_capacity)?;
        service.journal = Mutex::new(BrokerJournal::open(directory, target_id, replay_capacity)?);
        Ok(service)
    }

    /// Target-local operation metadata only; no unfiltered response payload is
    /// reconstructed or released by readback, and no provider is contacted.
    pub fn read_attempt(&self, attempt_id: &str) -> RuntimeResult<ReadAttemptMetadata> {
        self.journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .state()?
            .attempts
            .get(attempt_id)
            .cloned()
            .ok_or(RuntimeError::InvalidInput)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        now_ms: u64,
        expected_anchor: &Digest,
        read_law: ReadLaw,
        primary: &mut dyn ProviderTransport,
        parity: Option<&mut dyn ProviderTransport>,
    ) -> RuntimeResult<AttemptResolution> {
        let prepared = self.admit_read(
            request,
            bindings,
            decision,
            now_ms,
            expected_anchor,
            read_law,
        )?;
        let PreparedReadDispatch {
            attempt_id,
            request,
            expected_anchor,
            read_law,
        } = prepared;
        let outcome = match request.class {
            RequestClass::Read | RequestClass::Subscription => self.dispatch_read(
                &request,
                &attempt_id,
                &expected_anchor,
                read_law,
                primary,
                parity,
            ),
            RequestClass::Write => unreachable!("write requests reject before attempt creation"),
        };
        self.record_outcome(&attempt_id, &outcome)?;
        outcome
    }

    /// Deployed read/subscription dispatch through an asynchronous provider.
    /// Capability consumption is durably committed before the first await, and
    /// the terminal outcome is durably committed before a response is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_async(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        now_ms: u64,
        expected_anchor: &Digest,
        read_law: ReadLaw,
        primary: &mut dyn AsyncProviderTransport,
        parity: Option<&mut dyn AsyncProviderTransport>,
    ) -> RuntimeResult<AttemptResolution> {
        let prepared = self.admit_read(
            request,
            bindings,
            decision,
            now_ms,
            expected_anchor,
            read_law,
        )?;
        self.execute_prepared_async(prepared, primary, parity).await
    }

    /// Durably consume one read/subscription capability without contacting a
    /// provider. The trusted target owner supplies the route anchor and retry
    /// law at the same boundary; neither can be replaced when the body later
    /// arrives on Broker's private UDS.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_read(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        now_ms: u64,
        expected_anchor: &Digest,
        read_law: ReadLaw,
    ) -> RuntimeResult<PreparedReadDispatch> {
        // M29 is inactive and unqualified, and no authenticated producer owns the exact
        // signed-transaction hash. Reject before capability inspection, replay consumption,
        // sequence allocation or journal state. A locally synthesized request digest is never a
        // transaction identity.
        if request.class == RequestClass::Write {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let capability = decision
            .capability
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if now_ms >= request.deadline_at_ms || capability.claims.remaining_budget_ms == 0 {
            return Err(RuntimeError::BudgetExhausted);
        }
        if *expected_anchor == Digest::of([])
            || read_law.same_route_retries > 3
            || (read_law.same_route_retries > 0 && read_law.parity_failover)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let attempt_id =
            self.validate_and_consume(capability, request, bindings, decision, now_ms)?;
        Ok(PreparedReadDispatch {
            attempt_id,
            request: request.clone(),
            expected_anchor: expected_anchor.clone(),
            read_law,
        })
    }

    /// Execute exactly one previously admitted dispatch. The prepared object is
    /// consumed by value so a UDS handoff cannot reuse it after any outcome.
    pub async fn execute_prepared_async(
        &self,
        prepared: PreparedReadDispatch,
        primary: &mut dyn AsyncProviderTransport,
        parity: Option<&mut dyn AsyncProviderTransport>,
    ) -> RuntimeResult<AttemptResolution> {
        let PreparedReadDispatch {
            attempt_id,
            request,
            expected_anchor,
            read_law,
        } = prepared;
        let outcome = self
            .dispatch_read_async(
                &request,
                &attempt_id,
                &expected_anchor,
                read_law,
                primary,
                parity,
            )
            .await;
        self.record_outcome(&attempt_id, &outcome)?;
        outcome
    }

    /// Consume a prepared dispatch without contacting a provider and durably
    /// close its attempt. This is used when the private handoff boundary rejects
    /// a substituted body, peer, or expired budget after capability admission.
    pub fn reject_prepared(
        &self,
        prepared: PreparedReadDispatch,
        error: RuntimeError,
    ) -> RuntimeResult<()> {
        let outcome = Err(error);
        self.record_outcome(&prepared.attempt_id, &outcome)
    }

    pub fn reconcile(
        &self,
        attempt_id: &str,
        signed_transaction_hash: &Digest,
        provider: &mut dyn ProviderTransport,
    ) -> RuntimeResult<AttemptResolution> {
        let record = self
            .attempts
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .get(attempt_id)
            .cloned()
            .ok_or(RuntimeError::InvalidInput)?;
        if record.signed_transaction_hash.as_ref() != Some(signed_transaction_hash) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if record.resolution.effect != DecisionEffect::WriteAmbiguity {
            return Err(RuntimeError::InvalidInput);
        }
        let Some(response) = provider.reconcile(signed_transaction_hash) else {
            return Ok(record.resolution.clone());
        };
        self.validate_response(
            &record.reconciliation.request,
            &record.reconciliation.expected_anchor,
            &response,
        )?;
        let resolution = self.success_resolution(attempt_id, &record.request_digest, response)?;
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if attempts.get(attempt_id) != Some(&record) {
            return Err(RuntimeError::Replay);
        }
        attempts.insert(
            attempt_id.to_owned(),
            AttemptRecord {
                request_digest: record.request_digest,
                signed_transaction_hash: Some(signed_transaction_hash.clone()),
                resolution: resolution.clone(),
                reconciliation: record.reconciliation,
            },
        );
        Ok(resolution)
    }

    fn validate_capability(
        &self,
        capability: &SignedEnvelope<BrokerCapability>,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        self.capability_verifier.verify(capability)?;
        let claims = &capability.claims;
        if now_ms < claims.issued_at_ms || now_ms >= claims.expires_at_ms {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        request.validate_digest()?;
        if decision.effect != DecisionEffect::AllowForward
            || decision.pc_code != "PC-RUNTIME-0000"
            || claims.request_digest != request.request_digest
            || claims.request_class != request.class
            || claims.decision_digest != decision.decision_digest
            || claims.target_id != bindings.target_id
            || claims.active_generation_digest != bindings.active_generation_digest
            || claims.route_profile_digest != bindings.route_profile_digest
            || claims.provider_profile_digest != bindings.provider_profile_digest
            || bindings.eligible_provider_profile_ids.len() != 1
            || bindings.eligible_provider_profile_ids.first() != Some(&claims.provider_profile_id)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    fn validate_and_consume(
        &self,
        capability: &SignedEnvelope<BrokerCapability>,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        now_ms: u64,
    ) -> RuntimeResult<String> {
        self.validate_capability(capability, request, bindings, decision, now_ms)?;
        let claims = &capability.claims;
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = guard.state()?.clone();
        if next
            .target_id
            .as_ref()
            .is_some_and(|id| id != &bindings.target_id)
        {
            return Err(RuntimeError::TargetIdentity);
        }
        next.target_id = Some(bindings.target_id.clone());
        // Live admitted records cannot be reclaimed. Terminal and restart-marked
        // interrupted records retain metadata for at least 24 hours.
        next.attempts
            .retain(|_, r| r.status == ReadAttemptStatus::Admitted || r.retain_until_ms > now_ms);
        let retained: std::collections::BTreeSet<_> = next
            .attempts
            .values()
            .map(|r| r.capability_id.clone())
            .collect();
        next.consumed.retain(|id, _| retained.contains(id));
        if next.consumed.contains_key(&claims.capability_id) {
            return Err(RuntimeError::Replay);
        }
        if next.attempts.len() >= self.replay_capacity {
            return Err(RuntimeError::ReplayCapacity);
        }
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(RuntimeError::ReplayCapacity)?;
        let attempt_id = format!("local-attempt-{:016x}", next.sequence);
        let retain_until_ms = now_ms
            .checked_add(86_400_000)
            .ok_or(RuntimeError::InvalidInput)?
            .max(claims.expires_at_ms);
        next.consumed
            .insert(claims.capability_id.clone(), retain_until_ms);
        next.attempts.insert(
            attempt_id.clone(),
            ReadAttemptMetadata {
                request_digest: request.request_digest.clone(),
                decision_digest: decision.decision_digest.clone(),
                generation_digest: claims.active_generation_digest.clone(),
                provider_profile_id: claims.provider_profile_id.clone(),
                capability_id: claims.capability_id.clone(),
                admitted_at_ms: now_ms,
                retain_until_ms,
                status: ReadAttemptStatus::Admitted,
            },
        );
        guard.commit(next)?;
        Ok(attempt_id)
    }

    fn record_outcome(
        &self,
        attempt_id: &str,
        outcome: &RuntimeResult<AttemptResolution>,
    ) -> RuntimeResult<()> {
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = guard.state()?.clone();
        let record = next
            .attempts
            .get_mut(attempt_id)
            .ok_or(RuntimeError::InvalidInput)?;
        if record.status != ReadAttemptStatus::Admitted {
            return Err(RuntimeError::Replay);
        }
        record.status = match outcome {
            Ok(result) => ReadAttemptStatus::Completed {
                effect: result.effect,
                pc_code: result.pc_code.clone(),
                evidence_digest: result.evidence_digest.clone(),
                response_digest: result
                    .response
                    .as_ref()
                    .ok_or(RuntimeError::ResponseWithheld)?
                    .response_digest
                    .clone(),
            },
            Err(error) => ReadAttemptStatus::Failed {
                pc_code: error.pc_code().into(),
            },
        };
        guard.commit(next)
    }

    fn dispatch_read(
        &self,
        request: &RuntimeRequest,
        attempt_id: &str,
        expected_anchor: &Digest,
        law: ReadLaw,
        primary: &mut dyn ProviderTransport,
        parity: Option<&mut dyn ProviderTransport>,
    ) -> RuntimeResult<AttemptResolution> {
        if law.same_route_retries > 3 || (law.same_route_retries > 0 && law.parity_failover) {
            return Err(RuntimeError::InvalidInput);
        }
        let mut outcome = primary.send(request, attempt_id);
        for _ in 0..law.same_route_retries {
            if outcome != ProviderOutcome::TransientUnavailable {
                break;
            }
            outcome = primary.send(request, attempt_id);
        }
        if outcome == ProviderOutcome::TransientUnavailable && law.parity_failover {
            let parity = parity.ok_or(RuntimeError::RuntimeUnavailable)?;
            outcome = parity.send(request, attempt_id);
        }
        match outcome {
            ProviderOutcome::Response(response) => {
                self.validate_response(request, expected_anchor, &response)?;
                self.success_resolution(attempt_id, &request.request_digest, response)
            }
            ProviderOutcome::TransientUnavailable | ProviderOutcome::UnknownWriteOutcome => {
                Err(RuntimeError::RuntimeUnavailable)
            }
            ProviderOutcome::Rejected(error) => Err(error),
        }
    }

    async fn dispatch_read_async(
        &self,
        request: &RuntimeRequest,
        attempt_id: &str,
        expected_anchor: &Digest,
        law: ReadLaw,
        primary: &mut dyn AsyncProviderTransport,
        parity: Option<&mut dyn AsyncProviderTransport>,
    ) -> RuntimeResult<AttemptResolution> {
        if law.same_route_retries > 3 || (law.same_route_retries > 0 && law.parity_failover) {
            return Err(RuntimeError::InvalidInput);
        }
        let mut outcome = primary.send(request, attempt_id).await;
        for _ in 0..law.same_route_retries {
            if outcome != ProviderOutcome::TransientUnavailable {
                break;
            }
            outcome = primary.send(request, attempt_id).await;
        }
        if outcome == ProviderOutcome::TransientUnavailable && law.parity_failover {
            let parity = parity.ok_or(RuntimeError::RuntimeUnavailable)?;
            outcome = parity.send(request, attempt_id).await;
        }
        match outcome {
            ProviderOutcome::Response(response) => {
                self.validate_response(request, expected_anchor, &response)?;
                self.success_resolution(attempt_id, &request.request_digest, response)
            }
            ProviderOutcome::TransientUnavailable | ProviderOutcome::UnknownWriteOutcome => {
                Err(RuntimeError::RuntimeUnavailable)
            }
            ProviderOutcome::Rejected(error) => Err(error),
        }
    }

    fn validate_response(
        &self,
        request: &RuntimeRequest,
        expected_anchor: &Digest,
        response: &ProviderResponse,
    ) -> RuntimeResult<()> {
        if response.request_id != request.request_id
            || !response.complete
            || response.anchor_digest != *expected_anchor
            || response.body.len() as u64 > request.response_budget_bytes
            || response.response_digest != Digest::of(&response.body)
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        Ok(())
    }

    fn success_resolution(
        &self,
        attempt_id: &str,
        request_digest: &Digest,
        response: ProviderResponse,
    ) -> RuntimeResult<AttemptResolution> {
        Ok(AttemptResolution {
            attempt_id: attempt_id.to_owned(),
            request_digest: request_digest.clone(),
            signed_transaction_hash: None,
            effect: DecisionEffect::AllowForward,
            pc_code: "PC-RUNTIME-0000".to_owned(),
            evidence_digest: Digest::of(canonical_bytes(&(
                attempt_id,
                request_digest,
                &response.response_digest,
            ))?),
            response: Some(response),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pc_runtime_types::{
        BrokerCapability, DecisionEffect, PURPOSE_BROKER_CAPABILITY_V1, PurposeSigner,
        RequestClass, RuntimeDecision, Transport,
    };

    use super::*;

    #[derive(Clone)]
    pub(super) struct MockProvider {
        pub(super) outcomes: Vec<ProviderOutcome>,
        pub(super) calls: usize,
        pub(super) reconciliation: Option<ProviderResponse>,
        pub(super) reconciliation_calls: usize,
    }

    impl ProviderTransport for MockProvider {
        fn send(&mut self, _request: &RuntimeRequest, _attempt_id: &str) -> ProviderOutcome {
            let outcome = self
                .outcomes
                .get(self.calls)
                .cloned()
                .unwrap_or(ProviderOutcome::TransientUnavailable);
            self.calls += 1;
            outcome
        }

        fn reconcile(&mut self, _signed_transaction_hash: &Digest) -> Option<ProviderResponse> {
            self.reconciliation_calls += 1;
            self.reconciliation.clone()
        }
    }

    impl AsyncProviderTransport for MockProvider {
        fn send<'a>(
            &'a mut self,
            request: &'a RuntimeRequest,
            attempt_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
            Box::pin(async move { ProviderTransport::send(self, request, attempt_id) })
        }
    }

    pub(super) fn digest(value: &str) -> Digest {
        Digest::of(value)
    }

    pub(super) fn request(class: RequestClass) -> RuntimeRequest {
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "request-1".into(),
            method: if class == RequestClass::Write {
                "eth_sendRawTransaction"
            } else {
                "eth_call"
            }
            .into(),
            params_digest: digest("params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: digest("placeholder"),
            class,
            received_at_ms: 100,
            deadline_at_ms: 200,
            response_budget_bytes: 128,
            invocation: None,
        };
        request.request_digest = request.computed_digest().unwrap();
        request
    }

    pub(super) fn bindings() -> RuntimeBindings {
        RuntimeBindings {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            workload_id: "workload-1".into(),
            target_id: "target-1".into(),
            active_generation_digest: digest("generation"),
            observed_generation_digest: digest("generation"),
            policy_generation_digest: digest("policy"),
            expected_policy_generation_digest: digest("policy"),
            fact_generation_digest: digest("facts"),
            expected_fact_generation_digest: digest("facts"),
            route_profile_digest: digest("route"),
            expected_route_profile_digest: digest("route"),
            eligible_provider_profile_ids: vec!["provider-1".into()],
            provider_profile_digest: digest("provider"),
            expected_provider_profile_digest: digest("provider"),
        }
    }

    pub(super) fn decision(class: RequestClass, capability_id: &str) -> RuntimeDecision {
        let decision_digest = digest("decision");
        let claims = BrokerCapability {
            capability_id: capability_id.into(),
            request_digest: request(class).request_digest,
            decision_digest: decision_digest.clone(),
            target_id: "target-1".into(),
            active_generation_digest: digest("generation"),
            route_profile_digest: digest("route"),
            provider_profile_id: "provider-1".into(),
            provider_profile_digest: digest("provider"),
            request_class: class,
            issued_at_ms: 100,
            expires_at_ms: 150,
            remaining_budget_ms: 50,
        };
        RuntimeDecision {
            decision_id: "decision-1".into(),
            effect: DecisionEffect::AllowForward,
            pc_code: "PC-RUNTIME-0000".into(),
            active_generation_digest: digest("generation"),
            decision_input_digest: digest("input"),
            decision_digest,
            capability: Some(
                PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32])
                    .unwrap()
                    .sign(claims)
                    .unwrap(),
            ),
            protective_degradation: false,
        }
    }

    fn broker(replay_capacity: usize) -> BrokerService {
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        BrokerService::new(&signer.verifier().sec1_bytes(), replay_capacity).unwrap()
    }

    pub(super) fn response() -> ProviderResponse {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#.to_vec();
        ProviderResponse {
            request_id: "request-1".into(),
            response_digest: Digest::of(&body),
            anchor_digest: digest("anchor"),
            body,
            complete: true,
        }
    }

    #[test]
    fn read_retry_and_failover_are_mutually_exclusive() {
        let broker = broker(8);
        let mut primary = MockProvider {
            outcomes: vec![
                ProviderOutcome::TransientUnavailable,
                ProviderOutcome::Response(response()),
            ],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        let resolution = broker
            .dispatch(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-1"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 1,
                    parity_failover: false,
                },
                &mut primary,
                None,
            )
            .unwrap();
        assert_eq!(resolution.effect, DecisionEffect::AllowForward);
        assert_eq!(primary.calls, 2);

        let mut another = MockProvider {
            outcomes: vec![],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        assert_eq!(
            broker.dispatch(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-2"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 1,
                    parity_failover: true
                },
                &mut another,
                None,
            ),
            Err(RuntimeError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn async_dispatch_commits_admission_and_terminal_result_around_provider_await() {
        let broker = broker(8);
        let mut provider = MockProvider {
            outcomes: vec![
                ProviderOutcome::TransientUnavailable,
                ProviderOutcome::Response(response()),
            ],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        let result = broker
            .dispatch_async(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-async"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 1,
                    parity_failover: false,
                },
                &mut provider,
                None,
            )
            .await
            .unwrap();
        assert_eq!(provider.calls, 2);
        assert!(matches!(
            broker.read_attempt(&result.attempt_id).unwrap().status,
            ReadAttemptStatus::Completed { .. }
        ));

        let mut replay = MockProvider {
            outcomes: vec![ProviderOutcome::Response(response())],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        assert_eq!(
            broker
                .dispatch_async(
                    &request(RequestClass::Read),
                    &bindings(),
                    &decision(RequestClass::Read, "cap-async"),
                    110,
                    &digest("anchor"),
                    ReadLaw {
                        same_route_retries: 0,
                        parity_failover: false,
                    },
                    &mut replay,
                    None,
                )
                .await,
            Err(RuntimeError::Replay)
        );
        assert_eq!(replay.calls, 0);
    }

    #[tokio::test]
    async fn prepared_dispatch_separates_durable_admission_from_single_provider_contact() {
        let broker = broker(8);
        let prepared = broker
            .admit_read(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-handoff"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false,
                },
            )
            .unwrap();
        assert!(matches!(
            broker.read_attempt(&prepared.attempt_id).unwrap().status,
            ReadAttemptStatus::Admitted
        ));
        let mut provider = MockProvider {
            outcomes: vec![ProviderOutcome::Response(response())],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        let result = broker
            .execute_prepared_async(prepared, &mut provider, None)
            .await
            .unwrap();
        assert_eq!(provider.calls, 1);
        assert!(matches!(
            broker.read_attempt(&result.attempt_id).unwrap().status,
            ReadAttemptStatus::Completed { .. }
        ));
        let replay = MockProvider {
            outcomes: vec![ProviderOutcome::Response(response())],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        assert!(
            broker
                .admit_read(
                    &request(RequestClass::Read),
                    &bindings(),
                    &decision(RequestClass::Read, "cap-handoff"),
                    110,
                    &digest("anchor"),
                    ReadLaw {
                        same_route_retries: 0,
                        parity_failover: false,
                    },
                )
                .is_err()
        );
        assert_eq!(replay.calls, 0);
    }

    #[test]
    fn rejected_prepared_dispatch_is_terminal_and_restart_safe() {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("broker-reject-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        let broker =
            BrokerService::open("target-1", &signer.verifier().sec1_bytes(), 8, &root).unwrap();
        let prepared = broker
            .admit_read(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-rejected-handoff"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false,
                },
            )
            .unwrap();
        let attempt_id = prepared.attempt_id.clone();
        broker
            .reject_prepared(prepared, RuntimeError::InvalidAuthorization)
            .unwrap();
        assert_eq!(
            broker.read_attempt(&attempt_id).unwrap().status,
            ReadAttemptStatus::Failed {
                pc_code: "PC-RUNTIME-3004".into()
            }
        );
        drop(broker);
        let reopened =
            BrokerService::open("target-1", &signer.verifier().sec1_bytes(), 8, &root).unwrap();
        assert!(matches!(
            reopened.read_attempt(&attempt_id).unwrap().status,
            ReadAttemptStatus::Failed { .. }
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inactive_unqualified_m29_is_zero_send_and_has_no_synthetic_hash() {
        let broker = broker(8);
        let mut provider = MockProvider {
            outcomes: vec![
                ProviderOutcome::UnknownWriteOutcome,
                ProviderOutcome::Response(response()),
            ],
            calls: 0,
            reconciliation: Some(response()),
            reconciliation_calls: 0,
        };
        assert_eq!(
            broker.dispatch(
                &request(RequestClass::Write),
                &bindings(),
                &decision(RequestClass::Write, "cap-write"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false,
                },
                &mut provider,
                None,
            ),
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(provider.calls, 0);
        assert_eq!(provider.reconciliation_calls, 0);
        assert_eq!(
            broker.reconcile("uncreated-attempt", &digest("caller-hash"), &mut provider),
            Err(RuntimeError::InvalidInput)
        );
        assert_eq!(provider.reconciliation_calls, 0);
    }

    #[test]
    fn response_tamper_is_withheld() {
        let broker = broker(8);
        let mut bad = response();
        bad.response_digest = digest("forged");
        let mut provider = MockProvider {
            outcomes: vec![ProviderOutcome::Response(bad)],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        assert_eq!(
            broker.dispatch(
                &request(RequestClass::Read),
                &bindings(),
                &decision(RequestClass::Read, "cap-bad"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false
                },
                &mut provider,
                None,
            ),
            Err(RuntimeError::ResponseWithheld)
        );
    }

    #[test]
    fn request_or_decision_mutation_cannot_reuse_a_capability() {
        let broker = broker(8);
        let mut altered_request = request(RequestClass::Read);
        altered_request.method = "eth_getBlockByNumber".into();
        let mut provider = MockProvider {
            outcomes: vec![ProviderOutcome::Response(response())],
            calls: 0,
            reconciliation: None,
            reconciliation_calls: 0,
        };
        assert_eq!(
            broker.dispatch(
                &altered_request,
                &bindings(),
                &decision(RequestClass::Read, "cap-request-tamper"),
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false
                },
                &mut provider,
                None,
            ),
            Err(RuntimeError::InvalidInput)
        );
        assert_eq!(provider.calls, 0);

        let exact_request = request(RequestClass::Read);
        let mut altered_decision = decision(RequestClass::Read, "cap-decision-tamper");
        altered_decision.effect = DecisionEffect::DenyTerminal;
        assert_eq!(
            broker.dispatch(
                &exact_request,
                &bindings(),
                &altered_decision,
                110,
                &digest("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false
                },
                &mut provider,
                None,
            ),
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(provider.calls, 0);
    }

    #[test]
    fn capability_is_single_use_under_concurrency() {
        let broker = Arc::new(broker(8));
        let request = Arc::new(request(RequestClass::Read));
        let bindings = Arc::new(bindings());
        let decision = Arc::new(decision(RequestClass::Read, "cap-race"));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let broker = Arc::clone(&broker);
            let request = Arc::clone(&request);
            let bindings = Arc::clone(&bindings);
            let decision = Arc::clone(&decision);
            handles.push(std::thread::spawn(move || {
                let mut provider = MockProvider {
                    outcomes: vec![ProviderOutcome::Response(response())],
                    calls: 0,
                    reconciliation: None,
                    reconciliation_calls: 0,
                };
                broker.dispatch(
                    &request,
                    &bindings,
                    &decision,
                    110,
                    &digest("anchor"),
                    ReadLaw {
                        same_route_retries: 0,
                        parity_failover: false,
                    },
                    &mut provider,
                    None,
                )
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(RuntimeError::Replay))
                .count(),
            1
        );
    }
}

#[cfg(test)]
mod durability_tests;
