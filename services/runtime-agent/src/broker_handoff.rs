//! Bounded one-use handoff from ext_proc authorization to Broker's private UDS.
//! Request bodies and prepared dispatches live only in memory; Broker's journal
//! remains the durable owner of capability consumption and terminal outcomes.

use openpc_broker::{AsyncProviderTransport, BrokerService, PreparedReadDispatch};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

struct Entry {
    body: Vec<u8>,
    deadline_at_ms: u64,
    dispatch: Dispatch,
}
enum Dispatch {
    Read(Box<ReadDispatch>),
    Submission(Box<crate::request_route::CapturedSubmission>),
}
struct ReadDispatch {
    prepared: PreparedReadDispatch,
    primary: Box<dyn AsyncProviderTransport>,
    parity: Option<Box<dyn AsyncProviderTransport>>,
}
impl Entry {
    fn reject(self, broker: &BrokerService, error: RuntimeError) -> RuntimeResult<()> {
        match self.dispatch {
            Dispatch::Read(read) => broker.reject_prepared(read.prepared, error),
            Dispatch::Submission(submission) => submission.reject(&error),
        }
    }
}

struct State {
    body_bytes: usize,
    entries: BTreeMap<String, Entry>,
}

pub struct BrokerHandoffStore {
    broker: Arc<BrokerService>,
    submissions: Option<Arc<openpc_broker::write_dispatch::SubmissionBroker>>,
    capacity: usize,
    body_capacity_bytes: usize,
    state: Mutex<State>,
}

impl BrokerHandoffStore {
    pub fn new(
        broker: Arc<BrokerService>,
        capacity: usize,
        body_capacity_bytes: usize,
    ) -> RuntimeResult<Self> {
        if capacity == 0 || capacity > 4096 || body_capacity_bytes == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            broker,
            submissions: None,
            capacity,
            body_capacity_bytes,
            state: Mutex::new(State {
                body_bytes: 0,
                entries: BTreeMap::new(),
            }),
        })
    }

    pub fn with_submissions(
        mut self,
        submissions: Arc<openpc_broker::write_dispatch::SubmissionBroker>,
    ) -> RuntimeResult<Self> {
        if !submissions.uses_broker(&self.broker) {
            return Err(RuntimeError::TargetIdentity);
        }
        self.submissions = Some(submissions);
        Ok(self)
    }

    pub(crate) fn submissions(
        &self,
    ) -> Option<Arc<openpc_broker::write_dispatch::SubmissionBroker>> {
        self.submissions.clone()
    }

    /// Publish an opaque token after Broker has durably admitted the exact
    /// request. The transports already own their route-generation leases.
    pub fn publish(
        &self,
        prepared: PreparedReadDispatch,
        body: Vec<u8>,
        primary: Box<dyn AsyncProviderTransport>,
        parity: Option<Box<dyn AsyncProviderTransport>>,
    ) -> RuntimeResult<String> {
        let deadline_at_ms = prepared.deadline_at_ms();
        self.insert(Entry {
            body,
            deadline_at_ms,
            dispatch: Dispatch::Read(Box::new(ReadDispatch {
                prepared,
                primary,
                parity,
            })),
        })
    }

    pub(crate) fn publish_submission(
        &self,
        prepared: crate::request_route::CapturedSubmission,
        body: Vec<u8>,
    ) -> RuntimeResult<String> {
        if self
            .submissions
            .as_ref()
            .is_none_or(|broker| !prepared.owned_by(broker))
        {
            prepared.reject(&RuntimeError::TargetIdentity)?;
            return Err(RuntimeError::TargetIdentity);
        }
        let deadline_at_ms = prepared.deadline_at_ms();
        self.insert(Entry {
            body,
            deadline_at_ms,
            dispatch: Dispatch::Submission(Box::new(prepared)),
        })
    }

    fn insert(&self, entry: Entry) -> RuntimeResult<String> {
        if entry.body.is_empty() || entry.body.len() > 4 * 1024 * 1024 {
            entry.reject(&self.broker, RuntimeError::InvalidInput)?;
            return Err(RuntimeError::InvalidInput);
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                drop(poisoned);
                entry.reject(&self.broker, RuntimeError::RuntimeUnavailable)?;
                return Err(RuntimeError::RuntimeUnavailable);
            }
        };
        let next_bytes = state.body_bytes.checked_add(entry.body.len());
        if state.entries.len() >= self.capacity
            || next_bytes.is_none_or(|bytes| bytes > self.body_capacity_bytes)
        {
            drop(state);
            entry.reject(&self.broker, RuntimeError::ReplayCapacity)?;
            return Err(RuntimeError::ReplayCapacity);
        }
        let token = uuid::Uuid::now_v7().to_string();
        state.entries.insert(token.clone(), entry);
        state.body_bytes = next_bytes.ok_or(RuntimeError::RuntimeUnavailable)?;
        Ok(token)
    }

    /// Remove before any await. A token therefore authorizes at most one
    /// provider execution even when requests race or the provider times out.
    pub async fn execute(&self, token: &str, presented_body: &[u8]) -> RuntimeResult<Vec<u8>> {
        validate_token(token)?;
        let entry = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            let entry = state
                .entries
                .remove(token)
                .ok_or(RuntimeError::InvalidAuthorization)?;
            state.body_bytes = state
                .body_bytes
                .checked_sub(entry.body.len())
                .ok_or(RuntimeError::RuntimeUnavailable)?;
            entry
        };
        if entry.body.as_slice() != presented_body {
            entry.reject(&self.broker, RuntimeError::InvalidAuthorization)?;
            return Err(RuntimeError::InvalidAuthorization);
        }
        let read = match entry.dispatch {
            Dispatch::Read(read) => read,
            Dispatch::Submission(submission) => return submission.execute_response().await,
        };
        let ReadDispatch {
            prepared,
            mut primary,
            parity,
        } = *read;
        let resolution = match parity {
            Some(mut parity) => {
                self.broker
                    .execute_prepared_async(prepared, primary.as_mut(), Some(parity.as_mut()))
                    .await
            }
            None => {
                self.broker
                    .execute_prepared_async(prepared, primary.as_mut(), None)
                    .await
            }
        }?;
        resolution
            .response
            .map(|response| response.body)
            .ok_or(RuntimeError::ResponseWithheld)
    }

    /// Close expired volatile entries without provider contact. This prevents a
    /// live target from exhausting the handoff bound when Envoy abandons calls.
    pub fn reap_expired(&self, now_ms: u64) -> RuntimeResult<usize> {
        let expired = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            let tokens: Vec<_> = state
                .entries
                .iter()
                .filter(|(_, entry)| now_ms >= entry.deadline_at_ms)
                .map(|(token, _)| token.clone())
                .collect();
            let mut expired = Vec::with_capacity(tokens.len());
            for token in tokens {
                if let Some(entry) = state.entries.remove(&token) {
                    state.body_bytes = state
                        .body_bytes
                        .checked_sub(entry.body.len())
                        .ok_or(RuntimeError::RuntimeUnavailable)?;
                    expired.push(entry);
                }
            }
            expired
        };
        let count = expired.len();
        let mut failure = None;
        for entry in expired {
            if let Err(error) = entry.reject(&self.broker, RuntimeError::BudgetExhausted) {
                failure.get_or_insert(error);
            }
        }
        let durable_count = if let Some(submissions) = &self.submissions {
            match submissions.expire(now_ms) {
                Ok(count) => count,
                Err(error) => {
                    failure.get_or_insert(error);
                    0
                }
            }
        } else {
            0
        };
        failure.map_or(Ok(count + durable_count), Err)
    }
}

fn validate_token(token: &str) -> RuntimeResult<()> {
    let parsed = uuid::Uuid::parse_str(token).map_err(|_| RuntimeError::InvalidAuthorization)?;
    if parsed.get_version_num() != 7 || parsed.to_string() != token {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpc_broker::{ProviderOutcome, ReadAttemptStatus, ReadLaw};
    use pc_runtime_types::{
        BrokerCapability, DecisionEffect, Digest, PURPOSE_BROKER_CAPABILITY_V1, ProviderResponse,
        PurposeSigner, RequestClass, RuntimeBindings, RuntimeDecision, RuntimeRequest, Transport,
    };
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Provider {
        calls: Arc<AtomicUsize>,
    }
    impl AsyncProviderTransport for Provider {
        fn send<'a>(
            &'a mut self,
            request: &'a RuntimeRequest,
            _attempt_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                let body = br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#.to_vec();
                ProviderOutcome::Response(ProviderResponse {
                    request_id: request.request_id.clone(),
                    response_digest: Digest::of(&body),
                    anchor_digest: Digest::of("anchor"),
                    body,
                    complete: true,
                })
            })
        }
    }

    fn fixture(capability_id: &str) -> (RuntimeRequest, RuntimeBindings, RuntimeDecision) {
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "request-1".into(),
            method: "eth_call".into(),
            params_digest: Digest::of("params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of("pending"),
            class: RequestClass::Read,
            received_at_ms: 100,
            deadline_at_ms: 200,
            response_budget_bytes: 128,
            invocation: None,
        };
        request.request_digest = request.computed_digest().unwrap();
        let bindings = RuntimeBindings {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            workload_id: "workload-1".into(),
            target_id: "target-1".into(),
            active_generation_digest: Digest::of("generation"),
            observed_generation_digest: Digest::of("generation"),
            policy_generation_digest: Digest::of("policy"),
            expected_policy_generation_digest: Digest::of("policy"),
            fact_generation_digest: Digest::of("facts"),
            expected_fact_generation_digest: Digest::of("facts"),
            route_profile_digest: Digest::of("route"),
            expected_route_profile_digest: Digest::of("route"),
            eligible_provider_profile_ids: vec!["provider-1".into()],
            provider_profile_digest: Digest::of("provider"),
            expected_provider_profile_digest: Digest::of("provider"),
        };
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        let decision_digest = Digest::of("decision");
        let capability = signer
            .sign(BrokerCapability {
                capability_id: capability_id.into(),
                request_digest: request.request_digest.clone(),
                decision_digest: decision_digest.clone(),
                target_id: bindings.target_id.clone(),
                active_generation_digest: bindings.active_generation_digest.clone(),
                route_profile_digest: bindings.route_profile_digest.clone(),
                provider_profile_id: "provider-1".into(),
                provider_profile_digest: bindings.provider_profile_digest.clone(),
                request_class: RequestClass::Read,
                issued_at_ms: 100,
                expires_at_ms: 190,
                remaining_budget_ms: 80,
            })
            .unwrap();
        let decision = RuntimeDecision {
            decision_id: format!("decision-{capability_id}"),
            effect: DecisionEffect::AllowForward,
            pc_code: "PC-RUNTIME-0000".into(),
            active_generation_digest: bindings.active_generation_digest.clone(),
            decision_input_digest: Digest::of("input"),
            decision_digest,
            capability: Some(capability),
            protective_degradation: false,
        };
        (request, bindings, decision)
    }

    fn store() -> (Arc<BrokerService>, BrokerHandoffStore) {
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        let broker = Arc::new(BrokerService::new(&signer.verifier().sec1_bytes(), 8).unwrap());
        let store = BrokerHandoffStore::new(broker.clone(), 4, 1024).unwrap();
        (broker, store)
    }

    fn prepare(broker: &BrokerService, capability_id: &str) -> PreparedReadDispatch {
        let (request, bindings, decision) = fixture(capability_id);
        broker
            .admit_read(
                &request,
                &bindings,
                &decision,
                110,
                &Digest::of("anchor"),
                ReadLaw {
                    same_route_retries: 0,
                    parity_failover: false,
                },
            )
            .unwrap()
    }

    #[tokio::test]
    async fn token_body_substitution_and_replay_never_contact_provider() {
        let (broker, store) = store();
        let calls = Arc::new(AtomicUsize::new(0));
        let prepared = prepare(&broker, "cap-substitution");
        let attempt_id = prepared.attempt_id().to_owned();
        let token = store
            .publish(
                prepared,
                b"original".to_vec(),
                Box::new(Provider {
                    calls: calls.clone(),
                }),
                None,
            )
            .unwrap();
        assert_eq!(
            store.execute(&token, b"substituted").await,
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            broker.read_attempt(&attempt_id).unwrap().status,
            ReadAttemptStatus::Failed { .. }
        ));
        assert_eq!(
            store.execute(&token, b"original").await,
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn valid_handoff_contacts_once_and_expired_abandonment_contacts_never() {
        let (broker, store) = store();
        let calls = Arc::new(AtomicUsize::new(0));
        let token = store
            .publish(
                prepare(&broker, "cap-valid"),
                b"exact".to_vec(),
                Box::new(Provider {
                    calls: calls.clone(),
                }),
                None,
            )
            .unwrap();
        store.execute(&token, b"exact").await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            store.execute(&token, b"exact").await,
            Err(RuntimeError::InvalidAuthorization)
        );
        store
            .publish(
                prepare(&broker, "cap-expired"),
                b"abandoned".to_vec(),
                Box::new(Provider {
                    calls: calls.clone(),
                }),
                None,
            )
            .unwrap();
        assert_eq!(store.reap_expired(200).unwrap(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
