//! Request-local Broker adapter for an admitted, pinned Multi-RPC connection.
//! The target owner constructs this only after decoding the workload body into
//! the exact `RuntimeRequest`; neither URL nor TLS material comes from the call.

use crate::request_decode::DecodedProtectedRequest;
use crate::request_route::CapturedRequestRoute;
use openpc_broker::{AsyncProviderTransport, ProviderOutcome};
use openpc_multi_rpc::provider_connection::{ConnectionError, ConnectionLease};
use openpc_multi_rpc::route_witness::VerifiedChainAnchor;
use pc_runtime_types::{Digest, ProviderResponse, RuntimeError, RuntimeRequest};
use std::sync::Arc;
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

pub struct PinnedProviderTransport {
    target: Arc<CapturedRequestRoute>,
    // Retaining the registry lease fences provider retirement and replacement
    // through response validation. An extracted connection would detach the
    // request from the route owner's installed generation.
    connection: Arc<ConnectionLease>,
    decoded: Arc<DecodedProtectedRequest>,
    provider_body: Vec<u8>,
    expected_anchor: Digest,
    anchor: VerifiedChainAnchor,
    valid_until_ns: u64,
}

impl PinnedProviderTransport {
    /// The protected request retains the same connection lease through response
    /// release. The immutable decoder product supplies both the request and its
    /// bytes; callers cannot independently choose a body for an allowed digest.
    pub(crate) fn new(
        target: Arc<CapturedRequestRoute>,
        connection: Arc<ConnectionLease>,
        decoded: Arc<DecodedProtectedRequest>,
        anchor: &VerifiedChainAnchor,
    ) -> Result<Self, RuntimeError> {
        let request = decoded.request();
        request.validate_digest()?;
        if request.method.is_empty() || request.request_id.is_empty() {
            return Err(RuntimeError::InvalidInput);
        }
        let provider_body = decoded.hash_pinned_provider_body(anchor)?;
        anchor.revalidate_time(crate::target_state::wall_clock_ns()?)?;
        Ok(Self {
            target,
            connection,
            decoded,
            provider_body,
            expected_anchor: anchor.anchor().semantic_digest()?,
            anchor: anchor.clone(),
            valid_until_ns: anchor.valid_until_ns(),
        })
    }

    pub(crate) fn limit_validity(mut self, valid_until_ns: u64) -> Result<Self, RuntimeError> {
        self.valid_until_ns = self.valid_until_ns.min(valid_until_ns);
        self.revalidate_time(crate::target_state::wall_clock_ns()?)?;
        Ok(self)
    }

    fn revalidate_time(&self, now_ns: u64) -> Result<(), RuntimeError> {
        self.anchor.revalidate_time(now_ns)?;
        if now_ns >= self.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }

    fn revalidate_target(&self) -> Result<(), RuntimeError> {
        // This is a synchronous, short lease. It must be released before the
        // provider await so revocation and generation cutover can proceed.
        self.target.revalidate_dispatch()?;
        self.revalidate_time(crate::target_state::wall_clock_ns()?)?;
        Ok(())
    }
}

impl AsyncProviderTransport for PinnedProviderTransport {
    fn send<'a>(
        &'a mut self,
        request: &'a RuntimeRequest,
        attempt_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
        Box::pin(async move {
            if request.validate_digest().is_err() || request != self.decoded.request() {
                return ProviderOutcome::Rejected(RuntimeError::InvalidAuthorization);
            }
            if let Err(error) = self.revalidate_target() {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"provider_dispatch_rejected","stage":"target_revalidation","requestId":request.request_id,"attemptId":attempt_id,"pcCode":error.pc_code()})
                );
                return ProviderOutcome::Rejected(error);
            }
            let now_ms = match wall_clock_ms() {
                Ok(value) => value,
                Err(error) => return ProviderOutcome::Rejected(error),
            };
            let deadline_ms = request.deadline_at_ms.min(self.valid_until_ns / 1_000_000);
            let Some(remaining_ms) = deadline_ms.checked_sub(now_ms) else {
                return ProviderOutcome::Rejected(RuntimeError::BudgetExhausted);
            };
            if remaining_ms == 0 {
                return ProviderOutcome::Rejected(RuntimeError::BudgetExhausted);
            }
            let Some(deadline) = Instant::now().checked_add(Duration::from_millis(remaining_ms))
            else {
                return ProviderOutcome::Rejected(RuntimeError::BudgetExhausted);
            };
            let connection = match self.connection.connection() {
                Ok(connection) => connection,
                Err(ConnectionError::Expired) => {
                    return ProviderOutcome::Rejected(RuntimeError::BudgetExhausted);
                }
                Err(
                    ConnectionError::Endpoint
                    | ConnectionError::Destination
                    | ConnectionError::Tls
                    | ConnectionError::Unavailable
                    | ConnectionError::Response
                    | ConnectionError::RequestLimit
                    | ConnectionError::Generation
                    | ConnectionError::NotInstalled
                    | ConnectionError::Capacity
                    | ConnectionError::Owner,
                ) => return ProviderOutcome::Rejected(RuntimeError::RuntimeUnavailable),
            };
            eprintln!(
                "{}",
                serde_json::json!({"event":"provider_dispatch_started","requestId":request.request_id,"attemptId":attempt_id,"method":request.method})
            );
            match connection
                .post_json(self.provider_body.clone(), deadline)
                .await
            {
                Ok(body) => {
                    if let Err(error) = self.revalidate_target() {
                        eprintln!(
                            "{}",
                            serde_json::json!({"event":"provider_response_rejected","stage":"target_revalidation","requestId":request.request_id,"attemptId":attempt_id,"pcCode":error.pc_code()})
                        );
                        return ProviderOutcome::Rejected(error);
                    }
                    let body = match self.target.filter_provider_response(&body) {
                        Ok(filtered) => filtered,
                        Err(error) => return ProviderOutcome::Rejected(error),
                    };
                    match wall_clock_ms() {
                        Ok(now) if now < request.deadline_at_ms => {}
                        Ok(_) => return ProviderOutcome::Rejected(RuntimeError::BudgetExhausted),
                        Err(error) => return ProviderOutcome::Rejected(error),
                    }
                    ProviderOutcome::Response(ProviderResponse {
                        request_id: request.request_id.clone(),
                        response_digest: Digest::of(&body),
                        // This identifies the verified hash-pinned dispatch. The
                        // canonical owner must still revalidate before release.
                        anchor_digest: self.expected_anchor.clone(),
                        body,
                        complete: true,
                    })
                }
                Err(ConnectionError::Unavailable) => ProviderOutcome::TransientUnavailable,
                Err(ConnectionError::Expired) => {
                    ProviderOutcome::Rejected(RuntimeError::BudgetExhausted)
                }
                Err(ConnectionError::RequestLimit | ConnectionError::Response) => {
                    ProviderOutcome::Rejected(RuntimeError::ResponseWithheld)
                }
                Err(
                    ConnectionError::Endpoint
                    | ConnectionError::Destination
                    | ConnectionError::Tls
                    | ConnectionError::Generation
                    | ConnectionError::NotInstalled
                    | ConnectionError::Capacity
                    | ConnectionError::Owner,
                ) => ProviderOutcome::Rejected(RuntimeError::RuntimeUnavailable),
            }
        })
    }
}

fn wall_clock_ms() -> Result<u64, RuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}
