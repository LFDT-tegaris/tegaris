//! MRPC-CONTRACT-005 connection safety. These locally prepared objects are not
//! route admission or invocation authority. The routing owner must supply the
//! authenticated endpoint/policy and retain its eligibility fence through use.
mod endpoint;
mod owner;
mod tls;

pub use endpoint::{
    DestinationPolicy, EndpointDescriptor, NetworkRange, PreparedEndpoint, Resolution,
};
pub use owner::{ConnectionLease, ConnectionRecord, ConnectionRegistry, ConnectionStatus};
pub use tls::{LocalTlsMaterial, ProviderTlsMaterial, ServerTlsMaterial};

use pc_runtime_types::Digest;

use reqwest::{
    Client,
    dns::{Addrs, Name, Resolve, Resolving},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, timeout_at};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectionError {
    #[error("provider endpoint rejected")]
    Endpoint,
    #[error("provider destination rejected")]
    Destination,
    #[error("provider TLS identity rejected")]
    Tls,
    #[error("provider connection expired")]
    Expired,
    #[error("provider transport unavailable")]
    Unavailable,
    #[error("provider response rejected")]
    Response,
    #[error("provider request limit exceeded")]
    RequestLimit,
    #[error("provider connection generation changed")]
    Generation,
    #[error("provider connection is not installed")]
    NotInstalled,
    #[error("provider connection capacity exhausted")]
    Capacity,
    #[error("provider connection owner unavailable")]
    Owner,
}

/// A resolver containing only an already checked answer. It cannot query DNS,
/// even if the HTTP library unexpectedly asks for a different name.
struct PinnedResolver {
    hostname: String,
    addresses: Vec<SocketAddr>,
}
impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let matches = name.as_str() == self.hostname;
        let addresses = self.addresses.clone();
        Box::pin(async move {
            if !matches {
                return Err(std::io::Error::other("unbound destination").into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

/// No caller-supplied URL, headers, proxy, redirect or DNS resolver is accepted
/// at dispatch. The result is still untrusted provider data: Broker must apply
/// its response contract, anchor checks and disclosure policy before release.
pub struct ProviderConnection {
    client: Client,
    endpoint: PreparedEndpoint,
    expires: Instant,
    maximum_request_bytes: usize,
    maximum_response_bytes: usize,
    configuration_digest: Digest,
}
impl ProviderConnection {
    pub fn prepare(
        endpoint: PreparedEndpoint,
        tls: impl Into<ProviderTlsMaterial>,
        maximum_request_bytes: usize,
        maximum_response_bytes: usize,
    ) -> Result<Self, ConnectionError> {
        if maximum_request_bytes == 0
            || maximum_response_bytes == 0
            || maximum_request_bytes > 16 * 1024 * 1024
            || maximum_response_bytes > 16 * 1024 * 1024
        {
            return Err(ConnectionError::RequestLimit);
        }
        let remaining = endpoint
            .valid_until_ms
            .checked_sub(now_ms()?)
            .filter(|v| *v > 0)
            .ok_or(ConnectionError::Expired)?;
        let expires = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(ConnectionError::Expired)?;
        let tls = tls.into();
        tls.validate_size()?;
        use ciborium::value::Value;
        let configuration_digest = Digest::of(pc_policy_core::pc_cbor_1(&Value::Array(vec![
            Value::Text("openpc.provider-connection-authority.v1".into()),
            endpoint.authority_configuration_value(),
            tls.configuration_value(),
            Value::Integer((maximum_request_bytes as u64).into()),
            Value::Integer((maximum_response_bytes as u64).into()),
        ])));
        let client = Client::builder()
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(PinnedResolver {
                hostname: endpoint.reference_identity.clone(),
                addresses: endpoint.addresses.clone(),
            }))
            .tls_backend_preconfigured(tls.into_config()?)
            .build()
            .map_err(|_| ConnectionError::Tls)?;
        Ok(Self {
            client,
            endpoint,
            expires,
            maximum_request_bytes,
            maximum_response_bytes,
            configuration_digest,
        })
    }

    pub async fn post_json(
        &self,
        body: Vec<u8>,
        request_deadline: Instant,
    ) -> Result<Vec<u8>, ConnectionError> {
        self.post_json_with_response_limit(body, request_deadline, self.maximum_response_bytes)
            .await
    }

    /// A narrower observation budget is enforced while receiving the body,
    /// before JSON allocation. It never widens the admitted connection ceiling.
    pub async fn post_json_with_response_limit(
        &self,
        body: Vec<u8>,
        request_deadline: Instant,
        response_limit: usize,
    ) -> Result<Vec<u8>, ConnectionError> {
        let response_limit = response_limit.min(self.maximum_response_bytes);
        if response_limit == 0 {
            return Err(ConnectionError::RequestLimit);
        }
        if body.is_empty() || body.len() > self.maximum_request_bytes {
            return Err(ConnectionError::RequestLimit);
        }
        self.check_time()?;
        let deadline = self.expires.min(request_deadline);
        if deadline <= Instant::now() {
            return Err(ConnectionError::Expired);
        }
        timeout_at(deadline, async {
            let mut response = self
                .client
                .post(self.endpoint.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| ConnectionError::Unavailable)?;
            if !response.status().is_success()
                || !response
                    .remote_addr()
                    .is_some_and(|a| self.endpoint.addresses.contains(&a))
                || response
                    .content_length()
                    .is_some_and(|n| n > response_limit as u64)
                || response
                    .headers()
                    .contains_key(reqwest::header::CONTENT_ENCODING)
            {
                return Err(ConnectionError::Response);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| ConnectionError::Response)?
            {
                if chunk.len() > response_limit - bytes.len() {
                    return Err(ConnectionError::Response);
                }
                bytes.extend_from_slice(&chunk);
            }
            self.check_time()?;
            Ok(bytes)
        })
        .await
        .map_err(|_| ConnectionError::Expired)?
    }

    fn check_time(&self) -> Result<(), ConnectionError> {
        let now = now_ms()?;
        if now < self.endpoint.resolved_at_ms
            || now >= self.endpoint.valid_until_ms
            || Instant::now() >= self.expires
        {
            return Err(ConnectionError::Expired);
        }
        Ok(())
    }
}

pub(super) fn now_ms() -> Result<u64, ConnectionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_millis().try_into().ok())
        .ok_or(ConnectionError::Expired)
}
