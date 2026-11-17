//! Bounded internal reconciliation on the same verified TLS listener as ADS.
//! Target identity is transport-derived; requests carry no scope or trust key.
use crate::{FleetController, target_disposition::TargetDispositionStore};
use pc_runtime_types::Digest;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{Service, StdError},
    server::NamedService,
};

// Exact projection of proto/openpc/internal/runtime/v1/disposition.proto.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ReadDispositionRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct ReadDispositionResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub established: bool,
    #[prost(uint64, tag = "3")]
    pub revision: u64,
    #[prost(string, tag = "4")]
    pub admission_digest: String,
    #[prost(bytes = "vec", tag = "5")]
    pub signed_delivery: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub signed_acknowledgement: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct ReadOriginalConfirmationResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    #[prost(string, tag = "3")]
    pub admission_digest: String,
    #[prost(bytes = "vec", tag = "4")]
    pub signed_delivery: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub signed_acknowledgement: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct AcknowledgeDispositionRequest {
    #[prost(string, tag = "1")]
    pub delivery_digest: String,
    #[prost(bytes = "vec", tag = "2")]
    pub signed_acknowledgement: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct AcknowledgeDispositionResponse {
    #[prost(bool, tag = "1")]
    pub inserted: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DenyExpiredActivationRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub bundle: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub operator_mac: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub struct DenyExpiredActivationResponse {
    #[prost(string, tag = "1")]
    pub delivery_digest: String,
}

#[derive(Clone)]
pub struct TargetDispositionService {
    fleet: Arc<FleetController>,
    store: Arc<TargetDispositionStore>,
}
impl TargetDispositionService {
    pub(crate) fn new(fleet: Arc<FleetController>, store: Arc<TargetDispositionStore>) -> Self {
        Self { fleet, store }
    }
    async fn deny_expired(
        &self,
        request: Request<DenyExpiredActivationRequest>,
    ) -> Result<Response<DenyExpiredActivationResponse>, Status> {
        let timeout = deadline(&request)?;
        let body = request.get_ref();
        if body.bundle.is_empty()
            || body.bundle.len() > 120 * 1024
            || body.nonce.len() != 32
            || body.operator_mac.len() != 32
        {
            return Err(Status::invalid_argument("invalid operator denial request"));
        }
        let digest = tokio::time::timeout(
            timeout,
            self.store.deny_expired_operator(
                request.extensions(),
                &self.fleet,
                &body.bundle,
                &body.nonce,
                &body.operator_mac,
            ),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("denial outcome unconfirmed; read original record"))?
        .map_err(|_| {
            Status::failed_precondition("denial unavailable; read original record before retry")
        })?;
        Ok(Response::new(DenyExpiredActivationResponse {
            delivery_digest: digest.as_str().into(),
        }))
    }
    async fn handover_unsigned_expired(
        &self,
        request: Request<DenyExpiredActivationRequest>,
    ) -> Result<Response<DenyExpiredActivationResponse>, Status> {
        let timeout = deadline(&request)?;
        let body = request.get_ref();
        if body.bundle.is_empty()
            || body.bundle.len() > 120 * 1024
            || body.nonce.len() != 32
            || body.operator_mac.len() != 32
        {
            return Err(Status::invalid_argument("invalid operator denial request"));
        }
        let digest = tokio::time::timeout(
            timeout,
            self.store.handover_unsigned_expired_operator(
                request.extensions(),
                &self.fleet,
                &body.bundle,
                &body.nonce,
                &body.operator_mac,
            ),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("denial outcome unconfirmed; read original record"))?
        .map_err(|_| {
            Status::failed_precondition("denial unavailable; read original record before retry")
        })?;
        Ok(Response::new(DenyExpiredActivationResponse {
            delivery_digest: digest.as_str().into(),
        }))
    }
    async fn handover_credential_expired(
        &self,
        request: Request<DenyExpiredActivationRequest>,
    ) -> Result<Response<DenyExpiredActivationResponse>, Status> {
        let timeout = deadline(&request)?;
        let body = request.get_ref();
        if body.bundle.is_empty()
            || body.bundle.len() > 120 * 1024
            || body.nonce.len() != 32
            || body.operator_mac.len() != 32
        {
            return Err(Status::invalid_argument("invalid operator denial request"));
        }
        let digest = tokio::time::timeout(
            timeout,
            self.store.handover_expired_credential_operator(
                request.extensions(),
                &self.fleet,
                &body.bundle,
                &body.nonce,
                &body.operator_mac,
            ),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("denial outcome unconfirmed; read original record"))?
        .map_err(|_| {
            Status::failed_precondition("denial unavailable; read original record before retry")
        })?;
        Ok(Response::new(DenyExpiredActivationResponse {
            delivery_digest: digest.as_str().into(),
        }))
    }
    async fn current(
        &self,
        request: Request<ReadDispositionRequest>,
    ) -> Result<Response<ReadDispositionResponse>, Status> {
        let timeout = deadline(&request)?;
        if request.get_ref().challenge.len() != 32 {
            return Err(Status::invalid_argument("32-byte challenge required"));
        }
        let current = tokio::time::timeout(
            timeout,
            self.store.current(request.extensions(), &self.fleet),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("disposition read timed out"))?
        .map_err(|_| Status::failed_precondition("current target disposition unavailable"))?;
        let challenge = request.into_inner().challenge;
        Ok(Response::new(match current {
            None => ReadDispositionResponse {
                challenge,
                established: false,
                revision: 0,
                admission_digest: String::new(),
                signed_delivery: vec![],
                signed_acknowledgement: vec![],
            },
            Some(current) => ReadDispositionResponse {
                challenge,
                established: true,
                revision: current.revision,
                admission_digest: current.admission_digest.as_str().into(),
                signed_delivery: current.signed_delivery.unwrap_or_default(),
                signed_acknowledgement: current.signed_acknowledgement.unwrap_or_default(),
            },
        }))
    }
    async fn original_confirmation(
        &self,
        request: Request<ReadDispositionRequest>,
    ) -> Result<Response<ReadOriginalConfirmationResponse>, Status> {
        let timeout = deadline(&request)?;
        if request.get_ref().challenge.len() != 32 {
            return Err(Status::invalid_argument("32-byte challenge required"));
        }
        let original = tokio::time::timeout(
            timeout,
            self.store
                .original_confirmation(request.extensions(), &self.fleet),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("original confirmation read timed out"))?
        .map_err(|_| Status::failed_precondition("original confirmation unavailable"))?;
        Ok(Response::new(ReadOriginalConfirmationResponse {
            challenge: request.into_inner().challenge,
            revision: original.revision,
            admission_digest: original.admission_digest.as_str().into(),
            signed_delivery: original.signed_delivery,
            signed_acknowledgement: original.signed_acknowledgement.unwrap_or_default(),
        }))
    }
    async fn acknowledge(
        &self,
        request: Request<AcknowledgeDispositionRequest>,
    ) -> Result<Response<AcknowledgeDispositionResponse>, Status> {
        let timeout = deadline(&request)?;
        let message = request.get_ref();
        let digest = Digest::parse(&message.delivery_digest)
            .map_err(|_| Status::invalid_argument("invalid delivery digest"))?;
        if digest.as_str() != message.delivery_digest
            || message.signed_acknowledgement.is_empty()
            || message.signed_acknowledgement.len()
                > pc_runtime_types::target_disposition::MAX_TARGET_DISPOSITION_WIRE_BYTES
        {
            return Err(Status::invalid_argument(
                "invalid disposition acknowledgement",
            ));
        }
        let inserted = tokio::time::timeout(
            timeout,
            self.store.acknowledge(
                request.extensions(),
                &self.fleet,
                &digest,
                &message.signed_acknowledgement,
            ),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("disposition acknowledgement timed out"))?
        .map_err(|_| Status::failed_precondition("disposition acknowledgement unavailable"))?;
        Ok(Response::new(AcknowledgeDispositionResponse { inserted }))
    }
}

fn deadline<T>(request: &Request<T>) -> Result<Duration, Status> {
    let text = request
        .metadata()
        .get("grpc-timeout")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Status::invalid_argument("grpc-timeout required"))?;
    if !(2..=9).contains(&text.len())
        || !text.as_bytes()[..text.len() - 1]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(Status::invalid_argument("invalid grpc-timeout"));
    }
    let value: u64 = text[..text.len() - 1]
        .parse()
        .map_err(|_| Status::invalid_argument("invalid grpc-timeout"))?;
    let duration = match text.as_bytes()[text.len() - 1] {
        b'H' => Duration::from_secs(value * 3600),
        b'M' => Duration::from_secs(value * 60),
        b'S' => Duration::from_secs(value),
        b'm' => Duration::from_millis(value),
        b'u' => Duration::from_micros(value),
        b'n' => Duration::from_nanos(value),
        _ => return Err(Status::invalid_argument("invalid grpc-timeout")),
    };
    if duration.is_zero() {
        return Err(Status::deadline_exceeded("expired grpc-timeout"));
    }
    Ok(duration.min(Duration::from_secs(5)))
}

type ResponseFuture<T> = Pin<Box<dyn Future<Output = Result<Response<T>, Status>> + Send>>;
struct ReadCurrent(TargetDispositionService);
impl tonic::server::UnaryService<ReadDispositionRequest> for ReadCurrent {
    type Response = ReadDispositionResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<ReadDispositionRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.current(request).await })
    }
}
struct Acknowledge(TargetDispositionService);
struct DenyExpired(TargetDispositionService);
impl tonic::server::UnaryService<DenyExpiredActivationRequest> for DenyExpired {
    type Response = DenyExpiredActivationResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<DenyExpiredActivationRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.deny_expired(request).await })
    }
}
struct HandoverExpired(TargetDispositionService);
impl tonic::server::UnaryService<DenyExpiredActivationRequest> for HandoverExpired {
    type Response = DenyExpiredActivationResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<DenyExpiredActivationRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.handover_unsigned_expired(request).await })
    }
}
struct HandoverCredentialExpired(TargetDispositionService);
impl tonic::server::UnaryService<DenyExpiredActivationRequest> for HandoverCredentialExpired {
    type Response = DenyExpiredActivationResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<DenyExpiredActivationRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.handover_credential_expired(request).await })
    }
}
struct ReadOriginalConfirmation(TargetDispositionService);
impl tonic::server::UnaryService<ReadDispositionRequest> for ReadOriginalConfirmation {
    type Response = ReadOriginalConfirmationResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<ReadDispositionRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.original_confirmation(request).await })
    }
}
impl tonic::server::UnaryService<AcknowledgeDispositionRequest> for Acknowledge {
    type Response = AcknowledgeDispositionResponse;
    type Future = ResponseFuture<Self::Response>;
    fn call(&mut self, request: Request<AcknowledgeDispositionRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.acknowledge(request).await })
    }
}
impl NamedService for TargetDispositionService {
    const NAME: &'static str = "openpc.internal.runtime.v1.TargetDispositionService";
}
impl<B> Service<http::Request<B>> for TargetDispositionService
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            match request.uri().path() {
                "/openpc.internal.runtime.v1.TargetDispositionService/DenyExpiredActivation" => {
                    let codec = tonic_prost::ProstCodec::<
                        DenyExpiredActivationResponse,
                        DenyExpiredActivationRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(128 * 1024)
                        .max_encoding_message_size(1024)
                        .unary(DenyExpired(service), request)
                        .await)
                }
                "/openpc.internal.runtime.v1.TargetDispositionService/HandoverUnsignedExpiredDenial" =>
                {
                    let codec = tonic_prost::ProstCodec::<
                        DenyExpiredActivationResponse,
                        DenyExpiredActivationRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(128 * 1024)
                        .max_encoding_message_size(1024)
                        .unary(HandoverExpired(service), request)
                        .await)
                }
                "/openpc.internal.runtime.v1.TargetDispositionService/HandoverExpiredCredentialDenial" =>
                {
                    let codec = tonic_prost::ProstCodec::<
                        DenyExpiredActivationResponse,
                        DenyExpiredActivationRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(128 * 1024)
                        .max_encoding_message_size(1024)
                        .unary(HandoverCredentialExpired(service), request)
                        .await)
                }
                "/openpc.internal.runtime.v1.TargetDispositionService/ReadCurrent" => {
                    let codec = tonic_prost::ProstCodec::<
                        ReadDispositionResponse,
                        ReadDispositionRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(128)
                        .max_encoding_message_size(40 * 1024)
                        .unary(ReadCurrent(service), request)
                        .await)
                }
                "/openpc.internal.runtime.v1.TargetDispositionService/Acknowledge" => {
                    let codec = tonic_prost::ProstCodec::<
                        AcknowledgeDispositionResponse,
                        AcknowledgeDispositionRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(20 * 1024)
                        .max_encoding_message_size(128)
                        .unary(Acknowledge(service), request)
                        .await)
                }
                "/openpc.internal.runtime.v1.TargetDispositionService/ReadOriginalConfirmation" => {
                    let codec = tonic_prost::ProstCodec::<
                        ReadOriginalConfirmationResponse,
                        ReadDispositionRequest,
                    >::default();
                    Ok(tonic::server::Grpc::new(codec)
                        .max_decoding_message_size(128)
                        .max_encoding_message_size(40 * 1024)
                        .unary(ReadOriginalConfirmation(service), request)
                        .await)
                }
                _ => {
                    let mut response = http::Response::new(Body::empty());
                    response
                        .headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("12"));
                    response.headers_mut().insert(
                        "content-type",
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadlines_fail_closed_and_cannot_expand_the_server_budget() {
        for text in [
            None,
            Some("0S"),
            Some("1x"),
            Some("100000000S"),
            Some("-1S"),
            Some("1.5S"),
        ] {
            let mut request = Request::new(());
            if let Some(text) = text {
                request
                    .metadata_mut()
                    .insert("grpc-timeout", text.parse().unwrap());
            }
            assert!(deadline(&request).is_err());
        }
        for (text, wanted) in [
            ("1H", Duration::from_secs(5)),
            ("200m", Duration::from_millis(200)),
            ("20u", Duration::from_micros(20)),
            ("8n", Duration::from_nanos(8)),
        ] {
            let mut request = Request::new(());
            request
                .metadata_mut()
                .insert("grpc-timeout", text.parse().unwrap());
            assert_eq!(deadline(&request).unwrap(), wanted);
        }
    }
}
