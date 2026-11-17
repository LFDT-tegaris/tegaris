//! Tonic service adapter for Envoy's published StreamAggregatedResources API.
use crate::{
    ads::AdsService,
    ads_wire::{DiscoveryRequest, DiscoveryResponse},
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tonic::{
    body::Body,
    codegen::{Service, StdError},
    server::NamedService,
};
#[derive(Clone)]
struct AdsServer(AdsService);
impl NamedService for AdsServer {
    const NAME: &'static str = "envoy.service.discovery.v3.AggregatedDiscoveryService";
}
impl<B> Service<http::Request<B>> for AdsServer
where
    B: BodyTrait + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move {
            if request.uri().path()
                != "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources"
            {
                let mut response = http::Response::new(Body::empty());
                response
                    .headers_mut()
                    .insert("grpc-status", http::HeaderValue::from_static("12"));
                response.headers_mut().insert(
                    "content-type",
                    http::HeaderValue::from_static("application/grpc"),
                );
                return Ok(response);
            }
            let codec = tonic_prost::ProstCodec::<DiscoveryResponse, DiscoveryRequest>::default();
            let mut grpc = tonic::server::Grpc::new(codec)
                .max_decoding_message_size(64 * 1024)
                .max_encoding_message_size(8 * 1024 * 1024);
            Ok(grpc.streaming(StreamAds(service), request).await)
        })
    }
}
use tonic::codegen::Body as BodyTrait;
struct StreamAds(AdsService);
impl tonic::server::StreamingService<DiscoveryRequest> for StreamAds {
    type Response = DiscoveryResponse;
    type ResponseStream =
        tokio_stream::wrappers::ReceiverStream<Result<DiscoveryResponse, tonic::Status>>;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<tonic::Response<Self::ResponseStream>, tonic::Status>>
                + Send,
        >,
    >;
    fn call(
        &mut self,
        request: tonic::Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.stream(request).await })
    }
}
pub async fn serve_ads(
    service: AdsService,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), tonic::transport::Error> {
    let disposition = service.target_disposition.clone();
    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(4)
        .add_service(AdsServer(service))
        .add_optional_service(disposition)
        .serve_with_incoming_shutdown(crate::runtime_tls::incoming(listener, tls), shutdown)
        .await
}
