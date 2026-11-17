//! Envoy ext_proc over the target-owned, kernel-authenticated Unix socket.
use crate::{
    ext_proc::{ExtProcService, stream_stopped},
    ext_proc_wire::{ProcessingRequest, ProcessingResponse},
};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixStream,
    sync::watch,
};
use tonic::{
    body::Body,
    codegen::{Service, StdError},
    server::NamedService,
};
#[derive(Clone)]
struct ExtProcServer(ExtProcService);
impl NamedService for ExtProcServer {
    const NAME: &'static str = "envoy.service.ext_proc.v3.ExternalProcessor";
}
impl<B> Service<http::Request<B>> for ExtProcServer
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
            if request.uri().path() != "/envoy.service.ext_proc.v3.ExternalProcessor/Process" {
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
            let limit = service.message_limit();
            let codec = tonic_prost::ProstCodec::<ProcessingResponse, ProcessingRequest>::default();
            let mut grpc = tonic::server::Grpc::new(codec)
                .max_decoding_message_size(limit)
                .max_encoding_message_size(limit);
            Ok(grpc.streaming(Process(service), request).await)
        })
    }
}
use tonic::codegen::Body as BodyTrait;
struct Process(ExtProcService);
impl tonic::server::StreamingService<ProcessingRequest> for Process {
    type Response = ProcessingResponse;
    type ResponseStream =
        tokio_stream::wrappers::ReceiverStream<Result<ProcessingResponse, tonic::Status>>;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<tonic::Response<Self::ResponseStream>, tonic::Status>>
                + Send,
        >,
    >;
    fn call(
        &mut self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.stream(request).await })
    }
}

// Tonic owns its connection tasks. Interrupt both directions of the accepted
// kernel-authenticated socket so a peer holding a response cannot prevent its
// graceful connection drain, even when HTTP/2 flow control is exhausted.
struct DrainingUnixStream {
    inner: UnixStream,
    closed: bool,
    read_stop: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_stop: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl DrainingUnixStream {
    fn new(inner: UnixStream, stop: watch::Receiver<bool>) -> Self {
        Self {
            inner,
            closed: false,
            read_stop: Box::pin(stream_stopped(stop.clone())),
            write_stop: Box::pin(stream_stopped(stop)),
        }
    }
    fn closed() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "protected transport drained",
        )
    }
}
impl tonic::transport::server::Connected for DrainingUnixStream {
    type ConnectInfo = tonic::transport::server::UdsConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        tonic::transport::server::Connected::connect_info(&self.inner)
    }
}
impl AsyncRead for DrainingUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || self.read_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(Self::closed()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for DrainingUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.write_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(Self::closed()));
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed || self.write_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(Self::closed()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn serve_ext_proc(
    service: ExtProcService,
    listener: crate::ipc::OwnedUnixListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> RuntimeResult<()> {
    let streams = service.stream_lifecycle();
    let accept_stop = streams.subscribe();
    let server_stop = streams.subscribe();
    let observer = service.clone();
    let incoming = futures::stream::unfold(
        Some((listener, observer, accept_stop)),
        |state| async move {
            let (listener, observer, stop) = state?;
            loop {
                let accepted = tokio::select! {
                    biased;
                    () = stream_stopped(stop.clone()) => return None,
                    accepted = listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, _)) => {
                        return Some((
                            Ok::<_, io::Error>(DrainingUnixStream::new(stream, stop.clone())),
                            Some((listener, observer, stop)),
                        ));
                    }
                    Err(error) => {
                        let evidence = observer.peer_denial(&error);
                        if evidence.is_err()
                            || error != pc_runtime_types::RuntimeError::TargetIdentity
                        {
                            return Some((
                                Err(std::io::Error::other("protected Unix listener unavailable")),
                                None,
                            ));
                        }
                    }
                }
            }
        },
    );
    let server = tonic::transport::Server::builder()
        .concurrency_limit_per_connection(4)
        .add_service(ExtProcServer(service))
        .serve_with_incoming_shutdown(incoming, stream_stopped(server_stop));
    tokio::pin!(server, shutdown);
    let first = tokio::select! {
        biased;
        () = &mut shutdown => None,
        result = &mut server => Some(result),
    };
    streams.cancel();
    let (transport, requests) = tokio::join!(
        async {
            let result = match first {
                Some(result) => result,
                None => tokio::time::timeout(Duration::from_secs(12), &mut server)
                    .await
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?,
            };
            result.map_err(|_| RuntimeError::RuntimeUnavailable)
        },
        streams.drain(),
    );
    transport.and(requests)
}
