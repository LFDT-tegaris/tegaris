//! Private Broker HTTP adapter on the target-owned Envoy Unix socket.
//! The only request-carried authorization is a one-use opaque handoff token;
//! every route, provider and capability binding is retained in the local store.

use crate::{broker_handoff::BrokerHandoffStore, ipc::OwnedUnixListener};
use axum::body::{Body, to_bytes};
use http::{Method, Request, Response, StatusCode, header};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::{future::Future, sync::Arc};

const DISPATCH_PATH: &str = "/openpc/broker/v1/dispatch";
const HANDOFF_HEADER: &str = "x-openpc-runtime-capability";

pub trait BrokerServerEvidence: Send + Sync {
    /// A rejected kernel peer has no admitted request/decision ID. Persist only
    /// the closed error category; never record socket credentials as authority.
    fn record_transport_denial(&self, error: &RuntimeError) -> RuntimeResult<()>;
}

pub async fn serve_broker(
    store: Arc<BrokerHandoffStore>,
    evidence: Arc<dyn BrokerServerEvidence>,
    listener: OwnedUnixListener,
    body_limit: usize,
    shutdown: impl Future<Output = ()> + Send,
) -> RuntimeResult<()> {
    if body_limit == 0 || body_limit > 4 * 1024 * 1024 {
        return Err(RuntimeError::InvalidInput);
    }
    tokio::pin!(shutdown);
    let mut connections = tokio::task::JoinSet::new();
    let mut expiry = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Ok(());
            },
            result = listener.accept(), if connections.len() < 32 => Some(result),
            _ = connections.join_next(), if !connections.is_empty() => None,
            _ = expiry.tick() => {
                store.reap_expired(crate::target_state::wall_clock_ns()? / 1_000_000)?;
                None
            },
        };
        let Some(accepted) = accepted else { continue };
        let (stream, _) = match accepted {
            Ok(value) => value,
            Err(error) => {
                evidence.record_transport_denial(&error)?;
                if error == RuntimeError::TargetIdentity {
                    continue;
                }
                return Err(error);
            }
        };
        let store = Arc::clone(&store);
        connections.spawn(async move {
            let service = service_fn(move |request| {
                let store = Arc::clone(&store);
                async move {
                    Ok::<_, std::convert::Infallible>(handle(store, request, body_limit).await)
                }
            });
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn handle(
    store: Arc<BrokerHandoffStore>,
    request: Request<Incoming>,
    body_limit: usize,
) -> Response<Body> {
    let result = async {
        if request.method() != Method::POST || request.uri().path() != DISPATCH_PATH {
            return Err(RuntimeError::InvalidInput);
        }
        if request.uri().query().is_some() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut tokens = request.headers().get_all(HANDOFF_HEADER).iter();
        let token = tokens
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or(RuntimeError::InvalidAuthorization)?
            .to_owned();
        if tokens.next().is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/json")
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let body = to_bytes(Body::new(request.into_body()), body_limit)
            .await
            .map_err(|_| RuntimeError::InvalidInput)?;
        store.execute(&token, &body).await
    }
    .await;
    match result {
        Ok(body) => response(StatusCode::OK, Body::from(body)),
        Err(RuntimeError::InvalidInput | RuntimeError::InvalidAuthorization) => {
            response(StatusCode::FORBIDDEN, Body::empty())
        }
        Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, Body::empty()),
    }
}

fn response(status: StatusCode, body: Body) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::UnixSocketPolicy;
    use openpc_broker::BrokerService;
    use pc_runtime_types::{PURPOSE_BROKER_CAPABILITY_V1, PurposeSigner};
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    struct Evidence(AtomicUsize);
    impl BrokerServerEvidence for Evidence {
        fn record_transport_denial(&self, _error: &RuntimeError) -> RuntimeResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn actual_private_http_socket_rejects_request_without_handoff() {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("broker-http-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::DirBuilder::new().mode(0o750).create(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let socket = root.join("broker.sock");
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
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
        let broker = Arc::new(BrokerService::new(&signer.verifier().sec1_bytes(), 8).unwrap());
        let store = Arc::new(BrokerHandoffStore::new(broker, 4, 1024).unwrap());
        let evidence = Arc::new(Evidence(AtomicUsize::new(0)));
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server_evidence: Arc<dyn BrokerServerEvidence> = evidence.clone();
        let server = tokio::spawn(serve_broker(
            store,
            server_evidence,
            listener,
            1024,
            async {
                let _ = stopped.await;
            },
        ));

        let mut client = UnixStream::connect(&socket).await.unwrap();
        client
            .write_all(
                b"POST /openpc/broker/v1/dispatch HTTP/1.1\r\nHost: openpc\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = std::str::from_utf8(&response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(response.contains("cache-control: no-store\r\n"));
        assert_eq!(evidence.0.load(Ordering::Relaxed), 0);

        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
