//! One target process owns both private Envoy sockets. Losing either PDS or
//! Broker path stops the pair so readiness cannot describe a partial runtime.

use crate::{
    broker_handoff::BrokerHandoffStore,
    broker_server::{BrokerServerEvidence, serve_broker},
    ext_proc::ExtProcService,
    ext_proc_server::serve_ext_proc,
    ipc::OwnedUnixListener,
};
use pc_runtime_types::RuntimeResult;
use std::{future::Future, sync::Arc};
use tokio::sync::watch;

pub async fn serve_protected_target(
    ext_proc: ExtProcService,
    pds_listener: OwnedUnixListener,
    handoffs: Arc<BrokerHandoffStore>,
    broker_evidence: Arc<dyn BrokerServerEvidence>,
    broker_listener: OwnedUnixListener,
    body_limit: usize,
    shutdown: impl Future<Output = ()> + Send,
) -> RuntimeResult<()> {
    let (stop, _) = watch::channel(false);
    let pds_stop = stop.subscribe();
    // Keep both futures owned by this session. Dropping the session cannot
    // detach a listener task, and a child failure still drains its sibling.
    let pds = serve_ext_proc(ext_proc, pds_listener, stopped(pds_stop));
    let broker = serve_broker(
        handoffs,
        broker_evidence,
        broker_listener,
        body_limit,
        stopped(stop.subscribe()),
    );
    tokio::pin!(shutdown, pds, broker);

    let first = tokio::select! {
        () = &mut shutdown => None,
        result = &mut pds => Some((true, result)),
        result = &mut broker => Some((false, result)),
    };
    // A receiver may already have finished. That does not excuse skipping the
    // other child's cleanup or replace the first failure.
    stop.send_replace(true);
    match first {
        Some((true, result)) => result.and(broker.await),
        Some((false, result)) => result.and(pds.await),
        None => {
            let (pds, broker) = tokio::join!(pds, broker);
            pds.and(broker)
        }
    }
}

async fn stopped(mut stop: watch::Receiver<bool>) {
    while !*stop.borrow() && stop.changed().await.is_ok() {}
}
