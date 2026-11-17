//! A verified ADS stream is discovery, never permission to serve a generation.
use crate::TargetIdentity;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tonic::Status;

/// The durable owner must recheck the current scoped credential on every renewal.
#[tonic::async_trait]
pub trait TargetDiscovery: Send + Sync {
    async fn observe(
        &self,
        identity: &TargetIdentity,
        connection_id: &str,
        certificate_until_ms: u64,
    ) -> Result<(), Status>;
    async fn disconnect(&self, identity: &TargetIdentity, connection_id: &str);
}

#[derive(Clone, Default)]
pub(crate) struct Connections(Arc<Mutex<BTreeMap<String, Connection>>>);
struct Connection {
    id: String,
    until: Instant,
}

pub(crate) struct ConnectionGuard {
    connections: Connections,
    target: String,
    pub(crate) id: String,
}

impl Connections {
    pub(crate) fn open(&self, target: &str) -> Result<ConnectionGuard, Status> {
        let mut connections = self
            .0
            .lock()
            .map_err(|_| Status::unavailable("ADS connection owner unavailable"))?;
        // A second stream cannot recycle ACKs or race the first stream's lease.
        if connections.contains_key(target) {
            return Err(Status::failed_precondition("ADS target already connected"));
        }
        let id = uuid::Uuid::now_v7().to_string();
        connections.insert(
            target.into(),
            Connection {
                id: id.clone(),
                until: Instant::now(),
            },
        );
        Ok(ConnectionGuard {
            connections: self.clone(),
            target: target.into(),
            id,
        })
    }

    pub(crate) fn with_current<T>(
        &self,
        target: &str,
        id: &str,
        action: impl FnOnce() -> T,
    ) -> Result<T, Status> {
        let connections = self
            .0
            .lock()
            .map_err(|_| Status::unavailable("ADS connection owner unavailable"))?;
        let current = connections
            .get(target)
            .filter(|c| c.id == id && c.until > Instant::now())
            .ok_or_else(|| {
                Status::failed_precondition("current authenticated ADS connection required")
            })?;
        let _ = current;
        // Disconnect/drop and lease replacement cannot interleave with the effect.
        Ok(action())
    }
}

impl ConnectionGuard {
    pub(crate) fn renew(&self, remaining: Duration) -> Result<(), Status> {
        let mut connections = self
            .connections
            .0
            .lock()
            .map_err(|_| Status::unavailable("ADS connection owner unavailable"))?;
        let current = connections
            .get_mut(&self.target)
            .filter(|c| c.id == self.id)
            .ok_or_else(|| Status::failed_precondition("ADS connection replaced"))?;
        current.until = Instant::now() + remaining.min(Duration::from_secs(15));
        Ok(())
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut connections) = self.connections.0.lock()
            && connections
                .get(&self.target)
                .is_some_and(|c| c.id == self.id)
        {
            connections.remove(&self.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_requires_renewal_and_exact_live_stream_without_replacement() {
        let connections = Connections::default();
        let stream = connections.open("target").unwrap();
        assert!(
            connections
                .with_current("target", &stream.id, || ())
                .is_err()
        );
        stream.renew(Duration::from_secs(15)).unwrap();
        assert!(
            connections
                .with_current("target", &stream.id, || ())
                .is_ok()
        );
        assert!(
            connections
                .with_current("foreign", &stream.id, || ())
                .is_err()
        );
        assert!(
            connections
                .with_current("target", "foreign", || ())
                .is_err()
        );
        assert!(connections.open("target").is_err());
        stream.renew(Duration::ZERO).unwrap();
        assert!(
            connections
                .with_current("target", &stream.id, || ())
                .is_err()
        );
        let id = stream.id.clone();
        drop(stream);
        assert!(connections.with_current("target", &id, || ()).is_err());
        let replacement = connections.open("target").unwrap();
        replacement.renew(Duration::from_secs(15)).unwrap();
        assert_ne!(replacement.id, id);
        assert!(connections.with_current("target", &id, || ()).is_err());
    }
}
