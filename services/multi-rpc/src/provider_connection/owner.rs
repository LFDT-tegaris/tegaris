//! Exclusive target-local connection generations. Installation is durable, but
//! never establishes provider certification or routing authority. A restart
//! loses prepared connections and requires fresh preparation before dispatch.
use super::{ConnectionError, ProviderConnection};
use pc_runtime_types::{Digest, LocalJournal};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConnectionStatus {
    Prepared,
    Retired,
    PreparationLost,
}

/// Safe metadata only. Configuration identity commits the admitted endpoint,
/// addresses, policy, public TLS identity and bounds across targets. The
/// resolution digest and validity fields separately fence local freshness; no
/// digest here is a successful TLS/chain readiness observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRecord {
    pub provider_id: String,
    pub endpoint_id: String,
    pub endpoint_generation: u64,
    pub resolution_generation: u64,
    pub endpoint_content_digest: Digest,
    pub resolution_content_digest: Digest,
    pub dispatcher_generation: u64,
    pub configuration_digest: Digest,
    pub valid_until_ms: u64,
    pub status: ConnectionStatus,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    target_id: String,
    sequence: u64,
    records: BTreeMap<String, ConnectionRecord>,
}
struct State {
    journal: LocalJournal<Journal>,
    connections: BTreeMap<String, ProviderConnection>,
}
pub struct ConnectionRegistry {
    state: Arc<RwLock<State>>,
    capacity: usize,
}
pub struct ConnectionLease {
    guard: OwnedRwLockReadGuard<State>,
    endpoint_id: String,
}
fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
}
fn follows(previous: &ConnectionRecord, connection: &ProviderConnection) -> bool {
    let endpoint = &connection.endpoint;
    if endpoint.endpoint_generation != previous.endpoint_generation {
        return endpoint.endpoint_generation > previous.endpoint_generation;
    }
    if endpoint.descriptor_digest != previous.endpoint_content_digest {
        return false;
    }
    if endpoint.resolution_generation != previous.resolution_generation {
        return endpoint.resolution_generation > previous.resolution_generation;
    }
    // Credential/context rotation may reuse the exact still-current DNS answer.
    // Restart recovery cannot reuse it as a fresh readiness observation.
    previous.status != ConnectionStatus::PreparationLost
        && endpoint.resolution_digest == previous.resolution_content_digest
        && connection.configuration_digest != previous.configuration_digest
}
impl ConnectionRegistry {
    pub fn open(
        directory: &Path,
        target_id: &str,
        capacity: usize,
    ) -> Result<Self, ConnectionError> {
        if !opaque(target_id) || !(1..=1024).contains(&capacity) {
            return Err(ConnectionError::Capacity);
        }
        let mut journal = LocalJournal::open(directory, "provider-connections", || Journal {
            version: 1,
            target_id: target_id.into(),
            sequence: 0,
            records: BTreeMap::new(),
        })
        .map_err(|_| ConnectionError::Owner)?;
        let state = journal.state().map_err(|_| ConnectionError::Owner)?;
        if state.version != 1 || state.target_id != target_id || state.records.len() > capacity {
            return Err(ConnectionError::Generation);
        }
        for (id, r) in &state.records {
            if id != &r.endpoint_id
                || !opaque(id)
                || !opaque(&r.provider_id)
                || r.endpoint_generation == 0
                || r.resolution_generation == 0
                || r.dispatcher_generation == 0
                || r.dispatcher_generation > state.sequence
                || r.valid_until_ms == 0
            {
                return Err(ConnectionError::Generation);
            }
        }
        if state
            .records
            .values()
            .any(|r| r.status == ConnectionStatus::Prepared)
        {
            let mut recovered = state.clone();
            for r in recovered.records.values_mut() {
                if r.status == ConnectionStatus::Prepared {
                    r.status = ConnectionStatus::PreparationLost;
                }
            }
            journal
                .commit(recovered)
                .map_err(|_| ConnectionError::Owner)?;
        }
        Ok(Self {
            state: Arc::new(RwLock::new(State {
                journal,
                connections: BTreeMap::new(),
            })),
            capacity,
        })
    }

    /// The expected generation is a compare-and-swap guard, not permission.
    /// The installation caller must be the admitted routing/credential owner.
    pub async fn install(
        &self,
        provider_id: &str,
        expected_generation: u64,
        connection: ProviderConnection,
    ) -> Result<ConnectionRecord, ConnectionError> {
        if !opaque(provider_id) {
            return Err(ConnectionError::Endpoint);
        }
        connection.check_time()?;
        let mut state = self.state.write().await;
        connection.check_time()?;
        let mut next = state
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?
            .clone();
        let id = &connection.endpoint.endpoint_id;
        if !opaque(id) {
            return Err(ConnectionError::Endpoint);
        }
        match next.records.get(id) {
            Some(previous)
                if previous.dispatcher_generation == expected_generation
                    && follows(previous, &connection) => {}
            None if expected_generation == 0 && next.records.len() < self.capacity => {}
            None if next.records.len() >= self.capacity => return Err(ConnectionError::Capacity),
            _ => return Err(ConnectionError::Generation),
        }
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(ConnectionError::Capacity)?;
        let record = ConnectionRecord {
            provider_id: provider_id.into(),
            endpoint_id: id.clone(),
            endpoint_generation: connection.endpoint.endpoint_generation,
            resolution_generation: connection.endpoint.resolution_generation,
            endpoint_content_digest: connection.endpoint.descriptor_digest.clone(),
            resolution_content_digest: connection.endpoint.resolution_digest.clone(),
            dispatcher_generation: next.sequence,
            configuration_digest: connection.configuration_digest.clone(),
            valid_until_ms: connection.endpoint.valid_until_ms,
            status: ConnectionStatus::Prepared,
        };
        next.records.insert(id.clone(), record.clone());
        state
            .journal
            .commit(next)
            .map_err(|_| ConnectionError::Owner)?;
        state.connections.insert(id.clone(), connection);
        Ok(record)
    }

    /// Retirement waits for retained request leases. Once it returns, no old
    /// lease remains and no new request can obtain this connection generation.
    pub async fn retire(
        &self,
        endpoint_id: &str,
        expected_generation: u64,
    ) -> Result<(), ConnectionError> {
        let mut state = self.state.write().await;
        let mut next = state
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?
            .clone();
        let record = next
            .records
            .get_mut(endpoint_id)
            .ok_or(ConnectionError::NotInstalled)?;
        if record.dispatcher_generation != expected_generation {
            return Err(ConnectionError::Generation);
        }
        if record.status == ConnectionStatus::Retired {
            return Ok(());
        }
        record.status = ConnectionStatus::Retired;
        state
            .journal
            .commit(next)
            .map_err(|_| ConnectionError::Owner)?;
        state.connections.remove(endpoint_id);
        Ok(())
    }

    pub async fn readback(&self, endpoint_id: &str) -> Result<ConnectionRecord, ConnectionError> {
        self.state
            .read()
            .await
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?
            .records
            .get(endpoint_id)
            .cloned()
            .ok_or(ConnectionError::NotInstalled)
    }

    /// Hold this lease through response validation, evidence commit and release.
    /// Contention fails closed on the synchronous PDS path; it never reads an
    /// older map while a pending cutover or retirement is being applied.
    pub fn acquire(
        &self,
        provider_id: &str,
        endpoint_id: &str,
        dispatcher_generation: u64,
    ) -> Result<ConnectionLease, ConnectionError> {
        let guard = self
            .state
            .clone()
            .try_read_owned()
            .map_err(|_| ConnectionError::Owner)?;
        let record = guard
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?
            .records
            .get(endpoint_id)
            .ok_or(ConnectionError::NotInstalled)?;
        if record.provider_id != provider_id
            || record.dispatcher_generation != dispatcher_generation
        {
            return Err(ConnectionError::Generation);
        }
        if record.status != ConnectionStatus::Prepared {
            return Err(ConnectionError::NotInstalled);
        }
        guard
            .connections
            .get(endpoint_id)
            .ok_or(ConnectionError::NotInstalled)?
            .check_time()?;
        Ok(ConnectionLease {
            guard,
            endpoint_id: endpoint_id.into(),
        })
    }
}
impl ConnectionLease {
    /// Commits the actual pinned dispatcher, including admitted endpoint/TLS/
    /// credential/egress configuration, resolved destination set and generation.
    /// This is a direct HTTP dispatcher commitment, not an Envoy cluster claim.
    pub fn binding_digest(&self, routing_snapshot: &Digest) -> Result<Digest, ConnectionError> {
        let record = self.record()?;
        let connection = self.connection()?;
        if record.configuration_digest != connection.configuration_digest {
            return Err(ConnectionError::Generation);
        }
        pc_runtime_types::canonical_bytes(&(
            "openpc:pinned-http-dispatcher-binding:v1",
            routing_snapshot,
            record,
        ))
        .map(Digest::of)
        .map_err(|_| ConnectionError::Owner)
    }
    pub fn record(&self) -> Result<&ConnectionRecord, ConnectionError> {
        self.connection()?;
        self.guard
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?
            .records
            .get(&self.endpoint_id)
            .ok_or(ConnectionError::NotInstalled)
    }
    pub fn connection(&self) -> Result<&ProviderConnection, ConnectionError> {
        self.guard
            .journal
            .state()
            .map_err(|_| ConnectionError::Owner)?;
        let connection = self
            .guard
            .connections
            .get(&self.endpoint_id)
            .ok_or(ConnectionError::NotInstalled)?;
        connection.check_time()?;
        Ok(connection)
    }
}
