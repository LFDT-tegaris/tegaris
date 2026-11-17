//! Synchronous PDS adapter to the real read-only Fact owner. Its dedicated I/O
//! thread retains the database transaction through the decision/evidence fence;
//! no readiness flag or fact snapshot is accepted from an HTTP caller.
use crate::{
    FactSignatureVerifier, PolicyFactReader, PolicyFactSnapshot, VerifiedPolicyFactValue,
    VerifiedShard,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FactLeaseError {
    #[error("invalid fact lease request")]
    InvalidInput,
    #[error("fact lease owner unavailable")]
    RuntimeUnavailable,
    #[error("fact is not currently eligible")]
    Denied,
    #[error("fact lease budget exhausted")]
    BudgetExhausted,
}
type LeaseResult<T> = Result<T, FactLeaseError>;
use std::{
    collections::BTreeMap,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};

enum LeaseCommand {
    Revalidate(SyncSender<LeaseResult<()>>),
}
struct Acquire {
    participant: String,
    privacy: String,
    candidates: Vec<String>,
    value_candidates: Vec<String>,
    budget_ms: u64,
    reply: SyncSender<LeaseResult<FactLease>>,
}
#[derive(Clone)]
pub struct FactLeaseReader {
    requests: SyncSender<Acquire>,
}
pub struct FactLease {
    commands: Option<SyncSender<LeaseCommand>>,
    snapshots: Vec<PolicyFactSnapshot>,
    values: BTreeMap<String, VerifiedPolicyFactValue>,
    wait: Duration,
}
impl FactLease {
    /// A factless policy still needs a request-local fence, but it must not
    /// fabricate a Fact publication or open a Fact database transaction.
    pub fn no_publication() -> Self {
        Self {
            commands: None,
            snapshots: Vec::new(),
            values: BTreeMap::new(),
            wait: Duration::ZERO,
        }
    }
    pub fn value(&self, candidate: &str) -> LeaseResult<&VerifiedPolicyFactValue> {
        self.values.get(candidate).ok_or(FactLeaseError::Denied)
    }
    pub fn snapshot(&self) -> &PolicyFactSnapshot {
        &self.snapshots[0]
    }
    pub fn snapshots(&self) -> &[PolicyFactSnapshot] {
        &self.snapshots
    }
    /// Round-trip on the retained transaction, including actual database time.
    /// A disconnected/expired owner can never be revived by a local boolean.
    pub fn revalidate(&self) -> LeaseResult<()> {
        let Some(commands) = &self.commands else {
            return Ok(());
        };
        let (send, receive) = mpsc::sync_channel(1);
        commands
            .try_send(LeaseCommand::Revalidate(send))
            .map_err(|_| FactLeaseError::RuntimeUnavailable)?;
        receive
            .recv_timeout(self.wait)
            .map_err(|_| FactLeaseError::RuntimeUnavailable)?
    }
}
impl FactLeaseReader {
    /// Join the admitted publication to current database eligibility while
    /// retaining the actual mutation fence. A signed old manifest is not ready.
    pub fn acquire_for_shard(
        &self,
        shard: &VerifiedShard,
        candidate: &str,
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        self.acquire_many_for_shard(shard, &[candidate.to_owned()], budget_ms)
    }
    pub fn acquire_many_for_shard(
        &self,
        shard: &VerifiedShard,
        candidates: &[String],
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        self.acquire_many_for_shard_with_values(shard, candidates, &[], budget_ms)
    }
    pub fn acquire_many_for_shard_with_values(
        &self,
        shard: &VerifiedShard,
        candidates: &[String],
        value_candidates: &[String],
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        let lease = self.acquire_many_with_values(
            shard.participant_id(),
            shard.privacy_domain_id(),
            candidates,
            value_candidates,
            budget_ms,
        )?;
        if lease.snapshots().iter().any(|snapshot| {
            snapshot.participant_id != shard.participant_id()
                || snapshot.privacy_domain_id != shard.privacy_domain_id()
                || snapshot.generation_id != shard.generation_id()
                || snapshot.shard_digest.as_deref() != Some(shard.shard_digest().as_slice())
        }) {
            return Err(FactLeaseError::Denied);
        }
        Ok(lease)
    }

    /// Bootstrap supplies a least-privilege Fact database connection and pinned
    /// Fact verification key. Neither value is serialized or logged by this owner.
    pub fn connect(database_url: String, verifier: FactSignatureVerifier) -> LeaseResult<Self> {
        let (requests, receive) = mpsc::sync_channel::<Acquire>(1);
        let (ready, startup) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("openpc-fact-lease".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = ready.send(Err(FactLeaseError::RuntimeUnavailable));
                    return;
                };
                let pool = runtime.block_on(
                    sqlx::postgres::PgPoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(Duration::from_secs(5))
                        .connect(&database_url),
                );
                drop(database_url);
                let Ok(pool) = pool else {
                    let _ = ready.send(Err(FactLeaseError::RuntimeUnavailable));
                    return;
                };
                let reader = PolicyFactReader::new(pool.clone(), verifier);
                if ready.send(Ok(())).is_err() {
                    runtime.block_on(pool.close());
                    return;
                }
                while let Ok(request) = receive.recv() {
                    // The total acquisition budget covers the entire dependency
                    // set, rather than restarting the timeout for every query.
                    let acquired = runtime.block_on(async {
                        tokio::time::timeout(
                            Duration::from_millis(request.budget_ms),
                            reader.lease_many_with_values(
                                &request.participant,
                                &request.privacy,
                                &request.candidates,
                                &request.value_candidates,
                                request.budget_ms,
                            ),
                        )
                        .await
                    });
                    let mut lease = match acquired {
                        Ok(Ok(Some(lease))) => lease,
                        Ok(Ok(None)) => {
                            let _ = request.reply.send(Err(FactLeaseError::Denied));
                            continue;
                        }
                        Err(_) => {
                            let _ = request.reply.send(Err(FactLeaseError::BudgetExhausted));
                            continue;
                        }
                        _ => {
                            let _ = request.reply.send(Err(FactLeaseError::RuntimeUnavailable));
                            continue;
                        }
                    };
                    if runtime.block_on(lease.revalidate()).is_err() {
                        let _ = request.reply.send(Err(FactLeaseError::Denied));
                        let _ = runtime.block_on(lease.release());
                        continue;
                    }
                    let (commands, replies) = mpsc::sync_channel(1);
                    let result = FactLease {
                        commands: Some(commands),
                        snapshots: lease.snapshots().to_vec(),
                        values: lease.values().clone(),
                        wait: Duration::from_millis(request.budget_ms),
                    };
                    if request.reply.send(Ok(result)).is_ok() {
                        // The runtime also bounds idle transactions. A lost request
                        // cannot indefinitely retain the database mutation fence.
                        while let Ok(LeaseCommand::Revalidate(reply)) =
                            replies.recv_timeout(Duration::from_secs(5))
                        {
                            let valid = runtime
                                .block_on(lease.revalidate())
                                .map_err(|_| FactLeaseError::RuntimeUnavailable);
                            let failed = valid.is_err();
                            let _ = reply.send(valid);
                            if failed {
                                break;
                            }
                        }
                    }
                    let _ = runtime.block_on(lease.release());
                }
                runtime.block_on(pool.close());
            })
            .map_err(|_| FactLeaseError::RuntimeUnavailable)?;
        startup
            .recv_timeout(Duration::from_secs(6))
            .map_err(|_| FactLeaseError::RuntimeUnavailable)??;
        Ok(Self { requests })
    }
    pub fn acquire(
        &self,
        participant: &str,
        privacy: &str,
        candidate: &str,
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        self.acquire_many(participant, privacy, &[candidate.to_owned()], budget_ms)
    }
    pub fn acquire_many(
        &self,
        participant: &str,
        privacy: &str,
        candidates: &[String],
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        self.acquire_many_with_values(participant, privacy, candidates, &[], budget_ms)
    }
    fn acquire_many_with_values(
        &self,
        participant: &str,
        privacy: &str,
        candidates: &[String],
        value_candidates: &[String],
        budget_ms: u64,
    ) -> LeaseResult<FactLease> {
        if !(1..=5000).contains(&budget_ms)
            || [participant, privacy]
                .iter()
                .any(|v| v.is_empty() || v.len() > 256)
            || candidates.is_empty()
            || candidates.len() > 256
            || candidates.iter().any(|v| v.is_empty() || v.len() > 256)
            || candidates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != candidates.len()
        {
            return Err(FactLeaseError::InvalidInput);
        }
        if value_candidates.len() > 16
            || value_candidates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != value_candidates.len()
            || value_candidates.iter().any(|id| !candidates.contains(id))
        {
            return Err(FactLeaseError::InvalidInput);
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.requests
            .try_send(Acquire {
                participant: participant.into(),
                privacy: privacy.into(),
                candidates: candidates.to_vec(),
                value_candidates: value_candidates.to_vec(),
                budget_ms,
                reply,
            })
            .map_err(|_| FactLeaseError::BudgetExhausted)?;
        response
            .recv_timeout(Duration::from_millis(budget_ms))
            .map_err(|_| FactLeaseError::BudgetExhausted)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_publication_lease_is_empty_and_locally_revalidates() {
        let lease = FactLease::no_publication();
        assert!(lease.snapshots().is_empty());
        assert_eq!(lease.revalidate(), Ok(()));
        assert!(matches!(
            lease.value("candidate"),
            Err(FactLeaseError::Denied)
        ));
    }
}
