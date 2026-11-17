//! PDS-capability-bound admission into the existing Multi-RPC write journal.
//! The target retains live authority; this owner consumes the capability,
//! operation identity and nonce reservation in one durable record.
use crate::BrokerService;
use openpc_multi_rpc::{
    JournalError,
    governed_write::{self, LiveWriteAuthority},
    journal::{GovernedCommand, JournalState, PreparedCommand, WriteJournal},
    provider_connection::ConnectionLease,
    signed_transaction::SignedTransaction,
    submission_operation::{SubmissionAdmission, SubmissionOwner},
};
use pc_runtime_types::{
    Digest, RuntimeBindings, RuntimeDecision, RuntimeError, RuntimeRequest, RuntimeResult,
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub struct SubmissionBroker {
    broker: Arc<BrokerService>,
    target_id: String,
    journal: Mutex<WriteJournal>,
}

/// A non-constructible handle to the exact durable operation and signed bytes.
pub struct PreparedSubmission {
    command: PreparedCommand,
    transaction: SignedTransaction,
}
impl PreparedSubmission {
    pub fn command(&self) -> &GovernedCommand {
        self.command.command()
    }
}

/// A real observation over a retained predecessor. Only the existing recovery
/// route owner can produce it; fresh submission authority is still mandatory.
pub struct ReplacementObservation {
    target: openpc_multi_rpc::journal::ObservationTarget,
    proof: openpc_multi_rpc::journal::VerifiedObservation,
    connection: openpc_multi_rpc::provider_connection::ConnectionRecord,
}

impl SubmissionBroker {
    pub fn uses_broker(&self, broker: &Arc<BrokerService>) -> bool {
        Arc::ptr_eq(&self.broker, broker)
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn open(
        broker: Arc<BrokerService>,
        target_id: &str,
        directory: &Path,
    ) -> RuntimeResult<Self> {
        if target_id.is_empty() || target_id.len() > 256 {
            return Err(RuntimeError::InvalidInput);
        }
        let path = directory.join("submission.journal");
        let mut journal = if path.exists() {
            WriteJournal::open(path)
        } else {
            WriteJournal::create_new(path)
        }
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        journal
            .validate_submission_target(target_id)
            .map_err(|_| RuntimeError::TargetIdentity)?;
        journal
            .abandon_prepared_submissions()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(Self {
            broker,
            target_id: target_id.into(),
            journal: Mutex::new(journal),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        transaction: &SignedTransaction,
        admission: SubmissionAdmission,
        provider_instance_id: &str,
        anchor: &Digest,
        correlation_id: &str,
        now_ms: u64,
    ) -> RuntimeResult<PreparedSubmission> {
        self.prepare_inner(
            request,
            bindings,
            decision,
            transaction,
            admission,
            provider_instance_id,
            anchor,
            correlation_id,
            now_ms,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_replacement(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        transaction: &SignedTransaction,
        admission: SubmissionAdmission,
        provider_instance_id: &str,
        anchor: &Digest,
        correlation_id: &str,
        now_ms: u64,
        replacement: ReplacementObservation,
        connection: &openpc_multi_rpc::provider_connection::ConnectionRecord,
        policy: &pc_policy_core::transaction_policy::TransactionPolicyV1,
    ) -> RuntimeResult<PreparedSubmission> {
        if &replacement.connection != connection {
            return Err(RuntimeError::GenerationMismatch);
        }
        self.prepare_inner(
            request,
            bindings,
            decision,
            transaction,
            admission,
            provider_instance_id,
            anchor,
            correlation_id,
            now_ms,
            Some((replacement, policy)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_inner(
        &self,
        request: &RuntimeRequest,
        bindings: &RuntimeBindings,
        decision: &RuntimeDecision,
        transaction: &SignedTransaction,
        admission: SubmissionAdmission,
        provider_instance_id: &str,
        anchor: &Digest,
        correlation_id: &str,
        now_ms: u64,
        replacement: Option<(
            ReplacementObservation,
            &pc_policy_core::transaction_policy::TransactionPolicyV1,
        )>,
    ) -> RuntimeResult<PreparedSubmission> {
        if !uuid::Uuid::try_parse(correlation_id)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == correlation_id)
        {
            return Err(RuntimeError::InvalidInput);
        }
        admission.validate_runtime_request(request, transaction)?;
        let capability = decision
            .capability
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        self.broker
            .validate_capability(capability, request, bindings, decision, now_ms)?;
        if self.target_id != bindings.target_id
            || admission.target_runtime_id != self.target_id
            || admission.owner.participant_id != bindings.participant_id
            || admission.owner.privacy_domain_id != bindings.privacy_domain_id
            || admission.owner.workload_id != bindings.workload_id
            || admission.capability_id != capability.claims.capability_id
            || admission.decision_id != decision.decision_id
            || admission.decision_digest != decision.decision_digest
            || admission.capsule_digest != bindings.active_generation_digest
            || admission.policy_generation_digest != bindings.policy_generation_digest
            || now_ms < admission.admitted_at_ms
            || now_ms >= admission.valid_until_ms
            || admission.valid_until_ms > request.deadline_at_ms
            || admission.valid_until_ms > capability.claims.expires_at_ms
            || capability.claims.remaining_budget_ms == 0
            || provider_instance_id.is_empty()
            || *anchor == Digest::of([])
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // Deployment's global address owner has already allocated this identity.
        // The reservation is not authority; the capability and final live lease
        // still govern journal admission and STARTED. Contract writes retain
        // their existing Broker-owned allocation.
        let (command_id, attempt_id) = admission.deployment.as_ref().map_or_else(
            || {
                (
                    uuid::Uuid::now_v7().to_string(),
                    uuid::Uuid::now_v7().to_string(),
                )
            },
            |deployment| (deployment.command_id.clone(), deployment.attempt_id.clone()),
        );
        let body = governed_write::submission_body(transaction, &command_id)?;
        let occurred_at =
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
                .map_err(|_| RuntimeError::InvalidInput)?
                .format(
                    &time::format_description::parse_borrowed::<2>(
                        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
                    )
                    .map_err(|_| RuntimeError::InvalidInput)?,
                )
                .map_err(|_| RuntimeError::InvalidInput)?;
        let command = GovernedCommand {
            command_id,
            method: request.method.clone(),
            immutable_request_digest: request.request_digest.as_str().into(),
            request_or_transaction_hash: format!(
                "0x{}",
                transaction
                    .hash()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            submitted_bytes_digest: Digest::of(body).as_str().into(),
            provider_profile_digest: bindings.provider_profile_digest.as_str().into(),
            provider_instance_id: provider_instance_id.into(),
            attempt_id,
            anchor_digest: anchor.as_str().into(),
            participant_id: bindings.participant_id.clone(),
            privacy_domain_id: bindings.privacy_domain_id.clone(),
            correlation_id: correlation_id.into(),
            occurred_at,
        };
        let prepared = match replacement {
            None => self
                .lock_journal()?
                .prepare_submission(command, transaction, admission),
            Some((replacement, policy)) => self.lock_journal()?.prepare_replacement(
                command,
                transaction,
                admission,
                &replacement.target,
                replacement.proof,
                &replacement.connection,
                policy,
            ),
        }
        .map_err(journal_error)?;
        Ok(PreparedSubmission {
            command: prepared,
            transaction: transaction.clone(),
        })
    }

    fn lock_journal(&self) -> RuntimeResult<std::sync::MutexGuard<'_, WriteJournal>> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        journal
            .ensure_healthy()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(journal)
    }

    /// Identity lookup only. The caller must apply the independent live status
    /// capability and safe response projection before releasing any metadata.
    pub fn lookup(
        &self,
        operation_id: &str,
        owner: &SubmissionOwner,
    ) -> RuntimeResult<Option<(GovernedCommand, SubmissionAdmission, JournalState)>> {
        Ok(self.lock_journal()?.submission(operation_id, owner))
    }

    pub fn lookup_transaction(
        &self,
        transaction: &SignedTransaction,
        owner: &SubmissionOwner,
    ) -> RuntimeResult<Option<(GovernedCommand, SubmissionAdmission, JournalState)>> {
        Ok(self
            .lock_journal()?
            .submission_for_transaction(transaction, owner))
    }

    pub fn repeated_submission_view(
        &self,
        transaction: &SignedTransaction,
        participant_id: &str,
        privacy_domain_id: &str,
        workload_id: &str,
        peer_binding: &Digest,
    ) -> RuntimeResult<Option<openpc_multi_rpc::submission_status::OperationStatusView>> {
        self.lock_journal()?.repeated_submission_view(
            transaction,
            participant_id,
            privacy_domain_id,
            workload_id,
            peer_binding,
        )
    }

    /// Projection only; the target must independently authorize operation status.
    pub fn status(
        &self,
        operation_id: &str,
        owner: &SubmissionOwner,
    ) -> RuntimeResult<Option<openpc_multi_rpc::submission_status::SubmissionStatus>> {
        Ok(self.lock_journal()?.submission_status(operation_id, owner))
    }

    /// The closed public projection is captured under one journal lock. This
    /// method grants no disclosure authority.
    pub fn view(
        &self,
        operation_id: &str,
        owner: &SubmissionOwner,
    ) -> RuntimeResult<Option<openpc_multi_rpc::submission_status::OperationStatusView>> {
        self.lock_journal()?.submission_view(operation_id, owner)
    }

    /// Infrastructure evidence only; this does not authorize public disclosure.
    pub fn next_deployment_projection(
        &self,
        after: u64,
    ) -> RuntimeResult<(
        u64,
        Option<openpc_multi_rpc::deployment::projection::DeploymentProjection>,
    )> {
        self.lock_journal()?.next_deployment_projection(after)
    }

    pub fn reject(&self, prepared: PreparedSubmission, error: &RuntimeError) -> RuntimeResult<()> {
        self.lock_journal()?
            .fail_pre_start(
                prepared.command,
                Digest::of(error.pc_code()).as_str().into(),
            )
            .map_err(|_| RuntimeError::RuntimeUnavailable)
    }

    pub fn expire(&self, now_ms: u64) -> RuntimeResult<usize> {
        self.lock_journal()?
            .expire_submissions(now_ms)
            .map_err(|_| RuntimeError::RuntimeUnavailable)
    }

    pub fn pending_observations(
        &self,
        limit: usize,
    ) -> RuntimeResult<Vec<openpc_multi_rpc::journal::ObservationTarget>> {
        self.lock_journal()?
            .pending_observations(limit)
            .map_err(journal_error)
    }

    pub fn replacement_target(
        &self,
        operation_id: &str,
        owner: &SubmissionOwner,
    ) -> RuntimeResult<openpc_multi_rpc::journal::ObservationTarget> {
        let journal = self.lock_journal()?;
        if journal.submission(operation_id, owner).is_none()
            || journal.replacement_successor(operation_id, owner).is_some()
        {
            return Err(RuntimeError::Denied);
        }
        journal
            .observation_target(operation_id)
            .map_err(journal_error)?
            .ok_or(RuntimeError::Denied)
    }

    pub fn pending_observations_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> RuntimeResult<Vec<openpc_multi_rpc::journal::ObservationTarget>> {
        self.lock_journal()?
            .pending_observations_after(after, limit)
            .map_err(journal_error)
    }

    pub async fn observe_replacement(
        &self,
        target: &openpc_multi_rpc::journal::ObservationTarget,
        connection: &ConnectionLease,
        anchor: &openpc_multi_rpc::route_witness::VerifiedChainAnchor,
        witness: &openpc_multi_rpc::route_witness::VerifiedRouteWitness,
        authority: &dyn openpc_multi_rpc::journal::LiveObservationAuthority,
        deadline: tokio::time::Instant,
    ) -> RuntimeResult<ReplacementObservation> {
        if target.admission().target_runtime_id != self.target_id
            || self
                .lock_journal()?
                .observation_target(&target.command().command_id)
                .map_err(journal_error)?
                .as_ref()
                .is_none_or(|current| current.binding_digest() != target.binding_digest())
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let revalidate = || {
            authority
                .acquire(
                    target,
                    connection
                        .record()
                        .map_err(|_| RuntimeError::GenerationMismatch)?,
                    anchor,
                    witness,
                )?
                .revalidate()
        };
        let proof = openpc_multi_rpc::journal::observe_submission(
            target,
            connection,
            anchor,
            witness,
            deadline,
            &revalidate,
        )
        .await?;
        Ok(ReplacementObservation {
            target: target.clone(),
            proof,
            connection: connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?
                .clone(),
        })
    }

    pub async fn reconcile(
        &self,
        target: &openpc_multi_rpc::journal::ObservationTarget,
        connection: &ConnectionLease,
        anchor: &openpc_multi_rpc::route_witness::VerifiedChainAnchor,
        witness: &openpc_multi_rpc::route_witness::VerifiedRouteWitness,
        authority: &dyn openpc_multi_rpc::journal::LiveObservationAuthority,
        deadline: tokio::time::Instant,
    ) -> RuntimeResult<bool> {
        let proof = self
            .observe_replacement(target, connection, anchor, witness, authority, deadline)
            .await?
            .proof;
        let fence = authority.acquire(
            target,
            connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            anchor,
            witness,
        )?;
        fence.revalidate()?;
        self.lock_journal()?
            .commit_observation(
                target,
                proof,
                (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                    .try_into()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?,
            )
            .map_err(journal_error)
    }

    pub async fn execute(
        &self,
        prepared: PreparedSubmission,
        connection: &ConnectionLease,
        authority: &dyn LiveWriteAuthority,
        deadline: tokio::time::Instant,
    ) -> RuntimeResult<JournalState> {
        governed_write::submit(
            &self.journal,
            prepared.command,
            &prepared.transaction,
            connection,
            authority,
            deadline,
        )
        .await
    }
}

fn journal_error(error: JournalError) -> RuntimeError {
    match error {
        JournalError::DuplicateCommand => RuntimeError::Replay,
        JournalError::IdentityMismatch | JournalError::ForbiddenTransition => {
            RuntimeError::InvalidAuthorization
        }
        JournalError::Oversized => RuntimeError::ReplayCapacity,
        _ => RuntimeError::RuntimeUnavailable,
    }
}

#[cfg(test)]
#[path = "write_dispatch_tests.rs"]
mod tests;
