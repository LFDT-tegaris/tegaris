//! Observation custody for previously started owned submissions. A sealed
//! target carries the exact journal head; only protocol observations advance it.
use super::{JournalError, JournalRecord, JournalState, WriteJournal, command_from_record};
use crate::{
    provider_connection::ConnectionRecord,
    submission_operation::SubmissionAdmission,
    submission_status::{
        ChainObservation, ExecutionOutcome, SubmissionDisposition, SubmissionStatus,
    },
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};

#[path = "submission_observer.rs"]
mod protocol;
pub use protocol::observe_submission;

/// Implemented by the target's current recovery-route owner. These short
/// fences cover trusted route/configuration/fact state, not a new user grant.
pub trait LiveObservationAuthority: Send + Sync {
    fn acquire<'a>(
        &'a self,
        target: &ObservationTarget,
        connection: &ConnectionRecord,
        anchor: &crate::route_witness::VerifiedChainAnchor,
        witness: &crate::route_witness::VerifiedRouteWitness,
    ) -> RuntimeResult<Box<dyn ObservationAuthorityLease + 'a>>;
}
pub trait ObservationAuthorityLease {
    fn revalidate(&self) -> RuntimeResult<()>;
}

/// Reconstructed from exclusive durable custody, never from a status parameter
/// or caller-provided transaction/receipt identity. It authorizes no network I/O.
#[derive(Clone, Debug)]
pub struct ObservationTarget {
    command: super::GovernedCommand,
    admission: SubmissionAdmission,
    signed: super::SignedIdentity,
    head: Digest,
    operation_digest: Digest,
    prior: Option<ObservationState>,
    monitors_replacement: bool,
}
impl ObservationTarget {
    pub fn command(&self) -> &super::GovernedCommand {
        &self.command
    }
    pub fn admission(&self) -> &SubmissionAdmission {
        &self.admission
    }
    pub fn chain_id(&self) -> u64 {
        self.signed.chain_id
    }
    pub fn binding_digest(&self) -> &Digest {
        &self.head
    }
    pub fn operation_digest(&self) -> &Digest {
        &self.operation_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedBlock {
    number: u64,
    hash: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cigl_post_mine: Option<crate::cigl::reconciliation::PostMineComparison>,
    observation: ChainObservation,
    execution: ExecutionOutcome,
    block: Option<ObservedBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creation: Option<crate::deployment::MinedCreationEvidence>,
}
impl ObservationState {
    pub(super) fn is_finalized(&self) -> bool {
        self.observation == ChainObservation::Finalized
    }
    pub(super) fn apply(&self, status: &mut SubmissionStatus) {
        status.submission = SubmissionDisposition::Accepted;
        status.observation = self.observation;
        status.execution = self.execution;
    }
    fn validate(&self) -> Result<(), JournalError> {
        let valid = match self.observation {
            ChainObservation::MempoolObserved => {
                self.block.is_none() && self.execution == ExecutionOutcome::Unknown
            }
            ChainObservation::Included | ChainObservation::Safe | ChainObservation::Finalized => {
                self.block.is_some() && self.execution != ExecutionOutcome::Unknown
            }
            ChainObservation::Reorged | ChainObservation::Invalidated => {
                self.block.is_some() && self.execution == ExecutionOutcome::Unknown
            }
            _ => false,
        };
        if !valid
            || (self.creation.is_some()
                && (!matches!(
                    self.observation,
                    ChainObservation::Included
                        | ChainObservation::Safe
                        | ChainObservation::Finalized
                ) || self.execution != ExecutionOutcome::Success))
            || self
                .block
                .as_ref()
                .is_some_and(|block| Digest::parse(block.hash.as_str()).is_err())
        {
            return Err(JournalError::Integrity);
        }
        Ok(())
    }
    fn validate_creation(
        &self,
        admission: &SubmissionAdmission,
        require_complete: bool,
    ) -> Result<(), JournalError> {
        let included = matches!(
            self.observation,
            ChainObservation::Included | ChainObservation::Safe | ChainObservation::Finalized
        );
        match (&self.cigl_post_mine, &admission.cigl_post_mine) {
            (Some(comparison), Some(expected)) if included => {
                comparison
                    .validate(expected)
                    .map_err(|_| JournalError::Integrity)?;
            }
            (None, Some(_)) if included && require_complete => return Err(JournalError::Integrity),
            (None, _) => {}
            _ => return Err(JournalError::Integrity),
        }
        if let Some(creation) = &self.creation {
            let deployment = admission
                .deployment
                .as_ref()
                .ok_or(JournalError::Integrity)?;
            if deployment.transaction.is_none() {
                return Err(JournalError::Integrity);
            }
            creation
                .validate(&deployment.constraints)
                .map_err(|_| JournalError::Integrity)?;
        } else if require_complete
            && self.execution == ExecutionOutcome::Success
            && admission
                .deployment
                .as_ref()
                .is_some_and(|deployment| deployment.transaction.is_some())
        {
            return Err(JournalError::Integrity);
        }
        Ok(())
    }
    fn validate_successor(
        &self,
        prior: Option<&Self>,
        monitors_replacement: bool,
    ) -> Result<(), JournalError> {
        self.validate()?;
        if self.observation == ChainObservation::Invalidated
            && prior.is_none_or(|state| !state.is_finalized() || state.creation.is_none())
        {
            return Err(JournalError::ForbiddenTransition);
        }
        let Some(prior) = prior else {
            return Ok(());
        };
        if prior.is_finalized() {
            return if self == prior
                || ((prior.creation.is_some()
                    || prior.cigl_post_mine.is_some()
                    || monitors_replacement)
                    && matches!(
                        self.observation,
                        ChainObservation::Reorged | ChainObservation::Invalidated
                    )
                    && self.block == prior.block)
            {
                Ok(())
            } else {
                Err(JournalError::ForbiddenTransition)
            };
        }
        if prior.observation != ChainObservation::Reorged
            && prior.block.is_some()
            && (self.block != prior.block
                || self.observation == ChainObservation::MempoolObserved
                || (self.observation != ChainObservation::Reorged
                    && self.execution != prior.execution)
                || (self.observation != ChainObservation::Reorged
                    && prior.creation.is_some()
                    && self.creation != prior.creation)
                || (self.observation != ChainObservation::Reorged
                    && prior.cigl_post_mine.is_some()
                    && self.cigl_post_mine != prior.cigl_post_mine)
                || (prior.observation == ChainObservation::Safe
                    && self.observation == ChainObservation::Included))
        {
            return Err(JournalError::ForbiddenTransition);
        }
        Ok(())
    }
}

/// Non-deserializable result from the real pinned observer. The route and the
/// original journal head are part of its content, and raw provider data is absent.
#[derive(Debug)]
pub struct VerifiedObservation {
    evidence: ObservationEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservationEvidence {
    // Absent on historical records. V2 requires complete evidence for every
    // successful deployment that retained minimized signed-transaction identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    target_head: Digest,
    operation_id: String,
    attempt_id: String,
    transaction_hash: [u8; 32],
    connection: ConnectionRecord,
    route_witness_digest: Digest,
    state: Option<ObservationState>,
    completed_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
}
impl ObservationEvidence {
    pub(super) fn has_canonical_inclusion(&self) -> bool {
        self.state.as_ref().is_some_and(|state| {
            state.block.is_some()
                && state.execution != ExecutionOutcome::Unknown
                && matches!(
                    state.observation,
                    ChainObservation::Included
                        | ChainObservation::Safe
                        | ChainObservation::Finalized
                )
        })
    }
    pub(super) fn validate_pending_replacement(
        &self,
        predecessor: &JournalRecord,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        let head = predecessor
            .sender_boundary
            .as_ref()
            .ok_or(JournalError::IdentityMismatch)?;
        if self.version != Some(2)
            || !head.automatic_attempt_started
            || head.terminal
            || self.target_head.as_str() != head.digest()?
            || self.operation_id != predecessor.command_id
            || self.attempt_id != predecessor.attempt_id
            || predecessor
                .signed_identity
                .as_ref()
                .is_none_or(|id| id.transaction_hash != self.transaction_hash)
            || self.connection.status != crate::provider_connection::ConnectionStatus::Prepared
            || self.connection.valid_until_ms <= now_ms
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
            || self.exchanges.is_empty()
            || self.exchanges.len()
                > predecessor
                    .submission_admission
                    .as_ref()
                    .map_or(8, SubmissionAdmission::observation_call_budget)
            || self.state.as_ref().is_none_or(|state| {
                state.observation != ChainObservation::MempoolObserved
                    || state.execution != ExecutionOutcome::Unknown
                    || state.block.is_some()
                    || state.creation.is_some()
            })
            || predecessor
                .observation
                .as_ref()
                .and_then(|proof| proof.state.as_ref())
                .is_some_and(|state| {
                    state.observation != ChainObservation::MempoolObserved
                        || state.execution != ExecutionOutcome::Unknown
                })
        {
            return Err(JournalError::ForbiddenTransition);
        }
        Ok(())
    }
    pub(super) fn invalidate_occurrence(
        &self,
        occurrence: &crate::deployment::occurrence::DeploymentOccurrence,
    ) -> RuntimeResult<crate::deployment::occurrence::DeploymentInvalidation> {
        if !self.is_deployment_invalidation() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(crate::deployment::occurrence::DeploymentInvalidation {
            occurrence_id: occurrence.id().into(),
            occurrence_digest: occurrence.digest().clone(),
            reason: (if self
                .state
                .as_ref()
                .is_some_and(|state| state.observation == ChainObservation::Reorged)
            {
                "REORG"
            } else {
                "CODE_IDENTITY_MISMATCH"
            })
            .into(),
            observation_digest: self.digest()?,
        })
    }
    pub(super) fn is_deployment_invalidation(&self) -> bool {
        self.state.as_ref().is_some_and(|state| {
            state.creation.is_none()
                && state.execution == ExecutionOutcome::Unknown
                && matches!(
                    state.observation,
                    ChainObservation::Reorged | ChainObservation::Invalidated
                )
        })
    }
    pub(super) fn has_finalized_creation(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| state.is_finalized() && state.creation.is_some())
    }
    pub(super) fn finalized_occurrence(
        &self,
        admission: &SubmissionAdmission,
        attempt: &crate::deployment::occurrence::DeploymentAttemptBinding,
    ) -> RuntimeResult<Option<crate::deployment::occurrence::DeploymentOccurrence>> {
        let Some(state) = &self.state else {
            return Ok(None);
        };
        if state.observation != ChainObservation::Finalized
            || state.execution != ExecutionOutcome::Success
        {
            return Ok(None);
        }
        let Some(creation) = &state.creation else {
            return Ok(None);
        };
        state
            .validate_creation(admission, true)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let block = state
            .block
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        crate::deployment::occurrence::DeploymentOccurrence::finalized(
            admission,
            attempt,
            &block.hash,
            block.number,
            creation,
        )
        .map(Some)
    }
    fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:submission-observation:v1", self)).map(Digest::of)
    }
    pub(super) fn is_finalized(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(ObservationState::is_finalized)
    }
    pub(super) fn apply(&self, status: &mut SubmissionStatus) {
        if let Some(state) = &self.state {
            state.apply(status);
        }
    }
}
impl VerifiedObservation {
    pub(super) fn validate_replacement_binding(
        &self,
        target: &ObservationTarget,
        connection: &ConnectionRecord,
        now_ms: u64,
    ) -> Result<(), JournalError> {
        self.validate_binding(
            target,
            connection,
            &self.evidence.route_witness_digest,
            now_ms,
        )
        .map_err(|_| JournalError::IdentityMismatch)
    }
    pub(super) fn into_evidence(self) -> ObservationEvidence {
        self.evidence
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.evidence.digest()
    }
    pub fn validate_binding(
        &self,
        target: &ObservationTarget,
        connection: &ConnectionRecord,
        route_witness_digest: &Digest,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        if self.evidence.target_head != target.head
            || self.evidence.operation_id != target.command.command_id
            || self.evidence.attempt_id != target.command.attempt_id
            || self.evidence.transaction_hash != target.signed.transaction_hash
            || &self.evidence.connection != connection
            || &self.evidence.route_witness_digest != route_witness_digest
            || now_ms < self.evidence.completed_at_ms
            || now_ms >= self.evidence.valid_until_ms
            || self.evidence.exchanges.is_empty()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
}

impl WriteJournal {
    /// Scoped callers still own disclosure authorization. This projection is
    /// taken only from committed observation history, including restart replay.
    pub fn cigl_post_mine_comparison(
        &self,
        command_id: &str,
    ) -> Result<Option<&crate::cigl::reconciliation::PostMineComparison>, JournalError> {
        self.ensure_healthy()?;
        Ok(self
            .latest_by_command
            .get(command_id)
            .and_then(|record| record.observation.as_ref())
            .and_then(|evidence| evidence.state.as_ref())
            .and_then(|state| state.cigl_post_mine.as_ref()))
    }
    pub fn observation_target(
        &self,
        operation_id: &str,
    ) -> Result<Option<ObservationTarget>, JournalError> {
        self.ensure_healthy()?;
        let Some(record) = self.latest_by_command.get(operation_id) else {
            return Ok(None);
        };
        let Some(admission) = &record.submission_admission else {
            return Ok(None);
        };
        let Some(head) = &record.sender_boundary else {
            return Ok(None);
        };
        // A fee-bump link keeps finalized hashes observable, but it cannot
        // reopen a terminal deployment invalidation. That result permanently
        // suspends the original occurrence and its governance association.
        let invalidated_deployment = head.terminal
            && admission.deployment.is_some()
            && record
                .observation
                .as_ref()
                .is_some_and(ObservationEvidence::is_deployment_invalidation);
        if admission.chain.is_none()
            || !head.automatic_attempt_started
            || invalidated_deployment
            || (head.terminal
                && !monitors_finalized_submission(record)
                && !super::replacement::related(&self.latest_by_command, operation_id))
            || !matches!(
                record.state,
                JournalState::Acknowledged | JournalState::Ambiguous | JournalState::Observed
            )
        {
            return Ok(None);
        }
        Ok(Some(ObservationTarget {
            command: command_from_record(record),
            admission: admission.clone(),
            signed: record
                .signed_identity
                .clone()
                .ok_or(JournalError::IdentityMismatch)?,
            head: Digest::parse(head.digest()?).map_err(|_| JournalError::Integrity)?,
            operation_digest: Digest::parse(&head.operation_digest)
                .map_err(|_| JournalError::Integrity)?,
            monitors_replacement: super::replacement::related(
                &self.latest_by_command,
                operation_id,
            ),
            prior: record
                .observation
                .as_ref()
                .and_then(|evidence| evidence.state.clone()),
        }))
    }

    pub fn pending_observations(
        &self,
        limit: usize,
    ) -> Result<Vec<ObservationTarget>, JournalError> {
        self.pending_observations_after(None, limit)
    }

    /// Exclusive key cursor keeps a quiet or denied operation from starving
    /// later operations. The scheduler wraps after reaching the end.
    pub fn pending_observations_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObservationTarget>, JournalError> {
        self.ensure_healthy()?;
        if limit == 0 || limit > 64 {
            return Err(JournalError::Oversized);
        }
        let mut targets = Vec::new();
        use std::ops::Bound::{Excluded, Unbounded};
        let start = after.map_or(Unbounded, Excluded);
        for (operation_id, _) in self.latest_by_command.range::<str, _>((start, Unbounded)) {
            if let Some(target) = self.observation_target(operation_id)? {
                targets.push(target);
            }
            if targets.len() == limit {
                break;
            }
        }
        Ok(targets)
    }

    /// The caller retains current observation-route authority through this
    /// synchronous commit. Compare-and-append prevents a delayed observation
    /// from rewriting a newer inclusion, reorg, or finality result.
    pub fn commit_observation(
        &mut self,
        target: &ObservationTarget,
        proof: VerifiedObservation,
        now_ms: u64,
    ) -> Result<bool, JournalError> {
        let current = self
            .observation_target(&target.command.command_id)?
            .ok_or(JournalError::ForbiddenTransition)?;
        if current.head != target.head {
            return Err(JournalError::IdentityMismatch);
        }
        proof
            .validate_binding(
                target,
                &proof.evidence.connection,
                &proof.evidence.route_witness_digest,
                now_ms,
            )
            .map_err(|_| JournalError::IdentityMismatch)?;
        let Some(state) = &proof.evidence.state else {
            return Ok(false);
        };
        state.validate_creation(&target.admission, true)?;
        state.validate_successor(target.prior.as_ref(), current.monitors_replacement)?;
        if target.prior.as_ref() == Some(state) {
            return Ok(false);
        }
        let prior = self
            .latest_by_command
            .get(&target.command.command_id)
            .ok_or(JournalError::IdentityMismatch)?
            .clone();
        self.append_from_record_with_observation(
            &prior,
            JournalState::Observed,
            None,
            Some((
                "EXACT_TRANSACTION_OBSERVATION".into(),
                "TRANSACTION_STATUS".into(),
            )),
            Some(
                proof
                    .digest()
                    .map_err(|_| JournalError::Integrity)?
                    .as_str()
                    .into(),
            ),
            crate::event::EventKind::WriteReconciled,
            Some(proof.evidence),
        )?;
        Ok(true)
    }
}

/// Canonicality monitoring may invalidate a creation or CIGL comparison, while
/// the send boundary stays terminal. Historical ordinary records stay closed.
pub(super) fn monitors_finalized_submission(record: &JournalRecord) -> bool {
    if record
        .submission_admission
        .as_ref()
        .is_some_and(|admission| admission.cigl_post_mine.is_some())
    {
        return record
            .observation
            .as_ref()
            .and_then(|evidence| evidence.state.as_ref())
            .is_some_and(|state| state.is_finalized() && state.cigl_post_mine.is_some());
    }
    record
        .submission_admission
        .as_ref()
        .is_some_and(|admission| {
            admission
                .deployment
                .as_ref()
                .is_some_and(|deployment| deployment.dispatch.is_some())
        })
        && record
            .observation
            .as_ref()
            .is_some_and(ObservationEvidence::has_finalized_creation)
}

pub(super) fn validate_record(
    record: &JournalRecord,
    prior: Option<&JournalRecord>,
    monitors_replacement: bool,
) -> Result<(), JournalError> {
    if record.state != JournalState::Observed {
        return if record.observation.is_none() {
            Ok(())
        } else {
            Err(JournalError::Integrity)
        };
    }
    let observation = record.observation.as_ref().ok_or(JournalError::Integrity)?;
    if !matches!(observation.version, None | Some(2)) {
        return Err(JournalError::Integrity);
    }
    let state = observation.state.as_ref().ok_or(JournalError::Integrity)?;
    if observation.version.is_none() && state.creation.is_some() {
        return Err(JournalError::Integrity);
    }
    state.validate_creation(
        record
            .submission_admission
            .as_ref()
            .ok_or(JournalError::Integrity)?,
        observation.version == Some(2),
    )?;
    observation
        .state
        .as_ref()
        .ok_or(JournalError::Integrity)?
        .validate()?;
    let predecessor = prior.ok_or(JournalError::Integrity)?;
    observation
        .state
        .as_ref()
        .ok_or(JournalError::Integrity)?
        .validate_successor(
            predecessor
                .observation
                .as_ref()
                .and_then(|evidence| evidence.state.as_ref()),
            monitors_replacement,
        )?;
    if observation.target_head.as_str()
        != predecessor
            .sender_boundary
            .as_ref()
            .ok_or(JournalError::Integrity)?
            .digest()?
        || observation.operation_id != record.command_id
        || observation.attempt_id != record.attempt_id
        || record
            .signed_identity
            .as_ref()
            .is_none_or(|identity| identity.transaction_hash != observation.transaction_hash)
        || record.evidence_digest.as_deref()
            != Some(
                observation
                    .digest()
                    .map_err(|_| JournalError::Integrity)?
                    .as_str(),
            )
        || observation.exchanges.is_empty()
        || observation.exchanges.len()
            > record
                .submission_admission
                .as_ref()
                .map_or(8, SubmissionAdmission::observation_call_budget)
        || observation.completed_at_ms >= observation.valid_until_ms
    {
        return Err(JournalError::Integrity);
    }
    if record
        .submission_admission
        .as_ref()
        .is_none_or(|admission| admission.chain.is_none())
        || prior.is_none()
        || record.evidence_digest.is_none()
        || record.reconciliation_method.as_deref() != Some("EXACT_TRANSACTION_OBSERVATION")
        || record.reconciliation_data_class.as_deref() != Some("TRANSACTION_STATUS")
    {
        return Err(JournalError::Integrity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "submission_replacement_tests.rs"]
mod replacement_tests;
