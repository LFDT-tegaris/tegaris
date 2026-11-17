//! Closed lifecycle projection from durable journal history. This data carries
//! no status permission, provider detail, receipt, log or transaction payload.
use crate::journal::{GovernedCommand, JournalState, SenderBoundary};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmissionDisposition {
    ReadyToBroadcast,
    BroadcastStarted,
    Accepted,
    DefinitelyRejected,
    PossiblySent,
    NonceConflict,
    Quarantined,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainObservation {
    NotObserved,
    MempoolObserved,
    Included,
    Safe,
    Finalized,
    Reorged,
    Invalidated,
    Superseded,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    Unknown,
    Success,
    Reverted,
}

/// One read model for Broker, reconciliation and response adapters. Values are
/// derived from committed history, never from a provider acknowledgment alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionStatus {
    pub operation_id: String,
    pub submission: SubmissionDisposition,
    pub observation: ChainObservation,
    pub execution: ExecutionOutcome,
    pub automatic_attempt_started: bool,
    pub automatic_resubmission_prohibited: bool,
    pub provider_acknowledged: bool,
    pub updated_at: String,
}

/// The canonical JSON-RPC OperationStatus schema. Keep the richer internal
/// observation/execution axes out of this closed public compatibility object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationStatusView {
    pub operation_id: String,
    pub signed_transaction_hash: String,
    pub state: String,
    pub truth_state: String,
    pub attempt_id: String,
    pub evidence_digest: String,
}

impl OperationStatusView {
    pub(crate) fn project(
        command: &GovernedCommand,
        status: &SubmissionStatus,
        head: &SenderBoundary,
    ) -> RuntimeResult<Self> {
        let valid_id = |id: &str| {
            uuid::Uuid::try_parse(id)
                .is_ok_and(|parsed| parsed.get_version_num() == 7 && parsed.to_string() == id)
        };
        let valid_hash = command
            .request_or_transaction_hash
            .strip_prefix("0x")
            .is_some_and(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
        if !valid_id(&command.command_id)
            || !valid_id(&command.attempt_id)
            || !valid_hash
            || status.operation_id != command.command_id
            || head.operation_id != command.command_id
            || head.attempt_id != command.attempt_id
            || head.automatic_attempt_started != status.automatic_attempt_started
            || head.automatic_resubmission_prohibited != status.automatic_resubmission_prohibited
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let (state, truth_state) = match (status.submission, status.observation, status.execution) {
            // Preserve the frozen OperationStatus vocabulary. The internal
            // chain observation retains SUPERSEDED and the evidence binds both
            // exact hashes; no timeout/nonce inference reaches this branch.
            (_, ChainObservation::Superseded, _) => ("REJECTED", "CONFLICTING"),
            (_, ChainObservation::Reorged, _) => ("REORG", "REORG"),
            (_, ChainObservation::Invalidated, _) => ("FAILED", "UNAVAILABLE"),
            (_, ChainObservation::Finalized, ExecutionOutcome::Success) => ("CONFIRMED", "SUCCESS"),
            (_, ChainObservation::Finalized, ExecutionOutcome::Reverted) => ("FAILED", "FAILED"),
            (_, ChainObservation::Finalized, ExecutionOutcome::Unknown) => ("CONFIRMED", "UNKNOWN"),
            (SubmissionDisposition::ReadyToBroadcast, _, _) => ("PREPARED", "UNKNOWN"),
            (SubmissionDisposition::BroadcastStarted, _, _) => ("ATTEMPT_STARTED", "UNKNOWN"),
            (SubmissionDisposition::PossiblySent, _, _) => ("WRITE_AMBIGUITY", "WRITE_AMBIGUITY"),
            (SubmissionDisposition::DefinitelyRejected, _, _) => ("REJECTED", "DENIED"),
            (SubmissionDisposition::NonceConflict, _, _) => ("REJECTED", "CONFLICTING"),
            (SubmissionDisposition::Quarantined, _, _) => ("FAILED", "UNAVAILABLE"),
            (SubmissionDisposition::Accepted, _, _) => ("ACCEPTED", "UNKNOWN"),
        };
        Ok(Self {
            operation_id: format!("urn:openpc:operation:{}", command.command_id),
            signed_transaction_hash: command.request_or_transaction_hash.clone(),
            state: state.into(),
            truth_state: truth_state.into(),
            attempt_id: command.attempt_id.clone(),
            evidence_digest: format!(
                "sha256:{}",
                head.digest()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?
            ),
        })
    }
}
impl SubmissionStatus {
    pub(crate) fn prepared(operation_id: &str) -> Self {
        Self {
            operation_id: operation_id.into(),
            submission: SubmissionDisposition::ReadyToBroadcast,
            observation: ChainObservation::NotObserved,
            execution: ExecutionOutcome::Unknown,
            automatic_attempt_started: false,
            automatic_resubmission_prohibited: false,
            provider_acknowledged: false,
            updated_at: String::new(),
        }
    }
    pub(crate) fn apply(&mut self, state: JournalState, updated_at: &str) {
        use SubmissionDisposition as D;
        match state {
            JournalState::Prepared => {}
            JournalState::Observed => {} // Applied from the verified observation payload.
            JournalState::FailedPreStart => {
                self.submission = D::DefinitelyRejected;
                self.automatic_resubmission_prohibited = true;
            }
            JournalState::Started => {
                self.submission = D::BroadcastStarted;
                self.automatic_attempt_started = true;
                self.automatic_resubmission_prohibited = true;
            }
            JournalState::Acknowledged => {
                self.submission = D::Accepted;
                self.provider_acknowledged = true;
            }
            JournalState::Ambiguous => {
                // An already committed acknowledgement is not erased by a
                // later response-release failure or observation uncertainty.
                if !self.provider_acknowledged {
                    self.submission = D::PossiblySent;
                }
            }
            JournalState::Included => {
                self.submission = D::Accepted;
                self.observation = ChainObservation::Included;
            }
            JournalState::Executed => self.execution = ExecutionOutcome::Success,
            JournalState::Reverted => {
                self.submission = D::Accepted;
                self.observation = ChainObservation::Included;
                self.execution = ExecutionOutcome::Reverted;
            }
            JournalState::Finalized => self.observation = ChainObservation::Finalized,
            // The historical component state has no exact replacement proof.
            // It cannot establish SUPERSEDED merely from a missing receipt.
            JournalState::DroppedConfirmed => self.submission = D::Quarantined,
        }
        self.updated_at = updated_at.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledgment_inclusion_execution_and_finality_are_independent_truths() {
        let mut status = SubmissionStatus::prepared("operation");
        for (step, observation, execution, acknowledged) in [
            (
                JournalState::Prepared,
                ChainObservation::NotObserved,
                ExecutionOutcome::Unknown,
                false,
            ),
            (
                JournalState::Started,
                ChainObservation::NotObserved,
                ExecutionOutcome::Unknown,
                false,
            ),
            (
                JournalState::Acknowledged,
                ChainObservation::NotObserved,
                ExecutionOutcome::Unknown,
                true,
            ),
            (
                JournalState::Included,
                ChainObservation::Included,
                ExecutionOutcome::Unknown,
                true,
            ),
            (
                JournalState::Executed,
                ChainObservation::Included,
                ExecutionOutcome::Success,
                true,
            ),
            (
                JournalState::Finalized,
                ChainObservation::Finalized,
                ExecutionOutcome::Success,
                true,
            ),
        ] {
            status.apply(step, "2026-09-16T00:00:00.000000Z");
            assert_eq!(
                (
                    status.observation,
                    status.execution,
                    status.provider_acknowledged
                ),
                (observation, execution, acknowledged)
            );
            assert_eq!(
                status.automatic_attempt_started,
                step != JournalState::Prepared
            );
            assert_eq!(
                status.automatic_resubmission_prohibited,
                step != JournalState::Prepared
            );
        }
    }
}
