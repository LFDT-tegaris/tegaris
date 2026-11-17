//! Per-operation append-only sender evidence, committed inside the write frame.
//! This is the local durable encoding of the monotonic sender contract; it is
//! not a claim of the external TransactionOperationV4/CBOR wire encoding.
use super::{JournalError, JournalRecord, JournalState, hex_digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SenderBoundary {
    pub domain: String,
    pub operation_id: String,
    pub operation_digest: String,
    pub attempt_id: String,
    pub state_sequence: u64,
    pub prior_evidence_digest: Option<String>,
    pub transition: JournalState,
    pub observed_at: String,
    pub terminal: bool,
    pub automatic_attempt_started: bool,
    pub automatic_resubmission_prohibited: bool,
    pub event_digest: String,
}

impl SenderBoundary {
    pub fn digest(&self) -> Result<String, JournalError> {
        Ok(hex_digest(&serde_json::to_vec(self)?))
    }

    pub(super) fn genesis(record: &JournalRecord) -> Result<Self, JournalError> {
        if record.state != JournalState::Prepared || record.submission_admission.is_none() {
            return Err(JournalError::ForbiddenTransition);
        }
        // Bind the entire initial operation, including nonce, signed identity,
        // exact admission and event. Excluding the head avoids a digest cycle.
        let mut operation = record.clone();
        operation.sender_boundary = None;
        Ok(Self {
            domain: "openpc:sender-boundary:v2".into(),
            operation_id: record.command_id.clone(),
            operation_digest: hex_digest(&serde_json::to_vec(&operation)?),
            attempt_id: record.attempt_id.clone(),
            state_sequence: 1,
            prior_evidence_digest: None,
            transition: JournalState::Prepared,
            observed_at: record.event.time.clone(),
            terminal: false,
            automatic_attempt_started: false,
            automatic_resubmission_prohibited: false,
            event_digest: record.event_digest.clone(),
        })
    }

    pub(super) fn advance(
        &self,
        record: &JournalRecord,
        monitors_replacement: bool,
    ) -> Result<Self, JournalError> {
        let deployment_invalidation = record.state == JournalState::Observed
            && self.automatic_attempt_started
            && (monitors_replacement
                || record
                    .submission_admission
                    .as_ref()
                    .is_some_and(|admission| {
                        admission.cigl_post_mine.is_some()
                            || admission
                                .deployment
                                .as_ref()
                                .is_some_and(|deployment| deployment.dispatch.is_some())
                    }))
            && record
                .observation
                .as_ref()
                .is_some_and(|observation| observation.is_deployment_invalidation());
        let replacement_observation = monitors_replacement
            && self.automatic_attempt_started
            && record.state == JournalState::Observed
            && record.observation.is_some();
        if (self.terminal && !deployment_invalidation && !replacement_observation)
            || self.operation_id != record.command_id
            || self.attempt_id != record.attempt_id
            || record.event.time < self.observed_at
            || record.state == JournalState::Prepared
        {
            return Err(JournalError::ForbiddenTransition);
        }
        let started = self.automatic_attempt_started || record.state == JournalState::Started;
        // A reverted receipt is not finality. Observation/recovery may still
        // proceed, but it can never authorize another automatic attempt.
        let terminal = self.terminal
            || matches!(
                record.state,
                JournalState::FailedPreStart
                    | JournalState::Finalized
                    | JournalState::DroppedConfirmed
            )
            || record
                .observation
                .as_ref()
                .is_some_and(|observation| observation.is_finalized());
        Ok(Self {
            domain: self.domain.clone(),
            operation_id: self.operation_id.clone(),
            operation_digest: self.operation_digest.clone(),
            attempt_id: self.attempt_id.clone(),
            state_sequence: self
                .state_sequence
                .checked_add(1)
                .ok_or(JournalError::Integrity)?,
            prior_evidence_digest: Some(self.digest()?),
            transition: record.state,
            observed_at: record.event.time.clone(),
            terminal,
            automatic_attempt_started: started,
            automatic_resubmission_prohibited: self.automatic_resubmission_prohibited
                || started
                || terminal,
            event_digest: record.event_digest.clone(),
        })
    }
}

pub(super) fn validate(
    record: &JournalRecord,
    prior: Option<&JournalRecord>,
    monitors_replacement: bool,
) -> Result<(), JournalError> {
    let expected = match prior {
        Some(prior) => prior
            .sender_boundary
            .as_ref()
            .map(|head| head.advance(record, monitors_replacement))
            .transpose()?,
        None if record.sender_boundary.is_some() => Some(SenderBoundary::genesis(record)?),
        None => None, // Legacy evidence is retained, never silently backfilled.
    };
    if record.sender_boundary != expected {
        return Err(JournalError::Integrity);
    }
    Ok(())
}
