use crate::error::JournalError;
use crate::event::{EventContext, EventKind, OpenPcEventEnvelopeV1, hex_digest};
use crate::signed_transaction::SignedTransaction;
use crate::submission_operation::{SubmissionAdmission, SubmissionOwner};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[path = "sender_boundary.rs"]
mod sender_boundary;
pub use sender_boundary::SenderBoundary;

#[path = "submission_observation.rs"]
mod observation;
pub use observation::{
    LiveObservationAuthority, ObservationAuthorityLease, ObservationTarget, VerifiedObservation,
    observe_submission,
};

#[path = "submission_replacement.rs"]
mod replacement;

const DOMAIN: &str = "openpc:multi-rpc:write-journal:v1";
const VERSION: u16 = 1;
const GENESIS_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_FRAME_BYTES: usize = 1_048_576;
// Stop before exhaustion; retention/rotation belongs to an explicit custody
// operation. Never discard a started command to make room for another send.
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JournalState {
    Prepared,
    Started,
    Acknowledged,
    Ambiguous,
    Included,
    Executed,
    Finalized,
    Reverted,
    DroppedConfirmed,
    FailedPreStart,
    Observed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCommand {
    pub command_id: String,
    pub method: String,
    pub immutable_request_digest: String,
    pub request_or_transaction_hash: String,
    pub submitted_bytes_digest: String,
    pub provider_profile_digest: String,
    pub provider_instance_id: String,
    pub attempt_id: String,
    pub anchor_digest: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub correlation_id: String,
    pub occurred_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationEvidence {
    pub request_or_transaction_hash: String,
    pub provider_profile_digest: String,
    pub provider_instance_id: String,
    pub attempt_id: String,
    pub anchor_digest: String,
    pub observation_method: String,
    pub observation_data_class: String,
    pub evidence_digest: String,
    pub next_state: JournalState,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PreparedCommand {
    command: GovernedCommand,
    lease_id: Uuid,
}

impl PreparedCommand {
    pub fn command(&self) -> &GovernedCommand {
        &self.command
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StartedCommand {
    command: GovernedCommand,
    lease_id: Uuid,
}

impl StartedCommand {
    pub fn command(&self) -> &GovernedCommand {
        &self.command
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    command_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_created_at: Option<String>,
    method: String,
    immutable_request_digest: String,
    request_or_transaction_hash: String,
    submitted_bytes_digest: String,
    provider_profile_digest: String,
    provider_instance_id: String,
    attempt_id: String,
    anchor_digest: String,
    state: JournalState,
    no_bytes_sent_evidence_digest: Option<String>,
    reconciliation_method: Option<String>,
    reconciliation_data_class: Option<String>,
    evidence_digest: Option<String>,
    event: OpenPcEventEnvelopeV1,
    event_digest: String,
    // Absent only in legacy component journals. Preserve their digest encoding;
    // production submission requires a locally verified identity here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_identity: Option<SignedIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submission_admission: Option<SubmissionAdmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_boundary: Option<SenderBoundary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation: Option<observation::ObservationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fee_identity: Option<crate::signed_transaction::FeeBumpIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<replacement::ReplacementLink>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedIdentity {
    chain_id: u64,
    signer: [u8; 20],
    nonce: u64,
    transaction_hash: [u8; 32],
}
impl From<&SignedTransaction> for SignedIdentity {
    fn from(transaction: &SignedTransaction) -> Self {
        Self {
            chain_id: transaction.chain_id(),
            signer: *transaction.signer(),
            nonce: transaction.nonce(),
            transaction_hash: *transaction.hash(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFrame {
    domain: String,
    version: u16,
    sequence: u64,
    predecessor_digest: String,
    record: JournalRecord,
    record_digest: String,
}

#[derive(Serialize)]
struct DigestMaterial<'a> {
    domain: &'a str,
    version: u16,
    sequence: u64,
    predecessor_digest: &'a str,
    record: &'a JournalRecord,
}

pub struct WriteJournal {
    path: PathBuf,
    file: File,
    frames: Vec<JournalFrame>,
    latest_by_command: BTreeMap<String, JournalRecord>,
    lease_id: Uuid,
    issued_prepared: BTreeSet<String>,
    poisoned: bool,
}

impl WriteJournal {
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(JournalError::Integrity)?;
        std::fs::create_dir_all(parent)?;
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .append(true)
            .open(&path)?;
        acquire_exclusive_lease(&file)?;
        file.sync_all()?;
        sync_directory(parent)?;
        Ok(Self {
            path,
            file,
            frames: Vec::new(),
            latest_by_command: BTreeMap::new(),
            lease_id: Uuid::now_v7(),
            issued_prepared: BTreeSet::new(),
            poisoned: false,
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new().read(true).append(true).open(&path)?;
        acquire_exclusive_lease(&file)?;
        if file.metadata()?.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Oversized);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let frames = decode_frames(&bytes)?;
        let latest_by_command = validate_frames(&frames)?;
        let mut journal = Self {
            path,
            file,
            frames,
            latest_by_command,
            lease_id: Uuid::now_v7(),
            issued_prepared: BTreeSet::new(),
            poisoned: false,
        };
        let unresolved = journal
            .latest_by_command
            .values()
            .filter(|record| record.state == JournalState::Started)
            .cloned()
            .collect::<Vec<_>>();
        for record in unresolved {
            journal.append_from_record(
                &record,
                JournalState::Ambiguous,
                None,
                None,
                Some("recovered-unresolved-start".to_owned()),
                EventKind::WriteAmbiguous,
            )?;
        }
        Ok(journal)
    }

    /// Reserve verified bytes and the chain/signer nonce in the same durable
    /// record as PREPARED. A second command cannot escape the reservation by
    /// changing its participant, provider, transaction hash or operation ID.
    /// A governed replacement needs its own explicit owner; this path never
    /// releases an uncertain send's nonce on timeout or provider rejection.
    pub fn prepare_signed(
        &mut self,
        command: GovernedCommand,
        transaction: &SignedTransaction,
    ) -> Result<PreparedCommand, JournalError> {
        crate::governed_write::validate_submission(transaction, &command)
            .map_err(|_| JournalError::IdentityMismatch)?;
        self.prepare_identity(
            command,
            Some(transaction.into()),
            None,
            Some(
                transaction
                    .unsigned()
                    .fee_bump_identity()
                    .map_err(|_| JournalError::IdentityMismatch)?,
            ),
            None,
        )
    }

    /// Operation ownership, PDS capability custody and nonce reservation share
    /// the same durable PREPARED record. No second journal commit can split them.
    pub fn prepare_submission(
        &mut self,
        command: GovernedCommand,
        transaction: &SignedTransaction,
        admission: SubmissionAdmission,
    ) -> Result<PreparedCommand, JournalError> {
        crate::governed_write::validate_submission(transaction, &command)
            .map_err(|_| JournalError::IdentityMismatch)?;
        admission.validate(&command)?;
        admission.validate_transaction(transaction)?;
        self.prepare_identity(
            command,
            Some(transaction.into()),
            Some(admission),
            Some(
                transaction
                    .unsigned()
                    .fee_bump_identity()
                    .map_err(|_| JournalError::IdentityMismatch)?,
            ),
            None,
        )
    }

    #[cfg(test)]
    pub fn prepare(&mut self, command: GovernedCommand) -> Result<PreparedCommand, JournalError> {
        self.prepare_identity(command, None, None, None, None)
    }

    fn prepare_identity(
        &mut self,
        command: GovernedCommand,
        signed_identity: Option<SignedIdentity>,
        submission_admission: Option<SubmissionAdmission>,
        fee_identity: Option<crate::signed_transaction::FeeBumpIdentity>,
        replacement: Option<replacement::ReplacementLink>,
    ) -> Result<PreparedCommand, JournalError> {
        self.ensure_healthy()?;
        validate_command(&command)?;
        if self.latest_by_command.contains_key(&command.command_id) {
            return Err(JournalError::DuplicateCommand);
        }
        validate_capability_reservation(&self.latest_by_command, submission_admission.as_ref())?;
        validate_exact_submission(
            &self.latest_by_command,
            signed_identity.as_ref(),
            submission_admission.as_ref(),
        )?;
        let mut record = record_from_command(
            &command,
            JournalState::Prepared,
            None,
            None,
            None,
            EventKind::RoutePrepared,
            self.next_sequence(),
        )?;
        record.signed_identity = signed_identity;
        record.submission_admission = submission_admission;
        record.fee_identity = fee_identity;
        record.replacement = replacement;
        replacement::validate_new(&self.latest_by_command, &record)?;
        if record.submission_admission.is_some() {
            record.sender_boundary = Some(SenderBoundary::genesis(&record)?);
        }
        self.append_record(record)?;
        self.issued_prepared.insert(command.command_id.clone());
        Ok(PreparedCommand {
            command,
            lease_id: self.lease_id,
        })
    }

    pub(crate) fn validate_signed_prepared(
        &self,
        prepared: &PreparedCommand,
        transaction: &SignedTransaction,
    ) -> Result<(), JournalError> {
        self.validate_prepared_handle(prepared)?;
        let record = self.exact_latest(prepared.command())?;
        replacement::validate_start(&self.latest_by_command, record)?;
        if record.state != JournalState::Prepared
            || record.signed_identity.as_ref() != Some(&SignedIdentity::from(transaction))
            || (record.submission_admission.is_some() && record.sender_boundary.is_none())
        {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(())
    }

    /// Reconstructs the sole usable handle for a durable PREPARED command after reopen.
    pub fn resume_prepared(&mut self, command_id: &str) -> Result<PreparedCommand, JournalError> {
        self.ensure_healthy()?;
        let record = self
            .latest_by_command
            .get(command_id)
            .ok_or(JournalError::IdentityMismatch)?;
        if record.state != JournalState::Prepared || !self.issued_prepared.insert(command_id.into())
        {
            return Err(JournalError::ForbiddenTransition);
        }
        Ok(PreparedCommand {
            command: command_from_record(record),
            lease_id: self.lease_id,
        })
    }

    pub fn reselect_prepared(
        &mut self,
        prepared: PreparedCommand,
        provider_profile_digest: String,
        provider_instance_id: String,
        attempt_id: String,
        no_bytes_sent_evidence_digest: String,
    ) -> Result<PreparedCommand, JournalError> {
        self.validate_prepared_handle(&prepared)?;
        if provider_profile_digest.is_empty()
            || provider_instance_id.is_empty()
            || attempt_id.is_empty()
            || no_bytes_sent_evidence_digest.is_empty()
        {
            return Err(JournalError::IdentityMismatch);
        }
        let prior = self.exact_latest(prepared.command())?.clone();
        if prior.submission_admission.is_some()
            || prior.state != JournalState::Prepared
            || (prior.provider_profile_digest == provider_profile_digest
                && prior.provider_instance_id == provider_instance_id)
            || prior.attempt_id == attempt_id
        {
            return Err(JournalError::ForbiddenTransition);
        }
        let mut next = prepared.command;
        next.provider_profile_digest = provider_profile_digest;
        next.provider_instance_id = provider_instance_id;
        next.attempt_id = attempt_id;
        let mut record = record_from_command(
            &next,
            JournalState::Prepared,
            Some(no_bytes_sent_evidence_digest),
            None,
            None,
            EventKind::RoutePrepared,
            self.next_sequence(),
        )?;
        record.signed_identity = prior.signed_identity;
        record.submission_admission = prior.submission_admission;
        record.fee_identity = prior.fee_identity;
        record.replacement = prior.replacement;
        self.append_record(record)?;
        Ok(PreparedCommand {
            command: next,
            lease_id: self.lease_id,
        })
    }

    pub fn mark_started(
        &mut self,
        prepared: PreparedCommand,
        evidence_digest: String,
    ) -> Result<StartedCommand, JournalError> {
        self.validate_prepared_handle(&prepared)?;
        let prior = self.exact_latest(prepared.command())?.clone();
        replacement::validate_start(&self.latest_by_command, &prior)?;
        if prior.submission_admission.is_some() && prior.sender_boundary.is_none() {
            return Err(JournalError::Integrity);
        }
        self.append_from_record(
            &prior,
            JournalState::Started,
            None,
            None,
            Some(evidence_digest),
            EventKind::AttemptStarted,
        )?;
        Ok(StartedCommand {
            command: prepared.command,
            lease_id: self.lease_id,
        })
    }

    pub fn mark_acknowledged(
        &mut self,
        started: &StartedCommand,
        acknowledgement_digest: String,
    ) -> Result<(), JournalError> {
        self.validate_started_handle(started)?;
        let prior = self.exact_latest(started.command())?.clone();
        self.append_from_record(
            &prior,
            JournalState::Acknowledged,
            None,
            None,
            Some(acknowledgement_digest),
            EventKind::AttemptResolved,
        )
    }

    pub fn mark_ambiguous(
        &mut self,
        started: &StartedCommand,
        evidence_digest: String,
    ) -> Result<(), JournalError> {
        self.validate_started_handle(started)?;
        let prior = self.exact_latest(started.command())?.clone();
        self.append_from_record(
            &prior,
            JournalState::Ambiguous,
            None,
            None,
            Some(evidence_digest),
            EventKind::WriteAmbiguous,
        )
    }

    pub fn fail_pre_start(
        &mut self,
        prepared: PreparedCommand,
        no_bytes_sent_evidence_digest: String,
    ) -> Result<(), JournalError> {
        self.validate_prepared_handle(&prepared)?;
        let prior = self.exact_latest(prepared.command())?.clone();
        self.append_from_record(
            &prior,
            JournalState::FailedPreStart,
            Some(no_bytes_sent_evidence_digest),
            None,
            None,
            EventKind::AttemptResolved,
        )
    }

    pub fn reconcile(
        &mut self,
        command_id: &str,
        evidence: ReconciliationEvidence,
    ) -> Result<(), JournalError> {
        let prior = self
            .latest_by_command
            .get(command_id)
            .ok_or(JournalError::IdentityMismatch)?
            .clone();
        // Legacy component evidence is a bag of identifiers, not verified chain
        // observation. Production operation reconciliation requires its own
        // exact-hash observation owner and cannot use this compatibility path.
        if prior.submission_admission.is_some() {
            return Err(JournalError::ForbiddenTransition);
        }
        if evidence.request_or_transaction_hash != prior.request_or_transaction_hash
            || evidence.provider_profile_digest != prior.provider_profile_digest
            || evidence.provider_instance_id != prior.provider_instance_id
            || evidence.attempt_id != prior.attempt_id
            || evidence.anchor_digest != prior.anchor_digest
            || evidence.evidence_digest.is_empty()
        {
            return Err(JournalError::IdentityMismatch);
        }
        let expected_observation = match evidence.next_state {
            JournalState::Included
            | JournalState::Executed
            | JournalState::Reverted
            | JournalState::DroppedConfirmed => {
                ("eth_getTransactionReceipt", "TRANSACTION_RECEIPT")
            }
            JournalState::Finalized => ("eth_getBlockByNumber", "BLOCK_HEADER"),
            _ => return Err(JournalError::ForbiddenTransition),
        };
        if (
            evidence.observation_method.as_str(),
            evidence.observation_data_class.as_str(),
        ) != expected_observation
        {
            return Err(JournalError::IdentityMismatch);
        }
        self.append_from_record(
            &prior,
            evidence.next_state,
            None,
            Some((evidence.observation_method, evidence.observation_data_class)),
            Some(evidence.evidence_digest),
            EventKind::WriteReconciled,
        )
    }

    pub fn latest_state(&self, command_id: &str) -> Option<JournalState> {
        self.ensure_healthy().ok()?;
        self.latest_by_command
            .get(command_id)
            .map(|record| record.state)
    }

    pub fn validate_submission_target(&self, target_id: &str) -> Result<(), JournalError> {
        if self.latest_by_command.values().any(|record| {
            record
                .submission_admission
                .as_ref()
                .is_none_or(|a| a.target_runtime_id != target_id)
        }) {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(())
    }

    /// The new exclusive process cannot possess an old volatile handoff. A
    /// durable PREPARED operation therefore closes as proved not started.
    pub fn abandon_prepared_submissions(&mut self) -> Result<usize, JournalError> {
        self.expire_owned_submissions(0, true)
    }

    /// Deadline expiry proves no send only while PREPARED. A canceled or stuck
    /// STARTED future becomes ambiguous; it can never become retryable.
    pub fn expire_submissions(&mut self, now_ms: u64) -> Result<usize, JournalError> {
        self.expire_owned_submissions(now_ms, false)
    }

    fn expire_owned_submissions(
        &mut self,
        now_ms: u64,
        abandoned: bool,
    ) -> Result<usize, JournalError> {
        self.ensure_healthy()?;
        let expired: Vec<_> = self
            .latest_by_command
            .values()
            .filter(|record| {
                record
                    .submission_admission
                    .as_ref()
                    .is_some_and(|admission| {
                        (record.state == JournalState::Prepared && abandoned)
                            || (matches!(
                                record.state,
                                JournalState::Prepared | JournalState::Started
                            ) && now_ms >= admission.valid_until_ms)
                    })
            })
            .cloned()
            .collect();
        let count = expired.len();
        for record in expired {
            if record.state == JournalState::Prepared {
                self.append_from_record(
                    &record,
                    JournalState::FailedPreStart,
                    Some(hex_digest(b"owned handoff expired before attempt start")),
                    None,
                    Some(hex_digest(b"prepared operation abandoned")),
                    EventKind::AttemptResolved,
                )?;
            } else {
                self.append_from_record(
                    &record,
                    JournalState::Ambiguous,
                    None,
                    None,
                    Some(hex_digest(
                        b"deadline elapsed after attempt start; outcome unknown",
                    )),
                    EventKind::WriteAmbiguous,
                )?;
            }
        }
        Ok(count)
    }

    /// Read-only identity for the authenticated status owner. A matching owner
    /// still needs a separate current OPERATION_STATUS_DISCLOSURE permission.
    pub fn submission(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> Option<(GovernedCommand, SubmissionAdmission, JournalState)> {
        let record = self.latest_by_command.get(command_id)?;
        self.ensure_healthy().ok()?;
        let admission = record.submission_admission.as_ref()?;
        if &admission.owner != owner {
            return None;
        }
        Some((command_from_record(record), admission.clone(), record.state))
    }

    /// Exact-hash replay lookup precedes new-attempt authorization. It never
    /// creates a prepared handle or grants disclosure or another attempt.
    pub fn submission_for_transaction(
        &self,
        transaction: &SignedTransaction,
        owner: &SubmissionOwner,
    ) -> Option<(GovernedCommand, SubmissionAdmission, JournalState)> {
        let identity = SignedIdentity::from(transaction);
        let record = self.latest_by_command.values().find(|record| {
            record.signed_identity.as_ref() == Some(&identity)
                && record
                    .submission_admission
                    .as_ref()
                    .is_some_and(|a| &a.owner == owner)
        })?;
        self.submission(&record.command_id, owner)
    }

    /// Outcome precedence for a repeated signed submission from its original
    /// authenticated credential. No current decision or provider is consulted.
    /// This cannot create a prepared handle or a second provider attempt.
    pub fn repeated_submission_view(
        &self,
        transaction: &SignedTransaction,
        participant_id: &str,
        privacy_domain_id: &str,
        workload_id: &str,
        peer_binding: &pc_runtime_types::Digest,
    ) -> pc_runtime_types::RuntimeResult<Option<crate::submission_status::OperationStatusView>>
    {
        self.ensure_healthy()
            .map_err(|_| pc_runtime_types::RuntimeError::RuntimeUnavailable)?;
        let identity = SignedIdentity::from(transaction);
        let record = self.latest_by_command.values().find(|record| {
            record.signed_identity.as_ref() == Some(&identity)
                && record
                    .submission_admission
                    .as_ref()
                    .is_some_and(|admission| {
                        admission.owner.participant_id == participant_id
                            && admission.owner.privacy_domain_id == privacy_domain_id
                            && admission.owner.workload_id == workload_id
                            && admission.workload_peer_binding_digest.as_ref() == Some(peer_binding)
                    })
        });
        let Some(record) = record else {
            return Ok(None);
        };
        self.submission_view(
            &record.command_id,
            &record
                .submission_admission
                .as_ref()
                .ok_or(pc_runtime_types::RuntimeError::RuntimeUnavailable)?
                .owner,
        )
    }

    pub fn submission_status(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> Option<crate::submission_status::SubmissionStatus> {
        let mut status = self.submission_own_status(command_id, owner)?;
        if let Some(successor) =
            replacement::superseding_successor(&self.latest_by_command, command_id)
        {
            status.observation = crate::submission_status::ChainObservation::Superseded;
            status.execution = crate::submission_status::ExecutionOutcome::Unknown;
            status.updated_at.clone_from(&successor.event.time);
        }
        Some(status)
    }

    fn submission_own_status(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> Option<crate::submission_status::SubmissionStatus> {
        self.submission(command_id, owner)?;
        let mut status = crate::submission_status::SubmissionStatus::prepared(command_id);
        for frame in self
            .frames
            .iter()
            .filter(|f| f.record.command_id == command_id)
        {
            status.apply(frame.record.state, &frame.record.event.time);
            if let Some(observation) = &frame.record.observation {
                observation.apply(&mut status);
            }
        }
        Some(status)
    }

    /// Durable projection bytes describe only this command's journal head.
    /// Replacement truth is derived by the read owner from both verified
    /// projections; a successor cannot change bytes at an unchanged sequence.
    pub(crate) fn submission_projection_view(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> pc_runtime_types::RuntimeResult<Option<crate::submission_status::OperationStatusView>>
    {
        let Some((command, _, _)) = self.submission(command_id, owner) else {
            return Ok(None);
        };
        let status = self
            .submission_own_status(command_id, owner)
            .ok_or(pc_runtime_types::RuntimeError::RuntimeUnavailable)?;
        let head = self
            .submission_boundary(command_id, owner)
            .ok_or(pc_runtime_types::RuntimeError::RuntimeUnavailable)?;
        crate::submission_status::OperationStatusView::project(&command, &status, &head).map(Some)
    }

    /// Safe evidence identity only. The caller still owns status authorization.
    pub fn submission_boundary(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> Option<SenderBoundary> {
        self.submission(command_id, owner)?;
        self.latest_by_command
            .get(command_id)?
            .sender_boundary
            .clone()
    }

    pub fn submission_view(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> pc_runtime_types::RuntimeResult<Option<crate::submission_status::OperationStatusView>>
    {
        let Some((command, _, _)) = self.submission(command_id, owner) else {
            return Ok(None);
        };
        let status = self
            .submission_status(command_id, owner)
            .ok_or(pc_runtime_types::RuntimeError::RuntimeUnavailable)?;
        let head = self
            .submission_boundary(command_id, owner)
            .ok_or(pc_runtime_types::RuntimeError::RuntimeUnavailable)?;
        let mut view =
            crate::submission_status::OperationStatusView::project(&command, &status, &head)?;
        if let Some(successor) =
            replacement::superseding_successor(&self.latest_by_command, command_id)
        {
            let evidence = pc_runtime_types::canonical_bytes(&(
                "openpc:replacement-outcome:v1",
                &head,
                &successor.sender_boundary,
                &successor.replacement,
                &successor.observation,
            ))?;
            view.evidence_digest =
                format!("sha256:{}", pc_runtime_types::Digest::of(evidence).as_str());
        }
        Ok(Some(view))
    }

    /// Safe immutable identity for an already authorized status/replay owner.
    pub fn command(&self, command_id: &str) -> Option<GovernedCommand> {
        self.latest_by_command
            .get(command_id)
            .map(command_from_record)
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    // The physical journal sequence orders changes across commands. Skip old
    // frames so capture always describes the current authoritative head.
    fn current_heads_after(&self, after: u64) -> impl Iterator<Item = &JournalFrame> {
        self.frames
            .iter()
            .skip(usize::try_from(after).unwrap_or(usize::MAX))
            .take(256)
            .filter(|frame| {
                self.latest_by_command.get(&frame.record.command_id) == Some(&frame.record)
            })
    }

    pub(crate) fn deployment_projection_after(
        &self,
        after: u64,
    ) -> pc_runtime_types::RuntimeResult<(
        u64,
        Option<crate::deployment::projection::DeploymentProjection>,
    )> {
        for frame in self.current_heads_after(after) {
            let record = &frame.record;
            if let (Some(admission), Some(head)) =
                (&record.submission_admission, &record.sender_boundary)
                && let Some(result) = crate::deployment::projection::capture(
                    self,
                    &record.command_id,
                    admission,
                    head,
                    frame.sequence,
                )?
            {
                return Ok((frame.sequence, Some(result)));
            }
        }
        Ok((
            after.saturating_add(256).min(self.frames.len() as u64),
            None,
        ))
    }

    /// Owner-scoped immutable deployment documents. A verified STARTED frame
    /// creates the historical attempt; only complete current FINALIZED success
    /// creates an occurrence. This grants no runtime or Participant authority.
    pub fn deployment_outcome(
        &self,
        command_id: &str,
        owner: &SubmissionOwner,
    ) -> pc_runtime_types::RuntimeResult<Option<crate::deployment::occurrence::DeploymentOutcome>>
    {
        use crate::deployment::occurrence::{DeploymentAttemptBinding, DeploymentOutcome};
        use pc_runtime_types::RuntimeError;
        self.ensure_healthy()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let Some((command, admission, _)) = self.submission(command_id, owner) else {
            return Ok(None);
        };
        let Some(dispatch) = admission
            .deployment
            .as_ref()
            .and_then(|deployment| deployment.dispatch.as_ref())
        else {
            return Ok(None);
        };
        let started = self
            .frames
            .iter()
            .filter(|frame| {
                frame.record.command_id == command_id && frame.record.state == JournalState::Started
            })
            .count();
        if started == 0 {
            return Ok(None);
        }
        if started != 1 {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let attempt = DeploymentAttemptBinding::started(&command, &admission, dispatch)?;
        let occurrence = self
            .latest_by_command
            .get(command_id)
            .and_then(|record| record.observation.as_ref())
            .map(|observation| observation.finalized_occurrence(&admission, &attempt))
            .transpose()?
            .flatten();
        let mut invalidation = None;
        if let Some(observation) = self
            .latest_by_command
            .get(command_id)
            .and_then(|record| record.observation.as_ref())
            && observation.is_deployment_invalidation()
        {
            for frame in self
                .frames
                .iter()
                .rev()
                .filter(|frame| frame.record.command_id == command_id)
            {
                if let Some(previous) = &frame.record.observation
                    && let Some(previous) = previous.finalized_occurrence(&admission, &attempt)?
                {
                    invalidation = Some(observation.invalidate_occurrence(&previous)?);
                    break;
                }
            }
        }
        Ok(Some(DeploymentOutcome {
            attempt,
            occurrence,
            invalidation,
        }))
    }

    pub fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Integrity)
        } else {
            Ok(())
        }
    }

    fn validate_prepared_handle(&self, prepared: &PreparedCommand) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if prepared.lease_id != self.lease_id
            || !self.issued_prepared.contains(&prepared.command.command_id)
        {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_started_handle(&self, started: &StartedCommand) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if started.lease_id != self.lease_id {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(())
    }

    fn exact_latest(&self, command: &GovernedCommand) -> Result<&JournalRecord, JournalError> {
        let record = self
            .latest_by_command
            .get(&command.command_id)
            .ok_or(JournalError::IdentityMismatch)?;
        if record.request_or_transaction_hash != command.request_or_transaction_hash
            || record.method != command.method
            || record.immutable_request_digest != command.immutable_request_digest
            || record.submitted_bytes_digest != command.submitted_bytes_digest
            || record.provider_profile_digest != command.provider_profile_digest
            || record.provider_instance_id != command.provider_instance_id
            || record.attempt_id != command.attempt_id
            || record.anchor_digest != command.anchor_digest
        {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(record)
    }

    fn append_from_record(
        &mut self,
        prior: &JournalRecord,
        state: JournalState,
        no_bytes_sent_evidence_digest: Option<String>,
        reconciliation: Option<(String, String)>,
        evidence_digest: Option<String>,
        event_kind: EventKind,
    ) -> Result<(), JournalError> {
        self.append_from_record_with_observation(
            prior,
            state,
            no_bytes_sent_evidence_digest,
            reconciliation,
            evidence_digest,
            event_kind,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_from_record_with_observation(
        &mut self,
        prior: &JournalRecord,
        state: JournalState,
        no_bytes_sent_evidence_digest: Option<String>,
        reconciliation: Option<(String, String)>,
        evidence_digest: Option<String>,
        event_kind: EventKind,
        observation: Option<observation::ObservationEvidence>,
    ) -> Result<(), JournalError> {
        validate_transition(
            prior,
            state,
            no_bytes_sent_evidence_digest.as_deref(),
            replacement::related(&self.latest_by_command, &prior.command_id),
        )?;
        let context = EventContext {
            id: Uuid::now_v7().to_string(),
            source: "urn:openpc:service:multi-rpc".to_owned(),
            subject: format!("urn:openpc:governed-command:{}", prior.command_id),
            time: if prior.command_created_at.is_none() {
                prior.event.time.clone()
            } else {
                time::OffsetDateTime::now_utc()
                    .format(
                        &time::format_description::parse_borrowed::<2>(
                            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
                        )
                        .map_err(|_| JournalError::Integrity)?,
                    )
                    .map_err(|_| JournalError::Integrity)?
            },
            participant_id: prior.event.participantid.clone(),
            privacy_domain_id: prior.event.privacydomainid.clone(),
            correlation_id: prior.event.correlationid.clone(),
            causation_id: Some(prior.event.id.clone()),
            sequence: self.next_sequence(),
        };
        let event = build_event(
            event_kind,
            context,
            EventRecordIdentity::from_record(prior),
            state,
            evidence_digest.as_deref(),
        )?;
        let event_digest = event.digest()?;
        let (reconciliation_method, reconciliation_data_class) = reconciliation
            .map(|(method, data_class)| (Some(method), Some(data_class)))
            .unwrap_or((None, None));
        let mut record = JournalRecord {
            command_id: prior.command_id.clone(),
            command_created_at: prior.command_created_at.clone(),
            method: prior.method.clone(),
            immutable_request_digest: prior.immutable_request_digest.clone(),
            request_or_transaction_hash: prior.request_or_transaction_hash.clone(),
            submitted_bytes_digest: prior.submitted_bytes_digest.clone(),
            provider_profile_digest: prior.provider_profile_digest.clone(),
            provider_instance_id: prior.provider_instance_id.clone(),
            attempt_id: prior.attempt_id.clone(),
            anchor_digest: prior.anchor_digest.clone(),
            state,
            no_bytes_sent_evidence_digest,
            reconciliation_method,
            reconciliation_data_class,
            evidence_digest,
            event,
            event_digest,
            signed_identity: prior.signed_identity.clone(),
            fee_identity: prior.fee_identity.clone(),
            replacement: prior.replacement.clone(),
            submission_admission: prior.submission_admission.clone(),
            sender_boundary: None,
            observation,
        };
        record.sender_boundary = prior
            .sender_boundary
            .as_ref()
            .map(|head| {
                head.advance(
                    &record,
                    replacement::related(&self.latest_by_command, &record.command_id),
                )
            })
            .transpose()?;
        self.append_record(record)
    }

    fn append_record(&mut self, record: JournalRecord) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let sequence = self.next_sequence();
        let predecessor_digest = self.frames.last().map_or_else(
            || GENESIS_DIGEST.to_owned(),
            |frame| frame.record_digest.clone(),
        );
        let digest_bytes = serde_json::to_vec(&DigestMaterial {
            domain: DOMAIN,
            version: VERSION,
            sequence,
            predecessor_digest: &predecessor_digest,
            record: &record,
        })?;
        let frame = JournalFrame {
            domain: DOMAIN.to_owned(),
            version: VERSION,
            sequence,
            predecessor_digest,
            record,
            record_digest: hex_digest(&digest_bytes),
        };
        let encoded = serde_json::to_vec(&frame)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(JournalError::Oversized);
        }
        let reserve = if matches!(
            frame.record.state,
            JournalState::Prepared | JournalState::Started
        ) {
            MAX_FRAME_BYTES as u64 + 4
        } else {
            0
        };
        if self
            .file
            .metadata()?
            .len()
            .checked_add(encoded.len() as u64 + 4 + reserve)
            .is_none_or(|size| size > MAX_JOURNAL_BYTES)
        {
            return Err(JournalError::Oversized);
        }
        let length = u32::try_from(encoded.len()).map_err(|_| JournalError::Oversized)?;
        // After the first write, any error may leave a durable prefix or a
        // complete frame absent from memory. Only reopen/validation may recover.
        self.poisoned = true;
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(&encoded)?;
        self.file.flush()?;
        self.file.sync_all()?;
        sync_directory(self.path.parent().ok_or(JournalError::Integrity)?)?;
        self.latest_by_command
            .insert(frame.record.command_id.clone(), frame.record.clone());
        self.frames.push(frame);
        self.poisoned = false;
        Ok(())
    }

    fn next_sequence(&self) -> u64 {
        u64::try_from(self.frames.len())
            .expect("journal frame count fits u64")
            .checked_add(1)
            .expect("journal sequence does not overflow")
    }
}

fn acquire_exclusive_lease(file: &File) -> Result<(), JournalError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::Error(error)) => Err(JournalError::Io(error)),
        Err(TryLockError::WouldBlock) => Err(JournalError::ForbiddenTransition),
    }
}

fn record_from_command(
    command: &GovernedCommand,
    state: JournalState,
    no_bytes_sent_evidence_digest: Option<String>,
    reconciliation: Option<(String, String)>,
    evidence_digest: Option<String>,
    event_kind: EventKind,
    sequence: u64,
) -> Result<JournalRecord, JournalError> {
    let context = EventContext {
        id: Uuid::now_v7().to_string(),
        source: "urn:openpc:service:multi-rpc".to_owned(),
        subject: format!("urn:openpc:governed-command:{}", command.command_id),
        time: command.occurred_at.clone(),
        participant_id: command.participant_id.clone(),
        privacy_domain_id: command.privacy_domain_id.clone(),
        correlation_id: command.correlation_id.clone(),
        causation_id: None,
        sequence,
    };
    let event = build_event(
        event_kind,
        context,
        EventRecordIdentity::from_command(command),
        state,
        evidence_digest.as_deref(),
    )?;
    let event_digest = event.digest()?;
    let (reconciliation_method, reconciliation_data_class) = reconciliation
        .map(|(method, data_class)| (Some(method), Some(data_class)))
        .unwrap_or((None, None));
    Ok(JournalRecord {
        command_id: command.command_id.clone(),
        command_created_at: Some(command.occurred_at.clone()),
        method: command.method.clone(),
        immutable_request_digest: command.immutable_request_digest.clone(),
        request_or_transaction_hash: command.request_or_transaction_hash.clone(),
        submitted_bytes_digest: command.submitted_bytes_digest.clone(),
        provider_profile_digest: command.provider_profile_digest.clone(),
        provider_instance_id: command.provider_instance_id.clone(),
        attempt_id: command.attempt_id.clone(),
        anchor_digest: command.anchor_digest.clone(),
        state,
        no_bytes_sent_evidence_digest,
        reconciliation_method,
        reconciliation_data_class,
        evidence_digest,
        event,
        event_digest,
        signed_identity: None,
        fee_identity: None,
        replacement: None,
        submission_admission: None,
        sender_boundary: None,
        observation: None,
    })
}

fn command_from_record(record: &JournalRecord) -> GovernedCommand {
    GovernedCommand {
        command_id: record.command_id.clone(),
        method: record.method.clone(),
        immutable_request_digest: record.immutable_request_digest.clone(),
        request_or_transaction_hash: record.request_or_transaction_hash.clone(),
        submitted_bytes_digest: record.submitted_bytes_digest.clone(),
        provider_profile_digest: record.provider_profile_digest.clone(),
        provider_instance_id: record.provider_instance_id.clone(),
        attempt_id: record.attempt_id.clone(),
        anchor_digest: record.anchor_digest.clone(),
        participant_id: record.event.participantid.clone(),
        privacy_domain_id: record.event.privacydomainid.clone(),
        correlation_id: record.event.correlationid.clone(),
        occurred_at: record
            .command_created_at
            .as_ref()
            .unwrap_or(&record.event.time)
            .clone(),
    }
}

struct EventRecordIdentity<'a> {
    command_id: &'a str,
    method: &'a str,
    immutable_request_digest: &'a str,
    request_or_transaction_hash: &'a str,
    submitted_bytes_digest: &'a str,
    provider_profile_digest: &'a str,
    provider_instance_id: &'a str,
    attempt_id: &'a str,
}

impl<'a> EventRecordIdentity<'a> {
    fn from_command(value: &'a GovernedCommand) -> Self {
        Self {
            command_id: &value.command_id,
            method: &value.method,
            immutable_request_digest: &value.immutable_request_digest,
            request_or_transaction_hash: &value.request_or_transaction_hash,
            submitted_bytes_digest: &value.submitted_bytes_digest,
            provider_profile_digest: &value.provider_profile_digest,
            provider_instance_id: &value.provider_instance_id,
            attempt_id: &value.attempt_id,
        }
    }

    fn from_record(value: &'a JournalRecord) -> Self {
        Self {
            command_id: &value.command_id,
            method: &value.method,
            immutable_request_digest: &value.immutable_request_digest,
            request_or_transaction_hash: &value.request_or_transaction_hash,
            submitted_bytes_digest: &value.submitted_bytes_digest,
            provider_profile_digest: &value.provider_profile_digest,
            provider_instance_id: &value.provider_instance_id,
            attempt_id: &value.attempt_id,
        }
    }
}

fn build_event(
    kind: EventKind,
    context: EventContext,
    identity: EventRecordIdentity<'_>,
    state: JournalState,
    evidence_digest: Option<&str>,
) -> Result<OpenPcEventEnvelopeV1, JournalError> {
    let mut data = BTreeMap::from([
        ("request_id".to_owned(), identity.command_id.to_owned()),
        ("method".to_owned(), identity.method.to_owned()),
        (
            "request_digest".to_owned(),
            identity.immutable_request_digest.to_owned(),
        ),
        (
            "submitted_bytes_digest".to_owned(),
            identity.submitted_bytes_digest.to_owned(),
        ),
        (
            "transaction_digest".to_owned(),
            identity.request_or_transaction_hash.to_owned(),
        ),
        (
            "provider_profile_digest".to_owned(),
            identity.provider_profile_digest.to_owned(),
        ),
        (
            "provider_instance_id".to_owned(),
            identity.provider_instance_id.to_owned(),
        ),
        ("attempt_id".to_owned(), identity.attempt_id.to_owned()),
        ("state".to_owned(), format!("{state:?}").to_uppercase()),
    ]);
    if let Some(value) = evidence_digest {
        data.insert("evidence_digest".to_owned(), value.to_owned());
    }
    OpenPcEventEnvelopeV1::new(kind, context, data).map_err(|_| JournalError::IdentityMismatch)
}

fn validate_command(value: &GovernedCommand) -> Result<(), JournalError> {
    if [
        &value.command_id,
        &value.method,
        &value.immutable_request_digest,
        &value.request_or_transaction_hash,
        &value.submitted_bytes_digest,
        &value.provider_profile_digest,
        &value.provider_instance_id,
        &value.attempt_id,
        &value.anchor_digest,
        &value.participant_id,
        &value.privacy_domain_id,
        &value.correlation_id,
        &value.occurred_at,
    ]
    .into_iter()
    .any(|field| field.is_empty())
    {
        return Err(JournalError::IdentityMismatch);
    }
    Ok(())
}

fn validate_transition(
    prior: &JournalRecord,
    next: JournalState,
    no_bytes_sent_evidence: Option<&str>,
    monitors_replacement: bool,
) -> Result<(), JournalError> {
    let permitted = match (prior.state, next) {
        (JournalState::Prepared, JournalState::Prepared) => {
            prior.submission_admission.is_none() && no_bytes_sent_evidence.is_some()
        }
        (JournalState::Prepared, JournalState::Started) => true,
        (JournalState::Prepared, JournalState::FailedPreStart) => no_bytes_sent_evidence.is_some(),
        (JournalState::Started, JournalState::Acknowledged | JournalState::Ambiguous) => true,
        (JournalState::Acknowledged, JournalState::Ambiguous) => true,
        (
            JournalState::Acknowledged | JournalState::Ambiguous,
            JournalState::Included | JournalState::Reverted | JournalState::DroppedConfirmed,
        ) => true,
        (JournalState::Included, JournalState::Executed | JournalState::Reverted) => true,
        (JournalState::Executed, JournalState::Finalized | JournalState::Reverted) => true,
        (
            JournalState::Acknowledged | JournalState::Ambiguous | JournalState::Observed,
            JournalState::Observed,
        ) => {
            prior.submission_admission.is_some()
                && prior.sender_boundary.as_ref().is_some_and(|head| {
                    head.automatic_attempt_started
                        && (!head.terminal
                            || observation::monitors_finalized_submission(prior)
                            || monitors_replacement)
                })
        }
        _ => false,
    };
    if permitted {
        Ok(())
    } else {
        Err(JournalError::ForbiddenTransition)
    }
}

fn decode_frames(bytes: &[u8]) -> Result<Vec<JournalFrame>, JournalError> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let length_end = offset.checked_add(4).ok_or(JournalError::Truncated)?;
        let length_bytes: [u8; 4] = bytes
            .get(offset..length_end)
            .ok_or(JournalError::Truncated)?
            .try_into()
            .map_err(|_| JournalError::Truncated)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| JournalError::Oversized)?;
        if length > MAX_FRAME_BYTES {
            return Err(JournalError::Oversized);
        }
        let frame_end = length_end
            .checked_add(length)
            .ok_or(JournalError::Truncated)?;
        let encoded = bytes
            .get(length_end..frame_end)
            .ok_or(JournalError::Truncated)?;
        frames.push(serde_json::from_slice(encoded)?);
        offset = frame_end;
    }
    Ok(frames)
}

fn validate_frames(
    frames: &[JournalFrame],
) -> Result<BTreeMap<String, JournalRecord>, JournalError> {
    let mut latest = BTreeMap::<String, JournalRecord>::new();
    let mut seen_digests = BTreeSet::new();
    let mut predecessor = GENESIS_DIGEST.to_owned();
    for (index, frame) in frames.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .map_err(|_| JournalError::Integrity)?
            .checked_add(1)
            .ok_or(JournalError::Integrity)?;
        if frame.domain != DOMAIN
            || frame.version != VERSION
            || frame.sequence != expected_sequence
            || frame.predecessor_digest != predecessor
            || !seen_digests.insert(frame.record_digest.clone())
            || frame.record.event.digest()? != frame.record.event_digest
        {
            return Err(if frame.domain != DOMAIN || frame.version != VERSION {
                JournalError::UnknownVersion
            } else {
                JournalError::Integrity
            });
        }
        let expected_digest = hex_digest(&serde_json::to_vec(&DigestMaterial {
            domain: &frame.domain,
            version: frame.version,
            sequence: frame.sequence,
            predecessor_digest: &frame.predecessor_digest,
            record: &frame.record,
        })?);
        if expected_digest != frame.record_digest {
            return Err(JournalError::Integrity);
        }
        if let Some(admission) = &frame.record.submission_admission {
            admission.validate(&command_from_record(&frame.record))?;
            if frame.record.signed_identity.is_none() {
                return Err(JournalError::IdentityMismatch);
            }
        }
        if let Some(prior) = latest.get(&frame.record.command_id) {
            if prior.command_created_at != frame.record.command_created_at
                || prior.request_or_transaction_hash != frame.record.request_or_transaction_hash
                || prior.method != frame.record.method
                || prior.immutable_request_digest != frame.record.immutable_request_digest
                || prior.submitted_bytes_digest != frame.record.submitted_bytes_digest
                || prior.anchor_digest != frame.record.anchor_digest
                || prior.signed_identity != frame.record.signed_identity
                || prior.fee_identity != frame.record.fee_identity
                || prior.replacement != frame.record.replacement
                || prior.submission_admission != frame.record.submission_admission
                || prior.event.participantid != frame.record.event.participantid
                || prior.event.privacydomainid != frame.record.event.privacydomainid
            {
                return Err(JournalError::IdentityMismatch);
            }
            validate_transition(
                prior,
                frame.record.state,
                frame.record.no_bytes_sent_evidence_digest.as_deref(),
                replacement::related(&latest, &frame.record.command_id),
            )?;
            if frame.record.state != JournalState::Prepared
                && (prior.provider_profile_digest != frame.record.provider_profile_digest
                    || prior.provider_instance_id != frame.record.provider_instance_id
                    || prior.attempt_id != frame.record.attempt_id)
            {
                return Err(JournalError::IdentityMismatch);
            }
        } else {
            if frame.record.state != JournalState::Prepared {
                return Err(JournalError::ForbiddenTransition);
            }
            replacement::validate_new(&latest, &frame.record)?;
            validate_capability_reservation(&latest, frame.record.submission_admission.as_ref())?;
            validate_exact_submission(
                &latest,
                frame.record.signed_identity.as_ref(),
                frame.record.submission_admission.as_ref(),
            )?;
        }
        sender_boundary::validate(
            &frame.record,
            latest.get(&frame.record.command_id),
            replacement::related(&latest, &frame.record.command_id),
        )?;
        observation::validate_record(
            &frame.record,
            latest.get(&frame.record.command_id),
            replacement::related(&latest, &frame.record.command_id),
        )?;
        latest.insert(frame.record.command_id.clone(), frame.record.clone());
        predecessor.clone_from(&frame.record_digest);
    }
    Ok(latest)
}

fn validate_exact_submission(
    records: &BTreeMap<String, JournalRecord>,
    identity: Option<&SignedIdentity>,
    admission: Option<&SubmissionAdmission>,
) -> Result<(), JournalError> {
    // An exact transaction has one durable operation, including pre-start
    // failure. A different command ID must not obscure its existing outcome.
    if admission.is_some()
        && records
            .values()
            .any(|record| record.signed_identity.as_ref() == identity)
    {
        return Err(JournalError::DuplicateCommand);
    }
    Ok(())
}

fn validate_capability_reservation(
    records: &BTreeMap<String, JournalRecord>,
    admission: Option<&SubmissionAdmission>,
) -> Result<(), JournalError> {
    if let Some(admission) = admission
        && records.values().any(|record| {
            record.submission_admission.as_ref().is_some_and(|prior| {
                prior.target_runtime_id == admission.target_runtime_id
                    && prior.capability_id == admission.capability_id
            })
        })
    {
        return Err(JournalError::DuplicateCommand);
    }
    Ok(())
}

fn validate_nonce_reservation(
    records: &BTreeMap<String, JournalRecord>,
    identity: Option<&SignedIdentity>,
) -> Result<(), JournalError> {
    if let Some(identity) = identity
        && records.values().any(|record| {
            record.state != JournalState::FailedPreStart
                && record.signed_identity.as_ref().is_some_and(|prior| {
                    prior.chain_id == identity.chain_id
                        && prior.signer == identity.signer
                        && prior.nonce == identity.nonce
                })
        })
    {
        return Err(JournalError::DuplicateCommand);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn command(id: &str) -> GovernedCommand {
        GovernedCommand {
            command_id: id.into(),
            method: "eth_sendRawTransaction".into(),
            immutable_request_digest: format!("request-{id}"),
            request_or_transaction_hash: format!("tx-{id}"),
            submitted_bytes_digest: format!("bytes-{id}"),
            provider_profile_digest: "profile-a".into(),
            provider_instance_id: "provider-a".into(),
            attempt_id: "attempt-a".into(),
            anchor_digest: "anchor-1".into(),
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            correlation_id: "018f47a5-4a58-7b21-8f3a-222222222222".into(),
            occurred_at: "2026-09-02T00:00:00.000000Z".into(),
        }
    }

    pub(super) fn temp_path(name: &str) -> PathBuf {
        let root = std::env::var("OPENPC_TEST_TMP_ROOT")
            .map(PathBuf::from)
            .expect("OPENPC_TEST_TMP_ROOT must name the approved Agents/tmp root");
        root.join(format!("openpc-i06-{name}-{}", Uuid::now_v7()))
            .join("journal.bin")
    }

    pub(super) fn signed_command(id: &str, transaction: &SignedTransaction) -> GovernedCommand {
        let mut command = command(id);
        command.attempt_id = Uuid::now_v7().to_string();
        command.request_or_transaction_hash = format!(
            "0x{}",
            transaction
                .hash()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        command.submitted_bytes_digest =
            hex_digest(&crate::governed_write::submission_body(transaction, id).unwrap());
        command
    }

    pub(super) fn submission_admission() -> SubmissionAdmission {
        let d = || pc_runtime_types::Digest::of("admitted-owner-material");
        SubmissionAdmission {
            owner: SubmissionOwner {
                participant_id: "participant-1".into(),
                privacy_domain_id: "privacy-1".into(),
                actor_principal_id: "actor-1".into(),
                workload_id: "workload-1".into(),
            },
            target_runtime_id: "target-1".into(),
            runtime_binding_id: "binding-1".into(),
            risk_class: Some("LOW".into()),
            preflight_witness_digest: None,
            cigl_post_mine: None,
            chain: None,
            workload_peer_binding_digest: Some(pc_runtime_types::Digest::of(
                "verified original peer",
            )),
            wallet_binding_id: "wallet-1".into(),
            wallet_binding_epoch: 1,
            capability_id: "capability-1".into(),
            decision_id: "decision-1".into(),
            decision_digest: d(),
            identity_vector_digest: d(),
            capsule_digest: d(),
            contract_set_manifest_digest: d(),
            invocation_profile_digest: d(),
            capability_registry_digest: d(),
            request_form_registry_digest: d(),
            error_registry_digest: d(),
            policy_generation_digest: d(),
            transaction_policy_digest: d(),
            route_witness_set_digest: d(),
            evidence_admission_profile_digest: d(),
            prepared_intent_digest: None,
            contract_address: Some([0x35; 20]),
            selector: Some([0x12, 0x34, 0x56, 0x78]),
            deployment: None,
            admitted_at_ms: 1000,
            valid_until_ms: 2000,
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_append_poisoning_prevents_reuse_of_in_memory_authority() {
        let path = temp_path("uncertain-write-poison");
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let prepared = journal.prepare(command("before-failure")).unwrap();
        let original = std::mem::replace(
            &mut journal.file,
            OpenOptions::new().write(true).open("/dev/full").unwrap(),
        );
        assert!(matches!(
            journal.mark_started(prepared, "started".into()),
            Err(JournalError::Io(_))
        ));
        assert!(matches!(
            journal.ensure_healthy(),
            Err(JournalError::Integrity)
        ));
        assert!(journal.latest_state("before-failure").is_none());
        assert!(journal.prepare(command("after-failure")).is_err());
        assert!(journal.resume_prepared("before-failure").is_err());
        drop(journal);
        drop(original);
        let journal = WriteJournal::open(&path).unwrap();
        assert_eq!(
            journal.latest_state("before-failure"),
            Some(JournalState::Prepared)
        );
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn owned_submission_commits_actor_capability_nonce_and_restart_outcome_together() {
        let path = temp_path("owned-submission");
        let transaction = crate::signed_transaction::test_transaction_with_calldata(
            9,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        let admission = submission_admission();
        let owner = admission.owner.clone();
        let id = Uuid::now_v7().to_string();
        let command = signed_command(&id, &transaction);
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let prepared = journal
            .prepare_submission(command.clone(), &transaction, admission.clone())
            .unwrap();
        let genesis = journal.submission_boundary(&id, &owner).unwrap();
        assert_eq!(genesis.state_sequence, 1);
        assert!(genesis.prior_evidence_digest.is_none());
        assert!(!genesis.automatic_attempt_started);
        assert!(!genesis.automatic_resubmission_prohibited);
        assert_eq!(
            journal.submission(&id, &owner),
            Some((command.clone(), admission.clone(), JournalState::Prepared))
        );
        for mutate in [
            (|o: &mut SubmissionOwner| o.participant_id = "foreign".into())
                as fn(&mut SubmissionOwner),
            |o| o.privacy_domain_id = "foreign".into(),
            |o| o.actor_principal_id = "foreign".into(),
            |o| o.workload_id = "foreign".into(),
        ] {
            let mut foreign = owner.clone();
            mutate(&mut foreign);
            assert!(journal.submission(&id, &foreign).is_none());
            assert!(
                journal
                    .submission_for_transaction(&transaction, &foreign)
                    .is_none()
            );
        }
        let next_transaction = crate::signed_transaction::test_transaction_with_calldata(
            10,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        assert!(matches!(
            journal.prepare_submission(
                signed_command(&Uuid::now_v7().to_string(), &next_transaction),
                &next_transaction,
                admission.clone()
            ),
            Err(JournalError::DuplicateCommand)
        ));
        journal
            .mark_started(prepared, "durable-boundary".into())
            .unwrap();
        let started = journal.submission_boundary(&id, &owner).unwrap();
        assert_eq!(started.state_sequence, 2);
        assert_eq!(
            started.prior_evidence_digest,
            Some(genesis.digest().unwrap())
        );
        assert_eq!(started.operation_digest, genesis.operation_digest);
        assert!(started.automatic_attempt_started);
        assert!(started.automatic_resubmission_prohibited);
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        let recovered = journal.submission_boundary(&id, &owner).unwrap();
        assert_eq!(recovered.state_sequence, 3);
        assert_eq!(recovered.transition, JournalState::Ambiguous);
        assert_eq!(
            recovered.prior_evidence_digest,
            Some(started.digest().unwrap())
        );
        assert!(recovered.automatic_attempt_started);
        assert!(recovered.automatic_resubmission_prohibited);
        let replay = journal
            .repeated_submission_view(
                &transaction,
                &owner.participant_id,
                &owner.privacy_domain_id,
                &owner.workload_id,
                admission.workload_peer_binding_digest.as_ref().unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replay.state, "WRITE_AMBIGUITY");
        assert_eq!(replay.truth_state, "WRITE_AMBIGUITY");
        assert_eq!(replay.operation_id, format!("urn:openpc:operation:{id}"));
        for (participant, privacy, workload, binding) in [
            (
                "foreign",
                owner.privacy_domain_id.as_str(),
                owner.workload_id.as_str(),
                admission.workload_peer_binding_digest.clone().unwrap(),
            ),
            (
                owner.participant_id.as_str(),
                "foreign",
                owner.workload_id.as_str(),
                admission.workload_peer_binding_digest.clone().unwrap(),
            ),
            (
                owner.participant_id.as_str(),
                owner.privacy_domain_id.as_str(),
                "foreign",
                admission.workload_peer_binding_digest.clone().unwrap(),
            ),
            (
                owner.participant_id.as_str(),
                owner.privacy_domain_id.as_str(),
                owner.workload_id.as_str(),
                pc_runtime_types::Digest::of("different credential"),
            ),
        ] {
            assert!(
                journal
                    .repeated_submission_view(
                        &transaction,
                        participant,
                        privacy,
                        workload,
                        &binding
                    )
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            journal.submission_for_transaction(&transaction, &owner),
            Some((command, admission.clone(), JournalState::Ambiguous))
        );
        assert!(journal.resume_prepared(&id).is_err());
        let status = journal.submission_status(&id, &owner).unwrap();
        assert_eq!(
            status.submission,
            crate::submission_status::SubmissionDisposition::PossiblySent
        );
        assert!(status.automatic_attempt_started);
        assert!(status.automatic_resubmission_prohibited);
        assert!(!status.provider_acknowledged);
        assert_eq!(
            status.observation,
            crate::submission_status::ChainObservation::NotObserved
        );
        assert_eq!(
            status.execution,
            crate::submission_status::ExecutionOutcome::Unknown
        );
        assert!(
            journal
                .prepare_submission(
                    signed_command(&Uuid::now_v7().to_string(), &transaction),
                    &transaction,
                    admission
                )
                .is_err()
        );
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn owned_deadline_reaper_distinguishes_prepared_from_started_and_never_retries() {
        let path = temp_path("owned-expiry");
        let first = crate::signed_transaction::test_transaction_with_calldata(
            9,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        let second = crate::signed_transaction::test_transaction_with_calldata(
            10,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        let admission = submission_admission();
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let prepared = journal
            .prepare_submission(
                signed_command(&Uuid::now_v7().to_string(), &first),
                &first,
                admission.clone(),
            )
            .unwrap();
        let first_id = prepared.command().command_id.clone();
        assert_eq!(
            journal
                .expire_submissions(admission.valid_until_ms - 1)
                .unwrap(),
            0
        );
        let mut second_admission = admission.clone();
        second_admission.capability_id = "second capability".into();
        let second_prepared = journal
            .prepare_submission(
                signed_command(&Uuid::now_v7().to_string(), &second),
                &second,
                second_admission,
            )
            .unwrap();
        let started = journal
            .mark_started(second_prepared, hex_digest(b"durable before bytes"))
            .unwrap();
        assert_eq!(
            journal
                .expire_submissions(admission.valid_until_ms)
                .unwrap(),
            2
        );
        assert_eq!(
            journal.latest_state(&first_id),
            Some(JournalState::FailedPreStart)
        );
        assert_eq!(
            journal.latest_state(&started.command().command_id),
            Some(JournalState::Ambiguous)
        );
        assert!(
            journal
                .mark_started(prepared, hex_digest(b"expired handoff"))
                .is_err()
        );
        assert!(
            journal
                .mark_acknowledged(&started, hex_digest(b"late acknowledgment"))
                .is_err()
        );
        assert_eq!(
            journal
                .expire_submissions(admission.valid_until_ms + 1)
                .unwrap(),
            0
        );
        assert!(
            journal
                .submission_status(&started.command().command_id, &admission.owner)
                .unwrap()
                .automatic_resubmission_prohibited
        );
        drop(journal);
        let journal = WriteJournal::open(&path).unwrap();
        assert_eq!(
            journal.latest_state(&first_id),
            Some(JournalState::FailedPreStart)
        );
        assert_eq!(
            journal.latest_state(&started.command().command_id),
            Some(JournalState::Ambiguous)
        );
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn sender_boundary_rejects_resealed_flag_sequence_identity_and_downgrade_tampering() {
        let path = temp_path("sender-boundary-integrity");
        let transaction = crate::signed_transaction::test_transaction_with_calldata(
            9,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        let admission = submission_admission();
        let command = signed_command(&Uuid::now_v7().to_string(), &transaction);
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let prepared = journal
            .prepare_submission(command.clone(), &transaction, admission.clone())
            .unwrap();
        journal
            .mark_started(prepared, hex_digest(b"before send"))
            .unwrap();
        let original = journal.frames.clone();
        let reseal = |frames: &mut [JournalFrame]| {
            let mut predecessor = GENESIS_DIGEST.to_owned();
            for frame in frames {
                frame.predecessor_digest.clone_from(&predecessor);
                frame.record_digest = hex_digest(
                    &serde_json::to_vec(&DigestMaterial {
                        domain: &frame.domain,
                        version: frame.version,
                        sequence: frame.sequence,
                        predecessor_digest: &frame.predecessor_digest,
                        record: &frame.record,
                    })
                    .unwrap(),
                );
                predecessor.clone_from(&frame.record_digest);
            }
        };
        for mutate in [
            (|head: &mut SenderBoundary| head.state_sequence = 1) as fn(&mut SenderBoundary),
            |head| head.automatic_attempt_started = false,
            |head| head.automatic_resubmission_prohibited = false,
            |head| head.terminal = true,
            |head| head.attempt_id = "another attempt".into(),
            |head| head.operation_digest = hex_digest(b"another operation"),
            |head| head.prior_evidence_digest = None,
            |head| head.transition = JournalState::Prepared,
            |head| head.event_digest = hex_digest(b"another event"),
        ] {
            let mut frames = original.clone();
            mutate(frames[1].record.sender_boundary.as_mut().unwrap());
            reseal(&mut frames);
            assert!(validate_frames(&frames).is_err());
        }
        let mut removed = original.clone();
        removed[1].record.sender_boundary = None;
        reseal(&mut removed);
        assert!(validate_frames(&removed).is_err());
        // An old PREPARED frame remains readable, but it cannot start a new
        // attempt without evidence that never existed in that format.
        let mut legacy = original[..1].to_vec();
        legacy[0].record.sender_boundary = None;
        reseal(&mut legacy);
        validate_frames(&legacy).unwrap();
        drop(journal);
        let encoded = serde_json::to_vec(&legacy[0]).unwrap();
        let mut bytes = (encoded.len() as u32).to_be_bytes().to_vec();
        bytes.extend(encoded);
        std::fs::write(&path, bytes).unwrap();
        let mut journal = WriteJournal::open(&path).unwrap();
        assert!(
            journal
                .submission(&command.command_id, &admission.owner)
                .is_some()
        );
        assert!(
            journal
                .submission_boundary(&command.command_id, &admission.owner)
                .is_none()
        );
        let prepared = journal.resume_prepared(&command.command_id).unwrap();
        assert!(
            journal
                .mark_started(prepared, hex_digest(b"new start"))
                .is_err()
        );
        assert_eq!(
            journal.latest_state(&command.command_id),
            Some(JournalState::Prepared)
        );
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn owned_submission_rejects_misbinding_and_preserves_exact_hash_even_before_start() {
        let path = temp_path("owned-submission-denial");
        let transaction = crate::signed_transaction::test_transaction_with_calldata(
            9,
            2,
            &[0x12, 0x34, 0x56, 0x78],
        );
        let admission = submission_admission();
        let command = signed_command(&Uuid::now_v7().to_string(), &transaction);
        let mut journal = WriteJournal::create_new(&path).unwrap();
        for mutate in [
            (|a: &mut SubmissionAdmission| a.owner.participant_id = "foreign".into())
                as fn(&mut SubmissionAdmission),
            |a| a.owner.privacy_domain_id = "foreign".into(),
            |a| a.contract_address = Some([0; 20]),
            |a| a.selector = Some([0; 4]),
            |a| a.wallet_binding_epoch = 0,
            |a| a.valid_until_ms = a.admitted_at_ms,
            |a| a.valid_until_ms = a.admitted_at_ms + 10001,
            |a| a.capsule_digest = pc_runtime_types::Digest::of([]),
        ] {
            let mut bad = admission.clone();
            mutate(&mut bad);
            assert!(
                journal
                    .prepare_submission(command.clone(), &transaction, bad)
                    .is_err()
            );
            assert_eq!(journal.frame_count(), 0);
        }
        let prepared = journal
            .prepare_submission(command.clone(), &transaction, admission.clone())
            .unwrap();
        journal
            .fail_pre_start(prepared, "no-bytes-left".into())
            .unwrap();
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        let mut another = admission.clone();
        another.capability_id = "new-capability".into();
        assert!(
            journal
                .prepare_submission(
                    signed_command(&Uuid::now_v7().to_string(), &transaction),
                    &transaction,
                    another
                )
                .is_err()
        );
        assert_eq!(
            journal
                .submission_for_transaction(&transaction, &admission.owner)
                .unwrap()
                .2,
            JournalState::FailedPreStart
        );
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn signed_nonce_custody_survives_restart_and_cannot_be_replaced_after_start() {
        let path = temp_path("signed-nonce");
        let first = crate::signed_transaction::test_transaction(9, 2);
        let replacement = crate::signed_transaction::test_transaction(9, 3);
        assert_eq!(first.signer(), replacement.signer());
        assert_ne!(first.hash(), replacement.hash());
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let handle = journal
            .prepare_signed(signed_command("first", &first), &first)
            .unwrap();
        assert!(
            journal
                .validate_signed_prepared(&handle, &replacement)
                .is_err()
        );
        assert!(
            journal
                .prepare_signed(signed_command("replay", &first), &first)
                .is_err()
        );
        assert!(
            journal
                .prepare_signed(signed_command("replacement", &replacement), &replacement)
                .is_err()
        );
        journal.mark_started(handle, hex_digest(b"start")).unwrap();
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        assert_eq!(journal.latest_state("first"), Some(JournalState::Ambiguous));
        let mut alternate = signed_command("replacement", &replacement);
        alternate.participant_id = "other-participant".into();
        alternate.provider_instance_id = "other-provider".into();
        assert!(journal.prepare_signed(alternate, &replacement).is_err());
        let next = crate::signed_transaction::test_transaction(10, 2);
        journal
            .prepare_signed(signed_command("next", &next), &next)
            .unwrap();
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn only_durable_no_send_failure_releases_a_nonce_reservation() {
        let path = temp_path("signed-no-send");
        let transaction = crate::signed_transaction::test_transaction(9, 2);
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let handle = journal
            .prepare_signed(signed_command("first", &transaction), &transaction)
            .unwrap();
        journal
            .fail_pre_start(handle, hex_digest(b"authority-revoked-before-start"))
            .unwrap();
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        journal
            .prepare_signed(signed_command("second", &transaction), &transaction)
            .unwrap();
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        let handle = journal.resume_prepared("second").unwrap();
        journal
            .validate_signed_prepared(&handle, &transaction)
            .unwrap();
        drop(journal);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn oversized_journal_is_rejected_before_reading_its_contents() {
        let path = temp_path("bounded-recovery");
        let journal = WriteJournal::create_new(&path).unwrap();
        journal.file.set_len(MAX_JOURNAL_BYTES + 1).unwrap();
        drop(journal);
        assert!(matches!(
            WriteJournal::open(&path),
            Err(JournalError::Oversized)
        ));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    async fn zero_send_counter() -> (Arc<AtomicUsize>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let task = tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        });
        (count, task)
    }

    #[test]
    fn projection_change_cursor_reaches_old_command_without_wrap_and_survives_restart() {
        let path = temp_path("projection-change-cursor");
        let mut journal = WriteJournal::create_new(&path).unwrap();
        let oldest = journal.prepare(command("command-0000")).unwrap();
        for index in 1..300 {
            journal
                .prepare(command(&format!("command-{index:04}")))
                .unwrap();
        }
        assert_eq!(journal.current_heads_after(0).count(), 256);
        assert_eq!(journal.current_heads_after(256).count(), 44);
        let cursor = journal.frame_count() as u64;
        journal
            .fail_pre_start(oldest, "no-byte-proof".into())
            .unwrap();
        let changed: Vec<_> = journal.current_heads_after(cursor).collect();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].record.command_id, "command-0000");
        assert_eq!(changed[0].sequence, cursor + 1);
        assert_eq!(changed[0].record.state, JournalState::FailedPreStart);
        // Startup must not publish the superseded PREPARED head.
        assert!(
            journal
                .current_heads_after(0)
                .all(|f| f.record.command_id != "command-0000")
        );
        drop(journal);
        let reopened = WriteJournal::open(&path).unwrap();
        assert_eq!(
            reopened
                .current_heads_after(cursor)
                .next()
                .unwrap()
                .sequence,
            cursor + 1
        );
        assert!(
            reopened
                .current_heads_after(reopened.frame_count() as u64)
                .next()
                .is_none()
        );
        drop(reopened);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn journal_reselection_transition_and_recovery_are_durable() {
        let path = temp_path("journal-lifecycle");
        let mut journal = WriteJournal::create_new(&path).expect("create");
        let prepared = journal.prepare(command("command-1")).expect("prepare");
        assert!(journal.prepare(command("command-1")).is_err());
        let prepared = journal
            .reselect_prepared(
                prepared,
                "profile-b".into(),
                "provider-b".into(),
                "attempt-b".into(),
                "no-byte-proof".into(),
            )
            .expect("reselect");
        journal
            .mark_started(prepared, "started-proof".into())
            .expect("started");
        drop(journal);

        let mut recovered = WriteJournal::open(&path).expect("recover");
        assert_eq!(
            recovered.latest_state("command-1"),
            Some(JournalState::Ambiguous)
        );
        assert_eq!(recovered.frame_count(), 4);
        recovered
            .reconcile(
                "command-1",
                ReconciliationEvidence {
                    request_or_transaction_hash: "tx-command-1".into(),
                    provider_profile_digest: "profile-b".into(),
                    provider_instance_id: "provider-b".into(),
                    attempt_id: "attempt-b".into(),
                    anchor_digest: "anchor-1".into(),
                    observation_method: "eth_getTransactionReceipt".into(),
                    observation_data_class: "TRANSACTION_RECEIPT".into(),
                    evidence_digest: "included-proof".into(),
                    next_state: JournalState::Included,
                },
            )
            .expect("included");
        assert!(
            recovered
                .reconcile(
                    "command-1",
                    ReconciliationEvidence {
                        request_or_transaction_hash: "wrong".into(),
                        provider_profile_digest: "profile-b".into(),
                        provider_instance_id: "provider-b".into(),
                        attempt_id: "attempt-b".into(),
                        anchor_digest: "anchor-1".into(),
                        observation_method: "eth_getTransactionReceipt".into(),
                        observation_data_class: "TRANSACTION_RECEIPT".into(),
                        evidence_digest: "bad".into(),
                        next_state: JournalState::Finalized,
                    },
                )
                .is_err()
        );
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[tokio::test]
    async fn started_reopen_is_ambiguous_and_never_resubmitted() {
        let (send_count, send_task) = zero_send_counter().await;
        let path = temp_path("started-reopen");
        let mut journal = WriteJournal::create_new(&path).expect("create");
        let prepared = journal
            .prepare(command("command-started"))
            .expect("prepare");
        journal
            .mark_started(prepared, "started-proof".into())
            .expect("started");
        assert_eq!(journal.frame_count(), 2);
        drop(journal);

        let recovered = WriteJournal::open(&path).expect("recover");
        assert_eq!(recovered.frame_count(), 3);
        assert_eq!(
            recovered.latest_state("command-started"),
            Some(JournalState::Ambiguous)
        );
        tokio::task::yield_now().await;
        assert_eq!(send_count.load(Ordering::SeqCst), 0);
        send_task.abort();
        drop(recovered);
        let frames = decode_frames(&std::fs::read(&path).expect("read frames")).expect("frames");
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.record.state)
                .collect::<Vec<_>>(),
            [
                JournalState::Prepared,
                JournalState::Started,
                JournalState::Ambiguous
            ]
        );
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[tokio::test]
    async fn governed_write_transitions_preserve_exact_bindings() {
        let (send_count, send_task) = zero_send_counter().await;
        type Mutation = fn(&mut GovernedCommand);
        let mutations: [Mutation; 8] = [
            |value| value.method.push_str("-changed"),
            |value| value.immutable_request_digest.push_str("-changed"),
            |value| value.request_or_transaction_hash.push_str("-changed"),
            |value| value.submitted_bytes_digest.push_str("-changed"),
            |value| value.provider_profile_digest.push_str("-changed"),
            |value| value.provider_instance_id.push_str("-changed"),
            |value| value.attempt_id.push_str("-changed"),
            |value| value.anchor_digest.push_str("-changed"),
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let path = temp_path(&format!("binding-{index}"));
            let mut journal = WriteJournal::create_new(&path).expect("create");
            let prepared = journal
                .prepare(command(&format!("command-binding-{index}")))
                .expect("prepare");
            let mut changed = PreparedCommand {
                command: prepared.command.clone(),
                lease_id: prepared.lease_id,
            };
            mutate(&mut changed.command);
            assert!(matches!(
                journal.reselect_prepared(
                    changed,
                    "profile-b".into(),
                    "provider-b".into(),
                    "attempt-b".into(),
                    "durable-no-byte-proof".into(),
                ),
                Err(JournalError::IdentityMismatch)
            ));
            assert_eq!(journal.frame_count(), 1);
            assert_eq!(
                journal.latest_state(&format!("command-binding-{index}")),
                Some(JournalState::Prepared)
            );
            drop(journal);
            std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
        }

        let path = temp_path("binding-forbidden");
        let mut journal = WriteJournal::create_new(&path).expect("create");
        let prepared = journal
            .prepare(command("command-forbidden"))
            .expect("prepare");
        assert!(matches!(
            journal.reselect_prepared(
                prepared,
                "profile-a".into(),
                "provider-a".into(),
                "attempt-b".into(),
                "durable-no-byte-proof".into(),
            ),
            Err(JournalError::ForbiddenTransition)
        ));
        assert_eq!(journal.frame_count(), 1);
        tokio::task::yield_now().await;
        assert_eq!(send_count.load(Ordering::SeqCst), 0);
        send_task.abort();
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[tokio::test]
    async fn reconciliation_observes_only_and_never_resubmits() {
        let (send_count, send_task) = zero_send_counter().await;
        let path = temp_path("reconciliation-observes");
        let mut journal = WriteJournal::create_new(&path).expect("create");
        let prepared = journal
            .prepare(command("command-reconcile"))
            .expect("prepare");
        let started = journal
            .mark_started(prepared, "started-proof".into())
            .expect("started");
        journal
            .mark_ambiguous(&started, "ambiguous-proof".into())
            .expect("ambiguous");
        let included = ReconciliationEvidence {
            request_or_transaction_hash: "tx-command-reconcile".into(),
            provider_profile_digest: "profile-a".into(),
            provider_instance_id: "provider-a".into(),
            attempt_id: "attempt-a".into(),
            anchor_digest: "anchor-1".into(),
            observation_method: "eth_getTransactionReceipt".into(),
            observation_data_class: "TRANSACTION_RECEIPT".into(),
            evidence_digest: "included-proof".into(),
            next_state: JournalState::Included,
        };
        journal
            .reconcile("command-reconcile", included)
            .expect("included observation");
        let executed = ReconciliationEvidence {
            request_or_transaction_hash: "tx-command-reconcile".into(),
            provider_profile_digest: "profile-a".into(),
            provider_instance_id: "provider-a".into(),
            attempt_id: "attempt-a".into(),
            anchor_digest: "anchor-1".into(),
            observation_method: "eth_getTransactionReceipt".into(),
            observation_data_class: "TRANSACTION_RECEIPT".into(),
            evidence_digest: "executed-proof".into(),
            next_state: JournalState::Executed,
        };
        journal
            .reconcile("command-reconcile", executed)
            .expect("executed observation");
        assert_eq!(
            journal.latest_state("command-reconcile"),
            Some(JournalState::Executed)
        );
        let finalized = ReconciliationEvidence {
            request_or_transaction_hash: "tx-command-reconcile".into(),
            provider_profile_digest: "profile-a".into(),
            provider_instance_id: "provider-a".into(),
            attempt_id: "attempt-a".into(),
            anchor_digest: "anchor-1".into(),
            observation_method: "eth_getBlockByNumber".into(),
            observation_data_class: "BLOCK_HEADER".into(),
            evidence_digest: "finalized-proof".into(),
            next_state: JournalState::Finalized,
        };
        type Mutation = fn(&mut ReconciliationEvidence);
        let mutations: [Mutation; 9] = [
            |value| value.request_or_transaction_hash = "wrong".into(),
            |value| value.provider_profile_digest = "wrong".into(),
            |value| value.provider_instance_id = "wrong".into(),
            |value| value.attempt_id = "wrong".into(),
            |value| value.anchor_digest = "wrong".into(),
            |value| value.observation_method = "eth_getTransactionReceipt".into(),
            |value| value.observation_data_class = "TRANSACTION_RECEIPT".into(),
            |value| value.evidence_digest.clear(),
            |value| value.next_state = JournalState::Prepared,
        ];
        for mutate in mutations {
            let before = journal.frame_count();
            let mut changed = finalized.clone();
            mutate(&mut changed);
            assert!(journal.reconcile("command-reconcile", changed).is_err());
            assert_eq!(journal.frame_count(), before);
        }
        journal
            .reconcile("command-reconcile", finalized)
            .expect("finalized observation");
        assert_eq!(
            journal.latest_state("command-reconcile"),
            Some(JournalState::Finalized)
        );
        assert_eq!(journal.frame_count(), 6);
        tokio::task::yield_now().await;
        assert_eq!(send_count.load(Ordering::SeqCst), 0);
        send_task.abort();
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[test]
    fn journal_lease_and_prepared_recovery_are_exclusive_single_use() {
        let path = temp_path("lease-and-prepared-recovery");
        let mut first = WriteJournal::create_new(&path).expect("create");
        let stale = first
            .prepare(command("command-prepared-recovery"))
            .expect("prepare");
        assert!(matches!(
            WriteJournal::open(&path),
            Err(JournalError::ForbiddenTransition)
        ));
        drop(first);

        let mut recovered = WriteJournal::open(&path).expect("reopen prepared");
        assert!(matches!(
            recovered.fail_pre_start(stale, "stale-handle".into()),
            Err(JournalError::IdentityMismatch)
        ));
        let resumed = recovered
            .resume_prepared("command-prepared-recovery")
            .expect("sole resumed handle");
        assert!(matches!(
            recovered.resume_prepared("command-prepared-recovery"),
            Err(JournalError::ForbiddenTransition)
        ));
        recovered
            .fail_pre_start(resumed, "qualified-no-send".into())
            .expect("single terminal pre-start transition");
        assert_eq!(
            recovered.latest_state("command-prepared-recovery"),
            Some(JournalState::FailedPreStart)
        );
        drop(recovered);
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }

    #[test]
    fn journal_rejects_truncation_tamper_unknown_version_and_forbidden_transitions() {
        let path = temp_path("journal-corruption");
        let mut journal = WriteJournal::create_new(&path).expect("create");
        let prepared = journal.prepare(command("command-2")).expect("prepare");
        let forged_started = StartedCommand {
            command: prepared.command.clone(),
            lease_id: prepared.lease_id,
        };
        assert!(
            journal
                .mark_acknowledged(&forged_started, "ack-before-start".into())
                .is_err()
        );
        drop(journal);

        let original = std::fs::read(&path).expect("read");
        let truncated = path.with_extension("truncated");
        std::fs::write(&truncated, &original[..original.len() - 1]).expect("truncate fixture");
        assert!(matches!(
            WriteJournal::open(&truncated),
            Err(JournalError::Truncated)
        ));

        let mut tampered = original.clone();
        let position = tampered
            .iter()
            .position(|byte| *byte == b'p')
            .expect("payload byte");
        tampered[position] = b'q';
        let tampered_path = path.with_extension("tampered");
        std::fs::write(&tampered_path, tampered).expect("tamper fixture");
        assert!(WriteJournal::open(&tampered_path).is_err());

        let mut frame_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open frame");
        frame_file.seek(SeekFrom::Start(4)).expect("seek");
        let mut encoded = Vec::new();
        frame_file.read_to_end(&mut encoded).expect("read frame");
        let mut frame: JournalFrame = serde_json::from_slice(&encoded).expect("decode frame");
        frame.version = 99;
        let replacement = serde_json::to_vec(&frame).expect("encode frame");
        let unknown_path = path.with_extension("unknown");
        let mut unknown = Vec::new();
        unknown.extend_from_slice(
            &u32::try_from(replacement.len())
                .expect("small")
                .to_be_bytes(),
        );
        unknown.extend_from_slice(&replacement);
        std::fs::write(&unknown_path, unknown).expect("unknown fixture");
        assert!(matches!(
            WriteJournal::open(&unknown_path),
            Err(JournalError::UnknownVersion)
        ));
        std::fs::remove_dir_all(path.parent().expect("parent")).expect("cleanup");
    }
}
