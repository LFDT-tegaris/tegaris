//! Explicit fee-bump custody in the existing journal. The retained predecessor
//! never becomes retryable, and observation evidence grants no send authority.
use super::*;
use crate::provider_connection::ConnectionRecord;
use pc_policy_core::transaction_policy::TransactionPolicyV1;
use pc_runtime_types::{Digest, canonical_bytes};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplacementLink {
    predecessor_command_id: String,
    predecessor_transaction_hash: String,
    pending: observation::ObservationEvidence,
}

pub(super) fn related(records: &BTreeMap<String, JournalRecord>, command_id: &str) -> bool {
    records
        .get(command_id)
        .is_some_and(|record| record.replacement.is_some())
        || records.values().any(|record| {
            record
                .replacement
                .as_ref()
                .is_some_and(|link| link.predecessor_command_id == command_id)
        })
}

pub(super) fn superseding_successor<'a>(
    records: &'a BTreeMap<String, JournalRecord>,
    command_id: &str,
) -> Option<&'a JournalRecord> {
    let original = records.get(command_id)?;
    if original
        .observation
        .as_ref()
        .is_some_and(|proof| proof.has_canonical_inclusion())
    {
        return None;
    }
    records.values().find(|record| {
        record
            .replacement
            .as_ref()
            .is_some_and(|link| link.predecessor_command_id == command_id)
            && record
                .observation
                .as_ref()
                .is_some_and(|proof| proof.has_canonical_inclusion())
    })
}

impl WriteJournal {
    /// Called only after fresh runtime/PDS admission. The proof comes from the
    /// existing exact-hash observer over the same pinned connection; the final
    /// live write fence and one-use STARTED handle still govern execution.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_replacement(
        &mut self,
        command: GovernedCommand,
        transaction: &SignedTransaction,
        admission: SubmissionAdmission,
        predecessor: &ObservationTarget,
        proof: VerifiedObservation,
        connection: &ConnectionRecord,
        policy: &TransactionPolicyV1,
    ) -> Result<PreparedCommand, JournalError> {
        self.ensure_healthy()?;
        crate::governed_write::validate_submission(transaction, &command)
            .map_err(|_| JournalError::IdentityMismatch)?;
        admission.validate(&command)?;
        admission.validate_transaction(transaction)?;
        transaction
            .enforce_policy(policy)
            .map_err(|_| JournalError::IdentityMismatch)?;
        if Digest::of(canonical_bytes(policy).map_err(|_| JournalError::IdentityMismatch)?)
            != admission.transaction_policy_digest
        {
            return Err(JournalError::IdentityMismatch);
        }
        proof.validate_replacement_binding(predecessor, connection, admission.admitted_at_ms)?;
        let link = ReplacementLink {
            predecessor_command_id: predecessor.command().command_id.clone(),
            predecessor_transaction_hash: predecessor.command().request_or_transaction_hash.clone(),
            pending: proof.into_evidence(),
        };
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
            Some(link),
        )
    }

    /// Scoped lookup returns the one retained successor even after a pre-start
    /// failure. It never allocates another command or returns a send handle.
    pub fn replacement_successor(
        &self,
        predecessor: &str,
        owner: &SubmissionOwner,
    ) -> Option<GovernedCommand> {
        self.submission(predecessor, owner)?;
        let record = self.latest_by_command.values().find(|record| {
            record
                .replacement
                .as_ref()
                .is_some_and(|link| link.predecessor_command_id == predecessor)
                && record
                    .submission_admission
                    .as_ref()
                    .is_some_and(|admission| &admission.owner == owner)
        })?;
        Some(command_from_record(record))
    }
}

fn same_authority(prior: &SubmissionAdmission, next: &SubmissionAdmission) -> bool {
    // Fresh capability, decision, observation and deadlines are deliberately
    // distinct; all retained authority owners and effect bindings stay exact.
    prior.owner == next.owner
        && prior.target_runtime_id == next.target_runtime_id
        && prior.runtime_binding_id == next.runtime_binding_id
        && prior.chain.is_some()
        && prior.chain == next.chain
        && prior.wallet_binding_id == next.wallet_binding_id
        && prior.wallet_binding_epoch == next.wallet_binding_epoch
        && prior.workload_peer_binding_digest == next.workload_peer_binding_digest
        && prior.risk_class == next.risk_class
        && prior.capsule_digest == next.capsule_digest
        && prior.contract_set_manifest_digest == next.contract_set_manifest_digest
        && prior.invocation_profile_digest == next.invocation_profile_digest
        && prior.capability_registry_digest == next.capability_registry_digest
        && prior.request_form_registry_digest == next.request_form_registry_digest
        && prior.error_registry_digest == next.error_registry_digest
        && prior.policy_generation_digest == next.policy_generation_digest
        && prior.transaction_policy_digest == next.transaction_policy_digest
        && prior.evidence_admission_profile_digest == next.evidence_admission_profile_digest
        && prior.contract_address == next.contract_address
        && prior.selector == next.selector
        && match (&prior.deployment, &next.deployment) {
            (None, None) => prior.prepared_intent_digest == next.prepared_intent_digest,
            (Some(a), Some(b)) => {
                if a.predecessor_command_id.is_some()
                    || b.predecessor_command_id.as_ref() != Some(&a.command_id)
                    || match (&a.dispatch, &b.dispatch) {
                        (Some(a), Some(b)) => !a.same_route_and_connection(b),
                        (None, None) => false,
                        _ => true,
                    }
                {
                    return false;
                }
                let mut expected = a.clone();
                expected.command_id.clone_from(&b.command_id);
                expected.attempt_id.clone_from(&b.attempt_id);
                expected
                    .predecessor_command_id
                    .clone_from(&b.predecessor_command_id);
                expected.intent_id.clone_from(&b.intent_id);
                expected.intent_digest.clone_from(&b.intent_digest);
                expected
                    .preparation_digest
                    .clone_from(&b.preparation_digest);
                expected
                    .reservation_binding_digest
                    .clone_from(&b.reservation_binding_digest);
                expected.preparation_expires_at_ms = b.preparation_expires_at_ms;
                expected.constraints.signing_hash = b.constraints.signing_hash;
                expected.dispatch.clone_from(&b.dispatch);
                expected == *b
            }
            _ => false,
        }
}

pub(super) fn validate_new(
    records: &BTreeMap<String, JournalRecord>,
    next: &JournalRecord,
) -> Result<(), JournalError> {
    let Some(link) = &next.replacement else {
        if next
            .submission_admission
            .as_ref()
            .and_then(|a| a.deployment.as_ref())
            .is_some_and(|d| d.predecessor_command_id.is_some())
        {
            return Err(JournalError::IdentityMismatch);
        }
        return validate_nonce_reservation(records, next.signed_identity.as_ref());
    };
    let prior = records
        .get(&link.predecessor_command_id)
        .ok_or(JournalError::IdentityMismatch)?;
    let a = prior
        .submission_admission
        .as_ref()
        .ok_or(JournalError::IdentityMismatch)?;
    let b = next
        .submission_admission
        .as_ref()
        .ok_or(JournalError::IdentityMismatch)?;
    let old = prior
        .signed_identity
        .as_ref()
        .ok_or(JournalError::IdentityMismatch)?;
    let new = next
        .signed_identity
        .as_ref()
        .ok_or(JournalError::IdentityMismatch)?;
    if prior.replacement.is_some()
        || link.predecessor_transaction_hash != prior.request_or_transaction_hash
        || !same_authority(a, b)
        || old.chain_id != new.chain_id
        || old.signer != new.signer
        || old.nonce != new.nonce
        || old.transaction_hash == new.transaction_hash
        || prior.provider_profile_digest != next.provider_profile_digest
        || prior.provider_instance_id != next.provider_instance_id
        || next
            .fee_identity
            .as_ref()
            .zip(prior.fee_identity.as_ref())
            .is_none_or(|(new, old)| !new.increases(old))
        || records.values().any(|record| {
            record
                .replacement
                .as_ref()
                .is_some_and(|other| other.predecessor_command_id == prior.command_id)
                || (record.command_id != prior.command_id
                    && record.state != JournalState::FailedPreStart
                    && record.signed_identity.as_ref().is_some_and(|identity| {
                        identity.chain_id == new.chain_id
                            && identity.signer == new.signer
                            && identity.nonce == new.nonce
                    }))
        })
    {
        return Err(JournalError::IdentityMismatch);
    }
    link.pending
        .validate_pending_replacement(prior, b.admitted_at_ms)
}

pub(super) fn validate_start(
    records: &BTreeMap<String, JournalRecord>,
    next: &JournalRecord,
) -> Result<(), JournalError> {
    let Some(link) = &next.replacement else {
        return Ok(());
    };
    let prior = records
        .get(&link.predecessor_command_id)
        .ok_or(JournalError::IdentityMismatch)?;
    let now = crate::provider_connection::now_ms().map_err(|_| JournalError::Integrity)?;
    link.pending.validate_pending_replacement(prior, now)
}
