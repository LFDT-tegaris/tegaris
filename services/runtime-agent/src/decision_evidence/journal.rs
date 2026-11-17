//! One commit boundary for decision state and its immutable encrypted history.
//! The legacy file is retained verbatim; sealing does not authenticate its past.
use super::{DecisionEvidence, DecisionEvidenceStatus, Journal};
use pc_runtime_types::{Digest, LocalJournal, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

mod capacity;
mod sealed;
#[cfg(test)]
mod tests;
pub use sealed::{EvidenceAdmissionReceipt, EvidenceSpoolBinding};
use sealed::{SealedChain, SealedRecord};

pub(super) enum DecisionJournal {
    Legacy(LocalJournal<Journal>),
    Sealed(Box<SealedDecisionJournal>),
}

pub(super) struct SealedDecisionJournal {
    disk: LocalJournal<SealedChain>,
    state: Journal,
    legacy_ids: BTreeSet<String>,
    key: ring::aead::LessSafeKey,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    decision_id: String,
    previous_record_digest: Option<Digest>,
    record: TransitionRecord,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
enum TransitionRecord {
    Decision(DecisionEvidence),
    PreAdmissionDenial {
        capsule_digest: Digest,
        boundary: String,
        pc_code: String,
        trace_id: Option<String>,
        observed_at_ns: u64,
    },
}
impl TransitionRecord {
    fn context(&self, admitted_at_ns: &str) -> (Digest, String, String) {
        match self {
            Self::PreAdmissionDenial {
                capsule_digest,
                observed_at_ns,
                ..
            } => (
                capsule_digest.clone(),
                observed_at_ns.to_string(),
                observed_at_ns.to_string(),
            ),
            Self::Decision(record) => {
                let occurred = match record.status {
                    DecisionEvidenceStatus::Reserved
                    | DecisionEvidenceStatus::SourceReadStarted { .. } => {
                        record.reserved_at_ns.to_string()
                    }
                    DecisionEvidenceStatus::Committed {
                        committed_at_ns, ..
                    } => committed_at_ns.to_string(),
                    DecisionEvidenceStatus::Released { released_at_ns, .. }
                    | DecisionEvidenceStatus::SourceReadReleased { released_at_ns, .. }
                    | DecisionEvidenceStatus::OperationStatusReleased { released_at_ns, .. } => {
                        released_at_ns.to_string()
                    }
                    DecisionEvidenceStatus::Interrupted => admitted_at_ns.into(),
                };
                (
                    record.capsule_digest.clone(),
                    record.reserved_at_ns.to_string(),
                    occurred,
                )
            }
        }
    }
}

/// Off-path projection for authenticated custody. Source bytes retain the
/// original encrypted transition; none of the response/request bodies exist in
/// this store. Activation and tenant authority must be verified independently.
#[derive(Serialize)]
pub struct SpoolExportRecord {
    pub sequence: String,
    pub decision_id: String,
    pub capsule_digest: Digest,
    pub reserved_at_ns: String,
    pub occurred_at_ns: String,
    pub source_digest: Digest,
    pub source_bytes: Vec<u8>,
    pub provenance: SpoolProvenance,
}

/// Minimized metadata from the authenticated transition, never a new decision,
/// provider effect receipt, or permission. Historical absent fields stay absent.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpoolProvenance {
    pub phase: &'static str,
    pub trace_id: Option<String>,
    pub request_digest: Option<Digest>,
    pub decision_digest: Option<Digest>,
    pub response_digest: Option<Digest>,
    pub authority_binding_digest: Option<Digest>,
    pub source_scope_digest: Option<Digest>,
    pub operation_id: Option<String>,
    pub pc_code: Option<String>,
    pub decision_effect: Option<pc_runtime_types::DecisionEffect>,
    pub boundary: Option<String>,
    pub source_segment_id: String,
    pub source_record_digest: Digest,
    pub admitted_at_ns: String,
}

impl TransitionRecord {
    fn provenance(&self, admission: &EvidenceAdmissionReceipt) -> SpoolProvenance {
        let mut view = SpoolProvenance {
            phase: "PRE_ADMISSION_DENIAL",
            trace_id: None,
            request_digest: None,
            decision_digest: None,
            response_digest: None,
            authority_binding_digest: None,
            source_scope_digest: None,
            operation_id: None,
            pc_code: None,
            decision_effect: None,
            boundary: None,
            source_segment_id: admission.segment_id.clone(),
            source_record_digest: admission.record_digest.clone(),
            admitted_at_ns: admission.admitted_at_ns.clone(),
        };
        match self {
            Self::PreAdmissionDenial {
                boundary,
                pc_code,
                trace_id,
                ..
            } => {
                view.boundary = Some(boundary.clone());
                view.pc_code = Some(pc_code.clone());
                view.trace_id = trace_id.clone();
            }
            Self::Decision(record) => {
                view.trace_id = record.trace_id.clone();
                view.request_digest = Some(record.request_digest.clone());
                match &record.status {
                    DecisionEvidenceStatus::Reserved => view.phase = "RESERVED",
                    DecisionEvidenceStatus::Interrupted => view.phase = "INTERRUPTED",
                    DecisionEvidenceStatus::SourceReadStarted {
                        source_scope_digest,
                        authority_binding_digest,
                    } => {
                        view.phase = "SOURCE_READ_STARTED";
                        view.source_scope_digest = Some(source_scope_digest.clone());
                        view.authority_binding_digest = Some(authority_binding_digest.clone());
                    }
                    DecisionEvidenceStatus::SourceReadReleased {
                        source_scope_digest,
                        authority_binding_digest,
                        response_digest,
                        ..
                    } => {
                        view.phase = "SOURCE_READ_RELEASED";
                        view.source_scope_digest = Some(source_scope_digest.clone());
                        view.authority_binding_digest = Some(authority_binding_digest.clone());
                        view.response_digest = Some(response_digest.clone());
                    }
                    DecisionEvidenceStatus::Committed {
                        effect,
                        pc_code,
                        decision_digest,
                        ..
                    } => {
                        view.phase = "COMMITTED";
                        view.decision_effect = Some(*effect);
                        view.pc_code = Some(pc_code.clone());
                        view.decision_digest = Some(decision_digest.clone());
                    }
                    DecisionEvidenceStatus::Released {
                        pc_code,
                        decision_digest,
                        response_digest,
                        ..
                    } => {
                        view.phase = "RELEASED";
                        view.pc_code = Some(pc_code.clone());
                        view.decision_digest = Some(decision_digest.clone());
                        view.response_digest = Some(response_digest.clone());
                    }
                    DecisionEvidenceStatus::OperationStatusReleased {
                        operation_id,
                        authority_binding_digest,
                        response_digest,
                        ..
                    } => {
                        view.phase = "OPERATION_STATUS_RELEASED";
                        view.operation_id = Some(operation_id.clone());
                        view.authority_binding_digest = Some(authority_binding_digest.clone());
                        view.response_digest = Some(response_digest.clone());
                    }
                }
            }
        }
        view
    }
}

#[derive(Serialize)]
struct SourceRecord<'a> {
    binding: &'a EvidenceSpoolBinding,
    legacy_digest: &'a Option<Digest>,
    genesis: &'a Option<sealed::Ciphertext>,
    record: &'a SealedRecord,
}

/// A read-only atomic snapshot never claims the serving writer lock, performs
/// recovery, advances an export checkpoint, or rewrites a legacy file.
pub fn read_spool_for_export(
    directory: &Path,
    binding: &EvidenceSpoolBinding,
    key: [u8; 32],
    after_sequence: u64,
    prior_source_digest: Option<&Digest>,
) -> RuntimeResult<Vec<SpoolExportRecord>> {
    binding.validate()?;
    let chain = LocalJournal::<SealedChain>::read_committed(directory, "sealed-decisions")?;
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
            .map_err(|_| RuntimeError::InvalidInput)?,
    );
    if &chain.binding != binding
        || after_sequence > chain.records.len() as u64
        || (after_sequence == 0) != prior_source_digest.is_none()
    {
        return Err(RuntimeError::TargetIdentity);
    }
    chain.verify_genesis(&key)?;
    let mut state = legacy_state(directory, &chain)?;
    let legacy_ids = state.records.keys().cloned().collect();
    let transitions = replay(&chain, &key, &mut state, &legacy_ids)?;
    let mut result = vec![];
    for (sealed, transition) in chain.records.iter().zip(transitions) {
        let source_bytes = canonical_bytes(&SourceRecord {
            binding: &chain.binding,
            legacy_digest: &chain.legacy_digest,
            genesis: &chain.genesis,
            record: sealed,
        })?;
        let source_digest = Digest::of(&source_bytes);
        if sealed.receipt.sequence == after_sequence && Some(&source_digest) != prior_source_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
        if sealed.receipt.sequence > after_sequence && result.len() < 8 {
            let (capsule_digest, reserved_at_ns, occurred_at_ns) =
                transition.record.context(&sealed.receipt.admitted_at_ns);
            result.push(SpoolExportRecord {
                sequence: sealed.receipt.sequence.to_string(),
                decision_id: transition.decision_id.clone(),
                capsule_digest,
                reserved_at_ns,
                occurred_at_ns,
                source_digest,
                source_bytes,
                provenance: transition.record.provenance(&sealed.receipt),
            });
        }
    }
    Ok(result)
}

fn legacy_state(directory: &Path, chain: &SealedChain) -> RuntimeResult<Journal> {
    let state = if chain.legacy_digest.is_some() {
        let legacy = LocalJournal::<Journal>::read_committed(directory, "decisions")?;
        if Some(Digest::of(canonical_bytes(&legacy)?)) != chain.legacy_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        legacy
    } else {
        Journal {
            version: 1,
            target_id: chain.binding.target_runtime_id.clone(),
            records: Default::default(),
        }
    };
    if state.version != 1 || state.target_id != chain.binding.target_runtime_id {
        return Err(RuntimeError::TargetIdentity);
    }
    Ok(state)
}

fn replay(
    chain: &SealedChain,
    key: &ring::aead::LessSafeKey,
    state: &mut Journal,
    legacy_ids: &BTreeSet<String>,
) -> RuntimeResult<Vec<Transition>> {
    let mut previous = None;
    let mut denials = BTreeSet::new();
    let mut transitions = Vec::with_capacity(chain.records.len());
    for (index, sealed) in chain.records.iter().enumerate() {
        let transition: Transition = sealed.open(chain, key)?;
        if sealed.receipt.sequence != index as u64 + 1
            || sealed.previous_segment_digest != previous
            || sealed.receipt.record_id != transition.decision_id
            || legacy_ids.contains(&transition.decision_id)
            || denials.contains(&transition.decision_id)
            || transition.previous_record_digest
                != state
                    .records
                    .get(&transition.decision_id)
                    .map(canonical_bytes)
                    .transpose()?
                    .map(Digest::of)
        {
            return Err(RuntimeError::InvalidDigest);
        }
        previous = Some(sealed.digest()?);
        match &transition.record {
            TransitionRecord::Decision(record) => {
                state
                    .records
                    .insert(transition.decision_id.clone(), record.clone());
            }
            TransitionRecord::PreAdmissionDenial { .. } => {
                denials.insert(transition.decision_id.clone());
            }
        }
        transitions.push(transition);
    }
    Ok(transitions)
}

/// Local diagnostic readback remains minimized, read-only and explicit about
/// legacy provenance. This is not a public evidence/authorization endpoint.
pub fn read_spool_snapshot(
    directory: &Path,
    binding: &EvidenceSpoolBinding,
    key: [u8; 32],
) -> RuntimeResult<serde_json::Value> {
    binding.validate()?;
    let chain = LocalJournal::<SealedChain>::read_committed(directory, "sealed-decisions")?;
    if &chain.binding != binding {
        return Err(RuntimeError::TargetIdentity);
    }
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
            .map_err(|_| RuntimeError::InvalidInput)?,
    );
    chain.verify_genesis(&key)?;
    let mut state = legacy_state(directory, &chain)?;
    let legacy_ids = state.records.keys().cloned().collect();
    replay(&chain, &key, &mut state, &legacy_ids)?;
    let mut result = serde_json::to_value(state).map_err(|_| RuntimeError::InvalidInput)?;
    result["legacyUnverifiedRecordIds"] =
        serde_json::to_value(legacy_ids).map_err(|_| RuntimeError::InvalidInput)?;
    Ok(result)
}

impl DecisionJournal {
    pub(super) fn capacity(
        &self,
        decision_capacity: usize,
    ) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
        capacity::read(self, decision_capacity)
    }

    pub(super) fn capacity_after(
        &self,
        next: &Journal,
        decision_capacity: usize,
    ) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
        capacity::projected(self, next, decision_capacity)
    }

    pub(super) fn open_sealed(
        directory: &Path,
        binding: EvidenceSpoolBinding,
        key: [u8; 32],
    ) -> RuntimeResult<Self> {
        binding.validate()?;
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
                .map_err(|_| RuntimeError::InvalidInput)?,
        );
        // Taking the existing directory lock prevents a legacy writer from
        // changing the preserved baseline while this source owns the spool.
        let mut recovered = None;
        let mut legacy_digest = None;
        let mut legacy_ids = BTreeSet::new();
        let mut disk = LocalJournal::open_validated(
            directory,
            "sealed-decisions",
            || SealedChain::empty(binding.clone()),
            |committed| {
                let legacy = match std::fs::symlink_metadata(directory.join("decisions.json")) {
                    Ok(_) => Some(LocalJournal::<Journal>::read_committed(
                        directory,
                        "decisions",
                    )?),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => return Err(RuntimeError::RuntimeUnavailable),
                };
                legacy_digest = legacy
                    .as_ref()
                    .map(canonical_bytes)
                    .transpose()?
                    .map(Digest::of);
                let mut state = legacy.unwrap_or_else(|| Journal {
                    version: 1,
                    target_id: binding.target_runtime_id.clone(),
                    records: Default::default(),
                });
                if state.version != 1 || state.target_id != binding.target_runtime_id {
                    return Err(RuntimeError::TargetIdentity);
                }
                legacy_ids = state.records.keys().cloned().collect();
                if let Some(chain) = committed {
                    if chain.binding != binding || chain.legacy_digest != legacy_digest {
                        return Err(RuntimeError::TargetIdentity);
                    }
                    chain.verify_genesis(&key)?;
                    replay(chain, &key, &mut state, &legacy_ids)?;
                }
                recovered = Some(state);
                Ok(())
            },
        )?;
        // Only a genuinely absent committed file reaches initialization.
        // Existing bytes have already authenticated under this same lock.
        if disk.state()?.genesis.is_none() {
            let mut initial = disk.state()?.clone();
            initial.legacy_digest = legacy_digest;
            initial.initialize(&key)?;
            disk.commit(initial)?;
        }
        Ok(Self::Sealed(Box::new(SealedDecisionJournal {
            disk,
            state: recovered.ok_or(RuntimeError::RuntimeUnavailable)?,
            legacy_ids,
            key,
        })))
    }

    pub(super) fn state(&self) -> RuntimeResult<&Journal> {
        match self {
            Self::Legacy(journal) => journal.state(),
            Self::Sealed(journal) => {
                journal.disk.state()?;
                Ok(&journal.state)
            }
        }
    }

    pub(super) fn legacy_record(&self, id: &str) -> bool {
        matches!(self, Self::Sealed(journal) if journal.legacy_ids.contains(id))
    }

    pub(super) fn binding(&self) -> Option<&EvidenceSpoolBinding> {
        match self {
            Self::Sealed(journal) => Some(&journal.disk.state().ok()?.binding),
            Self::Legacy(_) => None,
        }
    }

    pub(super) fn receipt(&self, id: &str) -> RuntimeResult<Option<EvidenceAdmissionReceipt>> {
        self.state()?;
        Ok(match self {
            Self::Sealed(journal) => journal
                .disk
                .state()?
                .records
                .iter()
                .rev()
                .find(|record| record.receipt.record_id == id)
                .map(|record| record.receipt.clone()),
            Self::Legacy(_) => None,
        })
    }

    pub(super) fn commit(&mut self, next: Journal) -> RuntimeResult<()> {
        match self {
            Self::Legacy(journal) => journal.commit(next),
            Self::Sealed(journal) => {
                let mut chain = journal.disk.state()?.clone();
                if next.version != journal.state.version
                    || next.target_id != journal.state.target_id
                    || journal
                        .state
                        .records
                        .keys()
                        .any(|id| !next.records.contains_key(id))
                {
                    return Err(RuntimeError::InvalidInput);
                }
                for (id, record) in &next.records {
                    let previous = journal.state.records.get(id);
                    if previous == Some(record) {
                        continue;
                    }
                    if journal.legacy_ids.contains(id) {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    let transition = Transition {
                        decision_id: id.clone(),
                        previous_record_digest: previous
                            .map(canonical_bytes)
                            .transpose()?
                            .map(Digest::of),
                        record: TransitionRecord::Decision(record.clone()),
                    };
                    let record = SealedRecord::seal(&chain, id, &transition, &journal.key)?;
                    chain.records.push(record);
                }
                // No mutable decision snapshot is written separately. A rename
                // acknowledges both state and sequence, or poisons this owner.
                if chain.records.len() == journal.disk.state()?.records.len() {
                    return Ok(());
                }
                capacity::retain_completion_slots(&chain, &next, &journal.legacy_ids)?;
                chain.seal_head(&journal.key)?;
                journal.disk.commit(chain)?;
                journal.state = next;
                Ok(())
            }
        }
    }

    pub(super) fn deny(
        &mut self,
        capsule_digest: Digest,
        boundary: &str,
        pc_code: &str,
        trace: Option<&str>,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        let Self::Sealed(journal) = self else {
            return Err(RuntimeError::InvalidAuthorization);
        };
        let mut chain = journal.disk.state()?.clone();
        let id = uuid::Uuid::now_v7().to_string();
        let transition = Transition {
            decision_id: id.clone(),
            previous_record_digest: None,
            record: TransitionRecord::PreAdmissionDenial {
                capsule_digest,
                boundary: boundary.into(),
                pc_code: pc_code.into(),
                trace_id: trace.map(str::to_owned),
                observed_at_ns: now_ns,
            },
        };
        let record = SealedRecord::seal(&chain, &id, &transition, &journal.key)?;
        chain.records.push(record);
        capacity::retain_completion_slots(&chain, &journal.state, &journal.legacy_ids)?;
        chain.seal_head(&journal.key)?;
        journal.disk.commit(chain)
    }
}
