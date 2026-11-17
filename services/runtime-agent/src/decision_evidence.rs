//! Sole target-local reservation and decision evidence commit owner.
//! The store contains minimized decision metadata, never request/provider bodies
//! or reusable capabilities. Unfinished reservations never become success.
use crate::{ActiveCapsuleLease, RequestTraceId};
use pc_runtime_types::{
    DecisionEffect, Digest, EvidenceCapacity, LocalJournal, RuntimeDecision, RuntimeError,
    RuntimeRequest, RuntimeResult,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Mutex, MutexGuard},
};

mod journal;
mod source;
use journal::DecisionJournal;
pub use journal::{
    EvidenceAdmissionReceipt, EvidenceSpoolBinding, SpoolExportRecord, read_spool_for_export,
    read_spool_snapshot,
};
pub use source::SourceReadEvidenceInput;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DecisionEvidenceStatus {
    Reserved,
    Interrupted,
    SourceReadStarted {
        source_scope_digest: Digest,
        authority_binding_digest: Digest,
    },
    SourceReadReleased {
        source_scope_digest: Digest,
        authority_binding_digest: Digest,
        response_digest: Digest,
        released_at_ns: u64,
    },
    Committed {
        effect: DecisionEffect,
        pc_code: String,
        decision_input_digest: Digest,
        decision_digest: Digest,
        protective_degradation: bool,
        committed_at_ns: u64,
    },
    Released {
        pc_code: String,
        decision_input_digest: Digest,
        decision_digest: Digest,
        response_digest: Digest,
        committed_at_ns: u64,
        released_at_ns: u64,
    },
    /// A local status decision has no provider capability or provider effect.
    /// The authenticated operation/status owner commits the exact safe view.
    OperationStatusReleased {
        operation_id: String,
        authority_binding_digest: Digest,
        response_digest: Digest,
        released_at_ns: u64,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvidence {
    /// Older local records have no stream correlation and retain that fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub request_digest: Digest,
    pub capsule_digest: Digest,
    pub reserved_at_ns: u64,
    pub valid_until_ns: u64,
    pub status: DecisionEvidenceStatus,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    target_id: String,
    records: BTreeMap<String, DecisionEvidence>,
}
pub struct DecisionEvidenceStore {
    target_id: String,
    capacity: usize,
    journal: Mutex<DecisionJournal>,
}
pub struct DecisionEvidenceReservation<'a> {
    guard: MutexGuard<'a, DecisionJournal>,
    id: String,
    capacity: usize,
    finished: bool,
}
impl DecisionEvidenceStore {
    pub fn open(directory: &Path, target_id: &str, capacity: usize) -> RuntimeResult<Self> {
        // Compatibility access must never downgrade a migrated spool or write
        // its immutable unauthenticated baseline after sealed admission began.
        match std::fs::symlink_metadata(directory.join("sealed-decisions.json")) {
            Ok(_) => return Err(RuntimeError::InvalidAuthorization),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RuntimeError::RuntimeUnavailable),
        }
        // At most 1024 bounded records leave headroom below the generic 16MiB
        // journal ceiling. Retention is fail-closed until evidence export owns
        // an acknowledged release; elapsed time alone never deletes evidence.
        if target_id.is_empty() || target_id.len() > 160 || !(1..=1024).contains(&capacity) {
            return Err(RuntimeError::InvalidInput);
        }
        let journal = LocalJournal::open(directory, "decisions", || Journal {
            version: 1,
            target_id: target_id.into(),
            records: BTreeMap::new(),
        })?;
        Self::from_journal(DecisionJournal::Legacy(journal), target_id, capacity)
    }

    /// The service bootstrap supplies this binding from its verified manifest,
    /// and a dedicated host-provisioned key. Requests cannot choose either.
    pub fn open_sealed(
        directory: &Path,
        binding: EvidenceSpoolBinding,
        key: [u8; 32],
        capacity: usize,
    ) -> RuntimeResult<Self> {
        if !(1..=1024).contains(&capacity) {
            return Err(RuntimeError::InvalidInput);
        }
        let target_id = binding.target_runtime_id.clone();
        Self::from_journal(
            DecisionJournal::open_sealed(directory, binding, key)?,
            &target_id,
            capacity,
        )
    }

    pub fn admission_receipt(&self, id: &str) -> RuntimeResult<Option<EvidenceAdmissionReceipt>> {
        self.journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .receipt(id)
    }

    /// No request identity or authorization is invented for a failure before
    /// reservation. The actual installed capsule and closed failure category
    /// are retained under the same activation -> evidence lock order.
    pub fn record_transport_denial(
        &self,
        agent: &crate::RuntimeAgent,
        boundary: &str,
        error: &RuntimeError,
        trace: Option<&str>,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        if !matches!(
            boundary,
            "ext-proc" | "pds-pre-admission" | "broker" | "source-only-invocation-denial"
        ) || trace.is_some_and(|value| !RequestTraceId::valid(value))
            || now_ns == 0
        {
            return Err(RuntimeError::InvalidInput);
        }
        agent.with_active_capsule(|capsule, _| {
            if capsule.target_runtime_id != self.target_id {
                return Err(RuntimeError::TargetIdentity);
            }
            self.journal
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .deny(capsule.digest()?, boundary, error.pc_code(), trace, now_ns)
        })
    }

    pub fn validate_scope(
        &self,
        participant: &str,
        privacy: &str,
        target: &str,
    ) -> RuntimeResult<()> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let binding = journal
            .binding()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if binding.participant_id != participant
            || binding.privacy_domain_id != privacy
            || binding.target_runtime_id != target
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(())
    }

    fn from_journal(
        mut journal: DecisionJournal,
        target_id: &str,
        capacity: usize,
    ) -> RuntimeResult<Self> {
        let state = journal.state()?;
        if state.version != 1 || state.target_id != target_id || state.records.len() > capacity {
            return Err(RuntimeError::GenerationMismatch);
        }
        let mut traces = BTreeSet::new();
        for (id, evidence) in &state.records {
            let parsed = uuid::Uuid::parse_str(id).map_err(|_| RuntimeError::InvalidInput)?;
            if parsed.get_version_num() != 7
                || parsed.to_string() != *id
                || evidence.reserved_at_ns >= evidence.valid_until_ns
                || evidence
                    .trace_id
                    .as_ref()
                    .is_some_and(|trace| !RequestTraceId::valid(trace) || !traces.insert(trace))
            {
                return Err(RuntimeError::InvalidInput);
            }
            match &evidence.status {
                DecisionEvidenceStatus::SourceReadStarted {
                    source_scope_digest,
                    authority_binding_digest,
                }
                | DecisionEvidenceStatus::SourceReadReleased {
                    source_scope_digest,
                    authority_binding_digest,
                    ..
                } if Digest::parse(source_scope_digest.as_str()).is_err()
                    || Digest::parse(authority_binding_digest.as_str()).is_err() =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                DecisionEvidenceStatus::SourceReadReleased {
                    response_digest,
                    released_at_ns,
                    ..
                } if Digest::parse(response_digest.as_str()).is_err()
                    || *released_at_ns < evidence.reserved_at_ns
                    || *released_at_ns >= evidence.valid_until_ns =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                DecisionEvidenceStatus::OperationStatusReleased {
                    operation_id,
                    authority_binding_digest,
                    response_digest,
                    released_at_ns,
                } if !RequestTraceId::valid(operation_id)
                    || Digest::parse(authority_binding_digest.as_str()).is_err()
                    || Digest::parse(response_digest.as_str()).is_err()
                    || *released_at_ns < evidence.reserved_at_ns
                    || *released_at_ns >= evidence.valid_until_ns =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                DecisionEvidenceStatus::Committed {
                    pc_code,
                    effect,
                    committed_at_ns,
                    ..
                } if !valid_code(pc_code)
                    || *committed_at_ns < evidence.reserved_at_ns
                    || (*effect == DecisionEffect::AllowForward
                        && *committed_at_ns >= evidence.valid_until_ns) =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                DecisionEvidenceStatus::Released {
                    pc_code,
                    committed_at_ns,
                    released_at_ns,
                    ..
                } if pc_code != "PC-RUNTIME-0000"
                    || *committed_at_ns < evidence.reserved_at_ns
                    || *released_at_ns < *committed_at_ns
                    || *released_at_ns >= evidence.valid_until_ns =>
                {
                    return Err(RuntimeError::InvalidInput);
                }
                _ => {}
            }
        }
        if state.records.iter().any(|(id, e)| {
            e.status == DecisionEvidenceStatus::Reserved && !journal.legacy_record(id)
        }) {
            let mut recovered = state.clone();
            for (id, evidence) in &mut recovered.records {
                if evidence.status == DecisionEvidenceStatus::Reserved && !journal.legacy_record(id)
                {
                    evidence.status = DecisionEvidenceStatus::Interrupted;
                }
            }
            journal.commit(recovered)?;
        }
        Ok(Self {
            target_id: target_id.into(),
            capacity,
            journal: Mutex::new(journal),
        })
    }
    /// Lock order is always active capsule, then evidence. Both remain held
    /// through PDS evaluation and commit; activation cannot race evidence.
    pub fn reserve(
        &self,
        capsule: &ActiveCapsuleLease<'_>,
        request: &RuntimeRequest,
        now_ns: u64,
    ) -> RuntimeResult<DecisionEvidenceReservation<'_>> {
        self.reserve_inner(capsule, request, None, u64::MAX, now_ns)
    }
    pub fn reserve_for_trace(
        &self,
        capsule: &ActiveCapsuleLease<'_>,
        request: &RuntimeRequest,
        trace: &RequestTraceId,
        now_ns: u64,
    ) -> RuntimeResult<DecisionEvidenceReservation<'_>> {
        self.reserve_inner(capsule, request, Some(trace), u64::MAX, now_ns)
    }
    pub(crate) fn reserve_for_trace_until(
        &self,
        capsule: &ActiveCapsuleLease<'_>,
        request: &RuntimeRequest,
        trace: &RequestTraceId,
        valid_until_ns: u64,
        now_ns: u64,
    ) -> RuntimeResult<DecisionEvidenceReservation<'_>> {
        self.reserve_inner(capsule, request, Some(trace), valid_until_ns, now_ns)
    }
    fn reserve_inner(
        &self,
        capsule: &ActiveCapsuleLease<'_>,
        request: &RuntimeRequest,
        trace: Option<&RequestTraceId>,
        owner_valid_until_ns: u64,
        now_ns: u64,
    ) -> RuntimeResult<DecisionEvidenceReservation<'_>> {
        capsule.revalidate(now_ns)?;
        request.validate_digest()?;
        if capsule.capsule().target_runtime_id != self.target_id {
            return Err(RuntimeError::TargetIdentity);
        }
        let valid_until_ns = capsule.expires_at_ns().min(owner_valid_until_ns).min(
            request
                .deadline_at_ms
                .checked_mul(1_000_000)
                .ok_or(RuntimeError::InvalidInput)?,
        );
        if now_ns
            < request
                .received_at_ms
                .checked_mul(1_000_000)
                .ok_or(RuntimeError::InvalidInput)?
            || now_ns >= valid_until_ns
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = guard.state()?.clone();
        if trace.is_some_and(|trace| {
            next.records
                .values()
                .any(|record| record.trace_id.as_deref() == Some(trace.as_str()))
        }) {
            return Err(RuntimeError::Replay);
        }
        if next.records.len() >= self.capacity {
            return Err(RuntimeError::EvidenceCapacity);
        }
        let id = uuid::Uuid::now_v7().to_string();
        if next.records.contains_key(&id) {
            return Err(RuntimeError::Replay);
        }
        next.records.insert(
            id.clone(),
            DecisionEvidence {
                trace_id: trace.map(|trace| trace.as_str().to_owned()),
                request_digest: request.request_digest.clone(),
                capsule_digest: capsule.capsule().digest()?,
                reserved_at_ns: now_ns,
                valid_until_ns,
                status: DecisionEvidenceStatus::Reserved,
            },
        );
        guard.commit(next)?;
        Ok(DecisionEvidenceReservation {
            guard,
            id,
            capacity: self.capacity,
            finished: false,
        })
    }
    pub fn read(&self, id: &str) -> RuntimeResult<Option<DecisionEvidence>> {
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(guard.state()?.records.get(id).cloned())
    }
    pub fn read_for_trace(&self, trace: &str) -> RuntimeResult<Option<(String, DecisionEvidence)>> {
        if !RequestTraceId::valid(trace) {
            return Err(RuntimeError::InvalidInput);
        }
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(guard
            .state()?
            .records
            .iter()
            .find(|(_, record)| record.trace_id.as_deref() == Some(trace))
            .map(|(id, record)| (id.clone(), record.clone())))
    }

    /// Record the actual response-release effect after Broker completion and
    /// final authority revalidation. Replays cannot rewrite the response digest.
    pub fn release_for_trace(
        &self,
        trace: &RequestTraceId,
        response: &[u8],
        now_ns: u64,
    ) -> RuntimeResult<DecisionEvidence> {
        if response.is_empty() || response.len() > 4 * 1024 * 1024 {
            return Err(RuntimeError::ResponseWithheld);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = guard.state()?.clone();
        let (_, evidence) = next
            .records
            .iter_mut()
            .find(|(_, record)| record.trace_id.as_deref() == Some(trace.as_str()))
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let response_digest = Digest::of(response);
        match &evidence.status {
            DecisionEvidenceStatus::Committed {
                effect: DecisionEffect::AllowForward,
                pc_code,
                decision_input_digest,
                decision_digest,
                protective_degradation: false,
                committed_at_ns,
            } if pc_code == "PC-RUNTIME-0000"
                && now_ns >= *committed_at_ns
                && now_ns < evidence.valid_until_ns =>
            {
                evidence.status = DecisionEvidenceStatus::Released {
                    pc_code: pc_code.clone(),
                    decision_input_digest: decision_input_digest.clone(),
                    decision_digest: decision_digest.clone(),
                    response_digest,
                    committed_at_ns: *committed_at_ns,
                    released_at_ns: now_ns,
                };
            }
            DecisionEvidenceStatus::Released { .. } => return Err(RuntimeError::Replay),
            _ => return Err(RuntimeError::ResponseWithheld),
        }
        let released = evidence.clone();
        guard.commit(next)?;
        Ok(released)
    }
}
fn valid_code(code: &str) -> bool {
    code.strip_prefix("PC-RUNTIME-")
        .is_some_and(|suffix| suffix.len() == 4 && suffix.bytes().all(|b| b.is_ascii_digit()))
}
impl DecisionEvidenceReservation<'_> {
    pub(crate) fn commit_operation_status(
        &mut self,
        capsule: &ActiveCapsuleLease<'_>,
        request: &RuntimeRequest,
        operation_id: &str,
        authority_binding_digest: Digest,
        response: &[u8],
        now_ns: u64,
    ) -> RuntimeResult<()> {
        self.revalidate(capsule, now_ns)?;
        if self.finished
            || request.method != "pc_getOperationStatus"
            || request.class != pc_runtime_types::RequestClass::Read
            || request.invocation.is_some()
            || request.batch_index != 0
            || !RequestTraceId::valid(operation_id)
            || response.is_empty()
            || response.len() > 8192
            || response.len() as u64 > request.response_budget_bytes
        {
            return Err(RuntimeError::InvalidInput);
        }
        request.validate_digest()?;
        let operation_params =
            openpc_multi_rpc::rfc8785_canonical_bytes(&serde_json::json!([format!(
                "urn:openpc:operation:{operation_id}"
            )]))
            .map_err(|_| RuntimeError::InvalidInput)?;
        if request.params_digest != Digest::of(operation_params) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut next = self.guard.state()?.clone();
        let evidence = next
            .records
            .get_mut(&self.id)
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        if evidence.request_digest != request.request_digest || evidence.trace_id.is_none() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // Local status responses bypass PDS but still require durable capacity.
        // A failed reservation remains recoverable as interrupted, never released.
        if self.capacity()?.critical() {
            return Err(RuntimeError::EvidenceCapacity);
        }
        evidence.status = DecisionEvidenceStatus::OperationStatusReleased {
            operation_id: operation_id.into(),
            authority_binding_digest,
            response_digest: Digest::of(response),
            released_at_ns: now_ns,
        };
        self.guard.commit(next)?;
        self.finished = true;
        Ok(())
    }
    pub fn decision_id(&self) -> &str {
        &self.id
    }
    pub fn capacity(&self) -> RuntimeResult<EvidenceCapacity> {
        self.guard.capacity(self.capacity)
    }
    pub fn revalidate(&self, capsule: &ActiveCapsuleLease<'_>, now_ns: u64) -> RuntimeResult<()> {
        capsule.revalidate(now_ns)?;
        let evidence = self
            .guard
            .state()?
            .records
            .get(&self.id)
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        if self.finished
            || evidence.status != DecisionEvidenceStatus::Reserved
            || evidence.capsule_digest != capsule.capsule().digest()?
            || now_ns < evidence.reserved_at_ns
            || now_ns >= evidence.valid_until_ns
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }
    pub fn commit(
        &mut self,
        capsule: &ActiveCapsuleLease<'_>,
        decision: &RuntimeDecision,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        if decision.effect == DecisionEffect::AllowForward {
            self.revalidate(capsule, now_ns)?;
        }
        let mut next = self.guard.state()?.clone();
        let evidence = next
            .records
            .get_mut(&self.id)
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let capability_matches = match &decision.capability {
            Some(capability) => {
                decision.effect == DecisionEffect::AllowForward
                    && decision.pc_code == "PC-RUNTIME-0000"
                    && capability.claims.request_digest == evidence.request_digest
                    && capability.claims.active_generation_digest == evidence.capsule_digest
                    && capability.claims.decision_digest == decision.decision_digest
                    && capability.claims.target_id == capsule.capsule().target_runtime_id
                    && capability.claims.issued_at_ms < capability.claims.expires_at_ms
                    && capability.claims.issued_at_ms <= now_ns / 1_000_000
                    && capability.claims.expires_at_ms > now_ns / 1_000_000
                    && capability.claims.expires_at_ms <= evidence.valid_until_ns / 1_000_000
            }
            None => decision.effect != DecisionEffect::AllowForward,
        };
        if self.finished
            || evidence.status != DecisionEvidenceStatus::Reserved
            || decision.decision_id != self.id
            || decision.active_generation_digest != evidence.capsule_digest
            || !valid_code(&decision.pc_code)
            || capsule.capsule().digest()? != evidence.capsule_digest
            || now_ns < evidence.reserved_at_ns
            || !capability_matches
        {
            return Err(RuntimeError::InvalidInput);
        }
        evidence.status = DecisionEvidenceStatus::Committed {
            effect: decision.effect,
            pc_code: decision.pc_code.clone(),
            decision_input_digest: decision.decision_input_digest.clone(),
            decision_digest: decision.decision_digest.clone(),
            protective_degradation: decision.protective_degradation,
            committed_at_ns: now_ns,
        };
        self.guard.commit(next)?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for DecisionEvidenceReservation<'_> {
    fn drop(&mut self) {
        if !self.finished
            && let Ok(state) = self.guard.state()
        {
            let mut next = state.clone();
            if let Some(evidence) = next.records.get_mut(&self.id) {
                evidence.status = DecisionEvidenceStatus::Interrupted;
                // Failed persistence poisons this store; no later request can
                // reuse a reservation whose outcome is uncertain.
                let _ = self.guard.commit(next);
            }
        }
    }
}
