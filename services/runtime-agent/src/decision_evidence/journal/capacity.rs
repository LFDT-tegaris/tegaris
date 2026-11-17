//! Admission cannot consume the remaining sequence slots needed to finish an
//! already admitted decision. This does not grant storage or export authority.
//! These are logical slots, not allocated disk blocks or serialized-byte
//! reservations. LocalJournal still enforces its independent byte/I/O boundary.
use super::*;

pub(super) fn retain_completion_slots(
    chain: &SealedChain,
    state: &Journal,
    legacy_ids: &BTreeSet<String>,
) -> RuntimeResult<()> {
    if required_slots(chain.records.len(), state, legacy_ids) > sealed::MAX_RECORDS {
        return Err(RuntimeError::EvidenceCapacity);
    }
    Ok(())
}

fn required_slots(records: usize, state: &Journal, legacy_ids: &BTreeSet<String>) -> usize {
    let mut required = records;
    for (id, evidence) in &state.records {
        // Sealing never promotes or appends a transition to the legacy baseline.
        if legacy_ids.contains(id) {
            continue;
        }
        required += match &evidence.status {
            // A reservation may commit an allow decision and then its release;
            // interruption or a terminal denial consumes only one of these.
            DecisionEvidenceStatus::Reserved => 2,
            DecisionEvidenceStatus::SourceReadStarted { .. } => 1,
            DecisionEvidenceStatus::Committed {
                effect: pc_runtime_types::DecisionEffect::AllowForward,
                pc_code,
                protective_degradation: false,
                ..
            } if pc_code == "PC-RUNTIME-0000" => 1,
            _ => 0,
        };
    }
    required
}

/// Report the limiting logical bound, including denial records that have no
/// business-state row. Completion reservations already consume admission room.
/// This is not a claim about filesystem free space or serialized-byte headroom.
pub(super) fn read(
    journal: &DecisionJournal,
    decision_capacity: usize,
) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
    read_state(journal, journal.state()?, decision_capacity, 0)
}

/// Predict this owner's exact pending transitions without sealing or writing.
/// The normal commit still validates and durably admits the proposed state.
pub(super) fn projected(
    journal: &DecisionJournal,
    next: &Journal,
    decision_capacity: usize,
) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
    let current = journal.state()?;
    if next.version != current.version
        || next.target_id != current.target_id
        || current
            .records
            .keys()
            .any(|id| !next.records.contains_key(id))
    {
        return Err(RuntimeError::InvalidInput);
    }
    let mut additions = 0;
    for (id, record) in &next.records {
        if current.records.get(id) != Some(record) {
            if let DecisionJournal::Sealed(sealed) = journal
                && sealed.legacy_ids.contains(id)
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            additions += 1;
        }
    }
    read_state(journal, next, decision_capacity, additions)
}

fn read_state(
    journal: &DecisionJournal,
    state: &Journal,
    decision_capacity: usize,
    additions: usize,
) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
    let mut result = pc_runtime_types::EvidenceCapacity {
        used: state.records.len() as u64,
        capacity: decision_capacity as u64,
        high_watermark_percent: 80,
        critical_watermark_percent: 95,
    };
    if let DecisionJournal::Sealed(journal) = journal {
        let records = journal
            .disk
            .state()?
            .records
            .len()
            .checked_add(additions)
            .ok_or(RuntimeError::EvidenceCapacity)?;
        let required = required_slots(records, state, &journal.legacy_ids) as u64;
        let limit = sealed::MAX_RECORDS as u64;
        if u128::from(required) * u128::from(result.capacity)
            > u128::from(result.used) * u128::from(limit)
        {
            result.used = required;
            result.capacity = limit;
        }
    }
    Ok(result)
}
