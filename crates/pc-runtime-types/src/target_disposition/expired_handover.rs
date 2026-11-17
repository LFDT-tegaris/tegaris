//! Closed projection of one unsigned observed-effect denial. No issuance or
//! serving authority lives here; native Control and the journal own those gates.
use super::*;
use serde_json::json;

pub(super) fn reconstruct_abandoned(value: &TargetDispositionDelivery) -> RuntimeResult<Digest> {
    let TargetDispositionCause::ExpiredObservedDenialHandover {
        abandoned_revision, ..
    } = &value.cause
    else {
        return Err(RuntimeError::InvalidTransition);
    };
    // Explicit closed projection is the same material hashed by Control. The
    // later committed_admission_digest must not enter its own ancestor hash.
    let original = json!({"version":value.version,"action":"Withdraw","revision":abandoned_revision,
        "previous_revision":value.previous_revision,"previous_delivery_digest":value.previous_delivery_digest,
        "target":value.target,"source":value.source,"cause":{"kind":"Activation",
        "work_id":value.source.original_work_id,"operation_id":value.source.original_operation_id,
        "execution_attempt_id":value.source.original_execution_attempt_id}});
    Ok(Digest::of(canonical_bytes(&original)?))
}

pub(super) fn compare_installed(
    value: &TargetDispositionDelivery,
    previous: &TargetDispositionDelivery,
    previous_digest: &Digest,
) -> RuntimeResult<()> {
    let TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id,
        operation_id,
        installed_revision,
        installed_delivery_digest,
        ..
    } = &value.cause
    else {
        return Ok(());
    };
    if previous.action != TargetDispositionAction::Withdraw
        || value.target != previous.target
        || previous.revision != *installed_revision
        || previous_digest != installed_delivery_digest
        || value.source.predecessor_capsule_digest.as_ref() != Some(&previous.source.capsule_digest)
        || value.source.original_work_id == previous.source.original_work_id
        || previous.cause
            != (TargetDispositionCause::Activation {
                work_id: work_id.clone(),
                operation_id: operation_id.clone(),
                execution_attempt_id: None,
            })
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}

pub(super) fn check_floor(
    value: &TargetDispositionDelivery,
    previous: &TargetDispositionDelivery,
    revision: u64,
    admission: &Digest,
) -> RuntimeResult<()> {
    let TargetDispositionCause::ExpiredObservedDenialHandover {
        installed_revision,
        abandoned_revision,
        abandoned_admission_digest,
        observed_revision,
        observed_admission_digest,
        ..
    } = &value.cause
    else {
        return Err(RuntimeError::InvalidTransition);
    };
    if revision != *observed_revision
        || admission != observed_admission_digest
        || !((revision == *installed_revision && admission == &previous.committed_admission_digest)
            || (revision == *abandoned_revision && admission == abandoned_admission_digest))
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}
