//! Comparison-only reconstruction of the historical unsigned denial. This
//! projection is never verified or signed as a replacement delivery. The actual
//! current delivery retains its new credential and closed transition cause.
use super::*;

pub(super) fn historical_projection(
    value: &TargetDispositionDelivery,
) -> RuntimeResult<TargetDispositionDelivery> {
    let TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
        work_id,
        operation_id,
        execution_attempt_id,
        abandoned_revision,
        abandoned_admission_digest,
        original_receipt_wire_digest,
        installed_revision,
        installed_delivery_digest,
        observed_revision,
        observed_admission_digest,
        abandoned_target,
        ..
    } = &value.cause
    else {
        return Err(RuntimeError::InvalidTransition);
    };
    let current = &value.target;
    if observed_revision != abandoned_revision
        || observed_admission_digest != abandoned_admission_digest
        || current.participant_id != abandoned_target.participant_id
        || current.privacy_domain_id != abandoned_target.privacy_domain_id
        || current.target_id != abandoned_target.target_id
        || current.principal_id != abandoned_target.principal_id
        || current.principal_epoch != abandoned_target.principal_epoch
        || current.credential_id == abandoned_target.credential_id
        || current.certificate_digest == abandoned_target.certificate_digest
        || abandoned_target.credential_epoch.checked_add(1) != Some(current.credential_epoch)
    {
        return Err(RuntimeError::TargetIdentity);
    }
    let mut original = value.clone();
    original.target = abandoned_target.clone();
    original.cause = TargetDispositionCause::ExpiredObservedDenialHandover {
        work_id: work_id.clone(),
        operation_id: operation_id.clone(),
        execution_attempt_id: execution_attempt_id.clone(),
        abandoned_revision: *abandoned_revision,
        abandoned_admission_digest: abandoned_admission_digest.clone(),
        original_receipt_wire_digest: original_receipt_wire_digest.clone(),
        installed_revision: *installed_revision,
        installed_delivery_digest: installed_delivery_digest.clone(),
        observed_revision: *observed_revision,
        observed_admission_digest: observed_admission_digest.clone(),
    };
    Ok(original)
}

pub(super) fn compare_installed(
    value: &TargetDispositionDelivery,
    previous: &TargetDispositionDelivery,
    previous_digest: &Digest,
) -> RuntimeResult<()> {
    if !matches!(
        value.cause,
        TargetDispositionCause::ExpiredObservedCredentialDenialHandover { .. }
    ) {
        return Ok(());
    }
    let projection = historical_projection(value)?;
    expired_handover::compare_installed(&projection, previous, previous_digest)
}
