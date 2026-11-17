//! Read-only proof of the installed negative head and authenticated observed
//! floor. The host cannot manufacture a serving lease through this API.
use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExpiredDenialHandoverFloor {
    pub installed_revision: u64,
    pub installed_delivery_digest: Digest,
    pub observed_revision: u64,
    pub observed_admission_digest: Digest,
    pub original_receipt_wire_digest: Digest,
}

fn expired_receipt(
    agent: &RuntimeAgent,
    state: &CanonicalJournal,
    source: &TargetDispositionSource,
) -> RuntimeResult<Digest> {
    agent.match_disposition_source(state, source)?;
    let active = state
        .active
        .as_ref()
        .ok_or(RuntimeError::GenerationMismatch)?;
    let wire = agent.wire()?;
    let capsule = wire.validate(&active.custody)?;
    let receipt = wire.validate_activation(active)?;
    if crate::target_state::wall_clock_ns()? < capsule.hard_expiry_ns
        || capsule.previous_capsule_digest.is_none()
        || receipt.status != 1
        || receipt.observed_at_ns < capsule.not_before_ns
        || receipt.observed_at_ns >= capsule.hard_expiry_ns
        || receipt.agent_sequence != state.sequence
        || !state.receipts.contains(&active.receipt)
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(Digest::of(&active.receipt))
}

pub(super) fn validate_effect(
    agent: &RuntimeAgent,
    state: &CanonicalJournal,
    source: &TargetDispositionSource,
    delivery: &VerifiedTargetDispositionDelivery,
) -> RuntimeResult<()> {
    if let TargetDispositionCause::ExpiredObservedDenialHandover {
        original_receipt_wire_digest,
        ..
    }
    | TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
        original_receipt_wire_digest,
        ..
    } = &delivery.claims().cause
        && expired_receipt(agent, state, source)? != *original_receipt_wire_digest
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

impl RuntimeAgent {
    /// A fresh authenticated read must identify the exact pending unsigned
    /// denial. The read may advance only the antirollback floor; it signs no ACK.
    pub async fn observe_expired_denial_handover(
        &self,
        revision: u64,
        admission: &Digest,
    ) -> RuntimeResult<ExpiredDenialHandoverFloor> {
        self.observe_expired_denial_floor(revision, admission, None)
            .await
    }

    /// The already installed host owner must independently bind this historical
    /// credential. Only the unsigned floor is observed; no ACK or serving grant.
    pub async fn observe_expired_credential_denial_handover(
        &self,
        revision: u64,
        admission: &Digest,
        predecessor: &TargetDispositionIdentity,
    ) -> RuntimeResult<ExpiredDenialHandoverFloor> {
        self.observe_expired_denial_floor(revision, admission, Some(predecessor))
            .await
    }

    async fn observe_expired_denial_floor(
        &self,
        revision: u64,
        admission: &Digest,
        predecessor: Option<&TargetDispositionIdentity>,
    ) -> RuntimeResult<ExpiredDenialHandoverFloor> {
        let owner = self
            .disposition_owner
            .get()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        if predecessor.is_some() && owner.historical_target.as_ref() != predecessor {
            return Err(RuntimeError::TargetIdentity);
        }
        let _gate = owner.source_reads.write().await;
        self.fence_target_disposition()?;
        self.require_expired_confirmation_custody(owner)?;
        let response = read_current(owner).await?;
        if response.revision != revision
            || response.admission_digest != admission.as_str()
            || !response.signed_delivery.is_empty()
            || !response.signed_acknowledgement.is_empty()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        self.observe_disposition_head(owner, &response.custody()?)?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let receipt = expired_receipt(self, state, &owner.source)?;
        let disposition = state
            .target_disposition
            .as_ref()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let installed = owner
            .installed(disposition)?
            .ok_or(RuntimeError::GenerationMismatch)?;
        let observed = disposition
            .observed
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if installed.claims().action != TargetDispositionAction::Withdraw
            || &installed.claims().target != predecessor.unwrap_or(&owner.target)
            || installed.claims().revision.checked_add(1) != Some(revision)
            || installed.claims().source.capsule_digest
                != owner
                    .source
                    .predecessor_capsule_digest
                    .clone()
                    .ok_or(RuntimeError::GenerationMismatch)?
            || installed.claims().cause
                != (TargetDispositionCause::Activation {
                    work_id: owner.source.original_work_id.clone(),
                    operation_id: owner.source.original_operation_id.clone(),
                    execution_attempt_id: None,
                })
            || observed.revision != revision
            || observed.admission_digest != *admission
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(ExpiredDenialHandoverFloor {
            installed_revision: installed.claims().revision,
            installed_delivery_digest: installed.signed_digest().clone(),
            observed_revision: observed.revision,
            observed_admission_digest: observed.admission_digest.clone(),
            original_receipt_wire_digest: receipt,
        })
    }
}
