//! Target-local disposition custody. The host installs the authenticated Control
//! transport once; request callers cannot submit a readiness flag or a lease.
use crate::{RuntimeAgent, activation::CanonicalJournal};
use pc_runtime_types::{
    Digest, PurposeSigner, RuntimeError, RuntimeResult,
    target_disposition::{
        TARGET_DISPOSITION_ACK_PURPOSE, TargetDispositionAcknowledgement, TargetDispositionAction,
        TargetDispositionCause, TargetDispositionDependency, TargetDispositionIdentity,
        TargetDispositionInstalledState, TargetDispositionOrder, TargetDispositionSource,
        TargetDispositionVerifier, VerifiedTargetDispositionDelivery,
        encode_target_disposition_acknowledgement,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CURRENT_WINDOW: Duration = Duration::from_secs(5);
pub type AuthorityFuture<'a, T> = Pin<Box<dyn Future<Output = RuntimeResult<T>> + Send + 'a>>;

/// Exact internal ReadCurrent projection. It has no public operation that marks
/// a target ready: only the installed transport is consumed by reconciliation.
pub struct CurrentTargetDisposition {
    pub challenge: Vec<u8>,
    pub established: bool,
    pub revision: u64,
    pub admission_digest: String,
    pub signed_delivery: Vec<u8>,
    pub signed_acknowledgement: Vec<u8>,
}

/// Expired original confirmation custody. Deliberately not a current-read type.
pub struct HistoricalTargetConfirmation {
    pub challenge: Vec<u8>,
    pub revision: u64,
    pub admission_digest: String,
    pub signed_delivery: Vec<u8>,
    pub signed_acknowledgement: Vec<u8>,
}

/// Shared journal input contains no currentness or lifetime authority. Only the
/// successful two-read current path may set the separate monotonic deadline.
struct DispositionCustody<'a> {
    revision: u64,
    admission_digest: &'a str,
    signed_delivery: &'a [u8],
    signed_acknowledgement: &'a [u8],
}
impl CurrentTargetDisposition {
    fn custody(&self) -> RuntimeResult<DispositionCustody<'_>> {
        if !self.established {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        Ok(DispositionCustody {
            revision: self.revision,
            admission_digest: &self.admission_digest,
            signed_delivery: &self.signed_delivery,
            signed_acknowledgement: &self.signed_acknowledgement,
        })
    }
}
impl HistoricalTargetConfirmation {
    fn custody(&self) -> DispositionCustody<'_> {
        DispositionCustody {
            revision: self.revision,
            admission_digest: &self.admission_digest,
            signed_delivery: &self.signed_delivery,
            signed_acknowledgement: &self.signed_acknowledgement,
        }
    }
}

/// Trusted host composition, like ArtifactAdmission. Production installs the
/// concrete certificate-verifying Control client, never a request-owned callback.
/// Both operations must authenticate the server and actual target workload.
pub trait TargetDispositionAuthority: Send + Sync {
    fn read_current(&self, challenge: [u8; 32]) -> AuthorityFuture<'_, CurrentTargetDisposition>;
    fn read_original_confirmation(
        &self,
        _challenge: [u8; 32],
    ) -> AuthorityFuture<'_, HistoricalTargetConfirmation> {
        Box::pin(async { Err(RuntimeError::RuntimeUnavailable) })
    }
    fn acknowledge<'a>(
        &'a self,
        digest: &'a Digest,
        acknowledgement: &'a [u8],
    ) -> AuthorityFuture<'a, ()>;
}

pub(crate) struct DispositionOwner {
    target: TargetDispositionIdentity,
    source: TargetDispositionSource,
    verifier: TargetDispositionVerifier,
    historical_verifier: Option<TargetDispositionVerifier>,
    historical_target: Option<TargetDispositionIdentity>,
    signer: PurposeSigner,
    authority: Arc<dyn TargetDispositionAuthority>,
    reconcile: tokio::sync::Mutex<()>,
    source_reads: tokio::sync::RwLock<()>,
    currentness: Mutex<DispositionCurrentness>,
}

struct DispositionCurrentness {
    until: Option<Instant>,
    invalidation_epoch: Option<u64>,
}

impl DispositionCurrentness {
    fn invalidate(&mut self) {
        self.until = None;
        self.invalidation_epoch = self
            .invalidation_epoch
            .and_then(|epoch| epoch.checked_add(1));
    }
}

/// Coordinates source I/O with routine refreshes; it grants no serving authority.
/// Callers still validate their original generation, custody and deadline.
pub struct SourceReadPermit<'a> {
    agent: &'a RuntimeAgent,
    _guard: tokio::sync::RwLockReadGuard<'a, ()>,
    io_pending: bool,
}

/// Coordinates final response checks with routine refresh; it grants no
/// authority and does not retain any database or active-capsule lease.
pub struct ResponseReleasePermit<'a> {
    _guard: tokio::sync::RwLockReadGuard<'a, ()>,
}

impl SourceReadPermit<'_> {
    /// Arm before acquiring source database locks or starting provider work.
    pub fn begin_io(&mut self) {
        self.io_pending = true;
    }

    /// Call only after confirmed commit/rollback or completed connection teardown.
    pub fn complete_io(&mut self) {
        self.io_pending = false;
    }
}

impl Drop for SourceReadPermit<'_> {
    fn drop(&mut self) {
        if self.io_pending {
            // Deferred transaction cleanup cannot carry serving authority into
            // a refresh that may contend for those same database locks.
            let _ = self.agent.fence_target_disposition();
        }
    }
}

struct DispositionReconciliation<'a> {
    owner: &'a DispositionOwner,
    epoch: u64,
    accepted: bool,
    source_gate: Option<tokio::sync::RwLockWriteGuard<'a, ()>>,
}

impl Drop for DispositionReconciliation<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            // Fence cancellation/errors before releasing the source gate and
            // reconcile mutex. Independent fencing never waits for this gate.
            if let Ok(mut currentness) = self.owner.currentness.lock() {
                currentness.invalidate();
            }
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalDisposition {
    sequence: u64,
    observed: Option<ObservedHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_observed: Option<ObservedHead>,
    installed: Option<InstalledDisposition>,
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservedHead {
    revision: u64,
    admission_digest: Digest,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstalledDisposition {
    source: TargetDispositionSource,
    signed_delivery: Vec<u8>,
    signed_acknowledgement: Vec<u8>,
}

impl DispositionOwner {
    fn validate_credential_adoption(
        &self,
        previous: Option<&VerifiedTargetDispositionDelivery>,
        delivery: &VerifiedTargetDispositionDelivery,
    ) -> RuntimeResult<()> {
        if let Some(previous) = previous
            && previous.claims().target != self.target
        {
            if self.historical_target.as_ref() != Some(&previous.claims().target)
                || delivery.claims().action != TargetDispositionAction::Withdraw
            {
                return Err(RuntimeError::TargetIdentity);
            }
            let admitted = match &delivery.claims().cause {
                TargetDispositionCause::Dependency {
                    owner: TargetDispositionDependency::Platform,
                    ..
                } => delivery.claims().source == previous.claims().source,
                TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
                    abandoned_target,
                    ..
                } => {
                    abandoned_target == &previous.claims().target
                        && delivery.compare_previous(Some(previous)).is_ok()
                }
                _ => false,
            };
            if !admitted {
                return Err(RuntimeError::TargetIdentity);
            }
        }
        Ok(())
    }

    /// Historical journal custody only. An incoming delivery still needs the
    /// distinct credential-denial cause, current verifier and original receipt.
    fn is_expired_effect_predecessor(&self, delivery: &VerifiedTargetDispositionDelivery) -> bool {
        let previous = delivery.claims();
        self.historical_target.as_ref() == Some(&previous.target)
            && previous.action == TargetDispositionAction::Withdraw
            && previous.source.original_work_id != self.source.original_work_id
            && self.source.predecessor_capsule_digest.as_ref()
                == Some(&previous.source.capsule_digest)
            && previous.cause
                == (TargetDispositionCause::Activation {
                    work_id: self.source.original_work_id.clone(),
                    operation_id: self.source.original_operation_id.clone(),
                    execution_attempt_id: None,
                })
    }

    fn installed(
        &self,
        state: &JournalDisposition,
    ) -> RuntimeResult<Option<VerifiedTargetDispositionDelivery>> {
        let Some(installed) = &state.installed else {
            if state.sequence != 0 {
                return Err(RuntimeError::GenerationMismatch);
            }
            return Ok(None);
        };
        // Only this private retained-journal reader may use the authenticated
        // predecessor. Network deliveries always use the strict current verifier.
        let (delivery, verifier) = match self
            .verifier
            .verify_delivery(&installed.signed_delivery, &installed.source)
        {
            Ok(delivery) => (delivery, &self.verifier),
            Err(_) => {
                let verifier = self
                    .historical_verifier
                    .as_ref()
                    .ok_or(RuntimeError::TargetIdentity)?;
                let delivery =
                    verifier.verify_delivery(&installed.signed_delivery, &installed.source)?;
                if installed.source != self.source && !self.is_expired_effect_predecessor(&delivery)
                {
                    return Err(RuntimeError::TargetIdentity);
                }
                (delivery, verifier)
            }
        };
        let ack = verifier.verify_acknowledgement(&installed.signed_acknowledgement, &delivery)?;
        if installed.source != self.source
            && delivery.claims().target != self.target
            && ack.claims().installed_state != TargetDispositionInstalledState::NewUseDenied
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let observed = state
            .observed
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if ack.claims().journal_sequence != state.sequence
            || observed.revision < delivery.claims().revision
            || (observed.revision == delivery.claims().revision
                && observed.admission_digest != delivery.claims().committed_admission_digest)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(Some(delivery))
    }
}

impl RuntimeAgent {
    /// Install actual host trust and authenticated transport before listeners.
    /// The original source is resolved by the signed bootstrap owner; it is not
    /// copied from ReadCurrent. This never restores serving by itself.
    pub fn install_target_disposition_owner(
        &self,
        target: TargetDispositionIdentity,
        source: TargetDispositionSource,
        control_public_key: &[u8],
        acknowledgement_secret: [u8; 32],
        authority: Arc<dyn TargetDispositionAuthority>,
    ) -> RuntimeResult<()> {
        self.install_target_disposition_owner_with_credential_predecessor(
            target,
            source,
            control_public_key,
            acknowledgement_secret,
            authority,
            None,
        )
    }

    /// Trusted Fleet-signed host composition only. The predecessor supplies
    /// historical verification, never a current serving or network-ACK owner.
    #[allow(clippy::too_many_arguments)] // Existing host-key contract plus one authenticated predecessor.
    pub fn install_target_disposition_owner_with_credential_predecessor(
        &self,
        target: TargetDispositionIdentity,
        source: TargetDispositionSource,
        control_public_key: &[u8],
        acknowledgement_secret: [u8; 32],
        authority: Arc<dyn TargetDispositionAuthority>,
        credential_predecessor: Option<TargetDispositionIdentity>,
    ) -> RuntimeResult<()> {
        if target.target_id != self.target_id {
            return Err(RuntimeError::TargetIdentity);
        }
        if let Some(previous) = &credential_predecessor {
            previous.validate()?;
            if previous.participant_id != target.participant_id
                || previous.privacy_domain_id != target.privacy_domain_id
                || previous.target_id != target.target_id
                || previous.principal_id != target.principal_id
                || previous.principal_epoch != target.principal_epoch
                || previous.credential_id == target.credential_id
                || previous.certificate_digest == target.certificate_digest
                || previous.credential_epoch.checked_add(1) != Some(target.credential_epoch)
            {
                return Err(RuntimeError::TargetIdentity);
            }
        }
        source.validate()?;
        let signer = PurposeSigner::from_secret_bytes(
            TARGET_DISPOSITION_ACK_PURPOSE,
            acknowledgement_secret,
        )?;
        let owner = DispositionOwner {
            verifier: TargetDispositionVerifier::from_host_keys(
                target.clone(),
                control_public_key,
                &signer.verifier().sec1_bytes(),
            )?,
            historical_verifier: credential_predecessor
                .as_ref()
                .map(|previous| {
                    TargetDispositionVerifier::from_host_keys(
                        previous.clone(),
                        control_public_key,
                        &signer.verifier().sec1_bytes(),
                    )
                })
                .transpose()?,
            historical_target: credential_predecessor,
            target,
            source,
            signer,
            authority,
            reconcile: tokio::sync::Mutex::new(()),
            source_reads: tokio::sync::RwLock::new(()),
            currentness: Mutex::new(DispositionCurrentness {
                until: None,
                invalidation_epoch: Some(0),
            }),
        };
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if self.disposition_owner.get().is_some() {
            return Err(RuntimeError::InvalidTransition);
        }
        let mut journal = guard.state()?.clone();
        let state = journal
            .canonical
            .as_mut()
            .ok_or(RuntimeError::GenerationMismatch)?;
        self.match_disposition_source(state, &owner.source)?;
        if let Some(disposition) = &state.target_disposition {
            let installed = owner.installed(disposition)?;
            if installed
                .as_ref()
                .is_some_and(|delivery| delivery.claims().target != owner.target)
            {
                // Authenticate the predecessor with the pinned original keys
                // first, then preserve its journal before any new observation.
                guard.retain_committed_snapshot()?;
            }
        } else {
            state.target_disposition = Some(JournalDisposition::default());
            guard.commit(journal)?;
        }
        self.disposition_owner
            .set(owner)
            .map_err(|_| RuntimeError::InvalidTransition)
    }

    fn match_disposition_source(
        &self,
        state: &CanonicalJournal,
        source: &TargetDispositionSource,
    ) -> RuntimeResult<()> {
        let owner = self.wire()?;
        let active = state
            .active
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let capsule = owner.validate(&active.custody)?;
        let token = owner.verifier.verify_activation_token(
            active
                .activation_token
                .as_deref()
                .ok_or(RuntimeError::InvalidAuthorization)?,
        )?;
        if capsule.capsule_id != source.runtime_configuration_generation_id
            || capsule.digest()? != source.capsule_digest
            || capsule.previous_capsule_digest != source.predecessor_capsule_digest
            || token.desired_generation_digest != source.capsule_digest
            || token.xds_version_digest != source.xds_version_digest
            || token.expected_previous_generation_digest != source.predecessor_capsule_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }

    /// Invoked under the same journal guard as activation and request admission.
    /// A persisted disposition cannot be bypassed by reopening without its owner.
    pub(crate) fn require_disposition_current(
        &self,
        state: &CanonicalJournal,
    ) -> RuntimeResult<Option<Instant>> {
        let Some(disposition) = &state.target_disposition else {
            // Component/first-activation custody has no current serving grant.
            // Deployed listeners always install the owner before they start.
            return if self.disposition_owner.get().is_none() {
                Ok(None)
            } else {
                Err(RuntimeError::RuntimeUnavailable)
            };
        };
        let owner = self
            .disposition_owner
            .get()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let currentness = owner
            .currentness
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if !currentness
            .until
            .is_some_and(|deadline| Instant::now() < deadline)
        {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let installed = owner
            .installed(disposition)?
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        if !matches!(
            installed.claims().action,
            TargetDispositionAction::Restore | TargetDispositionAction::ConfirmActivation
        ) || installed.claims().target != owner.target
            || installed.claims().source != owner.source
            || disposition.observed.as_ref().map(|head| head.revision)
                != Some(installed.claims().revision)
        {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        self.match_disposition_source(state, &owner.source)?;
        Ok(currentness.until)
    }

    pub fn require_current_target_disposition(&self) -> RuntimeResult<()> {
        if self.disposition_owner.get().is_none() {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        self.require_disposition_current(
            guard
                .state()?
                .canonical
                .as_ref()
                .ok_or(RuntimeError::GenerationMismatch)?,
        )
        .map(|_| ())
    }

    /// Local transport/bootstrap failure can only remove admission, never grant
    /// it or acknowledge a disposition. Serialize with already admitted work.
    pub fn fence_target_disposition(&self) -> RuntimeResult<()> {
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        guard.state()?;
        self.invalidate_disposition_current()
    }

    /// Activation may consume its own one-use authority, but never carries a
    /// serving reconciliation across a generation switch. Called with journal held.
    pub(crate) fn invalidate_disposition_current(&self) -> RuntimeResult<()> {
        if let Some(owner) = self.disposition_owner.get() {
            owner
                .currentness
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .invalidate();
        }
        Ok(())
    }

    /// Acquire before capsule capture and any source database/provider I/O.
    /// The fair gate prevents new readers from starving a queued refresh.
    pub async fn coordinate_source_read(&self) -> RuntimeResult<SourceReadPermit<'_>> {
        let owner = self
            .disposition_owner
            .get()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        Ok(SourceReadPermit {
            agent: self,
            _guard: owner.source_reads.read().await,
            io_pending: false,
        })
    }

    /// Component owners without disposition custody retain their existing
    /// validation path. Deployed owners share the source/refresh gate, then
    /// revalidate the original request, generation and deadlines before release.
    pub async fn coordinate_response_release(
        &self,
        deadline_at_ms: u64,
    ) -> RuntimeResult<Option<ResponseReleasePermit<'_>>> {
        let remaining_ms = deadline_at_ms
            .checked_sub(crate::target_state::wall_clock_ns()? / 1_000_000)
            .filter(|remaining| *remaining > 0)
            .ok_or(RuntimeError::BudgetExhausted)?;
        let Some(owner) = self.disposition_owner.get() else {
            return Ok(None);
        };
        let guard = tokio::time::timeout(
            Duration::from_millis(remaining_ms),
            owner.source_reads.read(),
        )
        .await
        .map_err(|_| RuntimeError::BudgetExhausted)?;
        Ok(Some(ResponseReleasePermit { _guard: guard }))
    }

    /// Fence before network I/O, persist exact denial/delivery/original ACK in
    /// one fsynced journal replacement, then send ACK. A post-ACK fresh read must
    /// still identify those exact bytes before a RESTORE may admit new requests.
    /// Cancellation, timeout, cold restart and every failure leave serving fenced.
    pub async fn reconcile_target_disposition(&self) -> RuntimeResult<TargetDispositionAction> {
        let owner = self
            .disposition_owner
            .get()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let _reconcile = owner.reconcile.lock().await;
        let started = Instant::now();
        let epoch = owner
            .currentness
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .invalidation_epoch
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let mut attempt = DispositionReconciliation {
            owner,
            epoch,
            accepted: false,
            source_gate: None,
        };
        attempt.source_gate = Some(owner.source_reads.write().await);
        {
            let guard = self
                .journal
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            guard.state()?;
            owner
                .currentness
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .until = None;
        }
        let response = match read_current(owner).await {
            Ok(response) => response,
            Err(_) => {
                // The fallback cannot change the failed current result. It may
                // durably acknowledge only an authenticated expired original.
                if owner.historical_target.is_some() {
                    return Err(RuntimeError::RuntimeUnavailable);
                }
                self.acknowledge_expired_confirmation(owner).await?;
                return Err(RuntimeError::RuntimeUnavailable);
            }
        };
        let (action, digest, acknowledgement) =
            self.install_disposition_custody(owner, &response.custody()?)?;
        tokio::time::timeout(
            CURRENT_WINDOW,
            owner.authority.acknowledge(&digest, &acknowledgement),
        )
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)??;
        if action == TargetDispositionAction::Withdraw {
            return Ok(action);
        }
        let confirmed = read_current(owner).await?;
        self.observe_disposition_head(owner, &confirmed.custody()?)?;
        if confirmed.signed_delivery != response.signed_delivery
            || confirmed.signed_acknowledgement != acknowledgement
            || started.elapsed() >= CURRENT_WINDOW
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        self.match_disposition_source(state, &owner.source)?;
        let mut currentness = owner
            .currentness
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if currentness.invalidation_epoch != Some(attempt.epoch) {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        currentness.until = Some(started + CURRENT_WINDOW);
        attempt.accepted = true;
        Ok(action)
    }

    fn require_expired_confirmation_custody(&self, owner: &DispositionOwner) -> RuntimeResult<()> {
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        self.match_disposition_source(state, &owner.source)?;
        let active = state
            .active
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let wire = self.wire()?;
        let capsule = wire.validate(&active.custody)?;
        let receipt = wire.validate_activation(active)?;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .as_nanos(),
        )
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if now < capsule.hard_expiry_ns
            || receipt.status != 1
            || receipt.observed_at_ns < capsule.not_before_ns
            || receipt.observed_at_ns >= capsule.hard_expiry_ns
            || receipt.agent_sequence != state.sequence
            || !state.receipts.contains(&active.receipt)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    async fn acknowledge_expired_confirmation(
        &self,
        owner: &DispositionOwner,
    ) -> RuntimeResult<()> {
        self.require_expired_confirmation_custody(owner)?;
        let mut challenge = [0; 32];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let original = tokio::time::timeout(
            CURRENT_WINDOW,
            owner.authority.read_original_confirmation(challenge),
        )
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)??;
        if original.challenge != challenge {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let delivery = owner
            .verifier
            .verify_delivery(&original.signed_delivery, &owner.source)?;
        if delivery.claims().action != TargetDispositionAction::ConfirmActivation {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // Recheck after network I/O. Installation also binds the same active
        // source under the journal lock, so an intervening activation denies.
        self.require_expired_confirmation_custody(owner)?;
        let (_, digest, acknowledgement) =
            self.install_disposition_custody(owner, &original.custody())?;
        tokio::time::timeout(
            CURRENT_WINDOW,
            owner.authority.acknowledge(&digest, &acknowledgement),
        )
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)??;
        // No current read, current_until update, listener start or restore.
        Ok(())
    }

    fn observe_disposition_head(
        &self,
        owner: &DispositionOwner,
        response: &DispositionCustody<'_>,
    ) -> RuntimeResult<()> {
        if response.revision == 0 || response.revision > i64::MAX as u64 {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let head = ObservedHead {
            revision: response.revision,
            admission_digest: Digest::parse(response.admission_digest)?,
        };
        if head.admission_digest.as_str() != response.admission_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut journal = guard.state()?.clone();
        let state = journal
            .canonical
            .as_mut()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let disposition = state
            .target_disposition
            .as_mut()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let installed = owner.installed(disposition)?;
        if !response.signed_delivery.is_empty() {
            let delivery = owner
                .verifier
                .verify_delivery(response.signed_delivery, &owner.source)?;
            if delivery.claims().revision != head.revision
                || delivery.claims().committed_admission_digest != head.admission_digest
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            owner.validate_credential_adoption(installed.as_ref(), &delivery)?;
            if matches!(
                delivery.claims().cause,
                TargetDispositionCause::UnsignedWithdrawalRecovery { .. }
                    | TargetDispositionCause::ExpiredObservedDenialHandover { .. }
                    | TargetDispositionCause::ExpiredObservedCredentialDenialHandover { .. }
            ) {
                let installed = installed.as_ref().ok_or(RuntimeError::GenerationMismatch)?;
                if delivery.compare_previous(Some(installed))?
                    != TargetDispositionOrder::ExactReplay
                {
                    let observed = disposition
                        .observed
                        .as_ref()
                        .ok_or(RuntimeError::GenerationMismatch)?;
                    let floor = if observed.revision == delivery.claims().revision {
                        disposition
                            .prior_observed
                            .as_ref()
                            .ok_or(RuntimeError::GenerationMismatch)?
                    } else {
                        observed
                    };
                    delivery.check_recovery_floor(
                        installed,
                        floor.revision,
                        &floor.admission_digest,
                    )?;
                }
            }
        }
        if let Some(previous) = &disposition.observed {
            if head.revision < previous.revision
                || (head.revision == previous.revision && head != *previous)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            if head == *previous {
                return Ok(());
            }
        }
        disposition.prior_observed = disposition.observed.clone();
        disposition.observed = Some(head);
        guard.commit(journal)
    }

    fn install_disposition_custody(
        &self,
        owner: &DispositionOwner,
        response: &DispositionCustody<'_>,
    ) -> RuntimeResult<(TargetDispositionAction, Digest, Vec<u8>)> {
        self.observe_disposition_head(owner, response)?;
        let delivery = owner
            .verifier
            .verify_delivery(response.signed_delivery, &owner.source)?;
        if delivery.claims().revision != response.revision
            || delivery.claims().committed_admission_digest.as_str() != response.admission_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut journal = guard.state()?.clone();
        let state = journal
            .canonical
            .as_mut()
            .ok_or(RuntimeError::GenerationMismatch)?;
        self.match_disposition_source(state, &owner.source)?;
        expired_denial::validate_effect(self, state, &owner.source, &delivery)?;
        let disposition = state
            .target_disposition
            .as_mut()
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let previous = owner.installed(disposition)?;
        owner.validate_credential_adoption(previous.as_ref(), &delivery)?;
        let order = delivery.compare_previous(previous.as_ref())?;
        if order == TargetDispositionOrder::ExactReplay {
            let original = disposition
                .installed
                .as_ref()
                .ok_or(RuntimeError::GenerationMismatch)?;
            if !response.signed_acknowledgement.is_empty()
                && response.signed_acknowledgement != original.signed_acknowledgement
            {
                return Err(RuntimeError::Replay);
            }
            return Ok((
                delivery.claims().action,
                delivery.signed_digest().clone(),
                original.signed_acknowledgement.clone(),
            ));
        }
        // An ACK retained by Control but absent from this journal indicates a
        // restored/rolled-back local snapshot, not permission to mint a new ACK.
        if !response.signed_acknowledgement.is_empty() {
            return Err(RuntimeError::Replay);
        }
        let sequence = disposition
            .sequence
            .checked_add(1)
            .ok_or(RuntimeError::ReplayCapacity)?;
        let acknowledgement = encode_target_disposition_acknowledgement(&owner.signer.sign(
            TargetDispositionAcknowledgement {
                version: 1,
                target: owner.target.clone(),
                delivery_digest: delivery.signed_digest().clone(),
                disposition_revision: delivery.claims().revision,
                journal_sequence: sequence,
                installed_state: match delivery.claims().action {
                    TargetDispositionAction::Withdraw => {
                        TargetDispositionInstalledState::NewUseDenied
                    }
                    TargetDispositionAction::Restore => {
                        TargetDispositionInstalledState::SuspensionCleared
                    }
                    TargetDispositionAction::ConfirmActivation => {
                        TargetDispositionInstalledState::ActivationConfirmed
                    }
                },
            },
        )?)?;
        owner
            .verifier
            .verify_acknowledgement(&acknowledgement, &delivery)?;
        disposition.sequence = sequence;
        disposition.prior_observed = None;
        disposition.installed = Some(InstalledDisposition {
            source: owner.source.clone(),
            signed_delivery: response.signed_delivery.to_vec(),
            signed_acknowledgement: acknowledgement.clone(),
        });
        guard.commit(journal)?;
        Ok((
            delivery.claims().action,
            delivery.signed_digest().clone(),
            acknowledgement,
        ))
    }
}

async fn read_current(owner: &DispositionOwner) -> RuntimeResult<CurrentTargetDisposition> {
    let mut challenge = [0; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let response = tokio::time::timeout(CURRENT_WINDOW, owner.authority.read_current(challenge))
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)??;
    if response.challenge != challenge {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(response)
}

#[path = "target_disposition/expired_denial.rs"]
mod expired_denial;
pub use expired_denial::ExpiredDenialHandoverFloor;
