//! Existing worker-loop recovery of a terminal, unstarted successor. No new
//! activation or business intent is submitted, and historical outcomes remain.
use super::*;
use openpc_fleet_controller::target_disposition::{
    OriginalTargetActivation, TargetDispositionStore, TargetFactTrust,
};
use openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION;

/// One installed read-only pool shared with the existing Fleet Fact consumer.
/// Neither requests nor retained journal artifacts can replace this trust.
pub(super) struct FactCustody {
    reader: PolicyFactReader,
    verifier: FactSignatureVerifier,
}
impl FactCustody {
    pub(super) async fn connect(config: &Config) -> WorkerResult<Self> {
        let verifier = FactSignatureVerifier::from_key_identifier(
            &config.fact_verify_key_id,
            &config.fact_verify_key,
        )
        .map_err(|_| "Fleet Fact verification trust rejected")?;
        Ok(Self {
            reader: PolicyFactReader::new(config.connect_facts().await?, verifier.clone()),
            verifier,
        })
    }
    pub(super) fn reader(&self) -> &PolicyFactReader {
        &self.reader
    }
    fn trust<'a>(&'a self, config: &'a Config) -> TargetFactTrust<'a> {
        TargetFactTrust {
            fact_verifier: &self.verifier,
            installed_authority_signer_id: &config.worker_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConfirmationMode {
    OriginalObservation,
    ReconcileOriginal,
}
pub(super) const EXPIRED_OBSERVED_ACTIVATION: &str = "observed activation custody expired";

pub(super) struct HistoricalCompletionCandidate {
    work_id: String,
    execution_attempt_id: String,
    occurrence_id: String,
    capsule_digest: Digest,
    receipt_digest: Digest,
}
impl HistoricalCompletionCandidate {
    pub(super) fn new(
        work: &ClaimedWork,
        capsule: &Digest,
        receipt: &Digest,
    ) -> WorkerResult<Self> {
        if !work.reconcile_only
            || work.work_kind != "RUNTIME_ACTIVATION"
            || work.predecessor_digest.is_some()
        {
            return Err(EXPIRED_OBSERVED_ACTIVATION.into());
        }
        Ok(Self {
            work_id: work.work_id.clone(),
            execution_attempt_id: work
                .execution_attempt_id
                .clone()
                .ok_or("historical attempt missing")?,
            occurrence_id: work
                .occurrence_id
                .clone()
                .ok_or("historical occurrence missing")?,
            capsule_digest: capsule.clone(),
            receipt_digest: receipt.clone(),
        })
    }
    pub(super) async fn verify_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        config: &Config,
        plane: &RuntimePlane,
        work: &ClaimedWork,
    ) -> WorkerResult<openpc_fleet_controller::target_disposition::VerifiedHistoricalActivation>
    {
        if self.work_id != work.work_id
            || work.execution_attempt_id.as_deref() != Some(self.execution_attempt_id.as_str())
            || work.occurrence_id.as_deref() != Some(self.occurrence_id.as_str())
        {
            return Err("historical completion original claim changed".into());
        }
        let target = work
            .target_id
            .as_deref()
            .ok_or("historical target missing")?;
        let retained = retained_target::read_installed(config, target)
            .map_err(|_| "historical original journal unavailable")?;
        let peer = plane.target_identity(target)?;
        plane
            .disposition
            .as_ref()
            .ok_or("historical disposition owner missing")?
            .verify_original_activation_completion_in(
                tx,
                original(&peer, &retained),
                openpc_fleet_controller::target_disposition::HistoricalActivationCandidate {
                    work_id: &work.work_id,
                    operation_id: &work.operation_id,
                    execution_attempt_id: &self.execution_attempt_id,
                    occurrence_id: &self.occurrence_id,
                    generation_id: work
                        .generation_id
                        .as_deref()
                        .ok_or("historical generation missing")?,
                    generation_digest: work
                        .generation_digest
                        .as_ref()
                        .ok_or("historical generation digest missing")?,
                    configuration_digest: &work.configuration_digest,
                    xds_version_digest: work
                        .xds_version_digest
                        .as_ref()
                        .ok_or("historical xds missing")?,
                    capsule_digest: &self.capsule_digest,
                    receipt_digest: &self.receipt_digest,
                    claim: openpc_fleet_controller::target_disposition::HistoricalCompletionClaim::Leased {
                        owner: &config.worker_id,
                        count: work.attempt_count,
                    },
                },
            )
            .await
    }
}

fn historical_observation_expired(
    not_before_ns: u64,
    expires_at_ns: u64,
    observed_at_ns: u64,
    now_ns: u64,
) -> WorkerResult<bool> {
    if observed_at_ns < not_before_ns || observed_at_ns >= expires_at_ns {
        return Err("observed activation outside original custody".into());
    }
    Ok(expires_at_ns <= now_ns)
}

/// Classify only an exact, signed journal/observation pair. This grants no
/// confirmation and never substitutes a new capsule for the observed effect.
pub(super) fn expired_observed(
    config: &Config,
    target: &str,
    capsule: &Digest,
    signed_receipt: &[u8],
    observed_at_ns: u64,
) -> WorkerResult<Option<u64>> {
    let original = retained_target::read_installed(config, target)
        .map_err(|_| "target confirmation custody unavailable")?;
    if original.manifest.capsule_digest != *capsule || original.activation_receipt != signed_receipt
    {
        return Err("observed activation journal mismatch".into());
    }
    let now_ns = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "activation clock unavailable")?
            .as_nanos(),
    )
    .map_err(|_| "activation clock unavailable")?;
    historical_observation_expired(
        original.capsule.not_before_ns,
        original.capsule.hard_expiry_ns,
        observed_at_ns,
        now_ns,
    )
    .map(|expired| expired.then_some(original.capsule.hard_expiry_ns))
}
fn fact_bound(capsule: &RuntimeCapsule) -> bool {
    capsule.policy_fact_state_digest != Digest::of(NO_FACT_PUBLICATION)
}
fn original<'a>(
    peer: &'a TargetIdentity,
    retained: &'a retained_target::RetainedTarget,
) -> OriginalTargetActivation<'a> {
    OriginalTargetActivation {
        peer,
        capsule: &retained.capsule,
        signed_token: &retained.activation_token,
        signed_receipt: &retained.activation_receipt,
        artifacts: &retained.artifacts,
    }
}

async fn confirm(
    config: &Config,
    store: &TargetDispositionStore,
    facts: &FactCustody,
    original: OriginalTargetActivation<'_>,
    mode: ConfirmationMode,
) -> WorkerResult<bool> {
    if fact_bound(original.capsule) {
        if mode == ConfirmationMode::ReconcileOriginal {
            return store
                .lookup_fact_activation_confirmation(original, facts.reader(), facts.trust(config))
                .await;
        }
        store
            .publish_fact_activation_confirmation(original, facts.reader(), facts.trust(config))
            .await
    } else {
        store
            .publish_activation_confirmation(
                original.peer,
                original.capsule,
                original.signed_token,
                original.signed_receipt,
                original.artifacts,
                &config.worker_id,
            )
            .await
    }
}

#[derive(Default)]
pub(super) struct Recovery {
    next: Option<tokio::time::Instant>,
    deferred: bool,
}
impl Recovery {
    pub(super) async fn tick(&mut self, pool: &PgPool, config: &Config, plane: &RuntimePlane) {
        let now = tokio::time::Instant::now();
        if self.next.is_some_and(|next| now < next) {
            return;
        }
        self.next = Some(now + Duration::from_secs(2));
        let unavailable = reconcile(pool, config, plane).await.is_err();
        if unavailable && !self.deferred {
            eprintln!(
                r#"{{"level":"warn","event":"target_disposition_restore_deferred","reason":"current_source_or_original_custody_unavailable"}}"#
            );
        }
        self.deferred = unavailable;
    }
}

async fn reconcile(pool: &PgPool, config: &Config, plane: &RuntimePlane) -> WorkerResult<()> {
    let Some(store) = &plane.disposition else {
        return Ok(());
    };
    let pem = match fs::read(&plane.config.target_client_certificate) {
        Ok(pem) => pem,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("target restoration identity unavailable".into()),
    };
    let peer = runtime_tls::target_identity_from_pem(&pem)
        .map_err(|_| "target restoration identity rejected")?;
    let Some(cause) = store.unstarted_restore_cause(&peer).await? else {
        return Ok(());
    };
    let original = retained_target::read_installed(config, &peer.target_id)
        .map_err(|_| "target restoration custody rejected")?;
    let acknowledged = if fact_bound(&original.capsule) {
        store
            .lookup_fact_unstarted_restore(
                self::original(&peer, &original),
                plane.facts.reader(),
                plane.facts.trust(config),
            )
            .await?
    } else {
        store
            .publish_unstarted_restore(
                &peer,
                &original.capsule,
                &original.activation_token,
                &original.activation_receipt,
                &original.artifacts,
                &config.worker_id,
            )
            .await?
    };
    if !acknowledged {
        return Ok(());
    }
    // Clearing this signed local hint grants no serving capability. The target
    // must independently obtain fresh Control currentness and verify exact ACK.
    let mut manifest = prior_target_manifest(
        config,
        &peer.target_id,
        Some(&original.manifest.capsule_digest),
    )?
    .ok_or("target restoration bootstrap unavailable")?;
    match manifest.suspended_for_work.as_deref() {
        None => Ok(()),
        Some(work) if work == cause => {
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| "target restore source transaction unavailable")?;
            set_context(&mut tx, config).await?;
            match &manifest.target_disposition {
                Some(binding) => {
                    plane
                        .source_custody
                        .record_consumer_use(
                            &mut tx,
                            openpc_fleet_controller::runtime_artifact_source::SourceConsumerUse {
                                configuration_digest: binding.source.configuration_digest.clone(),
                                consumer_id: "disposition-bootstrap-restore".into(),
                                boundary: Some(openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::DispositionBootstrapRestore),
                                target_id: Some(peer.target_id.clone()),
                                original_id: binding.source.original_work_id.clone(),
                            },
                        )
                        .await
                }
                None => plane.source_custody.require_legacy_consumer(&mut tx).await,
            }
            .map_err(|_| "target restore source custody unavailable")?;
            manifest.suspended_for_work = None;
            write_target_bootstrap(
                &Path::new("/runtime/target-bootstrap").join(&peer.target_id),
                manifest,
                config.fleet_key,
            )
        }
        Some(_) => Err("target restoration suspension changed".into()),
    }
}

/// Only the worker which just committed a new terminal unstarted failure may
/// request first issue. Periodic/restart recovery above is lookup-only. This
/// selector grants no authority: native SQL revalidates the exact cause and
/// durably burns issuance before signing under reacquired Control/Fact fences.
pub(super) async fn newly_failed(config: &Config, plane: &RuntimePlane, work: &ClaimedWork) {
    let result = async {
        let target = work
            .target_id
            .as_deref()
            .ok_or("failed target unavailable")?;
        let peer = plane.target_identity(target)?;
        let store = plane
            .disposition
            .as_ref()
            .ok_or("target disposition installation unavailable")?;
        if store.unstarted_restore_cause(&peer).await?.as_deref() != Some(work.work_id.as_str()) {
            return Err("original unstarted failure changed".into());
        }
        let retained = retained_target::read_installed(config, target)
            .map_err(|_| "target restoration custody rejected")?;
        if fact_bound(&retained.capsule) {
            store
                .publish_fact_unstarted_restore(
                    original(&peer, &retained),
                    plane.facts.reader(),
                    plane.facts.trust(config),
                )
                .await?;
        }
        Ok::<(), String>(())
    }
    .await;
    if result.is_err() {
        eprintln!(
            r#"{{"level":"warn","event":"target_disposition_restore_deferred","reason":"original_first_issue_unavailable"}}"#
        );
    }
}

/// Join the real observation to original native custody before the target can
/// report convergence. Repeated calls reconcile one committed confirmation.
pub(super) async fn confirm_observed(
    config: &Config,
    plane: &RuntimePlane,
    target: &str,
    capsule: &Digest,
    mode: ConfirmationMode,
) -> WorkerResult<()> {
    let original = retained_target::read_installed(config, target)
        .map_err(|_| "target confirmation custody unavailable")?;
    if original.manifest.capsule_digest != *capsule {
        return Err("target confirmation capsule changed".into());
    }
    let store = plane
        .disposition
        .as_ref()
        .ok_or("target disposition installation unavailable")?;
    let peer = plane.target_identity(target)?;
    confirm(
        config,
        store,
        &plane.facts,
        self::original(&peer, &original),
        mode,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod expiry_tests {
    use super::historical_observation_expired;

    #[test]
    fn observed_effect_expires_only_after_a_valid_historical_receipt() {
        assert!(historical_observation_expired(10, 100, 99, 100).unwrap());
        assert!(!historical_observation_expired(10, 100, 99, 99).unwrap());
        assert!(historical_observation_expired(10, 100, 9, 100).is_err());
        assert!(historical_observation_expired(10, 100, 100, 100).is_err());
    }
}
