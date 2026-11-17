//! Holds the current source fences through the existing signed target effect.
use super::*;
use openpc_fleet_controller::cigl_publication::profile_activation::{
    VerifiedProfileActivation, prepare_activation,
};
use sqlx::{Postgres, Transaction};

/// Classify authenticated original custody, never current serving authority.
/// The caller verifies signatures and retained bytes before using this result.
fn recovered_activation_expired(
    work: &ClaimedWork,
    capsule: &RuntimeCapsule,
    token: &openpc_runtime_agent::RuntimeActivationToken,
    receipt: &openpc_runtime_agent::TargetActivationReceipt,
    capsule_digest: &Digest,
    now_ns: u64,
) -> WorkerResult<bool> {
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    if work.generation_id.as_deref() != Some(&capsule.capsule_id)
        || capsule.target_runtime_id != target
        || capsule
            .digest()
            .map_err(|_| "CIGL recovered capsule rejected")?
            != *capsule_digest
        || capsule.previous_capsule_digest != work.predecessor_digest
        || capsule.policy_bundle_digest != work.policy()?.generation_digest
        || capsule.not_before_ns > now_ns
        || token.target_runtime_id != target
        || token.occurrence_id != work.occurrence_id.as_deref().unwrap_or(&work.work_id)
        || token.desired_generation_digest != *capsule_digest
        || Some(&token.xds_version_digest) != work.xds_version_digest.as_ref()
        || token.expected_previous_generation_digest != work.predecessor_digest
        || receipt.target_runtime_id != target
        || receipt.capsule_digest != *capsule_digest
        || receipt.contract_set_manifest_digest != capsule.contract_set_manifest_digest
        || receipt.complete_component_set_digest != capsule.complete_component_set_digest
        || receipt.status != 1
        || receipt.reason_code != "ACTIVE_LOCAL"
        || receipt.signer_id != "openpc-local-agent-signer"
        || receipt.observed_at_ns < capsule.not_before_ns
        || receipt.observed_at_ns >= capsule.hard_expiry_ns
        || receipt.observed_at_ns < token.issued_at_ns
        || receipt.observed_at_ns >= token.expires_at_ns
        || receipt.observed_at_ns > now_ns
    {
        return Err("CIGL reconciliation generation rejected".into());
    }
    Ok(now_ns >= capsule.hard_expiry_ns)
}

pub(super) async fn restore_unstarted(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
) -> WorkerResult<()> {
    use openpc_fleet_controller::cigl_publication::profile_invalidation::lock_sources;
    if work.work_kind != "RUNTIME_ACTIVATION" {
        return Ok(());
    }
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    let directory = Path::new("/runtime/target-bootstrap").join(target);
    if !directory.join("bootstrap.json").exists() {
        return Ok(());
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "CIGL handoff recovery unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(&work.participant_id).bind(&work.privacy_domain_id).execute(&mut *tx).await
        .map_err(|_| "CIGL handoff recovery scope rejected")?;
    lock_sources(&mut tx)
        .await
        .map_err(|_| "CIGL handoff recovery fence rejected")?;
    let unstarted: Option<bool> = sqlx::query_scalar("select execution_started_at is null from control.configuration_work where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 for update")
        .bind(&work.work_id).bind(&config.worker_id).fetch_optional(&mut *tx).await
        .map_err(|_| "CIGL handoff recovery work rejected")?;
    if unstarted != Some(true) {
        return Ok(());
    }
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .map_err(|_| "CIGL handoff recovery trust rejected")?
        .verifier()
        .sec1_bytes();
    let manifest = read_target_bootstrap(&directory, &public)?;
    if manifest.suspended_for_work.as_deref() != Some(&work.work_id) {
        return Ok(());
    }
    if manifest.participant_id != work.participant_id
        || manifest.privacy_domain_id != work.privacy_domain_id
        || manifest.target_runtime_id != target
        || manifest.authority_signer_id != config.worker_id
        || Some(&manifest.capsule_digest) != work.predecessor_digest.as_ref()
    {
        return Err("CIGL handoff recovery predecessor rejected".into());
    }
    // No execution began, but that is not authority to restore a predecessor.
    // Keep the signed suspension until disposition delivery/antirollback exists.
    eprintln!(
        r#"{{"level":"warn","event":"retained_target_restore_blocked","boundary":"bootstrap_disposition_unavailable"}}"#
    );
    tx.rollback()
        .await
        .map_err(|_| "CIGL handoff recovery release failed".into())
}

pub(super) async fn wait_for_observation(
    config: &Config,
    target: &str,
    capsule: &Digest,
    generation: u64,
    sequence: u64,
    activated_at_ns: u64,
    expires_at_ns: u64,
) -> WorkerResult<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let public = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .map_err(|_| "canonical agent signer unavailable")?
        .verifier()
        .public_key_bytes();
    loop {
        let now_ns = now_ms()?.saturating_mul(1_000_000);
        if now_ns >= expires_at_ns {
            return Err("target observed capsule expired".into());
        }
        if let Some(observation) = openpc_fleet_controller::runtime_target_observation::read(
            &Path::new("/runtime/target-bootstrap").join(target),
            &public,
            target,
            "openpc-local-agent-signer",
            capsule,
            generation,
            now_ns,
        )
        .map_err(|_| "target request observation rejected")?
        {
            if observation.agent_sequence != sequence
                || observation.acknowledged_at_ns < activated_at_ns
            {
                return Err("target request observation identity rejected".into());
            }
            return Ok(observation.acknowledged_at_ns / 1_000_000);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("target request observation pending".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) async fn reconcile_observed(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
    plane: &RuntimePlane,
    capsule_digest: &Digest,
    signed_receipt: &[u8],
) -> WorkerResult<()> {
    use openpc_fleet_controller::cigl_publication::profile_invalidation::{
        generation_is_invalidated, lock_sources,
    };
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    let generation_id = work
        .generation_id
        .as_deref()
        .ok_or("CIGL generation unavailable")?;
    let mut lease = pool
        .begin()
        .await
        .map_err(|_| "CIGL reconciliation lease unavailable")?;
    set_context(&mut lease, config).await?;
    let renewed = sqlx::query("update control.configuration_work set lease_until=clock_timestamp()+interval '90 seconds',updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 and lease_until>clock_timestamp() and execution_attempt_id=$3::text::uuid")
        .bind(&work.work_id).bind(&config.worker_id).bind(&work.execution_attempt_id)
        .execute(&mut *lease).await.map_err(|_| "CIGL reconciliation lease rejected")?.rows_affected();
    if renewed != 1 {
        return Err("CIGL reconciliation lease rejected".into());
    }
    lease
        .commit()
        .await
        .map_err(|_| "CIGL reconciliation lease commit failed")?;
    let (capsule, activation_token, activation_receipt) = if source_activation::is_source_only(work)
    {
        let sources = retained_target::read(config, work)
            .map_err(|_| "source reconciliation custody rejected")?
            .ok_or("source reconciliation effect unavailable")?;
        (
            sources.capsule,
            sources.activation_token,
            sources.activation_receipt,
        )
    } else {
        let sources = cigl_profile::load_installed_sources(config, target, capsule_digest)
            .map_err(|_| "CIGL reconciliation custody rejected")?;
        let capsule = sources.borrowed().capsule.clone();
        let (token, receipt) = sources.activation_proof();
        (capsule, token, receipt)
    };
    let now_ns = now_ms()?.saturating_mul(1_000_000);
    let token = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "CIGL reconciliation control trust rejected")?
        .verifier()
        .verify_activation_token(&activation_token)
        .map_err(|_| "CIGL reconciliation token rejected")?;
    let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .map_err(|_| "CIGL reconciliation trust rejected")?
        .verifier()
        .verify_receipt(signed_receipt)
        .map_err(|_| "CIGL reconciliation receipt rejected")?;
    if activation_receipt != signed_receipt {
        return Err("CIGL reconciliation generation rejected".into());
    }
    // A signed receipt and retained journal prove the effect at its historical
    // observation time. After expiry the target is already fail-closed, but
    // recovery must still settle durable control state so a successor can use
    // the observed capsule as its predecessor.
    if recovered_activation_expired(work, &capsule, &token, &receipt, capsule_digest, now_ns)? {
        return Ok(());
    }
    // Expired custody settles only the original effect above. Still-live
    // recovery must obtain current confirmation before restoring transport.
    disposition_restore::confirm_observed(
        config,
        plane,
        target,
        capsule_digest,
        disposition_restore::ConfirmationMode::ReconcileOriginal,
    )
    .await?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "CIGL reconciliation fence unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(&work.participant_id).bind(&work.privacy_domain_id).execute(&mut *tx).await
        .map_err(|_| "CIGL reconciliation scope rejected")?;
    // This branch may restore transport, so it needs fresh admission. A denied,
    // busy or unavailable gate suppresses serving, never the verified original
    // result above. No token is sent again and no new effect identity is made.
    if require_work_configuration(work, config).is_err()
        || !matches!(
            runtime_artifact_new_use_allowed(
                &mut tx,
                &work.participant_id,
                &work.privacy_domain_id,
                &work.configuration_digest,
            )
            .await,
            Ok(true)
        )
    {
        eprintln!(
            r#"{{"level":"warn","event":"retained_target_restore_blocked","boundary":"runtime_artifact_admission"}}"#
        );
        return Ok(());
    }
    lock_sources(&mut tx)
        .await
        .map_err(|_| "CIGL reconciliation source fence unavailable")?;
    plane
        .source_custody
        .record_consumer_use(
            &mut tx,
            openpc_fleet_controller::runtime_artifact_source::SourceConsumerUse {
                configuration_digest: work.configuration_digest.clone(),
                consumer_id: "cigl-reconciliation".into(),
                boundary: Some(openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::CiglReconciliation),
                target_id: work.target_id.clone(),
                original_id: work.work_id.clone(),
            },
        )
        .await
        .map_err(|_| "CIGL reconciliation source custody unavailable")?;
    if generation_is_invalidated(&mut tx, target, generation_id, capsule_digest)
        .await
        .map_err(|_| "CIGL reconciliation effect rejected")?
        || !retained_target::serving_bootstrap_available(config, work, capsule_digest)?
    {
        return Ok(());
    }
    let identity = plane.target_identity(target)?;
    let xds = work
        .xds_version_digest
        .as_ref()
        .ok_or("CIGL xDS generation unavailable")?;
    let mut state = plane
        .fleet
        .state(target)
        .map_err(|_| "CIGL Fleet state unavailable")?;
    if matches!(
        state,
        TargetState::Discovered | TargetState::ActiveMismatch | TargetState::Failed
    ) {
        plane
            .fleet
            .command_generation(pc_runtime_types::DesiredGeneration {
                occurrence_id: work
                    .occurrence_id
                    .clone()
                    .unwrap_or_else(|| work.work_id.clone()),
                target_id: target.into(),
                capsule_digest: capsule_digest.clone(),
                xds_snapshot_digest: xds.clone(),
                expected_previous_generation_digest: work.predecessor_digest.clone(),
                expires_at_ms: capsule.hard_expiry_ns / 1_000_000,
            })
            .map_err(|_| "CIGL reconciliation desired generation rejected")?;
        state = TargetState::Staging;
    }
    if state == TargetState::Staging {
        plane
            .fleet
            .accept_prepared(target, capsule_digest)
            .map_err(|_| "CIGL reconciliation custody observation rejected")?;
        state = TargetState::Prepared;
    }
    if state == TargetState::Prepared {
        let provider = work
            .provider_receipt
            .as_ref()
            .ok_or("qualified provider receipt unavailable")?;
        let qualified = qualify_provider_profile(
            &receipt_bytes(provider, "artifactCbor")?,
            provider
                .get("artifactDigest")
                .and_then(Value::as_str)
                .ok_or("qualified provider digest unavailable")?,
        )
        .map_err(|_| "qualified provider replay rejected")?;
        let resources = openpc_fleet_controller::envoy_resources::protected_resources(
            ProtectedListenerConfig {
                target_id: target,
                capsule_id: &capsule.capsule_id,
                capsule_generation: capsule.generation,
                request_timeout_ms: qualified.timeout_budget_millis,
                bind_address: &plane.config.protected_bind,
                port: plane.config.protected_port,
                pds_socket: &plane.config.pds_socket,
                broker_socket: &plane.config.broker_socket,
                certificate_file: &plane.config.protected_certificate,
                private_key_file: &plane.config.protected_key,
                workload_ca_file: &plane.config.workload_ca,
            },
        )
        .map_err(|_| "CIGL reconciliation protected resources rejected")?;
        plane
            .ads
            .publish_version(target, resources, xds.clone())
            .map_err(|_| "CIGL reconciliation ADS publication rejected")?;
        state = TargetState::XdsPending;
    }
    if state == TargetState::XdsPending {
        plane.wait_for_ack(target).await?;
    }
    plane
        .fleet
        .replay_canonical_activation(&identity, signed_receipt, &activation_token)
        .map_err(|_| "CIGL reconciliation activation proof rejected")?;
    let observed = wait_for_observation(
        config,
        target,
        capsule_digest,
        capsule.generation,
        receipt.agent_sequence,
        receipt.observed_at_ns,
        capsule.hard_expiry_ns,
    )
    .await?;
    plane
        .fleet
        .observe_request_generation(&identity, capsule_digest.clone())
        .map_err(|_| "CIGL reconciliation request observation rejected")?;
    plane
        .fleet
        .heartbeat(&identity, capsule_digest.clone(), observed)
        .map_err(|_| "CIGL reconciliation heartbeat rejected")?;
    if plane
        .fleet
        .derive_state(target, observed)
        .map_err(|_| "CIGL reconciliation convergence rejected")?
        != TargetState::ActiveMatched
    {
        return Err("CIGL reconciliation convergence rejected".into());
    }
    tx.commit()
        .await
        .map_err(|_| "CIGL reconciliation source release failed".into())
}

pub(super) struct PreparedActivation {
    pub(super) sources: VerifiedProfileActivation,
    fence: Transaction<'static, Postgres>,
}
impl PreparedActivation {
    /// Local process handoff only after the immutable approved source join.
    /// Source fences remain held until actual observation is durable.
    pub(super) async fn suspend(
        &self,
        pool: &PgPool,
        config: &Config,
        work: &ClaimedWork,
        source: &openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
    ) -> WorkerResult<TargetBootstrapManifest> {
        let predecessor = work
            .predecessor_digest
            .as_ref()
            .ok_or("CIGL predecessor unavailable")?;
        self.sources
            .require_work(
                &work.work_id,
                work.generation_digest
                    .as_ref()
                    .ok_or("CIGL generation unavailable")?,
                predecessor,
            )
            .map_err(|_| "CIGL activation identity rejected")?;
        super::retained_target::suspend_current(pool, config, work, source)
            .await?
            .ok_or_else(|| "CIGL handoff predecessor unavailable".into())
    }

    pub(super) async fn release(self) -> WorkerResult<()> {
        self.fence
            .commit()
            .await
            .map_err(|_| "CIGL source fence release failed".into())
    }
}

pub(super) async fn prepare(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
) -> WorkerResult<Option<PreparedActivation>> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "CIGL activation source transaction unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(&work.participant_id).bind(&work.privacy_domain_id).execute(&mut *tx).await
        .map_err(|_| "CIGL activation source scope rejected")?;
    // Do not retain a work-row lock: the durable STARTED owner must commit its
    // own transaction before target contact. It checks the same live lease.
    let profiled: bool = sqlx::query_scalar(r#"select generation.cigl_profile_selection is not null
      from control.configuration_work work join control.runtime_configuration_generation generation
       on generation.runtime_configuration_generation_id=work.runtime_configuration_generation_id
        and generation.participant_id=work.participant_id and generation.privacy_domain_id=work.privacy_domain_id
      where work.configuration_work_id=$1::text::uuid and work.work_kind='RUNTIME_ACTIVATION'
       and work.state='LEASED' and work.lease_owner=$2 and work.lease_until>clock_timestamp()"#)
        .bind(&work.work_id).bind(&config.worker_id).fetch_one(&mut *tx).await
        .map_err(|_| "CIGL activation lease rejected")?;
    if !profiled {
        tx.rollback()
            .await
            .map_err(|_| "CIGL source transaction release failed")?;
        return Ok(None);
    }
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    let predecessor = work
        .predecessor_digest
        .as_ref()
        .ok_or("CIGL predecessor unavailable")?;
    let generation = work
        .generation_digest
        .as_ref()
        .ok_or("CIGL generation unavailable")?;
    let installed = cigl_profile::load_installed_sources(config, target, predecessor)
        .map_err(|_| "CIGL installed sources rejected")?;
    let key = PurposeSigner::from_secret_bytes(
        pc_policy_core::cigl::profile::publication::PURPOSE,
        config.fleet_key,
    )
    .map_err(|_| "CIGL compilation trust rejected")?
    .verifier()
    .sec1_bytes();
    let sources = prepare_activation(&mut tx, &installed.borrowed(), &key, &work.work_id)
        .await
        .map_err(|_| "CIGL approved activation sources rejected")?;
    sources
        .require_work(&work.work_id, generation, predecessor)
        .map_err(|_| "CIGL activation identity rejected")?;
    Ok(Some(PreparedActivation { sources, fence: tx }))
}

#[cfg(test)]
mod recovery_lifetime_tests {
    use super::*;
    use openpc_runtime_agent::{RuntimeActivationToken, TargetActivationReceipt};
    use serde_json::json;

    #[test]
    fn expired_original_requires_valid_effect_custody_and_live_original_still_requires_confirmation()
     {
        let mut work = super::super::tests::work();
        let digest = work.policy().unwrap().generation_digest.clone();
        let mut value = json!({
            "capsule_id":work.generation_id,"lifecycle_mode":1,"target_runtime_id":work.target_id,
            "fleet_id":"fixture-fleet","generation":1,"previous_capsule_digest":null,
            "emergency_deny_generation":0,"issued_at_ns":0,"not_before_ns":50,
            "hard_expiry_ns":1000,"signer_id":"fixture-control",
            "artifact_components":[{"component_id":"fixture.component","component_type":"fixture",
            "content_digest":digest,"semantic_digest":digest,"schema_id":1,"schema_version":1,"size_bytes":1,"required":true}]
        });
        for key in [
            "contract_set_manifest_digest",
            "schema_registry_digest",
            "cose_purpose_registry_digest",
            "complete_component_set_digest",
            "identity_snapshot_manifest_digest",
            "policy_bundle_digest",
            "semantic_model_digest",
            "named_set_registry_digest",
            "blocklist_digest",
            "policy_fact_state_digest",
            "routing_snapshot_digest",
            "provider_certification_registry_digest",
            "mrpc_runtime_profile_digest",
            "dynamic_event_profile_digest",
            "rpc_invocation_profile_digest",
            "capability_registry_digest",
            "request_form_registry_digest",
            "error_registry_digest",
            "evidence_admission_profile_digest",
        ] {
            value[key] = json!(digest);
        }
        let capsule: RuntimeCapsule = serde_json::from_value(value).unwrap();
        let actual = capsule.digest().unwrap();
        work.predecessor_digest = None;
        let token = RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: work.target_id.clone().unwrap(),
            occurrence_id: work.occurrence_id.clone().unwrap_or(work.work_id.clone()),
            desired_generation_digest: actual.clone(),
            xds_version_digest: work.xds_version_digest.clone().unwrap(),
            expected_previous_generation_digest: None,
            issued_at_ns: 100,
            expires_at_ns: 250,
        };
        let receipt = TargetActivationReceipt {
            receipt_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: capsule.target_runtime_id.clone(),
            capsule_digest: actual.clone(),
            contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
            complete_component_set_digest: capsule.complete_component_set_digest.clone(),
            status: 1,
            reason_code: "ACTIVE_LOCAL".into(),
            observed_at_ns: 200,
            agent_sequence: 1,
            signer_id: "openpc-local-agent-signer".into(),
        };
        let control = RuntimeWireSigner::from_secret_bytes([31; 32]).unwrap();
        let agent = RuntimeWireSigner::from_secret_bytes([33; 32]).unwrap();
        let token = control
            .verifier()
            .verify_activation_token(&control.sign_activation_token(&token).unwrap())
            .unwrap();
        let receipt = agent
            .verifier()
            .verify_receipt(&agent.sign_receipt(&receipt).unwrap())
            .unwrap();
        let check =
            |w: &ClaimedWork, t: &RuntimeActivationToken, r: &TargetActivationReceipt, now| {
                recovered_activation_expired(w, &capsule, t, r, &actual, now)
            };
        assert_eq!(check(&work, &token, &receipt, 999), Ok(false));
        assert_eq!(check(&work, &token, &receipt, 1000), Ok(true));
        assert_eq!(check(&work, &token, &receipt, 2000), Ok(true));
        assert!(check(&work, &token, &receipt, 199).is_err());
        for field in [
            "target",
            "generation",
            "predecessor",
            "policy",
            "occurrence",
            "xds",
        ] {
            let mut changed = work.clone();
            match field {
                "target" => changed.target_id = Some(uuid::Uuid::now_v7().to_string()),
                "generation" => changed.generation_id = Some(uuid::Uuid::now_v7().to_string()),
                "predecessor" => changed.predecessor_digest = Some(Digest::of(b"foreign")),
                "policy" => {
                    changed.policy.as_mut().unwrap().generation_digest = Digest::of(b"foreign")
                }
                "occurrence" => changed.occurrence_id = Some(uuid::Uuid::now_v7().to_string()),
                "xds" => changed.xds_version_digest = Some(Digest::of(b"foreign")),
                _ => unreachable!(),
            }
            assert!(check(&changed, &token, &receipt, 2000).is_err(), "{field}");
        }
        for observed in [49, 99, 250, 1000] {
            let changed = TargetActivationReceipt {
                observed_at_ns: observed,
                ..receipt.clone()
            };
            assert!(check(&work, &token, &changed, 2000).is_err());
        }
        for changed in [
            TargetActivationReceipt {
                status: 2,
                ..receipt.clone()
            },
            TargetActivationReceipt {
                capsule_digest: Digest::of(b"foreign"),
                ..receipt.clone()
            },
            TargetActivationReceipt {
                target_runtime_id: uuid::Uuid::now_v7().to_string(),
                ..receipt.clone()
            },
            TargetActivationReceipt {
                complete_component_set_digest: Digest::of(b"foreign"),
                ..receipt.clone()
            },
        ] {
            assert!(check(&work, &token, &changed, 2000).is_err());
        }
    }
}
