//! Restore the transport for a completed local activation after Fleet loses its
//! in-memory ADS map. Signed custody and the durable result must agree. This
//! does not activate, renew authority, or assert a fresh request observation.
use super::*;
use openpc_fleet_controller::cigl_publication::profile_invalidation::lock_sources;

pub(super) async fn restore(
    pool: &PgPool,
    config: &Config,
    plane: &RuntimePlane,
) -> WorkerResult<()> {
    let pem = match fs::read(&plane.config.target_client_certificate) {
        Ok(pem) => pem,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("settled ADS identity unavailable".into()),
    };
    let identity =
        runtime_tls::target_identity_from_pem(&pem).map_err(|_| "settled ADS identity rejected")?;
    let target = &identity.target_id;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "settled ADS store unavailable")?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
        .bind(&config.participant_id).bind(&config.privacy_domain_id).execute(&mut *tx).await
        .map_err(|_| "settled ADS scope rejected")?;
    let selection = r#"select work.configuration_work_id::text work_id,
      generation.runtime_configuration_generation_id::text generation_id,
      generation.provider_profile_id::text provider_id,work.predecessor_digest,work.configuration_digest,
      work.policy_generation_digest,observation.capsule_digest,observation.xds_version_digest,
      observation.activation_receipt,observation.activation_receipt_digest,
      (select occurrence.activation_occurrence_id::text from control.policy_activation_occurrence_target occurrence
        where occurrence.configuration_work_id=work.configuration_work_id
         and occurrence.participant_id=work.participant_id and occurrence.privacy_domain_id=work.privacy_domain_id) occurrence_id
      from control.runtime_target target
      join control.runtime_activation_observation observation on observation.runtime_target_id=target.runtime_target_id
       and observation.participant_id=target.participant_id and observation.privacy_domain_id=target.privacy_domain_id
       and observation.capsule_digest=target.active_generation_digest
      join control.runtime_configuration_generation generation
       on generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
        and generation.participant_id=target.participant_id and generation.privacy_domain_id=target.privacy_domain_id
        and generation.runtime_target_id=target.runtime_target_id and generation.generation_digest=observation.generation_digest
      join control.configuration_work work on work.configuration_work_id=observation.configuration_work_id
       and work.participant_id=target.participant_id and work.privacy_domain_id=target.privacy_domain_id
       and work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
       and work.runtime_target_id=target.runtime_target_id and work.generation_digest=generation.generation_digest
       and work.operation_id=observation.operation_id and work.execution_attempt_id=observation.execution_attempt_id
       and work.xds_version_digest=observation.xds_version_digest
       and work.policy_generation_digest=generation.policy_generation_digest
       and work.predecessor_digest is not distinct from generation.predecessor_digest
      where target.runtime_target_id=$1::text::uuid
       and target.participant_id=openpc.current_participant_id() and target.privacy_domain_id=openpc.current_privacy_domain_id()
       and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest
       and target.policy_generation_digest=generation.policy_generation_digest
       and generation.state='ACTIVE'
       and work.work_kind='RUNTIME_ACTIVATION' and work.state='COMPLETED' and work.execution_started_at is not null
       and work.result_receipt_digest=observation.activation_receipt_digest
      limit 2"#;
    // Identify the actual original input before taking any reference-row lock.
    let candidates = sqlx::query(selection)
        .bind(target)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| "settled ADS result unavailable")?;
    if candidates.is_empty() {
        return Ok(());
    }
    if candidates.len() != 1 {
        return Err("settled ADS result ambiguous".into());
    }
    let original_digest = parse_digest(
        candidates[0]
            .try_get("configuration_digest")
            .map_err(|_| "settled ADS configuration digest rejected")?,
    )?;
    match runtime_artifact_new_use_allowed(
        &mut tx,
        &config.participant_id,
        &config.privacy_domain_id,
        &original_digest,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(error) => return Err(error),
    }
    lock_sources(&mut tx)
        .await
        .map_err(|_| "settled ADS source fence unavailable")?;
    // Re-read under the same transaction and held retirement fence; a changed
    // original cannot consume the earlier digest's absence observation.
    // Both fragments are fixed SQL literals; all external values stay bound.
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{selection} for share of target,generation,work"
    )))
    .bind(target)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| "settled ADS result unavailable")?;
    if rows.is_empty() {
        return Ok(());
    }
    if rows.len() != 1 {
        return Err("settled ADS result ambiguous".into());
    }
    let row = &rows[0];
    let text = |name| {
        row.try_get::<String, _>(name)
            .map_err(|_| "settled ADS result field rejected".to_owned())
    };
    if parse_digest(text("configuration_digest")?)? != original_digest {
        return Err("settled ADS original configuration changed".into());
    }
    plane
        .source_custody
        .record_consumer_use(
            &mut tx,
            openpc_fleet_controller::runtime_artifact_source::SourceConsumerUse {
                configuration_digest: original_digest,
                consumer_id: "settled-transport".into(),
                boundary: Some(openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::SettledTransport),
                target_id: Some(target.to_owned()),
                original_id: text("work_id")?,
            },
        )
        .await
        .map_err(|_| "settled ADS source custody unavailable")?;
    let capsule_digest = parse_digest(text("capsule_digest")?)?;
    let policy_digest = parse_digest(text("policy_generation_digest")?)?;
    let xds = parse_digest(text("xds_version_digest")?)?;
    let predecessor = optional_digest(
        row.try_get("predecessor_digest")
            .map_err(|_| "settled ADS predecessor rejected")?,
    )?;
    let occurrence: Option<String> = row
        .try_get("occurrence_id")
        .map_err(|_| "settled ADS occurrence rejected")?;
    let occurrence = occurrence.unwrap_or(text("work_id")?);
    let observation: Value = row
        .try_get("activation_receipt")
        .map_err(|_| "settled ADS receipt rejected")?;
    let observation_digest = Digest::of(
        canonical_bytes(&observation).map_err(|_| "settled ADS receipt encoding rejected")?,
    );
    if observation_digest != parse_digest(text("activation_receipt_digest")?)? {
        return Err("settled ADS receipt digest rejected".into());
    }
    let Some(manifest) = prior_target_manifest(config, target, Some(&capsule_digest))? else {
        // A transport-only configuration can be completed before the first
        // governed policy installs target custody. Missing custody grants no
        // restored ADS authority, but must leave the control owner available
        // to process that subsequent governed activation. A present, invalid
        // manifest still fails at the authenticated reader above.
        eprintln!(
            r#"{{"level":"warn","event":"settled_transport_unavailable","boundary":"bootstrap_unavailable"}}"#
        );
        tx.rollback()
            .await
            .map_err(|_| "settled ADS source release failed".to_owned())?;
        return Ok(());
    };
    if manifest.suspended_for_work.is_some() {
        // Clearing this signed suspension requires the missing target
        // disposition/antirollback owner, not retained activation history.
        eprintln!(
            r#"{{"level":"warn","event":"settled_transport_unavailable","boundary":"bootstrap_disposition_unavailable"}}"#
        );
        return Ok(());
    }
    let source_only = manifest.source_only;
    let (capsule, activation_token, activation_receipt, configuration) = if source_only {
        let retained = retained_target::read_installed(config, target)
            .map_err(|_| "settled source ADS custody rejected")?;
        if retained
            .capsule
            .digest()
            .map_err(|_| "settled source capsule rejected")?
            != capsule_digest
            || !retained.manifest.source_only
        {
            return Err("settled source generation rejected".into());
        }
        // The original full input is immutable and named by this completed
        // work. Replaying its transport budget grants no provider/source I/O.
        let digest = parse_digest(text("configuration_digest")?)?;
        let inputs: Vec<String> = sqlx::query_scalar("select runtime_configuration_input_id::text from control.runtime_configuration_input where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_digest=decode($3,'hex') order by runtime_configuration_input_id limit 3")
            .bind(&config.participant_id).bind(&config.privacy_domain_id).bind(digest.as_str())
            .fetch_all(&mut *tx).await.map_err(|_| "settled source identity unavailable")?;
        if inputs.len() > 2 {
            return Err("settled source identity ambiguous".into());
        }
        for input in inputs {
            openpc_indexer_adapter::control_materialization::authorize_input(&mut tx, &input)
                .await?;
        }
        let bytes: Vec<Vec<u8>> = sqlx::query_scalar("select distinct openpc.runtime_artifact_input_payload(runtime_configuration_input_id) from control.runtime_configuration_input where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_digest=decode($3,'hex') limit 2")
            .bind(&config.participant_id).bind(&config.privacy_domain_id).bind(digest.as_str())
            .fetch_all(&mut *tx).await.map_err(|_| "settled source configuration unavailable")?;
        if bytes.len() != 1 {
            return Err("settled source configuration ambiguous".into());
        }
        let configuration = match decode_active_invocation_configuration(&bytes[0], &digest) {
            Ok(configuration) => configuration,
            Err(_) => {
                // An obsolete configuration cannot restore transport authority,
                // but must not prevent processing its governed replacement.
                eprintln!(
                    r#"{{"level":"warn","event":"settled_source_transport_unavailable","boundary":"configuration_rejected"}}"#
                );
                tx.rollback()
                    .await
                    .map_err(|_| "settled ADS source release failed".to_owned())?;
                return Ok(());
            }
        };
        (
            retained.capsule,
            retained.activation_token,
            retained.activation_receipt,
            configuration,
        )
    } else {
        let sources = cigl_profile::load_installed_custody(config, target, &capsule_digest)
            .map_err(|_| "settled ADS custody rejected")?;
        let configuration = sources
            .configuration()
            .map_err(|_| "settled ADS configuration rejected")?;
        (
            sources.capsule,
            sources.activation_token,
            sources.activation_receipt,
            configuration,
        )
    };
    let token = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "settled ADS trust rejected")?
        .verifier()
        .verify_activation_token(&activation_token)
        .map_err(|_| "settled ADS token rejected")?;
    if capsule.capsule_id != text("generation_id")?
        || capsule.policy_bundle_digest != policy_digest
        || capsule.previous_capsule_digest != predecessor
        || token.occurrence_id != occurrence
        || token.xds_version_digest != xds
        || token.expected_previous_generation_digest != predecessor
        || observation
            .get("activationReceiptCoseHex")
            .and_then(Value::as_str)
            != Some(hex_bytes(&activation_receipt).as_str())
    {
        return Err("settled ADS installed identity rejected".into());
    }
    if !serving_lifetime_current(
        capsule.not_before_ns,
        capsule.hard_expiry_ns,
        now_ms()?.saturating_mul(1_000_000),
    ) {
        eprintln!(
            "{}",
            serde_json::json!({
                "level":"warn", "event":"settled_transport_unavailable", "stage":"capsule_lifetime",
                "target_id":target, "work_id":text("work_id")?, "capsule_id":capsule.capsule_id,
                "expires_at_ns":capsule.hard_expiry_ns.to_string(), "disposition":"fresh_governed_activation_required"
            })
        );
        tx.rollback()
            .await
            .map_err(|_| "settled ADS source release failed".to_owned())?;
        return Ok(());
    }
    // Preserve the exact admitted budget when restoring the same xDS version.
    let provider_id = text("provider_id")?;
    let provider = configuration
        .resource_artifacts
        .iter()
        .find(|artifact| {
            artifact.artifact_id == provider_id
                && artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
        })
        .ok_or("settled ADS provider unavailable")?;
    let qualified = qualify_provider_profile(
        &provider.payload_cbor,
        &format!("sha256:{}", provider.artifact_digest.as_str()),
    )
    .map_err(|_| "settled ADS provider rejected")?;
    let resources =
        openpc_fleet_controller::envoy_resources::protected_resources(ProtectedListenerConfig {
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
        })
        .map_err(|_| "settled ADS resources rejected")?;
    plane
        .fleet
        .command_generation(pc_runtime_types::DesiredGeneration {
            occurrence_id: occurrence,
            target_id: target.clone(),
            capsule_digest: capsule_digest.clone(),
            xds_snapshot_digest: xds.clone(),
            expected_previous_generation_digest: predecessor,
            expires_at_ms: capsule.hard_expiry_ns / 1_000_000,
        })
        .map_err(|_| "settled ADS desired identity rejected")?;
    plane
        .fleet
        .accept_prepared(target, &capsule_digest)
        .map_err(|_| "settled ADS retained custody rejected")?;
    plane
        .ads
        .publish_version(target, resources, xds)
        .map_err(|_| "settled ADS publication rejected")?;
    tx.rollback()
        .await
        .map_err(|_| "settled ADS source release failed".into())
}

// Historical signature validity does not grant present serving authority.
fn serving_lifetime_current(not_before_ns: u64, expiry_ns: u64, now_ns: u64) -> bool {
    not_before_ns <= now_ns && now_ns < expiry_ns
}

#[cfg(test)]
mod tests {
    use super::serving_lifetime_current;
    #[test]
    fn settled_transport_never_restores_outside_original_signed_lifetime() {
        assert!(!serving_lifetime_current(100, 200, 99));
        assert!(serving_lifetime_current(100, 200, 100));
        assert!(serving_lifetime_current(100, 200, 199));
        assert!(!serving_lifetime_current(100, 200, 200));
        assert!(!serving_lifetime_current(100, 200, 201));
        assert!(!serving_lifetime_current(200, 100, 150));
    }
}
