//! Read the actual signed target effect after a crash, independently of whether
//! the controller managed to write a bootstrap or a Control observation.
use super::*;
use openpc_fleet_controller::routing_publication::{CERTIFICATION_DEFINITION, ROUTING_DEFINITION};
use pc_runtime_types::{RuntimeError, RuntimeResult};

struct RetainedAdmission<'a> {
    config: &'a Config,
    target: &'a str,
}

fn component(capsule: &RuntimeCapsule, schema: u64) -> RuntimeResult<&ArtifactComponent> {
    let mut matches = capsule
        .artifact_components
        .iter()
        .filter(|component| component.schema_id == schema);
    let component = matches.next().ok_or(RuntimeError::InvalidInput)?;
    if matches.next().is_some() || !component.required {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(component)
}

fn material<'a>(
    capsule: &RuntimeCapsule,
    artifacts: &'a BTreeMap<Digest, Vec<u8>>,
    schema: u64,
) -> RuntimeResult<&'a [u8]> {
    let component = component(capsule, schema)?;
    let bytes = artifacts
        .get(&component.content_digest)
        .ok_or(RuntimeError::InvalidInput)?;
    if bytes.len() as u64 != component.size_bytes || Digest::of(bytes) != component.content_digest {
        return Err(RuntimeError::InvalidDigest);
    }
    Ok(bytes)
}

impl RetainedAdmission<'_> {
    fn owners(
        &self,
        capsule: &RuntimeCapsule,
        _artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<Arc<dyn ArtifactAdmission>> {
        // RuntimeAgent verifies capsule trust/signature and the entire content
        // closure before lending the result. Profile selectors here originate
        // in that signed capsule; the normal owners still verify every profile.
        let public = RuntimeWireSigner::from_secret_bytes(self.config.fleet_key)?
            .verifier()
            .public_key_bytes();
        Ok(Arc::new(
            openpc_fleet_controller::runtime_target::GovernedJournalAdmission::new(
                &GovernedOwnerTrust {
                    participant_id: &self.config.participant_id,
                    privacy_domain_id: &self.config.privacy_domain_id,
                    target_runtime_id: self.target,
                    authority_signer_id: &self.config.worker_id,
                    authority_public_key: &public,
                    identity_runtime_public_key: &self.config.identity_runtime_public_key,
                    identity_profile_digest: component(capsule, 3010)?.semantic_digest.clone(),
                    fact_verify_key: &self.config.fact_verify_key,
                    fact_verify_key_id: &self.config.fact_verify_key_id,
                    mrpc_runtime_profile: &[],
                },
            ),
        ))
    }
}

impl ArtifactAdmission for RetainedAdmission<'_> {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidAuthorization)
    }
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        self.owners(capsule, artifacts)?
            .validate_bundle(capsule, artifacts)
    }
}

pub(super) struct RetainedTarget {
    pub artifacts: BTreeMap<Digest, Vec<u8>>,
    pub(super) capsule: RuntimeCapsule,
    pub(super) manifest: TargetBootstrapManifest,
    pub(super) activation_receipt: Vec<u8>,
    pub(super) activation_token: Vec<u8>,
}

pub(super) struct NoEffect {
    // Keep the exclusive writer alive through the terminal result transaction.
    _custody: RuntimeAgent,
    pub(super) evidence: Value,
}

pub(super) async fn no_effect(
    tx: &mut Transaction<'_, Postgres>,
    config: &Config,
    work: &ClaimedWork,
    source: &openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
) -> WorkerResult<Option<NoEffect>> {
    if config.participant_id != work.participant_id
        || config.privacy_domain_id != work.privacy_domain_id
    {
        return Err("CIGL no-effect scope rejected".into());
    }
    let profiled: bool = sqlx::query_scalar(r#"select exists(select 1 from control.runtime_configuration_generation generation
      join control.runtime_target target on target.runtime_target_id=generation.runtime_target_id
       and target.participant_id=generation.participant_id and target.privacy_domain_id=generation.privacy_domain_id
      join control.configuration_work work on work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
       and work.participant_id=generation.participant_id and work.privacy_domain_id=generation.privacy_domain_id
       and work.runtime_target_id=target.runtime_target_id and work.generation_digest=generation.generation_digest
       and work.predecessor_digest=generation.predecessor_digest and work.policy_generation_digest=generation.policy_generation_digest
      where generation.runtime_configuration_generation_id=$1::text::uuid and generation.runtime_target_id=$2::text::uuid
       and generation.state='ACTIVATING' and (generation.cigl_profile_selection is not null or $7)
       and target.state='STAGING' and target.active_generation_digest=$3 and target.desired_generation_digest=generation.generation_digest
       and work.configuration_work_id=$4::text::uuid and work.state='LEASED' and work.lease_owner=$5
       and work.lease_until>clock_timestamp() and work.execution_started_at is not null
       and work.execution_attempt_id=$6::text::uuid and work.work_kind='RUNTIME_ACTIVATION'
       and not exists(select 1 from control.runtime_activation_observation observation
         where observation.configuration_work_id=work.configuration_work_id))"#)
        .bind(&work.generation_id).bind(&work.target_id).bind(work.predecessor_digest.as_ref().map(|d|format!("sha256:{}",d.as_str())))
        .bind(&work.work_id).bind(&config.worker_id).bind(&work.execution_attempt_id).bind(source_activation::is_source_only(work))
        .fetch_one(&mut **tx).await.map_err(|_| "CIGL no-effect work rejected")?;
    if !profiled {
        return Ok(None);
    }
    let target = work
        .target_id
        .as_deref()
        .ok_or("CIGL no-effect target missing")?;
    let generation = work
        .generation_id
        .as_deref()
        .ok_or("CIGL no-effect generation missing")?;
    let predecessor = work
        .predecessor_digest
        .as_ref()
        .ok_or("CIGL no-effect predecessor missing")?;
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .map_err(|_| "CIGL no-effect trust rejected")?
        .verifier()
        .sec1_bytes();
    let directory = Path::new("/runtime/target-bootstrap").join(target);
    let mut manifest = read_target_bootstrap(&directory, &public)?;
    if manifest
        .suspended_for_work
        .as_deref()
        .is_some_and(|id| id != work.work_id)
    {
        return Ok(None);
    }
    if manifest.participant_id != work.participant_id
        || manifest.privacy_domain_id != work.privacy_domain_id
        || manifest.target_runtime_id != target
        || manifest.authority_signer_id != config.worker_id
    {
        return Err("CIGL no-effect predecessor rejected".into());
    }
    if &manifest.capsule_digest != predecessor {
        // An installed successor belongs to positive-effect reconciliation.
        return Ok(None);
    }
    if manifest.suspended_for_work.is_none() {
        // A failed result commit may have restored serving A. Reacquire the
        // same local handoff before inspecting custody on the next attempt.
        manifest.suspended_for_work = Some(work.work_id.clone());
        record_bootstrap_source_restriction(tx, source, &manifest, "no-effect-suspension").await?;
        write_target_bootstrap(&directory, manifest.clone(), config.fleet_key)?;
    }
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let fleet = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "CIGL no-effect signer rejected")?;
    let Some(agent) = RuntimeAgent::try_open_canonical(
        CapsuleTrust {
            target_id: target.into(),
            fleet_id: "openpc-local-runtime-fleet".into(),
            fleet_signer_id: "openpc-local-fleet-signer".into(),
            agent_signer_id: "openpc-local-agent-signer".into(),
            contract_set_manifest_digest: stable.clone(),
            schema_registry_digest: stable.clone(),
            cose_purpose_registry_digest: stable,
            complete_component_set_digest: Digest::of(
                b"OpenPC R1 runtime complete component set v1",
            ),
        },
        &fleet.verifier().public_key_bytes(),
        config.agent_key,
        64,
        config.artifact_capacity_bytes,
        &Path::new("/runtime/agent").join(target),
        Arc::new(OwnedRetainedAdmission {
            config: config.clone(),
            target: target.into(),
        }),
    )
    .map_err(|_| "CIGL no-effect custody rejected")?
    else {
        return Ok(None);
    };
    let now = now_ms()?.saturating_mul(1_000_000);
    let Some(proof) = agent
        .expired_preparation_no_effect(
            generation,
            predecessor,
            &work.policy()?.generation_digest,
            now,
        )
        .map_err(|_| "CIGL no-effect proof rejected")?
    else {
        return Ok(None);
    };
    let evidence = serde_json::json!({
        "effect":"NO_EFFECT", "capsuleId":generation,
        "preparedCapsuleDigest":format!("sha256:{}",proof.capsule().digest().map_err(|_| "CIGL no-effect digest rejected")?.as_str()),
        "preparedCapsuleCoseHex":hex_bytes(proof.signed_capsule()),
        "predecessorCapsuleDigest":format!("sha256:{}",predecessor.as_str()),
        "predecessorActivationReceiptCoseHex":hex_bytes(proof.predecessor_receipt()),
        "observedAtNs":now.to_string(), "preparationExpiredAtNs":proof.capsule().hard_expiry_ns.to_string(),
    });
    // This proof settles only the attempted successor's original NO_EFFECT.
    // Do not clear predecessor suspension: neither that outcome nor a signed
    // bootstrap supplies current disposition and antirollback delivery.
    eprintln!(
        r#"{{"level":"warn","event":"retained_target_restore_blocked","boundary":"bootstrap_disposition_unavailable"}}"#
    );
    Ok(Some(NoEffect {
        _custody: agent,
        evidence,
    }))
}

struct OwnedRetainedAdmission {
    config: Config,
    target: String,
}
impl ArtifactAdmission for OwnedRetainedAdmission {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidAuthorization)
    }
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        RetainedAdmission {
            config: &self.config,
            target: &self.target,
        }
        .validate_bundle(capsule, artifacts)
    }
}

pub(super) fn read(config: &Config, work: &ClaimedWork) -> RuntimeResult<Option<RetainedTarget>> {
    read_from(config, work, Path::new("/runtime/agent"))
}

pub(super) fn read_from(
    config: &Config,
    work: &ClaimedWork,
    journal_root: &Path,
) -> RuntimeResult<Option<RetainedTarget>> {
    let target = work
        .target_id
        .as_deref()
        .ok_or(RuntimeError::InvalidInput)?;
    let generation = work
        .generation_id
        .as_deref()
        .ok_or(RuntimeError::InvalidInput)?;
    if config.participant_id != work.participant_id
        || config.privacy_domain_id != work.privacy_domain_id
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let mut retained = read_installed_from(config, target, journal_root)?;
    let capsule = &retained.capsule;
    if Some(&capsule.digest()?) == work.predecessor_digest.as_ref() {
        // Seeing the predecessor cannot prove that an in-flight effect failed.
        return Ok(None);
    }
    let token = RuntimeWireSigner::from_secret_bytes(config.fleet_key)?
        .verifier()
        .verify_activation_token(&retained.activation_token)?;
    if capsule.capsule_id != generation
        || capsule.policy_bundle_digest
            != work
                .policy()
                .map_err(|_| RuntimeError::InvalidAuthorization)?
                .generation_digest
        || capsule.previous_capsule_digest != work.predecessor_digest
        || token.occurrence_id != work.occurrence_id.as_deref().unwrap_or(&work.work_id)
        || Some(&token.xds_version_digest) != work.xds_version_digest.as_ref()
        || token.expected_previous_generation_digest != work.predecessor_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    retained.manifest.suspended_for_work = Some(work.work_id.clone());
    Ok(Some(retained))
}

/// One authenticated, committed activation, without taking its live writer.
pub(super) fn read_installed(config: &Config, target: &str) -> RuntimeResult<RetainedTarget> {
    read_installed_from(config, target, Path::new("/runtime/agent"))
}

pub(super) fn read_installed_from(
    config: &Config,
    target: &str,
    journal_root: &Path,
) -> RuntimeResult<RetainedTarget> {
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let fleet = RuntimeWireSigner::from_secret_bytes(config.fleet_key)?;
    let admission = RetainedAdmission { config, target };
    RuntimeAgent::read_canonical_activation(
        &CapsuleTrust {
            target_id: target.into(),
            fleet_id: "openpc-local-runtime-fleet".into(),
            fleet_signer_id: "openpc-local-fleet-signer".into(),
            agent_signer_id: "openpc-local-agent-signer".into(),
            contract_set_manifest_digest: stable.clone(),
            schema_registry_digest: stable.clone(),
            cose_purpose_registry_digest: stable,
            complete_component_set_digest: Digest::of(
                b"OpenPC R1 runtime complete component set v1",
            ),
        },
        &fleet.verifier().public_key_bytes(),
        &RuntimeWireSigner::from_secret_bytes(config.agent_key)?
            .verifier()
            .public_key_bytes(),
        &journal_root.join(target),
        None,
        &admission,
        |capsule, artifacts, signed_token, receipt| {
            let actual = capsule.digest()?;
            let source = |id: &str, definition: &[u8]| -> RuntimeResult<Vec<u8>> {
                let binding = AuthoritySourceBinding {
                    artifact_id: id.into(),
                    artifact_class: 1,
                    source_media_type: "application/cbor".into(),
                    definition_digest: Digest::of(definition),
                    signer_id: config.worker_id.clone(),
                    maximum_source_bytes: 4 * 1024 * 1024,
                };
                Ok(binding
                    .in_capsule(&fleet.verifier(), capsule, artifacts)?
                    .2
                    .to_vec())
            };
            let source_only = capsule.artifact_components.iter().any(|c| {
                c.component_id == openpc_runtime_agent::indexer_custody::POLICY_ARTIFACT_ID
            });
            Ok(RetainedTarget {
                artifacts: artifacts.clone(),
                manifest: TargetBootstrapManifest {
                    version: 1,
                    participant_id: config.participant_id.clone(),
                    privacy_domain_id: config.privacy_domain_id.clone(),
                    target_runtime_id: target.into(),
                    fleet_id: capsule.fleet_id.clone(),
                    fleet_signer_id: capsule.signer_id.clone(),
                    agent_signer_id: "openpc-local-agent-signer".into(),
                    authority_signer_id: config.worker_id.clone(),
                    fleet_runtime_public_key: fleet.verifier().public_key_bytes(),
                    identity_runtime_public_key: config.identity_runtime_public_key.clone(),
                    fact_verify_key: config.fact_verify_key.clone(),
                    fact_verify_key_id: config.fact_verify_key_id.clone(),
                    contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
                    schema_registry_digest: capsule.schema_registry_digest.clone(),
                    cose_purpose_registry_digest: capsule.cose_purpose_registry_digest.clone(),
                    complete_component_set_digest: capsule.complete_component_set_digest.clone(),
                    capsule_id: capsule.capsule_id.clone(),
                    capsule_generation: capsule.generation,
                    capsule_digest: actual,
                    identity_profile_digest: component(capsule, 3010)?.semantic_digest.clone(),
                    mrpc_runtime_profile: if source_only {
                        Vec::new()
                    } else {
                        material(capsule, artifacts, 2014)?.to_vec()
                    },
                    routing_source: if source_only {
                        Vec::new()
                    } else {
                        source(ROUTING_ARTIFACT_ID, ROUTING_DEFINITION)?
                    },
                    certification_source: if source_only {
                        Vec::new()
                    } else {
                        source(CERTIFICATION_ARTIFACT_ID, CERTIFICATION_DEFINITION)?
                    },
                    protected_class_set_digest: protected_class_set_digest(),
                    source_only,
                    emergency_delivery: None,
                    suspended_for_work: None,
                    target_disposition: None,
                },
                capsule: capsule.clone(),
                activation_receipt: receipt.to_vec(),
                activation_token: signed_token.to_vec(),
            })
        },
    )
}

pub(super) async fn recover_observation(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
) -> WorkerResult<Option<(Digest, Value, Digest)>> {
    let Some(retained) =
        read(config, work).map_err(|_| "CIGL retained activation proof rejected")?
    else {
        return Ok(None);
    };
    record_verified_activation(
        pool,
        config,
        work,
        &retained.capsule,
        &retained.activation_receipt,
    )
    .await
    .map(Some)
}

pub(super) async fn record_verified_activation(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
    capsule: &RuntimeCapsule,
    signed_receipt: &[u8],
) -> WorkerResult<(Digest, Value, Digest)> {
    let actual = capsule
        .digest()
        .map_err(|_| "CIGL retained capsule rejected")?;
    let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .map_err(|_| "CIGL retained agent trust rejected")?
        .verifier()
        .verify_receipt(signed_receipt)
        .map_err(|_| "CIGL retained receipt rejected")?;
    if work.participant_id != config.participant_id
        || work.privacy_domain_id != config.privacy_domain_id
        || work.generation_id.as_deref() != Some(&capsule.capsule_id)
        || work.target_id.as_deref() != Some(&capsule.target_runtime_id)
        || capsule.policy_bundle_digest != work.policy()?.generation_digest
        || capsule.previous_capsule_digest != work.predecessor_digest
        || receipt.capsule_digest != actual
        || receipt.target_runtime_id != capsule.target_runtime_id
        || receipt.status != 1
        || receipt.reason_code != "ACTIVE_LOCAL"
        || receipt.signer_id != "openpc-local-agent-signer"
    {
        return Err("CIGL retained result binding rejected".into());
    }
    let mut value =
        serde_json::to_value(receipt).map_err(|_| "CIGL retained receipt encoding rejected")?;
    value["activationReceiptCoseHex"] = Value::String(hex_bytes(signed_receipt));
    value["capsuleGeneration"] = Value::Number(capsule.generation.into());
    let digest = record_runtime_observation(
        pool,
        work,
        config,
        work.execution_attempt_id
            .as_deref()
            .ok_or("CIGL retained execution attempt missing")?,
        &actual,
        &value,
    )
    .await?;
    Ok((actual, value, digest))
}

/// Inspect existing bootstrap custody without restoring or renewing it.
/// Callers still need current same-transaction retirement/source admission.
/// Suspended bootstrap restoration remains blocked until the target has an
/// authenticated disposition delivery and antirollback owner.
pub(super) fn serving_bootstrap_available(
    config: &Config,
    work: &ClaimedWork,
    expected_capsule: &Digest,
) -> WorkerResult<bool> {
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    let directory = Path::new("/runtime/target-bootstrap").join(target);
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .map_err(|_| "CIGL retained bootstrap trust rejected")?
        .verifier()
        .sec1_bytes();
    let previous = read_target_bootstrap(&directory, &public)?;
    existing_serving_bootstrap(&previous, config, work, expected_capsule)
}

// Identity/custody validation only; this never supplies new-use authority.
pub(super) fn existing_serving_bootstrap(
    previous: &TargetBootstrapManifest,
    config: &Config,
    work: &ClaimedWork,
    expected_capsule: &Digest,
) -> WorkerResult<bool> {
    let target = work.target_id.as_deref().ok_or("CIGL target unavailable")?;
    if config.participant_id != work.participant_id
        || config.privacy_domain_id != work.privacy_domain_id
        || previous.participant_id != work.participant_id
        || previous.privacy_domain_id != work.privacy_domain_id
        || previous.target_runtime_id != target
        || previous.authority_signer_id != config.worker_id
    {
        return Err("CIGL retained bootstrap scope rejected".into());
    }
    if previous.suspended_for_work.is_none() && previous.capsule_digest == *expected_capsule {
        return Ok(true);
    }
    if previous.suspended_for_work.as_deref() != Some(&work.work_id)
        || (previous.capsule_digest != *expected_capsule
            && Some(&previous.capsule_digest) != work.predecessor_digest.as_ref())
    {
        return Err("CIGL retained suspension identity rejected".into());
    }
    eprintln!(
        r#"{{"level":"warn","event":"retained_target_restore_blocked","boundary":"bootstrap_disposition_unavailable"}}"#
    );
    Ok(false)
}

/// Transfer exclusive target journal custody for an already leased activation.
/// Suspension only withdraws readiness; the signed activation token still owns
/// the effect, and the ordinary failure/reconciliation owner restores custody.
pub(super) async fn suspend_current(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
    source: &openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
) -> WorkerResult<Option<TargetBootstrapManifest>> {
    let target = work
        .target_id
        .as_deref()
        .ok_or("target handoff identity missing")?;
    let Some(predecessor) = work.predecessor_digest.as_ref() else {
        return Ok(None);
    };
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| "target handoff lease unavailable")?;
    set_context(&mut tx, config).await?;
    source
        .lock_consumer_scope(&mut tx)
        .await
        .map_err(|_| "target handoff source fence unavailable")?;
    let changed = sqlx::query("update control.configuration_work set lease_until=clock_timestamp()+interval '90 seconds',updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 and lease_until>clock_timestamp() and execution_started_at is null and work_kind='RUNTIME_ACTIVATION' and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid and runtime_target_id=$5::text::uuid and predecessor_digest=$6")
        .bind(&work.work_id).bind(&config.worker_id).bind(&work.participant_id).bind(&work.privacy_domain_id).bind(target).bind(format!("sha256:{}", predecessor.as_str())).execute(&mut *tx).await
        .map_err(|_| "target handoff lease rejected")?.rows_affected();
    if changed != 1 {
        return Err("target handoff lease rejected".into());
    }
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .map_err(|_| "target handoff trust rejected")?
        .verifier()
        .sec1_bytes();
    let directory = Path::new("/runtime/target-bootstrap").join(target);
    if !directory.join("bootstrap.json").exists() {
        return Ok(None);
    }
    let mut manifest = read_target_bootstrap(&directory, &public)?;
    if manifest.target_runtime_id != target
        || manifest.participant_id != work.participant_id
        || manifest.privacy_domain_id != work.privacy_domain_id
        || manifest.authority_signer_id != config.worker_id
        || manifest.capsule_digest != *predecessor
        || manifest
            .suspended_for_work
            .as_ref()
            .is_some_and(|id| id != &work.work_id)
    {
        return Err("target handoff predecessor rejected".into());
    }
    manifest.suspended_for_work = Some(work.work_id.clone());
    record_bootstrap_source_restriction(&mut tx, source, &manifest, "target-handoff").await?;
    write_target_bootstrap(&directory, manifest.clone(), config.fleet_key)?;
    tx.commit()
        .await
        .map_err(|_| "target handoff lease commit failed")?;
    Ok(Some(manifest))
}

/// Acquire the original journal without opening a listener or renewing any
/// custody. The ordinary concrete Control client will install denial only.
pub(super) fn open_expired_denial(
    config: &Config,
    target: &str,
) -> WorkerResult<(RuntimeAgent, TargetBootstrapManifest)> {
    let retained =
        read_installed(config, target).map_err(|_| "expired original journal rejected")?;
    if retained.capsule.previous_capsule_digest.is_none()
        || retained.capsule.hard_expiry_ns > now_ms()?.saturating_mul(1_000_000)
    {
        return Err("expired successor required".into());
    }
    let public = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
        .map_err(|_| "expired bootstrap trust rejected")?
        .verifier()
        .sec1_bytes();
    let manifest = read_target_bootstrap(
        &Path::new("/runtime/target-bootstrap").join(target),
        &public,
    )
    .map_err(|_| "expired bootstrap unavailable")?;
    if manifest.participant_id != config.participant_id
        || manifest.privacy_domain_id != config.privacy_domain_id
        || manifest.target_runtime_id != target
        || manifest.capsule_digest != retained.manifest.capsule_digest
        || manifest.authority_signer_id != config.worker_id
    {
        return Err("expired bootstrap binding rejected".into());
    }
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let fleet = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "expired trust unavailable")?;
    let agent = RuntimeAgent::try_open_canonical(
        CapsuleTrust {
            target_id: target.into(),
            fleet_id: "openpc-local-runtime-fleet".into(),
            fleet_signer_id: "openpc-local-fleet-signer".into(),
            agent_signer_id: "openpc-local-agent-signer".into(),
            contract_set_manifest_digest: stable.clone(),
            schema_registry_digest: stable.clone(),
            cose_purpose_registry_digest: stable,
            complete_component_set_digest: Digest::of(
                b"OpenPC R1 runtime complete component set v1",
            ),
        },
        &fleet.verifier().public_key_bytes(),
        config.agent_key,
        64,
        config.artifact_capacity_bytes,
        &Path::new("/runtime/agent").join(target),
        Arc::new(OwnedRetainedAdmission {
            config: config.clone(),
            target: target.into(),
        }),
    )
    .map_err(|_| "expired journal writer unavailable")?
    .ok_or("expired journal already owned")?;
    let current = agent
        .active_canonical_generation()
        .map_err(|_| "expired current journal rejected")?
        .ok_or("expired current journal absent")?;
    let token = fleet
        .verifier()
        .verify_activation_token(&retained.activation_token)
        .map_err(|_| "expired physical token rejected")?;
    let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
        .and_then(|signer| {
            signer
                .verifier()
                .verify_receipt(&retained.activation_receipt)
        })
        .map_err(|_| "expired physical receipt rejected")?;
    if current.0 != retained.manifest.capsule_digest
        || current.1 != token.xds_version_digest
        || current.2 != receipt.agent_sequence
    {
        return Err("expired physical predecessor changed".into());
    }
    Ok((agent, manifest))
}
