//! Source and visibility restriction custody. No Fact shard or invocation route is produced.
use super::*;
use openpc_fleet_controller::runtime_target::build_governed_source_owners;
use openpc_runtime_agent::indexer_custody::{
    CONFIGURATION_ARTIFACT_ID, CONFIGURATION_DEFINITION, NO_FACT_PUBLICATION, POLICY_ARTIFACT_ID,
    POLICY_DEFINITION,
};

pub(super) struct SourceCustody<'a> {
    pub identity: IdentityPublication,
    pub compiled: &'a CompiledContractPolicyBundle,
}

pub(super) fn bootstrap(
    work: &ClaimedWork,
    config: &Config,
    custody: &SourceCustody<'_>,
    capsule: &RuntimeCapsule,
    emergency_delivery: Option<openpc_fleet_controller::runtime_target::TargetEmergencyDelivery>,
    target_disposition: openpc_fleet_controller::runtime_target::TargetDispositionBootstrap,
) -> WorkerResult<TargetBootstrapManifest> {
    let signer = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "source bootstrap signer unavailable")?;
    Ok(TargetBootstrapManifest {
        version: 1,
        participant_id: work.participant_id.clone(),
        privacy_domain_id: work.privacy_domain_id.clone(),
        target_runtime_id: capsule.target_runtime_id.clone(),
        fleet_id: capsule.fleet_id.clone(),
        fleet_signer_id: capsule.signer_id.clone(),
        agent_signer_id: "openpc-local-agent-signer".into(),
        authority_signer_id: config.worker_id.clone(),
        fleet_runtime_public_key: signer.verifier().public_key_bytes(),
        identity_runtime_public_key: config.identity_runtime_public_key.clone(),
        fact_verify_key: config.fact_verify_key.clone(),
        fact_verify_key_id: config.fact_verify_key_id.clone(),
        contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
        schema_registry_digest: capsule.schema_registry_digest.clone(),
        cose_purpose_registry_digest: capsule.cose_purpose_registry_digest.clone(),
        complete_component_set_digest: capsule.complete_component_set_digest.clone(),
        capsule_id: capsule.capsule_id.clone(),
        capsule_generation: capsule.generation,
        capsule_digest: capsule
            .digest()
            .map_err(|_| "source capsule identity rejected")?,
        identity_profile_digest: custody.identity.profile_digest.clone(),
        mrpc_runtime_profile: Vec::new(),
        routing_source: Vec::new(),
        certification_source: Vec::new(),
        protected_class_set_digest: protected_class_set_digest(),
        source_only: true,
        emergency_delivery,
        suspended_for_work: None,
        target_disposition: Some(target_disposition),
    })
}

pub(super) fn capsule(
    work: &ClaimedWork,
    config: &Config,
    custody: &SourceCustody<'_>,
    previous: Option<Digest>,
    now_ns: u64,
) -> WorkerResult<CapsuleBuild> {
    let target = work.target_id.as_deref().ok_or("source target missing")?;
    let generation = pc_policy_core::invocation::decode_active_invocation_policy_generation(
        &custody.compiled.policy_cbor,
        &custody.compiled.policy_digest,
    )
    .map_err(|_| "source generation rejected")?;
    if !custody.compiled.policies.is_empty()
        || !custody.compiled.deployment_policies.is_empty()
        || (generation.indexer_policies.is_empty() && generation.visibility_policies.is_empty())
        || !generation.required_facts.is_empty()
        || custody.identity.expires_at_ns <= now_ns.saturating_add(1_000_000_000)
    {
        return Err("source-only custody unavailable".into());
    }
    let signer = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "source authority signer unavailable")?;
    let authority_public_key = signer.verifier().public_key_bytes();
    let mut artifacts = BTreeMap::new();
    let mut components = Vec::new();
    for bytes in &custody.identity.contents {
        artifacts.insert(Digest::of(bytes), bytes.clone());
    }
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.identity.snapshot",
        "identity-snapshot",
        (3004, 2),
        custody.identity.manifest_digest.clone(),
        custody.identity.manifest_cose.clone(),
    )?;
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.identity.runtime-profile",
        "identity-profile",
        (3010, 2),
        custody.identity.profile_digest.clone(),
        custody.identity.profile_cose.clone(),
    )?;
    add_authority_source(
        &mut artifacts,
        &mut components,
        &signer,
        (CONFIGURATION_ARTIFACT_ID, CONFIGURATION_DEFINITION),
        &config.worker_id,
        custody.compiled.configuration_cbor.clone(),
        now_ns.saturating_sub(1),
    )?;
    add_authority_source(
        &mut artifacts,
        &mut components,
        &signer,
        (POLICY_ARTIFACT_ID, POLICY_DEFINITION),
        &config.worker_id,
        custody.compiled.policy_cbor.clone(),
        now_ns.saturating_sub(1),
    )?;
    components.sort_by_key(|c| {
        c.canonical_bytes()
            .expect("constructed source component is valid")
    });
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let source_scope =
        Digest::of(b"OpenPC R1 source-only policy custody v1; no invocation authority");
    let capsule = RuntimeCapsule {
        capsule_id: work
            .generation_id
            .clone()
            .unwrap_or_else(|| work.work_id.clone()),
        lifecycle_mode: if previous.is_some() { 2 } else { 1 },
        target_runtime_id: target.into(),
        fleet_id: "openpc-local-runtime-fleet".into(),
        generation: work
            .journal_sequence
            .checked_add(1)
            .ok_or("source generation overflow")?,
        previous_capsule_digest: previous,
        contract_set_manifest_digest: stable.clone(),
        schema_registry_digest: stable.clone(),
        cose_purpose_registry_digest: stable,
        complete_component_set_digest: Digest::of(b"OpenPC R1 runtime complete component set v1"),
        identity_snapshot_manifest_digest: custody.identity.manifest_digest.clone(),
        policy_bundle_digest: work.policy()?.generation_digest.clone(),
        semantic_model_digest: custody.compiled.policy_digest.clone(),
        named_set_registry_digest: custody.compiled.configuration_digest.clone(),
        blocklist_digest: custody.compiled.configuration_digest.clone(),
        policy_fact_state_digest: Digest::of(NO_FACT_PUBLICATION),
        routing_snapshot_digest: source_scope.clone(),
        provider_certification_registry_digest: source_scope.clone(),
        mrpc_runtime_profile_digest: source_scope.clone(),
        dynamic_event_profile_digest: source_scope.clone(),
        rpc_invocation_profile_digest: source_scope.clone(),
        capability_registry_digest: source_scope.clone(),
        request_form_registry_digest: source_scope.clone(),
        error_registry_digest: source_scope.clone(),
        evidence_admission_profile_digest: source_scope,
        emergency_deny_generation: 0,
        issued_at_ns: now_ns,
        not_before_ns: now_ns.saturating_add(1),
        hard_expiry_ns: custody.identity.expires_at_ns,
        signer_id: "openpc-local-fleet-signer".into(),
        artifact_components: components,
    };
    let trust = GovernedOwnerTrust {
        participant_id: &work.participant_id,
        privacy_domain_id: &work.privacy_domain_id,
        target_runtime_id: target,
        authority_signer_id: &config.worker_id,
        authority_public_key: &authority_public_key,
        identity_runtime_public_key: &config.identity_runtime_public_key,
        identity_profile_digest: custody.identity.profile_digest.clone(),
        fact_verify_key: &config.fact_verify_key,
        fact_verify_key_id: &config.fact_verify_key_id,
        mrpc_runtime_profile: &[],
    };
    let journal = openpc_fleet_controller::runtime_target::GovernedJournalAdmission::new(&trust);
    let owners = build_governed_source_owners(trust, observed_admission)?;
    owners
        .indexer
        .admit_policies(&capsule, &artifacts)
        .map_err(|_| "source policy custody rejected")?;
    owners
        .identity
        .admit_identity(&capsule, &artifacts)
        .map_err(|_| "source identity custody rejected")?;
    capsule
        .encode()
        .map_err(|_| "source capsule encoding rejected")?;
    Ok((
        capsule,
        artifacts,
        Arc::new(GovernedOrBootstrapAdmission {
            governed: Arc::new(journal),
        }),
    ))
}

/// Classification only. Journal/source owners still authenticate every byte.
pub(super) fn is_source_only(work: &ClaimedWork) -> bool {
    let Some(policy) = &work.policy else {
        return false;
    };
    pc_policy_core::semantics::PolicySemanticDocument::decode(&policy.artifact_cbor).is_ok_and(
        |d| {
            (!d.indexer_policies.is_empty() || !d.visibility_policies.is_empty())
                && d.contract_policies.is_empty()
                && d.deployment_policies.is_empty()
        },
    )
}
