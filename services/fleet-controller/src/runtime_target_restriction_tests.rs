//! Signed delivery into real target custody; this is not CIGL source acceptance.
use super::*;
use openpc_runtime_agent::{
    CapsuleTrust, EmergencyDenyOverlay, RevocationFreshnessLease, RuntimeActivationToken,
    RuntimeAgent, RuntimeCapsule, RuntimeWireSigner, encode_emergency_deny_keys,
};

struct Fixture {
    root: std::path::PathBuf,
    signer: RuntimeWireSigner,
    manifest: TargetBootstrapManifest,
    capsule: RuntimeCapsule,
    artifacts: BTreeMap<Digest, Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        // Keep listener paths below sockaddr_un's limit under bounded TMPDIR.
        let root =
            std::env::temp_dir().join(format!("tr-{:016x}", uuid::Uuid::now_v7().as_u128() as u64));
        let signer = RuntimeWireSigner::from_secret_bytes([41; 32]).unwrap();
        let bytes = b"test bootstrap configuration".to_vec();
        let d = Digest::of(&bytes);
        let capsule = RuntimeCapsule {
            capsule_id: uuid::Uuid::now_v7().to_string(),
            lifecycle_mode: 1,
            target_runtime_id: "target".into(),
            fleet_id: "fleet".into(),
            generation: 1,
            previous_capsule_digest: None,
            contract_set_manifest_digest: d.clone(),
            schema_registry_digest: d.clone(),
            cose_purpose_registry_digest: d.clone(),
            complete_component_set_digest: d.clone(),
            identity_snapshot_manifest_digest: d.clone(),
            policy_bundle_digest: d.clone(),
            semantic_model_digest: d.clone(),
            named_set_registry_digest: d.clone(),
            blocklist_digest: d.clone(),
            policy_fact_state_digest: d.clone(),
            routing_snapshot_digest: d.clone(),
            provider_certification_registry_digest: d.clone(),
            mrpc_runtime_profile_digest: d.clone(),
            dynamic_event_profile_digest: d.clone(),
            rpc_invocation_profile_digest: d.clone(),
            capability_registry_digest: d.clone(),
            request_form_registry_digest: d.clone(),
            error_registry_digest: d.clone(),
            evidence_admission_profile_digest: d.clone(),
            emergency_deny_generation: 0,
            issued_at_ns: 1,
            not_before_ns: 2,
            hard_expiry_ns: 100,
            signer_id: "fleet-signer".into(),
            artifact_components: vec![ArtifactComponent {
                component_id: "openpc.runtime.configuration".into(),
                component_type: "openpc.runtime.configuration".into(),
                content_digest: d.clone(),
                semantic_digest: d.clone(),
                schema_id: 3101,
                schema_version: 1,
                size_bytes: bytes.len() as u64,
                required: true,
            }],
        };
        let manifest = TargetBootstrapManifest {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_runtime_id: capsule.target_runtime_id.clone(),
            fleet_id: capsule.fleet_id.clone(),
            fleet_signer_id: capsule.signer_id.clone(),
            agent_signer_id: "agent".into(),
            authority_signer_id: "authority".into(),
            fleet_runtime_public_key: signer.verifier().public_key_bytes(),
            identity_runtime_public_key: vec![],
            fact_verify_key: vec![],
            fact_verify_key_id: "fact".into(),
            contract_set_manifest_digest: d.clone(),
            schema_registry_digest: d.clone(),
            cose_purpose_registry_digest: d.clone(),
            complete_component_set_digest: d.clone(),
            capsule_id: capsule.capsule_id.clone(),
            capsule_generation: capsule.generation,
            capsule_digest: capsule.digest().unwrap(),
            identity_profile_digest: d.clone(),
            mrpc_runtime_profile: vec![],
            routing_source: vec![],
            certification_source: vec![],
            protected_class_set_digest: Digest::of("classes"),
            source_only: false,
            emergency_delivery: None,
            suspended_for_work: None,
            target_disposition: None,
        };
        Self {
            root,
            signer,
            manifest,
            capsule,
            artifacts: BTreeMap::from([(d, bytes)]),
        }
    }
    fn open(&self) -> RuntimeAgent {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .unwrap();
        RuntimeAgent::open_canonical(
            CapsuleTrust {
                target_id: self.manifest.target_runtime_id.clone(),
                fleet_id: self.manifest.fleet_id.clone(),
                fleet_signer_id: self.manifest.fleet_signer_id.clone(),
                agent_signer_id: self.manifest.agent_signer_id.clone(),
                contract_set_manifest_digest: self.manifest.contract_set_manifest_digest.clone(),
                schema_registry_digest: self.manifest.schema_registry_digest.clone(),
                cose_purpose_registry_digest: self.manifest.cose_purpose_registry_digest.clone(),
                complete_component_set_digest: self.manifest.complete_component_set_digest.clone(),
            },
            &self.manifest.fleet_runtime_public_key,
            [42; 32],
            8,
            16_384,
            &self.root.join("agent"),
            Arc::new(BootstrapArtifactAdmission),
        )
        .unwrap()
    }
    fn activate(&self, agent: &RuntimeAgent) {
        let digest = agent
            .prepare_capsule(
                self.signer.sign_capsule(&self.capsule).unwrap(),
                self.artifacts.clone(),
                2,
            )
            .unwrap();
        let token = RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: self.manifest.target_runtime_id.clone(),
            occurrence_id: "occurrence".into(),
            desired_generation_digest: digest,
            xds_version_digest: Digest::of("xds"),
            expected_previous_generation_digest: None,
            issued_at_ns: 2,
            expires_at_ns: 90,
        };
        agent
            .activate_capsule_authorized(&self.signer.sign_activation_token(&token).unwrap(), 3)
            .unwrap();
        let freshness = RevocationFreshnessLease {
            lease_id: "freshness".into(),
            target_runtime_id: self.manifest.target_runtime_id.clone(),
            fleet_id: self.manifest.fleet_id.clone(),
            lease_generation: 1,
            minimum_emergency_generation: 0,
            issued_at_ns: 3,
            expires_at_ns: 90,
            protected_class_set_digest: self.manifest.protected_class_set_digest.clone(),
            signer_id: self.manifest.fleet_signer_id.clone(),
        };
        agent
            .install_freshness_lease(&self.signer.sign_freshness_lease(&freshness).unwrap(), 3)
            .unwrap();
    }
    fn delivery(&self, generation: u64, keys: &[&str]) -> TargetEmergencyDelivery {
        let deny_keys =
            encode_emergency_deny_keys(&keys.iter().map(|s| (*s).into()).collect()).unwrap();
        let overlay = EmergencyDenyOverlay {
            overlay_id: format!("restriction-{generation}"),
            fleet_id: self.manifest.fleet_id.clone(),
            generation,
            issued_at_ns: 4,
            hard_expiry_ns: 80,
            deny_key_set_digest: Digest::of(&deny_keys),
            signer_id: self.manifest.fleet_signer_id.clone(),
        };
        TargetEmergencyDelivery {
            signed_overlay: self.signer.sign_emergency_overlay(&overlay).unwrap(),
            deny_keys,
        }
    }
    fn write(&self, delivery: Option<TargetEmergencyDelivery>) {
        let mut manifest = self.manifest.clone();
        manifest.emergency_delivery = delivery;
        write_target_bootstrap(&self.root.join("bootstrap"), manifest, [43; 32]).unwrap();
    }
    fn refresh(&self, agent: &RuntimeAgent, now: u64) -> RuntimeResult<()> {
        let key = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [43; 32])
            .unwrap()
            .verifier()
            .sec1_bytes();
        refresh_target_restrictions(
            agent,
            &self.manifest,
            &self.root.join("bootstrap"),
            &key,
            now,
        )
    }
    fn denied(&self, agent: &RuntimeAgent, now: u64) -> bool {
        agent
            .acquire_fresh_active_capsule(&self.manifest.protected_class_set_digest, now)
            .unwrap()
            .denies_any_scope(["urn:openpc:contract-method:revoked"])
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn signed_delivery_denies_replays_and_survives_target_restart() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    f.write(None);
    f.refresh(&agent, 4).unwrap();
    assert!(!f.denied(&agent, 4));
    let denied = f.delivery(2, &["urn:openpc:contract-method:revoked"]);
    f.write(Some(denied.clone()));
    f.refresh(&agent, 5).unwrap();
    assert!(f.denied(&agent, 5));
    f.refresh(&agent, 6).unwrap();
    drop(agent);
    let agent = f.open();
    assert!(f.denied(&agent, 7));
    // Replaying an old signed bootstrap without an overlay cannot clear custody.
    f.write(None);
    f.refresh(&agent, 7).unwrap();
    assert!(f.denied(&agent, 7));
    f.write(Some(f.delivery(1, &[])));
    assert_eq!(f.refresh(&agent, 8), Err(RuntimeError::GenerationMismatch));
    assert!(f.denied(&agent, 8));
    let mut altered = denied;
    altered.deny_keys = encode_emergency_deny_keys(&BTreeSet::new()).unwrap();
    f.write(Some(altered));
    assert_eq!(f.refresh(&agent, 8), Err(RuntimeError::InvalidDigest));
    assert!(f.denied(&agent, 8));
    assert!(matches!(
        agent.acquire_fresh_active_capsule(&f.manifest.protected_class_set_digest, 80),
        Err(RuntimeError::ExpiredAuthorization)
    ));
    // A strictly newer signed complete set is the existing explicit lift owner.
    f.write(Some(f.delivery(3, &[])));
    f.refresh(&agent, 9).unwrap();
    assert!(!f.denied(&agent, 9));
}

#[test]
fn expired_delivery_replay_preserves_custody_and_withdraws_request_ack() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    let delivery = f.delivery(2, &["urn:openpc:contract-method:revoked"]);
    f.write(Some(delivery.clone()));
    f.refresh(&agent, 5).unwrap();
    let classes = &f.manifest.protected_class_set_digest;
    let acknowledgement = f.root.join("request-observed.cose");
    // RuntimeAgent's custody regression exercises the genuine request ACK
    // producer. This transport test covers retirement of an existing file.
    fs::write(&acknowledgement, b"retained observation bytes").unwrap();
    // Expiry clears liveness without stopping the serving outcome owner.
    crate::runtime_target_observation::publish(&f.root, &agent, classes, 80).unwrap();
    assert!(!acknowledgement.exists());
    drop(agent);
    let agent = f.open();
    f.refresh(&agent, 81).unwrap();
    agent
        .with_emergency_overlay(|retained| {
            assert_eq!(
                retained,
                Some((
                    delivery.signed_overlay.as_slice(),
                    delivery.deny_keys.as_slice()
                ))
            );
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        agent.acquire_fresh_active_capsule(classes, 81),
        Err(RuntimeError::ExpiredAuthorization)
    ));
    crate::runtime_target_observation::publish(&f.root, &agent, classes, 81).unwrap();
    assert!(!acknowledgement.exists());
    // Even a correctly signed different expired set cannot enter custody.
    f.write(Some(f.delivery(3, &[])));
    assert_eq!(
        f.refresh(&agent, 81),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let mut altered = delivery;
    altered.deny_keys = encode_emergency_deny_keys(&BTreeSet::new()).unwrap();
    f.write(Some(altered));
    assert_eq!(f.refresh(&agent, 81), Err(RuntimeError::InvalidDigest));
}

#[test]
fn delivery_rejects_changed_target_configuration_and_retirement() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    let mut different = f.manifest.clone();
    different.emergency_delivery = Some(f.delivery(1, &["target"]));
    different.capsule_digest = Digest::of("another capsule");
    write_target_bootstrap(&f.root.join("bootstrap"), different, [43; 32]).unwrap();
    assert_eq!(f.refresh(&agent, 5), Err(RuntimeError::GenerationMismatch));
    assert!(!f.denied(&agent, 5));
    let mut different = f.manifest.clone();
    different.routing_source = vec![9];
    write_target_bootstrap(&f.root.join("bootstrap"), different, [43; 32]).unwrap();
    assert_eq!(f.refresh(&agent, 5), Err(RuntimeError::GenerationMismatch));
    let mut foreign = f.manifest.clone();
    foreign.emergency_delivery = Some(f.delivery(1, &["target"]));
    write_target_bootstrap(&f.root.join("bootstrap"), foreign, [44; 32]).unwrap();
    assert_eq!(
        f.refresh(&agent, 5),
        Err(RuntimeError::InvalidAuthorization)
    );
    assert!(!f.denied(&agent, 5));
    // Reject a large transport file after a bounded read, before JSON decoding.
    fs::OpenOptions::new()
        .write(true)
        .open(f.root.join("bootstrap/bootstrap.json"))
        .unwrap()
        .set_len((MAXIMUM_BOOTSTRAP_BYTES + 1) as u64)
        .unwrap();
    assert_eq!(
        f.refresh(&agent, 5),
        Err(RuntimeError::InvalidAuthorization)
    );
    retire_target_bootstrap(&f.root.join("bootstrap")).unwrap();
    assert_eq!(
        f.refresh(&agent, 5),
        Err(RuntimeError::InvalidAuthorization)
    );
}

#[test]
fn generation_restriction_preserves_other_scopes_and_does_not_revoke_a_successor() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    let mut manifest = f.manifest.clone();
    manifest.emergency_delivery = Some(f.delivery(7, &["urn:openpc:principal:unrelated"]));
    let delivery = restrict_target_generation(&manifest, [41; 32], 5, 80)
        .unwrap()
        .unwrap();
    let (overlay, keys) = f
        .signer
        .verifier()
        .verify_emergency_overlay_keys(&delivery.signed_overlay, &delivery.deny_keys)
        .unwrap();
    assert_eq!(overlay.generation, 8);
    assert_eq!(
        keys,
        BTreeSet::from([
            "urn:openpc:principal:unrelated".into(),
            format!("urn:openpc:resource:{}", manifest.capsule_id),
        ])
    );
    manifest.emergency_delivery = Some(delivery.clone());
    assert!(
        restrict_target_generation(&manifest, [41; 32], 6, 80)
            .unwrap()
            .is_none()
    );
    delivery.install(&agent, 5).unwrap();
    assert!(
        agent
            .acquire_fresh_active_capsule(&manifest.protected_class_set_digest, 6)
            .unwrap()
            .denies_any_scope(std::iter::empty())
    );
    drop(agent);
    let agent = f.open();
    assert!(
        agent
            .acquire_fresh_active_capsule(&manifest.protected_class_set_digest, 7)
            .unwrap()
            .denies_any_scope(std::iter::empty())
    );
    let mut successor = f.capsule.clone();
    successor.capsule_id = uuid::Uuid::now_v7().to_string();
    successor.generation = 2;
    successor.lifecycle_mode = 2;
    successor.previous_capsule_digest = Some(manifest.capsule_digest.clone());
    successor.issued_at_ns = 7;
    successor.not_before_ns = 8;
    let digest = agent
        .prepare_capsule(
            f.signer.sign_capsule(&successor).unwrap(),
            f.artifacts.clone(),
            8,
        )
        .unwrap();
    let token = RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: manifest.target_runtime_id.clone(),
        occurrence_id: "successor".into(),
        desired_generation_digest: digest,
        xds_version_digest: Digest::of("successor xds"),
        expected_previous_generation_digest: Some(manifest.capsule_digest),
        issued_at_ns: 8,
        expires_at_ns: 80,
    };
    agent
        .activate_capsule_authorized(&f.signer.sign_activation_token(&token).unwrap(), 9)
        .unwrap();
    let lease = agent
        .acquire_fresh_active_capsule(&manifest.protected_class_set_digest, 10)
        .unwrap();
    assert!(!lease.denies_any_scope(std::iter::empty()));
    assert!(lease.denies_any_scope(["urn:openpc:principal:unrelated"]));
}

#[test]
fn activation_renews_the_union_of_committed_and_pending_restrictions() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    assert!(
        renew_target_restrictions(&agent, &f.manifest, [41; 32], 5, 90)
            .unwrap()
            .is_none()
    );
    let committed = f.delivery(9, &["urn:openpc:principal:unrelated"]);
    committed.install(&agent, 5).unwrap();
    let mut manifest = f.manifest.clone();
    let generation_key = format!("urn:openpc:resource:{}", manifest.capsule_id);
    manifest.emergency_delivery = Some(f.delivery(8, &[&generation_key]));
    // Expired delivery still contributes every denial when renewed.
    let (generation, renewed) = renew_target_restrictions(&agent, &manifest, [41; 32], 81, 99)
        .unwrap()
        .unwrap();
    assert_eq!(generation, 10);
    let (overlay, keys) = f
        .signer
        .verifier()
        .verify_emergency_overlay_keys(&renewed.signed_overlay, &renewed.deny_keys)
        .unwrap();
    assert_eq!(overlay.issued_at_ns, 81);
    assert_eq!(overlay.hard_expiry_ns, 99);
    assert_eq!(
        keys,
        BTreeSet::from([generation_key, "urn:openpc:principal:unrelated".into()])
    );
    renewed.install(&agent, 81).unwrap();
    // Recovery can renew freshness without reactivating the capsule. Its
    // independent sequence must survive restart and keep all deny keys.
    let lease = RevocationFreshnessLease {
        lease_id: "recovered-freshness".into(),
        target_runtime_id: manifest.target_runtime_id.clone(),
        fleet_id: manifest.fleet_id.clone(),
        lease_generation: agent.next_freshness_generation().unwrap(),
        minimum_emergency_generation: generation,
        issued_at_ns: 81,
        expires_at_ns: 99,
        protected_class_set_digest: manifest.protected_class_set_digest.clone(),
        signer_id: manifest.fleet_signer_id.clone(),
    };
    assert_eq!(lease.lease_generation, 2);
    agent
        .install_freshness_lease(&f.signer.sign_freshness_lease(&lease).unwrap(), 81)
        .unwrap();
    drop(agent);
    let agent = f.open();
    assert_eq!(agent.next_freshness_generation().unwrap(), 3);
    let lease = agent
        .acquire_fresh_active_capsule(&manifest.protected_class_set_digest, 91)
        .unwrap();
    assert!(lease.denies_any_scope(std::iter::empty()));
    assert!(lease.denies_any_scope(["urn:openpc:principal:unrelated"]));
    drop(lease);
    assert!(renew_target_restrictions(&agent, &manifest, [44; 32], 82, 90).is_err());
    assert!(renew_target_restrictions(&agent, &manifest, [41; 32], 80, 90).is_err());
    assert!(renew_target_restrictions(&agent, &manifest, [41; 32], 90, 90).is_err());
    manifest
        .emergency_delivery
        .as_mut()
        .unwrap()
        .deny_keys
        .push(0);
    assert!(renew_target_restrictions(&agent, &manifest, [41; 32], 82, 90).is_err());
    agent
        .with_emergency_overlay(|stored| {
            assert_eq!(
                stored,
                Some((
                    renewed.signed_overlay.as_slice(),
                    renewed.deny_keys.as_slice()
                ))
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn signed_suspension_stops_refresh_and_restart_without_discarding_sources() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    f.write(None);
    f.refresh(&agent, 5).unwrap();
    let mut manifest = f.manifest.clone();
    manifest.suspended_for_work = Some(uuid::Uuid::now_v7().to_string());
    write_target_bootstrap(&f.root.join("bootstrap"), manifest.clone(), [43; 32]).unwrap();
    assert_eq!(f.refresh(&agent, 5), Err(RuntimeError::RuntimeUnavailable));
    let key = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [43; 32])
        .unwrap()
        .verifier()
        .sec1_bytes();
    let readback = read_target_bootstrap(&f.root.join("bootstrap"), &key).unwrap();
    assert_eq!(readback, manifest);
    assert_eq!(
        readback.require_serving(),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert_eq!(
        agent.active_canonical_generation().unwrap().unwrap().0,
        f.manifest.capsule_digest
    );
    manifest.suspended_for_work = Some("unbound-work".into());
    assert!(write_target_bootstrap(&f.root.join("bootstrap"), manifest, [43; 32]).is_err());
    assert_eq!(
        read_target_bootstrap(&f.root.join("bootstrap"), &key).unwrap(),
        readback
    );
}

#[test]
fn immutable_sources_are_readable_without_taking_the_live_target_writer_lock() {
    let f = Fixture::new();
    let agent = f.open();
    f.activate(&agent);
    let trust = CapsuleTrust {
        target_id: f.manifest.target_runtime_id.clone(),
        fleet_id: f.manifest.fleet_id.clone(),
        fleet_signer_id: f.manifest.fleet_signer_id.clone(),
        agent_signer_id: f.manifest.agent_signer_id.clone(),
        contract_set_manifest_digest: f.manifest.contract_set_manifest_digest.clone(),
        schema_registry_digest: f.manifest.schema_registry_digest.clone(),
        cose_purpose_registry_digest: f.manifest.cose_purpose_registry_digest.clone(),
        complete_component_set_digest: f.manifest.complete_component_set_digest.clone(),
    };
    let agent_public = RuntimeWireSigner::from_secret_bytes([42; 32])
        .unwrap()
        .verifier()
        .public_key_bytes();
    let directory = f.root.join("agent");
    let try_owner = || {
        RuntimeAgent::try_open_canonical(
            trust.clone(),
            &f.manifest.fleet_runtime_public_key,
            [42; 32],
            8,
            16_384,
            &directory,
            Arc::new(BootstrapArtifactAdmission),
        )
    };
    assert!(try_owner().unwrap().is_none());
    let read = |expected: &Digest, key: &[u8]| {
        RuntimeAgent::read_canonical_sources(
            &trust,
            &f.manifest.fleet_runtime_public_key,
            key,
            &directory,
            expected,
            &BootstrapArtifactAdmission,
            |capsule, artifacts| {
                assert_eq!(capsule, &f.capsule);
                assert_eq!(artifacts, &f.artifacts);
                capsule.digest()
            },
        )
    };
    assert_eq!(
        read(&f.manifest.capsule_digest, &agent_public).unwrap(),
        f.manifest.capsule_digest
    );
    let proof = RuntimeAgent::read_canonical_activation(
        &trust,
        &f.manifest.fleet_runtime_public_key,
        &agent_public,
        &directory,
        None,
        &BootstrapArtifactAdmission,
        |capsule, _, signed_token, signed_receipt| {
            let token = f.signer.verifier().verify_activation_token(signed_token)?;
            let receipt =
                openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(&agent_public)?
                    .verify_receipt(signed_receipt)?;
            assert_eq!(capsule.digest()?, token.desired_generation_digest);
            assert_eq!(receipt.capsule_digest, token.desired_generation_digest);
            assert_eq!(token.occurrence_id, "occurrence");
            Ok((token, receipt))
        },
    )
    .unwrap();
    assert_eq!(proof.1.agent_sequence, 1);
    assert!(
        pc_runtime_types::LocalJournal::<serde_json::Value>::open(&directory, "activation", || {
            serde_json::Value::Null
        })
        .is_err()
    );
    assert!(read(&Digest::of("another capsule"), &agent_public).is_err());
    let foreign = RuntimeWireSigner::from_secret_bytes([44; 32])
        .unwrap()
        .verifier()
        .public_key_bytes();
    assert!(read(&f.manifest.capsule_digest, &foreign).is_err());
    f.delivery(1, &["target"]).install(&agent, 5).unwrap();
    assert_eq!(
        read(&f.manifest.capsule_digest, &agent_public).unwrap(),
        f.manifest.capsule_digest
    );
    assert!(f.denied(&agent, 6));
    // A reader must leave interrupted staging and recovery exclusively owned.
    let pending = directory.join("activation.next");
    fs::write(&pending, b"interrupted staging").unwrap();
    read(&f.manifest.capsule_digest, &agent_public).unwrap();
    assert_eq!(fs::read(&pending).unwrap(), b"interrupted staging");
    drop(agent);
    let resumed = try_owner().unwrap().expect("the owner released custody");
    assert!(
        !pending.exists(),
        "only the new writer recovers interrupted staging"
    );
    assert!(f.denied(&resumed, 7));
    drop(resumed);
    let path = directory.join("activation.json");
    let committed = fs::read(&path).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    altered["canonical"]["active"]
        .as_object_mut()
        .unwrap()
        .remove("activation_token");
    fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(read(&f.manifest.capsule_digest, &agent_public).is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    altered["canonical"]["active"]["receipt"] = serde_json::json!([0]);
    fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(read(&f.manifest.capsule_digest, &agent_public).is_err());
    assert!(
        try_owner().is_err(),
        "bad custody must not be classified as a busy writer"
    );
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert!(read(&f.manifest.capsule_digest, &agent_public).is_err());
}

// Component regressions exercise real signatures and the real fsynced journal.
// The transport fixture is not evidence of the Control PG/TLS business journey.
mod disposition_tests {
    use super::*;
    use openpc_runtime_agent::target_disposition::{
        AuthorityFuture, CurrentTargetDisposition, HistoricalTargetConfirmation,
        TargetDispositionAuthority,
    };
    use pc_runtime_types::target_disposition::{
        TARGET_DISPOSITION_ACK_PURPOSE, TARGET_DISPOSITION_DELIVERY_PURPOSE,
        TargetDispositionAction, TargetDispositionCause, TargetDispositionDelivery,
        TargetDispositionIdentity, TargetDispositionSource, TargetDispositionVerifier,
        encode_target_disposition_delivery,
    };
    use std::sync::Mutex;

    fn release_clock_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap()
    }

    #[derive(Default)]
    struct ControlState {
        head: Option<(u64, Digest, Vec<u8>)>,
        acknowledgements: BTreeMap<Digest, Vec<u8>>,
        unavailable: bool,
        original_available: bool,
        original_reads: usize,
        wrong_challenge: bool,
        lose_ack_response: bool,
        after_ack: Option<(u64, Digest, Vec<u8>)>,
        read_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
        current_reads: usize,
        source_lifecycle_busy: bool,
    }
    #[derive(Default)]
    struct Control(Mutex<ControlState>);
    impl Control {
        fn head(&self, delivery: &TargetDispositionDelivery, signer: &PurposeSigner) -> Vec<u8> {
            let bytes = encode_target_disposition_delivery(&signer.sign(delivery.clone()).unwrap())
                .unwrap();
            self.0.lock().unwrap().head = Some((
                delivery.revision,
                delivery.committed_admission_digest.clone(),
                bytes.clone(),
            ));
            bytes
        }
        fn acknowledgements(&self) -> Vec<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .acknowledgements
                .values()
                .cloned()
                .collect()
        }
    }
    impl TargetDispositionAuthority for Control {
        fn read_current(
            &self,
            challenge: [u8; 32],
        ) -> AuthorityFuture<'_, CurrentTargetDisposition> {
            Box::pin(async move {
                let pause = {
                    let mut state = self.0.lock().unwrap();
                    state.current_reads += 1;
                    if state.source_lifecycle_busy {
                        return Err(RuntimeError::RuntimeUnavailable);
                    }
                    state.read_pause.clone()
                };
                if let Some((entered, resume)) = pause {
                    entered.notify_one();
                    resume.notified().await;
                }
                let state = self.0.lock().unwrap();
                if state.unavailable {
                    return Err(RuntimeError::RuntimeUnavailable);
                }
                let (revision, admission_digest, signed_delivery) =
                    state
                        .head
                        .clone()
                        .unwrap_or((0, Digest::of("unestablished"), vec![]));
                Ok(CurrentTargetDisposition {
                    challenge: if state.wrong_challenge {
                        vec![0; 32]
                    } else {
                        challenge.to_vec()
                    },
                    established: state.head.is_some(),
                    revision,
                    admission_digest: admission_digest.as_str().into(),
                    signed_acknowledgement: state
                        .acknowledgements
                        .get(&Digest::of(&signed_delivery))
                        .cloned()
                        .unwrap_or_default(),
                    signed_delivery,
                })
            })
        }
        fn read_original_confirmation(
            &self,
            challenge: [u8; 32],
        ) -> AuthorityFuture<'_, HistoricalTargetConfirmation> {
            Box::pin(async move {
                let mut state = self.0.lock().unwrap();
                state.original_reads += 1;
                if !state.original_available {
                    return Err(RuntimeError::RuntimeUnavailable);
                }
                let (revision, admission_digest, signed_delivery) =
                    state.head.clone().ok_or(RuntimeError::RuntimeUnavailable)?;
                Ok(HistoricalTargetConfirmation {
                    challenge: if state.wrong_challenge {
                        vec![0; 32]
                    } else {
                        challenge.to_vec()
                    },
                    revision,
                    admission_digest: admission_digest.as_str().into(),
                    signed_acknowledgement: state
                        .acknowledgements
                        .get(&Digest::of(&signed_delivery))
                        .cloned()
                        .unwrap_or_default(),
                    signed_delivery,
                })
            })
        }
        fn acknowledge<'a>(
            &'a self,
            digest: &'a Digest,
            bytes: &'a [u8],
        ) -> AuthorityFuture<'a, ()> {
            Box::pin(async move {
                let mut state = self.0.lock().unwrap();
                if state
                    .acknowledgements
                    .get(digest)
                    .is_some_and(|original| original != bytes)
                {
                    return Err(RuntimeError::Replay);
                }
                state
                    .acknowledgements
                    .insert(digest.clone(), bytes.to_vec());
                if let Some(next) = state.after_ack.take() {
                    state.head = Some(next);
                }
                if state.lose_ack_response {
                    return Err(RuntimeError::RuntimeUnavailable);
                }
                Ok(())
            })
        }
    }

    #[derive(Debug)]
    enum LifecycleObservation {
        Fenced(crate::runtime_target_service::lifecycle::Exit),
        Ready,
    }

    struct DispositionFixture {
        target: Fixture,
        control: Arc<Control>,
        signer: PurposeSigner,
        binding: TargetDispositionBootstrap,
    }
    impl DispositionFixture {
        fn new() -> Self {
            Self::with_expiry(100)
        }
        fn with_expiry(expiry: u64) -> Self {
            let mut target = Fixture::new();
            target.capsule.hard_expiry_ns = expiry;
            target.capsule.target_runtime_id = uuid::Uuid::now_v7().to_string();
            target.manifest.target_runtime_id = target.capsule.target_runtime_id.clone();
            target.manifest.participant_id = uuid::Uuid::now_v7().to_string();
            target.manifest.privacy_domain_id = uuid::Uuid::now_v7().to_string();
            target.manifest.capsule_digest = target.capsule.digest().unwrap();
            let binding = TargetDispositionBootstrap {
                target: TargetDispositionIdentity {
                    participant_id: target.manifest.participant_id.clone(),
                    privacy_domain_id: target.manifest.privacy_domain_id.clone(),
                    target_id: target.manifest.target_runtime_id.clone(),
                    credential_id: uuid::Uuid::now_v7().to_string(),
                    principal_id: uuid::Uuid::now_v7().to_string(),
                    credential_epoch: 1,
                    principal_epoch: 1,
                    certificate_digest: Digest::of("actual test certificate"),
                },
                source: TargetDispositionSource {
                    runtime_configuration_input_id: uuid::Uuid::now_v7().to_string(),
                    configuration_digest: Digest::of("full original test configuration"),
                    module_installation_id: uuid::Uuid::now_v7().to_string(),
                    module_configuration_generation_id: uuid::Uuid::now_v7().to_string(),
                    runtime_configuration_generation_id: target.capsule.capsule_id.clone(),
                    capsule_digest: target.manifest.capsule_digest.clone(),
                    xds_version_digest: Digest::of("xds"),
                    predecessor_capsule_digest: None,
                    original_work_id: uuid::Uuid::now_v7().to_string(),
                    original_operation_id: uuid::Uuid::now_v7().to_string(),
                    original_execution_attempt_id: uuid::Uuid::now_v7().to_string(),
                },
                credential_predecessor: None,
            };
            target.manifest.target_disposition = Some(binding.clone());
            Self {
                target,
                binding,
                control: Arc::new(Control::default()),
                signer: PurposeSigner::from_secret_bytes(
                    TARGET_DISPOSITION_DELIVERY_PURPOSE,
                    [71; 32],
                )
                .unwrap(),
            }
        }
        fn install(&self, agent: &RuntimeAgent) {
            agent
                .install_target_disposition_owner(
                    self.binding.target.clone(),
                    self.binding.source.clone(),
                    &self.signer.verifier().sec1_bytes(),
                    [72; 32],
                    self.control.clone(),
                )
                .unwrap();
        }
        fn start(&self) -> RuntimeAgent {
            let agent = self.target.open();
            self.target.activate(&agent);
            self.install(&agent);
            agent
        }
        fn withdrawal(&self) -> TargetDispositionDelivery {
            TargetDispositionDelivery {
                version: 1,
                target: self.binding.target.clone(),
                source: self.binding.source.clone(),
                cause: TargetDispositionCause::Activation {
                    work_id: uuid::Uuid::now_v7().to_string(),
                    operation_id: uuid::Uuid::now_v7().to_string(),
                    execution_attempt_id: None,
                },
                action: TargetDispositionAction::Withdraw,
                revision: 1,
                previous_revision: 0,
                previous_delivery_digest: None,
                committed_admission_digest: Digest::of("committed test withdrawal"),
            }
        }
        fn confirmation(&self) -> TargetDispositionDelivery {
            let mut confirmation = self.withdrawal();
            confirmation.action = TargetDispositionAction::ConfirmActivation;
            confirmation.cause = TargetDispositionCause::Activation {
                work_id: self.binding.source.original_work_id.clone(),
                operation_id: self.binding.source.original_operation_id.clone(),
                execution_attempt_id: Some(
                    self.binding.source.original_execution_attempt_id.clone(),
                ),
            };
            confirmation
        }
        fn successor(
            &self,
            prior: &TargetDispositionDelivery,
            wire: &[u8],
            action: TargetDispositionAction,
        ) -> TargetDispositionDelivery {
            let mut next = prior.clone();
            next.action = action;
            next.previous_revision = prior.revision;
            next.revision += 1;
            next.previous_delivery_digest = Some(Digest::of(wire));
            next.committed_admission_digest =
                Digest::of(format!("committed test admission {}", next.revision));
            next
        }
        fn denied(&self, agent: &RuntimeAgent) {
            assert!(agent.require_current_target_disposition().is_err());
            assert!(
                agent
                    .acquire_fresh_active_capsule(
                        &self.target.manifest.protected_class_set_digest,
                        7
                    )
                    .is_err()
            );
        }
        fn credential_successor(&self) -> TargetDispositionIdentity {
            let mut successor = self.binding.target.clone();
            successor.credential_id = uuid::Uuid::now_v7().to_string();
            successor.credential_epoch += 1;
            successor.certificate_digest = Digest::of("governed successor certificate");
            successor
        }
        fn install_successor(
            &self,
            agent: &RuntimeAgent,
            successor: TargetDispositionIdentity,
        ) -> RuntimeResult<()> {
            agent.install_target_disposition_owner_with_credential_predecessor(
                successor,
                self.binding.source.clone(),
                &self.signer.verifier().sec1_bytes(),
                [72; 32],
                self.control.clone(),
                Some(self.binding.target.clone()),
            )
        }
        async fn lifecycle_attempt(
            &self,
            mut stop: tokio::sync::watch::Receiver<bool>,
            observations: &tokio::sync::mpsc::UnboundedSender<LifecycleObservation>,
        ) -> Result<crate::runtime_target_service::lifecycle::Attempt, String> {
            use crate::runtime_target_service::lifecycle::{self, Attempt, Exit};
            use openpc_runtime_agent::ipc::{OwnedUnixListener, UnixSocketPolicy};
            use std::os::unix::fs::MetadataExt;
            let key = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [43; 32])
                .unwrap()
                .verifier()
                .sec1_bytes();
            let manifest = match read_target_bootstrap(&self.target.root.join("bootstrap"), &key) {
                Ok(manifest) => manifest,
                Err(_) => {
                    observations
                        .send(LifecycleObservation::Fenced(Exit::BootstrapUnavailable))
                        .unwrap();
                    return Ok(Attempt {
                        result: Ok(Exit::BootstrapUnavailable),
                        custody: std::sync::Weak::new(),
                    });
                }
            };
            let agent = Arc::new(self.target.open());
            let custody = Arc::downgrade(&agent);
            let binding = manifest.target_disposition.as_ref().unwrap();
            agent
                .install_target_disposition_owner(
                    binding.target.clone(),
                    binding.source.clone(),
                    &self.signer.verifier().sec1_bytes(),
                    [72; 32],
                    self.control.clone(),
                )
                .unwrap();
            let exit = match lifecycle::reconcile(
                &agent,
                &manifest,
                agent.reconcile_target_disposition(),
                &mut stop,
            )
            .await
            {
                Err(exit) => exit,
                Ok(()) => {
                    refresh_target_restrictions(
                        &agent,
                        &manifest,
                        &self.target.root.join("bootstrap"),
                        &key,
                        7,
                    )
                    .unwrap();
                    agent
                        .acquire_fresh_active_capsule(&manifest.protected_class_set_digest, 7)
                        .unwrap();
                    let metadata = fs::metadata(&self.target.root).unwrap();
                    let policy = UnixSocketPolicy {
                        owner_uid: metadata.uid(),
                        group_gid: metadata.gid(),
                        envoy_uid: metadata.uid(),
                    };
                    let pds = OwnedUnixListener::bind(&self.target.root.join("pds.sock"), policy)
                        .await
                        .unwrap();
                    let broker = if manifest.source_only {
                        None
                    } else {
                        Some(
                            OwnedUnixListener::bind(&self.target.root.join("broker.sock"), policy)
                                .await
                                .unwrap(),
                        )
                    };
                    observations.send(LifecycleObservation::Ready).unwrap();
                    let exit = lifecycle::watch_current(
                        &agent,
                        &manifest,
                        &self.target.root.join("bootstrap"),
                        &key,
                        &mut stop,
                    )
                    .await
                    .unwrap();
                    agent.fence_target_disposition().unwrap();
                    drop(broker);
                    drop(pds);
                    exit
                }
            };
            self.denied(&agent);
            drop(agent);
            observations
                .send(LifecycleObservation::Fenced(exit.clone()))
                .unwrap();
            Ok(Attempt {
                result: Ok(exit),
                custody,
            })
        }

        async fn restore(&self, agent: &RuntimeAgent) -> (TargetDispositionDelivery, Vec<u8>) {
            let withdraw = self.withdrawal();
            let wire = self.control.head(&withdraw, &self.signer);
            assert_eq!(
                agent.reconcile_target_disposition().await.unwrap(),
                TargetDispositionAction::Withdraw
            );
            self.denied(agent);
            let restore = self.successor(&withdraw, &wire, TargetDispositionAction::Restore);
            let wire = self.control.head(&restore, &self.signer);
            assert_eq!(
                agent.reconcile_target_disposition().await.unwrap(),
                TargetDispositionAction::Restore
            );
            agent.require_current_target_disposition().unwrap();
            (restore, wire)
        }
    }

    // Typed serialization oracle copied from immutable 10118225 before the
    // predecessor field existed. The old type, not the new type, signs bytes.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyDispositionBootstrap {
        target: TargetDispositionIdentity,
        source: TargetDispositionSource,
    }
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyBootstrapManifest {
        version: u32,
        participant_id: String,
        privacy_domain_id: String,
        target_runtime_id: String,
        fleet_id: String,
        fleet_signer_id: String,
        agent_signer_id: String,
        authority_signer_id: String,
        fleet_runtime_public_key: Vec<u8>,
        identity_runtime_public_key: Vec<u8>,
        fact_verify_key: Vec<u8>,
        fact_verify_key_id: String,
        contract_set_manifest_digest: Digest,
        schema_registry_digest: Digest,
        cose_purpose_registry_digest: Digest,
        complete_component_set_digest: Digest,
        capsule_id: String,
        capsule_generation: u64,
        capsule_digest: Digest,
        identity_profile_digest: Digest,
        mrpc_runtime_profile: Vec<u8>,
        routing_source: Vec<u8>,
        certification_source: Vec<u8>,
        protected_class_set_digest: Digest,
        /// The active capsule carries only dedicated indexer restrictions and
        /// admits no invocation route or Fact publication.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        source_only: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        emergency_delivery: Option<TargetEmergencyDelivery>,
        /// Signed local process handoff. This only stops serving; the existing
        /// one-use activation token remains necessary to change journal custody.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suspended_for_work: Option<String>,
        /// Original custody and workload identity, resolved by the canonical worker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_disposition: Option<LegacyDispositionBootstrap>,
    }

    #[test]
    fn original_nested_bootstrap_signed_bytes_survive_optional_predecessor_and_tampering_fails() {
        let f = DispositionFixture::new();
        let original: LegacyBootstrapManifest =
            serde_json::from_slice(&pc_runtime_types::canonical_bytes(&f.target.manifest).unwrap())
                .unwrap();
        assert!(original.target_disposition.is_some());
        let signer = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [43; 32]).unwrap();
        let signed = signer.sign(original).unwrap();
        let old_wire = serde_json::to_vec(&signed).unwrap();
        let parsed: SignedEnvelope<TargetBootstrapManifest> =
            serde_json::from_slice(&old_wire).unwrap();
        assert_eq!(
            pc_runtime_types::canonical_bytes(&parsed.claims).unwrap(),
            pc_runtime_types::canonical_bytes(&signed.claims).unwrap()
        );
        signer.verifier().verify(&parsed).unwrap();
        parsed.claims.validate().unwrap();
        let mut current = parsed.claims.clone();
        current.target_disposition.as_mut().unwrap().target = f.credential_successor();
        current
            .target_disposition
            .as_mut()
            .unwrap()
            .credential_predecessor = Some(f.binding.target.clone());
        current.validate().unwrap();
        let signed_current = signer.sign(current).unwrap();
        signer.verifier().verify(&signed_current).unwrap();
        // An old executable's closed binding rejects the new optional presence.
        assert!(
            serde_json::from_slice::<SignedEnvelope<LegacyBootstrapManifest>>(
                &serde_json::to_vec(&signed_current).unwrap()
            )
            .is_err()
        );
        for field in 0..9 {
            let mut altered = signed_current.clone();
            let predecessor = altered
                .claims
                .target_disposition
                .as_mut()
                .unwrap()
                .credential_predecessor
                .as_mut()
                .unwrap();
            match field {
                0 => predecessor.participant_id = uuid::Uuid::now_v7().to_string(),
                1 => predecessor.privacy_domain_id = uuid::Uuid::now_v7().to_string(),
                2 => predecessor.target_id = uuid::Uuid::now_v7().to_string(),
                3 => predecessor.credential_id = uuid::Uuid::now_v7().to_string(),
                4 => predecessor.principal_id = uuid::Uuid::now_v7().to_string(),
                5 => predecessor.credential_epoch += 1,
                6 => predecessor.principal_epoch += 1,
                7 => predecessor.certificate_digest = Digest::of("tampered historical certificate"),
                _ => {
                    altered
                        .claims
                        .target_disposition
                        .as_mut()
                        .unwrap()
                        .credential_predecessor = None
                }
            }
            assert!(signer.verifier().verify(&altered).is_err());
        }
        for field in 0..4 {
            let mut invalid = signed_current.claims.clone();
            let binding = invalid.target_disposition.as_mut().unwrap();
            match field {
                0 => binding.credential_predecessor = Some(binding.target.clone()),
                1 => binding.target.credential_epoch += 1,
                2 => {
                    binding
                        .credential_predecessor
                        .as_mut()
                        .unwrap()
                        .principal_epoch += 1
                }
                _ => {
                    binding.credential_predecessor.as_mut().unwrap().target_id =
                        uuid::Uuid::now_v7().to_string()
                }
            }
            let signed_invalid = signer.sign(invalid).unwrap();
            signer.verifier().verify(&signed_invalid).unwrap();
            assert!(signed_invalid.claims.validate().is_err());
        }
    }
    #[tokio::test]
    async fn credential_adoption_retains_old_bytes_and_acknowledges_only_current_platform_withdrawal()
     {
        use pc_runtime_types::target_disposition::{
            TargetDispositionDependency, TargetDispositionInstalledState,
        };
        let f = DispositionFixture::new();
        let agent = f.start();
        let old = f.confirmation();
        let old_wire = f.control.head(&old, &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        let old_ack = f.control.acknowledgements().pop().unwrap();
        let original_receipts = agent.replay_canonical_receipts().unwrap();
        let original_path = f.target.root.join("agent/activation.json");
        let original = fs::read(&original_path).unwrap();
        drop(agent);
        let successor = f.credential_successor();
        let agent = f.target.open();
        f.install_successor(&agent, successor.clone()).unwrap();
        let retained = f.target.root.join("agent").join(format!(
            "activation.custody.{}.json",
            Digest::of(&original).as_str()
        ));
        assert_eq!(fs::read(&retained).unwrap(), original);
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.denied(&agent);
        assert_eq!(f.control.acknowledgements(), vec![old_ack.clone()]);
        assert_eq!(f.control.0.lock().unwrap().original_reads, 0);
        let mut withdrawal = f.successor(&old, &old_wire, TargetDispositionAction::Withdraw);
        withdrawal.target = successor.clone();
        withdrawal.cause = TargetDispositionCause::Dependency {
            owner: TargetDispositionDependency::Platform,
            resource_id: uuid::Uuid::now_v7().to_string(),
            operation_id: uuid::Uuid::now_v7().to_string(),
            revision: 1,
        };
        let wire = f.control.head(&withdrawal, &f.signer);
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Withdraw
        );
        let verifier = TargetDispositionVerifier::from_host_keys(
            successor.clone(),
            &f.signer.verifier().sec1_bytes(),
            &PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_ACK_PURPOSE, [72; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
        )
        .unwrap();
        let delivery = verifier.verify_delivery(&wire, &f.binding.source).unwrap();
        let acknowledgements = f.control.acknowledgements();
        assert_eq!(acknowledgements.len(), 2);
        assert!(acknowledgements.contains(&old_ack));
        let new_ack = acknowledgements
            .iter()
            .find(|ack| **ack != old_ack)
            .unwrap();
        let verified_ack = verifier.verify_acknowledgement(new_ack, &delivery).unwrap();
        assert_eq!(verified_ack.claims().target, successor);
        assert_eq!(verified_ack.claims().journal_sequence, 2);
        assert_eq!(
            verified_ack.claims().installed_state,
            TargetDispositionInstalledState::NewUseDenied
        );
        assert_eq!(
            agent.replay_canonical_receipts().unwrap(),
            original_receipts
        );
        f.denied(&agent);
        drop(agent);
        let reopened = f.target.open();
        f.install_successor(&reopened, successor).unwrap();
        reopened.reconcile_target_disposition().await.unwrap();
        assert_eq!(f.control.acknowledgements(), acknowledgements);
        assert_eq!(fs::read(&retained).unwrap(), original);
        f.denied(&reopened);
    }

    #[tokio::test]
    async fn credential_adoption_rejects_restore_other_cause_and_broken_original_chain_without_ack()
    {
        use pc_runtime_types::target_disposition::TargetDispositionDependency;
        for fault in 0..5 {
            let f = DispositionFixture::new();
            let agent = f.start();
            let old = f.confirmation();
            let old_wire = f.control.head(&old, &f.signer);
            agent.reconcile_target_disposition().await.unwrap();
            let original_ack = f.control.acknowledgements();
            drop(agent);
            let successor = f.credential_successor();
            let agent = f.target.open();
            f.install_successor(&agent, successor.clone()).unwrap();
            let mut withdrawal = f.successor(&old, &old_wire, TargetDispositionAction::Withdraw);
            withdrawal.target = successor;
            withdrawal.cause = TargetDispositionCause::Dependency {
                owner: TargetDispositionDependency::Platform,
                resource_id: uuid::Uuid::now_v7().to_string(),
                operation_id: uuid::Uuid::now_v7().to_string(),
                revision: 1,
            };
            match fault {
                0 => withdrawal.action = TargetDispositionAction::Restore,
                1 => withdrawal.cause = old.cause.clone(),
                2 => withdrawal.source.original_work_id = uuid::Uuid::now_v7().to_string(),
                3 => withdrawal.previous_delivery_digest = Some(Digest::of("foreign signed bytes")),
                _ => withdrawal.previous_revision = 0,
            }
            // Invalid chain shape can also be rejected by the wire owner itself.
            if let Ok(signed) = f.signer.sign(withdrawal)
                && let Ok(wire) = encode_target_disposition_delivery(&signed)
            {
                let claims = signed.claims;
                f.control.0.lock().unwrap().head =
                    Some((claims.revision, claims.committed_admission_digest, wire));
                assert!(agent.reconcile_target_disposition().await.is_err());
            }
            assert_eq!(f.control.acknowledgements(), original_ack);
            f.denied(&agent);
        }
    }

    #[test]
    fn credential_predecessor_is_exact_one_hop_and_cannot_replace_identity_scope() {
        for fault in 0..7 {
            let f = DispositionFixture::new();
            let agent = f.target.open();
            f.target.activate(&agent);
            let mut successor = f.credential_successor();
            match fault {
                0 => successor.participant_id = uuid::Uuid::now_v7().to_string(),
                1 => successor.privacy_domain_id = uuid::Uuid::now_v7().to_string(),
                2 => successor.principal_id = uuid::Uuid::now_v7().to_string(),
                3 => successor.principal_epoch += 1,
                4 => successor.credential_id = f.binding.target.credential_id.clone(),
                5 => successor.certificate_digest = f.binding.target.certificate_digest.clone(),
                _ => successor.credential_epoch += 1,
            }
            assert!(f.install_successor(&agent, successor).is_err());
            assert!(f.control.acknowledgements().is_empty());
        }
    }

    #[tokio::test]
    async fn withdrawal_ack_is_exact_durable_and_preserves_original_activation() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let activation = agent.active_canonical_generation().unwrap();
        let receipts = agent.replay_canonical_receipts().unwrap();
        let original_token = RuntimeAgent::read_canonical_activation(
            &CapsuleTrust {
                target_id: f.target.manifest.target_runtime_id.clone(),
                fleet_id: f.target.manifest.fleet_id.clone(),
                fleet_signer_id: f.target.manifest.fleet_signer_id.clone(),
                agent_signer_id: f.target.manifest.agent_signer_id.clone(),
                contract_set_manifest_digest: f
                    .target
                    .manifest
                    .contract_set_manifest_digest
                    .clone(),
                schema_registry_digest: f.target.manifest.schema_registry_digest.clone(),
                cose_purpose_registry_digest: f
                    .target
                    .manifest
                    .cose_purpose_registry_digest
                    .clone(),
                complete_component_set_digest: f
                    .target
                    .manifest
                    .complete_component_set_digest
                    .clone(),
            },
            &f.target.manifest.fleet_runtime_public_key,
            &RuntimeWireSigner::from_secret_bytes([42; 32])
                .unwrap()
                .verifier()
                .public_key_bytes(),
            &f.target.root.join("agent"),
            None,
            &BootstrapArtifactAdmission,
            |_, _, token, _| Ok(token.to_vec()),
        )
        .unwrap();
        f.denied(&agent);
        let delivery = f.withdrawal();
        let wire = f.control.head(&delivery, &f.signer);
        f.control.0.lock().unwrap().lose_ack_response = true;
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.denied(&agent);
        let original = f.control.acknowledgements();
        assert_eq!(original.len(), 1);
        let verifier = TargetDispositionVerifier::from_host_keys(
            f.binding.target.clone(),
            &f.signer.verifier().sec1_bytes(),
            &PurposeSigner::from_secret_bytes(TARGET_DISPOSITION_ACK_PURPOSE, [72; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
        )
        .unwrap();
        let verified = verifier.verify_delivery(&wire, &f.binding.source).unwrap();
        verifier
            .verify_acknowledgement(&original[0], &verified)
            .unwrap();
        drop(agent);
        let agent = f.target.open();
        f.denied(&agent); // Reopening without the installed authority cannot bypass custody.
        f.install(&agent);
        f.control.0.lock().unwrap().lose_ack_response = false;
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Withdraw
        );
        assert_eq!(f.control.acknowledgements(), original);
        assert_eq!(agent.active_canonical_generation().unwrap(), activation);
        assert_eq!(agent.replay_canonical_receipts().unwrap(), receipts);
        assert_eq!(
            agent
                .activate_capsule_authorized(&original_token, 7)
                .unwrap(),
            receipts[0]
        );
        assert_eq!(agent.replay_canonical_receipts().unwrap(), receipts);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn missing_pending_transport_and_challenge_fail_closed_without_ack() {
        let f = DispositionFixture::new();
        let agent = f.start();
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.denied(&agent);
        f.control.0.lock().unwrap().unavailable = true;
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.control.0.lock().unwrap().unavailable = false;
        let withdrawal = f.withdrawal();
        f.control.head(&withdrawal, &f.signer);
        f.control.0.lock().unwrap().wrong_challenge = true;
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.control.0.lock().unwrap().wrong_challenge = false;
        f.control.0.lock().unwrap().head = Some((3, Digest::of("pending"), vec![]));
        assert!(agent.reconcile_target_disposition().await.is_err());
        drop(agent);
        let agent = f.target.open();
        f.install(&agent);
        f.control.head(&withdrawal, &f.signer);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert!(f.control.acknowledgements().is_empty());
        f.denied(&agent);
    }

    #[tokio::test]
    async fn fresh_restore_is_required_again_after_restart_and_later_withdrawal_wins() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let (restored, restore_wire) = f.restore(&agent).await;
        agent
            .acquire_fresh_active_capsule(&f.target.manifest.protected_class_set_digest, 7)
            .unwrap();
        let originals = agent.replay_canonical_receipts().unwrap();
        drop(agent);
        let agent = f.target.open();
        f.install(&agent);
        f.denied(&agent);
        agent.reconcile_target_disposition().await.unwrap();
        let withdraw = f.successor(&restored, &restore_wire, TargetDispositionAction::Withdraw);
        f.control.head(&withdraw, &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        f.denied(&agent);
        f.control.head(&restored, &f.signer);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert_eq!(agent.replay_canonical_receipts().unwrap(), originals);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn conflicting_revision_and_wrong_original_cause_cannot_restore() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let withdrawal = f.withdrawal();
        let wire = f.control.head(&withdrawal, &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        let mut conflict = withdrawal.clone();
        conflict.cause = f.withdrawal().cause;
        f.control.head(&conflict, &f.signer);
        assert!(agent.reconcile_target_disposition().await.is_err());
        let mut restore = f.successor(&withdrawal, &wire, TargetDispositionAction::Restore);
        restore.cause = conflict.cause;
        f.control.head(&restore, &f.signer);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert_eq!(f.control.acknowledgements().len(), 1);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn full_journal_rollback_cannot_regenerate_a_control_retained_ack() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let path = f.target.root.join("agent/activation.json");
        let old = fs::read(&path).unwrap();
        let withdrawal = f.withdrawal();
        f.control.head(&withdrawal, &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        let ack = f.control.acknowledgements();
        drop(agent);
        fs::write(&path, old).unwrap(); // Deliberate whole-snapshot rollback fixture.
        let agent = f.target.open();
        f.install(&agent);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert_eq!(f.control.acknowledgements(), ack);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn journal_write_failure_never_publishes_ack_or_rewrites_original_effect() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let original = agent.replay_canonical_receipts().unwrap();
        let withdrawal = f.withdrawal();
        f.control.head(&withdrawal, &f.signer);
        let pending = f.target.root.join("agent/activation.next");
        fs::create_dir(&pending).unwrap();
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert!(f.control.acknowledgements().is_empty());
        f.denied(&agent);
        drop(agent);
        fs::remove_dir(&pending).unwrap();
        let agent = f.target.open();
        assert_eq!(agent.replay_canonical_receipts().unwrap(), original);
        f.install(&agent);
        agent.reconcile_target_disposition().await.unwrap();
        assert_eq!(f.control.acknowledgements().len(), 1);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn changed_head_during_restore_ack_never_admits_requests() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let withdraw = f.withdrawal();
        let wire = f.control.head(&withdraw, &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        let restore = f.successor(&withdraw, &wire, TargetDispositionAction::Restore);
        let restore_wire = f.control.head(&restore, &f.signer);
        let later = f.successor(&restore, &restore_wire, TargetDispositionAction::Withdraw);
        let later_wire =
            encode_target_disposition_delivery(&f.signer.sign(later.clone()).unwrap()).unwrap();
        f.control.0.lock().unwrap().after_ack = Some((
            later.revision,
            later.committed_admission_digest.clone(),
            later_wire,
        ));
        assert!(agent.reconcile_target_disposition().await.is_err());
        f.denied(&agent);
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Withdraw
        );
        f.denied(&agent);
    }

    #[tokio::test]
    async fn signed_wrong_principal_full_source_or_key_is_not_authority() {
        for invalid in 0..7 {
            let f = DispositionFixture::new();
            let agent = f.start();
            let mut withdrawal = f.withdrawal();
            if invalid == 0 {
                withdrawal.target.principal_id = uuid::Uuid::now_v7().to_string();
            }
            if invalid == 1 {
                withdrawal.source.configuration_digest = Digest::of("substituted component");
            }
            if invalid == 3 {
                withdrawal.target.participant_id = uuid::Uuid::now_v7().to_string();
            }
            if invalid == 4 {
                withdrawal.target.privacy_domain_id = uuid::Uuid::now_v7().to_string();
            }
            if invalid == 5 {
                withdrawal.target.credential_epoch += 1;
            }
            if invalid == 6 {
                withdrawal.target.certificate_digest = Digest::of("other certificate");
            }
            if invalid == 2 {
                f.control.head(
                    &withdrawal,
                    &PurposeSigner::from_secret_bytes(
                        TARGET_DISPOSITION_DELIVERY_PURPOSE,
                        [73; 32],
                    )
                    .unwrap(),
                );
            } else {
                f.control.head(&withdrawal, &f.signer);
            }
            assert!(agent.reconcile_target_disposition().await.is_err());
            assert!(f.control.acknowledgements().is_empty());
            f.denied(&agent);
        }
    }

    #[tokio::test]
    async fn independently_signed_freshness_cannot_clear_withdrawal() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.control.head(&f.withdrawal(), &f.signer);
        agent.reconcile_target_disposition().await.unwrap();
        let lease = RevocationFreshnessLease {
            lease_id: "renewed".into(),
            target_runtime_id: f.binding.target.target_id.clone(),
            fleet_id: f.target.manifest.fleet_id.clone(),
            lease_generation: 2,
            minimum_emergency_generation: 0,
            issued_at_ns: 4,
            expires_at_ns: 95,
            protected_class_set_digest: f.target.manifest.protected_class_set_digest.clone(),
            signer_id: f.target.manifest.fleet_signer_id.clone(),
        };
        agent
            .install_freshness_lease(&f.target.signer.sign_freshness_lease(&lease).unwrap(), 4)
            .unwrap();
        f.denied(&agent);
    }

    #[tokio::test]
    async fn restore_without_the_exact_previous_withdrawal_is_not_bootstrap_authority() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let withdrawal = f.withdrawal();
        let wire = encode_target_disposition_delivery(&f.signer.sign(withdrawal.clone()).unwrap())
            .unwrap();
        let restore = f.successor(&withdrawal, &wire, TargetDispositionAction::Restore);
        f.control.head(&restore, &f.signer);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert!(f.control.acknowledgements().is_empty());
        f.denied(&agent);
    }

    // The external Control transport is a component fixture. Capsule activation,
    // receipt bytes, journal restart, owner lifetime and ACKs use the real SDK.
    #[tokio::test]
    async fn expired_handover_continues_the_prepared_owner_and_preserves_original_receipts() {
        for credential_transition in [false, true] {
            for corrupt_receipt in [false, true] {
                let mut f = DispositionFixture::new();
                let agent = f.start();
                let confirmed = f.confirmation();
                let confirmed_wire = f.control.head(&confirmed, &f.signer);
                agent.reconcile_target_disposition().await.unwrap();
                let mut source = f.binding.source.clone();
                source.original_work_id = uuid::Uuid::now_v7().to_string();
                source.original_operation_id = uuid::Uuid::now_v7().to_string();
                source.original_execution_attempt_id = uuid::Uuid::now_v7().to_string();
                let mut withdrawal = f.successor(
                    &confirmed,
                    &confirmed_wire,
                    TargetDispositionAction::Withdraw,
                );
                withdrawal.cause = TargetDispositionCause::Activation {
                    work_id: source.original_work_id.clone(),
                    operation_id: source.original_operation_id.clone(),
                    execution_attempt_id: None,
                };
                let withdrawal_wire = f.control.head(&withdrawal, &f.signer);
                agent.reconcile_target_disposition().await.unwrap();
                let mut next = f.target.capsule.clone();
                next.capsule_id = uuid::Uuid::now_v7().to_string();
                next.generation = 2;
                next.lifecycle_mode = 2;
                next.previous_capsule_digest = Some(f.binding.source.capsule_digest.clone());
                let digest = agent
                    .prepare_capsule(
                        f.target.signer.sign_capsule(&next).unwrap(),
                        f.target.artifacts.clone(),
                        7,
                    )
                    .unwrap();
                let token = RuntimeActivationToken {
                    token_id: uuid::Uuid::now_v7().to_string(),
                    target_runtime_id: f.binding.target.target_id.clone(),
                    occurrence_id: uuid::Uuid::now_v7().to_string(),
                    desired_generation_digest: digest.clone(),
                    xds_version_digest: Digest::of("successor xds"),
                    expected_previous_generation_digest: next.previous_capsule_digest.clone(),
                    issued_at_ns: 7,
                    expires_at_ns: 90,
                };
                let receipt = agent
                    .activate_capsule_authorized(
                        &f.target.signer.sign_activation_token(&token).unwrap(),
                        8,
                    )
                    .unwrap();
                let original_receipts = agent.replay_canonical_receipts().unwrap();
                drop(agent);
                source.runtime_configuration_generation_id = next.capsule_id.clone();
                source.capsule_digest = digest.clone();
                source.predecessor_capsule_digest = next.previous_capsule_digest;
                source.xds_version_digest = token.xds_version_digest;
                f.binding.source = source.clone();
                f.target.manifest.target_disposition = Some(f.binding.clone());
                f.target.manifest.capsule_id = next.capsule_id;
                f.target.manifest.capsule_generation = 2;
                f.target.manifest.capsule_digest = digest;
                let abandoned = serde_json::json!({"version":1,"action":"Withdraw","revision":3,
                "previous_revision":2,"previous_delivery_digest":Digest::of(&withdrawal_wire),"target":f.binding.target,
                "source":source,"cause":{"kind":"Activation","work_id":source.original_work_id,
                "operation_id":source.original_operation_id,"execution_attempt_id":source.original_execution_attempt_id}});
                let abandoned_digest =
                    Digest::of(pc_runtime_types::canonical_bytes(&abandoned).unwrap());
                f.control.0.lock().unwrap().head = Some((3, abandoned_digest.clone(), vec![]));
                let abandoned_target = f.binding.target.clone();
                if credential_transition {
                    f.binding.target = f.credential_successor();
                    f.binding.credential_predecessor = Some(abandoned_target.clone());
                    f.target.manifest.target_disposition = Some(f.binding.clone());
                }
                let agent = f.target.open();
                agent
                    .install_target_disposition_owner_with_credential_predecessor(
                        f.binding.target.clone(),
                        f.binding.source.clone(),
                        &f.signer.verifier().sec1_bytes(),
                        [72; 32],
                        f.control.clone(),
                        f.binding.credential_predecessor.clone(),
                    )
                    .unwrap();
                let expected = disposition::ExpiredUnsignedDenialHandover {
                    abandoned_revision: 3,
                    abandoned_admission_digest: abandoned_digest.clone(),
                    floor: openpc_runtime_agent::target_disposition::ExpiredDenialHandoverFloor {
                        installed_revision: 2,
                        installed_delivery_digest: Digest::of(&withdrawal_wire),
                        observed_revision: 3,
                        observed_admission_digest: abandoned_digest.clone(),
                        original_receipt_wire_digest: Digest::of(&receipt),
                    },
                };
                if credential_transition {
                    assert!(
                        agent
                            .observe_expired_denial_handover(3, &abandoned_digest)
                            .await
                            .is_err()
                    );
                    let floor = agent
                        .observe_expired_credential_denial_handover(
                            3,
                            &abandoned_digest,
                            &abandoned_target,
                        )
                        .await
                        .unwrap();
                    assert_eq!(floor, expected.floor);
                    let mut foreign = abandoned_target.clone();
                    foreign.credential_id = uuid::Uuid::now_v7().to_string();
                    assert!(
                        agent
                            .observe_expired_credential_denial_handover(
                                3,
                                &abandoned_digest,
                                &foreign
                            )
                            .await
                            .is_err()
                    );
                } else {
                    disposition::observe_prepared_expired_denial_handover(&agent, &expected)
                        .await
                        .unwrap();
                }
                assert_eq!(f.control.acknowledgements().len(), 2);
                assert!(
                    disposition::complete_expired_denial_handover(&agent)
                        .await
                        .is_err()
                );
                assert_eq!(f.control.acknowledgements().len(), 2);
                let mut handover = TargetDispositionDelivery {
                    version: 1,
                    target: f.binding.target.clone(),
                    source: source.clone(),
                    action: TargetDispositionAction::Withdraw,
                    revision: 4,
                    previous_revision: 2,
                    previous_delivery_digest: Some(Digest::of(&withdrawal_wire)),
                    committed_admission_digest: Digest::of("new handover admission"),
                    cause: TargetDispositionCause::ExpiredObservedDenialHandover {
                        work_id: source.original_work_id,
                        operation_id: source.original_operation_id,
                        execution_attempt_id: source.original_execution_attempt_id,
                        abandoned_revision: 3,
                        abandoned_admission_digest: abandoned_digest.clone(),
                        original_receipt_wire_digest: if corrupt_receipt {
                            Digest::of("different signed receipt")
                        } else {
                            Digest::of(&receipt)
                        },
                        installed_revision: 2,
                        installed_delivery_digest: Digest::of(&withdrawal_wire),
                        observed_revision: 3,
                        observed_admission_digest: abandoned_digest,
                    },
                };
                if credential_transition {
                    let TargetDispositionCause::ExpiredObservedDenialHandover {
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
                    } = handover.cause
                    else {
                        panic!()
                    };
                    handover.cause =
                        TargetDispositionCause::ExpiredObservedCredentialDenialHandover {
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
                            credential_rotation_operation_id: uuid::Uuid::now_v7().to_string(),
                        };
                }
                f.control.head(&handover, &f.signer);
                let result = disposition::complete_expired_denial_handover(&agent).await;
                if corrupt_receipt {
                    assert!(result.is_err());
                    assert_eq!(f.control.acknowledgements().len(), 2);
                } else {
                    assert_eq!(result.unwrap(), TargetDispositionAction::Withdraw);
                    assert_eq!(f.control.acknowledgements().len(), 3);
                    assert_eq!(
                        disposition::complete_expired_denial_handover(&agent)
                            .await
                            .unwrap(),
                        TargetDispositionAction::Withdraw
                    );
                    assert_eq!(f.control.acknowledgements().len(), 3);
                }
                f.denied(&agent);
                assert_eq!(
                    agent.replay_canonical_receipts().unwrap(),
                    original_receipts
                );
            }
        }
    }

    #[tokio::test]
    async fn activation_keeps_disposition_history_and_never_reuses_a_serving_grant() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let original = agent.replay_canonical_receipts().unwrap();
        let mut next = f.target.capsule.clone();
        next.capsule_id = uuid::Uuid::now_v7().to_string();
        next.generation += 1;
        next.lifecycle_mode = 2;
        next.previous_capsule_digest = Some(f.binding.source.capsule_digest.clone());
        let digest = agent
            .prepare_capsule(
                f.target.signer.sign_capsule(&next).unwrap(),
                f.target.artifacts.clone(),
                7,
            )
            .unwrap();
        let token = RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: f.binding.target.target_id.clone(),
            occurrence_id: uuid::Uuid::now_v7().to_string(),
            desired_generation_digest: digest.clone(),
            xds_version_digest: Digest::of("successor xds"),
            expected_previous_generation_digest: next.previous_capsule_digest,
            issued_at_ns: 7,
            expires_at_ns: 90,
        };
        let wire = f.target.signer.sign_activation_token(&token).unwrap();
        let receipt = agent.activate_capsule_authorized(&wire, 8).unwrap();
        let history = agent.replay_canonical_receipts().unwrap();
        assert_eq!(history, vec![original[0].clone(), receipt.clone()]);
        assert_eq!(
            agent.activate_capsule_authorized(&wire, 9).unwrap(),
            receipt
        );
        assert_eq!(
            agent.active_canonical_generation().unwrap().unwrap().0,
            digest
        );
        f.denied(&agent);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert_eq!(agent.replay_canonical_receipts().unwrap(), history);
        assert_eq!(f.control.acknowledgements().len(), 2);
    }

    #[tokio::test]
    async fn withdrawal_waits_for_admitted_request_fence_before_acknowledging() {
        let f = DispositionFixture::new();
        let agent = Arc::new(f.start());
        let (restore, wire) = f.restore(&agent).await;
        let lease = agent
            .acquire_fresh_active_capsule(&f.target.manifest.protected_class_set_digest, 7)
            .unwrap();
        let withdraw = f.successor(&restore, &wire, TargetDispositionAction::Withdraw);
        f.control.head(&withdraw, &f.signer);
        let (entered, entering) = std::sync::mpsc::channel();
        let (finished, finishing) = std::sync::mpsc::channel();
        let owner = agent.clone();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            entered.send(()).unwrap();
            let result = runtime.block_on(owner.reconcile_target_disposition());
            finished.send(result).unwrap();
        });
        entering.recv().unwrap();
        assert!(matches!(
            finishing.recv_timeout(std::time::Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(f.control.acknowledgements().len(), 2);
        drop(lease);
        assert_eq!(
            finishing
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            TargetDispositionAction::Withdraw
        );
        thread.join().unwrap();
        assert_eq!(f.control.acknowledgements().len(), 3);
        f.denied(&agent);
    }

    #[tokio::test]
    async fn source_admission_waits_for_refresh_without_changing_custody() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let receipts = agent.replay_canonical_receipts().unwrap();
        let acknowledgements = f.control.acknowledgements();
        let head = f.control.0.lock().unwrap().head.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        f.control.0.lock().unwrap().read_pause = Some((entered.clone(), resume.clone()));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        entered.notified().await;
        f.denied(&agent);
        let mut admission = Box::pin(agent.coordinate_source_read());
        assert!(futures::poll!(&mut admission).is_pending());
        f.control.0.lock().unwrap().read_pause = None;
        resume.notify_one();
        assert_eq!(refresh.await.unwrap(), TargetDispositionAction::Restore);
        let _permit = admission.await.unwrap();
        drop(
            agent
                .acquire_fresh_active_capsule(&f.target.manifest.protected_class_set_digest, 7)
                .unwrap(),
        );
        assert_eq!(f.control.0.lock().unwrap().head, head);
        assert_eq!(f.control.acknowledgements(), acknowledgements);
        assert_eq!(agent.replay_canonical_receipts().unwrap(), receipts);
    }

    #[tokio::test]
    async fn source_read_finishes_before_refresh_takes_the_control_lifecycle_lock() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let permit = agent.coordinate_source_read().await.unwrap();
        // Dispatch releases its short journal lease before provider I/O, but
        // retains the source permit and SQL lifecycle lock through commit.
        drop(
            agent
                .acquire_fresh_active_capsule(&f.target.manifest.protected_class_set_digest, 7)
                .unwrap(),
        );
        let reads = {
            let mut state = f.control.0.lock().unwrap();
            state.source_lifecycle_busy = true;
            state.current_reads
        };
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        assert_eq!(f.control.0.lock().unwrap().current_reads, reads);
        agent.require_current_target_disposition().unwrap();
        let mut later_reader = Box::pin(agent.coordinate_source_read());
        assert!(futures::poll!(&mut later_reader).is_pending());
        f.control.0.lock().unwrap().source_lifecycle_busy = false;
        drop(permit);
        assert_eq!(refresh.await.unwrap(), TargetDispositionAction::Restore);
        let _permit = later_reader.await.unwrap();
        agent.require_current_target_disposition().unwrap();
        assert_eq!(f.control.0.lock().unwrap().current_reads, reads + 2);
    }

    #[tokio::test]
    async fn response_release_waits_for_unchanged_refresh_before_reacquiring_authority() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let receipts = agent.replay_canonical_receipts().unwrap();
        let acknowledgements = f.control.acknowledgements();
        let resume = Arc::new(tokio::sync::Notify::new());
        f.control.0.lock().unwrap().read_pause =
            Some((Arc::new(tokio::sync::Notify::new()), resume.clone()));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        // This was the uncoordinated final-release failure even though the
        // signed head and original activation had not changed.
        f.denied(&agent);
        let deadline = release_clock_ms() + 1000;
        let mut release = Box::pin(agent.coordinate_response_release(deadline));
        assert!(futures::poll!(&mut release).is_pending());
        f.control.0.lock().unwrap().read_pause = None;
        resume.notify_one();
        refresh.await.unwrap();
        let _permit = release.await.unwrap().unwrap();
        agent.require_current_target_disposition().unwrap();
        assert_eq!(agent.replay_canonical_receipts().unwrap(), receipts);
        assert_eq!(f.control.acknowledgements(), acknowledgements);
        agent.fence_target_disposition().unwrap();
        f.denied(&agent);
    }

    #[tokio::test]
    async fn response_release_wait_cannot_extend_the_original_request_deadline() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let resume = Arc::new(tokio::sync::Notify::new());
        f.control.0.lock().unwrap().read_pause =
            Some((Arc::new(tokio::sync::Notify::new()), resume.clone()));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        assert!(matches!(
            agent
                .coordinate_response_release(release_clock_ms() + 10)
                .await,
            Err(RuntimeError::BudgetExhausted)
        ));
        f.denied(&agent);
        f.control.0.lock().unwrap().read_pause = None;
        resume.notify_one();
        refresh.await.unwrap();
        assert!(matches!(
            agent.coordinate_response_release(release_clock_ms()).await,
            Err(RuntimeError::BudgetExhausted)
        ));
        agent.require_current_target_disposition().unwrap();
    }

    #[tokio::test]
    async fn cancelled_refresh_does_not_grant_authority_to_a_waiting_response() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        f.control.0.lock().unwrap().read_pause = Some((
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        ));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        let mut release = Box::pin(agent.coordinate_response_release(release_clock_ms() + 1000));
        assert!(futures::poll!(&mut release).is_pending());
        drop(refresh);
        let _permit = release.await.unwrap().unwrap();
        f.denied(&agent);
    }

    #[tokio::test]
    async fn cancelled_queued_refresh_fences_without_waiting_for_source_reader() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let permit = agent.coordinate_source_read().await.unwrap();
        let acknowledgements = f.control.acknowledgements();
        let reads = f.control.0.lock().unwrap().current_reads;
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        drop(refresh);
        f.denied(&agent);
        assert_eq!(f.control.0.lock().unwrap().current_reads, reads);
        assert_eq!(f.control.acknowledgements(), acknowledgements);
        drop(permit);
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Restore
        );
        agent.require_current_target_disposition().unwrap();
    }

    #[tokio::test]
    async fn cancelled_refresh_releases_source_gate_after_fencing() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        f.control.0.lock().unwrap().read_pause = Some((
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        ));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        drop(refresh);
        let mut admission = Box::pin(agent.coordinate_source_read());
        assert!(futures::poll!(&mut admission).is_ready());
        f.denied(&agent);
        f.control.0.lock().unwrap().read_pause = None;
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Restore
        );
    }

    #[tokio::test]
    async fn independent_fence_cannot_be_overwritten_by_in_flight_refresh() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        f.control.0.lock().unwrap().read_pause = Some((entered.clone(), resume.clone()));
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        entered.notified().await;
        agent.fence_target_disposition().unwrap();
        f.control.0.lock().unwrap().read_pause = None;
        resume.notify_one();
        assert!(matches!(
            refresh.await,
            Err(RuntimeError::RuntimeUnavailable)
        ));
        f.denied(&agent);
        // Only a new current read after that fencing event may restore serving.
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Restore
        );
    }

    #[tokio::test]
    async fn independent_fence_acts_while_source_read_permit_is_held() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let _permit = agent.coordinate_source_read().await.unwrap();
        agent.require_current_target_disposition().unwrap();
        agent.fence_target_disposition().unwrap();
        f.denied(&agent);
    }

    #[tokio::test]
    async fn source_read_permit_does_not_extend_the_currentness_deadline() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let _permit = agent.coordinate_source_read().await.unwrap();
        agent.require_current_target_disposition().unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        f.denied(&agent);
    }

    #[tokio::test]
    async fn cancelled_source_cleanup_fences_before_releasing_the_refresh_gate() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let mut permit = agent.coordinate_source_read().await.unwrap();
        permit.begin_io();
        f.control.0.lock().unwrap().source_lifecycle_busy = true;
        let reads = f.control.0.lock().unwrap().current_reads;
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        assert_eq!(f.control.0.lock().unwrap().current_reads, reads);
        drop(permit);
        f.denied(&agent);
        assert!(refresh.await.is_err());
        f.denied(&agent);
        f.control.0.lock().unwrap().source_lifecycle_busy = false;
        assert_eq!(
            agent.reconcile_target_disposition().await.unwrap(),
            TargetDispositionAction::Restore
        );
    }

    #[tokio::test]
    async fn confirmed_source_rollback_keeps_the_current_deadline() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let mut permit = agent.coordinate_source_read().await.unwrap();
        permit.begin_io();
        permit.complete_io();
        drop(permit);
        agent.require_current_target_disposition().unwrap();
    }

    #[tokio::test]
    async fn queued_refresh_cannot_overwrite_an_independent_fence() {
        let f = DispositionFixture::new();
        let agent = f.start();
        f.restore(&agent).await;
        let permit = agent.coordinate_source_read().await.unwrap();
        let mut refresh = Box::pin(agent.reconcile_target_disposition());
        assert!(futures::poll!(&mut refresh).is_pending());
        agent.fence_target_disposition().unwrap();
        drop(permit);
        assert!(matches!(
            refresh.await,
            Err(RuntimeError::RuntimeUnavailable)
        ));
        f.denied(&agent);
    }

    async fn next_lifecycle_observation(
        observations: &mut tokio::sync::mpsc::UnboundedReceiver<LifecycleObservation>,
    ) -> LifecycleObservation {
        tokio::time::timeout(std::time::Duration::from_secs(4), observations.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn expired_confirmation_ack_recovers_original_bytes_without_currentness() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let effects = agent.replay_canonical_receipts().unwrap();
        f.control.head(&f.confirmation(), &f.signer);
        {
            let mut state = f.control.0.lock().unwrap();
            state.unavailable = true;
            state.original_available = true;
            state.lose_ack_response = true;
        }
        assert!(agent.reconcile_target_disposition().await.is_err());
        let original = f.control.acknowledgements();
        assert_eq!(original.len(), 1);
        f.denied(&agent);
        assert!(agent.require_current_target_disposition().is_err());
        assert_eq!(agent.replay_canonical_receipts().unwrap(), effects);
        drop(agent);
        let agent = f.target.open();
        f.install(&agent);
        f.control.0.lock().unwrap().lose_ack_response = false;
        for _ in 0..2 {
            assert!(agent.reconcile_target_disposition().await.is_err());
            f.denied(&agent);
            assert!(agent.require_current_target_disposition().is_err());
            assert_eq!(f.control.acknowledgements(), original);
            assert_eq!(agent.replay_canonical_receipts().unwrap(), effects);
            assert!(!f.target.root.join("pds.sock").exists());
        }
    }

    #[tokio::test]
    async fn historical_confirmation_rejects_live_pending_foreign_and_stale_custody() {
        for scenario in [
            "live",
            "pending",
            "challenge",
            "foreign",
            "withdraw",
            "stale",
        ] {
            let f =
                DispositionFixture::with_expiry(if scenario == "live" { u64::MAX } else { 100 });
            let agent = f.start();
            let mut confirmation = f.confirmation();
            if scenario == "foreign" {
                confirmation.target.principal_epoch += 1;
            }
            if scenario == "withdraw" {
                confirmation = f.withdrawal();
            }
            f.control.head(&confirmation, &f.signer);
            {
                let mut state = f.control.0.lock().unwrap();
                state.unavailable = true;
                state.original_available = true;
                state.wrong_challenge = scenario == "challenge";
                if scenario == "pending" {
                    state.head.as_mut().unwrap().2.clear();
                }
            }
            if scenario == "stale" {
                assert!(agent.reconcile_target_disposition().await.is_err());
                assert_eq!(f.control.acknowledgements().len(), 1);
                confirmation.committed_admission_digest = Digest::of("conflicting historical head");
                f.control.head(&confirmation, &f.signer);
            }
            let prior = f.control.acknowledgements();
            assert!(
                agent.reconcile_target_disposition().await.is_err(),
                "{scenario}"
            );
            assert_eq!(f.control.acknowledgements(), prior, "{scenario}");
            assert!(
                agent.require_current_target_disposition().is_err(),
                "{scenario}"
            );
            f.denied(&agent);
            if scenario == "live" {
                assert_eq!(f.control.0.lock().unwrap().original_reads, 0);
            }
        }
    }

    #[tokio::test]
    async fn historical_confirmation_cannot_regenerate_ack_after_journal_rollback() {
        let f = DispositionFixture::new();
        let agent = f.start();
        let path = f.target.root.join("agent/activation.json");
        let before = fs::read(&path).unwrap();
        f.control.head(&f.confirmation(), &f.signer);
        {
            let mut state = f.control.0.lock().unwrap();
            state.unavailable = true;
            state.original_available = true;
        }
        assert!(agent.reconcile_target_disposition().await.is_err());
        let original = f.control.acknowledgements();
        assert_eq!(original.len(), 1);
        drop(agent);
        fs::write(&path, before).unwrap(); // Deliberate snapshot rollback, never recovery advice.
        let agent = f.target.open();
        f.install(&agent);
        assert!(agent.reconcile_target_disposition().await.is_err());
        assert_eq!(f.control.acknowledgements(), original);
        f.denied(&agent);
        assert!(agent.require_current_target_disposition().is_err());
    }

    #[tokio::test]
    async fn activation_confirmation_keeps_bootstrap_fence_and_original_effect_in_both_modes() {
        use crate::runtime_target_service::lifecycle::{self, Exit};
        for source_only in [false, true] {
            let mut f = DispositionFixture::new();
            f.target.manifest.source_only = source_only;
            let original = f.start().replay_canonical_receipts().unwrap();
            let mut confirmation = f.withdrawal();
            confirmation.action = TargetDispositionAction::ConfirmActivation;
            confirmation.cause = TargetDispositionCause::Activation {
                work_id: f.binding.source.original_work_id.clone(),
                operation_id: f.binding.source.original_operation_id.clone(),
                execution_attempt_id: Some(f.binding.source.original_execution_attempt_id.clone()),
            };
            f.control.head(&confirmation, &f.signer);
            let mut suspended = f.target.manifest.clone();
            suspended.suspended_for_work = Some(uuid::Uuid::now_v7().to_string());
            write_target_bootstrap(&f.target.root.join("bootstrap"), suspended, [43; 32]).unwrap();
            let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let running = lifecycle::run(|stop| f.lifecycle_attempt(stop, &events), async {
                let _ = cancelled.await;
            });
            let scenario = async {
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::BootstrapChanged)
                ));
                assert!(!f.target.root.join("pds.sock").exists());
                let worker = f.target.open();
                assert_eq!(worker.replay_canonical_receipts().unwrap(), original);
                drop(worker);
                f.target.write(None);
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Ready
                ));
                cancel.send(()).unwrap();
            };
            let (result, ()) = tokio::join!(running, scenario);
            result.unwrap();
            assert_eq!(f.control.acknowledgements().len(), 1);
            let worker = f.target.open();
            assert_eq!(worker.replay_canonical_receipts().unwrap(), original);
        }
    }

    #[tokio::test]
    async fn both_bootstrap_modes_keep_reloading_after_withdrawal_lost_ack_and_pending() {
        use crate::runtime_target_service::lifecycle::{self, Exit};
        for source_only in [false, true] {
            let mut f = DispositionFixture::new();
            f.target.manifest.source_only = source_only;
            let original = {
                let agent = f.start();
                agent.replay_canonical_receipts().unwrap()
            };
            f.target.write(None);
            let withdrawal = f.withdrawal();
            let wire = f.control.head(&withdrawal, &f.signer);
            let restore = f.successor(&withdrawal, &wire, TargetDispositionAction::Restore);
            f.control.0.lock().unwrap().lose_ack_response = true;
            let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let running = lifecycle::run(|stop| f.lifecycle_attempt(stop, &events), async {
                let _ = cancelled.await;
            });
            let scenario = async {
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::DispositionUnavailable(_))
                ));
                let acknowledgement = f.control.acknowledgements();
                assert_eq!(acknowledgement.len(), 1);
                assert!(!f.target.root.join("pds.sock").exists());
                assert!(!f.target.root.join("broker.sock").exists());
                // The production retry delay holds no target journal handle.
                let worker = f.target.open();
                assert_eq!(worker.replay_canonical_receipts().unwrap(), original);
                drop(worker);
                f.control.0.lock().unwrap().lose_ack_response = false;
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::Withdrawn)
                ));
                assert_eq!(f.control.acknowledgements(), acknowledgement);
                f.control.0.lock().unwrap().unavailable = true;
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::DispositionUnavailable(_))
                ));
                {
                    let mut control = f.control.0.lock().unwrap();
                    control.unavailable = false;
                    control.head = Some((
                        restore.revision,
                        restore.committed_admission_digest.clone(),
                        vec![],
                    ));
                }
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::DispositionUnavailable(_))
                ));
                assert_eq!(f.control.acknowledgements(), acknowledgement);
                assert!(!f.target.root.join("pds.sock").exists());
                f.control.head(&restore, &f.signer);
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Ready
                ));
                assert!(f.target.root.join("pds.sock").exists());
                assert_eq!(f.target.root.join("broker.sock").exists(), !source_only);
                cancel.send(()).unwrap();
            };
            let (result, ()) = tokio::join!(running, scenario);
            result.unwrap();
            assert!(!f.target.root.join("pds.sock").exists());
            assert!(!f.target.root.join("broker.sock").exists());
            let worker = f.target.open();
            assert_eq!(worker.replay_canonical_receipts().unwrap(), original);
        }
    }

    #[tokio::test]
    async fn restarted_lifecycle_rejects_malformed_and_suspended_bootstrap_before_restoring() {
        use crate::runtime_target_service::lifecycle::{self, Exit};
        for source_only in [false, true] {
            let mut f = DispositionFixture::new();
            f.target.manifest.source_only = source_only;
            {
                let agent = f.start();
                f.restore(&agent).await;
            }
            let exact_acknowledgements = f.control.acknowledgements();
            f.target.write(None);
            fs::write(
                f.target.root.join("bootstrap/bootstrap.json"),
                b"not a signed bootstrap",
            )
            .unwrap();
            let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let running = lifecycle::run(|stop| f.lifecycle_attempt(stop, &events), async {
                let _ = cancelled.await;
            });
            let scenario = async {
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::BootstrapUnavailable)
                ));
                let mut suspended = f.target.manifest.clone();
                suspended.suspended_for_work = Some(uuid::Uuid::now_v7().to_string());
                write_target_bootstrap(&f.target.root.join("bootstrap"), suspended, [43; 32])
                    .unwrap();
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::BootstrapChanged)
                ));
                assert!(!f.target.root.join("pds.sock").exists());
                let worker = f.target.open();
                drop(worker);
                let mut incompatible = f.target.manifest.clone();
                incompatible.capsule_generation += 1;
                write_target_bootstrap(&f.target.root.join("bootstrap"), incompatible, [43; 32])
                    .unwrap();
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::BootstrapChanged)
                ));
                assert!(!f.target.root.join("pds.sock").exists());
                // Only a fresh read of the authentic, compatible bootstrap can
                // remove that independent fence; RESTORE itself never rewrites it.
                f.target.write(None);
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Ready
                ));
                assert_eq!(f.control.acknowledgements(), exact_acknowledgements);
                cancel.send(()).unwrap();
            };
            let (result, ()) = tokio::join!(running, scenario);
            result.unwrap();
            assert!(!f.target.root.join("pds.sock").exists());
            assert!(!f.target.root.join("broker.sock").exists());
        }
    }

    #[tokio::test]
    async fn cancellation_during_fenced_reload_releases_custody_without_another_attempt() {
        use crate::runtime_target_service::lifecycle::{self, Exit};
        let f = DispositionFixture::new();
        drop(f.start());
        f.target.write(None);
        f.control.head(&f.withdrawal(), &f.signer);
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let running = lifecycle::run(
            |stop| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                f.lifecycle_attempt(stop, &events)
            },
            async {
                let _ = cancelled.await;
            },
        );
        let scenario = async {
            assert!(matches!(
                next_lifecycle_observation(&mut observed).await,
                LifecycleObservation::Fenced(Exit::Withdrawn)
            ));
            cancel.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(running, scenario);
        result.unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        let worker = f.target.open();
        assert_eq!(worker.replay_canonical_receipts().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cancellation_during_current_read_does_not_leave_journal_or_ack_in_flight() {
        use crate::runtime_target_service::lifecycle;
        let f = DispositionFixture::new();
        drop(f.start());
        f.target.write(None);
        f.control.head(&f.withdrawal(), &f.signer);
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        f.control.0.lock().unwrap().read_pause = Some((entered.clone(), resume));
        let (events, _observed) = tokio::sync::mpsc::unbounded_channel();
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let running = lifecycle::run(|stop| f.lifecycle_attempt(stop, &events), async {
            let _ = cancelled.await;
        });
        let cancellation = async {
            tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            cancel.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(running, cancellation);
        result.unwrap();
        assert!(f.control.acknowledgements().is_empty());
        let worker = f.target.open();
        assert_eq!(worker.replay_canonical_receipts().unwrap().len(), 1);
        assert!(!f.target.root.join("pds.sock").exists());
    }

    #[tokio::test]
    async fn both_serving_modes_close_listeners_then_restore_in_the_same_lifecycle() {
        use crate::runtime_target_service::lifecycle::{self, Exit};
        for source_only in [false, true] {
            let mut f = DispositionFixture::new();
            f.target.manifest.source_only = source_only;
            let (prior, wire) = {
                let agent = f.start();
                f.restore(&agent).await
            };
            f.target.write(None);
            let withdraw = f.successor(&prior, &wire, TargetDispositionAction::Withdraw);
            let withdrawal_wire =
                encode_target_disposition_delivery(&f.signer.sign(withdraw.clone()).unwrap())
                    .unwrap();
            let restore = f.successor(
                &withdraw,
                &withdrawal_wire,
                TargetDispositionAction::Restore,
            );
            let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let running = lifecycle::run(|stop| f.lifecycle_attempt(stop, &events), async {
                let _ = cancelled.await;
            });
            let scenario = async {
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Ready
                ));
                let exact_withdrawal = f.control.head(&withdraw, &f.signer);
                assert_eq!(exact_withdrawal, withdrawal_wire);
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Fenced(Exit::Withdrawn)
                ));
                assert!(!f.target.root.join("pds.sock").exists());
                assert!(!f.target.root.join("broker.sock").exists());
                let worker = f.target.open();
                assert_eq!(worker.replay_canonical_receipts().unwrap().len(), 1);
                drop(worker);
                f.control.head(&restore, &f.signer);
                assert!(matches!(
                    next_lifecycle_observation(&mut observed).await,
                    LifecycleObservation::Ready
                ));
                cancel.send(()).unwrap();
            };
            let (result, ()) = tokio::join!(running, scenario);
            result.unwrap();
            assert_eq!(f.control.acknowledgements().len(), 4);
            assert!(!f.target.root.join("pds.sock").exists());
            assert!(!f.target.root.join("broker.sock").exists());
        }
    }
}
