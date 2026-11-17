//! Component custody fixture. Its receipt artifact is deliberately not a policy
//! release, runtime permission, or acceptance of the protected allow journey.
use openpc_fleet_controller::{
    FleetController,
    canonical_target::{CanonicalTargetCoordinator, PreparedCanonicalTarget},
    envoy_resources::ProtectedListenerConfig,
};
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent, CapsuleTrust, RuntimeAgent, RuntimeCapsule,
    RuntimeWireSigner, TargetActivationReceipt,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}
pub fn protected_classes() -> Digest {
    Digest::of(b"component transport observation only")
}
struct ReceiptComponent;
impl ArtifactAdmission for ReceiptComponent {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.schema_id != 2004
            || component.schema_version != 3
            || component.semantic_digest != Digest::of(bytes)
        {
            return Err(RuntimeError::InvalidInput);
        }
        TargetActivationReceipt::decode(bytes)?;
        Ok(())
    }
}
pub struct CanonicalHarness {
    pub agent: Arc<RuntimeAgent>,
    pub coordinator: CanonicalTargetCoordinator,
    pub prepared: PreparedCanonicalTarget,
    pub capsule: RuntimeCapsule,
    pub artifacts: BTreeMap<Digest, Vec<u8>>,
}
impl CanonicalHarness {
    pub fn prepare(
        fleet: Arc<FleetController>,
        directory: &Path,
        config: ProtectedListenerConfig<'_>,
    ) -> Self {
        let signer = RuntimeWireSigner::from_secret_bytes([32; 32]).unwrap();
        let d = Digest::of(b"component test, not runtime authority");
        let now = now_ns();
        let bytes = TargetActivationReceipt {
            receipt_id: "test-source".into(),
            target_runtime_id: "test-source".into(),
            capsule_digest: d.clone(),
            contract_set_manifest_digest: d.clone(),
            complete_component_set_digest: d.clone(),
            status: 1,
            reason_code: "COMPONENT_TEST".into(),
            observed_at_ns: now - 2,
            agent_sequence: 1,
            signer_id: "source".into(),
        }
        .encode()
        .unwrap();
        let content = Digest::of(&bytes);
        let capsule = RuntimeCapsule {
            capsule_id: config.capsule_id.into(),
            lifecycle_mode: 1,
            target_runtime_id: config.target_id.into(),
            fleet_id: "fleet-1".into(),
            generation: config.capsule_generation,
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
            issued_at_ns: now - 2,
            not_before_ns: now - 1,
            hard_expiry_ns: now + 60_000_000_000,
            signer_id: "fleet-key-1".into(),
            artifact_components: vec![ArtifactComponent {
                component_id: "receipt".into(),
                component_type: "test-receipt".into(),
                content_digest: content.clone(),
                semantic_digest: content.clone(),
                schema_id: 2004,
                schema_version: 3,
                size_bytes: bytes.len() as u64,
                required: true,
            }],
        };
        let agent = Arc::new(
            RuntimeAgent::open_canonical(
                CapsuleTrust {
                    target_id: capsule.target_runtime_id.clone(),
                    fleet_id: capsule.fleet_id.clone(),
                    fleet_signer_id: capsule.signer_id.clone(),
                    agent_signer_id: "agent-key-1".into(),
                    contract_set_manifest_digest: d.clone(),
                    schema_registry_digest: d.clone(),
                    cose_purpose_registry_digest: d.clone(),
                    complete_component_set_digest: d,
                },
                &signer.verifier().public_key_bytes(),
                [33; 32],
                8,
                10_000,
                &directory.join("activation"),
                Arc::new(ReceiptComponent),
            )
            .unwrap(),
        );
        let freshness = openpc_runtime_agent::RevocationFreshnessLease {
            lease_id: "transport-freshness".into(),
            target_runtime_id: capsule.target_runtime_id.clone(),
            fleet_id: capsule.fleet_id.clone(),
            lease_generation: 1,
            minimum_emergency_generation: 0,
            issued_at_ns: now - 1,
            expires_at_ns: capsule.hard_expiry_ns,
            protected_class_set_digest: protected_classes(),
            signer_id: capsule.signer_id.clone(),
        };
        agent
            .install_freshness_lease(&signer.sign_freshness_lease(&freshness).unwrap(), now)
            .unwrap();
        let coordinator = CanonicalTargetCoordinator::new(Arc::clone(&fleet), Arc::clone(&agent));
        let signed = signer.sign_capsule(&capsule).unwrap();
        let mut mismatched = config;
        mismatched.capsule_generation += 1;
        assert!(
            coordinator
                .prepare(
                    signed.clone(),
                    BTreeMap::from([(content.clone(), bytes.clone())]),
                    "occurrence-1",
                    mismatched,
                    now
                )
                .is_err()
        );
        assert_eq!(
            fleet.state(config.target_id).unwrap(),
            pc_runtime_types::TargetState::Discovered
        );
        assert!(
            coordinator
                .prepare(signed.clone(), BTreeMap::new(), "occurrence-1", config, now)
                .is_err()
        );
        assert_eq!(
            fleet.state(config.target_id).unwrap(),
            pc_runtime_types::TargetState::Failed
        );
        assert!(
            agent
                .with_active_capsule(|capsule, _| capsule.digest())
                .is_err()
        );
        let artifacts = BTreeMap::from([(content, bytes)]);
        let prepared = coordinator
            .prepare(signed, artifacts.clone(), "occurrence-1", config, now)
            .unwrap();
        assert!(coordinator.activate(&prepared, now).is_err());
        assert!(
            agent
                .with_active_capsule(|capsule, _| capsule.digest())
                .is_err()
        );
        Self {
            agent,
            coordinator,
            prepared,
            capsule,
            artifacts,
        }
    }
}
