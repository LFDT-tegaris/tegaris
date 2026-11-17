use std::collections::BTreeMap;

use openpc_fleet_controller::{FleetController, REQUIRED_XDS_TYPES, TargetIdentity, XdsSnapshot};
use openpc_runtime_agent::{ArtifactBundle, RuntimeAgent};
use pc_runtime_types::{
    ActivationToken, DesiredGeneration, Digest, PURPOSE_ACTIVATION_RECEIPT_V1,
    PURPOSE_ACTIVATION_TOKEN_V1, PURPOSE_DESIRED_GENERATION_V1, PurposeSigner, RuntimeError,
    TargetState, canonical_bytes,
};

fn digest(value: &str) -> Digest {
    Digest::of(value)
}

fn resources(target_id: &str) -> BTreeMap<String, Vec<String>> {
    REQUIRED_XDS_TYPES
        .iter()
        .map(|resource_type| {
            (
                (*resource_type).to_owned(),
                vec![format!("openpc/{target_id}/resource/v1")],
            )
        })
        .collect()
}

fn activate_generation(
    fleet: &FleetController,
    agent: &RuntimeAgent,
    identity: &TargetIdentity,
    desired: &DesiredGeneration,
    bundle: &ArtifactBundle,
    now_ms: u64,
) -> pc_runtime_types::SignedEnvelope<pc_runtime_types::ActivationReceipt> {
    let signed = fleet.command_generation(desired.clone()).unwrap();
    agent.prepare(&signed, bundle, now_ms).unwrap();
    fleet
        .accept_prepared(&desired.target_id, &desired.capsule_digest)
        .unwrap();
    let nonces = fleet
        .publish_snapshot(XdsSnapshot {
            target_id: desired.target_id.clone(),
            version_digest: desired.xds_snapshot_digest.clone(),
            resources_by_type: resources(&desired.target_id),
        })
        .unwrap();
    for resource_type in REQUIRED_XDS_TYPES {
        fleet
            .acknowledge(
                identity,
                resource_type,
                &desired.xds_snapshot_digest,
                nonces.get(resource_type).unwrap(),
            )
            .unwrap();
    }
    let token = fleet
        .issue_activation_token(&desired.target_id, now_ms + 1, 20)
        .unwrap();
    let receipt = agent.activate(&token, now_ms + 2).unwrap();
    fleet.accept_activation_receipt(&receipt).unwrap();
    fleet
        .observe_request_generation(identity, desired.capsule_digest.clone())
        .unwrap();
    fleet
        .heartbeat(identity, desired.capsule_digest.clone(), now_ms + 3)
        .unwrap();
    assert_eq!(
        fleet.derive_state(&desired.target_id, now_ms + 4).unwrap(),
        TargetState::ActiveMatched
    );
    receipt
}

#[test]
fn fleet_agent_activation_requires_complete_xds_and_durable_receipt() {
    let target_id = "018f1e44-7b2c-7abd-8def-0123456789ac";
    let fleet_secret = [31; 32];
    let agent_receipt_secret = [32; 32];
    let fleet_public =
        PurposeSigner::from_secret_bytes(PURPOSE_DESIRED_GENERATION_V1, fleet_secret)
            .unwrap()
            .verifier()
            .sec1_bytes();
    let agent_receipt_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, agent_receipt_secret)
            .unwrap()
            .verifier()
            .sec1_bytes();
    let agent = RuntimeAgent::new(target_id, &fleet_public, agent_receipt_secret, 8).unwrap();
    let fleet = FleetController::new(fleet_secret, &agent_receipt_public, 30).unwrap();
    let identity = TargetIdentity {
        target_id: target_id.into(),
        uri_san: format!("spiffe://openpc.local/runtime-target/{target_id}"),
        certificate_fingerprint: digest("certificate"),
        workload_epoch: 1,
    };
    fleet.register_target(identity.clone(), &identity).unwrap();
    let bundle = ArtifactBundle {
        manifest_digest: digest("manifest"),
        policy_generation_digest: digest("policy"),
        fact_generation_digest: digest("facts"),
        route_profile_digest: digest("route"),
        runtime_configuration_digest: digest("configuration"),
        schema_version: "1.0".into(),
        abi_version: "1.0".into(),
        declared_bytes: 1024,
        available_capacity_bytes: 2048,
    };
    let desired = DesiredGeneration {
        occurrence_id: "occurrence-1".into(),
        target_id: target_id.into(),
        capsule_digest: Digest::of(canonical_bytes(&bundle).unwrap()),
        xds_snapshot_digest: digest("xds-snapshot"),
        expected_previous_generation_digest: None,
        expires_at_ms: 200,
    };
    let signed_desired = fleet.command_generation(desired.clone()).unwrap();
    agent.prepare(&signed_desired, &bundle, 100).unwrap();
    fleet
        .accept_prepared(target_id, &desired.capsule_digest)
        .unwrap();
    let nonces = fleet
        .publish_snapshot(XdsSnapshot {
            target_id: target_id.into(),
            version_digest: desired.xds_snapshot_digest.clone(),
            resources_by_type: resources(target_id),
        })
        .unwrap();
    for resource_type in REQUIRED_XDS_TYPES {
        fleet
            .acknowledge(
                &identity,
                resource_type,
                &desired.xds_snapshot_digest,
                nonces.get(resource_type).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(
        fleet.state(target_id).unwrap(),
        TargetState::XdsAckedNotActive
    );
    let token = fleet.issue_activation_token(target_id, 110, 20).unwrap();
    let receipt = agent.activate(&token, 111).unwrap();
    fleet.accept_activation_receipt(&receipt).unwrap();
    fleet
        .observe_request_generation(&identity, desired.capsule_digest.clone())
        .unwrap();
    fleet
        .heartbeat(&identity, desired.capsule_digest, 112)
        .unwrap();
    assert_eq!(
        fleet.derive_state(target_id, 113).unwrap(),
        TargetState::ActiveMatched
    );
}

#[test]
fn gate4_rejects_identity_preparation_and_activation_mutations_before_state_change() {
    let target_id = "018f1e44-7b2c-7abd-8def-0123456789ac";
    let fleet_key = [41; 32];
    let receipt_key = [42; 32];
    let fleet_public = PurposeSigner::from_secret_bytes(PURPOSE_DESIRED_GENERATION_V1, fleet_key)
        .unwrap()
        .verifier()
        .sec1_bytes();
    let receipt_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, receipt_key)
            .unwrap()
            .verifier()
            .sec1_bytes();
    let agent = RuntimeAgent::new(target_id, &fleet_public, receipt_key, 8).unwrap();
    let fleet = FleetController::new(fleet_key, &receipt_public, 30).unwrap();
    let identity = TargetIdentity {
        target_id: target_id.into(),
        uri_san: format!("spiffe://openpc.local/runtime-target/{target_id}"),
        certificate_fingerprint: digest("certificate"),
        workload_epoch: 1,
    };
    for mutation in 0..3 {
        let mut presented = identity.clone();
        match mutation {
            0 => presented.uri_san.push_str("-wrong"),
            1 => presented.certificate_fingerprint = digest("wrong-certificate"),
            _ => presented.workload_epoch += 1,
        }
        assert_eq!(
            fleet.register_target(presented, &identity),
            Err(RuntimeError::TargetIdentity)
        );
    }
    fleet.register_target(identity.clone(), &identity).unwrap();
    let bundle = ArtifactBundle {
        manifest_digest: digest("manifest"),
        policy_generation_digest: digest("policy"),
        fact_generation_digest: digest("facts"),
        route_profile_digest: digest("route"),
        runtime_configuration_digest: digest("configuration"),
        schema_version: "1.0".into(),
        abi_version: "1.0".into(),
        declared_bytes: 1024,
        available_capacity_bytes: 2048,
    };
    let desired = DesiredGeneration {
        occurrence_id: "gate4-occurrence-1".into(),
        target_id: target_id.into(),
        capsule_digest: Digest::of(canonical_bytes(&bundle).unwrap()),
        xds_snapshot_digest: digest("xds-1"),
        expected_previous_generation_digest: None,
        expires_at_ms: 200,
    };
    let signed = PurposeSigner::from_secret_bytes(PURPOSE_DESIRED_GENERATION_V1, fleet_key)
        .unwrap()
        .sign(desired.clone())
        .unwrap();
    assert_eq!(
        agent.prepare(&signed, &bundle, 200),
        Err(RuntimeError::InvalidInput)
    );
    let mut oversized = bundle.clone();
    oversized.declared_bytes = oversized.available_capacity_bytes + 1;
    assert_eq!(
        agent.prepare(&signed, &oversized, 100),
        Err(RuntimeError::InvalidInput)
    );
    agent.prepare(&signed, &bundle, 100).unwrap();
    assert_eq!(agent.active_generation().unwrap(), None);

    let activation_signer =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_TOKEN_V1, fleet_key).unwrap();
    let base = ActivationToken {
        token_id: "gate4-token-1".into(),
        occurrence_id: desired.occurrence_id.clone(),
        target_id: target_id.into(),
        capsule_digest: desired.capsule_digest.clone(),
        xds_version_digest: desired.xds_snapshot_digest.clone(),
        expected_previous_generation_digest: None,
        issued_at_ms: 101,
        expires_at_ms: 150,
    };
    let mut wrong_target = base.clone();
    wrong_target.target_id = "wrong-target".into();
    assert_eq!(
        agent.activate(&activation_signer.sign(wrong_target).unwrap(), 110),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let mut wrong_xds = base.clone();
    wrong_xds.xds_version_digest = digest("wrong-xds");
    assert_eq!(
        agent.activate(&activation_signer.sign(wrong_xds).unwrap(), 110),
        Err(RuntimeError::GenerationMismatch)
    );
    let valid = activation_signer.sign(base).unwrap();
    agent.activate(&valid, 110).unwrap();
    assert_eq!(agent.activate(&valid, 111), Err(RuntimeError::Replay));
}

#[test]
fn gate4_rollback_is_a_new_signed_generation_with_exact_predecessor() {
    let target_id = "018f1e44-7b2c-7abd-8def-0123456789ac";
    let fleet_key = [51; 32];
    let receipt_key = [52; 32];
    let fleet_public = PurposeSigner::from_secret_bytes(PURPOSE_DESIRED_GENERATION_V1, fleet_key)
        .unwrap()
        .verifier()
        .sec1_bytes();
    let receipt_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, receipt_key)
            .unwrap()
            .verifier()
            .sec1_bytes();
    let agent = RuntimeAgent::new(target_id, &fleet_public, receipt_key, 16).unwrap();
    let fleet = FleetController::new(fleet_key, &receipt_public, 30).unwrap();
    let identity = TargetIdentity {
        target_id: target_id.into(),
        uri_san: format!("spiffe://openpc.local/runtime-target/{target_id}"),
        certificate_fingerprint: digest("certificate"),
        workload_epoch: 1,
    };
    fleet.register_target(identity.clone(), &identity).unwrap();

    let bundle_one = ArtifactBundle {
        manifest_digest: digest("manifest-1"),
        policy_generation_digest: digest("policy-1"),
        fact_generation_digest: digest("facts-1"),
        route_profile_digest: digest("route-1"),
        runtime_configuration_digest: digest("configuration-1"),
        schema_version: "1.0".into(),
        abi_version: "1.0".into(),
        declared_bytes: 1024,
        available_capacity_bytes: 2048,
    };
    let generation_one = Digest::of(canonical_bytes(&bundle_one).unwrap());
    let desired_one = DesiredGeneration {
        occurrence_id: "gate4-forward-1".into(),
        target_id: target_id.into(),
        capsule_digest: generation_one.clone(),
        xds_snapshot_digest: digest("xds-1"),
        expected_previous_generation_digest: None,
        expires_at_ms: 500,
    };
    activate_generation(&fleet, &agent, &identity, &desired_one, &bundle_one, 100);

    let mut bundle_two = bundle_one.clone();
    bundle_two.manifest_digest = digest("manifest-2");
    let generation_two = Digest::of(canonical_bytes(&bundle_two).unwrap());
    let desired_two = DesiredGeneration {
        occurrence_id: "gate4-forward-2".into(),
        target_id: target_id.into(),
        capsule_digest: generation_two.clone(),
        xds_snapshot_digest: digest("xds-2"),
        expected_previous_generation_digest: Some(generation_one.clone()),
        expires_at_ms: 500,
    };
    activate_generation(&fleet, &agent, &identity, &desired_two, &bundle_two, 200);

    let rollback = DesiredGeneration {
        occurrence_id: "gate4-rollback-new-occurrence".into(),
        target_id: target_id.into(),
        capsule_digest: generation_one.clone(),
        xds_snapshot_digest: digest("xds-rollback-new-version"),
        expected_previous_generation_digest: Some(generation_two.clone()),
        expires_at_ms: 500,
    };
    let receipt = activate_generation(&fleet, &agent, &identity, &rollback, &bundle_one, 300);
    assert_eq!(receipt.claims.occurrence_id, rollback.occurrence_id);
    assert_eq!(receipt.claims.active_generation_digest, generation_one);
    assert_eq!(
        receipt.claims.previous_generation_digest,
        Some(generation_two)
    );
    assert_eq!(agent.active_generation().unwrap().unwrap().2, 3);
}
