use super::*;
use crate::capsule::{map, uint};
use ciborium::value::Value;
use pc_policy_core::pc_cbor_1;

pub(crate) fn capsule() -> RuntimeCapsule {
    let d = Digest::of(b"test runtime component");
    RuntimeCapsule {
        capsule_id: "capsule-1".into(),
        lifecycle_mode: 1,
        target_runtime_id: "target-1".into(),
        fleet_id: "fleet-1".into(),
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
        signer_id: "fleet-key-1".into(),
        artifact_components: vec![ArtifactComponent {
            component_id: "policy-1".into(),
            component_type: "policy".into(),
            content_digest: d.clone(),
            semantic_digest: d,
            schema_id: 1002,
            schema_version: 1,
            size_bytes: 22,
            required: true,
        }],
    }
}
#[test]
fn capsule_lineage_uses_schema_bound_semantic_identity() {
    let capsule = capsule();
    // Independently encoded with the archived reference CBOR implementation
    // and CANON-CONTRACT-001's envelope/domain, not this crate's codec.
    assert_eq!(
        capsule.digest().unwrap().as_str(),
        "9d634d3df4d7eebe143dda2e3c3904dc6b8b92247951a60f175df34e3ce26562"
    );
    assert_ne!(
        capsule.digest().unwrap(),
        Digest::of(capsule.encode().unwrap())
    );
    assert_ne!(
        capsule.digest().unwrap(),
        crate::cose::semantic_digest(crate::cose::Profile::Receipt, &capsule.encode().unwrap())
            .unwrap()
    );
}
#[test]
fn primary_signatures_are_bound_to_exact_schema_purpose_key_and_payload() {
    let signer = RuntimeWireSigner::from_secret_bytes([21; 32]).unwrap();
    let capsule = capsule();
    let signed = signer.sign_capsule(&capsule).unwrap();
    assert_eq!(signer.verifier().verify_capsule(&signed).unwrap(), capsule);
    assert!(
        RuntimeWireSigner::from_secret_bytes([22; 32])
            .unwrap()
            .verifier()
            .verify_capsule(&signed)
            .is_err()
    );
    assert!(signer.verifier().verify_receipt(&signed).is_err());
    assert!(signer.verifier().verify_ack(&signed).is_err());
    let token = RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: capsule.target_runtime_id.clone(),
        occurrence_id: "urn:openpc:activation-occurrence:test".into(),
        desired_generation_digest: capsule.digest().unwrap(),
        xds_version_digest: Digest::of(b"xds"),
        expected_previous_generation_digest: None,
        issued_at_ns: 2,
        expires_at_ns: 10,
    };
    let signed_token = signer.sign_activation_token(&token).unwrap();
    assert_eq!(
        signer
            .verifier()
            .verify_activation_token(&signed_token)
            .unwrap(),
        token
    );
    assert!(signer.verifier().verify_capsule(&signed_token).is_err());
    assert!(signer.verifier().verify_activation_token(&signed).is_err());
    let mut tampered = signed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(signer.verifier().verify_capsule(&tampered).is_err());
    let wrongly_signed = signer
        .sign(crate::cose::Profile::Receipt, &capsule.encode().unwrap())
        .unwrap();
    assert!(signer.verifier().verify_capsule(&wrongly_signed).is_err());
}
#[test]
fn lineage_time_order_and_component_constraints_are_closed() {
    let original = capsule();
    let mut value = original.clone();
    value.previous_capsule_digest = Some(Digest::of(b"previous"));
    assert!(value.encode().is_err());
    value.lifecycle_mode = 2;
    assert!(value.encode().is_ok());
    value.previous_capsule_digest = None;
    assert!(value.encode().is_err());
    value = original.clone();
    value.not_before_ns = value.issued_at_ns;
    assert!(value.encode().is_err());
    value = original.clone();
    value.hard_expiry_ns = value.not_before_ns;
    assert!(value.encode().is_err());
    value = original.clone();
    value.artifact_components[0].component_id = "/bad".into();
    assert!(value.encode().is_err());
    value = original.clone();
    value.artifact_components[0].schema_id = 0;
    assert!(value.encode().is_err());
    value = original.clone();
    value
        .artifact_components
        .push(value.artifact_components[0].clone());
    assert!(value.encode().is_err());
    value = original;
    value.artifact_components[0].component_id = "bb".into();
    let mut second = value.artifact_components[0].clone();
    second.component_id = "z".into();
    value.artifact_components.push(second);
    assert!(
        value.encode().is_err(),
        "canonical ordering compares encoded bytes, not text names"
    );
    value.artifact_components.reverse();
    assert!(value.encode().is_ok());
}
#[test]
fn decoder_rejects_unknown_duplicate_noncanonical_and_trailing_fields() {
    let valid = capsule().encode().unwrap();
    let value = crate::cose::decode(&valid, 1_048_576).unwrap();
    let mut entries = value.as_map().unwrap().clone();
    entries.push((uint(31), uint(0)));
    assert!(RuntimeCapsule::decode(&pc_cbor_1(&Value::Map(entries))).is_err());
    let mut entries = value.as_map().unwrap().clone();
    entries.push(entries[0].clone());
    let mut duplicate_bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut duplicate_bytes).unwrap();
    assert!(RuntimeCapsule::decode(&duplicate_bytes).is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(RuntimeCapsule::decode(&trailing).is_err());
    let mut widened = valid;
    widened.splice(2..3, [0x18, 0]);
    assert!(RuntimeCapsule::decode(&widened).is_err());
    assert!(RuntimeCapsule::decode(&pc_cbor_1(&map(vec![(0, uint(1))]))).is_err());
}
#[test]
fn receipt_and_ack_keep_distinct_canonical_preimages() {
    let signer = RuntimeWireSigner::from_secret_bytes([23; 32]).unwrap();
    let d = capsule().digest().unwrap();
    let receipt = TargetActivationReceipt {
        receipt_id: "receipt-1".into(),
        target_runtime_id: "target-1".into(),
        capsule_digest: d.clone(),
        contract_set_manifest_digest: d.clone(),
        complete_component_set_digest: d.clone(),
        status: 1,
        reason_code: "TEST_RECEIPT".into(),
        observed_at_ns: 10,
        agent_sequence: 1,
        signer_id: "agent-key-1".into(),
    };
    let signed = signer.sign_receipt(&receipt).unwrap();
    assert_eq!(signer.verifier().verify_receipt(&signed).unwrap(), receipt);
    assert!(signer.verifier().verify_ack(&signed).is_err());
    let ack = RuntimeActivationAck {
        ack_id: "ack-1".into(),
        target_runtime_id: "target-1".into(),
        capsule_digest: d,
        generation: 1,
        status: 1,
        reason_code: "TEST_ACK".into(),
        acknowledged_at_ns: 10,
        agent_sequence: 1,
        signer_id: "agent-key-1".into(),
    };
    let signed = signer.sign_ack(&ack).unwrap();
    assert_eq!(signer.verifier().verify_ack(&signed).unwrap(), ack);
    assert!(signer.verifier().verify_receipt(&signed).is_err());
}

#[test]
fn full_registered_component_count_uses_collection_budget_not_scalar_count() {
    let mut capsule = capsule();
    let component = capsule.artifact_components[0].clone();
    capsule.artifact_components = (0..512)
        .map(|i| {
            let mut component = component.clone();
            component.component_id = format!("component-{i:04}");
            component
        })
        .collect();
    let bytes = capsule.encode().unwrap();
    assert_eq!(RuntimeCapsule::decode(&bytes).unwrap(), capsule);
    let mut extra = component;
    extra.component_id = "component-0512".into();
    capsule.artifact_components.push(extra);
    assert_eq!(capsule.encode(), Err(RuntimeError::InvalidInput));
}
