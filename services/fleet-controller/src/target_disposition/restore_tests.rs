use super::*;
use openpc_runtime_agent::indexer_custody::{
    CONFIGURATION_ARTIFACT_ID, CONFIGURATION_DEFINITION, NO_FACT_PUBLICATION, POLICY_ARTIFACT_ID,
    POLICY_DEFINITION,
};
use openpc_runtime_agent::{
    ArtifactComponent, RuntimeWireSigner, authority_artifact::AuthorityArtifact,
};
use pc_policy_core::invocation::{
    ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
    encode_active_invocation_configuration, encode_active_invocation_policy_generation,
};
use pc_policy_core::visibility_policy::VisibilityPolicy;

fn id(n: u16) -> String {
    format!("01950000-0000-7000-8000-{n:012x}")
}
fn capsule() -> RuntimeCapsule {
    let d = Digest::of(b"component-test-only");
    let mut value = serde_json::json!({
        "capsule_id":id(1), "lifecycle_mode":1, "target_runtime_id":id(2), "fleet_id":id(3),
        "generation":1, "previous_capsule_digest":null, "emergency_deny_generation":0,
        "issued_at_ns":1, "not_before_ns":2, "hard_expiry_ns":100, "signer_id":"fleet-test-owner",
        "artifact_components":[{
            "component_id":"component", "component_type":"component", "content_digest":d, "semantic_digest":d,
            "schema_id":1010, "schema_version":1, "size_bytes":1, "required":true
        }]
    });
    for field in [
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
        value[field] = serde_json::to_value(&d).unwrap();
    }
    serde_json::from_value(value).unwrap()
}

fn fixture(invocation: bool) -> (RuntimeCapsule, BTreeMap<Digest, Vec<u8>>) {
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let workload = "urn:openpc:workload:018f0000-0000-7000-8000-000000000191";
    let selector = serde_json::json!({"kind":"TRANSACTION", "runtimeBindingId":"018f0000-0000-7000-8000-000000000501", "bindingRevision":"1"});
    let visibility: VisibilityPolicy = serde_json::from_value(serde_json::json!({
            "policyId":"018f0000-0000-7000-8000-000000000901", "selector":selector,
            "mode":"STATIC", "effect":"ALLOW", "subject":{"kind":"PRINCIPAL", "principalId":"018f0000-0000-7000-8000-000000000301"},
            "purpose":"AUDIT", "requiredRoles":["reader"], "dimensions":["EXISTENCE","PAYLOAD"], "fields":["from"], "conditions":[]
        })).unwrap();
    let configuration = ActiveInvocationConfigurationV1 {
        workload_scope: Some(pc_policy_core::invocation::InvocationConfigurationScope {
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            workload_id: workload.into(),
        }),
        visibility_resources: vec![
            pc_policy_core::visibility_policy::AdmittedVisibilityResource {
                state_output_types: None,
                contract_binding: None,
                participant_id: participant.into(),
                privacy_domain_id: privacy.into(),
                selector: visibility.selector.clone(),
                available_fields: vec!["from".into()],
            },
        ],
        schema_version: "1.0".into(),
        assets: vec![],
        resource_artifacts: vec![],
        deployment_policies: vec![],
    };
    let generation = ActiveInvocationPolicyGenerationV1 {
        visibility_policies: vec![visibility],
        fact_conditions: vec![],
        indexer_policies: vec![],
        schema_version: "1.0".into(),
        root_asset_ids: vec![],
        assets: vec![],
        rpc_policies: vec![],
        required_facts: vec![],
        deployment_policies: vec![],
    };

    let signer = RuntimeWireSigner::from_secret_bytes([37; 32]).unwrap();
    let mut capsule = capsule();
    capsule.artifact_components.clear();
    capsule.policy_fact_state_digest = Digest::of(NO_FACT_PUBLICATION);
    let mut artifacts = BTreeMap::new();
    for (id, definition, bytes) in [
        (
            if invocation {
                "openpc.invocation.configuration"
            } else {
                CONFIGURATION_ARTIFACT_ID
            },
            if invocation {
                b"openpc.invocation.configuration-source.v1".as_slice()
            } else {
                CONFIGURATION_DEFINITION
            },
            encode_active_invocation_configuration(&configuration).unwrap(),
        ),
        (
            if invocation {
                "openpc.invocation.policy"
            } else {
                POLICY_ARTIFACT_ID
            },
            if invocation {
                b"openpc.invocation.policy-source.v1".as_slice()
            } else {
                POLICY_DEFINITION
            },
            encode_active_invocation_policy_generation(&generation).unwrap(),
        ),
    ] {
        let header = AuthorityArtifact {
            artifact_id: id.into(),
            artifact_version: 1,
            artifact_class: 1,
            source_media_type: "application/cbor".into(),
            source_content_sha256: Digest::of(&bytes),
            definition_digest: Digest::of(definition),
            issued_at_ns: capsule.issued_at_ns,
            signer_id: "fixture-source-owner".into(),
        };
        let signed = signer.sign_authority_artifact(&header).unwrap();
        capsule.artifact_components.push(ArtifactComponent {
            component_id: id.into(),
            component_type: "canonical-authority".into(),
            content_digest: Digest::of(&signed),
            semantic_digest: header.semantic_digest().unwrap(),
            schema_id: 1010,
            schema_version: 1,
            size_bytes: signed.len() as u64,
            required: true,
        });
        if id.ends_with("configuration") {
            capsule.named_set_registry_digest = Digest::of(&bytes);
        } else {
            capsule.semantic_model_digest = Digest::of(&bytes);
        }
        artifacts.insert(Digest::of(&bytes), bytes);
        artifacts.insert(Digest::of(&signed), signed);
    }
    capsule
        .artifact_components
        .sort_by_key(|c| c.canonical_bytes().unwrap());
    (capsule, artifacts)
}

fn store(participant: &str, privacy: &str) -> TargetDispositionStore {
    TargetDispositionStore::from_host_installation(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unavailable")
            .unwrap(),
        participant.into(),
        privacy.into(),
        [37; 32],
        [38; 32],
        BTreeMap::new(),
    )
    .unwrap()
}

#[tokio::test]
async fn fact_free_confirmation_accepts_signed_source_and_existing_invocation_bindings() {
    let store = store(
        "018f0000-0000-7000-8000-000000000101",
        "018f0000-0000-7000-8000-000000000201",
    );
    for invocation in [false, true] {
        let (capsule, artifacts) = fixture(invocation);
        assert_eq!(
            store
                .fact_free_restore_workload(&capsule, &artifacts, "fixture-source-owner")
                .unwrap(),
            "urn:openpc:workload:018f0000-0000-7000-8000-000000000191"
        );
    }
}

#[tokio::test]
async fn source_confirmation_rejects_missing_mixed_duplicate_and_tampered_custody() {
    let store = store(
        "018f0000-0000-7000-8000-000000000101",
        "018f0000-0000-7000-8000-000000000201",
    );
    for mutation in [
        "missing-policy",
        "missing-configuration",
        "mixed-policy",
        "mixed-configuration",
        "duplicate",
        "signature",
        "content",
        "fact",
        "generation",
        "configuration",
        "optional",
        "schema",
    ] {
        let (mut capsule, mut artifacts) = fixture(false);
        match mutation {
            "missing-policy" => capsule
                .artifact_components
                .retain(|c| c.component_id != POLICY_ARTIFACT_ID),
            "missing-configuration" => capsule
                .artifact_components
                .retain(|c| c.component_id != CONFIGURATION_ARTIFACT_ID),
            "mixed-policy" | "mixed-configuration" => {
                let (other, _) = fixture(true);
                capsule.artifact_components.push(
                    other
                        .artifact_components
                        .into_iter()
                        .find(|c| {
                            c.component_id.ends_with(if mutation == "mixed-policy" {
                                "policy"
                            } else {
                                "configuration"
                            })
                        })
                        .unwrap(),
                );
            }
            "duplicate" => capsule
                .artifact_components
                .push(capsule.artifact_components[0].clone()),
            "signature" => {
                artifacts
                    .get_mut(&capsule.artifact_components[0].content_digest)
                    .unwrap()[0] ^= 1
            }
            "content" => artifacts.get_mut(&capsule.semantic_model_digest).unwrap()[0] ^= 1,
            "fact" => capsule.policy_fact_state_digest = Digest::of(b"foreign-fact"),
            "generation" => capsule.semantic_model_digest = Digest::of(b"foreign-generation"),
            "configuration" => {
                capsule.named_set_registry_digest = Digest::of(b"foreign-configuration")
            }
            "optional" => capsule.artifact_components[0].required = false,
            "schema" => capsule.artifact_components[0].schema_id = 3004,
            _ => unreachable!(),
        }
        assert!(
            store
                .fact_free_restore_workload(&capsule, &artifacts, "fixture-source-owner")
                .is_err(),
            "{mutation}"
        );
    }
}

#[tokio::test]
async fn source_confirmation_requires_installed_owner_and_tenant_scope() {
    let (capsule, artifacts) = fixture(false);
    for (participant, privacy, signer) in [
        (
            "018f0000-0000-7000-8000-000000000102",
            "018f0000-0000-7000-8000-000000000201",
            "fixture-source-owner",
        ),
        (
            "018f0000-0000-7000-8000-000000000101",
            "018f0000-0000-7000-8000-000000000202",
            "fixture-source-owner",
        ),
        (
            "018f0000-0000-7000-8000-000000000101",
            "018f0000-0000-7000-8000-000000000201",
            "foreign-owner",
        ),
    ] {
        assert!(
            store(participant, privacy)
                .fact_free_restore_workload(&capsule, &artifacts, signer)
                .is_err()
        );
    }
}
