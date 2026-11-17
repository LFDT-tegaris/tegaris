//! The producer uses real governed HTTP publication. Release-profile trust and
//! Fleet signing here are component fixtures, not a policy-release journey.
use super::*;
use crate::{CapsuleTrust, RuntimeActivationToken, RuntimeAgent, RuntimeWireSigner};
use pc_policy_core::{
    contract_simulation::compile_document_with_deployments,
    deployment_policy::AdmittedDeploymentPolicy, semantics::PolicySemanticDocument,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Publication {
    document: PolicySemanticDocument,
    admitted: Vec<AdmittedDeploymentPolicy>,
    workload_id: String,
}

#[test]
#[ignore = "requires the real governed deployment-publication producer"]
fn published_deployment_has_signed_target_custody_after_restart() {
    let path = std::path::PathBuf::from(
        std::env::var("OPENPC_ASTRA08_DEPLOYMENT_PUBLICATION_FIXTURE").unwrap(),
    );
    let input: Publication = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let compiled = compile_document_with_deployments(
        &input.document,
        &[],
        &input.admitted,
        &input.workload_id,
        &input.document.digest().unwrap(),
    )
    .unwrap();
    let signer = RuntimeWireSigner::from_secret_bytes([37; 32]).unwrap();
    let mut capsule = crate::wire_tests::capsule();
    capsule.artifact_components.clear();
    let mut artifacts = BTreeMap::new();
    let admission = crate::invocation_publication_fixture::install_sources(
        (
            &input.document.participant_id,
            &input.document.privacy_domain_id,
        ),
        &mut capsule,
        &mut artifacts,
        &signer,
        compiled.configuration_cbor,
        compiled.policy_cbor,
    );
    let trust = CapsuleTrust {
        target_id: capsule.target_runtime_id.clone(),
        fleet_id: capsule.fleet_id.clone(),
        fleet_signer_id: capsule.signer_id.clone(),
        agent_signer_id: "deployment-custody-component".into(),
        contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
        schema_registry_digest: capsule.schema_registry_digest.clone(),
        cose_purpose_registry_digest: capsule.cose_purpose_registry_digest.clone(),
        complete_component_set_digest: capsule.complete_component_set_digest.clone(),
    };
    let directory = path.parent().unwrap().join("deployment-target-custody");
    let open = || {
        RuntimeAgent::open_canonical(
            trust.clone(),
            &signer.verifier().public_key_bytes(),
            [38; 32],
            8,
            4 * 1024 * 1024,
            &directory,
            admission.clone(),
        )
        .unwrap()
    };
    let agent = open();
    let signed = signer.sign_capsule(&capsule).unwrap();
    let mut substituted = artifacts.clone();
    substituted.get_mut(&compiled.configuration_digest).unwrap()[0] ^= 1;
    assert!(
        agent
            .prepare_capsule(signed.clone(), substituted, 2)
            .is_err()
    );
    let mut missing = artifacts.clone();
    missing.remove(&compiled.policy_digest);
    assert!(agent.prepare_capsule(signed.clone(), missing, 2).is_err());
    let mut wrong = capsule.clone();
    wrong.semantic_model_digest = Digest::of(b"another policy source");
    assert!(
        agent
            .prepare_capsule(signer.sign_capsule(&wrong).unwrap(), artifacts.clone(), 2)
            .is_err()
    );
    assert!(agent.active_canonical_generation().unwrap().is_none());
    let capsule_digest = agent.prepare_capsule(signed, artifacts, 2).unwrap();
    let token = RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: capsule.target_runtime_id.clone(),
        occurrence_id: "urn:openpc:activation-occurrence:deployment-custody-component".into(),
        desired_generation_digest: capsule_digest.clone(),
        xds_version_digest: Digest::of(b"deployment-custody-component-xds"),
        expected_previous_generation_digest: None,
        issued_at_ns: 3,
        expires_at_ns: 50,
    };
    let signed_token = signer.sign_activation_token(&token).unwrap();
    let receipt = agent.activate_capsule_authorized(&signed_token, 4).unwrap();
    drop(agent);
    let agent = open();
    assert_eq!(
        agent
            .activate_capsule_authorized(&signed_token, 60)
            .unwrap(),
        receipt
    );
    assert_eq!(
        agent.active_canonical_generation().unwrap(),
        Some((capsule_digest.clone(), token.xds_version_digest.clone(), 1)),
    );
    agent
        .with_active_capsule(|active, bytes| {
            let (installed, _) = admission.admit_policies(active, bytes)?;
            assert_eq!(installed.capsule_digest, capsule_digest);
            assert_eq!(installed.participant_id, input.document.participant_id);
            assert_eq!(
                installed.privacy_domain_id,
                input.document.privacy_domain_id
            );
            assert_eq!(installed.workload_id, input.workload_id);
            assert!(
                installed.policies.is_empty(),
                "direct deployment must not fabricate a contract invocation"
            );
            assert_eq!(installed.deployment_policies.len(), 2);
            for (policy, published) in installed.deployment_policies.iter().zip(&input.admitted) {
                assert_eq!(policy.publication(), published);
                assert_eq!(
                    policy.policy_generation_digest(),
                    &active.policy_bundle_digest
                );
                assert_eq!(
                    policy.configuration_digest(),
                    &compiled.configuration_digest
                );
                assert_eq!(policy.policy_artifact_digest(), &compiled.policy_digest);
            }
            Ok(())
        })
        .unwrap();
    let mut another_token = token;
    another_token.token_id = uuid::Uuid::now_v7().to_string();
    assert_eq!(
        agent
            .activate_capsule_authorized(&signer.sign_activation_token(&another_token).unwrap(), 5),
        Err(RuntimeError::Replay),
    );
    drop(agent);
    std::fs::remove_dir_all(directory).unwrap();
}
