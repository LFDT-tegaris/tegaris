//! Component custody uses compiler fixtures, not public activation authority.
use super::*;
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent, CapsuleTrust, RuntimeActivationToken, RuntimeAgent,
    RuntimeCapsule, RuntimeWireSigner,
    authority_artifact::{AuthorityArtifact, AuthoritySourceBinding},
    indexer_custody::*,
};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

struct Reject;
impl ArtifactAdmission for Reject {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidAuthorization)
    }
}
struct Fixture {
    capsule: RuntimeCapsule,
    artifacts: BTreeMap<Digest, Vec<u8>>,
    signer: RuntimeWireSigner,
    admission: Arc<IndexerArtifactAdmission>,
    participant: String,
    privacy: String,
}
impl Fixture {
    fn new() -> Self {
        let (document, configuration_cbor) = super::fixture::source_input();
        let compiled = compile_document_with_indexers(
            &document,
            &[],
            &[],
            &[pc_policy_core::indexer_policy::IndexerCompilationInput {
                configuration_digest: Digest::of(&configuration_cbor),
                configuration_cbor,
            }],
            &document.indexer_policies[0].workload_id,
            &document.digest().unwrap(),
        )
        .unwrap();
        let signer = RuntimeWireSigner::from_secret_bytes([37; 32]).unwrap();
        let d = Digest::of(b"source custody test registry");
        let mut capsule = RuntimeCapsule {
            capsule_id: "source-custody".into(),
            lifecycle_mode: 1,
            target_runtime_id: "source-target".into(),
            fleet_id: "source-fleet".into(),
            generation: 1,
            previous_capsule_digest: None,
            contract_set_manifest_digest: d.clone(),
            schema_registry_digest: d.clone(),
            cose_purpose_registry_digest: d.clone(),
            complete_component_set_digest: d.clone(),
            identity_snapshot_manifest_digest: d.clone(),
            blocklist_digest: d.clone(),
            routing_snapshot_digest: d.clone(),
            provider_certification_registry_digest: d.clone(),
            mrpc_runtime_profile_digest: d.clone(),
            dynamic_event_profile_digest: d.clone(),
            rpc_invocation_profile_digest: d.clone(),
            capability_registry_digest: d.clone(),
            request_form_registry_digest: d.clone(),
            error_registry_digest: d.clone(),
            evidence_admission_profile_digest: d.clone(),
            policy_bundle_digest: document.digest().unwrap(),
            semantic_model_digest: compiled.policy_digest,
            named_set_registry_digest: compiled.configuration_digest,
            policy_fact_state_digest: Digest::of(NO_FACT_PUBLICATION),
            emergency_deny_generation: 0,
            issued_at_ns: 1,
            not_before_ns: 2,
            hard_expiry_ns: 100,
            signer_id: "fleet-signer".into(),
            artifact_components: vec![],
        };
        let mut artifacts = BTreeMap::new();
        for (id, definition, bytes) in [
            (
                CONFIGURATION_ARTIFACT_ID,
                CONFIGURATION_DEFINITION,
                compiled.configuration_cbor,
            ),
            (POLICY_ARTIFACT_ID, POLICY_DEFINITION, compiled.policy_cbor),
        ] {
            let header = AuthorityArtifact {
                artifact_id: id.into(),
                artifact_version: 1,
                artifact_class: 1,
                source_media_type: "application/cbor".into(),
                source_content_sha256: Digest::of(&bytes),
                definition_digest: Digest::of(definition),
                issued_at_ns: 1,
                signer_id: "source-owner".into(),
            };
            let signed = signer.sign_authority_artifact(&header).unwrap();
            capsule.artifact_components.push(ArtifactComponent {
                component_id: id.into(),
                component_type: "source-policy".into(),
                content_digest: Digest::of(&signed),
                semantic_digest: header.semantic_digest().unwrap(),
                schema_id: 1010,
                schema_version: 1,
                size_bytes: signed.len() as u64,
                required: true,
            });
            artifacts.insert(header.source_content_sha256, bytes);
            artifacts.insert(Digest::of(&signed), signed);
        }
        capsule
            .artifact_components
            .sort_by_key(|c| c.canonical_bytes().unwrap());
        let admission = Self::admission(
            &signer,
            &document.participant_id,
            &document.privacy_domain_id,
        );
        Self {
            capsule,
            artifacts,
            signer,
            admission,
            participant: document.participant_id,
            privacy: document.privacy_domain_id,
        }
    }
    fn admission(
        signer: &RuntimeWireSigner,
        participant: &str,
        privacy: &str,
    ) -> Arc<IndexerArtifactAdmission> {
        let binding = |id: &str, definition: &[u8]| AuthoritySourceBinding {
            artifact_id: id.into(),
            artifact_class: 1,
            source_media_type: "application/cbor".into(),
            definition_digest: Digest::of(definition),
            signer_id: "source-owner".into(),
            maximum_source_bytes: 4 * 1024 * 1024,
        };
        Arc::new(
            IndexerArtifactAdmission::new(
                signer.verifier(),
                participant.into(),
                privacy.into(),
                binding(CONFIGURATION_ARTIFACT_ID, CONFIGURATION_DEFINITION),
                binding(POLICY_ARTIFACT_ID, POLICY_DEFINITION),
                Arc::new(Reject),
            )
            .unwrap(),
        )
    }
    fn trust(&self) -> CapsuleTrust {
        let c = &self.capsule;
        CapsuleTrust {
            target_id: c.target_runtime_id.clone(),
            fleet_id: c.fleet_id.clone(),
            fleet_signer_id: c.signer_id.clone(),
            agent_signer_id: "agent-signer".into(),
            contract_set_manifest_digest: c.contract_set_manifest_digest.clone(),
            schema_registry_digest: c.schema_registry_digest.clone(),
            cose_purpose_registry_digest: c.cose_purpose_registry_digest.clone(),
            complete_component_set_digest: c.complete_component_set_digest.clone(),
        }
    }
}
#[test]
fn signed_source_custody_rejects_scope_source_header_and_component_substitution() {
    let f = Fixture::new();
    let (_, closure) = f
        .admission
        .admit_policies(&f.capsule, &f.artifacts)
        .unwrap();
    assert_eq!(
        closure,
        f.artifacts.keys().cloned().collect::<BTreeSet<_>>()
    );
    assert!(
        Fixture::admission(
            &f.signer,
            &f.participant,
            "018f0000-0000-7000-8000-000000000999"
        )
        .admit_policies(&f.capsule, &f.artifacts)
        .is_err()
    );
    assert!(
        Fixture::admission(
            &RuntimeWireSigner::from_secret_bytes([38; 32]).unwrap(),
            &f.participant,
            &f.privacy
        )
        .admit_policies(&f.capsule, &f.artifacts)
        .is_err()
    );
    for digest in f.artifacts.keys() {
        let mut missing = f.artifacts.clone();
        missing.remove(digest);
        assert!(f.admission.admit_policies(&f.capsule, &missing).is_err());
        let mut corrupt = f.artifacts.clone();
        corrupt.get_mut(digest).unwrap()[0] ^= 1;
        assert!(f.admission.admit_policies(&f.capsule, &corrupt).is_err());
    }
    for i in 0..5 {
        let mut changed = f.capsule.clone();
        match i {
            0 => changed.semantic_model_digest = Digest::of(b"other policy"),
            1 => changed.named_set_registry_digest = Digest::of(b"other configuration"),
            2 => changed.policy_fact_state_digest = Digest::of(b"invented fact state"),
            3 => changed.artifact_components[0].required = false,
            4 => changed
                .artifact_components
                .push(changed.artifact_components[0].clone()),
            _ => unreachable!(),
        }
        assert!(
            f.admission.admit_policies(&changed, &f.artifacts).is_err(),
            "substitution {i}"
        );
    }
    for i in 0..3 {
        let mut changed = f.capsule.clone();
        let mut artifacts = f.artifacts.clone();
        let c = &mut changed.artifact_components[0];
        let mut header = f
            .signer
            .verifier()
            .verify_authority_artifact(artifacts.get(&c.content_digest).unwrap())
            .unwrap();
        match i {
            0 => header.definition_digest = Digest::of(b"another installed definition"),
            1 => header.signer_id = "another-owner".into(),
            2 => header.issued_at_ns = 2,
            _ => unreachable!(),
        }
        let signed = f.signer.sign_authority_artifact(&header).unwrap();
        artifacts.remove(&c.content_digest);
        c.content_digest = Digest::of(&signed);
        c.semantic_digest = header.semantic_digest().unwrap();
        c.size_bytes = signed.len() as u64;
        artifacts.insert(c.content_digest.clone(), signed);
        assert!(f.admission.admit_policies(&changed, &artifacts).is_err());
    }
}
#[test]
fn signed_source_policy_cannot_claim_an_unpublished_fact_dependency() {
    let mut f = Fixture::new();
    let mut policy = decode_active_invocation_policy_generation(
        f.artifacts.get(&f.capsule.semantic_model_digest).unwrap(),
        &f.capsule.semantic_model_digest,
    )
    .unwrap();
    policy
        .required_facts
        .push(pc_policy_core::semantics::FactReference {
            candidate_id: "018f0000-0000-7000-8000-000000000911".into(),
            generation_id: "018f0000-0000-7000-8000-000000000912".into(),
            fact_digest: format!("sha256:{}", Digest::of(b"unpublished fact").as_str()),
        });
    let bytes =
        pc_policy_core::invocation::encode_active_invocation_policy_generation(&policy).unwrap();
    let component = f
        .capsule
        .artifact_components
        .iter_mut()
        .find(|c| c.component_id == POLICY_ARTIFACT_ID)
        .unwrap();
    let mut header = f
        .signer
        .verifier()
        .verify_authority_artifact(f.artifacts.get(&component.content_digest).unwrap())
        .unwrap();
    f.artifacts.remove(&component.content_digest);
    f.artifacts.remove(&header.source_content_sha256);
    header.source_content_sha256 = Digest::of(&bytes);
    f.capsule.semantic_model_digest = header.source_content_sha256.clone();
    let signed = f.signer.sign_authority_artifact(&header).unwrap();
    component.content_digest = Digest::of(&signed);
    component.semantic_digest = header.semantic_digest().unwrap();
    component.size_bytes = signed.len() as u64;
    f.artifacts.insert(header.source_content_sha256, bytes);
    f.artifacts.insert(component.content_digest.clone(), signed);
    assert!(
        f.admission
            .admit_policies(&f.capsule, &f.artifacts)
            .is_err(),
        "even an authentic policy cannot satisfy a Fact dependency without its independent publication"
    );
}

#[test]
fn source_custody_restarts_without_fact_artifacts_and_replays_only_original_activation() {
    let f = Fixture::new();
    let directory = std::env::var_os("OPENPC_TEST_TMP_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("source-custody-{}", uuid::Uuid::now_v7()));
    let open = || {
        RuntimeAgent::open_canonical(
            f.trust(),
            &f.signer.verifier().public_key_bytes(),
            [39; 32],
            8,
            4 * 1024 * 1024,
            &directory,
            f.admission.clone(),
        )
        .unwrap()
    };
    let agent = open();
    let signed = f.signer.sign_capsule(&f.capsule).unwrap();
    let mut extra = f.artifacts.clone();
    extra.insert(Digest::of(b"unbound fact"), b"unbound fact".to_vec());
    assert!(agent.prepare_capsule(signed.clone(), extra, 2).is_err());
    let digest = agent
        .prepare_capsule(signed, f.artifacts.clone(), 2)
        .unwrap();
    let token = RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        occurrence_id: "source-custody-test".into(),
        desired_generation_digest: digest.clone(),
        xds_version_digest: Digest::of(b"source-custody-xds"),
        expected_previous_generation_digest: None,
        issued_at_ns: 3,
        expires_at_ns: 50,
    };
    let signed_token = f.signer.sign_activation_token(&token).unwrap();
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
        Some((digest, token.xds_version_digest.clone(), 1))
    );
    agent
        .with_active_capsule(|capsule, artifacts| {
            assert_eq!(artifacts.len(), 4);
            assert!(
                capsule
                    .artifact_components
                    .iter()
                    .all(|c| c.schema_id == 1010)
            );
            f.admission.admit_policies(capsule, artifacts)?;
            Ok(())
        })
        .unwrap();
    let mut replay = token;
    replay.token_id = uuid::Uuid::now_v7().to_string();
    assert_eq!(
        agent.activate_capsule_authorized(&f.signer.sign_activation_token(&replay).unwrap(), 5),
        Err(RuntimeError::Replay)
    );
    drop(agent);
    std::fs::remove_dir_all(directory).unwrap();
}
