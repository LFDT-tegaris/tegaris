use super::*;
use crate::{RuntimeWireSigner, authority_artifact::AuthorityArtifact};
use openpc_fact_service::PurposeBoundFactSigner;

struct RejectOther;
impl ArtifactAdmission for RejectOther {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidInput)
    }
}

#[test]
fn fact_publication_requires_both_source_owners_and_exact_capsule_scope() {
    let owner = RuntimeWireSigner::from_secret_bytes([62; 32]).unwrap();
    let fact = PurposeBoundFactSigner::from_secret_bytes(b"fact-owner".to_vec(), [63; 32]).unwrap();
    let binding = AuthoritySourceBinding {
        artifact_id: "test-fact-publication".into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(b"test-only fact publication definition"),
        signer_id: "test-source-owner".into(),
        maximum_source_bytes: 16_384,
    };
    let admission = FactArtifactAdmission::new(
        owner.verifier(),
        fact.verifier(),
        "participant".into(),
        "privacy".into(),
        binding,
        Arc::new(RejectOther),
    )
    .unwrap();
    let original = fact
        .sign_shard("participant", "privacy", "generation", [64; 32])
        .unwrap();
    let foreign = fact
        .sign_shard("participant", "foreign-privacy", "generation", [64; 32])
        .unwrap();
    let wrong_signer = PurposeBoundFactSigner::from_secret_bytes(b"fact-owner".to_vec(), [65; 32])
        .unwrap()
        .sign_shard("participant", "privacy", "generation", [64; 32])
        .unwrap();
    for (index, shard) in [original, foreign, wrong_signer].into_iter().enumerate() {
        let source = AuthorityArtifact {
            artifact_id: admission.source.artifact_id.clone(),
            artifact_class: 1,
            artifact_version: 1,
            source_media_type: "application/cbor".into(),
            source_content_sha256: Digest::of(&shard.cose_sign1),
            definition_digest: admission.source.definition_digest.clone(),
            issued_at_ns: 1,
            signer_id: admission.source.signer_id.clone(),
        };
        let signed = owner.sign_authority_artifact(&source).unwrap();
        let mut capsule = crate::wire_tests::capsule();
        capsule.policy_fact_state_digest = source.semantic_digest().unwrap();
        capsule.artifact_components = vec![ArtifactComponent {
            component_id: source.artifact_id.clone(),
            component_type: "test-fact-source".into(),
            content_digest: Digest::of(&signed),
            semantic_digest: source.semantic_digest().unwrap(),
            schema_id: 1010,
            schema_version: 1,
            size_bytes: signed.len() as u64,
            required: true,
        }];
        let mut artifacts = BTreeMap::from([
            (Digest::of(&signed), signed),
            (Digest::of(&shard.cose_sign1), shard.cose_sign1),
        ]);
        let actual = admission.admit_fact_state(&capsule, &artifacts);
        if index != 0 {
            assert!(
                actual.is_err(),
                "a valid wrapper cannot replace the Fact owner's authority"
            );
            continue;
        }
        let (installed, closure) = actual.unwrap();
        assert!(
            installed.local.is_none(),
            "a legacy digest-only shard cannot supply local condition values"
        );
        assert_eq!(
            installed.shard.as_ref().unwrap().generation_id(),
            "generation"
        );
        assert_eq!(installed.capsule_digest, capsule.digest().unwrap());
        assert_eq!(closure, artifacts.keys().cloned().collect());
        let content_key = Digest::parse("40".repeat(32)).unwrap();
        artifacts.insert(content_key.clone(), b"caller-provided membership".to_vec());
        assert!(admission.admit_fact_state(&capsule, &artifacts).is_err());
        artifacts.remove(&content_key);
        let correct_digest = capsule.policy_fact_state_digest.clone();
        capsule.policy_fact_state_digest = Digest::of(b"another fact state");
        assert!(admission.admit_fact_state(&capsule, &artifacts).is_err());
        capsule.policy_fact_state_digest = correct_digest;
        capsule.artifact_components[0].required = false;
        assert!(admission.admit_fact_state(&capsule, &artifacts).is_err());
        capsule.artifact_components[0].required = true;
        artifacts
            .get_mut(&source.source_content_sha256)
            .unwrap()
            .push(0);
        assert!(admission.admit_fact_state(&capsule, &artifacts).is_err());
    }
}

#[test]
fn no_fact_publication_is_exact_and_cannot_satisfy_declared_facts() {
    let mut capsule = crate::wire_tests::capsule();
    capsule.policy_fact_state_digest = Digest::of(crate::indexer_custody::NO_FACT_PUBLICATION);
    let state = InstalledFactState::no_publication(&capsule).unwrap();
    assert!(state.shard.is_none());

    let mut changed = capsule.clone();
    changed.policy_fact_state_digest = Digest::of(b"missing declared fact publication");
    assert!(InstalledFactState::no_publication(&changed).is_err());
}
