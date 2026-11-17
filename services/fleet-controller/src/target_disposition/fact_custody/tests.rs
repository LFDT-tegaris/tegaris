use super::*;
use openpc_fact_service::PurposeBoundFactSigner;
use openpc_runtime_agent::{
    RuntimeWireSigner,
    authority_artifact::AuthorityArtifact,
    routing_custody::{ProviderCertification, RoutingAssignment},
};

fn id(n: u16) -> String {
    format!("01950000-0000-7000-8000-{n:012x}")
}
fn reference(n: u16) -> FactReference {
    FactReference {
        candidate_id: id(n),
        generation_id: id(900),
        fact_digest: format!("sha256:{}", Digest::of(n.to_be_bytes()).as_str()),
    }
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
fn signed_fact(
    wrapper: &RuntimeWireSigner,
    fact: &PurposeBoundFactSigner,
    privacy: &str,
) -> (RuntimeCapsule, BTreeMap<Digest, Vec<u8>>) {
    let shard = fact
        .sign_shard(&id(10), privacy, &id(900), [73; 32])
        .unwrap();
    let authority = AuthorityArtifact {
        artifact_id: FACT_ID.into(),
        artifact_class: 1,
        artifact_version: 1,
        source_media_type: "application/cbor".into(),
        source_content_sha256: Digest::of(&shard.cose_sign1),
        definition_digest: Digest::of(FACT_DEFINITION),
        issued_at_ns: 1,
        signer_id: "installed-authority".into(),
    };
    let signed = wrapper.sign_authority_artifact(&authority).unwrap();
    let mut capsule = capsule();
    capsule.policy_fact_state_digest = authority.semantic_digest().unwrap();
    capsule.artifact_components = vec![ArtifactComponent {
        component_id: FACT_ID.into(),
        component_type: "fact-source".into(),
        content_digest: Digest::of(&signed),
        semantic_digest: capsule.policy_fact_state_digest.clone(),
        schema_id: 1010,
        schema_version: 1,
        size_bytes: signed.len() as u64,
        required: true,
    }];
    (
        capsule,
        BTreeMap::from([
            (Digest::of(&signed), signed),
            (Digest::of(&shard.cose_sign1), shard.cose_sign1),
        ]),
    )
}

#[test]
fn retained_fact_requires_both_real_signatures_exact_scope_and_original_bytes() {
    let authority = RuntimeWireSigner::from_secret_bytes([72; 32]).unwrap();
    let wrong_authority = RuntimeWireSigner::from_secret_bytes([73; 32]).unwrap();
    let facts = PurposeBoundFactSigner::from_secret_bytes(b"original-fact-test".to_vec(), [74; 32])
        .unwrap();
    let wrong_facts =
        PurposeBoundFactSigner::from_secret_bytes(b"original-fact-test".to_vec(), [75; 32])
            .unwrap();
    let verifier = facts.verifier();
    let trust = TargetFactTrust {
        fact_verifier: &verifier,
        installed_authority_signer_id: "installed-authority",
    };
    for (index, (capsule, artifacts)) in [
        signed_fact(&authority, &facts, &id(11)),
        signed_fact(&wrong_authority, &facts, &id(11)),
        signed_fact(&authority, &wrong_facts, &id(11)),
        signed_fact(&authority, &facts, &id(12)),
    ]
    .into_iter()
    .enumerate()
    {
        let result = authenticated_fact_shard(
            &authority.verifier(),
            &id(10),
            &id(11),
            &trust,
            &capsule,
            &artifacts,
        );
        assert_eq!(result.is_ok(), index == 0, "case {index}");
    }
    let (original, artifacts) = signed_fact(&authority, &facts, &id(11));
    for case in 0..6 {
        let mut changed = original.clone();
        let mut content = artifacts.clone();
        match case {
            0 => changed.policy_fact_state_digest = Digest::of(b"replacement state"),
            1 => changed.artifact_components[0].required = false,
            2 => changed.artifact_components[0].schema_id = 3101,
            3 => changed
                .artifact_components
                .push(changed.artifact_components[0].clone()),
            4 => content
                .get_mut(&changed.artifact_components[0].content_digest)
                .unwrap()
                .push(0),
            _ => {
                content.insert(
                    Digest::parse("49".repeat(32)).unwrap(),
                    b"unverified local values".to_vec(),
                );
            }
        }
        assert!(
            authenticated_fact_shard(
                &authority.verifier(),
                &id(10),
                &id(11),
                &trust,
                &changed,
                &content
            )
            .is_err(),
            "case {case}"
        );
    }
    let substituted = TargetFactTrust {
        fact_verifier: &verifier,
        installed_authority_signer_id: "received-header-signer",
    };
    assert!(
        authenticated_fact_shard(
            &authority.verifier(),
            &id(10),
            &id(11),
            &substituted,
            &original,
            &artifacts
        )
        .is_err()
    );
}

#[test]
fn dependencies_include_policy_routing_and_certification_without_conflicting_aliases() {
    let policy = vec![reference(1)];
    let routing = vec![reference(2), reference(1)];
    let certificates = vec![reference(3)];
    assert_eq!(
        dependency_union([
            policy.as_slice(),
            routing.as_slice(),
            certificates.as_slice()
        ])
        .unwrap(),
        vec![reference(1), reference(2), reference(3)]
    );
    for field in 0..2 {
        let mut conflict = reference(1);
        if field == 0 {
            conflict.generation_id = id(901);
        } else {
            conflict.fact_digest = format!("sha256:{}", "00".repeat(32));
        }
        assert!(dependency_union([policy.as_slice(), &[conflict]]).is_err());
    }
    assert!(dependency_union([&[][..]]).is_err());
    assert!(dependency_union([&[reference(1), reference(1)][..]]).is_err());
    let group = (1..=256).map(reference).collect::<Vec<_>>();
    assert!(dependency_union([group.as_slice()]).is_ok());
    assert!(dependency_union([group.as_slice(), &[reference(257)]]).is_err());
}

fn routes(capsule: &RuntimeCapsule) -> (RoutingSnapshotSource, ProviderCertificationSource) {
    let d = Digest::of(b"component-test-only");
    let routing = RoutingSnapshotSource {
        version: 1,
        participant_id: id(10),
        privacy_domain_id: id(11),
        target_id: capsule.target_runtime_id.clone(),
        runtime_generation: capsule.generation,
        policy_generation_digest: capsule.policy_bundle_digest.clone(),
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        assignments: vec![RoutingAssignment {
            runtime_binding_id: id(5),
            method: "eth_call".into(),
            risk_class: "LOW".into(),
            provider_profile_id: id(6),
            endpoint_id: id(7),
            endpoint_role: 1,
            purpose: 1,
            chain_environment_id: id(8),
            canonical_generation: 1,
            invalidation_generation: 1,
            coherence_group_digest: d.clone(),
            valid_until_ns: 80,
            required_facts: vec![reference(1)],
        }],
    };
    let certification = ProviderCertificationSource {
        version: 1,
        participant_id: id(10),
        privacy_domain_id: id(11),
        target_id: capsule.target_runtime_id.clone(),
        runtime_generation: capsule.generation,
        policy_generation_digest: capsule.policy_bundle_digest.clone(),
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        certifications: vec![ProviderCertification {
            provider_profile_id: id(6),
            provider_artifact_digest: d.clone(),
            provider_profile_cbor: vec![],
            endpoint_id: id(7),
            connection_configuration_digest: d,
            valid_from_ns: 2,
            valid_until_ns: 70,
            required_facts: vec![reference(2)],
        }],
    };
    (routing, certification)
}

#[test]
fn original_capsule_routes_and_certificates_keep_their_finite_lifetimes() {
    let capsule = capsule();
    let (routing, certification) = routes(&capsule);
    assert_eq!(
        dependency_deadline(&capsule, &routing, &certification, 20).unwrap(),
        70
    );
    for now in [0, 1, 70, 100, 101] {
        assert!(dependency_deadline(&capsule, &routing, &certification, now).is_err());
    }
    for case in 0..5 {
        let mut routes = routing.clone();
        let mut certs = certification.clone();
        match case {
            0 => routes.assignments[0].valid_until_ns = 20,
            1 => certs.certifications[0].valid_from_ns = 21,
            2 => certs.certifications[0].endpoint_id = id(19),
            3 => routes.assignments.clear(),
            _ => certs.certifications.clear(),
        }
        assert!(
            dependency_deadline(&capsule, &routes, &certs, 20).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn retained_source_decode_rejects_trailing_bytes_and_unsigned_field_extensions() {
    let (routing, _) = routes(&capsule());
    let bytes = pc_cbor_1(&routing);
    assert!(decode::<RoutingSnapshotSource>(&bytes).is_ok());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode::<RoutingSnapshotSource>(&trailing).is_err());
    let mut extended = serde_json::to_value(&routing).unwrap();
    extended["ready"] = true.into();
    assert!(decode::<RoutingSnapshotSource>(&pc_cbor_1(&extended)).is_err());
}

fn attestation() -> FactCustodyAttestation {
    FactCustodyAttestation {
        version: 1,
        capsule_digest: Digest::of(b"original capsule"),
        fact_state_digest: Digest::of(b"original fact state"),
        dependency_digest: Digest::of(b"original dependency closure"),
        original_records_digest: Digest::of(b"original record closure"),
        valid_until_ns: "70".into(),
    }
}

#[test]
fn replay_attestation_binds_exact_originals_and_cannot_renew_its_recorded_expiry() {
    let original = attestation();
    let mut current = original.clone();
    current.valid_until_ns = "90".into();
    assert_eq!(original.require_original(&current, 100, 20).unwrap(), 70);
    assert!(original.require_original(&current, 100, 70).is_err());
    assert!(original.require_original(&current, 69, 20).is_err());
    current.valid_until_ns = "69".into();
    assert!(original.require_original(&current, 100, 20).is_err());
    current.valid_until_ns = "90".into();
    for case in 0..10 {
        let mut changed = original.clone();
        match case {
            0 => changed.version = 2,
            1 => changed.capsule_digest = Digest::of(b"other"),
            2 => changed.fact_state_digest = Digest::of(b"other"),
            3 => changed.dependency_digest = Digest::of(b"other"),
            4 => changed.original_records_digest = Digest::of(b"other"),
            5 => changed.valid_until_ns = "91".into(),
            6 => changed.valid_until_ns = "070".into(),
            7 => changed.valid_until_ns = "+70".into(),
            8 => changed.valid_until_ns = "18446744073709551616".into(),
            _ => changed.valid_until_ns = "0".into(),
        }
        assert!(
            changed.require_original(&current, 100, 20).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn native_fact_attestation_has_a_closed_shape_and_cannot_enter_fact_free_proof() {
    let value = serde_json::to_value(attestation()).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "capsuleDigest",
            "dependencyDigest",
            "factStateDigest",
            "originalRecordsDigest",
            "validUntilNs",
            "version"
        ]
    );
    for field in [
        "ready",
        "factTransactionId",
        "authorityKey",
        "extendUntilNs",
    ] {
        let mut changed = value.clone();
        changed[field] = true.into();
        assert!(
            serde_json::from_value::<FactCustodyAttestation>(changed).is_err(),
            "{field}"
        );
    }
    let free = serde_json::json!({"sourceMode":"FACT_FREE"});
    assert!(require_fact_free_proof(&free).is_ok());
    assert!(
        require_fact_free_proof(&serde_json::json!({"sourceMode":"FACT_FREE","factCustody":value}))
            .is_err()
    );
    assert!(require_fact_free_proof(&serde_json::json!({"sourceMode":"FACT_BOUND"})).is_err());
    assert!(
        require_fact_free_proof(&serde_json::json!({"sourceMode":"FACT_FREE","factCustody":null}))
            .is_err()
    );
}

#[test]
fn native_attestation_encoder_preserves_the_existing_sql_size_bound() {
    let fits = serde_json::json!({"x":"x".repeat(8184)});
    assert_eq!(issuer_proof_bytes(&fits).unwrap().len(), 8192);
    let oversized = serde_json::json!({"x":"x".repeat(8185)});
    assert!(issuer_proof_bytes(&oversized).is_err());
}

#[tokio::test]
async fn raw_original_artifacts_do_not_construct_fact_custody_or_allocate_databases() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused@127.0.0.1:1/unavailable")
        .unwrap();
    let store = TargetDispositionStore::from_host_installation(
        pool.clone(),
        id(10),
        id(11),
        [71; 32],
        [72; 32],
        BTreeMap::new(),
    )
    .unwrap();
    let signer =
        PurposeBoundFactSigner::from_secret_bytes(b"source-test".to_vec(), [74; 32]).unwrap();
    let verifier = signer.verifier();
    let reader = PolicyFactReader::new(pool.clone(), verifier.clone());
    let peer = crate::TargetIdentity {
        target_id: id(2),
        uri_san: format!("urn:openpc:workload:{}", id(2)),
        certificate_fingerprint: Digest::of(b"certificate"),
        workload_epoch: 1,
    };
    let mut capsule = capsule();
    capsule.hard_expiry_ns = now_ns().unwrap() + 1_000_000_000;
    let artifacts = BTreeMap::new();
    let original = OriginalTargetActivation {
        peer: &peer,
        capsule: &capsule,
        signed_token: b"asserted token",
        signed_receipt: b"asserted receipt",
        artifacts: &artifacts,
    };
    let selection = DispositionSource::FactBound {
        reader: &reader,
        trust: TargetFactTrust {
            fact_verifier: &verifier,
            installed_authority_signer_id: "installed-authority",
        },
    };
    assert!(
        store
            .prepare_disposition_source(&original, selection)
            .await
            .is_err()
    );
    assert_eq!(pool.size(), 0);
    pool.close().await;
}
