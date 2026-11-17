//! Source-custody regressions. Signed fixture sources do not establish the
//! provider qualification journey or protected-target acceptance.
use super::*;
use crate::{RuntimeWireSigner, authority_artifact::AuthorityArtifact};
use openpc_multi_rpc::{provider_connection::ConnectionStatus, route_witness::ChainAnchor};
use pc_provider_api::{ProviderProfileV1, encode_provider_profile_pc_cbor};

struct RejectOther;
impl ArtifactAdmission for RejectOther {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidInput)
    }
}
fn profile() -> ProviderProfileV1 {
    let h = Digest::of(b"component-test-profile").as_str().to_owned();
    let mut value = serde_json::json!({
        "profile_id":"profile", "profile_version":"1.0.0", "provider_instance_id":"provider",
        "chain_id":"31337", "genesis_hash":format!("sha256:{h}"), "network_id":"local",
        "tls_credential_identity":"credential", "trust_epoch":1, "json_rpc_version":"2.0",
        "method_data_classes":[{"method":"eth_call","data_class":"STATE_CALL"}],
        "limits":{"max_request_bytes":4096,"max_response_bytes":4096,"max_range":1,"max_batch":1},
        "maximum_response_classification":"participant-confidential", "idempotency":"IdempotentRead",
        "route_plan":"SingleExact", "read_retry_budget":0, "timeout_budget_millis":1000,
        "lifecycle":"Qualified", "evidence_refs":[h]
    });
    for field in [
        "profile_digest",
        "provider_release_digest",
        "provider_build_digest",
        "configuration_digest",
        "tls_credential_fingerprint",
        "request_schema_digest",
        "response_schema_digest",
        "normalization_rule_digest",
        "privacy_behavior_digest",
        "failure_behavior_digest",
        "rate_limit_contract_digest",
        "capability_profile_digest",
        "corpus_digest",
        "conformance_receipt_digest",
    ] {
        value[field] = h.clone().into();
    }
    serde_json::from_value(value).unwrap()
}
fn facts() -> Vec<FactReference> {
    vec![FactReference {
        candidate_id: "route-fact".into(),
        generation_id: "generation".into(),
        fact_digest: format!("sha256:{}", Digest::of(b"fact").as_str()),
    }]
}
fn sources(target: &str) -> (RoutingSnapshotSource, ProviderCertificationSource) {
    let profile = encode_provider_profile_pc_cbor(&profile()).unwrap();
    let capsule = crate::wire_tests::capsule();
    (
        RoutingSnapshotSource {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_id: target.into(),
            runtime_generation: capsule.generation,
            policy_generation_digest: capsule.policy_bundle_digest.clone(),
            mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
            assignments: vec![RoutingAssignment {
                runtime_binding_id: "018f0000-0000-7000-8000-000000000101".into(),
                method: "eth_call".into(),
                risk_class: "HIGH".into(),
                provider_profile_id: "provider".into(),
                endpoint_id: "endpoint".into(),
                endpoint_role: 1,
                purpose: 1,
                chain_environment_id: "local".into(),
                canonical_generation: 3,
                invalidation_generation: 5,
                coherence_group_digest: Digest::of(b"coherence"),
                valid_until_ns: 80,
                required_facts: facts(),
            }],
        },
        ProviderCertificationSource {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_id: target.into(),
            runtime_generation: capsule.generation,
            policy_generation_digest: capsule.policy_bundle_digest,
            mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest,
            certifications: vec![ProviderCertification {
                provider_profile_id: "provider".into(),
                provider_artifact_digest: Digest::of(&profile),
                provider_profile_cbor: profile,
                endpoint_id: "endpoint".into(),
                connection_configuration_digest: Digest::of(b"prepared-connection"),
                valid_from_ns: 3,
                valid_until_ns: 70,
                required_facts: facts(),
            }],
        },
    )
}
fn binding(id: &str) -> AuthoritySourceBinding {
    AuthoritySourceBinding {
        artifact_id: id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(format!("component-only {id} definition")),
        signer_id: "publisher".into(),
        maximum_source_bytes: 65536,
    }
}
fn install(
    id: &str,
    bytes: Vec<u8>,
    signer: &RuntimeWireSigner,
    capsule: &mut RuntimeCapsule,
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
) -> Digest {
    let authority = AuthorityArtifact {
        artifact_id: id.into(),
        artifact_version: 1,
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        source_content_sha256: Digest::of(&bytes),
        definition_digest: binding(id).definition_digest,
        issued_at_ns: 1,
        signer_id: "publisher".into(),
    };
    let digest = authority.semantic_digest().unwrap();
    let signed = signer.sign_authority_artifact(&authority).unwrap();
    artifacts.insert(Digest::of(&bytes), bytes);
    artifacts.insert(Digest::of(&signed), signed.clone());
    capsule.artifact_components.push(ArtifactComponent {
        component_id: id.into(),
        component_type: id.into(),
        content_digest: Digest::of(&signed),
        semantic_digest: digest.clone(),
        schema_id: 1010,
        schema_version: 1,
        size_bytes: signed.len() as u64,
        required: true,
    });
    digest
}
#[test]
fn signed_route_sources_allow_factless_routes_and_reject_malformed_facts() {
    let signer = RuntimeWireSigner::from_secret_bytes([87; 32]).unwrap();
    let admission = RoutingArtifactAdmission::new(
        signer.verifier(),
        binding("routing"),
        binding("certification"),
        "participant".into(),
        "privacy".into(),
        Arc::new(RejectOther),
    )
    .unwrap();
    let baseline = crate::wire_tests::capsule();
    let (routing, certification) = sources(&baseline.target_runtime_id);
    for case in 0..15 {
        let mut r = routing.clone();
        let mut c = certification.clone();
        match case {
            1 => r.privacy_domain_id = "foreign".into(),
            2 => c.target_id = "foreign".into(),
            3 => r.assignments.push(r.assignments[0].clone()),
            4 => c.certifications[0].required_facts[0].fact_digest = "invalid".into(),
            5 => c.certifications[0].provider_profile_cbor[0] ^= 1,
            6 => r.assignments[0].canonical_generation = 0,
            7 => r.runtime_generation += 1,
            8 => c.policy_generation_digest = Digest::of(b"other-policy"),
            9 => c.mrpc_runtime_profile_digest = Digest::of(b"other-profile"),
            10 => r.assignments[0].method = "eth_sendRawTransaction".into(),
            11 => r.assignments[0].purpose = 3,
            12 => r.assignments[0].endpoint_role = 4,
            13 => {
                r.assignments[0].method = "eth_sendRawTransaction".into();
                r.assignments[0].purpose = 3;
                r.assignments[0].endpoint_role = 4;
            }
            14 => {
                r.assignments[0].required_facts.clear();
                c.certifications[0].required_facts.clear();
            }
            _ => {}
        }
        let mut capsule = baseline.clone();
        capsule.artifact_components.clear();
        let mut artifacts = BTreeMap::new();
        capsule.routing_snapshot_digest = install(
            "routing",
            pc_cbor_1(&r),
            &signer,
            &mut capsule,
            &mut artifacts,
        );
        capsule.provider_certification_registry_digest = install(
            "certification",
            pc_cbor_1(&c),
            &signer,
            &mut capsule,
            &mut artifacts,
        );
        let result = admission.admit(&capsule, &artifacts);
        if case == 0 || case == 13 || case == 14 {
            assert_eq!(result.unwrap().1, artifacts.keys().cloned().collect());
            capsule.routing_snapshot_digest = Digest::of(b"substitution");
            assert!(admission.admit(&capsule, &artifacts).is_err());
        } else {
            assert!(result.is_err(), "case {case}");
        }
    }
}
#[test]
fn route_witness_cannot_choose_generation_role_coherence_provider_or_connection() {
    let (r, c) = sources("target");
    let route = AdmittedRequestRoute {
        assignment: &r.assignments[0],
        certification: &c.certifications[0],
    };
    let witness = RequestRouteWitness {
        witness_id: "witness".into(),
        purpose: 1,
        operation_digest: Digest::of(b"operation"),
        request_digest: Digest::of(b"request"),
        chain_anchor: ChainAnchor {
            chain_environment_id: "local".into(),
            chain_id: 31337,
            block_number: 16,
            block_hash: Digest::of(b"block"),
            state_root: Digest::of(b"state"),
            canonical_generation: 3,
            observed_at_ns: 3,
        },
        endpoint_id: "endpoint".into(),
        endpoint_role: 1,
        routing_snapshot_digest: Digest::of(b"routing"),
        provider_certification_registry_digest: Digest::of(b"certification"),
        mrpc_runtime_profile_digest: Digest::of(b"profile"),
        coherence_group_digest: Digest::of(b"coherence"),
        selected_at_ns: 4,
        selection_deadline_ns: 90,
        invalidation_generation: 5,
        signer_id: "mrpc".into(),
    };
    let connection = ConnectionRecord {
        provider_id: "provider".into(),
        endpoint_id: "endpoint".into(),
        endpoint_generation: 1,
        resolution_generation: 1,
        endpoint_content_digest: Digest::of(b"endpoint"),
        resolution_content_digest: Digest::of(b"resolution"),
        dispatcher_generation: 1,
        configuration_digest: Digest::of(b"prepared-connection"),
        valid_until_ms: 1,
        status: ConnectionStatus::Prepared,
    };
    assert!(route.validate_witness(&witness, &connection, 5).is_ok());
    for case in 0..6 {
        let mut changed = witness.clone();
        match case {
            0 => changed.chain_anchor.canonical_generation += 1,
            1 => changed.invalidation_generation += 1,
            2 => changed.endpoint_role = 3,
            3 => changed.purpose = 2,
            4 => changed.coherence_group_digest = Digest::of(b"other"),
            _ => changed.chain_anchor.chain_environment_id = "foreign".into(),
        }
        assert!(route.validate_witness(&changed, &connection, 5).is_err());
    }
    let mut changed = connection.clone();
    changed.provider_id = "other".into();
    assert!(route.validate_witness(&witness, &changed, 5).is_err());
    changed = connection;
    changed.configuration_digest = Digest::of(b"other-connection");
    assert!(route.validate_witness(&witness, &changed, 5).is_err());
    assert!(route.validate_witness(&witness, &changed, 70).is_err());
}

#[test]
fn write_selection_requires_the_exact_binding_chain_form_and_no_retry_profile() {
    use pc_provider_api::{IdempotencyClass, MethodDataClass, RoutePlanDraftV1};
    use pc_runtime_types::{ContractInvocation, RequestClass, Transport};
    let (mut routing, certification) = sources("target");
    routing.assignments[0].method = "eth_sendRawTransaction".into();
    routing.assignments[0].purpose = 3;
    routing.assignments[0].endpoint_role = 4;
    let binding = routing.assignments[0].runtime_binding_id.clone();
    let mut admitted_profile = profile();
    admitted_profile.idempotency = IdempotencyClass::GovernedWrite;
    admitted_profile.method_data_classes = vec![MethodDataClass {
        method: "eth_sendRawTransaction".into(),
        data_class: "transaction".into(),
    }];
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "1".into(),
        method: "eth_sendRawTransaction".into(),
        params_digest: Digest::of(b"signed bytes"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class: RequestClass::Write,
        received_at_ms: 1,
        deadline_at_ms: 50,
        response_budget_bytes: 1024,
        invocation: Some(ContractInvocation {
            chain_id: "31337".into(),
            network_id: "local".into(),
            genesis_digest: Digest::of(b"component-test-profile"),
            contract_address: [1; 20],
            proxy_address: None,
            implementation_address: None,
            code_digest: Digest::of(b"code"),
            implementation_code_digest: None,
            abi_digest: Digest::of(b"abi"),
            calldata: vec![1, 2, 3, 4],
            nested_calls: vec![],
        }),
    };
    request.request_digest = request.computed_digest().unwrap();
    for case in 0..10 {
        let mut profile = admitted_profile.clone();
        let mut request = request.clone();
        let mut route = routing.clone();
        match case {
            1 => profile.idempotency = IdempotencyClass::IdempotentRead,
            2 => profile.read_retry_budget = 1,
            3 => profile.chain_id = "1".into(),
            4 => profile.network_id = "foreign".into(),
            5 => profile.method_data_classes[0].data_class = "STATE_CALL".into(),
            6 => request.class = RequestClass::Read,
            7 => route.assignments[0].runtime_binding_id = "foreign".into(),
            8 => request.method = "eth_sendTransaction".into(),
            9 => {
                profile.route_plan = RoutePlanDraftV1::HedgedSingle {
                    hedge_threshold_millis: 1,
                }
            }
            _ => {}
        }
        request.request_digest = request.computed_digest().unwrap();
        let mut certification = certification.clone();
        let bytes = encode_provider_profile_pc_cbor(&profile).unwrap();
        certification.certifications[0].provider_artifact_digest = Digest::of(&bytes);
        certification.certifications[0].provider_profile_cbor = bytes;
        let owner = InstalledRoutingAuthority {
            routing: route,
            certification,
        };
        assert_eq!(
            owner.select(&binding, &request).is_ok(),
            case == 0,
            "case {case}"
        );
    }
}
