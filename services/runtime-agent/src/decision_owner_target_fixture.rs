//! Downstream target assembly for the joined security-owner regression.
//! Source fixtures do not establish governed publication, ADS or qualification.
use super::*;
pub(crate) use crate::invocation_publication_fixture::CiglFixture;
use crate::{
    ArtifactComponent, CapsuleTrust, RuntimeAgent, RuntimeCapsule, RuntimeWireSigner,
    authority_artifact::{AuthorityArtifact, AuthoritySourceBinding},
    decision_evidence::DecisionEvidenceStore,
    fact_custody::FactArtifactAdmission,
    identity_custody::IdentityArtifactAdmission,
    invocation_profile_custody::{InvocationProfileAdmission, InvocationProfileTrust},
    mrpc_custody::{MrpcProfileAdmission, MrpcProfileTrust},
    routing_custody::{
        ProviderCertification, ProviderCertificationSource, RoutingArtifactAdmission,
        RoutingAssignment, RoutingSnapshotSource,
    },
    target_state::{TargetState, TargetStateOwners},
};
use openpc_multi_rpc::{
    provider_connection::ConnectionRecord, runtime_profile::MrpcRuntimeProfile,
};
use pc_policy_core::{
    invocation::{ConfigurationArtifactKind, ConfigurationArtifactV1},
    invocation_profile::InvocationProfileMaterial,
    pc_cbor_1,
};
use std::{path::Path, sync::Arc};

pub(super) fn open_evidence(
    root: &Path,
    context: &RuntimeIdentityContext,
) -> DecisionEvidenceStore {
    DecisionEvidenceStore::open_sealed(
        &root.join("evidence"),
        crate::decision_evidence::EvidenceSpoolBinding {
            participant_id: context.participant_id.clone(),
            privacy_domain_id: context.privacy_domain_id.clone(),
            target_runtime_id: context.target_runtime_id.clone(),
            spool_id: "joined-rpc-evidence".into(),
            key_id: "joined-evidence-key".into(),
        },
        [91; 32],
        32,
    )
    .unwrap()
}

pub(super) struct Target {
    pub state: Arc<TargetState>,
    pub agent: Arc<RuntimeAgent>,
    pub capsule: RuntimeCapsule,
    pub artifacts: BTreeMap<Digest, Vec<u8>>,
    pub signer: RuntimeWireSigner,
    pub generation: crate::ext_proc::EnvoyGeneration,
    pub evidence: Arc<DecisionEvidenceStore>,
}
fn add(
    c: &mut RuntimeCapsule,
    a: &mut BTreeMap<Digest, Vec<u8>>,
    id: &str,
    schema: u64,
    version: u64,
    semantic: Digest,
    signed: Vec<u8>,
) {
    c.artifact_components.push(ArtifactComponent {
        component_id: id.into(),
        component_type: id.into(),
        content_digest: Digest::of(&signed),
        semantic_digest: semantic,
        schema_id: schema,
        schema_version: version,
        size_bytes: signed.len() as u64,
        required: true,
    });
    a.insert(Digest::of(&signed), signed);
}
fn source(
    c: &mut RuntimeCapsule,
    a: &mut BTreeMap<Digest, Vec<u8>>,
    signer: &RuntimeWireSigner,
    id: &str,
    body: Vec<u8>,
) -> (AuthoritySourceBinding, Digest) {
    let binding = AuthoritySourceBinding {
        artifact_id: id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(format!("joined-component-only {id} definition")),
        signer_id: "joined-source".into(),
        maximum_source_bytes: 1024 * 1024,
    };
    let header = AuthorityArtifact {
        artifact_id: id.into(),
        artifact_version: 1,
        artifact_class: 1,
        source_media_type: binding.source_media_type.clone(),
        source_content_sha256: Digest::of(&body),
        definition_digest: binding.definition_digest.clone(),
        issued_at_ns: c.issued_at_ns,
        signer_id: binding.signer_id.clone(),
    };
    let digest = header.semantic_digest().unwrap();
    a.insert(Digest::of(&body), body);
    add(
        c,
        a,
        id,
        1010,
        1,
        digest.clone(),
        signer.sign_authority_artifact(&header).unwrap(),
    );
    (binding, digest)
}
fn provider(submission: bool) -> Vec<u8> {
    let h = Digest::of(b"fixture-provider").as_str().to_owned();
    let mut value = serde_json::json!({
        "profile_id":"joined-profile","profile_version":"1.0.0","provider_instance_id":"joined-provider",
        "chain_id":"31337","genesis_hash":format!("sha256:{}",Digest::of(b"local genesis").as_str()),"network_id":"local",
        "tls_credential_identity":"fixture-client","trust_epoch":1,"json_rpc_version":"2.0",
        "method_data_classes":[{"method":"eth_call","data_class":"STATE_CALL"},{"method":"eth_getLogs","data_class":"EVENT_LOG"},{"method":"eth_getTransactionByHash","data_class":"TRANSACTION"},{"method":"eth_getTransactionReceipt","data_class":"RECEIPT"}],
        "limits":{"max_request_bytes":4096,"max_response_bytes":4096,"max_range":1,"max_batch":1},
        "maximum_response_classification":"participant-confidential","idempotency":"IdempotentRead",
        "route_plan":"SingleExact","read_retry_budget":0,"timeout_budget_millis":1000,"lifecycle":"Qualified","evidence_refs":[h]
    });
    if submission {
        value["chain_id"] = "1".into();
        value["method_data_classes"] =
            serde_json::json!([{"method":"eth_sendRawTransaction","data_class":"transaction"}]);
        value["idempotency"] = "GovernedWrite".into();
    }
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
    value["response_schema_digest"] =
        crate::provider_response::call_result_response_schema_digest().into();
    value["normalization_rule_digest"] =
        crate::provider_response::call_result_normalization_rule_digest().into();
    pc_provider_api::encode_provider_profile_pc_cbor(&serde_json::from_value(value).unwrap())
        .unwrap()
}
#[test]
fn visibility_sources_admit_exact_scope_and_qualified_methods_before_database_setup() {
    let mut capsule = crate::wire_tests::capsule();
    capsule.artifact_components.clear();
    let mut artifacts = BTreeMap::new();
    let signer = RuntimeWireSigner::from_secret_bytes([94; 32]).unwrap();
    let provider = provider(false);
    openpc_multi_rpc::qualify_provider_profile(
        &provider,
        &format!("sha256:{}", Digest::of(&provider).as_str()),
    )
    .unwrap();
    let scope = (
        "participant",
        "privacy",
        "urn:openpc:workload:018f0000-0000-7000-8000-000000000111",
        "reader",
    );
    let admission = crate::invocation_publication_fixture::install_request(
        scope,
        &mut capsule,
        &mut artifacts,
        &signer,
        Some(crate::invocation_publication_fixture::RequestMaterial {
            binding_id: BINDING.into(),
            submission: false,
            cigl_mode: CiglFixture::Reviewed,
            facts: Vec::new(),
            recovery_provider: None,
            provider: ConfigurationArtifactV1 {
                artifact_id: "joined-provider".into(),
                artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                artifact_digest: Digest::of(&provider),
                payload_cbor: provider,
            },
        }),
    );
    let (configuration, policy) = admission
        .analysis_source_bytes(&capsule, &artifacts)
        .unwrap();
    pc_policy_core::invocation::ValidatedInvocationPolicy::load_active(
        configuration,
        &Digest::of(configuration),
        policy,
        &Digest::of(policy),
        &pc_policy_core::invocation::ActiveInvocationScope {
            policy_generation_digest: &capsule.policy_bundle_digest,
            tenant_id: scope.0,
            privacy_domain_id: scope.1,
            workload_id: scope.2,
        },
    )
    .unwrap();
}

impl Target {
    pub fn create(
        f: &Fixture,
        p: &Publication,
        peer: &WorkloadPeer,
        facts: &facts::Facts,
        record: &ConnectionRecord,
        root: &Path,
    ) -> Self {
        Self::create_inner(
            &context(f),
            &f.identity_public_key,
            &f.role_id,
            BINDING,
            p,
            peer,
            facts,
            record,
            root,
            false,
            CiglFixture::Reviewed,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_submission(
        f: &WalletFixture,
        p: &Publication,
        peer: &WorkloadPeer,
        facts: &facts::Facts,
        record: &ConnectionRecord,
        recovery_record: &ConnectionRecord,
        root: &Path,
        cigl_mode: CiglFixture,
    ) -> Self {
        let context = RuntimeIdentityContext {
            participant_id: f.participant_id.clone(),
            privacy_domain_id: f.privacy_domain_id.clone(),
            target_runtime_id: f.target_runtime_id.clone(),
        };
        Self::create_inner(
            &context,
            &f.identity_public_key,
            &f.role_id,
            &f.runtime_binding_id,
            p,
            peer,
            facts,
            record,
            root,
            true,
            cigl_mode,
            Some(recovery_record),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn create_inner(
        f: &RuntimeIdentityContext,
        public_key: &str,
        role_id: &str,
        binding_id: &str,
        p: &Publication,
        peer: &WorkloadPeer,
        facts: &facts::Facts,
        record: &ConnectionRecord,
        root: &Path,
        submission: bool,
        cigl_mode: CiglFixture,
        recovery_record: Option<&ConnectionRecord>,
    ) -> Self {
        let now = crate::target_state::wall_clock_ns().unwrap();
        let mut c = crate::wire_tests::capsule();
        c.artifact_components.clear();
        c.target_runtime_id = f.target_runtime_id.clone();
        c.issued_at_ns = now - 2;
        c.not_before_ns = now - 1;
        // Each sibling target shares the real published identity snapshot. Its
        // remaining lifetime decreases while public approvals execute; a new
        // capsule must never claim another full 45 seconds beyond that source.
        let verifier = IdentityAssertionVerifier::new(&[bytes(public_key)], 60_000).unwrap();
        let profile = verifier
            .verify_runtime_authority_profile(
                &evidence(&p.profile_payload, &p.profile_cose),
                &digest(&p.profile_digest),
                "local-test-identity",
            )
            .unwrap();
        let snapshot = verifier
            .verify_snapshot(
                &evidence(&p.manifest_payload, &p.manifest_cose),
                &p.shards
                    .iter()
                    .map(|shard| bytes(shard))
                    .collect::<Vec<_>>(),
                &IdentitySnapshotTrust {
                    manifest_digest: digest(&p.manifest_digest),
                    target_scope_digest: f.target_scope_digest(),
                    release_profile_registry_digest: digest(&p.profile_digest),
                    signer_id: "local-test-identity".into(),
                    profiles: vec![profile],
                    maximum_total_bytes: 4 * 1024 * 1024,
                },
                now,
            )
            .unwrap();
        c.hard_expiry_ns = (now + 45_000_000_000).min(snapshot.expires_at_ns());
        c.identity_snapshot_manifest_digest = Digest::parse(&p.manifest_digest).unwrap();
        let mut a: BTreeMap<_, _> = p
            .content
            .iter()
            .map(|v| (Digest::parse(&v.digest).unwrap(), bytes(&v.payload)))
            .collect();
        for shard in &p.shards {
            let b = bytes(shard);
            a.insert(Digest::of(&b), b);
        }
        add(
            &mut c,
            &mut a,
            "identity-snapshot",
            3004,
            2,
            Digest::parse(&p.manifest_digest).unwrap(),
            bytes(&p.manifest_cose),
        );
        add(
            &mut c,
            &mut a,
            "identity-profile",
            3010,
            2,
            Digest::parse(&p.profile_digest).unwrap(),
            bytes(&p.profile_cose),
        );
        let signer = RuntimeWireSigner::from_secret_bytes([94; 32]).unwrap();
        let provider = provider(submission);
        let recovery_provider = recovery_record.map(|_| {
            let mut profile = pc_provider_api::decode_provider_profile_pc_cbor(&provider).unwrap();
            profile.profile_id = "joined-recovery-profile".into();
            profile.provider_instance_id = "joined-observer".into();
            profile.idempotency = pc_provider_api::IdempotencyClass::IdempotentRead;
            profile.method_data_classes = [
                ("eth_chainId", "CHAIN_METADATA"),
                ("eth_getBlockByNumber", "BLOCK_HEADER"),
                ("eth_getTransactionByHash", "TRANSACTION"),
                ("eth_getTransactionReceipt", "RECEIPT"),
            ]
            .into_iter()
            .map(|(method, data_class)| pc_provider_api::MethodDataClass {
                method: method.into(),
                data_class: data_class.into(),
            })
            .collect();
            pc_provider_api::encode_provider_profile_pc_cbor(&profile).unwrap()
        });
        let invocation = crate::invocation_publication_fixture::install_request(
            (
                &f.participant_id,
                &f.privacy_domain_id,
                peer.workload_id(),
                role_id,
            ),
            &mut c,
            &mut a,
            &signer,
            Some(crate::invocation_publication_fixture::RequestMaterial {
                binding_id: binding_id.into(),
                submission,
                cigl_mode,
                facts: vec![facts.references[0].clone()],
                recovery_provider: recovery_provider.as_ref().map(|provider| {
                    ConfigurationArtifactV1 {
                        artifact_id: "joined-observer".into(),
                        artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                        artifact_digest: Digest::of(provider),
                        payload_cbor: provider.clone(),
                    }
                }),
                provider: ConfigurationArtifactV1 {
                    artifact_id: "joined-provider".into(),
                    artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                    artifact_digest: Digest::of(&provider),
                    payload_cbor: provider.clone(),
                },
            }),
        );
        let (fact_binding, fact_digest) = source(
            &mut c,
            &mut a,
            &signer,
            "facts",
            facts.shard.cose_sign1.clone(),
        );
        c.policy_fact_state_digest = fact_digest;
        let fact_owner = Arc::new(
            FactArtifactAdmission::new(
                signer.verifier(),
                facts.signer.verifier(),
                f.participant_id.clone(),
                f.privacy_domain_id.clone(),
                fact_binding,
                invocation.clone(),
            )
            .unwrap(),
        );
        let profile_signer =
            pc_policy_core::runtime_wire::Signer::from_secret_bytes([95; 32]).unwrap();
        let mrpc_profile = MrpcRuntimeProfile {
            profile_id: "joined-mrpc".into(),
            capability_registry_digest: Digest::of(b"mrpc-capabilities"),
            endpoint_role_rules_digest: Digest::of(b"mrpc-roles"),
            coherence_rules_digest: Digest::of(b"mrpc-coherence"),
            signer_id: "mrpc".into(),
        };
        c.mrpc_runtime_profile_digest = mrpc_profile.semantic_digest().unwrap();
        let mut routing = RoutingSnapshotSource {
            version: 1,
            participant_id: f.participant_id.clone(),
            privacy_domain_id: f.privacy_domain_id.clone(),
            target_id: f.target_runtime_id.clone(),
            runtime_generation: c.generation,
            policy_generation_digest: c.policy_bundle_digest.clone(),
            mrpc_runtime_profile_digest: c.mrpc_runtime_profile_digest.clone(),
            assignments: vec![RoutingAssignment {
                runtime_binding_id: binding_id.into(),
                method: if submission {
                    "eth_sendRawTransaction"
                } else {
                    "eth_call"
                }
                .into(),
                risk_class: "LOW".into(),
                provider_profile_id: "joined-provider".into(),
                endpoint_id: record.endpoint_id.clone(),
                endpoint_role: if submission { 4 } else { 1 },
                purpose: if submission { 3 } else { 1 },
                chain_environment_id: "joined-chain".into(),
                canonical_generation: 1,
                invalidation_generation: 1,
                coherence_group_digest: Digest::of(b"joined-coherence"),
                valid_until_ns: c.hard_expiry_ns,
                required_facts: vec![facts.references[1].clone()],
            }],
        };
        let mut certification = ProviderCertificationSource {
            version: 1,
            participant_id: f.participant_id.clone(),
            privacy_domain_id: f.privacy_domain_id.clone(),
            target_id: f.target_runtime_id.clone(),
            runtime_generation: c.generation,
            policy_generation_digest: c.policy_bundle_digest.clone(),
            mrpc_runtime_profile_digest: c.mrpc_runtime_profile_digest.clone(),
            certifications: vec![ProviderCertification {
                provider_profile_id: "joined-provider".into(),
                provider_artifact_digest: Digest::of(&provider),
                provider_profile_cbor: provider,
                endpoint_id: record.endpoint_id.clone(),
                connection_configuration_digest: record.configuration_digest.clone(),
                valid_from_ns: now - 1,
                valid_until_ns: c.hard_expiry_ns,
                required_facts: vec![facts.references[2].clone()],
            }],
        };
        if !submission {
            for method in [
                "eth_getTransactionByHash",
                "eth_getTransactionReceipt",
                "eth_getLogs",
            ] {
                let mut assignment = routing.assignments[0].clone();
                assignment.method = method.into();
                routing.assignments.push(assignment);
            }
        }
        if let (Some(record), Some(provider)) = (recovery_record, recovery_provider) {
            let mut assignment = routing.assignments[0].clone();
            assignment.method = "eth_getTransactionReceipt".into();
            assignment.purpose = 4;
            assignment.endpoint_role = 1;
            assignment.provider_profile_id = "joined-observer".into();
            assignment.endpoint_id = record.endpoint_id.clone();
            routing.assignments.push(assignment);
            certification.certifications.push(ProviderCertification {
                provider_profile_id: "joined-observer".into(),
                provider_artifact_digest: Digest::of(&provider),
                provider_profile_cbor: provider,
                endpoint_id: record.endpoint_id.clone(),
                connection_configuration_digest: record.configuration_digest.clone(),
                valid_from_ns: now - 1,
                valid_until_ns: c.hard_expiry_ns,
                required_facts: vec![facts.references[3].clone()],
            });
        }
        let (route_binding, d) = source(&mut c, &mut a, &signer, "routing", pc_cbor_1(&routing));
        c.routing_snapshot_digest = d;
        let (cert_binding, d) = source(
            &mut c,
            &mut a,
            &signer,
            "certification",
            pc_cbor_1(&certification),
        );
        c.provider_certification_registry_digest = d;
        let routing = Arc::new(
            RoutingArtifactAdmission::new(
                signer.verifier(),
                route_binding,
                cert_binding,
                f.participant_id.clone(),
                f.privacy_domain_id.clone(),
                fact_owner.clone(),
            )
            .unwrap(),
        );
        let d = c.mrpc_runtime_profile_digest.clone();
        add(
            &mut c,
            &mut a,
            "mrpc",
            2014,
            3,
            d,
            mrpc_profile.sign(&profile_signer).unwrap(),
        );
        let mrpc = Arc::new(
            MrpcProfileAdmission::new(
                profile_signer.verifier(),
                MrpcProfileTrust {
                    profile_id: mrpc_profile.profile_id,
                    signer_id: mrpc_profile.signer_id,
                    capability_registry_digest: mrpc_profile.capability_registry_digest,
                    endpoint_role_rules_digest: mrpc_profile.endpoint_role_rules_digest,
                    coherence_rules_digest: mrpc_profile.coherence_rules_digest,
                },
                routing.clone(),
            )
            .unwrap(),
        );
        let d = Digest::of(b"joined-registry");
        let profile = invocation_profile(submission, &d);
        c.capability_registry_digest = d.clone();
        c.request_form_registry_digest = d.clone();
        c.error_registry_digest = d;
        c.rpc_invocation_profile_digest = profile.semantic_digest().unwrap();
        let d = c.rpc_invocation_profile_digest.clone();
        add(
            &mut c,
            &mut a,
            "invocation-profile",
            3121,
            2,
            d,
            profile.sign(&profile_signer).unwrap(),
        );
        let invocation_profile = Arc::new(
            InvocationProfileAdmission::new(
                profile_signer.verifier(),
                InvocationProfileTrust {
                    profile_id: profile.profile_id,
                    release: profile.release,
                    capability_registry_id: profile.capability_registry_id,
                    request_form_registry_id: profile.request_form_registry_id,
                    error_registry_id: profile.error_registry_id,
                },
                mrpc.clone(),
            )
            .unwrap(),
        );
        let identity = Arc::new(
            IdentityArtifactAdmission::new(
                IdentityAssertionVerifier::new(&[bytes(public_key)], 60_000).unwrap(),
                f.clone(),
                Digest::parse(&p.profile_digest).unwrap(),
                "local-test-identity".into(),
                4 * 1024 * 1024,
                invocation_profile.clone(),
            )
            .unwrap(),
        );
        c.artifact_components.sort_by(|a, b| {
            a.component_id
                .len()
                .cmp(&b.component_id.len())
                .then(a.component_id.cmp(&b.component_id))
        });
        let trust = CapsuleTrust {
            target_id: c.target_runtime_id.clone(),
            fleet_id: c.fleet_id.clone(),
            fleet_signer_id: c.signer_id.clone(),
            agent_signer_id: "joined-agent".into(),
            contract_set_manifest_digest: c.contract_set_manifest_digest.clone(),
            schema_registry_digest: c.schema_registry_digest.clone(),
            cose_purpose_registry_digest: c.cose_purpose_registry_digest.clone(),
            complete_component_set_digest: c.complete_component_set_digest.clone(),
        };
        let open = || {
            RuntimeAgent::open_canonical(
                trust.clone(),
                &signer.verifier().public_key_bytes(),
                [96; 32],
                16,
                8 * 1024 * 1024,
                &root.join("target"),
                identity.clone(),
            )
            .unwrap()
        };
        let agent = open();
        use crate::ArtifactAdmission;
        let (_, mut verified) = identity.admit_identity(&c, &a).expect("identity admission");
        for component in &c.artifact_components {
            if matches!(component.schema_id, 3004 | 3010) {
                continue;
            }
            verified.extend(
                invocation_profile
                    .validate_component_in_bundle(&c, component, &a)
                    .unwrap_or_else(|error| {
                        panic!("{} admission: {error:?}", component.component_id)
                    }),
            );
        }
        assert_eq!(
            verified,
            a.keys().cloned().collect(),
            "exact admitted content closure"
        );
        let digest = agent
            .prepare_capsule(signer.sign_capsule(&c).unwrap(), a.clone(), now)
            .unwrap();
        agent.activate_capsule(&digest, now).unwrap();
        let classes = Digest::of(b"joined-protected-classes");
        let lease = crate::RevocationFreshnessLease {
            lease_id: "joined-lease".into(),
            target_runtime_id: c.target_runtime_id.clone(),
            fleet_id: c.fleet_id.clone(),
            lease_generation: 1,
            minimum_emergency_generation: 0,
            issued_at_ns: now,
            expires_at_ns: c.hard_expiry_ns,
            protected_class_set_digest: classes.clone(),
            signer_id: c.signer_id.clone(),
        };
        agent
            .install_freshness_lease(&signer.sign_freshness_lease(&lease).unwrap(), now)
            .unwrap();
        drop(agent);
        let agent = Arc::new(open());
        let evidence = Arc::new(open_evidence(root, f));
        let state = TargetState::new(
            classes,
            f.privacy_domain_id.clone(),
            TargetStateOwners {
                agent: agent.clone(),
                identity,
                identity_assertions: Arc::new(
                    IdentityAssertionVerifier::new(&[bytes(public_key)], 60_000).unwrap(),
                ),
                invocation,
                invocation_profile,
                facts: fact_owner,
                fact_reader: crate::fact_lease::FactLeaseReader::connect(
                    std::env::var("OPENPC_POLICY_FACT_READER_DATABASE_URL").unwrap(),
                    facts.signer.verifier(),
                )
                .unwrap(),
                mrpc,
                routing,
                route_evidence_trust: crate::request_route::RouteEvidenceTrust::new(
                    &pc_policy_core::runtime_wire::Signer::from_secret_bytes([91; 32])
                        .unwrap()
                        .verifier(),
                    &pc_policy_core::runtime_wire::Signer::from_secret_bytes([92; 32])
                        .unwrap()
                        .verifier(),
                    &pc_policy_core::runtime_wire::Signer::from_secret_bytes([99; 32])
                        .unwrap()
                        .verifier(),
                    "mrpc".into(),
                )
                .unwrap(),
                evidence: evidence.clone(),
            },
        )
        .unwrap();
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("x-openpc-runtime-capsule-id", c.capsule_id.parse().unwrap());
        metadata.insert(
            "x-openpc-runtime-generation",
            c.generation.to_string().parse().unwrap(),
        );
        let generation = crate::ext_proc::EnvoyGeneration::from_metadata(&metadata).unwrap();
        Self {
            state,
            agent,
            capsule: c,
            artifacts: a,
            signer,
            generation,
            evidence,
        }
    }
}

fn invocation_profile(submission: bool, d: &Digest) -> InvocationProfileMaterial {
    let mut profile = InvocationProfileMaterial {
        profile_id: "joined-invocation".into(),
        release: "component-test".into(),
        capability_registry_id: "pc.rpc.invocation-capabilities@2".into(),
        capability_registry_digest: d.clone(),
        request_form_registry_id: "pc.rpc.invocation-request-forms@2".into(),
        request_form_registry_digest: d.clone(),
        error_registry_id: "pc.rpc.errors@2".into(),
        error_registry_digest: d.clone(),
        required_capabilities: vec![
            if submission {
                "SIGNED_TRANSACTION_SUBMISSION"
            } else {
                "CALL_RESULT_DISCLOSURE"
            }
            .into(),
        ],
        optional_capabilities: vec!["GAS_ESTIMATE_DISCLOSURE".into()],
        deferred_capabilities: vec!["MULTI_CALL_SIMULATION_DISCLOSURE".into()],
        unsupported_capabilities: if submission {
            vec![
                "ACCESS_LIST_DISCLOSURE".into(),
                "UNSIGNED_TRANSACTION_PREPARATION".into(),
            ]
        } else {
            vec!["SIGNED_TRANSACTION_SUBMISSION".into()]
        },
        disclosure_policy_digest: crate::provider_response::call_result_disclosure_policy_digest(),
        transaction_policy_digest: d.clone(),
        composition_rule_digest: d.clone(),
        state_anchor_policy_digest: d.clone(),
        fault_precedence_digest: d.clone(),
        supported_request_forms: vec![
            if submission {
                "R1B_SIGNED_CONTRACT_TRANSACTION_V2"
            } else {
                "R1B_SINGLE_CONTRACT_CALL_V2"
            }
            .into(),
        ],
        resource_limits_digest: d.clone(),
        capability_ceiling: "fixture".into(),
    };
    if submission {
        profile
            .required_capabilities
            .push("OPERATION_STATUS_DISCLOSURE".into());
        profile
            .supported_request_forms
            .push("R1B_OWNED_OPERATION_STATUS_V2".into());
    }
    profile
}

#[test]
fn submission_fixture_profile_roundtrips_and_keeps_capabilities_separate() {
    use pc_policy_core::invocation_capability::InvocationCapability;
    for submission in [false, true] {
        let profile = invocation_profile(submission, &Digest::of(b"fixture registry"));
        let decoded = InvocationProfileMaterial::decode(&profile.encode().unwrap()).unwrap();
        assert_eq!(decoded, profile);
        if submission {
            assert_eq!(
                decoded
                    .capability_for_method("eth_sendRawTransaction")
                    .unwrap(),
                InvocationCapability::SignedTransactionSubmission
            );
            assert_eq!(
                decoded
                    .capability_for_method("pc_getOperationStatus")
                    .unwrap(),
                InvocationCapability::OperationStatusDisclosure
            );
            assert!(
                decoded
                    .capability_for_method("pc_prepareTransaction")
                    .is_err()
            );
            assert!(decoded.capability_for_method("eth_call").is_err());
        } else {
            assert!(
                decoded
                    .capability_for_method("eth_sendRawTransaction")
                    .is_err()
            );
        }
    }
}
