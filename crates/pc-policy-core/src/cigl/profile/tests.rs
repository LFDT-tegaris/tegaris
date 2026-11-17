use super::*;
use crate::{
    cigl::grants::{GrantEffect, GrantStatus, GrantSubject, InteractionGrant},
    contract_policy::{
        AdmittedContractPolicy, CompiledContractPolicyBundle, compile_admitted_contract_policies,
        tests::{admitted, rpc_policy},
    },
    invocation::*,
};

fn definition() -> MethodProfileDefinition {
    let root = admitted();
    MethodProfileDefinition {
        schema_version: "1.0".into(),
        profile_id: "018f0000-0000-7000-8000-000000000801".into(),
        revision: 1,
        participant_id: root.tenant_id,
        privacy_domain_id: root.privacy_domain_id,
        root_contract_method_policy_id: root.asset_id,
        analysis_digest: Digest::of("reviewed-analysis"),
        program: None,
        limits: TraceLimits {
            max_depth: 128,
            max_frames: 2048,
            max_response_bytes: 1_000_000,
            timeout_ms: 5000,
        },
        interactions: vec![MethodInteractionRule {
            interaction_id: "nested-transfer".into(),
            caller: CallerConstraint::RootExecution {},
            call_kind: CallKind::Call,
            contract_method_policy_id: "018f0000-0000-7000-8000-000000000703".into(),
            maximum_value: [0; 32],
        }],
    }
}
fn target() -> AdmittedContractPolicy {
    let mut target = admitted();
    target.asset_id = "018f0000-0000-7000-8000-000000000703".into();
    target.runtime_binding_id = Some("018f0000-0000-7000-8000-000000000704".into());
    target.contract_address = format!("0x{}", "33".repeat(20));
    target
}

#[test]
fn compilation_receipt_binds_exact_profile_scope_and_all_source_versions() {
    use super::publication::*;
    use pc_runtime_types::PurposeSigner;
    let (_, configuration) = fixture(definition(), target());
    let artifact = configuration
        .resource_artifacts
        .iter()
        .find(|a| a.artifact_kind == ConfigurationArtifactKind::CiglProfile)
        .unwrap();
    let mut profile: ConfiguredMethodProfile = decode_exact(&artifact.payload_cbor).unwrap();
    profile.grants.grants[0].grant_id = "018f0000-0000-7000-8000-000000000811".into();
    let sources = vec![GrantSourceVersion {
        grant_id: profile.grants.grants[0].grant_id.clone(),
        revision: u64::MAX,
        digest: profile.grants.grants[0].digest().unwrap(),
    }];
    let methods: Vec<_> = [admitted(), target()]
        .iter()
        .map(|m| MethodSourceVersion {
            method_id: m.asset_id.clone(),
            runtime_binding_id: m.runtime_binding_id.clone().unwrap(),
            method_revision: 1,
            binding_revision: 1,
        })
        .collect();
    let bytes = profile.to_cbor().unwrap();
    let receipt = ProfileCompilationReceipt {
        schema_version: "1.0".into(),
        configuration_work_id: "018f0000-0000-7000-8000-000000000812".into(),
        operation_id: "018f0000-0000-7000-8000-000000000813".into(),
        analysis_id: "018f0000-0000-7000-8000-000000000814".into(),
        profile_id: profile.definition.profile_id.clone(),
        profile_revision: profile.definition.revision,
        participant_id: profile.definition.participant_id.clone(),
        privacy_domain_id: profile.definition.privacy_domain_id.clone(),
        target_runtime_id: "018f0000-0000-7000-8000-000000000815".into(),
        capsule_digest: Digest::of("capsule"),
        review_digest: Digest::of("review"),
        analysis_digest: profile.definition.analysis_digest.clone(),
        policy_generation_digest: Digest::of("generation"),
        profile_digest: profile.definition.digest().unwrap(),
        artifact_digest: Digest::of(&bytes),
        method_sources_digest: method_sources_digest(&methods).unwrap(),
        grant_sources_digest: grant_sources_digest(&sources).unwrap(),
        dependency_paths_digest: None,
        compiled_at_ms: 1234,
        signer_id: "fleet".into(),
    };
    let signer = PurposeSigner::from_secret_bytes(PURPOSE, [52; 32]).unwrap();
    let signed = receipt.sign(&signer).unwrap();
    let key = signer.verifier().sec1_bytes();
    assert_eq!(
        ProfileCompilationReceipt::verify(&signed, &key, &receipt, &bytes, &methods, &sources)
            .unwrap(),
        profile
    );
    let encoded = serde_json::to_value(&sources).unwrap();
    assert_eq!(encoded[0]["revision"], u64::MAX.to_string());
    assert_eq!(
        serde_json::from_value::<Vec<GrantSourceVersion>>(encoded).unwrap(),
        sources
    );
    let other = PurposeSigner::from_secret_bytes(PURPOSE, [53; 32]).unwrap();
    assert!(
        ProfileCompilationReceipt::verify(
            &signed,
            &other.verifier().sec1_bytes(),
            &receipt,
            &bytes,
            &methods,
            &sources
        )
        .is_err()
    );
    let wrong_purpose = PurposeSigner::from_secret_bytes("openpc:other:v1", [52; 32]).unwrap();
    assert!(receipt.sign(&wrong_purpose).is_err());
    for case in 0..7 {
        let mut expected = receipt.clone();
        let mut source_methods = methods.clone();
        let mut source_grants = sources.clone();
        let mut artifact = bytes.clone();
        match case {
            0 => expected.participant_id = receipt.target_runtime_id.clone(),
            1 => expected.profile_revision += 1,
            2 => artifact[0] ^= 1,
            3 => {
                source_methods.pop();
            }
            4 => source_grants[0].revision -= 1,
            5 => source_grants.push(sources[0].clone()),
            _ => expected.compiled_at_ms += 1,
        }
        assert!(
            ProfileCompilationReceipt::verify(
                &signed,
                &key,
                &expected,
                &artifact,
                &source_methods,
                &source_grants
            )
            .is_err(),
            "case {case}"
        );
    }
    // Even a valid signer cannot attach unrelated method metadata to a profile.
    let mut wrong_methods = methods.clone();
    wrong_methods[0].method_id = receipt.target_runtime_id.clone();
    let mut wrong = receipt.clone();
    wrong.method_sources_digest = method_sources_digest(&wrong_methods).unwrap();
    assert!(
        ProfileCompilationReceipt::verify(
            &wrong.sign(&signer).unwrap(),
            &key,
            &wrong,
            &bytes,
            &wrong_methods,
            &sources
        )
        .is_err()
    );
}
fn fixture(
    definition: MethodProfileDefinition,
    target: AdmittedContractPolicy,
) -> (
    CompiledContractPolicyBundle,
    ActiveInvocationConfigurationV1,
) {
    let digest = definition.digest().unwrap();
    let mut root = admitted();
    root.nested_call_set_digest = format!("sha256:{}", digest.as_str());
    let configured = ConfiguredMethodProfile {
        grants: InteractionGrantSet {
            profile_id: definition.profile_id.clone(),
            profile_revision: definition.revision,
            profile_digest: digest,
            participant_id: definition.participant_id.clone(),
            privacy_domain_id: definition.privacy_domain_id.clone(),
            status: GrantStatus::Active,
            grants: vec![InteractionGrant {
                grant_id: "shared-method-grant".into(),
                runtime_binding_id: target.runtime_binding_id.clone().unwrap(),
                selector: [0xa9, 0x05, 0x9c, 0xbb],
                subject: GrantSubject::Role {
                    id: "treasury-writer".into(),
                },
                surface: super::super::grants::InteractionSurface::RawSubmission,
                effect: GrantEffect::Allow,
                status: GrantStatus::Active,
            }],
        },
        definition,
    };
    let bundle = compile_admitted_contract_policies(
        &[root, target],
        &[rpc_policy()],
        &Digest::of("generation"),
        "workload",
    )
    .unwrap()
    .unwrap();
    let mut configuration = decode_active_invocation_configuration(
        &bundle.configuration_cbor,
        &bundle.configuration_digest,
    )
    .unwrap();
    let bytes = configured.to_cbor().unwrap();
    configuration
        .resource_artifacts
        .push(ConfigurationArtifactV1 {
            artifact_id: configured.definition.profile_id.clone(),
            artifact_kind: ConfigurationArtifactKind::CiglProfile,
            artifact_digest: Digest::of(&bytes),
            payload_cbor: bytes,
        });
    (bundle, configuration)
}
fn load(
    bundle: &CompiledContractPolicyBundle,
    configuration: &ActiveInvocationConfigurationV1,
) -> RuntimeResult<Vec<ValidatedMethodProfile>> {
    let bytes = encode_active_invocation_configuration(configuration).unwrap();
    let root = admitted();
    let generation = Digest::of("generation");
    ValidatedMethodProfile::load_active(
        &bytes,
        &Digest::of(&bytes),
        &bundle.policy_cbor,
        &bundle.policy_digest,
        &ActiveInvocationScope {
            policy_generation_digest: &generation,
            tenant_id: &root.tenant_id,
            privacy_domain_id: &root.privacy_domain_id,
            workload_id: "workload",
        },
    )
}

#[test]
fn profile_is_bound_to_both_installed_artifacts_and_registered_method_references() {
    let definition = definition();
    let (bundle, configuration) = fixture(definition.clone(), target());
    let profiles = load(&bundle, &configuration).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].definition(), &definition);
    let bytes = encode_active_invocation_configuration(&configuration).unwrap();
    let generation = Digest::of("generation");
    let root = admitted();
    let scope = ActiveInvocationScope {
        policy_generation_digest: &generation,
        tenant_id: &root.tenant_id,
        privacy_domain_id: &root.privacy_domain_id,
        workload_id: "workload",
    };
    profiles[0]
        .validate_scope(&Digest::of(bytes), &bundle.policy_digest, &scope)
        .unwrap();
    assert!(
        profiles[0]
            .validate_scope(&Digest::of("changed"), &bundle.policy_digest, &scope)
            .is_err()
    );
    assert!(
        profiles[0]
            .validate_scope(
                &profiles[0].configuration_digest,
                &bundle.policy_digest,
                &ActiveInvocationScope {
                    workload_id: "foreign",
                    ..scope
                }
            )
            .is_err()
    );
}

#[test]
fn unresolved_or_cross_chain_targets_and_foreign_profiles_are_not_admitted() {
    let mut unknown = definition();
    unknown.interactions[0].contract_method_policy_id =
        "018f0000-0000-7000-8000-000000000799".into();
    let (bundle, configuration) = fixture(unknown, target());
    assert!(load(&bundle, &configuration).is_err());
    let mut foreign = definition();
    foreign.participant_id = "018f0000-0000-7000-8000-000000000999".into();
    let (bundle, configuration) = fixture(foreign, target());
    assert!(load(&bundle, &configuration).is_err());
    let mut other_chain = target();
    other_chain.chain_id = "31338".into();
    let (bundle, configuration) = fixture(definition(), other_chain);
    assert!(load(&bundle, &configuration).is_err());
}

#[test]
fn changed_profile_hash_unknown_grant_targets_and_legacy_method_roles_fail_closed() {
    let (mut bundle, mut configuration) = fixture(definition(), target());
    let mut profile: ConfiguredMethodProfile =
        decode_exact(&configuration.resource_artifacts[0].payload_cbor).unwrap();
    profile.grants.grants[0].runtime_binding_id = "018f0000-0000-7000-8000-000000000999".into();
    let bytes = profile.to_cbor().unwrap();
    configuration.resource_artifacts[0].artifact_digest = Digest::of(&bytes);
    configuration.resource_artifacts[0].payload_cbor = bytes;
    assert!(load(&bundle, &configuration).is_err());
    let (_, fresh) = fixture(definition(), target());
    configuration = fresh;
    let mut generation =
        decode_active_invocation_policy_generation(&bundle.policy_cbor, &bundle.policy_digest)
            .unwrap();
    generation.assets[0].nested_call_set_digest = Some(Digest::of("changed"));
    bundle.policy_cbor = encode_active_invocation_policy_generation(&generation).unwrap();
    bundle.policy_digest = Digest::of(&bundle.policy_cbor);
    assert!(load(&bundle, &configuration).is_err());
    generation.assets[0].nested_call_set_digest = Some(definition().digest().unwrap());
    generation.assets[1].method_required_roles = None;
    bundle.policy_cbor = encode_active_invocation_policy_generation(&generation).unwrap();
    bundle.policy_digest = Digest::of(&bundle.policy_cbor);
    assert!(load(&bundle, &configuration).is_err());
}

#[test]
fn malformed_or_unreviewed_rule_shapes_cannot_create_a_method_profile() {
    let valid = definition();
    for kind in [CallKind::Create, CallKind::Create2, CallKind::Selfdestruct] {
        let mut changed = valid.clone();
        changed.interactions[0].call_kind = kind;
        assert!(changed.validate().is_err());
    }
    let mut changed = valid.clone();
    changed.interactions.push(changed.interactions[0].clone());
    assert!(changed.validate().is_err());
    let mut changed = valid.clone();
    changed.interactions[0].call_kind = CallKind::Staticcall;
    changed.interactions[0].maximum_value[31] = 1;
    assert!(changed.validate().is_err());
    let (bundle, mut configuration) = fixture(valid, target());
    configuration.resource_artifacts[0].payload_cbor.push(0);
    configuration.resource_artifacts[0].artifact_digest =
        Digest::of(&configuration.resource_artifacts[0].payload_cbor);
    assert!(load(&bundle, &configuration).is_err());
}

#[test]
fn resolved_call_identity_rejects_symbolic_and_exact_caller_aliases() {
    let mut definition = definition();
    let mut duplicate = definition.interactions[0].clone();
    duplicate.interaction_id = "same-call-other-label".into();
    duplicate.caller = CallerConstraint::Exact {
        address: [0x11; 20],
    };
    definition.interactions.push(duplicate);
    // The ambiguity is semantic and only known after registration resolution.
    definition.validate().unwrap();
    let (bundle, configuration) = fixture(definition, target());
    assert!(load(&bundle, &configuration).is_err());
}

#[test]
fn reviewed_call_lookup_keeps_all_call_dimensions_and_installed_policy() {
    let (bundle, configuration) = fixture(definition(), target());
    let profiles = load(&bundle, &configuration).unwrap();
    let profile = &profiles[0];
    let input = [0xa9, 0x05, 0x9c, 0xbb];
    let (rule, policy) = profile
        .reviewed_call([0x11; 20], CallKind::Call, [0x33; 20], &input)
        .unwrap();
    assert_eq!(rule.interaction_id, "nested-transfer");
    assert_eq!(
        policy
            .configured_identity()
            .unwrap()
            .contract_method_policy_id(),
        target().asset_id
    );
    assert!(
        profile
            .reviewed_call([0x99; 20], CallKind::Call, [0x33; 20], &input)
            .is_err()
    );
    assert!(
        profile
            .reviewed_call([0x11; 20], CallKind::Staticcall, [0x33; 20], &input)
            .is_err()
    );
    assert!(
        profile
            .reviewed_call([0x11; 20], CallKind::Call, [0x99; 20], &input)
            .is_err()
    );
    assert!(
        profile
            .reviewed_call([0x11; 20], CallKind::Call, [0x33; 20], &[0; 4])
            .is_err()
    );
}

#[test]
fn public_empty_nested_call_set_is_not_a_reviewed_profile_reference() {
    let mut target = target();
    target.nested_call_set_digest = format!("sha256:{}", Digest::of(b"[]").as_str());
    let (bundle, _) = fixture(definition(), target.clone());
    let method = bundle
        .policies
        .iter()
        .find(|policy| {
            policy
                .configured_identity()
                .unwrap()
                .contract_method_policy_id()
                == target.asset_id
        })
        .unwrap();
    assert!(
        ValidatedMethodProfile::select(&[], method)
            .unwrap()
            .is_none()
    );

    // Only the exact historical empty set has this meaning. A different opaque
    // set/profile reference still requires the independently admitted profile.
    target.nested_call_set_digest = format!("sha256:{}", Digest::of(b"[[]]").as_str());
    let (bundle, _) = fixture(definition(), target.clone());
    let method = bundle
        .policies
        .iter()
        .find(|policy| {
            policy
                .configured_identity()
                .unwrap()
                .contract_method_policy_id()
                == target.asset_id
        })
        .unwrap();
    assert_eq!(
        ValidatedMethodProfile::select(&[], method).unwrap_err(),
        RuntimeError::InvalidAuthorization
    );
}

#[test]
fn required_profile_cannot_be_missing_duplicated_or_selected_by_another_reference() {
    let (bundle, configuration) = fixture(definition(), target());
    let profiles = load(&bundle, &configuration).unwrap();
    let root = profiles[0].root_method().unwrap();
    assert!(ValidatedMethodProfile::select(&[], root).is_err());
    assert!(
        ValidatedMethodProfile::select(&profiles, root)
            .unwrap()
            .is_some()
    );
    assert!(
        ValidatedMethodProfile::select(&[profiles[0].clone(), profiles[0].clone()], root).is_err()
    );
    let mut changed = root.artifact().clone();
    changed.nested_call_set_digest = Some(Digest::of("another reviewed profile"));
    // A hand-built policy does not acquire the installed identity used to select.
    assert!(
        ValidatedMethodProfile::select(
            &profiles,
            &ValidatedInvocationPolicy::try_new(changed).unwrap()
        )
        .is_err()
    );
    let legacy = bundle
        .policies
        .iter()
        .find(|p| p.configured_identity().unwrap().contract_method_policy_id() == target().asset_id)
        .unwrap();
    assert!(
        ValidatedMethodProfile::select(&profiles, legacy)
            .unwrap()
            .is_none()
    );
}

#[test]
fn program_state_references_must_belong_to_the_same_installed_fact_closure() {
    use crate::cigl::program::{CiglProgramV1, Primitive, ResultType, StateValueReference};
    let fact = crate::semantics::FactReference {
        candidate_id: "state-input".into(),
        generation_id: "state-generation".into(),
        fact_digest: format!("sha256:{}", Digest::of("state-value").as_str()),
    };
    let mut definition = definition();
    definition.program = Some(CiglProgramV1 {
        program_id: "cigl.state".into(),
        version: 1,
        primitives: vec![
            Primitive::LoadStateEvidence(StateValueReference {
                fact: fact.clone(),
                value_type: AbiType::Bool,
            }),
            Primitive::Return(()),
        ],
        max_steps: 2,
        max_stack_depth: 1,
        max_evidence_reads: 1,
        result_type: ResultType::AllowDenyIndeterminate,
    });
    let (mut bundle, configuration) = fixture(definition, target());
    assert!(load(&bundle, &configuration).is_err());
    let mut generation =
        decode_active_invocation_policy_generation(&bundle.policy_cbor, &bundle.policy_digest)
            .unwrap();
    generation.required_facts = vec![fact.clone()];
    bundle.policy_cbor = encode_active_invocation_policy_generation(&generation).unwrap();
    bundle.policy_digest = Digest::of(&bundle.policy_cbor);
    let profiles = load(&bundle, &configuration).unwrap();
    assert_eq!(
        profiles[0]
            .program()
            .unwrap()
            .state_references()
            .next()
            .unwrap()
            .fact,
        fact
    );
    generation.required_facts[0].generation_id = "other-generation".into();
    bundle.policy_cbor = encode_active_invocation_policy_generation(&generation).unwrap();
    bundle.policy_digest = Digest::of(&bundle.policy_cbor);
    assert!(load(&bundle, &configuration).is_err());
}
