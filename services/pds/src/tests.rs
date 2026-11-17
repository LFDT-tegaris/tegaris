// Component coverage only. A fixture local owner is not protected-target acceptance.
use super::*;
use crate::invocation::InvocationPolicy;
use pc_runtime_types::{
    DecisionEffect, Digest, EvidenceCapacity, RequestClass, RuntimeBindings, RuntimeError,
    RuntimeRequest, RuntimeResult, Transport,
};
use std::sync::{Arc, Mutex, MutexGuard};

struct FixtureOwner(Mutex<LocalDecisionState>, bool, bool);
struct FixtureLease<'a>(MutexGuard<'a, LocalDecisionState>, bool, bool);
impl LocalDecisionOwner for FixtureOwner {
    fn acquire(&self, _: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>> {
        Ok(Box::new(FixtureLease(
            self.0.lock().unwrap(),
            self.1,
            self.2,
        )))
    }
}
impl LocalDecisionLease for FixtureLease<'_> {
    fn state(&self) -> &LocalDecisionState {
        &self.0
    }
    fn revalidate(&self) -> RuntimeResult<()> {
        if self.1 {
            Ok(())
        } else {
            Err(RuntimeError::RuntimeUnavailable)
        }
    }
    fn commit(&mut self, decision: &pc_runtime_types::RuntimeDecision) -> RuntimeResult<()> {
        assert_eq!(
            decision.effect == DecisionEffect::AllowForward,
            decision.capability.is_some()
        );
        if self.2 {
            Ok(())
        } else {
            Err(RuntimeError::EvidenceCapacity)
        }
    }
}

fn fixture() -> (
    EvaluationInput,
    LocalDecisionState,
    IdentityAssertionVerifier,
) {
    let (verifier, identity_assertion, identity) = crate::identity::tests::fixture();
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "request-1".into(),
        method: "eth_call".into(),
        params_digest: digest("params"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: digest("placeholder"),
        class: RequestClass::Read,
        received_at_ms: 1_200,
        deadline_at_ms: 2_000,
        response_budget_bytes: 4096,
        invocation: Some(invocation()),
    };
    request.request_digest = request.computed_digest().unwrap();
    let state = LocalDecisionState {
        visibility_read: None,
        deployment_policy: None,
        submission_witness_digest: None,
        decision_id: "target-1/decision-1".into(),
        request_digest: request.request_digest.clone(),
        bindings: RuntimeBindings {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            workload_id: "workload-1".into(),
            target_id: "target-1".into(),
            active_generation_digest: digest("generation"),
            observed_generation_digest: digest("generation"),
            policy_generation_digest: digest("policy"),
            expected_policy_generation_digest: digest("policy"),
            fact_generation_digest: digest("facts"),
            expected_fact_generation_digest: digest("facts"),
            route_profile_digest: digest("route"),
            expected_route_profile_digest: digest("route"),
            eligible_provider_profile_ids: vec!["provider:one".into()],
            provider_profile_digest: digest("provider"),
            expected_provider_profile_digest: digest("provider"),
        },
        active_invocation_policies: vec![ValidatedInvocationPolicy::try_new(policy()).unwrap()],
        authorization: ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            workload_id: "workload-1".into(),
            actor_principal_id: "principal-1".into(),
            roles: vec!["reader".into()],
            approval: None,
            webauthn: None,
        })
        .unwrap(),
        identity,
        emergency_deny: false,
        evidence: EvidenceCapacity {
            used: 10,
            capacity: 100,
            high_watermark_percent: 80,
            critical_watermark_percent: 95,
        },
        valid_until_ms: 1_900,
    };
    (
        EvaluationInput {
            request,
            identity_assertion,
        },
        state,
        verifier,
    )
}

fn service(
    state: LocalDecisionState,
    verifier: IdentityAssertionVerifier,
    healthy: bool,
) -> PolicyDecisionService {
    PolicyDecisionService::with_runtime_owner(
        [7; 32],
        25,
        verifier,
        Arc::new(FixtureOwner(Mutex::new(state), healthy, true)),
    )
    .unwrap()
}

fn authorization() -> InvocationAuthorization {
    fixture().1.authorization.facts().clone()
}

#[test]
fn pre_route_policy_selection_preserves_exact_request_and_tenant_scope() {
    use pc_policy_core::invocation::select_active_policy_in_scope;
    let (input, state, _) = fixture();
    let scope = ActiveInvocationScope {
        policy_generation_digest: &state.bindings.policy_generation_digest,
        tenant_id: &state.bindings.participant_id,
        privacy_domain_id: &state.bindings.privacy_domain_id,
        workload_id: &state.bindings.workload_id,
    };
    let select = |request: &RuntimeRequest, scope| {
        select_active_policy_in_scope(&state.active_invocation_policies, request, scope).map(|_| ())
    };
    assert_eq!(select(&input.request, scope), Ok(()));
    let changed_generation = digest("successor");
    for wrong_scope in [
        ActiveInvocationScope {
            tenant_id: "foreign",
            ..scope
        },
        ActiveInvocationScope {
            privacy_domain_id: "foreign",
            ..scope
        },
        ActiveInvocationScope {
            workload_id: "foreign",
            ..scope
        },
        ActiveInvocationScope {
            policy_generation_digest: &changed_generation,
            ..scope
        },
    ] {
        assert!(select(&input.request, wrong_scope).is_err());
    }
    let mut substituted = input.request.clone();
    substituted.invocation.as_mut().unwrap().contract_address = [8; 20];
    assert!(select(&substituted, scope).is_err());
    substituted.request_digest = substituted.computed_digest().unwrap();
    assert!(select(&substituted, scope).is_err());
    let duplicated = vec![state.active_invocation_policies[0].clone(); 2];
    assert!(select_active_policy_in_scope(&duplicated, &input.request, scope).is_err());
}

#[test]
fn request_has_no_authority_or_currentness_fields_and_unconnected_owner_denies() {
    let (input, _, _) = fixture();
    // The closed Rust input model exposes only request and signature evidence.
    let encoded = pc_runtime_types::canonical_bytes(&input).unwrap();
    let encoded = String::from_utf8(encoded).unwrap();
    for rejected in [
        "authority_intersection",
        "roles",
        "approval",
        "now_ms",
        "observed_generation_digest",
        "expected_fact_generation_digest",
    ] {
        assert!(!encoded.contains(rejected));
    }
    let decision = PolicyDecisionService::new([7; 32], 25)
        .unwrap()
        .evaluate(&input)
        .unwrap();
    assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
    assert!(decision.capability.is_none());
}

#[test]
fn component_owner_and_existing_identity_protocol_bound_capability() {
    let (input, mut state, verifier) = fixture();
    state.valid_until_ms = 1_245;
    let service = service(state, verifier, true);
    let decision = service.evaluate_with_clock(&input, &|| Ok(1_234)).unwrap();
    assert_eq!(decision.effect, DecisionEffect::AllowForward);
    let capability = decision.capability.unwrap();
    assert_eq!(
        capability.claims.capability_id,
        format!("capability:{}", decision.decision_digest.as_str())
    );
    assert!(capability.claims.capability_id.len() <= 128);
    assert!(
        capability
            .claims
            .capability_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    );
    assert_eq!(capability.claims.expires_at_ms, 1_245);
    assert_eq!(capability.claims.remaining_budget_ms, 11);
    assert_eq!(
        capability.claims.request_digest,
        input.request.request_digest
    );
    pc_runtime_types::PurposeVerifier::from_sec1_bytes(
        pc_runtime_types::PURPOSE_BROKER_CAPABILITY_V1,
        &service.capability_verifier_sec1(),
    )
    .unwrap()
    .verify(&capability)
    .unwrap();
}

#[test]
fn final_capability_binds_the_owners_exact_preflight_witness() {
    let (input, mut state, verifier) = fixture();
    state.submission_witness_digest = Some(digest("route and preflight A"));
    let owner = Arc::new(FixtureOwner(Mutex::new(state), true, true));
    let pds =
        PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner.clone()).unwrap();
    let first = pds.evaluate_with_clock(&input, &|| Ok(1_234)).unwrap();
    owner.0.lock().unwrap().submission_witness_digest = Some(digest("route and preflight B"));
    let second = pds.evaluate_with_clock(&input, &|| Ok(1_234)).unwrap();
    assert_eq!(first.effect, DecisionEffect::AllowForward);
    assert_eq!(second.effect, DecisionEffect::AllowForward);
    assert_eq!(first.decision_id, second.decision_id);
    assert_ne!(first.decision_input_digest, second.decision_input_digest);
    assert_ne!(first.decision_digest, second.decision_digest);
    assert_ne!(first.capability, second.capability);
    assert_eq!(
        first.capability.unwrap().claims.decision_digest,
        first.decision_digest
    );
    assert_eq!(
        second.capability.unwrap().claims.decision_digest,
        second.decision_digest
    );
}

#[test]
fn signed_identity_never_overrides_owner_denials_or_fabricated_business_proofs() {
    for mutation in 0..16 {
        let (input, mut state, verifier) = fixture();
        match mutation {
            0 => state.emergency_deny = true,
            1 => {
                let mut facts = state.authorization.facts().clone();
                facts.roles = vec!["different-role".into()];
                state.authorization = ValidatedInvocationAuthorization::try_new(facts).unwrap();
            }
            2 => state.bindings.observed_generation_digest = digest("stale"),
            3 => state.bindings.expected_fact_generation_digest = digest("reorg"),
            4 => state
                .bindings
                .eligible_provider_profile_ids
                .push("ambiguous".into()),
            5 => state.evidence.used = 95,
            6 => state.valid_until_ms = 1_234,
            7 => state.request_digest = digest("other-request"),
            8 => state.identity.sender_credential_binding_digest[0] ^= 1,
            9 => state.bindings.privacy_domain_id = "foreign".into(),
            10 => state.active_invocation_policies.clear(),
            11 => state
                .active_invocation_policies
                .push(state.active_invocation_policies[0].clone()),
            12 => {
                let mut policy = policy();
                policy.approval = ApprovalRequirement::MakerChecker;
                state.active_invocation_policies =
                    vec![ValidatedInvocationPolicy::try_new(policy).unwrap()];
            }
            13 => {
                let mut policy = policy();
                policy.webauthn_required = true;
                state.active_invocation_policies =
                    vec![ValidatedInvocationPolicy::try_new(policy).unwrap()];
            }
            14 => {
                let mut facts = state.authorization.facts().clone();
                facts.approval = Some(VerifiedApprovalFact {
                    approval_id: "forged".into(),
                    participant_id: "participant-1".into(),
                    privacy_domain_id: "privacy-1".into(),
                    subject_digest: input.request.request_digest.clone(),
                    maker_principal_id: "principal-1".into(),
                    checker_principal_id: "principal-2".into(),
                    expires_at_ms: 2_000,
                });
                state.authorization = ValidatedInvocationAuthorization::try_new(facts).unwrap();
            }
            15 => {
                let mut facts = state.authorization.facts().clone();
                facts.webauthn = Some(VerifiedWebauthnFact {
                    challenge_id: "forged".into(),
                    participant_id: "participant-1".into(),
                    principal_id: "principal-1".into(),
                    request_digest: input.request.request_digest.clone(),
                    expires_at_ms: 2_000,
                });
                state.authorization = ValidatedInvocationAuthorization::try_new(facts).unwrap();
            }
            _ => unreachable!(),
        }
        let decision = service(state, verifier, true)
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap();
        assert_eq!(
            decision.effect,
            DecisionEffect::DenyTerminal,
            "mutation {mutation}"
        );
        assert!(decision.capability.is_none());
    }
}

#[test]
fn tampered_identity_or_request_and_owner_health_fail_closed() {
    for mutation in 0..5 {
        let (mut input, mut state, verifier) = fixture();
        match mutation {
            0 => *input.identity_assertion.cose_sign1.last_mut().unwrap() ^= 1,
            1 => input.request.invocation.as_mut().unwrap().calldata[3] ^= 1,
            2 => input.request.invocation.as_mut().unwrap().calldata[35] = 8,
            3 => input.request.invocation.as_mut().unwrap().abi_digest = digest("other"),
            _ => {}
        }
        input.request.request_digest = input.request.computed_digest().unwrap();
        state.request_digest = input.request.request_digest.clone();
        let decision = service(state, verifier, mutation != 4)
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap();
        assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
        assert!(decision.capability.is_none());
    }
}

#[test]
fn clock_crossing_freshness_edge_cannot_mint_and_state_fence_is_held() {
    use std::cell::Cell;
    let (input, state, verifier) = fixture();
    let owner = Arc::new(FixtureOwner(Mutex::new(state), true, true));
    let service =
        PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner.clone()).unwrap();
    let reads = Cell::new(0);
    let decision = service
        .evaluate_with_clock(&input, &|| {
            assert!(owner.0.try_lock().is_err());
            reads.set(reads.get() + 1);
            Ok(if reads.get() == 1 { 1_234 } else { 1_900 })
        })
        .unwrap();
    assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
    assert!(decision.capability.is_none());
    assert!(owner.0.try_lock().is_ok());
}

fn digest(value: &str) -> Digest {
    Digest::of(value)
}

fn invocation() -> pc_runtime_types::ContractInvocation {
    let mut calldata = vec![0x12, 0x34, 0x56, 0x78];
    calldata.extend_from_slice(&[0_u8; 31]);
    calldata.push(7);
    pc_runtime_types::ContractInvocation {
        chain_id: "1".into(),
        network_id: "mainnet".into(),
        genesis_digest: digest("genesis"),
        contract_address: [1; 20],
        proxy_address: None,
        implementation_address: None,
        code_digest: digest("code"),
        implementation_code_digest: None,
        abi_digest: digest("abi"),
        calldata,
        nested_calls: Vec::new(),
    }
}

fn policy() -> InvocationPolicy {
    InvocationPolicy {
        method_required_roles: None,
        nested_call_set_digest: None,
        rpc_denied: false,
        tenant_id: "participant-1".into(),
        privacy_domain_id: "privacy-1".into(),
        workload_id: "workload-1".into(),
        policy_version: "1.0.0".into(),
        policy_artifact_digest: digest("artifact"),
        policy_generation_digest: digest("policy"),
        active: true,
        rpc_method: "eth_call".into(),
        request_class: RequestClass::Read,
        chain_id: "1".into(),
        network_id: "mainnet".into(),
        genesis_digest: digest("genesis"),
        contract_address: [1; 20],
        proxy_address: None,
        implementation_address: None,
        code_digest: digest("code"),
        implementation_code_digest: None,
        abi_digest: digest("abi"),
        canonical_signature: "read(uint256)".into(),
        selector: [0x12, 0x34, 0x56, 0x78],
        input_types: vec![AbiType::Uint(256)],
        required_roles: vec!["reader".into()],
        approval: ApprovalRequirement::None,
        webauthn_required: false,
        argument_rules: vec![ArgumentRule {
            path: vec![PathSegment::Input(0)],
            comparator: Comparator::Eq,
            values: RuleValues::Inline(vec![ArgumentValue::uint(7)]),
        }],
        named_sets: Vec::new(),
        nested_policies: Vec::new(),
    }
}

#[test]
fn artifact_admission_rejects_selector_rule_set_and_abi_ambiguity() {
    let mut duplicate_selector = policy();
    let mut nested = policy();
    nested.canonical_signature = "other(uint256)".into();
    duplicate_selector.nested_policies.push(nested);
    assert!(ValidatedInvocationPolicy::try_new(duplicate_selector).is_err());

    let mut duplicate_rule = policy();
    duplicate_rule
        .argument_rules
        .push(duplicate_rule.argument_rules[0].clone());
    assert!(ValidatedInvocationPolicy::try_new(duplicate_rule).is_err());

    let mut invalid_comparator = policy();
    invalid_comparator.input_types[0] = AbiType::String;
    invalid_comparator.argument_rules[0].comparator = Comparator::Gt;
    invalid_comparator.argument_rules[0].values =
        RuleValues::Inline(vec![ArgumentValue::String("x".into())]);
    assert!(ValidatedInvocationPolicy::try_new(invalid_comparator).is_err());

    let mut invalid_width = policy();
    invalid_width.input_types[0] = AbiType::Uint(7);
    assert!(ValidatedInvocationPolicy::try_new(invalid_width).is_err());
}

#[test]
fn active_artifact_loader_rejects_digest_identity_and_topology_ambiguity() {
    let raw = policy();
    let configuration_asset = InvocationConfigurationAssetV1 {
        asset_id: "read-uint256".into(),
        runtime_binding_id: None,
        transaction_policy: None,
        tenant_id: raw.tenant_id,
        privacy_domain_id: raw.privacy_domain_id,
        workload_id: raw.workload_id,
        rpc_method: raw.rpc_method,
        request_class: raw.request_class,
        chain_id: raw.chain_id,
        network_id: raw.network_id,
        genesis_digest: raw.genesis_digest,
        contract_address: raw.contract_address,
        proxy_address: raw.proxy_address,
        implementation_address: raw.implementation_address,
        code_digest: raw.code_digest,
        implementation_code_digest: raw.implementation_code_digest,
        abi_digest: raw.abi_digest,
        canonical_signature: raw.canonical_signature,
        selector: raw.selector,
        input_types: raw.input_types,
        named_sets: raw.named_sets,
    };
    let policy_asset = InvocationPolicyAssetV1 {
        method_required_roles: None,
        nested_call_set_digest: None,
        rpc_denied: false,
        asset_id: "read-uint256".into(),
        policy_version: raw.policy_version,
        active: raw.active,
        required_roles: raw.required_roles,
        approval: raw.approval,
        webauthn_required: raw.webauthn_required,
        argument_rules: raw.argument_rules,
        nested_asset_ids: Vec::new(),
    };
    let provider_payload = vec![0xa0];
    let provider_artifact = ConfigurationArtifactV1 {
        artifact_id: "provider-1".into(),
        artifact_kind: ConfigurationArtifactKind::ProviderProfile,
        artifact_digest: Digest::of(&provider_payload),
        payload_cbor: provider_payload.clone(),
    };
    let configuration = ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        deployment_policies: Vec::new(),
        schema_version: "1.0".into(),
        assets: vec![configuration_asset.clone()],
        resource_artifacts: vec![provider_artifact.clone()],
    };
    let generation = ActiveInvocationPolicyGenerationV1 {
        visibility_policies: Vec::new(),
        fact_conditions: Vec::new(),
        indexer_policies: Vec::new(),
        deployment_policies: Vec::new(),
        required_facts: Vec::new(),
        rpc_policies: Vec::new(),
        schema_version: "1.0".into(),
        root_asset_ids: vec!["read-uint256".into()],
        assets: vec![policy_asset.clone()],
    };
    let configuration_bytes = encode_active_invocation_configuration(&configuration).unwrap();
    let generation_bytes = encode_active_invocation_policy_generation(&generation).unwrap();
    let dependency = pc_policy_core::semantics::FactReference {
        candidate_id: "required-candidate".into(),
        generation_id: "required-generation".into(),
        fact_digest: format!("sha256:{}", "ab".repeat(32)),
    };
    for references in [
        vec![dependency.clone(), dependency.clone()],
        vec![pc_policy_core::semantics::FactReference {
            fact_digest: "not-a-digest".into(),
            ..dependency.clone()
        }],
        vec![pc_policy_core::semantics::FactReference {
            generation_id: String::new(),
            ..dependency
        }],
    ] {
        let mut changed = generation.clone();
        changed.required_facts = references;
        let bytes = encode_active_invocation_policy_generation(&changed).unwrap();
        assert!(
            ValidatedInvocationPolicy::load_active(
                &configuration_bytes,
                &Digest::of(&configuration_bytes),
                &bytes,
                &Digest::of(&bytes),
                &ActiveInvocationScope {
                    policy_generation_digest: &digest("policy-generation"),
                    tenant_id: "participant-1",
                    privacy_domain_id: "privacy-1",
                    workload_id: "workload-1"
                },
            )
            .is_err(),
            "untrusted compiled fact references must be validated at admission"
        );
    }
    assert_eq!(
        ValidatedInvocationPolicy::load_active(
            &configuration_bytes,
            &Digest::of(&configuration_bytes),
            &generation_bytes,
            &Digest::of(&generation_bytes),
            &ActiveInvocationScope {
                policy_generation_digest: &digest("policy-generation"),
                tenant_id: "participant-1",
                privacy_domain_id: "privacy-1",
                workload_id: "workload-1",
            },
        )
        .unwrap()
        .len(),
        1
    );
    assert_eq!(
        load_active_configuration_artifact(
            &configuration_bytes,
            &Digest::of(&configuration_bytes),
            "provider-1",
            ConfigurationArtifactKind::ProviderProfile,
            &Digest::of(&provider_payload),
        )
        .unwrap(),
        provider_payload
    );
    assert!(
        load_active_configuration_artifact(
            &configuration_bytes,
            &Digest::of(&configuration_bytes),
            "provider-1",
            ConfigurationArtifactKind::ClientIndexerProfile,
            &Digest::of(&provider_payload),
        )
        .is_err()
    );
    assert!(
        ValidatedInvocationPolicy::load_active(
            &configuration_bytes,
            &digest("wrong-configuration"),
            &generation_bytes,
            &Digest::of(&generation_bytes),
            &ActiveInvocationScope {
                policy_generation_digest: &digest("policy-generation"),
                tenant_id: "participant-1",
                privacy_domain_id: "privacy-1",
                workload_id: "workload-1",
            },
        )
        .is_err()
    );

    let mut duplicate_resource = configuration.clone();
    let repeated_resource = duplicate_resource.resource_artifacts[0].clone();
    duplicate_resource
        .resource_artifacts
        .push(repeated_resource);
    let duplicate_resource_bytes =
        encode_active_invocation_configuration(&duplicate_resource).unwrap();
    assert!(
        load_active_configuration_artifact(
            &duplicate_resource_bytes,
            &Digest::of(&duplicate_resource_bytes),
            "provider-1",
            ConfigurationArtifactKind::ProviderProfile,
            &Digest::of(&provider_payload),
        )
        .is_err()
    );

    let duplicate_configuration = ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        deployment_policies: Vec::new(),
        schema_version: "1.0".into(),
        assets: vec![configuration_asset.clone(), configuration_asset],
        resource_artifacts: vec![provider_artifact],
    };
    let duplicate_bytes = encode_active_invocation_configuration(&duplicate_configuration).unwrap();
    assert!(
        ValidatedInvocationPolicy::load_active(
            &duplicate_bytes,
            &Digest::of(&duplicate_bytes),
            &generation_bytes,
            &Digest::of(&generation_bytes),
            &ActiveInvocationScope {
                policy_generation_digest: &digest("policy-generation"),
                tenant_id: "participant-1",
                privacy_domain_id: "privacy-1",
                workload_id: "workload-1",
            },
        )
        .is_err()
    );

    let cyclic_generation = ActiveInvocationPolicyGenerationV1 {
        visibility_policies: Vec::new(),
        fact_conditions: Vec::new(),
        indexer_policies: Vec::new(),
        deployment_policies: Vec::new(),
        required_facts: Vec::new(),
        rpc_policies: Vec::new(),
        schema_version: "1.0".into(),
        root_asset_ids: vec!["read-uint256".into()],
        assets: vec![InvocationPolicyAssetV1 {
            method_required_roles: None,
            nested_call_set_digest: None,
            rpc_denied: false,
            nested_asset_ids: vec!["read-uint256".into()],
            ..policy_asset
        }],
    };
    let cyclic_bytes = encode_active_invocation_policy_generation(&cyclic_generation).unwrap();
    assert!(
        ValidatedInvocationPolicy::load_active(
            &configuration_bytes,
            &Digest::of(&configuration_bytes),
            &cyclic_bytes,
            &Digest::of(&cyclic_bytes),
            &ActiveInvocationScope {
                policy_generation_digest: &digest("policy-generation"),
                tenant_id: "participant-1",
                privacy_domain_id: "privacy-1",
                workload_id: "workload-1",
            },
        )
        .is_err()
    );
}

#[test]
fn authorization_admission_rejects_duplicate_roles_and_foreign_facts() {
    let mut duplicate_roles = authorization();
    duplicate_roles.roles.push("reader".into());
    assert!(ValidatedInvocationAuthorization::try_new(duplicate_roles).is_err());

    let mut foreign = authorization();
    foreign.webauthn = Some(VerifiedWebauthnFact {
        challenge_id: "challenge".into(),
        participant_id: "foreign".into(),
        principal_id: "principal-1".into(),
        request_digest: digest("request"),
        expires_at_ms: 200,
    });
    assert!(ValidatedInvocationAuthorization::try_new(foreign).is_err());
}

#[test]
fn evidence_commit_failure_withholds_capability() {
    let (input, state, verifier) = fixture();
    let owner = Arc::new(FixtureOwner(Mutex::new(state), true, false));
    let service = PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner).unwrap();
    let decision = service.evaluate_with_clock(&input, &|| Ok(1_234)).unwrap();
    assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
    assert_eq!(decision.pc_code, RuntimeError::EvidenceCapacity.pc_code());
    assert!(decision.capability.is_none());
}

#[test]
fn identity_and_policy_denials_reach_the_evidence_owner_before_return() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct RecordingOwner {
        state: Mutex<LocalDecisionState>,
        count: AtomicUsize,
    }
    struct RecordingLease<'a> {
        state: MutexGuard<'a, LocalDecisionState>,
        count: &'a AtomicUsize,
    }
    impl LocalDecisionOwner for RecordingOwner {
        fn acquire(&self, _: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>> {
            Ok(Box::new(RecordingLease {
                state: self.state.lock().unwrap(),
                count: &self.count,
            }))
        }
    }
    impl LocalDecisionLease for RecordingLease<'_> {
        fn state(&self) -> &LocalDecisionState {
            &self.state
        }
        fn revalidate(&self) -> RuntimeResult<()> {
            Ok(())
        }
        fn commit(&mut self, decision: &pc_runtime_types::RuntimeDecision) -> RuntimeResult<()> {
            assert_eq!(decision.effect, DecisionEffect::DenyTerminal);
            assert!(decision.capability.is_none());
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    let (mut input, state, verifier) = fixture();
    let owner = Arc::new(RecordingOwner {
        state: Mutex::new(state),
        count: AtomicUsize::new(0),
    });
    let service =
        PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner.clone()).unwrap();
    let original = input.identity_assertion.clone();
    *input.identity_assertion.cose_sign1.last_mut().unwrap() ^= 1;
    assert_eq!(
        service
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap()
            .effect,
        DecisionEffect::DenyTerminal
    );
    input.identity_assertion = original;
    owner.state.lock().unwrap().emergency_deny = true;
    assert_eq!(
        service
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap()
            .effect,
        DecisionEffect::DenyTerminal
    );
    assert_eq!(owner.count.load(Ordering::Relaxed), 2);
}

#[test]
fn recreated_pds_uses_owner_reserved_ids_and_rejects_missing_reservation() {
    let (input, state, verifier) = fixture();
    let owner = Arc::new(FixtureOwner(Mutex::new(state), true, true));
    let first = PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner.clone())
        .unwrap()
        .evaluate_with_clock(&input, &|| Ok(1_234))
        .unwrap();
    assert_eq!(first.decision_id, "target-1/decision-1");
    owner.0.lock().unwrap().decision_id = "target-1/decision-2".into();
    let (_, _, verifier) = fixture();
    let second_service =
        PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, owner.clone()).unwrap();
    let second = second_service
        .evaluate_with_clock(&input, &|| Ok(1_234))
        .unwrap();
    assert_eq!(second.decision_id, "target-1/decision-2");
    assert_ne!(
        first.capability.unwrap().claims.capability_id,
        second.capability.unwrap().claims.capability_id
    );
    owner.0.lock().unwrap().decision_id.clear();
    let denied = second_service
        .evaluate_with_clock(&input, &|| Ok(1_234))
        .unwrap();
    assert!(denied.capability.is_none());
    assert_eq!(denied.pc_code, RuntimeError::RuntimeUnavailable.pc_code());
}

#[test]
fn request_local_owner_cannot_fall_back_to_another_peers_global_authority() {
    let (input, state, verifier) = fixture();
    let global = Arc::new(FixtureOwner(Mutex::new(state.clone()), true, true));
    let service = PolicyDecisionService::with_runtime_owner([7; 32], 25, verifier, global).unwrap();
    assert_eq!(
        service
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap()
            .effect,
        DecisionEffect::AllowForward
    );
    let mut foreign = state;
    foreign.identity.sender_credential_binding_digest = [99; 32];
    let foreign = FixtureOwner(Mutex::new(foreign), true, true);
    let denied = service
        .evaluate_owned_with_clock(&input, Some(&foreign), &|| Ok(1_234))
        .unwrap();
    assert_eq!(denied.effect, DecisionEffect::DenyTerminal);
    assert_eq!(denied.pc_code, RuntimeError::InvalidAuthorization.pc_code());
    assert!(denied.capability.is_none());
    let (_, _, verifier) = fixture();
    let without_default =
        PolicyDecisionService::with_identity_trust([7; 32], 25, verifier).unwrap();
    assert!(
        without_default
            .evaluate_with_clock(&input, &|| Ok(1_234))
            .unwrap()
            .capability
            .is_none()
    );
}
