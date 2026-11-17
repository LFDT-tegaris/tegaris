use super::*;
use crate::{
    pc_cbor_1,
    semantics::{ModuleBinding, PolicySemanticDocument},
};

fn policy() -> VisibilityPolicy {
    VisibilityPolicy {
        policy_id: "018f0000-0000-7000-8000-000000000901".into(),
        selector: VisibilitySelector::Disclosure {
            profile_id: "018f0000-0000-7000-8000-000000000950".into(),
            profile_digest: format!("sha256:{}", "ab".repeat(32)),
            data_class_id: "TRANSACTION".into(),
        },
        mode: VisibilityMode::Static,
        effect: RpcEffect::Allow,
        subject: VisibilitySubject::Principal {
            principal_id: "018f0000-0000-7000-8000-000000000301".into(),
        },
        purpose: "AUDIT".into(),
        required_roles: vec!["reader".into()],
        dimensions: vec![VisibilityDimension::Existence, VisibilityDimension::Payload],
        fields: vec!["PEF-AMOUNT".into(), "PEF-ASSET".into()],
        conditions: Vec::new(),
    }
}

fn request(policy: &VisibilityPolicy) -> VisibilityRequest<'_> {
    VisibilityRequest {
        selector: &policy.selector,
        mode: policy.mode,
        subject: &policy.subject,
        purpose: &policy.purpose,
        roles: &policy.required_roles,
    }
}

#[test]
fn visibility_event_fields_bind_exact_canonical_tuple_signature() {
    use crate::contract_policy::event_fields;
    let event = serde_json::json!({"type":"event","name":"Changed","anonymous":false,
        "inputs":[{"name":"owner","type":"address","indexed":true},
        {"name":"position","type":"tuple[]","indexed":false,"components":[{"type":"uint256"},{"type":"bytes32"}]}]});
    let abi = serde_json::json!([event]);
    let signature = "Changed(address,(uint256,bytes32)[])";
    assert_eq!(
        event_fields(&abi, signature).unwrap(),
        ["inputs[0]", "inputs[1]"]
    );
    assert!(event_fields(&abi, "Changed(address,uint256)").is_err());
    assert!(event_fields(&serde_json::json!([event, event]), signature).is_err());
    let mut invalid = abi.clone();
    invalid[0]["inputs"][1]["components"][0]["type"] = serde_json::json!("uint7");
    assert!(event_fields(&invalid, "Changed(address,(uint7,bytes32)[])").is_err());
}

fn disclosure_document() -> PolicySemanticDocument {
    let mut document = crate::semantics::tests::document();
    document.rpc_policies.clear();
    document.contract_policies.clear();
    document.required_facts.clear();
    document.module_bindings = vec![ModuleBinding {
        module_id: "pc.policy.selective-disclosure".into(),
        ..document.module_bindings[0].clone()
    }];
    document.visibility_policies = vec![policy()];
    document
}

#[test]
fn visibility_compilation_requires_exact_owner_resolved_scope_profile_and_fields() {
    use crate::contract_simulation::compile_document_with_visibility;
    let document = disclosure_document();
    let resource = AdmittedVisibilityResource {
        state_output_types: None,
        contract_binding: None,
        participant_id: document.participant_id.clone(),
        privacy_domain_id: document.privacy_domain_id.clone(),
        selector: document.visibility_policies[0].selector.clone(),
        available_fields: document.visibility_policies[0].fields.clone(),
    };
    let generation = document.digest().unwrap();
    let compile = |resources: &[AdmittedVisibilityResource]| {
        compile_document_with_visibility(
            &document,
            &[],
            &[],
            &[],
            resources,
            "principal",
            &generation,
        )
    };
    assert!(compile(&[]).is_err());
    let bundle = compile(std::slice::from_ref(&resource)).unwrap();
    let active = crate::invocation::decode_active_invocation_policy_generation(
        &bundle.policy_cbor,
        &bundle.policy_digest,
    )
    .unwrap();
    assert_eq!(active.visibility_policies, document.visibility_policies);
    assert!(active.assets.is_empty());
    assert!(bundle.policies.is_empty());
    use crate::invocation::{
        ActiveInvocationScope, ValidatedInvocationPolicy, active_invocation_workload,
        decode_active_invocation_configuration, encode_active_invocation_configuration,
    };
    let configuration = decode_active_invocation_configuration(
        &bundle.configuration_cbor,
        &bundle.configuration_digest,
    )
    .unwrap();
    assert!(configuration.assets.is_empty());
    assert!(configuration.deployment_policies.is_empty());
    assert!(configuration.resource_artifacts.is_empty());
    assert!(active.rpc_policies.is_empty());
    assert!(active.required_facts.is_empty());
    assert_eq!(
        active_invocation_workload(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
            &document.participant_id,
            &document.privacy_domain_id,
        )
        .unwrap(),
        "principal"
    );
    let scope = ActiveInvocationScope {
        policy_generation_digest: &generation,
        tenant_id: &document.participant_id,
        privacy_domain_id: &document.privacy_domain_id,
        workload_id: "principal",
    };
    assert!(
        ValidatedInvocationPolicy::load_active(
            &bundle.configuration_cbor,
            &bundle.configuration_digest,
            &bundle.policy_cbor,
            &bundle.policy_digest,
            &scope,
        )
        .unwrap()
        .is_empty()
    );
    for mutation in 0..4 {
        let mut wrong = configuration.clone();
        let binding = wrong.workload_scope.as_mut().unwrap();
        match mutation {
            0 => binding.participant_id = "foreign participant".into(),
            1 => binding.privacy_domain_id = "foreign privacy".into(),
            2 => binding.workload_id = "foreign workload".into(),
            _ => wrong.workload_scope = None,
        }
        let bytes = encode_active_invocation_configuration(&wrong).unwrap();
        let digest = pc_runtime_types::Digest::of(&bytes);
        assert!(
            ValidatedInvocationPolicy::load_active(
                &bytes,
                &digest,
                &bundle.policy_cbor,
                &bundle.policy_digest,
                &scope,
            )
            .is_err(),
            "scope mutation {mutation}"
        );
        if mutation != 2 {
            assert!(
                active_invocation_workload(
                    &bytes,
                    &digest,
                    &document.participant_id,
                    &document.privacy_domain_id,
                )
                .is_err()
            );
        }
    }
    for mutation in 0..3 {
        let mut wrong = resource.clone();
        match mutation {
            0 => wrong.privacy_domain_id = "018f0000-0000-7000-8000-000000000999".into(),
            1 => wrong.available_fields.clear(),
            _ => {
                if let VisibilitySelector::Disclosure { profile_digest, .. } = &mut wrong.selector {
                    *profile_digest = format!("sha256:{}", "cd".repeat(32));
                }
            }
        }
        assert!(compile(&[wrong]).is_err());
    }
    assert!(compile(&[resource.clone(), resource]).is_err());
}

#[test]
fn visibility_simulation_uses_authenticated_subject_purpose_and_requested_dimensions() {
    use crate::contract_simulation::SimulationActor;
    let document = disclosure_document();
    let mut input = VisibilitySimulationInput {
        visibility_inputs: vec![AdmittedVisibilityResource {
            state_output_types: None,
            contract_binding: None,
            participant_id: document.participant_id.clone(),
            privacy_domain_id: document.privacy_domain_id.clone(),
            selector: document.visibility_policies[0].selector.clone(),
            available_fields: document.visibility_policies[0].fields.clone(),
        }],
        actor: SimulationActor {
            participant_id: document.participant_id.clone(),
            privacy_domain_id: document.privacy_domain_id.clone(),
            principal_id: "018f0000-0000-7000-8000-000000000301".into(),
            workload_id: None,
            assignment_id: "assignment".into(),
            roles: vec!["reader".into()],
            authority_digest: "ab".repeat(32),
        },
        request: VisibilitySimulationRequest {
            visibility_policy_id: document.visibility_policies[0].policy_id.clone(),
            purpose: "AUDIT".into(),
            dimensions: vec![VisibilityDimension::Payload],
            fields: vec!["PEF-AMOUNT".into()],
        },
        document,
        admitted: vec![],
        deployments: vec![],
        indexer_inputs: vec![],
        workload_prediction: None,
        facts: vec![],
    };
    assert_eq!(
        evaluate_visibility_simulation(&input).unwrap().truth_state,
        crate::TruthState::Success
    );
    for mutation in 0..4 {
        let mut denied = input.clone();
        match mutation {
            0 => denied.actor.principal_id = "018f0000-0000-7000-8000-000000000302".into(),
            1 => denied.request.purpose = "MARKETING".into(),
            2 => denied.request.dimensions = vec![VisibilityDimension::Export],
            _ => denied.request.fields = vec!["PEF-SECRET".into()],
        }
        assert_eq!(
            evaluate_visibility_simulation(&denied).unwrap().truth_state,
            crate::TruthState::Denied
        );
    }
    // A public policy can retain the workload-bound acquisition contribution
    // while a human simulates its visibility rules. Compilation uses that
    // source workload; the permission decision still uses the actual reader.
    let (source, configuration) = crate::indexer_policy::compilation_tests::fixture();
    input.document.indexer_policies = source.indexer_policies;
    input.document.rpc_policies.extend(source.rpc_policies);
    input.document.module_bindings.extend(
        source
            .module_bindings
            .into_iter()
            .filter(|binding| {
                matches!(
                    binding.module_id.as_str(),
                    "pc.indexing.dedicated-policy" | "pc.policy.rpc-surface"
                )
            })
            .collect::<Vec<_>>(),
    );
    input.indexer_inputs.push(configuration);
    assert_eq!(
        evaluate_visibility_simulation(&input).unwrap().truth_state,
        crate::TruthState::Success
    );
    let mut foreign_reader = input.clone();
    foreign_reader.actor.principal_id = "018f0000-0000-7000-8000-000000000302".into();
    assert_eq!(
        evaluate_visibility_simulation(&foreign_reader)
            .unwrap()
            .truth_state,
        crate::TruthState::Denied
    );
    let mut missing_source = input.clone();
    missing_source.indexer_inputs.clear();
    assert!(evaluate_visibility_simulation(&missing_source).is_err());
    let mut wrong_source = input.clone();
    wrong_source.document.indexer_policies[0].workload_id =
        "urn:openpc:workload:018f0000-0000-7000-8000-000000000399".into();
    assert!(evaluate_visibility_simulation(&wrong_source).is_err());
    input.actor.privacy_domain_id = "018f0000-0000-7000-8000-000000000999".into();
    assert!(evaluate_visibility_simulation(&input).is_err());
}

#[test]
fn visibility_standalone_disclosure_has_no_dummy_rpc_contract_or_fact_grant() {
    let mut document = crate::semantics::tests::document();
    document.rpc_policies.clear();
    document.contract_policies.clear();
    document.required_facts.clear();
    document.module_bindings = vec![ModuleBinding {
        module_id: "pc.policy.selective-disclosure".into(),
        ..document.module_bindings[0].clone()
    }];
    document.visibility_policies = vec![policy()];
    document.validate().unwrap();
    assert_eq!(
        PolicySemanticDocument::decode(&pc_cbor_1(&document)).unwrap(),
        document
    );
    document.module_bindings.clear();
    assert!(document.validate().is_err());
}

#[test]
fn visibility_distinct_rules_can_narrow_against_distinct_conditions_of_one_fact() {
    let mut document = disclosure_document();
    let fact = crate::semantics::tests::document().required_facts.remove(0);
    document.required_facts = vec![fact.clone()];
    let mut second = document.visibility_policies[0].clone();
    second.policy_id = "018f0000-0000-7000-8000-000000000902".into();
    document.visibility_policies.push(second);
    for (index, policy) in document.visibility_policies.iter_mut().enumerate() {
        policy.conditions.push(FactCondition::ExternalObservation {
            fact: fact.clone(),
            provider_id: "compliance".into(),
            provider_version: "1".into(),
            provider_configuration_digest: pc_runtime_types::Digest::of(b"provider"),
            request_digest: pc_runtime_types::Digest::of(b"request"),
            condition: format!("condition-{index}"),
        });
    }
    document.validate().unwrap();
    assert!(
        evaluate_visibility(
            &document.visibility_policies,
            &document.required_facts,
            &request(&document.visibility_policies[0]),
            |condition| condition == &document.visibility_policies[0].conditions[0]
        )
        .is_err()
    );
}

#[test]
fn visibility_extension_preserves_preexisting_canonical_document_bytes() {
    let document = crate::semantics::tests::document();
    let before = serde_json::to_value(&document).unwrap();
    assert!(before.get("visibilityPolicies").is_none());
    assert_eq!(pc_cbor_1(&before), pc_cbor_1(&document));
    let mut explicit_empty = before.clone();
    explicit_empty["visibilityPolicies"] = serde_json::json!([]);
    let after: PolicySemanticDocument = serde_json::from_value(explicit_empty).unwrap();
    assert_eq!(document.digest().unwrap(), after.digest().unwrap());
}

#[test]
fn visibility_is_closed_bounded_and_rejects_fabricated_authority() {
    for field in ["current", "ready", "priority", "allowAll", "subjectKey"] {
        let mut value = serde_json::to_value(policy()).unwrap();
        value[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<VisibilityPolicy>(value).is_err());
    }
    let mut candidate = policy();
    candidate.fields = vec!["*".into()];
    assert!(candidate.validate(&[]).is_err());
    candidate = policy();
    candidate.dimensions.push(VisibilityDimension::Payload);
    assert!(candidate.validate(&[]).is_err());
    candidate = policy();
    candidate.mode = VisibilityMode::Dynamic;
    assert!(candidate.validate(&[]).is_err());
}

#[test]
fn visibility_intersects_fields_and_independent_dimensions_and_never_overrides_deny() {
    let broad = policy();
    let mut narrow = broad.clone();
    narrow.policy_id = "018f0000-0000-7000-8000-000000000902".into();
    narrow.fields = vec!["PEF-AMOUNT".into()];
    let decision = evaluate_visibility(
        &[broad.clone(), narrow.clone()],
        &[],
        &request(&broad),
        |_| false,
    )
    .unwrap();
    assert_eq!(decision.fields, BTreeSet::from(["PEF-AMOUNT".into()]));
    assert!(!decision.dimensions.contains(&VisibilityDimension::Evidence));
    assert!(!decision.dimensions.contains(&VisibilityDimension::Export));
    narrow.effect = RpcEffect::Deny;
    for policies in [
        vec![broad.clone(), narrow.clone()],
        vec![narrow, broad.clone()],
    ] {
        assert!(evaluate_visibility(&policies, &[], &request(&broad), |_| true).is_err());
    }
    let mut requested = request(&broad);
    requested.purpose = "MARKETING";
    assert!(evaluate_visibility(std::slice::from_ref(&broad), &[], &requested, |_| true).is_err());
    requested = request(&broad);
    let mut wrong_profile = broad.selector.clone();
    if let VisibilitySelector::Disclosure { profile_digest, .. } = &mut wrong_profile {
        *profile_digest = format!("sha256:{}", "cd".repeat(32));
    }
    requested.selector = &wrong_profile;
    assert!(evaluate_visibility(std::slice::from_ref(&broad), &[], &requested, |_| true).is_err());
}

#[test]
fn visibility_static_grant_does_not_satisfy_dynamic_request_or_failed_predicate() {
    let mut static_policy = policy();
    static_policy.selector = VisibilitySelector::Event {
        runtime_binding_id: "018f0000-0000-7000-8000-000000000701".into(),
        binding_revision: "1".into(),
        abi_digest: format!("sha256:{}", "ab".repeat(32)),
        event_signature: "Transfer(address,address,uint256)".into(),
    };
    let mut input = request(&static_policy);
    input.mode = VisibilityMode::Dynamic;
    assert!(
        evaluate_visibility(std::slice::from_ref(&static_policy), &[], &input, |_| true).is_err()
    );
    let fact = crate::semantics::tests::document().required_facts.remove(0);
    let mut dynamic = static_policy.clone();
    dynamic.policy_id = "018f0000-0000-7000-8000-000000000902".into();
    dynamic.mode = VisibilityMode::Dynamic;
    dynamic.conditions = vec![FactCondition::ExternalObservation {
        fact: fact.clone(),
        provider_id: "external-fact".into(),
        provider_version: "1.0.0".into(),
        provider_configuration_digest: pc_runtime_types::Digest::of(b"provider"),
        request_digest: pc_runtime_types::Digest::of(b"request"),
        condition: "PERMITTED".into(),
    }];
    let policies = vec![static_policy.clone(), dynamic];
    assert!(
        evaluate_visibility(&policies, std::slice::from_ref(&fact), &input, |_| false).is_err()
    );
    assert!(evaluate_visibility(&policies, &[fact], &input, |_| true).is_ok());
}

#[test]
fn visibility_receipts_require_complete_response_permission_without_field_shaping() {
    let mut receipt = policy();
    receipt.selector = VisibilitySelector::Receipt {
        runtime_binding_id: "018f0000-0000-7000-8000-000000000701".into(),
        binding_revision: "1".into(),
    };
    assert!(receipt.validate(&[]).is_err());
    receipt.fields.clear();
    assert!(
        evaluate_visibility(
            std::slice::from_ref(&receipt),
            &[],
            &request(&receipt),
            |_| true
        )
        .is_err()
    );
    receipt.dimensions.push(VisibilityDimension::Metadata);
    let result = evaluate_visibility(
        std::slice::from_ref(&receipt),
        &[],
        &request(&receipt),
        |_| true,
    )
    .unwrap();
    assert!(result.whole_receipt);
    assert!(result.fields.is_empty());
    assert!(!result.dimensions.contains(&VisibilityDimension::Evidence));
}
