use super::*;
use crate::{contract_simulation::compile_document_with_deployments, invocation::*, semantics};

fn publication() -> AdmittedDeploymentPolicy {
    let mut transaction = crate::transaction_policy::tests::policy();
    transaction.maximum_value = [0; 32];
    let definition: DeploymentPolicyDefinition = serde_json::from_value(serde_json::json!({
        "schemaVersion":"1.0.0", "profileId":"reference:direct", "profileVersion":"1.0.0",
        "assuranceLevel":"A0", "creationEvidence":"COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1",
        "chainId":"1", "networkId":"ethereum", "genesisDigest":format!("sha256:{}", "11".repeat(32)),
        "abiArtifactId":"urn:openpc:resource:018f0000-0000-7000-8000-000000000501",
        "artifact":{"mode":"EXACT_INIT_CODE", "initCode":"0x6001600c60003960016000f300",
            "runtimeCodeHash": hex(&Keccak256::digest([0]))},
        "route":{"mechanism":"TRANSACTION_CREATE"}, "allowedSenders":[format!("0x{}", "22".repeat(20))],
        "requiredRoles":["role:deployer"], "approvalRequirement":"MAKER_CHECKER", "webauthnRequired":true,
        "transactionPolicy":transaction, "expiresAt":"2030-01-01T00:00:00.000Z"
    })).unwrap();
    let init_code_hash = hex(&Keccak256::digest(
        bytes(&definition.artifact.init_code, 32_768).unwrap(),
    ));
    let artifact_digest = format!(
        "sha256:{}",
        json_digest(&serde_json::json!({
            "mode":"EXACT_INIT_CODE", "initCodeHash":init_code_hash,
            "runtimeCodeHash":definition.artifact.runtime_code_hash,
        }))
        .unwrap()
        .as_str()
    );
    AdmittedDeploymentPolicy {
        deployment_policy_id: "018f0000-0000-7000-8000-000000000401".into(),
        participant_id: "018f0000-0000-7000-8000-000000000101".into(),
        privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
        definition_digest: format!("sha256:{}", json_digest(&definition).unwrap().as_str()),
        definition,
        artifact_digest,
        init_code_hash,
        abi_digest: format!("sha256:{}", Digest::of(b"[]").as_str()),
        publication_operation_id: "018f0000-0000-7000-8000-000000000601".into(),
        publication_authority_digest: format!(
            "sha256:{}",
            Digest::of(b"actual authorization proof").as_str()
        ),
        factory_binding: None,
    }
}

#[test]
fn curated_create3_requires_the_exact_helper_and_complete_evidence_profile() {
    let mut definition = publication().definition;
    definition.route = DeploymentRouteDefinition::Create3 {
        runtime_binding_id: "urn:openpc:resource:018f0000-0000-7000-8000-000000000601".into(),
        canonical_signature: "deployCreate3(bytes32,bytes)".into(),
        code_hash: format!("0x{}", "22".repeat(32)),
        adapter_digest: format!("sha256:{}", "33".repeat(32)),
        arguments: "SALT_INIT_CODE".into(),
        salt_namespace_digest: format!("sha256:{}", "44".repeat(32)),
        salt_transform: "IDENTITY".into(),
        helper_profile: CREATE3_HELPER_PROFILE.into(),
    };
    assert!(
        definition.validate().is_err(),
        "single-creation evidence cannot cover CREATE3"
    );
    definition.creation_evidence = "COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1".into();
    definition.validate().unwrap();
    let DeploymentRouteDefinition::Create3 { helper_profile, .. } = &mut definition.route else {
        unreachable!()
    };
    *helper_profile = "caller-provided-helper".into();
    assert!(definition.validate().is_err());
}

fn document(publication: &AdmittedDeploymentPolicy) -> semantics::PolicySemanticDocument {
    let mut document = semantics::tests::document();
    document.contract_policies.clear();
    document.rpc_policies[0].rules[0].method = "eth_sendRawTransaction".into();
    document.deployment_policies = vec![DeploymentPolicyReference {
        deployment_policy_id: publication.deployment_policy_id.clone(),
        definition_digest: publication.definition_digest.clone(),
    }];
    for module in ["pc.policy.deployment", "pc.deployment.governance"] {
        let mut binding = document.module_bindings[0].clone();
        binding.module_id = module.into();
        document.module_bindings.push(binding);
    }
    document
}

#[test]
fn deployment_compilation_retains_exact_publication_without_a_contract_invocation() {
    let publication = publication();
    let document = document(&publication);
    let generation = document.digest().unwrap();
    let compiled = compile_document_with_deployments(
        &document,
        &[],
        std::slice::from_ref(&publication),
        "workload",
        &generation,
    )
    .unwrap();
    assert!(compiled.policies.is_empty());
    let configuration = decode_active_invocation_configuration(
        &compiled.configuration_cbor,
        &compiled.configuration_digest,
    )
    .unwrap();
    assert!(configuration.assets.is_empty());
    assert_eq!(
        configuration.deployment_policies[0].publication,
        publication
    );
    assert_eq!(
        active_invocation_workload(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &document.participant_id,
            &document.privacy_domain_id
        )
        .unwrap(),
        "workload"
    );
    let installed = &compiled.deployment_policies[0];
    assert_eq!(installed.publication(), &publication);
    assert_eq!(installed.policy_generation_digest(), &generation);
    assert_eq!(
        installed.configuration_digest(),
        &compiled.configuration_digest
    );
    assert_eq!(installed.policy_artifact_digest(), &compiled.policy_digest);
    assert_eq!(installed.workload_id(), "workload");
    let expiry = publication.definition.expires_at_ms().unwrap();
    assert!(installed.publication_is_unexpired(expiry - 1));
    assert!(!installed.publication_is_unexpired(expiry));
}

#[test]
fn deployment_generation_rejects_missing_extra_changed_and_cross_scope_publications() {
    let original = publication();
    let document = document(&original);
    let generation = document.digest().unwrap();
    assert!(
        compile_document_with_deployments(&document, &[], &[], "workload", &generation).is_err()
    );
    assert!(
        compile_document_with_deployments(
            &document,
            &[],
            &[original.clone(), original.clone()],
            "workload",
            &generation
        )
        .is_err()
    );
    for field in [
        "definitionDigest",
        "initCodeHash",
        "artifactDigest",
        "participantId",
        "privacyDomainId",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = match field {
            "participantId" | "privacyDomainId" => {
                Value::String("018f0000-0000-7000-8000-000000000999".into())
            }
            "initCodeHash" => Value::String(format!("0x{}", "33".repeat(32))),
            _ => Value::String(format!("sha256:{}", "33".repeat(32))),
        };
        let changed = serde_json::from_value(value).unwrap();
        assert!(
            compile_document_with_deployments(&document, &[], &[changed], "workload", &generation)
                .is_err(),
            "{field}"
        );
    }
    let mut missing_module = document.clone();
    missing_module
        .module_bindings
        .retain(|binding| binding.module_id != "pc.deployment.governance");
    assert!(missing_module.validate().is_err());
    let mut duplicate = document.clone();
    duplicate
        .deployment_policies
        .push(duplicate.deployment_policies[0].clone());
    assert!(duplicate.validate().is_err());
}

#[test]
fn installed_deployment_selection_is_exact_and_scope_bound() {
    let publication = publication();
    let document = document(&publication);
    let generation_digest = document.digest().unwrap();
    let compiled = compile_document_with_deployments(
        &document,
        &[],
        &[publication],
        "workload",
        &generation_digest,
    )
    .unwrap();
    let mut generation =
        decode_active_invocation_policy_generation(&compiled.policy_cbor, &compiled.policy_digest)
            .unwrap();
    let scope = ActiveInvocationScope {
        policy_generation_digest: &generation_digest,
        tenant_id: &document.participant_id,
        privacy_domain_id: &document.privacy_domain_id,
        workload_id: "workload",
    };
    generation.deployment_policies[0].definition_digest = format!("sha256:{}", "99".repeat(32));
    let changed = encode_active_invocation_policy_generation(&generation).unwrap();
    assert!(
        ValidatedDeploymentPolicy::load_active(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &changed,
            &Digest::of(&changed),
            &scope
        )
        .is_err()
    );
    let wrong_scope = ActiveInvocationScope {
        workload_id: "another-workload",
        ..scope
    };
    assert!(
        ValidatedDeploymentPolicy::load_active(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &compiled.policy_cbor,
            &compiled.policy_digest,
            &wrong_scope
        )
        .is_err()
    );
    generation.deployment_policies.clear();
    let unselected = encode_active_invocation_policy_generation(&generation).unwrap();
    assert!(
        ValidatedInvocationPolicy::load_active(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &unselected,
            &Digest::of(&unselected),
            &scope
        )
        .is_err()
    );
}

#[test]
fn deployment_definition_rejects_weakened_profiles_and_invalid_adapter_layouts() {
    let original = serde_json::to_value(publication().definition).unwrap();
    for (field, value) in [
        ("assuranceLevel", serde_json::json!("A2")),
        ("chainId", serde_json::json!("01")),
        ("expiresAt", serde_json::json!("2030-01-01T00:00:00Z")),
        ("allowedSenders", serde_json::json!([])),
        ("requiredRoles", serde_json::json!(["role:z", "role:a"])),
        (
            "route",
            serde_json::json!({"mechanism":"CREATE", "runtimeBindingId":"urn:openpc:resource:018f0000-0000-7000-8000-000000000701",
            "canonicalSignature":"deploy(bytes32,bytes)","codeHash":format!("0x{}","44".repeat(32)),"adapterDigest":format!("sha256:{}","55".repeat(32))}),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            serde_json::from_value::<DeploymentPolicyDefinition>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{field}"
        );
    }
    let mut extra = original;
    extra["ready"] = Value::Bool(true);
    assert!(serde_json::from_value::<DeploymentPolicyDefinition>(extra).is_err());
}

#[test]
fn contract_only_semantics_and_compilation_keep_the_existing_encoding() {
    let mut document = semantics::tests::document();
    let admitted = crate::contract_policy::tests::admitted();
    document.rpc_policies = vec![crate::contract_policy::tests::rpc_policy()];
    document.contract_policies[0].contract_method_policy_id = admitted.asset_id.clone();
    document.contract_policies[0].revision = admitted.policy_version.clone();
    let old = serde_json::to_value(&document).unwrap();
    assert!(old.get("deploymentPolicies").is_none());
    let encoded = crate::pc_cbor_1(&document);
    assert_eq!(
        semantics::PolicySemanticDocument::decode(&encoded).unwrap(),
        document
    );
    let generation = document.digest().unwrap();
    let expected = crate::contract_policy::compile_admitted_contract_policies_with_facts(
        std::slice::from_ref(&admitted),
        &document.rpc_policies,
        &generation,
        "workload",
        &document.required_facts,
    )
    .unwrap()
    .unwrap();
    let actual =
        compile_document_with_deployments(&document, &[admitted], &[], "workload", &generation)
            .unwrap();
    assert_eq!(actual.configuration_cbor, expected.configuration_cbor);
    assert_eq!(actual.policy_cbor, expected.policy_cbor);
}

#[test]
fn deployment_and_contract_assets_share_a_generation_without_sharing_identity() {
    let publication = publication();
    let contract = crate::contract_policy::tests::admitted();
    let mut document = document(&publication);
    document.rpc_policies = vec![crate::contract_policy::tests::rpc_policy()];
    document
        .contract_policies
        .push(semantics::ContractPolicyReference {
            contract_method_policy_id: contract.asset_id.clone(),
            revision: contract.policy_version.clone(),
        });
    let generation = document.digest().unwrap();
    let compiled = compile_document_with_deployments(
        &document,
        &[contract],
        &[publication],
        "workload",
        &generation,
    )
    .unwrap();
    assert_eq!(compiled.policies.len(), 1);
    assert_eq!(compiled.deployment_policies.len(), 1);
    let configuration = decode_active_invocation_configuration(
        &compiled.configuration_cbor,
        &compiled.configuration_digest,
    )
    .unwrap();
    assert_ne!(
        configuration.assets[0].asset_id,
        configuration.deployment_policies[0]
            .publication
            .deployment_policy_id
    );
    document.deployment_policies[0].deployment_policy_id = document.contract_policies[0]
        .contract_method_policy_id
        .clone();
    assert!(document.validate().is_err());
}

#[test]
fn installed_deployment_requires_current_scoped_authority_and_every_rpc_conjunct() {
    let mut publication = publication();
    publication.definition.approval_requirement = "NONE".into();
    publication.definition.webauthn_required = false;
    publication.definition_digest = format!(
        "sha256:{}",
        json_digest(&publication.definition).unwrap().as_str()
    );
    let mut document = document(&publication);
    document.rpc_policies[0].rules[0].required_roles = vec!["role:deployer".into()];
    let generation = document.digest().unwrap();
    let compile = |document: &semantics::PolicySemanticDocument,
                   publication: &AdmittedDeploymentPolicy| {
        compile_document_with_deployments(
            document,
            &[],
            std::slice::from_ref(publication),
            "workload",
            &document.digest().unwrap(),
        )
        .unwrap()
    };
    let compiled = compile(&document, &publication);
    let policy = &compiled.deployment_policies[0];
    let mut request = pc_runtime_types::RuntimeRequest {
        visibility: None,
        request_id: "1".into(),
        method: "eth_sendRawTransaction".into(),
        params_digest: Digest::of(b"exact signed transaction"),
        transport: pc_runtime_types::Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class: pc_runtime_types::RequestClass::Write,
        received_at_ms: 1000,
        deadline_at_ms: 2000,
        response_budget_bytes: 4096,
        invocation: None,
        deployment: Some(pc_runtime_types::DeploymentInvocation {
            deployment_policy_id: publication.deployment_policy_id.clone(),
            intent_digest: Digest::of(b"exact intent"),
        }),
    };
    request.request_digest = request.computed_digest().unwrap();
    let actor = InvocationAuthorization {
        participant_id: publication.participant_id.clone(),
        privacy_domain_id: publication.privacy_domain_id.clone(),
        workload_id: "workload".into(),
        actor_principal_id: "principal".into(),
        roles: vec!["role:deployer".into()],
        approval: None,
        webauthn: None,
    };
    let authorized = ValidatedInvocationAuthorization::try_new(actor.clone()).unwrap();
    policy
        .evaluate(&request, &authorized, &generation, 1001)
        .unwrap();
    for mutation in 0..4 {
        let mut changed = actor.clone();
        match mutation {
            0 => changed.participant_id = "other".into(),
            1 => changed.privacy_domain_id = "other".into(),
            2 => changed.workload_id = "other".into(),
            _ => changed.roles = vec!["reader".into()],
        }
        assert!(
            policy
                .evaluate(
                    &request,
                    &ValidatedInvocationAuthorization::try_new(changed).unwrap(),
                    &generation,
                    1001
                )
                .is_err()
        );
    }
    assert!(
        policy
            .evaluate(&request, &authorized, &Digest::of(b"changed"), 1001)
            .is_err()
    );
    assert!(
        policy
            .evaluate(&request, &authorized, &generation, 2000)
            .is_err()
    );
    let mut wrong_policy = request.clone();
    wrong_policy
        .deployment
        .as_mut()
        .unwrap()
        .deployment_policy_id = "other".into();
    wrong_policy.request_digest = wrong_policy.computed_digest().unwrap();
    assert!(
        policy
            .evaluate(&wrong_policy, &authorized, &generation, 1001)
            .is_err()
    );
    for rpc_failure in 0..3 {
        let mut denied = document.clone();
        match rpc_failure {
            0 => denied.rpc_policies[0].rules[0].method = "eth_call".into(),
            1 => denied.rpc_policies[0].rules[0].required_roles = vec!["unheld".into()],
            _ => {
                let mut deny = denied.rpc_policies[0].clone();
                deny.rules[0].effect = crate::rpc_policy::RpcEffect::Deny;
                denied.rpc_policies.push(deny);
            }
        }
        let denied_compiled = compile(&denied, &publication);
        assert!(
            denied_compiled.deployment_policies[0]
                .evaluate(&request, &authorized, &denied.digest().unwrap(), 1001)
                .is_err()
        );
    }
    let mut conditional = publication.clone();
    conditional.definition.approval_requirement = "MAKER_CHECKER".into();
    conditional.definition_digest = format!(
        "sha256:{}",
        json_digest(&conditional.definition).unwrap().as_str()
    );
    let mut conditional_document = document.clone();
    conditional_document.deployment_policies[0].definition_digest =
        conditional.definition_digest.clone();
    let conditional_compiled = compile(&conditional_document, &conditional);
    assert!(
        conditional_compiled.deployment_policies[0]
            .evaluate(
                &request,
                &authorized,
                &conditional_document.digest().unwrap(),
                1001
            )
            .is_err()
    );
}
