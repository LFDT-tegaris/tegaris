//! Nested method constraints use the same authored selector/argument/approval
//! source. Public RPC roles remain with the outer capability/surface owner.
use crate::{
    contract_policy::{
        compile_admitted_contract_policies,
        tests::{admitted, rpc_policy},
    },
    invocation::*,
};
use pc_runtime_types::{ContractInvocation, Digest, RequestClass, RuntimeError};

fn inputs() -> (
    crate::contract_policy::CompiledContractPolicyBundle,
    ContractInvocation,
    ValidatedInvocationAuthorization,
) {
    let mut input = admitted();
    input.approval_requirement = "NONE".into();
    input.mfa_requirement = "NONE".into();
    let bundle = compile_admitted_contract_policies(
        &[input.clone()],
        &[rpc_policy()],
        &Digest::of("generation"),
        "workload",
    )
    .unwrap()
    .unwrap();
    let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
    calldata.extend([0; 12]);
    calldata.extend([0x22; 20]);
    calldata.extend([0; 31]);
    calldata.push(50);
    let (_, invocation) = resolve_contract_invocation(
        &bundle.policies,
        "eth_sendRawTransaction",
        [0x11; 20],
        calldata,
    )
    .unwrap();
    let actor = ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
        participant_id: input.tenant_id,
        privacy_domain_id: input.privacy_domain_id,
        workload_id: "workload".into(),
        actor_principal_id: "actor".into(),
        roles: vec!["treasury-writer".into()],
        approval: None,
        webauthn: None,
    })
    .unwrap();
    (bundle, invocation, actor)
}

#[test]
fn internal_method_constraints_do_not_grant_public_rpc_or_borrow_its_roles() {
    let (bundle, invocation, actor) = inputs();
    let generation = Digest::of("generation");
    let request = Digest::of("root-request");
    let evaluation = InvocationEvaluation {
        request_method: "eth_call",
        request_class: RequestClass::Read,
        request_digest: &request,
        active_policy_generation: &generation,
        now_ms: 1000,
    };
    let policy = &bundle.policies[0];
    assert_eq!(
        policy.artifact().method_required_roles.as_deref(),
        Some(["treasury-writer".into()].as_slice())
    );
    assert_eq!(
        policy.artifact().required_roles,
        ["rpc-writer", "treasury-writer"]
    );
    assert!(evaluate_nested_contract_method(&invocation, policy, &actor, &evaluation).is_ok());
    assert!(evaluate_invocation(&invocation, policy, &actor, &evaluation).is_err());
    let public_write = InvocationEvaluation {
        request_method: "eth_sendRawTransaction",
        request_class: RequestClass::Write,
        ..evaluation
    };
    assert!(evaluate_invocation(&invocation, policy, &actor, &public_write).is_err());
    let mut both = actor.facts().clone();
    both.roles.push("rpc-writer".into());
    assert!(
        evaluate_invocation(
            &invocation,
            policy,
            &ValidatedInvocationAuthorization::try_new(both).unwrap(),
            &public_write
        )
        .is_ok()
    );
}

#[test]
fn nested_constraints_keep_typed_arguments_registration_tenant_generation_and_method_roles() {
    let (bundle, invocation, actor) = inputs();
    let generation = Digest::of("generation");
    let request = Digest::of("root-request");
    let evaluation = InvocationEvaluation {
        request_method: "eth_call",
        request_class: RequestClass::Read,
        request_digest: &request,
        active_policy_generation: &generation,
        now_ms: 1000,
    };
    let policy = &bundle.policies[0];
    let mut changed = invocation.clone();
    changed.calldata[4..36].fill(0);
    assert!(evaluate_nested_contract_method(&changed, policy, &actor, &evaluation).is_err());
    let mut changed = invocation.clone();
    changed.calldata[36..68].fill(255);
    assert!(evaluate_nested_contract_method(&changed, policy, &actor, &evaluation).is_err());
    let mut changed = invocation.clone();
    changed.code_digest = Digest::of("changed-code");
    assert!(evaluate_nested_contract_method(&changed, policy, &actor, &evaluation).is_err());
    let mut changed = invocation.clone();
    changed.nested_calls.push(invocation.clone());
    assert!(evaluate_nested_contract_method(&changed, policy, &actor, &evaluation).is_err());
    for field in ["participant", "role"] {
        let mut facts = actor.facts().clone();
        if field == "participant" {
            facts.participant_id = "foreign".into();
        } else {
            facts.roles = vec!["rpc-writer".into()];
        }
        assert!(
            evaluate_nested_contract_method(
                &invocation,
                policy,
                &ValidatedInvocationAuthorization::try_new(facts).unwrap(),
                &evaluation
            )
            .is_err()
        );
    }
    let different = Digest::of("different");
    assert!(
        evaluate_nested_contract_method(
            &invocation,
            policy,
            &actor,
            &InvocationEvaluation {
                active_policy_generation: &different,
                ..evaluation
            }
        )
        .is_err()
    );
    assert!(matches!(
        evaluate_nested_contract_method(
            &invocation,
            &ValidatedInvocationPolicy::try_new(policy.artifact().clone()).unwrap(),
            &actor,
            &evaluation
        ),
        Err(RuntimeError::InvalidAuthorization)
    ));
}

#[test]
fn legacy_artifacts_still_load_but_cannot_infer_internal_authority_from_rpc_roles() {
    let (bundle, invocation, actor) = inputs();
    let generation_digest = Digest::of("generation");
    let request = Digest::of("request");
    let mut generation =
        decode_active_invocation_policy_generation(&bundle.policy_cbor, &bundle.policy_digest)
            .unwrap();
    generation.assets[0].method_required_roles = None;
    let bytes = encode_active_invocation_policy_generation(&generation).unwrap();
    let scope = ActiveInvocationScope {
        policy_generation_digest: &generation_digest,
        tenant_id: &actor.facts().participant_id,
        privacy_domain_id: &actor.facts().privacy_domain_id,
        workload_id: "workload",
    };
    let policies = ValidatedInvocationPolicy::load_active(
        &bundle.configuration_cbor,
        &bundle.configuration_digest,
        &bytes,
        &Digest::of(&bytes),
        &scope,
    )
    .unwrap();
    let evaluation = InvocationEvaluation {
        request_method: "eth_sendRawTransaction",
        request_class: RequestClass::Write,
        request_digest: &request,
        active_policy_generation: &generation_digest,
        now_ms: 1000,
    };
    assert!(
        evaluate_nested_contract_method(&invocation, &policies[0], &actor, &evaluation).is_err()
    );
    let mut both = actor.facts().clone();
    both.roles.push("rpc-writer".into());
    assert!(
        evaluate_invocation(
            &invocation,
            &policies[0],
            &ValidatedInvocationAuthorization::try_new(both).unwrap(),
            &evaluation
        )
        .is_ok()
    );
}

#[test]
fn nested_approval_and_step_up_cannot_be_satisfied_by_an_unconditional_grant() {
    let (_, invocation, actor) = inputs();
    let generation = Digest::of("generation");
    let request = Digest::of("request");
    let evaluation = InvocationEvaluation {
        request_method: "eth_call",
        request_class: RequestClass::Read,
        request_digest: &request,
        active_policy_generation: &generation,
        now_ms: 1000,
    };
    for condition in ["approval", "step-up"] {
        let mut input = admitted();
        if condition == "approval" {
            input.mfa_requirement = "NONE".into();
        } else {
            input.approval_requirement = "NONE".into();
        }
        let bundle =
            compile_admitted_contract_policies(&[input], &[rpc_policy()], &generation, "workload")
                .unwrap()
                .unwrap();
        assert!(
            evaluate_nested_contract_method(&invocation, &bundle.policies[0], &actor, &evaluation)
                .is_err()
        );
    }
}

#[test]
fn reviewed_method_reference_requires_current_observed_registered_code_and_selector() {
    let (bundle, invocation, _) = inputs();
    let id = admitted().asset_id;
    let resolve = |policy_id: &str, target, input: Vec<u8>, code: Digest| {
        resolve_nested_contract_invocation(&bundle.policies, policy_id, target, input, |_| {
            Ok(code.clone())
        })
    };
    let (selected, resolved) = resolve(
        &id,
        [0x11; 20],
        invocation.calldata.clone(),
        Digest::of("code"),
    )
    .unwrap();
    assert_eq!(
        selected
            .configured_identity()
            .unwrap()
            .contract_method_policy_id(),
        id
    );
    assert_eq!(resolved, invocation);
    assert!(
        resolve(
            "unregistered",
            [0x11; 20],
            invocation.calldata.clone(),
            Digest::of("code")
        )
        .is_err()
    );
    assert!(
        resolve(
            &id,
            [0x12; 20],
            invocation.calldata.clone(),
            Digest::of("code")
        )
        .is_err()
    );
    assert!(
        resolve(
            &id,
            [0x11; 20],
            invocation.calldata.clone(),
            Digest::of("changed")
        )
        .is_err()
    );
    assert!(resolve(&id, [0x11; 20], vec![0; 4], Digest::of("code")).is_err());
    assert!(
        resolve_nested_contract_invocation(
            &bundle.policies,
            &id,
            [0x11; 20],
            invocation.calldata,
            |_| Err(RuntimeError::RuntimeUnavailable)
        )
        .is_err()
    );
}
