use super::*;
use crate::{invocation::InvocationAuthorization, rpc_policy::RpcRule};

pub(super) const PARTICIPANT: &str = "018f0000-0000-7000-8000-000000000101";
pub(super) const PRIVACY: &str = "018f0000-0000-7000-8000-000000000201";
pub(super) const SOURCE: &str = "018f0000-0000-7000-8000-000000000301";
pub(super) const PLAN: &str = "018f0000-0000-7000-8000-000000000401";
pub(super) const WORKLOAD: &str = "urn:openpc:workload:018f0000-0000-7000-8000-000000000501";

pub(super) fn rpc_policies() -> Vec<RpcSurfacePolicy> {
    vec![RpcSurfacePolicy {
        schema_version: "1.0.0".into(),
        participant_id: PARTICIPANT.into(),
        privacy_domain_id: PRIVACY.into(),
        rules: [IndexerDataClass::StateCall, IndexerDataClass::BlockHeader]
            .into_iter()
            .map(|class| RpcRule {
                method: class.profile_method().into(),
                effect: RpcEffect::Allow,
                required_roles: vec!["source-reader".into()],
            })
            .collect(),
    }]
}

pub(super) fn policy() -> IndexerPolicy {
    IndexerPolicy {
        schema_version: "1.0.0".into(),
        participant_id: PARTICIPANT.into(),
        privacy_domain_id: PRIVACY.into(),
        workload_id: WORKLOAD.into(),
        indexer_profile_id: SOURCE.into(),
        profile_artifact_digest: format!("sha256:{}", "11".repeat(32)),
        projection_plan_id: PLAN.into(),
        plan_artifact_digest: format!("sha256:{}", "22".repeat(32)),
        acquisition_configuration_digest: format!("sha256:{}", "33".repeat(32)),
        rpc_policy_digest: format!("sha256:{}", rpc_policies()[0].digest().unwrap().as_str()),
        range_start: "100".into(),
        range_end: "199".into(),
        maximum_range_blocks: "10".into(),
        maximum_response_bytes: 4096,
        rules: vec![IndexerDataRule {
            data_class: IndexerDataClass::StateCall,
            effect: RpcEffect::Allow,
            required_roles: vec!["source-reader".into()],
        }],
    }
}

fn request(policy: &IndexerPolicy) -> IndexerPolicyRequest<'_> {
    IndexerPolicyRequest {
        indexer_profile_id: &policy.indexer_profile_id,
        profile_artifact_digest: &policy.profile_artifact_digest,
        projection_plan_id: &policy.projection_plan_id,
        plan_artifact_digest: &policy.plan_artifact_digest,
        acquisition_configuration_digest: &policy.acquisition_configuration_digest,
        data_class: IndexerDataClass::StateCall,
        range_start: 100,
        range_end: 109,
        maximum_response_bytes: 4096,
    }
}

fn actor() -> InvocationAuthorization {
    InvocationAuthorization {
        participant_id: PARTICIPANT.into(),
        privacy_domain_id: PRIVACY.into(),
        workload_id: WORKLOAD.into(),
        actor_principal_id: "source-principal".into(),
        roles: vec!["source-reader".into()],
        approval: None,
        webauthn: None,
    }
}

#[test]
fn exact_tuple_and_current_actor_are_separate_required_inputs() {
    let policy = policy();
    let request = request(&policy);
    let authorization = ValidatedInvocationAuthorization::try_new(actor()).unwrap();
    assert!(
        evaluate_indexer_policies(
            std::slice::from_ref(&policy),
            &request,
            &authorization,
            &rpc_policies()
        )
        .is_ok()
    );
    assert!(evaluate_indexer_policies(&[], &request, &authorization, &rpc_policies()).is_err());
    for field in ["participant", "privacy", "workload", "role"] {
        let mut other = actor();
        match field {
            "participant" => other.participant_id = PLAN.into(),
            "privacy" => other.privacy_domain_id = PLAN.into(),
            "workload" => other.workload_id = format!("urn:openpc:workload:{PLAN}"),
            "role" => other.roles = vec!["viewer".into()],
            _ => unreachable!(),
        }
        let other = ValidatedInvocationAuthorization::try_new(other).unwrap();
        assert!(
            evaluate_indexer_policies(
                std::slice::from_ref(&policy),
                &request,
                &other,
                &rpc_policies()
            )
            .is_err(),
            "{field}"
        );
    }
    for field in ["source", "profile", "plan", "plan-bytes", "configuration"] {
        let mut other = policy.clone();
        match field {
            "source" => other.indexer_profile_id = PLAN.into(),
            "profile" => other.profile_artifact_digest = other.plan_artifact_digest.clone(),
            "plan" => other.projection_plan_id = SOURCE.into(),
            "plan-bytes" => other.plan_artifact_digest = other.profile_artifact_digest.clone(),
            "configuration" => {
                other.acquisition_configuration_digest = other.plan_artifact_digest.clone()
            }
            _ => unreachable!(),
        }
        assert!(
            evaluate_indexer_policies(&[other], &request, &authorization, &rpc_policies()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn minimum_data_class_range_and_response_budget_cannot_expand() {
    let policy = policy();
    let authorization = ValidatedInvocationAuthorization::try_new(actor()).unwrap();
    for (start, end, bytes) in [
        (99, 100, 4096),
        (100, 110, 4096),
        (195, 200, 4096),
        (109, 100, 4096),
        (100, 109, 4097),
        (100, 109, 0),
    ] {
        let mut candidate = request(&policy);
        candidate.range_start = start;
        candidate.range_end = end;
        candidate.maximum_response_bytes = bytes;
        assert!(
            evaluate_indexer_policies(
                std::slice::from_ref(&policy),
                &candidate,
                &authorization,
                &rpc_policies()
            )
            .is_err()
        );
    }
    let mut headers = policy.clone();
    headers.rules[0].data_class = IndexerDataClass::BlockHeader;
    let mut candidate = request(&policy);
    candidate.data_class = IndexerDataClass::BlockHeader;
    assert!(
        evaluate_indexer_policies(
            std::slice::from_ref(&headers),
            &candidate,
            &authorization,
            &rpc_policies()
        )
        .is_ok()
    );
    candidate.data_class = IndexerDataClass::FullBlockTransactions;
    assert!(
        evaluate_indexer_policies(&[headers], &candidate, &authorization, &rpc_policies()).is_err()
    );
    assert_ne!(
        IndexerDataClass::BlockHeader.profile_method(),
        IndexerDataClass::FullBlockTransactions.profile_method()
    );
}

#[test]
fn terminal_denial_and_stale_active_tuple_cannot_be_outvoted() {
    let policy = policy();
    let request = request(&policy);
    let authorization = ValidatedInvocationAuthorization::try_new(actor()).unwrap();
    let mut deny = policy.clone();
    deny.rules[0].effect = RpcEffect::Deny;
    deny.rules[0].required_roles.clear();
    let mut stale = policy.clone();
    stale.plan_artifact_digest = policy.profile_artifact_digest.clone();
    for restriction in [deny, stale] {
        for policies in [
            vec![policy.clone(), restriction.clone()],
            vec![restriction.clone(), policy.clone()],
        ] {
            assert_eq!(
                evaluate_indexer_policies(&policies, &request, &authorization, &rpc_policies()),
                Err(RuntimeError::Denied)
            );
        }
    }
}

#[test]
fn independent_projection_rules_do_not_expand_or_block_each_other() {
    let policy = policy();
    let authorization = ValidatedInvocationAuthorization::try_new(actor()).unwrap();
    let mut other = policy.clone();
    other.projection_plan_id = SOURCE.into();
    other.rules[0].effect = RpcEffect::Deny;
    assert!(
        evaluate_indexer_policies(
            &[policy.clone(), other.clone()],
            &request(&policy),
            &authorization,
            &rpc_policies()
        )
        .is_ok()
    );
    assert_eq!(
        evaluate_indexer_policies(
            &[policy, other.clone()],
            &request(&other),
            &authorization,
            &rpc_policies()
        ),
        Err(RuntimeError::Denied)
    );
}

#[test]
fn authored_policy_is_closed_and_canonical_before_versioning() {
    let original = policy();
    for value in ["01", "-1", "+1", "1.0", "18446744073709551616"] {
        let mut invalid = original.clone();
        invalid.maximum_range_blocks = value.into();
        assert!(invalid.digest().is_err());
    }
    let mut duplicate = original.clone();
    duplicate.rules.push(duplicate.rules[0].clone());
    assert!(duplicate.validate().is_err());
    let mut no_role = original.clone();
    no_role.rules[0].required_roles.clear();
    assert!(no_role.validate().is_err());
    let mut unknown = serde_json::to_value(&original).unwrap();
    unknown["ready"] = serde_json::json!(true);
    assert!(serde_json::from_value::<IndexerPolicy>(unknown).is_err());
    let decoded: IndexerPolicy =
        ciborium::de::from_reader(pc_cbor_1(&original).as_slice()).unwrap();
    assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());
}

#[test]
fn source_rule_cannot_bypass_an_independent_rpc_denial_or_missing_reference() {
    let mut policy = policy();
    let authorization = ValidatedInvocationAuthorization::try_new(actor()).unwrap();
    assert!(
        evaluate_indexer_policies(
            std::slice::from_ref(&policy),
            &request(&policy),
            &authorization,
            &[]
        )
        .is_err()
    );
    let mut rpc = rpc_policies();
    rpc[0].rules[0].effect = RpcEffect::Deny;
    policy.rpc_policy_digest = format!("sha256:{}", rpc[0].digest().unwrap().as_str());
    assert_eq!(
        evaluate_indexer_policies(
            std::slice::from_ref(&policy),
            &request(&policy),
            &authorization,
            &rpc
        ),
        Err(RuntimeError::Denied)
    );
    assert_eq!(
        crate::rpc_policy::request_class("eth_getBlockByNumber(false)"),
        None,
        "declaring source policy must not enable a runtime invocation form"
    );
    assert_eq!(
        IndexerDataClass::for_profile_method("eth_getBlockByNumber"),
        None,
        "ambiguous header/full-block form remains unsupported"
    );
}

#[test]
fn semantic_document_requires_the_module_and_cannot_discard_source_rules() {
    let mut document = crate::semantics::tests::document();
    let historical = pc_cbor_1(&document);
    let value = serde_json::to_value(&document).unwrap();
    assert!(
        value.get("indexerPolicies").is_none(),
        "old signed semantic bytes omit the new empty field"
    );
    let decoded: crate::semantics::PolicySemanticDocument = serde_json::from_value(value).unwrap();
    assert_eq!(pc_cbor_1(&decoded), historical);

    document.rpc_policies = rpc_policies();
    document.indexer_policies = vec![policy()];
    assert!(
        document.validate().is_err(),
        "dedicated module binding is required"
    );
    let mut module = document.module_bindings[0].clone();
    module.module_id = "pc.indexing.dedicated-policy".into();
    document.module_bindings.push(module);
    assert!(document.validate().is_ok());
    document.contract_policies.clear();
    document.required_facts.clear();
    assert!(
        document.validate().is_ok(),
        "source-only authoring must not invent a bootstrap fact dependency"
    );
    assert!(
        crate::contract_simulation::compile_document(
            &document,
            &[],
            WORKLOAD,
            &document.digest().unwrap()
        )
        .is_err(),
        "missing resolved source inputs cannot compile an empty or partial policy"
    );
    document.indexer_policies[0].privacy_domain_id = PLAN.into();
    assert!(document.validate().is_err());
}
