use super::*;
use crate::cigl::{
    CallKind, TraceLimits,
    analysis::{AnalyzedInteraction, MethodResolution},
    grants::GrantSubject,
    profile::{CallerConstraint, MethodInteractionRule},
};

fn id(suffix: u16) -> String {
    format!("018f0000-0000-7000-8000-{suffix:012}")
}
fn fixture() -> (MethodAnalysisV1, MethodProfileDefinition) {
    let first = AnalyzedInteraction {
        ordinal: 1,
        parent: 0,
        depth: 1,
        call_kind: CallKind::Call,
        caller: [1; 20],
        target: [2; 20],
        execution_address: [2; 20],
        selector: Some([2; 4]),
        input_digest: Digest::of("input"),
        message_value_digest: Digest::of("zero"),
        code_digest: Digest::of("code"),
        failed: false,
        resolution: MethodResolution::Registered {
            contract_method_policy_id: id(20),
            runtime_binding_id: id(21),
        },
    };
    let mut nested = first.clone();
    nested.ordinal = 2;
    nested.parent = 1;
    nested.depth = 2;
    nested.caller = [2; 20];
    // Recursive access is still a nested action, not a fabricated root path.
    nested.target = [1; 20];
    nested.execution_address = [1; 20];
    nested.selector = Some([1; 4]);
    nested.resolution = MethodResolution::Registered {
        contract_method_policy_id: id(10),
        runtime_binding_id: id(11),
    };
    let mut sibling = first.clone();
    sibling.ordinal = 3;
    let analysis = MethodAnalysisV1 {
        schema_version: "1.0".into(),
        participant_id: id(1),
        privacy_domain_id: id(2),
        workload_id: "workload".into(),
        root_contract_method_policy_id: id(10),
        root_runtime_binding_id: id(11),
        configuration_digest: Digest::of("configuration"),
        policy_artifact_digest: Digest::of("policy"),
        policy_generation_digest: Digest::of("generation"),
        request_digest: Digest::of("request"),
        authority_digest: Digest::of("authority"),
        observation_digest: Digest::of("observation"),
        observation_context_digest: Digest::of("context"),
        route_witness_set_digest: Digest::of("routes"),
        anchor_digest: Digest::of("anchor"),
        limits: TraceLimits {
            max_depth: 32,
            max_frames: 128,
            max_response_bytes: 100_000,
            timeout_ms: 5000,
        },
        interactions: vec![first, nested, sibling],
    };
    let profile = MethodProfileDefinition {
        schema_version: "1.0".into(),
        profile_id: id(3),
        revision: 1,
        participant_id: id(1),
        privacy_domain_id: id(2),
        root_contract_method_policy_id: id(10),
        analysis_digest: analysis.digest().unwrap(),
        program: None,
        limits: analysis.limits,
        interactions: vec![
            MethodInteractionRule {
                interaction_id: "first-and-sibling".into(),
                caller: CallerConstraint::Exact { address: [1; 20] },
                call_kind: CallKind::Call,
                contract_method_policy_id: id(20),
                maximum_value: [0; 32],
            },
            MethodInteractionRule {
                interaction_id: "recursive-child".into(),
                caller: CallerConstraint::Exact { address: [2; 20] },
                call_kind: CallKind::Call,
                contract_method_policy_id: id(10),
                maximum_value: [0; 32],
            },
        ],
    };
    (analysis, profile)
}

#[test]
fn backend_paths_preserve_nested_recursion_and_distinct_occurrences() {
    let (analysis, profile) = fixture();
    let paths = derive_nested_dependencies(&analysis, &profile).unwrap();
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0].relationship_path, vec![1]);
    assert_eq!(paths[1].relationship_path, vec![1, 2]);
    assert_eq!(paths[2].relationship_path, vec![3]);
    assert_eq!(paths[1].contract_method_policy_id, id(10));
    assert_ne!(paths[0].closure_digest, paths[2].closure_digest);
    let mut changed = profile.clone();
    changed.revision += 1;
    assert_ne!(
        paths[0].closure_digest,
        derive_nested_dependencies(&analysis, &changed).unwrap()[0].closure_digest
    );
    changed = profile.clone();
    changed.privacy_domain_id = id(99);
    assert!(derive_nested_dependencies(&analysis, &changed).is_err());
    changed = profile.clone();
    changed.interactions.pop();
    assert!(derive_nested_dependencies(&analysis, &changed).is_err());
    let mut bad_tree = analysis.clone();
    bad_tree.interactions[1].parent = 2;
    assert!(derive_nested_dependencies(&bad_tree, &profile).is_err());
}

#[test]
fn exact_subject_bundle_rejects_missing_extra_disabled_wrong_surface_and_denies() {
    let (analysis, profile) = fixture();
    let dependencies = derive_nested_dependencies(&analysis, &profile).unwrap();
    let source = InteractionGrant {
        grant_id: id(30),
        runtime_binding_id: id(11),
        selector: [1; 4],
        subject: GrantSubject::Role { id: "role".into() },
        surface: InteractionSurface::EthCall,
        effect: GrantEffect::Allow,
        status: GrantStatus::Active,
    };
    let mut child = source.clone();
    child.grant_id = id(31);
    child.runtime_binding_id = id(21);
    child.selector = [2; 4];
    let grants = vec![source.clone(), child];
    let reviewed: Vec<_> = dependencies
        .iter()
        .enumerate()
        .map(|(i, d)| ReviewedDependencyGrant {
            action_digest: d.action_digest.clone(),
            required_grant_id: id(if i == 1 { 30 } else { 31 }),
        })
        .collect();
    let check = |choices: &[ReviewedDependencyGrant], grants: &[InteractionGrant]| {
        verify_nested_bundle(
            &dependencies,
            &source,
            DependencyCapability::SimulateCall,
            choices,
            grants,
        )
    };
    assert!(check(&reviewed, &grants).is_ok());
    assert!(check(&reviewed[..2], &grants).is_err());
    let mut extra = reviewed.clone();
    extra.push(reviewed[0].clone());
    assert!(check(&extra, &grants).is_err());
    extra = reviewed.clone();
    extra[1] = extra[0].clone();
    assert!(check(&extra, &grants).is_err());
    for altered in 0..4 {
        let mut bad = grants.clone();
        match altered {
            0 => bad[1].subject = GrantSubject::User { id: "role".into() },
            1 => bad[1].status = GrantStatus::Disabled,
            2 => bad[1].surface = InteractionSurface::RawSubmission,
            _ => bad[1].runtime_binding_id = id(99),
        }
        assert!(check(&reviewed, &bad).is_err());
    }
    let mut denied = grants.clone();
    let mut deny = grants[1].clone();
    deny.grant_id = id(32);
    deny.effect = GrantEffect::Deny;
    deny.subject = GrantSubject::AnyAuthenticated {};
    denied.push(deny);
    assert_eq!(check(&reviewed, &denied), Err(RuntimeError::Denied));
    assert!(check(&reviewed, &grants).is_ok()); // Shared input was never mutated.
}

#[test]
fn capability_surface_mapping_cannot_escalate_simulation_into_write() {
    use DependencyCapability::*;
    use InteractionSurface::*;
    for surface in [
        EthCall,
        EthEstimateGas,
        PrepareWrite,
        RawSubmission,
        DeploymentConstructor,
        RuntimeWriteTrace,
    ] {
        assert_eq!(
            SimulateCall.require_surface(surface).is_ok(),
            surface == EthCall
        );
        assert_eq!(
            ExecuteTransaction.require_surface(surface).is_ok(),
            matches!(surface, PrepareWrite | RawSubmission | RuntimeWriteTrace)
        );
    }
}
