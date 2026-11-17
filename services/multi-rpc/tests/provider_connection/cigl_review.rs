use pc_policy_core::{
    cigl::{
        analysis::{
            MethodAnalysisV1, MethodResolution, UnresolvedReason,
            review::{MethodAnalysisReview, ReviewedInteraction},
        },
        program::{CiglProgramV1, Primitive, ResultType},
    },
    invocation::ArgumentValue,
};
use pc_runtime_types::Digest;

pub(super) fn assert_exact_review(
    analysis: &MethodAnalysisV1,
    configuration: &[u8],
    policy: &[u8],
) {
    let profile_id = "018f0000-0000-7000-8000-000000000800";
    let review_for = |source: &MethodAnalysisV1| MethodAnalysisReview {
        analysis_digest: source.digest().unwrap(),
        actions: source
            .interactions
            .iter()
            .map(|i| ReviewedInteraction {
                action_digest: i.action_digest().unwrap(),
                maximum_value: [0; 32],
            })
            .collect(),
        program: None,
    };
    let review = review_for(analysis);
    let candidate = review
        .compile_candidate(analysis, configuration, policy, profile_id, 1)
        .unwrap();
    assert_eq!(
        candidate.root_contract_method_policy_id,
        analysis.root_contract_method_policy_id
    );
    assert_eq!(candidate.analysis_digest, analysis.digest().unwrap());
    assert_eq!(candidate.interactions.len(), 1);
    assert_eq!(candidate.interactions[0].maximum_value, [0; 32]);
    for mode in [
        "missing",
        "extra",
        "foreign",
        "analysis",
        "static-value",
        "zero-revision",
    ] {
        let mut changed = review.clone();
        match mode {
            "missing" => changed.actions.clear(),
            "extra" => changed.actions.push(changed.actions[0].clone()),
            "foreign" => changed.actions[0].action_digest = Digest::of("foreign"),
            "analysis" => changed.analysis_digest = Digest::of("other-analysis"),
            "static-value" => changed.actions[0].maximum_value[31] = 1,
            _ => {}
        }
        assert!(
            changed
                .compile_candidate(
                    analysis,
                    configuration,
                    policy,
                    profile_id,
                    if mode == "zero-revision" { 0 } else { 1 }
                )
                .is_err(),
            "{mode}"
        );
    }
    let mut altered_configuration = configuration.to_vec();
    altered_configuration.push(0);
    assert!(
        review
            .compile_candidate(analysis, &altered_configuration, policy, profile_id, 1)
            .is_err()
    );
    let mut altered_policy = policy.to_vec();
    altered_policy.push(0);
    assert!(
        review
            .compile_candidate(analysis, configuration, &altered_policy, profile_id, 1)
            .is_err()
    );
    let mut blocked = analysis.clone();
    blocked.interactions[0].resolution = MethodResolution::Unresolved {
        reason: UnresolvedReason::RegistrationMismatch,
    };
    assert!(
        review_for(&blocked)
            .compile_candidate(&blocked, configuration, policy, profile_id, 1)
            .is_err()
    );
    let mut repeated = analysis.clone();
    let mut second = repeated.interactions[0].clone();
    second.ordinal = 2;
    repeated.interactions.push(second);
    let complete = review_for(&repeated);
    assert_eq!(
        complete
            .compile_candidate(&repeated, configuration, policy, profile_id, 1)
            .unwrap()
            .interactions
            .len(),
        1
    );
    let mut duplicate = complete.clone();
    duplicate.actions[1] = duplicate.actions[0].clone();
    assert!(
        duplicate
            .compile_candidate(&repeated, configuration, policy, profile_id, 1)
            .is_err()
    );
    let mut conflicting = complete.clone();
    conflicting.actions[1].maximum_value[31] = 1;
    assert!(
        conflicting
            .compile_candidate(&repeated, configuration, policy, profile_id, 1)
            .is_err()
    );
    let mut permuted = complete.clone();
    permuted.actions.reverse();
    assert_eq!(
        complete
            .compile_candidate(&repeated, configuration, policy, profile_id, 1)
            .unwrap(),
        permuted
            .compile_candidate(&repeated, configuration, policy, profile_id, 1)
            .unwrap()
    );
    let mut other_scope = analysis.clone();
    other_scope.privacy_domain_id = "018f0000-0000-7000-8000-000000000900".into();
    assert!(
        review_for(&other_scope)
            .compile_candidate(&other_scope, configuration, policy, profile_id, 1)
            .is_err()
    );
    let mut with_program = review.clone();
    with_program.program = Some(CiglProgramV1 {
        program_id: "review-program".into(),
        version: 1,
        primitives: vec![
            Primitive::PushConst(ArgumentValue::Bool(true)),
            Primitive::Return(()),
        ],
        max_steps: 2,
        max_stack_depth: 1,
        max_evidence_reads: 0,
        result_type: ResultType::AllowDenyIndeterminate,
    });
    assert!(
        with_program
            .compile_candidate(analysis, configuration, policy, profile_id, 1)
            .is_ok()
    );
    with_program.program.as_mut().unwrap().max_steps = 1;
    assert!(
        with_program
            .compile_candidate(analysis, configuration, policy, profile_id, 1)
            .is_err()
    );
}
