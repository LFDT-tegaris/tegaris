//! Compose a signed method's root policy, trusted trace, reviewed profile,
//! registered targets, typed method constraints and current shared grants.
//! This is one required evidence layer; it does not reserve a nonce or send.
use super::observer::{ObservationScope, ObservedCiglTrace};
use crate::{
    provider_connection::{ConnectionRecord, now_ms},
    route_witness::VerifiedChainAnchor,
    signed_transaction::SignedTransaction,
};
use pc_policy_core::{
    cigl::{
        grants::{
            CurrentInteractionSubjects, GrantScope, InteractionSurface, MatchedInteraction,
            RequiredMethodInteraction,
        },
        profile::ValidatedMethodProfile,
        program::{CurrentStateEvidence, ProgramResult},
    },
    invocation::{
        ActiveInvocationScope, InvocationEvaluation, evaluate_invocation,
        evaluate_nested_contract_method, resolve_nested_contract_invocation,
    },
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult, canonical_bytes};

pub struct SignedMethodContext<'a> {
    pub connection: &'a ConnectionRecord,
    pub request: &'a RuntimeRequest,
    pub transaction: &'a SignedTransaction,
    pub anchor: &'a VerifiedChainAnchor,
    pub configuration_digest: &'a Digest,
    pub policy_artifact_digest: &'a Digest,
    pub policy_generation_digest: &'a Digest,
    pub route_witness_set_digest: &'a Digest,
}

pub struct MethodCiglDecision {
    request_digest: Digest,
    profile_digest: Digest,
    configuration_digest: Digest,
    policy_artifact_digest: Digest,
    policy_generation_digest: Digest,
    observation_digest: Digest,
    authority_digest: Digest,
    matches: Vec<MatchedInteraction>,
}
impl MethodCiglDecision {
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&(
            "openpc:cigl-method-decision:v1",
            &self.request_digest,
            &self.profile_digest,
            &self.configuration_digest,
            &self.policy_artifact_digest,
            &self.policy_generation_digest,
            &self.observation_digest,
            &self.authority_digest,
            &self.matches,
        ))
        .map(Digest::of)
    }
    pub fn interaction_count(&self) -> usize {
        self.matches.len()
    }
}

/// `revalidate` retains the current installation/identity/route owners, including
/// revocations. No request-supplied frame path, principal or readiness is used.
pub fn evaluate_signed_method_profile(
    observation: &ObservedCiglTrace,
    profile: &ValidatedMethodProfile,
    subjects: &impl CurrentInteractionSubjects,
    state: &impl CurrentStateEvidence,
    context: &SignedMethodContext<'_>,
    revalidate: &impl Fn() -> RuntimeResult<()>,
) -> RuntimeResult<MethodCiglDecision> {
    revalidate()?;
    crate::governed_write::validate_runtime_signed_command(context.request, context.transaction)?;
    if context.request.deployment.is_some() || context.request.invocation.is_none() {
        return Err(RuntimeError::Denied);
    }
    let authorization = subjects.invocation_authorization()?;
    let facts = authorization.facts();
    let scope = ActiveInvocationScope {
        policy_generation_digest: context.policy_generation_digest,
        tenant_id: &facts.participant_id,
        privacy_domain_id: &facts.privacy_domain_id,
        workload_id: &facts.workload_id,
    };
    profile.validate_scope(
        context.configuration_digest,
        context.policy_artifact_digest,
        &scope,
    )?;
    let definition = profile.definition();
    let observation_scope = ObservationScope {
        profile_digest: &profile.grants().profile_digest,
        route_witness_set_digest: context.route_witness_set_digest,
    };
    let now = now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let now_ns = now
        .checked_mul(1_000_000)
        .ok_or(RuntimeError::InvalidInput)?;
    subjects.require_current(now_ns)?;
    observation.validate(
        context.connection,
        context.request,
        context.transaction,
        context.anchor,
        &observation_scope,
        now,
    )?;
    if observation.trace().steps() == 0
        || observation.trace().inspection().limits() != definition.limits
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let frames = observation.trace().inspection().frames();
    let root = frames.first().ok_or(RuntimeError::ResponseWithheld)?;
    let code_at = |address: &[u8; 20]| observation.code_digest(address).cloned();
    let (root_policy, root_invocation) = resolve_nested_contract_invocation(
        std::slice::from_ref(profile.root_method()?),
        &definition.root_contract_method_policy_id,
        *root.target(),
        root.input().to_vec(),
        code_at,
    )?;
    if context.request.invocation.as_ref() != Some(&root_invocation) {
        return Err(RuntimeError::GenerationMismatch);
    }
    let evaluation = InvocationEvaluation {
        request_method: &context.request.method,
        request_class: context.request.class,
        request_digest: &context.request.request_digest,
        active_policy_generation: context.policy_generation_digest,
        now_ms: now,
    };
    evaluate_invocation(&root_invocation, root_policy, authorization, &evaluation)?;
    if let Some(program) = profile.program() {
        match program.evaluate_invocation(&root_invocation, root_policy, state) {
            ProgramResult::Allow => {}
            ProgramResult::Deny => return Err(RuntimeError::Denied),
            ProgramResult::Indeterminate(_) => return Err(RuntimeError::ResponseWithheld),
        }
    }
    let mut required = Vec::with_capacity(frames.len() - 1);
    for frame in &frames[1..] {
        let (rule, method) = profile.reviewed_call(
            *frame.caller(),
            frame.kind(),
            *frame.target(),
            frame.input(),
        )?;
        if frame.message_value() > &rule.maximum_value {
            return Err(RuntimeError::Denied);
        }
        let (method, invocation) = resolve_nested_contract_invocation(
            std::slice::from_ref(method),
            &rule.contract_method_policy_id,
            *frame.target(),
            frame.input().to_vec(),
            code_at,
        )?;
        evaluate_nested_contract_method(&invocation, method, authorization, &evaluation)?;
        required.push(RequiredMethodInteraction {
            interaction_id: &rule.interaction_id,
            runtime_binding_id: method.configured_identity()?.runtime_binding_id(),
            selector: method.selector(),
        });
    }
    let matches = profile.grants().match_required(
        &required,
        &GrantScope {
            profile_id: &definition.profile_id,
            profile_revision: definition.revision,
            profile_digest: &profile.grants().profile_digest,
            participant_id: &facts.participant_id,
            privacy_domain_id: &facts.privacy_domain_id,
            surface: InteractionSurface::RawSubmission,
        },
        subjects,
        now_ns,
    )?;
    revalidate()?;
    let completed = now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    subjects.require_current(
        completed
            .checked_mul(1_000_000)
            .ok_or(RuntimeError::InvalidInput)?,
    )?;
    observation.validate(
        context.connection,
        context.request,
        context.transaction,
        context.anchor,
        &observation_scope,
        completed,
    )?;
    Ok(MethodCiglDecision {
        request_digest: context.request.request_digest.clone(),
        profile_digest: profile.grants().profile_digest.clone(),
        configuration_digest: context.configuration_digest.clone(),
        policy_artifact_digest: context.policy_artifact_digest.clone(),
        policy_generation_digest: context.policy_generation_digest.clone(),
        observation_digest: observation.digest()?,
        authority_digest: Digest::of(canonical_bytes(facts)?),
        matches,
    })
}
