//! Live, non-granting analysis from the same pinned observation as enforcement.
//! An administrator cannot supply frame paths, target resolution or readiness.
use super::{
    authorization::SignedMethodContext,
    observer::{ObservationScope, ObservedCiglTrace},
};
use crate::provider_connection::now_ms;
use pc_policy_core::{
    cigl::{
        analysis::{AnalyzedInteraction, MethodAnalysisIndex, MethodAnalysisV1},
        grants::CurrentInteractionSubjects,
    },
    invocation::{
        ActiveInvocationScope, InvocationEvaluation, ValidatedInvocationPolicy,
        evaluate_invocation, resolve_nested_contract_invocation,
    },
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};

pub mod receipt;

/// Only this live producer constructs it. Persist its document through the
/// authenticated analysis owner; deserializing the document cannot recreate it.
pub struct ObservedMethodAnalysis {
    document: MethodAnalysisV1,
    transaction_hash: [u8; 32],
    observed_at_ms: u64,
}
impl ObservedMethodAnalysis {
    pub fn document(&self) -> &MethodAnalysisV1 {
        &self.document
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.document.digest()
    }
}

pub struct AnalysisSources<'a> {
    pub configuration_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    pub root_contract_method_policy_id: &'a str,
    /// Current installed profile or governed analysis-job settings digest.
    /// It must be the exact source retained by the acquisition callback.
    pub observation_context_digest: &'a Digest,
}

pub fn analyze_signed_method(
    observation: &ObservedCiglTrace,
    sources: &AnalysisSources<'_>,
    subjects: &impl CurrentInteractionSubjects,
    context: &SignedMethodContext<'_>,
    revalidate: &impl Fn() -> RuntimeResult<()>,
) -> RuntimeResult<ObservedMethodAnalysis> {
    revalidate()?;
    crate::governed_write::validate_runtime_signed_command(context.request, context.transaction)?;
    if context.request.deployment.is_some()
        || context.request.invocation.is_none()
        || observation.trace().steps() == 0
    {
        return Err(RuntimeError::Denied);
    }
    let authorization = subjects.invocation_authorization()?;
    let facts = authorization.facts();
    let now = now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    subjects.require_current(
        now.checked_mul(1_000_000)
            .ok_or(RuntimeError::InvalidInput)?,
    )?;
    let observation_scope = ObservationScope {
        profile_digest: sources.observation_context_digest,
        route_witness_set_digest: context.route_witness_set_digest,
    };
    observation.validate(
        context.connection,
        context.request,
        context.transaction,
        context.anchor,
        &observation_scope,
        now,
    )?;
    let policies = ValidatedInvocationPolicy::load_active(
        sources.configuration_bytes,
        context.configuration_digest,
        sources.policy_bytes,
        context.policy_artifact_digest,
        &ActiveInvocationScope {
            policy_generation_digest: context.policy_generation_digest,
            tenant_id: &facts.participant_id,
            privacy_domain_id: &facts.privacy_domain_id,
            workload_id: &facts.workload_id,
        },
    )?;
    let frames = observation.trace().inspection().frames();
    let root = frames.first().ok_or(RuntimeError::ResponseWithheld)?;
    let code_at = |address: &[u8; 20]| observation.code_digest(address).cloned();
    let (root_policy, invocation) = resolve_nested_contract_invocation(
        &policies,
        sources.root_contract_method_policy_id,
        *root.target(),
        root.input().to_vec(),
        code_at,
    )?;
    if context.request.invocation.as_ref() != Some(&invocation) {
        return Err(RuntimeError::GenerationMismatch);
    }
    evaluate_invocation(
        &invocation,
        root_policy,
        authorization,
        &InvocationEvaluation {
            request_method: &context.request.method,
            request_class: context.request.class,
            request_digest: &context.request.request_digest,
            active_policy_generation: context.policy_generation_digest,
            now_ms: now,
        },
    )?;
    let methods = MethodAnalysisIndex::new(root_policy, &policies)?;
    let mut interactions = Vec::with_capacity(frames.len() - 1);
    for frame in &frames[1..] {
        interactions.push(AnalyzedInteraction {
            ordinal: frame.ordinal,
            parent: frame.parent.ok_or(RuntimeError::ResponseWithheld)?,
            depth: frame.depth,
            call_kind: frame.kind,
            caller: frame.caller,
            target: frame.target,
            execution_address: frame.execution_address,
            selector: frame.input.get(..4).and_then(|v| v.try_into().ok()),
            input_digest: Digest::of(&frame.input),
            message_value_digest: Digest::of(frame.message_value),
            code_digest: observation.code_digest(&frame.target)?.clone(),
            failed: frame.failed,
            resolution: methods.resolve(frame.kind, frame.target, &frame.input, code_at),
        });
    }
    let document = MethodAnalysisV1 {
        schema_version: "1.0".into(),
        participant_id: facts.participant_id.clone(),
        privacy_domain_id: facts.privacy_domain_id.clone(),
        workload_id: facts.workload_id.clone(),
        root_contract_method_policy_id: sources.root_contract_method_policy_id.into(),
        root_runtime_binding_id: root_policy
            .configured_identity()?
            .runtime_binding_id()
            .into(),
        configuration_digest: context.configuration_digest.clone(),
        policy_artifact_digest: context.policy_artifact_digest.clone(),
        policy_generation_digest: context.policy_generation_digest.clone(),
        request_digest: context.request.request_digest.clone(),
        authority_digest: Digest::of(canonical_bytes(facts)?),
        observation_digest: observation.digest()?,
        observation_context_digest: sources.observation_context_digest.clone(),
        route_witness_set_digest: context.route_witness_set_digest.clone(),
        anchor_digest: context.anchor.anchor().semantic_digest()?,
        limits: observation.trace().inspection().limits(),
        interactions,
    };
    document.validate()?;
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
    Ok(ObservedMethodAnalysis {
        document,
        transaction_hash: *context.transaction.hash(),
        observed_at_ms: completed,
    })
}
