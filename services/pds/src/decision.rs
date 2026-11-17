use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use pc_runtime_types::{
    BrokerCapability, DecisionEffect, Digest, PURPOSE_BROKER_CAPABILITY_V1, PurposeSigner,
    RuntimeDecision, RuntimeError, RuntimeRequest, RuntimeResult, canonical_bytes,
};
use serde::Serialize;

use crate::{
    IdentityAssertionEvidence, IdentityAssertionVerifier, LocalDecisionLease, LocalDecisionOwner,
    LocalDecisionState, invocation,
};

/// Request data and untrusted cryptographic evidence only. Authority, active
/// generations, fact currentness, capacity and time are never request fields.
#[derive(Clone, Debug, Serialize)]
pub struct EvaluationInput {
    pub request: RuntimeRequest,
    pub identity_assertion: IdentityAssertionEvidence,
}

struct RuntimeOwner {
    identity_verifier: IdentityAssertionVerifier,
    state: Option<Arc<dyn LocalDecisionOwner>>,
}

pub struct PolicyDecisionService {
    capability_signer: PurposeSigner,
    owner: Option<RuntimeOwner>,
    sequence: AtomicU64,
    maximum_capability_lifetime_ms: u64,
}

impl PolicyDecisionService {
    /// An unconnected service is fail-closed. Policy artifacts alone are not
    /// authority to forward a workload request.
    pub fn new(key: [u8; 32], maximum_capability_lifetime_ms: u64) -> RuntimeResult<Self> {
        if maximum_capability_lifetime_ms == 0 || maximum_capability_lifetime_ms > 60_000 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            capability_signer: PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, key)?,
            owner: None,
            sequence: AtomicU64::new(1),
            maximum_capability_lifetime_ms,
        })
    }

    pub fn with_runtime_owner(
        key: [u8; 32],
        maximum_capability_lifetime_ms: u64,
        identity_verifier: IdentityAssertionVerifier,
        owner: Arc<dyn LocalDecisionOwner>,
    ) -> RuntimeResult<Self> {
        let mut service =
            Self::with_identity_trust(key, maximum_capability_lifetime_ms, identity_verifier)?;
        service
            .owner
            .as_mut()
            .ok_or(RuntimeError::RuntimeUnavailable)?
            .state = Some(owner);
        Ok(service)
    }

    /// The shared signer/verifier can serve request-local owners captured by the
    /// authenticated transport adapter. No default owner means plain evaluate
    /// remains fail-closed; request data cannot select a replacement owner.
    pub fn with_identity_trust(
        key: [u8; 32],
        maximum_capability_lifetime_ms: u64,
        identity_verifier: IdentityAssertionVerifier,
    ) -> RuntimeResult<Self> {
        let mut service = Self::new(key, maximum_capability_lifetime_ms)?;
        service.owner = Some(RuntimeOwner {
            identity_verifier,
            state: None,
        });
        Ok(service)
    }

    pub fn evaluate(&self, input: &EvaluationInput) -> RuntimeResult<RuntimeDecision> {
        self.evaluate_with_clock(input, &wall_clock)
    }

    /// Trusted in-process adapter entry: the owner captures this request's
    /// transport-authenticated peer and durable local state. It is never decoded
    /// from request bytes, headers, or caller-provided readiness metadata.
    pub fn evaluate_for(
        &self,
        input: &EvaluationInput,
        owner: &dyn LocalDecisionOwner,
    ) -> RuntimeResult<RuntimeDecision> {
        self.evaluate_owned_with_clock(input, Some(owner), &wall_clock)
    }

    pub(crate) fn evaluate_with_clock(
        &self,
        input: &EvaluationInput,
        clock: &dyn Fn() -> RuntimeResult<u64>,
    ) -> RuntimeResult<RuntimeDecision> {
        self.evaluate_owned_with_clock(
            input,
            self.owner.as_ref().and_then(|o| o.state.as_deref()),
            clock,
        )
    }

    pub(crate) fn evaluate_owned_with_clock(
        &self,
        input: &EvaluationInput,
        state_owner: Option<&dyn LocalDecisionOwner>,
        clock: &dyn Fn() -> RuntimeResult<u64>,
    ) -> RuntimeResult<RuntimeDecision> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let decision_id = format!("local-decision-{sequence:016x}");
        let input_digest = Digest::of(canonical_bytes(input)?);
        let unbound = |error| denied(&decision_id, &input_digest, &Digest::of([]), false, error);
        input
            .request
            .validate_digest()
            .map_err(|_| RuntimeError::InvalidInput)?;
        let Some(owner) = &self.owner else {
            return Ok(unbound(RuntimeError::RuntimeUnavailable));
        };
        let Some(state_owner) = state_owner else {
            return Ok(unbound(RuntimeError::RuntimeUnavailable));
        };
        let mut lease = match state_owner.acquire(&input.request) {
            Ok(lease) => lease,
            Err(error) => return Ok(unbound(error)),
        };
        let state = lease.state().clone();
        if state.decision_id.is_empty()
            || state.decision_id.len() > 128
            || !state
                .decision_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
        {
            return Ok(unbound(RuntimeError::RuntimeUnavailable));
        }
        let decision_id = state.decision_id.clone();
        let input_digest = Digest::of(canonical_bytes(&(input, &state))?);
        let denial = |error| {
            denied(
                &decision_id,
                &input_digest,
                &state.bindings.active_generation_digest,
                state.evidence.high(),
                error,
            )
        };
        let now_ms = clock()?;
        let verified =
            match owner
                .identity_verifier
                .verify(&input.identity_assertion, &state.identity, now_ms)
            {
                Ok(verified) => verified,
                Err(_) => {
                    return Ok(commit_or_withhold(
                        lease.as_mut(),
                        denial(RuntimeError::InvalidAuthorization),
                    ));
                }
            };
        if let Err(error) = validate_state(input, &state, now_ms) {
            return Ok(commit_or_withhold(lease.as_mut(), denial(error)));
        }
        if let Err(error) = lease.revalidate() {
            return Ok(commit_or_withhold(lease.as_mut(), denial(error)));
        }
        // Verification and owner checks may cross a deadline or freshness edge.
        let issued_at_ms = clock()?;
        let expires_at_ms = input
            .request
            .deadline_at_ms
            .min(verified.expires_at_ms())
            .min(state.valid_until_ms)
            .min(issued_at_ms.saturating_add(self.maximum_capability_lifetime_ms));
        if issued_at_ms < now_ms || expires_at_ms <= issued_at_ms {
            return Ok(commit_or_withhold(
                lease.as_mut(),
                denial(RuntimeError::BudgetExhausted),
            ));
        }
        let bindings = &state.bindings;
        let provider_profile_id = bindings.eligible_provider_profile_ids[0].clone();
        let decision_digest = Digest::of(canonical_bytes(&(
            &decision_id,
            DecisionEffect::AllowForward,
            &input_digest,
            &bindings.active_generation_digest,
            &provider_profile_id,
        ))?);
        let capability = BrokerCapability {
            capability_id: format!("capability:{}", decision_digest.as_str()),
            request_digest: input.request.request_digest.clone(),
            decision_digest: decision_digest.clone(),
            target_id: bindings.target_id.clone(),
            active_generation_digest: bindings.active_generation_digest.clone(),
            route_profile_digest: bindings.route_profile_digest.clone(),
            provider_profile_id,
            provider_profile_digest: bindings.provider_profile_digest.clone(),
            request_class: input.request.class,
            issued_at_ms,
            expires_at_ms,
            remaining_budget_ms: expires_at_ms - issued_at_ms,
        };
        let decision = RuntimeDecision {
            decision_id,
            effect: DecisionEffect::AllowForward,
            pc_code: "PC-RUNTIME-0000".into(),
            active_generation_digest: bindings.active_generation_digest.clone(),
            decision_input_digest: input_digest,
            decision_digest,
            capability: Some(self.capability_signer.sign(capability)?),
            protective_degradation: state.evidence.high(),
        };
        Ok(commit_or_withhold(lease.as_mut(), decision))
    }

    #[must_use]
    pub fn capability_verifier_sec1(&self) -> Vec<u8> {
        self.capability_signer.verifier().sec1_bytes()
    }
}

fn wall_clock() -> RuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}

fn commit_or_withhold(
    lease: &mut dyn LocalDecisionLease,
    decision: RuntimeDecision,
) -> RuntimeDecision {
    match lease.commit(&decision) {
        Ok(()) => decision,
        Err(error) => denied(
            &decision.decision_id,
            &decision.decision_input_digest,
            &decision.active_generation_digest,
            decision.protective_degradation,
            error,
        ),
    }
}

fn validate_state(
    input: &EvaluationInput,
    state: &LocalDecisionState,
    now_ms: u64,
) -> RuntimeResult<()> {
    if state.request_digest != input.request.request_digest || now_ms >= state.valid_until_ms {
        return Err(RuntimeError::GenerationMismatch);
    }
    if now_ms < input.request.received_at_ms || now_ms >= input.request.deadline_at_ms {
        return Err(RuntimeError::BudgetExhausted);
    }
    let bindings = &state.bindings;
    let authorization = state.authorization.facts();
    // A generic identity assertion is not a governed invocation approval or a
    // verified step-up receipt. No raw proof-shaped record can grant that power.
    if state.emergency_deny
        || authorization.approval.is_some()
        || authorization.webauthn.is_some()
        || state.identity.actor_kind != 1
        || state.identity.sender_binding_kind != 2
        || bindings.participant_id != authorization.participant_id
        || bindings.privacy_domain_id != authorization.privacy_domain_id
        || bindings.workload_id != authorization.workload_id
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    if input.request.visibility.is_some() {
        if state.deployment_policy.is_some() {
            return Err(RuntimeError::Denied);
        }
        state
            .visibility_read
            .as_ref()
            .ok_or(RuntimeError::Denied)?
            .validate(
                &input.request,
                &bindings.policy_generation_digest,
                authorization,
            )?;
    } else if state.visibility_read.is_some() {
        return Err(RuntimeError::Denied);
    } else if input.request.deployment.is_some() {
        state
            .deployment_policy
            .as_ref()
            .ok_or(RuntimeError::Denied)?
            .evaluate(
                &input.request,
                &state.authorization,
                &bindings.policy_generation_digest,
                now_ms,
            )?;
    } else {
        if state.deployment_policy.is_some() {
            return Err(RuntimeError::Denied);
        }
        invocation::validate_active_policy_set(&state.active_invocation_policies)?;
        let policy = invocation::select_active_policy(
            &state.active_invocation_policies,
            &input.request,
            bindings,
        )?;
        invocation::evaluate_invocation(
            input
                .request
                .invocation
                .as_ref()
                .ok_or(RuntimeError::Denied)?,
            policy,
            &state.authorization,
            &invocation::InvocationEvaluation {
                request_method: &input.request.method,
                request_class: input.request.class,
                request_digest: &input.request.request_digest,
                active_policy_generation: &bindings.policy_generation_digest,
                now_ms,
            },
        )?;
    }
    if bindings.active_generation_digest != bindings.observed_generation_digest
        || bindings.policy_generation_digest != bindings.expected_policy_generation_digest
        || bindings.fact_generation_digest != bindings.expected_fact_generation_digest
        || bindings.route_profile_digest != bindings.expected_route_profile_digest
        || bindings.provider_profile_digest != bindings.expected_provider_profile_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    if bindings.eligible_provider_profile_ids.len() != 1 {
        return Err(RuntimeError::ConflictingRoute);
    }
    if state.evidence.critical() {
        return Err(RuntimeError::EvidenceCapacity);
    }
    Ok(())
}

fn denied(
    id: &str,
    input_digest: &Digest,
    generation: &Digest,
    protective_degradation: bool,
    error: RuntimeError,
) -> RuntimeDecision {
    let pc_code = error.pc_code().to_owned();
    let decision_digest = Digest::of(
        canonical_bytes(&(id, DecisionEffect::DenyTerminal, input_digest, &pc_code))
            .expect("closed denial tuple is serializable"),
    );
    RuntimeDecision {
        decision_id: id.into(),
        effect: DecisionEffect::DenyTerminal,
        pc_code,
        active_generation_digest: generation.clone(),
        decision_input_digest: input_digest.clone(),
        decision_digest,
        capability: None,
        protective_degradation,
    }
}
