//! Request-captured access to actual target-local custody. The capture is Send
//! and owns no synchronous guard. Its short-lived lease reconstructs admitted
//! owners under the observed activation/freshness fence; it is never retained
//! across provider I/O. Admission alone does not produce a PDS allow decision.

use crate::{
    ActiveCapsuleLease, RequestTraceId, RuntimeAgent, WorkloadPeer,
    decision_evidence::{DecisionEvidenceReservation, DecisionEvidenceStore},
    ext_proc::EnvoyGeneration,
    fact_custody::{FactArtifactAdmission, InstalledFactState},
    fact_lease::{FactLease, FactLeaseReader},
    identity_custody::IdentityArtifactAdmission,
    identity_state::{
        InstalledWorkloadIdentities, RuntimeInvocationAuthorityRequest, WorkloadAuthorization,
    },
    invocation_custody::InvocationArtifactAdmission,
    invocation_profile_custody::InvocationProfileAdmission,
    mrpc_custody::MrpcProfileAdmission,
    request_decode::{DecodedProtectedRequest, RequestDecodeLimits},
    request_route::{RequestRouteEvidence, RouteEvidenceTrust},
    routing_custody::{AdmittedRequestRoute, InstalledRoutingAuthority, RoutingArtifactAdmission},
};
use openpc_multi_rpc::runtime_profile::MrpcRuntimeProfile;
use openpc_pds::{
    EvaluationInput, IdentityAssertionEvidence, IdentityAssertionVerifier,
    ValidatedInvocationPolicy,
};
use pc_policy_core::semantics::FactReference;
use pc_policy_core::{
    invocation::{ActiveInvocationScope, select_active_policy_in_scope},
    invocation_profile::InvocationProfileMaterial,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Installed by the target bootstrap from the owning trust roots and scoped
/// readers. No request parser accepts this object or any of its owner handles.
pub struct TargetState {
    #[cfg(test)]
    evaluation_test_gate: std::sync::OnceLock<Arc<tokio::sync::RwLock<()>>>,
    #[cfg(test)]
    revalidation_attempts: std::sync::atomic::AtomicUsize,
    agent: Arc<RuntimeAgent>,
    protected_class_set: Digest,
    privacy_domain_id: String,
    identity: Arc<IdentityArtifactAdmission>,
    identity_assertions: Arc<IdentityAssertionVerifier>,
    invocation: Arc<InvocationArtifactAdmission>,
    invocation_profile: Arc<InvocationProfileAdmission>,
    facts: Arc<FactArtifactAdmission>,
    fact_reader: FactLeaseReader,
    mrpc: Arc<MrpcProfileAdmission>,
    routing: Arc<RoutingArtifactAdmission>,
    route_evidence_trust: RouteEvidenceTrust,
    evidence: Arc<DecisionEvidenceStore>,
}

pub struct TargetStateOwners {
    pub agent: Arc<RuntimeAgent>,
    pub identity: Arc<IdentityArtifactAdmission>,
    pub identity_assertions: Arc<IdentityAssertionVerifier>,
    pub invocation: Arc<InvocationArtifactAdmission>,
    pub invocation_profile: Arc<InvocationProfileAdmission>,
    pub facts: Arc<FactArtifactAdmission>,
    pub fact_reader: FactLeaseReader,
    pub mrpc: Arc<MrpcProfileAdmission>,
    pub routing: Arc<RoutingArtifactAdmission>,
    pub route_evidence_trust: RouteEvidenceTrust,
    pub evidence: Arc<DecisionEvidenceStore>,
}

/// The peer and Envoy observation originate at the authenticated transport.
/// Reusing a request digest cannot select another capture's identity or capsule.
pub struct CapturedTargetState {
    owner: Arc<TargetState>,
    peer: WorkloadPeer,
    generation: EnvoyGeneration,
    capsule_digest: Digest,
    trace: RequestTraceId,
}

/// Exactly one decoded workload request and its externally issued identity
/// assertion. Neither a digest lookup nor a later caller body can replace them.
pub struct CapturedTargetRequest {
    context: CapturedTargetState,
    decoded: Arc<DecodedProtectedRequest>,
    assertion: IdentityAssertionEvidence,
}

pub struct CapturedRequestLease<'a> {
    state: TargetStateLease<'a>,
    request: &'a CapturedTargetRequest,
}

/// Synchronous authorization/fact/evidence fence for the decision owner. This
/// holds no provider future and must be dropped before asynchronous dispatch.
/// Routing and disclosure still require their independently admitted owners.
pub struct CapturedDecisionFence<'a> {
    request: CapturedRequestLease<'a>,
    authorization: WorkloadAuthorization,
    facts: FactLease,
    evidence: DecisionEvidenceReservation<'a>,
    valid_until_ns: u64,
}

pub struct TargetStateLease<'a> {
    active: ActiveCapsuleLease<'a>,
    captured: &'a CapturedTargetState,
    identities: InstalledWorkloadIdentities,
    policies: Vec<ValidatedInvocationPolicy>,
    deployment_policies: Vec<pc_policy_core::deployment_policy::ValidatedDeploymentPolicy>,
    cigl_settings: pc_policy_core::cigl::settings::InstalledCiglSettings,
    cigl_profiles: Vec<pc_policy_core::cigl::profile::ValidatedMethodProfile>,
    rpc_policies: Vec<pc_policy_core::rpc_policy::RpcSurfacePolicy>,
    pub(crate) visibility_policies: Vec<pc_policy_core::visibility_policy::VisibilityPolicy>,
    pub(crate) visibility_resources:
        Vec<pc_policy_core::visibility_policy::AdmittedVisibilityResource>,
    invocation_profile: InvocationProfileMaterial,
    facts: InstalledFactState,
    pub(crate) required_facts: Vec<FactReference>,
    fact_conditions: Vec<pc_policy_core::fact_condition::FactCondition>,
    mrpc: MrpcRuntimeProfile,
    routing: InstalledRoutingAuthority,
}

impl TargetState {
    #[cfg(test)]
    pub(crate) fn revalidation_attempts(&self) -> usize {
        self.revalidation_attempts
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_evaluation_test_gate(&self, gate: Arc<tokio::sync::RwLock<()>>) {
        self.evaluation_test_gate.set(gate).unwrap();
    }

    pub(crate) async fn coordinate_evaluation(
        &self,
        deadline_at_ms: u64,
    ) -> RuntimeResult<Option<crate::target_disposition::OwnedResponseReleasePermit>> {
        #[cfg(test)]
        if let Some(gate) = self.evaluation_test_gate.get() {
            return crate::target_disposition::OwnedResponseReleasePermit::acquire(
                gate.clone(),
                deadline_at_ms,
            )
            .await
            .map(Some);
        }
        self.agent
            .coordinate_response_release_owned(deadline_at_ms)
            .await
    }

    pub(crate) async fn coordinate_response_release(
        &self,
        deadline_at_ms: u64,
    ) -> RuntimeResult<Option<crate::target_disposition::ResponseReleasePermit<'_>>> {
        self.agent.coordinate_response_release(deadline_at_ms).await
    }

    /// Source reads in a mixed capsule use the same signed policy admission
    /// and exact current Fact references as its protected invocation owner.
    /// Drop this lease before provider I/O and reacquire it for final release.
    pub fn acquire_source_policies(
        &self,
        active: &ActiveCapsuleLease<'_>,
        peer: &WorkloadPeer,
        budget_ms: u64,
    ) -> RuntimeResult<(crate::indexer_custody::InstalledIndexerPolicies, FactLease)> {
        let (policies, _) = self
            .invocation
            .admit_policies(active.capsule(), active.artifacts()?)?;
        let required =
            policies.required_facts_for(peer, &self.privacy_domain_id, active.capsule())?;
        let facts = if active.capsule().policy_fact_state_digest
            == Digest::of(crate::indexer_custody::NO_FACT_PUBLICATION)
        {
            if !required.is_empty() {
                return Err(RuntimeError::InvalidAuthorization);
            }
            InstalledFactState::no_publication(active.capsule())?
        } else {
            self.facts
                .admit_fact_state(active.capsule(), active.artifacts()?)?
                .0
        };
        let lease = acquire_fact_references(
            active,
            &facts,
            &self.fact_reader,
            required,
            &[],
            (peer.participant_id(), &self.privacy_domain_id),
            budget_ms,
        )?;
        Ok((policies.into_indexer_policies(), lease))
    }

    pub fn new(
        protected_class_set: Digest,
        privacy_domain_id: String,
        owners: TargetStateOwners,
    ) -> RuntimeResult<Arc<Self>> {
        crate::capsule::digest(&protected_class_set)?;
        crate::capsule::text(&privacy_domain_id, 160)?;
        Ok(Arc::new(Self {
            #[cfg(test)]
            evaluation_test_gate: std::sync::OnceLock::new(),
            #[cfg(test)]
            revalidation_attempts: std::sync::atomic::AtomicUsize::new(0),
            agent: owners.agent,
            protected_class_set,
            privacy_domain_id,
            identity: owners.identity,
            identity_assertions: owners.identity_assertions,
            invocation: owners.invocation,
            invocation_profile: owners.invocation_profile,
            facts: owners.facts,
            fact_reader: owners.fact_reader,
            mrpc: owners.mrpc,
            routing: owners.routing,
            route_evidence_trust: owners.route_evidence_trust,
            evidence: owners.evidence,
        }))
    }

    pub fn capture(
        self: &Arc<Self>,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        trace: &RequestTraceId,
    ) -> RuntimeResult<CapturedTargetState> {
        let active = self.agent.acquire_observed_capsule(
            &self.protected_class_set,
            generation,
            wall_clock_ns()?,
        )?;
        self.evidence.validate_scope(
            peer.participant_id(),
            &self.privacy_domain_id,
            &active.capsule().target_runtime_id,
        )?;
        Ok(CapturedTargetState {
            owner: self.clone(),
            peer: peer.clone(),
            generation: generation.clone(),
            capsule_digest: active.capsule().digest()?,
            trace: trace.clone(),
        })
    }
}

#[path = "operation_status_owner.rs"]
mod operation_status;
#[path = "submission_recovery.rs"]
mod recovery;
pub use recovery::CapturedRecovery;

impl CapturedTargetState {
    pub fn bind_deployment_request(
        self,
        body: &[u8],
        limits: RequestDecodeLimits<'_>,
        assertion: IdentityAssertionEvidence,
        worker_public_key: &[u8],
    ) -> RuntimeResult<CapturedTargetRequest> {
        if assertion.payload_cbor.is_empty()
            || assertion.payload_cbor.len() > 262_144
            || assertion.cose_sign1.is_empty()
            || assertion.cose_sign1.len() > 263_168
        {
            return Err(RuntimeError::InvalidInput);
        }
        let decoded = {
            let lease = self.acquire()?;
            let decoded = DecodedProtectedRequest::decode_deployment(
                body,
                lease.deployment_policies(),
                worker_public_key,
                limits,
                wall_clock_ns()? / 1_000_000,
            )?;
            lease
                .invocation_profile
                .capability_for_method(&decoded.request().method)?;
            Arc::new(decoded)
        };
        Ok(CapturedTargetRequest {
            context: self,
            decoded,
            assertion,
        })
    }
    pub fn bind_request(
        self,
        body: &[u8],
        limits: RequestDecodeLimits<'_>,
        assertion: IdentityAssertionEvidence,
    ) -> RuntimeResult<CapturedTargetRequest> {
        if assertion.payload_cbor.is_empty()
            || assertion.payload_cbor.len() > 262_144
            || assertion.cose_sign1.is_empty()
            || assertion.cose_sign1.len() > 263_168
        {
            return Err(RuntimeError::InvalidInput);
        }
        let decoded = {
            let lease = self.acquire()?;
            Arc::new(lease.decode(body, limits)?)
        };
        Ok(CapturedTargetRequest {
            context: self,
            decoded,
            assertion,
        })
    }

    pub fn acquire(&self) -> RuntimeResult<TargetStateLease<'_>> {
        let active = self.owner.agent.acquire_observed_capsule(
            &self.owner.protected_class_set,
            &self.generation,
            wall_clock_ns()?,
        ).inspect_err(|error| {
            eprintln!("{}", serde_json::json!({"event":"protected_request_rejected","stage":"current_capsule","pcCode":error.pc_code(),"traceId":self.trace.as_str()}));
        })?;
        if active.capsule().digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        let capsule = active.capsule();
        let artifacts = active.artifacts()?;
        let (identities, _) = self.owner.identity.admit_identity(capsule, artifacts)?;
        let (invocation, _) = self.owner.invocation.admit_policies(capsule, artifacts)?;
        let policies = invocation
            .policies_for(&self.peer, &self.owner.privacy_domain_id, capsule)?
            .to_vec();
        let deployment_policies = invocation
            .deployment_policies_for(&self.peer, &self.owner.privacy_domain_id, capsule)?
            .to_vec();
        for policy in &policies {
            policy.configured_identity()?;
        }
        let required_facts = invocation
            .required_facts_for(&self.peer, &self.owner.privacy_domain_id, capsule)?
            .to_vec();
        let facts = if capsule.policy_fact_state_digest
            == Digest::of(crate::indexer_custody::NO_FACT_PUBLICATION)
        {
            if !required_facts.is_empty() {
                return Err(RuntimeError::InvalidAuthorization);
            }
            InstalledFactState::no_publication(capsule)?
        } else {
            self.owner.facts.admit_fact_state(capsule, artifacts)?.0
        };
        let (invocation_profile, _) = self
            .owner
            .invocation_profile
            .admit_profile(capsule, artifacts)?;
        let (mrpc, _) = self.owner.mrpc.admit_profile(capsule, artifacts)?;
        let (routing, _) = self.owner.routing.admit(capsule, artifacts)?;
        active.revalidate(wall_clock_ns()?)?;
        Ok(TargetStateLease {
            active,
            captured: self,
            identities,
            policies,
            deployment_policies,
            cigl_profiles: invocation.cigl_profiles,
            cigl_settings: invocation.cigl_settings,
            rpc_policies: invocation.rpc_policies,
            visibility_policies: invocation.visibility_policies,
            visibility_resources: invocation.visibility_resources,
            invocation_profile,
            facts,
            required_facts,
            fact_conditions: invocation.fact_conditions,
            mrpc,
            routing,
        })
    }

    pub fn evidence(&self) -> &DecisionEvidenceStore {
        &self.owner.evidence
    }
}

impl CapturedTargetRequest {
    pub(crate) async fn coordinate_revalidation(
        &self,
    ) -> RuntimeResult<Option<crate::target_disposition::OwnedResponseReleasePermit>> {
        #[cfg(test)]
        self.context
            .owner
            .revalidation_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.context
            .owner
            .coordinate_evaluation(self.decoded.request().deadline_at_ms)
            .await
    }

    pub(crate) fn peer(&self) -> &WorkloadPeer {
        &self.context.peer
    }
    pub fn acquire_decision_fence(&self) -> RuntimeResult<CapturedDecisionFence<'_>> {
        let request = self.acquire()?;
        let authorization = request.authorize_invocation()?;
        let facts = request.acquire_required_facts()?;
        let valid_until_ns = facts.snapshots().iter().try_fold(
            authorization.valid_until_ns,
            |until, snapshot| {
                let fresh_until_ns = u64::try_from(snapshot.fresh_until_ms)
                    .ok()
                    .and_then(|ms| ms.checked_mul(1_000_000))
                    .ok_or(RuntimeError::ExpiredAuthorization)?;
                Ok::<_, RuntimeError>(until.min(fresh_until_ns))
            },
        )?;
        let evidence = self.evidence().reserve_for_trace_until(
            request.state().active(),
            self.decoded.request(),
            self.trace(),
            valid_until_ns,
            wall_clock_ns()?,
        )?;
        let fence = CapturedDecisionFence {
            request,
            authorization,
            facts,
            evidence,
            valid_until_ns,
        };
        fence.revalidate()?;
        Ok(fence)
    }
    pub fn acquire(&self) -> RuntimeResult<CapturedRequestLease<'_>> {
        self.revalidate_time()?;
        let state = self.context.acquire()?;
        self.revalidate_time()?;
        let lease = CapturedRequestLease {
            state,
            request: self,
        };
        lease.revalidate_identity()?;
        Ok(lease)
    }
    pub fn evaluation(&self) -> EvaluationInput {
        EvaluationInput {
            request: self.decoded.request().clone(),
            identity_assertion: self.assertion.clone(),
        }
    }
    pub fn decoded(&self) -> &Arc<DecodedProtectedRequest> {
        &self.decoded
    }
    pub fn evidence(&self) -> &DecisionEvidenceStore {
        self.context.evidence()
    }
    pub fn trace(&self) -> &RequestTraceId {
        &self.context.trace
    }
    fn revalidate_time(&self) -> RuntimeResult<()> {
        let now_ms = wall_clock_ns()? / 1_000_000;
        let request = self.decoded.request();
        if now_ms < request.received_at_ms || now_ms >= request.deadline_at_ms {
            return Err(RuntimeError::BudgetExhausted);
        }
        request.validate_digest()
    }
}

impl CapturedDecisionFence<'_> {
    pub(crate) fn fact_lease(&self) -> &FactLease {
        &self.facts
    }
    pub(crate) fn request_lease(&self) -> &CapturedRequestLease<'_> {
        &self.request
    }
    pub fn state(&self) -> &TargetStateLease<'_> {
        self.request.state()
    }
    pub fn authorization(&self) -> &WorkloadAuthorization {
        &self.authorization
    }
    pub fn decision_id(&self) -> &str {
        self.evidence.decision_id()
    }
    pub fn valid_until_ns(&self) -> u64 {
        self.valid_until_ns
    }
    pub fn evidence_capacity(&self) -> RuntimeResult<pc_runtime_types::EvidenceCapacity> {
        self.evidence.capacity()
    }
    pub fn revalidate(&self) -> RuntimeResult<()> {
        self.request.request.revalidate_time()?;
        self.evidence
            .revalidate(self.state().active(), wall_clock_ns()?)?;
        self.facts.revalidate().map_err(|error| match error {
            crate::fact_lease::FactLeaseError::InvalidInput => RuntimeError::InvalidInput,
            crate::fact_lease::FactLeaseError::Denied => RuntimeError::GenerationMismatch,
            crate::fact_lease::FactLeaseError::BudgetExhausted => RuntimeError::BudgetExhausted,
            crate::fact_lease::FactLeaseError::RuntimeUnavailable => {
                RuntimeError::RuntimeUnavailable
            }
        })?;
        if wall_clock_ns()? >= self.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        self.request.request.revalidate_time()
    }
    pub fn commit(&mut self, decision: &pc_runtime_types::RuntimeDecision) -> RuntimeResult<()> {
        if decision.effect == pc_runtime_types::DecisionEffect::AllowForward {
            self.revalidate()?;
        }
        self.evidence
            .commit(self.request.state().active(), decision, wall_clock_ns()?)
    }
}

impl<'a> CapturedRequestLease<'a> {
    pub(super) fn analysis_source_bytes(&self) -> RuntimeResult<(&[u8], &[u8])> {
        self.state
            .captured
            .owner
            .invocation
            .analysis_source_bytes(self.state.active.capsule(), self.state.active.artifacts()?)
    }
    pub(crate) fn transaction_policy(
        &self,
    ) -> RuntimeResult<&pc_policy_core::transaction_policy::TransactionPolicyV1> {
        if self.request.decoded.request().deployment.is_some() {
            Ok(&self
                .selected_deployment_policy()?
                .publication()
                .definition
                .transaction_policy)
        } else {
            self.selected_policy()?
                .configured_identity()?
                .transaction_policy()
        }
    }
    pub(crate) fn selected_deployment_policy(
        &self,
    ) -> RuntimeResult<&pc_policy_core::deployment_policy::ValidatedDeploymentPolicy> {
        use pc_policy_core::cigl::settings::GovernanceMode;
        let policy = self
            .state
            .selected_deployment_policy(self.request.decoded.request())?;
        let definition = &policy.publication().definition;
        let genesis = Digest::parse(
            definition
                .genesis_digest
                .strip_prefix("sha256:")
                .ok_or(RuntimeError::InvalidDigest)?,
        )?;
        if let Some(settings) = self.state.cigl_settings.for_environment(
            &policy.publication().participant_id,
            &policy.publication().privacy_domain_id,
            &definition.chain_id,
            &definition.network_id,
            &genesis,
        )? && settings.definition.mode == GovernanceMode::HybridStrict
            && settings.definition.enforcement.deployment_constructors
        {
            // Constructor observation has its own owner; never skip a required gate.
            return Err(RuntimeError::Denied);
        }
        Ok(policy)
    }
    pub(crate) fn selected_policy(&self) -> RuntimeResult<&ValidatedInvocationPolicy> {
        self.state.selected_policy(self.request.decoded.request())
    }
    pub(crate) fn selected_cigl_profile(
        &self,
    ) -> RuntimeResult<Option<&pc_policy_core::cigl::profile::ValidatedMethodProfile>> {
        if self.request.decoded.request().deployment.is_some() {
            return Ok(None);
        }
        use pc_policy_core::cigl::settings::{GovernanceMode, ReadinessScope, TraceProvider};
        let method = self.selected_policy()?;
        let profile = pc_policy_core::cigl::profile::ValidatedMethodProfile::select(
            &self.state.cigl_profiles,
            method,
        )?;
        if let Some(source) = self.state.cigl_settings.for_method(method)? {
            let settings = &source.definition;
            let required = settings.mode == GovernanceMode::HybridStrict
                && match self.request.decoded.request().method.as_str() {
                    "eth_call" => settings.enforcement.eth_call,
                    "eth_estimateGas" => settings.enforcement.eth_estimate_gas,
                    "pc_prepareTransaction" => settings.enforcement.prepare_write,
                    "eth_sendRawTransaction" => {
                        settings.enforcement.raw_submission
                            || settings.enforcement.runtime_trace_for_writes
                    }
                    _ => false,
                };
            if required {
                let reviewed = profile.ok_or(RuntimeError::Denied)?;
                // Unsupported required owners and narrower active budgets fail
                // closed. They cannot silently inherit a weaker method profile.
                if settings.trace_provider != TraceProvider::DebugTraceCall
                    || settings.readiness_scope != ReadinessScope::Method
                    || settings.post_mine.freeze_on_divergence
                    || reviewed.definition().limits.max_depth > settings.trace_limits.max_depth
                    || reviewed.definition().limits.max_frames > settings.trace_limits.max_frames
                    || reviewed.definition().limits.max_response_bytes
                        > settings.trace_limits.max_response_bytes
                    || reviewed.definition().limits.timeout_ms > settings.trace_limits.timeout_ms
                {
                    return Err(RuntimeError::Denied);
                }
            }
        }
        Ok(profile)
    }

    pub(crate) fn cigl_post_mine_required(&self) -> RuntimeResult<bool> {
        if self.request.decoded.request().deployment.is_some() {
            return Ok(false);
        }
        Ok(self
            .state
            .cigl_settings
            .for_method(self.selected_policy()?)?
            .is_some_and(|source| {
                source.definition.mode
                    == pc_policy_core::cigl::settings::GovernanceMode::HybridStrict
                    && source.definition.post_mine.enabled
            }))
    }

    pub(crate) fn analysis_observation_context(
        &self,
    ) -> RuntimeResult<(Digest, pc_policy_core::cigl::TraceLimits)> {
        use pc_policy_core::cigl::settings::{GovernanceMode, TraceProvider};
        let method = self.selected_policy()?;
        if let Some(source) = self.state.cigl_settings.for_method(method)? {
            if source.definition.mode != GovernanceMode::HybridStrict
                || source.definition.trace_provider != TraceProvider::DebugTraceCall
            {
                return Err(RuntimeError::Denied);
            }
            return Ok((
                Digest::of(source.to_cbor()?),
                source.definition.trace_limits,
            ));
        }
        let profile = pc_policy_core::cigl::profile::ValidatedMethodProfile::select(
            &self.state.cigl_profiles,
            method,
        )?
        .ok_or(RuntimeError::Denied)?;
        Ok((
            profile.grants().profile_digest.clone(),
            profile.definition().limits,
        ))
    }

    pub fn authorize_invocation(&self) -> RuntimeResult<WorkloadAuthorization> {
        let route = self
            .state
            .route_for_request(self.request.decoded.request())?;
        if self.request.decoded.request().visibility.is_some() {
            let now = wall_clock_ns()?;
            let mut grant = self.state.identities.authorize(
                &self.state.captured.peer,
                &crate::identity_state::RuntimeAuthorityRequest {
                    action_intent_id: "ACT-RUNTIME_READ_RPC-V1",
                    resource_id: &route.assignment.runtime_binding_id,
                    risk_class: &route.assignment.risk_class,
                },
                now,
            )?;
            let verified = self.state.captured.owner.identity_assertions.verify(
                &self.request.assertion,
                &grant.identity,
                now / 1_000_000,
            )?;
            self.state.check_emergency_scopes(
                &grant.authorization.facts().actor_principal_id,
                &route.assignment.runtime_binding_id,
            )?;
            if grant.authorization.facts().privacy_domain_id
                != self.state.captured.owner.privacy_domain_id
            {
                return Err(RuntimeError::TargetIdentity);
            }
            grant.valid_until_ns = grant
                .valid_until_ns
                .min(self.state.active.expires_at_ns())
                .min(route.valid_until_ns())
                .min(verified.expires_at_ms().saturating_mul(1_000_000))
                .min(
                    self.request
                        .decoded
                        .request()
                        .deadline_at_ms
                        .saturating_mul(1_000_000),
                );
            if wall_clock_ns()? >= grant.valid_until_ns {
                return Err(RuntimeError::ExpiredAuthorization);
            }
            return Ok(grant);
        }
        self.authorize_identity(&RuntimeInvocationAuthorityRequest {
            capability: self
                .state
                .invocation_profile
                .capability_for_method(&self.request.decoded.request().method)?,
            resource_id: &route.assignment.runtime_binding_id,
            risk_class: &route.assignment.risk_class,
        })
    }

    fn required_facts(&self) -> RuntimeResult<Vec<FactReference>> {
        let route = self
            .state
            .route_for_request(self.request.decoded.request())?;
        let mut required = std::collections::BTreeMap::new();
        for fact in self
            .state
            .required_facts
            .iter()
            .chain(&route.assignment.required_facts)
            .chain(&route.certification.required_facts)
        {
            if required
                .insert(fact.candidate_id.clone(), fact.clone())
                .is_some_and(|old| old != *fact)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        Ok(required.into_values().collect())
    }

    fn revalidate_identity(&self) -> RuntimeResult<()> {
        let now_ns = wall_clock_ns()?;
        let (identity, principal) = self
            .state
            .identities
            .identity_for_peer(&self.state.captured.peer, now_ns)?;
        self.state.captured.owner.identity_assertions.verify(
            &self.request.assertion,
            &identity,
            now_ns / 1_000_000,
        )?;
        let resource = self
            .state
            .runtime_resource(self.request.decoded.request())?;
        self.state.check_emergency_scopes(principal, resource)?;
        self.state.active.revalidate(wall_clock_ns()?)
    }
    pub fn state(&self) -> &TargetStateLease<'_> {
        &self.state
    }
    pub fn reserve_evidence(&self) -> RuntimeResult<DecisionEvidenceReservation<'a>> {
        self.request.revalidate_time()?;
        let request: &'a CapturedTargetRequest = self.request;
        request.evidence().reserve_for_trace(
            self.state.active(),
            request.decoded.request(),
            request.trace(),
            wall_clock_ns()?,
        )
    }
    pub fn acquire_required_facts(&self) -> RuntimeResult<FactLease> {
        let value_candidates = if self.request.decoded.request().invocation.is_some() {
            self.selected_cigl_profile()?
                .and_then(|profile| profile.program())
                .map(|program| {
                    program
                        .state_references()
                        .map(|reference| reference.fact.candidate_id.clone())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        self.acquire_facts_with_values(&value_candidates)
    }
    pub(crate) fn acquire_analysis_facts(&self) -> RuntimeResult<FactLease> {
        self.acquire_facts_with_values(&[])
    }
    fn acquire_facts_with_values(&self, value_candidates: &[String]) -> RuntimeResult<FactLease> {
        self.request.revalidate_time()?;
        let now_ms = wall_clock_ns()? / 1_000_000;
        let deadline_ms = self
            .request
            .decoded
            .request()
            .deadline_at_ms
            .min(self.state.active.expires_at_ns() / 1_000_000);
        let budget_ms = deadline_ms
            .checked_sub(now_ms)
            .filter(|remaining| *remaining != 0)
            .ok_or(RuntimeError::BudgetExhausted)?
            .min(5000);
        let facts = self.state.acquire_fact_references(
            &self.required_facts()?,
            value_candidates,
            budget_ms,
        )?;
        self.request.revalidate_time()?;
        Ok(facts)
    }
    pub fn authorize_identity(
        &self,
        invocation: &RuntimeInvocationAuthorityRequest<'_>,
    ) -> RuntimeResult<WorkloadAuthorization> {
        self.request.revalidate_time()?;
        let request = self.request.decoded.request();
        if request.invocation.is_some()
            && request.class != pc_runtime_types::RequestClass::Write
            && self.selected_cigl_profile()?.is_some()
        {
            // Until the corresponding observed read/preparation owner is wired,
            // a required CIGL profile must never be silently bypassed.
            return Err(RuntimeError::Denied);
        }
        let route = self.state.route_for_request(request)?;
        // A valid grant for another capability or runtime binding is not
        // authority for this immutable decoded invocation.
        if invocation.capability
            != self
                .state
                .invocation_profile
                .capability_for_method(&request.method)?
            || invocation.resource_id != self.state.runtime_resource(request)?
            || invocation.risk_class != route.assignment.risk_class
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let transaction = match request.class {
            pc_runtime_types::RequestClass::Write => Some(
                self.request
                    .decoded
                    .signed_transaction()
                    .ok_or(RuntimeError::Denied)?,
            ),
            _ => None,
        };
        if let Some(transaction) = transaction {
            transaction
                .enforce_policy(self.transaction_policy()?)
                .map_err(|_| RuntimeError::Denied)?;
        }
        let mut grant = self.state.authorize_identity_with_transaction(
            invocation,
            &self.request.assertion,
            transaction,
        )?;
        if let Some(sender) = self.request.decoded.call_sender() {
            let chain_id = request
                .invocation
                .as_ref()
                .ok_or(RuntimeError::InvalidAuthorization)?
                .chain_id
                .parse()
                .map_err(|_| RuntimeError::InvalidAuthorization)?;
            self.state.identities.validate_call_sender(
                &self.state.captured.peer,
                chain_id,
                sender,
                wall_clock_ns()?,
            )?;
        }
        if let Some(deployment) = self.request.decoded.deployment() {
            let context = deployment.preparation().context();
            let claims = deployment.handoff().claims();
            let actor = grant.authorization.facts();
            let wallet = grant.submission_wallet()?;
            let vector = Digest::parse(
                grant
                    .identity
                    .authority_vector_digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )?;
            if context.participant_id != actor.participant_id
                || Some(context.participant_epoch) != grant.participant_epoch
                || context.privacy_domain_id != actor.privacy_domain_id
                || context.actor_subject_id != actor.actor_principal_id
                || context.workload_binding_id.as_ref() != Some(&actor.workload_id)
                || context.wallet_binding_id != wallet.id()
                || context.wallet_binding_epoch != wallet.epoch()
                || context.target_runtime_id != self.state.active.capsule().target_runtime_id
                || context.policy_generation_digest
                    != self.state.active.capsule().policy_bundle_digest
                || context.routing_constraint_digest != self.state.routing.source_digest()
                || context.chain_environment_id != route.assignment.chain_environment_id
                || claims.identity_vector_digest != vector
                || claims.workload_peer_binding_digest
                    != self.request.peer().submission_binding_digest()?
                || wall_clock_ns()? / 1_000_000 >= claims.expires_at_ms
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            grant.valid_until_ns = grant
                .valid_until_ns
                .min(claims.expires_at_ms.saturating_mul(1_000_000));
        }
        grant.valid_until_ns = grant.valid_until_ns.min(route.valid_until_ns()).min(
            self.request
                .decoded
                .request()
                .deadline_at_ms
                .saturating_mul(1_000_000),
        );
        self.request.revalidate_time()?;
        Ok(grant)
    }
}

impl TargetStateLease<'_> {
    pub(crate) fn selected_deployment_policy(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
    ) -> RuntimeResult<&pc_policy_core::deployment_policy::ValidatedDeploymentPolicy> {
        request.validate_digest()?;
        let deployment = request.deployment.as_ref().ok_or(RuntimeError::Denied)?;
        let mut selected = self.deployment_policies.iter().filter(|policy| {
            policy.publication().deployment_policy_id == deployment.deployment_policy_id
                && policy.policy_generation_digest() == &self.active.capsule().policy_bundle_digest
                && policy.publication().participant_id == self.captured.peer.participant_id()
                && policy.publication().privacy_domain_id == self.captured.owner.privacy_domain_id
                && policy.workload_id() == self.captured.peer.workload_id()
        });
        let policy = selected.next().ok_or(RuntimeError::Denied)?;
        if selected.next().is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(policy)
    }

    pub(crate) fn runtime_resource(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
    ) -> RuntimeResult<&str> {
        if request.visibility.is_some() {
            Ok(pc_policy_core::visibility_policy::read_resource(
                &self.visibility_resources,
                request,
            )?
            .selector
            .resource_id())
        } else if request.deployment.is_some() {
            Ok(&self
                .selected_deployment_policy(request)?
                .publication()
                .deployment_policy_id)
        } else {
            Ok(self
                .selected_policy(request)?
                .configured_identity()?
                .runtime_binding_id())
        }
    }
    pub(crate) fn validate_route_evidence_trust(
        &self,
        evidence: &RequestRouteEvidence,
    ) -> RuntimeResult<()> {
        self.captured.owner.route_evidence_trust.validate(evidence)
    }
    fn selected_policy(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
    ) -> RuntimeResult<&ValidatedInvocationPolicy> {
        select_active_policy_in_scope(
            &self.policies,
            request,
            ActiveInvocationScope {
                policy_generation_digest: &self.active.capsule().policy_bundle_digest,
                tenant_id: self.captured.peer.participant_id(),
                privacy_domain_id: &self.captured.owner.privacy_domain_id,
                workload_id: self.captured.peer.workload_id(),
            },
        )
    }
    pub fn route_for_request(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
    ) -> RuntimeResult<AdmittedRequestRoute<'_>> {
        let route = if request.visibility.is_some() {
            let resource = pc_policy_core::visibility_policy::read_resource(
                &self.visibility_resources,
                request,
            )?;
            self.routing.select_visibility(resource, request)?
        } else if request.deployment.is_some() {
            self.routing
                .select_deployment(request, self.selected_deployment_policy(request)?)?
        } else {
            self.routing
                .select(self.runtime_resource(request)?, request)?
        };
        route.validate_emergency(&self.active)?;
        let configured = self.captured.owner.invocation.admit_provider_profile(
            self.active.capsule(),
            self.active.artifacts()?,
            &route.certification.provider_profile_id,
            &route.certification.provider_artifact_digest,
        )?;
        if configured != route.certification.provider_profile_cbor {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(route)
    }
    pub fn active(&self) -> &ActiveCapsuleLease<'_> {
        &self.active
    }
    pub fn policies(&self) -> &[ValidatedInvocationPolicy] {
        &self.policies
    }
    pub fn deployment_policies(
        &self,
    ) -> &[pc_policy_core::deployment_policy::ValidatedDeploymentPolicy] {
        &self.deployment_policies
    }
    pub fn mrpc_profile(&self) -> &MrpcRuntimeProfile {
        &self.mrpc
    }
    pub fn invocation_profile(&self) -> &InvocationProfileMaterial {
        &self.invocation_profile
    }

    pub fn decode(
        &self,
        body: &[u8],
        limits: RequestDecodeLimits<'_>,
    ) -> RuntimeResult<DecodedProtectedRequest> {
        let now_ns = wall_clock_ns()?;
        self.active.revalidate(now_ns)?;
        if let Some(decoded) = DecodedProtectedRequest::decode_visibility(
            body,
            &self.visibility_resources,
            limits,
            now_ns / 1_000_000,
        )? {
            return Ok(decoded);
        }
        let decoded =
            DecodedProtectedRequest::decode(body, &self.policies, limits, now_ns / 1_000_000)
                .inspect_err(|error| {
                    eprintln!("{}", serde_json::json!({"event":"protected_request_rejected","stage":"contract_decode","pcCode":error.pc_code(),"traceId":self.captured.trace.as_str()}));
                })?;
        self.invocation_profile
            .capability_for_method(&decoded.request().method)
            .inspect_err(|error| {
                eprintln!("{}", serde_json::json!({"event":"protected_request_rejected","stage":"invocation_profile","pcCode":error.pc_code(),"traceId":self.captured.trace.as_str()}));
            })?;
        Ok(decoded)
    }

    /// Capability, resource and risk must be resolved by the admitted invocation
    /// owner. This method verifies actual grant paths and the signed 3002 against
    /// the captured TLS peer and current authority vector, never self-signing an
    /// assertion or accepting roles from the request.
    pub fn authorize_identity(
        &self,
        invocation: &RuntimeInvocationAuthorityRequest<'_>,
        assertion: &IdentityAssertionEvidence,
    ) -> RuntimeResult<WorkloadAuthorization> {
        self.authorize_identity_with_transaction(invocation, assertion, None)
    }

    fn authorize_identity_with_transaction(
        &self,
        invocation: &RuntimeInvocationAuthorityRequest<'_>,
        assertion: &IdentityAssertionEvidence,
        transaction: Option<&openpc_multi_rpc::signed_transaction::SignedTransaction>,
    ) -> RuntimeResult<WorkloadAuthorization> {
        let now_ns = wall_clock_ns()?;
        self.active.revalidate(now_ns)?;
        let mut grant = match transaction {
            None if invocation.capability
                == pc_policy_core::invocation_capability::InvocationCapability::SignedTransactionSubmission =>
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            Some(transaction) => self.identities.authorize_submission(
                &self.captured.peer,
                transaction,
                invocation,
                now_ns,
            )?,
            None => self
                .identities
                .authorize_runtime(&self.captured.peer, invocation, now_ns)?,
        };
        if grant.authorization.facts().privacy_domain_id != self.captured.owner.privacy_domain_id {
            return Err(RuntimeError::TargetIdentity);
        }
        let verified = self.captured.owner.identity_assertions.verify(
            assertion,
            &grant.identity,
            now_ns / 1_000_000,
        )?;
        self.check_emergency_scopes(
            &grant.authorization.facts().actor_principal_id,
            invocation.resource_id,
        )?;
        grant.valid_until_ns = grant
            .valid_until_ns
            .min(self.active.expires_at_ns())
            .min(verified.expires_at_ms().saturating_mul(1_000_000));
        if wall_clock_ns()? >= grant.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(grant)
    }

    fn check_emergency_scopes(&self, principal: &str, resource: &str) -> RuntimeResult<()> {
        // Match the signed Identity publisher's applicable deny-scope names.
        // Raw UUIDs are not aliases for these canonical entity URNs.
        let participant_scope = format!(
            "urn:openpc:participant:{}",
            self.captured.peer.participant_id()
        );
        let privacy_scope = format!(
            "urn:openpc:privacy-domain:{}",
            self.captured.owner.privacy_domain_id
        );
        let principal_scope = format!("urn:openpc:principal:{principal}");
        if self.active.denies_any_scope([
            participant_scope.as_str(),
            privacy_scope.as_str(),
            principal_scope.as_str(),
            self.captured.peer.workload_id(),
            resource,
        ]) {
            return Err(RuntimeError::Denied);
        }
        Ok(())
    }

    /// Acquire exactly the semantic document's compiled dependencies, as one
    /// retained database transaction. No request or adapter supplies a candidate
    /// ID or substitutes another currently eligible fact from the same shard.
    pub fn acquire_required_facts(&self, budget_ms: u64) -> RuntimeResult<FactLease> {
        self.acquire_fact_references(&self.required_facts, &[], budget_ms)
    }
    pub(crate) fn validate_fact_conditions(
        &self,
        anchor: &openpc_multi_rpc::route_witness::ChainAnchor,
    ) -> RuntimeResult<()> {
        self.validate_conditions_at_anchor(anchor, &self.fact_conditions)
    }

    pub(crate) fn validate_visibility_condition(
        &self,
        anchor: &openpc_multi_rpc::route_witness::ChainAnchor,
        condition: &pc_policy_core::fact_condition::FactCondition,
    ) -> RuntimeResult<()> {
        self.validate_conditions_at_anchor(anchor, std::slice::from_ref(condition))
    }

    pub(crate) fn visibility_condition_at_occurrence(
        &self,
        anchor: &openpc_multi_rpc::route_witness::ChainAnchor,
        condition: &pc_policy_core::fact_condition::FactCondition,
        transaction: u64,
        log: u64,
    ) -> RuntimeResult<bool> {
        self.facts.condition_at_occurrence(
            &self.active,
            condition,
            &openpc_fact_service::LocalFactContext {
                participant_id: self.captured.peer.participant_id(),
                privacy_domain_id: &self.captured.owner.privacy_domain_id,
                workload_id: self.captured.peer.workload_id(),
                chain_id: anchor.chain_id,
                block_number: anchor.block_number,
                block_hash: &anchor.block_hash,
            },
            transaction,
            log,
        )
    }

    pub(crate) fn authorize_visibility_read(
        &self,
        request: &pc_runtime_types::RuntimeRequest,
        grant: &WorkloadAuthorization,
        anchor: &openpc_multi_rpc::route_witness::ChainAnchor,
    ) -> RuntimeResult<pc_policy_core::visibility_policy::ValidatedVisibilityRead> {
        let resource =
            pc_policy_core::visibility_policy::read_resource(&self.visibility_resources, request)?;
        let binding = resource
            .contract_binding
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        if binding.chain_id != anchor.chain_id.to_string() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        pc_policy_core::visibility_policy::ValidatedVisibilityRead::evaluate(
            request,
            &self.active.capsule().policy_bundle_digest,
            pc_policy_core::visibility_policy::VisibilityReadPolicySet {
                resource,
                policies: &self.visibility_policies,
                rpc: &self.rpc_policies,
                required: &self.required_facts,
            },
            grant.authorization.facts(),
            |condition| {
                if matches!(
                    request.visibility.as_ref().map(|read| &read.query),
                    Some(pc_runtime_types::VisibilityReadQuery::Logs { .. })
                ) {
                    self.facts.permits_any_occurrence(
                        &self.active,
                        condition,
                        &openpc_fact_service::LocalFactContext {
                            participant_id: self.captured.peer.participant_id(),
                            privacy_domain_id: &self.captured.owner.privacy_domain_id,
                            workload_id: self.captured.peer.workload_id(),
                            chain_id: anchor.chain_id,
                            block_number: anchor.block_number,
                            block_hash: &anchor.block_hash,
                        },
                    )
                } else {
                    self.validate_visibility_condition(anchor, condition)
                        .is_ok()
                }
            },
        )
    }

    fn validate_conditions_at_anchor(
        &self,
        anchor: &openpc_multi_rpc::route_witness::ChainAnchor,
        conditions: &[pc_policy_core::fact_condition::FactCondition],
    ) -> RuntimeResult<()> {
        self.facts.validate_conditions(
            &self.active,
            conditions,
            &openpc_fact_service::LocalFactContext {
                participant_id: self.captured.peer.participant_id(),
                privacy_domain_id: &self.captured.owner.privacy_domain_id,
                workload_id: self.captured.peer.workload_id(),
                chain_id: anchor.chain_id,
                block_number: anchor.block_number,
                block_hash: &anchor.block_hash,
            },
        )
    }
    fn acquire_fact_references(
        &self,
        required: &[FactReference],
        value_candidates: &[String],
        budget_ms: u64,
    ) -> RuntimeResult<FactLease> {
        acquire_fact_references(
            &self.active,
            &self.facts,
            &self.captured.owner.fact_reader,
            required,
            value_candidates,
            (
                self.captured.peer.participant_id(),
                &self.captured.owner.privacy_domain_id,
            ),
            budget_ms,
        )
    }
}

fn acquire_fact_references(
    active: &ActiveCapsuleLease<'_>,
    facts: &InstalledFactState,
    reader: &FactLeaseReader,
    required: &[FactReference],
    value_candidates: &[String],
    scope: (&str, &str),
    budget_ms: u64,
) -> RuntimeResult<FactLease> {
    active.revalidate(wall_clock_ns()?)?;
    let candidates = required
        .iter()
        .map(|r| r.candidate_id.clone())
        .collect::<Vec<_>>();
    let lease =
        facts.acquire_many_with_values(active, reader, &candidates, value_candidates, budget_ms)?;
    if lease.snapshots().len() != required.len() {
        return Err(RuntimeError::GenerationMismatch);
    }
    for (snapshot, reference) in lease.snapshots().iter().zip(required) {
        let expected = crate::capsule::digest(
            &reference
                .parsed_digest()
                .map_err(|_| RuntimeError::InvalidDigest)?,
        )?;
        if snapshot.candidate_id != reference.candidate_id
            || snapshot.generation_id != reference.generation_id
            || Some(&snapshot.fact_digest) != expected.as_bytes()
            || snapshot.participant_id != scope.0
            || snapshot.privacy_domain_id != scope.1
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    active.revalidate(wall_clock_ns()?)?;
    Ok(lease)
}

pub(crate) fn wall_clock_ns() -> RuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?
        .as_nanos()
        .try_into()
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_capture_can_cross_async_boundaries_without_a_journal_guard() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<TargetState>();
        send_sync::<CapturedTargetState>();
        send_sync::<CapturedTargetRequest>();
        send_sync::<DecodedProtectedRequest>();
    }
}
