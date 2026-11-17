//! Request-local PDS owner. Projection is built only while all admitted target,
//! identity, route, provider, fact and evidence fences are held together.
use super::CapturedRequestRoute;
use crate::target_state::{CapturedDecisionFence, wall_clock_ns};
use openpc_pds::{LocalDecisionLease, LocalDecisionOwner, LocalDecisionState};
use pc_runtime_types::{
    DecisionEffect, RuntimeBindings, RuntimeDecision, RuntimeError, RuntimeRequest, RuntimeResult,
};

struct RequestDecisionLease<'a> {
    route: &'a CapturedRequestRoute,
    fence: CapturedDecisionFence<'a>,
    projection: LocalDecisionState,
}

impl LocalDecisionOwner for CapturedRequestRoute {
    fn acquire(&self, request: &RuntimeRequest) -> RuntimeResult<Box<dyn LocalDecisionLease + '_>> {
        if request != self.request.decoded().request() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let fence = self.request.acquire_decision_fence()?;
        self.validate_state(fence.state())?;
        let state = fence.state();
        let submission_witness_digest =
            self.validate_write_preflight(fence.request_lease(), fence.fact_lease())?;
        let admitted = state.route_for_request(request)?;
        let grant = fence.authorization();
        let valid_until_ms = fence
            .valid_until_ns()
            .min(self.evidence.anchor.valid_until_ns())
            .min(self.evidence.witness_set.valid_until_ns())
            .min(admitted.valid_until_ns())
            / 1_000_000;
        let valid_until_ms = valid_until_ms.min(self.preflight_valid_until_ms()).min(
            self.evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
                .valid_until_ms,
        );
        if valid_until_ms <= wall_clock_ns()? / 1_000_000 {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let projection = LocalDecisionState {
            visibility_read: request
                .visibility
                .as_ref()
                .map(|_| {
                    state.authorize_visibility_read(request, grant, self.evidence.anchor.anchor())
                })
                .transpose()?,
            deployment_policy: request
                .deployment
                .as_ref()
                .map(|_| state.selected_deployment_policy(request).cloned())
                .transpose()?,
            decision_id: fence.decision_id().to_owned(),
            request_digest: request.request_digest.clone(),
            submission_witness_digest,
            bindings: self.runtime_bindings(state, grant)?,
            active_invocation_policies: state.policies().to_vec(),
            authorization: grant.authorization.clone(),
            identity: grant.identity.clone(),
            emergency_deny: false, // Checked against every applicable owner scope by acquire.
            evidence: fence.evidence_capacity()?,
            valid_until_ms,
        };
        let lease = RequestDecisionLease {
            route: self,
            fence,
            projection,
        };
        lease.revalidate()?;
        Ok(Box::new(lease))
    }
}
impl LocalDecisionLease for RequestDecisionLease<'_> {
    fn state(&self) -> &LocalDecisionState {
        &self.projection
    }
    fn revalidate(&self) -> RuntimeResult<()> {
        self.fence.revalidate()?;
        self.route.validate_state(self.fence.state())?;
        if self
            .route
            .validate_write_preflight(self.fence.request_lease(), self.fence.fact_lease())?
            != self.projection.submission_witness_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if wall_clock_ns()? / 1_000_000 >= self.projection.valid_until_ms {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }
    fn commit(&mut self, decision: &RuntimeDecision) -> RuntimeResult<()> {
        if decision.effect == DecisionEffect::AllowForward {
            self.revalidate()?;
            if decision.capability.as_ref().is_none_or(|capability| {
                capability.claims.expires_at_ms > self.projection.valid_until_ms
                    || capability.claims.provider_profile_id
                        != self.projection.bindings.eligible_provider_profile_ids[0]
                    || capability.claims.provider_profile_digest
                        != self.projection.bindings.provider_profile_digest
                    || capability.claims.route_profile_digest
                        != self.projection.bindings.route_profile_digest
            }) {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        self.fence.commit(decision)
    }
}

impl CapturedRequestRoute {
    pub(super) fn runtime_bindings(
        &self,
        state: &crate::target_state::TargetStateLease<'_>,
        grant: &crate::identity_state::WorkloadAuthorization,
    ) -> RuntimeResult<RuntimeBindings> {
        let capsule = state.active().capsule();
        let admitted = state.route_for_request(self.request.decoded().request())?;
        let active = capsule.digest()?;
        let scope = grant.authorization.facts();
        Ok(RuntimeBindings {
            participant_id: scope.participant_id.clone(),
            privacy_domain_id: scope.privacy_domain_id.clone(),
            workload_id: scope.workload_id.clone(),
            target_id: capsule.target_runtime_id.clone(),
            active_generation_digest: active.clone(),
            observed_generation_digest: active,
            policy_generation_digest: capsule.policy_bundle_digest.clone(),
            expected_policy_generation_digest: capsule.policy_bundle_digest.clone(),
            fact_generation_digest: capsule.policy_fact_state_digest.clone(),
            expected_fact_generation_digest: capsule.policy_fact_state_digest.clone(),
            route_profile_digest: capsule.routing_snapshot_digest.clone(),
            expected_route_profile_digest: capsule.routing_snapshot_digest.clone(),
            eligible_provider_profile_ids: vec![admitted.certification.provider_profile_id.clone()],
            provider_profile_digest: admitted.certification.provider_artifact_digest.clone(),
            expected_provider_profile_digest: admitted
                .certification
                .provider_artifact_digest
                .clone(),
        })
    }
}
