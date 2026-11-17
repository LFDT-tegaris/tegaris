//! Bind the committed PDS decision to Broker under the current captured owners.
//! Request handlers cannot supply bindings, an alternate anchor or a retry law.
use super::CapturedRequestRoute;
use crate::{decision_evidence::DecisionEvidenceStatus, target_state::wall_clock_ns};
use openpc_broker::{BrokerService, PreparedReadDispatch, ReadLaw};
use pc_runtime_types::{DecisionEffect, RuntimeDecision, RuntimeError, RuntimeResult};

impl CapturedRequestRoute {
    pub fn admit_broker_read(
        &self,
        broker: &BrokerService,
        decision: &RuntimeDecision,
    ) -> RuntimeResult<PreparedReadDispatch> {
        let request = self.acquire()?;
        let grant = request.authorize_invocation()?;
        let facts = request.acquire_required_facts()?;
        let now = wall_clock_ns()?;
        if now >= grant.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        self.validate_committed_decision(request.state(), decision, now)?;
        self.validate_state(request.state())?;
        let bindings = self.runtime_bindings(request.state(), &grant)?;
        facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        // Routing admission requires an IdempotentRead SingleExact profile with
        // zero retry budget. Quorum/failover profiles cannot reach this path.
        broker.admit_read(
            self.request.decoded().request(),
            &bindings,
            decision,
            wall_clock_ns()? / 1_000_000,
            &self.evidence.anchor.anchor().semantic_digest()?,
            ReadLaw {
                same_route_retries: 0,
                parity_failover: false,
            },
        )
    }

    pub(super) fn validate_committed_decision(
        &self,
        state: &crate::target_state::TargetStateLease<'_>,
        decision: &RuntimeDecision,
        now: u64,
    ) -> RuntimeResult<u64> {
        let (id, committed) = self
            .request
            .evidence()
            .read_for_trace(self.request.trace().as_str())?
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if id != decision.decision_id
            || committed.request_digest != self.request.decoded().request().request_digest
            || committed.capsule_digest != state.active().capsule().digest()?
            || committed.capsule_digest != decision.active_generation_digest
            || now >= committed.valid_until_ns
            || decision.effect != DecisionEffect::AllowForward
            || !matches!(&committed.status,
                DecisionEvidenceStatus::Committed {
                    effect: DecisionEffect::AllowForward, pc_code, decision_input_digest,
                    decision_digest, protective_degradation, ..
                } if pc_code == &decision.pc_code
                    && decision_input_digest == &decision.decision_input_digest
                    && decision_digest == &decision.decision_digest
                    && protective_degradation == &decision.protective_degradation)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(committed.valid_until_ns)
    }
}
