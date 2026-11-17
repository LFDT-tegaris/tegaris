//! Target-owned observation authority survives the original actor's submission
//! grant. It requires its own current signed route, certification and facts.
use super::*;
use openpc_broker::write_dispatch::SubmissionBroker;
use openpc_multi_rpc::{
    journal::{LiveObservationAuthority, ObservationAuthorityLease, ObservationTarget},
    provider_connection::ConnectionRecord,
    route_witness::{VerifiedChainAnchor, VerifiedRouteWitness},
};

pub struct CapturedRecovery {
    state: Arc<TargetState>,
    broker: Arc<SubmissionBroker>,
    target: ObservationTarget,
    evidence: RequestRouteEvidence,
    capsule_digest: Digest,
}

struct RecoveryLease<'a> {
    active: ActiveCapsuleLease<'a>,
    facts: Option<FactLease>,
    valid_until_ns: u64,
}
impl ObservationAuthorityLease for RecoveryLease<'_> {
    fn revalidate(&self) -> RuntimeResult<()> {
        let now = wall_clock_ns()?;
        self.active.revalidate(now)?;
        if now >= self.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if let Some(facts) = &self.facts {
            facts
                .revalidate()
                .map_err(|_| RuntimeError::GenerationMismatch)?;
        }
        Ok(())
    }
}

impl TargetState {
    /// One bounded observation per turn, advancing even when a route denies or
    /// the provider is unavailable. No original actor credential is recreated.
    pub async fn recover_next(
        self: &Arc<Self>,
        broker: Arc<SubmissionBroker>,
        cursor: &mut Option<String>,
        route: impl FnOnce(&ObservationTarget) -> RuntimeResult<RequestRouteEvidence>,
    ) -> RuntimeResult<Option<bool>> {
        let mut targets = broker.pending_observations_after(cursor.as_deref(), 1)?;
        if targets.is_empty() && cursor.take().is_some() {
            targets = broker.pending_observations_after(None, 1)?;
        }
        let Some(target) = targets.pop() else {
            return Ok(None);
        };
        *cursor = Some(target.command().command_id.clone());
        let evidence = route(&target)?;
        self.prepare_recovery(broker, target, evidence)?
            .execute()
            .await
            .map(Some)
    }

    pub fn prepare_recovery(
        self: &Arc<Self>,
        broker: Arc<SubmissionBroker>,
        target: ObservationTarget,
        evidence: RequestRouteEvidence,
    ) -> RuntimeResult<CapturedRecovery> {
        let capsule_digest = self
            .agent
            .acquire_fresh_active_capsule(&self.protected_class_set, wall_clock_ns()?)?
            .capsule()
            .digest()?;
        let recovery = CapturedRecovery {
            state: self.clone(),
            broker,
            target,
            evidence,
            capsule_digest,
        };
        recovery
            .acquire(
                &recovery.target,
                recovery
                    .evidence
                    .connection
                    .record()
                    .map_err(|_| RuntimeError::GenerationMismatch)?,
                &recovery.evidence.anchor,
                &recovery.evidence.witness,
            )?
            .revalidate()?;
        Ok(recovery)
    }
}
impl CapturedRecovery {
    pub async fn observe_for_replacement(
        self,
    ) -> RuntimeResult<openpc_broker::write_dispatch::ReplacementObservation> {
        self.broker
            .observe_replacement(
                &self.target,
                &self.evidence.connection,
                &self.evidence.anchor,
                &self.evidence.witness,
                &self,
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .await
    }

    pub async fn execute(self) -> RuntimeResult<bool> {
        self.broker
            .reconcile(
                &self.target,
                &self.evidence.connection,
                &self.evidence.anchor,
                &self.evidence.witness,
                &self,
                tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .await
    }
}

impl LiveObservationAuthority for CapturedRecovery {
    fn acquire<'a>(
        &'a self,
        target: &ObservationTarget,
        connection: &ConnectionRecord,
        anchor: &VerifiedChainAnchor,
        witness: &VerifiedRouteWitness,
    ) -> RuntimeResult<Box<dyn ObservationAuthorityLease + 'a>> {
        if target.binding_digest() != self.target.binding_digest()
            || target.command() != self.target.command()
            || target.admission() != self.target.admission()
            || target.admission().target_runtime_id != self.state.agent.target_id
            || self.broker.target_id() != self.state.agent.target_id
            || target.admission().owner.privacy_domain_id != self.state.privacy_domain_id
            || self
                .evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?
                != connection
            || anchor.anchor().semantic_digest() != self.evidence.anchor.anchor().semantic_digest()
            || anchor.verification_key_digest() != self.evidence.anchor.verification_key_digest()
            || witness.witness().semantic_digest()
                != self.evidence.witness.witness().semantic_digest()
            || witness.verification_key_digest() != self.evidence.witness.verification_key_digest()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let now = wall_clock_ns()?;
        let active = self
            .state
            .agent
            .acquire_fresh_active_capsule(&self.state.protected_class_set, now)?;
        let capsule = active.capsule();
        if capsule.digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        let artifacts = active.artifacts()?;
        self.state.route_evidence_trust.validate(&self.evidence)?;
        let (mrpc, _) = self.state.mrpc.admit_profile(capsule, artifacts)?;
        self.evidence.validate_current(
            capsule,
            &mrpc.semantic_digest()?,
            &Digest::parse(&target.command().immutable_request_digest)?,
            now,
        )?;
        if witness.witness().purpose != 4
            || witness.witness().operation_digest != *target.operation_digest()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let (routing, _) = self.state.routing.admit(capsule, artifacts)?;
        let route = routing.select_observation(target)?;
        route.validate_emergency(&active)?;
        route.validate_witness(witness.witness(), connection, now)?;
        let configured = self.state.invocation.admit_provider_profile(
            capsule,
            artifacts,
            &route.certification.provider_profile_id,
            &route.certification.provider_artifact_digest,
        )?;
        if configured != route.certification.provider_profile_cbor {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut required = std::collections::BTreeMap::new();
        for fact in route
            .assignment
            .required_facts
            .iter()
            .chain(&route.certification.required_facts)
        {
            if required
                .insert(fact.candidate_id.clone(), fact.clone())
                .is_some_and(|old| old != *fact)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        let valid_until_ns = active
            .expires_at_ns()
            .min(route.valid_until_ns())
            .min(anchor.valid_until_ns())
            .min(witness.witness().selection_deadline_ns)
            .min(self.evidence.witness_set.valid_until_ns())
            .min(connection.valid_until_ms.saturating_mul(1_000_000));
        let budget = (valid_until_ns
            .checked_sub(now)
            .ok_or(RuntimeError::ExpiredAuthorization)?
            / 1_000_000)
            .min(5_000);
        if budget == 0 {
            return Err(RuntimeError::BudgetExhausted);
        }
        let facts = if required.is_empty() {
            if capsule.policy_fact_state_digest
                != Digest::of(crate::indexer_custody::NO_FACT_PUBLICATION)
            {
                self.state.facts.admit_fact_state(capsule, artifacts)?;
            }
            None
        } else {
            let (facts, _) = self.state.facts.admit_fact_state(capsule, artifacts)?;
            Some(acquire_fact_references(
                &active,
                &facts,
                &self.state.fact_reader,
                &required.into_values().collect::<Vec<_>>(),
                &[],
                (
                    &target.admission().owner.participant_id,
                    &self.state.privacy_domain_id,
                ),
                budget,
            )?)
        };
        let lease = RecoveryLease {
            active,
            facts,
            valid_until_ns,
        };
        lease.revalidate()?;
        Ok(Box::new(lease))
    }
}
