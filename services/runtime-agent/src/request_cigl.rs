//! CIGL belongs to the captured installation, workload and provider route. Its
//! minimized decision joins the existing preflight/PDS/Broker evidence chain.
use super::*;
use openpc_multi_rpc::cigl::{
    authorization::{SignedMethodContext, evaluate_signed_method_profile},
    observer::{ObservationScope, observe_signed},
};
use pc_policy_core::cigl::program::{
    CurrentStateEvidence, StateValueReference, state::AnchoredStateValueV1,
};

struct CapturedStateEvidence<'a> {
    facts: &'a crate::fact_lease::FactLease,
    anchor: &'a VerifiedChainAnchor,
    participant: &'a str,
    privacy: &'a str,
}
impl CurrentStateEvidence for CapturedStateEvidence<'_> {
    fn read(
        &self,
        reference: &StateValueReference,
    ) -> RuntimeResult<pc_policy_core::invocation::ArgumentValue> {
        let snapshot = self
            .facts
            .snapshots()
            .iter()
            .find(|snapshot| snapshot.candidate_id == reference.fact.candidate_id)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let digest = reference
            .fact
            .parsed_digest()
            .map_err(|_| RuntimeError::InvalidDigest)?;
        if snapshot.participant_id != self.participant
            || snapshot.privacy_domain_id != self.privacy
            || snapshot.generation_id != reference.fact.generation_id
            || snapshot
                .fact_digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                != digest.as_str()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let value = self
            .facts
            .value(&reference.fact.candidate_id)
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let anchor = self.anchor.anchor();
        AnchoredStateValueV1::read_at_anchor(
            value.payload(),
            anchor.chain_id,
            anchor.block_number,
            &anchor.block_hash,
            value.finality_anchor(),
        )
    }
}

impl CapturedRequestRoute {
    pub(super) fn cigl_post_mine_expectation(
        &self,
        captured: &CapturedRequestLease<'_>,
    ) -> RuntimeResult<Option<openpc_multi_rpc::cigl::reconciliation::PostMineExpectation>> {
        if !captured.cigl_post_mine_required()? {
            return Ok(None);
        }
        let profile = captured
            .selected_cigl_profile()?
            .ok_or(RuntimeError::Denied)?;
        let observation = self
            .cigl_preflight
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let transaction = self
            .request
            .decoded()
            .signed_transaction()
            .ok_or(RuntimeError::Denied)?;
        openpc_multi_rpc::cigl::reconciliation::PostMineExpectation::capture(
            transaction,
            observation.trace().inspection(),
            profile.grants().profile_digest.clone(),
        )
        .map(Some)
    }
    /// Non-granting inspection of this exact captured request. The control
    /// analysis job still owns public authorization, durable storage and review;
    /// this entry cannot accept client frame paths or activate a profile.
    pub(super) fn analyze_observed_method(
        &self,
    ) -> RuntimeResult<openpc_multi_rpc::cigl::analysis::ObservedMethodAnalysis> {
        use openpc_multi_rpc::cigl::analysis::{AnalysisSources, analyze_signed_method};
        let captured = self.acquire()?;
        let facts = captured.acquire_analysis_facts()?;
        let (observation_context_digest, _) = captured.analysis_observation_context()?;
        let root = captured
            .selected_policy()?
            .configured_identity()?
            .contract_method_policy_id();
        let observation = self
            .cigl_preflight
            .as_ref()
            .ok_or(RuntimeError::ResponseWithheld)?;
        let subjects = captured.authorize_invocation()?;
        let (configuration_bytes, policy_bytes) = captured.analysis_source_bytes()?;
        let configuration_digest = Digest::of(configuration_bytes);
        let policy_artifact_digest = Digest::of(policy_bytes);
        let route_digest = self.evidence.witness_set.material().semantic_digest()?;
        let context = SignedMethodContext {
            connection: self
                .evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            request: self.request.decoded().request(),
            transaction: self
                .request
                .decoded()
                .signed_transaction()
                .ok_or(RuntimeError::Denied)?,
            anchor: &self.evidence.anchor,
            configuration_digest: &configuration_digest,
            policy_artifact_digest: &policy_artifact_digest,
            policy_generation_digest: &captured.state().active().capsule().policy_bundle_digest,
            route_witness_set_digest: &route_digest,
        };
        analyze_signed_method(
            observation,
            &AnalysisSources {
                configuration_bytes,
                policy_bytes,
                root_contract_method_policy_id: root,
                observation_context_digest: &observation_context_digest,
            },
            &subjects,
            &context,
            &|| {
                captured.authorize_invocation()?;
                facts
                    .revalidate()
                    .map_err(|_| RuntimeError::GenerationMismatch)?;
                self.validate_state(captured.state())
            },
        )
    }

    pub(super) async fn observe_method_cigl(
        &mut self,
        deadline: tokio::time::Instant,
        purpose: ObservationPurpose,
    ) -> RuntimeResult<()> {
        let selected = {
            let captured = self.acquire()?;
            match purpose {
                ObservationPurpose::Analysis => Some(captured.analysis_observation_context()?),
                ObservationPurpose::Submission => {
                    captured.selected_cigl_profile()?.map(|profile| {
                        (
                            profile.grants().profile_digest.clone(),
                            profile.definition().limits,
                        )
                    })
                }
            }
        };
        let Some((profile_digest, limits)) = selected else {
            return Ok(());
        };
        let route_digest = self.evidence.witness_set.material().semantic_digest()?;
        self.cigl_preflight = Some(
            observe_signed(
                &self.evidence.connection,
                self.request.decoded().request(),
                self.request
                    .decoded()
                    .signed_transaction()
                    .ok_or(RuntimeError::Denied)?,
                &self.evidence.anchor,
                &ObservationScope {
                    profile_digest: &profile_digest,
                    route_witness_set_digest: &route_digest,
                },
                limits,
                deadline,
                &|| self.revalidate_observation(purpose),
            )
            .await?,
        );
        Ok(())
    }

    pub(super) fn validate_method_cigl(
        &self,
        captured: &CapturedRequestLease<'_>,
        facts: &crate::fact_lease::FactLease,
    ) -> RuntimeResult<Option<Digest>> {
        let Some(profile) = captured.selected_cigl_profile()? else {
            return if self.cigl_preflight.is_none() {
                Ok(None)
            } else {
                Err(RuntimeError::GenerationMismatch)
            };
        };
        let observation = self
            .cigl_preflight
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let subjects = captured.authorize_invocation()?;
        let (configuration_digest, policy_artifact_digest) = profile.source_digests();
        let route_digest = self.evidence.witness_set.material().semantic_digest()?;
        let context = SignedMethodContext {
            connection: self
                .evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            request: self.request.decoded().request(),
            transaction: self
                .request
                .decoded()
                .signed_transaction()
                .ok_or(RuntimeError::Denied)?,
            anchor: &self.evidence.anchor,
            configuration_digest,
            policy_artifact_digest,
            policy_generation_digest: &captured.state().active().capsule().policy_bundle_digest,
            route_witness_set_digest: &route_digest,
        };
        let revalidate = || {
            // Retain this synchronous capsule fence; do not reacquire an active
            // lease recursively or hold it across asynchronous provider work.
            captured.authorize_invocation()?;
            facts
                .revalidate()
                .map_err(|_| RuntimeError::GenerationMismatch)?;
            self.validate_state(captured.state())
        };
        let state = CapturedStateEvidence {
            facts,
            anchor: &self.evidence.anchor,
            participant: &subjects.authorization.facts().participant_id,
            privacy: &subjects.authorization.facts().privacy_domain_id,
        };
        evaluate_signed_method_profile(
            observation,
            profile,
            &subjects,
            &state,
            &context,
            &revalidate,
        )?
        .digest()
        .map(Some)
    }
}
