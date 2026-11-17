//! Caller-owned status is an independent local capability. It does not need a
//! provider route, current wallet association or permission to submit again.
use super::*;
use openpc_broker::write_dispatch::SubmissionBroker;
use openpc_multi_rpc::{
    submission_operation::SubmissionOwner, submission_status::OperationStatusView,
};
use pc_policy_core::invocation_capability::InvocationCapability;

impl TargetState {
    /// A repeated signed submission is securely bound by the original verified
    /// peer and exact signed identity. Persist the durable outcome before
    /// current profile, policy, session, route or evidence admission checks.
    /// This does not implement or grant the independent status-poll capability.
    pub(crate) fn repeated_submission_response(
        &self,
        broker: &SubmissionBroker,
        peer: &WorkloadPeer,
        body: &[u8],
        maximum_bytes: usize,
        response_budget: u64,
    ) -> RuntimeResult<Option<Vec<u8>>> {
        if broker.target_id() != self.agent.target_id {
            return Err(RuntimeError::TargetIdentity);
        }
        let envelope = crate::request_decode::strict_json_rpc_envelope(body, maximum_bytes)?;
        let Some(transaction) = crate::request_decode::signed_submission_identity(&envelope)?
        else {
            return Ok(None);
        };
        let now = wall_clock_ns()? / 1_000_000;
        if now < peer.not_before_ms() || now >= peer.not_after_ms() {
            return Err(RuntimeError::TargetIdentity);
        }
        let Some(view) = broker.repeated_submission_view(
            &transaction,
            peer.participant_id(),
            &self.privacy_domain_id,
            peer.workload_id(),
            &peer.submission_binding_digest()?,
        )?
        else {
            return Ok(None);
        };
        crate::operation_status_rpc::encode_response(&envelope["id"], &view, response_budget)
            .map(Some)
    }
}

impl CapturedTargetState {
    /// Internal read boundary. A response adapter must commit disclosure
    /// evidence and reapply this current-owner check at the release boundary.
    pub fn read_owned_submission_status(
        &self,
        broker: &SubmissionBroker,
        operation_id: &str,
        assertion: &IdentityAssertionEvidence,
    ) -> RuntimeResult<OperationStatusView> {
        let state = self.acquire()?;
        self.authorized_submission_status(&state, broker, operation_id, assertion)
            .map(|(status, _)| status)
    }

    fn authorized_submission_status(
        &self,
        state: &TargetStateLease<'_>,
        broker: &SubmissionBroker,
        operation_id: &str,
        assertion: &IdentityAssertionEvidence,
    ) -> RuntimeResult<(OperationStatusView, WorkloadAuthorization)> {
        if !uuid::Uuid::try_parse(operation_id)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == operation_id)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let capability = state
            .invocation_profile()
            .capability_for_method("pc_getOperationStatus")?;
        if capability != InvocationCapability::OperationStatusDisclosure {
            return Err(RuntimeError::Denied);
        }
        // The signed profile must select the canonical method/result
        // registry. Only the authenticated original submitter can see its
        // already-known transaction hash in that registered six-field view.
        if state.invocation_profile().disclosure_policy_digest
            != crate::provider_response::call_result_disclosure_policy_digest()
        {
            return Err(RuntimeError::Denied);
        }
        let now = wall_clock_ns()?;
        let (identity, principal) = state.identities.identity_for_peer(&self.peer, now)?;
        self.owner
            .identity_assertions
            .verify(assertion, &identity, now / 1_000_000)?;
        let owner = SubmissionOwner {
            participant_id: self.peer.participant_id().into(),
            privacy_domain_id: self.owner.privacy_domain_id.clone(),
            actor_principal_id: principal.into(),
            workload_id: self.peer.workload_id().into(),
        };
        // Unknown and foreign operations share the same closed denial.
        let (_, admission, _) = broker
            .lookup(operation_id, &owner)?
            .ok_or(RuntimeError::Denied)?;
        if admission.target_runtime_id != state.active().capsule().target_runtime_id {
            return Err(RuntimeError::Denied);
        }
        let grant = state.authorize_identity(
            &RuntimeInvocationAuthorityRequest {
                capability,
                resource_id: operation_id,
                risk_class: admission
                    .risk_class
                    .as_deref()
                    .ok_or(RuntimeError::Denied)?,
            },
            assertion,
        )?;
        pc_policy_core::rpc_policy::RpcSurfacePolicy::authorize_operation_status(
            &state.rpc_policies,
            &owner.participant_id,
            &owner.privacy_domain_id,
            &grant.authorization.facts().roles,
        )?;
        let status = broker
            .view(operation_id, &owner)?
            .ok_or(RuntimeError::Denied)?;
        let now = wall_clock_ns()?;
        state.active().revalidate(now)?;
        if now >= grant.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok((status, grant))
    }

    pub(crate) fn release_submission_status(
        &self,
        broker: &SubmissionBroker,
        decoded: &crate::operation_status_rpc::OperationStatusRequest,
        assertion: &IdentityAssertionEvidence,
    ) -> RuntimeResult<Vec<u8>> {
        let state = self.acquire()?;
        let (status, grant) =
            self.authorized_submission_status(&state, broker, &decoded.operation_id, assertion)?;
        let response = decoded.response(&status)?;
        let authority_digest = Digest::of(pc_runtime_types::canonical_bytes(&(
            &grant.authorization,
            &grant.identity,
            &state.active().capsule().rpc_invocation_profile_digest,
            &decoded.operation_id,
        ))?);
        let mut evidence = self.evidence().reserve_for_trace_until(
            state.active(),
            &decoded.request,
            &self.trace,
            grant.valid_until_ns,
            wall_clock_ns()?,
        )?;
        let now = wall_clock_ns()?;
        state.active().revalidate(now)?;
        if now >= grant.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        evidence.commit_operation_status(
            state.active(),
            &decoded.request,
            &decoded.operation_id,
            authority_digest,
            &response,
            now,
        )?;
        Ok(response)
    }
}
