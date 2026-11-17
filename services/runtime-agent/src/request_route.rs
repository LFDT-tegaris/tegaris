//! Request-local route evidence custody. This joins independently verified
//! 2012/2013/2021 material to the active 2014 profile and installed connection.
//! It does not select a route or authorize one: signed assignment, certification,
//! overlay and canonical-generation owners must also participate in a decision.

use crate::{
    RuntimeCapsule,
    provider_transport::PinnedProviderTransport,
    target_state::{CapturedRequestLease, CapturedTargetRequest, TargetStateLease, wall_clock_ns},
};
use openpc_multi_rpc::{
    provider_connection::{ConnectionLease, ConnectionRecord, ConnectionStatus},
    route_witness::{VerifiedChainAnchor, VerifiedRouteWitness},
    route_witness_set::VerifiedRouteWitnessSet,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult};
use std::sync::Arc;

#[path = "request_broker.rs"]
mod broker;
#[path = "request_cigl.rs"]
mod cigl;
#[path = "request_decision.rs"]
mod decision;
#[path = "request_write.rs"]
mod write;

pub use write::CapturedSubmission;
pub(crate) use write::SubmissionOutcome;

pub struct RequestRouteEvidence {
    pub anchor: VerifiedChainAnchor,
    pub witness: VerifiedRouteWitness,
    pub witness_set: VerifiedRouteWitnessSet,
    pub connection: Arc<ConnectionLease>,
}

/// Bootstrap pins the independently owned anchor, witness and witness-set
/// verifiers. Successful verification under some other key is insufficient.
pub struct RouteEvidenceTrust {
    anchor_key: Digest,
    witness_key: Digest,
    witness_set_key: Digest,
    witness_signer_id: String,
}
impl RouteEvidenceTrust {
    pub fn new(
        anchor: &pc_policy_core::runtime_wire::Verifier,
        witness: &pc_policy_core::runtime_wire::Verifier,
        witness_set: &pc_policy_core::runtime_wire::Verifier,
        witness_signer_id: String,
    ) -> RuntimeResult<Self> {
        crate::capsule::text(&witness_signer_id, 160)?;
        Ok(Self {
            anchor_key: Digest::of(anchor.public_key_bytes()),
            witness_key: Digest::of(witness.public_key_bytes()),
            witness_set_key: Digest::of(witness_set.public_key_bytes()),
            witness_signer_id,
        })
    }
    pub(crate) fn validate(&self, evidence: &RequestRouteEvidence) -> RuntimeResult<()> {
        if evidence.anchor.verification_key_digest() != &self.anchor_key
            || evidence.witness.verification_key_digest() != &self.witness_key
            || evidence.witness_set.verification_key_digest() != &self.witness_set_key
            || evidence.witness.witness().signer_id != self.witness_signer_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
}

/// Immutable and Send; no activation, fact or evidence MutexGuard crosses I/O.
/// The retained connection fences replacement until this capture is released.
pub struct CapturedRequestRoute {
    validated_response: std::sync::Mutex<Option<Digest>>,
    request: Arc<CapturedTargetRequest>,
    evidence: RequestRouteEvidence,
    preflight: Option<openpc_multi_rpc::write_preflight::WritePreflight>,
    deployment_preflight: Option<openpc_multi_rpc::deployment::DeploymentPreflight>,
    cigl_preflight: Option<openpc_multi_rpc::cigl::observer::ObservedCiglTrace>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObservationPurpose {
    Submission,
    Analysis,
}

impl CapturedTargetRequest {
    /// The route signer receives only an actually observed head. Discovery
    /// checks current route/identity/policy/fact authority before every call.
    pub async fn prepare_submission_route(
        self: Arc<Self>,
        connection: Arc<ConnectionLease>,
        sign_route: impl FnOnce(
            &openpc_multi_rpc::write_preflight::PreflightAnchor,
        ) -> RuntimeResult<RequestRouteEvidence>
        + Send,
    ) -> RuntimeResult<CapturedRequestRoute> {
        let route = self
            .observe_submission_route(connection, sign_route, ObservationPurpose::Submission)
            .await?;
        {
            let captured = route.acquire()?;
            let facts = captured.acquire_required_facts()?;
            route.validate_write_preflight(&captured, &facts)?;
        }
        Ok(route)
    }

    /// Analysis may discover a denied nested interaction, but it returns only
    /// sanitized evidence. It cannot hand a route/capability to a send owner.
    pub async fn analyze_submission_method(
        self: Arc<Self>,
        connection: Arc<ConnectionLease>,
        sign_route: impl FnOnce(
            &openpc_multi_rpc::write_preflight::PreflightAnchor,
        ) -> RuntimeResult<RequestRouteEvidence>
        + Send,
    ) -> RuntimeResult<openpc_multi_rpc::cigl::analysis::ObservedMethodAnalysis> {
        if self.decoded().request().invocation.is_none() || self.decoded().deployment().is_some() {
            return Err(RuntimeError::Denied);
        }
        self.observe_submission_route(connection, sign_route, ObservationPurpose::Analysis)
            .await?
            .analyze_observed_method()
    }

    async fn observe_submission_route(
        self: Arc<Self>,
        connection: Arc<ConnectionLease>,
        sign_route: impl FnOnce(
            &openpc_multi_rpc::write_preflight::PreflightAnchor,
        ) -> RuntimeResult<RequestRouteEvidence>
        + Send,
        purpose: ObservationPurpose,
    ) -> RuntimeResult<CapturedRequestRoute> {
        let request = self.decoded().request();
        let transaction = self
            .decoded()
            .signed_transaction()
            .ok_or(RuntimeError::Denied)?;
        let remaining = request
            .deadline_at_ms
            .checked_sub(wall_clock_ns()? / 1_000_000)
            .filter(|remaining| *remaining > 0)
            .ok_or(RuntimeError::BudgetExhausted)?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(remaining);
        let revalidate = || {
            let captured = self.acquire()?;
            captured
                .state()
                .route_for_request(request)?
                .validate_connection(
                    connection
                        .record()
                        .map_err(|_| RuntimeError::GenerationMismatch)?,
                    wall_clock_ns()?,
                )?;
            write::validate_observation_policy(&captured, request, purpose)
        };
        let genesis = self
            .decoded()
            .deployment()
            .map(|_| {
                let captured = self.acquire()?;
                Digest::parse(
                    captured
                        .selected_deployment_policy()?
                        .publication()
                        .definition
                        .genesis_digest
                        .strip_prefix("sha256:")
                        .ok_or(RuntimeError::InvalidInput)?,
                )
            })
            .transpose()?;
        let head = if let Some(genesis) = &genesis {
            openpc_multi_rpc::write_preflight::select_deployment_anchor(
                &connection,
                request,
                transaction,
                genesis,
                deadline,
                &revalidate,
            )
            .await?
        } else {
            openpc_multi_rpc::write_preflight::select_anchor(
                &connection,
                request,
                transaction,
                deadline,
                &revalidate,
            )
            .await?
        };
        let evidence = sign_route(&head)?;
        let mut route = self.clone().bind_route_evidence(evidence)?;
        if let (Some(deployment), Some(genesis)) = (self.decoded().deployment(), genesis) {
            route.deployment_preflight = Some(
                openpc_multi_rpc::deployment::observe_preflight(
                    &route.evidence.connection,
                    request,
                    &deployment.handoff().submission().constraints,
                    transaction,
                    &genesis,
                    &route.evidence.anchor,
                    &route.evidence.witness_set.material().semantic_digest()?,
                    deadline,
                    &|| route.revalidate_observation(purpose),
                )
                .await?,
            );
        } else {
            let proof = head
                .complete(
                    &route.evidence.connection,
                    request,
                    transaction,
                    &route.evidence.anchor,
                    &route.evidence.witness_set.material().semantic_digest()?,
                    deadline,
                    &|| route.revalidate_observation(purpose),
                )
                .await?;
            route.preflight = Some(proof);
            route.observe_method_cigl(deadline, purpose).await?;
        }
        Ok(route)
    }

    pub fn bind_route_evidence(
        self: Arc<Self>,
        evidence: RequestRouteEvidence,
    ) -> RuntimeResult<CapturedRequestRoute> {
        let captured = CapturedRequestRoute {
            validated_response: std::sync::Mutex::new(None),
            request: self,
            evidence,
            preflight: None,
            deployment_preflight: None,
            cigl_preflight: None,
        };
        captured.acquire()?;
        // Also check the exact decoder-owned height and chain against the
        // independently signed anchor. Never accept the witness's inline
        // anchor as a substitute for primary 2012 verification.
        captured
            .request
            .decoded()
            .hash_pinned_provider_body(&captured.evidence.anchor)?;
        Ok(captured)
    }
}

impl CapturedRequestRoute {
    fn validate_write_preflight(
        &self,
        captured: &CapturedRequestLease<'_>,
        facts: &crate::fact_lease::FactLease,
    ) -> RuntimeResult<Option<Digest>> {
        let Some(transaction) = self.request.decoded().signed_transaction() else {
            return Ok(None);
        };
        if let Some(deployment) = self.request.decoded().deployment() {
            let proof = self
                .deployment_preflight
                .as_ref()
                .ok_or(RuntimeError::InvalidAuthorization)?;
            let genesis = deployment.preparation().genesis_digest();
            proof.validate(
                self.evidence
                    .connection
                    .record()
                    .map_err(|_| RuntimeError::GenerationMismatch)?,
                self.request.decoded().request(),
                &deployment.handoff().submission().constraints,
                transaction,
                genesis,
                &self.evidence.anchor,
                &self.evidence.witness_set.material().semantic_digest()?,
                wall_clock_ns()? / 1_000_000,
            )?;
            return Ok(Some(Digest::of(pc_runtime_types::canonical_bytes(&(
                proof.digest()?,
                deployment.handoff().claims(),
            ))?)));
        }
        let proof = self
            .preflight
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        proof.validate(
            self.evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            self.request.decoded().request(),
            transaction,
            &self.evidence.anchor,
            &self.evidence.witness_set.material().semantic_digest()?,
            wall_clock_ns()? / 1_000_000,
        )?;
        let digest = proof.digest()?;
        match self.validate_method_cigl(captured, facts)? {
            Some(cigl) => {
                pc_runtime_types::canonical_bytes(&("openpc:write-preflight-cigl:v1", digest, cigl))
                    .map(Digest::of)
                    .map(Some)
            }
            None => Ok(Some(digest)),
        }
    }

    fn preflight_valid_until_ms(&self) -> u64 {
        self.preflight
            .as_ref()
            .map_or(u64::MAX, |proof| proof.valid_until_ms())
            .min(
                self.deployment_preflight
                    .as_ref()
                    .map_or(u64::MAX, |proof| proof.valid_until_ms()),
            )
            .min(
                self.cigl_preflight
                    .as_ref()
                    .map_or(u64::MAX, |proof| proof.valid_until_ms()),
            )
    }

    pub fn request(&self) -> &CapturedTargetRequest {
        &self.request
    }

    /// A short synchronous lease; callers drop it before awaiting provider I/O
    /// and reacquire it before accepting an effect or releasing a response.
    pub fn acquire(&self) -> RuntimeResult<CapturedRequestLease<'_>> {
        let request = self.request.acquire()?;
        self.validate_state(request.state())?;
        Ok(request)
    }

    fn validate_state(&self, state: &TargetStateLease<'_>) -> RuntimeResult<()> {
        state.validate_route_evidence_trust(&self.evidence)?;
        state.validate_fact_conditions(self.evidence.anchor.anchor())?;
        let record = self
            .evidence
            .connection
            .record()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        validate_material(
            &self.evidence.anchor,
            &self.evidence.witness,
            &self.evidence.witness_set,
            RouteContext {
                request: self.request.decoded().request(),
                capsule: state.active().capsule(),
                admitted_profile: &state.mrpc_profile().semantic_digest()?,
                connection: record,
                now_ns: wall_clock_ns()?,
            },
        )?;
        state
            .route_for_request(self.request.decoded().request())?
            .validate_witness(self.evidence.witness.witness(), record, wall_clock_ns()?)?;
        state.active().revalidate(wall_clock_ns()?)
    }

    pub(crate) fn revalidate_dispatch(&self) -> RuntimeResult<()> {
        let request = self.acquire()?;
        let authorization = request.authorize_invocation()?;
        let facts = request.acquire_required_facts()?;
        if self.request.decoded().request().visibility.is_some() {
            request.state().authorize_visibility_read(
                self.request.decoded().request(),
                &authorization,
                self.evidence.anchor.anchor(),
            )?;
        }
        facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        if wall_clock_ns()? >= authorization.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        self.validate_state(request.state())
    }

    /// Reacquire every current owner and project the provider response through
    /// the exact disclosure, schema and normalization identities admitted by
    /// this capsule. Raw provider bytes do not cross this boundary.
    pub(crate) fn filter_provider_response(&self, body: &[u8]) -> RuntimeResult<Vec<u8>> {
        self.filter_response(body, false)
    }

    /// Keep the activation, identity and Fact leases through the durable release
    /// decision. A check followed by dropping these fences permits a revocation
    /// to commit before release custody is consumed.
    pub(crate) fn release_provider_response(&self, body: &[u8]) -> RuntimeResult<Vec<u8>> {
        self.filter_response(body, true)
    }

    fn filter_response(&self, body: &[u8], release: bool) -> RuntimeResult<Vec<u8>> {
        let failure = |stage: &'static str, error: &RuntimeError| {
            eprintln!(
                "{}",
                serde_json::json!({"event":"protected_response_rejected","stage":stage,"release":release,"pcCode":error.pc_code(),"traceId":self.request.trace().as_str()})
            );
        };
        let request = self
            .acquire()
            .inspect_err(|error| failure("current_state", error))?;
        let authorization = request
            .authorize_invocation()
            .inspect_err(|error| failure("authorization", error))?;
        let facts = request
            .acquire_required_facts()
            .inspect_err(|error| failure("fact_acquisition", error))?;
        let route = request
            .state()
            .route_for_request(self.request.decoded().request())?;
        let profile = route.provider_profile()?;
        facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        if wall_clock_ns()? >= authorization.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let decoded = self.request.decoded().request();
        let response = if decoded.visibility.is_some() {
            let proof = request.state().authorize_visibility_read(
                decoded,
                &authorization,
                self.evidence.anchor.anchor(),
            )?;
            if profile.response_schema_digest
                != crate::provider_response::call_result_response_schema_digest()
                || profile.normalization_rule_digest
                    != crate::provider_response::call_result_normalization_rule_digest()
            {
                return Err(RuntimeError::ResponseWithheld);
            }
            if release
                && *self
                    .validated_response
                    .lock()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?
                    != Some(Digest::of(body))
            {
                return Err(RuntimeError::ResponseWithheld);
            }
            if release
                && matches!(
                    decoded.visibility.as_ref().map(|read| &read.query),
                    Some(pc_runtime_types::VisibilityReadQuery::Transaction { .. })
                )
            {
                body.to_vec()
            } else {
                let filtered = crate::protected_target::visibility_response::filter(
                    crate::protected_target::visibility_response::ReadResponseContext {
                        request: decoded,
                        resource: pc_policy_core::visibility_policy::read_resource(
                            &request.state().visibility_resources,
                            decoded,
                        )?,
                        resources: &request.state().visibility_resources,
                        policies: &request.state().visibility_policies,
                        required_facts: &request.state().required_facts,
                        authorization: authorization.authorization.facts(),
                        anchor: self.evidence.anchor.anchor(),
                        decision: proof.decision(),
                    },
                    body,
                    |condition, transaction, log| {
                        request.state().visibility_condition_at_occurrence(
                            self.evidence.anchor.anchor(),
                            condition,
                            transaction,
                            log,
                        )
                    },
                )?;
                let mut admitted = self
                    .validated_response
                    .lock()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?;
                let digest = Digest::of(&filtered);
                if admitted.as_ref().is_some_and(|prior| prior != &digest) {
                    return Err(RuntimeError::ResponseWithheld);
                }
                *admitted = Some(digest);
                filtered
            }
        } else {
            let response = crate::provider_response::filter_call_success(
                self.request.decoded().request(),
                body,
                &request
                    .state()
                    .invocation_profile()
                    .disclosure_policy_digest,
                &profile.response_schema_digest,
                &profile.normalization_rule_digest,
            )?;
            crate::protected_target::visibility::filter(
                &request,
                &authorization,
                response,
                |condition| {
                    request
                        .state()
                        .validate_visibility_condition(self.evidence.anchor.anchor(), condition)
                        .is_ok()
                },
            )?
        };
        facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        self.validate_state(request.state())?;
        if wall_clock_ns()? >= authorization.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if release {
            self.request
                .evidence()
                .release_for_trace(self.request.trace(), &response, wall_clock_ns()?)
                .inspect_err(|error| failure("evidence_release", error))?;
        }
        Ok(response)
    }

    pub fn provider_transport(self: &Arc<Self>) -> RuntimeResult<PinnedProviderTransport> {
        let lease = self.acquire()?;
        PinnedProviderTransport::new(
            self.clone(),
            self.evidence.connection.clone(),
            self.request.decoded().clone(),
            &self.evidence.anchor,
        )?
        .limit_validity(
            self.evidence
                .witness_set
                .valid_until_ns()
                .min(lease.state().active().expires_at_ns()),
        )
    }
}

struct RouteContext<'a> {
    request: &'a RuntimeRequest,
    capsule: &'a RuntimeCapsule,
    admitted_profile: &'a Digest,
    connection: &'a ConnectionRecord,
    now_ns: u64,
}

fn validate_material(
    anchor: &VerifiedChainAnchor,
    witness: &VerifiedRouteWitness,
    witness_set: &VerifiedRouteWitnessSet,
    context: RouteContext<'_>,
) -> RuntimeResult<()> {
    let RouteContext {
        request,
        capsule,
        admitted_profile,
        connection,
        now_ns,
    } = context;
    request.validate_digest()?;
    if now_ns < request.received_at_ms.saturating_mul(1_000_000)
        || now_ns >= request.deadline_at_ms.saturating_mul(1_000_000)
    {
        return Err(RuntimeError::ExpiredAuthorization);
    }
    validate_route_material(
        anchor,
        witness,
        witness_set,
        RouteMaterialContext {
            request_digest: &request.request_digest,
            capsule,
            admitted_profile,
            connection,
            now_ns,
        },
    )
}

struct RouteMaterialContext<'a> {
    request_digest: &'a Digest,
    capsule: &'a RuntimeCapsule,
    admitted_profile: &'a Digest,
    connection: &'a ConnectionRecord,
    now_ns: u64,
}
impl RequestRouteEvidence {
    pub(crate) fn validate_current(
        &self,
        capsule: &RuntimeCapsule,
        admitted_profile: &Digest,
        request_digest: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        validate_route_material(
            &self.anchor,
            &self.witness,
            &self.witness_set,
            RouteMaterialContext {
                request_digest,
                capsule,
                admitted_profile,
                connection: self
                    .connection
                    .record()
                    .map_err(|_| RuntimeError::GenerationMismatch)?,
                now_ns,
            },
        )
    }
}
fn validate_route_material(
    anchor: &VerifiedChainAnchor,
    witness: &VerifiedRouteWitness,
    witness_set: &VerifiedRouteWitnessSet,
    context: RouteMaterialContext<'_>,
) -> RuntimeResult<()> {
    let RouteMaterialContext {
        request_digest,
        capsule,
        admitted_profile,
        connection,
        now_ns,
    } = context;
    anchor.revalidate_time(now_ns)?;
    let witness = witness.witness();
    let set = witness_set.material();
    if now_ns < witness.selected_at_ns
        || now_ns >= witness.selection_deadline_ns
        || now_ns < set.created_at_ns
        || now_ns >= witness_set.valid_until_ns()
        || now_ns / 1_000_000 >= connection.valid_until_ms
    {
        return Err(RuntimeError::ExpiredAuthorization);
    }
    if connection.status != ConnectionStatus::Prepared
        || &witness.request_digest != request_digest
        || witness.chain_anchor != *anchor.anchor()
        || witness.endpoint_id != connection.endpoint_id
        || witness.routing_snapshot_digest != capsule.routing_snapshot_digest
        || witness.provider_certification_registry_digest
            != capsule.provider_certification_registry_digest
        || witness.mrpc_runtime_profile_digest != *admitted_profile
        || *admitted_profile != capsule.mrpc_runtime_profile_digest
        || set.mrpc_runtime_profile_digest != *admitted_profile
        || set.operation_digest != witness.operation_digest
        || set.witnesses.len() != 1
        || set.witnesses[0].purpose != witness.purpose
        || set.witnesses[0].witness_digest != witness.semantic_digest()?
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

#[cfg(test)]
#[path = "request_route_tests.rs"]
mod tests;
