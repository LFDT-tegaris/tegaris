//! The real target owns final submission authority. Neither a journal record,
//! provider response nor request-carried metadata can manufacture this fence.
use super::{CapturedRequestRoute, ObservationPurpose};
use crate::{
    fact_lease::FactLease,
    identity_state::WorkloadAuthorization,
    target_state::{CapturedRequestLease, wall_clock_ns},
};
use openpc_broker::write_dispatch::{PreparedSubmission, SubmissionBroker};
use openpc_multi_rpc::{
    governed_write::{LiveWriteAuthority, WriteAuthorityLease},
    journal::{GovernedCommand, JournalState},
    provider_connection::ConnectionRecord,
    signed_transaction::SignedTransaction,
    submission_operation::{SubmissionAdmission, SubmissionOwner},
};
use pc_runtime_types::{Digest, RuntimeDecision, RuntimeError, RuntimeResult, canonical_bytes};
use std::sync::Arc;

/// A one-use execution handoff produced while every captured owner is current.
/// It holds immutable evidence and the connection generation, never a DB lock.
pub struct CapturedSubmission {
    broker: Arc<SubmissionBroker>,
    prepared: PreparedSubmission,
    authority: SubmissionAuthority,
}

/// Retained by the protected request that admitted this exact operation. It
/// exposes only durable operation truth and cannot authorize another attempt.
#[derive(Clone)]
pub(crate) struct SubmissionOutcome {
    broker: Arc<SubmissionBroker>,
    command: GovernedCommand,
    owner: SubmissionOwner,
    request_id: String,
    response_budget: u64,
}
impl SubmissionOutcome {
    pub(crate) fn response(&self) -> RuntimeResult<Vec<u8>> {
        let id = serde_json::from_str(&self.request_id).map_err(|_| RuntimeError::InvalidInput)?;
        if let Ok(Some(view)) = self.broker.view(&self.command.command_id, &self.owner)
            && let Ok(response) =
                crate::operation_status_rpc::encode_response(&id, &view, self.response_budget)
        {
            return Ok(response);
        }
        // If persistence became uncertain, the retained admitted identity is
        // sufficient to report ambiguity, never a no-send or retryable denial.
        // Use the canonical safe error projection, with no raw error.
        let fault = RuntimeError::WriteAmbiguity.public_error();
        openpc_multi_rpc::rfc8785_canonical_bytes(&serde_json::json!({
            "jsonrpc":"2.0", "id":id,
            "error":{"code":fault.json_rpc_code,"message":fault.message,"data":{
                "pcCode":fault.pc_code,"truthState":fault.truth_state,"retryable":false,
                "traceId":self.command.correlation_id,"attemptId":self.command.attempt_id,
                "signedTransactionHash":self.command.request_or_transaction_hash,
            }}
        }))
        .map_err(|_| RuntimeError::WriteAmbiguity)
    }
}
struct SubmissionAuthority {
    route: Arc<CapturedRequestRoute>,
    command: GovernedCommand,
    admission: SubmissionAdmission,
    decision: RuntimeDecision,
}
struct SubmissionLease<'a> {
    authority: &'a SubmissionAuthority,
    request: CapturedRequestLease<'a>,
    facts: FactLease,
}

pub(super) fn validate_observation_policy(
    request: &CapturedRequestLease<'_>,
    decoded: &pc_runtime_types::RuntimeRequest,
    purpose: ObservationPurpose,
) -> RuntimeResult<()> {
    let grant = request.authorize_invocation()?;
    let facts = match purpose {
        ObservationPurpose::Submission => request.acquire_required_facts()?,
        ObservationPurpose::Analysis => request.acquire_analysis_facts()?,
    };
    if decoded.deployment.is_some() {
        request.selected_deployment_policy()?.evaluate(
            decoded,
            &grant.authorization,
            &request.state().active().capsule().policy_bundle_digest,
            wall_clock_ns()? / 1_000_000,
        )?;
    } else {
        // A required reviewed profile must be installed before provider I/O.
        match purpose {
            ObservationPurpose::Submission => {
                request.selected_cigl_profile()?;
            }
            ObservationPurpose::Analysis => {
                request.analysis_observation_context()?;
            }
        }
        pc_policy_core::invocation::evaluate_invocation(
            decoded.invocation.as_ref().ok_or(RuntimeError::Denied)?,
            request.selected_policy()?,
            &grant.authorization,
            &pc_policy_core::invocation::InvocationEvaluation {
                request_method: &decoded.method,
                request_class: decoded.class,
                request_digest: &decoded.request_digest,
                active_policy_generation: &request.state().active().capsule().policy_bundle_digest,
                now_ms: wall_clock_ns()? / 1_000_000,
            },
        )?;
    }
    facts
        .revalidate()
        .map_err(|_| RuntimeError::GenerationMismatch)
}

impl CapturedRequestRoute {
    /// Local submission policy must permit the exact decoded input before any
    /// internal observation. This shared evaluator grants no call/estimate or
    /// actor disclosure right; PDS later binds the actual observation evidence.
    pub(super) fn revalidate_observation(&self, purpose: ObservationPurpose) -> RuntimeResult<()> {
        let request = self.acquire()?;
        validate_observation_policy(&request, self.request.decoded().request(), purpose)
    }

    pub fn admit_broker_submission(
        self: &Arc<Self>,
        broker: Arc<SubmissionBroker>,
        decision: &RuntimeDecision,
    ) -> RuntimeResult<CapturedSubmission> {
        self.admit_submission(broker, decision, None)
    }

    pub fn admit_broker_replacement(
        self: &Arc<Self>,
        broker: Arc<SubmissionBroker>,
        decision: &RuntimeDecision,
        replacement: openpc_broker::write_dispatch::ReplacementObservation,
    ) -> RuntimeResult<CapturedSubmission> {
        self.admit_submission(broker, decision, Some(replacement))
    }

    fn admit_submission(
        self: &Arc<Self>,
        broker: Arc<SubmissionBroker>,
        decision: &RuntimeDecision,
        replacement: Option<openpc_broker::write_dispatch::ReplacementObservation>,
    ) -> RuntimeResult<CapturedSubmission> {
        let request = self.acquire()?;
        let grant = request.authorize_invocation()?;
        let transaction = self
            .request
            .decoded()
            .signed_transaction()
            .ok_or(RuntimeError::Denied)?;
        let facts = request.acquire_required_facts()?;
        let now = wall_clock_ns()?;
        let evidence_until = self.validate_committed_decision(request.state(), decision, now)?;
        let preflight_witness_digest = self.validate_write_preflight(&request, &facts)?;
        let capability = decision
            .capability
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let capsule = request.state().active().capsule();
        let mut deployment = self
            .request
            .decoded()
            .deployment()
            .map(|value| value.handoff().submission().clone());
        if let Some(deployment) = &mut deployment {
            deployment.dispatch = Some(
                openpc_multi_rpc::deployment::DeploymentDispatchBinding::capture(
                    &self.evidence.witness,
                    &self.evidence.connection,
                )?,
            );
        }
        let (network_id, genesis_digest) = if deployment.is_some() {
            let definition = &request
                .selected_deployment_policy()?
                .publication()
                .definition;
            (
                definition.network_id.clone(),
                Digest::parse(
                    definition
                        .genesis_digest
                        .strip_prefix("sha256:")
                        .ok_or(RuntimeError::InvalidInput)?,
                )?,
            )
        } else {
            let invocation = self
                .request
                .decoded()
                .request()
                .invocation
                .as_ref()
                .ok_or(RuntimeError::Denied)?;
            (
                invocation.network_id.clone(),
                invocation.genesis_digest.clone(),
            )
        };
        let wallet = grant.submission_wallet()?;
        let scope = grant.authorization.facts();
        let connection = self
            .evidence
            .connection
            .record()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let valid_until_ms = (grant
            .valid_until_ns
            .min(evidence_until)
            .min(self.evidence.anchor.valid_until_ns())
            .min(self.evidence.witness_set.valid_until_ns())
            / 1_000_000)
            .min(capability.claims.expires_at_ms)
            .min(connection.valid_until_ms);
        // Factory destinations belong to the governed deployment binding.
        // Only ordinary invocation admissions carry a contract/selector pair;
        // combining both identities is rejected by the shared Broker owner.
        let contract_address = if deployment.is_none() {
            transaction.destination().copied()
        } else {
            None
        };
        let admission = SubmissionAdmission {
            owner: SubmissionOwner {
                participant_id: scope.participant_id.clone(),
                privacy_domain_id: scope.privacy_domain_id.clone(),
                actor_principal_id: scope.actor_principal_id.clone(),
                workload_id: scope.workload_id.clone(),
            },
            target_runtime_id: capsule.target_runtime_id.clone(),
            runtime_binding_id: request
                .state()
                .runtime_resource(self.request.decoded().request())?
                .into(),
            workload_peer_binding_digest: Some(self.request.peer().submission_binding_digest()?),
            preflight_witness_digest,
            cigl_post_mine: self.cigl_post_mine_expectation(&request)?,
            chain: Some(openpc_multi_rpc::submission_operation::SubmissionChain {
                chain_environment_id: request
                    .state()
                    .route_for_request(self.request.decoded().request())?
                    .assignment
                    .chain_environment_id
                    .clone(),
                network_id,
                genesis_digest,
            }),
            risk_class: Some(
                request
                    .state()
                    .route_for_request(self.request.decoded().request())?
                    .assignment
                    .risk_class
                    .clone(),
            ),
            wallet_binding_id: wallet.id().into(),
            wallet_binding_epoch: wallet.epoch(),
            capability_id: capability.claims.capability_id.clone(),
            decision_id: decision.decision_id.clone(),
            decision_digest: decision.decision_digest.clone(),
            identity_vector_digest: identity_vector(&grant)?,
            capsule_digest: capsule.digest()?,
            contract_set_manifest_digest: capsule.contract_set_manifest_digest.clone(),
            invocation_profile_digest: capsule.rpc_invocation_profile_digest.clone(),
            capability_registry_digest: capsule.capability_registry_digest.clone(),
            request_form_registry_digest: capsule.request_form_registry_digest.clone(),
            error_registry_digest: capsule.error_registry_digest.clone(),
            policy_generation_digest: capsule.policy_bundle_digest.clone(),
            transaction_policy_digest: Digest::of(canonical_bytes(request.transaction_policy()?)?),
            route_witness_set_digest: self.evidence.witness_set.material().semantic_digest()?,
            evidence_admission_profile_digest: capsule.evidence_admission_profile_digest.clone(),
            prepared_intent_digest: deployment.as_ref().map(|value| value.intent_digest.clone()),
            contract_address,
            selector: contract_address
                .map(|_| {
                    transaction
                        .data()
                        .get(..4)
                        .ok_or(RuntimeError::Denied)?
                        .try_into()
                        .map_err(|_| RuntimeError::Denied)
                })
                .transpose()?,
            deployment,
            admitted_at_ms: now / 1_000_000,
            valid_until_ms,
        };
        let bindings = self.runtime_bindings(request.state(), &grant)?;
        // ConnectionRecord.provider_id identifies the registered profile. The
        // provider instance is a separate identity in its signed artifact.
        let provider_instance_id = request
            .state()
            .route_for_request(self.request.decoded().request())?
            .provider_profile()?
            .provider_instance_id;
        self.validate_state(request.state())?;
        facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)?;
        let prepared = match replacement {
            None => broker.prepare(
                self.request.decoded().request(),
                &bindings,
                decision,
                transaction,
                admission.clone(),
                &provider_instance_id,
                &self.evidence.anchor.anchor().semantic_digest()?,
                self.request.trace().as_str(),
                wall_clock_ns()? / 1_000_000,
            )?,
            Some(replacement) => broker.prepare_replacement(
                self.request.decoded().request(),
                &bindings,
                decision,
                transaction,
                admission.clone(),
                &provider_instance_id,
                &self.evidence.anchor.anchor().semantic_digest()?,
                self.request.trace().as_str(),
                wall_clock_ns()? / 1_000_000,
                replacement,
                connection,
                request.transaction_policy()?,
            )?,
        };
        let command = prepared.command().clone();
        Ok(CapturedSubmission {
            broker,
            prepared,
            authority: SubmissionAuthority {
                route: self.clone(),
                command,
                admission,
                decision: decision.clone(),
            },
        })
    }
}

impl CapturedSubmission {
    pub(crate) fn owned_by(&self, broker: &Arc<SubmissionBroker>) -> bool {
        Arc::ptr_eq(&self.broker, broker)
    }
    pub(crate) fn outcome(&self) -> SubmissionOutcome {
        SubmissionOutcome {
            broker: self.broker.clone(),
            command: self.command().clone(),
            owner: self.authority.admission.owner.clone(),
            request_id: self
                .authority
                .route
                .request
                .decoded()
                .request()
                .request_id
                .clone(),
            response_budget: self
                .authority
                .route
                .request
                .decoded()
                .request()
                .response_budget_bytes,
        }
    }
    pub(crate) async fn execute_response(self) -> RuntimeResult<Vec<u8>> {
        let outcome = self.outcome();
        // Once an operation exists, a current-owner failure may only produce
        // its durable no-send/started/ambiguous outcome. It never erases it.
        let _execution = self.execute().await;
        outcome.response().map_err(|_| RuntimeError::WriteAmbiguity)
    }
    pub fn command(&self) -> &GovernedCommand {
        &self.authority.command
    }
    pub fn deadline_at_ms(&self) -> u64 {
        self.authority.admission.valid_until_ms
    }
    pub fn reject(self, error: &RuntimeError) -> RuntimeResult<()> {
        self.broker.reject(self.prepared, error)
    }
    pub async fn execute(self) -> RuntimeResult<JournalState> {
        let remaining = self
            .deadline_at_ms()
            .checked_sub(wall_clock_ns()? / 1_000_000)
            .filter(|remaining| *remaining > 0);
        let Some(remaining) = remaining else {
            self.reject(&RuntimeError::BudgetExhausted)?;
            return Err(RuntimeError::BudgetExhausted);
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(remaining);
        self.broker
            .execute(
                self.prepared,
                &self.authority.route.evidence.connection,
                &self.authority,
                deadline,
            )
            .await
    }
}

impl LiveWriteAuthority for SubmissionAuthority {
    fn acquire<'a>(
        &'a self,
        transaction: &SignedTransaction,
        command: &GovernedCommand,
        connection: &ConnectionRecord,
    ) -> RuntimeResult<Box<dyn WriteAuthorityLease + 'a>> {
        if command != &self.command
            || self.route.request.decoded().signed_transaction() != Some(transaction)
            || self
                .route
                .evidence
                .connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?
                != connection
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let request = self.route.acquire()?;
        let facts = request.acquire_required_facts()?;
        let lease = SubmissionLease {
            authority: self,
            request,
            facts,
        };
        lease.revalidate()?;
        Ok(Box::new(lease))
    }
}

impl WriteAuthorityLease for SubmissionLease<'_> {
    fn revalidate(&self) -> RuntimeResult<()> {
        let owner = self.authority;
        if owner
            .route
            .validate_write_preflight(&self.request, &self.facts)?
            != owner.admission.preflight_witness_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(deployment) = &owner.admission.deployment
            && deployment.dispatch.as_ref()
                != Some(
                    &openpc_multi_rpc::deployment::DeploymentDispatchBinding::capture(
                        &owner.route.evidence.witness,
                        &owner.route.evidence.connection,
                    )?,
                )
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let now = wall_clock_ns()?;
        if now / 1_000_000 >= owner.admission.valid_until_ms {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let grant = self.request.authorize_invocation()?;
        let wallet = grant.submission_wallet()?;
        let scope = grant.authorization.facts();
        if now >= grant.valid_until_ns
            || scope.actor_principal_id != owner.admission.owner.actor_principal_id
            || scope.participant_id != owner.admission.owner.participant_id
            || scope.privacy_domain_id != owner.admission.owner.privacy_domain_id
            || scope.workload_id != owner.admission.owner.workload_id
            || wallet.id() != owner.admission.wallet_binding_id
            || wallet.epoch() != owner.admission.wallet_binding_epoch
            || identity_vector(&grant)? != owner.admission.identity_vector_digest
            || self.request.state().active().capsule().digest()? != owner.admission.capsule_digest
            || self
                .request
                .state()
                .route_for_request(owner.route.request.decoded().request())?
                .provider_profile()?
                .provider_instance_id
                != owner.command.provider_instance_id
            || self
                .request
                .state()
                .runtime_resource(owner.route.request.decoded().request())?
                != owner.admission.runtime_binding_id
            || Digest::of(canonical_bytes(self.request.transaction_policy()?)?)
                != owner.admission.transaction_policy_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        owner
            .route
            .validate_committed_decision(self.request.state(), &owner.decision, now)?;
        owner.route.validate_state(self.request.state())?;
        self.facts
            .revalidate()
            .map_err(|_| RuntimeError::GenerationMismatch)
    }
}

fn identity_vector(grant: &WorkloadAuthorization) -> RuntimeResult<Digest> {
    Digest::parse(
        grant
            .identity
            .authority_vector_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}
