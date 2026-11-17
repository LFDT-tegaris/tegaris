//! Durable operation ownership and admission identity. These are journal
//! records supplied by the live target/Broker owners, never actor grants.
use crate::{
    deployment::DeploymentConstraints, error::JournalError, journal::GovernedCommand,
    signed_transaction::SignedTransaction,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionOwner {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub actor_principal_id: String,
    pub workload_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionChain {
    pub chain_environment_id: String,
    pub network_id: String,
    pub genesis_digest: Digest,
}

/// Exact creation identity retained by the existing submission journal. These
/// owner-resolved bindings are not a reservation handoff or a permission to send.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSubmission {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_command_id: Option<String>,
    /// Allocated by the deployment owner before global address reservation.
    /// Broker must retain these exact IDs, never create a second attempt.
    pub command_id: String,
    pub attempt_id: String,
    pub deployment_policy_id: String,
    pub intent_id: String,
    pub intent_digest: Digest,
    pub preparation_digest: Digest,
    pub publication_digest: Digest,
    pub reservation_binding_digest: Digest,
    pub preparation_expires_at_ms: u64,
    pub constraints: DeploymentConstraints,
    /// Copied only from the independently verified preparation and one-use
    /// handoff. This retained reference is not a standalone Native Value grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_value_authorization_digest: Option<Digest>,
    /// Minimized verified transaction fields needed to check mined creation
    /// traces after restart; never retain signed bytes or constructor calldata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<DeploymentTransactionIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<crate::deployment::DeploymentDispatchBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTransactionIdentity {
    pub value: [u8; 32],
    pub calldata_hash: [u8; 32],
    pub gas_limit: u64,
}

impl DeploymentSubmission {
    fn validate_endowment(&self, value: &[u8; 32]) -> Result<(), JournalError> {
        match (&self.native_value_authorization_digest, value == &[0; 32]) {
            (None, true) => Ok(()),
            (Some(digest), false)
                if self.transaction.is_some()
                    && matches!(
                        self.constraints.route,
                        crate::deployment::DeploymentRoute::DirectCreate { .. }
                    )
                    && Digest::parse(digest.as_str()).is_ok()
                    && *digest != Digest::of([]) =>
            {
                Ok(())
            }
            _ => Err(JournalError::IdentityMismatch),
        }
    }
}
impl From<&SignedTransaction> for DeploymentTransactionIdentity {
    fn from(transaction: &SignedTransaction) -> Self {
        Self {
            value: *transaction.value(),
            calldata_hash: crate::deployment::keccak(transaction.data()),
            gas_limit: transaction.gas_limit(),
        }
    }
}

/// The capsule binds the contract-set, registry, profile and evidence owners;
/// their exact identities remain available after the active capsule changes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionAdmission {
    pub owner: SubmissionOwner,
    pub target_runtime_id: String,
    pub runtime_binding_id: String,
    /// Operation classification retained from the admitted routing owner.
    /// Older component records lack it and cannot authorize a new status read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_class: Option<String>,
    /// Exact original authenticated transport identity for outcome-precedence
    /// readback. It grants neither status polling nor another submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_peer_binding_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_witness_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cigl_post_mine: Option<crate::cigl::reconciliation::PostMineExpectation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<SubmissionChain>,
    pub wallet_binding_id: String,
    pub wallet_binding_epoch: u64,
    pub capability_id: String,
    pub decision_id: String,
    pub decision_digest: Digest,
    pub identity_vector_digest: Digest,
    pub capsule_digest: Digest,
    pub contract_set_manifest_digest: Digest,
    pub invocation_profile_digest: Digest,
    pub capability_registry_digest: Digest,
    pub request_form_registry_digest: Digest,
    pub error_registry_digest: Digest,
    pub policy_generation_digest: Digest,
    pub transaction_policy_digest: Digest,
    pub route_witness_set_digest: Digest,
    pub evidence_admission_profile_digest: Digest,
    pub prepared_intent_digest: Option<Digest>,
    // Some preserves the original contract journal encoding. Direct creation
    // omits both fields; it never substitutes a synthetic contract or selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<[u8; 20]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<[u8; 4]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentSubmission>,
    pub admitted_at_ms: u64,
    pub valid_until_ms: u64,
}

impl SubmissionAdmission {
    pub(crate) fn transaction_destination(&self) -> Option<&[u8; 20]> {
        match self
            .deployment
            .as_ref()
            .map(|deployment| &deployment.constraints.route)
        {
            Some(crate::deployment::DeploymentRoute::DirectCreate { .. }) => None,
            Some(crate::deployment::DeploymentRoute::Factory(factory)) => Some(&factory.address),
            None => self.contract_address.as_ref(),
        }
    }

    pub(crate) fn observation_call_budget(&self) -> usize {
        match self
            .deployment
            .as_ref()
            .map(|deployment| &deployment.constraints.route)
        {
            None => 8 + usize::from(self.cigl_post_mine.is_some()) * 2,
            Some(crate::deployment::DeploymentRoute::DirectCreate { .. }) => {
                if self
                    .deployment
                    .as_ref()
                    .is_some_and(|deployment| deployment.transaction.is_some())
                {
                    11
                } else {
                    9 // Historical records retain receipt/code readback, never complete creation evidence.
                }
            }
            Some(crate::deployment::DeploymentRoute::Factory(factory)) => {
                if matches!(
                    factory.mechanism,
                    crate::deployment::FactoryMechanism::Create3 { .. }
                ) {
                    13
                } else {
                    12
                }
            }
        }
    }
    pub fn digest(&self) -> Result<Digest, JournalError> {
        canonical_bytes(self)
            .map(Digest::of)
            .map_err(|_| JournalError::IdentityMismatch)
    }

    pub(crate) fn validate(&self, command: &GovernedCommand) -> Result<(), JournalError> {
        if let Some(expected) = &self.cigl_post_mine {
            expected
                .validate()
                .map_err(|_| JournalError::IdentityMismatch)?;
            if self.deployment.is_some() || self.preflight_witness_digest.is_none() {
                return Err(JournalError::IdentityMismatch);
            }
        }
        match (&self.contract_address, &self.selector, &self.deployment) {
            (Some(_), Some(_), None) => {}
            (None, None, Some(deployment)) => {
                if let Some(dispatch) = &deployment.dispatch {
                    dispatch
                        .validate()
                        .map_err(|_| JournalError::IdentityMismatch)?;
                    for id in [
                        &command.command_id,
                        &command.attempt_id,
                        &command.provider_instance_id,
                        &self.capability_id,
                    ] {
                        crate::deployment::occurrence::valid_id(id)
                            .map_err(|_| JournalError::IdentityMismatch)?;
                    }
                }
                deployment.validate_endowment(
                    &deployment
                        .transaction
                        .as_ref()
                        .map_or([0; 32], |identity| identity.value),
                )?;
                if deployment
                    .transaction
                    .as_ref()
                    .is_some_and(|identity| identity.gas_limit == 0)
                    || (matches!(
                        deployment.constraints.route,
                        crate::deployment::DeploymentRoute::Factory(_)
                    ) && deployment.transaction.is_none())
                {
                    return Err(JournalError::IdentityMismatch);
                }
                if deployment.command_id != command.command_id
                    || deployment.attempt_id != command.attempt_id
                    || [&deployment.command_id, &deployment.attempt_id]
                        .iter()
                        .any(|value| {
                            !uuid::Uuid::try_parse(value).is_ok_and(|id| {
                                id.get_version_num() == 7 && id.to_string() == **value
                            })
                        })
                    || [&deployment.deployment_policy_id, &deployment.intent_id]
                        .iter()
                        .any(|value| {
                            value.is_empty()
                                || value.len() > 256
                                || value.chars().any(char::is_control)
                        })
                    || self.runtime_binding_id != deployment.deployment_policy_id
                    || self.prepared_intent_digest.as_ref() != Some(&deployment.intent_digest)
                    || self.preflight_witness_digest.is_none()
                    || self.chain.is_none()
                    || self.valid_until_ms > deployment.preparation_expires_at_ms
                {
                    return Err(JournalError::IdentityMismatch);
                }
                for digest in [
                    &deployment.intent_digest,
                    &deployment.preparation_digest,
                    &deployment.publication_digest,
                    &deployment.reservation_binding_digest,
                    &deployment.constraints.profile_digest,
                ] {
                    if Digest::parse(digest.as_str()).is_err() || *digest == Digest::of([]) {
                        return Err(JournalError::IdentityMismatch);
                    }
                }
            }
            _ => return Err(JournalError::IdentityMismatch),
        }
        if let Some(chain) = &self.chain
            && ([&chain.chain_environment_id, &chain.network_id]
                .iter()
                .any(|value| {
                    value.is_empty() || value.len() > 160 || value.chars().any(char::is_control)
                })
                || Digest::parse(chain.genesis_digest.as_str()).is_err()
                || chain.genesis_digest == Digest::of([]))
        {
            return Err(JournalError::IdentityMismatch);
        }
        if self.risk_class.as_ref().is_some_and(|risk| {
            risk.is_empty() || risk.len() > 64 || risk.chars().any(char::is_control)
        }) {
            return Err(JournalError::IdentityMismatch);
        }
        if self
            .workload_peer_binding_digest
            .as_ref()
            .is_some_and(|digest| {
                Digest::parse(digest.as_str()).is_err() || *digest == Digest::of([])
            })
        {
            return Err(JournalError::IdentityMismatch);
        }
        if [
            &self.owner.participant_id,
            &self.owner.privacy_domain_id,
            &self.owner.actor_principal_id,
            &self.owner.workload_id,
            &self.target_runtime_id,
            &self.runtime_binding_id,
            &self.wallet_binding_id,
            &self.capability_id,
            &self.decision_id,
        ]
        .iter()
        .any(|text| text.is_empty() || text.len() > 256 || text.chars().any(char::is_control))
            || self.owner.participant_id != command.participant_id
            || self.owner.privacy_domain_id != command.privacy_domain_id
            || self.wallet_binding_epoch == 0
            || self.admitted_at_ms == 0
            || self.valid_until_ms <= self.admitted_at_ms
            || self.valid_until_ms - self.admitted_at_ms
                > pc_policy_core::transaction_policy::MAX_TRANSACTION_DEADLINE_MS
            || command.method != "eth_sendRawTransaction"
            || uuid::Uuid::try_parse(&command.command_id).is_err()
        {
            return Err(JournalError::IdentityMismatch);
        }
        for digest in [
            &self.decision_digest,
            &self.identity_vector_digest,
            &self.capsule_digest,
            &self.contract_set_manifest_digest,
            &self.invocation_profile_digest,
            &self.capability_registry_digest,
            &self.request_form_registry_digest,
            &self.error_registry_digest,
            &self.policy_generation_digest,
            &self.transaction_policy_digest,
            &self.route_witness_set_digest,
            &self.evidence_admission_profile_digest,
        ]
        .into_iter()
        .chain(self.prepared_intent_digest.iter())
        .chain(self.preflight_witness_digest.iter())
        {
            if Digest::parse(digest.as_str()).is_err() || *digest == Digest::of([]) {
                return Err(JournalError::IdentityMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn validate_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<(), JournalError> {
        if let Some(expected) = &self.cigl_post_mine {
            expected
                .validate_transaction(transaction)
                .map_err(|_| JournalError::IdentityMismatch)?;
        }
        match (&self.contract_address, &self.selector, &self.deployment) {
            (Some(address), Some(selector), None)
                if transaction.destination() == Some(address)
                    && transaction.data().get(..4) == Some(selector.as_slice()) => {}
            (None, None, Some(deployment)) => {
                deployment.validate_endowment(transaction.value())?;
                if deployment.transaction.as_ref().is_some_and(|identity| {
                    identity != &DeploymentTransactionIdentity::from(transaction)
                }) || (matches!(
                    deployment.constraints.route,
                    crate::deployment::DeploymentRoute::Factory(_)
                ) && deployment.transaction.is_none())
                {
                    return Err(JournalError::IdentityMismatch);
                }
                deployment
                    .constraints
                    .bind(transaction)
                    .map_err(|_| JournalError::IdentityMismatch)?;
            }
            _ => return Err(JournalError::IdentityMismatch),
        }
        Ok(())
    }

    /// Shared Broker request binding. Runtime policy and the final live authority
    /// lease remain mandatory for either kind of signed transaction.
    pub fn validate_runtime_request(
        &self,
        request: &RuntimeRequest,
        transaction: &SignedTransaction,
    ) -> RuntimeResult<()> {
        self.validate_transaction(transaction)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        if let Some(deployment) = &self.deployment {
            crate::governed_write::validate_runtime_signed_command(request, transaction)?;
            if request.invocation.is_some()
                || request.deployment.as_ref().is_none_or(|identity| {
                    identity.deployment_policy_id != deployment.deployment_policy_id
                        || identity.intent_digest != deployment.intent_digest
                })
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            Ok(())
        } else {
            if request.deployment.is_some() {
                return Err(RuntimeError::InvalidAuthorization);
            }
            crate::governed_write::validate_runtime_submission(request, transaction)
        }
    }
}
