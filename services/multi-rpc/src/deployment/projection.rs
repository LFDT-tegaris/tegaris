//! Signed operational projection of the existing deployment journal. The
//! envelope is transport evidence; it cannot submit, reserve or grant control.
use crate::{
    journal::{SenderBoundary, WriteJournal},
    submission_operation::{SubmissionAdmission, SubmissionOwner},
    submission_status::OperationStatusView,
};
use pc_runtime_types::{
    Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope,
    canonical_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PURPOSE: &str = "openpc:deployment-journal-projection:v1";
pub const MAX_BYTES: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentProjection {
    schema: String,
    target_runtime_id: String,
    owner: SubmissionOwner,
    intent_digest: Digest,
    preparation_digest: Digest,
    chain_environment_id: String,
    chain_id: String,
    genesis_digest: Digest,
    sequence: String,
    journal_sequence: String,
    observed_at: String,
    status: OperationStatusView,
    outcome: Value,
}

/// Supplied by the Control reservation/preparation owner, never an API caller.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionExpectation {
    pub target_runtime_id: String,
    pub owner: SubmissionOwner,
    pub command_id: String,
    pub attempt_id: String,
    pub intent_digest: Digest,
    pub preparation_digest: Digest,
    pub chain_id: String,
    pub genesis_digest: Digest,
    pub transaction_hash: String,
}

pub struct VerifiedDeploymentProjection {
    claims: DeploymentProjection,
    digest: Digest,
}
impl VerifiedDeploymentProjection {
    pub fn claims(&self) -> &DeploymentProjection {
        &self.claims
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Rebind immutable chain/artifact/context facts independently of the target.
    /// Historical preparation is readable after expiry; this authorizes no send.
    pub fn verify_preparation(
        &self,
        prepared: &super::intent::PreparedDeploymentIntent,
        publication: &pc_policy_core::deployment_policy::AdmittedDeploymentPolicy,
    ) -> RuntimeResult<()> {
        let claims = &self.claims;
        let context = prepared.context();
        if context.participant_id != claims.owner.participant_id
            || context.privacy_domain_id != claims.owner.privacy_domain_id
            || context.actor_subject_id != claims.owner.actor_principal_id
            || context.workload_binding_id.as_ref() != Some(&claims.owner.workload_id)
            || context.target_runtime_id != claims.target_runtime_id
            || context.chain_environment_id != claims.chain_environment_id
            || prepared.record_digest()? != claims.preparation_digest
            || prepared.intent_digest() != &claims.intent_digest
            || prepared.genesis_digest() != &claims.genesis_digest
            || prepared.unsigned().chain_id().to_string() != claims.chain_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let occurrence = &claims.outcome["occurrence"];
        if occurrence.is_null() {
            return Ok(());
        }
        let direct = matches!(
            publication.definition.route,
            pc_policy_core::deployment_policy::DeploymentRouteDefinition::TransactionCreate
        );
        let mechanism = match publication.definition.route {
            pc_policy_core::deployment_policy::DeploymentRouteDefinition::TransactionCreate => None,
            pc_policy_core::deployment_policy::DeploymentRouteDefinition::Create { .. } => {
                Some("CREATE")
            }
            pc_policy_core::deployment_policy::DeploymentRouteDefinition::Create2 { .. } => {
                Some("CREATE2")
            }
            pc_policy_core::deployment_policy::DeploymentRouteDefinition::Create3 { .. } => {
                Some("CREATE3")
            }
        };
        if occurrence["runtimeCodeHash"].as_str()
            != publication
                .definition
                .artifact
                .runtime_code_hash
                .strip_prefix("0x")
            || prepared
                .expected_contract_address()
                .is_some_and(|address| occurrence["derivedContractAddress"] != address)
            || occurrence["rootCreationAttempts"] != u8::from(direct)
            || occurrence["childCreationAttempts"]
                != if mechanism == Some("CREATE3") {
                    2
                } else {
                    u8::from(!direct)
                }
            || (direct
                && (occurrence.get("schemaVersion").is_some()
                    || occurrence["receiptContractAddress"]
                        != occurrence["derivedContractAddress"]))
            || (!direct
                && (occurrence["schemaVersion"] != "PC-FACTORY-DEPLOYMENT-OCCURRENCE-1"
                    || occurrence["creationMechanism"].as_str() != mechanism
                    || !occurrence["receiptContractAddress"].is_null()
                    || publication
                        .factory_binding
                        .as_ref()
                        .is_none_or(|factory| occurrence["creator"] != factory.contract_address)))
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    pub fn verify_association(
        &self,
        bytes: &[u8],
        activation: &Self,
        association_id: &str,
        prepared: &super::intent::PreparedDeploymentIntent,
    ) -> RuntimeResult<Value> {
        if bytes.len() > 4096
            || self.claims.owner != activation.claims.owner
            || self.claims.status.operation_id != activation.claims.status.operation_id
            || self.claims.sequence()? < activation.claims.sequence()?
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let document: Value =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        check_document(&document)?;
        let occurrence = &activation.claims.outcome["occurrence"];
        let invalidation = &self.claims.outcome["invalidation"];
        let state = if invalidation.is_null() {
            "ACTIVE"
        } else {
            "SUSPENDED_REORG"
        };
        if document.as_object().is_none_or(|object| object.len() != 13)
            || occurrence.is_null()
            || document["associationId"] != association_id
            || document["occurrenceId"] != occurrence["occurrenceId"]
            || document["occurrenceDigest"] != occurrence["semanticDigest"]
            || document["contractAddress"] != occurrence["derivedContractAddress"]
            || document["chainEnvironmentId"] != self.claims.chain_environment_id
            || document["chainId"] != self.claims.chain_id
            || document["genesisHash"] != self.claims.genesis_digest.as_str()
            || document["controllerParticipantId"] != self.claims.owner.participant_id
            || document["controllerParticipantEpoch"] != prepared.context().participant_epoch
            || document["controllerGeneration"] != 1
            || document["state"] != state
            || (state == "ACTIVE" && self.claims.outcome["occurrence"] != *occurrence)
            || (state == "SUSPENDED_REORG"
                && (invalidation["occurrenceId"] != occurrence["occurrenceId"]
                    || invalidation["occurrenceDigest"] != occurrence["semanticDigest"]))
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        time::OffsetDateTime::parse(
            document["activatedAt"]
                .as_str()
                .ok_or(RuntimeError::InvalidInput)?,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        if crate::rfc8785_canonical_bytes(&document).map_err(|_| RuntimeError::CanonicalEncoding)?
            != bytes
        {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(document)
    }
}

impl DeploymentProjection {
    pub fn operation_id(&self) -> &str {
        self.status
            .operation_id
            .strip_prefix("urn:openpc:operation:")
            .unwrap_or_default()
    }
    pub fn target_id(&self) -> &str {
        &self.target_runtime_id
    }
    pub fn owner(&self) -> &SubmissionOwner {
        &self.owner
    }
    pub fn sequence(&self) -> RuntimeResult<u64> {
        self.sequence
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == self.sequence)
            .ok_or(RuntimeError::InvalidInput)
    }
    pub fn journal_sequence(&self) -> RuntimeResult<u64> {
        self.journal_sequence
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == self.journal_sequence)
            .ok_or(RuntimeError::InvalidInput)
    }
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
    pub fn status(&self) -> &OperationStatusView {
        &self.status
    }
    pub fn outcome(&self) -> &Value {
        &self.outcome
    }
    pub fn chain_environment_id(&self) -> &str {
        &self.chain_environment_id
    }
    pub fn sign(&self, signer: &PurposeSigner) -> RuntimeResult<Vec<u8>> {
        let envelope = signer.sign(self.clone())?;
        if envelope.purpose != PURPOSE {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bytes = canonical_bytes(&envelope)?;
        if bytes.len() > MAX_BYTES {
            return Err(RuntimeError::ResponseWithheld);
        }
        Ok(bytes)
    }

    pub fn verify(
        bytes: &[u8],
        public_key: &[u8],
        expected: &ProjectionExpectation,
    ) -> RuntimeResult<VerifiedDeploymentProjection> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(RuntimeError::InvalidInput);
        }
        let envelope: SignedEnvelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        // Reject unknown envelope fields, duplicate keys and alternate encodings.
        if canonical_bytes(&envelope)? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        PurposeVerifier::from_sec1_bytes(PURPOSE, public_key)?.verify(&envelope)?;
        let claims = envelope.claims;
        if claims.schema != "PC-DEPLOYMENT-JOURNAL-PROJECTION-1"
            || claims.target_runtime_id != expected.target_runtime_id
            || claims.owner != expected.owner
            || claims.intent_digest != expected.intent_digest
            || claims.preparation_digest != expected.preparation_digest
            || claims.chain_id != expected.chain_id
            || claims.genesis_digest != expected.genesis_digest
            || claims.status.operation_id != format!("urn:openpc:operation:{}", expected.command_id)
            || claims.status.attempt_id != expected.attempt_id
            || claims.status.signed_transaction_hash != expected.transaction_hash
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        claims.sequence()?;
        claims.journal_sequence()?;
        super::occurrence::valid_id(&claims.chain_environment_id)?;
        time::OffsetDateTime::parse(
            &claims.observed_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        if claims.outcome == no_attempt_outcome() {
            if claims.status.state != "REJECTED" || claims.status.truth_state != "DENIED" {
                return Err(RuntimeError::InvalidAuthorization);
            }
            return Ok(VerifiedDeploymentProjection {
                claims,
                digest: Digest::of(bytes),
            });
        }
        if claims.status.state == "PREPARED"
            || (claims.status.state == "REJECTED" && claims.status.truth_state == "DENIED")
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // Reuse the occurrence owner's exact wire model, including required
        // nulls and factory-only optional fields. No parallel readback schema.
        let typed: super::occurrence::DeploymentOutcome =
            serde_json::from_value(claims.outcome.clone())
                .map_err(|_| RuntimeError::InvalidInput)?;
        if serde_json::to_value(typed).map_err(|_| RuntimeError::InvalidInput)? != claims.outcome {
            return Err(RuntimeError::CanonicalEncoding);
        }
        let attempt = &claims.outcome["attempt"];
        if attempt["operationId"] != expected.command_id
            || attempt["attemptId"] != expected.attempt_id
            || attempt["signedTransactionHash"].as_str()
                != expected.transaction_hash.strip_prefix("0x")
            || attempt["writeState"] != "ATTEMPT_STARTED"
            || attempt["attemptOrdinal"] != 1
            || attempt["durableAttemptRecordedBeforeSend"] != true
            || attempt["automaticRetryAllowed"] != false
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        check_document(attempt)?;
        for name in ["attemptId", "operationId", "grantId", "providerId"] {
            super::occurrence::valid_id(attempt[name].as_str().ok_or(RuntimeError::InvalidInput)?)?;
        }
        let occurrence = &claims.outcome["occurrence"];
        let invalidation = &claims.outcome["invalidation"];
        if claims.status.state == "CONFIRMED"
            && claims.status.truth_state == "SUCCESS"
            && occurrence.is_null()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if !occurrence.is_null() {
            check_document(occurrence)?;
            if !invalidation.is_null()
                || occurrence["intentDigest"] != claims.intent_digest.as_str()
                || occurrence["attemptDigest"] != attempt["semanticDigest"]
                || occurrence["signedTransactionHash"] != attempt["signedTransactionHash"]
                || occurrence["finality"] != "FINALIZED"
                || occurrence["reorgStatus"] != "CANONICAL"
                || occurrence["receiptStatus"] != 1
                || occurrence["creationGraphComplete"] != true
                || occurrence["runtimeCodePresent"] != true
                || occurrence["internalNativeTransfers"] != 0
                || claims.status.state != "CONFIRMED"
                || claims.status.truth_state != "SUCCESS"
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        if !invalidation.is_null()
            && !matches!(
                (
                    claims.status.state.as_str(),
                    claims.status.truth_state.as_str()
                ),
                ("REORG", "REORG") | ("FAILED", "UNAVAILABLE")
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if !invalidation.is_null() {
            super::occurrence::valid_id(
                invalidation["occurrenceId"]
                    .as_str()
                    .ok_or(RuntimeError::InvalidInput)?,
            )?;
            let reason = if claims.status.state == "REORG" {
                "REORG"
            } else {
                "CODE_IDENTITY_MISMATCH"
            };
            if invalidation["reason"] != reason {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        Ok(VerifiedDeploymentProjection {
            claims,
            digest: Digest::of(bytes),
        })
    }
}

// A durable no-send rejection has an allocated operation/attempt ID, but no
// deployment attempt: that document exists only after verified STARTED.
fn no_attempt_outcome() -> Value {
    serde_json::json!({"attempt": null, "occurrence": null, "invalidation": null})
}

fn check_document(document: &Value) -> RuntimeResult<()> {
    let mut content = document
        .as_object()
        .ok_or(RuntimeError::InvalidInput)?
        .clone();
    let digest = content
        .remove("semanticDigest")
        .ok_or(RuntimeError::InvalidInput)?;
    if digest.as_str()
        != Some(
            Digest::of(
                crate::rfc8785_canonical_bytes(&Value::Object(content))
                    .map_err(|_| RuntimeError::CanonicalEncoding)?,
            )
            .as_str(),
        )
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

impl WriteJournal {
    /// One result at a time bounds allocation and includes terminal invalidated
    /// deployments, which no longer belong to the observation scheduler.
    pub fn next_deployment_projection(
        &self,
        after: u64,
    ) -> RuntimeResult<(u64, Option<DeploymentProjection>)> {
        self.ensure_healthy()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        // The journal owns the ordered identities; no caller can fabricate an
        // admission or replace the original dispatch with a recovery witness.
        self.deployment_projection_after(after)
    }
}

pub(crate) fn capture(
    journal: &WriteJournal,
    command_id: &str,
    admission: &SubmissionAdmission,
    head: &SenderBoundary,
    journal_sequence: u64,
) -> RuntimeResult<Option<DeploymentProjection>> {
    let Some(deployment) = &admission.deployment else {
        return Ok(None);
    };
    let outcome = match journal.deployment_outcome(command_id, &admission.owner)? {
        Some(outcome) => serde_json::to_value(outcome).map_err(|_| RuntimeError::InvalidInput)?,
        None if deployment.dispatch.is_some()
            && head.transition == crate::journal::JournalState::FailedPreStart
            && head.terminal
            && !head.automatic_attempt_started
            && head.automatic_resubmission_prohibited =>
        {
            no_attempt_outcome()
        }
        None => return Ok(None),
    };
    let chain = admission
        .chain
        .as_ref()
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let status = journal
        .submission_projection_view(command_id, &admission.owner)?
        .ok_or(RuntimeError::RuntimeUnavailable)?;
    Ok(Some(DeploymentProjection {
        schema: "PC-DEPLOYMENT-JOURNAL-PROJECTION-1".into(),
        target_runtime_id: admission.target_runtime_id.clone(),
        owner: admission.owner.clone(),
        intent_digest: deployment.intent_digest.clone(),
        preparation_digest: deployment.preparation_digest.clone(),
        chain_environment_id: chain.chain_environment_id.clone(),
        chain_id: deployment.constraints.chain_id.to_string(),
        genesis_digest: chain.genesis_digest.clone(),
        sequence: head.state_sequence.to_string(),
        journal_sequence: journal_sequence.to_string(),
        observed_at: head.observed_at.clone(),
        status,
        outcome,
    }))
}
