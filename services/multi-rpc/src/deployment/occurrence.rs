//! Frozen D1 occurrence and attempt documents from journal-owned execution.
//! Closed factory occurrences are explicitly tagged; they do not impersonate D1.
use super::{DeploymentDispatchBinding, DeploymentRoute, FactoryMechanism, MinedCreationEvidence};
use crate::{journal::GovernedCommand, submission_operation::SubmissionAdmission};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

/// Internal owner readback. These documents do not activate Participant control
/// or grant permission; signed downstream projection has a separate authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentOutcome {
    pub attempt: DeploymentAttemptBinding,
    pub occurrence: Option<DeploymentOccurrence>,
    pub invalidation: Option<DeploymentInvalidation>,
}

/// Revokes the usability of one immutable occurrence. This is observation
/// readback, not a replacement occurrence or permission to repeat the attempt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentInvalidation {
    pub(crate) occurrence_id: String,
    pub(crate) occurrence_digest: Digest,
    pub(crate) reason: String,
    pub(crate) observation_digest: Digest,
}

/// Historical DeploymentAttemptBindingV1 at the durable STARTED boundary.
/// Later observations reference this immutable attempt, never a second send.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentAttemptBinding {
    attempt_id: String,
    operation_id: String,
    grant_id: String,
    signed_transaction_hash: String,
    routing_snapshot_digest: Digest,
    route_witness_digest: Digest,
    dispatcher_binding_digest: Digest,
    provider_id: String,
    durable_attempt_recorded_before_send: bool,
    attempt_ordinal: u8,
    write_state: String,
    automatic_retry_allowed: bool,
    semantic_digest: Digest,
}
impl DeploymentAttemptBinding {
    /// Called only after the journal finds its verified STARTED frame.
    pub(crate) fn started(
        command: &GovernedCommand,
        admission: &SubmissionAdmission,
        dispatch: &DeploymentDispatchBinding,
    ) -> RuntimeResult<Self> {
        dispatch.validate()?;
        for id in [
            &command.command_id,
            &command.attempt_id,
            &admission.capability_id,
            &command.provider_instance_id,
        ] {
            valid_id(id)?;
        }
        let transaction_hash = command
            .request_or_transaction_hash
            .strip_prefix("0x")
            .ok_or(RuntimeError::InvalidAuthorization)?;
        Digest::parse(transaction_hash)?;
        let mut result = Self {
            attempt_id: command.attempt_id.clone(),
            operation_id: command.command_id.clone(),
            grant_id: admission.capability_id.clone(),
            signed_transaction_hash: transaction_hash.into(),
            routing_snapshot_digest: dispatch.routing_snapshot_digest.clone(),
            route_witness_digest: dispatch.route_witness_digest.clone(),
            dispatcher_binding_digest: dispatch.dispatcher_binding_digest.clone(),
            provider_id: command.provider_instance_id.clone(),
            durable_attempt_recorded_before_send: true,
            attempt_ordinal: 1,
            write_state: "ATTEMPT_STARTED".into(),
            automatic_retry_allowed: false,
            semantic_digest: Digest::of([]),
        };
        result.semantic_digest = semantic_digest(&result)?;
        Ok(result)
    }
    pub fn digest(&self) -> &Digest {
        &self.semantic_digest
    }
}

/// Frozen D1 DeploymentOccurrenceV1, or its explicitly tagged closed-factory
/// extension. Factory receipts have a null contractAddress; the complete mined
/// creation graph supplies the derived address instead.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentOccurrence {
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creation_mechanism: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creator: Option<String>,
    occurrence_id: String,
    intent_digest: Digest,
    attempt_digest: Digest,
    signed_transaction_hash: String,
    block_hash: Digest,
    block_number: String,
    receipt_status: u8,
    receipt_contract_address: Option<String>,
    derived_contract_address: String,
    creation_graph_complete: bool,
    root_creation_attempts: u8,
    child_creation_attempts: u8,
    internal_native_transfers: u8,
    runtime_code_hash: String,
    runtime_code_present: bool,
    finality: String,
    reorg_status: String,
    semantic_digest: Digest,
}
impl DeploymentOccurrence {
    /// The journal calls this only for successful canonical FINALIZED state
    /// with complete post-execution evidence. No caller-supplied readiness flag.
    pub(crate) fn finalized(
        admission: &SubmissionAdmission,
        attempt: &DeploymentAttemptBinding,
        block_hash: &Digest,
        block_number: u64,
        creation: &MinedCreationEvidence,
    ) -> RuntimeResult<Self> {
        let deployment = admission
            .deployment
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if attempt.operation_id != deployment.command_id
            || attempt.attempt_id != deployment.attempt_id
            || attempt.grant_id != admission.capability_id
            || !attempt.durable_attempt_recorded_before_send
            || attempt.automatic_retry_allowed
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        creation.validate(&deployment.constraints)?;
        valid_digest(block_hash)?;
        let (mechanism, creator) = match &deployment.constraints.route {
            DeploymentRoute::DirectCreate { .. } => (None, None),
            DeploymentRoute::Factory(factory) => (
                Some(match factory.mechanism {
                    FactoryMechanism::Create => "CREATE",
                    FactoryMechanism::Create2 { .. } => "CREATE2",
                    FactoryMechanism::Create3 { .. } => "CREATE3",
                }),
                Some(hex_address(&factory.address)),
            ),
        };
        let direct = mechanism.is_none();
        let address = hex_address(&creation.address);
        let identity = Digest::of(
            crate::rfc8785_canonical_bytes(&serde_json::json!([
                "openpc:deployment-occurrence-identity:v1",
                &deployment.intent_digest,
                attempt.digest(),
                block_hash,
                &address,
            ]))
            .map_err(|_| RuntimeError::CanonicalEncoding)?,
        );
        let mut result = Self {
            schema_version: mechanism.map(|_| "PC-FACTORY-DEPLOYMENT-OCCURRENCE-1".into()),
            creation_mechanism: mechanism.map(Into::into),
            creator,
            occurrence_id: format!("occurrence:{}", identity.as_str()),
            intent_digest: deployment.intent_digest.clone(),
            attempt_digest: attempt.digest().clone(),
            signed_transaction_hash: attempt.signed_transaction_hash.clone(),
            block_hash: block_hash.clone(),
            block_number: block_number.to_string(),
            receipt_status: 1,
            receipt_contract_address: direct.then(|| address.clone()),
            derived_contract_address: address,
            creation_graph_complete: true,
            root_creation_attempts: u8::from(direct),
            child_creation_attempts: if mechanism == Some("CREATE3") {
                2
            } else {
                u8::from(!direct)
            },
            internal_native_transfers: 0,
            runtime_code_hash: creation
                .runtime_code_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            runtime_code_present: true,
            finality: "FINALIZED".into(),
            reorg_status: "CANONICAL".into(),
            semantic_digest: Digest::of([]),
        };
        result.semantic_digest = semantic_digest(&result)?;
        Ok(result)
    }
    pub fn digest(&self) -> &Digest {
        &self.semantic_digest
    }
    pub fn id(&self) -> &str {
        &self.occurrence_id
    }
    pub fn address(&self) -> &str {
        &self.derived_contract_address
    }
    pub fn document_bytes(&self) -> RuntimeResult<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?;
        crate::rfc8785_canonical_bytes(&value).map_err(|_| RuntimeError::CanonicalEncoding)
    }
}

fn valid_digest(digest: &Digest) -> RuntimeResult<()> {
    Digest::parse(digest.as_str())?;
    if *digest == Digest::of([]) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}
pub(crate) fn valid_id(id: &str) -> RuntimeResult<()> {
    if id.is_empty()
        || id.len() > 128
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}
fn hex_address(address: &[u8; 20]) -> String {
    format!(
        "0x{}",
        address
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn semantic_digest(value: &impl Serialize) -> RuntimeResult<Digest> {
    let mut value = serde_json::to_value(value).map_err(|_| RuntimeError::InvalidInput)?;
    value
        .as_object_mut()
        .ok_or(RuntimeError::InvalidInput)?
        .remove("semanticDigest");
    crate::rfc8785_canonical_bytes(&value)
        .map(Digest::of)
        .map_err(|_| RuntimeError::CanonicalEncoding)
}
