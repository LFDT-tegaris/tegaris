//! Purpose-separated attestation by the existing reservation worker. This
//! proves only committed HANDOFF custody; PDS, workload identity and the final
//! live provider fence independently decide whether Broker may start an attempt.
use super::{bind_publication, intent::PreparedDeploymentIntent};
use crate::{signed_transaction::SignedTransaction, submission_operation::DeploymentSubmission};
use pc_policy_core::deployment_policy::AdmittedDeploymentPolicy;
use pc_runtime_types::{
    Digest, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope, canonical_bytes,
};
use serde::{Deserialize, Serialize};

pub const HANDOFF_PURPOSE: &str = "openpc:deployment-address-handoff:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentHandoff {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_command_id: Option<String>,
    pub command_id: String,
    pub attempt_id: String,
    pub reservation_binding_digest: Digest,
    pub publication_digest: Digest,
    pub candidate_digest: Digest,
    pub authorization_evidence_digest: Digest,
    pub workload_peer_binding_digest: Digest,
    pub identity_vector_digest: Digest,
    pub handoff_at_ms: u64,
    pub expires_at_ms: u64,
}

/// No deserialization or public constructor. Its producer verifies the pinned
/// worker key and independently re-derives the global reservation identity.
#[derive(Clone, Debug)]
pub struct VerifiedDeploymentHandoff {
    submission: DeploymentSubmission,
    claims: DeploymentHandoff,
}

impl VerifiedDeploymentHandoff {
    pub fn verify(
        worker_public_key: &[u8],
        signed: &SignedEnvelope<DeploymentHandoff>,
        prepared: &PreparedDeploymentIntent,
        publication: &AdmittedDeploymentPolicy,
        transaction: &SignedTransaction,
        now_ms: u64,
    ) -> RuntimeResult<Self> {
        PurposeVerifier::from_sec1_bytes(HANDOFF_PURPOSE, worker_public_key)?.verify(signed)?;
        let claims = &signed.claims;
        let context = prepared.context();
        if claims.predecessor_command_id.as_ref().is_some_and(|id| {
            id == &claims.command_id
                || !uuid::Uuid::try_parse(id)
                    .is_ok_and(|value| value.get_version_num() == 7 && value.to_string() == *id)
        }) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if context.workload_binding_id.is_none()
            || claims.handoff_at_ms < context.issued_at_ms
            || claims.handoff_at_ms > now_ms
            || now_ms >= claims.expires_at_ms
            || claims.expires_at_ms > context.expires_at_ms
            || [
                &claims.candidate_digest,
                &claims.authorization_evidence_digest,
                &claims.workload_peer_binding_digest,
                &claims.identity_vector_digest,
            ]
            .contains(&&Digest::of([]))
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let binding = prepared.reservation_binding(
            publication,
            transaction,
            &claims.command_id,
            &claims.attempt_id,
            now_ms,
        )?;
        let publication_digest = Digest::of(canonical_bytes(
            &serde_json::to_value(publication).map_err(|_| RuntimeError::InvalidInput)?,
        )?);
        if claims.reservation_binding_digest != Digest::of(canonical_bytes(&binding)?)
            || claims.publication_digest != publication_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let (constraints, _) = bind_publication(publication, transaction, now_ms)?;
        Ok(Self {
            claims: claims.clone(),
            submission: DeploymentSubmission {
                predecessor_command_id: claims.predecessor_command_id.clone(),
                command_id: claims.command_id.clone(),
                attempt_id: claims.attempt_id.clone(),
                deployment_policy_id: publication.deployment_policy_id.clone(),
                intent_id: context.intent_id.clone(),
                intent_digest: prepared.intent_digest().clone(),
                preparation_digest: prepared.record_digest()?,
                publication_digest,
                reservation_binding_digest: claims.reservation_binding_digest.clone(),
                preparation_expires_at_ms: claims.expires_at_ms,
                native_value_authorization_digest: prepared
                    .native_value_authorization_digest()
                    .cloned(),
                transaction: Some(transaction.into()),
                dispatch: None, // Filled by the live route owner immediately before Broker admission.
                constraints,
            },
        })
    }

    pub fn submission(&self) -> &DeploymentSubmission {
        &self.submission
    }
    pub fn claims(&self) -> &DeploymentHandoff {
        &self.claims
    }
}
