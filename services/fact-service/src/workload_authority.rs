//! Workload authentication through the existing Identity mTLS owner. Only a
//! successful pinned TLS exchange can construct the input to Control admission.
use base64ct::{Base64, Encoding};
use openpc_multi_rpc::provider_connection::{
    DestinationPolicy, EndpointDescriptor, LocalTlsMaterial, ProviderConnection, Resolution,
};
use openpc_pds::{IdentityAssertionEvidence, IdentityAssertionVerifier};
use pc_policy_core::identity_context::RuntimeIdentityContext;
use pc_runtime_types::Digest;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

mod current;
mod snapshot;
#[cfg(test)]
mod tests;
pub use current::FactWorkloadAdmission;

pub(crate) const ACTION: &str = "ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1";
pub(crate) type Result<T> = std::result::Result<T, WorkloadAuthorityError>;

#[derive(Debug, thiserror::Error)]
pub enum WorkloadAuthorityError {
    #[error("FACT-WORKLOAD-AUTHENTICATION")]
    Authentication,
    #[error("FACT-WORKLOAD-AUTHORITY")]
    Authority,
    #[error("FACT-WORKLOAD-EXPIRED")]
    Expired,
    #[error("FACT-WORKLOAD-DATABASE")]
    Database(#[from] sqlx::Error),
}

/// Deployment trust, never part of a candidate or caller request.
pub struct FactIdentityTrust {
    verifier: IdentityAssertionVerifier,
    profile_digest: [u8; 32],
    signer_id: String,
}
impl FactIdentityTrust {
    pub fn new(
        public_keys_spki_der: &[Vec<u8>],
        profile_digest: [u8; 32],
        signer_id: String,
    ) -> Result<Self> {
        if profile_digest == [0; 32] || signer_id.is_empty() || signer_id.len() > 160 {
            return Err(WorkloadAuthorityError::Authority);
        }
        Ok(Self {
            verifier: IdentityAssertionVerifier::new(public_keys_spki_der, 60_000)
                .map_err(|_| WorkloadAuthorityError::Authority)?,
            profile_digest,
            signer_id,
        })
    }
}

pub struct FactWorkloadAuthenticator {
    connection: ProviderConnection,
    certificate_digest: [u8; 32],
}
impl FactWorkloadAuthenticator {
    pub fn prepare(
        endpoint: &EndpointDescriptor,
        destination: &DestinationPolicy,
        resolution: Resolution,
        tls: LocalTlsMaterial,
    ) -> Result<Self> {
        if endpoint.path != "/internal/v1/workload/authenticate" {
            return Err(WorkloadAuthorityError::Authentication);
        }
        let leaf = tls
            .client_chain
            .first()
            .ok_or(WorkloadAuthorityError::Authentication)?;
        let certificate_digest = pc_facts_core::sha256(leaf.as_ref());
        let endpoint = endpoint
            .prepare(destination, resolution)
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        let connection = ProviderConnection::prepare(endpoint, tls, 1024, 65_536)
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        Ok(Self {
            connection,
            certificate_digest,
        })
    }

    /// Identity-only check for opening a candidate-store session. This does not
    /// grant a Fact action, authorize a secret recipient, or publish a runtime.
    pub(crate) async fn authenticate_peer(&self, participant: Uuid) -> Result<()> {
        let bytes = self
            .connection
            .post_json(b"{}".to_vec(), Instant::now() + Duration::from_secs(5))
            .await
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        let reply: AuthenticationReply =
            serde_json::from_slice(&bytes).map_err(|_| WorkloadAuthorityError::Authentication)?;
        reply.validate_peer(participant)?;
        if reply.runtime.is_some() {
            return Err(WorkloadAuthorityError::Authentication);
        }
        Ok(())
    }

    /// Call before acquiring the Control lease: publication holds the same
    /// Participant root fence, and calling it while holding custody deadlocks.
    pub async fn authenticate(
        &self,
        context: RuntimeIdentityContext,
    ) -> Result<AuthenticatedFactWorkload> {
        for value in [
            &context.participant_id,
            &context.privacy_domain_id,
            &context.target_runtime_id,
        ] {
            if !Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7) {
                return Err(WorkloadAuthorityError::Authentication);
            }
        }
        let request = serde_json::to_vec(&serde_json::json!({"runtimeContext": {
            "privacyDomainId": context.privacy_domain_id,
            "targetRuntimeId": context.target_runtime_id,
        }}))
        .map_err(|_| WorkloadAuthorityError::Authentication)?;
        let bytes = self
            .connection
            .post_json(request, Instant::now() + Duration::from_secs(5))
            .await
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        let mut reply: AuthenticationReply =
            serde_json::from_slice(&bytes).map_err(|_| WorkloadAuthorityError::Authentication)?;
        reply.validate_peer(
            Uuid::parse_str(&context.participant_id)
                .map_err(|_| WorkloadAuthorityError::Authentication)?,
        )?;
        if reply.participant_id.to_string() != context.participant_id {
            return Err(WorkloadAuthorityError::Authentication);
        }
        let publication = reply
            .runtime
            .take()
            .ok_or(WorkloadAuthorityError::Authentication)?;
        if publication.snapshot_id.get_version_num() != 7 {
            return Err(WorkloadAuthorityError::Authentication);
        }
        let key_digest = prefixed_digest(&reply.key_id)?;
        let cose_sign1 = Base64::decode_vec(&publication.assertion_cose_sign1)
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        let assertion = IdentityAssertionEvidence::from_cose_sign1(&cose_sign1)
            .map_err(|_| WorkloadAuthorityError::Authentication)?;
        if assertion.payload_cbor
            != Base64::decode_vec(&publication.assertion_payload)
                .map_err(|_| WorkloadAuthorityError::Authentication)?
        {
            return Err(WorkloadAuthorityError::Authentication);
        }
        Ok(AuthenticatedFactWorkload {
            reply,
            publication,
            context,
            key_digest,
            certificate_digest: self.certificate_digest,
            assertion,
        })
    }
}

/// Deliberately no public constructor, Clone, Deserialize or caller-set trust flags.
pub struct AuthenticatedFactWorkload {
    reply: AuthenticationReply,
    publication: PublicationReply,
    context: RuntimeIdentityContext,
    key_digest: [u8; 32],
    certificate_digest: [u8; 32],
    assertion: IdentityAssertionEvidence,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticationReply {
    credential_id: Uuid,
    principal_id: Uuid,
    participant_id: Uuid,
    workload_id: String,
    participant_epoch: String,
    principal_epoch: String,
    workload_epoch: String,
    key_id: String,
    uri_san: String,
    not_before: String,
    not_after: String,
    runtime: Option<PublicationReply>,
}
impl AuthenticationReply {
    fn validate_peer(&self, participant: Uuid) -> Result<()> {
        let workload = self
            .workload_id
            .strip_prefix("urn:openpc:workload:")
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| id.get_version_num() == 7)
            .ok_or(WorkloadAuthorityError::Authentication)?;
        if participant.get_version_num() != 7
            || self.participant_id != participant
            || self.principal_id.get_version_num() != 7
            || self.credential_id.get_version_num() != 7
            || self.uri_san != format!("urn:openpc:participant:{participant}:workload:{workload}")
            || [
                &self.participant_epoch,
                &self.principal_epoch,
                &self.workload_epoch,
            ]
            .iter()
            .any(|v| v.parse::<u64>().is_err())
        {
            return Err(WorkloadAuthorityError::Authentication);
        }
        prefixed_digest(&self.key_id)?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationReply {
    snapshot_id: Uuid,
    manifest_digest: String,
    assertion_payload: String,
    assertion_cose_sign1: String,
    expires_at_ns: String,
}

fn prefixed_digest(value: &str) -> Result<[u8; 32]> {
    let value = value
        .strip_prefix("sha256:")
        .ok_or(WorkloadAuthorityError::Authority)?;
    let digest = Digest::parse(value).map_err(|_| WorkloadAuthorityError::Authority)?;
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest.as_str()[index * 2..index * 2 + 2], 16)
            .map_err(|_| WorkloadAuthorityError::Authority)?;
    }
    Ok(bytes)
}
