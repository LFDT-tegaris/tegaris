//! Authenticated host consumer of the committed internal Control transport.
//! Bootstrap binds original custody; TLS proves current Control readback. Neither
//! a signed bootstrap nor a successful connection alone grants serving authority.
use super::TargetBootstrapManifest;
use crate::target_disposition_transport::{
    AcknowledgeDispositionRequest, AcknowledgeDispositionResponse, DenyExpiredActivationRequest,
    DenyExpiredActivationResponse, ReadDispositionRequest, ReadDispositionResponse,
    ReadOriginalConfirmationResponse,
};
use openpc_runtime_agent::{
    RuntimeAgent,
    target_disposition::{
        AuthorityFuture, CurrentTargetDisposition, HistoricalTargetConfirmation,
        TargetDispositionAuthority,
    },
};
use pc_runtime_types::{
    Digest, RuntimeError, RuntimeResult,
    target_disposition::{
        TargetDispositionAction, TargetDispositionIdentity, TargetDispositionSource,
    },
};
use serde::{Deserialize, Serialize};
use std::{env, fs, io::Read, path::Path, sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Inside the existing Fleet-signed bootstrap, populated only by the canonical
/// original-work/readback owner. This carries no trust key or readiness flag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDispositionBootstrap {
    pub target: TargetDispositionIdentity,
    pub source: TargetDispositionSource,
    /// Authenticated historical custody only, derived from the completed exact
    /// discovery issuer and the original signed admission by the SQL owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_predecessor: Option<TargetDispositionIdentity>,
}
impl TargetDispositionBootstrap {
    pub(super) fn validate(&self, manifest: &TargetBootstrapManifest) -> RuntimeResult<()> {
        self.validate_identity_lineage()?;
        if self.target.target_id != manifest.target_runtime_id
            || self.target.participant_id != manifest.participant_id
            || self.target.privacy_domain_id != manifest.privacy_domain_id
            || self.source.capsule_digest != manifest.capsule_digest
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(())
    }
    pub(crate) fn validate_identity_lineage(&self) -> RuntimeResult<()> {
        self.target.validate()?;
        self.source.validate()?;
        if let Some(previous) = &self.credential_predecessor {
            previous.validate()?;
            if previous.participant_id != self.target.participant_id
                || previous.privacy_domain_id != self.target.privacy_domain_id
                || previous.target_id != self.target.target_id
                || previous.principal_id != self.target.principal_id
                || previous.principal_epoch != self.target.principal_epoch
                || previous.credential_id == self.target.credential_id
                || previous.certificate_digest == self.target.certificate_digest
                || previous.credential_epoch.checked_add(1) != Some(self.target.credential_epoch)
            {
                return Err(RuntimeError::TargetIdentity);
            }
        }
        Ok(())
    }
}

/// Closed proof read from the actual target journal after a fresh mTLS read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExpiredUnsignedDenialHandover {
    pub abandoned_revision: u64,
    pub abandoned_admission_digest: Digest,
    pub floor: openpc_runtime_agent::target_disposition::ExpiredDenialHandoverFloor,
}

/// Selectors bind the ordinary, already committed rotation. They grant no
/// authority and cannot turn a historical credential into a current one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExpiredDenialCredentialTransition {
    pub predecessor_target: TargetDispositionIdentity,
    pub successor_credential_id: String,
    pub rotation_operation_id: String,
}

/// Ephemeral host composition resolved from the actual scoped Control owner.
/// This is deliberately neither a new signed bootstrap nor serializable.
pub struct ExpiredCredentialDenialConnection {
    binding: TargetDispositionBootstrap,
}

impl ExpiredCredentialDenialConnection {
    pub fn certificate_digest(&self) -> &Digest {
        &self.binding.target.certificate_digest
    }
}

pub async fn read_expired_credential_denial_connection(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    original: &TargetBootstrapManifest,
    expected: &ExpiredDenialCredentialTransition,
) -> RuntimeResult<ExpiredCredentialDenialConnection> {
    use sqlx::Row;
    let previous = original
        .target_disposition
        .as_ref()
        .ok_or(RuntimeError::RuntimeUnavailable)?;
    previous.validate(original)?;
    if expected.predecessor_target != previous.target {
        return Err(RuntimeError::TargetIdentity);
    }
    let certificate = input("CERT_FILE", 64 * 1024)?;
    let peer = crate::runtime_tls::target_identity_from_pem(&certificate)?;
    if peer.target_id != original.target_runtime_id {
        return Err(RuntimeError::TargetIdentity);
    }
    let row=sqlx::query("select binding,rotation_operation_id::text from openpc.expired_denial_credential_bootstrap($1::text::uuid,$2)")
        .bind(&original.target_runtime_id).bind(format!("sha256:{}",peer.certificate_fingerprint.as_str()))
        .fetch_one(&mut **tx).await.map_err(|_|RuntimeError::RuntimeUnavailable)?;
    let binding: TargetDispositionBootstrap = serde_json::from_value(
        row.try_get("binding")
            .map_err(|_| RuntimeError::RuntimeUnavailable)?,
    )
    .map_err(|_| RuntimeError::InvalidInput)?;
    binding.validate(original)?;
    let rotation: String = row
        .try_get("rotation_operation_id")
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if binding.source != previous.source
        || binding.credential_predecessor.as_ref() != Some(&previous.target)
        || binding.target.credential_id != expected.successor_credential_id
        || rotation != expected.rotation_operation_id
        || binding.target.certificate_digest != peer.certificate_fingerprint
    {
        return Err(RuntimeError::TargetIdentity);
    }
    Ok(ExpiredCredentialDenialConnection { binding })
}

/// Only constructor verifies a TLS endpoint, installed CA/server name and the
/// actual certificate's target URI/digest against the signed bootstrap identity.
/// No insecure channel constructor or caller-produced currentness capability.
struct ControlDispositionClient {
    channel: Channel,
}
impl ControlDispositionClient {
    fn from_environment(binding: &TargetDispositionBootstrap) -> RuntimeResult<Self> {
        let endpoint = required("ENDPOINT")?;
        let uri: http::Uri = endpoint.parse().map_err(|_| RuntimeError::InvalidInput)?;
        if uri.scheme_str() != Some("https")
            || uri.authority().is_none()
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let certificate = input("CERT_FILE", 64 * 1024)?;
        let identity = crate::runtime_tls::target_identity_from_pem(&certificate)?;
        if identity.target_id != binding.target.target_id
            || identity.certificate_fingerprint != binding.target.certificate_digest
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let server_name = required("SERVER_NAME")?;
        if server_name.is_empty() {
            return Err(RuntimeError::InvalidInput);
        }
        let tls = ClientTlsConfig::new()
            .domain_name(server_name)
            .ca_certificate(Certificate::from_pem(input("CA_FILE", 64 * 1024)?))
            .identity(Identity::from_pem(
                certificate,
                input("TLS_KEY_FILE", 16 * 1024)?,
            ));
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|_| RuntimeError::InvalidInput)?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .tls_config(tls)
            .map_err(|_| RuntimeError::InvalidAuthorization)?
            .connect_lazy();
        Ok(Self { channel })
    }
}
impl TargetDispositionAuthority for ControlDispositionClient {
    fn read_current(&self, challenge: [u8; 32]) -> AuthorityFuture<'_, CurrentTargetDisposition> {
        Box::pin(async move {
            let mut grpc = tonic::client::Grpc::new(self.channel.clone())
                .max_decoding_message_size(40 * 1024)
                .max_encoding_message_size(128);
            grpc.ready()
                .await
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            let mut request = tonic::Request::new(ReadDispositionRequest {
                challenge: challenge.to_vec(),
            });
            request.set_timeout(Duration::from_secs(5));
            let response = grpc.unary(request,
                http::uri::PathAndQuery::from_static("/openpc.internal.runtime.v1.TargetDispositionService/ReadCurrent"),
                tonic_prost::ProstCodec::<ReadDispositionRequest, ReadDispositionResponse>::default())
                .await.map_err(|_| RuntimeError::RuntimeUnavailable)?.into_inner();
            Ok(CurrentTargetDisposition {
                challenge: response.challenge,
                established: response.established,
                revision: response.revision,
                admission_digest: response.admission_digest,
                signed_delivery: response.signed_delivery,
                signed_acknowledgement: response.signed_acknowledgement,
            })
        })
    }
    fn read_original_confirmation(
        &self,
        challenge: [u8; 32],
    ) -> AuthorityFuture<'_, HistoricalTargetConfirmation> {
        Box::pin(async move {
            let mut grpc = tonic::client::Grpc::new(self.channel.clone())
                .max_decoding_message_size(40 * 1024)
                .max_encoding_message_size(128);
            grpc.ready()
                .await
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            let mut request = tonic::Request::new(ReadDispositionRequest {
                challenge: challenge.to_vec(),
            });
            request.set_timeout(Duration::from_secs(5));
            let response=grpc.unary(request,
                http::uri::PathAndQuery::from_static("/openpc.internal.runtime.v1.TargetDispositionService/ReadOriginalConfirmation"),
                tonic_prost::ProstCodec::<ReadDispositionRequest, ReadOriginalConfirmationResponse>::default())
                .await.map_err(|_| RuntimeError::RuntimeUnavailable)?.into_inner();
            Ok(HistoricalTargetConfirmation {
                challenge: response.challenge,
                revision: response.revision,
                admission_digest: response.admission_digest,
                signed_delivery: response.signed_delivery,
                signed_acknowledgement: response.signed_acknowledgement,
            })
        })
    }
    fn acknowledge<'a>(
        &'a self,
        digest: &'a Digest,
        acknowledgement: &'a [u8],
    ) -> AuthorityFuture<'a, ()> {
        Box::pin(async move {
            let mut grpc = tonic::client::Grpc::new(self.channel.clone())
                .max_decoding_message_size(128)
                .max_encoding_message_size(20 * 1024);
            grpc.ready()
                .await
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            let mut request = tonic::Request::new(AcknowledgeDispositionRequest {
                delivery_digest: digest.as_str().into(),
                signed_acknowledgement: acknowledgement.to_vec(),
            });
            request.set_timeout(Duration::from_secs(5));
            grpc.unary(
                request,
                http::uri::PathAndQuery::from_static(
                    "/openpc.internal.runtime.v1.TargetDispositionService/Acknowledge",
                ),
                tonic_prost::ProstCodec::<
                    AcknowledgeDispositionRequest,
                    AcknowledgeDispositionResponse,
                >::default(),
            )
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            Ok(())
        })
    }
}

/// Before listeners, including for a suspended bootstrap: install/ACK an exact
/// withdrawal first. Missing binding/keys/current authority remains fenced.
pub async fn establish_target_disposition(
    agent: &RuntimeAgent,
    manifest: &TargetBootstrapManifest,
) -> RuntimeResult<TargetDispositionAction> {
    install_disposition_owner(agent, manifest)?;
    // Withdrawal is a successful durable reconciliation. The caller must keep
    // listeners closed and release journal custody for the activation owner.
    agent.reconcile_target_disposition().await
}

fn install_disposition_owner(
    agent: &RuntimeAgent,
    manifest: &TargetBootstrapManifest,
) -> RuntimeResult<()> {
    let binding = manifest
        .target_disposition
        .as_ref()
        .ok_or(RuntimeError::RuntimeUnavailable)?;
    binding.validate(manifest)?;
    install_bound_disposition_owner(agent, binding)
}

fn install_bound_disposition_owner(
    agent: &RuntimeAgent,
    binding: &TargetDispositionBootstrap,
) -> RuntimeResult<()> {
    let authority = Arc::new(ControlDispositionClient::from_environment(binding)?);
    let control = hex_input("CONTROL_PUBLIC_KEY_FILE", 130)?;
    let acknowledgement: [u8; 32] = hex_input("ACK_SECRET_FILE", 32)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidInput)?;
    agent.install_target_disposition_owner_with_credential_predecessor(
        binding.target.clone(),
        binding.source.clone(),
        &control,
        acknowledgement,
        authority,
        binding.credential_predecessor.clone(),
    )?;
    Ok(())
}

pub async fn prepare_expired_denial_handover(
    agent: &RuntimeAgent,
    manifest: &TargetBootstrapManifest,
    expected: &ExpiredUnsignedDenialHandover,
) -> RuntimeResult<()> {
    install_disposition_owner(agent, manifest)?;
    observe_prepared_expired_denial_handover(agent, expected).await
}

pub(super) async fn observe_prepared_expired_denial_handover(
    agent: &RuntimeAgent,
    expected: &ExpiredUnsignedDenialHandover,
) -> RuntimeResult<()> {
    let actual = agent
        .observe_expired_denial_handover(
            expected.abandoned_revision,
            &expected.abandoned_admission_digest,
        )
        .await?;
    if actual != expected.floor {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}

pub async fn prepare_expired_credential_denial_handover(
    agent: &RuntimeAgent,
    connection: &ExpiredCredentialDenialConnection,
    expected: &ExpiredUnsignedDenialHandover,
) -> RuntimeResult<()> {
    install_bound_disposition_owner(agent, &connection.binding)?;
    let previous = connection
        .binding
        .credential_predecessor
        .as_ref()
        .ok_or(RuntimeError::TargetIdentity)?;
    let actual = agent
        .observe_expired_credential_denial_handover(
            expected.abandoned_revision,
            &expected.abandoned_admission_digest,
            previous,
        )
        .await?;
    if actual != expected.floor {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}

/// Continue with the owner established by the fresh pre-request read. Installing
/// it again would reject the already-owned journal after consuming admission.
pub async fn complete_expired_denial_handover(
    agent: &RuntimeAgent,
) -> RuntimeResult<TargetDispositionAction> {
    let action = agent.reconcile_target_disposition().await?;
    if action != TargetDispositionAction::Withdraw {
        return Err(RuntimeError::InvalidTransition);
    }
    Ok(action)
}

pub async fn refresh_target_disposition(agent: &RuntimeAgent) -> RuntimeResult<()> {
    agent.reconcile_target_disposition().await?;
    agent.require_current_target_disposition()
}

/// One host-operator request on the ordinary concrete mTLS Control channel.
/// No automatic retry: a lost response requires original admission readback.
pub async fn request_expired_activation_denial(
    manifest: &TargetBootstrapManifest,
    bundle: Vec<u8>,
    nonce: Vec<u8>,
    operator_mac: Vec<u8>,
) -> RuntimeResult<Digest> {
    request_expired_operator(manifest, bundle, nonce, operator_mac, false).await
}

pub async fn request_expired_denial_handover(
    manifest: &TargetBootstrapManifest,
    bundle: Vec<u8>,
    nonce: Vec<u8>,
    operator_mac: Vec<u8>,
) -> RuntimeResult<Digest> {
    request_expired_operator(manifest, bundle, nonce, operator_mac, true).await
}

async fn request_expired_operator(
    manifest: &TargetBootstrapManifest,
    bundle: Vec<u8>,
    nonce: Vec<u8>,
    operator_mac: Vec<u8>,
    handover: bool,
) -> RuntimeResult<Digest> {
    let binding = manifest
        .target_disposition
        .as_ref()
        .ok_or(RuntimeError::RuntimeUnavailable)?;
    binding.validate(manifest)?;
    send_expired_operator(
        binding,
        bundle,
        nonce,
        operator_mac,
        if handover {
            "/openpc.internal.runtime.v1.TargetDispositionService/HandoverUnsignedExpiredDenial"
        } else {
            "/openpc.internal.runtime.v1.TargetDispositionService/DenyExpiredActivation"
        },
    )
    .await
}

pub async fn request_expired_credential_denial_handover(
    connection: &ExpiredCredentialDenialConnection,
    bundle: Vec<u8>,
    nonce: Vec<u8>,
    operator_mac: Vec<u8>,
) -> RuntimeResult<Digest> {
    send_expired_operator(
        &connection.binding,
        bundle,
        nonce,
        operator_mac,
        "/openpc.internal.runtime.v1.TargetDispositionService/HandoverExpiredCredentialDenial",
    )
    .await
}

async fn send_expired_operator(
    binding: &TargetDispositionBootstrap,
    bundle: Vec<u8>,
    nonce: Vec<u8>,
    operator_mac: Vec<u8>,
    path: &'static str,
) -> RuntimeResult<Digest> {
    if bundle.is_empty()
        || bundle.len() > 120 * 1024
        || nonce.len() != 32
        || operator_mac.len() != 32
    {
        return Err(RuntimeError::InvalidInput);
    }
    let client = ControlDispositionClient::from_environment(binding)?;
    let mut grpc = tonic::client::Grpc::new(client.channel)
        .max_decoding_message_size(1024)
        .max_encoding_message_size(128 * 1024);
    grpc.ready()
        .await
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let mut request = tonic::Request::new(DenyExpiredActivationRequest {
        bundle,
        nonce,
        operator_mac,
    });
    request.set_timeout(Duration::from_secs(5));
    let response =
        grpc
            .unary(
                request,
                http::uri::PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::<
                    DenyExpiredActivationRequest,
                    DenyExpiredActivationResponse,
                >::default(),
            )
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .into_inner();
    let digest = Digest::parse(&response.delivery_digest)?;
    if digest.as_str() != response.delivery_digest {
        return Err(RuntimeError::InvalidDigest);
    }
    Ok(digest)
}

fn required(suffix: &str) -> RuntimeResult<String> {
    env::var(format!("OPENPC_TARGET_DISPOSITION_{suffix}"))
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}
fn input(suffix: &str, maximum: usize) -> RuntimeResult<Vec<u8>> {
    let path = required(suffix)?;
    let mut bytes = Vec::new();
    fs::File::open(Path::new(&path))
        .map_err(|_| RuntimeError::RuntimeUnavailable)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(bytes)
}
fn hex_input(suffix: &str, maximum: usize) -> RuntimeResult<Vec<u8>> {
    let bytes = input(suffix, maximum * 2 + 2)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::InvalidInput)?
        .trim();
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(RuntimeError::InvalidInput);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| RuntimeError::InvalidInput))
        .collect()
}
