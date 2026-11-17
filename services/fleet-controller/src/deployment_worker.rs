//! Managed direct-deployment adapter in the existing control worker. Command
//! approval and address custody are durable control owners; actual workload
//! authentication, PDS, preflight and Broker STARTED remain target owners.
pub mod projection;
mod result_event;
mod store;

use base64ct::{Base64, Encoding};
use openpc_multi_rpc::{
    deployment::{
        custody::{DeploymentHandoff, HANDOFF_PURPOSE},
        intent::PreparedDeploymentIntent,
        rejection::{PURPOSE as REJECTION_PURPOSE, ReservationRejection},
    },
    signed_transaction::SignedTransaction,
};
use openpc_pds::{IdentityAssertionBindings, IdentityAssertionEvidence, IdentityAssertionVerifier};
use openpc_runtime_agent::identity_state::{RuntimeIdentityContext, workload_actor_key_digest};
use pc_policy_core::{
    deployment_policy::AdmittedDeploymentPolicy,
    pc_cbor_1,
    runtime_wire::{Profile, Verifier},
};
use pc_runtime_types::{Digest, PurposeSigner, canonical_bytes};
use reqwest::{Certificate, Client, Identity, Url, tls::Version};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{
    env, fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_parser::{extensions::GeneralName, prelude::*};

type Result<T> = std::result::Result<T, String>;
fn failure() -> String {
    "deployment worker owner unavailable".into()
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| v.as_millis().try_into().ok())
        .ok_or_else(failure)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").ok_or_else(failure)?;
    if value.is_empty()
        || value.len() > 524_288
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(failure());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| failure())?, 16)
                .map_err(|_| failure())
        })
        .collect()
}

struct CertificateBinding {
    participant: String,
    workload: String,
    uri: String,
    fingerprint: Digest,
    public_key: Digest,
}
impl CertificateBinding {
    fn read(pem: &[u8]) -> Result<Self> {
        let (rest, pem) = parse_x509_pem(pem).map_err(|_| failure())?;
        if !rest.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
            return Err(failure());
        }
        let (rest, cert) = X509Certificate::from_der(&pem.contents).map_err(|_| failure())?;
        if !rest.is_empty() {
            return Err(failure());
        }
        let san = cert
            .subject_alternative_name()
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        let uris = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [uri] = uris.as_slice() else {
            return Err(failure());
        };
        let parts = uri.split(':').collect::<Vec<_>>();
        if parts.len() != 6
            || parts[..3] != ["urn", "openpc", "participant"]
            || parts[4] != "workload"
            || [parts[3], parts[5]].iter().any(|v| {
                !uuid::Uuid::parse_str(v)
                    .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == *v)
            })
        {
            return Err(failure());
        }
        Ok(Self {
            participant: parts[3].into(),
            workload: format!("urn:openpc:workload:{}", parts[5]),
            uri: (*uri).into(),
            fingerprint: Digest::of(&pem.contents),
            public_key: Digest::of(cert.public_key().raw),
        })
    }
    fn digest(&self) -> Result<Digest> {
        canonical_bytes(&(
            "openpc:submission-workload-peer:v1",
            &self.participant,
            &self.workload,
            &self.uri,
            &self.fingerprint,
            &self.public_key,
        ))
        .map(Digest::of)
        .map_err(|_| failure())
    }
}

pub struct DeploymentWorker {
    projection: projection::Consumer,
    client: Client,
    identity_origin: Url,
    target_origin: Url,
    target_id: String,
    peer: CertificateBinding,
    identity_key: Vec<u8>,
    signer: PurposeSigner,
    rejection_signer: PurposeSigner,
}
impl DeploymentWorker {
    /// Unconfigured outside explicitly enabled isolated deployment acceptance.
    pub fn from_environment(
        fleet_key: [u8; 32],
        identity_key: &[u8],
        agent_key: [u8; 32],
    ) -> Result<Option<Self>> {
        match env::var("OPENPC_MANAGED_DEPLOYMENT_ENABLED").as_deref() {
            Err(_) | Ok("false") => return Ok(None),
            Ok("true") => {}
            _ => return Err(failure()),
        }
        let get = |name| env::var(name).map_err(|_| failure());
        let read = |name| fs::read(get(name)?).map_err(|_| failure());
        let origin = |name| -> Result<Url> {
            let url = Url::parse(&get(name)?).map_err(|_| failure())?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(failure());
            }
            Ok(url)
        };
        let identity_origin = origin("CONTROL_WORKER_DEPLOYMENT_IDENTITY_URL")?;
        let target_origin = origin("CONTROL_WORKER_DEPLOYMENT_TARGET_URL")?;
        let target_id = get("CONTROL_WORKER_DEPLOYMENT_TARGET_ID")?;
        if !uuid::Uuid::parse_str(&target_id)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == target_id)
        {
            return Err(failure());
        }
        let mut identity = read("CONTROL_WORKER_DEPLOYMENT_CERT_FILE")?;
        let peer = CertificateBinding::read(&identity)?;
        identity.extend(read("CONTROL_WORKER_DEPLOYMENT_KEY_FILE")?);
        let tls = Identity::from_pem(&identity).map_err(|_| failure());
        identity.fill(0);
        let client = Client::builder()
            .identity(tls?)
            .tls_certs_only([
                Certificate::from_pem(&read("CONTROL_WORKER_DEPLOYMENT_CA_FILE")?)
                    .map_err(|_| failure())?,
            ])
            .tls_version_min(Version::TLS_1_3)
            .tls_version_max(Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| failure())?;
        Verifier::from_spki_der(identity_key).map_err(|_| failure())?;
        Ok(Some(Self {
            projection: projection::Consumer::new(
                get("CONTROL_WORKER_DEPLOYMENT_RESULT_ROOT")?.into(),
                &target_id,
                agent_key,
            )?,
            client,
            identity_origin,
            target_origin,
            target_id,
            peer,
            identity_key: identity_key.into(),
            signer: PurposeSigner::from_secret_bytes(HANDOFF_PURPOSE, fleet_key)
                .map_err(|_| failure())?,
            rejection_signer: PurposeSigner::from_secret_bytes(REJECTION_PURPOSE, fleet_key)
                .map_err(|_| failure())?,
        }))
    }

    async fn authenticate(
        &self,
        participant: &str,
        privacy: &str,
        principal: &str,
    ) -> Result<(Vec<u8>, Digest, u64)> {
        let value=response_json(self.client.post(self.identity_origin.join("/internal/v1/workload/authenticate").map_err(|_|failure())?)
            .header("content-type", "application/json")
            .body(canonical_bytes(&json!({"runtimeContext":{"privacyDomainId":privacy,"targetRuntimeId":self.target_id}})).map_err(|_|failure())?)
            .send().await.map_err(|_|failure())?).await?;
        if value["workloadId"] != self.peer.workload {
            return Err(failure());
        }
        let cose = Base64::decode_vec(
            value["runtime"]["assertionCoseSign1"]
                .as_str()
                .ok_or_else(failure)?,
        )
        .map_err(|_| failure())?;
        let verifier = Verifier::from_spki_der(&self.identity_key).map_err(|_| failure())?;
        let payload = verifier
            .verify(Profile::IdentityAssertion, &cose, 8192)
            .map_err(|_| failure())?;
        let fields: ciborium::Value =
            ciborium::de::from_reader(payload.as_slice()).map_err(|_| failure())?;
        let fields = fields.as_map().ok_or_else(failure)?;
        let digest = |index: u64| -> Result<[u8; 32]> {
            fields
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Integer(index.into()))
                .and_then(|(_, v)| v.as_bytes())
                .and_then(|v| v.as_slice().try_into().ok())
                .ok_or_else(failure)
        };
        let vector = digest(7)?;
        let context = RuntimeIdentityContext {
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            target_runtime_id: self.target_id.clone(),
        };
        let fingerprint: [u8; 32] = unhex(&format!("0x{}", self.peer.fingerprint.as_str()))?
            .try_into()
            .map_err(|_| failure())?;
        let key = unhex(&format!("0x{}", self.peer.public_key.as_str()))?;
        let authentication = Digest::of(pc_cbor_1(&ciborium::Value::Array(vec![
            ciborium::Value::Text("TLS1.3".into()),
            ciborium::Value::Text(self.peer.uri.clone()),
            ciborium::Value::Bytes(fingerprint.to_vec()),
            ciborium::Value::Bytes(key),
        ])));
        // The signed vector is retained as a custody binding. The target still
        // resolves and checks current Identity sources, roles and permissions.
        let verified =
            IdentityAssertionVerifier::new(std::slice::from_ref(&self.identity_key), 60_000)
                .map_err(|_| failure())?
                .verify(
                    &IdentityAssertionEvidence::from_cose_sign1(&cose).map_err(|_| failure())?,
                    &IdentityAssertionBindings {
                        actor_kind: 1,
                        sender_binding_kind: 2,
                        actor_key_digest: workload_actor_key_digest(participant, principal)
                            .map_err(|_| failure())?,
                        participant_context_digest: context.participant_context_digest(),
                        audience_digest: context.target_scope_digest(),
                        assurance_profile_digest: digest(6)?,
                        authority_vector_digest: vector,
                        authentication_evidence_digest: unhex(&format!(
                            "0x{}",
                            authentication.as_str()
                        ))?
                        .try_into()
                        .map_err(|_| failure())?,
                        sender_credential_binding_digest: fingerprint,
                    },
                    now_ms()?,
                )
                .map_err(|_| failure())?;
        Ok((
            cose,
            Digest::parse(hex(&vector)).map_err(|_| failure())?,
            verified.expires_at_ms(),
        ))
    }

    pub async fn tick(&mut self, pool: &PgPool, participant: &str, privacy: &str) -> Result<bool> {
        if self.peer.participant != participant {
            return Err(failure());
        }
        self.projection.tick(pool, participant, privacy).await?;
        let Some(command) = store::next(
            pool,
            participant,
            privacy,
            &self.target_id,
            &self.peer.workload,
        )
        .await?
        else {
            return Ok(false);
        };
        let publication: AdmittedDeploymentPolicy =
            serde_json::from_slice(&command.publication).map_err(|_| failure())?;
        let prepared = PreparedDeploymentIntent::restore(&command.preparation, &publication)
            .map_err(|_| failure())?;
        let context = prepared.context();
        if context.participant_id != participant
            || context.privacy_domain_id != privacy
            || context.target_runtime_id != self.target_id
            || context.actor_subject_id != command.principal_id
            || context.workload_binding_id.as_ref() != Some(&self.peer.workload)
        {
            return Err(failure());
        }
        let signed = command.candidate["signedTransaction"]
            .as_str()
            .ok_or_else(failure)?;
        let transaction = SignedTransaction::decode(&unhex(signed)?).map_err(|_| failure())?;
        let rejection_binding = ReservationRejection::binding(
            &prepared,
            &transaction,
            &command.command_id,
            &command.attempt_id,
        )
        .map_err(|_| failure())?;
        let rejection = store::Rejection {
            command: &command,
            binding: &rejection_binding,
            signer: &self.rejection_signer,
        };
        if now_ms()? >= context.expires_at_ms {
            store::reject_expired(pool, rejection, participant, privacy).await?;
            return Ok(true);
        }
        let binding = prepared
            .reservation_binding(
                &publication,
                &transaction,
                &command.command_id,
                &command.attempt_id,
                now_ms()?,
            )
            .map_err(|_| failure())?;
        let (assertion, vector, assertion_until) = self
            .authenticate(participant, privacy, &command.principal_id)
            .await?;
        let Some(at) = store::handoff(
            pool,
            &binding,
            transaction.nonce(),
            participant,
            privacy,
            Some(rejection),
        )
        .await?
        else {
            return Ok(false);
        };
        let expires = context.expires_at_ms.min(assertion_until);
        if now_ms()? >= expires {
            return Err(failure());
        }
        let handoff = self
            .signer
            .sign(DeploymentHandoff {
                predecessor_command_id: command.predecessor()?,
                command_id: command.command_id.clone(),
                attempt_id: command.attempt_id,
                reservation_binding_digest: Digest::of(
                    canonical_bytes(&binding).map_err(|_| failure())?,
                ),
                publication_digest: Digest::of(
                    canonical_bytes(&serde_json::to_value(&publication).map_err(|_| failure())?)
                        .map_err(|_| failure())?,
                ),
                candidate_digest: command.candidate_digest,
                authorization_evidence_digest: command.evidence_digest,
                workload_peer_binding_digest: self.peer.digest()?,
                identity_vector_digest: vector,
                handoff_at_ms: at,
                expires_at_ms: expires,
            })
            .map_err(|_| failure())?;
        let body = json!({"requestId":command.command_id,"deploymentPolicyId":publication.deployment_policy_id,
            "preparationBytes":format!("0x{}",hex(&command.preparation)),"signedTransaction":signed,"handoff":handoff});
        // One transport call, with library retries disabled. Every uncertain
        // response remains HANDOFF; later turns only find new unhanded commands.
        let response = self
            .client
            .post(
                self.target_origin
                    .join("/internal/v1/deployment-submissions")
                    .map_err(|_| failure())?,
            )
            .header("x-openpc-identity-assertion", hex(&assertion))
            .header("content-type", "application/json")
            .body(canonical_bytes(&body).map_err(|_| failure())?)
            .send()
            .await;
        let outcome = match response {
            Ok(response) => response_json(response).await.map(|_| ()),
            Err(_) => Err(failure()),
        };
        if outcome.is_err() {
            eprintln!(
                "{{\"boundary\":\"deployment_worker\",\"event\":\"handoff_response_unknown\"}}"
            );
        }
        Ok(true)
    }
}

async fn response_json(mut response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success()
        || !response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"))
    {
        return Err(failure());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
        if body.len() + chunk.len() > 262_144 {
            return Err(failure());
        }
        body.extend_from_slice(&chunk);
    }
    openpc_multi_rpc::parse_strict_json(&body, 16).map_err(|_| failure())
}
