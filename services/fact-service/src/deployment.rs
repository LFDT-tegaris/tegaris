//! Deployment wiring for the real FactBridge. Input files contain restricted
//! endpoint/trust configuration and local secret references, never candidates,
//! admitted results, authority booleans or freshness defaults.
use crate::{
    DurableAdmissionOutcome, FactStore, PurposeBoundFactSigner,
    admission::{StateAdmissionError, StateFactBridge},
    candidate_feed::{CandidateFeedError, CandidateFeedReader, CandidateReadScope},
    source_authority::FactSourceAuthority,
    workload_authority::{FactIdentityTrust, FactWorkloadAuthenticator},
};
use openpc_multi_rpc::provider_connection::{
    ConnectionRegistry, DestinationPolicy, EndpointDescriptor, LocalTlsMaterial, NetworkRange,
    Resolution,
};
use pc_policy_core::identity_context::RuntimeIdentityContext;
use pc_runtime_types::Digest;
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

mod secret_recipient;
mod selection;
pub use selection::CandidateSelection;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentInput {
    version: u32,
    participant_id: Uuid,
    privacy_domain_id: Uuid,
    runtime_target_id: Uuid,
    candidate_database_url_file: PathBuf,
    #[serde(default)]
    candidate_secret_recipient: Option<secret_recipient::SecretRecipientInput>,
    control_database_url_file: PathBuf,
    provider_directory: PathBuf,
    connection_directory: PathBuf,
    #[serde(default)]
    artifact_directory: Option<PathBuf>,
    identity_endpoint: EndpointDescriptor,
    identity_addresses: Vec<IpAddr>,
    allowed_ranges: Vec<String>,
    private_network_ranges: Vec<String>,
    allow_ip_endpoint: bool,
    root_der_files: Vec<PathBuf>,
    client_chain_der_files: Vec<PathBuf>,
    client_key_der_file: PathBuf,
    server_certificate_digest: Digest,
    identity_public_key_der_files: Vec<PathBuf>,
    identity_profile_digest: Digest,
    identity_signer_id: String,
}

pub struct DeployedFactBridge {
    input: DeploymentInput,
    candidates: CandidateFeedReader,
    sources: FactSourceAuthority,
    identity_trust: FactIdentityTrust,
    providers: ConnectionRegistry,
    operations_observation: tokio::sync::Mutex<Option<secret_recipient::ObservedSecretUse>>,
    candidate_connections_terminal: AtomicBool,
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("fact input path must be absolute".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "fact input unavailable")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "fact input unreadable")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("fact input size rejected".into());
    }
    Ok(bytes)
}
fn database_url(path: &Path) -> Result<String, String> {
    let text =
        String::from_utf8(read(path, 8192)?).map_err(|_| "fact database reference rejected")?;
    Ok(text.trim().into())
}

/// RecoverGap uses the existing public projection recovery operation.
/// These references are untrusted until current Control and workload validation.
#[derive(Clone, Debug, Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoverGapRequest {
    pub prior_partition: Uuid,
    pub fenced_checkpoint: Uuid,
    pub checkpoint_digest: String,
    pub new_partition: Uuid,
    pub new_source_generation: Uuid,
    pub candidate_sequence: u64,
    pub public_operation: Uuid,
    pub action_intent_id: String,
    pub bootstrap_start: u64,
    pub end_watermark: u64,
    pub idempotency_key: Uuid,
    pub correlation_id: Uuid,
}

impl DeployedFactBridge {
    /// Actual packaged entrypoint's first phase: authenticate and publish before
    /// the installer binds the resulting inode into the final consumer. Opens no
    /// candidate/Fact/Control database and cannot construct a usable bridge.
    pub async fn prepare_candidate_secret(path: &Path) -> Result<(), String> {
        let input: DeploymentInput = serde_json::from_slice(&read(path, 131_072)?)
            .map_err(|_| "fact deployment configuration rejected")?;
        if input.version != 1
            || [
                input.participant_id,
                input.privacy_domain_id,
                input.runtime_target_id,
            ]
            .iter()
            .any(|id| id.get_version_num() != 7)
        {
            return Err("fact deployment scope rejected".into());
        }
        input.authenticator()?;
        input
            .candidate_secret_recipient
            .as_ref()
            .ok_or("fact installed secret recipient missing")?
            .authorize(&input, true)
            .await
    }

    /// Stop future candidate acquisitions and drain every owned session. This
    /// is terminal for this instance; a replacement must authenticate afresh.
    /// The caller must await completion before claiming session cleanup. This
    /// is not database-role revocation or an installed-recipient authority grant.
    pub async fn close_candidate_connections(&self) {
        self.candidate_connections_terminal
            .store(true, Ordering::Release);
        if let Some(observation) = self.operations_observation.lock().await.take()
            && observation.close().await.is_err()
        {
            eprintln!("OPS_SECRET_OBSERVATION_CLEANUP|UNKNOWN");
        }
        self.candidates.close().await;
    }

    pub(crate) fn candidate_connections_closed(&self) -> bool {
        self.candidate_connections_terminal.load(Ordering::Acquire) || self.candidates.is_closed()
    }

    async fn authenticated_candidates(&self) -> Result<&CandidateFeedReader, CandidateFeedError> {
        self.check_candidate_secret_recipient().await?;
        let authenticator = match self.input.authenticator() {
            Ok(authenticator) => authenticator,
            Err(_) => {
                self.close_candidate_connections().await;
                return Err(CandidateFeedError::Authentication);
            }
        };
        self.candidates
            .authenticate(&authenticator, self.input.participant_id)
            .await
    }

    /// Background and per-acquisition checks use the real installed-recipient
    /// endpoint. Failure permanently closes this instance's candidate pool.
    pub(crate) async fn check_candidate_secret_recipient(&self) -> Result<(), CandidateFeedError> {
        if let Some(recipient) = &self.input.candidate_secret_recipient
            && (self.candidate_connections_closed()
                || recipient.authorize(&self.input, false).await.is_err())
        {
            self.close_candidate_connections().await;
            return Err(CandidateFeedError::Authentication);
        }
        if self.refresh_operations_observation().await.is_err() {
            self.close_candidate_connections().await;
            return Err(CandidateFeedError::Authentication);
        }
        Ok(())
    }

    async fn refresh_operations_observation(&self) -> Result<(), String> {
        if self.candidate_connections_closed() {
            return Err("fact observation instance closed".into());
        }
        let Some(recipient) = &self.input.candidate_secret_recipient else {
            return Ok(());
        };
        if !recipient.has_operations_observer() {
            return Ok(());
        }
        let mut slot = self.operations_observation.lock().await;
        if self.candidate_connections_closed() {
            return Err("fact observation instance closed".into());
        }
        let now = openpc_multi_rpc::provider_probe_source::now_ms()?;
        if slot
            .as_ref()
            .is_some_and(|observation| observation.fresh(now))
        {
            return Ok(());
        }
        if let Some(previous) = slot.take() {
            previous.close().await?;
        }
        // Existing real workload authentication precedes the new no-effect DB
        // check. Neither this observation nor the secret grants Fact actions.
        self.input
            .authenticator()?
            .authenticate_peer(self.input.participant_id)
            .await
            .map_err(|_| "fact observation workload unavailable")?;
        *slot = Some(recipient.observe_use(&self.input).await?);
        if self.candidate_connections_closed() {
            return Err("fact observation instance closed".into());
        }
        Ok(())
    }

    pub(crate) async fn reconcile_producer_deliveries(
        &self,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, StateAdmissionError> {
        let Some(root) = self.input.artifact_directory.as_deref() else {
            return Ok(0);
        };
        Ok(facts
            .reconcile_producer_deliveries(
                &self.input.participant_id.to_string(),
                &self.input.privacy_domain_id.to_string(),
                &signer.verifier(),
                root,
            )
            .await?)
    }

    pub(crate) async fn reconcile_fleet_deliveries(
        &self,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, StateAdmissionError> {
        facts
            .reconcile_fleet_deliveries(
                self.input.participant_id,
                self.input.privacy_domain_id,
                &signer.verifier(),
                &self.sources,
            )
            .await
    }

    pub(crate) async fn reconcile_control_deliveries(
        &self,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, StateAdmissionError> {
        facts
            .reconcile_control_deliveries(
                self.input.participant_id,
                self.input.privacy_domain_id,
                &signer.verifier(),
                &self.sources,
            )
            .await
    }

    pub(crate) async fn materialize_pending_admissions(
        &self,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<bool, StateAdmissionError> {
        Ok(facts
            .materialize_pending_admissions(
                &self.input.participant_id.to_string(),
                &self.input.privacy_domain_id.to_string(),
                &signer.verifier(),
            )
            .await?)
    }

    pub async fn reconcile_source_withdrawals(
        &self,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<u64, StateAdmissionError> {
        let participant = self.input.participant_id;
        let privacy = self.input.privacy_domain_id;
        let pending = facts
            .pending_source_events(&participant.to_string(), &privacy.to_string())
            .await?;
        let mut changed = 0;
        for (partition, sequence) in pending {
            let operation = Uuid::now_v7();
            let mut feed = self
                .authenticated_candidates()
                .await?
                .read_partition(
                    CandidateReadScope::new(participant, privacy, operation)?,
                    partition,
                )
                .await?;
            let reorg = feed.source_reorg(sequence).await?;
            let event = if reorg.is_none() {
                feed.source_fence(sequence).await?
            } else {
                None
            };
            feed.close().await?;
            if let Some(event) = reorg {
                let mut proof = self
                    .sources
                    .verify_reorg(event, &self.input.provider_directory, &self.providers)
                    .await?;
                changed += facts.apply_source_reorg(&mut proof, signer).await?;
            }
            if let Some(event) = event {
                let Some(mut proof) = self.sources.verify_withdrawal(event, operation).await?
                else {
                    return Err(crate::source_authority::SourceAuthorityError::Binding.into());
                };
                changed += facts.apply_source_withdrawal(&mut proof, signer).await?;
            }
        }
        Ok(changed)
    }

    /// Separate COM-019 reconciliation after durable admission. A missing local
    /// publication adapter leaves the accepted SQL fact explicitly not ready.
    pub async fn publish(
        &self,
        scope: CandidateReadScope,
        candidate: Uuid,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<bool, StateAdmissionError> {
        if scope.participant != self.input.participant_id
            || scope.privacy != self.input.privacy_domain_id
        {
            return Err(CandidateFeedError::Scope.into());
        }
        let Some(directory) = &self.input.artifact_directory else {
            return Ok(false);
        };
        Ok(facts
            .publish_candidate(
                &scope.participant.to_string(),
                &scope.privacy.to_string(),
                &candidate.to_string(),
                signer,
                directory,
            )
            .await?)
    }

    pub async fn connect(path: &Path) -> Result<Self, String> {
        let input: DeploymentInput = serde_json::from_slice(&read(path, 131_072)?)
            .map_err(|_| "fact deployment configuration rejected")?;
        for digest in [
            &input.identity_profile_digest,
            &input.server_certificate_digest,
        ] {
            if Digest::parse(digest.as_str()).as_ref() != Ok(digest) {
                return Err("fact deployment digest rejected".into());
            }
        }
        if input.version != 1
            || [
                input.participant_id,
                input.privacy_domain_id,
                input.runtime_target_id,
            ]
            .iter()
            .any(|id| id.get_version_num() != 7)
            || !input.provider_directory.is_absolute()
            || !input.connection_directory.is_absolute()
            || !(1..=16).contains(&input.root_der_files.len())
            || !(1..=8).contains(&input.client_chain_der_files.len())
            || !(1..=16).contains(&input.identity_public_key_der_files.len())
            || input.identity_addresses.is_empty()
            || input.identity_addresses.len() > 16
        {
            return Err("fact deployment scope or bounds rejected".into());
        }
        let public_keys = input
            .identity_public_key_der_files
            .iter()
            .map(|path| read(path, 4096))
            .collect::<Result<Vec<_>, _>>()?;
        let profile: [u8; 32] = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &input.identity_profile_digest.as_str()[i * 2..i * 2 + 2],
                    16,
                )
                .map_err(|_| "fact identity digest rejected")
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "fact identity digest rejected")?;
        let identity_trust =
            FactIdentityTrust::new(&public_keys, profile, input.identity_signer_id.clone())
                .map_err(|_| "fact identity trust rejected")?;
        // Fail startup before opening stores when endpoint/key preparation fails.
        input.authenticator()?;
        if let Some(recipient) = &input.candidate_secret_recipient {
            recipient.authorize(&input, true).await?;
        }
        let candidates =
            CandidateFeedReader::prepare(&database_url(&input.candidate_database_url_file)?)
                .map_err(|_| "fact candidate connection rejected")?;
        let sources =
            FactSourceAuthority::connect(&database_url(&input.control_database_url_file)?)
                .await
                .map_err(|_| "fact control connection rejected")?;
        let providers = ConnectionRegistry::open(
            &input.connection_directory,
            &input.runtime_target_id.to_string(),
            16,
        )
        .map_err(|_| "fact connection custody unavailable")?;
        let bridge = Self {
            input,
            candidates,
            sources,
            identity_trust,
            providers,
            operations_observation: tokio::sync::Mutex::new(None),
            candidate_connections_terminal: AtomicBool::new(false),
        };
        if let Err(failure) = bridge.refresh_operations_observation().await {
            bridge.close_candidate_connections().await;
            return Err(failure);
        }
        Ok(bridge)
    }

    pub async fn recover_gap(
        &self,
        scope: CandidateReadScope,
        request: &RecoverGapRequest,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<Vec<u8>, StateAdmissionError> {
        if scope.participant != self.input.participant_id
            || scope.privacy != self.input.privacy_domain_id
            || [
                request.prior_partition,
                request.fenced_checkpoint,
                request.new_partition,
                request.new_source_generation,
                request.public_operation,
                request.idempotency_key,
                request.correlation_id,
            ]
            .iter()
            .any(|id| id.get_version_num() != 7)
            || request.candidate_sequence != 1
            || request.prior_partition == request.new_partition
            || request.bootstrap_start > request.end_watermark
        {
            return Err(CandidateFeedError::Scope.into());
        }
        let authenticator = self
            .input
            .authenticator()
            .map_err(|_| crate::workload_authority::WorkloadAuthorityError::Authentication)?;
        let authenticated = authenticator
            .authenticate(RuntimeIdentityContext {
                participant_id: scope.participant.to_string(),
                privacy_domain_id: scope.privacy.to_string(),
                target_runtime_id: self.input.runtime_target_id.to_string(),
            })
            .await?;
        let mut feed = self
            .authenticated_candidates()
            .await?
            .read_partition(
                CandidateReadScope::new(scope.participant, scope.privacy, scope.operation)?,
                request.new_partition,
            )
            .await?;
        let (batch, _) = feed.batch(request.candidate_sequence).await?;
        let material = &batch[0].0;
        if material.source.inputs.published().projection_generation_id
            != request.new_source_generation
            || material.batch_sequence != 1
            || material.predecessor_batch_digest.is_some()
            || material.range_start != request.bootstrap_start
            || material.range_end != request.end_watermark
            || !material.source.inputs.plan().partitions.iter().any(|p| {
                p.partition_id == material.source.partition_id
                    && p.source_id == material.source.source_id
                    && p.range.start == request.bootstrap_start
            })
        {
            return Err(CandidateFeedError::Material.into());
        }
        let mut authority = self
            .sources
            .acquire(&scope, &material.source)
            .await?
            .authorize_workload(
                authenticated,
                &self.identity_trust,
                &format!("urn:openpc:resource:{}", request.prior_partition),
            )
            .await?;
        let operation = authority
            .source
            .recovery_operation(
                material.source.inputs.source(),
                request.public_operation,
                &request.action_intent_id,
            )
            .await?;
        let result = facts
            .authorize_rebootstrap(&batch, request, &operation, signer, &mut authority)
            .await?;
        authority.confirm_live().await?;
        feed.close().await?;
        Ok(result)
    }

    pub async fn consume(
        &self,
        scope: CandidateReadScope,
        partition: Uuid,
        sequence: u64,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
    ) -> Result<DurableAdmissionOutcome, StateAdmissionError> {
        self.consume_with_operation(scope, partition, sequence, facts, signer, None)
            .await
    }

    pub(crate) async fn consume_with_operation(
        &self,
        scope: CandidateReadScope,
        partition: Uuid,
        sequence: u64,
        facts: &FactStore,
        signer: &PurposeBoundFactSigner,
        binding: Option<&crate::FactOperationBinding>,
    ) -> Result<DurableAdmissionOutcome, StateAdmissionError> {
        if scope.participant != self.input.participant_id
            || scope.privacy != self.input.privacy_domain_id
        {
            return Err(CandidateFeedError::Scope.into());
        }
        self.reconcile_source_withdrawals(facts, signer).await?;
        let authenticator = self
            .input
            .authenticator()
            .map_err(|_| crate::workload_authority::WorkloadAuthorityError::Authentication)?;
        StateFactBridge {
            candidates: self.authenticated_candidates().await?,
            sources: &self.sources,
            authenticator: &authenticator,
            identity_trust: &self.identity_trust,
            facts,
            signer,
            providers: &self.providers,
            provider_directory: &self.input.provider_directory,
        }
        .consume_with_operation(
            RuntimeIdentityContext {
                participant_id: scope.participant.to_string(),
                privacy_domain_id: scope.privacy.to_string(),
                target_runtime_id: self.input.runtime_target_id.to_string(),
            },
            scope.operation,
            partition,
            sequence,
            binding,
        )
        .await
    }
}

impl DeploymentInput {
    fn authenticator(&self) -> Result<FactWorkloadAuthenticator, String> {
        let ranges = |values: &[String]| {
            values
                .iter()
                .map(|value| {
                    NetworkRange::parse(value).map_err(|_| "fact identity destination rejected")
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let now = openpc_multi_rpc::provider_probe_source::now_ms()?;
        FactWorkloadAuthenticator::prepare(
            &self.identity_endpoint,
            &DestinationPolicy {
                allowed_ranges: ranges(&self.allowed_ranges)?,
                private_network_ranges: ranges(&self.private_network_ranges)?,
                allow_ip_endpoint: self.allow_ip_endpoint,
            },
            Resolution {
                addresses: self.identity_addresses.clone(),
                resolved_at_ms: now,
                valid_until_ms: now.checked_add(30_000).ok_or("fact clock overflow")?,
                generation: now,
            },
            LocalTlsMaterial {
                roots: self
                    .root_der_files
                    .iter()
                    .map(|path| read(path, 65536).map(Into::into))
                    .collect::<Result<_, _>>()?,
                client_chain: self
                    .client_chain_der_files
                    .iter()
                    .map(|path| read(path, 65536).map(Into::into))
                    .collect::<Result<_, _>>()?,
                client_key: read(&self.client_key_der_file, 16384)?
                    .try_into()
                    .map_err(|_| "fact identity key rejected")?,
                expected_server_certificate: self.server_certificate_digest.clone(),
            },
        )
        .map_err(|_| "fact identity transport rejected".into())
    }
}
