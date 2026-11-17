//! Production target process assembled only from the active target journal,
//! Fleet-signed bootstrap, independently scoped public trust and local secrets.

use crate::{
    provider_probe_source,
    runtime_target::{
        GovernedOrBootstrapAdmission, GovernedOwnerTrust, TargetBootstrapManifest,
        build_governed_runtime_owners, disposition::establish_target_disposition,
        passthrough_admission, read_target_bootstrap, refresh_target_restrictions,
    },
};
use openpc_broker::BrokerService;
use openpc_multi_rpc::{
    journal::ObservationTarget,
    provider_connection::{ConnectionLease, ConnectionRecord, ConnectionRegistry},
    provider_probe::HashPinnedCallProbePlan,
    route_witness::{
        ChainAnchor, ChainAnchorBindings, RequestRouteWitness, RouteWitnessBindings,
        VerifiedChainAnchor, VerifiedRouteWitness,
    },
    route_witness_set::{RouteWitnessRef, RouteWitnessSet, VerifiedRouteWitnessSet},
};
use openpc_pds::{IdentityAssertionEvidence, IdentityAssertionVerifier, PolicyDecisionService};
use openpc_runtime_agent::{
    CapsuleTrust, RequestTraceId, RuntimeAgent, RuntimeCapsule, RuntimeWireSigner, WorkloadPeer,
    broker_handoff::BrokerHandoffStore,
    broker_server::BrokerServerEvidence,
    decision_evidence::DecisionEvidenceStore,
    ext_proc::{ExtProcLimits, ExtProcRequestOwner, ExtProcService},
    fact_lease::FactLeaseReader,
    ipc::{OwnedUnixListener, UnixSocketPolicy},
    protected_target::{ProtectedTargetAuthority, ProtectedTargetOwner, TargetTransportEvidence},
    request_decode::RequestDecodeLimits,
    request_route::{RequestRouteEvidence, RouteEvidenceTrust},
    routing_custody::{
        ProviderCertification, ProviderCertificationSource, RoutingAssignment,
        RoutingSnapshotSource,
    },
    target_server::serve_protected_target,
    target_state::{CapturedTargetRequest, TargetState, TargetStateOwners},
};
use pc_policy_core::{pc_cbor_1, runtime_wire::Signer};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::de::DeserializeOwned;
use std::{
    env, fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type TargetResult<T> = Result<T, String>;
mod source_only;

// Process orchestration only. Authority remains in the installed Control
// transport and RuntimeAgent; these outcomes never constitute a serving grant.
pub(crate) mod lifecycle {
    use super::*;
    use pc_runtime_types::target_disposition::TargetDispositionAction;
    use std::{future::Future, sync::Weak, time::Duration};
    use tokio::sync::{Notify, watch};

    const RELOAD_DELAY: Duration = Duration::from_secs(1);
    const RELEASE_TIMEOUT: Duration = Duration::from_secs(15);

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum Exit {
        Withdrawn,
        DispositionUnavailable(RuntimeError),
        BootstrapUnavailable,
        CustodyUnavailable,
        BootstrapChanged,
        Cancelled,
    }
    impl Exit {
        fn boundary(&self) -> &'static str {
            match self {
                Self::Withdrawn => "withdrawn",
                Self::DispositionUnavailable(_) => "disposition_unavailable",
                Self::BootstrapUnavailable => "bootstrap_unavailable",
                Self::CustodyUnavailable => "custody_unavailable",
                Self::BootstrapChanged => "bootstrap_changed",
                Self::Cancelled => "cancelled",
            }
        }
    }
    pub(crate) struct Attempt {
        pub(crate) result: TargetResult<Exit>,
        pub(crate) custody: Weak<RuntimeAgent>,
    }
    impl Attempt {
        pub(super) fn closed(exit: Exit) -> Self {
            Self {
                result: Ok(exit),
                custody: Weak::new(),
            }
        }
    }

    pub(crate) async fn stopped(stop: &mut watch::Receiver<bool>) {
        while !*stop.borrow() && stop.changed().await.is_ok() {}
    }

    /// Every invocation owns a single session, including its listeners and all
    /// strong agent handles. The completed future is dropped before the release
    /// barrier and reload delay, allowing the original worker to claim custody.
    pub(crate) async fn run<F, Session, Shutdown>(
        mut attempt: F,
        shutdown: Shutdown,
    ) -> TargetResult<()>
    where
        F: FnMut(watch::Receiver<bool>) -> Session,
        Session: Future<Output = TargetResult<Attempt>>,
        Shutdown: Future<Output = ()>,
    {
        let (cancel, stop) = watch::channel(false);
        tokio::pin!(shutdown);
        let mut previous = None;
        loop {
            let completed = {
                let session = attempt(stop.clone());
                tokio::pin!(session);
                tokio::select! {
                    biased;
                    () = &mut shutdown => {
                        let _ = cancel.send(true);
                        tokio::time::timeout(RELEASE_TIMEOUT, &mut session).await
                            .map_err(|_| "target cancellation drain timed out")?
                    },
                    result = &mut session => result,
                }
            }?;
            let released = release(completed.custody).await;
            let exit = match (completed.result, released) {
                (Err(original), Err(_)) => {
                    return Err(format!("{original}; target journal release failed"));
                }
                (Err(original), Ok(())) => return Err(original),
                (Ok(_), Err(cleanup)) => return Err(cleanup),
                (Ok(exit), Ok(())) => exit,
            };
            if *stop.borrow() || exit == Exit::Cancelled {
                return Ok(());
            }
            if previous.as_ref() != Some(&exit) {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"runtime_target_fenced", "boundary":exit.boundary(),
                        "pcCode": match &exit { Exit::DispositionUnavailable(error) => Some(error.pc_code()), _ => None }})
                );
                previous = Some(exit);
            }
            tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                () = tokio::time::sleep(RELOAD_DELAY) => {},
            }
        }
    }

    /// A lingering shared transport/request handle is a failed drain, never a
    /// reason to start a competing session or wait with the journal forever.
    async fn release(custody: Weak<RuntimeAgent>) -> TargetResult<()> {
        tokio::time::timeout(RELEASE_TIMEOUT, async {
            while custody.strong_count() != 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "target journal handles retained after drain".into())
    }

    /// The same gate is used at cold start and during serving. In particular a
    /// successful withdrawal is acknowledged before returning its closed state.
    /// RESTORE and confirmation of an already applied activation never waive
    /// the signed bootstrap suspension or capsule binding.
    pub(crate) async fn reconcile(
        agent: &RuntimeAgent,
        manifest: &TargetBootstrapManifest,
        reconciliation: impl Future<Output = RuntimeResult<TargetDispositionAction>>,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<(), Exit> {
        let outcome = tokio::select! {
            biased;
            () = stopped(stop) => Err(Exit::Cancelled),
            result = reconciliation => match result {
                Ok(TargetDispositionAction::Withdraw) => Err(Exit::Withdrawn),
                Err(error) => Err(Exit::DispositionUnavailable(error)),
                Ok(TargetDispositionAction::Restore | TargetDispositionAction::ConfirmActivation) => {
                    if manifest.require_serving().is_err() || agent.with_active_capsule(|capsule, _| {
                        if capsule.target_runtime_id != manifest.target_runtime_id
                            || capsule.capsule_id != manifest.capsule_id
                            || capsule.generation != manifest.capsule_generation
                            || capsule.digest()? != manifest.capsule_digest {
                            return Err(RuntimeError::GenerationMismatch);
                        }
                        Ok(())
                    }).is_err() {
                        Err(Exit::BootstrapChanged)
                    } else {
                        agent.require_current_target_disposition()
                            .map_err(Exit::DispositionUnavailable)
                    }
                },
            },
        };
        if let Err(exit) = outcome {
            return match agent.fence_target_disposition() {
                Ok(()) => Err(exit),
                Err(_) => Err(Exit::CustodyUnavailable),
            };
        }
        Ok(())
    }

    /// Independent of provider recovery: authority loss/cancellation must not
    /// wait for an unrelated readback. Each source check uses the signed file
    /// and installed owners again; no listener readiness flag is consulted.
    pub(crate) async fn watch_current(
        agent: &RuntimeAgent,
        manifest: &TargetBootstrapManifest,
        bootstrap_directory: &Path,
        bootstrap_public: &[u8],
        stop: &mut watch::Receiver<bool>,
    ) -> RuntimeResult<Exit> {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = stopped(stop) => {
                    agent.fence_target_disposition()?;
                    return Ok(Exit::Cancelled);
                },
                _ = interval.tick() => {},
            }
            if let Err(exit) =
                reconcile(agent, manifest, agent.reconcile_target_disposition(), stop).await
            {
                return Ok(exit);
            }
            let now = wall_clock_ns()?;
            if refresh_target_restrictions(
                agent,
                manifest,
                bootstrap_directory,
                bootstrap_public,
                now,
            )
            .is_err()
            {
                return Ok(Exit::BootstrapChanged);
            }
            crate::runtime_target_observation::publish(
                bootstrap_directory,
                agent,
                &manifest.protected_class_set_digest,
                now,
            )?;
        }
    }

    /// Graceful listener shutdown has a finite completion budget. A failure
    /// exits the process owner instead of retrying with detached live handles.
    pub(super) async fn drain<T>(
        server: impl Future<Output = T>,
        draining: Arc<Notify>,
    ) -> TargetResult<T> {
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => Ok(result),
            () = draining.notified() => tokio::time::timeout(RELEASE_TIMEOUT, &mut server).await
                .map_err(|_| "target listener drain timed out".into()),
        }
    }
}

fn wall_clock_ns() -> RuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_nanos().try_into().ok())
        .ok_or(RuntimeError::RuntimeUnavailable)
}

fn required(name: &str) -> TargetResult<String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn hex_bytes(value: &str, maximum: usize) -> TargetResult<Vec<u8>> {
    let value = value.trim();
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum.saturating_mul(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("hexadecimal input rejected".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "hexadecimal input rejected".to_owned())
        })
        .collect()
}

fn read_hex(path: &Path, maximum: usize) -> TargetResult<Vec<u8>> {
    let value = fs::read_to_string(path).map_err(|_| "target trust input unavailable")?;
    hex_bytes(&value, maximum)
}

fn read_key(path: &Path) -> TargetResult<[u8; 32]> {
    read_hex(path, 32)?
        .try_into()
        .map_err(|_| "target signing key rejected".into())
}

fn open_decision_evidence(
    config: &TargetConfig,
    manifest: &TargetBootstrapManifest,
    directory: &Path,
    stream: &str,
) -> RuntimeResult<DecisionEvidenceStore> {
    use openpc_runtime_agent::decision_evidence::EvidenceSpoolBinding;
    let key = read_key(&config.evidence_key_file).map_err(|_| RuntimeError::RuntimeUnavailable)?;
    // Bootstrap verification owns scope authority; an encryption key does not.
    DecisionEvidenceStore::open_sealed(
        directory,
        EvidenceSpoolBinding {
            participant_id: manifest.participant_id.clone(),
            privacy_domain_id: manifest.privacy_domain_id.clone(),
            target_runtime_id: manifest.target_runtime_id.clone(),
            spool_id: format!(
                "{stream}:{}",
                Digest::of(manifest.target_runtime_id.as_bytes()).as_str()
            ),
            key_id: format!("sha256:{}", Digest::of(key).as_str()),
        },
        key,
        1024,
    )
}

/// Host-side diagnostics use the authenticated bootstrap scope and the same
/// read-only encrypted journal decoder as archival. They never claim a writer
/// lock, recover a reservation, or expose request/provider bodies.
pub fn evidence_snapshot_from_environment(stream: &str) -> TargetResult<()> {
    use openpc_runtime_agent::decision_evidence::{EvidenceSpoolBinding, read_spool_snapshot};
    if !matches!(stream, "rpc" | "source") {
        return Err("evidence stream rejected".into());
    }
    let config = TargetConfig::read()?;
    let manifest = read_target_bootstrap(
        &config.bootstrap_directory,
        &read_hex(&config.bootstrap_public_key_file, 256)?,
    )?;
    if manifest.target_runtime_id != config.target_id {
        return Err("evidence target rejected".into());
    }
    let key = read_key(&config.evidence_key_file)?;
    let binding = EvidenceSpoolBinding {
        participant_id: manifest.participant_id,
        privacy_domain_id: manifest.privacy_domain_id,
        target_runtime_id: manifest.target_runtime_id.clone(),
        spool_id: format!(
            "{stream}:{}",
            Digest::of(manifest.target_runtime_id.as_bytes()).as_str()
        ),
        key_id: format!("sha256:{}", Digest::of(key).as_str()),
    };
    let mut directory = config.runtime_root.join("evidence").join(&config.target_id);
    if stream == "source" {
        directory = directory.join("source-reads");
    }
    let value =
        read_spool_snapshot(&directory, &binding, key).map_err(|_| "evidence snapshot rejected")?;
    println!("{value}");
    Ok(())
}

fn secure_directory(path: &Path, failure: &'static str) -> TargetResult<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| failure)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| failure.to_owned())
}

fn socket_policy(
    path: &Path,
    envoy_uid: u32,
    failure: &'static str,
) -> TargetResult<UnixSocketPolicy> {
    match fs::DirBuilder::new().mode(0o750).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(failure.into()),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| failure)?;
    if !metadata.is_dir() {
        return Err(failure.into());
    }
    Ok(UnixSocketPolicy {
        owner_uid: metadata.uid(),
        group_gid: metadata.gid(),
        envoy_uid,
    })
}

fn decode_source<T: DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> TargetResult<T> {
    let value: T = ciborium::de::from_reader(bytes)
        .map_err(|_| "target bootstrap source decoding rejected")?;
    if pc_cbor_1(&value) != bytes {
        return Err("target bootstrap source canonical encoding rejected".into());
    }
    Ok(value)
}

struct TargetConfig {
    target_id: String,
    bootstrap_directory: PathBuf,
    bootstrap_public_key_file: PathBuf,
    agent_key_file: PathBuf,
    evidence_key_file: PathBuf,
    pds_key_file: PathBuf,
    anchor_key_file: PathBuf,
    witness_key_file: PathBuf,
    witness_set_key_file: PathBuf,
    provider_directory: PathBuf,
    runtime_root: PathBuf,
    fact_database_host: String,
    fact_database_port: u16,
    fact_database_name: String,
    fact_database_user: String,
    fact_database_password_file: PathBuf,
    pds_socket: PathBuf,
    broker_socket: PathBuf,
    envoy_uid: u32,
}

impl TargetConfig {
    fn read() -> TargetResult<Self> {
        Ok(Self {
            target_id: required("OPENPC_TARGET_RUNTIME_ID")?,
            bootstrap_directory: required("OPENPC_TARGET_BOOTSTRAP_DIRECTORY")?.into(),
            bootstrap_public_key_file: required("OPENPC_TARGET_BOOTSTRAP_PUBLIC_KEY_FILE")?.into(),
            agent_key_file: required("OPENPC_TARGET_AGENT_SIGNING_SECRET_FILE")?.into(),
            evidence_key_file: required("OPENPC_TARGET_EVIDENCE_ENCRYPTION_KEY_FILE")?.into(),
            pds_key_file: required("OPENPC_TARGET_PDS_SIGNING_SECRET_FILE")?.into(),
            anchor_key_file: required("OPENPC_TARGET_ANCHOR_SIGNING_SECRET_FILE")?.into(),
            witness_key_file: required("OPENPC_TARGET_WITNESS_SIGNING_SECRET_FILE")?.into(),
            witness_set_key_file: required("OPENPC_TARGET_WITNESS_SET_SIGNING_SECRET_FILE")?.into(),
            provider_directory: required("OPENPC_TARGET_PROVIDER_SOURCE_DIRECTORY")?.into(),
            runtime_root: required("OPENPC_TARGET_RUNTIME_ROOT")?.into(),
            fact_database_host: required("OPENPC_TARGET_FACT_DATABASE_HOST")?,
            fact_database_port: required("OPENPC_TARGET_FACT_DATABASE_PORT")?
                .parse()
                .map_err(|_| "target fact database port rejected".to_owned())?,
            fact_database_name: required("OPENPC_TARGET_FACT_DATABASE_NAME")?,
            fact_database_user: required("OPENPC_TARGET_FACT_DATABASE_USER")?,
            fact_database_password_file: required("OPENPC_TARGET_FACT_DATABASE_PASSWORD_FILE")?
                .into(),
            pds_socket: required("OPENPC_TARGET_PDS_SOCKET")?.into(),
            broker_socket: required("OPENPC_TARGET_BROKER_SOCKET")?.into(),
            envoy_uid: required("OPENPC_TARGET_ENVOY_UID")?
                .parse()
                .map_err(|_| "target Envoy uid rejected".to_owned())?,
        })
    }
}

struct FileEvidence {
    agent: Arc<RuntimeAgent>,
    decisions: Arc<DecisionEvidenceStore>,
}

impl FileEvidence {
    fn record(
        &self,
        boundary: &str,
        error: &RuntimeError,
        trace: Option<&str>,
    ) -> RuntimeResult<()> {
        self.decisions.record_transport_denial(
            &self.agent,
            boundary,
            error,
            trace,
            wall_clock_ns()?,
        )?;
        eprintln!(
            "{}",
            serde_json::json!({"boundary": boundary, "pcCode": error.pc_code(), "traceId": trace})
        );
        Ok(())
    }
}

impl TargetTransportEvidence for FileEvidence {
    fn record(&self, error: &RuntimeError, trace: &RequestTraceId) -> RuntimeResult<()> {
        self.record("ext-proc", error, Some(trace.as_str()))
    }

    fn record_pre_admission_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.record("pds-pre-admission", error, Some(trace.as_str()))
    }
}

impl BrokerServerEvidence for FileEvidence {
    fn record_transport_denial(&self, error: &RuntimeError) -> RuntimeResult<()> {
        self.record("broker", error, None)
    }
}

struct TargetAuthority {
    recovery_routes: Vec<RecoveryRoute>,
    workload_header: &'static str,
    capsule: RuntimeCapsule,
    witness_signer_id: String,
    connection: Arc<ConnectionLease>,
    plan: HashPinnedCallProbePlan,
    anchor: Signer,
    witness: Signer,
    witness_set: Signer,
}

struct RecoveryRoute {
    assignment: RoutingAssignment,
    connection: Arc<ConnectionLease>,
    plan: HashPinnedCallProbePlan,
}

fn shared_request_provider<'a>(
    assignments: &[&'a RoutingAssignment],
) -> TargetResult<&'a RoutingAssignment> {
    let first = *assignments
        .first()
        .ok_or("target request routing assignment missing")?;
    // This process uses one decoder/profile and one provider connection for
    // requests. Several policy assignments can safely share that exact owner.
    if assignments.iter().any(|assignment| {
        assignment.provider_profile_id != first.provider_profile_id
            || assignment.endpoint_id != first.endpoint_id
    }) {
        return Err("target request routes require one qualified provider connection".into());
    }
    Ok(first)
}

impl TargetAuthority {
    fn request_assignment(
        &self,
        captured: &CapturedTargetRequest,
    ) -> RuntimeResult<RoutingAssignment> {
        let lease = captured.acquire()?;
        // Select through the live policy/routing owner. A shared provider
        // connection never substitutes another policy's routing assignment.
        let route = lease
            .state()
            .route_for_request(captured.decoded().request())?;
        route.validate_connection(
            self.connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            wall_clock_ns()?,
        )?;
        Ok(route.assignment.clone())
    }

    fn recovery_evidence(&self, target: &ObservationTarget) -> RuntimeResult<RequestRouteEvidence> {
        let route = self
            .recovery_routes
            .iter()
            .find(|route| {
                route.assignment.runtime_binding_id == target.admission().runtime_binding_id
            })
            .ok_or(RuntimeError::Denied)?;
        route_evidence(
            &Digest::parse(&target.command().immutable_request_digest)?,
            target.operation_digest(),
            &self.capsule,
            &route.assignment,
            &self.witness_signer_id,
            route.connection.clone(),
            &route.plan,
            None,
            &self.anchor,
            &self.witness,
            &self.witness_set,
        )
    }
}

impl ProtectedTargetAuthority for TargetAuthority {
    fn replacement_observation_evidence(
        &self,
        target: &ObservationTarget,
    ) -> RuntimeResult<RequestRouteEvidence> {
        self.recovery_evidence(target)
    }
    fn identity_assertion(
        &self,
        _: &WorkloadPeer,
        headers: &[(String, Vec<u8>)],
    ) -> RuntimeResult<IdentityAssertionEvidence> {
        let mut values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(self.workload_header));
        let (_, encoded) = values.next().ok_or(RuntimeError::InvalidAuthorization)?;
        if values.next().is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let encoded = std::str::from_utf8(encoded).map_err(|_| RuntimeError::InvalidInput)?;
        let cose = hex_bytes(encoded, 263_168).map_err(|_| RuntimeError::InvalidInput)?;
        IdentityAssertionEvidence::from_cose_sign1(&cose)
    }

    fn route_evidence(
        &self,
        captured: &CapturedTargetRequest,
    ) -> RuntimeResult<RequestRouteEvidence> {
        let request = captured.decoded().request();
        let assignment = self.request_assignment(captured)?;
        let operation = Digest::of(pc_runtime_types::canonical_bytes(&(
            "openpc-target-route-v1",
            &request.request_digest,
            &assignment.runtime_binding_id,
        ))?);
        route_evidence(
            &request.request_digest,
            &operation,
            &self.capsule,
            &assignment,
            &self.witness_signer_id,
            self.connection.clone(),
            &self.plan,
            None,
            &self.anchor,
            &self.witness,
            &self.witness_set,
        )
    }
    fn submission_connection(
        &self,
        captured: &CapturedTargetRequest,
    ) -> RuntimeResult<Arc<ConnectionLease>> {
        self.request_assignment(captured)?;
        Ok(self.connection.clone())
    }

    fn submission_route_evidence(
        &self,
        captured: &CapturedTargetRequest,
        head: &openpc_multi_rpc::write_preflight::PreflightAnchor,
    ) -> RuntimeResult<RequestRouteEvidence> {
        let request = captured.decoded().request();
        let assignment = self.request_assignment(captured)?;
        let operation = Digest::of(pc_runtime_types::canonical_bytes(&(
            "openpc-target-route-v1",
            &request.request_digest,
            &assignment.runtime_binding_id,
        ))?);
        route_evidence(
            &request.request_digest,
            &operation,
            &self.capsule,
            &assignment,
            &self.witness_signer_id,
            self.connection.clone(),
            &self.plan,
            Some(head),
            &self.anchor,
            &self.witness,
            &self.witness_set,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn route_evidence(
    request_digest: &Digest,
    operation: &Digest,
    capsule: &RuntimeCapsule,
    assignment: &RoutingAssignment,
    witness_signer_id: &str,
    connection: Arc<ConnectionLease>,
    plan: &HashPinnedCallProbePlan,
    observed: Option<&openpc_multi_rpc::write_preflight::PreflightAnchor>,
    anchor_signer: &Signer,
    witness_signer: &Signer,
    set_signer: &Signer,
) -> RuntimeResult<RequestRouteEvidence> {
    let now = wall_clock_ns()?;
    let anchor = if let Some(observed) = observed {
        observed.chain_anchor(
            &assignment.chain_environment_id,
            assignment.canonical_generation,
        )?
    } else {
        ChainAnchor {
            chain_environment_id: assignment.chain_environment_id.clone(),
            chain_id: plan.chain_id,
            block_number: plan.block_number,
            block_hash: plan.block_hash.clone(),
            state_root: plan.state_root.clone(),
            canonical_generation: assignment.canonical_generation,
            observed_at_ns: now,
        }
    };
    let anchor = VerifiedChainAnchor::verify(
        &anchor_signer.verifier(),
        &anchor.sign(anchor_signer)?,
        &ChainAnchorBindings {
            chain_environment_id: &assignment.chain_environment_id,
            chain_id: plan.chain_id,
            canonical_generation: assignment.canonical_generation,
            maximum_age_ns: 30_000_000_000,
        },
        now,
    )?;
    let witness = RequestRouteWitness {
        witness_id: uuid::Uuid::now_v7().to_string(),
        purpose: assignment.purpose,
        operation_digest: operation.clone(),
        request_digest: request_digest.clone(),
        chain_anchor: anchor.anchor().clone(),
        endpoint_id: assignment.endpoint_id.clone(),
        endpoint_role: assignment.endpoint_role,
        routing_snapshot_digest: capsule.routing_snapshot_digest.clone(),
        provider_certification_registry_digest: capsule
            .provider_certification_registry_digest
            .clone(),
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        coherence_group_digest: assignment.coherence_group_digest.clone(),
        selected_at_ns: now,
        selection_deadline_ns: now.saturating_add(20_000_000_000),
        invalidation_generation: assignment.invalidation_generation,
        signer_id: witness_signer_id.into(),
    };
    let verified_witness = VerifiedRouteWitness::verify(
        &witness_signer.verifier(),
        &witness.sign(witness_signer)?,
        &RouteWitnessBindings {
            purpose: witness.purpose,
            operation_digest: &witness.operation_digest,
            request_digest: &witness.request_digest,
            chain_anchor: anchor.anchor(),
            endpoint_id: &witness.endpoint_id,
            endpoint_role: witness.endpoint_role,
            routing_snapshot_digest: &witness.routing_snapshot_digest,
            provider_certification_registry_digest: &witness.provider_certification_registry_digest,
            mrpc_runtime_profile_digest: &witness.mrpc_runtime_profile_digest,
            coherence_group_digest: &witness.coherence_group_digest,
            invalidation_generation: witness.invalidation_generation,
            signer_id: &witness.signer_id,
        },
        now,
    )?;
    let set = RouteWitnessSet {
        set_id: uuid::Uuid::now_v7().to_string(),
        operation_digest: operation.clone(),
        witnesses: vec![RouteWitnessRef {
            purpose: assignment.purpose,
            witness_digest: witness.semantic_digest()?,
        }],
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        created_at_ns: now,
    };
    let verified_set = VerifiedRouteWitnessSet::verify(
        &set_signer.verifier(),
        &set.sign(set_signer)?,
        std::slice::from_ref(&verified_witness),
        &[assignment.purpose],
        operation,
        &capsule.mrpc_runtime_profile_digest,
        now,
    )?;
    Ok(RequestRouteEvidence {
        anchor,
        witness: verified_witness,
        witness_set: verified_set,
        connection,
    })
}

async fn install_connection(
    config: &TargetConfig,
    registry: &ConnectionRegistry,
    provider: &ProviderCertification,
    profile: &pc_provider_api::ProviderProfileV1,
    participant_id: &str,
    privacy_domain_id: &str,
) -> TargetResult<(ConnectionRecord, HashPinnedCallProbePlan)> {
    let prior = registry.readback(&provider.endpoint_id).await.ok();
    let expected_generation = prior
        .as_ref()
        .map_or(0, |record| record.dispatcher_generation);
    let resolution_generation = prior
        .as_ref()
        .map_or(1, |record| record.resolution_generation.saturating_add(1));
    let prepared = provider_probe_source::prepare_matching_profile(
        &config.provider_directory,
        profile,
        participant_id,
        privacy_domain_id,
        resolution_generation,
    )?;
    if prepared.endpoint_id != provider.endpoint_id {
        return Err("target provider endpoint binding rejected".into());
    }
    let plan = prepared.plan.clone();
    let record = registry
        .install(
            &provider.provider_profile_id,
            expected_generation,
            prepared.connection,
        )
        .await
        .map_err(|_| "target provider installation rejected")?;
    if record.configuration_digest != provider.connection_configuration_digest {
        return Err("target provider connection commitment rejected".into());
    }
    Ok((record, plan))
}

/// Invocation startup requires both listeners before the first request.
/// Source-only custody has no Broker and requires signed request observation.
pub fn ready_from_environment() -> TargetResult<()> {
    use std::os::unix::fs::FileTypeExt;
    let config = TargetConfig::read()?;
    let key = read_hex(&config.bootstrap_public_key_file, 256)?;
    let manifest = read_target_bootstrap(&config.bootstrap_directory, &key)?;
    manifest.require_serving().map_err(|_| "target suspended")?;
    manifest
        .target_disposition
        .as_ref()
        .ok_or("target disposition binding missing")?;
    let socket = |path: &Path| fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket());
    if manifest.target_runtime_id != config.target_id
        || !socket(&config.pds_socket)
        || (!manifest.source_only && !socket(&config.broker_socket))
    {
        return Err("target listeners unavailable".into());
    }
    if !manifest.source_only {
        return Ok(());
    }
    let public = RuntimeWireSigner::from_secret_bytes(read_key(&config.agent_key_file)?)
        .map_err(|_| "target readiness signer unavailable")?
        .verifier()
        .public_key_bytes();
    crate::runtime_target_observation::read(
        &config.bootstrap_directory,
        &public,
        &config.target_id,
        &manifest.agent_signer_id,
        &manifest.capsule_digest,
        manifest.capsule_generation,
        wall_clock_ns().map_err(|_| "target readiness clock unavailable")?,
    )
    .map_err(|_| "target readiness observation rejected")?
    .ok_or("target request generation not observed")?;
    Ok(())
}

fn open_active_agent(
    config: &TargetConfig,
    manifest: &mut crate::runtime_target::TargetBootstrapManifest,
) -> TargetResult<(Arc<RuntimeAgent>, RuntimeCapsule)> {
    if manifest.target_runtime_id != config.target_id {
        return Err("target bootstrap identity rejected".into());
    }
    let admission = Arc::new(crate::runtime_target::GovernedJournalAdmission::new(
        &GovernedOwnerTrust {
            participant_id: &manifest.participant_id,
            privacy_domain_id: &manifest.privacy_domain_id,
            target_runtime_id: &manifest.target_runtime_id,
            authority_signer_id: &manifest.authority_signer_id,
            authority_public_key: &manifest.fleet_runtime_public_key,
            identity_runtime_public_key: &manifest.identity_runtime_public_key,
            identity_profile_digest: manifest.identity_profile_digest.clone(),
            fact_verify_key: &manifest.fact_verify_key,
            fact_verify_key_id: &manifest.fact_verify_key_id,
            mrpc_runtime_profile: &manifest.mrpc_runtime_profile,
        },
    ));
    let agent = Arc::new(
        RuntimeAgent::open_canonical(
            CapsuleTrust {
                target_id: manifest.target_runtime_id.clone(),
                fleet_id: manifest.fleet_id.clone(),
                fleet_signer_id: manifest.fleet_signer_id.clone(),
                agent_signer_id: manifest.agent_signer_id.clone(),
                contract_set_manifest_digest: manifest.contract_set_manifest_digest.clone(),
                schema_registry_digest: manifest.schema_registry_digest.clone(),
                cose_purpose_registry_digest: manifest.cose_purpose_registry_digest.clone(),
                complete_component_set_digest: manifest.complete_component_set_digest.clone(),
            },
            &manifest.fleet_runtime_public_key,
            read_key(&config.agent_key_file)?,
            64,
            1024 * 1024,
            &config.runtime_root.join("agent").join(&config.target_id),
            Arc::new(GovernedOrBootstrapAdmission {
                governed: admission,
            }),
        )
        .map_err(|error| format!("target runtime journal rejected: {}", error.pc_code()))?,
    );
    let (active_digest, _, _) = agent
        .active_canonical_generation()
        .map_err(|_| "target active generation unavailable")?
        .ok_or("target active generation missing")?;
    if active_digest != manifest.capsule_digest {
        return Err("target active generation bootstrap mismatch".into());
    }
    crate::runtime_target_observation::clear(&config.bootstrap_directory)
        .map_err(|_| "target previous observation retirement failed")?;
    let capsule = agent
        .with_active_capsule(|capsule, _| Ok(capsule.clone()))
        .map_err(|_| "target active capsule unavailable")?;
    if capsule.capsule_id != manifest.capsule_id
        || capsule.generation != manifest.capsule_generation
        || capsule
            .digest()
            .map_err(|_| "target capsule digest rejected")?
            != manifest.capsule_digest
    {
        return Err("target capsule bootstrap mismatch".into());
    }
    if let Some(emergency) = manifest.emergency_delivery.take() {
        emergency
            .install(
                &agent,
                wall_clock_ns().map_err(|_| "target clock unavailable")?,
            )
            .map_err(|_| "target emergency delivery rejected")?;
    }
    Ok((agent, capsule))
}

pub async fn run_from_environment() -> TargetResult<()> {
    run_from_environment_until(std::future::pending()).await
}

/// Cooperative cancellation signals the active serving session and awaits its
/// listener/journal release; it never drops a spawned server and starts another.
pub async fn run_from_environment_until(
    shutdown: impl std::future::Future<Output = ()>,
) -> TargetResult<()> {
    lifecycle::run(run_session_from_environment, shutdown).await
}

async fn run_session_from_environment(
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> TargetResult<lifecycle::Attempt> {
    if *stop.borrow() {
        return Ok(lifecycle::Attempt::closed(lifecycle::Exit::Cancelled));
    }
    let config = TargetConfig::read()?;
    let bootstrap_public = read_hex(&config.bootstrap_public_key_file, 256)?;
    let mut manifest = match read_target_bootstrap(&config.bootstrap_directory, &bootstrap_public) {
        Ok(manifest) if manifest.target_runtime_id == config.target_id => manifest,
        _ => {
            return Ok(lifecycle::Attempt::closed(
                lifecycle::Exit::BootstrapUnavailable,
            ));
        }
    };
    let (agent, capsule) = match open_active_agent(&config, &mut manifest) {
        Ok(opened) => opened,
        Err(_) => {
            return Ok(lifecycle::Attempt::closed(
                lifecycle::Exit::CustodyUnavailable,
            ));
        }
    };
    let custody = Arc::downgrade(&agent);
    let result = if let Err(exit) = lifecycle::reconcile(
        &agent,
        &manifest,
        establish_target_disposition(&agent, &manifest),
        &mut stop,
    )
    .await
    {
        Ok(exit)
    } else if manifest.source_only {
        source_only::run(config, manifest, bootstrap_public, agent.clone(), stop).await
    } else {
        run_invocation(
            config,
            manifest,
            bootstrap_public,
            agent.clone(),
            capsule,
            stop,
        )
        .await
    };
    agent
        .fence_target_disposition()
        .map_err(|_| "target final admission fence unavailable")?;
    drop(agent);
    Ok(lifecycle::Attempt { result, custody })
}

async fn run_invocation(
    config: TargetConfig,
    manifest: TargetBootstrapManifest,
    bootstrap_public: Vec<u8>,
    agent: Arc<RuntimeAgent>,
    capsule: RuntimeCapsule,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> TargetResult<lifecycle::Exit> {
    let fact_password = fs::read_to_string(&config.fact_database_password_file)
        .map_err(|_| "target fact database password unavailable")?;
    let fact_password = fact_password.trim();
    if fact_password.is_empty()
        || !fact_password
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err("target fact database password rejected".into());
    }
    let fact_database_url = format!(
        "postgresql://{}:{}@{}:{}/{}",
        config.fact_database_user,
        fact_password,
        config.fact_database_host,
        config.fact_database_port,
        config.fact_database_name
    );
    let owners = build_governed_runtime_owners(
        GovernedOwnerTrust {
            participant_id: &manifest.participant_id,
            privacy_domain_id: &manifest.privacy_domain_id,
            target_runtime_id: &manifest.target_runtime_id,
            authority_signer_id: &manifest.authority_signer_id,
            authority_public_key: &manifest.fleet_runtime_public_key,
            identity_runtime_public_key: &manifest.identity_runtime_public_key,
            identity_profile_digest: manifest.identity_profile_digest.clone(),
            fact_verify_key: &manifest.fact_verify_key,
            fact_verify_key_id: &manifest.fact_verify_key_id,
            mrpc_runtime_profile: &manifest.mrpc_runtime_profile,
        },
        capsule.policy_fact_state_digest
            != pc_runtime_types::Digest::of(
                openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION,
            ),
        passthrough_admission,
    )?;
    let routing: RoutingSnapshotSource = decode_source(&manifest.routing_source)?;
    let certification: ProviderCertificationSource = decode_source(&manifest.certification_source)?;
    let request_assignments = routing
        .assignments
        .iter()
        .filter(|a| a.purpose != 4)
        .collect::<Vec<_>>();
    let assignment = shared_request_provider(&request_assignments)?;
    // Separate write/observation pairs for the selected contract and deployment
    // bindings remain bounded even when they share one qualified connection.
    if routing.assignments.len() > 16 {
        return Err("target route connection capacity rejected".into());
    }
    let provider = certification
        .certifications
        .iter()
        .find(|candidate| {
            candidate.provider_profile_id == assignment.provider_profile_id
                && candidate.endpoint_id == assignment.endpoint_id
        })
        .ok_or("target provider certification unavailable")?;
    let profile = openpc_multi_rpc::qualify_provider_profile(
        &provider.provider_profile_cbor,
        &format!("sha256:{}", provider.provider_artifact_digest.as_str()),
    )
    .map_err(|_| "target provider profile rejected")?;
    let registry_directory = config
        .runtime_root
        .join("connections")
        .join(&config.target_id);
    secure_directory(
        &registry_directory,
        "target connection directory unavailable",
    )?;
    let registry = ConnectionRegistry::open(&registry_directory, &config.target_id, 8)
        .map_err(|_| "target connection registry rejected")?;
    let (request_record, plan) = install_connection(
        &config,
        &registry,
        provider,
        &profile,
        &manifest.participant_id,
        &manifest.privacy_domain_id,
    )
    .await?;
    let mut endpoint_ids = std::collections::BTreeSet::from([assignment.endpoint_id.as_str()]);
    let mut installed_recovery = Vec::new();
    for recovery in routing.assignments.iter().filter(|a| a.purpose == 4) {
        if recovery.endpoint_id == assignment.endpoint_id
            && recovery.provider_profile_id == assignment.provider_profile_id
            && recovery.endpoint_role == assignment.endpoint_role
            && assignment.purpose == 3
        {
            // An original handed-off command can outlive its submission policy.
            // Sharing the qualified connection does not install a request grant;
            // select_observation still checks the original journal's provider pin.
            installed_recovery.push((recovery.clone(), request_record.clone(), plan.clone()));
            continue;
        }
        if !endpoint_ids.insert(recovery.endpoint_id.as_str()) {
            return Err("target route endpoint ownership collision".into());
        }
        let provider = certification
            .certifications
            .iter()
            .find(|c| {
                c.provider_profile_id == recovery.provider_profile_id
                    && c.endpoint_id == recovery.endpoint_id
            })
            .ok_or("target recovery certification unavailable")?;
        let profile = openpc_multi_rpc::qualify_provider_profile(
            &provider.provider_profile_cbor,
            &format!("sha256:{}", provider.provider_artifact_digest.as_str()),
        )
        .map_err(|_| "target recovery profile rejected")?;
        let (record, plan) = install_connection(
            &config,
            &registry,
            provider,
            &profile,
            &manifest.participant_id,
            &manifest.privacy_domain_id,
        )
        .await?;
        installed_recovery.push((recovery.clone(), record, plan));
    }
    // Registry leases fence reconfiguration for the whole registry. Install
    // the complete committed connection set before taking any read lease.
    let connection = Arc::new(
        registry
            .acquire(
                &provider.provider_profile_id,
                &provider.endpoint_id,
                request_record.dispatcher_generation,
            )
            .map_err(|_| "target request provider lease rejected")?,
    );
    let recovery_routes = installed_recovery
        .into_iter()
        .map(|(assignment, record, plan)| {
            let connection = Arc::new(
                registry
                    .acquire(
                        &assignment.provider_profile_id,
                        &assignment.endpoint_id,
                        record.dispatcher_generation,
                    )
                    .map_err(|_| "target recovery provider lease rejected")?,
            );
            Ok(RecoveryRoute {
                assignment,
                connection,
                plan,
            })
        })
        .collect::<TargetResult<Vec<_>>>()?;
    let anchor = Signer::from_secret_bytes(read_key(&config.anchor_key_file)?)
        .map_err(|_| "target anchor signer rejected")?;
    let witness = Signer::from_secret_bytes(read_key(&config.witness_key_file)?)
        .map_err(|_| "target witness signer rejected")?;
    let witness_set = Signer::from_secret_bytes(read_key(&config.witness_set_key_file)?)
        .map_err(|_| "target witness-set signer rejected")?;
    let evidence_directory = config.runtime_root.join("evidence").join(&config.target_id);
    secure_directory(&evidence_directory, "target evidence directory unavailable")?;
    let evidence = Arc::new(
        open_decision_evidence(&config, &manifest, &evidence_directory, "rpc")
            .map_err(|_| "target decision evidence rejected")?,
    );
    let state = TargetState::new(
        manifest.protected_class_set_digest.clone(),
        manifest.privacy_domain_id.clone(),
        TargetStateOwners {
            agent: Arc::clone(&agent),
            identity: owners.identity.clone(),
            identity_assertions: owners.identity_assertions.clone(),
            invocation: owners.invocation.clone(),
            invocation_profile: owners.invocation_profile.clone(),
            facts: owners.facts.clone(),
            fact_reader: FactLeaseReader::connect(
                fact_database_url,
                openpc_fact_service::FactSignatureVerifier::from_key_identifier(
                    &manifest.fact_verify_key_id,
                    &manifest.fact_verify_key,
                )
                .map_err(|_| "target fact verifier rejected")?,
            )
            .map_err(|_| "target fact reader rejected")?,
            mrpc: owners.mrpc.clone(),
            routing: owners.routing.clone(),
            route_evidence_trust: RouteEvidenceTrust::new(
                &anchor.verifier(),
                &witness.verifier(),
                &witness_set.verifier(),
                manifest.authority_signer_id.clone(),
            )
            .map_err(|_| "target route evidence trust rejected")?,
            evidence: evidence.clone(),
        },
    )
    .map_err(|_| "target state rejected")?;
    let pds = Arc::new(
        PolicyDecisionService::with_identity_trust(
            read_key(&config.pds_key_file)?,
            5_000,
            IdentityAssertionVerifier::new(
                std::slice::from_ref(&manifest.identity_runtime_public_key),
                60_000,
            )
            .map_err(|_| "target PDS identity trust rejected")?,
        )
        .map_err(|_| "target PDS rejected")?,
    );
    let broker_directory = config.runtime_root.join("broker").join(&config.target_id);
    secure_directory(&broker_directory, "target Broker directory unavailable")?;
    let broker = Arc::new(
        BrokerService::open(
            &config.target_id,
            &pds.capability_verifier_sec1(),
            1024,
            &broker_directory,
        )
        .map_err(|_| "target Broker rejected")?,
    );
    let submissions = Arc::new(
        openpc_broker::write_dispatch::SubmissionBroker::open(
            broker.clone(),
            &config.target_id,
            &broker_directory,
        )
        .map_err(|_| "target submission journal rejected")?,
    );
    let handoffs = Arc::new(
        BrokerHandoffStore::new(broker.clone(), 64, 4 * 1024 * 1024)
            .and_then(|store| store.with_submissions(submissions.clone()))
            .map_err(|_| "target Broker handoff rejected")?,
    );
    let transport_evidence = Arc::new(FileEvidence {
        agent: agent.clone(),
        decisions: evidence.clone(),
    });
    let authority = Arc::new(TargetAuthority {
        recovery_routes,
        workload_header: "x-openpc-identity-assertion",
        capsule,
        witness_signer_id: manifest.authority_signer_id.clone(),
        connection,
        plan,
        anchor,
        witness,
        witness_set,
    });
    let block_selector = format!("0x{:x}", authority.plan.block_number);
    let owner: Arc<dyn ExtProcRequestOwner> = Arc::new(
        ProtectedTargetOwner::new(
            state.clone(),
            broker,
            handoffs.clone(),
            authority.clone(),
            transport_evidence.clone(),
            RequestDecodeLimits {
                maximum_request_bytes: profile.limits.max_request_bytes as usize,
                maximum_response_bytes: profile.limits.max_response_bytes,
                timeout_ms: profile.timeout_budget_millis,
                block_selector: &block_selector,
            },
        )
        .and_then(|owner| {
            owner.with_cigl_analysis_target(
                &config.target_id,
                read_key(&config.agent_key_file).map_err(|_| RuntimeError::InvalidAuthorization)?,
            )
        })
        .and_then(
            |owner| match env::var("OPENPC_MANAGED_DEPLOYMENT_ENABLED").as_deref() {
                Ok("true") => owner.with_deployment_worker_key(&bootstrap_public),
                Ok("false") | Err(_) => Ok(owner),
                _ => Err(RuntimeError::InvalidInput),
            },
        )
        .map_err(|_| "target protected owner rejected")?,
    );
    let owner = source_only::mixed_owner(
        &config,
        &manifest,
        agent.clone(),
        state.clone(),
        owners.identity.clone(),
        transport_evidence.clone(),
        owner,
    )
    .await?;
    let ext_proc = ExtProcService::new(
        pds,
        owner,
        ExtProcLimits {
            headers: 128,
            header_bytes: 64 * 1024,
            body_bytes: profile.limits.max_request_bytes as usize,
        },
    )
    .map_err(|_| "target ext-proc service rejected")?;
    let socket_parent = config
        .pds_socket
        .parent()
        .ok_or("target socket parent rejected")?;
    let socket_policy = socket_policy(
        socket_parent,
        config.envoy_uid,
        "target socket directory rejected",
    )?;
    // Provider/setup work may outlive the earlier currentness observation.
    if let Err(exit) = lifecycle::reconcile(
        &agent,
        &manifest,
        agent.reconcile_target_disposition(),
        &mut stop,
    )
    .await
    {
        return Ok(exit);
    }
    if refresh_target_restrictions(
        &agent,
        &manifest,
        &config.bootstrap_directory,
        &bootstrap_public,
        wall_clock_ns().map_err(|_| "target clock unavailable")?,
    )
    .is_err()
    {
        return Ok(lifecycle::Exit::BootstrapChanged);
    }
    let pds_listener = OwnedUnixListener::bind(&config.pds_socket, socket_policy)
        .await
        .map_err(|_| "target PDS socket rejected")?;
    let broker_listener = OwnedUnixListener::bind(&config.broker_socket, socket_policy)
        .await
        .map_err(|_| "target Broker socket rejected")?;
    let broker_evidence: Arc<dyn BrokerServerEvidence> = transport_evidence.clone();
    let recovery = async {
        let mut projection =
            if env::var("OPENPC_MANAGED_DEPLOYMENT_ENABLED").as_deref() == Ok("true") {
                Some(
                    crate::deployment_projection::DeploymentProjectionPublisher::new(
                        &config.runtime_root,
                        &config.target_id,
                        read_key(&config.agent_key_file)
                            .map_err(|_| RuntimeError::RuntimeUnavailable)?,
                    )?,
                )
            } else {
                None
            };
        let mut cursor = None;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = state
                .recover_next(submissions.clone(), &mut cursor, |target| {
                    authority.recovery_evidence(target)
                })
                .await
            {
                // A failed observation is an operational diagnostic, not a
                // pre-admission denial of the already-started write. The write
                // journal retains its original outcome; current authority is
                // still required by both recovery and the request owner.
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "submission_recovery_deferred",
                        "level": "warn",
                        "pcCode": error.pc_code(),
                        "operationId": cursor,
                    })
                );
            }
            if let Some(publisher) = &mut projection {
                publisher.publish_next(&submissions)?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), RuntimeError>(())
    };
    tokio::pin!(recovery);
    let mut recovery_failure = None;

    let draining = Arc::new(tokio::sync::Notify::new());
    lifecycle::drain(
        serve_protected_target(
            ext_proc,
            pds_listener,
            handoffs,
            broker_evidence,
            broker_listener,
            profile.limits.max_request_bytes as usize,
            async {
                recovery_failure = Some(tokio::select! {
                    result = lifecycle::watch_current(&agent, &manifest, &config.bootstrap_directory, &bootstrap_public, &mut stop) => result,
                    result = &mut recovery => result.and(Err(RuntimeError::RuntimeUnavailable)),
                });
                // Ensure every shutdown cause closes request admission before drain.
                let _ = agent.fence_target_disposition();
                draining.notify_one();
            },
        ),
        draining.clone(),
    )
    .await?
    .map_err(|error| format!("target server stopped: {}", error.pc_code()))?;
    crate::runtime_target_observation::clear(&config.bootstrap_directory)
        .map_err(|_| "target stopped observation retirement failed")?;
    match recovery_failure {
        Some(Ok(exit)) => Ok(exit),
        Some(Err(error)) => Err(format!("target recovery stopped: {}", error.pc_code())),
        None => Err("target listener stopped without reconciliation".into()),
    }
}

#[cfg(test)]
mod request_provider_tests {
    use super::*;

    #[test]
    fn multiple_policy_assignments_share_only_the_exact_request_provider() {
        let first = RoutingAssignment {
            runtime_binding_id: "first-policy".into(),
            method: "eth_sendRawTransaction".into(),
            risk_class: "HIGH".into(),
            provider_profile_id: "profile".into(),
            endpoint_id: "endpoint".into(),
            endpoint_role: 4,
            purpose: 3,
            chain_environment_id: "chain".into(),
            canonical_generation: 1,
            invalidation_generation: 1,
            coherence_group_digest: Digest::of("coherence"),
            valid_until_ns: 100,
            required_facts: vec![],
        };
        let mut second = first.clone();
        second.runtime_binding_id = "second-policy".into();
        assert!(shared_request_provider(&[&first, &second]).is_ok());
        assert!(shared_request_provider(&[]).is_err());
        second.endpoint_id = "other-endpoint".into();
        assert!(shared_request_provider(&[&first, &second]).is_err());
        second.endpoint_id = first.endpoint_id.clone();
        second.provider_profile_id = "other-profile".into();
        assert!(shared_request_provider(&[&first, &second]).is_err());
    }
}
