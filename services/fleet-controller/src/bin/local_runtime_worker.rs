#![forbid(unsafe_code)]

#[path = "local_runtime_worker/activation_observation.rs"]
mod activation_observation;

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openpc_fact_service::{FactSignatureVerifier, PolicyFactReader, VerifiedShard};
use openpc_fleet_controller::contract_policy::{
    AdmittedContractPolicy, compile_admitted_contract_policies,
};
use openpc_fleet_controller::local_fixture::build_local_configuration_fixture_in_scope;
use openpc_fleet_controller::routing_publication::{
    CERTIFICATION_ARTIFACT_ID, GovernedRoutingPublicationInput, PublishedRoutingArtifacts,
    ROUTING_ARTIFACT_ID, RoutingPublicationRepository,
};
use openpc_fleet_controller::runtime_configuration_input::{
    RUNTIME_ARTIFACT_BUSY, runtime_artifact_database_error, runtime_artifact_new_use_allowed,
};
use openpc_fleet_controller::runtime_target::{
    BootstrapArtifactAdmission as WorkerArtifactAdmission, GovernedOrBootstrapAdmission,
    GovernedOwnerTrust, TargetBootstrapManifest, build_governed_runtime_owners,
    read_target_bootstrap, renew_target_restrictions, retire_target_bootstrap,
    write_target_bootstrap,
};
use openpc_fleet_controller::{
    FleetController, TargetIdentity, ads::AdsService, canonical_target::CanonicalTargetCoordinator,
    envoy_resources::ProtectedListenerConfig, runtime_tls, serve_ads,
};
use openpc_indexer_adapter::{admit_scoped_client_indexer_profile, validate_projection_admission};
use openpc_multi_rpc::qualify_provider_profile;
use openpc_pds::{
    ActiveInvocationScope, ConfigurationArtifactKind, ValidatedInvocationPolicy,
    decode_active_invocation_configuration, encode_active_invocation_configuration,
    load_active_configuration_artifact,
};
#[cfg(test)]
use openpc_runtime_agent::ArtifactBundle;
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent, CapsuleTrust, RevocationFreshnessLease, RuntimeAgent,
    RuntimeCapsule, RuntimeWireSigner,
    authority_artifact::{AuthorityArtifact, AuthoritySourceBinding},
};

fn protected_class_set_digest() -> Digest {
    Digest::of(b"OpenPC R1 contract-read protected classes v1")
}
use pc_policy_core::{
    contract_policy::CompiledContractPolicyBundle, runtime_wire::Signer as ProfileSigner,
};
use pc_runtime_types::{
    ActivationReceipt, Digest, PURPOSE_ACTIVATION_RECEIPT_V1, PurposeSigner, SignedEnvelope,
    TargetState, canonical_bytes,
};
#[cfg(test)]
use pc_runtime_types::{DesiredGeneration, PURPOSE_DESIRED_GENERATION_V1};
use serde_json::Value;
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

type WorkerResult<T> = Result<T, String>;
const TARGET_DISPOSITION_PENDING: &str = "target withdrawal acknowledgement pending";
#[path = "local_runtime_worker/activation_maintenance.rs"]
mod activation_maintenance;
#[path = "local_runtime_worker/cigl_activation.rs"]
mod cigl_activation;
#[path = "local_runtime_worker/cigl_invalidation.rs"]
mod cigl_invalidation;
#[path = "local_runtime_worker/cigl_profile.rs"]
mod cigl_profile;
#[path = "local_runtime_worker/discovery.rs"]
mod discovery;
#[path = "local_runtime_worker/discovery_retry.rs"]
mod discovery_retry;
#[path = "local_runtime_worker/disposition_restore.rs"]
mod disposition_restore;
#[path = "local_runtime_worker/expired_activation.rs"]
mod expired_activation;
#[path = "local_runtime_worker/platform_scope.rs"]
mod platform_scope;
#[path = "local_runtime_worker/projection_admission.rs"]
mod projection_admission;
#[cfg(test)]
#[path = "local_runtime_worker/recovery_tests.rs"]
mod recovery_tests;
#[path = "local_runtime_worker/retained_target.rs"]
mod retained_target;
#[path = "local_runtime_worker/settled_transport.rs"]
mod settled_transport;
#[path = "local_runtime_worker/source_activation.rs"]
mod source_activation;
#[path = "local_runtime_worker/source_revision.rs"]
mod source_revision;
type CapsuleBuild = (
    RuntimeCapsule,
    BTreeMap<Digest, Vec<u8>>,
    Arc<dyn ArtifactAdmission>,
);

#[derive(Clone, Copy)]
enum ExecutionPersistence<'a> {
    Durable(&'a PgPool),
    #[cfg(test)]
    TestOnlyBypass,
}

#[derive(Clone, Debug)]
struct Config {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: String,
    participant_id: String,
    privacy_domain_id: String,
    worker_id: String,
    artifact_capacity_bytes: u64,
    fleet_key: [u8; 32],
    agent_key: [u8; 32],
    identity_runtime_public_key: Vec<u8>,
    fact_host: String,
    fact_port: u16,
    fact_database: String,
    fact_user: String,
    fact_password: String,
    fact_verify_key: Vec<u8>,
    fact_verify_key_id: String,
}

struct RuntimePlaneConfig {
    listen: String,
    server_certificate: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    target_client_certificate: PathBuf,
    protected_bind: String,
    protected_port: u32,
    pds_socket: String,
    broker_socket: String,
    protected_certificate: String,
    protected_key: String,
    workload_ca: String,
}

struct RuntimePlane {
    fleet: Arc<FleetController>,
    ads: AdsService,
    config: RuntimePlaneConfig,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    disposition: Option<Arc<openpc_fleet_controller::target_disposition::TargetDispositionStore>>,
    facts: disposition_restore::FactCustody,
    agent_public_key: Vec<u8>,
    runtime_agent_public_key: Vec<u8>,
    source_custody: openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
}

struct ObservedArtifactAdmission {
    owner: &'static str,
    inner: Arc<dyn ArtifactAdmission>,
}

impl ArtifactAdmission for ObservedArtifactAdmission {
    fn validate(
        &self,
        component: &ArtifactComponent,
        bytes: &[u8],
    ) -> pc_runtime_types::RuntimeResult<()> {
        self.inner.validate(component, bytes).inspect_err(|error| {
            eprintln!(
                "{{\"boundary\":\"runtime_artifact_admission\",\"event\":\"owner_rejected\",\"owner\":\"{}\",\"pc_code\":\"{}\"}}",
                self.owner,
                error.pc_code()
            );
        })
    }

    fn validate_component_in_bundle(
        &self,
        capsule: &RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> pc_runtime_types::RuntimeResult<BTreeSet<Digest>> {
        self.inner
            .validate_component_in_bundle(capsule, component, artifacts)
            .inspect_err(|error| {
                eprintln!(
                    "{{\"boundary\":\"runtime_artifact_admission\",\"event\":\"owner_rejected\",\"owner\":\"{}\",\"pc_code\":\"{}\"}}",
                    self.owner,
                    error.pc_code()
                );
            })
    }

    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> pc_runtime_types::RuntimeResult<BTreeSet<Digest>> {
        self.inner
            .validate_bundle(capsule, artifacts)
            .inspect_err(|error| {
                eprintln!(
                    "{{\"boundary\":\"runtime_artifact_admission\",\"event\":\"owner_rejected\",\"owner\":\"{}\",\"pc_code\":\"{}\"}}",
                    self.owner,
                    error.pc_code()
                );
            })
    }
}

fn observed_admission(
    owner: &'static str,
    inner: Arc<dyn ArtifactAdmission>,
) -> Arc<dyn ArtifactAdmission> {
    Arc::new(ObservedArtifactAdmission { owner, inner })
}

fn prior_target_manifest(
    config: &Config,
    target_id: &str,
    expected_digest: Option<&Digest>,
) -> WorkerResult<Option<TargetBootstrapManifest>> {
    let Some(expected_digest) = expected_digest else {
        return Ok(None);
    };
    let directory = Path::new("/runtime/target-bootstrap").join(target_id);
    if !directory.join("bootstrap.json").exists() {
        return Ok(None);
    }
    let fleet_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.fleet_key)
            .map_err(|_| "target bootstrap verifier unavailable")?
            .verifier()
            .sec1_bytes();
    let manifest = read_target_bootstrap(&directory, &fleet_public)?;
    if manifest.target_runtime_id != target_id
        || manifest.participant_id != config.participant_id
        || manifest.privacy_domain_id != config.privacy_domain_id
        || manifest.authority_signer_id != config.worker_id
        || manifest.capsule_digest != *expected_digest
    {
        return Err("target bootstrap predecessor binding rejected".into());
    }
    Ok(Some(manifest))
}
fn prior_governed_admission(
    config: &Config,
    target_id: &str,
    expected_digest: Option<&Digest>,
) -> WorkerResult<Option<Arc<dyn ArtifactAdmission>>> {
    let Some(manifest) = prior_target_manifest(config, target_id, expected_digest)? else {
        return Ok(None);
    };
    let authority_public_key = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "runtime authority verifier unavailable")?
        .verifier()
        .public_key_bytes();
    let trust = GovernedOwnerTrust {
        participant_id: &manifest.participant_id,
        privacy_domain_id: &manifest.privacy_domain_id,
        target_runtime_id: &manifest.target_runtime_id,
        authority_signer_id: &manifest.authority_signer_id,
        authority_public_key: &authority_public_key,
        identity_runtime_public_key: &config.identity_runtime_public_key,
        identity_profile_digest: manifest.identity_profile_digest,
        fact_verify_key: &config.fact_verify_key,
        fact_verify_key_id: &config.fact_verify_key_id,
        mrpc_runtime_profile: &manifest.mrpc_runtime_profile,
    };
    Ok(Some(Arc::new(GovernedOrBootstrapAdmission {
        governed: Arc::new(
            openpc_fleet_controller::runtime_target::GovernedJournalAdmission::new(&trust),
        ),
    })))
}
fn prior_governed_owners(
    config: &Config,
    target_id: &str,
    expected_digest: Option<&Digest>,
) -> WorkerResult<Option<openpc_fleet_controller::runtime_target::GovernedRuntimeOwners>> {
    let Some(manifest) = prior_target_manifest(config, target_id, expected_digest)? else {
        return Ok(None);
    };
    if manifest.source_only {
        return Err("invocation predecessor required".into());
    }
    let authority_public_key = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "runtime authority verifier unavailable")?
        .verifier()
        .public_key_bytes();
    let trust = GovernedOwnerTrust {
        participant_id: &manifest.participant_id,
        privacy_domain_id: &manifest.privacy_domain_id,
        target_runtime_id: &manifest.target_runtime_id,
        authority_signer_id: &manifest.authority_signer_id,
        authority_public_key: &authority_public_key,
        identity_runtime_public_key: &config.identity_runtime_public_key,
        identity_profile_digest: manifest.identity_profile_digest,
        fact_verify_key: &config.fact_verify_key,
        fact_verify_key_id: &config.fact_verify_key_id,
        mrpc_runtime_profile: &manifest.mrpc_runtime_profile,
    };
    Ok(Some(build_governed_runtime_owners(
        trust,
        true,
        observed_admission,
    )?))
}

#[derive(Clone, Debug)]
struct IdentityPublication {
    manifest_digest: Digest,
    manifest_cose: Vec<u8>,
    profile_digest: Digest,
    profile_cose: Vec<u8>,
    contents: Vec<Vec<u8>>,
    expires_at_ns: u64,
}

#[derive(Clone)]
struct GovernedCustodyMaterial<'a> {
    identity: IdentityPublication,
    fact: Option<VerifiedShard>,
    invocation: &'a CompiledContractPolicyBundle,
    cigl_settings: openpc_fleet_controller::cigl_publication::VerifiedCiglSettingsSources,
    cigl_profiles: Option<&'a openpc_fleet_controller::cigl_publication::profile_activation::VerifiedProfileActivation>,
}

enum WorkCompletion {
    Current(Option<Digest>, Value, Digest),
    Historical(disposition_restore::HistoricalCompletionCandidate),
}

#[derive(Clone, Debug)]
struct ClaimedWork {
    work_id: String,
    occurrence_id: Option<String>,
    operation_id: String,
    work_kind: String,
    resource_id: String,
    input_digest: String,
    participant_id: String,
    privacy_domain_id: String,
    configuration_cbor: Vec<u8>,
    configuration_digest: Digest,
    policy: Option<ClaimedPolicy>,
    related_profile_receipt: Option<Value>,
    provider_receipt: Option<Value>,
    projection_receipt: Option<Value>,
    contract_policy_assets: Vec<AdmittedContractPolicy>,
    generation_id: Option<String>,
    target_id: Option<String>,
    generation_digest: Option<Digest>,
    predecessor_digest: Option<Digest>,
    xds_version_digest: Option<Digest>,
    active_generation_digest: Option<Digest>,
    active_xds_version_digest: Option<Digest>,
    journal_sequence: u64,
    attempt_count: i64,
    execution_attempt_id: Option<String>,
    reconcile_only: bool,
}

#[derive(Clone, Debug)]
struct ClaimedPolicy {
    artifact_cbor: Vec<u8>,
    artifact_digest: Digest,
    fact_generation_digest: Digest,
    generation_digest: Digest,
}

impl ClaimedWork {
    fn policy(&self) -> WorkerResult<&ClaimedPolicy> {
        self.policy
            .as_ref()
            .ok_or_else(|| "serving policy provenance unavailable".into())
    }

    fn result_identity(
        &self,
    ) -> openpc_fleet_controller::configuration_result::WorkResultIdentity<'_> {
        openpc_fleet_controller::configuration_result::WorkResultIdentity {
            participant_id: &self.participant_id,
            privacy_domain_id: &self.privacy_domain_id,
            operation_id: &self.operation_id,
            work_id: &self.work_id,
            resource_id: &self.resource_id,
        }
    }
}

// Configuration rows retain the generation under which they were governed.
// Typed policies name immutable revisions; consuming one in a later generation
// must not require rewriting its admission provenance. Legacy snapshots still
// require the original generation match.
fn decode_claimed_contract_assets(
    value: Value,
    policy_cbor: &[u8],
) -> WorkerResult<Vec<AdmittedContractPolicy>> {
    let typed = pc_policy_core::semantics::PolicySemanticDocument::decode(policy_cbor).is_ok();
    let Value::Array(rows) = value else {
        return Err("invalid contract policy assets".into());
    };
    let mut assets = Vec::new();
    for mut row in rows {
        let matching_generation = row
            .as_object_mut()
            .and_then(|row| row.remove("generationMatches"))
            .and_then(|value| value.as_bool());
        if typed
            || matching_generation
                .ok_or_else(|| "invalid contract generation provenance".to_owned())?
        {
            assets.push(
                serde_json::from_value(row)
                    .map_err(|_| "invalid contract policy assets".to_owned())?,
            );
        }
    }
    Ok(assets)
}

fn required(name: &str) -> WorkerResult<String> {
    env::var(name).map_err(|_| format!("missing {name}"))
}

fn read_secret(path: &str) -> WorkerResult<String> {
    let value = fs::read_to_string(Path::new(path)).map_err(|_| "secret unavailable".to_owned())?;
    let value = value.trim();
    if !(32..=256).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("invalid secret".into());
    }
    Ok(value.into())
}

#[cfg(test)]
fn publication_declared_bytes(publication: &PublishedRoutingArtifacts) -> usize {
    publication.mrpc_runtime_profile.len()
        + publication.routing_source.len()
        + publication.routing_authority.len()
        + publication.certification_source.len()
        + publication.certification_authority.len()
}

fn add_runtime_component(
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    components: &mut Vec<ArtifactComponent>,
    component_id: &str,
    schema_id: u64,
    semantic_digest: Digest,
    bytes: Vec<u8>,
) -> WorkerResult<()> {
    let content_digest = Digest::of(&bytes);
    let size_bytes =
        u64::try_from(bytes.len()).map_err(|_| "runtime component size overflow".to_owned())?;
    artifacts.insert(content_digest.clone(), bytes);
    components.push(ArtifactComponent {
        component_id: component_id.into(),
        component_type: component_id.into(),
        content_digest,
        semantic_digest,
        schema_id,
        schema_version: 1,
        size_bytes,
        required: true,
    });
    Ok(())
}

fn add_component(
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    components: &mut Vec<ArtifactComponent>,
    component_id: &str,
    component_type: &str,
    schema: (u64, u64),
    semantic_digest: Digest,
    bytes: Vec<u8>,
) -> WorkerResult<()> {
    let content_digest = Digest::of(&bytes);
    let size_bytes =
        u64::try_from(bytes.len()).map_err(|_| "runtime component size overflow".to_owned())?;
    artifacts.insert(content_digest.clone(), bytes);
    components.push(ArtifactComponent {
        component_id: component_id.into(),
        component_type: component_type.into(),
        content_digest,
        semantic_digest,
        schema_id: schema.0,
        schema_version: schema.1,
        size_bytes,
        required: true,
    });
    Ok(())
}

fn add_authority_source(
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    components: &mut Vec<ArtifactComponent>,
    signer: &RuntimeWireSigner,
    artifact: (&str, &[u8]),
    signer_id: &str,
    source: Vec<u8>,
    issued_at_ns: u64,
) -> WorkerResult<(AuthoritySourceBinding, Digest)> {
    let (artifact_id, definition) = artifact;
    let binding = AuthoritySourceBinding {
        artifact_id: artifact_id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(definition),
        signer_id: signer_id.into(),
        maximum_source_bytes: 4 * 1024 * 1024,
    };
    let header = AuthorityArtifact {
        artifact_id: artifact_id.into(),
        artifact_version: 1,
        artifact_class: 1,
        source_media_type: binding.source_media_type.clone(),
        source_content_sha256: Digest::of(&source),
        definition_digest: binding.definition_digest.clone(),
        issued_at_ns,
        signer_id: binding.signer_id.clone(),
    };
    let semantic_digest = header
        .semantic_digest()
        .map_err(|_| "authority source digest rejected".to_owned())?;
    let signed = signer
        .sign_authority_artifact(&header)
        .map_err(|_| "authority source signing rejected".to_owned())?;
    artifacts.insert(header.source_content_sha256.clone(), source);
    add_component(
        artifacts,
        components,
        artifact_id,
        "canonical-authority",
        (1010, 1),
        semantic_digest.clone(),
        signed,
    )?;
    Ok((binding, semantic_digest))
}

fn canonical_runtime_capsule(
    work: &ClaimedWork,
    provider_cbor: Vec<u8>,
    profile_cbor: Vec<u8>,
    projection_cbor: Vec<u8>,
    routing: Option<&PublishedRoutingArtifacts>,
    previous: Option<Digest>,
    now_ns: u64,
) -> WorkerResult<CapsuleBuild> {
    let mut artifacts = BTreeMap::new();
    let mut components = Vec::new();
    add_runtime_component(
        &mut artifacts,
        &mut components,
        "openpc.runtime.configuration",
        3101,
        work.configuration_digest.clone(),
        work.configuration_cbor.clone(),
    )?;
    add_runtime_component(
        &mut artifacts,
        &mut components,
        "openpc.runtime.policy",
        3102,
        work.policy()?.artifact_digest.clone(),
        work.policy()?.artifact_cbor.clone(),
    )?;
    add_runtime_component(
        &mut artifacts,
        &mut components,
        "openpc.runtime.provider",
        3103,
        Digest::of(&provider_cbor),
        provider_cbor,
    )?;
    add_runtime_component(
        &mut artifacts,
        &mut components,
        "openpc.runtime.indexer-profile",
        3104,
        Digest::of(&profile_cbor),
        profile_cbor,
    )?;
    add_runtime_component(
        &mut artifacts,
        &mut components,
        "openpc.runtime.projection",
        3105,
        Digest::of(&projection_cbor),
        projection_cbor,
    )?;
    if let Some(routing) = routing {
        for (id, schema, semantic, bytes) in [
            (
                "openpc.runtime.mrpc-profile",
                3106,
                routing.mrpc_runtime_profile_digest.clone(),
                routing.mrpc_runtime_profile.clone(),
            ),
            (
                "openpc.runtime.routing-source",
                3107,
                routing.routing_source_digest.clone(),
                routing.routing_source.clone(),
            ),
            (
                "openpc.runtime.routing-authority",
                3108,
                routing.routing_authority_digest.clone(),
                routing.routing_authority.clone(),
            ),
            (
                "openpc.runtime.certification-source",
                3109,
                routing.certification_source_digest.clone(),
                routing.certification_source.clone(),
            ),
            (
                "openpc.runtime.certification-authority",
                3110,
                routing.certification_authority_digest.clone(),
                routing.certification_authority.clone(),
            ),
        ] {
            add_runtime_component(&mut artifacts, &mut components, id, schema, semantic, bytes)?;
        }
    }
    components.sort_by_key(|component| {
        component
            .canonical_bytes()
            .expect("constructed runtime component is valid")
    });
    let admission: Arc<dyn ArtifactAdmission> = Arc::new(WorkerArtifactAdmission);
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let complete = Digest::of(b"OpenPC R1 runtime complete component set v1");
    let capsule = RuntimeCapsule {
        capsule_id: work
            .generation_id
            .clone()
            .unwrap_or_else(|| work.work_id.clone()),
        lifecycle_mode: if previous.is_some() { 2 } else { 1 },
        target_runtime_id: work
            .target_id
            .clone()
            .ok_or_else(|| "runtime target missing".to_owned())?,
        fleet_id: "openpc-local-runtime-fleet".into(),
        generation: work.journal_sequence.saturating_add(1).max(1),
        previous_capsule_digest: previous,
        contract_set_manifest_digest: stable.clone(),
        schema_registry_digest: stable.clone(),
        cose_purpose_registry_digest: stable.clone(),
        complete_component_set_digest: complete,
        identity_snapshot_manifest_digest: work.configuration_digest.clone(),
        policy_bundle_digest: work.policy()?.artifact_digest.clone(),
        semantic_model_digest: work.policy()?.artifact_digest.clone(),
        named_set_registry_digest: work.configuration_digest.clone(),
        blocklist_digest: work.configuration_digest.clone(),
        policy_fact_state_digest: work.policy()?.fact_generation_digest.clone(),
        routing_snapshot_digest: routing.map_or_else(
            || work.configuration_digest.clone(),
            |value| value.routing_authority_digest.clone(),
        ),
        provider_certification_registry_digest: routing.map_or_else(
            || work.configuration_digest.clone(),
            |value| value.certification_authority_digest.clone(),
        ),
        mrpc_runtime_profile_digest: routing.map_or_else(
            || work.configuration_digest.clone(),
            |value| value.mrpc_runtime_profile_digest.clone(),
        ),
        dynamic_event_profile_digest: stable.clone(),
        rpc_invocation_profile_digest: work.policy()?.artifact_digest.clone(),
        capability_registry_digest: stable.clone(),
        request_form_registry_digest: stable.clone(),
        error_registry_digest: stable.clone(),
        evidence_admission_profile_digest: stable,
        emergency_deny_generation: 0,
        issued_at_ns: now_ns.saturating_sub(1),
        not_before_ns: now_ns,
        hard_expiry_ns: now_ns.saturating_add(300_000_000_000),
        signer_id: "openpc-local-fleet-signer".into(),
        artifact_components: components,
    };
    capsule
        .encode()
        .map_err(|_| "runtime capsule encoding rejected".to_owned())?;
    Ok((capsule, artifacts, admission))
}

fn join_runtime_invocation_configuration(
    contract_bytes: &[u8],
    contract_digest: &Digest,
    resource_bytes: &[u8],
    resource_digest: &Digest,
    settings: Option<&openpc_fleet_controller::cigl_publication::VerifiedCiglSettingsSources>,
    profiles: Option<
        &openpc_fleet_controller::cigl_publication::profile_activation::VerifiedProfileActivation,
    >,
) -> WorkerResult<(Vec<u8>, Digest)> {
    let mut runtime_invocation_configuration =
        decode_active_invocation_configuration(contract_bytes, contract_digest)
            .map_err(|_| "compiled invocation configuration rejected")?;
    let resource_configuration =
        decode_active_invocation_configuration(resource_bytes, resource_digest)
            .map_err(|_| "active resource configuration rejected")?;
    if resource_configuration.resource_artifacts.is_empty() {
        return Err("active runtime resource artifacts unavailable".into());
    }
    // A generic configuration approval cannot attest trusted analysis, action
    // review or the complete current global grant set. The dedicated CIGL
    // publisher must materialize those sources before this join may admit them.
    if resource_configuration
        .resource_artifacts
        .iter()
        .any(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile)
    {
        return Err("governed CIGL publication unavailable".into());
    }
    if resource_configuration
        .resource_artifacts
        .iter()
        .any(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglSettings)
    {
        settings
            .ok_or("governed CIGL settings unavailable")?
            .require_configuration(resource_digest)
            .map_err(|_| "CIGL settings source mismatch")?;
    }
    let has_profiles = runtime_invocation_configuration
        .resource_artifacts
        .iter()
        .any(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile);
    match profiles {
        Some(profiles) => profiles
            .require_profile_artifacts(&runtime_invocation_configuration)
            .map_err(|_| "governed CIGL profile source mismatch")?,
        None if has_profiles => return Err("governed CIGL publication unavailable".into()),
        None => {}
    }
    let mut joined = resource_configuration.resource_artifacts;
    joined.extend(
        runtime_invocation_configuration
            .resource_artifacts
            .into_iter()
            .filter(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile),
    );
    runtime_invocation_configuration.resource_artifacts = joined;
    let runtime_invocation_configuration =
        encode_active_invocation_configuration(&runtime_invocation_configuration)
            .map_err(|_| "runtime invocation configuration join rejected")?;
    let runtime_invocation_configuration_digest = Digest::of(&runtime_invocation_configuration);
    decode_active_invocation_configuration(
        &runtime_invocation_configuration,
        &runtime_invocation_configuration_digest,
    )
    .map_err(|_| "runtime invocation configuration validation rejected")?;
    Ok((
        runtime_invocation_configuration,
        runtime_invocation_configuration_digest,
    ))
}

fn governed_runtime_capsule(
    work: &ClaimedWork,
    config: &Config,
    custody: &GovernedCustodyMaterial<'_>,
    routing: &PublishedRoutingArtifacts,
    previous: Option<Digest>,
    now_ns: u64,
) -> WorkerResult<CapsuleBuild> {
    let target_id = work
        .target_id
        .clone()
        .ok_or_else(|| "runtime target missing".to_owned())?;
    if custody.identity.expires_at_ns <= now_ns.saturating_add(1_000_000_000) {
        return Err("identity publication expires before activation".into());
    }
    let signer = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "runtime authority signer unavailable".to_owned())?;
    let profile_signer = ProfileSigner::from_secret_bytes(config.fleet_key)
        .map_err(|_| "runtime profile signer unavailable".to_owned())?;
    let authority_public_key = signer.verifier().public_key_bytes();
    let mut artifacts = BTreeMap::new();
    let mut components = Vec::new();
    let (runtime_invocation_configuration, runtime_invocation_configuration_digest) =
        join_runtime_invocation_configuration(
            &custody.invocation.configuration_cbor,
            &custody.invocation.configuration_digest,
            &work.configuration_cbor,
            &work.configuration_digest,
            Some(&custody.cigl_settings),
            custody.cigl_profiles,
        )?;

    for bytes in &custody.identity.contents {
        artifacts.insert(Digest::of(bytes), bytes.clone());
    }
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.identity.snapshot",
        "identity-snapshot",
        (3004, 2),
        custody.identity.manifest_digest.clone(),
        custody.identity.manifest_cose.clone(),
    )?;
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.identity.runtime-profile",
        "identity-profile",
        (3010, 2),
        custody.identity.profile_digest.clone(),
        custody.identity.profile_cose.clone(),
    )?;

    let authority_signer_id = config.worker_id.as_str();
    add_authority_source(
        &mut artifacts,
        &mut components,
        &signer,
        (
            "openpc.invocation.configuration",
            b"openpc.invocation.configuration-source.v1",
        ),
        authority_signer_id,
        runtime_invocation_configuration,
        now_ns.saturating_sub(1),
    )?;
    add_authority_source(
        &mut artifacts,
        &mut components,
        &signer,
        (
            "openpc.invocation.policy",
            b"openpc.invocation.policy-source.v1",
        ),
        authority_signer_id,
        custody.invocation.policy_cbor.clone(),
        now_ns.saturating_sub(1),
    )?;

    let fact_state_digest = if let Some(fact) = &custody.fact {
        let (_, digest) = add_authority_source(
            &mut artifacts,
            &mut components,
            &signer,
            (
                "openpc.fact.signed-shard",
                b"openpc.fact.signed-shard-source.v1",
            ),
            authority_signer_id,
            fact.cose_sign1().to_vec(),
            now_ns.saturating_sub(1),
        )?;
        if let Some(content) = fact.local_content() {
            artifacts.insert(Digest::of(content), content.to_vec());
        }
        for checkpoint in fact.checkpoint_proofs() {
            artifacts.insert(Digest::of(checkpoint), checkpoint.clone());
        }
        digest
    } else {
        Digest::of(openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION)
    };

    artifacts.insert(
        routing.routing_source_digest.clone(),
        routing.routing_source.clone(),
    );
    artifacts.insert(
        routing.certification_source_digest.clone(),
        routing.certification_source.clone(),
    );
    add_component(
        &mut artifacts,
        &mut components,
        ROUTING_ARTIFACT_ID,
        "canonical-authority",
        (1010, 1),
        routing.routing_authority_digest.clone(),
        routing.routing_authority.clone(),
    )?;
    add_component(
        &mut artifacts,
        &mut components,
        CERTIFICATION_ARTIFACT_ID,
        "canonical-authority",
        (1010, 1),
        routing.certification_authority_digest.clone(),
        routing.certification_authority.clone(),
    )?;
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.mrpc.runtime-profile",
        "mrpc-runtime-profile",
        (2014, 3),
        routing.mrpc_runtime_profile_digest.clone(),
        routing.mrpc_runtime_profile.clone(),
    )?;
    let trust = GovernedOwnerTrust {
        participant_id: &work.participant_id,
        privacy_domain_id: &work.privacy_domain_id,
        target_runtime_id: &target_id,
        authority_signer_id: &config.worker_id,
        authority_public_key: &authority_public_key,
        identity_runtime_public_key: &config.identity_runtime_public_key,
        identity_profile_digest: custody.identity.profile_digest.clone(),
        fact_verify_key: &config.fact_verify_key,
        fact_verify_key_id: &config.fact_verify_key_id,
        mrpc_runtime_profile: &routing.mrpc_runtime_profile,
    };
    let journal = openpc_fleet_controller::runtime_target::GovernedJournalAdmission::new(&trust);
    let owners = build_governed_runtime_owners(trust, custody.fact.is_some(), observed_admission)?;
    let invocation_profile = &owners.invocation_profile_material;
    let invocation_profile_digest = invocation_profile
        .semantic_digest()
        .map_err(|_| "invocation profile digest rejected".to_owned())?;
    add_component(
        &mut artifacts,
        &mut components,
        "openpc.rpc.invocation-profile",
        "invocation-profile",
        (3121, 2),
        invocation_profile_digest.clone(),
        invocation_profile
            .sign(&profile_signer)
            .map_err(|_| "invocation profile signing rejected".to_owned())?,
    )?;

    components.sort_by_key(|component| {
        component
            .canonical_bytes()
            .expect("constructed runtime component is valid")
    });
    let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
    let capsule = RuntimeCapsule {
        capsule_id: work
            .generation_id
            .clone()
            .unwrap_or_else(|| work.work_id.clone()),
        lifecycle_mode: if previous.is_some() { 2 } else { 1 },
        target_runtime_id: target_id,
        fleet_id: "openpc-local-runtime-fleet".into(),
        generation: work.journal_sequence.saturating_add(1).max(1),
        previous_capsule_digest: previous,
        contract_set_manifest_digest: stable.clone(),
        schema_registry_digest: stable.clone(),
        cose_purpose_registry_digest: stable.clone(),
        complete_component_set_digest: Digest::of(b"OpenPC R1 runtime complete component set v1"),
        identity_snapshot_manifest_digest: custody.identity.manifest_digest.clone(),
        policy_bundle_digest: work.policy()?.generation_digest.clone(),
        semantic_model_digest: custody.invocation.policy_digest.clone(),
        named_set_registry_digest: runtime_invocation_configuration_digest.clone(),
        blocklist_digest: runtime_invocation_configuration_digest,
        policy_fact_state_digest: fact_state_digest,
        routing_snapshot_digest: routing.routing_authority_digest.clone(),
        provider_certification_registry_digest: routing.certification_authority_digest.clone(),
        mrpc_runtime_profile_digest: routing.mrpc_runtime_profile_digest.clone(),
        dynamic_event_profile_digest: stable.clone(),
        rpc_invocation_profile_digest: invocation_profile_digest,
        capability_registry_digest: invocation_profile.capability_registry_digest.clone(),
        request_form_registry_digest: invocation_profile.request_form_registry_digest.clone(),
        error_registry_digest: invocation_profile.error_registry_digest.clone(),
        evidence_admission_profile_digest: stable,
        emergency_deny_generation: 0,
        // Routing and certification are signed at this same control-plane
        // instant. The enclosing capsule must not predate those authorities.
        issued_at_ns: now_ns,
        not_before_ns: now_ns.saturating_add(1),
        hard_expiry_ns: custody.identity.expires_at_ns,
        signer_id: "openpc-local-fleet-signer".into(),
        artifact_components: components,
    };
    capsule
        .encode()
        .map_err(|_| "governed runtime capsule encoding rejected".to_owned())?;
    Ok((
        capsule,
        artifacts,
        Arc::new(GovernedOrBootstrapAdmission {
            governed: observed_admission("journal", Arc::new(journal)),
        }),
    ))
}

fn read_key(path: &str) -> WorkerResult<[u8; 32]> {
    let encoded = read_secret(path)?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("signing secret must contain 32 hex-encoded bytes".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| "signing secret is not hexadecimal".to_owned())?;
    }
    Ok(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_bytes(value: &str) -> WorkerResult<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > 2 * 1024 * 1024
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid canonical receipt encoding".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid canonical receipt encoding".to_owned())
        })
        .collect()
}

impl Config {
    fn read() -> WorkerResult<Self> {
        if required("OPENPC_LOCAL_RUNTIME")? != "1" {
            return Err("local runtime gate is closed".into());
        }
        let config = Self {
            host: required("CONTROL_WORKER_DATABASE_HOST")?,
            port: required("CONTROL_WORKER_DATABASE_PORT")?
                .parse()
                .map_err(|_| "invalid database port".to_owned())?,
            database: required("CONTROL_WORKER_DATABASE_NAME")?,
            user: required("CONTROL_WORKER_DATABASE_USER")?,
            password: read_secret(&required("CONTROL_WORKER_DATABASE_PASSWORD_FILE")?)?,
            participant_id: required("CONTROL_WORKER_PARTICIPANT_ID")?,
            privacy_domain_id: required("CONTROL_WORKER_PRIVACY_DOMAIN_ID")?,
            worker_id: required("CONTROL_WORKER_ID")?,
            artifact_capacity_bytes: required("CONTROL_WORKER_ARTIFACT_CAPACITY_BYTES")?
                .parse()
                .map_err(|_| "invalid artifact capacity".to_owned())?,
            fleet_key: read_key(&required("CONTROL_WORKER_FLEET_SIGNING_SECRET_FILE")?)?,
            agent_key: read_key(&required("CONTROL_WORKER_AGENT_SIGNING_SECRET_FILE")?)?,
            identity_runtime_public_key: fs::read(required(
                "CONTROL_WORKER_IDENTITY_RUNTIME_PUBLIC_KEY_FILE",
            )?)
            .map_err(|_| "identity runtime verification key unavailable".to_owned())?,
            fact_host: required("CONTROL_WORKER_FACT_DATABASE_HOST")?,
            fact_port: required("CONTROL_WORKER_FACT_DATABASE_PORT")?
                .parse()
                .map_err(|_| "invalid fact database port".to_owned())?,
            fact_database: required("CONTROL_WORKER_FACT_DATABASE_NAME")?,
            fact_user: required("CONTROL_WORKER_FACT_DATABASE_USER")?,
            fact_password: read_secret(&required("CONTROL_WORKER_FACT_DATABASE_PASSWORD_FILE")?)?,
            fact_verify_key: fs::read(required("CONTROL_WORKER_FACT_VERIFY_KEY_FILE")?)
                .map_err(|_| "fact verification key unavailable".to_owned())?,
            fact_verify_key_id: required("CONTROL_WORKER_FACT_VERIFY_KEY_ID")?,
        };
        if config.participant_id.is_empty()
            || config.privacy_domain_id.is_empty()
            || config.worker_id.is_empty()
            || !config.worker_id.bytes().all(|byte| byte.is_ascii_graphic())
            || config.artifact_capacity_bytes == 0
        {
            return Err("invalid worker scope".into());
        }
        Ok(config)
    }

    async fn connect(&self) -> WorkerResult<PgPool> {
        let options = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.user)
            .password(&self.password);
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|_| "control database unavailable".into())
    }

    async fn connect_facts(&self) -> WorkerResult<PgPool> {
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::new()
                    .host(&self.fact_host)
                    .port(self.fact_port)
                    .database(&self.fact_database)
                    .username(&self.fact_user)
                    .password(&self.fact_password),
            )
            .await
            .map_err(|_| "fact database unavailable".into())
    }
}

impl RuntimePlaneConfig {
    fn read() -> WorkerResult<Self> {
        let protected_port = required("CONTROL_WORKER_PROTECTED_PORT")?
            .parse()
            .map_err(|_| "invalid protected listener port".to_owned())?;
        if protected_port == 0 {
            return Err("invalid protected listener port".into());
        }
        Ok(Self {
            listen: required("CONTROL_WORKER_ADS_LISTEN")?,
            server_certificate: required("CONTROL_WORKER_ADS_SERVER_CERT_FILE")?.into(),
            server_key: required("CONTROL_WORKER_ADS_SERVER_KEY_FILE")?.into(),
            client_ca: required("CONTROL_WORKER_ADS_CLIENT_CA_FILE")?.into(),
            target_client_certificate: required("CONTROL_WORKER_TARGET_CLIENT_CERT_FILE")?.into(),
            protected_bind: required("CONTROL_WORKER_PROTECTED_BIND")?,
            protected_port,
            pds_socket: required("CONTROL_WORKER_PDS_SOCKET")?,
            broker_socket: required("CONTROL_WORKER_BROKER_SOCKET")?,
            protected_certificate: required("CONTROL_WORKER_PROTECTED_CERT_FILE")?,
            protected_key: required("CONTROL_WORKER_PROTECTED_KEY_FILE")?,
            workload_ca: required("CONTROL_WORKER_WORKLOAD_CA_FILE")?,
        })
    }
}

impl RuntimePlane {
    async fn start(
        worker: &Config,
        pool: &PgPool,
        facts: disposition_restore::FactCustody,
        source_custody: openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
    ) -> WorkerResult<Self> {
        let config = RuntimePlaneConfig::read()?;
        let receipt_public =
            PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, worker.agent_key)
                .map_err(|_| "agent signer unavailable".to_owned())?
                .verifier()
                .sec1_bytes();
        let canonical_agent_public = RuntimeWireSigner::from_secret_bytes(worker.agent_key)
            .map_err(|_| "canonical agent signer unavailable".to_owned())?
            .verifier()
            .public_key_bytes();
        let fleet = Arc::new(
            FleetController::new(worker.fleet_key, &receipt_public, 30_000)
                .map_err(|_| "fleet controller initialization rejected".to_owned())?
                .with_canonical_signing(worker.fleet_key, &canonical_agent_public)
                .map_err(|_| "canonical Fleet trust rejected".to_owned())?,
        );
        match fs::read(&config.target_client_certificate) {
            Ok(pem) => {
                let identity = runtime_tls::target_identity_from_pem(&pem)
                    .map_err(|_| "persisted target ADS identity rejected".to_owned())?;
                fleet
                    .register_target(identity.clone(), &identity)
                    .map_err(|_| "persisted runtime target identity rejected".to_owned())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("target ADS certificate unavailable".into()),
        }
        let disposition = match std::env::var("CONTROL_WORKER_TARGET_DISPOSITION_KEY_FILE") {
            Ok(path) => Some(Arc::new(openpc_fleet_controller::target_disposition::TargetDispositionStore::from_host_installation(
                pool.clone(),worker.participant_id.clone(),worker.privacy_domain_id.clone(),
                worker.fleet_key,read_key(&path)?,BTreeMap::new())?.with_source_custody(source_custody.clone())
                .with_identity_runtime_trust(&worker.identity_runtime_public_key)?)),
            // Legacy non-serving harnesses need no new authority. With no
            // installed owner the RPC is absent; target reconciliation denies.
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("target disposition installation unavailable".into()),
        };
        let mut ads = AdsService::new(Arc::clone(&fleet)).with_discovery(Arc::new(
            discovery::DiscoveryOwner {
                pool: pool.clone(),
                config: worker.clone(),
            },
        ));
        if let Some(store) = &disposition {
            if let Ok(pem) = fs::read(&config.target_client_certificate) {
                let identity = runtime_tls::target_identity_from_pem(&pem)
                    .map_err(|_| "target disposition identity unavailable")?;
                store.register_host_target_key(&identity.target_id, &receipt_public)?;
                store.register_host_runtime_target_key(
                    &identity.target_id,
                    &canonical_agent_public,
                )?;
            }
            ads = ads.with_target_disposition(Arc::clone(store));
        }
        let listener = tokio::net::TcpListener::bind(&config.listen)
            .await
            .map_err(|_| "ADS listener unavailable".to_owned())?;
        let tls = runtime_tls::server_config(
            &fs::read(&config.server_certificate)
                .map_err(|_| "ADS server certificate unavailable".to_owned())?,
            &fs::read(&config.server_key).map_err(|_| "ADS server key unavailable".to_owned())?,
            &fs::read(&config.client_ca).map_err(|_| "ADS client trust unavailable".to_owned())?,
        )
        .map_err(|_| "ADS TLS configuration rejected".to_owned())?;
        let service = ads.clone();
        let server = tokio::spawn(serve_ads(service, listener, tls, std::future::pending()));
        Ok(Self {
            fleet,
            ads,
            config,
            server,
            disposition,
            facts,
            agent_public_key: receipt_public,
            runtime_agent_public_key: canonical_agent_public,
            source_custody,
        })
    }

    fn target_identity(&self, target_id: &str) -> WorkerResult<TargetIdentity> {
        let pem = fs::read(&self.config.target_client_certificate)
            .map_err(|_| "target ADS certificate unavailable".to_owned())?;
        let identity = runtime_tls::target_identity_from_pem(&pem)
            .map_err(|_| "target ADS certificate invalid".to_owned())?;
        if identity.target_id != target_id {
            return Err("target ADS identity mismatch".into());
        }
        Ok(identity)
    }

    fn register_target(&self, target_id: &str) -> WorkerResult<TargetIdentity> {
        let identity = self.target_identity(target_id)?;
        self.fleet
            .register_target(identity.clone(), &identity)
            .map_err(|_| "runtime target identity rejected".to_owned())?;
        if let Some(store) = &self.disposition {
            store.register_host_target_key(target_id, &self.agent_public_key)?;
            store.register_host_runtime_target_key(target_id, &self.runtime_agent_public_key)?;
        }
        Ok(identity)
    }

    async fn wait_for_ack(&self, target_id: &str) -> WorkerResult<()> {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match self.fleet.state(target_id) {
                    Ok(TargetState::XdsAckedNotActive) => return Ok(()),
                    Ok(TargetState::Nacked) => return Err("xDS version NACKed".to_owned()),
                    Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                    Err(_) => return Err("Fleet target state unavailable".to_owned()),
                }
            }
        })
        .await
        .map_err(|_| "xDS ACK barrier timed out".to_owned())?
    }
}

fn parse_digest(value: String) -> WorkerResult<Digest> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| "invalid stored digest".to_owned())?;
    Digest::parse(hex).map_err(|_| "invalid stored digest".into())
}

fn optional_digest(value: Option<String>) -> WorkerResult<Option<Digest>> {
    value.map(parse_digest).transpose()
}

fn optional_fixture_identifier(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
}

async fn set_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &Config,
) -> WorkerResult<()> {
    sqlx::query(
        "select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),$3,true),openpc.assert_request_context(true)",
    )
    .bind(&config.participant_id)
    .bind(&config.privacy_domain_id)
    .bind("ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1")
    .execute(&mut **transaction)
    .await
    .map_err(|_| "request context rejected".to_owned())?;
    Ok(())
}

fn digest_from_database(bytes: &[u8], owner: &str) -> WorkerResult<Digest> {
    if bytes.len() != 32 {
        return Err(format!("{owner} digest invalid"));
    }
    Digest::parse(hex_bytes(bytes)).map_err(|_| format!("{owner} digest invalid"))
}

async fn load_cigl_settings(
    pool: &PgPool,
    config: &Config,
    work: &ClaimedWork,
) -> WorkerResult<openpc_fleet_controller::cigl_publication::VerifiedCiglSettingsSources> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "CIGL settings transaction unavailable")?;
    set_context(&mut transaction, config).await?;
    let sources = openpc_fleet_controller::cigl_publication::verify_settings_sources(
        &mut transaction,
        &work.participant_id,
        &work.privacy_domain_id,
        &work.configuration_cbor,
        &work.configuration_digest,
    )
    .await
    .map_err(|_| "CIGL settings provenance rejected")?;
    transaction
        .commit()
        .await
        .map_err(|_| "CIGL settings transaction failed")?;
    Ok(sources)
}

async fn load_identity_publication(
    pool: &PgPool,
    config: &Config,
    target_id: &str,
    now_ns: u64,
) -> WorkerResult<IdentityPublication> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "identity publication transaction unavailable".to_owned())?;
    set_context(&mut transaction, config).await?;
    let row = sqlx::query(
        r#"select s.snapshot_id::text,s.manifest_digest,s.manifest_cose,
                  s.profile_digest,s.profile_cose,s.expires_at_ns::text
             from control.identity_runtime_snapshot_head h
             join control.identity_runtime_snapshot s
               on s.snapshot_id=h.snapshot_id and s.participant_id=h.participant_id
              and s.privacy_domain_id=h.privacy_domain_id
              and s.target_runtime_id=h.target_runtime_id
            where h.participant_id=$1::text::uuid
              and h.privacy_domain_id=$2::text::uuid
              and h.target_runtime_id=$3::text::uuid
              and s.expires_at_ns>$4::numeric+30000000000"#,
    )
    .bind(&config.participant_id)
    .bind(&config.privacy_domain_id)
    .bind(target_id)
    .bind(now_ns.to_string())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| match error {
        sqlx::Error::RowNotFound => "current identity runtime publication absent".to_owned(),
        sqlx::Error::Database(_) => "identity runtime publication query rejected".to_owned(),
        _ => "identity runtime publication read unavailable".to_owned(),
    })?;
    let snapshot_id: String = row
        .try_get("snapshot_id")
        .map_err(|_| "identity publication invalid".to_owned())?;
    let contents: Vec<Vec<u8>> = sqlx::query_scalar(
        r#"select payload from control.identity_runtime_snapshot_content
            where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid
              and snapshot_id=$3::text::uuid
            order by case content_kind when 'SHARD' then 0 when 'ROLE_ASSIGNMENTS' then 1 else 2 end,
                     ordinal,content_digest"#,
    )
    .bind(&config.participant_id)
    .bind(&config.privacy_domain_id)
    .bind(&snapshot_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| "identity publication content unavailable".to_owned())?;
    if contents.is_empty() {
        return Err("identity publication content empty".into());
    }
    let expires_at_ns: String = row
        .try_get("expires_at_ns")
        .map_err(|_| "identity publication validity invalid".to_owned())?;
    let publication = IdentityPublication {
        manifest_digest: digest_from_database(
            &row.try_get::<Vec<u8>, _>("manifest_digest")
                .map_err(|_| "identity manifest digest invalid".to_owned())?,
            "identity manifest",
        )?,
        manifest_cose: row
            .try_get("manifest_cose")
            .map_err(|_| "identity manifest unavailable".to_owned())?,
        profile_digest: digest_from_database(
            &row.try_get::<Vec<u8>, _>("profile_digest")
                .map_err(|_| "identity profile digest invalid".to_owned())?,
            "identity profile",
        )?,
        profile_cose: row
            .try_get("profile_cose")
            .map_err(|_| "identity profile unavailable".to_owned())?,
        contents,
        expires_at_ns: expires_at_ns
            .parse()
            .map_err(|_| "identity publication validity invalid".to_owned())?,
    };
    transaction
        .commit()
        .await
        .map_err(|_| "identity publication commit failed".to_owned())?;
    Ok(publication)
}

async fn load_fact_publication(
    control: &PgPool,
    config: &Config,
    required: &[pc_policy_core::semantics::FactReference],
) -> WorkerResult<VerifiedShard> {
    pc_policy_core::semantics::validate_fact_references(required)?;
    openpc_fleet_controller::fact_admission::require_admitted(
        control,
        &config.participant_id,
        &config.privacy_domain_id,
        required,
    )
    .await?;
    let pool = config.connect_facts().await?;
    let verifier = FactSignatureVerifier::from_key_identifier(
        &config.fact_verify_key_id,
        &config.fact_verify_key,
    )
    .map_err(|_| "fact verification trust rejected".to_owned())?;
    let reader = PolicyFactReader::new(pool.clone(), verifier);
    let candidates = required
        .iter()
        .map(|reference| reference.candidate_id.clone())
        .collect::<Vec<_>>();
    let (publication, snapshots) = reader
        .publication(
            &config.participant_id,
            &config.privacy_domain_id,
            &candidates,
        )
        .await
        .map_err(|_| "fact publication read rejected".to_owned())?
        .ok_or_else(|| "fact publication unavailable".to_owned())?;
    pool.close().await;
    for (reference, snapshot) in required.iter().zip(&snapshots) {
        if reference.candidate_id != snapshot.candidate_id
            || reference.generation_id != snapshot.generation_id
            || reference.parsed_digest()?
                != digest_from_database(&snapshot.fact_digest, "fact record")?
        {
            return Err("fact publication does not close policy references".into());
        }
    }
    Ok(publication)
}

async fn claim(pool: &PgPool, config: &Config) -> WorkerResult<Option<ClaimedWork>> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "claim begin failed".to_owned())?;
    set_context(&mut transaction, config).await?;
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||$1||':'||$2,0))")
        .bind(&config.participant_id).bind(&config.privacy_domain_id)
        .execute(&mut *transaction).await.map_err(|_| "claim generation fence unavailable")?;
    let row = sqlx::query(
        r#"with admitted as materialized (
             -- Materialize admission before locking any reference/work row.
             -- CASE preserves original started-result lookup without calling
             -- new-use/current-view gates, even after retirement.
             select w.configuration_work_id,w.configuration_digest,w.execution_started_at is not null as started
               from control.configuration_work w
              where w.participant_id=$1::text::uuid and w.privacy_domain_id=$2::text::uuid
                and w.work_kind<>'CIGL_PROFILE_COMPILATION'
                and (w.state='PENDING'
                  or (w.state='LEASED' and w.lease_until<clock_timestamp())
                  or (w.state='RECONCILING' and w.reconcile_after<=clock_timestamp()))
                and case when w.execution_started_at is not null then true else
                  openpc.runtime_artifact_new_use_allowed(w.participant_id,w.privacy_domain_id,
                    decode(substring(w.configuration_digest from 8),'hex')) is true end
              order by (w.state='RECONCILING'),w.created_at,w.configuration_work_id limit 1
           ), candidate as (
             select w.*
               from control.configuration_work w join admitted a
                 on a.configuration_work_id=w.configuration_work_id
                and a.configuration_digest=w.configuration_digest
                and (not a.started or w.execution_started_at is not null)
              where w.participant_id=$1::text::uuid and w.privacy_domain_id=$2::text::uuid
                and (w.state='PENDING'
                  or (w.state='LEASED' and w.lease_until<clock_timestamp())
                  or (w.state='RECONCILING' and w.reconcile_after<=clock_timestamp()))
              for update of w skip locked limit 1
           )
           update control.configuration_work w
              set state='LEASED',attempt_count=w.attempt_count+1,lease_owner=$3,
                  lease_until=clock_timestamp()+interval '30 seconds',last_error_code=null,
                  updated_at=clock_timestamp()
             from candidate c
             left join control.policy_generation policy on policy.participant_id=c.participant_id
               and policy.privacy_domain_id=c.privacy_domain_id
               and 'sha256:'||encode(policy.generation_digest,'hex')=c.policy_generation_digest
             left join control.policy_version policy_version on policy_version.policy_version_id=policy.policy_version_id
               and policy_version.participant_id=policy.participant_id and policy_version.privacy_domain_id=policy.privacy_domain_id
             left join control.policy_artifact policy_artifact on policy_artifact.participant_id=policy.participant_id
               and policy_artifact.privacy_domain_id=policy.privacy_domain_id
               and policy_artifact.semantic_digest=policy_version.semantic_digest and policy_artifact.payload_digest=policy.artifact_digest,
               control.runtime_configuration_input configuration,control.module_installation installation,
               control.module_version version,control.module_registration module
            where w.configuration_work_id=c.configuration_work_id
              and installation.participant_id=w.participant_id
              and installation.privacy_domain_id=w.privacy_domain_id and installation.state='ENABLED'
              and version.module_version_id=installation.module_version_id
              and module.module_id=version.module_id and module.module_id='pc.config.assets'
              and configuration.module_installation_id=installation.module_installation_id
              and configuration.participant_id=w.participant_id and configuration.privacy_domain_id=w.privacy_domain_id
              and w.configuration_digest='sha256:'||encode(configuration.configuration_digest,'hex')
              and case when w.execution_started_at is not null then true else exists (
                select 1 from control.runtime_configuration_input_current_metadata current_configuration
                 where current_configuration.runtime_configuration_input_id=
                   configuration.runtime_configuration_input_id) end
              and case when w.execution_started_at is not null then true else 1=(select count(*) from control.module_installation exact_installation
                join control.module_version exact_version
                  on exact_version.module_version_id=exact_installation.module_version_id
                join control.module_registration exact_module
                  on exact_module.module_id=exact_version.module_id
                 and exact_module.module_id='pc.config.assets'
                join control.runtime_configuration_input_current_metadata exact_configuration
                  on exact_configuration.module_installation_id=exact_installation.module_installation_id
                 and exact_configuration.active=true
               where exact_installation.participant_id=w.participant_id
                 and exact_installation.privacy_domain_id=w.privacy_domain_id
                 and exact_installation.state='ENABLED'
                 and 'sha256:'||encode(exact_configuration.configuration_digest,'hex')=
                   w.configuration_digest) end
              and ((w.policy_generation_digest is null
                and w.work_kind in ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION')
                and not exists(select 1 from control.policy_generation history
                  where history.participant_id=w.participant_id and history.privacy_domain_id=w.privacy_domain_id))
                or (policy.participant_id=w.participant_id
              and policy.privacy_domain_id=w.privacy_domain_id
              and (policy.active=true or
                (w.work_kind='PROVIDER_QUALIFICATION' and policy.state='PREPARED'
                 and not policy.active and exists (
                   select 1 from control.policy_release_bundle release
                    where release.participant_id=policy.participant_id
                      and release.privacy_domain_id=policy.privacy_domain_id
                      and release.policy_version_id=policy.policy_version_id
                      and release.approval_request_id=policy.approval_request_id
                      and release.manifest_digest=policy.generation_digest
                      and release.state in ('PUBLISHED','STAGED')))
               or exists (
                select 1 from control.policy_activation_occurrence_target occurrence_target
                join control.policy_activation_occurrence occurrence
                  on occurrence.participant_id=occurrence_target.participant_id
                 and occurrence.privacy_domain_id=occurrence_target.privacy_domain_id
                 and occurrence.activation_occurrence_id=occurrence_target.activation_occurrence_id
                join control.policy_activation activation
                  on activation.participant_id=occurrence.participant_id
                 and activation.privacy_domain_id=occurrence.privacy_domain_id
                 and activation.policy_activation_id=occurrence.activation_occurrence_id
               where occurrence_target.participant_id=w.participant_id
                 and occurrence_target.privacy_domain_id=w.privacy_domain_id
                 and occurrence_target.configuration_work_id=w.configuration_work_id
                 and ((occurrence_target.phase='FORWARD'
                       and occurrence.policy_generation_id=policy.policy_generation_id
                       and policy.state='PREPARED')
                      or (occurrence_target.phase='ROLLBACK'
                          and activation.state='ACTIVE'
                          and activation.prior_generation_digest=policy.generation_digest
                          and policy.state='RETIRED'))))
              and 'sha256:'||encode(policy.generation_digest,'hex')=w.policy_generation_digest
              and policy_version.policy_version_id=policy.policy_version_id
              and policy_version.participant_id=policy.participant_id
              and policy_version.privacy_domain_id=policy.privacy_domain_id
              and policy_artifact.participant_id=policy.participant_id
              and policy_artifact.privacy_domain_id=policy.privacy_domain_id
              and policy_artifact.semantic_digest=policy_version.semantic_digest
              and policy_artifact.payload_digest=policy.artifact_digest))
           returning w.configuration_work_id::text,w.operation_id::text,w.work_kind,
             w.resource_id::text,w.input_digest,w.participant_id::text,w.privacy_domain_id::text,
             configuration.runtime_configuration_input_id::text input_id,
             'sha256:'||encode(configuration.configuration_digest,'hex') configuration_digest,
             policy_version.semantic_cbor as policy_artifact_cbor,
             'sha256:'||encode(policy_artifact.semantic_digest,'hex') policy_artifact_digest,
             'sha256:'||encode(policy.fact_generation_digest,'hex') fact_generation_digest,
             (select prior.result_receipt || jsonb_build_object(
                 'qualificationOperationId',prior.operation_id::text,
                 'qualificationRevision',indexer.revision::text)
               from control.configuration_work prior
               join control.projection_plan plan on plan.projection_plan_id=w.resource_id
               join control.indexer_profile indexer on indexer.indexer_profile_id=plan.indexer_profile_id
                 and indexer.participant_id=w.participant_id and indexer.privacy_domain_id=w.privacy_domain_id
                 and indexer.state in ('QUALIFIED','ACTIVE')
              where w.work_kind='PROJECTION_VALIDATION'
                and prior.resource_id=plan.indexer_profile_id and prior.work_kind='INDEXER_ADMISSION'
                and prior.participant_id=w.participant_id and prior.privacy_domain_id=w.privacy_domain_id
                and prior.input_digest=indexer.method_profile_digest
                and exists (select 1 from control.idempotency_record result
                  where result.participant_id=prior.participant_id and result.operation_id=prior.operation_id
                    and result.terminal_state='COMMITTED' and result.result_payload->>'state'='SUCCEEDED'
                    and result.result_aggregate_version=indexer.revision)
                and prior.state='COMPLETED' order by prior.completed_at desc limit 1) related_profile_receipt,
             (select prior.result_receipt from control.configuration_work prior
               join control.runtime_configuration_generation generation
                 on generation.runtime_configuration_generation_id=w.runtime_configuration_generation_id
              where w.work_kind='RUNTIME_ACTIVATION'
                and prior.resource_id=generation.provider_profile_id
                and prior.work_kind='PROVIDER_QUALIFICATION' and prior.state='COMPLETED'
              order by prior.completed_at desc limit 1) provider_receipt,
             (select prior.result_receipt from control.configuration_work prior
               join control.runtime_configuration_generation generation
                 on generation.runtime_configuration_generation_id=w.runtime_configuration_generation_id
              where w.work_kind='RUNTIME_ACTIVATION'
                and prior.resource_id=generation.projection_plan_id
                and prior.work_kind='PROJECTION_VALIDATION' and prior.state='COMPLETED'
              order by prior.completed_at desc limit 1) projection_receipt,
             coalesce((select jsonb_agg(jsonb_build_object(
               'generationMatches',(
                 method.policy_generation_digest=w.policy_generation_digest
                 and binding.policy_generation_digest=w.policy_generation_digest
                 and artifact.policy_generation_digest=w.policy_generation_digest
                 and (method.argument_rule_version_id is null or exists(
                   select 1 from control.typed_argument_rule_version version
                   where version.argument_rule_version_id=method.argument_rule_version_id
                     and version.policy_generation_digest=w.policy_generation_digest))),
               'assetId',method.contract_method_policy_id::text,
               'runtimeBindingId',binding.runtime_binding_id::text,
               'transactionPolicy',binding.transaction_policy,
               'policyVersion',method.revision::text,
               'tenantId',method.participant_id::text,
               'privacyDomainId',method.privacy_domain_id::text,
               'chainId',binding.chain_id,'networkId',binding.network_id,
               'genesisDigest',binding.genesis_digest,
               'contractAddress',binding.contract_address,'proxyAddress',binding.proxy_address,
               'implementationAddress',binding.implementation_address,
               'codeDigest',binding.code_digest,
               'implementationCodeDigest',binding.implementation_code_digest,
               'abiDigest',artifact.abi_digest,'canonicalSignature',method.canonical_signature,
               'selector',method.selector,'canonicalAbi',artifact.canonical_abi,
               'effect',method.effect,'requiredRoles',method.required_roles,
               'approvalRequirement',method.approval_requirement,
               'mfaRequirement',method.mfa_requirement,
               'rpcMethodPolicyDigest',method.rpc_method_policy_digest,
               'nestedCallSetDigest',method.nested_call_set_digest,
               'namedSetCount',(select count(*) from control.argument_rule_named_set_binding named
                 where named.argument_rule_version_id=method.argument_rule_version_id),
               'rules',coalesce((select jsonb_agg(jsonb_build_object(
                 'parameterPath',rule.parameter_path,'operandType',rule.operand_type,
                 'operator',rule.operator,'values',rule.scalar_values) order by rule.ordinal::integer)
                 from control.typed_argument_rule rule
                 where rule.argument_rule_version_id=method.argument_rule_version_id),'[]'::jsonb)
             ) order by method.contract_method_policy_id)
               from control.contract_method_policy method
               join control.contract_runtime_binding binding
                 on binding.participant_id=method.participant_id
                and binding.privacy_domain_id=method.privacy_domain_id
                and binding.runtime_binding_id=method.runtime_binding_id
                and binding.abi_artifact_id=method.abi_artifact_id
                and binding.state='BOUND'
               join control.abi_artifact artifact
                 on artifact.participant_id=binding.participant_id
                and artifact.privacy_domain_id=binding.privacy_domain_id
                and artifact.abi_artifact_id=binding.abi_artifact_id
              where w.work_kind='RUNTIME_ACTIVATION'
                and method.participant_id=w.participant_id
                and method.privacy_domain_id=w.privacy_domain_id
                and method.state='ACTIVE' and 'LOCAL'=any(method.environments)
                and (method.argument_rule_version_id is null or exists(
                  select 1 from control.typed_argument_rule_version version
                   where version.argument_rule_version_id=method.argument_rule_version_id
                     and version.participant_id=method.participant_id
                     and version.privacy_domain_id=method.privacy_domain_id
                     and version.runtime_binding_id=method.runtime_binding_id
                     and version.abi_artifact_id=method.abi_artifact_id
                     and version.canonical_signature=method.canonical_signature
                     and version.state='ACTIVE'))),'[]'::jsonb) contract_policy_assets,
             w.runtime_configuration_generation_id::text,w.runtime_target_id::text,
             w.generation_digest,w.predecessor_digest,w.policy_generation_digest,
             w.xds_version_digest,w.attempt_count::bigint as attempt_count,
             w.execution_attempt_id::text,
             (w.execution_started_at is not null) as reconcile_only,
             (select target.activation_occurrence_id::text
                from control.policy_activation_occurrence_target target
               where target.configuration_work_id=w.configuration_work_id) occurrence_id,
             (select target.active_generation_digest from control.runtime_target target
               where target.runtime_target_id=w.runtime_target_id) active_generation_digest,
             (select target.xds_version_digest from control.runtime_target target
               where target.runtime_target_id=w.runtime_target_id) active_xds_version_digest,
             case when w.denied_predecessor_work_id is not null then
              (select c.capsule_generation from control.runtime_denied_predecessor c
               where c.configuration_work_id=w.denied_predecessor_work_id and c.participant_id=w.participant_id
                and c.privacy_domain_id=w.privacy_domain_id and c.runtime_target_id=w.runtime_target_id
                and c.capsule_digest=w.predecessor_digest)
             else coalesce((select max((prior.result_receipt->>'capsuleGeneration')::bigint)
               from control.configuration_work prior
               where prior.runtime_target_id=w.runtime_target_id and prior.state='COMPLETED'),0) end
               as journal_sequence"#,
    )
    .bind(&config.participant_id)
    .bind(&config.privacy_domain_id)
    .bind(&config.worker_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(runtime_artifact_database_error);
    let row = match row {
        Ok(row) => row,
        Err(error) if error == RUNTIME_ARTIFACT_BUSY => return Ok(None),
        Err(error) => return Err(error),
    };
    let configuration_cbor = if let Some(row) = &row {
        let input_id: String = row
            .try_get("input_id")
            .map_err(|_| "claim input identity rejected")?;
        openpc_indexer_adapter::control_materialization::authorize_input(
            &mut transaction,
            &input_id,
        )
        .await?;
        sqlx::query_scalar("select openpc.runtime_artifact_input_payload($1::text::uuid)")
            .bind(&input_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "claim source materialization unavailable")?
    } else {
        Vec::new()
    };
    transaction
        .commit()
        .await
        .map_err(|_| "claim commit failed".to_owned())?;
    let Some(row) = row else { return Ok(None) };
    let journal_sequence: i64 = row
        .try_get("journal_sequence")
        .map_err(|_| "invalid journal sequence".to_owned())?;
    Ok(Some(ClaimedWork {
        work_id: row
            .try_get("configuration_work_id")
            .map_err(|_| "invalid work id".to_owned())?,
        occurrence_id: row
            .try_get("occurrence_id")
            .map_err(|_| "invalid occurrence id".to_owned())?,
        operation_id: row
            .try_get("operation_id")
            .map_err(|_| "invalid operation id".to_owned())?,
        work_kind: row
            .try_get("work_kind")
            .map_err(|_| "invalid work kind".to_owned())?,
        resource_id: row
            .try_get("resource_id")
            .map_err(|_| "invalid resource id".to_owned())?,
        input_digest: row
            .try_get("input_digest")
            .map_err(|_| "invalid input digest".to_owned())?,
        participant_id: row
            .try_get("participant_id")
            .map_err(|_| "invalid participant".to_owned())?,
        privacy_domain_id: row
            .try_get("privacy_domain_id")
            .map_err(|_| "invalid privacy domain".to_owned())?,
        configuration_cbor,
        configuration_digest: parse_digest(
            row.try_get("configuration_digest")
                .map_err(|_| "invalid configuration digest".to_owned())?,
        )?,
        policy: match (
            row.try_get::<Option<Vec<u8>>, _>("policy_artifact_cbor"),
            row.try_get::<Option<String>, _>("policy_artifact_digest"),
            row.try_get::<Option<String>, _>("fact_generation_digest"),
            row.try_get::<Option<String>, _>("policy_generation_digest"),
        ) {
            (
                Ok(Some(artifact_cbor)),
                Ok(Some(artifact)),
                Ok(Some(facts)),
                Ok(Some(generation)),
            ) => Some(ClaimedPolicy {
                artifact_cbor,
                artifact_digest: parse_digest(artifact)?,
                fact_generation_digest: parse_digest(facts)?,
                generation_digest: parse_digest(generation)?,
            }),
            (Ok(None), Ok(None), Ok(None), Ok(None))
                if matches!(
                    row.try_get::<&str, _>("work_kind")
                        .map_err(|_| "invalid work kind")?,
                    "PROVIDER_QUALIFICATION" | "INDEXER_ADMISSION" | "PROJECTION_VALIDATION"
                ) =>
            {
                None
            }
            _ => return Err("incomplete claimed policy provenance".into()),
        },
        related_profile_receipt: row
            .try_get("related_profile_receipt")
            .map_err(|_| "invalid related profile receipt".to_owned())?,
        provider_receipt: row
            .try_get("provider_receipt")
            .map_err(|_| "invalid provider receipt".to_owned())?,
        projection_receipt: row
            .try_get("projection_receipt")
            .map_err(|_| "invalid projection receipt".to_owned())?,
        contract_policy_assets: decode_claimed_contract_assets(
            row.try_get("contract_policy_assets")
                .map_err(|_| "invalid contract policy assets".to_owned())?,
            &row.try_get::<Option<Vec<u8>>, _>("policy_artifact_cbor")
                .map_err(|_| "invalid policy artifact".to_owned())?
                .unwrap_or_default(),
        )?,
        generation_id: row
            .try_get("runtime_configuration_generation_id")
            .map_err(|_| "invalid generation id".to_owned())?,
        target_id: row
            .try_get("runtime_target_id")
            .map_err(|_| "invalid target id".to_owned())?,
        generation_digest: optional_digest(
            row.try_get("generation_digest")
                .map_err(|_| "invalid generation digest".to_owned())?,
        )?,
        predecessor_digest: optional_digest(
            row.try_get("predecessor_digest")
                .map_err(|_| "invalid predecessor digest".to_owned())?,
        )?,
        xds_version_digest: optional_digest(
            row.try_get("xds_version_digest")
                .map_err(|_| "invalid xds digest".to_owned())?,
        )?,
        active_generation_digest: optional_digest(
            row.try_get("active_generation_digest")
                .map_err(|_| "invalid active digest".to_owned())?,
        )?,
        active_xds_version_digest: optional_digest(
            row.try_get("active_xds_version_digest")
                .map_err(|_| "invalid active xds digest".to_owned())?,
        )?,
        journal_sequence: u64::try_from(journal_sequence)
            .map_err(|_| "invalid journal sequence".to_owned())?,
        attempt_count: row
            .try_get("attempt_count")
            .map_err(|_| "invalid attempt count".to_owned())?,
        execution_attempt_id: row
            .try_get("execution_attempt_id")
            .map_err(|_| "invalid execution attempt id".to_owned())?,
        reconcile_only: row
            .try_get("reconcile_only")
            .map_err(|_| "invalid reconciliation disposition".to_owned())?,
    }))
}

fn now_ms() -> WorkerResult<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock unavailable".to_owned())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system clock overflow".to_owned())
}

#[cfg(test)]
fn resources(target_id: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    openpc_fleet_controller::REQUIRED_XDS_TYPES
        .iter()
        .map(|resource_type| {
            (
                (*resource_type).to_owned(),
                vec![format!("openpc/{target_id}/configuration/v1")],
            )
        })
        .collect()
}

fn receipt_bytes(receipt: &Value, field: &str) -> WorkerResult<Vec<u8>> {
    receipt
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {field}"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| format!("invalid {field}"))
        })
        .collect()
}

fn generic_receipt(work: &ClaimedWork) -> WorkerResult<Value> {
    let artifact_kind = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => ConfigurationArtifactKind::ProviderProfile,
        "INDEXER_ADMISSION" => ConfigurationArtifactKind::ClientIndexerProfile,
        "PROJECTION_VALIDATION" => ConfigurationArtifactKind::ProjectionPlan,
        _ => return Err("unsupported configuration work kind".into()),
    };
    let artifact_digest = parse_digest(work.input_digest.clone())?;
    let artifact_cbor = load_active_configuration_artifact(
        &work.configuration_cbor,
        &work.configuration_digest,
        &work.resource_id,
        artifact_kind,
        &artifact_digest,
    )
    .map_err(|_| "configuration resource artifact rejected".to_owned())?;
    match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => {
            let profile = qualify_provider_profile(&artifact_cbor, &work.input_digest)
                .map_err(|_| "provider qualification rejected".to_owned())?;
            Ok(serde_json::json!({
                "artifactCbor": artifact_cbor,
                "artifactDigest": work.input_digest,
                "consumer": "LS-MULTI-RPC",
                "profileId": profile.profile_id,
                "profileVersion": profile.profile_version,
                "resourceId": work.resource_id,
                "workKind": work.work_kind,
            }))
        }
        "INDEXER_ADMISSION" => {
            let profile = admit_scoped_client_indexer_profile(
                &artifact_cbor,
                &work.input_digest,
                &work.participant_id,
                &work.privacy_domain_id,
            )
            .map_err(|_| "indexer admission rejected".to_owned())?;
            Ok(serde_json::json!({
                "artifactCbor": artifact_cbor,
                "artifactDigest": work.input_digest,
                "consumer": "LS-INDEXER-MANAGER/LS-INDEXER-ADAPTER",
                "profileId": profile.profile_id,
                "profileVersion": profile.profile_version,
                "resourceId": work.resource_id,
                "workKind": work.work_kind,
            }))
        }
        "PROJECTION_VALIDATION" => projection_admission::receipt(work, artifact_cbor),
        _ => Err("unsupported configuration work kind".into()),
    }
}

fn require_work_configuration(work: &ClaimedWork, config: &Config) -> WorkerResult<()> {
    if config.participant_id != work.participant_id
        || config.privacy_domain_id != work.privacy_domain_id
        || work.configuration_cbor.is_empty()
        || work.configuration_cbor.len() > 4 * 1024 * 1024
        || Digest::of(&work.configuration_cbor) != work.configuration_digest
    {
        return Err("runtime effect original configuration rejected".into());
    }
    Ok(())
}

async fn record_bootstrap_source_restriction(
    tx: &mut Transaction<'_, Postgres>,
    source: &openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
    manifest: &TargetBootstrapManifest,
    consumer: &str,
) -> WorkerResult<()> {
    match &manifest.target_disposition {
        Some(binding) => {
            source
                .record_consumer_restriction(
                    tx,
                    openpc_fleet_controller::runtime_artifact_source::SourceConsumerUse {
                        configuration_digest: binding.source.configuration_digest.clone(),
                        consumer_id: consumer.into(),
                        boundary: Some(match consumer {
                            "prior-bootstrap-binding" => openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::PriorBootstrapBinding,
                            "cigl-invalidation" => openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::CiglInvalidation,
                            "no-effect-suspension" => openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::NoEffectSuspension,
                            "target-handoff" => openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::TargetHandoff,
                            _ => return Err("uninstalled source consumer boundary".into()),
                        }),
                        target_id: Some(manifest.target_runtime_id.clone()),
                        original_id: binding.source.original_work_id.clone(),
                    },
                )
                .await
        }
        None => source.require_legacy_consumer(tx).await,
    }
    .map_err(|_| "target bootstrap source custody unavailable".into())
}

async fn mark_effect_started(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
) -> WorkerResult<String> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "execution boundary begin failed".to_owned())?;
    set_context(&mut transaction, config).await?;
    require_work_configuration(work, config)?;
    if work.reconcile_only || work.execution_attempt_id.is_some() {
        return Err("runtime effect already started".into());
    }
    if !runtime_artifact_new_use_allowed(
        &mut transaction,
        &work.participant_id,
        &work.privacy_domain_id,
        &work.configuration_digest,
    )
    .await?
    {
        return Err("runtime artifact retired".into());
    }
    let attempt_id: String = sqlx::query_scalar(
        "update control.configuration_work set execution_attempt_id=uuidv7(),execution_started_at=clock_timestamp(),updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 and lease_until>clock_timestamp() and execution_attempt_id is null and execution_started_at is null and participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid and configuration_digest=$5 and exists(select 1 from control.runtime_configuration_input_current_metadata input where input.participant_id=$3::text::uuid and input.privacy_domain_id=$4::text::uuid and 'sha256:'||encode(input.configuration_digest,'hex')=$5) returning execution_attempt_id::text",
    )
    .bind(&work.work_id)
    .bind(&config.worker_id)
    .bind(&work.participant_id)
    .bind(&work.privacy_domain_id)
    .bind(format!("sha256:{}", work.configuration_digest.as_str()))
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| "execution boundary compare-and-set rejected".to_owned())?;
    transaction
        .commit()
        .await
        .map_err(|_| "execution boundary commit failed".to_owned())?;
    Ok(attempt_id)
}

async fn record_runtime_observation(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    execution_attempt_id: &str,
    capsule_digest: &Digest,
    receipt: &Value,
) -> WorkerResult<Digest> {
    activation_observation::record(
        pool,
        work,
        config,
        execution_attempt_id,
        capsule_digest,
        receipt,
    )
    .await
}

async fn execute_runtime(
    persistence: ExecutionPersistence<'_>,
    work: &ClaimedWork,
    config: &Config,
    plane: Option<&RuntimePlane>,
) -> WorkerResult<(Digest, Value, Digest)> {
    let target_id = work
        .target_id
        .as_deref()
        .ok_or_else(|| "runtime target missing".to_owned())?;
    let xds_version_digest = work
        .xds_version_digest
        .as_ref()
        .ok_or_else(|| "xds version missing".to_owned())?;
    if work.active_generation_digest.is_some() != work.active_xds_version_digest.is_some() {
        return Err("incomplete durable active journal".into());
    }
    if work.predecessor_digest != work.active_generation_digest {
        // An expired observed effect is never presented as confirmed active.
        // Its separately acknowledged denial cursor supplies physical custody.
        let matches = match persistence {
            ExecutionPersistence::Durable(pool) => {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| "denied predecessor read unavailable")?;
                set_context(&mut tx, config).await?;
                let matched: bool = sqlx::query_scalar("select coalesce(openpc.runtime_work_predecessor_matches(w.configuration_work_id),false) from control.configuration_work w where w.configuration_work_id=$1::text::uuid and w.participant_id=$2::text::uuid and w.privacy_domain_id=$3::text::uuid and w.runtime_target_id=$4::text::uuid and w.predecessor_digest=$5 and w.state='LEASED' and w.lease_owner=$6 and w.lease_until>clock_timestamp() and w.denied_predecessor_work_id is not null")
                    .bind(&work.work_id).bind(&work.participant_id).bind(&work.privacy_domain_id)
                    .bind(target_id).bind(work.predecessor_digest.as_ref().map(|d|format!("sha256:{}",d.as_str())))
                    .bind(&config.worker_id).fetch_one(&mut *tx).await.map_err(|_| "denied predecessor rejected")?;
                tx.rollback()
                    .await
                    .map_err(|_| "denied predecessor read release unconfirmed")?;
                matched
            }
            #[cfg(test)]
            ExecutionPersistence::TestOnlyBypass => false,
        };
        if !matches {
            return Err("predecessor does not match active generation".into());
        }
    }
    let provider_receipt = work
        .provider_receipt
        .as_ref()
        .ok_or_else(|| "qualified provider receipt unavailable".to_owned())?;
    let projection_receipt = work
        .projection_receipt
        .as_ref()
        .ok_or_else(|| "validated projection receipt unavailable".to_owned())?;
    let provider_cbor = receipt_bytes(provider_receipt, "artifactCbor")?;
    let profile_cbor = receipt_bytes(projection_receipt, "profileArtifactCbor")?;
    let projection_cbor = receipt_bytes(projection_receipt, "artifactCbor")?;
    let provider_digest = provider_receipt
        .get("artifactDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| "qualified provider digest unavailable".to_owned())?;
    let projection_digest = projection_receipt
        .get("artifactDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| "validated projection digest unavailable".to_owned())?;
    let qualified_provider = qualify_provider_profile(&provider_cbor, provider_digest)
        .map_err(|_| "qualified provider replay rejected".to_owned())?;
    validate_projection_admission(&profile_cbor, &projection_cbor, projection_digest)
        .map_err(|_| "validated projection replay rejected".to_owned())?;
    let workload_id = pc_policy_core::invocation::active_invocation_workload(
        &work.configuration_cbor,
        &work.configuration_digest,
        &work.participant_id,
        &work.privacy_domain_id,
    )
    .map_err(|_| "runtime configuration workload scope rejected".to_owned())?;
    let typed_document =
        pc_policy_core::semantics::PolicySemanticDocument::decode(&work.policy()?.artifact_cbor);
    let (
        mut contract_policies,
        required_facts,
        governed_routing_ready,
        selected_read_asset_ids,
        selected_write_asset_ids,
    ) = if let Ok(document) = typed_document {
        if document.digest()? != work.policy()?.artifact_digest {
            return Err("policy semantic digest rejected".into());
        }
        // Resolve after the claim commits: a missing, expired or quarantined
        // publication must reach the durable failure owner, not roll back
        // the lease and stop the worker with the same pending item.
        let (deployments, indexers, visibility) = if document.deployment_policies.is_empty()
            && document.indexer_policies.is_empty()
            && document.visibility_policies.is_empty()
        {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            match persistence {
                ExecutionPersistence::Durable(pool) => {
                    let mut transaction = pool
                        .begin()
                        .await
                        .map_err(|_| "deployment publication begin failed".to_owned())?;
                    set_context(&mut transaction, config).await?;
                    let deployments =
                        openpc_fleet_controller::deployment_policy::load_deployment_policy_inputs(
                            &mut transaction,
                            &document,
                        )
                        .await?;
                    let indexers =
                        openpc_fleet_controller::indexer_policy::load_indexer_policy_inputs(
                            &mut transaction,
                            &document,
                            &work.configuration_digest,
                        )
                        .await?;
                    let visibility =
                        openpc_fleet_controller::visibility_policy::load_visibility_policy_inputs(
                            &mut transaction,
                            &document,
                        )
                        .await?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| "deployment publication commit failed".to_owned())?;
                    (deployments, indexers, visibility)
                }
                #[cfg(test)]
                ExecutionPersistence::TestOnlyBypass => {
                    return Err("policy publication requires durable resolution".into());
                }
            }
        };
        let selected = work
            .contract_policy_assets
            .iter()
            .filter(|asset| {
                document
                    .contract_policies
                    .iter()
                    .any(|reference| reference.contract_method_policy_id == asset.asset_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let selected_read_asset_ids = selected
            .iter()
            .filter(|asset| asset.effect == "READ")
            .map(|asset| asset.asset_id.clone())
            .collect::<Vec<_>>();
        let selected_write_asset_ids = selected
            .iter()
            .filter(|asset| asset.effect == "WRITE")
            .map(|asset| asset.asset_id.clone())
            .collect::<Vec<_>>();
        let required_facts = document.required_facts.clone();
        (
            Some(
                pc_policy_core::contract_simulation::compile_document_with_visibility(
                    &document,
                    &selected,
                    &deployments,
                    &indexers,
                    &visibility,
                    &workload_id,
                    &work.policy()?.generation_digest,
                )?,
            ),
            required_facts,
            true,
            selected_read_asset_ids,
            selected_write_asset_ids,
        )
    } else {
        let policies = ValidatedInvocationPolicy::load_active(
            &work.configuration_cbor,
            &work.configuration_digest,
            &work.policy()?.artifact_cbor,
            &work.policy()?.artifact_digest,
            &ActiveInvocationScope {
                policy_generation_digest: &work.policy()?.generation_digest,
                tenant_id: &work.participant_id,
                privacy_domain_id: &work.privacy_domain_id,
                workload_id: &workload_id,
            },
        )
        .map_err(|_| "active invocation artifacts rejected".to_owned())?;
        if policies.is_empty() {
            return Err("active invocation artifacts empty".into());
        }
        let generation = pc_policy_core::invocation::decode_active_invocation_policy_generation(
            &work.policy()?.artifact_cbor,
            &work.policy()?.artifact_digest,
        )
        .map_err(|_| "policy semantic document rejected".to_owned())?;
        let required_facts = generation.required_facts.clone();
        (
            compile_admitted_contract_policies(
                &work.contract_policy_assets,
                &generation.rpc_policies,
                &work.policy()?.generation_digest,
                &workload_id,
            )?,
            required_facts,
            false,
            Vec::new(),
            Vec::new(),
        )
    };
    let profile_activation = match persistence {
        ExecutionPersistence::Durable(pool) => cigl_activation::prepare(pool, config, work).await?,
        #[cfg(test)]
        ExecutionPersistence::TestOnlyBypass => None,
    };
    if let Some(prepared) = &profile_activation {
        let base = contract_policies
            .take()
            .ok_or("CIGL base contract policies unavailable")?;
        contract_policies = Some(
            prepared
                .sources
                .bind_invocation(base)
                .map_err(|_| "CIGL invocation composition rejected")?,
        );
    }
    let visibility_resources = contract_policies
        .as_ref()
        .map(|compiled| {
            pc_policy_core::invocation::decode_active_invocation_configuration(
                &compiled.configuration_cbor,
                &compiled.configuration_digest,
            )
            .map(|configuration| {
                configuration
                    .visibility_resources
                    .into_iter()
                    .filter(|resource| {
                        matches!(resource.selector,
                pc_policy_core::visibility_policy::VisibilitySelector::Event {..}
                | pc_policy_core::visibility_policy::VisibilitySelector::Transaction {..}
                | pc_policy_core::visibility_policy::VisibilitySelector::Receipt {..})
                    })
                    .collect::<Vec<_>>()
            })
        })
        .transpose()
        .map_err(|_| "visibility route configuration rejected")?
        .unwrap_or_default();
    let source_only = contract_policies.as_ref().is_some_and(|bundle| {
        bundle.policies.is_empty()
            && bundle.deployment_policies.is_empty()
            && visibility_resources.is_empty()
    });
    let source_custody = if source_only {
        let invocation = contract_policies
            .as_ref()
            .ok_or("source policy compilation missing")?;
        let generation = pc_policy_core::invocation::decode_active_invocation_policy_generation(
            &invocation.policy_cbor,
            &invocation.policy_digest,
        )
        .map_err(|_| "source policy generation rejected")?;
        if generation.indexer_policies.is_empty() && generation.visibility_policies.is_empty() {
            return Err("admitted policies empty".into());
        }
        #[cfg(not(test))]
        let ExecutionPersistence::Durable(control_pool) = persistence;
        #[cfg(test)]
        let control_pool = match persistence {
            ExecutionPersistence::Durable(pool) => pool,
            #[cfg(test)]
            ExecutionPersistence::TestOnlyBypass => {
                return Err("source custody requires durable owners".into());
            }
        };
        Some(source_activation::SourceCustody {
            identity: load_identity_publication(
                control_pool,
                config,
                target_id,
                now_ms()?.saturating_mul(1_000_000),
            )
            .await?,
            compiled: invocation,
        })
    } else {
        None
    };
    #[cfg(test)]
    let fleet_public =
        PurposeSigner::from_secret_bytes(PURPOSE_DESIRED_GENERATION_V1, config.fleet_key)
            .map_err(|_| "fleet signer unavailable".to_owned())?
            .verifier()
            .sec1_bytes();
    #[cfg(test)]
    let receipt_public =
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.agent_key)
            .map_err(|_| "agent signer unavailable".to_owned())?
            .verifier()
            .sec1_bytes();
    #[cfg(test)]
    let restored = work
        .active_generation_digest
        .clone()
        .zip(work.active_xds_version_digest.clone())
        .map(|(generation, xds)| (generation, xds, work.journal_sequence.max(1)));
    #[cfg(test)]
    let legacy_agent =
        RuntimeAgent::restore(target_id, &fleet_public, config.agent_key, 64, restored)
            .map_err(|_| "runtime agent restore rejected".to_owned())?;
    let (fleet, identity) = match persistence {
        ExecutionPersistence::Durable(_) => {
            let plane = plane.ok_or_else(|| "runtime plane unavailable".to_owned())?;
            (Arc::clone(&plane.fleet), plane.register_target(target_id)?)
        }
        #[cfg(test)]
        ExecutionPersistence::TestOnlyBypass => {
            let fleet = Arc::new(
                FleetController::new(config.fleet_key, &receipt_public, 30_000)
                    .map_err(|_| "fleet controller initialization rejected".to_owned())?,
            );
            let identity = TargetIdentity {
                target_id: target_id.to_owned(),
                uri_san: format!("spiffe://openpc.local/runtime-target/{target_id}"),
                certificate_fingerprint: Digest::of(format!(
                    "openpc-local-certificate:{target_id}"
                )),
                workload_epoch: 1,
            };
            fleet
                .register_target(identity.clone(), &identity)
                .map_err(|_| "runtime target identity rejected".to_owned())?;
            (fleet, identity)
        }
    };
    #[cfg(test)]
    let runtime_configuration_digest = match &contract_policies {
        Some(contract) => Digest::of(
            canonical_bytes(&(
                work.configuration_digest.clone(),
                contract.configuration_digest.clone(),
                contract.policy_digest.clone(),
            ))
            .map_err(|_| "contract policy digest closure rejected".to_owned())?,
        ),
        None => work.configuration_digest.clone(),
    };
    let mut read_runtime_binding_ids = BTreeSet::new();
    let mut write_runtime_binding_ids = BTreeSet::new();
    for (selected_ids, bindings) in [
        (&selected_read_asset_ids, &mut read_runtime_binding_ids),
        (&selected_write_asset_ids, &mut write_runtime_binding_ids),
    ] {
        if selected_ids.is_empty() {
            continue;
        }
        let contract = contract_policies
            .as_ref()
            .ok_or_else(|| "contract policy owner identity unavailable".to_owned())?;
        for asset_id in selected_ids {
            let admitted = work
                .contract_policy_assets
                .iter()
                .find(|asset| asset.asset_id == *asset_id)
                .ok_or_else(|| "contract policy owner identity unavailable".to_owned())?;
            let identity = contract
                .policies
                .iter()
                .filter_map(|policy| policy.configured_identity().ok())
                .find(|identity| identity.contract_method_policy_id() == asset_id)
                .ok_or_else(|| "contract policy owner identity unavailable".to_owned())?;
            if admitted.runtime_binding_id.as_deref() != Some(identity.runtime_binding_id()) {
                return Err("contract policy binding substituted".into());
            }
            bindings.insert(identity.runtime_binding_id().to_owned());
        }
    }
    let read_runtime_binding_ids = read_runtime_binding_ids.into_iter().collect::<Vec<_>>();
    let write_runtime_binding_ids = write_runtime_binding_ids.into_iter().collect::<Vec<_>>();
    let deployment_policies = contract_policies
        .as_ref()
        .map(|compiled| {
            compiled
                .deployment_policies
                .iter()
                .map(|policy| {
                    let publication = policy.publication();
                    pc_policy_core::deployment_policy::DeploymentPolicyReference {
                        deployment_policy_id: publication.deployment_policy_id.clone(),
                        definition_digest: publication.definition_digest.clone(),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let now = now_ms()?;
    let routing_publication = match persistence {
        ExecutionPersistence::Durable(pool)
            if governed_routing_ready
                && (!read_runtime_binding_ids.is_empty()
                    || !visibility_resources.is_empty()
                    || !write_runtime_binding_ids.is_empty()
                    || !deployment_policies.is_empty()) =>
        {
            let generation_id = work
                .generation_id
                .as_deref()
                .ok_or_else(|| "runtime generation missing".to_owned())?;
            let generation_digest = work
                .generation_digest
                .as_ref()
                .ok_or_else(|| "runtime generation digest missing".to_owned())?;
            let runtime_generation = work
                .journal_sequence
                .checked_add(1)
                .ok_or_else(|| "runtime generation sequence overflow".to_owned())?;
            let now_ns = now
                .checked_mul(1_000_000)
                .ok_or_else(|| "routing publication timestamp overflow".to_owned())?;
            let repository = RoutingPublicationRepository::new(
                pool.clone(),
                work.participant_id.clone(),
                work.privacy_domain_id.clone(),
                config.worker_id.clone(),
                config.fleet_key,
            )?;
            let published = repository
                .publish(
                    &GovernedRoutingPublicationInput {
                        configuration_work_id: work.work_id.clone(),
                        runtime_configuration_generation_id: generation_id.to_owned(),
                        runtime_target_id: target_id.to_owned(),
                        runtime_generation,
                        generation_digest: generation_digest.clone(),
                        policy_generation_digest: work.policy()?.generation_digest.clone(),
                        read_runtime_binding_ids,
                        visibility_resources,
                        write_runtime_binding_ids,
                        deployment_policies,
                        required_facts: required_facts.clone(),
                    },
                    now_ns,
                )
                .await?;
            let readback = repository.read_current(generation_id, now_ns).await?;
            if readback != published {
                return Err("routing publication readback mismatch".into());
            }
            Some(published)
        }
        _ => None,
    };
    let governed_custody = match (&routing_publication, &contract_policies) {
        (Some(_), Some(invocation)) => {
            let now_ns = now
                .checked_mul(1_000_000)
                .ok_or_else(|| "runtime timestamp overflow".to_owned())?;
            #[cfg(not(test))]
            let ExecutionPersistence::Durable(control_pool) = persistence;
            #[cfg(test)]
            let control_pool = match persistence {
                ExecutionPersistence::Durable(pool) => pool,
                ExecutionPersistence::TestOnlyBypass => {
                    return Err("governed custody requires durable owners".into());
                }
            };
            Some(GovernedCustodyMaterial {
                identity: load_identity_publication(control_pool, config, target_id, now_ns)
                    .await?,
                fact: if required_facts.is_empty() {
                    None
                } else {
                    Some(load_fact_publication(control_pool, config, &required_facts).await?)
                },
                invocation,
                cigl_settings: load_cigl_settings(control_pool, config, work).await?,
                cigl_profiles: profile_activation
                    .as_ref()
                    .map(|prepared| &prepared.sources),
            })
        }
        (None, _) => None,
        (Some(_), None) => return Err("governed invocation custody unavailable".into()),
    };
    if profile_activation.is_some() && governed_custody.is_none() {
        return Err("CIGL governed custody unavailable".into());
    }
    #[cfg(test)]
    let route_profile_digest = if let Some(published) = &routing_publication {
        Digest::of(
            canonical_bytes(&(
                published.mrpc_runtime_profile_digest.clone(),
                published.routing_authority_digest.clone(),
                published.certification_authority_digest.clone(),
            ))
            .map_err(|_| "routing publication digest closure rejected".to_owned())?,
        )
    } else {
        Digest::of(&provider_cbor)
    };
    #[cfg(test)]
    let bundle = ArtifactBundle {
        manifest_digest: work.configuration_digest.clone(),
        policy_generation_digest: work.policy()?.generation_digest.clone(),
        fact_generation_digest: work.policy()?.fact_generation_digest.clone(),
        route_profile_digest,
        runtime_configuration_digest,
        schema_version: "1.0".into(),
        abi_version: "1.0".into(),
        declared_bytes: u64::try_from(
            work.configuration_cbor.len()
                + work.policy()?.artifact_cbor.len()
                + provider_cbor.len()
                + profile_cbor.len()
                + projection_cbor.len()
                + routing_publication
                    .as_ref()
                    .map_or(0, publication_declared_bytes)
                + contract_policies.as_ref().map_or(0, |contract| {
                    contract.configuration_cbor.len() + contract.policy_cbor.len()
                }),
        )
        .map_err(|_| "runtime artifact size overflow".to_owned())?,
        available_capacity_bytes: config.artifact_capacity_bytes,
    };
    let (capsule_digest, execution_attempt_id, mut receipt_value, capsule_expiry_ns) =
        match persistence {
            ExecutionPersistence::Durable(pool) => {
                let plane = plane.ok_or_else(|| "runtime plane unavailable".to_owned())?;
                let now_ns = now
                    .checked_mul(1_000_000)
                    .ok_or_else(|| "runtime timestamp overflow".to_owned())?;
                let governed = routing_publication.as_ref().zip(governed_custody.as_ref());
                let (mut capsule, artifacts, mut admission) = if let Some(custody) = &source_custody
                {
                    source_activation::capsule(
                        work,
                        config,
                        custody,
                        work.predecessor_digest.clone(),
                        now_ns,
                    )?
                } else if let Some((routing, custody)) = governed {
                    governed_runtime_capsule(
                        work,
                        config,
                        custody,
                        routing,
                        work.predecessor_digest.clone(),
                        now_ns,
                    )?
                } else {
                    canonical_runtime_capsule(
                        work,
                        provider_cbor.clone(),
                        profile_cbor.clone(),
                        projection_cbor.clone(),
                        routing_publication.as_ref(),
                        work.predecessor_digest.clone(),
                        now_ns,
                    )?
                };
                if governed.is_none()
                    && source_custody.is_none()
                    && let Some(previous) = prior_governed_admission(
                        config,
                        target_id,
                        work.predecessor_digest.as_ref(),
                    )?
                {
                    admission = previous;
                }
                let stable = Digest::of(b"OpenPC R1 runtime primary registry v1");
                let complete_component_set_digest =
                    Digest::of(b"OpenPC R1 runtime complete component set v1");
                let agent_signer = RuntimeWireSigner::from_secret_bytes(config.agent_key)
                    .map_err(|_| "canonical agent signer unavailable".to_owned())?;
                let fleet_signer = RuntimeWireSigner::from_secret_bytes(config.fleet_key)
                    .map_err(|_| "canonical Fleet signer unavailable".to_owned())?;
                activation_observation::require_activation_budget(
                    capsule.hard_expiry_ns,
                    now_ms()?.saturating_mul(1_000_000),
                )?;
                let agent_directory = Path::new("/runtime/agent").join(target_id);
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&agent_directory)
                    .map_err(|_| "target journal directory unavailable".to_owned())?;
                fs::set_permissions(
                    &agent_directory,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .map_err(|_| "target journal permissions unavailable".to_owned())?;
                let suspended = if let Some(prepared) = &profile_activation {
                    Some(
                        prepared
                            .suspend(pool, config, work, &plane.source_custody)
                            .await?,
                    )
                } else {
                    retained_target::suspend_current(pool, config, work, &plane.source_custody)
                        .await?
                };
                let trust = CapsuleTrust {
                    target_id: target_id.to_owned(),
                    fleet_id: "openpc-local-runtime-fleet".into(),
                    fleet_signer_id: "openpc-local-fleet-signer".into(),
                    agent_signer_id: "openpc-local-agent-signer".into(),
                    contract_set_manifest_digest: stable.clone(),
                    schema_registry_digest: stable.clone(),
                    cose_purpose_registry_digest: stable,
                    complete_component_set_digest,
                };
                let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                let agent = loop {
                    match RuntimeAgent::try_open_canonical(
                        trust.clone(),
                        &fleet_signer.verifier().public_key_bytes(),
                        config.agent_key,
                        64,
                        config.artifact_capacity_bytes,
                        &agent_directory,
                        admission.clone(),
                    )
                    .map_err(|_| "canonical runtime agent open rejected")?
                    {
                        Some(agent) => break Arc::new(agent),
                        None if suspended.is_some() && tokio::time::Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        None => return Err("canonical target handoff timed out".into()),
                    }
                };
                let previous = agent
                    .active_canonical_generation()
                    .map_err(|_| "canonical active generation readback rejected".to_owned())?
                    .map(|(digest, _, _)| digest);
                if previous != work.predecessor_digest {
                    return Err(
                        "canonical predecessor does not match durable active generation".into(),
                    );
                }
                let renewed = if let Some(previous) = &suspended {
                    renew_target_restrictions(
                        &agent,
                        previous,
                        config.fleet_key,
                        now_ms()?.saturating_mul(1_000_000),
                        capsule.hard_expiry_ns,
                    )
                    .map_err(|_| "target restriction renewal rejected")?
                } else {
                    None
                };
                if let Some((generation, _)) = &renewed {
                    capsule.emergency_deny_generation = *generation;
                }
                let capsule_digest = capsule
                    .digest()
                    .map_err(|_| "canonical capsule digest rejected".to_owned())?;
                let capsule_id = capsule.capsule_id.clone();
                let capsule_generation = capsule.generation;
                let preparation_now_ns = now_ms()?
                    .saturating_mul(1_000_000)
                    .max(capsule.not_before_ns);
                let coordinator = CanonicalTargetCoordinator::with_ads(
                    Arc::clone(&fleet),
                    Arc::clone(&agent),
                    plane.ads.clone(),
                )
                .map_err(|_| "canonical ADS owner rejected".to_owned())?;
                let prepared = coordinator
                    .prepare_versioned(
                        fleet_signer
                            .sign_capsule(&capsule)
                            .map_err(|_| "canonical capsule signing rejected".to_owned())?,
                        artifacts,
                        work.occurrence_id.as_deref().unwrap_or(&work.work_id),
                        ProtectedListenerConfig {
                            target_id,
                            capsule_id: &capsule_id,
                            capsule_generation,
                            request_timeout_ms: qualified_provider.timeout_budget_millis,
                            bind_address: &plane.config.protected_bind,
                            port: plane.config.protected_port,
                            pds_socket: &plane.config.pds_socket,
                            broker_socket: &plane.config.broker_socket,
                            certificate_file: &plane.config.protected_certificate,
                            private_key_file: &plane.config.protected_key,
                            workload_ca_file: &plane.config.workload_ca,
                        },
                        xds_version_digest.clone(),
                        preparation_now_ns,
                    )
                    .map_err(|error| {
                        format!(
                            "canonical runtime preparation rejected: {}",
                            error.pc_code()
                        )
                    })?;
                plane.wait_for_ack(target_id).await?;
                let discovery =
                    discovery::ActivationDiscovery::fence(pool, config, target_id).await?;
                // Preparation, ADS and journal handoff can consume publication validity.
                // Decline before consuming the effect; never extend the signed deadline.
                activation_observation::require_activation_budget(
                    capsule.hard_expiry_ns,
                    now_ms()?.saturating_mul(1_000_000),
                )?;
                let execution_attempt_id = mark_effect_started(pool, work, config).await?;
                let activation_now_ns = now_ms()?.saturating_mul(1_000_000);
                let signed_receipt = discovery.activate(plane, target_id, || {
                    coordinator
                        .activate(&prepared, activation_now_ns.saturating_add(1))
                        .map_err(|_| "canonical target activation rejected".to_owned())
                })?;
                discovery.release().await?;
                if let Some((_, delivery)) = &renewed {
                    delivery
                        .install(&agent, activation_now_ns.saturating_add(1))
                        .map_err(|_| "target renewed restrictions rejected")?;
                }
                let freshness = RevocationFreshnessLease {
                    lease_id: format!("{}:freshness", capsule_id),
                    target_runtime_id: target_id.to_owned(),
                    fleet_id: "openpc-local-runtime-fleet".into(),
                    lease_generation: agent
                        .next_freshness_generation()
                        .map_err(|_| "runtime freshness sequence exhausted")?,
                    minimum_emergency_generation: capsule.emergency_deny_generation,
                    issued_at_ns: activation_now_ns.saturating_add(1),
                    expires_at_ns: capsule.hard_expiry_ns,
                    protected_class_set_digest: protected_class_set_digest(),
                    signer_id: "openpc-local-fleet-signer".into(),
                };
                agent
                    .install_freshness_lease(
                        &fleet_signer
                            .sign_freshness_lease(&freshness)
                            .map_err(|_| "runtime freshness lease signing rejected".to_owned())?,
                        activation_now_ns.saturating_add(1),
                    )
                    .map_err(|_| "runtime freshness lease installation rejected".to_owned())?;
                let target_disposition = plane
                    .disposition
                    .as_ref()
                    .ok_or("target disposition installation unavailable")?
                    .bootstrap_for_activation(&plane.target_identity(target_id)?, &capsule)
                    .await?;
                if let Some(custody) = &source_custody {
                    write_target_bootstrap(
                        &Path::new("/runtime/target-bootstrap").join(target_id),
                        source_activation::bootstrap(
                            work,
                            config,
                            custody,
                            &capsule,
                            renewed.map(|(_, delivery)| delivery),
                            target_disposition,
                        )?,
                        config.fleet_key,
                    )?;
                } else if let Some((routing, custody)) =
                    routing_publication.as_ref().zip(governed_custody.as_ref())
                {
                    write_target_bootstrap(
                        &Path::new("/runtime/target-bootstrap").join(target_id),
                        TargetBootstrapManifest {
                            version: 1,
                            participant_id: work.participant_id.clone(),
                            privacy_domain_id: work.privacy_domain_id.clone(),
                            target_runtime_id: target_id.to_owned(),
                            fleet_id: capsule.fleet_id.clone(),
                            fleet_signer_id: capsule.signer_id.clone(),
                            agent_signer_id: "openpc-local-agent-signer".into(),
                            authority_signer_id: config.worker_id.clone(),
                            fleet_runtime_public_key: fleet_signer.verifier().public_key_bytes(),
                            identity_runtime_public_key: config.identity_runtime_public_key.clone(),
                            fact_verify_key: config.fact_verify_key.clone(),
                            fact_verify_key_id: config.fact_verify_key_id.clone(),
                            contract_set_manifest_digest: capsule
                                .contract_set_manifest_digest
                                .clone(),
                            schema_registry_digest: capsule.schema_registry_digest.clone(),
                            cose_purpose_registry_digest: capsule
                                .cose_purpose_registry_digest
                                .clone(),
                            complete_component_set_digest: capsule
                                .complete_component_set_digest
                                .clone(),
                            capsule_id: capsule_id.clone(),
                            capsule_generation,
                            capsule_digest: capsule_digest.clone(),
                            identity_profile_digest: custody.identity.profile_digest.clone(),
                            mrpc_runtime_profile: routing.mrpc_runtime_profile.clone(),
                            routing_source: routing.routing_source.clone(),
                            certification_source: routing.certification_source.clone(),
                            protected_class_set_digest: protected_class_set_digest(),
                            source_only: false,
                            emergency_delivery: renewed.map(|(_, delivery)| delivery),
                            suspended_for_work: None,
                            target_disposition: Some(target_disposition),
                        },
                        config.fleet_key,
                    )?;
                } else {
                    retire_target_bootstrap(
                        &Path::new("/runtime/target-bootstrap").join(target_id),
                    )?;
                }
                let receipt = agent_signer
                    .verifier()
                    .verify_receipt(&signed_receipt)
                    .map_err(|_| "canonical activation receipt rejected".to_owned())?;
                // Release exclusive journal custody before waiting for the real
                // target process to reopen, serve, and observe Envoy's generation.
                drop(coordinator);
                drop(agent);
                let mut value = serde_json::to_value(receipt)
                    .map_err(|_| "activation receipt serialization rejected".to_owned())?;
                value
                    .as_object_mut()
                    .ok_or_else(|| "activation receipt shape rejected".to_owned())?
                    .insert(
                        "activationReceiptCoseHex".into(),
                        Value::String(hex_bytes(&signed_receipt)),
                    );
                value
                    .as_object_mut()
                    .ok_or_else(|| "activation receipt shape rejected".to_owned())?
                    .insert(
                        "capsuleGeneration".into(),
                        Value::Number(capsule_generation.into()),
                    );
                (
                    capsule_digest,
                    execution_attempt_id,
                    value,
                    capsule.hard_expiry_ns,
                )
            }
            #[cfg(test)]
            ExecutionPersistence::TestOnlyBypass => {
                let capsule_digest = Digest::of(
                    canonical_bytes(&bundle)
                        .map_err(|_| "runtime capsule encoding rejected".to_owned())?,
                );
                let desired = DesiredGeneration {
                    occurrence_id: work
                        .occurrence_id
                        .clone()
                        .unwrap_or_else(|| work.work_id.clone()),
                    target_id: target_id.to_owned(),
                    capsule_digest: capsule_digest.clone(),
                    xds_snapshot_digest: xds_version_digest.clone(),
                    expected_previous_generation_digest: work.predecessor_digest.clone(),
                    expires_at_ms: now.saturating_add(60_000),
                };
                let signed = fleet
                    .command_generation(desired)
                    .map_err(|_| "fleet command rejected".to_owned())?;
                legacy_agent
                    .prepare(&signed, &bundle, now)
                    .map_err(|_| "runtime preparation rejected".to_owned())?;
                fleet
                    .accept_prepared(target_id, &capsule_digest)
                    .map_err(|_| "prepared fact rejected".to_owned())?;
                let nonces = fleet
                    .publish_snapshot(openpc_fleet_controller::XdsSnapshot {
                        target_id: target_id.to_owned(),
                        version_digest: xds_version_digest.clone(),
                        resources_by_type: resources(target_id),
                    })
                    .map_err(|_| "xds snapshot rejected".to_owned())?;
                for resource_type in openpc_fleet_controller::REQUIRED_XDS_TYPES {
                    fleet
                        .acknowledge(
                            &identity,
                            resource_type,
                            xds_version_digest,
                            nonces
                                .get(resource_type)
                                .ok_or_else(|| "xds nonce missing".to_owned())?,
                        )
                        .map_err(|_| "xds acknowledgement rejected".to_owned())?;
                }
                let token = fleet
                    .issue_activation_token(target_id, now + 1, 30_000)
                    .map_err(|_| "activation token rejected".to_owned())?;
                let receipt = legacy_agent
                    .activate(&token, now + 2)
                    .map_err(|_| "activation rejected".to_owned())?;
                fleet
                    .accept_activation_receipt(&receipt)
                    .map_err(|_| "activation receipt rejected".to_owned())?;
                fleet
                    .observe_request_generation(&identity, capsule_digest.clone())
                    .map_err(|_| "request observation rejected".to_owned())?;
                fleet
                    .heartbeat(&identity, capsule_digest.clone(), now + 3)
                    .map_err(|_| "runtime heartbeat rejected".to_owned())?;
                if fleet
                    .derive_state(target_id, now + 4)
                    .map_err(|_| "runtime convergence rejected".to_owned())?
                    != TargetState::ActiveMatched
                {
                    return Err("runtime did not converge".into());
                }
                (
                    capsule_digest,
                    "018f0000-0000-7000-8000-0000000004ff".into(),
                    serde_json::to_value(receipt)
                        .map_err(|_| "activation receipt serialization rejected".to_owned())?,
                    0,
                )
            }
        };
    if let Some(publication) = &routing_publication {
        let object = receipt_value
            .as_object_mut()
            .ok_or_else(|| "activation receipt shape rejected".to_owned())?;
        object.insert(
            "routingPublicationId".into(),
            Value::String(publication.publication_id.clone()),
        );
        object.insert(
            "mrpcRuntimeProfileDigest".into(),
            Value::String(format!(
                "sha256:{}",
                publication.mrpc_runtime_profile_digest.as_str()
            )),
        );
        object.insert(
            "routingSnapshotDigest".into(),
            Value::String(format!(
                "sha256:{}",
                publication.routing_authority_digest.as_str()
            )),
        );
        object.insert(
            "providerCertificationRegistryDigest".into(),
            Value::String(format!(
                "sha256:{}",
                publication.certification_authority_digest.as_str()
            )),
        );
    }
    let governed_confirmation = source_only || governed_custody.is_some();
    if let Some(contract) = contract_policies {
        let object = receipt_value
            .as_object_mut()
            .ok_or_else(|| "activation receipt shape rejected".to_owned())?;
        object.insert(
            "contractPolicyConfigurationDigest".into(),
            Value::String(format!("sha256:{}", contract.configuration_digest.as_str())),
        );
        object.insert(
            "contractPolicyArtifactDigest".into(),
            Value::String(format!("sha256:{}", contract.policy_digest.as_str())),
        );
        object.insert(
            "contractPolicyCount".into(),
            Value::from(u64::try_from(contract.policies.len()).unwrap_or(u64::MAX)),
        );
        if !contract.deployment_policies.is_empty() {
            object.insert(
                "deploymentPolicyCount".into(),
                Value::from(u64::try_from(contract.deployment_policies.len()).unwrap_or(u64::MAX)),
            );
        }
    }
    let profiled = profile_activation.is_some();
    let receipt_digest = match persistence {
        ExecutionPersistence::Durable(pool) => {
            record_runtime_observation(
                pool,
                work,
                config,
                &execution_attempt_id,
                &capsule_digest,
                &receipt_value,
            )
            .await?
        }
        #[cfg(test)]
        ExecutionPersistence::TestOnlyBypass => Digest::of(
            canonical_bytes(&receipt_value)
                .map_err(|_| "activation receipt encoding rejected".to_owned())?,
        ),
    };
    // The effect and its observation are durable. Release the old profile TX
    // before the native confirmation independently acquires current sources;
    // holding both would contend with this same worker's CIGL fence.
    if let Some(prepared) = profile_activation {
        prepared.release().await?;
    }
    if matches!(persistence, ExecutionPersistence::Durable(_)) {
        if governed_confirmation {
            disposition_restore::confirm_observed(
                config,
                plane.ok_or("runtime plane unavailable")?,
                target_id,
                &capsule_digest,
                disposition_restore::ConfirmationMode::OriginalObservation,
            )
            .await?;
        }
        let observed_at_ms = if profiled || governed_confirmation {
            let receipt = RuntimeWireSigner::from_secret_bytes(config.agent_key)
                .map_err(|_| "canonical agent signer unavailable")?
                .verifier()
                .verify_receipt(&parse_hex_bytes(
                    receipt_value
                        .get("activationReceiptCoseHex")
                        .and_then(Value::as_str)
                        .ok_or("canonical activation receipt missing")?,
                )?)
                .map_err(|_| "canonical activation receipt rejected")?;
            let generation = receipt_value
                .get("capsuleGeneration")
                .and_then(Value::as_u64)
                .ok_or("canonical capsule generation missing")?;
            cigl_activation::wait_for_observation(
                config,
                target_id,
                &capsule_digest,
                generation,
                receipt.agent_sequence,
                receipt.observed_at_ns,
                capsule_expiry_ns,
            )
            .await?
        } else {
            now + 3
        };
        fleet
            .observe_request_generation(&identity, capsule_digest.clone())
            .map_err(|_| "request observation rejected")?;
        fleet
            .heartbeat(&identity, capsule_digest.clone(), observed_at_ms)
            .map_err(|_| "runtime heartbeat rejected")?;
        if fleet
            .derive_state(target_id, observed_at_ms)
            .map_err(|_| "runtime convergence rejected")?
            != TargetState::ActiveMatched
        {
            return Err("runtime did not converge".into());
        }
    }
    Ok((capsule_digest, receipt_value, receipt_digest))
}

async fn execute(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    plane: &RuntimePlane,
) -> WorkerResult<(Option<Digest>, Value, Digest)> {
    // The durable negative marker precedes profile/capsule signing, target
    // bootstrap writes and native dispatch, including failures in preparation.
    // Its SQL fence is the existing original-input/new-use owner.
    let mut source_tx = pool
        .begin()
        .await
        .map_err(|_| "native source transaction unavailable")?;
    set_context(&mut source_tx, config).await?;
    require_work_configuration(work, config)?;
    plane
        .source_custody
        .record_consumer_use(
            &mut source_tx,
            openpc_fleet_controller::runtime_artifact_source::SourceConsumerUse {
                configuration_digest: work.configuration_digest.clone(),
                consumer_id: config.worker_id.clone(),
                boundary: Some(openpc_fleet_controller::runtime_artifact_source::SourceConsumerBoundary::RuntimeTargetEffect),
                target_id: work.target_id.clone(),
                original_id: work.work_id.clone(),
            },
        )
        .await
        .map_err(|_| "native source custody unavailable")?;
    source_tx
        .commit()
        .await
        .map_err(|_| "native source transaction unavailable")?;
    if work.work_kind == "RUNTIME_ACTIVATION" {
        if work.predecessor_digest.is_some() {
            require_work_configuration(work, config)?;
            let target = work.target_id.as_deref().ok_or("runtime target missing")?;
            let peer = plane.register_target(target)?;
            let disposition = plane
                .disposition
                .as_ref()
                .ok_or("target disposition installation unavailable")?;
            let mut prior =
                prior_target_manifest(config, target, work.predecessor_digest.as_ref())?
                    .ok_or("target disposition original bootstrap missing")?;
            if prior.target_disposition.is_none() {
                let retained = retained_target::read_installed(config, target)
                    .map_err(|_| "target disposition original custody unavailable")?;
                if retained
                    .capsule
                    .digest()
                    .map_err(|_| "target disposition capsule rejected")?
                    != prior.capsule_digest
                {
                    return Err("target disposition original capsule changed".into());
                }
                prior.target_disposition = Some(
                    disposition
                        .bootstrap_for_activation(&peer, &retained.capsule)
                        .await?,
                );
                let mut prior_tx = pool
                    .begin()
                    .await
                    .map_err(|_| "prior source transaction unavailable")?;
                set_context(&mut prior_tx, config).await?;
                record_bootstrap_source_restriction(
                    &mut prior_tx,
                    &plane.source_custody,
                    &prior,
                    "prior-bootstrap-binding",
                )
                .await?;
                write_target_bootstrap(
                    &Path::new("/runtime/target-bootstrap").join(target),
                    prior,
                    config.fleet_key,
                )?;
            }
            // Commit pending denial before acquiring CIGL/source/evidence
            // fences. Bootstrap custody metadata above cannot authorize serving;
            // no activation effect precedes exact ACK.
            let acknowledgement_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                if disposition
                    .publish_activation_withdrawal(&peer, &work.work_id, &config.worker_id)
                    .await?
                {
                    break;
                }
                if tokio::time::Instant::now() >= acknowledgement_deadline {
                    return Err(TARGET_DISPOSITION_PENDING.into());
                }
                // Reconcile the same original admission while the lease and
                // authority are live. Returning immediately would postpone a
                // normal ACK until lease expiry and consume freshness needlessly.
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        let (capsule, receipt, receipt_digest) = execute_runtime(
            ExecutionPersistence::Durable(pool),
            work,
            config,
            Some(plane),
        )
        .await?;
        Ok((Some(capsule), receipt, receipt_digest))
    } else {
        let mut receipt = generic_receipt(work)?;
        if work.work_kind == "PROVIDER_QUALIFICATION" {
            let mut transaction = pool
                .begin()
                .await
                .map_err(|_| "provider qualification read begin failed")?;
            set_context(&mut transaction, config).await?;
            let observation = sqlx::query(
                r#"select o.observation_id::text,o.observation_digest,o.observation
              from control.provider_profile p join control.provider_probe_observation o
                on o.observation_id=p.qualification_observation_id
               and o.participant_id=p.participant_id and o.privacy_domain_id=p.privacy_domain_id
               and o.provider_profile_id=p.provider_profile_id
              where p.provider_profile_id=$1::text::uuid and p.state='SHADOW'
                and p.behavior_fingerprint=$2 and o.input_digest=$2
                and o.configuration_digest=$3 and p.revision=o.observed_revision+1
                and o.state='OBSERVED' and o.valid_until>clock_timestamp()"#,
            )
            .bind(&work.resource_id)
            .bind(&work.input_digest)
            .bind(format!("sha256:{}", work.configuration_digest.as_str()))
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "reviewed provider observation unavailable")?;
            receipt["liveObservationId"] = Value::String(observation.get("observation_id"));
            receipt["liveObservationDigest"] = Value::String(observation.get("observation_digest"));
            receipt["liveObservation"] = observation.get("observation");
            transaction
                .commit()
                .await
                .map_err(|_| "provider qualification read commit failed")?;
        }
        let receipt_digest = Digest::of(
            canonical_bytes(&receipt).map_err(|_| "result receipt encoding rejected".to_owned())?,
        );
        Ok((None, receipt, receipt_digest))
    }
}

async fn reconcile_runtime_observation(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    plane: &RuntimePlane,
) -> WorkerResult<Option<WorkCompletion>> {
    let execution_attempt_id = work
        .execution_attempt_id
        .as_deref()
        .ok_or_else(|| "reconciliation attempt missing".to_owned())?;
    let generation_id = work
        .generation_id
        .as_deref()
        .ok_or_else(|| "runtime generation missing".to_owned())?;
    let target_id = work
        .target_id
        .as_deref()
        .ok_or_else(|| "runtime target missing".to_owned())?;
    let generation_digest = work
        .generation_digest
        .as_ref()
        .ok_or_else(|| "runtime generation digest missing".to_owned())?;
    let xds_version_digest = work
        .xds_version_digest
        .as_ref()
        .ok_or_else(|| "runtime xds digest missing".to_owned())?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "reconciliation begin failed".to_owned())?;
    set_context(&mut transaction, config).await?;
    let row = sqlx::query(
        "select capsule_digest,activation_receipt,activation_receipt_digest from control.runtime_activation_observation where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_work_id=$3::text::uuid and operation_id=$4::text::uuid and execution_attempt_id=$5::text::uuid and runtime_configuration_generation_id=$6::text::uuid and runtime_target_id=$7::text::uuid and generation_digest=$8 and xds_version_digest=$9",
    )
    .bind(&work.participant_id)
    .bind(&work.privacy_domain_id)
    .bind(&work.work_id)
    .bind(&work.operation_id)
    .bind(execution_attempt_id)
    .bind(generation_id)
    .bind(target_id)
    .bind(format!("sha256:{}", generation_digest.as_str()))
    .bind(format!("sha256:{}", xds_version_digest.as_str()))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| "activation observation readback failed".to_owned())?;
    transaction
        .commit()
        .await
        .map_err(|_| "reconciliation commit failed".to_owned())?;
    let mut selected = pool
        .begin()
        .await
        .map_err(|_| "CIGL reconciliation selection unavailable")?;
    set_context(&mut selected, config).await?;
    let profiled: bool = sqlx::query_scalar("select cigl_profile_selection is not null from control.runtime_configuration_generation where runtime_configuration_generation_id=$1::text::uuid")
        .bind(generation_id).fetch_one(&mut *selected).await.map_err(|_| "CIGL reconciliation selection rejected")?;
    selected
        .rollback()
        .await
        .map_err(|_| "CIGL reconciliation selection release failed")?;
    let (capsule_digest, receipt, stored_receipt_digest) = if let Some(row) = row {
        (
            parse_digest(
                row.try_get("capsule_digest")
                    .map_err(|_| "invalid observed capsule digest")?,
            )?,
            row.try_get::<Value, _>("activation_receipt")
                .map_err(|_| "invalid observed activation receipt")?,
            parse_digest(
                row.try_get("activation_receipt_digest")
                    .map_err(|_| "invalid observed receipt digest")?,
            )?,
        )
    } else if profiled || work.policy.is_some() {
        let Some(recovered) = retained_target::recover_observation(pool, config, work).await?
        else {
            return Ok(None);
        };
        recovered
    } else {
        return Ok(None);
    };
    let receipt_digest = Digest::of(
        canonical_bytes(&receipt)
            .map_err(|_| "observed activation receipt encoding rejected".to_owned())?,
    );
    if receipt_digest != stored_receipt_digest {
        return Err("observed activation receipt digest mismatch".into());
    }
    if let Some(encoded) = receipt
        .get("activationReceiptCoseHex")
        .and_then(Value::as_str)
    {
        let signed = parse_hex_bytes(encoded)?;
        let canonical = RuntimeWireSigner::from_secret_bytes(config.agent_key)
            .map_err(|_| "canonical agent signer unavailable".to_owned())?
            .verifier()
            .verify_receipt(&signed)
            .map_err(|_| "observed canonical receipt signature rejected".to_owned())?;
        if canonical.target_runtime_id != target_id
            || canonical.capsule_digest != capsule_digest
            || canonical.status != 1
            || canonical.reason_code != "ACTIVE_LOCAL"
            || canonical.signer_id != "openpc-local-agent-signer"
        {
            return Err("observed canonical receipt binding rejected".into());
        }
        if profiled || source_activation::is_source_only(work) {
            cigl_activation::reconcile_observed(
                pool,
                config,
                work,
                plane,
                &capsule_digest,
                &signed,
            )
            .await?;
        } else {
            if let Some(expires_at_ns) = disposition_restore::expired_observed(
                config,
                target_id,
                &capsule_digest,
                &signed,
                canonical.observed_at_ns,
            )? {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "level": "warn",
                        "event": "observed_activation_custody_expired",
                        "work_id": work.work_id,
                        "target_id": target_id,
                        "execution_attempt_id": execution_attempt_id,
                        "capsule_expires_at_ns": expires_at_ns.to_string(),
                        "disposition": "verify_original_completion_or_retain_ambiguity",
                    })
                );
                if work.predecessor_digest.is_none() {
                    return Ok(Some(WorkCompletion::Historical(
                        disposition_restore::HistoricalCompletionCandidate::new(
                            work,
                            &capsule_digest,
                            &receipt_digest,
                        )?,
                    )));
                }
                return Err(disposition_restore::EXPIRED_OBSERVED_ACTIVATION.into());
            }
            disposition_restore::confirm_observed(
                config,
                plane,
                target_id,
                &capsule_digest,
                disposition_restore::ConfirmationMode::ReconcileOriginal,
            )
            .await?;
        }
    } else {
        if profiled {
            return Err("CIGL canonical activation proof required".into());
        }
        let signed_receipt: SignedEnvelope<ActivationReceipt> =
            serde_json::from_value(receipt.clone())
                .map_err(|_| "observed activation receipt shape rejected".to_owned())?;
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, config.agent_key)
            .map_err(|_| "agent signer unavailable".to_owned())?
            .verifier()
            .verify(&signed_receipt)
            .map_err(|_| "observed activation receipt signature rejected".to_owned())?;
        if signed_receipt.claims.occurrence_id
            != work
                .occurrence_id
                .as_deref()
                .unwrap_or(work.work_id.as_str())
            || signed_receipt.claims.target_id != target_id
            || signed_receipt.claims.active_generation_digest != capsule_digest
            || signed_receipt.claims.xds_version_digest != xds_version_digest.clone()
            || signed_receipt.claims.previous_generation_digest != work.predecessor_digest.clone()
            || signed_receipt.claims.state != TargetState::ActiveMatched
        {
            return Err("observed activation receipt binding rejected".into());
        }
    }
    Ok(Some(WorkCompletion::Current(
        Some(capsule_digest),
        receipt,
        receipt_digest,
    )))
}

async fn append_result_event(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
    event_id: &str,
    event_type: &str,
    aggregate_type: &str,
    payload: &[u8],
    payload_digest: &Digest,
) -> WorkerResult<()> {
    openpc_fleet_controller::configuration_result::append_result_event(
        transaction,
        &work.result_identity(),
        event_id,
        event_type,
        aggregate_type,
        payload,
        payload_digest,
    )
    .await
}
async fn update_operation_result(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
    state: &str,
    truth_state: &str,
    revision: i64,
) -> WorkerResult<()> {
    openpc_fleet_controller::configuration_result::update_operation_result(
        transaction,
        &work.result_identity(),
        state,
        truth_state,
        revision,
    )
    .await
}

fn completion_uncertain(error: &str) -> bool {
    matches!(
        error,
        "completion commit failed" | "result transaction begin failed"
    ) || error.starts_with("completion rollback unconfirmed: ")
        || error.starts_with("result fence rollback unconfirmed: ")
}

fn record_result_failure(event: &str, primary: &str) -> bool {
    let record = format!(
        "{}\n",
        serde_json::json!({"event":event,"primary_error":primary})
    );
    // A failed diagnostic sink must never prevent the transaction rollback.
    std::io::Write::write_all(&mut std::io::stderr(), record.as_bytes()).is_err()
}

async fn result_roots<'a>(
    pool: &'a PgPool,
    config: &Config,
    work_kind: &str,
) -> WorkerResult<Transaction<'a, Postgres>> {
    result_roots_with_deadlines(pool, config, work_kind, false).await
}

async fn result_roots_with_deadlines<'a>(
    pool: &'a PgPool,
    config: &Config,
    work_kind: &str,
    maintenance: bool,
) -> WorkerResult<Transaction<'a, Postgres>> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| "result transaction begin failed".to_owned())?;
    if maintenance {
        for setting in [
            "set local TimeZone='UTC'",
            "set local lock_timeout='2s'",
            "set local statement_timeout='10s'",
            "set local idle_in_transaction_session_timeout='15s'",
        ] {
            sqlx::query(setting)
                .execute(&mut *transaction)
                .await
                .map_err(|_| "maintenance database deadline unavailable")?;
        }
    }
    let result: WorkerResult<()> = async {
    // All results retain the Participant root before generation/resource locks
    // and outbox FK checks. Runtime results additionally retain grant sources.
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(&config.participant_id).bind(&config.privacy_domain_id)
            .execute(&mut *transaction).await
            .map_err(|_| "result source context rejected".to_owned())?;
    let lifecycle: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
        .fetch_one(&mut *transaction).await.map_err(|_| "result lifecycle fence unavailable")?;
    if !lifecycle {
        return Err(RUNTIME_ARTIFACT_BUSY.into());
    }
    sqlx::query("select openpc.lock_cigl_invalidation_participant()")
        .execute(&mut *transaction)
        .await
        .map_err(|_| "result Participant fence rejected")?;
    if work_kind == "RUNTIME_ACTIVATION" {
        openpc_fleet_controller::cigl_publication::profile_invalidation::lock_sources(
            &mut transaction,
        )
        .await
        .map_err(|_| "result source fence rejected".to_owned())?;
    }
    set_context(&mut transaction, config).await?;
    Ok(())
    }.await;
    if let Err(error) = result {
        let diagnostic_failed = record_result_failure("result_fence_failed", &error);
        if transaction.rollback().await.is_err() {
            return Err(format!(
                "result fence rollback unconfirmed: {}",
                serde_json::json!({"primary":error,"diagnosticFailed":diagnostic_failed})
            ));
        }
        return Err(error);
    }
    Ok(transaction)
}

async fn result_transaction<'a>(
    pool: &'a PgPool,
    config: &Config,
    work_kind: &str,
) -> WorkerResult<Transaction<'a, Postgres>> {
    let mut transaction = result_roots(pool, config, work_kind).await?;
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))")
        .execute(&mut *transaction).await.map_err(|_| "result generation fence unavailable")?;
    Ok(transaction)
}

async fn complete(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    plane: &RuntimePlane,
    input: WorkCompletion,
) -> WorkerResult<()> {
    let mut transaction = result_roots(pool, config, &work.work_kind).await?;
    let result = async {
        let resolved = resolve_completion(&mut transaction, work, config, plane, input).await?;
        complete_in(&mut transaction, work, config, resolved).await
    }
    .await;
    match result {
        Ok(()) => transaction
            .commit()
            .await
            .map_err(|_| "completion commit failed".to_owned()),
        Err(error) => {
            let diagnostic_failed = record_result_failure("completion_failed", &error);
            if transaction.rollback().await.is_err() {
                return Err(format!(
                    "completion rollback unconfirmed: {}",
                    serde_json::json!({"primary":error,"diagnosticFailed":diagnostic_failed})
                ));
            }
            Err(error)
        }
    }
}

struct ResolvedCompletion {
    capsule_value: Option<Digest>,
    receipt: Value,
    digest_value: Digest,
    observed_at: Option<String>,
    historical: bool,
}

async fn resolve_completion(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
    config: &Config,
    plane: &RuntimePlane,
    input: WorkCompletion,
) -> WorkerResult<ResolvedCompletion> {
    let historical = matches!(&input, WorkCompletion::Historical(_));
    let (capsule_value, receipt, digest_value, observed_at) = match input {
        WorkCompletion::Current(capsule, receipt, digest) => (capsule, receipt, digest, None),
        WorkCompletion::Historical(candidate) => {
            let verified = candidate
                .verify_in(transaction, config, plane, work)
                .await?;
            let ns = verified.observed_at_ns();
            (
                Some(verified.capsule_digest().clone()),
                verified.receipt().clone(),
                verified.receipt_digest().clone(),
                Some(format!(
                    "{}.{:06} seconds",
                    ns / 1_000_000_000,
                    (ns % 1_000_000_000) / 1_000
                )),
            )
        }
    };
    Ok(ResolvedCompletion {
        capsule_value,
        receipt,
        digest_value,
        observed_at,
        historical,
    })
}

async fn complete_in(
    transaction: &mut Transaction<'_, Postgres>,
    work: &ClaimedWork,
    config: &Config,
    resolved: ResolvedCompletion,
) -> WorkerResult<()> {
    let ResolvedCompletion {
        capsule_value,
        receipt,
        digest_value,
        observed_at,
        historical,
    } = resolved;
    set_context(transaction, config).await?;
    sqlx::query("select pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))")
        .execute(&mut **transaction).await.map_err(|_| "result generation fence unavailable")?;
    let capsule_digest = capsule_value.as_ref();
    let receipt_digest = &digest_value;
    let payload =
        canonical_bytes(&receipt).map_err(|_| "result receipt encoding rejected".to_owned())?;
    let source_revision = source_revision::lock(transaction, work).await?;
    if let Some(revision) = &source_revision {
        revision.require_current()?;
    }
    if work.work_kind == "PROJECTION_VALIDATION" {
        projection_admission::assert_current(transaction, work, &receipt).await?;
    }
    let event_id: String = sqlx::query_scalar("select uuidv7()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "result event id unavailable".to_owned())?;
    let work_count = sqlx::query(
        "update control.configuration_work set state='COMPLETED',lease_owner=null,lease_until=null,reconcile_after=null,result_receipt=$1,result_receipt_digest=$2,result_event_id=$3::text::uuid,last_error_code=null,completed_at=clock_timestamp(),updated_at=clock_timestamp() where configuration_work_id=$4::text::uuid and state='LEASED' and lease_owner=$5 and (not $6::boolean or (lease_until>clock_timestamp() and execution_attempt_id=$7::text::uuid and runtime_configuration_generation_id=$8::text::uuid and runtime_target_id=$9::text::uuid and configuration_digest=$10 and attempt_count=$11))",
    )
    .bind(&receipt)
    .bind(format!("sha256:{}", receipt_digest.as_str()))
    .bind(&event_id)
    .bind(&work.work_id)
    .bind(&config.worker_id)
    .bind(historical)
    .bind(work.execution_attempt_id.as_deref())
    .bind(work.generation_id.as_deref())
    .bind(work.target_id.as_deref())
    .bind(format!("sha256:{}",work.configuration_digest.as_str()))
    .bind(work.attempt_count)
    .execute(&mut **transaction)
    .await
    .map_err(|_| "work completion failed".to_owned())?
    .rows_affected();
    if work_count != 1 {
        return Err("completion compare-and-set rejected".into());
    }
    let revision: i64 = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => sqlx::query_scalar(
            "update control.provider_profile p set state='QUALIFIED',revision=revision+1,updated_at=clock_timestamp() where p.provider_profile_id=$1::text::uuid and p.state='SHADOW' and p.behavior_fingerprint=$2 and exists (select 1 from control.provider_probe_observation o where o.observation_id=p.qualification_observation_id and o.provider_profile_id=p.provider_profile_id and o.participant_id=p.participant_id and o.privacy_domain_id=p.privacy_domain_id and o.state='OBSERVED' and o.input_digest=$2 and o.configuration_digest=$3 and o.observation_id::text=$4 and o.observation_digest=$5 and p.revision=o.observed_revision+1 and o.valid_until>clock_timestamp()) returning revision::bigint",
        )
        .bind(&work.resource_id)
        .bind(&work.input_digest)
        .bind(format!("sha256:{}",work.configuration_digest.as_str()))
        .bind(receipt.get("liveObservationId").and_then(Value::as_str))
        .bind(receipt.get("liveObservationDigest").and_then(Value::as_str))
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| "provider completion rejected".to_owned())?,
        "INDEXER_ADMISSION" | "PROJECTION_VALIDATION" => source_revision
            .as_ref()
            .ok_or_else(|| "source revision missing".to_owned())?
            .finish(transaction, work, true)
            .await?,
        "RUNTIME_ACTIVATION" => {
            let generation_id = work
                .generation_id
                .as_deref()
                .ok_or_else(|| "runtime generation missing".to_owned())?;
            let target_id = work
                .target_id
                .as_deref()
                .ok_or_else(|| "runtime target missing".to_owned())?;
            let generation_digest = work
                .generation_digest
                .as_ref()
                .ok_or_else(|| "runtime generation digest missing".to_owned())?;
            let xds_version_digest = work
                .xds_version_digest
                .as_ref()
                .ok_or_else(|| "runtime xds digest missing".to_owned())?;
            let capsule_digest = capsule_digest
                .ok_or_else(|| "runtime capsule digest missing".to_owned())?;
            let generation_count = sqlx::query(
                "update control.runtime_configuration_generation set state='ACTIVE',activated_at=coalesce(timestamptz 'epoch'+$2::text::interval,clock_timestamp()),revision=revision+1 where runtime_configuration_generation_id=$1::text::uuid and state='ACTIVATING'",
            )
            .bind(generation_id)
            .bind(observed_at.as_deref())
            .execute(&mut **transaction)
            .await
            .map_err(|_| "generation completion failed".to_owned())?
            .rows_affected();
            if generation_count != 1 {
                return Err("generation completion compare-and-set rejected".into());
            }
            let target_revision: i64 = sqlx::query_scalar(
                "update control.runtime_target set desired_generation_digest=$1,active_generation_digest=$1,xds_version_digest=$2,state='ACTIVE_MATCHED',observed_at=case when $7::text is null then clock_timestamp() else greatest(observed_at,timestamptz 'epoch'+$7::text::interval) end,revision=revision+1,updated_at=clock_timestamp() where runtime_target_id=$3::text::uuid and ((state='STAGING' and desired_generation_digest=$4) or ($5 and state='FAILED' and active_generation_digest=$6)) returning revision::bigint",
            )
            .bind(format!("sha256:{}", capsule_digest.as_str()))
            .bind(format!("sha256:{}", xds_version_digest.as_str()))
            .bind(target_id)
            .bind(format!("sha256:{}", generation_digest.as_str()))
            .bind(work.reconcile_only)
            .bind(
                work.predecessor_digest
                    .as_ref()
                    .map(|digest| format!("sha256:{}", digest.as_str())),
            )
            .bind(observed_at.as_deref())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| "target completion rejected".to_owned())?;
            {
                let mapped = sqlx::query(
                    "update control.policy_activation_occurrence_target set state=case phase when 'ROLLBACK' then 'ROLLED_BACK' else 'ACTIVE_MATCHED' end,observed_generation_digest=$1,activation_receipt_digest=$2,updated_at=clock_timestamp() where participant_id=$3::text::uuid and privacy_domain_id=$4::text::uuid and configuration_work_id=$5::text::uuid and state in ('STAGING','WRITE_AMBIGUITY') returning activation_occurrence_id::text,phase",
                )
                .bind(format!("sha256:{}", capsule_digest.as_str()))
                .bind(format!("sha256:{}", receipt_digest.as_str()))
                .bind(&work.participant_id)
                .bind(&work.privacy_domain_id)
                .bind(&work.work_id)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|_| "activation occurrence target completion rejected".to_owned())?;
                if let Some(mapped) = mapped {
                    let occurrence_id: String = mapped
                        .try_get("activation_occurrence_id")
                        .map_err(|_| "activation occurrence id invalid".to_owned())?;
                    let phase: String = mapped
                        .try_get("phase")
                        .map_err(|_| "activation occurrence phase invalid".to_owned())?;
                    let aggregate = sqlx::query(
                        "with counts as (select count(*)::bigint total,count(*) filter (where state in ('ACTIVE_MATCHED','ROLLED_BACK'))::bigint matched,count(*) filter (where state='FAILED')::bigint failed,count(*) filter (where state='WRITE_AMBIGUITY')::bigint ambiguous from control.policy_activation_occurrence_target where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and activation_occurrence_id=$3::text::uuid and phase=$4), changed as (update control.policy_activation_occurrence occurrence set matched_target_count=counts.matched,state=case when counts.matched=counts.total then case $4 when 'ROLLBACK' then 'ROLLED_BACK' else 'ACTIVE_MATCHED' end when counts.matched>0 or counts.ambiguous>0 then 'PARTIAL' when counts.failed=counts.total then 'FAILED' when $4='ROLLBACK' then 'ROLLING_BACK' else 'STAGING' end,activated_at=case when $4='FORWARD' and counts.matched=counts.total then clock_timestamp() else occurrence.activated_at end,rolled_back_at=case when $4='ROLLBACK' and counts.matched=counts.total then clock_timestamp() else occurrence.rolled_back_at end,revision=revision+1,updated_at=clock_timestamp() from counts where occurrence.participant_id=$1::text::uuid and occurrence.privacy_domain_id=$2::text::uuid and occurrence.activation_occurrence_id=$3::text::uuid returning occurrence.policy_generation_id::text,occurrence.release_bundle_id::text,occurrence.state,occurrence.target_generation_digest) select * from changed",
                    )
                    .bind(&work.participant_id)
                    .bind(&work.privacy_domain_id)
                    .bind(&occurrence_id)
                    .bind(&phase)
                    .fetch_one(&mut **transaction)
                    .await
                    .map_err(|_| "activation occurrence aggregation rejected".to_owned())?;
                    let aggregate_state: String = aggregate
                        .try_get("state")
                        .map_err(|_| "activation occurrence state invalid".to_owned())?;
                    if phase == "FORWARD" && aggregate_state == "ACTIVE_MATCHED" {
                        let policy_generation_id: String = aggregate
                            .try_get("policy_generation_id")
                            .map_err(|_| "policy generation id invalid".to_owned())?;
                        let release_bundle_id: String = aggregate
                            .try_get("release_bundle_id")
                            .map_err(|_| "release bundle id invalid".to_owned())?;
                        let target_generation_digest: Vec<u8> = aggregate
                            .try_get("target_generation_digest")
                            .map_err(|_| "target generation digest invalid".to_owned())?;
                        if !historical {
                        sqlx::query(
                            "update control.policy_generation set state='RETIRED',active=false where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and active=true and policy_generation_id<>$3::text::uuid and scope_digest=(select scope_digest from control.policy_generation where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_generation_id=$3::text::uuid)",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&policy_generation_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "prior policy retirement rejected".to_owned())?;
                        }
                        let activated_generation = sqlx::query(
                            "update control.policy_generation set state='ACTIVE',active=true where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_generation_id=$3::text::uuid and generation_digest=$4 and (state='PREPARED' or (state='ACTIVE' and active=true))",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&policy_generation_id)
                        .bind(&target_generation_digest)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "policy generation activation rejected".to_owned())?
                        .rows_affected();
                        if activated_generation != 1 {
                            return Err("policy generation activation compare-and-set rejected".into());
                        }
                        let activated_occurrence = sqlx::query(
                            "update control.policy_activation set state='ACTIVE',receipt_digest=sha256(convert_to((select string_agg(activation_receipt_digest,',' order by runtime_target_id) from control.policy_activation_occurrence_target where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and activation_occurrence_id=$3::text::uuid and phase='FORWARD'),'UTF8')),activated_at=clock_timestamp(),row_version=row_version+1 where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_activation_id=$3::text::uuid and state='PREPARED'",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&occurrence_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "policy activation completion rejected".to_owned())?
                        .rows_affected();
                        if activated_occurrence != 1 {
                            return Err("policy activation completion compare-and-set rejected".into());
                        }
                        let activated_release = sqlx::query(
                            "update control.policy_release_bundle set state='ACTIVE',revision=revision+1,updated_at=clock_timestamp() where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and release_bundle_id=$3::text::uuid and state in ('PUBLISHED','STAGED','ACTIVE')",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&release_bundle_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "release activation completion rejected".to_owned())?
                        .rows_affected();
                        if activated_release != 1 {
                            return Err("release activation completion compare-and-set rejected".into());
                        }
                    } else if phase == "ROLLBACK" && aggregate_state == "ROLLED_BACK" {
                        let policy_generation_id: String = aggregate
                            .try_get("policy_generation_id")
                            .map_err(|_| "policy generation id invalid".to_owned())?;
                        let release_bundle_id: String = aggregate
                            .try_get("release_bundle_id")
                            .map_err(|_| "release bundle id invalid".to_owned())?;
                        let prior_generation_id: String = sqlx::query_scalar(
                            "select prior.policy_generation_id::text from control.policy_activation activation join control.policy_generation current_generation on current_generation.participant_id=activation.participant_id and current_generation.privacy_domain_id=activation.privacy_domain_id and current_generation.policy_generation_id=activation.policy_generation_id join control.policy_generation prior on prior.participant_id=activation.participant_id and prior.privacy_domain_id=activation.privacy_domain_id and prior.scope_digest=current_generation.scope_digest and prior.generation_digest=activation.prior_generation_digest where activation.participant_id=$1::text::uuid and activation.privacy_domain_id=$2::text::uuid and activation.policy_activation_id=$3::text::uuid and activation.state='ACTIVE' and current_generation.policy_generation_id=$4::text::uuid for update of activation,current_generation,prior",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&occurrence_id)
                        .bind(&policy_generation_id)
                        .fetch_one(&mut **transaction)
                        .await
                        .map_err(|_| "rollback predecessor policy unavailable".to_owned())?;
                        let retired_current = sqlx::query(
                            "update control.policy_generation set state='RETIRED',active=false where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_generation_id=$3::text::uuid and state='ACTIVE' and active=true",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&policy_generation_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "rollback current policy retirement rejected".to_owned())?
                        .rows_affected();
                        if retired_current != 1 {
                            return Err("rollback current policy retirement compare-and-set rejected".into());
                        }
                        let activated_prior = sqlx::query(
                            "update control.policy_generation set state='ACTIVE',active=true where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_generation_id=$3::text::uuid and state='RETIRED' and active=false",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&prior_generation_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "rollback predecessor policy activation rejected".to_owned())?
                        .rows_affected();
                        if activated_prior != 1 {
                            return Err("rollback predecessor activation compare-and-set rejected".into());
                        }
                        let retired_activation = sqlx::query(
                            "update control.policy_activation set state='RETIRED',retired_at=clock_timestamp(),row_version=row_version+1 where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and policy_activation_id=$3::text::uuid and state='ACTIVE'",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&occurrence_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "rollback activation retirement rejected".to_owned())?
                        .rows_affected();
                        if retired_activation != 1 {
                            return Err("rollback activation retirement compare-and-set rejected".into());
                        }
                        let rolled_back_release = sqlx::query(
                            "update control.policy_release_bundle set state='ROLLED_BACK',revision=revision+1,updated_at=clock_timestamp() where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and release_bundle_id=$3::text::uuid and state='ACTIVE'",
                        )
                        .bind(&work.participant_id)
                        .bind(&work.privacy_domain_id)
                        .bind(&release_bundle_id)
                        .execute(&mut **transaction)
                        .await
                        .map_err(|_| "release rollback completion rejected".to_owned())?
                        .rows_affected();
                        if rolled_back_release != 1 {
                            return Err("release rollback completion compare-and-set rejected".into());
                        }
                    }
                }
            }
            target_revision
        }
        _ => return Err("unsupported work completion".into()),
    };
    let event_type = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => "provider-profile.qualified.v1",
        "INDEXER_ADMISSION" => "indexer-profile.qualified.v1",
        "PROJECTION_VALIDATION" => "projection-plan.validated.v1",
        "RUNTIME_ACTIVATION" => "runtime-target.activated.v1",
        _ => return Err("unsupported work result event".into()),
    };
    let aggregate_type = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => "provider-profile",
        "INDEXER_ADMISSION" => "indexer-profile",
        "PROJECTION_VALIDATION" => "projection-plan",
        "RUNTIME_ACTIVATION" => "runtime-targets",
        _ => return Err("unsupported work result aggregate".into()),
    };
    append_result_event(
        transaction,
        work,
        &event_id,
        event_type,
        aggregate_type,
        &payload,
        receipt_digest,
    )
    .await?;
    update_operation_result(transaction, work, "SUCCEEDED", "SUCCESS", revision).await?;
    Ok(())
}

async fn retry_or_fail(
    pool: &PgPool,
    work: &ClaimedWork,
    config: &Config,
    dependency_superseded: bool,
    source: &openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker,
    park_expired_observation: bool,
) -> WorkerResult<bool> {
    let mut transaction = result_transaction(pool, config, &work.work_kind).await?;
    let source_revision = source_revision::lock(&mut transaction, work).await?;
    let source_superseded = source_revision
        .as_ref()
        .is_some_and(|revision| !revision.current);
    let effect_started: bool = sqlx::query_scalar(
        "select execution_started_at is not null from control.configuration_work where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 for update",
    )
    .bind(&work.work_id)
    .bind(&config.worker_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| "failure disposition work unavailable".to_owned())?;
    let no_effect = if effect_started && work.work_kind == "RUNTIME_ACTIVATION" {
        retained_target::no_effect(&mut transaction, config, work, source).await?
    } else {
        None
    };
    if effect_started && no_effect.is_none() {
        let target_id = work
            .target_id
            .as_deref()
            .ok_or_else(|| "runtime target missing".to_owned())?;
        let changed = sqlx::query(
            "update control.configuration_work set state='RECONCILING',lease_owner=null,lease_until=null,reconcile_after=case when $3 then 'infinity'::timestamptz else clock_timestamp()+interval '5 seconds' end,last_error_code='PC-RUNTIME-3002',updated_at=clock_timestamp() where configuration_work_id=$1::text::uuid and state='LEASED' and lease_owner=$2 and execution_started_at is not null and (not $3 or exists(select 1 from control.runtime_activation_observation o where o.configuration_work_id=control.configuration_work.configuration_work_id and o.execution_attempt_id=control.configuration_work.execution_attempt_id and o.runtime_target_id=control.configuration_work.runtime_target_id))",
        )
        .bind(&work.work_id)
        .bind(&config.worker_id)
        .bind(park_expired_observation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| "ambiguity disposition failed".to_owned())?
        .rows_affected();
        if changed != 1 {
            return Err("ambiguity disposition compare-and-set rejected".into());
        }
        sqlx::query(
            "with mapped as (update control.policy_activation_occurrence_target set state='WRITE_AMBIGUITY',updated_at=clock_timestamp() where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_work_id=$3::text::uuid and state='STAGING' returning activation_occurrence_id), ids as (select distinct activation_occurrence_id from mapped) update control.policy_activation_occurrence occurrence set state='PARTIAL',revision=revision+1,updated_at=clock_timestamp() from ids where occurrence.participant_id=$1::text::uuid and occurrence.privacy_domain_id=$2::text::uuid and occurrence.activation_occurrence_id=ids.activation_occurrence_id",
        )
        .bind(&work.participant_id)
        .bind(&work.privacy_domain_id)
        .bind(&work.work_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| "activation occurrence ambiguity disposition failed".to_owned())?;
        let revision: i64 = sqlx::query_scalar(
            "select revision::bigint from control.runtime_target where runtime_target_id=$1::text::uuid",
        )
        .bind(target_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| "runtime target truth unavailable".to_owned())?;
        update_operation_result(
            &mut transaction,
            work,
            "WRITE_AMBIGUITY",
            "WRITE_AMBIGUITY",
            revision,
        )
        .await?;
        return transaction
            .commit()
            .await
            .map(|_| false)
            .map_err(|_| "ambiguity disposition commit failed".to_owned());
    }
    let terminal = dependency_superseded
        || source_superseded
        || no_effect.is_some()
        || work.attempt_count >= 3;
    let error_code = if dependency_superseded || source_superseded {
        "PC-DATA-6007"
    } else if work.work_kind == "RUNTIME_ACTIVATION" {
        "PC-RUNTIME-3001"
    } else {
        "PC-FACT-4001"
    };
    if !terminal {
        let changed = sqlx::query(
            "update control.configuration_work set state='PENDING',lease_owner=null,lease_until=null,last_error_code=$1,updated_at=clock_timestamp() where configuration_work_id=$2::text::uuid and state='LEASED' and lease_owner=$3",
        )
        .bind(error_code)
        .bind(&work.work_id)
        .bind(&config.worker_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| "retry disposition failed".to_owned())?
        .rows_affected();
        if changed != 1 {
            return Err("retry compare-and-set rejected".into());
        }
        return transaction
            .commit()
            .await
            .map(|_| false)
            .map_err(|_| "retry commit failed".to_owned());
    }

    let mut receipt = serde_json::json!({
        "errorCode": error_code,
        "resourceId": work.resource_id,
        "terminal": true,
        "workKind": work.work_kind,
    });
    if let Some(proof) = &no_effect {
        receipt["custodyObservation"] = proof.evidence.clone();
    }
    let payload =
        canonical_bytes(&receipt).map_err(|_| "failure receipt encoding rejected".to_owned())?;
    let receipt_digest = Digest::of(&payload);
    let event_id: String = sqlx::query_scalar("select uuidv7()::text")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| "failure event id unavailable".to_owned())?;
    let changed = sqlx::query(
        "update control.configuration_work set state='FAILED',lease_owner=null,lease_until=null,result_receipt=$1,result_receipt_digest=$2,result_event_id=$3::text::uuid,last_error_code=$4,completed_at=clock_timestamp(),updated_at=clock_timestamp() where configuration_work_id=$5::text::uuid and state='LEASED' and lease_owner=$6",
    )
    .bind(&receipt)
    .bind(format!("sha256:{}", receipt_digest.as_str()))
    .bind(&event_id)
    .bind(error_code)
    .bind(&work.work_id)
    .bind(&config.worker_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| "failure disposition failed".to_owned())?
    .rows_affected();
    if changed != 1 {
        return Err("failure compare-and-set rejected".into());
    }

    let revision: i64 = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => sqlx::query_scalar(
            "update control.provider_profile set state='QUARANTINED',revision=revision+1,updated_at=clock_timestamp() where provider_profile_id=$1::text::uuid and state='SHADOW' returning revision::bigint",
        )
        .bind(&work.resource_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| "provider failure disposition rejected".to_owned())?,
        "INDEXER_ADMISSION" | "PROJECTION_VALIDATION" => source_revision
            .as_ref()
            .ok_or_else(|| "source revision missing".to_owned())?
            .finish(&mut transaction, work, false)
            .await?,
        "RUNTIME_ACTIVATION" => {
            let generation_id = work
                .generation_id
                .as_deref()
                .ok_or_else(|| "runtime generation missing".to_owned())?;
            let target_id = work
                .target_id
                .as_deref()
                .ok_or_else(|| "runtime target missing".to_owned())?;
            let generation_count = sqlx::query(
                "update control.runtime_configuration_generation set state='FAILED',revision=revision+1 where runtime_configuration_generation_id=$1::text::uuid and state='ACTIVATING'",
            )
            .bind(generation_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| "generation failure disposition failed".to_owned())?
            .rows_affected();
            if generation_count != 1 {
                return Err("generation failure compare-and-set rejected".into());
            }
            let target_revision: i64 = sqlx::query_scalar(
                "update control.runtime_target set state='FAILED',revision=revision+1,updated_at=clock_timestamp() where runtime_target_id=$1::text::uuid and state='STAGING' returning revision::bigint",
            )
            .bind(target_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "target failure disposition rejected".to_owned())?;
            sqlx::query(
                "with mapped as (update control.policy_activation_occurrence_target set state='FAILED',updated_at=clock_timestamp() where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and configuration_work_id=$3::text::uuid and state in ('STAGING','WRITE_AMBIGUITY') returning activation_occurrence_id,phase), counts as (select target.activation_occurrence_id,target.phase,count(*)::bigint total,count(*) filter (where target.state in ('ACTIVE_MATCHED','ROLLED_BACK'))::bigint matched,count(*) filter (where target.state='FAILED' or target.configuration_work_id=$3::text::uuid)::bigint failed from control.policy_activation_occurrence_target target join mapped on mapped.activation_occurrence_id=target.activation_occurrence_id and mapped.phase=target.phase where target.participant_id=$1::text::uuid and target.privacy_domain_id=$2::text::uuid group by target.activation_occurrence_id,target.phase) update control.policy_activation_occurrence occurrence set matched_target_count=counts.matched,state=case when counts.matched>0 then 'PARTIAL' when counts.failed=counts.total then 'FAILED' when counts.phase='ROLLBACK' then 'ROLLING_BACK' else 'STAGING' end,revision=revision+1,updated_at=clock_timestamp() from counts where occurrence.participant_id=$1::text::uuid and occurrence.privacy_domain_id=$2::text::uuid and occurrence.activation_occurrence_id=counts.activation_occurrence_id",
            )
            .bind(&work.participant_id)
            .bind(&work.privacy_domain_id)
            .bind(&work.work_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| "activation occurrence failure aggregation rejected".to_owned())?;
            target_revision
        }
        _ => return Err("unsupported work failure".into()),
    };
    let (event_type, aggregate_type) = match work.work_kind.as_str() {
        "PROVIDER_QUALIFICATION" => (
            "provider-profile.qualification-failed.v1",
            "provider-profile",
        ),
        "INDEXER_ADMISSION" => ("indexer-profile.admission-failed.v1", "indexer-profile"),
        "PROJECTION_VALIDATION" => ("projection-plan.validation-failed.v1", "projection-plan"),
        "RUNTIME_ACTIVATION" => ("runtime-target.activation-failed.v1", "runtime-targets"),
        _ => return Err("unsupported work failure event".into()),
    };
    append_result_event(
        &mut transaction,
        work,
        &event_id,
        event_type,
        aggregate_type,
        &payload,
        &receipt_digest,
    )
    .await?;
    update_operation_result(&mut transaction, work, "FAILED", "FAILED", revision).await?;
    transaction
        .commit()
        .await
        .map(|_| !effect_started && work.work_kind == "RUNTIME_ACTIVATION")
        .map_err(|_| "failure commit failed".to_owned())
}

async fn ready(pool: &PgPool) -> WorkerResult<()> {
    let present: Option<String> =
        sqlx::query_scalar("select to_regclass('control.configuration_work')::text")
            .fetch_one(pool)
            .await
            .map_err(|_| "readiness query failed".to_owned())?;
    present
        .map(|_| ())
        .ok_or_else(|| "work table unavailable".to_owned())
}

// Host installation needs only its own initial-trust inputs. In particular it
// must not require mounting runtime signing, Fact or transport credentials.
async fn install_source_custody() -> WorkerResult<()> {
    if required("OPENPC_LOCAL_RUNTIME")? != "1" {
        return Err("local runtime gate is closed".into());
    }
    let participant = required("CONTROL_WORKER_PARTICIPANT_ID")?;
    let privacy = required("CONTROL_WORKER_PRIVACY_DOMAIN_ID")?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&required("CONTROL_WORKER_DATABASE_HOST")?)
                .port(
                    required("CONTROL_WORKER_DATABASE_PORT")?
                        .parse()
                        .map_err(|_| "invalid database port")?,
                )
                .database(&required("CONTROL_WORKER_DATABASE_NAME")?)
                .username(&required("CONTROL_WORKER_DATABASE_USER")?)
                .password(&read_secret(&required(
                    "CONTROL_WORKER_DATABASE_PASSWORD_FILE",
                )?)?),
        )
        .await
        .map_err(|_| "source installation database unavailable")?;
    ready(&pool).await?;
    let inputs = openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource::from_environment()?;
    openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::install_from_environment(
        &pool, &participant, &privacy, inputs.as_ref().map(|source| source.path()),
    ).await.map_err(|_| "runtime source initial installation unavailable")?;
    let role = openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::installation_database_role(&participant, &privacy)
        .map_err(|_| "runtime source installation identity unavailable")?;
    pool.close().await;
    println!(
        "RUNTIME_SOURCE_CUSTODY|INSTALLED|database_role={role}|coverage=UNPROVEN|serving_authority=NONE"
    );
    Ok(())
}

/// Deployment preparation only: typed configuration without database writes or runtime authority.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceConfigurationRequest {
    participant_id: String,
    privacy_domain_id: String,
    workload_id: String,
    chain_id: String,
    providers: Vec<ResourceProviderInput>,
    #[serde(default)]
    indexers: Vec<ResourceIndexerInput>,
    #[serde(default)]
    projections: Vec<ResourceProjectionInput>,
    #[serde(default)]
    assets: Vec<pc_policy_core::invocation::InvocationConfigurationAssetV1>,
    #[serde(default)]
    base_configuration: Option<ResourceConfigurationBase>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceConfigurationBase {
    configuration_cbor_hex: String,
    configuration_digest: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceProviderInput {
    resource_id: String,
    #[serde(default)]
    artifact_digest: Option<String>,
    profile: pc_provider_api::ProviderProfileV1,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceIndexerInput {
    resource_id: String,
    #[serde(default)]
    artifact_digest: Option<String>,
    profile: pc_provider_api::ClientIndexerProfileV1,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceProjectionInput {
    resource_id: String,
    indexer_resource_id: String,
    #[serde(default)]
    artifact_digest: Option<String>,
    plan: pc_provider_api::ProjectionPlanV1,
}

fn encode_resource_configuration(path: &Path) -> WorkerResult<serde_json::Value> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "resource configuration source unavailable")?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "resource configuration source unreadable")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("resource configuration source oversized".into());
    }
    encode_resource_configuration_document(&bytes)
}

fn encode_resource_configuration_document(bytes: &[u8]) -> WorkerResult<serde_json::Value> {
    use pc_policy_core::invocation::{
        ActiveInvocationConfigurationV1, ConfigurationArtifactV1, InvocationConfigurationScope,
        active_invocation_workload,
    };
    let input: ResourceConfigurationRequest =
        serde_json::from_slice(bytes).map_err(|_| "resource configuration input rejected")?;
    let valid_id = |value: &str| {
        uuid::Uuid::parse_str(value).is_ok_and(|id| {
            id.to_string() == value
                && id.get_version_num() == 7
                && id.get_variant() == uuid::Variant::RFC4122
        })
    };
    if ![&input.participant_id, &input.privacy_domain_id]
        .iter()
        .all(|id| valid_id(id))
        || input
            .workload_id
            .strip_prefix("urn:openpc:workload:")
            .is_none_or(|id| !valid_id(id))
        || input.providers.is_empty()
        || input.providers.len() > 16
    {
        return Err("resource configuration scope rejected".into());
    }
    if input.indexers.len() > 16 || input.projections.len() > 16 || input.assets.len() > 1024 {
        return Err("resource configuration bounds rejected".into());
    }
    // Adding a provider must not discard another network's installed resources.
    // The base is data for preparation; the source owner still admits each
    // public resource and records a new import before it can be used.
    let base = input
        .base_configuration
        .map(|base| {
            if base.configuration_cbor_hex.len() > 8 * 1024 * 1024 {
                return Err("resource configuration base oversized".to_owned());
            }
            let bytes = parse_hex_bytes(&base.configuration_cbor_hex)
                .map_err(|_| "resource configuration base encoding rejected".to_owned())?;
            let digest = base
                .configuration_digest
                .strip_prefix("sha256:")
                .ok_or("resource configuration base digest rejected")?;
            let digest = Digest::parse(digest)
                .map_err(|_| "resource configuration base digest rejected".to_owned())?;
            let configuration = decode_active_invocation_configuration(&bytes, &digest)
                .map_err(|_| "resource configuration base rejected".to_owned())?;
            let workload = active_invocation_workload(
                &bytes,
                &digest,
                &input.participant_id,
                &input.privacy_domain_id,
            )
            .map_err(|_| "resource configuration base scope rejected".to_owned())?;
            if workload != input.workload_id || !configuration.deployment_policies.is_empty() {
                return Err("resource configuration base scope rejected".to_owned());
            }
            Ok(configuration)
        })
        .transpose()?;
    let mut ids = BTreeSet::new();
    let mut artifacts = Vec::new();
    let mut network = None;
    for provider in input.providers {
        if !valid_id(&provider.resource_id)
            || !ids.insert(provider.resource_id.clone())
            || provider.profile.chain_id != input.chain_id
        {
            return Err("resource configuration provider binding rejected".into());
        }
        let binding = (
            provider.profile.network_id.clone(),
            provider.profile.genesis_hash.clone(),
        );
        if network
            .as_ref()
            .is_some_and(|expected| expected != &binding)
        {
            return Err("resource configuration network mismatch".into());
        }
        network = Some(binding);
        let payload = pc_provider_api::encode_provider_profile_pc_cbor(&provider.profile)
            .map_err(|_| "resource configuration profile rejected")?;
        let digest = Digest::of(&payload);
        if provider
            .artifact_digest
            .as_ref()
            .is_some_and(|expected| expected != &format!("sha256:{}", digest.as_str()))
        {
            return Err("resource configuration digest mismatch".into());
        }
        qualify_provider_profile(&payload, &format!("sha256:{}", digest.as_str()))
            .map_err(|_| "resource configuration profile admission rejected")?;
        artifacts.push(ConfigurationArtifactV1 {
            artifact_id: provider.resource_id,
            artifact_kind: ConfigurationArtifactKind::ProviderProfile,
            artifact_digest: digest,
            payload_cbor: payload,
        });
    }
    let (network_id, genesis_hash) = network.ok_or("resource configuration provider missing")?;
    let mut indexer_profiles = BTreeMap::new();
    for indexer in input.indexers {
        if !valid_id(&indexer.resource_id)
            || !ids.insert(indexer.resource_id.clone())
            || indexer.profile.chain_id != input.chain_id
            || indexer.profile.network_id != network_id
            || indexer.profile.genesis_hash.trim_start_matches("sha256:")
                != genesis_hash.trim_start_matches("sha256:")
            || indexer.profile.workload_binding != input.workload_id
        {
            return Err("resource configuration indexer binding rejected".into());
        }
        let payload = pc_provider_api::encode_client_indexer_profile_pc_cbor(&indexer.profile)
            .map_err(|_| "resource configuration indexer encoding rejected")?;
        let computed = format!("sha256:{}", Digest::of(&payload).as_str());
        if indexer
            .artifact_digest
            .as_ref()
            .is_some_and(|expected| expected != &computed)
        {
            return Err("resource configuration indexer digest mismatch".into());
        }
        admit_scoped_client_indexer_profile(
            &payload,
            &computed,
            &input.participant_id,
            &input.privacy_domain_id,
        )
        .map_err(|_| "resource configuration indexer scope or digest rejected")?;
        indexer_profiles.insert(indexer.resource_id.clone(), payload.clone());
        artifacts.push(ConfigurationArtifactV1 {
            artifact_id: indexer.resource_id,
            artifact_kind: ConfigurationArtifactKind::ClientIndexerProfile,
            artifact_digest: Digest::of(&payload),
            payload_cbor: payload,
        });
    }
    for projection in input.projections {
        if !valid_id(&projection.resource_id) || !ids.insert(projection.resource_id.clone()) {
            return Err("resource configuration projection identity rejected".into());
        }
        let profile = indexer_profiles
            .get(&projection.indexer_resource_id)
            .ok_or("resource configuration projection source missing")?;
        let payload = pc_provider_api::encode_projection_plan_pc_cbor(&projection.plan)
            .map_err(|_| "resource configuration projection encoding rejected")?;
        let computed = format!("sha256:{}", Digest::of(&payload).as_str());
        if projection
            .artifact_digest
            .as_ref()
            .is_some_and(|expected| expected != &computed)
        {
            return Err("resource configuration projection digest mismatch".into());
        }
        validate_projection_admission(profile, &payload, &computed)
            .map_err(|_| "resource configuration projection scope or digest rejected")?;
        artifacts.push(ConfigurationArtifactV1 {
            artifact_id: projection.resource_id,
            artifact_kind: ConfigurationArtifactKind::ProjectionPlan,
            artifact_digest: Digest::of(&payload),
            payload_cbor: payload,
        });
    }
    for asset in &input.assets {
        if !valid_id(&asset.asset_id)
            || asset.tenant_id != input.participant_id
            || asset.privacy_domain_id != input.privacy_domain_id
            || asset.workload_id != input.workload_id
            || asset.chain_id != input.chain_id
            || asset.network_id != network_id
            || asset.genesis_digest.as_str() != genesis_hash.trim_start_matches("sha256:")
            || !asset.runtime_binding_id.as_deref().is_some_and(valid_id)
        {
            return Err("resource configuration contract binding rejected".into());
        }
    }
    artifacts.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
    if let Some(base) = &base
        && (artifacts.iter().any(|added| {
            base.resource_artifacts
                .iter()
                .any(|existing| existing.artifact_id == added.artifact_id)
        }) || input.assets.iter().any(|added| {
            base.assets.iter().any(|existing| {
                existing.asset_id == added.asset_id
                    || (added.runtime_binding_id.is_some()
                        && existing.runtime_binding_id == added.runtime_binding_id)
            })
        }))
    {
        return Err("resource configuration base resource conflict".into());
    }
    let mut configuration = base.unwrap_or_else(|| ActiveInvocationConfigurationV1 {
        schema_version: "1.0".into(),
        workload_scope: Some(InvocationConfigurationScope {
            participant_id: input.participant_id.clone(),
            privacy_domain_id: input.privacy_domain_id.clone(),
            workload_id: input.workload_id.clone(),
        }),
        assets: Vec::new(),
        deployment_policies: Vec::new(),
        visibility_resources: Vec::new(),
        resource_artifacts: Vec::new(),
    });
    configuration.assets.extend(input.assets);
    configuration.resource_artifacts.extend(artifacts);
    let descriptors = configuration
        .resource_artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "resourceId": artifact.artifact_id, "kind": artifact.artifact_kind,
                "artifactDigest": format!("sha256:{}", artifact.artifact_digest.as_str()),
            })
        })
        .collect::<Vec<_>>();
    let bytes = encode_active_invocation_configuration(&configuration)
        .map_err(|_| "resource configuration encoding rejected")?;
    let digest = Digest::of(&bytes);
    active_invocation_workload(
        &bytes,
        &digest,
        &input.participant_id,
        &input.privacy_domain_id,
    )
    .map_err(|_| "resource configuration scope rejected")?;
    Ok(
        serde_json::json!({ "configurationCborHex": hex_bytes(&bytes),
        "configurationDigest": format!("sha256:{}", digest.as_str()), "resourceArtifacts": descriptors, "authority": "NONE" }),
    )
}

#[tokio::main]
async fn main() {
    // Closed owner names locate startup/loop failures without exposing provider
    // errors, SQL, credentials or retained business payloads.
    let mut phase = "command";
    let result: WorkerResult<()> = async {
        let arguments: Vec<String> = env::args().collect();
        if arguments.get(1).map(String::as_str)==Some("handover-expired-credential-denial") {
            phase="expired_credential_denial_handover";
            if arguments.len()!=4 {return Err("credential denial handover requires sealed intent and digest".into());}
            return expired_activation::run_credential_handover(Path::new(&arguments[2]),&arguments[3]).await;
        }
        if arguments.get(1).map(String::as_str)==Some("handover-expired-denial") {
            phase="expired_denial_handover";
            if arguments.len()!=4 {return Err("expired handover requires sealed intent and digest".into());}
            return expired_activation::run_handover(Path::new(&arguments[2]),&arguments[3]).await;
        }
        if arguments.get(1).map(String::as_str) == Some("deny-expired-activation") {
            phase="expired_activation_denial";
            if arguments.len()!=4 {return Err("expired denial requires sealed intent and digest".into());}
            return expired_activation::run(Path::new(&arguments[2]),&arguments[3]).await;
        }
        if arguments.get(1).map(String::as_str) == Some("complete-original-activation") {
            phase = "original_activation_maintenance";
            if arguments.len() != 4 {
                return Err("original activation maintenance requires a sealed intent file and digest".into());
            }
            return activation_maintenance::run(Path::new(&arguments[2]), &arguments[3]).await;
        }

        if arguments.get(1).map(String::as_str) == Some("encode-resource-configuration") {
            phase = "resource_configuration";
            if arguments.len() != 3 { return Err("resource configuration requires one input file".into()); }
            println!("{}", encode_resource_configuration(Path::new(&arguments[2]))?);
            return Ok(());
        }

        if arguments.get(1).map(String::as_str) == Some("source-custody-configuration") {
            if arguments.len() != 3 { return Err("source configuration requires one public input file".into()); }
            let value=openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::render_configuration(Path::new(&arguments[2]))
                .map_err(|_| "source configuration input rejected")?;
            println!("{}",serde_json::to_string(&value).map_err(|_| "source configuration encoding rejected")?);
            return Ok(());
        }
        if arguments.get(1).map(String::as_str) == Some("source-custody-install") {
            if arguments.len() != 2 { return Err("source custody installation takes no overrides".into()); }
            phase = "runtime_source_installation";
            return install_source_custody().await;
        }
        if arguments.get(1).map(String::as_str) == Some("runtime-evidence-snapshot") {
            if arguments.len() != 3 { return Err("evidence snapshot requires a stream".into()); }
            return openpc_fleet_controller::runtime_target_service::evidence_snapshot_from_environment(&arguments[2]);
        }
        if arguments.get(1).map(String::as_str) == Some("runtime-target-ready") {
            if arguments.len() != 2 { return Err("target readiness accepts no arguments".into()); }
            return openpc_fleet_controller::runtime_target_service::ready_from_environment();
        }
        if arguments.get(1).map(String::as_str) == Some("runtime-target") {
            if arguments.len() != 2 {
                return Err("runtime target accepts no arguments".into());
            }
            let result =
                openpc_fleet_controller::runtime_target_service::run_from_environment().await;
            if let Err(reason) = &result {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "level": "error",
                        "event": "runtime_target_stopped",
                        "reason": reason,
                    })
                );
            }
            return result;
        }
        if arguments.get(1).map(String::as_str) == Some("runtime-public-keys") {
            if arguments.len() != 3 {
                return Err("runtime public keys require one signing secret file".into());
            }
            let key = read_key(&arguments[2])?;
            let bootstrap = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, key)
                .map_err(|_| "runtime bootstrap public key unavailable")?
                .verifier()
                .sec1_bytes();
            let runtime = RuntimeWireSigner::from_secret_bytes(key)
                .map_err(|_| "runtime wire public key unavailable")?
                .verifier()
                .public_key_bytes();
            println!(
                "{}",
                serde_json::json!({
                    "bootstrapP256Sec1Hex": hex_bytes(&bootstrap),
                    "runtimeEd25519Hex": hex_bytes(&runtime),
                })
            );
            return Ok(());
        }
        if arguments.get(1).map(String::as_str) == Some("local-indexer-input") {
            if arguments.len()!=9 && !(arguments.len()==10 && arguments[9]=="--state-candidates") { return Err("local indexer fixture arguments rejected".into()); }
            let configuration=fs::read(&arguments[2]).map_err(|_| "local indexer configuration unavailable")?;
            let acquisition=fs::read(&arguments[6]).map_err(|_| "local indexer acquisition unavailable")?;
            if configuration.len()>4*1024*1024 || acquisition.len()>131_072 {
                return Err("local indexer input oversized".into());
            }
            let acquisition=serde_json::from_slice(&acquisition).map_err(|_| "local indexer acquisition invalid")?;
            let generation=arguments[7].parse().map_err(|_| "local indexer generation invalid")?;
            let confirmations=arguments[8].parse().map_err(|_| "local indexer finality invalid")?;
            let mut fixture=openpc_fleet_controller::local_fixture::indexer::acquisition_input(
                &configuration,&arguments[3],&arguments[4],&arguments[5],acquisition,openpc_fleet_controller::local_fixture::indexer::AcquisitionFixtureOptions { generation, confirmation_count: confirmations, state_candidates: arguments.len()==10 },
            )?;
            if let Some(path)=env::var_os("OPENPC_LOCAL_INDEXER_CONTRACT_FILE") {
                if !Path::new(&path).is_absolute() {return Err("source contract fixture path rejected".into());}
                let bytes=fs::read(path).map_err(|_| "source contract fixture unavailable")?;
                if bytes.len()>262_144 {return Err("source contract fixture oversized".into());}
                let record=serde_json::from_slice(&bytes).map_err(|_| "source contract fixture rejected")?;
                openpc_fleet_controller::local_fixture::indexer::bind_state_contract(&mut fixture,&record)?;
            }
            println!("{}",serde_json::to_string(&fixture).map_err(|_| "local indexer input encoding rejected")?);
            return Ok(());
        }
        if arguments.get(1).map(String::as_str) == Some("local-fixture") {
            if arguments.len() != 6 && arguments.len() != 7 {
                return Err(
                    "local fixture requires provider, indexer, projection, and workload identifiers, with an optional policy version".into(),
                );
            }
            let provider_id = optional_fixture_identifier(&arguments[2]);
            let indexer_id = optional_fixture_identifier(&arguments[3]);
            let projection_id = optional_fixture_identifier(&arguments[4]);
            let workload_id = optional_fixture_identifier(&arguments[5]);
            let profile = if let Some(path)=env::var_os("OPENPC_LOCAL_PROVIDER_PROFILE_FILE") {
                let bytes=fs::read(path).map_err(|_| "external fixture profile unavailable")?;
                if bytes.len()>65536 {return Err("external fixture profile oversized".into())}
                Some(serde_json::from_slice(&bytes).map_err(|_| "external fixture profile invalid")?)
            } else { None };
            let scope: (String, String) = match env::var("OPENPC_LOCAL_FIXTURE_SCOPE") {
                Ok(value) if value.len() <= 256 => serde_json::from_str(&value).map_err(|_| "local fixture scope invalid")?,
                Err(env::VarError::NotPresent) => ("018f0000-0000-7000-8000-000000000101".into(), "018f0000-0000-7000-8000-000000000201".into()),
                _ => return Err("local fixture scope invalid".into()),
            };
            let fixture = build_local_configuration_fixture_in_scope(
                provider_id, indexer_id, projection_id, workload_id,
                arguments.get(6).map_or("1.0.0", String::as_str), profile.as_ref(), (&scope.0, &scope.1),
            )?;
            let fixture = match env::var("OPENPC_LOCAL_CIGL_SETTINGS_CBOR_HEX") {
                Ok(encoded) => {
                    if encoded.len() > 131_072 { return Err("local CIGL settings fixture oversized".into()); }
                    fixture.with_cigl_settings(parse_hex_bytes(&encoded)?)?
                },
                Err(env::VarError::NotPresent) => fixture,
                Err(_) => return Err("local CIGL settings fixture encoding rejected".into()),
            };
            println!(
                "{}",
                serde_json::to_string(&fixture)
                    .map_err(|_| "local fixture serialization failed".to_owned())?
            );
            return Ok(());
        }
        activation_maintenance::require_remaining_arguments(&arguments)?;
        phase = "configuration";
        let config = Config::read()?;
        phase = "control_database";
        let pool = config.connect().await?;
        phase = "database_readiness";
        ready(&pool).await?;
        if arguments.get(1).map(String::as_str) == Some("healthcheck") {
            return Ok(());
        }
        phase = "runtime_source_custody";
        let runtime_inputs = openpc_fleet_controller::runtime_configuration_input::RuntimeConfigurationInputSource::from_environment()?;
        if arguments.get(1).map(String::as_str) == Some("source-custody-restore") {
            let backup = arguments.get(2).filter(|_| arguments.len() == 3)
                .ok_or("source custody restore requires one source-journal directory")?;
            openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::restore_from_environment(
                &pool, &config.participant_id, &config.privacy_domain_id, runtime_inputs.as_ref().map(|source|source.path()), Path::new(backup),
            ).await.map_err(|_| "runtime source custody restoration unavailable")?;
            println!("RUNTIME_SOURCE_CUSTODY|RESTORED|serving_authority=NONE");
            return Ok(());
        }
        if arguments.get(1).map(String::as_str) == Some("source-custody-initialize") {
            openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::initialize_from_environment(
                &pool, &config.participant_id, &config.privacy_domain_id, runtime_inputs.as_ref().map(|source|source.path()),
            ).await.map_err(|_| "runtime source custody installation unavailable")?;
            println!("RUNTIME_SOURCE_CUSTODY|INSTALLED|serving_authority=NONE");
            return Ok(());
        }
        let mut source_custody = openpc_fleet_controller::runtime_artifact_source::RuntimeArtifactSourceWorker::from_environment(
            &pool, &config.participant_id, &config.privacy_domain_id, runtime_inputs.as_ref().map(|source|source.path()),
        ).await.map_err(|error| {
            let stage=error.stage();
            let reason=error.reason();
            eprintln!(r#"{{"level":"error","event":"runtime_source_startup_rejected","phase":"startup","stage":"{stage}","reason":"{reason}"}}"#);
            "runtime source custody unavailable"
        })?;
        let materialization = source_custody.start_materialization().await
            .map_err(|_| "runtime source materialization unavailable")?;
        phase = "fact_custody";
        let facts = disposition_restore::FactCustody::connect(&config).await?;
        let fact_admission = openpc_fleet_controller::fact_admission::FleetFactAdmissionConsumer::new(
            facts.reader().clone(),
            read_key(&required("CONTROL_WORKER_FACT_ADMISSION_KEY_FILE")?)?,
            p256::ecdsa::SigningKey::from_slice(&read_key(&required("CONTROL_WORKER_FACT_FAILURE_SIGNING_KEY_FILE")?)?).map_err(|_| "Fleet failure signing key rejected")?,
        );
        if arguments.get(1).map(String::as_str) == Some("fact-admission-once") {
            let admitted = fact_admission.tick(&pool, &config.participant_id, &config.privacy_domain_id).await?;
            println!("FLEET_FACT_ADMISSION|PASS|committed={admitted}|runtime_authority=NONE");
            return Ok(());
        }
        phase = "runtime_plane";
        let plane = RuntimePlane::start(&config, &pool, facts, source_custody.clone()).await?;
        let mut disposition_recovery = disposition_restore::Recovery::default();
        let mut platform_withdrawal = platform_scope::Withdrawal::default();
        phase = "settled_transport";
        let mut settled_restore_pending = match settled_transport::restore(&pool, &config, &plane).await {
            Ok(()) => false,
            Err(error) if error == RUNTIME_ARTIFACT_BUSY => true,
            Err(error) => return Err(error),
        };
        phase = "worker_configuration";
        let signing_worker = openpc_fleet_controller::signing_provider_worker::SigningProviderWorker::from_environment()?;
        let mut indexer_publication = openpc_fleet_controller::indexer_publication::IndexerPublicationWorker::from_environment().await?;
        let mut deployment_worker = openpc_fleet_controller::deployment_worker::DeploymentWorker::from_environment(config.fleet_key, &config.identity_runtime_public_key, config.agent_key)?;
        let probe_worker = openpc_fleet_controller::provider_probe_worker::ProviderProbeWorker::from_environment()?;
        let mut probe_task = probe_worker.map(|worker| {
            let pool=pool.clone();
            let participant=config.participant_id.clone();
            let privacy=config.privacy_domain_id.clone();
            tokio::spawn(async move {
                loop {
                    worker.tick(&pool,&participant,&privacy).await?;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                #[allow(unreachable_code)]
                Ok::<(), String>(())
            })
        });
        let mut cigl_invalidation_task = tokio::spawn(cigl_invalidation::run(
            pool.clone(), config.participant_id.clone(), config.privacy_domain_id.clone(), config.fleet_key, source_custody.clone(),
        ));
        let mut reported_idle_poll = false;
        loop {
            phase = "runtime_source_custody_ongoing";
            if materialization.as_ref().is_some_and(|server| !server.healthy()) {
                return Err("runtime source materialization stopped".into());
            }
            match source_custody.tick(&pool).await {
                Ok(()) => {}
                Err(openpc_fleet_controller::runtime_artifact_source::SourceCustodyError::Busy) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Err(_) => return Err("runtime source custody unavailable".into()),
            }
            phase = "background_tasks";
            if plane.server.is_finished() {
                return Err("ADS server stopped".into());
            }
            if cigl_invalidation_task.is_finished() {
                (&mut cigl_invalidation_task).await.map_err(|_| "CIGL invalidation task failed")??;
                return Err("CIGL invalidation task stopped".into());
            }
            if probe_task.as_ref().is_some_and(|task|task.is_finished()) {
                probe_task.take().expect("finished probe task").await
                    .map_err(|_| "provider probe task failed")??;
                return Err("provider probe task stopped".into());
            }
            disposition_recovery.tick(&pool, &config, &plane).await;
            platform_withdrawal.tick(&pool, &config, &plane).await;
            if settled_restore_pending {
                phase = "settled_transport";
                match settled_transport::restore(&pool, &config, &plane).await {
                    Ok(()) => settled_restore_pending = false,
                    Err(error) if error == RUNTIME_ARTIFACT_BUSY => {}
                    Err(error) => return Err(error),
                }
            }
            phase = "signing_provider_queue";
            signing_worker.tick(&pool, &config.participant_id, &config.privacy_domain_id).await?;
            phase = "fact_admission";
            fact_admission.tick(&pool, &config.participant_id, &config.privacy_domain_id).await?;
            if let Some(source) = &runtime_inputs {
                phase = "runtime_input";
                source.refresh_guarded(&pool, &config.participant_id, &config.privacy_domain_id, &source_custody).await?;
            }
            if let Some(worker) = &mut indexer_publication {
                phase = "indexer_publication";
                worker.tick(&pool, &config.participant_id, &config.privacy_domain_id).await?;
            }
            if let Some(worker) = &mut deployment_worker {
                phase = "deployment_worker";
                worker.tick(&pool, &config.participant_id, &config.privacy_domain_id).await?;
            }
            phase = "qualified_receipts";
            openpc_fleet_controller::qualified_receipts::consume_next(
                &pool, &config.participant_id, &config.privacy_domain_id,
            ).await?;
            phase = "qualified_lifecycle_receipts";
            openpc_fleet_controller::qualified_receipts::lifecycle::consume_next(
                &pool, &config.participant_id, &config.privacy_domain_id,
            ).await?;
            phase = "cigl_profile";
            cigl_profile::tick(&pool, &config).await?;
            phase = "configuration_claim";
            if let Some(work) = claim(&pool, &config).await? {
                phase = "configuration_execution";
                let result = if work.reconcile_only {
                    if work.work_kind != "RUNTIME_ACTIVATION" {
                        Err("non-runtime work entered reconciliation".into())
                    } else {
                        match reconcile_runtime_observation(&pool, &work, &config, &plane).await {
                            Ok(Some(completion)) => Ok(completion),
                            Ok(None) => Err("activation observation not yet available".into()),
                            Err(error) => Err(error),
                        }
                    }
                } else {
                    execute(&pool, &work, &config, &plane).await
                        .map(|(capsule, receipt, digest)| WorkCompletion::Current(capsule, receipt, digest))
                };
                match result {
                    Ok(input) => {
                        let historical = matches!(&input, WorkCompletion::Historical(_));
                        let completion = complete(
                            &pool,
                            &work,
                            &config,
                            &plane,
                            input,
                        )
                        .await;
                        match completion {
                            Err(error) if error == source_revision::SUPERSEDED => {
                                // Completion revalidates after execution. A source
                                // update in that interval rejects only this old
                                // operation, not the worker or the replacement.
                                if retry_or_fail(&pool, &work, &config, true, &source_custody, false).await? {
                                    disposition_restore::newly_failed(&config, &plane, &work).await;
                                }
                            }
                            Err(error) if historical && completion_uncertain(&error) => {
                                return Err(error);
                            }
                            Err(error) if historical && (error == openpc_fleet_controller::target_disposition::TARGET_DISPOSITION_BUSY || error == RUNTIME_ARTIFACT_BUSY) => {
                                tokio::time::sleep(Duration::from_millis(250)).await;
                            }
                            Err(_) if historical => {
                                eprintln!("{}", serde_json::json!({"event":"historical_activation_settlement_unavailable","work_id":work.work_id,"disposition":"retain_write_ambiguity"}));
                                retry_or_fail(&pool, &work, &config, false, &source_custody, true).await?;
                            }
                            result => result?,
                        }
                    }
                    Err(error) if error == RUNTIME_ARTIFACT_BUSY || error == TARGET_DISPOSITION_PENDING
                        || error == openpc_fleet_controller::target_disposition::TARGET_DISPOSITION_BUSY => {
                        // No effect began. Retain the original lease/identity;
                        // normal lease expiry retries without failure/replay.
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(error) if error == disposition_restore::EXPIRED_OBSERVED_ACTIVATION => {
                        retry_or_fail(&pool, &work, &config, false, &source_custody, true).await?;
                    }
                    Err(error) => {
                        cigl_activation::restore_unstarted(&pool, &config, &work).await?;
                        // Never log provider/database text or private inputs. These
                        // closed categories identify the owner requiring correction.
                        let boundary = match error.as_str() {
                            "policy contract references rejected" | "policy contract references missing" => "policy_contract_references",
                            "policy semantic digest rejected" | "policy semantic document rejected" => "policy_semantics",
                            "admitted contract policy rejected" | "admitted contract policy validation rejected" => "contract_policy",
                            "predecessor does not match active generation" => "predecessor_generation",
                            "RPC policy reference or method unresolved" => "rpc_policy_reference",
                            "current routing owners unavailable" => "routing_current_owners",
                            "provider route instance unsupported" => "routing_provider_instance",
                            "provider route chain unsupported" => "routing_provider_chain",
                            "provider route plan unsupported" => "routing_provider_plan",
                            "provider route retry unsupported" => "routing_provider_retry",
                            "provider route data class unsupported" => "routing_provider_data_class",
                            "provider route response schema unsupported" => "routing_provider_response_schema",
                            "provider route normalization unsupported" => "routing_provider_normalization",
                            "governed read binding unavailable" => "routing_binding_owner",
                            "governed read binding chain mismatch" | "cross-chain route publication rejected" => "routing_chain",
                            "routing publication insert rejected" => "routing_persistence",
                            "current routing publication unavailable" | "routing publication readback mismatch" => "routing_readback",
                            _ => "runtime_execution",
                        };
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "level": "warn",
                                "event": "control_work_rejected",
                                "boundary": boundary,
                                "reason": error,
                            })
                        );
                        if retry_or_fail(&pool, &work, &config, false, &source_custody, false).await? {
                            disposition_restore::newly_failed(&config, &plane, &work).await;
                        }
                    }
                }
            } else {
                if !reported_idle_poll {
                    eprintln!(r#"{{"level":"info","event":"control_worker_idle_poll"}}"#);
                    reported_idle_poll = true;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    .await;
    if let Err(error) = result {
        if phase == "resource_configuration" {
            let stage = match error.as_str() {
                "resource configuration source unavailable" => "source_unavailable",
                "resource configuration source unreadable" => "source_unreadable",
                "resource configuration source oversized" => "source_oversized",
                "resource configuration input rejected" => "input",
                "resource configuration scope rejected" => "scope",
                "resource configuration provider binding rejected" => "provider_binding",
                "resource configuration network mismatch" => "network_binding",
                "resource configuration profile rejected" => "profile_encoding",
                "resource configuration digest mismatch" => "profile_digest",
                "resource configuration profile admission rejected" => "profile_admission",
                "resource configuration encoding rejected" => "configuration_encoding",
                _ => "other",
            };
            eprintln!(
                r#"{{"level":"error","event":"resource_configuration_rejected","stage":"{stage}"}}"#
            );
        }
        // Closed diagnostic codes only: database/provider errors may contain private inputs.
        if phase == "runtime_input" {
            let stage = match error.as_str() {
                "runtime input configuration rejected" => "decode_configuration",
                "runtime input scope rejected" => "scope",
                "runtime provider input rejected" => "provider_artifact",
                "runtime indexer input rejected" => "indexer_artifact",
                "runtime projection input rejected" => "projection_artifact",
                "runtime input references rejected" => "reference_query",
                "runtime input source custody unavailable" => "source_custody",
                "runtime input original custody unavailable" => "import_custody",
                "runtime input persistence rejected" => "persist",
                "runtime input committed custody unavailable" => "commit_custody",
                "runtime artifact retirement enforcement unavailable" => "retirement_fence",
                _ => "other",
            };
            eprintln!(r#"{{"level":"error","event":"runtime_input_rejected","stage":"{stage}"}}"#);
        }
        let boundary = match error.as_str() {
            "settled ADS result unavailable" => "settled_ads_result_unavailable",
            "settled ADS result ambiguous" => "settled_ads_result_ambiguous",
            "settled ADS result field rejected" => "settled_ads_result_field_rejected",
            "settled ADS receipt digest rejected" => "settled_ads_receipt_digest_rejected",
            "settled ADS bootstrap unavailable" => "settled_ads_bootstrap_unavailable",
            "settled ADS custody rejected" => "settled_ads_custody_rejected",
            "settled ADS configuration rejected" => "settled_ads_configuration_rejected",
            "settled source ADS custody rejected" => "settled_source_ads_custody_rejected",
            "settled source generation rejected" => "settled_source_generation_rejected",
            "settled source configuration unavailable" => {
                "settled_source_configuration_unavailable"
            }
            "settled source configuration ambiguous" => "settled_source_configuration_ambiguous",
            "settled source configuration rejected" => "settled_source_configuration_rejected",
            "settled ADS installed identity rejected" => "settled_ads_installed_identity_rejected",
            "settled ADS provider unavailable" => "settled_ads_provider_unavailable",
            "settled ADS provider rejected" => "settled_ads_provider_rejected",
            "settled ADS resources rejected" => "settled_ads_resources_rejected",
            "settled ADS desired identity rejected" => "settled_ads_desired_identity_rejected",
            "settled ADS retained custody rejected" => "settled_ads_retained_custody_rejected",
            "settled ADS publication rejected" => "settled_ads_publication_rejected",
            "target bootstrap predecessor binding rejected" => {
                "target_bootstrap_predecessor_binding_rejected"
            }
            "qualified lifecycle occurrence rejected" => "lifecycle_occurrence",
            "qualified lifecycle evidence or event rejected" => "lifecycle_evidence_event",
            "qualified receipt rejected" => "qualified_receipt",
            "CIGL compilation claim unavailable" => "cigl_compilation_claim",
            "deployment result source rejected" => "deployment_result_source",
            "deployment result binding rejected" => "deployment_result_binding",
            "deployment result signature rejected" => "deployment_result_signature",
            "deployment result preparation rejected" => "deployment_result_preparation",
            "deployment result persistence rejected" => "deployment_result_persistence",
            _ => "runtime",
        };
        eprintln!(
            r#"{{"level":"error","event":"control_worker_stopped","boundary":"{boundary}","phase":"{phase}"}}"#
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn completion_uncertainty_never_enters_the_reschedule_path() {
        for error in [
            "completion commit failed",
            "result transaction begin failed",
            "completion rollback unconfirmed: {\"primary\":\"validation failed\"}",
            "result fence rollback unconfirmed: {\"primary\":\"owner busy\"}",
        ] {
            assert!(super::completion_uncertain(error));
        }
        for error in [
            "historical completion policy scope advanced",
            "target disposition owner busy",
            "validation failed",
        ] {
            assert!(!super::completion_uncertain(error));
        }
    }
    use super::*;
    use openpc_pds::{
        AbiType, ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
        ApprovalRequirement, ConfigurationArtifactV1, InvocationConfigurationAssetV1,
        InvocationPolicyAssetV1, encode_active_invocation_configuration,
        encode_active_invocation_policy_generation,
    };
    use pc_provider_api::{
        ClientIndexerFamily, ClientIndexerLifecycle, ClientIndexerProfileV1, DependencyV1,
        DesiredState, IdempotencyClass, IndexerBehaviorV1, IndexerCapability, IndexerLimitsV1,
        IndexerProtocolKind, MethodDataClass, NamedDigestV1, PartitionState, ProfileLifecycle,
        ProjectionPartitionV1, ProjectionPlanV1, ProviderLimits, ProviderProfileV1, RangeEndV1,
        RoutePlanDraftV1, SecretPurposeV1, SecretReferenceV1, SourceAuthority, SourceRangeV1,
        WorkloadIdentityV1, encode_client_indexer_profile_pc_cbor, encode_projection_plan_pc_cbor,
        encode_provider_profile_pc_cbor,
    };
    use pc_runtime_types::RequestClass;

    fn label(value: &str) -> String {
        format!("sha256:{}", Digest::of(value).as_str())
    }

    fn provider_profile() -> ProviderProfileV1 {
        ProviderProfileV1 {
            profile_id: "provider-profile-1".into(),
            profile_version: "1.0.0".into(),
            profile_digest: label("provider-profile"),
            provider_instance_id: "provider-instance-1".into(),
            provider_release_digest: label("provider-release"),
            provider_build_digest: label("provider-build"),
            configuration_digest: label("provider-configuration"),
            chain_id: "1".into(),
            genesis_hash: label("genesis"),
            network_id: "local".into(),
            tls_credential_identity: "local-provider-credential".into(),
            tls_credential_fingerprint: label("credential"),
            trust_epoch: 1,
            json_rpc_version: "2.0".into(),
            method_data_classes: vec![MethodDataClass {
                method: "eth_call".into(),
                data_class: "STATE_CALL".into(),
            }],
            request_schema_digest: label("request-schema"),
            response_schema_digest:
                openpc_runtime_agent::provider_response::call_result_response_schema_digest(),
            normalization_rule_digest:
                openpc_runtime_agent::provider_response::call_result_normalization_rule_digest(),
            limits: ProviderLimits {
                max_request_bytes: 1_024,
                max_response_bytes: 4_096,
                max_range: 100,
                max_batch: 10,
            },
            privacy_behavior_digest: label("privacy"),
            failure_behavior_digest: label("failure"),
            rate_limit_contract_digest: label("rate"),
            capability_profile_digest: label("capability"),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::IdempotentRead,
            route_plan: RoutePlanDraftV1::SingleExact,
            read_retry_budget: 0,
            timeout_budget_millis: 1_000,
            corpus_digest: label("corpus"),
            conformance_receipt_digest: label("receipt"),
            lifecycle: ProfileLifecycle::Active,
            evidence_refs: vec![label("evidence")],
        }
    }

    fn raw_digest(value: &str) -> String {
        Digest::of(value).as_str().to_owned()
    }

    fn named_digest(name: &str) -> NamedDigestV1 {
        NamedDigestV1 {
            name: name.into(),
            digest: raw_digest(name),
        }
    }

    fn source_range() -> SourceRangeV1 {
        SourceRangeV1 {
            start: 1,
            end: RangeEndV1::Inclusive(10),
        }
    }

    fn indexer_limits() -> IndexerLimitsV1 {
        IndexerLimitsV1 {
            max_request_bytes: 10_000,
            max_range: 10,
            max_batch: 10,
            max_response_bytes: 10_000,
            max_depth: 10,
            max_resource: 10,
            rate_limit_contract_digest: raw_digest("rate"),
        }
    }

    pub(super) fn indexer_profile() -> ClientIndexerProfileV1 {
        ClientIndexerProfileV1 {
            profile_id: "indexer-profile-1".into(),
            profile_version: "1.0.0".into(),
            profile_digest: raw_digest("indexer-profile"),
            client_family: ClientIndexerFamily::CustomEvmIndexer,
            engine_or_runtime: "local-runtime".into(),
            engine_version: "1.0.0".into(),
            dependencies: vec![DependencyV1 {
                name: "local-dependency".into(),
                version: "1.0.0".into(),
                digest: raw_digest("dependency"),
            }],
            configuration_digest: raw_digest("indexer-configuration"),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            workload_binding: "workload".into(),
            deployment_owner: "owner".into(),
            boundary_declaration_digest: raw_digest("boundary"),
            protocol_kind: IndexerProtocolKind::JsonRpc,
            protocol_version: "2.0".into(),
            chain_id: "1".into(),
            genesis_hash: "01".repeat(32),
            network_id: "local".into(),
            capability_profiles: vec![IndexerCapability::ProjectSessionCore],
            method_data_classes: vec![MethodDataClass {
                method: "eth_call".into(),
                data_class: "call-result".into(),
            }],
            source_range: source_range(),
            finality_rule_digest: raw_digest("finality"),
            reorg_behavior_digest: raw_digest("reorg"),
            removed_event_behavior_digest: raw_digest("removed"),
            checkpoint_semantics_digest: raw_digest("checkpoint"),
            completed_watermark_semantics_digest: raw_digest("watermark"),
            artifact_digests: vec![named_digest("abi")],
            limits: indexer_limits(),
            behavior: IndexerBehaviorV1 {
                visibility_miss_digest: raw_digest("miss"),
                empty_digest: raw_digest("empty"),
                partial_digest: raw_digest("partial"),
                error_digest: raw_digest("error"),
                retry_digest: raw_digest("retry"),
                recovery_digest: raw_digest("recovery"),
                retirement_digest: raw_digest("retirement"),
            },
            candidate_store_contract_digest: raw_digest("candidate"),
            outbox_contract_digest: raw_digest("outbox"),
            fact_bridge_contract_digest: raw_digest("bridge"),
            security_evidence_digest: raw_digest("security"),
            privacy_evidence_digest: raw_digest("privacy"),
            licensing_digest: raw_digest("license"),
            supply_chain_digest: raw_digest("supply"),
            telemetry_classification_digest: raw_digest("telemetry"),
            rollback_digest: raw_digest("rollback"),
            uninstall_digest: raw_digest("uninstall"),
            corpus_digest: raw_digest("corpus"),
            conformance_receipt_digest: raw_digest("receipt"),
            lifecycle: ClientIndexerLifecycle::Active,
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }

    pub(super) fn projection_plan(profile: &ClientIndexerProfileV1) -> ProjectionPlanV1 {
        ProjectionPlanV1 {
            profile_id: profile.profile_id.clone(),
            profile_version: profile.profile_version.clone(),
            profile_digest: profile.profile_digest.clone(),
            plan_digest: raw_digest("projection-plan"),
            workload_identity: WorkloadIdentityV1::ExternalOwner {
                owner: "owner".into(),
                boundary_digest: raw_digest("workload"),
            },
            partitions: vec![ProjectionPartitionV1 {
                partition_id: "partition".into(),
                source_id: "source".into(),
                range: source_range(),
                state: PartitionState::Complete,
                finality_digest: profile.finality_rule_digest.clone(),
                checkpoint_digest: raw_digest("checkpoint"),
            }],
            source_range: source_range(),
            finality_rule_digest: profile.finality_rule_digest.clone(),
            extractor_digests: vec![named_digest("extractor")],
            candidate_schema_digests: vec![named_digest("schema")],
            limits: indexer_limits(),
            secret_references: vec![SecretReferenceV1 {
                purpose: SecretPurposeV1::ApiToken,
                reference: "ref:token".into(),
            }],
            lifecycle_generation: 1,
            desired_state: DesiredState::Active,
        }
    }

    pub(super) fn invocation_asset() -> InvocationConfigurationAssetV1 {
        InvocationConfigurationAssetV1 {
            asset_id: "read-uint256".into(),
            runtime_binding_id: None,
            transaction_policy: None,
            tenant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            workload_id: "urn:openpc:workload:configured-reader".into(),
            rpc_method: "eth_call".into(),
            request_class: RequestClass::Read,
            chain_id: "1".into(),
            network_id: "local".into(),
            genesis_digest: Digest::of("genesis"),
            contract_address: [1; 20],
            proxy_address: None,
            implementation_address: None,
            code_digest: Digest::of("code"),
            implementation_code_digest: None,
            abi_digest: Digest::of("abi"),
            canonical_signature: "read(uint256)".into(),
            selector: [0x12, 0x34, 0x56, 0x78],
            input_types: vec![AbiType::Uint(256)],
            named_sets: Vec::new(),
        }
    }

    pub(super) fn work() -> ClaimedWork {
        ClaimedWork {
            work_id: "018f0000-0000-7000-8000-000000000401".into(),
            occurrence_id: None,
            operation_id: "018f0000-0000-7000-8000-000000000402".into(),
            work_kind: "RUNTIME_ACTIVATION".into(),
            resource_id: "018f0000-0000-7000-8000-000000000403".into(),
            input_digest: format!("sha256:{}", Digest::of("input").as_str()),
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            configuration_cbor: Vec::new(),
            configuration_digest: Digest::of([]),
            policy: Some(ClaimedPolicy {
                artifact_cbor: Vec::new(),
                artifact_digest: Digest::of([]),
                fact_generation_digest: Digest::of("facts"),
                generation_digest: Digest::of("policy"),
            }),
            related_profile_receipt: None,
            provider_receipt: None,
            projection_receipt: None,
            contract_policy_assets: Vec::new(),
            generation_id: Some("018f0000-0000-7000-8000-000000000404".into()),
            target_id: Some("018f0000-0000-7000-8000-000000000403".into()),
            generation_digest: Some(Digest::of("configuration")),
            predecessor_digest: None,
            xds_version_digest: Some(Digest::of("xds")),
            active_generation_digest: None,
            active_xds_version_digest: None,
            journal_sequence: 0,
            attempt_count: 1,
            execution_attempt_id: None,
            reconcile_only: false,
        }
    }

    fn resource_configuration_input() -> serde_json::Value {
        let scope = work();
        let workload = "urn:openpc:workload:018f0000-0000-7000-8000-000000000407";
        let provider = provider_profile();
        let provider_cbor = encode_provider_profile_pc_cbor(&provider).unwrap();
        let mut profile = indexer_profile();
        profile.participant_binding = scope.participant_id.clone();
        profile.privacy_binding = scope.privacy_domain_id.clone();
        profile.workload_binding = workload.into();
        profile.genesis_hash = provider.genesis_hash.trim_start_matches("sha256:").into();
        let profile_cbor = encode_client_indexer_profile_pc_cbor(&profile).unwrap();
        let mut plan = projection_plan(&profile);
        plan.partitions[0].state = PartitionState::CatchingUp;
        let plan_cbor = encode_projection_plan_pc_cbor(&plan).unwrap();
        let mut asset = invocation_asset();
        asset.workload_id = workload.into();
        asset.asset_id = "018f0000-0000-7000-8000-000000000411".into();
        asset.runtime_binding_id = Some("018f0000-0000-7000-8000-000000000301".into());
        serde_json::json!({
            "participant_id": scope.participant_id, "privacy_domain_id": scope.privacy_domain_id,
            "workload_id": workload, "chain_id": "1",
            "providers": [{"resource_id": "018f0000-0000-7000-8000-000000000408",
                "artifact_digest": format!("sha256:{}", Digest::of(provider_cbor).as_str()), "profile": provider}],
            "indexers": [{"resource_id": "018f0000-0000-7000-8000-000000000409",
                "artifact_digest": format!("sha256:{}", Digest::of(profile_cbor).as_str()), "profile": profile}],
            "projections": [{"resource_id": "018f0000-0000-7000-8000-000000000410",
                "indexer_resource_id": "018f0000-0000-7000-8000-000000000409",
                "artifact_digest": format!("sha256:{}", Digest::of(plan_cbor).as_str()), "plan": plan}],
            "assets": [asset],
        })
    }

    #[test]
    fn resource_configuration_scoped_resources_have_no_execution_authority() {
        let input = resource_configuration_input();
        let result =
            encode_resource_configuration_document(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(result["authority"], "NONE");
        assert_eq!(result["resourceArtifacts"].as_array().unwrap().len(), 3);
        let mut derived = input.clone();
        for field in ["providers", "indexers", "projections"] {
            derived[field][0]
                .as_object_mut()
                .unwrap()
                .remove("artifact_digest");
        }
        assert_eq!(
            result,
            encode_resource_configuration_document(&serde_json::to_vec(&derived).unwrap()).unwrap()
        );
        assert!(result["configurationCborHex"].as_str().unwrap().len() > 100);
        let configuration_bytes =
            parse_hex_bytes(result["configurationCborHex"].as_str().unwrap()).unwrap();
        let configuration_digest = Digest::of(&configuration_bytes);
        assert_eq!(
            pc_policy_core::invocation::active_invocation_workload(
                &configuration_bytes,
                &configuration_digest,
                input["participant_id"].as_str().unwrap(),
                input["privacy_domain_id"].as_str().unwrap(),
            )
            .unwrap(),
            input["workload_id"].as_str().unwrap(),
        );
        let mut old = input;
        for field in ["indexers", "projections", "assets"] {
            old.as_object_mut().unwrap().remove(field);
        }
        let legacy =
            encode_resource_configuration_document(&serde_json::to_vec(&old).unwrap()).unwrap();
        for field in ["indexers", "projections", "assets"] {
            old[field] = serde_json::json!([]);
        }
        assert_eq!(
            legacy,
            encode_resource_configuration_document(&serde_json::to_vec(&old).unwrap()).unwrap()
        );
    }

    #[test]
    fn resource_configuration_requires_the_canonical_identity_workload_urn() {
        for workload in [
            "018f0000-0000-7000-8000-000000000407",
            "urn:openpc:participant:018f0000-0000-7000-8000-000000000407",
            "urn:openpc:workload:018F0000-0000-7000-8000-000000000407",
            "urn:openpc:workload:018f0000-0000-4000-8000-000000000407",
            "urn:openpc:workload:018f0000-0000-7000-8000-000000000407:extra",
        ] {
            let mut input = resource_configuration_input();
            input["workload_id"] = serde_json::json!(workload);
            assert_eq!(
                encode_resource_configuration_document(&serde_json::to_vec(&input).unwrap())
                    .unwrap_err(),
                "resource configuration scope rejected",
            );
        }
    }

    fn resource_configuration_append_input() -> (serde_json::Value, serde_json::Value) {
        let input = resource_configuration_input();
        let base =
            encode_resource_configuration_document(&serde_json::to_vec(&input).unwrap()).unwrap();
        let mut added = input.clone();
        added["chain_id"] = serde_json::json!("2");
        added["providers"][0]["resource_id"] =
            serde_json::json!("018f0000-0000-7000-8000-000000000412");
        added["providers"][0]["profile"]["chain_id"] = serde_json::json!("2");
        added["providers"][0]["profile"]["network_id"] = serde_json::json!("second-network");
        added["providers"][0]["profile"]["genesis_hash"] =
            serde_json::json!(format!("sha256:{}", "22".repeat(32)));
        added["providers"][0]
            .as_object_mut()
            .unwrap()
            .remove("artifact_digest");
        for field in ["indexers", "projections", "assets"] {
            added[field] = serde_json::json!([]);
        }
        added["base_configuration"] = serde_json::json!({
            "configuration_cbor_hex": base["configurationCborHex"],
            "configuration_digest": base["configurationDigest"],
        });
        (input, added)
    }

    #[test]
    fn resource_configuration_appends_a_network_without_replacing_installed_resources() {
        for explicit_scope in [true, false] {
            let (input, mut added) = resource_configuration_append_input();
            let bytes = parse_hex_bytes(
                added["base_configuration"]["configuration_cbor_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let mut base =
                decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
            if !explicit_scope {
                base.workload_scope = None;
                let bytes = encode_active_invocation_configuration(&base).unwrap();
                added["base_configuration"] = serde_json::json!({
                    "configuration_cbor_hex": hex_bytes(&bytes),
                    "configuration_digest": format!("sha256:{}", Digest::of(&bytes).as_str()),
                });
            }
            let result =
                encode_resource_configuration_document(&serde_json::to_vec(&added).unwrap())
                    .unwrap();
            assert_eq!(result["authority"], "NONE");
            let bytes = parse_hex_bytes(result["configurationCborHex"].as_str().unwrap()).unwrap();
            let digest = Digest::of(&bytes);
            let combined = decode_active_invocation_configuration(&bytes, &digest).unwrap();
            assert_eq!(combined.assets, base.assets);
            assert_eq!(combined.deployment_policies, base.deployment_policies);
            assert_eq!(combined.visibility_resources, base.visibility_resources);
            assert_eq!(combined.workload_scope, base.workload_scope);
            assert_eq!(
                &combined.resource_artifacts[..base.resource_artifacts.len()],
                base.resource_artifacts.as_slice()
            );
            assert_eq!(
                combined.resource_artifacts.len(),
                base.resource_artifacts.len() + 1
            );
            let new = combined.resource_artifacts.last().unwrap();
            assert_eq!(new.artifact_id, "018f0000-0000-7000-8000-000000000412");
            assert_eq!(
                qualify_provider_profile(
                    &new.payload_cbor,
                    &format!("sha256:{}", new.artifact_digest.as_str())
                )
                .unwrap()
                .chain_id,
                "2"
            );
            assert_eq!(
                pc_policy_core::invocation::active_invocation_workload(
                    &bytes,
                    &digest,
                    input["participant_id"].as_str().unwrap(),
                    input["privacy_domain_id"].as_str().unwrap(),
                )
                .unwrap(),
                input["workload_id"].as_str().unwrap()
            );
            assert_eq!(result["resourceArtifacts"].as_array().unwrap().len(), 4);
        }
    }

    #[test]
    fn resource_configuration_base_rejects_changed_bytes_or_scope() {
        let (_, added) = resource_configuration_append_input();
        for (pointer, value) in [
            (
                "/base_configuration/configuration_digest",
                serde_json::json!(label("replacement")),
            ),
            (
                "/base_configuration/configuration_cbor_hex",
                serde_json::json!(format!(
                    "{}00",
                    added["base_configuration"]["configuration_cbor_hex"]
                        .as_str()
                        .unwrap()
                )),
            ),
            (
                "/participant_id",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            (
                "/privacy_domain_id",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            (
                "/workload_id",
                serde_json::json!("urn:openpc:workload:018f0000-0000-7000-8000-000000000999"),
            ),
        ] {
            let mut invalid = added.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                encode_resource_configuration_document(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err()
                    .starts_with("resource configuration base")
            );
        }
        let mut invalid = added;
        invalid["base_configuration"]["qualification"] = serde_json::json!("QUALIFIED");
        assert_eq!(
            encode_resource_configuration_document(&serde_json::to_vec(&invalid).unwrap())
                .unwrap_err(),
            "resource configuration input rejected"
        );
    }

    #[test]
    fn resource_configuration_base_rejects_resource_or_binding_replacement() {
        let (input, added) = resource_configuration_append_input();
        let mut invalid = added.clone();
        invalid["providers"][0]["resource_id"] = input["providers"][0]["resource_id"].clone();
        assert_eq!(
            encode_resource_configuration_document(&serde_json::to_vec(&invalid).unwrap())
                .unwrap_err(),
            "resource configuration base resource conflict"
        );
        for same_asset in [true, false] {
            let mut invalid = added.clone();
            invalid["chain_id"] = input["chain_id"].clone();
            invalid["providers"][0]["profile"] = input["providers"][0]["profile"].clone();
            invalid["assets"] = input["assets"].clone();
            if !same_asset {
                invalid["assets"][0]["asset_id"] =
                    serde_json::json!("018f0000-0000-7000-8000-000000000413");
            }
            assert_eq!(
                encode_resource_configuration_document(&serde_json::to_vec(&invalid).unwrap())
                    .unwrap_err(),
                "resource configuration base resource conflict"
            );
        }
    }

    #[test]
    fn resource_configuration_rejects_scope_digest_and_source_substitution() {
        for (pointer, value) in [
            (
                "/indexers/0/profile/participant_binding",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            (
                "/indexers/0/profile/workload_binding",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            (
                "/indexers/0/artifact_digest",
                serde_json::json!(label("replacement")),
            ),
            (
                "/projections/0/indexer_resource_id",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            (
                "/projections/0/artifact_digest",
                serde_json::json!(label("replacement")),
            ),
            (
                "/assets/0/tenant_id",
                serde_json::json!("018f0000-0000-7000-8000-000000000999"),
            ),
            ("/assets/0/runtime_binding_id", serde_json::Value::Null),
        ] {
            let mut input = resource_configuration_input();
            *input.pointer_mut(pointer).unwrap() = value;
            assert!(
                encode_resource_configuration_document(&serde_json::to_vec(&input).unwrap())
                    .is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn local_fixture_dash_is_the_only_absent_identifier() {
        assert_eq!(optional_fixture_identifier("-"), None);
        assert_eq!(
            optional_fixture_identifier("provider-a"),
            Some("provider-a")
        );
        assert_eq!(optional_fixture_identifier(""), Some(""));
    }

    #[test]
    fn worker_admission_is_stable_across_valid_generation_content() {
        let admission = WorkerArtifactAdmission;
        let component = |bytes: &[u8]| ArtifactComponent {
            component_id: "openpc.runtime.configuration".into(),
            component_type: "openpc.runtime.configuration".into(),
            content_digest: Digest::of(bytes),
            semantic_digest: Digest::of(bytes),
            schema_id: 3101,
            schema_version: 1,
            size_bytes: u64::try_from(bytes.len()).unwrap(),
            required: true,
        };
        for bytes in [b"predecessor".as_slice(), b"successor".as_slice()] {
            assert_eq!(admission.validate(&component(bytes), bytes), Ok(()));
        }
        let mut substituted = component(b"predecessor");
        substituted.schema_id = 3102;
        assert_eq!(
            admission.validate(&substituted, b"predecessor"),
            Err(pc_runtime_types::RuntimeError::InvalidDigest)
        );
    }

    #[test]
    fn unsupported_work_kind_fails_closed() {
        let mut invalid = work();
        invalid.work_kind = "UNKNOWN".into();
        assert_eq!(
            generic_receipt(&invalid),
            Err("unsupported configuration work kind".into())
        );
    }

    #[tokio::test]
    async fn durable_work_rejects_a_predecessor_not_in_the_agent_journal() {
        let mut invalid = work();
        invalid.predecessor_digest = Some(Digest::of("other"));
        invalid.active_generation_digest = Some(Digest::of("active"));
        invalid.active_xds_version_digest = Some(Digest::of("active-xds"));
        assert_eq!(
            execute_runtime(
                ExecutionPersistence::TestOnlyBypass,
                &invalid,
                &Config {
                    host: "host".into(),
                    port: 5432,
                    database: "database".into(),
                    user: "user".into(),
                    password: "password-password-password-password".into(),
                    participant_id: invalid.participant_id.clone(),
                    privacy_domain_id: invalid.privacy_domain_id.clone(),
                    worker_id: "worker".into(),
                    artifact_capacity_bytes: 1,
                    fleet_key: [41; 32],
                    agent_key: [42; 32],
                    identity_runtime_public_key: Vec::new(),
                    fact_host: String::new(),
                    fact_port: 0,
                    fact_database: String::new(),
                    fact_user: String::new(),
                    fact_password: String::new(),
                    fact_verify_key: Vec::new(),
                    fact_verify_key_id: String::new(),
                },
                None,
            )
            .await,
            Err("predecessor does not match active generation".into())
        );
    }

    #[test]
    fn provider_work_consumes_the_exact_active_configuration_artifact() {
        let resource_id = "018f0000-0000-7000-8000-000000000403";
        let profile_cbor = encode_provider_profile_pc_cbor(&provider_profile()).unwrap();
        let profile_digest = Digest::of(&profile_cbor);
        let configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![invocation_asset()],
            resource_artifacts: vec![ConfigurationArtifactV1 {
                artifact_id: resource_id.into(),
                artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                artifact_digest: profile_digest.clone(),
                payload_cbor: profile_cbor,
            }],
        };
        let configuration_cbor = encode_active_invocation_configuration(&configuration).unwrap();
        let mut admitted = work();
        admitted.work_kind = "PROVIDER_QUALIFICATION".into();
        admitted.resource_id = resource_id.into();
        admitted.input_digest = format!("sha256:{}", profile_digest.as_str());
        admitted.configuration_digest = Digest::of(&configuration_cbor);
        admitted.configuration_cbor = configuration_cbor;

        let receipt = generic_receipt(&admitted).unwrap();
        assert_eq!(receipt["consumer"], "LS-MULTI-RPC");
        assert_eq!(receipt["profileId"], "provider-profile-1");

        admitted.resource_id = "018f0000-0000-7000-8000-000000000499".into();
        assert_eq!(
            generic_receipt(&admitted),
            Err("configuration resource artifact rejected".into())
        );
    }

    #[test]
    fn runtime_invocation_join_retains_contract_assets_and_active_resources() {
        let contract_configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![invocation_asset()],
            resource_artifacts: Vec::new(),
        };
        let contract_cbor =
            encode_active_invocation_configuration(&contract_configuration).unwrap();
        let profile_cbor = encode_provider_profile_pc_cbor(&provider_profile()).unwrap();
        let resource_id = "018f0000-0000-7000-8000-000000000403";
        let resource_configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![invocation_asset()],
            resource_artifacts: vec![ConfigurationArtifactV1 {
                artifact_id: resource_id.into(),
                artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                artifact_digest: Digest::of(&profile_cbor),
                payload_cbor: profile_cbor.clone(),
            }],
        };
        let resource_cbor =
            encode_active_invocation_configuration(&resource_configuration).unwrap();

        let (joined_cbor, joined_digest) = join_runtime_invocation_configuration(
            &contract_cbor,
            &Digest::of(&contract_cbor),
            &resource_cbor,
            &Digest::of(&resource_cbor),
            None,
            None,
        )
        .unwrap();
        let joined = decode_active_invocation_configuration(&joined_cbor, &joined_digest).unwrap();

        assert_eq!(joined.assets, contract_configuration.assets);
        assert_eq!(joined.resource_artifacts.len(), 1);
        assert_eq!(joined.resource_artifacts[0].artifact_id, resource_id);
        assert_eq!(joined.resource_artifacts[0].payload_cbor, profile_cbor);

        // Even correctly digested resource bytes do not establish the missing
        // public CIGL review/grant provenance. No generic upload may mint it.
        let mut unreviewed = resource_configuration;
        use pc_policy_core::cigl::{
            TraceLimits,
            grants::{GrantStatus, InteractionGrantSet},
            profile::{ConfiguredMethodProfile, MethodProfileDefinition},
        };
        let definition = MethodProfileDefinition {
            schema_version: "1.0".into(),
            profile_id: resource_id.into(),
            revision: 1,
            participant_id: contract_configuration.assets[0].tenant_id.clone(),
            privacy_domain_id: contract_configuration.assets[0].privacy_domain_id.clone(),
            root_contract_method_policy_id: "018f0000-0000-7000-8000-000000000701".into(),
            analysis_digest: Digest::of("caller-supplied-analysis"),
            program: None,
            limits: TraceLimits {
                max_depth: 16,
                max_frames: 32,
                max_response_bytes: 100_000,
                timeout_ms: 5000,
            },
            interactions: Vec::new(),
        };
        let grants = InteractionGrantSet {
            profile_id: definition.profile_id.clone(),
            profile_revision: 1,
            profile_digest: definition.digest().unwrap(),
            participant_id: definition.participant_id.clone(),
            privacy_domain_id: definition.privacy_domain_id.clone(),
            status: GrantStatus::Active,
            grants: Vec::new(),
        };
        let unreviewed_payload = ConfiguredMethodProfile { definition, grants }
            .to_cbor()
            .unwrap();
        unreviewed.resource_artifacts[0].artifact_kind = ConfigurationArtifactKind::CiglProfile;
        unreviewed.resource_artifacts[0].artifact_digest = Digest::of(&unreviewed_payload);
        unreviewed.resource_artifacts[0].payload_cbor = unreviewed_payload;
        let bytes = encode_active_invocation_configuration(&unreviewed).unwrap();
        assert_eq!(
            join_runtime_invocation_configuration(
                &contract_cbor,
                &Digest::of(&contract_cbor),
                &bytes,
                &Digest::of(&bytes),
                None,
                None,
            ),
            Err("governed CIGL publication unavailable".into())
        );
    }

    #[test]
    fn workload_scope_comes_from_admitted_configuration_and_rejects_mixed_tenants() {
        let asset = invocation_asset();
        let mut configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![asset.clone()],
            resource_artifacts: Vec::new(),
        };
        let resolve = |configuration: &ActiveInvocationConfigurationV1| {
            let bytes = encode_active_invocation_configuration(configuration).unwrap();
            pc_policy_core::invocation::active_invocation_workload(
                &bytes,
                &Digest::of(&bytes),
                &asset.tenant_id,
                &asset.privacy_domain_id,
            )
        };
        assert_eq!(resolve(&configuration).unwrap(), asset.workload_id);
        assert_ne!(asset.workload_id, work().target_id.unwrap());
        for (tenant, privacy, workload) in [
            (
                "foreign-tenant",
                asset.privacy_domain_id.as_str(),
                asset.workload_id.as_str(),
            ),
            (
                asset.tenant_id.as_str(),
                "foreign-privacy",
                asset.workload_id.as_str(),
            ),
            (
                asset.tenant_id.as_str(),
                asset.privacy_domain_id.as_str(),
                "another-workload",
            ),
        ] {
            let mut other = asset.clone();
            other.asset_id = "second-asset".into();
            other.tenant_id = tenant.into();
            other.privacy_domain_id = privacy.into();
            other.workload_id = workload.into();
            configuration.assets = vec![asset.clone(), other];
            assert!(resolve(&configuration).is_err());
        }
    }

    pub(super) fn test_config(admitted: &ClaimedWork) -> Config {
        Config {
            host: String::new(),
            port: 0,
            database: String::new(),
            user: String::new(),
            password: String::new(),
            participant_id: admitted.participant_id.clone(),
            privacy_domain_id: admitted.privacy_domain_id.clone(),
            worker_id: "worker-1".into(),
            artifact_capacity_bytes: 1_000_000,
            fleet_key: [3; 32],
            agent_key: [4; 32],
            identity_runtime_public_key: Vec::new(),
            fact_host: String::new(),
            fact_port: 0,
            fact_database: String::new(),
            fact_user: String::new(),
            fact_password: String::new(),
            fact_verify_key: Vec::new(),
            fact_verify_key_id: String::new(),
        }
    }

    #[tokio::test]
    async fn runtime_work_replays_all_qualified_consumers_before_activation() {
        let provider = encode_provider_profile_pc_cbor(&provider_profile()).unwrap();
        let indexer_profile = indexer_profile();
        let indexer = encode_client_indexer_profile_pc_cbor(&indexer_profile).unwrap();
        let plan = encode_projection_plan_pc_cbor(&projection_plan(&indexer_profile)).unwrap();
        let provider_digest = Digest::of(&provider);
        let indexer_digest = Digest::of(&indexer);
        let plan_digest = Digest::of(&plan);
        let configuration = ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![invocation_asset()],
            resource_artifacts: vec![
                ConfigurationArtifactV1 {
                    artifact_id: "018f0000-0000-7000-8000-000000000405".into(),
                    artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                    artifact_digest: provider_digest.clone(),
                    payload_cbor: provider.clone(),
                },
                ConfigurationArtifactV1 {
                    artifact_id: "018f0000-0000-7000-8000-000000000406".into(),
                    artifact_kind: ConfigurationArtifactKind::ClientIndexerProfile,
                    artifact_digest: indexer_digest.clone(),
                    payload_cbor: indexer.clone(),
                },
                ConfigurationArtifactV1 {
                    artifact_id: "018f0000-0000-7000-8000-000000000407".into(),
                    artifact_kind: ConfigurationArtifactKind::ProjectionPlan,
                    artifact_digest: plan_digest.clone(),
                    payload_cbor: plan.clone(),
                },
            ],
        };
        let configuration_cbor = encode_active_invocation_configuration(&configuration).unwrap();
        let policy_generation_digest = Digest::of("policy-generation");
        let rpc_policy = pc_policy_core::rpc_policy::RpcSurfacePolicy {
            schema_version: "1.0.0".into(),
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            rules: vec![pc_policy_core::rpc_policy::RpcRule {
                method: "eth_sendRawTransaction".into(),
                effect: pc_policy_core::rpc_policy::RpcEffect::Allow,
                required_roles: vec!["treasury-writer".into()],
            }],
        };
        let policy = ActiveInvocationPolicyGenerationV1 {
            visibility_policies: Vec::new(),
            fact_conditions: Vec::new(),
            indexer_policies: Vec::new(),
            deployment_policies: Vec::new(),
            required_facts: Vec::new(),
            rpc_policies: vec![rpc_policy.clone()],
            schema_version: "1.0".into(),
            root_asset_ids: vec!["read-uint256".into()],
            assets: vec![InvocationPolicyAssetV1 {
                method_required_roles: None,
                nested_call_set_digest: None,
                rpc_denied: false,
                asset_id: "read-uint256".into(),
                policy_version: "1.0.0".into(),
                active: true,
                required_roles: vec!["reader".into()],
                approval: ApprovalRequirement::None,
                webauthn_required: false,
                argument_rules: Vec::new(),
                nested_asset_ids: Vec::new(),
            }],
        };
        let policy_cbor = encode_active_invocation_policy_generation(&policy).unwrap();
        let mut admitted = work();
        admitted.configuration_digest = Digest::of(&configuration_cbor);
        admitted.configuration_cbor = configuration_cbor;
        admitted.policy.as_mut().unwrap().artifact_digest = Digest::of(&policy_cbor);
        admitted.policy.as_mut().unwrap().artifact_cbor = policy_cbor;
        admitted.policy.as_mut().unwrap().generation_digest = policy_generation_digest;
        admitted.provider_receipt = Some(serde_json::json!({
            "artifactCbor": provider,
            "artifactDigest": format!("sha256:{}", provider_digest.as_str()),
        }));
        admitted.projection_receipt = Some(serde_json::json!({
            "profileArtifactCbor": indexer,
            "artifactCbor": plan,
            "artifactDigest": format!("sha256:{}", plan_digest.as_str()),
        }));
        admitted.generation_digest = Some(Digest::of("generation"));
        admitted.input_digest = label("generation");
        admitted.occurrence_id = Some("018f0000-0000-7000-8000-000000000709".into());
        admitted.contract_policy_assets = serde_json::from_value(serde_json::json!([{
            "assetId": "018f0000-0000-7000-8000-000000000708",
            "policyVersion": "1",
            "tenantId": admitted.participant_id,
            "privacyDomainId": admitted.privacy_domain_id,
            "chainId": "31337",
            "networkId": "openpc-local",
            "genesisDigest": format!("sha256:{}", Digest::of("contract-genesis").as_str()),
            "contractAddress": format!("0x{}", "11".repeat(20)),
            "proxyAddress": null,
            "implementationAddress": null,
            "codeDigest": format!("sha256:{}", Digest::of("contract-code").as_str()),
            "implementationCodeDigest": null,
            "abiDigest": format!("sha256:{}", Digest::of("contract-abi").as_str()),
            "canonicalSignature": "transfer(address,uint256)",
            "selector": "0xa9059cbb",
            "canonicalAbi": [{
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            }],
            "effect": "WRITE",
            "requiredRoles": ["treasury-writer"],
            "approvalRequirement": "MAKER_CHECKER",
            "mfaRequirement": "WEBAUTHN",
            "rpcMethodPolicyDigest": format!("sha256:{}", rpc_policy.digest().unwrap().as_str()),
            "nestedCallSetDigest": format!("sha256:{}", Digest::of([]).as_str()),
            "namedSetCount": 0,
            "rules": [{
                "parameterPath": "inputs[1]",
                "operandType": "INTEGER",
                "operator": "LTE",
                "values": ["1000"]
            }]
        }]))
        .unwrap();
        let config = test_config(&admitted);

        let (capsule, receipt, _) = execute_runtime(
            ExecutionPersistence::TestOnlyBypass,
            &admitted,
            &config,
            None,
        )
        .await
        .unwrap();
        assert_ne!(capsule, Digest::of([]));
        assert_eq!(receipt["claims"]["target_id"], admitted.resource_id);
        assert_eq!(
            receipt["claims"]["occurrence_id"],
            admitted.occurrence_id.as_deref().unwrap()
        );
        assert_eq!(receipt["contractPolicyCount"], 1);
        assert!(
            receipt["contractPolicyConfigurationDigest"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
        assert!(
            receipt["contractPolicyArtifactDigest"]
                .as_str()
                .is_some_and(|value| value.starts_with("sha256:"))
        );

        let mut projection = serde_json::to_value(&admitted.contract_policy_assets[0]).unwrap();
        projection["generationMatches"] = Value::Bool(false);
        assert!(
            decode_claimed_contract_assets(
                Value::Array(vec![projection.clone()]),
                &admitted.policy.as_ref().unwrap().artifact_cbor
            )
            .unwrap()
            .is_empty()
        );
        let semantic = serde_json::json!({
            "schemaVersion":"1.0.0", "participantId":admitted.participant_id,
            "privacyDomainId":admitted.privacy_domain_id,
            "moduleBindings":(["pc.policy.rpc-surface","pc.policy.contract-method","pc.policy.argument-guard"].map(|module| serde_json::json!({
                "moduleId":module,"semanticVersion":"1.0.0","manifestDigest":label("module"),"configurationDigest":label("configuration"),
            }))),
            "rpcPolicies":[rpc_policy],
            "contractPolicies":[{"contractMethodPolicyId":admitted.contract_policy_assets[0].asset_id,"revision":"1"}],
            "requiredFacts":[{"candidateId":"fact","generationId":"generation","factDigest":label("fact")}],
        });
        let mut typed = admitted.clone();
        typed.policy.as_mut().unwrap().artifact_cbor = pc_policy_core::pc_cbor_1(&semantic);
        typed.policy.as_mut().unwrap().artifact_digest =
            Digest::of(&typed.policy.as_ref().unwrap().artifact_cbor);
        projection["runtimeBindingId"] =
            Value::String("018f0000-0000-7000-8000-000000000710".into());
        typed.contract_policy_assets = decode_claimed_contract_assets(
            Value::Array(vec![projection]),
            &typed.policy.as_ref().unwrap().artifact_cbor,
        )
        .unwrap();
        assert_eq!(typed.contract_policy_assets.len(), 1);
        let mut nullable_projection =
            serde_json::to_value(&typed.contract_policy_assets[0]).unwrap();
        nullable_projection["generationMatches"] = Value::Null;
        assert_eq!(
            decode_claimed_contract_assets(
                Value::Array(vec![nullable_projection]),
                &typed.policy.as_ref().unwrap().artifact_cbor,
            )
            .unwrap()
            .len(),
            1
        );
        let (_, typed_receipt, _) =
            execute_runtime(ExecutionPersistence::TestOnlyBypass, &typed, &config, None)
                .await
                .unwrap();
        assert_eq!(typed_receipt["contractPolicyCount"], 1);

        let mut unbound_write = typed.clone();
        unbound_write.contract_policy_assets[0].runtime_binding_id = None;
        assert_eq!(
            execute_runtime(
                ExecutionPersistence::TestOnlyBypass,
                &unbound_write,
                &config,
                None,
            )
            .await
            .unwrap_err(),
            "contract policy owner identity unavailable"
        );

        let mut unrelated_read = typed.contract_policy_assets[0].clone();
        unrelated_read.asset_id = "018f0000-0000-7000-8000-000000000711".into();
        unrelated_read.runtime_binding_id = Some("018f0000-0000-7000-8000-000000000712".into());
        unrelated_read.effect = "READ".into();
        typed.contract_policy_assets.push(unrelated_read);
        let (_, selected_receipt, _) =
            execute_runtime(ExecutionPersistence::TestOnlyBypass, &typed, &config, None)
                .await
                .expect("unselected tenant policy must not become a routing owner");
        assert_eq!(selected_receipt["contractPolicyCount"], 1);

        let mut changed_policy = admitted.clone();
        changed_policy.contract_policy_assets[0].required_roles = vec!["auditor".into()];
        let (changed_capsule, changed_receipt, _) = execute_runtime(
            ExecutionPersistence::TestOnlyBypass,
            &changed_policy,
            &config,
            None,
        )
        .await
        .unwrap();
        assert_ne!(capsule, changed_capsule);
        assert_ne!(
            receipt["contractPolicyArtifactDigest"],
            changed_receipt["contractPolicyArtifactDigest"]
        );
        assert_eq!(
            receipt["contractPolicyConfigurationDigest"],
            changed_receipt["contractPolicyConfigurationDigest"]
        );
    }
    #[tokio::test]
    #[ignore = "requires the scoped PostgreSQL owner in run-decision-owner.py --cigl-analysis"]
    async fn postgres_runtime_result_fences_precede_target_mutations() {
        use openpc_fleet_controller::cigl_publication::profile_invalidation::lock_sources;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&env::var("OPENPC_CIGL_COMPILATION_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&env::var("OPENPC_ASTRA05_ADMIN_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let admitted = work();
        let config = test_config(&admitted);
        // Identity owns the Participant before it reads any target. Completion
        // must wait here, before it can acquire its work/generation/target rows.
        let mut identity = admin.begin().await.unwrap();
        sqlx::query("select participant_id from control.participant where participant_id=$1::text::uuid for update")
            .bind(&config.participant_id).fetch_one(&mut *identity).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(150),
                result_transaction(&pool, &config, "RUNTIME_ACTIVATION")
            )
            .await
            .is_err()
        );
        identity.rollback().await.unwrap();

        let mut result = tokio::time::timeout(
            Duration::from_secs(3),
            result_transaction(&pool, &config, "RUNTIME_ACTIVATION"),
        )
        .await
        .unwrap()
        .unwrap();
        let action: String = sqlx::query_scalar("select openpc.current_action_intent_id()")
            .fetch_one(&mut *result)
            .await
            .unwrap();
        assert_eq!(
            action,
            "ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1"
        );
        let mut identity = admin.begin().await.unwrap();
        sqlx::query("set local lock_timeout='100ms'")
            .execute(&mut *identity)
            .await
            .unwrap();
        let error = sqlx::query("select participant_id from control.participant where participant_id=$1::text::uuid for update")
            .bind(&config.participant_id).fetch_one(&mut *identity).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        identity.rollback().await.unwrap();

        // The invalidator cannot reach target/generation SHARE locks while
        // completion holds the grant fence, eliminating the opposite row order.
        let mut invalidation = pool.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(&config.participant_id).bind(&config.privacy_domain_id)
            .execute(&mut *invalidation).await.unwrap();
        sqlx::query("set local lock_timeout='100ms'")
            .execute(&mut *invalidation)
            .await
            .unwrap();
        assert_eq!(
            lock_sources(&mut invalidation).await.unwrap_err(),
            pc_runtime_types::RuntimeError::RuntimeUnavailable
        );
        invalidation.rollback().await.unwrap();
        result.rollback().await.unwrap();
        let mut invalidation = pool.begin().await.unwrap();
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(&config.participant_id).bind(&config.privacy_domain_id)
            .execute(&mut *invalidation).await.unwrap();
        lock_sources(&mut invalidation).await.unwrap();
        invalidation.rollback().await.unwrap();
        pool.close().await;
        admin.close().await;
    }
}
