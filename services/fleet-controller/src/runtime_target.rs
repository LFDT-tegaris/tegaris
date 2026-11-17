//! Shared construction of the governed Runtime Agent admission owners.
//! Control-plane preparation and the restarted target process use the same
//! trust graph; neither reconstructs authority from workload request fields.

use crate::routing_publication::{
    CERTIFICATION_ARTIFACT_ID, CERTIFICATION_DEFINITION, ROUTING_ARTIFACT_ID, ROUTING_DEFINITION,
};
use openpc_fact_service::FactSignatureVerifier;
use openpc_pds::IdentityAssertionVerifier;
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent,
    authority_artifact::AuthoritySourceBinding,
    fact_custody::FactArtifactAdmission,
    identity_custody::IdentityArtifactAdmission,
    identity_state::RuntimeIdentityContext,
    indexer_custody::{
        CONFIGURATION_ARTIFACT_ID as INDEXER_CONFIGURATION_ID,
        CONFIGURATION_DEFINITION as INDEXER_CONFIGURATION_DEFINITION, IndexerArtifactAdmission,
        POLICY_ARTIFACT_ID as INDEXER_POLICY_ID, POLICY_DEFINITION as INDEXER_POLICY_DEFINITION,
    },
    invocation_custody::InvocationArtifactAdmission,
    invocation_profile_custody::{InvocationProfileAdmission, InvocationProfileTrust},
    mrpc_custody::{MrpcProfileAdmission, MrpcProfileTrust},
    routing_custody::RoutingArtifactAdmission,
};
use pc_policy_core::invocation_profile::InvocationProfileMaterial;
use pc_runtime_types::{
    Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

pub mod disposition;
pub use disposition::TargetDispositionBootstrap;

const TARGET_BOOTSTRAP_PURPOSE: &str = "openpc:runtime-target-bootstrap:v1";
const MAXIMUM_BOOTSTRAP_BYTES: usize = 512 * 1024;

/// Transport for the existing primary-2003 owner. The target independently
/// verifies and journals this signed complete set; absence never clears it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEmergencyDelivery {
    pub signed_overlay: Vec<u8>,
    pub deny_keys: Vec<u8>,
}

impl TargetEmergencyDelivery {
    pub fn install(
        &self,
        agent: &openpc_runtime_agent::RuntimeAgent,
        now_ns: u64,
    ) -> RuntimeResult<()> {
        match agent.install_emergency_overlay(&self.signed_overlay, &self.deny_keys, now_ns) {
            Err(RuntimeError::ExpiredAuthorization) => agent.with_emergency_overlay(|retained| {
                // An exact, independently verified journal replay preserves
                // deny custody after restart. It does not renew freshness;
                // new requests remain blocked by the expired authority.
                if retained == Some((self.signed_overlay.as_slice(), self.deny_keys.as_slice())) {
                    Ok(())
                } else {
                    Err(RuntimeError::ExpiredAuthorization)
                }
            }),
            result => result,
        }
    }
}

/// Renew restrictions during approved activation without losing either the
/// committed set or a signed delivery the old process had not consumed. The
/// caller holds target/source custody and installs this result before serving.
pub fn renew_target_restrictions(
    agent: &openpc_runtime_agent::RuntimeAgent,
    previous: &TargetBootstrapManifest,
    fleet_key: [u8; 32],
    now_ns: u64,
    expires_at_ns: u64,
) -> RuntimeResult<Option<(u64, TargetEmergencyDelivery)>> {
    use openpc_runtime_agent::{
        EmergencyDenyOverlay, RuntimeWireSigner, encode_emergency_deny_keys,
    };
    let signer = RuntimeWireSigner::from_secret_bytes(fleet_key)?;
    if signer.verifier().public_key_bytes() != previous.fleet_runtime_public_key {
        return Err(RuntimeError::TargetIdentity);
    }
    agent.with_emergency_overlay(|committed| {
        let pending = previous.emergency_delivery.as_ref().map(|delivery| {
            (
                delivery.signed_overlay.as_slice(),
                delivery.deny_keys.as_slice(),
            )
        });
        let mut generation = 0;
        let mut keys = BTreeSet::new();
        for (signed, bytes) in committed.into_iter().chain(pending) {
            let (overlay, included) = signer
                .verifier()
                .verify_emergency_overlay_keys(signed, bytes)?;
            if overlay.fleet_id != previous.fleet_id
                || overlay.signer_id != previous.fleet_signer_id
            {
                return Err(RuntimeError::TargetIdentity);
            }
            if overlay.issued_at_ns > now_ns {
                return Err(RuntimeError::ExpiredAuthorization);
            }
            generation = generation.max(overlay.generation);
            keys.extend(included);
        }
        if generation == 0 {
            return Ok(None);
        }
        let generation = generation
            .checked_add(1)
            .ok_or(RuntimeError::BudgetExhausted)?;
        let deny_keys = encode_emergency_deny_keys(&keys)?;
        let overlay = EmergencyDenyOverlay {
            overlay_id: format!("activation-restrictions:{}", previous.capsule_id),
            fleet_id: previous.fleet_id.clone(),
            generation,
            issued_at_ns: now_ns,
            hard_expiry_ns: expires_at_ns,
            deny_key_set_digest: Digest::of(&deny_keys),
            signer_id: previous.fleet_signer_id.clone(),
        };
        Ok(Some((
            generation,
            TargetEmergencyDelivery {
                signed_overlay: signer.sign_emergency_overlay(&overlay)?,
                deny_keys,
            },
        )))
    })
}

/// Add a restriction for this immutable generation while preserving every
/// previously signed deny contribution. Only the current-source owner calls
/// this after resolving the exact installed generation from durable work.
pub fn restrict_target_generation(
    manifest: &TargetBootstrapManifest,
    fleet_key: [u8; 32],
    now_ns: u64,
    expires_at_ns: u64,
) -> RuntimeResult<Option<TargetEmergencyDelivery>> {
    use openpc_runtime_agent::{
        EmergencyDenyOverlay, RuntimeWireSigner, encode_emergency_deny_keys,
    };
    let id = uuid::Uuid::parse_str(&manifest.capsule_id).map_err(|_| RuntimeError::InvalidInput)?;
    if id.to_string() != manifest.capsule_id {
        return Err(RuntimeError::InvalidInput);
    }
    let signer = RuntimeWireSigner::from_secret_bytes(fleet_key)?;
    if signer.verifier().public_key_bytes() != manifest.fleet_runtime_public_key {
        return Err(RuntimeError::TargetIdentity);
    }
    let (generation, mut keys) = if let Some(previous) = &manifest.emergency_delivery {
        let (overlay, keys) = signer
            .verifier()
            .verify_emergency_overlay_keys(&previous.signed_overlay, &previous.deny_keys)?;
        if overlay.fleet_id != manifest.fleet_id || overlay.signer_id != manifest.fleet_signer_id {
            return Err(RuntimeError::TargetIdentity);
        }
        if overlay.issued_at_ns > now_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        (overlay.generation, keys)
    } else {
        (0, BTreeSet::new())
    };
    if !keys.insert(format!("urn:openpc:resource:{}", manifest.capsule_id)) {
        return Ok(None);
    }
    let deny_keys = encode_emergency_deny_keys(&keys)?;
    let overlay = EmergencyDenyOverlay {
        overlay_id: format!("cigl-source-invalidation:{}", manifest.capsule_id),
        fleet_id: manifest.fleet_id.clone(),
        generation: generation
            .checked_add(1)
            .ok_or(RuntimeError::BudgetExhausted)?,
        issued_at_ns: now_ns,
        hard_expiry_ns: expires_at_ns,
        deny_key_set_digest: Digest::of(&deny_keys),
        signer_id: manifest.fleet_signer_id.clone(),
    };
    Ok(Some(TargetEmergencyDelivery {
        signed_overlay: signer.sign_emergency_overlay(&overlay)?,
        deny_keys,
    }))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBootstrapManifest {
    pub version: u32,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_runtime_id: String,
    pub fleet_id: String,
    pub fleet_signer_id: String,
    pub agent_signer_id: String,
    pub authority_signer_id: String,
    pub fleet_runtime_public_key: Vec<u8>,
    pub identity_runtime_public_key: Vec<u8>,
    pub fact_verify_key: Vec<u8>,
    pub fact_verify_key_id: String,
    pub contract_set_manifest_digest: Digest,
    pub schema_registry_digest: Digest,
    pub cose_purpose_registry_digest: Digest,
    pub complete_component_set_digest: Digest,
    pub capsule_id: String,
    pub capsule_generation: u64,
    pub capsule_digest: Digest,
    pub identity_profile_digest: Digest,
    pub mrpc_runtime_profile: Vec<u8>,
    pub routing_source: Vec<u8>,
    pub certification_source: Vec<u8>,
    pub protected_class_set_digest: Digest,
    /// The active capsule carries only dedicated indexer restrictions and
    /// admits no invocation route or Fact publication.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_delivery: Option<TargetEmergencyDelivery>,
    /// Signed local process handoff. This only stops serving; the existing
    /// one-use activation token remains necessary to change journal custody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_for_work: Option<String>,
    /// Original custody and workload identity, resolved by the canonical worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_disposition: Option<TargetDispositionBootstrap>,
}

impl TargetBootstrapManifest {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.capsule_generation == 0
            || (self.source_only
                && (!self.mrpc_runtime_profile.is_empty()
                    || !self.routing_source.is_empty()
                    || !self.certification_source.is_empty()))
        {
            return Err("target bootstrap manifest rejected".into());
        }
        if let Some(binding) = &self.target_disposition {
            binding
                .validate(self)
                .map_err(|_| "target disposition bootstrap rejected")?;
        }
        if let Some(work) = &self.suspended_for_work {
            let id =
                uuid::Uuid::parse_str(work).map_err(|_| "target suspension identity rejected")?;
            if id.get_version_num() != 7 || id.to_string() != *work {
                return Err("target suspension identity rejected".into());
            }
        }
        Ok(())
    }

    pub fn require_serving(&self) -> RuntimeResult<()> {
        if self.suspended_for_work.is_some() {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        Ok(())
    }
}

pub struct BootstrapArtifactAdmission;

impl ArtifactAdmission for BootstrapArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| RuntimeError::BudgetExhausted)?;
        let expected_schema = match component.component_id.as_str() {
            "openpc.runtime.configuration" => 3101,
            "openpc.runtime.policy" => 3102,
            "openpc.runtime.provider" => 3103,
            "openpc.runtime.indexer-profile" => 3104,
            "openpc.runtime.projection" => 3105,
            "openpc.runtime.mrpc-profile" => 3106,
            "openpc.runtime.routing-source" => 3107,
            "openpc.runtime.routing-authority" => 3108,
            "openpc.runtime.certification-source" => 3109,
            "openpc.runtime.certification-authority" => 3110,
            _ => return Err(RuntimeError::InvalidAuthorization),
        };
        if component.component_type != component.component_id
            || component.schema_id != expected_schema
            || component.schema_version != 1
            || !component.required
            || component.size_bytes != size_bytes
            || Digest::of(bytes) != component.content_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(())
    }
}

/// Replays both the current governed generation and its bounded bootstrap
/// predecessor. A capsule carrying Identity's primary manifest must traverse
/// the governed owner chain and can never fall back to the bootstrap allowlist.
pub struct GovernedOrBootstrapAdmission {
    pub governed: Arc<dyn ArtifactAdmission>,
}

impl ArtifactAdmission for GovernedOrBootstrapAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        BootstrapArtifactAdmission.validate(component, bytes)
    }

    fn validate_component_in_bundle(
        &self,
        capsule: &openpc_runtime_agent::RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if capsule
            .artifact_components
            .iter()
            .any(|candidate| candidate.schema_id == 3004)
        {
            self.governed
                .validate_component_in_bundle(capsule, component, artifacts)
        } else {
            BootstrapArtifactAdmission.validate_component_in_bundle(capsule, component, artifacts)
        }
    }

    fn validate_bundle(
        &self,
        capsule: &openpc_runtime_agent::RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if capsule
            .artifact_components
            .iter()
            .any(|candidate| candidate.schema_id == 3004)
        {
            self.governed.validate_bundle(capsule, artifacts)
        } else {
            BootstrapArtifactAdmission.validate_bundle(capsule, artifacts)
        }
    }
}

pub fn write_target_bootstrap(
    directory: &Path,
    manifest: TargetBootstrapManifest,
    fleet_key: [u8; 32],
) -> Result<(), String> {
    manifest.validate()?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|_| "target bootstrap directory unavailable")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| "target bootstrap directory permissions unavailable")?;
    let signed = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, fleet_key)
        .map_err(|_| "target bootstrap signer unavailable")?
        .sign(manifest)
        .map_err(|_| "target bootstrap signing rejected")?;
    let bytes = serde_json::to_vec(&signed).map_err(|_| "target bootstrap encoding rejected")?;
    if bytes.len() > MAXIMUM_BOOTSTRAP_BYTES {
        return Err("target bootstrap size rejected".into());
    }
    let temporary = directory.join("bootstrap.json.next");
    let current = directory.join("bootstrap.json");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    let mut file = options
        .open(&temporary)
        .map_err(|_| "target bootstrap staging unavailable")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "target bootstrap staging failed")?;
    fs::rename(&temporary, &current).map_err(|_| "target bootstrap cutover failed")?;
    fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "target bootstrap directory sync failed".to_owned())
}

pub fn retire_target_bootstrap(directory: &Path) -> Result<(), String> {
    let current = directory.join("bootstrap.json");
    match fs::remove_file(&current) {
        Ok(()) => fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| "target bootstrap directory sync failed".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("target bootstrap retirement failed".into()),
    }
}

pub fn read_target_bootstrap(
    directory: &Path,
    fleet_public_key: &[u8],
) -> Result<TargetBootstrapManifest, String> {
    read_target_bootstrap_with_custody(directory, fleet_public_key).map(|(manifest, _)| manifest)
}

/// Return the exact authenticated bytes for an original-custody transition.
/// Callers retain these bytes before replacing the current host pointer.
pub fn read_target_bootstrap_with_custody(
    directory: &Path,
    fleet_public_key: &[u8],
) -> Result<(TargetBootstrapManifest, Vec<u8>), String> {
    let mut bytes = Vec::new();
    fs::File::open(directory.join("bootstrap.json"))
        .map_err(|_| "target bootstrap unavailable")?
        .take((MAXIMUM_BOOTSTRAP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "target bootstrap unavailable")?;
    if bytes.is_empty() || bytes.len() > MAXIMUM_BOOTSTRAP_BYTES {
        return Err("target bootstrap size rejected".into());
    }
    let signed: SignedEnvelope<TargetBootstrapManifest> =
        serde_json::from_slice(&bytes).map_err(|_| "target bootstrap encoding rejected")?;
    PurposeVerifier::from_sec1_bytes(TARGET_BOOTSTRAP_PURPOSE, fleet_public_key)
        .map_err(|_| "target bootstrap trust rejected")?
        .verify(&signed)
        .map_err(|_| "target bootstrap signature rejected")?;
    signed.claims.validate()?;
    Ok((signed.claims, bytes))
}

/// Poll the signed control delivery without opening another process's journal.
/// A running target may receive restrictions only for its exact bootstrapped
/// configuration. A changed or retired bootstrap stops readiness; activation
/// of another generation remains with the existing activation owner.
pub fn refresh_target_restrictions(
    agent: &openpc_runtime_agent::RuntimeAgent,
    expected: &TargetBootstrapManifest,
    directory: &Path,
    fleet_public_key: &[u8],
    now_ns: u64,
) -> RuntimeResult<()> {
    let result = (|| {
        let mut delivered = read_target_bootstrap(directory, fleet_public_key)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        delivered.require_serving()?;
        expected.require_serving()?;
        let emergency = delivered.emergency_delivery.take();
        if expected.emergency_delivery.is_some() || delivered != *expected {
            return Err(RuntimeError::GenerationMismatch);
        }
        let active = agent
            .active_canonical_generation()?
            .ok_or(RuntimeError::GenerationMismatch)?;
        if active.0 != expected.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(emergency) = emergency {
            emergency.install(agent, now_ns)?;
        }
        Ok(())
    })();
    if result.is_err() {
        agent.fence_target_disposition()?;
    }
    result
}

#[derive(Clone)]
pub struct GovernedOwnerTrust<'a> {
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub target_runtime_id: &'a str,
    pub authority_signer_id: &'a str,
    pub authority_public_key: &'a [u8],
    pub identity_runtime_public_key: &'a [u8],
    pub identity_profile_digest: Digest,
    pub fact_verify_key: &'a [u8],
    pub fact_verify_key_id: &'a str,
    pub mrpc_runtime_profile: &'a [u8],
}

pub struct GovernedRuntimeOwners {
    pub identity: Arc<IdentityArtifactAdmission>,
    pub identity_assertions: Arc<IdentityAssertionVerifier>,
    pub invocation: Arc<InvocationArtifactAdmission>,
    pub invocation_profile: Arc<InvocationProfileAdmission>,
    pub invocation_profile_material: InvocationProfileMaterial,
    pub facts: Arc<FactArtifactAdmission>,
    pub mrpc: Arc<MrpcProfileAdmission>,
    pub routing: Arc<RoutingArtifactAdmission>,
}

pub struct GovernedSourceOwners {
    pub identity: Arc<IdentityArtifactAdmission>,
    pub indexer: Arc<IndexerArtifactAdmission>,
}

pub fn build_governed_source_owners(
    trust: GovernedOwnerTrust<'_>,
    observe: impl Fn(&'static str, Arc<dyn ArtifactAdmission>) -> Arc<dyn ArtifactAdmission>,
) -> Result<GovernedSourceOwners, String> {
    let indexer = indexer_admission(
        openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(
            trust.authority_public_key,
        )
        .map_err(|_| "source authority verifier unavailable")?,
        trust.participant_id,
        trust.privacy_domain_id,
        trust.authority_signer_id,
        Arc::new(RejectUnknownArtifact),
    )?;
    let identity = Arc::new(
        IdentityArtifactAdmission::new(
            IdentityAssertionVerifier::new(&[trust.identity_runtime_public_key.to_vec()], 60_000)
                .map_err(|_| "source identity verification trust rejected")?,
            RuntimeIdentityContext {
                participant_id: trust.participant_id.into(),
                privacy_domain_id: trust.privacy_domain_id.into(),
                target_runtime_id: trust.target_runtime_id.into(),
            },
            trust.identity_profile_digest,
            format!(
                "sha256:{}",
                Digest::of(trust.identity_runtime_public_key).as_str()
            ),
            8 * 1024 * 1024,
            observe("indexer", indexer.clone()),
        )
        .map_err(|_| "source identity custody construction rejected")?,
    );
    Ok(GovernedSourceOwners { identity, indexer })
}

struct RejectUnknownArtifact;
impl ArtifactAdmission for RejectUnknownArtifact {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidInput)
    }
}

fn source_binding(artifact_id: &str, definition: &[u8], signer_id: &str) -> AuthoritySourceBinding {
    AuthoritySourceBinding {
        artifact_id: artifact_id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(definition),
        signer_id: signer_id.into(),
        maximum_source_bytes: 4 * 1024 * 1024,
    }
}

fn indexer_admission(
    verifier: openpc_runtime_agent::RuntimeWireVerifier,
    participant: &str,
    privacy: &str,
    signer: &str,
    remaining: Arc<dyn ArtifactAdmission>,
) -> Result<Arc<IndexerArtifactAdmission>, String> {
    Ok(Arc::new(
        IndexerArtifactAdmission::new(
            verifier,
            participant.into(),
            privacy.into(),
            source_binding(
                INDEXER_CONFIGURATION_ID,
                INDEXER_CONFIGURATION_DEFINITION,
                signer,
            ),
            source_binding(INDEXER_POLICY_ID, INDEXER_POLICY_DEFINITION, signer),
            remaining,
        )
        .map_err(|_| "source policy custody construction rejected")?,
    ))
}

pub(crate) fn source_policy_workload(
    verifier: openpc_runtime_agent::RuntimeWireVerifier,
    participant: &str,
    privacy: &str,
    signer: &str,
    capsule: &openpc_runtime_agent::RuntimeCapsule,
    artifacts: &BTreeMap<Digest, Vec<u8>>,
) -> Result<String, String> {
    let owner = indexer_admission(
        verifier,
        participant,
        privacy,
        signer,
        Arc::new(RejectUnknownArtifact),
    )?;
    let (policies, _) = owner
        .admit_policies(capsule, artifacts)
        .map_err(|_| "source policy custody rejected")?;
    Ok(policies.workload_id().into())
}

pub fn build_governed_runtime_owners(
    trust: GovernedOwnerTrust<'_>,
    fact_bound: bool,
    observe: impl Fn(&'static str, Arc<dyn ArtifactAdmission>) -> Arc<dyn ArtifactAdmission>,
) -> Result<GovernedRuntimeOwners, String> {
    let authority_verifier = openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(
        trust.authority_public_key,
    )
    .map_err(|_| "runtime authority verifier unavailable")?;
    let profile_verifier =
        pc_policy_core::runtime_wire::Verifier::from_public_key_bytes(trust.authority_public_key)
            .map_err(|_| "runtime profile verifier unavailable")?;
    let invocation = Arc::new(
        InvocationArtifactAdmission::new(
            authority_verifier.clone(),
            trust.participant_id.into(),
            trust.privacy_domain_id.into(),
            source_binding(
                "openpc.invocation.configuration",
                b"openpc.invocation.configuration-source.v1",
                trust.authority_signer_id,
            ),
            source_binding(
                "openpc.invocation.policy",
                b"openpc.invocation.policy-source.v1",
                trust.authority_signer_id,
            ),
            observe("unknown-artifact", Arc::new(RejectUnknownArtifact)),
        )
        .map_err(|_| "invocation custody construction rejected")?,
    );
    let fact_verifier =
        FactSignatureVerifier::from_key_identifier(trust.fact_verify_key_id, trust.fact_verify_key)
            .map_err(|_| "fact custody trust rejected")?;
    let facts = Arc::new(
        FactArtifactAdmission::new(
            authority_verifier.clone(),
            fact_verifier,
            trust.participant_id.into(),
            trust.privacy_domain_id.into(),
            source_binding(
                "openpc.fact.signed-shard",
                b"openpc.fact.signed-shard-source.v1",
                trust.authority_signer_id,
            ),
            observe("invocation", invocation.clone()),
        )
        .map_err(|_| "fact custody construction rejected")?,
    );
    let routing_tail = if fact_bound {
        observe("fact", facts.clone())
    } else {
        observe("invocation", invocation.clone())
    };
    let routing = Arc::new(
        RoutingArtifactAdmission::new(
            authority_verifier,
            source_binding(
                ROUTING_ARTIFACT_ID,
                ROUTING_DEFINITION,
                trust.authority_signer_id,
            ),
            source_binding(
                CERTIFICATION_ARTIFACT_ID,
                CERTIFICATION_DEFINITION,
                trust.authority_signer_id,
            ),
            trust.participant_id.into(),
            trust.privacy_domain_id.into(),
            routing_tail,
        )
        .map_err(|_| "routing custody construction rejected")?,
    );
    let mrpc_profile = openpc_multi_rpc::runtime_profile::MrpcRuntimeProfile::verify(
        &profile_verifier,
        trust.mrpc_runtime_profile,
    )
    .map_err(|_| "mRPC runtime profile rejected")?;
    let mrpc = Arc::new(
        MrpcProfileAdmission::new(
            profile_verifier.clone(),
            MrpcProfileTrust {
                profile_id: mrpc_profile.profile_id.clone(),
                signer_id: mrpc_profile.signer_id.clone(),
                capability_registry_digest: mrpc_profile.capability_registry_digest.clone(),
                endpoint_role_rules_digest: mrpc_profile.endpoint_role_rules_digest.clone(),
                coherence_rules_digest: mrpc_profile.coherence_rules_digest.clone(),
            },
            observe("routing", routing.clone()),
        )
        .map_err(|_| "mRPC custody construction rejected")?,
    );
    let deployment = mrpc_profile.profile_id == "openpc-r1-single-exact-deployment";
    let registry = mrpc_profile.capability_registry_digest;
    let mut invocation_profile_material = InvocationProfileMaterial {
        profile_id: "openpc-r1-contract-read".into(),
        release: "openpc-r1".into(),
        capability_registry_id: "pc.rpc.invocation-capabilities@2".into(),
        capability_registry_digest: registry,
        request_form_registry_id: "pc.rpc.invocation-request-forms@2".into(),
        request_form_registry_digest: Digest::of(b"openpc.rpc.request-forms.v2"),
        error_registry_id: "pc.rpc.errors@2".into(),
        error_registry_digest: Digest::of(b"openpc.rpc.errors.v2"),
        required_capabilities: vec!["CALL_RESULT_DISCLOSURE".into()],
        optional_capabilities: vec!["GAS_ESTIMATE_DISCLOSURE".into()],
        deferred_capabilities: vec!["MULTI_CALL_SIMULATION_DISCLOSURE".into()],
        unsupported_capabilities: vec!["SIGNED_TRANSACTION_SUBMISSION".into()],
        disclosure_policy_digest:
            openpc_runtime_agent::provider_response::call_result_disclosure_policy_digest(),
        transaction_policy_digest: Digest::of(b"openpc.rpc.read-only-transactions.v1"),
        composition_rule_digest: Digest::of(b"openpc.rpc.single-call-composition.v1"),
        state_anchor_policy_digest: Digest::of(b"openpc.rpc.hash-pinned-anchor.v1"),
        fault_precedence_digest: Digest::of(b"openpc.rpc.fail-closed-faults.v1"),
        supported_request_forms: vec!["R1B_SINGLE_CONTRACT_CALL_V2".into()],
        resource_limits_digest: Digest::of(b"openpc.rpc.local-bounds.v1"),
        capability_ceiling: "contract-read".into(),
    };
    if deployment {
        invocation_profile_material.profile_id = "openpc-r1-managed-deployment".into();
        invocation_profile_material.required_capabilities =
            vec!["SIGNED_TRANSACTION_SUBMISSION".into()];
        invocation_profile_material.optional_capabilities =
            vec!["OPERATION_STATUS_DISCLOSURE".into()];
        invocation_profile_material.unsupported_capabilities = vec![
            "CALL_RESULT_DISCLOSURE".into(),
            "GAS_ESTIMATE_DISCLOSURE".into(),
            "ACCESS_LIST_DISCLOSURE".into(),
            "UNSIGNED_TRANSACTION_PREPARATION".into(),
        ];
        invocation_profile_material.supported_request_forms = vec![
            "R1B_SIGNED_CONTRACT_TRANSACTION_V2".into(),
            "R1B_OWNED_OPERATION_STATUS_V2".into(),
        ];
        invocation_profile_material.transaction_policy_digest =
            Digest::of(b"openpc.rpc.deployment-transaction-policy.v1");
        invocation_profile_material.composition_rule_digest =
            Digest::of(b"openpc.rpc.managed-single-deployment.v1");
        invocation_profile_material.capability_ceiling = "managed-deployment".into();
    }
    let invocation_profile = Arc::new(
        InvocationProfileAdmission::new(
            profile_verifier,
            InvocationProfileTrust {
                profile_id: invocation_profile_material.profile_id.clone(),
                release: invocation_profile_material.release.clone(),
                capability_registry_id: invocation_profile_material.capability_registry_id.clone(),
                request_form_registry_id: invocation_profile_material
                    .request_form_registry_id
                    .clone(),
                error_registry_id: invocation_profile_material.error_registry_id.clone(),
            },
            observe("mrpc-profile", mrpc.clone()),
        )
        .map_err(|_| "invocation profile custody construction rejected")?,
    );
    let identity_assertions = Arc::new(
        IdentityAssertionVerifier::new(&[trust.identity_runtime_public_key.to_vec()], 60_000)
            .map_err(|_| "identity runtime verification trust rejected")?,
    );
    let identity = Arc::new(
        IdentityArtifactAdmission::new(
            IdentityAssertionVerifier::new(&[trust.identity_runtime_public_key.to_vec()], 60_000)
                .map_err(|_| "identity runtime verification trust rejected")?,
            RuntimeIdentityContext {
                participant_id: trust.participant_id.into(),
                privacy_domain_id: trust.privacy_domain_id.into(),
                target_runtime_id: trust.target_runtime_id.into(),
            },
            trust.identity_profile_digest,
            format!(
                "sha256:{}",
                Digest::of(trust.identity_runtime_public_key).as_str()
            ),
            8 * 1024 * 1024,
            observe("invocation-profile", invocation_profile.clone()),
        )
        .map_err(|_| "identity custody construction rejected")?,
    );
    Ok(GovernedRuntimeOwners {
        identity,
        identity_assertions,
        invocation,
        invocation_profile,
        invocation_profile_material,
        facts,
        mrpc,
        routing,
    })
}

pub fn passthrough_admission(
    _: &'static str,
    admission: Arc<dyn ArtifactAdmission>,
) -> Arc<dyn ArtifactAdmission> {
    admission
}

pub fn artifact_closure(
    admission: &dyn ArtifactAdmission,
    capsule: &openpc_runtime_agent::RuntimeCapsule,
    artifacts: &BTreeMap<Digest, Vec<u8>>,
) -> RuntimeResult<()> {
    let verified = admission.validate_bundle(capsule, artifacts)?;
    if verified == artifacts.keys().cloned().collect() {
        Ok(())
    } else {
        Err(RuntimeError::InvalidInput)
    }
}

#[cfg(test)]
#[path = "runtime_target_restriction_tests.rs"]
mod restriction_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_bootstrap_is_atomic_and_bound_to_fleet_trust() {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("target-bootstrap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let signer = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [31; 32]).unwrap();
        let manifest = TargetBootstrapManifest {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_runtime_id: "target".into(),
            fleet_id: "fleet".into(),
            fleet_signer_id: "fleet-signer".into(),
            agent_signer_id: "agent-signer".into(),
            authority_signer_id: "worker".into(),
            fleet_runtime_public_key: vec![8; 32],
            identity_runtime_public_key: vec![9; 44],
            fact_verify_key: vec![10; 65],
            fact_verify_key_id: "fact-signer".into(),
            contract_set_manifest_digest: Digest::of(b"contracts"),
            schema_registry_digest: Digest::of(b"schemas"),
            cose_purpose_registry_digest: Digest::of(b"purposes"),
            complete_component_set_digest: Digest::of(b"components"),
            capsule_id: "capsule".into(),
            capsule_generation: 2,
            capsule_digest: Digest::of(b"capsule"),
            identity_profile_digest: Digest::of(b"identity"),
            mrpc_runtime_profile: vec![1, 2, 3],
            routing_source: vec![4, 5, 6],
            certification_source: vec![7, 8, 9],
            protected_class_set_digest: Digest::of(b"classes"),
            source_only: false,
            emergency_delivery: None,
            suspended_for_work: None,
            target_disposition: None,
        };
        write_target_bootstrap(&root, manifest.clone(), [31; 32]).unwrap();
        assert_eq!(
            read_target_bootstrap(&root, &signer.verifier().sec1_bytes()).unwrap(),
            manifest
        );
        let foreign = PurposeSigner::from_secret_bytes(TARGET_BOOTSTRAP_PURPOSE, [32; 32]).unwrap();
        assert!(read_target_bootstrap(&root, &foreign.verifier().sec1_bytes()).is_err());
        let path = root.join("bootstrap.json");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(read_target_bootstrap(&root, &signer.verifier().sec1_bytes()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn target_bootstrap_retirement_is_durable_and_idempotent() {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "target-bootstrap-retirement-{}",
                std::process::id()
            ));
        let _ = fs::remove_dir_all(&root);
        let manifest = TargetBootstrapManifest {
            version: 1,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            target_runtime_id: "target".into(),
            fleet_id: "fleet".into(),
            fleet_signer_id: "fleet-signer".into(),
            agent_signer_id: "agent-signer".into(),
            authority_signer_id: "worker".into(),
            fleet_runtime_public_key: vec![8; 32],
            identity_runtime_public_key: vec![9; 44],
            fact_verify_key: vec![10; 65],
            fact_verify_key_id: "fact-signer".into(),
            contract_set_manifest_digest: Digest::of(b"contracts"),
            schema_registry_digest: Digest::of(b"schemas"),
            cose_purpose_registry_digest: Digest::of(b"purposes"),
            complete_component_set_digest: Digest::of(b"components"),
            capsule_id: "capsule".into(),
            capsule_generation: 2,
            capsule_digest: Digest::of(b"capsule"),
            identity_profile_digest: Digest::of(b"identity"),
            mrpc_runtime_profile: vec![1, 2, 3],
            routing_source: vec![4, 5, 6],
            certification_source: vec![7, 8, 9],
            protected_class_set_digest: Digest::of(b"classes"),
            source_only: false,
            emergency_delivery: None,
            suspended_for_work: None,
            target_disposition: None,
        };
        write_target_bootstrap(&root, manifest, [31; 32]).unwrap();

        retire_target_bootstrap(&root).unwrap();
        assert!(!root.join("bootstrap.json").exists());
        retire_target_bootstrap(&root).unwrap();

        fs::remove_dir_all(root).unwrap();
    }
}

mod journal;
pub use journal::GovernedJournalAdmission;
