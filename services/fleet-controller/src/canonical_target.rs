//! Local control coordination over the real target custody and ADS owners.
//! No compatibility envelope is transmitted. A primary receipt establishes
//! target-local activation only, never independently observed request effect.
use crate::{
    FleetController, REQUIRED_XDS_TYPES, TargetIdentity,
    ads::AdsService,
    envoy_resources::{ProtectedListenerConfig, protected_resources},
};
use openpc_runtime_agent::{RuntimeAgent, RuntimeCapsule};
use pc_runtime_types::{DesiredGeneration, Digest, RuntimeError, RuntimeResult, TargetState};
use std::{collections::BTreeMap, sync::Arc};

/// Created only after actual target preparation and publication of the exact
/// protected listener configuration. It cannot be supplied as request metadata.
pub struct PreparedCanonicalTarget {
    identity: TargetIdentity,
    occurrence_id: String,
    capsule: RuntimeCapsule,
    version: Digest,
    activation_token: std::sync::Mutex<Option<Vec<u8>>>,
}
impl PreparedCanonicalTarget {
    pub fn capsule_digest(&self) -> RuntimeResult<Digest> {
        self.capsule.digest()
    }
    pub fn xds_version(&self) -> &Digest {
        &self.version
    }
}
pub struct CanonicalTargetCoordinator {
    fleet: Arc<FleetController>,
    agent: Arc<RuntimeAgent>,
    ads: AdsService,
}
impl CanonicalTargetCoordinator {
    pub fn new(fleet: Arc<FleetController>, agent: Arc<RuntimeAgent>) -> Self {
        Self {
            ads: AdsService::new(Arc::clone(&fleet)),
            fleet,
            agent,
        }
    }
    pub fn with_ads(
        fleet: Arc<FleetController>,
        agent: Arc<RuntimeAgent>,
        ads: AdsService,
    ) -> RuntimeResult<Self> {
        if !ads.belongs_to(&fleet) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self { fleet, agent, ads })
    }
    pub fn ads(&self) -> AdsService {
        self.ads.clone()
    }
    /// Caller is the release owner. Target custody independently verifies the
    /// capsule, installed trust and every artifact before ADS publication.
    pub fn prepare(
        &self,
        signed_capsule: Vec<u8>,
        artifacts: BTreeMap<Digest, Vec<u8>>,
        occurrence_id: &str,
        config: ProtectedListenerConfig<'_>,
        now_ns: u64,
    ) -> RuntimeResult<PreparedCanonicalTarget> {
        let resources = protected_resources(config)?;
        let version = AdsService::resource_version(&resources)?;
        self.prepare_versioned(
            signed_capsule,
            artifacts,
            occurrence_id,
            config,
            version,
            now_ns,
        )
    }

    /// Prepare a generation whose public xDS version is the durable deployment
    /// identity selected by the configuration owner. Resource bytes are still
    /// decoded and target-scoped by ADS before publication; the opaque version
    /// cannot replace either that validation or the authenticated ACK barrier.
    pub fn prepare_versioned(
        &self,
        signed_capsule: Vec<u8>,
        artifacts: BTreeMap<Digest, Vec<u8>>,
        occurrence_id: &str,
        config: ProtectedListenerConfig<'_>,
        version: Digest,
        now_ns: u64,
    ) -> RuntimeResult<PreparedCanonicalTarget> {
        let capsule = self
            .fleet
            .canonical_fleet_verifier
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .verify_capsule(&signed_capsule)?;
        if capsule.target_runtime_id != config.target_id
            || capsule.capsule_id != config.capsule_id
            || capsule.generation != config.capsule_generation
            || occurrence_id.is_empty()
            || occurrence_id.len() > 160
            || now_ns < capsule.not_before_ns
            || now_ns >= capsule.hard_expiry_ns
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let resources = protected_resources(config)?;
        let digest = capsule.digest()?;
        let target_id = capsule.target_runtime_id.clone();
        let identity = self
            .fleet
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .get(&capsule.target_runtime_id)
            .ok_or(RuntimeError::TargetIdentity)?
            .identity
            .clone();
        self.fleet.command_generation(DesiredGeneration {
            occurrence_id: occurrence_id.into(),
            target_id: capsule.target_runtime_id.clone(),
            capsule_digest: digest.clone(),
            xds_snapshot_digest: version.clone(),
            expected_previous_generation_digest: capsule.previous_capsule_digest.clone(),
            expires_at_ms: capsule.hard_expiry_ns / 1_000_000,
        })?;
        let result = (|| {
            let prepared_digest =
                match self
                    .agent
                    .prepare_capsule(signed_capsule.clone(), artifacts.clone(), now_ns)
                {
                    Ok(prepared) => prepared,
                    // A restarted Fleet must republish and obtain a fresh ACK
                    // barrier. The target's verified active journal can recover
                    // custody, but a historical receipt for an older generation
                    // cannot prepare that generation again.
                    Err(RuntimeError::Replay | RuntimeError::GenerationMismatch) => self
                        .agent
                        .recover_active_capsule(signed_capsule, artifacts, now_ns)?,
                    Err(error) => return Err(error),
                };
            if prepared_digest != digest {
                return Err(RuntimeError::GenerationMismatch);
            }
            self.fleet.check_current_peer(&identity)?;
            self.fleet
                .accept_prepared(&capsule.target_runtime_id, &digest)?;
            self.ads
                .publish_version(&capsule.target_runtime_id, resources, version.clone())?;
            Ok(PreparedCanonicalTarget {
                identity,
                occurrence_id: occurrence_id.into(),
                capsule,
                version,
                activation_token: std::sync::Mutex::new(None),
            })
        })();
        // A failed preparation/publication cannot remain a readiness claim.
        if result.is_err() {
            let mut targets = self
                .fleet
                .targets
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            if let Some(target) = targets.get_mut(&target_id)
                && target
                    .desired
                    .as_ref()
                    .is_some_and(|d| d.capsule_digest == digest)
                && matches!(
                    target.state,
                    TargetState::Staging | TargetState::Prepared | TargetState::XdsPending
                )
            {
                FleetController::transition(target, TargetState::Failed)?;
            }
        }
        result
    }
    pub fn activate(
        &self,
        prepared: &PreparedCanonicalTarget,
        now_ns: u64,
    ) -> RuntimeResult<Vec<u8>> {
        let digest = prepared.capsule.digest()?;
        // Hold Fleet's generation/credential/ACK fence through target fsync and
        // receipt verification. No newer publication can borrow this barrier.
        let mut targets = self
            .fleet
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&prepared.identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.identity != prepared.identity
            || !matches!(
                target.state,
                TargetState::XdsAckedNotActive | TargetState::Activating
            )
            || desired.capsule_digest != digest
            || desired.xds_snapshot_digest != prepared.version
            || target
                .snapshot
                .as_ref()
                .is_none_or(|s| s.version_digest != prepared.version)
            || target.acked_types.len() != REQUIRED_XDS_TYPES.len()
            || target.quarantined_versions.contains(&prepared.version)
            || now_ns < prepared.capsule.not_before_ns
            || now_ns >= prepared.capsule.hard_expiry_ns
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let signer = self
            .fleet
            .canonical_fleet_signer
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let signed_token = {
            let mut issued = prepared
                .activation_token
                .lock()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            if let Some(token) = issued.as_ref() {
                token.clone()
            } else {
                let token = openpc_runtime_agent::RuntimeActivationToken {
                    token_id: uuid::Uuid::now_v7().to_string(),
                    target_runtime_id: prepared.identity.target_id.clone(),
                    occurrence_id: prepared.occurrence_id.clone(),
                    desired_generation_digest: digest.clone(),
                    xds_version_digest: prepared.version.clone(),
                    expected_previous_generation_digest: prepared
                        .capsule
                        .previous_capsule_digest
                        .clone(),
                    issued_at_ns: now_ns,
                    expires_at_ns: now_ns.saturating_add(30_000_000_000),
                };
                let signed = signer.sign_activation_token(&token)?;
                *issued = Some(signed.clone());
                signed
            }
        };
        let signed = self
            .agent
            .activate_capsule_authorized(&signed_token, now_ns)?;
        let receipt = self
            .fleet
            .canonical_receipt_verifier
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .verify_receipt(&signed)?;
        if receipt.target_runtime_id != target.identity.target_id
            || receipt.capsule_digest != digest
            || receipt.contract_set_manifest_digest != prepared.capsule.contract_set_manifest_digest
            || receipt.complete_component_set_digest
                != prepared.capsule.complete_component_set_digest
            || receipt.status != 1
            || receipt.reason_code != "ACTIVE_LOCAL"
            || receipt.observed_at_ns > now_ns
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if target.state == TargetState::XdsAckedNotActive {
            FleetController::transition(target, TargetState::Activating)?;
        }
        target.canonical_activation_receipt = Some(receipt);
        Ok(signed)
    }
}

impl FleetController {
    /// Observe an already committed effect after republishing the desired
    /// resources and receiving a fresh authenticated ACK barrier. The retained
    /// token binds the original occurrence; no new activation token is issued.
    pub fn replay_canonical_activation(
        &self,
        identity: &TargetIdentity,
        signed_receipt: &[u8],
        signed_token: &[u8],
    ) -> RuntimeResult<()> {
        let receipt = self
            .canonical_receipt_verifier
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .verify_receipt(signed_receipt)?;
        let token = self
            .canonical_fleet_verifier
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .verify_activation_token(signed_token)?;
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.identity != *identity
            || !matches!(
                target.state,
                TargetState::XdsAckedNotActive
                    | TargetState::Activating
                    | TargetState::ActiveMatched
            )
            || target.acked_types.len() != REQUIRED_XDS_TYPES.len()
            || target
                .quarantined_versions
                .contains(&desired.xds_snapshot_digest)
            || target
                .snapshot
                .as_ref()
                .is_none_or(|s| s.version_digest != desired.xds_snapshot_digest)
            || receipt.target_runtime_id != identity.target_id
            || receipt.capsule_digest != desired.capsule_digest
            || receipt.status != 1
            || receipt.reason_code != "ACTIVE_LOCAL"
            || token.target_runtime_id != identity.target_id
            || token.desired_generation_digest != desired.capsule_digest
            || token.occurrence_id != desired.occurrence_id
            || token.xds_version_digest != desired.xds_snapshot_digest
            || token.expected_previous_generation_digest
                != desired.expected_previous_generation_digest
            || receipt.observed_at_ns < token.issued_at_ns
            || receipt.observed_at_ns >= token.expires_at_ns
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if target.state == TargetState::XdsAckedNotActive {
            Self::transition(target, TargetState::Activating)?;
        }
        target.canonical_activation_receipt = Some(receipt);
        Ok(())
    }
}
