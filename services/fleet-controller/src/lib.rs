#![forbid(unsafe_code)]

//! Target-scoped SOTW xDS and activation convergence controller.

pub mod ads;
pub mod ads_discovery;
mod ads_server;
pub mod ads_wire;
pub mod canonical_target;
pub mod cigl_publication;
pub mod configuration_result;
pub mod contract_policy;
pub mod deployment_policy;
pub mod deployment_projection;
pub mod deployment_worker;
pub mod envoy_resources;
pub mod fact_admission;
pub mod indexer_policy;
pub mod indexer_publication;
pub mod qualified_receipts;
pub mod runtime_artifact_source;
pub mod runtime_configuration_input;
pub mod runtime_tls;
pub mod target_disposition;
pub mod target_disposition_transport;
pub mod visibility_policy;
pub use ads_server::serve_ads;

#[doc(hidden)]
pub mod local_fixture;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use pc_runtime_types::{
    ActivationReceipt, ActivationToken, DesiredGeneration, Digest, PURPOSE_ACTIVATION_RECEIPT_V1,
    PURPOSE_ACTIVATION_TOKEN_V1, PURPOSE_DESIRED_GENERATION_V1, PurposeSigner, PurposeVerifier,
    RuntimeError, RuntimeResult, SignedEnvelope, TargetState,
};
use serde::{Deserialize, Serialize};

pub const REQUIRED_XDS_TYPES: [&str; 4] = [
    "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    "type.googleapis.com/envoy.config.listener.v3.Listener",
    "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetIdentity {
    pub target_id: String,
    pub uri_san: String,
    pub certificate_fingerprint: Digest,
    pub workload_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XdsSnapshot {
    pub target_id: String,
    pub version_digest: Digest,
    pub resources_by_type: BTreeMap<String, Vec<String>>,
}

impl XdsSnapshot {
    pub fn validate_complete(&self) -> RuntimeResult<()> {
        if self.resources_by_type.len() != REQUIRED_XDS_TYPES.len()
            || REQUIRED_XDS_TYPES.iter().any(|resource_type| {
                self.resources_by_type
                    .get(*resource_type)
                    .is_none_or(Vec::is_empty)
            })
            || self
                .resources_by_type
                .values()
                .flatten()
                .any(|name| !name.starts_with(&format!("openpc/{}/", self.target_id)))
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TargetRecord {
    identity: TargetIdentity,
    state: TargetState,
    desired: Option<DesiredGeneration>,
    snapshot: Option<XdsSnapshot>,
    nonce_by_type: BTreeMap<String, String>,
    acked_types: BTreeSet<String>,
    quarantined_versions: BTreeSet<Digest>,
    activation_receipt: Option<ActivationReceipt>,
    canonical_activation_receipt: Option<openpc_runtime_agent::TargetActivationReceipt>,
    request_observed_generation: Option<Digest>,
    heartbeat_generation: Option<Digest>,
    heartbeat_at_ms: Option<u64>,
}

pub struct FleetController {
    fleet_desired_signer: PurposeSigner,
    fleet_activation_signer: PurposeSigner,
    agent_receipt_verifier: PurposeVerifier,
    canonical_fleet_verifier: Option<openpc_runtime_agent::RuntimeWireVerifier>,
    canonical_fleet_signer: Option<openpc_runtime_agent::RuntimeWireSigner>,
    canonical_receipt_verifier: Option<openpc_runtime_agent::RuntimeWireVerifier>,
    targets: Mutex<BTreeMap<String, TargetRecord>>,
    sequence: AtomicU64,
    heartbeat_freshness_ms: u64,
}

impl FleetController {
    fn transition(target: &mut TargetRecord, next: TargetState) -> RuntimeResult<()> {
        if !target.state.allows_transition_to(next) {
            return Err(RuntimeError::InvalidTransition);
        }
        target.state = next;
        Ok(())
    }

    pub fn new(
        fleet_key: [u8; 32],
        agent_receipt_public_key: &[u8],
        heartbeat_freshness_ms: u64,
    ) -> RuntimeResult<Self> {
        Ok(Self {
            fleet_desired_signer: PurposeSigner::from_secret_bytes(
                PURPOSE_DESIRED_GENERATION_V1,
                fleet_key,
            )?,
            fleet_activation_signer: PurposeSigner::from_secret_bytes(
                PURPOSE_ACTIVATION_TOKEN_V1,
                fleet_key,
            )?,
            agent_receipt_verifier: PurposeVerifier::from_sec1_bytes(
                PURPOSE_ACTIVATION_RECEIPT_V1,
                agent_receipt_public_key,
            )?,
            canonical_fleet_verifier: None,
            canonical_fleet_signer: None,
            canonical_receipt_verifier: None,
            targets: Mutex::new(BTreeMap::new()),
            sequence: AtomicU64::new(1),
            heartbeat_freshness_ms,
        })
    }

    /// Primary runtime trust is separate from compatibility command/receipt keys.
    pub fn with_canonical_trust(
        mut self,
        fleet_public_key: &[u8],
        agent_public_key: &[u8],
    ) -> RuntimeResult<Self> {
        self.canonical_fleet_verifier = Some(
            openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(fleet_public_key)?,
        );
        self.canonical_receipt_verifier = Some(
            openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(agent_public_key)?,
        );
        Ok(self)
    }

    pub fn with_canonical_signing(
        mut self,
        fleet_secret: [u8; 32],
        agent_public_key: &[u8],
    ) -> RuntimeResult<Self> {
        let signer = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes(fleet_secret)?;
        self.canonical_fleet_verifier = Some(signer.verifier());
        self.canonical_fleet_signer = Some(signer);
        self.canonical_receipt_verifier = Some(
            openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(agent_public_key)?,
        );
        Ok(self)
    }

    pub fn register_target(
        &self,
        presented: TargetIdentity,
        expected: &TargetIdentity,
    ) -> RuntimeResult<()> {
        if &presented != expected
            || runtime_tls::target_id_from_uri_san(&presented.uri_san)
                != Some(presented.target_id.as_str())
            || presented.workload_epoch == 0
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let mut record = TargetRecord {
            identity: presented,
            state: TargetState::Offline,
            desired: None,
            snapshot: None,
            nonce_by_type: BTreeMap::new(),
            acked_types: BTreeSet::new(),
            quarantined_versions: BTreeSet::new(),
            activation_receipt: None,
            canonical_activation_receipt: None,
            request_observed_generation: None,
            heartbeat_generation: None,
            heartbeat_at_ms: None,
        };
        Self::transition(&mut record, TargetState::Discovered)?;
        self.targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .insert(record.identity.target_id.clone(), record);
        Ok(())
    }

    pub fn command_generation(
        &self,
        desired: DesiredGeneration,
    ) -> RuntimeResult<SignedEnvelope<DesiredGeneration>> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&desired.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        if !matches!(
            target.state,
            TargetState::Discovered
                | TargetState::ActiveMatched
                | TargetState::ActiveMismatch
                | TargetState::Nacked
                | TargetState::Failed
                | TargetState::RolledBack
        ) {
            return Err(RuntimeError::InvalidTransition);
        }
        Self::transition(target, TargetState::Staging)?;
        target.desired = Some(desired.clone());
        target.snapshot = None;
        target.nonce_by_type.clear();
        target.acked_types.clear();
        target.activation_receipt = None;
        target.canonical_activation_receipt = None;
        target.request_observed_generation = None;
        target.heartbeat_generation = None;
        target.heartbeat_at_ms = None;
        self.fleet_desired_signer.sign(desired)
    }

    pub fn accept_prepared(&self, target_id: &str, capsule_digest: &Digest) -> RuntimeResult<()> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state != TargetState::Staging || &desired.capsule_digest != capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        Self::transition(target, TargetState::Prepared)?;
        Ok(())
    }

    pub fn publish_snapshot(
        &self,
        snapshot: XdsSnapshot,
    ) -> RuntimeResult<BTreeMap<String, String>> {
        snapshot.validate_complete()?;
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&snapshot.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state != TargetState::Prepared
            || desired.xds_snapshot_digest != snapshot.version_digest
            || target
                .quarantined_versions
                .contains(&snapshot.version_digest)
        {
            return Err(RuntimeError::XdsQuarantined);
        }
        Self::transition(target, TargetState::XdsPending)?;
        target.nonce_by_type.clear();
        for resource_type in REQUIRED_XDS_TYPES {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
            target.nonce_by_type.insert(
                resource_type.to_owned(),
                format!("local-xds-nonce-{sequence:016x}"),
            );
        }
        target.snapshot = Some(snapshot);
        Ok(target.nonce_by_type.clone())
    }

    /// The transport supplies its authenticated peer, including the current
    /// credential epoch. A resource name or target ID alone never identifies a peer.
    pub fn acknowledge(
        &self,
        identity: &TargetIdentity,
        resource_type: &str,
        version: &Digest,
        nonce: &str,
    ) -> RuntimeResult<TargetState> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        if &target.identity != identity {
            return Err(RuntimeError::TargetIdentity);
        }
        let snapshot = target
            .snapshot
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if snapshot.version_digest != *version
            || target.nonce_by_type.get(resource_type).map(String::as_str) != Some(nonce)
            || !REQUIRED_XDS_TYPES.contains(&resource_type)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if target.state != TargetState::XdsPending {
            // A new authenticated ADS stream acknowledges the same snapshot
            // again. Preserve the completed barrier without activating or
            // renewing anything. Rejected and replacement generations stay closed.
            if target.acked_types.contains(resource_type)
                && matches!(
                    target.state,
                    TargetState::XdsAckedNotActive
                        | TargetState::Activating
                        | TargetState::ActiveMatched
                )
            {
                return Ok(target.state);
            }
            return Err(RuntimeError::GenerationMismatch);
        }
        target.acked_types.insert(resource_type.to_owned());
        if target.acked_types.len() == REQUIRED_XDS_TYPES.len() {
            Self::transition(target, TargetState::XdsAckedNotActive)?;
        }
        Ok(target.state)
    }

    pub fn nack(
        &self,
        identity: &TargetIdentity,
        version: &Digest,
        nonce: &str,
    ) -> RuntimeResult<()> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        if &target.identity != identity {
            return Err(RuntimeError::TargetIdentity);
        }
        let snapshot = target
            .snapshot
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state != TargetState::XdsPending
            || snapshot.version_digest != *version
            || !target
                .nonce_by_type
                .values()
                .any(|expected| expected == nonce)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        target.quarantined_versions.insert(version.clone());
        Self::transition(target, TargetState::Nacked)?;
        Err(RuntimeError::XdsQuarantined)
    }

    pub fn issue_activation_token(
        &self,
        target_id: &str,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> RuntimeResult<SignedEnvelope<ActivationToken>> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state != TargetState::XdsAckedNotActive || lifetime_ms == 0 {
            return Err(RuntimeError::InvalidTransition);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let token = ActivationToken {
            token_id: format!("local-activation-token-{sequence:016x}"),
            occurrence_id: desired.occurrence_id.clone(),
            target_id: target_id.to_owned(),
            capsule_digest: desired.capsule_digest.clone(),
            xds_version_digest: desired.xds_snapshot_digest.clone(),
            expected_previous_generation_digest: desired
                .expected_previous_generation_digest
                .clone(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(lifetime_ms),
        };
        Self::transition(target, TargetState::Activating)?;
        self.fleet_activation_signer.sign(token)
    }

    pub fn accept_activation_receipt(
        &self,
        receipt: &SignedEnvelope<ActivationReceipt>,
    ) -> RuntimeResult<TargetState> {
        self.agent_receipt_verifier.verify(receipt)?;
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&receipt.claims.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state != TargetState::Activating
            || receipt.claims.occurrence_id != desired.occurrence_id
            || receipt.claims.active_generation_digest != desired.capsule_digest
            || receipt.claims.xds_version_digest != desired.xds_snapshot_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        target.activation_receipt = Some(receipt.claims.clone());
        Ok(target.state)
    }

    pub fn observe_request_generation(
        &self,
        identity: &TargetIdentity,
        generation: Digest,
    ) -> RuntimeResult<()> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        if &target.identity != identity {
            return Err(RuntimeError::TargetIdentity);
        }
        target.request_observed_generation = Some(generation);
        Ok(())
    }

    pub fn heartbeat(
        &self,
        identity: &TargetIdentity,
        generation: Digest,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(&identity.target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        if &target.identity != identity {
            return Err(RuntimeError::TargetIdentity);
        }
        target.heartbeat_generation = Some(generation);
        target.heartbeat_at_ms = Some(now_ms);
        Ok(())
    }

    pub fn derive_state(&self, target_id: &str, now_ms: u64) -> RuntimeResult<TargetState> {
        let mut targets = self
            .targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let target = targets
            .get_mut(target_id)
            .ok_or(RuntimeError::TargetIdentity)?;
        let desired = target
            .desired
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if target.state == TargetState::Nacked
            || target
                .quarantined_versions
                .contains(&desired.xds_snapshot_digest)
        {
            return Ok(target.state);
        }
        if target.state == TargetState::ActiveMismatch {
            return Ok(target.state);
        }
        if !matches!(
            target.state,
            TargetState::Activating | TargetState::ActiveMatched
        ) {
            return Err(RuntimeError::InvalidTransition);
        }
        let receipt_match = target
            .activation_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.active_generation_digest == desired.capsule_digest)
            || target
                .canonical_activation_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.capsule_digest == desired.capsule_digest);
        let request_match =
            target.request_observed_generation.as_ref() == Some(&desired.capsule_digest);
        let heartbeat_match = target.heartbeat_generation.as_ref() == Some(&desired.capsule_digest)
            && target
                .heartbeat_at_ms
                .is_some_and(|seen| now_ms.saturating_sub(seen) <= self.heartbeat_freshness_ms);
        let ack_complete = target.acked_types.len() == REQUIRED_XDS_TYPES.len();
        let derived = if receipt_match && request_match && heartbeat_match && ack_complete {
            TargetState::ActiveMatched
        } else {
            TargetState::ActiveMismatch
        };
        if target.state != derived {
            Self::transition(target, derived)?;
        }
        Ok(target.state)
    }

    pub fn state(&self, target_id: &str) -> RuntimeResult<TargetState> {
        self.targets
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .get(target_id)
            .map(|target| target.state)
            .ok_or(RuntimeError::TargetIdentity)
    }
}

#[cfg(test)]
mod tests {
    use pc_runtime_types::PURPOSE_ACTIVATION_RECEIPT_V1;

    use super::*;

    fn digest(value: &str) -> Digest {
        Digest::of(value)
    }

    fn identity() -> TargetIdentity {
        TargetIdentity {
            target_id: "018f1e44-7b2c-7abd-8def-0123456789ac".into(),
            uri_san: "spiffe://openpc.local/runtime-target/018f1e44-7b2c-7abd-8def-0123456789ac"
                .into(),
            certificate_fingerprint: digest("cert"),
            workload_epoch: 1,
        }
    }

    fn desired() -> DesiredGeneration {
        DesiredGeneration {
            occurrence_id: "occurrence-1".into(),
            target_id: identity().target_id,
            capsule_digest: digest("capsule"),
            xds_snapshot_digest: digest("xds"),
            expected_previous_generation_digest: None,
            expires_at_ms: 200,
        }
    }

    fn snapshot() -> XdsSnapshot {
        let target = identity().target_id;
        let resources_by_type = REQUIRED_XDS_TYPES
            .iter()
            .map(|resource_type| {
                (
                    (*resource_type).to_owned(),
                    vec![format!("openpc/{target}/resource/v1")],
                )
            })
            .collect();
        XdsSnapshot {
            target_id: target,
            version_digest: digest("xds"),
            resources_by_type,
        }
    }

    fn receipt_signer() -> PurposeSigner {
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, [4; 32]).unwrap()
    }

    fn fleet() -> FleetController {
        FleetController::new([3; 32], &receipt_signer().verifier().sec1_bytes(), 30).unwrap()
    }

    fn advance_to_acked(fleet: &FleetController) -> (DesiredGeneration, BTreeMap<String, String>) {
        let desired = desired();
        fleet.command_generation(desired.clone()).unwrap();
        fleet
            .accept_prepared(&desired.target_id, &desired.capsule_digest)
            .unwrap();
        let nonces = fleet.publish_snapshot(snapshot()).unwrap();
        for resource_type in REQUIRED_XDS_TYPES {
            fleet
                .acknowledge(
                    &identity(),
                    resource_type,
                    &desired.xds_snapshot_digest,
                    nonces.get(resource_type).unwrap(),
                )
                .unwrap();
        }
        (desired, nonces)
    }

    #[test]
    fn replayed_canonical_effect_needs_the_exact_token_and_new_ack_barrier() {
        use openpc_runtime_agent::{
            RuntimeActivationToken, RuntimeWireSigner, TargetActivationReceipt,
        };
        let fleet_signer = RuntimeWireSigner::from_secret_bytes([3; 32]).unwrap();
        let agent_signer = RuntimeWireSigner::from_secret_bytes([4; 32]).unwrap();
        let fleet = fleet()
            .with_canonical_trust(
                &fleet_signer.verifier().public_key_bytes(),
                &agent_signer.verifier().public_key_bytes(),
            )
            .unwrap();
        fleet.register_target(identity(), &identity()).unwrap();
        let desired = desired();
        fleet.command_generation(desired.clone()).unwrap();
        fleet
            .accept_prepared(&desired.target_id, &desired.capsule_digest)
            .unwrap();
        let nonces = fleet.publish_snapshot(snapshot()).unwrap();
        let token = RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: desired.target_id.clone(),
            occurrence_id: desired.occurrence_id.clone(),
            desired_generation_digest: desired.capsule_digest.clone(),
            xds_version_digest: desired.xds_snapshot_digest.clone(),
            expected_previous_generation_digest: None,
            issued_at_ns: 1,
            expires_at_ns: 20,
        };
        let receipt = TargetActivationReceipt {
            receipt_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: desired.target_id.clone(),
            capsule_digest: desired.capsule_digest.clone(),
            contract_set_manifest_digest: digest("contracts"),
            complete_component_set_digest: digest("components"),
            status: 1,
            reason_code: "ACTIVE_LOCAL".into(),
            observed_at_ns: 2,
            agent_sequence: 1,
            signer_id: "agent".into(),
        };
        let signed = agent_signer.sign_receipt(&receipt).unwrap();
        let proof = fleet_signer.sign_activation_token(&token).unwrap();
        assert!(
            fleet
                .replay_canonical_activation(&identity(), &signed, &proof)
                .is_err()
        );
        for kind in REQUIRED_XDS_TYPES {
            fleet
                .acknowledge(
                    &identity(),
                    kind,
                    &desired.xds_snapshot_digest,
                    &nonces[kind],
                )
                .unwrap();
        }
        for mismatch in 0..5 {
            let mut changed = token.clone();
            match mismatch {
                0 => changed.occurrence_id = "other occurrence".into(),
                1 => changed.desired_generation_digest = digest("other capsule"),
                2 => changed.xds_version_digest = digest("other xds"),
                3 => {
                    changed.expected_previous_generation_digest = Some(digest("other predecessor"))
                }
                _ => {
                    changed.issued_at_ns = 3;
                }
            }
            assert!(
                fleet
                    .replay_canonical_activation(
                        &identity(),
                        &signed,
                        &fleet_signer.sign_activation_token(&changed).unwrap()
                    )
                    .is_err()
            );
        }
        fleet
            .replay_canonical_activation(&identity(), &signed, &proof)
            .unwrap();
        assert_eq!(
            fleet.state(&desired.target_id).unwrap(),
            TargetState::Activating
        );
        // A historical receipt still cannot manufacture request/heartbeat truth.
        assert_eq!(
            fleet.derive_state(&desired.target_id, 100).unwrap(),
            TargetState::ActiveMismatch
        );
    }

    #[test]
    fn exact_identity_and_complete_sotw_are_required() {
        let fleet = fleet();
        let expected = identity();
        let mut wrong = expected.clone();
        wrong.workload_epoch = 2;
        assert_eq!(
            fleet.register_target(wrong, &expected),
            Err(RuntimeError::TargetIdentity)
        );
        fleet.register_target(expected.clone(), &expected).unwrap();
        let desired = desired();
        fleet.command_generation(desired.clone()).unwrap();
        fleet
            .accept_prepared(&desired.target_id, &desired.capsule_digest)
            .unwrap();
        let mut incomplete = snapshot();
        incomplete.resources_by_type.remove(REQUIRED_XDS_TYPES[0]);
        assert_eq!(
            fleet.publish_snapshot(incomplete),
            Err(RuntimeError::InvalidInput)
        );
    }

    #[test]
    fn ack_is_not_activation_and_full_evidence_is_required() {
        let fleet = fleet();
        let expected = identity();
        fleet.register_target(expected.clone(), &expected).unwrap();
        let (desired, nonces) = advance_to_acked(&fleet);
        let replay = |state| {
            let before = fleet.targets.lock().unwrap()[&desired.target_id].clone();
            for resource_type in REQUIRED_XDS_TYPES {
                let nonce = &nonces[resource_type];
                assert_eq!(
                    fleet.acknowledge(
                        &expected,
                        resource_type,
                        &desired.xds_snapshot_digest,
                        nonce
                    ),
                    Ok(state)
                );
                for (version, replay_nonce) in [
                    (digest("stale-snapshot"), nonce.as_str()),
                    (desired.xds_snapshot_digest.clone(), "stale-nonce"),
                ] {
                    assert_eq!(
                        fleet.acknowledge(&expected, resource_type, &version, replay_nonce),
                        Err(RuntimeError::GenerationMismatch)
                    );
                }
                let mut wrong_peer = expected.clone();
                wrong_peer.workload_epoch += 1;
                assert_eq!(
                    fleet.acknowledge(
                        &wrong_peer,
                        resource_type,
                        &desired.xds_snapshot_digest,
                        nonce
                    ),
                    Err(RuntimeError::TargetIdentity)
                );
            }
            let targets = fleet.targets.lock().unwrap();
            let after = &targets[&desired.target_id];
            assert_eq!(after.state, before.state);
            assert_eq!(after.desired, before.desired);
            assert_eq!(after.activation_receipt, before.activation_receipt);
            assert_eq!(
                after.request_observed_generation,
                before.request_observed_generation
            );
            assert_eq!(after.heartbeat_at_ms, before.heartbeat_at_ms);
        };
        replay(TargetState::XdsAckedNotActive);
        assert_eq!(
            fleet.state(&desired.target_id).unwrap(),
            TargetState::XdsAckedNotActive
        );
        let token = fleet
            .issue_activation_token(&desired.target_id, 100, 20)
            .unwrap();
        let receipt = ActivationReceipt {
            receipt_id: "receipt-1".into(),
            occurrence_id: desired.occurrence_id.clone(),
            target_id: desired.target_id.clone(),
            active_generation_digest: desired.capsule_digest.clone(),
            xds_version_digest: desired.xds_snapshot_digest.clone(),
            previous_generation_digest: None,
            journal_sequence: 1,
            activated_at_ms: 105,
            state: TargetState::ActiveMatched,
        };
        let signed_receipt = receipt_signer().sign(receipt).unwrap();
        replay(TargetState::Activating);
        assert_eq!(
            fleet.accept_activation_receipt(&signed_receipt).unwrap(),
            TargetState::Activating
        );
        fleet
            .observe_request_generation(&identity(), desired.capsule_digest.clone())
            .unwrap();
        fleet
            .heartbeat(&expected, desired.capsule_digest.clone(), 110)
            .unwrap();
        assert_eq!(
            fleet.derive_state(&desired.target_id, 111).unwrap(),
            TargetState::ActiveMatched
        );
        replay(TargetState::ActiveMatched);
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_TOKEN_V1, [3; 32])
            .unwrap()
            .verifier()
            .verify(&token)
            .unwrap();
    }

    #[test]
    fn wrong_peer_ack_nack_observation_and_heartbeat_have_no_effect() {
        let fleet = fleet();
        let expected = identity();
        fleet.register_target(expected.clone(), &expected).unwrap();
        let desired = desired();
        fleet.command_generation(desired.clone()).unwrap();
        fleet
            .accept_prepared(&desired.target_id, &desired.capsule_digest)
            .unwrap();
        let nonces = fleet.publish_snapshot(snapshot()).unwrap();
        for mutation in 0..4 {
            let mut peer = expected.clone();
            match mutation {
                0 => peer.target_id.push_str("-other"),
                1 => peer.uri_san.push_str("-other"),
                2 => peer.certificate_fingerprint = digest("wrong-peer-certificate"),
                _ => peer.workload_epoch += 1,
            }
            let nonce = nonces.get(REQUIRED_XDS_TYPES[0]).unwrap();
            assert_eq!(
                fleet.acknowledge(
                    &peer,
                    REQUIRED_XDS_TYPES[0],
                    &desired.xds_snapshot_digest,
                    nonce
                ),
                Err(RuntimeError::TargetIdentity)
            );
            assert_eq!(
                fleet.nack(&peer, &desired.xds_snapshot_digest, nonce),
                Err(RuntimeError::TargetIdentity)
            );
            assert_eq!(
                fleet.observe_request_generation(&peer, desired.capsule_digest.clone()),
                Err(RuntimeError::TargetIdentity)
            );
            assert_eq!(
                fleet.heartbeat(&peer, desired.capsule_digest.clone(), 100),
                Err(RuntimeError::TargetIdentity)
            );
            let targets = fleet.targets.lock().unwrap();
            let target = targets.get(&expected.target_id).unwrap();
            assert!(target.acked_types.is_empty());
            assert!(target.quarantined_versions.is_empty());
            assert!(target.request_observed_generation.is_none());
            assert!(target.heartbeat_at_ms.is_none());
            assert_eq!(target.state, TargetState::XdsPending);
        }
        // Rejected peers cannot prevent the registered peer from converging.
        for resource_type in REQUIRED_XDS_TYPES {
            fleet
                .acknowledge(
                    &expected,
                    resource_type,
                    &desired.xds_snapshot_digest,
                    nonces.get(resource_type).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            fleet.state(&expected.target_id).unwrap(),
            TargetState::XdsAckedNotActive
        );
    }

    #[test]
    fn stale_ack_does_not_mutate_and_nack_quarantines_exact_version() {
        let fleet = fleet();
        let expected = identity();
        fleet.register_target(expected.clone(), &expected).unwrap();
        let desired = desired();
        fleet.command_generation(desired.clone()).unwrap();
        fleet
            .accept_prepared(&desired.target_id, &desired.capsule_digest)
            .unwrap();
        let nonces = fleet.publish_snapshot(snapshot()).unwrap();
        assert_eq!(
            fleet.acknowledge(
                &identity(),
                REQUIRED_XDS_TYPES[0],
                &digest("stale"),
                nonces.get(REQUIRED_XDS_TYPES[0]).unwrap(),
            ),
            Err(RuntimeError::GenerationMismatch)
        );
        assert_eq!(
            fleet.state(&desired.target_id).unwrap(),
            TargetState::XdsPending
        );
        assert_eq!(
            fleet.nack(
                &identity(),
                &desired.xds_snapshot_digest,
                nonces.get(REQUIRED_XDS_TYPES[1]).unwrap(),
            ),
            Err(RuntimeError::XdsQuarantined)
        );
        assert_eq!(
            fleet.state(&desired.target_id).unwrap(),
            TargetState::Nacked
        );

        {
            let mut targets = fleet.targets.lock().unwrap();
            let target = targets.get_mut(&desired.target_id).unwrap();
            target.activation_receipt = Some(ActivationReceipt {
                receipt_id: "stale-receipt".into(),
                occurrence_id: desired.occurrence_id.clone(),
                target_id: desired.target_id.clone(),
                active_generation_digest: desired.capsule_digest.clone(),
                xds_version_digest: desired.xds_snapshot_digest.clone(),
                previous_generation_digest: None,
                journal_sequence: 1,
                activated_at_ms: 100,
                state: TargetState::ActiveMatched,
            });
            target.request_observed_generation = Some(desired.capsule_digest.clone());
            target.heartbeat_generation = Some(desired.capsule_digest.clone());
            target.heartbeat_at_ms = Some(100);
            target.acked_types = REQUIRED_XDS_TYPES
                .iter()
                .map(|resource_type| (*resource_type).to_owned())
                .collect();
        }
        assert_eq!(
            fleet.derive_state(&desired.target_id, 101).unwrap(),
            TargetState::Nacked,
            "matching stale evidence must not resurrect a quarantined version"
        );
        assert_eq!(
            fleet.nack(
                &identity(),
                &desired.xds_snapshot_digest,
                nonces.get(REQUIRED_XDS_TYPES[1]).unwrap(),
            ),
            Err(RuntimeError::GenerationMismatch),
            "NACK is valid only while the exact version is XDS_PENDING"
        );
    }
}

mod provider_probe_source;
pub mod provider_probe_worker;
pub mod routing_publication;
pub mod runtime_target;
pub mod runtime_target_observation;
pub mod runtime_target_service;
pub mod signing_provider_worker;
