#![forbid(unsafe_code)]

//! Atomic target-local preparation, activation journal and receipt replay.

use std::sync::Mutex;

use pc_runtime_types::{
    ActivationReceipt, ActivationToken, DesiredGeneration, Digest, PURPOSE_ACTIVATION_RECEIPT_V1,
    PURPOSE_ACTIVATION_TOKEN_V1, PURPOSE_DESIRED_GENERATION_V1, PreparedGeneration, PurposeSigner,
    PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope, TargetState, canonical_bytes,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactBundle {
    pub manifest_digest: Digest,
    pub policy_generation_digest: Digest,
    pub fact_generation_digest: Digest,
    pub route_profile_digest: Digest,
    pub runtime_configuration_digest: Digest,
    pub schema_version: String,
    pub abi_version: String,
    pub declared_bytes: u64,
    pub available_capacity_bytes: u64,
}

mod activation;
mod activation_token;
pub mod target_disposition;
pub use activation_token::RuntimeActivationToken;
pub mod authority_artifact;
mod capsule;
pub use activation::{ArtifactAdmission, CapsuleTrust, ExpiredPreparationNoEffect};
mod cose;
#[cfg(test)]
mod custody_tests;
#[cfg(test)]
mod durability_tests;
pub mod ext_proc;
pub mod ext_proc_server;
pub mod ext_proc_wire;
mod identity_credentials;
pub mod identity_custody;
#[cfg(test)]
mod identity_publication_tests;
mod identity_source;
pub mod identity_state;
mod identity_wallet;
pub mod indexer_custody;
pub mod invocation_custody;
pub mod invocation_profile_custody;
#[cfg(test)]
mod invocation_publication_fixture;
pub mod ipc;
mod workload_peer;
pub use workload_peer::WorkloadPeer;
pub mod broker_handoff;
pub mod broker_server;
pub mod decision_evidence;
pub mod fact_custody;
pub mod fact_lease;
pub mod mrpc_custody;
pub mod protected_target;
pub mod provider_response;
pub mod provider_transport;
pub mod request_decode;
pub mod request_route;
mod request_trace;
pub mod routing_custody;
pub use request_trace::RequestTraceId;
pub mod target_server;
pub mod target_state;
pub use pc_policy_core::{decision_input, decision_material};
mod emergency;
mod freshness;
pub use emergency::{EmergencyDenyOverlay, encode_emergency_deny_keys};
mod journal;
pub use freshness::{ActiveCapsuleLease, RevocationFreshnessLease};
mod receipt;
#[cfg(test)]
mod wire_tests;
pub use capsule::{ArtifactComponent, RuntimeCapsule};
pub use cose::{RuntimeWireSigner, RuntimeWireVerifier};
pub use receipt::{RuntimeActivationAck, TargetActivationReceipt};

const RECEIPT_REPLAY_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

use journal::{Journal, JournalStore, PreparedRecord};
use std::path::Path;

struct LegacyOwner {
    desired_verifier: PurposeVerifier,
    activation_verifier: PurposeVerifier,
    receipt_signer: PurposeSigner,
}

pub struct RuntimeAgent {
    target_id: String,
    legacy: Option<LegacyOwner>,
    capacity: usize,
    artifact_capacity_bytes: u64,
    journal: Mutex<JournalStore>,
    wire: Option<activation::WireOwner>,
    disposition_owner: std::sync::OnceLock<target_disposition::DispositionOwner>,
    // Process-local evidence from the private Envoy channel. A restarted
    // process must observe a real request before it can attest convergence.
    request_observed: Mutex<Option<Digest>>,
}

impl RuntimeAgent {
    /// Component-only volatile owner. Deployed targets must use `open`.
    pub fn new(
        target_id: impl Into<String>,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        replay_capacity: usize,
    ) -> RuntimeResult<Self> {
        Self::restore(
            target_id,
            fleet_public_key,
            receipt_key,
            replay_capacity,
            None,
        )
    }

    /// Legacy component restoration; it cannot establish target-local durability.
    pub fn restore(
        target_id: impl Into<String>,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        replay_capacity: usize,
        active: Option<(Digest, Digest, u64)>,
    ) -> RuntimeResult<Self> {
        let target_id = target_id.into();
        let mut state = Journal::empty(target_id.clone());
        if let Some((generation, xds, sequence)) = active {
            if sequence == 0 {
                return Err(RuntimeError::InvalidInput);
            }
            state.active = Some(generation);
            state.xds_version = Some(xds);
            state.sequence = sequence;
        }
        Self::build(
            target_id,
            fleet_public_key,
            receipt_key,
            replay_capacity,
            u64::MAX,
            JournalStore::volatile(state),
        )
    }

    /// Open an exclusively owned target-local journal. Preparation and activation
    /// are acknowledged only after the replacement file and directory are synced.
    /// A failed/uncertain write poisons this owner until it is reopened.
    pub fn open(
        target_id: impl Into<String>,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        replay_capacity: usize,
        artifact_capacity_bytes: u64,
        directory: &Path,
    ) -> RuntimeResult<Self> {
        let target_id = target_id.into();
        let store = JournalStore::open(directory, "activation", || {
            crate::journal::Journal::empty(target_id.clone())
        })?;
        let agent = Self::build(
            target_id,
            fleet_public_key,
            receipt_key,
            replay_capacity,
            artifact_capacity_bytes,
            store,
        )?;
        agent.validate_restored()?;
        Ok(agent)
    }

    fn build(
        target_id: String,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        capacity: usize,
        artifact_capacity_bytes: u64,
        store: JournalStore,
    ) -> RuntimeResult<Self> {
        if target_id.is_empty() || capacity == 0 || artifact_capacity_bytes == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            target_id,
            legacy: Some(LegacyOwner {
                desired_verifier: PurposeVerifier::from_sec1_bytes(
                    PURPOSE_DESIRED_GENERATION_V1,
                    fleet_public_key,
                )?,
                activation_verifier: PurposeVerifier::from_sec1_bytes(
                    PURPOSE_ACTIVATION_TOKEN_V1,
                    fleet_public_key,
                )?,
                receipt_signer: PurposeSigner::from_secret_bytes(
                    PURPOSE_ACTIVATION_RECEIPT_V1,
                    receipt_key,
                )?,
            }),
            capacity,
            artifact_capacity_bytes,
            journal: Mutex::new(store),
            wire: None,
            disposition_owner: std::sync::OnceLock::new(),
            request_observed: Mutex::new(None),
        })
    }

    fn legacy(&self) -> RuntimeResult<&LegacyOwner> {
        self.legacy
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)
    }

    fn validate_restored(&self) -> RuntimeResult<()> {
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard.state()?;
        if state.canonical.is_some()
            || state.target_id != self.target_id
            || state.version != 1
            || state.prepared.len() > self.capacity
            || state.receipts.len() > self.capacity
            || state.consumed.len() > self.capacity
            || state.active.is_some() != state.xds_version.is_some()
            || state.active.is_some() != (state.sequence > 0)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let mut prepared_bytes = 0_u64;
        for (id, record) in &state.prepared {
            self.legacy()?.desired_verifier.verify(&record.signed)?;
            if id != &record.signed.claims.occurrence_id
                || record.signed.claims.target_id != self.target_id
                || record.prepared.desired != record.signed.claims
                || record.prepared.artifact_set_digest != record.signed.claims.capsule_digest
                || Digest::of(canonical_bytes(&record.bundle)?)
                    != record.signed.claims.capsule_digest
                || record.bundle.declared_bytes > self.artifact_capacity_bytes
                || record.bundle.declared_bytes == 0
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            prepared_bytes = prepared_bytes
                .checked_add(record.bundle.declared_bytes)
                .ok_or(RuntimeError::ReplayCapacity)?;
        }
        if prepared_bytes > self.artifact_capacity_bytes {
            return Err(RuntimeError::ReplayCapacity);
        }
        for (id, receipt) in &state.receipts {
            self.legacy()?.receipt_signer.verifier().verify(receipt)?;
            if id != &receipt.claims.receipt_id
                || receipt.claims.target_id != self.target_id
                || receipt.claims.journal_sequence > state.sequence
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        if state.sequence > 0 {
            let last = state
                .receipts
                .values()
                .find(|r| r.claims.journal_sequence == state.sequence)
                .ok_or(RuntimeError::GenerationMismatch)?;
            if Some(&last.claims.active_generation_digest) != state.active.as_ref()
                || Some(&last.claims.xds_version_digest) != state.xds_version.as_ref()
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        Ok(())
    }

    pub fn prepare(
        &self,
        desired: &SignedEnvelope<DesiredGeneration>,
        bundle: &ArtifactBundle,
        now_ms: u64,
    ) -> RuntimeResult<PreparedGeneration> {
        if self.wire.is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        self.legacy()?.desired_verifier.verify(desired)?;
        if desired.claims.target_id != self.target_id
            || desired.claims.occurrence_id.is_empty()
            || now_ms >= desired.claims.expires_at_ms
            || bundle.schema_version != "1.0"
            || bundle.abi_version != "1.0"
            || bundle.declared_bytes == 0
            || bundle.declared_bytes > bundle.available_capacity_bytes
            || bundle.declared_bytes > self.artifact_capacity_bytes
            || desired.claims.capsule_digest != Digest::of(canonical_bytes(bundle)?)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard.state()?;
        if state
            .receipts
            .values()
            .any(|r| r.claims.occurrence_id == desired.claims.occurrence_id)
        {
            return Err(RuntimeError::Replay);
        }
        if state.active != desired.claims.expected_previous_generation_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(existing) = state.prepared.get(&desired.claims.occurrence_id) {
            return if existing.signed == *desired {
                Ok(existing.prepared.clone())
            } else {
                Err(RuntimeError::GenerationMismatch)
            };
        }
        let mut next = state.clone();
        next.prepared
            .retain(|_, r| r.signed.claims.expires_at_ms > now_ms);
        if next.prepared.len() >= self.capacity {
            return Err(RuntimeError::ReplayCapacity);
        }
        let reserved = next
            .prepared
            .values()
            .try_fold(bundle.declared_bytes, |sum, record| {
                sum.checked_add(record.bundle.declared_bytes)
                    .ok_or(RuntimeError::ReplayCapacity)
            })?;
        if reserved > self.artifact_capacity_bytes {
            return Err(RuntimeError::ReplayCapacity);
        }
        let prepared = PreparedGeneration {
            desired: desired.claims.clone(),
            artifact_set_digest: desired.claims.capsule_digest.clone(),
            prepared_at_ms: now_ms,
        };
        next.prepared.insert(
            desired.claims.occurrence_id.clone(),
            PreparedRecord {
                signed: desired.clone(),
                prepared: prepared.clone(),
                bundle: bundle.clone(),
            },
        );
        guard.commit(next)?;
        Ok(prepared)
    }

    pub fn activate(
        &self,
        token: &SignedEnvelope<ActivationToken>,
        now_ms: u64,
    ) -> RuntimeResult<SignedEnvelope<ActivationReceipt>> {
        if self.wire.is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        self.legacy()?.activation_verifier.verify(token)?;
        let claims = &token.claims;
        if claims.target_id != self.target_id
            || now_ms < claims.issued_at_ms
            || now_ms >= claims.expires_at_ms
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if claims.token_id.is_empty() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard.state()?;
        if state.consumed.contains_key(&claims.token_id)
            || state
                .receipts
                .values()
                .any(|r| r.claims.occurrence_id == claims.occurrence_id)
        {
            return Err(RuntimeError::Replay);
        }
        let prepared = state
            .prepared
            .get(&claims.occurrence_id)
            .ok_or(RuntimeError::GenerationMismatch)?;
        if now_ms >= prepared.signed.claims.expires_at_ms
            || prepared.prepared.desired.capsule_digest != claims.capsule_digest
            || prepared.prepared.desired.xds_snapshot_digest != claims.xds_version_digest
            || prepared
                .prepared
                .desired
                .expected_previous_generation_digest
                != claims.expected_previous_generation_digest
            || state.active != claims.expected_previous_generation_digest
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let mut next = state.clone();
        next.consumed.retain(|_, expiry| *expiry > now_ms);
        // Preserve the registered receipt replay window and the latest receipt
        // needed to authenticate restart state, even after a long idle period.
        next.receipts.retain(|_, receipt| {
            receipt.claims.journal_sequence == next.sequence
                || now_ms
                    < receipt
                        .claims
                        .activated_at_ms
                        .saturating_add(RECEIPT_REPLAY_WINDOW_MS)
        });
        if next.consumed.len() >= self.capacity || next.receipts.len() >= self.capacity {
            return Err(RuntimeError::ReplayCapacity);
        }
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(RuntimeError::RuntimeUnavailable)?;
        let receipt = self.legacy()?.receipt_signer.sign(ActivationReceipt {
            receipt_id: format!("local-receipt-{:016x}", next.sequence),
            occurrence_id: claims.occurrence_id.clone(),
            target_id: self.target_id.clone(),
            active_generation_digest: claims.capsule_digest.clone(),
            xds_version_digest: claims.xds_version_digest.clone(),
            previous_generation_digest: next.active.clone(),
            journal_sequence: next.sequence,
            activated_at_ms: now_ms,
            state: TargetState::ActiveMatched,
        })?;
        next.active = Some(claims.capsule_digest.clone());
        next.xds_version = Some(claims.xds_version_digest.clone());
        next.consumed
            .insert(claims.token_id.clone(), claims.expires_at_ms);
        next.prepared.remove(&claims.occurrence_id);
        next.receipts
            .insert(receipt.claims.receipt_id.clone(), receipt.clone());
        guard.commit(next)?;
        Ok(receipt)
    }

    pub fn active_generation(&self) -> RuntimeResult<Option<(Digest, Digest, u64)>> {
        if self.wire.is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard.state()?;
        Ok(state
            .active
            .clone()
            .zip(state.xds_version.clone())
            .map(|(generation, xds)| (generation, xds, state.sequence)))
    }

    pub fn replay_receipts(&self) -> RuntimeResult<Vec<SignedEnvelope<ActivationReceipt>>> {
        if self.wire.is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(guard.state()?.receipts.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: &str) -> Digest {
        Digest::of(value)
    }

    pub(super) fn bundle() -> ArtifactBundle {
        ArtifactBundle {
            manifest_digest: digest("manifest"),
            policy_generation_digest: digest("policy"),
            fact_generation_digest: digest("facts"),
            route_profile_digest: digest("route"),
            runtime_configuration_digest: digest("config"),
            schema_version: "1.0".into(),
            abi_version: "1.0".into(),
            declared_bytes: 1024,
            available_capacity_bytes: 2048,
        }
    }

    pub(super) fn desired(bundle: &ArtifactBundle, previous: Option<Digest>) -> DesiredGeneration {
        DesiredGeneration {
            occurrence_id: "occurrence-1".into(),
            target_id: "target-1".into(),
            capsule_digest: Digest::of(canonical_bytes(bundle).unwrap()),
            xds_snapshot_digest: digest("xds"),
            expected_previous_generation_digest: previous,
            expires_at_ms: 200,
        }
    }

    pub(super) fn fleet_signer(purpose: &'static str) -> PurposeSigner {
        PurposeSigner::from_secret_bytes(purpose, [3; 32]).unwrap()
    }

    fn agent() -> RuntimeAgent {
        let public = fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
            .verifier()
            .sec1_bytes();
        RuntimeAgent::new("target-1", &public, [4; 32], 4).unwrap()
    }

    #[test]
    fn prepare_never_changes_active_and_activation_is_atomic_one_use() {
        let agent = agent();
        let bundle = bundle();
        let desired = desired(&bundle, None);
        let signed_desired = fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
            .sign(desired.clone())
            .unwrap();
        agent.prepare(&signed_desired, &bundle, 100).unwrap();
        assert_eq!(agent.active_generation().unwrap(), None);
        let token = ActivationToken {
            token_id: "token-1".into(),
            occurrence_id: desired.occurrence_id.clone(),
            target_id: desired.target_id.clone(),
            capsule_digest: desired.capsule_digest.clone(),
            xds_version_digest: desired.xds_snapshot_digest.clone(),
            expected_previous_generation_digest: None,
            issued_at_ms: 101,
            expires_at_ms: 150,
        };
        let signed_token = fleet_signer(PURPOSE_ACTIVATION_TOKEN_V1)
            .sign(token)
            .unwrap();
        let receipt = agent.activate(&signed_token, 110).unwrap();
        PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, [4; 32])
            .unwrap()
            .verifier()
            .verify(&receipt)
            .unwrap();
        assert_eq!(
            agent.active_generation().unwrap().unwrap().0,
            desired.capsule_digest
        );
        assert_eq!(
            agent.activate(&signed_token, 111),
            Err(RuntimeError::Replay)
        );
        assert_eq!(agent.replay_receipts().unwrap(), vec![receipt]);
    }

    #[test]
    fn invalid_bundle_and_predecessor_leave_journal_unchanged() {
        let agent = agent();
        let mut invalid = bundle();
        let desired = desired(&invalid, None);
        invalid.schema_version = "2.0".into();
        let signed_desired = fleet_signer(PURPOSE_DESIRED_GENERATION_V1)
            .sign(desired)
            .unwrap();
        assert_eq!(
            agent.prepare(&signed_desired, &invalid, 100),
            Err(RuntimeError::InvalidInput)
        );
        assert_eq!(agent.active_generation().unwrap(), None);
    }
}

mod operation_status_rpc;
