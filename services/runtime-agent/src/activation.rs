//! Canonical capsule custody uses the same exclusive, fsynced target journal.
use crate::{
    ArtifactComponent, RuntimeAgent, RuntimeCapsule, RuntimeWireSigner, RuntimeWireVerifier,
    TargetActivationReceipt, journal::JournalStore,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

/// Installed by the runtime's artifact owners. Neither RPC input nor artifact
/// metadata can supply a successful schema/semantic/ABI admission result.
pub trait ArtifactAdmission: Send + Sync {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()>;

    fn validate_component_in_bundle(
        &self,
        _capsule: &RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        self.validate(
            component,
            artifacts
                .get(&component.content_digest)
                .ok_or(RuntimeError::InvalidInput)?,
        )?;
        Ok(BTreeSet::from([component.content_digest.clone()]))
    }

    /// Return the complete content closure actually verified by the installed
    /// owners. The custody owner rejects any omitted or unreferenced bytes.
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        let mut verified = BTreeSet::new();
        for component in &capsule.artifact_components {
            verified.extend(self.validate_component_in_bundle(capsule, component, artifacts)?);
        }
        Ok(verified)
    }
}
#[derive(Clone)]
pub struct CapsuleTrust {
    pub target_id: String,
    pub fleet_id: String,
    pub fleet_signer_id: String,
    pub agent_signer_id: String,
    pub contract_set_manifest_digest: Digest,
    pub schema_registry_digest: Digest,
    pub cose_purpose_registry_digest: Digest,
    pub complete_component_set_digest: Digest,
}
pub(crate) struct WireOwner {
    pub(crate) trust: CapsuleTrust,
    pub(crate) verifier: RuntimeWireVerifier,
    signer: RuntimeWireSigner,
    admission: Arc<dyn ArtifactAdmission>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Custody {
    pub signed_capsule: Vec<u8>,
    pub artifacts: BTreeMap<Digest, Vec<u8>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Activation {
    pub custody: Custody,
    pub receipt: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_token: Option<Vec<u8>>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalJournal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_disposition: Option<crate::target_disposition::JournalDisposition>,
    #[serde(default)]
    pub freshness_lease: Option<Vec<u8>>,
    #[serde(default)]
    pub emergency_overlay: Option<crate::emergency::InstalledOverlay>,
    pub sequence: u64,
    pub prepared: Option<Custody>,
    pub active: Option<Activation>,
    pub previous: Option<Activation>,
    pub receipts: Vec<Vec<u8>>,
}

/// Authenticated material for an expired preparation that never became active.
/// The caller must retain this agent's exclusive journal custody until its
/// disposition commits. This observation never grants activation authority.
pub struct ExpiredPreparationNoEffect {
    capsule: RuntimeCapsule,
    signed_capsule: Vec<u8>,
    predecessor_receipt: Vec<u8>,
}
impl ExpiredPreparationNoEffect {
    pub fn capsule(&self) -> &RuntimeCapsule {
        &self.capsule
    }
    pub fn signed_capsule(&self) -> &[u8] {
        &self.signed_capsule
    }
    pub fn predecessor_receipt(&self) -> &[u8] {
        &self.predecessor_receipt
    }
}
impl WireOwner {
    pub(crate) fn sign_ack(&self, ack: &crate::RuntimeActivationAck) -> RuntimeResult<Vec<u8>> {
        self.signer.sign_ack(ack)
    }

    pub(crate) fn validate(&self, custody: &Custody) -> RuntimeResult<RuntimeCapsule> {
        verify_custody(
            &self.trust,
            &self.verifier,
            self.admission.as_ref(),
            custody,
        )
    }
    pub(crate) fn validate_activation(
        &self,
        activation: &Activation,
    ) -> RuntimeResult<TargetActivationReceipt> {
        let capsule = self.validate(&activation.custody)?;
        verify_activation(
            &self.trust,
            &self.verifier,
            &self.signer.verifier(),
            &capsule,
            activation,
        )
    }
}

fn verify_custody(
    t: &CapsuleTrust,
    verifier: &RuntimeWireVerifier,
    admission: &dyn ArtifactAdmission,
    custody: &Custody,
) -> RuntimeResult<RuntimeCapsule> {
    let capsule = verifier.verify_capsule(&custody.signed_capsule)?;
    if capsule.target_runtime_id != t.target_id
        || capsule.fleet_id != t.fleet_id
        || capsule.signer_id != t.fleet_signer_id
        || capsule.contract_set_manifest_digest != t.contract_set_manifest_digest
        || capsule.schema_registry_digest != t.schema_registry_digest
        || capsule.cose_purpose_registry_digest != t.cose_purpose_registry_digest
        || capsule.complete_component_set_digest != t.complete_component_set_digest
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    for (digest, bytes) in &custody.artifacts {
        if Digest::of(bytes) != *digest {
            return Err(RuntimeError::InvalidDigest);
        }
    }
    for component in &capsule.artifact_components {
        let bytes = custody
            .artifacts
            .get(&component.content_digest)
            .ok_or(RuntimeError::InvalidInput)?;
        if bytes.len() as u64 != component.size_bytes
            || Digest::of(bytes) != component.content_digest
        {
            return Err(RuntimeError::InvalidDigest);
        }
    }
    let verified = admission.validate_bundle(&capsule, &custody.artifacts)?;
    if verified != custody.artifacts.keys().cloned().collect() {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(capsule)
}

fn verify_activation(
    trust: &CapsuleTrust,
    fleet: &RuntimeWireVerifier,
    agent: &RuntimeWireVerifier,
    capsule: &RuntimeCapsule,
    activation: &Activation,
) -> RuntimeResult<TargetActivationReceipt> {
    let receipt = agent.verify_receipt(&activation.receipt)?;
    if receipt.target_runtime_id != trust.target_id
        || receipt.signer_id != trust.agent_signer_id
        || receipt.capsule_digest != capsule.digest()?
        || receipt.contract_set_manifest_digest != capsule.contract_set_manifest_digest
        || receipt.complete_component_set_digest != capsule.complete_component_set_digest
        || receipt.reason_code != "ACTIVE_LOCAL"
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    if let Some(signed) = &activation.activation_token {
        let token = fleet.verify_activation_token(signed)?;
        if token.target_runtime_id != receipt.target_runtime_id
            || token.desired_generation_digest != receipt.capsule_digest
            || token.expected_previous_generation_digest != capsule.previous_capsule_digest
            || token.issued_at_ns > receipt.observed_at_ns
            || token.expires_at_ns <= receipt.observed_at_ns
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    Ok(receipt)
}
impl RuntimeAgent {
    pub fn expired_preparation_no_effect(
        &self,
        capsule_id: &str,
        predecessor: &Digest,
        policy: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<Option<ExpiredPreparationNoEffect>> {
        let owner = self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let active = state
            .active
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let receipt = owner.validate_activation(active)?;
        if receipt.status != 1 || &receipt.capsule_digest != predecessor {
            return Ok(None);
        }
        let Some(prepared) = &state.prepared else {
            return Ok(None);
        };
        let capsule = owner.validate(prepared)?;
        if capsule.capsule_id != capsule_id
            || &capsule.policy_bundle_digest != policy
            || capsule.previous_capsule_digest.as_ref() != Some(predecessor)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if now_ns < capsule.hard_expiry_ns {
            // Writer custody alone does not retire a still-valid preparation.
            return Ok(None);
        }
        Ok(Some(ExpiredPreparationNoEffect {
            capsule,
            signed_capsule: prepared.signed_capsule.clone(),
            predecessor_receipt: active.receipt.clone(),
        }))
    }

    /// Read authenticated immutable source bytes while the target retains its
    /// exclusive writer lock. This neither installs state nor establishes live
    /// request freshness. The caller pins the observed capsule under its source
    /// fences; a concurrent generation change must reject that pin.
    #[allow(clippy::too_many_arguments)]
    pub fn read_canonical_sources<T>(
        trust: &CapsuleTrust,
        fleet_public_key: &[u8],
        agent_public_key: &[u8],
        directory: &Path,
        expected_capsule: &Digest,
        admission: &dyn ArtifactAdmission,
        read: impl FnOnce(&RuntimeCapsule, &BTreeMap<Digest, Vec<u8>>) -> RuntimeResult<T>,
    ) -> RuntimeResult<T> {
        Self::read_canonical_activation(
            trust,
            fleet_public_key,
            agent_public_key,
            directory,
            Some(expected_capsule),
            admission,
            |capsule, artifacts, _, _| read(capsule, artifacts),
        )
    }

    /// Same authenticated source read with the retained activation proof for
    /// exact occurrence/xDS reconciliation. It never repeats the target effect.
    #[allow(clippy::too_many_arguments)]
    pub fn read_canonical_activation<T>(
        trust: &CapsuleTrust,
        fleet_public_key: &[u8],
        agent_public_key: &[u8],
        directory: &Path,
        expected_capsule: Option<&Digest>,
        admission: &dyn ArtifactAdmission,
        read: impl FnOnce(&RuntimeCapsule, &BTreeMap<Digest, Vec<u8>>, &[u8], &[u8]) -> RuntimeResult<T>,
    ) -> RuntimeResult<T> {
        let journal = JournalStore::read_committed(directory, "activation")?;
        if journal.target_id != trust.target_id
            || journal.version != 1
            || journal.sequence != 0
            || journal.active.is_some()
            || !journal.prepared.is_empty()
            || !journal.receipts.is_empty()
            || !journal.consumed.is_empty()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let state = journal
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let active = state
            .active
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if active.activation_token.is_none() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let fleet = RuntimeWireVerifier::from_public_key_bytes(fleet_public_key)?;
        let agent = RuntimeWireVerifier::from_public_key_bytes(agent_public_key)?;
        let capsule = verify_custody(trust, &fleet, admission, &active.custody)?;
        let receipt = verify_activation(trust, &fleet, &agent, &capsule, active)?;
        if expected_capsule.is_some_and(|expected| &receipt.capsule_digest != expected)
            || receipt.status != 1
            || receipt.agent_sequence != state.sequence
            || !state.receipts.contains(&active.receipt)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        read(
            &capsule,
            &active.custody.artifacts,
            active
                .activation_token
                .as_deref()
                .ok_or(RuntimeError::InvalidAuthorization)?,
            &active.receipt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_canonical(
        trust: CapsuleTrust,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        replay_capacity: usize,
        artifact_capacity_bytes: u64,
        directory: &Path,
        admission: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        Self::try_open_canonical(
            trust,
            fleet_public_key,
            receipt_key,
            replay_capacity,
            artifact_capacity_bytes,
            directory,
            admission,
        )?
        .ok_or(RuntimeError::RuntimeUnavailable)
    }

    /// Return None only while another process owns the journal. Invalid
    /// storage, custody and trust remain errors and must not be retried as busy.
    #[allow(clippy::too_many_arguments)]
    pub fn try_open_canonical(
        trust: CapsuleTrust,
        fleet_public_key: &[u8],
        receipt_key: [u8; 32],
        replay_capacity: usize,
        artifact_capacity_bytes: u64,
        directory: &Path,
        admission: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Option<Self>> {
        if trust.fleet_id.is_empty()
            || trust.fleet_signer_id.is_empty()
            || trust.agent_signer_id.is_empty()
        {
            return Err(RuntimeError::InvalidInput);
        }
        let Some(store) = JournalStore::try_open(directory, "activation", || {
            crate::journal::Journal::empty(trust.target_id.clone())
        })?
        else {
            return Ok(None);
        };
        if trust.target_id.is_empty() || replay_capacity == 0 || artifact_capacity_bytes == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        let agent = Self {
            target_id: trust.target_id.clone(),
            legacy: None,
            capacity: replay_capacity,
            artifact_capacity_bytes,
            journal: std::sync::Mutex::new(store),
            request_observed: std::sync::Mutex::new(None),
            disposition_owner: std::sync::OnceLock::new(),
            wire: Some(WireOwner {
                trust,
                verifier: RuntimeWireVerifier::from_public_key_bytes(fleet_public_key)?,
                signer: RuntimeWireSigner::from_secret_bytes(receipt_key)?,
                admission,
            }),
        };
        agent.validate_canonical_journal()?;
        Ok(Some(agent))
    }
    pub(crate) fn wire(&self) -> RuntimeResult<&WireOwner> {
        self.wire.as_ref().ok_or(RuntimeError::InvalidAuthorization)
    }
    fn validate_canonical_journal(&self) -> RuntimeResult<()> {
        let owner = self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let journal = guard.state()?;
        if journal.target_id != self.target_id
            || journal.version != 1
            || journal.sequence != 0
            || journal.active.is_some()
            || !journal.prepared.is_empty()
            || !journal.receipts.is_empty()
            || !journal.consumed.is_empty()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let Some(state) = &journal.canonical else {
            return Ok(());
        };
        if let Some(lease) = &state.freshness_lease {
            owner.verify_lease_identity(lease)?;
        }
        if let Some(overlay) = &state.emergency_overlay {
            owner.verify_overlay(overlay)?;
        }
        if state.active.is_some() != (state.sequence > 0) || state.receipts.len() > self.capacity {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(active) = &state.active {
            let receipt = owner.validate_activation(active)?;
            if receipt.agent_sequence != state.sequence || !state.receipts.contains(&active.receipt)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        if let Some(previous) = &state.previous {
            let previous_receipt = owner.validate_activation(previous)?;
            let active = owner.validate(
                &state
                    .active
                    .as_ref()
                    .ok_or(RuntimeError::GenerationMismatch)?
                    .custody,
            )?;
            if previous_receipt.agent_sequence.checked_add(1) != Some(state.sequence)
                || active.previous_capsule_digest.as_ref() != Some(&previous_receipt.capsule_digest)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        if let Some(prepared) = &state.prepared {
            owner.validate(prepared)?;
        }
        let mut sequences = BTreeSet::new();
        for bytes in &state.receipts {
            let receipt = owner.signer.verifier().verify_receipt(bytes)?;
            if receipt.target_runtime_id != self.target_id
                || receipt.signer_id != owner.trust.agent_signer_id
                || receipt.agent_sequence > state.sequence
                || !sequences.insert(receipt.agent_sequence)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        self.admit_custody_capacity(state)
    }
    fn admit_custody_capacity(&self, state: &CanonicalJournal) -> RuntimeResult<()> {
        let mut content = BTreeMap::new();
        for custody in state
            .prepared
            .iter()
            .chain(state.active.iter().map(|a| &a.custody))
            .chain(state.previous.iter().map(|a| &a.custody))
        {
            for (digest, bytes) in &custody.artifacts {
                content.insert(digest, bytes.len() as u64);
            }
        }
        let total = content.values().try_fold(0u64, |sum, size| {
            sum.checked_add(*size).ok_or(RuntimeError::ReplayCapacity)
        })?;
        if total > self.artifact_capacity_bytes {
            return Err(RuntimeError::ReplayCapacity);
        }
        Ok(())
    }
    pub fn prepare_capsule(
        &self,
        signed_capsule: Vec<u8>,
        artifacts: BTreeMap<Digest, Vec<u8>>,
        now_ns: u64,
    ) -> RuntimeResult<Digest> {
        let owner = self.wire()?;
        let custody = Custody {
            signed_capsule,
            artifacts,
        };
        let capsule = owner.validate(&custody)?;
        if now_ns < capsule.not_before_ns || now_ns >= capsule.hard_expiry_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let digest = capsule.digest()?;
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut journal = guard.state()?.clone();
        let state = journal
            .canonical
            .get_or_insert_with(CanonicalJournal::default);
        let active = state
            .active
            .as_ref()
            .map(|a| owner.validate(&a.custody))
            .transpose()?;
        if capsule.previous_capsule_digest
            != active.as_ref().map(RuntimeCapsule::digest).transpose()?
            || active
                .as_ref()
                .is_some_and(|a| capsule.generation <= a.generation)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if state.receipts.iter().any(|r| {
            owner
                .signer
                .verifier()
                .verify_receipt(r)
                .is_ok_and(|r| r.capsule_digest == digest)
        }) {
            return Err(RuntimeError::Replay);
        }
        if let Some(prepared) = &state.prepared {
            if prepared.signed_capsule == custody.signed_capsule {
                return Ok(digest);
            }
            let previous = owner.validate(prepared)?;
            // An interrupted ACK/activation sequence may leave custody that
            // can no longer activate. A fresh signed preparation may replace
            // it atomically, preserving active lineage and generation order.
            // A still-valid preparation remains exclusively owned.
            if now_ns < previous.hard_expiry_ns || capsule.generation < previous.generation {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        state.prepared = Some(custody);
        self.admit_custody_capacity(state)?;
        guard.commit(journal)?;
        Ok(digest)
    }
    /// Recover custody for a restarted controller without preparing an old
    /// generation again. Validate both the supplied closure and durable owner;
    /// neither a historical receipt nor a matching caller digest is sufficient.
    pub fn recover_active_capsule(
        &self,
        signed_capsule: Vec<u8>,
        artifacts: BTreeMap<Digest, Vec<u8>>,
        now_ns: u64,
    ) -> RuntimeResult<Digest> {
        let custody = Custody {
            signed_capsule,
            artifacts,
        };
        let capsule = self.wire()?.validate(&custody)?;
        if now_ns < capsule.not_before_ns || now_ns >= capsule.hard_expiry_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let digest = capsule.digest()?;
        self.with_active_capsule(|active, artifacts| {
            if active.digest()? != digest || artifacts != &custody.artifacts {
                return Err(RuntimeError::GenerationMismatch);
            }
            Ok(digest)
        })
    }
    /// Component-only activation retained for custody regressions. Deployed
    /// targets must use `activate_capsule_authorized`.
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn activate_capsule(
        &self,
        expected: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<Vec<u8>> {
        self.activate_capsule_inner(expected, None, now_ns)
    }

    /// Verify the one-use Fleet token before the atomic target-local switch.
    /// A token is bound to the exact target, capsule, xDS version, predecessor,
    /// occurrence and validity interval; only its original retry replays receipt.
    pub fn activate_capsule_authorized(
        &self,
        signed_token: &[u8],
        now_ns: u64,
    ) -> RuntimeResult<Vec<u8>> {
        let token = self
            .wire()?
            .verifier
            .verify_activation_token(signed_token)?;
        if token.target_runtime_id != self.target_id {
            return Err(RuntimeError::TargetIdentity);
        }
        self.activate_capsule_inner(
            &token.desired_generation_digest,
            Some((signed_token, &token)),
            now_ns,
        )
    }

    fn activate_capsule_inner(
        &self,
        expected: &Digest,
        authorization: Option<(&[u8], &crate::RuntimeActivationToken)>,
        now_ns: u64,
    ) -> RuntimeResult<Vec<u8>> {
        let owner = self.wire()?;
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut journal = guard.state()?.clone();
        let state = journal
            .canonical
            .as_mut()
            .ok_or(RuntimeError::GenerationMismatch)?;
        if let Some(active) = &state.active {
            let receipt = owner.signer.verifier().verify_receipt(&active.receipt)?;
            if receipt.capsule_digest == *expected {
                return match (&active.activation_token, authorization) {
                    (Some(installed), Some((presented, _))) if installed == presented => {
                        Ok(active.receipt.clone())
                    }
                    (None, None) => Ok(active.receipt.clone()),
                    _ => Err(RuntimeError::Replay),
                };
            }
        }
        if let Some((_, token)) = authorization
            && (now_ns < token.issued_at_ns || now_ns >= token.expires_at_ns)
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let custody = state
            .prepared
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let capsule = owner.validate(custody)?;
        if capsule.digest()? != *expected {
            return Err(RuntimeError::GenerationMismatch);
        }
        if now_ns < capsule.not_before_ns || now_ns >= capsule.hard_expiry_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let active = state
            .active
            .as_ref()
            .map(|a| owner.validate(&a.custody))
            .transpose()?;
        if capsule.previous_capsule_digest
            != active.as_ref().map(RuntimeCapsule::digest).transpose()?
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some((_, token)) = authorization
            && (token.expected_previous_generation_digest != capsule.previous_capsule_digest
                || token.occurrence_id.is_empty()
                || token.xds_version_digest.as_str().is_empty())
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let retention_ns = super::RECEIPT_REPLAY_WINDOW_MS * 1_000_000;
        let mut retained = Vec::new();
        for bytes in &state.receipts {
            let receipt = owner.signer.verifier().verify_receipt(bytes)?;
            if now_ns < receipt.observed_at_ns.saturating_add(retention_ns) {
                retained.push(bytes.clone());
            }
        }
        if retained.len() >= self.capacity {
            return Err(RuntimeError::ReplayCapacity);
        }
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(RuntimeError::ReplayCapacity)?;
        let receipt = owner.signer.sign_receipt(&TargetActivationReceipt {
            receipt_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: self.target_id.clone(),
            capsule_digest: expected.clone(),
            contract_set_manifest_digest: capsule.contract_set_manifest_digest,
            complete_component_set_digest: capsule.complete_component_set_digest,
            status: 1,
            reason_code: "ACTIVE_LOCAL".into(),
            observed_at_ns: now_ns,
            agent_sequence: sequence,
            signer_id: owner.trust.agent_signer_id.clone(),
        })?;
        retained.push(receipt.clone());
        state.receipts = retained;
        state.sequence = sequence;
        // The one-use activation token changes custody, never disposition.
        // Retain withdrawal/currentness floors and fence this new generation.
        self.invalidate_disposition_current()?;
        state.previous = state.active.take();
        state.active = Some(Activation {
            custody: state
                .prepared
                .take()
                .ok_or(RuntimeError::GenerationMismatch)?,
            receipt: receipt.clone(),
            activation_token: authorization.map(|(signed, _)| signed.to_vec()),
        });
        self.admit_custody_capacity(state)?;
        guard.commit(journal)?;
        Ok(receipt)
    }

    /// Durable readback for the deployed RuntimeAgentService. The xDS version
    /// comes from the verified activation token retained in the active journal,
    /// never from current Envoy metadata or a caller-supplied generation.
    pub fn active_canonical_generation(&self) -> RuntimeResult<Option<(Digest, Digest, u64)>> {
        let owner = self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let Some(state) = guard.state()?.canonical.as_ref() else {
            return Ok(None);
        };
        let Some(active) = &state.active else {
            return Ok(None);
        };
        let receipt = owner.validate_activation(active)?;
        let signed_token = active
            .activation_token
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let token = owner.verifier.verify_activation_token(signed_token)?;
        Ok(Some((
            receipt.capsule_digest,
            token.xds_version_digest,
            receipt.agent_sequence,
        )))
    }
    /// Reads verified artifact bytes under the activation fence. The callback
    /// cannot outlive the fence or observe a partly installed generation.
    pub fn with_active_capsule<T>(
        &self,
        read: impl FnOnce(&RuntimeCapsule, &BTreeMap<Digest, Vec<u8>>) -> RuntimeResult<T>,
    ) -> RuntimeResult<T> {
        let owner = self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let active = guard
            .state()?
            .canonical
            .as_ref()
            .and_then(|v| v.active.as_ref())
            .ok_or(RuntimeError::GenerationMismatch)?;
        let capsule = owner.validate(&active.custody)?;
        read(&capsule, &active.custody.artifacts)
    }
    pub fn replay_canonical_receipts(&self) -> RuntimeResult<Vec<Vec<u8>>> {
        self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(guard
            .state()?
            .canonical
            .as_ref()
            .map_or_else(Vec::new, |s| s.receipts.clone()))
    }
}
