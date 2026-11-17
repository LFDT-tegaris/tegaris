//! Closed prerequisite wire types, not issuance, target clearance or serving
//! authority. Canonical owns purpose registration, authenticated current target
//! identity, committed admission, delivery/ACK persistence and all runtime gates.
//! A verified signature cannot establish currentness, installed denial or fsync.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Digest, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope, canonical_bytes,
};

// Canonical internal PurposeSigner families. These are distinct from C04's
// public PC-CBOR profiles and grant no numeric wire/permission registration.
pub const TARGET_DISPOSITION_DELIVERY_PURPOSE: &str = "openpc:target-disposition-delivery:v1";
pub const TARGET_DISPOSITION_ACK_PURPOSE: &str = "openpc:target-disposition-acknowledgement:v1";
pub const MAX_TARGET_DISPOSITION_WIRE_BYTES: usize = 16 * 1024;
const MAX_COUNTER: u64 = i64::MAX as u64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDispositionIdentity {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub target_id: String,
    pub credential_id: String,
    pub principal_id: String,
    pub credential_epoch: u64,
    pub principal_epoch: u64,
    pub certificate_digest: Digest,
}
impl TargetDispositionIdentity {
    pub fn validate(&self) -> RuntimeResult<()> {
        for id in [
            &self.participant_id,
            &self.privacy_domain_id,
            &self.target_id,
            &self.credential_id,
            &self.principal_id,
        ] {
            uuid_v7(id)?;
        }
        counter(self.credential_epoch)?;
        counter(self.principal_epoch)?;
        digest(&self.certificate_digest)
    }
    fn same_target(&self, other: &Self) -> bool {
        self.participant_id == other.participant_id
            && self.privacy_domain_id == other.privacy_domain_id
            && self.target_id == other.target_id
    }
}

/// The original active custody tuple. The input digest is the original full
/// configuration, not a substituted capsule/component digest. This profile does
/// not bootstrap a target with no original execution attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDispositionSource {
    pub runtime_configuration_input_id: String,
    pub configuration_digest: Digest,
    pub module_installation_id: String,
    pub module_configuration_generation_id: String,
    pub runtime_configuration_generation_id: String,
    pub capsule_digest: Digest,
    pub xds_version_digest: Digest,
    pub predecessor_capsule_digest: Option<Digest>,
    pub original_work_id: String,
    pub original_operation_id: String,
    pub original_execution_attempt_id: String,
}
impl TargetDispositionSource {
    pub fn validate(&self) -> RuntimeResult<()> {
        for id in [
            &self.runtime_configuration_input_id,
            &self.module_installation_id,
            &self.module_configuration_generation_id,
            &self.runtime_configuration_generation_id,
            &self.original_work_id,
            &self.original_operation_id,
            &self.original_execution_attempt_id,
        ] {
            uuid_v7(id)?;
        }
        for value in [
            &self.configuration_digest,
            &self.capsule_digest,
            &self.xds_version_digest,
        ] {
            digest(value)?;
        }
        if let Some(value) = &self.predecessor_capsule_digest {
            digest(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TargetDispositionDependency {
    Module,
    Policy,
    Source,
    Workload,
    Platform,
}

/// Original cause identity, not a new business intent. An unstarted suspension
/// has no attempt; UNKNOWN retains the original attempt when one exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TargetDispositionCause {
    Activation {
        work_id: String,
        operation_id: String,
        execution_attempt_id: Option<String>,
    },
    /// A fresh denial skips one preserved admission which never acquired a
    /// delivery. Control admits this only for an independently governed
    /// successor after proving the abandoned cause terminal and unstarted.
    UnsignedWithdrawalRecovery {
        work_id: String,
        operation_id: String,
        abandoned_revision: u64,
        abandoned_admission_digest: Digest,
    },
    /// One negative handover of an observed, expired effect. This never
    /// reconstructs the abandoned admission's first-issue authorization.
    ExpiredObservedDenialHandover {
        work_id: String,
        operation_id: String,
        execution_attempt_id: String,
        abandoned_revision: u64,
        abandoned_admission_digest: Digest,
        original_receipt_wire_digest: Digest,
        installed_revision: u64,
        installed_delivery_digest: Digest,
        observed_revision: u64,
        observed_admission_digest: Digest,
    },
    /// A current, ordinarily rotated credential may acknowledge only the
    /// original expired effect's denial. SQL owns rotation provenance; the
    /// wire binds its operation and the exact historical target identity.
    ExpiredObservedCredentialDenialHandover {
        work_id: String,
        operation_id: String,
        execution_attempt_id: String,
        abandoned_revision: u64,
        abandoned_admission_digest: Digest,
        original_receipt_wire_digest: Digest,
        installed_revision: u64,
        installed_delivery_digest: Digest,
        observed_revision: u64,
        observed_admission_digest: Digest,
        abandoned_target: TargetDispositionIdentity,
        credential_rotation_operation_id: String,
    },
    RuntimeArtifactRetirement {
        deletion_job_id: String,
        operation_id: String,
    },
    Dependency {
        owner: TargetDispositionDependency,
        resource_id: String,
        operation_id: String,
        revision: u64,
    },
}
impl TargetDispositionCause {
    pub fn validate(&self) -> RuntimeResult<()> {
        match self {
            Self::UnsignedWithdrawalRecovery {
                work_id,
                operation_id,
                abandoned_revision,
                abandoned_admission_digest,
            } => {
                uuid_v7(work_id)?;
                uuid_v7(operation_id)?;
                counter(*abandoned_revision)?;
                digest(abandoned_admission_digest)?;
            }
            Self::ExpiredObservedDenialHandover {
                work_id,
                operation_id,
                execution_attempt_id,
                abandoned_revision,
                abandoned_admission_digest,
                original_receipt_wire_digest,
                installed_revision,
                installed_delivery_digest,
                observed_revision,
                observed_admission_digest,
            } => {
                uuid_v7(work_id)?;
                uuid_v7(operation_id)?;
                uuid_v7(execution_attempt_id)?;
                for n in [abandoned_revision, installed_revision, observed_revision] {
                    counter(*n)?;
                }
                for d in [
                    abandoned_admission_digest,
                    original_receipt_wire_digest,
                    installed_delivery_digest,
                    observed_admission_digest,
                ] {
                    digest(d)?;
                }
            }
            Self::ExpiredObservedCredentialDenialHandover {
                work_id,
                operation_id,
                execution_attempt_id,
                abandoned_revision,
                abandoned_admission_digest,
                original_receipt_wire_digest,
                installed_revision,
                installed_delivery_digest,
                observed_revision,
                observed_admission_digest,
                abandoned_target,
                credential_rotation_operation_id,
            } => {
                for id in [
                    work_id,
                    operation_id,
                    execution_attempt_id,
                    credential_rotation_operation_id,
                ] {
                    uuid_v7(id)?;
                }
                abandoned_target.validate()?;
                for n in [abandoned_revision, installed_revision, observed_revision] {
                    counter(*n)?;
                }
                for d in [
                    abandoned_admission_digest,
                    original_receipt_wire_digest,
                    installed_delivery_digest,
                    observed_admission_digest,
                ] {
                    digest(d)?;
                }
            }
            Self::Activation {
                work_id,
                operation_id,
                execution_attempt_id,
            } => {
                uuid_v7(work_id)?;
                uuid_v7(operation_id)?;
                if let Some(id) = execution_attempt_id {
                    uuid_v7(id)?;
                }
            }
            Self::RuntimeArtifactRetirement {
                deletion_job_id,
                operation_id,
            } => {
                uuid_v7(deletion_job_id)?;
                uuid_v7(operation_id)?;
            }
            Self::Dependency {
                resource_id,
                operation_id,
                revision,
                ..
            } => {
                uuid_v7(resource_id)?;
                uuid_v7(operation_id)?;
                counter(*revision)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TargetDispositionAction {
    Withdraw,
    Restore,
    /// Confirms an already applied activation under its original execution
    /// identity. It cannot restore a predecessor or authorize a new effect.
    ConfirmActivation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDispositionDelivery {
    pub version: u16,
    pub target: TargetDispositionIdentity,
    pub source: TargetDispositionSource,
    pub cause: TargetDispositionCause,
    pub action: TargetDispositionAction,
    pub revision: u64,
    pub previous_revision: u64,
    pub previous_delivery_digest: Option<Digest>,
    /// Digest of the actual committed canonical admission, resolved by its
    /// owner. Shape/signature verification cannot prove that commit occurred.
    pub committed_admission_digest: Digest,
}
impl TargetDispositionDelivery {
    pub fn validate(&self) -> RuntimeResult<()> {
        version(self.version)?;
        self.target.validate()?;
        self.source.validate()?;
        self.cause.validate()?;
        counter(self.revision)?;
        let ordered = match &self.cause {
            TargetDispositionCause::UnsignedWithdrawalRecovery {
                abandoned_revision, ..
            } => {
                self.action == TargetDispositionAction::Withdraw
                    && self.previous_revision != 0
                    && self.previous_revision.checked_add(1) == Some(*abandoned_revision)
                    && abandoned_revision.checked_add(1) == Some(self.revision)
            }
            TargetDispositionCause::ExpiredObservedDenialHandover {
                abandoned_revision,
                installed_revision,
                installed_delivery_digest,
                work_id,
                operation_id,
                execution_attempt_id,
                observed_revision,
                observed_admission_digest,
                abandoned_admission_digest,
                ..
            } => {
                self.action == TargetDispositionAction::Withdraw
                    && self.source.predecessor_capsule_digest.is_some()
                    && self.previous_revision == *installed_revision
                    && self.previous_delivery_digest.as_ref() == Some(installed_delivery_digest)
                    && installed_revision.checked_add(1) == Some(*abandoned_revision)
                    && abandoned_revision.checked_add(1) == Some(self.revision)
                    && work_id == &self.source.original_work_id
                    && operation_id == &self.source.original_operation_id
                    && execution_attempt_id == &self.source.original_execution_attempt_id
                    && (*observed_revision == *installed_revision
                        || (*observed_revision == *abandoned_revision
                            && observed_admission_digest == abandoned_admission_digest))
                    && expired_handover::reconstruct_abandoned(self)? == *abandoned_admission_digest
            }
            TargetDispositionCause::ExpiredObservedCredentialDenialHandover { .. } => {
                expired_credential_handover::historical_projection(self)?.validate()?;
                true
            }
            _ => self.previous_revision.checked_add(1) == Some(self.revision),
        };
        if !ordered
            || (matches!(
                self.cause,
                TargetDispositionCause::Dependency {
                    owner: TargetDispositionDependency::Platform,
                    ..
                }
            ) && self.action != TargetDispositionAction::Withdraw)
            || (self.previous_revision == 0) != self.previous_delivery_digest.is_none()
            || (self.action == TargetDispositionAction::Restore && self.previous_revision == 0)
            || (self.action == TargetDispositionAction::Restore
                && matches!(
                    self.cause,
                    TargetDispositionCause::RuntimeArtifactRetirement { .. }
                ))
        {
            return Err(RuntimeError::InvalidTransition);
        }
        if let Some(value) = &self.previous_delivery_digest {
            digest(value)?;
        }
        if self.action == TargetDispositionAction::ConfirmActivation
            && (self.cause
                != (TargetDispositionCause::Activation {
                    work_id: self.source.original_work_id.clone(),
                    operation_id: self.source.original_operation_id.clone(),
                    execution_attempt_id: Some(self.source.original_execution_attempt_id.clone()),
                })
                || (self.previous_revision == 0
                    && self.source.predecessor_capsule_digest.is_some()))
        {
            return Err(RuntimeError::InvalidTransition);
        }
        digest(&self.committed_admission_digest)
    }
}

/// Exact installed state claimed by the target's durable owner. Neither state
/// says that a provider effect did not happen, that references are clear, or that
/// current business authorization permits serving. Expiry/ADS ACK are excluded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TargetDispositionInstalledState {
    NewUseDenied,
    SuspensionCleared,
    ActivationConfirmed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDispositionAcknowledgement {
    pub version: u16,
    pub target: TargetDispositionIdentity,
    pub delivery_digest: Digest,
    pub disposition_revision: u64,
    pub journal_sequence: u64,
    pub installed_state: TargetDispositionInstalledState,
}
impl TargetDispositionAcknowledgement {
    pub fn validate(&self) -> RuntimeResult<()> {
        version(self.version)?;
        self.target.validate()?;
        digest(&self.delivery_digest)?;
        counter(self.disposition_revision)?;
        counter(self.journal_sequence)
    }
}

/// Pure comparison result. Applying/persisting a successor and replaying its
/// original ACK remain with the actual target journal owner; no cache lives here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetDispositionOrder {
    InitialWithdrawal,
    InitialActivation,
    Successor,
    ExactReplay,
}

pub struct VerifiedTargetDispositionDelivery {
    claims: TargetDispositionDelivery,
    signed_digest: Digest,
    // Prevent a delivery verified under another installation's Control trust
    // from being laundered through this installation's target ACK verifier.
    control_public_key: Vec<u8>,
}
impl VerifiedTargetDispositionDelivery {
    pub fn claims(&self) -> &TargetDispositionDelivery {
        &self.claims
    }
    pub fn signed_digest(&self) -> &Digest {
        &self.signed_digest
    }

    /// The previous value must come from authenticated committed journal state,
    /// never the incoming caller. This compares data; it proves no persistence.
    pub fn compare_previous(
        &self,
        previous: Option<&Self>,
    ) -> RuntimeResult<TargetDispositionOrder> {
        let Some(previous) = previous else {
            return match (self.claims.revision, self.claims.action) {
                (1, TargetDispositionAction::Withdraw) => {
                    Ok(TargetDispositionOrder::InitialWithdrawal)
                }
                (1, TargetDispositionAction::ConfirmActivation) => {
                    Ok(TargetDispositionOrder::InitialActivation)
                }
                _ => Err(RuntimeError::GenerationMismatch),
            };
        };
        if !self.claims.target.same_target(&previous.claims.target) {
            return Err(RuntimeError::TargetIdentity);
        }
        if self.signed_digest == previous.signed_digest && self.claims == previous.claims {
            return Ok(TargetDispositionOrder::ExactReplay);
        }
        if self.claims.previous_revision != previous.claims.revision
            || self.claims.previous_delivery_digest.as_ref() != Some(&previous.signed_digest)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if matches!(
            self.claims.cause,
            TargetDispositionCause::UnsignedWithdrawalRecovery { .. }
        ) && (self.claims.target != previous.claims.target
            || self.claims.source != previous.claims.source)
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        expired_handover::compare_installed(
            &self.claims,
            &previous.claims,
            &previous.signed_digest,
        )?;
        expired_credential_handover::compare_installed(
            &self.claims,
            &previous.claims,
            &previous.signed_digest,
        )?;
        if self.claims.action == TargetDispositionAction::Restore
            && (previous.claims.action != TargetDispositionAction::Withdraw
                || self.claims.source != previous.claims.source
                || self.claims.cause != previous.claims.cause)
        {
            return Err(RuntimeError::InvalidTransition);
        }
        if self.claims.action == TargetDispositionAction::ConfirmActivation {
            let expected_cause = &self.claims.cause;
            let cause_matches = match (&previous.claims.cause, expected_cause) {
                (
                    TargetDispositionCause::UnsignedWithdrawalRecovery {
                        work_id: old_work,
                        operation_id: old_operation,
                        ..
                    },
                    TargetDispositionCause::Activation {
                        work_id,
                        operation_id,
                        execution_attempt_id,
                    },
                ) => {
                    old_work == work_id
                        && old_operation == operation_id
                        && execution_attempt_id.is_some()
                }
                (
                    TargetDispositionCause::Activation {
                        work_id: old_work,
                        operation_id: old_operation,
                        execution_attempt_id: old_attempt,
                    },
                    TargetDispositionCause::Activation {
                        work_id,
                        operation_id,
                        execution_attempt_id,
                    },
                ) => {
                    old_work == work_id
                        && old_operation == operation_id
                        && (old_attempt.is_none() || old_attempt == execution_attempt_id)
                }
                _ => false,
            };
            if previous.claims.action != TargetDispositionAction::Withdraw
                || !cause_matches
                || self.claims.source.predecessor_capsule_digest.as_ref()
                    != Some(&previous.claims.source.capsule_digest)
                || self.claims.source.capsule_digest == previous.claims.source.capsule_digest
                || self.claims.source.original_work_id == previous.claims.source.original_work_id
            {
                return Err(RuntimeError::InvalidTransition);
            }
        }
        Ok(TargetDispositionOrder::Successor)
    }

    /// The journal supplies the retained floor. This is a comparison only;
    /// recovery may skip exactly its signed, committed abandoned admission.
    pub fn check_recovery_floor(
        &self,
        previous: &Self,
        revision: u64,
        admission: &Digest,
    ) -> RuntimeResult<()> {
        if matches!(
            self.claims.cause,
            TargetDispositionCause::ExpiredObservedDenialHandover { .. }
        ) {
            self.compare_previous(Some(previous))?;
            return expired_handover::check_floor(
                &self.claims,
                &previous.claims,
                revision,
                admission,
            );
        }
        if matches!(
            self.claims.cause,
            TargetDispositionCause::ExpiredObservedCredentialDenialHandover { .. }
        ) {
            self.compare_previous(Some(previous))?;
            let projection = expired_credential_handover::historical_projection(&self.claims)?;
            return expired_handover::check_floor(
                &projection,
                &previous.claims,
                revision,
                admission,
            );
        }
        let TargetDispositionCause::UnsignedWithdrawalRecovery {
            abandoned_revision,
            abandoned_admission_digest,
            ..
        } = &self.claims.cause
        else {
            return Ok(());
        };
        self.compare_previous(Some(previous))?;
        if (revision == previous.claims.revision
            && admission == &previous.claims.committed_admission_digest)
            || (revision == *abandoned_revision && admission == abandoned_admission_digest)
        {
            Ok(())
        } else {
            Err(RuntimeError::GenerationMismatch)
        }
    }
}

pub struct VerifiedTargetDispositionAcknowledgement {
    claims: TargetDispositionAcknowledgement,
    signed_digest: Digest,
}
impl VerifiedTargetDispositionAcknowledgement {
    pub fn claims(&self) -> &TargetDispositionAcknowledgement {
        &self.claims
    }
    pub fn signed_digest(&self) -> &Digest {
        &self.signed_digest
    }

    pub fn compare_previous(&self, previous: &Self) -> RuntimeResult<TargetDispositionOrder> {
        if !self.claims.target.same_target(&previous.claims.target) {
            return Err(RuntimeError::TargetIdentity);
        }
        if self.signed_digest == previous.signed_digest && self.claims == previous.claims {
            return Ok(TargetDispositionOrder::ExactReplay);
        }
        if self.claims.disposition_revision
            != previous
                .claims
                .disposition_revision
                .checked_add(1)
                .ok_or(RuntimeError::GenerationMismatch)?
            || self.claims.journal_sequence <= previous.claims.journal_sequence
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(TargetDispositionOrder::Successor)
    }
}

/// Installed host trust only. The canonical authenticator must bind these keys
/// and the expected identity to the actual target. No key arrives in the wire.
pub struct TargetDispositionVerifier {
    target: TargetDispositionIdentity,
    delivery: PurposeVerifier,
    acknowledgement: PurposeVerifier,
}
impl TargetDispositionVerifier {
    pub fn from_host_keys(
        target: TargetDispositionIdentity,
        control_key: &[u8],
        target_key: &[u8],
    ) -> RuntimeResult<Self> {
        target.validate()?;
        let delivery =
            PurposeVerifier::from_sec1_bytes(TARGET_DISPOSITION_DELIVERY_PURPOSE, control_key)?;
        let acknowledgement =
            PurposeVerifier::from_sec1_bytes(TARGET_DISPOSITION_ACK_PURPOSE, target_key)?;
        if delivery.sec1_bytes() == acknowledgement.sec1_bytes() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self {
            target,
            delivery,
            acknowledgement,
        })
    }
    /// Expected source comes from real original custody/readback, independently
    /// of the incoming message. Verification grants no currentness or effect.
    pub fn verify_delivery(
        &self,
        bytes: &[u8],
        expected: &TargetDispositionSource,
    ) -> RuntimeResult<VerifiedTargetDispositionDelivery> {
        let signed: SignedEnvelope<TargetDispositionDelivery> = decode(bytes)?;
        self.delivery.verify(&signed)?;
        signed.claims.validate()?;
        expected.validate()?;
        if signed.claims.target != self.target || signed.claims.source != *expected {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(VerifiedTargetDispositionDelivery {
            claims: signed.claims,
            signed_digest: Digest::of(bytes),
            control_public_key: self.delivery.sec1_bytes(),
        })
    }
    pub fn verify_acknowledgement(
        &self,
        bytes: &[u8],
        delivery: &VerifiedTargetDispositionDelivery,
    ) -> RuntimeResult<VerifiedTargetDispositionAcknowledgement> {
        let signed: SignedEnvelope<TargetDispositionAcknowledgement> = decode(bytes)?;
        self.acknowledgement.verify(&signed)?;
        signed.claims.validate()?;
        let expected = match delivery.claims.action {
            TargetDispositionAction::Withdraw => TargetDispositionInstalledState::NewUseDenied,
            TargetDispositionAction::Restore => TargetDispositionInstalledState::SuspensionCleared,
            TargetDispositionAction::ConfirmActivation => {
                TargetDispositionInstalledState::ActivationConfirmed
            }
        };
        if delivery.control_public_key != self.delivery.sec1_bytes()
            || delivery.claims.target != self.target
            || signed.claims.target != self.target
            || signed.claims.delivery_digest != delivery.signed_digest
            || signed.claims.disposition_revision != delivery.claims.revision
            || signed.claims.installed_state != expected
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(VerifiedTargetDispositionAcknowledgement {
            claims: signed.claims,
            signed_digest: Digest::of(bytes),
        })
    }
}

pub fn encode_target_disposition_delivery(
    signed: &SignedEnvelope<TargetDispositionDelivery>,
) -> RuntimeResult<Vec<u8>> {
    signed.claims.validate()?;
    if signed.purpose != TARGET_DISPOSITION_DELIVERY_PURPOSE {
        return Err(RuntimeError::InvalidAuthorization);
    }
    encode(signed)
}
pub fn encode_target_disposition_acknowledgement(
    signed: &SignedEnvelope<TargetDispositionAcknowledgement>,
) -> RuntimeResult<Vec<u8>> {
    signed.claims.validate()?;
    if signed.purpose != TARGET_DISPOSITION_ACK_PURPOSE {
        return Err(RuntimeError::InvalidAuthorization);
    }
    encode(signed)
}
fn version(value: u16) -> RuntimeResult<()> {
    if value != 1 {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}
fn counter(value: u64) -> RuntimeResult<()> {
    if value == 0 || value > MAX_COUNTER {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}
fn digest(value: &Digest) -> RuntimeResult<()> {
    if Digest::parse(value.as_str())? != *value {
        return Err(RuntimeError::InvalidDigest);
    }
    Ok(())
}
fn uuid_v7(value: &str) -> RuntimeResult<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[14] != b'7'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        || !bytes.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
    {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> RuntimeResult<Vec<u8>> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > MAX_TARGET_DISPOSITION_WIRE_BYTES {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> RuntimeResult<T> {
    if bytes.is_empty() || bytes.len() > MAX_TARGET_DISPOSITION_WIRE_BYTES {
        return Err(RuntimeError::InvalidInput);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
    // The existing generic envelope is permissive. Exact canonical roundtrip
    // closes its unknown/duplicate fields and alternate JSON representations.
    if encode(&value)? != bytes {
        return Err(RuntimeError::CanonicalEncoding);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "target_disposition_tests.rs"]
mod tests;

#[path = "target_disposition/expired_handover.rs"]
mod expired_handover;

#[path = "target_disposition/expired_credential_handover.rs"]
mod expired_credential_handover;
