//! Internal retirement wire profiles. Host-installed trust authenticates the
//! durable Control admission; a signature is never target-store eligibility.
//! The SQLx owner must still serialize execute/cancel and check its live source,
//! generation, readiness, references, retention and archive predicates.
//!
//! This module exposes wire verification, not a durable Control admission owner.
//! No deletion entrypoint is exposed; target mutations remain closed until that
//! owner and the target's atomic SQL predicates are integrated.

use serde::{Deserialize, Serialize};

use crate::store_retirement::{
    RetirementAttempt, RetirementOutcome, RetirementScope, RetirementStore,
};
use crate::{Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope};

pub const REQUEST_PURPOSE: &str = "openpc:store-retirement-request:v1";
pub const CANCEL_PURPOSE: &str = "openpc:store-retirement-cancel:v1";
pub const OUTCOME_PURPOSE: &str = "openpc:store-retirement-outcome:v1";
const MAX_WIRE_BYTES: usize = 1_048_576;
const MAX_AUTHORITY_LIFETIME_MS: u64 = 60_000;

/// A deployment identity, never supplied by a deletion caller. Store and scope
/// are repeated in the attempt and must agree with this host-installed binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementHost {
    pub environment_id: String,
    pub target_id: String,
    pub scope: RetirementScope,
    pub store: RetirementStore,
}

/// Host configuration loaded with service configuration, never from a request.
/// Installation pins the separately configured service identity as well as both
/// purpose-key roles. This contains public keys only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementAuthorityConfiguration {
    pub version: u16,
    pub host: RetirementHost,
    pub control_public_key_sec1: Vec<u8>,
    pub target_public_key_sec1: Vec<u8>,
}

impl RetirementAuthorityConfiguration {
    pub fn install(
        self,
        expected_host: &RetirementHost,
    ) -> RuntimeResult<RetirementAuthorityTrust> {
        version(self.version)?;
        if self.host != *expected_host {
            return Err(RuntimeError::InvalidAuthorization);
        }
        RetirementAuthorityTrust::from_host_keys(
            self.host,
            &self.control_public_key_sec1,
            &self.target_public_key_sec1,
        )
    }
}

impl RetirementHost {
    fn validate(&self) -> RuntimeResult<()> {
        self.scope.validate().map_err(rejected)?;
        for value in [&self.environment_id, &self.target_id] {
            if value.is_empty() || value.len() > 160 || !value.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        Ok(())
    }

    fn matches(&self, attempt: &RetirementAttempt) -> RuntimeResult<()> {
        self.validate()?;
        attempt.validate().map_err(rejected)?;
        if self.scope != attempt.scope || self.store != attempt.store {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
}

/// Receipt and committed-admission digests bind the real Control owner. That
/// owner may issue this only after commit; an uncertain commit requires readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementRequestClaims {
    pub version: u16,
    pub host: RetirementHost,
    pub attempt: RetirementAttempt,
    pub admission_receipt_digest: Digest,
    pub committed_admission_digest: Digest,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Carries the complete original attempt so a target can create a durable
/// cancellation tombstone before the dispatch arrives. A hold revision alone
/// does not assert that an already-dispatched effect has been prevented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementCancelClaims {
    pub version: u16,
    pub host: RetirementHost,
    pub attempt: RetirementAttempt,
    pub cancellation_id: String,
    pub lifecycle_revision: u64,
    pub committed_cancellation_digest: Digest,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// The target stores these exact signed bytes with its terminal transaction.
/// Readback returns the original bytes; it never signs a fresh outcome on retry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementOutcomeClaims {
    pub version: u16,
    pub host: RetirementHost,
    pub business_intent_id: String,
    pub attempt_id: String,
    pub outcome: RetirementOutcome,
    pub completed_at_ms: u64,
}

/// Signature admission only. No Deserialize/public constructor/eligibility flag.
pub struct VerifiedRetirementRequest {
    claims: RetirementRequestClaims,
    signed_digest: Digest,
}
impl VerifiedRetirementRequest {
    pub fn claims(&self) -> &RetirementRequestClaims {
        &self.claims
    }
    pub fn signed_digest(&self) -> &Digest {
        &self.signed_digest
    }
    pub fn ensure_live(&self, now_ms: u64) -> RuntimeResult<()> {
        validate_request(&self.claims, now_ms)
    }
}

pub struct VerifiedRetirementCancel {
    claims: RetirementCancelClaims,
    signed_digest: Digest,
}
impl VerifiedRetirementCancel {
    pub fn claims(&self) -> &RetirementCancelClaims {
        &self.claims
    }
    pub fn signed_digest(&self) -> &Digest {
        &self.signed_digest
    }
    pub fn ensure_live(&self, now_ms: u64) -> RuntimeResult<()> {
        validate_cancel(&self.claims, now_ms)
    }
}

/// Installed by the host, outside all request bodies. Request/cancel trust is
/// independent of the target outcome key and of ordinary Fact-update authority.
pub struct RetirementAuthorityTrust {
    host: RetirementHost,
    request: PurposeVerifier,
    cancel: PurposeVerifier,
    outcome: PurposeVerifier,
}
impl RetirementAuthorityTrust {
    pub fn from_host_keys(
        host: RetirementHost,
        control_public_key_sec1: &[u8],
        target_public_key_sec1: &[u8],
    ) -> RuntimeResult<Self> {
        host.validate()?;
        let request = PurposeVerifier::from_sec1_bytes(REQUEST_PURPOSE, control_public_key_sec1)?;
        let outcome = PurposeVerifier::from_sec1_bytes(OUTCOME_PURPOSE, target_public_key_sec1)?;
        if request.sec1_bytes() == outcome.sec1_bytes() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self {
            host,
            request,
            cancel: PurposeVerifier::from_sec1_bytes(CANCEL_PURPOSE, control_public_key_sec1)?,
            outcome,
        })
    }

    pub fn verify_request(
        &self,
        bytes: &[u8],
        now_ms: u64,
    ) -> RuntimeResult<VerifiedRetirementRequest> {
        let signed: SignedEnvelope<RetirementRequestClaims> = decode(bytes)?;
        self.request.verify(&signed)?;
        let claims = signed.claims;
        self.check_host(&claims.host, &claims.attempt)?;
        validate_request(&claims, now_ms)?;
        Ok(VerifiedRetirementRequest {
            claims,
            signed_digest: Digest::of(bytes),
        })
    }

    pub fn verify_cancel(
        &self,
        bytes: &[u8],
        now_ms: u64,
    ) -> RuntimeResult<VerifiedRetirementCancel> {
        let signed: SignedEnvelope<RetirementCancelClaims> = decode(bytes)?;
        self.cancel.verify(&signed)?;
        let claims = signed.claims;
        self.check_host(&claims.host, &claims.attempt)?;
        validate_cancel(&claims, now_ms)?;
        Ok(VerifiedRetirementCancel {
            claims,
            signed_digest: Digest::of(bytes),
        })
    }

    /// Historical outcomes have no new execution authority or renewable expiry.
    /// Missing rows and transport errors must remain UNKNOWN at the caller.
    pub fn verify_outcome(
        &self,
        bytes: &[u8],
        attempt: &RetirementAttempt,
    ) -> RuntimeResult<RetirementOutcomeClaims> {
        let signed: SignedEnvelope<RetirementOutcomeClaims> = decode(bytes)?;
        self.outcome.verify(&signed)?;
        self.check_host(&signed.claims.host, attempt)?;
        validate_outcome(&signed.claims, attempt)?;
        Ok(signed.claims)
    }

    fn check_host(&self, host: &RetirementHost, attempt: &RetirementAttempt) -> RuntimeResult<()> {
        if *host != self.host {
            return Err(RuntimeError::InvalidAuthorization);
        }
        host.matches(attempt)
    }
}

/// This key is a service-host capability. It must be provided only to the
/// governed committed-attempt dispatcher, never a public generic signing API.
pub struct RetirementDispatchSigner {
    host: RetirementHost,
    request: PurposeSigner,
    cancel: PurposeSigner,
}
impl RetirementDispatchSigner {
    pub fn from_host_key(host: RetirementHost, key: [u8; 32]) -> RuntimeResult<Self> {
        host.validate()?;
        Ok(Self {
            host,
            request: PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, key)?,
            cancel: PurposeSigner::from_secret_bytes(CANCEL_PURPOSE, key)?,
        })
    }
    pub fn sign_committed_request(
        &self,
        claims: RetirementRequestClaims,
        now_ms: u64,
    ) -> RuntimeResult<Vec<u8>> {
        if claims.host != self.host {
            return Err(RuntimeError::InvalidAuthorization);
        }
        validate_request(&claims, now_ms)?;
        encode(&self.request.sign(claims)?)
    }
    pub fn sign_committed_cancellation(
        &self,
        claims: RetirementCancelClaims,
        now_ms: u64,
    ) -> RuntimeResult<Vec<u8>> {
        if claims.host != self.host {
            return Err(RuntimeError::InvalidAuthorization);
        }
        validate_cancel(&claims, now_ms)?;
        encode(&self.cancel.sign(claims)?)
    }
}

/// Kept inside the target transaction owner. Signing alone does not establish
/// commit; original outcome bytes and physical effects must commit atomically.
pub struct RetirementOutcomeSigner {
    host: RetirementHost,
    signer: PurposeSigner,
}
impl RetirementOutcomeSigner {
    pub fn from_host_key(host: RetirementHost, key: [u8; 32]) -> RuntimeResult<Self> {
        host.validate()?;
        Ok(Self {
            host,
            signer: PurposeSigner::from_secret_bytes(OUTCOME_PURPOSE, key)?,
        })
    }
    pub fn sign_in_transaction(
        &self,
        claims: RetirementOutcomeClaims,
        attempt: &RetirementAttempt,
    ) -> RuntimeResult<Vec<u8>> {
        if claims.host != self.host {
            return Err(RuntimeError::InvalidAuthorization);
        }
        self.host.matches(attempt)?;
        validate_outcome(&claims, attempt)?;
        encode(&self.signer.sign(claims)?)
    }
}

fn validate_request(claims: &RetirementRequestClaims, now_ms: u64) -> RuntimeResult<()> {
    claims.host.matches(&claims.attempt)?;
    version(claims.version)?;
    lifetime(claims.issued_at_ms, claims.expires_at_ms, now_ms)?;
    exact_digest(&claims.admission_receipt_digest)?;
    exact_digest(&claims.committed_admission_digest)
}
fn validate_cancel(claims: &RetirementCancelClaims, now_ms: u64) -> RuntimeResult<()> {
    claims.host.matches(&claims.attempt)?;
    version(claims.version)?;
    lifetime(claims.issued_at_ms, claims.expires_at_ms, now_ms)?;
    if claims.cancellation_id.is_empty()
        || claims.cancellation_id.len() > 160
        || !claims.cancellation_id.bytes().all(|b| b.is_ascii_graphic())
        || claims.lifecycle_revision < claims.attempt.governance.lifecycle_revision
        || claims.lifecycle_revision > i64::MAX as u64
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    exact_digest(&claims.committed_cancellation_digest)
}
fn validate_outcome(
    claims: &RetirementOutcomeClaims,
    attempt: &RetirementAttempt,
) -> RuntimeResult<()> {
    version(claims.version)?;
    claims.host.matches(attempt)?;
    if claims.business_intent_id != attempt.business_intent_id
        || claims.attempt_id != attempt.attempt_id
        || claims.completed_at_ms == 0
        || claims.completed_at_ms > i64::MAX as u64
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    claims.outcome.validate_for(attempt).map_err(rejected)
}
fn version(value: u16) -> RuntimeResult<()> {
    if value != 1 {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}
fn lifetime(issued: u64, expires: u64, now: u64) -> RuntimeResult<()> {
    if issued == 0
        || now < issued
        || now >= expires
        || expires > i64::MAX as u64
        || expires
            .checked_sub(issued)
            .is_none_or(|span| span == 0 || span > MAX_AUTHORITY_LIFETIME_MS)
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}
fn exact_digest(value: &Digest) -> RuntimeResult<()> {
    if Digest::parse(value.as_str())? != *value {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> RuntimeResult<Vec<u8>> {
    let bytes = crate::canonical_bytes(value)?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> RuntimeResult<T> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let value: T = serde_json::from_slice(bytes).map_err(rejected)?;
    // Reject unknown envelope fields, duplicate keys, alternate spellings and
    // trailing data even though generic SignedEnvelope is used elsewhere.
    if encode(&value)? != bytes {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(value)
}
fn rejected<T>(_: T) -> RuntimeError {
    RuntimeError::InvalidAuthorization
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_retirement::{
        CandidatePayloadSelection, RetirementEffect, RetirementGovernance, RetirementSelection,
        RetirementSource,
    };

    fn request() -> RetirementRequestClaims {
        let scope = RetirementScope {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
        };
        let selection = RetirementSelection::Candidates {
            source: RetirementSource {
                profile_id: "profile".into(),
                generation_id: "generation".into(),
                partition_id: "partition".into(),
                identity_digest: Digest::of(b"source"),
            },
            rows: vec![CandidatePayloadSelection {
                candidate_id: "candidate".into(),
                candidate_feed_sequence: 9,
                payload_digest: Digest::of(b"payload"),
                payload_bytes: 7,
                checkpoint_digest: Digest::of(b"checkpoint"),
            }],
        };
        RetirementRequestClaims {
            version: 1,
            host: RetirementHost {
                environment_id: "local".into(),
                target_id: "candidate-owner".into(),
                scope: scope.clone(),
                store: RetirementStore::CandidateIndex,
            },
            attempt: RetirementAttempt {
                selection_digest: selection.digest(&scope).unwrap(),
                selection,
                scope,
                store: RetirementStore::CandidateIndex,
                business_intent_id: "business".into(),
                attempt_id: "attempt".into(),
                governance: RetirementGovernance {
                    retention_policy_digest: Digest::of(b"retention"),
                    archive_manifest_digest: Digest::of(b"archive"),
                    archive_acknowledgement_digest: Digest::of(b"ack"),
                    approval_digest: Digest::of(b"approval"),
                    lifecycle_revision: 2,
                    retention_not_before_ms: 1,
                },
            },
            admission_receipt_digest: Digest::of(b"receipt"),
            committed_admission_digest: Digest::of(b"commit"),
            issued_at_ms: 100,
            expires_at_ms: 1100,
        }
    }
    fn keys(
        host: &RetirementHost,
    ) -> (
        RetirementDispatchSigner,
        RetirementOutcomeSigner,
        RetirementAuthorityTrust,
    ) {
        let control = PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32]).unwrap();
        let target = PurposeSigner::from_secret_bytes(OUTCOME_PURPOSE, [32; 32]).unwrap();
        (
            RetirementDispatchSigner::from_host_key(host.clone(), [31; 32]).unwrap(),
            RetirementOutcomeSigner::from_host_key(host.clone(), [32; 32]).unwrap(),
            RetirementAuthorityTrust::from_host_keys(
                host.clone(),
                &control.verifier().sec1_bytes(),
                &target.verifier().sec1_bytes(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn host_configuration_pins_identity_and_separates_key_roles() {
        let claims = request();
        let control = PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32]).unwrap();
        let target = PurposeSigner::from_secret_bytes(OUTCOME_PURPOSE, [32; 32]).unwrap();
        let configuration = RetirementAuthorityConfiguration {
            version: 1,
            host: claims.host.clone(),
            control_public_key_sec1: control.verifier().sec1_bytes(),
            target_public_key_sec1: target.verifier().sec1_bytes(),
        };
        assert!(configuration.clone().install(&claims.host).is_ok());
        let mut wrong_host = claims.host.clone();
        wrong_host.target_id = "foreign".into();
        assert!(configuration.clone().install(&wrong_host).is_err());
        for changed in 0..3 {
            let mut invalid = configuration.clone();
            match changed {
                0 => invalid.version = 2,
                1 => invalid.target_public_key_sec1 = invalid.control_public_key_sec1.clone(),
                _ => invalid.control_public_key_sec1 = vec![0; 33],
            }
            assert!(invalid.install(&claims.host).is_err());
        }
    }

    #[test]
    fn actual_signature_pins_host_original_attempt_and_finite_lifetime() {
        let claims = request();
        let (signer, _, trust) = keys(&claims.host);
        let bytes = signer.sign_committed_request(claims.clone(), 100).unwrap();
        let verified = trust.verify_request(&bytes, 101).unwrap();
        assert_eq!(verified.claims(), &claims);
        assert_eq!(verified.signed_digest(), &Digest::of(&bytes));
        assert!(verified.ensure_live(1100).is_err());
        for now in [0, 99, 1100, u64::MAX] {
            assert!(trust.verify_request(&bytes, now).is_err());
        }
        for changed in 0..5 {
            let mut altered = claims.clone();
            match changed {
                0 => altered.host.environment_id = "other".into(),
                1 => altered.host.target_id = "other".into(),
                2 => altered.host.scope.privacy_domain_id = "other".into(),
                3 => altered.attempt.governance.lifecycle_revision += 1,
                _ => altered.admission_receipt_digest = Digest::of(b"different"),
            }
            let mut envelope: SignedEnvelope<RetirementRequestClaims> = decode(&bytes).unwrap();
            envelope.claims = altered;
            assert!(
                trust
                    .verify_request(&encode(&envelope).unwrap(), 101)
                    .is_err()
            );
        }
        let wrong_key =
            RetirementDispatchSigner::from_host_key(claims.host.clone(), [33; 32]).unwrap();
        assert!(
            trust
                .verify_request(&wrong_key.sign_committed_request(claims, 100).unwrap(), 101)
                .is_err()
        );
    }

    #[test]
    fn even_valid_signature_cannot_change_host_scope_or_profile() {
        let claims = request();
        let (_, _, trust) = keys(&claims.host);
        for changed in 0..5 {
            let mut altered = claims.clone();
            match changed {
                0 => altered.version = 2,
                1 => altered.host.target_id = "foreign".into(),
                2 => altered.host.environment_id = "foreign".into(),
                3 => altered.expires_at_ms = 60_101,
                _ => altered.host.store = RetirementStore::Facts,
            }
            let raw = PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32])
                .unwrap()
                .sign(altered)
                .unwrap();
            assert!(trust.verify_request(&encode(&raw).unwrap(), 101).is_err());
        }
        let wrong_purpose = PurposeSigner::from_secret_bytes(CANCEL_PURPOSE, [31; 32])
            .unwrap()
            .sign(claims)
            .unwrap();
        assert!(
            trust
                .verify_request(&encode(&wrong_purpose).unwrap(), 101)
                .is_err()
        );
    }

    #[test]
    fn cancellation_carries_original_identity_before_dispatch() {
        let request = request();
        let (signer, _, trust) = keys(&request.host);
        let claims = RetirementCancelClaims {
            version: 1,
            host: request.host,
            attempt: request.attempt,
            cancellation_id: "cancel".into(),
            lifecycle_revision: 3,
            committed_cancellation_digest: Digest::of(b"committed cancellation"),
            issued_at_ms: 100,
            expires_at_ms: 1100,
        };
        let bytes = signer
            .sign_committed_cancellation(claims.clone(), 100)
            .unwrap();
        assert_eq!(trust.verify_cancel(&bytes, 101).unwrap().claims(), &claims);
        assert!(trust.verify_request(&bytes, 101).is_err());
        let mut older = claims;
        older.lifecycle_revision = 1;
        assert!(signer.sign_committed_cancellation(older, 100).is_err());
    }

    #[test]
    fn original_outcome_is_pinned_and_remains_historical() {
        let request = request();
        let (_, signer, trust) = keys(&request.host);
        let claims = RetirementOutcomeClaims {
            version: 1,
            host: request.host,
            business_intent_id: request.attempt.business_intent_id.clone(),
            attempt_id: request.attempt.attempt_id.clone(),
            outcome: RetirementOutcome {
                attempt_digest: request.attempt.digest().unwrap(),
                effect: RetirementEffect::Applied {
                    retired_rows: 1,
                    retired_payload_bytes: 7,
                    retained_lineage_digest: Digest::of(b"lineage"),
                    outbox_event_digest: Digest::of(b"event"),
                },
            },
            completed_at_ms: 102,
        };
        let bytes = signer
            .sign_in_transaction(claims.clone(), &request.attempt)
            .unwrap();
        assert_eq!(
            trust.verify_outcome(&bytes, &request.attempt).unwrap(),
            claims
        );
        let mut other = request.attempt.clone();
        other.attempt_id = "other".into();
        assert!(trust.verify_outcome(&bytes, &other).is_err());
        let mut invalid = claims;
        if let RetirementEffect::Applied {
            retired_payload_bytes,
            ..
        } = &mut invalid.outcome.effect
        {
            *retired_payload_bytes = 8;
        }
        assert!(
            signer
                .sign_in_transaction(invalid, &request.attempt)
                .is_err()
        );
    }

    #[test]
    fn malformed_unknown_duplicate_and_oversize_wire_is_rejected() {
        let claims = request();
        let (signer, _, trust) = keys(&claims.host);
        let valid = signer.sign_committed_request(claims, 100).unwrap();
        let mut extra = valid.clone();
        extra.pop();
        extra.extend_from_slice(b",\"extra\":true}");
        let mut duplicate = valid.clone();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"purpose\":\"openpc:store-retirement-request:v1\"}");
        let mut whitespace = valid.clone();
        whitespace.push(b'\n');
        for bytes in [
            vec![],
            vec![b' '; MAX_WIRE_BYTES + 1],
            b"null".to_vec(),
            extra,
            duplicate,
            whitespace,
        ] {
            assert!(trust.verify_request(&bytes, 101).is_err());
        }
        assert!(trust.verify_request(&valid, 101).is_ok());
    }
}
