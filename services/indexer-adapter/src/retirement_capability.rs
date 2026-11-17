//! Candidate-index-only SQL capability seam for the governed retirement owner.
//! Host-installed secrets are not request inputs. Issuance authenticates both
//! Control authority and the target's exact signed outcome. The SQL owner must
//! separately fence/recheck source state and consume the nonce in its effect TX.
//! Neither this module nor a successful MAC comparison performs a physical effect.

use hmac::{Hmac, KeyInit, Mac};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use pc_runtime_types::store_retirement::{RetirementEffect, RetirementStore};
use pc_runtime_types::store_retirement_authority::RetirementAuthorityTrust;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

pub const EXECUTION_DOMAIN: &str = "OPENPC_CANDIDATE_INDEX_RETIREMENT_EXECUTION_V1";
pub const CANCELLATION_DOMAIN: &str = "OPENPC_CANDIDATE_INDEX_RETIREMENT_CANCELLATION_V1";
pub const BINDING_DOMAIN: &str = "OPENPC_CANDIDATE_INDEX_RETIREMENT_BINDING_V1";

/// SQL verifies HMAC-SHA256(domain || binding || nonce), where binding is
/// SHA256(BINDING_DOMAIN || exact_attempt_digest || SHA256(authority_bytes) ||
/// SHA256(outcome_bytes)). All digests/nonces/MACs are exactly 32 raw bytes.
/// Execution and cancellation need separate SECURITY DEFINER entrypoints;
/// runtime roles must never call a generic domain-selecting SQL verifier.
#[derive(Debug, Eq, PartialEq)]
pub struct CandidateRetirementCapability {
    pub nonce: [u8; 32],
    pub mac: [u8; 32],
}

pub struct CandidateRetirementCapabilityIssuer {
    secret: [u8; 32],
}

impl Drop for CandidateRetirementCapabilityIssuer {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl CandidateRetirementCapabilityIssuer {
    #[must_use]
    pub fn from_host_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn execution(
        &self,
        signed_request: &[u8],
        signed_outcome: &[u8],
        trust: &RetirementAuthorityTrust,
        now_ms: u64,
    ) -> RuntimeResult<CandidateRetirementCapability> {
        let request = trust.verify_request(signed_request, now_ms)?;
        let attempt = &request.claims().attempt;
        let outcome = trust.verify_outcome(signed_outcome, attempt)?;
        if attempt.store != RetirementStore::CandidateIndex
            || matches!(
                outcome.outcome.effect,
                RetirementEffect::CancelledNoEffect {}
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        self.issue(
            EXECUTION_DOMAIN,
            &attempt.digest().map_err(invalid)?,
            signed_request,
            signed_outcome,
        )
    }

    pub fn cancellation(
        &self,
        signed_cancellation: &[u8],
        signed_outcome: &[u8],
        trust: &RetirementAuthorityTrust,
        now_ms: u64,
    ) -> RuntimeResult<CandidateRetirementCapability> {
        let request = trust.verify_cancel(signed_cancellation, now_ms)?;
        let attempt = &request.claims().attempt;
        let outcome = trust.verify_outcome(signed_outcome, attempt)?;
        if attempt.store != RetirementStore::CandidateIndex
            || !matches!(
                outcome.outcome.effect,
                RetirementEffect::CancelledNoEffect {}
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        self.issue(
            CANCELLATION_DOMAIN,
            &attempt.digest().map_err(invalid)?,
            signed_cancellation,
            signed_outcome,
        )
    }

    fn issue(
        &self,
        domain: &str,
        attempt: &Digest,
        authority: &[u8],
        outcome: &[u8],
    ) -> RuntimeResult<CandidateRetirementCapability> {
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&attempt.as_str()[index * 2..index * 2 + 2], 16)
                .map_err(invalid)?;
        }
        let mut binding = Sha256::new();
        binding.update(BINDING_DOMAIN.as_bytes());
        binding.update(digest);
        binding.update(Sha256::digest(authority));
        binding.update(Sha256::digest(outcome));
        let nonce: [u8; 32] = SigningKey::generate().to_bytes().into();
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).map_err(invalid)?;
        mac.update(domain.as_bytes());
        mac.update(&binding.finalize());
        mac.update(&nonce);
        Ok(CandidateRetirementCapability {
            nonce,
            mac: mac.finalize().into_bytes().into(),
        })
    }
}

fn invalid<T>(_: T) -> RuntimeError {
    RuntimeError::InvalidAuthorization
}

#[cfg(test)]
mod tests;
