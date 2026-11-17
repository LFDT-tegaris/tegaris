use std::collections::BTreeMap;

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Digest, RuntimeError, RuntimeResult, canonical_bytes,
    digest::{decode_hex, hex},
};

#[derive(Clone)]
pub struct PurposeSigner {
    purpose: &'static str,
    key: SigningKey,
}

impl PurposeSigner {
    pub fn from_secret_bytes(purpose: &'static str, bytes: [u8; 32]) -> RuntimeResult<Self> {
        let key = SigningKey::from_bytes((&bytes).into())
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        Ok(Self { purpose, key })
    }

    #[must_use]
    pub fn verifier(&self) -> PurposeVerifier {
        PurposeVerifier {
            purpose: self.purpose,
            key: *self.key.verifying_key(),
        }
    }

    pub fn sign<T>(&self, claims: T) -> RuntimeResult<SignedEnvelope<T>>
    where
        T: Serialize,
    {
        let claims_digest = Digest::of(canonical_bytes(&claims)?);
        let preimage = canonical_bytes(&(self.purpose, &claims_digest))?;
        let signature: Signature = self.key.sign(&preimage);
        Ok(SignedEnvelope {
            purpose: self.purpose.to_owned(),
            claims,
            claims_digest,
            signature_p1363_hex: hex(signature.to_bytes().as_slice()),
        })
    }
}

#[derive(Clone)]
pub struct PurposeVerifier {
    purpose: &'static str,
    key: VerifyingKey,
}

impl PurposeVerifier {
    pub fn from_sec1_bytes(purpose: &'static str, bytes: &[u8]) -> RuntimeResult<Self> {
        let key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| RuntimeError::InvalidAuthorization)?;
        Ok(Self { purpose, key })
    }

    #[must_use]
    pub fn sec1_bytes(&self) -> Vec<u8> {
        self.key.to_sec1_point(true).as_bytes().to_vec()
    }

    pub fn verify<T>(&self, envelope: &SignedEnvelope<T>) -> RuntimeResult<()>
    where
        T: Serialize,
    {
        if envelope.purpose != self.purpose {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let digest = Digest::of(canonical_bytes(&envelope.claims)?);
        if digest != envelope.claims_digest {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let signature_bytes = decode_hex(&envelope.signature_p1363_hex)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let preimage = canonical_bytes(&(self.purpose, &digest))?;
        self.key
            .verify(&preimage, &signature)
            .map_err(|_| RuntimeError::InvalidAuthorization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct SignedEnvelope<T> {
    pub purpose: String,
    pub claims: T,
    pub claims_digest: Digest,
    pub signature_p1363_hex: String,
}

#[derive(Debug)]
pub struct ReplayAdmission {
    capacity: usize,
    entries: BTreeMap<String, u64>,
}

impl ReplayAdmission {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
        }
    }

    pub fn admit(&mut self, replay_id: &str, expires_at_ms: u64, now_ms: u64) -> RuntimeResult<()> {
        self.admit_batch(&[(replay_id, expires_at_ms)], now_ms)
    }

    pub fn admit_batch(&mut self, admissions: &[(&str, u64)], now_ms: u64) -> RuntimeResult<()> {
        self.entries.retain(|_, expiry| *expiry > now_ms);
        let mut pending = BTreeMap::new();
        for (replay_id, expires_at_ms) in admissions {
            if self.entries.contains_key(*replay_id)
                || pending
                    .insert((*replay_id).to_owned(), *expires_at_ms)
                    .is_some()
            {
                return Err(RuntimeError::Replay);
            }
        }
        if self.entries.len().saturating_add(pending.len()) > self.capacity {
            return Err(RuntimeError::ReplayCapacity);
        }
        self.entries.extend(pending);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer(purpose: &'static str, byte: u8) -> PurposeSigner {
        PurposeSigner::from_secret_bytes(purpose, [byte; 32]).unwrap()
    }

    #[test]
    fn purpose_tamper_and_wrong_public_key_are_rejected() {
        let signer = make_signer("purpose:a", 1);
        let verifier = signer.verifier();
        let mut envelope = signer.sign(vec!["exact"]).unwrap();
        verifier.verify(&envelope).unwrap();
        envelope.claims.push("altered");
        assert_eq!(
            verifier.verify(&envelope),
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(
            make_signer("purpose:b", 1)
                .verifier()
                .verify(&signer.sign("x").unwrap()),
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(
            make_signer("purpose:a", 2)
                .verifier()
                .verify(&signer.sign("x").unwrap()),
            Err(RuntimeError::InvalidAuthorization)
        );
    }

    #[test]
    fn verifier_round_trips_public_sec1() {
        let signer = make_signer("purpose:a", 3);
        let verifier = signer.verifier();
        let public_only =
            PurposeVerifier::from_sec1_bytes("purpose:a", &verifier.sec1_bytes()).unwrap();
        public_only.verify(&signer.sign("exact").unwrap()).unwrap();
    }

    #[test]
    fn replay_capacity_fails_closed_and_expiry_reclaims() {
        let mut replay = ReplayAdmission::new(1);
        replay.admit("one", 10, 1).unwrap();
        assert_eq!(replay.admit("one", 10, 1), Err(RuntimeError::Replay));
        assert_eq!(
            replay.admit("two", 10, 1),
            Err(RuntimeError::ReplayCapacity)
        );
        replay.admit("two", 20, 10).unwrap();
    }

    #[test]
    fn batch_admission_is_atomic_on_replay_and_capacity_failure() {
        let mut replay = ReplayAdmission::new(2);
        replay.admit("existing", 20, 1).unwrap();
        assert_eq!(
            replay.admit_batch(&[("fresh", 20), ("existing", 20)], 1),
            Err(RuntimeError::Replay)
        );
        replay.admit("fresh", 20, 1).unwrap();

        let mut capacity = ReplayAdmission::new(1);
        assert_eq!(
            capacity.admit_batch(&[("one", 20), ("two", 20)], 1),
            Err(RuntimeError::ReplayCapacity)
        );
        capacity.admit("one", 20, 1).unwrap();
    }
}
