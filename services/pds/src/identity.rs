//! Verification-only adapter for the existing IdentityAuthContextAssertionV2
//! (schema 3002, purpose 13). Signature validity alone never supplies role authority.

use std::io::Cursor;

use ciborium::value::Value;
use pc_policy_core::pc_cbor_1;
use pc_policy_core::runtime_wire::{Profile, Verifier};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Serialize)]
pub struct IdentityAssertionEvidence {
    pub payload_cbor: Vec<u8>,
    pub cose_sign1: Vec<u8>,
}
impl IdentityAssertionEvidence {
    /// Extract attached payload bytes only. This establishes no trust; every
    /// consumer must still use the schema-specific signature verifier.
    pub fn from_cose_sign1(bytes: &[u8]) -> RuntimeResult<Self> {
        let cose = bytes.strip_prefix(&[0xd2]).unwrap_or(bytes);
        let value = decode_bounded(cose, 262_144 + 1024)?;
        let fields = value.as_array().ok_or(RuntimeError::InvalidInput)?;
        let [
            Value::Bytes(_),
            Value::Map(unprotected),
            Value::Bytes(payload),
            Value::Bytes(signature),
        ] = fields.as_slice()
        else {
            return Err(RuntimeError::InvalidInput);
        };
        if !unprotected.is_empty() || signature.len() != 64 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            payload_cbor: {
                let envelope = decode_bounded(payload, 262_144 + 32)?;
                let fields = envelope
                    .as_map()
                    .filter(|m| m.len() == 4)
                    .ok_or(RuntimeError::InvalidInput)?;
                if fields[3].0 != integer(3) {
                    return Err(RuntimeError::InvalidInput);
                }
                pc_cbor_1(&fields[3].1)
            },
            cose_sign1: bytes.to_vec(),
        })
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Produced by createLocalIdentityRuntimeCryptoAdapter and the existing
    // security-kernel v2 encoder. Only public material is retained.
    const PUBLIC_KEY: &str =
        "302a300506032b6570032100c13148d4c21fe4f8acb59e7ffe30feef58cb1d8249148270e66e106a430b87f5";
    const PAYLOAD: &str = "ac00767064732d6964656e746974792d766563746f722d76320158200101010101010101010101010101010101010101010101010101010101010101020103582002020202020202020202020202020202020202020202020202020202020202020458200303030303030303030303030303030303030303030303030303030303030303050206582004040404040404040404040404040404040404040404040404040404040404040758200505050505050505050505050505050505050505050505050505050505050505081a47868c00091b0000000e3fcde4000a582006060606060606060606060606060606060606060606060606060606060606060b58200707070707070707070707070707070707070707070707070707070707070707";
    const COSE: &str = "d2845896a801270284186418651866186703736170706c69636174696f6e2f70632b63626f720458477368613235363a363461633861643835666561383533306430343664383231633262363638393164363737356465336561626335303065343437383563363031313637386365391864190bba1865021866781b70632e636f73652e6964656e746974792d72756e74696d652e7632186702a059012ca4000101190bba020203ac00767064732d6964656e746974792d766563746f722d76320158200101010101010101010101010101010101010101010101010101010101010101020103582002020202020202020202020202020202020202020202020202020202020202020458200303030303030303030303030303030303030303030303030303030303030303050206582004040404040404040404040404040404040404040404040404040404040404040758200505050505050505050505050505050505050505050505050505050505050505081a47868c00091b0000000e3fcde4000a582006060606060606060606060606060606060606060606060606060606060606060b582007070707070707070707070707070707070707070707070707070707070707075840b8539d3a3208ec7d935cb5086704abfbec0174a0e1a5e24e60a95dc452a26b8ee787f331b932b1ec29b2a22717161d135143813bdc58726f663bcf48560ce506";

    fn bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn duplicate_untrusted_cbor_keys_are_rejected_without_panicking() {
        assert!(decode(&[0xa2, 0, 1, 0, 2]).is_err());
        assert!(decode(&[0x81, 0xa2, 0, 1, 0, 2]).is_err());
    }

    #[test]
    fn verifies_typescript_actor_projection_without_confusing_request_authority() {
        let public = bytes(PUBLIC_KEY);
        let mut evidence = IdentityAssertionEvidence {
            payload_cbor: bytes(
                "a6005820010101010101010101010101010101010101010101010101010101010101010101010258200202020202020202020202020202020202020202020202020202020202020202035820030303030303030303030303030303030303030303030303030303030303030304582004040404040404040404040404040404040404040404040404040404040404040558200505050505050505050505050505050505050505050505050505050505050505",
            ),
            cose_sign1: bytes(
                "d2845896a801270284186418651866186703736170706c69636174696f6e2f70632b63626f720458477368613235363a363461633861643835666561383533306430343664383231633262363638393164363737356465336561626335303065343437383563363031313637386365391864190bbb1865021866781b70632e636f73652e6964656e746974792d72756e74696d652e7632186702a058bca4000101190bbb020203a60058200101010101010101010101010101010101010101010101010101010101010101010102582002020202020202020202020202020202020202020202020202020202020202020358200303030303030303030303030303030303030303030303030303030303030303045820040404040404040404040404040404040404040404040404040404040404040405582005050505050505050505050505050505050505050505050505050505050505055840112a725cd61a9ca4c3523315dc9f8aabf017893c6820ec5c2ffe17fc1e7c0d205115355a5cf0a9f69351396a996b33ba2a0f5290c6b9688aef418e0b562d6501",
            ),
        };
        let verifier = IdentityAssertionVerifier::new(&[public], 60_000).unwrap();
        let projection = verifier.verify_actor_projection(&evidence).unwrap();
        assert_eq!(projection.actor_kind(), 1);
        assert_eq!(projection.actor_key_digest(), &[1; 32]);
        assert_eq!(projection.participant_context_digest(), &[2; 32]);
        assert_eq!(projection.role_assignment_set_digest(), &[3; 32]);
        assert_eq!(projection.participant_envelope_digest(), &[4; 32]);
        assert_eq!(projection.authority_vector_digest(), &[5; 32]);
        let (_, assertion, expected) = fixture();
        assert!(verifier.verify(&evidence, &expected, 1_234).is_err());
        assert!(verifier.verify_actor_projection(&assertion).is_err());
        *evidence.payload_cbor.last_mut().unwrap() ^= 1;
        assert!(verifier.verify_actor_projection(&evidence).is_err());
    }

    pub(crate) fn fixture() -> (
        IdentityAssertionVerifier,
        IdentityAssertionEvidence,
        IdentityAssertionBindings,
    ) {
        (
            IdentityAssertionVerifier::new(&[bytes(PUBLIC_KEY)], 60_000).unwrap(),
            IdentityAssertionEvidence {
                payload_cbor: bytes(PAYLOAD),
                cose_sign1: bytes(COSE),
            },
            IdentityAssertionBindings {
                actor_kind: 1,
                sender_binding_kind: 2,
                actor_key_digest: [1; 32],
                participant_context_digest: [2; 32],
                audience_digest: [3; 32],
                assurance_profile_digest: [4; 32],
                authority_vector_digest: [5; 32],
                authentication_evidence_digest: [6; 32],
                sender_credential_binding_digest: [7; 32],
            },
        )
    }

    #[test]
    fn verifies_existing_typescript_issuer_and_exact_validity_bounds() {
        let (verifier, mut evidence, expected) = fixture();
        let verified = verifier.verify(&evidence, &expected, 1_234).unwrap();
        assert_eq!(verified.assertion_id(), "pds-identity-vector-v2");
        assert_eq!(verified.expires_at_ms(), 61_200);
        evidence.cose_sign1.remove(0);
        assert!(verifier.verify(&evidence, &expected, 1_234).is_ok());
        assert!(verifier.verify(&evidence, &expected, 1_199).is_err());
        assert!(verifier.verify(&evidence, &expected, 61_200).is_err());
        let short = IdentityAssertionVerifier::new(&[bytes(PUBLIC_KEY)], 59_999).unwrap();
        assert!(short.verify(&evidence, &expected, 1_234).is_err());
    }

    #[test]
    fn rejects_substitution_of_every_authority_and_request_binding() {
        let (verifier, evidence, baseline) = fixture();
        for field in 0..9 {
            let mut expected = baseline.clone();
            match field {
                0 => expected.actor_kind = 0,
                1 => expected.sender_binding_kind = 1,
                2 => expected.actor_key_digest[0] ^= 1,
                3 => expected.participant_context_digest[0] ^= 1,
                4 => expected.audience_digest[0] ^= 1,
                5 => expected.assurance_profile_digest[0] ^= 1,
                6 => expected.authority_vector_digest[0] ^= 1,
                7 => expected.authentication_evidence_digest[0] ^= 1,
                8 => expected.sender_credential_binding_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                verifier.verify(&evidence, &expected, 1_234).is_err(),
                "binding {field}"
            );
        }
    }

    #[test]
    fn rejects_tampering_unknown_trust_and_noncanonical_or_unsupported_cbor() {
        let (verifier, original, expected) = fixture();
        let mut evidence = original.clone();
        *evidence.cose_sign1.last_mut().unwrap() ^= 1;
        assert!(verifier.verify(&evidence, &expected, 1_234).is_err());
        let mut evidence = original.clone();
        evidence.payload_cbor.push(0);
        assert!(verifier.verify(&evidence, &expected, 1_234).is_err());
        let mut evidence = original.clone();
        evidence.cose_sign1.push(0);
        assert!(verifier.verify(&evidence, &expected, 1_234).is_err());
        let unrelated_public = bytes(
            "302a300506032b6570032100b20923e5c28276b12453ce7fb5d2aba6f03925b7fdc4cdf8b76aec57038feb61",
        );
        let unrelated = IdentityAssertionVerifier::new(&[unrelated_public], 60_000).unwrap();
        assert!(unrelated.verify(&original, &expected, 1_234).is_err());
        assert!(IdentityAssertionVerifier::new(&[], 60_000).is_err());
        assert!(
            IdentityAssertionVerifier::new(&[bytes(PUBLIC_KEY), bytes(PUBLIC_KEY)], 60_000)
                .is_err()
        );
        for malformed in [
            vec![0xfa, 0x3f, 0x80, 0, 0],
            vec![0xc0, 0x00],
            vec![0x98, 0x00],
            vec![0x40; 8_193],
            [vec![0x81; 32], vec![0x00]].concat(),
        ] {
            let evidence = IdentityAssertionEvidence {
                payload_cbor: original.payload_cbor.clone(),
                cose_sign1: malformed,
            };
            assert!(verifier.verify(&evidence, &expected, 1_234).is_err());
        }
    }
}

/// Expected bindings come from the local authority owner and authenticated
/// request boundary, never from claims selected by the request itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IdentityAssertionBindings {
    pub actor_kind: u64,
    pub sender_binding_kind: u64,
    pub actor_key_digest: [u8; 32],
    pub participant_context_digest: [u8; 32],
    pub audience_digest: [u8; 32],
    pub assurance_profile_digest: [u8; 32],
    pub authority_vector_digest: [u8; 32],
    pub authentication_evidence_digest: [u8; 32],
    pub sender_credential_binding_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedActorProjection {
    actor_key_digest: [u8; 32],
    actor_kind: u64,
    participant_context_digest: [u8; 32],
    role_assignment_set_digest: [u8; 32],
    participant_envelope_digest: [u8; 32],
    authority_vector_digest: [u8; 32],
}

impl VerifiedActorProjection {
    pub fn actor_key_digest(&self) -> &[u8; 32] {
        &self.actor_key_digest
    }
    pub fn actor_kind(&self) -> u64 {
        self.actor_kind
    }
    pub fn participant_context_digest(&self) -> &[u8; 32] {
        &self.participant_context_digest
    }
    pub fn role_assignment_set_digest(&self) -> &[u8; 32] {
        &self.role_assignment_set_digest
    }
    pub fn participant_envelope_digest(&self) -> &[u8; 32] {
        &self.participant_envelope_digest
    }
    pub fn authority_vector_digest(&self) -> &[u8; 32] {
        &self.authority_vector_digest
    }
}

pub struct VerifiedIdentityAssertion {
    assertion_id: String,
    expires_at_ms: u64,
}

impl VerifiedIdentityAssertion {
    pub fn assertion_id(&self) -> &str {
        &self.assertion_id
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

pub struct IdentityAssertionVerifier {
    keys: Vec<Verifier>,
    maximum_lifetime_ns: u64,
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

#[cfg(test)]
fn decode(bytes: &[u8]) -> RuntimeResult<Value> {
    decode_bounded(bytes, 8_192)
}
pub(crate) fn decode_bounded(bytes: &[u8], maximum: usize) -> RuntimeResult<Value> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuntimeError::InvalidInput);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| RuntimeError::InvalidInput)?;
    if cursor.position() != bytes.len() as u64
        || !plain_value(&value, 8, &mut 8192)
        || pc_cbor_1(&value) != bytes
    {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn plain_value(value: &Value, depth: usize, remaining: &mut usize) -> bool {
    if depth == 0 {
        return false;
    }
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) => true,
        Value::Array(values) => {
            if values.len() > *remaining {
                return false;
            }
            *remaining -= values.len();
            values
                .iter()
                .all(|value| plain_value(value, depth - 1, remaining))
        }
        Value::Map(values) => {
            if values.len() > *remaining {
                return false;
            }
            *remaining -= values.len();
            if !values.iter().all(|(key, value)| {
                plain_value(key, depth - 1, remaining) && plain_value(value, depth - 1, remaining)
            }) {
                return false;
            }
            let keys: std::collections::BTreeSet<_> =
                values.iter().map(|(key, _)| pc_cbor_1(key)).collect();
            keys.len() == values.len()
        }
        _ => false,
    }
}

impl IdentityAssertionVerifier {
    pub fn new(public_keys_spki_der: &[Vec<u8>], maximum_lifetime_ms: u64) -> RuntimeResult<Self> {
        if public_keys_spki_der.is_empty() || public_keys_spki_der.len() > 16 {
            return Err(RuntimeError::InvalidInput);
        }
        let maximum_lifetime_ns = maximum_lifetime_ms
            .checked_mul(1_000_000)
            .filter(|value| *value > 0)
            .ok_or(RuntimeError::InvalidInput)?;
        let mut keys = Vec::new();
        for der in public_keys_spki_der {
            let key = Verifier::from_spki_der(der)?;
            if keys
                .iter()
                .any(|prior: &Verifier| prior.public_key_bytes() == key.public_key_bytes())
            {
                return Err(RuntimeError::InvalidInput);
            }
            keys.push(key);
        }
        Ok(Self {
            keys,
            maximum_lifetime_ns,
        })
    }

    pub(crate) fn verify_cose(
        &self,
        evidence: &IdentityAssertionEvidence,
        schema_id: u64,
    ) -> RuntimeResult<Value> {
        let maximum = match schema_id {
            3002 | 3003 => 8_192,
            3004 | 3010 => 262_144,
            _ => return Err(RuntimeError::InvalidInput),
        };
        let profile = match schema_id {
            3002 => Profile::IdentityAssertion,
            3003 => Profile::IdentityActorProjection,
            3004 => Profile::IdentitySnapshot,
            3010 => Profile::IdentityProfile,
            _ => return Err(RuntimeError::InvalidInput),
        };
        let payload = self
            .keys
            .iter()
            .find_map(|key| key.verify(profile, &evidence.cose_sign1, maximum).ok())
            .ok_or(RuntimeError::Denied)?;
        if payload != evidence.payload_cbor {
            return Err(RuntimeError::Denied);
        }

        decode_bounded(&payload, maximum)
    }

    /// A signed actor projection binds role/envelope digests. It must be admitted
    /// inside the active identity snapshot; it never replaces request authentication.
    pub fn verify_actor_projection(
        &self,
        evidence: &IdentityAssertionEvidence,
    ) -> RuntimeResult<VerifiedActorProjection> {
        Self::projection_from_value(self.verify_cose(evidence, 3003)?)
    }

    pub(crate) fn projection_from_value(value: Value) -> RuntimeResult<VerifiedActorProjection> {
        let Value::Map(fields) = value else {
            return Err(RuntimeError::InvalidInput);
        };
        if fields.len() != 6
            || fields
                .iter()
                .enumerate()
                .any(|(index, (key, _))| key != &integer(index as u64))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let digest = |index: usize| -> RuntimeResult<[u8; 32]> {
            fields[index]
                .1
                .as_bytes()
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .ok_or(RuntimeError::InvalidInput)
        };
        let actor_kind = fields[1]
            .1
            .as_integer()
            .and_then(|value| u64::try_from(value).ok())
            .filter(|kind| *kind <= 1)
            .ok_or(RuntimeError::InvalidInput)?;
        Ok(VerifiedActorProjection {
            actor_key_digest: digest(0)?,
            actor_kind,
            participant_context_digest: digest(2)?,
            role_assignment_set_digest: digest(3)?,
            participant_envelope_digest: digest(4)?,
            authority_vector_digest: digest(5)?,
        })
    }

    pub fn verify(
        &self,
        evidence: &IdentityAssertionEvidence,
        expected: &IdentityAssertionBindings,
        now_ms: u64,
    ) -> RuntimeResult<VerifiedIdentityAssertion> {
        let Value::Map(claims) = self.verify_cose(evidence, 3002)? else {
            return Err(RuntimeError::InvalidInput);
        };
        // This consumer requires sender binding. The profile's optional key 11
        // cannot be omitted for a request that may mint a broker capability.
        if claims.len() != 12
            || claims
                .iter()
                .enumerate()
                .any(|(index, (key, _))| key != &integer(index as u64))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let unsigned = |index: usize| -> RuntimeResult<u64> {
            let Value::Integer(value) = claims[index].1 else {
                return Err(RuntimeError::InvalidInput);
            };
            value.try_into().map_err(|_| RuntimeError::InvalidInput)
        };
        let Value::Text(assertion_id) = &claims[0].1 else {
            return Err(RuntimeError::InvalidInput);
        };
        if assertion_id.is_empty()
            || assertion_id.len() > 160
            || !assertion_id.nfc().eq(assertion_id.chars())
            || expected.actor_kind > 1
            || expected.sender_binding_kind > 4
            || unsigned(2)? != expected.actor_kind
            || unsigned(5)? != expected.sender_binding_kind
        {
            return Err(RuntimeError::Denied);
        }
        for (index, digest) in [
            (1, &expected.actor_key_digest),
            (3, &expected.participant_context_digest),
            (4, &expected.audience_digest),
            (6, &expected.assurance_profile_digest),
            (7, &expected.authority_vector_digest),
            (10, &expected.authentication_evidence_digest),
            (11, &expected.sender_credential_binding_digest),
        ] {
            if claims[index].1 != Value::Bytes(digest.to_vec()) {
                return Err(RuntimeError::Denied);
            }
        }
        let issued = unsigned(8)?;
        let expires = unsigned(9)?;
        let now = now_ms
            .checked_mul(1_000_000)
            .ok_or(RuntimeError::InvalidInput)?;
        if issued >= expires
            || issued > now
            || expires <= now
            || expires - issued > self.maximum_lifetime_ns
        {
            return Err(RuntimeError::Denied);
        }
        Ok(VerifiedIdentityAssertion {
            assertion_id: assertion_id.clone(),
            expires_at_ms: expires / 1_000_000,
        })
    }
}
