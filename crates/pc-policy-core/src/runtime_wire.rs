//! Closed Ed25519 COSE_Sign1 contexts for the accepted primary runtime schemas.
#[path = "runtime_wire_fields.rs"]
pub mod fields;
use crate::pc_cbor_1;
use ciborium::value::Value;
use fields::{map, uint};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest as _, Sha256};
use std::{io::Cursor, sync::Arc};

#[derive(Clone, Copy)]
pub enum Profile {
    Capsule,
    ActivationToken,
    Receipt,
    Ack,
    FreshnessLease,
    EmergencyOverlay,
    AuthorityArtifact,
    DecisionInput,
    DecisionMaterial,
    IdentityAssertion,
    IdentityActorProjection,
    IdentitySnapshot,
    IdentityProfile,
    ChainAnchor,
    RouteWitness,
    RouteWitnessSet,
    MrpcProfile,
    InvocationProfile,
}
impl Profile {
    fn schema(self) -> u64 {
        match self {
            Self::Capsule => 2001,
            Self::ActivationToken => 21703,
            Self::Receipt => 2004,
            Self::Ack => 2005,
            Self::FreshnessLease => 2002,
            Self::EmergencyOverlay => 2003,
            Self::AuthorityArtifact => 1010,
            Self::DecisionInput => 1001,
            Self::DecisionMaterial => 1002,
            Self::IdentityAssertion => 3002,
            Self::IdentityActorProjection => 3003,
            Self::IdentitySnapshot => 3004,
            Self::IdentityProfile => 3010,
            Self::ChainAnchor => 2012,
            Self::RouteWitness => 2013,
            Self::RouteWitnessSet => 2021,
            Self::MrpcProfile => 2014,
            Self::InvocationProfile => 3121,
        }
    }
    fn version(self) -> u64 {
        match self {
            Self::FreshnessLease
            | Self::EmergencyOverlay
            | Self::IdentityAssertion
            | Self::IdentityActorProjection
            | Self::IdentitySnapshot
            | Self::IdentityProfile
            | Self::InvocationProfile
            | Self::ChainAnchor => 2,
            Self::AuthorityArtifact
            | Self::ActivationToken
            | Self::DecisionInput
            | Self::DecisionMaterial
            | Self::RouteWitnessSet => 1,
            _ => 3,
        }
    }
    fn purpose(self) -> &'static str {
        match self {
            Self::Capsule => "pc.cose.runtime-activation-capsule.v3",
            Self::ActivationToken => "openpc:activation-token:v1",
            Self::Receipt | Self::Ack => "pc.cose.target-activation-receipt.v3",
            Self::FreshnessLease => "pc.cose.revocation-freshness-lease.v2",
            Self::EmergencyOverlay => "pc.cose.emergency-deny-overlay.v2",
            Self::AuthorityArtifact => "pc.cose.canonical-authority.v1",
            Self::ChainAnchor | Self::RouteWitness | Self::RouteWitnessSet => {
                "pc.cose.request-route-witness.v3"
            }
            Self::MrpcProfile => "pc.cose.mrpc-runtime-profile.v3",
            Self::InvocationProfile => "pc.cose.rpc-invocation.v2",
            Self::DecisionInput | Self::DecisionMaterial => "pc.cose.runtime-decision.v1",
            Self::IdentityAssertion
            | Self::IdentityActorProjection
            | Self::IdentitySnapshot
            | Self::IdentityProfile => "pc.cose.identity-runtime.v2",
        }
    }
}
/// CANON-CONTRACT-001 revision 4: semantic identity includes the schema-bound
/// envelope and domain separator. Raw content hashes and COSE byte hashes are
/// different identities and must never be used for capsule lineage.
pub fn semantic_digest(
    profile: Profile,
    payload: &[u8],
) -> RuntimeResult<pc_runtime_types::Digest> {
    let payload = decode(payload, 1024 * 1024)?;
    let digest = crate::pc_cbor_1_semantic_digest(profile.schema(), profile.version(), &payload);
    pc_runtime_types::Digest::parse(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}
pub fn decode(bytes: &[u8], maximum: usize) -> RuntimeResult<Value> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuntimeError::InvalidInput);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| RuntimeError::InvalidInput)?;
    if cursor.position() != bytes.len() as u64
        || !bounded(&value, 8, &mut 8192)
        || pc_cbor_1(&value) != bytes
    {
        return Err(RuntimeError::CanonicalEncoding);
    }
    Ok(value)
}
fn bounded(value: &Value, depth: usize, remaining: &mut usize) -> bool {
    if depth == 0 {
        return false;
    }
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) => true,
        Value::Array(v) => {
            if v.len() > 4096 || v.len() > *remaining {
                return false;
            }
            *remaining -= v.len();
            v.iter().all(|x| bounded(x, depth - 1, remaining))
        }
        Value::Map(v) => {
            if v.len() > 64 || v.len() > *remaining {
                return false;
            }
            *remaining -= v.len();
            if !v
                .iter()
                .all(|(k, x)| bounded(k, depth - 1, remaining) && bounded(x, depth - 1, remaining))
            {
                return false;
            }
            let keys: std::collections::BTreeSet<_> = v.iter().map(|(k, _)| pc_cbor_1(k)).collect();
            keys.len() == v.len()
        }
        _ => false,
    }
}
fn header(profile: Profile, key: &[u8; 32]) -> RuntimeResult<Vec<u8>> {
    // RFC 8410 SPKI for Ed25519. The registered kid is UTF-8 encoded as a
    // byte string, not the binary SHA-256 value used by compatibility codecs.
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend(key);
    let kid = format!(
        "sha256:{}",
        Sha256::digest(&spki)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(pc_cbor_1(&map(vec![
        (1, Value::Integer((-8).into())),
        (2, Value::Array([100, 101, 102, 103].map(uint).to_vec())),
        (3, Value::Text("application/pc+cbor".into())),
        (4, Value::Bytes(kid.into_bytes())),
        (100, uint(profile.schema())),
        (101, uint(profile.version())),
        (102, Value::Text(profile.purpose().into())),
        (103, uint(2)),
    ])))
}
fn structure(profile: Profile, header: &[u8], payload: &[u8]) -> Vec<u8> {
    pc_cbor_1(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(header.to_vec()),
        Value::Bytes(
            [
                b"pcplane:cose-sign1:v2\0".as_slice(),
                profile.purpose().as_bytes(),
            ]
            .concat(),
        ),
        Value::Bytes(payload.to_vec()),
    ]))
}
#[derive(Clone)]
pub struct Signer {
    key: Arc<Ed25519KeyPair>,
}
impl Signer {
    pub fn from_secret_bytes(bytes: [u8; 32]) -> RuntimeResult<Self> {
        Ok(Self {
            key: Arc::new(
                Ed25519KeyPair::from_seed_unchecked(&bytes)
                    .map_err(|_| RuntimeError::InvalidAuthorization)?,
            ),
        })
    }
    pub fn verifier(&self) -> Verifier {
        Verifier {
            key: self
                .key
                .public_key()
                .as_ref()
                .try_into()
                .expect("Ed25519 public key is 32 bytes"),
        }
    }
    pub fn sign(&self, profile: Profile, payload: &[u8]) -> RuntimeResult<Vec<u8>> {
        let protected = header(profile, &self.verifier().key)?;
        let payload = pc_cbor_1(&map(vec![
            (0, uint(1)),
            (1, uint(profile.schema())),
            (2, uint(profile.version())),
            (3, decode(payload, 1024 * 1024)?),
        ]));
        let signature = self.key.sign(&structure(profile, &protected, &payload));
        let mut bytes = vec![0xd2];
        bytes.extend(pc_cbor_1(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(signature.as_ref().to_vec()),
        ])));
        Ok(bytes)
    }
}
#[derive(Clone)]
pub struct Verifier {
    key: [u8; 32],
}
impl Verifier {
    pub fn from_public_key_bytes(bytes: &[u8]) -> RuntimeResult<Self> {
        Ok(Self {
            key: bytes
                .try_into()
                .map_err(|_| RuntimeError::InvalidAuthorization)?,
        })
    }
    pub fn from_spki_der(bytes: &[u8]) -> RuntimeResult<Self> {
        let raw = bytes
            .strip_prefix(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ])
            .ok_or(RuntimeError::InvalidAuthorization)?;
        Self::from_public_key_bytes(raw)
    }
    pub fn spki_der(&self) -> Vec<u8> {
        [
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ],
            self.key.as_slice(),
        ]
        .concat()
    }
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }
    pub fn verify(&self, profile: Profile, cose: &[u8], maximum: usize) -> RuntimeResult<Vec<u8>> {
        let bytes = cose.strip_prefix(&[0xd2]).unwrap_or(cose);
        let v = decode(bytes, maximum + 1024)?;
        let a = v
            .as_array()
            .filter(|a| a.len() == 4)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let h = a[0].as_bytes().ok_or(RuntimeError::InvalidAuthorization)?;
        if *h != header(profile, &self.key)? || a[1] != Value::Map(vec![]) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let payload = a[2]
            .as_bytes()
            .filter(|b| b.len() <= maximum + 32)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let signature = a[3]
            .as_bytes()
            .filter(|bytes| bytes.len() == 64)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        UnparsedPublicKey::new(&ED25519, self.key)
            .verify(&structure(profile, h, payload), signature)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let envelope = decode(payload, maximum + 32)?;
        let fields = envelope
            .as_map()
            .filter(|m| m.len() == 4)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if fields[0] != (uint(0), uint(1))
            || fields[1] != (uint(1), uint(profile.schema()))
            || fields[2] != (uint(2), uint(profile.version()))
            || fields[3].0 != uint(3)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let payload = pc_cbor_1(&fields[3].1);
        if payload.len() > maximum {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_ed25519_semantic_envelope_vector() {
        // R1-COSE-AUTHORITY-004 and CANON-CONTRACT-001. Constructed independently
        // with RFC 8949 CBOR and Node/OpenSSL; only public wire bytes are retained.
        // This exercises the crypto envelope, not authority-artifact schema acceptance.
        let expected = bytes(
            "d2845899a801270284186418651866186703736170706c69636174696f6e2f70632b63626f720458477368613235363a3539646163306434633734326239373266633332313464313862303135303534373366303736313066363832323461363632343962333862393635653662636218641903f21865011866781e70632e636f73652e63616e6f6e6963616c2d617574686f726974792e7631186702a04ba40001011903f2020103a0584080faf6bfe1ab646efa4a367f1373aca4a1e55dbcfd2cfd1df44b3717f9707cbb2581e954c3c98c93569b9dd72eab0d16a9437664b428ef58b9ed78e50b556109",
        );
        let signer = Signer::from_secret_bytes([21; 32]).unwrap();
        assert_eq!(
            signer.sign(Profile::AuthorityArtifact, &[0xa0]).unwrap(),
            expected
        );
        assert_eq!(
            signer
                .verifier()
                .verify(Profile::AuthorityArtifact, &expected, 1)
                .unwrap(),
            [0xa0]
        );
        assert!(
            signer
                .verifier()
                .verify(Profile::DecisionInput, &expected, 1)
                .is_err()
        );
        assert!(Verifier::from_spki_der(&[0; 44]).is_err());
    }
    #[test]
    fn authentic_signature_cannot_weaken_the_registered_preimage() {
        let profile = Profile::AuthorityArtifact;
        let signer = Signer::from_secret_bytes([21; 32]).unwrap();
        let valid = signer.sign(profile, &[0xa0]).unwrap();
        let fields = decode(&valid[1..], 4096)
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        for mutation in 0..6 {
            let mut fields = fields.clone();
            let mut h = decode(fields[0].as_bytes().unwrap(), 1024).unwrap();
            let mut aad = [
                b"pcplane:cose-sign1:v2\0".as_slice(),
                profile.purpose().as_bytes(),
            ]
            .concat();
            match mutation {
                0 => h.as_map_mut().unwrap()[0].1 = Value::Integer((-7).into()),
                1 => h.as_map_mut().unwrap()[6].1 = uint(17),
                2 => h.as_map_mut().unwrap()[3].1 = Value::Bytes(vec![0; 32]),
                3 => aad = b"pcplane:cose-sign1:v2\0".to_vec(),
                4 => fields[2] = Value::Bytes(vec![0xa0]),
                5 => aad = b"pcplane:cose-sign1:v2\0pc.cose.runtime-decision.v1".to_vec(),
                _ => unreachable!(),
            }
            fields[0] = Value::Bytes(pc_cbor_1(&h));
            let preimage = pc_cbor_1(&Value::Array(vec![
                Value::Text("Signature1".into()),
                fields[0].clone(),
                Value::Bytes(aad),
                fields[2].clone(),
            ]));
            fields[3] = Value::Bytes(signer.key.sign(&preimage).as_ref().to_vec());
            assert!(
                signer
                    .verifier()
                    .verify(profile, &pc_cbor_1(&Value::Array(fields)), 1024)
                    .is_err(),
                "mutation {mutation}"
            );
        }
    }
}
