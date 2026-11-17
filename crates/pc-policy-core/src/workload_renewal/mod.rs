//! Exact renewal wire and cryptographic proof. Present policy, attestation and
//! signing admission are separate durable owners; these values grant nothing.
use crate::{
    identity_envelope::{DomainUuid, Hash32, Identifier, Nanos, Positive, Unsigned, Wire, digest},
    pc_cbor_1,
    runtime_wire::{
        self,
        fields::{field, fields, map, number, uint},
    },
};
use ciborium::value::Value;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

fn invalid<T>() -> RuntimeResult<T> {
    Err(RuntimeError::InvalidInput)
}
macro_rules! fixed_enum {
    ($name:ident, $value:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename=$value)]
            V1,
        }
        impl Wire for $name {
            fn encode_value(&self) -> RuntimeResult<Value> {
                Ok(uint(1))
            }
            fn decode_value(value: &Value) -> RuntimeResult<Self> {
                if number(value)? != 1 {
                    return invalid();
                }
                Ok(Self::V1)
            }
        }
    };
}
fixed_enum!(RequestProfile, "pc.identity.workload-renewal.request.v1");
fixed_enum!(
    AuthorizationProfile,
    "pc.identity.workload-renewal.policy-authorization.v1"
);
fixed_enum!(PolicyAuthorized, "POLICY_AUTHORIZED");
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionOne(pub String);
impl Wire for VersionOne {
    fn encode_value(&self) -> RuntimeResult<Value> {
        if self.0 != "1" {
            return invalid();
        }
        Ok(uint(1))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        if number(value)? != 1 {
            return invalid();
        }
        Ok(Self("1".to_owned()))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Workload(pub String);
impl Wire for Workload {
    fn encode_value(&self) -> RuntimeResult<Value> {
        let uuid = self
            .0
            .strip_prefix("urn:openpc:workload:")
            .ok_or(RuntimeError::InvalidInput)?;
        DomainUuid(uuid.to_owned()).encode_value()?;
        Ok(Value::Text(self.0.clone()))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let out = Self(
            value
                .as_text()
                .ok_or(RuntimeError::InvalidInput)?
                .to_owned(),
        );
        out.encode_value()?;
        Ok(out)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestBytes(pub Vec<u8>);
impl Wire for RequestBytes {
    fn encode_value(&self) -> RuntimeResult<Value> {
        Request::decode(&self.0)?;
        Ok(Value::Bytes(self.0.clone()))
    }
    fn decode_value(value: &Value) -> RuntimeResult<Self> {
        let out = Self(value.as_bytes().ok_or(RuntimeError::InvalidInput)?.clone());
        out.encode_value()?;
        Ok(out)
    }
}
macro_rules! renewal_record {
    ($name:ident, $digest:expr, $($field:ident : $ty:ty => $key:literal),+ $(,)?) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all="camelCase", deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),+ }
        impl Wire for $name {
            fn encode_value(&self) -> RuntimeResult<Value> {
                self.validate()?;
                let mut values = Vec::new();
                if let Some(digest) = $digest { values.push((0, Hash32(digest.to_owned()).encode_value()?)); }
                $(values.push(($key, self.$field.encode_value()?));)+
                Ok(map(values))
            }
            fn decode_value(value: &Value) -> RuntimeResult<Self> {
                let mut allowed = vec![$($key),+];
                if ($digest).is_some() { allowed.insert(0, 0); }
                let f = fields(value, &allowed)?;
                if f.len() != allowed.len() { return invalid(); }
                if let Some(digest) = $digest {
                    if Hash32::decode_value(field(&f, 0)?)?.0 != digest { return invalid(); }
                }
                let out = Self { $($field: <$ty>::decode_value(field(&f,$key)?)?),+ };
                out.validate()?; Ok(out)
            }
        }
    };
}
mod generated;
mod generated_signing;
mod signing_trust;
pub use generated::{Authorization, Request, Signer};
pub use generated_signing::SIGNING_PROFILE_DIGEST;
pub use signing_trust::SigningTrust;

impl Signer {
    fn validate(&self) -> RuntimeResult<()> {
        Ok(())
    }
}
impl Request {
    fn validate(&self) -> RuntimeResult<()> {
        let (start, end) = (
            self.request_valid_from_ns.value()?,
            self.request_valid_until_ns.value()?,
        );
        let (from, until) = (
            self.requested_certificate_not_before_ns.value()?,
            self.requested_certificate_not_after_ns.value()?,
        );
        if end <= start
            || end - start > 120_000_000_000
            || until <= from
            || until - from > 86_400_000_000_000
            || !from.is_multiple_of(1_000_000_000)
            || !until.is_multiple_of(1_000_000_000)
            || self.renewal_id == self.predecessor_credential_id
        {
            return invalid();
        }
        Ok(())
    }
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        decode(bytes)
    }
    pub fn verify_cose(payload: &[u8], spki: &[u8], cose: &[u8]) -> RuntimeResult<Self> {
        let value = Self::decode(payload)?;
        verify_cose(
            payload,
            spki,
            cose,
            generated::REQUEST_SCHEMA_ID,
            generated::REQUEST_PURPOSE_CODE,
            &value.new_key_digest,
        )?;
        Ok(value)
    }
}
impl Authorization {
    fn validate(&self) -> RuntimeResult<()> {
        let request = Request::decode(&self.request_bytes.0)?;
        let (issued, until) = (self.issued_at_ns.value()?, self.valid_until_ns.value()?);
        let ids = [
            &request.renewal_id,
            &request.predecessor_credential_id,
            &self.operation_id,
            &self.credential_id,
        ];
        if self.request_digest != digest(&self.request_bytes.0)
            || self.signer.participant_id != request.participant_id
            || self.signer.privacy_domain_id != request.privacy_domain_id
            || self.signer.key_id == request.new_key_digest
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != 4
            || issued < request.request_valid_from_ns.value()?
            || until <= issued
            || until - issued > 30_000_000_000
            || until > request.request_valid_until_ns.value()?
            || until > self.attestation_valid_until_ns.value()?
        {
            return invalid();
        }
        Ok(())
    }
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        decode(bytes)
    }
    pub fn verify_cose(payload: &[u8], spki: &[u8], cose: &[u8]) -> RuntimeResult<Self> {
        let value = Self::decode(payload)?;
        verify_cose(
            payload,
            spki,
            cose,
            generated::AUTHORIZATION_SCHEMA_ID,
            generated::AUTHORIZATION_PURPOSE_CODE,
            &value.signer.key_id,
        )?;
        Ok(value)
    }
}
fn encode<T: Wire>(value: &T) -> RuntimeResult<Vec<u8>> {
    let bytes = pc_cbor_1(&value.encode_value()?);
    if bytes.len() > 65_536 {
        return invalid();
    }
    Ok(bytes)
}
fn decode<T: Wire>(bytes: &[u8]) -> RuntimeResult<T> {
    let value = T::decode_value(&runtime_wire::decode(bytes, 65_536)?)?;
    if encode(&value)? != bytes {
        return invalid();
    }
    Ok(value)
}
fn verify_cose(
    payload: &[u8],
    spki: &[u8],
    cose: &[u8],
    schema: u64,
    purpose: u64,
    expected_key: &Hash32,
) -> RuntimeResult<()> {
    const PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    if spki.len() != 91
        || !spki.starts_with(PREFIX)
        || &digest(spki) != expected_key
        || cose.first() != Some(&0xd2)
        || cose.len() > 66_560
    {
        return invalid();
    }
    let value = runtime_wire::decode(&cose[1..], 66_560)?;
    let parts = value
        .as_array()
        .filter(|v| v.len() == 4)
        .ok_or(RuntimeError::InvalidInput)?;
    let header = pc_cbor_1(&map(vec![
        (1, Value::Integer((-7).into())),
        (2, Value::Array([100, 101, 102, 103].map(uint).to_vec())),
        (3, Value::Text("application/pc+cbor".to_owned())),
        (4, Value::Bytes(digest(spki).0.into_bytes())),
        (100, uint(schema)),
        (101, uint(1)),
        (102, uint(purpose)),
        (103, uint(2)),
    ]));
    if parts[0].as_bytes() != Some(&header)
        || !parts[1].as_map().is_some_and(Vec::is_empty)
        || parts[2].as_bytes().map(Vec::as_slice) != Some(payload)
    {
        return invalid();
    }
    let signature = parts[3]
        .as_bytes()
        .filter(|s| s.len() == 64)
        .ok_or(RuntimeError::InvalidInput)?;
    let structure = pc_cbor_1(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(header),
        Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
        Value::Bytes(payload.to_vec()),
    ]));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &spki[26..])
        .verify(&structure, signature)
        .map_err(|_| RuntimeError::InvalidInput)
}

#[cfg(test)]
mod tests;
