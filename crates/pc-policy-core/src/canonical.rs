use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CanonicalValue>),
    Map(Vec<(CanonicalValue, CanonicalValue)>),
}

#[derive(Debug)]
struct CanonicalError(String);

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalError {}

impl ser::Error for CanonicalError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

struct CanonicalSerializer;

enum CompoundKind {
    Array {
        values: Vec<CanonicalValue>,
        fixed_bytes: bool,
    },
    Map {
        entries: Vec<(CanonicalValue, CanonicalValue)>,
        pending_key: Option<CanonicalValue>,
    },
}

struct Compound {
    kind: CompoundKind,
    variant: Option<String>,
}

impl Compound {
    fn array(capacity: Option<usize>, variant: Option<&str>, fixed_bytes: bool) -> Self {
        Self {
            kind: CompoundKind::Array {
                values: Vec::with_capacity(capacity.unwrap_or(0)),
                fixed_bytes,
            },
            variant: variant.map(str::to_owned),
        }
    }

    fn map(capacity: Option<usize>, variant: Option<&str>) -> Self {
        Self {
            kind: CompoundKind::Map {
                entries: Vec::with_capacity(capacity.unwrap_or(0)),
                pending_key: None,
            },
            variant: variant.map(str::to_owned),
        }
    }

    fn push(&mut self, value: CanonicalValue) -> Result<(), CanonicalError> {
        match &mut self.kind {
            CompoundKind::Array { values, .. } => {
                values.push(value);
                Ok(())
            }
            CompoundKind::Map { .. } => Err(CanonicalError("expected an array".to_owned())),
        }
    }

    fn key(&mut self, key: CanonicalValue) -> Result<(), CanonicalError> {
        match &mut self.kind {
            CompoundKind::Map { pending_key, .. } if pending_key.is_none() => {
                *pending_key = Some(key);
                Ok(())
            }
            CompoundKind::Map { .. } => Err(CanonicalError("map key already pending".to_owned())),
            CompoundKind::Array { .. } => Err(CanonicalError("expected a map".to_owned())),
        }
    }

    fn value(&mut self, value: CanonicalValue) -> Result<(), CanonicalError> {
        match &mut self.kind {
            CompoundKind::Map {
                entries,
                pending_key,
            } => {
                let key = pending_key
                    .take()
                    .ok_or_else(|| CanonicalError("map value has no key".to_owned()))?;
                entries.push((key, value));
                Ok(())
            }
            CompoundKind::Array { .. } => Err(CanonicalError("expected a map".to_owned())),
        }
    }

    fn finish(self) -> Result<CanonicalValue, CanonicalError> {
        let value = match self.kind {
            CompoundKind::Array {
                values,
                fixed_bytes,
            } => {
                if fixed_bytes
                    && values.len() == 32
                    && values
                        .iter()
                        .all(|value| matches!(value, CanonicalValue::Integer(0..=255)))
                {
                    CanonicalValue::Bytes(
                        values
                            .into_iter()
                            .map(|value| match value {
                                CanonicalValue::Integer(byte) => byte as u8,
                                _ => unreachable!("byte predicate checked"),
                            })
                            .collect(),
                    )
                } else {
                    CanonicalValue::Array(values)
                }
            }
            CompoundKind::Map {
                entries,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return Err(CanonicalError("map ended with a pending key".to_owned()));
                }
                CanonicalValue::Map(entries)
            }
        };
        Ok(match self.variant {
            Some(variant) => CanonicalValue::Map(vec![(CanonicalValue::Text(variant), value)]),
            None => value,
        })
    }
}

impl Serializer for CanonicalSerializer {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    type SerializeSeq = Compound;
    type SerializeTuple = Compound;
    type SerializeTupleStruct = Compound;
    type SerializeTupleVariant = Compound;
    type SerializeMap = Compound;
    type SerializeStruct = Compound;
    type SerializeStructVariant = Compound;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Bool(value))
    }
    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        self.serialize_i128(value.into())
    }
    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        self.serialize_i128(value.into())
    }
    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        self.serialize_i128(value.into())
    }
    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        self.serialize_i128(value.into())
    }
    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        if value < -(u64::MAX as i128) - 1 || value > u64::MAX as i128 {
            return Err(CanonicalError(
                "integer outside the PC-CBOR-1 range".to_owned(),
            ));
        }
        Ok(CanonicalValue::Integer(value))
    }
    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u128(value.into())
    }
    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u128(value.into())
    }
    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u128(value.into())
    }
    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        self.serialize_u128(value.into())
    }
    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        if value > u64::MAX as u128 {
            return Err(CanonicalError(
                "integer outside the PC-CBOR-1 range".to_owned(),
            ));
        }
        Ok(CanonicalValue::Integer(value as i128))
    }
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Err(CanonicalError(
            "PC-CBOR-1 forbids floating-point values".to_owned(),
        ))
    }
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Err(CanonicalError(
            "PC-CBOR-1 forbids floating-point values".to_owned(),
        ))
    }
    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(&value.to_string())
    }
    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Text(value.to_owned()))
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Bytes(value.to_vec()))
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(CanonicalValue::Map(vec![(
            CanonicalValue::Text(variant.to_owned()),
            value.serialize(self)?,
        )]))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(Compound::array(len, None, false))
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(Compound::array(Some(len), None, len == 32))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(Compound::array(Some(len), None, false))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(Compound::array(Some(len), Some(variant), false))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(Compound::map(len, None))
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(Compound::map(Some(len), None))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(Compound::map(Some(len), Some(variant)))
    }
}

impl SerializeSeq for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeTuple for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeTupleStruct for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeTupleVariant for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeMap for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.key(key.serialize(CanonicalSerializer)?)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.value(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeStruct for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.key(CanonicalValue::Text(key.to_owned()))?;
        self.value(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}
impl SerializeStructVariant for Compound {
    type Ok = CanonicalValue;
    type Error = CanonicalError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.key(CanonicalValue::Text(key.to_owned()))?;
        self.value(value.serialize(CanonicalSerializer)?)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

fn push_major(output: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=0xff => output.extend([(major << 5) | 24, value as u8]),
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend((value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend((value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend(value.to_be_bytes());
        }
    }
}

fn encode_value(value: &CanonicalValue, output: &mut Vec<u8>) {
    match value {
        CanonicalValue::Null => output.push(0xf6),
        CanonicalValue::Bool(false) => output.push(0xf4),
        CanonicalValue::Bool(true) => output.push(0xf5),
        CanonicalValue::Integer(value) if *value >= 0 => push_major(output, 0, *value as u64),
        CanonicalValue::Integer(value) => push_major(output, 1, (-1 - *value) as u64),
        CanonicalValue::Bytes(bytes) => {
            push_major(output, 2, bytes.len() as u64);
            output.extend(bytes);
        }
        CanonicalValue::Text(text) => {
            push_major(output, 3, text.len() as u64);
            output.extend(text.as_bytes());
        }
        CanonicalValue::Array(values) => {
            push_major(output, 4, values.len() as u64);
            for item in values {
                encode_value(item, output);
            }
        }
        CanonicalValue::Map(values) => {
            let mut entries = values
                .iter()
                .map(|(key, value)| {
                    let mut encoded_key = Vec::new();
                    encode_value(key, &mut encoded_key);
                    (encoded_key, value)
                })
                .collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            });
            for pair in entries.windows(2) {
                assert_ne!(pair[0].0, pair[1].0, "PC-CBOR-1 forbids duplicate map keys");
            }
            push_major(output, 5, entries.len() as u64);
            for (key, value) in entries {
                output.extend(key);
                encode_value(value, output);
            }
        }
    }
}

/// RFC 8949 Core Deterministic CBOR bytes. This encoder does not select a schema
/// or a digest domain; callers validate their owned payload before encoding.
pub fn pc_cbor_1<T: Serialize>(value: &T) -> Vec<u8> {
    let value = value
        .serialize(CanonicalSerializer)
        .expect("PC-CBOR-1 value must use the closed supported type set");
    let mut output = Vec::new();
    encode_value(&value, &mut output);
    output
}

pub fn pc_cbor_1_digest<T: Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(pc_cbor_1(value)).into()
}

/// CANON-CONTRACT-001 revision 4 semantic identity. The payload must already be
/// validated against the registered schema and its semantic collection rules.
pub fn pc_cbor_1_semantic_digest<T: Serialize>(
    schema_id: u64,
    schema_version: u64,
    payload: &T,
) -> [u8; 32] {
    let payload = payload
        .serialize(CanonicalSerializer)
        .expect("PC-CBOR-1 value must use the closed supported type set");
    let envelope = CanonicalValue::Map(vec![
        (CanonicalValue::Integer(0), CanonicalValue::Integer(1)),
        (
            CanonicalValue::Integer(1),
            CanonicalValue::Integer(schema_id.into()),
        ),
        (
            CanonicalValue::Integer(2),
            CanonicalValue::Integer(schema_version.into()),
        ),
        (CanonicalValue::Integer(3), payload),
    ]);
    let mut bytes = b"pcplane:semantic-digest:v1\0".to_vec();
    encode_value(&envelope, &mut bytes);
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct RawBytes(Vec<u8>);
    impl Serialize for RawBytes {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&self.0)
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "hex must have an even length");
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    fn encode_hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    struct IdentityCredentialVector;
    impl Serialize for IdentityCredentialVector {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(9))?;
            map.serialize_entry(&1_u32, "openpc:identity-credential:v1")?;
            map.serialize_entry(&2_u32, &22_501_u32)?;
            map.serialize_entry(&3_u32, "1.0.0")?;
            map.serialize_entry(
                &4_u32,
                &RawBytes(decode_hex(
                    "2bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b1111",
                )),
            )?;
            map.serialize_entry(
                &5_u32,
                "urn:openpc:participant:018f1e2d-3c4b-7a69-8abc-0123456789ab",
            )?;
            map.serialize_entry(
                &6_u32,
                "urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-1123456789ab",
            )?;
            map.serialize_entry(&7_u32, "7")?;
            map.serialize_entry(&8_u32, "2026-08-24T00:00:00.000000Z")?;
            map.serialize_entry(&9_u32, "2026-08-24T00:05:00.000000Z")?;
            map.end()
        }
    }

    #[test]
    fn map_order_does_not_change_identity() {
        assert_eq!(
            pc_cbor_1_digest(&json!({"a": 1, "bbb": 2})),
            pc_cbor_1_digest(&json!({"bbb": 2, "a": 1})),
        );
        assert_eq!(pc_cbor_1(&json!({"a": 1}))[0], 0xa1);
        assert_eq!(
            &pc_cbor_1(&serde_json::Value::Array(vec![json!(0); 32]))[..2],
            &[0x98, 0x20],
        );
    }

    #[test]
    fn exact_numeric_schema_vector_matches() {
        let bytes = pc_cbor_1(&IdentityCredentialVector);
        assert_eq!(
            encode_hex(&bytes),
            "a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a"
        );
        assert_eq!(
            encode_hex(&pc_cbor_1_digest(&IdentityCredentialVector)),
            "fa9834eb305287cef4489713cb503816f84179db7a3a1fab20f347fa29f986be"
        );
    }
}
