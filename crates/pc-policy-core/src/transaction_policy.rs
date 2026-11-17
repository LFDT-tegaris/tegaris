//! Contract-binding transaction upper bounds. They constrain an independently
//! authorized submission and never grant signing, submission or disclosure.
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

pub const MAX_RAW_TRANSACTION_BYTES: usize = 131_072;
pub const MAX_CALLDATA_BYTES: usize = 32_768;
pub const MAX_ACCESS_LIST_ADDRESSES: usize = 128;
pub const MAX_ACCESS_LIST_STORAGE_KEYS: usize = 1_024;
pub const MAX_TRANSACTION_DEADLINE_MS: u64 = 10_000;

/// JSON uses exact hexadecimal strings; admitted CBOR uses fixed 32-byte values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionPolicyV1 {
    pub version: u8,
    pub allowed_transaction_types: Vec<u8>,
    #[serde(with = "uint256")]
    pub maximum_value: [u8; 32],
    #[serde(with = "uint64")]
    pub maximum_gas_limit: u64,
    #[serde(with = "uint256")]
    pub maximum_fee_per_gas: [u8; 32],
    #[serde(with = "uint256")]
    pub maximum_priority_fee_per_gas: [u8; 32],
    pub maximum_raw_transaction_bytes: usize,
    pub maximum_calldata_bytes: usize,
    pub maximum_access_list_addresses: usize,
    pub maximum_access_list_storage_keys: usize,
}

impl TransactionPolicyV1 {
    pub fn validate(&self) -> RuntimeResult<()> {
        if self.version != 1
            || self.allowed_transaction_types.is_empty()
            || self.allowed_transaction_types.iter().any(|kind| *kind > 2)
            || self
                .allowed_transaction_types
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.maximum_gas_limit == 0
            || self.maximum_priority_fee_per_gas > self.maximum_fee_per_gas
            || !(1..=MAX_RAW_TRANSACTION_BYTES).contains(&self.maximum_raw_transaction_bytes)
            || !(4..=MAX_CALLDATA_BYTES).contains(&self.maximum_calldata_bytes)
            || self.maximum_access_list_addresses > MAX_ACCESS_LIST_ADDRESSES
            || self.maximum_access_list_storage_keys > MAX_ACCESS_LIST_STORAGE_KEYS
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

mod uint256 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!(
                "0x{}",
                value.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ))
        } else {
            serializer.serialize_bytes(value)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            let hex = value
                .strip_prefix("0x")
                .filter(|v| {
                    v.len() == 64
                        && v.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or_else(|| de::Error::custom("exact uint256 required"))?;
            let mut bytes = [0; 32];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                    .map_err(de::Error::custom)?;
            }
            Ok(bytes)
        } else {
            struct FixedBytes;
            impl de::Visitor<'_> for FixedBytes {
                type Value = [u8; 32];
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("32-byte unsigned integer")
                }
                fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                    value
                        .try_into()
                        .map_err(|_| E::custom("exact uint256 required"))
                }
            }
            deserializer.deserialize_bytes(FixedBytes)
        }
    }
}

mod uint64 {
    use serde::{Deserialize, Deserializer, Serializer, de};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&value.to_string())
        } else {
            serializer.serialize_u64(*value)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        if !deserializer.is_human_readable() {
            return u64::deserialize(deserializer);
        }
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(de::Error::custom)?;
        if parsed.to_string() != value {
            return Err(de::Error::custom("exact uint64 required"));
        }
        Ok(parsed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn policy() -> TransactionPolicyV1 {
        TransactionPolicyV1 {
            version: 1,
            allowed_transaction_types: vec![0, 1, 2],
            maximum_value: [255; 32],
            maximum_gas_limit: u64::MAX,
            maximum_fee_per_gas: [255; 32],
            maximum_priority_fee_per_gas: [255; 32],
            maximum_raw_transaction_bytes: MAX_RAW_TRANSACTION_BYTES,
            maximum_calldata_bytes: MAX_CALLDATA_BYTES,
            maximum_access_list_addresses: MAX_ACCESS_LIST_ADDRESSES,
            maximum_access_list_storage_keys: MAX_ACCESS_LIST_STORAGE_KEYS,
        }
    }
    #[test]
    fn transaction_policy_preserves_full_width_json_and_fixed_byte_cbor() {
        let policy = policy();
        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json["maximumValue"], format!("0x{}", "ff".repeat(32)));
        assert_eq!(json["maximumGasLimit"], "18446744073709551615");
        assert_eq!(
            serde_json::from_value::<TransactionPolicyV1>(json.clone()).unwrap(),
            policy
        );
        for bad in [
            serde_json::json!(1),
            serde_json::json!("0x1"),
            serde_json::json!(format!("0x{}", "FF".repeat(32))),
            serde_json::json!(vec![255; 32]),
        ] {
            let mut altered = json.clone();
            altered["maximumValue"] = bad;
            assert!(serde_json::from_value::<TransactionPolicyV1>(altered).is_err());
        }
        for bad in [
            serde_json::json!(9007199254740992u64),
            serde_json::json!("18446744073709551616"),
            serde_json::json!("01"),
        ] {
            let mut altered = json.clone();
            altered["maximumGasLimit"] = bad;
            assert!(serde_json::from_value::<TransactionPolicyV1>(altered).is_err());
        }
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&policy, &mut cbor).unwrap();
        assert_eq!(
            ciborium::de::from_reader::<TransactionPolicyV1, _>(cbor.as_slice()).unwrap(),
            policy
        );
        let value: ciborium::value::Value = ciborium::de::from_reader(cbor.as_slice()).unwrap();
        let fields = value.as_map().unwrap();
        let monetary = fields
            .iter()
            .find(|(key, _)| key.as_text() == Some("maximumValue"))
            .unwrap();
        assert_eq!(monetary.1.as_bytes().unwrap(), &[255; 32]);
    }
    #[test]
    fn transaction_policy_cannot_raise_reference_ceilings() {
        let base = policy();
        base.validate().unwrap();
        for mutate in [
            |p: &mut TransactionPolicyV1| p.version = 2,
            |p: &mut TransactionPolicyV1| p.allowed_transaction_types = vec![2, 1],
            |p: &mut TransactionPolicyV1| p.allowed_transaction_types = vec![0, 3],
            |p: &mut TransactionPolicyV1| p.allowed_transaction_types.clear(),
            |p: &mut TransactionPolicyV1| p.maximum_gas_limit = 0,
            |p: &mut TransactionPolicyV1| p.maximum_fee_per_gas = [0; 32],
            |p: &mut TransactionPolicyV1| p.maximum_raw_transaction_bytes += 1,
            |p: &mut TransactionPolicyV1| p.maximum_calldata_bytes += 1,
            |p: &mut TransactionPolicyV1| p.maximum_access_list_addresses += 1,
            |p: &mut TransactionPolicyV1| p.maximum_access_list_storage_keys += 1,
        ] {
            let mut altered = base.clone();
            mutate(&mut altered);
            assert!(altered.validate().is_err());
        }
    }
}
