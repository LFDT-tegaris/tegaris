//! Closed BLOCK_HEADER decoding shared by live conformance and source consumers.
//! Shape admission alone establishes neither canonicality nor finality.
use serde_json::Value;

const HEADER_FIELDS: [&str; 25] = [
    "number",
    "hash",
    "parentHash",
    "nonce",
    "sha3Uncles",
    "logsBloom",
    "transactionsRoot",
    "stateRoot",
    "receiptsRoot",
    "miner",
    "difficulty",
    "totalDifficulty",
    "extraData",
    "size",
    "gasLimit",
    "gasUsed",
    "timestamp",
    "transactions",
    "uncles",
    "baseFeePerGas",
    "withdrawalsRoot",
    "blobGasUsed",
    "excessBlobGas",
    "parentBeaconBlockRoot",
    "requestsHash",
];
const NULLABLE_FIELDS: [&str; 9] = [
    "nonce",
    "logsBloom",
    "totalDifficulty",
    "baseFeePerGas",
    "withdrawalsRoot",
    "blobGasUsed",
    "excessBlobGas",
    "parentBeaconBlockRoot",
    "requestsHash",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("source block header rejected")]
pub struct SourceHeaderError;

pub struct SourceBlockHeader {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub state_root: String,
    pub timestamp_seconds: u64,
}
impl SourceBlockHeader {
    pub fn decode(result: &Value, expected_number: u64) -> Result<Self, SourceHeaderError> {
        let normalized = normalize_provider_header(result, expected_number)?;
        let result = &normalized;
        Ok(Self {
            number: expected_number,
            hash: bytes(&result["hash"], Some(32))?.to_owned(),
            parent_hash: bytes(&result["parentHash"], Some(32))?.to_owned(),
            state_root: bytes(&result["stateRoot"], Some(32))?.to_owned(),
            timestamp_seconds: quantity(&result["timestamp"])?,
        })
    }
}

/// Admit a closed provider representation and return the unchanged canonical
/// header class. Provider-only fields are validated before being omitted.
pub fn normalize_provider_header(
    result: &Value,
    expected_number: u64,
) -> Result<Value, SourceHeaderError> {
    let object = result.as_object().ok_or(SourceHeaderError)?;
    if object.keys().any(|key| {
        !HEADER_FIELDS.contains(&key.as_str())
            && ![
                "mixHash",
                "blockGasCost",
                "minDelayExcess",
                "timestampMilliseconds",
            ]
            .contains(&key.as_str())
    }) {
        return Err(SourceHeaderError);
    }
    if let Some(value) = object.get("mixHash") {
        bytes(value, Some(32))?;
    }
    if let Some(value) = object.get("blockGasCost") {
        wide_quantity(value)?;
    }
    if let Some(value) = object.get("minDelayExcess") {
        quantity(value)?;
    }
    if let Some(value) = object.get("timestampMilliseconds")
        && quantity(value)? / 1000 != quantity(&result["timestamp"])?
    {
        return Err(SourceHeaderError);
    }
    let mut normalized = object.clone();
    normalized.retain(|key, _| HEADER_FIELDS.contains(&key.as_str()));
    for key in NULLABLE_FIELDS {
        normalized.entry(key).or_insert(Value::Null);
    }
    let normalized = Value::Object(normalized);
    validate(&normalized, expected_number)?;
    Ok(normalized)
}

fn bytes(value: &Value, length: Option<usize>) -> Result<&str, SourceHeaderError> {
    let hex = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(SourceHeaderError)?;
    if !hex.len().is_multiple_of(2)
        || length.is_some_and(|n| hex.len() != n * 2)
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SourceHeaderError);
    }
    Ok(hex)
}

fn quantity(value: &Value) -> Result<u64, SourceHeaderError> {
    let text = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(SourceHeaderError)?;
    if text.is_empty()
        || text.len() > 16
        || (text.len() > 1 && text.starts_with('0'))
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SourceHeaderError);
    }
    u64::from_str_radix(text, 16).map_err(|_| SourceHeaderError)
}

fn wide_quantity(value: &Value) -> Result<(), SourceHeaderError> {
    let hex = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(SourceHeaderError)?;
    if hex.is_empty()
        || hex.len() > 64
        || (hex.len() > 1 && hex.starts_with('0'))
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SourceHeaderError);
    }
    Ok(())
}

fn validate(result: &Value, expected_number: u64) -> Result<(), SourceHeaderError> {
    let object = result.as_object().ok_or(SourceHeaderError)?;
    // This registered header response admits hashes, never full transaction or
    // withdrawal objects. A different response class needs its own permission.
    if object.len() != HEADER_FIELDS.len()
        || HEADER_FIELDS.iter().any(|key| !object.contains_key(*key))
        || quantity(&result["number"])? != expected_number
    {
        return Err(SourceHeaderError);
    }
    for key in [
        "hash",
        "parentHash",
        "stateRoot",
        "receiptsRoot",
        "transactionsRoot",
    ] {
        bytes(&result[key], Some(32))?;
    }
    for (key, value) in object {
        if value.is_null() && NULLABLE_FIELDS.contains(&key.as_str()) {
            continue;
        }
        match key.as_str() {
            "number" | "difficulty" | "totalDifficulty" | "baseFeePerGas" => {
                wide_quantity(value)?;
            }
            "size" | "gasLimit" | "gasUsed" | "timestamp" | "blobGasUsed" | "excessBlobGas" => {
                quantity(value)?;
            }
            "transactions" | "uncles" => {
                for hash in value.as_array().ok_or(SourceHeaderError)? {
                    bytes(hash, Some(32))?;
                }
            }
            "nonce" => {
                bytes(value, Some(8))?;
            }
            "logsBloom" => {
                bytes(value, Some(256))?;
            }
            "miner" => {
                bytes(value, Some(20))?;
            }
            "extraData" => {
                bytes(value, None)?;
            }
            _ => {
                bytes(value, Some(32))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn synthetic_header() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/synthetic-provider-header.json"
        ))
        .unwrap()
    }

    #[test]
    fn synthetic_provider_header_keeps_identity_and_canonical_response_contract() {
        let raw = synthetic_header();
        let original = raw.clone();
        let normalized = normalize_provider_header(&raw, 6282).unwrap();
        assert_eq!(raw, original);
        assert_eq!(normalized.as_object().unwrap().len(), 25);
        assert!(normalized["requestsHash"].is_null());
        assert!(normalized["withdrawalsRoot"].is_null());
        for field in HEADER_FIELDS {
            if let Some(value) = raw.get(field) {
                assert_eq!(&normalized[field], value, "{field} must not change");
            }
        }
        assert_eq!(
            normalize_provider_header(&normalized, 6282).unwrap(),
            normalized
        );
        let header = SourceBlockHeader::decode(&raw, 6282).unwrap();
        assert_eq!(header.number, 6282);
        assert_eq!(
            header.hash,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(header.timestamp_seconds, 1700000000);
        assert_eq!(header.parent_hash, raw["parentHash"].as_str().unwrap()[2..]);
        assert_eq!(header.state_root, raw["stateRoot"].as_str().unwrap()[2..]);
    }

    #[test]
    fn provider_extensions_require_closed_types_and_consistent_time() {
        for (field, value) in [
            ("privatePayload", json!("0x1234")),
            ("withdrawals", json!([])),
            ("mixHash", json!("0x00")),
            ("blockGasCost", json!("0x00")),
            ("blockGasCost", json!({"value":"0x0"})),
            ("blockGasCost", json!(format!("0x{}", "f".repeat(65)))),
            ("minDelayExcess", json!("0x10000000000000000")),
            ("timestampMilliseconds", json!("0x0")),
            ("timestampMilliseconds", json!(1700000000123u64)),
            ("transactions", json!([{"hash":"0x1234","input":"private"}])),
            ("uncles", json!([{"hash":"0x1234"}])),
            ("requestsHash", json!({"hash":"private"})),
        ] {
            let mut raw = synthetic_header();
            raw[field] = value;
            assert!(
                normalize_provider_header(&raw, 6282).is_err(),
                "must reject {field}"
            );
            assert!(SourceBlockHeader::decode(&raw, 6282).is_err());
        }
        for field in HEADER_FIELDS
            .into_iter()
            .filter(|field| !NULLABLE_FIELDS.contains(field))
        {
            let mut raw = synthetic_header();
            raw.as_object_mut().unwrap().remove(field);
            assert!(
                normalize_provider_header(&raw, 6282).is_err(),
                "missing {field}"
            );
        }
        assert!(normalize_provider_header(&synthetic_header(), 6283).is_err());
    }
}
