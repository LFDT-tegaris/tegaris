//! One duplicate-safe JSON owner. Enforce depth while parsing, including the
//! reviewed CIGL limit of 128 call frames nested through objects/calls arrays.
use super::{MultiRpcError, RpcCondition, condition, invalid};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

// 128 nested calls plus the root frame and JSON-RPC envelope. Disabling Serde's
// fixed 128-level limit is safe only while this explicit bounded seed is used.
const MAX_JSON_DEPTH: u32 = 260;

#[derive(Clone, Copy)]
struct JsonSeed {
    remaining: u32,
}
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.deserialize(deserializer)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("JSON depth exceeded"))?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed { remaining })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("JSON depth exceeded"))?;
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            object.insert(key, map.next_value_seed(JsonSeed { remaining })?);
        }
        Ok(Value::Object(object))
    }
}

/// Byte limits remain with the request/response owner. Unknown depth profiles,
/// excessive nesting, duplicate keys and trailing data all fail before use.
pub fn parse_strict_json(bytes: &[u8], max_depth: u32) -> Result<Value, MultiRpcError> {
    if max_depth > MAX_JSON_DEPTH {
        return invalid();
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    decoder.disable_recursion_limit();
    let value = JsonSeed {
        remaining: max_depth,
    }
    .deserialize(&mut decoder)
    .map_err(|_| condition(RpcCondition::InvalidResponse))?;
    decoder
        .end()
        .map_err(|_| condition(RpcCondition::InvalidResponse))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_depth_is_enforced_during_decode_at_the_actual_supported_boundary() {
        assert_eq!(parse_strict_json(b"42", 0).unwrap(), Value::from(42));
        assert!(parse_strict_json(b"[]", 0).is_err());
        assert!(parse_strict_json(b"{}", 0).is_err());
        for depth in [1, 40, 128, 259, 260] {
            let json = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            assert!(parse_strict_json(json.as_bytes(), depth as u32).is_ok());
            assert!(parse_strict_json(json.as_bytes(), depth as u32 - 1).is_err());
        }
        assert!(parse_strict_json(b"null", MAX_JSON_DEPTH + 1).is_err());
        assert!(parse_strict_json(b"null", u32::MAX).is_err());
    }

    #[test]
    fn deep_duplicate_keys_truncation_and_trailing_values_remain_rejected() {
        let prefix = "[".repeat(256);
        let suffix = "]".repeat(256);
        for inner in [r#"{"value":1,"value":2}"#, r#"{"value":1,"\u0076alue":2}"#] {
            assert!(parse_strict_json(format!("{prefix}{inner}{suffix}").as_bytes(), 260).is_err());
        }
        for invalid in ["[1,", "{", "null true", "[1,]", "1e99999"] {
            assert!(parse_strict_json(invalid.as_bytes(), 260).is_err());
        }
        let valid = br#"{"a":[null,true,-1,1.25,"x"],"b":18446744073709551615}"#;
        assert_eq!(
            parse_strict_json(valid, 2).unwrap(),
            serde_json::from_slice::<Value>(valid).unwrap()
        );
    }
}
