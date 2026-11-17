//! Shared closed-field admission for primary runtime wire models.
use ciborium::value::Value;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use unicode_normalization::UnicodeNormalization;

pub fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
pub fn text(value: &str, maximum: usize) -> RuntimeResult<Value> {
    if value.is_empty() || value.len() > maximum || value.nfc().collect::<String>() != value {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(Value::Text(value.to_owned()))
}
pub fn digest(value: &Digest) -> RuntimeResult<Value> {
    let value = value.as_str();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RuntimeError::InvalidDigest);
    }
    let bytes: Result<Vec<_>, _> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect();
    Ok(Value::Bytes(
        bytes.map_err(|_| RuntimeError::InvalidDigest)?,
    ))
}
pub fn map(values: Vec<(u64, Value)>) -> Value {
    Value::Map(
        values
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
    )
}
pub fn fields<'a>(value: &'a Value, allowed: &[u64]) -> RuntimeResult<Vec<(u64, &'a Value)>> {
    let pairs = value.as_map().ok_or(RuntimeError::InvalidInput)?;
    let mut result = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let key = number(key)?;
        if !allowed.contains(&key) || result.last().is_some_and(|(last, _)| *last >= key) {
            return Err(RuntimeError::InvalidInput);
        }
        result.push((key, value));
    }
    Ok(result)
}
pub fn field<'a>(fields: &[(u64, &'a Value)], key: u64) -> RuntimeResult<&'a Value> {
    fields
        .iter()
        .find(|(id, _)| *id == key)
        .map(|(_, v)| *v)
        .ok_or(RuntimeError::InvalidInput)
}
pub fn number(value: &Value) -> RuntimeResult<u64> {
    value
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(RuntimeError::InvalidInput)
}
pub fn string(value: &Value) -> RuntimeResult<String> {
    value
        .as_text()
        .map(str::to_owned)
        .ok_or(RuntimeError::InvalidInput)
}
pub fn read_digest(value: &Value) -> RuntimeResult<Digest> {
    let bytes = value
        .as_bytes()
        .filter(|v| v.len() == 32)
        .ok_or(RuntimeError::InvalidDigest)?;
    Digest::parse(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
