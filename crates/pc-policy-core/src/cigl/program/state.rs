//! Typed projection of a verified Fact payload. This validates the state anchor,
//! not Fact admission: only the held Fact owner may supply these bytes at runtime.
use super::*;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAnchorV1 {
    pub chain_id: String,
    pub block_hash: String,
    pub block_number: String,
    pub require_canonical: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchoredStateValueV1 {
    pub schema_version: String,
    pub state_anchor: StateAnchorV1,
    pub value: ArgumentValue,
}
impl AnchoredStateValueV1 {
    pub fn to_fact_payload(&self) -> RuntimeResult<Vec<u8>> {
        if self.schema_version != "1.0" || !self.state_anchor.require_canonical {
            return Err(RuntimeError::InvalidInput);
        }
        for quantity in [&self.state_anchor.chain_id, &self.state_anchor.block_number] {
            let digits = quantity
                .strip_prefix("0x")
                .ok_or(RuntimeError::InvalidInput)?;
            let value = u64::from_str_radix(digits, 16).map_err(|_| RuntimeError::InvalidInput)?;
            if &format!("0x{value:x}") != quantity {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Digest::parse(
            self.state_anchor
                .block_hash
                .strip_prefix("0x")
                .ok_or(RuntimeError::InvalidInput)?,
        )?;
        value_kind(&self.value)?;
        let value = serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?;
        let bytes = crate::pc_cbor_1(&value);
        if bytes.len() > 65_536 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(bytes)
    }
    pub fn read_at_anchor(
        bytes: &[u8],
        chain_id: u64,
        block_number: u64,
        block_hash: &Digest,
        finality_anchor: &[u8; 32],
    ) -> RuntimeResult<ArgumentValue> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(RuntimeError::InvalidInput);
        }
        let mut cursor = Cursor::new(bytes);
        let value: serde_json::Value =
            ciborium::de::from_reader(&mut cursor).map_err(|_| RuntimeError::InvalidInput)?;
        if cursor.position() != bytes.len() as u64 || crate::pc_cbor_1(&value) != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        let value: Self = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
        if value.schema_version != "1.0"
            || !value.state_anchor.require_canonical
            || value.state_anchor.chain_id != format!("0x{chain_id:x}")
            || value.state_anchor.block_number != format!("0x{block_number:x}")
            || value.state_anchor.block_hash != format!("0x{}", block_hash.as_str())
            || finality_anchor
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                != block_hash.as_str()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        value_kind(&value.value)?;
        Ok(value.value)
    }
}
