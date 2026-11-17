//! Exact non-authoritative state-result mapping. It carries no decoded ABI claim,
//! subject membership, permission, or fact readiness.
use crate::{CandidateStoreError, candidate::digest_hex, store::canonical_cbor};
use pc_provider_api::{NamedDigestV1, ProjectionPlanV1};
use serde_json::{Value, json};

const SCHEMA: &str = r#"{"additionalProperties":false,"properties":{"result":{"pattern":"^0x([0-9a-f]{2})*$","type":"string"}},"required":["result"],"type":"object"}"#;
const EXTRACTOR: &str =
    r#"["openpc:state-result-extractor:v1",["result","$.result"],"canonical-pc-cbor"]"#;

pub fn state_result_schema() -> NamedDigestV1 {
    NamedDigestV1 {
        name: "pc.candidate.evm.state.result.v1".into(),
        digest: format!("sha256:{}", digest_hex(SCHEMA.as_bytes())),
    }
}
pub fn state_result_extractor() -> NamedDigestV1 {
    NamedDigestV1 {
        name: "pc.candidate.evm.state.result.v1".into(),
        digest: format!("sha256:{}", digest_hex(EXTRACTOR.as_bytes())),
    }
}
pub(super) fn validate_mapping(plan: &ProjectionPlanV1) -> Result<(), CandidateStoreError> {
    if plan.candidate_schema_digests != [state_result_schema()]
        || plan.extractor_digests != [state_result_extractor()]
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(())
}
pub(super) fn state_payload(response: &Value) -> Result<Vec<u8>, CandidateStoreError> {
    let result = response["result"]
        .as_str()
        .ok_or(CandidateStoreError::InvalidBatch)?;
    let bytes = result
        .strip_prefix("0x")
        .ok_or(CandidateStoreError::InvalidBatch)?;
    if !bytes.len().is_multiple_of(2)
        || !bytes
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    Ok(canonical_cbor(&json!({"result":result})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_mapping_preserves_bytes_and_never_invents_a_decoded_fact() {
        let payload = state_payload(&json!({"result":"0x001234"})).unwrap();
        let decoded: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(decoded, json!({"result":"0x001234"}));
        for invalid in [
            json!(null),
            json!(42),
            json!("0x1"),
            json!("0xGG"),
            json!({"value":true}),
        ] {
            assert!(state_payload(&json!({"result":invalid})).is_err());
        }
        assert_ne!(
            state_result_schema().digest,
            state_result_extractor().digest
        );
    }
}
