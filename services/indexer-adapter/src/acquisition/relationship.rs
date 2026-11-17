//! Closed RGRA event projection. Candidate storage contains scoped digests of
//! entity/subject values, never the original event topics or member identifiers.
use super::*;
use crate::candidate::decode_digest;
use pc_provider_api::NamedDigestV1;

pub const RGRA_EVENT_NAME: &str = "RelationshipChanged";
pub const RGRA_EVENT_SIGNATURE: &str =
    "0xb1fad1cf1959b1f2ff99e75268b8f16a068328466f001adc4e591b68e642baf3";
const MAPPING: &str = "RGRA_EVENT_RELATIONSHIP_V1:topics[1,2]->SHA256_SCOPED_KEYS_V1;data=(transition:uint8,from:uint64,through:uint64);OPEN=0,CLOSE=1,REPLACE=2;MAX_UINT64=open;PC-CBOR-1";

pub fn relationship_schema() -> NamedDigestV1 {
    NamedDigestV1 {
        name: "RelationshipCandidateV1".into(),
        digest: "sha256:b86eeaf46d4d23b047eab61e5e8e7a5dfd8e74525882005b316a93fb77125d38".into(),
    }
}
pub fn relationship_extractor() -> NamedDigestV1 {
    NamedDigestV1 {
        name: RGRA_EVENT_NAME.into(),
        digest: format!("sha256:{}", digest_hex(MAPPING.as_bytes())),
    }
}
fn fixed(value: &Value, bytes: usize) -> Result<Vec<u8>, CandidateStoreError> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or(CandidateStoreError::InvalidBatch)?;
    if text.len() != bytes * 2
        || !text
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| CandidateStoreError::InvalidBatch)
        })
        .collect()
}
fn number(value: &Value) -> Result<u64, CandidateStoreError> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or(CandidateStoreError::InvalidBatch)?;
    let result = u64::from_str_radix(text, 16).map_err(|_| CandidateStoreError::InvalidBatch)?;
    if text != format!("{result:x}") {
        return Err(CandidateStoreError::InvalidBatch);
    }
    Ok(result)
}
pub fn relationship_candidate(
    log: &Value,
    participant: &str,
    privacy: &str,
    contract: &str,
    signature: &str,
    block: u64,
    hash: &str,
) -> Result<(CandidateRecordIdentityV1, Vec<u8>), CandidateStoreError> {
    let topics = log["topics"]
        .as_array()
        .filter(|v| v.len() == 3)
        .ok_or(CandidateStoreError::InvalidBatch)?;
    if signature != RGRA_EVENT_SIGNATURE
        || log["removed"] != false
        || log["address"] != contract
        || topics[0] != signature
        || number(&log["blockNumber"])? != block
        || log["blockHash"] != format!("0x{}", hash.trim_start_matches("0x"))
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    let data = fixed(&log["data"], 96)?;
    let word = |offset: usize| -> Result<u64, CandidateStoreError> {
        let value = &data[offset * 32..(offset + 1) * 32];
        if value[..24].iter().any(|v| *v != 0) {
            return Err(CandidateStoreError::InvalidBatch);
        }
        Ok(u64::from_be_bytes(
            value[24..]
                .try_into()
                .map_err(|_| CandidateStoreError::InvalidBatch)?,
        ))
    };
    let transition = match word(0)? {
        0 => "OPEN",
        1 => "CLOSE",
        2 => "REPLACE",
        _ => return Err(CandidateStoreError::InvalidBatch),
    };
    let from = word(1)?;
    let through = match word(2)? {
        u64::MAX => None,
        value => Some(value),
    };
    if from > block
        || through.is_some_and(|value| value < from || value > block)
        || (transition == "CLOSE") != through.is_some()
    {
        return Err(CandidateStoreError::InvalidBatch);
    }
    let key = |value: &Value, kind: &str| -> Result<String, CandidateStoreError> {
        Ok(format!(
            "sha256:{}",
            digest_hex(&canonical_cbor(&json!([
                "openpc:rgra-scoped-key:v1",
                participant,
                privacy,
                kind,
                fixed(value, 32)?
            ])))
        ))
    };
    let transaction = fixed(&log["transactionHash"], 32)?;
    let transaction_hash = transaction
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    decode_digest(&transaction_hash)?;
    let identity = CandidateRecordIdentityV1::EventLog {
        transaction_hash,
        transaction_index: number(&log["transactionIndex"])?,
        log_index: number(&log["logIndex"])?,
        contract_address: contract.trim_start_matches("0x").into(),
        event_signature: signature.trim_start_matches("0x").into(),
    };
    let payload = canonical_cbor(&json!({"semanticProfile":"RGRA_EVENT_RELATIONSHIP_V1",
        "entityKeyDigest":key(&topics[1],"entity")?,"subjectKeyDigest":key(&topics[2],"subject")?,
        "transition":transition,"effectiveFromBlock":from.to_string(),"effectiveThroughBlock":through.map(|v|v.to_string())}));
    Ok((identity, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn log() -> Value {
        json!({"removed":false,"address":format!("0x{}","77".repeat(20)),
            "blockNumber":"0xa","blockHash":format!("0x{}","22".repeat(32)),
            "transactionHash":format!("0x{}","33".repeat(32)),"transactionIndex":"0x0","logIndex":"0x0",
            "topics":[RGRA_EVENT_SIGNATURE,format!("0x{}","44".repeat(32)),format!("0x{}","55".repeat(32))],
            "data":format!("0x{:064x}{:064x}{:064x}",0,10,u64::MAX)})
    }
    fn project(
        log: &Value,
        scope: &str,
    ) -> Result<(CandidateRecordIdentityV1, Vec<u8>), CandidateStoreError> {
        relationship_candidate(
            log,
            scope,
            "privacy",
            &format!("0x{}", "77".repeat(20)),
            RGRA_EVENT_SIGNATURE,
            10,
            &"22".repeat(32),
        )
    }
    #[test]
    fn relationship_projection_is_scoped_private_and_rejects_malformed_occurrences() {
        let original = log();
        let (_, payload) = project(&original, "participant").unwrap();
        let decoded: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(decoded["transition"], "OPEN");
        assert_ne!(payload, project(&original, "foreign").unwrap().1);
        assert!(!String::from_utf8_lossy(&payload).contains(&"44".repeat(32)));
        for field in [
            "removed",
            "blockNumber",
            "blockHash",
            "address",
            "transactionHash",
            "transactionIndex",
            "logIndex",
            "topics",
            "data",
        ] {
            let mut wrong = original.clone();
            wrong[field] = Value::Null;
            assert!(project(&wrong, "participant").is_err(), "{field}");
        }
        for (kind, from, through) in [
            (3, 10, u64::MAX),
            (0, 11, u64::MAX),
            (0, 10, 10),
            (1, 10, u64::MAX),
            (1, 9, 8),
            (1, 10, 11),
        ] {
            let mut wrong = original.clone();
            wrong["data"] = json!(format!("0x{kind:064x}{from:064x}{through:064x}"));
            assert!(project(&wrong, "participant").is_err());
        }
        let mut close = original;
        close["data"] = json!(format!("0x{:064x}{:064x}{:064x}", 1, 9, 10));
        assert!(project(&close, "participant").is_ok());
    }
}
