//! Source response admission never turns provider errors, missing data, removed
//! logs or a class mismatch into a successful empty acquisition.
use super::*;

pub(super) fn validate(
    request: &DecodedAcquisitionRequest,
    body: &[u8],
    maximum_bytes: usize,
    maximum_depth: usize,
) -> Result<Vec<u8>, CandidateStoreError> {
    if body.is_empty() || body.len() > maximum_bytes || maximum_depth == 0 {
        return Err(CandidateStoreError::InvalidBinding);
    }
    let mut response = openpc_multi_rpc::parse_strict_json(body, maximum_depth.min(64) as u32)
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
    let object = response
        .as_object()
        .ok_or(CandidateStoreError::InvalidBinding)?;
    if object.len() != 3
        || response["jsonrpc"] != "2.0"
        || !object.contains_key("result")
        || serde_json::to_string(&response["id"])
            .map_err(|_| CandidateStoreError::InvalidBinding)?
            != request.id
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    let result = &response["result"];
    match request.class.data_class.as_str() {
        "STATE_CALL" => {
            bytes(result, None)?;
        }
        "EXTERNAL_OBSERVATION" => {
            serde_json::from_value::<
                openpc_multi_rpc::external_decision::ExternalDecisionObservationV1,
            >(result.clone())
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        }
        "EVENT_LOG" => logs(request, result)?,
        "BLOCK_HEADER" => {
            response["result"] =
                openpc_multi_rpc::source_header::normalize_provider_header(result, request.block)
                    .map_err(|_| CandidateStoreError::InvalidBinding)?;
        }
        _ => return Err(CandidateStoreError::InvalidBinding),
    }
    let canonical = openpc_multi_rpc::rfc8785_canonical_bytes(&response)
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
    if canonical.len() > maximum_bytes {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(canonical)
}

fn bytes(value: &Value, length: Option<usize>) -> Result<&str, CandidateStoreError> {
    let hex = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(CandidateStoreError::InvalidBinding)?;
    if !hex.len().is_multiple_of(2)
        || length.is_some_and(|n| hex.len() != n * 2)
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    Ok(hex)
}

fn logs(request: &DecodedAcquisitionRequest, result: &Value) -> Result<(), CandidateStoreError> {
    let original: Value =
        serde_json::from_slice(&request.body).map_err(|_| CandidateStoreError::InvalidBinding)?;
    let filter = &original["params"][0];
    let mut previous = None;
    let mut block_hash = None;
    for log in result
        .as_array()
        .ok_or(CandidateStoreError::InvalidBinding)?
    {
        let object = log.as_object().ok_or(CandidateStoreError::InvalidBinding)?;
        let keys = [
            "address",
            "topics",
            "data",
            "blockNumber",
            "blockHash",
            "transactionHash",
            "transactionIndex",
            "logIndex",
            "removed",
        ];
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || log["address"] != filter["address"]
            || log["removed"] != false
            || quantity(&log["blockNumber"])? != request.block
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        bytes(&log["address"], Some(20))?;
        bytes(&log["data"], None)?;
        bytes(&log["transactionHash"], Some(32))?;
        let hash = bytes(&log["blockHash"], Some(32))?;
        if block_hash.is_some_and(|old| old != hash) {
            return Err(CandidateStoreError::InvalidBinding);
        }
        block_hash = Some(hash);
        let topics = log["topics"]
            .as_array()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        if topics.is_empty() || topics.len() > 4 || topics[0] != filter["topics"][0] {
            return Err(CandidateStoreError::InvalidBinding);
        }
        for topic in topics {
            bytes(topic, Some(32))?;
        }
        let position = (
            quantity(&log["transactionIndex"])?,
            quantity(&log["logIndex"])?,
        );
        if previous.is_some_and(|old: (u64, u64)| position.0 < old.0 || position.1 <= old.1) {
            return Err(CandidateStoreError::InvalidBinding);
        }
        previous = Some(position);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> DecodedAcquisitionRequest {
        DecodedAcquisitionRequest {
            body: br#"{"jsonrpc":"2.0","id":"header","method":"eth_getBlockByNumber","params":["0x188a",false]}"#.to_vec(),
            id: "\"header\"".into(),
            class: MethodDataClass {
                method: "eth_getBlockByNumber(false)".into(),
                data_class: "BLOCK_HEADER".into(),
            },
            block: 6282,
            target_id: "header-source".into(),
        }
    }

    fn response() -> Value {
        let header: Value = serde_json::from_str(include_str!(
            "../../multi-rpc/tests/fixtures/synthetic-provider-header.json"
        ))
        .unwrap();
        json!({"jsonrpc":"2.0","id":"header","result":header})
    }

    #[test]
    fn acquisition_releases_only_the_canonical_header_class() {
        let original = response();
        let admitted = request()
            .validate_response(&serde_json::to_vec(&original).unwrap(), 131_072, 8)
            .unwrap();
        let canonical: Value = serde_json::from_slice(&admitted).unwrap();
        assert_eq!(canonical.as_object().unwrap().len(), 3);
        assert_eq!(canonical["result"].as_object().unwrap().len(), 25);
        assert_eq!(canonical["result"]["hash"], original["result"]["hash"]);
        assert_eq!(
            canonical["result"]["stateRoot"],
            original["result"]["stateRoot"]
        );
        assert_eq!(
            canonical["result"]["transactions"],
            original["result"]["transactions"]
        );
        assert!(canonical["result"]["withdrawalsRoot"].is_null());
        assert!(canonical["result"]["requestsHash"].is_null());
        for field in [
            "mixHash",
            "blockGasCost",
            "minDelayExcess",
            "timestampMilliseconds",
        ] {
            assert!(canonical["result"].get(field).is_none());
        }
        assert_eq!(
            request().validate_response(&admitted, 131_072, 8).unwrap(),
            admitted
        );
    }

    #[test]
    fn normalization_does_not_admit_uncorrelated_or_private_responses() {
        for (pointer, value) in [
            ("/id", json!("other-request")),
            ("/jsonrpc", json!("1.0")),
            ("/result/number", json!("0x188b")),
            (
                "/result/transactions",
                json!([{"hash":"0x1234", "input":"private"}]),
            ),
            ("/result/timestampMilliseconds", json!("0x0")),
        ] {
            let mut raw = response();
            *raw.pointer_mut(pointer).unwrap() = value;
            assert!(
                request()
                    .validate_response(&serde_json::to_vec(&raw).unwrap(), 131_072, 8)
                    .is_err()
            );
        }
        let mut raw = response();
        raw["result"]["privatePayload"] = json!("0x1234");
        assert!(
            request()
                .validate_response(&serde_json::to_vec(&raw).unwrap(), 131_072, 8)
                .is_err()
        );
        let mut raw = response();
        raw["error"] = json!({"code":-32000, "message":"unavailable"});
        assert!(
            request()
                .validate_response(&serde_json::to_vec(&raw).unwrap(), 131_072, 8)
                .is_err()
        );
    }
}
