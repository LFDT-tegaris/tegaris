//! Strict local operation-status transport form; no provider request is built.
use openpc_multi_rpc::submission_status::OperationStatusView;
use pc_runtime_types::{
    Digest, RequestClass, RuntimeError, RuntimeRequest, RuntimeResult, Transport,
};
use serde_json::Value;

pub(crate) struct OperationStatusRequest {
    pub operation_id: String,
    pub request: RuntimeRequest,
    id: Value,
}
impl OperationStatusRequest {
    pub fn decode(
        body: &[u8],
        maximum_bytes: usize,
        now_ms: u64,
        timeout_ms: u64,
        response_budget_bytes: u64,
    ) -> RuntimeResult<Option<Self>> {
        let value = crate::request_decode::strict_json_rpc_envelope(body, maximum_bytes)?;
        if value["method"] != "pc_getOperationStatus" {
            return Ok(None);
        }
        if now_ms == 0
            || !(1..=10_000).contains(&timeout_ms)
            || !(1..=8192).contains(&response_budget_bytes)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let params = value["params"]
            .as_array()
            .filter(|p| p.len() == 1)
            .ok_or(RuntimeError::InvalidInput)?;
        let operation_id = params[0]
            .as_str()
            .and_then(|urn| urn.strip_prefix("urn:openpc:operation:"))
            .filter(|id| crate::RequestTraceId::valid(id))
            .ok_or(RuntimeError::InvalidInput)?
            .to_owned();
        let id = value["id"].clone();
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: crate::request_decode::request_id(&id)?,
            method: "pc_getOperationStatus".into(),
            params_digest: Digest::of(
                openpc_multi_rpc::rfc8785_canonical_bytes(&value["params"])
                    .map_err(|_| RuntimeError::InvalidInput)?,
            ),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Read,
            received_at_ms: now_ms,
            deadline_at_ms: now_ms
                .checked_add(timeout_ms)
                .ok_or(RuntimeError::InvalidInput)?,
            response_budget_bytes,
            invocation: None,
        };
        request.request_digest = request.computed_digest()?;
        Ok(Some(Self {
            operation_id,
            request,
            id,
        }))
    }
    pub fn response(&self, status: &OperationStatusView) -> RuntimeResult<Vec<u8>> {
        if status.operation_id != format!("urn:openpc:operation:{}", self.operation_id) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        encode_response(&self.id, status, self.request.response_budget_bytes)
    }
}

pub(crate) fn encode_response(
    id: &Value,
    status: &OperationStatusView,
    budget: u64,
) -> RuntimeResult<Vec<u8>> {
    crate::request_decode::request_id(id)?;
    let bytes = openpc_multi_rpc::rfc8785_canonical_bytes(
        &serde_json::json!({"jsonrpc":"2.0", "id":id, "result":status}),
    )
    .map_err(|_| RuntimeError::ResponseWithheld)?;
    if bytes.len() as u64 > budget || bytes.len() > 8192 {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_form_accepts_only_one_owned_operation_identifier() {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"pc_getOperationStatus","params":["urn:openpc:operation:018f0000-0000-7000-8000-000000000001"]});
        let decode = |v: &Value| {
            OperationStatusRequest::decode(&serde_json::to_vec(v).unwrap(), 4096, 100, 1000, 8192)
        };
        let decoded = decode(&body).unwrap().unwrap();
        assert!(decoded.request.invocation.is_none());
        decoded.request.validate_digest().unwrap();
        let view = OperationStatusView {
            operation_id: format!("urn:openpc:operation:{}", decoded.operation_id),
            signed_transaction_hash: format!("0x{}", "ab".repeat(32)),
            state: "ACCEPTED".into(),
            truth_state: "UNKNOWN".into(),
            attempt_id: "018f0000-0000-7000-8000-000000000002".into(),
            evidence_digest: format!("sha256:{}", "cd".repeat(32)),
        };
        let wire: Value = serde_json::from_slice(&decoded.response(&view).unwrap()).unwrap();
        assert_eq!(wire["id"], 1);
        assert_eq!(
            wire["result"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "attemptId",
                "evidenceDigest",
                "operationId",
                "signedTransactionHash",
                "state",
                "truthState"
            ]
        );
        let mut changed = view;
        changed.operation_id = "urn:openpc:operation:018f0000-0000-7000-8000-000000000003".into();
        assert!(decoded.response(&changed).is_err());
        for params in [
            serde_json::json!([]),
            serde_json::json!(["018f0000-0000-7000-8000-000000000001"]),
            serde_json::json!(["urn:openpc:foreign:018f0000-0000-7000-8000-000000000001"]),
            serde_json::json!([{"operationId":"invalid"}]),
            serde_json::json!([{"operationId":"018f0000-0000-7000-8000-000000000001","includeReceipt":true}]),
        ] {
            let mut altered = body.clone();
            altered["params"] = params;
            assert!(decode(&altered).is_err());
        }
        assert!(decode(&serde_json::json!([body])).is_err());
    }
}
