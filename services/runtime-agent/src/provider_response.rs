//! Policy-controlled release for the M20/M21 `eth_call` success schema.
//! Provider errors require a separate safe error projection and are withheld;
//! raw provider bytes never become a successful Broker response.
use pc_runtime_types::{Digest, RequestClass, RuntimeError, RuntimeRequest, RuntimeResult};
use serde::Serialize;
use serde_json::Value;

const JSONRPC_RESPONSE_SCHEMA_SHA256: &str =
    "20aaa63d00ada53380a4a64ac15bae6ee849148d6d7a7386a4f2fb6cff43c3c1";
const METHOD_PROFILE_REGISTRY_SHA256: &str =
    "619eba3715fdd2bfec698c78a2e823747a18257652ae5ceecec67ace22d8e2e5";

pub fn call_result_disclosure_policy_digest() -> Digest {
    Digest::parse(METHOD_PROFILE_REGISTRY_SHA256)
        .expect("method-profile registry digest is static and valid")
}

pub fn call_result_response_schema_digest() -> String {
    format!("sha256:{JSONRPC_RESPONSE_SCHEMA_SHA256}")
}

pub fn call_result_normalization_rule_digest() -> String {
    format!("sha256:{METHOD_PROFILE_REGISTRY_SHA256}")
}

#[derive(Serialize)]
struct ReleasedCallResult<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    result: &'a str,
}

pub(crate) fn filter_call_success(
    request: &RuntimeRequest,
    body: &[u8],
    disclosure_policy_digest: &Digest,
    response_schema_digest: &str,
    normalization_rule_digest: &str,
) -> RuntimeResult<Vec<u8>> {
    let reject = || RuntimeError::ResponseWithheld;
    if request.method != "eth_call"
        || request.class != RequestClass::Read
        || disclosure_policy_digest != &call_result_disclosure_policy_digest()
        || response_schema_digest != call_result_response_schema_digest()
        || normalization_rule_digest != call_result_normalization_rule_digest()
        || body.is_empty()
        || body.len() as u64 > request.response_budget_bytes
    {
        return Err(reject());
    }
    let value = openpc_multi_rpc::parse_strict_json(body, 8).map_err(|_| reject())?;
    let object = value.as_object().ok_or_else(reject)?;
    if object.len() != 3
        || !["jsonrpc", "id", "result"]
            .iter()
            .all(|key| object.contains_key(*key))
        || object.get("jsonrpc") != Some(&Value::String("2.0".into()))
    {
        return Err(reject());
    }
    if crate::request_decode::request_id(&object["id"]).map_err(|_| reject())? != request.request_id
    {
        return Err(reject());
    }
    let result = object["result"].as_str().ok_or_else(reject)?;
    let digits = result.strip_prefix("0x").ok_or_else(reject)?;
    if !digits.len().is_multiple_of(2)
        || !digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(reject());
    }
    let released = serde_json::to_vec(&ReleasedCallResult {
        jsonrpc: "2.0",
        id: &object["id"],
        result,
    })
    .map_err(|_| reject())?;
    if released.len() as u64 > request.response_budget_bytes {
        return Err(reject());
    }
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_runtime_types::{Digest, Transport};

    fn filter(request: &RuntimeRequest, body: &[u8]) -> RuntimeResult<Vec<u8>> {
        filter_call_success(
            request,
            body,
            &call_result_disclosure_policy_digest(),
            &call_result_response_schema_digest(),
            &call_result_normalization_rule_digest(),
        )
    }

    #[test]
    fn duplicate_misbound_unknown_malformed_and_provider_errors_are_withheld() {
        let request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "1".into(),
            method: "eth_call".into(),
            params_digest: Digest::of(b"params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of(b"request"),
            class: RequestClass::Read,
            received_at_ms: 1,
            deadline_at_ms: 2,
            response_budget_bytes: 1024,
            invocation: None,
        };
        for valid in [
            r#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#,
        ] {
            assert!(filter(&request, valid.as_bytes()).is_ok());
        }
        for invalid in [
            r#"{"jsonrpc":"2.0","id":"1","result":"0x1234"}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":"0x1234"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234","result":"0x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234","provider":"private"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0xAB"}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"private provider details"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234","error":{}}"#,
        ] {
            assert_eq!(
                filter(&request, invalid.as_bytes()),
                Err(RuntimeError::ResponseWithheld)
            );
        }
        let mut tiny = request;
        tiny.response_budget_bytes = 1;
        assert!(filter(&tiny, br#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#).is_err());
    }

    #[test]
    fn release_requires_exact_policy_schema_and_normalization_and_is_canonical() {
        let request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "1".into(),
            method: "eth_call".into(),
            params_digest: Digest::of(b"params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of(b"request"),
            class: RequestClass::Read,
            received_at_ms: 1,
            deadline_at_ms: 2,
            response_budget_bytes: 1024,
            invocation: None,
        };
        let raw = b"{ \"result\" : \"0x1234\", \"id\" : 1, \"jsonrpc\" : \"2.0\" }";
        assert_eq!(
            filter(&request, raw).unwrap(),
            br#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#
        );
        for changed in 0..3 {
            let disclosure = if changed == 0 {
                Digest::of(b"other")
            } else {
                call_result_disclosure_policy_digest()
            };
            let schema = if changed == 1 {
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
            } else {
                call_result_response_schema_digest()
            };
            let normalization = if changed == 2 {
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned()
            } else {
                call_result_normalization_rule_digest()
            };
            assert_eq!(
                filter_call_success(&request, raw, &disclosure, &schema, &normalization),
                Err(RuntimeError::ResponseWithheld)
            );
        }
    }
}
