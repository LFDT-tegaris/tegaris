use std::collections::BTreeSet;

#[cfg(test)]
use pc_provider_api::IdempotencyClass;
use pc_provider_api::{ChainReadAnchorV1, ProviderLimits, ResolutionTruth, RouteRequestV1};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{MultiRpcError, RpcCondition};

mod strict_json;
pub use strict_json::parse_strict_json;

const REQUEST_ID: &str = "openpc-local-eth-getlogs-1";
const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const TOPIC0: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
#[cfg(test)]
const PINNED_BLOCK_HASH: &str =
    "0x3333333333333333333333333333333333333333333333333333333333333333";
const RESPONSE_SCHEMA_DIGEST: &str = "ResponseM10V1";
const NORMALIZATION_RULE_DIGEST: &str = "OPENPC-LOCAL-ETH_GETLOGS-EVENT_LOG-NORM-V1";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportCompletionV1 {
    CompleteNonPartial,
    UnknownCompleteness,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNormalizedResponseV1 {
    bytes: Vec<u8>,
    digest: String,
    truth: ResolutionTruth,
    provider_observed_anchor: Option<ChainReadAnchorV1>,
    records: Vec<CanonicalEthGetLogsRecordV1>,
}

impl LocalNormalizedResponseV1 {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn truth(&self) -> ResolutionTruth {
        self.truth
    }

    pub fn records(&self) -> &[CanonicalEthGetLogsRecordV1] {
        &self.records
    }

    pub(crate) fn provider_observed_anchor(&self) -> Option<&ChainReadAnchorV1> {
        self.provider_observed_anchor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalEthGetLogsRecordV1 {
    address: Vec<u8>,
    topics: Vec<Vec<u8>>,
    data: Vec<u8>,
    block_number: u64,
    transaction_hash: Vec<u8>,
    transaction_index: u64,
    block_hash: Vec<u8>,
    log_index: u64,
    removed: bool,
}

impl CanonicalEthGetLogsRecordV1 {
    fn duplicate_key(&self) -> (&[u8], &[u8], u64) {
        (&self.block_hash, &self.transaction_hash, self.log_index)
    }

    pub fn address(&self) -> &[u8] {
        &self.address
    }
    pub fn topics(&self) -> &[Vec<u8>] {
        &self.topics
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn block_number(&self) -> u64 {
        self.block_number
    }
    pub fn transaction_hash(&self) -> &[u8] {
        &self.transaction_hash
    }
    pub fn transaction_index(&self) -> u64 {
        self.transaction_index
    }
    pub fn block_hash(&self) -> &[u8] {
        &self.block_hash
    }
    pub fn log_index(&self) -> u64 {
        self.log_index
    }
    pub fn removed(&self) -> bool {
        self.removed
    }
}

pub fn validate_local_eth_get_logs_request(
    request: &RouteRequestV1,
    bytes: &[u8],
    limits: &ProviderLimits,
    max_json_depth: u32,
) -> Result<(), MultiRpcError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > limits.max_request_bytes)
        || limits.max_range < 1
        || request.request_id != REQUEST_ID
        || request.method != "eth_getLogs"
        || request.data_class != "EVENT_LOG"
        || request.anchor.block_number.is_none()
        || request.anchor.block_hash.is_none()
    {
        return invalid();
    }
    let value = parse_strict_json(bytes, max_json_depth)?;
    let object = exact_object(&value, &["id", "jsonrpc", "method", "params"])?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || object.get("id") != Some(&Value::String(REQUEST_ID.into()))
        || object.get("method") != Some(&Value::String("eth_getLogs".into()))
    {
        return invalid();
    }
    let params = object
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(invalid_error)?;
    if params.len() != 1 {
        return invalid();
    }
    if normalized_parameter_digest(&Value::Array(params.clone()))?
        != request.normalized_parameter_digest
    {
        return invalid();
    }
    let filter = exact_object(&params[0], &["address", "fromBlock", "toBlock", "topics"])?;
    let pinned_block = format!(
        "0x{:x}",
        request.anchor.block_number.ok_or_else(invalid_error)?
    );
    if filter.get("fromBlock") != Some(&Value::String(pinned_block.clone()))
        || filter.get("toBlock") != Some(&Value::String(pinned_block))
        || filter.get("address") != Some(&Value::String(ADDRESS.into()))
        || filter.get("topics") != Some(&Value::Array(vec![Value::String(TOPIC0.into())]))
    {
        return invalid();
    }
    Ok(())
}

pub fn normalize_local_eth_get_logs(
    bytes: &[u8],
    request: &RouteRequestV1,
    response_schema_digest: &str,
    normalization_rule_digest: &str,
    limits: &ProviderLimits,
    max_json_depth: u32,
    completion: TransportCompletionV1,
) -> Result<LocalNormalizedResponseV1, MultiRpcError> {
    if response_schema_digest != RESPONSE_SCHEMA_DIGEST
        || normalization_rule_digest != NORMALIZATION_RULE_DIGEST
    {
        return Err(condition(RpcCondition::ProfileMismatch));
    }
    if completion == TransportCompletionV1::Partial {
        return Err(condition(RpcCondition::Partial));
    }
    if u64::try_from(bytes.len()).map_or(true, |length| length > limits.max_response_bytes) {
        return invalid();
    }
    let value = parse_strict_json(bytes, max_json_depth)?;
    let object = exact_object(&value, &["id", "jsonrpc", "result"])?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || object.get("id") != Some(&Value::String(request.request_id.clone()))
    {
        return invalid();
    }
    let raw_records = object
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(invalid_error)?;
    if u32::try_from(raw_records.len()).map_or(true, |count| count > limits.max_batch) {
        return invalid();
    }
    if raw_records.is_empty() && completion != TransportCompletionV1::CompleteNonPartial {
        return invalid();
    }
    let mut records = raw_records
        .iter()
        .map(decode_log)
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = BTreeSet::new();
    if records.iter().any(|record| {
        let (block_hash, transaction_hash, log_index) = record.duplicate_key();
        !keys.insert((block_hash.to_vec(), transaction_hash.to_vec(), log_index))
    }) {
        return invalid();
    }
    records.sort_by(|left, right| {
        (
            left.block_number,
            left.transaction_index,
            left.log_index,
            &left.transaction_hash,
            &left.address,
            &left.topics,
            &left.data,
            left.removed,
        )
            .cmp(&(
                right.block_number,
                right.transaction_index,
                right.log_index,
                &right.transaction_hash,
                &right.address,
                &right.topics,
                &right.data,
                right.removed,
            ))
    });
    let provider_observed_anchor = provider_observed_anchor(&records, &request.anchor)?;
    let normalized = encode_records(&records);
    let truth = if records.is_empty() {
        ResolutionTruth::AuthorizedEmpty
    } else {
        ResolutionTruth::Success
    };
    Ok(LocalNormalizedResponseV1 {
        digest: hex_sha256(&normalized),
        bytes: normalized,
        truth,
        provider_observed_anchor,
        records,
    })
}

fn decode_log(value: &Value) -> Result<CanonicalEthGetLogsRecordV1, MultiRpcError> {
    let object = exact_object(
        value,
        &[
            "address",
            "blockHash",
            "blockNumber",
            "data",
            "logIndex",
            "removed",
            "topics",
            "transactionHash",
            "transactionIndex",
        ],
    )?;
    let text = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(invalid_error)
    };
    let address = decode_fixed_hex(text("address")?, 20)?;
    let topics = object
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(invalid_error)?
        .iter()
        .map(|topic| decode_fixed_hex(topic.as_str().ok_or_else(invalid_error)?, 32))
        .collect::<Result<Vec<_>, _>>()?;
    if topics.is_empty() || topics[0] != decode_fixed_hex(TOPIC0, 32)? {
        return invalid();
    }
    let data = decode_fixed_hex(text("data")?, 32)?;
    let block_number = decode_quantity(text("blockNumber")?)?;
    let transaction_hash = decode_fixed_hex(text("transactionHash")?, 32)?;
    let transaction_index = decode_quantity(text("transactionIndex")?)?;
    let block_hash = decode_fixed_hex(text("blockHash")?, 32)?;
    let log_index = decode_quantity(text("logIndex")?)?;
    let removed = object
        .get("removed")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_error)?;
    if removed {
        return invalid();
    }
    Ok(CanonicalEthGetLogsRecordV1 {
        address,
        topics,
        data,
        block_number,
        transaction_hash,
        transaction_index,
        block_hash,
        log_index,
        removed,
    })
}

fn provider_observed_anchor(
    records: &[CanonicalEthGetLogsRecordV1],
    request_anchor: &ChainReadAnchorV1,
) -> Result<Option<ChainReadAnchorV1>, MultiRpcError> {
    let Some(first) = records.first() else {
        return Ok(None);
    };
    if records.iter().any(|record| {
        record.block_number != first.block_number || record.block_hash != first.block_hash
    }) {
        return invalid();
    }
    let observed = ChainReadAnchorV1 {
        chain_id: request_anchor.chain_id.clone(),
        genesis_hash: request_anchor.genesis_hash.clone(),
        network_id: request_anchor.network_id.clone(),
        selector_kind: request_anchor.selector_kind,
        block_number: Some(first.block_number),
        block_hash: Some(format!("0x{}", encode_lower_hex(&first.block_hash))),
        pending_authorized_by_profile: false,
    };
    if &observed != request_anchor {
        return invalid();
    }
    Ok(Some(observed))
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn exact_object<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a Map<String, Value>, MultiRpcError> {
    let object = value.as_object().ok_or_else(invalid_error)?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != names.iter().copied().collect() {
        return invalid();
    }
    Ok(object)
}

fn normalized_parameter_digest(params: &Value) -> Result<String, MultiRpcError> {
    rfc8785_canonical_bytes(params).map(|bytes| hex_sha256(&bytes))
}

/// Derives the parameter identity from the admitted raw JSON-RPC request bytes.
///
/// This is the construction-side owner for `RouteRequestV1.normalized_parameter_digest`; runtime
/// validation independently repeats the derivation before any transport use.
pub(crate) fn derive_normalized_parameter_digest_from_request(
    bytes: &[u8],
    max_json_depth: u32,
) -> Result<String, MultiRpcError> {
    let value = parse_strict_json(bytes, max_json_depth)?;
    let object = exact_object(&value, &["id", "jsonrpc", "method", "params"])?;
    let params = object
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(invalid_error)?;
    normalized_parameter_digest(&Value::Array(params.clone()))
}

/// Canonical JSON for this module's closed RFC 8785 scalar domain.
///
/// Admitted projections contain strings, booleans, arrays, objects and bounded integers. Sorting
/// object member names before serde's scalar rendering is therefore the complete JCS operation
/// required by these contracts.
pub fn rfc8785_canonical_bytes(value: &Value) -> Result<Vec<u8>, MultiRpcError> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            Value::Object(values) => {
                let mut names = values.keys().collect::<Vec<_>>();
                names.sort();
                Value::Object(
                    names
                        .into_iter()
                        .map(|name| (name.clone(), sorted(&values[name])))
                        .collect(),
                )
            }
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).map_err(|_| invalid_error())
}

#[derive(Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct ValidatedM29RequestV1 {
    request_id: Value,
    raw_signed_transaction: String,
}

#[cfg(test)]
impl ValidatedM29RequestV1 {
    pub(crate) fn request_id(&self) -> &Value {
        &self.request_id
    }

    pub(crate) fn raw_signed_transaction(&self) -> &str {
        &self.raw_signed_transaction
    }
}

#[cfg(test)]
pub(crate) fn validate_governed_write_request(
    request: &RouteRequestV1,
    bytes: &[u8],
    limits: &ProviderLimits,
    max_json_depth: u32,
) -> Result<ValidatedM29RequestV1, MultiRpcError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > limits.max_request_bytes)
        || request.method != "eth_sendRawTransaction"
        || request.action_intent != "ACT-RUNTIME_CREATE_SIGNED_SUBMISSION-V1"
        || request.data_class != "WRITE_SUBMISSION"
        || request.idempotency != IdempotencyClass::GovernedWrite
    {
        return invalid();
    }
    let value = parse_strict_json(bytes, max_json_depth)?;
    let object = exact_object(&value, &["id", "jsonrpc", "method", "params"])?;
    let request_id = object.get("id").ok_or_else(invalid_error)?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || request_id != &Value::String(request.request_id.clone())
        || !valid_json_rpc_id(request_id)
        || object.get("method") != Some(&Value::String(request.method.clone()))
    {
        return invalid();
    }
    let params = object
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(invalid_error)?;
    let raw_transaction = match params.as_slice() {
        [Value::String(value)] => value,
        _ => return invalid(),
    };
    let digits = raw_transaction
        .strip_prefix("0x")
        .ok_or_else(invalid_error)?;
    if !digits.len().is_multiple_of(2)
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || normalized_parameter_digest(&Value::Array(params.clone()))?
            != request.normalized_parameter_digest
    {
        return invalid();
    }
    Ok(ValidatedM29RequestV1 {
        request_id: request_id.clone(),
        raw_signed_transaction: raw_transaction.clone(),
    })
}

#[derive(Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum ValidatedM29ResponseV1 {
    TransactionHash(String),
    OperationStatus { signed_transaction_hash: String },
    Error,
}

#[cfg(test)]
pub(crate) fn validate_governed_write_response(
    request_id: &Value,
    expected_signed_transaction_hash: &str,
    bytes: &[u8],
    limits: &ProviderLimits,
    max_json_depth: u32,
) -> Result<ValidatedM29ResponseV1, MultiRpcError> {
    if !valid_transaction_hash(expected_signed_transaction_hash)
        || u64::try_from(bytes.len()).map_or(true, |length| length > limits.max_response_bytes)
    {
        return invalid();
    }
    let value = parse_strict_json(bytes, max_json_depth)?;
    let object = value.as_object().ok_or_else(invalid_error)?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".into()))
        || object.get("id") != Some(request_id)
        || !valid_json_rpc_id(request_id)
    {
        return invalid();
    }
    match (object.get("result"), object.get("error")) {
        (Some(Value::String(hash)), None)
            if object.len() == 3 && hash == expected_signed_transaction_hash =>
        {
            Ok(ValidatedM29ResponseV1::TransactionHash(hash.clone()))
        }
        (Some(Value::Object(status)), None) if object.len() == 3 => {
            let actual = status.keys().map(String::as_str).collect::<BTreeSet<_>>();
            let expected = [
                "attemptId",
                "evidenceDigest",
                "operationId",
                "signedTransactionHash",
                "state",
                "truthState",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if actual != expected {
                return invalid();
            }
            let signed_transaction_hash = status
                .get("signedTransactionHash")
                .and_then(Value::as_str)
                .filter(|value| *value == expected_signed_transaction_hash)
                .ok_or_else(invalid_error)?;
            if !status
                .get("attemptId")
                .and_then(Value::as_str)
                .is_some_and(valid_uuid_v7)
                || !status
                    .get("evidenceDigest")
                    .and_then(Value::as_str)
                    .is_some_and(valid_sha256_digest)
                || !status
                    .get("operationId")
                    .and_then(Value::as_str)
                    .is_some_and(valid_openpc_urn)
                || !status
                    .get("state")
                    .and_then(Value::as_str)
                    .is_some_and(|state| {
                        matches!(
                            state,
                            "PREPARED"
                                | "ATTEMPT_STARTED"
                                | "ACCEPTED"
                                | "REJECTED"
                                | "WRITE_AMBIGUITY"
                                | "CONFIRMED"
                                | "REORG"
                                | "FAILED"
                        )
                    })
                || !status
                    .get("truthState")
                    .and_then(Value::as_str)
                    .is_some_and(valid_truth_state)
            {
                return invalid();
            }
            Ok(ValidatedM29ResponseV1::OperationStatus {
                signed_transaction_hash: signed_transaction_hash.to_owned(),
            })
        }
        (None, Some(Value::Object(error))) if object.len() == 3 => {
            let names = error.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if names != ["code", "data", "message"].into_iter().collect() {
                return invalid();
            }
            if !error
                .get("code")
                .and_then(Value::as_i64)
                .is_some_and(|code| (-32_768..=-32_000).contains(&code))
                || !error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|message| !message.is_empty() && message.chars().count() <= 160)
                || !error.get("data").is_some_and(|value| {
                    valid_safe_error_data(value, expected_signed_transaction_hash)
                })
            {
                return invalid();
            }
            Ok(ValidatedM29ResponseV1::Error)
        }
        _ => invalid(),
    }
}

#[cfg(test)]
fn valid_transaction_hash(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|digits| {
        digits.len() == 64
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
fn valid_json_rpc_id(value: &Value) -> bool {
    value.as_u64().is_some_and(|id| id <= 9_007_199_254_740_991)
        || value
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.chars().count() <= 128)
}

#[cfg(test)]
fn valid_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

#[cfg(test)]
fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
fn valid_openpc_urn(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("urn:openpc:") else {
        return false;
    };
    let Some((kind, id)) = remainder.rsplit_once(':') else {
        return false;
    };
    (1..=63).contains(&kind.len())
        && kind
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && valid_uuid_v7(id)
}

#[cfg(test)]
fn valid_truth_state(value: &str) -> bool {
    matches!(
        value,
        "SUCCESS"
            | "AUTHORIZED_EMPTY"
            | "DENIED"
            | "LOADING"
            | "UNKNOWN"
            | "UNAVAILABLE"
            | "STALE"
            | "REORG"
            | "PARTIAL"
            | "CONFLICTING"
            | "DEGRADED"
            | "FAILED"
            | "RETRY_ELIGIBLE"
            | "FAILOVER_ELIGIBLE"
            | "WRITE_AMBIGUITY"
            | "RECOVERY"
            | "ROLLBACK"
            | "RETIREMENT"
            | "UNINSTALL"
            | "DECOMMISSION"
    )
}

#[cfg(test)]
fn valid_safe_error_data(value: &Value, expected_signed_transaction_hash: &str) -> bool {
    let Some(data) = value.as_object() else {
        return false;
    };
    if data.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != [
            "attemptId",
            "pcCode",
            "retryable",
            "signedTransactionHash",
            "traceId",
            "truthState",
        ]
        .into_iter()
        .collect()
    {
        return false;
    }
    data.get("attemptId")
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(valid_uuid_v7))
        && data.get("signedTransactionHash").is_some_and(|value| {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|hash| hash == expected_signed_transaction_hash)
        })
        && data
            .get("traceId")
            .and_then(Value::as_str)
            .is_some_and(valid_uuid_v7)
        && data
            .get("pcCode")
            .and_then(Value::as_str)
            .is_some_and(valid_pc_code)
        && data.get("retryable").is_some_and(Value::is_boolean)
        && data
            .get("truthState")
            .and_then(Value::as_str)
            .is_some_and(valid_truth_state)
}

#[cfg(test)]
fn valid_pc_code(value: &str) -> bool {
    let Some((family, code)) = value
        .strip_prefix("PC-")
        .and_then(|rest| rest.rsplit_once('-'))
    else {
        return false;
    };
    (2..=16).contains(&family.len())
        && family
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && code.len() == 4
        && code.bytes().all(|byte| byte.is_ascii_digit())
}

fn decode_quantity(value: &str) -> Result<u64, MultiRpcError> {
    let digits = value.strip_prefix("0x").ok_or_else(invalid_error)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid();
    }
    u64::from_str_radix(digits, 16).map_err(|_| invalid_error())
}

fn decode_fixed_hex(value: &str, byte_len: usize) -> Result<Vec<u8>, MultiRpcError> {
    let digits = value.strip_prefix("0x").ok_or_else(invalid_error)?;
    if digits.len() != byte_len * 2
        || !digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid();
    }
    digits
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid_error())?;
            u8::from_str_radix(text, 16).map_err(|_| invalid_error())
        })
        .collect()
}

fn encode_records(records: &[CanonicalEthGetLogsRecordV1]) -> Vec<u8> {
    let mut out = vec![0xa1, 0x00];
    encode_len(&mut out, 4, records.len() as u64);
    for record in records {
        encode_len(&mut out, 5, 9);
        for (key, value) in [
            (0_u64, CborValue::Bytes(&record.address)),
            (1, CborValue::ByteArrays(&record.topics)),
            (2, CborValue::Bytes(&record.data)),
            (3, CborValue::Unsigned(record.block_number)),
            (4, CborValue::Bytes(&record.transaction_hash)),
            (5, CborValue::Unsigned(record.transaction_index)),
            (6, CborValue::Bytes(&record.block_hash)),
            (7, CborValue::Unsigned(record.log_index)),
            (8, CborValue::Bool(record.removed)),
        ] {
            encode_len(&mut out, 0, key);
            value.encode(&mut out);
        }
    }
    out
}

enum CborValue<'a> {
    Bytes(&'a [u8]),
    ByteArrays(&'a [Vec<u8>]),
    Unsigned(u64),
    Bool(bool),
}
impl CborValue<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Bytes(bytes) => {
                encode_len(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Self::ByteArrays(values) => {
                encode_len(out, 4, values.len() as u64);
                for bytes in *values {
                    encode_len(out, 2, bytes.len() as u64);
                    out.extend_from_slice(bytes);
                }
            }
            Self::Unsigned(value) => encode_len(out, 0, *value),
            Self::Bool(value) => out.push(if *value { 0xf5 } else { 0xf4 }),
        }
    }
}

fn encode_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    out
}
fn condition(value: RpcCondition) -> MultiRpcError {
    MultiRpcError::condition(value)
}
fn invalid_error() -> MultiRpcError {
    condition(RpcCondition::InvalidResponse)
}
fn invalid<T>() -> Result<T, MultiRpcError> {
    Err(invalid_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_provider_api::{BlockSelectorKind, IdempotencyClass};
    use serde_json::json;

    const TEST_MAX_JSON_DEPTH: u32 = 8;
    const READ_REQUEST: &[u8] = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#;

    fn limits() -> ProviderLimits {
        ProviderLimits {
            max_request_bytes: 1_024,
            max_response_bytes: 2_048,
            max_range: 1,
            max_batch: 2,
        }
    }

    fn request() -> RouteRequestV1 {
        RouteRequestV1 {
            request_id: REQUEST_ID.into(),
            authority_context_digest: "authority".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            workload_binding: "workload".into(),
            action_intent: "read".into(),
            method: "eth_getLogs".into(),
            data_class: "EVENT_LOG".into(),
            normalized_parameter_digest: derive_normalized_parameter_digest_from_request(
                READ_REQUEST,
                TEST_MAX_JSON_DEPTH,
            )
            .expect("actual request parameter digest"),
            anchor: ChainReadAnchorV1 {
                chain_id: "1".into(),
                genesis_hash: "11".repeat(32),
                network_id: "openpc-local".into(),
                selector_kind: BlockSelectorKind::Pinned,
                block_number: Some(16),
                block_hash: Some(PINNED_BLOCK_HASH.into()),
                pending_authorized_by_profile: false,
            },
            required_capability_profile_digest: "capability".into(),
            maximum_response_classification: "participant-confidential".into(),
            idempotency: IdempotencyClass::IdempotentRead,
            request_deadline_millis: 1_000,
            evidence_correlation_id: "correlation".into(),
        }
    }

    fn record(transaction: u8, transaction_index: u64, log_index: u64, data: u8) -> Value {
        json!({
            "address": ADDRESS,
            "blockHash": PINNED_BLOCK_HASH,
            "blockNumber": "0x10",
            "data": format!("0x{}", format!("{data:02x}").repeat(32)),
            "logIndex": format!("0x{log_index:x}"),
            "removed": false,
            "topics": [TOPIC0],
            "transactionHash": format!("0x{}", format!("{transaction:02x}").repeat(32)),
            "transactionIndex": format!("0x{transaction_index:x}")
        })
    }

    fn response(records: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"id": REQUEST_ID, "jsonrpc": "2.0", "result": records}))
            .expect("fixture JSON")
    }

    #[test]
    fn local_eth_getlogs_request_and_exact_positive_empty_vectors() {
        assert!(
            validate_local_eth_get_logs_request(
                &request(),
                READ_REQUEST,
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .is_ok()
        );
        let empty = normalize_local_eth_get_logs(
            &response(vec![]),
            &request(),
            RESPONSE_SCHEMA_DIGEST,
            NORMALIZATION_RULE_DIGEST,
            &limits(),
            TEST_MAX_JSON_DEPTH,
            TransportCompletionV1::CompleteNonPartial,
        )
        .expect("authorized empty");
        assert_eq!(empty.bytes(), &[0xa1, 0x00, 0x80]);
        assert_eq!(empty.truth(), ResolutionTruth::AuthorizedEmpty);
        assert_eq!(empty.digest(), hex_sha256(&[0xa1, 0x00, 0x80]));
        assert_eq!(empty.provider_observed_anchor(), None);
    }

    #[test]
    fn local_eth_getlogs_exact_pc_cbor_vector() {
        let normalized = normalize_local_eth_get_logs(
            &response(vec![record(0x55, 0, 0, 0x44)]),
            &request(),
            RESPONSE_SCHEMA_DIGEST,
            NORMALIZATION_RULE_DIGEST,
            &limits(),
            TEST_MAX_JSON_DEPTH,
            TransportCompletionV1::CompleteNonPartial,
        )
        .expect("positive record");
        let mut expected = vec![0xa1, 0x00, 0x81, 0xa9, 0x00, 0x54];
        expected.extend_from_slice(&[0x11; 20]);
        expected.extend_from_slice(&[0x01, 0x81, 0x58, 0x20]);
        expected.extend_from_slice(&decode_fixed_hex(TOPIC0, 32).expect("topic"));
        expected.extend_from_slice(&[0x02, 0x58, 0x20]);
        expected.extend_from_slice(&[0x44; 32]);
        expected.extend_from_slice(&[0x03, 0x10, 0x04, 0x58, 0x20]);
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(&[0x05, 0x00, 0x06, 0x58, 0x20]);
        expected.extend_from_slice(&[0x33; 32]);
        expected.extend_from_slice(&[0x07, 0x00, 0x08, 0xf4]);
        assert_eq!(normalized.bytes(), expected);
        assert_eq!(normalized.digest(), hex_sha256(&expected));
        assert_eq!(normalized.truth(), ResolutionTruth::Success);
        assert_eq!(
            normalized.provider_observed_anchor(),
            Some(&request().anchor)
        );
    }

    #[test]
    fn local_eth_getlogs_permutation_and_duplicate_closure() {
        let first = record(0x55, 0, 0, 0x44);
        let second = record(0x66, 1, 1, 0x77);
        let left = normalize_local_eth_get_logs(
            &response(vec![second.clone(), first.clone()]),
            &request(),
            RESPONSE_SCHEMA_DIGEST,
            NORMALIZATION_RULE_DIGEST,
            &limits(),
            TEST_MAX_JSON_DEPTH,
            TransportCompletionV1::CompleteNonPartial,
        )
        .expect("permuted response");
        let right = normalize_local_eth_get_logs(
            &response(vec![first.clone(), second]),
            &request(),
            RESPONSE_SCHEMA_DIGEST,
            NORMALIZATION_RULE_DIGEST,
            &limits(),
            TEST_MAX_JSON_DEPTH,
            TransportCompletionV1::CompleteNonPartial,
        )
        .expect("ordered response");
        assert_eq!(left, right);
        assert!(
            normalize_local_eth_get_logs(
                &response(vec![first.clone(), first]),
                &request(),
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
                &limits(),
                TEST_MAX_JSON_DEPTH,
                TransportCompletionV1::CompleteNonPartial,
            )
            .is_err()
        );

        let mut mixed = record(0x66, 1, 1, 0x77);
        mixed["blockHash"] = Value::String(format!("0x{}", "44".repeat(32)));
        assert!(
            normalize_local_eth_get_logs(
                &response(vec![record(0x55, 0, 0, 0x44), mixed]),
                &request(),
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
                &limits(),
                TEST_MAX_JSON_DEPTH,
                TransportCompletionV1::CompleteNonPartial,
            )
            .is_err()
        );

        let mut wrong_request = request();
        wrong_request.anchor.block_hash = Some(format!("0x{}", "44".repeat(32)));
        assert!(
            normalize_local_eth_get_logs(
                &response(vec![record(0x55, 0, 0, 0x44)]),
                &wrong_request,
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
                &limits(),
                TEST_MAX_JSON_DEPTH,
                TransportCompletionV1::CompleteNonPartial,
            )
            .is_err()
        );
    }

    #[test]
    fn local_eth_getlogs_complete_negative_corpus() {
        let mut unknown = json!({"id": REQUEST_ID, "jsonrpc": "2.0", "result": [], "extra": true});
        assert!(
            normalize_local_eth_get_logs(
                &serde_json::to_vec(&unknown).expect("JSON"),
                &request(),
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
                &limits(),
                TEST_MAX_JSON_DEPTH,
                TransportCompletionV1::CompleteNonPartial,
            )
            .is_err()
        );
        unknown["extra"] = Value::Null;
        let mut removed = record(0x55, 0, 0, 0x44);
        removed["removed"] = Value::Bool(true);
        for (bytes, completion, schema, normalization) in [
            (
                response(vec![]),
                TransportCompletionV1::UnknownCompleteness,
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
            ),
            (
                response(vec![removed]),
                TransportCompletionV1::CompleteNonPartial,
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
            ),
            (
                response(vec![record(0x55, 0, 0, 0x44)]),
                TransportCompletionV1::Partial,
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
            ),
            (
                response(vec![record(0x55, 0, 0, 0x44)]),
                TransportCompletionV1::CompleteNonPartial,
                "wrong",
                NORMALIZATION_RULE_DIGEST,
            ),
            (
                response(vec![record(0x55, 0, 0, 0x44)]),
                TransportCompletionV1::CompleteNonPartial,
                RESPONSE_SCHEMA_DIGEST,
                "wrong",
            ),
        ] {
            assert!(
                normalize_local_eth_get_logs(
                    &bytes,
                    &request(),
                    schema,
                    normalization,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                    completion,
                )
                .is_err()
            );
        }

        for duplicate_request in [
            br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_sendRawTransaction","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#.as_slice(),
            br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[],"params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#.as_slice(),
            br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x2222222222222222222222222222222222222222","address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#.as_slice(),
        ] {
            assert!(
                validate_local_eth_get_logs_request(
                    &request(),
                    duplicate_request,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                )
                .is_err()
            );
        }

        let mut wrong_parameter_digest = request();
        wrong_parameter_digest.normalized_parameter_digest = "00".repeat(32);
        let request_bytes = br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","method":"eth_getLogs","params":[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0x10","toBlock":"0x10","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}"#;
        assert!(
            validate_local_eth_get_logs_request(
                &wrong_parameter_digest,
                request_bytes,
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .is_err()
        );
        assert!(
            validate_local_eth_get_logs_request(
                &request(),
                request_bytes,
                &ProviderLimits {
                    max_request_bytes: u64::try_from(request_bytes.len() - 1)
                        .expect("bounded fixture"),
                    ..limits()
                },
                TEST_MAX_JSON_DEPTH,
            )
            .is_err()
        );
        assert!(
            normalize_local_eth_get_logs(
                &response(vec![record(0x55, 0, 0, 0x44), record(0x66, 1, 1, 0x77)]),
                &request(),
                RESPONSE_SCHEMA_DIGEST,
                NORMALIZATION_RULE_DIGEST,
                &ProviderLimits {
                    max_batch: 1,
                    ..limits()
                },
                TEST_MAX_JSON_DEPTH,
                TransportCompletionV1::CompleteNonPartial,
            )
            .is_err()
        );

        for duplicate_response in [
            br#"{"id":"wrong","id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[]}"#.as_slice(),
            br#"{"id":"openpc-local-eth-getlogs-1","jsonrpc":"2.0","result":[{"address":"0x1111111111111111111111111111111111111111","blockHash":"0x3333333333333333333333333333333333333333333333333333333333333333","blockNumber":"0xf","blockNumber":"0x10","data":"0x4444444444444444444444444444444444444444444444444444444444444444","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x5555555555555555555555555555555555555555555555555555555555555555","transactionIndex":"0x0"}]}"#.as_slice(),
        ] {
            assert!(
                normalize_local_eth_get_logs(
                    duplicate_response,
                    &request(),
                    RESPONSE_SCHEMA_DIGEST,
                    NORMALIZATION_RULE_DIGEST,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                    TransportCompletionV1::CompleteNonPartial,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn governed_write_bytes_own_raw_transaction_without_inventing_its_hash() {
        let bytes = br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x010203"]}"#;
        let mut governed = request();
        governed.request_id = "request".into();
        governed.action_intent = "ACT-RUNTIME_CREATE_SIGNED_SUBMISSION-V1".into();
        governed.method = "eth_sendRawTransaction".into();
        governed.data_class = "WRITE_SUBMISSION".into();
        governed.normalized_parameter_digest =
            derive_normalized_parameter_digest_from_request(bytes, TEST_MAX_JSON_DEPTH)
                .expect("actual governed request parameter digest");
        governed.idempotency = IdempotencyClass::GovernedWrite;
        let validated =
            validate_governed_write_request(&governed, bytes, &limits(), TEST_MAX_JSON_DEPTH)
                .expect("closed governed request");
        assert_eq!(validated.raw_signed_transaction(), "0x010203");
        assert_eq!(validated.request_id(), &Value::String("request".into()));
        let mut schema_minimum = governed.clone();
        schema_minimum.normalized_parameter_digest =
            normalized_parameter_digest(&serde_json::json!(["0x"])).expect("parameter digest");
        assert_eq!(
            validate_governed_write_request(
                &schema_minimum,
                br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x"]}"#,
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .expect("the schema permits an empty byte string")
            .raw_signed_transaction(),
            "0x"
        );
        let spaced = br#"{ "params" : ["0x010203"], "method" : "eth_sendRawTransaction", "jsonrpc" : "2.0", "id" : "request" }"#;
        assert_eq!(
            validate_governed_write_request(&governed, spaced, &limits(), TEST_MAX_JSON_DEPTH)
                .expect("legal noncanonical spelling")
                .raw_signed_transaction(),
            "0x010203"
        );

        for invalid_bytes in [
            br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x010203"],"params":["0x040506"]}"#.as_slice(),
            br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xABCDEF"]}"#.as_slice(),
            br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x1"]}"#.as_slice(),
            br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":[]}"#.as_slice(),
            br#"{"id":"request","jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x010203"],"extra":true}"#.as_slice(),
        ] {
            assert!(
                validate_governed_write_request(
                    &governed,
                    invalid_bytes,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                )
                .is_err()
            );
        }
        let mut wrong_digest = governed.clone();
        wrong_digest.normalized_parameter_digest = "00".repeat(32);
        assert!(
            validate_governed_write_request(&wrong_digest, bytes, &limits(), TEST_MAX_JSON_DEPTH,)
                .is_err()
        );
        assert!(
            validate_governed_write_request(
                &governed,
                bytes,
                &ProviderLimits {
                    max_request_bytes: u64::try_from(bytes.len() - 1).expect("bounded fixture"),
                    ..limits()
                },
                TEST_MAX_JSON_DEPTH,
            )
            .is_err()
        );
        for wrong_binding in [
            {
                let mut value = governed.clone();
                value.action_intent = "ACT-RUNTIME_READ".into();
                value
            },
            {
                let mut value = governed.clone();
                value.data_class = "EVENT_LOG".into();
                value
            },
            {
                let mut value = governed.clone();
                value.idempotency = IdempotencyClass::IdempotentRead;
                value
            },
        ] {
            assert!(
                validate_governed_write_request(
                    &wrong_binding,
                    bytes,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn governed_write_response_is_duplicate_free_id_bound_and_hash_exact() {
        let request_id = Value::String("request".into());
        let hash = format!("0x{}", "11".repeat(32));
        let result = format!(r#"{{"jsonrpc":"2.0","id":"request","result":"{hash}"}}"#);
        assert_eq!(
            validate_governed_write_response(
                &request_id,
                &hash,
                result.as_bytes(),
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .expect("transaction result"),
            ValidatedM29ResponseV1::TransactionHash(hash.clone())
        );
        let status = format!(
            r#"{{"jsonrpc":"2.0","id":"request","result":{{"operationId":"urn:openpc:operation:018f47a5-4a58-7b21-8f3a-111111111111","signedTransactionHash":"{hash}","state":"PREPARED","truthState":"UNKNOWN","attemptId":"018f47a5-4a58-7b21-8f3a-222222222222","evidenceDigest":"sha256:{}"}}}}"#,
            "22".repeat(32)
        );
        assert_eq!(
            validate_governed_write_response(
                &request_id,
                &hash,
                status.as_bytes(),
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .expect("operation status"),
            ValidatedM29ResponseV1::OperationStatus {
                signed_transaction_hash: hash.clone(),
            }
        );
        let error = br#"{"jsonrpc":"2.0","id":"request","error":{"code":-32000,"message":"not qualified","data":{"pcCode":"PC-RUNTIME-3005","truthState":"UNAVAILABLE","traceId":"018f47a5-4a58-7b21-8f3a-333333333333","retryable":false,"attemptId":null,"signedTransactionHash":null}}}"#;
        assert_eq!(
            validate_governed_write_response(
                &request_id,
                &hash,
                error,
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .expect("governed error"),
            ValidatedM29ResponseV1::Error
        );
        for invalid in [
            br#"{"jsonrpc":"2.0","id":"request","id":"other","result":"0x1111111111111111111111111111111111111111111111111111111111111111"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"other","result":"0x1111111111111111111111111111111111111111111111111111111111111111"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","result":"0x1111111111111111111111111111111111111111111111111111111111111111","error":{"code":-1,"message":"both"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","result":"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","result":{"operationId":"urn:openpc:operation:018f47a5-4a58-7b21-8f3a-111111111111","signedTransactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111","state":"PREPARED","state":"ACCEPTED","truthState":"UNKNOWN","attemptId":"018f47a5-4a58-7b21-8f3a-222222222222","evidenceDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","result":{"operationId":"urn:openpc:operation:018f47a5-4a58-7b21-8f3a-111111111111","signedTransactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111","state":"CALLER_STATE","truthState":"UNKNOWN","attemptId":"018f47a5-4a58-7b21-8f3a-222222222222","evidenceDigest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","error":{"code":-32000,"message":"missing governed data"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":"request","error":{"code":-32000,"message":"duplicate nested data","data":{"pcCode":"PC-RUNTIME-3005","truthState":"UNAVAILABLE","truthState":"FAILED","traceId":"018f47a5-4a58-7b21-8f3a-333333333333","retryable":false,"attemptId":null,"signedTransactionHash":null}}}"#.as_slice(),
        ] {
            assert!(
                validate_governed_write_response(
                    &request_id,
                    &hash,
                    invalid,
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                )
                .is_err()
            );
        }

        let other_hash = format!("0x{}", "22".repeat(32));
        let mismatched_result =
            format!(r#"{{"jsonrpc":"2.0","id":"request","result":"{other_hash}"}}"#);
        let mismatched_status = status.replace(&hash, &other_hash);
        let mismatched_error = format!(
            r#"{{"jsonrpc":"2.0","id":"request","error":{{"code":-32000,"message":"not qualified","data":{{"pcCode":"PC-RUNTIME-3005","truthState":"UNAVAILABLE","traceId":"018f47a5-4a58-7b21-8f3a-333333333333","retryable":false,"attemptId":null,"signedTransactionHash":"{other_hash}"}}}}}}"#
        );
        for mismatched in [mismatched_result, mismatched_status, mismatched_error] {
            assert!(
                validate_governed_write_response(
                    &request_id,
                    &hash,
                    mismatched.as_bytes(),
                    &limits(),
                    TEST_MAX_JSON_DEPTH,
                )
                .is_err()
            );
        }
        assert!(
            validate_governed_write_response(
                &request_id,
                "not-an-authenticated-transaction-hash",
                result.as_bytes(),
                &limits(),
                TEST_MAX_JSON_DEPTH,
            )
            .is_err()
        );
    }
}
