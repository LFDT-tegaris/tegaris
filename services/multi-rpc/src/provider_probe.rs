//! Live HASH_PINNED eth_call evidence over the actual prepared authenticated TLS path.
//! MRPC-CONTRACT-002 requires independent review and signed publication before
//! ACTIVE certification. A successful probe alone never grants that state.
use crate::{
    normalization::parse_strict_json,
    provider_connection::{ConnectionLease, ConnectionRecord, ConnectionRegistry},
};
use pc_runtime_types::Digest;
use serde::Serialize;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{Instant, sleep_until};

/// Resolved from the approved method-specific certification corpus. The corpus
/// owns known/unknown/noncanonical blocks and the expected response identity.
#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HashPinnedCallProbePlan {
    pub corpus_digest: Digest,
    pub chain_id: u64,
    pub genesis_hash: Digest,
    pub block_hash: Digest,
    pub block_number: u64,
    pub state_root: Digest,
    pub unknown_block_hash: Digest,
    /// None is admitted only by the exact-source bounded-QA deployment owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noncanonical_block_hash: Option<Digest>,
    pub sender: [u8; 20],
    pub target: [u8; 20],
    pub calldata: Vec<u8>,
    pub expected_result_digest: Digest,
    pub expected_client_version_digest: Digest,
    pub unknown_hash_error_code: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noncanonical_hash_error_code: Option<i64>,
    pub repeat_window: Duration,
    pub per_request_timeout: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_header: Option<BlockHeaderProbePlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log: Option<EventLogProbePlan>,
}

#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogProbePlan {
    pub event_signature: Digest,
    pub expected_logs_digest: Digest,
}

/// Additional method-specific corpus; old state-only receipts cannot certify it.
#[derive(Clone, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeaderProbePlan {
    pub expected_header_digest: Digest,
    pub unknown_block_number: u64,
    #[serde(default, skip_serializing_if = "MissingHeaderResponse::is_default")]
    pub unknown_block_response: MissingHeaderResponse,
}

/// The corpus chooses one missing-header response. Other failures cannot certify it.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, Serialize)]
pub enum MissingHeaderResponse {
    #[default]
    Null,
    UnfinalizedDataRejected,
}

impl MissingHeaderResponse {
    fn is_default(&self) -> bool {
        matches!(self, Self::Null)
    }

    fn validate(self, value: &Value) -> Result<(), ProbeError> {
        match self {
            Self::Null if result(value)?.is_null() => Ok(()),
            Self::UnfinalizedDataRejected => {
                error_code(value, -32000)?;
                if value["error"]["message"] == "cannot query unfinalized data" {
                    Ok(())
                } else {
                    Err(ProbeError::Exactness)
                }
            }
            Self::Null => Err(ProbeError::Exactness),
        }
    }
}
impl HashPinnedCallProbePlan {
    pub fn content_digest(&self) -> Result<Digest, ProbeError> {
        serde_json::to_vec(self)
            .map(Digest::of)
            .map_err(|_| ProbeError::Profile)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProbeError {
    #[error("provider probe profile rejected")]
    Profile,
    #[error("provider probe transport unavailable")]
    Transport,
    #[error("provider chain identity mismatch")]
    Chain,
    #[error("provider method exactness rejected")]
    Exactness,
    #[error("provider behavior drift detected")]
    Drift,
    #[error("provider probe deadline exhausted")]
    Deadline,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeExchange {
    request_digest: Digest,
    response_digest: Digest,
}
/// A non-deserializable observation produced only after actual protocol checks.
/// It contains no raw result, calldata, sender, URL, certificate or credential.
#[derive(Clone, Debug, Serialize)]
pub struct HashPinnedCallObservation {
    connection: ConnectionRecord,
    corpus_digest: Digest,
    plan_digest: Digest,
    started_at_ms: u64,
    completed_at_ms: u64,
    exchanges: Vec<ProbeExchange>,
    admission_scope: &'static str,
    historical_reorg_conformance: &'static str,
}
impl HashPinnedCallObservation {
    pub fn connection(&self) -> &ConnectionRecord {
        &self.connection
    }
    pub fn corpus_digest(&self) -> &Digest {
        &self.corpus_digest
    }
    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
    pub fn exchanges(&self) -> &[ProbeExchange] {
        &self.exchanges
    }
    pub fn content_digest(&self) -> Result<Digest, ProbeError> {
        serde_json::to_vec(self)
            .map(Digest::of)
            .map_err(|_| ProbeError::Profile)
    }
}
fn wall_time() -> Result<u64, ProbeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_millis().try_into().ok())
        .ok_or(ProbeError::Deadline)
}
fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(2 + bytes.len() * 2);
    result.push_str("0x");
    for b in bytes {
        use std::fmt::Write;
        write!(result, "{b:02x}").expect("string write");
    }
    result
}
fn rpc_hash(digest: &Digest) -> String {
    format!("0x{}", digest.as_str())
}
fn result(value: &Value) -> Result<&Value, ProbeError> {
    let object = value.as_object().ok_or(ProbeError::Exactness)?;
    if object.len() != 3 || !object.contains_key("result") {
        return Err(ProbeError::Exactness);
    }
    Ok(&object["result"])
}
fn error_code(value: &Value, expected: i64) -> Result<(), ProbeError> {
    let object = value.as_object().ok_or(ProbeError::Exactness)?;
    if object.len() != 3 || !object.contains_key("error") {
        return Err(ProbeError::Exactness);
    }
    let error = object["error"].as_object().ok_or(ProbeError::Exactness)?;
    if error.len() != 2
        || error.get("code").and_then(Value::as_i64) != Some(expected)
        || !error.get("message").is_some_and(Value::is_string)
    {
        return Err(ProbeError::Exactness);
    }
    Ok(())
}
struct Probe<'a> {
    registry: &'a ConnectionRegistry,
    connection: &'a ConnectionRecord,
    per_request_timeout: Duration,
    deadline: Instant,
    exchanges: Vec<ProbeExchange>,
}
impl Probe<'_> {
    fn acquire(&self) -> Result<ConnectionLease, ProbeError> {
        let lease = self
            .registry
            .acquire(
                &self.connection.provider_id,
                &self.connection.endpoint_id,
                self.connection.dispatcher_generation,
            )
            .map_err(|_| ProbeError::Transport)?;
        if lease.record().map_err(|_| ProbeError::Transport)? != self.connection {
            return Err(ProbeError::Drift);
        }
        Ok(lease)
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value, ProbeError> {
        if Instant::now() >= self.deadline {
            return Err(ProbeError::Deadline);
        }
        let id = format!("openpc-probe-{}", self.exchanges.len());
        let request = serde_json::to_vec(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
        .map_err(|_| ProbeError::Profile)?;
        let request_digest = Digest::of(&request);
        let lease = self.acquire()?;
        let deadline = self.deadline.min(Instant::now() + self.per_request_timeout);
        let response = lease
            .connection()
            .map_err(|_| ProbeError::Transport)?
            .post_json(request, deadline)
            .await
            .map_err(|_| ProbeError::Transport)?;
        let value = parse_strict_json(&response, 8).map_err(|_| ProbeError::Exactness)?;
        if value.get("id") != Some(&Value::String(id))
            || value.get("jsonrpc") != Some(&Value::String("2.0".into()))
        {
            return Err(ProbeError::Exactness);
        }
        self.exchanges.push(ProbeExchange {
            request_digest,
            response_digest: Digest::of(response),
        });
        Ok(value)
    }
    async fn chain(&mut self, plan: &HashPinnedCallProbePlan) -> Result<(), ProbeError> {
        let chain = self.rpc("eth_chainId", json!([])).await?;
        if result(&chain)? != &Value::String(format!("0x{:x}", plan.chain_id)) {
            return Err(ProbeError::Chain);
        }
        let genesis = self
            .rpc("eth_getBlockByNumber", json!(["0x0", false]))
            .await?;
        let genesis = result(&genesis)?.as_object().ok_or(ProbeError::Chain)?;
        if genesis.get("hash") != Some(&Value::String(rpc_hash(&plan.genesis_hash)))
            || genesis.get("number") != Some(&Value::String("0x0".into()))
        {
            return Err(ProbeError::Chain);
        }
        let header = self
            .rpc(
                "eth_getBlockByHash",
                json!([rpc_hash(&plan.block_hash), false]),
            )
            .await?;
        let header = result(&header)?.as_object().ok_or(ProbeError::Chain)?;
        if header.get("hash") != Some(&Value::String(rpc_hash(&plan.block_hash)))
            || header.get("number") != Some(&Value::String(format!("0x{:x}", plan.block_number)))
            || header.get("stateRoot") != Some(&Value::String(rpc_hash(&plan.state_root)))
        {
            return Err(ProbeError::Chain);
        }
        // A bounded QA observation still fences the real canonical mapping on
        // every round and after the final call; historical conformance is separate.
        if plan.noncanonical_block_hash.is_none() {
            let canonical = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([format!("0x{:x}", plan.block_number), false]),
                )
                .await?;
            let canonical = result(&canonical)?.as_object().ok_or(ProbeError::Chain)?;
            if canonical.get("hash") != Some(&Value::String(rpc_hash(&plan.block_hash)))
                || canonical.get("number")
                    != Some(&Value::String(format!("0x{:x}", plan.block_number)))
                || canonical.get("stateRoot") != Some(&Value::String(rpc_hash(&plan.state_root)))
            {
                return Err(ProbeError::Chain);
            }
        }
        let version = self.rpc("web3_clientVersion", json!([])).await?;
        let version = result(&version)?.as_str().ok_or(ProbeError::Drift)?;
        if Digest::of(version) != plan.expected_client_version_digest {
            return Err(ProbeError::Drift);
        }
        Ok(())
    }
    async fn call(
        &mut self,
        plan: &HashPinnedCallProbePlan,
        block: &Digest,
    ) -> Result<Value, ProbeError> {
        self.rpc(
            "eth_call",
            json!([
                { "from": hex(&plan.sender), "to": hex(&plan.target), "data": hex(&plan.calldata) },
                { "blockHash": rpc_hash(block), "requireCanonical": true }
            ]),
        )
        .await
    }
    async fn round(&mut self, plan: &HashPinnedCallProbePlan) -> Result<(), ProbeError> {
        self.chain(plan).await?;
        if let Some(header) = &plan.block_header {
            let response = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([format!("0x{:x}", plan.block_number), false]),
                )
                .await?;
            let value = result(&response)?;
            let observed =
                crate::source_header::SourceBlockHeader::decode(value, plan.block_number)
                    .map_err(|_| ProbeError::Exactness)?;
            let normalized =
                crate::rfc8785_canonical_bytes(value).map_err(|_| ProbeError::Exactness)?;
            if observed.hash != plan.block_hash.as_str()
                || observed.state_root != plan.state_root.as_str()
                || Digest::of(normalized) != header.expected_header_digest
            {
                return Err(ProbeError::Exactness);
            }
            let missing = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([format!("0x{:x}", header.unknown_block_number), false]),
                )
                .await?;
            header.unknown_block_response.validate(&missing)?;
        }
        if let Some(log) = &plan.event_log {
            if plan.block_header.is_none() {
                return Err(ProbeError::Profile);
            }
            let response=self.rpc("eth_getLogs",json!([{"address":hex(&plan.target),"blockHash":rpc_hash(&plan.block_hash),"topics":[rpc_hash(&log.event_signature)]}])).await?;
            let value = result(&response)?;
            let entries = value
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 64)
                .ok_or(ProbeError::Exactness)?;
            if entries.iter().any(|entry| {
                entry["address"] != hex(&plan.target)
                    || entry["blockHash"] != rpc_hash(&plan.block_hash)
                    || entry["topics"][0] != rpc_hash(&log.event_signature)
                    || entry["removed"] != false
            }) || Digest::of(
                crate::rfc8785_canonical_bytes(value).map_err(|_| ProbeError::Exactness)?,
            ) != log.expected_logs_digest
            {
                return Err(ProbeError::Exactness);
            }
            let missing=self.rpc("eth_getLogs",json!([{"address":hex(&plan.target),"blockHash":rpc_hash(&plan.unknown_block_hash),"topics":[rpc_hash(&log.event_signature)]}])).await?;
            error_code(&missing, plan.unknown_hash_error_code)?;
        }
        let call = self.call(plan, &plan.block_hash).await?;
        let data = result(&call)?.as_str().ok_or(ProbeError::Exactness)?;
        let hex_data = data.strip_prefix("0x").ok_or(ProbeError::Exactness)?;
        if !hex_data.len().is_multiple_of(2)
            || !hex_data
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProbeError::Exactness);
        }
        let decoded = hex_data
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                u8::from_str_radix(
                    std::str::from_utf8(p).map_err(|_| ProbeError::Exactness)?,
                    16,
                )
                .map_err(|_| ProbeError::Exactness)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if Digest::of(decoded) != plan.expected_result_digest {
            return Err(ProbeError::Exactness);
        }
        let unknown = self.call(plan, &plan.unknown_block_hash).await?;
        error_code(&unknown, plan.unknown_hash_error_code)?;
        if let Some(hash) = &plan.noncanonical_block_hash {
            let noncanonical = self.call(plan, hash).await?;
            error_code(
                &noncanonical,
                plan.noncanonical_hash_error_code
                    .ok_or(ProbeError::Profile)?,
            )?;
        }
        Ok(())
    }
}

pub async fn probe_hash_pinned_call(
    registry: &ConnectionRegistry,
    connection: &ConnectionRecord,
    plan: &HashPinnedCallProbePlan,
    deadline: Instant,
) -> Result<HashPinnedCallObservation, ProbeError> {
    let digests = [
        &plan.corpus_digest,
        &plan.genesis_hash,
        &plan.block_hash,
        &plan.state_root,
        &plan.unknown_block_hash,
        &plan.expected_result_digest,
        &plan.expected_client_version_digest,
    ];
    if digests
        .into_iter()
        .chain(plan.noncanonical_block_hash.as_ref())
        .any(|d| {
            d.as_str().len() != 64
                || !d
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || plan.chain_id == 0
        || plan.calldata.len() < 4
        || plan.calldata.len() > 65_536
        || plan.repeat_window < Duration::from_secs(5)
        || plan.repeat_window > Duration::from_secs(3600)
        || plan.per_request_timeout.is_zero()
        || plan.per_request_timeout > Duration::from_secs(30)
        || plan.block_hash == plan.unknown_block_hash
        || plan
            .noncanonical_block_hash
            .as_ref()
            .is_some_and(|hash| hash == &plan.block_hash || hash == &plan.unknown_block_hash)
        || !(-32099..=-32000).contains(&plan.unknown_hash_error_code)
        || plan.noncanonical_block_hash.is_some() != plan.noncanonical_hash_error_code.is_some()
        || plan
            .noncanonical_hash_error_code
            .is_some_and(|code| !(-32099..=-32000).contains(&code))
        || plan.block_header.as_ref().is_some_and(|header| {
            header.unknown_block_number <= plan.block_number
                || header.expected_header_digest.as_str().len() != 64
        })
    {
        return Err(ProbeError::Profile);
    }
    let repeat_at = Instant::now()
        .checked_add(plan.repeat_window)
        .ok_or(ProbeError::Deadline)?;
    if repeat_at >= deadline {
        return Err(ProbeError::Deadline);
    }
    let started_at_ms = wall_time()?;
    let mut probe = Probe {
        registry,
        connection,
        per_request_timeout: plan.per_request_timeout,
        deadline,
        exchanges: Vec::new(),
    };
    probe.round(plan).await?;
    // No lease is held across the observation window: cutover/quarantine is
    // free to proceed. Every later exchange reacquires this exact generation.
    let repeat_at = Instant::now()
        .checked_add(plan.repeat_window)
        .ok_or(ProbeError::Deadline)?;
    if repeat_at >= deadline {
        return Err(ProbeError::Deadline);
    }
    sleep_until(repeat_at).await;
    probe.round(plan).await?;
    // Recheck chain/client identity after the last method response as well.
    probe.chain(plan).await?;
    let completed_at_ms = wall_time()?;
    if completed_at_ms < started_at_ms || Instant::now() >= deadline {
        return Err(ProbeError::Deadline);
    }
    let _final_lease = probe.acquire()?;
    Ok(HashPinnedCallObservation {
        connection: connection.clone(),
        corpus_digest: plan.corpus_digest.clone(),
        plan_digest: plan.content_digest()?,
        started_at_ms,
        completed_at_ms,
        exchanges: probe.exchanges,
        admission_scope: if plan.noncanonical_block_hash.is_some() {
            "FULL_CORPUS"
        } else {
            "BOUNDED_QA"
        },
        historical_reorg_conformance: if plan.noncanonical_block_hash.is_some() {
            "OBSERVED"
        } else {
            "NOT_TESTED"
        },
    })
}
