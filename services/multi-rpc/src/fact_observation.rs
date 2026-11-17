//! Bounded off-path FactBridge verification. No observed byte is returned to a
//! runtime caller, and this proof alone grants neither fact admission nor reads.
use crate::external_decision::{AdapterCallContextV1, ExternalDecisionRequestV1};
use crate::{
    observation_rpc::ObservationRpc,
    provider_connection::{ConnectionLease, ConnectionRecord},
    source_header::SourceBlockHeader,
    write_preflight::{data, hex, quantity_u64, rpc_hash},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::Serialize;
use serde_json::json;
use tokio::time::Instant;

mod reorg;
pub use reorg::{FactReorgQuery, observe_fact_reorg};

/// The admission owner resolves these from its current governed source, code
/// binding and exact candidate anchor; these fields confer no authority.
#[derive(Serialize)]
pub struct FactStateQuery {
    pub chain_id: u64,
    pub genesis_hash: Digest,
    pub block_number: u64,
    pub block_hash: Digest,
    pub target: [u8; 20],
    pub calldata: Vec<u8>,
    pub code_digest: Digest,
    pub confirmations: u32,
}

/// Private construction and no deserialization: callers cannot supply a
/// claimed result digest or declare confirmation evidence successful.
pub struct VerifiedFactStateObservation {
    connection: ConnectionRecord,
    query_digest: Digest,
    result: Vec<u8>,
    headers_digest: Digest,
    canonical_blocks: Vec<(u64, String)>,
    head_number: u64,
    head_hash: Digest,
    started_at_ms: u64,
    completed_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
}

impl std::fmt::Debug for VerifiedFactStateObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedFactStateObservation")
            .field("query_digest", &self.query_digest)
            .finish_non_exhaustive()
    }
}

impl VerifiedFactStateObservation {
    pub fn connection(&self) -> &ConnectionRecord {
        &self.connection
    }
    pub fn result(&self) -> &[u8] {
        &self.result
    }
    pub fn canonical_blocks(&self) -> &[(u64, String)] {
        &self.canonical_blocks
    }
    pub fn head_number(&self) -> u64 {
        self.head_number
    }
    pub fn head_hash(&self) -> &Digest {
        &self.head_hash
    }
    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
    pub fn completed_at_ms(&self) -> u64 {
        self.completed_at_ms
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&(
            "openpc:independent-fact-state-observation:v1",
            &self.connection,
            &self.query_digest,
            Digest::of(&self.result),
            &self.headers_digest,
            self.head_number,
            &self.head_hash,
            self.started_at_ms,
            self.completed_at_ms,
            self.valid_until_ms,
            &self.exchanges,
        ))
        .map(Digest::of)
    }
    pub fn validate_external(
        &self,
        query: &FactStateQuery,
        request: &ExternalDecisionRequestV1,
        connection: &ConnectionRecord,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        if &self.connection != connection
            || self.query_digest != external_query_digest(query, request)?
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub fn validate_event(
        &self,
        query: &FactStateQuery,
        signature: &Digest,
        connection: &ConnectionRecord,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        if &self.connection != connection
            || self.query_digest
                != Digest::of(canonical_bytes(&(
                    "openpc:fact-event-query:v1",
                    query,
                    signature,
                ))?)
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub fn validate(
        &self,
        query: &FactStateQuery,
        connection: &ConnectionRecord,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        if &self.connection != connection
            || self.query_digest != query.digest()?
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
}
impl FactStateQuery {
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:fact-state-query:v1", self)).map(Digest::of)
    }
    fn validate(&self) -> RuntimeResult<()> {
        if self.chain_id == 0
            || self.block_number == 0
            || !(1..=64).contains(&self.confirmations)
            || !(4..=32768).contains(&self.calldata.len())
            || self
                .block_number
                .checked_add(u64::from(self.confirmations) - 1)
                .is_none()
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

/// Each exchange reacquires the admission owner's finite current authority.
/// The separate Control lease and connection generation must remain held; the
/// caller must recheck both before committing facts.
pub async fn observe_fact_state(
    connection: &ConnectionLease,
    query: &FactStateQuery,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<VerifiedFactStateObservation> {
    observe_fact_contract(connection, query, None, None, deadline, revalidate).await
}

/// Off-path event acquisition shares chain, code, deadline and closing-fence
/// verification with state observations. Event queries contain no calldata.
pub async fn observe_fact_event(
    connection: &ConnectionLease,
    query: &FactStateQuery,
    event_signature: &Digest,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<VerifiedFactStateObservation> {
    observe_fact_contract(
        connection,
        query,
        Some(event_signature),
        None,
        deadline,
        revalidate,
    )
    .await
}

/// Independent off-path acquisition under the same chain/code/canonicality fence.
pub async fn observe_fact_external(
    connection: &ConnectionLease,
    query: &FactStateQuery,
    request: &ExternalDecisionRequestV1,
    context: &AdapterCallContextV1<'_>,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<VerifiedFactStateObservation> {
    observe_fact_contract(
        connection,
        query,
        None,
        Some((request, context)),
        context.deadline,
        revalidate,
    )
    .await
}
fn external_query_digest(
    query: &FactStateQuery,
    request: &ExternalDecisionRequestV1,
) -> RuntimeResult<Digest> {
    canonical_bytes(&(
        "openpc:fact-external-query:v1",
        query,
        request.digest().map_err(|_| RuntimeError::InvalidInput)?,
    ))
    .map(Digest::of)
}

async fn observe_fact_contract(
    connection: &ConnectionLease,
    query: &FactStateQuery,
    event_signature: Option<&Digest>,
    external: Option<(&ExternalDecisionRequestV1, &AdapterCallContextV1<'_>)>,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<VerifiedFactStateObservation> {
    if event_signature.is_none() {
        query.validate()?;
    } else if !query.calldata.is_empty()
        || query.chain_id == 0
        || query.block_number == 0
        || !(1..=64).contains(&query.confirmations)
        || query
            .block_number
            .checked_add(u64::from(query.confirmations) - 1)
            .is_none()
    {
        return Err(RuntimeError::InvalidInput);
    }
    revalidate()?;
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let started_at_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RuntimeError::BudgetExhausted)?;
    if remaining.as_millis() > 30000 {
        return Err(RuntimeError::BudgetExhausted);
    }
    // The call deadline bounds execution, not the lifetime of completed evidence.
    // Provider/connection expiry (and an external observation's own expiry)
    // still bound this proof; Fact admission applies its freshness profile.
    let mut valid_until_ms = record.valid_until_ms;
    let query_digest = if let Some((request, _)) = external {
        external_query_digest(query, request)?
    } else {
        match event_signature {
            None => query.digest()?,
            Some(signature) => Digest::of(canonical_bytes(&(
                "openpc:fact-event-query:v1",
                query,
                signature,
            ))?),
        }
    };
    let mut rpc = ObservationRpc {
        connection,
        request_digest: &query_digest,
        deadline,
        revalidate,
        exchanges: Vec::new(),
        maximum_calls: 2 * query.confirmations as usize
            + 4
            + if event_signature.is_some() { 64 } else { 0 },
        maximum_depth: 8,
        purpose: "fact-verification",
    };
    let mut remaining_response_bytes = 1_048_576;
    if quantity_u64(
        &rpc.rpc_with_response_budget(
            "eth_chainId",
            json!([]),
            1024,
            &mut remaining_response_bytes,
        )
        .await?,
    )? != query.chain_id
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let genesis = rpc
        .rpc_with_response_budget(
            "eth_getBlockByNumber",
            json!(["0x0", false]),
            131072,
            &mut remaining_response_bytes,
        )
        .await?;
    if genesis["number"] != "0x0" || genesis["hash"] != rpc_hash(&query.genesis_hash) {
        return Err(RuntimeError::GenerationMismatch);
    }
    let mut headers = Vec::new();
    for offset in 0..query.confirmations {
        let number = query.block_number + u64::from(offset);
        let value = rpc
            .rpc_with_response_budget(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
                131072,
                &mut remaining_response_bytes,
            )
            .await?;
        let header = SourceBlockHeader::decode(&value, number)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        if headers.last().is_some_and(|previous: &SourceBlockHeader| {
            header.parent_hash != previous.hash
                || header.timestamp_seconds < previous.timestamp_seconds
        }) || header.timestamp_seconds > started_at_ms / 1000
            || (offset == 0 && header.hash != query.block_hash.as_str())
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        headers.push(header);
    }
    let selector = json!({"blockHash":rpc_hash(&query.block_hash),"requireCanonical":true});
    let code = rpc
        .rpc_with_response_budget(
            "eth_getCode",
            json!([hex(&query.target), selector]),
            65536,
            &mut remaining_response_bytes,
        )
        .await?;
    let code = data(&code, 24576)?;
    if code.is_empty() || Digest::of(code) != query.code_digest {
        return Err(RuntimeError::GenerationMismatch);
    }
    let result = if let Some((request, context)) = external {
        let observed = crate::external_decision::acquire_observation(connection, request, context)
            .await
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let result = crate::rfc8785_canonical_bytes(
            &serde_json::to_value(observed.observation())
                .map_err(|_| RuntimeError::InvalidInput)?,
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        valid_until_ms = valid_until_ms.min(observed.observation().expires_at_ms);
        rpc.exchanges
            .push((observed.request_digest().clone(), Digest::of(&result)));
        result
    } else if let Some(signature) = event_signature {
        let logs = rpc.rpc_with_response_budget("eth_getLogs",
            json!([{"address":hex(&query.target),"blockHash":rpc_hash(&query.block_hash),"topics":[rpc_hash(signature)]}]),
            131072,&mut remaining_response_bytes).await?;
        let entries = logs
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or(RuntimeError::ResponseWithheld)?;
        let mut previous = None;
        for log in entries {
            let index = (
                quantity_u64(&log["transactionIndex"])?,
                quantity_u64(&log["logIndex"])?,
            );
            if log["removed"] != false
                || log["address"] != hex(&query.target)
                || log["blockHash"] != rpc_hash(&query.block_hash)
                || quantity_u64(&log["blockNumber"])? != query.block_number
                || log["topics"][0] != rpc_hash(signature)
                || previous.is_some_and(|prior| prior >= index)
            {
                return Err(RuntimeError::ResponseWithheld);
            }
            previous = Some(index);
            let transaction = data(&log["transactionHash"], 32)?;
            if transaction.len() != 32 {
                return Err(RuntimeError::ResponseWithheld);
            }
            let receipt = rpc
                .rpc_with_response_budget(
                    "eth_getTransactionReceipt",
                    json!([hex(&transaction)]),
                    131072,
                    &mut remaining_response_bytes,
                )
                .await?;
            if receipt["status"] != "0x1"
                || receipt["transactionHash"] != log["transactionHash"]
                || receipt["blockHash"] != log["blockHash"]
                || receipt["blockNumber"] != log["blockNumber"]
                || receipt["transactionIndex"] != log["transactionIndex"]
                || receipt["logs"]
                    .as_array()
                    .is_none_or(|values| values.iter().filter(|v| *v == log).count() != 1)
            {
                return Err(RuntimeError::ResponseWithheld);
            }
        }
        crate::rfc8785_canonical_bytes(&logs).map_err(|_| RuntimeError::InvalidInput)?
    } else {
        let result = rpc
            .rpc_with_response_budget(
                "eth_call",
                json!([{"to":hex(&query.target),"data":hex(&query.calldata)},selector]),
                131072,
                &mut remaining_response_bytes,
            )
            .await?;
        data(&result, 65536)?
    };
    for previous in &headers {
        let value = rpc
            .rpc_with_response_budget(
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", previous.number), false]),
                131072,
                &mut remaining_response_bytes,
            )
            .await?;
        let current = SourceBlockHeader::decode(&value, previous.number)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        if current.hash != previous.hash
            || current.parent_hash != previous.parent_hash
            || current.state_root != previous.state_root
            || current.timestamp_seconds != previous.timestamp_seconds
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    revalidate()?;
    let completed_at_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if completed_at_ms < started_at_ms
        || completed_at_ms >= valid_until_ms
        || Instant::now() >= deadline
    {
        return Err(RuntimeError::BudgetExhausted);
    }
    let head = headers.last().ok_or(RuntimeError::ResponseWithheld)?;
    let headers_digest = Digest::of(canonical_bytes(
        &headers
            .iter()
            .map(|header| {
                (
                    header.number,
                    &header.hash,
                    &header.parent_hash,
                    &header.state_root,
                    header.timestamp_seconds,
                )
            })
            .collect::<Vec<_>>(),
    )?);
    Ok(VerifiedFactStateObservation {
        connection: record,
        query_digest: query_digest.clone(),
        result,
        headers_digest,
        canonical_blocks: headers.iter().map(|h| (h.number, h.hash.clone())).collect(),
        head_number: head.number,
        head_hash: Digest::parse(&head.hash)?,
        started_at_ms,
        completed_at_ms,
        valid_until_ms,
        exchanges: rpc.exchanges,
    })
}
