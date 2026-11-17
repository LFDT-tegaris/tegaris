//! Independent bounded canonical-header verification for off-path invalidation.
use super::*;

#[derive(Serialize)]
pub struct FactReorgQuery {
    pub chain_id: u64,
    pub genesis_hash: Digest,
    pub start: u64,
    pub end: u64,
    pub old_hash: Digest,
    pub new_hash: Digest,
    pub confirmations: u32,
}

/// The returned digest commits actual exchanges under the retained current
/// connection and authority. It conveys no admission or replacement permission.
pub async fn observe_fact_reorg(
    connection: &ConnectionLease,
    query: &FactReorgQuery,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<Digest> {
    let count = query
        .end
        .checked_sub(query.start)
        .and_then(|n| n.checked_add(u64::from(query.confirmations)))
        .ok_or(RuntimeError::InvalidInput)?;
    if query.start == 0
        || query.chain_id == 0
        || query.old_hash == query.new_hash
        || !(1..=64).contains(&count)
        || query.confirmations == 0
    {
        return Err(RuntimeError::InvalidInput);
    }
    revalidate()?;
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let started =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if deadline
        .checked_duration_since(Instant::now())
        .is_none_or(|remaining| remaining.as_millis() > 30000)
    {
        return Err(RuntimeError::BudgetExhausted);
    }
    let query_digest = Digest::of(canonical_bytes(&("openpc:fact-reorg-query:v1", query))?);
    let mut rpc = ObservationRpc {
        connection,
        request_digest: &query_digest,
        deadline,
        revalidate,
        exchanges: Vec::new(),
        maximum_calls: 2 + 2 * count as usize,
        maximum_depth: 8,
        purpose: "fact-reorg",
    };
    let mut budget = 16 * 1024 * 1024;
    if quantity_u64(
        &rpc.rpc_with_response_budget("eth_chainId", json!([]), 1024, &mut budget)
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
            &mut budget,
        )
        .await?;
    if genesis["number"] != "0x0" || genesis["hash"] != rpc_hash(&query.genesis_hash) {
        return Err(RuntimeError::GenerationMismatch);
    }
    let mut headers = Vec::new();
    for offset in 0..count {
        let number = query
            .start
            .checked_add(offset)
            .ok_or(RuntimeError::InvalidInput)?;
        let value = rpc
            .rpc_with_response_budget(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
                131072,
                &mut budget,
            )
            .await?;
        let header = SourceBlockHeader::decode(&value, number)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        if header.timestamp_seconds > started / 1000
            || (offset == 0 && header.hash != query.new_hash.as_str())
            || headers.last().is_some_and(|previous: &SourceBlockHeader| {
                header.parent_hash != previous.hash
                    || header.timestamp_seconds < previous.timestamp_seconds
            })
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        headers.push(header);
    }
    for header in &headers {
        let value = rpc
            .rpc_with_response_budget(
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", header.number), false]),
                131072,
                &mut budget,
            )
            .await?;
        let current = SourceBlockHeader::decode(&value, header.number)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        if current.hash != header.hash
            || current.parent_hash != header.parent_hash
            || current.state_root != header.state_root
            || current.timestamp_seconds != header.timestamp_seconds
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    revalidate()?;
    let completed =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if completed < started || completed >= record.valid_until_ms || Instant::now() >= deadline {
        return Err(RuntimeError::BudgetExhausted);
    }
    Ok(Digest::of(canonical_bytes(&(
        "openpc:verified-fact-reorg:v1",
        &query_digest,
        record,
        started,
        completed,
        rpc.exchanges,
    ))?))
}
