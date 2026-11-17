//! One pinned provider, exact signed call, exact certified state and current
//! authority before every exchange. This evidence does not authorize a send.
use super::*;
use crate::{
    observation_rpc::ObservationRpc,
    provider_connection::{ConnectionLease, ConnectionRecord, now_ms},
    route_witness::VerifiedChainAnchor,
    write_preflight::{data, hex, rpc_hash, validate_header},
};
use pc_runtime_types::RuntimeRequest;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use tokio::time::{Duration, Instant};

/// These digests must come from current installed owners. The required callback
/// revalidates those owners; a caller's claim of readiness cannot replace it.
pub struct ObservationScope<'a> {
    pub profile_digest: &'a Digest,
    pub route_witness_set_digest: &'a Digest,
}

/// Only live acquisition constructs this value. It is not Deserialize/Serialize:
/// consumers persist the minimized evidence digest, not ephemeral calldata.
pub struct ObservedCiglTrace {
    connection: ConnectionRecord,
    request_digest: Digest,
    transaction_hash: [u8; 32],
    anchor_digest: Digest,
    profile_digest: Digest,
    route_witness_set_digest: Digest,
    completed_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
    trace: CrossCheckedTrace,
    code_observations: BTreeMap<[u8; 20], Digest>,
}
impl ObservedCiglTrace {
    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
    pub fn trace(&self) -> &CrossCheckedTrace {
        &self.trace
    }
    /// Pre-execution code at the certified anchor, including explicit empty
    /// code. Empty code never supplies a registered-method permission.
    pub fn code_digest(&self, address: &[u8; 20]) -> RuntimeResult<&Digest> {
        self.code_observations
            .get(address)
            .ok_or(RuntimeError::GenerationMismatch)
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&(
            "openpc:cigl-observation:v2",
            &self.connection,
            &self.request_digest,
            self.transaction_hash,
            &self.anchor_digest,
            &self.profile_digest,
            &self.route_witness_set_digest,
            self.completed_at_ms,
            self.valid_until_ms,
            &self.exchanges,
            self.trace.inspection.summaries()?,
            &self.trace.inspection.limits,
            self.code_observations.iter().collect::<Vec<_>>(),
        ))
        .map(Digest::of)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        connection: &ConnectionRecord,
        request: &RuntimeRequest,
        transaction: &SignedTransaction,
        anchor: &VerifiedChainAnchor,
        scope: &ObservationScope<'_>,
        now: u64,
    ) -> RuntimeResult<()> {
        if &self.connection != connection
            || self.request_digest != request.request_digest
            || &self.transaction_hash != transaction.hash()
            || self.anchor_digest != anchor.anchor().semantic_digest()?
            || &self.profile_digest != scope.profile_digest
            || &self.route_witness_set_digest != scope.route_witness_set_digest
            || now < self.completed_at_ms
            || now >= self.valid_until_ms
            || self.exchanges.len() != 4 + self.code_observations.len()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        anchor.revalidate_time(
            now.checked_mul(1_000_000)
                .ok_or(RuntimeError::InvalidInput)?,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn observe_signed(
    connection: &ConnectionLease,
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
    anchor: &VerifiedChainAnchor,
    scope: &ObservationScope<'_>,
    limits: TraceLimits,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<ObservedCiglTrace> {
    limits.validate()?;
    crate::governed_write::validate_runtime_signed_command(request, transaction)?;
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let started = now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let valid_until_ms = request
        .deadline_at_ms
        .min(record.valid_until_ms)
        .min(anchor.valid_until_ns() / 1_000_000)
        .min(
            started
                .checked_add(u64::from(limits.timeout_ms))
                .ok_or(RuntimeError::InvalidInput)?,
        );
    if started >= valid_until_ms
        || scope.profile_digest == &Digest::of([])
        || scope.route_witness_set_digest == &Digest::of([])
        || anchor.anchor().chain_id != transaction.chain_id()
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let deadline = deadline.min(Instant::now() + Duration::from_millis(valid_until_ms - started));
    anchor.revalidate_time(
        started
            .checked_mul(1_000_000)
            .ok_or(RuntimeError::InvalidInput)?,
    )?;
    let mut observer = ObservationRpc {
        connection,
        request_digest: &request.request_digest,
        deadline,
        revalidate,
        exchanges: Vec::with_capacity(4),
        maximum_calls: 4 + usize::from(limits.max_frames) * 2,
        maximum_depth: limits.json_depth()?,
        purpose: "cigl",
    };
    let header = observer
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    validate_header(&header, anchor.anchor(), transaction)?;
    let call = transaction
        .simulation_call()
        .map_err(|_| RuntimeError::InvalidInput)?;
    let selected =
        json!({"blockHash":rpc_hash(&anchor.anchor().block_hash),"requireCanonical":true});
    let timeout = format!("{}ms", limits.timeout_ms);
    let value = observer.rpc_with_response_limit("debug_traceCall", json!([call, selected, {
        "tracer":"callTracer", "timeout":timeout, "tracerConfig":{"onlyTopCall":false,"withLog":false}
    }]), limits.max_response_bytes as usize).await?;
    // The shared observer has already applied byte/depth/duplicate-key checks.
    // Classify its tree directly, then drop it before acquiring the opcode tree.
    let inspection = TraceInspection {
        trace_digest: observer
            .exchanges
            .last()
            .ok_or(RuntimeError::ResponseWithheld)?
            .1
            .clone(),
        limits,
        frames: geth::inspect(&value, &TraceRoot::for_signed(transaction), limits)?,
    };
    drop(value);
    if inspection.frames[0].failed {
        return Err(RuntimeError::ResponseWithheld);
    }
    observer.maximum_depth = 8;
    let value = observer.rpc_with_response_limit("debug_traceCall", json!([call, selected, {
        "timeout":timeout,"enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0
    }]), limits.max_response_bytes as usize).await?;
    let steps = opcodes::inspect(&inspection, &value)?;
    drop(value);
    let trace = CrossCheckedTrace {
        inspection,
        opcode_digest: observer
            .exchanges
            .last()
            .ok_or(RuntimeError::ResponseWithheld)?
            .1
            .clone(),
        steps,
    };
    let mut code_observations = BTreeMap::new();
    let addresses: BTreeSet<_> = trace
        .inspection
        .frames
        .iter()
        .flat_map(|frame| [frame.target, frame.execution_address])
        .collect();
    for address in addresses {
        let value = observer
            .rpc_with_response_limit(
                "eth_getCode",
                json!([hex(&address), selected]),
                limits.max_response_bytes as usize,
            )
            .await?;
        let code = data(&value, 24_576)?;
        code_observations.insert(address, Digest::of(code));
    }
    let header = observer
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    validate_header(&header, anchor.anchor(), transaction)?;
    revalidate()?;
    let completed_at_ms = now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let proof = ObservedCiglTrace {
        connection: record,
        request_digest: request.request_digest.clone(),
        transaction_hash: *transaction.hash(),
        anchor_digest: anchor.anchor().semantic_digest()?,
        profile_digest: scope.profile_digest.clone(),
        route_witness_set_digest: scope.route_witness_set_digest.clone(),
        completed_at_ms,
        valid_until_ms,
        exchanges: observer.exchanges,
        trace,
        code_observations,
    };
    proof.validate(
        connection
            .record()
            .map_err(|_| RuntimeError::GenerationMismatch)?,
        request,
        transaction,
        anchor,
        scope,
        completed_at_ms,
    )?;
    Ok(proof)
}
