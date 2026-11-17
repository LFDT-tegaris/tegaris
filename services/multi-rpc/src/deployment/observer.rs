//! Actual pinned provider observations for the closed reference deployment
//! profile. The target must admit this profile and each observation capability
//! before entry and in revalidate; connection installation alone is insufficient.
use super::{
    BoundDeployment, CreationInspection, CreationMechanism, DeploymentConstraints, keccak,
};
use crate::{
    observation_rpc::ObservationRpc,
    provider_connection::{ConnectionLease, ConnectionRecord},
    route_witness::VerifiedChainAnchor,
    signed_transaction::{SignedTransaction, create_address},
    write_preflight::{data, hex, maximum_cost, quantity, quantity_u64, rpc_hash, validate_header},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult, canonical_bytes};
use serde::Serialize;
use serde_json::json;
use tokio::time::Instant;

const MAX_CALLS: usize = 16;
const MAX_CODE_BYTES: usize = 24_576;

/// Sealed predictive evidence from real provider exchanges. It is never actor
/// permission, a receipt, mined code identity or a finality/association result.
#[derive(Debug, Serialize)]
pub struct DeploymentPreflight {
    connection: ConnectionRecord,
    request_digest: Digest,
    binding: BoundDeployment,
    genesis_digest: Digest,
    anchor_digest: Digest,
    route_witness_set_digest: Digest,
    inspection: CreationInspection,
    completed_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
}
impl DeploymentPreflight {
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:deployment-preflight:v1", self)).map(Digest::of)
    }
    pub fn address(&self) -> &[u8; 20] {
        self.inspection.address()
    }
    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        connection: &ConnectionRecord,
        request: &RuntimeRequest,
        constraints: &DeploymentConstraints,
        transaction: &SignedTransaction,
        genesis_digest: &Digest,
        anchor: &VerifiedChainAnchor,
        route_witness_set_digest: &Digest,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        crate::governed_write::validate_runtime_signed_command(request, transaction)?;
        let expected_calls = match self.binding.mechanism {
            CreationMechanism::TransactionCreate => 12,
            CreationMechanism::Create2 => 13,
            CreationMechanism::Create => 14,
            CreationMechanism::Create3 => 16,
        };
        if &self.connection != connection
            || self.request_digest != request.request_digest
            || self.binding != constraints.bind(transaction)?
            || &self.genesis_digest != genesis_digest
            || self.anchor_digest != anchor.anchor().semantic_digest()?
            || &self.route_witness_set_digest != route_witness_set_digest
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
            || self.exchanges.len() != expected_calls
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn observe_preflight(
    connection: &ConnectionLease,
    request: &RuntimeRequest,
    constraints: &DeploymentConstraints,
    transaction: &SignedTransaction,
    genesis_digest: &Digest,
    anchor: &VerifiedChainAnchor,
    route_witness_set_digest: &Digest,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<DeploymentPreflight> {
    crate::governed_write::validate_runtime_signed_command(request, transaction)?;
    let binding = constraints.bind(transaction)?;
    if let Some(invocation) = &request.invocation {
        crate::governed_write::validate_runtime_submission(request, transaction)?;
        if invocation.genesis_digest != *genesis_digest
            || invocation.proxy_address.is_some()
            || invocation.implementation_address.is_some()
            || invocation.implementation_code_digest.is_some()
            || !invocation.nested_calls.is_empty()
            || !matches!(&constraints.route, super::DeploymentRoute::Factory(factory) if factory.abi_digest == invocation.abi_digest)
        {
            return Err(RuntimeError::Denied);
        }
    } else if request.deployment.is_none() && transaction.destination().is_some() {
        return Err(RuntimeError::Denied);
    }
    super::valid_digest(genesis_digest)?;
    super::valid_digest(route_witness_set_digest)?;
    // D1 observation measures the exact root endowment and forbids internal
    // transfers. Native Value permission comes from protected issuance and the
    // verified one-use handoff, never from this predictive observation.
    if (transaction.value() != &[0; 32]
        && binding.mechanism != CreationMechanism::TransactionCreate)
        || anchor.anchor().chain_id != transaction.chain_id()
    {
        return Err(RuntimeError::Denied);
    }
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let started =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let valid_until_ms = request
        .deadline_at_ms
        .min(record.valid_until_ms)
        .min(anchor.valid_until_ns() / 1_000_000)
        .min(
            started.saturating_add(pc_policy_core::transaction_policy::MAX_TRANSACTION_DEADLINE_MS),
        );
    if started >= valid_until_ms || Instant::now() >= deadline {
        return Err(RuntimeError::BudgetExhausted);
    }
    let deadline =
        deadline.min(Instant::now() + std::time::Duration::from_millis(valid_until_ms - started));
    let mut observer = ObservationRpc {
        connection,
        request_digest: &request.request_digest,
        deadline,
        revalidate,
        exchanges: Vec::with_capacity(MAX_CALLS),
        maximum_calls: MAX_CALLS,
        maximum_depth: 40,
        purpose: "deployment-preflight",
    };
    if quantity_u64(&observer.rpc("eth_chainId", json!([])).await?)? != transaction.chain_id() {
        return Err(RuntimeError::GenerationMismatch);
    }
    let genesis = observer
        .rpc("eth_getBlockByNumber", json!(["0x0", false]))
        .await?;
    if genesis["number"] != json!("0x0") || genesis["hash"] != json!(rpc_hash(genesis_digest)) {
        return Err(RuntimeError::GenerationMismatch);
    }
    let header = observer
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    validate_header(&header, anchor.anchor(), transaction)?;
    let selected =
        json!({"blockHash":rpc_hash(&anchor.anchor().block_hash),"requireCanonical":true});
    let sender = hex(transaction.signer());
    if !data(
        &observer
            .rpc("eth_getCode", json!([sender, selected]))
            .await?,
        MAX_CODE_BYTES,
    )?
    .is_empty()
        || quantity_u64(
            &observer
                .rpc("eth_getTransactionCount", json!([sender, selected]))
                .await?,
        )? != transaction.nonce()
    {
        return Err(RuntimeError::Denied);
    }
    let balance = observer
        .rpc("eth_getBalance", json!([sender, selected]))
        .await?;
    if quantity(&balance)?
        < maximum_cost(
            transaction.value(),
            transaction.maximum_fee(),
            transaction.gas_limit(),
        )?
    {
        return Err(RuntimeError::Denied);
    }
    if let Some(expected) = binding.factory_code_hash {
        let super::DeploymentRoute::Factory(factory) = &constraints.route else {
            return Err(RuntimeError::InvalidAuthorization);
        };
        let code = data(
            &observer
                .rpc("eth_getCode", json!([hex(&binding.creator), selected]))
                .await?,
            MAX_CODE_BYTES,
        )?;
        if code.is_empty()
            || keccak(&code) != expected
            || Digest::of(&code) != factory.code_digest
            || request
                .invocation
                .as_ref()
                .is_some_and(|invocation| invocation.code_digest != Digest::of(&code))
        {
            return Err(RuntimeError::GenerationMismatch);
        }
    }
    let nonce = if binding.mechanism == CreationMechanism::Create {
        Some(quantity_u64(
            &observer
                .rpc(
                    "eth_getTransactionCount",
                    json!([hex(&binding.creator), selected]),
                )
                .await?,
        )?)
    } else {
        None
    };
    let predicted = binding
        .predicted_address
        .unwrap_or_else(|| create_address(&binding.creator, nonce.expect("factory CREATE nonce")));
    let mut targets = vec![predicted];
    if binding.mechanism == CreationMechanism::Create3 {
        let (helper, _) = super::solady_create3_addresses(
            &binding.creator,
            &binding.salt.ok_or(RuntimeError::InvalidAuthorization)?,
        )?;
        targets.push(helper);
    }
    for address in targets {
        let target = hex(&address);
        if !data(
            &observer
                .rpc("eth_getCode", json!([target, selected]))
                .await?,
            MAX_CODE_BYTES,
        )?
        .is_empty()
            || quantity_u64(
                &observer
                    .rpc("eth_getTransactionCount", json!([target, selected]))
                    .await?,
            )? != 0
        {
            return Err(RuntimeError::Denied);
        }
        // Nonzero prebalance is a profile denial, distinct from an EVM collision.
        if quantity(
            &observer
                .rpc("eth_getBalance", json!([target, selected]))
                .await?,
        )? != [0; 32]
        {
            return Err(RuntimeError::Denied);
        }
    }
    let call = transaction
        .simulation_call()
        .map_err(|_| RuntimeError::InvalidInput)?;
    let call_trace = observer.rpc("debug_traceCall",json!([call,selected,{
        "tracer":"callTracer","timeout":"5s","tracerConfig":{"onlyTopCall":false,"withLog":false}
    }])).await?;
    if call_trace.get("error").is_some() || call_trace.get("revertReason").is_some() {
        return Err(RuntimeError::ResponseWithheld);
    }
    let opcode_trace = observer.rpc("debug_traceCall",json!([call,selected,{
        "timeout":"5s","enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0
    }])).await?;
    let inspection = binding.inspect_single_creation(
        &crate::rfc8785_canonical_bytes(&call_trace).map_err(|_| RuntimeError::ResponseWithheld)?,
        &crate::rfc8785_canonical_bytes(&opcode_trace)
            .map_err(|_| RuntimeError::ResponseWithheld)?,
        nonce,
    )?;
    if inspection.address() != &predicted {
        return Err(RuntimeError::GenerationMismatch);
    }
    let header = observer
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    validate_header(&header, anchor.anchor(), transaction)?;
    revalidate()?;
    let completed_at_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let proof = DeploymentPreflight {
        connection: record,
        request_digest: request.request_digest.clone(),
        binding,
        genesis_digest: genesis_digest.clone(),
        anchor_digest: anchor.anchor().semantic_digest()?,
        route_witness_set_digest: route_witness_set_digest.clone(),
        inspection,
        completed_at_ms,
        valid_until_ms,
        exchanges: observer.exchanges,
    };
    proof.validate(
        connection
            .record()
            .map_err(|_| RuntimeError::GenerationMismatch)?,
        request,
        constraints,
        transaction,
        genesis_digest,
        anchor,
        route_witness_set_digest,
        completed_at_ms,
    )?;
    Ok(proof)
}
