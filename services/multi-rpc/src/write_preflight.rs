//! Bounded internal safety observation for one signed submission. This evidence
//! neither grants submission nor authorizes actor-visible reads/simulation.
use crate::{
    observation_rpc::ObservationRpc as Observer,
    provider_connection::{ConnectionLease, ConnectionRecord},
    route_witness::{ChainAnchor, VerifiedChainAnchor},
    signed_transaction::SignedTransaction,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeRequest, RuntimeResult, canonical_bytes};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Instant;

const MAX_CALLS: usize = 8;
const MAX_CODE_BYTES: usize = 24_576;

/// Only the actual pinned transport observer can construct this value. No raw
/// state, balance, code, provider error or credential is retained or disclosed.
#[derive(Debug, Serialize)]
pub struct WritePreflight {
    connection: ConnectionRecord,
    request_digest: Digest,
    transaction_hash: [u8; 32],
    anchor_digest: Digest,
    route_witness_set_digest: Digest,
    started_at_ms: u64,
    completed_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
}

impl WritePreflight {
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:write-preflight:v1", self)).map(Digest::of)
    }

    pub fn validate(
        &self,
        connection: &ConnectionRecord,
        request: &RuntimeRequest,
        transaction: &SignedTransaction,
        anchor: &VerifiedChainAnchor,
        route_witness_set_digest: &Digest,
        now_ms: u64,
    ) -> RuntimeResult<()> {
        if &self.connection != connection
            || self.request_digest != request.request_digest
            || &self.transaction_hash != transaction.hash()
            || self.anchor_digest != anchor.anchor().semantic_digest()?
            || &self.route_witness_set_digest != route_witness_set_digest
            || self.exchanges.len() != MAX_CALLS
            || now_ms < self.completed_at_ms
            || now_ms >= self.valid_until_ms
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }

    pub fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
}

/// The first three exchanges select actual canonical state. This sealed value
/// supplies no permission and cannot be deserialized from caller metadata.
#[derive(Debug)]
pub struct PreflightAnchor {
    connection: ConnectionRecord,
    request_digest: Digest,
    transaction_hash: [u8; 32],
    chain_id: u64,
    header: Value,
    observed_at_ns: u64,
    started_at_ms: u64,
    valid_until_ms: u64,
    exchanges: Vec<(Digest, Digest)>,
}
impl PreflightAnchor {
    pub fn chain_anchor(
        &self,
        chain_environment_id: &str,
        canonical_generation: u64,
    ) -> RuntimeResult<ChainAnchor> {
        if canonical_generation == 0 || chain_environment_id.is_empty() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(ChainAnchor {
            chain_environment_id: chain_environment_id.into(),
            chain_id: self.chain_id,
            block_number: quantity_u64(&self.header["number"])?,
            block_hash: header_digest(&self.header["hash"])?,
            state_root: header_digest(&self.header["stateRoot"])?,
            canonical_generation,
            observed_at_ns: self.observed_at_ns,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn complete(
        self,
        connection: &ConnectionLease,
        request: &RuntimeRequest,
        transaction: &SignedTransaction,
        anchor: &VerifiedChainAnchor,
        route_witness_set_digest: &Digest,
        deadline: Instant,
        revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
    ) -> RuntimeResult<WritePreflight> {
        validate_submission(request, transaction)?;
        let record = connection
            .record()
            .map_err(|_| RuntimeError::GenerationMismatch)?
            .clone();
        let selected = self.chain_anchor(
            &anchor.anchor().chain_environment_id,
            anchor.anchor().canonical_generation,
        )?;
        if self.connection != record
            || self.request_digest != request.request_digest
            || &self.transaction_hash != transaction.hash()
            || selected != *anchor.anchor()
            || self.exchanges.len() != 3
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let now =
            crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let valid_until_ms = self.valid_until_ms.min(anchor.valid_until_ns() / 1_000_000);
        if now >= valid_until_ms || Instant::now() >= deadline {
            return Err(RuntimeError::BudgetExhausted);
        }
        let invocation = request.invocation.as_ref().ok_or(RuntimeError::Denied)?;
        validate_header(&self.header, anchor.anchor(), transaction)?;
        let started_at_ms = self.started_at_ms;
        let mut observer = Observer {
            connection,
            request_digest: &request.request_digest,
            deadline,
            revalidate,
            exchanges: self.exchanges,
            maximum_calls: MAX_CALLS,
            maximum_depth: 8,
            purpose: "preflight",
        };
        let selector =
            json!({"blockHash":rpc_hash(&anchor.anchor().block_hash),"requireCanonical":true});
        let code = observer
            .rpc(
                "eth_getCode",
                json!([hex(&invocation.contract_address), selector]),
            )
            .await?;
        let code = data(&code, MAX_CODE_BYTES)?;
        if code.is_empty() || Digest::of(&code) != invocation.code_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        let sender = hex(transaction.signer());
        let signer_code = observer
            .rpc("eth_getCode", json!([sender, selector]))
            .await?;
        if !data(&signer_code, MAX_CODE_BYTES)?.is_empty() {
            return Err(RuntimeError::Denied);
        }
        let nonce = observer
            .rpc("eth_getTransactionCount", json!([sender, selector]))
            .await?;
        // A higher nonce can queue behind an earlier pending transaction. Only a
        // nonce already consumed in this canonical state is definitely stale here;
        // the durable sender/nonce claim separately prevents local conflicts.
        if quantity_u64(&nonce)? > transaction.nonce() {
            return Err(RuntimeError::Denied);
        }
        let balance = observer
            .rpc("eth_getBalance", json!([sender, selector]))
            .await?;
        let minimum_balance = maximum_cost(
            transaction.value(),
            transaction.maximum_fee(),
            transaction.gas_limit(),
        )?;
        if quantity(&balance)? < minimum_balance {
            return Err(RuntimeError::Denied);
        }
        // Detect a changed head or canonical mapping across the observations. A
        // fresh timestamp on an old certification block cannot satisfy this check.
        let final_header = observer
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        validate_header(&final_header, anchor.anchor(), transaction)?;
        revalidate()?;
        let completed_at_ms =
            crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let proof = WritePreflight {
            connection: record,
            request_digest: request.request_digest.clone(),
            transaction_hash: *transaction.hash(),
            anchor_digest: anchor.anchor().semantic_digest()?,
            route_witness_set_digest: route_witness_set_digest.clone(),
            started_at_ms,
            completed_at_ms,
            valid_until_ms,
            exchanges: observer.exchanges,
        };
        proof.validate(
            connection
                .record()
                .map_err(|_| RuntimeError::GenerationMismatch)?,
            request,
            transaction,
            anchor,
            route_witness_set_digest,
            completed_at_ms,
        )?;
        Ok(proof)
    }
}

/// Observe chain identity and the current head once. Current target route,
/// identity, policy and fact authority must precede every discovery exchange.
pub async fn select_anchor(
    connection: &ConnectionLease,
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<PreflightAnchor> {
    validate_submission(request, transaction)?;
    let invocation = request.invocation.as_ref().ok_or(RuntimeError::Denied)?;
    select_signed_anchor(
        connection,
        request,
        transaction,
        &invocation.genesis_digest,
        deadline,
        revalidate,
    )
    .await
}

pub async fn select_deployment_anchor(
    connection: &ConnectionLease,
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
    genesis_digest: &Digest,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<PreflightAnchor> {
    crate::governed_write::validate_runtime_signed_command(request, transaction)?;
    if request.deployment.is_none() || request.invocation.is_some() {
        return Err(RuntimeError::Denied);
    }
    select_signed_anchor(
        connection,
        request,
        transaction,
        genesis_digest,
        deadline,
        revalidate,
    )
    .await
}

async fn select_signed_anchor(
    connection: &ConnectionLease,
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
    genesis_digest: &Digest,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<PreflightAnchor> {
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let started_at_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let valid_until_ms = request.deadline_at_ms.min(record.valid_until_ms);
    if started_at_ms >= valid_until_ms || Instant::now() >= deadline {
        return Err(RuntimeError::BudgetExhausted);
    }
    let mut observer = Observer {
        connection,
        request_digest: &request.request_digest,
        deadline,
        revalidate,
        exchanges: Vec::with_capacity(MAX_CALLS),
        maximum_calls: MAX_CALLS,
        maximum_depth: 8,
        purpose: "preflight",
    };
    if quantity_u64(&observer.rpc("eth_chainId", json!([])).await?)? != transaction.chain_id() {
        return Err(RuntimeError::GenerationMismatch);
    }
    let genesis = observer
        .rpc("eth_getBlockByNumber", json!(["0x0", false]))
        .await?;
    if genesis.get("hash") != Some(&json!(rpc_hash(genesis_digest)))
        || genesis.get("number") != Some(&json!("0x0"))
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let header = observer
        .rpc("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    let proof = PreflightAnchor {
        connection: record,
        request_digest: request.request_digest.clone(),
        transaction_hash: *transaction.hash(),
        chain_id: transaction.chain_id(),
        header,
        observed_at_ns: crate::provider_connection::now_ms()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            * 1_000_000,
        started_at_ms,
        valid_until_ms,
        exchanges: observer.exchanges,
    };
    // Parse every selected identity before handing it to the independent signer.
    quantity_u64(&proof.header["number"])?;
    header_digest(&proof.header["hash"])?;
    header_digest(&proof.header["stateRoot"])?;
    validate_header_budget(&proof.header, transaction)?;
    revalidate()?;
    Ok(proof)
}

fn validate_submission(
    request: &RuntimeRequest,
    transaction: &SignedTransaction,
) -> RuntimeResult<()> {
    crate::governed_write::validate_runtime_submission(request, transaction)?;
    let invocation = request.invocation.as_ref().ok_or(RuntimeError::Denied)?;
    if invocation.proxy_address.is_some()
        || invocation.implementation_address.is_some()
        || invocation.implementation_code_digest.is_some()
        || !invocation.nested_calls.is_empty()
    {
        return Err(RuntimeError::Denied);
    }
    Ok(())
}
fn header_digest(value: &Value) -> RuntimeResult<Digest> {
    if data(value, 32)?.len() != 32 {
        return Err(RuntimeError::ResponseWithheld);
    }
    Digest::parse(&value.as_str().ok_or(RuntimeError::ResponseWithheld)?[2..])
        .map_err(|_| RuntimeError::ResponseWithheld)
}

pub(crate) fn validate_header(
    header: &Value,
    anchor: &ChainAnchor,
    transaction: &SignedTransaction,
) -> RuntimeResult<()> {
    if header.get("hash") != Some(&json!(rpc_hash(&anchor.block_hash)))
        || header.get("number") != Some(&json!(format!("0x{:x}", anchor.block_number)))
        || header.get("stateRoot") != Some(&json!(rpc_hash(&anchor.state_root)))
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    validate_header_budget(header, transaction)
}
fn validate_header_budget(header: &Value, transaction: &SignedTransaction) -> RuntimeResult<()> {
    if quantity_u64(&header["gasLimit"])? < transaction.gas_limit() {
        return Err(RuntimeError::GenerationMismatch);
    }
    if let Some(base_fee) = header.get("baseFeePerGas") {
        if quantity(base_fee)? > *transaction.maximum_fee() {
            return Err(RuntimeError::Denied);
        }
    } else if transaction.kind() == 2 {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(())
}

pub(crate) fn maximum_cost(value: &[u8; 32], fee: &[u8; 32], gas: u64) -> RuntimeResult<[u8; 32]> {
    let mut result = [0; 32];
    let mut carry = 0u128;
    for index in (0..32).rev() {
        let word = u128::from(fee[index]) * u128::from(gas) + u128::from(value[index]) + carry;
        result[index] = word as u8;
        carry = word >> 8;
    }
    if carry != 0 {
        return Err(RuntimeError::Denied);
    }
    Ok(result)
}
pub(crate) fn quantity(value: &Value) -> RuntimeResult<[u8; 32]> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .filter(|v| !v.is_empty() && v.len() <= 64 && (v.len() == 1 || !v.starts_with('0')))
        .ok_or(RuntimeError::ResponseWithheld)?;
    let mut out = [0; 32];
    for (index, byte) in text.bytes().rev().enumerate() {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        out[31 - index / 2] |= digit << ((index % 2) * 4);
    }
    Ok(out)
}
pub(crate) fn quantity_u64(value: &Value) -> RuntimeResult<u64> {
    let quantity = quantity(value)?;
    if quantity[..24].iter().any(|b| *b != 0) {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(u64::from_be_bytes(
        quantity[24..]
            .try_into()
            .map_err(|_| RuntimeError::ResponseWithheld)?,
    ))
}
pub(crate) fn data(value: &Value, maximum: usize) -> RuntimeResult<Vec<u8>> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .filter(|v| v.len() % 2 == 0 && v.len() / 2 <= maximum)
        .ok_or(RuntimeError::ResponseWithheld)?;
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(RuntimeError::ResponseWithheld),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}
pub(crate) fn rpc_hash(digest: &Digest) -> String {
    format!("0x{}", digest.as_str())
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monetary_checks_preserve_full_width_and_reject_overflow() {
        let mut value = [0; 32];
        value[31] = 3;
        let mut fee = [0; 32];
        fee[31] = 2;
        let mut expected = [0; 32];
        expected[29..].copy_from_slice(&[3, 13, 67]);
        assert_eq!(maximum_cost(&value, &fee, 100_000).unwrap(), expected);
        assert_eq!(maximum_cost(&[0; 32], &[255; 32], 1).unwrap(), [255; 32]);
        assert!(maximum_cost(&value, &[255; 32], 1).is_err());
        assert!(maximum_cost(&[0; 32], &[255; 32], u64::MAX).is_err());
        assert_eq!(
            quantity(&json!(format!("0x{}", "f".repeat(64)))).unwrap(),
            [255; 32]
        );
        for invalid in [
            json!("0x"),
            json!("0x00"),
            json!("0xF"),
            json!(1),
            json!(format!("0x1{}", "0".repeat(64))),
        ] {
            assert!(quantity(&invalid).is_err());
        }
        assert!(quantity_u64(&json!("0x10000000000000000")).is_err());
        assert_eq!(data(&json!("0x6000"), 2).unwrap(), vec![0x60, 0]);
        assert!(data(&json!("0x6000"), 1).is_err());
        assert!(data(&json!("0x6"), 2).is_err());
    }
}
