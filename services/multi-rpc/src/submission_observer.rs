//! Exact-hash observation through a separately authorized recovery route. No
//! method here can submit, replace, rebroadcast or inspect a transaction pool.
use super::{
    ObservationEvidence, ObservationState, ObservationTarget, ObservedBlock, VerifiedObservation,
};
use crate::{
    provider_connection::ConnectionLease,
    route_witness::{VerifiedChainAnchor, VerifiedRouteWitness},
    submission_status::{ChainObservation, ExecutionOutcome},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde_json::{Value, json};
use tokio::time::Instant;

const MAX_CALLS: usize = 8;

fn deployment_helper(constraints: &crate::deployment::DeploymentConstraints) -> Option<[u8; 20]> {
    match &constraints.route {
        crate::deployment::DeploymentRoute::Factory(factory) => match factory.mechanism {
            crate::deployment::FactoryMechanism::Create3 {
                expected_helper_address,
                ..
            } => Some(expected_helper_address),
            _ => None,
        },
        _ => None,
    }
}

struct Observer<'a> {
    target: &'a ObservationTarget,
    connection: &'a ConnectionLease,
    deadline: Instant,
    revalidate: &'a (dyn Fn() -> RuntimeResult<()> + Sync),
    exchanges: Vec<(Digest, Digest)>,
}
impl Observer<'_> {
    async fn rpc(&mut self, method: &str, params: Value) -> RuntimeResult<Value> {
        let maximum = self.target.admission.observation_call_budget();
        if self.exchanges.len() >= maximum || Instant::now() >= self.deadline {
            return Err(RuntimeError::BudgetExhausted);
        }
        (self.revalidate)()?;
        let id = format!(
            "observe:{}:{}",
            self.target.command.command_id,
            self.exchanges.len()
        );
        let body = crate::rfc8785_canonical_bytes(
            &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        )
        .map_err(|_| RuntimeError::InvalidInput)?;
        let request_digest = Digest::of(&body);
        let response = self
            .connection
            .connection()
            .map_err(|_| RuntimeError::GenerationMismatch)?
            .post_json(body, self.deadline)
            .await
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let trace_limits = (method == "debug_traceTransaction")
            .then(|| {
                self.target
                    .admission
                    .cigl_post_mine
                    .as_ref()
                    .map(|expected| expected.limits())
            })
            .flatten();
        let byte_limit =
            trace_limits.map_or(4 * 1024 * 1024, |limits| limits.max_response_bytes as usize);
        if response.len() > byte_limit {
            return Err(RuntimeError::BudgetExhausted);
        }
        let value = crate::parse_strict_json(
            &response,
            if method == "debug_traceTransaction" {
                match trace_limits {
                    Some(limits) => limits.json_depth()?,
                    None => 40,
                }
            } else {
                12
            },
        )
        .map_err(|_| RuntimeError::ResponseWithheld)?;
        let object = value.as_object().ok_or(RuntimeError::ResponseWithheld)?;
        if object.len() != 3
            || object.get("id") != Some(&json!(id))
            || object.get("jsonrpc") != Some(&json!("2.0"))
            || !object.contains_key("result")
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        self.exchanges.push((request_digest, Digest::of(response)));
        Ok(object["result"].clone())
    }
    async fn header(&mut self, selector: Value) -> RuntimeResult<Value> {
        self.rpc("eth_getBlockByNumber", json!([selector, false]))
            .await
    }
    async fn classify(&mut self) -> RuntimeResult<Option<ObservationState>> {
        let chain = self
            .target
            .admission
            .chain
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if quantity(&self.rpc("eth_chainId", json!([])).await?)? != self.target.signed.chain_id {
            return Err(RuntimeError::GenerationMismatch);
        }
        let genesis = self.header(json!("0x0")).await?;
        if quantity(&genesis["number"])? != 0 || hash(&genesis["hash"])? != chain.genesis_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(prior) = &self.target.prior
            && prior.is_finalized()
            && prior.creation.is_some()
        {
            return self.check_finalized_creation(prior.clone()).await;
        }
        if let Some(prior) = &self.target.prior
            && prior.is_finalized()
            && prior.cigl_post_mine.is_some()
        {
            let block = prior
                .block
                .as_ref()
                .ok_or(RuntimeError::InvalidAuthorization)?;
            let canonical = self.header(json!(format!("0x{:x}", block.number))).await?;
            return Ok(Some(if same_block(&canonical, block)? {
                prior.clone()
            } else {
                reorged(block.clone())
            }));
        }
        let transaction_hash = self.target.command.request_or_transaction_hash.clone();
        let receipt = self
            .rpc("eth_getTransactionReceipt", json!([transaction_hash]))
            .await?;
        if receipt.is_null() {
            let transaction = self
                .rpc("eth_getTransactionByHash", json!([transaction_hash]))
                .await?;
            if !transaction.is_null() {
                self.validate_transaction(&transaction)?;
                if transaction.get("blockHash").is_none()
                    || transaction.get("blockNumber").is_none()
                {
                    return Err(RuntimeError::ResponseWithheld);
                }
            }
            if let Some(prior) = &self.target.prior
                && let Some(block) = &prior.block
                && prior.observation != ChainObservation::Reorged
            {
                let canonical = self.header(json!(format!("0x{:x}", block.number))).await?;
                return if !same_block(&canonical, block)? {
                    Ok(Some(reorged(block.clone())))
                } else {
                    Ok(None)
                };
            }
            return if transaction.is_null() {
                Ok(None)
            } else {
                if !transaction["blockHash"].is_null() || !transaction["blockNumber"].is_null() {
                    // A mined transaction without its receipt is not execution
                    // evidence. Preserve prior truth while the index catches up.
                    return Ok(None);
                }
                Ok(Some(ObservationState {
                    cigl_post_mine: None,
                    creation: None,
                    observation: ChainObservation::MempoolObserved,
                    execution: ExecutionOutcome::Unknown,
                    block: None,
                }))
            };
        }
        if receipt["transactionHash"] != json!(transaction_hash)
            || receipt["from"] != json!(hex(&self.target.signed.signer))
            || receipt.get("to")
                != Some(&json!(
                    self.target
                        .admission
                        .transaction_destination()
                        .map(|value| hex(value))
                ))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let block = ObservedBlock {
            number: quantity(&receipt["blockNumber"])?,
            hash: hash(&receipt["blockHash"])?,
        };
        let execution = match quantity(&receipt["status"])? {
            0 => ExecutionOutcome::Reverted,
            1 => ExecutionOutcome::Success,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        if let Some(deployment) = &self.target.admission.deployment {
            let expected = match &deployment.constraints.route {
                crate::deployment::DeploymentRoute::DirectCreate { expected_address }
                    if execution == ExecutionOutcome::Success =>
                {
                    json!(hex(expected_address))
                }
                _ => Value::Null,
            };
            // Inclusion is not an occurrence/association proof. It still must
            // identify the independently derived creation destination exactly.
            if receipt.get("contractAddress") != Some(&expected) {
                return Err(RuntimeError::ResponseWithheld);
            }
        }
        let index = usize::try_from(quantity(&receipt["transactionIndex"])?)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let canonical = self.header(json!(format!("0x{:x}", block.number))).await?;
        if !same_block(&canonical, &block)? {
            let invalidated = self
                .target
                .prior
                .as_ref()
                .filter(|prior| prior.observation != ChainObservation::Reorged)
                .and_then(|prior| prior.block.clone())
                .unwrap_or(block);
            return Ok(Some(reorged(invalidated)));
        }
        let transactions = canonical["transactions"]
            .as_array()
            .filter(|v| v.len() <= 4096)
            .ok_or(RuntimeError::ResponseWithheld)?;
        if transactions.get(index) != Some(&json!(transaction_hash))
            || transactions
                .iter()
                .filter(|hash| **hash == json!(transaction_hash))
                .count()
                != 1
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        if let Some(prior) = &self.target.prior
            && prior.observation != ChainObservation::Reorged
            && let Some(previous) = &prior.block
            && previous != &block
        {
            // Publish invalidation of the old inclusion before a later cycle
            // admits the reminted receipt. The attempt remains non-repeatable.
            return Ok(Some(reorged(previous.clone())));
        }
        let mut creation = None;
        if execution == ExecutionOutcome::Success
            && let Some(deployment) = &self.target.admission.deployment
        {
            let expected_hash = deployment.constraints.artifact.runtime_code_hash;
            let helper = deployment_helper(&deployment.constraints);
            let address = if deployment.transaction.is_some() {
                let inspected = self.mined_creation().await?;
                let address = json!(hex(&inspected.address));
                creation = Some(inspected);
                address
            } else {
                // Legacy direct submissions lack trace identity. Preserve their
                // existing status readback without inventing complete evidence.
                receipt["contractAddress"].clone()
            };
            let code = self
                .rpc(
                    "eth_getCode",
                    json!([address, {
                        "blockHash": format!("0x{}", block.hash.as_str()), "requireCanonical": true
                    }]),
                )
                .await?;
            let code = crate::write_preflight::data(&code, 24_576)?;
            if code.is_empty() || crate::deployment::keccak(&code) != expected_hash {
                return Err(RuntimeError::ResponseWithheld);
            }
            if !self.helper_code_matches(helper, &block).await? {
                return Err(RuntimeError::ResponseWithheld);
            }
        }
        let cigl_post_mine = self.mined_cigl(execution).await?;
        let finalized = self.header(json!("finalized")).await?;
        let observation = if !finalized.is_null() && quantity(&finalized["number"])? >= block.number
        {
            let finalized_block = ObservedBlock {
                number: quantity(&finalized["number"])?,
                hash: hash(&finalized["hash"])?,
            };
            let final_canonical = self
                .header(json!(format!("0x{:x}", finalized_block.number)))
                .await?;
            if !same_block(&final_canonical, &finalized_block)? {
                return Err(RuntimeError::GenerationMismatch);
            }
            ChainObservation::Finalized
        } else {
            let safe = self.header(json!("safe")).await?;
            if !safe.is_null() && quantity(&safe["number"])? >= block.number {
                let safe_block = ObservedBlock {
                    number: quantity(&safe["number"])?,
                    hash: hash(&safe["hash"])?,
                };
                let safe_canonical = self
                    .header(json!(format!("0x{:x}", safe_block.number)))
                    .await?;
                if !same_block(&safe_canonical, &safe_block)? {
                    return Err(RuntimeError::GenerationMismatch);
                }
                ChainObservation::Safe
            } else {
                ChainObservation::Included
            }
        };
        let closure = self.header(json!(format!("0x{:x}", block.number))).await?;
        if !same_block(&closure, &block)? {
            return Ok(Some(reorged(block)));
        }
        Ok(Some(ObservationState {
            cigl_post_mine,
            creation,
            observation,
            execution,
            block: Some(block),
        }))
    }
    async fn mined_cigl(
        &mut self,
        execution: ExecutionOutcome,
    ) -> RuntimeResult<Option<crate::cigl::reconciliation::PostMineComparison>> {
        let Some(expected) = self.target.admission.cigl_post_mine.clone() else {
            return Ok(None);
        };
        let limits = expected.limits();
        self.deadline = self
            .deadline
            .min(Instant::now() + std::time::Duration::from_millis(u64::from(limits.timeout_ms)));
        let hash = self.target.command.request_or_transaction_hash.clone();
        let timeout = format!("{}ms", limits.timeout_ms);
        let calls = self
            .rpc(
                "debug_traceTransaction",
                json!([hash, {
                    "tracer":"callTracer", "timeout":timeout,
                    "tracerConfig":{"onlyTopCall":false,"withLog":false}
                }]),
            )
            .await?;
        let call_bytes =
            crate::rfc8785_canonical_bytes(&calls).map_err(|_| RuntimeError::ResponseWithheld)?;
        drop(calls);
        let opcodes = self
            .rpc(
                "debug_traceTransaction",
                json!([hash, {
                    "timeout":timeout,"enableMemory":false,"disableStack":true,
                    "disableStorage":true,"enableReturnData":false,"limit":0
                }]),
            )
            .await?;
        let opcode_bytes =
            crate::rfc8785_canonical_bytes(&opcodes).map_err(|_| RuntimeError::ResponseWithheld)?;
        expected
            .compare(
                &call_bytes,
                &opcode_bytes,
                execution == ExecutionOutcome::Reverted,
            )
            .map(Some)
    }
    /// Finalized monitoring uses canonical block/code checks, not repeated full
    /// transaction traces. Invalidation cannot reopen the terminal send fence.
    async fn check_finalized_creation(
        &mut self,
        prior: ObservationState,
    ) -> RuntimeResult<Option<ObservationState>> {
        let block = prior.block.ok_or(RuntimeError::InvalidAuthorization)?;
        let creation = prior.creation.ok_or(RuntimeError::InvalidAuthorization)?;
        let original = self.header(json!(format!("0x{:x}", block.number))).await?;
        if !same_block(&original, &block)? {
            return Ok(Some(reorged(block)));
        }
        let current = self.header(json!("latest")).await?;
        let current_block = ObservedBlock {
            number: quantity(&current["number"])?,
            hash: hash(&current["hash"])?,
        };
        if current_block.number < block.number {
            return Err(RuntimeError::ResponseWithheld);
        }
        let code = self
            .rpc(
                "eth_getCode",
                json!([hex(&creation.address), {
                    "blockHash":format!("0x{}",current_block.hash.as_str()), "requireCanonical":true
                }]),
            )
            .await?;
        let code = crate::write_preflight::data(&code, 24_576)?;
        let helper = self
            .target
            .admission
            .deployment
            .as_ref()
            .and_then(|deployment| deployment_helper(&deployment.constraints));
        let helper_matches = self.helper_code_matches(helper, &current_block).await?;
        let closure = self
            .header(json!(format!("0x{:x}", current_block.number)))
            .await?;
        if !same_block(&closure, &current_block)? {
            return Err(RuntimeError::GenerationMismatch);
        }
        let original = self.header(json!(format!("0x{:x}", block.number))).await?;
        if !same_block(&original, &block)? {
            return Ok(Some(reorged(block)));
        }
        let expected = self
            .target
            .admission
            .deployment
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .constraints
            .artifact
            .runtime_code_hash;
        if code.is_empty() || crate::deployment::keccak(&code) != expected || !helper_matches {
            Ok(Some(ObservationState {
                cigl_post_mine: None,
                observation: ChainObservation::Invalidated,
                execution: ExecutionOutcome::Unknown,
                block: Some(block),
                creation: None,
            }))
        } else {
            Ok(None)
        }
    }

    async fn helper_code_matches(
        &mut self,
        helper: Option<[u8; 20]>,
        block: &ObservedBlock,
    ) -> RuntimeResult<bool> {
        let Some(helper) = helper else {
            return Ok(true);
        };
        let code = self
            .rpc(
                "eth_getCode",
                json!([hex(&helper), {
                    "blockHash":format!("0x{}", block.hash.as_str()), "requireCanonical":true
                }]),
            )
            .await?;
        Ok(crate::write_preflight::data(&code, 24_576)?
            == pc_policy_core::deployment_policy::CREATE3_HELPER_RUNTIME_CODE)
    }

    async fn mined_creation(&mut self) -> RuntimeResult<crate::deployment::MinedCreationEvidence> {
        use crate::deployment::{BoundDeployment, DeploymentRoute, MinedCreationEvidence};
        let deployment = self
            .target
            .admission
            .deployment
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if deployment.constraints.sender != self.target.signed.signer
            || deployment.constraints.chain_id != self.target.signed.chain_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bound = BoundDeployment::for_observation(
            &deployment.constraints,
            self.target.signed.transaction_hash,
            deployment
                .transaction
                .as_ref()
                .ok_or(RuntimeError::InvalidAuthorization)?,
        )?;
        let constraints = deployment.constraints.clone();
        let nonce = match &constraints.route {
            DeploymentRoute::DirectCreate { .. } => None,
            DeploymentRoute::Factory(factory) => self.factory_prestate_nonce(factory).await?,
        };
        let transaction_hash = self.target.command.request_or_transaction_hash.clone();
        let call = self.rpc("debug_traceTransaction", json!([transaction_hash, {
            "tracer":"callTracer", "timeout":"5s", "tracerConfig":{"onlyTopCall":false,"withLog":false}
        }])).await?;
        let opcodes = self.rpc("debug_traceTransaction", json!([transaction_hash, {
            "timeout":"5s", "enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0
        }])).await?;
        let call =
            crate::rfc8785_canonical_bytes(&call).map_err(|_| RuntimeError::ResponseWithheld)?;
        let opcodes =
            crate::rfc8785_canonical_bytes(&opcodes).map_err(|_| RuntimeError::ResponseWithheld)?;
        let inspection = bound.inspect_single_creation(&call, &opcodes, nonce)?;
        MinedCreationEvidence::from_inspection(&inspection, &constraints, nonce)
    }

    async fn factory_prestate_nonce(
        &mut self,
        factory: &crate::deployment::FactoryDeployment,
    ) -> RuntimeResult<Option<u64>> {
        let transaction_hash = self.target.command.request_or_transaction_hash.clone();
        // Named Geth-compatible primitives only. Prestate is transaction-local,
        // not a latest or block-start nonce, and storage capture is disabled.
        // https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers
        let prestate = self
            .rpc(
                "debug_traceTransaction",
                json!([transaction_hash, {
                    "tracer":"prestateTracer", "timeout":"5s",
                    "tracerConfig":{"diffMode":false,"disableCode":false,"disableStorage":true}
                }]),
            )
            .await?;
        let accounts = prestate
            .as_object()
            .filter(|accounts| accounts.len() <= 64)
            .ok_or(RuntimeError::ResponseWithheld)?;
        let account = accounts
            .get(&hex(&factory.address))
            .and_then(Value::as_object)
            .ok_or(RuntimeError::ResponseWithheld)?;
        if account
            .keys()
            .any(|key| !matches!(key.as_str(), "balance" | "nonce" | "code"))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let code = crate::write_preflight::data(
            account.get("code").ok_or(RuntimeError::ResponseWithheld)?,
            24_576,
        )?;
        if code.is_empty()
            || crate::deployment::keccak(&code) != factory.code_hash
            || Digest::of(&code) != factory.code_digest
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        if matches!(
            factory.mechanism,
            crate::deployment::FactoryMechanism::Create
        ) {
            Ok(Some(
                account
                    .get("nonce")
                    .and_then(Value::as_u64)
                    .ok_or(RuntimeError::ResponseWithheld)?,
            ))
        } else {
            Ok(None)
        }
    }

    fn validate_transaction(&self, transaction: &Value) -> RuntimeResult<()> {
        if transaction["hash"] != json!(self.target.command.request_or_transaction_hash)
            || transaction["from"] != json!(hex(&self.target.signed.signer))
            || transaction.get("to")
                != Some(&json!(
                    self.target
                        .admission
                        .transaction_destination()
                        .map(|value| hex(value))
                ))
            || quantity(&transaction["nonce"])? != self.target.signed.nonce
            || transaction
                .get("chainId")
                .is_some_and(|v| quantity(v) != Ok(self.target.signed.chain_id))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        Ok(())
    }
}

/// The target's recovery owner validates the signature trust, installed
/// observation-only provider profile and current route/fact fences. The signed
/// witness must bind this exact operation and its persisted chain identity.
pub async fn observe_submission(
    target: &ObservationTarget,
    connection: &ConnectionLease,
    anchor: &VerifiedChainAnchor,
    witness: &VerifiedRouteWitness,
    deadline: Instant,
    revalidate: &(dyn Fn() -> RuntimeResult<()> + Sync),
) -> RuntimeResult<VerifiedObservation> {
    let chain = target
        .admission
        .chain
        .as_ref()
        .ok_or(RuntimeError::InvalidAuthorization)?;
    let record = connection
        .record()
        .map_err(|_| RuntimeError::GenerationMismatch)?
        .clone();
    let route = witness.witness();
    let now_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    if route.purpose != 4
        || route.operation_digest != target.operation_digest
        || route.request_digest.as_str() != target.command.immutable_request_digest
        || route.chain_anchor != *anchor.anchor()
        || route.chain_anchor.chain_id != target.signed.chain_id
        || route.chain_anchor.chain_environment_id != chain.chain_environment_id
        || route.endpoint_id != record.endpoint_id
        || now_ms * 1_000_000 < route.selected_at_ns
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    anchor.revalidate_time(now_ms * 1_000_000)?;
    let valid_until_ms = (route.selection_deadline_ns / 1_000_000)
        .min(anchor.valid_until_ns() / 1_000_000)
        .min(record.valid_until_ms)
        .min(now_ms.saturating_add(5_000));
    if now_ms >= valid_until_ms || deadline <= Instant::now() {
        return Err(RuntimeError::BudgetExhausted);
    }
    let deadline =
        deadline.min(Instant::now() + std::time::Duration::from_millis(valid_until_ms - now_ms));
    let mut observer = Observer {
        target,
        connection,
        deadline,
        revalidate,
        exchanges: Vec::with_capacity(MAX_CALLS),
    };
    let state = observer.classify().await?;
    if let Some(state) = &state {
        state
            .validate_successor(target.prior.as_ref(), target.monitors_replacement)
            .map_err(|_| RuntimeError::GenerationMismatch)?;
    }
    revalidate()?;
    let completed_at_ms =
        crate::provider_connection::now_ms().map_err(|_| RuntimeError::RuntimeUnavailable)?;
    let proof = VerifiedObservation {
        evidence: ObservationEvidence {
            version: Some(2),
            target_head: target.head.clone(),
            operation_id: target.command.command_id.clone(),
            attempt_id: target.command.attempt_id.clone(),
            transaction_hash: target.signed.transaction_hash,
            connection: record,
            route_witness_digest: route.semantic_digest()?,
            state,
            completed_at_ms,
            valid_until_ms,
            exchanges: observer.exchanges,
        },
    };
    proof.validate_binding(
        target,
        connection
            .record()
            .map_err(|_| RuntimeError::GenerationMismatch)?,
        &route.semantic_digest()?,
        completed_at_ms,
    )?;
    Ok(proof)
}

fn reorged(block: ObservedBlock) -> ObservationState {
    ObservationState {
        cigl_post_mine: None,
        creation: None,
        observation: ChainObservation::Reorged,
        execution: ExecutionOutcome::Unknown,
        block: Some(block),
    }
}
fn same_block(header: &Value, block: &ObservedBlock) -> RuntimeResult<bool> {
    if header.is_null() {
        return Err(RuntimeError::ResponseWithheld);
    }
    if quantity(&header["number"])? != block.number {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(hash(&header["hash"])? == block.hash)
}
fn quantity(value: &Value) -> RuntimeResult<u64> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 16
                && (v.len() == 1 || !v.starts_with('0'))
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(RuntimeError::ResponseWithheld)?;
    u64::from_str_radix(text, 16).map_err(|_| RuntimeError::ResponseWithheld)
}
fn hash(value: &Value) -> RuntimeResult<Digest> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or(RuntimeError::ResponseWithheld)?;
    Digest::parse(text).map_err(|_| RuntimeError::ResponseWithheld)
}
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
