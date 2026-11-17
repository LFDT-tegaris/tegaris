//! Closed single-creation evidence grammar for the reference D1/factory
//! adapter. Geth callTracer alone can miss an opcode attempt that fails before
//! a frame is entered; the complete opcode trace is required as a second view.
//! Tracer configuration and transport qualification remain the observer's job.
//! https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers
use super::{BoundDeployment, CreationMechanism, keccak};
use crate::evm_trace::ordinary_opcode;
use crate::signed_transaction::create_address;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::Serialize;
use serde_json::Value;

mod create3;

const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STEPS: usize = 25_000;
const MAX_FRAMES: usize = 64;
const MAX_DEPTH: u64 = 16;
const MAX_CODE_BYTES: usize = 24_576;

/// The matching result contains no raw trace, calldata, storage or return data.
/// It is not a grant, persistence/finality claim, or provider attestation. The
/// observer must bind these inputs to one exact simulation or mined transaction
/// and perform independent code, canonicality and finality checks.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CreationInspection {
    binding_digest: Digest,
    address: [u8; 20],
    runtime_code_hash: [u8; 32],
    call_trace_digest: Digest,
    opcode_trace_digest: Digest,
}
impl CreationInspection {
    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }
    pub(crate) fn runtime_code_hash(&self) -> [u8; 32] {
        self.runtime_code_hash
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:creation-inspection:v1", self)).map(Digest::of)
    }
}

impl BoundDeployment {
    /// Inspect provider-owned full callTracer and opcode-logger results. The
    /// nonce for symbolic factory CREATE must come from that same transaction's
    /// prestate owner, never a latest nonce or an actor's expected address.
    pub fn inspect_single_creation(
        &self,
        call_trace: &[u8],
        opcode_trace: &[u8],
        factory_prestate_nonce: Option<u64>,
    ) -> RuntimeResult<CreationInspection> {
        if self.mechanism == CreationMechanism::Create3 {
            if factory_prestate_nonce.is_some() {
                return Err(RuntimeError::InvalidInput);
            }
            return create3::inspect(self, call_trace, opcode_trace);
        }
        let address = match (
            self.mechanism,
            self.predicted_address,
            factory_prestate_nonce,
        ) {
            (CreationMechanism::Create, None, Some(nonce)) => create_address(&self.creator, nonce),
            (
                CreationMechanism::TransactionCreate | CreationMechanism::Create2,
                Some(address),
                None,
            ) => address,
            _ => return Err(RuntimeError::InvalidInput),
        };
        if call_trace.len() > MAX_TRACE_BYTES || opcode_trace.len() > MAX_TRACE_BYTES {
            return Err(RuntimeError::BudgetExhausted);
        }
        let call =
            crate::parse_strict_json(call_trace, 40).map_err(|_| RuntimeError::ResponseWithheld)?;
        let opcodes = crate::parse_strict_json(opcode_trace, 8)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let call_gas = quantity(&call["gasUsed"])?;
        let returned = match call.get("output") {
            Some(value) => data(value, MAX_CODE_BYTES)?,
            None => Vec::new(),
        };
        if call_gas > self.gas_limit || call_gas == 0 {
            return Err(RuntimeError::ResponseWithheld);
        }
        let mut frames = vec![(&call, 0usize)];
        let mut seen = 0;
        let mut creations = 0;
        while let Some((frame, depth)) = frames.pop() {
            seen += 1;
            if seen > MAX_FRAMES || depth > MAX_DEPTH as usize {
                return Err(RuntimeError::BudgetExhausted);
            }
            let object = frame.as_object().ok_or(RuntimeError::ResponseWithheld)?;
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type"
                        | "from"
                        | "to"
                        | "value"
                        | "gas"
                        | "gasUsed"
                        | "input"
                        | "output"
                        | "calls"
                        | "error"
                        | "revertReason"
                )
            }) || object.contains_key("error")
                || object.contains_key("revertReason")
            {
                return Err(RuntimeError::ResponseWithheld);
            }
            let kind = frame["type"]
                .as_str()
                .ok_or(RuntimeError::ResponseWithheld)?;
            let creation = matches!(kind, "CREATE" | "CREATE2");
            // Nested invocation authorization belongs to CIGL. This adapter's
            // closed single-creation profile cannot silently approve a call,
            // delegatecall, value transfer, selfdestruct or another creation.
            if depth > 0
                && (!creation
                    || depth != 1
                    || self.mechanism == CreationMechanism::TransactionCreate)
            {
                return Err(RuntimeError::Denied);
            }
            let from = address_field(&frame["from"])?;
            let to = address_field(&frame["to"])?;
            let input = data(&frame["input"], super::MAX_INIT_CODE_BYTES + 128)?;
            let value = quantity256(&frame["value"])?;
            if depth == 0 {
                let expected_type = if self.mechanism == CreationMechanism::TransactionCreate {
                    "CREATE"
                } else {
                    "CALL"
                };
                let expected_to = if creation { address } else { self.creator };
                if kind != expected_type
                    || from != self.sender
                    || to != expected_to
                    || keccak(&input) != self.calldata_hash
                    || value != self.transaction_value
                    || quantity(&frame["gas"])? != self.gas_limit
                {
                    return Err(RuntimeError::GenerationMismatch);
                }
            }
            if creation {
                creations += 1;
                let expected_type = if self.mechanism == CreationMechanism::Create2 {
                    "CREATE2"
                } else {
                    "CREATE"
                };
                let output = data(&frame["output"], MAX_CODE_BYTES)?;
                if creations != 1
                    || kind != expected_type
                    || from != self.creator
                    || to != address
                    || keccak(&input) != self.init_code_hash
                    || output.is_empty()
                    || keccak(&output) != self.runtime_code_hash
                    || (depth > 0 && value != [0; 32])
                {
                    return Err(RuntimeError::Denied);
                }
            }
            if let Some(children) = object.get("calls") {
                let children = children.as_array().ok_or(RuntimeError::ResponseWithheld)?;
                if children.len() > MAX_FRAMES || children.len() + seen > MAX_FRAMES {
                    return Err(RuntimeError::BudgetExhausted);
                }
                frames.extend(children.iter().rev().map(|child| (child, depth + 1)));
            }
        }
        if creations != 1 {
            return Err(RuntimeError::Denied);
        }
        inspect_opcodes(&opcodes, self.mechanism, call_gas, &returned)?;
        Ok(CreationInspection {
            binding_digest: self.digest()?,
            address,
            runtime_code_hash: self.runtime_code_hash,
            call_trace_digest: Digest::of(call_trace),
            opcode_trace_digest: Digest::of(opcode_trace),
        })
    }
}

fn inspect_opcodes(
    trace: &Value,
    mechanism: CreationMechanism,
    gas_used: u64,
    expected_return: &[u8],
) -> RuntimeResult<()> {
    let object = trace.as_object().ok_or(RuntimeError::ResponseWithheld)?;
    if object.len() != 4
        || trace["failed"] != Value::Bool(false)
        || trace["gas"].as_u64() != Some(gas_used)
        || !object.contains_key("returnValue")
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let returned = trace["returnValue"]
        .as_str()
        .ok_or(RuntimeError::ResponseWithheld)?;
    // The struct logger uses unprefixed returnValue, unlike callTracer output.
    if data(&Value::String(format!("0x{returned}")), MAX_CODE_BYTES)? != expected_return {
        return Err(RuntimeError::ResponseWithheld);
    }
    let steps = trace["structLogs"]
        .as_array()
        .ok_or(RuntimeError::ResponseWithheld)?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err(RuntimeError::BudgetExhausted);
    }
    let mut previous_depth = 1;
    let mut previous_op = "";
    let expected_entries: &[(&str, u64)] = match mechanism {
        CreationMechanism::TransactionCreate => &[],
        CreationMechanism::Create => &[("CREATE", 1)],
        CreationMechanism::Create2 => &[("CREATE2", 1)],
        CreationMechanism::Create3 => &[("CREATE2", 1), ("CALL", 1), ("CREATE", 2)],
    };
    let mut entries = 0;
    for step in steps {
        let step = step.as_object().ok_or(RuntimeError::ResponseWithheld)?;
        if step.get("error").is_some_and(|value| !value.is_null())
            || step.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "pc" | "op"
                        | "gas"
                        | "gasCost"
                        | "depth"
                        | "error"
                        | "refund"
                        | "memSize"
                        | "memory"
                        | "stack"
                        | "storage"
                        | "returnData"
                )
            })
            || ["memory", "stack", "storage", "returnData"]
                .iter()
                .any(|key| step.get(*key).is_some_and(|value| !value.is_null()))
            || ["pc", "gas", "gasCost"]
                .iter()
                .any(|key| step.get(*key).and_then(Value::as_u64).is_none())
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let depth = step
            .get("depth")
            .and_then(Value::as_u64)
            .ok_or(RuntimeError::ResponseWithheld)?;
        if depth == 0
            || depth
                > if mechanism == CreationMechanism::Create3 {
                    3
                } else {
                    2
                }
            || depth > previous_depth + 1
            || (depth > previous_depth && !matches!(previous_op, "CREATE" | "CREATE2" | "CALL"))
            || (matches!(previous_op, "CREATE" | "CREATE2" | "CALL") && depth != previous_depth + 1)
            || (depth == previous_depth && matches!(previous_op, "STOP" | "RETURN"))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        previous_depth = depth;
        let op = step
            .get("op")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::ResponseWithheld)?;
        previous_op = op;
        match op {
            "CREATE" | "CREATE2" | "CALL" => {
                if expected_entries.get(entries) != Some(&(op, depth)) {
                    return Err(RuntimeError::Denied);
                }
                entries += 1;
            }
            "SELFDESTRUCT" | "SUICIDE" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" | "REVERT"
            | "INVALID" => return Err(RuntimeError::Denied),
            _ if ordinary_opcode(op) => {}
            _ => return Err(RuntimeError::ResponseWithheld),
        }
    }
    if entries != expected_entries.len()
        || steps[0]["depth"].as_u64() != Some(1)
        || previous_depth != 1
        || !matches!(
            steps.last().and_then(|step| step["op"].as_str()),
            Some("RETURN" | "STOP")
        )
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(())
}

fn data(value: &Value, max: usize) -> RuntimeResult<Vec<u8>> {
    let text = value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RuntimeError::ResponseWithheld)?;
    if text.len() > max * 2
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| {
            let text = std::str::from_utf8(bytes).map_err(|_| RuntimeError::ResponseWithheld)?;
            u8::from_str_radix(text, 16).map_err(|_| RuntimeError::ResponseWithheld)
        })
        .collect()
}
fn address_field(value: &Value) -> RuntimeResult<[u8; 20]> {
    data(value, 20)?
        .try_into()
        .map_err(|_| RuntimeError::ResponseWithheld)
}
fn quantity256(value: &Value) -> RuntimeResult<[u8; 32]> {
    let text = value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or(RuntimeError::ResponseWithheld)?;
    if text.is_empty() || text.len() > 64 || (text.len() > 1 && text.starts_with('0')) {
        return Err(RuntimeError::ResponseWithheld);
    }
    let padded = if text.len() % 2 == 0 {
        format!("0x{text}")
    } else {
        format!("0x0{text}")
    };
    let bytes = data(&Value::String(padded), 32)?;
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(word)
}
fn quantity(value: &Value) -> RuntimeResult<u64> {
    let word = quantity256(value)?;
    if word[..24] != [0; 24] {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(u64::from_be_bytes(
        word[24..]
            .try_into()
            .map_err(|_| RuntimeError::ResponseWithheld)?,
    ))
}
