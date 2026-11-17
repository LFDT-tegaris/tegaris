//! Provider trace classification for CIGL. Inspection is non-granting evidence;
//! the live provider, exact state anchor, active profile, registered targets and
//! all applicable root/nested permissions remain separate required owners.
use crate::signed_transaction::{SignedTransaction, create_address};
use pc_policy_core::cigl::{CallKind, TraceLimits};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::Serialize;
use serde_json::Value;

pub mod analysis;
pub mod authorization;
mod geth;
pub mod observer;
mod opcodes;
pub mod reconciliation;

/// Exact transaction fields from the signed-byte owner, also usable by the
/// separately authenticated read/prepare owner. This grants no tracing rights.
pub struct TraceRoot<'a> {
    pub sender: [u8; 20],
    pub destination: Option<[u8; 20]>,
    pub creation_address: Option<[u8; 20]>,
    pub input: &'a [u8],
    pub value: [u8; 32],
    pub gas_limit: u64,
}
impl<'a> TraceRoot<'a> {
    pub fn for_signed(transaction: &'a SignedTransaction) -> Self {
        let destination = transaction.destination().copied();
        Self {
            sender: *transaction.signer(),
            destination,
            creation_address: destination
                .is_none()
                .then(|| create_address(transaction.signer(), transaction.nonce())),
            input: transaction.data(),
            value: *transaction.value(),
            gas_limit: transaction.gas_limit(),
        }
    }
}

/// Raw call data stays ephemeral and is intentionally neither Serialize nor
/// Debug. Public audit output uses only the minimized summaries below.
pub struct Frame {
    ordinal: u16,
    parent: Option<u16>,
    depth: u16,
    kind: CallKind,
    caller: [u8; 20],
    target: [u8; 20],
    execution_address: [u8; 20],
    message_value: [u8; 32],
    input: Vec<u8>,
    gas: u64,
    gas_used: u64,
    output_hex_digest: Digest,
    failed: bool,
    static_context: bool,
}
impl Frame {
    pub fn kind(&self) -> CallKind {
        self.kind
    }
    pub fn caller(&self) -> &[u8; 20] {
        &self.caller
    }
    pub fn target(&self) -> &[u8; 20] {
        &self.target
    }
    pub fn execution_address(&self) -> &[u8; 20] {
        &self.execution_address
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn transferred_value(&self) -> [u8; 32] {
        if self.kind.transfers_value() {
            self.message_value
        } else {
            [0; 32]
        }
    }
    pub fn message_value(&self) -> &[u8; 32] {
        &self.message_value
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameSummary {
    ordinal: u16,
    parent: Option<u16>,
    depth: u16,
    kind: CallKind,
    identity_digest: Digest,
    calldata_digest: Digest,
    transferred_value_digest: Digest,
    failed: bool,
}

pub struct TraceInspection {
    trace_digest: Digest,
    limits: TraceLimits,
    frames: Vec<Frame>,
}
impl TraceInspection {
    /// Compare minimized interaction structure and inputs, never provider timing
    /// or gas accounting. The enclosing journal binds chain, actor and profile.
    pub fn path_digest(&self) -> RuntimeResult<Digest> {
        canonical_bytes(&("openpc:cigl-path:v1", self.summaries()?)).map(Digest::of)
    }
    pub fn limits(&self) -> TraceLimits {
        self.limits
    }
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
    pub fn trace_digest(&self) -> &Digest {
        &self.trace_digest
    }
    /// Cross-check every interaction opcode against the frame tree. Neither
    /// view may silently omit an attempted interaction, including failed calls.
    /// Provenance and exact-state acquisition are still separately required.
    pub fn cross_check(self, opcode_bytes: &[u8]) -> RuntimeResult<CrossCheckedTrace> {
        self.cross_check_outcome(opcode_bytes, false)
    }
    fn cross_check_mined(self, opcode_bytes: &[u8]) -> RuntimeResult<CrossCheckedTrace> {
        self.cross_check_outcome(opcode_bytes, true)
    }
    fn cross_check_outcome(
        self,
        opcode_bytes: &[u8],
        mined: bool,
    ) -> RuntimeResult<CrossCheckedTrace> {
        if opcode_bytes.is_empty() || opcode_bytes.len() > self.limits.max_response_bytes as usize {
            return Err(RuntimeError::BudgetExhausted);
        }
        let value = crate::parse_strict_json(opcode_bytes, 8)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let steps = if mined {
            opcodes::inspect_mined(&self, &value)?
        } else {
            opcodes::inspect(&self, &value)?
        };
        Ok(CrossCheckedTrace {
            inspection: self,
            opcode_digest: Digest::of(opcode_bytes),
            steps,
        })
    }
    pub fn summaries(&self) -> RuntimeResult<Vec<FrameSummary>> {
        self.frames
            .iter()
            .map(|frame| {
                Ok(FrameSummary {
                    ordinal: frame.ordinal,
                    parent: frame.parent,
                    depth: frame.depth,
                    kind: frame.kind,
                    identity_digest: Digest::of(canonical_bytes(&(
                        "openpc:cigl-frame-identity:v1",
                        frame.kind,
                        frame.caller,
                        frame.target,
                        frame.execution_address,
                    ))?),
                    calldata_digest: Digest::of(&frame.input),
                    transferred_value_digest: Digest::of(frame.transferred_value()),
                    failed: frame.failed,
                })
            })
            .collect()
    }
}

/// This cannot be deserialized from actor metadata. It describes two consistent
/// provider views, not current authorization or proof that the provider is honest.
pub struct CrossCheckedTrace {
    inspection: TraceInspection,
    opcode_digest: Digest,
    steps: usize,
}
impl CrossCheckedTrace {
    pub fn inspection(&self) -> &TraceInspection {
        &self.inspection
    }
    pub fn opcode_digest(&self) -> &Digest {
        &self.opcode_digest
    }
    pub fn steps(&self) -> usize {
        self.steps
    }
}

/// Decode the complete Geth callTracer tree with onlyTopCall=false/withLog=false.
/// This checks structural completeness, not provider honesty or opcode-attempt
/// completeness. The live acquisition owner must bind and cross-check evidence.
pub fn inspect_geth_trace(
    bytes: &[u8],
    root: &TraceRoot<'_>,
    limits: TraceLimits,
) -> RuntimeResult<TraceInspection> {
    limits.validate()?;
    if bytes.is_empty() || bytes.len() > limits.max_response_bytes as usize {
        return Err(RuntimeError::BudgetExhausted);
    }
    let value = crate::parse_strict_json(bytes, limits.json_depth()?)
        .map_err(|_| RuntimeError::ResponseWithheld)?;
    let frames = geth::inspect(&value, root, limits)?;
    Ok(TraceInspection {
        trace_digest: Digest::of(bytes),
        limits,
        frames,
    })
}

#[cfg(test)]
mod tests;
