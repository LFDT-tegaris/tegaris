//! Minimized preflight identity and exact mined-path comparison. These records
//! are observation work, never grants, profile promotion or permission to retry.
use super::{TraceInspection, TraceRoot, inspect_geth_trace};
use crate::{deployment::keccak, signed_transaction::SignedTransaction};
use pc_policy_core::cigl::TraceLimits;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostMineExpectation {
    profile_digest: Digest,
    path_digest: Digest,
    sender: [u8; 20],
    destination: [u8; 20],
    input_hash: [u8; 32],
    value: [u8; 32],
    gas_limit: u64,
    limits: TraceLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostMineComparison {
    pub profile_digest: Digest,
    pub expected_path_digest: Digest,
    pub observed_path_digest: Digest,
}
impl PostMineComparison {
    pub fn diverged(&self) -> bool {
        self.expected_path_digest != self.observed_path_digest
    }
    pub(crate) fn validate(&self, expected: &PostMineExpectation) -> RuntimeResult<()> {
        if self.profile_digest != expected.profile_digest
            || self.expected_path_digest != expected.path_digest
            || Digest::parse(self.observed_path_digest.as_str()).is_err()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
}
impl PostMineExpectation {
    pub fn capture(
        transaction: &SignedTransaction,
        inspection: &TraceInspection,
        profile_digest: Digest,
    ) -> RuntimeResult<Self> {
        let root = inspection
            .frames()
            .first()
            .ok_or(RuntimeError::InvalidInput)?;
        if root.caller() != transaction.signer()
            || Some(root.target()) != transaction.destination()
            || root.input() != transaction.data()
            || root.message_value() != transaction.value()
            || root.failed()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let value = Self {
            profile_digest,
            path_digest: inspection.path_digest()?,
            sender: *transaction.signer(),
            destination: *transaction.destination().ok_or(RuntimeError::Denied)?,
            input_hash: keccak(transaction.data()),
            value: *transaction.value(),
            gas_limit: transaction.gas_limit(),
            limits: inspection.limits(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> RuntimeResult<()> {
        self.limits.validate()?;
        if self.gas_limit == 0
            || self.profile_digest == Digest::of([])
            || self.path_digest == Digest::of([])
            || Digest::parse(self.profile_digest.as_str()).is_err()
            || Digest::parse(self.path_digest.as_str()).is_err()
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
    pub(crate) fn validate_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> RuntimeResult<()> {
        self.validate()?;
        if transaction.signer() != &self.sender
            || transaction.destination() != Some(&self.destination)
            || keccak(transaction.data()) != self.input_hash
            || transaction.value() != &self.value
            || transaction.gas_limit() != self.gas_limit
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub(crate) fn limits(&self) -> TraceLimits {
        self.limits
    }
    pub(crate) fn compare(
        &self,
        call_trace: &[u8],
        opcode_trace: &[u8],
        reverted: bool,
    ) -> RuntimeResult<PostMineComparison> {
        self.validate()?;
        let value = crate::parse_strict_json(call_trace, self.limits.json_depth()?)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let input = crate::write_preflight::data(&value["input"], 131_072)?;
        if keccak(&input) != self.input_hash {
            return Err(RuntimeError::ResponseWithheld);
        }
        let root = TraceRoot {
            sender: self.sender,
            destination: Some(self.destination),
            creation_address: None,
            input: &input,
            value: self.value,
            gas_limit: self.gas_limit,
        };
        let trace =
            inspect_geth_trace(call_trace, &root, self.limits)?.cross_check_mined(opcode_trace)?;
        if trace
            .inspection()
            .frames()
            .first()
            .is_none_or(|root| root.failed() != reverted)
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        Ok(PostMineComparison {
            profile_digest: self.profile_digest.clone(),
            expected_path_digest: self.path_digest.clone(),
            observed_path_digest: trace.inspection().path_digest()?,
        })
    }
}
