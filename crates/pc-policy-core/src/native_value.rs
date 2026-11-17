//! NativeValueAuthorizationV1 and the deployment amount intersection.
//! These data and checks do not issue authority. The authenticated Native Value
//! owner supplies the grant; durable handoff/journal custody owns its one use.
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeValueAmountMode {
    Exact,
    Maximum,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativeValuePurpose {
    #[serde(rename = "CONTRACT_CREATION_ENDOWMENT")]
    ContractCreationEndowment,
}

/// Exact public document. Privacy and target custody belong to the outer
/// authenticated owner and must not be injected as extra document properties.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeValueAuthorizationV1 {
    pub authorization_id: String,
    pub participant_id: String,
    pub participant_epoch: u64,
    pub actor_subject_id: String,
    pub chain_environment_id: String,
    pub chain_id: String,
    pub genesis_hash: Digest,
    pub purpose: NativeValuePurpose,
    pub amount_mode: NativeValueAmountMode,
    pub max_amount_wei: String,
    pub one_use: bool,
    pub used: bool,
    pub policy_decision_digest: Digest,
    pub valid_until: String,
    pub semantic_digest: Digest,
}

impl NativeValueAuthorizationV1 {
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        if bytes.len() > 4096 {
            return Err(RuntimeError::BudgetExhausted);
        }
        // Decode directly into the closed struct so repeated properties are
        // rejected before a JSON object map could silently collapse them.
        let value: Self = serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        value.validate()?;
        Ok(value)
    }

    pub fn document_bytes(&self) -> RuntimeResult<Vec<u8>> {
        self.validate()?;
        canonical_bytes(&serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?)
    }

    pub fn computed_digest(&self) -> RuntimeResult<Digest> {
        let mut value = serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?;
        value
            .as_object_mut()
            .ok_or(RuntimeError::InvalidInput)?
            .remove("semanticDigest");
        // Sorted JSON object keys and exact integer serialization preserve the
        // The uint64 epoch must remain exact through conversion.
        Ok(Digest::of(canonical_bytes(&value)?))
    }

    pub fn valid_until_ns(&self) -> RuntimeResult<i128> {
        OffsetDateTime::parse(&self.valid_until, &Rfc3339)
            .map(|instant| instant.unix_timestamp_nanos())
            .map_err(|_| RuntimeError::InvalidAuthorization)
    }

    /// Historical used/expired documents remain valid records, but the amount
    /// intersection below never admits them for a new execution.
    pub fn validate(&self) -> RuntimeResult<()> {
        if [
            &self.authorization_id,
            &self.participant_id,
            &self.actor_subject_id,
            &self.chain_environment_id,
        ]
        .into_iter()
        .any(|value| !identifier(value))
            || self.participant_epoch == 0
            || !decimal(&self.chain_id)
            || !decimal(&self.max_amount_wei)
            || !self.one_use
            || [
                &self.genesis_hash,
                &self.policy_decision_digest,
                &self.semantic_digest,
            ]
            .into_iter()
            .any(|value| !digest(value))
            || OffsetDateTime::parse(&self.valid_until, &Rfc3339).is_err()
            || self.computed_digest()? != self.semantic_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
}

/// Current owner-resolved identity, never a caller assertion of readiness.
pub struct NativeValueScope<'a> {
    pub participant_id: &'a str,
    pub participant_epoch: u64,
    pub actor_subject_id: &'a str,
    pub chain_environment_id: &'a str,
    pub chain_id: &'a str,
    pub genesis_hash: &'a Digest,
}

/// DCC-074..081: the signed value, independent Native Value grant and
/// deployment upper bound all intersect. Fees are deliberately absent.
/// Target prebalance and internal transfers still require the real creation
/// inspector (DCC-082/083); this function cannot certify either chain fact.
pub fn intersect_creation_endowment<'a>(
    authorization: Option<&'a NativeValueAuthorizationV1>,
    scope: &NativeValueScope<'_>,
    signed_value: &[u8; 32],
    deployment_maximum: &[u8; 32],
    now_ms: u64,
) -> RuntimeResult<Option<&'a NativeValueAuthorizationV1>> {
    if signed_value > deployment_maximum {
        return Err(RuntimeError::Denied);
    }
    if signed_value == &[0; 32] {
        return Ok(None);
    }
    let authorization = authorization.ok_or(RuntimeError::Denied)?;
    authorization.validate()?;
    if authorization.used
        || authorization.participant_id != scope.participant_id
        || authorization.participant_epoch != scope.participant_epoch
        || authorization.actor_subject_id != scope.actor_subject_id
        || authorization.chain_environment_id != scope.chain_environment_id
        || authorization.chain_id != scope.chain_id
        || &authorization.genesis_hash != scope.genesis_hash
        || authorization.valid_until_ns()? <= i128::from(now_ms) * 1_000_000
    {
        return Err(RuntimeError::Denied);
    }
    let value = decimal_uint256(signed_value);
    let limit = &authorization.max_amount_wei;
    let comparison = value.len().cmp(&limit.len()).then_with(|| value.cmp(limit));
    if match authorization.amount_mode {
        NativeValueAmountMode::Exact => !comparison.is_eq(),
        NativeValueAmountMode::Maximum => comparison.is_gt(),
    } {
        return Err(RuntimeError::Denied);
    }
    Ok(Some(authorization))
}

fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn decimal(value: &str) -> bool {
    (1..=78).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn digest(value: &Digest) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Exact signed endowment amount, with no floating-point or narrowing conversion.
pub fn decimal_uint256(value: &[u8; 32]) -> String {
    let mut value = *value;
    let mut digits = Vec::with_capacity(78);
    loop {
        let mut remainder = 0u16;
        for byte in &mut value {
            let current = remainder * 256 + u16::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(char::from(b'0' + remainder as u8));
        if value == [0; 32] {
            return digits.into_iter().rev().collect();
        }
    }
}

#[cfg(test)]
mod tests;
