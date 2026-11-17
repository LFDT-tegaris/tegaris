//! Dedicated managed-deployment input. Ordinary JSON-RPC decoding continues to
//! reject contract creation. All supplied identity is rebound to installed data
//! and the independently pinned reservation worker before capture.
use super::{DecodedProtectedRequest, RequestDecodeLimits, request_id, signed_submission_identity};
use openpc_multi_rpc::deployment::{
    custody::{DeploymentHandoff, VerifiedDeploymentHandoff},
    intent::PreparedDeploymentIntent,
};
use pc_policy_core::deployment_policy::ValidatedDeploymentPolicy;
use pc_runtime_types::{
    DeploymentInvocation, Digest, RequestClass, RuntimeError, RuntimeRequest, RuntimeResult,
    SignedEnvelope, Transport,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedDeploymentRequest {
    request_id: serde_json::Value,
    deployment_policy_id: String,
    preparation_bytes: String,
    signed_transaction: String,
    handoff: SignedEnvelope<DeploymentHandoff>,
}

/// Outcome-precedence parsing uses only the exact transaction and original
/// transport peer. It cannot validate a handoff or authorize another attempt.
pub(crate) fn deployment_rpc_body(body: &[u8], maximum: usize) -> RuntimeResult<Vec<u8>> {
    if body.is_empty() || body.len() > maximum || body.len() > 4 * 1024 * 1024 {
        return Err(RuntimeError::InvalidInput);
    }
    let value =
        openpc_multi_rpc::parse_strict_json(body, 16).map_err(|_| RuntimeError::InvalidInput)?;
    let input: ManagedDeploymentRequest =
        serde_json::from_value(value.clone()).map_err(|_| RuntimeError::InvalidInput)?;
    if serde_json::to_value(&input).map_err(|_| RuntimeError::InvalidInput)? != value {
        return Err(RuntimeError::InvalidInput);
    }
    request_id(&input.request_id)?;
    openpc_multi_rpc::rfc8785_canonical_bytes(
        &serde_json::json!({"jsonrpc":"2.0", "id":input.request_id,
        "method":"eth_sendRawTransaction", "params":[input.signed_transaction]}),
    )
    .map_err(|_| RuntimeError::InvalidInput)
}

pub struct DecodedDeployment {
    pub(super) preparation: PreparedDeploymentIntent,
    pub(super) handoff: VerifiedDeploymentHandoff,
}
impl DecodedDeployment {
    pub fn preparation(&self) -> &PreparedDeploymentIntent {
        &self.preparation
    }
    pub fn handoff(&self) -> &VerifiedDeploymentHandoff {
        &self.handoff
    }
}

impl DecodedProtectedRequest {
    pub fn decode_deployment(
        body: &[u8],
        policies: &[ValidatedDeploymentPolicy],
        worker_public_key: &[u8],
        limits: RequestDecodeLimits<'_>,
        received_at_ms: u64,
    ) -> RuntimeResult<Self> {
        if body.len() > limits.maximum_request_bytes
            || body.len() > 4 * 1024 * 1024
            || received_at_ms == 0
            || !(1..=pc_policy_core::transaction_policy::MAX_TRANSACTION_DEADLINE_MS)
                .contains(&limits.timeout_ms)
            || limits.maximum_response_bytes == 0
            || limits.maximum_response_bytes > 16 * 1024 * 1024
        {
            return Err(RuntimeError::InvalidInput);
        }
        let value = openpc_multi_rpc::parse_strict_json(body, 16)
            .map_err(|_| RuntimeError::InvalidInput)?;
        let input: ManagedDeploymentRequest =
            serde_json::from_value(value.clone()).map_err(|_| RuntimeError::InvalidInput)?;
        if serde_json::to_value(&input).map_err(|_| RuntimeError::InvalidInput)? != value {
            return Err(RuntimeError::InvalidInput);
        }
        let mut selected = policies.iter().filter(|policy| {
            policy.publication().deployment_policy_id == input.deployment_policy_id
        });
        let publication = selected.next().ok_or(RuntimeError::Denied)?.publication();
        if selected.next().is_some() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let preparation =
            PreparedDeploymentIntent::restore(&hex_bytes(&input.preparation_bytes)?, publication)?;
        let provider_body = serde_json::json!({"jsonrpc":"2.0", "id":input.request_id,
            "method":"eth_sendRawTransaction", "params":[input.signed_transaction]});
        let transaction =
            signed_submission_identity(&provider_body)?.ok_or(RuntimeError::InvalidInput)?;
        let handoff = VerifiedDeploymentHandoff::verify(
            worker_public_key,
            &input.handoff,
            &preparation,
            publication,
            &transaction,
            received_at_ms,
        )?;
        let mut request = RuntimeRequest {
            visibility: None,
            request_id: request_id(&input.request_id)?,
            method: "eth_sendRawTransaction".into(),
            params_digest: openpc_multi_rpc::governed_write::submission_params_digest(
                &transaction,
            )?,
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Write,
            received_at_ms,
            deadline_at_ms: received_at_ms
                .checked_add(limits.timeout_ms)
                .ok_or(RuntimeError::InvalidInput)?
                .min(handoff.claims().expires_at_ms),
            response_budget_bytes: limits.maximum_response_bytes,
            invocation: None,
            deployment: Some(DeploymentInvocation {
                deployment_policy_id: input.deployment_policy_id,
                intent_digest: preparation.intent_digest().clone(),
            }),
        };
        request.request_digest = request.computed_digest()?;
        Ok(Self {
            request,
            body: openpc_multi_rpc::rfc8785_canonical_bytes(&provider_body)
                .map_err(|_| RuntimeError::InvalidInput)?,
            signed_transaction: Some(transaction),
            call_sender: None,
            call_block_selector: None,
            deployment: Some(DecodedDeployment {
                preparation,
                handoff,
            }),
        })
    }
}

fn hex_bytes(value: &str) -> RuntimeResult<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 2 * 1024 * 1024
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(RuntimeError::InvalidInput)?;
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| RuntimeError::InvalidInput)?,
                16,
            )
            .map_err(|_| RuntimeError::InvalidInput)
        })
        .collect()
}

#[cfg(test)]
#[path = "request_deployment_tests.rs"]
mod tests;
