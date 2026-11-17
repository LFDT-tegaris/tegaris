use serde::{Deserialize, Serialize};

use crate::{Digest, SignedEnvelope};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestClass {
    Read,
    Write,
    Subscription,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Transport {
    Http,
    WebSocket,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyConjunct {
    Allow,
    Deny,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractInvocation {
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: Digest,
    pub contract_address: [u8; 20],
    pub proxy_address: Option<[u8; 20]>,
    pub implementation_address: Option<[u8; 20]>,
    pub code_digest: Digest,
    pub implementation_code_digest: Option<Digest>,
    pub abi_digest: Digest,
    pub calldata: Vec<u8>,
    pub nested_calls: Vec<ContractInvocation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentInvocation {
    pub deployment_policy_id: String,
    pub intent_digest: Digest,
}

/// Exact read intent resolved by the decoder against installed visibility
/// resources. The digest binds the admitted chain/contract/ABI snapshot; these
/// fields are never a grant or a provider observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VisibilityRead {
    pub runtime_binding_id: String,
    pub binding_digest: Digest,
    pub block_number: u64,
    pub query: VisibilityReadQuery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum VisibilityReadQuery {
    Transaction {
        hash: String,
    },
    Receipt {
        hash: String,
    },
    Logs {
        event_signature: String,
        topics: Vec<String>,
    },
}

impl VisibilityReadQuery {
    pub fn method(&self) -> &'static str {
        match self {
            Self::Transaction { .. } => "eth_getTransactionByHash",
            Self::Receipt { .. } => "eth_getTransactionReceipt",
            Self::Logs { .. } => "eth_getLogs",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeRequest {
    pub request_id: String,
    pub method: String,
    pub params_digest: Digest,
    pub transport: Transport,
    pub batch_index: u32,
    pub request_digest: Digest,
    pub class: RequestClass,
    pub received_at_ms: u64,
    pub deadline_at_ms: u64,
    pub response_budget_bytes: u64,
    pub invocation: Option<ContractInvocation>,
    /// Identity only, resolved through the dedicated managed deployment entry.
    /// This never substitutes for preparation, reservation or live authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentInvocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<VisibilityRead>,
}

impl RuntimeRequest {
    pub fn computed_digest(&self) -> crate::RuntimeResult<Digest> {
        let legacy = Digest::of(crate::canonical_bytes(&(
            &self.request_id,
            &self.method,
            &self.params_digest,
            self.transport,
            self.batch_index,
            self.class,
            self.received_at_ms,
            self.deadline_at_ms,
            self.response_budget_bytes,
            &self.invocation,
        ))?);
        if let Some(read) = &self.visibility {
            if self.invocation.is_some()
                || self.deployment.is_some()
                || self.class != RequestClass::Read
                || self.method != read.query.method()
                || read.runtime_binding_id.is_empty()
                || read.binding_digest == Digest::of([])
            {
                return Err(crate::RuntimeError::InvalidInput);
            }
            return Ok(Digest::of(crate::canonical_bytes(&(
                "openpc:visibility-read:v1",
                legacy,
                read,
            ))?));
        }
        match &self.deployment {
            None => Ok(legacy),
            Some(deployment) => {
                if self.invocation.is_some()
                    || self.class != RequestClass::Write
                    || self.method != "eth_sendRawTransaction"
                    || deployment.deployment_policy_id.is_empty()
                    || deployment.intent_digest == Digest::of([])
                {
                    return Err(crate::RuntimeError::InvalidInput);
                }
                Ok(Digest::of(crate::canonical_bytes(&(
                    "openpc:deployment-request:v1",
                    legacy,
                    deployment,
                ))?))
            }
        }
    }

    pub fn validate_digest(&self) -> crate::RuntimeResult<()> {
        if self.request_digest != self.computed_digest()? {
            return Err(crate::RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeBindings {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub target_id: String,
    pub active_generation_digest: Digest,
    pub observed_generation_digest: Digest,
    pub policy_generation_digest: Digest,
    pub expected_policy_generation_digest: Digest,
    pub fact_generation_digest: Digest,
    pub expected_fact_generation_digest: Digest,
    pub route_profile_digest: Digest,
    pub expected_route_profile_digest: Digest,
    pub eligible_provider_profile_ids: Vec<String>,
    pub provider_profile_digest: Digest,
    pub expected_provider_profile_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCapacity {
    pub used: u64,
    pub capacity: u64,
    pub high_watermark_percent: u8,
    pub critical_watermark_percent: u8,
}

impl EvidenceCapacity {
    #[must_use]
    pub fn critical(&self) -> bool {
        self.capacity == 0
            || self.used.saturating_mul(100)
                >= self
                    .capacity
                    .saturating_mul(u64::from(self.critical_watermark_percent))
    }

    #[must_use]
    pub fn high(&self) -> bool {
        self.capacity == 0
            || self.used.saturating_mul(100)
                >= self
                    .capacity
                    .saturating_mul(u64::from(self.high_watermark_percent))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionEffect {
    AllowForward,
    DenyTerminal,
    AuthorizedEmpty,
    WithholdStale,
    WriteAmbiguity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BrokerCapability {
    pub capability_id: String,
    pub request_digest: Digest,
    pub decision_digest: Digest,
    pub target_id: String,
    pub active_generation_digest: Digest,
    pub route_profile_digest: Digest,
    pub provider_profile_id: String,
    pub provider_profile_digest: Digest,
    pub request_class: RequestClass,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub remaining_budget_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeDecision {
    pub decision_id: String,
    pub effect: DecisionEffect,
    pub pc_code: String,
    pub active_generation_digest: Digest,
    pub decision_input_digest: Digest,
    pub decision_digest: Digest,
    pub capability: Option<SignedEnvelope<BrokerCapability>>,
    pub protective_degradation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderResponse {
    pub request_id: String,
    pub response_digest: Digest,
    pub anchor_digest: Digest,
    pub body: Vec<u8>,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptResolution {
    pub attempt_id: String,
    pub request_digest: Digest,
    pub signed_transaction_hash: Option<Digest>,
    pub effect: DecisionEffect,
    pub pc_code: String,
    pub response: Option<ProviderResponse>,
    pub evidence_digest: Digest,
}
