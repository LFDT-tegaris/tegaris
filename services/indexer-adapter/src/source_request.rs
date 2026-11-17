//! Exact requests for a governed acquisition configuration. Decoding establishes
//! no workload grant, current qualification or provider dispatch authority.
use crate::{AcquisitionConfiguration, CandidateStoreError};
use pc_provider_api::{
    ClientIndexerProfileV1, MethodDataClass, ProjectionPlanV1, RangeEndV1,
    validate_client_indexer_profile, validate_projection_plan,
};
use serde_json::Value;

#[path = "source_response.rs"]
mod response;

pub struct DecodedAcquisitionRequest {
    body: Vec<u8>,
    id: String,
    class: MethodDataClass,
    block: u64,
    target_id: String,
}

impl DecodedAcquisitionRequest {
    pub fn decode(
        profile: &ClientIndexerProfileV1,
        plan: &ProjectionPlanV1,
        acquisition_cbor: &[u8],
        body: &[u8],
    ) -> Result<Self, CandidateStoreError> {
        validate_client_indexer_profile(profile)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        validate_projection_plan(profile, plan).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let configuration = AcquisitionConfiguration::resolve(profile, acquisition_cbor)?;
        if body.is_empty()
            || body.len() > 131_072
            || body.len() as u64 > profile.limits.max_request_bytes
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let request = openpc_multi_rpc::parse_strict_json(body, 8)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let object = request
            .as_object()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        if object.len() != 4
            || !["jsonrpc", "id", "method", "params"]
                .iter()
                .all(|k| object.contains_key(*k))
            || request["jsonrpc"] != "2.0"
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        match &request["id"] {
            Value::String(id) if !id.is_empty() && id.chars().count() <= 128 => {}
            Value::Number(id) if id.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991) => {}
            _ => return Err(CandidateStoreError::InvalidBinding),
        }
        let method = request["method"]
            .as_str()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        let params = request["params"]
            .as_array()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        let (profile_method, data_class, block) = if method == "eth_getBlockByNumber" {
            if params.len() != 2 || params[1] != false {
                return Err(CandidateStoreError::InvalidBinding);
            }
            (
                "eth_getBlockByNumber(false)",
                "BLOCK_HEADER",
                quantity(&params[0])?,
            )
        } else if method == configuration.request.method() {
            let block = match method {
                "eth_call" | "acquireObservation" if params.len() == 2 => quantity(&params[1])?,
                "eth_getLogs" if params.len() == 1 => quantity(&params[0]["fromBlock"])?,
                _ => return Err(CandidateStoreError::InvalidBinding),
            };
            if request["params"] != configuration.primary_params(block)? {
                return Err(CandidateStoreError::InvalidBinding);
            }
            (
                configuration.request.method(),
                configuration.request.data_class(),
                block,
            )
        } else {
            return Err(CandidateStoreError::InvalidBinding);
        };
        let within = |start: u64, end: &RangeEndV1| {
            block >= start
                && match end {
                    RangeEndV1::Open => true,
                    RangeEndV1::Inclusive(end) => block <= *end,
                }
        };
        if block == 0
            || !within(profile.source_range.start, &profile.source_range.end)
            || !within(plan.source_range.start, &plan.source_range.end)
            || plan.limits.max_range == 0
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let class = profile
            .method_data_classes
            .iter()
            .find(|pair| pair.method == profile_method && pair.data_class == data_class)
            .ok_or(CandidateStoreError::InvalidBinding)?
            .clone();
        let id = String::from_utf8(
            openpc_multi_rpc::rfc8785_canonical_bytes(&request["id"])
                .map_err(|_| CandidateStoreError::InvalidBinding)?,
        )
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
        Ok(Self {
            body: openpc_multi_rpc::rfc8785_canonical_bytes(&request)
                .map_err(|_| CandidateStoreError::InvalidBinding)?,
            id,
            class,
            block,
            target_id: configuration.runtime_target_id,
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn request_id(&self) -> &str {
        &self.id
    }
    pub fn method_class(&self) -> &MethodDataClass {
        &self.class
    }
    pub fn block(&self) -> u64 {
        self.block
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Bind a state read to the independently qualified block. The caller must
    /// authenticate that proof and its current provider/profile association;
    /// request parameters never establish the block's canonicality.
    pub fn hash_pinned_state_call(
        &self,
        qualified_number: u64,
        qualified_hash: &str,
    ) -> Result<Vec<u8>, CandidateStoreError> {
        if self.class.data_class != "STATE_CALL"
            || self.class.method != "eth_call"
            || qualified_number != self.block
            || qualified_hash.len() != 64
            || !qualified_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let mut request: Value =
            serde_json::from_slice(&self.body).map_err(|_| CandidateStoreError::InvalidBinding)?;
        request["params"][1] = serde_json::json!({
            "blockHash": format!("0x{qualified_hash}"), "requireCanonical": true
        });
        openpc_multi_rpc::rfc8785_canonical_bytes(&request)
            .map_err(|_| CandidateStoreError::InvalidBinding)
    }

    pub fn hash_pinned_event_logs(
        &self,
        number: u64,
        hash: &str,
    ) -> Result<Vec<u8>, CandidateStoreError> {
        if self.class.data_class != "EVENT_LOG"
            || self.class.method != "eth_getLogs"
            || number != self.block
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let mut request: Value =
            serde_json::from_slice(&self.body).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let filter = request["params"][0]
            .as_object_mut()
            .ok_or(CandidateStoreError::InvalidBinding)?;
        filter.remove("fromBlock");
        filter.remove("toBlock");
        filter.insert("blockHash".into(), format!("0x{hash}").into());
        openpc_multi_rpc::rfc8785_canonical_bytes(&request)
            .map_err(|_| CandidateStoreError::InvalidBinding)
    }

    /// Admit only a bounded, exactly correlated response of the registered
    /// data class. This does not establish canonicality, finality or a fact.
    pub fn validate_response(
        &self,
        body: &[u8],
        maximum_bytes: usize,
        maximum_depth: usize,
    ) -> Result<Vec<u8>, CandidateStoreError> {
        response::validate(self, body, maximum_bytes, maximum_depth)
    }
}

fn quantity(value: &Value) -> Result<u64, CandidateStoreError> {
    let text = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(CandidateStoreError::InvalidBinding)?;
    if text.is_empty()
        || text.len() > 16
        || (text.len() > 1 && text.starts_with('0'))
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CandidateStoreError::InvalidBinding);
    }
    u64::from_str_radix(text, 16).map_err(|_| CandidateStoreError::InvalidBinding)
}
