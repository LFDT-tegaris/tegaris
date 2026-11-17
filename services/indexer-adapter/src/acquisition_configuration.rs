//! Resolved acquisition input bound by the governed ClientIndexerProfile's
//! configuration_digest. The target remains responsible for authenticating
//! and authorizing each request; these parameters confer no data authority.
use pc_provider_api::{ClientIndexerProfileV1, validate_canonical_pc_cbor_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CandidateStoreError, candidate::decode_digest, store::canonical_cbor};

const PURPOSE: &str = "openpc:indexer-acquisition-configuration:v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionConfiguration {
    pub runtime_target_id: String,
    pub request: AcquisitionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<AcquisitionRateLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionRateLimit {
    pub window_ms: u32,
    pub maximum_requests: u32,
}

impl AcquisitionRateLimit {
    pub fn digest(&self) -> Result<String, CandidateStoreError> {
        if !(1..=3_600_000).contains(&self.window_ms)
            || !(1..=10_000).contains(&self.maximum_requests)
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let value = serde_json::to_value(("openpc:indexer-source-rate:v1", self))
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let hex: String = Sha256::digest(canonical_cbor(&value))
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(format!("sha256:{hex}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AcquisitionRequest {
    ExternalDecision {
        target_address: String,
        calldata: String,
        provider_id: String,
        provider_version: String,
        provider_configuration_digest: String,
        condition: String,
    },
    StateCall {
        target_address: String,
        calldata: String,
    },
    EventLogs {
        contract_address: String,
        event_name: String,
        event_signature: String,
    },
}

impl AcquisitionConfiguration {
    /// Construct the exact primary request registered by this source. The
    /// acquisition owner processes bounded blocks and admits completeness only
    /// after every required block and its canonicality observations are durable.
    pub fn primary_params(&self, block: u64) -> Result<serde_json::Value, CandidateStoreError> {
        self.validate()?;
        match &self.request {
            AcquisitionRequest::StateCall { .. } => self.state_call_params(block),
            AcquisitionRequest::ExternalDecision {
                target_address,
                calldata,
                condition,
                ..
            } => Ok(serde_json::json!([
                {"targetAddress":target_address,"calldata":calldata,"condition":condition},format!("0x{block:x}")
            ])),
            AcquisitionRequest::EventLogs {
                contract_address,
                event_signature,
                ..
            } => Ok(serde_json::json!([{
                "address": contract_address,
                "fromBlock": format!("0x{block:x}"),
                "toBlock": format!("0x{block:x}"),
                "topics": [event_signature],
            }])),
        }
    }

    pub fn state_call_params(&self, block: u64) -> Result<serde_json::Value, CandidateStoreError> {
        self.validate()?;
        let (AcquisitionRequest::StateCall {
            target_address,
            calldata,
        }
        | AcquisitionRequest::ExternalDecision {
            target_address,
            calldata,
            ..
        }) = &self.request
        else {
            return Err(CandidateStoreError::InvalidBinding);
        };
        Ok(serde_json::json!([
            { "to": target_address, "data": calldata }, format!("0x{block:x}")
        ]))
    }

    pub fn external_request(
        &self,
        profile: &ClientIndexerProfileV1,
        block: u64,
        block_hash: &str,
    ) -> Result<openpc_multi_rpc::external_decision::ExternalDecisionRequestV1, CandidateStoreError>
    {
        use pc_runtime_types::Digest;
        let AcquisitionRequest::ExternalDecision {
            target_address,
            calldata,
            provider_id,
            provider_version,
            provider_configuration_digest,
            condition,
        } = &self.request
        else {
            return Err(CandidateStoreError::InvalidBinding);
        };
        let hash = block_hash.trim_start_matches("0x");
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let input = canonical_cbor(&serde_json::json!([
            target_address,
            calldata,
            profile.chain_id,
            profile.genesis_hash,
            profile.network_id,
            block.to_string(),
            hash
        ]));
        let occurrence = canonical_cbor(&serde_json::json!([
            "openpc:external-source-occurrence:v1",
            profile.participant_binding,
            profile.privacy_binding,
            Digest::of(&input)
        ]));
        Ok(
            openpc_multi_rpc::external_decision::ExternalDecisionRequestV1 {
                participant_id: profile.participant_binding.clone(),
                privacy_domain_id: profile.privacy_binding.clone(),
                provider_id: provider_id.clone(),
                provider_version: provider_version.clone(),
                provider_configuration_digest: Digest::parse(
                    provider_configuration_digest.trim_start_matches("sha256:"),
                )
                .map_err(|_| CandidateStoreError::InvalidBinding)?,
                source_occurrence: Digest::of(&occurrence),
                condition: condition.clone(),
                input_digest: Digest::of(&input),
            },
        )
    }

    pub fn state_call_parameter_digest(&self, block: u64) -> Result<String, CandidateStoreError> {
        let bytes = openpc_multi_rpc::rfc8785_canonical_bytes(&self.state_call_params(block)?)
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        Ok(format!("sha256:{}", crate::candidate::digest_hex(&bytes)))
    }

    pub fn encode(&self) -> Result<Vec<u8>, CandidateStoreError> {
        self.validate()?;
        let value = serde_json::to_value((PURPOSE, self))
            .map_err(|_| CandidateStoreError::InvalidBinding)?;
        Ok(canonical_cbor(&value))
    }

    pub fn resolve(
        profile: &ClientIndexerProfileV1,
        bytes: &[u8],
    ) -> Result<Self, CandidateStoreError> {
        if bytes.is_empty()
            || bytes.len() > 131_072
            || Sha256::digest(bytes).as_slice() != decode_digest(&profile.configuration_digest)?
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        validate_canonical_pc_cbor_bytes(bytes).map_err(|_| CandidateStoreError::InvalidBinding)?;
        let (purpose, configuration): (String, Self) =
            ciborium::de::from_reader(bytes).map_err(|_| CandidateStoreError::InvalidBinding)?;
        if purpose != PURPOSE
            || configuration.encode()? != bytes
            || !profile.method_data_classes.iter().any(|pair| {
                pair.method == configuration.request.method()
                    && pair.data_class == configuration.request.data_class()
            })
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        Ok(configuration)
    }

    fn validate(&self) -> Result<(), CandidateStoreError> {
        if let Some(rate) = &self.rate_limit {
            rate.digest()?;
        }
        let valid = Uuid::parse_str(&self.runtime_target_id)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == self.runtime_target_id)
            && match &self.request {
                AcquisitionRequest::ExternalDecision {
                    target_address,
                    calldata,
                    provider_id,
                    provider_version,
                    provider_configuration_digest,
                    condition,
                } => {
                    canonical_hex(target_address, 20, 20)
                        && canonical_hex(calldata, 4, 32768)
                        && decode_digest(provider_configuration_digest).is_ok()
                        && [provider_id, provider_version, condition].iter().all(|v| {
                            !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control)
                        })
                }
                AcquisitionRequest::StateCall {
                    target_address,
                    calldata,
                } => canonical_hex(target_address, 20, 20) && canonical_hex(calldata, 4, 32_768),
                AcquisitionRequest::EventLogs {
                    contract_address,
                    event_name,
                    event_signature,
                } => {
                    canonical_hex(contract_address, 20, 20)
                        && canonical_hex(event_signature, 32, 32)
                        && !event_name.is_empty()
                        && event_name.len() <= 128
                        && event_name.as_bytes()[0].is_ascii_alphabetic()
                        && event_name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                }
            };
        if valid {
            Ok(())
        } else {
            Err(CandidateStoreError::InvalidBinding)
        }
    }
}

impl AcquisitionRequest {
    pub fn method(&self) -> &'static str {
        match self {
            Self::StateCall { .. } => "eth_call",
            Self::ExternalDecision { .. } => "acquireObservation",
            Self::EventLogs { .. } => "eth_getLogs",
        }
    }

    pub fn data_class(&self) -> &'static str {
        match self {
            Self::StateCall { .. } => "STATE_CALL",
            Self::ExternalDecision { .. } => "EXTERNAL_OBSERVATION",
            Self::EventLogs { .. } => "EVENT_LOG",
        }
    }
}

fn canonical_hex(value: &str, minimum_bytes: usize, maximum_bytes: usize) -> bool {
    value.strip_prefix("0x").is_some_and(|hex| {
        hex.len() % 2 == 0
            && (minimum_bytes * 2..=maximum_bytes * 2).contains(&hex.len())
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
