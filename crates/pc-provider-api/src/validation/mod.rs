use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use crate::*;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProviderContractError {
    #[error("schema catalog: {0}")]
    SchemaCatalog(&'static str),
    #[error("invalid exact contract: {0}")]
    Invalid(&'static str),
}

fn invalid(reason: &'static str) -> ProviderContractError {
    ProviderContractError::Invalid(reason)
}

fn nonempty(value: &str, reason: &'static str) -> Result<(), ProviderContractError> {
    if value.is_empty() {
        Err(invalid(reason))
    } else {
        Ok(())
    }
}

fn evidence(values: Vec<String>) -> Result<Vec<EvidenceDigest>, ProviderContractError> {
    if values.is_empty() {
        return Err(invalid("evidence refs"));
    }
    values
        .into_iter()
        .map(|value| EvidenceDigest::new(value).map_err(|_| invalid("evidence refs")))
        .collect()
}

fn provider_key(
    profile_digest: String,
    provider_instance_id: String,
) -> Result<ProviderKeyV1, ProviderContractError> {
    Ok(ProviderKeyV1 {
        profile_digest: ProviderProfileDigest::new(profile_digest)
            .map_err(|_| invalid("profile digest"))?,
        provider_instance_id: ProviderInstanceId::new(provider_instance_id)
            .map_err(|_| invalid("provider instance"))?,
    })
}

mod attempt;
mod profile;
mod read;
mod temporal;
mod witness;
mod write;

use attempt::*;
pub(crate) use profile::{
    profile_key_from_profile, validate_profile_request_binding, validate_route_plan,
};
pub use profile::{
    provider_profile_admission_enabled, validate_candidate_projection_batch,
    validate_candidate_projection_batch_structure,
    validate_candidate_projection_batch_with_predecessor, validate_chain_anchor,
    validate_client_indexer_profile, validate_explorer_page, validate_explorer_profile,
    validate_projection_plan, validate_provider_profile, validate_route_request,
    validate_subquery_batch, validate_subquery_profile, validate_thegraph_batch,
    validate_thegraph_manifest,
};
use read::*;
pub(crate) use temporal::derive_terminal_outcome_draft;
use temporal::*;
pub(crate) use witness::canonicalize_provider_order_with_excluded;
use write::*;

pub(super) struct WitnessValidationContext<'a> {
    pub(super) request: &'a RouteRequestV1,
    pub(super) request_digest: &'a RequestDigest,
    pub(super) eligibility: &'a EligibilitySnapshotV1,
    pub(super) attempts: &'a [RouteAttemptV1],
    pub(super) attempts_by_id: &'a BTreeMap<AttemptId, &'a RouteAttemptV1>,
}

pub fn validate_candidate_authority(
    authority: SourceAuthority,
) -> Result<(), ProviderContractError> {
    if authority == SourceAuthority::NonAuthoritativeCandidateOnly {
        Ok(())
    } else {
        Err(invalid("candidate authority"))
    }
}

pub fn encode_provider_profile_pc_cbor(
    value: &ProviderProfileV1,
) -> Result<Vec<u8>, ProviderContractError> {
    encode_canonical_cbor(value, "provider profile PC-CBOR")
}

pub fn decode_provider_profile_pc_cbor(
    bytes: &[u8],
) -> Result<ProviderProfileV1, ProviderContractError> {
    decode_canonical_cbor(bytes, "provider profile PC-CBOR")
}

pub fn encode_client_indexer_profile_pc_cbor(
    value: &ClientIndexerProfileV1,
) -> Result<Vec<u8>, ProviderContractError> {
    encode_canonical_cbor(value, "client indexer profile PC-CBOR")
}

pub fn decode_client_indexer_profile_pc_cbor(
    bytes: &[u8],
) -> Result<ClientIndexerProfileV1, ProviderContractError> {
    decode_canonical_cbor(bytes, "client indexer profile PC-CBOR")
}

pub fn encode_projection_plan_pc_cbor(
    value: &ProjectionPlanV1,
) -> Result<Vec<u8>, ProviderContractError> {
    encode_canonical_cbor(value, "projection plan PC-CBOR")
}

pub fn decode_projection_plan_pc_cbor(
    bytes: &[u8],
) -> Result<ProjectionPlanV1, ProviderContractError> {
    decode_canonical_cbor(bytes, "projection plan PC-CBOR")
}

pub fn encode_candidate_projection_batch_pc_cbor(
    value: &CandidateProjectionBatchV1,
) -> Result<Vec<u8>, ProviderContractError> {
    encode_canonical_cbor(value, "candidate projection batch PC-CBOR")
}

pub fn validate_canonical_pc_cbor_bytes(bytes: &[u8]) -> Result<(), ProviderContractError> {
    decode_canonical_cbor::<ciborium::Value>(bytes, "canonical PC-CBOR payload").map(drop)
}

pub(crate) fn encode_canonical_cbor<T: serde::Serialize>(
    value: &T,
    reason: &'static str,
) -> Result<Vec<u8>, ProviderContractError> {
    let mut initial = Vec::new();
    ciborium::ser::into_writer(value, &mut initial).map_err(|_| invalid(reason))?;
    let decoded: ciborium::Value =
        ciborium::de::from_reader(initial.as_slice()).map_err(|_| invalid(reason))?;
    let canonical = canonical_cbor_value(decoded, reason)?;
    let mut output = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut output).map_err(|_| invalid(reason))?;
    Ok(output)
}

fn decode_canonical_cbor<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    reason: &'static str,
) -> Result<T, ProviderContractError> {
    let mut value_cursor = Cursor::new(bytes);
    let decoded: ciborium::Value =
        ciborium::de::from_reader(&mut value_cursor).map_err(|_| invalid(reason))?;
    if value_cursor.position() != bytes.len() as u64 {
        return Err(invalid(reason));
    }
    let canonical = canonical_cbor_value(decoded, reason)?;
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut encoded).map_err(|_| invalid(reason))?;
    if encoded != bytes {
        return Err(invalid(reason));
    }
    let mut typed_cursor = Cursor::new(bytes);
    let typed = ciborium::de::from_reader(&mut typed_cursor).map_err(|_| invalid(reason))?;
    if typed_cursor.position() != bytes.len() as u64 {
        return Err(invalid(reason));
    }
    Ok(typed)
}

fn canonical_cbor_value(
    value: ciborium::Value,
    reason: &'static str,
) -> Result<ciborium::Value, ProviderContractError> {
    use ciborium::Value;
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) | Value::Null => {
            Ok(value)
        }
        Value::Array(values) => values
            .into_iter()
            .map(|item| canonical_cbor_value(item, reason))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Map(entries) => {
            let mut canonical = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = canonical_cbor_value(key, reason)?;
                    let value = canonical_cbor_value(value, reason)?;
                    let mut key_bytes = Vec::new();
                    ciborium::ser::into_writer(&key, &mut key_bytes)
                        .map_err(|_| invalid(reason))?;
                    Ok((key_bytes, key, value))
                })
                .collect::<Result<Vec<_>, ProviderContractError>>()?;
            canonical.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(invalid(reason));
            }
            Ok(Value::Map(
                canonical
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        }
        Value::Tag(_, _) | Value::Float(_) => Err(invalid(reason)),
        _ => Err(invalid(reason)),
    }
}

#[cfg(test)]
mod tests;
