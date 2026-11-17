#![forbid(unsafe_code)]

//! Pure Privacy Explorer response validation, minimization, and digest construction.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use pc_contracts::generated::json_schema::openpc_contracts::{
    PrivacyExplorerExplorerProjectionResultV1 as ProjectionResult,
    PrivacyExplorerExplorerProjectionResultV1Completeness as Completeness,
    PrivacyExplorerExplorerProjectionResultV1Conflict as Conflict,
    PrivacyExplorerExplorerProjectionResultV1Freshness as Freshness,
    PrivacyExplorerPrivacyExplorerResultV1 as PublicResult,
};
use pc_request_narrowing::{NarrowedRequest, canonical_json_bytes, sha256_digest};
use serde_json::{Value, json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactionError {
    #[error("PC-RUNTIME-3009 response binding rejected")]
    Binding,
    #[error("PC-INTEGRATION-5002 response scope rejected")]
    Scope,
    #[error("PC-OPS-9004 partial result")]
    Partial,
    #[error("PC-INTEGRATION-5001 source unavailable")]
    Unavailable,
    #[error("PC-FACT-4002 stale result")]
    Stale,
    #[error("PC-FACT-4003 reorganization")]
    Reorg,
    #[error("PC-RUNTIME-3011 conflicting observations")]
    Conflict,
    #[error("PC-FACT-4001 absence unproven")]
    Absence,
}

impl RedactionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Binding => "PC-RUNTIME-3009",
            Self::Scope => "PC-INTEGRATION-5002",
            Self::Partial => "PC-OPS-9004",
            Self::Unavailable => "PC-INTEGRATION-5001",
            Self::Stale => "PC-FACT-4002",
            Self::Reorg => "PC-FACT-4003",
            Self::Conflict => "PC-RUNTIME-3011",
            Self::Absence => "PC-FACT-4001",
        }
    }
}

fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn validate_truth(result: &ProjectionResult) -> Result<(), RedactionError> {
    match result.conflict {
        Conflict::Reorg => return Err(RedactionError::Reorg),
        Conflict::Conflict => return Err(RedactionError::Conflict),
        Conflict::None => {}
    }
    if result.freshness == Freshness::Stale {
        return Err(RedactionError::Stale);
    }
    match result.completeness {
        Completeness::Complete
            if result.freshness == Freshness::Fresh
                && result.page.gap_free
                && result.page.cursor.is_none() => {}
        Completeness::Partial
            if result.freshness == Freshness::Fresh
                && (!result.page.gap_free || result.page.cursor.is_some()) => {}
        Completeness::Unknown
            if result.freshness == Freshness::Unknown
                && result.records.is_empty()
                && result.page.cursor.is_none()
                && !result.page.gap_free => {}
        Completeness::Unavailable
            if result.freshness == Freshness::Unknown
                && result.records.is_empty()
                && result.page.cursor.is_none()
                && !result.page.gap_free => {}
        Completeness::Unavailable => return Err(RedactionError::Unavailable),
        Completeness::Unknown => return Err(RedactionError::Absence),
        _ => return Err(RedactionError::Partial),
    }
    Ok(())
}

pub fn redact_result(
    result: &ProjectionResult,
    request: &NarrowedRequest,
) -> Result<PublicResult, RedactionError> {
    if result.schema_version != json!("1.0")
        || result.schema_version.as_str() != Some(request.response_schema_version())
        || result.request_digest.as_str() != request.request_digest()
        || result.profile_digest.as_str() != request.profile_digest()
    {
        return Err(RedactionError::Binding);
    }
    let mut response_value = serde_json::to_value(result).map_err(|_| RedactionError::Binding)?;
    let response = response_value
        .as_object_mut()
        .ok_or(RedactionError::Binding)?;
    response.remove("responseDigest");
    let expected_response_digest =
        sha256_digest(&canonical_json_bytes(&response_value).map_err(|_| RedactionError::Binding)?);
    let expected_provenance_digest = sha256_digest(
        &canonical_json_bytes(&json!({
            "profileDigest": request.profile_digest(),
            "requestDigest": request.request_digest(),
            "provenanceProfileDigest": request.provenance_profile_digest(),
        }))
        .map_err(|_| RedactionError::Binding)?,
    );
    if result.response_digest.as_str() != expected_response_digest
        || result.provenance_digest.as_str() != expected_provenance_digest
    {
        return Err(RedactionError::Binding);
    }
    let observed_at = OffsetDateTime::parse(&result.observed_at, &Rfc3339)
        .map_err(|_| RedactionError::Binding)?;
    if observed_at > request.issued_at()
        || observed_at > request.deadline_at()
        || (request.issued_at() - observed_at).whole_milliseconds()
            > i128::from(request.maximum_freshness_age_milliseconds())
    {
        return Err(RedactionError::Stale);
    }
    if result.records.len() > request.page_limit()
        || result.page.cursor.as_deref().map(String::as_str) == request.prior_cursor()
            && result.page.cursor.is_some()
    {
        return Err(RedactionError::Partial);
    }
    validate_truth(result)?;
    let allowed = request
        .projection_fields()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut prior_record: Option<&str> = None;
    for record in &result.records {
        if prior_record.is_some_and(|prior| cmp_utf16(prior, record.id.as_str()) != Ordering::Less)
        {
            return Err(RedactionError::Partial);
        }
        prior_record = Some(record.id.as_str());
        let mut prior_field: Option<&str> = None;
        for field in &record.fields {
            if !allowed.contains(field.field_id.as_str()) {
                return Err(RedactionError::Scope);
            }
            if prior_field
                .is_some_and(|prior| cmp_utf16(prior, field.field_id.as_str()) != Ordering::Less)
            {
                return Err(RedactionError::Partial);
            }
            prior_field = Some(field.field_id.as_str());
        }
    }
    let outcome = result.completeness.to_string();
    let truth_state = match result.completeness {
        Completeness::Complete => "TRUE",
        Completeness::Partial => "PARTIAL",
        Completeness::Unknown => "UNKNOWN",
        Completeness::Unavailable => "UNAVAILABLE",
    };
    let records = serde_json::to_value(&result.records).map_err(|_| RedactionError::Binding)?;
    let page = json!({
        "cursor": result.page.cursor.as_deref().map(String::as_str),
        "gapFree": result.page.gap_free,
    });
    let preimage = json!({
        "schemaVersion": "1.0",
        "outcome": outcome,
        "truthState": truth_state,
        "requestDigest": request.request_digest(),
        "profileDigest": request.profile_digest(),
        "queryDigest": request.query_digest(),
        "records": records,
        "page": page,
    });
    let result_digest =
        sha256_digest(&canonical_json_bytes(&preimage).map_err(|_| RedactionError::Binding)?);
    let mut public = match preimage {
        Value::Object(values) => values,
        _ => return Err(RedactionError::Binding),
    };
    public.insert("resultDigest".to_owned(), Value::String(result_digest));
    serde_json::from_value(Value::Object(public)).map_err(|_| RedactionError::Binding)
}
