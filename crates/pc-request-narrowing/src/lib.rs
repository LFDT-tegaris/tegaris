#![forbid(unsafe_code)]

//! Pure Privacy Explorer request narrowing over generated contract types.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use pc_contracts::generated::json_schema::openpc_contracts::{
    PrivacyExplorerExplorerProjectionRequestV1 as ProjectionRequest, PrivacyExplorerScalarValue,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NarrowingError {
    #[error("PC-INTEGRATION-5002 request scope rejected")]
    Scope,
    #[error("PC-RUNTIME-3009 request binding rejected")]
    Binding,
    #[error("PC-DATA-6004 request ordering or bounds rejected")]
    Shape,
}

pub struct NarrowingContext<'a> {
    pub purpose: &'a str,
    pub subject: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub platform_id: &'a str,
    pub workload_id: &'a str,
    pub profile_digest: &'a str,
    pub request_id: &'a str,
    pub correlation_id: &'a str,
    pub deadline_at: &'a str,
    pub allowed_field_ids: &'a [&'a str],
    pub allowed_filter_ids: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowedRequest {
    canonical_request: Vec<u8>,
    query_digest: String,
    request_digest: String,
    profile_digest: String,
    response_schema_version: String,
    provenance_profile_digest: String,
    projection_fields: Vec<String>,
    page_limit: usize,
    prior_cursor: Option<String>,
    issued_at: OffsetDateTime,
    deadline_at: OffsetDateTime,
    maximum_freshness_age_milliseconds: i64,
}

impl NarrowedRequest {
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    #[must_use]
    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn response_schema_version(&self) -> &str {
        &self.response_schema_version
    }

    #[must_use]
    pub fn provenance_profile_digest(&self) -> &str {
        &self.provenance_profile_digest
    }

    #[must_use]
    pub fn projection_fields(&self) -> &[String] {
        &self.projection_fields
    }

    #[must_use]
    pub const fn page_limit(&self) -> usize {
        self.page_limit
    }

    #[must_use]
    pub fn prior_cursor(&self) -> Option<&str> {
        self.prior_cursor.as_deref()
    }

    #[must_use]
    pub const fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    #[must_use]
    pub const fn deadline_at(&self) -> OffsetDateTime {
        self.deadline_at
    }

    #[must_use]
    pub const fn maximum_freshness_age_milliseconds(&self) -> i64 {
        self.maximum_freshness_age_milliseconds
    }
}

fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn strings_are_strictly_ordered<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut prior: Option<&str> = None;
    for value in values {
        if prior.is_some_and(|previous| cmp_utf16(previous, value) != Ordering::Less) {
            return false;
        }
        prior = Some(value);
    }
    true
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_value(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Number(number) => number.as_f64().map_or_else(
            || value.clone(),
            |number| {
                if number.fract() != 0.0 || number.abs() > 9_007_199_254_740_991.0 {
                    value.clone()
                } else if number.is_sign_negative() {
                    Value::Number(serde_json::Number::from(number as i64))
                } else {
                    Value::Number(serde_json::Number::from(number as u64))
                }
            },
        ),
        _ => value.clone(),
    }
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, NarrowingError> {
    let value = serde_json::to_value(value).map_err(|_| NarrowingError::Shape)?;
    serde_json::to_vec(&canonical_value(&value)).map_err(|_| NarrowingError::Shape)
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in Sha256::digest(bytes) {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn scalar_is_admitted(value: &PrivacyExplorerScalarValue) -> bool {
    !matches!(value, PrivacyExplorerScalarValue::Integer(number) if number.unsigned_abs() > 9_007_199_254_740_991)
}

pub fn narrow_request(
    request: &ProjectionRequest,
    context: &NarrowingContext<'_>,
) -> Result<NarrowedRequest, NarrowingError> {
    if request.operation_version != json!("v1") || request.schema_version != json!("1.0") {
        return Err(NarrowingError::Shape);
    }
    if request.purpose.as_str() != context.purpose
        || request.subject.as_str() != context.subject
        || request.resource.as_str() != context.resource
        || request.action.as_str() != context.action
        || request.scope.participant_id.as_str() != context.participant_id
        || request.scope.privacy_domain_id.as_str() != context.privacy_domain_id
        || request.scope.platform_id.as_str() != context.platform_id
        || request.scope.workload_id.as_str() != context.workload_id
        || request.scope.action.as_str() != context.action
        || request.export_profile.digest.as_str() != context.profile_digest
        || request.occurrence.request_id.as_str() != context.request_id
        || request.occurrence.correlation_id.as_str() != context.correlation_id
    {
        return Err(NarrowingError::Binding);
    }
    let mut profile_value =
        serde_json::to_value(&request.export_profile).map_err(|_| NarrowingError::Shape)?;
    let profile_object = profile_value.as_object_mut().ok_or(NarrowingError::Shape)?;
    profile_object.remove("digest");
    if request.export_profile.digest.as_str()
        != sha256_digest(&canonical_json_bytes(&profile_value)?)
    {
        return Err(NarrowingError::Binding);
    }
    let profile = &request.export_profile;
    let attempts = profile.maximum_read_attempts.get();
    let issued_at =
        OffsetDateTime::parse(&request.issued_at, &Rfc3339).map_err(|_| NarrowingError::Shape)?;
    let deadline_at =
        OffsetDateTime::parse(context.deadline_at, &Rfc3339).map_err(|_| NarrowingError::Shape)?;
    let profile_deadline = OffsetDateTime::parse(&profile.maximum_deadline_at, &Rfc3339)
        .map_err(|_| NarrowingError::Shape)?;
    if profile.operation_versions.len() != 9
        || !strings_are_strictly_ordered(
            profile
                .operation_versions
                .iter()
                .map(|entry| entry.operation_id.as_str()),
        )
        || profile.operation_versions.iter().any(|entry| {
            entry.accepted_data_class_ids.is_empty()
                || entry.accepted_data_class_ids.len() > 64
                || !strings_are_strictly_ordered(
                    entry
                        .accepted_data_class_ids
                        .iter()
                        .map(|class| class.as_str()),
                )
        })
        || profile.allowed_field_ids.is_empty()
        || profile.allowed_field_ids.len() > 64
        || !strings_are_strictly_ordered(
            profile.allowed_field_ids.iter().map(|field| field.as_str()),
        )
        || profile.allowed_filter_ids.is_empty()
        || profile.allowed_filter_ids.len() > 32
        || !strings_are_strictly_ordered(
            profile
                .allowed_filter_ids
                .iter()
                .map(|filter| filter.as_str()),
        )
        || profile.maximum_page_size.get() > 200
        || !(0..=31_536_000_000).contains(&profile.maximum_freshness_age_milliseconds)
        || !(1..=4).contains(&attempts)
        || profile.retry_backoff_milliseconds.len() != (attempts - 1) as usize
        || profile
            .retry_backoff_milliseconds
            .iter()
            .any(|delay| !(0..=60_000).contains(delay))
        || profile
            .retry_backoff_milliseconds
            .windows(2)
            .any(|pair| pair[0] > pair[1])
        || profile.response_schema_version != json!("1.0")
        || deadline_at <= issued_at
        || deadline_at > profile_deadline
    {
        return Err(NarrowingError::Shape);
    }
    let operation = request
        .export_profile
        .operation_versions
        .iter()
        .find(|entry| {
            entry.operation_id.as_str() == request.operation_id.as_str()
                && entry.version.as_str() == request.semantic_operation_version.as_str()
        });
    if operation.is_none_or(|entry| {
        !entry
            .accepted_data_class_ids
            .iter()
            .any(|class| class.as_str() == request.data_class_id.as_str())
    }) {
        return Err(NarrowingError::Scope);
    }
    let allowed_fields = context
        .allowed_field_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let allowed_filters = context
        .allowed_filter_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let profile_fields = profile
        .allowed_field_ids
        .iter()
        .map(|field| field.as_str())
        .collect::<BTreeSet<_>>();
    let profile_filters = profile
        .allowed_filter_ids
        .iter()
        .map(|filter| filter.as_str())
        .collect::<BTreeSet<_>>();
    if allowed_fields.len() != context.allowed_field_ids.len()
        || allowed_filters.len() != context.allowed_filter_ids.len()
        || !strings_are_strictly_ordered(context.allowed_field_ids.iter().copied())
        || !strings_are_strictly_ordered(context.allowed_filter_ids.iter().copied())
        || request.projection_fields.is_empty()
        || request.projection_fields.len() > 64
        || request
            .projection_fields
            .windows(2)
            .any(|pair| cmp_utf16(pair[0].as_str(), pair[1].as_str()) != Ordering::Less)
        || request.projection_fields.iter().any(|field| {
            !allowed_fields.contains(field.as_str()) || !profile_fields.contains(field.as_str())
        })
    {
        return Err(NarrowingError::Scope);
    }
    if request.filters.len() > 32
        || request.page.limit.get() > request.export_profile.maximum_page_size.get()
    {
        return Err(NarrowingError::Shape);
    }
    let projection_fields = request
        .projection_fields
        .iter()
        .map(|field| field.as_str())
        .collect::<BTreeSet<_>>();
    let mut prior_filter: Option<(String, String, String)> = None;
    for filter in &request.filters {
        if !projection_fields.contains(filter.field_id.as_str())
            || !allowed_filters.contains(filter.filter_id.as_str())
            || !profile_filters.contains(filter.filter_id.as_str())
            || !scalar_is_admitted(&filter.value)
        {
            return Err(NarrowingError::Scope);
        }
        let value = String::from_utf8(canonical_json_bytes(&filter.value)?)
            .map_err(|_| NarrowingError::Shape)?;
        let identity = (
            filter.field_id.to_string(),
            filter.filter_id.to_string(),
            value,
        );
        if prior_filter.as_ref().is_some_and(|prior| {
            cmp_utf16(&prior.0, &identity.0)
                .then_with(|| cmp_utf16(&prior.1, &identity.1))
                .then_with(|| cmp_utf16(&prior.2, &identity.2))
                != Ordering::Less
        }) {
            return Err(NarrowingError::Shape);
        }
        prior_filter = Some(identity);
    }
    let query_preimage = json!({
        "purpose": request.purpose,
        "subject": request.subject,
        "resource": request.resource,
        "action": request.action,
        "scope": request.scope,
        "operationId": request.operation_id,
        "semanticOperationVersion": request.semantic_operation_version,
        "dataClassId": request.data_class_id,
        "filters": request.filters,
        "page": { "limit": request.page.limit.get() },
        "projectionFields": request.projection_fields,
        "exportProfileDigest": request.export_profile.digest,
    });
    let query_digest = sha256_digest(&canonical_json_bytes(&query_preimage)?);
    if request.query_digest.as_str() != query_digest {
        return Err(NarrowingError::Binding);
    }
    let canonical_request = canonical_json_bytes(request)?;
    let request_digest = sha256_digest(&canonical_request);
    Ok(NarrowedRequest {
        canonical_request,
        query_digest,
        request_digest,
        profile_digest: request.export_profile.digest.to_string(),
        response_schema_version: request
            .export_profile
            .response_schema_version
            .as_str()
            .ok_or(NarrowingError::Shape)?
            .to_owned(),
        provenance_profile_digest: request.export_profile.provenance_profile_digest.to_string(),
        projection_fields: request
            .projection_fields
            .iter()
            .map(|field| field.as_str().to_owned())
            .collect(),
        page_limit: request.page.limit.get() as usize,
        prior_cursor: request.page.cursor.as_deref().map(ToString::to_string),
        issued_at,
        deadline_at,
        maximum_freshness_age_milliseconds: profile.maximum_freshness_age_milliseconds,
    })
}
