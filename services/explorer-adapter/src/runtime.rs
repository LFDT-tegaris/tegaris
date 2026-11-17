use pc_provider_api::{
    ExplorerCandidatePageV1, ExplorerCursorV1, ExplorerFactSourceProfileV1, InclusiveRangeV1,
    validate_explorer_page, validate_explorer_profile,
};
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerAcquisitionIntent {
    pub request_id: String,
    pub operation: String,
    pub data_class: String,
    pub fields: Vec<String>,
    pub filters: BTreeMap<String, String>,
    pub authorized_scope_digest: String,
    pub range: InclusiveRangeV1,
    pub cursor: ExplorerCursorV1,
    pub deadline_millis: u64,
}

#[derive(Debug, Error)]
pub enum ExplorerRuntimeError {
    #[error("EXPLORER-ACQUISITION-BINDING-INVALID")]
    InvalidIntent,
    #[error("EXPLORER-RATE-BUDGET-EXHAUSTED")]
    RateBudgetExhausted,
    #[error("EXPLORER-ACQUISITION-UNAVAILABLE")]
    Unavailable,
    #[error("EXPLORER-RESPONSE-OVERSIZED")]
    Oversized,
    #[error("EXPLORER-RESPONSE-INVALID")]
    InvalidResponse,
}

pub struct LocalFixtureExplorerRuntimeV1 {
    profile: ExplorerFactSourceProfileV1,
    client: reqwest::Client,
    endpoint: SecretString,
    secret_reference: String,
    _configuration_generation: u64,
    configuration_digest: String,
    secret: SecretString,
    remaining_requests: AtomicU64,
}

/// Opaque, unsigned local projection-shape evidence.
///
/// This type deliberately exposes no production conversion or persistence surface. A qualified
/// Explorer profile and an active LS-INDEXER/COM-015 owner are required before the contained page
/// can become durable candidate material.
pub struct LocalExplorerProjectionShapeV1 {
    _page: ExplorerCandidatePageV1,
    _local_configuration_digest: String,
}

impl LocalFixtureExplorerRuntimeV1 {
    /// Constructs the only admitted Explorer runtime: a fixed, loopback-only local fixture.
    pub fn for_i06_candidate_page(
        loopback_endpoint: &str,
        secret: SecretString,
    ) -> Result<Self, ExplorerRuntimeError> {
        let profile = crate::local_fixture_config::profile();
        validate_explorer_profile(&profile).map_err(|_| ExplorerRuntimeError::InvalidIntent)?;
        let parsed = reqwest::Url::parse(loopback_endpoint)
            .map_err(|_| ExplorerRuntimeError::InvalidIntent)?;
        let loopback_host = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
        if parsed.scheme() != "http"
            || !loopback_host
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || secret.expose_secret().is_empty()
        {
            return Err(ExplorerRuntimeError::InvalidIntent);
        }
        let secret_reference = "local-fixture:explorer-token".to_owned();
        let resolved_secret_version = "fixture-v1";
        let resolved_secret_fingerprint = digest_hex(secret.expose_secret().as_bytes());
        let configuration_generation = 1;
        let request_budget = 1;
        let configuration_projection = serde_json::json!({
            "profile": &profile,
            "endpointFingerprint": digest_hex(parsed.to_string().as_bytes()),
            "secretReference": &secret_reference,
            "resolvedSecretVersion": resolved_secret_version,
            "resolvedSecretFingerprint": &resolved_secret_fingerprint,
            "configurationGeneration": configuration_generation,
            "requestBudget": request_budget,
        });
        let configuration_digest = digest_hex(
            &bounded_jcs_bytes(&configuration_projection)
                .map_err(|_| ExplorerRuntimeError::InvalidIntent)?,
        );
        Ok(Self {
            profile,
            client: reqwest::Client::new(),
            endpoint: SecretString::from(parsed.to_string()),
            secret_reference,
            _configuration_generation: configuration_generation,
            configuration_digest,
            secret,
            remaining_requests: AtomicU64::new(request_budget),
        })
    }

    pub async fn acquire(
        &self,
        intent: &ExplorerAcquisitionIntent,
    ) -> Result<LocalExplorerProjectionShapeV1, ExplorerRuntimeError> {
        validate_intent(&self.profile, intent)?;
        let request_bytes = explorer_request_bytes(&self.profile, intent)?;
        if u64::try_from(request_bytes.len())
            .map_or(true, |size| size > self.profile.limits.max_request_bytes)
            || parse_strict_json(&request_bytes, self.profile.limits.max_depth).is_err()
        {
            return Err(ExplorerRuntimeError::InvalidIntent);
        }

        self.remaining_requests
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .map_err(|_| ExplorerRuntimeError::RateBudgetExhausted)?;

        let started = Instant::now();
        let deadline = Duration::from_millis(intent.deadline_millis);
        let send = self
            .client
            .post(self.endpoint.expose_secret())
            .header("content-type", "application/json")
            .header("x-openpc-secret-reference", &self.secret_reference)
            .bearer_auth(self.secret.expose_secret())
            .body(request_bytes)
            .send();
        let mut response = tokio::time::timeout(deadline, send)
            .await
            .map_err(|_| ExplorerRuntimeError::Unavailable)?
            .map_err(|_| ExplorerRuntimeError::Unavailable)?;
        if !response.status().is_success() {
            return Err(ExplorerRuntimeError::Unavailable);
        }
        let byte_limit = self
            .profile
            .page_limits
            .max_page_bytes
            .min(self.profile.limits.max_response_bytes);
        if response
            .content_length()
            .is_some_and(|length| length > byte_limit)
        {
            return Err(ExplorerRuntimeError::Oversized);
        }
        let mut bytes = Vec::new();
        loop {
            let remaining = deadline
                .checked_sub(started.elapsed())
                .ok_or(ExplorerRuntimeError::Unavailable)?;
            let chunk = tokio::time::timeout(remaining, response.chunk())
                .await
                .map_err(|_| ExplorerRuntimeError::Unavailable)?
                .map_err(|_| ExplorerRuntimeError::Unavailable)?;
            let Some(chunk) = chunk else { break };
            let next_size = bytes
                .len()
                .checked_add(chunk.len())
                .and_then(|size| u64::try_from(size).ok())
                .ok_or(ExplorerRuntimeError::Oversized)?;
            if next_size > byte_limit {
                return Err(ExplorerRuntimeError::Oversized);
            }
            bytes.extend_from_slice(&chunk);
        }
        let page = validate_response_bytes(&self.profile, intent, &bytes)?;
        Ok(LocalExplorerProjectionShapeV1 {
            _page: page,
            _local_configuration_digest: self.configuration_digest.clone(),
        })
    }

    #[cfg(test)]
    fn local_configuration_identity(&self) -> (&str, u64) {
        (&self.configuration_digest, self._configuration_generation)
    }

    #[cfg(test)]
    fn for_test(
        profile: ExplorerFactSourceProfileV1,
        endpoint: String,
        secret: &str,
        request_budget: u64,
    ) -> Result<Self, ExplorerRuntimeError> {
        validate_explorer_profile(&profile).map_err(|_| ExplorerRuntimeError::InvalidIntent)?;
        let parsed =
            reqwest::Url::parse(&endpoint).map_err(|_| ExplorerRuntimeError::InvalidIntent)?;
        let secret_reference = "local-fixture:explorer-token".to_owned();
        let configuration_generation = 1;
        let configuration_projection = serde_json::json!({
            "profile": &profile,
            "endpointFingerprint": digest_hex(parsed.to_string().as_bytes()),
            "secretReference": &secret_reference,
            "resolvedSecretVersion": "fixture-v1",
            "resolvedSecretFingerprint": digest_hex(secret.as_bytes()),
            "configurationGeneration": configuration_generation,
            "requestBudget": request_budget,
        });
        let configuration_digest = digest_hex(
            &bounded_jcs_bytes(&configuration_projection)
                .map_err(|_| ExplorerRuntimeError::InvalidIntent)?,
        );
        Ok(Self {
            profile,
            client: reqwest::Client::new(),
            endpoint: SecretString::from(parsed.to_string()),
            secret_reference,
            _configuration_generation: configuration_generation,
            configuration_digest,
            secret: SecretString::from(secret.to_owned()),
            remaining_requests: AtomicU64::new(request_budget),
        })
    }
}

impl LocalExplorerProjectionShapeV1 {
    #[cfg(test)]
    fn page(&self) -> &ExplorerCandidatePageV1 {
        &self._page
    }

    #[cfg(test)]
    fn local_configuration_digest(&self) -> &str {
        &self._local_configuration_digest
    }
}

#[derive(Serialize)]
struct ExplorerRequestProjection<'a> {
    request_id: &'a str,
    profile_digest: &'a str,
    source_instance_id: &'a str,
    participant_binding: &'a str,
    privacy_binding: &'a str,
    authorized_scope_digest: &'a str,
    operation: &'a str,
    data_class: &'a str,
    fields: &'a [String],
    filters: &'a BTreeMap<String, String>,
    range: &'a InclusiveRangeV1,
    cursor: &'a ExplorerCursorV1,
    max_page_items: u64,
    chain_id: &'a str,
    genesis_hash: &'a str,
    network_id: &'a str,
}

fn explorer_request_projection<'a>(
    profile: &'a ExplorerFactSourceProfileV1,
    intent: &'a ExplorerAcquisitionIntent,
) -> ExplorerRequestProjection<'a> {
    ExplorerRequestProjection {
        request_id: &intent.request_id,
        profile_digest: &profile.profile_digest,
        source_instance_id: &profile.instance_id,
        participant_binding: &profile.participant_binding,
        privacy_binding: &profile.privacy_binding,
        authorized_scope_digest: &intent.authorized_scope_digest,
        operation: &intent.operation,
        data_class: &intent.data_class,
        fields: &intent.fields,
        filters: &intent.filters,
        range: &intent.range,
        cursor: &intent.cursor,
        max_page_items: profile.page_limits.max_page_items,
        chain_id: &profile.chain_id,
        genesis_hash: &profile.genesis_hash,
        network_id: &profile.network_id,
    }
}

fn explorer_request_bytes(
    profile: &ExplorerFactSourceProfileV1,
    intent: &ExplorerAcquisitionIntent,
) -> Result<Vec<u8>, ExplorerRuntimeError> {
    let value = serde_json::to_value(explorer_request_projection(profile, intent))
        .map_err(|_| ExplorerRuntimeError::InvalidIntent)?;
    bounded_jcs_bytes(&value).map_err(|_| ExplorerRuntimeError::InvalidIntent)
}

fn validate_intent(
    profile: &ExplorerFactSourceProfileV1,
    intent: &ExplorerAcquisitionIntent,
) -> Result<(), ExplorerRuntimeError> {
    let fields = intent.fields.iter().collect::<BTreeSet<_>>();
    let filters = intent.filters.keys().collect::<BTreeSet<_>>();
    let field_ordered = intent.fields.windows(2).all(|pair| pair[0] < pair[1]);
    let span = intent
        .range
        .end
        .checked_sub(intent.range.start)
        .and_then(|value| value.checked_add(1));
    let owned = profile.source_partitions.iter().filter(|partition| {
        partition.range.start <= intent.range.start
            && match partition.range.end {
                pc_provider_api::RangeEndV1::Inclusive(end) => intent.range.end <= end,
                pc_provider_api::RangeEndV1::Open => true,
            }
    });
    if intent.request_id.is_empty()
        || !profile.allowed_operations.contains(&intent.operation)
        || !profile.allowed_data_classes.contains(&intent.data_class)
        || intent.fields.is_empty()
        || !field_ordered
        || fields.len() != intent.fields.len()
        || !fields
            .iter()
            .all(|field| profile.allowed_fields.contains(field))
        || !filters
            .iter()
            .all(|filter| profile.allowed_filters.contains(filter))
        || !profile
            .scope_digests
            .iter()
            .any(|scope| scope.digest == intent.authorized_scope_digest)
        || intent.range.start == 0
        || intent.range.start > intent.range.end
        || span.is_none_or(|value| value > profile.limits.max_range)
        || owned.count() != 1
        || intent.deadline_millis == 0
    {
        return Err(ExplorerRuntimeError::InvalidIntent);
    }
    Ok(())
}

fn validate_response_bytes(
    profile: &ExplorerFactSourceProfileV1,
    intent: &ExplorerAcquisitionIntent,
    bytes: &[u8],
) -> Result<ExplorerCandidatePageV1, ExplorerRuntimeError> {
    if u64::try_from(bytes.len()).map_or(true, |size| {
        size > profile.page_limits.max_page_bytes || size > profile.limits.max_response_bytes
    }) {
        return Err(ExplorerRuntimeError::Oversized);
    }
    let value = parse_strict_json(bytes, profile.limits.max_depth)?;
    bounded_jcs_bytes(&value).map_err(|_| ExplorerRuntimeError::InvalidResponse)?;
    let page: ExplorerCandidatePageV1 =
        serde_json::from_value(value).map_err(|_| ExplorerRuntimeError::InvalidResponse)?;
    let digest_material = explorer_response_digest_material(&page)?;
    if digest_hex(&digest_material) != page.response_digest
        || page.request_id != intent.request_id
        || page.authorized_scope_digest != intent.authorized_scope_digest
        || page.range != intent.range
        || page.resume_cursor != intent.cursor
    {
        return Err(ExplorerRuntimeError::InvalidResponse);
    }
    validate_explorer_page(profile, &page).map_err(|_| ExplorerRuntimeError::InvalidResponse)?;
    Ok(page)
}

fn explorer_response_digest_material(
    page: &ExplorerCandidatePageV1,
) -> Result<Vec<u8>, ExplorerRuntimeError> {
    let mut value =
        serde_json::to_value(page).map_err(|_| ExplorerRuntimeError::InvalidResponse)?;
    let object = value
        .as_object_mut()
        .ok_or(ExplorerRuntimeError::InvalidResponse)?;
    match object.remove("response_digest") {
        Some(Value::String(_)) => {}
        _ => return Err(ExplorerRuntimeError::InvalidResponse),
    }
    bounded_jcs_bytes(&value).map_err(|_| ExplorerRuntimeError::InvalidResponse)
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object member {key:?}"
                )));
            }
            let StrictJson(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictJson(Value::Object(object)))
    }
}

fn parse_strict_json(bytes: &[u8], max_depth: u64) -> Result<Value, ExplorerRuntimeError> {
    let StrictJson(value) = serde_json::from_slice::<StrictJson>(bytes)
        .map_err(|_| ExplorerRuntimeError::InvalidResponse)?;
    if usize::try_from(max_depth).map_or(true, |depth| json_depth(&value) > depth) {
        return Err(ExplorerRuntimeError::InvalidResponse);
    }
    Ok(value)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn bounded_jcs_bytes(value: &Value) -> Result<Vec<u8>, ()> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;

    fn append(value: &Value, output: &mut Vec<u8>) -> Result<(), ()> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Number(number) => {
                if let Some(signed) = number.as_i64() {
                    if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER as i64).contains(&signed) {
                        return Err(());
                    }
                    output.extend_from_slice(signed.to_string().as_bytes());
                } else if let Some(unsigned) = number.as_u64() {
                    if unsigned > MAX_SAFE_INTEGER {
                        return Err(());
                    }
                    output.extend_from_slice(unsigned.to_string().as_bytes());
                } else {
                    return Err(());
                }
            }
            Value::String(text) => {
                if !text.is_ascii() {
                    return Err(());
                }
                let encoded = serde_json::to_string(text).map_err(|_| ())?;
                output.extend_from_slice(encoded.as_bytes());
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    append(item, output)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                let mut names = values.keys().collect::<Vec<_>>();
                if names.iter().any(|name| !name.is_ascii()) {
                    return Err(());
                }
                names.sort_unstable();
                output.push(b'{');
                for (index, name) in names.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    let encoded = serde_json::to_string(name).map_err(|_| ())?;
                    output.extend_from_slice(encoded.as_bytes());
                    output.push(b':');
                    append(&values[name], output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    append(value, &mut output)?;
    Ok(output)
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_provider_api::{CandidateRecordV1, CompletedWatermarkV1, SourceAuthority};
    use secrecy::SecretString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const EXACT_REQUEST_BYTES: &[u8] = br#"{"authorized_scope_digest":"scope-digest","chain_id":"1","cursor":"Initial","data_class":"event","fields":["field"],"filters":{"filter":"value"},"genesis_hash":"genesis","max_page_items":100,"network_id":"network","operation":"read","participant_binding":"participant","privacy_binding":"privacy","profile_digest":"explorer-digest","range":{"end":2,"start":1},"request_id":"request","source_instance_id":"instance"}"#;
    const EXACT_REQUEST_SHA256: &str =
        "389744d8242130413035cfc47f284777bbe33dd4ed12fe0c3d597c950e18a6a7";
    const EXACT_RESPONSE_MATERIAL: &[u8] = br#"{"authorized_scope_digest":"scope-digest","completed_watermark":{"block_number":2,"canonical_block_hash":"block-2"},"derivation_digest":"derivation","evidence_refs":["evidence"],"missing_intervals":[],"next_cursor":"Complete","page_id":"page","participant_binding":"participant","privacy_binding":"privacy","profile_digest":"explorer-digest","profile_id":"explorer","profile_version":"1","provenance_digest":"provenance","range":{"end":2,"start":1},"records":[{"block_number":2,"canonical_block_hash":"block-2","evidence_digest":"record-evidence","normalized_digest":"normalized","record_id":"record","schema_digest":"schema","sequence":1}],"removal_observations":[],"reorg_observations":[],"request_id":"request","resume_cursor":"Initial","source_authority":"NonAuthoritativeCandidateOnly","source_instance_id":"instance"}"#;
    const EXACT_RESPONSE_DIGEST: &str =
        "6700573c5cd5c575cb1d21c16bd37b4bb79c521f9244501f5d1419483dbd7670";
    const EXACT_RESPONSE_BYTES: &[u8] = br#"{"authorized_scope_digest":"scope-digest","completed_watermark":{"block_number":2,"canonical_block_hash":"block-2"},"derivation_digest":"derivation","evidence_refs":["evidence"],"missing_intervals":[],"next_cursor":"Complete","page_id":"page","participant_binding":"participant","privacy_binding":"privacy","profile_digest":"explorer-digest","profile_id":"explorer","profile_version":"1","provenance_digest":"provenance","range":{"end":2,"start":1},"records":[{"block_number":2,"canonical_block_hash":"block-2","evidence_digest":"record-evidence","normalized_digest":"normalized","record_id":"record","schema_digest":"schema","sequence":1}],"removal_observations":[],"reorg_observations":[],"request_id":"request","response_digest":"6700573c5cd5c575cb1d21c16bd37b4bb79c521f9244501f5d1419483dbd7670","resume_cursor":"Initial","source_authority":"NonAuthoritativeCandidateOnly","source_instance_id":"instance"}"#;

    fn intent() -> ExplorerAcquisitionIntent {
        ExplorerAcquisitionIntent {
            request_id: "request".into(),
            operation: "read".into(),
            data_class: "event".into(),
            fields: vec!["field".into()],
            filters: BTreeMap::from([("filter".into(), "value".into())]),
            authorized_scope_digest: "scope-digest".into(),
            range: InclusiveRangeV1 { start: 1, end: 2 },
            cursor: ExplorerCursorV1::Initial,
            deadline_millis: 2_000,
        }
    }

    fn page() -> ExplorerCandidatePageV1 {
        ExplorerCandidatePageV1 {
            request_id: "request".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            profile_id: "explorer".into(),
            profile_version: "1".into(),
            profile_digest: "explorer-digest".into(),
            source_instance_id: "instance".into(),
            authorized_scope_digest: "scope-digest".into(),
            range: InclusiveRangeV1 { start: 1, end: 2 },
            page_id: "page".into(),
            resume_cursor: ExplorerCursorV1::Initial,
            response_digest: String::new(),
            records: vec![CandidateRecordV1 {
                sequence: 1,
                record_id: "record".into(),
                schema_digest: "schema".into(),
                normalized_digest: "normalized".into(),
                block_number: 2,
                canonical_block_hash: "block-2".into(),
                evidence_digest: "record-evidence".into(),
            }],
            missing_intervals: Vec::new(),
            completed_watermark: CompletedWatermarkV1 {
                block_number: 2,
                canonical_block_hash: "block-2".into(),
            },
            reorg_observations: Vec::new(),
            removal_observations: Vec::new(),
            derivation_digest: "derivation".into(),
            provenance_digest: "provenance".into(),
            evidence_refs: vec!["evidence".into()],
            next_cursor: ExplorerCursorV1::Complete,
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }

    fn independent_test_jcs(value: &Value) -> Vec<u8> {
        fn append(value: &Value, output: &mut Vec<u8>) {
            match value {
                Value::Null => output.extend_from_slice(b"null"),
                Value::Bool(value) => output.extend_from_slice(value.to_string().as_bytes()),
                Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
                Value::String(value) => output.extend_from_slice(
                    serde_json::to_string(value)
                        .expect("test JSON string")
                        .as_bytes(),
                ),
                Value::Array(values) => {
                    output.push(b'[');
                    for (index, item) in values.iter().enumerate() {
                        if index != 0 {
                            output.push(b',');
                        }
                        append(item, output);
                    }
                    output.push(b']');
                }
                Value::Object(values) => {
                    let mut names = values.keys().collect::<Vec<_>>();
                    names.sort_unstable();
                    output.push(b'{');
                    for (index, name) in names.into_iter().enumerate() {
                        if index != 0 {
                            output.push(b',');
                        }
                        output.extend_from_slice(
                            serde_json::to_string(name)
                                .expect("test JSON key")
                                .as_bytes(),
                        );
                        output.push(b':');
                        append(&values[name], output);
                    }
                    output.push(b'}');
                }
            }
        }
        let mut output = Vec::new();
        append(value, &mut output);
        output
    }

    fn response_bytes(mut page: ExplorerCandidatePageV1) -> Vec<u8> {
        let mut material = serde_json::to_value(&page).expect("response material");
        material
            .as_object_mut()
            .expect("response object")
            .remove("response_digest")
            .expect("response digest field");
        page.response_digest = digest_hex(&independent_test_jcs(&material));
        independent_test_jcs(&serde_json::to_value(page).expect("response object"))
    }

    fn build_runtime(
        profile: ExplorerFactSourceProfileV1,
        endpoint: String,
        secret: &str,
        request_budget: u64,
    ) -> Result<LocalFixtureExplorerRuntimeV1, ExplorerRuntimeError> {
        LocalFixtureExplorerRuntimeV1::for_test(profile, endpoint, secret, request_budget)
    }

    #[test]
    fn explorer_configuration_is_fixed_resource_bound_and_loopback_only() {
        let runtime = LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
            "http://127.0.0.1:8123",
            SecretString::from("test-secret"),
        )
        .expect("fixed local fixture");
        assert!(!runtime.local_configuration_identity().0.is_empty());
        assert_eq!(runtime.local_configuration_identity().1, 1);

        let equivalent = LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
            "http://127.0.0.1:8123/",
            SecretString::from("test-secret"),
        )
        .expect("canonical equivalent endpoint");
        assert_eq!(
            runtime.local_configuration_identity().0,
            equivalent.local_configuration_identity().0
        );
        let changed_endpoint = LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
            "http://127.0.0.1:8124/",
            SecretString::from("test-secret"),
        )
        .expect("different loopback resource");
        assert_ne!(
            runtime.local_configuration_identity().0,
            changed_endpoint.local_configuration_identity().0
        );
        let changed_secret = LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
            "http://127.0.0.1:8123/",
            SecretString::from("different-secret"),
        )
        .expect("different resolved secret");
        assert_ne!(
            runtime.local_configuration_identity().0,
            changed_secret.local_configuration_identity().0
        );
        for endpoint in [
            "https://127.0.0.1:8123/",
            "http://explorer.invalid/",
            "http://user@127.0.0.1:8123/",
            "http://127.0.0.1:8123/?query=1",
            "http://127.0.0.1:8123/#fragment",
        ] {
            assert!(
                LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
                    endpoint,
                    SecretString::from("test-secret"),
                )
                .is_err(),
                "non-fixture endpoint must reject: {endpoint}"
            );
        }
        assert!(
            LocalFixtureExplorerRuntimeV1::for_i06_candidate_page(
                "http://127.0.0.1:8123/",
                SecretString::from(String::new()),
            )
            .is_err()
        );
    }

    #[test]
    fn narrowing_rejects_disallowed_fields_filters_and_ranges() {
        let mut profile = crate::local_fixture_config::profile();
        profile.limits.max_range = 10;
        let base = intent();
        assert!(validate_intent(&profile, &base).is_ok());
        let mut field = base.clone();
        field.fields = vec!["forbidden".into()];
        assert!(validate_intent(&profile, &field).is_err());
        let mut filter = base.clone();
        filter.filters = BTreeMap::from([("forbidden".into(), "value".into())]);
        assert!(validate_intent(&profile, &filter).is_err());
        let mut range = base;
        range.range.end = 11;
        assert!(validate_intent(&profile, &range).is_err());
    }

    #[test]
    fn explorer_bounded_jcs_has_independent_known_answers_and_rejects_outside_domain() {
        let profile = crate::local_fixture_config::profile();
        let intent = intent();
        let request_value =
            serde_json::to_value(explorer_request_projection(&profile, &intent)).expect("request");
        assert_eq!(independent_test_jcs(&request_value), EXACT_REQUEST_BYTES);
        assert_eq!(digest_hex(EXACT_REQUEST_BYTES), EXACT_REQUEST_SHA256);
        assert_eq!(
            explorer_request_bytes(&profile, &intent).expect("bounded request"),
            EXACT_REQUEST_BYTES
        );

        let baseline_page = page();
        let mut material = serde_json::to_value(&baseline_page).expect("response material");
        material
            .as_object_mut()
            .expect("response object")
            .remove("response_digest")
            .expect("response digest field");
        assert_eq!(independent_test_jcs(&material), EXACT_RESPONSE_MATERIAL);
        assert_eq!(digest_hex(EXACT_RESPONSE_MATERIAL), EXACT_RESPONSE_DIGEST);
        assert_eq!(response_bytes(baseline_page), EXACT_RESPONSE_BYTES);

        let mut non_ascii_intent = intent.clone();
        non_ascii_intent.request_id = "requ\u{e9}st".into();
        assert!(explorer_request_bytes(&profile, &non_ascii_intent).is_err());
        let mut unsafe_profile = profile.clone();
        unsafe_profile.page_limits.max_page_items = 9_007_199_254_740_992;
        assert!(explorer_request_bytes(&unsafe_profile, &intent).is_err());
        assert!(bounded_jcs_bytes(&serde_json::json!({"float": 1.5})).is_err());

        let mut non_ascii_page = page();
        non_ascii_page.page_id = "p\u{e9}ge".into();
        assert!(explorer_response_digest_material(&non_ascii_page).is_err());
    }

    #[test]
    fn explorer_authoritative_empty_requires_affirmative_complete_coverage() {
        let mut profile = crate::local_fixture_config::profile();
        profile.page_limits.max_page_bytes = 10_000;
        profile.limits.max_response_bytes = 10_000;
        let intent = intent();
        let valid = response_bytes(page());
        assert_eq!(valid, EXACT_RESPONSE_BYTES);
        assert!(validate_response_bytes(&profile, &intent, &valid).is_ok());
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<Value>(&valid).expect("response JSON"),
        )
        .expect("pretty response");
        assert!(validate_response_bytes(&profile, &intent, &pretty).is_ok());
        let text = String::from_utf8(valid.clone()).expect("response text");
        let duplicate_root = text.replacen(
            "\"request_id\":\"request\"",
            "\"request_id\":\"wrong\",\"request_id\":\"request\"",
            1,
        );
        assert!(matches!(
            validate_response_bytes(&profile, &intent, duplicate_root.as_bytes()),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
        let duplicate_nested = text.replacen("\"sequence\":1", "\"sequence\":2,\"sequence\":1", 1);
        assert!(matches!(
            validate_response_bytes(&profile, &intent, duplicate_nested.as_bytes()),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
        let configured_depth = profile.limits.max_depth;
        profile.limits.max_depth = 2;
        assert!(matches!(
            validate_response_bytes(&profile, &intent, &valid),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
        profile.limits.max_depth = configured_depth;
        assert!(matches!(
            validate_response_bytes(&profile, &intent, b"not-json"),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
        let false_digest = String::from_utf8(valid.clone())
            .expect("response text")
            .replacen(EXACT_RESPONSE_DIGEST, &"0".repeat(64), 1);
        assert!(matches!(
            validate_response_bytes(&profile, &intent, false_digest.as_bytes()),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
        profile.page_limits.max_page_bytes = 1;
        assert!(matches!(
            validate_response_bytes(&profile, &intent, &valid),
            Err(ExplorerRuntimeError::Oversized)
        ));
        profile.page_limits.max_page_bytes = 10_000;
        let mut wrong = page();
        wrong.request_id = "wrong".into();
        assert!(matches!(
            validate_response_bytes(&profile, &intent, &response_bytes(wrong)),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));

        let mut empty = page();
        empty.records.clear();
        let accepted_empty =
            validate_response_bytes(&profile, &intent, &response_bytes(empty.clone()))
                .expect("affirmative authoritative empty");
        assert!(accepted_empty.records.is_empty());
        assert_eq!(accepted_empty.next_cursor, ExplorerCursorV1::Complete);
        empty.next_cursor = ExplorerCursorV1::Initial;
        assert!(matches!(
            validate_response_bytes(&profile, &intent, &response_bytes(empty)),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
    }

    #[test]
    fn explorer_handoff_preserves_identity_order_sequence_and_provenance() {
        let mut profile = crate::local_fixture_config::profile();
        profile.page_limits.max_page_bytes = 10_000;
        profile.page_limits.max_page_items = 2;
        profile.limits.max_response_bytes = 10_000;
        profile.limits.max_batch = 2;
        let intent = intent();
        let mut ordered = page();
        ordered.records.push(CandidateRecordV1 {
            sequence: 2,
            record_id: "record-2".into(),
            schema_digest: "schema".into(),
            normalized_digest: "normalized-2".into(),
            block_number: 2,
            canonical_block_hash: "block-2".into(),
            evidence_digest: "record-evidence-2".into(),
        });
        let validated =
            validate_response_bytes(&profile, &intent, &response_bytes(ordered.clone()))
                .expect("ordered page");
        assert_eq!(validated.records, ordered.records);
        assert_eq!(validated.provenance_digest, ordered.provenance_digest);
        assert_eq!(validated.evidence_refs, ordered.evidence_refs);

        ordered.records.reverse();
        assert!(matches!(
            validate_response_bytes(&profile, &intent, &response_bytes(ordered)),
            Err(ExplorerRuntimeError::InvalidResponse)
        ));
    }

    #[tokio::test]
    async fn loopback_request_is_narrowed_and_never_contains_the_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let body = response_bytes(page());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 32_768];
            let length = stream.read(&mut request).await.expect("read");
            request.truncate(length);
            let text = String::from_utf8(request).expect("request text");
            let (_, json_body) = text.split_once("\r\n\r\n").expect("HTTP body");
            assert_eq!(json_body.as_bytes(), EXACT_REQUEST_BYTES);
            assert!(!json_body.contains("test-secret"));
            assert!(json_body.contains("\"authorized_scope_digest\":\"scope-digest\""));
            assert!(json_body.contains("\"fields\":[\"field\"]"));
            assert!(
                text.to_ascii_lowercase()
                    .contains("authorization: bearer test-secret")
            );
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.expect("headers");
            stream.write_all(&body).await.expect("body");
        });
        let mut profile = crate::local_fixture_config::profile();
        profile.limits.max_request_bytes = 10_000;
        profile.limits.max_response_bytes = 10_000;
        profile.page_limits.max_page_bytes = 10_000;
        let runtime =
            build_runtime(profile, format!("http://{address}"), "test-secret", 1).expect("runtime");
        let validated = runtime.acquire(&intent()).await.expect("acquire");
        assert_eq!(validated.page().page_id, "page");
        assert_eq!(
            validated.local_configuration_digest(),
            runtime.local_configuration_identity().0
        );
        server.await.expect("server");
        assert!(matches!(
            runtime.acquire(&intent()).await,
            Err(ExplorerRuntimeError::RateBudgetExhausted)
        ));
    }

    #[tokio::test]
    async fn local_request_rejection_does_not_consume_budget_or_open_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let intent = intent();
        let mut profile = crate::local_fixture_config::profile();
        let exact_size = u64::try_from(EXACT_REQUEST_BYTES.len()).expect("request length");
        profile.limits.max_request_bytes = exact_size.checked_sub(1).expect("nonempty request");
        let runtime =
            build_runtime(profile, format!("http://{address}"), "test-secret", 1).expect("runtime");

        let mut invalid_intent = intent.clone();
        invalid_intent.fields = vec!["forbidden".into()];
        assert!(matches!(
            runtime.acquire(&invalid_intent).await,
            Err(ExplorerRuntimeError::InvalidIntent)
        ));
        assert_eq!(runtime.remaining_requests.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );

        assert!(matches!(
            runtime.acquire(&intent).await,
            Err(ExplorerRuntimeError::InvalidIntent)
        ));
        assert_eq!(runtime.remaining_requests.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn accepted_request_consumes_exactly_one_budget_before_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let intent = intent();
        let mut profile = crate::local_fixture_config::profile();
        profile.limits.max_request_bytes =
            u64::try_from(EXACT_REQUEST_BYTES.len()).expect("request length");
        let runtime =
            build_runtime(profile, format!("http://{address}"), "test-secret", 1).expect("runtime");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let length = stream.read(&mut request).await.expect("read");
            assert!(length > 0);
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await
                .expect("response");
        });

        assert!(matches!(
            runtime.acquire(&intent).await,
            Err(ExplorerRuntimeError::Unavailable)
        ));
        server.await.expect("server");
        assert_eq!(runtime.remaining_requests.load(Ordering::SeqCst), 0);
        assert!(matches!(
            runtime.acquire(&intent).await,
            Err(ExplorerRuntimeError::RateBudgetExhausted)
        ));
    }

    #[tokio::test]
    async fn streamed_body_obeys_the_header_to_body_deadline_and_decoded_byte_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n20\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n10\r\nbbbbbbbbbbbbbbbb\r\n0\r\n\r\n")
                .await
                .expect("chunked response");
        });
        let mut profile = crate::local_fixture_config::profile();
        profile.limits.max_request_bytes = 10_000;
        profile.limits.max_response_bytes = 64;
        profile.page_limits.max_page_bytes = 40;
        let runtime =
            build_runtime(profile, format!("http://{address}"), "test-secret", 1).expect("runtime");
        assert!(matches!(
            runtime.acquire(&intent()).await,
            Err(ExplorerRuntimeError::Oversized)
        ));
        server.await.expect("server");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("read");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n")
                .await
                .expect("headers");
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = stream.write_all(b"{}").await;
        });
        let mut profile = crate::local_fixture_config::profile();
        profile.limits.max_request_bytes = 10_000;
        profile.limits.max_response_bytes = 10_000;
        profile.page_limits.max_page_bytes = 10_000;
        let runtime =
            build_runtime(profile, format!("http://{address}"), "test-secret", 1).expect("runtime");
        let mut short_deadline = intent();
        short_deadline.deadline_millis = 10;
        assert!(matches!(
            runtime.acquire(&short_deadline).await,
            Err(ExplorerRuntimeError::Unavailable)
        ));
        server.await.expect("server");
    }
}
