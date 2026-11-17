use std::fs;

use pc_contracts::generated::json_schema::openpc_contracts::{
    PrivacyExplorerExplorerProjectionRequestV1, PrivacyExplorerExplorerProjectionResultV1,
};
use pc_redaction::{RedactionError, redact_result};
use pc_request_narrowing::{
    NarrowedRequest, NarrowingContext, canonical_json_bytes, narrow_request, sha256_digest,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/privacy-explorer/i07-gate2-b3-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

fn narrowed(fixture: &Value) -> NarrowedRequest {
    let request: PrivacyExplorerExplorerProjectionRequestV1 =
        serde_json::from_value(fixture["request"].clone()).unwrap();
    let value = &fixture["context"];
    narrow_request(
        &request,
        &NarrowingContext {
            purpose: value["purpose"].as_str().unwrap(),
            subject: value["subject"].as_str().unwrap(),
            resource: value["resource"].as_str().unwrap(),
            action: value["action"].as_str().unwrap(),
            participant_id: value["participantId"].as_str().unwrap(),
            privacy_domain_id: value["privacyDomainId"].as_str().unwrap(),
            platform_id: value["platformId"].as_str().unwrap(),
            workload_id: value["workloadId"].as_str().unwrap(),
            profile_digest: value["profileDigest"].as_str().unwrap(),
            request_id: value["requestId"].as_str().unwrap(),
            correlation_id: value["correlationId"].as_str().unwrap(),
            deadline_at: "2027-01-01T00:01:00.000Z",
            allowed_field_ids: &["PEF-A", "PEF-B"],
            allowed_filter_ids: &["PEFILTER-A", "PEFILTER-B"],
        },
    )
    .unwrap()
}

fn refresh_response_digest(value: &mut Value) {
    let mut preimage = value.clone();
    preimage.as_object_mut().unwrap().remove("responseDigest");
    value["responseDigest"] =
        Value::String(sha256_digest(&canonical_json_bytes(&preimage).unwrap()));
}

#[test]
fn redaction_matches_typescript_public_digest_and_preserves_scalar_types() {
    let fixture = fixture();
    let raw: PrivacyExplorerExplorerProjectionResultV1 =
        serde_json::from_value(fixture["completeRaw"].clone()).unwrap();
    let public = redact_result(&raw, &narrowed(&fixture)).unwrap();
    assert_eq!(
        public.result_digest.as_str(),
        fixture["expected"]["resultDigest"]
    );
    let serialized = serde_json::to_value(public).unwrap();
    assert_eq!(
        serialized["records"][0]["fields"][0]["value"].as_f64(),
        Some(7.0)
    );
    assert_eq!(serialized["records"][1]["fields"][0]["value"], true);
    assert!(serialized["records"][1]["fields"][1]["value"].is_null());
}

#[test]
fn binding_scope_truth_and_order_relations_map_to_exact_codes() {
    let fixture = fixture();
    let cases = [
        (
            "profileDigest",
            Value::String(format!("sha256:{}", "d".repeat(64))),
            RedactionError::Binding,
        ),
        (
            "freshness",
            Value::String("STALE".into()),
            RedactionError::Stale,
        ),
        (
            "conflict",
            Value::String("REORG".into()),
            RedactionError::Reorg,
        ),
        (
            "conflict",
            Value::String("CONFLICT".into()),
            RedactionError::Conflict,
        ),
        (
            "observedAt",
            Value::String("2026-12-31T23:58:00.000Z".into()),
            RedactionError::Stale,
        ),
        (
            "observedAt",
            Value::String("2027-01-01T00:00:01.000Z".into()),
            RedactionError::Stale,
        ),
        (
            "observedAt",
            Value::String("not-a-date".into()),
            RedactionError::Binding,
        ),
    ];
    for (field, value, expected) in cases {
        let mut raw = fixture["completeRaw"].clone();
        raw[field] = value;
        refresh_response_digest(&mut raw);
        let raw = serde_json::from_value(raw).unwrap();
        let error = redact_result(&raw, &narrowed(&fixture)).unwrap_err();
        assert_eq!(error, expected);
        let key = match expected {
            RedactionError::Binding => "binding",
            RedactionError::Stale => "stale",
            RedactionError::Reorg => "reorg",
            RedactionError::Conflict => "conflict",
            _ => unreachable!(),
        };
        assert_eq!(error.code(), fixture["expected"]["errorCodes"][key]);
    }

    let mut forbidden = fixture["completeRaw"].clone();
    forbidden["records"][0]["fields"][1]["fieldId"] = Value::String("PEF-X".into());
    refresh_response_digest(&mut forbidden);
    let raw = serde_json::from_value(forbidden).unwrap();
    assert_eq!(
        redact_result(&raw, &narrowed(&fixture)).unwrap_err(),
        RedactionError::Scope
    );

    let mut unknown_with_records = fixture["completeRaw"].clone();
    unknown_with_records["completeness"] = Value::String("UNKNOWN".into());
    unknown_with_records["freshness"] = Value::String("UNKNOWN".into());
    unknown_with_records["page"]["gapFree"] = Value::Bool(false);
    refresh_response_digest(&mut unknown_with_records);
    let raw = serde_json::from_value(unknown_with_records).unwrap();
    assert_eq!(
        redact_result(&raw, &narrowed(&fixture)).unwrap_err(),
        RedactionError::Absence
    );
}
