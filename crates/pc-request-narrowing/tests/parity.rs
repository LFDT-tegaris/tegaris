use std::fs;

use pc_contracts::generated::json_schema::openpc_contracts::PrivacyExplorerExplorerProjectionRequestV1;
use pc_request_narrowing::{
    NarrowingContext, NarrowingError, canonical_json_bytes, narrow_request, sha256_digest,
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

fn context<'a>(fixture: &'a Value) -> NarrowingContext<'a> {
    let value = &fixture["context"];
    NarrowingContext {
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
    }
}

fn reseal_request(request: &mut Value) -> String {
    let mut profile = request["exportProfile"].clone();
    profile.as_object_mut().unwrap().remove("digest");
    let profile_digest = sha256_digest(&canonical_json_bytes(&profile).unwrap());
    request["exportProfile"]["digest"] = Value::String(profile_digest.clone());
    let query_preimage = serde_json::json!({
        "purpose": request["purpose"],
        "subject": request["subject"],
        "resource": request["resource"],
        "action": request["action"],
        "scope": request["scope"],
        "operationId": request["operationId"],
        "semanticOperationVersion": request["semanticOperationVersion"],
        "dataClassId": request["dataClassId"],
        "filters": request["filters"],
        "page": { "limit": request["page"]["limit"] },
        "projectionFields": request["projectionFields"],
        "exportProfileDigest": profile_digest,
    });
    request["queryDigest"] = Value::String(sha256_digest(
        &canonical_json_bytes(&query_preimage).unwrap(),
    ));
    request["exportProfile"]["digest"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn generated_request_matches_canonical_typescript_vectors() {
    let fixture = fixture();
    let request: PrivacyExplorerExplorerProjectionRequestV1 =
        serde_json::from_value(fixture["request"].clone()).unwrap();
    let narrowed = narrow_request(&request, &context(&fixture)).unwrap();
    assert_eq!(narrowed.query_digest(), fixture["expected"]["queryDigest"]);
    assert_eq!(
        narrowed.request_digest(),
        fixture["expected"]["requestDigest"]
    );
    assert!(
        std::str::from_utf8(narrowed.canonical_request())
            .unwrap()
            .contains("\"occurrence\"")
    );
}

#[test]
fn binding_scope_order_duplicates_and_scalar_types_fail_closed() {
    let fixture = fixture();
    let mut mismatched = fixture["request"].clone();
    mismatched["occurrence"]["requestId"] = Value::String("other".into());
    let request = serde_json::from_value(mismatched).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&fixture)),
        Err(NarrowingError::Binding)
    );

    let mut duplicate = fixture["request"].clone();
    duplicate["projectionFields"] = serde_json::json!(["PEF-A", "PEF-A"]);
    let request = serde_json::from_value(duplicate).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&fixture)),
        Err(NarrowingError::Scope)
    );

    let mut scalar = fixture["request"].clone();
    scalar["filters"][0]["value"] = Value::String("7".into());
    let request = serde_json::from_value(scalar).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&fixture)),
        Err(NarrowingError::Binding)
    );

    let mut unsafe_integer = fixture["request"].clone();
    unsafe_integer["filters"][0]["value"] = Value::from(9_007_199_254_740_992_i64);
    let request = serde_json::from_value(unsafe_integer).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&fixture)),
        Err(NarrowingError::Scope)
    );

    let mut fractional = fixture["request"].clone();
    fractional["filters"][0]["value"] = serde_json::json!(1.5);
    assert!(
        serde_json::from_value::<PrivacyExplorerExplorerProjectionRequestV1>(fractional).is_err()
    );
}

#[test]
fn self_consistent_false_profile_relations_fail_closed() {
    let mut missing_operation = fixture();
    missing_operation["request"]["exportProfile"]["operationVersions"]
        .as_array_mut()
        .unwrap()
        .pop();
    let profile_digest = reseal_request(&mut missing_operation["request"]);
    missing_operation["context"]["profileDigest"] = Value::String(profile_digest);
    let request = serde_json::from_value(missing_operation["request"].clone()).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&missing_operation)),
        Err(NarrowingError::Shape)
    );

    let mut missing_profile_field = fixture();
    missing_profile_field["request"]["exportProfile"]["allowedFieldIds"] =
        serde_json::json!(["PEF-A"]);
    let profile_digest = reseal_request(&mut missing_profile_field["request"]);
    missing_profile_field["context"]["profileDigest"] = Value::String(profile_digest);
    let request = serde_json::from_value(missing_profile_field["request"].clone()).unwrap();
    assert_eq!(
        narrow_request(&request, &context(&missing_profile_field)),
        Err(NarrowingError::Scope)
    );
}
