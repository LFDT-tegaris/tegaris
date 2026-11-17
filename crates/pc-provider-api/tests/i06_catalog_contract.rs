use pc_provider_api::{PROVIDER_SCHEMA_IDENTITIES, SchemaIdentity, validate_schema_catalog};

const EXPECTED: [SchemaIdentity; 16] = [
    SchemaIdentity::new("ProviderProfileV1", 22001, "openpc:provider-profile:v1"),
    SchemaIdentity::new("RouteRequestV1", 22002, "openpc:route-request:v1"),
    SchemaIdentity::new("ChainReadAnchorV1", 22003, "openpc:chain-read-anchor:v1"),
    SchemaIdentity::new("AttemptEnvelopeV1", 22004, "openpc:provider-attempt:v1"),
    SchemaIdentity::new(
        "AttemptResolutionV2",
        22005,
        "openpc:provider-attempt-resolution:v2",
    ),
    SchemaIdentity::new(
        "RequestRouteWitnessV1",
        22006,
        "openpc:request-route-witness:v1",
    ),
    SchemaIdentity::new(
        "WriteReconciliationV1",
        22007,
        "openpc:write-reconciliation:v1",
    ),
    SchemaIdentity::new(
        "ClientIndexerProfileV1",
        22101,
        "openpc:client-indexer-profile:v1",
    ),
    SchemaIdentity::new("ProjectionPlanV1", 22102, "openpc:projection-plan:v1"),
    SchemaIdentity::new(
        "CandidateProjectionBatchV1",
        22103,
        "openpc:candidate-projection-batch:v1",
    ),
    SchemaIdentity::new(
        "ExplorerFactSourceProfileV1",
        22201,
        "openpc:explorer-fact-source-profile:v1",
    ),
    SchemaIdentity::new(
        "ExplorerCandidatePageV1",
        22202,
        "openpc:explorer-candidate-page:v1",
    ),
    SchemaIdentity::new(
        "TheGraphManifestProfileV1",
        22301,
        "openpc:the-graph-manifest-profile:v1",
    ),
    SchemaIdentity::new(
        "TheGraphCandidateBatchV1",
        22302,
        "openpc:the-graph-candidate-batch:v1",
    ),
    SchemaIdentity::new(
        "SubQueryClientProfileV1",
        22401,
        "openpc:subquery-client-profile:v1",
    ),
    SchemaIdentity::new(
        "SubQueryCandidateBatchV1",
        22402,
        "openpc:subquery-candidate-batch:v1",
    ),
];

#[test]
fn compiled_export_is_the_closed_pc_cbor_catalog() {
    /* nested decoy: /* SchemaIdentity::new("Wrong", 1, "wrong") */ still a comment */
    let _normal = "SchemaIdentity::new(\\\"Wrong\\\", 1, \\\"wrong\\\")";
    let _raw = r#"SchemaIdentity::new("Wrong", 1, "wrong")"#;
    let _byte = b"SchemaIdentity::new(\"Wrong\", 1, \"wrong\")";
    let _raw_byte = br#"SchemaIdentity::new("Wrong", 1, "wrong")"#;
    assert_eq!(PROVIDER_SCHEMA_IDENTITIES, EXPECTED);
    assert!(validate_schema_catalog(&PROVIDER_SCHEMA_IDENTITIES).is_ok());
}

#[test]
fn compiled_catalog_rejects_order_and_identity_drift() {
    let mut reordered = EXPECTED;
    reordered.swap(0, 1);
    assert!(validate_schema_catalog(&reordered).is_err());
    let mut drifted = EXPECTED;
    drifted[0].purpose_separator = "openpc:wrong:v1";
    assert!(validate_schema_catalog(&drifted).is_err());
}
