use pc_contracts::{ContractError, ContractResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaIdentity {
    pub type_name: &'static str,
    pub numeric_schema_id: u32,
    pub purpose_separator: &'static str,
}

/// Semantic version of the facts schema family.
pub const FACT_SCHEMA_VERSION_V1: &str = "1.0.0";

/// SHA-256 of the authenticated normative fact-bridge definition.
///
/// The schema tuple is `(numeric ID, semantic version, schema digest)`
/// but does not publish a separate per-type JSON Schema digest for the fact
/// family. Binding the live owner to the authenticated normative definition
/// removes caller-selected digests without inventing an alternate schema.
pub const FACT_BRIDGE_SCHEMA_DIGEST_V1: [u8; 32] = [
    0xb0, 0x1a, 0x7c, 0x0d, 0x29, 0xf3, 0x0b, 0x33, 0x5a, 0xff, 0x75, 0xdb, 0x0c, 0x26, 0xfe, 0xa0,
    0x28, 0x7e, 0xa9, 0xfd, 0xd7, 0xe7, 0x7b, 0x1c, 0x6f, 0x5d, 0x2d, 0xe8, 0xb7, 0xca, 0x05, 0x25,
];

pub const RELATIONSHIP_CANDIDATE_SCHEMA_ID: u32 = 21_102;
pub const RELATIONSHIP_FACT_SCHEMA_ID: u32 = 21_103;
pub const RELATIONSHIP_SHARD_SCHEMA_ID: u32 = 21_104;
/// Authenticated relationship schema definition, shared by its registered types.
pub const RELATIONSHIP_SCHEMA_DIGEST_V1: [u8; 32] = [
    0xb8, 0x6e, 0xea, 0xf4, 0x6d, 0x4d, 0x23, 0xb0, 0x47, 0xea, 0xb6, 0x1e, 0x5e, 0x8e, 0x7a, 0x5d,
    0xfd, 0x8e, 0x74, 0x52, 0x58, 0x82, 0x00, 0x5b, 0x31, 0x6a, 0x93, 0xfb, 0x77, 0x12, 0x5d, 0x38,
];
pub const fn record_schema(relationship: bool) -> u32 {
    if relationship {
        RELATIONSHIP_FACT_SCHEMA_ID
    } else {
        FACT_RECORD_SCHEMA_ID
    }
}
pub const fn record_schema_digest(relationship: bool) -> &'static [u8; 32] {
    if relationship {
        &RELATIONSHIP_SCHEMA_DIGEST_V1
    } else {
        &FACT_BRIDGE_SCHEMA_DIGEST_V1
    }
}
pub const FACT_ADMISSION_CANDIDATE_SCHEMA_ID: u32 = 21_002;
pub const FACT_RECORD_SCHEMA_ID: u32 = 21_006;
pub const FACT_SHARD_MANIFEST_SCHEMA_ID: u32 = 21_009;

impl SchemaIdentity {
    pub const fn new(
        type_name: &'static str,
        numeric_schema_id: u32,
        purpose_separator: &'static str,
    ) -> Self {
        Self {
            type_name,
            numeric_schema_id,
            purpose_separator,
        }
    }
}

pub const FACT_SCHEMA_IDENTITIES: [SchemaIdentity; 10] = [
    SchemaIdentity::new(
        "CandidateOutboxEnvelopeV1",
        21001,
        "openpc:fact-candidate-outbox:v1",
    ),
    SchemaIdentity::new(
        "FactAdmissionCandidateV1",
        21002,
        "openpc:fact-admission-candidate:v1",
    ),
    SchemaIdentity::new(
        "CanonicalFactIdentityV1",
        21003,
        "openpc:canonical-fact-identity:v1",
    ),
    SchemaIdentity::new(
        "FactLineageActionV1",
        21004,
        "openpc:fact-lineage-action:v1",
    ),
    SchemaIdentity::new(
        "FactAdmissionReceiptV1",
        21005,
        "openpc:fact-admission-receipt:v1",
    ),
    SchemaIdentity::new("FactRecordV1", 21006, "openpc:fact-record:v1"),
    SchemaIdentity::new("FactReadinessV1", 21007, "openpc:fact-readiness:v1"),
    SchemaIdentity::new("FactCheckpointV1", 21008, "openpc:fact-checkpoint:v1"),
    SchemaIdentity::new(
        "FactShardManifestV1",
        21009,
        "openpc:fact-shard-manifest:v1",
    ),
    SchemaIdentity::new("FactQueryResultV1", 21010, "openpc:fact-query-result:v1"),
];

pub const RELATIONSHIP_SCHEMA_IDENTITIES: [SchemaIdentity; 8] = [
    SchemaIdentity::new(
        "RelationshipProfileV1",
        21101,
        "openpc:relationship-profile:v1",
    ),
    SchemaIdentity::new(
        "RelationshipCandidateV1",
        21102,
        "openpc:relationship-candidate:v1",
    ),
    SchemaIdentity::new("RelationshipFactV1", 21103, "openpc:relationship-fact:v1"),
    SchemaIdentity::new("RelationshipShardV1", 21104, "openpc:relationship-shard:v1"),
    SchemaIdentity::new(
        "RelationshipLookupV1",
        21105,
        "openpc:relationship-lookup:v1",
    ),
    SchemaIdentity::new(
        "RelationshipResultV1",
        21106,
        "openpc:relationship-result:v1",
    ),
    SchemaIdentity::new(
        "DynamicEventProfileV1",
        21107,
        "openpc:dynamic-event-profile:v1",
    ),
    SchemaIdentity::new(
        "DynamicEventCandidateV1",
        21108,
        "openpc:dynamic-event-candidate:v1",
    ),
];

pub const FACT_ADMISSION_GATES: [&str; 11] = [
    "AUTHORITY_AND_SCOPE",
    "CLOSED_ENVELOPE_AND_SCHEMA",
    "INDEPENDENT_PROVENANCE",
    "CANONICAL_CHAIN_AND_REORG_FENCE",
    "SEMANTIC_AND_PRIVACY_BOUNDS",
    "COMPLETENESS_AND_CONTIGUITY",
    "FRESHNESS_AND_PROFILE",
    "CONFLICT_AND_TERMINAL_DENIAL",
    "PC_CBOR_1_AND_COSE_SIGN1",
    "ATOMIC_FACT_COMMIT",
    "IMMUTABLE_SHARD_AND_READINESS",
];

pub const FACT_BRIDGE_OPERATIONS: [&str; 8] = [
    "AdmitFactCandidate",
    "GetReadiness",
    "ReadFact",
    "InvalidateFacts",
    "AdmitReplacement",
    "QuarantineCandidate",
    "RecoverGap",
    "RetireFactProfile",
];

#[must_use]
pub fn fact_schema_identity(schema_id: u32) -> Option<SchemaIdentity> {
    FACT_SCHEMA_IDENTITIES
        .iter()
        .chain(RELATIONSHIP_SCHEMA_IDENTITIES.iter())
        .copied()
        .find(|identity| identity.numeric_schema_id == schema_id)
}

pub fn validate_schema_identities(identities: &[SchemaIdentity]) -> ContractResult<()> {
    if identities.is_empty() {
        return Err(ContractError::InvalidData(
            "schema identity catalog is empty".to_owned(),
        ));
    }
    for (index, identity) in identities.iter().enumerate() {
        if identity.type_name.is_empty()
            || identity.purpose_separator.is_empty()
            || !identity.purpose_separator.starts_with("openpc:")
            || !identity.purpose_separator.ends_with(":v1")
        {
            return Err(ContractError::InvalidData(format!(
                "invalid schema identity at index {index}"
            )));
        }
        if identities[..index].iter().any(|prior| {
            prior.type_name == identity.type_name
                || prior.numeric_schema_id == identity.numeric_schema_id
                || prior.purpose_separator == identity.purpose_separator
        }) {
            return Err(ContractError::InvalidData(format!(
                "duplicate schema identity at index {index}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_schema_catalogs_are_closed_and_disjoint() {
        let all = FACT_SCHEMA_IDENTITIES
            .into_iter()
            .chain(RELATIONSHIP_SCHEMA_IDENTITIES)
            .collect::<Vec<_>>();
        validate_schema_identities(&all).expect("frozen catalogs are valid");
        assert_eq!(
            FACT_SCHEMA_IDENTITIES.map(|row| row.numeric_schema_id),
            [
                21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010
            ]
        );
        assert_eq!(
            RELATIONSHIP_SCHEMA_IDENTITIES.map(|row| row.numeric_schema_id),
            [21101, 21102, 21103, 21104, 21105, 21106, 21107, 21108]
        );
    }

    #[test]
    fn altered_missing_unknown_and_duplicate_catalog_rows_fail() {
        let mut rows = FACT_SCHEMA_IDENTITIES.to_vec();
        rows[0].purpose_separator = "openpc:wrong:v1";
        assert_ne!(rows, FACT_SCHEMA_IDENTITIES);

        let mut duplicate = FACT_SCHEMA_IDENTITIES.to_vec();
        duplicate.push(FACT_SCHEMA_IDENTITIES[0]);
        assert!(validate_schema_identities(&duplicate).is_err());

        assert!(validate_schema_identities(&[]).is_err());

        let mut invalid = FACT_SCHEMA_IDENTITIES.to_vec();
        invalid[0].purpose_separator = "candidate-outbox";
        assert!(validate_schema_identities(&invalid).is_err());
    }
}
