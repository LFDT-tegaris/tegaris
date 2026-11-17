use crate::ProviderContractError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaIdentity {
    pub type_name: &'static str,
    pub numeric_schema_id: u32,
    pub purpose_separator: &'static str,
}

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

pub const PROVIDER_SCHEMA_IDENTITY_COUNT: usize = 16;

pub const PROVIDER_SCHEMA_IDENTITIES: [SchemaIdentity; PROVIDER_SCHEMA_IDENTITY_COUNT] = [
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

#[must_use]
pub fn provider_schema_identity(schema_id: u32) -> Option<SchemaIdentity> {
    PROVIDER_SCHEMA_IDENTITIES
        .into_iter()
        .find(|identity| identity.numeric_schema_id == schema_id)
}

pub fn validate_schema_catalog(identities: &[SchemaIdentity]) -> Result<(), ProviderContractError> {
    if identities.len() != PROVIDER_SCHEMA_IDENTITIES.len() {
        return Err(ProviderContractError::SchemaCatalog(
            "catalog length is not closed",
        ));
    }
    for (index, identity) in identities.iter().enumerate() {
        if identity != &PROVIDER_SCHEMA_IDENTITIES[index]
            || identities[..index].iter().any(|prior| {
                prior.type_name == identity.type_name
                    || prior.numeric_schema_id == identity.numeric_schema_id
                    || prior.purpose_separator == identity.purpose_separator
            })
        {
            return Err(ProviderContractError::SchemaCatalog(
                "schema identity drift",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_schema_catalog_is_closed() {
        validate_schema_catalog(&PROVIDER_SCHEMA_IDENTITIES).expect("frozen catalog");
        assert_eq!(
            provider_schema_identity(22001).unwrap().type_name,
            "ProviderProfileV1"
        );
    }
    #[test]
    fn schema_catalog_rejects_drift() {
        let mut rows = PROVIDER_SCHEMA_IDENTITIES.to_vec();
        rows[0].purpose_separator = "openpc:wrong:v1";
        assert!(validate_schema_catalog(&rows).is_err());
    }
}
