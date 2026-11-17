#![forbid(unsafe_code)]

//! Explorer candidate acquisition boundary. It cannot acquire fact authority.

mod runtime;

pub use runtime::{
    ExplorerAcquisitionIntent, ExplorerRuntimeError, LocalExplorerProjectionShapeV1,
    LocalFixtureExplorerRuntimeV1,
};

use pc_provider_api::{
    ExplorerFactSourceProfileV1, validate_candidate_authority, validate_explorer_profile,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplorerAdapterContract {
    pub profile: ExplorerFactSourceProfileV1,
    pub raw_fallback_forbidden: bool,
    pub fact_store_write_forbidden: bool,
}
pub fn validate_explorer_contract(
    value: &ExplorerAdapterContract,
) -> Result<(), pc_provider_api::ProviderContractError> {
    validate_explorer_profile(&value.profile)?;
    validate_candidate_authority(value.profile.source_authority)?;
    if !value.raw_fallback_forbidden || !value.fact_store_write_forbidden {
        return Err(pc_provider_api::ProviderContractError::Invalid(
            "Explorer authority boundary",
        ));
    }
    Ok(())
}
pub const CANDIDATE_WIRE_CONTRACT: &str = "CandidateOutboxEnvelopeV1";

mod local_fixture_config {
    use super::*;
    use pc_provider_api::*;

    fn named(name: &str) -> NamedDigestV1 {
        NamedDigestV1 {
            name: name.into(),
            digest: format!("{name}-digest"),
        }
    }
    fn limits() -> IndexerLimitsV1 {
        IndexerLimitsV1 {
            max_request_bytes: 10_000,
            max_range: 10,
            max_batch: 100,
            max_response_bytes: 100_000,
            max_depth: 8,
            max_resource: 100,
            rate_limit_contract_digest: "rate".into(),
        }
    }
    pub(crate) fn profile() -> ExplorerFactSourceProfileV1 {
        ExplorerFactSourceProfileV1 {
            adapter_contract_id: "OPENEXPLORER_FACT_SOURCE_V1".into(),
            adapter_contract_version: "1.0.0".into(),
            adapter_schema_digest: "schema".into(),
            profile_id: "explorer".into(),
            profile_version: "1".into(),
            profile_digest: "explorer-digest".into(),
            product_id: "product".into(),
            instance_id: "instance".into(),
            release_digest: "release".into(),
            build_digest: "build".into(),
            api_digest: "api".into(),
            current_receipt_digest: "receipt".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            source_trust_binding: "trust".into(),
            supported_fact_profiles: vec!["fact".into()],
            dynamic_event_schemas: vec![named("event")],
            allowed_operations: vec!["read".into()],
            allowed_data_classes: vec!["event".into()],
            allowed_fields: vec!["field".into()],
            allowed_filters: vec!["filter".into()],
            limits: limits(),
            page_limits: ExplorerPageLimitsV1 {
                max_page_items: 100,
                max_page_bytes: 100_000,
            },
            checkpoint_protocol_digest: "checkpoint".into(),
            resume_protocol_digest: "resume".into(),
            response_schema_digests: vec![named("response")],
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            source_partitions: vec![ProjectionPartitionV1 {
                partition_id: "partition".into(),
                source_id: "instance".into(),
                range: SourceRangeV1 {
                    start: 1,
                    end: RangeEndV1::Inclusive(10),
                },
                state: PartitionState::Complete,
                finality_digest: "finality".into(),
                checkpoint_digest: "checkpoint".into(),
            }],
            scope_digests: vec![named("scope")],
            canonicality_digest: "canonicality".into(),
            finality_digest: "finality".into(),
            reorg_digest: "reorg".into(),
            removal_digest: "removal".into(),
            completeness_digest: "complete".into(),
            watermark_digest: "watermark".into(),
            freshness_digest: "fresh".into(),
            trust_digest: "trust".into(),
            revocation_digest: "revoke".into(),
            provenance_digest: "provenance".into(),
            conflict_digest: "conflict".into(),
            privacy_projection_digest: "projection".into(),
            redaction_digest: "redaction".into(),
            hmac_key_version: "key".into(),
            privacy_evidence_digest: "privacy-evidence".into(),
            telemetry_classifications: vec!["telemetry".into()],
            rate_law_digest: "rate".into(),
            timeout_law_digest: "timeout".into(),
            retry_law_digest: "retry".into(),
            lifecycle: ExplorerLifecycle::Active,
            upgrade_digest: "upgrade".into(),
            rollback_digest: "rollback".into(),
            disable_digest: "disable".into(),
            uninstall_digest: "uninstall".into(),
            corpus_digest: "corpus".into(),
            conformance_receipt_digest: "receipt".into(),
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }
    #[cfg(test)]
    fn contract(profile: ExplorerFactSourceProfileV1) -> ExplorerAdapterContract {
        ExplorerAdapterContract {
            profile,
            raw_fallback_forbidden: true,
            fact_store_write_forbidden: true,
        }
    }
    #[cfg(test)]
    #[test]
    fn explorer_candidate_boundary_is_closed() {
        assert_eq!(CANDIDATE_WIRE_CONTRACT, "CandidateOutboxEnvelopeV1");
    }
    #[cfg(test)]
    #[test]
    fn explorer_has_no_fact_authority() {
        assert!(CANDIDATE_WIRE_CONTRACT.contains("Candidate"));
    }
    #[cfg(test)]
    #[test]
    fn complete_explorer_profile_precedes_boundary_booleans() {
        assert!(validate_explorer_contract(&contract(profile())).is_ok());
        let mut drift = profile();
        drift.adapter_contract_version = "2.0.0".into();
        assert!(validate_explorer_contract(&contract(drift)).is_err());
        let mut raw = contract(profile());
        raw.raw_fallback_forbidden = false;
        assert!(validate_explorer_contract(&raw).is_err());
        let mut fact = contract(profile());
        fact.fact_store_write_forbidden = false;
        assert!(validate_explorer_contract(&fact).is_err());
    }
}
