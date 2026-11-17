#![forbid(unsafe_code)]

//! The Graph contract boundary. Manifest identity and candidate authority are closed.

mod manifest;

pub use manifest::{
    NativeEventOnlyProjectV1, parse_native_event_only_project, project_native_transfer,
};

use pc_provider_api::{
    ClientIndexerProfileV1, ProjectionPlanV1, TheGraphManifestProfileV1,
    validate_candidate_authority, validate_thegraph_manifest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TheGraphAdapterContract {
    pub client: ClientIndexerProfileV1,
    pub plan: ProjectionPlanV1,
    pub profile: TheGraphManifestProfileV1,
    pub exact_manifest_required: bool,
    pub candidate_only: bool,
    pub raw_fallback_forbidden: bool,
}
pub fn validate_thegraph_contract(
    value: &TheGraphAdapterContract,
) -> Result<(), pc_provider_api::ProviderContractError> {
    validate_thegraph_manifest(&value.client, &value.plan, &value.profile)?;
    validate_candidate_authority(value.profile.source_authority)?;
    if !value.exact_manifest_required || !value.candidate_only || !value.raw_fallback_forbidden {
        return Err(pc_provider_api::ProviderContractError::Invalid(
            "The Graph boundary",
        ));
    }
    Ok(())
}
pub const CANDIDATE_WIRE_CONTRACT: &str = "CandidateOutboxEnvelopeV1";

#[cfg(test)]
mod tests {
    use super::*;
    use pc_provider_api::*;
    fn named(n: &str) -> NamedDigestV1 {
        NamedDigestV1 {
            name: n.into(),
            digest: format!("{n}-digest"),
        }
    }
    fn limits() -> IndexerLimitsV1 {
        IndexerLimitsV1 {
            max_request_bytes: 1,
            max_range: 10,
            max_batch: 1,
            max_response_bytes: 1,
            max_depth: 1,
            max_resource: 1,
            rate_limit_contract_digest: "rate".into(),
        }
    }
    fn method() -> MethodDataClass {
        MethodDataClass {
            method: "eth_getLogs".into(),
            data_class: "EVENT_LOG".into(),
        }
    }
    fn client() -> ClientIndexerProfileV1 {
        ClientIndexerProfileV1 {
            profile_id: "client".into(),
            profile_version: "1".into(),
            profile_digest: "client-digest".into(),
            client_family: ClientIndexerFamily::TheGraphEvmJsonRpc,
            engine_or_runtime: "runtime".into(),
            engine_version: "1".into(),
            dependencies: vec![DependencyV1 {
                name: "dep".into(),
                version: "1".into(),
                digest: "digest".into(),
            }],
            configuration_digest: "config".into(),
            participant_binding: "participant".into(),
            privacy_binding: "privacy".into(),
            workload_binding: "workload".into(),
            deployment_owner: "owner".into(),
            boundary_declaration_digest: "boundary".into(),
            protocol_kind: IndexerProtocolKind::JsonRpc,
            protocol_version: "2".into(),
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            capability_profiles: vec![IndexerCapability::ProjectSessionCore],
            method_data_classes: vec![method()],
            source_range: SourceRangeV1 {
                start: 1,
                end: RangeEndV1::Inclusive(10),
            },
            finality_rule_digest: "finality".into(),
            reorg_behavior_digest: "reorg".into(),
            removed_event_behavior_digest: "removed".into(),
            checkpoint_semantics_digest: "checkpoint".into(),
            completed_watermark_semantics_digest: "watermark".into(),
            artifact_digests: vec![named("abi")],
            limits: limits(),
            behavior: IndexerBehaviorV1 {
                visibility_miss_digest: "miss".into(),
                empty_digest: "empty".into(),
                partial_digest: "partial".into(),
                error_digest: "error".into(),
                retry_digest: "retry".into(),
                recovery_digest: "recovery".into(),
                retirement_digest: "retire".into(),
            },
            candidate_store_contract_digest: "candidate".into(),
            outbox_contract_digest: "outbox".into(),
            fact_bridge_contract_digest: "bridge".into(),
            security_evidence_digest: "security".into(),
            privacy_evidence_digest: "privacy-evidence".into(),
            licensing_digest: "license".into(),
            supply_chain_digest: "supply".into(),
            telemetry_classification_digest: "telemetry".into(),
            rollback_digest: "rollback".into(),
            uninstall_digest: "uninstall".into(),
            corpus_digest: "corpus".into(),
            conformance_receipt_digest: "receipt".into(),
            lifecycle: ClientIndexerLifecycle::Active,
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }
    fn plan() -> ProjectionPlanV1 {
        ProjectionPlanV1 {
            profile_id: "client".into(),
            profile_version: "1".into(),
            profile_digest: "client-digest".into(),
            plan_digest: "plan".into(),
            workload_identity: WorkloadIdentityV1::ImageBuild {
                image_digest: "image".into(),
                build_digest: "build".into(),
                sbom_digest: "sbom".into(),
                provenance_digest: "provenance".into(),
            },
            partitions: vec![ProjectionPartitionV1 {
                partition_id: "partition".into(),
                source_id: "source".into(),
                range: SourceRangeV1 {
                    start: 1,
                    end: RangeEndV1::Inclusive(10),
                },
                state: PartitionState::Complete,
                finality_digest: "finality".into(),
                checkpoint_digest: "checkpoint".into(),
            }],
            source_range: SourceRangeV1 {
                start: 1,
                end: RangeEndV1::Inclusive(10),
            },
            finality_rule_digest: "finality".into(),
            extractor_digests: vec![named("extractor")],
            candidate_schema_digests: vec![named("schema")],
            limits: limits(),
            secret_references: vec![SecretReferenceV1 {
                purpose: SecretPurposeV1::ApiToken,
                reference: "ref:token".into(),
            }],
            lifecycle_generation: 1,
            desired_state: DesiredState::Active,
        }
    }
    fn manifest() -> TheGraphManifestProfileV1 {
        TheGraphManifestProfileV1 {
            profile_id: "graph".into(),
            profile_version: "1".into(),
            profile_digest: "graph-digest".into(),
            client_profile_id: "client".into(),
            client_profile_version: "1".into(),
            client_profile_digest: "client-digest".into(),
            projection_plan_digest: "plan".into(),
            manifest_digest: "manifest".into(),
            referenced_files: vec![named("abi"), named("file")],
            spec_version: "1".into(),
            features: vec!["feature".into()],
            network: "network".into(),
            range: SourceRangeV1 {
                start: 1,
                end: RangeEndV1::Inclusive(10),
            },
            data_sources: vec![GraphDataSourceV1 {
                data_source_id: "source".into(),
                kind: "evm".into(),
                name: "source".into(),
                network: "network".into(),
                address: "address".into(),
                abi_digest: "abi-digest".into(),
                start_block: 1,
                mapping_id: "mapping".into(),
            }],
            mappings: vec![GraphMappingV1 {
                mapping_id: "mapping".into(),
                data_source_id: "source".into(),
                language: "wasm".into(),
                api_version: "1".into(),
                file_digest: "file-digest".into(),
                entities: vec!["entity".into()],
            }],
            handlers: vec![GraphHandlerV1 {
                handler_id: "handler".into(),
                data_source_id: "source".into(),
                mapping_id: "mapping".into(),
                kind: GraphHandlerKind::Event,
                signature: "event".into(),
                filter: "filter".into(),
                function: "handle".into(),
                required_method_data: vec![method()],
            }],
            dynamic_templates: vec![],
            state_read_dependencies: vec![method()],
            entity_projection_schemas: vec![named("entity")],
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }
    fn contract() -> TheGraphAdapterContract {
        TheGraphAdapterContract {
            client: client(),
            plan: plan(),
            profile: manifest(),
            exact_manifest_required: true,
            candidate_only: true,
            raw_fallback_forbidden: true,
        }
    }
    #[test]
    fn graph_candidate_boundary_is_closed() {
        assert_eq!(CANDIDATE_WIRE_CONTRACT, "CandidateOutboxEnvelopeV1");
    }
    #[test]
    fn graph_runtime_remains_external_candidate_only() {
        assert!(CANDIDATE_WIRE_CONTRACT.contains("Candidate"));
        let manifest = include_str!("../Cargo.toml");
        for forbidden in ["graph-node", "ipfs", "postgres", "deployment"] {
            assert!(!manifest.to_ascii_lowercase().contains(forbidden));
        }
        let value = contract();
        assert_eq!(
            value.profile.source_authority,
            SourceAuthority::NonAuthoritativeCandidateOnly
        );
        assert!(value.candidate_only);
        assert!(value.raw_fallback_forbidden);
    }
    #[test]
    fn complete_graph_profile_precedes_boundary_booleans() {
        assert!(validate_thegraph_contract(&contract()).is_ok());
        let mut drift = contract();
        drift.profile.handlers[0].data_source_id = "other".into();
        assert!(validate_thegraph_contract(&drift).is_err());
        for mutate in [
            |v: &mut TheGraphAdapterContract| v.exact_manifest_required = false,
            |v: &mut TheGraphAdapterContract| v.candidate_only = false,
            |v: &mut TheGraphAdapterContract| v.raw_fallback_forbidden = false,
        ] {
            let mut v = contract();
            mutate(&mut v);
            assert!(validate_thegraph_contract(&v).is_err());
        }
    }
}
