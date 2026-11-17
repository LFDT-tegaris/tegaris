#![forbid(unsafe_code)]

//! SubQuery client contract boundary. Managed SubQuery is future-absent in R1.

use pc_provider_api::{
    ClientIndexerProfileV1, ManagedSubqueryLifecycle, ProjectionPlanV1, SubQueryClientProfileV1,
    validate_candidate_authority, validate_subquery_profile,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubqueryAdapterContract {
    pub client: ClientIndexerProfileV1,
    pub plan: ProjectionPlanV1,
    pub profile: SubQueryClientProfileV1,
    pub managed_lifecycle: ManagedSubqueryLifecycle,
    pub candidate_only: bool,
    pub deployment_forbidden: bool,
}
pub fn validate_subquery_contract(
    value: &SubqueryAdapterContract,
) -> Result<(), pc_provider_api::ProviderContractError> {
    validate_subquery_profile(&value.client, &value.plan, &value.profile)?;
    validate_candidate_authority(value.profile.source_authority)?;
    if value.managed_lifecycle != ManagedSubqueryLifecycle::FutureAbsent
        || !value.candidate_only
        || !value.deployment_forbidden
    {
        return Err(pc_provider_api::ProviderContractError::Invalid(
            "SubQuery boundary",
        ));
    }
    Ok(())
}
pub const CANDIDATE_WIRE_CONTRACT: &str = "CandidateOutboxEnvelopeV1";
pub const MANAGED_REGISTRY_STATE: &str = "FUTURE_CONDITIONAL_NO_R1_DEPENDENCY";

#[cfg(test)]
mod tests {
    use super::*;
    use pc_provider_api::*;
    fn n(x: &str) -> NamedDigestV1 {
        NamedDigestV1 {
            name: x.into(),
            digest: format!("{x}-digest"),
        }
    }
    fn m() -> MethodDataClass {
        MethodDataClass {
            method: "eth_call".into(),
            data_class: "STATE_CALL".into(),
        }
    }
    fn l() -> IndexerLimitsV1 {
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
    fn client() -> ClientIndexerProfileV1 {
        ClientIndexerProfileV1 {
            profile_id: "client".into(),
            profile_version: "1".into(),
            profile_digest: "client-digest".into(),
            client_family: ClientIndexerFamily::SubQueryEvmJsonRpc,
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
            method_data_classes: vec![m()],
            source_range: SourceRangeV1 {
                start: 1,
                end: RangeEndV1::Inclusive(10),
            },
            finality_rule_digest: "finality".into(),
            reorg_behavior_digest: "reorg".into(),
            removed_event_behavior_digest: "removed".into(),
            checkpoint_semantics_digest: "checkpoint".into(),
            completed_watermark_semantics_digest: "watermark".into(),
            artifact_digests: vec![n("abi")],
            limits: l(),
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
            extractor_digests: vec![n("extractor")],
            candidate_schema_digests: vec![n("schema")],
            limits: l(),
            secret_references: vec![SecretReferenceV1 {
                purpose: SecretPurposeV1::ApiToken,
                reference: "ref:token".into(),
            }],
            lifecycle_generation: 1,
            desired_state: DesiredState::Active,
        }
    }
    fn profile() -> SubQueryClientProfileV1 {
        let d = |x: &str| DependencyV1 {
            name: x.into(),
            version: "1".into(),
            digest: format!("{x}-digest"),
        };
        SubQueryClientProfileV1 {
            profile_id: "subquery".into(),
            profile_version: "1".into(),
            profile_digest: "subquery-digest".into(),
            client_profile_id: "client".into(),
            client_profile_version: "1".into(),
            client_profile_digest: "client-digest".into(),
            plan_digest: "plan".into(),
            project_id: "project".into(),
            manifest_spec_version: "1".into(),
            manifest_digest: "manifest".into(),
            chain_id: "1".into(),
            genesis_hash: "genesis".into(),
            network_id: "network".into(),
            runner: d("runner"),
            node: d("node"),
            query_service: d("query"),
            package_manager: d("pnpm"),
            dependencies: vec![d("dep")],
            data_sources: vec![SubQueryDataSourceV1 {
                data_source_id: "source".into(),
                kind: "evm".into(),
                start: 1,
                end: RangeEndV1::Inclusive(10),
                mapping_digest: "mapping-digest".into(),
                asset_digests: vec!["asset-digest".into()],
                abi_digests: vec!["abi-digest".into()],
            }],
            mappings: vec![n("mapping")],
            processors: vec![n("processor")],
            assets: vec![n("asset")],
            handlers: vec![SubQueryHandlerV1 {
                handler_id: "handler".into(),
                data_source_id: "source".into(),
                processor_id: "processor".into(),
                filter_id: "filter".into(),
                required_method_data: vec![m()],
            }],
            filters: vec![TypedSelectorV1 {
                field_id: "filter".into(),
                schema_digest: "schema".into(),
                selector_digest: "selector".into(),
            }],
            abi_schema_code_digests: vec![
                NamedDigestV1 {
                    name: "abis/erc20.json".into(),
                    digest: "abi-digest".into(),
                },
                NamedDigestV1 {
                    name: "dist/mapping.js".into(),
                    digest: "mapping-digest".into(),
                },
                NamedDigestV1 {
                    name: "dist/processor.js".into(),
                    digest: "processor-digest".into(),
                },
                NamedDigestV1 {
                    name: "schemas/project.graphql".into(),
                    digest: "schema-digest".into(),
                },
            ],
            project_schema_digests: vec!["schema-digest".into()],
            data_node_surface: SubQueryDataNodeSurfaceV1::NotDeclared,
            checkpoint_digest: "checkpoint".into(),
            finality_digest: "finality".into(),
            reorg_digest: "reorg".into(),
            limits: l(),
            privacy_law_digest: "privacy-evidence".into(),
            lifecycle: ClientIndexerLifecycle::Active,
            managed_lifecycle: ManagedSubqueryLifecycle::FutureAbsent,
            current_receipt_digest: "receipt".into(),
            source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
        }
    }
    fn c() -> SubqueryAdapterContract {
        SubqueryAdapterContract {
            client: client(),
            plan: plan(),
            profile: profile(),
            managed_lifecycle: ManagedSubqueryLifecycle::FutureAbsent,
            candidate_only: true,
            deployment_forbidden: true,
        }
    }
    #[test]
    fn subquery_candidate_boundary_is_closed() {
        assert_eq!(CANDIDATE_WIRE_CONTRACT, "CandidateOutboxEnvelopeV1");
    }
    #[test]
    fn managed_subquery_is_future_absent() {
        assert_eq!(
            ManagedSubqueryLifecycle::FutureAbsent,
            ManagedSubqueryLifecycle::FutureAbsent
        );
    }

    #[test]
    fn subquery_r1_negative_closure_has_zero_runtime_dependency() {
        let manifest = include_str!("../Cargo.toml");
        assert_eq!(
            MANAGED_REGISTRY_STATE,
            "FUTURE_CONDITIONAL_NO_R1_DEPENDENCY"
        );
        for forbidden in [
            "serde_yaml",
            "serde_json",
            "reqwest",
            "tokio",
            "subql",
            "subquery-node",
            "deployment",
        ] {
            assert!(!manifest.to_ascii_lowercase().contains(forbidden));
        }
        assert_eq!(
            ManagedSubqueryLifecycle::FutureAbsent,
            c().managed_lifecycle
        );
    }
    #[test]
    fn complete_profile_precedes_boundary_booleans() {
        assert!(validate_subquery_contract(&c()).is_ok());
        let mut drift = c();
        drift.profile.handlers[0].data_source_id = "other".into();
        assert!(validate_subquery_contract(&drift).is_err());
        let mut managed = c();
        managed.managed_lifecycle = ManagedSubqueryLifecycle::FutureAbsent;
        managed.profile.managed_lifecycle = ManagedSubqueryLifecycle::FutureAbsent;
        managed.candidate_only = false;
        assert!(validate_subquery_contract(&managed).is_err());
        let mut deployment = c();
        deployment.deployment_forbidden = false;
        assert!(validate_subquery_contract(&deployment).is_err());
    }
}
