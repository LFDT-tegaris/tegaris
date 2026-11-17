//! Deterministic non-production configuration input for the local runtime join.

use openpc_pds::{
    AbiType, ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
    ApprovalRequirement, ConfigurationArtifactKind, ConfigurationArtifactV1,
    InvocationConfigurationAssetV1, InvocationPolicyAssetV1,
    encode_active_invocation_configuration, encode_active_invocation_policy_generation,
};
use pc_provider_api::{
    ClientIndexerFamily, ClientIndexerLifecycle, ClientIndexerProfileV1, DependencyV1,
    DesiredState, IdempotencyClass, IndexerBehaviorV1, IndexerCapability, IndexerLimitsV1,
    IndexerProtocolKind, MethodDataClass, NamedDigestV1, PartitionState, ProfileLifecycle,
    ProjectionPartitionV1, ProjectionPlanV1, ProviderLimits, ProviderProfileV1, RangeEndV1,
    RoutePlanDraftV1, SecretPurposeV1, SecretReferenceV1, SourceAuthority, SourceRangeV1,
    WorkloadIdentityV1, encode_client_indexer_profile_pc_cbor, encode_projection_plan_pc_cbor,
    encode_provider_profile_pc_cbor,
};
use pc_runtime_types::{Digest, RequestClass};
use serde::Serialize;

pub mod indexer;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConfigurationFixture {
    pub configuration_cbor_hex: String,
    pub configuration_digest: String,
    pub provider_artifact_digest: String,
    pub indexer_artifact_digest: String,
    pub projection_artifact_digest: String,
    pub policy_cbor_hex: String,
    pub policy_artifact_digest: String,
    pub rpc_policy_digest: String,
    pub policy_generation_digest: String,
    pub fact_generation_digest: String,
}

fn digest(value: &str) -> String {
    Digest::of(value).as_str().to_owned()
}

fn named_digest(name: &str) -> NamedDigestV1 {
    NamedDigestV1 {
        name: name.into(),
        digest: digest(name),
    }
}

fn source_range() -> SourceRangeV1 {
    SourceRangeV1 {
        start: 1,
        end: RangeEndV1::Inclusive(10),
    }
}

fn indexer_limits() -> IndexerLimitsV1 {
    IndexerLimitsV1 {
        max_request_bytes: 10_000,
        max_range: 10,
        max_batch: 10,
        max_response_bytes: 10_000,
        max_depth: 10,
        max_resource: 10,
        rate_limit_contract_digest: digest("local-rate-limit"),
    }
}

fn provider_profile() -> ProviderProfileV1 {
    ProviderProfileV1 {
        profile_id: "local-provider-profile".into(),
        profile_version: "1.0.0".into(),
        profile_digest: digest("local-provider-profile"),
        provider_instance_id: "local-provider-instance".into(),
        provider_release_digest: digest("local-provider-release"),
        provider_build_digest: digest("local-provider-build"),
        configuration_digest: digest("local-provider-configuration"),
        chain_id: "31337".into(),
        genesis_hash: digest("local-genesis"),
        network_id: "openpc-local".into(),
        tls_credential_identity: "local-provider-credential".into(),
        tls_credential_fingerprint: digest("local-provider-credential"),
        trust_epoch: 1,
        json_rpc_version: "2.0".into(),
        method_data_classes: vec![MethodDataClass {
            method: "eth_call".into(),
            data_class: "STATE_CALL".into(),
        }],
        request_schema_digest: digest("local-request-schema"),
        response_schema_digest:
            openpc_runtime_agent::provider_response::call_result_response_schema_digest(),
        normalization_rule_digest:
            openpc_runtime_agent::provider_response::call_result_normalization_rule_digest(),
        limits: ProviderLimits {
            max_request_bytes: 1_024,
            max_response_bytes: 4_096,
            max_range: 100,
            max_batch: 10,
        },
        privacy_behavior_digest: digest("local-provider-privacy"),
        failure_behavior_digest: digest("local-provider-failure"),
        rate_limit_contract_digest: digest("local-provider-rate"),
        capability_profile_digest: digest("local-provider-capability"),
        maximum_response_classification: "participant-confidential".into(),
        idempotency: IdempotencyClass::IdempotentRead,
        route_plan: RoutePlanDraftV1::SingleExact,
        read_retry_budget: 0,
        timeout_budget_millis: 1_000,
        corpus_digest: digest("local-provider-corpus"),
        conformance_receipt_digest: digest("local-provider-receipt"),
        lifecycle: ProfileLifecycle::Active,
        evidence_refs: vec![digest("local-provider-evidence")],
    }
}

fn indexer_profile() -> ClientIndexerProfileV1 {
    ClientIndexerProfileV1 {
        profile_id: "local-indexer-profile".into(),
        profile_version: "1.0.0".into(),
        profile_digest: digest("local-indexer-profile"),
        client_family: ClientIndexerFamily::CustomEvmIndexer,
        engine_or_runtime: "local-runtime".into(),
        engine_version: "1.0.0".into(),
        dependencies: vec![DependencyV1 {
            name: "local-dependency".into(),
            version: "1.0.0".into(),
            digest: digest("local-dependency"),
        }],
        configuration_digest: digest("local-indexer-configuration"),
        participant_binding: "018f0000-0000-7000-8000-000000000101".into(),
        privacy_binding: "018f0000-0000-7000-8000-000000000201".into(),
        workload_binding: "local-indexer-workload".into(),
        deployment_owner: "openpc-local".into(),
        boundary_declaration_digest: digest("local-indexer-boundary"),
        protocol_kind: IndexerProtocolKind::JsonRpc,
        protocol_version: "2.0".into(),
        chain_id: "31337".into(),
        genesis_hash: "01".repeat(32),
        network_id: "openpc-local".into(),
        capability_profiles: vec![IndexerCapability::ProjectSessionCore],
        method_data_classes: vec![MethodDataClass {
            method: "eth_call".into(),
            data_class: "call-result".into(),
        }],
        source_range: source_range(),
        finality_rule_digest: digest("local-finality"),
        reorg_behavior_digest: digest("local-reorg"),
        removed_event_behavior_digest: digest("local-removed"),
        checkpoint_semantics_digest: digest("local-checkpoint"),
        completed_watermark_semantics_digest: digest("local-watermark"),
        artifact_digests: vec![named_digest("local-abi")],
        limits: indexer_limits(),
        behavior: IndexerBehaviorV1 {
            visibility_miss_digest: digest("local-miss"),
            empty_digest: digest("local-empty"),
            partial_digest: digest("local-partial"),
            error_digest: digest("local-error"),
            retry_digest: digest("local-retry"),
            recovery_digest: digest("local-recovery"),
            retirement_digest: digest("local-retirement"),
        },
        candidate_store_contract_digest: digest("local-candidate"),
        outbox_contract_digest: digest("local-outbox"),
        fact_bridge_contract_digest: digest("local-fact-bridge"),
        security_evidence_digest: digest("local-security"),
        privacy_evidence_digest: digest("local-privacy"),
        licensing_digest: digest("local-license"),
        supply_chain_digest: digest("local-supply"),
        telemetry_classification_digest: digest("local-telemetry"),
        rollback_digest: digest("local-rollback"),
        uninstall_digest: digest("local-uninstall"),
        corpus_digest: digest("local-indexer-corpus"),
        conformance_receipt_digest: digest("local-indexer-receipt"),
        lifecycle: ClientIndexerLifecycle::Active,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

fn projection_plan(profile: &ClientIndexerProfileV1) -> ProjectionPlanV1 {
    ProjectionPlanV1 {
        profile_id: profile.profile_id.clone(),
        profile_version: profile.profile_version.clone(),
        profile_digest: profile.profile_digest.clone(),
        plan_digest: digest("local-projection-plan"),
        workload_identity: WorkloadIdentityV1::ExternalOwner {
            owner: "openpc-local".into(),
            boundary_digest: digest("local-projection-workload"),
        },
        partitions: vec![ProjectionPartitionV1 {
            partition_id: "local-partition".into(),
            source_id: "local-source".into(),
            range: source_range(),
            state: PartitionState::Complete,
            finality_digest: profile.finality_rule_digest.clone(),
            checkpoint_digest: digest("local-projection-checkpoint"),
        }],
        source_range: source_range(),
        finality_rule_digest: profile.finality_rule_digest.clone(),
        extractor_digests: vec![named_digest("local-extractor")],
        candidate_schema_digests: vec![named_digest("local-candidate-schema")],
        limits: indexer_limits(),
        secret_references: vec![SecretReferenceV1 {
            purpose: SecretPurposeV1::ApiToken,
            reference: "ref:local-indexer-token".into(),
        }],
        lifecycle_generation: 1,
        desired_state: DesiredState::Active,
    }
}

fn invocation_asset(workload_id: &str) -> InvocationConfigurationAssetV1 {
    InvocationConfigurationAssetV1 {
        asset_id: "local-read-uint256".into(),
        runtime_binding_id: None,
        transaction_policy: None,
        tenant_id: "018f0000-0000-7000-8000-000000000101".into(),
        privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
        workload_id: workload_id.into(),
        rpc_method: "eth_call".into(),
        request_class: RequestClass::Read,
        chain_id: "31337".into(),
        network_id: "openpc-local".into(),
        genesis_digest: Digest::of("local-genesis"),
        contract_address: [1; 20],
        proxy_address: None,
        implementation_address: None,
        code_digest: Digest::of("local-code"),
        implementation_code_digest: None,
        abi_digest: Digest::of("local-abi"),
        canonical_signature: "read(uint256)".into(),
        selector: [0x12, 0x34, 0x56, 0x78],
        input_types: vec![AbiType::Uint(256)],
        named_sets: Vec::new(),
    }
}

fn prefixed(value: &Digest) -> String {
    format!("sha256:{}", value.as_str())
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl LocalConfigurationFixture {
    /// Include the canonical bytes returned by the public settings owner.
    /// Fleet still verifies the approved database source before admission.
    pub fn with_cigl_settings(mut self, bytes: Vec<u8>) -> Result<Self, String> {
        let source = pc_policy_core::cigl::settings::ConfiguredCiglSettings::from_cbor(&bytes)
            .map_err(|_| "public CIGL settings fixture rejected")?;
        let configuration = (0..self.configuration_cbor_hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&self.configuration_cbor_hex[offset..offset + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "local configuration fixture encoding rejected")?;
        let mut configuration = openpc_pds::decode_active_invocation_configuration(
            &configuration,
            &Digest::of(&configuration),
        )
        .map_err(|_| "local configuration fixture rejected")?;
        configuration
            .resource_artifacts
            .push(ConfigurationArtifactV1 {
                artifact_id: source.settings_id,
                artifact_kind: ConfigurationArtifactKind::CiglSettings,
                artifact_digest: Digest::of(&bytes),
                payload_cbor: bytes,
            });
        configuration
            .resource_artifacts
            .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        let bytes = encode_active_invocation_configuration(&configuration)
            .map_err(|_| "local CIGL configuration fixture rejected")?;
        self.configuration_digest = prefixed(&Digest::of(&bytes));
        self.configuration_cbor_hex = hex(&bytes);
        Ok(self)
    }
}

pub fn build_local_configuration_fixture(
    provider_id: Option<&str>,
    indexer_id: Option<&str>,
    projection_id: Option<&str>,
    workload_id: Option<&str>,
) -> Result<LocalConfigurationFixture, String> {
    build_local_configuration_fixture_with_policy_version(
        provider_id,
        indexer_id,
        projection_id,
        workload_id,
        "1.0.0",
    )
}

pub fn build_local_configuration_fixture_with_policy_version(
    provider_id: Option<&str>,
    indexer_id: Option<&str>,
    projection_id: Option<&str>,
    workload_id: Option<&str>,
    policy_version: &str,
) -> Result<LocalConfigurationFixture, String> {
    build_local_configuration_fixture_with_provider_profile(
        provider_id,
        indexer_id,
        projection_id,
        workload_id,
        policy_version,
        &provider_profile(),
    )
}

pub fn build_local_configuration_fixture_with_provider_profile(
    provider_id: Option<&str>,
    indexer_id: Option<&str>,
    projection_id: Option<&str>,
    workload_id: Option<&str>,
    policy_version: &str,
    provider: &ProviderProfileV1,
) -> Result<LocalConfigurationFixture, String> {
    build_local_configuration_fixture_in_scope(
        provider_id,
        indexer_id,
        projection_id,
        workload_id,
        policy_version,
        Some(provider),
        (
            "018f0000-0000-7000-8000-000000000101",
            "018f0000-0000-7000-8000-000000000201",
        ),
    )
}

/// Isolated input bytes only; public resource, module and policy owners still admit them.
pub fn build_local_configuration_fixture_in_scope(
    provider_id: Option<&str>,
    indexer_id: Option<&str>,
    projection_id: Option<&str>,
    workload_id: Option<&str>,
    policy_version: &str,
    provider: Option<&ProviderProfileV1>,
    scope: (&str, &str),
) -> Result<LocalConfigurationFixture, String> {
    for value in [scope.0, scope.1] {
        if !uuid::Uuid::parse_str(value).is_ok_and(|id| {
            id.to_string() == value
                && id.get_version_num() == 7
                && id.get_variant() == uuid::Variant::RFC4122
        }) {
            return Err("local fixture scope rejected".into());
        }
    }
    let default_provider = provider_profile();
    let provider = provider.unwrap_or(&default_provider);
    if projection_id.is_some() && indexer_id.is_none() {
        return Err("projection fixture requires an indexer fixture".into());
    }
    pc_provider_api::validate_provider_profile(provider)
        .map_err(|_| "provider fixture profile rejected".to_owned())?;
    let provider_cbor = encode_provider_profile_pc_cbor(provider)
        .map_err(|_| "provider fixture rejected".to_owned())?;
    let mut indexer = indexer_profile();
    indexer.participant_binding = scope.0.into();
    indexer.privacy_binding = scope.1.into();
    let indexer_cbor = encode_client_indexer_profile_pc_cbor(&indexer)
        .map_err(|_| "indexer fixture rejected".to_owned())?;
    let projection_cbor = encode_projection_plan_pc_cbor(&projection_plan(&indexer))
        .map_err(|_| "projection fixture rejected".to_owned())?;
    let provider_digest = Digest::of(&provider_cbor);
    let indexer_digest = Digest::of(&indexer_cbor);
    let projection_digest = Digest::of(&projection_cbor);
    let mut resource_artifacts = Vec::new();
    if let Some(artifact_id) = provider_id {
        resource_artifacts.push(ConfigurationArtifactV1 {
            artifact_id: artifact_id.into(),
            artifact_kind: ConfigurationArtifactKind::ProviderProfile,
            artifact_digest: provider_digest.clone(),
            payload_cbor: provider_cbor,
        });
    }
    if let Some(artifact_id) = indexer_id {
        resource_artifacts.push(ConfigurationArtifactV1 {
            artifact_id: artifact_id.into(),
            artifact_kind: ConfigurationArtifactKind::ClientIndexerProfile,
            artifact_digest: indexer_digest.clone(),
            payload_cbor: indexer_cbor,
        });
    }
    if let Some(artifact_id) = projection_id {
        resource_artifacts.push(ConfigurationArtifactV1 {
            artifact_id: artifact_id.into(),
            artifact_kind: ConfigurationArtifactKind::ProjectionPlan,
            artifact_digest: projection_digest.clone(),
            payload_cbor: projection_cbor,
        });
    }
    let mut asset = invocation_asset(workload_id.unwrap_or("018f0000-0000-7000-8000-000000000603"));
    asset.tenant_id = scope.0.into();
    asset.privacy_domain_id = scope.1.into();
    let configuration_cbor =
        encode_active_invocation_configuration(&ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: vec![asset],
            resource_artifacts,
        })
        .map_err(|_| "configuration fixture rejected".to_owned())?;
    let rpc_policy = pc_policy_core::rpc_policy::RpcSurfacePolicy {
        schema_version: "1.0.0".into(),
        participant_id: scope.0.into(),
        privacy_domain_id: scope.1.into(),
        rules: vec![pc_policy_core::rpc_policy::RpcRule {
            method: "eth_sendRawTransaction".into(),
            effect: pc_policy_core::rpc_policy::RpcEffect::Allow,
            required_roles: vec!["urn:openpc:role:018f0000-0000-7000-8000-000000000801".into()],
        }],
    };
    let rpc_policy_digest = prefixed(&rpc_policy.digest()?);
    // The local lifecycle also admits a balance-read asset before exercising
    // rollback. Its RPC reference must exist in the bootstrap predecessor.
    let mut read_rpc_policy = rpc_policy.clone();
    read_rpc_policy.rules[0].method = "eth_call".into();
    let policy_cbor =
        encode_active_invocation_policy_generation(&ActiveInvocationPolicyGenerationV1 {
            visibility_policies: Vec::new(),
            fact_conditions: Vec::new(),
            indexer_policies: Vec::new(),
            deployment_policies: Vec::new(),
            required_facts: Vec::new(),
            rpc_policies: vec![rpc_policy, read_rpc_policy],
            schema_version: "1.0".into(),
            root_asset_ids: vec!["local-read-uint256".into()],
            assets: vec![InvocationPolicyAssetV1 {
                method_required_roles: None,
                nested_call_set_digest: None,
                rpc_denied: false,
                asset_id: "local-read-uint256".into(),
                policy_version: policy_version.into(),
                active: true,
                required_roles: vec!["reader".into()],
                approval: ApprovalRequirement::None,
                webauthn_required: false,
                argument_rules: Vec::new(),
                nested_asset_ids: Vec::new(),
            }],
        })
        .map_err(|_| "policy fixture rejected".to_owned())?;
    Ok(LocalConfigurationFixture {
        configuration_digest: prefixed(&Digest::of(&configuration_cbor)),
        configuration_cbor_hex: hex(&configuration_cbor),
        provider_artifact_digest: prefixed(&provider_digest),
        indexer_artifact_digest: prefixed(&indexer_digest),
        projection_artifact_digest: prefixed(&projection_digest),
        policy_artifact_digest: prefixed(&Digest::of(&policy_cbor)),
        rpc_policy_digest,
        policy_generation_digest: prefixed(&Digest::of("local-policy-generation-v1")),
        fact_generation_digest: prefixed(&Digest::of("local-fact-generation-v1")),
        policy_cbor_hex: hex(&policy_cbor),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_fixture_binds_invocation_indexer_and_rpc_to_the_requested_scope() {
        let participant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000007201";
        let fixture = build_local_configuration_fixture_in_scope(
            None,
            Some("source"),
            Some("plan"),
            None,
            "1.0.0",
            None,
            (participant, privacy),
        )
        .unwrap();
        let bytes = (0..fixture.configuration_cbor_hex.len())
            .step_by(2)
            .map(|offset| {
                u8::from_str_radix(&fixture.configuration_cbor_hex[offset..offset + 2], 16).unwrap()
            })
            .collect::<Vec<_>>();
        let configuration =
            openpc_pds::decode_active_invocation_configuration(&bytes, &Digest::of(&bytes))
                .unwrap();
        assert_eq!(configuration.assets[0].tenant_id, participant);
        assert_eq!(configuration.assets[0].privacy_domain_id, privacy);
        let source = configuration
            .resource_artifacts
            .iter()
            .find(|a| a.artifact_id == "source")
            .unwrap();
        let profile =
            pc_provider_api::decode_client_indexer_profile_pc_cbor(&source.payload_cbor).unwrap();
        assert_eq!(profile.participant_binding, participant);
        assert_eq!(profile.privacy_binding, privacy);
        let ordinary =
            build_local_configuration_fixture(None, Some("source"), Some("plan"), None).unwrap();
        assert_ne!(ordinary.configuration_digest, fixture.configuration_digest);
        assert_ne!(
            ordinary.indexer_artifact_digest,
            fixture.indexer_artifact_digest
        );
        assert_ne!(ordinary.rpc_policy_digest, fixture.rpc_policy_digest);
        assert_eq!(
            ordinary.provider_artifact_digest,
            fixture.provider_artifact_digest
        );
        assert!(
            build_local_configuration_fixture_in_scope(
                None,
                None,
                None,
                None,
                "1.0.0",
                None,
                (participant, "unknown")
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_provider_methods_fail_before_configuration_publication() {
        let mut profile = provider_profile();
        profile.method_data_classes.push(MethodDataClass {
            method: "debug_traceCall".into(),
            data_class: "STATE_CALL".into(),
        });
        assert!(
            build_local_configuration_fixture_with_provider_profile(
                Some("provider"),
                None,
                None,
                None,
                "1.0.0",
                &profile
            )
            .is_err()
        );
        profile.method_data_classes.reverse();
        assert!(
            build_local_configuration_fixture_with_provider_profile(
                Some("provider"),
                None,
                None,
                None,
                "1.0.0",
                &profile
            )
            .is_ok()
        );
        profile
            .method_data_classes
            .push(profile.method_data_classes[1].clone());
        assert!(
            build_local_configuration_fixture_with_provider_profile(
                Some("provider"),
                None,
                None,
                None,
                "1.0.0",
                &profile
            )
            .is_err()
        );
    }

    #[test]
    fn fixture_is_deterministic_and_resource_identity_changes_only_the_bundle() {
        let empty = build_local_configuration_fixture(None, None, None, None).unwrap();
        let first =
            build_local_configuration_fixture(Some("provider-a"), None, None, None).unwrap();
        let repeated =
            build_local_configuration_fixture(Some("provider-a"), None, None, None).unwrap();
        assert_eq!(
            first.configuration_cbor_hex,
            repeated.configuration_cbor_hex
        );
        assert_ne!(empty.configuration_digest, first.configuration_digest);
        assert_eq!(
            empty.provider_artifact_digest,
            first.provider_artifact_digest
        );
        assert_eq!(empty.policy_cbor_hex, first.policy_cbor_hex);
        assert!(build_local_configuration_fixture(None, None, Some("plan"), None).is_err());
        let bound = build_local_configuration_fixture(
            Some("provider-a"),
            None,
            None,
            Some("018f0000-0000-7000-8000-000000000999"),
        )
        .unwrap();
        assert_ne!(first.configuration_digest, bound.configuration_digest);
        let next =
            build_local_configuration_fixture_with_policy_version(None, None, None, None, "2.0.0")
                .unwrap();
        assert_eq!(empty.configuration_digest, next.configuration_digest);
        assert_ne!(empty.policy_artifact_digest, next.policy_artifact_digest);
    }
}
