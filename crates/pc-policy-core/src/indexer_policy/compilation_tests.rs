use super::tests::{PARTICIPANT, PLAN, PRIVACY, SOURCE, WORKLOAD, policy, rpc_policies};
use super::*;
use crate::invocation::*;
use pc_provider_api::*;

fn named(name: &str) -> NamedDigestV1 {
    NamedDigestV1 {
        name: name.into(),
        digest: format!("{name}-digest"),
    }
}

fn source_range() -> SourceRangeV1 {
    SourceRangeV1 {
        start: 100,
        end: RangeEndV1::Inclusive(199),
    }
}
fn method() -> MethodDataClass {
    MethodDataClass {
        method: "eth_call".into(),
        data_class: "STATE_CALL".into(),
    }
}
fn limits() -> IndexerLimitsV1 {
    IndexerLimitsV1 {
        max_request_bytes: 1,
        max_range: 10,
        max_batch: 1,
        max_response_bytes: 4096,
        max_depth: 1,
        max_resource: 1,
        rate_limit_contract_digest: "rate".into(),
    }
}

fn client_indexer() -> ClientIndexerProfileV1 {
    ClientIndexerProfileV1 {
        profile_id: "external-project-profile".into(),
        profile_version: "1".into(),
        profile_digest: "client-digest".into(),
        client_family: ClientIndexerFamily::CustomEvmIndexer,
        engine_or_runtime: "runtime".into(),
        engine_version: "1".into(),
        dependencies: vec![DependencyV1 {
            name: "dep".into(),
            version: "1".into(),
            digest: "dep-digest".into(),
        }],
        configuration_digest: "config".into(),
        participant_binding: PARTICIPANT.into(),
        privacy_binding: PRIVACY.into(),
        workload_binding: WORKLOAD.into(),
        deployment_owner: "owner".into(),
        boundary_declaration_digest: "boundary".into(),
        protocol_kind: IndexerProtocolKind::JsonRpc,
        protocol_version: "2".into(),
        chain_id: "1".into(),
        genesis_hash: "genesis".into(),
        network_id: "network".into(),
        capability_profiles: vec![IndexerCapability::ProjectSessionCore],
        method_data_classes: vec![method()],
        source_range: source_range(),
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

fn projection_plan() -> ProjectionPlanV1 {
    ProjectionPlanV1 {
        profile_id: "external-project-profile".into(),
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
            range: source_range(),
            state: PartitionState::Complete,
            finality_digest: "finality".into(),
            checkpoint_digest: "checkpoint".into(),
        }],
        source_range: source_range(),
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

pub(crate) fn fixture() -> (
    crate::semantics::PolicySemanticDocument,
    IndexerCompilationInput,
) {
    let mut policy = policy();
    // The acquisition owner validates this separately; compilation pins its
    // exact bytes without interpreting or granting provider credentials.
    let acquisition = pc_cbor_1(&serde_json::json!({"fixture": "acquisition-owner-input"}));
    policy.acquisition_configuration_digest =
        format!("sha256:{}", Digest::of(&acquisition).as_str());
    let mut profile = client_indexer();
    profile.configuration_digest = policy.acquisition_configuration_digest.clone();
    let profile_bytes = encode_client_indexer_profile_pc_cbor(&profile).unwrap();
    let plan_bytes = encode_projection_plan_pc_cbor(&projection_plan()).unwrap();
    policy.profile_artifact_digest = format!("sha256:{}", Digest::of(&profile_bytes).as_str());
    policy.plan_artifact_digest = format!("sha256:{}", Digest::of(&plan_bytes).as_str());
    let artifacts = [
        (
            ConfigurationArtifactKind::ClientIndexerProfile,
            SOURCE,
            profile_bytes,
        ),
        (ConfigurationArtifactKind::ProjectionPlan, PLAN, plan_bytes),
        (
            ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
            SOURCE,
            acquisition,
        ),
    ]
    .into_iter()
    .map(
        |(artifact_kind, id, payload_cbor)| ConfigurationArtifactV1 {
            artifact_kind,
            artifact_id: id.into(),
            artifact_digest: Digest::of(&payload_cbor),
            payload_cbor,
        },
    )
    .collect();
    let bytes = encode_active_invocation_configuration(&ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        schema_version: "1.0".into(),
        assets: vec![],
        deployment_policies: vec![],
        resource_artifacts: artifacts,
    })
    .unwrap();
    let mut document = crate::semantics::tests::document();
    document.contract_policies.clear();
    document.required_facts.clear();
    let mut binding = document.module_bindings[0].clone();
    binding.module_id = "pc.indexing.dedicated-policy".into();
    document.module_bindings.push(binding);
    document.rpc_policies = rpc_policies();
    document.indexer_policies = vec![policy];
    (
        document,
        IndexerCompilationInput {
            configuration_digest: Digest::of(&bytes),
            configuration_cbor: bytes,
        },
    )
}

#[test]
fn source_only_bundle_compiles_and_reloads_the_same_scope_and_rules() {
    let (document, input) = fixture();
    let compiled = crate::contract_simulation::compile_document_with_indexers(
        &document,
        &[],
        &[],
        &[input],
        WORKLOAD,
        &document.digest().unwrap(),
    )
    .unwrap();
    assert!(compiled.policies.is_empty());
    assert!(compiled.deployment_policies.is_empty());
    let configuration = decode_active_invocation_configuration(
        &compiled.configuration_cbor,
        &compiled.configuration_digest,
    )
    .unwrap();
    assert_eq!(configuration.resource_artifacts.len(), 3);
    assert!(configuration.assets.is_empty());
    assert!(configuration.workload_scope.is_none());
    // Optional compilation scope must not alter pre-visibility canonical bytes.
    #[derive(serde::Serialize)]
    struct LegacyConfiguration<'a> {
        schema_version: &'a str,
        assets: &'a [InvocationConfigurationAssetV1],
        resource_artifacts: &'a [ConfigurationArtifactV1],
        #[serde(skip_serializing_if = "Vec::is_empty")]
        deployment_policies: &'a Vec<crate::deployment_policy::ConfiguredDeploymentPolicy>,
    }
    let legacy = LegacyConfiguration {
        schema_version: &configuration.schema_version,
        assets: &configuration.assets,
        resource_artifacts: &configuration.resource_artifacts,
        deployment_policies: &configuration.deployment_policies,
    };
    let mut legacy_bytes = Vec::new();
    ciborium::ser::into_writer(&legacy, &mut legacy_bytes).unwrap();
    assert!(legacy_bytes == compiled.configuration_cbor);
    let mut mixed = configuration.clone();
    mixed.workload_scope = Some(InvocationConfigurationScope {
        participant_id: PARTICIPANT.into(),
        privacy_domain_id: PRIVACY.into(),
        workload_id: SOURCE.into(),
    });
    let mixed_bytes = encode_active_invocation_configuration(&mixed).unwrap();
    assert!(
        active_invocation_workload(
            &mixed_bytes,
            &pc_runtime_types::Digest::of(&mixed_bytes),
            PARTICIPANT,
            PRIVACY,
        )
        .is_err()
    );
    assert_eq!(
        active_invocation_workload(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            PARTICIPANT,
            PRIVACY
        )
        .unwrap(),
        WORKLOAD
    );
    assert!(
        active_invocation_workload(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            PARTICIPANT,
            PLAN
        )
        .is_err()
    );
    let generation =
        decode_active_invocation_policy_generation(&compiled.policy_cbor, &compiled.policy_digest)
            .unwrap();
    assert_eq!(generation.indexer_policies, document.indexer_policies);
    assert!(generation.required_facts.is_empty());
    let wrong = ActiveInvocationScope {
        policy_generation_digest: &document.digest().unwrap(),
        tenant_id: PARTICIPANT,
        privacy_domain_id: PRIVACY,
        workload_id: SOURCE,
    };
    assert!(
        ValidatedInvocationPolicy::load_active(
            &compiled.configuration_cbor,
            &compiled.configuration_digest,
            &compiled.policy_cbor,
            &compiled.policy_digest,
            &wrong
        )
        .is_err()
    );
}

#[test]
fn resolved_source_bounds_and_artifacts_cannot_be_relabelled() {
    let (document, input) = fixture();
    for field in [
        "profile-bytes",
        "plan-bytes",
        "acquisition",
        "workload",
        "range",
        "range-limit",
        "response-limit",
        "class",
    ] {
        let mut candidate = document.indexer_policies.clone();
        let policy = &mut candidate[0];
        match field {
            "profile-bytes" => policy.profile_artifact_digest = policy.plan_artifact_digest.clone(),
            "plan-bytes" => policy.plan_artifact_digest = policy.profile_artifact_digest.clone(),
            "acquisition" => {
                policy.acquisition_configuration_digest = policy.profile_artifact_digest.clone()
            }
            "workload" => policy.workload_id = format!("urn:openpc:workload:{PLAN}"),
            "range" => policy.range_end = "200".into(),
            "range-limit" => policy.maximum_range_blocks = "11".into(),
            "response-limit" => policy.maximum_response_bytes = 4097,
            "class" => policy.rules[0].data_class = IndexerDataClass::FullBlockTransactions,
            _ => unreachable!(),
        }
        assert!(
            compile_indexer_sources(&candidate, std::slice::from_ref(&input)).is_err(),
            "{field}"
        );
    }
    let mut corrupted = input.clone();
    corrupted.configuration_cbor.push(0);
    assert!(compile_indexer_sources(&document.indexer_policies, &[corrupted]).is_err());
    let mut configuration = decode_active_invocation_configuration(
        &input.configuration_cbor,
        &input.configuration_digest,
    )
    .unwrap();
    let artifact = &mut configuration.resource_artifacts[0];
    let mut profile = decode_client_indexer_profile_pc_cbor(&artifact.payload_cbor).unwrap();
    profile.profile_id = PLAN.into();
    artifact.payload_cbor = encode_client_indexer_profile_pc_cbor(&profile).unwrap();
    artifact.artifact_digest = Digest::of(&artifact.payload_cbor);
    let mut relabelled = document.indexer_policies.clone();
    relabelled[0].profile_artifact_digest = format!("sha256:{}", artifact.artifact_digest.as_str());
    let bytes = encode_active_invocation_configuration(&configuration).unwrap();
    let relabelled_input = IndexerCompilationInput {
        configuration_digest: Digest::of(&bytes),
        configuration_cbor: bytes,
    };
    assert!(compile_indexer_sources(&relabelled, &[relabelled_input]).is_err());
}

fn workload_prediction() -> WorkloadPolicyPrediction {
    use serde_json::json;
    let principal = json!({"principal_id":"workload-principal", "participant_id":PARTICIPANT,
        "kind":"WORKLOAD", "state":"ACTIVE", "authority_epoch":"1", "row_version":"1"});
    let common = json!({"participant_id":PARTICIPANT, "delegation_epoch":"0",
        "privacy_domain_ids":[PRIVACY], "action_intent_ids":["ACT-RUNTIME_READ_RPC-V1"],
        "resource_ids":[SOURCE], "risk_classes":["LOW"], "maker_checker_required":false,
        "step_up_required":false, "onward_delegation_depth":0, "state":"ACTIVE", "row_version":"1",
        "valid_from_ns":"100", "valid_until_ns":"1000", "valid_now":true});
    let mut assignment = common.clone();
    assignment.as_object_mut().unwrap().extend(
        json!({"assignment_id":"source-assignment",
        "principal_id":"workload-principal", "role_id":"source-reader", "authority_group_id":null,
        "authority_envelope_id":"source-envelope", "scope_digest":"digest", "valid_during":"[)",
        "created_by_principal_id":"maker"})
        .as_object()
        .unwrap()
        .clone(),
    );
    let mut envelope = common;
    envelope.as_object_mut().unwrap().extend(json!({"authority_envelope_id":"source-envelope",
        "principal_id":"owner", "maker_principal_id":"maker", "checker_principal_id":"checker",
        "authority_epoch":"1", "valid_from":"time", "valid_until":"time", "semantic_digest":"digest"
    }).as_object().unwrap().clone());
    WorkloadPolicyPrediction {
        workload_id: WORKLOAD.into(),
        principal: principal.clone(),
        paths: vec![json!([{"grant":assignment,"principal":principal}])],
        envelopes: vec![envelope],
        revocations: vec![],
        source_digest: "bc".repeat(32),
        evaluated_at_ns: "200".into(),
        credential_valid_until_ns: "900".into(),
    }
}

#[test]
fn source_simulation_uses_the_authored_tuple_and_never_invents_missing_facts() {
    let (document, input) = fixture();
    let mut input = IndexerSimulationInput {
        document,
        admitted: vec![],
        deployments: vec![],
        indexer_inputs: vec![input],
        workload_prediction: workload_prediction(),
        actor: crate::contract_simulation::SimulationActor {
            participant_id: PARTICIPANT.into(),
            privacy_domain_id: PRIVACY.into(),
            principal_id: "authoring-principal".into(),
            workload_id: None,
            assignment_id: "authoring-assignment".into(),
            roles: vec!["source-reader".into()],
            authority_digest: "ab".repeat(32),
        },
        request: IndexerSimulationRequest {
            indexer_profile_id: SOURCE.into(),
            projection_plan_id: PLAN.into(),
            data_class: IndexerDataClass::StateCall,
            range_start: "100".into(),
            range_end: "109".into(),
            maximum_response_bytes: 4096,
        },
        facts: vec![],
    };
    let allowed = evaluate_indexer_simulation(&input).unwrap();
    assert_eq!(allowed.truth_state, crate::TruthState::Success);
    assert_eq!(allowed.permissions, vec!["eth_call"]);
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().input_digest,
        allowed.input_digest
    );
    // Author permissions cannot impersonate or suppress the distinct workload.
    input.actor.roles.clear();
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Success
    );
    let baseline = input.workload_prediction.clone();
    for (field, value) in [
        ("state", serde_json::json!("REVOKED")),
        ("valid_until_ns", serde_json::json!("200")),
        ("privacy_domain_ids", serde_json::json!([PLAN])),
        ("resource_ids", serde_json::json!([PLAN])),
        (
            "action_intent_ids",
            serde_json::json!(["ACT-IDENTITY_READ_ROLE-V1"]),
        ),
        ("step_up_required", serde_json::json!(true)),
        ("maker_checker_required", serde_json::json!(true)),
    ] {
        input.workload_prediction.paths[0][0]["grant"][field] = value;
        assert_eq!(
            evaluate_indexer_simulation(&input).unwrap().truth_state,
            crate::TruthState::Denied,
            "{field}"
        );
        input.workload_prediction = baseline.clone();
    }
    input.workload_prediction.credential_valid_until_ns = "200".into();
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Denied
    );
    input.workload_prediction = baseline.clone();
    input.workload_prediction.revocations.push(serde_json::json!({
        "revocation_id":"revoked", "participant_id":PARTICIPANT, "target_type":"ASSIGNMENT",
        "target_id":"source-assignment", "effective_at":"time", "reason_code":"SECURITY",
        "authority_epoch":"2", "receipt_digest":"digest", "created_by_principal_id":"maker", "effective_now":true
    }));
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Denied
    );
    input.workload_prediction = baseline.clone();
    input.workload_prediction.workload_id = PLAN.into();
    assert!(evaluate_indexer_simulation(&input).is_err());
    input.workload_prediction = baseline;
    input.actor.roles.push("source-reader".into());
    input.request.range_end = "110".into();
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Denied
    );
    input.request.range_end = "109".into();
    input.request.data_class = IndexerDataClass::FullBlockTransactions;
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Denied
    );
    input.request.data_class = IndexerDataClass::StateCall;
    input.document.required_facts = vec![crate::semantics::FactReference {
        candidate_id: "source-dependency".into(),
        generation_id: "current".into(),
        fact_digest: format!("sha256:{}", "ab".repeat(32)),
    }];
    assert!(evaluate_indexer_simulation(&input).is_err());
    input.facts.push(None);
    assert_eq!(
        evaluate_indexer_simulation(&input).unwrap().truth_state,
        crate::TruthState::Partial
    );
    input.actor.privacy_domain_id = PLAN.into();
    assert!(evaluate_indexer_simulation(&input).is_err());
    input.actor.privacy_domain_id = PRIVACY.into();
    input.indexer_inputs.clear();
    assert!(evaluate_indexer_simulation(&input).is_err());
}
