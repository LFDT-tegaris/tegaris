//! Typed policy component fixture for the real SQL/TLS/capsule owner regression.
//! Its definition bindings are test-local and do not qualify a release profile.
use crate::{
    ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireSigner,
    authority_artifact::{AuthorityArtifact, AuthoritySourceBinding},
    invocation_custody::InvocationArtifactAdmission,
};
use pc_policy_core::invocation::{
    AbiType, ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
    ApprovalRequirement, InvocationConfigurationAssetV1, InvocationPolicyAssetV1,
    encode_active_invocation_configuration, encode_active_invocation_policy_generation,
};
use pc_runtime_types::{Digest, RequestClass, RuntimeError, RuntimeResult};
use std::{collections::BTreeMap, sync::Arc};
struct RejectOther;
impl ArtifactAdmission for RejectOther {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidInput)
    }
}
pub(crate) fn install(
    participant: &str,
    privacy: &str,
    workload: &str,
    role: &str,
    capsule: &mut RuntimeCapsule,
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    signer: &RuntimeWireSigner,
) -> Arc<InvocationArtifactAdmission> {
    install_request(
        (participant, privacy, workload, role),
        capsule,
        artifacts,
        signer,
        None,
    )
}

#[derive(Clone, Copy)]
pub(crate) enum CiglFixture {
    Reviewed,
    StateProgram,
    Initial,
    InitialRequired,
    InitialWrongChain,
    InitialDisabled,
    InitialTraceCall,
}

pub(crate) struct RequestMaterial {
    pub binding_id: String,
    pub submission: bool,
    pub cigl_mode: CiglFixture,
    pub facts: Vec<pc_policy_core::semantics::FactReference>,
    pub provider: pc_policy_core::invocation::ConfigurationArtifactV1,
    pub recovery_provider: Option<pc_policy_core::invocation::ConfigurationArtifactV1>,
}

pub(crate) fn install_request(
    (participant, privacy, workload, role): (&str, &str, &str, &str),
    capsule: &mut RuntimeCapsule,
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    signer: &RuntimeWireSigner,
    material: Option<RequestMaterial>,
) -> Arc<InvocationArtifactAdmission> {
    let mut configuration = ActiveInvocationConfigurationV1 {
        workload_scope: None,
        visibility_resources: Vec::new(),
        deployment_policies: Vec::new(),
        schema_version: "1.0".into(),
        resource_artifacts: Vec::new(),
        assets: vec![InvocationConfigurationAssetV1 {
            asset_id: "balance".into(),
            runtime_binding_id: None,
            transaction_policy: None,
            tenant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            workload_id: workload.into(),
            rpc_method: "eth_call".into(),
            request_class: RequestClass::Read,
            chain_id: "31337".into(),
            network_id: "local".into(),
            genesis_digest: Digest::of(b"local genesis"),
            contract_address: [1; 20],
            proxy_address: None,
            implementation_address: None,
            code_digest: Digest::of(b"controlled contract code"),
            implementation_code_digest: None,
            abi_digest: Digest::of(b"balanceOf ABI"),
            canonical_signature: "balanceOf(address)".into(),
            selector: [0x70, 0xa0, 0x82, 0x31],
            input_types: vec![AbiType::Address],
            named_sets: Vec::new(),
        }],
    };
    let mut policy = ActiveInvocationPolicyGenerationV1 {
        visibility_policies: Vec::new(),
        fact_conditions: Vec::new(),
        indexer_policies: Vec::new(),
        deployment_policies: Vec::new(),
        required_facts: Vec::new(),
        schema_version: "1.0".into(),
        root_asset_ids: vec!["balance".into()],
        rpc_policies: Vec::new(),
        assets: vec![InvocationPolicyAssetV1 {
            method_required_roles: None,
            // Match the existing public configuration's canonical empty set.
            nested_call_set_digest: Some(Digest::of(b"[]")),
            rpc_denied: false,
            asset_id: "balance".into(),
            policy_version: "1".into(),
            active: true,
            required_roles: vec![role.into()],
            approval: ApprovalRequirement::None,
            webauthn_required: false,
            argument_rules: Vec::new(),
            nested_asset_ids: Vec::new(),
        }],
    };
    if let Some(material) = material {
        if !material.submission {
            install_visibility(
                &mut configuration,
                &mut policy,
                (participant, privacy, workload, role),
                &material.binding_id,
            );
        }
        if material.submission {
            policy
                .rpc_policies
                .push(pc_policy_core::rpc_policy::RpcSurfacePolicy {
                    schema_version: "1.0.0".into(),
                    participant_id: participant.into(),
                    privacy_domain_id: privacy.into(),
                    rules: vec![pc_policy_core::rpc_policy::RpcRule {
                        method: "pc_getOperationStatus".into(),
                        effect: pc_policy_core::rpc_policy::RpcEffect::Allow,
                        required_roles: vec![role.into()],
                    }],
                });
            configuration.assets[0].rpc_method = "eth_sendRawTransaction".into();
            configuration.assets[0].request_class = RequestClass::Write;
            configuration.assets[0].chain_id = "1".into();
            configuration.assets[0].code_digest = Digest::of([0x60, 0x00, 0x60, 0x00, 0xf3]);
            configuration.assets[0].transaction_policy =
                Some(pc_policy_core::transaction_policy::TransactionPolicyV1 {
                    version: 1,
                    allowed_transaction_types: vec![0, 1, 2],
                    maximum_value: [0; 32],
                    maximum_gas_limit: 100_000,
                    maximum_fee_per_gas: [255; 32],
                    maximum_priority_fee_per_gas: [255; 32],
                    maximum_raw_transaction_bytes: 4096,
                    maximum_calldata_bytes: 1024,
                    maximum_access_list_addresses: 0,
                    maximum_access_list_storage_keys: 0,
                });
        }
        let policy_id = "018f0000-0000-7000-8000-000000000102";
        configuration.assets[0].asset_id = policy_id.into();
        policy.assets[0].asset_id = policy_id.into();
        policy.root_asset_ids = vec![policy_id.into()];
        configuration.assets[0].runtime_binding_id = Some(material.binding_id);
        configuration.resource_artifacts.push(material.provider);
        configuration
            .resource_artifacts
            .extend(material.recovery_provider);
        policy.required_facts = material.facts;
        if material.submission {
            let state_fact = matches!(material.cigl_mode, CiglFixture::StateProgram)
                .then(|| policy.required_facts[0].clone());
            install_cigl_component(&mut configuration, &mut policy, role, state_fact);
            if matches!(
                material.cigl_mode,
                CiglFixture::Initial
                    | CiglFixture::InitialRequired
                    | CiglFixture::InitialWrongChain
                    | CiglFixture::InitialDisabled
                    | CiglFixture::InitialTraceCall
            ) {
                install_initial_analysis(&mut configuration, &mut policy, material.cigl_mode);
            }
        }
    }
    // Preserve the production compiler's source-version binding for the
    // downstream Fleet compilation join exercised by this fixture.
    for asset in policy
        .assets
        .iter_mut()
        .filter(|asset| asset.method_required_roles.is_some())
    {
        asset.policy_version = format!(
            "1:{}:{}",
            Digest::of("fixture rpc method policy").as_str(),
            asset
                .nested_call_set_digest
                .as_ref()
                .unwrap_or(&Digest::of([]))
                .as_str()
        );
    }
    install_sources(
        (participant, privacy),
        capsule,
        artifacts,
        signer,
        encode_active_invocation_configuration(&configuration).unwrap(),
        encode_active_invocation_policy_generation(&policy).unwrap(),
    )
}

fn install_visibility(
    configuration: &mut ActiveInvocationConfigurationV1,
    policy: &mut ActiveInvocationPolicyGenerationV1,
    (participant, privacy, workload, role): (&str, &str, &str, &str),
    binding_id: &str,
) {
    configuration.workload_scope = Some(pc_policy_core::invocation::InvocationConfigurationScope {
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        workload_id: workload.into(),
    });
    use pc_policy_core::rpc_policy::{RpcEffect, RpcRule, RpcSurfacePolicy};
    use pc_policy_core::visibility_policy::*;
    let binding = VisibilityContractBinding {
        chain_id: "31337".into(),
        network_id: "local".into(),
        genesis_digest: format!("sha256:{}", Digest::of(b"local genesis").as_str()),
        contract_address: format!("0x{}", "01".repeat(20)),
        code_digest: format!(
            "sha256:{}",
            Digest::of(b"controlled contract code").as_str()
        ),
        abi_digest: format!("sha256:{}", Digest::of(b"visibility ABI").as_str()),
        canonical_abi: serde_json::json!([{"type":"event","name":"Changed","anonymous":false,"inputs":[{"name":"value","type":"uint256","indexed":false}]}]),
    };
    let selectors = [
        (
            VisibilitySelector::Transaction {
                runtime_binding_id: binding_id.into(),
                binding_revision: "1".into(),
            },
            "eth_getTransactionByHash",
            "TRANSACTION_READ",
            vec![
                "hash",
                "blockHash",
                "blockNumber",
                "transactionIndex",
                "from",
                "to",
                "gas",
                "input",
                "nonce",
                "value",
            ],
        ),
        (
            VisibilitySelector::Receipt {
                runtime_binding_id: binding_id.into(),
                binding_revision: "1".into(),
            },
            "eth_getTransactionReceipt",
            "RECEIPT_READ",
            vec![],
        ),
        (
            VisibilitySelector::Event {
                runtime_binding_id: binding_id.into(),
                binding_revision: "1".into(),
                abi_digest: binding.abi_digest.clone(),
                event_signature: "Changed(uint256)".into(),
            },
            "eth_getLogs",
            "EVENT_READ",
            vec!["inputs[0]"],
        ),
    ];
    let mut rules = Vec::new();
    for (index, (selector, method, purpose, fields)) in selectors.into_iter().enumerate() {
        let available_fields = fields.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        configuration
            .visibility_resources
            .push(AdmittedVisibilityResource {
                state_output_types: None,
                participant_id: participant.into(),
                privacy_domain_id: privacy.into(),
                selector: selector.clone(),
                available_fields: available_fields.clone(),
                contract_binding: Some(binding.clone()),
            });
        policy.visibility_policies.push(VisibilityPolicy {
            policy_id: format!("018f0000-0000-7000-8000-000000000{:03}", 700 + index),
            selector,
            mode: VisibilityMode::Static,
            effect: RpcEffect::Allow,
            subject: VisibilitySubject::Workload {
                workload_id: workload.into(),
            },
            purpose: purpose.into(),
            required_roles: vec![role.into()],
            dimensions: vec![
                VisibilityDimension::Existence,
                VisibilityDimension::Metadata,
                VisibilityDimension::Payload,
            ],
            fields: if method == "eth_getTransactionByHash" {
                vec!["hash".into(), "from".into()]
            } else {
                available_fields
            },
            conditions: vec![],
        });
        rules.push(RpcRule {
            method: method.into(),
            effect: RpcEffect::Allow,
            required_roles: vec![role.into()],
        });
    }
    policy.rpc_policies.push(RpcSurfacePolicy {
        schema_version: "1.0.0".into(),
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        rules,
    });
}

// Downstream signed-settings fixture. Public settings provenance is tested by
// Fleet against the real approved SQL source in the ordinary identity runner.
fn install_initial_analysis(
    configuration: &mut ActiveInvocationConfigurationV1,
    policy: &mut ActiveInvocationPolicyGenerationV1,
    mode: CiglFixture,
) {
    use pc_policy_core::{
        cigl::settings::*,
        invocation::{ConfigurationArtifactKind, ConfigurationArtifactV1},
    };
    configuration
        .resource_artifacts
        .retain(|artifact| artifact.artifact_kind != ConfigurationArtifactKind::CiglProfile);
    if matches!(mode, CiglFixture::Initial) {
        policy.assets[0].nested_call_set_digest = Some(Digest::of(b"[]"));
    }
    let definition: CiglSettingsDefinition = serde_json::from_value(serde_json::json!({
        "schemaVersion":"1.0", "scope":{"kind":"ALL_CHAINS"}, "mode":"HYBRID_STRICT",
        "enforcement":{"ethCall":true,"ethEstimateGas":true,"prepareWrite":true,"rawSubmission":true,
            "deploymentConstructors":true,"runtimeTraceForWrites":true,"reviewedSchemaSubset":true,
            "failClosed":true,"rejectExternalStateOverrides":true},
        "traceLimits":{"maxDepth":16,"maxFrames":32,"maxResponseBytes":100000,"timeoutMs":5000},
        "traceProvider":"DEBUG_TRACE_CALL","readinessScope":"METHOD","schemaFallbackEnabled":false,
        "precompileAllowlist":[],"systemContractAllowlist":[],"postMine":{"enabled":false,"freezeOnDivergence":false}
    })).unwrap();
    let mut definition = definition;
    if matches!(mode, CiglFixture::InitialWrongChain) {
        definition.scope = SettingsScope::Chain {
            chain_id: "92870".into(),
            network_id: "devnet".into(),
            genesis_digest: format!("sha256:{}", Digest::of("other genesis").as_str()),
        };
    }
    if matches!(mode, CiglFixture::InitialDisabled) {
        definition.mode = GovernanceMode::Off;
    }
    if matches!(mode, CiglFixture::InitialTraceCall) {
        definition.trace_provider = TraceProvider::TraceCall;
    }
    let settings = ConfiguredCiglSettings {
        settings_id: "018f0000-0000-7000-8000-000000000901".into(),
        participant_id: configuration.assets[0].tenant_id.clone(),
        privacy_domain_id: configuration.assets[0].privacy_domain_id.clone(),
        publication_operation_id: "018f0000-0000-7000-8000-000000000902".into(),
        publication_authority_digest: Digest::of("test-installed source"),
        definition_digest: definition.digest().unwrap(),
        definition,
    };
    let payload = settings.to_cbor().unwrap();
    configuration
        .resource_artifacts
        .push(ConfigurationArtifactV1 {
            artifact_id: settings.settings_id,
            artifact_kind: ConfigurationArtifactKind::CiglSettings,
            artifact_digest: Digest::of(&payload),
            payload_cbor: payload,
        });
}

/// Downstream installed-profile fixture, not public analysis/review acceptance.
/// Its subjects still resolve through the real signed identity publication.
fn install_cigl_component(
    configuration: &mut ActiveInvocationConfigurationV1,
    policy: &mut ActiveInvocationPolicyGenerationV1,
    role: &str,
    state_fact: Option<pc_policy_core::semantics::FactReference>,
) {
    use pc_policy_core::cigl::program::{
        CiglProgramV1, Primitive, ResultType, StateValueReference,
    };
    use pc_policy_core::cigl::{CallKind, TraceLimits, grants::*, profile::*};
    use pc_policy_core::invocation::{
        ArgumentRule, ArgumentValue, Comparator, ConfigurationArtifactKind,
        ConfigurationArtifactV1, PathSegment, RuleValues,
    };
    let mut primitives = Vec::new();
    if let Some(fact) = state_fact {
        primitives.extend([
            Primitive::LoadStateEvidence(StateValueReference {
                fact,
                value_type: AbiType::Bool,
            }),
            Primitive::Require(()),
        ]);
    }
    primitives.extend([
        Primitive::LoadArgument(vec![PathSegment::Input(0)]),
        Primitive::PushConst(ArgumentValue::Address([2; 20])),
        Primitive::Eq(()),
        Primitive::Return(()),
    ]);
    let root = &configuration.assets[0];
    let mut definition = MethodProfileDefinition {
        schema_version: "1.0".into(),
        profile_id: "018f0000-0000-7000-8000-000000000801".into(),
        revision: 1,
        participant_id: root.tenant_id.clone(),
        privacy_domain_id: root.privacy_domain_id.clone(),
        root_contract_method_policy_id: root.asset_id.clone(),
        analysis_digest: Digest::of("downstream reviewed-profile fixture"),
        program: Some(CiglProgramV1 {
            program_id: "cigl.joined/root".into(),
            version: 1,
            primitives,
            max_steps: 16,
            max_stack_depth: 2,
            max_evidence_reads: 1,
            result_type: ResultType::AllowDenyIndeterminate,
        }),
        limits: TraceLimits {
            max_depth: 16,
            max_frames: 32,
            max_response_bytes: 100_000,
            timeout_ms: 10_000,
        },
        interactions: Vec::new(),
    };
    let mut grants = Vec::new();
    policy.assets[0].method_required_roles = Some(vec![role.into()]);
    for (address, method_id, binding_id) in [
        (
            2,
            "018f0000-0000-7000-8000-000000000802",
            "018f0000-0000-7000-8000-000000000803",
        ),
        (
            3,
            "018f0000-0000-7000-8000-000000000804",
            "018f0000-0000-7000-8000-000000000805",
        ),
    ] {
        let mut target = configuration.assets[0].clone();
        target.asset_id = method_id.into();
        target.runtime_binding_id = Some(binding_id.into());
        target.contract_address = [address; 20];
        target.code_digest = Digest::of([0x60, 1]);
        target.transaction_policy = None;
        target.rpc_method = "eth_call".into();
        target.request_class = RequestClass::Read;
        definition.interactions.push(MethodInteractionRule {
            interaction_id: format!("target-{address}"),
            caller: CallerConstraint::RootExecution {},
            call_kind: CallKind::Staticcall,
            contract_method_policy_id: method_id.into(),
            maximum_value: [0; 32],
        });
        let allow = InteractionGrant {
            grant_id: format!("shared-allow-{address}"),
            runtime_binding_id: binding_id.into(),
            selector: target.selector,
            subject: GrantSubject::Role { id: role.into() },
            surface: InteractionSurface::RawSubmission,
            effect: GrantEffect::Allow,
            status: GrantStatus::Active,
        };
        if address == 3 {
            let mut deny = allow.clone();
            deny.grant_id = "shared-deny-3".into();
            deny.effect = GrantEffect::Deny;
            grants.push(deny);
        }
        grants.push(allow);
        let mut target_policy = policy.assets[0].clone();
        target_policy.asset_id = method_id.into();
        target_policy
            .required_roles
            .push("ungranted-direct-reader".into());
        target_policy.argument_rules = vec![ArgumentRule {
            path: vec![PathSegment::Input(0)],
            comparator: Comparator::Eq,
            values: RuleValues::Inline(vec![ArgumentValue::Address([2; 20])]),
        }];
        configuration.assets.push(target);
        policy.assets.push(target_policy);
        policy.root_asset_ids.push(method_id.into());
    }
    let digest = definition.digest().unwrap();
    policy.assets[0].nested_call_set_digest = Some(digest.clone());
    let profile = ConfiguredMethodProfile {
        grants: InteractionGrantSet {
            profile_id: definition.profile_id.clone(),
            profile_revision: 1,
            profile_digest: digest,
            participant_id: definition.participant_id.clone(),
            privacy_domain_id: definition.privacy_domain_id.clone(),
            status: GrantStatus::Active,
            grants,
        },
        definition,
    };
    let payload = profile.to_cbor().unwrap();
    configuration
        .resource_artifacts
        .push(ConfigurationArtifactV1 {
            artifact_id: profile.definition.profile_id.clone(),
            artifact_kind: ConfigurationArtifactKind::CiglProfile,
            artifact_digest: Digest::of(&payload),
            payload_cbor: payload,
        });
}

pub(crate) fn install_sources(
    (participant, privacy): (&str, &str),
    capsule: &mut RuntimeCapsule,
    artifacts: &mut BTreeMap<Digest, Vec<u8>>,
    signer: &RuntimeWireSigner,
    configuration_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
) -> Arc<InvocationArtifactAdmission> {
    let mut add = |id: &str, source: Vec<u8>| {
        let header = AuthorityArtifact {
            artifact_id: id.into(),
            artifact_version: 1,
            artifact_class: 1,
            source_media_type: "application/cbor".into(),
            source_content_sha256: Digest::of(&source),
            definition_digest: Digest::of(format!("test-local {id} definition")),
            issued_at_ns: capsule.issued_at_ns,
            signer_id: "fixture-policy-owner".into(),
        };
        let binding = AuthoritySourceBinding {
            artifact_id: id.into(),
            artifact_class: 1,
            source_media_type: header.source_media_type.clone(),
            definition_digest: header.definition_digest.clone(),
            signer_id: header.signer_id.clone(),
            maximum_source_bytes: 1024 * 1024,
        };
        let signed = signer.sign_authority_artifact(&header).unwrap();
        let source_digest = header.source_content_sha256.clone();
        capsule.artifact_components.push(ArtifactComponent {
            component_id: id.into(),
            component_type: "canonical-authority".into(),
            content_digest: Digest::of(&signed),
            semantic_digest: header.semantic_digest().unwrap(),
            schema_id: 1010,
            schema_version: 1,
            size_bytes: signed.len() as u64,
            required: true,
        });
        artifacts.insert(header.source_content_sha256, source);
        artifacts.insert(Digest::of(&signed), signed);
        (binding, source_digest)
    };
    let (configuration, _) = add("configuration", configuration_bytes);
    let (policy, policy_source_digest) = add("policy", policy_bytes);
    capsule.semantic_model_digest = policy_source_digest;
    capsule.policy_bundle_digest = capsule
        .artifact_components
        .iter()
        .find(|c| c.component_id == "policy")
        .unwrap()
        .semantic_digest
        .clone();
    capsule
        .artifact_components
        .sort_by_key(|c| c.canonical_bytes().unwrap());
    Arc::new(
        InvocationArtifactAdmission::new(
            signer.verifier(),
            participant.into(),
            privacy.into(),
            configuration,
            policy,
            Arc::new(RejectOther),
        )
        .unwrap(),
    )
}
