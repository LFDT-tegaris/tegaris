//! Source references are resolved by the existing configuration owner. Pure
//! compilation verifies their bytes and bounds but establishes no live state.
use super::*;
use crate::invocation::{
    ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1, ActiveInvocationScope,
    ConfigurationArtifactKind, ConfigurationArtifactV1, decode_active_invocation_configuration,
};
use pc_provider_api::{
    RangeEndV1, decode_client_indexer_profile_pc_cbor, decode_projection_plan_pc_cbor,
    validate_client_indexer_profile, validate_projection_plan,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexerCompilationInput {
    pub configuration_cbor: Vec<u8>,
    pub configuration_digest: Digest,
}

/// Exact immutable inputs used by the policy version. The service that supplies
/// these configurations must resolve their current Control references itself;
/// accepting these bytes in an end-user request would bypass that owner.
pub fn compile_indexer_sources(
    policies: &[IndexerPolicy],
    inputs: &[IndexerCompilationInput],
) -> Result<Vec<ConfigurationArtifactV1>, String> {
    if policies.is_empty() {
        return if inputs.is_empty() {
            Ok(Vec::new())
        } else {
            Err("unexpected indexer compilation inputs".into())
        };
    }
    if policies.len() > 256 || inputs.is_empty() || inputs.len() > 256 {
        return Err("indexer compilation inputs missing or oversized".into());
    }
    let mut supplied = BTreeMap::new();
    for input in inputs {
        let configuration = decode_active_invocation_configuration(
            &input.configuration_cbor,
            &input.configuration_digest,
        )
        .map_err(|_| "indexer configuration bytes rejected")?;
        for artifact in configuration.resource_artifacts {
            let key = (artifact.artifact_kind, artifact.artifact_id.clone());
            if let Some(previous) = supplied.insert(key, artifact.clone())
                && (previous.artifact_digest != artifact.artifact_digest
                    || previous.payload_cbor != artifact.payload_cbor)
            {
                return Err("conflicting indexer compilation inputs".into());
            }
        }
    }
    let mut selected = BTreeMap::new();
    for policy in policies {
        policy.validate()?;
        let profile = exact(
            &supplied,
            ConfigurationArtifactKind::ClientIndexerProfile,
            &policy.indexer_profile_id,
            &policy.profile_artifact_digest,
        )?;
        let plan = exact(
            &supplied,
            ConfigurationArtifactKind::ProjectionPlan,
            &policy.projection_plan_id,
            &policy.plan_artifact_digest,
        )?;
        let acquisition = exact(
            &supplied,
            ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
            &policy.indexer_profile_id,
            &policy.acquisition_configuration_digest,
        )?;
        let source = decode_client_indexer_profile_pc_cbor(&profile.payload_cbor)
            .map_err(|_| "indexer profile decoding rejected")?;
        let projection = decode_projection_plan_pc_cbor(&plan.payload_cbor)
            .map_err(|_| "indexer projection decoding rejected")?;
        validate_client_indexer_profile(&source).map_err(|_| "indexer profile tuple rejected")?;
        validate_projection_plan(&source, &projection)
            .map_err(|_| "indexer projection tuple rejected")?;
        let within = |start: u64, end: &RangeEndV1| {
            let requested_start = number(&policy.range_start)?;
            let requested_end = number(&policy.range_end)?;
            Ok::<_, String>(
                requested_start >= start
                    && match end {
                        RangeEndV1::Inclusive(end) => requested_end <= *end,
                        RangeEndV1::Open => true,
                    },
            )
        };
        // The Control resource UUID identifies the artifact binding; the
        // external profile's own identifier belongs to its profile/plan tuple.
        if source.participant_binding != policy.participant_id
            || source.privacy_binding != policy.privacy_domain_id
            || source.workload_binding != policy.workload_id
            || source.configuration_digest != policy.acquisition_configuration_digest
            || !within(source.source_range.start, &source.source_range.end)?
            || !within(projection.source_range.start, &projection.source_range.end)?
            || number(&policy.maximum_range_blocks)? > projection.limits.max_range
            || u64::from(policy.maximum_response_bytes) > projection.limits.max_response_bytes
            || policy.rules.iter().any(|rule| {
                !source.method_data_classes.iter().any(|pair| {
                    pair.method == rule.data_class.profile_method()
                        && pair.data_class == rule.data_class.data_class()
                })
            })
        {
            return Err("indexer policy exceeds its exact source requirements".into());
        }
        for artifact in [profile, plan, acquisition] {
            selected.insert(
                (artifact.artifact_kind, artifact.artifact_id.clone()),
                artifact.clone(),
            );
        }
    }
    Ok(selected.into_values().collect())
}

fn exact<'a>(
    supplied: &'a BTreeMap<(ConfigurationArtifactKind, String), ConfigurationArtifactV1>,
    kind: ConfigurationArtifactKind,
    id: &str,
    expected: &str,
) -> Result<&'a ConfigurationArtifactV1, String> {
    let artifact = supplied
        .get(&(kind, id.to_owned()))
        .ok_or("indexer source reference unresolved")?;
    if format!("sha256:{}", artifact.artifact_digest.as_str()) != expected {
        return Err("indexer source reference digest rejected".into());
    }
    Ok(artifact)
}

pub(crate) fn configuration_context(
    configuration: &ActiveInvocationConfigurationV1,
) -> RuntimeResult<(String, String, String)> {
    let mut scopes = BTreeSet::new();
    for artifact in &configuration.resource_artifacts {
        if artifact.artifact_kind != ConfigurationArtifactKind::ClientIndexerProfile {
            continue;
        }
        let profile = decode_client_indexer_profile_pc_cbor(&artifact.payload_cbor)
            .map_err(|_| RuntimeError::InvalidInput)?;
        validate_client_indexer_profile(&profile).map_err(|_| RuntimeError::InvalidInput)?;
        scopes.insert((
            profile.participant_binding,
            profile.privacy_binding,
            profile.workload_binding,
        ));
    }
    if scopes.len() != 1 {
        return Err(RuntimeError::InvalidAuthorization);
    }
    scopes
        .into_iter()
        .next()
        .ok_or(RuntimeError::InvalidAuthorization)
}

pub(crate) fn validate_selection(
    configuration: &ActiveInvocationConfigurationV1,
    generation: &ActiveInvocationPolicyGenerationV1,
    scope: &ActiveInvocationScope<'_>,
) -> RuntimeResult<()> {
    if generation.indexer_policies.is_empty() {
        return Ok(());
    }
    if generation.indexer_policies.iter().any(|policy| {
        policy.participant_id != scope.tenant_id
            || policy.privacy_domain_id != scope.privacy_domain_id
            || policy.workload_id != scope.workload_id
    }) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let bytes = crate::invocation::encode_active_invocation_configuration(configuration)?;
    compile_indexer_sources(
        &generation.indexer_policies,
        &[IndexerCompilationInput {
            configuration_digest: Digest::of(&bytes),
            configuration_cbor: bytes,
        }],
    )
    .map_err(|_| RuntimeError::InvalidInput)?;
    let mut seen = BTreeSet::new();
    for policy in &generation.indexer_policies {
        if !seen.insert(policy.digest().map_err(|_| RuntimeError::InvalidInput)?) {
            return Err(RuntimeError::InvalidInput);
        }
        let digest = Digest::parse(&policy.rpc_policy_digest[7..])
            .map_err(|_| RuntimeError::InvalidInput)?;
        for rule in &policy.rules {
            RpcSurfacePolicy::resolve(
                &generation.rpc_policies,
                &digest,
                scope.tenant_id,
                scope.privacy_domain_id,
                rule.data_class.profile_method(),
            )
            .map_err(|_| RuntimeError::InvalidInput)?;
        }
    }
    Ok(())
}

pub(crate) fn attach_indexer_assets(
    document: &crate::semantics::PolicySemanticDocument,
    base: Option<crate::contract_policy::CompiledContractPolicyBundle>,
    artifacts: Vec<ConfigurationArtifactV1>,
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<crate::contract_policy::CompiledContractPolicyBundle, String> {
    use crate::invocation::{
        ValidatedInvocationPolicy, decode_active_invocation_policy_generation,
        encode_active_invocation_configuration, encode_active_invocation_policy_generation,
    };
    use crate::{
        contract_policy::CompiledContractPolicyBundle, deployment_policy::ValidatedDeploymentPolicy,
    };
    let invalid = |_| "compiled indexer selection rejected".to_owned();
    let (mut configuration, mut generation) = if let Some(base) = base {
        (
            decode_active_invocation_configuration(
                &base.configuration_cbor,
                &base.configuration_digest,
            )
            .map_err(invalid)?,
            decode_active_invocation_policy_generation(&base.policy_cbor, &base.policy_digest)
                .map_err(invalid)?,
        )
    } else {
        (
            ActiveInvocationConfigurationV1 {
                workload_scope: None,
                visibility_resources: Vec::new(),
                schema_version: "1.0".into(),
                assets: Vec::new(),
                resource_artifacts: Vec::new(),
                deployment_policies: Vec::new(),
            },
            ActiveInvocationPolicyGenerationV1 {
                visibility_policies: Vec::new(),
                fact_conditions: document.fact_conditions.clone(),
                schema_version: "1.0".into(),
                assets: Vec::new(),
                root_asset_ids: Vec::new(),
                deployment_policies: Vec::new(),
                indexer_policies: Vec::new(),
                required_facts: document.required_facts.clone(),
                rpc_policies: document.rpc_policies.clone(),
            },
        )
    };
    for artifact in artifacts {
        if configuration.resource_artifacts.iter().any(|existing| {
            existing.artifact_kind == artifact.artifact_kind
                && existing.artifact_id == artifact.artifact_id
        }) {
            return Err("duplicate indexer artifact binding".into());
        }
        configuration.resource_artifacts.push(artifact);
    }
    configuration
        .resource_artifacts
        .sort_by(|a, b| (a.artifact_kind, &a.artifact_id).cmp(&(b.artifact_kind, &b.artifact_id)));
    generation.indexer_policies = document.indexer_policies.clone();
    let configuration_cbor =
        encode_active_invocation_configuration(&configuration).map_err(invalid)?;
    let configuration_digest = Digest::of(&configuration_cbor);
    let policy_cbor = encode_active_invocation_policy_generation(&generation).map_err(invalid)?;
    let policy_digest = Digest::of(&policy_cbor);
    let scope = ActiveInvocationScope {
        policy_generation_digest: generation_digest,
        tenant_id: &document.participant_id,
        privacy_domain_id: &document.privacy_domain_id,
        workload_id,
    };
    let policies = ValidatedInvocationPolicy::load_active(
        &configuration_cbor,
        &configuration_digest,
        &policy_cbor,
        &policy_digest,
        &scope,
    )
    .map_err(invalid)?;
    let deployment_policies = ValidatedDeploymentPolicy::load_active(
        &configuration_cbor,
        &configuration_digest,
        &policy_cbor,
        &policy_digest,
        &scope,
    )
    .map_err(invalid)?;
    Ok(CompiledContractPolicyBundle {
        configuration_cbor,
        configuration_digest,
        policy_cbor,
        policy_digest,
        policies,
        deployment_policies,
    })
}
