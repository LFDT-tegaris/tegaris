use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use pc_runtime_types::{ContractInvocation, Digest, RequestClass, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const WORD: usize = 32;
const MAX_DECODED_COLLECTION: usize = 4_096;

mod abi_projection;
pub use abi_projection::decode_canonical_abi;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AbiType {
    Address,
    Bool,
    Uint(u16),
    Int(u16),
    FixedBytes(u8),
    Bytes,
    String,
    Array {
        element: Box<AbiType>,
        length: Option<usize>,
    },
    Tuple(Vec<AbiType>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArgumentValue {
    Address([u8; 20]),
    Bool(bool),
    Uint([u8; WORD]),
    Int([u8; WORD]),
    Bytes(Vec<u8>),
    String(String),
    Array(Vec<ArgumentValue>),
    Tuple(Vec<ArgumentValue>),
}

impl ArgumentValue {
    #[must_use]
    pub fn uint(value: u128) -> Self {
        let mut word = [0_u8; WORD];
        word[16..].copy_from_slice(&value.to_be_bytes());
        Self::Uint(word)
    }

    #[must_use]
    pub fn int(value: i128) -> Self {
        let fill = if value.is_negative() { u8::MAX } else { 0 };
        let mut word = [fill; WORD];
        word[16..].copy_from_slice(&value.to_be_bytes());
        Self::Int(word)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PathSegment {
    Input(usize),
    Field(usize),
    Index(usize),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Comparator {
    Eq,
    In,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuleValues {
    Inline(Vec<ArgumentValue>),
    NamedSet {
        owner_id: String,
        set_id: String,
        version: String,
        digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArgumentRule {
    pub path: Vec<PathSegment>,
    pub comparator: Comparator,
    pub values: RuleValues,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedSet {
    pub owner_id: String,
    pub set_id: String,
    pub version: String,
    pub digest: Digest,
    pub tenant_id: String,
    pub locked: bool,
    pub values: Vec<ArgumentValue>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalRequirement {
    None,
    Single,
    MakerChecker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationPolicy {
    /// Original authored method roles, before intersection with the public RPC
    /// surface. Legacy artifacts cannot infer these from the combined role set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_required_roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_call_set_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rpc_denied: bool,
    pub tenant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub policy_version: String,
    pub policy_artifact_digest: Digest,
    pub policy_generation_digest: Digest,
    pub active: bool,
    pub rpc_method: String,
    pub request_class: RequestClass,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: Digest,
    pub contract_address: [u8; 20],
    pub proxy_address: Option<[u8; 20]>,
    pub implementation_address: Option<[u8; 20]>,
    pub code_digest: Digest,
    pub implementation_code_digest: Option<Digest>,
    pub abi_digest: Digest,
    pub canonical_signature: String,
    pub selector: [u8; 4],
    pub input_types: Vec<AbiType>,
    pub required_roles: Vec<String>,
    pub approval: ApprovalRequirement,
    pub webauthn_required: bool,
    pub argument_rules: Vec<ArgumentRule>,
    pub named_sets: Vec<NamedSet>,
    pub nested_policies: Vec<InvocationPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationConfigurationAssetV1 {
    pub asset_id: String,
    /// Owning control-store binding. Legacy component artifacts omit this and
    /// remain readable, but cannot establish a production authorization scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_policy: Option<crate::transaction_policy::TransactionPolicyV1>,
    pub tenant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub rpc_method: String,
    pub request_class: RequestClass,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: Digest,
    pub contract_address: [u8; 20],
    pub proxy_address: Option<[u8; 20]>,
    pub implementation_address: Option<[u8; 20]>,
    pub code_digest: Digest,
    pub implementation_code_digest: Option<Digest>,
    pub abi_digest: Digest,
    pub canonical_signature: String,
    pub selector: [u8; 4],
    pub input_types: Vec<AbiType>,
    pub named_sets: Vec<NamedSet>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveInvocationConfigurationV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_scope: Option<InvocationConfigurationScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visibility_resources: Vec<crate::visibility_policy::AdmittedVisibilityResource>,
    pub schema_version: String,
    pub assets: Vec<InvocationConfigurationAssetV1>,
    pub resource_artifacts: Vec<ConfigurationArtifactV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_policies: Vec<crate::deployment_policy::ConfiguredDeploymentPolicy>,
}

/// The compilation owner's target workload binding, independent of whether
/// the document grants any invocation or indexer operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationConfigurationScope {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ConfigurationArtifactKind {
    ProviderProfile,
    ClientIndexerProfile,
    IndexerFinalityRule,
    IndexerAcquisitionConfiguration,
    ProjectionPlan,
    FactAdmissionProfile,
    CiglProfile,
    CiglSettings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationArtifactV1 {
    pub artifact_id: String,
    pub artifact_kind: ConfigurationArtifactKind,
    pub artifact_digest: Digest,
    pub payload_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationPolicyAssetV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_required_roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_call_set_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rpc_denied: bool,
    pub asset_id: String,
    pub policy_version: String,
    pub active: bool,
    pub required_roles: Vec<String>,
    pub approval: ApprovalRequirement,
    pub webauthn_required: bool,
    pub argument_rules: Vec<ArgumentRule>,
    pub nested_asset_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveInvocationPolicyGenerationV1 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visibility_policies: Vec<crate::visibility_policy::VisibilityPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_conditions: Vec<crate::fact_condition::FactCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexer_policies: Vec<crate::indexer_policy::IndexerPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_policies: Vec<crate::deployment_policy::DeploymentPolicyReference>,
    /// Exact dependencies of the approved semantic document. Older component
    /// artifacts decode without them but cannot establish production readiness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_facts: Vec<crate::semantics::FactReference>,
    pub schema_version: String,
    pub root_asset_ids: Vec<String>,
    pub assets: Vec<InvocationPolicyAssetV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpc_policies: Vec<crate::rpc_policy::RpcSurfacePolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedApprovalFact {
    pub approval_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub subject_digest: Digest,
    pub maker_principal_id: String,
    pub checker_principal_id: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedWebauthnFact {
    pub challenge_id: String,
    pub participant_id: String,
    pub principal_id: String,
    pub request_digest: Digest,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvocationAuthorization {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub workload_id: String,
    pub actor_principal_id: String,
    pub roles: Vec<String>,
    pub approval: Option<VerifiedApprovalFact>,
    pub webauthn: Option<VerifiedWebauthnFact>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedInvocationPolicy {
    artifact: InvocationPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    configured_identity: Option<ConfiguredInvocationIdentity>,
}

/// Exact control-store identities recovered from the same configuration entry
/// that supplies this policy's chain, target and selector. These identify the
/// owning resources; they do not independently grant invocation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfiguredInvocationIdentity {
    contract_method_policy_id: String,
    runtime_binding_id: String,
    transaction_policy: Option<crate::transaction_policy::TransactionPolicyV1>,
}
impl ConfiguredInvocationIdentity {
    pub fn contract_method_policy_id(&self) -> &str {
        &self.contract_method_policy_id
    }
    pub fn transaction_policy(
        &self,
    ) -> RuntimeResult<&crate::transaction_policy::TransactionPolicyV1> {
        self.transaction_policy
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)
    }
    pub fn runtime_binding_id(&self) -> &str {
        &self.runtime_binding_id
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatedInvocationAuthorization {
    facts: InvocationAuthorization,
}

#[derive(Clone, Copy, Debug)]
pub struct ActiveInvocationScope<'a> {
    pub policy_generation_digest: &'a Digest,
    pub tenant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub workload_id: &'a str,
}

impl ValidatedInvocationPolicy {
    pub fn try_new(artifact: InvocationPolicy) -> RuntimeResult<Self> {
        let mut selectors = BTreeMap::new();
        let mut signatures = BTreeSet::new();
        validate_policy_artifact(&artifact, &artifact, 0, &mut selectors, &mut signatures)?;
        Ok(Self {
            artifact,
            configured_identity: None,
        })
    }

    pub fn load_active(
        configuration_bytes: &[u8],
        configuration_digest: &Digest,
        policy_bytes: &[u8],
        policy_artifact_digest: &Digest,
        scope: &ActiveInvocationScope<'_>,
    ) -> RuntimeResult<Vec<Self>> {
        if scope.tenant_id.is_empty()
            || scope.privacy_domain_id.is_empty()
            || scope.workload_id.is_empty()
            || Digest::of(configuration_bytes) != *configuration_digest
            || Digest::of(policy_bytes) != *policy_artifact_digest
            || *scope.policy_generation_digest == Digest::of([])
        {
            return Err(RuntimeError::InvalidInput);
        }
        let configuration = decode_active_configuration(configuration_bytes, configuration_digest)?;
        let generation: ActiveInvocationPolicyGenerationV1 = decode_exact(policy_bytes)?;
        crate::fact_condition::validate_conditions(
            &generation.fact_conditions,
            &generation.required_facts,
        )?;
        if !generation.required_facts.is_empty() {
            crate::semantics::validate_fact_references(&generation.required_facts)
                .map_err(|_| RuntimeError::InvalidInput)?;
        }
        if configuration.schema_version != "1.0"
            || generation.schema_version != "1.0"
            || (configuration.assets.is_empty()
                && configuration.deployment_policies.is_empty()
                && generation.indexer_policies.is_empty()
                && generation.visibility_policies.is_empty())
            || configuration.assets.len() > MAX_DECODED_COLLECTION
            || (generation.assets.is_empty()
                && generation.deployment_policies.is_empty()
                && generation.indexer_policies.is_empty()
                && generation.visibility_policies.is_empty())
            || generation.assets.len() > MAX_DECODED_COLLECTION
            || (generation.root_asset_ids.is_empty() && !generation.assets.is_empty())
            || generation.root_asset_ids.len() > MAX_DECODED_COLLECTION
            || (!generation.visibility_policies.is_empty()
                && configuration.workload_scope.is_none())
        {
            return Err(RuntimeError::InvalidInput);
        }
        if configuration
            .workload_scope
            .as_ref()
            .is_some_and(|configured| {
                configured.participant_id != scope.tenant_id
                    || configured.privacy_domain_id != scope.privacy_domain_id
                    || configured.workload_id != scope.workload_id
            })
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        crate::deployment_policy::validate_selection(&configuration, &generation)?;
        crate::indexer_policy::validate_selection(&configuration, &generation, scope)?;
        crate::visibility_policy::validate_resources(&configuration, &generation, scope)?;
        if configuration.deployment_policies.iter().any(|configured| {
            configured.workload_id != scope.workload_id
                || configured.publication.participant_id != scope.tenant_id
                || configured.publication.privacy_domain_id != scope.privacy_domain_id
        }) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let configuration_by_id = unique_by_id(&configuration.assets, |asset| &asset.asset_id)?;
        let policy_by_id = unique_by_id(&generation.assets, |asset| &asset.asset_id)?;
        if configuration_by_id.keys().copied().collect::<BTreeSet<_>>()
            != policy_by_id.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err(RuntimeError::InvalidInput);
        }
        let roots = generation
            .root_asset_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if roots.len() != generation.root_asset_ids.len()
            || roots
                .iter()
                .any(|asset_id| !policy_by_id.contains_key(asset_id))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut parent_count = policy_by_id
            .keys()
            .map(|asset_id| (*asset_id, 0_usize))
            .collect::<BTreeMap<_, _>>();
        for asset in &generation.assets {
            let children = asset
                .nested_asset_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if children.len() != asset.nested_asset_ids.len()
                || children.contains(asset.asset_id.as_str())
            {
                return Err(RuntimeError::InvalidInput);
            }
            for child in children {
                let count = parent_count
                    .get_mut(child)
                    .ok_or(RuntimeError::InvalidInput)?;
                *count = count.checked_add(1).ok_or(RuntimeError::InvalidInput)?;
            }
        }
        if parent_count.iter().any(|(asset_id, count)| {
            (roots.contains(asset_id) && *count != 0) || (!roots.contains(asset_id) && *count != 1)
        }) {
            return Err(RuntimeError::InvalidInput);
        }
        let mut visiting = BTreeSet::new();
        let mut policies = Vec::with_capacity(roots.len());
        for root in &generation.root_asset_ids {
            let mut policy = Self::try_new(build_policy(
                root,
                &configuration_by_id,
                &policy_by_id,
                policy_artifact_digest,
                scope.policy_generation_digest,
                scope.tenant_id,
                scope.privacy_domain_id,
                scope.workload_id,
                &mut visiting,
            )?)?;
            policy.configured_identity = configured_identity(
                configuration_by_id
                    .get(root.as_str())
                    .ok_or(RuntimeError::InvalidInput)?,
            )?;
            policies.push(policy);
        }
        Ok(policies)
    }

    /// Read-only compiled source for publication provenance checks. Borrowing
    /// this document does not supply invocation authorization or currentness.
    pub fn artifact(&self) -> &InvocationPolicy {
        &self.artifact
    }

    /// Hand-built policies and legacy artifacts have no recovered resource
    /// provenance. A target must reject them instead of fabricating a scope ID.
    pub fn configured_identity(&self) -> RuntimeResult<&ConfiguredInvocationIdentity> {
        self.configured_identity
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)
    }
    pub fn exposed_contract_address(&self) -> [u8; 20] {
        self.artifact
            .proxy_address
            .unwrap_or(self.artifact.contract_address)
    }
    pub fn selector(&self) -> [u8; 4] {
        self.artifact.selector
    }
}

fn configured_identity(
    asset: &InvocationConfigurationAssetV1,
) -> RuntimeResult<Option<ConfiguredInvocationIdentity>> {
    if let Some(policy) = &asset.transaction_policy {
        policy.validate()?;
        if asset.runtime_binding_id.is_none() {
            return Err(RuntimeError::InvalidInput);
        }
    }
    let Some(binding) = &asset.runtime_binding_id else {
        return Ok(None);
    };
    if !crate::semantics::uuid_v7(binding) || !crate::semantics::uuid_v7(&asset.asset_id) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(Some(ConfiguredInvocationIdentity {
        contract_method_policy_id: asset.asset_id.clone(),
        runtime_binding_id: binding.clone(),
        transaction_policy: asset.transaction_policy.clone(),
    }))
}

pub fn validate_active_policy_set(policies: &[ValidatedInvocationPolicy]) -> RuntimeResult<()> {
    for (index, policy) in policies.iter().enumerate() {
        if policies[..index]
            .iter()
            .any(|existing| same_dispatch_identity(existing.artifact(), policy.artifact()))
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(())
}

pub fn select_active_policy<'a>(
    policies: &'a [ValidatedInvocationPolicy],
    request: &pc_runtime_types::RuntimeRequest,
    bindings: &pc_runtime_types::RuntimeBindings,
) -> RuntimeResult<&'a ValidatedInvocationPolicy> {
    select_active_policy_in_scope(
        policies,
        request,
        ActiveInvocationScope {
            policy_generation_digest: &bindings.policy_generation_digest,
            tenant_id: &bindings.participant_id,
            privacy_domain_id: &bindings.privacy_domain_id,
            workload_id: &bindings.workload_id,
        },
    )
}

/// Resolve invocation authority before routing. Selecting a policy must not
/// require an adapter to fabricate provider or readiness fields in bindings.
pub fn select_active_policy_in_scope<'a>(
    policies: &'a [ValidatedInvocationPolicy],
    request: &pc_runtime_types::RuntimeRequest,
    scope: ActiveInvocationScope<'_>,
) -> RuntimeResult<&'a ValidatedInvocationPolicy> {
    request.validate_digest()?;
    let invocation = request.invocation.as_ref().ok_or(RuntimeError::Denied)?;
    let selector = invocation.calldata.get(..4).ok_or(RuntimeError::Denied)?;
    let mut matches = policies.iter().filter(|policy| {
        let policy = policy.artifact();
        policy.active
            && policy.tenant_id == scope.tenant_id
            && policy.privacy_domain_id == scope.privacy_domain_id
            && policy.workload_id == scope.workload_id
            && &policy.policy_generation_digest == scope.policy_generation_digest
            && policy.rpc_method == request.method
            && policy.request_class == request.class
            && policy.chain_id == invocation.chain_id
            && policy.network_id == invocation.network_id
            && policy.genesis_digest == invocation.genesis_digest
            && policy.contract_address == invocation.contract_address
            && policy.proxy_address == invocation.proxy_address
            && policy.implementation_address == invocation.implementation_address
            && policy.code_digest == invocation.code_digest
            && policy.implementation_code_digest == invocation.implementation_code_digest
            && policy.abi_digest == invocation.abi_digest
            && selector == policy.selector
    });
    let selected = matches.next().ok_or(RuntimeError::Denied)?;
    if matches.next().is_some() {
        return Err(RuntimeError::Denied);
    }
    Ok(selected)
}

/// Resolve the immutable contract bindings for a workload-supplied JSON-RPC
/// target and calldata. The caller supplies only request data; chain, code, ABI,
/// proxy and implementation identities always come from the admitted policy.
/// Ambiguous selector/address matches fail closed before a `RuntimeRequest` can
/// be constructed.
pub fn resolve_contract_invocation(
    policies: &[ValidatedInvocationPolicy],
    method: &str,
    target_address: [u8; 20],
    calldata: Vec<u8>,
) -> RuntimeResult<(RequestClass, ContractInvocation)> {
    let class = crate::rpc_policy::request_class(method).ok_or(RuntimeError::Denied)?;
    let selector: [u8; 4] = calldata
        .get(..4)
        .and_then(|value| value.try_into().ok())
        .ok_or(RuntimeError::Denied)?;
    let mut matches = policies.iter().filter(|candidate| {
        let policy = candidate.artifact();
        let exposed_address = policy.proxy_address.unwrap_or(policy.contract_address);
        policy.active
            && !policy.rpc_denied
            && policy.rpc_method == method
            && policy.request_class == class
            && policy.selector == selector
            && exposed_address == target_address
    });
    let policy = matches.next().ok_or(RuntimeError::Denied)?.artifact();
    if matches.next().is_some() {
        return Err(RuntimeError::Denied);
    }
    Ok((class, invocation_from_policy(policy, calldata)))
}

/// Resolve the exact reviewed method reference from installed registrations.
/// `code_at` must read the sealed observation at the same certified anchor;
/// this function checks identity and never performs an implicit provider read.
pub fn resolve_nested_contract_invocation<'a>(
    policies: &'a [ValidatedInvocationPolicy],
    contract_method_policy_id: &str,
    target_address: [u8; 20],
    calldata: Vec<u8>,
    code_at: impl Fn(&[u8; 20]) -> RuntimeResult<Digest>,
) -> RuntimeResult<(&'a ValidatedInvocationPolicy, ContractInvocation)> {
    let mut matches = policies.iter().filter(|policy| {
        policy
            .configured_identity()
            .is_ok_and(|identity| identity.contract_method_policy_id() == contract_method_policy_id)
    });
    let selected = matches.next().ok_or(RuntimeError::Denied)?;
    if matches.next().is_some() {
        return Err(RuntimeError::Denied);
    }
    let policy = selected.artifact();
    if !policy.active
        || policy.method_required_roles.is_none()
        || policy.proxy_address.unwrap_or(policy.contract_address) != target_address
        || calldata.get(..4) != Some(policy.selector.as_slice())
        || code_at(&target_address)? != policy.code_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    if let Some(address) = &policy.implementation_address
        && policy.implementation_code_digest.as_ref() != Some(&code_at(address)?)
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok((selected, invocation_from_policy(policy, calldata)))
}

fn invocation_from_policy(policy: &InvocationPolicy, calldata: Vec<u8>) -> ContractInvocation {
    ContractInvocation {
        chain_id: policy.chain_id.clone(),
        network_id: policy.network_id.clone(),
        genesis_digest: policy.genesis_digest.clone(),
        contract_address: policy.contract_address,
        proxy_address: policy.proxy_address,
        implementation_address: policy.implementation_address,
        code_digest: policy.code_digest.clone(),
        implementation_code_digest: policy.implementation_code_digest.clone(),
        abi_digest: policy.abi_digest.clone(),
        calldata,
        nested_calls: Vec::new(),
    }
}

fn same_dispatch_identity(left: &InvocationPolicy, right: &InvocationPolicy) -> bool {
    left.tenant_id == right.tenant_id
        && left.privacy_domain_id == right.privacy_domain_id
        && left.workload_id == right.workload_id
        && left.policy_generation_digest == right.policy_generation_digest
        && left.rpc_method == right.rpc_method
        && left.request_class == right.request_class
        && left.chain_id == right.chain_id
        && left.network_id == right.network_id
        && left.genesis_digest == right.genesis_digest
        && left.contract_address == right.contract_address
        && left.proxy_address == right.proxy_address
        && left.implementation_address == right.implementation_address
        && left.code_digest == right.code_digest
        && left.implementation_code_digest == right.implementation_code_digest
        && left.abi_digest == right.abi_digest
        && left.selector == right.selector
}

pub fn load_active_configuration_artifact(
    configuration_bytes: &[u8],
    configuration_digest: &Digest,
    artifact_id: &str,
    artifact_kind: ConfigurationArtifactKind,
    artifact_digest: &Digest,
) -> RuntimeResult<Vec<u8>> {
    if artifact_id.is_empty() || *artifact_digest == Digest::of([]) {
        return Err(RuntimeError::InvalidInput);
    }
    let configuration = decode_active_configuration(configuration_bytes, configuration_digest)?;
    let matches = configuration
        .resource_artifacts
        .iter()
        .filter(|artifact| {
            artifact.artifact_id == artifact_id
                && artifact.artifact_kind == artifact_kind
                && artifact.artifact_digest == *artifact_digest
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(matches[0].payload_cbor.clone())
}

/// Resolve the workload of the current single-scope compiled configuration.
/// Runtime target IDs identify custody, and must never substitute for this
/// workload identity. Mixed scopes require separate compiled bundles.
pub fn active_invocation_workload(
    configuration_bytes: &[u8],
    configuration_digest: &Digest,
    participant_id: &str,
    privacy_domain_id: &str,
) -> RuntimeResult<String> {
    let configuration = decode_active_configuration(configuration_bytes, configuration_digest)?;
    let source_context = if configuration.assets.is_empty()
        && configuration.deployment_policies.is_empty()
        && (configuration.workload_scope.is_none()
            || configuration.resource_artifacts.iter().any(|artifact| {
                artifact.artifact_kind == ConfigurationArtifactKind::ClientIndexerProfile
            })) {
        Some(crate::indexer_policy::configuration_context(
            &configuration,
        )?)
    } else {
        None
    };
    let workload = configuration
        .assets
        .first()
        .map(|asset| asset.workload_id.as_str())
        .or_else(|| {
            configuration
                .deployment_policies
                .first()
                .map(|policy| policy.workload_id.as_str())
        })
        .or_else(|| {
            configuration
                .workload_scope
                .as_ref()
                .map(|scope| scope.workload_id.as_str())
        })
        .or_else(|| source_context.as_ref().map(|context| context.2.as_str()))
        .ok_or(RuntimeError::InvalidInput)?;
    if workload.is_empty()
        || source_context.as_ref().is_some_and(|context| {
            context.0 != participant_id || context.1 != privacy_domain_id || context.2 != workload
        })
        || configuration.workload_scope.as_ref().is_some_and(|scope| {
            scope.participant_id != participant_id
                || scope.privacy_domain_id != privacy_domain_id
                || scope.workload_id != workload
        })
        || configuration.assets.iter().any(|asset| {
            asset.workload_id != workload
                || asset.tenant_id != participant_id
                || asset.privacy_domain_id != privacy_domain_id
        })
        || configuration.deployment_policies.iter().any(|policy| {
            policy.workload_id != workload
                || policy.publication.participant_id != participant_id
                || policy.publication.privacy_domain_id != privacy_domain_id
        })
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(workload.to_owned())
}

fn decode_active_configuration(
    configuration_bytes: &[u8],
    configuration_digest: &Digest,
) -> RuntimeResult<ActiveInvocationConfigurationV1> {
    if Digest::of(configuration_bytes) != *configuration_digest {
        return Err(RuntimeError::InvalidInput);
    }
    let configuration: ActiveInvocationConfigurationV1 = decode_exact(configuration_bytes)?;
    if configuration.schema_version != "1.0"
        || (configuration.assets.is_empty()
            && configuration.deployment_policies.is_empty()
            && configuration.visibility_resources.is_empty()
            && !(configuration.workload_scope.is_some()
                && !configuration.resource_artifacts.is_empty()
                && configuration.resource_artifacts.iter().all(|artifact| {
                    artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                }))
            && crate::indexer_policy::configuration_context(&configuration).is_err())
        || configuration.assets.len() > MAX_DECODED_COLLECTION
        || configuration.visibility_resources.len() > MAX_DECODED_COLLECTION
    {
        return Err(RuntimeError::InvalidInput);
    }
    crate::deployment_policy::validate_configuration(&configuration.deployment_policies)?;
    if configuration.workload_scope.as_ref().is_some_and(|scope| {
        [
            &scope.participant_id,
            &scope.privacy_domain_id,
            &scope.workload_id,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 256)
    }) {
        return Err(RuntimeError::InvalidInput);
    }
    unique_by_id(&configuration.assets, |asset| &asset.asset_id)?;
    let mut binding_targets = BTreeMap::new();
    for asset in &configuration.assets {
        configured_identity(asset)?;
        if let Some(binding) = &asset.runtime_binding_id
            && let Some(previous) = binding_targets.insert(binding, asset)
            && !same_configured_target(previous, asset)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    if configuration.resource_artifacts.len() > MAX_DECODED_COLLECTION {
        return Err(RuntimeError::InvalidInput);
    }
    let mut resource_keys = BTreeSet::new();
    for artifact in &configuration.resource_artifacts {
        if artifact.artifact_id.is_empty()
            || artifact.payload_cbor.is_empty()
            || artifact.artifact_digest == Digest::of([])
            || Digest::of(&artifact.payload_cbor) != artifact.artifact_digest
            || !resource_keys.insert((artifact.artifact_kind, artifact.artifact_id.as_str()))
        {
            return Err(RuntimeError::InvalidInput);
        }
        if artifact.artifact_kind == ConfigurationArtifactKind::FactAdmissionProfile {
            crate::fact_profile::StateFactProfile::resolve(&configuration, &artifact.artifact_id)?;
        }
    }
    Ok(configuration)
}

pub fn decode_active_invocation_configuration(
    bytes: &[u8],
    digest: &Digest,
) -> RuntimeResult<ActiveInvocationConfigurationV1> {
    decode_active_configuration(bytes, digest)
}

fn same_configured_target(
    left: &InvocationConfigurationAssetV1,
    right: &InvocationConfigurationAssetV1,
) -> bool {
    left.tenant_id == right.tenant_id
        && left.privacy_domain_id == right.privacy_domain_id
        && left.transaction_policy == right.transaction_policy
        && left.chain_id == right.chain_id
        && left.network_id == right.network_id
        && left.genesis_digest == right.genesis_digest
        && left.contract_address == right.contract_address
        && left.proxy_address == right.proxy_address
        && left.implementation_address == right.implementation_address
        && left.code_digest == right.code_digest
        && left.implementation_code_digest == right.implementation_code_digest
        && left.abi_digest == right.abi_digest
}

pub(crate) fn decode_exact<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> RuntimeResult<T> {
    let mut cursor = Cursor::new(bytes);
    let decoded: T =
        ciborium::de::from_reader(&mut cursor).map_err(|_| RuntimeError::InvalidInput)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(RuntimeError::InvalidInput);
    }
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut canonical).map_err(|_| RuntimeError::InvalidInput)?;
    if canonical != bytes {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(decoded)
}

pub fn encode_active_invocation_configuration(
    value: &ActiveInvocationConfigurationV1,
) -> RuntimeResult<Vec<u8>> {
    encode_exact(value)
}

pub fn encode_active_invocation_policy_generation(
    value: &ActiveInvocationPolicyGenerationV1,
) -> RuntimeResult<Vec<u8>> {
    encode_exact(value)
}

pub fn decode_active_invocation_policy_generation(
    bytes: &[u8],
    digest: &Digest,
) -> RuntimeResult<ActiveInvocationPolicyGenerationV1> {
    if Digest::of(bytes) != *digest {
        return Err(RuntimeError::InvalidInput);
    }
    decode_exact(bytes)
}

pub(crate) fn encode_exact<T: Serialize>(value: &T) -> RuntimeResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_| RuntimeError::InvalidInput)?;
    Ok(bytes)
}

fn unique_by_id<'a, T>(
    values: &'a [T],
    id: impl Fn(&'a T) -> &'a str,
) -> RuntimeResult<BTreeMap<&'a str, &'a T>> {
    let mut by_id = BTreeMap::new();
    for value in values {
        let asset_id = id(value);
        if asset_id.is_empty() || by_id.insert(asset_id, value).is_some() {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(by_id)
}

#[allow(clippy::too_many_arguments)]
fn build_policy(
    asset_id: &str,
    configuration_by_id: &BTreeMap<&str, &InvocationConfigurationAssetV1>,
    policy_by_id: &BTreeMap<&str, &InvocationPolicyAssetV1>,
    policy_artifact_digest: &Digest,
    policy_generation_digest: &Digest,
    tenant_id: &str,
    privacy_domain_id: &str,
    workload_id: &str,
    visiting: &mut BTreeSet<String>,
) -> RuntimeResult<InvocationPolicy> {
    if !visiting.insert(asset_id.to_owned()) {
        return Err(RuntimeError::InvalidInput);
    }
    let configuration = configuration_by_id
        .get(asset_id)
        .copied()
        .ok_or(RuntimeError::InvalidInput)?;
    let policy = policy_by_id
        .get(asset_id)
        .copied()
        .ok_or(RuntimeError::InvalidInput)?;
    if configuration.tenant_id != tenant_id
        || configuration.privacy_domain_id != privacy_domain_id
        || configuration.workload_id != workload_id
    {
        return Err(RuntimeError::InvalidInput);
    }
    let mut nested_policies = Vec::with_capacity(policy.nested_asset_ids.len());
    for nested in &policy.nested_asset_ids {
        nested_policies.push(build_policy(
            nested,
            configuration_by_id,
            policy_by_id,
            policy_artifact_digest,
            policy_generation_digest,
            tenant_id,
            privacy_domain_id,
            workload_id,
            visiting,
        )?);
    }
    visiting.remove(asset_id);
    Ok(InvocationPolicy {
        method_required_roles: policy.method_required_roles.clone(),
        nested_call_set_digest: policy.nested_call_set_digest.clone(),
        rpc_denied: policy.rpc_denied,
        tenant_id: configuration.tenant_id.clone(),
        privacy_domain_id: configuration.privacy_domain_id.clone(),
        workload_id: configuration.workload_id.clone(),
        policy_version: policy.policy_version.clone(),
        policy_artifact_digest: policy_artifact_digest.clone(),
        policy_generation_digest: policy_generation_digest.clone(),
        active: policy.active,
        rpc_method: configuration.rpc_method.clone(),
        request_class: configuration.request_class,
        chain_id: configuration.chain_id.clone(),
        network_id: configuration.network_id.clone(),
        genesis_digest: configuration.genesis_digest.clone(),
        contract_address: configuration.contract_address,
        proxy_address: configuration.proxy_address,
        implementation_address: configuration.implementation_address,
        code_digest: configuration.code_digest.clone(),
        implementation_code_digest: configuration.implementation_code_digest.clone(),
        abi_digest: configuration.abi_digest.clone(),
        canonical_signature: configuration.canonical_signature.clone(),
        selector: configuration.selector,
        input_types: configuration.input_types.clone(),
        required_roles: policy.required_roles.clone(),
        approval: policy.approval,
        webauthn_required: policy.webauthn_required,
        argument_rules: policy.argument_rules.clone(),
        named_sets: configuration.named_sets.clone(),
        nested_policies,
    })
}

impl ValidatedInvocationAuthorization {
    pub fn try_new(facts: InvocationAuthorization) -> RuntimeResult<Self> {
        if facts.participant_id.is_empty()
            || facts.privacy_domain_id.is_empty()
            || facts.workload_id.is_empty()
            || facts.actor_principal_id.is_empty()
            || facts.roles.is_empty()
            || facts.roles.iter().any(String::is_empty)
            || facts.roles.iter().collect::<BTreeSet<_>>().len() != facts.roles.len()
            || facts.approval.as_ref().is_some_and(|approval| {
                approval.approval_id.is_empty()
                    || approval.participant_id != facts.participant_id
                    || approval.privacy_domain_id != facts.privacy_domain_id
                    || approval.maker_principal_id.is_empty()
                    || approval.checker_principal_id.is_empty()
                    || approval.maker_principal_id == approval.checker_principal_id
                    || approval.subject_digest == Digest::of([])
                    || approval.expires_at_ms == 0
            })
            || facts.webauthn.as_ref().is_some_and(|webauthn| {
                webauthn.challenge_id.is_empty()
                    || webauthn.participant_id != facts.participant_id
                    || webauthn.principal_id.is_empty()
                    || webauthn.request_digest == Digest::of([])
                    || webauthn.expires_at_ms == 0
            })
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self { facts })
    }

    pub fn facts(&self) -> &InvocationAuthorization {
        &self.facts
    }
}

fn validate_policy_artifact(
    policy: &InvocationPolicy,
    root: &InvocationPolicy,
    depth: usize,
    selectors: &mut BTreeMap<[u8; 4], String>,
    signatures: &mut BTreeSet<String>,
) -> RuntimeResult<()> {
    if depth > 16
        || !policy.active
        || policy.tenant_id.is_empty()
        || policy.privacy_domain_id.is_empty()
        || policy.workload_id.is_empty()
        || policy.policy_version.is_empty()
        || policy.rpc_method.is_empty()
        || policy.chain_id.is_empty()
        || policy.network_id.is_empty()
        || policy.canonical_signature.is_empty()
        || policy.policy_artifact_digest == Digest::of([])
        || policy.policy_generation_digest == Digest::of([])
        || policy.abi_digest == Digest::of([])
        || policy.code_digest == Digest::of([])
        || policy.tenant_id != root.tenant_id
        || policy.privacy_domain_id != root.privacy_domain_id
        || policy.workload_id != root.workload_id
        || policy.policy_generation_digest != root.policy_generation_digest
        || policy.required_roles.is_empty()
        || policy.required_roles.iter().any(String::is_empty)
        || policy.required_roles.iter().collect::<BTreeSet<_>>().len()
            != policy.required_roles.len()
        || policy.method_required_roles.as_ref().is_some_and(|roles| {
            roles.is_empty()
                || roles.len() > MAX_DECODED_COLLECTION
                || roles
                    .iter()
                    .any(|role| role.is_empty() || !policy.required_roles.contains(role))
                || roles.iter().collect::<BTreeSet<_>>().len() != roles.len()
        })
        || policy.input_types.len() > MAX_DECODED_COLLECTION
        || policy.argument_rules.len() > MAX_DECODED_COLLECTION
        || policy.named_sets.len() > MAX_DECODED_COLLECTION
        || policy.nested_policies.len() > MAX_DECODED_COLLECTION
    {
        return Err(RuntimeError::InvalidInput);
    }
    match selectors.insert(policy.selector, policy.canonical_signature.clone()) {
        Some(existing) if existing != policy.canonical_signature => {
            return Err(RuntimeError::InvalidInput);
        }
        Some(_) => return Err(RuntimeError::InvalidInput),
        None => {}
    }
    if !signatures.insert(policy.canonical_signature.clone()) {
        return Err(RuntimeError::InvalidInput);
    }
    for abi in &policy.input_types {
        validate_abi_type(abi, 0)?;
    }
    let mut set_keys = BTreeSet::new();
    for set in &policy.named_sets {
        if set.owner_id.is_empty()
            || set.set_id.is_empty()
            || set.version.is_empty()
            || set.digest == Digest::of([])
            || set.tenant_id != policy.tenant_id
            || !set.locked
            || set.values.is_empty()
            || set.values.len() > MAX_DECODED_COLLECTION
            || !set_keys.insert((
                set.owner_id.clone(),
                set.set_id.clone(),
                set.version.clone(),
                set.digest.clone(),
            ))
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    let mut rules = BTreeSet::new();
    for rule in &policy.argument_rules {
        let encoded = pc_runtime_types::canonical_bytes(rule)?;
        if !rules.insert(encoded) {
            return Err(RuntimeError::InvalidInput);
        }
        let abi = abi_at_path(&policy.input_types, &rule.path)?;
        let values = match &rule.values {
            RuleValues::Inline(values) => values,
            RuleValues::NamedSet {
                owner_id,
                set_id,
                version,
                digest,
            } => {
                let matches = policy
                    .named_sets
                    .iter()
                    .filter(|set| {
                        set.owner_id == *owner_id
                            && set.set_id == *set_id
                            && set.version == *version
                            && set.digest == *digest
                    })
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(RuntimeError::InvalidInput);
                }
                &matches[0].values
            }
        };
        if values.is_empty()
            || values.len() > MAX_DECODED_COLLECTION
            || values.iter().any(|value| !value_matches_abi(value, abi))
            || values
                .iter()
                .map(pc_runtime_types::canonical_bytes)
                .collect::<RuntimeResult<BTreeSet<_>>>()?
                .len()
                != values.len()
            || matches!(
                rule.comparator,
                Comparator::Lt | Comparator::Lte | Comparator::Gt | Comparator::Gte
            ) && !matches!(abi, AbiType::Uint(_) | AbiType::Int(_))
            || !matches!(rule.comparator, Comparator::In) && values.len() != 1
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    for nested in &policy.nested_policies {
        validate_policy_artifact(nested, root, depth + 1, selectors, signatures)?;
    }
    Ok(())
}

pub(crate) fn validate_abi_type(abi: &AbiType, depth: usize) -> RuntimeResult<()> {
    if depth > 16 {
        return Err(RuntimeError::InvalidInput);
    }
    match abi {
        AbiType::Uint(bits) | AbiType::Int(bits) => validate_width(*bits),
        AbiType::FixedBytes(length) if (1..=32).contains(length) => Ok(()),
        AbiType::FixedBytes(_) => Err(RuntimeError::InvalidInput),
        AbiType::Array { element, length } => {
            if length.is_some_and(|value| value == 0 || value > MAX_DECODED_COLLECTION) {
                return Err(RuntimeError::InvalidInput);
            }
            validate_abi_type(element, depth + 1)
        }
        AbiType::Tuple(fields) => {
            if fields.is_empty() || fields.len() > MAX_DECODED_COLLECTION {
                return Err(RuntimeError::InvalidInput);
            }
            fields
                .iter()
                .try_for_each(|field| validate_abi_type(field, depth + 1))
        }
        AbiType::Address | AbiType::Bool | AbiType::Bytes | AbiType::String => Ok(()),
    }
}

pub(crate) fn abi_at_path<'a>(
    types: &'a [AbiType],
    path: &[PathSegment],
) -> RuntimeResult<&'a AbiType> {
    let (PathSegment::Input(index), tail) = path.split_first().ok_or(RuntimeError::InvalidInput)?
    else {
        return Err(RuntimeError::InvalidInput);
    };
    let mut current = types.get(*index).ok_or(RuntimeError::InvalidInput)?;
    for segment in tail {
        current = match (segment, current) {
            (PathSegment::Field(index), AbiType::Tuple(fields)) => {
                fields.get(*index).ok_or(RuntimeError::InvalidInput)?
            }
            (PathSegment::Index(index), AbiType::Array { element, length })
                if length.is_none_or(|bound| *index < bound) =>
            {
                element
            }
            _ => return Err(RuntimeError::InvalidInput),
        };
    }
    Ok(current)
}

pub(crate) fn value_matches_abi(value: &ArgumentValue, abi: &AbiType) -> bool {
    match (value, abi) {
        (ArgumentValue::Address(_), AbiType::Address)
        | (ArgumentValue::Bool(_), AbiType::Bool)
        | (ArgumentValue::String(_), AbiType::String) => true,
        (ArgumentValue::Uint(value), AbiType::Uint(bits)) => {
            validate_width(*bits).is_ok()
                && !leading_bits_nonzero(value, 256 - usize::from(*bits), false)
        }
        (ArgumentValue::Int(value), AbiType::Int(bits)) => {
            validate_width(*bits).is_ok()
                && !leading_bits_nonzero(
                    value,
                    256 - usize::from(*bits),
                    bit(value, 256 - usize::from(*bits)),
                )
        }
        (ArgumentValue::Bytes(value), AbiType::FixedBytes(length)) => {
            value.len() == usize::from(*length)
        }
        (ArgumentValue::Bytes(value), AbiType::Bytes) => {
            value.len() <= MAX_DECODED_COLLECTION * WORD
        }
        (ArgumentValue::Array(values), AbiType::Array { element, length }) => {
            length.is_none_or(|expected| values.len() == expected)
                && values.len() <= MAX_DECODED_COLLECTION
                && values.iter().all(|value| value_matches_abi(value, element))
        }
        (ArgumentValue::Tuple(values), AbiType::Tuple(fields)) => {
            values.len() == fields.len()
                && values
                    .iter()
                    .zip(fields)
                    .all(|(value, field)| value_matches_abi(value, field))
        }
        _ => false,
    }
}

pub struct InvocationEvaluation<'a> {
    pub request_method: &'a str,
    pub request_class: RequestClass,
    pub request_digest: &'a Digest,
    pub active_policy_generation: &'a Digest,
    pub now_ms: u64,
}

pub fn evaluate_invocation(
    invocation: &ContractInvocation,
    policy: &ValidatedInvocationPolicy,
    authorization: &ValidatedInvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
) -> RuntimeResult<()> {
    if policy.artifact().rpc_denied {
        return Err(RuntimeError::Denied);
    }
    evaluate_invocation_conditions(invocation, policy, authorization, evaluation)
}

/// Denial provenance uses the same checks as live invocation evaluation. It
/// supplies no permission and never changes the terminal RPC denial result.
pub(crate) fn complete_explicit_rpc_denial(
    invocation: &ContractInvocation,
    policy: &ValidatedInvocationPolicy,
    authorization: &ValidatedInvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
) -> bool {
    policy.artifact().rpc_denied
        && evaluate_invocation_conditions(invocation, policy, authorization, evaluation).is_ok()
}

fn evaluate_invocation_conditions(
    invocation: &ContractInvocation,
    policy: &ValidatedInvocationPolicy,
    authorization: &ValidatedInvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
) -> RuntimeResult<()> {
    let policy = policy.artifact();
    let authorization = authorization.facts();
    if !policy.active
        || policy.policy_version.is_empty()
        || policy.canonical_signature.is_empty()
        || policy.policy_artifact_digest == Digest::of([])
        || &policy.policy_generation_digest != evaluation.active_policy_generation
        || policy.rpc_method != evaluation.request_method
        || policy.request_class != evaluation.request_class
        || policy.tenant_id != authorization.participant_id
        || policy.privacy_domain_id != authorization.privacy_domain_id
        || policy.workload_id != authorization.workload_id
        || policy.required_roles.is_empty()
        || policy
            .required_roles
            .iter()
            .any(|required| !authorization.roles.contains(required))
    {
        return Err(RuntimeError::Denied);
    }
    exact_contract_binding(invocation, policy)?;
    let decoded = decode_call(invocation, policy)?;
    for rule in &policy.argument_rules {
        evaluate_rule(rule, &decoded, &policy.named_sets, &policy.tenant_id)?;
    }
    if invocation.nested_calls.len() != policy.nested_policies.len() {
        return Err(RuntimeError::Denied);
    }
    for (nested, nested_policy) in invocation.nested_calls.iter().zip(&policy.nested_policies) {
        evaluate_invocation_artifact(nested, nested_policy, authorization, evaluation)?;
    }
    match policy.approval {
        ApprovalRequirement::None => {}
        ApprovalRequirement::Single | ApprovalRequirement::MakerChecker => {
            let approval = authorization
                .approval
                .as_ref()
                .ok_or(RuntimeError::Denied)?;
            if approval.participant_id != authorization.participant_id
                || approval.privacy_domain_id != authorization.privacy_domain_id
                || approval.subject_digest != *evaluation.request_digest
                || approval.expires_at_ms <= evaluation.now_ms
                || approval.maker_principal_id == approval.checker_principal_id
                || (policy.approval == ApprovalRequirement::MakerChecker
                    && approval.maker_principal_id != authorization.actor_principal_id)
            {
                return Err(RuntimeError::Denied);
            }
        }
    }
    if policy.webauthn_required {
        let fact = authorization
            .webauthn
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        if fact.participant_id != authorization.participant_id
            || fact.principal_id != authorization.actor_principal_id
            || fact.request_digest != *evaluation.request_digest
            || fact.expires_at_ms <= evaluation.now_ms
        {
            return Err(RuntimeError::Denied);
        }
    }
    Ok(())
}

/// Internal CIGL method constraints from an installed registration. The root
/// request still needs its own RPC/capability decision, and each actual nested
/// frame needs a current CIGL grant. This never authorizes public result access.
pub fn evaluate_nested_contract_method(
    invocation: &ContractInvocation,
    policy: &ValidatedInvocationPolicy,
    authorization: &ValidatedInvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
) -> RuntimeResult<()> {
    policy.configured_identity()?;
    if !invocation.nested_calls.is_empty() || !policy.artifact.nested_policies.is_empty() {
        // Preserve the old positional graph meaning. The CIGL owner evaluates
        // its trusted dynamic frames individually with this entry point.
        return Err(RuntimeError::Denied);
    }
    evaluate_method_constraints(
        invocation,
        policy.artifact(),
        authorization.facts(),
        evaluation,
        MethodSurface::InternalCigl,
    )
}

#[derive(Clone, Copy)]
enum MethodSurface {
    PublicRpc,
    InternalCigl,
}

fn evaluate_invocation_artifact(
    invocation: &ContractInvocation,
    policy: &InvocationPolicy,
    authorization: &InvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
) -> RuntimeResult<()> {
    evaluate_method_constraints(
        invocation,
        policy,
        authorization,
        evaluation,
        MethodSurface::PublicRpc,
    )
}

fn evaluate_method_constraints(
    invocation: &ContractInvocation,
    policy: &InvocationPolicy,
    authorization: &InvocationAuthorization,
    evaluation: &InvocationEvaluation<'_>,
    surface: MethodSurface,
) -> RuntimeResult<()> {
    let required_roles = match surface {
        MethodSurface::PublicRpc => {
            if policy.rpc_denied
                || policy.rpc_method != evaluation.request_method
                || policy.request_class != evaluation.request_class
            {
                return Err(RuntimeError::Denied);
            }
            &policy.required_roles
        }
        MethodSurface::InternalCigl => policy
            .method_required_roles
            .as_ref()
            .ok_or(RuntimeError::Denied)?,
    };
    if !policy.active
        || &policy.policy_generation_digest != evaluation.active_policy_generation
        || policy.tenant_id != authorization.participant_id
        || policy.privacy_domain_id != authorization.privacy_domain_id
        || policy.workload_id != authorization.workload_id
        || required_roles
            .iter()
            .any(|required| !authorization.roles.contains(required))
    {
        return Err(RuntimeError::Denied);
    }
    exact_contract_binding(invocation, policy)?;
    let decoded = decode_call(invocation, policy)?;
    for rule in &policy.argument_rules {
        evaluate_rule(rule, &decoded, &policy.named_sets, &policy.tenant_id)?;
    }
    if invocation.nested_calls.len() != policy.nested_policies.len() {
        return Err(RuntimeError::Denied);
    }
    for (nested, nested_policy) in invocation.nested_calls.iter().zip(&policy.nested_policies) {
        evaluate_invocation_artifact(nested, nested_policy, authorization, evaluation)?;
    }
    match policy.approval {
        ApprovalRequirement::None => {}
        ApprovalRequirement::Single | ApprovalRequirement::MakerChecker => {
            let approval = authorization
                .approval
                .as_ref()
                .ok_or(RuntimeError::Denied)?;
            if approval.participant_id != authorization.participant_id
                || approval.privacy_domain_id != authorization.privacy_domain_id
                || approval.subject_digest != *evaluation.request_digest
                || approval.expires_at_ms <= evaluation.now_ms
                || approval.maker_principal_id == approval.checker_principal_id
                || (policy.approval == ApprovalRequirement::MakerChecker
                    && approval.maker_principal_id != authorization.actor_principal_id)
            {
                return Err(RuntimeError::Denied);
            }
        }
    }
    if policy.webauthn_required {
        let fact = authorization
            .webauthn
            .as_ref()
            .ok_or(RuntimeError::Denied)?;
        if fact.participant_id != authorization.participant_id
            || fact.principal_id != authorization.actor_principal_id
            || fact.request_digest != *evaluation.request_digest
            || fact.expires_at_ms <= evaluation.now_ms
        {
            return Err(RuntimeError::Denied);
        }
    }
    Ok(())
}

fn exact_contract_binding(
    invocation: &ContractInvocation,
    policy: &InvocationPolicy,
) -> RuntimeResult<()> {
    if invocation.chain_id != policy.chain_id
        || invocation.network_id != policy.network_id
        || invocation.genesis_digest != policy.genesis_digest
        || invocation.contract_address != policy.contract_address
        || invocation.proxy_address != policy.proxy_address
        || invocation.implementation_address != policy.implementation_address
        || invocation.code_digest != policy.code_digest
        || invocation.implementation_code_digest != policy.implementation_code_digest
        || invocation.abi_digest != policy.abi_digest
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(())
}

pub(crate) fn decode_call(
    invocation: &ContractInvocation,
    policy: &InvocationPolicy,
) -> RuntimeResult<Vec<ArgumentValue>> {
    if invocation.calldata.len() < 4 || invocation.calldata[..4] != policy.selector {
        return Err(RuntimeError::Denied);
    }
    decode_sequence(&policy.input_types, &invocation.calldata[4..], 0)
}

fn is_dynamic(abi: &AbiType) -> bool {
    match abi {
        AbiType::Bytes | AbiType::String | AbiType::Array { length: None, .. } => true,
        AbiType::Array {
            element,
            length: Some(_),
        } => is_dynamic(element),
        AbiType::Tuple(fields) => fields.iter().any(is_dynamic),
        _ => false,
    }
}

fn static_size(abi: &AbiType) -> RuntimeResult<usize> {
    match abi {
        AbiType::Array {
            element,
            length: Some(length),
        } if !is_dynamic(element) => static_size(element)?
            .checked_mul(*length)
            .ok_or(RuntimeError::InvalidInput),
        AbiType::Tuple(fields) if !fields.iter().any(is_dynamic) => {
            fields.iter().try_fold(0_usize, |sum, field| {
                sum.checked_add(static_size(field)?)
                    .ok_or(RuntimeError::InvalidInput)
            })
        }
        abi if !is_dynamic(abi) => Ok(WORD),
        _ => Err(RuntimeError::InvalidInput),
    }
}

fn word(data: &[u8], offset: usize) -> RuntimeResult<&[u8]> {
    data.get(offset..offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)?)
        .ok_or(RuntimeError::InvalidInput)
}

fn usize_word(data: &[u8], offset: usize) -> RuntimeResult<usize> {
    let value = word(data, offset)?;
    if value[..WORD - size_of::<usize>()]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(RuntimeError::InvalidInput);
    }
    let mut bytes = [0_u8; size_of::<usize>()];
    bytes.copy_from_slice(&value[WORD - size_of::<usize>()..]);
    Ok(usize::from_be_bytes(bytes))
}

fn decode_sequence(
    types: &[AbiType],
    data: &[u8],
    base: usize,
) -> RuntimeResult<Vec<ArgumentValue>> {
    if types.len() > MAX_DECODED_COLLECTION {
        return Err(RuntimeError::InvalidInput);
    }
    let mut head = base;
    let mut values = Vec::with_capacity(types.len());
    for abi in types {
        let value = if is_dynamic(abi) {
            let relative = usize_word(data, head)?;
            decode_value(
                abi,
                data,
                base.checked_add(relative)
                    .ok_or(RuntimeError::InvalidInput)?,
            )?
        } else {
            decode_value(abi, data, head)?
        };
        head = head
            .checked_add(if is_dynamic(abi) {
                WORD
            } else {
                static_size(abi)?
            })
            .ok_or(RuntimeError::InvalidInput)?;
        values.push(value);
    }
    Ok(values)
}

fn decode_value(abi: &AbiType, data: &[u8], offset: usize) -> RuntimeResult<ArgumentValue> {
    match abi {
        AbiType::Address => {
            let value = word(data, offset)?;
            if value[..12].iter().any(|byte| *byte != 0) {
                return Err(RuntimeError::InvalidInput);
            }
            let mut address = [0_u8; 20];
            address.copy_from_slice(&value[12..]);
            Ok(ArgumentValue::Address(address))
        }
        AbiType::Bool => match word(data, offset)? {
            value if value[..31].iter().all(|byte| *byte == 0) && value[31] <= 1 => {
                Ok(ArgumentValue::Bool(value[31] == 1))
            }
            _ => Err(RuntimeError::InvalidInput),
        },
        AbiType::Uint(bits) => {
            validate_width(*bits)?;
            let mut value = [0_u8; WORD];
            value.copy_from_slice(word(data, offset)?);
            let unused = 256_usize - usize::from(*bits);
            if unused > 0 && leading_bits_nonzero(&value, unused, false) {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(ArgumentValue::Uint(value))
        }
        AbiType::Int(bits) => {
            validate_width(*bits)?;
            let mut value = [0_u8; WORD];
            value.copy_from_slice(word(data, offset)?);
            let unused = 256_usize - usize::from(*bits);
            let negative = bit(&value, unused);
            if unused > 0 && leading_bits_nonzero(&value, unused, negative) {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(ArgumentValue::Int(value))
        }
        AbiType::FixedBytes(length) if (1..=32).contains(length) => {
            let value = word(data, offset)?;
            let length = usize::from(*length);
            if value[length..].iter().any(|byte| *byte != 0) {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(ArgumentValue::Bytes(value[..length].to_vec()))
        }
        AbiType::Bytes | AbiType::String => {
            let length = usize_word(data, offset)?;
            if length > MAX_DECODED_COLLECTION * WORD {
                return Err(RuntimeError::InvalidInput);
            }
            let start = offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)?;
            let bytes = data
                .get(
                    start
                        ..start
                            .checked_add(length)
                            .ok_or(RuntimeError::InvalidInput)?,
                )
                .ok_or(RuntimeError::InvalidInput)?
                .to_vec();
            if matches!(abi, AbiType::String) {
                String::from_utf8(bytes)
                    .map(ArgumentValue::String)
                    .map_err(|_| RuntimeError::InvalidInput)
            } else {
                Ok(ArgumentValue::Bytes(bytes))
            }
        }
        AbiType::Array { element, length } => {
            let (count, elements_base) = if let Some(count) = length {
                (*count, offset)
            } else {
                (
                    usize_word(data, offset)?,
                    offset.checked_add(WORD).ok_or(RuntimeError::InvalidInput)?,
                )
            };
            if count > MAX_DECODED_COLLECTION {
                return Err(RuntimeError::InvalidInput);
            }
            let types = vec![(**element).clone(); count];
            decode_sequence(&types, data, elements_base).map(ArgumentValue::Array)
        }
        AbiType::Tuple(fields) => decode_sequence(fields, data, offset).map(ArgumentValue::Tuple),
        AbiType::FixedBytes(_) => Err(RuntimeError::InvalidInput),
    }
}

fn validate_width(bits: u16) -> RuntimeResult<()> {
    if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}

fn bit(value: &[u8; WORD], index: usize) -> bool {
    let byte = index / 8;
    let shift = 7 - index % 8;
    value[byte] & (1 << shift) != 0
}

fn leading_bits_nonzero(value: &[u8; WORD], count: usize, expected: bool) -> bool {
    (0..count).any(|index| bit(value, index) != expected)
}

pub(crate) fn value_at<'a>(
    values: &'a [ArgumentValue],
    path: &[PathSegment],
) -> RuntimeResult<&'a ArgumentValue> {
    let (PathSegment::Input(index), tail) = path.split_first().ok_or(RuntimeError::Denied)? else {
        return Err(RuntimeError::Denied);
    };
    let mut current = values.get(*index).ok_or(RuntimeError::Denied)?;
    for segment in tail {
        current = match (segment, current) {
            (PathSegment::Field(index), ArgumentValue::Tuple(fields))
            | (PathSegment::Index(index), ArgumentValue::Array(fields)) => {
                fields.get(*index).ok_or(RuntimeError::Denied)?
            }
            _ => return Err(RuntimeError::Denied),
        };
    }
    Ok(current)
}

fn evaluate_rule(
    rule: &ArgumentRule,
    decoded: &[ArgumentValue],
    named_sets: &[NamedSet],
    tenant_id: &str,
) -> RuntimeResult<()> {
    let actual = value_at(decoded, &rule.path)?;
    let expected = match &rule.values {
        RuleValues::Inline(values) => values,
        RuleValues::NamedSet {
            owner_id,
            set_id,
            version,
            digest,
        } => {
            let mut matching = named_sets.iter().filter(|set| {
                set.owner_id == *owner_id
                    && set.set_id == *set_id
                    && set.version == *version
                    && set.digest == *digest
                    && set.tenant_id == tenant_id
                    && set.locked
            });
            let set = matching.next().ok_or(RuntimeError::Denied)?;
            if matching.next().is_some() {
                return Err(RuntimeError::Denied);
            }
            &set.values
        }
    };
    let allowed = match rule.comparator {
        Comparator::Eq => expected.len() == 1 && actual == &expected[0],
        Comparator::In => !expected.is_empty() && expected.contains(actual),
        Comparator::Lt | Comparator::Lte | Comparator::Gt | Comparator::Gte => {
            if expected.len() != 1 {
                false
            } else {
                let ordering = numeric_cmp(actual, &expected[0]);
                matches!(
                    (rule.comparator, ordering),
                    (Comparator::Lt, Some(Ordering::Less))
                        | (Comparator::Lte, Some(Ordering::Less | Ordering::Equal))
                        | (Comparator::Gt, Some(Ordering::Greater))
                        | (Comparator::Gte, Some(Ordering::Greater | Ordering::Equal))
                )
            }
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(RuntimeError::Denied)
    }
}

pub(crate) fn numeric_cmp(left: &ArgumentValue, right: &ArgumentValue) -> Option<Ordering> {
    match (left, right) {
        (ArgumentValue::Uint(left), ArgumentValue::Uint(right)) => Some(left.cmp(right)),
        (ArgumentValue::Int(left), ArgumentValue::Int(right)) => {
            let left_negative = left[0] & 0x80 != 0;
            let right_negative = right[0] & 0x80 != 0;
            Some(match (left_negative, right_negative) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => left.cmp(right),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod provider_only_configuration_tests {
    use super::*;

    fn fixture() -> ActiveInvocationConfigurationV1 {
        let payload = vec![0xa0];
        ActiveInvocationConfigurationV1 {
            schema_version: "1.0".into(),
            workload_scope: Some(InvocationConfigurationScope {
                participant_id: "participant".into(),
                privacy_domain_id: "privacy".into(),
                workload_id: "workload".into(),
            }),
            assets: vec![],
            deployment_policies: vec![],
            visibility_resources: vec![],
            resource_artifacts: vec![ConfigurationArtifactV1 {
                artifact_id: "provider".into(),
                artifact_kind: ConfigurationArtifactKind::ProviderProfile,
                artifact_digest: Digest::of(&payload),
                payload_cbor: payload,
            }],
        }
    }

    fn bytes(value: &ActiveInvocationConfigurationV1) -> (Vec<u8>, Digest) {
        let bytes = encode_active_invocation_configuration(value).unwrap();
        let digest = Digest::of(&bytes);
        (bytes, digest)
    }

    #[test]
    fn scoped_provider_only_input_has_a_workload_without_granting_an_operation() {
        let value = fixture();
        let (bytes, digest) = bytes(&value);
        let decoded = decode_active_invocation_configuration(&bytes, &digest).unwrap();
        assert!(decoded.assets.is_empty());
        assert!(decoded.deployment_policies.is_empty());
        assert!(decoded.visibility_resources.is_empty());
        assert_eq!(
            active_invocation_workload(&bytes, &digest, "participant", "privacy").unwrap(),
            "workload"
        );
        assert!(active_invocation_workload(&bytes, &digest, "foreign", "privacy").is_err());
        assert!(active_invocation_workload(&bytes, &digest, "participant", "foreign").is_err());
    }

    #[test]
    fn provider_only_input_requires_scope_and_a_nonempty_provider_set() {
        for variant in 0..4 {
            let mut value = fixture();
            match variant {
                0 => value.workload_scope = None,
                1 => value.workload_scope.as_mut().unwrap().workload_id.clear(),
                2 => value.resource_artifacts.clear(),
                _ => {
                    value.resource_artifacts[0].artifact_kind =
                        ConfigurationArtifactKind::CiglProfile
                }
            }
            let (bytes, digest) = bytes(&value);
            assert!(decode_active_invocation_configuration(&bytes, &digest).is_err());
        }
    }

    #[test]
    fn provider_only_input_preserves_digest_and_artifact_validation() {
        let mut value = fixture();
        let (bytes, _) = bytes(&value);
        assert!(decode_active_invocation_configuration(&bytes, &Digest::of(b"wrong")).is_err());
        value.resource_artifacts[0].payload_cbor.push(0);
        let (bytes, digest) = self::bytes(&value);
        assert!(decode_active_invocation_configuration(&bytes, &digest).is_err());
        value.resource_artifacts[0].artifact_digest =
            Digest::of(&value.resource_artifacts[0].payload_cbor);
        value
            .resource_artifacts
            .push(value.resource_artifacts[0].clone());
        let (bytes, digest) = self::bytes(&value);
        assert!(decode_active_invocation_configuration(&bytes, &digest).is_err());
    }
}
