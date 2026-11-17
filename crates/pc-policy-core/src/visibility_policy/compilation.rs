use super::*;
use crate::{
    contract_policy::{AdmittedContractPolicy, read_method_types},
    invocation::{
        ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1, ActiveInvocationScope,
    },
    semantics::PolicySemanticDocument,
};

/// A scoped projection resolved by the configuration owner, never a public
/// policy-authoring field. The selector includes the exact immutable source
/// identity; available fields come from its admitted ABI or export profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedVisibilityResource {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub selector: VisibilitySelector,
    pub available_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_binding: Option<VisibilityContractBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_output_types: Option<Vec<crate::invocation::AbiType>>,
}

/// The configuration owner resolves these bytes from the exact bound contract
/// revision. A policy author can reference that revision, not provide its code,
/// chain or ABI. Older simulation-only snapshots remain readable; runtime reads
/// require this binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VisibilityContractBinding {
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: String,
    pub contract_address: String,
    pub code_digest: String,
    pub abi_digest: String,
    pub canonical_abi: serde_json::Value,
}

impl VisibilityContractBinding {
    pub fn digest(&self) -> RuntimeResult<pc_runtime_types::Digest> {
        let address = self
            .contract_address
            .strip_prefix("0x")
            .ok_or(RuntimeError::InvalidInput)?;
        if self.chain_id.parse::<u64>().is_err()
            || self.network_id.is_empty()
            || address.len() != 40
            || !address.bytes().all(|b| b.is_ascii_hexdigit())
            || !digest(&self.genesis_digest)
            || !digest(&self.code_digest)
            || !digest(&self.abi_digest)
            || !self.canonical_abi.is_array()
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_runtime_types::Digest::of(crate::pc_cbor_1(self)))
    }
}

pub(crate) fn compile_resources(
    document: &PolicySemanticDocument,
    contracts: &[AdmittedContractPolicy],
    admitted: &[AdmittedVisibilityResource],
) -> Result<Vec<AdmittedVisibilityResource>, String> {
    let invalid = || "visibility resource binding rejected".to_owned();
    let mut resources = Vec::new();
    let mut used = BTreeSet::new();
    for policy in &document.visibility_policies {
        if resources
            .iter()
            .any(|resource: &AdmittedVisibilityResource| resource.selector == policy.selector)
        {
            continue;
        }
        let resource = if let VisibilitySelector::StateRead {
            contract_method_policy_id,
            revision,
        } = &policy.selector
        {
            let contract = contracts
                .iter()
                .find(|contract| {
                    contract.asset_id == *contract_method_policy_id
                        && contract.policy_version == *revision
                        && contract.effect == "READ"
                })
                .ok_or_else(invalid)?;
            let selector = contract
                .selector
                .strip_prefix("0x")
                .filter(|value| value.len() == 8)
                .ok_or_else(invalid)?;
            let mut bytes = [0; 4];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16)
                    .map_err(|_| invalid())?;
            }
            let (_, outputs) = read_method_types(
                &contract.canonical_abi,
                &contract.canonical_signature,
                &bytes,
            )?;
            AdmittedVisibilityResource {
                state_output_types: Some(outputs.clone()),
                contract_binding: None,
                participant_id: contract.tenant_id.clone(),
                privacy_domain_id: contract.privacy_domain_id.clone(),
                selector: policy.selector.clone(),
                available_fields: (0..outputs.len())
                    .map(|index| format!("outputs[{index}]"))
                    .collect(),
            }
        } else {
            let matching = admitted
                .iter()
                .enumerate()
                .filter(|(_, resource)| resource.selector == policy.selector)
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(invalid());
            }
            used.insert(matching[0].0);
            matching[0].1.clone()
        };
        resources.push(resource);
    }
    if used.len() != admitted.len() {
        return Err(invalid());
    }
    validate_resource_bindings(
        &resources,
        &document.visibility_policies,
        &document.participant_id,
        &document.privacy_domain_id,
    )
    .map_err(|_| invalid())?;
    resources.sort_by_key(|resource| crate::pc_cbor_1(&resource.selector));
    Ok(resources)
}

fn validate_resource_bindings(
    resources: &[AdmittedVisibilityResource],
    policies: &[VisibilityPolicy],
    participant: &str,
    privacy: &str,
) -> RuntimeResult<()> {
    if resources.len() > 256 || policies.len() > 256 {
        return Err(RuntimeError::InvalidInput);
    }
    let mut selectors = BTreeSet::new();
    for resource in resources {
        if let Some(outputs) = &resource.state_output_types {
            if !matches!(resource.selector, VisibilitySelector::StateRead { .. })
                || outputs.len() > 64
                || resource.available_fields
                    != (0..outputs.len())
                        .map(|index| format!("outputs[{index}]"))
                        .collect::<Vec<_>>()
            {
                return Err(RuntimeError::InvalidInput);
            }
            for output in outputs {
                crate::invocation::validate_abi_type(output, 0)?;
            }
        }
        if let Some(binding) = &resource.contract_binding {
            binding.digest()?;
            if matches!(&resource.selector, VisibilitySelector::Event { abi_digest, .. } if abi_digest != &binding.abi_digest)
                || matches!(
                    &resource.selector,
                    VisibilitySelector::Disclosure { .. } | VisibilitySelector::StateRead { .. }
                )
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if resource.participant_id != participant
            || resource.privacy_domain_id != privacy
            || !resource.selector.validate()
            || !unique_labels(&resource.available_fields, 64)
            || !selectors.insert(crate::pc_cbor_1(&resource.selector))
            || !policies
                .iter()
                .any(|policy| policy.selector == resource.selector)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    for policy in policies {
        let resource = resources
            .iter()
            .find(|resource| resource.selector == policy.selector)
            .ok_or(RuntimeError::InvalidInput)?;
        if !policy
            .fields
            .iter()
            .all(|field| resource.available_fields.contains(field))
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    Ok(())
}

pub fn validate_resources(
    configuration: &ActiveInvocationConfigurationV1,
    generation: &ActiveInvocationPolicyGenerationV1,
    scope: &ActiveInvocationScope<'_>,
) -> RuntimeResult<()> {
    for policy in &generation.visibility_policies {
        policy.validate(&generation.required_facts)?;
    }
    validate_resource_bindings(
        &configuration.visibility_resources,
        &generation.visibility_policies,
        scope.tenant_id,
        scope.privacy_domain_id,
    )
}

pub(crate) use compile_resources as compile;
