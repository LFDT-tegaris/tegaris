//! Reviewed method-interaction profiles selected through the existing active
//! configuration/policy artifacts. Review completion belongs to the public
//! analysis/profile owner; a structurally valid document does not establish it.
use super::program::{CiglProgramV1, ValidatedCiglProgram};
use super::{CallKind, TraceLimits, grants::InteractionGrantSet};
use crate::invocation::{
    ActiveInvocationScope, ConfigurationArtifactKind, ValidatedInvocationPolicy,
    decode_active_invocation_configuration, decode_exact, encode_exact,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub mod publication;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CallerConstraint {
    RootExecution {},
    Exact { address: [u8; 20] },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodInteractionRule {
    pub interaction_id: String,
    pub caller: CallerConstraint,
    pub call_kind: CallKind,
    pub contract_method_policy_id: String,
    /// EVM msg.value, including inherited delegate value. Actual transfer is
    /// separately classified; this does not duplicate Native Value custody.
    pub maximum_value: [u8; 32],
}

/// The method-readiness branch. Deployment creation and reviewed special
/// classifications need their own admitted rules before they can be authorized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodProfileDefinition {
    pub schema_version: String,
    pub profile_id: String,
    pub revision: u64,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub root_contract_method_policy_id: String,
    pub analysis_digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<CiglProgramV1>,
    pub limits: TraceLimits,
    pub interactions: Vec<MethodInteractionRule>,
}
impl MethodProfileDefinition {
    pub fn validate(&self) -> RuntimeResult<()> {
        self.limits.validate()?;
        if self.schema_version != "1.0"
            || self.revision == 0
            || [
                &self.profile_id,
                &self.participant_id,
                &self.privacy_domain_id,
                &self.root_contract_method_policy_id,
            ]
            .into_iter()
            .any(|id| !crate::semantics::uuid_v7(id))
            || self.analysis_digest == Digest::of([])
            || self.interactions.len() > 2048
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut ids = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for rule in &self.interactions {
            if rule.interaction_id.is_empty()
                || rule.interaction_id.len() > 256
                || !rule.interaction_id.bytes().all(|b| b.is_ascii_graphic())
                || !ids.insert(&rule.interaction_id)
                || !crate::semantics::uuid_v7(&rule.contract_method_policy_id)
                || !matches!(
                    rule.call_kind,
                    CallKind::Call
                        | CallKind::Staticcall
                        | CallKind::Delegatecall
                        | CallKind::Callcode
                )
                || (rule.call_kind == CallKind::Staticcall && rule.maximum_value != [0; 32])
                || !identities.insert(canonical_bytes(&(
                    &rule.caller,
                    rule.call_kind,
                    &rule.contract_method_policy_id,
                ))?)
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.validate()?;
        canonical_bytes(&serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?)
            .map(Digest::of)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfiguredMethodProfile {
    pub definition: MethodProfileDefinition,
    pub grants: InteractionGrantSet,
}
impl ConfiguredMethodProfile {
    pub fn from_cbor(bytes: &[u8]) -> RuntimeResult<Self> {
        let configured: Self = decode_exact(bytes)?;
        configured.validate()?;
        Ok(configured)
    }

    pub fn validate(&self) -> RuntimeResult<()> {
        self.definition.validate()?;
        self.grants.validate()?;
        if self.grants.profile_id != self.definition.profile_id
            || self.grants.profile_revision != self.definition.revision
            || self.grants.profile_digest != self.definition.digest()?
            || self.grants.participant_id != self.definition.participant_id
            || self.grants.privacy_domain_id != self.definition.privacy_domain_id
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }
    pub fn to_cbor(&self) -> RuntimeResult<Vec<u8>> {
        self.validate()?;
        encode_exact(self)
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedMethodProfile {
    configured: ConfiguredMethodProfile,
    configuration_digest: Digest,
    policy_artifact_digest: Digest,
    policy_generation_digest: Digest,
    workload_id: String,
    // Share immutable registrations across profiles from the same installation.
    // Evaluation cannot substitute a different policy set under the same IDs.
    methods: Arc<BTreeMap<String, ValidatedInvocationPolicy>>,
    rules_by_call: BTreeMap<ReviewedCall, usize>,
    program: Option<ValidatedCiglProgram>,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReviewedCall {
    caller: [u8; 20],
    kind: CallKind,
    target: [u8; 20],
    selector: [u8; 4],
}
impl ValidatedMethodProfile {
    pub fn program(&self) -> Option<&ValidatedCiglProgram> {
        self.program.as_ref()
    }
    pub fn source_digests(&self) -> (&Digest, &Digest) {
        (&self.configuration_digest, &self.policy_artifact_digest)
    }
    /// An opaque reference is never permission to skip CIGL. Legacy methods
    /// with no reference, including the public canonical empty nested-call set,
    /// retain their existing behavior until governed settings require an admitted
    /// profile for those methods too. An empty set is not a reviewed profile.
    pub fn select<'a>(
        profiles: &'a [Self],
        method: &ValidatedInvocationPolicy,
    ) -> RuntimeResult<Option<&'a Self>> {
        let Some(expected) = method
            .artifact()
            .nested_call_set_digest
            .as_ref()
            .filter(|digest| **digest != Digest::of([]) && **digest != Digest::of(b"[]"))
        else {
            return Ok(None);
        };
        let id = method.configured_identity()?.contract_method_policy_id();
        let mut matching = profiles
            .iter()
            .filter(|profile| profile.definition().root_contract_method_policy_id == id);
        let selected = matching.next().ok_or(RuntimeError::InvalidAuthorization)?;
        if matching.next().is_some() || &selected.grants().profile_digest != expected {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(Some(selected))
    }
    pub fn definition(&self) -> &MethodProfileDefinition {
        &self.configured.definition
    }
    pub fn grants(&self) -> &InteractionGrantSet {
        &self.configured.grants
    }
    pub fn root_method(&self) -> RuntimeResult<&ValidatedInvocationPolicy> {
        self.method(&self.definition().root_contract_method_policy_id)
    }
    fn method(&self, id: &str) -> RuntimeResult<&ValidatedInvocationPolicy> {
        self.methods.get(id).ok_or(RuntimeError::GenerationMismatch)
    }
    pub fn reviewed_call(
        &self,
        caller: [u8; 20],
        kind: CallKind,
        target: [u8; 20],
        input: &[u8],
    ) -> RuntimeResult<(&MethodInteractionRule, &ValidatedInvocationPolicy)> {
        let selector = input
            .get(..4)
            .and_then(|value| value.try_into().ok())
            .ok_or(RuntimeError::Denied)?;
        let index = self
            .rules_by_call
            .get(&ReviewedCall {
                caller,
                kind,
                target,
                selector,
            })
            .ok_or(RuntimeError::Denied)?;
        let rule = &self.definition().interactions[*index];
        Ok((rule, self.method(&rule.contract_method_policy_id)?))
    }
    pub fn validate_scope(
        &self,
        configuration_digest: &Digest,
        policy_artifact_digest: &Digest,
        scope: &ActiveInvocationScope<'_>,
    ) -> RuntimeResult<()> {
        if &self.configuration_digest != configuration_digest
            || &self.policy_artifact_digest != policy_artifact_digest
            || &self.policy_generation_digest != scope.policy_generation_digest
            || self.workload_id != scope.workload_id
            || self.definition().participant_id != scope.tenant_id
            || self.definition().privacy_domain_id != scope.privacy_domain_id
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(())
    }

    /// The caller must retain the actual signed installation and its current
    /// generation fence, as for the existing invocation/deployment loaders.
    pub fn load_active(
        configuration_bytes: &[u8],
        configuration_digest: &Digest,
        policy_bytes: &[u8],
        policy_artifact_digest: &Digest,
        scope: &ActiveInvocationScope<'_>,
    ) -> RuntimeResult<Vec<Self>> {
        let configuration =
            decode_active_invocation_configuration(configuration_bytes, configuration_digest)?;
        if !configuration
            .resource_artifacts
            .iter()
            .any(|artifact| artifact.artifact_kind == ConfigurationArtifactKind::CiglProfile)
        {
            return Ok(Vec::new());
        }
        let methods = ValidatedInvocationPolicy::load_active(
            configuration_bytes,
            configuration_digest,
            policy_bytes,
            policy_artifact_digest,
            scope,
        )?;
        let mut by_id = BTreeMap::new();
        for method in methods {
            if let Ok(identity) = method.configured_identity()
                && by_id
                    .insert(identity.contract_method_policy_id().to_owned(), method)
                    .is_some()
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        let methods = Arc::new(by_id);
        let mut roots = BTreeSet::new();
        let mut profiles = Vec::new();
        for artifact in &configuration.resource_artifacts {
            if artifact.artifact_kind != ConfigurationArtifactKind::CiglProfile {
                continue;
            }
            let configured: ConfiguredMethodProfile = decode_exact(&artifact.payload_cbor)?;
            configured.validate()?;
            let definition = &configured.definition;
            if artifact.artifact_id != definition.profile_id
                || definition.participant_id != scope.tenant_id
                || definition.privacy_domain_id != scope.privacy_domain_id
                || !roots.insert(definition.root_contract_method_policy_id.clone())
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            let select = |id: &str| methods.get(id).ok_or(RuntimeError::InvalidAuthorization);
            let root = select(&definition.root_contract_method_policy_id)?;
            if !root.artifact().active
                || root.artifact().method_required_roles.is_none()
                || root.artifact().nested_call_set_digest.as_ref() != Some(&definition.digest()?)
            {
                return Err(RuntimeError::GenerationMismatch);
            }
            let mut required_targets = BTreeSet::new();
            let program = definition
                .program
                .clone()
                .map(|program| ValidatedCiglProgram::try_new(program, &root.artifact().input_types))
                .transpose()?;
            if let Some(program) = &program {
                let generation = crate::invocation::decode_active_invocation_policy_generation(
                    policy_bytes,
                    policy_artifact_digest,
                )?;
                if program
                    .state_references()
                    .any(|reference| !generation.required_facts.contains(&reference.fact))
                {
                    return Err(RuntimeError::GenerationMismatch);
                }
            }
            let mut rules_by_call = BTreeMap::new();
            for (index, rule) in definition.interactions.iter().enumerate() {
                let target = select(&rule.contract_method_policy_id)?;
                if !target.artifact().active
                    || target.artifact().method_required_roles.is_none()
                    || target.artifact().chain_id != root.artifact().chain_id
                    || target.artifact().network_id != root.artifact().network_id
                    || target.artifact().genesis_digest != root.artifact().genesis_digest
                {
                    return Err(RuntimeError::GenerationMismatch);
                }
                let caller = match rule.caller {
                    CallerConstraint::RootExecution {} => root.exposed_contract_address(),
                    CallerConstraint::Exact { address } => address,
                };
                if rules_by_call
                    .insert(
                        ReviewedCall {
                            caller,
                            kind: rule.call_kind,
                            target: target.exposed_contract_address(),
                            selector: target.selector(),
                        },
                        index,
                    )
                    .is_some()
                {
                    // Symbolic and exact callers, or distinct method references,
                    // must not resolve to conflicting rules for the same call.
                    return Err(RuntimeError::GenerationMismatch);
                }
                required_targets.insert((
                    target
                        .configured_identity()?
                        .runtime_binding_id()
                        .to_owned(),
                    target.artifact().selector,
                ));
            }
            if configured.grants.grants.iter().any(|grant| {
                !required_targets.contains(&(grant.runtime_binding_id.clone(), grant.selector))
            }) {
                return Err(RuntimeError::GenerationMismatch);
            }
            profiles.push(Self {
                configured,
                configuration_digest: configuration_digest.clone(),
                policy_artifact_digest: policy_artifact_digest.clone(),
                policy_generation_digest: scope.policy_generation_digest.clone(),
                workload_id: scope.workload_id.into(),
                methods: methods.clone(),
                rules_by_call,
                program,
            });
        }
        Ok(profiles)
    }
}

#[cfg(test)]
mod tests;
