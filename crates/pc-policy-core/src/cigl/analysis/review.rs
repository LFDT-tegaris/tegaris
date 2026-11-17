//! Exact action review, shared by the public persistence owner and compiler.
//! This creates a candidate definition only. Source authentication, independent
//! approval, current global grants and active publication remain required.
use super::*;
use crate::cigl::{
    profile::{CallerConstraint, MethodInteractionRule, MethodProfileDefinition},
    program::{CiglProgramV1, ValidatedCiglProgram},
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewedInteraction {
    pub action_digest: Digest,
    pub maximum_value: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodAnalysisReview {
    pub analysis_digest: Digest,
    pub actions: Vec<ReviewedInteraction>,
    pub program: Option<CiglProgramV1>,
}

impl MethodAnalysisReview {
    /// Exact non-granting action review. Typed program/source compilation still
    /// requires compile_candidate with the admitted configuration and policy.
    pub fn validate_analysis(&self, analysis: &MethodAnalysisV1) -> RuntimeResult<()> {
        self.reviewed_actions(analysis).map(|_| ())
    }

    fn reviewed_actions<'a>(
        &'a self,
        analysis: &MethodAnalysisV1,
    ) -> RuntimeResult<BTreeMap<Digest, &'a ReviewedInteraction>> {
        if analysis.digest()? != self.analysis_digest
            || analysis.unresolved_count() != 0
            || analysis.interactions.len() != self.actions.len()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        let expected = analysis
            .interactions
            .iter()
            .map(|interaction| interaction.action_digest())
            .collect::<RuntimeResult<BTreeSet<_>>>()?;
        let mut actions = BTreeMap::new();
        for action in &self.actions {
            if !expected.contains(&action.action_digest)
                || actions
                    .insert(action.action_digest.clone(), action)
                    .is_some()
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if actions.len() != expected.len() {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(actions)
    }

    pub fn compile_candidate(
        &self,
        analysis: &MethodAnalysisV1,
        configuration_bytes: &[u8],
        policy_bytes: &[u8],
        profile_id: &str,
        revision: u64,
    ) -> RuntimeResult<MethodProfileDefinition> {
        let actions = self.reviewed_actions(analysis)?;
        // Resolve the ABI and registrations from these exact source bytes.
        // A policy object alone would not prove the analysis's configuration
        // digest, even when its method ID and policy generation still matched.
        let policies = ValidatedInvocationPolicy::load_active(
            configuration_bytes,
            &analysis.configuration_digest,
            policy_bytes,
            &analysis.policy_artifact_digest,
            &crate::invocation::ActiveInvocationScope {
                policy_generation_digest: &analysis.policy_generation_digest,
                tenant_id: &analysis.participant_id,
                privacy_domain_id: &analysis.privacy_domain_id,
                workload_id: &analysis.workload_id,
            },
        )?;
        let mut roots = policies.iter().filter(|policy| {
            policy.configured_identity().is_ok_and(|identity| {
                identity.contract_method_policy_id() == analysis.root_contract_method_policy_id
            })
        });
        let root = roots.next().ok_or(RuntimeError::GenerationMismatch)?;
        let source = root.artifact();
        if roots.next().is_some()
            || root.configured_identity()?.runtime_binding_id() != analysis.root_runtime_binding_id
            || source.tenant_id != analysis.participant_id
            || source.privacy_domain_id != analysis.privacy_domain_id
            || source.workload_id != analysis.workload_id
            || source.policy_artifact_digest != analysis.policy_artifact_digest
            || source.policy_generation_digest != analysis.policy_generation_digest
            || !source.active
            || source.method_required_roles.is_none()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if let Some(program) = &self.program {
            ValidatedCiglProgram::try_new(program.clone(), &source.input_types)?;
        }
        let mut rules: BTreeMap<_, MethodInteractionRule> = BTreeMap::new();
        let mut consumed = BTreeSet::new();
        for interaction in &analysis.interactions {
            let digest = interaction.action_digest()?;
            let action = actions.get(&digest).ok_or(RuntimeError::InvalidInput)?;
            if !consumed.insert(digest) {
                return Err(RuntimeError::InvalidInput);
            }
            let MethodResolution::Registered {
                contract_method_policy_id,
                ..
            } = &interaction.resolution
            else {
                return Err(RuntimeError::Denied);
            };
            // One exact runtime dispatch identity has one reviewed bound. A
            // repeated frame cannot introduce an alias or conflicting limit.
            let key = (
                interaction.caller,
                interaction.call_kind,
                interaction.target,
                interaction.selector,
            );
            let rule = MethodInteractionRule {
                interaction_id: Digest::of(canonical_bytes(&(
                    "openpc:cigl-reviewed-call:v1",
                    &key,
                ))?)
                .as_str()
                .into(),
                caller: CallerConstraint::Exact {
                    address: interaction.caller,
                },
                call_kind: interaction.call_kind,
                contract_method_policy_id: contract_method_policy_id.clone(),
                maximum_value: action.maximum_value,
            };
            if let Some(previous) = rules.insert(key, rule.clone())
                && previous != rule
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        let definition = MethodProfileDefinition {
            schema_version: "1.0".into(),
            profile_id: profile_id.into(),
            revision,
            participant_id: analysis.participant_id.clone(),
            privacy_domain_id: analysis.privacy_domain_id.clone(),
            root_contract_method_policy_id: analysis.root_contract_method_policy_id.clone(),
            analysis_digest: self.analysis_digest.clone(),
            program: self.program.clone(),
            limits: analysis.limits,
            interactions: rules.into_values().collect(),
        };
        definition.validate()?;
        Ok(definition)
    }
}
