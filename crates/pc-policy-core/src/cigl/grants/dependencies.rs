//! Backend-derived, nested-only dependency coverage. These claims describe
//! upstream ownership; they do not replace base selector authorization or make
//! a compiled profile active. Callers authenticate and fence all source rows.
use super::{GrantEffect, GrantStatus, InteractionGrant, InteractionSurface};
use crate::cigl::{analysis::MethodAnalysisV1, profile::MethodProfileDefinition};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyCapability {
    SimulateCall,
    ExecuteTransaction,
}
impl DependencyCapability {
    /// REQ-SR01-S03-010809..010823. An individual source owns one selected
    /// surface. In particular, preparing a write never imports eth_call access.
    /// Estimate/deployment mappings require their own accepted owning surface.
    pub fn require_surface(self, surface: InteractionSurface) -> RuntimeResult<()> {
        match (self, surface) {
            (Self::SimulateCall, InteractionSurface::EthCall)
            | (Self::ExecuteTransaction, InteractionSurface::PrepareWrite)
            | (Self::ExecuteTransaction, InteractionSurface::RawSubmission)
            | (Self::ExecuteTransaction, InteractionSurface::RuntimeWriteTrace) => Ok(()),
            _ => Err(RuntimeError::InvalidAuthorization),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NestedDependency {
    pub ordinal: u16,
    pub action_digest: Digest,
    pub contract_method_policy_id: String,
    pub runtime_binding_id: String,
    pub selector: [u8; 4],
    /// Ordered analysis ordinals from the root's first child to this action.
    /// The root itself is never an imported dependency, even for recursion.
    /// Ordinals avoid copying an action digest at every ancestor of every path;
    /// the signed analysis digest binds their exact identities and ordering.
    pub relationship_path: Vec<u16>,
    pub closure_digest: Digest,
}

pub fn dependency_paths_digest(paths: &[NestedDependency]) -> RuntimeResult<Digest> {
    if paths.len() > 2048 {
        return Err(RuntimeError::BudgetExhausted);
    }
    for (i, path) in paths.iter().enumerate() {
        if usize::from(path.ordinal) != i + 1
            || path.relationship_path.is_empty()
            || path.relationship_path.len() > 128
            || path.relationship_path.last() != Some(&path.ordinal)
        {
            return Err(RuntimeError::InvalidInput);
        }
    }
    // Key-sorted objects also permit the SQL persistence owner to check the
    // exact complete set against the signed receipt at transaction commit.
    canonical_bytes(&serde_json::to_value(paths).map_err(|_| RuntimeError::InvalidInput)?)
        .map(Digest::of)
}

/// The analysis and definition must already have passed their signed-source
/// and exact-review owners. Recheck their binding here before deriving paths.
pub fn derive_nested_dependencies(
    analysis: &MethodAnalysisV1,
    profile: &MethodProfileDefinition,
) -> RuntimeResult<Vec<NestedDependency>> {
    analysis.validate()?;
    profile.validate()?;
    if analysis.unresolved_count() != 0
        || analysis.digest()? != profile.analysis_digest
        || analysis.participant_id != profile.participant_id
        || analysis.privacy_domain_id != profile.privacy_domain_id
        || analysis.root_contract_method_policy_id != profile.root_contract_method_policy_id
        || analysis.limits != profile.limits
    {
        return Err(RuntimeError::GenerationMismatch);
    }
    let mut dependencies: Vec<NestedDependency> = Vec::with_capacity(analysis.interactions.len());
    let mut consumed = BTreeSet::new();
    for interaction in &analysis.interactions {
        let crate::cigl::analysis::MethodResolution::Registered {
            contract_method_policy_id,
            runtime_binding_id,
        } = &interaction.resolution
        else {
            return Err(RuntimeError::Denied);
        };
        let mut rules = profile.interactions.iter().filter(|rule| {
            rule.contract_method_policy_id == *contract_method_policy_id
                && rule.call_kind == interaction.call_kind
                && matches!(&rule.caller, crate::cigl::profile::CallerConstraint::Exact { address }
                    if *address == interaction.caller)
        });
        let rule = rules.next().ok_or(RuntimeError::GenerationMismatch)?;
        if rules.next().is_some() {
            return Err(RuntimeError::GenerationMismatch);
        }
        consumed.insert(&rule.interaction_id);
        let action_digest = interaction.action_digest()?;
        let mut relationship_path = if interaction.parent == 0 {
            Vec::new()
        } else {
            dependencies[usize::from(interaction.parent) - 1]
                .relationship_path
                .clone()
        };
        relationship_path.push(interaction.ordinal);
        let closure_digest = Digest::of(canonical_bytes(&(
            "openpc:cigl-dependency-path:v1",
            &profile.profile_id,
            profile.revision,
            &profile.analysis_digest,
            &relationship_path,
        ))?);
        dependencies.push(NestedDependency {
            ordinal: interaction.ordinal,
            action_digest,
            contract_method_policy_id: contract_method_policy_id.clone(),
            runtime_binding_id: runtime_binding_id.clone(),
            selector: interaction.selector.ok_or(RuntimeError::Denied)?,
            relationship_path,
            closure_digest,
        });
    }
    if consumed.len() != profile.interactions.len() {
        return Err(RuntimeError::GenerationMismatch);
    }
    Ok(dependencies)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewedDependencyGrant {
    pub action_digest: Digest,
    pub required_grant_id: String,
}

/// Match every reviewed action to an active, same-subject/surface ALLOW. Shared
/// grants remain independent authority. The current runtime resolver still
/// applies all overlapping DENYs, role resolution and base method policy.
pub fn verify_nested_bundle(
    dependencies: &[NestedDependency],
    source: &InteractionGrant,
    capability: DependencyCapability,
    reviewed: &[ReviewedDependencyGrant],
    current_grants: &[InteractionGrant],
) -> RuntimeResult<()> {
    source.validate()?;
    capability.require_surface(source.surface)?;
    if source.status != GrantStatus::Active
        || source.effect != GrantEffect::Allow
        || reviewed.len() != dependencies.len()
        || current_grants.len() > 4096
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let mut grants = BTreeMap::new();
    for grant in current_grants {
        grant.validate()?;
        if grants.insert(&grant.grant_id, grant).is_some() {
            return Err(RuntimeError::InvalidInput);
        }
    }
    let mut actions = BTreeMap::new();
    for choice in reviewed {
        if actions.insert(&choice.action_digest, choice).is_some() {
            return Err(RuntimeError::InvalidInput);
        }
    }
    for dependency in dependencies {
        let choice = actions
            .remove(&dependency.action_digest)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let grant = grants
            .get(&choice.required_grant_id)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        if grant.runtime_binding_id != dependency.runtime_binding_id
            || grant.selector != dependency.selector
            || grant.subject != source.subject
            || grant.surface != source.surface
            || grant.effect != GrantEffect::Allow
            || grant.status != GrantStatus::Active
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // A same-subject or universal DENY is provably applicable without
        // pretending that static coverage can resolve other role memberships.
        if current_grants.iter().any(|candidate| {
            candidate.runtime_binding_id == dependency.runtime_binding_id
                && candidate.selector == dependency.selector
                && candidate.surface == source.surface
                && candidate.status == GrantStatus::Active
                && candidate.effect == GrantEffect::Deny
                && (candidate.subject == source.subject
                    || matches!(candidate.subject, super::GrantSubject::AnyAuthenticated {}))
        }) {
            return Err(RuntimeError::Denied);
        }
    }
    if !actions.is_empty() {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
