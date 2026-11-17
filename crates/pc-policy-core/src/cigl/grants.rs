//! Deny-first matching of an installed profile's grant rows. Profile publication,
//! trusted frame-to-interaction classification and base-method authorization are
//! required by callers; this module cannot turn trace data into authority.
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod dependencies;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum GrantSubject {
    Role { id: String },
    User { id: String },
    Group { id: String },
    Workload { id: String },
    Participant { id: String },
    AnyAuthenticated {},
}
impl GrantSubject {
    fn validate(&self) -> RuntimeResult<()> {
        let id = match self {
            Self::Role { id }
            | Self::User { id }
            | Self::Group { id }
            | Self::Workload { id }
            | Self::Participant { id } => id,
            Self::AnyAuthenticated {} => return Ok(()),
        };
        if identifier(id) {
            Ok(())
        } else {
            Err(RuntimeError::InvalidInput)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InteractionSurface {
    EthCall,
    EthEstimateGas,
    PrepareWrite,
    RawSubmission,
    DeploymentConstructor,
    RuntimeWriteTrace,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantEffect {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InteractionGrant {
    pub grant_id: String,
    /// Shared target-method authority, independent of profile/edge identity.
    /// The publisher includes every applicable current allow and deny row.
    pub runtime_binding_id: String,
    pub selector: [u8; 4],
    pub subject: GrantSubject,
    pub surface: InteractionSurface,
    pub effect: GrantEffect,
    pub status: GrantStatus,
}
impl InteractionGrant {
    /// Structural validation only. Current subject resolution and governed
    /// source provenance belong to the publication and identity owners.
    pub fn validate(&self) -> RuntimeResult<()> {
        if !identifier(&self.grant_id) || !identifier(&self.runtime_binding_id) {
            return Err(RuntimeError::InvalidInput);
        }
        self.subject.validate()
    }

    /// Key-sorted JSON identity shared with the public source store. This is
    /// independent of Rust struct field ordering and carries no authority.
    pub fn digest(&self) -> RuntimeResult<Digest> {
        self.validate()?;
        pc_runtime_types::canonical_bytes(
            &serde_json::to_value(self).map_err(|_| RuntimeError::InvalidInput)?,
        )
        .map(Digest::of)
    }
}

/// Loaded with the active policy/configuration artifacts. The outer owner must
/// verify those artifact digests and retain the current generation fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InteractionGrantSet {
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: Digest,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub status: GrantStatus,
    pub grants: Vec<InteractionGrant>,
}

pub struct GrantScope<'a> {
    pub profile_id: &'a str,
    pub profile_revision: u64,
    pub profile_digest: &'a Digest,
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub surface: InteractionSurface,
}

/// Produced by matching a trusted frame to a reviewed profile and installed
/// method registration. The interaction ID labels evidence, not grant authority.
pub struct RequiredMethodInteraction<'a> {
    pub interaction_id: &'a str,
    pub runtime_binding_id: &'a str,
    pub selector: [u8; 4],
}

/// Implement only at an authenticated identity owner. Each subject uses its own
/// current resolver; a missing/unavailable resolution is an error, not a wildcard.
pub trait CurrentInteractionSubjects {
    /// The composed invocation evaluator requires the same authenticated facts
    /// used by subject resolution. A standalone lookup cannot supply them.
    fn invocation_authorization(
        &self,
    ) -> RuntimeResult<&crate::invocation::ValidatedInvocationAuthorization> {
        Err(RuntimeError::InvalidAuthorization)
    }
    fn participant_id(&self) -> &str;
    fn privacy_domain_id(&self) -> &str;
    fn require_current(&self, now_ns: u64) -> RuntimeResult<()>;
    fn matches(&self, subject: &GrantSubject) -> RuntimeResult<bool>;
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchedInteraction {
    pub interaction_id: String,
    pub grant_ids: Vec<String>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic())
}

impl InteractionGrantSet {
    pub fn validate(&self) -> RuntimeResult<()> {
        if [
            &self.profile_id,
            &self.participant_id,
            &self.privacy_domain_id,
        ]
        .into_iter()
        .any(|id| !identifier(id))
            || self.profile_revision == 0
            || self.profile_digest == Digest::of([])
            || self.grants.len() > 4096
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut ids = BTreeSet::new();
        for grant in &self.grants {
            grant.validate()?;
            if !ids.insert(&grant.grant_id) {
                return Err(RuntimeError::InvalidInput);
            }
        }
        Ok(())
    }

    /// CIGL-C01/02/06/10. Every required interaction must match an active allow;
    /// every applicable active deny defeats it, independent of row/frame order.
    /// This result alone is not an invocation decision or permission to disclose.
    pub fn match_required(
        &self,
        required_interactions: &[RequiredMethodInteraction<'_>],
        scope: &GrantScope<'_>,
        subjects: &impl CurrentInteractionSubjects,
        now_ns: u64,
    ) -> RuntimeResult<Vec<MatchedInteraction>> {
        self.validate()?;
        subjects.require_current(now_ns)?;
        if self.status != GrantStatus::Active
            || self.profile_id != scope.profile_id
            || self.profile_revision != scope.profile_revision
            || &self.profile_digest != scope.profile_digest
            || self.participant_id != scope.participant_id
            || self.privacy_domain_id != scope.privacy_domain_id
            || subjects.participant_id() != scope.participant_id
            || subjects.privacy_domain_id() != scope.privacy_domain_id
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        if required_interactions.len() > 2048
            || required_interactions.iter().any(|required| {
                !identifier(required.interaction_id) || !identifier(required.runtime_binding_id)
            })
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut by_interaction: BTreeMap<(&str, [u8; 4]), Vec<&InteractionGrant>> = BTreeMap::new();
        for grant in &self.grants {
            if grant.status == GrantStatus::Active && grant.surface == scope.surface {
                by_interaction
                    .entry((&grant.runtime_binding_id, grant.selector))
                    .or_default()
                    .push(grant);
            }
        }
        let mut matches = Vec::with_capacity(required_interactions.len());
        for required in required_interactions {
            let mut allowed = BTreeSet::new();
            for grant in by_interaction
                .get(&(required.runtime_binding_id, required.selector))
                .into_iter()
                .flatten()
            {
                if subjects.matches(&grant.subject)? {
                    if grant.effect == GrantEffect::Deny {
                        return Err(RuntimeError::Denied);
                    }
                    allowed.insert(grant.grant_id.clone());
                }
            }
            if allowed.is_empty() {
                return Err(RuntimeError::Denied);
            }
            matches.push(MatchedInteraction {
                interaction_id: required.interaction_id.into(),
                grant_ids: allowed.into_iter().collect(),
            });
        }
        subjects.require_current(now_ns)?;
        Ok(matches)
    }
}

#[cfg(test)]
mod tests;
