use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DelegationContractType {
    #[serde(rename = "Delegation")]
    Delegation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationStatus {
    Proposed,
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delegation {
    pub contract_type: DelegationContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: DelegationStatus,
    pub participant_id: String,
    pub delegation_epoch: String,
    pub grantor_id: String,
    pub grantee_id: String,
    pub parent_delegation_id: Option<String>,
    pub grantable_digest: String,
    pub usable_digest: String,
    pub downward_proof_digest: String,
    pub not_after: String,
}

impl Delegation {
    #[must_use]
    pub fn is_non_self_downward_candidate(&self) -> bool {
        self.grantor_id != self.grantee_id
            && self.parent_delegation_id.as_deref() != Some(self.metadata.id.as_str())
            && self.delegation_epoch.parse::<u64>().is_ok()
            && self.grantable_digest.starts_with("sha256:")
            && self.usable_digest.starts_with("sha256:")
            && self.downward_proof_digest.starts_with("sha256:")
    }
}
