use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AssignmentContractType {
    #[serde(rename = "Assignment")]
    Assignment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssignmentStatus {
    Proposed,
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assignment {
    pub contract_type: AssignmentContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: AssignmentStatus,
    pub participant_id: String,
    pub participant_epoch: String,
    pub subject_id: String,
    pub role_id: String,
    pub scope_digest: String,
    pub not_before: String,
    pub not_after: String,
}
