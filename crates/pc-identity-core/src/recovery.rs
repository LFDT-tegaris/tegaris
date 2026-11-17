use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryCaseContractType {
    #[serde(rename = "RecoveryCase")]
    RecoveryCase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryCaseStatus {
    Requested,
    CustodianOneApproved,
    CustodianTwoApproved,
    LeaseActive,
    Completed,
    Denied,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryCase {
    pub contract_type: RecoveryCaseContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: RecoveryCaseStatus,
    pub recovery_principal_id: String,
    pub subject_id: String,
    pub purpose_digest: String,
    pub custodian_principal_ids: [String; 2],
    pub lease_expires_at: String,
    pub post_review_required: bool,
}

impl RecoveryCase {
    #[must_use]
    pub fn has_distinct_custodians(&self) -> bool {
        self.custodian_principal_ids[0] != self.custodian_principal_ids[1]
            && self.post_review_required
            && !self.purpose_digest.is_empty()
    }
}
