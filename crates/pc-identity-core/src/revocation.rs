use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RevocationRecordContractType {
    #[serde(rename = "RevocationRecord")]
    RevocationRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationRecordStatus {
    Requested,
    Committed,
    Evidenced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationRecord {
    pub contract_type: RevocationRecordContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: RevocationRecordStatus,
    pub aggregate_id: String,
    pub prior_epoch: String,
    pub new_epoch: String,
    pub reason_code: String,
    pub effective_at: String,
    pub evidence_digest: String,
}
