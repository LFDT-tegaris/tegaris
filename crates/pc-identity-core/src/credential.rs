use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorkloadCredentialContractType {
    #[serde(rename = "WorkloadCredential")]
    WorkloadCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkloadCredentialStatus {
    Issued,
    Active,
    Rotating,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadCredential {
    pub contract_type: WorkloadCredentialContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: WorkloadCredentialStatus,
    pub credential_id: String,
    pub workload_id: String,
    pub participant_id: String,
    pub workload_epoch: String,
    pub key_id: String,
    pub uri_san: String,
    pub not_before: String,
    pub not_after: String,
    pub rotation_due_at: String,
    pub tls_version: String,
}

impl WorkloadCredential {
    #[must_use]
    pub fn has_exact_workload_binding(&self) -> bool {
        let Some(workload_uuid) = self.workload_id.rsplit(':').next() else {
            return false;
        };
        let expected = format!("{}:workload:{workload_uuid}", self.participant_id);
        self.tls_version == "TLS1.3"
            && self.uri_san == expected
            && self.workload_epoch.parse::<u64>().is_ok()
            && self.key_id.starts_with("sha256:")
    }
}
