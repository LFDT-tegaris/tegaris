use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WalletBindingContractType {
    #[serde(rename = "WalletBinding")]
    WalletBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletBindingStatus {
    Proposed,
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletBinding {
    pub contract_type: WalletBindingContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: WalletBindingStatus,
    pub participant_id: String,
    pub subject_id: String,
    pub chain_id: String,
    pub wallet_address: String,
    pub binding_epoch: String,
    pub permission_effect: String,
}

impl WalletBinding {
    #[must_use]
    pub fn is_non_authorizing(&self) -> bool {
        self.permission_effect == "NONE_WITHOUT_EFFECTIVE_AUTHORITY"
            && self.binding_epoch.parse::<u64>().is_ok()
    }
}
