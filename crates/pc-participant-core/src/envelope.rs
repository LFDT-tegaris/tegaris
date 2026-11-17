use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuthorityEnvelopeContractType {
    #[serde(rename = "AuthorityEnvelope")]
    AuthorityEnvelope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEnvelopeStatus {
    Draft,
    Submitted,
    Approved,
    Active,
    Superseded,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEnvelope {
    pub contract_type: AuthorityEnvelopeContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: AuthorityEnvelopeStatus,
    pub participant_id: String,
    pub authority_epoch: String,
    pub envelope_digest: String,
    pub scope_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub maker_principal_id: String,
    pub checker_principal_id: String,
}

impl AuthorityEnvelope {
    #[must_use]
    pub fn has_distinct_maker_checker(&self) -> bool {
        self.maker_principal_id != self.checker_principal_id
            && !self.scope_ids.is_empty()
            && !self.capability_ids.is_empty()
            && self.authority_epoch.parse::<u64>().is_ok()
    }
}
