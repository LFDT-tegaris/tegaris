use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ParticipantContractType {
    #[serde(rename = "Participant")]
    Participant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParticipantStatus {
    Provisioning,
    Active,
    Suspended,
    TransferPending,
    Revoked,
    Offboarded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Participant {
    pub contract_type: ParticipantContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: ParticipantStatus,
    pub participant_id: String,
    pub participant_epoch: String,
    pub authority_envelope_id: String,
    pub privacy_domain_id: String,
}
