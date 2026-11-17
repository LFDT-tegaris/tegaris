use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MfaEvidenceContractType {
    #[serde(rename = "MfaEvidence")]
    MfaEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MfaEvidenceStatus {
    ChallengeIssued,
    Verified,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaEvidence {
    pub contract_type: MfaEvidenceContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: MfaEvidenceStatus,
    pub principal_id: String,
    pub session_id: String,
    pub method: String,
    pub challenge_digest: String,
    pub rp_id_hash: String,
    pub verified_at: String,
    pub valid_until: String,
    pub action_intent_id: String,
}

impl MfaEvidence {
    #[must_use]
    pub fn is_action_bound_webauthn(&self) -> bool {
        self.method == "WEBAUTHN"
            && self.challenge_digest.starts_with("sha256:")
            && self.rp_id_hash.starts_with("sha256:")
            && self.action_intent_id.starts_with("ACT-")
    }
}
