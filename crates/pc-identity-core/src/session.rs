use serde::{Deserialize, Serialize};

use crate::EntityMetadata;

pub const SESSION_COOKIE_PROFILE: &str =
    "__Host-openpc_session; Secure; HttpOnly; SameSite=Strict; Path=/";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SessionContractType {
    #[serde(rename = "Session")]
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionStatus {
    Authenticating,
    Active,
    StepUpRequired,
    Revoked,
    Expired,
    Compromised,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub contract_type: SessionContractType,
    #[serde(flatten)]
    pub metadata: EntityMetadata,
    pub status: SessionStatus,
    pub session_id: String,
    pub principal_id: String,
    pub participant_id: String,
    pub participant_epoch: String,
    pub session_epoch: String,
    pub idle_expires_at: String,
    pub absolute_expires_at: String,
    pub step_up_valid_until: Option<String>,
    pub refresh_family_id: String,
    pub cookie_profile: String,
}

impl Session {
    #[must_use]
    pub fn has_hardened_cookie_profile(&self) -> bool {
        self.cookie_profile == SESSION_COOKIE_PROFILE
    }

    #[must_use]
    pub fn has_valid_epoch(&self) -> bool {
        self.participant_epoch.parse::<u64>().is_ok() && self.session_epoch.parse::<u64>().is_ok()
    }
}
