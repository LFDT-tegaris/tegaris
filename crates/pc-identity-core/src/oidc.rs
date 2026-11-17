use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OidcAuthorizationStatus {
    Requested,
    CallbackValidated,
    Consumed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcAuthorization {
    pub status: OidcAuthorizationStatus,
    pub flow: String,
    pub pkce_method: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub authorization_uri: String,
    pub state_digest: String,
    pub nonce_digest: String,
    pub code_challenge: String,
    pub expires_at: String,
    pub trace_set_id: String,
}
