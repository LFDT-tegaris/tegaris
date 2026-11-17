use serde::{Deserialize, Serialize};

/// Every value other than `Allow` is terminal non-allowing at an enforcement boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityDecision {
    Allow,
    Deny,
    Unknown,
    Unavailable,
    Stale,
    Conflict,
    Tampered,
    Incompatible,
}

impl AuthorityDecision {
    #[must_use]
    pub const fn permits(self) -> bool {
        matches!(self, Self::Allow)
    }
}
